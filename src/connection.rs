use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, oneshot};
use tokio::time::timeout;
use uuid::Uuid;

use crate::log::{LogLevel, LogStruct};
use crate::protocol::{
    self, AddKeyResult, Message, PROTOCOL_VERSION, PqStatusResult, PublicIpInfo, QueryKeyResult,
    RelayStatusResult, SidecarError, SuccessResult,
};
use crate::service;

/// 控制指令默认超时，需不小于节点侧 `dispatcher.query_timeout_secs`（默认 60s）
const CONTROL_TIMEOUT: Duration = Duration::from_secs(60);

/// 单个后端的「id → 响应等待者」挂起表
type PendingMap = Arc<Mutex<HashMap<Uuid, oneshot::Sender<Result<Vec<u8>, SidecarError>>>>>;

struct Shared {
    writer: Mutex<OwnedWriteHalf>,
    pending: PendingMap,
}

/// 后端回连节点的控制句柄，可 clone 后跨任务使用
#[derive(Clone)]
pub struct BackendClient {
    shared: Arc<Shared>,
    timeout: Duration,
}

impl BackendClient {
    /// 发送一条控制指令并等待节点 `reply`
    async fn call(&self, id: Uuid, msg: Message) -> Result<Vec<u8>, SidecarError> {
        let (tx, rx) = oneshot::channel();
        self.shared.pending.lock().await.insert(id, tx);

        if let Err(e) = write_msg(&self.shared.writer, &msg).await {
            self.shared.pending.lock().await.remove(&id);
            return Err(SidecarError::new("io_error", e));
        }

        match timeout(self.timeout, rx).await {
            Ok(Ok(Ok(data))) => Ok(data),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => Err(SidecarError::new("node_gone", "response channel closed")),
            Err(_) => {
                self.shared.pending.lock().await.remove(&id);
                Err(SidecarError::new("timeout", "control command timed out"))
            }
        }
    }

    /// 发送控制指令并把 `reply.result` 解码为 `T`
    async fn call_result<T: DeserializeOwned>(
        &self,
        id: Uuid,
        msg: Message,
    ) -> Result<T, SidecarError> {
        let bytes = self.call(id, msg).await?;
        protocol::decode_result(&bytes)
    }

    /// 列出全局服务类型
    pub async fn list_services(&self) -> Result<Vec<String>, SidecarError> {
        let id = Uuid::new_v4();
        self.call_result(id, Message::ListServices { id }).await
    }

    /// 查询某服务的提供者
    pub async fn discover_providers(&self, service: &str) -> Result<Vec<String>, SidecarError> {
        let id = Uuid::new_v4();
        self.call_result(
            id,
            Message::DiscoverProviders {
                id,
                service: service.to_string(),
            },
        )
        .await
    }

    /// 查询本节点公网地址
    pub async fn query_public_ip(&self) -> Result<PublicIpInfo, SidecarError> {
        let id = Uuid::new_v4();
        self.call_result(id, Message::QueryPublicIp { id }).await
    }

    /// 重新拨号 bootstrap
    pub async fn reconnect_bootstrap(&self) -> Result<SuccessResult, SidecarError> {
        let id = Uuid::new_v4();
        self.call_result(id, Message::ReconnectBootstrap { id })
            .await
    }

    /// 重新宣告本地服务
    pub async fn reannounce_services(&self) -> Result<SuccessResult, SidecarError> {
        let id = Uuid::new_v4();
        self.call_result(id, Message::ReannounceServices { id })
            .await
    }

    /// 重载节点配置
    pub async fn reload_config(&self) -> Result<SuccessResult, SidecarError> {
        let id = Uuid::new_v4();
        self.call_result(id, Message::ReloadConfig { id }).await
    }

    /// 中继状态
    pub async fn relay_status(&self) -> Result<RelayStatusResult, SidecarError> {
        let id = Uuid::new_v4();
        self.call_result(id, Message::RelayStatus { id }).await
    }

    /// 抗量子状态
    pub async fn pq_status(&self) -> Result<PqStatusResult, SidecarError> {
        let id = Uuid::new_v4();
        self.call_result(id, Message::PqStatus { id }).await
    }

    /// 鉴权状态（结构随版本扩展，返回原始 JSON 值）
    pub async fn auth_status(&self) -> Result<serde_json::Value, SidecarError> {
        let id = Uuid::new_v4();
        self.call_result(id, Message::AuthStatus { id }).await
    }

    /// 读取 DHT 记录
    pub async fn query_key(&self, key: &str) -> Result<QueryKeyResult, SidecarError> {
        let id = Uuid::new_v4();
        self.call_result(
            id,
            Message::QueryKey {
                id,
                key: key.to_string(),
            },
        )
        .await
    }

    /// 写入 DHT 记录 / 宣告提供
    pub async fn add_key(
        &self,
        key: &str,
        value: Option<Vec<u8>>,
        providing: bool,
    ) -> Result<AddKeyResult, SidecarError> {
        let id = Uuid::new_v4();
        self.call_result(
            id,
            Message::AddKey {
                id,
                key: key.to_string(),
                value,
                providing,
            },
        )
        .await
    }

    /// 发起 P2P 服务调用（节点自动选优提供者）
    pub async fn service_request(
        &self,
        service: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, SidecarError> {
        let id = Uuid::new_v4();
        self.call(
            id,
            Message::ServiceRequest {
                id,
                service: service.to_string(),
                payload,
            },
        )
        .await
    }

    /// 向指定 peer 发起 P2P 服务调用
    pub async fn service_request_to(
        &self,
        service: &str,
        peer: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, SidecarError> {
        let id = Uuid::new_v4();
        self.call(
            id,
            Message::ServiceRequestTo {
                id,
                service: service.to_string(),
                peer: peer.to_string(),
                payload,
            },
        )
        .await
    }
}

async fn write_msg(writer: &Mutex<OwnedWriteHalf>, msg: &Message) -> Result<(), String> {
    let mut w = writer.lock().await;
    protocol::write_frame(&mut *w, msg)
        .await
        .map_err(|e| e.to_string())
}

/// 与节点交换 hello，校验协议版本
async fn handshake(read_half: &mut OwnedReadHalf, client: &BackendClient) -> Result<(), String> {
    match protocol::read_frame(read_half).await {
        Ok(Message::Hello { version }) if version == PROTOCOL_VERSION => {
            write_msg(
                &client.shared.writer,
                &Message::Hello {
                    version: PROTOCOL_VERSION,
                },
            )
            .await?;
            Ok(())
        }
        Ok(Message::Hello { version }) => Err(format!(
            "协议版本不兼容: 对端 {version}, 本端 {PROTOCOL_VERSION}"
        )),
        Ok(other) => Err(format!("期望 hello 首帧, 收到 {}", other.kind())),
        Err(e) => Err(e.to_string()),
    }
}

/// 处理单条节点连接：握手后进入读写循环
pub async fn handle_connection(stream: TcpStream) -> std::io::Result<()> {
    let (mut read_half, write_half) = stream.into_split();
    let client = BackendClient {
        shared: Arc::new(Shared {
            writer: Mutex::new(write_half),
            pending: Arc::new(Mutex::new(HashMap::new())),
        }),
        timeout: CONTROL_TIMEOUT,
    };

    if let Err(e) = handshake(&mut read_half, &client).await {
        LogStruct::new(LogLevel::Warning, "后端握手失败", e).emit();
        return Ok(());
    }
    LogStruct::new(
        LogLevel::Preset,
        "握手完成",
        format!("协议 v{PROTOCOL_VERSION}"),
    )
    .emit();

    read_loop(read_half, client).await;
    Ok(())
}

/// 读取节点消息：服务请求派发业务，控制回复唤醒等待者
async fn read_loop(mut read_half: OwnedReadHalf, client: BackendClient) {
    loop {
        match protocol::read_frame(&mut read_half).await {
            Ok(Message::Request {
                id,
                service,
                payload,
            }) => {
                let client = client.clone();
                tokio::spawn(async move {
                    let reply =
                        match service::handle_service_request(&service, &payload, &client).await {
                            Ok(result) => Message::Reply {
                                id,
                                ok: true,
                                result: Some(result),
                                error: None,
                            },
                            Err(e) => Message::Reply {
                                id,
                                ok: false,
                                result: None,
                                error: Some(e),
                            },
                        };
                    if let Err(e) = write_msg(&client.shared.writer, &reply).await {
                        LogStruct::new(LogLevel::Critical, "回复写入失败", e).emit();
                    }
                });
            }
            Ok(Message::Reply {
                id,
                ok,
                result,
                error,
            }) => {
                let sender = client.shared.pending.lock().await.remove(&id);
                match sender {
                    Some(tx) => {
                        let outcome = if ok {
                            Ok(result.unwrap_or_default())
                        } else {
                            Err(error.unwrap_or_else(|| {
                                SidecarError::new("backend_error", "unknown error")
                            }))
                        };
                        let _ = tx.send(outcome);
                    }
                    None => {
                        LogStruct::new(LogLevel::Warning, "未知响应", format!("未匹配的 id {id}"))
                            .emit();
                    }
                }
            }
            Ok(other) => {
                LogStruct::new(
                    LogLevel::Warning,
                    "非预期消息",
                    format!("节点不应发送 {}", other.kind()),
                )
                .emit();
            }
            Err(e) => {
                LogStruct::new(LogLevel::Warning, "连接断开", e.to_string()).emit();
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn spawn_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_connection(stream).await;
        });
        (port, handle)
    }

    async fn connect(port: u16) -> TcpStream {
        TcpStream::connect(("127.0.0.1", port)).await.unwrap()
    }

    fn enc<T: serde::Serialize>(v: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(v, &mut buf).unwrap();
        buf
    }

    #[tokio::test]
    async fn handshake_ok() {
        let (port, _srv) = spawn_server().await;
        let mut stream = connect(port).await;
        let (mut r, mut w) = stream.split();

        protocol::write_frame(
            &mut w,
            &Message::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();

        match protocol::read_frame(&mut r).await.unwrap() {
            Message::Hello { version } => assert_eq!(version, PROTOCOL_VERSION),
            other => panic!("expected hello, got {}", other.kind()),
        }
    }

    #[tokio::test]
    async fn handshake_version_mismatch_closes() {
        let (port, srv) = spawn_server().await;
        let mut stream = connect(port).await;
        let (mut r, mut w) = stream.split();

        protocol::write_frame(&mut w, &Message::Hello { version: 999 })
            .await
            .unwrap();

        assert!(protocol::read_frame(&mut r).await.is_err());
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_non_hello_closes() {
        let (port, srv) = spawn_server().await;
        let mut stream = connect(port).await;
        let (mut r, mut w) = stream.split();

        protocol::write_frame(&mut w, &Message::ListServices { id: Uuid::new_v4() })
            .await
            .unwrap();

        assert!(protocol::read_frame(&mut r).await.is_err());
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn service_request_round_trip() {
        let (port, _srv) = spawn_server().await;
        let mut stream = connect(port).await;
        let (mut r, mut w) = stream.split();

        protocol::write_frame(
            &mut w,
            &Message::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        protocol::read_frame(&mut r).await.unwrap();

        let id = Uuid::new_v4();
        protocol::write_frame(
            &mut w,
            &Message::Request {
                id,
                service: "example".into(),
                payload: b"ping".to_vec(),
            },
        )
        .await
        .unwrap();

        match protocol::read_frame(&mut r).await.unwrap() {
            Message::Reply {
                id: rid,
                ok,
                result,
                error,
            } => {
                assert_eq!(rid, id);
                assert!(ok);
                assert_eq!(result.unwrap(), b"ping");
                assert!(error.is_none());
            }
            other => panic!("expected reply, got {}", other.kind()),
        }
    }

    #[tokio::test]
    async fn control_call_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let node = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            match protocol::read_frame(&mut r).await.unwrap() {
                Message::QueryPublicIp { id } => {
                    let body = enc(&PublicIpInfo {
                        ipv4: Some("1.2.3.4".into()),
                        ipv6: None,
                    });
                    protocol::write_frame(
                        &mut w,
                        &Message::Reply {
                            id,
                            ok: true,
                            result: Some(body),
                            error: None,
                        },
                    )
                    .await
                    .unwrap();
                }
                other => panic!("unexpected {}", other.kind()),
            }
        });

        let stream = connect(addr.port()).await;
        let (r, w) = stream.into_split();
        let client = BackendClient {
            shared: Arc::new(Shared {
                writer: Mutex::new(w),
                pending: Arc::new(Mutex::new(HashMap::new())),
            }),
            timeout: Duration::from_secs(5),
        };

        let read_task = tokio::spawn(read_loop(r, client.clone()));
        let info = client.query_public_ip().await.unwrap();
        assert_eq!(info.ipv4.as_deref(), Some("1.2.3.4"));
        assert!(info.ipv6.is_none());

        node.await.unwrap();
        read_task.abort();
    }
}
