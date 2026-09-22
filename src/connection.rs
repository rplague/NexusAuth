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
    RelayStatusResult, SidecarError, SuccessResult, WhoamiResult,
};
use crate::runtime::Runtime;
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

    /// 查询本节点 PeerId
    pub async fn whoami(&self) -> Result<String, SidecarError> {
        let id = Uuid::new_v4();
        let result: WhoamiResult = self.call_result(id, Message::Whoami { id }).await?;
        Ok(result.peer_id)
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

/// 处理单条节点连接：握手后确保就绪（必要时入网），再进入读写循环
pub async fn handle_connection(stream: TcpStream, runtime: Arc<Runtime>) -> std::io::Result<()> {
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

    // 先启动读循环，使入网期间的控制回复能被处理。
    let read_task = tokio::spawn(read_loop(read_half, client.clone(), runtime.clone()));

    // 未就绪时用本连接执行入网。
    let ctx = runtime.ensure_ready(&client).await;
    let conn_id = if ctx.is_some() {
        Some(runtime.publisher.register(client.clone()))
    } else {
        None
    };

    let _ = read_task.await;
    if let Some(id) = conn_id {
        runtime.publisher.unregister(id);
    }
    Ok(())
}

/// 读取节点消息：服务请求派发业务，控制回复唤醒等待者
async fn read_loop(mut read_half: OwnedReadHalf, client: BackendClient, runtime: Arc<Runtime>) {
    loop {
        match protocol::read_frame(&mut read_half).await {
            Ok(Message::Request {
                id,
                service,
                payload,
            }) => {
                let client = client.clone();
                let ctx = runtime.ctx();
                tokio::spawn(async move {
                    let reply = match ctx {
                        Some(ctx) => {
                            match service::handle_service_request(
                                &service,
                                &payload,
                                &ctx,
                                Some(&client),
                            )
                            .await
                            {
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
                            }
                        }
                        None => Message::Reply {
                            id,
                            ok: false,
                            result: None,
                            error: Some(SidecarError::new("joining", "边车尚未就绪")),
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

    use crate::admin::AdminAuth;
    use crate::authority::Authority;
    use crate::context::AuthContext;
    use crate::store::Store;

    fn test_ctx() -> Arc<AuthContext> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nexusauth-conn-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let network = "myorg";
        let authority = Authority::generate(network).unwrap();
        let store = Store::load_or_create(
            dir.join("state.toml"),
            network,
            &std::collections::BTreeMap::new(),
        )
        .unwrap();
        Arc::new(AuthContext {
            authority,
            store: std::sync::Mutex::new(store),
            admin: AdminAuth::new("pw", network).unwrap(),
            join: crate::join::JoinServer::new("pw", true),
            replicate: crate::replicate::RepAuth::new("pw", network).unwrap(),
            publisher: crate::publisher::PublisherHandle::new(),
            network: network.to_string(),
            service_name: "auth".to_string(),
            expires_secs: 3600,
            renew_secs: 1200,
            started_at: std::time::Instant::now(),
        })
    }

    async fn spawn_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let runtime = Runtime::ready_for_test(test_ctx());
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_connection(stream, runtime).await;
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
    async fn not_ready_service_request_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let runtime = Runtime::not_ready_for_test();
        let _srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (r, w) = stream.into_split();
            let client = BackendClient {
                shared: Arc::new(Shared {
                    writer: Mutex::new(w),
                    pending: Arc::new(Mutex::new(HashMap::new())),
                }),
                timeout: Duration::from_secs(5),
            };
            let _ = read_loop(r, client, runtime).await;
        });

        let mut stream = connect(port).await;
        let (mut r, mut w) = stream.split();
        let id = Uuid::new_v4();
        protocol::write_frame(
            &mut w,
            &Message::Request {
                id,
                service: "auth".into(),
                payload: b"{}".to_vec(),
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
                assert!(!ok);
                assert!(result.is_none());
                assert_eq!(error.unwrap().code, "joining");
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

        let read_task = tokio::spawn(read_loop(r, client.clone(), Runtime::not_ready_for_test()));
        let info = client.query_public_ip().await.unwrap();
        assert_eq!(info.ipv4.as_deref(), Some("1.2.3.4"));
        assert!(info.ipv6.is_none());

        node.await.unwrap();
        read_task.abort();
    }

    #[tokio::test]
    async fn whoami_call_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let node = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            match protocol::read_frame(&mut r).await.unwrap() {
                Message::Whoami { id } => {
                    let body = enc(&WhoamiResult {
                        peer_id: "12D3KooWtest".into(),
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
        let read_task = tokio::spawn(read_loop(r, client.clone(), Runtime::not_ready_for_test()));
        let peer = client.whoami().await.unwrap();
        assert_eq!(peer, "12D3KooWtest");

        node.await.unwrap();
        read_task.abort();
    }

    #[tokio::test]
    async fn management_request_over_tcp() {
        let ctx = test_ctx();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let runtime = Runtime::ready_for_test(ctx.clone());
        let _srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_connection(stream, runtime).await;
        });

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

        let nonce = "n-test";
        let ts = crate::authority::now_unix();
        let mac = ctx.admin.compute_mac("status", "", &[], nonce, ts);
        let payload = serde_json::to_vec(&serde_json::json!({
            "op": "status", "service": "", "peers": [], "nonce": nonce, "ts": ts, "mac": mac
        }))
        .unwrap();
        let id = Uuid::new_v4();
        protocol::write_frame(
            &mut w,
            &Message::Request {
                id,
                service: "auth".into(),
                payload,
            },
        )
        .await
        .unwrap();

        loop {
            match protocol::read_frame(&mut r).await.unwrap() {
                // 握手后会先收到成员发现宣告（providing-only），回复即可
                Message::AddKey { id: aid, key, .. } => {
                    let body = enc(&AddKeyResult { success: true, key });
                    protocol::write_frame(
                        &mut w,
                        &Message::Reply {
                            id: aid,
                            ok: true,
                            result: Some(body),
                            error: None,
                        },
                    )
                    .await
                    .unwrap();
                }
                Message::Reply {
                    id: rid,
                    ok,
                    result,
                    ..
                } => {
                    assert_eq!(rid, id);
                    assert!(ok);
                    let v: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
                    assert_eq!(v["network"], "myorg");
                    assert_eq!(v["index_version"], 1);
                    break;
                }
                other => panic!("expected reply, got {}", other.kind()),
            }
        }
    }

    #[tokio::test]
    async fn join_attempt_fetches_key_and_state() {
        use crate::config::{ConfigHandle, ServiceConfig};
        use crate::join::{self, JoinRequest};
        use crate::store::{ServiceState, StoreSnapshot};
        use std::collections::{BTreeMap, BTreeSet};

        let password = "high-entropy-password";
        let network = "myorg";

        let responder = Authority::generate(network).unwrap();
        let mut members = BTreeSet::new();
        members.insert(libp2p_identity::PeerId::random().to_string());
        let mut services = BTreeMap::new();
        services.insert(
            "cmd".to_string(),
            ServiceState {
                version: 5,
                members,
            },
        );
        let snapshot = StoreSnapshot {
            network: network.to_string(),
            index_version: 7,
            services,
            tombstones: BTreeMap::new(),
        };
        let responder_peer = libp2p_identity::PeerId::random().to_string();

        // 模拟节点：应答发现 / whoami / 入网请求
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = crate::join::JoinServer::new(password, true);
        let snap = snapshot.clone();
        let responder_seed = responder.seed();
        let rp = responder_peer.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            while let Ok(msg) = protocol::read_frame(&mut r).await {
                match msg {
                    Message::DiscoverProviders { id, .. } => {
                        let body = enc(&vec![rp.clone()]);
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
                    Message::Whoami { id } => {
                        let body = enc(&WhoamiResult {
                            peer_id: "12D3KooWself".into(),
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
                    Message::QueryKey { id, key } => {
                        // 索引 key 无记录（跳过验签）
                        let body = enc(&QueryKeyResult {
                            key,
                            value: None,
                            providers: vec![],
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
                    Message::ServiceRequestTo { id, payload, .. } => {
                        let req: JoinRequest = serde_json::from_slice(&payload).unwrap();
                        let resp = server
                            .respond(
                                network,
                                &req,
                                crate::authority::now_unix(),
                                &responder_seed,
                                &snap,
                            )
                            .unwrap();
                        let bytes = serde_json::to_vec(&resp).unwrap();
                        protocol::write_frame(
                            &mut w,
                            &Message::Reply {
                                id,
                                ok: true,
                                result: Some(bytes),
                                error: None,
                            },
                        )
                        .await
                        .unwrap();
                    }
                    _ => break,
                }
            }
        });

        // 新边车配置（无本地密钥，require 入网）
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nexusauth-join-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let mut sc = ServiceConfig::default();
        sc.network = network.into();
        sc.management_password = password.into();
        sc.join_mode = "require".into();
        sc.join_service = "auth".into();
        sc.authority_key_path = dir.join("authority.key").to_string_lossy().into_owned();
        sc.state_path = dir.join("auth_state.toml").to_string_lossy().into_owned();
        let config = ConfigHandle::new(sc);

        let stream = connect(port).await;
        let (r, w) = stream.into_split();
        let client = BackendClient {
            shared: Arc::new(Shared {
                writer: Mutex::new(w),
                pending: Arc::new(Mutex::new(HashMap::new())),
            }),
            timeout: Duration::from_secs(5),
        };
        let read_task = tokio::spawn(read_loop(r, client.clone(), Runtime::not_ready_for_test()));

        let (authority, store) = join::attempt(&client, &config).await.unwrap();
        assert_eq!(authority.public_key_b64(), responder.public_key_b64());
        assert_eq!(store.index_version(), 7);
        assert_eq!(store.version("cmd"), Some(5));
        assert_eq!(store.members("cmd").unwrap().len(), 1);
        assert!(dir.join("authority.key").exists());
        assert!(dir.join("auth_state.toml").exists());

        read_task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn join_prefers_join_peers() {
        use crate::config::{ConfigHandle, ServiceConfig};
        use crate::join::{self, JoinRequest};
        use crate::store::StoreSnapshot;

        let password = "pw";
        let network = "myorg";
        let responder = Authority::generate(network).unwrap();
        let responder_seed = responder.seed();
        let snap = StoreSnapshot {
            network: network.to_string(),
            index_version: 1,
            services: std::collections::BTreeMap::new(),
            tombstones: std::collections::BTreeMap::new(),
        };
        let server = crate::join::JoinServer::new(password, true);

        let x = libp2p_identity::PeerId::random().to_string();
        let y = libp2p_identity::PeerId::random().to_string();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let y2 = y.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            while let Ok(msg) = protocol::read_frame(&mut r).await {
                match msg {
                    Message::Whoami { id } => {
                        let body = enc(&WhoamiResult {
                            peer_id: "12D3KooWself".into(),
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
                    Message::DiscoverProviders { id, .. } => {
                        let body = enc(&vec![y2.clone()]);
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
                    Message::QueryKey { id, key } => {
                        let body = enc(&QueryKeyResult {
                            key,
                            value: None,
                            providers: vec![],
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
                    Message::ServiceRequestTo {
                        id, peer, payload, ..
                    } => {
                        let _ = tx.send(peer.clone());
                        if peer == y2 {
                            let req: JoinRequest = serde_json::from_slice(&payload).unwrap();
                            let resp = server
                                .respond(
                                    network,
                                    &req,
                                    crate::authority::now_unix(),
                                    &responder_seed,
                                    &snap,
                                )
                                .unwrap();
                            let bytes = serde_json::to_vec(&resp).unwrap();
                            protocol::write_frame(
                                &mut w,
                                &Message::Reply {
                                    id,
                                    ok: true,
                                    result: Some(bytes),
                                    error: None,
                                },
                            )
                            .await
                            .unwrap();
                        } else {
                            protocol::write_frame(
                                &mut w,
                                &Message::Reply {
                                    id,
                                    ok: false,
                                    result: None,
                                    error: Some(crate::protocol::SidecarError::new(
                                        "no_authority",
                                        "not the authority",
                                    )),
                                },
                            )
                            .await
                            .unwrap();
                        }
                    }
                    _ => break,
                }
            }
        });

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nexusauth-join-order-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let mut sc = ServiceConfig::default();
        sc.network = network.into();
        sc.management_password = password.into();
        sc.join_mode = "require".into();
        sc.join_service = "auth".into();
        sc.join_peers = vec![x.clone()];
        sc.authority_key_path = dir.join("authority.key").to_string_lossy().into_owned();
        sc.state_path = dir.join("auth_state.toml").to_string_lossy().into_owned();
        let config = ConfigHandle::new(sc);

        let stream = connect(port).await;
        let (r, w) = stream.into_split();
        let client = BackendClient {
            shared: Arc::new(Shared {
                writer: Mutex::new(w),
                pending: Arc::new(Mutex::new(HashMap::new())),
            }),
            timeout: Duration::from_secs(5),
        };
        let read_task = tokio::spawn(read_loop(r, client.clone(), Runtime::not_ready_for_test()));

        let (authority, _store) = join::attempt(&client, &config).await.unwrap();
        assert_eq!(authority.public_key_b64(), responder.public_key_b64());

        // 目标顺序应为 [join_peers 的 X, 发现到的 Y]
        assert_eq!(rx.recv().await.unwrap(), x);
        assert_eq!(rx.recv().await.unwrap(), y);

        read_task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn join_attempt_no_candidates() {
        use crate::config::{ConfigHandle, ServiceConfig};
        use crate::join::{self, JoinError};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            while let Ok(msg) = protocol::read_frame(&mut r).await {
                match msg {
                    Message::DiscoverProviders { id, .. } => {
                        let body = enc(&Vec::<String>::new());
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
                    Message::Whoami { id } => {
                        let body = enc(&WhoamiResult {
                            peer_id: "12D3KooWself".into(),
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
                    _ => break,
                }
            }
        });

        let stream = connect(port).await;
        let (r, w) = stream.into_split();
        let client = BackendClient {
            shared: Arc::new(Shared {
                writer: Mutex::new(w),
                pending: Arc::new(Mutex::new(HashMap::new())),
            }),
            timeout: Duration::from_secs(5),
        };
        let read_task = tokio::spawn(read_loop(r, client.clone(), Runtime::not_ready_for_test()));

        let config = ConfigHandle::new(ServiceConfig {
            network: "myorg".into(),
            management_password: "pw".into(),
            ..Default::default()
        });
        let err = match join::attempt(&client, &config).await {
            Err(e) => e,
            Ok(_) => panic!("expected NoCandidates"),
        };
        assert!(matches!(err, JoinError::NoCandidates));

        read_task.abort();
    }

    #[tokio::test]
    async fn replicate_broadcast_sends_signed_change() {
        use crate::replicate;

        let ctx = test_ctx();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer_id = libp2p_identity::PeerId::random().to_string();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let rp = peer_id.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            while let Ok(msg) = protocol::read_frame(&mut r).await {
                match msg {
                    Message::DiscoverProviders { id, .. } => {
                        let body = enc(&vec![rp.clone()]);
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
                    Message::Whoami { id } => {
                        let body = enc(&WhoamiResult {
                            peer_id: "12D3KooWself".into(),
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
                    Message::ServiceRequestTo { id, payload, .. } => {
                        let _ = tx.send(payload);
                        protocol::write_frame(
                            &mut w,
                            &Message::Reply {
                                id,
                                ok: true,
                                result: Some(vec![]),
                                error: None,
                            },
                        )
                        .await
                        .unwrap();
                    }
                    _ => break,
                }
            }
        });

        let stream = connect(port).await;
        let (r, w) = stream.into_split();
        let client = BackendClient {
            shared: Arc::new(Shared {
                writer: Mutex::new(w),
                pending: Arc::new(Mutex::new(HashMap::new())),
            }),
            timeout: Duration::from_secs(5),
        };
        let read_task = tokio::spawn(read_loop(r, client.clone(), Runtime::not_ready_for_test()));

        replicate::broadcast(&ctx, &client, "cmd", 5, vec!["peerA".to_string()], 7, false).await;

        let payload = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .expect("broadcast payload");
        let msg: replicate::ReplicateMsg = serde_json::from_slice(&payload).unwrap();
        assert_eq!(msg.service, "cmd");
        assert_eq!(msg.version, 5);
        assert_eq!(msg.members, vec!["peerA".to_string()]);
        assert_eq!(msg.index_version, 7);
        assert!(
            ctx.replicate
                .verify_replicate(&msg, crate::authority::now_unix())
                .is_ok()
        );

        read_task.abort();
    }

    #[tokio::test]
    async fn sync_once_merges_peer_snapshot() {
        use crate::replicate;
        use crate::store::{ServiceState, StoreSnapshot};
        use std::collections::{BTreeMap, BTreeSet};

        let ctx = test_ctx();
        ctx.store
            .lock()
            .unwrap()
            .create_service("cmd", &[])
            .unwrap();

        let mut services = BTreeMap::new();
        services.insert(
            "cmd".to_string(),
            ServiceState {
                version: 9,
                members: std::iter::once(libp2p_identity::PeerId::random().to_string())
                    .collect::<BTreeSet<_>>(),
            },
        );
        let snapshot = StoreSnapshot {
            network: "myorg".to_string(),
            index_version: 12,
            services,
            tombstones: BTreeMap::new(),
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer_id = libp2p_identity::PeerId::random().to_string();
        let rp = peer_id.clone();
        let snap = snapshot.clone();
        tokio::spawn(async move {
            let rep = replicate::RepAuth::new("pw", "myorg").unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            while let Ok(msg) = protocol::read_frame(&mut r).await {
                match msg {
                    Message::DiscoverProviders { id, .. } => {
                        let body = enc(&vec![rp.clone()]);
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
                    Message::Whoami { id } => {
                        let body = enc(&WhoamiResult {
                            peer_id: "12D3KooWself".into(),
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
                    Message::ServiceRequestTo { id, payload, .. } => {
                        let req: replicate::SyncRequest = serde_json::from_slice(&payload).unwrap();
                        let ts = crate::authority::now_unix();
                        let mac = rep
                            .sign_sync_response("myorg", &req.nonce, &snap, ts)
                            .unwrap();
                        let resp = replicate::SyncResponse {
                            op: replicate::OP_SYNC_RESPONSE.to_string(),
                            nonce: req.nonce,
                            snapshot: snap.clone(),
                            ts,
                            mac,
                        };
                        let bytes = serde_json::to_vec(&resp).unwrap();
                        protocol::write_frame(
                            &mut w,
                            &Message::Reply {
                                id,
                                ok: true,
                                result: Some(bytes),
                                error: None,
                            },
                        )
                        .await
                        .unwrap();
                    }
                    _ => break,
                }
            }
        });

        let stream = connect(port).await;
        let (r, w) = stream.into_split();
        let client = BackendClient {
            shared: Arc::new(Shared {
                writer: Mutex::new(w),
                pending: Arc::new(Mutex::new(HashMap::new())),
            }),
            timeout: Duration::from_secs(5),
        };
        let read_task = tokio::spawn(read_loop(r, client.clone(), Runtime::not_ready_for_test()));

        let changed = replicate::sync_once(&ctx, &client).await;
        assert!(changed);
        assert_eq!(ctx.store.lock().unwrap().version("cmd"), Some(9));
        assert_eq!(ctx.store.lock().unwrap().index_version(), 12);

        read_task.abort();
    }

    #[tokio::test]
    async fn sync_once_tries_next_candidate() {
        use crate::replicate;
        use crate::store::{ServiceState, StoreSnapshot};
        use std::collections::{BTreeMap, BTreeSet};

        let ctx = test_ctx();
        ctx.store
            .lock()
            .unwrap()
            .create_service("cmd", &[])
            .unwrap();

        let mut services = BTreeMap::new();
        services.insert(
            "cmd".to_string(),
            ServiceState {
                version: 9,
                members: std::iter::once(libp2p_identity::PeerId::random().to_string())
                    .collect::<BTreeSet<_>>(),
            },
        );
        let snapshot = StoreSnapshot {
            network: "myorg".to_string(),
            index_version: 12,
            services,
            tombstones: BTreeMap::new(),
        };

        let bad = libp2p_identity::PeerId::random().to_string();
        let good = libp2p_identity::PeerId::random().to_string();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let good2 = good.clone();
        let snap = snapshot.clone();
        tokio::spawn(async move {
            let rep = replicate::RepAuth::new("pw", "myorg").unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            while let Ok(msg) = protocol::read_frame(&mut r).await {
                match msg {
                    Message::Whoami { id } => {
                        let body = enc(&WhoamiResult {
                            peer_id: "12D3KooWself".into(),
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
                    Message::DiscoverProviders { id, .. } => {
                        let body = enc(&vec![bad.clone(), good2.clone()]);
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
                    Message::ServiceRequestTo {
                        id, peer, payload, ..
                    } => {
                        if peer == good2 {
                            let req: replicate::SyncRequest =
                                serde_json::from_slice(&payload).unwrap();
                            let ts = crate::authority::now_unix();
                            let mac = rep
                                .sign_sync_response("myorg", &req.nonce, &snap, ts)
                                .unwrap();
                            let resp = replicate::SyncResponse {
                                op: replicate::OP_SYNC_RESPONSE.to_string(),
                                nonce: req.nonce,
                                snapshot: snap.clone(),
                                ts,
                                mac,
                            };
                            let bytes = serde_json::to_vec(&resp).unwrap();
                            protocol::write_frame(
                                &mut w,
                                &Message::Reply {
                                    id,
                                    ok: true,
                                    result: Some(bytes),
                                    error: None,
                                },
                            )
                            .await
                            .unwrap();
                        } else {
                            protocol::write_frame(
                                &mut w,
                                &Message::Reply {
                                    id,
                                    ok: false,
                                    result: None,
                                    error: Some(crate::protocol::SidecarError::new(
                                        "no_authority",
                                        "not the authority",
                                    )),
                                },
                            )
                            .await
                            .unwrap();
                        }
                    }
                    _ => break,
                }
            }
        });

        let stream = connect(port).await;
        let (r, w) = stream.into_split();
        let client = BackendClient {
            shared: Arc::new(Shared {
                writer: Mutex::new(w),
                pending: Arc::new(Mutex::new(HashMap::new())),
            }),
            timeout: Duration::from_secs(5),
        };
        let read_task = tokio::spawn(read_loop(r, client.clone(), Runtime::not_ready_for_test()));

        // 候选中有一个坏对端 + 一个好对端：应跳过失败并最终成功
        let changed = replicate::sync_once(&ctx, &client).await;
        assert!(changed);
        assert_eq!(ctx.store.lock().unwrap().version("cmd"), Some(9));
        assert_eq!(ctx.store.lock().unwrap().index_version(), 12);

        read_task.abort();
    }
}
