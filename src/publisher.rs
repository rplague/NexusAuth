//! DHT 发布与续期。
//!
//! - 节点握手成功后注册其控制句柄；有连接时发布，无连接时静默等待。
//! - 成员变更（store 提升版本后）触发重签发布；每 `renew_secs` 续期：
//!   索引重签（`expires_at` 前移、`version+1`），白名单重发相同字节刷新 DHT TTL。
//! - 发布顺序：先各服务白名单，后索引（索引引用白名单的 hash/length）。
//! - 每条记录对所有在线连接发布；失败退避重试，下次续期再试。

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{Notify, watch};
use tokio::time::MissedTickBehavior;

use crate::authority::{IndexDoc, ServiceEntry, WhitelistDoc, content_hash, now_unix};
use crate::connection::BackendClient;
use crate::context::AuthContext;
use crate::log::{LogLevel, LogStruct};
use crate::protocol::SidecarError;

/// 单条记录对单个连接的发布重试次数。
const PUBLISH_ATTEMPTS: usize = 3;
/// 首次重试退避。
const PUBLISH_BACKOFF: Duration = Duration::from_millis(200);

struct Inner {
    clients: Mutex<Vec<(u64, BackendClient)>>,
    notify: Notify,
    next_id: AtomicU64,
}

/// 发布句柄：连接注册与发布触发，可 clone 后跨任务使用。
#[derive(Clone)]
pub struct PublisherHandle {
    inner: Arc<Inner>,
}

impl Default for PublisherHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl PublisherHandle {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                clients: Mutex::new(Vec::new()),
                notify: Notify::new(),
                next_id: AtomicU64::new(1),
            }),
        }
    }

    /// 注册一个节点连接，并触发一次发布。返回连接 id。
    pub fn register(&self, client: BackendClient) -> u64 {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        self.inner
            .clients
            .lock()
            .expect("clients poisoned")
            .push((id, client));
        self.inner.notify.notify_one();
        id
    }

    /// 注销连接。
    pub fn unregister(&self, id: u64) {
        self.inner
            .clients
            .lock()
            .expect("clients poisoned")
            .retain(|(i, _)| *i != id);
    }

    /// 请求一次发布（成员变更后调用）。
    pub fn notify_publish(&self) {
        self.inner.notify.notify_one();
    }

    /// 当前在线连接数。
    pub fn connection_count(&self) -> usize {
        self.inner.clients.lock().expect("clients poisoned").len()
    }

    /// 任取一个在线连接（供反熵同步发起请求）。
    pub fn any_client(&self) -> Option<BackendClient> {
        self.inner
            .clients
            .lock()
            .expect("clients poisoned")
            .first()
            .map(|(_, c)| c.clone())
    }

    fn is_empty(&self) -> bool {
        self.inner
            .clients
            .lock()
            .expect("clients poisoned")
            .is_empty()
    }

    async fn notified(&self) {
        self.inner.notify.notified().await;
    }

    /// 把一条记录发布到所有在线连接。
    async fn publish(&self, key: &str, value: Vec<u8>) {
        let clients = self.inner.clients.lock().expect("clients poisoned").clone();
        for (id, client) in clients {
            if let Err(e) = add_key_with_retry(&client, key, value.clone()).await {
                LogStruct::new(
                    LogLevel::Warning,
                    "发布失败",
                    format!("conn#{id} {key}: [{}] {}", e.code, e.message),
                )
                .emit();
            }
        }
    }
}

/// 发布循环：连接事件 / 成员变更 / 定时续期。
pub async fn run(
    handle: PublisherHandle,
    ctx: Arc<AuthContext>,
    renew_secs: u64,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let period = Duration::from_secs(renew_secs.max(1));
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // 消费立即触发的首次 tick，续期从下一个周期开始。
    interval.tick().await;

    loop {
        tokio::select! {
            _ = handle.notified() => publish_once(&ctx, &handle, false).await,
            _ = interval.tick() => publish_once(&ctx, &handle, true).await,
            _ = shutdown_rx.changed() => break,
        }
    }
}

/// 发布一轮：`renew` 为真时先提升索引版本。
async fn publish_once(ctx: &AuthContext, handle: &PublisherHandle, renew: bool) {
    if handle.is_empty() {
        return;
    }
    if renew {
        ctx.store
            .lock()
            .expect("store poisoned")
            .bump_index_version();
    }

    let (index_version, services) = {
        let store = ctx.store.lock().expect("store poisoned");
        let services: Vec<(String, u64, Vec<String>)> = store
            .service_names()
            .into_iter()
            .map(|name| {
                let version = store.version(&name).unwrap_or(1);
                let members = store.members(&name).unwrap_or_default();
                (name, version, members)
            })
            .collect();
        (store.index_version(), services)
    };

    let mut entries = Vec::with_capacity(services.len());
    for (name, version, members) in services {
        let doc = WhitelistDoc { version, members };
        let value = match ctx.authority.sign_whitelist(&name, &doc) {
            Ok(v) => v,
            Err(e) => {
                LogStruct::new(LogLevel::Error, "白名单签名失败", format!("{name}: {e}")).emit();
                continue;
            }
        };
        let key = match ctx.authority.service_key(&name) {
            Ok(k) => k,
            Err(e) => {
                LogStruct::new(LogLevel::Error, "服务名非法", format!("{name}: {e}")).emit();
                continue;
            }
        };
        entries.push(ServiceEntry {
            name: name.clone(),
            hash: content_hash(&value),
            length: value.len() as u64,
        });
        handle.publish(&key, value).await;
    }

    let index = IndexDoc {
        version: index_version,
        expires_at: now_unix() + ctx.expires_secs,
        services: entries,
    };
    match ctx.authority.sign_index(&index) {
        Ok(bytes) => handle.publish(&ctx.authority.index_key(), bytes).await,
        Err(e) => {
            LogStruct::new(LogLevel::Error, "索引签名失败", e.to_string()).emit();
        }
    }
}

async fn add_key_with_retry(
    client: &BackendClient,
    key: &str,
    value: Vec<u8>,
) -> Result<(), SidecarError> {
    let mut backoff = PUBLISH_BACKOFF;
    let mut last = SidecarError::new("publish_failed", "no attempt made");
    for attempt in 0..PUBLISH_ATTEMPTS {
        match client.add_key(key, Some(value.clone()), false).await {
            Ok(_) => return Ok(()),
            Err(e) => last = e,
        }
        if attempt + 1 < PUBLISH_ATTEMPTS {
            tokio::time::sleep(backoff).await;
            backoff *= 2;
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Mutex as StdMutex;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use coset::CborSerializable;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    use crate::admin::AdminAuth;
    use crate::authority::Authority;
    use crate::connection;
    use crate::protocol::{self, AddKeyResult, Message, PROTOCOL_VERSION};
    use crate::store::Store;

    struct Fixture {
        ctx: Arc<AuthContext>,
        dir: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn peer() -> String {
        libp2p_identity::PeerId::random().to_string()
    }

    fn fixture() -> Fixture {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nexusauth-publisher-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        let network = "myorg";
        let authority = Authority::generate(network).unwrap();
        let mut initial = BTreeMap::new();
        initial.insert("cmd".to_string(), vec![peer()]);
        let store = Store::load_or_create(dir.join("auth_state.toml"), network, &initial).unwrap();
        let ctx = Arc::new(AuthContext {
            authority,
            store: StdMutex::new(store),
            admin: AdminAuth::new("pw", network).unwrap(),
            join: crate::join::JoinServer::new("pw", true),
            replicate: crate::replicate::RepAuth::new("pw", network).unwrap(),
            network: network.to_string(),
            service_name: "auth".to_string(),
            expires_secs: 3600,
            renew_secs: 1,
            started_at: Instant::now(),
            publisher: PublisherHandle::new(),
        });
        Fixture { ctx, dir }
    }

    /// 启动边车侧监听 + 发布循环，返回端口。
    async fn start_sidecar(ctx: Arc<AuthContext>, renew_secs: u64) -> u16 {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = ctx.publisher.clone();
        tokio::spawn(run(handle, ctx.clone(), renew_secs, shutdown_rx));
        // 防止 shutdown_tx 被提前 drop
        std::mem::forget(shutdown_tx);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let runtime = crate::runtime::Runtime::ready_for_test(ctx);
                    let _ = connection::handle_connection(stream, runtime).await;
                });
            }
        });
        port
    }

    /// 作为「节点」连接边车，握手后把收到的 `add_key` 转发到 channel 并回复。
    async fn spawn_node(port: u16) -> mpsc::UnboundedReceiver<(String, Vec<u8>)> {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let (mut r, mut w) = stream.into_split();
            protocol::write_frame(
                &mut w,
                &Message::Hello {
                    version: PROTOCOL_VERSION,
                },
            )
            .await
            .unwrap();
            let _ = protocol::read_frame(&mut r).await.unwrap();
            while let Ok(Message::AddKey { id, key, value, .. }) =
                protocol::read_frame(&mut r).await
            {
                let mut body = Vec::new();
                ciborium::ser::into_writer(
                    &AddKeyResult {
                        success: true,
                        key: key.clone(),
                    },
                    &mut body,
                )
                .unwrap();
                if protocol::write_frame(
                    &mut w,
                    &Message::Reply {
                        id,
                        ok: true,
                        result: Some(body),
                        error: None,
                    },
                )
                .await
                .is_err()
                {
                    break;
                }
                // providing-only（成员发现宣告）不计入发布记录
                let Some(val) = value else { continue };
                if tx.send((key, val)).is_err() {
                    break;
                }
            }
        });
        rx
    }

    async fn recv(rx: &mut mpsc::UnboundedReceiver<(String, Vec<u8>)>) -> (String, Vec<u8>) {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("等待发布超时")
            .expect("节点任务结束")
    }

    fn decode_payload(value: &[u8]) -> Vec<u8> {
        coset::CoseSign1::from_slice(value)
            .unwrap()
            .payload
            .unwrap()
    }

    #[tokio::test]
    async fn publishes_whitelist_then_index_on_connect() {
        let fx = fixture();
        let port = start_sidecar(fx.ctx.clone(), 60).await;
        let mut rx = spawn_node(port).await;

        let (k1, v1) = recv(&mut rx).await;
        assert_eq!(k1, fx.ctx.authority.service_key("cmd").unwrap());
        let (k2, v2) = recv(&mut rx).await;
        assert_eq!(k2, fx.ctx.authority.index_key());

        let index: IndexDoc = ciborium::de::from_reader(decode_payload(&v2).as_slice()).unwrap();
        assert_eq!(index.services.len(), 1);
        assert_eq!(index.services[0].name, "cmd");
        assert_eq!(index.services[0].hash, content_hash(&v1));
        assert_eq!(index.services[0].length, v1.len() as u64);
        assert!(index.expires_at > now_unix());
        assert_eq!(index.version, 1);
    }

    #[tokio::test]
    async fn member_change_triggers_republish() {
        let fx = fixture();
        let port = start_sidecar(fx.ctx.clone(), 60).await;
        let mut rx = spawn_node(port).await;

        // 初次发布
        let _ = recv(&mut rx).await;
        let _ = recv(&mut rx).await;

        // 变更成员并触发发布
        fx.ctx
            .store
            .lock()
            .unwrap()
            .add_members("cmd", &[peer()])
            .unwrap();
        fx.ctx.publisher.notify_publish();

        let (k1, v1) = recv(&mut rx).await;
        assert_eq!(k1, fx.ctx.authority.service_key("cmd").unwrap());
        let (k2, v2) = recv(&mut rx).await;
        assert_eq!(k2, fx.ctx.authority.index_key());

        let doc: WhitelistDoc = ciborium::de::from_reader(decode_payload(&v1).as_slice()).unwrap();
        assert_eq!(doc.version, 2);
        assert_eq!(doc.members.len(), 2);

        let index: IndexDoc = ciborium::de::from_reader(decode_payload(&v2).as_slice()).unwrap();
        assert_eq!(index.version, 2);
        assert_eq!(index.services[0].hash, content_hash(&v1));
    }

    #[tokio::test]
    async fn renew_bumps_index_version() {
        let fx = fixture();
        let port = start_sidecar(fx.ctx.clone(), 1).await;
        let mut rx = spawn_node(port).await;

        // 初次发布
        let _ = recv(&mut rx).await;
        let (_, v1) = recv(&mut rx).await;
        let first: IndexDoc = ciborium::de::from_reader(decode_payload(&v1).as_slice()).unwrap();
        assert_eq!(first.version, 1);

        // 续期：白名单重发相同字节，索引版本 +1
        let (_, w) = recv(&mut rx).await;
        let (_, v2) = recv(&mut rx).await;
        let second: IndexDoc = ciborium::de::from_reader(decode_payload(&v2).as_slice()).unwrap();
        assert_eq!(second.version, 2);
        assert!(second.expires_at >= first.expires_at);
        // 白名单内容不变（同版本同成员 → 同字节）
        let whitelist: WhitelistDoc =
            ciborium::de::from_reader(decode_payload(&w).as_slice()).unwrap();
        assert_eq!(whitelist.version, 1);
    }

    #[tokio::test]
    async fn management_change_publishes() {
        let fx = fixture();
        let port = start_sidecar(fx.ctx.clone(), 60).await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let ctx = fx.ctx.clone();
        let new_peer = peer();

        // 节点：握手 → 收初次发布 → 发管理指令 → 收再次发布
        tokio::spawn(async move {
            let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let (mut r, mut w) = stream.into_split();
            protocol::write_frame(
                &mut w,
                &Message::Hello {
                    version: PROTOCOL_VERSION,
                },
            )
            .await
            .unwrap();
            let _ = protocol::read_frame(&mut r).await.unwrap();

            let mut published = 0usize;
            let mut sent = false;
            while published < 4 {
                match protocol::read_frame(&mut r).await {
                    Ok(Message::AddKey { id, key, value, .. }) => {
                        let mut body = Vec::new();
                        ciborium::ser::into_writer(
                            &AddKeyResult {
                                success: true,
                                key: key.clone(),
                            },
                            &mut body,
                        )
                        .unwrap();
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
                        // providing-only（成员发现宣告）不计入发布记录
                        let Some(val) = value else { continue };
                        let _ = tx.send((key, val));
                        published += 1;

                        if published == 2 && !sent {
                            sent = true;
                            let nonce = "mgmt-nonce-1";
                            let ts = now_unix();
                            let mac = ctx.admin.compute_mac(
                                "add_members",
                                "cmd",
                                std::slice::from_ref(&new_peer),
                                nonce,
                                ts,
                            );
                            let payload = serde_json::to_vec(&serde_json::json!({
                                "op": "add_members",
                                "service": "cmd",
                                "peers": [new_peer],
                                "nonce": nonce,
                                "ts": ts,
                                "mac": mac,
                            }))
                            .unwrap();
                            protocol::write_frame(
                                &mut w,
                                &Message::Request {
                                    id: uuid::Uuid::new_v4(),
                                    service: "auth".into(),
                                    payload,
                                },
                            )
                            .await
                            .unwrap();
                        }
                    }
                    // 变更广播会先做发现查询：返回空 providers 即可
                    Ok(Message::QueryKey { id, key }) => {
                        let mut body = Vec::new();
                        ciborium::ser::into_writer(
                            &crate::protocol::QueryKeyResult {
                                key,
                                value: None,
                                providers: vec![],
                            },
                            &mut body,
                        )
                        .unwrap();
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
                    Ok(Message::ServiceRequestTo { id, .. }) => {
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
                    Ok(Message::Reply { ok, .. }) => assert!(ok),
                    _ => break,
                }
            }
        });

        // 初次发布
        let (k1, _) = recv(&mut rx).await;
        assert_eq!(k1, fx.ctx.authority.service_key("cmd").unwrap());
        let (_, v1) = recv(&mut rx).await;
        let first: IndexDoc = ciborium::de::from_reader(decode_payload(&v1).as_slice()).unwrap();
        assert_eq!(first.version, 1);

        // 管理指令触发的再次发布
        let (k2, w2) = recv(&mut rx).await;
        assert_eq!(k2, fx.ctx.authority.service_key("cmd").unwrap());
        let (_, v2) = recv(&mut rx).await;
        let second: IndexDoc = ciborium::de::from_reader(decode_payload(&v2).as_slice()).unwrap();
        assert_eq!(second.version, 2);

        let doc: WhitelistDoc = ciborium::de::from_reader(decode_payload(&w2).as_slice()).unwrap();
        assert_eq!(doc.version, 2);
        assert_eq!(doc.members.len(), 2);
    }
}
