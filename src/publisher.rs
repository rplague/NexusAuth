//! DHT 发布与续期。
//!
//! - Raft 模式：只有 leader 发布，内容来自 state machine 快照；
//!   续期通过 `PolicyCommand::RenewIndex { expires_at }` 进入 Raft log。
//! - 旧模式（`cluster.enabled = false`）：保留多写者发布与本地 `bump_index_version`。
//! - 发布顺序：先各服务白名单，全部成功后才发布索引。
//! - 任一白名单失败时索引不得发布；失败退避重试，记录可见状态。

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
use crate::raft::types::PolicyCommand;

/// 单条记录对单个连接的发布重试次数。
const PUBLISH_ATTEMPTS: usize = 3;
/// 首次重试退避。
const PUBLISH_BACKOFF: Duration = Duration::from_millis(200);
/// 一轮发布失败后的整体重试次数（仅后台发布循环）。
const PUBLISH_ROUND_ATTEMPTS: usize = 3;

/// 最近一次发布尝试的可见状态。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublishStatus {
    pub last_publish_epoch: Option<u64>,
    pub last_publish_ok: bool,
    pub last_publish_error: Option<String>,
    pub last_publish_at: Option<u64>,
}

/// 一轮发布的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    Published { policy_epoch: u64 },
    NoConnections,
    NotLeader,
}

/// 发布失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishError {
    pub message: String,
}

impl PublishError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PublishError {}

struct Inner {
    clients: Mutex<Vec<(u64, BackendClient)>>,
    publish_notify: Notify,
    renew_notify: Notify,
    next_id: AtomicU64,
    status: Mutex<PublishStatus>,
    publish_lock: tokio::sync::Mutex<()>,
    #[cfg(test)]
    forced_error: Mutex<Option<String>>,
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
                publish_notify: Notify::new(),
                renew_notify: Notify::new(),
                next_id: AtomicU64::new(1),
                status: Mutex::new(PublishStatus::default()),
                publish_lock: tokio::sync::Mutex::new(()),
                #[cfg(test)]
                forced_error: Mutex::new(None),
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
        self.inner.publish_notify.notify_one();
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

    /// 请求一次发布（成员变更后调用）；Raft 模式下 epoch 已由 apply 推进。
    pub fn notify_publish(&self) {
        self.inner.publish_notify.notify_one();
    }

    /// 请求一次续期后发布（leader 变更、定时续期、publish_now）。
    pub fn notify_renew(&self) {
        self.inner.renew_notify.notify_one();
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

    /// 最近一次发布尝试的状态。
    pub fn status(&self) -> PublishStatus {
        self.inner
            .status
            .lock()
            .expect("publish status poisoned")
            .clone()
    }

    fn is_empty(&self) -> bool {
        self.inner
            .clients
            .lock()
            .expect("clients poisoned")
            .is_empty()
    }

    async fn notified(&self) {
        self.inner.publish_notify.notified().await;
    }

    async fn renew_notified(&self) {
        self.inner.renew_notify.notified().await;
    }

    fn record_success(&self, epoch: u64) {
        let mut status = self.inner.status.lock().expect("publish status poisoned");
        status.last_publish_epoch = Some(epoch);
        status.last_publish_ok = true;
        status.last_publish_error = None;
        status.last_publish_at = Some(now_unix());
    }

    fn record_failure(&self, epoch: Option<u64>, error: &str) {
        let mut status = self.inner.status.lock().expect("publish status poisoned");
        if let Some(epoch) = epoch {
            status.last_publish_epoch = Some(match status.last_publish_epoch {
                Some(previous) => previous.max(epoch),
                None => epoch,
            });
        }
        status.last_publish_ok = false;
        status.last_publish_error = Some(error.to_string());
        status.last_publish_at = Some(now_unix());
    }

    #[cfg(test)]
    pub fn force_next_publish_error(&self, message: impl Into<String>) {
        *self
            .inner
            .forced_error
            .lock()
            .expect("forced error poisoned") = Some(message.into());
    }

    #[cfg(test)]
    fn take_forced_error(&self) -> Option<String> {
        self.inner
            .forced_error
            .lock()
            .expect("forced error poisoned")
            .take()
    }

    /// 把一条记录发布到所有在线连接；任一连接失败即返回错误。
    async fn publish(&self, key: &str, value: Vec<u8>) -> Result<(), PublishError> {
        let clients = self.inner.clients.lock().expect("clients poisoned").clone();
        let mut first_error = None;
        for (id, client) in clients {
            if let Err(e) = add_key_with_retry(&client, key, value.clone()).await {
                let message = format!("conn#{id} {key}: [{}] {}", e.code, e.message);
                LogStruct::new(LogLevel::Warning, "发布失败", message.clone()).emit();
                if first_error.is_none() {
                    first_error = Some(message);
                }
            }
        }
        match first_error {
            Some(message) => Err(PublishError::new(message)),
            None => Ok(()),
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
            _ = handle.notified() => run_publish_round(&ctx, &handle, false).await,
            _ = handle.renew_notified() => run_publish_round(&ctx, &handle, true).await,
            _ = interval.tick() => run_publish_round(&ctx, &handle, true).await,
            _ = shutdown_rx.changed() => break,
        }
    }
}

async fn run_publish_round(ctx: &Arc<AuthContext>, handle: &PublisherHandle, renew: bool) {
    match publish_with_retry(ctx, handle, renew, PUBLISH_ROUND_ATTEMPTS).await {
        Ok(_) => {}
        Err(e) => LogStruct::new(LogLevel::Warning, "发布失败", e.to_string()).emit(),
    }
}

async fn publish_with_retry(
    ctx: &Arc<AuthContext>,
    handle: &PublisherHandle,
    renew: bool,
    attempts: usize,
) -> Result<PublishOutcome, PublishError> {
    let mut backoff = PUBLISH_BACKOFF;
    let mut last = PublishError::new("publish not attempted");
    for attempt in 0..attempts.max(1) {
        match publish_once(ctx, handle, renew).await {
            Ok(outcome) => return Ok(outcome),
            Err(e) => last = e,
        }
        if attempt + 1 < attempts {
            tokio::time::sleep(backoff).await;
            backoff *= 2;
        }
    }
    Err(last)
}

/// 触发一次发布（leader 模式下会按需先续期）。
pub async fn publish_now(
    ctx: &Arc<AuthContext>,
    renew: bool,
) -> Result<PublishOutcome, PublishError> {
    let handle = ctx.publisher.clone();
    publish_once(ctx, &handle, renew).await
}

/// 发布一轮：`renew` 为真时先通过 Raft 提案续期。
async fn publish_once(
    ctx: &Arc<AuthContext>,
    handle: &PublisherHandle,
    renew: bool,
) -> Result<PublishOutcome, PublishError> {
    let _guard = handle.inner.publish_lock.lock().await;

    #[cfg(test)]
    if let Some(message) = handle.take_forced_error() {
        handle.record_failure(None, &message);
        return Err(PublishError::new(message));
    }

    if handle.is_empty() {
        return Ok(PublishOutcome::NoConnections);
    }

    if ctx.raft_required {
        return publish_once_raft(ctx, handle, renew).await;
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
    let expires_at = now_unix().saturating_add(ctx.expires_secs);
    let entries = publish_whitelists(ctx, handle, services).await?;
    publish_index(ctx, handle, index_version, expires_at, entries).await?;
    handle.record_success(index_version);
    Ok(PublishOutcome::Published {
        policy_epoch: index_version,
    })
}

async fn publish_once_raft(
    ctx: &Arc<AuthContext>,
    handle: &PublisherHandle,
    renew: bool,
) -> Result<PublishOutcome, PublishError> {
    let raft = ctx
        .admin_raft
        .read()
        .expect("admin raft poisoned")
        .clone()
        .ok_or_else(|| PublishError::new("raft_not_ready: Raft 控制面尚未就绪"))?;

    if !raft.is_leader().await {
        return Ok(PublishOutcome::NotLeader);
    }

    let mut state = raft.policy_snapshot().await;
    let now = now_unix();
    if renew || state.index_expires_at <= now {
        let expires_at = now.saturating_add(ctx.expires_secs);
        if let Err(e) = raft.propose(PolicyCommand::RenewIndex { expires_at }).await {
            let message = format!("renew_index failed: {e}");
            handle.record_failure(Some(state.policy_epoch), &message);
            return Err(PublishError::new(message));
        }
        state = raft.policy_snapshot().await;
    }

    if !raft.is_leader().await {
        return Ok(PublishOutcome::NotLeader);
    }

    let epoch = state.policy_epoch;
    if let Some(last_epoch) = handle.status().last_publish_epoch
        && epoch < last_epoch
    {
        let message = format!("stale policy_epoch {epoch} < last_publish_epoch {last_epoch}");
        handle.record_failure(Some(epoch), &message);
        return Err(PublishError::new(message));
    }
    if state.index_expires_at == 0 {
        let message = "state machine has no index expires_at".to_string();
        handle.record_failure(Some(epoch), &message);
        return Err(PublishError::new(message));
    }

    let services: Vec<(String, u64, Vec<String>)> = state
        .services
        .iter()
        .map(|(name, service)| {
            (
                name.clone(),
                service.version,
                service.members.iter().cloned().collect(),
            )
        })
        .collect();
    let entries = match publish_whitelists(ctx, handle, services).await {
        Ok(entries) => entries,
        Err(e) => {
            handle.record_failure(Some(epoch), &e.to_string());
            return Err(e);
        }
    };

    if !raft.is_leader().await {
        let message = "lost leadership before publishing index".to_string();
        handle.record_failure(Some(epoch), &message);
        return Err(PublishError::new(message));
    }

    if let Err(e) = publish_index(ctx, handle, epoch, state.index_expires_at, entries).await {
        handle.record_failure(Some(epoch), &e.to_string());
        return Err(e);
    }
    handle.record_success(epoch);
    Ok(PublishOutcome::Published {
        policy_epoch: epoch,
    })
}

async fn publish_whitelists(
    ctx: &AuthContext,
    handle: &PublisherHandle,
    services: Vec<(String, u64, Vec<String>)>,
) -> Result<Vec<ServiceEntry>, PublishError> {
    let authority = ctx
        .authority()
        .ok_or_else(|| PublishError::new("learner has no authority seed; refusing to publish"))?;
    let mut pending = Vec::with_capacity(services.len());
    let mut entries = Vec::with_capacity(services.len());
    for (name, version, members) in services {
        let doc = WhitelistDoc { version, members };
        let value = authority
            .sign_whitelist(&name, &doc)
            .map_err(|e| PublishError::new(format!("whitelist sign failed for {name}: {e}")))?;
        let key = authority
            .service_key(&name)
            .map_err(|e| PublishError::new(format!("invalid service {name}: {e}")))?;
        entries.push(ServiceEntry {
            name: name.clone(),
            hash: content_hash(&value),
            length: value.len() as u64,
        });
        pending.push((key, value));
    }

    for (key, value) in pending {
        handle.publish(&key, value).await?;
    }
    Ok(entries)
}

async fn publish_index(
    ctx: &AuthContext,
    handle: &PublisherHandle,
    index_version: u64,
    expires_at: u64,
    services: Vec<ServiceEntry>,
) -> Result<(), PublishError> {
    let index = IndexDoc {
        version: index_version,
        expires_at,
        services,
    };
    let authority = ctx
        .authority()
        .ok_or_else(|| PublishError::new("learner has no authority seed; refusing to publish"))?;
    let bytes = authority
        .sign_index(&index)
        .map_err(|e| PublishError::new(format!("index sign failed: {e}")))?;
    handle.publish(&authority.index_key(), bytes).await
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
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use coset::CborSerializable;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    use crate::admin::AdminAuth;
    use crate::admin_v2::{AdminProposal, AdminRaft, AdminVerifier};
    use crate::authority::Authority;
    use crate::connection;
    use crate::protocol::{self, AddKeyResult, Message, PROTOCOL_VERSION};
    use crate::raft::state_machine::PolicyState;
    use crate::raft::types::PolicyCommand;
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
            authority: std::sync::RwLock::new(Some(authority)),
            authority_key_path: dir.join("authority.key"),
            store: StdMutex::new(store),
            admin: AdminAuth::new("pw", network).unwrap(),
            admin_keys: crate::admin_v2::AdminVerifier::default(),
            join: crate::join::JoinServer::new("pw", true),
            replicate: crate::replicate::RepAuth::new("pw", network).unwrap(),
            network: network.to_string(),
            service_name: "auth".to_string(),
            expires_secs: 3600,
            renew_secs: 1,
            started_at: Instant::now(),
            publisher: PublisherHandle::new(),
            raft: std::sync::RwLock::new(None),
            admin_raft: std::sync::RwLock::new(None),
            raft_required: false,
        });
        Fixture { ctx, dir }
    }

    struct PublisherFakeRaft {
        leader: AtomicBool,
        fail_propose: AtomicBool,
        state: StdMutex<PolicyState>,
    }

    impl PublisherFakeRaft {
        fn new(leader: bool, state: PolicyState) -> Self {
            Self {
                leader: AtomicBool::new(leader),
                fail_propose: AtomicBool::new(false),
                state: StdMutex::new(state),
            }
        }

        fn set_leader(&self, leader: bool) {
            self.leader.store(leader, Ordering::SeqCst);
        }

        fn set_fail_propose(&self, fail: bool) {
            self.fail_propose.store(fail, Ordering::SeqCst);
        }

        fn set_state(&self, state: PolicyState) {
            *self.state.lock().unwrap() = state;
        }

        fn policy_state(&self) -> PolicyState {
            self.state.lock().unwrap().clone()
        }
    }

    impl AdminRaft for PublisherFakeRaft {
        fn is_leader(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            let leader = self.leader.load(Ordering::SeqCst);
            Box::pin(async move { leader })
        }

        fn term(&self) -> Pin<Box<dyn Future<Output = u64> + Send + '_>> {
            Box::pin(async move { 7 })
        }

        fn leader_peer(&self) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
            Box::pin(async move { Some("leader-peer".to_string()) })
        }

        fn policy_snapshot(&self) -> Pin<Box<dyn Future<Output = PolicyState> + Send + '_>> {
            let state = self.state.lock().unwrap().clone();
            Box::pin(async move { state })
        }

        fn applied_index(&self) -> Pin<Box<dyn Future<Output = Option<u64>> + Send + '_>> {
            let applied = self.state.lock().unwrap().policy_epoch;
            Box::pin(async move { Some(applied) })
        }

        fn stale(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            Box::pin(async move { false })
        }

        fn service_name(&self) -> &str {
            "auth"
        }

        fn propose(
            &self,
            command: PolicyCommand,
        ) -> Pin<Box<dyn Future<Output = Result<AdminProposal, String>> + Send + '_>> {
            if self.fail_propose.load(Ordering::SeqCst) {
                return Box::pin(async move { Err("no quorum".to_string()) });
            }
            let mut state = self.state.lock().unwrap();
            let index = state.policy_epoch.saturating_add(1);
            let result = state.apply_command_at(&command, index);
            Box::pin(async move {
                Ok(AdminProposal {
                    result,
                    raft_index: index,
                })
            })
        }
    }

    fn raft_fixture(state: PolicyState) -> (Fixture, Arc<PublisherFakeRaft>) {
        raft_fixture_with(state, true)
    }

    fn raft_fixture_with(state: PolicyState, leader: bool) -> (Fixture, Arc<PublisherFakeRaft>) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nexusauth-publisher-raft-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        let network = "myorg";
        let authority = Authority::generate(network).unwrap();
        // 旧 Store 故意保留一个不同的服务，验证 Raft 模式不会从中构造发布内容。
        let mut initial = BTreeMap::new();
        initial.insert("cmd".to_string(), vec![peer()]);
        let store = Store::load_or_create(dir.join("auth_state.toml"), network, &initial).unwrap();
        let fake = Arc::new(PublisherFakeRaft::new(leader, state));
        let admin_raft: Arc<dyn AdminRaft> = fake.clone();
        let ctx = Arc::new(AuthContext {
            authority: std::sync::RwLock::new(Some(authority)),
            authority_key_path: dir.join("authority.key"),
            store: StdMutex::new(store),
            admin: AdminAuth::new("pw", network).unwrap(),
            admin_keys: AdminVerifier::default(),
            join: crate::join::JoinServer::new("pw", true),
            replicate: crate::replicate::RepAuth::new("pw", network).unwrap(),
            network: network.to_string(),
            service_name: "auth".to_string(),
            expires_secs: 3600,
            renew_secs: 1,
            started_at: Instant::now(),
            publisher: PublisherHandle::new(),
            raft: std::sync::RwLock::new(None),
            admin_raft: std::sync::RwLock::new(Some(admin_raft)),
            raft_required: true,
        });
        (Fixture { ctx, dir }, fake)
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
        spawn_node_with(port, None).await
    }

    async fn spawn_node_rejecting(
        port: u16,
        reject_key: String,
    ) -> mpsc::UnboundedReceiver<(String, Vec<u8>)> {
        spawn_node_with(port, Some(reject_key)).await
    }

    async fn spawn_node_with(
        port: u16,
        reject_key: Option<String>,
    ) -> mpsc::UnboundedReceiver<(String, Vec<u8>)> {
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
                // providing-only（成员发现宣告）不计入发布记录
                let Some(val) = value else {
                    let _ = reply_add_key(&mut w, id, &key, true).await;
                    continue;
                };
                let rejected = reject_key.as_deref() == Some(key.as_str());
                if tx.send((key.clone(), val)).is_err() {
                    break;
                }
                if reply_add_key(&mut w, id, &key, !rejected).await.is_err() {
                    break;
                }
            }
        });
        rx
    }

    async fn reply_add_key(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        id: uuid::Uuid,
        key: &str,
        ok: bool,
    ) -> Result<(), ()> {
        let mut body = Vec::new();
        ciborium::ser::into_writer(
            &AddKeyResult {
                success: ok,
                key: key.to_string(),
            },
            &mut body,
        )
        .map_err(|_| ())?;
        protocol::write_frame(
            writer,
            &Message::Reply {
                id,
                ok,
                result: ok.then_some(body),
                error: (!ok).then(|| SidecarError::new("rejected", "add_key rejected")),
            },
        )
        .await
        .map_err(|_| ())
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
        assert_eq!(k1, fx.ctx.authority().unwrap().service_key("cmd").unwrap());
        let (k2, v2) = recv(&mut rx).await;
        assert_eq!(k2, fx.ctx.authority().unwrap().index_key());

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
        assert_eq!(k1, fx.ctx.authority().unwrap().service_key("cmd").unwrap());
        let (k2, v2) = recv(&mut rx).await;
        assert_eq!(k2, fx.ctx.authority().unwrap().index_key());

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
                    Ok(Message::DiscoverProviders { id, .. }) => {
                        let mut body = Vec::new();
                        ciborium::ser::into_writer(&Vec::<String>::new(), &mut body).unwrap();
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
                    Ok(Message::Whoami { id }) => {
                        let mut body = Vec::new();
                        ciborium::ser::into_writer(
                            &crate::protocol::WhoamiResult {
                                peer_id: "12D3KooWself".into(),
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
        assert_eq!(k1, fx.ctx.authority().unwrap().service_key("cmd").unwrap());
        let (_, v1) = recv(&mut rx).await;
        let first: IndexDoc = ciborium::de::from_reader(decode_payload(&v1).as_slice()).unwrap();
        assert_eq!(first.version, 1);

        // 管理指令触发的再次发布
        let (k2, w2) = recv(&mut rx).await;
        assert_eq!(k2, fx.ctx.authority().unwrap().service_key("cmd").unwrap());
        let (_, v2) = recv(&mut rx).await;
        let second: IndexDoc = ciborium::de::from_reader(decode_payload(&v2).as_slice()).unwrap();
        assert_eq!(second.version, 2);

        let doc: WhitelistDoc = ciborium::de::from_reader(decode_payload(&w2).as_slice()).unwrap();
        assert_eq!(doc.version, 2);
        assert_eq!(doc.members.len(), 2);
    }

    #[tokio::test]
    async fn raft_mode_publishes_from_state_machine_not_old_store() {
        let mut state = PolicyState::new("myorg");
        let member = peer();
        state.apply_command_at(
            &PolicyCommand::CreateService {
                service: "from-raft".into(),
                members: vec![member.clone()],
            },
            1,
        );
        let epoch = state.policy_epoch;
        let (fx, fake) = raft_fixture(state);
        let port = start_sidecar(fx.ctx.clone(), 60).await;
        let mut rx = spawn_node(port).await;

        let (k1, v1) = recv(&mut rx).await;
        assert_eq!(
            k1,
            fx.ctx
                .authority()
                .unwrap()
                .service_key("from-raft")
                .unwrap()
        );
        assert_ne!(k1, fx.ctx.authority().unwrap().service_key("cmd").unwrap());
        let (k2, v2) = recv(&mut rx).await;
        assert_eq!(k2, fx.ctx.authority().unwrap().index_key());

        let doc: WhitelistDoc = ciborium::de::from_reader(decode_payload(&v1).as_slice()).unwrap();
        assert_eq!(doc.version, 1);
        assert_eq!(doc.members, vec![member]);

        let index: IndexDoc = ciborium::de::from_reader(decode_payload(&v2).as_slice()).unwrap();
        let applied = fake.policy_state();
        assert!(applied.policy_epoch > epoch, "首次发布应先通过 Raft 续期");
        assert_eq!(index.version, applied.policy_epoch);
        assert_eq!(index.expires_at, applied.index_expires_at);
        assert_eq!(index.services.len(), 1);
        assert_eq!(index.services[0].name, "from-raft");
        assert_eq!(index.services[0].hash, content_hash(&v1));

        // 旧 Store 未被发布路径修改，也不参与构造。
        let store = fx.ctx.store.lock().unwrap();
        assert_eq!(store.service_names(), vec!["cmd"]);
        assert_eq!(store.version("cmd"), Some(1));
    }

    fn service_state(service: &str, member: &str) -> PolicyState {
        let mut state = PolicyState::new("myorg");
        state.apply_command_at(
            &PolicyCommand::CreateService {
                service: service.into(),
                members: vec![member.to_string()],
            },
            1,
        );
        state
    }

    #[tokio::test]
    async fn raft_follower_does_not_publish() {
        let state = service_state("cmd", &peer());
        let (fx, _fake) = raft_fixture_with(state, false);
        let port = start_sidecar(fx.ctx.clone(), 60).await;
        let mut rx = spawn_node(port).await;

        let received = tokio::time::timeout(Duration::from_millis(600), rx.recv()).await;
        assert!(received.is_err(), "follower 不得发布任何记录");
        assert_eq!(fx.ctx.publisher.status().last_publish_epoch, None);
    }

    #[tokio::test]
    async fn raft_leader_change_publishes_higher_epoch() {
        let state = service_state("cmd", &peer());
        let (fx, fake) = raft_fixture(state);
        let port = start_sidecar(fx.ctx.clone(), 60).await;
        let mut rx = spawn_node(port).await;

        let _ = recv(&mut rx).await;
        let (_, first_bytes) = recv(&mut rx).await;
        let first: IndexDoc =
            ciborium::de::from_reader(decode_payload(&first_bytes).as_slice()).unwrap();

        fake.set_leader(false);
        fx.ctx.publisher.notify_publish();
        let lost = tokio::time::timeout(Duration::from_millis(400), rx.recv()).await;
        assert!(lost.is_err(), "失去 leadership 后不得发布");

        fake.set_leader(true);
        fx.ctx.publisher.notify_renew();
        let _ = recv(&mut rx).await;
        let (_, second_bytes) = recv(&mut rx).await;
        let second: IndexDoc =
            ciborium::de::from_reader(decode_payload(&second_bytes).as_slice()).unwrap();
        assert!(second.version > first.version);
        assert_eq!(second.version, fake.policy_state().policy_epoch);
    }

    #[tokio::test]
    async fn old_leader_cannot_overwrite_higher_epoch() {
        let mut state = service_state("cmd", &peer());
        state.apply_command_at(
            &PolicyCommand::RenewIndex {
                expires_at: now_unix() + 3600,
            },
            2,
        );
        let high_epoch = state.policy_epoch;
        let (fx, fake) = raft_fixture(state);
        let port = start_sidecar(fx.ctx.clone(), 60).await;
        let mut rx = spawn_node(port).await;

        let _ = recv(&mut rx).await;
        let (_, first_bytes) = recv(&mut rx).await;
        let first: IndexDoc =
            ciborium::de::from_reader(decode_payload(&first_bytes).as_slice()).unwrap();
        assert_eq!(first.version, high_epoch);

        let mut stale = service_state("cmd", &peer());
        stale.index_expires_at = now_unix() + 3600;
        assert!(stale.policy_epoch < high_epoch);
        fake.set_state(stale);
        fx.ctx.publisher.notify_publish();

        let published = tokio::time::timeout(Duration::from_millis(800), rx.recv()).await;
        assert!(published.is_err(), "旧 epoch 不得覆盖已发布的更高 epoch");
        let status = fx.ctx.publisher.status();
        assert!(!status.last_publish_ok);
        assert_eq!(status.last_publish_epoch, Some(high_epoch));
        assert!(
            status
                .last_publish_error
                .as_deref()
                .unwrap_or_default()
                .contains("stale policy_epoch")
        );
    }

    #[tokio::test]
    async fn whitelist_failure_prevents_index_publish() {
        let mut state = service_state("cmd", &peer());
        state.index_expires_at = now_unix() + 3600;
        let (fx, _fake) = raft_fixture(state);
        let port = start_sidecar(fx.ctx.clone(), 60).await;
        let service_key = fx.ctx.authority().unwrap().service_key("cmd").unwrap();
        let index_key = fx.ctx.authority().unwrap().index_key();
        let mut rx = spawn_node_rejecting(port, service_key.clone()).await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut keys = Vec::new();
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
                Ok(Some((key, _))) => keys.push(key),
                Ok(None) => break,
                Err(_) => {}
            }
        }

        assert!(!keys.is_empty(), "应至少尝试发布白名单");
        assert!(
            keys.iter().all(|key| key == &service_key),
            "白名单失败后不得发布索引: {keys:?} (index={index_key})"
        );
        let status = fx.ctx.publisher.status();
        assert!(!status.last_publish_ok);
        let error = status.last_publish_error.as_deref().unwrap_or_default();
        assert!(error.contains("conn#"), "unexpected error: {error}");
        assert!(error.contains("[rejected]"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn renewal_without_quorum_does_not_publish() {
        let state = service_state("cmd", &peer());
        let (fx, fake) = raft_fixture(state);
        fake.set_fail_propose(true);
        let port = start_sidecar(fx.ctx.clone(), 60).await;
        let mut rx = spawn_node(port).await;

        let received = tokio::time::timeout(Duration::from_millis(1200), rx.recv()).await;
        assert!(received.is_err(), "续期失败时不得发布");
        let status = fx.ctx.publisher.status();
        assert!(!status.last_publish_ok);
        assert!(
            status
                .last_publish_error
                .as_deref()
                .unwrap_or_default()
                .contains("no quorum")
        );
    }

    #[tokio::test]
    async fn raft_renewal_advances_epoch_monotonically() {
        let state = service_state("cmd", &peer());
        let (fx, fake) = raft_fixture(state);
        let port = start_sidecar(fx.ctx.clone(), 1).await;
        let mut rx = spawn_node(port).await;

        let _ = recv(&mut rx).await;
        let (_, first_bytes) = recv(&mut rx).await;
        let first: IndexDoc =
            ciborium::de::from_reader(decode_payload(&first_bytes).as_slice()).unwrap();

        let _ = recv(&mut rx).await;
        let (_, second_bytes) = recv(&mut rx).await;
        let second: IndexDoc =
            ciborium::de::from_reader(decode_payload(&second_bytes).as_slice()).unwrap();

        assert!(second.version > first.version);
        assert!(second.expires_at >= first.expires_at);
        assert!(fake.policy_state().policy_epoch >= second.version);
    }
}
