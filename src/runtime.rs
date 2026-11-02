//! 边车运行时：延迟就绪（入网）与发布循环装配。

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, watch};

use crate::admin::AdminAuth;
use crate::admin_v2::{AdminRaft, AdminVerifier};
use crate::authority::Authority;
use crate::config::ConfigHandle;
use crate::connection::BackendClient;
use crate::context::AuthContext;
use crate::join;
use crate::log::{LogLevel, LogStruct};
use crate::publisher::{self, PublisherHandle};
use crate::replicate::{self, RepAuth};
use crate::store::Store;

/// 边车运行时：持有发布句柄与「是否已就绪」状态。
pub struct Runtime {
    config: ConfigHandle,
    pub publisher: PublisherHandle,
    ready: RwLock<Option<Arc<AuthContext>>>,
    join_lock: Mutex<()>,
    raft_start_lock: Mutex<()>,
    shutdown_rx: watch::Receiver<bool>,
    start: Instant,
}

impl Runtime {
    pub fn new(
        config: ConfigHandle,
        publisher: PublisherHandle,
        shutdown_rx: watch::Receiver<bool>,
        ready: Option<Arc<AuthContext>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            publisher,
            ready: RwLock::new(ready),
            join_lock: Mutex::new(()),
            raft_start_lock: Mutex::new(()),
            shutdown_rx,
            start: Instant::now(),
        })
    }

    pub fn is_ready(&self) -> bool {
        self.ready.read().expect("ready poisoned").is_some()
    }

    pub fn ctx(&self) -> Option<Arc<AuthContext>> {
        self.ready.read().expect("ready poisoned").clone()
    }

    /// 确保就绪；未就绪时用给定连接执行入网（仅一次）。
    ///
    /// 返回 `None` 表示在 `join_timeout_secs` 内未能入网。
    pub async fn ensure_ready(&self, client: &BackendClient) -> Option<Arc<AuthContext>> {
        if let Some(ctx) = self.ctx() {
            return Some(ctx);
        }
        let _guard = self.join_lock.lock().await;
        if let Some(ctx) = self.ctx() {
            return Some(ctx);
        }

        // Raft 模式：learner 不以旧密码入网；无 seed 时以 `None` authority 就绪，
        // 由 join token/leader seed 分发补齐。voter 的 seed 来自离线部署或安全分发。
        if self.config.cluster_enabled() {
            let network = self.config.network();
            let authority = match Authority::load(self.config.authority_key_path(), &network) {
                Ok(authority) => Some(authority),
                Err(crate::authority::AuthorityError::Io(e))
                    if e.kind() == std::io::ErrorKind::NotFound =>
                {
                    None
                }
                Err(e) => {
                    LogStruct::new(LogLevel::Critical, "加载权威密钥失败", e.to_string()).emit();
                    return None;
                }
            };
            let store = match Store::load_or_create(
                self.config.state_path(),
                &network,
                &self.config.initial_members(),
            ) {
                Ok(store) => store,
                Err(e) => {
                    LogStruct::new(LogLevel::Critical, "加载成员状态失败", e.to_string()).emit();
                    return None;
                }
            };
            return Some(self.activate(authority, store));
        }

        let network = self.config.network();
        let timeout = Duration::from_secs(self.config.join_timeout_secs().max(1));
        let deadline = self.start + timeout;

        loop {
            match join::attempt(client, &self.config).await {
                Ok((authority, store)) => return Some(self.activate(Some(authority), store)),
                Err(e) => {
                    LogStruct::new(LogLevel::Warning, "入网失败", e.to_string()).emit();
                }
            }
            if Instant::now() >= deadline {
                LogStruct::new(
                    LogLevel::Critical,
                    "入网超时",
                    format!("{network}: 未能在 {} 秒内取回权威密钥", timeout.as_secs()),
                )
                .emit();
                return None;
            }
            tokio::time::sleep(Duration::from_secs(self.config.join_retry_secs().max(1))).await;
        }
    }

    /// 在已有 whoami 的连接上启动 Raft（仅 `[cluster].enabled = true`）。
    pub async fn ensure_raft(&self, client: &BackendClient) {
        if !self.config.cluster_enabled() {
            return;
        }
        let Some(ctx) = self.ctx() else {
            return;
        };
        if ctx.raft.read().expect("raft poisoned").is_some() {
            return;
        }
        let _guard = self.raft_start_lock.lock().await;
        if ctx.raft.read().expect("raft poisoned").is_some() {
            return;
        }
        match crate::raft::RaftRuntime::start(&self.config, client).await {
            Ok(raft) => {
                LogStruct::new(
                    LogLevel::Important,
                    "Raft 控制面启动",
                    format!("cluster={} node={}", raft.cluster_id(), raft.node_id()),
                )
                .emit();
                match raft.try_join(&self.config).await {
                    Ok(true) => LogStruct::new(
                        LogLevel::Important,
                        "Raft 入网成功",
                        "已以 learner 身份加入集群，等待快照同步",
                    )
                    .emit(),
                    Ok(false) => {}
                    Err(e) => {
                        LogStruct::new(LogLevel::Warning, "Raft 入网失败", e).emit();
                    }
                }
                let publisher = ctx.publisher.clone();
                let watcher_raft = raft.clone();
                let mut metrics = watcher_raft.metrics();
                let admin_raft: Arc<dyn AdminRaft> = raft.clone();
                let mut shutdown = self.shutdown_rx.clone();
                tokio::spawn(async move {
                    let mut was_leader = metrics.borrow().state == openraft::ServerState::Leader;
                    loop {
                        tokio::select! {
                            changed = metrics.changed() => {
                                if changed.is_err() {
                                    break;
                                }
                                watcher_raft.refresh_verifier_from_metrics();
                                let is_leader =
                                    metrics.borrow().state == openraft::ServerState::Leader;
                                if is_leader && !was_leader {
                                    publisher.notify_renew();
                                }
                                was_leader = is_leader;
                            }
                            _ = shutdown.changed() => break,
                        }
                    }
                });
                *ctx.admin_raft.write().expect("admin raft poisoned") = Some(admin_raft);
                *ctx.raft.write().expect("raft poisoned") = Some(raft);
            }
            Err(e) => {
                LogStruct::new(LogLevel::Warning, "Raft 控制面启动失败", e.to_string()).emit();
            }
        }
    }

    /// 激活上下文：写入就绪状态并启动发布循环。
    fn activate(&self, authority: Option<Authority>, store: Store) -> Arc<AuthContext> {
        let ctx = build_context(
            &self.config,
            authority,
            store,
            &self.publisher,
            &self.shutdown_rx,
        );
        *self.ready.write().expect("ready poisoned") = Some(ctx.clone());
        ctx
    }
}

/// 由权威密钥与状态构造 `AuthContext`，并启动发布循环。
pub fn build_context(
    config: &ConfigHandle,
    authority: Option<Authority>,
    store: Store,
    publisher: &PublisherHandle,
    shutdown_rx: &watch::Receiver<bool>,
) -> Arc<AuthContext> {
    let network = config.network();
    if config.cluster_enabled() && config.renew_secs() >= config.expires_secs() {
        LogStruct::new(
            LogLevel::Critical,
            "续期配置无效",
            format!(
                "renew_secs={} 必须小于 expires_secs={}，拒绝启动 Raft 控制面（fail-closed）",
                config.renew_secs(),
                config.expires_secs()
            ),
        )
        .emit();
        std::process::exit(1);
    }
    let configured_password = config.management_password();
    // Raft 模式使用管理员公钥认证；旧 HMAC 路径仍需要非空密码。
    let password = if configured_password.is_empty() && config.cluster_enabled() {
        format!("cluster-only-{}", uuid::Uuid::new_v4())
    } else {
        configured_password
    };
    let admin_keys =
        match AdminVerifier::from_config(&config.admin_keys(), config.cluster_enabled()) {
            Ok(verifier) => verifier,
            Err(e) => {
                LogStruct::new(
                    LogLevel::Critical,
                    "管理员公钥配置无效",
                    format!("拒绝启动（fail-closed）: {e}"),
                )
                .emit();
                std::process::exit(1);
            }
        };
    let ctx = Arc::new(AuthContext {
        authority: RwLock::new(authority),
        authority_key_path: config.authority_key_path(),
        store: std::sync::Mutex::new(store),
        admin: AdminAuth::new(&password, &network).expect("管理密码已在启动时校验"),
        admin_keys,
        join: join::JoinServer::new(&password, config.allow_join()),
        replicate: RepAuth::new(&password, &network).expect("管理密码已在启动时校验"),
        publisher: publisher.clone(),
        raft: std::sync::RwLock::new(None),
        admin_raft: std::sync::RwLock::new(None),
        raft_required: config.cluster_enabled(),
        network,
        service_name: config.service(),
        expires_secs: config.expires_secs(),
        renew_secs: config.renew_secs(),
        started_at: Instant::now(),
    });
    tokio::spawn(publisher::run(
        publisher.clone(),
        ctx.clone(),
        ctx.renew_secs,
        shutdown_rx.clone(),
    ));
    // 反熵同步：仅旧多写者路径启用；Raft 模式下由 leader 单写。
    if !config.cluster_enabled() {
        tokio::spawn(replicate::sync_loop(
            ctx.clone(),
            publisher.clone(),
            Duration::from_secs(config.renew_secs().max(1)),
            shutdown_rx.clone(),
        ));
    }
    match ctx.authority_public_key_b64() {
        Some(public_key) => LogStruct::new(
            LogLevel::Important,
            "权威公钥",
            format!(
                "{public_key}（填入 NexusNet auth.networks.{}.authority）",
                ctx.network
            ),
        )
        .emit(),
        None => LogStruct::new(
            LogLevel::Important,
            "learner 无 authority seed",
            format!("{}: 等待 voter 提升时安全分发", ctx.network),
        )
        .emit(),
    }
    ctx
}

#[cfg(test)]
impl Runtime {
    /// 测试用：直接注入一个已就绪的上下文。
    pub fn ready_for_test(ctx: Arc<AuthContext>) -> Arc<Self> {
        let (_, shutdown_rx) = watch::channel(false);
        Arc::new(Self {
            config: ConfigHandle::new(crate::config::ServiceConfig::default()),
            publisher: ctx.publisher.clone(),
            ready: RwLock::new(Some(ctx)),
            join_lock: Mutex::new(()),
            raft_start_lock: Mutex::new(()),
            shutdown_rx,
            start: Instant::now(),
        })
    }

    /// 测试用：未就绪的运行时（不触发入网）。
    pub fn not_ready_for_test() -> Arc<Self> {
        let (_, shutdown_rx) = watch::channel(false);
        Arc::new(Self {
            config: ConfigHandle::new(crate::config::ServiceConfig::default()),
            publisher: PublisherHandle::new(),
            ready: RwLock::new(None),
            join_lock: Mutex::new(()),
            raft_start_lock: Mutex::new(()),
            shutdown_rx,
            start: Instant::now(),
        })
    }
}
