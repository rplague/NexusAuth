//! 边车运行时：延迟就绪（入网）与发布循环装配。

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, watch};

use crate::admin::AdminAuth;
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

        let network = self.config.network();
        let timeout = Duration::from_secs(self.config.join_timeout_secs().max(1));
        let deadline = self.start + timeout;

        loop {
            match join::attempt(client, &self.config).await {
                Ok((authority, store)) => return Some(self.activate(authority, store)),
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

    /// 激活上下文：写入就绪状态并启动发布循环。
    fn activate(&self, authority: Authority, store: Store) -> Arc<AuthContext> {
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
    authority: Authority,
    store: Store,
    publisher: &PublisherHandle,
    shutdown_rx: &watch::Receiver<bool>,
) -> Arc<AuthContext> {
    let network = config.network();
    let password = config.management_password();
    let ctx = Arc::new(AuthContext {
        authority,
        store: std::sync::Mutex::new(store),
        admin: AdminAuth::new(&password, &network).expect("管理密码已在启动时校验"),
        join: join::JoinServer::new(&password, config.allow_join()),
        replicate: RepAuth::new(&password, &network).expect("管理密码已在启动时校验"),
        publisher: publisher.clone(),
        network,
        service_name: config.join_service(),
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
    // 反熵同步：每 renew_secs 拉取一次对端快照。
    tokio::spawn(replicate::sync_loop(
        ctx.clone(),
        publisher.clone(),
        Duration::from_secs(config.renew_secs().max(1)),
        shutdown_rx.clone(),
    ));
    LogStruct::new(
        LogLevel::Important,
        "权威公钥",
        format!(
            "{}（填入 NexusNet auth.networks.{}.authority）",
            ctx.authority.public_key_b64(),
            ctx.network
        ),
    )
    .emit();
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
            shutdown_rx,
            start: Instant::now(),
        })
    }
}
