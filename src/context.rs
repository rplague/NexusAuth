//! 边车运行时上下文：权威签名者、成员状态、管理认证与配置快照。

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::admin::AdminAuth;
use crate::admin_v2::{AdminRaft, AdminVerifier};
use crate::authority::Authority;
use crate::join::JoinServer;
use crate::publisher::PublisherHandle;
use crate::raft::RaftRuntime;
use crate::replicate::RepAuth;
use crate::store::Store;

/// 供连接处理、管理指令、复制与发布流程共享的运行时状态。
pub struct AuthContext {
    /// authority seed；learner 必须为 `None`（不持有 seed）。
    pub authority: RwLock<Option<Authority>>,
    /// voter seed 文件路径（learner 为 `None` 时不写）。
    pub authority_key_path: PathBuf,
    pub store: Mutex<Store>,
    pub admin: AdminAuth,
    /// Phase 2 管理员公钥表（Raft 模式）。
    pub admin_keys: AdminVerifier,
    pub join: JoinServer,
    pub replicate: RepAuth,
    pub publisher: PublisherHandle,
    /// Raft 控制面；`None` 表示未启用或尚未启动。
    pub raft: RwLock<Option<Arc<RaftRuntime>>>,
    /// 管理面使用的 Raft 视图（生产为同一个 `RaftRuntime`，测试可注入）。
    pub admin_raft: RwLock<Option<Arc<dyn AdminRaft>>>,
    /// 配置要求 Raft 单写者；为 true 且 `raft` 为 None 时必须 fail-closed。
    pub raft_required: bool,
    pub network: String,
    /// 本边车在节点侧登记的服务名（用于发现与寻址对端）。
    pub service_name: String,
    pub expires_secs: u64,
    pub renew_secs: u64,
    pub started_at: Instant,
}

impl AuthContext {
    /// 当前是否持有 authority seed。
    pub fn has_authority_seed(&self) -> bool {
        self.authority.read().expect("authority poisoned").is_some()
    }

    /// 由内存 seed 重建一个短期 authority 签名者（避免跨 await 持锁）。
    pub fn authority(&self) -> Option<Authority> {
        let guard = self.authority.read().expect("authority poisoned");
        let authority = guard.as_ref()?;
        Authority::from_seed(authority.seed(), &self.network).ok()
    }

    pub fn authority_seed(&self) -> Option<[u8; 32]> {
        self.authority
            .read()
            .expect("authority poisoned")
            .as_ref()
            .map(Authority::seed)
    }

    pub fn authority_public_key_b64(&self) -> Option<String> {
        self.authority
            .read()
            .expect("authority poisoned")
            .as_ref()
            .map(Authority::public_key_b64)
    }

    /// seed 分发成功后安装 authority。
    pub fn install_authority(&self, authority: Authority) {
        *self.authority.write().expect("authority poisoned") = Some(authority);
    }

    /// demote/remove 后清除内存中的 seed。
    pub fn clear_authority(&self) {
        *self.authority.write().expect("authority poisoned") = None;
    }
}
