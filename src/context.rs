//! 边车运行时上下文：权威签名者、成员状态、管理认证与配置快照。

use std::sync::Mutex;
use std::time::Instant;

use crate::admin::AdminAuth;
use crate::authority::Authority;
use crate::join::JoinServer;
use crate::publisher::PublisherHandle;
use crate::replicate::RepAuth;
use crate::store::Store;

/// 供连接处理、管理指令、复制与发布流程共享的运行时状态。
pub struct AuthContext {
    pub authority: Authority,
    pub store: Mutex<Store>,
    pub admin: AdminAuth,
    pub join: JoinServer,
    pub replicate: RepAuth,
    pub publisher: PublisherHandle,
    pub network: String,
    /// 本边车在节点侧登记的服务名（用于发现与寻址对端）。
    pub service_name: String,
    pub expires_secs: u64,
    pub renew_secs: u64,
    pub started_at: Instant,
}
