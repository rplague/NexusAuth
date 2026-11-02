//! NexusAuth 库入口。
//!
//! 二进制 `NexusAuth` 与 `nexusauthctl` 共享同一套协议、管理请求与运维实现。

pub mod admin;
pub mod admin_v2;
// 权威签名核心：Phase 1 落地，自 Phase 2 起被配置与发布流程消费。
#[allow(dead_code)]
pub mod authority;
pub mod backup;
pub mod config;
pub mod connection;
pub mod context;
pub mod ctl;
pub mod fsutil;
pub mod join;
pub mod log;
pub mod paths;
pub mod protocol;
pub mod publisher;
pub mod raft;
pub mod replay;
pub mod replicate;
pub mod runtime;
pub mod security;
pub mod service;
// 成员状态：Phase 2 落地，自 Phase 3 起被管理指令消费。
#[allow(dead_code)]
pub mod store;
