mod admin;
// 权威签名核心：Phase 1 落地，自 Phase 2 起被配置与发布流程消费。
#[allow(dead_code)]
mod authority;
mod config;
mod connection;
mod context;
mod fsutil;
mod join;
mod log;
mod paths;
mod protocol;
mod publisher;
mod replay;
mod replicate;
mod runtime;
mod service;
// 成员状态：Phase 2 落地，自 Phase 3 起被管理指令消费。
#[allow(dead_code)]
mod store;

use std::sync::Arc;
use std::time::Duration;

use config::ConfigHandle;
use log::{LogLevel, LogStruct};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::authority::Authority;
use crate::context::AuthContext;
use crate::publisher::PublisherHandle;
use crate::runtime::{Runtime, build_context};
use crate::store::Store;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = ConfigHandle::load_or_create_default();
    let network = config.network();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let publisher = PublisherHandle::new();

    // 网络未配置：仅监听，管理指令与发布均不可用（fail-closed）。
    let initial_ctx = if network.is_empty() {
        LogStruct::new(
            LogLevel::Warning,
            "网络未配置",
            "config.network 为空，管理指令与发布均不可用",
        )
        .emit();
        None
    } else {
        let password = config.management_password();
        if password.is_empty() {
            LogStruct::new(
                LogLevel::Critical,
                "管理密码未配置",
                "config.management_password 为空，拒绝启动（fail-closed）",
            )
            .emit();
            std::process::exit(1);
        }
        build_initial(&config, &network, &publisher, &shutdown_rx)
    };

    let runtime = Runtime::new(config.clone(), publisher, shutdown_rx.clone(), initial_ctx);

    // require 模式：未就绪时设看门狗，超时即退出（fail-closed）。
    if !network.is_empty() && !runtime.is_ready() {
        let rt = runtime.clone();
        let timeout = config.join_timeout_secs().max(1);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(timeout + 2)).await;
            if !rt.is_ready() {
                LogStruct::new(
                    LogLevel::Critical,
                    "入网超时",
                    "未能在限定时间内入网，退出（fail-closed）",
                )
                .emit();
                std::process::exit(1);
            }
        });
    }

    let address = format!("127.0.0.1:{}", config.port());
    let listener = TcpListener::bind(&address).await?;
    LogStruct::new(LogLevel::Important, "服务启动", &address).emit();

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            Ok((stream, addr)) = listener.accept() => {
                LogStruct::new(LogLevel::Preset, "节点接入", addr.to_string()).emit();
                let runtime = runtime.clone();
                tokio::spawn(async move {
                    if let Err(e) = connection::handle_connection(stream, runtime).await {
                        LogStruct::new(
                            LogLevel::Critical,
                            "连接错误",
                            format!("位于 {}: {}", addr, e),
                        ).emit();
                    }
                });
            }
            _ = &mut ctrl_c => {
                LogStruct::new(LogLevel::Important, "关闭", "收到关闭信号").emit();
                break;
            }
            _ = sigterm.recv() => {
                LogStruct::new(LogLevel::Important, "关闭", "收到 SIGTERM").emit();
                break;
            }
        }
    }

    let _ = shutdown_tx.send(true);
    drop(listener);
    Ok(())
}

/// 启动时就绪路径：本地已有密钥，或 `join_mode = init` 生成新权威。
///
/// 返回 `None` 表示 `require` 模式且本地无密钥，需等待连接后入网。
fn build_initial(
    config: &ConfigHandle,
    network: &str,
    publisher: &PublisherHandle,
    shutdown_rx: &watch::Receiver<bool>,
) -> Option<Arc<AuthContext>> {
    if config.authority_key_path().exists() {
        let authority = match Authority::load(config.authority_key_path(), network) {
            Ok(a) => a,
            Err(e) => {
                LogStruct::new(LogLevel::Critical, "加载权威密钥失败", e.to_string()).emit();
                std::process::exit(1);
            }
        };
        let store =
            match Store::load_or_create(config.state_path(), network, &config.initial_members()) {
                Ok(s) => s,
                Err(e) => {
                    LogStruct::new(LogLevel::Critical, "加载成员状态失败", e.to_string()).emit();
                    std::process::exit(1);
                }
            };
        LogStruct::new(
            LogLevel::Important,
            "鉴权网络就绪",
            format!("{network}，{} 个服务", store.service_names().len()),
        )
        .emit();
        return Some(build_context(
            config,
            authority,
            store,
            publisher,
            shutdown_rx,
        ));
    }

    if config.join_mode() == "init" {
        let authority = match Authority::generate(network) {
            Ok(a) => a,
            Err(e) => {
                LogStruct::new(LogLevel::Critical, "生成权威密钥失败", e.to_string()).emit();
                std::process::exit(1);
            }
        };
        if let Err(e) =
            fsutil::atomic_write(&config.authority_key_path(), &authority.seed(), Some(0o600))
        {
            LogStruct::new(LogLevel::Critical, "写入权威密钥失败", e.to_string()).emit();
            std::process::exit(1);
        }
        let store =
            match Store::load_or_create(config.state_path(), network, &config.initial_members()) {
                Ok(s) => s,
                Err(e) => {
                    LogStruct::new(LogLevel::Critical, "加载成员状态失败", e.to_string()).emit();
                    std::process::exit(1);
                }
            };
        LogStruct::new(
            LogLevel::Important,
            "初始化新鉴权网络",
            format!("{network}，{} 个服务", store.service_names().len()),
        )
        .emit();
        return Some(build_context(
            config,
            authority,
            store,
            publisher,
            shutdown_rx,
        ));
    }

    LogStruct::new(
        LogLevel::Important,
        "等待入网",
        format!("{network}: 本地无权威密钥，将向在线边车入网"),
    )
    .emit();
    None
}
