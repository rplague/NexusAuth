mod config;
mod connection;
mod log;
mod paths;
mod protocol;
mod service;
use config::ConfigHandle;
use log::{LogLevel, LogStruct};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config_handle = ConfigHandle::load_or_create_default();
    let address = format!("127.0.0.1:{}", config_handle.port());
    let listener = TcpListener::bind(&address).await?;
    LogStruct::new(LogLevel::Important, "服务启动", &address).emit();

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            Ok((stream, addr)) = listener.accept() => {
                LogStruct::new(LogLevel::Preset, "节点接入", addr.to_string()).emit();
                tokio::spawn(async move {
                    if let Err(e) = connection::handle_connection(stream).await {
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

    drop(listener);
    Ok(())
}
