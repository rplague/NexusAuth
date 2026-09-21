//! 统一路径解析。
//!
//! - systemd 部署：由 `NEXUSAUTH_HOME` / `NEXUSAUTH_CONFIG` / `NEXUSAUTH_LOG_PATH` /
//!   `NEXUSAUTH_AUTHORITY_KEY` / `NEXUSAUTH_STATE` 环境变量锚定标准目录。
//! - 本地 `cargo run`：未设置任何环境变量时回退当前目录（`./config.toml`、`./log`、
//!   `./authority.key`、`./auth_state.toml`），以兼容既有行为。

use std::env;
use std::path::PathBuf;

/// 读取非空环境变量并转为路径。
fn env_path(key: &str) -> Option<PathBuf> {
    env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// 配置文件路径。
///
/// 优先级：`NEXUSAUTH_CONFIG` → `$NEXUSAUTH_HOME/config.toml` → `./config.toml`。
pub fn config_path() -> PathBuf {
    if let Some(path) = env_path("NEXUSAUTH_CONFIG") {
        return path;
    }
    if let Some(home) = env_path("NEXUSAUTH_HOME") {
        return home.join("config.toml");
    }
    PathBuf::from("./config.toml")
}

/// 日志目录。
///
/// 优先级：`NEXUSAUTH_LOG_PATH` → `$NEXUSAUTH_HOME` → `./`。
pub fn log_path() -> PathBuf {
    if let Some(path) = env_path("NEXUSAUTH_LOG_PATH") {
        return path;
    }
    if let Some(home) = env_path("NEXUSAUTH_HOME") {
        return home;
    }
    PathBuf::from("./")
}

/// 权威私钥文件路径。
///
/// 优先级：`NEXUSAUTH_AUTHORITY_KEY` → `$NEXUSAUTH_HOME/authority.key` → `./authority.key`。
pub fn authority_key_path() -> PathBuf {
    if let Some(path) = env_path("NEXUSAUTH_AUTHORITY_KEY") {
        return path;
    }
    if let Some(home) = env_path("NEXUSAUTH_HOME") {
        return home.join("authority.key");
    }
    PathBuf::from("./authority.key")
}

/// 成员状态文件路径。
///
/// 优先级：`NEXUSAUTH_STATE` → `$NEXUSAUTH_HOME/auth_state.toml` → `./auth_state.toml`。
pub fn state_path() -> PathBuf {
    if let Some(path) = env_path("NEXUSAUTH_STATE") {
        return path;
    }
    if let Some(home) = env_path("NEXUSAUTH_HOME") {
        return home.join("auth_state.toml");
    }
    PathBuf::from("./auth_state.toml")
}
