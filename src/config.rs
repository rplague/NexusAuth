use crate::fsutil;
use crate::log::{LogLevel, LogStruct};
use crate::paths;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

macro_rules! default_u32_fn {
    ($name:ident, $value:expr) => {
        fn $name() -> u32 {
            $value
        }
    };
}

default_u32_fn!(default_port, 5100);

fn default_expires_secs() -> u64 {
    3600
}

fn default_renew_secs() -> u64 {
    1200
}

fn default_authority_key_path() -> String {
    paths::authority_key_path().to_string_lossy().into_owned()
}

fn default_state_path() -> String {
    paths::state_path().to_string_lossy().into_owned()
}

fn default_join_mode() -> String {
    "require".to_string()
}

fn default_join_service() -> String {
    "auth".to_string()
}

fn default_join_timeout_secs() -> u64 {
    30
}

fn default_join_retry_secs() -> u64 {
    5
}

fn default_allow_join() -> bool {
    true
}

/// 边车配置。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceConfig {
    #[serde(default = "default_port")]
    pub port: u32,
    /// 鉴权网络名；空表示未配置。
    #[serde(default)]
    pub network: String,
    /// 权威 ed25519 私钥（裸 32B seed）路径。
    #[serde(default = "default_authority_key_path")]
    pub authority_key_path: String,
    /// 成员状态文件路径。
    #[serde(default = "default_state_path")]
    pub state_path: String,
    /// 索引 `expires_at` 时长（秒）。
    #[serde(default = "default_expires_secs")]
    pub expires_secs: u64,
    /// 续期间隔（秒），应小于 `expires_secs`。
    #[serde(default = "default_renew_secs")]
    pub renew_secs: u64,
    /// 管理密码；空则拒绝管理指令（Phase 3 起强制）。
    #[serde(default)]
    pub management_password: String,
    /// 首启播种的服务与初始成员（状态文件缺失时生效）。
    #[serde(default)]
    pub services: BTreeMap<String, ServiceEntryConfig>,
    /// 入网模式：`require`（默认，必须入网成功）/ `init`（生成新权威，首个节点用）。
    #[serde(default = "default_join_mode")]
    pub join_mode: String,
    /// 额外的候选边车（节点 PeerId），DHT 发现为空时兜底。
    #[serde(default)]
    pub join_peers: Vec<String>,
    /// 目标节点上边车的服务名。
    #[serde(default = "default_join_service")]
    pub join_service: String,
    /// 入网总超时（秒）。
    #[serde(default = "default_join_timeout_secs")]
    pub join_timeout_secs: u64,
    /// 入网单轮失败后的重试间隔（秒）。
    #[serde(default = "default_join_retry_secs")]
    pub join_retry_secs: u64,
    /// 是否响应他人的入网请求。
    #[serde(default = "default_allow_join")]
    pub allow_join: bool,
}

/// 配置中单个服务的初始成员。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ServiceEntryConfig {
    #[serde(default)]
    pub members: Vec<String>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            network: String::new(),
            authority_key_path: default_authority_key_path(),
            state_path: default_state_path(),
            expires_secs: default_expires_secs(),
            renew_secs: default_renew_secs(),
            management_password: String::new(),
            services: BTreeMap::new(),
            join_mode: default_join_mode(),
            join_peers: Vec::new(),
            join_service: default_join_service(),
            join_timeout_secs: default_join_timeout_secs(),
            join_retry_secs: default_join_retry_secs(),
            allow_join: default_allow_join(),
        }
    }
}

impl ServiceConfig {
    pub fn from_toml_file(path: impl AsRef<Path>, create_if_missing: bool) -> ServiceConfig {
        let path = path.as_ref();

        if !create_if_missing && !path.exists() {
            LogStruct::new(LogLevel::Warning, "配置文件不存在，使用默认配置", "").emit();
            return ServiceConfig::default();
        }

        match fs::read_to_string(path) {
            Ok(content) => match toml::from_str(&content) {
                Ok(config) => {
                    ensure_private(path);
                    return config;
                }
                Err(e) => {
                    LogStruct::new(LogLevel::Error, "配置文件解析失败", e.to_string()).emit();
                    if let Err(rename_err) = rename_bad_config(path) {
                        LogStruct::new(
                            LogLevel::Critical,
                            "重命名损坏的配置文件失败",
                            rename_err.to_string(),
                        )
                        .emit();
                        std::process::exit(1);
                    }
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                LogStruct::new(LogLevel::Critical, "无法读取配置文件", e.to_string()).emit();
                std::process::exit(1);
            }
        }

        let default_config = ServiceConfig::default();
        let toml_string = match toml::to_string_pretty(&default_config) {
            Ok(s) => s,
            Err(e) => {
                LogStruct::new(LogLevel::Critical, "序列化默认配置失败", e.to_string()).emit();
                std::process::exit(1);
            }
        };
        if let Err(e) = fsutil::atomic_write(path, toml_string.as_bytes(), Some(0o600)) {
            LogStruct::new(LogLevel::Critical, "写入默认配置文件失败", e.to_string()).emit();
            std::process::exit(1);
        }
        default_config
    }
}

fn rename_bad_config(path: &Path) -> io::Result<()> {
    let mut backup_path = path.with_extension("bak");
    let mut counter = 1;
    while backup_path.exists() {
        backup_path = path.with_extension(format!("bak.{}", counter));
        counter += 1;
    }
    fs::rename(path, &backup_path)?;
    Ok(())
}

/// 尽力将文件权限收紧为 0600（Unix）。
fn ensure_private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    let _ = path;
}

#[derive(Clone)]
pub struct ConfigHandle {
    inner: Arc<RwLock<ServiceConfig>>,
}

impl ConfigHandle {
    pub fn new(config: ServiceConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(config)),
        }
    }

    pub fn from_toml_file(path: impl AsRef<Path>, create_if_missing: bool) -> Self {
        let config = ServiceConfig::from_toml_file(path, create_if_missing);
        Self::new(config)
    }

    pub fn load_or_create_default() -> Self {
        Self::from_toml_file(paths::config_path(), true)
    }

    pub fn save_to_file(&self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        let snapshot = self.snapshot();
        let toml_string = match toml::to_string_pretty(&snapshot) {
            Ok(s) => s,
            Err(e) => {
                LogStruct::new(LogLevel::Critical, "序列化配置失败", e.to_string()).emit();
                std::process::exit(1);
            }
        };

        if let Err(e) = fsutil::atomic_write(path, toml_string.as_bytes(), Some(0o600)) {
            LogStruct::new(
                LogLevel::Critical,
                "写入配置文件失败",
                format!("路径: {}, 错误: {}", path.display(), e),
            )
            .emit();
            std::process::exit(1);
        }
    }

    pub fn save_to_default(&self) {
        self.save_to_file(paths::config_path());
    }

    pub fn read(&self) -> RwLockReadGuard<'_, ServiceConfig> {
        self.inner.read().expect("RwLock 被污染")
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, ServiceConfig> {
        self.inner.write().expect("RwLock 被污染")
    }

    pub fn replace_config(&self, new_config: ServiceConfig) {
        *self.write() = new_config;
    }

    pub fn snapshot(&self) -> ServiceConfig {
        self.read().clone()
    }

    // ========== 便捷只读方法 ==========

    pub fn port(&self) -> u32 {
        self.read().port
    }

    /// 鉴权网络名（可能为空）。
    pub fn network(&self) -> String {
        self.read().network.clone()
    }

    pub fn authority_key_path(&self) -> PathBuf {
        PathBuf::from(&self.read().authority_key_path)
    }

    pub fn state_path(&self) -> PathBuf {
        PathBuf::from(&self.read().state_path)
    }

    pub fn expires_secs(&self) -> u64 {
        self.read().expires_secs
    }

    pub fn renew_secs(&self) -> u64 {
        self.read().renew_secs
    }

    pub fn management_password(&self) -> String {
        self.read().management_password.clone()
    }

    pub fn join_mode(&self) -> String {
        self.read().join_mode.clone()
    }

    pub fn join_peers(&self) -> Vec<String> {
        self.read().join_peers.clone()
    }

    pub fn join_service(&self) -> String {
        self.read().join_service.clone()
    }

    pub fn join_timeout_secs(&self) -> u64 {
        self.read().join_timeout_secs
    }

    pub fn join_retry_secs(&self) -> u64 {
        self.read().join_retry_secs
    }

    pub fn allow_join(&self) -> bool {
        self.read().allow_join
    }

    /// 首启播种的服务与初始成员。
    pub fn initial_members(&self) -> BTreeMap<String, Vec<String>> {
        self.read()
            .services
            .iter()
            .map(|(name, entry)| (name.clone(), entry.members.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_uses_defaults() {
        let cfg: ServiceConfig = toml::from_str("port = 5200\n").unwrap();
        assert_eq!(cfg.port, 5200);
        assert!(cfg.network.is_empty());
        assert_eq!(cfg.expires_secs, 3600);
        assert_eq!(cfg.renew_secs, 1200);
        assert!(cfg.management_password.is_empty());
        assert!(cfg.services.is_empty());
    }

    #[test]
    fn full_config_round_trip() {
        let toml = r#"
port = 5100
network = "myorg"
authority_key_path = "/var/lib/nexusauth/authority.key"
state_path = "/var/lib/nexusauth/auth_state.toml"
expires_secs = 600
renew_secs = 200
management_password = "secret"

[services.cmd]
members = ["12D3KooWExample"]
"#;
        let cfg: ServiceConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.network, "myorg");
        assert_eq!(cfg.expires_secs, 600);
        assert_eq!(cfg.renew_secs, 200);
        assert_eq!(cfg.management_password, "secret");
        assert_eq!(cfg.services["cmd"].members, vec!["12D3KooWExample"]);

        let back: ServiceConfig = toml::from_str(&toml::to_string_pretty(&cfg).unwrap()).unwrap();
        assert_eq!(back.network, cfg.network);
        assert_eq!(back.services["cmd"].members, cfg.services["cmd"].members);
    }

    #[test]
    fn initial_members_extraction() {
        let toml = r#"
network = "myorg"
[services.cmd]
members = ["a", "b"]
[services.ocr]
members = []
"#;
        let cfg: ServiceConfig = toml::from_str(toml).unwrap();
        let handle = ConfigHandle::new(cfg);
        let initial = handle.initial_members();
        assert_eq!(initial["cmd"], vec!["a", "b"]);
        assert_eq!(initial["ocr"].len(), 0);
    }

    #[test]
    fn saved_config_is_private() {
        let dir = std::env::temp_dir().join(format!(
            "nexusauth-config-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("config.toml");
        let handle = ConfigHandle::new(ServiceConfig::default());
        handle.save_to_file(&path);
        assert!(path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let loaded = ServiceConfig::from_toml_file(&path, true);
        assert_eq!(loaded.port, default_port());
        let _ = fs::remove_dir_all(&dir);
    }
}
