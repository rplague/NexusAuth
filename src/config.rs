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

fn default_service() -> String {
    "auth".to_string()
}

fn default_join_mode() -> String {
    "require".to_string()
}

fn default_join_timeout_secs() -> u64 {
    30
}

fn default_join_retry_secs() -> u64 {
    5
}

fn default_allow_join() -> bool {
    false
}

fn default_raft_seed_exchange_key_path() -> String {
    paths::raft_seed_exchange_key_path()
        .to_string_lossy()
        .into_owned()
}

fn default_cluster_id() -> String {
    "nexusauth".to_string()
}

fn default_raft_identity_key_path() -> String {
    paths::raft_identity_key_path()
        .to_string_lossy()
        .into_owned()
}

fn default_raft_data_path() -> String {
    paths::raft_data_path().to_string_lossy().into_owned()
}

fn default_heartbeat_interval_ms() -> u64 {
    500
}

fn default_election_timeout_min_ms() -> u64 {
    1500
}

fn default_election_timeout_max_ms() -> u64 {
    3000
}

/// 管理员公钥配置（Phase 2）。
///
/// 边车只保存公钥；私钥留在管理员侧。
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminKeyConfig {
    /// 全局唯一、非空的 key id。
    #[serde(default)]
    pub kid: String,
    /// Ed25519 公钥（标准 base64，32 字节）。
    #[serde(default)]
    pub public_key: String,
    /// `viewer` 或 `root`。
    #[serde(default)]
    pub role: String,
}

/// `[admin]`：管理员公钥表。
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminConfig {
    #[serde(default)]
    pub keys: Vec<AdminKeyConfig>,
}

/// Raft 控制面成员。
///
/// NodeId 由 `peer_id` 派生，不再作为配置项。
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClusterMemberConfig {
    /// 节点侧 PeerId；Raft RPC 通过 `service_request_to` 发往该 Peer。
    pub peer_id: String,
    /// sidecar Ed25519 身份公钥（标准 base64，32 字节）。
    #[serde(default)]
    pub identity_key: String,
}

/// `[cluster]`：Raft 控制面配置。默认关闭，保持旧行为。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cluster_id")]
    pub cluster_id: String,
    /// 是否在启动时初始化单节点/配置中的 voter 集群。
    #[serde(default)]
    pub bootstrap: bool,
    #[serde(default = "default_raft_identity_key_path")]
    pub identity_key_path: String,
    #[serde(default = "default_raft_data_path")]
    pub data_path: String,
    /// 接收入网 seed 的 X25519 私钥路径（learner 也会生成，但不用于签名）。
    #[serde(default = "default_raft_seed_exchange_key_path")]
    pub seed_exchange_key_path: String,
    /// 新节点一次性 join token（JSON 字符串）。
    #[serde(default)]
    pub join_token: String,
    /// 新节点一次性 join token 文件路径（优先于 `join_token`）。
    #[serde(default)]
    pub join_token_path: String,
    #[serde(default = "default_heartbeat_interval_ms")]
    pub heartbeat_interval_ms: u64,
    #[serde(default = "default_election_timeout_min_ms")]
    pub election_timeout_min_ms: u64,
    #[serde(default = "default_election_timeout_max_ms")]
    pub election_timeout_max_ms: u64,
    #[serde(default)]
    pub voters: Vec<ClusterMemberConfig>,
    #[serde(default)]
    pub learners: Vec<ClusterMemberConfig>,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cluster_id: default_cluster_id(),
            bootstrap: false,
            identity_key_path: default_raft_identity_key_path(),
            data_path: default_raft_data_path(),
            seed_exchange_key_path: default_raft_seed_exchange_key_path(),
            join_token: String::new(),
            join_token_path: String::new(),
            heartbeat_interval_ms: default_heartbeat_interval_ms(),
            election_timeout_min_ms: default_election_timeout_min_ms(),
            election_timeout_max_ms: default_election_timeout_max_ms(),
            voters: Vec::new(),
            learners: Vec::new(),
        }
    }
}

/// 边车配置。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceConfig {
    /// 唯一服务名；用于 DHT 发现、legacy join 寻址、Raft RPC 与 `AuthContext`。
    #[serde(default = "default_service")]
    pub service: String,
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
    /// 入网总超时（秒）。
    #[serde(default = "default_join_timeout_secs")]
    pub join_timeout_secs: u64,
    /// 入网单轮失败后的重试间隔（秒）。
    #[serde(default = "default_join_retry_secs")]
    pub join_retry_secs: u64,
    /// 是否响应他人的入网请求。
    #[serde(default = "default_allow_join")]
    pub allow_join: bool,
    /// Raft 控制面（默认禁用）。
    #[serde(default)]
    pub cluster: ClusterConfig,
    /// 管理员公钥（Phase 2，Raft 模式下启用）。
    #[serde(default)]
    pub admin: AdminConfig,
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
            service: default_service(),
            port: default_port(),
            network: String::new(),
            authority_key_path: default_authority_key_path(),
            state_path: default_state_path(),
            expires_secs: default_expires_secs(),
            renew_secs: default_renew_secs(),
            management_password: String::new(),
            services: BTreeMap::new(),
            join_mode: default_join_mode(),
            join_timeout_secs: default_join_timeout_secs(),
            join_retry_secs: default_join_retry_secs(),
            allow_join: default_allow_join(),
            cluster: ClusterConfig::default(),
            admin: AdminConfig::default(),
        }
    }
}

/// 检查 TOML 文本中是否出现已从 schema 删除的字段。
///
/// 语法错误的 TOML 返回 `Ok(())`，交给常规解析路径处理（备份并重建默认配置）。
/// 旧字段必须显式拒绝，不能被静默忽略或回退到默认配置。
pub fn validate_legacy_fields(content: &str) -> Result<(), String> {
    let Ok(value) = toml::from_str::<toml::Value>(content) else {
        return Ok(());
    };

    if value.get("join_service").is_some() {
        return Err(legacy_field_error("join_service"));
    }
    if value.get("join_peers").is_some() {
        return Err(legacy_field_error("join_peers"));
    }

    let Some(cluster) = value.get("cluster") else {
        return Ok(());
    };
    if cluster.get("service").is_some() {
        return Err(legacy_field_error("[cluster].service"));
    }
    if cluster.get("node_id").is_some() {
        return Err(legacy_field_error("[cluster].node_id"));
    }
    for table in ["voters", "learners"] {
        let Some(members) = cluster.get(table).and_then(|value| value.as_array()) else {
            continue;
        };
        for (index, member) in members.iter().enumerate() {
            if member.get("node_id").is_some() {
                return Err(format!(
                    "配置字段 [[cluster.{table}]].node_id 已删除；请迁移到顶层 service / 删除 node_id（第 {} 项）",
                    index + 1
                ));
            }
        }
    }

    Ok(())
}

fn legacy_field_error(field: &str) -> String {
    format!("旧配置字段 {field} 已删除；请迁移到顶层 service / 删除 node_id")
}

impl ServiceConfig {
    /// 校验新 schema 中必须满足的约束。
    pub fn validate(&self) -> Result<(), String> {
        if self.service.trim().is_empty() {
            return Err("service 不能为空".to_string());
        }
        Ok(())
    }

    pub fn from_toml_file(path: impl AsRef<Path>, create_if_missing: bool) -> ServiceConfig {
        let path = path.as_ref();

        if !create_if_missing && !path.exists() {
            LogStruct::new(LogLevel::Warning, "配置文件不存在，使用默认配置", "").emit();
            return ServiceConfig::default();
        }

        match fs::read_to_string(path) {
            Ok(content) => {
                if let Err(message) = validate_legacy_fields(&content) {
                    LogStruct::new(LogLevel::Critical, "配置文件包含已删除字段", message).emit();
                    std::process::exit(1);
                }
                match toml::from_str(&content) {
                    Ok(config) => {
                        if let Err(message) = ServiceConfig::validate(&config) {
                            LogStruct::new(LogLevel::Critical, "配置校验失败", message).emit();
                            std::process::exit(1);
                        }
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
                }
            }
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

#[allow(dead_code)]
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

    /// 唯一服务名（默认 `"auth"`）。
    pub fn service(&self) -> String {
        self.read().service.clone()
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

    pub fn join_timeout_secs(&self) -> u64 {
        self.read().join_timeout_secs
    }

    pub fn join_retry_secs(&self) -> u64 {
        self.read().join_retry_secs
    }

    pub fn allow_join(&self) -> bool {
        self.read().allow_join
    }

    /// Raft 控制面配置（克隆）。
    pub fn cluster(&self) -> ClusterConfig {
        self.read().cluster.clone()
    }

    pub fn cluster_enabled(&self) -> bool {
        self.read().cluster.enabled
    }

    /// 管理员公钥表（克隆）。
    pub fn admin_keys(&self) -> Vec<AdminKeyConfig> {
        self.read().admin.keys.clone()
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
        assert_eq!(cfg.service, "auth");
        assert_eq!(cfg.port, 5200);
        assert!(cfg.network.is_empty());
        assert_eq!(cfg.expires_secs, 3600);
        assert_eq!(cfg.renew_secs, 1200);
        assert!(cfg.management_password.is_empty());
        assert!(cfg.services.is_empty());
        assert!(!cfg.allow_join, "allow_join must default to false");
    }

    #[test]
    fn service_default_and_explicit_value() {
        let cfg: ServiceConfig = toml::from_str("port = 5100\n").unwrap();
        assert_eq!(cfg.service, "auth");
        assert_eq!(ConfigHandle::new(cfg).service(), "auth");

        let cfg: ServiceConfig = toml::from_str("service = \"gateway\"\n").unwrap();
        assert_eq!(cfg.service, "gateway");
        assert_eq!(ConfigHandle::new(cfg).service(), "gateway");
    }

    #[test]
    fn empty_service_is_rejected() {
        let cfg: ServiceConfig = toml::from_str("service = \"  \"\n").unwrap();
        assert!(cfg.validate().is_err());
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
    fn cluster_defaults_disabled() {
        let cfg: ServiceConfig = toml::from_str("port = 5100\n").unwrap();
        assert!(!cfg.cluster.enabled);
        assert_eq!(cfg.cluster.cluster_id, "nexusauth");
        assert!(cfg.cluster.voters.is_empty());
        assert!(cfg.cluster.learners.is_empty());
    }

    #[test]
    fn cluster_config_round_trip() {
        let toml = r#"
service = "auth"
network = "myorg"

[cluster]
enabled = true
cluster_id = "prod"
bootstrap = true
heartbeat_interval_ms = 200
election_timeout_min_ms = 800
election_timeout_max_ms = 1600

[[cluster.voters]]
peer_id = "12D3KooWExample"
identity_key = "AAAA"

[[cluster.learners]]
peer_id = "12D3KooWLearner"
identity_key = "BBBB"
"#;
        let cfg: ServiceConfig = toml::from_str(toml).unwrap();
        assert!(cfg.cluster.enabled);
        assert_eq!(cfg.cluster.cluster_id, "prod");
        assert_eq!(cfg.cluster.voters.len(), 1);
        assert_eq!(cfg.cluster.voters[0].peer_id, "12D3KooWExample");
        assert_eq!(cfg.cluster.learners.len(), 1);
        assert_eq!(cfg.cluster.learners[0].peer_id, "12D3KooWLearner");

        let serialized = toml::to_string_pretty(&cfg).unwrap();
        assert!(!serialized.contains("node_id"));
        let back: ServiceConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(back.cluster.cluster_id, "prod");
        assert_eq!(back.cluster.voters[0].peer_id, "12D3KooWExample");
        assert_eq!(back.cluster.learners[0].peer_id, "12D3KooWLearner");
    }

    #[test]
    fn legacy_fields_are_rejected() {
        let cases = [
            ("join_service = \"auth\"\n", "join_service"),
            ("join_peers = [\"12D3KooWExample\"]\n", "join_peers"),
            ("[cluster]\nservice = \"auth\"\n", "[cluster].service"),
            ("[cluster]\nnode_id = 7\n", "[cluster].node_id"),
            (
                "[[cluster.voters]]\nnode_id = 7\npeer_id = \"12D3KooWExample\"\n",
                "[[cluster.voters]].node_id",
            ),
            (
                "[[cluster.learners]]\nnode_id = 8\npeer_id = \"12D3KooWExample\"\n",
                "[[cluster.learners]].node_id",
            ),
        ];

        for (content, field) in cases {
            let error = validate_legacy_fields(content).unwrap_err();
            assert!(
                error.contains(field),
                "错误 {error:?} 应包含已删除字段 {field}"
            );
            assert!(
                error.contains("请迁移到顶层 service / 删除 node_id"),
                "错误 {error:?} 应包含迁移提示"
            );
        }
    }

    #[test]
    fn new_schema_passes_legacy_check() {
        let toml = r#"
service = "auth"

[cluster]
enabled = true

[[cluster.voters]]
peer_id = "12D3KooWExample"
identity_key = "AAAA"
"#;
        assert!(validate_legacy_fields(toml).is_ok());
        assert!(validate_legacy_fields("not = [valid").is_ok());
    }

    #[test]
    fn admin_keys_parse_and_round_trip() {
        let toml = r#"
network = "myorg"

[cluster]
enabled = true

[[admin.keys]]
kid = "root-2026"
public_key = "AAAA"
role = "root"

[[admin.keys]]
kid = "viewer-2026"
public_key = "BBBB"
role = "viewer"
"#;
        let cfg: ServiceConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.admin.keys.len(), 2);
        assert_eq!(cfg.admin.keys[0].kid, "root-2026");
        assert_eq!(cfg.admin.keys[0].role, "root");
        let handle = ConfigHandle::new(cfg);
        assert_eq!(handle.admin_keys().len(), 2);

        let back: ServiceConfig =
            toml::from_str(&toml::to_string_pretty(&handle.snapshot()).unwrap()).unwrap();
        assert_eq!(back.admin.keys[1].kid, "viewer-2026");
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
