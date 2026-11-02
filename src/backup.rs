//! 运维备份：把 voter 的关键文件复制到受限目录并生成 manifest。
//!
//! 不打包管理员私钥；`[admin.keys]` 只随配置文件保存公钥。Raft 数据（redb）
//! 本身包含日志与快照，按原文件复制；若配置为目录则递归复制。

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authority::Authority;
use crate::config::ServiceConfig;

pub const BACKUP_SCHEMA: u32 = 1;
pub const MANIFEST_NAME: &str = "manifest.json";

#[derive(Debug)]
pub enum BackupError {
    Io(String),
    Config(String),
    OutputExists(PathBuf),
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "backup io error: {e}"),
            Self::Config(e) => write!(f, "backup config error: {e}"),
            Self::OutputExists(path) => {
                write!(f, "backup output is not empty: {}", path.display())
            }
        }
    }
}

impl std::error::Error for BackupError {}

impl From<io::Error> for BackupError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFile {
    pub name: String,
    pub source: String,
    pub bytes: u64,
    pub sha256: String,
    pub mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupReport {
    pub schema: u32,
    pub created_at: u64,
    pub output_dir: String,
    pub manifest: String,
    pub network: String,
    pub cluster_id: Option<String>,
    pub authority_public_key: Option<String>,
    pub files: Vec<BackupFile>,
    pub skipped: Vec<String>,
    /// 管理员私钥必须离线保存，不进入边车备份。
    pub admin_private_keys_included: bool,
}

/// 创建备份目录。`force` 允许写入已有但非空的目录（覆盖同名文件，不删除其他内容）。
pub fn create_backup(
    config: &ServiceConfig,
    config_path: &Path,
    output_dir: &Path,
    force: bool,
) -> Result<BackupReport, BackupError> {
    let output_existed = output_dir.exists();
    if output_existed {
        let mut entries = fs::read_dir(output_dir)?;
        if entries.next().is_some() && !force {
            return Err(BackupError::OutputExists(output_dir.to_path_buf()));
        }
    } else {
        fs::create_dir_all(output_dir)?;
    }
    if !output_existed {
        set_dir_mode(output_dir)?;
    }

    let mut files = Vec::new();
    let mut skipped = Vec::new();

    copy_required(config_path, output_dir, "config.toml", &mut files)?;

    let authority_path = PathBuf::from(&config.authority_key_path);
    if authority_path.is_file() {
        copy_file(&authority_path, output_dir, "authority.key", &mut files)?;
    } else if config.cluster.enabled {
        return Err(BackupError::Config(format!(
            "cluster 模式缺少 authority key: {}",
            authority_path.display()
        )));
    } else {
        skipped.push("authority.key".to_string());
    }

    copy_optional(
        &PathBuf::from(&config.state_path),
        output_dir,
        "auth_state.toml",
        &mut files,
        &mut skipped,
    )?;

    if config.cluster.enabled {
        copy_optional(
            &PathBuf::from(&config.cluster.identity_key_path),
            output_dir,
            "raft_identity.key",
            &mut files,
            &mut skipped,
        )?;
        copy_optional(
            &PathBuf::from(&config.cluster.seed_exchange_key_path),
            output_dir,
            "raft_seed_exchange.key",
            &mut files,
            &mut skipped,
        )?;
        let data = PathBuf::from(&config.cluster.data_path);
        if data.is_dir() {
            let dest = output_dir.join("raft_data");
            copy_dir_all(&data, &dest)?;
            set_dir_mode(&dest)?;
            let (bytes, sha256) = hash_tree(&dest)?;
            files.push(BackupFile {
                name: "raft_data".to_string(),
                source: data.display().to_string(),
                bytes,
                sha256,
                mode: "0700".to_string(),
            });
        } else if data.is_file() {
            copy_file(&data, output_dir, "raft.redb", &mut files)?;
        } else {
            skipped.push("raft_data".to_string());
        }
    }

    let authority_public_key = if authority_path.is_file() {
        let network = config.network.as_str();
        if network.is_empty() {
            None
        } else {
            Authority::load(&authority_path, network)
                .ok()
                .map(|authority| authority.public_key_b64())
        }
    } else {
        None
    };

    let report = BackupReport {
        schema: BACKUP_SCHEMA,
        created_at: crate::authority::now_unix(),
        output_dir: output_dir.display().to_string(),
        manifest: output_dir.join(MANIFEST_NAME).display().to_string(),
        network: config.network.clone(),
        cluster_id: config
            .cluster
            .enabled
            .then(|| config.cluster.cluster_id.clone()),
        authority_public_key,
        files,
        skipped,
        admin_private_keys_included: false,
    };
    let manifest = serde_json::to_vec_pretty(&report)
        .map_err(|e| BackupError::Config(format!("manifest 序列化失败: {e}")))?;
    crate::fsutil::atomic_write(&output_dir.join(MANIFEST_NAME), &manifest, Some(0o600))?;
    Ok(report)
}

fn copy_required(
    source: &Path,
    output_dir: &Path,
    dest_name: &str,
    files: &mut Vec<BackupFile>,
) -> Result<(), BackupError> {
    if !source.is_file() {
        return Err(BackupError::Config(format!(
            "缺少必需文件: {}",
            source.display()
        )));
    }
    copy_file(source, output_dir, dest_name, files)
}

fn copy_optional(
    source: &Path,
    output_dir: &Path,
    dest_name: &str,
    files: &mut Vec<BackupFile>,
    skipped: &mut Vec<String>,
) -> Result<(), BackupError> {
    if source.is_file() {
        copy_file(source, output_dir, dest_name, files)
    } else {
        skipped.push(dest_name.to_string());
        Ok(())
    }
}

fn copy_file(
    source: &Path,
    output_dir: &Path,
    dest_name: &str,
    files: &mut Vec<BackupFile>,
) -> Result<(), BackupError> {
    let data = fs::read(source)?;
    let dest = output_dir.join(dest_name);
    crate::fsutil::atomic_write(&dest, &data, Some(0o600))?;
    files.push(BackupFile {
        name: dest_name.to_string(),
        source: source.display().to_string(),
        bytes: data.len() as u64,
        sha256: hash_bytes(&data),
        mode: "0600".to_string(),
    });
    Ok(())
}

fn copy_dir_all(source: &Path, dest: &Path) -> Result<(), BackupError> {
    fs::create_dir_all(dest)?;
    set_dir_mode(dest)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target = dest.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &target)?;
        } else if file_type.is_file() {
            let data = fs::read(entry.path())?;
            crate::fsutil::atomic_write(&target, &data, Some(0o600))?;
        }
    }
    Ok(())
}

fn hash_tree(root: &Path) -> Result<(u64, String), BackupError> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort();
    let mut total = 0u64;
    let mut hasher = Sha256::new();
    for (relative, path) in files {
        let data = fs::read(&path)?;
        total += data.len() as u64;
        hasher.update(relative.as_bytes());
        hasher.update([0u8]);
        hasher.update(Sha256::digest(&data));
    }
    Ok((total, hex(&hasher.finalize())))
}

fn collect_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<(), BackupError> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_files(root, &path, files)?;
        } else if entry.file_type()?.is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            files.push((relative, path));
        }
    }
    Ok(())
}

fn hash_bytes(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(unix)]
fn set_dir_mode(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_dir_mode(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// 备份 manifest 中的文件清单（供恢复核对）。
pub fn manifest_summary(report: &BackupReport) -> BTreeMap<String, String> {
    report
        .files
        .iter()
        .map(|file| (file.name.clone(), file.sha256.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::authority::Authority;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nexusauth-backup-{tag}-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_config(dir: &Path, cluster: bool) -> (ServiceConfig, PathBuf) {
        let authority_path = dir.join("authority.key");
        let authority = Authority::generate("myorg").unwrap();
        crate::fsutil::atomic_write(&authority_path, &authority.seed(), Some(0o600)).unwrap();
        let raft = dir.join("raft.redb");
        fs::write(&raft, b"raft-data").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&raft, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let config_path = dir.join("config.toml");
        let config_toml = format!(
            r#"network = "myorg"
authority_key_path = "{}"
state_path = "{}"

[cluster]
enabled = {cluster}
cluster_id = "prod"
data_path = "{}"
identity_key_path = "{}"
seed_exchange_key_path = "{}"

[[admin.keys]]
kid = "root-1"
public_key = "AAAA"
role = "root"
"#,
            authority_path.display(),
            dir.join("auth_state.toml").display(),
            raft.display(),
            dir.join("raft_identity.key").display(),
            dir.join("seed_exchange.key").display(),
        );
        fs::write(&config_path, &config_toml).unwrap();
        let config: ServiceConfig = toml::from_str(&config_toml).unwrap();
        (config, config_path)
    }

    #[test]
    fn backup_layout_and_permissions() {
        let dir = temp_dir("layout");
        let (config, config_path) = write_config(&dir, true);
        let output = dir.join("backup");
        let report = create_backup(&config, &config_path, &output, false).unwrap();

        assert!(output.join("config.toml").is_file());
        assert!(output.join("authority.key").is_file());
        assert!(output.join("raft.redb").is_file());
        assert!(output.join(MANIFEST_NAME).is_file());
        assert!(!report.admin_private_keys_included);
        assert!(report.authority_public_key.is_some());
        assert!(report.files.iter().any(|f| f.name == "authority.key"));
        assert!(report.files.iter().any(|f| f.name == "raft.redb"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in ["authority.key", "raft.redb", "config.toml", MANIFEST_NAME] {
                let mode = fs::metadata(output.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600, "{name}");
            }
            let mode = fs::metadata(&output).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }

        let manifest: BackupReport =
            serde_json::from_slice(&fs::read(output.join(MANIFEST_NAME)).unwrap()).unwrap();
        assert_eq!(manifest.schema, BACKUP_SCHEMA);
        assert_eq!(manifest.cluster_id.as_deref(), Some("prod"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_empty_output_requires_force() {
        let dir = temp_dir("exists");
        let (config, config_path) = write_config(&dir, true);
        let output = dir.join("backup");
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("old"), b"x").unwrap();
        assert!(matches!(
            create_backup(&config, &config_path, &output, false),
            Err(BackupError::OutputExists(_))
        ));
        assert!(create_backup(&config, &config_path, &output, true).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cluster_backup_requires_authority_key() {
        let dir = temp_dir("noauth");
        let (config, config_path) = write_config(&dir, true);
        fs::remove_file(&config.authority_key_path).unwrap();
        let output = dir.join("backup");
        assert!(matches!(
            create_backup(&config, &config_path, &output, false),
            Err(BackupError::Config(_))
        ));
        let _ = fs::remove_dir_all(&dir);
    }
}
