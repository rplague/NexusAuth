//! 启动期文件权限审计。
//!
//! 只做只读检查并输出告警，不自动修改部署中的权限；避免在运维不知情时
//! 改动机器状态。日志只包含路径与八进制权限位，不包含 seed/私钥内容。

use std::fs;
use std::path::{Path, PathBuf};

use crate::config::ConfigHandle;
use crate::log::{LogLevel, LogStruct};
use crate::paths;

/// 单个权限问题。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionIssue {
    pub label: String,
    pub path: PathBuf,
    pub mode: u32,
    pub expected: String,
}

impl PermissionIssue {
    pub fn message(&self) -> String {
        format!(
            "{}={} mode={:04o} expected={}",
            self.label,
            self.path.display(),
            self.mode,
            self.expected
        )
    }
}

/// 检查文件是否禁止 group/other 访问（Unix 权限位 `0o077`）。
#[cfg(unix)]
pub fn check_private_path(path: &Path, label: &str, directory: bool) -> Option<PermissionIssue> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() {
        return None;
    }
    let mode = metadata.permissions().mode() & 0o777;
    let forbidden = 0o077;
    if mode & forbidden == 0 {
        return None;
    }
    Some(PermissionIssue {
        label: label.to_string(),
        path: path.to_path_buf(),
        mode,
        expected: if directory {
            "0700".to_string()
        } else {
            "0600".to_string()
        },
    })
}

#[cfg(not(unix))]
pub fn check_private_path(_path: &Path, _label: &str, _directory: bool) -> Option<PermissionIssue> {
    None
}

/// 检查配置中所有敏感路径。返回发现的问题（可能为空）。
pub fn audit_config(config: &ConfigHandle) -> Vec<PermissionIssue> {
    let mut issues = Vec::new();
    let cluster = config.cluster();
    let mut sensitive: Vec<(PathBuf, &'static str, bool)> = vec![
        (paths::config_path(), "config", false),
        (config.authority_key_path(), "authority_key", false),
        (config.state_path(), "state", false),
    ];
    if cluster.enabled {
        sensitive.push((
            PathBuf::from(&cluster.identity_key_path),
            "raft_identity_key",
            false,
        ));
        sensitive.push((
            PathBuf::from(&cluster.seed_exchange_key_path),
            "raft_seed_exchange_key",
            false,
        ));
        let data = PathBuf::from(&cluster.data_path);
        let is_dir = fs::metadata(&data)
            .map(|meta| meta.is_dir())
            .unwrap_or(false);
        sensitive.push((data, "raft_data", is_dir));
    }
    for (path, label, directory) in sensitive {
        if let Some(issue) = check_private_path(&path, label, directory) {
            issues.push(issue);
        }
    }
    issues
}

/// 输出启动告警。权限问题不阻塞启动，但会明确记录。
pub fn audit_config_permissions(config: &ConfigHandle) {
    for issue in audit_config(config) {
        LogStruct::new(
            LogLevel::Warning,
            "文件权限过宽",
            format!(
                "{}；请执行 chmod {} {}",
                issue.message(),
                if issue.expected == "0700" {
                    "0700"
                } else {
                    "0600"
                },
                issue.path.display()
            ),
        )
        .emit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nexusauth-security-{tag}-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn private_file_accepts_0600_and_rejects_0644() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("file");
        let path = dir.join("authority.key");
        fs::write(&path, [0u8; 32]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(check_private_path(&path, "authority_key", false).is_none());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let issue = check_private_path(&path, "authority_key", false).unwrap();
        assert_eq!(issue.mode, 0o644);
        assert!(issue.message().contains("authority_key"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_accepts_0700_and_rejects_0755() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("dir");
        let nested = dir.join("raft");
        fs::create_dir(&nested).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(check_private_path(&nested, "raft_data", true).is_none());

        fs::set_permissions(&nested, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            check_private_path(&nested, "raft_data", true).unwrap().mode,
            0o755
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_paths_are_ignored() {
        let dir = temp_dir("missing");
        assert!(check_private_path(&dir.join("nope"), "x", false).is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
