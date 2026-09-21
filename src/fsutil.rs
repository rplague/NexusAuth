//! 文件写入辅助：原子写入（临时文件 + rename），可选设置权限位。

use std::fs;
use std::io;
use std::path::Path;

/// 原子写入：先写 `<path>.tmp`，按需设置权限，再 rename 覆盖目标。
///
/// `mode` 为 `Some` 时在 Unix 上设置权限位（如 `0o600`）。
pub fn atomic_write(path: &Path, data: &[u8], mode: Option<u32>) -> io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("tmp");
    fs::write(&temp, data)?;
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(mode))?;
    }
    let _ = mode;
    fs::rename(&temp, path)?;
    Ok(())
}
