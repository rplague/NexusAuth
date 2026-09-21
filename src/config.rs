use crate::log::{LogLevel, LogStruct};
use crate::paths;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

macro_rules! default_u32_fn {
    ($name:ident, $value:expr) => {
        fn $name() -> u32 {
            $value
        }
    };
}

default_u32_fn!(default_port, 5100);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceConfig {
    #[serde(default = "default_port")]
    pub port: u32,
    // TODO: 在此添加你的业务配置字段
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
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
                Ok(config) => return config,
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
        if let Err(e) = fs::write(path, toml_string) {
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

        let temp_path = path.with_extension("tmp");

        if let Err(e) = fs::write(&temp_path, toml_string) {
            LogStruct::new(
                LogLevel::Critical,
                "写入临时配置文件失败",
                format!("路径: {}, 错误: {}", temp_path.display(), e),
            )
            .emit();
            std::process::exit(1);
        }

        if let Err(e) = fs::rename(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            LogStruct::new(
                LogLevel::Critical,
                "重命名配置文件失败",
                format!(
                    "从 {} 到 {}, 错误: {}",
                    temp_path.display(),
                    path.display(),
                    e
                ),
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
}
