//! 成员状态：服务 → 白名单成员集合 + 版本号，落盘持久化。
//!
//! 状态文件为 TOML，首启可由配置 `[services.<name>].members` 播种；之后以状态文件为准。
//! 版本号单调递增（重启不回退），供白名单/索引记录签名使用。

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::authority::{is_valid_peer_id, is_valid_service_name};
use crate::fsutil;

/// 状态层错误。
#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    /// 状态文件解析失败
    Parse(String),
    /// 状态文件记录的网络与配置不一致
    NetworkMismatch {
        expected: String,
        found: String,
    },
    InvalidService(String),
    InvalidPeer(String),
    NotFound(String),
    AlreadyExists(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "io error: {e}"),
            StoreError::Parse(e) => write!(f, "state parse error: {e}"),
            StoreError::NetworkMismatch { expected, found } => {
                write!(
                    f,
                    "state network mismatch: expected '{expected}', found '{found}'"
                )
            }
            StoreError::InvalidService(s) => write!(f, "invalid service name: '{s}'"),
            StoreError::InvalidPeer(p) => write!(f, "invalid peer id: '{p}'"),
            StoreError::NotFound(s) => write!(f, "service not found: '{s}'"),
            StoreError::AlreadyExists(s) => write!(f, "service already exists: '{s}'"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e)
    }
}

/// 单个服务的持久化状态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceState {
    pub version: u64,
    #[serde(default)]
    pub members: BTreeSet<String>,
}

/// 状态快照（即状态文件的完整内容，用于落盘、入网与复制传输）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreSnapshot {
    pub network: String,
    pub index_version: u64,
    #[serde(default)]
    pub services: BTreeMap<String, ServiceState>,
    /// 服务 → 删除版本（墓碑，防旧复制/旧快照复活）。
    #[serde(default)]
    pub tombstones: BTreeMap<String, u64>,
}

/// 权威发布状态。
pub struct Store {
    path: PathBuf,
    network: String,
    index_version: u64,
    services: BTreeMap<String, ServiceState>,
    tombstones: BTreeMap<String, u64>,
}

impl Store {
    /// 加载状态文件；不存在则以 `initial` 播种并落盘。
    ///
    /// 状态文件存在时以它为准（配置中的成员仅用于首启播种）。
    pub fn load_or_create(
        path: impl AsRef<Path>,
        network: &str,
        initial: &BTreeMap<String, Vec<String>>,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref();
        match fs::read_to_string(path) {
            Ok(content) => {
                let file: StoreSnapshot =
                    toml::from_str(&content).map_err(|e| StoreError::Parse(e.to_string()))?;
                if file.network != network {
                    return Err(StoreError::NetworkMismatch {
                        expected: network.to_string(),
                        found: file.network,
                    });
                }
                Ok(Self {
                    path: path.to_path_buf(),
                    network: network.to_string(),
                    index_version: file.index_version,
                    services: file.services,
                    tombstones: file.tombstones,
                })
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut services = BTreeMap::new();
                for (name, members) in initial {
                    if !is_valid_service_name(name) {
                        return Err(StoreError::InvalidService(name.clone()));
                    }
                    let mut set = BTreeSet::new();
                    for m in members {
                        if !is_valid_peer_id(m) {
                            return Err(StoreError::InvalidPeer(m.clone()));
                        }
                        set.insert(m.clone());
                    }
                    services.insert(
                        name.clone(),
                        ServiceState {
                            version: 1,
                            members: set,
                        },
                    );
                }
                let store = Self {
                    path: path.to_path_buf(),
                    network: network.to_string(),
                    index_version: 1,
                    services,
                    tombstones: BTreeMap::new(),
                };
                store.save()?;
                Ok(store)
            }
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    /// 当前状态快照（用于入网与复制传输）。
    pub fn snapshot(&self) -> StoreSnapshot {
        StoreSnapshot {
            network: self.network.clone(),
            index_version: self.index_version,
            services: self.services.clone(),
            tombstones: self.tombstones.clone(),
        }
    }

    /// 由快照构造并落盘（网络须一致）。
    pub fn from_snapshot(
        path: impl AsRef<Path>,
        network: &str,
        snapshot: StoreSnapshot,
    ) -> Result<Self, StoreError> {
        if snapshot.network != network {
            return Err(StoreError::NetworkMismatch {
                expected: network.to_string(),
                found: snapshot.network,
            });
        }
        let store = Self {
            path: path.as_ref().to_path_buf(),
            network: network.to_string(),
            index_version: snapshot.index_version,
            services: snapshot.services,
            tombstones: snapshot.tombstones,
        };
        store.save()?;
        Ok(store)
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn index_version(&self) -> u64 {
        self.index_version
    }

    pub fn service_names(&self) -> Vec<String> {
        self.services.keys().cloned().collect()
    }

    pub fn contains(&self, service: &str) -> bool {
        self.services.contains_key(service)
    }

    pub fn version(&self, service: &str) -> Option<u64> {
        self.services.get(service).map(|s| s.version)
    }

    pub fn members(&self, service: &str) -> Option<Vec<String>> {
        self.services
            .get(service)
            .map(|s| s.members.iter().cloned().collect())
    }

    pub fn member_count(&self, service: &str) -> Option<usize> {
        self.services.get(service).map(|s| s.members.len())
    }

    /// 新增成员；实际有变化时才提升版本。返回该服务新版本。
    pub fn add_members(&mut self, service: &str, peers: &[String]) -> Result<u64, StoreError> {
        validate_peers(peers)?;
        let state = self
            .services
            .get_mut(service)
            .ok_or_else(|| StoreError::NotFound(service.to_string()))?;
        let mut changed = false;
        for p in peers {
            changed |= state.members.insert(p.clone());
        }
        Ok(self.finish_change(service, changed))
    }

    /// 移除成员；实际有变化时才提升版本。返回该服务新版本。
    pub fn remove_members(&mut self, service: &str, peers: &[String]) -> Result<u64, StoreError> {
        validate_peers(peers)?;
        let state = self
            .services
            .get_mut(service)
            .ok_or_else(|| StoreError::NotFound(service.to_string()))?;
        let mut changed = false;
        for p in peers {
            changed |= state.members.remove(p);
        }
        Ok(self.finish_change(service, changed))
    }

    /// 整体替换成员集合；有变化时才提升版本。返回该服务新版本。
    pub fn set_members(&mut self, service: &str, peers: &[String]) -> Result<u64, StoreError> {
        validate_peers(peers)?;
        let new: BTreeSet<String> = peers.iter().cloned().collect();
        let state = self
            .services
            .get_mut(service)
            .ok_or_else(|| StoreError::NotFound(service.to_string()))?;
        let changed = state.members != new;
        if changed {
            state.members = new;
        }
        Ok(self.finish_change(service, changed))
    }

    /// 新建服务，初始版本为 1。
    pub fn create_service(&mut self, service: &str, peers: &[String]) -> Result<u64, StoreError> {
        if !is_valid_service_name(service) {
            return Err(StoreError::InvalidService(service.to_string()));
        }
        validate_peers(peers)?;
        if self.services.contains_key(service) {
            return Err(StoreError::AlreadyExists(service.to_string()));
        }
        self.services.insert(
            service.to_string(),
            ServiceState {
                version: 1,
                members: peers.iter().cloned().collect(),
            },
        );
        self.index_version += 1;
        self.save()?;
        Ok(1)
    }

    /// 删除服务，返回墓碑版本（= 原服务版本 + 1，单调）。
    pub fn delete_service(&mut self, service: &str) -> Result<u64, StoreError> {
        let removed = self
            .services
            .remove(service)
            .ok_or_else(|| StoreError::NotFound(service.to_string()))?;
        let tombstone = removed.version + 1;
        self.tombstones.insert(service.to_string(), tombstone);
        self.index_version += 1;
        self.save()?;
        Ok(tombstone)
    }

    /// 单服务合并（不落盘）：合并服务条目并提升索引版本。
    ///
    /// `index_version` 始终取 `max`（即使条目被忽略）；返回「条目或索引版本是否有变化」。
    fn merge_entry(
        &mut self,
        service: &str,
        version: u64,
        members: &[String],
        index_version: u64,
        deleted: bool,
    ) -> Result<bool, StoreError> {
        let entry_changed = self.merge_service(service, version, members, deleted)?;
        let index_changed = index_version > self.index_version;
        if index_changed {
            self.index_version = index_version;
        }
        Ok(entry_changed || index_changed)
    }

    /// 服务条目合并，确定性收敛：
    ///
    /// - 删除在同版本上胜出（防并发 delete/update 分叉）。
    /// - 同版本不同内容时按成员集合规范哈希**择大**，双方最终取同一内容。
    fn merge_service(
        &mut self,
        service: &str,
        version: u64,
        members: &[String],
        deleted: bool,
    ) -> Result<bool, StoreError> {
        if !is_valid_service_name(service) {
            return Err(StoreError::InvalidService(service.to_string()));
        }
        let current = self.services.get(service).map(|s| s.version).unwrap_or(0);
        let tombstone = self.tombstones.get(service).copied().unwrap_or(0);

        if deleted {
            if version < current || version < tombstone {
                return Ok(false);
            }
            // 已删除且墓碑不早于该版本 → 幂等无变化
            if !self.services.contains_key(service) && tombstone >= version {
                return Ok(false);
            }
            self.services.remove(service);
            self.tombstones.insert(service.to_string(), version);
            return Ok(true);
        }

        validate_peers(members)?;
        // 删除在同版本上胜出
        if version <= tombstone || version < current {
            return Ok(false);
        }
        let incoming: BTreeSet<String> = members.iter().cloned().collect();
        if version == current {
            let existing = self.services.get(service).expect("current > 0");
            if existing.members == incoming {
                return Ok(false);
            }
            // 等版本不同内容：规范哈希择大
            if members_hash(&existing.members) >= members_hash(&incoming) {
                return Ok(false);
            }
        }
        self.services.insert(
            service.to_string(),
            ServiceState {
                version,
                members: incoming,
            },
        );
        self.tombstones.remove(service);
        Ok(true)
    }

    /// 复制应用：按服务版本 LWW 合并单服务（含墓碑）。返回是否有变化。
    pub fn apply_replicated(
        &mut self,
        service: &str,
        version: u64,
        members: &[String],
        index_version: u64,
        deleted: bool,
    ) -> Result<bool, StoreError> {
        let changed = self.merge_entry(service, version, members, index_version, deleted)?;
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    /// 反熵：合并整份快照（含墓碑），只落盘一次。返回是否有变化。
    pub fn merge_snapshot(&mut self, snapshot: StoreSnapshot) -> Result<bool, StoreError> {
        let mut changed = false;
        for (name, state) in &snapshot.services {
            let members: Vec<String> = state.members.iter().cloned().collect();
            changed |=
                self.merge_entry(name, state.version, &members, snapshot.index_version, false)?;
        }
        for (name, version) in &snapshot.tombstones {
            changed |= self.merge_entry(name, *version, &[], snapshot.index_version, true)?;
        }
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    /// 提升索引版本（续期时使用）。返回新版本。
    pub fn bump_index_version(&mut self) -> u64 {
        self.index_version += 1;
        let _ = self.save();
        self.index_version
    }

    /// 变更收尾：有变化则提升服务与索引版本并落盘。
    fn finish_change(&mut self, service: &str, changed: bool) -> u64 {
        if !changed {
            return self.services[service].version;
        }
        let state = self.services.get_mut(service).expect("service exists");
        state.version += 1;
        self.index_version += 1;
        let version = state.version;
        let _ = self.save();
        version
    }

    fn save(&self) -> Result<(), StoreError> {
        let file = self.snapshot();
        let toml_string =
            toml::to_string_pretty(&file).map_err(|e| StoreError::Parse(e.to_string()))?;
        fsutil::atomic_write(&self.path, toml_string.as_bytes(), Some(0o600))?;
        Ok(())
    }
}

fn validate_peers(peers: &[String]) -> Result<(), StoreError> {
    for p in peers {
        if !is_valid_peer_id(p) {
            return Err(StoreError::InvalidPeer(p.clone()));
        }
    }
    Ok(())
}

/// 成员集合的规范哈希（有序、带分隔符），用于等版本冲突的确定性 tie-break。
fn members_hash(members: &BTreeSet<String>) -> Vec<u8> {
    let mut buf = Vec::new();
    for m in members {
        buf.extend_from_slice(m.as_bytes());
        buf.push(0);
    }
    crate::authority::content_hash(&buf)
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
        let dir = std::env::temp_dir().join(format!("nexusauth-store-{tag}-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn peer() -> String {
        libp2p_identity::PeerId::random().to_string()
    }

    fn initial(service: &str, members: &[String]) -> BTreeMap<String, Vec<String>> {
        let mut map = BTreeMap::new();
        map.insert(service.to_string(), members.to_vec());
        map
    }

    #[test]
    fn first_run_seeds_and_persists() {
        let dir = temp_dir("seed");
        let path = dir.join("auth_state.toml");
        let p = peer();
        let store = Store::load_or_create(&path, "myorg", &initial("cmd", &[p.clone()])).unwrap();

        assert_eq!(store.network(), "myorg");
        assert_eq!(store.index_version(), 1);
        assert_eq!(store.service_names(), vec!["cmd".to_string()]);
        assert_eq!(store.version("cmd"), Some(1));
        assert_eq!(store.members("cmd"), Some(vec![p.clone()]));
        assert!(path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reload_uses_state_not_config() {
        let dir = temp_dir("reload");
        let path = dir.join("auth_state.toml");
        let p1 = peer();
        let p2 = peer();
        let mut store =
            Store::load_or_create(&path, "myorg", &initial("cmd", &[p1.clone()])).unwrap();
        store.add_members("cmd", std::slice::from_ref(&p2)).unwrap();

        // 再次加载：配置里的初始成员被忽略，以状态文件为准
        let reloaded = Store::load_or_create(&path, "myorg", &initial("cmd", &[])).unwrap();
        assert_eq!(reloaded.members("cmd").unwrap().len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn version_bumps_only_on_change() {
        let dir = temp_dir("bump");
        let path = dir.join("auth_state.toml");
        let p1 = peer();
        let p2 = peer();
        let mut store =
            Store::load_or_create(&path, "myorg", &initial("cmd", &[p1.clone()])).unwrap();

        assert_eq!(
            store.add_members("cmd", std::slice::from_ref(&p2)).unwrap(),
            2
        );
        assert_eq!(store.index_version(), 2);
        // 重复添加同一成员：无变化
        assert_eq!(
            store.add_members("cmd", std::slice::from_ref(&p2)).unwrap(),
            2
        );
        assert_eq!(store.index_version(), 2);

        assert_eq!(
            store
                .remove_members("cmd", std::slice::from_ref(&p1))
                .unwrap(),
            3
        );
        assert_eq!(store.index_version(), 3);
        // 移除不存在的成员：无变化
        assert_eq!(
            store
                .remove_members("cmd", std::slice::from_ref(&p1))
                .unwrap(),
            3
        );

        let all = vec![p1.clone(), p2.clone()];
        assert_eq!(store.set_members("cmd", &all).unwrap(), 4);
        assert_eq!(store.set_members("cmd", &all).unwrap(), 4);
        assert_eq!(store.bump_index_version(), 5);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_inputs_rejected() {
        let dir = temp_dir("invalid");
        let path = dir.join("auth_state.toml");
        let mut store = Store::load_or_create(&path, "myorg", &initial("cmd", &[])).unwrap();

        assert!(matches!(
            store.add_members("cmd", &["not-a-peer".to_string()]),
            Err(StoreError::InvalidPeer(_))
        ));
        assert!(matches!(
            store.create_service("bad name", &[]),
            Err(StoreError::InvalidService(_))
        ));
        assert!(matches!(
            store.create_service("service", &[]),
            Err(StoreError::InvalidService(_))
        ));
        assert!(matches!(
            store.add_members("missing", &[peer()]),
            Err(StoreError::NotFound(_))
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_and_delete_service() {
        let dir = temp_dir("create-delete");
        let path = dir.join("auth_state.toml");
        let mut store = Store::load_or_create(&path, "myorg", &BTreeMap::new()).unwrap();
        assert_eq!(store.index_version(), 1);

        assert_eq!(store.create_service("ocr", &[peer()]).unwrap(), 1);
        assert!(store.contains("ocr"));
        assert_eq!(store.index_version(), 2);
        assert!(matches!(
            store.create_service("ocr", &[]),
            Err(StoreError::AlreadyExists(_))
        ));

        store.delete_service("ocr").unwrap();
        assert!(!store.contains("ocr"));
        assert_eq!(store.index_version(), 3);
        assert!(matches!(
            store.delete_service("ocr"),
            Err(StoreError::NotFound(_))
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn network_mismatch_rejected() {
        let dir = temp_dir("mismatch");
        let path = dir.join("auth_state.toml");
        Store::load_or_create(&path, "myorg", &BTreeMap::new()).unwrap();
        assert!(matches!(
            Store::load_or_create(&path, "other", &BTreeMap::new()),
            Err(StoreError::NetworkMismatch { .. })
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn replicated_lww_and_tombstone() {
        let dir = temp_dir("repl");
        let path = dir.join("auth_state.toml");
        let p = peer();
        let mut store = Store::load_or_create(&path, "myorg", &initial("cmd", &[])).unwrap();

        // 高版本采用
        assert!(
            store
                .apply_replicated("cmd", 3, std::slice::from_ref(&p), 5, false)
                .unwrap()
        );
        assert_eq!(store.version("cmd"), Some(3));
        assert_eq!(store.index_version(), 5);
        // 低版本 / 等版本同内容：无变化（索引版本不变）
        assert!(!store.apply_replicated("cmd", 2, &[], 5, false).unwrap());
        assert!(
            !store
                .apply_replicated("cmd", 3, std::slice::from_ref(&p), 5, false)
                .unwrap()
        );
        // 删除（墓碑 v4）
        assert!(store.apply_replicated("cmd", 4, &[], 6, true).unwrap());
        assert!(!store.contains("cmd"));
        // 旧复制不能复活
        assert!(
            !store
                .apply_replicated("cmd", 3, std::slice::from_ref(&p), 6, false)
                .unwrap()
        );
        // 更高版本可复活
        assert!(
            store
                .apply_replicated("cmd", 5, std::slice::from_ref(&p), 7, false)
                .unwrap()
        );
        assert_eq!(store.version("cmd"), Some(5));

        let reloaded = Store::load_or_create(&path, "myorg", &BTreeMap::new()).unwrap();
        assert_eq!(reloaded.version("cmd"), Some(5));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_sets_tombstone_and_persists() {
        let dir = temp_dir("tombstone");
        let path = dir.join("auth_state.toml");
        let mut store = Store::load_or_create(&path, "myorg", &initial("cmd", &[])).unwrap();
        let tombstone = store.delete_service("cmd").unwrap();
        assert_eq!(tombstone, 2);
        assert_eq!(store.snapshot().tombstones.get("cmd"), Some(&2));

        let reloaded = Store::load_or_create(&path, "myorg", &BTreeMap::new()).unwrap();
        assert!(!reloaded.contains("cmd"));
        assert_eq!(reloaded.snapshot().tombstones.get("cmd"), Some(&2));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_snapshot_merges_services_and_tombstones() {
        let dir = temp_dir("merge");
        let path = dir.join("auth_state.toml");
        let p = peer();
        let mut store = Store::load_or_create(&path, "myorg", &initial("cmd", &[])).unwrap();

        let mut services = BTreeMap::new();
        services.insert(
            "cmd".to_string(),
            ServiceState {
                version: 4,
                members: std::iter::once(p.clone()).collect(),
            },
        );
        services.insert(
            "ocr".to_string(),
            ServiceState {
                version: 1,
                members: BTreeSet::new(),
            },
        );
        let mut tombstones = BTreeMap::new();
        tombstones.insert("old".to_string(), 3);
        let snap = StoreSnapshot {
            network: "myorg".to_string(),
            index_version: 20,
            services,
            tombstones,
        };

        assert!(store.merge_snapshot(snap).unwrap());
        assert_eq!(store.version("cmd"), Some(4));
        assert_eq!(store.members("cmd"), Some(vec![p]));
        assert!(store.contains("ocr"));
        assert_eq!(store.index_version(), 20);
        assert_eq!(store.snapshot().tombstones.get("old"), Some(&3));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_equal_version_converges() {
        let dir = temp_dir("converge");
        let mut a =
            Store::load_or_create(dir.join("a.toml"), "myorg", &initial("cmd", &[])).unwrap();
        let mut b =
            Store::load_or_create(dir.join("b.toml"), "myorg", &initial("cmd", &[])).unwrap();

        let set_x: Vec<String> = vec![peer()];
        let set_y: Vec<String> = vec![peer(), peer()];
        a.apply_replicated("cmd", 2, &set_x, 2, false).unwrap();
        b.apply_replicated("cmd", 2, &set_y, 2, false).unwrap();

        // 互相收到对方同版本内容
        a.apply_replicated("cmd", 2, &set_y, 2, false).unwrap();
        b.apply_replicated("cmd", 2, &set_x, 2, false).unwrap();

        assert_eq!(a.members("cmd"), b.members("cmd"));
        let hx = members_hash(&set_x.iter().cloned().collect());
        let hy = members_hash(&set_y.iter().cloned().collect());
        let mut expected = if hx >= hy { set_x } else { set_y };
        expected.sort();
        assert_eq!(a.members("cmd").unwrap(), expected);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_wins_equal_version() {
        let dir = temp_dir("delwin");
        let mut a =
            Store::load_or_create(dir.join("a.toml"), "myorg", &initial("cmd", &[])).unwrap();
        let mut b =
            Store::load_or_create(dir.join("b.toml"), "myorg", &initial("cmd", &[])).unwrap();
        let p = peer();

        a.apply_replicated("cmd", 2, &[], 2, true).unwrap();
        b.apply_replicated("cmd", 2, std::slice::from_ref(&p), 2, false)
            .unwrap();

        a.apply_replicated("cmd", 2, std::slice::from_ref(&p), 2, false)
            .unwrap();
        b.apply_replicated("cmd", 2, &[], 2, true).unwrap();

        assert!(!a.contains("cmd"));
        assert!(!b.contains("cmd"));
        assert_eq!(a.snapshot().tombstones.get("cmd"), Some(&2));
        assert_eq!(b.snapshot().tombstones.get("cmd"), Some(&2));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn equal_version_same_content_idempotent() {
        let dir = temp_dir("idem");
        let mut s =
            Store::load_or_create(dir.join("s.toml"), "myorg", &initial("cmd", &[])).unwrap();
        let p = peer();
        assert!(
            s.apply_replicated("cmd", 2, std::slice::from_ref(&p), 2, false)
                .unwrap()
        );
        assert!(
            !s.apply_replicated("cmd", 2, std::slice::from_ref(&p), 2, false)
                .unwrap()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_merge_converges_without_leader() {
        let dir = temp_dir("noleader");
        let mut a =
            Store::load_or_create(dir.join("a.toml"), "myorg", &initial("cmd", &[])).unwrap();
        let mut b =
            Store::load_or_create(dir.join("b.toml"), "myorg", &initial("cmd", &[])).unwrap();
        let p = peer();

        // A 改成员（service v2, index 2）；B 独立续期（index 3）
        a.add_members("cmd", std::slice::from_ref(&p)).unwrap();
        b.bump_index_version();
        b.bump_index_version();

        let sa = a.snapshot();
        let sb = b.snapshot();
        a.merge_snapshot(sb).unwrap();
        b.merge_snapshot(sa).unwrap();

        assert_eq!(a.members("cmd"), Some(vec![p.clone()]));
        assert_eq!(b.members("cmd"), Some(vec![p]));
        assert_eq!(a.index_version(), 3);
        assert_eq!(b.index_version(), 3);
        let _ = fs::remove_dir_all(&dir);
    }
}
