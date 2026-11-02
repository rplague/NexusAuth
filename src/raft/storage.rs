//! openraft 持久化：redb 中的 log、vote、成员关系、状态机与快照。
//!
//! 设计要点：
//! - append/save_vote/apply/install_snapshot 都在返回前提交 redb 事务。
//! - state machine 一次 apply 批量原子落盘；失败返回 `StorageError`，不更新内存。
//! - 快照与状态机共享同一 redb 文件，重启后优先使用持久化的 applied state。
#![allow(clippy::result_large_err)]

use std::fmt;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use openraft::storage::{LogState, RaftLogStorage, RaftStateMachine};
use openraft::{
    Entry, EntryPayload, LogId, RaftLogReader, RaftSnapshotBuilder, Snapshot, SnapshotMeta,
    StorageError, StorageIOError, StoredMembership,
};
use redb::{Database, ReadableTable, TableDefinition};
use tokio::sync::Mutex;

use super::state_machine::PolicyState;
use super::types::{NodeId, PolicyResult, RaftNode, TypeConfig};

const LOG_TABLE: TableDefinition<'static, u64, &[u8]> = TableDefinition::new("raft_logs");
const META_TABLE: TableDefinition<'static, &str, &[u8]> = TableDefinition::new("raft_meta");
const SNAPSHOT_TABLE: TableDefinition<'static, &str, &[u8]> = TableDefinition::new("raft_snapshot");

const KEY_VOTE: &str = "vote";
const KEY_LAST_PURGED: &str = "last_purged";
const KEY_COMMITTED: &str = "committed";
const KEY_APPLIED: &str = "applied";
const KEY_MEMBERSHIP: &str = "membership";
const KEY_POLICY_STATE: &str = "policy_state";
const KEY_SNAPSHOT_META: &str = "meta";
const KEY_SNAPSHOT_DATA: &str = "data";

#[derive(Debug)]
struct StorageFailure(String);

impl fmt::Display for StorageFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for StorageFailure {}

fn io_read(what: &str, e: impl fmt::Display) -> StorageError<NodeId> {
    let failure = StorageFailure(format!("{what}: {e}"));
    StorageError::IO {
        source: StorageIOError::read(&failure),
    }
}

fn io_write(what: &str, e: impl fmt::Display) -> StorageError<NodeId> {
    let failure = StorageFailure(format!("{what}: {e}"));
    StorageError::IO {
        source: StorageIOError::write(&failure),
    }
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, StorageError<NodeId>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).map_err(|e| io_write("cbor encode", e))?;
    Ok(buf)
}

fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    what: &str,
) -> Result<T, StorageError<NodeId>> {
    ciborium::de::from_reader(bytes).map_err(|e| io_read(what, e))
}

/// 打开 redb 并返回 log store / state machine 两个句柄。
pub fn open(
    path: impl AsRef<Path>,
    network: &str,
) -> Result<(LogStore, StateMachineStore), StorageError<NodeId>> {
    let path = path.as_ref();
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| io_write("create raft data dir", e))?;
    }
    let db = Database::create(path).map_err(|e| io_write("open redb", e))?;
    {
        let txn = db.begin_write().map_err(|e| io_write("begin init", e))?;
        {
            txn.open_table(LOG_TABLE)
                .map_err(|e| io_write("open log table", e))?;
            txn.open_table(META_TABLE)
                .map_err(|e| io_write("open meta table", e))?;
            txn.open_table(SNAPSHOT_TABLE)
                .map_err(|e| io_write("open snapshot table", e))?;
        }
        txn.commit().map_err(|e| io_write("commit init", e))?;
    }
    let db = Arc::new(db);
    let log_store = LogStore { db: db.clone() };
    let state_machine = StateMachineStore::open(db, network)?;
    Ok((log_store, state_machine))
}

fn meta_get(db: &Database, key: &str) -> Result<Option<Vec<u8>>, StorageError<NodeId>> {
    let txn = db.begin_read().map_err(|e| io_read("begin read meta", e))?;
    let table = txn
        .open_table(META_TABLE)
        .map_err(|e| io_read("open meta table", e))?;
    let value = table.get(key).map_err(|e| io_read("read meta", e))?;
    Ok(value.map(|v| v.value().to_vec()))
}

fn snapshot_get(db: &Database, key: &str) -> Result<Option<Vec<u8>>, StorageError<NodeId>> {
    let txn = db
        .begin_read()
        .map_err(|e| io_read("begin read snapshot", e))?;
    let table = txn
        .open_table(SNAPSHOT_TABLE)
        .map_err(|e| io_read("open snapshot table", e))?;
    let value = table.get(key).map_err(|e| io_read("read snapshot", e))?;
    Ok(value.map(|v| v.value().to_vec()))
}

/// openraft log/vote 存储。
#[derive(Clone)]
pub struct LogStore {
    db: Arc<Database>,
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| io_read("begin read log", e))?;
        let table = txn
            .open_table(LOG_TABLE)
            .map_err(|e| io_read("open log table", e))?;
        let iter = table.range(range).map_err(|e| io_read("range log", e))?;
        let mut entries = Vec::new();
        for item in iter {
            let (_, value) = item.map_err(|e| io_read("read log entry", e))?;
            entries.push(decode(value.value(), "decode log entry")?);
        }
        Ok(entries)
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = LogStore;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let last_purged = meta_get(&self.db, KEY_LAST_PURGED)?
            .map(|bytes| decode::<LogId<NodeId>>(&bytes, "decode last_purged"))
            .transpose()?;

        let txn = self
            .db
            .begin_read()
            .map_err(|e| io_read("begin read log", e))?;
        let table = txn
            .open_table(LOG_TABLE)
            .map_err(|e| io_read("open log table", e))?;
        let mut last: Option<LogId<NodeId>> = None;
        for item in table.iter().map_err(|e| io_read("iterate logs", e))? {
            let (_, value) = item.map_err(|e| io_read("read last log", e))?;
            let entry: Entry<TypeConfig> = decode(value.value(), "decode last log")?;
            last = Some(entry.log_id);
        }
        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id: last.or(last_purged),
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(
        &mut self,
        vote: &openraft::Vote<NodeId>,
    ) -> Result<(), StorageError<NodeId>> {
        let bytes = encode(vote)?;
        let txn = self
            .db
            .begin_write()
            .map_err(|e| io_write("begin save vote", e))?;
        {
            let mut table = txn
                .open_table(META_TABLE)
                .map_err(|e| io_write("open meta table", e))?;
            table
                .insert(KEY_VOTE, bytes.as_slice())
                .map_err(|e| io_write("save vote", e))?;
        }
        txn.commit().map_err(|e| io_write("commit vote", e))
    }

    async fn read_vote(&mut self) -> Result<Option<openraft::Vote<NodeId>>, StorageError<NodeId>> {
        meta_get(&self.db, KEY_VOTE)?
            .map(|bytes| decode(&bytes, "decode vote"))
            .transpose()
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        let bytes = encode(&committed)?;
        let txn = self
            .db
            .begin_write()
            .map_err(|e| io_write("begin save committed", e))?;
        {
            let mut table = txn
                .open_table(META_TABLE)
                .map_err(|e| io_write("open meta table", e))?;
            table
                .insert(KEY_COMMITTED, bytes.as_slice())
                .map_err(|e| io_write("save committed", e))?;
        }
        txn.commit().map_err(|e| io_write("commit committed", e))
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        meta_get(&self.db, KEY_COMMITTED)?
            .map(|bytes| decode(&bytes, "decode committed"))
            .transpose()
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: openraft::storage::LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut encoded = Vec::new();
        for entry in entries {
            encoded.push((entry.log_id.index, encode(&entry)?));
        }

        let result = (|| -> Result<(), StorageError<NodeId>> {
            let txn = self
                .db
                .begin_write()
                .map_err(|e| io_write("begin append", e))?;
            {
                let mut table = txn
                    .open_table(LOG_TABLE)
                    .map_err(|e| io_write("open log table", e))?;
                for (index, bytes) in &encoded {
                    table
                        .insert(*index, bytes.as_slice())
                        .map_err(|e| io_write("append log", e))?;
                }
            }
            txn.commit().map_err(|e| io_write("commit append", e))
        })();

        match &result {
            Ok(()) => callback.log_io_completed(Ok(())),
            Err(e) => callback.log_io_completed(Err(std::io::Error::other(e.to_string()))),
        }
        result
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| io_write("begin truncate", e))?;
        {
            let mut table = txn
                .open_table(LOG_TABLE)
                .map_err(|e| io_write("open log table", e))?;
            let mut keys = Vec::new();
            for item in table.iter().map_err(|e| io_read("iterate truncate", e))? {
                let (key, _) = item.map_err(|e| io_read("read truncate key", e))?;
                if key.value() >= log_id.index {
                    keys.push(key.value());
                }
            }
            for key in keys {
                table.remove(key).map_err(|e| io_write("truncate log", e))?;
            }
        }
        txn.commit().map_err(|e| io_write("commit truncate", e))
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let meta = encode(&log_id)?;
        let txn = self
            .db
            .begin_write()
            .map_err(|e| io_write("begin purge", e))?;
        {
            let mut logs = txn
                .open_table(LOG_TABLE)
                .map_err(|e| io_write("open log table", e))?;
            let mut keys = Vec::new();
            for item in logs.iter().map_err(|e| io_read("iterate purge", e))? {
                let (key, _) = item.map_err(|e| io_read("read purge key", e))?;
                if key.value() <= log_id.index {
                    keys.push(key.value());
                }
            }
            for key in keys {
                logs.remove(key).map_err(|e| io_write("purge log", e))?;
            }
            let mut meta_table = txn
                .open_table(META_TABLE)
                .map_err(|e| io_write("open meta table", e))?;
            meta_table
                .insert(KEY_LAST_PURGED, meta.as_slice())
                .map_err(|e| io_write("save last_purged", e))?;
        }
        txn.commit().map_err(|e| io_write("commit purge", e))
    }
}

struct SmInner {
    state: PolicyState,
    applied: Option<LogId<NodeId>>,
    membership: StoredMembership<NodeId, RaftNode>,
}

/// redb 持久化的确定性状态机。
#[derive(Clone)]
pub struct StateMachineStore {
    db: Arc<Database>,
    inner: Arc<Mutex<SmInner>>,
    snapshot_idx: Arc<AtomicU64>,
}

impl StateMachineStore {
    fn open(db: Arc<Database>, network: &str) -> Result<Self, StorageError<NodeId>> {
        let state = match meta_get(&db, KEY_POLICY_STATE)? {
            Some(bytes) => decode(&bytes, "decode policy state")?,
            None => PolicyState::new(network),
        };
        let applied = meta_get(&db, KEY_APPLIED)?
            .map(|bytes| decode(&bytes, "decode applied"))
            .transpose()?;
        let membership = match meta_get(&db, KEY_MEMBERSHIP)? {
            Some(bytes) => decode(&bytes, "decode membership")?,
            None => StoredMembership::default(),
        };
        Ok(Self {
            db,
            inner: Arc::new(Mutex::new(SmInner {
                state,
                applied,
                membership,
            })),
            snapshot_idx: Arc::new(AtomicU64::new(0)),
        })
    }

    /// 当前策略状态快照（只读）。
    pub async fn policy_state(&self) -> PolicyState {
        self.inner.lock().await.state.clone()
    }

    #[allow(dead_code)]
    pub async fn policy_epoch(&self) -> u64 {
        self.inner.lock().await.state.policy_epoch
    }

    /// 已应用的最后一个 Raft log index。
    pub async fn applied_index(&self) -> Option<u64> {
        self.inner.lock().await.applied.map(|log_id| log_id.index)
    }

    /// 已持久化的成员节点列表。
    pub async fn membership_nodes(&self) -> Vec<(NodeId, RaftNode)> {
        let membership = self.inner.lock().await.membership.clone();
        membership
            .membership()
            .nodes()
            .map(|(id, node)| (*id, node.clone()))
            .collect()
    }

    async fn persist_state(
        &self,
        txn: &redb::WriteTransaction,
        state: &PolicyState,
        applied: Option<LogId<NodeId>>,
        membership: &StoredMembership<NodeId, RaftNode>,
    ) -> Result<(), StorageError<NodeId>> {
        let state_bytes = encode(state)?;
        let applied_bytes = encode(&applied)?;
        let membership_bytes = encode(membership)?;
        let mut table = txn
            .open_table(META_TABLE)
            .map_err(|e| io_write("open meta table", e))?;
        table
            .insert(KEY_POLICY_STATE, state_bytes.as_slice())
            .map_err(|e| io_write("persist policy state", e))?;
        table
            .insert(KEY_APPLIED, applied_bytes.as_slice())
            .map_err(|e| io_write("persist applied", e))?;
        table
            .insert(KEY_MEMBERSHIP, membership_bytes.as_slice())
            .map_err(|e| io_write("persist membership", e))?;
        Ok(())
    }
}

impl RaftSnapshotBuilder<TypeConfig> for StateMachineStore {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let (state, applied, membership) = {
            let guard = self.inner.lock().await;
            (guard.state.clone(), guard.applied, guard.membership.clone())
        };
        let data = encode(&state)?;
        let idx = self.snapshot_idx.fetch_add(1, Ordering::Relaxed) + 1;
        let snapshot_id = match applied {
            Some(log_id) => format!("{}-{}-{}", log_id.leader_id, log_id.index, idx),
            None => format!("--{idx}"),
        };
        let meta = SnapshotMeta {
            last_log_id: applied,
            last_membership: membership,
            snapshot_id,
        };
        let meta_bytes = encode(&meta)?;

        let txn = self
            .db
            .begin_write()
            .map_err(|e| io_write("begin snapshot", e))?;
        {
            let mut table = txn
                .open_table(SNAPSHOT_TABLE)
                .map_err(|e| io_write("open snapshot table", e))?;
            table
                .insert(KEY_SNAPSHOT_META, meta_bytes.as_slice())
                .map_err(|e| io_write("save snapshot meta", e))?;
            table
                .insert(KEY_SNAPSHOT_DATA, data.as_slice())
                .map_err(|e| io_write("save snapshot data", e))?;
        }
        txn.commit().map_err(|e| io_write("commit snapshot", e))?;

        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftStateMachine<TypeConfig> for StateMachineStore {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, RaftNode>), StorageError<NodeId>>
    {
        let guard = self.inner.lock().await;
        Ok((guard.applied, guard.membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<PolicyResult>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut guard = self.inner.lock().await;
        let mut state = guard.state.clone();
        let mut applied = guard.applied;
        let mut membership = guard.membership.clone();
        let mut responses = Vec::new();

        for entry in entries {
            let log_id = entry.log_id;
            applied = Some(log_id);
            match entry.payload {
                EntryPayload::Blank => responses.push(PolicyResult::Applied {
                    service: None,
                    version: None,
                    policy_epoch: state.policy_epoch,
                    changed: false,
                }),
                EntryPayload::Normal(command) => {
                    responses.push(state.apply_command_at(&command, log_id.index));
                }
                EntryPayload::Membership(mem) => {
                    membership = StoredMembership::new(Some(entry.log_id), mem);
                    responses.push(PolicyResult::Applied {
                        service: None,
                        version: None,
                        policy_epoch: state.policy_epoch,
                        changed: true,
                    });
                }
            }
        }

        // 整批原子落盘；失败时不更新内存，向 Raft 返回错误。
        let txn = self
            .db
            .begin_write()
            .map_err(|e| io_write("begin apply", e))?;
        self.persist_state(&txn, &state, applied, &membership)
            .await?;
        txn.commit().map_err(|e| io_write("commit apply", e))?;

        guard.state = state;
        guard.applied = applied;
        guard.membership = membership;
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, RaftNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let data = snapshot.into_inner();
        let state: PolicyState = decode(&data, "decode snapshot state")?;
        let meta_bytes = encode(meta)?;

        let mut guard = self.inner.lock().await;
        let txn = self
            .db
            .begin_write()
            .map_err(|e| io_write("begin install snapshot", e))?;
        self.persist_state(&txn, &state, meta.last_log_id, &meta.last_membership)
            .await?;
        {
            let mut table = txn
                .open_table(SNAPSHOT_TABLE)
                .map_err(|e| io_write("open snapshot table", e))?;
            table
                .insert(KEY_SNAPSHOT_META, meta_bytes.as_slice())
                .map_err(|e| io_write("save snapshot meta", e))?;
            table
                .insert(KEY_SNAPSHOT_DATA, data.as_slice())
                .map_err(|e| io_write("save snapshot data", e))?;
        }
        txn.commit()
            .map_err(|e| io_write("commit install snapshot", e))?;

        guard.state = state;
        guard.applied = meta.last_log_id;
        guard.membership = meta.last_membership.clone();
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        let Some(meta_bytes) = snapshot_get(&self.db, KEY_SNAPSHOT_META)? else {
            return Ok(None);
        };
        let Some(data) = snapshot_get(&self.db, KEY_SNAPSHOT_DATA)? else {
            return Ok(None);
        };
        let meta: SnapshotMeta<NodeId, RaftNode> = decode(&meta_bytes, "decode snapshot meta")?;
        Ok(Some(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::types::TypeConfig;
    use openraft::Vote;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("nexusauth-raft-storage-{tag}-{nanos}"))
            .join("raft.redb")
    }

    #[test]
    fn log_and_vote_round_trip() {
        let path = temp_path("log");
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (mut log, sm) = open(&path, "myorg").unwrap();
            let vote = Vote::new(1, 3);
            log.save_vote(&vote).await.unwrap();
            assert_eq!(log.read_vote().await.unwrap(), Some(vote));

            let state = sm.policy_state().await;
            assert_eq!(state.network, "myorg");
            assert_eq!(state.policy_epoch, 1);
        });
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn state_machine_applies_and_persists() {
        use crate::raft::types::PolicyCommand;
        use openraft::{Entry, EntryPayload};

        let path = temp_path("apply");
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (_log, mut sm) = open(&path, "myorg").unwrap();
            let entry = Entry::<TypeConfig> {
                log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
                payload: EntryPayload::Normal(PolicyCommand::CreateService {
                    service: "cmd".into(),
                    members: vec![],
                }),
            };
            let res = sm.apply(vec![entry]).await.unwrap();
            assert_eq!(res.len(), 1);
            assert_eq!(sm.policy_epoch().await, 2);
            drop(sm);
            drop(_log);

            let (_log, sm2) = open(&path, "myorg").unwrap();
            let state = sm2.policy_state().await;
            assert_eq!(state.policy_epoch, 2);
            assert_eq!(state.service_version("cmd"), Some(1));
        });
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn snapshot_build_and_reload() {
        use crate::raft::types::PolicyCommand;
        use openraft::{Entry, EntryPayload};

        let path = temp_path("snapshot");
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (_log, mut sm) = open(&path, "myorg").unwrap();
            let entry = Entry::<TypeConfig> {
                log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
                payload: EntryPayload::Normal(PolicyCommand::CreateService {
                    service: "cmd".into(),
                    members: vec![],
                }),
            };
            sm.apply(vec![entry]).await.unwrap();
            let snap = sm
                .get_snapshot_builder()
                .await
                .build_snapshot()
                .await
                .unwrap();
            assert!(snap.meta.last_log_id.is_some());
            drop(sm);
            drop(_log);

            let (_log, mut sm2) = open(&path, "myorg").unwrap();
            let current = sm2.get_current_snapshot().await.unwrap();
            assert!(current.is_some());
            assert_eq!(sm2.policy_state().await.policy_epoch, 2);
        });
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
