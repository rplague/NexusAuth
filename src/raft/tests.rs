//! Raft 核心集成测试：3 节点选主/复制、leader 故障重选、快照/重启恢复。

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openraft::error::NetworkError;
use openraft::error::RPCError;
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{Config, Raft, ServerState};

use super::storage::{self, StateMachineStore};
use super::types::{AdminOutcome, NodeId, PolicyCommand, PolicyResult, RaftNode, TypeConfig};

#[derive(Debug)]
struct TestFailure(String);

impl fmt::Display for TestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for TestFailure {}

fn rpc_error<E: std::error::Error>(msg: impl Into<String>) -> RPCError<NodeId, RaftNode, E> {
    RPCError::Network(NetworkError::new(&TestFailure(msg.into())))
}

#[derive(Default)]
struct Registry {
    nodes: Mutex<HashMap<NodeId, Raft<TypeConfig>>>,
}

impl Registry {
    fn insert(&self, id: NodeId, raft: Raft<TypeConfig>) {
        self.nodes.lock().unwrap().insert(id, raft);
    }

    fn get(&self, id: NodeId) -> Option<Raft<TypeConfig>> {
        self.nodes.lock().unwrap().get(&id).cloned()
    }

    fn remove(&self, id: NodeId) {
        self.nodes.lock().unwrap().remove(&id);
    }
}

#[derive(Clone)]
struct TestNetwork {
    registry: Arc<Registry>,
}

impl RaftNetworkFactory<TypeConfig> for TestNetwork {
    type Network = TestNetworkConnection;

    async fn new_client(&mut self, target: NodeId, _node: &RaftNode) -> Self::Network {
        TestNetworkConnection {
            target,
            registry: self.registry.clone(),
        }
    }
}

struct TestNetworkConnection {
    target: NodeId,
    registry: Arc<Registry>,
}

impl RaftNetwork<TypeConfig> for TestNetworkConnection {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        AppendEntriesResponse<NodeId>,
        RPCError<NodeId, RaftNode, openraft::error::RaftError<NodeId>>,
    > {
        let raft = self
            .registry
            .get(self.target)
            .ok_or_else(|| rpc_error("target unreachable"))?;
        raft.append_entries(rpc)
            .await
            .map_err(|e| rpc_error(e.to_string()))
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<
            NodeId,
            RaftNode,
            openraft::error::RaftError<NodeId, openraft::error::InstallSnapshotError>,
        >,
    > {
        let raft = self
            .registry
            .get(self.target)
            .ok_or_else(|| rpc_error("target unreachable"))?;
        raft.install_snapshot(rpc)
            .await
            .map_err(|e| rpc_error(e.to_string()))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, RaftNode, openraft::error::RaftError<NodeId>>>
    {
        let raft = self
            .registry
            .get(self.target)
            .ok_or_else(|| rpc_error("target unreachable"))?;
        raft.vote(rpc).await.map_err(|e| rpc_error(e.to_string()))
    }
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("nexusauth-raft-it-{tag}-{nanos}"))
}

fn config() -> Arc<Config> {
    Arc::new(
        Config {
            cluster_name: "test".into(),
            heartbeat_interval: 40,
            election_timeout_min: 200,
            election_timeout_max: 400,
            ..Default::default()
        }
        .validate()
        .unwrap(),
    )
}

fn node(id: NodeId) -> RaftNode {
    RaftNode {
        peer_id: format!("peer-{id}"),
        identity_key: "test".into(),
        x25519_key: String::new(),
    }
}

async fn start_node(
    dir: &std::path::Path,
    id: NodeId,
    registry: Arc<Registry>,
) -> (Raft<TypeConfig>, StateMachineStore) {
    // 重启场景下旧 Raft 的后台任务可能尚未释放 redb 文件锁；短暂重试。
    let path = dir.join(format!("raft-{id}.redb"));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let (log_store, sm) = loop {
        match storage::open(&path, "myorg") {
            Ok(opened) => break opened,
            Err(_e) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => panic!("open raft storage {}: {e}", path.display()),
        }
    };
    let network = TestNetwork {
        registry: registry.clone(),
    };
    let raft = Raft::new(id, config(), network, log_store, sm.clone())
        .await
        .unwrap();
    registry.insert(id, raft.clone());
    (raft, sm)
}

async fn wait_leader(
    nodes: &[(NodeId, Raft<TypeConfig>)],
    exclude: Option<NodeId>,
) -> (NodeId, Raft<TypeConfig>) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            for (id, raft) in nodes {
                if Some(*id) == exclude {
                    continue;
                }
                let metrics = raft.metrics();
                if metrics.borrow().state == ServerState::Leader {
                    return (*id, raft.clone());
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("leader election timed out")
}

async fn wait_service(sm: &StateMachineStore, service: &str, version: u64) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let state = sm.policy_state().await;
            if state.service_version(service) == Some(version) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("log replication timed out");
}

fn voters(ids: &[NodeId]) -> BTreeMap<NodeId, RaftNode> {
    ids.iter().map(|id| (*id, node(*id))).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_nodes_elect_and_replicate() {
    let dir = temp_dir("three");
    let registry = Arc::new(Registry::default());
    let mut nodes = Vec::new();
    let mut sms = HashMap::new();
    for id in 1..=3 {
        let (raft, sm) = start_node(&dir, id, registry.clone()).await;
        sms.insert(id, sm);
        nodes.push((id, raft));
    }
    nodes[0].1.initialize(voters(&[1, 2, 3])).await.unwrap();

    let (leader_id, leader) = wait_leader(&nodes, None).await;
    let cmd = PolicyCommand::CreateService {
        service: "cmd".into(),
        members: vec![],
    };
    let response = leader.client_write(cmd).await.unwrap();
    assert!(matches!(
        response.data,
        super::types::PolicyResult::Applied { changed: true, .. }
    ));

    for (id, sm) in &sms {
        wait_service(sm, "cmd", 1).await;
        let state = sm.policy_state().await;
        assert_eq!(state.policy_epoch, 2, "node {id} epoch");
    }
    assert!((1..=3).contains(&leader_id));

    for (_, raft) in nodes {
        let _ = raft.shutdown().await;
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leader_failover_and_continued_replication() {
    let dir = temp_dir("failover");
    let registry = Arc::new(Registry::default());
    let mut nodes = Vec::new();
    let mut sms = HashMap::new();
    for id in 1..=3 {
        let (raft, sm) = start_node(&dir, id, registry.clone()).await;
        sms.insert(id, sm);
        nodes.push((id, raft));
    }
    nodes[0].1.initialize(voters(&[1, 2, 3])).await.unwrap();
    let (old_leader, _) = wait_leader(&nodes, None).await;

    // 杀掉旧 leader：shutdown 并从注册表移除，模拟不可达。
    let old = nodes
        .iter()
        .find(|(id, _)| *id == old_leader)
        .map(|(_, r)| r.clone())
        .unwrap();
    registry.remove(old_leader);
    let _ = old.shutdown().await;

    let remaining: Vec<_> = nodes
        .iter()
        .filter(|(id, _)| *id != old_leader)
        .cloned()
        .collect();
    let (new_leader, leader) = wait_leader(&remaining, Some(old_leader)).await;
    assert_ne!(new_leader, old_leader);

    let response = leader
        .client_write(PolicyCommand::CreateService {
            service: "ocr".into(),
            members: vec![],
        })
        .await
        .unwrap();
    assert!(matches!(
        response.data,
        super::types::PolicyResult::Applied { changed: true, .. }
    ));

    for (id, _) in &remaining {
        wait_service(&sms[id], "ocr", 1).await;
    }

    for (_, raft) in remaining {
        let _ = raft.shutdown().await;
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_and_restart_recovery() {
    let dir = temp_dir("restart");
    let registry = Arc::new(Registry::default());
    let (raft, sm) = start_node(&dir, 1, registry.clone()).await;
    raft.initialize(voters(&[1])).await.unwrap();
    let _ = wait_leader(&[(1, raft.clone())], None).await;

    // 直接使用 Raft client_write，保证走真实提交流程。
    raft.client_write(PolicyCommand::CreateService {
        service: "cmd".into(),
        members: vec![],
    })
    .await
    .unwrap();
    raft.client_write(PolicyCommand::AddMembers {
        service: "cmd".into(),
        peers: vec![libp2p_identity::PeerId::random().to_string()],
    })
    .await
    .unwrap();

    raft.trigger().snapshot().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if raft.get_snapshot().await.unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("snapshot not built");

    let before = sm.policy_state().await;
    assert_eq!(before.policy_epoch, 3);
    let _ = raft.shutdown().await;
    drop(raft);
    drop(sm);
    registry.remove(1);

    // 重启：同一 redb 文件，状态应从持久化 applied state/快照恢复。
    let (_raft2, sm2) = start_node(&dir, 1, registry.clone()).await;
    let after = sm2.policy_state().await;
    assert_eq!(after.network, "myorg");
    assert_eq!(after.policy_epoch, 3);
    assert_eq!(after.service_version("cmd"), Some(2));

    let _ = _raft2.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

fn admin_create(request_id: &str, request_hash: &str, request_ts: u64) -> PolicyCommand {
    PolicyCommand::Admin {
        request_id: request_id.into(),
        kid: "root-1".into(),
        request_hash: request_hash.into(),
        request_ts,
        command: Box::new(PolicyCommand::CreateService {
            service: "cmd".into(),
            members: vec![],
        }),
    }
}

fn admin_result_fields(result: &PolicyResult) -> (u64, u64, bool, AdminOutcome) {
    match result {
        PolicyResult::Admin {
            policy_epoch,
            raft_index,
            duplicate,
            outcome,
            ..
        } => (*policy_epoch, *raft_index, *duplicate, outcome.clone()),
        other => panic!("unexpected result: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_request_idempotent_across_leader_change() {
    let dir = temp_dir("admin-idem");
    let registry = Arc::new(Registry::default());
    let mut nodes = Vec::new();
    let mut sms = HashMap::new();
    for id in 1..=3 {
        let (raft, sm) = start_node(&dir, id, registry.clone()).await;
        sms.insert(id, sm);
        nodes.push((id, raft));
    }
    nodes[0].1.initialize(voters(&[1, 2, 3])).await.unwrap();
    let (old_leader, leader) = wait_leader(&nodes, None).await;

    let command = admin_create("admin-req-1", "hash-1", 1_000);
    let first = leader.client_write(command.clone()).await.unwrap();
    let (epoch, first_index, duplicate, outcome) = admin_result_fields(&first.data);
    assert!(!duplicate);
    assert_eq!(epoch, 2);
    assert!(matches!(
        outcome,
        AdminOutcome::Applied { changed: true, .. }
    ));

    // 同一 leader 上用新日志条目重试：返回第一次结果。
    let retry = leader.client_write(command.clone()).await.unwrap();
    let (retry_epoch, retry_index, retry_duplicate, retry_outcome) =
        admin_result_fields(&retry.data);
    assert!(retry_duplicate);
    assert_eq!(retry_epoch, epoch);
    assert_eq!(retry_index, first_index);
    assert_eq!(retry_outcome, outcome);

    // leader 故障后，在新 leader 上重试同一 request_id 仍幂等。
    let old = nodes
        .iter()
        .find(|(id, _)| *id == old_leader)
        .map(|(_, r)| r.clone())
        .unwrap();
    registry.remove(old_leader);
    let _ = old.shutdown().await;
    let remaining: Vec<_> = nodes
        .iter()
        .filter(|(id, _)| *id != old_leader)
        .cloned()
        .collect();
    let (new_leader, new_leader_raft) = wait_leader(&remaining, Some(old_leader)).await;
    assert_ne!(new_leader, old_leader);

    let after_failover = new_leader_raft.client_write(command).await.unwrap();
    let (failover_epoch, failover_index, failover_duplicate, failover_outcome) =
        admin_result_fields(&after_failover.data);
    assert!(failover_duplicate);
    assert_eq!(failover_epoch, epoch);
    assert_eq!(failover_index, first_index);
    assert_eq!(failover_outcome, outcome);

    for (id, _) in &remaining {
        wait_service(&sms[id], "cmd", 1).await;
        let state = sms[id].policy_state().await;
        assert_eq!(state.policy_epoch, 2, "node {id} epoch");
        assert!(state.dedup.contains_key("admin-req-1"));
    }

    for (_, raft) in remaining {
        let _ = raft.shutdown().await;
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renew_index_through_raft_is_monotonic() {
    let dir = temp_dir("renew");
    let registry = Arc::new(Registry::default());
    let (raft, sm) = start_node(&dir, 1, registry.clone()).await;
    raft.initialize(voters(&[1])).await.unwrap();
    let _ = wait_leader(&[(1, raft.clone())], None).await;

    let first = raft
        .client_write(PolicyCommand::RenewIndex { expires_at: 1_000 })
        .await
        .unwrap();
    assert!(matches!(
        first.data,
        PolicyResult::Applied {
            policy_epoch: 2,
            changed: true,
            ..
        }
    ));
    assert_eq!(sm.policy_state().await.index_expires_at, 1_000);

    let second = raft
        .client_write(PolicyCommand::RenewIndex { expires_at: 2_000 })
        .await
        .unwrap();
    assert!(matches!(
        second.data,
        PolicyResult::Applied {
            policy_epoch: 3,
            changed: true,
            ..
        }
    ));
    let state = sm.policy_state().await;
    assert_eq!(state.policy_epoch, 3);
    assert_eq!(state.index_expires_at, 2_000);

    let _ = raft.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn remaining_voters_rejects_empty_and_preserves_quorum_sets() {
    use std::collections::BTreeSet;
    assert!(super::remaining_voters([1u64], 1).is_err());
    let remaining = super::remaining_voters([1u64, 2, 3], 1).unwrap();
    assert_eq!(remaining, BTreeSet::from([2, 3]));
    assert!(super::remaining_voters([1u64, 2], 1).is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_voter_bootstrap_learners_snapshot_sync_promote_three() {
    use std::collections::BTreeSet;

    let dir = temp_dir("membership");
    let registry = Arc::new(Registry::default());
    let mut nodes = Vec::new();
    let mut sms = HashMap::new();
    for id in 1..=3 {
        let (raft, sm) = start_node(&dir, id, registry.clone()).await;
        sms.insert(id, sm);
        nodes.push((id, raft));
    }

    // 单 voter bootstrap。
    nodes[0].1.initialize(voters(&[1])).await.unwrap();
    let (_, leader) = wait_leader(&nodes, None).await;
    leader
        .client_write(PolicyCommand::CreateService {
            service: "cmd".into(),
            members: vec![],
        })
        .await
        .unwrap();
    leader
        .client_write(PolicyCommand::AddMembers {
            service: "cmd".into(),
            peers: vec![libp2p_identity::PeerId::random().to_string()],
        })
        .await
        .unwrap();

    // 构建快照并清理日志，强制新 learner 通过 InstallSnapshot 获取策略状态。
    leader.trigger().snapshot().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if leader.get_snapshot().await.unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("snapshot not built");
    let applied = leader
        .metrics()
        .borrow()
        .last_applied
        .expect("applied log")
        .index;
    leader.trigger().purge_log(applied).await.unwrap();

    // 两个 learner 加入。
    leader.add_learner(2, node(2), false).await.unwrap();
    leader.add_learner(3, node(3), false).await.unwrap();
    wait_service(&sms[&2], "cmd", 2).await;
    wait_service(&sms[&3], "cmd", 2).await;

    // 追平后提升到 3 voters。
    leader.add_learner(2, node(2), true).await.unwrap();
    leader.add_learner(3, node(3), true).await.unwrap();
    leader
        .change_membership(BTreeSet::from([1, 2, 3]), true)
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let voters: BTreeSet<_> = leader
                .metrics()
                .borrow()
                .membership_config
                .membership()
                .voter_ids()
                .collect();
            if voters == BTreeSet::from([1, 2, 3]) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("promotion to 3 voters timed out");

    for id in 2..=3 {
        let state = sms[&id].policy_state().await;
        assert_eq!(state.service_version("cmd"), Some(2), "node {id}");
        let members: BTreeSet<_> = sms[&id]
            .membership_nodes()
            .await
            .into_iter()
            .map(|(node_id, _)| node_id)
            .collect();
        assert!(members.contains(&id));
    }

    // 重启后 membership 持久化恢复。
    for (_, raft) in &nodes {
        let _ = raft.shutdown().await;
    }
    drop(nodes);
    drop(sms);
    registry.remove(1);

    let (_raft2, sm2) = start_node(&dir, 1, registry.clone()).await;
    let restored: BTreeSet<_> = sm2
        .membership_nodes()
        .await
        .into_iter()
        .map(|(node_id, _)| node_id)
        .collect();
    assert_eq!(restored, BTreeSet::from([1, 2, 3]));

    let _ = _raft2.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
