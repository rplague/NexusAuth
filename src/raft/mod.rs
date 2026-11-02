//! Raft 控制面。
//!
//! Phase 1：openraft 0.9 + redb 持久化 + sidecar 签名 RPC + 确定性策略状态机。
//! Phase 2：viewer/root 管理员认证、edge → leader 转发、管理写进入 Raft log。
//! Phase 3：leader-only 发布、epoch/fencing。
//! Phase 4：join token、learner/voter 动态成员、authority seed 安全分发。
//! 默认由 `[cluster].enabled = false` 关闭；关闭时完全走旧多写者路径。

pub mod bootstrap;
pub mod join;
pub mod network;
pub mod seed;
pub mod state_machine;
pub mod storage;
pub mod token;
pub mod transport;
pub mod types;

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use openraft::{ChangeMembers, Raft};

use crate::admin_v2::{
    AdminProposal, AdminRaft, AdminVerifier, RaftStatusMember, RaftStatusSnapshot,
};
use crate::authority::Authority;
use crate::config::{ClusterConfig, ConfigHandle};
use crate::connection::BackendClient;
use crate::context::AuthContext;
use crate::log::{LogLevel, LogStruct};
use crate::protocol::SidecarError;

use self::join::{MemberInfo, RaftJoinRequest, RaftJoinResponse};
use self::network::{BackendTransport, NetworkFactory};
use self::seed::{SeedAck, SeedDeliveryRequest, SeedDropRequest, SeedExchangeKey};
use self::state_machine::PolicyState;
use self::storage::StateMachineStore;
use self::transport::{
    IdentityKey, RAFT_RPC_OP, RpcVerifier, TransportError, encode_request, node_id_from_peer_id,
};
use self::types::{
    JoinToken, NodeId, PolicyCommand, RaftNode, RaftRpcBody, RaftRpcEnvelope, RaftRpcReply,
    TypeConfig,
};

/// 启动失败原因。
#[derive(Debug)]
pub enum RaftInitError {
    Disabled,
    Whoami(String),
    Transport(TransportError),
    Storage(String),
    Config(String),
    Bootstrap(String),
}

impl fmt::Display for RaftInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RaftInitError::Disabled => write!(f, "raft cluster is disabled"),
            RaftInitError::Whoami(e) => write!(f, "whoami failed: {e}"),
            RaftInitError::Transport(e) => write!(f, "raft identity error: {e}"),
            RaftInitError::Storage(e) => write!(f, "raft storage error: {e}"),
            RaftInitError::Config(e) => write!(f, "raft config error: {e}"),
            RaftInitError::Bootstrap(e) => write!(f, "raft bootstrap error: {e}"),
        }
    }
}

impl std::error::Error for RaftInitError {}

/// 集群成员视图（公钥可见，seed 不可见）。
#[derive(Debug, Clone, Default)]
pub struct MembershipView {
    pub voters: Vec<MemberInfo>,
    pub learners: Vec<MemberInfo>,
    pub leader: Option<NodeId>,
    pub term: u64,
}

impl MembershipView {
    pub fn all(&self) -> impl Iterator<Item = &MemberInfo> {
        self.voters.iter().chain(self.learners.iter())
    }

    pub fn find(&self, node_id: NodeId) -> Option<&MemberInfo> {
        self.all().find(|member| member.node_id == node_id)
    }

    pub fn is_voter(&self, node_id: NodeId) -> bool {
        self.voters.iter().any(|member| member.node_id == node_id)
    }

    pub fn is_member(&self, node_id: NodeId) -> bool {
        self.find(node_id).is_some()
    }
}

/// 运行中的 Raft 控制面。
pub struct RaftRuntime {
    raft: Raft<TypeConfig>,
    identity: Arc<IdentityKey>,
    verifier: Arc<RpcVerifier>,
    cluster_id: String,
    node_id: NodeId,
    peer_id: String,
    service: String,
    state_machine: StateMachineStore,
    x25519: Arc<SeedExchangeKey>,
    client: BackendClient,
    rpc_timeout: Duration,
}

impl RaftRuntime {
    /// 由配置与已建立的 BackendClient 启动 Raft。
    pub async fn start(
        config: &ConfigHandle,
        client: &BackendClient,
    ) -> Result<Arc<Self>, RaftInitError> {
        let cluster = config.cluster();
        if !cluster.enabled {
            return Err(RaftInitError::Disabled);
        }
        if config.renew_secs() == 0 || config.renew_secs() >= config.expires_secs() {
            return Err(RaftInitError::Config(format!(
                "renew_secs={} must be less than expires_secs={}",
                config.renew_secs(),
                config.expires_secs()
            )));
        }
        // fail-closed：Raft 管理面至少要有一个有效的 root 公钥。
        AdminVerifier::from_config(&config.admin_keys(), true)
            .map_err(|e| RaftInitError::Config(e.to_string()))?;
        let whoami = client
            .whoami()
            .await
            .map_err(|e| RaftInitError::Whoami(e.message))?;
        let node_id = node_id_from_peer_id(&whoami);
        if node_id == 0 {
            return Err(RaftInitError::Config("node_id must be non-zero".into()));
        }

        let identity = Arc::new(
            IdentityKey::load_or_create(&cluster.identity_key_path)
                .map_err(RaftInitError::Transport)?,
        );
        let x25519 = Arc::new(
            SeedExchangeKey::load_or_create(&cluster.seed_exchange_key_path)
                .map_err(|e| RaftInitError::Config(e.to_string()))?,
        );
        let local_node = RaftNode {
            peer_id: whoami.clone(),
            identity_key: identity.public_key_b64().to_string(),
            x25519_key: x25519.public_key_b64().to_string(),
        };

        let verifier = Arc::new(RpcVerifier::new(cluster.cluster_id.clone(), node_id));
        let mut member_ids = BTreeSet::new();
        let mut self_in_config = false;
        for member in cluster.voters.iter().chain(cluster.learners.iter()) {
            if member.peer_id.is_empty() {
                return Err(RaftInitError::Config(
                    "cluster member missing peer_id".into(),
                ));
            }
            let member_id = node_id_from_peer_id(&member.peer_id);
            if !member_ids.insert(member_id) {
                return Err(RaftInitError::Config(format!(
                    "duplicate node_id {member_id} derived from configured peer_id"
                )));
            }
            self_in_config |= member.peer_id == whoami;
            verifier
                .add_node(member_id, &member.identity_key)
                .map_err(RaftInitError::Transport)?;
        }
        if member_ids.contains(&node_id) && !self_in_config {
            return Err(RaftInitError::Config(
                "local node_id collides with a configured member".into(),
            ));
        }
        // 本节点实际身份以本地 key 为准。
        verifier
            .add_node(node_id, local_node.identity_key.as_str())
            .map_err(RaftInitError::Transport)?;

        let (log_store, state_machine) = storage::open(&cluster.data_path, &config.network())
            .map_err(|e| RaftInitError::Storage(e.to_string()))?;
        // 重启后从持久化 membership 恢复 verifier，避免旧公钥失效/新公钥缺失。
        for (id, node) in state_machine.membership_nodes().await {
            verifier
                .add_node(id, &node.identity_key)
                .map_err(RaftInitError::Transport)?;
        }

        let rpc_timeout = Duration::from_millis(
            cluster
                .heartbeat_interval_ms
                .saturating_mul(4)
                .clamp(200, 10_000),
        );
        let transport = Arc::new(BackendTransport::new(client.clone(), rpc_timeout));
        let network = NetworkFactory::new(
            transport,
            identity.clone(),
            verifier.clone(),
            cluster.cluster_id.clone(),
            node_id,
            config.service(),
        );

        let raft_config = Arc::new(
            openraft::Config {
                cluster_name: cluster.cluster_id.clone(),
                heartbeat_interval: cluster.heartbeat_interval_ms.max(10),
                election_timeout_min: cluster.election_timeout_min_ms.max(50),
                election_timeout_max: cluster
                    .election_timeout_max_ms
                    .max(cluster.election_timeout_min_ms.saturating_add(50)),
                ..Default::default()
            }
            .validate()
            .map_err(|e| RaftInitError::Config(e.to_string()))?,
        );

        let raft = Raft::new(
            node_id,
            raft_config,
            network,
            log_store,
            state_machine.clone(),
        )
        .await
        .map_err(|e| RaftInitError::Storage(e.to_string()))?;

        bootstrap::bootstrap_if_enabled(&raft, &cluster, node_id, &local_node)
            .await
            .map_err(|e| RaftInitError::Bootstrap(e.to_string()))?;

        let runtime = Arc::new(Self {
            raft,
            identity,
            verifier,
            cluster_id: cluster.cluster_id,
            node_id,
            peer_id: whoami,
            service: config.service(),
            state_machine,
            x25519,
            client: client.clone(),
            rpc_timeout,
        });
        runtime.refresh_verifier_from_metrics();
        Ok(runtime)
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    pub fn service_name(&self) -> &str {
        &self.service
    }

    #[allow(dead_code)]
    pub fn verifier(&self) -> Arc<RpcVerifier> {
        self.verifier.clone()
    }

    pub fn identity(&self) -> &IdentityKey {
        &self.identity
    }

    pub async fn is_leader(&self) -> bool {
        self.raft.metrics().borrow().state == openraft::ServerState::Leader
    }

    pub async fn term(&self) -> u64 {
        self.raft.metrics().borrow().current_term
    }

    pub async fn leader_id(&self) -> Option<NodeId> {
        self.raft.metrics().borrow().current_leader
    }

    /// 当前 leader 的 NexusNet PeerId；未知时为 `None`。
    pub async fn leader_peer(&self) -> Option<String> {
        let metrics = self.raft.metrics().borrow().clone();
        let leader_id = metrics.current_leader?;
        metrics
            .membership_config
            .membership()
            .get_node(&leader_id)
            .map(|node| node.peer_id.clone())
    }

    /// 本地已应用的策略状态快照。
    pub async fn policy_snapshot(&self) -> PolicyState {
        self.state_machine.policy_state().await
    }

    /// 本地已应用的最后一个 Raft log index。
    pub async fn applied_index(&self) -> Option<u64> {
        self.state_machine.applied_index().await
    }

    /// 本地状态是否可能落后（无 leader，或 applied 落后于本地 last log）。
    pub async fn stale(&self) -> bool {
        let metrics = self.raft.metrics().borrow().clone();
        let applied = metrics.last_applied.map(|log_id| log_id.index).unwrap_or(0);
        let last = metrics.last_log_index.unwrap_or(0);
        metrics.current_leader.is_none() || applied < last
    }

    /// 订阅 Raft metrics（用于 leader 变化时触发发布）。
    pub fn metrics(&self) -> tokio::sync::watch::Receiver<openraft::RaftMetrics<NodeId, RaftNode>> {
        self.raft.metrics()
    }

    pub async fn propose(&self, command: PolicyCommand) -> Result<AdminProposal, String> {
        let response = self
            .raft
            .client_write(command)
            .await
            .map_err(|e| e.to_string())?;
        Ok(AdminProposal {
            result: response.data,
            raft_index: response.log_id.index,
        })
    }

    /// `status` 使用的 Raft 快照：包含 leader/term/state/index 与成员。
    ///
    /// 只返回公开字段；不含 authority seed、私钥或 nonce。
    pub async fn status_snapshot(&self) -> RaftStatusSnapshot {
        let metrics = self.raft.metrics().borrow().clone();
        let membership = metrics.membership_config.membership();
        let voters: BTreeSet<NodeId> = membership.voter_ids().collect();
        let mut status_voters = Vec::new();
        let mut status_learners = Vec::new();
        for (id, node) in membership.nodes() {
            let entry = RaftStatusMember {
                node_id: *id,
                peer_id: node.peer_id.clone(),
                voter: voters.contains(id),
            };
            if entry.voter {
                status_voters.push(entry);
            } else {
                status_learners.push(entry);
            }
        }
        status_voters.sort_by_key(|member| member.node_id);
        status_learners.sort_by_key(|member| member.node_id);
        let leader = metrics
            .current_leader
            .and_then(|id| membership.get_node(&id).map(|node| node.peer_id.clone()));
        let applied = metrics.last_applied.map(|log_id| log_id.index);
        let last = metrics.last_log_index;
        let stale = metrics.current_leader.is_none() || applied.unwrap_or(0) < last.unwrap_or(0);
        RaftStatusSnapshot {
            cluster_id: self.cluster_id.clone(),
            node_id: self.node_id,
            leader,
            term: metrics.current_term,
            state: server_state_name(metrics.state).to_string(),
            applied_index: applied,
            last_log_index: last,
            voters: status_voters,
            learners: status_learners,
            stale,
        }
    }

    /// 成员视图：voter/learner、当前 leader 与 term。
    pub async fn membership_view(&self) -> MembershipView {
        let metrics = self.raft.metrics().borrow().clone();
        let membership = metrics.membership_config.membership();
        let voters: BTreeSet<NodeId> = membership.voter_ids().collect();
        let mut view = MembershipView {
            leader: metrics.current_leader,
            term: metrics.current_term,
            ..Default::default()
        };
        for (id, node) in membership.nodes() {
            let info = MemberInfo {
                node_id: *id,
                peer_id: node.peer_id.clone(),
                identity_key: node.identity_key.clone(),
                x25519_key: node.x25519_key.clone(),
                voter: voters.contains(id),
            };
            if info.voter {
                view.voters.push(info);
            } else {
                view.learners.push(info);
            }
        }
        view.voters.sort_by_key(|member| member.node_id);
        view.learners.sort_by_key(|member| member.node_id);
        view
    }

    pub async fn member_node(&self, node_id: NodeId) -> Option<RaftNode> {
        let metrics = self.raft.metrics().borrow().clone();
        metrics
            .membership_config
            .membership()
            .get_node(&node_id)
            .cloned()
    }

    /// 用当前 membership 原子替换 verifier 公钥表（移除成员后旧公钥立即失效）。
    pub fn refresh_verifier_from_metrics(&self) {
        let metrics = self.raft.metrics().borrow().clone();
        let membership = metrics.membership_config.membership();
        let nodes: Vec<(NodeId, String)> = membership
            .nodes()
            .map(|(id, node)| (*id, node.identity_key.clone()))
            .collect();
        if nodes.is_empty() {
            return;
        }
        let _ = self.verifier.replace_nodes(nodes);
    }

    /// root `add_learner`：写入 Raft membership，不等待追平。
    pub async fn add_learner_node(
        &self,
        node_id: NodeId,
        node: RaftNode,
    ) -> Result<MemberInfo, String> {
        let view = self.membership_view().await;
        if view.is_member(node_id) {
            return Err(format!("node {node_id} is already a member"));
        }
        if node.identity_key.is_empty() {
            return Err("identity_key is required".into());
        }
        self.raft
            .add_learner(node_id, node.clone(), false)
            .await
            .map_err(|e| e.to_string())?;
        self.refresh_verifier_from_metrics();
        Ok(MemberInfo {
            node_id,
            peer_id: node.peer_id,
            identity_key: node.identity_key,
            x25519_key: node.x25519_key,
            voter: false,
        })
    }

    /// `promote_voter`：先阻塞等待 learner 追平，再切换 voter 集合。
    pub async fn promote_voter(&self, node_id: NodeId) -> Result<(), String> {
        let view = self.membership_view().await;
        if view.is_voter(node_id) {
            return Err(format!("node {node_id} is already a voter"));
        }
        let node = view
            .find(node_id)
            .map(|member| RaftNode {
                peer_id: member.peer_id.clone(),
                identity_key: member.identity_key.clone(),
                x25519_key: member.x25519_key.clone(),
            })
            .ok_or_else(|| format!("node {node_id} is not a learner"))?;

        // 确认 learner 已追平（openraft 会等待到 line-rate）。
        self.raft
            .add_learner(node_id, node, true)
            .await
            .map_err(|e| e.to_string())?;

        let mut voters: BTreeSet<NodeId> =
            view.voters.iter().map(|member| member.node_id).collect();
        voters.insert(node_id);
        self.raft
            .change_membership(voters, true)
            .await
            .map_err(|e| e.to_string())?;
        self.refresh_verifier_from_metrics();
        Ok(())
    }

    /// `demote_voter`：保留为 learner；leader 需要先重新选主。
    pub async fn demote_voter(&self, node_id: NodeId) -> Result<(), String> {
        let view = self.membership_view().await;
        if !view.is_voter(node_id) {
            return Err(format!("node {node_id} is not a voter"));
        }
        let remaining = remaining_voters(view.voters.iter().map(|member| member.node_id), node_id)?;
        if node_id == self.node_id && self.is_leader().await {
            self.transfer_leader_away().await?;
        }
        self.raft
            .change_membership(remaining, true)
            .await
            .map_err(|e| e.to_string())?;
        self.refresh_verifier_from_metrics();
        Ok(())
    }

    /// `remove_member`：voter 先降级再移除，learner 直接移除。
    pub async fn remove_member(&self, node_id: NodeId) -> Result<(), String> {
        let view = self.membership_view().await;
        if !view.is_member(node_id) {
            return Err(format!("node {node_id} is not a member"));
        }
        if node_id == self.node_id && self.is_leader().await {
            self.transfer_leader_away().await?;
        }
        if view.is_voter(node_id) {
            let remaining =
                remaining_voters(view.voters.iter().map(|member| member.node_id), node_id)?;
            self.raft
                .change_membership(remaining, true)
                .await
                .map_err(|e| e.to_string())?;
        }
        // 此时目标应为 learner；RemoveNodes 精确移除，不影响其他 learner。
        if self.member_node(node_id).await.is_some() {
            self.raft
                .change_membership(
                    ChangeMembers::<NodeId, RaftNode>::RemoveNodes(BTreeSet::from([node_id])),
                    true,
                )
                .await
                .map_err(|e| e.to_string())?;
        }
        self.refresh_verifier_from_metrics();
        Ok(())
    }

    /// 无 openraft transfer API：请求另一个 voter 立即竞选，并等待其成为 leader。
    async fn transfer_leader_away(&self) -> Result<(), String> {
        let view = self.membership_view().await;
        let candidate = view
            .voters
            .iter()
            .map(|member| member.node_id)
            .find(|id| *id != self.node_id)
            .ok_or_else(|| "no other voter available for leader transfer".to_string())?;
        self.send_body(candidate, RaftRpcBody::Elect).await?;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            {
                let metrics = self.raft.metrics().borrow().clone();
                if metrics.current_leader == Some(candidate)
                    && metrics.state != openraft::ServerState::Leader
                {
                    return Ok(());
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("leader re-election timed out before membership change".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn send_body(&self, target: NodeId, body: RaftRpcBody) -> Result<(), String> {
        let node = self
            .member_node(target)
            .await
            .ok_or_else(|| format!("unknown target node {target}"))?;
        let payload = encode_request(
            &self.identity,
            &self.cluster_id,
            self.node_id,
            target,
            &body,
        )
        .map_err(|e| e.to_string())?;
        let raw = self
            .client
            .service_request_to_with_timeout(
                &self.service,
                &node.peer_id,
                payload,
                self.rpc_timeout,
            )
            .await
            .map_err(|e| format!("[{}] {}", e.code, e.message))?;
        let reply: RaftRpcReply =
            serde_json::from_slice(&raw).map_err(|e| format!("decode reply: {e}"))?;
        self.verifier
            .verify_reply(target, &reply)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// leader → 新 voter：加密分发 authority seed 并验证回执。
    pub async fn deliver_seed(&self, ctx: &AuthContext, target: NodeId) -> Result<(), String> {
        let seed = ctx
            .authority_seed()
            .ok_or_else(|| "leader has no authority seed".to_string())?;
        let node = self
            .member_node(target)
            .await
            .ok_or_else(|| format!("unknown target node {target}"))?;
        let envelope = seed::seal_seed(
            &self.identity,
            self.node_id,
            &self.cluster_id,
            &ctx.network,
            target,
            &node,
            &seed,
        )
        .map_err(|e| e.to_string())?;
        let request = SeedDeliveryRequest {
            op: seed::SEED_DELIVERY_OP.to_string(),
            envelope,
        };
        let payload = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        let raw = self
            .client
            .service_request_to_with_timeout(
                &self.service,
                &node.peer_id,
                payload,
                self.rpc_timeout,
            )
            .await
            .map_err(|e| format!("[{}] {}", e.code, e.message))?;
        let ack: SeedAck = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        seed::verify_ack(&self.verifier, target, &ack).map_err(|e| e.to_string())
    }

    /// leader → 被降级/移除节点：清除 authority seed。
    pub async fn drop_remote_seed(&self, target: NodeId) -> Result<(), String> {
        let node = self
            .member_node(target)
            .await
            .ok_or_else(|| format!("unknown target node {target}"))?;
        let request = seed::sign_drop_request(
            &self.identity,
            self.node_id,
            &self.cluster_id,
            target,
            &node,
        )
        .map_err(|e| e.to_string())?;
        let payload = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        let raw = self
            .client
            .service_request_to_with_timeout(
                &self.service,
                &node.peer_id,
                payload,
                self.rpc_timeout,
            )
            .await
            .map_err(|e| format!("[{}] {}", e.code, e.message))?;
        let ack: SeedAck = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        seed::verify_ack(&self.verifier, target, &ack).map_err(|e| e.to_string())
    }

    /// learner 收到 seed 后验签、解密、写 0600 并安装到内存。
    pub async fn accept_seed(
        &self,
        ctx: &AuthContext,
        envelope: &seed::SeedEnvelope,
    ) -> Result<(), String> {
        let leader = self.leader_id().await;
        let seed = seed::open_seed(
            &self.x25519,
            &self.verifier,
            self.node_id,
            &self.peer_id,
            self.identity.public_key_b64(),
            &self.cluster_id,
            &ctx.network,
            leader,
            envelope,
        )
        .map_err(|e| e.to_string())?;
        let authority = Authority::from_seed(seed, &ctx.network).map_err(|e| e.to_string())?;
        seed::write_seed_file(&ctx.authority_key_path, &seed).map_err(|e| e.to_string())?;
        ctx.install_authority(authority);
        Ok(())
    }

    /// 收到 seed 清除请求。
    pub async fn accept_seed_drop(
        &self,
        ctx: &AuthContext,
        request: &SeedDropRequest,
    ) -> Result<(), String> {
        let leader = self.leader_id().await;
        seed::verify_drop_request(
            &self.verifier,
            leader,
            request,
            self.node_id,
            &self.peer_id,
            &self.cluster_id,
        )
        .map_err(|e| e.to_string())?;
        seed::remove_seed_file(&ctx.authority_key_path).map_err(|e| e.to_string())?;
        ctx.clear_authority();
        Ok(())
    }

    /// 新节点使用配置中的一次性 token 向任意已有 sidecar 入网。
    pub async fn try_join(&self, config: &ConfigHandle) -> Result<bool, String> {
        if self
            .raft
            .is_initialized()
            .await
            .map_err(|e| e.to_string())?
        {
            return Ok(false);
        }
        let cluster = config.cluster();
        let Some(token) = read_join_token(&cluster) else {
            return Ok(false);
        };
        let configured = cluster
            .voters
            .iter()
            .chain(cluster.learners.iter())
            .map(|member| member.peer_id.clone());
        let discovered = match self.client.discover_providers(&self.service).await {
            Ok(peers) => peers,
            Err(e) => {
                LogStruct::new(
                    LogLevel::Debug,
                    "Raft 入网发现失败",
                    format!("{}: [{}] {}", self.service, e.code, e.message),
                )
                .emit();
                Vec::new()
            }
        };
        let candidates = join_candidates(configured, discovered, &self.peer_id);
        if candidates.is_empty() {
            return Err("no join candidate available".into());
        }

        let mut request = RaftJoinRequest {
            op: join::RAFT_JOIN_OP.to_string(),
            v: join::RAFT_JOIN_VERSION,
            cluster_id: self.cluster_id.clone(),
            network: config.network(),
            token,
            node_id: self.node_id,
            peer_id: self.peer_id.clone(),
            identity_key: self.identity.public_key_b64().to_string(),
            x25519_key: self.x25519.public_key_b64().to_string(),
            nonce: random_nonce(),
            ts: crate::authority::now_unix(),
            edge_peer: String::new(),
            sig: String::new(),
        };
        join::sign_request(&self.identity, &mut request).map_err(|e| e.to_string())?;
        let payload = serde_json::to_vec(&request).map_err(|e| e.to_string())?;

        let mut last_error = String::new();
        for peer in candidates {
            let raw = match self
                .client
                .service_request_to_with_timeout(
                    &self.service,
                    &peer,
                    payload.clone(),
                    self.rpc_timeout,
                )
                .await
            {
                Ok(raw) => raw,
                Err(e) => {
                    last_error = format!("[{}] {}", e.code, e.message);
                    continue;
                }
            };
            let response: RaftJoinResponse = match serde_json::from_slice(&raw) {
                Ok(response) => response,
                Err(e) => {
                    last_error = format!("decode join response: {e}");
                    continue;
                }
            };
            if !response.ok {
                last_error = response.error;
                continue;
            }
            if response.cluster_id != self.cluster_id || response.network != config.network() {
                last_error = "join response cluster/network mismatch".into();
                continue;
            }
            let mut nodes: Vec<(NodeId, String)> = response
                .members
                .iter()
                .map(|member| (member.node_id, member.identity_key.clone()))
                .collect();
            if !nodes.iter().any(|(id, _)| *id == self.node_id) {
                nodes.push((self.node_id, self.identity.public_key_b64().to_string()));
            }
            self.verifier
                .replace_nodes(nodes)
                .map_err(|e| e.to_string())?;
            return Ok(true);
        }
        Err(if last_error.is_empty() {
            "all join candidates failed".into()
        } else {
            last_error
        })
    }

    /// 处理入站 `raft_rpc`：验签、校验 cluster 成员关系，再交给 openraft。
    pub async fn handle_rpc(&self, payload: &[u8]) -> Result<Vec<u8>, SidecarError> {
        let envelope: RaftRpcEnvelope = serde_json::from_slice(payload)
            .map_err(|e| SidecarError::new("raft_bad_request", format!("RPC 解析失败: {e}")))?;
        if envelope.op != RAFT_RPC_OP {
            return Err(SidecarError::new("raft_bad_request", "非 raft_rpc 请求"));
        }
        let (from, body) = self
            .verifier
            .verify_request(&envelope)
            .map_err(rpc_auth_error)?;

        let outcome: Result<Vec<u8>, String> = match body {
            RaftRpcBody::Vote(req) => match self.raft.vote(req).await {
                Ok(resp) => encode_cbor(&resp),
                Err(e) => Err(e.to_string()),
            },
            RaftRpcBody::AppendEntries(req) => match self.raft.append_entries(req).await {
                Ok(resp) => encode_cbor(&resp),
                Err(e) => Err(e.to_string()),
            },
            RaftRpcBody::InstallSnapshot(req) => match self.raft.install_snapshot(req).await {
                Ok(resp) => encode_cbor(&resp),
                Err(e) => Err(e.to_string()),
            },
            RaftRpcBody::Elect => match self.raft.trigger().elect().await {
                Ok(()) => Ok(Vec::new()),
                Err(e) => Err(e.to_string()),
            },
        };

        let (ok, body, error) = match outcome {
            Ok(body) => (true, body, String::new()),
            Err(e) => (false, Vec::new(), e),
        };
        network::signed_reply_payload(
            &self.identity,
            &self.cluster_id,
            self.node_id,
            from,
            ok,
            body,
            error,
        )
        .map_err(|e| SidecarError::new("raft_encode_error", e))
    }
}

fn server_state_name(state: openraft::ServerState) -> &'static str {
    match state {
        openraft::ServerState::Leader => "leader",
        openraft::ServerState::Follower => "follower",
        openraft::ServerState::Candidate => "candidate",
        openraft::ServerState::Learner => "learner",
        openraft::ServerState::Shutdown => "shutdown",
    }
}

/// 计算移除某 voter 后的集合；拒绝清空 voter（quorum 保护的最后防线）。
fn remaining_voters(
    voters: impl IntoIterator<Item = NodeId>,
    remove: NodeId,
) -> Result<BTreeSet<NodeId>, String> {
    let remaining: BTreeSet<NodeId> = voters.into_iter().filter(|id| *id != remove).collect();
    if remaining.is_empty() {
        return Err("refusing to remove/demote the last voter".into());
    }
    Ok(remaining)
}

/// 合并配置成员与 DHT 发现结果：排除自身、排序去重。
fn join_candidates(
    configured: impl IntoIterator<Item = String>,
    discovered: impl IntoIterator<Item = String>,
    self_peer: &str,
) -> Vec<String> {
    let mut candidates: Vec<String> = configured
        .into_iter()
        .chain(discovered)
        .filter(|peer| peer != self_peer)
        .collect();
    candidates.sort();
    candidates.dedup();
    candidates
}

fn read_join_token(cluster: &ClusterConfig) -> Option<JoinToken> {
    let text = if !cluster.join_token_path.is_empty() {
        std::fs::read_to_string(&cluster.join_token_path).ok()?
    } else if !cluster.join_token.is_empty() {
        cluster.join_token.clone()
    } else {
        return None;
    };
    serde_json::from_str(&text).ok()
}

fn random_nonce() -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rand_core::RngCore;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

impl AdminRaft for RaftRuntime {
    fn is_leader(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async move { RaftRuntime::is_leader(self).await })
    }

    fn term(&self) -> Pin<Box<dyn Future<Output = u64> + Send + '_>> {
        Box::pin(async move { RaftRuntime::term(self).await })
    }

    fn leader_peer(&self) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        Box::pin(async move { RaftRuntime::leader_peer(self).await })
    }

    fn policy_snapshot(&self) -> Pin<Box<dyn Future<Output = PolicyState> + Send + '_>> {
        Box::pin(async move { RaftRuntime::policy_snapshot(self).await })
    }

    fn applied_index(&self) -> Pin<Box<dyn Future<Output = Option<u64>> + Send + '_>> {
        Box::pin(async move { RaftRuntime::applied_index(self).await })
    }

    fn stale(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async move { RaftRuntime::stale(self).await })
    }

    fn service_name(&self) -> &str {
        &self.service
    }

    fn propose(
        &self,
        command: PolicyCommand,
    ) -> Pin<Box<dyn Future<Output = Result<AdminProposal, String>> + Send + '_>> {
        Box::pin(async move { RaftRuntime::propose(self, command).await })
    }

    fn status_snapshot(&self) -> Pin<Box<dyn Future<Output = RaftStatusSnapshot> + Send + '_>> {
        Box::pin(async move { RaftRuntime::status_snapshot(self).await })
    }
}

fn encode_cbor<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

fn rpc_auth_error(e: TransportError) -> SidecarError {
    SidecarError::new("raft_auth_failed", e.to_string())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod join_candidate_tests {
    use super::join_candidates;

    #[test]
    fn configured_and_discovered_are_merged_sorted_deduped() {
        let got = join_candidates(
            vec!["b".to_string(), "self".to_string()],
            vec!["a".to_string(), "b".to_string()],
            "self",
        );
        assert_eq!(got, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn only_self_yields_no_candidates() {
        let got = join_candidates(Vec::<String>::new(), vec!["self".to_string()], "self");
        assert!(got.is_empty());
    }
}
