//! 单节点 bootstrap 与 learner 加入的基础逻辑。
//!
//! Phase 1 只提供显式调用：`bootstrap` 配置为 true 时初始化配置中的 voter；
//! learner 的自动加入/提升留给后续阶段接入管理面。

use std::collections::BTreeMap;
use std::fmt;

use openraft::Raft;

use crate::config::{ClusterConfig, ClusterMemberConfig};
use crate::raft::transport::node_id_from_peer_id;
use crate::raft::types::{NodeId, RaftNode, TypeConfig};

#[derive(Debug)]
pub enum BootstrapError {
    Raft(String),
    Member(String),
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootstrapError::Raft(e) => write!(f, "raft bootstrap error: {e}"),
            BootstrapError::Member(e) => write!(f, "bad cluster member config: {e}"),
        }
    }
}

impl std::error::Error for BootstrapError {}

/// 把配置中的成员转换为 openraft 的 `NodeId -> RaftNode`。
///
/// NodeId 始终由 `peer_id` 派生；重复 PeerId（或派生冲突）会被拒绝。
pub fn members_from_config(
    members: &[ClusterMemberConfig],
) -> Result<BTreeMap<NodeId, RaftNode>, BootstrapError> {
    let mut map = BTreeMap::new();
    for member in members {
        if member.peer_id.is_empty() {
            return Err(BootstrapError::Member("missing peer_id".to_string()));
        }
        let node_id = node_id_from_peer_id(&member.peer_id);
        if node_id == 0 {
            return Err(BootstrapError::Member(
                "derived node_id must be non-zero".to_string(),
            ));
        }
        if member.identity_key.is_empty() {
            return Err(BootstrapError::Member(format!(
                "node {node_id} missing identity_key"
            )));
        }
        if map
            .insert(
                node_id,
                RaftNode {
                    peer_id: member.peer_id.clone(),
                    identity_key: member.identity_key.clone(),
                    x25519_key: String::new(),
                },
            )
            .is_some()
        {
            return Err(BootstrapError::Member(format!(
                "duplicate node_id {node_id} derived from peer_id"
            )));
        }
    }
    Ok(map)
}

/// 按配置初始化集群。返回是否实际执行了 initialize。
pub async fn bootstrap_if_enabled(
    raft: &Raft<TypeConfig>,
    config: &ClusterConfig,
    local_id: NodeId,
    local_node: &RaftNode,
) -> Result<bool, BootstrapError> {
    if !config.bootstrap {
        return Ok(false);
    }
    if raft
        .is_initialized()
        .await
        .map_err(|e| BootstrapError::Raft(e.to_string()))?
    {
        return Ok(false);
    }

    let mut voters = members_from_config(&config.voters)?;
    if voters.is_empty() {
        voters.insert(local_id, local_node.clone());
    } else {
        voters.entry(local_id).or_insert_with(|| local_node.clone());
    }
    if voters.is_empty() {
        return Err(BootstrapError::Member("no voter configured".into()));
    }

    raft.initialize(voters)
        .await
        .map_err(|e| BootstrapError::Raft(e.to_string()))?;
    Ok(true)
}

/// 由 leader 添加 learner（不阻塞等待追平）。
#[allow(dead_code)]
pub async fn add_learner(
    raft: &Raft<TypeConfig>,
    id: NodeId,
    node: RaftNode,
) -> Result<(), BootstrapError> {
    raft.add_learner(id, node, false)
        .await
        .map_err(|e| BootstrapError::Raft(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(peer_id: &str) -> ClusterMemberConfig {
        ClusterMemberConfig {
            peer_id: peer_id.into(),
            identity_key: "AAAA".into(),
        }
    }

    #[test]
    fn config_members_derive_node_id() {
        let members = vec![member("12D3KooW")];
        let map = members_from_config(&members).unwrap();
        let expected = node_id_from_peer_id("12D3KooW");
        assert_eq!(map.get(&expected).unwrap().peer_id, "12D3KooW");
    }

    #[test]
    fn invalid_member_rejected() {
        let members = vec![member("")];
        assert!(matches!(
            members_from_config(&members),
            Err(BootstrapError::Member(_))
        ));
    }

    #[test]
    fn duplicate_peer_id_rejected() {
        let members = vec![member("12D3KooW"), member("12D3KooW")];
        assert!(matches!(
            members_from_config(&members),
            Err(BootstrapError::Member(_))
        ));
    }
}
