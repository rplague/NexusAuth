//! Raft 控制面数据类型：NodeId、策略命令/结果与 RPC envelope。
//!
//! 本模块只定义跨节点/跨持久化边界的稳定类型，不包含网络或存储实现。

use std::io::Cursor;

use openraft::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
use serde::{Deserialize, Serialize};

/// Raft NodeId。使用 u64 以满足 openraft 的 `Copy` 约束。
pub type NodeId = u64;

/// Raft 成员信息：既包含 NexusNet 寻址所需的 PeerId，也包含 RPC 验签公钥。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftNode {
    /// 节点侧 PeerId，RPC 通过 `service_request_to` 发往该 Peer。
    pub peer_id: String,
    /// sidecar Ed25519 身份公钥（标准 base64，32 字节）。
    pub identity_key: String,
    /// 节点用于接收 authority seed 的 X25519 公钥（标准 base64，32 字节）。
    ///
    /// learner 也携带该公钥，但只有提升为 voter 时 leader 才会向其分发 seed。
    #[serde(default)]
    pub x25519_key: String,
}

/// root 管理员签发的入网 token。
///
/// `sig` 覆盖除 `sig` 外的所有字段（规范 CBOR），由 `[admin.keys]` 中的 root 公钥验签。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinToken {
    pub v: u8,
    pub jti: String,
    pub cluster_id: String,
    pub network: String,
    pub audience: String,
    pub expires_at: u64,
    #[serde(default = "default_max_uses")]
    pub max_uses: u32,
    #[serde(default)]
    pub bind_peer_id: String,
    pub kid: String,
    #[serde(default)]
    pub sig: String,
}

fn default_max_uses() -> u32 {
    1
}

/// 已签发 token 在 Raft 状态机中的记录（不含任何密钥）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredJoinToken {
    pub token: JoinToken,
    #[serde(default)]
    pub uses: u32,
}

impl std::fmt::Display for RaftNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.peer_id)
    }
}

/// 由 apply 推进的全局策略命令。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyCommand {
    CreateService {
        service: String,
        #[serde(default)]
        members: Vec<String>,
    },
    DeleteService {
        service: String,
    },
    AddMembers {
        service: String,
        #[serde(default)]
        peers: Vec<String>,
    },
    RemoveMembers {
        service: String,
        #[serde(default)]
        peers: Vec<String>,
    },
    SetMembers {
        service: String,
        #[serde(default)]
        peers: Vec<String>,
    },
    /// Phase 2：带幂等元数据的管理员命令。
    Admin {
        request_id: String,
        kid: String,
        /// 请求身份哈希（不含 nonce/ts）。
        request_hash: String,
        /// 请求时间戳，用于去重表 TTL（随日志复制，确定性）。
        request_ts: u64,
        command: Box<PolicyCommand>,
    },
    RenewIndex {
        #[serde(default)]
        expires_at: u64,
    },
    /// 持久化 root 签发的 join token（jti 去重随 Raft 状态管理）。
    IssueJoinToken {
        token: JoinToken,
    },
    /// 消耗一次 join token；apply 时保证一次性/最大次数与绑定 PeerId。
    ConsumeJoinToken {
        jti: String,
        node_id: NodeId,
        peer_id: String,
        used_at: u64,
    },
}

/// 管理员命令的确定性结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminOutcome {
    Applied {
        service: Option<String>,
        version: Option<u64>,
        changed: bool,
    },
    Rejected {
        code: String,
        message: String,
    },
}

/// apply 的结果。拒绝也是确定性结果，不改变策略状态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyResult {
    Applied {
        service: Option<String>,
        version: Option<u64>,
        policy_epoch: u64,
        changed: bool,
    },
    Rejected {
        code: String,
        message: String,
        policy_epoch: u64,
    },
    Admin {
        request_id: String,
        policy_epoch: u64,
        raft_index: u64,
        /// 是否为重复请求（返回第一次结果）。
        duplicate: bool,
        outcome: AdminOutcome,
    },
}

/// Raft RPC 的请求体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaftRpcBody {
    Vote(VoteRequest<NodeId>),
    AppendEntries(AppendEntriesRequest<TypeConfig>),
    InstallSnapshot(InstallSnapshotRequest<TypeConfig>),
    /// leader 移除自身前请求另一个 voter 立即发起选举（openraft 0.9 无 transfer API）。
    Elect,
}

impl RaftRpcBody {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf).map_err(|e| e.to_string())?;
        Ok(buf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        ciborium::de::from_reader(bytes).map_err(|e| e.to_string())
    }
}

/// 内部 `raft_rpc` 请求（JSON 传输外层）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftRpcEnvelope {
    pub op: String,
    pub cluster_id: String,
    pub from: NodeId,
    pub to: NodeId,
    /// CBOR(`RaftRpcBody`) 的 base64url 无填充编码。
    pub body: String,
    /// sidecar Ed25519 签名（base64url 无填充）。
    pub signature: String,
}

/// 内部 `raft_rpc` 响应（JSON 传输外层）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftRpcReply {
    pub op: String,
    pub cluster_id: String,
    pub from: NodeId,
    pub to: NodeId,
    pub ok: bool,
    /// CBOR(响应体) 的 base64url 无填充编码。
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub error: String,
    /// sidecar Ed25519 签名（base64url 无填充）。
    pub signature: String,
}

openraft::declare_raft_types!(
    pub TypeConfig:
        D = PolicyCommand,
        R = PolicyResult,
        NodeId = NodeId,
        Node = RaftNode,
        Entry = openraft::Entry<TypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = openraft::TokioRuntime,
);

#[cfg(test)]
mod tests {
    use super::*;
    use openraft::Vote;

    #[test]
    fn policy_command_round_trip() {
        let cmd = PolicyCommand::AddMembers {
            service: "cmd".into(),
            peers: vec!["12D3KooW".into()],
        };
        let enc = RaftRpcBody::Vote(VoteRequest {
            vote: Vote::new(1, 1),
            last_log_id: None,
        })
        .encode()
        .unwrap();
        assert!(RaftRpcBody::decode(&enc).is_ok());

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&cmd, &mut buf).unwrap();
        let back: PolicyCommand = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back, cmd);
    }
}
