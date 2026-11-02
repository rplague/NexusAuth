//! sidecar Ed25519 身份与 Raft RPC 签名/验签。
//!
//! RPC 经 NexusNet 的 `service_request_to("auth", peer, payload)` 传输；payload 为
//! JSON envelope，`body` 为 CBOR(`RaftRpcBody`) 的 base64url 编码。请求/响应都由
//! sidecar 身份私钥签名，接收方用配置中的成员公钥验签并校验 cluster/from/to。

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::RwLock;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::RngCore;

use crate::fsutil;
use crate::raft::types::{NodeId, RaftRpcBody, RaftRpcEnvelope, RaftRpcReply};

pub const RAFT_RPC_OP: &str = "raft_rpc";
pub const IDENTITY_SEED_LEN: usize = 32;

const REQ_DOMAIN: &[u8] = b"nexusauth/raft/rpc";
const RESP_DOMAIN: &[u8] = b"nexusauth/raft/resp";

#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),
    InvalidSeed,
    InvalidKey,
    BadBase64,
    BadSignature,
    WrongCluster,
    WrongTarget,
    WrongSender,
    UnknownNode(NodeId),
    Decode(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "io error: {e}"),
            TransportError::InvalidSeed => write!(f, "invalid sidecar identity seed"),
            TransportError::InvalidKey => write!(f, "invalid sidecar identity key"),
            TransportError::BadBase64 => write!(f, "invalid base64 in raft rpc"),
            TransportError::BadSignature => write!(f, "invalid raft rpc signature"),
            TransportError::WrongCluster => write!(f, "raft rpc cluster mismatch"),
            TransportError::WrongTarget => write!(f, "raft rpc target mismatch"),
            TransportError::WrongSender => write!(f, "raft rpc sender mismatch"),
            TransportError::UnknownNode(id) => write!(f, "raft rpc from unknown node {id}"),
            TransportError::Decode(e) => write!(f, "raft rpc decode error: {e}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        TransportError::Io(e)
    }
}

/// sidecar 的 Raft 身份私钥。
pub struct IdentityKey {
    signing_key: SigningKey,
    public_key_b64: String,
}

impl IdentityKey {
    pub fn generate() -> Self {
        let mut seed = [0u8; IDENTITY_SEED_LEN];
        rand_core::OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: [u8; IDENTITY_SEED_LEN]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key_b64 = STANDARD.encode(signing_key.verifying_key().to_bytes());
        Self {
            signing_key,
            public_key_b64,
        }
    }

    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, TransportError> {
        let path = path.as_ref();
        let seed = match fs::read(path) {
            Ok(bytes) => {
                if bytes.len() != IDENTITY_SEED_LEN {
                    return Err(TransportError::InvalidSeed);
                }
                let mut seed = [0u8; IDENTITY_SEED_LEN];
                seed.copy_from_slice(&bytes);
                seed
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let identity = Self::generate();
                let seed = identity.signing_key.to_bytes();
                fsutil::atomic_write(path, &seed, Some(0o600))?;
                return Ok(identity);
            }
            Err(e) => return Err(TransportError::Io(e)),
        };
        Ok(Self::from_seed(seed))
    }

    pub fn public_key_b64(&self) -> &str {
        &self.public_key_b64
    }

    pub fn sign_b64(&self, msg: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.sign(msg).to_bytes())
    }
}

fn request_input(cluster_id: &str, from: NodeId, to: NodeId, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(REQ_DOMAIN);
    v.push(0);
    v.extend_from_slice(cluster_id.as_bytes());
    v.push(0);
    v.extend_from_slice(&from.to_be_bytes());
    v.push(0);
    v.extend_from_slice(&to.to_be_bytes());
    v.push(0);
    v.extend_from_slice(body);
    v
}

fn response_input(
    cluster_id: &str,
    from: NodeId,
    to: NodeId,
    ok: bool,
    body: &[u8],
    error: &str,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(RESP_DOMAIN);
    v.push(0);
    v.extend_from_slice(cluster_id.as_bytes());
    v.push(0);
    v.extend_from_slice(&from.to_be_bytes());
    v.push(0);
    v.extend_from_slice(&to.to_be_bytes());
    v.push(0);
    v.push(ok as u8);
    v.push(0);
    v.extend_from_slice(body);
    v.push(0);
    v.extend_from_slice(error.as_bytes());
    v
}

/// 构造并签名一条请求 envelope（JSON bytes）。
pub fn encode_request(
    identity: &IdentityKey,
    cluster_id: &str,
    from: NodeId,
    to: NodeId,
    body: &RaftRpcBody,
) -> Result<Vec<u8>, TransportError> {
    let body_bytes = body.encode().map_err(TransportError::Decode)?;
    let signature = identity.sign_b64(&request_input(cluster_id, from, to, &body_bytes));
    let envelope = RaftRpcEnvelope {
        op: RAFT_RPC_OP.to_string(),
        cluster_id: cluster_id.to_string(),
        from,
        to,
        body: URL_SAFE_NO_PAD.encode(body_bytes),
        signature,
    };
    serde_json::to_vec(&envelope).map_err(|e| TransportError::Decode(e.to_string()))
}

/// 构造并签名一条响应 envelope（JSON bytes）。
pub fn encode_reply(
    identity: &IdentityKey,
    cluster_id: &str,
    from: NodeId,
    to: NodeId,
    ok: bool,
    body: &[u8],
    error: &str,
) -> Result<Vec<u8>, TransportError> {
    let signature = identity.sign_b64(&response_input(cluster_id, from, to, ok, body, error));
    let reply = RaftRpcReply {
        op: RAFT_RPC_OP.to_string(),
        cluster_id: cluster_id.to_string(),
        from,
        to,
        ok,
        body: URL_SAFE_NO_PAD.encode(body),
        error: error.to_string(),
        signature,
    };
    serde_json::to_vec(&reply).map_err(|e| TransportError::Decode(e.to_string()))
}

/// cluster 成员公钥表 + 验签器。
///
/// 成员变更时由 `RaftRuntime` 原地更新，网络层共享同一个 `Arc`。
pub struct RpcVerifier {
    cluster_id: String,
    local_id: NodeId,
    keys: RwLock<BTreeMap<NodeId, VerifyingKey>>,
}

impl RpcVerifier {
    pub fn new(cluster_id: impl Into<String>, local_id: NodeId) -> Self {
        Self {
            cluster_id: cluster_id.into(),
            local_id,
            keys: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn add_node(&self, node_id: NodeId, identity_key_b64: &str) -> Result<(), TransportError> {
        let key = parse_verifying_key(identity_key_b64)?;
        self.keys
            .write()
            .expect("verifier poisoned")
            .insert(node_id, key);
        Ok(())
    }

    #[allow(dead_code)]
    pub fn remove_node(&self, node_id: NodeId) {
        self.keys
            .write()
            .expect("verifier poisoned")
            .remove(&node_id);
    }

    /// 用给定成员集合替换验签公钥表（移除不再属于集群的旧公钥）。
    pub fn replace_nodes(
        &self,
        nodes: impl IntoIterator<Item = (NodeId, String)>,
    ) -> Result<(), TransportError> {
        let mut parsed = BTreeMap::new();
        for (node_id, key_b64) in nodes {
            parsed.insert(node_id, parse_verifying_key(&key_b64)?);
        }
        *self.keys.write().expect("verifier poisoned") = parsed;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn has_node(&self, node_id: NodeId) -> bool {
        self.keys
            .read()
            .expect("verifier poisoned")
            .contains_key(&node_id)
    }

    #[allow(dead_code)]
    pub fn node_ids(&self) -> Vec<NodeId> {
        self.keys
            .read()
            .expect("verifier poisoned")
            .keys()
            .copied()
            .collect()
    }

    /// 用某节点身份公钥验证任意字节（seed 分发回执等内部消息）。
    pub fn verify_node_signature(
        &self,
        node_id: NodeId,
        message: &[u8],
        signature_b64: &str,
    ) -> Result<(), TransportError> {
        let keys = self.keys.read().expect("verifier poisoned");
        let key = keys
            .get(&node_id)
            .ok_or(TransportError::UnknownNode(node_id))?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| TransportError::BadSignature)?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| TransportError::BadSignature)?;
        key.verify(message, &sig)
            .map_err(|_| TransportError::BadSignature)
    }

    /// 校验请求并返回 (from, body)。
    pub fn verify_request(
        &self,
        envelope: &RaftRpcEnvelope,
    ) -> Result<(NodeId, RaftRpcBody), TransportError> {
        if envelope.op != RAFT_RPC_OP {
            return Err(TransportError::Decode("unexpected op".into()));
        }
        if envelope.cluster_id != self.cluster_id {
            return Err(TransportError::WrongCluster);
        }
        if envelope.to != self.local_id {
            return Err(TransportError::WrongTarget);
        }
        let keys = self.keys.read().expect("verifier poisoned");
        let key = keys
            .get(&envelope.from)
            .ok_or(TransportError::UnknownNode(envelope.from))?;
        let body = URL_SAFE_NO_PAD
            .decode(&envelope.body)
            .map_err(|_| TransportError::BadBase64)?;
        let sig = URL_SAFE_NO_PAD
            .decode(&envelope.signature)
            .map_err(|_| TransportError::BadBase64)?;
        let sig = Signature::from_slice(&sig).map_err(|_| TransportError::BadSignature)?;
        let input = request_input(&envelope.cluster_id, envelope.from, envelope.to, &body);
        key.verify(&input, &sig)
            .map_err(|_| TransportError::BadSignature)?;
        let body = RaftRpcBody::decode(&body).map_err(TransportError::Decode)?;
        Ok((envelope.from, body))
    }

    /// 校验响应签名；`expected_from` 必须是目标节点。
    pub fn verify_reply(
        &self,
        expected_from: NodeId,
        reply: &RaftRpcReply,
    ) -> Result<Vec<u8>, TransportError> {
        if reply.op != RAFT_RPC_OP {
            return Err(TransportError::Decode("unexpected op".into()));
        }
        if reply.cluster_id != self.cluster_id {
            return Err(TransportError::WrongCluster);
        }
        if reply.from != expected_from {
            return Err(TransportError::WrongSender);
        }
        if reply.to != self.local_id {
            return Err(TransportError::WrongTarget);
        }
        let keys = self.keys.read().expect("verifier poisoned");
        let key = keys
            .get(&expected_from)
            .ok_or(TransportError::UnknownNode(expected_from))?;
        let body = URL_SAFE_NO_PAD
            .decode(&reply.body)
            .map_err(|_| TransportError::BadBase64)?;
        let sig = URL_SAFE_NO_PAD
            .decode(&reply.signature)
            .map_err(|_| TransportError::BadBase64)?;
        let sig = Signature::from_slice(&sig).map_err(|_| TransportError::BadSignature)?;
        let input = response_input(
            &reply.cluster_id,
            reply.from,
            reply.to,
            reply.ok,
            &body,
            &reply.error,
        );
        key.verify(&input, &sig)
            .map_err(|_| TransportError::BadSignature)?;
        if !reply.ok {
            return Err(TransportError::Decode(reply.error.clone()));
        }
        Ok(body)
    }
}

fn parse_verifying_key(identity_key_b64: &str) -> Result<VerifyingKey, TransportError> {
    let raw = STANDARD
        .decode(identity_key_b64)
        .map_err(|_| TransportError::InvalidKey)?;
    let bytes: [u8; 32] = raw.try_into().map_err(|_| TransportError::InvalidKey)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| TransportError::InvalidKey)
}

/// 方便测试与启动逻辑：把成员身份公钥放入 verifier。
#[allow(dead_code)]
pub fn verifier_with_nodes(
    cluster_id: &str,
    local_id: NodeId,
    nodes: impl IntoIterator<Item = (NodeId, String)>,
) -> Result<RpcVerifier, TransportError> {
    let verifier = RpcVerifier::new(cluster_id, local_id);
    for (id, key) in nodes {
        verifier.add_node(id, &key)?;
    }
    Ok(verifier)
}

/// 从 PeerId 稳定派生 NodeId（配置未覆盖时使用）。
pub fn node_id_from_peer_id(peer_id: &str) -> NodeId {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(peer_id.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    let id = u64::from_be_bytes(bytes);
    if id == 0 { 1 } else { id }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::types::RaftRpcBody;
    use openraft::Vote;
    use openraft::raft::VoteRequest;

    fn body() -> RaftRpcBody {
        RaftRpcBody::Vote(VoteRequest {
            vote: Vote::new(1, 7),
            last_log_id: None,
        })
    }

    fn setup() -> (IdentityKey, IdentityKey, RpcVerifier) {
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        let verifier = verifier_with_nodes(
            "c1",
            2,
            vec![
                (1, a.public_key_b64().to_string()),
                (2, b.public_key_b64().to_string()),
            ],
        )
        .unwrap();
        (a, b, verifier)
    }

    fn envelope(a: &IdentityKey) -> RaftRpcEnvelope {
        let bytes = encode_request(a, "c1", 1, 2, &body()).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn valid_request_verifies() {
        let (a, _b, verifier) = setup();
        let env = envelope(&a);
        let (from, body) = verifier.verify_request(&env).unwrap();
        assert_eq!(from, 1);
        assert!(matches!(body, RaftRpcBody::Vote(_)));
    }

    #[test]
    fn tampered_body_rejected() {
        let (a, _b, verifier) = setup();
        let mut env = envelope(&a);
        let mut raw = URL_SAFE_NO_PAD.decode(&env.body).unwrap();
        raw[0] ^= 0xff;
        env.body = URL_SAFE_NO_PAD.encode(raw);
        assert!(matches!(
            verifier.verify_request(&env),
            Err(TransportError::BadSignature)
        ));
    }

    #[test]
    fn tampered_signature_rejected() {
        let (a, _b, verifier) = setup();
        let mut env = envelope(&a);
        let mut sig = URL_SAFE_NO_PAD.decode(&env.signature).unwrap();
        sig[0] ^= 0xff;
        env.signature = URL_SAFE_NO_PAD.encode(sig);
        assert!(matches!(
            verifier.verify_request(&env),
            Err(TransportError::BadSignature)
        ));
    }

    #[test]
    fn unknown_sender_cluster_and_target_rejected() {
        let (a, _b, verifier) = setup();
        let mut env = envelope(&a);
        env.from = 99;
        assert!(matches!(
            verifier.verify_request(&env),
            Err(TransportError::UnknownNode(99))
        ));

        let mut env = envelope(&a);
        env.cluster_id = "other".into();
        assert!(matches!(
            verifier.verify_request(&env),
            Err(TransportError::WrongCluster)
        ));

        let mut env = envelope(&a);
        env.to = 1;
        assert!(matches!(
            verifier.verify_request(&env),
            Err(TransportError::WrongTarget)
        ));
    }

    #[test]
    fn reply_signature_verified() {
        let (a, b, _verifier) = setup();
        let raw = encode_reply(&b, "c1", 2, 1, true, b"hello", "").unwrap();
        let reply: RaftRpcReply = serde_json::from_slice(&raw).unwrap();

        // 构造一个「节点 1 收到节点 2 响应」的 verifier 视角
        let v1 = verifier_with_nodes(
            "c1",
            1,
            vec![
                (1, a.public_key_b64().to_string()),
                (2, b.public_key_b64().to_string()),
            ],
        )
        .unwrap();
        assert_eq!(v1.verify_reply(2, &reply).unwrap(), b"hello");

        let mut bad = reply.clone();
        bad.error = "tampered".into();
        bad.ok = false;
        assert!(v1.verify_reply(2, &bad).is_err());
    }

    #[test]
    fn replace_nodes_revokes_removed_public_keys() {
        let (a, b, verifier) = setup();
        let env = envelope(&a);
        assert!(verifier.verify_request(&env).is_ok());

        // 移除节点 1，只保留节点 2。
        verifier
            .replace_nodes(vec![(2, b.public_key_b64().to_string())])
            .unwrap();
        assert!(matches!(
            verifier.verify_request(&env),
            Err(TransportError::UnknownNode(1))
        ));

        // 节点 2 仍然有效。
        let env2: RaftRpcEnvelope =
            serde_json::from_slice(&encode_request(&b, "c1", 2, 2, &body()).unwrap()).unwrap();
        assert!(verifier.verify_request(&env2).is_ok());
    }

    #[test]
    fn node_id_derivation_stable() {
        let peer = libp2p_identity::PeerId::random().to_string();
        let a = node_id_from_peer_id(&peer);
        let b = node_id_from_peer_id(&peer);
        assert_eq!(a, b);
        assert_ne!(a, 0);
    }
}
