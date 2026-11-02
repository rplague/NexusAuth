//! Phase 4 入网请求：token + 新节点 Raft 身份 + X25519 交换公钥。
//!
//! 新节点用 Raft 身份私钥签名请求；任意 sidecar 验 token 后转发给 leader，
//! leader 二次校验并调用 `add_learner`。响应只包含成员公钥与策略元数据，
//! 绝不包含 authority seed。

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::admin_v2::AdminVerifier;
use crate::authority::is_valid_peer_id;
use crate::raft::token::{JoinTokenError, verify_join_token};
use crate::raft::transport::node_id_from_peer_id;
use crate::raft::types::JoinToken;

/// 入网请求 op。
pub const RAFT_JOIN_OP: &str = "raft_join";
/// 入网请求版本。
pub const RAFT_JOIN_VERSION: u8 = 1;
/// 时间戳允许偏差（秒）。
pub const RAFT_JOIN_MAX_TS_SKEW_SECS: u64 = 300;

/// 入网错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinError {
    BadRequest(String),
    Auth,
    Token(JoinTokenError),
    ExpiredTimestamp,
}

impl JoinError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::Auth => "join_auth_failed",
            Self::Token(e) => e.code(),
            Self::ExpiredTimestamp => "expired_timestamp",
        }
    }
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRequest(m) => write!(f, "bad join request: {m}"),
            Self::Auth => write!(f, "join request signature invalid"),
            Self::Token(e) => write!(f, "{e}"),
            Self::ExpiredTimestamp => write!(f, "join timestamp out of range"),
        }
    }
}

impl std::error::Error for JoinError {}

/// 新节点入网请求。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftJoinRequest {
    pub op: String,
    pub v: u8,
    pub cluster_id: String,
    pub network: String,
    pub token: JoinToken,
    pub node_id: u64,
    pub peer_id: String,
    pub identity_key: String,
    pub x25519_key: String,
    pub nonce: String,
    pub ts: u64,
    #[serde(default)]
    pub edge_peer: String,
    #[serde(default)]
    pub sig: String,
}

#[derive(Serialize)]
struct JoinSigned<'a> {
    v: u8,
    cluster_id: &'a str,
    network: &'a str,
    token: &'a JoinToken,
    node_id: u64,
    peer_id: &'a str,
    identity_key: &'a str,
    x25519_key: &'a str,
    nonce: &'a str,
    ts: u64,
}

fn signing_bytes(req: &RaftJoinRequest) -> Result<Vec<u8>, JoinError> {
    let signed = JoinSigned {
        v: req.v,
        cluster_id: &req.cluster_id,
        network: &req.network,
        token: &req.token,
        node_id: req.node_id,
        peer_id: &req.peer_id,
        identity_key: &req.identity_key,
        x25519_key: &req.x25519_key,
        nonce: &req.nonce,
        ts: req.ts,
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&signed, &mut buf)
        .map_err(|e| JoinError::BadRequest(e.to_string()))?;
    Ok(buf)
}

fn parse_identity(key_b64: &str) -> Result<VerifyingKey, JoinError> {
    let raw = STANDARD.decode(key_b64).map_err(|_| JoinError::Auth)?;
    let bytes: [u8; 32] = raw.try_into().map_err(|_| JoinError::Auth)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| JoinError::Auth)
}

fn parse_x25519(key_b64: &str) -> Result<[u8; 32], JoinError> {
    let raw = STANDARD
        .decode(key_b64)
        .map_err(|_| JoinError::BadRequest("x25519_key is not base64".into()))?;
    raw.try_into()
        .map_err(|_| JoinError::BadRequest("x25519_key must be 32 bytes".into()))
}

/// 新节点用自己的 Raft 身份私钥签名请求。
pub fn sign_request(
    identity: &crate::raft::transport::IdentityKey,
    req: &mut RaftJoinRequest,
) -> Result<(), JoinError> {
    let bytes = signing_bytes(req)?;
    req.sig = identity.sign_b64(&bytes);
    Ok(())
}

/// 校验请求自身（不校验 token 的 Raft 状态）。
pub fn verify_request(
    req: &RaftJoinRequest,
    verifier: &AdminVerifier,
    cluster_id: &str,
    network: &str,
    now: u64,
    allowed_audiences: &[&str],
) -> Result<(), JoinError> {
    if req.op != RAFT_JOIN_OP || req.v != RAFT_JOIN_VERSION {
        return Err(JoinError::BadRequest("unsupported join request".into()));
    }
    if req.cluster_id != cluster_id || req.network != network {
        return Err(JoinError::BadRequest("cluster/network mismatch".into()));
    }
    if req.node_id == 0 {
        return Err(JoinError::BadRequest("node_id must be non-zero".into()));
    }
    if !is_valid_peer_id(&req.peer_id) {
        return Err(JoinError::BadRequest("invalid peer_id".into()));
    }
    if req.node_id != node_id_from_peer_id(&req.peer_id) {
        return Err(JoinError::BadRequest(
            "node_id does not match peer_id".into(),
        ));
    }
    if req.nonce.is_empty() || req.nonce.len() > 128 {
        return Err(JoinError::BadRequest("invalid nonce".into()));
    }
    if now.abs_diff(req.ts) > RAFT_JOIN_MAX_TS_SKEW_SECS {
        return Err(JoinError::ExpiredTimestamp);
    }
    parse_x25519(&req.x25519_key)?;
    let identity = parse_identity(&req.identity_key)?;

    if !req.token.bind_peer_id.is_empty() && req.token.bind_peer_id != req.peer_id {
        return Err(JoinError::Token(JoinTokenError::WrongPeer));
    }
    verify_join_token(
        verifier,
        &req.token,
        now,
        cluster_id,
        network,
        allowed_audiences,
    )
    .map_err(JoinError::Token)?;

    let sig_raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.sig)
        .map_err(|_| JoinError::Auth)?;
    let sig = Signature::from_slice(&sig_raw).map_err(|_| JoinError::Auth)?;
    identity
        .verify(&signing_bytes(req)?, &sig)
        .map_err(|_| JoinError::Auth)?;
    Ok(())
}

/// 成员公钥视图（不含任何 seed）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberInfo {
    pub node_id: u64,
    pub peer_id: String,
    pub identity_key: String,
    #[serde(default)]
    pub x25519_key: String,
    pub voter: bool,
}

/// leader 返回给新节点的入网结果。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RaftJoinResponse {
    pub v: u8,
    pub ok: bool,
    #[serde(default)]
    pub error: String,
    pub cluster_id: String,
    pub network: String,
    pub node_id: u64,
    pub peer_id: String,
    pub role: String,
    pub term: u64,
    pub leader: Option<u64>,
    pub policy_epoch: u64,
    pub members: Vec<MemberInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_v2::AdminVerifier;
    use crate::config::AdminKeyConfig;
    use crate::raft::token::{sign_join_token, token_from_spec, token_spec, verify_join_token};
    use crate::raft::transport::IdentityKey;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::SigningKey;

    fn root() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn verifier(root: &SigningKey) -> AdminVerifier {
        AdminVerifier::from_config(
            &[AdminKeyConfig {
                kid: "root-1".into(),
                public_key: STANDARD.encode(root.verifying_key().to_bytes()),
                role: "root".into(),
            }],
            true,
        )
        .unwrap()
    }

    fn request(identity: &IdentityKey, audience: &str, ts: u64) -> RaftJoinRequest {
        let root = root();
        let mut token = token_from_spec(
            "prod",
            "myorg",
            "root-1",
            &token_spec("jti-join", audience, 2_000, ""),
        );
        sign_join_token(&root, &mut token).unwrap();
        let peer_id = libp2p_identity::PeerId::random().to_string();
        let mut req = RaftJoinRequest {
            op: RAFT_JOIN_OP.into(),
            v: RAFT_JOIN_VERSION,
            cluster_id: "prod".into(),
            network: "myorg".into(),
            token,
            node_id: node_id_from_peer_id(&peer_id),
            peer_id,
            identity_key: identity.public_key_b64().to_string(),
            x25519_key: STANDARD.encode([3u8; 32]),
            nonce: "nonce-1".into(),
            ts,
            edge_peer: String::new(),
            sig: String::new(),
        };
        sign_request(identity, &mut req).unwrap();
        req
    }

    #[test]
    fn valid_join_request_verifies() {
        let identity = IdentityKey::from_seed([9u8; 32]);
        let req = request(&identity, "auth", 1_000);
        verify_request(&req, &verifier(&root()), "prod", "myorg", 1_000, &[]).unwrap();
    }

    #[test]
    fn node_id_peer_id_mismatch_rejected() {
        let identity = IdentityKey::from_seed([9u8; 32]);
        let mut req = request(&identity, "auth", 1_000);
        req.node_id = if req.node_id == 1 { 2 } else { 1 };
        sign_request(&identity, &mut req).unwrap();
        assert!(matches!(
            verify_request(&req, &verifier(&root()), "prod", "myorg", 1_000, &[]),
            Err(JoinError::BadRequest(_))
        ));
    }

    #[test]
    fn expired_join_request_rejected() {
        let identity = IdentityKey::from_seed([9u8; 32]);
        let req = request(&identity, "auth", 1_000);
        assert_eq!(
            verify_request(
                &req,
                &verifier(&root()),
                "prod",
                "myorg",
                1_000 + RAFT_JOIN_MAX_TS_SKEW_SECS + 1,
                &[]
            ),
            Err(JoinError::ExpiredTimestamp)
        );
    }

    #[test]
    fn wrong_audience_and_tampered_identity_rejected() {
        let identity = IdentityKey::from_seed([9u8; 32]);
        let req = request(&identity, "peer-a", 1_000);
        assert!(matches!(
            verify_request(
                &req,
                &verifier(&root()),
                "prod",
                "myorg",
                1_000,
                &["peer-b"]
            ),
            Err(JoinError::Token(JoinTokenError::WrongAudience))
        ));

        let mut tampered = request(&identity, "auth", 1_000);
        tampered.identity_key = IdentityKey::from_seed([8u8; 32])
            .public_key_b64()
            .to_string();
        assert_eq!(
            verify_request(&tampered, &verifier(&root()), "prod", "myorg", 1_000, &[]),
            Err(JoinError::Auth)
        );
    }

    #[test]
    fn token_signature_verification_is_reused() {
        let root = root();
        let identity = IdentityKey::from_seed([9u8; 32]);
        let req = request(&identity, "auth", 1_000);
        assert!(
            verify_join_token(&verifier(&root), &req.token, 1_000, "prod", "myorg", &[]).is_ok()
        );
    }
}
