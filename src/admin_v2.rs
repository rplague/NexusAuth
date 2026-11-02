//! Phase 2 管理员认证：Ed25519 签名请求、viewer/root 角色与 edge → leader 转发。
//!
//! 与旧 HMAC 路径（`admin` 模块）并存：`[cluster].enabled = true` 时只接受本模块的
//! v2 请求；关闭时继续走旧 `management_password` 路径。
//!
//! 签名覆盖规范 CBOR `AdminSigned`（字段顺序固定、`peers` 去重排序）。幂等哈希
//! `request_hash` 只覆盖请求身份（v/op/service/peers/kid/request_id），不包含
//! `nonce`/`ts`，因此管理员用新 nonce/时间戳重试同一 `request_id` 仍能命中幂等。

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::AdminKeyConfig;
use crate::connection::BackendClient;
use crate::protocol::SidecarError;
use crate::raft::state_machine::PolicyState;
use crate::raft::types::{PolicyCommand, PolicyResult};
use crate::replay::{ReplayError, ReplayGuard};

/// v2 管理员请求版本。
pub const ADMIN_REQUEST_VERSION: u8 = 2;
/// 时间戳允许偏差（秒）。
pub const ADMIN_MAX_TS_SKEW_SECS: u64 = 300;
/// nonce 最大长度。
pub const ADMIN_MAX_NONCE_LEN: usize = 64;
/// request_id 最大长度。
pub const ADMIN_MAX_REQUEST_ID_LEN: usize = 128;
/// `forwarded_admin` 信封版本。
pub const FORWARDED_ADMIN_VERSION: u8 = 1;
/// 转发信封 op。
pub const FORWARDED_ADMIN_OP: &str = "forwarded_admin";

/// 管理员角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRole {
    Viewer,
    Root,
}

impl AdminRole {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "viewer" => Some(Self::Viewer),
            "root" => Some(Self::Root),
            _ => None,
        }
    }
}

/// Phase 4 成员操作的目标节点（可选字段，仅新命令使用）。
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminMemberSpec {
    pub node_id: u64,
    pub peer_id: String,
    pub identity_key: String,
    #[serde(default)]
    pub x25519_key: String,
}

/// Phase 4 root 签发的 join token 内容（`sig` 由 root 私钥生成）。
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminJoinTokenSpec {
    pub jti: String,
    pub audience: String,
    pub expires_at: u64,
    #[serde(default = "default_token_uses")]
    pub max_uses: u32,
    #[serde(default)]
    pub bind_peer_id: String,
    pub sig: String,
}

fn default_token_uses() -> u32 {
    1
}

/// v2 管理员请求（外层 JSON）。
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminRequestV2 {
    #[serde(default)]
    pub v: u8,
    #[serde(default)]
    pub op: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default)]
    pub kid: String,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub ts: u64,
    #[serde(default)]
    pub sig: String,
    /// Phase 4：成员操作目标；旧请求缺省为 `None`，签名编码保持不变。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<AdminMemberSpec>,
    /// Phase 4：`issue_join_token` 的 token 内容。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_token: Option<AdminJoinTokenSpec>,
}

/// 签名覆盖的规范体（固定字段顺序）。
#[derive(Serialize)]
struct AdminSigned<'a> {
    v: u8,
    op: &'a str,
    service: &'a str,
    peers: &'a [String],
    kid: &'a str,
    request_id: &'a str,
    nonce: &'a str,
    ts: u64,
}

/// Phase 4 扩展签名体；仅在请求携带 `member`/`join_token` 时使用。
#[derive(Serialize)]
struct AdminSignedExtended<'a> {
    v: u8,
    op: &'a str,
    service: &'a str,
    peers: &'a [String],
    kid: &'a str,
    request_id: &'a str,
    nonce: &'a str,
    ts: u64,
    member: &'a Option<AdminMemberSpec>,
    join_token: &'a Option<AdminJoinTokenSpec>,
}

/// 幂等哈希覆盖的请求身份（不含 nonce/ts/sig）。
#[derive(Serialize)]
struct AdminIdentity<'a> {
    v: u8,
    op: &'a str,
    service: &'a str,
    peers: &'a [String],
    kid: &'a str,
    request_id: &'a str,
}

#[derive(Serialize)]
struct AdminIdentityExtended<'a> {
    v: u8,
    op: &'a str,
    service: &'a str,
    peers: &'a [String],
    kid: &'a str,
    request_id: &'a str,
    member: &'a Option<AdminMemberSpec>,
    join_token: &'a Option<AdminJoinTokenSpec>,
}

/// 去重并排序 `peers`。
pub fn canonical_peers(peers: &[String]) -> Vec<String> {
    peers
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// 管理员认证/配置错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminV2Error {
    BadRequest(String),
    UnknownKey,
    BadSignature,
    ExpiredTimestamp,
    Replay,
    Config(String),
}

impl AdminV2Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::UnknownKey => "unknown_admin_key",
            Self::BadSignature => "bad_signature",
            Self::ExpiredTimestamp => "expired_timestamp",
            Self::Replay => "replay",
            Self::Config(_) => "admin_config_invalid",
        }
    }
}

impl fmt::Display for AdminV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest(m) => write!(f, "bad admin request: {m}"),
            Self::UnknownKey => write!(f, "unknown admin key"),
            Self::BadSignature => write!(f, "invalid admin signature"),
            Self::ExpiredTimestamp => write!(f, "admin timestamp out of range"),
            Self::Replay => write!(f, "admin nonce replayed"),
            Self::Config(m) => write!(f, "invalid admin key config: {m}"),
        }
    }
}

impl std::error::Error for AdminV2Error {}

/// 验签通过后的管理员身份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAdmin {
    pub kid: String,
    pub role: AdminRole,
    /// 请求身份哈希（base64url no-pad SHA-256）。
    pub request_hash: String,
    pub signed_bytes: Vec<u8>,
}

/// 管理员公钥表 + nonce 去重。
pub struct AdminVerifier {
    keys: BTreeMap<String, (VerifyingKey, AdminRole)>,
    guard: Mutex<ReplayGuard>,
}

impl Default for AdminVerifier {
    fn default() -> Self {
        Self {
            keys: BTreeMap::new(),
            guard: Mutex::new(ReplayGuard::default()),
        }
    }
}

impl AdminVerifier {
    /// 从配置构造。`require_root` 为真时至少需要一个 root 公钥。
    pub fn from_config(keys: &[AdminKeyConfig], require_root: bool) -> Result<Self, AdminV2Error> {
        let mut map: BTreeMap<String, (VerifyingKey, AdminRole)> = BTreeMap::new();
        let mut has_root = false;
        for entry in keys {
            if entry.kid.trim().is_empty() {
                return Err(AdminV2Error::Config("kid must not be empty".into()));
            }
            if map.contains_key(&entry.kid) {
                return Err(AdminV2Error::Config(format!(
                    "duplicate kid: {}",
                    entry.kid
                )));
            }
            let role = AdminRole::parse(&entry.role).ok_or_else(|| {
                AdminV2Error::Config(format!(
                    "kid {} has invalid role: {}",
                    entry.kid, entry.role
                ))
            })?;
            let raw = STANDARD.decode(&entry.public_key).map_err(|_| {
                AdminV2Error::Config(format!("kid {} has invalid base64 public_key", entry.kid))
            })?;
            let bytes: [u8; 32] = raw.try_into().map_err(|_| {
                AdminV2Error::Config(format!("kid {} public_key must be 32 bytes", entry.kid))
            })?;
            let verifying_key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
                AdminV2Error::Config(format!("kid {} has invalid Ed25519 public_key", entry.kid))
            })?;
            if role == AdminRole::Root {
                has_root = true;
            }
            map.insert(entry.kid.clone(), (verifying_key, role));
        }
        if require_root && !has_root {
            return Err(AdminV2Error::Config(
                "cluster mode requires at least one root key".into(),
            ));
        }
        Ok(Self {
            keys: map,
            guard: Mutex::new(ReplayGuard::default()),
        })
    }

    /// 验签、验时间戳并登记 nonce。
    pub fn verify(&self, req: &AdminRequestV2, now: u64) -> Result<VerifiedAdmin, AdminV2Error> {
        if req.v != ADMIN_REQUEST_VERSION {
            return Err(AdminV2Error::BadRequest(format!(
                "unsupported admin request version: {}",
                req.v
            )));
        }
        if req.kid.trim().is_empty() {
            return Err(AdminV2Error::BadRequest("missing kid".into()));
        }
        if req.request_id.trim().is_empty() {
            return Err(AdminV2Error::BadRequest("missing request_id".into()));
        }
        if req.request_id.len() > ADMIN_MAX_REQUEST_ID_LEN {
            return Err(AdminV2Error::BadRequest("request_id too long".into()));
        }
        if req.nonce.is_empty() {
            return Err(AdminV2Error::BadRequest("missing nonce".into()));
        }
        if req.nonce.len() > ADMIN_MAX_NONCE_LEN {
            return Err(AdminV2Error::BadRequest("nonce too long".into()));
        }

        let (verifying_key, role) = self.keys.get(&req.kid).ok_or(AdminV2Error::UnknownKey)?;

        let signed_bytes = signing_bytes(req)?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(&req.sig)
            .map_err(|_| AdminV2Error::BadSignature)?;
        let signature =
            Signature::from_slice(&sig_bytes).map_err(|_| AdminV2Error::BadSignature)?;
        verifying_key
            .verify(&signed_bytes, &signature)
            .map_err(|_| AdminV2Error::BadSignature)?;

        if now.abs_diff(req.ts) > ADMIN_MAX_TS_SKEW_SECS {
            return Err(AdminV2Error::ExpiredTimestamp);
        }

        self.guard
            .lock()
            .expect("admin replay guard poisoned")
            .check_and_insert(&req.nonce)
            .map_err(|e| match e {
                ReplayError::Empty => AdminV2Error::BadRequest("missing nonce".into()),
                ReplayError::Replay => AdminV2Error::Replay,
            })?;

        Ok(VerifiedAdmin {
            kid: req.kid.clone(),
            role: *role,
            request_hash: request_hash(req)?,
            signed_bytes,
        })
    }

    /// 用指定 `kid` 的公钥验签任意字节（供 join token/seed ack 复用）。
    pub fn verify_signature(
        &self,
        kid: &str,
        message: &[u8],
        signature_b64: &str,
    ) -> Result<AdminRole, AdminV2Error> {
        let (verifying_key, role) = self.keys.get(kid).ok_or(AdminV2Error::UnknownKey)?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| AdminV2Error::BadSignature)?;
        let signature =
            Signature::from_slice(&sig_bytes).map_err(|_| AdminV2Error::BadSignature)?;
        verifying_key
            .verify(message, &signature)
            .map_err(|_| AdminV2Error::BadSignature)?;
        Ok(*role)
    }
}

/// 签名输入：规范 CBOR `AdminSigned`（Phase 4 命令使用扩展体）。
pub fn signing_bytes(req: &AdminRequestV2) -> Result<Vec<u8>, AdminV2Error> {
    let peers = canonical_peers(&req.peers);
    let mut buf = Vec::new();
    if req.member.is_none() && req.join_token.is_none() {
        let signed = AdminSigned {
            v: req.v,
            op: &req.op,
            service: &req.service,
            peers: &peers,
            kid: &req.kid,
            request_id: &req.request_id,
            nonce: &req.nonce,
            ts: req.ts,
        };
        ciborium::ser::into_writer(&signed, &mut buf)
            .map_err(|e| AdminV2Error::BadRequest(format!("CBOR encode failed: {e}")))?;
    } else {
        let signed = AdminSignedExtended {
            v: req.v,
            op: &req.op,
            service: &req.service,
            peers: &peers,
            kid: &req.kid,
            request_id: &req.request_id,
            nonce: &req.nonce,
            ts: req.ts,
            member: &req.member,
            join_token: &req.join_token,
        };
        ciborium::ser::into_writer(&signed, &mut buf)
            .map_err(|e| AdminV2Error::BadRequest(format!("CBOR encode failed: {e}")))?;
    }
    Ok(buf)
}

/// 幂等哈希：只覆盖请求身份，不含 nonce/ts。
pub fn request_hash(req: &AdminRequestV2) -> Result<String, AdminV2Error> {
    let peers = canonical_peers(&req.peers);
    let mut buf = Vec::new();
    if req.member.is_none() && req.join_token.is_none() {
        let identity = AdminIdentity {
            v: req.v,
            op: &req.op,
            service: &req.service,
            peers: &peers,
            kid: &req.kid,
            request_id: &req.request_id,
        };
        ciborium::ser::into_writer(&identity, &mut buf)
            .map_err(|e| AdminV2Error::BadRequest(format!("CBOR encode failed: {e}")))?;
    } else {
        let identity = AdminIdentityExtended {
            v: req.v,
            op: &req.op,
            service: &req.service,
            peers: &peers,
            kid: &req.kid,
            request_id: &req.request_id,
            member: &req.member,
            join_token: &req.join_token,
        };
        ciborium::ser::into_writer(&identity, &mut buf)
            .map_err(|e| AdminV2Error::BadRequest(format!("CBOR encode failed: {e}")))?;
    }
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(&buf)))
}

/// 用管理员私钥签名一条请求（供测试与外部管理工具复用）。
#[allow(dead_code)]
pub fn sign_request(
    signing_key: &SigningKey,
    req: &mut AdminRequestV2,
) -> Result<(), AdminV2Error> {
    let bytes = signing_bytes(req)?;
    req.sig = URL_SAFE_NO_PAD.encode(signing_key.sign(&bytes).to_bytes());
    Ok(())
}

/// `forwarded_admin` 信封：只携带原始请求字节与 edge 身份。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForwardedAdminEnvelope {
    pub op: String,
    pub v: u8,
    /// 原始 v2 JSON 请求的 base64。
    pub request_b64: String,
    #[serde(default)]
    pub edge_peer: String,
    #[serde(default)]
    pub edge_sig: String,
}

/// 转发结果（由 edge 使用）。
pub trait AdminForwarder: Send + Sync {
    fn forward_admin<'a>(
        &'a self,
        service: &'a str,
        peer: &'a str,
        payload: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, SidecarError>> + Send + 'a>>;

    fn whoami<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<String, SidecarError>> + Send + 'a>>;
}

impl AdminForwarder for BackendClient {
    fn forward_admin<'a>(
        &'a self,
        service: &'a str,
        peer: &'a str,
        payload: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, SidecarError>> + Send + 'a>> {
        Box::pin(async move { self.service_request_to(service, peer, payload).await })
    }

    fn whoami<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<String, SidecarError>> + Send + 'a>> {
        Box::pin(async move { BackendClient::whoami(self).await })
    }
}

/// `status` 暴露的 Raft 成员（只含公开字段，不含 seed）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftStatusMember {
    pub node_id: u64,
    pub peer_id: String,
    #[serde(default)]
    pub voter: bool,
}

/// 一次 Raft 状态快照。用于 `status` 与健康判断。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftStatusSnapshot {
    #[serde(default)]
    pub cluster_id: String,
    #[serde(default)]
    pub node_id: u64,
    #[serde(default)]
    pub leader: Option<String>,
    #[serde(default)]
    pub term: u64,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub applied_index: Option<u64>,
    #[serde(default)]
    pub last_log_index: Option<u64>,
    #[serde(default)]
    pub voters: Vec<RaftStatusMember>,
    #[serde(default)]
    pub learners: Vec<RaftStatusMember>,
    #[serde(default)]
    pub stale: bool,
}

impl RaftStatusSnapshot {
    /// 供 `status` 使用的健康状态。
    pub fn health(&self) -> &'static str {
        if self.leader.is_none() {
            "no_leader"
        } else if self.stale {
            "stale"
        } else {
            "ok"
        }
    }
}

/// 管理员写操作在 Raft 中的提案结果。
#[derive(Debug, Clone)]
pub struct AdminProposal {
    pub result: PolicyResult,
    pub raft_index: u64,
}

/// 管理面所需的 Raft 视图（可注入测试实现）。
pub trait AdminRaft: Send + Sync {
    fn is_leader(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;
    fn term(&self) -> Pin<Box<dyn Future<Output = u64> + Send + '_>>;
    fn leader_peer(&self) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>>;
    fn policy_snapshot(&self) -> Pin<Box<dyn Future<Output = PolicyState> + Send + '_>>;
    fn applied_index(&self) -> Pin<Box<dyn Future<Output = Option<u64>> + Send + '_>>;
    fn stale(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;
    fn service_name(&self) -> &str;
    fn propose(
        &self,
        command: PolicyCommand,
    ) -> Pin<Box<dyn Future<Output = Result<AdminProposal, String>> + Send + '_>>;

    /// 完整状态快照。默认实现只填写通用字段，测试实现可按需覆盖。
    fn status_snapshot(&self) -> Pin<Box<dyn Future<Output = RaftStatusSnapshot> + Send + '_>> {
        Box::pin(async move {
            RaftStatusSnapshot {
                leader: self.leader_peer().await,
                term: self.term().await,
                applied_index: self.applied_index().await,
                stale: self.stale().await,
                ..Default::default()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn key_config(kid: &str, key: &SigningKey, role: &str) -> AdminKeyConfig {
        AdminKeyConfig {
            kid: kid.to_string(),
            public_key: STANDARD.encode(key.verifying_key().to_bytes()),
            role: role.to_string(),
        }
    }

    fn request(kid: &str, request_id: &str) -> AdminRequestV2 {
        AdminRequestV2 {
            v: ADMIN_REQUEST_VERSION,
            op: "add_members".into(),
            service: "cmd".into(),
            peers: vec!["b".into(), "a".into(), "a".into()],
            kid: kid.into(),
            request_id: request_id.into(),
            nonce: "nonce-1".into(),
            ts: 1_700_000_000,
            sig: String::new(),
            member: None,
            join_token: None,
        }
    }

    fn verifier() -> (AdminVerifier, SigningKey, SigningKey) {
        let root = signing_key(1);
        let viewer = signing_key(2);
        let config = vec![
            key_config("root-1", &root, "root"),
            key_config("viewer-1", &viewer, "viewer"),
        ];
        (
            AdminVerifier::from_config(&config, true).unwrap(),
            root,
            viewer,
        )
    }

    #[test]
    fn canonical_peers_dedup_and_sort() {
        assert_eq!(
            canonical_peers(&["b".into(), "a".into(), "b".into()]),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn valid_signature_verifies_and_peer_order_is_irrelevant() {
        let (verifier, root, _) = verifier();
        let mut req = request("root-1", "req-1");
        let peers = vec!["a".into(), "b".into()];
        req.peers = peers;
        sign_request(&root, &mut req).unwrap();

        // 接收端以不同顺序提供 peers。
        req.peers = vec!["b".into(), "a".into()];
        let verified = verifier.verify(&req, 1_700_000_000).unwrap();
        assert_eq!(verified.role, AdminRole::Root);
        assert_eq!(verified.kid, "root-1");
    }

    #[test]
    fn tampered_field_rejected() {
        let (verifier, root, _) = verifier();
        let mut req = request("root-1", "req-1");
        sign_request(&root, &mut req).unwrap();
        req.service = "other".into();
        assert_eq!(
            verifier.verify(&req, 1_700_000_000),
            Err(AdminV2Error::BadSignature)
        );
    }

    #[test]
    fn unknown_kid_rejected() {
        let (verifier, root, _) = verifier();
        let mut req = request("missing", "req-1");
        sign_request(&root, &mut req).unwrap();
        assert_eq!(
            verifier.verify(&req, 1_700_000_000),
            Err(AdminV2Error::UnknownKey)
        );
    }

    #[test]
    fn timestamp_window_enforced() {
        let (verifier, root, _) = verifier();
        let mut req = request("root-1", "req-1");
        sign_request(&root, &mut req).unwrap();
        assert_eq!(
            verifier.verify(&req, req.ts + ADMIN_MAX_TS_SKEW_SECS + 1),
            Err(AdminV2Error::ExpiredTimestamp)
        );
    }

    #[test]
    fn nonce_replay_rejected() {
        let (verifier, root, _) = verifier();
        let mut req = request("root-1", "req-1");
        sign_request(&root, &mut req).unwrap();
        assert!(verifier.verify(&req, req.ts).is_ok());
        assert_eq!(verifier.verify(&req, req.ts), Err(AdminV2Error::Replay));
    }

    #[test]
    fn request_hash_ignores_nonce_and_ts() {
        let mut req = request("root-1", "req-1");
        let h1 = request_hash(&req).unwrap();
        req.nonce = "nonce-2".into();
        req.ts += 10;
        let h2 = request_hash(&req).unwrap();
        assert_eq!(h1, h2);

        req.peers = vec!["a".into()];
        let h3 = request_hash(&req).unwrap();
        assert_ne!(h1, h3);
    }

    #[test]
    fn config_validation() {
        let root = signing_key(1);
        let viewer = signing_key(2);
        assert!(AdminVerifier::from_config(&[], false).is_ok());
        assert!(AdminVerifier::from_config(&[], true).is_err());

        let viewer_only = vec![key_config("v", &viewer, "viewer")];
        assert!(AdminVerifier::from_config(&viewer_only, true).is_err());
        assert!(AdminVerifier::from_config(&viewer_only, false).is_ok());

        let no_kid = vec![AdminKeyConfig {
            kid: String::new(),
            public_key: STANDARD.encode(root.verifying_key().to_bytes()),
            role: "root".into(),
        }];
        assert!(AdminVerifier::from_config(&no_kid, false).is_err());

        let duplicate = vec![
            key_config("dup", &root, "root"),
            key_config("dup", &viewer, "viewer"),
        ];
        assert!(AdminVerifier::from_config(&duplicate, true).is_err());

        let bad_role = vec![AdminKeyConfig {
            kid: "x".into(),
            public_key: STANDARD.encode(root.verifying_key().to_bytes()),
            role: "admin".into(),
        }];
        assert!(AdminVerifier::from_config(&bad_role, false).is_err());

        let bad_key = vec![AdminKeyConfig {
            kid: "x".into(),
            public_key: "not-base64".into(),
            role: "root".into(),
        }];
        assert!(AdminVerifier::from_config(&bad_key, false).is_err());
    }
}
