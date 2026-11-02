//! Phase 4 join token：root 管理员 Ed25519 签名、一次性、可绑定 PeerId。
//!
//! token 本身不包含任何 authority seed。签名覆盖除 `sig` 外的全部字段，
//! 使用固定字段顺序的 CBOR，便于管理员侧独立实现。

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;

use crate::admin_v2::{AdminJoinTokenSpec, AdminRole, AdminV2Error, AdminVerifier};
use crate::raft::types::JoinToken;

/// 当前 token 版本。
pub const JOIN_TOKEN_VERSION: u8 = 1;
/// join token 校验错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinTokenError {
    BadVersion,
    EmptyJti,
    UnknownKey,
    NotRoot,
    BadSignature,
    Expired,
    WrongCluster,
    WrongNetwork,
    WrongAudience,
    WrongPeer,
    Exhausted,
    BadRequest(String),
}

impl JoinTokenError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadVersion => "join_token_bad_version",
            Self::EmptyJti => "join_token_bad_jti",
            Self::UnknownKey => "unknown_admin_key",
            Self::NotRoot => "forbidden_role",
            Self::BadSignature => "bad_signature",
            Self::Expired => "join_token_expired",
            Self::WrongCluster => "join_token_wrong_cluster",
            Self::WrongNetwork => "join_token_wrong_network",
            Self::WrongAudience => "join_token_wrong_audience",
            Self::WrongPeer => "join_token_wrong_peer",
            Self::Exhausted => "join_token_replayed",
            Self::BadRequest(_) => "bad_request",
        }
    }
}

impl std::fmt::Display for JoinTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadVersion => write!(f, "unsupported join token version"),
            Self::EmptyJti => write!(f, "join token jti is empty"),
            Self::UnknownKey => write!(f, "unknown admin key"),
            Self::NotRoot => write!(f, "join token must be signed by a root key"),
            Self::BadSignature => write!(f, "invalid join token signature"),
            Self::Expired => write!(f, "join token expired"),
            Self::WrongCluster => write!(f, "join token cluster mismatch"),
            Self::WrongNetwork => write!(f, "join token network mismatch"),
            Self::WrongAudience => write!(f, "join token audience mismatch"),
            Self::WrongPeer => write!(f, "join token bound to a different peer"),
            Self::Exhausted => write!(f, "join token already used"),
            Self::BadRequest(m) => write!(f, "bad join token: {m}"),
        }
    }
}

impl std::error::Error for JoinTokenError {}

#[derive(Serialize)]
struct JoinTokenSigned<'a> {
    v: u8,
    jti: &'a str,
    cluster_id: &'a str,
    network: &'a str,
    audience: &'a str,
    expires_at: u64,
    max_uses: u32,
    bind_peer_id: &'a str,
    kid: &'a str,
}

/// 签名输入：除 `sig` 外的全部 token 字段。
pub fn token_signing_bytes(token: &JoinToken) -> Result<Vec<u8>, JoinTokenError> {
    let signed = JoinTokenSigned {
        v: token.v,
        jti: &token.jti,
        cluster_id: &token.cluster_id,
        network: &token.network,
        audience: &token.audience,
        expires_at: token.expires_at,
        max_uses: token.max_uses,
        bind_peer_id: &token.bind_peer_id,
        kid: &token.kid,
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&signed, &mut buf)
        .map_err(|e| JoinTokenError::BadRequest(e.to_string()))?;
    Ok(buf)
}

/// 由 root 私钥签发 token（供管理员工具与测试复用）。
#[allow(dead_code)]
pub fn sign_join_token(
    signing_key: &SigningKey,
    token: &mut JoinToken,
) -> Result<(), JoinTokenError> {
    let bytes = token_signing_bytes(token)?;
    token.sig = URL_SAFE_NO_PAD.encode(signing_key.sign(&bytes).to_bytes());
    Ok(())
}

/// 把管理员请求中的 token 内容补全为完整 `JoinToken`（`sig` 由调用方生成）。
pub fn token_from_spec(
    cluster_id: &str,
    network: &str,
    kid: &str,
    spec: &AdminJoinTokenSpec,
) -> JoinToken {
    JoinToken {
        v: JOIN_TOKEN_VERSION,
        jti: spec.jti.clone(),
        cluster_id: cluster_id.to_string(),
        network: network.to_string(),
        audience: spec.audience.clone(),
        expires_at: spec.expires_at,
        max_uses: spec.max_uses.max(1),
        bind_peer_id: spec.bind_peer_id.clone(),
        kid: kid.to_string(),
        sig: spec.sig.clone(),
    }
}

fn map_admin_error(e: AdminV2Error) -> JoinTokenError {
    match e {
        AdminV2Error::UnknownKey => JoinTokenError::UnknownKey,
        AdminV2Error::BadSignature => JoinTokenError::BadSignature,
        other => JoinTokenError::BadRequest(other.to_string()),
    }
}

/// 校验 token 签名、版本、cluster/network、过期时间与 audience。
///
/// `allowed_audiences` 用于接收端限制：`auth` 表示任意边车服务入口，其他值通常是
/// ingress 或 leader 的 PeerId。
pub fn verify_join_token(
    verifier: &AdminVerifier,
    token: &JoinToken,
    now: u64,
    cluster_id: &str,
    network: &str,
    allowed_audiences: &[&str],
) -> Result<(), JoinTokenError> {
    if token.v != JOIN_TOKEN_VERSION {
        return Err(JoinTokenError::BadVersion);
    }
    if token.jti.trim().is_empty() {
        return Err(JoinTokenError::EmptyJti);
    }
    if token.cluster_id != cluster_id {
        return Err(JoinTokenError::WrongCluster);
    }
    if token.network != network {
        return Err(JoinTokenError::WrongNetwork);
    }
    if token.expires_at == 0 || now > token.expires_at {
        return Err(JoinTokenError::Expired);
    }
    if token.max_uses == 0 {
        return Err(JoinTokenError::Exhausted);
    }
    let allowed = token.audience == "auth"
        || allowed_audiences
            .iter()
            .any(|candidate| !candidate.is_empty() && *candidate == token.audience);
    if !allowed {
        return Err(JoinTokenError::WrongAudience);
    }

    let bytes = token_signing_bytes(token)?;
    let role = verifier
        .verify_signature(&token.kid, &bytes, &token.sig)
        .map_err(map_admin_error)?;
    if role != AdminRole::Root {
        return Err(JoinTokenError::NotRoot);
    }
    Ok(())
}

/// 用于测试/工具的 token 请求构造（不签名）。
#[allow(dead_code)]
pub fn token_spec(
    jti: &str,
    audience: &str,
    expires_at: u64,
    bind_peer_id: &str,
) -> AdminJoinTokenSpec {
    AdminJoinTokenSpec {
        jti: jti.to_string(),
        audience: audience.to_string(),
        expires_at,
        max_uses: 1,
        bind_peer_id: bind_peer_id.to_string(),
        sig: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AdminKeyConfig;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::SigningKey;

    fn root() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn verifier(root: &SigningKey) -> AdminVerifier {
        let config = vec![AdminKeyConfig {
            kid: "root-1".into(),
            public_key: STANDARD.encode(root.verifying_key().to_bytes()),
            role: "root".into(),
        }];
        AdminVerifier::from_config(&config, true).unwrap()
    }

    fn token(root: &SigningKey) -> JoinToken {
        let mut token = token_from_spec(
            "prod",
            "myorg",
            "root-1",
            &token_spec("jti-1", "auth", 2_000, ""),
        );
        sign_join_token(root, &mut token).unwrap();
        token
    }

    #[test]
    fn valid_token_verifies() {
        let root = root();
        let token = token(&root);
        verify_join_token(&verifier(&root), &token, 1_000, "prod", "myorg", &[]).unwrap();
    }

    #[test]
    fn expired_token_rejected() {
        let root = root();
        let token = token(&root);
        assert_eq!(
            verify_join_token(&verifier(&root), &token, 2_001, "prod", "myorg", &[]),
            Err(JoinTokenError::Expired)
        );
    }

    #[test]
    fn wrong_audience_rejected() {
        let root = root();
        let mut token = token_from_spec(
            "prod",
            "myorg",
            "root-1",
            &token_spec("jti-a", "peer-a", 2_000, ""),
        );
        sign_join_token(&root, &mut token).unwrap();
        assert_eq!(
            verify_join_token(
                &verifier(&root),
                &token,
                1_000,
                "prod",
                "myorg",
                &["other-peer"]
            ),
            Err(JoinTokenError::WrongAudience)
        );
    }

    #[test]
    fn tampered_token_rejected() {
        let root = root();
        let mut token = token(&root);
        token.audience = "other".into();
        assert_eq!(
            verify_join_token(&verifier(&root), &token, 1_000, "prod", "myorg", &["other"]),
            Err(JoinTokenError::BadSignature)
        );
    }

    #[test]
    fn non_root_token_rejected() {
        let root = root();
        let viewer = SigningKey::from_bytes(&[9u8; 32]);
        let config = vec![
            AdminKeyConfig {
                kid: "root-1".into(),
                public_key: STANDARD.encode(root.verifying_key().to_bytes()),
                role: "root".into(),
            },
            AdminKeyConfig {
                kid: "viewer-1".into(),
                public_key: STANDARD.encode(viewer.verifying_key().to_bytes()),
                role: "viewer".into(),
            },
        ];
        let verifier = AdminVerifier::from_config(&config, true).unwrap();
        let mut token = token_from_spec(
            "prod",
            "myorg",
            "viewer-1",
            &token_spec("jti-v", "auth", 2_000, ""),
        );
        sign_join_token(&viewer, &mut token).unwrap();
        assert_eq!(
            verify_join_token(&verifier, &token, 1_000, "prod", "myorg", &[]),
            Err(JoinTokenError::NotRoot)
        );
    }

    #[test]
    fn spec_conversion() {
        let spec = token_spec("j", "auth", 10, "peer");
        let token = token_from_spec("c", "n", "root", &spec);
        assert_eq!(token.max_uses, 1);
        assert_eq!(token.bind_peer_id, "peer");
    }
}
