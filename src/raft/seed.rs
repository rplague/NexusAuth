//! authority seed 的安全分发。
//!
//! - 每个节点持久化一把 X25519 交换密钥（0600），仅用于接收 seed。
//! - leader 提升 learner 前，用目标节点 X25519 公钥做 ECDH + HKDF，再用
//!   ChaCha20-Poly1305 加密 seed；AAD 绑定 cluster/network/node/peer/identity。
//! - 分发信封由 leader 的 sidecar Ed25519 身份签名；目标节点回执同样签名。
//! - seed 永不进入 Raft 日志或普通快照。

use std::fs;
use std::io;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::authority::SEED_LEN;
use crate::fsutil;
use crate::raft::transport::{IdentityKey, RpcVerifier};
use crate::raft::types::{NodeId, RaftNode};

/// X25519 私钥长度。
pub const X25519_KEY_LEN: usize = 32;
/// seed 分发信封版本。
pub const SEED_ENVELOPE_VERSION: u8 = 1;
/// seed 分发内部 op。
pub const SEED_DELIVERY_OP: &str = "raft_seed_delivery";
/// seed 清除内部 op（demote/remove 后）。
pub const SEED_DROP_OP: &str = "raft_seed_drop";
const SEED_AAD_INFO: &[u8] = b"nexusauth/seed/v1";

/// seed 分发错误。
#[derive(Debug)]
pub enum SeedError {
    Io(io::Error),
    InvalidKey,
    InvalidSeed,
    BadSignature,
    WrongCluster,
    WrongNode,
    Encrypt,
    Decrypt,
    Encode(String),
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "seed io error: {e}"),
            Self::InvalidKey => write!(f, "invalid X25519 key"),
            Self::InvalidSeed => write!(f, "invalid authority seed"),
            Self::BadSignature => write!(f, "invalid seed delivery signature"),
            Self::WrongCluster => write!(f, "seed delivery cluster mismatch"),
            Self::WrongNode => write!(f, "seed delivery addressed to a different node"),
            Self::Encrypt => write!(f, "seed encryption failed"),
            Self::Decrypt => write!(f, "seed decryption failed"),
            Self::Encode(e) => write!(f, "seed encode error: {e}"),
        }
    }
}

impl std::error::Error for SeedError {}

impl From<io::Error> for SeedError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// 节点的持久化 X25519 交换密钥。
pub struct SeedExchangeKey {
    secret: StaticSecret,
    public_b64: String,
}

impl SeedExchangeKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SeedError> {
        let raw: [u8; X25519_KEY_LEN] = bytes.try_into().map_err(|_| SeedError::InvalidKey)?;
        let secret = StaticSecret::from(raw);
        let public_b64 = STANDARD.encode(PublicKey::from(&secret).as_bytes());
        Ok(Self { secret, public_b64 })
    }

    /// 加载或生成；新文件权限 0600。
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, SeedError> {
        let path = path.as_ref();
        match fs::read(path) {
            Ok(bytes) => Self::from_bytes(&bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut bytes = [0u8; X25519_KEY_LEN];
                rand_core::OsRng.fill_bytes(&mut bytes);
                let key = Self::from_bytes(&bytes)?;
                fsutil::atomic_write(path, &bytes, Some(0o600))?;
                Ok(key)
            }
            Err(e) => Err(SeedError::Io(e)),
        }
    }

    pub fn public_key_b64(&self) -> &str {
        &self.public_b64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeedBinding {
    network: String,
    cluster_id: String,
    node_id: NodeId,
    peer_id: String,
    identity_key: String,
    ephemeral_key: String,
}

#[derive(Serialize)]
struct SeedEnvelopeSigned<'a> {
    v: u8,
    from_node: NodeId,
    cluster_id: &'a str,
    network: &'a str,
    node_id: NodeId,
    peer_id: &'a str,
    identity_key: &'a str,
    ephemeral_key: &'a str,
    aead_nonce: &'a str,
    ciphertext: &'a str,
}

/// leader → 新 voter 的加密 seed 信封。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedEnvelope {
    pub v: u8,
    pub from_node: NodeId,
    pub cluster_id: String,
    pub network: String,
    pub node_id: NodeId,
    pub peer_id: String,
    pub identity_key: String,
    pub ephemeral_key: String,
    pub aead_nonce: String,
    pub ciphertext: String,
    pub sig: String,
}

fn binding_bytes(binding: &SeedBinding) -> Result<Vec<u8>, SeedError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(binding, &mut buf).map_err(|e| SeedError::Encode(e.to_string()))?;
    Ok(buf)
}

fn derive_key(
    shared: &[u8; 32],
    cluster_id: &str,
    binding: &SeedBinding,
) -> Result<[u8; 32], SeedError> {
    let hkdf = Hkdf::<Sha256>::new(Some(cluster_id.as_bytes()), shared);
    let mut info = Vec::new();
    info.extend_from_slice(SEED_AAD_INFO);
    info.push(0);
    info.extend_from_slice(&binding_bytes(binding)?);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|_| SeedError::Encrypt)?;
    Ok(key)
}

fn envelope_signing_bytes(envelope: &SeedEnvelope) -> Result<Vec<u8>, SeedError> {
    let signed = SeedEnvelopeSigned {
        v: envelope.v,
        from_node: envelope.from_node,
        cluster_id: &envelope.cluster_id,
        network: &envelope.network,
        node_id: envelope.node_id,
        peer_id: &envelope.peer_id,
        identity_key: &envelope.identity_key,
        ephemeral_key: &envelope.ephemeral_key,
        aead_nonce: &envelope.aead_nonce,
        ciphertext: &envelope.ciphertext,
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&signed, &mut buf).map_err(|e| SeedError::Encode(e.to_string()))?;
    Ok(buf)
}

/// leader 侧：把 seed 加密到目标节点身份并签名信封。
pub fn seal_seed(
    leader_identity: &IdentityKey,
    leader_node: NodeId,
    cluster_id: &str,
    network: &str,
    target_node: NodeId,
    target: &RaftNode,
    seed: &[u8; SEED_LEN],
) -> Result<SeedEnvelope, SeedError> {
    let target_raw = STANDARD
        .decode(&target.x25519_key)
        .map_err(|_| SeedError::InvalidKey)?;
    let target_bytes: [u8; X25519_KEY_LEN] =
        target_raw.try_into().map_err(|_| SeedError::InvalidKey)?;
    let target_public = PublicKey::from(target_bytes);

    let mut eph_bytes = [0u8; X25519_KEY_LEN];
    rand_core::OsRng.fill_bytes(&mut eph_bytes);
    let eph_secret = StaticSecret::from(eph_bytes);
    let eph_public = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&target_public);

    let ephemeral_key = STANDARD.encode(eph_public.as_bytes());
    let binding = SeedBinding {
        network: network.to_string(),
        cluster_id: cluster_id.to_string(),
        node_id: target_node,
        peer_id: target.peer_id.clone(),
        identity_key: target.identity_key.clone(),
        ephemeral_key: ephemeral_key.clone(),
    };
    let key = derive_key(shared.as_bytes(), cluster_id, &binding)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| SeedError::Encrypt)?;
    let mut aead_bytes = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut aead_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&aead_bytes), seed.as_ref())
        .map_err(|_| SeedError::Encrypt)?;

    let mut envelope = SeedEnvelope {
        v: SEED_ENVELOPE_VERSION,
        from_node: leader_node,
        cluster_id: cluster_id.to_string(),
        network: network.to_string(),
        node_id: target_node,
        peer_id: target.peer_id.clone(),
        identity_key: target.identity_key.clone(),
        ephemeral_key,
        aead_nonce: STANDARD.encode(aead_bytes),
        ciphertext: STANDARD.encode(ciphertext),
        sig: String::new(),
    };
    envelope.sig = leader_identity.sign_b64(&envelope_signing_bytes(&envelope)?);
    Ok(envelope)
}

/// 目标节点：验签后解密 seed。`expected_leader` 必须等于当前 Raft leader。
#[allow(clippy::too_many_arguments)]
pub fn open_seed(
    local_key: &SeedExchangeKey,
    verifier: &RpcVerifier,
    local_node_id: NodeId,
    local_peer_id: &str,
    local_identity_key: &str,
    cluster_id: &str,
    network: &str,
    expected_leader: Option<NodeId>,
    envelope: &SeedEnvelope,
) -> Result<[u8; SEED_LEN], SeedError> {
    if envelope.v != SEED_ENVELOPE_VERSION {
        return Err(SeedError::Decrypt);
    }
    if envelope.cluster_id != cluster_id || envelope.network != network {
        return Err(SeedError::WrongCluster);
    }
    if envelope.node_id != local_node_id
        || envelope.peer_id != local_peer_id
        || envelope.identity_key != local_identity_key
    {
        return Err(SeedError::WrongNode);
    }
    if let Some(leader) = expected_leader
        && envelope.from_node != leader
    {
        return Err(SeedError::WrongNode);
    }
    verifier
        .verify_node_signature(
            envelope.from_node,
            &envelope_signing_bytes(envelope)?,
            &envelope.sig,
        )
        .map_err(|_| SeedError::BadSignature)?;

    let eph_raw = STANDARD
        .decode(&envelope.ephemeral_key)
        .map_err(|_| SeedError::InvalidKey)?;
    let eph_bytes: [u8; X25519_KEY_LEN] = eph_raw.try_into().map_err(|_| SeedError::InvalidKey)?;
    let eph_public = PublicKey::from(eph_bytes);
    let shared = local_key.secret.diffie_hellman(&eph_public);
    let binding = SeedBinding {
        network: envelope.network.clone(),
        cluster_id: envelope.cluster_id.clone(),
        node_id: envelope.node_id,
        peer_id: envelope.peer_id.clone(),
        identity_key: envelope.identity_key.clone(),
        ephemeral_key: envelope.ephemeral_key.clone(),
    };
    let key = derive_key(shared.as_bytes(), &envelope.cluster_id, &binding)
        .map_err(|_| SeedError::Decrypt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| SeedError::Decrypt)?;
    let nonce_raw = STANDARD
        .decode(&envelope.aead_nonce)
        .map_err(|_| SeedError::Decrypt)?;
    let nonce: [u8; 12] = nonce_raw.try_into().map_err(|_| SeedError::Decrypt)?;
    let ciphertext = STANDARD
        .decode(&envelope.ciphertext)
        .map_err(|_| SeedError::Decrypt)?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| SeedError::Decrypt)?;
    let seed: [u8; SEED_LEN] = plaintext.try_into().map_err(|_| SeedError::InvalidSeed)?;
    Ok(seed)
}

#[derive(Serialize)]
struct SeedAckSigned<'a> {
    v: u8,
    from: NodeId,
    to: NodeId,
    ok: bool,
    error: &'a str,
}

/// seed 分发/清除回执。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeedAck {
    pub v: u8,
    pub from: NodeId,
    pub to: NodeId,
    pub ok: bool,
    pub error: String,
    pub sig: String,
}

fn ack_signing_bytes(ack: &SeedAck) -> Result<Vec<u8>, SeedError> {
    let signed = SeedAckSigned {
        v: ack.v,
        from: ack.from,
        to: ack.to,
        ok: ack.ok,
        error: &ack.error,
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&signed, &mut buf).map_err(|e| SeedError::Encode(e.to_string()))?;
    Ok(buf)
}

/// 目标节点签名回执。
pub fn sign_ack(
    identity: &IdentityKey,
    from: NodeId,
    to: NodeId,
    ok: bool,
    error: &str,
) -> Result<SeedAck, SeedError> {
    let mut ack = SeedAck {
        v: SEED_ENVELOPE_VERSION,
        from,
        to,
        ok,
        error: error.to_string(),
        sig: String::new(),
    };
    ack.sig = identity.sign_b64(&ack_signing_bytes(&ack)?);
    Ok(ack)
}

/// leader 验证目标节点回执。
pub fn verify_ack(
    verifier: &RpcVerifier,
    expected_from: NodeId,
    ack: &SeedAck,
) -> Result<(), SeedError> {
    if ack.v != SEED_ENVELOPE_VERSION || ack.from != expected_from {
        return Err(SeedError::BadSignature);
    }
    verifier
        .verify_node_signature(ack.from, &ack_signing_bytes(ack)?, &ack.sig)
        .map_err(|_| SeedError::BadSignature)?;
    if !ack.ok {
        return Err(SeedError::Decrypt);
    }
    Ok(())
}

/// seed 分发请求外层。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedDeliveryRequest {
    pub op: String,
    pub envelope: SeedEnvelope,
}

/// seed 清除请求（leader → 被降级/移除的节点）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedDropRequest {
    pub op: String,
    pub v: u8,
    pub cluster_id: String,
    pub from_node: NodeId,
    pub node_id: NodeId,
    pub peer_id: String,
    #[serde(default)]
    pub sig: String,
}

#[derive(Serialize)]
struct DropSigned<'a> {
    v: u8,
    cluster_id: &'a str,
    from_node: NodeId,
    node_id: NodeId,
    peer_id: &'a str,
}

fn drop_signing_bytes(req: &SeedDropRequest) -> Result<Vec<u8>, SeedError> {
    let signed = DropSigned {
        v: req.v,
        cluster_id: &req.cluster_id,
        from_node: req.from_node,
        node_id: req.node_id,
        peer_id: &req.peer_id,
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&signed, &mut buf).map_err(|e| SeedError::Encode(e.to_string()))?;
    Ok(buf)
}

/// leader 签名 seed 清除请求。
pub fn sign_drop_request(
    identity: &IdentityKey,
    leader_node: NodeId,
    cluster_id: &str,
    target_node: NodeId,
    target: &RaftNode,
) -> Result<SeedDropRequest, SeedError> {
    let mut req = SeedDropRequest {
        op: SEED_DROP_OP.to_string(),
        v: SEED_ENVELOPE_VERSION,
        cluster_id: cluster_id.to_string(),
        from_node: leader_node,
        node_id: target_node,
        peer_id: target.peer_id.clone(),
        sig: String::new(),
    };
    req.sig = identity.sign_b64(&drop_signing_bytes(&req)?);
    Ok(req)
}

/// 目标节点验证 seed 清除请求。
pub fn verify_drop_request(
    verifier: &RpcVerifier,
    expected_leader: Option<NodeId>,
    req: &SeedDropRequest,
    local_node_id: NodeId,
    local_peer_id: &str,
    cluster_id: &str,
) -> Result<(), SeedError> {
    if req.op != SEED_DROP_OP
        || req.v != SEED_ENVELOPE_VERSION
        || req.cluster_id != cluster_id
        || req.node_id != local_node_id
        || req.peer_id != local_peer_id
    {
        return Err(SeedError::WrongNode);
    }
    if let Some(leader) = expected_leader
        && req.from_node != leader
    {
        return Err(SeedError::WrongNode);
    }
    verifier
        .verify_node_signature(req.from_node, &drop_signing_bytes(req)?, &req.sig)
        .map_err(|_| SeedError::BadSignature)
}

/// 写入 voter seed 文件（0600）。
pub fn write_seed_file(path: impl AsRef<Path>, seed: &[u8; SEED_LEN]) -> Result<(), SeedError> {
    fsutil::atomic_write(path.as_ref(), seed, Some(0o600))?;
    Ok(())
}

/// 删除 seed 文件（demote/remove 后 learner 不得保留）。
pub fn remove_seed_file(path: impl AsRef<Path>) -> Result<(), SeedError> {
    match fs::remove_file(path.as_ref()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(SeedError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    fn identity(seed: u8) -> IdentityKey {
        IdentityKey::from_seed([seed; 32])
    }

    fn verifier_for(nodes: &[(NodeId, &IdentityKey)]) -> RpcVerifier {
        let verifier = RpcVerifier::new("prod", 2);
        for (id, key) in nodes {
            verifier.add_node(*id, key.public_key_b64()).unwrap();
        }
        verifier
    }

    fn target(key: &SeedExchangeKey, id: u64) -> RaftNode {
        RaftNode {
            peer_id: format!("peer-{id}"),
            identity_key: identity(9).public_key_b64().to_string(),
            x25519_key: key.public_key_b64().to_string(),
        }
    }

    #[test]
    fn seed_round_trip_and_wrong_node_rejected() {
        let leader = identity(1);
        let local = SeedExchangeKey::from_bytes(&[5u8; 32]).unwrap();
        let node = target(&local, 2);
        let seed = [42u8; SEED_LEN];
        let envelope = seal_seed(&leader, 1, "prod", "myorg", 2, &node, &seed).unwrap();

        let verifier = verifier_for(&[(1, &leader)]);
        let opened = open_seed(
            &local,
            &verifier,
            2,
            &node.peer_id,
            &node.identity_key,
            "prod",
            "myorg",
            Some(1),
            &envelope,
        )
        .unwrap();
        assert_eq!(opened, seed);

        let err = open_seed(
            &local,
            &verifier,
            3,
            "peer-3",
            &node.identity_key,
            "prod",
            "myorg",
            Some(1),
            &envelope,
        );
        assert!(matches!(err, Err(SeedError::WrongNode)));
    }

    #[test]
    fn wrong_leader_rejected() {
        let leader = identity(1);
        let local = SeedExchangeKey::from_bytes(&[5u8; 32]).unwrap();
        let node = target(&local, 2);
        let envelope = seal_seed(&leader, 1, "prod", "myorg", 2, &node, &[1u8; 32]).unwrap();
        let verifier = verifier_for(&[(1, &leader)]);
        assert!(matches!(
            open_seed(
                &local,
                &verifier,
                2,
                &node.peer_id,
                &node.identity_key,
                "prod",
                "myorg",
                Some(3),
                &envelope
            ),
            Err(SeedError::WrongNode)
        ));
    }

    #[test]
    fn ack_is_signed_by_target_identity() {
        let local = identity(2);
        let ack = sign_ack(&local, 2, 1, true, "").unwrap();
        let verifier = verifier_for(&[(2, &local)]);
        verify_ack(&verifier, 2, &ack).unwrap();

        let mut tampered = ack;
        tampered.ok = false;
        assert!(verify_ack(&verifier, 2, &tampered).is_err());
    }

    #[test]
    fn seed_file_round_trip_and_removal() {
        let dir = std::env::temp_dir().join(format!(
            "nexusauth-seed-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("authority.key");
        write_seed_file(&path, &[7u8; SEED_LEN]).unwrap();
        assert_eq!(fs::read(&path).unwrap(), vec![7u8; SEED_LEN]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        remove_seed_file(&path).unwrap();
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn public_key_is_32_bytes_base64() {
        let local = SeedExchangeKey::from_bytes(&[3u8; 32]).unwrap();
        let raw = STANDARD.decode(local.public_key_b64()).unwrap();
        assert_eq!(raw.len(), X25519_KEY_LEN);
    }
}
