//! 权威密钥与 COSE_Sign1 记录签名。
//!
//! 与 NexusNet `src/auth.rs` 的签名侧字节级对齐：DHT 中存放的 value 为
//! `COSE_Sign1(payload = CBOR(doc), external_aad = key 路径字节)`。
//! 权威密钥为裸 32 字节 ed25519 seed。

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use coset::{
    CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, RegisteredLabelWithPrivate, iana,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 单个记录的字节上限。
pub const MAX_DOC_BYTES: usize = 1 << 20;
/// 白名单成员数上限。
pub const MAX_MEMBERS: usize = 100_000;
/// 索引服务数上限。
pub const MAX_SERVICES: usize = 10_000;
/// 索引 key 的保留末段，禁止服务使用该名。
pub const RESERVED_SERVICE: &str = "service";
/// DHT key 前缀。
pub const AUTH_PREFIX: &str = "/oahd/auth";
/// 权威私钥 seed 长度。
pub const SEED_LEN: usize = 32;
/// 网络名 / 服务名长度上限。
pub const MAX_NAME_LEN: usize = 64;

/// 权威层错误。
#[derive(Debug)]
pub enum AuthorityError {
    Io(io::Error),
    /// seed 文件长度不是 32 字节
    InvalidSeed,
    /// 网络名 / 服务名非法
    InvalidName,
    /// COSE 信封编码失败
    Cose,
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorityError::Io(e) => write!(f, "io error: {e}"),
            AuthorityError::InvalidSeed => {
                write!(f, "invalid authority seed (need {SEED_LEN} bytes)")
            }
            AuthorityError::InvalidName => write!(f, "invalid network or service name"),
            AuthorityError::Cose => write!(f, "cose encoding error"),
        }
    }
}

impl std::error::Error for AuthorityError {}

impl From<io::Error> for AuthorityError {
    fn from(e: io::Error) -> Self {
        AuthorityError::Io(e)
    }
}

/// 索引中的一条服务项，绑定对应白名单记录的字节摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub name: String,
    /// 白名单记录完整字节的 SHA-256。
    pub hash: Vec<u8>,
    /// 白名单记录完整字节的长度。
    pub length: u64,
}

/// 索引记录 payload。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexDoc {
    pub version: u64,
    pub expires_at: u64,
    pub services: Vec<ServiceEntry>,
}

/// 白名单记录 payload。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhitelistDoc {
    pub version: u64,
    pub members: Vec<String>,
}

/// 一个鉴权网络的权威签名者。
pub struct Authority {
    signing_key: SigningKey,
    network: String,
    net_hash: String,
}

impl Authority {
    /// 由 32 字节 seed 与网络名构造。
    pub fn from_seed(seed: [u8; SEED_LEN], network: &str) -> Result<Self, AuthorityError> {
        if !is_valid_network_name(network) {
            return Err(AuthorityError::InvalidName);
        }
        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed),
            network: network.to_string(),
            net_hash: net_hash(network),
        })
    }

    /// 从文件加载 seed（文件必须存在且为 32 字节）。
    pub fn load(path: impl AsRef<Path>, network: &str) -> Result<Self, AuthorityError> {
        let bytes = fs::read(path)?;
        if bytes.len() != SEED_LEN {
            return Err(AuthorityError::InvalidSeed);
        }
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(&bytes);
        Self::from_seed(seed, network)
    }

    /// 从文件加载 seed；不存在则随机生成并原子写入（0600）。
    pub fn load_or_create(path: impl AsRef<Path>, network: &str) -> Result<Self, AuthorityError> {
        let path = path.as_ref();
        let seed = match fs::read(path) {
            Ok(bytes) => {
                if bytes.len() != SEED_LEN {
                    return Err(AuthorityError::InvalidSeed);
                }
                let mut seed = [0u8; SEED_LEN];
                seed.copy_from_slice(&bytes);
                seed
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut seed = [0u8; SEED_LEN];
                rand_core::OsRng.fill_bytes(&mut seed);
                crate::fsutil::atomic_write(path, &seed, Some(0o600))?;
                seed
            }
            Err(e) => return Err(AuthorityError::Io(e)),
        };
        Self::from_seed(seed, network)
    }

    /// 生成一把全新的随机密钥（不落盘）。
    pub fn generate(network: &str) -> Result<Self, AuthorityError> {
        let mut seed = [0u8; SEED_LEN];
        rand_core::OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed, network)
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn net_hash(&self) -> &str {
        &self.net_hash
    }

    /// 32 字节原始公钥。
    pub fn public_key_bytes(&self) -> [u8; SEED_LEN] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// 原始 32 字节 seed（仅供持久化与入网传输，**切勿写入日志**）。
    pub fn seed(&self) -> [u8; SEED_LEN] {
        self.signing_key.to_bytes()
    }

    /// 标准 base64 公钥，用于填入 NexusNet `auth.networks.<n>.authority`。
    pub fn public_key_b64(&self) -> String {
        STANDARD.encode(self.public_key_bytes())
    }

    /// 索引记录 key：`/oahd/auth/<net_hash>/service`。
    pub fn index_key(&self) -> String {
        format!("{}/{}/{}", AUTH_PREFIX, self.net_hash, RESERVED_SERVICE)
    }

    /// 白名单记录 key：`/oahd/auth/<net_hash>/<service>`。
    pub fn service_key(&self, service: &str) -> Result<String, AuthorityError> {
        if !is_valid_service_name(service) {
            return Err(AuthorityError::InvalidName);
        }
        Ok(format!("{}/{}/{}", AUTH_PREFIX, self.net_hash, service))
    }

    /// 构造并签名索引记录，返回可写入 DHT 的完整字节。
    pub fn sign_index(&self, doc: &IndexDoc) -> Result<Vec<u8>, AuthorityError> {
        let payload = cbor_encode(doc)?;
        self.sign_payload(self.index_key().as_bytes(), payload)
    }

    /// 构造并签名某服务的白名单记录，返回可写入 DHT 的完整字节。
    pub fn sign_whitelist(
        &self,
        service: &str,
        doc: &WhitelistDoc,
    ) -> Result<Vec<u8>, AuthorityError> {
        let key = self.service_key(service)?;
        let payload = cbor_encode(doc)?;
        self.sign_payload(key.as_bytes(), payload)
    }

    fn sign_payload(&self, aad: &[u8], payload: Vec<u8>) -> Result<Vec<u8>, AuthorityError> {
        let sign1 = CoseSign1Builder::new()
            .protected(eddsa_header())
            .payload(payload)
            .try_create_signature(aad, |data| -> Result<Vec<u8>, AuthorityError> {
                Ok(self.signing_key.sign(data).to_bytes().to_vec())
            })?
            .build();
        sign1.to_vec().map_err(|_| AuthorityError::Cose)
    }
}

fn eddsa_header() -> coset::Header {
    HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .build()
}

fn cbor_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, AuthorityError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).map_err(|_| AuthorityError::Cose)?;
    Ok(buf)
}

/// 网络名：非空、≤64、仅 `[A-Za-z0-9_-]`。
pub fn is_valid_network_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// 服务名：同网络名规则，且不得为保留名 `service`。
pub fn is_valid_service_name(s: &str) -> bool {
    is_valid_network_name(s) && s != RESERVED_SERVICE
}

/// 校验 libp2p PeerId 字符串。
pub fn is_valid_peer_id(s: &str) -> bool {
    s.parse::<libp2p_identity::PeerId>().is_ok()
}

/// 当前 Unix 时间（秒）。
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 记录内容的 SHA-256。
pub fn content_hash(value: &[u8]) -> Vec<u8> {
    Sha256::digest(value).to_vec()
}

/// 网络名哈希（key 路径段）：`base64url_nopad(SHA-256(name))`。
pub fn net_hash(name: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(name.as_bytes()))
}

/// 索引记录 key（不依赖 `Authority` 实例）。
pub fn index_key_for(network: &str) -> String {
    format!("{}/{}/{}", AUTH_PREFIX, net_hash(network), RESERVED_SERVICE)
}

/// 用原始公钥验签 COSE_Sign1，返回 payload 字节。
pub fn verify_cose_sign1(
    public_key: &[u8; SEED_LEN],
    aad: &[u8],
    value: &[u8],
) -> Result<Vec<u8>, AuthorityError> {
    let sign1 = CoseSign1::from_slice(value).map_err(|_| AuthorityError::Cose)?;
    let expected = RegisteredLabelWithPrivate::Assigned(iana::Algorithm::EdDSA);
    if sign1.protected.header.alg != Some(expected) {
        return Err(AuthorityError::Cose);
    }
    let verifying_key = VerifyingKey::from_bytes(public_key).map_err(|_| AuthorityError::Cose)?;
    sign1
        .verify_signature(aad, |sig, data| -> Result<(), AuthorityError> {
            let sig = Signature::from_slice(sig).map_err(|_| AuthorityError::Cose)?;
            verifying_key
                .verify(data, &sig)
                .map_err(|_| AuthorityError::Cose)
        })
        .map_err(|_| AuthorityError::Cose)?;
    sign1.payload.ok_or(AuthorityError::Cose)
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::{CoseSign1, RegisteredLabelWithPrivate};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn authority(network: &str) -> Authority {
        Authority::generate(network).unwrap()
    }

    /// 复刻 NexusNet `auth::verify_payload` 的验签路径。
    fn verify(auth: &Authority, aad: &[u8], value: &[u8]) -> Result<Vec<u8>, ()> {
        let sign1 = CoseSign1::from_slice(value).map_err(|_| ())?;
        let expected = RegisteredLabelWithPrivate::Assigned(iana::Algorithm::EdDSA);
        if sign1.protected.header.alg != Some(expected) {
            return Err(());
        }
        let vk = VerifyingKey::from_bytes(&auth.public_key_bytes()).map_err(|_| ())?;
        sign1
            .verify_signature(aad, |sig, data| -> Result<(), ()> {
                let sig = Signature::from_slice(sig).map_err(|_| ())?;
                vk.verify(data, &sig).map_err(|_| ())
            })
            .map_err(|_| ())?;
        sign1.payload.ok_or(())
    }

    fn whitelist(version: u64, members: &[&str]) -> WhitelistDoc {
        WhitelistDoc {
            version,
            members: members.iter().map(|m| m.to_string()).collect(),
        }
    }

    #[test]
    fn net_hash_known_vector() {
        assert_eq!(
            net_hash("myorg"),
            "vvOVh66VpayGBbvhjZZ8agt7V9BWVO2o58oakcZCEZ4"
        );
    }

    #[test]
    fn key_paths() {
        let auth = authority("myorg");
        let h = net_hash("myorg");
        assert_eq!(auth.index_key(), format!("/oahd/auth/{h}/service"));
        assert_eq!(
            auth.service_key("cmd").unwrap(),
            format!("/oahd/auth/{h}/cmd")
        );
        assert!(matches!(
            auth.service_key("service"),
            Err(AuthorityError::InvalidName)
        ));
        assert!(matches!(
            auth.service_key(""),
            Err(AuthorityError::InvalidName)
        ));
        assert!(matches!(
            auth.service_key("bad name"),
            Err(AuthorityError::InvalidName)
        ));
        assert!(matches!(
            auth.service_key(&"a".repeat(65)),
            Err(AuthorityError::InvalidName)
        ));
    }

    #[test]
    fn index_round_trip() {
        let auth = authority("myorg");
        let value = auth
            .sign_whitelist("cmd", &whitelist(1, &["peer-a"]))
            .unwrap();
        let doc = IndexDoc {
            version: 3,
            expires_at: now_unix() + 300,
            services: vec![ServiceEntry {
                name: "cmd".into(),
                hash: content_hash(&value),
                length: value.len() as u64,
            }],
        };
        let bytes = auth.sign_index(&doc).unwrap();
        let payload = verify(&auth, auth.index_key().as_bytes(), &bytes).unwrap();
        let got: IndexDoc = ciborium::de::from_reader(payload.as_slice()).unwrap();
        assert_eq!(got, doc);
    }

    #[test]
    fn whitelist_round_trip() {
        let auth = authority("myorg");
        let doc = whitelist(7, &["peer-a", "peer-b"]);
        let bytes = auth.sign_whitelist("cmd", &doc).unwrap();
        let payload = verify(&auth, auth.service_key("cmd").unwrap().as_bytes(), &bytes).unwrap();
        let got: WhitelistDoc = ciborium::de::from_reader(payload.as_slice()).unwrap();
        assert_eq!(got, doc);
    }

    #[test]
    fn tampered_payload_rejected() {
        let auth = authority("myorg");
        let mut bytes = auth
            .sign_whitelist("cmd", &whitelist(1, &["peer-a"]))
            .unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        assert!(verify(&auth, auth.service_key("cmd").unwrap().as_bytes(), &bytes).is_err());
    }

    #[test]
    fn wrong_aad_rejected() {
        let auth = authority("myorg");
        let bytes = auth
            .sign_whitelist("cmd", &whitelist(1, &["peer-a"]))
            .unwrap();
        // 同一 value、以另一个服务的 key 路径验签 → aad 不符
        assert!(verify(&auth, auth.service_key("ocr").unwrap().as_bytes(), &bytes).is_err());
    }

    #[test]
    fn authority_mismatch_rejected() {
        let signer = authority("myorg");
        let other = authority("myorg");
        let bytes = signer
            .sign_whitelist("cmd", &whitelist(1, &["peer-a"]))
            .unwrap();
        assert!(
            verify(
                &other,
                signer.service_key("cmd").unwrap().as_bytes(),
                &bytes
            )
            .is_err()
        );
    }

    #[test]
    fn public_key_is_32_bytes_base64() {
        let auth = authority("myorg");
        let decoded = STANDARD.decode(auth.public_key_b64()).unwrap();
        assert_eq!(decoded.len(), SEED_LEN);
        assert_eq!(decoded, auth.public_key_bytes());
    }

    #[test]
    fn invalid_network_name_rejected() {
        let seed = [7u8; SEED_LEN];
        assert!(matches!(
            Authority::from_seed(seed, ""),
            Err(AuthorityError::InvalidName)
        ));
        assert!(matches!(
            Authority::from_seed(seed, "bad name"),
            Err(AuthorityError::InvalidName)
        ));
        assert!(matches!(
            Authority::from_seed(seed, &"a".repeat(65)),
            Err(AuthorityError::InvalidName)
        ));
    }

    #[test]
    fn peer_id_validation() {
        let valid = libp2p_identity::PeerId::random().to_string();
        assert!(is_valid_peer_id(&valid));
        assert!(!is_valid_peer_id("not-a-peer-id"));
        assert!(!is_valid_peer_id(""));
    }

    #[test]
    fn load_or_create_persists_private_seed() {
        let dir = std::env::temp_dir().join(format!("nexusauth-authority-{}", now_unix_nanos()));
        let path = dir.join("authority.key");
        let a1 = Authority::load_or_create(&path, "myorg").unwrap();
        assert!(path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let a2 = Authority::load_or_create(&path, "myorg").unwrap();
        assert_eq!(a1.public_key_bytes(), a2.public_key_bytes());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_rejects_wrong_seed_length() {
        let dir =
            std::env::temp_dir().join(format!("nexusauth-authority-bad-{}", now_unix_nanos()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("authority.key");
        fs::write(&path, [0u8; 16]).unwrap();
        assert!(matches!(
            Authority::load_or_create(&path, "myorg"),
            Err(AuthorityError::InvalidSeed)
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    fn now_unix_nanos() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }
}
