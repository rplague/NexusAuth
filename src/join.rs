//! 入网引导：以管理密码完成单轮证明，从在线边车取回 `K_auth` 与状态快照。
//!
//! - 发现：查询正常服务列表 `/oahd/service/<join_service>` 的 providers 得到已入网边车的
//!   节点 PeerId，并与配置的 `join_peers` 合并为候选。
//! - 请求：`mac = HMAC(K_mac, network‖nonce‖ts)`，`K_mac = HKDF(password, salt="nexusauth/join", info=network)`。
//! - 响应：`seed`+`state` 以 `ChaCha20-Poly1305` 加密，密钥由双方 nonce 与密码派生；响应 mac 双向认证。
//!
//! 安全前提：管理密码需为**高熵**口令（本协议不抗离线口令爆破）。

use std::collections::HashSet;
use std::fmt;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::authority::{self, Authority};
use crate::config::ConfigHandle;
use crate::connection::BackendClient;
use crate::log::{LogLevel, LogStruct};
use crate::replay::{ReplayError, ReplayGuard};
use crate::store::{Store, StoreSnapshot};

const JOIN_SALT: &[u8] = b"nexusauth/join";
const ENC_SALT: &[u8] = b"nexusauth/join/enc";
const SEED_LEN: usize = 32;
/// 时间戳允许的偏差（秒）。
pub const MAX_TS_SKEW_SECS: u64 = 300;
/// 请求判别字段。
pub const OP_REQUEST: &str = "join_request";
/// 响应判别字段。
pub const OP_RESPONSE: &str = "join_response";

/// 入网错误。
#[derive(Debug)]
pub enum JoinError {
    /// 未发现任何候选边车
    NoCandidates,
    /// 控制指令/传输失败
    Request(String),
    /// 响应结构非法
    BadResponse(String),
    /// 认证失败（mac/网络/时间戳/重放）
    Auth,
    /// 解密失败
    Decrypt,
    /// 编解码失败
    Decode(String),
    /// 取回的密钥与 DHT 记录不符
    KeyMismatch,
    /// 落盘失败
    Persist(String),
    /// nonce 非法
    InvalidNonce,
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JoinError::NoCandidates => write!(f, "no join candidate available"),
            JoinError::Request(e) => write!(f, "join request failed: {e}"),
            JoinError::BadResponse(e) => write!(f, "bad join response: {e}"),
            JoinError::Auth => write!(f, "join authentication failed"),
            JoinError::Decrypt => write!(f, "join secret decryption failed"),
            JoinError::Decode(e) => write!(f, "join decode error: {e}"),
            JoinError::KeyMismatch => write!(f, "fetched authority key mismatches DHT record"),
            JoinError::Persist(e) => write!(f, "persist joined state failed: {e}"),
            JoinError::InvalidNonce => write!(f, "invalid join nonce"),
        }
    }
}

impl std::error::Error for JoinError {}

/// 入网请求。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub op: String,
    pub network: String,
    pub nonce: String,
    pub ts: u64,
    pub mac: String,
}

/// 入网响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    pub op: String,
    pub responder_nonce: String,
    pub aead_nonce: String,
    pub ciphertext: String,
    pub mac: String,
}

/// 加密载荷。
#[derive(Serialize, Deserialize)]
struct JoinSecret {
    seed: Vec<u8>,
    state: StoreSnapshot,
}

fn derive_key(salt: &[u8], password: &str, info: &[u8]) -> Result<[u8; 32], JoinError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(info, &mut key).map_err(|_| JoinError::Auth)?;
    Ok(key)
}

fn join_mac_key(password: &str, network: &str) -> Result<[u8; 32], JoinError> {
    derive_key(JOIN_SALT, password, network.as_bytes())
}

fn enc_key(
    password: &str,
    network: &str,
    joiner_nonce: &str,
    responder_nonce: &str,
) -> Result<[u8; 32], JoinError> {
    let mut info = Vec::new();
    info.extend_from_slice(network.as_bytes());
    info.push(0);
    info.extend_from_slice(joiner_nonce.as_bytes());
    info.push(0);
    info.extend_from_slice(responder_nonce.as_bytes());
    derive_key(ENC_SALT, password, &info)
}

fn request_mac_input(network: &str, nonce: &str, ts: u64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"nexusauth/join/request");
    v.push(0);
    v.extend_from_slice(network.as_bytes());
    v.push(0);
    v.extend_from_slice(nonce.as_bytes());
    v.push(0);
    v.extend_from_slice(&ts.to_be_bytes());
    v
}

fn response_mac_input(
    network: &str,
    responder_nonce: &str,
    aead_nonce: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"nexusauth/join/response");
    v.push(0);
    v.extend_from_slice(network.as_bytes());
    v.push(0);
    v.extend_from_slice(responder_nonce.as_bytes());
    v.push(0);
    v.extend_from_slice(aead_nonce);
    v.push(0);
    v.extend_from_slice(ciphertext);
    v
}

fn hmac_b64(key: &[u8; 32], input: &[u8]) -> Result<String, JoinError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| JoinError::Auth)?;
    mac.update(input);
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn random_b64(len: usize) -> String {
    let mut buf = vec![0u8; len];
    rand_core::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand_core::OsRng.fill_bytes(&mut buf);
    buf
}

fn b64_decode(s: &str) -> Result<Vec<u8>, JoinError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| JoinError::Decode("base64".into()))
}

/// 构造入网请求。
pub fn make_request(
    password: &str,
    network: &str,
    nonce: &str,
    ts: u64,
) -> Result<JoinRequest, JoinError> {
    let key = join_mac_key(password, network)?;
    let mac = hmac_b64(&key, &request_mac_input(network, nonce, ts))?;
    Ok(JoinRequest {
        op: OP_REQUEST.to_string(),
        network: network.to_string(),
        nonce: nonce.to_string(),
        ts,
        mac,
    })
}

/// 校验入网请求（mac → 时间戳 → nonce 去重）。
pub fn verify_request(
    password: &str,
    network: &str,
    req: &JoinRequest,
    now: u64,
    guard: &mut ReplayGuard,
) -> Result<(), JoinError> {
    if req.op != OP_REQUEST || req.network != network {
        return Err(JoinError::Auth);
    }
    let key = join_mac_key(password, network)?;
    let provided = b64_decode(&req.mac)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).map_err(|_| JoinError::Auth)?;
    mac.update(&request_mac_input(network, &req.nonce, req.ts));
    mac.verify_slice(&provided).map_err(|_| JoinError::Auth)?;

    if now.abs_diff(req.ts) > MAX_TS_SKEW_SECS {
        return Err(JoinError::Auth);
    }
    guard.check_and_insert(&req.nonce).map_err(|e| match e {
        ReplayError::Empty => JoinError::InvalidNonce,
        ReplayError::Replay => JoinError::Auth,
    })
}

/// 构造入网响应（加密 seed 与状态快照）。
pub fn make_response(
    password: &str,
    network: &str,
    joiner_nonce: &str,
    seed: &[u8; SEED_LEN],
    state: &StoreSnapshot,
) -> Result<JoinResponse, JoinError> {
    let responder_nonce = random_b64(16);
    let aead_nonce = random_bytes(12);
    let key = enc_key(password, network, joiner_nonce, &responder_nonce)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| JoinError::Auth)?;

    let secret = JoinSecret {
        seed: seed.to_vec(),
        state: state.clone(),
    };
    let mut plaintext = Vec::new();
    ciborium::ser::into_writer(&secret, &mut plaintext)
        .map_err(|e| JoinError::Decode(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&aead_nonce), plaintext.as_ref())
        .map_err(|_| JoinError::Auth)?;

    let mac_key = join_mac_key(password, network)?;
    let mac = hmac_b64(
        &mac_key,
        &response_mac_input(network, &responder_nonce, &aead_nonce, &ciphertext),
    )?;

    Ok(JoinResponse {
        op: OP_RESPONSE.to_string(),
        responder_nonce,
        aead_nonce: URL_SAFE_NO_PAD.encode(&aead_nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(&ciphertext),
        mac,
    })
}

/// 校验并解密入网响应，返回 `(seed, 状态快照)`。
pub fn open_response(
    password: &str,
    network: &str,
    joiner_nonce: &str,
    resp: &JoinResponse,
) -> Result<([u8; SEED_LEN], StoreSnapshot), JoinError> {
    if resp.op != OP_RESPONSE {
        return Err(JoinError::Auth);
    }
    let aead_nonce = b64_decode(&resp.aead_nonce)?;
    if aead_nonce.len() != 12 {
        return Err(JoinError::Decode("aead nonce length".into()));
    }
    let ciphertext = b64_decode(&resp.ciphertext)?;

    let mac_key = join_mac_key(password, network)?;
    let provided = b64_decode(&resp.mac)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key).map_err(|_| JoinError::Auth)?;
    mac.update(&response_mac_input(
        network,
        &resp.responder_nonce,
        &aead_nonce,
        &ciphertext,
    ));
    mac.verify_slice(&provided).map_err(|_| JoinError::Auth)?;

    let key = enc_key(password, network, joiner_nonce, &resp.responder_nonce)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| JoinError::Auth)?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&aead_nonce), ciphertext.as_ref())
        .map_err(|_| JoinError::Decrypt)?;
    let secret: JoinSecret = ciborium::de::from_reader(plaintext.as_slice())
        .map_err(|_| JoinError::Decode("secret".into()))?;
    if secret.seed.len() != SEED_LEN {
        return Err(JoinError::Decode("seed length".into()));
    }
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&secret.seed);
    Ok((seed, secret.state))
}

/// 入网服务端：校验请求并生成响应。
pub struct JoinServer {
    password: String,
    allow: bool,
    guard: Mutex<ReplayGuard>,
}

impl JoinServer {
    pub fn new(password: &str, allow: bool) -> Self {
        Self {
            password: password.to_string(),
            allow,
            guard: Mutex::new(ReplayGuard::default()),
        }
    }

    /// 校验并响应一条入网请求。
    pub fn respond(
        &self,
        network: &str,
        req: &JoinRequest,
        now: u64,
        seed: &[u8; SEED_LEN],
        state: &StoreSnapshot,
    ) -> Result<JoinResponse, JoinError> {
        if !self.allow {
            return Err(JoinError::Auth);
        }
        verify_request(
            &self.password,
            network,
            req,
            now,
            &mut self.guard.lock().expect("join guard poisoned"),
        )?;
        make_response(&self.password, network, &req.nonce, seed, state)
    }
}

/// 发起一次入网：发现候选 → 逐个请求 → 取回并持久化。
pub async fn attempt(
    client: &BackendClient,
    config: &ConfigHandle,
) -> Result<(Authority, Store), JoinError> {
    let network = config.network();
    let password = config.management_password();
    let service = config.join_service();
    // 发现：查询正常服务列表 `/oahd/service/<service>` 的 providers（已是字符串 PeerId）。
    let service_key = format!("/oahd/service/{service}");

    let mut candidates: Vec<String> = Vec::new();
    match client.query_key(&service_key).await {
        Ok(result) => candidates.extend(result.providers),
        Err(e) => LogStruct::new(
            LogLevel::Debug,
            "入网发现失败",
            format!("{service_key}: {}", e.message),
        )
        .emit(),
    }
    candidates.extend(config.join_peers());
    let mut seen = HashSet::new();
    candidates.retain(|p| seen.insert(p.clone()));

    if candidates.is_empty() {
        return Err(JoinError::NoCandidates);
    }

    let mut last_error: Option<JoinError> = None;
    for peer in candidates {
        let nonce = random_b64(16);
        let ts = authority::now_unix();
        let req = make_request(&password, &network, &nonce, ts)?;
        let payload = serde_json::to_vec(&req).map_err(|e| JoinError::Decode(e.to_string()))?;

        let bytes = match client.service_request_to(&service, &peer, payload).await {
            Ok(b) => b,
            Err(e) => {
                LogStruct::new(
                    LogLevel::Warning,
                    "入网请求失败",
                    format!("{peer}: [{}] {}", e.code, e.message),
                )
                .emit();
                last_error = Some(JoinError::Request(format!(
                    "{peer}: [{}] {}",
                    e.code, e.message
                )));
                continue;
            }
        };
        let resp: JoinResponse = match serde_json::from_slice(&bytes) {
            Ok(r) => r,
            Err(e) => {
                LogStruct::new(
                    LogLevel::Warning,
                    "入网响应解析失败",
                    format!("{peer}: {e}"),
                )
                .emit();
                last_error = Some(JoinError::BadResponse(format!("{peer}: {e}")));
                continue;
            }
        };
        let (seed, state) = match open_response(&password, &network, &nonce, &resp) {
            Ok(v) => v,
            Err(e) => {
                LogStruct::new(
                    LogLevel::Warning,
                    "入网响应校验失败",
                    format!("{peer}: {e}"),
                )
                .emit();
                last_error = Some(e);
                continue;
            }
        };

        let authority =
            Authority::from_seed(seed, &network).map_err(|e| JoinError::Decode(e.to_string()))?;

        if let Err(e) = verify_against_dht(client, &authority).await {
            LogStruct::new(
                LogLevel::Warning,
                "入网密钥校验失败",
                format!("{peer}: {e}"),
            )
            .emit();
            continue;
        }

        crate::fsutil::atomic_write(&config.authority_key_path(), &authority.seed(), Some(0o600))
            .map_err(|e| JoinError::Persist(e.to_string()))?;
        let store = Store::from_snapshot(config.state_path(), &network, state)
            .map_err(|e| JoinError::Persist(e.to_string()))?;

        LogStruct::new(
            LogLevel::Important,
            "入网成功",
            format!("从 {peer} 取回权威密钥与状态"),
        )
        .emit();
        return Ok((authority, store));
    }

    Err(last_error.unwrap_or(JoinError::NoCandidates))
}

/// 用取回的权威公钥验证 DHT 中已有索引；无记录则跳过。
async fn verify_against_dht(
    client: &BackendClient,
    authority: &Authority,
) -> Result<(), JoinError> {
    let index_key = authority.index_key();
    let result = match client.query_key(&index_key).await {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    let Some(value) = result.value else {
        return Ok(());
    };
    authority::verify_cose_sign1(&authority.public_key_bytes(), index_key.as_bytes(), &value)
        .map_err(|_| JoinError::KeyMismatch)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::Authority;
    use std::collections::BTreeMap;

    fn snapshot(network: &str) -> StoreSnapshot {
        let mut services = BTreeMap::new();
        services.insert(
            "cmd".to_string(),
            crate::store::ServiceState {
                version: 2,
                members: ["peer-a".to_string()].into_iter().collect(),
            },
        );
        StoreSnapshot {
            network: network.to_string(),
            index_version: 3,
            services,
            tombstones: BTreeMap::new(),
        }
    }

    #[test]
    fn request_response_round_trip() {
        let password = "high-entropy-password";
        let network = "myorg";
        let authority = Authority::generate(network).unwrap();
        let snap = snapshot(network);

        let req = make_request(password, network, "joiner-nonce", 1000).unwrap();
        let mut guard = ReplayGuard::default();
        verify_request(password, network, &req, 1000, &mut guard).unwrap();

        let resp = make_response(password, network, &req.nonce, &authority.seed(), &snap).unwrap();
        let (seed, got) = open_response(password, network, &req.nonce, &resp).unwrap();
        assert_eq!(seed, authority.seed());
        assert_eq!(got.network, network);
        assert_eq!(got.index_version, 3);
        assert_eq!(got.services["cmd"].version, 2);
    }

    #[test]
    fn wrong_password_rejected() {
        let network = "myorg";
        let authority = Authority::generate(network).unwrap();
        let req = make_request("pw", network, "n", 1000).unwrap();
        let mut guard = ReplayGuard::default();
        assert!(matches!(
            verify_request("other", network, &req, 1000, &mut guard),
            Err(JoinError::Auth)
        ));

        let resp =
            make_response("pw", network, "n", &authority.seed(), &snapshot(network)).unwrap();
        assert!(open_response("other", network, "n", &resp).is_err());
    }

    #[test]
    fn wrong_network_rejected() {
        let req = make_request("pw", "myorg", "n", 1000).unwrap();
        let mut guard = ReplayGuard::default();
        assert!(matches!(
            verify_request("pw", "other", &req, 1000, &mut guard),
            Err(JoinError::Auth)
        ));
    }

    #[test]
    fn stale_and_replay_rejected() {
        let password = "pw";
        let network = "myorg";
        let mut guard = ReplayGuard::default();
        let old = make_request(password, network, "n1", 1000).unwrap();
        assert!(matches!(
            verify_request(
                password,
                network,
                &old,
                1000 + MAX_TS_SKEW_SECS + 1,
                &mut guard
            ),
            Err(JoinError::Auth)
        ));
        let req = make_request(password, network, "n2", 1000).unwrap();
        verify_request(password, network, &req, 1000, &mut guard).unwrap();
        assert!(matches!(
            verify_request(password, network, &req, 1000, &mut guard),
            Err(JoinError::Auth)
        ));
    }

    #[test]
    fn join_server_respects_allow_flag() {
        let network = "myorg";
        let authority = Authority::generate(network).unwrap();
        let req = make_request("pw", network, "n", 1000).unwrap();
        let server = JoinServer::new("pw", false);
        assert!(matches!(
            server.respond(network, &req, 1000, &authority.seed(), &snapshot(network)),
            Err(JoinError::Auth)
        ));
        let server = JoinServer::new("pw", true);
        assert!(
            server
                .respond(network, &req, 1000, &authority.seed(), &snapshot(network))
                .is_ok()
        );
    }
}
