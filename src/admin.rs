//! 管理指令认证：基于共享管理密码的 HMAC 证明 + nonce/ts 防重放。
//!
//! - `K_mac = HKDF-SHA256(password, salt = "nexusauth/mgmt", info = network)`
//! - `mac = HMAC-SHA256(K_mac, json(MacInput{ op, service, peers排序, nonce, ts }))`
//! - 请求本身不携带明文密码；凭 `mac` 证明持有密码。
//! - `ts` 偏差上限 `MAX_TS_SKEW_SECS`；nonce 在进程内去重（有界）。

use std::fmt;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::replay::{ReplayError, ReplayGuard};

/// 时间戳允许的偏差（秒）。
pub const MAX_TS_SKEW_SECS: u64 = 300;
const HKDF_SALT: &[u8] = b"nexusauth/mgmt";
const MAC_LEN: usize = 32;

/// 管理认证错误。
#[derive(Debug, PartialEq, Eq)]
pub enum AdminError {
    /// 管理密码为空
    EmptyPassword,
    /// KDF 失败
    Kdf,
    /// mac 缺失/非法/不匹配
    BadMac,
    /// 时间戳超出允许偏差
    ExpiredTimestamp,
    /// nonce 重放
    Replay,
    /// nonce 为空
    BadNonce,
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminError::EmptyPassword => write!(f, "management password is empty"),
            AdminError::Kdf => write!(f, "key derivation failed"),
            AdminError::BadMac => write!(f, "invalid management mac"),
            AdminError::ExpiredTimestamp => write!(f, "management timestamp out of range"),
            AdminError::Replay => write!(f, "management nonce replayed"),
            AdminError::BadNonce => write!(f, "management nonce is empty"),
        }
    }
}

impl std::error::Error for AdminError {}

/// 管理请求（JSON）。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManagementRequest {
    pub op: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub peers: Vec<String>,
    pub nonce: String,
    pub ts: u64,
    pub mac: String,
}

/// mac 的规范输入（固定字段序）。
#[derive(Serialize)]
struct MacInput<'a> {
    op: &'a str,
    service: &'a str,
    peers: &'a [&'a str],
    nonce: &'a str,
    ts: u64,
}

/// 管理指令认证器。
pub struct AdminAuth {
    mac_key: [u8; MAC_LEN],
    guard: Mutex<ReplayGuard>,
}

impl AdminAuth {
    /// 由管理密码与网络名派生 mac 密钥。
    pub fn new(password: &str, network: &str) -> Result<Self, AdminError> {
        if password.is_empty() {
            return Err(AdminError::EmptyPassword);
        }
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), password.as_bytes());
        let mut mac_key = [0u8; MAC_LEN];
        hkdf.expand(network.as_bytes(), &mut mac_key)
            .map_err(|_| AdminError::Kdf)?;
        Ok(Self {
            mac_key,
            guard: Mutex::new(ReplayGuard::default()),
        })
    }

    /// 计算一条请求的 mac（base64url 无填充）。
    ///
    /// 边车侧只做校验；该签名能力供测试与外部管理工具复用。
    #[allow(dead_code)]
    pub fn compute_mac(
        &self,
        op: &str,
        service: &str,
        peers: &[String],
        nonce: &str,
        ts: u64,
    ) -> String {
        let mut sorted: Vec<&str> = peers.iter().map(|p| p.as_str()).collect();
        sorted.sort_unstable();
        let input = MacInput {
            op,
            service,
            peers: &sorted,
            nonce,
            ts,
        };
        let bytes = serde_json::to_vec(&input).expect("mac input serialization");
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.mac_key).expect("hmac key length");
        mac.update(&bytes);
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// 校验：先验 mac，再验时间戳，最后登记 nonce。
    pub fn verify(&self, req: &ManagementRequest, now: u64) -> Result<(), AdminError> {
        let provided = URL_SAFE_NO_PAD
            .decode(&req.mac)
            .map_err(|_| AdminError::BadMac)?;
        if provided.len() != MAC_LEN {
            return Err(AdminError::BadMac);
        }

        let mut sorted: Vec<&str> = req.peers.iter().map(|p| p.as_str()).collect();
        sorted.sort_unstable();
        let input = MacInput {
            op: &req.op,
            service: &req.service,
            peers: &sorted,
            nonce: &req.nonce,
            ts: req.ts,
        };
        let bytes = serde_json::to_vec(&input).map_err(|_| AdminError::BadMac)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.mac_key).map_err(|_| AdminError::Kdf)?;
        mac.update(&bytes);
        mac.verify_slice(&provided)
            .map_err(|_| AdminError::BadMac)?;

        if now.abs_diff(req.ts) > MAX_TS_SKEW_SECS {
            return Err(AdminError::ExpiredTimestamp);
        }

        self.guard
            .lock()
            .expect("replay guard poisoned")
            .check_and_insert(&req.nonce)
            .map_err(|e| match e {
                ReplayError::Empty => AdminError::BadNonce,
                ReplayError::Replay => AdminError::Replay,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(op: &str, service: &str, peers: &[&str], nonce: &str, ts: u64) -> ManagementRequest {
        ManagementRequest {
            op: op.to_string(),
            service: service.to_string(),
            peers: peers.iter().map(|p| p.to_string()).collect(),
            nonce: nonce.to_string(),
            ts,
            mac: String::new(),
        }
    }

    fn signed(admin: &AdminAuth, mut r: ManagementRequest) -> ManagementRequest {
        r.mac = admin.compute_mac(&r.op, &r.service, &r.peers, &r.nonce, r.ts);
        r
    }

    #[test]
    fn correct_mac_accepted() {
        let admin = AdminAuth::new("pw", "myorg").unwrap();
        let r = signed(&admin, req("add_members", "cmd", &["b", "a"], "n1", 1000));
        assert_eq!(admin.verify(&r, 1000), Ok(()));
    }

    #[test]
    fn peer_order_does_not_matter() {
        let admin = AdminAuth::new("pw", "myorg").unwrap();
        // 以 b,a 顺序签名
        let r = signed(&admin, req("set_members", "cmd", &["b", "a"], "n1", 1000));
        // 接收端按 a,b 顺序提供
        let mut recv = r.clone();
        recv.peers = vec!["a".to_string(), "b".to_string()];
        assert_eq!(admin.verify(&recv, 1000), Ok(()));
    }

    #[test]
    fn wrong_mac_rejected() {
        let admin = AdminAuth::new("pw", "myorg").unwrap();
        let mut r = signed(&admin, req("status", "", &[], "n1", 1000));
        r.mac = URL_SAFE_NO_PAD.encode([0u8; MAC_LEN]);
        assert_eq!(admin.verify(&r, 1000), Err(AdminError::BadMac));
    }

    #[test]
    fn tampered_op_rejected() {
        let admin = AdminAuth::new("pw", "myorg").unwrap();
        let mut r = signed(&admin, req("status", "", &[], "n1", 1000));
        r.op = "delete_service".to_string();
        assert_eq!(admin.verify(&r, 1000), Err(AdminError::BadMac));
    }

    #[test]
    fn wrong_password_or_network_rejected() {
        let r = signed(
            &AdminAuth::new("pw", "myorg").unwrap(),
            req("status", "", &[], "n1", 1000),
        );
        assert_eq!(
            AdminAuth::new("other", "myorg").unwrap().verify(&r, 1000),
            Err(AdminError::BadMac)
        );
        assert_eq!(
            AdminAuth::new("pw", "other").unwrap().verify(&r, 1000),
            Err(AdminError::BadMac)
        );
    }

    #[test]
    fn stale_timestamp_rejected() {
        let admin = AdminAuth::new("pw", "myorg").unwrap();
        let r = signed(&admin, req("status", "", &[], "n1", 1000));
        assert_eq!(
            admin.verify(&r, 1000 + MAX_TS_SKEW_SECS + 1),
            Err(AdminError::ExpiredTimestamp)
        );
        // 偏差边界内通过
        assert_eq!(admin.verify(&r, 1000 + MAX_TS_SKEW_SECS), Ok(()));
    }

    #[test]
    fn replay_rejected() {
        let admin = AdminAuth::new("pw", "myorg").unwrap();
        let r = signed(&admin, req("status", "", &[], "n1", 1000));
        assert_eq!(admin.verify(&r, 1000), Ok(()));
        assert_eq!(admin.verify(&r, 1000), Err(AdminError::Replay));
    }

    #[test]
    fn empty_nonce_rejected() {
        let admin = AdminAuth::new("pw", "myorg").unwrap();
        let r = signed(&admin, req("status", "", &[], "", 1000));
        assert_eq!(admin.verify(&r, 1000), Err(AdminError::BadNonce));
    }

    #[test]
    fn empty_password_rejected() {
        assert!(matches!(
            AdminAuth::new("", "myorg"),
            Err(AdminError::EmptyPassword)
        ));
    }
}
