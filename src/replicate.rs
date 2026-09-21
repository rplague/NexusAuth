//! 多边车状态复制：变更广播与反熵同步。
//!
//! - 认证：`K_rep = HKDF-SHA256(password, salt="nexusauth/replicate", info=network)`，
//!   所有边车共享密码，故都能签/验（与既有「持密码即可管理」模型一致）。
//! - `replicate`：单服务变更（含墓碑），按版本 LWW 合并。
//! - `sync_request` / `sync_response`：全量快照拉取合并（反熵）。
//! - 发现复用正常服务列表 `/oahd/service/<service>` 的 providers。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::watch;

use crate::authority::now_unix;
use crate::connection::BackendClient;
use crate::context::AuthContext;
use crate::log::{LogLevel, LogStruct};
use crate::publisher::PublisherHandle;
use crate::replay::{ReplayError, ReplayGuard};
use crate::store::{StoreError, StoreSnapshot};

const REP_SALT: &[u8] = b"nexusauth/replicate";
const MAC_LEN: usize = 32;
/// 时间戳允许的偏差（秒）。
pub const MAX_TS_SKEW_SECS: u64 = 300;
pub const OP_REPLICATE: &str = "replicate";
pub const OP_SYNC_REQUEST: &str = "sync_request";
pub const OP_SYNC_RESPONSE: &str = "sync_response";

/// 复制层错误。
#[derive(Debug)]
pub enum RepError {
    EmptyPassword,
    Kdf,
    BadMac,
    ExpiredTimestamp,
    Replay,
    BadNonce,
    Decode(String),
    Store(StoreError),
}

impl std::fmt::Display for RepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepError::EmptyPassword => write!(f, "management password is empty"),
            RepError::Kdf => write!(f, "key derivation failed"),
            RepError::BadMac => write!(f, "invalid replication mac"),
            RepError::ExpiredTimestamp => write!(f, "replication timestamp out of range"),
            RepError::Replay => write!(f, "replication nonce replayed"),
            RepError::BadNonce => write!(f, "replication nonce is empty"),
            RepError::Decode(e) => write!(f, "replication decode error: {e}"),
            RepError::Store(e) => write!(f, "state merge error: {e}"),
        }
    }
}

impl std::error::Error for RepError {}

impl From<StoreError> for RepError {
    fn from(e: StoreError) -> Self {
        RepError::Store(e)
    }
}

/// 单服务变更复制消息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicateMsg {
    pub op: String,
    pub service: String,
    pub version: u64,
    #[serde(default)]
    pub members: Vec<String>,
    pub index_version: u64,
    #[serde(default)]
    pub deleted: bool,
    pub nonce: String,
    pub ts: u64,
    pub mac: String,
}

/// 反熵同步请求。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub op: String,
    pub network: String,
    pub nonce: String,
    pub ts: u64,
    pub mac: String,
}

/// 反熵同步响应（回显请求 nonce）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub op: String,
    pub nonce: String,
    pub snapshot: StoreSnapshot,
    pub ts: u64,
    pub mac: String,
}

fn random_b64(len: usize) -> String {
    let mut buf = vec![0u8; len];
    rand_core::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, RepError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| RepError::Decode("base64".into()))
}

fn replicate_input(msg: &ReplicateMsg) -> Vec<u8> {
    let mut members: Vec<&str> = msg.members.iter().map(|m| m.as_str()).collect();
    members.sort_unstable();
    let mut v = Vec::new();
    v.extend_from_slice(b"nexusauth/replicate");
    v.push(0);
    v.extend_from_slice(msg.service.as_bytes());
    v.push(0);
    v.extend_from_slice(&msg.version.to_be_bytes());
    v.push(0);
    v.extend_from_slice(&msg.index_version.to_be_bytes());
    v.push(0);
    v.push(msg.deleted as u8);
    v.push(0);
    v.extend_from_slice(members.join(",").as_bytes());
    v.push(0);
    v.extend_from_slice(msg.nonce.as_bytes());
    v.push(0);
    v.extend_from_slice(&msg.ts.to_be_bytes());
    v
}

fn sync_req_input(network: &str, nonce: &str, ts: u64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"nexusauth/sync/req");
    v.push(0);
    v.extend_from_slice(network.as_bytes());
    v.push(0);
    v.extend_from_slice(nonce.as_bytes());
    v.push(0);
    v.extend_from_slice(&ts.to_be_bytes());
    v
}

fn sync_resp_input(
    network: &str,
    nonce: &str,
    snapshot: &StoreSnapshot,
    ts: u64,
) -> Result<Vec<u8>, RepError> {
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(snapshot, &mut cbor).map_err(|e| RepError::Decode(e.to_string()))?;
    let mut v = Vec::new();
    v.extend_from_slice(b"nexusauth/sync/resp");
    v.push(0);
    v.extend_from_slice(network.as_bytes());
    v.push(0);
    v.extend_from_slice(nonce.as_bytes());
    v.push(0);
    v.extend_from_slice(&cbor);
    v.push(0);
    v.extend_from_slice(&ts.to_be_bytes());
    Ok(v)
}

/// 复制消息认证器（含独立 nonce 去重）。
pub struct RepAuth {
    key: [u8; 32],
    guard: Mutex<ReplayGuard>,
}

impl RepAuth {
    pub fn new(password: &str, network: &str) -> Result<Self, RepError> {
        if password.is_empty() {
            return Err(RepError::EmptyPassword);
        }
        let hkdf = Hkdf::<Sha256>::new(Some(REP_SALT), password.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(network.as_bytes(), &mut key)
            .map_err(|_| RepError::Kdf)?;
        Ok(Self {
            key,
            guard: Mutex::new(ReplayGuard::default()),
        })
    }

    fn mac_b64(&self, input: &[u8]) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("hmac key length");
        mac.update(input);
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    fn verify_mac(&self, input: &[u8], provided_b64: &str) -> Result<(), RepError> {
        let provided = b64_decode(provided_b64)?;
        if provided.len() != MAC_LEN {
            return Err(RepError::BadMac);
        }
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.key).map_err(|_| RepError::Kdf)?;
        mac.update(input);
        mac.verify_slice(&provided).map_err(|_| RepError::BadMac)
    }

    fn check_fresh(&self, nonce: &str, ts: u64, now: u64) -> Result<(), RepError> {
        if now.abs_diff(ts) > MAX_TS_SKEW_SECS {
            return Err(RepError::ExpiredTimestamp);
        }
        self.guard
            .lock()
            .expect("rep guard poisoned")
            .check_and_insert(nonce)
            .map_err(|e| match e {
                ReplayError::Empty => RepError::BadNonce,
                ReplayError::Replay => RepError::Replay,
            })
    }

    pub fn sign_replicate(&self, msg: &ReplicateMsg) -> String {
        self.mac_b64(&replicate_input(msg))
    }

    pub fn verify_replicate(&self, msg: &ReplicateMsg, now: u64) -> Result<(), RepError> {
        if msg.op != OP_REPLICATE {
            return Err(RepError::BadMac);
        }
        self.verify_mac(&replicate_input(msg), &msg.mac)?;
        self.check_fresh(&msg.nonce, msg.ts, now)
    }

    pub fn sign_sync_request(&self, network: &str, nonce: &str, ts: u64) -> String {
        self.mac_b64(&sync_req_input(network, nonce, ts))
    }

    pub fn verify_sync_request(&self, req: &SyncRequest, now: u64) -> Result<(), RepError> {
        if req.op != OP_SYNC_REQUEST {
            return Err(RepError::BadMac);
        }
        self.verify_mac(&sync_req_input(&req.network, &req.nonce, req.ts), &req.mac)?;
        self.check_fresh(&req.nonce, req.ts, now)
    }

    pub fn sign_sync_response(
        &self,
        network: &str,
        nonce: &str,
        snapshot: &StoreSnapshot,
        ts: u64,
    ) -> Result<String, RepError> {
        Ok(self.mac_b64(&sync_resp_input(network, nonce, snapshot, ts)?))
    }

    pub fn verify_sync_response(
        &self,
        network: &str,
        nonce: &str,
        resp: &SyncResponse,
    ) -> Result<(), RepError> {
        if resp.op != OP_SYNC_RESPONSE || resp.nonce != nonce {
            return Err(RepError::BadMac);
        }
        self.verify_mac(
            &sync_resp_input(network, nonce, &resp.snapshot, resp.ts)?,
            &resp.mac,
        )
    }
}

/// 发现服务列表中的边车节点 PeerId。
pub async fn discover_peers(client: &BackendClient, service: &str) -> Vec<String> {
    let key = format!("/oahd/service/{service}");
    match client.query_key(&key).await {
        Ok(result) => result.providers,
        Err(e) => {
            LogStruct::new(
                LogLevel::Debug,
                "复制发现失败",
                format!("{key}: {}", e.message),
            )
            .emit();
            Vec::new()
        }
    }
}

/// 异步广播一次变更（不阻塞调用方；失败不重试）。
pub fn spawn_broadcast(
    ctx: &Arc<AuthContext>,
    client: &BackendClient,
    service: &str,
    version: u64,
    members: Vec<String>,
    index_version: u64,
    deleted: bool,
) {
    let ctx = ctx.clone();
    let client = client.clone();
    let service = service.to_string();
    tokio::spawn(async move {
        broadcast(
            &ctx,
            &client,
            &service,
            version,
            members,
            index_version,
            deleted,
        )
        .await;
    });
}

/// 向所有发现的边车广播一条变更。
pub async fn broadcast(
    ctx: &Arc<AuthContext>,
    client: &BackendClient,
    service: &str,
    version: u64,
    members: Vec<String>,
    index_version: u64,
    deleted: bool,
) {
    let peers = discover_peers(client, &ctx.service_name).await;
    for peer in peers {
        let mut msg = ReplicateMsg {
            op: OP_REPLICATE.to_string(),
            service: service.to_string(),
            version,
            members: members.clone(),
            index_version,
            deleted,
            nonce: random_b64(16),
            ts: now_unix(),
            mac: String::new(),
        };
        msg.mac = ctx.replicate.sign_replicate(&msg);
        let payload = match serde_json::to_vec(&msg) {
            Ok(p) => p,
            Err(e) => {
                LogStruct::new(LogLevel::Warning, "复制序列化失败", e.to_string()).emit();
                continue;
            }
        };
        if let Err(e) = client
            .service_request_to(&ctx.service_name, &peer, payload)
            .await
        {
            LogStruct::new(
                LogLevel::Warning,
                "复制广播失败",
                format!("{peer}: [{}] {}", e.code, e.message),
            )
            .emit();
        }
    }
}

/// 反熵：随机拉取一个对端快照并合并；返回本地是否有变化。
pub async fn sync_once(ctx: &Arc<AuthContext>, client: &BackendClient) -> bool {
    let peers = discover_peers(client, &ctx.service_name).await;
    if peers.is_empty() {
        return false;
    }
    let idx = (rand_core::OsRng.next_u32() as usize) % peers.len();
    let peer = &peers[idx];

    let nonce = random_b64(16);
    let ts = now_unix();
    let mut req = SyncRequest {
        op: OP_SYNC_REQUEST.to_string(),
        network: ctx.network.clone(),
        nonce: nonce.clone(),
        ts,
        mac: String::new(),
    };
    req.mac = ctx
        .replicate
        .sign_sync_request(&ctx.network, &req.nonce, req.ts);
    let payload = match serde_json::to_vec(&req) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let bytes = match client
        .service_request_to(&ctx.service_name, peer, payload)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            LogStruct::new(
                LogLevel::Warning,
                "反熵同步请求失败",
                format!("{peer}: [{}] {}", e.code, e.message),
            )
            .emit();
            return false;
        }
    };
    let resp: SyncResponse = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(e) => {
            LogStruct::new(LogLevel::Warning, "反熵响应解析失败", e.to_string()).emit();
            return false;
        }
    };
    if let Err(e) = ctx
        .replicate
        .verify_sync_response(&ctx.network, &nonce, &resp)
    {
        LogStruct::new(LogLevel::Warning, "反熵响应校验失败", e.to_string()).emit();
        return false;
    }
    let changed = match ctx
        .store
        .lock()
        .expect("store poisoned")
        .merge_snapshot(resp.snapshot)
    {
        Ok(c) => c,
        Err(e) => {
            LogStruct::new(LogLevel::Warning, "反熵合并失败", e.to_string()).emit();
            return false;
        }
    };
    if changed {
        ctx.publisher.notify_publish();
    }
    changed
}

/// 反熵同步循环：每 `interval` 拉取一次。
pub async fn sync_loop(
    ctx: Arc<AuthContext>,
    publisher: PublisherHandle,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval.max(Duration::from_secs(1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // 消费立即触发的首次 tick。
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Some(client) = publisher.any_client() {
                    let _ = sync_once(&ctx, &client).await;
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{ServiceState, StoreSnapshot};
    use std::collections::BTreeMap;

    fn snapshot(network: &str) -> StoreSnapshot {
        let mut services = BTreeMap::new();
        services.insert(
            "cmd".to_string(),
            ServiceState {
                version: 3,
                members: ["peer-a".to_string()].into_iter().collect(),
            },
        );
        let mut tombstones = BTreeMap::new();
        tombstones.insert("old".to_string(), 5);
        StoreSnapshot {
            network: network.to_string(),
            index_version: 9,
            services,
            tombstones,
        }
    }

    fn replicate_msg() -> ReplicateMsg {
        ReplicateMsg {
            op: OP_REPLICATE.to_string(),
            service: "cmd".to_string(),
            version: 4,
            members: vec!["b".into(), "a".into()],
            index_version: 10,
            deleted: false,
            nonce: "n1".to_string(),
            ts: 1000,
            mac: String::new(),
        }
    }

    #[test]
    fn replicate_round_trip() {
        let auth = RepAuth::new("pw", "myorg").unwrap();
        let mut msg = replicate_msg();
        msg.mac = auth.sign_replicate(&msg);
        assert!(auth.verify_replicate(&msg, 1000).is_ok());
    }

    #[test]
    fn replicate_wrong_password_or_network_rejected() {
        let auth = RepAuth::new("pw", "myorg").unwrap();
        let mut msg = replicate_msg();
        msg.mac = auth.sign_replicate(&msg);
        assert!(matches!(
            RepAuth::new("other", "myorg")
                .unwrap()
                .verify_replicate(&msg, 1000),
            Err(RepError::BadMac)
        ));
        assert!(matches!(
            RepAuth::new("pw", "other")
                .unwrap()
                .verify_replicate(&msg, 1000),
            Err(RepError::BadMac)
        ));
    }

    #[test]
    fn replicate_tamper_rejected() {
        let auth = RepAuth::new("pw", "myorg").unwrap();
        let mut msg = replicate_msg();
        msg.mac = auth.sign_replicate(&msg);
        msg.version = 99;
        assert!(matches!(
            auth.verify_replicate(&msg, 1000),
            Err(RepError::BadMac)
        ));
    }

    #[test]
    fn replicate_stale_and_replay_rejected() {
        let auth = RepAuth::new("pw", "myorg").unwrap();
        let mut msg = replicate_msg();
        msg.mac = auth.sign_replicate(&msg);
        assert!(matches!(
            auth.verify_replicate(&msg, 1000 + MAX_TS_SKEW_SECS + 1),
            Err(RepError::ExpiredTimestamp)
        ));
        assert!(auth.verify_replicate(&msg, 1000).is_ok());
        assert!(matches!(
            auth.verify_replicate(&msg, 1000),
            Err(RepError::Replay)
        ));
    }

    #[test]
    fn sync_round_trip() {
        let auth = RepAuth::new("pw", "myorg").unwrap();
        let network = "myorg";
        let nonce = "sync-nonce";
        let ts = 1000;

        let mut req = SyncRequest {
            op: OP_SYNC_REQUEST.to_string(),
            network: network.to_string(),
            nonce: nonce.to_string(),
            ts,
            mac: String::new(),
        };
        req.mac = auth.sign_sync_request(network, nonce, ts);
        assert!(auth.verify_sync_request(&req, 1000).is_ok());

        let snap = snapshot(network);
        let resp = SyncResponse {
            op: OP_SYNC_RESPONSE.to_string(),
            nonce: nonce.to_string(),
            snapshot: snap.clone(),
            ts,
            mac: auth.sign_sync_response(network, nonce, &snap, ts).unwrap(),
        };
        assert!(auth.verify_sync_response(network, nonce, &resp).is_ok());
        // 错误 nonce 拒绝
        assert!(auth.verify_sync_response(network, "other", &resp).is_err());
    }
}
