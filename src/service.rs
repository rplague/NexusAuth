//! 入站管理/状态指令处理（JSON + 管理密码 HMAC 认证）。
//!
//! 指令由节点经 `request` 转发到此；每条指令必须携带有效 `mac`（见 `admin` 模块）。

use std::sync::Arc;

use serde_json::json;

use crate::admin::{AdminError, ManagementRequest};
use crate::authority::now_unix;
use crate::connection::BackendClient;
use crate::context::AuthContext;
use crate::join::{self, JoinError, JoinRequest};
use crate::log::{LogLevel, LogStruct};
use crate::protocol::SidecarError;
use crate::replicate::{self, RepError, ReplicateMsg, SyncRequest, SyncResponse};
use crate::store::StoreError;

/// 处理一条入站指令，返回 `reply.result` 的 JSON 字节。
pub async fn handle_service_request(
    _service: &str,
    payload: &[u8],
    ctx: &Arc<AuthContext>,
    client: Option<&BackendClient>,
) -> Result<Vec<u8>, SidecarError> {
    let value: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| SidecarError::new("bad_request", format!("请求解析失败: {e}")))?;
    let op = value
        .get("op")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SidecarError::new("bad_request", "缺少 'op' 字段"))?
        .to_string();

    // 入网 / 复制 / 反熵使用各自独立认证，不走管理 mac。
    if op == join::OP_REQUEST {
        return handle_join(&value, ctx);
    }
    if op == replicate::OP_REPLICATE {
        return handle_replicate(&value, ctx);
    }
    if op == replicate::OP_SYNC_REQUEST {
        return handle_sync_request(&value, ctx);
    }

    let req: ManagementRequest = serde_json::from_value(value)
        .map_err(|e| SidecarError::new("bad_request", format!("请求解析失败: {e}")))?;

    ctx.admin.verify(&req, now_unix()).map_err(admin_error)?;

    LogStruct::new(
        LogLevel::Preset,
        "管理指令",
        format!("op={} service={}", req.op, req.service),
    )
    .emit();

    match req.op.as_str() {
        "status" => Ok(encode(status(ctx))),
        "export_authority_pubkey" => Ok(encode(json!({
            "network": ctx.network,
            "public_key": ctx.authority.public_key_b64(),
        }))),
        "list_services" => Ok(encode(list_services(ctx))),
        "list_members" => {
            let service = require_service(&req)?;
            let store = ctx.store.lock().expect("store poisoned");
            match (store.version(service), store.members(service)) {
                (Some(version), Some(members)) => Ok(encode(json!({
                    "service": service,
                    "version": version,
                    "members": members,
                }))),
                _ => Err(SidecarError::new(
                    "not_found",
                    format!("服务不存在: {service}"),
                )),
            }
        }
        "add_members" => {
            let service = require_service(&req)?;
            let (version, members, index_version) = {
                let mut store = ctx.store.lock().expect("store poisoned");
                let version = store
                    .add_members(service, &req.peers)
                    .map_err(store_error)?;
                let members = store.members(service).unwrap_or_default();
                (version, members, store.index_version())
            };
            after_change(ctx, client, service, version, members, index_version, false);
            Ok(encode(change_reply(ctx, service, version)))
        }
        "remove_members" => {
            let service = require_service(&req)?;
            let (version, members, index_version) = {
                let mut store = ctx.store.lock().expect("store poisoned");
                let version = store
                    .remove_members(service, &req.peers)
                    .map_err(store_error)?;
                let members = store.members(service).unwrap_or_default();
                (version, members, store.index_version())
            };
            after_change(ctx, client, service, version, members, index_version, false);
            Ok(encode(change_reply(ctx, service, version)))
        }
        "set_members" => {
            let service = require_service(&req)?;
            let (version, members, index_version) = {
                let mut store = ctx.store.lock().expect("store poisoned");
                let version = store
                    .set_members(service, &req.peers)
                    .map_err(store_error)?;
                let members = store.members(service).unwrap_or_default();
                (version, members, store.index_version())
            };
            after_change(ctx, client, service, version, members, index_version, false);
            Ok(encode(change_reply(ctx, service, version)))
        }
        "create_service" => {
            let service = require_service(&req)?;
            let (version, members, index_version) = {
                let mut store = ctx.store.lock().expect("store poisoned");
                let version = store
                    .create_service(service, &req.peers)
                    .map_err(store_error)?;
                let members = store.members(service).unwrap_or_default();
                (version, members, store.index_version())
            };
            after_change(ctx, client, service, version, members, index_version, false);
            Ok(encode(change_reply(ctx, service, version)))
        }
        "delete_service" => {
            let service = require_service(&req)?;
            let (tombstone, index_version) = {
                let mut store = ctx.store.lock().expect("store poisoned");
                let tombstone = store.delete_service(service).map_err(store_error)?;
                (tombstone, store.index_version())
            };
            after_change(
                ctx,
                client,
                service,
                tombstone,
                Vec::new(),
                index_version,
                true,
            );
            Ok(encode(json!({
                "service": service,
                "index_version": index_version,
            })))
        }
        "publish_now" => {
            ctx.publisher.notify_publish();
            Ok(encode(json!({ "scheduled": true })))
        }
        other => Err(SidecarError::new(
            "unknown_op",
            format!("未知指令: {other}"),
        )),
    }
}

/// 变更后：触发发布，并在有连接时异步广播。
fn after_change(
    ctx: &Arc<AuthContext>,
    client: Option<&BackendClient>,
    service: &str,
    version: u64,
    members: Vec<String>,
    index_version: u64,
    deleted: bool,
) {
    ctx.publisher.notify_publish();
    if let Some(client) = client {
        replicate::spawn_broadcast(
            ctx,
            client,
            service,
            version,
            members,
            index_version,
            deleted,
        );
    }
}

/// 应用一条复制变更（不转发）。
fn handle_replicate(value: &serde_json::Value, ctx: &AuthContext) -> Result<Vec<u8>, SidecarError> {
    let msg: ReplicateMsg = serde_json::from_value(value.clone())
        .map_err(|e| SidecarError::new("bad_request", format!("复制请求解析失败: {e}")))?;
    ctx.replicate
        .verify_replicate(&msg, now_unix())
        .map_err(rep_error)?;
    let changed = ctx
        .store
        .lock()
        .expect("store poisoned")
        .apply_replicated(
            &msg.service,
            msg.version,
            &msg.members,
            msg.index_version,
            msg.deleted,
        )
        .map_err(store_error)?;
    if changed {
        ctx.publisher.notify_publish();
    }
    Ok(encode(json!({
        "applied": changed,
        "service": msg.service,
        "version": msg.version,
    })))
}

/// 响应一条反熵同步请求。
fn handle_sync_request(
    value: &serde_json::Value,
    ctx: &AuthContext,
) -> Result<Vec<u8>, SidecarError> {
    let req: SyncRequest = serde_json::from_value(value.clone())
        .map_err(|e| SidecarError::new("bad_request", format!("同步请求解析失败: {e}")))?;
    ctx.replicate
        .verify_sync_request(&req, now_unix())
        .map_err(rep_error)?;
    let snapshot = ctx.store.lock().expect("store poisoned").snapshot();
    let ts = now_unix();
    let mac = ctx
        .replicate
        .sign_sync_response(&ctx.network, &req.nonce, &snapshot, ts)
        .map_err(rep_error)?;
    let resp = SyncResponse {
        op: replicate::OP_SYNC_RESPONSE.to_string(),
        nonce: req.nonce,
        snapshot,
        ts,
        mac,
    };
    Ok(encode(
        serde_json::to_value(resp).unwrap_or(serde_json::Value::Null),
    ))
}

fn rep_error(e: RepError) -> SidecarError {
    let code = match e {
        RepError::EmptyPassword => "rep_empty_password",
        RepError::Kdf => "rep_kdf_error",
        RepError::BadMac => "rep_bad_mac",
        RepError::ExpiredTimestamp => "rep_expired_timestamp",
        RepError::Replay => "rep_replay",
        RepError::BadNonce => "rep_bad_nonce",
        RepError::Decode(_) => "rep_decode_error",
        RepError::Store(_) => "rep_store_error",
    };
    SidecarError::new(code, e.to_string())
}

fn handle_join(value: &serde_json::Value, ctx: &AuthContext) -> Result<Vec<u8>, SidecarError> {
    let req: JoinRequest = serde_json::from_value(value.clone())
        .map_err(|e| SidecarError::new("bad_request", format!("入网请求解析失败: {e}")))?;
    let seed = ctx.authority.seed();
    let state = ctx.store.lock().expect("store poisoned").snapshot();
    let resp = ctx
        .join
        .respond(&ctx.network, &req, now_unix(), &seed, &state)
        .map_err(join_error)?;
    LogStruct::new(LogLevel::Preset, "入网请求", "已响应").emit();
    Ok(encode(
        serde_json::to_value(resp).unwrap_or(serde_json::Value::Null),
    ))
}

fn join_error(e: JoinError) -> SidecarError {
    let code = match e {
        JoinError::NoCandidates => "no_candidates",
        JoinError::Request(_) => "request_failed",
        JoinError::BadResponse(_) => "bad_response",
        JoinError::Auth => "join_auth_failed",
        JoinError::Decrypt => "join_decrypt_failed",
        JoinError::Decode(_) => "join_decode_error",
        JoinError::KeyMismatch => "join_key_mismatch",
        JoinError::Persist(_) => "join_persist_error",
        JoinError::InvalidNonce => "join_invalid_nonce",
    };
    SidecarError::new(code, e.to_string())
}

fn status(ctx: &AuthContext) -> serde_json::Value {
    let store = ctx.store.lock().expect("store poisoned");
    let mut services = serde_json::Map::new();
    for name in store.service_names() {
        services.insert(
            name.clone(),
            json!({
                "version": store.version(&name).unwrap_or(0),
                "members": store.member_count(&name).unwrap_or(0),
            }),
        );
    }
    json!({
        "network": ctx.network,
        "authority_public_key": ctx.authority.public_key_b64(),
        "index_version": store.index_version(),
        "services": services,
        "expires_secs": ctx.expires_secs,
        "renew_secs": ctx.renew_secs,
        "connections": ctx.publisher.connection_count(),
        "uptime_secs": ctx.started_at.elapsed().as_secs(),
    })
}

fn list_services(ctx: &AuthContext) -> serde_json::Value {
    let store = ctx.store.lock().expect("store poisoned");
    json!({ "services": store.service_names() })
}

fn change_reply(ctx: &AuthContext, service: &str, version: u64) -> serde_json::Value {
    let store = ctx.store.lock().expect("store poisoned");
    json!({
        "service": service,
        "version": version,
        "members": store.member_count(service).unwrap_or(0),
        "index_version": store.index_version(),
    })
}

fn require_service<'a>(req: &'a ManagementRequest) -> Result<&'a str, SidecarError> {
    if req.service.is_empty() {
        return Err(SidecarError::new("bad_request", "缺少 'service' 字段"));
    }
    Ok(&req.service)
}

fn encode(value: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec())
}

fn admin_error(e: AdminError) -> SidecarError {
    let code = match e {
        AdminError::EmptyPassword => "empty_password",
        AdminError::Kdf => "kdf_error",
        AdminError::BadMac => "bad_mac",
        AdminError::ExpiredTimestamp => "expired_timestamp",
        AdminError::Replay => "replay",
        AdminError::BadNonce => "bad_nonce",
    };
    SidecarError::new(code, e.to_string())
}

fn store_error(e: StoreError) -> SidecarError {
    let code = match e {
        StoreError::NotFound(_) => "not_found",
        StoreError::AlreadyExists(_) => "already_exists",
        StoreError::InvalidService(_) => "invalid_service",
        StoreError::InvalidPeer(_) => "invalid_peer",
        StoreError::NetworkMismatch { .. } => "network_mismatch",
        StoreError::Parse(_) => "state_error",
        StoreError::Io(_) => "io_error",
    };
    SidecarError::new(code, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::admin::AdminAuth;
    use crate::authority::Authority;
    use crate::context::AuthContext;
    use crate::store::Store;

    struct Fixture {
        ctx: Arc<AuthContext>,
        dir: std::path::PathBuf,
        password: String,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn fixture() -> Fixture {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nexusauth-service-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        let network = "myorg";
        let password = "dev-password";
        let authority = Authority::generate(network).unwrap();
        let store =
            Store::load_or_create(dir.join("auth_state.toml"), network, &BTreeMap::new()).unwrap();
        let admin = AdminAuth::new(password, network).unwrap();
        let ctx = Arc::new(AuthContext {
            authority,
            store: std::sync::Mutex::new(store),
            admin,
            join: crate::join::JoinServer::new(password, true),
            replicate: crate::replicate::RepAuth::new(password, network).unwrap(),
            publisher: crate::publisher::PublisherHandle::new(),
            network: network.to_string(),
            service_name: "auth".to_string(),
            expires_secs: 3600,
            renew_secs: 1200,
            started_at: std::time::Instant::now(),
        });
        Fixture {
            ctx,
            dir,
            password: password.to_string(),
        }
    }

    fn peer() -> String {
        libp2p_identity::PeerId::random().to_string()
    }

    fn nonce() -> String {
        use base64::Engine;
        use rand_core::RngCore;
        let mut buf = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut buf);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    }

    fn call(
        fx: &Fixture,
        op: &str,
        service: &str,
        peers: &[String],
    ) -> Result<serde_json::Value, SidecarError> {
        call_with(fx, op, service, peers, &nonce(), now_unix())
    }

    fn call_with(
        fx: &Fixture,
        op: &str,
        service: &str,
        peers: &[String],
        nonce: &str,
        ts: u64,
    ) -> Result<serde_json::Value, SidecarError> {
        let mac = fx.ctx.admin.compute_mac(op, service, peers, nonce, ts);
        let payload = serde_json::to_vec(&json!({
            "op": op,
            "service": service,
            "peers": peers,
            "nonce": nonce,
            "ts": ts,
            "mac": mac,
        }))
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let bytes = rt.block_on(handle_service_request("auth", &payload, &fx.ctx, None))?;
        Ok(serde_json::from_slice(&bytes).unwrap())
    }

    #[test]
    fn status_and_pubkey() {
        let fx = fixture();
        let status = call(&fx, "status", "", &[]).unwrap();
        assert_eq!(status["network"], "myorg");
        assert_eq!(status["index_version"], 1);
        assert_eq!(status["expires_secs"], 3600);
        assert_eq!(
            status["authority_public_key"],
            fx.ctx.authority.public_key_b64()
        );

        let key = call(&fx, "export_authority_pubkey", "", &[]).unwrap();
        assert_eq!(key["public_key"], fx.ctx.authority.public_key_b64());
    }

    #[test]
    fn member_lifecycle() {
        let fx = fixture();
        let p1 = peer();
        let p2 = peer();

        let created = call(&fx, "create_service", "cmd", std::slice::from_ref(&p1)).unwrap();
        assert_eq!(created["version"], 1);
        assert_eq!(created["members"], 1);

        let listed = call(&fx, "list_services", "", &[]).unwrap();
        assert_eq!(listed["services"], json!(["cmd"]));

        let members = call(&fx, "list_members", "cmd", &[]).unwrap();
        assert_eq!(members["version"], 1);
        assert_eq!(members["members"], json!([p1]));

        let added = call(&fx, "add_members", "cmd", std::slice::from_ref(&p2)).unwrap();
        assert_eq!(added["version"], 2);
        assert_eq!(added["members"], 2);

        let removed = call(&fx, "remove_members", "cmd", std::slice::from_ref(&p1)).unwrap();
        assert_eq!(removed["version"], 3);
        assert_eq!(removed["members"], 1);

        let set = call(&fx, "set_members", "cmd", &[p1.clone(), p2.clone()]).unwrap();
        assert_eq!(set["version"], 4);

        let deleted = call(&fx, "delete_service", "cmd", &[]).unwrap();
        assert_eq!(deleted["service"], "cmd");
        assert!(call(&fx, "list_members", "cmd", &[]).is_err());
    }

    #[test]
    fn bad_mac_rejected() {
        let fx = fixture();
        let payload = serde_json::to_vec(&json!({
            "op": "status", "nonce": nonce(), "ts": now_unix(), "mac": "AAAA"
        }))
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(handle_service_request("auth", &payload, &fx.ctx, None))
            .unwrap_err();
        assert_eq!(err.code, "bad_mac");
    }

    #[test]
    fn stale_and_replay_rejected() {
        let fx = fixture();
        let n = nonce();
        let old = now_unix().saturating_sub(10_000);
        let err = call_with(&fx, "status", "", &[], &n, old).unwrap_err();
        assert_eq!(err.code, "expired_timestamp");

        let n2 = nonce();
        assert!(call_with(&fx, "status", "", &[], &n2, now_unix()).is_ok());
        let err = call_with(&fx, "status", "", &[], &n2, now_unix()).unwrap_err();
        assert_eq!(err.code, "replay");
    }

    #[test]
    fn invalid_peer_rejected() {
        let fx = fixture();
        call(&fx, "create_service", "cmd", &[]).unwrap();
        let err = call(&fx, "add_members", "cmd", &["not-a-peer".to_string()]).unwrap_err();
        assert_eq!(err.code, "invalid_peer");
    }

    #[test]
    fn publish_now_schedules() {
        let fx = fixture();
        let r = call(&fx, "publish_now", "", &[]).unwrap();
        assert_eq!(r["scheduled"], true);
    }

    #[test]
    fn unknown_op_rejected() {
        let fx = fixture();
        let err = call(&fx, "nonsense", "", &[]).unwrap_err();
        assert_eq!(err.code, "unknown_op");
    }

    #[test]
    fn password_is_not_in_request() {
        let fx = fixture();
        // 构造请求时只用 mac，不含密码
        let payload = serde_json::to_vec(&json!({
            "op": "status", "nonce": nonce(), "ts": now_unix(), "mac": "x"
        }))
        .unwrap();
        let text = String::from_utf8(payload).unwrap();
        assert!(!text.contains(&fx.password));
    }

    fn invoke(fx: &Fixture, payload: &[u8]) -> Result<serde_json::Value, SidecarError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let bytes = rt.block_on(handle_service_request("auth", payload, &fx.ctx, None))?;
        Ok(serde_json::from_slice(&bytes).unwrap())
    }

    #[test]
    fn inbound_replicate_applied() {
        use crate::replicate::{OP_REPLICATE, ReplicateMsg};

        let fx = fixture();
        call(&fx, "create_service", "cmd", &[]).unwrap();
        let p = peer();

        let mut msg = ReplicateMsg {
            op: OP_REPLICATE.to_string(),
            service: "cmd".to_string(),
            version: 5,
            members: vec![p.clone()],
            index_version: 9,
            deleted: false,
            nonce: nonce(),
            ts: now_unix(),
            mac: String::new(),
        };
        msg.mac = fx.ctx.replicate.sign_replicate(&msg);
        let payload = serde_json::to_vec(&msg).unwrap();
        let v = invoke(&fx, &payload).unwrap();
        assert_eq!(v["applied"], true);
        assert_eq!(fx.ctx.store.lock().unwrap().version("cmd"), Some(5));
        assert_eq!(fx.ctx.store.lock().unwrap().members("cmd"), Some(vec![p]));
    }

    #[test]
    fn inbound_sync_request_returns_signed_snapshot() {
        use crate::replicate::{OP_SYNC_REQUEST, SyncRequest, SyncResponse};

        let fx = fixture();
        call(&fx, "create_service", "cmd", &[]).unwrap();

        let mut req = SyncRequest {
            op: OP_SYNC_REQUEST.to_string(),
            network: "myorg".to_string(),
            nonce: nonce(),
            ts: now_unix(),
            mac: String::new(),
        };
        req.mac = fx
            .ctx
            .replicate
            .sign_sync_request("myorg", &req.nonce, req.ts);
        let payload = serde_json::to_vec(&req).unwrap();
        let v = invoke(&fx, &payload).unwrap();
        let resp: SyncResponse = serde_json::from_value(v).unwrap();
        assert_eq!(resp.nonce, req.nonce);
        assert!(resp.snapshot.services.contains_key("cmd"));
        assert!(
            fx.ctx
                .replicate
                .verify_sync_response("myorg", &req.nonce, &resp)
                .is_ok()
        );
    }
}
