//! 入站管理/状态指令处理。
//!
//! - `[cluster].enabled = false`：旧 HMAC 路径（见 `admin` 模块）。
//! - `[cluster].enabled = true`：v2 Ed25519 管理员请求；root 写请求可转发给 leader
//!   （见 `admin_v2` 模块）。

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use crate::admin::{AdminError, ManagementRequest};
use crate::admin_v2::{
    AdminForwarder, AdminMemberSpec, AdminRaft, AdminRequestV2, AdminRole, AdminV2Error,
    FORWARDED_ADMIN_OP, FORWARDED_ADMIN_VERSION, ForwardedAdminEnvelope, RaftStatusSnapshot,
    VerifiedAdmin, canonical_peers,
};
use crate::authority::now_unix;
use crate::connection::BackendClient;
use crate::context::AuthContext;
use crate::join::{self, JoinError, JoinRequest};
use crate::log::{LogLevel, LogStruct};
use crate::protocol::SidecarError;
use crate::raft::seed::{SEED_DELIVERY_OP, SEED_DROP_OP};
use crate::raft::transport::node_id_from_peer_id;
use crate::raft::types::{AdminOutcome, PolicyCommand, PolicyResult};
use crate::raft::{RaftRuntime, join as raft_join, seed, token};
use crate::replicate::{self, RepError, ReplicateMsg, SyncRequest, SyncResponse};
use crate::store::StoreError;

/// 处理一条入站指令，返回 `reply.result` 的 JSON 字节。
pub async fn handle_service_request(
    _service: &str,
    payload: &[u8],
    ctx: &Arc<AuthContext>,
    client: Option<&BackendClient>,
    forwarder: Option<&dyn AdminForwarder>,
) -> Result<Vec<u8>, SidecarError> {
    let value: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| SidecarError::new("bad_request", format!("请求解析失败: {e}")))?;
    let op = value
        .get("op")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SidecarError::new("bad_request", "缺少 'op' 字段"))?
        .to_string();

    // Raft 内部 RPC：独立 sidecar 身份签名，绝不走管理员路径。
    if op == crate::raft::transport::RAFT_RPC_OP {
        let raft = ctx
            .raft
            .read()
            .expect("raft poisoned")
            .clone()
            .ok_or_else(|| SidecarError::new("raft_disabled", "Raft 控制面未启用"))?;
        return raft.handle_rpc(payload).await;
    }

    // Phase 4：join token 入网与 seed 分发使用独立认证，不走管理 mac。
    if op == raft_join::RAFT_JOIN_OP {
        return handle_raft_join(&value, ctx, client).await;
    }
    if op == SEED_DELIVERY_OP {
        return handle_seed_delivery(&value, ctx).await;
    }
    if op == SEED_DROP_OP {
        return handle_seed_drop(&value, ctx).await;
    }

    // 入网 / 复制 / 反熵使用各自独立认证，不走管理 mac。
    if op == join::OP_REQUEST {
        if ctx.raft_required {
            return Err(SidecarError::new(
                "join_disabled",
                "Raft 模式下旧密码入网已禁用；请使用 join token",
            ));
        }
        return handle_join(&value, ctx);
    }
    if op == replicate::OP_REPLICATE {
        if ctx.raft_required {
            return Err(SidecarError::new(
                "replicate_disabled",
                "Raft 模式下禁用旧 replicate 写入",
            ));
        }
        return handle_replicate(&value, ctx);
    }
    if op == replicate::OP_SYNC_REQUEST {
        if ctx.raft_required {
            return Err(SidecarError::new(
                "sync_disabled",
                "Raft 模式下禁用旧 sync_request 反熵",
            ));
        }
        return handle_sync_request(&value, ctx);
    }

    // Raft 模式：只接受 v2 管理员签名请求（viewer/root）。
    if ctx.raft_required {
        return handle_admin_v2(payload, &value, ctx, forwarder).await;
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
            "public_key": ctx.authority_public_key_b64().unwrap_or_default(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminOpClass {
    Read,
    Write,
    Unknown,
}

fn classify_admin_op(op: &str) -> AdminOpClass {
    match op {
        "status" | "export_authority_pubkey" | "list_services" | "list_members" => {
            AdminOpClass::Read
        }
        "publish_now" => AdminOpClass::Write,
        other if is_mutating_op(other) => AdminOpClass::Write,
        _ => AdminOpClass::Unknown,
    }
}

/// Raft 模式下的管理员请求入口（v2 签名 + viewer/root）。
async fn handle_admin_v2(
    raw: &[u8],
    value: &Value,
    ctx: &Arc<AuthContext>,
    forwarder: Option<&dyn AdminForwarder>,
) -> Result<Vec<u8>, SidecarError> {
    let op = value.get("op").and_then(Value::as_str).unwrap_or_default();
    if op == FORWARDED_ADMIN_OP {
        return handle_forwarded_admin(raw, ctx).await;
    }

    let req: AdminRequestV2 = serde_json::from_value(value.clone())
        .map_err(|e| SidecarError::new("bad_request", format!("管理员请求解析失败: {e}")))?;
    let verified = match ctx.admin_keys.verify(&req, now_unix()) {
        Ok(verified) => verified,
        Err(e) => {
            audit_admin(
                LogLevel::Warning,
                AdminAudit {
                    kid: &req.kid,
                    request_id: &req.request_id,
                    op: &req.op,
                    service: &req.service,
                    result: e.code(),
                    policy_epoch: None,
                    raft_index: None,
                    leader: None,
                    edge_peer: None,
                },
            );
            return Err(admin_v2_error(e));
        }
    };

    match classify_admin_op(&req.op) {
        AdminOpClass::Read => handle_admin_read(&req, ctx).await,
        AdminOpClass::Write => {
            if verified.role != AdminRole::Root {
                audit_admin(
                    LogLevel::Warning,
                    AdminAudit {
                        kid: &req.kid,
                        request_id: &req.request_id,
                        op: &req.op,
                        service: &req.service,
                        result: "forbidden_role",
                        policy_epoch: None,
                        raft_index: None,
                        leader: None,
                        edge_peer: None,
                    },
                );
                return Err(SidecarError::new(
                    "forbidden_role",
                    "viewer 管理员不能执行写操作",
                ));
            }
            handle_root_write(raw, &req, &verified, ctx, forwarder, None).await
        }
        AdminOpClass::Unknown => {
            audit_admin(
                LogLevel::Warning,
                AdminAudit {
                    kid: &req.kid,
                    request_id: &req.request_id,
                    op: &req.op,
                    service: &req.service,
                    result: "unknown_op",
                    policy_epoch: None,
                    raft_index: None,
                    leader: None,
                    edge_peer: None,
                },
            );
            Err(SidecarError::new(
                "unknown_op",
                format!("未知指令: {}", req.op),
            ))
        }
    }
}

/// leader 收到 edge 转发来的原始请求后，重新解析、验签并执行。
async fn handle_forwarded_admin(
    raw: &[u8],
    ctx: &Arc<AuthContext>,
) -> Result<Vec<u8>, SidecarError> {
    let envelope: ForwardedAdminEnvelope = serde_json::from_slice(raw)
        .map_err(|e| SidecarError::new("bad_request", format!("转发信封解析失败: {e}")))?;
    if envelope.op != FORWARDED_ADMIN_OP || envelope.v != FORWARDED_ADMIN_VERSION {
        return Err(SidecarError::new(
            "bad_request",
            "非法的 forwarded_admin 信封",
        ));
    }

    let raft = admin_raft(ctx)?;
    if !raft.is_leader().await {
        return Err(SidecarError::new(
            "not_leader",
            "forwarded_admin 只能由 leader 处理",
        ));
    }

    let request_bytes = STANDARD
        .decode(&envelope.request_b64)
        .map_err(|_| SidecarError::new("bad_request", "request_b64 不是合法 base64"))?;
    let value: Value = serde_json::from_slice(&request_bytes)
        .map_err(|e| SidecarError::new("bad_request", format!("原始请求解析失败: {e}")))?;
    let req: AdminRequestV2 = serde_json::from_value(value)
        .map_err(|e| SidecarError::new("bad_request", format!("管理员请求解析失败: {e}")))?;

    // leader 必须二次验签，不能信任 edge 的认证结论。
    let verified = ctx
        .admin_keys
        .verify(&req, now_unix())
        .map_err(admin_v2_error)?;
    if verified.role != AdminRole::Root {
        return Err(SidecarError::new(
            "forbidden_role",
            "viewer 管理员不能执行写操作",
        ));
    }
    if classify_admin_op(&req.op) != AdminOpClass::Write {
        return Err(SidecarError::new(
            "bad_request",
            "forwarded_admin 只接受写操作",
        ));
    }

    execute_root_write(&req, &verified, &raft, ctx, Some(&envelope.edge_peer)).await
}

async fn handle_root_write(
    raw: &[u8],
    req: &AdminRequestV2,
    verified: &VerifiedAdmin,
    ctx: &Arc<AuthContext>,
    forwarder: Option<&dyn AdminForwarder>,
    edge_peer: Option<&str>,
) -> Result<Vec<u8>, SidecarError> {
    let raft = admin_raft(ctx)?;
    if raft.is_leader().await {
        return execute_root_write(req, verified, &raft, ctx, edge_peer).await;
    }

    let Some(leader) = raft.leader_peer().await else {
        audit_admin(
            LogLevel::Warning,
            AdminAudit {
                kid: &req.kid,
                request_id: &req.request_id,
                op: &req.op,
                service: &req.service,
                result: "no_leader",
                policy_epoch: None,
                raft_index: None,
                leader: None,
                edge_peer,
            },
        );
        return Err(SidecarError::new("no_leader", "当前没有已知的 Raft leader"));
    };
    let Some(forwarder) = forwarder else {
        return Err(SidecarError::new(
            "not_leader",
            "本节点不是 leader 且没有可用的转发连接",
        ));
    };

    let edge_peer = forwarder.whoami().await.unwrap_or_default();
    let envelope = ForwardedAdminEnvelope {
        op: FORWARDED_ADMIN_OP.to_string(),
        v: FORWARDED_ADMIN_VERSION,
        request_b64: STANDARD.encode(raw),
        edge_peer: edge_peer.clone(),
        edge_sig: String::new(),
    };
    let payload = serde_json::to_vec(&envelope)
        .map_err(|e| SidecarError::new("bad_request", format!("转发信封编码失败: {e}")))?;
    let service = raft.service_name().to_string();

    audit_admin(
        LogLevel::Preset,
        AdminAudit {
            kid: &req.kid,
            request_id: &req.request_id,
            op: &req.op,
            service: &req.service,
            result: "forwarded",
            policy_epoch: None,
            raft_index: None,
            leader: Some(&leader),
            edge_peer: Some(&edge_peer),
        },
    );

    forwarder
        .forward_admin(&service, &leader, payload)
        .await
        .map_err(|e| SidecarError::new(e.code, e.message))
}

async fn execute_root_write(
    req: &AdminRequestV2,
    verified: &VerifiedAdmin,
    raft: &Arc<dyn AdminRaft>,
    ctx: &Arc<AuthContext>,
    edge_peer: Option<&str>,
) -> Result<Vec<u8>, SidecarError> {
    let leader = raft.leader_peer().await;

    if is_member_management_op(&req.op) {
        return execute_member_write(req, verified, ctx, edge_peer).await;
    }

    if req.op == "publish_now" {
        let outcome = crate::publisher::publish_now(ctx, true).await;
        let state = raft.policy_snapshot().await;
        let applied = raft.applied_index().await;
        match outcome {
            Ok(crate::publisher::PublishOutcome::NotLeader) => {
                return Err(SidecarError::new(
                    "not_leader",
                    "本节点已不是 leader，放弃 publish_now",
                ));
            }
            Ok(outcome) => {
                audit_admin(
                    LogLevel::Preset,
                    AdminAudit {
                        kid: &req.kid,
                        request_id: &req.request_id,
                        op: &req.op,
                        service: &req.service,
                        result: "ok",
                        policy_epoch: Some(state.policy_epoch),
                        raft_index: applied,
                        leader: leader.as_deref(),
                        edge_peer,
                    },
                );
                return Ok(encode(json!({
                    "published": matches!(
                        outcome,
                        crate::publisher::PublishOutcome::Published { .. }
                    ),
                    "policy_epoch": state.policy_epoch,
                    "raft_index": applied,
                    "request_id": req.request_id,
                })));
            }
            Err(e) => {
                audit_admin(
                    LogLevel::Warning,
                    AdminAudit {
                        kid: &req.kid,
                        request_id: &req.request_id,
                        op: &req.op,
                        service: &req.service,
                        result: "publish_failed",
                        policy_epoch: Some(state.policy_epoch),
                        raft_index: applied,
                        leader: leader.as_deref(),
                        edge_peer,
                    },
                );
                return Err(publish_error("publish_failed", &e, state.policy_epoch));
            }
        }
    }

    let command = policy_command_for(req)?;
    let admin_command = PolicyCommand::Admin {
        request_id: req.request_id.clone(),
        kid: req.kid.clone(),
        request_hash: verified.request_hash.clone(),
        request_ts: req.ts,
        command: Box::new(command),
    };

    let proposal = raft
        .propose(admin_command)
        .await
        .map_err(map_admin_apply_error)?;

    match proposal.result {
        PolicyResult::Admin {
            request_id,
            policy_epoch,
            raft_index,
            duplicate,
            outcome,
        } => {
            // 重复请求返回第一次的 raft_index；首次请求使用本次 log index。
            let effective_index = if duplicate {
                raft_index
            } else {
                proposal.raft_index
            };
            match outcome {
                AdminOutcome::Applied {
                    service,
                    version,
                    changed,
                } => {
                    if changed {
                        match crate::publisher::publish_now(ctx, false).await {
                            Ok(crate::publisher::PublishOutcome::NotLeader) => {
                                audit_admin(
                                    LogLevel::Warning,
                                    AdminAudit {
                                        kid: &req.kid,
                                        request_id: &req.request_id,
                                        op: &req.op,
                                        service: &req.service,
                                        result: "publish_not_leader",
                                        policy_epoch: Some(policy_epoch),
                                        raft_index: Some(effective_index),
                                        leader: leader.as_deref(),
                                        edge_peer,
                                    },
                                );
                                return Err(SidecarError::new(
                                    "committed_but_publish_failed",
                                    "状态已提交，但发布前已失去 leadership",
                                )
                                .with_publish_error("not_leader"));
                            }
                            Ok(_) => {}
                            Err(e) => {
                                audit_admin(
                                    LogLevel::Warning,
                                    AdminAudit {
                                        kid: &req.kid,
                                        request_id: &req.request_id,
                                        op: &req.op,
                                        service: &req.service,
                                        result: "committed_but_publish_failed",
                                        policy_epoch: Some(policy_epoch),
                                        raft_index: Some(effective_index),
                                        leader: leader.as_deref(),
                                        edge_peer,
                                    },
                                );
                                return Err(publish_error(
                                    "committed_but_publish_failed",
                                    &e,
                                    policy_epoch,
                                ));
                            }
                        }
                    }
                    audit_admin(
                        LogLevel::Preset,
                        AdminAudit {
                            kid: &req.kid,
                            request_id: &req.request_id,
                            op: &req.op,
                            service: &req.service,
                            result: "ok",
                            policy_epoch: Some(policy_epoch),
                            raft_index: Some(effective_index),
                            leader: leader.as_deref(),
                            edge_peer,
                        },
                    );
                    Ok(encode(json!({
                        "request_id": request_id,
                        "service": service,
                        "version": version,
                        "changed": changed,
                        "policy_epoch": policy_epoch,
                        "raft_index": effective_index,
                        "duplicate": duplicate,
                    })))
                }
                AdminOutcome::Rejected { code, message } => {
                    audit_admin(
                        LogLevel::Warning,
                        AdminAudit {
                            kid: &req.kid,
                            request_id: &req.request_id,
                            op: &req.op,
                            service: &req.service,
                            result: "rejected",
                            policy_epoch: Some(policy_epoch),
                            raft_index: Some(effective_index),
                            leader: leader.as_deref(),
                            edge_peer,
                        },
                    );
                    Err(SidecarError::new(code, message))
                }
            }
        }
        other => Err(SidecarError::new(
            "raft_unexpected_result",
            format!("非管理员 apply 结果: {other:?}"),
        )),
    }
}

fn is_member_management_op(op: &str) -> bool {
    matches!(
        op,
        "add_learner" | "promote_voter" | "demote_voter" | "remove_member" | "issue_join_token"
    )
}

fn raft_runtime(ctx: &AuthContext) -> Result<Arc<RaftRuntime>, SidecarError> {
    ctx.raft
        .read()
        .expect("raft poisoned")
        .clone()
        .ok_or_else(|| SidecarError::new("raft_not_ready", "Raft 控制面尚未就绪"))
}

fn require_member(req: &AdminRequestV2) -> Result<&AdminMemberSpec, SidecarError> {
    req.member
        .as_ref()
        .ok_or_else(|| SidecarError::new("bad_request", "缺少 'member' 字段"))
}

async fn execute_member_write(
    req: &AdminRequestV2,
    verified: &VerifiedAdmin,
    ctx: &Arc<AuthContext>,
    edge_peer: Option<&str>,
) -> Result<Vec<u8>, SidecarError> {
    let runtime = raft_runtime(ctx)?;
    if !runtime.is_leader().await {
        return Err(SidecarError::new(
            "not_leader",
            "成员变更必须由 leader 执行",
        ));
    }

    match req.op.as_str() {
        "issue_join_token" => issue_join_token(req, verified, ctx, &runtime, edge_peer).await,
        "add_learner" => {
            let spec = require_member(req)?;
            let target = member_node_id(spec)?;
            let node = node_from_spec(spec, true)?;
            let info = runtime
                .add_learner_node(target, node)
                .await
                .map_err(|e| SidecarError::new("add_learner_failed", e))?;
            let state = runtime.policy_snapshot().await;
            audit_member(
                req,
                "add_learner",
                &info.peer_id,
                "ok",
                state.policy_epoch,
                edge_peer,
                &runtime,
            )
            .await;
            Ok(encode(json!({
                "request_id": req.request_id,
                "node_id": info.node_id,
                "peer_id": info.peer_id,
                "voter": false,
                "policy_epoch": state.policy_epoch,
                "raft_index": runtime.applied_index().await,
                "term": runtime.term().await,
            })))
        }
        "promote_voter" => {
            let spec = require_member(req)?;
            let target = member_node_id(spec)?;
            let view = runtime.membership_view().await;
            let Some(member) = view.find(target) else {
                return Err(SidecarError::new(
                    "not_found",
                    format!("node {target} is not a member"),
                ));
            };
            if member.voter {
                return Err(SidecarError::new(
                    "already_voter",
                    format!("node {target} is already a voter"),
                ));
            }
            if member.x25519_key.is_empty() {
                return Err(SidecarError::new(
                    "missing_x25519_key",
                    format!("node {target} has no X25519 exchange key"),
                ));
            }
            runtime
                .deliver_seed(ctx, target)
                .await
                .map_err(|e| SidecarError::new("seed_delivery_failed", e))?;
            if let Err(e) = runtime.promote_voter(target).await {
                // 提升失败时撤销刚分发的 seed，保持 learner 无 seed。
                let _ = runtime.drop_remote_seed(target).await;
                return Err(SidecarError::new("promote_voter_failed", e));
            }
            let state = runtime.policy_snapshot().await;
            audit_member(
                req,
                "promote_voter",
                &member.peer_id,
                "ok",
                state.policy_epoch,
                edge_peer,
                &runtime,
            )
            .await;
            Ok(encode(json!({
                "request_id": req.request_id,
                "node_id": target,
                "peer_id": member.peer_id,
                "voter": true,
                "policy_epoch": state.policy_epoch,
                "raft_index": runtime.applied_index().await,
                "term": runtime.term().await,
            })))
        }
        "demote_voter" => {
            let spec = require_member(req)?;
            let target = member_node_id(spec)?;
            let view = runtime.membership_view().await;
            if !view.is_voter(target) {
                return Err(SidecarError::new(
                    "not_voter",
                    format!("node {target} is not a voter"),
                ));
            }
            runtime
                .demote_voter(target)
                .await
                .map_err(|e| SidecarError::new("demote_voter_failed", e))?;
            if target == runtime.node_id() {
                seed::remove_seed_file(&ctx.authority_key_path)
                    .map_err(|e| SidecarError::new("seed_remove_failed", e.to_string()))?;
                ctx.clear_authority();
            } else {
                runtime
                    .drop_remote_seed(target)
                    .await
                    .map_err(|e| SidecarError::new("seed_remove_failed", e))?;
            }
            let state = runtime.policy_snapshot().await;
            let view = runtime.membership_view().await;
            audit_member(
                req,
                "demote_voter",
                &view
                    .find(target)
                    .map(|m| m.peer_id.clone())
                    .unwrap_or_default(),
                "ok",
                state.policy_epoch,
                edge_peer,
                &runtime,
            )
            .await;
            Ok(encode(json!({
                "request_id": req.request_id,
                "node_id": target,
                "voter": false,
                "policy_epoch": state.policy_epoch,
                "raft_index": runtime.applied_index().await,
                "term": runtime.term().await,
            })))
        }
        "remove_member" => {
            let spec = require_member(req)?;
            let target = member_node_id(spec)?;
            let view = runtime.membership_view().await;
            if !view.is_member(target) {
                return Err(SidecarError::new(
                    "not_found",
                    format!("node {target} is not a member"),
                ));
            }
            let was_voter = view.is_voter(target);
            if was_voter && target != runtime.node_id() {
                // 先清除旧 voter 的 seed，避免移除后仍持有签名能力。
                runtime
                    .drop_remote_seed(target)
                    .await
                    .map_err(|e| SidecarError::new("seed_remove_failed", e))?;
            }
            if let Err(e) = runtime.remove_member(target).await {
                // 移除失败时恢复刚清除的 seed，避免留下无 seed 的 voter。
                if was_voter && target != runtime.node_id() {
                    let _ = runtime.deliver_seed(ctx, target).await;
                }
                return Err(SidecarError::new("remove_member_failed", e));
            }
            if was_voter && target == runtime.node_id() {
                seed::remove_seed_file(&ctx.authority_key_path)
                    .map_err(|e| SidecarError::new("seed_remove_failed", e.to_string()))?;
                ctx.clear_authority();
            }
            let state = runtime.policy_snapshot().await;
            audit_member(
                req,
                "remove_member",
                &spec.peer_id,
                "ok",
                state.policy_epoch,
                edge_peer,
                &runtime,
            )
            .await;
            Ok(encode(json!({
                "request_id": req.request_id,
                "node_id": target,
                "removed": true,
                "policy_epoch": state.policy_epoch,
                "raft_index": runtime.applied_index().await,
                "term": runtime.term().await,
            })))
        }
        other => Err(SidecarError::new(
            "unknown_op",
            format!("未知成员指令: {other}"),
        )),
    }
}

async fn issue_join_token(
    req: &AdminRequestV2,
    verified: &VerifiedAdmin,
    ctx: &Arc<AuthContext>,
    runtime: &Arc<RaftRuntime>,
    edge_peer: Option<&str>,
) -> Result<Vec<u8>, SidecarError> {
    let spec = req
        .join_token
        .as_ref()
        .ok_or_else(|| SidecarError::new("bad_request", "缺少 'join_token' 字段"))?;
    let token = token::token_from_spec(runtime.cluster_id(), &ctx.network, &req.kid, spec);
    // 签发端校验签名/过期/cluster/network；audience 的实际可达性在 join 入口按
    // edge/leader PeerId 再次校验，因此这里接受管理员指定的非空 audience。
    token::verify_join_token(
        &ctx.admin_keys,
        &token,
        now_unix(),
        runtime.cluster_id(),
        &ctx.network,
        &[runtime.peer_id(), token.audience.as_str()],
    )
    .map_err(|e| SidecarError::new(e.code(), e.to_string()))?;

    let command = PolicyCommand::IssueJoinToken {
        token: token.clone(),
    };
    let admin_command = PolicyCommand::Admin {
        request_id: req.request_id.clone(),
        kid: req.kid.clone(),
        request_hash: verified.request_hash.clone(),
        request_ts: req.ts,
        command: Box::new(command),
    };
    let proposal = runtime
        .propose(admin_command)
        .await
        .map_err(map_admin_apply_error)?;
    let effective_index = match proposal.result {
        PolicyResult::Admin {
            raft_index,
            duplicate,
            outcome,
            ..
        } => {
            if let AdminOutcome::Rejected { code, message } = outcome {
                return Err(SidecarError::new(code, message));
            }
            if duplicate {
                raft_index
            } else {
                proposal.raft_index
            }
        }
        other => {
            return Err(SidecarError::new(
                "raft_unexpected_result",
                format!("join token apply 结果异常: {other:?}"),
            ));
        }
    };
    let state = runtime.policy_snapshot().await;
    audit_member(
        req,
        "issue_join_token",
        &token.jti,
        "ok",
        state.policy_epoch,
        edge_peer,
        runtime,
    )
    .await;
    Ok(encode(json!({
        "request_id": req.request_id,
        "token": token,
        "policy_epoch": state.policy_epoch,
        "raft_index": effective_index,
        "term": runtime.term().await,
    })))
}

fn node_from_spec(
    spec: &AdminMemberSpec,
    require_identity: bool,
) -> Result<crate::raft::types::RaftNode, SidecarError> {
    member_node_id(spec)?;
    if require_identity && spec.identity_key.is_empty() {
        return Err(SidecarError::new("bad_request", "identity_key is required"));
    }
    if require_identity && spec.x25519_key.is_empty() {
        return Err(SidecarError::new(
            "bad_request",
            "x25519_key is required for later seed delivery",
        ));
    }
    Ok(crate::raft::types::RaftNode {
        peer_id: spec.peer_id.clone(),
        identity_key: spec.identity_key.clone(),
        x25519_key: spec.x25519_key.clone(),
    })
}

/// 成员操作的 NodeId 必须由 `peer_id` 派生，配置/请求里的 `node_id` 只作一致性校验。
fn member_node_id(spec: &AdminMemberSpec) -> Result<u64, SidecarError> {
    if !crate::authority::is_valid_peer_id(&spec.peer_id) {
        return Err(SidecarError::new("bad_request", "invalid peer_id"));
    }
    let derived = node_id_from_peer_id(&spec.peer_id);
    if spec.node_id == 0 || spec.node_id != derived {
        return Err(SidecarError::new(
            "bad_request",
            format!(
                "node_id {} does not match node_id_from_peer_id({}) = {derived}",
                spec.node_id, spec.peer_id
            ),
        ));
    }
    Ok(derived)
}

async fn audit_member(
    req: &AdminRequestV2,
    op: &str,
    target: &str,
    result: &str,
    policy_epoch: u64,
    edge_peer: Option<&str>,
    runtime: &Arc<RaftRuntime>,
) {
    let applied = runtime.applied_index().await;
    let leader = runtime.leader_peer().await;
    audit_admin(
        LogLevel::Preset,
        AdminAudit {
            kid: &req.kid,
            request_id: &req.request_id,
            op,
            service: target,
            result,
            policy_epoch: Some(policy_epoch),
            raft_index: applied,
            leader: leader.as_deref(),
            edge_peer,
        },
    );
}

async fn handle_admin_read(
    req: &AdminRequestV2,
    ctx: &Arc<AuthContext>,
) -> Result<Vec<u8>, SidecarError> {
    let raft = admin_raft(ctx)?;
    let state = raft.policy_snapshot().await;
    let applied = raft.applied_index().await;
    let leader = raft.leader_peer().await;
    let term = raft.term().await;
    let stale = raft.stale().await;

    let result = match req.op.as_str() {
        "status" => {
            let services: serde_json::Map<String, Value> = state
                .services
                .iter()
                .map(|(name, service)| {
                    (
                        name.clone(),
                        json!({
                            "version": service.version,
                            "members": service.members.len(),
                        }),
                    )
                })
                .collect();
            let publish = ctx.publisher.status();
            let snapshot = raft.status_snapshot().await;
            let value = json!({
                "network": ctx.network,
                "authority_public_key": ctx.authority_public_key_b64(),
                "has_authority_seed": ctx.has_authority_seed(),
                "authority_seed_present": ctx.has_authority_seed(),
                "index_version": state.policy_epoch,
                "services": services,
                "expires_secs": ctx.expires_secs,
                "renew_secs": ctx.renew_secs,
                "connections": ctx.publisher.connection_count(),
                "uptime_secs": ctx.started_at.elapsed().as_secs(),
                "last_publish_epoch": publish.last_publish_epoch,
                "last_publish_ok": publish.last_publish_ok,
                "last_publish_error": publish.last_publish_error,
                "last_publish_at": publish.last_publish_at,
            });
            with_raft_status(value, state.policy_epoch, &snapshot)
        }
        "export_authority_pubkey" => {
            let Some(public_key) = ctx.authority_public_key_b64() else {
                return Err(SidecarError::new(
                    "no_authority_seed",
                    "learner 不持有 authority seed",
                ));
            };
            let value = json!({
                "network": ctx.network,
                "public_key": public_key,
            });
            with_raft_meta(value, state.policy_epoch, applied, &leader, term, stale)
        }
        "list_services" => {
            let names: Vec<String> = state.services.keys().cloned().collect();
            let value = json!({ "services": names });
            with_raft_meta(value, state.policy_epoch, applied, &leader, term, stale)
        }
        "list_members" => {
            // Phase 4：`service` 为空时返回 Raft 集群成员；否则保持旧的服务成员语义。
            if req.service.is_empty() {
                let runtime = raft_runtime(ctx)?;
                let view = runtime.membership_view().await;
                let value = json!({
                    "voters": view.voters,
                    "learners": view.learners,
                    "leader": view.leader,
                    "term": view.term,
                    "cluster_id": runtime.cluster_id(),
                });
                return Ok(encode(with_raft_meta(
                    value,
                    state.policy_epoch,
                    applied,
                    &leader,
                    term,
                    stale,
                )));
            }
            let service = require_service_v2(req)?;
            let Some(entry) = state.services.get(service) else {
                return Err(SidecarError::new(
                    "not_found",
                    format!("服务不存在: {service}"),
                ));
            };
            let value = json!({
                "service": service,
                "version": entry.version,
                "members": entry.members,
            });
            with_raft_meta(value, state.policy_epoch, applied, &leader, term, stale)
        }
        _ => {
            return Err(SidecarError::new(
                "unknown_op",
                format!("未知指令: {}", req.op),
            ));
        }
    };

    audit_admin(
        LogLevel::Preset,
        AdminAudit {
            kid: &req.kid,
            request_id: &req.request_id,
            op: &req.op,
            service: &req.service,
            result: "ok",
            policy_epoch: Some(state.policy_epoch),
            raft_index: applied,
            leader: leader.as_deref(),
            edge_peer: None,
        },
    );

    Ok(encode(result))
}

fn policy_command_for(req: &AdminRequestV2) -> Result<PolicyCommand, SidecarError> {
    let service = require_service_v2(req)?;
    let peers = canonical_peers(&req.peers);
    let command = match req.op.as_str() {
        "add_members" => PolicyCommand::AddMembers {
            service: service.to_string(),
            peers,
        },
        "remove_members" => PolicyCommand::RemoveMembers {
            service: service.to_string(),
            peers,
        },
        "set_members" => PolicyCommand::SetMembers {
            service: service.to_string(),
            peers,
        },
        "create_service" => PolicyCommand::CreateService {
            service: service.to_string(),
            members: peers,
        },
        "delete_service" => PolicyCommand::DeleteService {
            service: service.to_string(),
        },
        other => {
            return Err(SidecarError::new(
                "unknown_op",
                format!("未知写指令: {other}"),
            ));
        }
    };
    Ok(command)
}

fn require_service_v2(req: &AdminRequestV2) -> Result<&str, SidecarError> {
    if req.service.is_empty() {
        return Err(SidecarError::new("bad_request", "缺少 'service' 字段"));
    }
    Ok(&req.service)
}

fn admin_raft(ctx: &AuthContext) -> Result<Arc<dyn AdminRaft>, SidecarError> {
    ctx.admin_raft
        .read()
        .expect("admin raft poisoned")
        .clone()
        .ok_or_else(|| {
            SidecarError::new(
                "raft_not_ready",
                "Raft 控制面尚未就绪，拒绝管理请求（fail-closed）",
            )
        })
}

fn with_raft_status(mut value: Value, policy_epoch: u64, snapshot: &RaftStatusSnapshot) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert("policy_epoch".to_string(), json!(policy_epoch));
        object.insert("cluster_id".to_string(), json!(snapshot.cluster_id));
        object.insert("node_id".to_string(), json!(snapshot.node_id));
        object.insert("leader".to_string(), json!(snapshot.leader));
        object.insert("term".to_string(), json!(snapshot.term));
        object.insert("state".to_string(), json!(snapshot.state));
        object.insert("applied_index".to_string(), json!(snapshot.applied_index));
        object.insert("last_log_index".to_string(), json!(snapshot.last_log_index));
        object.insert("voters".to_string(), json!(snapshot.voters));
        object.insert("learners".to_string(), json!(snapshot.learners));
        object.insert("stale".to_string(), json!(snapshot.stale));
        object.insert("health".to_string(), json!(snapshot.health()));
    }
    value
}

fn with_raft_meta(
    mut value: Value,
    policy_epoch: u64,
    applied_index: Option<u64>,
    leader: &Option<String>,
    term: u64,
    stale: bool,
) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert("policy_epoch".to_string(), json!(policy_epoch));
        object.insert("applied_index".to_string(), json!(applied_index));
        object.insert("leader".to_string(), json!(leader));
        object.insert("term".to_string(), json!(term));
        object.insert("stale".to_string(), json!(stale));
    }
    value
}

struct AdminAudit<'a> {
    kid: &'a str,
    request_id: &'a str,
    op: &'a str,
    service: &'a str,
    result: &'a str,
    policy_epoch: Option<u64>,
    raft_index: Option<u64>,
    leader: Option<&'a str>,
    edge_peer: Option<&'a str>,
}

fn audit_admin(level: LogLevel, audit: AdminAudit<'_>) {
    LogStruct::new(level, "admin_op", audit_line(&audit)).emit();
}

fn audit_line(audit: &AdminAudit<'_>) -> String {
    let epoch = audit
        .policy_epoch
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let index = audit
        .raft_index
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    format!(
        "event=admin_op mode=raft kid={} request_id={} op={} service={} result={} epoch={} policy_epoch={} raft_index={} leader={} edge_peer={}",
        audit.kid,
        audit.request_id,
        audit.op,
        audit.service,
        audit.result,
        epoch,
        epoch,
        index,
        audit.leader.unwrap_or("-"),
        audit.edge_peer.unwrap_or("-"),
    )
}

fn admin_v2_error(e: AdminV2Error) -> SidecarError {
    SidecarError::new(e.code(), e.to_string())
}

fn map_admin_apply_error(e: String) -> SidecarError {
    let lower = e.to_lowercase();
    if lower.contains("forwardtoleader") || lower.contains("not leader") {
        SidecarError::new("not_leader", e)
    } else {
        SidecarError::new("apply_timeout", e)
    }
}

fn publish_error(
    code: &str,
    error: &crate::publisher::PublishError,
    policy_epoch: u64,
) -> SidecarError {
    SidecarError::new(
        code,
        format!("policy_epoch={policy_epoch} publish_error={error}"),
    )
    .with_publish_error(error.message.clone())
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
    // 旧多写者广播在 Raft 模式下禁用（即使 Raft 尚未启动也 fail-closed）。
    if ctx.raft_required {
        return;
    }
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

fn is_mutating_op(op: &str) -> bool {
    matches!(
        op,
        "add_members" | "remove_members" | "set_members" | "create_service" | "delete_service"
    )
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
    let authority = ctx
        .authority()
        .ok_or_else(|| SidecarError::new("no_authority_seed", "本节点不持有 authority seed"))?;
    let seed = authority.seed();
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

async fn handle_raft_join(
    value: &Value,
    ctx: &Arc<AuthContext>,
    client: Option<&BackendClient>,
) -> Result<Vec<u8>, SidecarError> {
    let runtime = raft_runtime(ctx)?;
    if !ctx.join.allowed() {
        return Err(SidecarError::new(
            "join_not_allowed",
            "allow_join = false，拒绝入网",
        ));
    }
    let req: raft_join::RaftJoinRequest = serde_json::from_value(value.clone())
        .map_err(|e| SidecarError::new("bad_request", format!("入网请求解析失败: {e}")))?;
    raft_join::verify_request(
        &req,
        &ctx.admin_keys,
        runtime.cluster_id(),
        &ctx.network,
        now_unix(),
        &[runtime.peer_id()],
    )
    .map_err(|e| SidecarError::new(e.code(), e.to_string()))?;

    if !runtime.is_leader().await {
        // edge 验签后原样转发；leader 会再次验签并校验 token 状态。
        let Some(leader) = runtime.leader_peer().await else {
            return Err(SidecarError::new("no_leader", "当前没有已知的 Raft leader"));
        };
        let Some(client) = client else {
            return Err(SidecarError::new(
                "not_leader",
                "本节点不是 leader 且没有可用的转发连接",
            ));
        };
        let mut forwarded = req;
        forwarded.edge_peer = runtime.peer_id().to_string();
        let payload = serde_json::to_vec(&forwarded)
            .map_err(|e| SidecarError::new("bad_request", format!("入网转发编码失败: {e}")))?;
        return client
            .service_request_to(runtime.service_name(), &leader, payload)
            .await
            .map_err(|e| SidecarError::new(e.code, e.message));
    }

    handle_leader_join(&runtime, req, ctx).await
}

async fn handle_leader_join(
    runtime: &Arc<RaftRuntime>,
    req: raft_join::RaftJoinRequest,
    ctx: &Arc<AuthContext>,
) -> Result<Vec<u8>, SidecarError> {
    let mut audiences: Vec<&str> = vec![runtime.peer_id()];
    if !req.edge_peer.is_empty() {
        audiences.push(&req.edge_peer);
    }
    raft_join::verify_request(
        &req,
        &ctx.admin_keys,
        runtime.cluster_id(),
        &ctx.network,
        now_unix(),
        &audiences,
    )
    .map_err(|e| SidecarError::new(e.code(), e.to_string()))?;

    let view = runtime.membership_view().await;
    if view.is_member(req.node_id) {
        return Err(SidecarError::new(
            "already_member",
            format!("node {} is already a member", req.node_id),
        ));
    }

    let state = runtime.policy_snapshot().await;
    let Some(stored) = state.join_tokens.get(&req.token.jti) else {
        return Err(SidecarError::new(
            "join_token_unknown",
            format!("join token not issued through raft: {}", req.token.jti),
        ));
    };
    if stored.token != req.token {
        return Err(SidecarError::new(
            "join_token_mismatch",
            "join token does not match the recorded token",
        ));
    }
    if stored.uses >= stored.token.max_uses {
        return Err(SidecarError::new(
            "join_token_replayed",
            format!("join token already used: {}", req.token.jti),
        ));
    }

    // 先消耗 token（写入 Raft），否则不执行成员变更；重放/并发由状态机保证一次性。
    let proposal = runtime
        .propose(PolicyCommand::ConsumeJoinToken {
            jti: req.token.jti.clone(),
            node_id: req.node_id,
            peer_id: req.peer_id.clone(),
            used_at: now_unix(),
        })
        .await
        .map_err(|e| SidecarError::new("raft_join_failed", e))?;
    match proposal.result {
        PolicyResult::Applied { .. } => {}
        PolicyResult::Rejected { code, message, .. } => {
            return Err(SidecarError::new(code, message));
        }
        other => {
            return Err(SidecarError::new(
                "raft_unexpected_result",
                format!("consume join token 结果异常: {other:?}"),
            ));
        }
    }

    let node = crate::raft::types::RaftNode {
        peer_id: req.peer_id.clone(),
        identity_key: req.identity_key.clone(),
        x25519_key: req.x25519_key.clone(),
    };
    let info = runtime
        .add_learner_node(req.node_id, node)
        .await
        .map_err(|e| SidecarError::new("add_learner_failed", e))?;

    let mut members = runtime.membership_view().await;
    if members.find(info.node_id).is_none() {
        members.learners.push(info.clone());
        members.learners.sort_by_key(|member| member.node_id);
    }
    let state = runtime.policy_snapshot().await;
    let response = raft_join::RaftJoinResponse {
        v: raft_join::RAFT_JOIN_VERSION,
        ok: true,
        error: String::new(),
        cluster_id: runtime.cluster_id().to_string(),
        network: ctx.network.clone(),
        node_id: info.node_id,
        peer_id: info.peer_id,
        role: "learner".into(),
        term: runtime.term().await,
        leader: runtime.leader_id().await,
        policy_epoch: state.policy_epoch,
        members: members
            .voters
            .iter()
            .chain(members.learners.iter())
            .cloned()
            .collect(),
    };
    audit_member(
        &AdminRequestV2 {
            op: "raft_join".into(),
            request_id: req.token.jti.clone(),
            kid: req.token.kid.clone(),
            ..Default::default()
        },
        "raft_join",
        &response.peer_id,
        "ok",
        state.policy_epoch,
        req.edge_peer.as_str().into(),
        runtime,
    )
    .await;
    serde_json::to_vec(&response)
        .map_err(|e| SidecarError::new("encode_error", format!("入网响应编码失败: {e}")))
}

async fn handle_seed_delivery(
    value: &Value,
    ctx: &Arc<AuthContext>,
) -> Result<Vec<u8>, SidecarError> {
    let runtime = raft_runtime(ctx)?;
    let req: seed::SeedDeliveryRequest = serde_json::from_value(value.clone())
        .map_err(|e| SidecarError::new("bad_request", format!("seed 请求解析失败: {e}")))?;
    let result = runtime.accept_seed(ctx, &req.envelope).await;
    let ack = seed::sign_ack(
        runtime.identity(),
        runtime.node_id(),
        req.envelope.from_node,
        result.is_ok(),
        result.as_ref().err().map(String::as_str).unwrap_or(""),
    )
    .map_err(|e| SidecarError::new("seed_encode_error", e.to_string()))?;
    if let Err(e) = result {
        LogStruct::new(LogLevel::Warning, "seed 分发失败", e).emit();
    }
    serde_json::to_vec(&ack)
        .map_err(|e| SidecarError::new("encode_error", format!("seed 回执编码失败: {e}")))
}

async fn handle_seed_drop(value: &Value, ctx: &Arc<AuthContext>) -> Result<Vec<u8>, SidecarError> {
    let runtime = raft_runtime(ctx)?;
    let req: seed::SeedDropRequest = serde_json::from_value(value.clone())
        .map_err(|e| SidecarError::new("bad_request", format!("seed 清除请求解析失败: {e}")))?;
    let result = runtime.accept_seed_drop(ctx, &req).await;
    let ack = seed::sign_ack(
        runtime.identity(),
        runtime.node_id(),
        req.from_node,
        result.is_ok(),
        result.as_ref().err().map(String::as_str).unwrap_or(""),
    )
    .map_err(|e| SidecarError::new("seed_encode_error", e.to_string()))?;
    if let Err(e) = result {
        LogStruct::new(LogLevel::Warning, "seed 清除失败", e).emit();
    }
    serde_json::to_vec(&ack)
        .map_err(|e| SidecarError::new("encode_error", format!("seed 回执编码失败: {e}")))
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
        "authority_public_key": ctx.authority_public_key_b64(),
        "has_authority_seed": ctx.has_authority_seed(),
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

fn require_service(req: &ManagementRequest) -> Result<&str, SidecarError> {
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

    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::SigningKey;
    use std::future::Future;
    use std::pin::Pin;

    use crate::admin::AdminAuth;
    use crate::admin_v2::{
        ADMIN_REQUEST_VERSION, AdminProposal, AdminRaft, AdminRequestV2, AdminVerifier,
        ForwardedAdminEnvelope, sign_request,
    };
    use crate::authority::Authority;
    use crate::config::AdminKeyConfig;
    use crate::context::AuthContext;
    use crate::raft::state_machine::PolicyState;
    use crate::raft::types::PolicyCommand;
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
            authority: std::sync::RwLock::new(Some(authority)),
            authority_key_path: dir.join("authority.key"),
            store: std::sync::Mutex::new(store),
            admin,
            admin_keys: crate::admin_v2::AdminVerifier::default(),
            join: crate::join::JoinServer::new(password, true),
            replicate: crate::replicate::RepAuth::new(password, network).unwrap(),
            publisher: crate::publisher::PublisherHandle::new(),
            raft: std::sync::RwLock::new(None),
            admin_raft: std::sync::RwLock::new(None),
            raft_required: false,
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
        let bytes = rt.block_on(handle_service_request(
            "auth", &payload, &fx.ctx, None, None,
        ))?;
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
            fx.ctx.authority_public_key_b64().unwrap()
        );

        let key = call(&fx, "export_authority_pubkey", "", &[]).unwrap();
        assert_eq!(
            key["public_key"],
            fx.ctx.authority_public_key_b64().unwrap()
        );
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
    fn raft_rpc_without_cluster_is_not_admin_path() {
        let fx = fixture();
        let payload = serde_json::to_vec(&json!({"op": "raft_rpc"})).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(handle_service_request(
                "auth", &payload, &fx.ctx, None, None,
            ))
            .unwrap_err();
        assert_eq!(err.code, "raft_disabled");
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
            .block_on(handle_service_request(
                "auth", &payload, &fx.ctx, None, None,
            ))
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
        let bytes = rt.block_on(handle_service_request("auth", payload, &fx.ctx, None, None))?;
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

    // ===== Phase 2：viewer/root 与 edge → leader 转发 =====

    struct FakeRaft {
        leader: bool,
        leader_peer: Option<String>,
        service_name: String,
        state: std::sync::Mutex<PolicyState>,
        applied: std::sync::Mutex<u64>,
        stale: bool,
        proposals: std::sync::atomic::AtomicUsize,
    }

    impl FakeRaft {
        fn new(leader: bool, leader_peer: Option<&str>) -> Self {
            Self {
                leader,
                leader_peer: leader_peer.map(str::to_string),
                service_name: "auth".to_string(),
                state: std::sync::Mutex::new(PolicyState::new("myorg")),
                applied: std::sync::Mutex::new(0),
                stale: false,
                proposals: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn proposal_count(&self) -> usize {
            self.proposals.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn seed_service(&self, service: &str, members: Vec<String>) {
            let mut state = self.state.lock().unwrap();
            state.apply_command_at(
                &PolicyCommand::CreateService {
                    service: service.to_string(),
                    members,
                },
                3,
            );
            *self.applied.lock().unwrap() = 3;
        }
    }

    impl AdminRaft for FakeRaft {
        fn is_leader(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            Box::pin(async move { self.leader })
        }

        fn term(&self) -> Pin<Box<dyn Future<Output = u64> + Send + '_>> {
            Box::pin(async move { 4 })
        }

        fn leader_peer(&self) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
            let leader = self.leader_peer.clone();
            Box::pin(async move { leader })
        }

        fn policy_snapshot(&self) -> Pin<Box<dyn Future<Output = PolicyState> + Send + '_>> {
            let state = self.state.lock().unwrap().clone();
            Box::pin(async move { state })
        }

        fn applied_index(&self) -> Pin<Box<dyn Future<Output = Option<u64>> + Send + '_>> {
            let applied = *self.applied.lock().unwrap();
            Box::pin(async move { if applied == 0 { None } else { Some(applied) } })
        }

        fn stale(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            Box::pin(async move { self.stale })
        }

        fn service_name(&self) -> &str {
            &self.service_name
        }

        fn propose(
            &self,
            command: PolicyCommand,
        ) -> Pin<Box<dyn Future<Output = Result<AdminProposal, String>> + Send + '_>> {
            let index = {
                let mut applied = self.applied.lock().unwrap();
                *applied += 1;
                *applied
            };
            let result = {
                let mut state = self.state.lock().unwrap();
                state.apply_command_at(&command, index)
            };
            self.proposals
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                Ok(AdminProposal {
                    result,
                    raft_index: index,
                })
            })
        }

        fn status_snapshot(&self) -> Pin<Box<dyn Future<Output = RaftStatusSnapshot> + Send + '_>> {
            let leader = self.leader_peer.clone();
            let applied = *self.applied.lock().unwrap();
            let stale = self.stale;
            let state = if self.leader { "leader" } else { "follower" };
            Box::pin(async move {
                RaftStatusSnapshot {
                    cluster_id: "cluster-test".into(),
                    node_id: 7,
                    leader,
                    term: 4,
                    state: state.into(),
                    applied_index: if applied == 0 { None } else { Some(applied) },
                    last_log_index: Some(9),
                    voters: vec![crate::admin_v2::RaftStatusMember {
                        node_id: 1,
                        peer_id: "voter-peer".into(),
                        voter: true,
                    }],
                    learners: vec![crate::admin_v2::RaftStatusMember {
                        node_id: 2,
                        peer_id: "learner-peer".into(),
                        voter: false,
                    }],
                    stale,
                }
            })
        }
    }

    struct FakeForwarder {
        captured: std::sync::Mutex<Vec<(String, String, Vec<u8>)>>,
        response: Vec<u8>,
        edge_peer: String,
    }

    impl FakeForwarder {
        fn new(response: serde_json::Value) -> Self {
            Self {
                captured: std::sync::Mutex::new(Vec::new()),
                response: serde_json::to_vec(&response).unwrap(),
                edge_peer: "edge-peer".to_string(),
            }
        }

        fn captured(&self) -> Vec<(String, String, Vec<u8>)> {
            self.captured.lock().unwrap().clone()
        }
    }

    impl crate::admin_v2::AdminForwarder for FakeForwarder {
        fn forward_admin<'a>(
            &'a self,
            service: &'a str,
            peer: &'a str,
            payload: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, SidecarError>> + Send + 'a>> {
            self.captured
                .lock()
                .unwrap()
                .push((service.to_string(), peer.to_string(), payload));
            let response = self.response.clone();
            Box::pin(async move { Ok(response) })
        }

        fn whoami<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<String, SidecarError>> + Send + 'a>> {
            let peer = self.edge_peer.clone();
            Box::pin(async move { Ok(peer) })
        }
    }

    struct ClusterFixture {
        ctx: Arc<AuthContext>,
        dir: std::path::PathBuf,
        root: SigningKey,
        viewer: SigningKey,
        raft: Arc<FakeRaft>,
    }

    impl Drop for ClusterFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn cluster_fixture(leader: bool, leader_peer: Option<&str>) -> ClusterFixture {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nexusauth-admin-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        let network = "myorg";
        let root = SigningKey::from_bytes(&[7u8; 32]);
        let viewer = SigningKey::from_bytes(&[9u8; 32]);
        let keys = vec![
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
        let admin_keys = AdminVerifier::from_config(&keys, true).unwrap();
        let authority = Authority::generate(network).unwrap();
        let store =
            Store::load_or_create(dir.join("auth_state.toml"), network, &BTreeMap::new()).unwrap();
        let raft = Arc::new(FakeRaft::new(leader, leader_peer));
        let admin_raft: Arc<dyn AdminRaft> = raft.clone();
        let ctx = Arc::new(AuthContext {
            authority: std::sync::RwLock::new(Some(authority)),
            authority_key_path: dir.join("authority.key"),
            store: std::sync::Mutex::new(store),
            admin: AdminAuth::new("pw", network).unwrap(),
            admin_keys,
            join: crate::join::JoinServer::new("pw", true),
            replicate: crate::replicate::RepAuth::new("pw", network).unwrap(),
            publisher: crate::publisher::PublisherHandle::new(),
            raft: std::sync::RwLock::new(None),
            admin_raft: std::sync::RwLock::new(Some(admin_raft)),
            raft_required: true,
            network: network.to_string(),
            service_name: "auth".to_string(),
            expires_secs: 3600,
            renew_secs: 1200,
            started_at: std::time::Instant::now(),
        });
        ClusterFixture {
            ctx,
            dir,
            root,
            viewer,
            raft,
        }
    }

    fn v2_request(
        signing: &SigningKey,
        kid: &str,
        op: &str,
        service: &str,
        peers: &[String],
        request_id: &str,
    ) -> Vec<u8> {
        let mut req = AdminRequestV2 {
            v: ADMIN_REQUEST_VERSION,
            op: op.to_string(),
            service: service.to_string(),
            peers: peers.to_vec(),
            kid: kid.to_string(),
            request_id: request_id.to_string(),
            nonce: nonce(),
            ts: now_unix(),
            sig: String::new(),
            member: None,
            join_token: None,
        };
        sign_request(signing, &mut req).unwrap();
        serde_json::to_vec(&req).unwrap()
    }

    fn invoke_cluster(
        fx: &ClusterFixture,
        payload: &[u8],
        forwarder: Option<&dyn crate::admin_v2::AdminForwarder>,
    ) -> Result<serde_json::Value, SidecarError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let bytes = rt.block_on(handle_service_request(
            "auth", payload, &fx.ctx, None, forwarder,
        ))?;
        Ok(serde_json::from_slice(&bytes).unwrap())
    }

    #[test]
    fn audit_line_contains_required_fields_and_no_secrets() {
        let line = audit_line(&AdminAudit {
            kid: "root-1",
            request_id: "req-1",
            op: "add_members",
            service: "cmd",
            result: "ok",
            policy_epoch: Some(5),
            raft_index: Some(11),
            leader: Some("leader-peer"),
            edge_peer: Some("edge-peer"),
        });
        for needle in [
            "event=admin_op",
            "mode=raft",
            "kid=root-1",
            "request_id=req-1",
            "op=add_members",
            "service=cmd",
            "result=ok",
            "epoch=5",
            "raft_index=11",
            "leader=leader-peer",
            "edge_peer=edge-peer",
        ] {
            assert!(line.contains(needle), "missing {needle}: {line}");
        }
        assert!(!line.contains("nonce="));
        assert!(!line.contains("seed="));
    }

    #[test]
    fn viewer_reads_local_state_machine() {
        let fx = cluster_fixture(false, Some("leader-peer"));
        let member = peer();
        fx.raft.seed_service("cmd", vec![member.clone()]);

        let status = invoke_cluster(
            &fx,
            &v2_request(&fx.viewer, "viewer-1", "status", "", &[], "read-1"),
            None,
        )
        .unwrap();
        assert_eq!(status["policy_epoch"], 2);
        assert_eq!(status["applied_index"], 3);
        assert_eq!(status["leader"], "leader-peer");
        assert_eq!(status["term"], 4);
        assert_eq!(status["stale"], false);
        assert_eq!(status["last_publish_ok"], false);
        assert_eq!(status["last_publish_epoch"], serde_json::Value::Null);
        assert_eq!(status["services"]["cmd"]["version"], 1);
        assert_eq!(status["services"]["cmd"]["members"], 1);
        assert_eq!(status["cluster_id"], "cluster-test");
        assert_eq!(status["node_id"], 7);
        assert_eq!(status["state"], "follower");
        assert_eq!(status["last_log_index"], 9);
        assert_eq!(status["health"], "ok");
        assert_eq!(status["authority_seed_present"], true);
        assert_eq!(status["voters"][0]["peer_id"], "voter-peer");
        assert_eq!(status["learners"][0]["peer_id"], "learner-peer");
        assert!(
            status.get("authority_seed").is_none(),
            "status 不得输出 seed 本身"
        );

        let services = invoke_cluster(
            &fx,
            &v2_request(&fx.viewer, "viewer-1", "list_services", "", &[], "read-2"),
            None,
        )
        .unwrap();
        assert_eq!(services["services"], json!(["cmd"]));
        assert_eq!(services["policy_epoch"], 2);

        let members = invoke_cluster(
            &fx,
            &v2_request(&fx.viewer, "viewer-1", "list_members", "cmd", &[], "read-3"),
            None,
        )
        .unwrap();
        assert_eq!(members["version"], 1);
        assert_eq!(members["members"], json!([member]));
        assert_eq!(members["applied_index"], 3);
        assert_eq!(fx.raft.proposal_count(), 0, "viewer 读不得触发写路径");
    }

    #[test]
    fn root_write_on_follower_forwards_original_request() {
        let fx = cluster_fixture(false, Some("leader-peer"));
        let member = peer();
        let payload = v2_request(
            &fx.root,
            "root-1",
            "add_members",
            "cmd",
            std::slice::from_ref(&member),
            "write-1",
        );
        let forwarder = FakeForwarder::new(json!({ "forwarded_ok": true }));

        let result = invoke_cluster(&fx, &payload, Some(&forwarder)).unwrap();
        assert_eq!(result["forwarded_ok"], true);

        let captured = forwarder.captured();
        assert_eq!(captured.len(), 1);
        let (service, peer, envelope_bytes) = &captured[0];
        assert_eq!(service, "auth");
        assert_eq!(peer, "leader-peer");
        let envelope: ForwardedAdminEnvelope = serde_json::from_slice(envelope_bytes).unwrap();
        assert_eq!(envelope.op, FORWARDED_ADMIN_OP);
        assert_eq!(envelope.v, FORWARDED_ADMIN_VERSION);
        assert_eq!(envelope.edge_peer, "edge-peer");
        assert_eq!(
            STANDARD.decode(&envelope.request_b64).unwrap(),
            payload,
            "必须转发原始签名请求字节"
        );
        assert_eq!(fx.raft.proposal_count(), 0, "follower 不得本地 apply");
    }

    #[test]
    fn leader_rejects_tampered_forwarded_request() {
        let fx = cluster_fixture(true, Some("leader-peer"));
        let member = peer();
        let payload = v2_request(
            &fx.root,
            "root-1",
            "create_service",
            "cmd",
            std::slice::from_ref(&member),
            "tamper-1",
        );
        let mut value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        value["service"] = json!("tampered");
        let tampered = serde_json::to_vec(&value).unwrap();
        let envelope = ForwardedAdminEnvelope {
            op: FORWARDED_ADMIN_OP.to_string(),
            v: FORWARDED_ADMIN_VERSION,
            request_b64: STANDARD.encode(tampered),
            edge_peer: "edge-peer".to_string(),
            edge_sig: String::new(),
        };

        let err = invoke_cluster(&fx, &serde_json::to_vec(&envelope).unwrap(), None).unwrap_err();
        assert_eq!(err.code, "bad_signature");
        assert_eq!(fx.raft.proposal_count(), 0);
    }

    #[test]
    fn leader_accepts_valid_forwarded_request() {
        let fx = cluster_fixture(true, Some("leader-peer"));
        let member = peer();
        let request = v2_request(
            &fx.root,
            "root-1",
            "create_service",
            "cmd",
            std::slice::from_ref(&member),
            "forward-ok-1",
        );
        let envelope = ForwardedAdminEnvelope {
            op: FORWARDED_ADMIN_OP.to_string(),
            v: FORWARDED_ADMIN_VERSION,
            request_b64: STANDARD.encode(&request),
            edge_peer: "edge-peer".to_string(),
            edge_sig: String::new(),
        };

        let result = invoke_cluster(&fx, &serde_json::to_vec(&envelope).unwrap(), None).unwrap();
        assert_eq!(result["service"], "cmd");
        assert_eq!(result["version"], 1);
        assert_eq!(result["policy_epoch"], 2);
        assert_eq!(result["duplicate"], false);
        assert_eq!(fx.raft.proposal_count(), 1);
    }

    #[test]
    fn forwarded_admin_on_follower_returns_not_leader() {
        let fx = cluster_fixture(false, Some("leader-peer"));
        let envelope = ForwardedAdminEnvelope {
            op: FORWARDED_ADMIN_OP.to_string(),
            v: FORWARDED_ADMIN_VERSION,
            request_b64: STANDARD.encode(b"{}"),
            edge_peer: "edge-peer".to_string(),
            edge_sig: String::new(),
        };
        let err = invoke_cluster(&fx, &serde_json::to_vec(&envelope).unwrap(), None).unwrap_err();
        assert_eq!(err.code, "not_leader");
    }

    #[test]
    fn viewer_write_is_forbidden() {
        let fx = cluster_fixture(true, Some("leader-peer"));
        let payload = v2_request(
            &fx.viewer,
            "viewer-1",
            "add_members",
            "cmd",
            &[peer()],
            "write-viewer",
        );
        let err = invoke_cluster(&fx, &payload, None).unwrap_err();
        assert_eq!(err.code, "forbidden_role");
        assert_eq!(fx.raft.proposal_count(), 0);
    }

    #[test]
    fn root_write_without_leader_returns_no_leader() {
        let fx = cluster_fixture(false, None);
        let payload = v2_request(
            &fx.root,
            "root-1",
            "create_service",
            "cmd",
            &[peer()],
            "write-noleader",
        );
        let err = invoke_cluster(&fx, &payload, None).unwrap_err();
        assert_eq!(err.code, "no_leader");
    }

    #[test]
    fn admin_write_request_id_is_idempotent_and_conflicts() {
        let fx = cluster_fixture(true, Some("leader-peer"));
        let member = peer();

        let first = invoke_cluster(
            &fx,
            &v2_request(
                &fx.root,
                "root-1",
                "create_service",
                "cmd",
                std::slice::from_ref(&member),
                "idem-1",
            ),
            None,
        )
        .unwrap();
        assert_eq!(first["version"], 1);
        assert_eq!(first["policy_epoch"], 2);
        assert_eq!(first["duplicate"], false);
        let first_index = first["raft_index"].as_u64().unwrap();

        // 相同 request_id + 相同内容、新 nonce/ts：返回第一次结果，不重复 apply。
        let retry = invoke_cluster(
            &fx,
            &v2_request(
                &fx.root,
                "root-1",
                "create_service",
                "cmd",
                std::slice::from_ref(&member),
                "idem-1",
            ),
            None,
        )
        .unwrap();
        assert_eq!(retry["policy_epoch"], 2);
        assert_eq!(retry["version"], 1);
        assert_eq!(retry["raft_index"], first_index);
        assert_eq!(retry["duplicate"], true);

        // 相同 request_id、不同内容：冲突且不改变状态。
        let err = invoke_cluster(
            &fx,
            &v2_request(
                &fx.root,
                "root-1",
                "create_service",
                "cmd",
                &[peer()],
                "idem-1",
            ),
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, "request_id_conflict");
    }

    #[test]
    fn raft_mode_rejects_inbound_replicate() {
        use crate::replicate::{OP_REPLICATE, ReplicateMsg};

        let fx = cluster_fixture(false, Some("leader-peer"));
        let mut msg = ReplicateMsg {
            op: OP_REPLICATE.to_string(),
            service: "cmd".to_string(),
            version: 5,
            members: vec![peer()],
            index_version: 9,
            deleted: false,
            nonce: nonce(),
            ts: now_unix(),
            mac: String::new(),
        };
        msg.mac = fx.ctx.replicate.sign_replicate(&msg);
        let payload = serde_json::to_vec(&msg).unwrap();

        let err = invoke_cluster(&fx, &payload, None).unwrap_err();
        assert_eq!(err.code, "replicate_disabled");
        assert!(fx.ctx.store.lock().unwrap().service_names().is_empty());
    }

    #[test]
    fn raft_mode_rejects_inbound_sync_request() {
        use crate::replicate::{OP_SYNC_REQUEST, SyncRequest};

        let fx = cluster_fixture(false, Some("leader-peer"));
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

        let err = invoke_cluster(&fx, &payload, None).unwrap_err();
        assert_eq!(err.code, "sync_disabled");
        assert!(fx.ctx.store.lock().unwrap().service_names().is_empty());
    }

    #[test]
    fn raft_mode_rejects_legacy_password_join() {
        let fx = cluster_fixture(false, Some("leader-peer"));
        let payload = serde_json::to_vec(&json!({
            "op": crate::join::OP_REQUEST,
            "network": "myorg",
            "nonce": nonce(),
            "ts": now_unix(),
            "mac": "AAAA",
        }))
        .unwrap();
        let err = invoke_cluster(&fx, &payload, None).unwrap_err();
        assert_eq!(err.code, "join_disabled");
    }

    #[test]
    fn publish_now_on_follower_returns_not_leader() {
        let fx = cluster_fixture(false, Some("leader-peer"));
        let err = invoke_cluster(
            &fx,
            &v2_request(&fx.root, "root-1", "publish_now", "", &[], "pub-follower"),
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, "not_leader");
        assert_eq!(fx.raft.proposal_count(), 0);
    }

    #[test]
    fn publish_failure_returns_committed_but_publish_failed() {
        let fx = cluster_fixture(true, Some("leader-peer"));
        fx.ctx.publisher.force_next_publish_error("dht unavailable");

        let err = invoke_cluster(
            &fx,
            &v2_request(
                &fx.root,
                "root-1",
                "create_service",
                "cmd",
                &[peer()],
                "publish-fail-1",
            ),
            None,
        )
        .unwrap_err();

        assert_eq!(err.code, "committed_but_publish_failed");
        assert_eq!(err.publish_error.as_deref(), Some("dht unavailable"));
        assert!(err.message.contains("dht unavailable"));
        assert_eq!(fx.raft.proposal_count(), 1);

        let state = fx.raft.state.lock().unwrap();
        assert_eq!(state.service_version("cmd"), Some(1));
        drop(state);

        let status = invoke_cluster(
            &fx,
            &v2_request(
                &fx.viewer,
                "viewer-1",
                "status",
                "",
                &[],
                "after-publish-fail",
            ),
            None,
        )
        .unwrap();
        assert_eq!(status["last_publish_ok"], false);
        assert_eq!(status["last_publish_error"], "dht unavailable");
        assert!(status["last_publish_at"].as_u64().is_some());
    }

    #[test]
    fn learner_without_seed_reports_no_authority() {
        let fx = cluster_fixture(false, Some("leader-peer"));
        fx.ctx.clear_authority();

        let status = invoke_cluster(
            &fx,
            &v2_request(&fx.viewer, "viewer-1", "status", "", &[], "learner-status"),
            None,
        )
        .unwrap();
        assert_eq!(status["has_authority_seed"], false);
        assert!(status["authority_public_key"].is_null());

        let err = invoke_cluster(
            &fx,
            &v2_request(
                &fx.viewer,
                "viewer-1",
                "export_authority_pubkey",
                "",
                &[],
                "learner-export",
            ),
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, "no_authority_seed");
    }

    #[test]
    fn member_spec_node_id_must_match_peer_id() {
        let peer = libp2p_identity::PeerId::random().to_string();
        let derived = node_id_from_peer_id(&peer);
        let spec = AdminMemberSpec {
            node_id: derived,
            peer_id: peer,
            identity_key: String::new(),
            x25519_key: String::new(),
        };
        assert_eq!(member_node_id(&spec).unwrap(), derived);

        let mut mismatched = spec.clone();
        mismatched.node_id = derived.wrapping_add(1).max(1);
        assert_eq!(member_node_id(&mismatched).unwrap_err().code, "bad_request");
    }
}
