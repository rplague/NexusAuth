//! 确定性的策略状态机。
//!
//! Raft 提交顺序即唯一写入顺序；因此无需旧多写者路径的 LWW 合并。
//! 但成员校验、墓碑版本与「只在真正变化时提升版本」的语义与 `store` 保持一致。
//! 全局索引版本统一为 `policy_epoch`，只由本状态机的 apply 推进。

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::authority::{is_valid_peer_id, is_valid_service_name};
use crate::store::{ServiceState, StoreSnapshot};

use super::types::{AdminOutcome, PolicyCommand, PolicyResult, StoredJoinToken};

/// 去重表条目上限。
pub const DEDUP_MAX_ENTRIES: usize = 10_000;
/// 去重表 TTL（秒）。以请求 `ts` 为确定性时间基准。
pub const DEDUP_TTL_SECS: u64 = 24 * 60 * 60;

/// 一条已应用管理员请求的去重记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminRecord {
    pub request_hash: String,
    pub outcome: AdminOutcome,
    /// 第一次 apply 后的 `policy_epoch`。
    pub policy_epoch: u64,
    /// 第一次 apply 的 Raft log index。
    pub raft_index: u64,
    /// 请求时间戳（用于 TTL）。
    pub request_ts: u64,
}

/// 策略状态（可序列化为快照）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyState {
    pub network: String,
    /// 全局策略版本；只由 `apply_command` 推进。
    pub policy_epoch: u64,
    /// 最近一次续期提案写入的索引过期时间（秒）；只来自 Raft 日志。
    #[serde(default)]
    pub index_expires_at: u64,
    #[serde(default)]
    pub services: BTreeMap<String, ServiceState>,
    /// 服务 → 删除版本（墓碑，防旧快照复活）。
    #[serde(default)]
    pub tombstones: BTreeMap<String, u64>,
    /// `request_id -> 首次结果`；进入快照，leader 切换后仍幂等。
    #[serde(default)]
    pub dedup: BTreeMap<String, AdminRecord>,
    /// `jti -> token 与已用次数`；随 Raft 快照复制，用于一次性校验。
    #[serde(default)]
    pub join_tokens: BTreeMap<String, StoredJoinToken>,
}

impl PolicyState {
    pub fn new(network: impl Into<String>) -> Self {
        Self {
            network: network.into(),
            policy_epoch: 1,
            index_expires_at: 0,
            services: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            dedup: BTreeMap::new(),
            join_tokens: BTreeMap::new(),
        }
    }

    /// 从旧状态文件快照构造，便于重新初始化时复用成员状态。
    #[allow(dead_code)]
    pub fn from_store_snapshot(snapshot: StoreSnapshot) -> Self {
        Self {
            network: snapshot.network,
            policy_epoch: snapshot.index_version.max(1),
            index_expires_at: 0,
            services: snapshot.services,
            tombstones: snapshot.tombstones,
            dedup: BTreeMap::new(),
            join_tokens: BTreeMap::new(),
        }
    }

    #[allow(dead_code)]
    pub fn to_store_snapshot(&self) -> StoreSnapshot {
        StoreSnapshot {
            network: self.network.clone(),
            index_version: self.policy_epoch,
            services: self.services.clone(),
            tombstones: self.tombstones.clone(),
        }
    }

    /// 应用一条命令。必须保持确定性：相同输入状态 + 相同命令 → 相同输出状态/结果。
    #[allow(dead_code)]
    pub fn apply_command(&mut self, cmd: &PolicyCommand) -> PolicyResult {
        self.apply_command_at(cmd, 0)
    }

    /// 应用一条命令，并记录它在 Raft log 中的 index（用于幂等结果）。
    pub fn apply_command_at(&mut self, cmd: &PolicyCommand, raft_index: u64) -> PolicyResult {
        if let PolicyCommand::Admin {
            request_id,
            kid: _,
            request_hash,
            request_ts,
            command,
        } = cmd
        {
            return self.apply_admin(request_id, request_hash, *request_ts, command, raft_index);
        }
        match self.apply_inner(cmd) {
            Ok((service, version, changed)) => PolicyResult::Applied {
                service,
                version,
                policy_epoch: self.policy_epoch,
                changed,
            },
            Err((code, message)) => PolicyResult::Rejected {
                code,
                message,
                policy_epoch: self.policy_epoch,
            },
        }
    }

    fn apply_admin(
        &mut self,
        request_id: &str,
        request_hash: &str,
        request_ts: u64,
        command: &PolicyCommand,
        raft_index: u64,
    ) -> PolicyResult {
        if let Some(record) = self.dedup.get(request_id) {
            let outcome = if record.request_hash == request_hash {
                record.outcome.clone()
            } else {
                AdminOutcome::Rejected {
                    code: "request_id_conflict".into(),
                    message: format!(
                        "request_id {request_id} reused with different request content"
                    ),
                }
            };
            return PolicyResult::Admin {
                request_id: request_id.to_string(),
                policy_epoch: if record.request_hash == request_hash {
                    record.policy_epoch
                } else {
                    self.policy_epoch
                },
                raft_index: if record.request_hash == request_hash {
                    record.raft_index
                } else {
                    raft_index
                },
                duplicate: true,
                outcome,
            };
        }

        let outcome = match self.apply_inner(command) {
            Ok((service, version, changed)) => AdminOutcome::Applied {
                service,
                version,
                changed,
            },
            Err((code, message)) => AdminOutcome::Rejected { code, message },
        };
        let policy_epoch = self.policy_epoch;
        self.dedup.insert(
            request_id.to_string(),
            AdminRecord {
                request_hash: request_hash.to_string(),
                outcome: outcome.clone(),
                policy_epoch,
                raft_index,
                request_ts,
            },
        );
        self.prune_dedup(request_ts);

        PolicyResult::Admin {
            request_id: request_id.to_string(),
            policy_epoch,
            raft_index,
            duplicate: false,
            outcome,
        }
    }

    fn prune_dedup(&mut self, now: u64) {
        self.dedup
            .retain(|_, record| now.saturating_sub(record.request_ts) <= DEDUP_TTL_SECS);
        while self.dedup.len() > DEDUP_MAX_ENTRIES {
            let oldest = self
                .dedup
                .iter()
                .min_by_key(|(_, record)| record.raft_index)
                .map(|(key, _)| key.clone());
            match oldest {
                Some(key) => {
                    self.dedup.remove(&key);
                }
                None => break,
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn apply_inner(
        &mut self,
        cmd: &PolicyCommand,
    ) -> Result<(Option<String>, Option<u64>, bool), (String, String)> {
        match cmd {
            PolicyCommand::CreateService { service, members } => self
                .create_service(service, members)
                .map(|v| (Some(service.clone()), Some(v), true)),
            PolicyCommand::DeleteService { service } => {
                let tombstone = self.delete_service(service)?;
                Ok((Some(service.clone()), Some(tombstone), true))
            }
            PolicyCommand::AddMembers { service, peers } => {
                let (version, changed) = self.add_members(service, peers)?;
                Ok((Some(service.clone()), Some(version), changed))
            }
            PolicyCommand::RemoveMembers { service, peers } => {
                let (version, changed) = self.remove_members(service, peers)?;
                Ok((Some(service.clone()), Some(version), changed))
            }
            PolicyCommand::SetMembers { service, peers } => {
                let (version, changed) = self.set_members(service, peers)?;
                Ok((Some(service.clone()), Some(version), changed))
            }
            PolicyCommand::Admin { .. } => Err((
                "bad_command".into(),
                "nested Admin command is not allowed".into(),
            )),
            PolicyCommand::RenewIndex { expires_at } => {
                self.policy_epoch = self.policy_epoch.saturating_add(1);
                self.index_expires_at = *expires_at;
                Ok((None, None, true))
            }
            PolicyCommand::IssueJoinToken { token } => {
                self.issue_join_token(token)?;
                Ok((Some(token.jti.clone()), Some(token.expires_at), true))
            }
            PolicyCommand::ConsumeJoinToken {
                jti,
                node_id: _,
                peer_id,
                used_at,
            } => {
                self.consume_join_token(jti, peer_id, *used_at)?;
                Ok((Some(jti.clone()), None, true))
            }
        }
    }

    fn issue_join_token(
        &mut self,
        token: &super::types::JoinToken,
    ) -> Result<(), (String, String)> {
        if token.v != 1 {
            return Err((
                "join_token_bad_version".into(),
                format!("unsupported join token version: {}", token.v),
            ));
        }
        if token.jti.trim().is_empty() {
            return Err((
                "join_token_bad_jti".into(),
                "join token jti is empty".into(),
            ));
        }
        if token.max_uses == 0 {
            return Err((
                "join_token_bad_uses".into(),
                "join token max_uses must be positive".into(),
            ));
        }
        if token.network != self.network {
            return Err((
                "join_token_wrong_network".into(),
                format!(
                    "join token network {} does not match state network {}",
                    token.network, self.network
                ),
            ));
        }
        if self.join_tokens.contains_key(&token.jti) {
            return Err((
                "join_token_exists".into(),
                format!("join token jti already recorded: {}", token.jti),
            ));
        }
        self.join_tokens.insert(
            token.jti.clone(),
            StoredJoinToken {
                token: token.clone(),
                uses: 0,
            },
        );
        Ok(())
    }

    fn consume_join_token(
        &mut self,
        jti: &str,
        peer_id: &str,
        used_at: u64,
    ) -> Result<(), (String, String)> {
        let record = self.join_tokens.get_mut(jti).ok_or_else(|| {
            (
                "join_token_unknown".into(),
                format!("unknown join token: {jti}"),
            )
        })?;
        if record.uses >= record.token.max_uses {
            return Err((
                "join_token_replayed".into(),
                format!("join token already used: {jti}"),
            ));
        }
        if !record.token.bind_peer_id.is_empty() && record.token.bind_peer_id != peer_id {
            return Err((
                "join_token_wrong_peer".into(),
                format!("join token bound to a different peer: {jti}"),
            ));
        }
        if record.token.expires_at == 0 || used_at > record.token.expires_at {
            return Err((
                "join_token_expired".into(),
                format!("join token expired: {jti}"),
            ));
        }
        record.uses = record.uses.saturating_add(1);
        Ok(())
    }

    fn create_service(
        &mut self,
        service: &str,
        members: &[String],
    ) -> Result<u64, (String, String)> {
        if !is_valid_service_name(service) {
            return Err(("invalid_service".into(), format!("非法服务名: {service}")));
        }
        validate_peers(members)?;
        if self.services.contains_key(service) {
            return Err(("already_exists".into(), format!("服务已存在: {service}")));
        }
        self.services.insert(
            service.to_string(),
            ServiceState {
                version: 1,
                members: members.iter().cloned().collect(),
            },
        );
        self.policy_epoch = self.policy_epoch.saturating_add(1);
        Ok(1)
    }

    fn delete_service(&mut self, service: &str) -> Result<u64, (String, String)> {
        let removed = self
            .services
            .remove(service)
            .ok_or_else(|| ("not_found".to_string(), format!("服务不存在: {service}")))?;
        let tombstone = removed.version.saturating_add(1);
        self.tombstones.insert(service.to_string(), tombstone);
        self.policy_epoch = self.policy_epoch.saturating_add(1);
        Ok(tombstone)
    }

    fn add_members(
        &mut self,
        service: &str,
        peers: &[String],
    ) -> Result<(u64, bool), (String, String)> {
        validate_peers(peers)?;
        let state = self
            .services
            .get_mut(service)
            .ok_or_else(|| ("not_found".to_string(), format!("服务不存在: {service}")))?;
        let mut changed = false;
        for peer in peers {
            changed |= state.members.insert(peer.clone());
        }
        Ok(self.finish_change(service, changed))
    }

    fn remove_members(
        &mut self,
        service: &str,
        peers: &[String],
    ) -> Result<(u64, bool), (String, String)> {
        validate_peers(peers)?;
        let state = self
            .services
            .get_mut(service)
            .ok_or_else(|| ("not_found".to_string(), format!("服务不存在: {service}")))?;
        let mut changed = false;
        for peer in peers {
            changed |= state.members.remove(peer);
        }
        Ok(self.finish_change(service, changed))
    }

    fn set_members(
        &mut self,
        service: &str,
        peers: &[String],
    ) -> Result<(u64, bool), (String, String)> {
        validate_peers(peers)?;
        let incoming: BTreeSet<String> = peers.iter().cloned().collect();
        let state = self
            .services
            .get_mut(service)
            .ok_or_else(|| ("not_found".to_string(), format!("服务不存在: {service}")))?;
        let changed = state.members != incoming;
        if changed {
            state.members = incoming;
        }
        Ok(self.finish_change(service, changed))
    }

    fn finish_change(&mut self, service: &str, changed: bool) -> (u64, bool) {
        let state = self.services.get_mut(service).expect("service exists");
        if !changed {
            return (state.version, false);
        }
        state.version = state.version.saturating_add(1);
        self.policy_epoch = self.policy_epoch.saturating_add(1);
        (state.version, true)
    }

    #[allow(dead_code)]
    pub fn service_version(&self, service: &str) -> Option<u64> {
        self.services.get(service).map(|s| s.version)
    }

    #[allow(dead_code)]
    pub fn service_members(&self, service: &str) -> Option<Vec<String>> {
        self.services
            .get(service)
            .map(|s| s.members.iter().cloned().collect())
    }
}

fn validate_peers(peers: &[String]) -> Result<(), (String, String)> {
    for peer in peers {
        if !is_valid_peer_id(peer) {
            return Err(("invalid_peer".into(), format!("非法 PeerId: {peer}")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> String {
        libp2p_identity::PeerId::random().to_string()
    }

    #[test]
    fn create_is_deterministic_and_rejects_duplicate() {
        let mut a = PolicyState::new("myorg");
        let mut b = PolicyState::new("myorg");
        let p = peer();
        let cmd = PolicyCommand::CreateService {
            service: "cmd".into(),
            members: vec![p.clone()],
        };
        let ra = a.apply_command(&cmd);
        let rb = b.apply_command(&cmd);
        assert_eq!(ra, rb);
        assert_eq!(a, b);
        assert_eq!(a.policy_epoch, 2);
        assert_eq!(a.service_version("cmd"), Some(1));
        assert_eq!(a.service_members("cmd"), Some(vec![p]));

        let dup = a.apply_command(&cmd);
        assert!(matches!(
            dup,
            PolicyResult::Rejected { ref code, .. } if code == "already_exists"
        ));
        assert_eq!(a.policy_epoch, 2);
    }

    #[test]
    fn member_change_only_bumps_on_real_change() {
        let mut state = PolicyState::new("myorg");
        let p1 = peer();
        let p2 = peer();
        state.apply_command(&PolicyCommand::CreateService {
            service: "cmd".into(),
            members: vec![p1.clone()],
        });
        assert_eq!(state.policy_epoch, 2);

        let added = state.apply_command(&PolicyCommand::AddMembers {
            service: "cmd".into(),
            peers: vec![p2.clone()],
        });
        assert!(matches!(added, PolicyResult::Applied { changed: true, .. }));
        assert_eq!(state.policy_epoch, 3);
        assert_eq!(state.service_version("cmd"), Some(2));

        let again = state.apply_command(&PolicyCommand::AddMembers {
            service: "cmd".into(),
            peers: vec![p2.clone()],
        });
        assert!(matches!(
            again,
            PolicyResult::Applied { changed: false, .. }
        ));
        assert_eq!(state.policy_epoch, 3);
        assert_eq!(state.service_version("cmd"), Some(2));

        state.apply_command(&PolicyCommand::SetMembers {
            service: "cmd".into(),
            peers: vec![p1],
        });
        assert_eq!(state.policy_epoch, 4);
        assert_eq!(state.service_version("cmd"), Some(3));
    }

    #[test]
    fn delete_tombstone_and_epoch() {
        let mut state = PolicyState::new("myorg");
        state.apply_command(&PolicyCommand::CreateService {
            service: "cmd".into(),
            members: vec![],
        });
        let deleted = state.apply_command(&PolicyCommand::DeleteService {
            service: "cmd".into(),
        });
        assert!(matches!(
            deleted,
            PolicyResult::Applied {
                version: Some(2),
                ..
            }
        ));
        assert_eq!(state.tombstones.get("cmd"), Some(&2));
        assert_eq!(state.policy_epoch, 3);
        assert!(state.service_version("cmd").is_none());
    }

    #[test]
    fn renew_increments_exactly_once() {
        let mut state = PolicyState::new("myorg");
        let r = state.apply_command(&PolicyCommand::RenewIndex { expires_at: 100 });
        assert!(matches!(r, PolicyResult::Applied { changed: true, .. }));
        assert_eq!(state.policy_epoch, 2);
        assert_eq!(state.index_expires_at, 100);

        let r = state.apply_command(&PolicyCommand::RenewIndex { expires_at: 200 });
        assert!(matches!(r, PolicyResult::Applied { changed: true, .. }));
        assert_eq!(state.policy_epoch, 3);
        assert_eq!(state.index_expires_at, 200);
    }

    #[test]
    fn invalid_inputs_are_deterministic_rejections() {
        let mut state = PolicyState::new("myorg");
        let r1 = state.apply_command(&PolicyCommand::CreateService {
            service: "bad name".into(),
            members: vec![],
        });
        let r2 = state.apply_command(&PolicyCommand::CreateService {
            service: "bad name".into(),
            members: vec![],
        });
        assert_eq!(r1, r2);
        assert!(matches!(r1, PolicyResult::Rejected { .. }));
        assert_eq!(state.policy_epoch, 1);

        let r = state.apply_command(&PolicyCommand::AddMembers {
            service: "cmd".into(),
            peers: vec!["not-a-peer".into()],
        });
        assert!(matches!(
            r,
            PolicyResult::Rejected { ref code, .. } if code == "invalid_peer"
        ));
    }

    fn admin_cmd(request_id: &str, hash: &str, ts: u64, cmd: PolicyCommand) -> PolicyCommand {
        PolicyCommand::Admin {
            request_id: request_id.into(),
            kid: "root-1".into(),
            request_hash: hash.into(),
            request_ts: ts,
            command: Box::new(cmd),
        }
    }

    #[test]
    fn admin_request_is_idempotent() {
        let mut state = PolicyState::new("myorg");
        let cmd = admin_cmd(
            "req-1",
            "hash-1",
            1_000,
            PolicyCommand::CreateService {
                service: "cmd".into(),
                members: vec![peer()],
            },
        );
        let first = state.apply_command_at(&cmd, 5);
        let first_outcome = match &first {
            PolicyResult::Admin {
                outcome,
                duplicate,
                policy_epoch,
                raft_index,
                ..
            } => {
                assert!(!duplicate);
                assert_eq!(*policy_epoch, 2);
                assert_eq!(*raft_index, 5);
                outcome.clone()
            }
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(state.policy_epoch, 2);

        // 相同 request_id/内容、不同 log index：返回第一次结果，不重复 apply。
        let second = state.apply_command_at(&cmd, 9);
        match second {
            PolicyResult::Admin {
                outcome,
                duplicate,
                policy_epoch,
                raft_index,
                ..
            } => {
                assert!(duplicate);
                assert_eq!(outcome, first_outcome);
                assert_eq!(policy_epoch, 2);
                assert_eq!(raft_index, 5);
            }
            other => panic!("unexpected result: {other:?}"),
        }
        assert_eq!(state.policy_epoch, 2);
        assert_eq!(state.service_version("cmd"), Some(1));
    }

    #[test]
    fn admin_request_id_conflict_is_rejected_without_state_change() {
        let mut state = PolicyState::new("myorg");
        state.apply_command_at(
            &admin_cmd(
                "req-1",
                "hash-1",
                1_000,
                PolicyCommand::CreateService {
                    service: "cmd".into(),
                    members: vec![],
                },
            ),
            1,
        );

        let conflict = state.apply_command_at(
            &admin_cmd(
                "req-1",
                "hash-2",
                1_000,
                PolicyCommand::AddMembers {
                    service: "cmd".into(),
                    peers: vec![peer()],
                },
            ),
            2,
        );
        match conflict {
            PolicyResult::Admin {
                duplicate,
                policy_epoch,
                raft_index,
                outcome,
                ..
            } => {
                assert!(duplicate);
                assert_eq!(policy_epoch, 2);
                assert_eq!(raft_index, 2);
                assert!(matches!(
                    outcome,
                    AdminOutcome::Rejected { ref code, .. } if code == "request_id_conflict"
                ));
            }
            other => panic!("unexpected result: {other:?}"),
        }
        assert_eq!(state.policy_epoch, 2);
        assert_eq!(state.service_version("cmd"), Some(1));
    }

    #[test]
    fn admin_dedup_has_ttl_and_capacity() {
        let mut state = PolicyState::new("myorg");
        state.apply_command_at(
            &admin_cmd(
                "old",
                "h-old",
                1_000,
                PolicyCommand::RenewIndex { expires_at: 100 },
            ),
            1,
        );
        assert!(state.dedup.contains_key("old"));

        // 超过 TTL 后旧记录被清除（时间基准来自请求 ts，确定性）。
        state.apply_command_at(
            &admin_cmd(
                "new",
                "h-new",
                1_000 + DEDUP_TTL_SECS + 1,
                PolicyCommand::RenewIndex { expires_at: 100 },
            ),
            2,
        );
        assert!(!state.dedup.contains_key("old"));

        // 上限：直接灌满去重表，再 apply 一条，长度不超过上限。
        for i in 0..DEDUP_MAX_ENTRIES {
            state.dedup.insert(
                format!("filler-{i}"),
                AdminRecord {
                    request_hash: format!("h-{i}"),
                    outcome: AdminOutcome::Applied {
                        service: None,
                        version: None,
                        changed: false,
                    },
                    policy_epoch: state.policy_epoch,
                    raft_index: i as u64 + 10,
                    request_ts: 1_000 + DEDUP_TTL_SECS + 1,
                },
            );
        }
        let before = state.dedup.len();
        assert!(before >= DEDUP_MAX_ENTRIES);
        state.apply_command_at(
            &admin_cmd(
                "newest",
                "h-newest",
                1_000 + DEDUP_TTL_SECS + 1,
                PolicyCommand::RenewIndex { expires_at: 100 },
            ),
            u64::MAX,
        );
        assert_eq!(state.dedup.len(), DEDUP_MAX_ENTRIES);
        assert!(state.dedup.contains_key("newest"));
    }

    #[test]
    fn admin_dedup_survives_snapshot_round_trip() {
        let mut state = PolicyState::new("myorg");
        state.apply_command_at(
            &admin_cmd(
                "req-1",
                "hash-1",
                1_000,
                PolicyCommand::CreateService {
                    service: "cmd".into(),
                    members: vec![],
                },
            ),
            3,
        );
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&state, &mut buf).unwrap();
        let back: PolicyState = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back, state);
        assert!(back.dedup.contains_key("req-1"));
    }

    #[test]
    fn snapshot_conversion_preserves_state() {
        let mut state = PolicyState::new("myorg");
        state.apply_command(&PolicyCommand::CreateService {
            service: "cmd".into(),
            members: vec![peer()],
        });
        let snapshot = state.to_store_snapshot();
        let back = PolicyState::from_store_snapshot(snapshot);
        assert_eq!(back, state);
    }

    fn join_token(
        jti: &str,
        expires_at: u64,
        bind_peer_id: &str,
    ) -> super::super::types::JoinToken {
        super::super::types::JoinToken {
            v: 1,
            jti: jti.into(),
            cluster_id: "prod".into(),
            network: "myorg".into(),
            audience: "auth".into(),
            expires_at,
            max_uses: 1,
            bind_peer_id: bind_peer_id.into(),
            kid: "root-1".into(),
            sig: "sig".into(),
        }
    }

    fn issue(state: &mut PolicyState, token: super::super::types::JoinToken) -> PolicyResult {
        state.apply_command(&PolicyCommand::IssueJoinToken { token })
    }

    fn consume(state: &mut PolicyState, jti: &str, peer_id: &str, used_at: u64) -> PolicyResult {
        state.apply_command(&PolicyCommand::ConsumeJoinToken {
            jti: jti.into(),
            node_id: 2,
            peer_id: peer_id.into(),
            used_at,
        })
    }

    #[test]
    fn join_token_is_one_time_and_persisted_in_snapshot() {
        let mut state = PolicyState::new("myorg");
        assert!(matches!(
            issue(&mut state, join_token("jti-1", 2_000, "")),
            PolicyResult::Applied { changed: true, .. }
        ));
        assert!(state.join_tokens.contains_key("jti-1"));

        assert!(matches!(
            consume(&mut state, "jti-1", "peer-a", 1_000),
            PolicyResult::Applied { changed: true, .. }
        ));
        let replay = consume(&mut state, "jti-1", "peer-a", 1_001);
        assert!(matches!(
            replay,
            PolicyResult::Rejected { ref code, .. } if code == "join_token_replayed"
        ));

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&state, &mut buf).unwrap();
        let back: PolicyState = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back.join_tokens, state.join_tokens);
    }

    #[test]
    fn join_token_expiry_and_peer_binding_rejected() {
        let mut state = PolicyState::new("myorg");
        issue(&mut state, join_token("jti-exp", 1_500, ""));
        assert!(matches!(
            consume(&mut state, "jti-exp", "peer-a", 1_501),
            PolicyResult::Rejected { ref code, .. } if code == "join_token_expired"
        ));

        issue(&mut state, join_token("jti-bind", 2_000, "peer-b"));
        assert!(matches!(
            consume(&mut state, "jti-bind", "peer-a", 1_000),
            PolicyResult::Rejected { ref code, .. } if code == "join_token_wrong_peer"
        ));
    }

    #[test]
    fn join_token_rejects_duplicate_and_wrong_network() {
        let mut state = PolicyState::new("myorg");
        issue(&mut state, join_token("jti-dup", 2_000, ""));
        assert!(matches!(
            issue(&mut state, join_token("jti-dup", 2_000, "")),
            PolicyResult::Rejected { ref code, .. } if code == "join_token_exists"
        ));

        let mut wrong = join_token("jti-net", 2_000, "");
        wrong.network = "other".into();
        assert!(matches!(
            issue(&mut state, wrong),
            PolicyResult::Rejected { ref code, .. } if code == "join_token_wrong_network"
        ));
    }
}
