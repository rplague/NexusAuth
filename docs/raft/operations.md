# Raft 控制面运维手册（Phase 5）

本文覆盖 3 voter 部署、日常 CLI、status/审计、备份恢复、重初始化与安全加固。
实现边界：不做 HSM、离线 root、委派 signer、用户身份/scope，也不修改 NexusNet。

## 1. 部署前准备

### 1.1 管理员密钥（只在管理员侧）

在受控工作站生成 root/viewer 私钥。边车只接收公钥片段：

```bash
nexusauthctl keygen --role root --kid root-2026 --out-dir ./admin-keys
nexusauthctl keygen --role viewer --kid viewer-2026 --out-dir ./admin-keys
```

- 私钥：`admin-keys/<kid>.key`，`0600`，离线保存，不复制到边车。
- 公钥片段：`admin-keys/<kid>.pub.toml`，加入边车 `config.toml` 的 `[admin.keys]`。
- CLI 默认读取 `./admin.key`；生产建议显式传 `--key` 或设置 `NEXUSAUTH_CTL_KEY`。
- root 私钥丢失时用另一把 root 轮换；没有可用 root 只能重建管理面。

### 1.2 3 voter 配置

三台 voter 使用相同的 `cluster_id`、`network`、顶层 `service` 与 `[admin.keys]`。不再配置 `node_id`：NodeId 由 NexusNet PeerId 稳定派生。

```toml
service = "auth"                 # 必须与 NexusNet local_services[].name 一致
network = "myorg"
port = 5100

[cluster]
enabled = true
cluster_id = "prod-auth"
bootstrap = true            # 仅第一台首次启动为 true
heartbeat_interval_ms = 500
election_timeout_min_ms = 3000
election_timeout_max_ms = 6000

[[cluster.voters]]
peer_id = "12D3KooW..."
identity_key = "<base64 ed25519 公钥>"

[[cluster.voters]]
peer_id = "12D3KooW..."
identity_key = "<base64 ed25519 公钥>"

[[cluster.voters]]
peer_id = "12D3KooW..."
identity_key = "<base64 ed25519 公钥>"
```

规则：

- voter 数量保持奇数：3 或 5；quorum 分别为 2 或 3。
- 只有 voter 持有 `authority.key`；learner 的 seed 由 leader 在提升时通过
  X25519 + AEAD 加密分发。
- 配置中不写 NodeId。内部 `NodeId` 仍为 `u64`，算法为 `SHA-256(PeerId)` 前 8 字节按大端解释，结果为 0 时取 1；本节点由 `whoami` PeerId 派生，voter/learner 由其 `peer_id` 派生。所有派生 NodeId 必须唯一且非 0。
- PeerId 或 identity key 改变视为新节点；`identity_key_path`、`data_path`、`authority.key` 必须位于持久目录。
- 所有 sidecar 的 `cluster_id` 与顶层 `service` 必须一致。
- `renew_secs < expires_secs`，否则 Raft 管理面 fail-closed 拒绝启动。

### 1.3 初始 3 voter 顺序

1. 在三台 voter 上离线部署同一份新 `authority.key`（`0600`）。
2. 写入管理员公钥、成员表和 `cluster` 配置。
3. **只让第一台** `bootstrap = true` 启动，确认它成为单节点 leader。
4. 第二、三台配置 `bootstrap = false`，作为 learner 启动。
5. 用 root 签发一次性 join token，让新节点加入：

   ```bash
   nexusauthctl issue-join-token \
     --audience 12D3KooW目标节点PeerId \
     --bind-peer 12D3KooW目标节点PeerId \
     --expires-in 600 --json
   ```

   把返回的 token 写入目标节点的 `[cluster].join_token_path`（权限 `0600`）。

6. learner 追平快照后提升为 voter：

   ```bash
   nexusauthctl promote-voter --peer-id 12D3KooW... --json
   nexusauthctl promote-voter --peer-id 12D3KooW... --json
   ```

   提升前请确认 `status` 中 learner 已出现且 leader 正常。提升时 leader 会先加密
   分发 authority seed，再做 Raft 成员变更。

7. 更新所有 NexusNet 节点的 `auth.networks.<network>.authority` 为新权威公钥，
   重启对应节点。NexusAuth 仍作为 `require_auth = false` 的本地服务，不改
   NexusNet 的 fail-open 语义。
8. 验证发布、发现、鉴权放行/拒绝与 epoch。

### 1.4 日常成员命令

```bash
# 服务成员（策略状态，写入 Raft）
nexusauthctl add-members --service ocr --peer 12D3KooW... --peer 12D3KooW...
nexusauthctl remove-members --service ocr --peer 12D3KooW...

# 集群成员
nexusauthctl promote-voter --peer-id 12D3KooW... --json
nexusauthctl demote-voter --peer-id 12D3KooW... --json

# 立即触发 leader 发布
nexusauthctl publish-now --json
```

- 任意 sidecar 可接收请求；root 写请求由 edge 验签后转发给 leader，leader 二次验签。
- 所有写命令自动生成 UUID `request_id`；失败重试时请复用 `--request-id`。
  CLI 对传输失败会用新 nonce/ts 自动重试一次，Raft 侧按 `request_id` 幂等。
- `--dry-run` 只输出签名后的请求，不发送写操作。

## 2. status 与可观测性

```bash
nexusauthctl status --key ./admin-keys/viewer-2026.key --kid viewer-2026 --json
```

关键字段：

| 字段 | 含义 |
|---|---|
| `cluster_id` / `node_id` | 当前节点归属；`node_id` 是内部派生值，不是配置项 |
| `leader` / `term` / `state` | 当前 leader PeerId、任期、节点状态 |
| `applied_index` / `last_log_index` | 已应用与本地最后日志索引 |
| `policy_epoch` / `index_version` | 全局策略 epoch |
| `last_publish_epoch/ok/error/at` | 最近一次发布结果 |
| `voters` / `learners` | 成员 PeerId 与派生 `node_id`（不可配置） |
| `authority_seed_present` | 是否持有 seed；**永不输出 seed 本身** |
| `health` | `ok` / `stale` / `no_leader` |
| `stale` | 本地 applied 落后或没有 leader |

审计日志为单行 key=value（journald 模式）：

```text
event=admin_op mode=raft kid=... request_id=... op=... service=... result=... \
epoch=... policy_epoch=... raft_index=... leader=... edge_peer=...
```

- edge 转发记录 `result=forwarded`，leader 执行记录同一 `request_id`；用
  `journalctl -u nexusauth | rg 'request_id=<ID>'` 串联两端。
- 不记录 authority seed、管理员私钥或完整 nonce。
- `raft_join`、`add_learner`、`promote_voter`、`demote_voter`、`remove_member`
  也写审计，便于定位成员变更。

## 3. 备份

在 voter 上以运行用户执行（默认读取 `config.toml` 中的路径）：

```bash
nexusauthctl backup --config /etc/nexusauth/config.toml \
  --out /var/backups/nexusauth/$(date +%Y%m%dT%H%M%S) --json
```

备份目录布局（目录 `0700`，文件 `0600`）：

```text
<out>/
  manifest.json          # schema、时间、network/cluster、sha256、权限、skipped
  config.toml            # 含 [cluster] 与 [admin.keys] 公钥
  authority.key          # voter 的 authority seed（cluster 模式必需）
  auth_state.toml        # 旧兼容状态（存在时）
  raft.redb              # Raft 日志/状态机/快照（data_path 为文件时）
  raft_data/             # data_path 为目录时递归复制
  raft_identity.key      # sidecar Ed25519 身份私钥
  raft_seed_exchange.key # X25519 seed 交换私钥
```

必须另行离线备份：

- 管理员 root/viewer 私钥。
- NexusNet 的 `auth.networks.<network>.authority` 配置。
- 审计日志与部署配置版本。

`manifest.json` 明确 `admin_private_keys_included=false`；不要手工把管理员私钥放进边车备份。

## 4. 恢复与重初始化

### 4.1 单节点故障（quorum 仍在）

1. 停止故障节点。
2. 用同一 PeerId、同一 identity key、同一数据目录和 authority key 恢复文件。
3. 校验权限：密钥/数据 `0600`，目录 `0700`。
4. 启动并检查 `status`：leader、term、applied_index、policy_epoch、发布状态。
5. 若该节点曾是 voter，确认 quorum 未受影响；必要时用 `promote-voter` 重新加入。

### 4.2 quorum 丢失（无法恢复旧日志）

按重新初始化处理，不强行拼接旧 Raft 日志：

1. 停止所有旧 sidecar 发布（或切为只读/下线）。
2. 备份旧 authority、state、Raft 数据、配置与审计。
3. 生成新 authority key，替换所有 voter 的 `authority.key`（`0600`）。
4. 清空 Raft 数据目录/redb（旧日志与快照不迁移）。
5. 按 §1.2/§1.3 重新 bootstrap 3 voter，先 learner 再提升。
6. 更新所有 NexusNet 节点的 authority 公钥并重启。
7. 验证发布、发现、鉴权放行/拒绝、epoch 单调。
8. 旧 DHT 记录等待过期；如仍冲突，使用新 `network` 名。

### 4.3 管理员 key 丢失

- 还有另一把 root：用它签发新的 `[admin.keys]` 配置并滚动重启；
- 没有 root：重建管理面（重新生成 root 公钥并更新配置），按安全事件处理。

## 5. 安全加固

- `authority.key`、`raft_identity.key`、`raft_seed_exchange.key`、`raft.redb`：
  `0600`；Raft 数据目录 `0700`。
- 启动时会审计敏感路径权限，发现 group/other 可读写会输出 `文件权限过宽` 告警，
  不自动改权限。
- systemd 单元使用 `UMask=0077`、`ProtectSystem=strict`、`PrivateTmp` 等限制；
  只允许写 `/etc/<pkg>` 与 `/var/lib/<pkg>`。
- 评估使用独立系统账号，不要与 NexusNet 共用高权限账号。
- root 私钥离线保存；voter 数量最小化；learner 不持有 seed。
- 日志与 status 不输出 seed/私钥/完整 nonce。
- NexusNet 仅保存 authority 公钥；NexusAuth 不修改 NexusNet 代码或 DHT 协议。

## 6. 升级与演练

升级顺序：learner → follower → leader。升级前先做一次备份并确认 quorum。

> **0.2.2 是破坏性配置变更**：旧 `join_service`、`join_peers`、`[cluster].service`、`[cluster].node_id` 以及 voter/learner 的 `node_id` 都会被明确拒绝。升级前必须把配置重写为顶层 `service` + `peer_id` 形式；成员命令只接受 `--peer-id`，`--node-id` 不再接受。没有旧 Raft 数据，因此不做旧日志迁移。

检查项：

```bash
nexusauthctl status --json
nexusauthctl publish-now --json
```

故障演练清单：

- kill leader / follower，确认重新选主与发布；
- 网络分区后旧 leader 恢复，确认不能覆盖新 epoch；
- 快照安装、磁盘满/redb 写失败；
- join token 过期、audience 错误、jti 重放；
- 管理员 key 轮换与权限告警；
- NexusNet 重启后 sidecar 重连。

大版本或旧多写者状态切换使用重新初始化流程，不做旧日志迁移。
