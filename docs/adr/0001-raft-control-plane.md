# ADR 0001：Raft 单写者控制面

- 状态：已接受（Phase 1 骨架）
- 日期：2026-10-26
- 决策范围：NexusAuth 控制面选主与策略状态复制

## 背景

现有多边车模型允许所有实例写成员状态并发布 DHT，通过 LWW + 墓碑 + 规范哈希收敛。
该模型可用，但 `index_version` 会由各实例独立递增，且没有全局唯一 writer。目标是用
Raft 选主，让 leader 成为唯一 writer/publisher，其余 sidecar 作为 learner/read replica。

## 决策

### 1. Raft 库与版本

使用 **openraft 0.9.25**（crate `openraft = "0.9.25"`，启用 `serde`、`storage-v2`），
持久化使用 **redb 2.6.4**。均锁定到 `Cargo.lock`。选择 0.9.x 稳定线；不使用 0.10 alpha，
也不换 raft-rs。Spike 结论：openraft 0.9 的 `RaftLogStorage` / `RaftStateMachine` /
`RaftNetwork` / `RaftNetworkFactory` 与当前 edition/deps 兼容，编译通过。

### 2. NexusNet transport

不新增 sidecar 监听端口。Raft RPC 复用：

```text
BackendClient::service_request_to("auth", peer, payload)
```

新增 `service_request_to_with_timeout(...)`，Raft 使用 heartbeat 量级的短超时
（默认 `heartbeat_interval_ms * 4`，夹在 200ms..10s），避免沿用控制指令的 60 秒超时。

payload 是 JSON envelope：

```text
RaftRpcEnvelope {
  op: "raft_rpc",
  cluster_id, from: NodeId, to: NodeId,
  body: base64url(CBOR(Vote | AppendEntries | InstallSnapshot)),
  signature: base64url(Ed25519)
}
```

请求与响应都签名。签名覆盖 `cluster_id + from + to + body`（响应还覆盖 ok/error）。
接收方用 `[cluster].voters/learners` 中登记的公钥验签，并校验 cluster 与目标 NodeId。
`raft_rpc` 在 `service.rs` 中先于管理员认证被识别，永远不会进入管理员 MAC 路径。

### 3. voter / learner

- 3 个 voter 组成选举与提交 quorum。
- 其他 sidecar 为 learner/read replica；learner 不参与投票，也不持有 authority seed。
- voter 才持有 authority seed（Phase 1 尚未实现 seed 分发）。
- 成员信息 `RaftNode { peer_id, identity_key }` 随 Raft membership 复制；网络层据此寻址与验签。
- `bootstrap = true` 时按 `[cluster].voters` 初始化；为空则单节点自举。

### 4. epoch / fencing

旧 `index_version` 在 Raft 模式改名为全局 **`policy_epoch`**：

- 只由 `PolicyState` 的 apply 推进（Create/Delete/Add/Remove/Set/RenewIndex）。
- 无实际变化的成员操作不推进 epoch。
- `RenewIndex` 每次 apply 只推进一次。
- epoch 持久化在 redb 的 state machine 中，并进入快照。
- leader 发布时使用 state machine 的 epoch；非 leader 不发布。
- 旧多写者路径保留但 Raft 模式下不启动反熵循环，管理变更也不再广播 replicate。

### 5. 持久化

单个 redb 数据库保存：

- Raft log（index → CBOR Entry）
- vote / last_purged / committed
- applied LogId / membership
- 确定性策略状态
- 当前快照 meta + data

`append`、`save_vote`、`apply`、`install_snapshot` 都在返回前提交 redb 事务。
`apply` 失败返回 `StorageError`，不会吞掉持久化错误，也不会先更新内存。

### 6. 默认关闭

`[cluster].enabled = false` 默认。关闭时完全保留旧多写者行为、现有测试与部署语义不变。
启用后 Raft 只在拿到 `whoami` PeerId 的连接上下文后启动。

## 本阶段边界

已实现：

- openraft 0.9.25 编译 spike、log/vote/snapshot/state machine 存储
- 确定性策略状态机与 3 节点选主/复制/leader 故障重选/快照重启测试
- sidecar Ed25519 RPC 签名与篡改拒绝
- `[cluster]` 配置、单节点 bootstrap、learner 添加基础函数

明确未实现：

- 管理员 viewer/root Ed25519 请求与 edge → leader 转发（Phase 2）
- join token / seed 分发（Phase 4）
- 删除旧 replicate 路径
- HSM、用户身份、scope
- admin 写请求真正写入 Raft log（当前仅 leader gate）

## 后续风险

1. **管理面尚未 Raft 化**：Raft 启用时写指令只允许 leader，但仍直接修改旧 `Store`；
   与 state machine 的 `PolicyState` 可能在管理变更后分叉。Phase 2 必须把 admin 写
   转成 `PolicyCommand` 并等待 apply 后再更新可见状态。
2. **发布内容仍来自旧 Store**：Phase 1 只把 `policy_epoch` 与 Raft 对齐，DHT 记录的
   服务成员仍由旧 Store 生成。Phase 2 应让 leader 从 state machine 构造发布快照。
3. **静态成员表**：RPC 验签公钥来自配置，动态加入/移除成员后需要同步更新 verifier；
   否则新 voter 的 RPC 会被拒绝。
4. **无迁移**：按任务要求允许重新初始化，不做旧多写者状态迁移。
5. **快照传输**：使用 openraft 默认 chunked snapshot；尚未做超大快照/限流压测。
6. **单写者范围**：lease/read-index 尚未接入 DHT 读取路径；本阶段只保证 leader 发布。
