# 从零建立 NexusNet 鉴权网络

本指南介绍如何用 **NexusNet 节点**、**NexusAuth 权威边车**与**业务后端**搭起一套鉴权网络，并用管理指令维护白名单。

- 管理指令与 `mac` 计算见 [`admin.md`](./admin.md)。
- 记录格式与验证算法见 NexusNet 的 `docs/auth.md`。

## 1. 角色与信任模型

- **NexusAuth** 持有权威 ed25519 私钥 `K_auth`，签名「服务 → 允许的 PeerId 白名单」并写入 DHT。
- **NexusNet 节点** 只配置权威**公钥**；收到服务请求时按「DHT 为准 + fail-closed」判定：索引/白名单缺失、过期或验签失败一律拒绝。
- 所有节点必须在**同一个 P2P 网络**（通过 bootstrap 互相连通）。
- 一个鉴权网络用一个 `network` 名（如 `myorg`）标识；所有节点与边车配同一个名字。
- 边车与节点通过本地回环 TCP 的「后端协议 v2」通信；边车在 NexusNet 里登记为一个 `require_auth = false` 的本地服务（避免循环鉴权）。

```
业务后端 ──本地──▶ NexusNet 节点 ◀──P2P/DHT──▶ 其他节点 ◀──本地── NexusAuth 边车
   (require_auth)         ▲                                          │
                          └──────── 本地 TCP（后端协议 v2）───────────┘
```

## 2. 前置准备

1. **编译 / 安装**（Debian 系可用 `.deb`）：

   ```bash
   apt install -y ./nexusnet_<ver>_amd64.deb
   apt install -y ./nexusauth_<ver>_amd64.deb
   ```

   或开发模式 `cargo run`（读取当前目录的 `config.toml`）。

2. **规划取值**：
   - 网络名 `network = "myorg"`
   - **高熵管理口令**（`management_password`）
   - 端口：节点 P2P 端口（默认 5000）、边车端口（默认 5100）、业务端口

3. **连通性**：所有节点能互相访问 P2P 端口；至少一个节点作为 bootstrap 点。

4. **文件落位**（deb 安装）：
   - 节点：`/etc/nexusnet/config.toml`、`/var/lib/nexusnet/keypair.bin`
   - 边车：`/etc/nexusauth/config.toml`、`/var/lib/nexusauth/{authority.key,auth_state.toml}`

## 3. 第一个节点：初始化权威（`init`）

### 3.1 先起 NexusAuth

`/etc/nexusauth/config.toml`：

```toml
port = 5100
network = "myorg"
join_mode = "init"                 # 首个节点：生成新权威密钥
management_password = "<高熵口令>"
expires_secs = 3600
renew_secs = 1200

[services.cmd]                     # 可在此预置要鉴权的服务（也可稍后用管理指令建）
members = []
```

启动后日志会打印**权威公钥**：

```
[IMPORTANT] 权威公钥
    <base64 32B 公钥>（填入 NexusNet auth.networks.myorg.authority）
```

同时生成 `/var/lib/nexusauth/authority.key`（`0600`，**不可丢**）。

### 3.2 再起 NexusNet

`/etc/nexusnet/config.toml`：

```toml
[node]
name = "node-a"
allow_bootstrap = true

[network]
port = 5000
ipv4_enabled = true
# ipv4_address = "1.2.3.4"        # 可选；不设则自动探测

[services.kademlia]
bootstrap_nodes = []              # 首个节点留空

[auth]
network = "myorg"                 # 与边车一致
cache_ttl_secs = 300
refresh_interval_secs = 60

[auth.networks.myorg]
authority = "<NexusAuth 打印的公钥>"

[[services.dispatcher.local_services]]
name = "auth"                     # 边车服务名（不能是保留名 "service"）
host = "127.0.0.1"
port = 5100                       # 与边车 config.port 一致
require_auth = false              # 权威自身不参与鉴权
```

启动 NexusNet：它会主动拨入边车，边车随即发布（空的）白名单与索引到 DHT。

> 顺序：**先起 NexusAuth，再起 NexusNet**（节点启动时会拨后端）。

## 4. 加入更多节点（`require`）

新机器上：

`/etc/nexusauth/config.toml`：

```toml
port = 5100
network = "myorg"
join_mode = "require"             # 默认：必须从在线边车入网
management_password = "<同一口令>"
join_service = "auth"             # 用于发现与寻址对端
# join_peers = ["<node-a 的 PeerId>"]   # 可选兜底
join_timeout_secs = 120           # 视网络就绪速度调整
```

`/etc/nexusnet/config.toml`：与节点 A 基本相同，但

```toml
[node]
name = "node-b"

[services.kademlia]
bootstrap_nodes = ["/ip4/<node-a-ip>/tcp/5000/p2p/<node-a-peerid>"]
```

启动顺序：

1. 起 **NexusAuth**（开始监听）。
2. 起 **NexusNet**（拨入边车；并 bootstrap 到 node-a 接入 P2P）。
3. 边车借这条连接执行入网：`discover_providers("auth")` 发现已有边车、`whoami` 排除自身（候选以配置的 `join_peers` 优先）→ 单轮口令证明 → 取回 `K_auth` 与状态快照 → 持久化 → 开始发布。
   - 入网需要节点已完成 bootstrap 且能到达对端；失败会按 `join_retry_secs` 重试，直到 `join_timeout_secs`。
   - 成功日志：`入网成功 从 <peer> 取回权威密钥与状态`。
   - 失败且超时 → `require` 模式会 `[CRITICAL]` 退出（fail-closed）。
4. 验证：`/var/lib/nexusauth/authority.key` 与 `auth_state.toml` 生成；日志出现「鉴权网络就绪」。

> 每个节点的 `[auth.networks.myorg].authority` 必须是**同一把公钥**（首个边车打印的那把）。

## 5. 注册需要鉴权的业务服务

以 `ocr` 为例：

1. **业务后端**：用 `NexusService_Template` 派生，实现 `service.rs`，监听某端口（如 5110）。
2. **在 NexusNet 登记该后端并开启鉴权**：

   ```toml
   [[services.dispatcher.local_services]]
   name = "ocr"
   host = "127.0.0.1"
   port = 5110
   require_auth = true
   ```

3. **在鉴权网络里创建该服务并设白名单**（管理指令见 [`admin.md`](./admin.md)）：

   ```json
   { "op": "create_service", "service": "ocr", "peers": ["<允许的 PeerId>"], "...": "..." }
   ```

4. 边车重签并发布白名单/索引；节点后台刷新缓存后开始强制鉴权。

> ⚠️ **顺序很重要**：先让服务进入**鉴权索引**（`create_service` / `add_members`），再确保 `require_auth = true`。否则节点的判定是「服务不在索引 → 放行并自动把 `require_auth` 同步为 `false`」（DHT 为准）。索引里已有该服务后，白名单才真正生效。

## 6. 验证与排障

- 边车日志：`journalctl -u nexusauth -f` —— 看「权威公钥 / 鉴权网络就绪 / 入网成功 / 发布失败 / 管理指令」。
- 节点日志：`journalctl -u nexusnet -f` —— 看「后端连接建立 / 已注册服务 / 鉴权拒绝 / 鉴权网络同步」。
- 状态查询：
  - 向边车发管理指令 `status` → 网络、公钥、索引版本、各服务版本与成员数、连接数。
  - NexusNet 控制指令 `auth_status`（需后端/管理工具发起）→ 节点的鉴权状态与缓存。

常见问题：

| 现象 | 排查 |
|---|---|
| 入网超时 | 节点未 bootstrap 或对端不可达；检查 `bootstrap_nodes`、P2P 端口、`join_timeout_secs` |
| `require_auth` 被自动置回 false | 该服务还没进鉴权索引（见第 5 节顺序） |
| `auth index unavailable` / 请求被拒 | 节点还没刷新到索引/白名单，或边车未发布；查边车发布日志与 `expires_secs`/`renew_secs` |
| 权威公钥不一致 | 各节点 `authority` 必须完全相同 |
| 服务名冲突 | 边车服务名不能用保留名 `service` |

## 7. 多边车与容灾

- 同网络可跑多个边车；成员变更会**广播复制**，并周期性**反熵同步**。
- **无选主**：所有边车都可发布，任一存活边车续期即可维持 DHT 记录，故**故障接管天然成立**；并发/乱序用确定性合并收敛（删除胜出、成员规范哈希择大、索引版本取 max）。
- 把边车部署在**不同节点/机器**上可提升可用性。

## 8. 安全清单

- 管理口令必须**高熵**（入网/复制协议不抗离线口令爆破）。
- `authority.key` 权限 `0600`，**务必备份**（丢失即换权威，全网需改公钥）。
- 默认边车与节点共用 `nexusnet` 账号：同账号进程可读 `authority.key`；如需隔离请改独立账号。
- 控制 `expires_secs`（索引有效期）与 `renew_secs`（续期间隔），并让节点 `cache_ttl_secs` 小于索引有效期。
- 撤销成员依赖索引过期与缓存 TTL：不续发即失效，撤销延迟 ≈ `cache_ttl_secs`。

## 9. 最小端到端清单

1. **node-a**：NexusAuth `init` 起 → 抄公钥 → NexusNet 配 `myorg` + 公钥 + `auth` 服务 → 起。
2. **node-b**：NexusAuth `require` 起 → NexusNet 配同公钥 + `auth` + bootstrap 指 node-a → 起 → 确认入网成功。
3. 业务后端 `ocr` 注册为 `require_auth = true`。
4. 管理工具发 `create_service ocr peers=[...]`（索引生效后再确保 `require_auth=true`）。
5. 用 `auth_status` / 边车 `status` 验证；让一个非白名单节点调用 `ocr` 应被拒。
