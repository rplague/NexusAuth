# 管理指令与管理员工具

NexusAuth 通过 NexusNet 的「后端协议 v2」接收管理指令：节点把入站 `request` 的 `payload` 原样转发给边车，边车返回 `reply.result`。**每条指令都必须携带 `mac`**（证明持有管理口令，请求中不含明文口令）。

## 1. 指令格式

```json
{
  "op": "add_members",
  "service": "ocr",
  "peers": ["12D3KooW..."],
  "nonce": "<base64url 16B>",
  "ts": 1700000000,
  "mac": "<base64url>"
}
```

- `op`：见下表。
- `service`：目标服务名（`status` / `publish_now` 等无需）。
- `peers`：成员 PeerId 列表（成员类指令使用，顺序无关）。
- `nonce`：随机 16 字节，base64url **无填充**；单次有效（防重放）。
- `ts`：Unix 秒；与接收端偏差 ≤ **300s**。
- `mac`：见第 2 节。

## 2. `mac` 计算

```
K_mac = HKDF-SHA256(ikm = management_password, salt = "nexusauth/mgmt", info = network, L = 32)
mac   = HMAC-SHA256(K_mac, json({op, service, peers 排序, nonce, ts}))   # base64url 无填充
```

规范 JSON 要求（务必逐字节一致）：

- 字段顺序固定：`op, service, peers, nonce, ts`；
- 无多余空格（`separators=(",", ":")`）；
- `peers` 升序排序；
- UTF-8，不转义非 ASCII（`ensure_ascii=False`）。

### Python 参考实现

```python
import json, hmac, hashlib, base64, os, time

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length=32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def make_command(password: str, network: str, op: str,
                 service: str = "", peers=None, ts=None) -> bytes:
    peers = sorted(peers or [])
    ts = ts or int(time.time())
    nonce = b64url(os.urandom(16))
    key = hkdf_sha256(password.encode(), b"nexusauth/mgmt", network.encode(), 32)
    body = json.dumps(
        {"op": op, "service": service, "peers": peers, "nonce": nonce, "ts": ts},
        separators=(",", ":"), ensure_ascii=False,
    ).encode()
    mac = b64url(hmac.new(key, body, hashlib.sha256).digest())
    return json.dumps(
        {"op": op, "service": service, "peers": peers,
         "nonce": nonce, "ts": ts, "mac": mac},
        separators=(",", ":"), ensure_ascii=False,
    ).encode()

# 例：给 ocr 增加成员
payload = make_command("口令", "myorg", "add_members", "ocr", ["12D3KooW..."])
```

## 3. 指令列表

| op | 参数 | 说明 | `reply.result`（JSON） |
|---|---|---|---|
| `status` | — | 网络 / 公钥 / 索引版本 / 各服务版本与成员数 / 连接数 / 运行时长 | `{network, authority_public_key, index_version, services:{name:{version,members}}, expires_secs, renew_secs, connections, uptime_secs}` |
| `export_authority_pubkey` | — | 返回权威公钥 | `{network, public_key}` |
| `list_services` | — | 服务名列表 | `{services:[tstr]}` |
| `list_members` | `service` | 成员与版本 | `{service, version, members:[tstr]}` |
| `add_members` | `service`, `peers` | 增加成员 | `{service, version, members, index_version}` |
| `remove_members` | `service`, `peers` | 移除成员 | 同上 |
| `set_members` | `service`, `peers` | 整体替换 | 同上 |
| `create_service` | `service`, `peers?` | 新建服务 | 同上 |
| `delete_service` | `service` | 删除服务 | `{service, index_version}` |
| `publish_now` | — | 立即触发一次发布 | `{scheduled:true}` |

成员增删仅在**真正变化**时提升版本；任何变更都会触发一次重签发布，并广播给其他边车。

## 4. 如何把指令送进去

管理指令必须经某个 **NexusNet 后端**调用服务的方式送达：

1. 自备一个「管理工具边车」（同样基于 `NexusService_Template`，在某个节点登记为 `local_services`，如 `name = "authctl"`）。
2. 它收到运维输入后，用第 2 节算法算出 `mac`，然后调用控制指令：
   - `client.service_request_to("auth", "<某边车节点 PeerId>", payload)`（指定对端），或
   - `client.service_request("auth", payload)`（自动选一个 `auth` 提供者；因状态已复制，选谁都行）。

> `auth` 是边车在节点侧登记的服务名（`local_services[].name`），须与边车 `join_service` 一致。

## 5. 错误码

`reply.ok = false` 时 `reply.error` 为 `{code, message}`：

| code | 含义 |
|---|---|
| `bad_request` | 请求解析失败 / 缺少 `op`/`service` |
| `bad_mac` | `mac` 非法或不匹配 |
| `expired_timestamp` | `ts` 超出 ±300s |
| `replay` | `nonce` 重放 |
| `invalid_service` / `invalid_peer` | 服务名非法 / PeerId 非法 |
| `not_found` / `already_exists` | 服务不存在 / 已存在 |
| `unknown_op` | 未知 `op` |
| `joining` | 边车尚未就绪（入网中） |

## 6. 约束与注意

- 时间戳偏差 ≤ 300s；`nonce` 单次有效。
- 请求**不含明文口令**；口令仅用于本地计算 `mac`。
- `service` 不得为保留名 `service`。
- 撤销成员依赖索引过期与缓存 TTL；不续发即失效。
