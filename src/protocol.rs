use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

/// 协议版本
pub const PROTOCOL_VERSION: u32 = 2;
/// 单帧上限（含 CBOR 载荷）
pub const MAX_FRAME: usize = 16 << 20;

/// 结构化错误
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SidecarError {
    pub code: String,
    pub message: String,
}

impl SidecarError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// 协议消息，判别字段为文本 `t`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Message {
    /// 握手
    Hello { version: u32 },
    /// 节点 -> 后端：转发入站服务请求
    Request {
        id: Uuid,
        service: String,
        payload: Vec<u8>,
    },
    /// 关联回复
    Reply {
        id: Uuid,
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Vec<u8>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<SidecarError>,
    },
    /// 后端 -> 节点：列出全局服务类型
    ListServices { id: Uuid },
    /// 后端 -> 节点：查询某服务的提供者
    DiscoverProviders { id: Uuid, service: String },
    /// 后端 -> 节点：查询本节点公网地址
    QueryPublicIp { id: Uuid },
    /// 后端 -> 节点：查询本节点 PeerId
    Whoami { id: Uuid },
    /// 后端 -> 节点：重新拨号 bootstrap
    ReconnectBootstrap { id: Uuid },
    /// 后端 -> 节点：重新宣告本地服务
    ReannounceServices { id: Uuid },
    /// 后端 -> 节点：重载配置
    ReloadConfig { id: Uuid },
    /// 后端 -> 节点：中继状态
    RelayStatus { id: Uuid },
    /// 后端 -> 节点：抗量子状态
    PqStatus { id: Uuid },
    /// 后端 -> 节点：鉴权状态
    AuthStatus { id: Uuid },
    /// 后端 -> 节点：读取 DHT 记录
    QueryKey { id: Uuid, key: String },
    /// 后端 -> 节点：写入 DHT 记录 / 宣告提供
    AddKey {
        id: Uuid,
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<Vec<u8>>,
        #[serde(default)]
        providing: bool,
    },
    /// 后端 -> 节点：发起 P2P 服务调用（自动选优）
    ServiceRequest {
        id: Uuid,
        service: String,
        payload: Vec<u8>,
    },
    /// 后端 -> 节点：向指定 peer 发起 P2P 服务调用
    ServiceRequestTo {
        id: Uuid,
        service: String,
        peer: String,
        payload: Vec<u8>,
    },
}

impl Message {
    /// 取关联 id；`hello` 无 id
    pub fn id(&self) -> Option<Uuid> {
        match self {
            Message::Hello { .. } => None,
            Message::Request { id, .. }
            | Message::Reply { id, .. }
            | Message::ListServices { id }
            | Message::DiscoverProviders { id, .. }
            | Message::QueryPublicIp { id }
            | Message::Whoami { id }
            | Message::ReconnectBootstrap { id }
            | Message::ReannounceServices { id }
            | Message::ReloadConfig { id }
            | Message::RelayStatus { id }
            | Message::PqStatus { id }
            | Message::AuthStatus { id }
            | Message::QueryKey { id, .. }
            | Message::AddKey { id, .. }
            | Message::ServiceRequest { id, .. }
            | Message::ServiceRequestTo { id, .. } => Some(*id),
        }
    }

    /// 判别字段 `t` 的值，用于日志
    pub fn kind(&self) -> &'static str {
        match self {
            Message::Hello { .. } => "hello",
            Message::Request { .. } => "request",
            Message::Reply { .. } => "reply",
            Message::ListServices { .. } => "list_services",
            Message::DiscoverProviders { .. } => "discover_providers",
            Message::QueryPublicIp { .. } => "query_public_ip",
            Message::Whoami { .. } => "whoami",
            Message::ReconnectBootstrap { .. } => "reconnect_bootstrap",
            Message::ReannounceServices { .. } => "reannounce_services",
            Message::ReloadConfig { .. } => "reload_config",
            Message::RelayStatus { .. } => "relay_status",
            Message::PqStatus { .. } => "pq_status",
            Message::AuthStatus { .. } => "auth_status",
            Message::QueryKey { .. } => "query_key",
            Message::AddKey { .. } => "add_key",
            Message::ServiceRequest { .. } => "service_request",
            Message::ServiceRequestTo { .. } => "service_request_to",
        }
    }
}

/// `query_public_ip`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIpInfo {
    #[serde(default)]
    pub ipv4: Option<String>,
    #[serde(default)]
    pub ipv6: Option<String>,
}

/// `whoami`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhoamiResult {
    pub peer_id: String,
}

/// `query_key`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryKeyResult {
    pub key: String,
    #[serde(default)]
    pub value: Option<Vec<u8>>,
    #[serde(default)]
    pub providers: Vec<String>,
}

/// `relay_status`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayStatusResult {
    pub need_relay: bool,
    pub target: u64,
    #[serde(default)]
    pub active: Vec<String>,
    #[serde(default)]
    pub pending: Vec<String>,
}

/// `pq_status`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqStatusResult {
    pub enabled: bool,
    pub transport: bool,
    pub identity: bool,
    pub required: bool,
}

/// `reconnect_bootstrap` / `reannounce_services` / `reload_config`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessResult {
    pub success: bool,
    #[serde(default)]
    pub error: Option<String>,
}

/// `add_key`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddKeyResult {
    pub success: bool,
    pub key: String,
}

/// 解码 `reply.result` 的 CBOR 字节
pub fn decode_result<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, SidecarError> {
    ciborium::de::from_reader(bytes).map_err(|e| SidecarError::new("decode_error", e.to_string()))
}

/// 帧编解码错误
#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    TooLarge(usize),
    Encode(String),
    Decode(String),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "io error: {e}"),
            FrameError::TooLarge(n) => write!(f, "frame too large: {n} bytes"),
            FrameError::Encode(e) => write!(f, "cbor encode error: {e}"),
            FrameError::Decode(e) => write!(f, "cbor decode error: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        FrameError::Io(e)
    }
}

/// 将消息编码为完整帧
pub fn encode_frame(msg: &Message) -> Result<Vec<u8>, FrameError> {
    let mut body = Vec::new();
    ciborium::ser::into_writer(msg, &mut body).map_err(|e| FrameError::Encode(e.to_string()))?;
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// 解析帧体
pub fn decode_frame(body: &[u8]) -> Result<Message, FrameError> {
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    ciborium::de::from_reader(body).map_err(|e| FrameError::Decode(e.to_string()))
}

/// 读取一个完整帧
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Message, FrameError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    decode_frame(&body)
}

/// 写入一个完整帧
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &Message,
) -> Result<(), FrameError> {
    let frame = encode_frame(msg)?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(msg: Message) {
        let frame = encode_frame(&msg).unwrap();
        let body = &frame[4..];
        assert_eq!(frame.len(), 4 + body.len());
        assert_eq!(
            u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize,
            body.len()
        );
        assert_eq!(decode_frame(body).unwrap(), msg);
    }

    #[test]
    fn request_reply_round_trip() {
        let id = Uuid::new_v4();
        round_trip(Message::Request {
            id,
            service: "example".into(),
            payload: vec![0, 1, 2, 255],
        });
        round_trip(Message::Reply {
            id,
            ok: false,
            result: None,
            error: Some(SidecarError::new("timeout", "too slow")),
        });
        round_trip(Message::Reply {
            id,
            ok: true,
            result: Some(vec![9, 8, 7]),
            error: None,
        });
    }

    #[test]
    fn control_ops_round_trip() {
        let id = Uuid::new_v4();
        round_trip(Message::Hello {
            version: PROTOCOL_VERSION,
        });
        round_trip(Message::ListServices { id });
        round_trip(Message::DiscoverProviders {
            id,
            service: "example".into(),
        });
        round_trip(Message::QueryPublicIp { id });
        round_trip(Message::Whoami { id });
        round_trip(Message::ReconnectBootstrap { id });
        round_trip(Message::ReannounceServices { id });
        round_trip(Message::ReloadConfig { id });
        round_trip(Message::RelayStatus { id });
        round_trip(Message::PqStatus { id });
        round_trip(Message::AuthStatus { id });
        round_trip(Message::QueryKey {
            id,
            key: "/oahd/service/example".into(),
        });
        round_trip(Message::AddKey {
            id,
            key: "/k".into(),
            value: Some(vec![9, 8, 7]),
            providing: true,
        });
        round_trip(Message::ServiceRequest {
            id,
            service: "example".into(),
            payload: vec![],
        });
        round_trip(Message::ServiceRequestTo {
            id,
            service: "example".into(),
            peer: "12D3KooW".into(),
            payload: vec![1, 2, 3],
        });
    }

    #[test]
    fn oversized_frame_rejected() {
        assert!(matches!(
            decode_frame(&vec![0u8; MAX_FRAME + 1]),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn malformed_body_rejected() {
        // 0xff 是 CBOR 的 break，单独出现非法
        assert!(matches!(decode_frame(&[0xff]), Err(FrameError::Decode(_))));
    }

    #[test]
    fn uuid_is_cbor_bstr() {
        // 契约要求 uuid = bstr .size 16（CBOR 头 0x50）
        let id = Uuid::from_bytes([0xAB; 16]);
        let frame = encode_frame(&Message::Request {
            id,
            service: "s".into(),
            payload: vec![],
        })
        .unwrap();
        let body = &frame[4..];
        let needle = id.as_bytes();
        let found = body.windows(17).any(|w| w[0] == 0x50 && &w[1..] == needle);
        assert!(found, "uuid 未编码为 16 字节 CBOR bstr");
    }

    #[test]
    fn result_payloads_round_trip() {
        fn enc<T: Serialize>(v: &T) -> Vec<u8> {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(v, &mut buf).unwrap();
            buf
        }

        let ip = PublicIpInfo {
            ipv4: Some("1.2.3.4".into()),
            ipv6: None,
        };
        let decoded: PublicIpInfo = decode_result(&enc(&ip)).unwrap();
        assert_eq!(decoded, ip);

        let key = QueryKeyResult {
            key: "/k".into(),
            value: Some(vec![1, 2, 3]),
            providers: vec!["12D3KooW".into()],
        };
        let decoded: QueryKeyResult = decode_result(&enc(&key)).unwrap();
        assert_eq!(decoded, key);

        let relay = RelayStatusResult {
            need_relay: true,
            target: 3,
            active: vec!["12D3KooW".into()],
            pending: vec![],
        };
        let decoded: RelayStatusResult = decode_result(&enc(&relay)).unwrap();
        assert_eq!(decoded, relay);

        let who = WhoamiResult {
            peer_id: "12D3KooWabc".into(),
        };
        let decoded: WhoamiResult = decode_result(&enc(&who)).unwrap();
        assert_eq!(decoded, who);
    }
}
