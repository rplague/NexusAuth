//! `nexusauthctl`：管理员侧 CLI。
//!
//! 私钥只在管理员侧读取/生成；边车只保存公钥。所有写命令生成 `request_id`，
//! 同一 `request_id` 可在失败后用新的 nonce/ts 安全重试（Raft 侧幂等）。

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::RngCore;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::admin_v2::{
    ADMIN_REQUEST_VERSION, AdminJoinTokenSpec, AdminMemberSpec, AdminRequestV2, AdminVerifier,
    canonical_peers, sign_request,
};
use crate::backup::{self, BackupReport};
use crate::config::ServiceConfig;
use crate::protocol::{Message, PROTOCOL_VERSION, SidecarError, read_frame, write_frame};
use crate::raft::token::{JOIN_TOKEN_VERSION, sign_join_token, verify_join_token};
use crate::raft::types::JoinToken;

const DEFAULT_SERVER: &str = "127.0.0.1:5100";
const DEFAULT_KEY: &str = "admin.key";
const DEFAULT_KID: &str = "root";
const DEFAULT_TIMEOUT_SECS: u64 = 10;

#[derive(Debug)]
pub enum CtlError {
    Usage(String),
    Config(String),
    Io(String),
    Transport(String),
    Server { code: String, message: String },
}

impl fmt::Display for CtlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(m) => write!(f, "usage error: {m}"),
            Self::Config(m) => write!(f, "config error: {m}"),
            Self::Io(m) => write!(f, "io error: {m}"),
            Self::Transport(m) => write!(f, "transport error: {m}"),
            Self::Server { code, message } => write!(f, "server error [{code}]: {message}"),
        }
    }
}

impl std::error::Error for CtlError {}

impl From<std::io::Error> for CtlError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Help,
    Keygen,
    Status,
    AddMembers,
    RemoveMembers,
    IssueJoinToken,
    PromoteVoter,
    DemoteVoter,
    PublishNow,
    Backup,
}

#[derive(Debug, Default)]
struct RawArgs {
    command: Option<String>,
    values: HashMap<String, Vec<String>>,
    flags: HashSet<String>,
}

const BOOLEAN_FLAGS: &[&str] = &["json", "dry-run", "force", "help"];

impl RawArgs {
    fn one(&self, key: &str) -> Option<String> {
        self.values
            .get(key)
            .and_then(|values| values.last().cloned())
    }

    fn many(&self, key: &str) -> Vec<String> {
        self.values.get(key).cloned().unwrap_or_default()
    }

    fn flag(&self, key: &str) -> bool {
        self.flags.contains(key)
    }

    fn required(&self, key: &str) -> Result<String, CtlError> {
        self.one(key)
            .ok_or_else(|| CtlError::Usage(format!("缺少 --{key}")))
    }
}

fn parse_raw(args: &[String]) -> Result<RawArgs, CtlError> {
    let mut raw = RawArgs::default();
    let mut index = 0usize;
    while index < args.len() {
        let arg = &args[index];
        if let Some(rest) = arg.strip_prefix("--") {
            if rest.is_empty() {
                return Err(CtlError::Usage("空的 -- 参数".into()));
            }
            let (key, inline) = match rest.split_once('=') {
                Some((key, value)) => (key.to_string(), Some(value.to_string())),
                None => (rest.to_string(), None),
            };
            if !is_known_flag(&key) {
                return Err(CtlError::Usage(format!("未知参数 --{key}")));
            }
            if BOOLEAN_FLAGS.contains(&key.as_str()) {
                if inline.is_some() {
                    return Err(CtlError::Usage(format!("--{key} 不接受值")));
                }
                raw.flags.insert(key);
            } else if let Some(value) = inline {
                raw.values.entry(key).or_default().push(value);
            } else {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| CtlError::Usage(format!("--{key} 缺少值")))?;
                if value.starts_with("--") {
                    return Err(CtlError::Usage(format!("--{key} 缺少值")));
                }
                raw.values.entry(key).or_default().push(value.clone());
            }
        } else if raw.command.is_none() {
            raw.command = Some(arg.clone());
        } else {
            return Err(CtlError::Usage(format!("多余的位置参数: {arg}")));
        }
        index += 1;
    }
    Ok(raw)
}

fn is_known_flag(key: &str) -> bool {
    matches!(
        key,
        "server"
            | "config"
            | "key"
            | "kid"
            | "request-id"
            | "timeout-secs"
            | "role"
            | "out-dir"
            | "service"
            | "peer"
            | "audience"
            | "jti"
            | "expires-at"
            | "expires-in"
            | "max-uses"
            | "bind-peer"
            | "peer-id"
            | "identity-key"
            | "x25519-key"
            | "out"
            | "json"
            | "dry-run"
            | "force"
            | "help"
    )
}

fn parse_command(raw: &RawArgs) -> Result<Command, CtlError> {
    if raw.flag("help") {
        return Ok(Command::Help);
    }
    let command = raw
        .command
        .as_deref()
        .ok_or_else(|| CtlError::Usage("缺少命令（--help 查看用法）".into()))?;
    match command {
        "keygen" => Ok(Command::Keygen),
        "status" => Ok(Command::Status),
        "add-members" => Ok(Command::AddMembers),
        "remove-members" => Ok(Command::RemoveMembers),
        "issue-join-token" => Ok(Command::IssueJoinToken),
        "promote-voter" => Ok(Command::PromoteVoter),
        "demote-voter" => Ok(Command::DemoteVoter),
        "publish-now" => Ok(Command::PublishNow),
        "backup" => Ok(Command::Backup),
        other => Err(CtlError::Usage(format!("未知命令: {other}"))),
    }
}

fn load_config(path: &Path) -> Result<ServiceConfig, CtlError> {
    let text = fs::read_to_string(path)
        .map_err(|e| CtlError::Config(format!("读取 {} 失败: {e}", path.display())))?;
    toml::from_str(&text)
        .map_err(|e| CtlError::Config(format!("解析 {} 失败: {e}", path.display())))
}

fn resolve_server(raw: &RawArgs) -> Result<String, CtlError> {
    if let Some(server) = raw.one("server") {
        return Ok(server);
    }
    if let Ok(server) = std::env::var("NEXUSAUTH_CTL_SERVER")
        && !server.trim().is_empty()
    {
        return Ok(server);
    }
    if let Some(config_path) = raw.one("config") {
        let config = load_config(Path::new(&config_path))?;
        return Ok(format!("127.0.0.1:{}", config.port));
    }
    Ok(DEFAULT_SERVER.to_string())
}

fn key_path(raw: &RawArgs) -> PathBuf {
    raw.one("key")
        .or_else(|| std::env::var("NEXUSAUTH_CTL_KEY").ok())
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_KEY))
}

fn kid(raw: &RawArgs) -> String {
    raw.one("kid")
        .or_else(|| std::env::var("NEXUSAUTH_CTL_KID").ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_KID.to_string())
}

fn load_signing_key(path: &Path) -> Result<SigningKey, CtlError> {
    let bytes = fs::read(path)
        .map_err(|e| CtlError::Config(format!("读取私钥 {} 失败: {e}", path.display())))?;
    let seed = if bytes.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        seed
    } else {
        let text = String::from_utf8(bytes)
            .map_err(|_| CtlError::Config("私钥既不是 32 字节原文也不是文本".into()))?;
        let decoded = STANDARD
            .decode(text.trim())
            .or_else(|_| URL_SAFE_NO_PAD.decode(text.trim()))
            .map_err(|_| CtlError::Config("私钥 base64 无效".into()))?;
        decoded
            .try_into()
            .map_err(|_| CtlError::Config("私钥必须为 32 字节 seed".into()))?
    };
    Ok(SigningKey::from_bytes(&seed))
}

fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now_unix() -> u64 {
    crate::authority::now_unix()
}

fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

#[derive(Debug, Clone, Default)]
struct RequestExtras {
    member: Option<AdminMemberSpec>,
    join_token: Option<AdminJoinTokenSpec>,
}

fn build_request(
    signing_key: &SigningKey,
    kid: &str,
    op: &str,
    service: &str,
    peers: &[String],
    request_id: &str,
    extras: RequestExtras,
) -> Result<AdminRequestV2, CtlError> {
    let mut req = AdminRequestV2 {
        v: ADMIN_REQUEST_VERSION,
        op: op.to_string(),
        service: service.to_string(),
        peers: canonical_peers(peers),
        kid: kid.to_string(),
        request_id: request_id.to_string(),
        nonce: random_nonce(),
        ts: now_unix(),
        sig: String::new(),
        member: extras.member,
        join_token: extras.join_token,
    };
    sign_request(signing_key, &mut req).map_err(|e| CtlError::Usage(e.to_string()))?;
    Ok(req)
}

fn json_text(value: &Value, compact: bool) -> Result<String, CtlError> {
    if compact {
        serde_json::to_string(value)
    } else {
        serde_json::to_string_pretty(value)
    }
    .map_err(|e| CtlError::Io(format!("JSON 输出失败: {e}")))
}

fn print_json(value: &Value, compact: bool) -> Result<(), CtlError> {
    println!("{}", json_text(value, compact)?);
    Ok(())
}

fn print_human(lines: &[(&str, String)]) {
    for (key, value) in lines {
        println!("{key}: {value}");
    }
}

async fn call_server(
    server: &str,
    payload: Vec<u8>,
    timeout_duration: Duration,
) -> Result<Value, CtlError> {
    let stream = tokio::time::timeout(timeout_duration, TcpStream::connect(server))
        .await
        .map_err(|_| CtlError::Transport(format!("连接 {server} 超时")))?
        .map_err(|e| CtlError::Transport(format!("连接 {server} 失败: {e}")))?;
    let (mut reader, mut writer) = stream.into_split();

    write_frame(
        &mut writer,
        &Message::Hello {
            version: PROTOCOL_VERSION,
        },
    )
    .await
    .map_err(|e| CtlError::Transport(format!("发送 hello 失败: {e}")))?;
    match read_hello(&mut reader, timeout_duration).await? {
        PROTOCOL_VERSION => {}
        other => {
            return Err(CtlError::Transport(format!(
                "协议版本不兼容: 对端 {other}, 本端 {PROTOCOL_VERSION}"
            )));
        }
    }

    let id = Uuid::new_v4();
    write_frame(
        &mut writer,
        &Message::Request {
            id,
            service: "auth".to_string(),
            payload,
        },
    )
    .await
    .map_err(|e| CtlError::Transport(format!("发送请求失败: {e}")))?;

    loop {
        let message = tokio::time::timeout(timeout_duration, read_frame(&mut reader))
            .await
            .map_err(|_| CtlError::Transport("等待回复超时".into()))?
            .map_err(|e| CtlError::Transport(format!("读取回复失败: {e}")))?;
        match message {
            Message::Reply {
                id: reply_id,
                ok,
                result,
                error,
            } if reply_id == id => {
                if ok {
                    let bytes = result.unwrap_or_default();
                    return serde_json::from_slice(&bytes)
                        .map_err(|e| CtlError::Transport(format!("回复不是合法 JSON: {e}")));
                }
                let error = error.unwrap_or_else(|| SidecarError::new("backend_error", "unknown"));
                return Err(CtlError::Server {
                    code: error.code,
                    message: error.message,
                });
            }
            _ => continue,
        }
    }
}

async fn read_hello(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
    timeout_duration: Duration,
) -> Result<u32, CtlError> {
    let message = tokio::time::timeout(timeout_duration, read_frame(reader))
        .await
        .map_err(|_| CtlError::Transport("等待 hello 超时".into()))?
        .map_err(|e| CtlError::Transport(format!("读取 hello 失败: {e}")))?;
    match message {
        Message::Hello { version } => Ok(version),
        other => Err(CtlError::Transport(format!(
            "期望 hello，收到 {}",
            other.kind()
        ))),
    }
}

struct RequestContext<'a> {
    server: &'a str,
    signing_key: &'a SigningKey,
    kid: &'a str,
    request_id: &'a str,
    timeout: Duration,
    dry_run: bool,
}

async fn send_request(
    ctx: &RequestContext<'_>,
    op: &str,
    service: &str,
    peers: &[String],
    member: Option<AdminMemberSpec>,
    join_token: Option<AdminJoinTokenSpec>,
) -> Result<Value, CtlError> {
    let mut last_error = None;
    for attempt in 0..2 {
        let req = build_request(
            ctx.signing_key,
            ctx.kid,
            op,
            service,
            peers,
            ctx.request_id,
            RequestExtras {
                member: member.clone(),
                join_token: join_token.clone(),
            },
        )?;
        if ctx.dry_run {
            return serde_json::to_value(&req)
                .map_err(|e| CtlError::Io(format!("请求序列化失败: {e}")));
        }
        let payload =
            serde_json::to_vec(&req).map_err(|e| CtlError::Io(format!("请求编码失败: {e}")))?;
        match call_server(ctx.server, payload, ctx.timeout).await {
            Ok(value) => return Ok(value),
            Err(CtlError::Transport(message)) if attempt == 0 => {
                last_error = Some(CtlError::Transport(message));
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_error.unwrap_or_else(|| CtlError::Transport("请求失败".into())))
}

fn parse_member(raw: &RawArgs) -> Result<AdminMemberSpec, CtlError> {
    let peer_id = raw.required("peer-id")?;
    if !crate::authority::is_valid_peer_id(&peer_id) {
        return Err(CtlError::Usage(
            "--peer-id 必须是合法的 libp2p PeerId".into(),
        ));
    }
    Ok(AdminMemberSpec {
        node_id: crate::raft::transport::node_id_from_peer_id(&peer_id),
        peer_id,
        identity_key: raw.one("identity-key").unwrap_or_default(),
        x25519_key: raw.one("x25519-key").unwrap_or_default(),
    })
}

async fn keygen(raw: &RawArgs) -> Result<Value, CtlError> {
    let role = raw.required("role")?;
    if role != "root" && role != "viewer" {
        return Err(CtlError::Usage("--role 只能是 root 或 viewer".into()));
    }
    let kid = raw
        .one("kid")
        .unwrap_or_else(|| format!("{role}-{}", now_unix()));
    if !kid
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(CtlError::Usage("--kid 只能包含字母、数字、'-'、'_'".into()));
    }
    let out_dir = PathBuf::from(raw.one("out-dir").unwrap_or_else(|| ".".into()));
    let out_dir_existed = out_dir.exists();
    fs::create_dir_all(&out_dir)?;
    #[cfg(unix)]
    if !out_dir_existed {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&out_dir, fs::Permissions::from_mode(0o700))?;
    }

    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = STANDARD.encode(VerifyingKey::from(&signing_key).to_bytes());

    let private_path = out_dir.join(format!("{kid}.key"));
    let public_path = out_dir.join(format!("{kid}.pub.toml"));
    if !raw.flag("force") && (private_path.exists() || public_path.exists()) {
        return Err(CtlError::Usage(format!(
            "目标已存在（使用 --force 覆盖）: {}",
            private_path.display()
        )));
    }
    crate::fsutil::atomic_write(&private_path, &seed, Some(0o600))?;
    let snippet = format!(
        "[[admin.keys]]\nkid = \"{kid}\"\npublic_key = \"{public_key}\"\nrole = \"{role}\"\n"
    );
    crate::fsutil::atomic_write(&public_path, snippet.as_bytes(), Some(0o644))?;

    Ok(json!({
        "ok": true,
        "kid": kid,
        "role": role,
        "public_key": public_key,
        "private_key": private_path.display().to_string(),
        "public_config": public_path.display().to_string(),
        "admin_keys_snippet": snippet,
    }))
}

fn backup_command(raw: &RawArgs) -> Result<Value, CtlError> {
    let config_path = raw
        .one("config")
        .map(PathBuf::from)
        .unwrap_or_else(crate::paths::config_path);
    let config = load_config(&config_path)?;
    let output = raw
        .one("out")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("nexusauth-backup-{}", now_unix())));
    let report = backup::create_backup(&config, &config_path, &output, raw.flag("force"))
        .map_err(|e| CtlError::Config(e.to_string()))?;
    serde_json::to_value(&report).map_err(|e| CtlError::Io(e.to_string()))
}

pub async fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json_requested = args.iter().any(|arg| arg == "--json");
    match execute(&args).await {
        Ok(()) => 0,
        Err(CtlError::Usage(message)) => {
            if json_requested {
                let _ = print_json(
                    &json!({"ok": false, "error": {"code": "usage", "message": message}}),
                    true,
                );
            } else {
                eprintln!("{message}");
                eprintln!("{}", usage());
            }
            2
        }
        Err(error) => {
            if json_requested {
                let _ = print_json(
                    &json!({"ok": false, "error": {"code": error_code(&error), "message": error.to_string()}}),
                    true,
                );
            } else {
                eprintln!("{error}");
            }
            1
        }
    }
}

fn error_code(error: &CtlError) -> &'static str {
    match error {
        CtlError::Usage(_) => "usage",
        CtlError::Config(_) => "config",
        CtlError::Io(_) => "io",
        CtlError::Transport(_) => "transport",
        CtlError::Server { .. } => "server",
    }
}

pub async fn execute(args: &[String]) -> Result<(), CtlError> {
    let raw = parse_raw(args)?;
    let command = parse_command(&raw)?;
    if command == Command::Help {
        println!("{}", usage());
        return Ok(());
    }
    if command == Command::Keygen {
        let value = keygen(&raw).await?;
        if raw.flag("json") {
            print_json(&value, true)?;
        } else {
            let kid = value.get("kid").and_then(Value::as_str).unwrap_or_default();
            let role = value
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let public_key = value
                .get("public_key")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let private_key = value
                .get("private_key")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let snippet = value
                .get("admin_keys_snippet")
                .and_then(Value::as_str)
                .unwrap_or_default();
            print_human(&[
                ("kid", kid.to_string()),
                ("role", role.to_string()),
                ("public_key", public_key.to_string()),
                ("private_key", private_key.to_string()),
            ]);
            println!("\n将以下片段加入配置文件：\n{snippet}");
        }
        return Ok(());
    }
    if command == Command::Backup {
        let value = backup_command(&raw)?;
        if raw.flag("json") {
            print_json(&value, true)?;
        } else {
            let report: BackupReport = serde_json::from_value(value)
                .map_err(|e| CtlError::Io(format!("备份结果解析失败: {e}")))?;
            print_human(&[
                ("backup", report.output_dir),
                ("manifest", report.manifest),
                ("files", report.files.len().to_string()),
                (
                    "authority_public_key",
                    report.authority_public_key.unwrap_or_default(),
                ),
            ]);
        }
        return Ok(());
    }

    let server = resolve_server(&raw)?;
    let key_path = key_path(&raw);
    let signing_key = load_signing_key(&key_path)?;
    let kid = kid(&raw);
    let request_id = raw.one("request-id").unwrap_or_else(new_request_id);
    let timeout_secs = raw
        .one("timeout-secs")
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| CtlError::Usage("--timeout-secs 必须是整数".into()))
        })
        .transpose()?
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    let context = RequestContext {
        server: &server,
        signing_key: &signing_key,
        kid: &kid,
        request_id: &request_id,
        timeout: Duration::from_secs(timeout_secs.max(1)),
        dry_run: raw.flag("dry-run"),
    };

    let value = match command {
        Command::Status => send_request(&context, "status", "", &[], None, None).await?,
        Command::AddMembers | Command::RemoveMembers => {
            let service = raw.required("service")?;
            let peers = raw.many("peer");
            if peers.is_empty() {
                return Err(CtlError::Usage("至少需要一个 --peer".into()));
            }
            let op = if command == Command::AddMembers {
                "add_members"
            } else {
                "remove_members"
            };
            send_request(&context, op, &service, &peers, None, None).await?
        }
        Command::PublishNow => send_request(&context, "publish_now", "", &[], None, None).await?,
        Command::PromoteVoter | Command::DemoteVoter => {
            let member = parse_member(&raw)?;
            let op = if command == Command::PromoteVoter {
                "promote_voter"
            } else {
                "demote_voter"
            };
            send_request(&context, op, "", &[], Some(member), None).await?
        }
        Command::IssueJoinToken => issue_join_token(&raw, &context).await?,
        Command::Help | Command::Keygen | Command::Backup => unreachable!(),
    };

    if context.dry_run {
        print_json(
            &json!({"ok": true, "dry_run": true, "request_id": request_id, "request": value}),
            raw.flag("json"),
        )?;
    } else if raw.flag("json") {
        print_json(&value, true)?;
    } else {
        print_json(&value, false)?;
    }
    Ok(())
}

async fn issue_join_token(raw: &RawArgs, context: &RequestContext<'_>) -> Result<Value, CtlError> {
    // 读取 cluster/network 是安全的只读操作；--dry-run 时仍执行，最终写请求不发送。
    let status_context = RequestContext {
        server: context.server,
        signing_key: context.signing_key,
        kid: context.kid,
        request_id: context.request_id,
        timeout: context.timeout,
        dry_run: false,
    };
    let status = send_request(&status_context, "status", "", &[], None, None).await?;
    let cluster_id = status
        .get("cluster_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CtlError::Server {
            code: "missing_cluster_id".into(),
            message: "status 未返回 cluster_id（Raft 未就绪？）".into(),
        })?;
    let network = status
        .get("network")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CtlError::Server {
            code: "missing_network".into(),
            message: "status 未返回 network".into(),
        })?;
    let audience = raw.one("audience").unwrap_or_else(|| "auth".into());
    let jti = raw.one("jti").unwrap_or_else(|| Uuid::new_v4().to_string());
    let expires_at = if let Some(value) = raw.one("expires-at") {
        value
            .parse::<u64>()
            .map_err(|_| CtlError::Usage("--expires-at 必须是 Unix 秒".into()))?
    } else {
        let expires_in = raw
            .one("expires-in")
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| CtlError::Usage("--expires-in 必须是秒".into()))
            })
            .transpose()?
            .unwrap_or(600);
        now_unix().saturating_add(expires_in.max(1))
    };
    let max_uses = raw
        .one("max-uses")
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| CtlError::Usage("--max-uses 必须是整数".into()))
        })
        .transpose()?
        .unwrap_or(1)
        .max(1);
    let bind_peer_id = raw.one("bind-peer").unwrap_or_default();
    let kid = context.kid.to_string();
    let mut token = JoinToken {
        v: JOIN_TOKEN_VERSION,
        jti: jti.clone(),
        cluster_id: cluster_id.to_string(),
        network: network.to_string(),
        audience: audience.clone(),
        expires_at,
        max_uses,
        bind_peer_id: bind_peer_id.clone(),
        kid: kid.clone(),
        sig: String::new(),
    };
    sign_join_token(context.signing_key, &mut token)
        .map_err(|e| CtlError::Usage(format!("join token 签名失败: {e}")))?;

    // 本地自检：避免把签名错误的 token 提交进 Raft。
    let verifier = AdminVerifier::from_config(
        &[crate::config::AdminKeyConfig {
            kid: kid.clone(),
            public_key: STANDARD.encode(VerifyingKey::from(context.signing_key).to_bytes()),
            role: "root".into(),
        }],
        true,
    )
    .map_err(|e| CtlError::Config(e.to_string()))?;
    let allowed: Vec<&str> = vec!["auth", audience.as_str()];
    verify_join_token(&verifier, &token, now_unix(), cluster_id, network, &allowed)
        .map_err(|e| CtlError::Usage(format!("join token 自检失败: {e}")))?;

    let spec = AdminJoinTokenSpec {
        jti,
        audience,
        expires_at,
        max_uses,
        bind_peer_id,
        sig: token.sig,
    };
    send_request(context, "issue_join_token", "", &[], None, Some(spec)).await
}

fn usage() -> &'static str {
    r#"nexusauthctl - NexusAuth Raft 管理 CLI

用法:
  nexusauthctl keygen --role root|viewer [--kid KID] [--out-dir DIR] [--force] [--json]
  nexusauthctl status [--server HOST:PORT] [--key FILE] [--kid KID] [--json]
  nexusauthctl add-members --service SVC --peer PEER [--peer PEER...]
  nexusauthctl remove-members --service SVC --peer PEER [--peer PEER...]
  nexusauthctl issue-join-token [--audience auth|PEER] [--expires-in SECS] [--bind-peer PEER]
  nexusauthctl promote-voter --peer-id PEER [--identity-key KEY] [--x25519-key KEY]
  nexusauthctl demote-voter --peer-id PEER
  nexusauthctl publish-now
  nexusauthctl backup [--config FILE] [--out DIR] [--force] [--json]

集群成员:
  promote-voter / demote-voter 使用 --peer-id（合法 libp2p PeerId）；
  内部 NodeId 由 PeerId 派生，不需要也无法手工配置。

全局:
  --server HOST:PORT   边车地址（默认 127.0.0.1:5100 或 --config 的 port）
  --key FILE          管理员 Ed25519 私钥（默认 admin.key，或 NEXUSAUTH_CTL_KEY）
  --kid KID           管理员 kid（默认 root，或 NEXUSAUTH_CTL_KID）
  --request-id ID     写命令幂等 ID（默认 UUID；失败重试请复用）
  --timeout-secs N    连接/请求超时（默认 10）
  --dry-run           只输出签名请求，不发送
  --json              紧凑 JSON 输出

私钥只在管理员侧；边车仅保存 [admin.keys] 公钥。备份命令在本机读取配置与文件。
"#
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_v2::request_hash;
    use crate::config::AdminKeyConfig;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn parses_repeated_peers_and_global_flags() {
        let raw = parse_raw(&args(&[
            "add-members",
            "--service",
            "cmd",
            "--peer",
            "a",
            "--peer=b",
            "--json",
            "--request-id",
            "rid-1",
        ]))
        .unwrap();
        assert_eq!(raw.command.as_deref(), Some("add-members"));
        assert_eq!(raw.many("peer"), vec!["a".to_string(), "b".to_string()]);
        assert!(raw.flag("json"));
        assert_eq!(raw.one("request-id").as_deref(), Some("rid-1"));
    }

    #[test]
    fn json_output_is_compact_or_pretty() {
        let value = json!({"ok": true, "request_id": "rid-1", "count": 2});
        let compact = json_text(&value, true).unwrap();
        let pretty = json_text(&value, false).unwrap();
        assert!(!compact.contains('\n'));
        assert!(compact.contains("\"request_id\":\"rid-1\""));
        assert!(pretty.contains('\n'));
        assert!(pretty.contains("  \"ok\""));
        let parsed: Value = serde_json::from_str(&compact).unwrap();
        assert_eq!(parsed["count"], 2);
    }

    #[test]
    fn rejects_unknown_flag_and_missing_value() {
        assert!(matches!(
            parse_raw(&args(&["status", "--nope"])),
            Err(CtlError::Usage(_))
        ));
        assert!(matches!(
            parse_raw(&args(&["status", "--kid"])),
            Err(CtlError::Usage(_))
        ));
    }

    #[test]
    fn parse_member_derives_node_id_from_peer_id() {
        let peer = libp2p_identity::PeerId::random().to_string();
        let raw = parse_raw(&args(&[
            "promote-voter",
            "--peer-id",
            &peer,
            "--identity-key",
            "identity",
            "--x25519-key",
            "x25519",
        ]))
        .unwrap();
        let member = parse_member(&raw).unwrap();
        assert_eq!(member.peer_id, peer);
        assert_eq!(
            member.node_id,
            crate::raft::transport::node_id_from_peer_id(&peer)
        );
        assert_ne!(member.node_id, 0);
        assert_eq!(member.identity_key, "identity");
        assert_eq!(member.x25519_key, "x25519");
    }

    #[test]
    fn parse_member_rejects_missing_empty_or_invalid_peer_id() {
        let missing = parse_raw(&args(&["demote-voter"])).unwrap();
        assert!(matches!(parse_member(&missing), Err(CtlError::Usage(_))));

        let empty = parse_raw(&args(&["demote-voter", "--peer-id", ""])).unwrap();
        assert!(matches!(parse_member(&empty), Err(CtlError::Usage(_))));

        let invalid = parse_raw(&args(&["demote-voter", "--peer-id", "not-a-peer-id"])).unwrap();
        assert!(matches!(parse_member(&invalid), Err(CtlError::Usage(_))));
    }

    #[test]
    fn node_id_flag_is_removed() {
        assert!(matches!(
            parse_raw(&args(&["promote-voter", "--node-id", "1"])),
            Err(CtlError::Usage(_))
        ));
    }

    #[test]
    fn promote_request_carries_derived_node_id() {
        let peer = libp2p_identity::PeerId::random().to_string();
        let raw = parse_raw(&args(&["promote-voter", "--peer-id", &peer])).unwrap();
        let member = parse_member(&raw).unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let request = build_request(
            &key,
            "root-1",
            "promote_voter",
            "",
            &[],
            "rid-member",
            RequestExtras {
                member: Some(member.clone()),
                join_token: None,
            },
        )
        .unwrap();
        let spec = request.member.expect("member spec");
        assert_eq!(spec.peer_id, peer);
        assert_eq!(
            spec.node_id,
            crate::raft::transport::node_id_from_peer_id(&peer)
        );
    }

    #[test]
    fn signed_request_verifies_and_retry_hash_is_stable() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let verifier = AdminVerifier::from_config(
            &[AdminKeyConfig {
                kid: "root-1".into(),
                public_key: STANDARD.encode(VerifyingKey::from(&key).to_bytes()),
                role: "root".into(),
            }],
            true,
        )
        .unwrap();
        let first = build_request(
            &key,
            "root-1",
            "add_members",
            "cmd",
            &["b".into(), "a".into()],
            "rid-stable",
            RequestExtras::default(),
        )
        .unwrap();
        let second = build_request(
            &key,
            "root-1",
            "add_members",
            "cmd",
            &["a".into(), "b".into()],
            "rid-stable",
            RequestExtras::default(),
        )
        .unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert_eq!(first.request_id, second.request_id);
        assert_eq!(
            request_hash(&first).unwrap(),
            request_hash(&second).unwrap()
        );
        assert!(verifier.verify(&first, first.ts).is_ok());
        assert!(verifier.verify(&second, second.ts).is_ok());
    }

    #[tokio::test]
    async fn keygen_writes_private_and_public_files() {
        let dir = std::env::temp_dir().join(format!("nexusauth-ctl-keygen-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let raw = parse_raw(&args(&[
            "keygen",
            "--role",
            "root",
            "--kid",
            "root-test",
            "--out-dir",
            dir.to_str().unwrap(),
            "--json",
        ]))
        .unwrap();
        let value = keygen(&raw).await.unwrap();
        assert_eq!(value["role"], "root");
        let private = dir.join("root-test.key");
        let public = dir.join("root-test.pub.toml");
        assert_eq!(fs::read(&private).unwrap().len(), 32);
        assert!(public.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&private).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let loaded = load_signing_key(&private).unwrap();
        let public_key = STANDARD.encode(VerifyingKey::from(&loaded).to_bytes());
        assert_eq!(value["public_key"], public_key);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn token_signature_is_verifiable_by_join_verifier() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let mut token = JoinToken {
            v: JOIN_TOKEN_VERSION,
            jti: "jti-1".into(),
            cluster_id: "prod".into(),
            network: "myorg".into(),
            audience: "auth".into(),
            expires_at: now_unix() + 600,
            max_uses: 1,
            bind_peer_id: String::new(),
            kid: "root-1".into(),
            sig: String::new(),
        };
        sign_join_token(&key, &mut token).unwrap();
        let verifier = AdminVerifier::from_config(
            &[AdminKeyConfig {
                kid: "root-1".into(),
                public_key: STANDARD.encode(VerifyingKey::from(&key).to_bytes()),
                role: "root".into(),
            }],
            true,
        )
        .unwrap();
        verify_join_token(&verifier, &token, now_unix(), "prod", "myorg", &["auth"]).unwrap();
    }
}
