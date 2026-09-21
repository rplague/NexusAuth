use crate::connection::BackendClient;
use crate::log::{LogLevel, LogStruct};
use crate::protocol::SidecarError;

/// 处理一条入站服务请求，返回 `reply.result` 的原始字节。
///
/// - `service`：节点侧 `local_services[].name` 对应的服务名（本进程不配置）
/// - `payload`：调用方自定义的二进制负载
/// - `client`：回连本节点的控制句柄，可在业务中调用 DHT / P2P 控制指令
///
/// 返回 `Err(SidecarError)` 时，节点会以 `reply { ok: false, error }` 应答。
pub async fn handle_service_request(
    service: &str,
    payload: &[u8],
    client: &BackendClient,
) -> Result<Vec<u8>, SidecarError> {
    LogStruct::new(
        LogLevel::Debug,
        "服务请求",
        format!("service={}, payload_len={}", service, payload.len()),
    )
    .emit();

    // TODO: 在此实现你的业务逻辑。
    //
    // 解析请求：
    //   let req: serde_json::Value = serde_json::from_slice(payload)
    //       .map_err(|e| SidecarError::new("invalid_request", e.to_string()))?;
    //
    // 调用节点控制指令（示例，均返回已解码的结果）：
    //   let ip: PublicIpInfo = client.query_public_ip().await?;
    //   let providers: Vec<String> = client.discover_providers(service).await?;
    //   let result: QueryKeyResult = client.query_key("/oahd/service/example").await?;
    //
    // 回复（返回值即 reply.result 的字节）：
    //   Ok(serde_json::to_vec(&serde_json::json!({"ok": true})).unwrap())

    // 默认实现：原样回显，便于端到端自测。
    let _ = client;
    Ok(payload.to_vec())
}
