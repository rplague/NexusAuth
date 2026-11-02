//! openraft 网络层：把 Raft RPC 封装为 NexusNet `service_request_to` 调用。
//!
//! 不新增 sidecar 端口：请求发往目标节点上的边车服务（默认 `auth`），
//! 节点按既有拓扑转发。请求/响应均带 sidecar Ed25519 签名。

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use openraft::error::NetworkError;
use openraft::error::RPCError;
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};

use crate::connection::BackendClient;
use crate::raft::transport::{IdentityKey, RpcVerifier, encode_reply, encode_request};
use crate::raft::types::{NodeId, RaftNode, RaftRpcBody, RaftRpcReply, TypeConfig};

/// 传输抽象：生产实现走 NexusNet，测试可用内存注册表。
pub trait RaftTransport: Send + Sync + 'static {
    fn request(
        &self,
        service: &str,
        peer_id: &str,
        payload: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send;
}

#[derive(Debug)]
struct TransportFailure(String);

impl fmt::Display for TransportFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for TransportFailure {}

fn rpc_error<E: std::error::Error>(
    target: NodeId,
    e: impl fmt::Display,
) -> RPCError<NodeId, RaftNode, E> {
    let _ = target;
    RPCError::Network(NetworkError::new(&TransportFailure(e.to_string())))
}

/// 生产传输：复用既有 BackendClient，Raft RPC 使用可配置的短超时。
#[derive(Clone)]
pub struct BackendTransport {
    client: BackendClient,
    timeout: Duration,
}

impl BackendTransport {
    pub fn new(client: BackendClient, timeout: Duration) -> Self {
        Self { client, timeout }
    }
}

impl RaftTransport for BackendTransport {
    async fn request(
        &self,
        service: &str,
        peer_id: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.client
            .service_request_to_with_timeout(service, peer_id, payload, self.timeout)
            .await
            .map_err(|e| format!("[{}] {}", e.code, e.message))
    }
}

pub struct NetworkFactory<T: RaftTransport> {
    transport: Arc<T>,
    identity: Arc<IdentityKey>,
    verifier: Arc<RpcVerifier>,
    cluster_id: String,
    local_id: NodeId,
    service: String,
}

impl<T: RaftTransport> NetworkFactory<T> {
    pub fn new(
        transport: Arc<T>,
        identity: Arc<IdentityKey>,
        verifier: Arc<RpcVerifier>,
        cluster_id: impl Into<String>,
        local_id: NodeId,
        service: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            identity,
            verifier,
            cluster_id: cluster_id.into(),
            local_id,
            service: service.into(),
        }
    }
}

impl<T: RaftTransport> RaftNetworkFactory<TypeConfig> for NetworkFactory<T> {
    type Network = NetworkConnection<T>;

    async fn new_client(&mut self, target: NodeId, node: &RaftNode) -> Self::Network {
        NetworkConnection {
            transport: self.transport.clone(),
            identity: self.identity.clone(),
            verifier: self.verifier.clone(),
            cluster_id: self.cluster_id.clone(),
            local_id: self.local_id,
            service: self.service.clone(),
            target,
            target_node: node.clone(),
        }
    }
}

pub struct NetworkConnection<T: RaftTransport> {
    transport: Arc<T>,
    identity: Arc<IdentityKey>,
    verifier: Arc<RpcVerifier>,
    cluster_id: String,
    local_id: NodeId,
    service: String,
    target: NodeId,
    target_node: RaftNode,
}

impl<T: RaftTransport> NetworkConnection<T> {
    async fn send(&self, body: &RaftRpcBody) -> Result<Vec<u8>, String> {
        let payload = encode_request(
            &self.identity,
            &self.cluster_id,
            self.local_id,
            self.target,
            body,
        )
        .map_err(|e| e.to_string())?;

        let raw = self
            .transport
            .request(&self.service, &self.target_node.peer_id, payload)
            .await?;
        let reply: RaftRpcReply =
            serde_json::from_slice(&raw).map_err(|e| format!("decode raft rpc reply: {e}"))?;
        self.verifier
            .verify_reply(self.target, &reply)
            .map_err(|e| e.to_string())
    }
}

impl<T: RaftTransport> RaftNetwork<TypeConfig> for NetworkConnection<T> {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        AppendEntriesResponse<NodeId>,
        RPCError<NodeId, RaftNode, openraft::error::RaftError<NodeId>>,
    > {
        let body = RaftRpcBody::AppendEntries(rpc);
        let bytes = self
            .send(&body)
            .await
            .map_err(|e| rpc_error(self.target, e))?;
        ciborium::de::from_reader(bytes.as_slice())
            .map_err(|e| rpc_error(self.target, format!("decode append_entries: {e}")))
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<
            NodeId,
            RaftNode,
            openraft::error::RaftError<NodeId, openraft::error::InstallSnapshotError>,
        >,
    > {
        let body = RaftRpcBody::InstallSnapshot(rpc);
        let bytes = self
            .send(&body)
            .await
            .map_err(|e| rpc_error(self.target, e))?;
        ciborium::de::from_reader(bytes.as_slice())
            .map_err(|e| rpc_error(self.target, format!("decode install_snapshot: {e}")))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, RaftNode, openraft::error::RaftError<NodeId>>>
    {
        let body = RaftRpcBody::Vote(rpc);
        let bytes = self
            .send(&body)
            .await
            .map_err(|e| rpc_error(self.target, e))?;
        ciborium::de::from_reader(bytes.as_slice())
            .map_err(|e| rpc_error(self.target, format!("decode vote: {e}")))
    }
}

// 保留给 handler 使用的响应签名辅助（避免在 handler 中重复拼 envelope）。
pub fn signed_reply_payload(
    identity: &IdentityKey,
    cluster_id: &str,
    from: NodeId,
    to: NodeId,
    ok: bool,
    body: Vec<u8>,
    error: String,
) -> Result<Vec<u8>, String> {
    encode_reply(identity, cluster_id, from, to, ok, &body, &error).map_err(|e| e.to_string())
}
