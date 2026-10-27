//! HTTP-only, replica-independent transport of end-to-end WireGuard packets.
//! HTTP workers hold no tunnel sockets or session ownership. A bounded shared
//! mailbox retains batches until the recipient acknowledges them.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Mutex as SyncMutex, Weak};
use tokio::sync::Notify;

pub const MAX_BATCH_BYTES: usize = 64 * 1024;
pub const MAX_BATCH_PACKETS: usize = 32;
pub const MAX_PENDING_BATCHES: usize = 256;
pub const MAX_PENDING_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_SOURCE_BATCHES: usize = 8192;
pub const MAX_NODE_NONCES: usize = 32768;
pub const BATCH_TTL_SECONDS: i64 = 120;
pub const MAX_RECEIVE_BATCHES: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshRequest {
    pub query: ControlPlaneNodeQueryRequest,
    pub action: MeshAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum MeshAction {
    Lease {
        ephemeral: bool,
        http_only: bool,
    },
    Routes {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after: Option<NodeId>,
        limit: u16,
    },
    Leave,
    Forward {
        source: IpAddr,
        destination: IpAddr,
    },
    Peer {
        address: String,
    },
    Send {
        target: NodeId,
        batch_id: String,
        packets: Vec<String>,
    },
    Poll {
        acknowledgements: Vec<MeshAck>,
        wait_ms: u64,
    },
}

impl MeshRequest {
    pub fn binding_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&("http-mesh-v1", &self.action))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshAck {
    pub source: NodeId,
    pub batch_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshEnvelope {
    pub source: NodeId,
    pub target: NodeId,
    pub batch_id: String,
    pub packets: Vec<String>,
    pub bytes: u64,
    pub expires_at: chrono::DateTime<Utc>,
}

impl MeshEnvelope {
    pub fn digest(&self) -> Result<String, ControlPlaneError> {
        let body = serde_json::to_vec(&(&self.target, &self.packets))
            .map_err(|error| ControlPlaneError::Store(error.to_string()))?;
        Ok(format!("{:x}", Sha256::digest(body)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshStats {
    pub node_id: NodeId,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub pending_bytes: u64,
    pub pending_batches: u64,
    pub last_poll_at: Option<chrono::DateTime<Utc>>,
}
impl Default for MeshStats {
    fn default() -> Self {
        Self {
            node_id: NodeId::from_string(""),
            sent_bytes: 0,
            received_bytes: 0,
            pending_bytes: 0,
            pending_batches: 0,
            last_poll_at: None,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MeshResponse {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<NodeRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<NodeId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<IpNet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_node: Option<NodeId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
    pub envelopes: Vec<MeshEnvelope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Accepted,
    Duplicate,
    Full,
    Conflict,
}

#[async_trait]
pub trait HttpMeshStore: Send + Sync {
    async fn lease(
        &self,
        node: &NodeRecord,
        ephemeral: bool,
        http_only: bool,
        now: chrono::DateTime<Utc>,
    ) -> Result<(), ControlPlaneError>;
    async fn members(
        &self,
        cluster: &ClusterId,
        after: Option<&NodeId>,
        limit: usize,
        now: chrono::DateTime<Utc>,
    ) -> Result<Vec<NodeId>, ControlPlaneError>;
    async fn is_http_only(&self, node: &NodeId) -> Result<bool, ControlPlaneError>;
    async fn consume_nonce(
        &self,
        node: &NodeId,
        nonce: &str,
        expires_at: chrono::DateTime<Utc>,
        now: chrono::DateTime<Utc>,
    ) -> Result<bool, ControlPlaneError>;
    async fn enqueue(
        &self,
        envelope: MeshEnvelope,
        now: chrono::DateTime<Utc>,
    ) -> Result<EnqueueOutcome, ControlPlaneError>;
    async fn poll(
        &self,
        node: &NodeId,
        acknowledgements: &[MeshAck],
        now: chrono::DateTime<Utc>,
    ) -> Result<Vec<MeshEnvelope>, ControlPlaneError>;
    async fn stats(
        &self,
        nodes: &BTreeSet<NodeId>,
        now: chrono::DateTime<Utc>,
    ) -> Result<Vec<MeshStats>, ControlPlaneError>;
    fn notifier(&self, node: &NodeId) -> Arc<Notify>;
}

#[derive(Debug, Default)]
pub struct MeshWakeups {
    entries: SyncMutex<BTreeMap<NodeId, Weak<Notify>>>,
    last_sweep: SyncMutex<Option<Instant>>,
    pub listener: SyncMutex<Option<tokio::task::JoinHandle<()>>>,
}
impl MeshWakeups {
    pub fn notifier(&self, node: &NodeId) -> Arc<Notify> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if entries.len() >= 1024 {
            let mut last = self
                .last_sweep
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            // Sweep by elapsed time, not on every request above a size limit.
            // Otherwise N waiting polls would each scan N live entries.
            if last.is_none_or(|instant| instant.elapsed() >= Duration::from_secs(30)) {
                entries.retain(|_, value| value.strong_count() != 0);
                *last = Some(Instant::now());
            }
        }
        if let Some(notifier) = entries.get(node).and_then(Weak::upgrade) {
            return notifier;
        }
        let notifier = Arc::new(Notify::new());
        entries.insert(node.clone(), Arc::downgrade(&notifier));
        notifier
    }
    pub fn wake(&self, node: &NodeId) {
        let notifier = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(node)
            .and_then(Weak::upgrade);
        if let Some(notifier) = notifier {
            notifier.notify_waiters();
        }
    }
}
impl Drop for MeshWakeups {
    fn drop(&mut self) {
        if let Some(listener) = self
            .listener
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            listener.abort();
        }
    }
}

#[derive(Debug)]
struct Stored {
    envelope: MeshEnvelope,
    digest: String,
    acknowledged: bool,
}
#[derive(Debug, Default)]
struct MemoryState {
    members: BTreeMap<NodeId, (bool, bool, ClusterId, chrono::DateTime<Utc>)>,
    nonces: BTreeMap<NodeId, BTreeMap<String, chrono::DateTime<Utc>>>,
    batches: BTreeMap<(NodeId, String), Stored>,
    stats: BTreeMap<NodeId, MeshStats>,
}
#[derive(Debug, Default)]
pub struct MemoryMeshStore {
    state: Mutex<MemoryState>,
    wakeups: MeshWakeups,
}

#[async_trait]
impl HttpMeshStore for MemoryMeshStore {
    async fn lease(
        &self,
        node: &NodeRecord,
        ephemeral: bool,
        http_only: bool,
        now: chrono::DateTime<Utc>,
    ) -> Result<(), ControlPlaneError> {
        self.state.lock().await.members.insert(
            node.node_id.clone(),
            (
                ephemeral,
                http_only,
                node.cluster_id.clone(),
                now + chrono::Duration::minutes(5),
            ),
        );
        Ok(())
    }
    async fn members(
        &self,
        cluster: &ClusterId,
        after: Option<&NodeId>,
        limit: usize,
        now: chrono::DateTime<Utc>,
    ) -> Result<Vec<NodeId>, ControlPlaneError> {
        Ok(self
            .state
            .lock()
            .await
            .members
            .iter()
            .filter(|(id, (_, http_only, c, expires))| {
                *http_only
                    && c == cluster
                    && *expires > now
                    && after.is_none_or(|after| *id > after)
            })
            .take(limit)
            .map(|(id, _)| id.clone())
            .collect())
    }
    async fn is_http_only(&self, node: &NodeId) -> Result<bool, ControlPlaneError> {
        Ok(self
            .state
            .lock()
            .await
            .members
            .get(node)
            .is_some_and(|(_, http_only, _, _)| *http_only))
    }
    async fn consume_nonce(
        &self,
        node: &NodeId,
        nonce: &str,
        expires_at: chrono::DateTime<Utc>,
        now: chrono::DateTime<Utc>,
    ) -> Result<bool, ControlPlaneError> {
        let mut state = self.state.lock().await;
        let nonces = state.nonces.entry(node.clone()).or_default();
        nonces.retain(|_, expiry| *expiry > now);
        if nonces.contains_key(nonce) {
            return Ok(false);
        }
        if nonces.len() >= MAX_NODE_NONCES {
            return Err(ControlPlaneError::HttpMeshCapacity);
        }
        nonces.insert(nonce.into(), expires_at);
        Ok(true)
    }
    async fn enqueue(
        &self,
        envelope: MeshEnvelope,
        now: chrono::DateTime<Utc>,
    ) -> Result<EnqueueOutcome, ControlPlaneError> {
        let mut state = self.state.lock().await;
        state
            .batches
            .retain(|_, value| value.envelope.expires_at > now);
        let key = (envelope.source.clone(), envelope.batch_id.clone());
        let digest = envelope.digest()?;
        if let Some(previous) = state.batches.get(&key) {
            return Ok(if previous.digest == digest {
                EnqueueOutcome::Duplicate
            } else {
                EnqueueOutcome::Conflict
            });
        }
        let pending = state
            .batches
            .values()
            .filter(|value| !value.acknowledged && value.envelope.target == envelope.target)
            .collect::<Vec<_>>();
        if pending.len() >= MAX_PENDING_BATCHES
            || pending
                .iter()
                .map(|value| value.envelope.bytes)
                .sum::<u64>()
                + envelope.bytes
                > MAX_PENDING_BYTES
            || state
                .batches
                .values()
                .filter(|value| value.envelope.source == envelope.source)
                .count()
                >= MAX_SOURCE_BATCHES
        {
            return Ok(EnqueueOutcome::Full);
        }
        let stats = state
            .stats
            .entry(envelope.source.clone())
            .or_insert_with(|| MeshStats {
                node_id: envelope.source.clone(),
                ..Default::default()
            });
        stats.sent_bytes = stats.sent_bytes.saturating_add(envelope.bytes);
        let target = envelope.target.clone();
        state
            .stats
            .entry(target.clone())
            .or_insert_with(|| MeshStats {
                node_id: target.clone(),
                ..Default::default()
            });
        state.batches.insert(
            key,
            Stored {
                envelope,
                digest,
                acknowledged: false,
            },
        );
        drop(state);
        self.wakeups.wake(&target);
        Ok(EnqueueOutcome::Accepted)
    }
    async fn poll(
        &self,
        node: &NodeId,
        acknowledgements: &[MeshAck],
        now: chrono::DateTime<Utc>,
    ) -> Result<Vec<MeshEnvelope>, ControlPlaneError> {
        let mut state = self.state.lock().await;
        state
            .batches
            .retain(|_, value| value.envelope.expires_at > now);
        let mut received = 0;
        for ack in acknowledgements {
            if let Some(stored) = state
                .batches
                .get_mut(&(ack.source.clone(), ack.batch_id.clone()))
            {
                if stored.envelope.target == *node && !stored.acknowledged {
                    stored.acknowledged = true;
                    received += stored.envelope.bytes;
                    stored.envelope.packets.clear();
                }
            }
        }
        let stats = state
            .stats
            .entry(node.clone())
            .or_insert_with(|| MeshStats {
                node_id: node.clone(),
                ..Default::default()
            });
        stats.last_poll_at = Some(now);
        stats.received_bytes = stats.received_bytes.saturating_add(received);
        if let Some((_, _, _, expiry)) = state.members.get_mut(node) {
            *expiry = now + chrono::Duration::minutes(5);
        }
        Ok(state
            .batches
            .values()
            .filter(|value| !value.acknowledged && value.envelope.target == *node)
            .take(MAX_RECEIVE_BATCHES)
            .map(|value| value.envelope.clone())
            .collect())
    }
    async fn stats(
        &self,
        nodes: &BTreeSet<NodeId>,
        now: chrono::DateTime<Utc>,
    ) -> Result<Vec<MeshStats>, ControlPlaneError> {
        let state = self.state.lock().await;
        Ok(nodes
            .iter()
            .filter_map(|node| {
                let mut stats = state.stats.get(node).cloned()?;
                for stored in state.batches.values().filter(|value| {
                    !value.acknowledged
                        && value.envelope.target == *node
                        && value.envelope.expires_at > now
                }) {
                    stats.pending_batches += 1;
                    stats.pending_bytes += stored.envelope.bytes;
                }
                Some(stats)
            })
            .collect())
    }
    fn notifier(&self, node: &NodeId) -> Arc<Notify> {
        self.wakeups.notifier(node)
    }
}

fn invalid(reason: &str) -> ControlPlaneError {
    ControlPlaneError::InvalidTransportQuery(reason.to_string())
}

impl<S: ControlPlaneStore> ControlPlane<S> {
    async fn http_mesh_peer_response(
        &self,
        source: &NodeRecord,
        target: NodeRecord,
    ) -> Result<MeshResponse, ControlPlaneError> {
        let policy = self.current_cluster_policy().await?;
        let allowed = |left: &NodeRecord, right: &NodeRecord| {
            left.cluster_id == right.cluster_id
                && !left.is_administratively_stopped()
                && !right.is_administratively_stopped()
                && (policy.acl_rules.is_empty()
                    || (acl_allows_peer(left, right, &policy)
                        && acl_allows_peer(right, left, &policy)))
        };
        if source.node_id != target.node_id && !allowed(source, &target) {
            return Err(ControlPlaneError::RelayDenied);
        }
        let destination = target.vpn_ip.0;
        let destination_node = target.node_id.clone();
        let client = if source.role.is_client() && source.node_id != target.node_id {
            Some(source)
        } else if target.role.is_client() && source.node_id != target.node_id {
            Some(&target)
        } else {
            None
        };
        let transport = if let Some(client) = client {
            let selection = self
                .store
                .get_client_gateway_selection(&client.node_id)
                .await?
                .ok_or(ControlPlaneError::RelayDenied)?;
            self.store
                .get_node(&selection.gateway_node_id)
                .await?
                .ok_or(ControlPlaneError::RelayDenied)?
        } else {
            target
        };
        if source.node_id != transport.node_id {
            self.authorize_mesh_pair(source, &transport).await?;
        }
        let mut prefixes = BTreeSet::new();
        if let Some(prefix) = vpn_host_cidr(&transport.vpn_ip) {
            prefixes.insert(prefix);
        }
        if let Some(prefix) = vpn_host_cidr(&VpnIp(destination)) {
            prefixes.insert(prefix);
        }
        let clients = if transport.endpoint_candidates.is_empty() {
            BTreeSet::new()
        } else {
            self.store
                .list_client_gateway_selections()
                .await?
                .into_iter()
                .filter(|(_, selection)| selection.gateway_node_id == transport.node_id)
                .map(|(client_id, _)| client_id)
                .collect::<BTreeSet<_>>()
        };
        for client in self.store.get_nodes_by_ids(&clients).await? {
            if allowed(source, &client) {
                if let Some(prefix) = vpn_host_cidr(&client.vpn_ip) {
                    prefixes.insert(prefix);
                }
            }
        }
        Ok(MeshResponse {
            node: Some(transport),
            destination: Some(destination),
            destination_node: Some(destination_node),
            allowed_ips: prefixes.into_iter().collect(),
            ..Default::default()
        })
    }
    async fn authorize_mesh_pair(
        &self,
        source: &NodeRecord,
        target: &NodeRecord,
    ) -> Result<(), ControlPlaneError> {
        let policy = self.current_cluster_policy().await?;
        if source.cluster_id != target.cluster_id
            || source.is_administratively_stopped()
            || target.is_administratively_stopped()
            || (!policy.acl_rules.is_empty()
                && (!acl_allows_peer(source, target, &policy)
                    || !acl_allows_peer(target, source, &policy)))
        {
            return Err(ControlPlaneError::RelayDenied);
        }
        for (client, gateway) in [(source, target), (target, source)] {
            if client.role.is_client()
                && self
                    .store
                    .get_client_gateway_selection(&client.node_id)
                    .await?
                    .is_none_or(|selection| selection.gateway_node_id != gateway.node_id)
            {
                return Err(ControlPlaneError::RelayDenied);
            }
        }
        Ok(())
    }

    pub async fn http_mesh_request(
        &self,
        request: MeshRequest,
    ) -> Result<MeshResponse, ControlPlaneError> {
        let binding = request
            .binding_bytes()
            .map_err(|_| invalid("invalid HTTP mesh request"))?;
        if !request
            .query
            .request_signature
            .as_ref()
            .is_some_and(|signature| {
                ipars_crypto::node_query_nonce_matches_binding(&signature.nonce, &binding)
            })
        {
            return Err(invalid("HTTP mesh body commitment mismatch"));
        }
        // Bound packet allocation and acknowledgements before signature/database work.
        match &request.action {
            MeshAction::Routes { after, limit }
                if *limit == 0
                    || *limit > 50
                    || after.as_ref().is_some_and(|id| id.as_str().len() > 128) =>
            {
                return Err(invalid("invalid HTTP mesh route page"))
            }
            MeshAction::Send {
                batch_id, packets, ..
            } => {
                if uuid::Uuid::parse_str(batch_id).is_err()
                    || packets.is_empty()
                    || packets.len() > MAX_BATCH_PACKETS
                    || packets.iter().map(String::len).sum::<usize>()
                        > MAX_BATCH_BYTES * 4 / 3 + MAX_BATCH_PACKETS * 4
                {
                    return Err(invalid("invalid HTTP mesh batch"));
                }
            }
            MeshAction::Poll {
                acknowledgements,
                wait_ms,
            } => {
                if *wait_ms > 15_000
                    || acknowledgements.len() > 64
                    || acknowledgements.iter().any(|ack| {
                        uuid::Uuid::parse_str(&ack.batch_id).is_err()
                            || ack.source.as_str().len() > 128
                    })
                {
                    return Err(invalid("invalid HTTP mesh acknowledgement or wait"));
                }
            }
            MeshAction::Peer { address } if address.is_empty() || address.len() > 128 => {
                return Err(invalid("invalid HTTP mesh address"))
            }
            _ => {}
        }
        let source = self
            .authenticate_node_query(
                &request.query,
                ControlPlaneNodeQueryKind::HttpMesh,
                Utc::now(),
            )
            .await?;
        if source.is_administratively_stopped() {
            return Err(ControlPlaneError::RelayDenied);
        }
        let store = self
            .store
            .http_mesh()
            .ok_or_else(|| ControlPlaneError::Store("shared HTTP mesh store unavailable".into()))?;
        match request.action {
            MeshAction::Lease {
                ephemeral,
                http_only,
            } => {
                if (ephemeral && !source.is_http_only())
                    || (http_only
                        && (source.role.is_client() || !source.endpoint_candidates.is_empty()))
                {
                    return Err(ControlPlaneError::RelayDenied);
                }
                store
                    .lease(&source, ephemeral, http_only, Utc::now())
                    .await?;
                Ok(MeshResponse {
                    accepted: Some(true),
                    ..Default::default()
                })
            }
            MeshAction::Leave => {
                self.remove_verified_node(&source.node_id, false).await?;
                Ok(MeshResponse {
                    accepted: Some(true),
                    ..Default::default()
                })
            }
            MeshAction::Forward {
                source: origin,
                destination,
            } => {
                if source.role.is_client() || source.is_http_only() {
                    return Err(ControlPlaneError::RelayDenied);
                }
                let origin = self
                    .store
                    .find_node_by_vpn_ip(origin)
                    .await?
                    .ok_or(ControlPlaneError::RelayDenied)?;
                let destination = self
                    .store
                    .find_node_by_vpn_ip(destination)
                    .await?
                    .ok_or(ControlPlaneError::RelayDenied)?;
                // Authorize the inner IP pair, not just the outer gateway tunnel.
                // A cloud participant must not use the bridge to reach underlay
                // addresses or bypass another client's ACL/gateway assignment.
                let cloud = match (origin.is_http_only(), destination.is_http_only()) {
                    (true, false) => &origin,
                    (false, true) => &destination,
                    _ => return Err(ControlPlaneError::RelayDenied),
                };
                self.authorize_mesh_pair(&source, cloud).await?;
                let policy = self.current_cluster_policy().await?;
                if origin.cluster_id != source.cluster_id
                    || destination.cluster_id != source.cluster_id
                    || origin.is_administratively_stopped()
                    || destination.is_administratively_stopped()
                    || (!policy.acl_rules.is_empty()
                        && (!acl_allows_peer(&origin, &destination, &policy)
                            || !acl_allows_peer(&destination, &origin, &policy)))
                {
                    return Err(ControlPlaneError::RelayDenied);
                }
                for client in [&origin, &destination]
                    .into_iter()
                    .filter(|node| node.role.is_client())
                {
                    if self
                        .store
                        .get_client_gateway_selection(&client.node_id)
                        .await?
                        .is_none_or(|selection| selection.gateway_node_id != source.node_id)
                    {
                        return Err(ControlPlaneError::RelayDenied);
                    }
                }
                Ok(MeshResponse {
                    accepted: Some(true),
                    ..Default::default()
                })
            }
            MeshAction::Peer { address } => {
                let target = if let Ok(ip) = address.parse::<IpAddr>() {
                    self.store.find_node_by_vpn_ip(ip).await?
                } else {
                    self.store.get_node(&NodeId::from_string(address)).await?
                }
                .ok_or_else(|| invalid("HTTP mesh peer not found"))?;
                self.http_mesh_peer_response(&source, target).await
            }
            MeshAction::Routes { after, limit } => {
                if source.role.is_client() {
                    return Err(ControlPlaneError::RelayDenied);
                }
                let mut ids = store
                    .members(
                        &source.cluster_id,
                        after.as_ref(),
                        usize::from(limit) + 1,
                        Utc::now(),
                    )
                    .await?;
                let more = ids.len() > usize::from(limit);
                ids.truncate(usize::from(limit));
                let next_cursor = if more { ids.last().cloned() } else { None };
                let policy = self.current_cluster_policy().await?;
                let nodes = self
                    .store
                    .get_nodes_by_ids(&ids.into_iter().collect())
                    .await?
                    .into_iter()
                    .filter(|node| {
                        node.node_id != source.node_id
                            && !node.is_administratively_stopped()
                            && node.cluster_id == source.cluster_id
                            && (policy.acl_rules.is_empty()
                                || (acl_allows_peer(&source, node, &policy)
                                    && acl_allows_peer(node, &source, &policy)))
                    })
                    .collect();
                Ok(MeshResponse {
                    nodes,
                    next_cursor,
                    ..Default::default()
                })
            }
            MeshAction::Send {
                target,
                batch_id,
                packets,
            } => {
                let peer = self
                    .store
                    .get_node(&target)
                    .await?
                    .ok_or_else(|| invalid("HTTP mesh peer not found"))?;
                self.authorize_mesh_pair(&source, &peer).await?;
                let mut bytes = 0;
                for packet in &packets {
                    let packet = STANDARD
                        .decode(packet)
                        .map_err(|_| invalid("invalid HTTP mesh packet encoding"))?;
                    if packet.len() < 4
                        || packet.len() > 65507
                        || packet[1..4] != [0, 0, 0]
                        || !match packet[0] {
                            1 => packet.len() == 148,
                            2 => packet.len() == 92,
                            3 => packet.len() == 64,
                            4 => packet.len() >= 32,
                            _ => false,
                        }
                    {
                        return Err(invalid("HTTP mesh only accepts WireGuard packets"));
                    }
                    bytes += packet.len() as u64;
                }
                if bytes > MAX_BATCH_BYTES as u64 {
                    return Err(invalid("HTTP mesh packet batch too large"));
                }
                let now = Utc::now();
                let outcome = store
                    .enqueue(
                        MeshEnvelope {
                            source: source.node_id,
                            target,
                            batch_id,
                            packets,
                            bytes,
                            expires_at: now + chrono::Duration::seconds(BATCH_TTL_SECONDS),
                        },
                        now,
                    )
                    .await?;
                match outcome {
                    EnqueueOutcome::Full => Err(ControlPlaneError::HttpMeshCapacity),
                    EnqueueOutcome::Conflict => {
                        Err(invalid("HTTP mesh batch ID reused with different data"))
                    }
                    _ => Ok(MeshResponse {
                        accepted: Some(outcome == EnqueueOutcome::Accepted),
                        ..Default::default()
                    }),
                }
            }
            MeshAction::Poll {
                acknowledgements,
                wait_ms,
            } => {
                if source.endpoint_candidates.is_empty()
                    && store.is_http_only(&source.node_id).await?
                    && self
                        .store
                        .get_health(&source.node_id)
                        .await?
                        .is_none_or(|health| {
                            health.state != HealthState::Healthy
                                || (Utc::now() - health.last_seen_at).num_seconds() >= 15
                        })
                {
                    self.store
                        .upsert_health(
                            source.node_id.clone(),
                            NodeHealth {
                                state: HealthState::Healthy,
                                last_seen_at: Utc::now(),
                                latency_ms: None,
                                relay_load: None,
                                message: Some("HTTP mesh connected".into()),
                            },
                        )
                        .await?;
                }
                let notify = store.notifier(&source.node_id);
                let deadline = tokio::time::Instant::now() + Duration::from_millis(wait_ms);
                let mut acknowledgements = acknowledgements;
                loop {
                    let notified = notify.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    let envelopes = store
                        .poll(&source.node_id, &acknowledgements, Utc::now())
                        .await?;
                    acknowledgements.clear();
                    let mut allowed = Vec::new();
                    for envelope in envelopes {
                        let current =
                            self.store.get_node(&source.node_id).await?.ok_or_else(|| {
                                ControlPlaneError::NodeNotFound(source.node_id.clone())
                            })?;
                        let peer = self.store.get_node(&envelope.source).await?;
                        if let Some(peer) = peer {
                            if self.authorize_mesh_pair(&peer, &current).await.is_ok() {
                                allowed.push(envelope);
                                continue;
                            }
                        }
                        acknowledgements.push(MeshAck {
                            source: envelope.source,
                            batch_id: envelope.batch_id,
                        });
                    }
                    if !allowed.is_empty() || tokio::time::Instant::now() >= deadline {
                        if !acknowledgements.is_empty() {
                            let _ = store
                                .poll(&source.node_id, &acknowledgements, Utc::now())
                                .await?;
                        }
                        return Ok(MeshResponse {
                            envelopes: allowed,
                            ..Default::default()
                        });
                    }
                    // A timeout also recovers missed NOTIFY events and SQLite
                    // multi-process readers, without retaining a DB connection.
                    let until = deadline.min(tokio::time::Instant::now() + Duration::from_secs(1));
                    tokio::select! {_ = notified => {},_ = tokio::time::sleep_until(until)=>{}}
                }
            }
        }
    }

    pub async fn http_mesh_stats(
        &self,
        nodes: &BTreeSet<NodeId>,
    ) -> Result<Vec<MeshStats>, ControlPlaneError> {
        match self.store.http_mesh() {
            Some(store) => store.stats(nodes, Utc::now()).await,
            None => Ok(Vec::new()),
        }
    }
}
