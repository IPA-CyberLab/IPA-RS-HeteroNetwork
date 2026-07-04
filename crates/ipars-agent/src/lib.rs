use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use futures_util::{StreamExt, TryStreamExt};
use ipars_crypto::{CryptoError, IdentityKeyPair, WireGuardKeyPair};
use ipars_relay::encode_relay_datagram;
use ipars_route_manager::{
    with_netlink_namespace, LinuxNetlinkSocket, LinuxNetworkNamespace, RouteManager,
    RouteManagerError, RoutePlan,
};
use ipars_stun::{StunError, StunProbe, UdpStunProbe};
use ipars_types::api::{
    AgentMetricsResponse, AgentRelayForwarderMetrics, AgentStatusResponse, PathStateCount, PeerMap,
    SignalHolePunchPlanResponse,
};
use ipars_types::{
    CandidateSource, ClusterPolicy, EndpointCandidate, EndpointCandidateKind, NatClassification,
    NatProbeObservation, NodeId, NodeRecord, PathChangeEvent, PathChangeKind, PathRecord,
    PathScore, PathState, Role, Route, Tag, VpnIp,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(target_os = "linux")]
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST};
#[cfg(target_os = "linux")]
use netlink_packet_generic::GenlMessage;
#[cfg(target_os = "linux")]
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute,
    WireguardCmd, WireguardMessage, WireguardPeer, WireguardPeerAttribute, WireguardPeerFlags,
};
#[cfg(target_os = "linux")]
use rtnetlink::{LinkUnspec, LinkWireguard};

const MAX_PATH_CHANGE_EVENTS: usize = 1024;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("agent state io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("agent state serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("stun probe error: {0}")]
    Stun(#[from] StunError),
    #[error("route manager error: {0}")]
    RouteManager(#[from] RouteManagerError),
    #[error("route planning error: {0}")]
    RoutePlanning(String),
    #[error("control-plane client error: {0}")]
    ControlPlaneClient(String),
    #[error("hole punch error: {0}")]
    HolePunch(String),
    #[error("relay session error: {0}")]
    RelaySession(String),
    #[error("wireguard backend error: {0}")]
    WireGuard(String),
    #[error("peer path does not exist: {0}")]
    MissingPeer(NodeId),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentNodeState {
    pub node_id: NodeId,
    pub identity_private_key_b64: String,
    pub identity_public_key_b64: String,
    pub wireguard_private_key_b64: String,
    pub wireguard_public_key_b64: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AgentNodeState {
    pub fn generate(now: DateTime<Utc>) -> Self {
        let identity = IdentityKeyPair::generate();
        let wireguard = WireGuardKeyPair::generate();
        Self {
            node_id: identity.node_id(),
            identity_private_key_b64: identity.signing_key_b64(),
            identity_public_key_b64: identity.public_key_b64(),
            wireguard_private_key_b64: wireguard.private_key_b64,
            wireguard_public_key_b64: wireguard.public_key_b64,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn identity_key_pair(&self) -> Result<IdentityKeyPair, AgentError> {
        Ok(IdentityKeyPair::from_signing_key_b64(
            &self.identity_private_key_b64,
        )?)
    }
}

#[derive(Debug, Clone)]
pub struct FileAgentStateStore {
    path: PathBuf,
}

impl FileAgentStateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<AgentNodeState, AgentError> {
        let bytes = std::fs::read(&self.path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save(&self, state: &AgentNodeState) -> Result<(), AgentError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(state)?;
        std::fs::write(&self.path, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn load_or_create(&self, now: DateTime<Utc>) -> Result<AgentNodeState, AgentError> {
        match self.load() {
            Ok(state) => Ok(state),
            Err(AgentError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let state = AgentNodeState::generate(now);
                self.save(&state)?;
                Ok(state)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug)]
pub struct AgentRuntime {
    state: AgentNodeState,
    candidates: tokio::sync::RwLock<Vec<EndpointCandidate>>,
    nat_classification: tokio::sync::RwLock<Option<NatClassification>>,
    path_state: tokio::sync::RwLock<BTreeMap<(NodeId, NodeId), PathRecord>>,
    path_change_events: tokio::sync::RwLock<VecDeque<PathChangeEvent>>,
    relay_sessions: tokio::sync::RwLock<BTreeMap<NodeId, RelaySessionState>>,
    relay_forwarder_endpoints: tokio::sync::RwLock<BTreeMap<NodeId, SocketAddr>>,
    relay_forwarder_metrics: tokio::sync::RwLock<BTreeMap<NodeId, Arc<RelayForwarderStats>>>,
    lazy_connect: tokio::sync::RwLock<LazyConnectManager>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySessionState {
    pub peer: NodeId,
    pub relay_node: NodeId,
    pub relay_endpoint: SocketAddr,
    pub admitted_local_addr: SocketAddr,
    pub admitted_peer_addr: SocketAddr,
    pub session_id: String,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct RelayForwarderStats {
    peer: NodeId,
    relay_node: NodeId,
    relay_endpoint: SocketAddr,
    local_endpoint: SocketAddr,
    outbound_packets: AtomicU64,
    outbound_payload_bytes: AtomicU64,
    outbound_datagram_bytes: AtomicU64,
    inbound_packets: AtomicU64,
    inbound_payload_bytes: AtomicU64,
    last_forwarded_unix_millis: AtomicI64,
}

impl RelayForwarderStats {
    pub fn new(
        peer: NodeId,
        relay_node: NodeId,
        relay_endpoint: SocketAddr,
        local_endpoint: SocketAddr,
    ) -> Self {
        Self {
            peer,
            relay_node,
            relay_endpoint,
            local_endpoint,
            outbound_packets: AtomicU64::new(0),
            outbound_payload_bytes: AtomicU64::new(0),
            outbound_datagram_bytes: AtomicU64::new(0),
            inbound_packets: AtomicU64::new(0),
            inbound_payload_bytes: AtomicU64::new(0),
            last_forwarded_unix_millis: AtomicI64::new(-1),
        }
    }

    pub fn peer(&self) -> &NodeId {
        &self.peer
    }

    pub fn record_outbound(&self, payload_bytes: usize, datagram_bytes: usize) {
        self.outbound_packets.fetch_add(1, Ordering::Relaxed);
        self.outbound_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
        self.outbound_datagram_bytes
            .fetch_add(datagram_bytes as u64, Ordering::Relaxed);
        self.record_forwarded_at();
    }

    pub fn record_inbound(&self, payload_bytes: usize) {
        self.inbound_packets.fetch_add(1, Ordering::Relaxed);
        self.inbound_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
        self.record_forwarded_at();
    }

    pub fn snapshot(&self) -> AgentRelayForwarderMetrics {
        let last_forwarded_unix_millis = self.last_forwarded_unix_millis.load(Ordering::Relaxed);
        AgentRelayForwarderMetrics {
            peer: self.peer.clone(),
            relay_node: self.relay_node.clone(),
            relay_endpoint: self.relay_endpoint,
            local_endpoint: self.local_endpoint,
            outbound_packets: self.outbound_packets.load(Ordering::Relaxed),
            outbound_payload_bytes: self.outbound_payload_bytes.load(Ordering::Relaxed),
            outbound_datagram_bytes: self.outbound_datagram_bytes.load(Ordering::Relaxed),
            inbound_packets: self.inbound_packets.load(Ordering::Relaxed),
            inbound_payload_bytes: self.inbound_payload_bytes.load(Ordering::Relaxed),
            last_forwarded_at: (last_forwarded_unix_millis >= 0)
                .then(|| DateTime::<Utc>::from_timestamp_millis(last_forwarded_unix_millis))
                .flatten(),
        }
    }

    fn record_forwarded_at(&self) {
        self.last_forwarded_unix_millis
            .store(Utc::now().timestamp_millis(), Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
pub struct UdpRelayFrameForwarder {
    session: RelaySessionState,
    wireguard_endpoint: SocketAddr,
    metrics: Option<Arc<RelayForwarderStats>>,
}

impl UdpRelayFrameForwarder {
    pub fn new(session: RelaySessionState, wireguard_endpoint: SocketAddr) -> Self {
        Self {
            session,
            wireguard_endpoint,
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: Arc<RelayForwarderStats>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn session(&self) -> &RelaySessionState {
        &self.session
    }

    pub fn wireguard_endpoint(&self) -> SocketAddr {
        self.wireguard_endpoint
    }

    pub fn encode_outbound(&self, payload: &[u8]) -> Result<Vec<u8>, AgentError> {
        self.ensure_session_active()?;
        encode_relay_datagram(
            &self.session.session_id,
            &self.session.session_token,
            payload,
        )
        .map_err(|error| AgentError::RelaySession(error.to_string()))
    }

    pub async fn send_to_relay(
        &self,
        socket: &tokio::net::UdpSocket,
        payload: &[u8],
    ) -> Result<usize, AgentError> {
        let datagram = self.encode_outbound(payload)?;
        let bytes_sent = socket
            .send_to(&datagram, self.session.relay_endpoint)
            .await?;
        if let Some(metrics) = &self.metrics {
            metrics.record_outbound(payload.len(), datagram.len());
        }
        Ok(bytes_sent)
    }

    pub async fn forward_to_wireguard(
        &self,
        socket: &tokio::net::UdpSocket,
        payload: &[u8],
    ) -> Result<usize, AgentError> {
        self.ensure_session_active()?;
        let bytes_sent = socket.send_to(payload, self.wireguard_endpoint).await?;
        if let Some(metrics) = &self.metrics {
            metrics.record_inbound(payload.len());
        }
        Ok(bytes_sent)
    }

    pub async fn serve(
        self,
        socket: tokio::net::UdpSocket,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), AgentError> {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                packet = socket.recv_from(&mut buffer) => {
                    let (len, peer) = packet?;
                    if peer == self.session.relay_endpoint {
                        self.forward_to_wireguard(&socket, &buffer[..len]).await?;
                    } else {
                        self.send_to_relay(&socket, &buffer[..len]).await?;
                    }
                }
            }
        }
    }

    fn ensure_session_active(&self) -> Result<(), AgentError> {
        if Utc::now() >= self.session.expires_at {
            return Err(AgentError::RelaySession(format!(
                "relay session {} expired at {}",
                self.session.session_id, self.session.expires_at
            )));
        }
        Ok(())
    }
}

impl AgentRuntime {
    pub fn new(state: AgentNodeState, policy: ClusterPolicy) -> Self {
        Self {
            state,
            candidates: tokio::sync::RwLock::new(Vec::new()),
            nat_classification: tokio::sync::RwLock::new(None),
            path_state: tokio::sync::RwLock::new(BTreeMap::new()),
            path_change_events: tokio::sync::RwLock::new(VecDeque::new()),
            relay_sessions: tokio::sync::RwLock::new(BTreeMap::new()),
            relay_forwarder_endpoints: tokio::sync::RwLock::new(BTreeMap::new()),
            relay_forwarder_metrics: tokio::sync::RwLock::new(BTreeMap::new()),
            lazy_connect: tokio::sync::RwLock::new(LazyConnectManager::new(policy)),
        }
    }

    pub fn state(&self) -> &AgentNodeState {
        &self.state
    }

    pub async fn status(&self) -> AgentStatusResponse {
        let candidates = self.candidates.read().await.clone();
        let nat_classification = self.nat_classification.read().await.clone();
        AgentStatusResponse {
            node_id: self.state.node_id.clone(),
            identity_public_key: self.state.identity_public_key_b64.clone(),
            wireguard_public_key: self.state.wireguard_public_key_b64.clone(),
            candidate_count: candidates.len(),
            candidates,
            nat_classification,
            state_updated_at: self.state.updated_at,
        }
    }

    pub async fn probe_stun(
        &self,
        local_bind: std::net::SocketAddr,
        stun_server: std::net::SocketAddr,
    ) -> Result<EndpointCandidate, AgentError> {
        let candidate = UdpStunProbe
            .probe(self.state.node_id.clone(), local_bind, stun_server)
            .await?;
        self.candidates.write().await.push(candidate.clone());
        Ok(candidate)
    }

    pub async fn classify_nat(
        &self,
        local_bind: std::net::SocketAddr,
        stun_servers: Vec<std::net::SocketAddr>,
    ) -> Result<NatClassification, AgentError> {
        if stun_servers.is_empty() {
            return Err(AgentError::Stun(StunError::InvalidResponse(
                "at least one STUN server is required for NAT classification".to_string(),
            )));
        }

        let observations = UdpStunProbe
            .observe_binding_many(local_bind, &stun_servers)
            .await?;
        let filtering_observations = match stun_servers.first().copied() {
            Some(stun_server) => UdpStunProbe
                .observe_filtering(local_bind, stun_server)
                .await
                .unwrap_or_default(),
            None => Vec::new(),
        };
        let local_addr = observations
            .first()
            .map(|observation| observation.local_addr)
            .unwrap_or(local_bind);
        let classification = NatClassification::from_observations_with_filtering(
            local_addr,
            observations.clone(),
            filtering_observations,
            Utc::now(),
        );

        let mut candidates = self.candidates.write().await;
        candidates.extend(
            observations
                .iter()
                .map(|observation| self.stun_candidate_from_observation(observation)),
        );
        *self.nat_classification.write().await = Some(classification.clone());

        Ok(classification)
    }

    fn stun_candidate_from_observation(
        &self,
        observation: &NatProbeObservation,
    ) -> EndpointCandidate {
        EndpointCandidate {
            node_id: self.state.node_id.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr: observation.reflexive_addr,
            observed_at: observation.observed_at,
            priority: 80,
            cost: 20,
            source: CandidateSource::StunProbe,
        }
    }

    pub async fn path_state(&self) -> Vec<PathRecord> {
        self.path_state.read().await.values().cloned().collect()
    }

    pub async fn path_change_events(&self) -> Vec<PathChangeEvent> {
        self.path_change_events
            .read()
            .await
            .iter()
            .cloned()
            .collect()
    }

    pub async fn metrics(&self) -> AgentMetricsResponse {
        let candidates = self.candidates.read().await;
        let path_state = self.path_state.read().await;
        let relay_sessions = self.relay_sessions.read().await;
        let relay_forwarders = self.relay_forwarder_endpoints.read().await;
        let relay_forwarder_metrics = self.relay_forwarder_metrics.read().await;
        let path_change_events = self.path_change_events.read().await;
        let mut path_state_counts = BTreeMap::<PathState, usize>::new();
        for path in path_state.values() {
            *path_state_counts.entry(path.selected_state).or_default() += 1;
        }

        AgentMetricsResponse {
            node_id: self.state.node_id.clone(),
            candidate_count: candidates.len(),
            path_count: path_state.len(),
            relay_session_count: relay_sessions.len(),
            relay_forwarder_count: relay_forwarders.len(),
            relay_forwarders: relay_forwarder_metrics
                .values()
                .map(|metrics| metrics.snapshot())
                .collect(),
            path_change_event_count: path_change_events.len(),
            path_state_counts: path_state_counts
                .into_iter()
                .map(|(state, count)| PathStateCount { state, count })
                .collect(),
            generated_at: Utc::now(),
        }
    }

    pub async fn path_record_for_peer(&self, peer: &NodeId) -> Option<PathRecord> {
        self.path_state
            .read()
            .await
            .get(&(self.state.node_id.clone(), peer.clone()))
            .cloned()
    }

    pub async fn upsert_path_state(&self, record: PathRecord) {
        let previous = self.path_state.write().await.insert(
            (record.key.local.clone(), record.key.remote.clone()),
            record.clone(),
        );
        if record.pinned {
            self.lazy_connect
                .write()
                .await
                .pin_peer(record.key.remote.clone());
        }
        if let Some(event) = path_change_event(previous.as_ref(), &record) {
            let mut events = self.path_change_events.write().await;
            if events.len() >= MAX_PATH_CHANGE_EVENTS {
                events.pop_front();
            }
            events.push_back(event);
        }
    }

    pub async fn upsert_relay_session(&self, session: RelaySessionState) {
        self.relay_sessions
            .write()
            .await
            .insert(session.peer.clone(), session);
    }

    pub async fn relay_session(&self, peer: &NodeId) -> Option<RelaySessionState> {
        self.relay_sessions.read().await.get(peer).cloned()
    }

    pub async fn relay_sessions(&self) -> Vec<RelaySessionState> {
        self.relay_sessions.read().await.values().cloned().collect()
    }

    pub async fn remove_relay_session(&self, peer: &NodeId) -> Option<RelaySessionState> {
        self.relay_sessions.write().await.remove(peer)
    }

    pub async fn upsert_relay_forwarder_endpoint(&self, peer: NodeId, endpoint: SocketAddr) {
        self.relay_forwarder_endpoints
            .write()
            .await
            .insert(peer, endpoint);
    }

    pub async fn register_relay_forwarder_metrics(&self, metrics: Arc<RelayForwarderStats>) {
        self.relay_forwarder_metrics
            .write()
            .await
            .insert(metrics.peer().clone(), metrics);
    }

    pub async fn relay_forwarder_endpoint(&self, peer: &NodeId) -> Option<SocketAddr> {
        self.relay_forwarder_endpoints
            .read()
            .await
            .get(peer)
            .copied()
    }

    pub async fn remove_relay_forwarder_endpoint(&self, peer: &NodeId) -> Option<SocketAddr> {
        self.relay_forwarder_metrics.write().await.remove(peer);
        self.relay_forwarder_endpoints.write().await.remove(peer)
    }

    pub async fn relay_forwarder_endpoints(&self) -> BTreeMap<NodeId, SocketAddr> {
        self.relay_forwarder_endpoints.read().await.clone()
    }

    pub async fn relay_session_needs_renewal(
        &self,
        peer: &NodeId,
        relay_node: &NodeId,
        now: DateTime<Utc>,
        renew_before: Duration,
    ) -> bool {
        let renew_before = chrono::Duration::from_std(renew_before)
            .unwrap_or_else(|_| chrono::Duration::seconds(i64::MAX));
        self.relay_sessions
            .read()
            .await
            .get(peer)
            .map(|session| {
                &session.relay_node != relay_node || now + renew_before >= session.expires_at
            })
            .unwrap_or(true)
    }

    pub async fn relay_forwarder_endpoint_for_peer(
        &self,
        peer: &NodeId,
        now: DateTime<Utc>,
        fallback_forwarder_endpoint: Option<SocketAddr>,
    ) -> Option<SocketAddr> {
        let path = self.path_record_for_peer(peer).await?;
        if path.selected_state != PathState::Relay {
            return None;
        }

        let session = self.relay_session(peer).await?;
        if now >= session.expires_at {
            return None;
        }
        if path.relay_node.as_ref() != Some(&session.relay_node) {
            return None;
        }

        self.relay_forwarder_endpoint(peer)
            .await
            .or(fallback_forwarder_endpoint)
    }

    pub async fn idle_peers_to_close(&self, now: DateTime<Utc>) -> Vec<NodeId> {
        self.lazy_connect.read().await.idle_peers_to_close(now)
    }

    pub async fn record_peer_activity(&self, peer: NodeId, at: DateTime<Utc>, pin: bool) -> bool {
        let mut lazy_connect = self.lazy_connect.write().await;
        lazy_connect.record_activity(peer.clone(), at);
        if pin {
            lazy_connect.pin_peer(peer.clone());
        }
        lazy_connect.is_pinned(&peer)
    }

    pub async fn observe_peer_map_for_lazy_connect(&self, peers: &[NodeRecord]) {
        let mut lazy_connect = self.lazy_connect.write().await;
        for peer in peers {
            lazy_connect.observe_peer(peer);
        }
    }

    pub async fn should_connect_peer(&self, peer: &NodeRecord) -> bool {
        self.lazy_connect.read().await.should_connect_peer(peer)
    }

    pub async fn take_idle_peers_to_close(&self, now: DateTime<Utc>) -> Vec<NodeId> {
        let mut lazy_connect = self.lazy_connect.write().await;
        let idle_peers = lazy_connect.idle_peers_to_close(now);
        for peer in &idle_peers {
            lazy_connect.remove_activity(peer);
        }
        idle_peers
    }
}

fn path_change_event(
    previous: Option<&PathRecord>,
    current: &PathRecord,
) -> Option<PathChangeEvent> {
    let kind = match previous {
        None => PathChangeKind::Created,
        Some(previous) if previous.selected_state != current.selected_state => {
            PathChangeKind::StateChanged
        }
        Some(previous) if previous.relay_node != current.relay_node => PathChangeKind::RelayChanged,
        Some(previous) if previous.selected_candidate != current.selected_candidate => {
            PathChangeKind::CandidateChanged
        }
        Some(previous) if previous.score != current.score => PathChangeKind::ScoreChanged,
        Some(_) => return None,
    };

    Some(PathChangeEvent {
        key: current.key.clone(),
        kind,
        previous_state: previous.map(|path| path.selected_state),
        new_state: current.selected_state,
        previous_relay_node: previous.and_then(|path| path.relay_node.clone()),
        new_relay_node: current.relay_node.clone(),
        previous_candidate: previous.and_then(|path| path.selected_candidate.clone()),
        new_candidate: current.selected_candidate.clone(),
        previous_score: previous.map(|path| path.score.clone()),
        new_score: current.score.clone(),
        changed_at: current.updated_at,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardPeerConfig {
    pub peer: NodeId,
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive_seconds: Option<u16>,
}

#[async_trait]
pub trait WireGuardBackend: Send + Sync {
    async fn upsert_peer(&self, config: WireGuardPeerConfig) -> Result<(), AgentError>;
    async fn remove_peer(&self, peer: &NodeId) -> Result<(), AgentError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl LinuxCommand {
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn in_namespace(self, namespace: &LinuxNetworkNamespace) -> Self {
        let (program, args) = namespace.wrap_program_args(&self.program, &self.args);
        Self { program, args }
    }
}

#[derive(Debug, Clone)]
pub struct UdpHolePuncher {
    local_bind: std::net::SocketAddr,
    attempts: usize,
    interval: Duration,
}

impl UdpHolePuncher {
    pub fn new(local_bind: std::net::SocketAddr) -> Self {
        Self {
            local_bind,
            attempts: 5,
            interval: Duration::from_millis(100),
        }
    }

    pub fn with_attempts(mut self, attempts: usize) -> Self {
        self.attempts = attempts.max(1);
        self
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    pub async fn execute(
        &self,
        local_node: &NodeId,
        plan: &SignalHolePunchPlanResponse,
    ) -> Result<usize, AgentError> {
        let socket = tokio::net::UdpSocket::bind(self.local_bind).await?;
        self.execute_on_socket(local_node, plan, &socket).await
    }

    pub async fn execute_on_socket(
        &self,
        local_node: &NodeId,
        plan: &SignalHolePunchPlanResponse,
        socket: &tokio::net::UdpSocket,
    ) -> Result<usize, AgentError> {
        let remote_addr = remote_reflexive_addr(local_node, plan)?;
        if Utc::now() >= plan.expires_at {
            return Err(AgentError::HolePunch("hole punch plan expired".to_string()));
        }

        if plan.start_after_millis > 0 {
            tokio::time::sleep(Duration::from_millis(plan.start_after_millis)).await;
        }

        let payload = hole_punch_payload(local_node, plan);
        for attempt in 0..self.attempts {
            socket.send_to(payload.as_bytes(), remote_addr).await?;
            if attempt + 1 < self.attempts && !self.interval.is_zero() {
                tokio::time::sleep(self.interval).await;
            }
        }
        Ok(self.attempts)
    }
}

fn remote_reflexive_addr(
    local_node: &NodeId,
    plan: &SignalHolePunchPlanResponse,
) -> Result<std::net::SocketAddr, AgentError> {
    if local_node == &plan.key.local {
        return plan
            .target_reflexive
            .as_ref()
            .map(|candidate| candidate.addr)
            .ok_or_else(|| {
                AgentError::HolePunch("target reflexive candidate missing".to_string())
            });
    }
    if local_node == &plan.key.remote {
        return plan
            .source_reflexive
            .as_ref()
            .map(|candidate| candidate.addr)
            .ok_or_else(|| {
                AgentError::HolePunch("source reflexive candidate missing".to_string())
            });
    }

    Err(AgentError::HolePunch(format!(
        "node {local_node} is not part of hole punch plan {} -> {}",
        plan.key.local, plan.key.remote
    )))
}

fn hole_punch_payload(local_node: &NodeId, plan: &SignalHolePunchPlanResponse) -> String {
    format!(
        "ipars-hole-punch-v1 source={} target={} local={}",
        plan.key.local, plan.key.remote, local_node
    )
}

#[async_trait]
pub trait LinuxCommandRunner: Send + Sync {
    async fn run(&self, command: LinuxCommand) -> Result<(), AgentError>;
}

#[derive(Debug, Clone, Default)]
pub struct SystemCommandRunner;

#[async_trait]
impl LinuxCommandRunner for SystemCommandRunner {
    async fn run(&self, command: LinuxCommand) -> Result<(), AgentError> {
        let output = Command::new(&command.program)
            .args(&command.args)
            .output()?;
        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(AgentError::WireGuard(format!(
            "{} {} failed: {}",
            command.program,
            command.args.join(" "),
            stderr.trim()
        )))
    }
}

#[derive(Debug, Clone)]
pub struct NamespacedLinuxCommandRunner<R> {
    namespace: LinuxNetworkNamespace,
    inner: R,
}

impl<R> NamespacedLinuxCommandRunner<R> {
    pub fn new(namespace: LinuxNetworkNamespace, inner: R) -> Self {
        Self { namespace, inner }
    }
}

#[async_trait]
impl<R> LinuxCommandRunner for NamespacedLinuxCommandRunner<R>
where
    R: LinuxCommandRunner,
{
    async fn run(&self, command: LinuxCommand) -> Result<(), AgentError> {
        self.inner.run(command.in_namespace(&self.namespace)).await
    }
}

#[derive(Debug)]
pub struct LinuxWireGuardBackend<R> {
    interface: String,
    runner: R,
    peer_public_keys: tokio::sync::RwLock<BTreeMap<NodeId, String>>,
}

impl<R> LinuxWireGuardBackend<R>
where
    R: LinuxCommandRunner,
{
    pub fn new(interface: impl Into<String>, runner: R) -> Self {
        Self {
            interface: interface.into(),
            runner,
            peer_public_keys: tokio::sync::RwLock::new(BTreeMap::new()),
        }
    }

    pub async fn ensure_interface(&self) -> Result<(), AgentError> {
        if self
            .runner
            .run(LinuxCommand::new(
                "ip",
                ["link", "show", "dev", self.interface.as_str()],
            ))
            .await
            .is_ok()
        {
            return Ok(());
        }

        self.runner
            .run(LinuxCommand::new(
                "ip",
                [
                    "link",
                    "add",
                    "dev",
                    self.interface.as_str(),
                    "type",
                    "wireguard",
                ],
            ))
            .await?;
        self.runner
            .run(LinuxCommand::new(
                "ip",
                ["link", "set", "up", "dev", self.interface.as_str()],
            ))
            .await
    }

    fn upsert_command(&self, config: &WireGuardPeerConfig) -> LinuxCommand {
        let mut args = vec![
            "set".to_string(),
            self.interface.clone(),
            "peer".to_string(),
            config.public_key.clone(),
        ];
        if !config.allowed_ips.is_empty() {
            args.push("allowed-ips".to_string());
            args.push(config.allowed_ips.join(","));
        }
        if let Some(endpoint) = &config.endpoint {
            args.push("endpoint".to_string());
            args.push(endpoint.clone());
        }
        if let Some(keepalive) = config.persistent_keepalive_seconds {
            args.push("persistent-keepalive".to_string());
            args.push(keepalive.to_string());
        }
        LinuxCommand::new("wg", args)
    }
}

#[async_trait]
impl<R> WireGuardBackend for LinuxWireGuardBackend<R>
where
    R: LinuxCommandRunner,
{
    async fn upsert_peer(&self, config: WireGuardPeerConfig) -> Result<(), AgentError> {
        self.runner.run(self.upsert_command(&config)).await?;
        self.peer_public_keys
            .write()
            .await
            .insert(config.peer, config.public_key);
        Ok(())
    }

    async fn remove_peer(&self, peer: &NodeId) -> Result<(), AgentError> {
        let public_key = self
            .peer_public_keys
            .read()
            .await
            .get(peer)
            .cloned()
            .ok_or_else(|| AgentError::MissingPeer(peer.clone()))?;
        self.runner
            .run(LinuxCommand::new(
                "wg",
                [
                    "set",
                    self.interface.as_str(),
                    "peer",
                    public_key.as_str(),
                    "remove",
                ],
            ))
            .await?;
        self.peer_public_keys.write().await.remove(peer);
        Ok(())
    }
}

#[derive(Debug)]
pub struct KernelWireGuardBackend {
    interface: String,
    namespace: Option<LinuxNetworkNamespace>,
    peer_public_keys: tokio::sync::RwLock<BTreeMap<NodeId, [u8; 32]>>,
}

impl KernelWireGuardBackend {
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            namespace: None,
            peer_public_keys: tokio::sync::RwLock::new(BTreeMap::new()),
        }
    }

    pub fn new_in_namespace(
        interface: impl Into<String>,
        namespace: LinuxNetworkNamespace,
    ) -> Self {
        Self {
            interface: interface.into(),
            namespace: Some(namespace),
            peer_public_keys: tokio::sync::RwLock::new(BTreeMap::new()),
        }
    }

    pub fn namespace(&self) -> Option<&LinuxNetworkNamespace> {
        self.namespace.as_ref()
    }

    #[cfg(target_os = "linux")]
    pub async fn ensure_interface(&self) -> Result<(), AgentError> {
        let (connection, handle, _) = with_netlink_namespace(self.namespace.as_ref(), || {
            rtnetlink::new_connection_with_socket::<LinuxNetlinkSocket>()
        })
        .map_err(|error| {
            AgentError::WireGuard(format!(
                "failed to open route netlink connection for WireGuard interface {}{}: {error}",
                self.interface,
                wireguard_namespace_suffix(self.namespace.as_ref())
            ))
        })?;
        tokio::spawn(connection);

        let index = match find_link_index(&handle, &self.interface).await? {
            Some(index) => index,
            None => {
                handle
                    .link()
                    .add(LinkWireguard::new(&self.interface).build())
                    .execute()
                    .await
                    .map_err(|error| {
                        AgentError::WireGuard(format!(
                            "failed to create WireGuard interface {} through rtnetlink: {error}",
                            self.interface
                        ))
                    })?;
                find_link_index(&handle, &self.interface)
                    .await?
                    .ok_or_else(|| {
                        AgentError::WireGuard(format!(
                            "WireGuard interface {} was not visible after rtnetlink create",
                            self.interface
                        ))
                    })?
            }
        };

        handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await
            .map_err(|error| {
                AgentError::WireGuard(format!(
                    "failed to set WireGuard interface {} up through rtnetlink: {error}",
                    self.interface
                ))
            })
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn ensure_interface(&self) -> Result<(), AgentError> {
        Err(AgentError::WireGuard(
            "kernel WireGuard netlink backend is only supported on Linux".to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl WireGuardBackend for KernelWireGuardBackend {
    async fn upsert_peer(&self, config: WireGuardPeerConfig) -> Result<(), AgentError> {
        let public_key = parse_wireguard_public_key(&config.public_key)?;
        let peer = netlink_peer_config(&config, public_key)?;
        apply_wireguard_netlink(
            &self.interface,
            self.namespace.as_ref(),
            vec![WireguardAttribute::Peers(vec![peer])],
        )
        .await?;
        self.peer_public_keys
            .write()
            .await
            .insert(config.peer, public_key);
        Ok(())
    }

    async fn remove_peer(&self, peer: &NodeId) -> Result<(), AgentError> {
        let public_key = self
            .peer_public_keys
            .read()
            .await
            .get(peer)
            .copied()
            .ok_or_else(|| AgentError::MissingPeer(peer.clone()))?;
        apply_wireguard_netlink(
            &self.interface,
            self.namespace.as_ref(),
            vec![WireguardAttribute::Peers(vec![WireguardPeer(vec![
                WireguardPeerAttribute::PublicKey(public_key),
                WireguardPeerAttribute::Flags(WireguardPeerFlags::RemoveMe),
            ])])],
        )
        .await?;
        self.peer_public_keys.write().await.remove(peer);
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl WireGuardBackend for KernelWireGuardBackend {
    async fn upsert_peer(&self, _config: WireGuardPeerConfig) -> Result<(), AgentError> {
        Err(AgentError::WireGuard(
            "kernel WireGuard netlink backend is only supported on Linux".to_string(),
        ))
    }

    async fn remove_peer(&self, _peer: &NodeId) -> Result<(), AgentError> {
        Err(AgentError::WireGuard(
            "kernel WireGuard netlink backend is only supported on Linux".to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
async fn find_link_index(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<Option<u32>, AgentError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links.try_next().await.map_err(|error| {
        AgentError::WireGuard(format!(
            "failed to query WireGuard interface {name} through rtnetlink: {error}"
        ))
    })?;
    Ok(link.map(|link| link.header.index))
}

#[cfg(target_os = "linux")]
fn wireguard_namespace_suffix(namespace: Option<&LinuxNetworkNamespace>) -> String {
    namespace
        .map(|namespace| format!(" in linux network namespace `{}`", namespace.name()))
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn parse_wireguard_public_key(value: &str) -> Result<[u8; 32], AgentError> {
    let decoded = BASE64_STANDARD.decode(value.trim()).map_err(|error| {
        AgentError::WireGuard(format!("invalid WireGuard public key base64: {error}"))
    })?;
    decoded.try_into().map_err(|decoded: Vec<u8>| {
        AgentError::WireGuard(format!(
            "WireGuard public key decoded to {} bytes, expected 32",
            decoded.len()
        ))
    })
}

#[cfg(target_os = "linux")]
fn netlink_peer_config(
    config: &WireGuardPeerConfig,
    public_key: [u8; 32],
) -> Result<WireguardPeer, AgentError> {
    let mut attributes = vec![
        WireguardPeerAttribute::PublicKey(public_key),
        WireguardPeerAttribute::Flags(WireguardPeerFlags::ReplaceAllowedIps),
        WireguardPeerAttribute::AllowedIps(netlink_allowed_ips(&config.allowed_ips)?),
    ];
    if let Some(endpoint) = config.endpoint.as_deref() {
        attributes.push(WireguardPeerAttribute::Endpoint(
            endpoint.parse::<SocketAddr>().map_err(|error| {
                AgentError::WireGuard(format!(
                    "kernel WireGuard netlink backend requires socket-address endpoints; `{endpoint}` is invalid: {error}"
                ))
            })?,
        ));
    }
    if let Some(keepalive) = config.persistent_keepalive_seconds {
        attributes.push(WireguardPeerAttribute::PersistentKeepalive(keepalive));
    }
    Ok(WireguardPeer(attributes))
}

#[cfg(target_os = "linux")]
fn netlink_allowed_ips(allowed_ips: &[String]) -> Result<Vec<WireguardAllowedIp>, AgentError> {
    allowed_ips
        .iter()
        .map(|allowed_ip| {
            let network = allowed_ip.parse::<ipnet::IpNet>().map_err(|error| {
                AgentError::WireGuard(format!(
                    "invalid WireGuard allowed IP `{allowed_ip}`: {error}"
                ))
            })?;
            let family = match network.addr() {
                IpAddr::V4(_) => WireguardAddressFamily::Ipv4,
                IpAddr::V6(_) => WireguardAddressFamily::Ipv6,
            };
            Ok(WireguardAllowedIp(vec![
                WireguardAllowedIpAttr::Family(family),
                WireguardAllowedIpAttr::IpAddr(network.addr()),
                WireguardAllowedIpAttr::Cidr(network.prefix_len()),
            ]))
        })
        .collect()
}

#[cfg(target_os = "linux")]
async fn apply_wireguard_netlink(
    interface: &str,
    namespace: Option<&LinuxNetworkNamespace>,
    mut attributes: Vec<WireguardAttribute>,
) -> Result<(), AgentError> {
    attributes.insert(0, WireguardAttribute::IfName(interface.to_string()));
    let (connection, mut handle, _) = with_netlink_namespace(namespace, || {
        genetlink::new_connection_with_socket::<LinuxNetlinkSocket>()
    })
    .map_err(|error| {
        AgentError::WireGuard(format!(
            "failed to open generic netlink connection for WireGuard interface {interface}{}: {error}",
            wireguard_namespace_suffix(namespace)
        ))
    })?;
    tokio::spawn(connection);

    let genlmsg = GenlMessage::from_payload(WireguardMessage {
        cmd: WireguardCmd::SetDevice,
        attributes,
    });
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

    let mut responses = handle.request(nlmsg).await.map_err(|error| {
        AgentError::WireGuard(format!(
            "failed to send WireGuard netlink request for interface {interface}: {error}"
        ))
    })?;
    while let Some(response) = responses.next().await {
        let response = response.map_err(|error| {
            AgentError::WireGuard(format!(
                "failed to decode WireGuard netlink response for interface {interface}: {error}"
            ))
        })?;
        match response.payload {
            NetlinkPayload::Error(error) if error.code.is_some() => {
                return Err(AgentError::WireGuard(format!(
                    "WireGuard netlink request for interface {interface} failed: {}",
                    error.to_io()
                )));
            }
            NetlinkPayload::Error(_) | NetlinkPayload::Done(_) => return Ok(()),
            _ => {}
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct MemoryWireGuardBackend {
    peers: tokio::sync::RwLock<BTreeMap<NodeId, WireGuardPeerConfig>>,
}

#[async_trait]
impl WireGuardBackend for MemoryWireGuardBackend {
    async fn upsert_peer(&self, config: WireGuardPeerConfig) -> Result<(), AgentError> {
        self.peers.write().await.insert(config.peer.clone(), config);
        Ok(())
    }

    async fn remove_peer(&self, peer: &NodeId) -> Result<(), AgentError> {
        self.peers.write().await.remove(peer);
        Ok(())
    }
}

#[async_trait]
pub trait PeerMapSource: Send + Sync {
    async fn fetch_peer_map(&self, node_id: &NodeId) -> Result<PeerMap, AgentError>;
}

#[async_trait]
pub trait PeerMapSink: Send + Sync {
    async fn apply_peer_map_update(
        &self,
        peer_map: PeerMap,
    ) -> Result<PeerMapApplySummary, AgentError>;
}

#[async_trait]
pub trait PeerEndpointResolver: Send + Sync + std::fmt::Debug {
    async fn endpoint_for_peer(&self, peer: &NodeRecord) -> Result<Option<String>, AgentError>;
}

#[derive(Debug, Clone, Default)]
pub struct DirectPeerEndpointResolver;

#[async_trait]
impl PeerEndpointResolver for DirectPeerEndpointResolver {
    async fn endpoint_for_peer(&self, peer: &NodeRecord) -> Result<Option<String>, AgentError> {
        Ok(preferred_endpoint(peer))
    }
}

#[derive(Debug, Clone)]
pub struct RuntimePeerEndpointResolver {
    runtime: Arc<AgentRuntime>,
    relay_forwarder_endpoint: Option<SocketAddr>,
}

impl RuntimePeerEndpointResolver {
    pub fn new(runtime: Arc<AgentRuntime>) -> Self {
        Self {
            runtime,
            relay_forwarder_endpoint: None,
        }
    }

    pub fn with_relay_forwarder_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.relay_forwarder_endpoint = Some(endpoint);
        self
    }
}

#[async_trait]
impl PeerEndpointResolver for RuntimePeerEndpointResolver {
    async fn endpoint_for_peer(&self, peer: &NodeRecord) -> Result<Option<String>, AgentError> {
        let path = self.runtime.path_record_for_peer(&peer.node_id).await;
        let Some(path) = path else {
            return Ok(preferred_endpoint(peer));
        };

        match path.selected_state {
            PathState::Relay => Ok(self
                .runtime
                .relay_forwarder_endpoint_for_peer(
                    &peer.node_id,
                    Utc::now(),
                    self.relay_forwarder_endpoint,
                )
                .await
                .map(|endpoint| endpoint.to_string())),
            PathState::Unreachable => Ok(None),
            _ => Ok(path
                .selected_candidate
                .map(|candidate| candidate.addr.to_string())
                .or_else(|| preferred_endpoint(peer))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerMapApplySummary {
    pub peers_applied: usize,
    pub peers_removed: usize,
    pub routes_applied: usize,
}

#[derive(Debug)]
pub struct PeerMapApplier<W, R> {
    interface: String,
    wireguard: W,
    route_manager: R,
    endpoint_resolver: Arc<dyn PeerEndpointResolver>,
    lazy_runtime: Option<Arc<AgentRuntime>>,
    applied_peers: tokio::sync::RwLock<BTreeSet<NodeId>>,
}

impl<W, R> PeerMapApplier<W, R>
where
    W: WireGuardBackend,
    R: RouteManager,
{
    pub fn new(interface: impl Into<String>, wireguard: W, route_manager: R) -> Self {
        Self {
            interface: interface.into(),
            wireguard,
            route_manager,
            endpoint_resolver: Arc::new(DirectPeerEndpointResolver),
            lazy_runtime: None,
            applied_peers: tokio::sync::RwLock::new(BTreeSet::new()),
        }
    }

    pub fn with_endpoint_resolver(
        mut self,
        endpoint_resolver: impl PeerEndpointResolver + 'static,
    ) -> Self {
        self.endpoint_resolver = Arc::new(endpoint_resolver);
        self
    }

    pub fn with_lazy_connect_runtime(mut self, runtime: Arc<AgentRuntime>) -> Self {
        self.lazy_runtime = Some(runtime);
        self
    }

    pub async fn apply_peer_map(
        &self,
        peer_map: PeerMap,
    ) -> Result<PeerMapApplySummary, AgentError> {
        if let Some(runtime) = &self.lazy_runtime {
            runtime
                .observe_peer_map_for_lazy_connect(&peer_map.peers)
                .await;
        }

        let now = Utc::now();
        let peer_map_ids = peer_map
            .peers
            .iter()
            .map(|peer| peer.node_id.clone())
            .collect::<BTreeSet<_>>();
        let mut peers_to_remove = BTreeSet::new();
        if let Some(runtime) = &self.lazy_runtime {
            peers_to_remove.extend(runtime.take_idle_peers_to_close(now).await);
        }
        let stale_peers = {
            let applied_peers = self.applied_peers.read().await;
            applied_peers
                .iter()
                .filter(|peer| !peer_map_ids.contains(*peer))
                .cloned()
                .collect::<Vec<_>>()
        };
        peers_to_remove.extend(stale_peers);

        let mut peers_removed = 0;
        for peer in peers_to_remove {
            let was_applied = self.applied_peers.read().await.contains(&peer);
            if !was_applied {
                continue;
            }
            self.wireguard.remove_peer(&peer).await?;
            self.applied_peers.write().await.remove(&peer);
            peers_removed += 1;
        }

        let mut routes = Vec::new();
        let mut peers_applied = 0;

        for peer in peer_map.peers {
            if let Some(runtime) = &self.lazy_runtime {
                if !runtime.should_connect_peer(&peer).await {
                    continue;
                }
            }

            let allowed_ip = peer_overlay_cidr(&peer.vpn_ip);
            let endpoint = self.endpoint_resolver.endpoint_for_peer(&peer).await?;
            self.wireguard
                .upsert_peer(WireGuardPeerConfig {
                    peer: peer.node_id.clone(),
                    public_key: peer.wireguard_public_key.clone(),
                    endpoint: endpoint.clone(),
                    allowed_ips: vec![allowed_ip],
                    persistent_keepalive_seconds: endpoint.map(|_| 25),
                })
                .await?;
            self.applied_peers
                .write()
                .await
                .insert(peer.node_id.clone());
            peers_applied += 1;

            routes.push(peer_host_route(&peer)?);
            routes.extend(peer.routes);
        }

        let routes_applied = routes.len();
        if routes_applied > 0 {
            self.route_manager
                .apply_routes(RoutePlan {
                    interface: self.interface.clone(),
                    routes,
                    policy_rules: Vec::new(),
                })
                .await?;
        }

        Ok(PeerMapApplySummary {
            peers_applied,
            peers_removed,
            routes_applied,
        })
    }
}

#[async_trait]
impl<W, R> PeerMapSink for PeerMapApplier<W, R>
where
    W: WireGuardBackend,
    R: RouteManager,
{
    async fn apply_peer_map_update(
        &self,
        peer_map: PeerMap,
    ) -> Result<PeerMapApplySummary, AgentError> {
        self.apply_peer_map(peer_map).await
    }
}

#[derive(Debug)]
pub struct PeerMapSync<S, A> {
    node_id: NodeId,
    source: S,
    sink: A,
}

impl<S, A> PeerMapSync<S, A>
where
    S: PeerMapSource,
    A: PeerMapSink,
{
    pub fn new(node_id: NodeId, source: S, sink: A) -> Self {
        Self {
            node_id,
            source,
            sink,
        }
    }

    pub async fn sync_once(&self) -> Result<PeerMapApplySummary, AgentError> {
        let peer_map = self.source.fetch_peer_map(&self.node_id).await?;
        self.sink.apply_peer_map_update(peer_map).await
    }
}

fn peer_overlay_cidr(vpn_ip: &VpnIp) -> String {
    match vpn_ip.0 {
        std::net::IpAddr::V4(ip) => format!("{ip}/32"),
        std::net::IpAddr::V6(ip) => format!("{ip}/128"),
    }
}

fn peer_host_route(peer: &NodeRecord) -> Result<Route, AgentError> {
    let cidr = peer_overlay_cidr(&peer.vpn_ip);
    Ok(Route {
        id: format!("peer-{}", peer.node_id),
        cidr: cidr
            .parse()
            .map_err(|error| AgentError::RoutePlanning(format!("{cidr}: {error}")))?,
        advertised_by: peer.node_id.clone(),
        via: Some(peer.node_id.clone()),
        metric: 10,
        tags: peer.tags.clone(),
    })
}

fn preferred_endpoint(peer: &NodeRecord) -> Option<String> {
    peer.endpoint_candidates
        .iter()
        .filter_map(|candidate| candidate_kind_rank(candidate.kind).map(|rank| (rank, candidate)))
        .min_by(|(left_rank, left), (right_rank, right)| {
            left_rank
                .cmp(right_rank)
                .then_with(|| left.cost.cmp(&right.cost))
                .then_with(|| right.priority.cmp(&left.priority))
        })
        .map(|(_, candidate)| candidate.addr.to_string())
}

fn candidate_kind_rank(kind: EndpointCandidateKind) -> Option<u8> {
    match kind {
        EndpointCandidateKind::Ipv6 => Some(0),
        EndpointCandidateKind::PublicUdp => Some(1),
        EndpointCandidateKind::StunReflexive => Some(2),
        EndpointCandidateKind::LocalUdp => Some(3),
        EndpointCandidateKind::Relay => None,
    }
}

#[derive(Debug, Clone)]
pub struct LazyConnectManager {
    policy: ClusterPolicy,
    pins: BTreeSet<NodeId>,
    last_used: BTreeMap<NodeId, DateTime<Utc>>,
}

impl LazyConnectManager {
    pub fn new(policy: ClusterPolicy) -> Self {
        Self {
            policy,
            pins: BTreeSet::new(),
            last_used: BTreeMap::new(),
        }
    }

    pub fn record_activity(&mut self, peer: NodeId, at: DateTime<Utc>) {
        self.last_used.insert(peer, at);
    }

    pub fn pin_peer(&mut self, peer: NodeId) {
        self.pins.insert(peer);
    }

    pub fn is_pinned(&self, peer: &NodeId) -> bool {
        self.pins.contains(peer)
    }

    pub fn is_pinned_by_policy(&self, role: &Role, tags: &BTreeSet<Tag>) -> bool {
        self.policy.pinned_roles.contains(role)
            || tags.iter().any(|tag| self.policy.pinned_tags.contains(tag))
    }

    pub fn observe_peer(&mut self, peer: &NodeRecord) {
        if self.is_pinned_by_policy(&peer.role, &peer.tags)
            || !peer.routes.is_empty()
            || peer
                .relay_capability
                .as_ref()
                .is_some_and(|capability| capability.can_admit())
        {
            self.pin_peer(peer.node_id.clone());
        }
    }

    pub fn should_connect_peer(&self, peer: &NodeRecord) -> bool {
        self.pins.contains(&peer.node_id) || self.last_used.contains_key(&peer.node_id)
    }

    pub fn idle_peers_to_close(&self, now: DateTime<Utc>) -> Vec<NodeId> {
        let idle_timeout = Duration::from_secs(self.policy.idle_timeout_seconds);
        self.last_used
            .iter()
            .filter_map(|(peer, last_used)| {
                if self.pins.contains(peer) {
                    return None;
                }
                let idle_for = now.signed_duration_since(*last_used).to_std().ok()?;
                if idle_for >= idle_timeout {
                    Some(peer.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn remove_activity(&mut self, peer: &NodeId) {
        self.last_used.remove(peer);
    }
}

#[derive(Debug, Clone)]
pub struct PathSelector;

impl PathSelector {
    pub fn best_path(paths: &[PathRecord]) -> Option<PathRecord> {
        paths
            .iter()
            .filter(|path| path.selected_state != PathState::Unreachable)
            .max_by(|left, right| compare_score(&left.score, &right.score))
            .cloned()
    }

    pub fn should_promote(current: &PathRecord, candidate: &PathRecord) -> bool {
        candidate.selected_state.is_direct()
            && current.selected_state == PathState::Relay
            && candidate.score.value > current.score.value
    }
}

fn compare_score(left: &PathScore, right: &PathScore) -> std::cmp::Ordering {
    left.value
        .partial_cmp(&right.value)
        .unwrap_or(std::cmp::Ordering::Equal)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use chrono::Duration as ChronoDuration;
    use ipars_relay::{encode_relay_datagram, RelayService, UdpRelay};
    use ipars_route_manager::{
        DockerNetworkIntent, KubernetesUnderlayIntent, RouteManager, RouteManagerError, RoutePlan,
    };
    use ipars_stun::{BindingStunServer, Rfc5780StunServer};
    use ipars_types::api::RelayAdmissionRequest;
    use ipars_types::{
        CandidateSource, ClusterId, NatFilteringBehavior, NatMappingBehavior, NatTraversalStrategy,
        PathMetrics, PeerPathKey, RelayCapability, TokenPolicy,
    };

    use super::*;

    fn temp_state_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ipars-agent-{name}-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ))
    }

    fn path(peer: &str, state: PathState, score: f32) -> PathRecord {
        PathRecord {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string(peer)),
            selected_state: state,
            selected_candidate: None,
            relay_node: None,
            score: PathScore {
                value: score,
                reasons: Vec::new(),
            },
            updated_at: Utc::now(),
            pinned: false,
        }
    }

    fn reflexive_candidate(node_id: &NodeId, addr: SocketAddr) -> EndpointCandidate {
        EndpointCandidate {
            node_id: node_id.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr,
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: ipars_types::CandidateSource::StunProbe,
        }
    }

    #[derive(Debug, Clone, Default)]
    struct RecordingRunner {
        commands: Arc<tokio::sync::RwLock<Vec<LinuxCommand>>>,
        fail_interface_show: bool,
        fail_remove: bool,
    }

    impl RecordingRunner {
        fn with_missing_interface() -> Self {
            Self {
                fail_interface_show: true,
                ..Self::default()
            }
        }

        fn with_failed_remove() -> Self {
            Self {
                fail_remove: true,
                ..Self::default()
            }
        }

        async fn commands(&self) -> Vec<LinuxCommand> {
            self.commands.read().await.clone()
        }
    }

    #[async_trait]
    impl LinuxCommandRunner for RecordingRunner {
        async fn run(&self, command: LinuxCommand) -> Result<(), AgentError> {
            let should_fail_show = self.fail_interface_show
                && command.program == "ip"
                && command
                    .args
                    .iter()
                    .map(String::as_str)
                    .eq(["link", "show", "dev", "ipars0"]);
            let should_fail_remove = self.fail_remove
                && command.program == "wg"
                && command.args.last().is_some_and(|arg| arg == "remove");
            self.commands.write().await.push(command);
            if should_fail_show {
                Err(AgentError::WireGuard("interface missing".to_string()))
            } else if should_fail_remove {
                Err(AgentError::WireGuard("remove failed".to_string()))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Debug, Default)]
    struct RecordingRouteManager {
        applied: tokio::sync::RwLock<Vec<RoutePlan>>,
        removed: tokio::sync::RwLock<Vec<RoutePlan>>,
    }

    #[async_trait]
    impl RouteManager for RecordingRouteManager {
        async fn apply_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError> {
            self.applied.write().await.push(plan);
            Ok(())
        }

        async fn remove_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError> {
            self.removed.write().await.push(plan);
            Ok(())
        }

        async fn apply_docker_intent(
            &self,
            _intent: DockerNetworkIntent,
        ) -> Result<RoutePlan, RouteManagerError> {
            Err(RouteManagerError::Backend(
                "docker intent is not used by agent tests".to_string(),
            ))
        }

        async fn apply_kubernetes_intent(
            &self,
            _intent: KubernetesUnderlayIntent,
        ) -> Result<RoutePlan, RouteManagerError> {
            Err(RouteManagerError::Backend(
                "kubernetes intent is not used by agent tests".to_string(),
            ))
        }
    }

    fn peer_record(
        node_id: NodeId,
        vpn_ip: IpAddr,
        wireguard_public_key: &str,
        endpoint_candidates: Vec<EndpointCandidate>,
        routes: Vec<Route>,
    ) -> NodeRecord {
        NodeRecord {
            node_id,
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(vpn_ip),
            identity_public_key: "identity-public".to_string(),
            wireguard_public_key: wireguard_public_key.to_string(),
            role: Role::edge(),
            tags: Default::default(),
            endpoint_candidates,
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes,
            registered_at: Utc::now(),
        }
    }

    #[derive(Debug, Clone)]
    struct StaticPeerMapSource {
        expected_node_id: NodeId,
        peer_map: PeerMap,
        requests: Arc<tokio::sync::RwLock<Vec<NodeId>>>,
    }

    impl StaticPeerMapSource {
        fn new(expected_node_id: NodeId, peer_map: PeerMap) -> Self {
            Self {
                expected_node_id,
                peer_map,
                requests: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl PeerMapSource for StaticPeerMapSource {
        async fn fetch_peer_map(&self, node_id: &NodeId) -> Result<PeerMap, AgentError> {
            self.requests.write().await.push(node_id.clone());
            if node_id == &self.expected_node_id {
                Ok(self.peer_map.clone())
            } else {
                Err(AgentError::ControlPlaneClient(format!(
                    "unexpected node id {node_id}"
                )))
            }
        }
    }

    #[derive(Debug, Clone)]
    struct RecordingPeerMapSink {
        summary: PeerMapApplySummary,
        applied: Arc<tokio::sync::RwLock<Vec<PeerMap>>>,
    }

    impl RecordingPeerMapSink {
        fn new(summary: PeerMapApplySummary) -> Self {
            Self {
                summary,
                applied: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl PeerMapSink for RecordingPeerMapSink {
        async fn apply_peer_map_update(
            &self,
            peer_map: PeerMap,
        ) -> Result<PeerMapApplySummary, AgentError> {
            self.applied.write().await.push(peer_map);
            Ok(self.summary.clone())
        }
    }

    #[test]
    fn lazy_manager_keeps_pinned_peers_open() {
        let mut manager = LazyConnectManager::new(ClusterPolicy {
            idle_timeout_seconds: 10,
            ..ClusterPolicy::default()
        });
        manager.record_activity(
            NodeId::from_string("peer-a"),
            Utc::now() - ChronoDuration::seconds(30),
        );
        manager.pin_peer(NodeId::from_string("peer-a"));

        assert!(manager.idle_peers_to_close(Utc::now()).is_empty());
    }

    #[test]
    fn selector_promotes_direct_path_over_relay_when_score_improves() {
        let relay = path("peer-a", PathState::Relay, 70.0);
        let direct = path("peer-a", PathState::DirectNatTraversal, 90.0);

        assert!(PathSelector::should_promote(&relay, &direct));
    }

    #[test]
    fn score_helper_keeps_metrics_type_in_scope() {
        let score = PathScore::calculate(PathState::DirectPublic, &PathMetrics::default(), true, 0);
        assert!(score.value > 0.0);
    }

    #[tokio::test]
    async fn runtime_stores_latest_path_state() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let first = path("peer-a", PathState::Relay, 70.0);
        let latest = path("peer-a", PathState::DirectPublic, 115.0);

        runtime.upsert_path_state(first).await;
        runtime.upsert_path_state(latest.clone()).await;

        assert_eq!(runtime.path_state().await, vec![latest]);
    }

    #[tokio::test]
    async fn runtime_records_path_change_events_and_metrics() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let first = path("peer-a", PathState::Relay, 70.0);
        let latest = path("peer-a", PathState::DirectPublic, 115.0);
        runtime.upsert_path_state(first.clone()).await;
        runtime.upsert_path_state(first.clone()).await;
        runtime.upsert_path_state(latest.clone()).await;

        let events = runtime.path_change_events().await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, PathChangeKind::Created);
        assert_eq!(events[0].previous_state, None);
        assert_eq!(events[0].new_state, PathState::Relay);
        assert_eq!(events[1].kind, PathChangeKind::StateChanged);
        assert_eq!(events[1].previous_state, Some(PathState::Relay));
        assert_eq!(events[1].new_state, PathState::DirectPublic);

        let metrics = runtime.metrics().await;
        assert_eq!(metrics.path_count, 1);
        assert_eq!(metrics.path_change_event_count, 2);
        assert_eq!(metrics.relay_session_count, 0);
        assert!(metrics.relay_forwarders.is_empty());
        assert_eq!(
            metrics.path_state_counts,
            vec![PathStateCount {
                state: PathState::DirectPublic,
                count: 1,
            }]
        );
    }

    #[tokio::test]
    async fn runtime_stores_relay_sessions_separately_from_path_state() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer = NodeId::from_string("peer-a");
        let session = RelaySessionState {
            peer: peer.clone(),
            relay_node: NodeId::from_string("relay-a"),
            relay_endpoint: SocketAddr::from(([203, 0, 113, 20], 51820)),
            admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
            admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
            session_id: "session-a".to_string(),
            session_token: "secret".to_string(),
            expires_at: Utc::now() + ChronoDuration::seconds(60),
        };

        runtime.upsert_relay_session(session.clone()).await;

        assert_eq!(runtime.relay_session(&peer).await, Some(session));
        assert!(runtime.path_state().await.is_empty());
    }

    #[tokio::test]
    async fn runtime_renews_relay_sessions_before_expiry_or_relay_change() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let now = Utc::now();
        let peer = NodeId::from_string("peer-a");
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: peer.clone(),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 20], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-a".to_string(),
                session_token: "secret".to_string(),
                expires_at: now + ChronoDuration::seconds(120),
            })
            .await;

        assert!(
            !runtime
                .relay_session_needs_renewal(
                    &peer,
                    &NodeId::from_string("relay-a"),
                    now,
                    std::time::Duration::from_secs(60),
                )
                .await
        );
        assert!(
            runtime
                .relay_session_needs_renewal(
                    &peer,
                    &NodeId::from_string("relay-a"),
                    now + ChronoDuration::seconds(70),
                    std::time::Duration::from_secs(60),
                )
                .await
        );
        assert!(
            runtime
                .relay_session_needs_renewal(
                    &peer,
                    &NodeId::from_string("relay-b"),
                    now,
                    std::time::Duration::from_secs(60),
                )
                .await
        );
        assert!(runtime.remove_relay_session(&peer).await.is_some());
        assert!(runtime.relay_session(&peer).await.is_none());
    }

    #[tokio::test]
    async fn relay_frame_forwarder_sends_framed_payload_to_relay(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let relay = UdpRelay::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let relay_addr = relay.local_addr()?;
        let left_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let right_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let service = RelayService::new(
            NodeId::from_string("relay-a"),
            RelayCapability {
                enabled_by_policy: true,
                public_endpoint: Some(relay_addr),
                admission_url: Some("http://127.0.0.1:9580".to_string()),
                max_sessions: 10,
                active_sessions: 0,
                max_mbps: 1000,
                e2e_only: true,
            },
        );
        let admission = service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left"),
                right: NodeId::from_string("right"),
                left_addr: left_socket.local_addr()?,
                right_addr: right_socket.local_addr()?,
            })
            .await?;
        let forwarder = UdpRelayFrameForwarder::new(
            RelaySessionState {
                peer: NodeId::from_string("right"),
                relay_node: admission.relay_node,
                relay_endpoint: relay_addr,
                admitted_local_addr: admission.left_addr,
                admitted_peer_addr: admission.right_addr,
                session_id: admission.session_id,
                session_token: admission.session_token,
                expires_at: admission.expires_at,
            },
            left_socket.local_addr()?,
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let relay_task = tokio::spawn(relay.serve(service.table(), shutdown_rx));

        forwarder
            .send_to_relay(&left_socket, b"opaque-wireguard-packet")
            .await?;
        let mut buffer = [0_u8; 128];
        let (len, _peer) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            right_socket.recv_from(&mut buffer),
        )
        .await??;

        assert_eq!(&buffer[..len], b"opaque-wireguard-packet");
        shutdown_tx.send(true)?;
        relay_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn relay_frame_forwarder_proxies_wireguard_and_relay_datagrams(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let relay = UdpRelay::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let relay_addr = relay.local_addr()?;
        let forwarder_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let forwarder_addr = forwarder_socket.local_addr()?;
        let wireguard_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let wireguard_addr = wireguard_socket.local_addr()?;
        let peer_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let peer_addr = peer_socket.local_addr()?;
        let service = RelayService::new(
            NodeId::from_string("relay-a"),
            RelayCapability {
                enabled_by_policy: true,
                public_endpoint: Some(relay_addr),
                admission_url: Some("http://127.0.0.1:9580".to_string()),
                max_sessions: 10,
                active_sessions: 0,
                max_mbps: 1000,
                e2e_only: true,
            },
        );
        let admission = service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left"),
                right: NodeId::from_string("right"),
                left_addr: forwarder_addr,
                right_addr: peer_addr,
            })
            .await?;
        let stats = Arc::new(RelayForwarderStats::new(
            NodeId::from_string("right"),
            admission.relay_node.clone(),
            relay_addr,
            forwarder_addr,
        ));
        let forwarder = UdpRelayFrameForwarder::new(
            RelaySessionState {
                peer: NodeId::from_string("right"),
                relay_node: admission.relay_node.clone(),
                relay_endpoint: relay_addr,
                admitted_local_addr: admission.left_addr,
                admitted_peer_addr: admission.right_addr,
                session_id: admission.session_id.clone(),
                session_token: admission.session_token.clone(),
                expires_at: admission.expires_at,
            },
            wireguard_addr,
        )
        .with_metrics(stats.clone());
        let (relay_shutdown_tx, relay_shutdown_rx) = tokio::sync::watch::channel(false);
        let (forwarder_shutdown_tx, forwarder_shutdown_rx) = tokio::sync::watch::channel(false);
        let relay_task = tokio::spawn(relay.serve(service.table(), relay_shutdown_rx));
        let forwarder_task = tokio::spawn(forwarder.serve(forwarder_socket, forwarder_shutdown_rx));

        wireguard_socket
            .send_to(b"opaque-wireguard-outbound", forwarder_addr)
            .await?;
        let mut buffer = [0_u8; 128];
        let (len, _peer) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_socket.recv_from(&mut buffer),
        )
        .await??;
        assert_eq!(&buffer[..len], b"opaque-wireguard-outbound");

        let datagram = encode_relay_datagram(
            &admission.session_id,
            &admission.session_token,
            b"opaque-wireguard-inbound",
        )?;
        peer_socket.send_to(&datagram, relay_addr).await?;
        let (len, _peer) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            wireguard_socket.recv_from(&mut buffer),
        )
        .await??;
        assert_eq!(&buffer[..len], b"opaque-wireguard-inbound");
        let stats = stats.snapshot();
        assert_eq!(stats.outbound_packets, 1);
        assert_eq!(
            stats.outbound_payload_bytes,
            b"opaque-wireguard-outbound".len() as u64
        );
        assert!(stats.outbound_datagram_bytes > stats.outbound_payload_bytes);
        assert_eq!(stats.inbound_packets, 1);
        assert_eq!(
            stats.inbound_payload_bytes,
            b"opaque-wireguard-inbound".len() as u64
        );
        assert!(stats.last_forwarded_at.is_some());

        forwarder_shutdown_tx.send(true)?;
        relay_shutdown_tx.send(true)?;
        forwarder_task.await??;
        relay_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn udp_hole_puncher_sends_to_remote_reflexive_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let local = NodeId::from_string("local");
        let remote = NodeId::from_string("remote");
        let receiver = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let target_addr = receiver.local_addr()?;
        let plan = SignalHolePunchPlanResponse {
            key: PeerPathKey::new(local.clone(), remote.clone()),
            source_reflexive: Some(reflexive_candidate(
                &local,
                SocketAddr::from(([127, 0, 0, 1], 50_000)),
            )),
            target_reflexive: Some(reflexive_candidate(&remote, target_addr)),
            start_after_millis: 0,
            expires_at: Utc::now() + ChronoDuration::seconds(5),
        };

        let sent = UdpHolePuncher::new(SocketAddr::from(([127, 0, 0, 1], 0)))
            .with_attempts(1)
            .with_interval(std::time::Duration::ZERO)
            .execute(&local, &plan)
            .await?;
        let mut buffer = [0_u8; 256];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            receiver.recv_from(&mut buffer),
        )
        .await??;
        let payload = std::str::from_utf8(&buffer[..len])?;

        assert_eq!(sent, 1);
        assert!(payload.contains("ipars-hole-punch-v1"));
        assert!(payload.contains("local=local"));
        Ok(())
    }

    #[tokio::test]
    async fn udp_hole_puncher_rejects_plan_without_remote_candidate() {
        let local = NodeId::from_string("local");
        let remote = NodeId::from_string("remote");
        let plan = SignalHolePunchPlanResponse {
            key: PeerPathKey::new(local.clone(), remote),
            source_reflexive: None,
            target_reflexive: None,
            start_after_millis: 0,
            expires_at: Utc::now() + ChronoDuration::seconds(5),
        };

        let error = UdpHolePuncher::new(SocketAddr::from(([127, 0, 0, 1], 0)))
            .execute(&local, &plan)
            .await;

        assert!(matches!(
            error,
            Err(AgentError::HolePunch(message)) if message == "target reflexive candidate missing"
        ));
    }

    #[tokio::test]
    async fn namespaced_wireguard_runner_wraps_command() -> Result<(), Box<dyn std::error::Error>> {
        let runner = RecordingRunner::default();
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let namespaced_runner = NamespacedLinuxCommandRunner::new(namespace, runner.clone());

        namespaced_runner
            .run(LinuxCommand::new("wg", ["show", "ipars0"]))
            .await?;

        assert_eq!(
            runner.commands().await,
            vec![LinuxCommand::new(
                "ip",
                ["netns", "exec", "node-a", "wg", "show", "ipars0"],
            )]
        );
        Ok(())
    }

    #[tokio::test]
    async fn linux_wireguard_backend_generates_peer_upsert_and_remove_commands(
    ) -> Result<(), AgentError> {
        let runner = RecordingRunner::default();
        let backend = LinuxWireGuardBackend::new("ipars0", runner.clone());
        let peer = NodeId::from_string("node-a");

        backend
            .upsert_peer(WireGuardPeerConfig {
                peer: peer.clone(),
                public_key: "peer-public".to_string(),
                endpoint: Some("203.0.113.10:51820".to_string()),
                allowed_ips: vec!["100.64.0.2/32".to_string()],
                persistent_keepalive_seconds: Some(25),
            })
            .await?;
        backend.remove_peer(&peer).await?;

        assert_eq!(
            runner.commands().await,
            vec![
                LinuxCommand::new(
                    "wg",
                    [
                        "set",
                        "ipars0",
                        "peer",
                        "peer-public",
                        "allowed-ips",
                        "100.64.0.2/32",
                        "endpoint",
                        "203.0.113.10:51820",
                        "persistent-keepalive",
                        "25",
                    ],
                ),
                LinuxCommand::new("wg", ["set", "ipars0", "peer", "peer-public", "remove"],),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn linux_wireguard_backend_keeps_peer_when_remove_command_fails() -> Result<(), AgentError>
    {
        let runner = RecordingRunner::with_failed_remove();
        let backend = LinuxWireGuardBackend::new("ipars0", runner);
        let peer = NodeId::from_string("node-a");

        backend
            .upsert_peer(WireGuardPeerConfig {
                peer: peer.clone(),
                public_key: "peer-public".to_string(),
                endpoint: None,
                allowed_ips: vec!["100.64.0.2/32".to_string()],
                persistent_keepalive_seconds: None,
            })
            .await?;
        let error = backend.remove_peer(&peer).await;

        assert!(matches!(
            error,
            Err(AgentError::WireGuard(message)) if message == "remove failed"
        ));
        assert_eq!(
            backend.peer_public_keys.read().await.get(&peer).cloned(),
            Some("peer-public".to_string())
        );
        Ok(())
    }

    #[tokio::test]
    async fn linux_wireguard_backend_creates_missing_interface() -> Result<(), AgentError> {
        let runner = RecordingRunner::with_missing_interface();
        let backend = LinuxWireGuardBackend::new("ipars0", runner.clone());

        backend.ensure_interface().await?;

        assert_eq!(
            runner.commands().await,
            vec![
                LinuxCommand::new("ip", ["link", "show", "dev", "ipars0"]),
                LinuxCommand::new("ip", ["link", "add", "dev", "ipars0", "type", "wireguard"],),
                LinuxCommand::new("ip", ["link", "set", "up", "dev", "ipars0"]),
            ]
        );
        Ok(())
    }

    #[test]
    fn kernel_wireguard_backend_tracks_namespace() -> Result<(), Box<dyn std::error::Error>> {
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let backend = KernelWireGuardBackend::new_in_namespace("ipars0", namespace.clone());

        assert_eq!(backend.namespace(), Some(&namespace));
        assert_eq!(KernelWireGuardBackend::new("ipars0").namespace(), None);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_wireguard_backend_builds_netlink_peer_config() -> Result<(), AgentError> {
        let public_key =
            parse_wireguard_public_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")?;
        let config = WireGuardPeerConfig {
            peer: NodeId::from_string("node-a"),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            endpoint: Some("203.0.113.10:51820".to_string()),
            allowed_ips: vec!["100.64.0.2/32".to_string(), "fd00::2/128".to_string()],
            persistent_keepalive_seconds: Some(25),
        };

        let peer = netlink_peer_config(&config, public_key)?;

        assert_eq!(public_key, [0; 32]);
        assert!(peer.0.contains(&WireguardPeerAttribute::PublicKey([0; 32])));
        assert!(peer.0.contains(&WireguardPeerAttribute::Flags(
            WireguardPeerFlags::ReplaceAllowedIps
        )));
        assert!(peer
            .0
            .contains(&WireguardPeerAttribute::Endpoint(SocketAddr::from((
                [203, 0, 113, 10],
                51_820
            )))));
        assert!(peer
            .0
            .contains(&WireguardPeerAttribute::PersistentKeepalive(25)));
        let allowed_ips = peer.0.iter().find_map(|attribute| match attribute {
            WireguardPeerAttribute::AllowedIps(allowed_ips) => Some(allowed_ips),
            _ => None,
        });
        assert_eq!(
            allowed_ips,
            Some(&vec![
                WireguardAllowedIp(vec![
                    WireguardAllowedIpAttr::Family(WireguardAddressFamily::Ipv4),
                    WireguardAllowedIpAttr::IpAddr("100.64.0.2".parse().map_err(|error| {
                        AgentError::WireGuard(format!("test IP parse failed: {error}"))
                    })?),
                    WireguardAllowedIpAttr::Cidr(32),
                ]),
                WireguardAllowedIp(vec![
                    WireguardAllowedIpAttr::Family(WireguardAddressFamily::Ipv6),
                    WireguardAllowedIpAttr::IpAddr("fd00::2".parse().map_err(|error| {
                        AgentError::WireGuard(format!("test IP parse failed: {error}"))
                    })?),
                    WireguardAllowedIpAttr::Cidr(128),
                ]),
            ])
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_wireguard_backend_rejects_unresolved_endpoint() {
        let config = WireGuardPeerConfig {
            peer: NodeId::from_string("node-a"),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            endpoint: Some("peer.example.com:51820".to_string()),
            allowed_ips: vec!["100.64.0.2/32".to_string()],
            persistent_keepalive_seconds: None,
        };

        let error = netlink_peer_config(&config, [0; 32]);

        assert!(matches!(
            error,
            Err(AgentError::WireGuard(message))
                if message.contains("requires socket-address endpoints")
        ));
    }

    #[tokio::test]
    async fn peer_map_applier_configures_wireguard_and_routes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wireguard = MemoryWireGuardBackend::default();
        let route_manager = RecordingRouteManager::default();
        let applier = PeerMapApplier::new("ipars0", wireguard, route_manager);
        let peer_id = NodeId::from_string("peer-a");
        let advertised_route = Route {
            id: "advertised-a".to_string(),
            cidr: "10.10.0.0/16".parse()?,
            advertised_by: peer_id.clone(),
            via: Some(peer_id.clone()),
            metric: 50,
            tags: Default::default(),
        };
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
            "wg-peer-public",
            vec![
                EndpointCandidate {
                    node_id: peer_id.clone(),
                    kind: EndpointCandidateKind::StunReflexive,
                    addr: SocketAddr::from(([198, 51, 100, 20], 51820)),
                    observed_at: Utc::now(),
                    priority: 100,
                    cost: 1,
                    source: CandidateSource::StunProbe,
                },
                EndpointCandidate {
                    node_id: peer_id.clone(),
                    kind: EndpointCandidateKind::PublicUdp,
                    addr: SocketAddr::from(([203, 0, 113, 10], 51820)),
                    observed_at: Utc::now(),
                    priority: 10,
                    cost: 50,
                    source: CandidateSource::ControlPlane,
                },
            ],
            vec![advertised_route],
        );

        let summary = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer],
                generated_at: Utc::now(),
            })
            .await?;

        assert_eq!(
            summary,
            PeerMapApplySummary {
                peers_applied: 1,
                peers_removed: 0,
                routes_applied: 2,
            }
        );

        let wireguard_peers = applier.wireguard.peers.read().await;
        let config = wireguard_peers
            .get(&peer_id)
            .ok_or_else(|| AgentError::MissingPeer(peer_id.clone()))?;
        assert_eq!(config.public_key, "wg-peer-public");
        assert_eq!(config.allowed_ips, vec!["100.64.0.2/32"]);
        assert_eq!(config.endpoint.as_deref(), Some("203.0.113.10:51820"));
        assert_eq!(config.persistent_keepalive_seconds, Some(25));
        drop(wireguard_peers);

        let applied = applier.route_manager.applied.read().await;
        let plan = applied
            .first()
            .ok_or_else(|| AgentError::RoutePlanning("missing route plan".to_string()))?;
        assert_eq!(plan.interface, "ipars0");
        assert!(plan.policy_rules.is_empty());
        assert_eq!(plan.routes.len(), 2);
        assert_eq!(plan.routes[0].cidr, "100.64.0.2/32".parse()?);
        assert_eq!(plan.routes[0].metric, 10);
        assert_eq!(plan.routes[1].cidr, "10.10.0.0/16".parse()?);
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_uses_relay_forwarder_endpoint_for_active_relay_path(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let local_id = runtime.state().node_id.clone();
        let peer_id = NodeId::from_string("peer-relay");
        let relay_id = NodeId::from_string("relay-a");
        let forwarder_endpoint = SocketAddr::from(([127, 0, 0, 1], 52_000));
        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(local_id, peer_id.clone()),
                selected_state: PathState::Relay,
                selected_candidate: None,
                relay_node: Some(relay_id.clone()),
                score: PathScore {
                    value: 70.0,
                    reasons: Vec::new(),
                },
                updated_at: Utc::now(),
                pinned: false,
            })
            .await;
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: peer_id.clone(),
                relay_node: relay_id,
                relay_endpoint: SocketAddr::from(([203, 0, 113, 30], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-a".to_string(),
                session_token: "secret".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
            })
            .await;
        runtime
            .upsert_relay_forwarder_endpoint(peer_id.clone(), forwarder_endpoint)
            .await;

        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        )
        .with_endpoint_resolver(RuntimePeerEndpointResolver::new(runtime));
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)),
            "wg-peer-public",
            vec![EndpointCandidate {
                node_id: peer_id.clone(),
                kind: EndpointCandidateKind::PublicUdp,
                addr: SocketAddr::from(([203, 0, 113, 10], 51820)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::ControlPlane,
            }],
            Vec::new(),
        );

        applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer],
                generated_at: Utc::now(),
            })
            .await?;

        let wireguard_peers = applier.wireguard.peers.read().await;
        let config = wireguard_peers
            .get(&peer_id)
            .ok_or_else(|| AgentError::MissingPeer(peer_id.clone()))?;
        assert_eq!(config.endpoint.as_deref(), Some("127.0.0.1:52000"));
        assert_eq!(config.persistent_keepalive_seconds, Some(25));
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_prunes_idle_unpinned_peers() -> Result<(), Box<dyn std::error::Error>>
    {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy {
                idle_timeout_seconds: 10,
                ..ClusterPolicy::default()
            },
        ));
        let active_peer_id = NodeId::from_string("peer-active");
        let inactive_peer_id = NodeId::from_string("peer-inactive");
        let pinned_peer_id = NodeId::from_string("peer-pinned");
        runtime
            .record_peer_activity(active_peer_id.clone(), Utc::now(), false)
            .await;
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        )
        .with_lazy_connect_runtime(runtime.clone());
        let active_peer = peer_record(
            active_peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10)),
            "wg-active",
            vec![EndpointCandidate {
                node_id: active_peer_id.clone(),
                kind: EndpointCandidateKind::PublicUdp,
                addr: SocketAddr::from(([203, 0, 113, 10], 51820)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::ControlPlane,
            }],
            Vec::new(),
        );
        let inactive_peer = peer_record(
            inactive_peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 11)),
            "wg-inactive",
            Vec::new(),
            Vec::new(),
        );
        let mut pinned_peer = peer_record(
            pinned_peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 12)),
            "wg-pinned",
            Vec::new(),
            Vec::new(),
        );
        pinned_peer.role = Role::control_plane();
        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: vec![active_peer, inactive_peer, pinned_peer],
            generated_at: Utc::now(),
        };

        let first = applier.apply_peer_map(peer_map.clone()).await?;

        assert_eq!(
            first,
            PeerMapApplySummary {
                peers_applied: 2,
                peers_removed: 0,
                routes_applied: 2,
            }
        );
        let wireguard_peers = applier.wireguard.peers.read().await;
        assert!(wireguard_peers.contains_key(&active_peer_id));
        assert!(!wireguard_peers.contains_key(&inactive_peer_id));
        assert!(wireguard_peers.contains_key(&pinned_peer_id));
        drop(wireguard_peers);

        runtime
            .record_peer_activity(
                active_peer_id.clone(),
                Utc::now() - ChronoDuration::seconds(30),
                false,
            )
            .await;
        let second = applier.apply_peer_map(peer_map).await?;

        assert_eq!(
            second,
            PeerMapApplySummary {
                peers_applied: 1,
                peers_removed: 1,
                routes_applied: 1,
            }
        );
        let wireguard_peers = applier.wireguard.peers.read().await;
        assert!(!wireguard_peers.contains_key(&active_peer_id));
        assert!(!wireguard_peers.contains_key(&inactive_peer_id));
        assert!(wireguard_peers.contains_key(&pinned_peer_id));
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_sync_fetches_and_applies_once() -> Result<(), AgentError> {
        let node_id = NodeId::from_string("local");
        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: Vec::new(),
            generated_at: Utc::now(),
        };
        let source = StaticPeerMapSource::new(node_id.clone(), peer_map.clone());
        let sink = RecordingPeerMapSink::new(PeerMapApplySummary {
            peers_applied: 3,
            peers_removed: 0,
            routes_applied: 5,
        });
        let sync = PeerMapSync::new(node_id.clone(), source.clone(), sink.clone());

        let summary = sync.sync_once().await?;

        assert_eq!(
            summary,
            PeerMapApplySummary {
                peers_applied: 3,
                peers_removed: 0,
                routes_applied: 5,
            }
        );
        assert_eq!(source.requests.read().await.as_slice(), &[node_id]);
        assert_eq!(sink.applied.read().await.as_slice(), &[peer_map]);
        Ok(())
    }

    #[test]
    fn file_state_store_creates_and_reloads_node_identity() -> Result<(), AgentError> {
        let path = temp_state_path("state");
        let store = FileAgentStateStore::new(&path);
        let created = store.load_or_create(Utc::now())?;
        let loaded = store.load_or_create(Utc::now())?;

        assert_eq!(created.node_id, loaded.node_id);
        assert_eq!(
            created.identity_public_key_b64,
            loaded.identity_key_pair()?.public_key_b64()
        );
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_collects_stun_candidate() -> Result<(), Box<dyn std::error::Error>> {
        let server = BindingStunServer::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move { server.serve_once().await });
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );

        let candidate = runtime
            .probe_stun(SocketAddr::from(([127, 0, 0, 1], 0)), server_addr)
            .await?;
        server_task.await??;

        assert_eq!(candidate.addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(runtime.status().await.candidate_count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_classifies_nat_from_multiple_stun_observations(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let first_server = Rfc5780StunServer::bind(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .await?;
        let first_server_addr = first_server.primary_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let first_task = tokio::spawn(async move { first_server.serve(shutdown_rx).await });
        let second_server = BindingStunServer::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let second_server_addr = second_server.local_addr()?;
        let second_task = tokio::spawn(async move { second_server.serve_once().await });
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );

        let classification = runtime
            .classify_nat(
                SocketAddr::from(([127, 0, 0, 1], 0)),
                vec![first_server_addr, second_server_addr],
            )
            .await?;
        second_task.await??;
        shutdown_tx.send(true)?;
        first_task.await??;

        assert_eq!(classification.observations.len(), 2);
        assert!(!classification.filtering_observations.is_empty());
        assert_eq!(classification.mapping_behavior, NatMappingBehavior::NoNat);
        assert_eq!(
            classification.filtering_behavior,
            NatFilteringBehavior::EndpointIndependent
        );
        assert_eq!(
            classification.strategy,
            NatTraversalStrategy::DirectCandidate
        );
        let status = runtime.status().await;
        assert_eq!(status.candidate_count, 2);
        assert_eq!(status.nat_classification, Some(classification));
        Ok(())
    }
}
