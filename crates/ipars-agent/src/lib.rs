use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipars_crypto::{CryptoError, IdentityKeyPair, WireGuardKeyPair};
use ipars_stun::{StunError, StunProbe, UdpStunProbe};
use ipars_types::api::AgentStatusResponse;
use ipars_types::{
    ClusterPolicy, EndpointCandidate, NodeId, PathRecord, PathScore, PathState, Role, Tag,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    lazy_connect: tokio::sync::RwLock<LazyConnectManager>,
}

impl AgentRuntime {
    pub fn new(state: AgentNodeState, policy: ClusterPolicy) -> Self {
        Self {
            state,
            candidates: tokio::sync::RwLock::new(Vec::new()),
            lazy_connect: tokio::sync::RwLock::new(LazyConnectManager::new(policy)),
        }
    }

    pub fn state(&self) -> &AgentNodeState {
        &self.state
    }

    pub async fn status(&self) -> AgentStatusResponse {
        let candidates = self.candidates.read().await.clone();
        AgentStatusResponse {
            node_id: self.state.node_id.clone(),
            identity_public_key: self.state.identity_public_key_b64.clone(),
            wireguard_public_key: self.state.wireguard_public_key_b64.clone(),
            candidate_count: candidates.len(),
            candidates,
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

    pub async fn idle_peers_to_close(&self, now: DateTime<Utc>) -> Vec<NodeId> {
        self.lazy_connect.read().await.idle_peers_to_close(now)
    }
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

    pub fn is_pinned_by_policy(&self, role: &Role, tags: &BTreeSet<Tag>) -> bool {
        self.policy.pinned_roles.contains(role)
            || tags.iter().any(|tag| self.policy.pinned_tags.contains(tag))
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

    use chrono::Duration as ChronoDuration;
    use ipars_stun::EchoStunServer;
    use ipars_types::{PathMetrics, PeerPathKey};

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
        let server = EchoStunServer::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
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
}
