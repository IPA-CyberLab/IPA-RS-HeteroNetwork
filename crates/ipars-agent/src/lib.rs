use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipars_types::{ClusterPolicy, NodeId, PathRecord, PathScore, PathState, Role, Tag};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("wireguard backend error: {0}")]
    WireGuard(String),
    #[error("peer path does not exist: {0}")]
    MissingPeer(NodeId),
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
    use chrono::Duration as ChronoDuration;
    use ipars_types::{PathMetrics, PeerPathKey};

    use super::*;

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
}
