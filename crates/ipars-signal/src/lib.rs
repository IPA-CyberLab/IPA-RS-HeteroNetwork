use std::collections::BTreeMap;

use chrono::Utc;
use ipars_types::api::{
    SignalHolePunchPlanResponse, SignalNodeUpsertResponse, SignalPathRequest, SignalPathResponse,
};
use ipars_types::{
    ClusterPolicy, EndpointCandidate, EndpointCandidateKind, HealthState, NatClassification,
    NatTraversalStrategy, NodeHealth, NodeId, NodeRecord, PathMetrics, PathScore, PathState,
    PeerPathKey,
};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum SignalError {
    #[error("node not found: {0}")]
    NodeNotFound(NodeId),
}

#[derive(Debug)]
pub struct SignalRegistry {
    coordinator: SignalCoordinator,
    nodes: RwLock<BTreeMap<NodeId, NodeRecord>>,
    nat_classifications: RwLock<BTreeMap<NodeId, NatClassification>>,
    health: RwLock<BTreeMap<NodeId, NodeHealth>>,
}

impl SignalRegistry {
    pub fn new(policy: ClusterPolicy) -> Self {
        Self {
            coordinator: SignalCoordinator::new(policy),
            nodes: RwLock::new(BTreeMap::new()),
            nat_classifications: RwLock::new(BTreeMap::new()),
            health: RwLock::new(BTreeMap::new()),
        }
    }

    pub async fn upsert_node(&self, node: NodeRecord) -> SignalNodeUpsertResponse {
        self.upsert_node_with_nat(node, None).await
    }

    pub async fn upsert_node_with_nat(
        &self,
        node: NodeRecord,
        nat_classification: Option<NatClassification>,
    ) -> SignalNodeUpsertResponse {
        self.upsert_node_with_nat_and_health(node, nat_classification, None)
            .await
    }

    pub async fn upsert_node_with_nat_and_health(
        &self,
        node: NodeRecord,
        nat_classification: Option<NatClassification>,
        health: Option<NodeHealth>,
    ) -> SignalNodeUpsertResponse {
        let registered_at = Utc::now();
        match nat_classification {
            Some(classification) => {
                self.nat_classifications
                    .write()
                    .await
                    .insert(node.node_id.clone(), classification);
            }
            None => {
                self.nat_classifications.write().await.remove(&node.node_id);
            }
        }
        match health {
            Some(health) => {
                self.health
                    .write()
                    .await
                    .insert(node.node_id.clone(), health);
            }
            None => {
                self.health.write().await.remove(&node.node_id);
            }
        }
        self.nodes
            .write()
            .await
            .insert(node.node_id.clone(), node.clone());
        SignalNodeUpsertResponse {
            node,
            registered_at,
        }
    }

    pub async fn get_node(&self, node_id: &NodeId) -> Option<NodeRecord> {
        self.nodes.read().await.get(node_id).cloned()
    }

    pub async fn negotiate(
        &self,
        request: SignalPathRequest,
    ) -> Result<SignalPathResponse, SignalError> {
        let target = self
            .get_node(&request.target)
            .await
            .ok_or_else(|| SignalError::NodeNotFound(request.target.clone()))?;
        let target_nat_classification = self
            .nat_classifications
            .read()
            .await
            .get(&request.target)
            .cloned();
        let relays = self.relay_candidates().await;
        Ok(self.coordinator.negotiate(
            request,
            &target,
            target_nat_classification.as_ref(),
            &relays,
        ))
    }

    pub async fn hole_punch_plan(
        &self,
        source: NodeId,
        target: NodeId,
    ) -> Result<SignalHolePunchPlanResponse, SignalError> {
        let source_node = self
            .get_node(&source)
            .await
            .ok_or_else(|| SignalError::NodeNotFound(source.clone()))?;
        let target_node = self
            .get_node(&target)
            .await
            .ok_or_else(|| SignalError::NodeNotFound(target.clone()))?;
        let plan = self.coordinator.punch_plan(
            &source_node.endpoint_candidates,
            &target_node.endpoint_candidates,
        );

        Ok(SignalHolePunchPlanResponse {
            key: PeerPathKey::new(source, target),
            source_reflexive: plan.source_reflexive,
            target_reflexive: plan.target_reflexive,
            start_after_millis: plan.start_after_millis,
            expires_at: plan.expires_at,
        })
    }

    pub async fn relay_candidates(&self) -> Vec<NodeRecord> {
        let nodes = self.nodes.read().await;
        let health = self.health.read().await;
        let now = Utc::now();
        nodes
            .values()
            .filter(|node| {
                relay_candidate_allowed(
                    node,
                    health.get(&node.node_id),
                    now,
                    &self.coordinator.policy,
                )
            })
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct SignalCoordinator {
    policy: ClusterPolicy,
}

impl SignalCoordinator {
    pub fn new(policy: ClusterPolicy) -> Self {
        Self { policy }
    }

    pub fn negotiate(
        &self,
        request: SignalPathRequest,
        target: &NodeRecord,
        target_nat_classification: Option<&NatClassification>,
        relays: &[NodeRecord],
    ) -> SignalPathResponse {
        let preferred_state = self.preferred_state(
            &request.source_candidates,
            request.source_nat_classification.as_ref(),
            target,
            target_nat_classification,
        );
        let relay_candidates = relays
            .iter()
            .filter(|relay| {
                relay
                    .relay_capability
                    .as_ref()
                    .map(|capability| capability.can_admit())
                    .unwrap_or(false)
            })
            .cloned()
            .collect::<Vec<_>>();

        let usable_state = if preferred_state == PathState::Unreachable
            && self.policy.allow_relay_fallback
            && !relay_candidates.is_empty()
        {
            PathState::Relay
        } else {
            preferred_state
        };

        let metrics = PathMetrics {
            relay_load: relay_candidates
                .first()
                .and_then(|relay| relay.relay_capability.as_ref())
                .map(|capability| {
                    if capability.max_sessions == 0 {
                        1.0
                    } else {
                        capability.active_sessions as f32 / capability.max_sessions as f32
                    }
                }),
            ..PathMetrics::default()
        };

        SignalPathResponse {
            key: PeerPathKey::new(request.source, request.target),
            target_candidates: target.endpoint_candidates.clone(),
            relay_candidates,
            preferred_state: usable_state,
            score: PathScore::calculate(usable_state, &metrics, true, 0),
        }
    }

    pub fn punch_plan(
        &self,
        source: &[EndpointCandidate],
        target: &[EndpointCandidate],
    ) -> HolePunchPlan {
        let source_reflexive = source
            .iter()
            .find(|candidate| candidate.kind == EndpointCandidateKind::StunReflexive)
            .cloned();
        let target_reflexive = target
            .iter()
            .find(|candidate| candidate.kind == EndpointCandidateKind::StunReflexive)
            .cloned();

        HolePunchPlan {
            source_reflexive,
            target_reflexive,
            start_after_millis: 50,
            expires_at: Utc::now() + chrono::Duration::seconds(5),
        }
    }

    fn preferred_state(
        &self,
        source_candidates: &[EndpointCandidate],
        source_nat_classification: Option<&NatClassification>,
        target: &NodeRecord,
        target_nat_classification: Option<&NatClassification>,
    ) -> PathState {
        if self.policy.allow_ipv6_direct
            && source_candidates
                .iter()
                .any(|candidate| candidate.kind == EndpointCandidateKind::Ipv6)
            && target
                .endpoint_candidates
                .iter()
                .any(|candidate| candidate.kind == EndpointCandidateKind::Ipv6)
        {
            return PathState::DirectIpv6;
        }

        if target
            .endpoint_candidates
            .iter()
            .any(|candidate| candidate.kind == EndpointCandidateKind::PublicUdp)
        {
            return PathState::DirectPublic;
        }

        if self.policy.allow_nat_traversal
            && source_candidates
                .iter()
                .any(|candidate| candidate.kind == EndpointCandidateKind::StunReflexive)
            && target
                .endpoint_candidates
                .iter()
                .any(|candidate| candidate.kind == EndpointCandidateKind::StunReflexive)
            && nat_classifications_allow_hole_punch(
                source_nat_classification,
                target_nat_classification,
            )
        {
            return PathState::DirectNatTraversal;
        }

        PathState::Unreachable
    }
}

fn nat_classifications_allow_hole_punch(
    source: Option<&NatClassification>,
    target: Option<&NatClassification>,
) -> bool {
    nat_classification_allows_hole_punch(source) && nat_classification_allows_hole_punch(target)
}

fn nat_classification_allows_hole_punch(classification: Option<&NatClassification>) -> bool {
    match classification.map(|classification| classification.strategy) {
        None => true,
        Some(NatTraversalStrategy::DirectCandidate)
        | Some(NatTraversalStrategy::CoordinatedHolePunch) => true,
        Some(NatTraversalStrategy::RelayPreferred)
        | Some(NatTraversalStrategy::InsufficientData) => false,
    }
}

fn relay_candidate_allowed(
    node: &NodeRecord,
    health: Option<&NodeHealth>,
    now: chrono::DateTime<Utc>,
    policy: &ClusterPolicy,
) -> bool {
    node.relay_capability
        .as_ref()
        .is_some_and(|capability| capability.can_admit())
        && relay_health_allows(health, now, policy.relay_health_ttl_seconds)
}

fn relay_health_allows(
    health: Option<&NodeHealth>,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> bool {
    let Some(health) = health else {
        return false;
    };
    if health.state != HealthState::Healthy {
        return false;
    }
    match now.signed_duration_since(health.last_seen_at).to_std() {
        Ok(age) => age <= std::time::Duration::from_secs(ttl_seconds),
        Err(_) => true,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HolePunchPlan {
    pub source_reflexive: Option<EndpointCandidate>,
    pub target_reflexive: Option<EndpointCandidate>,
    pub start_after_millis: u64,
    pub expires_at: chrono::DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use ipars_types::{
        CandidateSource, ClusterId, HealthState, NatMappingBehavior, NodeHealth, NodeId,
        RelayCapability, Role, TokenPolicy, VpnIp,
    };

    use super::*;

    fn candidate(kind: EndpointCandidateKind) -> EndpointCandidate {
        EndpointCandidate {
            node_id: NodeId::from_string("node-a"),
            kind,
            addr: SocketAddr::from(([203, 0, 113, 10], 51820)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::StunProbe,
        }
    }

    fn target(candidates: Vec<EndpointCandidate>) -> NodeRecord {
        NodeRecord {
            node_id: NodeId::from_string("node-b"),
            cluster_id: ClusterId::new(),
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
            identity_public_key: "identity".to_string(),
            wireguard_public_key: "wg".to_string(),
            role: Role::edge(),
            tags: BTreeSet::new(),
            endpoint_candidates: candidates,
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        }
    }

    fn relay() -> NodeRecord {
        NodeRecord {
            node_id: NodeId::from_string("relay-a"),
            cluster_id: ClusterId::new(),
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10))),
            identity_public_key: "identity-relay".to_string(),
            wireguard_public_key: "wg-relay".to_string(),
            role: Role::from_string("relay"),
            tags: BTreeSet::new(),
            endpoint_candidates: Vec::new(),
            relay_capability: Some(RelayCapability {
                enabled_by_policy: true,
                public_endpoint: Some(SocketAddr::from(([203, 0, 113, 20], 51820))),
                admission_url: Some("http://203.0.113.20:9580".to_string()),
                max_sessions: 10,
                active_sessions: 0,
                max_mbps: 1000,
                e2e_only: true,
            }),
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        }
    }

    fn healthy_health() -> NodeHealth {
        NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: Utc::now(),
            latency_ms: Some(1.0),
            relay_load: Some(0.1),
            message: None,
        }
    }

    #[test]
    fn direct_public_is_preferred_when_target_has_public_udp() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![candidate(EndpointCandidateKind::StunReflexive)],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![candidate(EndpointCandidateKind::PublicUdp)]),
            None,
            &[],
        );

        assert_eq!(response.preferred_state, PathState::DirectPublic);
    }

    #[tokio::test]
    async fn registry_uses_relay_fallback_when_direct_is_unreachable() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        registry.upsert_node(target(Vec::new())).await;
        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(healthy_health()))
            .await;

        let response = registry
            .negotiate(SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: Vec::new(),
                source_nat_classification: None,
                desired_routes: Vec::new(),
            })
            .await?;

        assert_eq!(response.preferred_state, PathState::Relay);
        assert_eq!(response.relay_candidates.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn registry_ignores_relay_without_admission_url() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let mut relay = relay();
        if let Some(capability) = relay.relay_capability.as_mut() {
            capability.admission_url = None;
        }
        registry.upsert_node(target(Vec::new())).await;
        registry
            .upsert_node_with_nat_and_health(relay, None, Some(healthy_health()))
            .await;

        let response = registry
            .negotiate(SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: Vec::new(),
                source_nat_classification: None,
                desired_routes: Vec::new(),
            })
            .await?;

        assert_eq!(response.preferred_state, PathState::Unreachable);
        assert!(response.relay_candidates.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn registry_uses_relay_when_nat_classification_prefers_relay() -> Result<(), SignalError>
    {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let mut source = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        source.node_id = NodeId::from_string("node-a");
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        registry
            .upsert_node_with_nat(target, Some(relay_preferred_nat()))
            .await;
        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(healthy_health()))
            .await;

        let response = registry
            .negotiate(SignalPathRequest {
                source: source.node_id.clone(),
                target: NodeId::from_string("node-b"),
                source_candidates: source.endpoint_candidates.clone(),
                source_nat_classification: Some(relay_preferred_nat()),
                desired_routes: Vec::new(),
            })
            .await?;

        assert_eq!(response.preferred_state, PathState::Relay);
        assert_eq!(response.relay_candidates.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn registry_requires_fresh_healthy_relay_health() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        registry.upsert_node(target(Vec::new())).await;

        registry.upsert_node(relay()).await;
        assert!(registry.relay_candidates().await.is_empty());

        let mut unhealthy = healthy_health();
        unhealthy.state = HealthState::Unhealthy;
        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(unhealthy))
            .await;
        assert!(registry.relay_candidates().await.is_empty());

        let mut stale = healthy_health();
        stale.last_seen_at = Utc::now() - chrono::Duration::seconds(120);
        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(stale))
            .await;
        assert!(registry.relay_candidates().await.is_empty());

        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(healthy_health()))
            .await;
        assert_eq!(registry.relay_candidates().await.len(), 1);

        let response = registry
            .negotiate(SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: Vec::new(),
                source_nat_classification: None,
                desired_routes: Vec::new(),
            })
            .await?;
        assert_eq!(response.preferred_state, PathState::Relay);
        assert_eq!(response.relay_candidates.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn registry_clears_nat_classification_when_upsert_omits_it() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        registry
            .upsert_node_with_nat(target.clone(), Some(relay_preferred_nat()))
            .await;
        registry.upsert_node(target).await;

        let response = registry
            .negotiate(SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![candidate(EndpointCandidateKind::StunReflexive)],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            })
            .await?;

        assert_eq!(response.preferred_state, PathState::DirectNatTraversal);
        Ok(())
    }

    #[tokio::test]
    async fn registry_builds_hole_punch_plan_for_reflexive_candidates() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let mut source = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        source.node_id = NodeId::from_string("node-a");
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        registry.upsert_node(source).await;
        registry.upsert_node(target).await;

        let plan = registry
            .hole_punch_plan(NodeId::from_string("node-a"), NodeId::from_string("node-b"))
            .await?;

        assert!(plan.source_reflexive.is_some());
        assert!(plan.target_reflexive.is_some());
        assert_eq!(plan.start_after_millis, 50);
        Ok(())
    }

    fn relay_preferred_nat() -> NatClassification {
        NatClassification {
            local_addr: SocketAddr::from(([10, 0, 0, 10], 50_000)),
            mapping_behavior: NatMappingBehavior::AddressAndPortDependent,
            filtering_behavior: ipars_types::NatFilteringBehavior::Unknown,
            observed_endpoint: None,
            observations: Vec::new(),
            filtering_observations: Vec::new(),
            strategy: NatTraversalStrategy::RelayPreferred,
            confidence: 0.9,
            assessed_at: Utc::now(),
        }
    }
}
