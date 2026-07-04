use std::collections::BTreeMap;

use chrono::Utc;
use ipars_types::api::{
    SignalHolePunchPlanResponse, SignalNodeUpsertResponse, SignalPathRequest, SignalPathResponse,
};
use ipars_types::{
    ClusterPolicy, EndpointCandidate, EndpointCandidateKind, NodeId, NodeRecord, PathMetrics,
    PathScore, PathState, PeerPathKey,
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
}

impl SignalRegistry {
    pub fn new(policy: ClusterPolicy) -> Self {
        Self {
            coordinator: SignalCoordinator::new(policy),
            nodes: RwLock::new(BTreeMap::new()),
        }
    }

    pub async fn upsert_node(&self, node: NodeRecord) -> SignalNodeUpsertResponse {
        let registered_at = Utc::now();
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
        let relays = self.relay_candidates().await;
        Ok(self.coordinator.negotiate(request, &target, &relays))
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
        self.nodes
            .read()
            .await
            .values()
            .filter(|node| {
                node.relay_capability
                    .as_ref()
                    .map(|capability| capability.can_admit())
                    .unwrap_or(false)
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
        relays: &[NodeRecord],
    ) -> SignalPathResponse {
        let preferred_state = self.preferred_state(&request.source_candidates, target);
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
        target: &NodeRecord,
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
        {
            return PathState::DirectNatTraversal;
        }

        PathState::Unreachable
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
        CandidateSource, ClusterId, NodeId, RelayCapability, Role, TokenPolicy, VpnIp,
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

    #[test]
    fn direct_public_is_preferred_when_target_has_public_udp() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![candidate(EndpointCandidateKind::StunReflexive)],
                desired_routes: Vec::new(),
            },
            &target(vec![candidate(EndpointCandidateKind::PublicUdp)]),
            &[],
        );

        assert_eq!(response.preferred_state, PathState::DirectPublic);
    }

    #[tokio::test]
    async fn registry_uses_relay_fallback_when_direct_is_unreachable() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        registry.upsert_node(target(Vec::new())).await;
        registry.upsert_node(relay()).await;

        let response = registry
            .negotiate(SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: Vec::new(),
                desired_routes: Vec::new(),
            })
            .await?;

        assert_eq!(response.preferred_state, PathState::Relay);
        assert_eq!(response.relay_candidates.len(), 1);
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
}
