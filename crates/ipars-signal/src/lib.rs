use chrono::Utc;
use ipars_types::api::{SignalPathRequest, SignalPathResponse};
use ipars_types::{
    ClusterPolicy, EndpointCandidate, EndpointCandidateKind, NodeRecord, PathMetrics, PathScore,
    PathState, PeerPathKey,
};

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

    use ipars_types::{CandidateSource, ClusterId, NodeId, Role, TokenPolicy, VpnIp};

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
}
