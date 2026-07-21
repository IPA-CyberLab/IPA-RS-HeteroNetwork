use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::Utc;
use ipars_types::api::{
    NatTraversalStrategyCount, PathStateCount, SignalHolePunchPlanResponse, SignalMetricsResponse,
    SignalNodeUpsertResponse, SignalPathRequest, SignalPathResponse,
};
use ipars_types::{
    endpoint_addr_is_usable, private_ip_addrs_share_subnet, socket_addr_is_globally_routable,
    AclAction, AclRule, ClusterPolicy, EndpointCandidate, EndpointCandidateKind, HealthState,
    NatClassification, NatTraversalStrategy, NodeHealth, NodeId, NodeRecord, PathMetrics,
    PathQualityObservation, PathScore, PathState, PeerPathKey, Route, TransportProtocol,
};
use ipnet::IpNet;
use thiserror::Error;
use tokio::sync::RwLock;

const PATH_STATE_METRIC_ORDER: [PathState; 5] = [
    PathState::DirectPublic,
    PathState::DirectIpv6,
    PathState::DirectNatTraversal,
    PathState::Relay,
    PathState::Unreachable,
];
const SIGNAL_TIMESTAMP_MAX_FUTURE_SKEW_SECONDS: u64 = 300;
const MAX_PATH_QUALITY_OBSERVATION_SAMPLES: u16 = 64;

#[derive(Debug, Error)]
pub enum SignalError {
    #[error("node not found: {0}")]
    NodeNotFound(NodeId),
    #[error("candidate for node {node_id} belongs to {candidate_node_id}")]
    CandidateOwnerMismatch {
        node_id: NodeId,
        candidate_node_id: NodeId,
    },
    #[error("candidate {kind:?} at {addr} for node {node_id} is invalid: {reason}")]
    CandidateInvalid {
        node_id: NodeId,
        kind: EndpointCandidateKind,
        addr: std::net::SocketAddr,
        reason: &'static str,
    },
    #[error("health report for node {node_id} is invalid: {reason}")]
    HealthInvalid {
        node_id: NodeId,
        reason: &'static str,
    },
    #[error("NAT classification for node {node_id} is invalid: {reason}")]
    NatClassificationInvalid {
        node_id: NodeId,
        reason: &'static str,
    },
    #[error("desired route {route} for target node {node_id} is invalid: {reason}")]
    DesiredRouteInvalid {
        node_id: NodeId,
        route: IpNet,
        reason: &'static str,
    },
    #[error("route {route_id} for node {node_id} is invalid: {reason}")]
    RouteInvalid {
        node_id: NodeId,
        route_id: String,
        reason: &'static str,
    },
    #[error("path quality observation from {source_node} to {target_node} is invalid: {reason}")]
    PathQualityObservationInvalid {
        source_node: NodeId,
        target_node: NodeId,
        reason: String,
    },
}

#[derive(Debug)]
pub struct SignalRegistry {
    coordinator: SignalCoordinator,
    nodes: RwLock<BTreeMap<NodeId, NodeRecord>>,
    nat_classifications: RwLock<BTreeMap<NodeId, NatClassification>>,
    health: RwLock<BTreeMap<NodeId, NodeHealth>>,
    node_upserts: AtomicU64,
    path_negotiations: AtomicU64,
    path_acl_denials: AtomicU64,
    relay_candidate_acl_denials: AtomicU64,
    path_quality_observation_accepted: AtomicU64,
    path_quality_observation_stale: AtomicU64,
    path_quality_observation_path_mismatch: AtomicU64,
    path_quality_observation_rejected: AtomicU64,
    direct_public_negotiations: AtomicU64,
    direct_ipv6_negotiations: AtomicU64,
    direct_nat_traversal_negotiations: AtomicU64,
    relay_negotiations: AtomicU64,
    unreachable_negotiations: AtomicU64,
    hole_punch_plans: AtomicU64,
    hole_punch_acl_denials: AtomicU64,
    hole_punch_nat_suppressions: AtomicU64,
    hole_punch_nat_suppression_direct_candidate: AtomicU64,
    hole_punch_nat_suppression_coordinated_hole_punch: AtomicU64,
    hole_punch_nat_suppression_relay_preferred: AtomicU64,
    hole_punch_nat_suppression_insufficient_data: AtomicU64,
}

impl SignalRegistry {
    pub fn new(policy: ClusterPolicy) -> Self {
        Self {
            coordinator: SignalCoordinator::new(policy),
            nodes: RwLock::new(BTreeMap::new()),
            nat_classifications: RwLock::new(BTreeMap::new()),
            health: RwLock::new(BTreeMap::new()),
            node_upserts: AtomicU64::new(0),
            path_negotiations: AtomicU64::new(0),
            path_acl_denials: AtomicU64::new(0),
            relay_candidate_acl_denials: AtomicU64::new(0),
            path_quality_observation_accepted: AtomicU64::new(0),
            path_quality_observation_stale: AtomicU64::new(0),
            path_quality_observation_path_mismatch: AtomicU64::new(0),
            path_quality_observation_rejected: AtomicU64::new(0),
            direct_public_negotiations: AtomicU64::new(0),
            direct_ipv6_negotiations: AtomicU64::new(0),
            direct_nat_traversal_negotiations: AtomicU64::new(0),
            relay_negotiations: AtomicU64::new(0),
            unreachable_negotiations: AtomicU64::new(0),
            hole_punch_plans: AtomicU64::new(0),
            hole_punch_acl_denials: AtomicU64::new(0),
            hole_punch_nat_suppressions: AtomicU64::new(0),
            hole_punch_nat_suppression_direct_candidate: AtomicU64::new(0),
            hole_punch_nat_suppression_coordinated_hole_punch: AtomicU64::new(0),
            hole_punch_nat_suppression_relay_preferred: AtomicU64::new(0),
            hole_punch_nat_suppression_insufficient_data: AtomicU64::new(0),
        }
    }

    pub async fn upsert_node(
        &self,
        node: NodeRecord,
    ) -> Result<SignalNodeUpsertResponse, SignalError> {
        self.upsert_node_with_nat(node, None).await
    }

    pub async fn upsert_node_with_nat(
        &self,
        node: NodeRecord,
        nat_classification: Option<NatClassification>,
    ) -> Result<SignalNodeUpsertResponse, SignalError> {
        self.upsert_node_with_nat_and_health(node, nat_classification, None)
            .await
    }

    pub async fn upsert_node_with_nat_and_health(
        &self,
        mut node: NodeRecord,
        nat_classification: Option<NatClassification>,
        health: Option<NodeHealth>,
    ) -> Result<SignalNodeUpsertResponse, SignalError> {
        let registered_at = Utc::now();
        validate_signal_routes(&node.node_id, &node.routes)?;
        validate_endpoint_candidates(&node.node_id, &node.endpoint_candidates, registered_at)?;
        if let Some(health) = health.as_ref() {
            validate_health_report(&node.node_id, health, registered_at)?;
        }
        if let Some(classification) = nat_classification.as_ref() {
            validate_nat_classification(&node.node_id, classification, registered_at)?;
        }
        normalize_relay_capability(&mut node);
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
        self.node_upserts.fetch_add(1, Ordering::Relaxed);
        Ok(SignalNodeUpsertResponse {
            node,
            registered_at,
        })
    }

    pub async fn get_node(&self, node_id: &NodeId) -> Option<NodeRecord> {
        self.nodes.read().await.get(node_id).cloned()
    }

    pub async fn remove_node(&self, node_id: &NodeId) -> bool {
        self.nat_classifications.write().await.remove(node_id);
        self.health.write().await.remove(node_id);
        self.nodes.write().await.remove(node_id).is_some()
    }

    pub async fn negotiate(
        &self,
        request: SignalPathRequest,
    ) -> Result<SignalPathResponse, SignalError> {
        self.negotiate_with_observation(request, None).await
    }

    pub async fn negotiate_with_observation(
        &self,
        mut request: SignalPathRequest,
        path_observation: Option<PathQualityObservation>,
    ) -> Result<SignalPathResponse, SignalError> {
        self.path_negotiations.fetch_add(1, Ordering::Relaxed);
        let now = Utc::now();
        let source_node = self
            .get_node(&request.source)
            .await
            .ok_or_else(|| SignalError::NodeNotFound(request.source.clone()))?;
        validate_endpoint_candidates(&request.source, &request.source_candidates, now)?;
        if let Some(classification) = request.source_nat_classification.as_ref() {
            validate_nat_classification(&request.source, classification, now)?;
        }
        let target = self
            .get_node(&request.target)
            .await
            .ok_or_else(|| SignalError::NodeNotFound(request.target.clone()))?;
        if let Some(observation) = path_observation.as_ref() {
            if let Err(error) = validate_path_quality_observation(
                &request.source,
                &request.target,
                observation,
                now,
            ) {
                self.path_quality_observation_rejected
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error);
            }
        }
        validate_desired_routes(&target, &request.desired_routes)?;
        if !acl_allows_path(
            &source_node,
            &target,
            &request.desired_routes,
            &self.coordinator.policy,
        ) {
            self.path_acl_denials.fetch_add(1, Ordering::Relaxed);
            let response = acl_denied_signal_path_response(request);
            self.record_path_quality_observation_result(path_observation.as_ref(), &response, now);
            self.record_path_negotiation_state(response.preferred_state);
            return Ok(response);
        }
        let nat_classifications = self.nat_classifications.read().await;
        let source_nat_classification = fresh_stored_nat_classification(
            nat_classifications.get(&request.source),
            request.source_nat_classification.take(),
            now,
            self.coordinator.policy.nat_classification_ttl_seconds,
        );
        let target_nat_classification = nat_classifications
            .get(&request.target)
            .filter(|classification| {
                nat_classification_is_fresh(
                    classification,
                    now,
                    self.coordinator.policy.nat_classification_ttl_seconds,
                )
            })
            .cloned();
        drop(nat_classifications);
        if let Some(source_nat_classification) = source_nat_classification {
            request.source_nat_classification = Some(source_nat_classification);
        }
        let mut relay_acl_denials = 0;
        let relays = self
            .relay_candidates()
            .await
            .into_iter()
            .filter(|relay| {
                let allowed = acl_allows_peer(&source_node, relay, &self.coordinator.policy);
                if !allowed {
                    relay_acl_denials += 1;
                }
                allowed
            })
            .collect::<Vec<_>>();
        if relay_acl_denials > 0 {
            self.relay_candidate_acl_denials
                .fetch_add(relay_acl_denials, Ordering::Relaxed);
        }
        let response = self.coordinator.negotiate_with_observation(
            request,
            &target,
            target_nat_classification.as_ref(),
            &relays,
            path_observation.as_ref(),
            now,
        );
        self.record_path_quality_observation_result(path_observation.as_ref(), &response, now);
        self.record_path_negotiation_state(response.preferred_state);
        Ok(response)
    }

    pub async fn hole_punch_plan(
        &self,
        source: NodeId,
        target: NodeId,
    ) -> Result<SignalHolePunchPlanResponse, SignalError> {
        self.hole_punch_plans.fetch_add(1, Ordering::Relaxed);
        let source_node = self
            .get_node(&source)
            .await
            .ok_or_else(|| SignalError::NodeNotFound(source.clone()))?;
        let target_node = self
            .get_node(&target)
            .await
            .ok_or_else(|| SignalError::NodeNotFound(target.clone()))?;
        let now = Utc::now();
        if !acl_allows_hole_punch_plan(&source_node, &target_node, &self.coordinator.policy) {
            self.hole_punch_acl_denials.fetch_add(1, Ordering::Relaxed);
            return Ok(SignalHolePunchPlanResponse {
                key: PeerPathKey::new(source, target),
                source_reflexive: None,
                target_reflexive: None,
                start_after_millis: 0,
                expires_at: now,
            });
        }
        let nat_classifications = self.nat_classifications.read().await;
        let source_nat_classification = nat_classifications
            .get(&source)
            .filter(|classification| {
                nat_classification_is_fresh(
                    classification,
                    now,
                    self.coordinator.policy.nat_classification_ttl_seconds,
                )
            })
            .cloned();
        let target_nat_classification = nat_classifications
            .get(&target)
            .filter(|classification| {
                nat_classification_is_fresh(
                    classification,
                    now,
                    self.coordinator.policy.nat_classification_ttl_seconds,
                )
            })
            .cloned();
        drop(nat_classifications);
        if !nat_classifications_allow_hole_punch(
            source_nat_classification.as_ref(),
            target_nat_classification.as_ref(),
            self.coordinator
                .policy
                .nat_classification_min_confidence_percent,
        ) {
            self.hole_punch_nat_suppressions
                .fetch_add(1, Ordering::Relaxed);
            self.record_hole_punch_nat_suppression_strategies(
                source_nat_classification.as_ref(),
                target_nat_classification.as_ref(),
            );
        }
        let plan = self.coordinator.punch_plan(
            &source_node.endpoint_candidates,
            source_nat_classification.as_ref(),
            &target_node.endpoint_candidates,
            target_nat_classification.as_ref(),
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

    pub async fn metrics(&self) -> SignalMetricsResponse {
        let nodes = self.nodes.read().await;
        let nat_classifications = self.nat_classifications.read().await;
        let health = self.health.read().await;
        let now = Utc::now();
        let relay_health_ttl_seconds = self.coordinator.policy.relay_health_ttl_seconds;
        let endpoint_candidate_ttl_seconds = self.coordinator.policy.endpoint_candidate_ttl_seconds;
        let path_quality_observation_ttl_seconds =
            self.coordinator.policy.path_quality_observation_ttl_seconds;
        let nat_classification_ttl_seconds = self.coordinator.policy.nat_classification_ttl_seconds;
        let nat_classification_min_confidence_percent = self
            .coordinator
            .policy
            .nat_classification_min_confidence_percent;
        let mut healthy_node_count = 0;
        let mut degraded_node_count = 0;
        let mut unhealthy_node_count = 0;
        let mut stale_health_report_count = 0;

        for report in health.values() {
            match report.state {
                HealthState::Healthy => healthy_node_count += 1,
                HealthState::Degraded => degraded_node_count += 1,
                HealthState::Unhealthy => unhealthy_node_count += 1,
            }
            if !health_report_is_fresh(report, now, relay_health_ttl_seconds) {
                stale_health_report_count += 1;
            }
        }
        let stale_endpoint_candidate_count = nodes
            .values()
            .flat_map(|node| &node.endpoint_candidates)
            .filter(|candidate| {
                !endpoint_candidate_is_fresh(candidate, now, endpoint_candidate_ttl_seconds)
            })
            .count();
        let stale_nat_classification_count = nat_classifications
            .values()
            .filter(|classification| {
                !nat_classification_is_fresh(classification, now, nat_classification_ttl_seconds)
            })
            .count();
        let fresh_low_confidence_nat_classification_count = nat_classifications
            .values()
            .filter(|classification| {
                nat_classification_is_fresh(classification, now, nat_classification_ttl_seconds)
                    && !nat_classification_meets_confidence(
                        classification,
                        nat_classification_min_confidence_percent,
                    )
            })
            .count();
        let fresh_nat_classification_strategy_counts = nat_classification_strategy_counts(
            &nat_classifications,
            now,
            nat_classification_ttl_seconds,
        );

        let relay_candidate_count = nodes
            .values()
            .filter(|node| {
                relay_candidate_allowed(
                    node,
                    health.get(&node.node_id),
                    now,
                    &self.coordinator.policy,
                )
            })
            .count();

        SignalMetricsResponse {
            node_count: nodes.len(),
            relay_candidate_count,
            nat_classification_count: nat_classifications.len(),
            stale_nat_classification_count,
            fresh_low_confidence_nat_classification_count,
            fresh_nat_classification_strategy_counts,
            health_report_count: health.len(),
            healthy_node_count,
            degraded_node_count,
            unhealthy_node_count,
            stale_health_report_count,
            stale_endpoint_candidate_count,
            node_upsert_count: self.node_upserts.load(Ordering::Relaxed),
            path_negotiation_count: self.path_negotiations.load(Ordering::Relaxed),
            path_acl_denied_count: self.path_acl_denials.load(Ordering::Relaxed),
            relay_candidate_acl_denied_count: self
                .relay_candidate_acl_denials
                .load(Ordering::Relaxed),
            path_quality_observation_accepted_count: self
                .path_quality_observation_accepted
                .load(Ordering::Relaxed),
            path_quality_observation_stale_count: self
                .path_quality_observation_stale
                .load(Ordering::Relaxed),
            path_quality_observation_path_mismatch_count: self
                .path_quality_observation_path_mismatch
                .load(Ordering::Relaxed),
            path_quality_observation_rejected_count: self
                .path_quality_observation_rejected
                .load(Ordering::Relaxed),
            path_negotiation_state_counts: self.path_negotiation_state_counts(),
            hole_punch_plan_count: self.hole_punch_plans.load(Ordering::Relaxed),
            hole_punch_acl_denied_count: self.hole_punch_acl_denials.load(Ordering::Relaxed),
            hole_punch_nat_suppressed_count: self
                .hole_punch_nat_suppressions
                .load(Ordering::Relaxed),
            hole_punch_nat_suppressed_strategy_counts: self
                .hole_punch_nat_suppression_strategy_counts(),
            relay_health_ttl_seconds,
            endpoint_candidate_ttl_seconds,
            path_quality_observation_ttl_seconds,
            nat_classification_ttl_seconds,
            nat_classification_min_confidence_percent,
            generated_at: now,
        }
    }

    fn record_path_negotiation_state(&self, state: PathState) {
        match state {
            PathState::DirectPublic => &self.direct_public_negotiations,
            PathState::DirectIpv6 => &self.direct_ipv6_negotiations,
            PathState::DirectNatTraversal => &self.direct_nat_traversal_negotiations,
            PathState::Relay => &self.relay_negotiations,
            PathState::Unreachable => &self.unreachable_negotiations,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    fn record_path_quality_observation_result(
        &self,
        observation: Option<&PathQualityObservation>,
        response: &SignalPathResponse,
        now: chrono::DateTime<Utc>,
    ) {
        let Some(observation) = observation else {
            return;
        };
        if !path_quality_observation_is_fresh(
            observation,
            now,
            self.coordinator.policy.path_quality_observation_ttl_seconds,
        ) {
            self.path_quality_observation_stale
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        if matching_path_observation_metrics(
            response.preferred_state,
            &response.target_candidates,
            &response.relay_candidates,
            Some(observation),
            now,
            self.coordinator.policy.path_quality_observation_ttl_seconds,
        )
        .is_some()
        {
            self.path_quality_observation_accepted
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.path_quality_observation_path_mismatch
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn path_negotiation_state_counts(&self) -> Vec<PathStateCount> {
        PATH_STATE_METRIC_ORDER
            .into_iter()
            .map(|state| {
                let count = match state {
                    PathState::DirectPublic => {
                        self.direct_public_negotiations.load(Ordering::Relaxed)
                    }
                    PathState::DirectIpv6 => self.direct_ipv6_negotiations.load(Ordering::Relaxed),
                    PathState::DirectNatTraversal => self
                        .direct_nat_traversal_negotiations
                        .load(Ordering::Relaxed),
                    PathState::Relay => self.relay_negotiations.load(Ordering::Relaxed),
                    PathState::Unreachable => self.unreachable_negotiations.load(Ordering::Relaxed),
                };
                PathStateCount {
                    state,
                    count: count as usize,
                }
            })
            .collect()
    }

    fn record_hole_punch_nat_suppression_strategies(
        &self,
        source: Option<&NatClassification>,
        target: Option<&NatClassification>,
    ) {
        for strategy in [source, target].into_iter().filter_map(|classification| {
            nat_classification_hole_punch_suppression_strategy(
                classification,
                self.coordinator
                    .policy
                    .nat_classification_min_confidence_percent,
            )
        }) {
            self.hole_punch_nat_suppression_strategy_counter(strategy)
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn hole_punch_nat_suppression_strategy_counter(
        &self,
        strategy: NatTraversalStrategy,
    ) -> &AtomicU64 {
        match strategy {
            NatTraversalStrategy::DirectCandidate => {
                &self.hole_punch_nat_suppression_direct_candidate
            }
            NatTraversalStrategy::CoordinatedHolePunch => {
                &self.hole_punch_nat_suppression_coordinated_hole_punch
            }
            NatTraversalStrategy::RelayPreferred => {
                &self.hole_punch_nat_suppression_relay_preferred
            }
            NatTraversalStrategy::InsufficientData => {
                &self.hole_punch_nat_suppression_insufficient_data
            }
        }
    }

    fn hole_punch_nat_suppression_strategy_counts(&self) -> Vec<NatTraversalStrategyCount> {
        NatTraversalStrategy::ALL
            .into_iter()
            .map(|strategy| NatTraversalStrategyCount {
                strategy,
                count: self
                    .hole_punch_nat_suppression_strategy_counter(strategy)
                    .load(Ordering::Relaxed) as usize,
            })
            .collect()
    }
}

fn normalize_relay_capability(node: &mut NodeRecord) {
    if node
        .relay_capability
        .as_ref()
        .is_some_and(|capability| capability.can_admit())
    {
        return;
    }
    node.relay_capability = None;
}

fn nat_classification_strategy_counts(
    classifications: &BTreeMap<NodeId, NatClassification>,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> Vec<NatTraversalStrategyCount> {
    NatTraversalStrategy::ALL
        .into_iter()
        .map(|strategy| NatTraversalStrategyCount {
            strategy,
            count: classifications
                .values()
                .filter(|classification| {
                    classification.strategy == strategy
                        && nat_classification_is_fresh(classification, now, ttl_seconds)
                })
                .count(),
        })
        .collect()
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
        self.negotiate_with_observation(
            request,
            target,
            target_nat_classification,
            relays,
            None,
            Utc::now(),
        )
    }

    pub fn negotiate_with_observation(
        &self,
        request: SignalPathRequest,
        target: &NodeRecord,
        target_nat_classification: Option<&NatClassification>,
        relays: &[NodeRecord],
        path_observation: Option<&PathQualityObservation>,
        now: chrono::DateTime<Utc>,
    ) -> SignalPathResponse {
        let source_candidates = fresh_endpoint_candidates(
            &request.source_candidates,
            now,
            self.policy.endpoint_candidate_ttl_seconds,
        );
        let target_candidates = fresh_endpoint_candidates(
            &target.endpoint_candidates,
            now,
            self.policy.endpoint_candidate_ttl_seconds,
        );
        let preferred_state = self.preferred_state(
            &source_candidates,
            request.source_nat_classification.as_ref(),
            &target_candidates,
            target_nat_classification,
        );
        let mut relay_candidates = relays
            .iter()
            .filter(|relay| relay.node_id != request.source && relay.node_id != request.target)
            .filter(|relay| {
                relay
                    .relay_capability
                    .as_ref()
                    .map(|capability| capability.can_admit())
                    .unwrap_or(false)
            })
            .cloned()
            .collect::<Vec<_>>();
        relay_candidates.sort_by(compare_relay_candidates);

        let usable_state = if preferred_state == PathState::Unreachable
            && self.policy.allow_relay_fallback
            && !relay_candidates.is_empty()
        {
            PathState::Relay
        } else {
            preferred_state
        };

        if usable_state == PathState::Relay {
            prioritize_observed_relay(
                &mut relay_candidates,
                path_observation,
                now,
                self.policy.path_quality_observation_ttl_seconds,
            );
        }

        let mut metrics = matching_path_observation_metrics(
            usable_state,
            &target_candidates,
            &relay_candidates,
            path_observation,
            now,
            self.policy.path_quality_observation_ttl_seconds,
        )
        .unwrap_or_default();
        metrics.relay_load = relay_candidates
            .first()
            .and_then(|relay| relay.relay_capability.as_ref())
            .map(|capability| {
                if capability.max_sessions == 0 {
                    1.0
                } else {
                    capability.active_sessions as f32 / capability.max_sessions as f32
                }
            });
        let cost = path_candidate_cost(usable_state, &source_candidates, &target_candidates);

        SignalPathResponse {
            key: PeerPathKey::new(request.source, request.target),
            target_candidates,
            relay_candidates,
            preferred_state: usable_state,
            score: PathScore::calculate(usable_state, &metrics, true, cost),
        }
    }

    pub fn punch_plan(
        &self,
        source: &[EndpointCandidate],
        source_nat_classification: Option<&NatClassification>,
        target: &[EndpointCandidate],
        target_nat_classification: Option<&NatClassification>,
    ) -> HolePunchPlan {
        let now = Utc::now();
        if !nat_classifications_allow_hole_punch(
            source_nat_classification,
            target_nat_classification,
            self.policy.nat_classification_min_confidence_percent,
        ) {
            return HolePunchPlan {
                source_reflexive: None,
                target_reflexive: None,
                start_after_millis: 50,
                expires_at: now + chrono::Duration::seconds(5),
            };
        }

        let source =
            fresh_endpoint_candidates(source, now, self.policy.endpoint_candidate_ttl_seconds);
        let target =
            fresh_endpoint_candidates(target, now, self.policy.endpoint_candidate_ttl_seconds);
        let source_reflexive = source
            .iter()
            .find(|candidate| {
                candidate.kind == EndpointCandidateKind::StunReflexive
                    && socket_addr_is_globally_routable(candidate.addr)
            })
            .cloned();
        let target_reflexive = target
            .iter()
            .find(|candidate| {
                candidate.kind == EndpointCandidateKind::StunReflexive
                    && socket_addr_is_globally_routable(candidate.addr)
            })
            .cloned();

        HolePunchPlan {
            source_reflexive,
            target_reflexive,
            start_after_millis: 50,
            expires_at: now + chrono::Duration::seconds(5),
        }
    }

    fn preferred_state(
        &self,
        source_candidates: &[EndpointCandidate],
        source_nat_classification: Option<&NatClassification>,
        target_candidates: &[EndpointCandidate],
        target_nat_classification: Option<&NatClassification>,
    ) -> PathState {
        if self.policy.allow_ipv6_direct
            && source_candidates
                .iter()
                .any(|candidate| candidate.kind == EndpointCandidateKind::Ipv6)
            && target_candidates
                .iter()
                .any(|candidate| candidate.kind == EndpointCandidateKind::Ipv6)
        {
            return PathState::DirectIpv6;
        }

        if target_candidates
            .iter()
            .any(|candidate| candidate.kind == EndpointCandidateKind::PublicUdp)
        {
            return PathState::DirectPublic;
        }

        if self.policy.allow_nat_traversal
            && local_udp_candidates_share_private_subnet(source_candidates, target_candidates)
        {
            return PathState::DirectNatTraversal;
        }

        if self.policy.allow_nat_traversal
            && source_candidates.iter().any(|candidate| {
                candidate.kind == EndpointCandidateKind::StunReflexive
                    && socket_addr_is_globally_routable(candidate.addr)
            })
            && target_candidates.iter().any(|candidate| {
                candidate.kind == EndpointCandidateKind::StunReflexive
                    && socket_addr_is_globally_routable(candidate.addr)
            })
            && nat_classifications_allow_hole_punch(
                source_nat_classification,
                target_nat_classification,
                self.policy.nat_classification_min_confidence_percent,
            )
        {
            return PathState::DirectNatTraversal;
        }

        PathState::Unreachable
    }
}

fn local_udp_candidates_share_private_subnet(
    source: &[EndpointCandidate],
    target: &[EndpointCandidate],
) -> bool {
    source.iter().any(|source_candidate| {
        source_candidate.kind == EndpointCandidateKind::LocalUdp
            && endpoint_addr_is_usable(source_candidate.addr)
            && target.iter().any(|target_candidate| {
                target_candidate.kind == EndpointCandidateKind::LocalUdp
                    && endpoint_addr_is_usable(target_candidate.addr)
                    && private_ip_addrs_share_subnet(
                        source_candidate.addr.ip(),
                        target_candidate.addr.ip(),
                    )
            })
    })
}

fn validate_path_quality_observation(
    source: &NodeId,
    target: &NodeId,
    observation: &PathQualityObservation,
    now: chrono::DateTime<Utc>,
) -> Result<(), SignalError> {
    let invalid = |reason: String| SignalError::PathQualityObservationInvalid {
        source_node: source.clone(),
        target_node: target.clone(),
        reason,
    };
    observation
        .metrics
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    if observation.metrics.relay_load.is_some() {
        return Err(invalid(
            "relay_load must be omitted because Signal supplies authoritative relay load"
                .to_string(),
        ));
    }
    if observation.sample_count == 0
        || observation.sample_count > MAX_PATH_QUALITY_OBSERVATION_SAMPLES
    {
        return Err(invalid(format!(
            "sample_count must be between 1 and {MAX_PATH_QUALITY_OBSERVATION_SAMPLES}"
        )));
    }
    if observation.successful_sample_count > observation.sample_count {
        return Err(invalid(
            "successful_sample_count must not exceed sample_count".to_string(),
        ));
    }
    let lost = u64::from(observation.sample_count - observation.successful_sample_count);
    let expected_loss_ppm = (lost * 1_000_000 / u64::from(observation.sample_count)) as u32;
    if observation.metrics.loss_ppm != expected_loss_ppm {
        return Err(invalid(format!(
            "loss_ppm must equal {expected_loss_ppm} for the supplied sample counts"
        )));
    }
    match observation.successful_sample_count {
        0 if observation.metrics.latency_ms.is_some()
            || observation.metrics.jitter_ms.is_some() =>
        {
            return Err(invalid(
                "latency_ms and jitter_ms must be omitted when no samples succeeded".to_string(),
            ));
        }
        0 => {}
        1 if observation.metrics.latency_ms.is_none()
            || observation.metrics.jitter_ms.is_some() =>
        {
            return Err(invalid(
                "one successful sample requires latency_ms and no jitter_ms".to_string(),
            ));
        }
        1 => {}
        _ if observation.metrics.latency_ms.is_none()
            || observation.metrics.jitter_ms.is_none() =>
        {
            return Err(invalid(
                "multiple successful samples require latency_ms and jitter_ms".to_string(),
            ));
        }
        _ => {}
    }

    match observation.selected_state {
        state if state.is_direct() => {
            if observation.relay_node.is_some() {
                return Err(invalid(
                    "direct observations must not include relay_node".to_string(),
                ));
            }
            let candidate = observation.selected_candidate.as_ref().ok_or_else(|| {
                invalid("direct observations require selected_candidate".to_string())
            })?;
            if candidate.node_id != *target {
                return Err(invalid(
                    "selected_candidate must belong to the target node".to_string(),
                ));
            }
            if !state.allows_selected_candidate_kind(candidate.kind) {
                return Err(invalid(
                    "selected_candidate kind does not match selected_state".to_string(),
                ));
            }
            candidate
                .validate_kind_address()
                .map_err(|reason| invalid(reason.to_string()))?;
            if !endpoint_addr_is_usable(candidate.addr) {
                return Err(invalid(
                    "selected_candidate address is not usable".to_string(),
                ));
            }
        }
        PathState::Relay => {
            if observation.selected_candidate.is_some() {
                return Err(invalid(
                    "relay observations must not include selected_candidate".to_string(),
                ));
            }
            let relay = observation
                .relay_node
                .as_ref()
                .ok_or_else(|| invalid("relay observations require relay_node".to_string()))?;
            if relay == source || relay == target {
                return Err(invalid(
                    "relay_node must differ from source and target".to_string(),
                ));
            }
        }
        PathState::Unreachable => {
            return Err(invalid(
                "unreachable paths cannot produce quality observations".to_string(),
            ));
        }
        _ => unreachable!("all direct states are handled by the guarded arm"),
    }

    let future_skew = chrono::Duration::seconds(SIGNAL_TIMESTAMP_MAX_FUTURE_SKEW_SECONDS as i64);
    if observation.observed_at > now + future_skew {
        return Err(invalid("observed_at is too far in the future".to_string()));
    }
    Ok(())
}

fn path_quality_observation_is_fresh(
    observation: &PathQualityObservation,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> bool {
    now.signed_duration_since(observation.observed_at)
        .to_std()
        .map(|age| age <= Duration::from_secs(ttl_seconds))
        .unwrap_or(true)
}

fn prioritize_observed_relay(
    relay_candidates: &mut Vec<NodeRecord>,
    observation: Option<&PathQualityObservation>,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) {
    let Some(observation) = observation.filter(|observation| {
        observation.selected_state == PathState::Relay
            && path_quality_observation_is_fresh(observation, now, ttl_seconds)
    }) else {
        return;
    };
    let Some(relay_node) = observation.relay_node.as_ref() else {
        return;
    };
    if let Some(index) = relay_candidates
        .iter()
        .position(|relay| relay.node_id == *relay_node)
    {
        let relay = relay_candidates.remove(index);
        relay_candidates.insert(0, relay);
    }
}

fn matching_path_observation_metrics(
    state: PathState,
    target_candidates: &[EndpointCandidate],
    relay_candidates: &[NodeRecord],
    observation: Option<&PathQualityObservation>,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> Option<PathMetrics> {
    let observation = observation?;
    if observation.selected_state != state
        || !path_quality_observation_is_fresh(observation, now, ttl_seconds)
    {
        return None;
    }
    let matches_path = if state.is_direct() {
        selected_target_candidate(state, target_candidates).is_some_and(|selected| {
            observation
                .selected_candidate
                .as_ref()
                .is_some_and(|observed| endpoint_candidate_identity_matches(selected, observed))
        })
    } else if state == PathState::Relay {
        relay_candidates
            .first()
            .is_some_and(|relay| observation.relay_node.as_ref() == Some(&relay.node_id))
    } else {
        false
    };
    matches_path.then(|| observation.metrics.clone())
}

fn selected_target_candidate(
    state: PathState,
    target_candidates: &[EndpointCandidate],
) -> Option<&EndpointCandidate> {
    target_candidates
        .iter()
        .filter(|candidate| state.allows_selected_candidate_kind(candidate.kind))
        .min_by(|left, right| {
            left.cost
                .cmp(&right.cost)
                .then_with(|| right.priority.cmp(&left.priority))
        })
}

fn endpoint_candidate_identity_matches(
    left: &EndpointCandidate,
    right: &EndpointCandidate,
) -> bool {
    left.node_id == right.node_id && left.kind == right.kind && left.addr == right.addr
}

fn validate_endpoint_candidates(
    node_id: &NodeId,
    candidates: &[EndpointCandidate],
    now: chrono::DateTime<Utc>,
) -> Result<(), SignalError> {
    if let Some(candidate) = candidates
        .iter()
        .find(|candidate| candidate.node_id != *node_id)
    {
        return Err(SignalError::CandidateOwnerMismatch {
            node_id: node_id.clone(),
            candidate_node_id: candidate.node_id.clone(),
        });
    }
    if let Some((candidate, reason)) = candidates.iter().find_map(|candidate| {
        candidate
            .validate_kind_address()
            .err()
            .map(|reason| (candidate, reason))
    }) {
        return Err(SignalError::CandidateInvalid {
            node_id: node_id.clone(),
            kind: candidate.kind,
            addr: candidate.addr,
            reason,
        });
    }
    if let Some(candidate) = candidates.iter().find(|candidate| {
        !timestamp_not_after_skew(
            candidate.observed_at,
            now,
            Duration::from_secs(SIGNAL_TIMESTAMP_MAX_FUTURE_SKEW_SECONDS),
        )
    }) {
        return Err(SignalError::CandidateInvalid {
            node_id: node_id.clone(),
            kind: candidate.kind,
            addr: candidate.addr,
            reason: "observed_at is too far in the future",
        });
    }
    Ok(())
}

fn validate_health_report(
    node_id: &NodeId,
    health: &NodeHealth,
    now: chrono::DateTime<Utc>,
) -> Result<(), SignalError> {
    if !timestamp_not_after_skew(
        health.last_seen_at,
        now,
        Duration::from_secs(SIGNAL_TIMESTAMP_MAX_FUTURE_SKEW_SECONDS),
    ) {
        return Err(SignalError::HealthInvalid {
            node_id: node_id.clone(),
            reason: "last_seen_at is too far in the future",
        });
    }
    if let Some(latency_ms) = health.latency_ms {
        if !latency_ms.is_finite() || latency_ms < 0.0 {
            return Err(SignalError::HealthInvalid {
                node_id: node_id.clone(),
                reason: "latency_ms must be a finite non-negative value",
            });
        }
    }
    if let Some(relay_load) = health.relay_load {
        if !relay_load.is_finite() || !(0.0..=1.0).contains(&relay_load) {
            return Err(SignalError::HealthInvalid {
                node_id: node_id.clone(),
                reason: "relay_load must be a finite value between 0 and 1",
            });
        }
    }
    Ok(())
}

fn validate_nat_classification(
    node_id: &NodeId,
    classification: &NatClassification,
    now: chrono::DateTime<Utc>,
) -> Result<(), SignalError> {
    if !classification.public_state_is_supported() {
        return Err(SignalError::NatClassificationInvalid {
            node_id: node_id.clone(),
            reason: "public state requires matching globally routable no-NAT observations",
        });
    }
    validate_nat_addr(
        node_id,
        classification.local_addr,
        "local address is unusable",
    )?;
    if let Some(observed_endpoint) = classification.observed_endpoint {
        validate_nat_addr(node_id, observed_endpoint, "observed endpoint is unusable")?;
    }
    for observation in &classification.observations {
        validate_nat_addr(
            node_id,
            observation.local_addr,
            "NAT probe local address is unusable",
        )?;
        validate_nat_addr(
            node_id,
            observation.stun_server,
            "NAT probe STUN server endpoint is unusable",
        )?;
        validate_nat_addr(
            node_id,
            observation.reflexive_addr,
            "NAT probe reflexive endpoint is unusable",
        )?;
    }
    for observation in &classification.filtering_observations {
        validate_nat_addr(
            node_id,
            observation.local_addr,
            "NAT filtering local address is unusable",
        )?;
        validate_nat_addr(
            node_id,
            observation.stun_server,
            "NAT filtering STUN server endpoint is unusable",
        )?;
        if let Some(response_origin) = observation.response_origin {
            validate_nat_addr(
                node_id,
                response_origin,
                "NAT filtering response origin is unusable",
            )?;
        }
        if let Some(other_address) = observation.other_address {
            validate_nat_addr(
                node_id,
                other_address,
                "NAT filtering other-address endpoint is unusable",
            )?;
        }
    }
    if !timestamp_not_after_skew(
        classification.assessed_at,
        now,
        Duration::from_secs(SIGNAL_TIMESTAMP_MAX_FUTURE_SKEW_SECONDS),
    ) {
        return Err(SignalError::NatClassificationInvalid {
            node_id: node_id.clone(),
            reason: "assessed_at is too far in the future",
        });
    }
    if !classification.confidence.is_finite() || !(0.0..=1.0).contains(&classification.confidence) {
        return Err(SignalError::NatClassificationInvalid {
            node_id: node_id.clone(),
            reason: "confidence must be a finite value between 0 and 1",
        });
    }
    if classification.observations.iter().any(|observation| {
        !timestamp_not_after_skew(
            observation.observed_at,
            now,
            Duration::from_secs(SIGNAL_TIMESTAMP_MAX_FUTURE_SKEW_SECONDS),
        )
    }) {
        return Err(SignalError::NatClassificationInvalid {
            node_id: node_id.clone(),
            reason: "NAT probe observation timestamp is too far in the future",
        });
    }
    if classification
        .filtering_observations
        .iter()
        .any(|observation| {
            !timestamp_not_after_skew(
                observation.observed_at,
                now,
                Duration::from_secs(SIGNAL_TIMESTAMP_MAX_FUTURE_SKEW_SECONDS),
            )
        })
    {
        return Err(SignalError::NatClassificationInvalid {
            node_id: node_id.clone(),
            reason: "NAT filtering observation timestamp is too far in the future",
        });
    }
    Ok(())
}

fn validate_nat_addr(
    node_id: &NodeId,
    addr: std::net::SocketAddr,
    reason: &'static str,
) -> Result<(), SignalError> {
    if endpoint_addr_is_usable(addr) {
        Ok(())
    } else {
        Err(SignalError::NatClassificationInvalid {
            node_id: node_id.clone(),
            reason,
        })
    }
}

fn validate_desired_routes(
    target: &NodeRecord,
    desired_routes: &[IpNet],
) -> Result<(), SignalError> {
    let mut seen_routes = BTreeSet::new();
    for route in desired_routes {
        let canonical = route.trunc();
        if *route != canonical {
            return Err(SignalError::DesiredRouteInvalid {
                node_id: target.node_id.clone(),
                route: *route,
                reason: "route CIDR must be canonical",
            });
        }
        if !seen_routes.insert(*route) {
            return Err(SignalError::DesiredRouteInvalid {
                node_id: target.node_id.clone(),
                route: *route,
                reason: "desired routes must not repeat CIDR",
            });
        }
        let advertised_by_target = target.routes.iter().any(|advertised| {
            advertised.advertised_by == target.node_id && ipnet_contains(&advertised.cidr, route)
        });
        if !advertised_by_target {
            return Err(SignalError::DesiredRouteInvalid {
                node_id: target.node_id.clone(),
                route: *route,
                reason: "route is not advertised by target",
            });
        }
    }
    Ok(())
}

fn validate_signal_routes(node_id: &NodeId, routes: &[Route]) -> Result<(), SignalError> {
    let mut seen_route_ids = BTreeSet::new();
    let mut seen_route_cidrs = BTreeSet::new();
    for route in routes {
        validate_signal_route_id(node_id, &route.id)?;
        if !seen_route_ids.insert(route.id.as_str()) {
            return Err(SignalError::RouteInvalid {
                node_id: node_id.clone(),
                route_id: route.id.clone(),
                reason: "route ID is duplicated",
            });
        }
        if route.advertised_by != *node_id {
            return Err(SignalError::RouteInvalid {
                node_id: node_id.clone(),
                route_id: route.id.clone(),
                reason: "route must be advertised by the reporting node",
            });
        }
        if route.metric == 0 {
            return Err(SignalError::RouteInvalid {
                node_id: node_id.clone(),
                route_id: route.id.clone(),
                reason: "metric must be greater than zero",
            });
        }
        if restricted_advertised_route_cidr_reason(&route.cidr).is_some() {
            return Err(SignalError::RouteInvalid {
                node_id: node_id.clone(),
                route_id: route.id.clone(),
                reason: "route CIDR is restricted",
            });
        }
        let canonical = route.cidr.trunc();
        if route.cidr != canonical {
            return Err(SignalError::RouteInvalid {
                node_id: node_id.clone(),
                route_id: route.id.clone(),
                reason: "route CIDR must be canonical",
            });
        }
        if !seen_route_cidrs.insert(route.cidr) {
            return Err(SignalError::RouteInvalid {
                node_id: node_id.clone(),
                route_id: route.id.clone(),
                reason: "route CIDR is duplicated",
            });
        }
    }
    Ok(())
}

fn validate_signal_route_id(node_id: &NodeId, route_id: &str) -> Result<(), SignalError> {
    let reason = if route_id.is_empty() {
        Some("route ID cannot be empty")
    } else if route_id.len() > 128 {
        Some("route ID exceeds 128 bytes")
    } else if matches!(route_id, "." | "..") {
        Some("route ID must not be '.' or '..'")
    } else if !route_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        Some("route ID contains invalid characters")
    } else {
        None
    };

    if let Some(reason) = reason {
        Err(SignalError::RouteInvalid {
            node_id: node_id.clone(),
            route_id: route_id.to_string(),
            reason,
        })
    } else {
        Ok(())
    }
}

fn restricted_advertised_route_cidr_reason(cidr: &IpNet) -> Option<&'static str> {
    if cidr.prefix_len() == 0 {
        return Some("unrestricted");
    }
    match cidr {
        IpNet::V4(network) => restricted_advertised_ipv4_route_cidr_reason(network),
        IpNet::V6(network) => restricted_advertised_ipv6_route_cidr_reason(network),
    }
}

fn restricted_advertised_ipv4_route_cidr_reason(network: &ipnet::Ipv4Net) -> Option<&'static str> {
    let restricted = [
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(0, 0, 0, 0), 8),
            "unspecified",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 0), 8),
            "loopback",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(169, 254, 0, 0), 16),
            "link-local",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(224, 0, 0, 0), 4),
            "multicast",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(255, 255, 255, 255), 32),
            "broadcast",
        ),
    ];
    restricted
        .iter()
        .find_map(|(restricted, reason)| ipv4_cidrs_overlap(network, restricted).then_some(*reason))
}

fn restricted_advertised_ipv6_route_cidr_reason(network: &ipnet::Ipv6Net) -> Option<&'static str> {
    let restricted = [
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 128),
            "unspecified",
        ),
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::LOCALHOST, 128),
            "loopback",
        ),
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
            "link-local",
        ),
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
            "multicast",
        ),
    ];
    restricted
        .iter()
        .find_map(|(restricted, reason)| ipv6_cidrs_overlap(network, restricted).then_some(*reason))
}

fn ipv4_cidrs_overlap(left: &ipnet::Ipv4Net, right: &ipnet::Ipv4Net) -> bool {
    left.contains(&right.network())
        || left.contains(&right.broadcast())
        || right.contains(&left.network())
        || right.contains(&left.broadcast())
}

fn ipv6_cidrs_overlap(left: &ipnet::Ipv6Net, right: &ipnet::Ipv6Net) -> bool {
    left.contains(&right.network())
        || left.contains(&right.broadcast())
        || right.contains(&left.network())
        || right.contains(&left.broadcast())
}

fn timestamp_not_after_skew(
    timestamp: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
    max_skew: Duration,
) -> bool {
    let Ok(max_skew) = chrono::Duration::from_std(max_skew) else {
        return false;
    };
    timestamp <= now + max_skew
}

fn fresh_stored_nat_classification(
    stored: Option<&NatClassification>,
    requested: Option<NatClassification>,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> Option<NatClassification> {
    stored
        .filter(|classification| nat_classification_is_fresh(classification, now, ttl_seconds))
        .cloned()
        .or_else(|| {
            requested.filter(|classification| {
                nat_classification_is_fresh(classification, now, ttl_seconds)
            })
        })
}

fn nat_classification_is_fresh(
    classification: &NatClassification,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> bool {
    match now
        .signed_duration_since(classification.assessed_at)
        .to_std()
    {
        Ok(age) => age <= Duration::from_secs(ttl_seconds),
        Err(_) => true,
    }
}

fn fresh_endpoint_candidates(
    candidates: &[EndpointCandidate],
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> Vec<EndpointCandidate> {
    candidates
        .iter()
        .filter(|candidate| endpoint_candidate_is_fresh(candidate, now, ttl_seconds))
        .filter(|candidate| endpoint_addr_is_usable(candidate.addr))
        .cloned()
        .collect()
}

fn endpoint_candidate_is_fresh(
    candidate: &EndpointCandidate,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> bool {
    match now.signed_duration_since(candidate.observed_at).to_std() {
        Ok(age) => age <= Duration::from_secs(ttl_seconds),
        Err(_) => true,
    }
}

fn acl_denied_signal_path_response(request: SignalPathRequest) -> SignalPathResponse {
    SignalPathResponse {
        key: PeerPathKey::new(request.source, request.target),
        target_candidates: Vec::new(),
        relay_candidates: Vec::new(),
        preferred_state: PathState::Unreachable,
        score: PathScore::calculate(PathState::Unreachable, &PathMetrics::default(), false, 0),
    }
}

fn acl_allows_peer(source: &NodeRecord, target: &NodeRecord, policy: &ClusterPolicy) -> bool {
    if policy.acl_rules.is_empty() {
        return true;
    }

    acl_decision(source, target, None, policy).unwrap_or(false)
}

fn acl_allows_path(
    source: &NodeRecord,
    target: &NodeRecord,
    desired_routes: &[IpNet],
    policy: &ClusterPolicy,
) -> bool {
    if desired_routes.is_empty() {
        return acl_allows_peer(source, target, policy);
    }
    if policy.acl_rules.is_empty() {
        return true;
    }

    desired_routes
        .iter()
        .all(|route| acl_decision(source, target, Some(route), policy).unwrap_or(false))
}

fn acl_allows_hole_punch_plan(
    source: &NodeRecord,
    target: &NodeRecord,
    policy: &ClusterPolicy,
) -> bool {
    if acl_allows_peer(source, target, policy) {
        return true;
    }

    target.routes.iter().any(|route| {
        route.advertised_by == target.node_id
            && acl_decision(source, target, Some(&route.cidr), policy).unwrap_or(false)
    })
}

fn acl_decision(
    source: &NodeRecord,
    target: &NodeRecord,
    route: Option<&IpNet>,
    policy: &ClusterPolicy,
) -> Option<bool> {
    let mut allowed = None;
    for rule in &policy.acl_rules {
        if !acl_rule_matches(rule, source, target, route) {
            continue;
        }
        match rule.action {
            AclAction::Deny => return Some(false),
            AclAction::Allow => allowed = Some(true),
        }
    }
    allowed
}

fn acl_rule_matches(
    rule: &AclRule,
    source: &NodeRecord,
    target: &NodeRecord,
    route: Option<&IpNet>,
) -> bool {
    if rule.protocol != TransportProtocol::Any {
        return false;
    }
    if !rule.from_roles.is_empty() && !rule.from_roles.contains(&source.role) {
        return false;
    }
    if !rule.to_roles.is_empty() && !rule.to_roles.contains(&target.role) {
        return false;
    }
    if !rule.from_tags.is_empty() && rule.from_tags.is_disjoint(&source.tags) {
        return false;
    }
    if !rule.to_tags.is_empty() && rule.to_tags.is_disjoint(&target.tags) {
        return false;
    }
    match route {
        Some(route) => {
            rule.routes.is_empty()
                || rule
                    .routes
                    .iter()
                    .any(|allowed| ipnet_contains(allowed, route))
        }
        None => rule.routes.is_empty(),
    }
}

fn ipnet_contains(outer: &IpNet, inner: &IpNet) -> bool {
    match (outer, inner) {
        (IpNet::V4(outer), IpNet::V4(inner)) => {
            outer.prefix_len() <= inner.prefix_len() && outer.contains(&inner.addr())
        }
        (IpNet::V6(outer), IpNet::V6(inner)) => {
            outer.prefix_len() <= inner.prefix_len() && outer.contains(&inner.addr())
        }
        _ => false,
    }
}

fn nat_classifications_allow_hole_punch(
    source: Option<&NatClassification>,
    target: Option<&NatClassification>,
    min_confidence_percent: u8,
) -> bool {
    nat_classification_allows_hole_punch(source, min_confidence_percent)
        && nat_classification_allows_hole_punch(target, min_confidence_percent)
}

fn nat_classification_allows_hole_punch(
    classification: Option<&NatClassification>,
    min_confidence_percent: u8,
) -> bool {
    match classification {
        None => true,
        // An insufficient-data result is explicitly non-authoritative. Keep
        // trying the advertised reflexive candidate and let path probing or
        // relay fallback establish whether it works.
        Some(classification)
            if classification.strategy == NatTraversalStrategy::InsufficientData =>
        {
            true
        }
        Some(classification)
            if !nat_classification_meets_confidence(classification, min_confidence_percent) =>
        {
            false
        }
        Some(classification) => matches!(
            classification.strategy,
            NatTraversalStrategy::DirectCandidate | NatTraversalStrategy::CoordinatedHolePunch
        ),
    }
}

fn nat_classification_hole_punch_suppression_strategy(
    classification: Option<&NatClassification>,
    min_confidence_percent: u8,
) -> Option<NatTraversalStrategy> {
    let classification = classification?;
    if nat_classification_allows_hole_punch(Some(classification), min_confidence_percent) {
        None
    } else {
        Some(classification.strategy)
    }
}

fn nat_classification_meets_confidence(
    classification: &NatClassification,
    min_confidence_percent: u8,
) -> bool {
    classification.confidence.is_finite()
        && classification.confidence * 100.0 >= min_confidence_percent as f32
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
    health_report_is_fresh(health, now, ttl_seconds)
}

fn compare_relay_candidates(left: &NodeRecord, right: &NodeRecord) -> std::cmp::Ordering {
    match (
        left.relay_capability.as_ref(),
        right.relay_capability.as_ref(),
    ) {
        (Some(left_capability), Some(right_capability)) => {
            compare_relay_load(left_capability, right_capability)
                .then_with(|| {
                    right_capability
                        .available_capacity()
                        .cmp(&left_capability.available_capacity())
                })
                .then_with(|| right_capability.max_mbps.cmp(&left_capability.max_mbps))
                .then_with(|| left.node_id.cmp(&right.node_id))
        }
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => left.node_id.cmp(&right.node_id),
    }
}

fn compare_relay_load(
    left: &ipars_types::RelayCapability,
    right: &ipars_types::RelayCapability,
) -> std::cmp::Ordering {
    let left_denominator = left.max_sessions.max(1) as u64;
    let right_denominator = right.max_sessions.max(1) as u64;
    let left_scaled = left.active_sessions as u64 * right_denominator;
    let right_scaled = right.active_sessions as u64 * left_denominator;
    left_scaled.cmp(&right_scaled)
}

fn path_candidate_cost(
    state: PathState,
    source_candidates: &[EndpointCandidate],
    target_candidates: &[EndpointCandidate],
) -> u32 {
    match state {
        PathState::DirectIpv6 => {
            endpoint_kind_min_cost(source_candidates, EndpointCandidateKind::Ipv6).saturating_add(
                endpoint_kind_min_cost(target_candidates, EndpointCandidateKind::Ipv6),
            )
        }
        PathState::DirectPublic => {
            endpoint_kind_min_cost(target_candidates, EndpointCandidateKind::PublicUdp)
        }
        PathState::DirectNatTraversal => {
            endpoint_kind_min_cost(source_candidates, EndpointCandidateKind::StunReflexive)
                .saturating_add(endpoint_kind_min_cost(
                    target_candidates,
                    EndpointCandidateKind::StunReflexive,
                ))
        }
        PathState::Relay | PathState::Unreachable => 0,
    }
}

fn endpoint_kind_min_cost(candidates: &[EndpointCandidate], kind: EndpointCandidateKind) -> u32 {
    candidates
        .iter()
        .filter(|candidate| candidate.kind == kind)
        .map(|candidate| candidate.cost)
        .min()
        .unwrap_or(0)
}

fn health_report_is_fresh(
    health: &NodeHealth,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> bool {
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use ipars_types::{
        CandidateSource, ClusterId, HealthState, NatConnectivityState, NatFilteringObservation,
        NatFilteringProbeKind, NatMappingBehavior, NatProbeObservation, NodeHealth, NodeId,
        RelayCapability, Role, Route, Tag, TokenPolicy, VpnIp,
    };

    use super::*;

    fn candidate(kind: EndpointCandidateKind) -> EndpointCandidate {
        EndpointCandidate {
            node_id: NodeId::from_string("node-a"),
            kind,
            addr: SocketAddr::from(([8, 8, 8, 10], 51820)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::StunProbe,
        }
    }

    fn candidate_at(kind: EndpointCandidateKind, addr: SocketAddr) -> EndpointCandidate {
        EndpointCandidate {
            addr,
            ..candidate(kind)
        }
    }

    fn candidate_with_cost(kind: EndpointCandidateKind, cost: u32) -> EndpointCandidate {
        EndpointCandidate {
            cost,
            ..candidate(kind)
        }
    }

    fn ipv6_candidate() -> EndpointCandidate {
        EndpointCandidate {
            addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x10)),
                51820,
            ),
            ..candidate(EndpointCandidateKind::Ipv6)
        }
    }

    fn ipv6_candidate_with_cost(cost: u32) -> EndpointCandidate {
        EndpointCandidate {
            cost,
            ..ipv6_candidate()
        }
    }

    fn stale_ipv6_candidate() -> EndpointCandidate {
        let mut candidate = ipv6_candidate();
        candidate.observed_at = Utc::now() - chrono::Duration::seconds(121);
        candidate
    }

    fn stale_candidate(kind: EndpointCandidateKind) -> EndpointCandidate {
        let mut candidate = candidate(kind);
        candidate.observed_at = Utc::now() - chrono::Duration::seconds(121);
        candidate
    }

    fn node_record(node_id: &str, mut candidates: Vec<EndpointCandidate>) -> NodeRecord {
        let node_id = NodeId::from_string(node_id);
        for candidate in &mut candidates {
            candidate.node_id = node_id.clone();
        }
        NodeRecord {
            node_id,
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

    fn source(candidates: Vec<EndpointCandidate>) -> NodeRecord {
        node_record("node-a", candidates)
    }

    fn target(candidates: Vec<EndpointCandidate>) -> NodeRecord {
        node_record("node-b", candidates)
    }

    fn relay_capability() -> RelayCapability {
        RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 20], 51820))),
            admission_url: Some("http://203.0.113.20:9580".to_string()),
            max_sessions: 10,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
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
            relay_capability: Some(relay_capability()),
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        }
    }

    fn relay_with_capacity(
        node_id: &str,
        max_sessions: u32,
        active_sessions: u32,
        max_mbps: u32,
    ) -> NodeRecord {
        let mut relay = relay();
        relay.node_id = NodeId::from_string(node_id);
        relay.vpn_ip = VpnIp(IpAddr::V4(Ipv4Addr::new(
            100,
            64,
            0,
            node_id.bytes().fold(10u8, u8::wrapping_add),
        )));
        let mut capability = relay_capability();
        capability.max_sessions = max_sessions;
        capability.active_sessions = active_sessions;
        capability.max_mbps = max_mbps;
        relay.relay_capability = Some(capability);
        relay
    }

    fn deny_to_tag_acl(id: &str, tag: &str) -> AclRule {
        AclRule {
            id: id.to_string(),
            from_roles: BTreeSet::new(),
            from_tags: BTreeSet::new(),
            to_roles: BTreeSet::new(),
            to_tags: BTreeSet::from([Tag::from_string(tag)]),
            routes: Vec::new(),
            protocol: TransportProtocol::Any,
            action: AclAction::Deny,
        }
    }

    fn allow_peer_acl(id: &str) -> AclRule {
        AclRule {
            id: id.to_string(),
            from_roles: BTreeSet::new(),
            from_tags: BTreeSet::new(),
            to_roles: BTreeSet::new(),
            to_tags: BTreeSet::new(),
            routes: Vec::new(),
            protocol: TransportProtocol::Any,
            action: AclAction::Allow,
        }
    }

    fn allow_route_acl(id: &str, cidr: &str) -> AclRule {
        route_acl(id, cidr, AclAction::Allow)
    }

    fn deny_route_acl(id: &str, cidr: &str) -> AclRule {
        route_acl(id, cidr, AclAction::Deny)
    }

    fn test_cidr(value: &str) -> IpNet {
        match value.parse() {
            Ok(cidr) => cidr,
            Err(error) => panic!("invalid test CIDR `{value}`: {error}"),
        }
    }

    fn route_acl(id: &str, cidr: &str, action: AclAction) -> AclRule {
        AclRule {
            id: id.to_string(),
            from_roles: BTreeSet::new(),
            from_tags: BTreeSet::new(),
            to_roles: BTreeSet::new(),
            to_tags: BTreeSet::new(),
            routes: vec![test_cidr(cidr)],
            protocol: TransportProtocol::Any,
            action,
        }
    }

    fn advertised_route(id: &str, cidr: &str, advertised_by: &NodeId) -> Route {
        Route {
            id: id.to_string(),
            cidr: test_cidr(cidr),
            advertised_by: advertised_by.clone(),
            via: None,
            metric: 100,
            tags: BTreeSet::new(),
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

    fn quality_observation(
        selected_state: PathState,
        selected_candidate: Option<EndpointCandidate>,
        relay_node: Option<NodeId>,
        observed_at: chrono::DateTime<Utc>,
    ) -> PathQualityObservation {
        PathQualityObservation {
            selected_state,
            selected_candidate,
            relay_node,
            metrics: PathMetrics {
                latency_ms: Some(42.0),
                loss_ppm: 200_000,
                jitter_ms: Some(5.0),
                relay_load: None,
                stability: 0.8,
            },
            sample_count: 5,
            successful_sample_count: 4,
            observed_at,
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

    #[test]
    fn matching_fresh_path_observation_drives_direct_score() {
        let now = Utc::now();
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let target = target(vec![candidate(EndpointCandidateKind::PublicUdp)]);
        let observation = quality_observation(
            PathState::DirectPublic,
            target.endpoint_candidates.first().cloned(),
            None,
            now,
        );
        let response = coordinator.negotiate_with_observation(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: Vec::new(),
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target,
            None,
            &[],
            Some(&observation),
            now,
        );

        assert_eq!(response.preferred_state, PathState::DirectPublic);
        assert!(response
            .score
            .reasons
            .iter()
            .any(|reason| reason == "latency_ms=42.0"));
        assert!(response
            .score
            .reasons
            .iter()
            .any(|reason| reason == "loss_ppm=200000"));
        assert!(response
            .score
            .reasons
            .iter()
            .any(|reason| reason == "jitter_ms=5.0"));
        assert!(response
            .score
            .reasons
            .iter()
            .any(|reason| reason == "stability=0.80"));
    }

    #[test]
    fn stale_or_mismatched_path_observation_is_not_reused() {
        let now = Utc::now();
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let target = target(vec![candidate(EndpointCandidateKind::PublicUdp)]);
        let mut mismatched_candidate = target.endpoint_candidates[0].clone();
        mismatched_candidate.addr.set_port(51821);
        let observations = [
            quality_observation(
                PathState::DirectPublic,
                Some(mismatched_candidate),
                None,
                now,
            ),
            quality_observation(
                PathState::DirectPublic,
                target.endpoint_candidates.first().cloned(),
                None,
                now - chrono::Duration::seconds(121),
            ),
        ];

        for observation in observations {
            let response = coordinator.negotiate_with_observation(
                SignalPathRequest {
                    source: NodeId::from_string("node-a"),
                    target: NodeId::from_string("node-b"),
                    source_candidates: Vec::new(),
                    source_nat_classification: None,
                    desired_routes: Vec::new(),
                },
                &target,
                None,
                &[],
                Some(&observation),
                now,
            );
            assert!(!response
                .score
                .reasons
                .iter()
                .any(|reason| reason.starts_with("latency_ms=")));
        }
    }

    #[tokio::test]
    async fn registry_counts_path_observation_dispositions() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let source_node = source(Vec::new());
        let target_node = target(vec![candidate(EndpointCandidateKind::PublicUdp)]);
        registry.upsert_node(source_node.clone()).await?;
        registry.upsert_node(target_node.clone()).await?;
        let request = || SignalPathRequest {
            source: source_node.node_id.clone(),
            target: target_node.node_id.clone(),
            source_candidates: Vec::new(),
            source_nat_classification: None,
            desired_routes: Vec::new(),
        };
        let now = Utc::now();
        let observation = quality_observation(
            PathState::DirectPublic,
            target_node.endpoint_candidates.first().cloned(),
            None,
            now,
        );

        registry
            .negotiate_with_observation(request(), Some(observation.clone()))
            .await?;
        let mut stale = observation.clone();
        stale.observed_at = now - chrono::Duration::seconds(121);
        registry
            .negotiate_with_observation(request(), Some(stale))
            .await?;
        let mut mismatched = observation.clone();
        let Some(candidate) = mismatched.selected_candidate.as_mut() else {
            panic!("direct test observation must contain a selected candidate");
        };
        candidate.addr.set_port(51_821);
        registry
            .negotiate_with_observation(request(), Some(mismatched))
            .await?;
        let mut invalid = observation;
        invalid.metrics.loss_ppm = 0;
        assert!(matches!(
            registry
                .negotiate_with_observation(request(), Some(invalid))
                .await,
            Err(SignalError::PathQualityObservationInvalid { .. })
        ));

        let metrics = registry.metrics().await;
        assert_eq!(metrics.path_quality_observation_accepted_count, 1);
        assert_eq!(metrics.path_quality_observation_stale_count, 1);
        assert_eq!(metrics.path_quality_observation_path_mismatch_count, 1);
        assert_eq!(metrics.path_quality_observation_rejected_count, 1);
        assert_eq!(metrics.path_quality_observation_ttl_seconds, 120);
        Ok(())
    }

    #[test]
    fn direct_public_score_uses_lowest_target_public_candidate_cost() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![candidate(EndpointCandidateKind::StunReflexive)],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![
                candidate_with_cost(EndpointCandidateKind::PublicUdp, 50),
                candidate_with_cost(EndpointCandidateKind::PublicUdp, 7),
            ]),
            None,
            &[],
        );

        assert_eq!(response.preferred_state, PathState::DirectPublic);
        assert!(response
            .score
            .reasons
            .iter()
            .any(|reason| reason == "cost=7"));
    }

    #[test]
    fn direct_ipv6_is_preferred_when_both_nodes_have_ipv6_candidates() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![ipv6_candidate()],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![
                candidate(EndpointCandidateKind::PublicUdp),
                ipv6_candidate(),
            ]),
            None,
            &[],
        );

        assert_eq!(response.preferred_state, PathState::DirectIpv6);
    }

    #[test]
    fn direct_ipv6_score_uses_lowest_source_and_target_ipv6_candidate_costs() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![ipv6_candidate_with_cost(40), ipv6_candidate_with_cost(3)],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![
                candidate(EndpointCandidateKind::PublicUdp),
                ipv6_candidate_with_cost(50),
                ipv6_candidate_with_cost(9),
            ]),
            None,
            &[],
        );

        assert_eq!(response.preferred_state, PathState::DirectIpv6);
        assert!(response
            .score
            .reasons
            .iter()
            .any(|reason| reason == "cost=12"));
    }

    #[test]
    fn direct_public_is_used_when_ipv6_direct_is_disabled() {
        let coordinator = SignalCoordinator::new(ClusterPolicy {
            allow_ipv6_direct: false,
            ..ClusterPolicy::default()
        });
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![ipv6_candidate()],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![
                candidate(EndpointCandidateKind::PublicUdp),
                ipv6_candidate(),
            ]),
            None,
            &[],
        );

        assert_eq!(response.preferred_state, PathState::DirectPublic);
        assert!(response
            .score
            .reasons
            .iter()
            .any(|reason| reason == "state=DirectPublic"));
    }

    #[test]
    fn nat_traversal_is_not_used_when_policy_disables_it() {
        let coordinator = SignalCoordinator::new(ClusterPolicy {
            allow_nat_traversal: false,
            ..ClusterPolicy::default()
        });
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![candidate(EndpointCandidateKind::StunReflexive)],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![candidate(EndpointCandidateKind::StunReflexive)]),
            None,
            &[],
        );

        assert_eq!(response.preferred_state, PathState::Unreachable);
    }

    #[test]
    fn stale_ipv6_candidate_is_not_used_for_direct_path() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![ipv6_candidate()],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![stale_ipv6_candidate()]),
            None,
            &[],
        );

        assert_eq!(response.preferred_state, PathState::Unreachable);
        assert!(response.target_candidates.is_empty());
    }

    #[test]
    fn stale_public_candidate_is_not_used_for_direct_path() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![candidate(EndpointCandidateKind::StunReflexive)],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![stale_candidate(EndpointCandidateKind::PublicUdp)]),
            None,
            &[],
        );

        assert_eq!(response.preferred_state, PathState::Unreachable);
        assert!(response.target_candidates.is_empty());
    }

    #[test]
    fn unusable_public_candidate_is_not_used_for_direct_path() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![candidate(EndpointCandidateKind::StunReflexive)],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![
                candidate_at(
                    EndpointCandidateKind::PublicUdp,
                    SocketAddr::from(([0, 0, 0, 0], 51820)),
                ),
                candidate_at(
                    EndpointCandidateKind::PublicUdp,
                    SocketAddr::from(([203, 0, 113, 10], 0)),
                ),
                candidate_at(
                    EndpointCandidateKind::PublicUdp,
                    SocketAddr::from(([224, 0, 0, 1], 51820)),
                ),
                candidate_at(
                    EndpointCandidateKind::PublicUdp,
                    SocketAddr::from(([255, 255, 255, 255], 51820)),
                ),
            ]),
            None,
            &[],
        );

        assert_eq!(response.preferred_state, PathState::Unreachable);
        assert!(response.target_candidates.is_empty());
    }

    #[test]
    fn unusable_ipv6_candidate_is_not_used_for_direct_path() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![ipv6_candidate()],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![
                candidate_at(
                    EndpointCandidateKind::Ipv6,
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 51820),
                ),
                candidate_at(
                    EndpointCandidateKind::Ipv6,
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
                ),
                candidate_at(
                    EndpointCandidateKind::Ipv6,
                    SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
                        51820,
                    ),
                ),
            ]),
            None,
            &[],
        );

        assert_eq!(response.preferred_state, PathState::Unreachable);
        assert!(response.target_candidates.is_empty());
    }

    #[test]
    fn stale_reflexive_candidate_is_not_used_for_nat_traversal() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![candidate(EndpointCandidateKind::StunReflexive)],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![stale_candidate(EndpointCandidateKind::StunReflexive)]),
            None,
            &[],
        );

        assert_eq!(response.preferred_state, PathState::Unreachable);
    }

    #[test]
    fn nat_traversal_score_uses_lowest_source_and_target_reflexive_candidate_costs() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![
                    candidate_with_cost(EndpointCandidateKind::StunReflexive, 80),
                    candidate_with_cost(EndpointCandidateKind::StunReflexive, 4),
                ],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![
                candidate_with_cost(EndpointCandidateKind::StunReflexive, 70),
                candidate_with_cost(EndpointCandidateKind::StunReflexive, 6),
            ]),
            None,
            &[],
        );

        assert_eq!(response.preferred_state, PathState::DirectNatTraversal);
        assert!(response
            .score
            .reasons
            .iter()
            .any(|reason| reason == "cost=10"));
    }

    #[test]
    fn unusable_reflexive_candidate_is_not_used_for_nat_traversal_or_punch_plan() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let unusable_reflexive = candidate_at(
            EndpointCandidateKind::StunReflexive,
            SocketAddr::from(([0, 0, 0, 0], 40000)),
        );
        let usable_reflexive = candidate_at(
            EndpointCandidateKind::StunReflexive,
            SocketAddr::from(([8, 8, 8, 20], 40000)),
        );
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![unusable_reflexive.clone()],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![usable_reflexive.clone()]),
            None,
            &[],
        );

        assert_eq!(response.preferred_state, PathState::Unreachable);

        let plan = coordinator.punch_plan(&[unusable_reflexive], None, &[usable_reflexive], None);

        assert!(plan.source_reflexive.is_none());
        assert_eq!(
            plan.target_reflexive.map(|candidate| candidate.addr),
            Some(SocketAddr::from(([8, 8, 8, 20], 40000)))
        );
    }

    #[test]
    fn shared_private_lan_uses_direct_local_candidates() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let source_local = candidate_at(
            EndpointCandidateKind::LocalUdp,
            SocketAddr::from(([192, 168, 10, 20], 51_820)),
        );
        let target_local = candidate_at(
            EndpointCandidateKind::LocalUdp,
            SocketAddr::from(([192, 168, 10, 30], 51_820)),
        );
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![source_local],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![target_local]),
            None,
            &[],
        );

        assert_eq!(response.preferred_state, PathState::DirectNatTraversal);
    }

    #[test]
    fn shared_address_overlay_is_not_used_as_nat_reflexive_path() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let source_reflexive = candidate_at(
            EndpointCandidateKind::StunReflexive,
            SocketAddr::from(([100, 100, 20, 30], 51_820)),
        );
        let target_reflexive = candidate_at(
            EndpointCandidateKind::StunReflexive,
            SocketAddr::from(([100, 100, 20, 40], 51_820)),
        );
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: vec![source_reflexive.clone()],
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(vec![target_reflexive.clone()]),
            None,
            &[],
        );
        let plan = coordinator.punch_plan(&[source_reflexive], None, &[target_reflexive], None);

        assert_eq!(response.preferred_state, PathState::Unreachable);
        assert!(plan.source_reflexive.is_none());
        assert!(plan.target_reflexive.is_none());
    }

    #[test]
    fn hole_punch_plan_uses_only_fresh_reflexive_candidates() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let plan = coordinator.punch_plan(
            &[stale_candidate(EndpointCandidateKind::StunReflexive)],
            None,
            &[candidate(EndpointCandidateKind::StunReflexive)],
            None,
        );

        assert!(plan.source_reflexive.is_none());
        assert_eq!(
            plan.target_reflexive.map(|candidate| candidate.kind),
            Some(EndpointCandidateKind::StunReflexive)
        );
    }

    #[tokio::test]
    async fn registry_uses_relay_fallback_when_direct_is_unreachable() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        registry.upsert_node(source(Vec::new())).await?;
        registry.upsert_node(target(Vec::new())).await?;
        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(healthy_health()))
            .await?;

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

    #[test]
    fn relay_candidates_are_sorted_by_load_capacity_and_bandwidth() {
        let coordinator = SignalCoordinator::new(ClusterPolicy::default());
        let response = coordinator.negotiate(
            SignalPathRequest {
                source: NodeId::from_string("node-a"),
                target: NodeId::from_string("node-b"),
                source_candidates: Vec::new(),
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            &target(Vec::new()),
            None,
            &[
                relay_with_capacity("relay-busy", 10, 8, 10_000),
                relay_with_capacity("relay-less-bandwidth", 10, 1, 1_000),
                relay_with_capacity("relay-more-capacity", 20, 2, 500),
                relay_with_capacity("relay-more-bandwidth", 10, 1, 2_000),
            ],
        );

        assert_eq!(response.preferred_state, PathState::Relay);
        assert_eq!(
            response
                .relay_candidates
                .iter()
                .map(|relay| relay.node_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "relay-more-capacity",
                "relay-more-bandwidth",
                "relay-less-bandwidth",
                "relay-busy",
            ]
        );
        assert!(response
            .score
            .reasons
            .iter()
            .any(|reason| reason == "relay_load=0.10"));
    }

    #[tokio::test]
    async fn registry_does_not_use_relay_fallback_when_policy_disables_it(
    ) -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy {
            allow_relay_fallback: false,
            ..ClusterPolicy::default()
        });
        registry.upsert_node(source(Vec::new())).await?;
        registry.upsert_node(target(Vec::new())).await?;
        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(healthy_health()))
            .await?;

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
        assert_eq!(response.relay_candidates.len(), 1);
        let metrics = registry.metrics().await;
        assert_eq!(signal_path_state_count(&metrics, PathState::Unreachable), 1);
        assert_eq!(signal_path_state_count(&metrics, PathState::Relay), 0);
        Ok(())
    }

    #[tokio::test]
    async fn registry_excludes_path_endpoints_from_relay_candidates() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let mut source_relay = source(Vec::new());
        source_relay.relay_capability = Some(relay_capability());
        let mut target_relay = target(Vec::new());
        target_relay.relay_capability = Some(relay_capability());
        registry
            .upsert_node_with_nat_and_health(source_relay, None, Some(healthy_health()))
            .await?;
        registry
            .upsert_node_with_nat_and_health(target_relay, None, Some(healthy_health()))
            .await?;

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

        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(healthy_health()))
            .await?;
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
        assert_eq!(
            response
                .relay_candidates
                .iter()
                .map(|relay| relay.node_id.clone())
                .collect::<Vec<_>>(),
            vec![NodeId::from_string("relay-a")]
        );
        Ok(())
    }

    #[tokio::test]
    async fn registry_applies_acl_to_path_negotiation() -> Result<(), SignalError> {
        let policy = ClusterPolicy {
            acl_rules: vec![
                deny_to_tag_acl("deny-blocked", "blocked"),
                allow_peer_acl("allow-rest"),
            ],
            ..ClusterPolicy::default()
        };
        let registry = SignalRegistry::new(policy);
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let mut blocked_target = target(vec![candidate(EndpointCandidateKind::PublicUdp)]);
        blocked_target.tags.insert(Tag::from_string("blocked"));
        registry.upsert_node(source.clone()).await?;
        registry.upsert_node(blocked_target.clone()).await?;

        let response = registry
            .negotiate(SignalPathRequest {
                source: source.node_id.clone(),
                target: blocked_target.node_id.clone(),
                source_candidates: source.endpoint_candidates.clone(),
                source_nat_classification: None,
                desired_routes: Vec::new(),
            })
            .await?;

        assert_eq!(response.preferred_state, PathState::Unreachable);
        assert!(response.target_candidates.is_empty());
        assert!(response.relay_candidates.is_empty());
        assert_eq!(response.score.reasons, vec!["policy_denied".to_string()]);
        let metrics = registry.metrics().await;
        assert_eq!(metrics.path_acl_denied_count, 1);
        assert_eq!(metrics.relay_candidate_acl_denied_count, 0);
        assert_eq!(metrics.hole_punch_acl_denied_count, 0);
        assert_eq!(signal_path_state_count(&metrics, PathState::Unreachable), 1);
        Ok(())
    }

    #[tokio::test]
    async fn registry_allows_route_specific_acl_for_desired_routes() -> Result<(), SignalError> {
        let policy = ClusterPolicy {
            acl_rules: vec![allow_route_acl("allow-service-routes", "10.10.0.0/16")],
            ..ClusterPolicy::default()
        };
        let registry = SignalRegistry::new(policy);
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let mut route_target = target(vec![candidate(EndpointCandidateKind::PublicUdp)]);
        route_target.routes.push(advertised_route(
            "service-route",
            "10.10.0.0/16",
            &route_target.node_id,
        ));
        registry.upsert_node(source.clone()).await?;
        registry.upsert_node(route_target.clone()).await?;

        let response = registry
            .negotiate(SignalPathRequest {
                source: source.node_id.clone(),
                target: route_target.node_id.clone(),
                source_candidates: source.endpoint_candidates.clone(),
                source_nat_classification: None,
                desired_routes: vec![test_cidr("10.10.5.0/24")],
            })
            .await?;

        assert_eq!(response.preferred_state, PathState::DirectPublic);
        assert_eq!(response.target_candidates.len(), 1);
        let metrics = registry.metrics().await;
        assert_eq!(metrics.path_acl_denied_count, 0);
        assert_eq!(
            signal_path_state_count(&metrics, PathState::DirectPublic),
            1
        );
        Ok(())
    }

    #[tokio::test]
    async fn registry_denies_disallowed_desired_routes() -> Result<(), SignalError> {
        let policy = ClusterPolicy {
            acl_rules: vec![
                deny_route_acl("deny-admin-subnet", "10.10.5.0/24"),
                allow_route_acl("allow-service-routes", "10.10.0.0/16"),
            ],
            ..ClusterPolicy::default()
        };
        let registry = SignalRegistry::new(policy);
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let mut route_target = target(vec![candidate(EndpointCandidateKind::PublicUdp)]);
        route_target.routes.push(advertised_route(
            "service-route",
            "10.10.0.0/16",
            &route_target.node_id,
        ));
        registry.upsert_node(source.clone()).await?;
        registry.upsert_node(route_target.clone()).await?;

        let response = registry
            .negotiate(SignalPathRequest {
                source: source.node_id.clone(),
                target: route_target.node_id.clone(),
                source_candidates: source.endpoint_candidates.clone(),
                source_nat_classification: None,
                desired_routes: vec![test_cidr("10.10.5.0/24")],
            })
            .await?;

        assert_eq!(response.preferred_state, PathState::Unreachable);
        assert!(response.target_candidates.is_empty());
        assert_eq!(response.score.reasons, vec!["policy_denied".to_string()]);
        let metrics = registry.metrics().await;
        assert_eq!(metrics.path_acl_denied_count, 1);
        assert_eq!(signal_path_state_count(&metrics, PathState::Unreachable), 1);
        Ok(())
    }

    #[tokio::test]
    async fn registry_rejects_unadvertised_desired_routes() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let route_target = target(vec![candidate(EndpointCandidateKind::PublicUdp)]);
        registry.upsert_node(source.clone()).await?;
        registry.upsert_node(route_target.clone()).await?;
        let requested_route = test_cidr("10.99.0.0/16");

        assert!(matches!(
            registry
                .negotiate(SignalPathRequest {
                    source: source.node_id.clone(),
                    target: route_target.node_id.clone(),
                    source_candidates: source.endpoint_candidates.clone(),
                    source_nat_classification: None,
                    desired_routes: vec![requested_route],
                })
                .await,
            Err(SignalError::DesiredRouteInvalid {
                route,
                reason: "route is not advertised by target",
                ..
            }) if route == requested_route
        ));
        Ok(())
    }

    #[tokio::test]
    async fn registry_filters_relay_candidates_by_acl() -> Result<(), SignalError> {
        let policy = ClusterPolicy {
            acl_rules: vec![
                deny_to_tag_acl("deny-hidden-relay", "relay-hidden"),
                allow_peer_acl("allow-rest"),
            ],
            ..ClusterPolicy::default()
        };
        let registry = SignalRegistry::new(policy);
        let source = source(Vec::new());
        let target = target(Vec::new());
        let mut hidden_relay = relay();
        hidden_relay.tags.insert(Tag::from_string("relay-hidden"));
        registry.upsert_node(source.clone()).await?;
        registry.upsert_node(target.clone()).await?;
        registry
            .upsert_node_with_nat_and_health(hidden_relay, None, Some(healthy_health()))
            .await?;

        let response = registry
            .negotiate(SignalPathRequest {
                source: source.node_id.clone(),
                target: target.node_id.clone(),
                source_candidates: Vec::new(),
                source_nat_classification: None,
                desired_routes: Vec::new(),
            })
            .await?;

        assert_eq!(response.preferred_state, PathState::Unreachable);
        assert!(response.relay_candidates.is_empty());
        let metrics = registry.metrics().await;
        assert_eq!(metrics.path_acl_denied_count, 0);
        assert_eq!(metrics.relay_candidate_acl_denied_count, 1);

        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(healthy_health()))
            .await?;
        let response = registry
            .negotiate(SignalPathRequest {
                source: source.node_id.clone(),
                target: target.node_id.clone(),
                source_candidates: Vec::new(),
                source_nat_classification: None,
                desired_routes: Vec::new(),
            })
            .await?;

        assert_eq!(response.preferred_state, PathState::Relay);
        assert_eq!(
            response
                .relay_candidates
                .iter()
                .map(|relay| relay.node_id.clone())
                .collect::<Vec<_>>(),
            vec![NodeId::from_string("relay-a")]
        );
        let metrics = registry.metrics().await;
        assert_eq!(metrics.relay_candidate_acl_denied_count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn registry_ignores_relay_without_admission_url() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let mut relay = relay();
        if let Some(capability) = relay.relay_capability.as_mut() {
            capability.admission_url = None;
        }
        registry.upsert_node(source(Vec::new())).await?;
        registry.upsert_node(target(Vec::new())).await?;
        registry
            .upsert_node_with_nat_and_health(relay, None, Some(healthy_health()))
            .await?;

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
    async fn registry_ignores_relay_with_unusable_admission_url() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let mut relay = relay();
        if let Some(capability) = relay.relay_capability.as_mut() {
            capability.admission_url = Some("http://0.0.0.0:9580".to_string());
        }
        registry.upsert_node(source(Vec::new())).await?;
        registry.upsert_node(target(Vec::new())).await?;
        registry
            .upsert_node_with_nat_and_health(relay, None, Some(healthy_health()))
            .await?;

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
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        registry.upsert_node(source.clone()).await?;
        registry
            .upsert_node_with_nat(target, Some(relay_preferred_nat()))
            .await?;
        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(healthy_health()))
            .await?;

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
    async fn registry_uses_nat_traversal_for_address_dependent_nat() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let nat = address_dependent_hole_punch_nat();
        registry.upsert_node(source.clone()).await?;
        registry
            .upsert_node_with_nat(target.clone(), Some(nat.clone()))
            .await?;

        let response = registry
            .negotiate(SignalPathRequest {
                source: source.node_id.clone(),
                target: target.node_id.clone(),
                source_candidates: source.endpoint_candidates.clone(),
                source_nat_classification: Some(nat),
                desired_routes: Vec::new(),
            })
            .await?;

        assert_eq!(response.preferred_state, PathState::DirectNatTraversal);
        assert!(response.relay_candidates.is_empty());
        let metrics = registry.metrics().await;
        assert_eq!(
            signal_path_state_count(&metrics, PathState::DirectNatTraversal),
            1
        );
        assert_eq!(
            signal_nat_strategy_count(&metrics, NatTraversalStrategy::CoordinatedHolePunch),
            1
        );
        Ok(())
    }

    #[tokio::test]
    async fn registry_blocks_low_confidence_nat_classification_for_negotiation(
    ) -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy {
            nat_classification_min_confidence_percent: 80,
            ..ClusterPolicy::default()
        });
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        registry
            .upsert_node_with_nat(source.clone(), Some(coordinated_hole_punch_nat(0.7)))
            .await?;
        registry.upsert_node(target.clone()).await?;

        let response = registry
            .negotiate(SignalPathRequest {
                source: source.node_id.clone(),
                target: target.node_id.clone(),
                source_candidates: source.endpoint_candidates.clone(),
                source_nat_classification: None,
                desired_routes: Vec::new(),
            })
            .await?;

        assert_eq!(response.preferred_state, PathState::Unreachable);
        let metrics = registry.metrics().await;
        assert_eq!(metrics.nat_classification_min_confidence_percent, 80);
        assert_eq!(metrics.fresh_low_confidence_nat_classification_count, 1);
        assert_eq!(
            signal_path_state_count(&metrics, PathState::DirectNatTraversal),
            0
        );
        assert_eq!(signal_path_state_count(&metrics, PathState::Unreachable), 1);
        Ok(())
    }

    #[tokio::test]
    async fn registry_uses_stored_source_nat_classification_for_negotiation(
    ) -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        registry
            .upsert_node_with_nat(source.clone(), Some(relay_preferred_nat()))
            .await?;
        registry.upsert_node(target.clone()).await?;
        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(healthy_health()))
            .await?;

        let response = registry
            .negotiate(SignalPathRequest {
                source: source.node_id.clone(),
                target: target.node_id.clone(),
                source_candidates: source.endpoint_candidates.clone(),
                source_nat_classification: None,
                desired_routes: Vec::new(),
            })
            .await?;

        assert_eq!(response.preferred_state, PathState::Relay);
        assert_eq!(response.relay_candidates.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn registry_ignores_stale_source_nat_classification_for_negotiation(
    ) -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy {
            nat_classification_ttl_seconds: 30,
            ..ClusterPolicy::default()
        });
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let mut stale_nat = relay_preferred_nat();
        stale_nat.assessed_at = Utc::now() - chrono::Duration::seconds(60);
        registry
            .upsert_node_with_nat(source.clone(), Some(stale_nat))
            .await?;
        registry.upsert_node(target.clone()).await?;

        let response = registry
            .negotiate(SignalPathRequest {
                source: source.node_id.clone(),
                target: target.node_id.clone(),
                source_candidates: source.endpoint_candidates.clone(),
                source_nat_classification: None,
                desired_routes: Vec::new(),
            })
            .await?;

        assert_eq!(response.preferred_state, PathState::DirectNatTraversal);
        let metrics = registry.metrics().await;
        assert_eq!(metrics.nat_classification_count, 1);
        assert_eq!(metrics.stale_nat_classification_count, 1);
        assert_eq!(
            signal_nat_strategy_count(&metrics, NatTraversalStrategy::RelayPreferred),
            0
        );
        assert_eq!(metrics.nat_classification_ttl_seconds, 30);
        Ok(())
    }

    #[tokio::test]
    async fn registry_requires_fresh_healthy_relay_health() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        registry.upsert_node(source(Vec::new())).await?;
        registry.upsert_node(target(Vec::new())).await?;

        registry.upsert_node(relay()).await?;
        assert!(registry.relay_candidates().await.is_empty());

        let mut unhealthy = healthy_health();
        unhealthy.state = HealthState::Unhealthy;
        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(unhealthy))
            .await?;
        assert!(registry.relay_candidates().await.is_empty());

        let mut stale = healthy_health();
        stale.last_seen_at = Utc::now() - chrono::Duration::seconds(120);
        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(stale))
            .await?;
        assert!(registry.relay_candidates().await.is_empty());

        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(healthy_health()))
            .await?;
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
    async fn registry_clears_non_admissible_relay_capability_on_upsert() -> Result<(), SignalError>
    {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let mut invalid_capabilities = Vec::new();

        let mut policy_disabled = relay_capability();
        policy_disabled.enabled_by_policy = false;
        invalid_capabilities.push(policy_disabled);

        let mut missing_public_endpoint = relay_capability();
        missing_public_endpoint.public_endpoint = None;
        invalid_capabilities.push(missing_public_endpoint);

        let mut unusable_public_endpoint = relay_capability();
        unusable_public_endpoint.public_endpoint = Some(SocketAddr::from(([0, 0, 0, 0], 51820)));
        invalid_capabilities.push(unusable_public_endpoint);

        let mut missing_admission_url = relay_capability();
        missing_admission_url.admission_url = None;
        invalid_capabilities.push(missing_admission_url);

        let mut invalid_admission_url = relay_capability();
        invalid_admission_url.admission_url = Some("udp://203.0.113.20:9580".to_string());
        invalid_capabilities.push(invalid_admission_url);

        let mut full_capacity = relay_capability();
        full_capacity.active_sessions = full_capacity.max_sessions;
        invalid_capabilities.push(full_capacity);

        let mut zero_bandwidth = relay_capability();
        zero_bandwidth.max_mbps = 0;
        invalid_capabilities.push(zero_bandwidth);

        let mut decrypting_relay = relay_capability();
        decrypting_relay.e2e_only = false;
        invalid_capabilities.push(decrypting_relay);

        for capability in invalid_capabilities {
            let mut relay = relay();
            relay.relay_capability = Some(capability);

            let response = registry
                .upsert_node_with_nat_and_health(relay, None, Some(healthy_health()))
                .await?;

            assert!(response.node.relay_capability.is_none());
            let stored = match registry.get_node(&NodeId::from_string("relay-a")).await {
                Some(node) => node,
                None => panic!("relay node should be stored"),
            };
            assert!(stored.relay_capability.is_none());
            assert!(registry.relay_candidates().await.is_empty());
        }

        Ok(())
    }

    #[tokio::test]
    async fn registry_metrics_report_signal_state() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy {
            relay_health_ttl_seconds: 30,
            endpoint_candidate_ttl_seconds: 30,
            ..ClusterPolicy::default()
        });
        let source = source(vec![
            stale_candidate(EndpointCandidateKind::StunReflexive),
            candidate(EndpointCandidateKind::StunReflexive),
        ]);
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        registry
            .upsert_node_with_nat_and_health(
                source.clone(),
                Some(relay_preferred_nat()),
                Some(healthy_health()),
            )
            .await?;
        registry
            .upsert_node_with_nat_and_health(target.clone(), None, Some(healthy_health()))
            .await?;
        let mut stale = healthy_health();
        stale.last_seen_at = Utc::now() - chrono::Duration::seconds(60);
        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(stale))
            .await?;
        registry
            .negotiate(SignalPathRequest {
                source: source.node_id.clone(),
                target: target.node_id.clone(),
                source_candidates: source.endpoint_candidates.clone(),
                source_nat_classification: Some(relay_preferred_nat()),
                desired_routes: Vec::new(),
            })
            .await?;
        registry
            .hole_punch_plan(source.node_id.clone(), target.node_id.clone())
            .await?;

        let stale_metrics = registry.metrics().await;
        assert_eq!(stale_metrics.node_count, 3);
        assert_eq!(stale_metrics.relay_candidate_count, 0);
        assert_eq!(stale_metrics.nat_classification_count, 1);
        assert_eq!(stale_metrics.stale_nat_classification_count, 0);
        assert_eq!(
            stale_metrics.fresh_low_confidence_nat_classification_count,
            0
        );
        assert_eq!(
            signal_nat_strategy_count(&stale_metrics, NatTraversalStrategy::RelayPreferred),
            1
        );
        assert_eq!(
            signal_nat_strategy_count(&stale_metrics, NatTraversalStrategy::CoordinatedHolePunch),
            0
        );
        assert_eq!(stale_metrics.health_report_count, 3);
        assert_eq!(stale_metrics.healthy_node_count, 3);
        assert_eq!(stale_metrics.stale_health_report_count, 1);
        assert_eq!(stale_metrics.node_upsert_count, 3);
        assert_eq!(stale_metrics.path_negotiation_count, 1);
        assert_eq!(
            signal_path_state_count(&stale_metrics, PathState::Unreachable),
            1
        );
        assert_eq!(signal_path_state_count(&stale_metrics, PathState::Relay), 0);
        assert_eq!(stale_metrics.hole_punch_plan_count, 1);
        assert_eq!(stale_metrics.hole_punch_nat_suppressed_count, 1);
        assert_eq!(
            signal_hole_punch_nat_suppression_strategy_count(
                &stale_metrics,
                NatTraversalStrategy::RelayPreferred,
            ),
            1
        );
        assert_eq!(
            signal_hole_punch_nat_suppression_strategy_count(
                &stale_metrics,
                NatTraversalStrategy::CoordinatedHolePunch,
            ),
            0
        );
        assert_eq!(stale_metrics.relay_health_ttl_seconds, 30);
        assert_eq!(stale_metrics.endpoint_candidate_ttl_seconds, 30);
        assert_eq!(stale_metrics.nat_classification_ttl_seconds, 300);
        assert_eq!(stale_metrics.nat_classification_min_confidence_percent, 50);
        assert_eq!(stale_metrics.stale_endpoint_candidate_count, 1);

        registry
            .upsert_node_with_nat_and_health(relay(), None, Some(healthy_health()))
            .await?;
        let fresh_metrics = registry.metrics().await;
        assert_eq!(fresh_metrics.relay_candidate_count, 1);
        assert_eq!(fresh_metrics.stale_health_report_count, 0);
        assert_eq!(fresh_metrics.stale_endpoint_candidate_count, 1);
        assert_eq!(fresh_metrics.node_upsert_count, 4);
        Ok(())
    }

    #[tokio::test]
    async fn registry_clears_nat_classification_when_upsert_omits_it() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        registry.upsert_node(source.clone()).await?;
        registry
            .upsert_node_with_nat(target.clone(), Some(relay_preferred_nat()))
            .await?;
        registry.upsert_node(target).await?;

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
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        registry.upsert_node(source).await?;
        registry.upsert_node(target).await?;

        let plan = registry
            .hole_punch_plan(NodeId::from_string("node-a"), NodeId::from_string("node-b"))
            .await?;

        assert!(plan.source_reflexive.is_some());
        assert!(plan.target_reflexive.is_some());
        assert_eq!(plan.start_after_millis, 50);
        let metrics = registry.metrics().await;
        assert_eq!(metrics.hole_punch_plan_count, 1);
        assert_eq!(metrics.hole_punch_nat_suppressed_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn registry_applies_acl_to_hole_punch_plans() -> Result<(), SignalError> {
        let policy = ClusterPolicy {
            acl_rules: vec![
                deny_to_tag_acl("deny-blocked", "blocked"),
                allow_peer_acl("allow-rest"),
            ],
            ..ClusterPolicy::default()
        };
        let registry = SignalRegistry::new(policy);
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let mut blocked_target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        blocked_target.tags.insert(Tag::from_string("blocked"));
        registry.upsert_node(source.clone()).await?;
        registry.upsert_node(blocked_target.clone()).await?;

        let plan = registry
            .hole_punch_plan(source.node_id.clone(), blocked_target.node_id.clone())
            .await?;

        assert_eq!(
            plan.key,
            PeerPathKey::new(source.node_id, blocked_target.node_id)
        );
        assert!(plan.source_reflexive.is_none());
        assert!(plan.target_reflexive.is_none());
        assert_eq!(plan.start_after_millis, 0);
        let metrics = registry.metrics().await;
        assert_eq!(metrics.hole_punch_plan_count, 1);
        assert_eq!(metrics.hole_punch_acl_denied_count, 1);
        assert_eq!(metrics.hole_punch_nat_suppressed_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn registry_allows_hole_punch_plan_for_route_specific_acl() -> Result<(), SignalError> {
        let policy = ClusterPolicy {
            acl_rules: vec![allow_route_acl("allow-service-routes", "10.10.0.0/16")],
            ..ClusterPolicy::default()
        };
        let registry = SignalRegistry::new(policy);
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let mut route_target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        route_target.routes.push(advertised_route(
            "service-route",
            "10.10.0.0/16",
            &route_target.node_id,
        ));
        registry.upsert_node(source.clone()).await?;
        registry.upsert_node(route_target.clone()).await?;

        let plan = registry
            .hole_punch_plan(source.node_id.clone(), route_target.node_id.clone())
            .await?;

        assert!(plan.source_reflexive.is_some());
        assert!(plan.target_reflexive.is_some());
        assert_eq!(plan.start_after_millis, 50);
        let metrics = registry.metrics().await;
        assert_eq!(metrics.hole_punch_acl_denied_count, 0);
        assert_eq!(metrics.hole_punch_nat_suppressed_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn registry_denies_hole_punch_plan_for_route_specific_acl_denial(
    ) -> Result<(), SignalError> {
        let policy = ClusterPolicy {
            acl_rules: vec![
                deny_route_acl("deny-admin-subnet", "10.10.5.0/24"),
                allow_route_acl("allow-service-routes", "10.10.0.0/16"),
            ],
            ..ClusterPolicy::default()
        };
        let registry = SignalRegistry::new(policy);
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let mut route_target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        route_target.routes.push(advertised_route(
            "admin-route",
            "10.10.5.0/24",
            &route_target.node_id,
        ));
        registry.upsert_node(source.clone()).await?;
        registry.upsert_node(route_target.clone()).await?;

        let plan = registry
            .hole_punch_plan(source.node_id.clone(), route_target.node_id.clone())
            .await?;

        assert!(plan.source_reflexive.is_none());
        assert!(plan.target_reflexive.is_none());
        assert_eq!(plan.start_after_millis, 0);
        let metrics = registry.metrics().await;
        assert_eq!(metrics.hole_punch_acl_denied_count, 1);
        assert_eq!(metrics.hole_punch_nat_suppressed_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn registry_blocks_hole_punch_plan_when_nat_prefers_relay() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        registry
            .upsert_node_with_nat(source, Some(relay_preferred_nat()))
            .await?;
        registry.upsert_node(target).await?;

        let plan = registry
            .hole_punch_plan(NodeId::from_string("node-a"), NodeId::from_string("node-b"))
            .await?;

        assert!(plan.source_reflexive.is_none());
        assert!(plan.target_reflexive.is_none());
        let metrics = registry.metrics().await;
        assert_eq!(metrics.hole_punch_plan_count, 1);
        assert_eq!(metrics.hole_punch_nat_suppressed_count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn registry_blocks_hole_punch_plan_when_nat_confidence_is_too_low(
    ) -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy {
            nat_classification_min_confidence_percent: 80,
            ..ClusterPolicy::default()
        });
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        registry
            .upsert_node_with_nat(source, Some(coordinated_hole_punch_nat(0.7)))
            .await?;
        registry.upsert_node(target).await?;

        let plan = registry
            .hole_punch_plan(NodeId::from_string("node-a"), NodeId::from_string("node-b"))
            .await?;

        assert!(plan.source_reflexive.is_none());
        assert!(plan.target_reflexive.is_none());
        let metrics = registry.metrics().await;
        assert_eq!(metrics.hole_punch_plan_count, 1);
        assert_eq!(metrics.hole_punch_nat_suppressed_count, 1);
        assert_eq!(metrics.nat_classification_min_confidence_percent, 80);
        assert_eq!(metrics.fresh_low_confidence_nat_classification_count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn registry_attempts_direct_traversal_when_nat_data_is_insufficient(
    ) -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        registry
            .upsert_node_with_nat(source.clone(), Some(insufficient_data_nat()))
            .await?;
        registry.upsert_node(target.clone()).await?;

        let response = registry
            .negotiate(SignalPathRequest {
                source: source.node_id.clone(),
                target: target.node_id.clone(),
                source_candidates: source.endpoint_candidates.clone(),
                source_nat_classification: Some(insufficient_data_nat()),
                desired_routes: Vec::new(),
            })
            .await?;
        assert_eq!(response.preferred_state, PathState::DirectNatTraversal);

        let plan = registry
            .hole_punch_plan(source.node_id, target.node_id)
            .await?;
        assert!(plan.source_reflexive.is_some());
        assert!(plan.target_reflexive.is_some());
        let metrics = registry.metrics().await;
        assert_eq!(metrics.hole_punch_nat_suppressed_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn registry_ignores_stale_nat_classification_for_hole_punch_plan(
    ) -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy {
            nat_classification_ttl_seconds: 30,
            ..ClusterPolicy::default()
        });
        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let mut stale_nat = relay_preferred_nat();
        stale_nat.assessed_at = Utc::now() - chrono::Duration::seconds(60);
        registry
            .upsert_node_with_nat(source, Some(stale_nat))
            .await?;
        registry.upsert_node(target).await?;

        let plan = registry
            .hole_punch_plan(NodeId::from_string("node-a"), NodeId::from_string("node-b"))
            .await?;

        assert!(plan.source_reflexive.is_some());
        assert!(plan.target_reflexive.is_some());
        let metrics = registry.metrics().await;
        assert_eq!(metrics.hole_punch_plan_count, 1);
        assert_eq!(metrics.hole_punch_nat_suppressed_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn registry_rejects_unowned_endpoint_candidates() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let mut unowned_node = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        unowned_node.endpoint_candidates[0].node_id = NodeId::from_string("other-node");

        assert!(matches!(
            registry.upsert_node(unowned_node).await,
            Err(SignalError::CandidateOwnerMismatch { .. })
        ));

        let source = source(Vec::new());
        let target = target(Vec::new());
        registry.upsert_node(source.clone()).await?;
        registry.upsert_node(target.clone()).await?;
        let mut unowned_candidate = candidate(EndpointCandidateKind::StunReflexive);
        unowned_candidate.node_id = target.node_id.clone();

        assert!(matches!(
            registry
                .negotiate(SignalPathRequest {
                    source: source.node_id,
                    target: target.node_id,
                    source_candidates: vec![unowned_candidate],
                    source_nat_classification: None,
                    desired_routes: Vec::new(),
                })
                .await,
            Err(SignalError::CandidateOwnerMismatch { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn registry_rejects_future_endpoint_candidates() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let mut future_node = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        future_node.endpoint_candidates[0].observed_at =
            Utc::now() + chrono::Duration::seconds(301);

        assert!(matches!(
            registry.upsert_node(future_node).await,
            Err(SignalError::CandidateInvalid {
                reason: "observed_at is too far in the future",
                ..
            })
        ));
        assert!(registry
            .get_node(&NodeId::from_string("node-a"))
            .await
            .is_none());

        let source = source(Vec::new());
        let target = target(Vec::new());
        registry.upsert_node(source.clone()).await?;
        registry.upsert_node(target.clone()).await?;
        let mut future_candidate = candidate(EndpointCandidateKind::StunReflexive);
        future_candidate.observed_at = Utc::now() + chrono::Duration::seconds(301);

        assert!(matches!(
            registry
                .negotiate(SignalPathRequest {
                    source: source.node_id,
                    target: target.node_id,
                    source_candidates: vec![future_candidate],
                    source_nat_classification: None,
                    desired_routes: Vec::new(),
                })
                .await,
            Err(SignalError::CandidateInvalid {
                reason: "observed_at is too far in the future",
                ..
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn registry_rejects_invalid_health_reports_before_persistence() -> Result<(), SignalError>
    {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let mut future = healthy_health();
        future.last_seen_at = Utc::now() + chrono::Duration::seconds(301);
        let mut negative_latency = healthy_health();
        negative_latency.latency_ms = Some(-1.0);
        let mut invalid_relay_load = healthy_health();
        invalid_relay_load.relay_load = Some(1.1);
        let cases = [
            (future, "last_seen_at is too far in the future"),
            (
                negative_latency,
                "latency_ms must be a finite non-negative value",
            ),
            (
                invalid_relay_load,
                "relay_load must be a finite value between 0 and 1",
            ),
        ];

        for (health, expected) in cases {
            assert!(matches!(
                registry
                    .upsert_node_with_nat_and_health(relay(), None, Some(health))
                    .await,
                Err(SignalError::HealthInvalid { reason, .. }) if reason == expected
            ));
            assert!(registry
                .get_node(&NodeId::from_string("relay-a"))
                .await
                .is_none());
        }
        Ok(())
    }

    #[tokio::test]
    async fn registry_rejects_invalid_route_advertisements() -> Result<(), SignalError> {
        let invalid_owner = {
            let mut node = source(Vec::new());
            node.routes.push(advertised_route(
                "service-route",
                "10.10.0.0/16",
                &NodeId::from_string("other-node"),
            ));
            node
        };
        let metric_zero = {
            let mut node = source(Vec::new());
            let mut route = advertised_route("service-route", "10.10.0.0/16", &node.node_id);
            route.metric = 0;
            node.routes.push(route);
            node
        };
        let restricted = {
            let mut node = source(Vec::new());
            node.routes.push(advertised_route(
                "loopback-route",
                "127.0.0.0/8",
                &node.node_id,
            ));
            node
        };
        let duplicate_cidr = {
            let mut node = source(Vec::new());
            node.routes
                .push(advertised_route("service-a", "10.10.0.0/16", &node.node_id));
            node.routes
                .push(advertised_route("service-b", "10.10.0.0/16", &node.node_id));
            node
        };
        let invalid_id = {
            let mut node = source(Vec::new());
            node.routes
                .push(advertised_route("../bad", "10.10.0.0/16", &node.node_id));
            node
        };
        let cases = [
            (
                invalid_owner,
                "service-route",
                "route must be advertised by the reporting node",
            ),
            (
                metric_zero,
                "service-route",
                "metric must be greater than zero",
            ),
            (restricted, "loopback-route", "route CIDR is restricted"),
            (duplicate_cidr, "service-b", "route CIDR is duplicated"),
            (invalid_id, "../bad", "route ID contains invalid characters"),
        ];

        for (node, expected_route_id, expected_reason) in cases {
            let registry = SignalRegistry::new(ClusterPolicy::default());
            assert!(matches!(
                registry.upsert_node(node).await,
                Err(SignalError::RouteInvalid {
                    route_id,
                    reason,
                    ..
                }) if route_id == expected_route_id && reason == expected_reason
            ));
            assert!(registry
                .get_node(&NodeId::from_string("node-a"))
                .await
                .is_none());
        }
        Ok(())
    }

    #[tokio::test]
    async fn registry_rejects_invalid_nat_classifications() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let mut future = coordinated_hole_punch_nat(0.9);
        future.assessed_at = Utc::now() + chrono::Duration::seconds(301);
        assert!(matches!(
            registry
                .upsert_node_with_nat(source(Vec::new()), Some(future))
                .await,
            Err(SignalError::NatClassificationInvalid {
                reason: "assessed_at is too far in the future",
                ..
            })
        ));
        assert!(registry
            .get_node(&NodeId::from_string("node-a"))
            .await
            .is_none());

        let mut invalid_confidence = coordinated_hole_punch_nat(f32::NAN);
        invalid_confidence.assessed_at = Utc::now();
        assert!(matches!(
            registry
                .upsert_node_with_nat(source(Vec::new()), Some(invalid_confidence))
                .await,
            Err(SignalError::NatClassificationInvalid {
                reason: "confidence must be a finite value between 0 and 1",
                ..
            })
        ));

        let mut invalid_local_addr = coordinated_hole_punch_nat(0.9);
        invalid_local_addr.local_addr = SocketAddr::from(([0, 0, 0, 0], 50_000));
        assert!(matches!(
            registry
                .upsert_node_with_nat(source(Vec::new()), Some(invalid_local_addr))
                .await,
            Err(SignalError::NatClassificationInvalid {
                reason: "local address is unusable",
                ..
            })
        ));

        let mut invalid_observed_endpoint = coordinated_hole_punch_nat(0.9);
        invalid_observed_endpoint.observed_endpoint =
            Some(SocketAddr::from(([0, 0, 0, 0], 50_000)));
        assert!(matches!(
            registry
                .upsert_node_with_nat(source(Vec::new()), Some(invalid_observed_endpoint))
                .await,
            Err(SignalError::NatClassificationInvalid {
                reason: "observed endpoint is unusable",
                ..
            })
        ));

        let mut invalid_probe_observation = coordinated_hole_punch_nat(0.9);
        invalid_probe_observation
            .observations
            .push(NatProbeObservation {
                local_addr: SocketAddr::from(([10, 0, 0, 10], 50_000)),
                stun_server: SocketAddr::from(([203, 0, 113, 20], 3478)),
                reflexive_addr: SocketAddr::from(([224, 0, 0, 1], 50_000)),
                observed_at: Utc::now(),
            });
        assert!(matches!(
            registry
                .upsert_node_with_nat(source(Vec::new()), Some(invalid_probe_observation))
                .await,
            Err(SignalError::NatClassificationInvalid {
                reason: "NAT probe reflexive endpoint is unusable",
                ..
            })
        ));

        let mut invalid_filtering_observation = coordinated_hole_punch_nat(0.9);
        invalid_filtering_observation
            .filtering_observations
            .push(NatFilteringObservation {
                local_addr: SocketAddr::from(([10, 0, 0, 10], 50_000)),
                stun_server: SocketAddr::from(([203, 0, 113, 20], 3478)),
                probe: NatFilteringProbeKind::ChangeAddressAndPort,
                response_origin: Some(SocketAddr::from(([255, 255, 255, 255], 3478))),
                other_address: Some(SocketAddr::from(([203, 0, 113, 21], 3479))),
                observed_at: Utc::now(),
            });
        assert!(matches!(
            registry
                .upsert_node_with_nat(source(Vec::new()), Some(invalid_filtering_observation))
                .await,
            Err(SignalError::NatClassificationInvalid {
                reason: "NAT filtering response origin is unusable",
                ..
            })
        ));

        let private_addr = SocketAddr::from(([100, 100, 20, 30], 51_820));
        let mut forged_public = NatClassification::from_observations(
            private_addr,
            vec![NatProbeObservation {
                local_addr: private_addr,
                stun_server: SocketAddr::from(([100, 100, 20, 40], 3478)),
                reflexive_addr: private_addr,
                observed_at: Utc::now(),
            }],
            Utc::now(),
        );
        forged_public.connectivity_state = NatConnectivityState::Public;
        assert!(matches!(
            registry
                .upsert_node_with_nat(source(Vec::new()), Some(forged_public))
                .await,
            Err(SignalError::NatClassificationInvalid {
                reason: "public state requires matching globally routable no-NAT observations",
                ..
            })
        ));

        let source = source(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        let target = target(vec![candidate(EndpointCandidateKind::StunReflexive)]);
        registry.upsert_node(source.clone()).await?;
        registry.upsert_node(target.clone()).await?;
        let mut future_request_nat = coordinated_hole_punch_nat(0.9);
        future_request_nat.assessed_at = Utc::now() + chrono::Duration::seconds(301);

        assert!(matches!(
            registry
                .negotiate(SignalPathRequest {
                    source: source.node_id,
                    target: target.node_id,
                    source_candidates: Vec::new(),
                    source_nat_classification: Some(future_request_nat),
                    desired_routes: Vec::new(),
                })
                .await,
            Err(SignalError::NatClassificationInvalid {
                reason: "assessed_at is too far in the future",
                ..
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn registry_rejects_ipv6_candidates_with_ipv4_addresses() -> Result<(), SignalError> {
        let registry = SignalRegistry::new(ClusterPolicy::default());
        let invalid_node = source(vec![candidate(EndpointCandidateKind::Ipv6)]);

        assert!(matches!(
            registry.upsert_node(invalid_node).await,
            Err(SignalError::CandidateInvalid {
                kind: EndpointCandidateKind::Ipv6,
                ..
            })
        ));

        let source = source(Vec::new());
        let target = target(Vec::new());
        registry.upsert_node(source.clone()).await?;
        registry.upsert_node(target.clone()).await?;

        assert!(matches!(
            registry
                .negotiate(SignalPathRequest {
                    source: source.node_id,
                    target: target.node_id,
                    source_candidates: vec![candidate(EndpointCandidateKind::Ipv6)],
                    source_nat_classification: None,
                    desired_routes: Vec::new(),
                })
                .await,
            Err(SignalError::CandidateInvalid {
                kind: EndpointCandidateKind::Ipv6,
                ..
            })
        ));
        Ok(())
    }

    fn coordinated_hole_punch_nat(confidence: f32) -> NatClassification {
        NatClassification {
            local_addr: SocketAddr::from(([10, 0, 0, 10], 50_000)),
            mapping_behavior: NatMappingBehavior::EndpointIndependent,
            filtering_behavior: ipars_types::NatFilteringBehavior::EndpointIndependent,
            observed_endpoint: Some(SocketAddr::from(([203, 0, 113, 10], 50_000))),
            observations: Vec::new(),
            filtering_observations: Vec::new(),
            strategy: NatTraversalStrategy::CoordinatedHolePunch,
            connectivity_state: NatConnectivityState::Nat,
            confidence,
            assessed_at: Utc::now(),
        }
    }

    fn address_dependent_hole_punch_nat() -> NatClassification {
        NatClassification {
            local_addr: SocketAddr::from(([10, 0, 0, 10], 50_000)),
            mapping_behavior: NatMappingBehavior::AddressDependent,
            filtering_behavior: ipars_types::NatFilteringBehavior::AddressDependent,
            observed_endpoint: None,
            observations: Vec::new(),
            filtering_observations: Vec::new(),
            strategy: NatTraversalStrategy::CoordinatedHolePunch,
            connectivity_state: NatConnectivityState::DoubleNat,
            confidence: 0.85,
            assessed_at: Utc::now(),
        }
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
            connectivity_state: NatConnectivityState::RelayOnly,
            confidence: 0.9,
            assessed_at: Utc::now(),
        }
    }

    fn insufficient_data_nat() -> NatClassification {
        NatClassification {
            local_addr: SocketAddr::from(([10, 0, 0, 10], 50_000)),
            mapping_behavior: NatMappingBehavior::Unknown,
            filtering_behavior: ipars_types::NatFilteringBehavior::Unknown,
            observed_endpoint: None,
            observations: Vec::new(),
            filtering_observations: Vec::new(),
            strategy: NatTraversalStrategy::InsufficientData,
            connectivity_state: NatConnectivityState::Unknown,
            confidence: 0.25,
            assessed_at: Utc::now(),
        }
    }

    fn signal_path_state_count(metrics: &SignalMetricsResponse, state: PathState) -> usize {
        metrics
            .path_negotiation_state_counts
            .iter()
            .find(|entry| entry.state == state)
            .map(|entry| entry.count)
            .unwrap_or(0)
    }

    fn signal_hole_punch_nat_suppression_strategy_count(
        metrics: &SignalMetricsResponse,
        strategy: NatTraversalStrategy,
    ) -> usize {
        metrics
            .hole_punch_nat_suppressed_strategy_counts
            .iter()
            .find(|entry| entry.strategy == strategy)
            .map(|entry| entry.count)
            .unwrap_or(0)
    }

    fn signal_nat_strategy_count(
        metrics: &SignalMetricsResponse,
        strategy: NatTraversalStrategy,
    ) -> usize {
        metrics
            .fresh_nat_classification_strategy_counts
            .iter()
            .find(|entry| entry.strategy == strategy)
            .map(|entry| entry.count)
            .unwrap_or(0)
    }
}
