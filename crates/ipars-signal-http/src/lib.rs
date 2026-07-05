use std::fmt::Write;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use ipars_signal::{SignalError, SignalRegistry};
use ipars_types::api::{
    SignalHolePunchPlanResponse, SignalMetricsResponse, SignalNodeUpsertRequest,
    SignalNodeUpsertResponse, SignalPathRequest, SignalPathResponse,
};
use ipars_types::{NodeId, PathState};
use serde::Serialize;

macro_rules! prometheus_line {
    ($body:expr, $($arg:tt)*) => {{
        let _ = writeln!($body, $($arg)*);
    }};
}

#[derive(Debug, Clone)]
pub struct SignalHttpState {
    registry: Arc<SignalRegistry>,
}

impl SignalHttpState {
    pub fn new(registry: Arc<SignalRegistry>) -> Self {
        Self { registry }
    }
}

pub fn router(state: SignalHttpState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(prometheus_metrics))
        .route("/v1/metrics", get(metrics))
        .route("/v1/nodes/{node_id}", put(upsert_node))
        .route("/v1/paths/negotiate", post(negotiate))
        .route("/v1/hole-punch/{source}/{target}", get(hole_punch_plan))
        .with_state(state)
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn metrics(State(state): State<SignalHttpState>) -> Json<SignalMetricsResponse> {
    Json(state.registry.metrics().await)
}

async fn prometheus_metrics(State(state): State<SignalHttpState>) -> impl IntoResponse {
    let metrics = state.registry.metrics().await;
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render_prometheus_metrics(&metrics),
    )
}

async fn upsert_node(
    State(state): State<SignalHttpState>,
    Path(node_id): Path<String>,
    Json(request): Json<SignalNodeUpsertRequest>,
) -> Result<Json<SignalNodeUpsertResponse>, ApiError> {
    let path_node_id = NodeId::from_string(node_id);
    if path_node_id != request.node.node_id {
        return Err(ApiError::bad_request("node_id path/body mismatch"));
    }

    Ok(Json(
        state
            .registry
            .upsert_node_with_nat_and_health(
                request.node,
                request.nat_classification,
                request.health,
            )
            .await?,
    ))
}

async fn negotiate(
    State(state): State<SignalHttpState>,
    Json(request): Json<SignalPathRequest>,
) -> Result<Json<SignalPathResponse>, ApiError> {
    Ok(Json(state.registry.negotiate(request).await?))
}

async fn hole_punch_plan(
    State(state): State<SignalHttpState>,
    Path((source, target)): Path<(String, String)>,
) -> Result<Json<SignalHolePunchPlanResponse>, ApiError> {
    Ok(Json(
        state
            .registry
            .hole_punch_plan(NodeId::from_string(source), NodeId::from_string(target))
            .await?,
    ))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

fn render_prometheus_metrics(metrics: &SignalMetricsResponse) -> String {
    let mut body = String::new();
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_nodes Number of nodes registered with the signal service."
    );
    prometheus_line!(&mut body, "# TYPE ipars_signal_nodes gauge");
    prometheus_line!(&mut body, "ipars_signal_nodes {}", metrics.node_count);
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_relay_candidates Number of relay candidates available for signal path negotiation."
    );
    prometheus_line!(&mut body, "# TYPE ipars_signal_relay_candidates gauge");
    prometheus_line!(
        &mut body,
        "ipars_signal_relay_candidates {}",
        metrics.relay_candidate_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_nat_classifications Number of nodes with NAT classification registered in signal."
    );
    prometheus_line!(&mut body, "# TYPE ipars_signal_nat_classifications gauge");
    prometheus_line!(
        &mut body,
        "ipars_signal_nat_classifications {}",
        metrics.nat_classification_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_stale_nat_classifications Number of signal NAT classifications older than the NAT classification TTL."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_stale_nat_classifications gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_stale_nat_classifications {}",
        metrics.stale_nat_classification_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_fresh_low_confidence_nat_classifications Number of fresh signal NAT classifications below the configured confidence threshold."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_fresh_low_confidence_nat_classifications gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_fresh_low_confidence_nat_classifications {}",
        metrics.fresh_low_confidence_nat_classification_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_fresh_nat_classifications_by_strategy Number of fresh signal NAT classifications by traversal strategy."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_fresh_nat_classifications_by_strategy gauge"
    );
    for strategy_count in &metrics.fresh_nat_classification_strategy_counts {
        prometheus_line!(
            &mut body,
            "ipars_signal_fresh_nat_classifications_by_strategy{{strategy=\"{}\"}} {}",
            strategy_count.strategy.as_str(),
            strategy_count.count
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_health_reports Number of signal health reports stored by state."
    );
    prometheus_line!(&mut body, "# TYPE ipars_signal_health_reports gauge");
    prometheus_line!(
        &mut body,
        "ipars_signal_health_reports{{state=\"healthy\"}} {}",
        metrics.healthy_node_count
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_health_reports{{state=\"degraded\"}} {}",
        metrics.degraded_node_count
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_health_reports{{state=\"unhealthy\"}} {}",
        metrics.unhealthy_node_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_stale_health_reports Number of signal health reports older than the relay health TTL."
    );
    prometheus_line!(&mut body, "# TYPE ipars_signal_stale_health_reports gauge");
    prometheus_line!(
        &mut body,
        "ipars_signal_stale_health_reports {}",
        metrics.stale_health_report_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_stale_endpoint_candidates Number of endpoint candidates older than the signal candidate TTL."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_stale_endpoint_candidates gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_stale_endpoint_candidates {}",
        metrics.stale_endpoint_candidate_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_node_upserts_total Total signal node upsert requests handled."
    );
    prometheus_line!(&mut body, "# TYPE ipars_signal_node_upserts_total counter");
    prometheus_line!(
        &mut body,
        "ipars_signal_node_upserts_total {}",
        metrics.node_upsert_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_path_negotiations_total Total signal path negotiation requests handled."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_path_negotiations_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_path_negotiations_total {}",
        metrics.path_negotiation_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_path_acl_denials_total Total signal path negotiations hidden by cluster ACL policy."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_path_acl_denials_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_path_acl_denials_total {}",
        metrics.path_acl_denied_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_relay_candidate_acl_denials_total Total eligible relay candidates removed from signal negotiation by cluster ACL policy."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_relay_candidate_acl_denials_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_relay_candidate_acl_denials_total {}",
        metrics.relay_candidate_acl_denied_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_path_negotiation_state_total Successful signal path negotiations by selected state."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_path_negotiation_state_total counter"
    );
    for state_count in &metrics.path_negotiation_state_counts {
        prometheus_line!(
            &mut body,
            "ipars_signal_path_negotiation_state_total{{state=\"{}\"}} {}",
            path_state_label(state_count.state),
            state_count.count
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_hole_punch_plans_total Total signal hole-punch plan requests handled."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_hole_punch_plans_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_hole_punch_plans_total {}",
        metrics.hole_punch_plan_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_hole_punch_acl_denials_total Total signal hole-punch plans hidden by cluster ACL policy."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_hole_punch_acl_denials_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_hole_punch_acl_denials_total {}",
        metrics.hole_punch_acl_denied_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_hole_punch_nat_suppressions_total Total hole-punch plans suppressed by fresh NAT classification strategy."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_hole_punch_nat_suppressions_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_hole_punch_nat_suppressions_total {}",
        metrics.hole_punch_nat_suppressed_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_relay_health_ttl_seconds Relay health freshness window used by signal."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_relay_health_ttl_seconds gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_relay_health_ttl_seconds {}",
        metrics.relay_health_ttl_seconds
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_endpoint_candidate_ttl_seconds Endpoint candidate freshness window used by signal."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_endpoint_candidate_ttl_seconds gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_endpoint_candidate_ttl_seconds {}",
        metrics.endpoint_candidate_ttl_seconds
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_nat_classification_ttl_seconds NAT classification freshness window used by signal."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_nat_classification_ttl_seconds gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_nat_classification_ttl_seconds {}",
        metrics.nat_classification_ttl_seconds
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_signal_nat_classification_min_confidence_percent Minimum NAT classification confidence percentage required by signal."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_nat_classification_min_confidence_percent gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_nat_classification_min_confidence_percent {}",
        metrics.nat_classification_min_confidence_percent
    );
    body
}

fn path_state_label(state: PathState) -> &'static str {
    match state {
        PathState::DirectPublic => "DIRECT_PUBLIC",
        PathState::DirectIpv6 => "DIRECT_IPV6",
        PathState::DirectNatTraversal => "DIRECT_NAT_TRAVERSAL",
        PathState::Relay => "RELAY",
        PathState::Unreachable => "UNREACHABLE",
    }
}

#[derive(Debug)]
pub enum ApiError {
    Signal(SignalError),
    BadRequest(String),
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }
}

impl From<SignalError> for ApiError {
    fn from(error: SignalError) -> Self {
        Self::Signal(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::Signal(SignalError::NodeNotFound(node_id)) => {
                (StatusCode::NOT_FOUND, format!("node not found: {node_id}"))
            }
            Self::Signal(SignalError::CandidateOwnerMismatch {
                node_id,
                candidate_node_id,
            }) => (
                StatusCode::BAD_REQUEST,
                format!("candidate for node {node_id} belongs to {candidate_node_id}"),
            ),
            Self::Signal(SignalError::CandidateInvalid {
                node_id,
                kind,
                addr,
                reason,
            }) => (
                StatusCode::BAD_REQUEST,
                format!("candidate {kind:?} at {addr} for node {node_id} is invalid: {reason}"),
            ),
            Self::BadRequest(error) => (StatusCode::BAD_REQUEST, error),
        };
        (status, Json(ErrorResponse { error })).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::body::Body;
    use axum::http::{header, Request};
    use chrono::Utc;
    use ipars_types::api::{
        SignalMetricsResponse, SignalNodeUpsertRequest, SignalPathRequest, SignalPathResponse,
    };
    use ipars_types::{
        CandidateSource, ClusterId, ClusterPolicy, EndpointCandidate, EndpointCandidateKind,
        NatTraversalStrategy, NodeRecord, Role, TokenPolicy, VpnIp,
    };
    use tower::ServiceExt;

    use super::*;

    fn candidate(node_id: &str, kind: EndpointCandidateKind) -> EndpointCandidate {
        EndpointCandidate {
            node_id: NodeId::from_string(node_id),
            kind,
            addr: SocketAddr::from(([203, 0, 113, 10], 51820)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::StunProbe,
        }
    }

    fn node(node_id: &str, candidates: Vec<EndpointCandidate>) -> NodeRecord {
        NodeRecord {
            node_id: NodeId::from_string(node_id),
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
            identity_public_key: format!("identity-{node_id}"),
            wireguard_public_key: format!("wg-{node_id}"),
            role: Role::edge(),
            tags: BTreeSet::new(),
            endpoint_candidates: candidates,
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn http_signal_registers_node_and_negotiates_path(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = Arc::new(SignalRegistry::new(ClusterPolicy::default()));
        let app = router(SignalHttpState::new(registry));
        let source = node(
            "node-a",
            vec![candidate("node-a", EndpointCandidateKind::StunReflexive)],
        );
        let target = node(
            "node-b",
            vec![candidate("node-b", EndpointCandidateKind::PublicUdp)],
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/nodes/node-a")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&SignalNodeUpsertRequest {
                        node: source,
                        nat_classification: None,
                        health: None,
                    })?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/nodes/node-b")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&SignalNodeUpsertRequest {
                        node: target,
                        nat_classification: None,
                        health: None,
                    })?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/paths/negotiate")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&SignalPathRequest {
                        source: NodeId::from_string("node-a"),
                        target: NodeId::from_string("node-b"),
                        source_candidates: vec![candidate(
                            "node-a",
                            EndpointCandidateKind::StunReflexive,
                        )],
                        source_nat_classification: None,
                        desired_routes: Vec::new(),
                    })?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response: SignalPathResponse = serde_json::from_slice(&body)?;
        assert_eq!(
            response.preferred_state,
            ipars_types::PathState::DirectPublic
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/metrics")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let metrics: SignalMetricsResponse = serde_json::from_slice(&body)?;
        assert_eq!(metrics.node_count, 2);
        assert_eq!(metrics.relay_candidate_count, 0);
        assert_eq!(metrics.stale_nat_classification_count, 0);
        assert_eq!(metrics.fresh_low_confidence_nat_classification_count, 0);
        assert!(metrics
            .fresh_nat_classification_strategy_counts
            .iter()
            .any(
                |entry| entry.strategy == NatTraversalStrategy::DirectCandidate && entry.count == 0
            ));
        assert_eq!(metrics.stale_endpoint_candidate_count, 0);
        assert_eq!(metrics.endpoint_candidate_ttl_seconds, 120);
        assert_eq!(metrics.nat_classification_ttl_seconds, 300);
        assert_eq!(metrics.nat_classification_min_confidence_percent, 50);
        assert_eq!(metrics.node_upsert_count, 2);
        assert_eq!(metrics.path_negotiation_count, 1);
        assert_eq!(metrics.path_acl_denied_count, 0);
        assert_eq!(metrics.relay_candidate_acl_denied_count, 0);
        assert_eq!(metrics.hole_punch_acl_denied_count, 0);
        assert_eq!(metrics.hole_punch_nat_suppressed_count, 0);
        assert_eq!(
            signal_path_state_count(&metrics, ipars_types::PathState::DirectPublic),
            1
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("ipars_signal_nodes 2"));
        assert!(body.contains("ipars_signal_stale_nat_classifications 0"));
        assert!(body.contains("ipars_signal_fresh_low_confidence_nat_classifications 0"));
        assert!(body.contains("ipars_signal_stale_endpoint_candidates 0"));
        assert!(body.contains("ipars_signal_endpoint_candidate_ttl_seconds 120"));
        assert!(body.contains("ipars_signal_nat_classification_ttl_seconds 300"));
        assert!(body.contains("ipars_signal_nat_classification_min_confidence_percent 50"));
        assert!(body.contains(
            "ipars_signal_fresh_nat_classifications_by_strategy{strategy=\"direct_candidate\"} 0"
        ));
        assert!(body.contains("ipars_signal_path_negotiations_total 1"));
        assert!(body.contains("ipars_signal_path_acl_denials_total 0"));
        assert!(body.contains("ipars_signal_relay_candidate_acl_denials_total 0"));
        assert!(body.contains("ipars_signal_hole_punch_acl_denials_total 0"));
        assert!(body.contains("ipars_signal_hole_punch_nat_suppressions_total 0"));
        assert!(
            body.contains("ipars_signal_path_negotiation_state_total{state=\"DIRECT_PUBLIC\"} 1")
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_signal_rejects_unowned_endpoint_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = Arc::new(SignalRegistry::new(ClusterPolicy::default()));
        let app = router(SignalHttpState::new(registry));
        let node = node(
            "node-a",
            vec![candidate("node-b", EndpointCandidateKind::StunReflexive)],
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/nodes/node-a")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&SignalNodeUpsertRequest {
                        node,
                        nat_classification: None,
                        health: None,
                    })?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("candidate for node node-a belongs to node-b"));
        Ok(())
    }

    #[tokio::test]
    async fn http_signal_rejects_invalid_endpoint_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = Arc::new(SignalRegistry::new(ClusterPolicy::default()));
        let app = router(SignalHttpState::new(registry));
        let node = node(
            "node-a",
            vec![candidate("node-a", EndpointCandidateKind::Ipv6)],
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/nodes/node-a")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&SignalNodeUpsertRequest {
                        node,
                        nat_classification: None,
                        health: None,
                    })?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("IPv6 candidates must use an IPv6 socket address"));
        Ok(())
    }

    fn signal_path_state_count(
        metrics: &SignalMetricsResponse,
        state: ipars_types::PathState,
    ) -> usize {
        metrics
            .path_negotiation_state_counts
            .iter()
            .find(|entry| entry.state == state)
            .map(|entry| entry.count)
            .unwrap_or(0)
    }
}
