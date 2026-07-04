use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use ipars_signal::{SignalError, SignalRegistry};
use ipars_types::api::{
    SignalHolePunchPlanResponse, SignalNodeUpsertRequest, SignalNodeUpsertResponse,
    SignalPathRequest, SignalPathResponse,
};
use ipars_types::NodeId;
use serde::Serialize;

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
        .route("/v1/nodes/{node_id}", put(upsert_node))
        .route("/v1/paths/negotiate", post(negotiate))
        .route("/v1/hole-punch/{source}/{target}", get(hole_punch_plan))
        .with_state(state)
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
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
            .upsert_node_with_nat(request.node, request.nat_classification)
            .await,
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
    use ipars_types::api::{SignalNodeUpsertRequest, SignalPathRequest, SignalPathResponse};
    use ipars_types::{
        CandidateSource, ClusterId, ClusterPolicy, EndpointCandidate, EndpointCandidateKind,
        NodeRecord, Role, TokenPolicy, VpnIp,
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
        let target = node(
            "node-b",
            vec![candidate("node-b", EndpointCandidateKind::PublicUdp)],
        );

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
                    })?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
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
        Ok(())
    }
}
