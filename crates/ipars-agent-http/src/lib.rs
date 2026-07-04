use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipars_agent::{AgentError, AgentRuntime};
use ipars_types::api::{
    AgentMetricsResponse, AgentNatClassifyRequest, AgentNatClassifyResponse,
    AgentPathEventsResponse, AgentStatusResponse, AgentStunProbeRequest, AgentStunProbeResponse,
};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct AgentHttpState {
    runtime: Arc<AgentRuntime>,
}

impl AgentHttpState {
    pub fn new(runtime: Arc<AgentRuntime>) -> Self {
        Self { runtime }
    }
}

pub fn router(state: AgentHttpState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/status", get(status))
        .route("/v1/metrics", get(metrics))
        .route("/v1/path-events", get(path_events))
        .route("/v1/stun-probe", post(stun_probe))
        .route("/v1/nat-classification", post(nat_classification))
        .with_state(state)
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn status(State(state): State<AgentHttpState>) -> Json<AgentStatusResponse> {
    Json(state.runtime.status().await)
}

async fn metrics(State(state): State<AgentHttpState>) -> Json<AgentMetricsResponse> {
    Json(state.runtime.metrics().await)
}

async fn path_events(State(state): State<AgentHttpState>) -> Json<AgentPathEventsResponse> {
    Json(AgentPathEventsResponse {
        events: state.runtime.path_change_events().await,
        generated_at: chrono::Utc::now(),
    })
}

async fn stun_probe(
    State(state): State<AgentHttpState>,
    Json(request): Json<AgentStunProbeRequest>,
) -> Result<(StatusCode, Json<AgentStunProbeResponse>), ApiError> {
    let candidate = state
        .runtime
        .probe_stun(request.local_bind, request.stun_server)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(AgentStunProbeResponse { candidate }),
    ))
}

async fn nat_classification(
    State(state): State<AgentHttpState>,
    Json(request): Json<AgentNatClassifyRequest>,
) -> Result<(StatusCode, Json<AgentNatClassifyResponse>), ApiError> {
    let classification = state
        .runtime
        .classify_nat(request.local_bind, request.stun_servers)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(AgentNatClassifyResponse { classification }),
    ))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug)]
pub struct ApiError(AgentError);

impl From<AgentError> for ApiError {
    fn from(error: AgentError) -> Self {
        Self(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            AgentError::Io(_)
            | AgentError::Json(_)
            | AgentError::Crypto(_)
            | AgentError::Stun(_)
            | AgentError::RouteManager(_)
            | AgentError::RoutePlanning(_)
            | AgentError::ControlPlaneClient(_)
            | AgentError::HolePunch(_)
            | AgentError::RelaySession(_)
            | AgentError::WireGuard(_) => StatusCode::SERVICE_UNAVAILABLE,
            AgentError::MissingPeer(_) => StatusCode::NOT_FOUND,
        };
        (
            status,
            Json(ErrorResponse {
                error: self.0.to_string(),
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use chrono::Utc;
    use ipars_agent::{AgentNodeState, AgentRuntime};
    use ipars_types::{ClusterPolicy, NodeId, PathRecord, PathScore, PathState, PeerPathKey};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn http_agent_status_returns_node_keys() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let node_id = runtime.state().node_id.clone();
        let app = router(AgentHttpState::new(runtime));

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/status")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let status: AgentStatusResponse = serde_json::from_slice(&body)?;
        assert_eq!(status.node_id, node_id);
        assert_eq!(status.candidate_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_exports_metrics_and_path_events() -> Result<(), Box<dyn std::error::Error>>
    {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let node_id = runtime.state().node_id.clone();
        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(node_id.clone(), NodeId::from_string("peer-a")),
                selected_state: PathState::Relay,
                selected_candidate: None,
                relay_node: Some(NodeId::from_string("relay-a")),
                score: PathScore {
                    value: 70.0,
                    reasons: vec!["state=Relay".to_string()],
                },
                updated_at: Utc::now(),
                pinned: false,
            })
            .await;
        let app = router(AgentHttpState::new(runtime));

        let metrics_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/metrics")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(metrics_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(metrics_response.into_body(), usize::MAX).await?;
        let metrics: AgentMetricsResponse = serde_json::from_slice(&body)?;
        assert_eq!(metrics.node_id, node_id);
        assert_eq!(metrics.path_count, 1);
        assert_eq!(metrics.path_change_event_count, 1);

        let events_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/path-events")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(events_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(events_response.into_body(), usize::MAX).await?;
        let events: AgentPathEventsResponse = serde_json::from_slice(&body)?;
        assert_eq!(events.events.len(), 1);
        assert_eq!(events.events[0].new_state, PathState::Relay);
        Ok(())
    }
}
