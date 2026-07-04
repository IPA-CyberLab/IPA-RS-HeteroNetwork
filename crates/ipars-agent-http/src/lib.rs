use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipars_agent::{AgentError, AgentRuntime};
use ipars_types::api::{AgentStatusResponse, AgentStunProbeRequest, AgentStunProbeResponse};
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
        .route("/v1/stun-probe", post(stun_probe))
        .with_state(state)
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn status(State(state): State<AgentHttpState>) -> Json<AgentStatusResponse> {
    Json(state.runtime.status().await)
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
    use ipars_types::ClusterPolicy;
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
}
