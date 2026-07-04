use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipars_relay::{RelayError, RelayService};
use ipars_types::api::{RelayAdmissionRequest, RelayAdmissionResponse, RelayStatusResponse};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct RelayHttpState {
    relay: Arc<RelayService>,
}

impl RelayHttpState {
    pub fn new(relay: Arc<RelayService>) -> Self {
        Self { relay }
    }
}

pub fn router(state: RelayHttpState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/status", get(status))
        .route("/v1/sessions", post(admit))
        .with_state(state)
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn status(State(state): State<RelayHttpState>) -> Json<RelayStatusResponse> {
    Json(state.relay.status().await)
}

async fn admit(
    State(state): State<RelayHttpState>,
    Json(request): Json<RelayAdmissionRequest>,
) -> Result<(StatusCode, Json<RelayAdmissionResponse>), ApiError> {
    Ok((StatusCode::CREATED, Json(state.relay.admit(request).await?)))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug)]
pub struct ApiError(RelayError);

impl From<RelayError> for ApiError {
    fn from(error: RelayError) -> Self {
        Self(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            RelayError::AdmissionDenied => StatusCode::FORBIDDEN,
            RelayError::UnknownSession => StatusCode::NOT_FOUND,
            RelayError::SessionExpired => StatusCode::GONE,
            RelayError::InvalidSessionCredential => StatusCode::FORBIDDEN,
            RelayError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            RelayError::MalformedFrame => StatusCode::BAD_REQUEST,
            RelayError::Socket(_) => StatusCode::SERVICE_UNAVAILABLE,
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
    use std::net::SocketAddr;

    use axum::body::Body;
    use axum::http::{header, Request};
    use ipars_types::api::{RelayAdmissionRequest, RelayAdmissionResponse, RelayStatusResponse};
    use ipars_types::{NodeId, RelayCapability};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn http_relay_admits_session_and_reports_status() -> Result<(), Box<dyn std::error::Error>>
    {
        let relay = Arc::new(RelayService::new(
            NodeId::from_string("relay-a"),
            RelayCapability {
                enabled_by_policy: true,
                public_endpoint: Some(SocketAddr::from(([203, 0, 113, 10], 51820))),
                admission_url: Some("http://203.0.113.10:9580".to_string()),
                max_sessions: 10,
                active_sessions: 0,
                max_mbps: 1000,
                e2e_only: true,
            },
        ));
        let app = router(RelayHttpState::new(relay));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&RelayAdmissionRequest {
                        left: NodeId::from_string("left"),
                        right: NodeId::from_string("right"),
                        left_addr: SocketAddr::from(([10, 0, 0, 1], 10000)),
                        right_addr: SocketAddr::from(([10, 0, 0, 2], 10000)),
                    })?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response: RelayAdmissionResponse = serde_json::from_slice(&body)?;
        assert_eq!(response.session_id, "left:right");
        assert!(!response.session_token.is_empty());
        assert!(response.expires_at > chrono::Utc::now());

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
        let response: RelayStatusResponse = serde_json::from_slice(&body)?;
        assert_eq!(response.capability.active_sessions, 1);
        Ok(())
    }
}
