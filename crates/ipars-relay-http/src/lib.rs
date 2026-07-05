use std::fmt::Write;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipars_relay::{RelayError, RelayService};
use ipars_types::api::{RelayAdmissionRequest, RelayAdmissionResponse, RelayStatusResponse};
use ipars_types::HealthState;
use serde::Serialize;

macro_rules! prometheus_line {
    ($body:expr, $($arg:tt)*) => {{
        let _ = writeln!($body, $($arg)*);
    }};
}

#[derive(Debug, Clone)]
pub struct RelayHttpState {
    relay: Arc<RelayService>,
    admission_bearer_token: Option<String>,
}

impl RelayHttpState {
    pub fn new(relay: Arc<RelayService>) -> Self {
        Self {
            relay,
            admission_bearer_token: None,
        }
    }

    pub fn require_admission_bearer_token(mut self, token: String) -> Self {
        self.admission_bearer_token = Some(token);
        self
    }

    fn authorize_admission(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        let Some(expected) = self.admission_bearer_token.as_deref() else {
            return Ok(());
        };
        let Some(provided) = bearer_token_from_headers(headers) else {
            return Err(ApiError::unauthorized(
                "relay admission bearer token is required",
            ));
        };
        if relay_admission_token_matches(expected, provided) {
            Ok(())
        } else {
            Err(ApiError::unauthorized(
                "relay admission bearer token was rejected",
            ))
        }
    }
}

pub fn router(state: RelayHttpState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(prometheus_metrics))
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

async fn prometheus_metrics(State(state): State<RelayHttpState>) -> impl IntoResponse {
    let status = state.relay.status().await;
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render_prometheus_metrics(&status),
    )
}

async fn admit(
    State(state): State<RelayHttpState>,
    headers: HeaderMap,
    Json(request): Json<RelayAdmissionRequest>,
) -> Result<(StatusCode, Json<RelayAdmissionResponse>), ApiError> {
    if let Err(error) = state.authorize_admission(&headers) {
        state.relay.record_unauthorized_admission_attempt();
        return Err(error);
    }
    Ok((StatusCode::CREATED, Json(state.relay.admit(request).await?)))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

fn render_prometheus_metrics(status: &RelayStatusResponse) -> String {
    let relay_node = prometheus_label(status.relay_node.as_str());
    let mut body = String::new();
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_active_sessions Number of active relay sessions."
    );
    prometheus_line!(&mut body, "# TYPE ipars_relay_active_sessions gauge");
    prometheus_line!(
        &mut body,
        "ipars_relay_active_sessions{{relay_node=\"{relay_node}\"}} {}",
        status.capability.active_sessions
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_max_sessions Configured relay session capacity."
    );
    prometheus_line!(&mut body, "# TYPE ipars_relay_max_sessions gauge");
    prometheus_line!(
        &mut body,
        "ipars_relay_max_sessions{{relay_node=\"{relay_node}\"}} {}",
        status.capability.max_sessions
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_available_sessions Remaining relay session capacity."
    );
    prometheus_line!(&mut body, "# TYPE ipars_relay_available_sessions gauge");
    prometheus_line!(
        &mut body,
        "ipars_relay_available_sessions{{relay_node=\"{relay_node}\"}} {}",
        status.capability.available_capacity()
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_max_mbps Configured relay throughput budget in megabits per second."
    );
    prometheus_line!(&mut body, "# TYPE ipars_relay_max_mbps gauge");
    prometheus_line!(
        &mut body,
        "ipars_relay_max_mbps{{relay_node=\"{relay_node}\"}} {}",
        status.capability.max_mbps
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_enabled_by_policy Whether relay admission is enabled by policy."
    );
    prometheus_line!(&mut body, "# TYPE ipars_relay_enabled_by_policy gauge");
    prometheus_line!(
        &mut body,
        "ipars_relay_enabled_by_policy{{relay_node=\"{relay_node}\"}} {}",
        u8::from(status.capability.enabled_by_policy)
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_e2e_only Whether relay forwarding is restricted to end-to-end encrypted opaque payloads."
    );
    prometheus_line!(&mut body, "# TYPE ipars_relay_e2e_only gauge");
    prometheus_line!(
        &mut body,
        "ipars_relay_e2e_only{{relay_node=\"{relay_node}\"}} {}",
        u8::from(status.capability.e2e_only)
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_admission_attempts_total Total relay session admission attempts."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_relay_admission_attempts_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_relay_admission_attempts_total{{relay_node=\"{relay_node}\"}} {}",
        status.admission_attempt_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_admission_success_total Total relay session admissions accepted."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_relay_admission_success_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_relay_admission_success_total{{relay_node=\"{relay_node}\"}} {}",
        status.admission_success_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_admission_failures_total Total relay session admission failures."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_relay_admission_failures_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_relay_admission_failures_total{{relay_node=\"{relay_node}\"}} {}",
        status.admission_failure_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_datagrams_received_total Total UDP relay datagrams received."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_relay_datagrams_received_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_relay_datagrams_received_total{{relay_node=\"{relay_node}\"}} {}",
        status.dataplane.datagrams_received
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_datagram_bytes_received_total Total UDP relay datagram bytes received, including relay metadata."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_relay_datagram_bytes_received_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_relay_datagram_bytes_received_total{{relay_node=\"{relay_node}\"}} {}",
        status.dataplane.datagram_bytes_received
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_datagrams_forwarded_total Total UDP relay datagrams accepted for forwarding."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_relay_datagrams_forwarded_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_relay_datagrams_forwarded_total{{relay_node=\"{relay_node}\"}} {}",
        status.dataplane.datagrams_forwarded
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_datagrams_dropped_total Total UDP relay datagrams dropped before forwarding."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_relay_datagrams_dropped_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_relay_datagrams_dropped_total{{relay_node=\"{relay_node}\"}} {}",
        status.dataplane.datagrams_dropped
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_datagram_bytes_dropped_total Total UDP relay datagram bytes dropped, including relay metadata."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_relay_datagram_bytes_dropped_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_relay_datagram_bytes_dropped_total{{relay_node=\"{relay_node}\"}} {}",
        status.dataplane.datagram_bytes_dropped
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_datagrams_dropped_by_reason_total Total UDP relay datagrams dropped by reason."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_relay_datagrams_dropped_by_reason_total counter"
    );
    for (reason, count) in &status.dataplane.drops_by_reason {
        prometheus_line!(
            &mut body,
            "ipars_relay_datagrams_dropped_by_reason_total{{relay_node=\"{relay_node}\",reason=\"{}\"}} {count}",
            reason.as_str()
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_bytes_forwarded_total Total opaque payload bytes accepted for relay forwarding."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_relay_bytes_forwarded_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_relay_bytes_forwarded_total{{relay_node=\"{relay_node}\"}} {}",
        status.dataplane.payload_bytes_forwarded
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_relay_health Relay health state as a labeled gauge."
    );
    prometheus_line!(&mut body, "# TYPE ipars_relay_health gauge");
    prometheus_line!(
        &mut body,
        "ipars_relay_health{{relay_node=\"{relay_node}\",state=\"{}\"}} 1",
        health_label(status.health)
    );
    body
}

fn health_label(state: HealthState) -> &'static str {
    match state {
        HealthState::Healthy => "healthy",
        HealthState::Degraded => "degraded",
        HealthState::Unhealthy => "unhealthy",
    }
}

fn prometheus_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

const MAX_RELAY_ADMISSION_BEARER_TOKEN_BYTES: usize = 512;

fn bearer_token_from_headers(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.contains(char::is_whitespace)
    {
        return None;
    }
    Some(token)
}

fn relay_admission_token_matches(expected: &str, provided: &str) -> bool {
    if expected.is_empty()
        || provided.is_empty()
        || expected.len() > MAX_RELAY_ADMISSION_BEARER_TOKEN_BYTES
        || provided.len() > MAX_RELAY_ADMISSION_BEARER_TOKEN_BYTES
    {
        return false;
    }

    let expected = expected.as_bytes();
    let provided = provided.as_bytes();
    let mut diff = expected.len() ^ provided.len();
    for index in 0..MAX_RELAY_ADMISSION_BEARER_TOKEN_BYTES {
        let expected_byte = expected.get(index).copied().unwrap_or_default();
        let provided_byte = provided.get(index).copied().unwrap_or_default();
        diff |= usize::from(expected_byte ^ provided_byte);
    }
    diff == 0
}

#[derive(Debug)]
pub enum ApiError {
    Relay(RelayError),
    Unauthorized(&'static str),
}

impl ApiError {
    fn unauthorized(message: &'static str) -> Self {
        Self::Unauthorized(message)
    }
}

impl From<RelayError> for ApiError {
    fn from(error: RelayError) -> Self {
        Self::Relay(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let error = match self {
            ApiError::Relay(error) => error,
            ApiError::Unauthorized(message) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Bearer")],
                    Json(ErrorResponse {
                        error: message.to_string(),
                    }),
                )
                    .into_response();
            }
        };
        let status = match error {
            RelayError::AdmissionDenied => StatusCode::FORBIDDEN,
            RelayError::UnknownSession => StatusCode::NOT_FOUND,
            RelayError::SessionExpired => StatusCode::GONE,
            RelayError::InvalidSessionCredential => StatusCode::FORBIDDEN,
            RelayError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            RelayError::MalformedFrame => StatusCode::BAD_REQUEST,
            RelayError::FrameTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            RelayError::Socket(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(ErrorResponse {
                error: error.to_string(),
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
        let app = router(RelayHttpState::new(relay.clone()));

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
            .clone()
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
        assert_eq!(response.admission_attempt_count, 1);
        assert_eq!(response.admission_success_count, 1);
        assert_eq!(response.admission_failure_count, 0);
        assert_eq!(response.dataplane.datagrams_received, 0);

        let table = relay.table();
        let malformed = table
            .write()
            .await
            .forward_datagram_for_addr(SocketAddr::from(([10, 0, 0, 1], 10000)), b"bad frame");
        assert!(matches!(malformed, Err(RelayError::MalformedFrame)));

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static(
                "text/plain; version=0.0.4; charset=utf-8"
            ))
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("ipars_relay_active_sessions"));
        assert!(body.contains("ipars_relay_active_sessions{relay_node=\"relay-a\"} 1"));
        assert!(body.contains("ipars_relay_e2e_only{relay_node=\"relay-a\"} 1"));
        assert!(body.contains("ipars_relay_admission_attempts_total"));
        assert!(body.contains("ipars_relay_admission_attempts_total{relay_node=\"relay-a\"} 1"));
        assert!(body.contains("ipars_relay_admission_success_total{relay_node=\"relay-a\"} 1"));
        assert!(body.contains("ipars_relay_admission_failures_total{relay_node=\"relay-a\"} 0"));
        assert!(body.contains("ipars_relay_datagrams_received_total"));
        assert!(body.contains("ipars_relay_datagrams_dropped_total{relay_node=\"relay-a\"} 1"));
        assert!(body.contains(
            "ipars_relay_datagrams_dropped_by_reason_total{relay_node=\"relay-a\",reason=\"malformed_frame\"} 1"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn http_relay_admission_can_require_bearer_token(
    ) -> Result<(), Box<dyn std::error::Error>> {
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
        let app = router(
            RelayHttpState::new(relay.clone())
                .require_admission_bearer_token("cluster-relay-secret".to_string()),
        );

        let request_body = serde_json::to_vec(&RelayAdmissionRequest {
            left: NodeId::from_string("left"),
            right: NodeId::from_string("right"),
            left_addr: SocketAddr::from(([10, 0, 0, 1], 10000)),
            right_addr: SocketAddr::from(([10, 0, 0, 2], 10000)),
        })?;
        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request_body.clone()))?,
            )
            .await?;
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            missing.headers().get(header::WWW_AUTHENTICATE),
            Some(&header::HeaderValue::from_static("Bearer"))
        );

        let rejected = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer wrong-secret")
                    .body(Body::from(request_body.clone()))?,
            )
            .await?;
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);

        let accepted = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer cluster-relay-secret")
                    .body(Body::from(request_body))?,
            )
            .await?;

        assert_eq!(accepted.status(), StatusCode::CREATED);
        let status = relay.status().await;
        assert_eq!(status.admission_attempt_count, 3);
        assert_eq!(status.admission_success_count, 1);
        assert_eq!(status.admission_failure_count, 2);
        Ok(())
    }
}
