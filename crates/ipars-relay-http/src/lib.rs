use std::fmt::Write;
use std::sync::Arc;
pub mod transport;

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipars_relay::{RelayError, RelayService};
use ipars_types::api::{
    RelayAdmissionFailureReason, RelayAdmissionRequest, RelayAdmissionResponse,
    RelayDataplaneDropReason, RelayStatusResponse,
};
use ipars_types::HealthState;
use serde::Serialize;

macro_rules! prometheus_line {
    ($body:expr, $($arg:tt)*) => {{
        let _ = writeln!($body, $($arg)*);
    }};
}

#[derive(Clone)]
pub struct RelayHttpState {
    relay: Arc<RelayService>,
    admission_bearer_token: Option<Arc<str>>,
    operator_api_bearer_token: Option<Arc<str>>,
    http_transport: Option<Arc<ipars_http_tunnel::TunnelHub>>,
    tcp_endpoint: Option<std::net::SocketAddr>,
    transport_urls: Vec<String>,
}

impl RelayHttpState {
    pub fn new(relay: Arc<RelayService>) -> Self {
        Self {
            relay,
            admission_bearer_token: None,
            operator_api_bearer_token: None,
            http_transport: None,
            tcp_endpoint: None,
            transport_urls: Vec::new(),
        }
    }

    pub fn require_admission_bearer_token(mut self, token: String) -> Self {
        self.admission_bearer_token = Some(Arc::from(token));
        self
    }
    pub fn with_http_transport(mut self, backend: std::net::SocketAddr, maximum: usize) -> Self {
        self.http_transport = Some(Arc::new(ipars_http_tunnel::TunnelHub::new(
            backend, maximum,
        )));
        self
    }

    pub fn with_tcp_endpoint(mut self, endpoint: std::net::SocketAddr) -> Self {
        self.tcp_endpoint = Some(endpoint);
        self
    }
    pub fn with_transport_urls(mut self, urls: Vec<String>) -> Self {
        self.transport_urls = urls;
        self
    }
    pub fn tcp_authorizer(&self) -> ipars_http_tunnel::tcp::Authorizer {
        let state = self.clone();
        Arc::new(move |request, body| {
            let state = state.clone();
            Box::pin(async move {
                if !request.relay {
                    return Err(ipars_http_tunnel::TunnelError::Unauthorized);
                }
                let hub = state
                    .http_transport
                    .clone()
                    .ok_or(ipars_http_tunnel::TunnelError::Unauthorized)?;
                let (session, expires) = state
                    .relay
                    .table()
                    .write()
                    .await
                    .authorize_http_announcement(&request.node, &body)
                    .map_err(|_| ipars_http_tunnel::TunnelError::Unauthorized)?;
                let lifetime = (expires - chrono::Utc::now())
                    .to_std()
                    .map_err(|_| ipars_http_tunnel::TunnelError::Unauthorized)?;
                let opened = hub
                    .open(
                        request.node.clone(),
                        ipars_types::api::DataPlaneTransport::Tcp,
                        &body,
                        false,
                        lifetime,
                        format!("{session}:{}", request.node),
                    )
                    .await?;
                Ok((hub, opened))
            })
        })
    }

    pub fn require_operator_api_bearer_token(mut self, token: String) -> Self {
        self.operator_api_bearer_token = Some(Arc::from(token));
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
        if relay_api_token_matches(expected, provided) {
            Ok(())
        } else {
            Err(ApiError::unauthorized(
                "relay admission bearer token was rejected",
            ))
        }
    }
}

pub fn router(state: RelayHttpState) -> Router {
    let protocol = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/status", get(status))
        .route("/v1/sessions", post(admit));
    let app = if let Some(token) = state.operator_api_bearer_token.clone() {
        let operator = Router::new()
            .route("/metrics", get(prometheus_metrics))
            .route_layer(middleware::from_fn_with_state(
                token,
                require_relay_operator_api_bearer,
            ));
        protocol.merge(operator)
    } else {
        protocol
    };
    app.merge(transport::routes()).with_state(state)
}

async fn require_relay_operator_api_bearer(
    State(expected): State<Arc<str>>,
    request: Request,
    next: Next,
) -> Response {
    let provided = bearer_token_from_headers(request.headers());
    if !provided.is_some_and(|provided| relay_api_token_matches(&expected, provided)) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(ErrorResponse {
                error: "relay operator API bearer token was rejected".to_string(),
            }),
        )
            .into_response();
    }
    next.run(request).await
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn status(State(state): State<RelayHttpState>) -> Json<RelayStatusResponse> {
    let mut status = state.relay.status().await;
    status.tcp_endpoint = state.tcp_endpoint;
    status.transport_urls = state.transport_urls.clone();
    if let Some(hub) = &state.http_transport {
        status.http_transports = hub.observations();
    }
    Json(status)
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
        state.relay.record_unauthorized_admission_attempt()?;
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
        "# HELP ipars_relay_status_generated_timestamp_seconds Unix timestamp of the relay status snapshot."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_relay_status_generated_timestamp_seconds gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_relay_status_generated_timestamp_seconds{{relay_node=\"{relay_node}\"}} {}",
        status.generated_at.timestamp().max(0)
    );
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
        "# HELP ipars_relay_max_sessions_per_node Configured active relay session cap per participating node. Zero means disabled."
    );
    prometheus_line!(&mut body, "# TYPE ipars_relay_max_sessions_per_node gauge");
    prometheus_line!(
        &mut body,
        "ipars_relay_max_sessions_per_node{{relay_node=\"{relay_node}\"}} {}",
        status.max_sessions_per_node.unwrap_or_default()
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
        "# HELP ipars_relay_admission_failures_by_reason_total Total relay session admission failures by reason."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_relay_admission_failures_by_reason_total counter"
    );
    for reason in RelayAdmissionFailureReason::ALL {
        let count = status
            .admission_failures_by_reason
            .get(&reason)
            .copied()
            .unwrap_or_default();
        prometheus_line!(
            &mut body,
            "ipars_relay_admission_failures_by_reason_total{{relay_node=\"{relay_node}\",reason=\"{}\"}} {count}",
            reason.as_str()
        );
    }
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
    for reason in RelayDataplaneDropReason::ALL {
        let count = status
            .dataplane
            .drops_by_reason
            .get(&reason)
            .copied()
            .unwrap_or_default();
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

const MIN_RELAY_API_BEARER_TOKEN_BYTES: usize = 32;
const MAX_RELAY_API_BEARER_TOKEN_BYTES: usize = 512;

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

fn relay_api_token_matches(expected: &str, provided: &str) -> bool {
    if expected.len() < MIN_RELAY_API_BEARER_TOKEN_BYTES
        || provided.len() < MIN_RELAY_API_BEARER_TOKEN_BYTES
        || expected.len() > MAX_RELAY_API_BEARER_TOKEN_BYTES
        || provided.len() > MAX_RELAY_API_BEARER_TOKEN_BYTES
    {
        return false;
    }

    let expected = expected.as_bytes();
    let provided = provided.as_bytes();
    let mut diff = expected.len() ^ provided.len();
    for index in 0..MAX_RELAY_API_BEARER_TOKEN_BYTES {
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
            RelayError::InvalidAdmissionRequest => StatusCode::BAD_REQUEST,
            RelayError::AdmissionDenied => StatusCode::FORBIDDEN,
            RelayError::NodeSessionLimitExceeded => StatusCode::FORBIDDEN,
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
    use ipars_relay::encode_relay_datagram;
    use ipars_types::api::{
        RelayAdmissionFailureReason, RelayAdmissionRequest, RelayAdmissionResponse,
        RelayDataplaneDropReason, RelayStatusResponse,
    };
    use ipars_types::{NodeId, RelayCapability};
    use tower::ServiceExt;

    use super::*;

    const OPERATOR_API_BEARER_TOKEN: &str = "relay-test-operator-token-with-32-bytes";

    fn test_relay() -> Arc<RelayService> {
        Arc::new(RelayService::new(
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
        ))
    }

    #[test]
    fn relay_bearer_comparison_rejects_short_credentials() {
        assert!(!relay_api_token_matches("too-short", "too-short"));
        assert!(relay_api_token_matches(
            OPERATOR_API_BEARER_TOKEN,
            OPERATOR_API_BEARER_TOKEN
        ));
    }

    #[tokio::test]
    async fn relay_operator_routes_are_disabled_without_a_credential(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let app = router(RelayHttpState::new(test_relay()));
        let metrics = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(metrics.status(), StatusCode::NOT_FOUND);
        let status = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/status")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(status.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn relay_operator_routes_require_the_configured_credential(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let app = router(
            RelayHttpState::new(test_relay())
                .require_operator_api_bearer_token(OPERATOR_API_BEARER_TOKEN.to_string()),
        );
        for authorization in [
            None,
            Some("Bearer too-short"),
            Some("Bearer wrong-relay-token-with-at-least-32-bytes"),
        ] {
            let mut request = Request::builder().method("GET").uri("/metrics");
            if let Some(authorization) = authorization {
                request = request.header(header::AUTHORIZATION, authorization);
            }
            let response = app.clone().oneshot(request.body(Body::empty())?).await?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.headers().get(header::WWW_AUTHENTICATE),
                Some(&header::HeaderValue::from_static("Bearer"))
            );
        }
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

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
        let app = router(
            RelayHttpState::new(relay.clone())
                .require_operator_api_bearer_token(OPERATOR_API_BEARER_TOKEN.to_string()),
        );

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
        let admission: RelayAdmissionResponse = serde_json::from_slice(&body)?;
        assert_eq!(admission.session_id, "left:right");
        assert!(!admission.session_token.is_empty());
        assert!(admission.expires_at > chrono::Utc::now());

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
        assert!(response.generated_at <= chrono::Utc::now());
        assert_eq!(response.admission_attempt_count, 1);
        assert_eq!(response.admission_success_count, 1);
        assert_eq!(response.admission_failure_count, 0);
        assert_eq!(
            response.admission_failures_by_reason.len(),
            RelayAdmissionFailureReason::ALL.len()
        );
        assert_eq!(
            response
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::Unauthorized),
            Some(&0)
        );
        assert_eq!(
            response
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::InvalidAdmissionRequest),
            Some(&0)
        );
        assert_eq!(response.dataplane.datagrams_received, 0);
        assert_eq!(
            response.dataplane.drops_by_reason.len(),
            RelayDataplaneDropReason::ALL.len()
        );
        assert_eq!(
            response
                .dataplane
                .drops_by_reason
                .get(&RelayDataplaneDropReason::MalformedFrame),
            Some(&0)
        );

        let table = relay.table();
        let malformed = table
            .write()
            .await
            .forward_datagram_for_addr(SocketAddr::from(([10, 0, 0, 1], 10000)), b"bad frame");
        assert!(matches!(malformed, Err(RelayError::MalformedFrame)));
        let invalid_credential = encode_relay_datagram(
            &admission.session_id,
            "wrong-session-token",
            b"opaque-payload",
        )?;
        let invalid_credential = table.write().await.forward_datagram_for_addr(
            SocketAddr::from(([10, 0, 0, 1], 10000)),
            &invalid_credential,
        );
        assert!(matches!(
            invalid_credential,
            Err(RelayError::InvalidSessionCredential)
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
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
        assert!(body.contains("ipars_relay_status_generated_timestamp_seconds"));
        assert!(body
            .contains("ipars_relay_status_generated_timestamp_seconds{relay_node=\"relay-a\"} "));
        assert!(body.contains("ipars_relay_active_sessions"));
        assert!(body.contains("ipars_relay_active_sessions{relay_node=\"relay-a\"} 1"));
        assert!(body.contains("ipars_relay_max_sessions_per_node{relay_node=\"relay-a\"} 0"));
        assert!(body.contains("ipars_relay_e2e_only{relay_node=\"relay-a\"} 1"));
        assert!(body.contains("ipars_relay_admission_attempts_total"));
        assert!(body.contains("ipars_relay_admission_attempts_total{relay_node=\"relay-a\"} 1"));
        assert!(body.contains("ipars_relay_admission_success_total{relay_node=\"relay-a\"} 1"));
        assert!(body.contains("ipars_relay_admission_failures_total{relay_node=\"relay-a\"} 0"));
        assert!(body.contains("ipars_relay_admission_failures_by_reason_total"));
        assert!(body.contains(
            "ipars_relay_admission_failures_by_reason_total{relay_node=\"relay-a\",reason=\"unauthorized\"} 0"
        ));
        assert!(body.contains(
            "ipars_relay_admission_failures_by_reason_total{relay_node=\"relay-a\",reason=\"invalid_admission_request\"} 0"
        ));
        assert!(body.contains(
            "ipars_relay_admission_failures_by_reason_total{relay_node=\"relay-a\",reason=\"internal_error\"} 0"
        ));
        assert!(body.contains("ipars_relay_datagrams_received_total"));
        assert!(body.contains("ipars_relay_datagrams_dropped_total{relay_node=\"relay-a\"} 2"));
        assert!(body.contains(
            "ipars_relay_datagrams_dropped_by_reason_total{relay_node=\"relay-a\",reason=\"unknown_session\"} 0"
        ));
        assert!(body.contains(
            "ipars_relay_datagrams_dropped_by_reason_total{relay_node=\"relay-a\",reason=\"invalid_session_credential\"} 1"
        ));
        assert!(body.contains(
            "ipars_relay_datagrams_dropped_by_reason_total{relay_node=\"relay-a\",reason=\"malformed_frame\"} 1"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn http_relay_rejects_unsafe_node_id_admission() -> Result<(), Box<dyn std::error::Error>>
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
        let app = router(
            RelayHttpState::new(relay.clone())
                .require_operator_api_bearer_token(OPERATOR_API_BEARER_TOKEN.to_string()),
        );

        let rejected = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&RelayAdmissionRequest {
                        left: NodeId::from_string("left/../spoof"),
                        right: NodeId::from_string("right"),
                        left_addr: SocketAddr::from(([10, 0, 0, 1], 10000)),
                        right_addr: SocketAddr::from(([10, 0, 0, 2], 10000)),
                    })?))?,
            )
            .await?;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

        let status = relay.status().await;
        assert_eq!(status.admission_attempt_count, 1);
        assert_eq!(status.admission_success_count, 0);
        assert_eq!(status.admission_failure_count, 1);
        assert_eq!(
            status
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::InvalidAdmissionRequest),
            Some(&1)
        );

        let metrics = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(metrics.status(), StatusCode::OK);
        let body = axum::body::to_bytes(metrics.into_body(), usize::MAX).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains(
            "ipars_relay_admission_failures_by_reason_total{relay_node=\"relay-a\",reason=\"invalid_admission_request\"} 1"
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
                .require_admission_bearer_token(
                    "cluster-relay-secret-with-at-least-32-bytes".to_string(),
                )
                .require_operator_api_bearer_token(OPERATOR_API_BEARER_TOKEN.to_string()),
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
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        "Bearer cluster-relay-secret-with-at-least-32-bytes",
                    )
                    .body(Body::from(request_body))?,
            )
            .await?;

        assert_eq!(accepted.status(), StatusCode::CREATED);
        let status = relay.status().await;
        assert_eq!(status.admission_attempt_count, 3);
        assert_eq!(status.admission_success_count, 1);
        assert_eq!(status.admission_failure_count, 2);
        assert_eq!(
            status
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::Unauthorized),
            Some(&2)
        );

        let metrics = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(metrics.status(), StatusCode::OK);
        let body = axum::body::to_bytes(metrics.into_body(), usize::MAX).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains(
            "ipars_relay_admission_failures_by_reason_total{relay_node=\"relay-a\",reason=\"unauthorized\"} 2"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn http_relay_admission_rate_limits_unauthorized_attempts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let relay = Arc::new(RelayService::with_session_ttl_and_admission_rate_limit(
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
            chrono::Duration::seconds(300),
            Some(ipars_relay::RelayAdmissionRateLimit {
                max_attempts: 1,
                window: chrono::Duration::seconds(60),
            }),
        ));
        let app = router(
            RelayHttpState::new(relay.clone()).require_admission_bearer_token(
                "cluster-relay-secret-with-at-least-32-bytes".to_string(),
            ),
        );

        let request_body = serde_json::to_vec(&RelayAdmissionRequest {
            left: NodeId::from_string("left"),
            right: NodeId::from_string("right"),
            left_addr: SocketAddr::from(([10, 0, 0, 1], 10000)),
            right_addr: SocketAddr::from(([10, 0, 0, 2], 10000)),
        })?;

        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request_body.clone()))?,
            )
            .await?;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let limited = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request_body))?,
            )
            .await?;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

        let status = relay.status().await;
        assert_eq!(status.admission_attempt_count, 2);
        assert_eq!(status.admission_success_count, 0);
        assert_eq!(status.admission_failure_count, 2);
        assert_eq!(
            status
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::Unauthorized),
            Some(&1)
        );
        assert_eq!(
            status
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::RateLimited),
            Some(&1)
        );
        Ok(())
    }
    #[tokio::test]
    async fn http_transport_interoperates_with_udp_and_http_relay_peers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use ipars_http_tunnel::{
            append_packet, decode_batch, OpenResponse, NODE_HEADER, TOKEN_SCHEME,
        };
        use ipars_relay::{
            encode_relay_datagram_with_route, encode_relay_endpoint_announcement,
            encode_relay_endpoint_probe, UdpRelay,
        };
        let service = test_relay();
        let udp = UdpRelay::bind("127.0.0.1:0".parse()?).await?;
        let backend = udp.local_addr()?;
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        let serving = tokio::spawn(udp.serve(service.table(), receiver));
        let left = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let right = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let admitted = service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left"),
                right: NodeId::from_string("right"),
                left_addr: left.local_addr()?,
                right_addr: right.local_addr()?,
            })
            .await?;
        let state = RelayHttpState::new(service).with_http_transport(backend, 16);
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let tcp_endpoint = tcp_listener.local_addr()?;
        let (tcp_shutdown, tcp_receiver) = tokio::sync::watch::channel(false);
        let tcp_serving = tokio::spawn(ipars_http_tunnel::tcp::serve(
            tcp_listener,
            state.tcp_authorizer(),
            tcp_receiver,
        ));
        let app = router(state);
        let announcement = |node: &str, other: &str| {
            encode_relay_endpoint_probe(
                &admitted.session_id,
                &admitted.session_token,
                &NodeId::from_string(node),
                &NodeId::from_string(other),
            )
        };
        let request =
            |method: &str, path: &str, token: Option<&str>, node: Option<&str>, body: Vec<u8>| {
                let mut request = Request::builder().method(method).uri(path);
                if let Some(token) = token {
                    request = request.header("authorization", format!("{TOKEN_SCHEME}{token}"));
                }
                if let Some(node) = node {
                    request = request.header(NODE_HEADER, node);
                }
                request.body(Body::from(body))
            };
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/v1/tunnels/relay/open",
                None,
                Some("left"),
                announcement("left", "right")?,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let left_http: OpenResponse =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
        right
            .send_to(
                &encode_relay_endpoint_announcement(
                    &admitted.session_id,
                    &admitted.session_token,
                    &NodeId::from_string("right"),
                    &NodeId::from_string("left"),
                )?,
                backend,
            )
            .await?;
        let mut packet = vec![0_u8; 148];
        packet[0] = 1;
        packet[4] = 7;
        let frame = encode_relay_datagram_with_route(
            &admitted.session_id,
            &admitted.session_token,
            &NodeId::from_string("left"),
            &NodeId::from_string("right"),
            &packet,
        )?;
        let mut batch = Vec::new();
        append_packet(&mut batch, &frame)?;
        assert_eq!(
            app.clone()
                .oneshot(request(
                    "POST",
                    "/v1/tunnels/relay/packets",
                    Some(&left_http.token),
                    None,
                    batch.clone()
                )?)
                .await?
                .status(),
            StatusCode::NO_CONTENT
        );
        let mut buffer = vec![0_u8; 65535];
        let len = tokio::time::timeout(std::time::Duration::from_secs(2), right.recv(&mut buffer))
            .await??;
        assert_eq!(&buffer[..len], &packet);
        let mut response_packet = vec![0_u8; 92];
        response_packet[0] = 2;
        response_packet[4] = 8;
        response_packet[8] = 7;
        right
            .send_to(
                &encode_relay_datagram_with_route(
                    &admitted.session_id,
                    &admitted.session_token,
                    &NodeId::from_string("right"),
                    &NodeId::from_string("left"),
                    &response_packet,
                )?,
                backend,
            )
            .await?;
        let collect = |token: String| {
            let app = app.clone();
            async move {
                let response = app
                    .oneshot(
                        Request::builder()
                            .uri("/v1/tunnels/relay/packets")
                            .header("authorization", format!("{TOKEN_SCHEME}{token}"))
                            .body(Body::empty())?,
                    )
                    .await?;
                let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024).await?;
                Ok::<_, Box<dyn std::error::Error>>(
                    decode_batch(&bytes)?
                        .into_iter()
                        .map(|p| p.to_vec())
                        .collect::<Vec<_>>(),
                )
            }
        };
        let mut found = false;
        for _ in 0..3 {
            if collect(left_http.token.clone())
                .await?
                .contains(&response_packet)
            {
                found = true;
                break;
            }
        }
        assert!(found);
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/v1/tunnels/relay/open",
                None,
                Some("right"),
                announcement("right", "left")?,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let right_http: OpenResponse =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(
            app.clone()
                .oneshot(request(
                    "POST",
                    "/v1/tunnels/relay/packets",
                    Some(&left_http.token),
                    None,
                    batch
                )?)
                .await?
                .status(),
            StatusCode::NO_CONTENT
        );
        let mut found = false;
        for _ in 0..3 {
            if collect(right_http.token.clone()).await?.contains(&packet) {
                found = true;
                break;
            }
        }
        assert!(found);
        let left_tcp = ipars_http_tunnel::tcp::TcpTunnel::open(
            tcp_endpoint,
            &NodeId::from_string("left"),
            announcement("left", "right")?,
            None,
            &Default::default(),
        )
        .await?;
        let mut batch = Vec::new();
        append_packet(&mut batch, &frame)?;
        left_tcp.send(batch).await?;
        let mut found = false;
        for _ in 0..3 {
            if collect(right_http.token.clone()).await?.contains(&packet) {
                found = true;
                break;
            }
        }
        assert!(found, "native TCP to HTTP relay failed");
        let right_tcp = ipars_http_tunnel::tcp::TcpTunnel::open(
            tcp_endpoint,
            &NodeId::from_string("right"),
            announcement("right", "left")?,
            None,
            &Default::default(),
        )
        .await?;
        let reply = encode_relay_datagram_with_route(
            &admitted.session_id,
            &admitted.session_token,
            &NodeId::from_string("right"),
            &NodeId::from_string("left"),
            &response_packet,
        )?;
        let mut batch = Vec::new();
        append_packet(&mut batch, &reply)?;
        right_tcp.send(batch).await?;
        let mut found = false;
        for _ in 0..3 {
            if left_tcp.receive().await?.contains(&response_packet) {
                found = true;
                break;
            }
        }
        assert!(found, "native TCP to native TCP relay failed");
        let mut forged = announcement("left", "right")?;
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert_eq!(
            app.oneshot(request(
                "POST",
                "/v1/tunnels/relay/open",
                None,
                Some("left"),
                forged
            )?)
            .await?
            .status(),
            StatusCode::UNAUTHORIZED
        );
        tcp_shutdown.send(true)?;
        tcp_serving.await??;
        shutdown.send(true)?;
        serving.await??;
        Ok(())
    }
}
