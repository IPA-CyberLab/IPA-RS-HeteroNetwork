use std::collections::BTreeMap;
use std::fmt::{Debug, Write};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ipars_crypto::{verify_signal_hole_punch_plan_signature, verify_signal_path_signature};
use ipars_signal::{SignalError, SignalRegistry};
use ipars_types::api::{
    AuthenticatedSignalPathRequest, NodeApiRequestSignature, SignalHolePunchPlanRequest,
    SignalHolePunchPlanResponse, SignalMetricsResponse, SignalNodeAuthenticationResponse,
    SignalNodeUpsertRequest, SignalNodeUpsertResponse, SignalPathResponse,
};
use ipars_types::{NodeId, NodeRecord, PathState};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::Mutex;

const MAX_CONTROL_PLANE_AUTH_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CONTROL_PLANE_ERROR_RESPONSE_BYTES: u64 = 64 * 1024;
const CONTROL_PLANE_AUTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SIGNAL_REQUEST_SIGNATURE_MAX_AGE_SECONDS: i64 = 300;
const MAX_ACCEPTED_SIGNAL_REQUEST_NONCES: usize = 131_072;
const MAX_OPERATOR_API_BEARER_TOKEN_BYTES: usize = 512;

macro_rules! prometheus_line {
    ($body:expr, $($arg:tt)*) => {{
        let _ = writeln!($body, $($arg)*);
    }};
}

#[derive(Debug, Error)]
pub enum SignalNodeAuthenticationError {
    #[error("at least one control-plane URL is required for signal node authentication")]
    MissingControlPlane,
    #[error("signal node authentication TTL must be a positive representable duration")]
    InvalidNodeAuthenticationTtl,
    #[error("control-plane node authentication rejected the request: {0}")]
    Rejected(String),
    #[error("all control-plane node authentication endpoints failed: {0}")]
    Unavailable(String),
    #[error("control-plane node authentication returned an invalid response: {0}")]
    InvalidResponse(String),
    #[error("failed to build the control-plane authentication client: {0}")]
    Client(String),
}

#[async_trait]
pub trait SignalNodeAuthenticator: Debug + Send + Sync {
    async fn authenticate(
        &self,
        request: &SignalNodeUpsertRequest,
    ) -> Result<SignalNodeAuthenticationResponse, SignalNodeAuthenticationError>;
}

#[derive(Debug, Clone)]
pub struct ControlPlaneSignalNodeAuthenticator {
    client: reqwest::Client,
    control_plane_urls: Arc<Vec<String>>,
}

impl ControlPlaneSignalNodeAuthenticator {
    pub fn new(control_plane_urls: Vec<String>) -> Result<Self, SignalNodeAuthenticationError> {
        if control_plane_urls.is_empty() {
            return Err(SignalNodeAuthenticationError::MissingControlPlane);
        }
        let client = reqwest::Client::builder()
            .timeout(CONTROL_PLANE_AUTH_REQUEST_TIMEOUT)
            .build()
            .map_err(|error| SignalNodeAuthenticationError::Client(error.to_string()))?;
        Ok(Self {
            client,
            control_plane_urls: Arc::new(control_plane_urls),
        })
    }
}

#[async_trait]
impl SignalNodeAuthenticator for ControlPlaneSignalNodeAuthenticator {
    async fn authenticate(
        &self,
        request: &SignalNodeUpsertRequest,
    ) -> Result<SignalNodeAuthenticationResponse, SignalNodeAuthenticationError> {
        let mut failures = Vec::new();
        for control_plane_url in self.control_plane_urls.iter() {
            let url = format!(
                "{}/v1/nodes/authenticate-signal-upsert",
                control_plane_url.trim_end_matches('/')
            );
            let response = match self.client.post(&url).json(request).send().await {
                Ok(response) => response,
                Err(error) => {
                    failures.push(format!("{url}: {error}"));
                    continue;
                }
            };
            let status = response.status();
            if !status.is_success() {
                let detail = read_bounded_response_body(
                    response,
                    MAX_CONTROL_PLANE_ERROR_RESPONSE_BYTES,
                    "control-plane authentication error",
                )
                .await
                .map(|body| String::from_utf8_lossy(&body).into_owned())
                .unwrap_or_else(|error| error);
                if status.is_client_error() {
                    return Err(SignalNodeAuthenticationError::Rejected(format!(
                        "{status} from {url}: {detail}"
                    )));
                }
                failures.push(format!("{url}: {status}: {detail}"));
                continue;
            }
            let body = read_bounded_response_body(
                response,
                MAX_CONTROL_PLANE_AUTH_RESPONSE_BYTES,
                "control-plane authentication response",
            )
            .await
            .map_err(SignalNodeAuthenticationError::InvalidResponse)?;
            let authenticated: SignalNodeAuthenticationResponse = serde_json::from_slice(&body)
                .map_err(|error| {
                    SignalNodeAuthenticationError::InvalidResponse(error.to_string())
                })?;
            if authenticated.node.node_id != request.node.node_id {
                return Err(SignalNodeAuthenticationError::InvalidResponse(format!(
                    "node ID mismatch: expected {}, got {}",
                    request.node.node_id, authenticated.node.node_id
                )));
            }
            return Ok(authenticated);
        }
        Err(SignalNodeAuthenticationError::Unavailable(
            failures.join("; "),
        ))
    }
}

async fn read_bounded_response_body(
    mut response: reqwest::Response,
    max_bytes: u64,
    context: &str,
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes)
    {
        return Err(format!("{context} exceeds {max_bytes} bytes"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("failed to read {context}: {error}"))?
    {
        let next_len = body.len() as u64 + chunk.len() as u64;
        if next_len > max_bytes {
            return Err(format!("{context} exceeds {max_bytes} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Clone)]
pub struct SignalHttpState {
    registry: Arc<SignalRegistry>,
    authenticator: Arc<dyn SignalNodeAuthenticator>,
    accepted_nonces: AcceptedNonceLedger,
    authenticated_nodes: Arc<Mutex<BTreeMap<NodeId, DateTime<Utc>>>>,
    node_auth_ttl: ChronoDuration,
    operator_api_bearer_token: Option<Arc<str>>,
}

type AcceptedNonceLedger = Arc<Mutex<BTreeMap<(NodeId, String), DateTime<Utc>>>>;

impl SignalHttpState {
    pub fn new(
        registry: Arc<SignalRegistry>,
        control_plane_urls: Vec<String>,
        node_auth_ttl: Duration,
    ) -> Result<Self, SignalNodeAuthenticationError> {
        let authenticator = Arc::new(ControlPlaneSignalNodeAuthenticator::new(
            control_plane_urls,
        )?);
        Self::with_authenticator(registry, authenticator, node_auth_ttl)
    }

    pub fn with_authenticator(
        registry: Arc<SignalRegistry>,
        authenticator: Arc<dyn SignalNodeAuthenticator>,
        node_auth_ttl: Duration,
    ) -> Result<Self, SignalNodeAuthenticationError> {
        if node_auth_ttl.is_zero() {
            return Err(SignalNodeAuthenticationError::InvalidNodeAuthenticationTtl);
        }
        let node_auth_ttl = ChronoDuration::from_std(node_auth_ttl)
            .map_err(|_| SignalNodeAuthenticationError::InvalidNodeAuthenticationTtl)?;
        Ok(Self {
            registry,
            authenticator,
            accepted_nonces: Arc::new(Mutex::new(BTreeMap::new())),
            authenticated_nodes: Arc::new(Mutex::new(BTreeMap::new())),
            node_auth_ttl,
            operator_api_bearer_token: None,
        })
    }

    pub fn require_operator_api_bearer_token(mut self, token: String) -> Self {
        self.operator_api_bearer_token = Some(Arc::from(token));
        self
    }
}

pub fn router(state: SignalHttpState) -> Router {
    let protocol = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/nodes/{node_id}", put(upsert_node))
        .route("/v1/paths/negotiate", post(negotiate))
        .route("/v1/hole-punch", post(hole_punch_plan));
    let app = if let Some(token) = state.operator_api_bearer_token.clone() {
        let operator = Router::new()
            .route("/metrics", get(prometheus_metrics))
            .route("/v1/metrics", get(metrics))
            .route_layer(middleware::from_fn_with_state(
                token,
                require_signal_operator_api_bearer,
            ));
        protocol.merge(operator)
    } else {
        protocol
    };
    app.with_state(state)
}

async fn require_signal_operator_api_bearer(
    State(expected): State<Arc<str>>,
    request: Request,
    next: Next,
) -> Response {
    let provided = bearer_token_from_headers(request.headers());
    if !provided.is_some_and(|provided| operator_api_token_matches(&expected, provided)) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(ErrorResponse {
                error: "signal operator API bearer token was rejected".to_string(),
            }),
        )
            .into_response();
    }
    next.run(request).await
}

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

fn operator_api_token_matches(expected: &str, provided: &str) -> bool {
    if expected.is_empty()
        || provided.is_empty()
        || expected.len() > MAX_OPERATOR_API_BEARER_TOKEN_BYTES
        || provided.len() > MAX_OPERATOR_API_BEARER_TOKEN_BYTES
    {
        return false;
    }
    let expected = expected.as_bytes();
    let provided = provided.as_bytes();
    let mut diff = expected.len() ^ provided.len();
    for index in 0..MAX_OPERATOR_API_BEARER_TOKEN_BYTES {
        let expected_byte = expected.get(index).copied().unwrap_or_default();
        let provided_byte = provided.get(index).copied().unwrap_or_default();
        diff |= usize::from(expected_byte ^ provided_byte);
    }
    diff == 0
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn metrics(State(state): State<SignalHttpState>) -> Json<SignalMetricsResponse> {
    purge_stale_authenticated_nodes(&state, Utc::now()).await;
    Json(state.registry.metrics().await)
}

async fn prometheus_metrics(State(state): State<SignalHttpState>) -> impl IntoResponse {
    purge_stale_authenticated_nodes(&state, Utc::now()).await;
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
    let now = Utc::now();
    purge_stale_authenticated_nodes(&state, now).await;
    let path_node_id = NodeId::from_string(node_id);
    if path_node_id != request.node.node_id {
        return Err(ApiError::bad_request("node_id path/body mismatch"));
    }

    let authenticated = state
        .authenticator
        .authenticate(&request)
        .await
        .map_err(ApiError::Authentication)?;
    let signature = request
        .request_signature
        .as_ref()
        .ok_or(ApiError::Unauthorized(
            "signal node request signature is required",
        ))?;
    record_authenticated_request_nonce(&state, &request.node.node_id, signature, now).await?;

    let response = state
        .registry
        .upsert_node_with_nat_and_health(
            authenticated.node,
            request.nat_classification,
            request.health,
        )
        .await?;
    state
        .authenticated_nodes
        .lock()
        .await
        .insert(response.node.node_id.clone(), now);
    Ok(Json(response))
}

async fn purge_stale_authenticated_nodes(state: &SignalHttpState, now: DateTime<Utc>) {
    let oldest = now - state.node_auth_ttl;
    let stale = {
        let mut authenticated = state.authenticated_nodes.lock().await;
        let stale = authenticated
            .iter()
            .filter(|(_, authenticated_at)| **authenticated_at < oldest)
            .map(|(node_id, _)| node_id.clone())
            .collect::<Vec<_>>();
        for node_id in &stale {
            authenticated.remove(node_id);
        }
        stale
    };
    for node_id in stale {
        state.registry.remove_node(&node_id).await;
    }
}

async fn authenticated_node(
    state: &SignalHttpState,
    node_id: &NodeId,
    now: DateTime<Utc>,
) -> Result<NodeRecord, ApiError> {
    purge_stale_authenticated_nodes(state, now).await;
    if !state.authenticated_nodes.lock().await.contains_key(node_id) {
        return Err(ApiError::Unauthorized(
            "signal node membership authentication is stale or missing",
        ));
    }
    state
        .registry
        .get_node(node_id)
        .await
        .ok_or(ApiError::Unauthorized(
            "signal node membership authentication is stale or missing",
        ))
}

async fn record_authenticated_request_nonce(
    state: &SignalHttpState,
    node_id: &NodeId,
    signature: &NodeApiRequestSignature,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    if signature.nonce.len() != 32
        || !signature
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApiError::Unauthorized(
            "signal node request nonce is invalid",
        ));
    }
    let skew = ChronoDuration::seconds(SIGNAL_REQUEST_SIGNATURE_MAX_AGE_SECONDS);
    if signature.signed_at < now - skew || signature.signed_at > now + skew {
        return Err(ApiError::Unauthorized(
            "signal node request signature is outside the allowed time window",
        ));
    }

    let key = (node_id.clone(), signature.nonce.clone());
    let mut accepted = state.accepted_nonces.lock().await;
    let oldest = now - skew;
    accepted.retain(|_, signed_at| *signed_at >= oldest);
    if accepted.contains_key(&key) {
        return Err(ApiError::Replay(
            "signal node request nonce was already accepted".to_string(),
        ));
    }
    if accepted.len() >= MAX_ACCEPTED_SIGNAL_REQUEST_NONCES {
        return Err(ApiError::AuthenticationCapacity);
    }
    accepted.insert(key, signature.signed_at);
    Ok(())
}

async fn negotiate(
    State(state): State<SignalHttpState>,
    Json(request): Json<AuthenticatedSignalPathRequest>,
) -> Result<Json<SignalPathResponse>, ApiError> {
    let now = Utc::now();
    let source = authenticated_node(&state, &request.request.source, now).await?;
    authenticated_node(&state, &request.request.target, now).await?;
    verify_signal_path_signature(&request, &source.identity_public_key)
        .map_err(|_| ApiError::Unauthorized("signal path request signature was rejected"))?;
    let signature = request
        .request_signature
        .as_ref()
        .ok_or(ApiError::Unauthorized(
            "signal path request signature is required",
        ))?;
    record_authenticated_request_nonce(&state, &source.node_id, signature, now).await?;
    Ok(Json(
        state
            .registry
            .negotiate_with_observation(request.request, request.path_observation)
            .await?,
    ))
}

async fn hole_punch_plan(
    State(state): State<SignalHttpState>,
    Json(request): Json<SignalHolePunchPlanRequest>,
) -> Result<Json<SignalHolePunchPlanResponse>, ApiError> {
    let now = Utc::now();
    let source = authenticated_node(&state, &request.source, now).await?;
    authenticated_node(&state, &request.target, now).await?;
    verify_signal_hole_punch_plan_signature(&request, &source.identity_public_key)
        .map_err(|_| ApiError::Unauthorized("signal hole-punch signature was rejected"))?;
    let signature = request
        .request_signature
        .as_ref()
        .ok_or(ApiError::Unauthorized(
            "signal hole-punch signature is required",
        ))?;
    record_authenticated_request_nonce(&state, &source.node_id, signature, now).await?;
    Ok(Json(
        state
            .registry
            .hole_punch_plan(request.source, request.target)
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
        "# HELP ipars_signal_metrics_generated_timestamp_seconds Unix timestamp of the signal metrics snapshot."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_metrics_generated_timestamp_seconds gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_metrics_generated_timestamp_seconds {}",
        metrics.generated_at.timestamp().max(0)
    );
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
        "# HELP ipars_signal_path_quality_observations_total Signed path quality observations received by disposition."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_path_quality_observations_total counter"
    );
    for (status, value) in [
        ("accepted", metrics.path_quality_observation_accepted_count),
        ("stale", metrics.path_quality_observation_stale_count),
        (
            "path_mismatch",
            metrics.path_quality_observation_path_mismatch_count,
        ),
        ("rejected", metrics.path_quality_observation_rejected_count),
    ] {
        prometheus_line!(
            &mut body,
            "ipars_signal_path_quality_observations_total{{status=\"{status}\"}} {value}"
        );
    }
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
        "# HELP ipars_signal_hole_punch_nat_suppressions_by_strategy_total Total hole-punch suppressing NAT classifications observed during suppressed plans by traversal strategy."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_hole_punch_nat_suppressions_by_strategy_total counter"
    );
    for strategy_count in &metrics.hole_punch_nat_suppressed_strategy_counts {
        prometheus_line!(
            &mut body,
            "ipars_signal_hole_punch_nat_suppressions_by_strategy_total{{strategy=\"{}\"}} {}",
            strategy_count.strategy.as_str(),
            strategy_count.count
        );
    }
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
        "# HELP ipars_signal_path_quality_observation_ttl_seconds Signed path quality observation freshness window used by Signal."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_signal_path_quality_observation_ttl_seconds gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_signal_path_quality_observation_ttl_seconds {}",
        metrics.path_quality_observation_ttl_seconds
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
    Authentication(SignalNodeAuthenticationError),
    Unauthorized(&'static str),
    Replay(String),
    AuthenticationCapacity,
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
            Self::Signal(SignalError::HealthInvalid { node_id, reason }) => (
                StatusCode::BAD_REQUEST,
                format!("health report for node {node_id} is invalid: {reason}"),
            ),
            Self::Signal(SignalError::NatClassificationInvalid { node_id, reason }) => (
                StatusCode::BAD_REQUEST,
                format!("NAT classification for node {node_id} is invalid: {reason}"),
            ),
            Self::Signal(SignalError::DesiredRouteInvalid {
                node_id,
                route,
                reason,
            }) => (
                StatusCode::BAD_REQUEST,
                format!("desired route {route} for target node {node_id} is invalid: {reason}"),
            ),
            Self::Signal(SignalError::RouteInvalid {
                node_id,
                route_id,
                reason,
            }) => (
                StatusCode::BAD_REQUEST,
                format!("route {route_id} for node {node_id} is invalid: {reason}"),
            ),
            Self::Signal(SignalError::PathQualityObservationInvalid {
                source_node,
                target_node,
                reason,
            }) => (
                StatusCode::BAD_REQUEST,
                format!(
                    "path quality observation from {source_node} to {target_node} is invalid: {reason}"
                ),
            ),
            Self::BadRequest(error) => (StatusCode::BAD_REQUEST, error),
            Self::Authentication(SignalNodeAuthenticationError::Rejected(error)) => {
                (StatusCode::UNAUTHORIZED, error)
            }
            Self::Authentication(error @ SignalNodeAuthenticationError::MissingControlPlane)
            | Self::Authentication(
                error @ SignalNodeAuthenticationError::InvalidNodeAuthenticationTtl,
            )
            | Self::Authentication(error @ SignalNodeAuthenticationError::Unavailable(_))
            | Self::Authentication(error @ SignalNodeAuthenticationError::Client(_)) => {
                (StatusCode::SERVICE_UNAVAILABLE, error.to_string())
            }
            Self::Authentication(error @ SignalNodeAuthenticationError::InvalidResponse(_)) => {
                (StatusCode::BAD_GATEWAY, error.to_string())
            }
            Self::Unauthorized(error) => (StatusCode::UNAUTHORIZED, error.to_string()),
            Self::Replay(error) => (StatusCode::CONFLICT, error),
            Self::AuthenticationCapacity => (
                StatusCode::SERVICE_UNAVAILABLE,
                "signal request authentication replay cache is full".to_string(),
            ),
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
    use ipars_crypto::{verify_signal_node_upsert_signature, IdentityKeyPair};
    use ipars_types::api::{
        AuthenticatedSignalPathRequest, SignalHolePunchPlanRequest, SignalMetricsResponse,
        SignalNodeUpsertRequest, SignalPathRequest, SignalPathResponse,
    };
    use ipars_types::{
        CandidateSource, ClusterId, ClusterPolicy, EndpointCandidate, EndpointCandidateKind,
        NatTraversalStrategy, NodeRecord, Role, Route, TokenPolicy, VpnIp,
    };
    use tower::ServiceExt;

    use super::*;

    const OPERATOR_API_BEARER_TOKEN: &str = "signal-test-operator-token-with-32-bytes";

    #[derive(Debug)]
    struct TestSignalNodeAuthenticator;

    #[async_trait]
    impl SignalNodeAuthenticator for TestSignalNodeAuthenticator {
        async fn authenticate(
            &self,
            request: &SignalNodeUpsertRequest,
        ) -> Result<SignalNodeAuthenticationResponse, SignalNodeAuthenticationError> {
            verify_signal_node_upsert_signature(request, &request.node.identity_public_key)
                .map_err(|error| SignalNodeAuthenticationError::Rejected(error.to_string()))?;
            Ok(SignalNodeAuthenticationResponse {
                node: request.node.clone(),
                authenticated_at: Utc::now(),
            })
        }
    }

    fn test_state(registry: Arc<SignalRegistry>) -> SignalHttpState {
        SignalHttpState::with_authenticator(
            registry,
            Arc::new(TestSignalNodeAuthenticator),
            Duration::from_secs(90),
        )
        .unwrap_or_else(|error| panic!("test signal state should be valid: {error}"))
        .require_operator_api_bearer_token(OPERATOR_API_BEARER_TOKEN.to_string())
    }

    #[tokio::test]
    async fn signal_operator_routes_are_disabled_without_a_credential(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = SignalHttpState::with_authenticator(
            Arc::new(SignalRegistry::new(ClusterPolicy::default())),
            Arc::new(TestSignalNodeAuthenticator),
            Duration::from_secs(90),
        )?;
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/metrics")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn signal_operator_routes_require_the_configured_credential(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let app = router(test_state(Arc::new(SignalRegistry::new(
            ClusterPolicy::default(),
        ))));
        for authorization in [None, Some("Bearer wrong-token-with-at-least-32-bytes")] {
            let mut request = Request::builder().method("GET").uri("/v1/metrics");
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
        Ok(())
    }

    fn identity_for_node(node_id: &str) -> IdentityKeyPair {
        let mut seed = [0_u8; 32];
        for (index, byte) in node_id.as_bytes().iter().enumerate() {
            seed[index % seed.len()] = seed[index % seed.len()].wrapping_add(*byte);
        }
        if seed.iter().all(|byte| *byte == 0) {
            seed[0] = 1;
        }
        IdentityKeyPair::from_signing_bytes(seed)
    }

    fn signed_upsert(node: NodeRecord) -> SignalNodeUpsertRequest {
        let identity = identity_for_node(&node.node_id.to_string());
        let mut request = SignalNodeUpsertRequest {
            node,
            nat_classification: None,
            health: None,
            request_signature: None,
        };
        request.request_signature = Some(
            identity
                .sign_signal_node_upsert_request(&request, Utc::now())
                .unwrap_or_else(|error| panic!("test node should sign signal upsert: {error}")),
        );
        request
    }

    fn signed_path(request: SignalPathRequest) -> AuthenticatedSignalPathRequest {
        let identity = identity_for_node(&request.source.to_string());
        let mut authenticated = AuthenticatedSignalPathRequest {
            request,
            path_observation: None,
            request_signature: None,
        };
        authenticated.request_signature = Some(
            identity
                .sign_signal_path_request(&authenticated.request, Utc::now())
                .unwrap_or_else(|error| panic!("test node should sign signal path: {error}")),
        );
        authenticated
    }

    fn signed_hole_punch(source: &str, target: &str) -> SignalHolePunchPlanRequest {
        let identity = identity_for_node(source);
        let mut request = SignalHolePunchPlanRequest {
            source: NodeId::from_string(source),
            target: NodeId::from_string(target),
            request_signature: None,
        };
        request.request_signature = Some(
            identity
                .sign_signal_hole_punch_plan_request(&request, Utc::now())
                .unwrap_or_else(|error| {
                    panic!("test node should sign signal hole-punch request: {error}")
                }),
        );
        request
    }

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
        let identity = identity_for_node(node_id);
        NodeRecord {
            node_id: NodeId::from_string(node_id),
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
            identity_public_key: identity.public_key_b64(),
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

    fn advertised_route(id: &str, cidr: &str, advertised_by: &NodeId) -> Route {
        let cidr = match cidr.parse() {
            Ok(cidr) => cidr,
            Err(error) => panic!("invalid test CIDR `{cidr}`: {error}"),
        };
        Route {
            id: id.to_string(),
            cidr,
            advertised_by: advertised_by.clone(),
            via: None,
            metric: 100,
            tags: BTreeSet::new(),
        }
    }

    #[tokio::test]
    async fn http_signal_registers_node_and_negotiates_path(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = Arc::new(SignalRegistry::new(ClusterPolicy::default()));
        let app = router(test_state(registry));
        let source = node(
            "node-a",
            vec![candidate("node-a", EndpointCandidateKind::StunReflexive)],
        );
        let target = node(
            "node-b",
            vec![candidate("node-b", EndpointCandidateKind::PublicUdp)],
        );

        let unsigned = SignalNodeUpsertRequest {
            node: source.clone(),
            nat_classification: None,
            health: None,
            request_signature: None,
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/nodes/node-a")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&unsigned)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let source_upsert = signed_upsert(source);
        let source_body = serde_json::to_vec(&source_upsert)?;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/nodes/node-a")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(source_body.clone()))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/nodes/node-a")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(source_body))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/nodes/node-b")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&signed_upsert(target))?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let path_request = SignalPathRequest {
            source: NodeId::from_string("node-a"),
            target: NodeId::from_string("node-b"),
            source_candidates: vec![candidate("node-a", EndpointCandidateKind::StunReflexive)],
            source_nat_classification: None,
            desired_routes: Vec::new(),
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/paths/negotiate")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(
                        &AuthenticatedSignalPathRequest {
                            request: path_request.clone(),
                            path_observation: None,
                            request_signature: None,
                        },
                    )?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let signed_path_body = serde_json::to_vec(&signed_path(path_request))?;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/paths/negotiate")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(signed_path_body.clone()))?,
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
                    .method("POST")
                    .uri("/v1/paths/negotiate")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(signed_path_body))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let signed_hole_punch_body = serde_json::to_vec(&signed_hole_punch("node-a", "node-b"))?;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/hole-punch")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(signed_hole_punch_body.clone()))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/hole-punch")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(signed_hole_punch_body))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/metrics")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
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
        assert_eq!(metrics.path_quality_observation_ttl_seconds, 120);
        assert_eq!(metrics.nat_classification_ttl_seconds, 300);
        assert_eq!(metrics.nat_classification_min_confidence_percent, 50);
        assert_eq!(metrics.node_upsert_count, 2);
        assert_eq!(metrics.path_negotiation_count, 1);
        assert_eq!(metrics.path_acl_denied_count, 0);
        assert_eq!(metrics.relay_candidate_acl_denied_count, 0);
        assert_eq!(metrics.path_quality_observation_accepted_count, 0);
        assert_eq!(metrics.path_quality_observation_stale_count, 0);
        assert_eq!(metrics.path_quality_observation_path_mismatch_count, 0);
        assert_eq!(metrics.path_quality_observation_rejected_count, 0);
        assert_eq!(metrics.hole_punch_acl_denied_count, 0);
        assert_eq!(metrics.hole_punch_nat_suppressed_count, 0);
        assert!(metrics
            .hole_punch_nat_suppressed_strategy_counts
            .iter()
            .any(
                |entry| entry.strategy == NatTraversalStrategy::DirectCandidate && entry.count == 0
            ));
        assert_eq!(
            signal_path_state_count(&metrics, ipars_types::PathState::DirectPublic),
            1
        );
        assert_eq!(metrics.path_negotiation_state_counts.len(), 5);
        assert_eq!(
            signal_path_state_count(&metrics, ipars_types::PathState::Relay),
            0
        );

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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("ipars_signal_metrics_generated_timestamp_seconds "));
        assert!(body.contains("ipars_signal_nodes 2"));
        assert!(body.contains("ipars_signal_stale_nat_classifications 0"));
        assert!(body.contains("ipars_signal_fresh_low_confidence_nat_classifications 0"));
        assert!(body.contains("ipars_signal_stale_endpoint_candidates 0"));
        assert!(body.contains("ipars_signal_endpoint_candidate_ttl_seconds 120"));
        assert!(body.contains("ipars_signal_path_quality_observation_ttl_seconds 120"));
        assert!(body.contains("ipars_signal_nat_classification_ttl_seconds 300"));
        assert!(body.contains("ipars_signal_nat_classification_min_confidence_percent 50"));
        assert!(body.contains(
            "ipars_signal_fresh_nat_classifications_by_strategy{strategy=\"direct_candidate\"} 0"
        ));
        assert!(body.contains("ipars_signal_path_negotiations_total 1"));
        assert!(body.contains("ipars_signal_path_acl_denials_total 0"));
        assert!(body.contains("ipars_signal_relay_candidate_acl_denials_total 0"));
        assert!(
            body.contains("ipars_signal_path_quality_observations_total{status=\"accepted\"} 0")
        );
        assert!(body.contains("ipars_signal_hole_punch_acl_denials_total 0"));
        assert!(body.contains("ipars_signal_hole_punch_nat_suppressions_total 0"));
        assert!(body.contains(
            "ipars_signal_hole_punch_nat_suppressions_by_strategy_total{strategy=\"direct_candidate\"} 0"
        ));
        assert!(
            body.contains("ipars_signal_path_negotiation_state_total{state=\"DIRECT_PUBLIC\"} 1")
        );
        assert!(body.contains("ipars_signal_path_negotiation_state_total{state=\"RELAY\"} 0"));
        Ok(())
    }

    #[tokio::test]
    async fn http_signal_evicts_nodes_after_membership_authentication_ttl(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = Arc::new(SignalRegistry::new(ClusterPolicy::default()));
        let state = SignalHttpState::with_authenticator(
            registry.clone(),
            Arc::new(TestSignalNodeAuthenticator),
            Duration::from_millis(1),
        )?
        .require_operator_api_bearer_token(OPERATOR_API_BEARER_TOKEN.to_string());
        let app = router(state);
        let request = signed_upsert(node("node-a", Vec::new()));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/nodes/node-a")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&request)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(registry
            .get_node(&NodeId::from_string("node-a"))
            .await
            .is_some());

        tokio::time::sleep(Duration::from_millis(5)).await;
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/metrics")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let metrics: SignalMetricsResponse = serde_json::from_slice(&body)?;
        assert_eq!(metrics.node_count, 0);
        assert!(registry
            .get_node(&NodeId::from_string("node-a"))
            .await
            .is_none());
        Ok(())
    }

    #[tokio::test]
    async fn http_signal_rejects_unowned_endpoint_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = Arc::new(SignalRegistry::new(ClusterPolicy::default()));
        let app = router(test_state(registry));
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
                    .body(Body::from(serde_json::to_vec(&signed_upsert(node))?))?,
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
        let app = router(test_state(registry));
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
                    .body(Body::from(serde_json::to_vec(&signed_upsert(node))?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("IPv6 candidates must use an IPv6 socket address"));
        Ok(())
    }

    #[tokio::test]
    async fn http_signal_rejects_invalid_route_advertisement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = Arc::new(SignalRegistry::new(ClusterPolicy::default()));
        let app = router(test_state(registry.clone()));
        let mut node = node("node-a", Vec::new());
        node.routes.push(advertised_route(
            "unsafe-route",
            "127.0.0.0/8",
            &node.node_id,
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/nodes/node-a")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&signed_upsert(node))?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("route unsafe-route for node node-a is invalid"));
        assert!(body.contains("route CIDR is restricted"));
        let metrics = registry.metrics().await;
        assert_eq!(metrics.node_count, 0);
        assert_eq!(metrics.node_upsert_count, 0);
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
