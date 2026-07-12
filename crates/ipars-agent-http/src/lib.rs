use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipars_agent::{AgentError, AgentRuntime, FileAgentStateStore};
use ipars_types::api::{
    packet_flow_destination_drop_reason, AgentManagedProcessState, AgentMetricsResponse,
    AgentNatClassifyRequest, AgentNatClassifyResponse, AgentNodeRemovalRequest,
    AgentNodeRemovalResponse, AgentPacketFlowApplication, AgentPacketFlowClassification,
    AgentPacketFlowDropReason, AgentPacketFlowDuplicateSource, AgentPacketFlowRequest,
    AgentPacketFlowResponse, AgentPathEventsResponse, AgentPathProbeRequest,
    AgentPathProbeResponse, AgentPathsResponse, AgentPeerActivityRequest,
    AgentPeerActivityResponse, AgentStatusResponse, AgentStunProbeRequest, AgentStunProbeResponse,
    AgentWireGuardKeyRotationRequest, AgentWireGuardKeyRotationResponse, PeerMap,
    RemoveNodeRequest, RemoveNodeResponse, RotateWireGuardKeyRequest, RotateWireGuardKeyResponse,
};
use ipars_types::{NodeId, PathState};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

const MAX_CONTROL_PLANE_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_AGENT_API_BEARER_TOKEN_BYTES: usize = 512;
const DEFAULT_CONTROL_PLANE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

macro_rules! prometheus_line {
    ($body:expr, $($arg:tt)*) => {{
        let _ = writeln!($body, $($arg)*);
    }};
}

#[derive(Debug, Clone)]
pub struct AgentHttpState {
    runtime: Arc<AgentRuntime>,
    state_store: Option<FileAgentStateStore>,
    control_plane_urls: Vec<String>,
    control_plane_client: reqwest::Client,
    control_plane_request_timeout: Duration,
    api_bearer_token: Option<Arc<str>>,
}

impl AgentHttpState {
    pub fn new(runtime: Arc<AgentRuntime>) -> Self {
        Self {
            runtime,
            state_store: None,
            control_plane_urls: Vec::new(),
            control_plane_client: reqwest::Client::new(),
            control_plane_request_timeout: DEFAULT_CONTROL_PLANE_REQUEST_TIMEOUT,
            api_bearer_token: None,
        }
    }

    pub fn with_control_plane_urls(
        runtime: Arc<AgentRuntime>,
        control_plane_urls: Vec<String>,
    ) -> Self {
        Self {
            runtime,
            state_store: None,
            control_plane_urls,
            control_plane_client: reqwest::Client::new(),
            control_plane_request_timeout: DEFAULT_CONTROL_PLANE_REQUEST_TIMEOUT,
            api_bearer_token: None,
        }
    }

    pub fn with_wireguard_key_rotation(
        runtime: Arc<AgentRuntime>,
        state_store: FileAgentStateStore,
        control_plane_urls: Vec<String>,
    ) -> Self {
        Self {
            runtime,
            state_store: Some(state_store),
            control_plane_urls,
            control_plane_client: reqwest::Client::new(),
            control_plane_request_timeout: DEFAULT_CONTROL_PLANE_REQUEST_TIMEOUT,
            api_bearer_token: None,
        }
    }

    pub fn with_control_plane_http_client(
        mut self,
        client: reqwest::Client,
        request_timeout: Duration,
    ) -> Self {
        self.control_plane_client = client;
        self.control_plane_request_timeout = request_timeout;
        self
    }

    pub fn require_api_bearer_token(mut self, token: String) -> Self {
        self.api_bearer_token = Some(Arc::from(token));
        self
    }
}

pub fn router(state: AgentHttpState) -> Router {
    let mut protected = Router::new()
        .route("/metrics", get(prometheus_metrics))
        .route("/v1/status", get(status))
        .route("/v1/metrics", get(metrics))
        .route("/v1/peers", get(peers))
        .route("/v1/paths", get(paths))
        .route("/v1/path-events", get(path_events))
        .route("/v1/path-probe", post(path_probe))
        .route("/v1/stun-probe", post(stun_probe))
        .route("/v1/nat-classification", post(nat_classification))
        .route("/v1/peer-activity", post(peer_activity))
        .route("/v1/packet-flow", post(packet_flow))
        .route("/v1/wireguard-key/rotate", post(rotate_wireguard_key))
        .route("/v1/node/remove", post(remove_node));
    if let Some(token) = state.api_bearer_token.clone() {
        protected = protected.route_layer(middleware::from_fn_with_state(
            token,
            require_agent_api_bearer,
        ));
    }
    Router::new()
        .route("/healthz", get(healthz))
        .merge(protected)
        .with_state(state)
}

async fn require_agent_api_bearer(
    State(expected): State<Arc<str>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let provided = bearer_token_from_headers(request.headers())
        .ok_or_else(|| ApiError::unauthorized("agent API bearer token is required"))?;
    if !agent_api_token_matches(&expected, provided) {
        return Err(ApiError::unauthorized(
            "agent API bearer token was rejected",
        ));
    }
    Ok(next.run(request).await)
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

fn agent_api_token_matches(expected: &str, provided: &str) -> bool {
    if expected.is_empty()
        || provided.is_empty()
        || expected.len() > MAX_AGENT_API_BEARER_TOKEN_BYTES
        || provided.len() > MAX_AGENT_API_BEARER_TOKEN_BYTES
    {
        return false;
    }

    let expected = expected.as_bytes();
    let provided = provided.as_bytes();
    let mut diff = expected.len() ^ provided.len();
    for index in 0..MAX_AGENT_API_BEARER_TOKEN_BYTES {
        let expected_byte = expected.get(index).copied().unwrap_or_default();
        let provided_byte = provided.get(index).copied().unwrap_or_default();
        diff |= usize::from(expected_byte ^ provided_byte);
    }
    diff == 0
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn status(State(state): State<AgentHttpState>) -> Json<AgentStatusResponse> {
    Json(state.runtime.status().await)
}

async fn rotate_wireguard_key(
    State(state): State<AgentHttpState>,
    Json(request): Json<AgentWireGuardKeyRotationRequest>,
) -> Result<Json<AgentWireGuardKeyRotationResponse>, ApiError> {
    let state_store = state.state_store.clone().ok_or_else(|| {
        AgentError::ControlPlaneClient(
            "agent state store is required for WireGuard key rotation".to_string(),
        )
    })?;
    let control_plane_urls = request
        .control_plane_url
        .map(|url| vec![url])
        .unwrap_or_else(|| state.control_plane_urls.clone());
    if control_plane_urls.is_empty() {
        return Err(AgentError::ControlPlaneClient(
            "control-plane URL is required for WireGuard key rotation".to_string(),
        )
        .into());
    }

    let rotated_at = chrono::Utc::now();
    let plan = state.runtime.plan_wireguard_key_rotation(rotated_at)?;
    let control_plane_response = send_wireguard_key_rotation_to_control_planes(
        &state.control_plane_client,
        state.control_plane_request_timeout,
        &control_plane_urls,
        plan.request.clone(),
    )
    .await?;
    let mut next_state = plan.next_state;
    next_state.updated_at = control_plane_response.rotated_at;
    state_store.save(&next_state)?;
    state.runtime.replace_state(next_state.clone());

    Ok(Json(AgentWireGuardKeyRotationResponse {
        node_id: next_state.node_id,
        previous_wireguard_public_key: plan.previous_wireguard_public_key,
        next_wireguard_public_key: plan.next_wireguard_public_key,
        control_plane_node: control_plane_response.node,
        rotated_at: control_plane_response.rotated_at,
        state_updated_at: next_state.updated_at,
    }))
}

async fn remove_node(
    State(state): State<AgentHttpState>,
    Json(request): Json<AgentNodeRemovalRequest>,
) -> Result<Json<AgentNodeRemovalResponse>, ApiError> {
    let control_plane_urls = request
        .control_plane_url
        .map(|url| vec![url])
        .unwrap_or_else(|| state.control_plane_urls.clone());
    if control_plane_urls.is_empty() {
        return Err(AgentError::ControlPlaneClient(
            "control-plane URL is required for node removal".to_string(),
        )
        .into());
    }

    let remove_request = state.runtime.remove_node_request(chrono::Utc::now())?;
    let control_plane_response = send_node_removal_to_control_planes(
        &state.control_plane_client,
        state.control_plane_request_timeout,
        &control_plane_urls,
        remove_request,
    )
    .await?;

    Ok(Json(AgentNodeRemovalResponse {
        node_id: control_plane_response.node.node_id.clone(),
        control_plane_node: control_plane_response.node,
        removed_path_count: control_plane_response.removed_path_count,
        removed_health: control_plane_response.removed_health,
        removed_at: control_plane_response.removed_at,
    }))
}

async fn send_wireguard_key_rotation_to_control_planes(
    client: &reqwest::Client,
    request_timeout: Duration,
    control_plane_urls: &[String],
    request: RotateWireGuardKeyRequest,
) -> Result<RotateWireGuardKeyResponse, AgentError> {
    let mut failures = Vec::new();
    for control_plane_url in control_plane_urls {
        let url = wireguard_key_rotation_url(control_plane_url, &request.node_id);
        match client
            .put(&url)
            .timeout(request_timeout)
            .json(&request)
            .send()
            .await
        {
            Ok(response) => match response.error_for_status() {
                Ok(response) => match read_bounded_json_response(
                    response,
                    MAX_CONTROL_PLANE_RESPONSE_BYTES,
                    "control-plane WireGuard key rotation",
                )
                .await
                {
                    Ok(response) => return Ok(response),
                    Err(error) => failures.push(format!("{url}: decode failed: {error}")),
                },
                Err(error) => failures.push(format!("{url}: rejected: {error}")),
            },
            Err(error) => failures.push(format!("{url}: send failed: {error}")),
        }
    }
    Err(AgentError::ControlPlaneClient(format!(
        "all control-plane WireGuard key rotation endpoints failed: {}",
        failures.join("; ")
    )))
}

async fn send_node_removal_to_control_planes(
    client: &reqwest::Client,
    request_timeout: Duration,
    control_plane_urls: &[String],
    request: RemoveNodeRequest,
) -> Result<RemoveNodeResponse, AgentError> {
    let mut failures = Vec::new();
    for control_plane_url in control_plane_urls {
        let url = node_removal_url(control_plane_url, &request.node_id);
        match client
            .delete(&url)
            .timeout(request_timeout)
            .json(&request)
            .send()
            .await
        {
            Ok(response) => match response.error_for_status() {
                Ok(response) => match read_bounded_json_response(
                    response,
                    MAX_CONTROL_PLANE_RESPONSE_BYTES,
                    "control-plane node removal",
                )
                .await
                {
                    Ok(response) => return Ok(response),
                    Err(error) => failures.push(format!("{url}: decode failed: {error}")),
                },
                Err(error) => failures.push(format!("{url}: rejected: {error}")),
            },
            Err(error) => failures.push(format!("{url}: send failed: {error}")),
        }
    }
    Err(AgentError::ControlPlaneClient(format!(
        "all control-plane node removal endpoints failed: {}",
        failures.join("; ")
    )))
}

async fn read_bounded_json_response<T>(
    mut response: reqwest::Response,
    max_bytes: u64,
    context: &str,
) -> Result<T, AgentError>
where
    T: DeserializeOwned,
{
    if let Some(length) = response.content_length() {
        ensure_http_response_size(length, max_bytes, context)?;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        AgentError::ControlPlaneClient(format!("failed to read {context} response: {error}"))
    })? {
        let next_len = body.len() as u64 + chunk.len() as u64;
        ensure_http_response_size(next_len, max_bytes, context)?;
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|error| {
        AgentError::ControlPlaneClient(format!("failed to decode {context} response: {error}"))
    })
}

fn ensure_http_response_size(size: u64, max_bytes: u64, context: &str) -> Result<(), AgentError> {
    if size > max_bytes {
        return Err(AgentError::ControlPlaneClient(format!(
            "{context} response exceeds maximum size of {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn wireguard_key_rotation_url(control_plane_url: &str, node_id: &NodeId) -> String {
    format!(
        "{}/v1/nodes/{}/wireguard-key",
        control_plane_url.trim_end_matches('/'),
        node_id
    )
}

fn node_removal_url(control_plane_url: &str, node_id: &NodeId) -> String {
    format!(
        "{}/v1/nodes/{}",
        control_plane_url.trim_end_matches('/'),
        node_id
    )
}

async fn metrics(State(state): State<AgentHttpState>) -> Json<AgentMetricsResponse> {
    Json(state.runtime.metrics().await)
}

async fn prometheus_metrics(State(state): State<AgentHttpState>) -> impl IntoResponse {
    let metrics = state.runtime.metrics().await;
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render_prometheus_metrics(&metrics),
    )
}

async fn path_events(State(state): State<AgentHttpState>) -> Json<AgentPathEventsResponse> {
    let (events, total_count, dropped_count) = state.runtime.path_change_events_with_counts().await;
    Json(AgentPathEventsResponse {
        events,
        total_count,
        dropped_count,
        generated_at: chrono::Utc::now(),
    })
}

async fn peers(State(state): State<AgentHttpState>) -> Result<Json<PeerMap>, ApiError> {
    Ok(Json(state.runtime.peer_map_snapshot().await?))
}

async fn paths(State(state): State<AgentHttpState>) -> Json<AgentPathsResponse> {
    Json(AgentPathsResponse {
        paths: state.runtime.path_state().await,
        generated_at: chrono::Utc::now(),
    })
}

async fn path_probe(
    State(state): State<AgentHttpState>,
    Json(request): Json<AgentPathProbeRequest>,
) -> Result<(StatusCode, Json<AgentPathProbeResponse>), ApiError> {
    let recorded_at = chrono::Utc::now();
    let path = state
        .runtime
        .record_path_probe(request, recorded_at)
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(AgentPathProbeResponse { path, recorded_at }),
    ))
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

async fn peer_activity(
    State(state): State<AgentHttpState>,
    Json(request): Json<AgentPeerActivityRequest>,
) -> Result<(StatusCode, Json<AgentPeerActivityResponse>), ApiError> {
    let recorded_at = chrono::Utc::now();
    let pinned = state
        .runtime
        .record_peer_activity(request.peer.clone(), recorded_at, request.pin)
        .await;
    Ok((
        StatusCode::ACCEPTED,
        Json(AgentPeerActivityResponse {
            peer: request.peer,
            recorded_at,
            pinned,
        }),
    ))
}

async fn packet_flow(
    State(state): State<AgentHttpState>,
    Json(request): Json<AgentPacketFlowRequest>,
) -> Result<(StatusCode, Json<AgentPacketFlowResponse>), ApiError> {
    let recorded_at = chrono::Utc::now();
    let observation = request.observation;
    observation
        .validate_transport_metadata()
        .map_err(ApiError::BadRequest)?;
    let destination_drop_reason = packet_flow_destination_drop_reason(request.destination);
    let matched = state
        .runtime
        .record_packet_flow_observation(
            request.destination,
            observation.clone(),
            recorded_at,
            request.pin,
        )
        .await;
    let filtered_reason = destination_drop_reason.or_else(|| {
        matched
            .is_none()
            .then_some(AgentPacketFlowDropReason::NoOverlayMatch)
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(AgentPacketFlowResponse {
            destination: request.destination,
            recorded_at,
            observation,
            filtered_reason,
            matched,
        }),
    ))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

fn render_prometheus_metrics(metrics: &AgentMetricsResponse) -> String {
    let node_id = prometheus_label(metrics.node_id.as_str());
    let mut body = String::new();
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_metrics_generated_timestamp_seconds Unix timestamp of the agent metrics snapshot."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_metrics_generated_timestamp_seconds gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_metrics_generated_timestamp_seconds{{node_id=\"{node_id}\"}} {}",
        metrics.generated_at.timestamp().max(0)
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_candidates Number of endpoint candidates currently known."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_candidates gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_candidates{{node_id=\"{node_id}\"}} {}",
        metrics.candidate_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_peer_map_synced Whether the agent has successfully applied at least one peer map."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_peer_map_synced gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_peer_map_synced{{node_id=\"{node_id}\"}} {}",
        u8::from(metrics.peer_map_synced)
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_peer_map_peers Number of peers in the last successfully applied peer map."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_peer_map_peers gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_peer_map_peers{{node_id=\"{node_id}\"}} {}",
        metrics.peer_map_peer_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_peer_map_routes Number of advertised routes in the last successfully applied peer map."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_peer_map_routes gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_peer_map_routes{{node_id=\"{node_id}\"}} {}",
        metrics.peer_map_route_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_peer_map_generated_timestamp_seconds Unix timestamp of the control-plane peer map currently held by the agent, or 0 before the first successful sync."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_peer_map_generated_timestamp_seconds gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_peer_map_generated_timestamp_seconds{{node_id=\"{node_id}\"}} {}",
        metrics
            .peer_map_generated_at
            .map(|generated_at| generated_at.timestamp())
            .unwrap_or_default()
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_paths Number of peer paths currently tracked."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_paths gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_paths{{node_id=\"{node_id}\"}} {}",
        metrics.path_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_sessions Number of active relay sessions held by the agent."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_relay_sessions gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_relay_sessions{{node_id=\"{node_id}\"}} {}",
        metrics.relay_session_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_admission_attempts_total Relay admission candidate attempts made by the agent."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_admission_attempts_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_relay_admission_attempts_total{{node_id=\"{node_id}\"}} {}",
        metrics.relay_admission_attempt_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_admission_success_total Relay admission candidate attempts accepted by relays."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_admission_success_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_relay_admission_success_total{{node_id=\"{node_id}\"}} {}",
        metrics.relay_admission_success_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_admission_failures_total Relay admission candidate attempts rejected or unreachable."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_admission_failures_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_relay_admission_failures_total{{node_id=\"{node_id}\"}} {}",
        metrics.relay_admission_failure_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_admission_failures_by_reason_total Relay admission candidate failures by agent-observed reason."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_admission_failures_by_reason_total counter"
    );
    for reason_count in &metrics.relay_admission_failure_reason_counts {
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_admission_failures_by_reason_total{{node_id=\"{node_id}\",reason=\"{}\"}} {}",
            reason_count.reason.as_str(),
            reason_count.count
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarders Number of supervised relay forwarder endpoints."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_relay_forwarders gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_relay_forwarders{{node_id=\"{node_id}\"}} {}",
        metrics.relay_forwarder_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_userspace_wireguard_process_state Managed userspace WireGuard process state, exported as one-hot gauges."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_userspace_wireguard_process_state gauge"
    );
    let userspace_wireguard_state = metrics
        .userspace_wireguard_process
        .as_ref()
        .map(|status| status.state)
        .unwrap_or(AgentManagedProcessState::Disabled);
    for state in AgentManagedProcessState::ALL {
        let value = u8::from(state == userspace_wireguard_state);
        prometheus_line!(
            &mut body,
            "ipars_agent_userspace_wireguard_process_state{{node_id=\"{node_id}\",state=\"{}\"}} {}",
            state.as_str(),
            value
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_socket_receive_errors_total Relay forwarder recoverable UDP receive errors that did not stop the forwarder."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_socket_receive_errors_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_packets_total Relay forwarder packets sent from local WireGuard to relay."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_packets_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_payload_bytes_total Relay forwarder opaque payload bytes sent from local WireGuard to relay."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_payload_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_datagram_bytes_total Relay forwarder framed datagram bytes sent to relay."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_datagram_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_dropped_unexpected_source_packets_total Relay forwarder packets dropped before relay because the sender did not match the configured local WireGuard endpoint."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_dropped_unexpected_source_packets_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_dropped_unexpected_source_payload_bytes_total Relay forwarder payload bytes dropped before relay because the sender did not match the configured local WireGuard endpoint."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_dropped_unexpected_source_payload_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_dropped_expired_session_packets_total Relay forwarder local packets dropped before relay because the relay session credential expired."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_dropped_expired_session_packets_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_dropped_expired_session_payload_bytes_total Relay forwarder local payload bytes dropped before relay because the relay session credential expired."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_dropped_expired_session_payload_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_dropped_oversized_packets_total Relay forwarder local packets dropped before relay because the framed relay datagram would exceed the UDP payload limit."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_dropped_oversized_packets_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_dropped_oversized_payload_bytes_total Relay forwarder local payload bytes dropped before relay because the framed relay datagram would exceed the UDP payload limit."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_dropped_oversized_payload_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_dropped_oversized_datagram_bytes_total Relay forwarder framed datagram bytes dropped before relay because they would exceed the UDP payload limit."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_dropped_oversized_datagram_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_dropped_socket_error_packets_total Relay forwarder local packets dropped because sending the framed relay datagram failed."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_dropped_socket_error_packets_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_dropped_socket_error_payload_bytes_total Relay forwarder local payload bytes dropped because sending the framed relay datagram failed."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_dropped_socket_error_payload_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_dropped_socket_error_datagram_bytes_total Relay forwarder framed datagram bytes dropped because sending them to the relay failed."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_dropped_socket_error_datagram_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_dropped_non_wireguard_packets_total Relay forwarder local packets dropped before relay because they were not WireGuard datagrams."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_dropped_non_wireguard_packets_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_dropped_non_wireguard_payload_bytes_total Relay forwarder local payload bytes dropped before relay because they were not WireGuard datagrams."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_dropped_non_wireguard_payload_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_inbound_packets_total Relay forwarder packets received from relay and sent to local WireGuard."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_inbound_packets_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_inbound_payload_bytes_total Relay forwarder opaque payload bytes received from relay."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_inbound_payload_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_inbound_dropped_expired_session_packets_total Relay forwarder relay packets dropped before local WireGuard because the relay session credential expired."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_inbound_dropped_expired_session_packets_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_inbound_dropped_expired_session_payload_bytes_total Relay forwarder relay payload bytes dropped before local WireGuard because the relay session credential expired."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_inbound_dropped_expired_session_payload_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_inbound_dropped_oversized_packets_total Relay forwarder relay packets dropped before local WireGuard because the payload exceeds the UDP payload limit."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_inbound_dropped_oversized_packets_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_inbound_dropped_oversized_payload_bytes_total Relay forwarder relay payload bytes dropped before local WireGuard because the payload exceeds the UDP payload limit."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_inbound_dropped_oversized_payload_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_inbound_dropped_socket_error_packets_total Relay forwarder relay packets dropped because sending the payload to local WireGuard failed."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_inbound_dropped_socket_error_packets_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_inbound_dropped_socket_error_payload_bytes_total Relay forwarder relay payload bytes dropped because sending the payload to local WireGuard failed."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_inbound_dropped_socket_error_payload_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_inbound_dropped_non_wireguard_packets_total Relay forwarder relay packets dropped before local WireGuard because they were not WireGuard datagrams."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_inbound_dropped_non_wireguard_packets_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_inbound_dropped_non_wireguard_payload_bytes_total Relay forwarder relay payload bytes dropped before local WireGuard because they were not WireGuard datagrams."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_inbound_dropped_non_wireguard_payload_bytes_total counter"
    );
    for forwarder in &metrics.relay_forwarders {
        let peer = prometheus_label(forwarder.peer.as_str());
        let relay_node = prometheus_label(forwarder.relay_node.as_str());
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_socket_receive_errors_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.socket_receive_errors
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_packets_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_packets
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_payload_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_payload_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_datagram_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_datagram_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_dropped_unexpected_source_packets_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_dropped_unexpected_source_packets
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_dropped_unexpected_source_payload_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_dropped_unexpected_source_payload_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_dropped_expired_session_packets_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_dropped_expired_session_packets
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_dropped_expired_session_payload_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_dropped_expired_session_payload_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_dropped_oversized_packets_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_dropped_oversized_packets
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_dropped_oversized_payload_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_dropped_oversized_payload_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_dropped_oversized_datagram_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_dropped_oversized_datagram_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_dropped_socket_error_packets_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_dropped_socket_error_packets
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_dropped_socket_error_payload_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_dropped_socket_error_payload_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_dropped_socket_error_datagram_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_dropped_socket_error_datagram_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_dropped_non_wireguard_packets_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_dropped_non_wireguard_packets
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_dropped_non_wireguard_payload_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_dropped_non_wireguard_payload_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_inbound_packets_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.inbound_packets
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_inbound_payload_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.inbound_payload_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_inbound_dropped_expired_session_packets_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.inbound_dropped_expired_session_packets
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_inbound_dropped_expired_session_payload_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.inbound_dropped_expired_session_payload_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_inbound_dropped_oversized_packets_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.inbound_dropped_oversized_packets
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_inbound_dropped_oversized_payload_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.inbound_dropped_oversized_payload_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_inbound_dropped_socket_error_packets_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.inbound_dropped_socket_error_packets
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_inbound_dropped_socket_error_payload_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.inbound_dropped_socket_error_payload_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_inbound_dropped_non_wireguard_packets_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.inbound_dropped_non_wireguard_packets
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_inbound_dropped_non_wireguard_payload_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.inbound_dropped_non_wireguard_payload_bytes
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_path_change_events Number of retained path change events."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_path_change_events gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_path_change_events{{node_id=\"{node_id}\"}} {}",
        metrics.path_change_event_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_path_change_events_total Total path change events recorded by the agent."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_path_change_events_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_path_change_events_total{{node_id=\"{node_id}\"}} {}",
        metrics.path_change_event_total_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_path_change_events_dropped_total Total path change events dropped from the bounded retention buffer."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_path_change_events_dropped_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_path_change_events_dropped_total{{node_id=\"{node_id}\"}} {}",
        metrics.path_change_event_dropped_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_active_peers Number of peers with recent lazy-connect activity."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_active_peers gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_active_peers{{node_id=\"{node_id}\"}} {}",
        metrics.lazy_connect.active_peer_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_pinned_peers Number of peers pinned in lazy-connect state."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_pinned_peers gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_pinned_peers{{node_id=\"{node_id}\"}} {}",
        metrics.lazy_connect.pinned_peer_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_observed_peer_vpn_ips Number of peer VPN IPs indexed for packet-flow resolution."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_observed_peer_vpn_ips gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_observed_peer_vpn_ips{{node_id=\"{node_id}\"}} {}",
        metrics.lazy_connect.observed_peer_vpn_ip_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_observed_route_peers Number of peers with advertised routes indexed for packet-flow resolution."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_observed_route_peers gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_observed_route_peers{{node_id=\"{node_id}\"}} {}",
        metrics.lazy_connect.observed_route_peer_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_observed_routes Number of advertised routes indexed for packet-flow resolution."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_observed_routes gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_observed_routes{{node_id=\"{node_id}\"}} {}",
        metrics.lazy_connect.observed_route_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_peer_activity_records_total Peer activity records accepted by the agent."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_peer_activity_records_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_peer_activity_records_total{{node_id=\"{node_id}\"}} {}",
        metrics.peer_activity_record_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_path_probe_records_total Path probe records accepted by the agent."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_path_probe_records_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_path_probe_records_total{{node_id=\"{node_id}\"}} {}",
        metrics.path_probe_record_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_direct_path_probes_started_total Direct WireGuard path verification probes started by the agent."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_direct_path_probes_started_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_direct_path_probes_started_total{{node_id=\"{node_id}\"}} {}",
        metrics.direct_path_probe_started_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_direct_path_probes_confirmed_total Direct WireGuard path verification probes confirmed by handshake or transfer evidence."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_direct_path_probes_confirmed_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_direct_path_probes_confirmed_total{{node_id=\"{node_id}\"}} {}",
        metrics.direct_path_probe_confirmed_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_direct_path_probes_timeout_total Direct WireGuard path verification probes that expired without evidence."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_direct_path_probes_timeout_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_direct_path_probes_timeout_total{{node_id=\"{node_id}\"}} {}",
        metrics.direct_path_probe_timeout_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_packet_flow_observations_total Packet-flow observations submitted to lazy-connect resolution."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_packet_flow_observations_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_packet_flow_observations_total{{node_id=\"{node_id}\"}} {}",
        metrics.packet_flow_observation_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_packet_flow_matches_total Packet-flow observations that resolved to a peer."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_packet_flow_matches_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_packet_flow_matches_total{{node_id=\"{node_id}\"}} {}",
        metrics.packet_flow_match_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_packet_flow_unmatched_total Packet-flow observations that did not resolve to a peer."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_packet_flow_unmatched_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_packet_flow_unmatched_total{{node_id=\"{node_id}\"}} {}",
        metrics.packet_flow_unmatched_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_packet_flow_filtered_total Packet-flow observations filtered before or after lazy-connect resolution."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_packet_flow_filtered_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_packet_flow_filtered_total{{node_id=\"{node_id}\"}} {}",
        metrics.packet_flow_filtered_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_packet_flow_duplicate_suppressions_total Duplicate packet-flow observations suppressed before lazy-connect resolution."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_packet_flow_duplicate_suppressions_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_packet_flow_duplicate_suppressions_total{{node_id=\"{node_id}\"}} {}",
        metrics.packet_flow_duplicate_suppression_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_packet_flow_duplicate_suppressions_by_source_total Duplicate packet-flow observations suppressed before lazy-connect resolution, by detector source."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_packet_flow_duplicate_suppressions_by_source_total counter"
    );
    for source in AgentPacketFlowDuplicateSource::ALL {
        prometheus_line!(
            &mut body,
            "ipars_agent_packet_flow_duplicate_suppressions_by_source_total{{node_id=\"{node_id}\",source=\"{}\"}} {}",
            source.as_str(),
            packet_flow_duplicate_source_count(metrics, source)
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_packet_flow_filtered_by_reason_total Packet-flow observations filtered before or after lazy-connect resolution, by reason."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_packet_flow_filtered_by_reason_total counter"
    );
    for reason in AgentPacketFlowDropReason::ALL {
        prometheus_line!(
            &mut body,
            "ipars_agent_packet_flow_filtered_by_reason_total{{node_id=\"{node_id}\",reason=\"{}\"}} {}",
            reason.as_str(),
            packet_flow_drop_reason_count(metrics, reason)
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_packet_flow_classified_by_lifecycle_total Packet-flow observations classified by inferred conntrack lifecycle."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_packet_flow_classified_by_lifecycle_total counter"
    );
    for classification in AgentPacketFlowClassification::ALL {
        prometheus_line!(
            &mut body,
            "ipars_agent_packet_flow_classified_by_lifecycle_total{{node_id=\"{node_id}\",classification=\"{}\"}} {}",
            classification.as_str(),
            packet_flow_classification_count(metrics, classification)
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_packet_flow_classified_by_application_total Packet-flow observations classified by inferred application protocol."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_packet_flow_classified_by_application_total counter"
    );
    for application in AgentPacketFlowApplication::ALL {
        prometheus_line!(
            &mut body,
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{node_id}\",application=\"{}\"}} {}",
            application.as_str(),
            packet_flow_application_count(metrics, application)
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_path_state_count Number of peer paths by selected state."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_path_state_count gauge");
    for state in [
        PathState::DirectPublic,
        PathState::DirectIpv6,
        PathState::DirectNatTraversal,
        PathState::Relay,
        PathState::Unreachable,
    ] {
        prometheus_line!(
            &mut body,
            "ipars_agent_path_state_count{{node_id=\"{node_id}\",state=\"{}\"}} {}",
            path_state_label(state),
            path_state_count(metrics, state)
        );
    }
    body
}

fn packet_flow_duplicate_source_count(
    metrics: &AgentMetricsResponse,
    source: AgentPacketFlowDuplicateSource,
) -> u64 {
    metrics
        .packet_flow_duplicate_suppression_counts
        .iter()
        .find(|entry| entry.source == source)
        .map(|entry| entry.count)
        .unwrap_or(0)
}

fn packet_flow_drop_reason_count(
    metrics: &AgentMetricsResponse,
    reason: AgentPacketFlowDropReason,
) -> u64 {
    metrics
        .packet_flow_filtered_reason_counts
        .iter()
        .find(|entry| entry.reason == reason)
        .map(|entry| entry.count)
        .unwrap_or(0)
}

fn packet_flow_classification_count(
    metrics: &AgentMetricsResponse,
    classification: AgentPacketFlowClassification,
) -> u64 {
    metrics
        .packet_flow_classification_counts
        .iter()
        .find(|entry| entry.classification == classification)
        .map(|entry| entry.count)
        .unwrap_or(0)
}

fn packet_flow_application_count(
    metrics: &AgentMetricsResponse,
    application: AgentPacketFlowApplication,
) -> u64 {
    metrics
        .packet_flow_application_counts
        .iter()
        .find(|entry| entry.application == application)
        .map(|entry| entry.count)
        .unwrap_or(0)
}

fn path_state_count(metrics: &AgentMetricsResponse, state: PathState) -> usize {
    metrics
        .path_state_counts
        .iter()
        .find(|entry| entry.state == state)
        .map(|entry| entry.count)
        .unwrap_or(0)
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

fn prometheus_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[derive(Debug)]
pub enum ApiError {
    Agent(AgentError),
    BadRequest(String),
    Unauthorized(&'static str),
}

impl ApiError {
    fn unauthorized(message: &'static str) -> Self {
        Self::Unauthorized(message)
    }
}

impl From<AgentError> for ApiError {
    fn from(error: AgentError) -> Self {
        Self::Agent(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let error = match self {
            ApiError::BadRequest(error) => {
                return (StatusCode::BAD_REQUEST, Json(ErrorResponse { error })).into_response();
            }
            ApiError::Unauthorized(error) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Bearer")],
                    Json(ErrorResponse {
                        error: error.to_string(),
                    }),
                )
                    .into_response();
            }
            ApiError::Agent(error) => error,
        };
        let status = match error {
            AgentError::Io(_)
            | AgentError::Json(_)
            | AgentError::Crypto(_)
            | AgentError::Stun(_)
            | AgentError::RouteManager(_)
            | AgentError::RoutePlanning(_)
            | AgentError::ControlPlaneClient(_)
            | AgentError::HolePunch(_)
            | AgentError::RelaySession(_)
            | AgentError::InsecureStatePath(_)
            | AgentError::WireGuard(_) => StatusCode::SERVICE_UNAVAILABLE,
            AgentError::PathProbeRejected(_) | AgentError::PathStateRejected(_) => {
                StatusCode::BAD_REQUEST
            }
            AgentError::MissingPeer(_) | AgentError::PeerMapUnavailable(_) => StatusCode::NOT_FOUND,
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

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{header, Request};
    use chrono::Utc;
    use ipars_agent::{AgentNodeState, AgentRuntime, FileAgentStateStore, RelayForwarderStats};
    use ipars_types::api::{
        AgentNodeRemovalRequest, AgentNodeRemovalResponse, AgentPacketFlowApplication,
        AgentPacketFlowClassification, AgentPacketFlowConntrackStatus, AgentPacketFlowDropReason,
        AgentPacketFlowDuplicateSource, AgentPacketFlowMatchKind, AgentPacketFlowObservation,
        AgentRelayAdmissionFailureReason, AgentWireGuardKeyRotationRequest,
        AgentWireGuardKeyRotationResponse, LazyConnectMetrics, PeerMap, RelayMap,
        RemoveNodeRequest, RemoveNodeResponse, RotateWireGuardKeyRequest,
        RotateWireGuardKeyResponse,
    };
    use ipars_types::{
        CandidateSource, ClusterId, ClusterPolicy, EndpointCandidate, EndpointCandidateKind,
        NodeId, NodeRecord, PathMetrics, PathRecord, PathScore, PathState, PeerPathKey, Role,
        Route, TokenPolicy, VpnIp,
    };
    use tower::ServiceExt;

    use super::*;

    fn peer_record(node_id: NodeId, vpn_ip: IpAddr, routes: Vec<Route>) -> NodeRecord {
        NodeRecord {
            node_id,
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(vpn_ip),
            identity_public_key: "identity-public".to_string(),
            wireguard_public_key: "wireguard-public".to_string(),
            role: Role::edge(),
            tags: BTreeSet::new(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes,
            registered_at: Utc::now(),
        }
    }

    fn temp_state_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ipars-agent-http-{name}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ))
    }

    #[test]
    fn prometheus_metrics_zero_fill_packet_flow_and_path_labels() {
        let node_id = NodeId::from_string("node-zero-fill");
        let metrics = AgentMetricsResponse {
            node_id: node_id.clone(),
            candidate_count: 0,
            peer_map_synced: false,
            peer_map_peer_count: 0,
            peer_map_route_count: 0,
            peer_map_generated_at: None,
            path_count: 0,
            relay_session_count: 0,
            relay_admission_attempt_count: 0,
            relay_admission_success_count: 0,
            relay_admission_failure_count: 0,
            relay_admission_failure_reason_counts: Vec::new(),
            relay_forwarder_count: 0,
            relay_forwarders: Vec::new(),
            path_change_event_count: 0,
            path_change_event_total_count: 0,
            path_change_event_dropped_count: 0,
            path_state_counts: Vec::new(),
            lazy_connect: LazyConnectMetrics {
                active_peer_count: 0,
                pinned_peer_count: 0,
                observed_peer_vpn_ip_count: 0,
                observed_route_peer_count: 0,
                observed_route_count: 0,
            },
            path_probe_record_count: 0,
            direct_path_probe_started_count: 0,
            direct_path_probe_confirmed_count: 0,
            direct_path_probe_timeout_count: 0,
            peer_activity_record_count: 0,
            packet_flow_observation_count: 0,
            packet_flow_match_count: 0,
            packet_flow_unmatched_count: 0,
            packet_flow_filtered_count: 0,
            packet_flow_filtered_reason_counts: Vec::new(),
            packet_flow_duplicate_suppression_count: 0,
            packet_flow_duplicate_suppression_counts: Vec::new(),
            packet_flow_classification_counts: Vec::new(),
            packet_flow_application_counts: Vec::new(),
            userspace_wireguard_process: None,
            generated_at: Utc::now(),
        };
        let body = render_prometheus_metrics(&metrics);
        let prometheus_node_id = prometheus_label(node_id.as_str());
        assert!(body.contains(&format!(
            "ipars_agent_path_change_events_total{{node_id=\"{prometheus_node_id}\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_path_change_events_dropped_total{{node_id=\"{prometheus_node_id}\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_direct_path_probes_started_total{{node_id=\"{prometheus_node_id}\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_direct_path_probes_confirmed_total{{node_id=\"{prometheus_node_id}\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_direct_path_probes_timeout_total{{node_id=\"{prometheus_node_id}\"}} 0"
        )));

        for source in AgentPacketFlowDuplicateSource::ALL {
            assert!(body.contains(&format!(
                "ipars_agent_packet_flow_duplicate_suppressions_by_source_total{{node_id=\"{prometheus_node_id}\",source=\"{}\"}} 0",
                source.as_str()
            )));
        }
        for reason in AgentPacketFlowDropReason::ALL {
            assert!(body.contains(&format!(
                "ipars_agent_packet_flow_filtered_by_reason_total{{node_id=\"{prometheus_node_id}\",reason=\"{}\"}} 0",
                reason.as_str()
            )));
        }
        for classification in AgentPacketFlowClassification::ALL {
            assert!(body.contains(&format!(
                "ipars_agent_packet_flow_classified_by_lifecycle_total{{node_id=\"{prometheus_node_id}\",classification=\"{}\"}} 0",
                classification.as_str()
            )));
        }
        for application in AgentPacketFlowApplication::ALL {
            assert!(body.contains(&format!(
                "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"{}\"}} 0",
                application.as_str()
            )));
        }
        for state in [
            PathState::DirectPublic,
            PathState::DirectIpv6,
            PathState::DirectNatTraversal,
            PathState::Relay,
            PathState::Unreachable,
        ] {
            assert!(body.contains(&format!(
                "ipars_agent_path_state_count{{node_id=\"{prometheus_node_id}\",state=\"{}\"}} 0",
                path_state_label(state)
            )));
        }
    }

    #[derive(Clone)]
    struct RotationCapture {
        request: Arc<tokio::sync::Mutex<Option<RotateWireGuardKeyRequest>>>,
    }

    async fn control_plane_rotation_handler(
        axum::extract::State(capture): axum::extract::State<RotationCapture>,
        axum::extract::Path(node_id): axum::extract::Path<String>,
        Json(request): Json<RotateWireGuardKeyRequest>,
    ) -> Json<RotateWireGuardKeyResponse> {
        assert_eq!(node_id, request.node_id.as_str());
        assert!(request.node_signature.is_some());
        *capture.request.lock().await = Some(request.clone());
        let node = NodeRecord {
            node_id: request.node_id.clone(),
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
            identity_public_key: "identity-public".to_string(),
            wireguard_public_key: request.next_wireguard_public_key.clone(),
            role: Role::edge(),
            tags: BTreeSet::new(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        };
        Json(RotateWireGuardKeyResponse {
            node,
            peer_map: PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: Vec::new(),
                generated_at: Utc::now(),
            },
            relay_map: RelayMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                relays: Vec::new(),
                generated_at: Utc::now(),
            },
            rotated_at: Utc::now(),
        })
    }

    async fn spawn_rotation_control_plane(
        capture: RotationCapture,
    ) -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let app = Router::new()
            .route(
                "/v1/nodes/{node_id}/wireguard-key",
                axum::routing::put(control_plane_rotation_handler),
            )
            .with_state(capture);
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok((format!("http://{addr}"), task))
    }

    #[derive(Clone)]
    struct RemovalCapture {
        request: Arc<tokio::sync::Mutex<Option<RemoveNodeRequest>>>,
    }

    async fn control_plane_removal_handler(
        axum::extract::State(capture): axum::extract::State<RemovalCapture>,
        axum::extract::Path(node_id): axum::extract::Path<String>,
        Json(request): Json<RemoveNodeRequest>,
    ) -> Json<RemoveNodeResponse> {
        assert_eq!(node_id, request.node_id.as_str());
        assert!(request.node_signature.is_some());
        *capture.request.lock().await = Some(request.clone());
        let node = NodeRecord {
            node_id: request.node_id.clone(),
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
            identity_public_key: "identity-public".to_string(),
            wireguard_public_key: "wireguard-public".to_string(),
            role: Role::edge(),
            tags: BTreeSet::new(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        };
        Json(RemoveNodeResponse {
            node,
            removed_path_count: 2,
            removed_health: true,
            removed_at: Utc::now(),
        })
    }

    async fn spawn_removal_control_plane(
        capture: RemovalCapture,
    ) -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let app = Router::new()
            .route(
                "/v1/nodes/{node_id}",
                axum::routing::delete(control_plane_removal_handler),
            )
            .with_state(capture);
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok((format!("http://{addr}"), task))
    }

    async fn spawn_raw_http_response(
        response: String,
    ) -> Result<(String, tokio::task::JoinHandle<std::io::Result<()>>), Box<dyn std::error::Error>>
    {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream.write_all(response.as_bytes()).await?;
            Ok(())
        });
        Ok((format!("http://{addr}"), task))
    }

    async fn spawn_stalled_http_service(
    ) -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let _stream = stream;
            std::future::pending::<()>().await;
        });
        Ok((format!("http://{addr}"), task))
    }

    #[tokio::test]
    async fn wireguard_key_rotation_times_out_stalled_endpoint_and_fails_over(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (stalled_url, stalled_task) = spawn_stalled_http_service().await?;
        let capture = RotationCapture {
            request: Arc::new(tokio::sync::Mutex::new(None)),
        };
        let (available_url, available_task) = spawn_rotation_control_plane(capture.clone()).await?;
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let request = runtime.plan_wireguard_key_rotation(Utc::now())?.request;
        let started = std::time::Instant::now();

        let response = send_wireguard_key_rotation_to_control_planes(
            &reqwest::Client::new(),
            Duration::from_millis(100),
            &[stalled_url, available_url],
            request.clone(),
        )
        .await?;

        assert_eq!(response.node.node_id, request.node_id);
        assert_eq!(
            capture
                .request
                .lock()
                .await
                .as_ref()
                .map(|request| &request.next_wireguard_public_key),
            Some(&request.next_wireguard_public_key)
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "stalled lifecycle endpoint failover exceeded the bounded request timeout"
        );
        stalled_task.abort();
        available_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn wireguard_key_rotation_client_rejects_oversized_control_plane_response(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_CONTROL_PLANE_RESPONSE_BYTES + 1
        );
        let (control_plane_url, server) = spawn_raw_http_response(response).await?;
        let request = RotateWireGuardKeyRequest {
            node_id: NodeId::from_string("node-a"),
            previous_wireguard_public_key: "previous".to_string(),
            next_wireguard_public_key: "next".to_string(),
            node_signature: None,
        };

        let error = send_wireguard_key_rotation_to_control_planes(
            &reqwest::Client::new(),
            DEFAULT_CONTROL_PLANE_REQUEST_TIMEOUT,
            &[control_plane_url],
            request,
        )
        .await
        .expect_err("oversized WireGuard key rotation response should be rejected");

        assert!(error
            .to_string()
            .contains("control-plane WireGuard key rotation response exceeds maximum size"));
        tokio::time::timeout(std::time::Duration::from_secs(5), server).await???;
        Ok(())
    }

    #[tokio::test]
    async fn bounded_control_plane_json_reader_rejects_oversized_chunked_body(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\n{\"ok\"\r\n5\r\n:true\r\n1\r\n}\r\n0\r\n\r\n"
            .to_string();
        let (url, server) = spawn_raw_http_response(response).await?;
        let response = reqwest::Client::new().get(&url).send().await?;
        let error = read_bounded_json_response::<serde_json::Value>(
            response,
            10,
            "test control-plane JSON",
        )
        .await
        .expect_err("oversized chunked control-plane body should be rejected");

        assert!(error
            .to_string()
            .contains("test control-plane JSON response exceeds maximum size of 10 bytes"));
        tokio::time::timeout(std::time::Duration::from_secs(5), server).await???;
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_status_returns_node_keys() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        runtime
            .record_userspace_wireguard_process_status(
                AgentManagedProcessState::Ready,
                Some(4242),
                None,
                None,
            )
            .await;
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
        assert_eq!(
            status
                .userspace_wireguard_process
                .as_ref()
                .map(|process| process.state),
            Some(AgentManagedProcessState::Ready)
        );
        assert_eq!(
            status
                .userspace_wireguard_process
                .as_ref()
                .and_then(|process| process.pid),
            Some(4242)
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_api_bearer_auth_protects_every_endpoint_except_health(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const TOKEN: &str = "agent-api-secret-with-at-least-32-bytes";
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let app = router(AgentHttpState::new(runtime).require_api_bearer_token(TOKEN.to_string()));

        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/healthz")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(health.status(), StatusCode::OK);

        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/status")
                    .body(Body::empty())?,
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
                    .method("GET")
                    .uri("/metrics")
                    .header(header::AUTHORIZATION, "Bearer wrong-secret")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);

        let protected_mutation = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/path-probe")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(protected_mutation.status(), StatusCode::UNAUTHORIZED);

        let accepted = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/status")
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(accepted.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_peer_map_returns_runtime_snapshot() -> Result<(), Box<dyn std::error::Error>>
    {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let app = router(AgentHttpState::new(runtime.clone()));

        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/peers")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let peer = peer_record(
            NodeId::from_string("peer-a"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 22)),
            Vec::new(),
        );
        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: vec![peer],
            generated_at: Utc::now(),
        };
        runtime.record_peer_map_snapshot(peer_map.clone()).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/peers")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response: PeerMap = serde_json::from_slice(&body)?;
        assert_eq!(response, peer_map);
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_rotates_wireguard_key_with_control_plane(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let previous_wireguard_public_key = state.wireguard_public_key_b64.clone();
        let state_dir = temp_state_dir("wireguard-rotation");
        let state_path = state_dir.join("state.json");
        let store = FileAgentStateStore::new(&state_path);
        store.save(&state)?;
        let runtime = Arc::new(AgentRuntime::new(state.clone(), ClusterPolicy::default()));
        let capture = RotationCapture {
            request: Arc::new(tokio::sync::Mutex::new(None)),
        };
        let (control_plane_url, control_plane_task) =
            spawn_rotation_control_plane(capture.clone()).await?;
        let app = router(AgentHttpState::with_wireguard_key_rotation(
            runtime.clone(),
            store.clone(),
            vec![control_plane_url],
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/wireguard-key/rotate")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(
                        &AgentWireGuardKeyRotationRequest::default(),
                    )?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response: AgentWireGuardKeyRotationResponse = serde_json::from_slice(&body)?;
        assert_eq!(
            response.previous_wireguard_public_key,
            previous_wireguard_public_key
        );
        assert_ne!(
            response.next_wireguard_public_key,
            previous_wireguard_public_key
        );
        assert_eq!(
            response.control_plane_node.wireguard_public_key,
            response.next_wireguard_public_key
        );

        let sent_request = capture
            .request
            .lock()
            .await
            .clone()
            .ok_or_else(|| std::io::Error::other("control-plane did not receive rotation"))?;
        assert_eq!(
            sent_request.previous_wireguard_public_key,
            previous_wireguard_public_key
        );
        assert_eq!(
            sent_request.next_wireguard_public_key,
            response.next_wireguard_public_key
        );
        assert!(sent_request.node_signature.is_some());

        let persisted = store.load()?;
        assert_eq!(
            persisted.wireguard_public_key_b64,
            response.next_wireguard_public_key
        );
        assert_ne!(
            persisted.wireguard_private_key_b64,
            state.wireguard_private_key_b64
        );
        assert_eq!(
            runtime.status().await.wireguard_public_key,
            response.next_wireguard_public_key
        );

        control_plane_task.abort();
        let _ = std::fs::remove_dir_all(state_dir);
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_removes_node_with_control_plane() -> Result<(), Box<dyn std::error::Error>>
    {
        let state = AgentNodeState::generate(Utc::now());
        let runtime = Arc::new(AgentRuntime::new(state.clone(), ClusterPolicy::default()));
        let capture = RemovalCapture {
            request: Arc::new(tokio::sync::Mutex::new(None)),
        };
        let (control_plane_url, control_plane_task) =
            spawn_removal_control_plane(capture.clone()).await?;
        let app = router(AgentHttpState::with_control_plane_urls(
            runtime,
            vec![control_plane_url],
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/node/remove")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(
                        &AgentNodeRemovalRequest::default(),
                    )?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response: AgentNodeRemovalResponse = serde_json::from_slice(&body)?;
        assert_eq!(response.node_id, state.node_id);
        assert_eq!(response.control_plane_node.node_id, response.node_id);
        assert_eq!(response.removed_path_count, 2);
        assert!(response.removed_health);

        let sent_request = capture
            .request
            .lock()
            .await
            .clone()
            .ok_or_else(|| std::io::Error::other("control-plane did not receive removal"))?;
        assert_eq!(sent_request.node_id, response.node_id);
        assert!(sent_request.node_signature.is_some());

        control_plane_task.abort();
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
            .await
            .expect("valid relay path state should be stored");
        let forwarder_metrics = Arc::new(RelayForwarderStats::new(
            NodeId::from_string("peer-a"),
            NodeId::from_string("relay-a"),
            std::net::SocketAddr::from(([127, 0, 0, 1], 51820)),
            std::net::SocketAddr::from(([127, 0, 0, 1], 52000)),
        ));
        forwarder_metrics.record_socket_receive_error();
        forwarder_metrics.record_outbound(64, 128);
        forwarder_metrics.record_outbound_expired_session_drop(96);
        forwarder_metrics.record_outbound_oversized_drop(112, 160);
        forwarder_metrics.record_outbound_socket_error_drop(120, 176);
        forwarder_metrics.record_inbound(32);
        forwarder_metrics.record_inbound_expired_session_drop(48);
        forwarder_metrics.record_inbound_oversized_drop(80);
        forwarder_metrics.record_inbound_socket_error_drop(88);
        runtime
            .upsert_relay_forwarder_endpoint(
                NodeId::from_string("peer-a"),
                std::net::SocketAddr::from(([127, 0, 0, 1], 52000)),
            )
            .await;
        runtime
            .register_relay_forwarder_metrics(forwarder_metrics)
            .await;
        runtime.record_relay_admission_attempt();
        runtime.record_relay_admission_success();
        runtime.record_relay_admission_failure_reason(AgentRelayAdmissionFailureReason::Rejected);
        runtime
            .record_userspace_wireguard_process_status(
                AgentManagedProcessState::Ready,
                Some(4242),
                None,
                None,
            )
            .await;
        runtime
            .record_peer_activity(NodeId::from_string("peer-a"), Utc::now(), true)
            .await;
        runtime
            .record_packet_flow_activity(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                Utc::now(),
                false,
            )
            .await;
        runtime.record_packet_flow_filtered(AgentPacketFlowDropReason::Multicast);
        runtime.record_packet_flow_filtered(AgentPacketFlowDropReason::Broadcast);
        runtime
            .record_packet_flow_filtered(AgentPacketFlowDropReason::InconsistentTransportMetadata);
        runtime.record_packet_flow_duplicate_suppression(
            AgentPacketFlowDuplicateSource::ConntrackNetlink,
            2,
        );
        let peer_map_generated_at = Utc::now();
        let peer_route = Route {
            id: "route-a".to_string(),
            cidr: "10.42.0.0/16".parse()?,
            advertised_by: NodeId::from_string("peer-a"),
            via: Some(NodeId::from_string("peer-a")),
            metric: 100,
            tags: BTreeSet::new(),
        };
        runtime
            .record_peer_map_snapshot(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer_record(
                    NodeId::from_string("peer-a"),
                    IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
                    vec![peer_route],
                )],
                generated_at: peer_map_generated_at,
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
        assert!(metrics.peer_map_synced);
        assert_eq!(metrics.peer_map_peer_count, 1);
        assert_eq!(metrics.peer_map_route_count, 1);
        assert_eq!(metrics.peer_map_generated_at, Some(peer_map_generated_at));
        assert_eq!(metrics.path_count, 1);
        assert_eq!(metrics.path_state_counts.len(), 5);
        assert!(metrics
            .path_state_counts
            .iter()
            .any(|entry| entry.state == PathState::Relay && entry.count == 1));
        assert!(metrics
            .path_state_counts
            .iter()
            .any(|entry| entry.state == PathState::DirectPublic && entry.count == 0));
        assert_eq!(metrics.relay_forwarder_count, 1);
        assert_eq!(metrics.path_change_event_count, 1);
        assert_eq!(metrics.path_change_event_total_count, 1);
        assert_eq!(metrics.path_change_event_dropped_count, 0);
        assert_eq!(metrics.relay_forwarders.len(), 1);
        assert_eq!(metrics.relay_forwarders[0].socket_receive_errors, 1);
        assert_eq!(metrics.relay_forwarders[0].outbound_packets, 1);
        assert_eq!(metrics.relay_forwarders[0].outbound_payload_bytes, 64);
        assert_eq!(metrics.relay_forwarders[0].outbound_datagram_bytes, 128);
        assert_eq!(
            metrics.relay_forwarders[0].outbound_dropped_expired_session_packets,
            1
        );
        assert_eq!(
            metrics.relay_forwarders[0].outbound_dropped_expired_session_payload_bytes,
            96
        );
        assert_eq!(
            metrics.relay_forwarders[0].outbound_dropped_oversized_packets,
            1
        );
        assert_eq!(
            metrics.relay_forwarders[0].outbound_dropped_oversized_payload_bytes,
            112
        );
        assert_eq!(
            metrics.relay_forwarders[0].outbound_dropped_oversized_datagram_bytes,
            160
        );
        assert_eq!(
            metrics.relay_forwarders[0].outbound_dropped_socket_error_packets,
            1
        );
        assert_eq!(
            metrics.relay_forwarders[0].outbound_dropped_socket_error_payload_bytes,
            120
        );
        assert_eq!(
            metrics.relay_forwarders[0].outbound_dropped_socket_error_datagram_bytes,
            176
        );
        assert_eq!(metrics.relay_forwarders[0].inbound_packets, 1);
        assert_eq!(metrics.relay_forwarders[0].inbound_payload_bytes, 32);
        assert_eq!(
            metrics.relay_forwarders[0].inbound_dropped_expired_session_packets,
            1
        );
        assert_eq!(
            metrics.relay_forwarders[0].inbound_dropped_expired_session_payload_bytes,
            48
        );
        assert_eq!(
            metrics.relay_forwarders[0].inbound_dropped_oversized_packets,
            1
        );
        assert_eq!(
            metrics.relay_forwarders[0].inbound_dropped_oversized_payload_bytes,
            80
        );
        assert_eq!(
            metrics.relay_forwarders[0].inbound_dropped_socket_error_packets,
            1
        );
        assert_eq!(
            metrics.relay_forwarders[0].inbound_dropped_socket_error_payload_bytes,
            88
        );
        assert_eq!(metrics.relay_admission_attempt_count, 1);
        assert_eq!(metrics.relay_admission_success_count, 1);
        assert_eq!(metrics.relay_admission_failure_count, 1);
        assert!(metrics
            .relay_admission_failure_reason_counts
            .iter()
            .any(|entry| {
                entry.reason == AgentRelayAdmissionFailureReason::Rejected && entry.count == 1
            }));
        assert_eq!(
            metrics
                .userspace_wireguard_process
                .as_ref()
                .map(|status| status.state),
            Some(AgentManagedProcessState::Ready)
        );
        assert_eq!(
            metrics
                .userspace_wireguard_process
                .as_ref()
                .and_then(|status| status.pid),
            Some(4242)
        );
        assert_eq!(metrics.lazy_connect.active_peer_count, 1);
        assert_eq!(metrics.lazy_connect.pinned_peer_count, 1);
        assert_eq!(metrics.path_probe_record_count, 0);
        assert_eq!(metrics.peer_activity_record_count, 1);
        assert_eq!(metrics.packet_flow_observation_count, 1);
        assert_eq!(metrics.packet_flow_match_count, 0);
        assert_eq!(metrics.packet_flow_unmatched_count, 1);
        assert_eq!(metrics.packet_flow_filtered_count, 4);
        assert_eq!(metrics.packet_flow_duplicate_suppression_count, 2);
        assert!(metrics
            .packet_flow_duplicate_suppression_counts
            .iter()
            .any(
                |entry| entry.source == AgentPacketFlowDuplicateSource::ConntrackNetlink
                    && entry.count == 2
            ));
        assert!(metrics
            .packet_flow_classification_counts
            .iter()
            .any(
                |entry| entry.classification == AgentPacketFlowClassification::Unknown
                    && entry.count == 1
            ));
        assert!(metrics
            .packet_flow_application_counts
            .iter()
            .any(
                |entry| entry.application == AgentPacketFlowApplication::Unknown
                    && entry.count == 1
            ));
        assert!(metrics
            .packet_flow_filtered_reason_counts
            .iter()
            .any(|entry| entry.reason == AgentPacketFlowDropReason::Multicast && entry.count == 1));
        assert!(metrics
            .packet_flow_filtered_reason_counts
            .iter()
            .any(
                |entry| entry.reason == AgentPacketFlowDropReason::NoOverlayMatch
                    && entry.count == 1
            ));
        assert!(metrics
            .packet_flow_filtered_reason_counts
            .iter()
            .any(
                |entry| entry.reason == AgentPacketFlowDropReason::InconsistentTransportMetadata
                    && entry.count == 1
            ));

        let prometheus_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(prometheus_response.status(), StatusCode::OK);
        assert_eq!(
            prometheus_response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static(
                "text/plain; version=0.0.4; charset=utf-8"
            ))
        );
        let body = axum::body::to_bytes(prometheus_response.into_body(), usize::MAX).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("ipars_agent_metrics_generated_timestamp_seconds"));
        assert!(body.contains("ipars_agent_paths"));
        assert!(body.contains("ipars_agent_peer_map_synced"));
        assert!(body.contains("ipars_agent_peer_map_peers"));
        assert!(body.contains("ipars_agent_peer_map_routes"));
        assert!(body.contains("ipars_agent_peer_map_generated_timestamp_seconds"));
        assert!(body.contains("state=\"RELAY\""));
        assert!(body.contains("state=\"DIRECT_PUBLIC\""));
        assert!(body.contains("state=\"DIRECT_IPV6\""));
        assert!(body.contains("state=\"DIRECT_NAT_TRAVERSAL\""));
        assert!(body.contains("state=\"UNREACHABLE\""));
        assert!(body.contains("ipars_agent_relay_forwarder_outbound_packets_total"));
        assert!(body.contains(
            "ipars_agent_relay_forwarder_outbound_dropped_unexpected_source_packets_total"
        ));
        assert!(body.contains(
            "ipars_agent_relay_forwarder_outbound_dropped_expired_session_packets_total"
        ));
        assert!(
            body.contains("ipars_agent_relay_forwarder_outbound_dropped_oversized_packets_total")
        );
        assert!(body.contains("ipars_agent_relay_forwarder_socket_receive_errors_total"));
        assert!(body
            .contains("ipars_agent_relay_forwarder_outbound_dropped_socket_error_packets_total"));
        assert!(body
            .contains("ipars_agent_relay_forwarder_outbound_dropped_non_wireguard_packets_total"));
        assert!(body
            .contains("ipars_agent_relay_forwarder_inbound_dropped_expired_session_packets_total"));
        assert!(
            body.contains("ipars_agent_relay_forwarder_inbound_dropped_oversized_packets_total")
        );
        assert!(
            body.contains("ipars_agent_relay_forwarder_inbound_dropped_socket_error_packets_total")
        );
        assert!(body
            .contains("ipars_agent_relay_forwarder_inbound_dropped_non_wireguard_packets_total"));
        assert!(body.contains("ipars_agent_relay_admission_attempts_total"));
        assert!(body.contains("ipars_agent_relay_admission_success_total"));
        assert!(body.contains("ipars_agent_relay_admission_failures_total"));
        assert!(body.contains("ipars_agent_relay_admission_failures_by_reason_total"));
        assert!(body.contains("ipars_agent_userspace_wireguard_process_state"));
        assert!(body.contains("state=\"ready\"} 1"));
        assert!(body.contains("state=\"disabled\"} 0"));
        assert!(body.contains("peer=\"peer-a\""));
        assert!(body.contains("relay_node=\"relay-a\""));
        assert!(body.contains("peer=\"peer-a\",relay_node=\"relay-a\"} 64"));
        assert!(body.contains("peer=\"peer-a\",relay_node=\"relay-a\"} 32"));
        assert!(body.contains("ipars_agent_active_peers"));
        assert!(body.contains("ipars_agent_pinned_peers"));
        assert!(body.contains("ipars_agent_path_probe_records_total"));
        assert!(body.contains("ipars_agent_peer_activity_records_total"));
        assert!(body.contains("ipars_agent_packet_flow_observations_total"));
        assert!(body.contains("ipars_agent_packet_flow_unmatched_total"));
        assert!(body.contains("ipars_agent_packet_flow_filtered_total"));
        assert!(body.contains("ipars_agent_packet_flow_duplicate_suppressions_total"));
        assert!(body.contains("ipars_agent_packet_flow_duplicate_suppressions_by_source_total"));
        assert!(body.contains("ipars_agent_packet_flow_classified_by_lifecycle_total"));
        assert!(body.contains("ipars_agent_packet_flow_classified_by_application_total"));
        let prometheus_node_id = prometheus_label(node_id.as_str());
        assert!(body.contains(&format!(
            "ipars_agent_metrics_generated_timestamp_seconds{{node_id=\"{prometheus_node_id}\"}} "
        )));
        assert!(body.contains(&format!(
            "ipars_agent_peer_map_synced{{node_id=\"{prometheus_node_id}\"}} 1"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_peer_map_peers{{node_id=\"{prometheus_node_id}\"}} 1"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_peer_map_routes{{node_id=\"{prometheus_node_id}\"}} 1"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_peer_map_generated_timestamp_seconds{{node_id=\"{prometheus_node_id}\"}} {}",
            peer_map_generated_at.timestamp()
        )));
        assert!(body.contains(&format!(
            "ipars_agent_path_state_count{{node_id=\"{prometheus_node_id}\",state=\"RELAY\"}} 1"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_path_state_count{{node_id=\"{prometheus_node_id}\",state=\"DIRECT_PUBLIC\"}} 0"
        )));
        assert!(body.contains(
            &format!("ipars_agent_relay_admission_failures_by_reason_total{{node_id=\"{prometheus_node_id}\",reason=\"rejected\"}} 1")
        ));
        assert!(body.contains(
            &format!("ipars_agent_packet_flow_duplicate_suppressions_by_source_total{{node_id=\"{prometheus_node_id}\",source=\"conntrack-netlink\"}} 2")
        ));
        assert!(body.contains(
            &format!("ipars_agent_packet_flow_filtered_by_reason_total{{node_id=\"{prometheus_node_id}\",reason=\"multicast\"}} 1")
        ));
        assert!(body.contains(
            &format!("ipars_agent_packet_flow_filtered_by_reason_total{{node_id=\"{prometheus_node_id}\",reason=\"no_overlay_match\"}} 1")
        ));
        assert!(body.contains(
            &format!("ipars_agent_packet_flow_filtered_by_reason_total{{node_id=\"{prometheus_node_id}\",reason=\"inconsistent_transport_metadata\"}} 1")
        ));
        assert!(body.contains(
            &format!("ipars_agent_packet_flow_classified_by_lifecycle_total{{node_id=\"{prometheus_node_id}\",classification=\"unknown\"}} 1")
        ));
        assert!(body.contains(
            &format!("ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"unknown\"}} 1")
        ));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"kafka\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"dhcp\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"ike\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"ipsec\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"gre\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"vxlan\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"geneve\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"consul\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"vault\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"nomad\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"jaeger\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"loki\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"tempo\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"zipkin\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"clickhouse\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"influxdb\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"nfs\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"syslog\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"snmp\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"kerberos\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"ntp\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"radius\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"tacacs\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"bgp\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_packet_flow_classified_by_application_total{{node_id=\"{prometheus_node_id}\",application=\"bfd\"}} 0"
        )));

        let paths_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/paths")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(paths_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(paths_response.into_body(), usize::MAX).await?;
        let paths: AgentPathsResponse = serde_json::from_slice(&body)?;
        assert_eq!(paths.paths.len(), 1);
        assert_eq!(paths.paths[0].selected_state, PathState::Relay);

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
        assert_eq!(events.total_count, 1);
        assert_eq!(events.dropped_count, 0);
        assert_eq!(events.events[0].new_state, PathState::Relay);
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_records_path_probe() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let local = runtime.state().node_id.clone();
        let metrics_runtime = Arc::clone(&runtime);
        let app = router(AgentHttpState::new(runtime));
        let request = AgentPathProbeRequest {
            peer: NodeId::from_string("peer-probed"),
            selected_state: PathState::DirectNatTraversal,
            selected_candidate: None,
            relay_node: None,
            metrics: PathMetrics {
                latency_ms: Some(35.0),
                loss_ppm: 100,
                jitter_ms: Some(4.0),
                relay_load: None,
                stability: 0.9,
            },
            policy_allowed: true,
            cost: 25,
            pin: true,
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/path-probe")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&request)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response: AgentPathProbeResponse = serde_json::from_slice(&body)?;
        assert_eq!(response.path.key.local, local);
        assert_eq!(response.path.key.remote, request.peer);
        assert_eq!(response.path.selected_state, PathState::DirectNatTraversal);
        assert!(response.path.pinned);
        assert!(response
            .path
            .score
            .reasons
            .iter()
            .any(|reason| reason == "latency_ms=35.0"));
        let metrics = metrics_runtime.metrics().await;
        assert_eq!(metrics.path_probe_record_count, 1);

        let paths_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/paths")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(paths_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(paths_response.into_body(), usize::MAX).await?;
        let paths: AgentPathsResponse = serde_json::from_slice(&body)?;
        assert_eq!(paths.paths, vec![response.path.clone()]);

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
        assert_eq!(events.total_count, 1);
        assert_eq!(events.dropped_count, 0);
        assert_eq!(events.events[0].new_state, PathState::DirectNatTraversal);
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_rejects_invalid_path_probe_metrics(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let metrics_runtime = Arc::clone(&runtime);
        let app = router(AgentHttpState::new(runtime));
        let request = AgentPathProbeRequest {
            peer: NodeId::from_string("peer-probed"),
            selected_state: PathState::DirectPublic,
            selected_candidate: None,
            relay_node: None,
            metrics: PathMetrics {
                latency_ms: Some(-1.0),
                ..PathMetrics::default()
            },
            policy_allowed: true,
            cost: 0,
            pin: false,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/path-probe")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&request)?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let error: serde_json::Value = serde_json::from_slice(&body)?;
        assert!(error["error"]
            .as_str()
            .unwrap_or_default()
            .contains("latency_ms"));
        assert_eq!(metrics_runtime.metrics().await.path_probe_record_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_rejects_unusable_path_probe_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let metrics_runtime = Arc::clone(&runtime);
        let app = router(AgentHttpState::new(runtime));
        let peer = NodeId::from_string("peer-probed");
        let request = AgentPathProbeRequest {
            peer: peer.clone(),
            selected_state: PathState::DirectPublic,
            selected_candidate: Some(EndpointCandidate {
                node_id: peer,
                kind: EndpointCandidateKind::PublicUdp,
                addr: "203.0.113.10:0".parse()?,
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::ControlPlane,
            }),
            relay_node: None,
            metrics: PathMetrics::default(),
            policy_allowed: true,
            cost: 0,
            pin: false,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/path-probe")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&request)?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let error: serde_json::Value = serde_json::from_slice(&body)?;
        assert!(error["error"]
            .as_str()
            .unwrap_or_default()
            .contains("selected candidate"));
        assert!(error["error"]
            .as_str()
            .unwrap_or_default()
            .contains("is unusable"));
        assert_eq!(metrics_runtime.metrics().await.path_probe_record_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_rejects_inconsistent_path_probe_shape(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let metrics_runtime = Arc::clone(&runtime);
        let app = router(AgentHttpState::new(runtime));
        let peer = NodeId::from_string("peer-probed");
        let relay = NodeId::from_string("relay-a");
        let candidate = EndpointCandidate {
            node_id: peer.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr: "203.0.113.10:51820".parse()?,
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::ControlPlane,
        };

        let direct_mismatch = AgentPathProbeRequest {
            peer: peer.clone(),
            selected_state: PathState::DirectPublic,
            selected_candidate: Some(candidate.clone()),
            relay_node: None,
            metrics: PathMetrics::default(),
            policy_allowed: true,
            cost: 0,
            pin: false,
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/path-probe")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&direct_mismatch)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let error: serde_json::Value = serde_json::from_slice(&body)?;
        assert!(error["error"]
            .as_str()
            .unwrap_or_default()
            .contains("selected state DirectPublic"));
        assert!(error["error"]
            .as_str()
            .unwrap_or_default()
            .contains("selected candidate kind StunReflexive"));

        let relay_with_candidate = AgentPathProbeRequest {
            peer,
            selected_state: PathState::Relay,
            selected_candidate: Some(candidate),
            relay_node: Some(relay),
            metrics: PathMetrics::default(),
            policy_allowed: true,
            cost: 0,
            pin: false,
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/path-probe")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&relay_with_candidate)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let error: serde_json::Value = serde_json::from_slice(&body)?;
        assert!(error["error"]
            .as_str()
            .unwrap_or_default()
            .contains("relay path probe must not carry"));

        let paths_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/paths")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(paths_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(paths_response.into_body(), usize::MAX).await?;
        let paths: AgentPathsResponse = serde_json::from_slice(&body)?;
        assert!(paths.paths.is_empty());
        assert_eq!(metrics_runtime.metrics().await.path_probe_record_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_records_peer_activity_for_lazy_connect(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let peer = NodeId::from_string("peer-active");
        let app = router(AgentHttpState::new(runtime.clone()));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/peer-activity")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&AgentPeerActivityRequest {
                        peer: peer.clone(),
                        pin: true,
                    })?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let activity: AgentPeerActivityResponse = serde_json::from_slice(&body)?;
        assert_eq!(activity.peer, peer);
        assert!(activity.pinned);
        assert!(runtime.idle_peers_to_close(Utc::now()).await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_records_packet_flow_for_lazy_connect(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let peer = NodeId::from_string("peer-route");
        let route = "10.44.0.0/16".parse()?;
        let peer_record = peer_record(
            peer.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 44)),
            vec![Route {
                id: "peer-route-cidr".to_string(),
                cidr: route,
                advertised_by: peer.clone(),
                via: None,
                metric: 10,
                tags: BTreeSet::new(),
            }],
        );
        runtime
            .observe_peer_map_for_lazy_connect(std::slice::from_ref(&peer_record))
            .await;
        let app = router(AgentHttpState::new(runtime.clone()));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/packet-flow")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&AgentPacketFlowRequest {
                        destination: IpAddr::V4(Ipv4Addr::new(10, 44, 3, 10)),
                        pin: true,
                        observation: AgentPacketFlowObservation {
                            source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
                            protocol: Some(ipars_types::TransportProtocol::Udp),
                            source_port: Some(50_000),
                            destination_port: Some(51820),
                            detector: Some("unit-test".to_string()),
                            application: Some(AgentPacketFlowApplication::WireGuard),
                            payload_prefix: Vec::new(),
                            conntrack_status: vec![AgentPacketFlowConntrackStatus::Assured],
                            tcp_state: None,
                        },
                    })?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let packet_flow: AgentPacketFlowResponse = serde_json::from_slice(&body)?;
        assert_eq!(
            packet_flow.observation.protocol,
            Some(ipars_types::TransportProtocol::Udp)
        );
        assert_eq!(packet_flow.observation.source_port, Some(50_000));
        assert_eq!(packet_flow.observation.destination_port, Some(51820));
        assert_eq!(
            packet_flow.observation.detector.as_deref(),
            Some("unit-test")
        );
        assert_eq!(
            packet_flow.observation.application,
            Some(AgentPacketFlowApplication::WireGuard)
        );
        assert_eq!(
            packet_flow.observation.conntrack_status,
            vec![AgentPacketFlowConntrackStatus::Assured]
        );
        assert_eq!(packet_flow.observation.tcp_state, None);
        assert_eq!(packet_flow.filtered_reason, None);
        let matched = packet_flow
            .matched
            .ok_or_else(|| std::io::Error::other("route should match peer"))?;
        assert_eq!(matched.peer, peer);
        assert_eq!(matched.kind, AgentPacketFlowMatchKind::AdvertisedRoute);
        assert_eq!(matched.route, Some(route));
        assert!(matched.pinned);
        assert!(runtime.should_connect_peer(&peer_record).await);
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_rejects_inconsistent_packet_flow_transport_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let app = router(AgentHttpState::new(runtime));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/packet-flow")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"destination":"100.64.0.11","protocol":"udp","tcp_state":"established"}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let error: ErrorResponse = serde_json::from_slice(&body)?;
        assert!(error
            .error
            .contains("packet-flow TCP state requires TCP protocol"));
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_filters_unusable_packet_flow_destinations(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let app = router(AgentHttpState::new(runtime.clone()));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/packet-flow")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"destination":"127.0.0.1","protocol":"tcp","destination_port":443}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let packet_flow: AgentPacketFlowResponse = serde_json::from_slice(&body)?;
        assert!(packet_flow.matched.is_none());
        assert_eq!(
            packet_flow.filtered_reason,
            Some(AgentPacketFlowDropReason::Loopback)
        );

        let metrics = runtime.metrics().await;
        assert_eq!(metrics.packet_flow_observation_count, 0);
        assert_eq!(metrics.packet_flow_match_count, 0);
        assert_eq!(metrics.packet_flow_unmatched_count, 0);
        assert_eq!(metrics.packet_flow_filtered_count, 1);
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| entry.reason == AgentPacketFlowDropReason::Loopback)
                .map(|entry| entry.count),
            Some(1)
        );
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| entry.reason == AgentPacketFlowDropReason::NoOverlayMatch)
                .map(|entry| entry.count),
            Some(0)
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_reports_no_overlay_packet_flow_matches(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let app = router(AgentHttpState::new(runtime.clone()));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/packet-flow")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"destination":"192.0.2.10","protocol":"tcp","destination_port":443}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let packet_flow: AgentPacketFlowResponse = serde_json::from_slice(&body)?;
        assert!(packet_flow.matched.is_none());
        assert_eq!(
            packet_flow.filtered_reason,
            Some(AgentPacketFlowDropReason::NoOverlayMatch)
        );

        let metrics = runtime.metrics().await;
        assert_eq!(metrics.packet_flow_observation_count, 1);
        assert_eq!(metrics.packet_flow_match_count, 0);
        assert_eq!(metrics.packet_flow_unmatched_count, 1);
        assert_eq!(metrics.packet_flow_filtered_count, 1);
        Ok(())
    }
}
