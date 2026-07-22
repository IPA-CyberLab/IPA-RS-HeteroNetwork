use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::{Extension, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{any, delete, get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
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
use ipars_types::{canonical_bootstrap_endpoint_url, BootstrapEndpointKind, NodeId, PathState};
use rand_core::{OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinSet;

const MAX_CONTROL_PLANE_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_AGENT_API_BEARER_TOKEN_BYTES: usize = 512;
const DEFAULT_CONTROL_PLANE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const WEB_UI_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_WEB_UI_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_WEB_UI_PROXY_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_NODE_INSTALL_PROXY_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;
const PUBLIC_WEB_GATEWAY_HEADER: &str = "x-heteronetwork-gateway-token";
const MAX_PENDING_DEVICE_LOGINS: usize = 256;
const MAX_DEVICE_AUTH_RESPONSE_BYTES: u64 = 256 * 1024;
const MIN_DEVICE_LOGIN_START_INTERVAL: Duration = Duration::from_millis(250);
const MAX_DEVICE_LOGIN_LIFETIME: Duration = Duration::from_secs(15 * 60);

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
    local_web_ui_enabled: bool,
    web_ui_selection: Arc<RwLock<Option<String>>>,
    web_ui_health: Arc<RwLock<BTreeMap<String, bool>>>,
    public_web_gateway: Option<PublicWebGatewayAccess>,
    device_logins: Arc<Mutex<DeviceLoginState>>,
}

#[derive(Debug, Default)]
struct DeviceLoginState {
    pending: BTreeMap<String, PendingDeviceLogin>,
    last_started_at: Option<Instant>,
}

#[derive(Debug)]
struct PendingDeviceLogin {
    device_code: String,
    code_verifier: String,
    token_endpoint: String,
    client_id: String,
    expires_at: Instant,
    next_poll_at: Instant,
    interval: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicWebGatewayPhase {
    Disabled,
    Standby,
    Provisioning,
    Ready,
    Error,
}

impl PublicWebGatewayPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Standby => "standby",
            Self::Provisioning => "provisioning",
            Self::Ready => "ready",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicWebGatewayStatus {
    pub phase: PublicWebGatewayPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl Default for PublicWebGatewayStatus {
    fn default() -> Self {
        Self {
            phase: PublicWebGatewayPhase::Disabled,
            public_ip: None,
            url: None,
            last_error: None,
            updated_at: chrono::Utc::now(),
        }
    }
}

#[derive(Clone)]
struct PublicWebGatewayAccess {
    token: Arc<str>,
    status: Arc<StdRwLock<PublicWebGatewayStatus>>,
}

#[derive(Debug, Clone, Copy)]
struct PublicWebGatewayRequest;

#[derive(Debug, Clone)]
struct OverlayWebUiAccess {
    origins: Arc<[String]>,
}

impl std::fmt::Debug for PublicWebGatewayAccess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublicWebGatewayAccess")
            .field("token", &"[REDACTED]")
            .field("status", &self.status)
            .finish()
    }
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
            local_web_ui_enabled: false,
            web_ui_selection: Arc::new(RwLock::new(None)),
            web_ui_health: Arc::new(RwLock::new(BTreeMap::new())),
            public_web_gateway: None,
            device_logins: Arc::new(Mutex::new(DeviceLoginState::default())),
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
            local_web_ui_enabled: false,
            web_ui_selection: Arc::new(RwLock::new(None)),
            web_ui_health: Arc::new(RwLock::new(BTreeMap::new())),
            public_web_gateway: None,
            device_logins: Arc::new(Mutex::new(DeviceLoginState::default())),
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
            local_web_ui_enabled: false,
            web_ui_selection: Arc::new(RwLock::new(None)),
            web_ui_health: Arc::new(RwLock::new(BTreeMap::new())),
            public_web_gateway: None,
            device_logins: Arc::new(Mutex::new(DeviceLoginState::default())),
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

    pub fn enable_local_web_ui(mut self, enabled: bool) -> Self {
        self.local_web_ui_enabled = enabled;
        self
    }

    pub fn with_public_web_gateway(
        mut self,
        token: String,
        status: Arc<StdRwLock<PublicWebGatewayStatus>>,
    ) -> Self {
        self.public_web_gateway = Some(PublicWebGatewayAccess {
            token: Arc::from(token),
            status,
        });
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
    let app = Router::new()
        .route("/healthz", get(healthz))
        .merge(protected);
    let app = if state.local_web_ui_enabled {
        let mut local_web = gateway_web_ui_routes()
            .route("/v1/web-ui/endpoints", delete(remove_web_ui_endpoint))
            .route("/v1/web-ui/bootstrap", post(bootstrap_web_ui_endpoint))
            .route("/v1/web-ui/select", post(select_web_ui_endpoint));
        local_web = if let Some(access) = state.public_web_gateway.clone() {
            local_web.route_layer(middleware::from_fn_with_state(
                access,
                require_web_ui_access,
            ))
        } else {
            local_web.route_layer(middleware::from_fn(require_loopback_web_ui_host))
        };
        app.merge(local_web)
    } else {
        app
    };
    app.with_state(state)
}

fn gateway_web_ui_routes() -> Router<AgentHttpState> {
    Router::new()
        .route("/", get(local_ui_root))
        .route("/ui", get(local_ui_index))
        .route("/ui/", get(local_ui_index))
        .route("/ui/app.js", get(local_ui_app))
        .route("/ui/theme.js", get(local_ui_theme))
        .route("/ui/styles.css", get(local_ui_styles))
        .route("/ui/fonts/noto-sans-jp-ui.ttf", get(local_ui_japanese_font))
        .route("/ui/config", get(local_ui_config))
        .route("/v1/web-ui/healthz", get(healthz))
        .route("/v1/web-ui/endpoints", get(web_ui_endpoints))
        .route("/v1/web-ui/auth/device", post(start_device_login))
        .route("/v1/web-ui/auth/device/poll", post(poll_device_login))
        .route("/v1/install/{*path}", get(proxy_management_request))
        .route("/v1/admin/{*path}", any(proxy_management_request))
        .route("/v1/clients/join", post(proxy_management_request))
        .route("/v1/clients/peers/query", post(proxy_management_request))
        .route("/v1/clients/{client_id}", delete(proxy_management_request))
}

pub fn overlay_web_ui_router(
    state: AgentHttpState,
    listen: std::net::SocketAddr,
    dns_name: &str,
) -> Router {
    let ip_origin = match listen.ip() {
        IpAddr::V4(ip) => format!("http://{ip}:{}", listen.port()),
        IpAddr::V6(ip) => format!("http://[{ip}]:{}", listen.port()),
    };
    let dns_origin = format!("http://{dns_name}:{}", listen.port());
    gateway_web_ui_routes()
        .route_layer(middleware::from_fn_with_state(
            OverlayWebUiAccess {
                origins: Arc::from([ip_origin, dns_origin]),
            },
            require_overlay_web_ui_access,
        ))
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

#[derive(Debug, Clone)]
struct WebUiCandidate {
    url: String,
    source: &'static str,
    trusted_directory: bool,
}

#[derive(Debug, Serialize)]
struct WebUiEndpointStatus {
    url: String,
    source: &'static str,
    trusted_directory: bool,
    reachable: bool,
    selected: bool,
    latency_ms: Option<u64>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct WebUiEndpointsResponse {
    selected_url: Option<String>,
    endpoints: Vec<WebUiEndpointStatus>,
    public_gateway: PublicWebGatewayStatus,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebUiEndpointRequest {
    endpoint: String,
}

#[derive(Debug, Serialize)]
struct DeviceLoginStartResponse {
    handle: String,
    user_code: String,
    verification_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceLoginPollRequest {
    handle: String,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorizationProviderResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default = "default_device_login_interval")]
    interval: u64,
}

fn default_device_login_interval() -> u64 {
    5
}

fn random_device_login_handle() -> String {
    let mut bytes = [0_u8; 24];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn device_login_pkce() -> (String, String) {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn web_ui_config_string(config: &Value, key: &str) -> Result<String, ApiError> {
    config
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= 4096 && !value.contains(char::is_control)
        })
        .map(str::to_string)
        .ok_or_else(|| ApiError::BadRequest(format!("Web UI configuration does not provide {key}")))
}

async fn start_device_login(
    State(state): State<AgentHttpState>,
    public_gateway: Option<Extension<PublicWebGatewayRequest>>,
) -> Result<Response, ApiError> {
    let (_, config) = select_healthy_web_ui_with_scope(&state, public_gateway.is_some()).await?;
    if config.get("provider").and_then(Value::as_str) != Some("keycloak") {
        return Err(ApiError::BadRequest(
            "device login requires the Keycloak provider".to_string(),
        ));
    }
    let device_endpoint = web_ui_config_string(&config, "device_authorization_endpoint")?;
    let token_endpoint = web_ui_config_string(&config, "token_endpoint")?;
    let client_id = web_ui_config_string(&config, "client_id")?;
    let scopes = web_ui_config_string(&config, "scopes")?;
    let device_url = reqwest::Url::parse(&device_endpoint).map_err(|_| {
        ApiError::BadRequest("device authorization endpoint is invalid".to_string())
    })?;
    let token_url = reqwest::Url::parse(&token_endpoint)
        .map_err(|_| ApiError::BadRequest("OIDC token endpoint is invalid".to_string()))?;
    if !matches!(device_url.scheme(), "http" | "https")
        || device_url.origin() != token_url.origin()
        || device_url.username() != ""
        || device_url.password().is_some()
        || token_url.username() != ""
        || token_url.password().is_some()
    {
        return Err(ApiError::BadRequest(
            "device authorization and token endpoints must be HTTP(S) endpoints on the same origin"
                .to_string(),
        ));
    }
    let now = Instant::now();
    {
        let mut logins = state.device_logins.lock().await;
        logins.pending.retain(|_, pending| pending.expires_at > now);
        if logins
            .last_started_at
            .is_some_and(|last| now.duration_since(last) < MIN_DEVICE_LOGIN_START_INTERVAL)
        {
            return Ok((
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "device login was started too quickly"})),
            )
                .into_response());
        }
        if logins.pending.len() >= MAX_PENDING_DEVICE_LOGINS {
            return Ok((
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "too many device logins are pending"})),
            )
                .into_response());
        }
        logins.last_started_at = Some(now);
    }

    let (code_verifier, code_challenge) = device_login_pkce();
    let response = state
        .control_plane_client
        .post(device_url.clone())
        .header(header::ACCEPT, "application/json")
        .form(&[
            ("client_id", client_id.as_str()),
            ("scope", scopes.as_str()),
            ("code_challenge", code_challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .timeout(state.control_plane_request_timeout)
        .send()
        .await
        .map_err(|error| {
            AgentError::ControlPlaneClient(format!(
                "Keycloak device authorization request failed: {error}"
            ))
        })?;
    if !response.status().is_success() {
        return Err(AgentError::ControlPlaneClient(format!(
            "Keycloak device authorization request returned HTTP {}",
            response.status()
        ))
        .into());
    }
    let provider: DeviceAuthorizationProviderResponse = read_bounded_json_response(
        response,
        MAX_DEVICE_AUTH_RESPONSE_BYTES,
        "Keycloak device authorization",
    )
    .await?;
    if provider.device_code.is_empty()
        || provider.device_code.len() > 16 * 1024
        || provider.user_code.is_empty()
        || provider.user_code.len() > 256
        || provider.expires_in < 30
        || provider.expires_in > MAX_DEVICE_LOGIN_LIFETIME.as_secs()
        || provider.interval == 0
        || provider.interval > 30
    {
        return Err(AgentError::ControlPlaneClient(
            "Keycloak returned invalid device authorization parameters".to_string(),
        )
        .into());
    }
    for verification_url in std::iter::once(provider.verification_uri.as_str())
        .chain(provider.verification_uri_complete.as_deref())
    {
        let parsed = reqwest::Url::parse(verification_url).map_err(|_| {
            AgentError::ControlPlaneClient(
                "Keycloak returned an invalid device verification URL".to_string(),
            )
        })?;
        if parsed.origin() != device_url.origin() || parsed.scheme() != device_url.scheme() {
            return Err(AgentError::ControlPlaneClient(
                "Keycloak returned a device verification URL on an unexpected origin".to_string(),
            )
            .into());
        }
    }
    let handle = random_device_login_handle();
    let interval = Duration::from_secs(provider.interval);
    let pending = PendingDeviceLogin {
        device_code: provider.device_code,
        code_verifier,
        token_endpoint,
        client_id,
        expires_at: now + Duration::from_secs(provider.expires_in),
        next_poll_at: now + interval,
        interval,
    };
    state
        .device_logins
        .lock()
        .await
        .pending
        .insert(handle.clone(), pending);
    Ok(Json(DeviceLoginStartResponse {
        handle,
        user_code: provider.user_code,
        verification_uri: provider.verification_uri,
        verification_uri_complete: provider.verification_uri_complete,
        expires_in: provider.expires_in,
        interval: provider.interval,
    })
    .into_response())
}

async fn poll_device_login(
    State(state): State<AgentHttpState>,
    Json(request): Json<DeviceLoginPollRequest>,
) -> Result<Response, ApiError> {
    if request.handle.is_empty()
        || request.handle.len() > 128
        || request.handle.contains(char::is_whitespace)
    {
        return Err(ApiError::BadRequest(
            "device login handle is invalid".to_string(),
        ));
    }
    let now = Instant::now();
    let mut pending = {
        let mut logins = state.device_logins.lock().await;
        logins.pending.retain(|_, pending| pending.expires_at > now);
        let Some(pending) = logins.pending.remove(&request.handle) else {
            return Ok((
                StatusCode::GONE,
                Json(json!({"error": "device login expired or was not found"})),
            )
                .into_response());
        };
        pending
    };
    if now < pending.next_poll_at {
        let retry_after = pending.next_poll_at.duration_since(now).as_secs().max(1);
        state
            .device_logins
            .lock()
            .await
            .pending
            .insert(request.handle, pending);
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"status": "pending", "retry_after_seconds": retry_after})),
        )
            .into_response());
    }
    let response = match state
        .control_plane_client
        .post(&pending.token_endpoint)
        .header(header::ACCEPT, "application/json")
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", pending.client_id.as_str()),
            ("device_code", pending.device_code.as_str()),
            ("code_verifier", pending.code_verifier.as_str()),
        ])
        .timeout(state.control_plane_request_timeout)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            pending.next_poll_at = Instant::now() + pending.interval;
            state
                .device_logins
                .lock()
                .await
                .pending
                .insert(request.handle, pending);
            return Err(AgentError::ControlPlaneClient(format!(
                "Keycloak device token request failed: {error}"
            ))
            .into());
        }
    };
    let status = response.status();
    let body: Value = read_bounded_json_response(
        response,
        MAX_DEVICE_AUTH_RESPONSE_BYTES,
        "Keycloak device token",
    )
    .await?;
    if status.is_success() {
        let access_token = body
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty() && token.len() <= 16 * 1024)
            .ok_or_else(|| {
                AgentError::ControlPlaneClient(
                    "Keycloak device token response omitted the access token".to_string(),
                )
            })?;
        return Ok(
            Json(json!({"status": "complete", "access_token": access_token})).into_response(),
        );
    }
    let error = body
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if matches!(error, "authorization_pending" | "slow_down") {
        if error == "slow_down" {
            pending.interval = pending.interval.saturating_add(Duration::from_secs(5));
        }
        let retry_after = pending.interval.as_secs().max(1);
        pending.next_poll_at = Instant::now() + pending.interval;
        if pending.expires_at > pending.next_poll_at {
            state
                .device_logins
                .lock()
                .await
                .pending
                .insert(request.handle, pending);
        }
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({"status": "pending", "retry_after_seconds": retry_after})),
        )
            .into_response());
    }
    let response_status = if matches!(error, "access_denied" | "expired_token") {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::BAD_GATEWAY
    };
    Ok((
        response_status,
        Json(json!({"error": "Keycloak device authorization was rejected"})),
    )
        .into_response())
}

async fn require_loopback_web_ui_host(request: Request, next: Next) -> Response {
    let Some(host) = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return local_web_ui_rejection("Host header is required");
    };
    let Ok(host_url) = reqwest::Url::parse(&format!("http://{host}")) else {
        return local_web_ui_rejection("Host header is invalid");
    };
    if !url_host_is_loopback(&host_url) {
        return local_web_ui_rejection("local Web UI only accepts loopback hosts");
    }
    if request
        .headers()
        .get(HeaderName::from_static("sec-fetch-site"))
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("cross-site"))
    {
        return local_web_ui_rejection("cross-site local Web UI requests are rejected");
    }
    if let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        let Ok(origin_url) = reqwest::Url::parse(origin) else {
            return local_web_ui_rejection("Origin header is invalid");
        };
        if origin_url.origin() != host_url.origin() {
            return local_web_ui_rejection("cross-origin local Web UI requests are rejected");
        }
    }
    next.run(request).await
}

async fn require_web_ui_access(
    State(access): State<PublicWebGatewayAccess>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(host) = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return local_web_ui_rejection("Host header is required");
    };
    let Ok(http_host_url) = reqwest::Url::parse(&format!("http://{host}")) else {
        return local_web_ui_rejection("Host header is invalid");
    };
    if url_host_is_loopback(&http_host_url) {
        return require_loopback_web_ui_host(request, next).await;
    }

    let token_header = HeaderName::from_static(PUBLIC_WEB_GATEWAY_HEADER);
    let provided = request
        .headers()
        .get(&token_header)
        .and_then(|value| value.to_str().ok());
    if !provided.is_some_and(|provided| agent_api_token_matches(&access.token, provided)) {
        return local_web_ui_rejection("public Web UI gateway authentication was rejected");
    }
    let gateway = access
        .status
        .read()
        .map(|status| status.clone())
        .unwrap_or_default();
    let Some(expected_url) = gateway.url.as_deref() else {
        return local_web_ui_rejection("public Web UI gateway is not active");
    };
    let Ok(expected) = reqwest::Url::parse(expected_url) else {
        return local_web_ui_rejection("public Web UI gateway state is invalid");
    };
    let Ok(actual) = reqwest::Url::parse(&format!("https://{host}/")) else {
        return local_web_ui_rejection("public Web UI Host header is invalid");
    };
    if actual.origin() != expected.origin() {
        return local_web_ui_rejection(
            "public Web UI Host header does not match the active gateway",
        );
    }
    if request
        .headers()
        .get(HeaderName::from_static("sec-fetch-site"))
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("cross-site"))
    {
        return local_web_ui_rejection("cross-site public Web UI requests are rejected");
    }
    if let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        let Ok(origin_url) = reqwest::Url::parse(origin) else {
            return local_web_ui_rejection("Origin header is invalid");
        };
        if origin_url.origin() != expected.origin() {
            return local_web_ui_rejection("cross-origin public Web UI requests are rejected");
        }
    }
    let path = request.uri().path();
    let public_route_allowed = match (request.method(), path) {
        (&Method::GET, "/" | "/ui" | "/ui/") => true,
        (&Method::GET, path) if path.starts_with("/ui/") => true,
        (&Method::GET, "/v1/web-ui/endpoints") => true,
        (&Method::POST, "/v1/web-ui/auth/device") => true,
        (&Method::POST, "/v1/web-ui/auth/device/poll") => true,
        (&Method::GET, path) if path.starts_with("/v1/install/") => true,
        (_, path) if path.starts_with("/v1/admin/") => true,
        (&Method::POST, "/v1/clients/join" | "/v1/clients/peers/query") => true,
        (&Method::DELETE, path) if path.starts_with("/v1/clients/") => true,
        _ => false,
    };
    if !public_route_allowed {
        return local_web_ui_rejection("route is only available from the local Agent Web UI");
    }
    request.headers_mut().remove(token_header);
    request.extensions_mut().insert(PublicWebGatewayRequest);
    next.run(request).await
}

async fn require_overlay_web_ui_access(
    State(access): State<OverlayWebUiAccess>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(host) = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return local_web_ui_rejection("Host header is required");
    };
    let Ok(actual) = reqwest::Url::parse(&format!("http://{host}/")) else {
        return local_web_ui_rejection("overlay Web UI Host header is invalid");
    };
    let actual_origin = actual.origin().ascii_serialization();
    if !access.origins.iter().any(|origin| origin == &actual_origin) {
        return local_web_ui_rejection("overlay Web UI Host header was rejected");
    }
    if request
        .headers()
        .get(HeaderName::from_static("sec-fetch-site"))
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("cross-site"))
    {
        return local_web_ui_rejection("cross-site overlay Web UI requests are rejected");
    }
    if let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        let Ok(origin_url) = reqwest::Url::parse(origin) else {
            return local_web_ui_rejection("Origin header is invalid");
        };
        if origin_url.origin().ascii_serialization() != actual_origin {
            return local_web_ui_rejection("cross-origin overlay Web UI requests are rejected");
        }
    }
    request.extensions_mut().insert(PublicWebGatewayRequest);
    next.run(request).await
}

fn local_web_ui_rejection(message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: message.to_string(),
        }),
    )
        .into_response()
}

fn url_host_is_loopback(url: &reqwest::Url) -> bool {
    match url.host_str() {
        Some(host) if host.eq_ignore_ascii_case("localhost") => true,
        Some(host) => parse_url_ip_addr(host).is_some_and(|ip| ip.is_loopback()),
        None => false,
    }
}

fn parse_url_ip_addr(host: &str) -> Option<IpAddr> {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()
}

fn web_ui_candidates(state: &AgentHttpState) -> Vec<WebUiCandidate> {
    let runtime_state = state.runtime.state();
    let own_public_gateway_url = state
        .public_web_gateway
        .as_ref()
        .and_then(|access| access.status.read().ok()?.url.clone())
        .and_then(|url| normalize_web_ui_base_url(&url).ok());
    let mut candidates = Vec::new();
    for endpoint in runtime_state
        .bootstrap_endpoints
        .iter()
        .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::WebUi)
    {
        candidates.push(WebUiCandidate {
            url: endpoint.url.clone(),
            source: "service_directory",
            trusted_directory: true,
        });
    }
    for url in &runtime_state.web_ui_seed_urls {
        candidates.push(WebUiCandidate {
            url: url.clone(),
            source: "manual_seed",
            trusted_directory: false,
        });
    }
    for endpoint in runtime_state
        .bootstrap_endpoints
        .iter()
        .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
    {
        candidates.push(WebUiCandidate {
            url: endpoint.url.clone(),
            source: "control_plane_directory",
            trusted_directory: true,
        });
    }
    for url in &state.control_plane_urls {
        candidates.push(WebUiCandidate {
            url: url.clone(),
            source: "control_plane_runtime",
            trusted_directory: true,
        });
    }

    let mut seen = BTreeSet::new();
    candidates
        .into_iter()
        .filter_map(|mut candidate| {
            candidate.url = normalize_web_ui_base_url(&candidate.url).ok()?;
            if own_public_gateway_url.as_deref() == Some(candidate.url.as_str()) {
                return None;
            }
            seen.insert(candidate.url.clone()).then_some(candidate)
        })
        .collect()
}

fn normalize_web_ui_base_url(input: &str) -> Result<String, String> {
    let input = input.trim();
    if input.is_empty() || input.len() > 2048 || input.chars().any(char::is_control) {
        return Err("endpoint must be a non-empty URL of at most 2048 bytes".to_string());
    }
    let absolute = if input.contains("://") {
        input.to_string()
    } else {
        let probe = reqwest::Url::parse(&format!("http://{input}"))
            .map_err(|_| "endpoint is not a valid IP address or URL".to_string())?;
        let scheme = if url_host_allows_plain_http(&probe) {
            "http"
        } else {
            "https"
        };
        format!("{scheme}://{input}")
    };
    let mut parsed = reqwest::Url::parse(&absolute)
        .map_err(|_| "endpoint is not a valid absolute URL".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || parsed.port() == Some(0)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(
            "endpoint must be an HTTP(S) origin without userinfo, query, or fragment".to_string(),
        );
    }
    if !url_host_is_usable(&parsed) {
        return Err("endpoint uses an unusable IP address or port".to_string());
    }
    if parsed.scheme() == "http" && !url_host_allows_plain_http(&parsed) {
        return Err(
            "plain HTTP is only allowed for loopback, private, link-local, or CGNAT addresses"
                .to_string(),
        );
    }
    if !matches!(parsed.path(), "" | "/" | "/ui" | "/ui/") {
        return Err("endpoint path must be / or /ui/".to_string());
    }
    parsed.set_path("");
    canonical_bootstrap_endpoint_url(parsed.as_str())
        .ok_or_else(|| "endpoint is not a valid absolute URL".to_string())
}

fn url_host_allows_plain_http(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let Some(ip) = parse_url_ip_addr(host) else {
        return false;
    };
    match ip {
        IpAddr::V4(ip) => ipv4_allows_plain_http(ip),
        IpAddr::V6(ip) => ipv6_allows_plain_http(ip),
    }
}

fn url_host_is_usable(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let Some(ip) = parse_url_ip_addr(host) else {
        return true;
    };
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified() && !ip.is_multicast() && ip != Ipv4Addr::new(255, 255, 255, 255)
        }
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

fn ipv4_allows_plain_http(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
}

fn ipv6_allows_plain_http(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_loopback() || (segments[0] & 0xfe00) == 0xfc00 || (segments[0] & 0xffc0) == 0xfe80
}

async fn fetch_web_ui_config(
    client: &reqwest::Client,
    candidate: &WebUiCandidate,
    expected_cluster_id: Option<&str>,
) -> Result<Value, String> {
    let response = client
        .get(format!("{}/ui/config", candidate.url))
        .header(header::ACCEPT, "application/json")
        .timeout(WEB_UI_PROBE_TIMEOUT)
        .send()
        .await
        .map_err(|error| format!("connection failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("UI config returned HTTP {}", response.status()));
    }
    let config = read_bounded_json_response::<Value>(
        response,
        MAX_WEB_UI_CONFIG_BYTES,
        "web UI configuration",
    )
    .await
    .map_err(|error| error.to_string())?;
    if !config.is_object() || config.get("enabled").and_then(Value::as_bool) == Some(false) {
        return Err("endpoint does not expose an enabled HeteroNetwork Web UI".to_string());
    }
    if let Some(expected_cluster_id) = expected_cluster_id {
        match config.get("cluster_id").and_then(Value::as_str) {
            Some(cluster_id) if cluster_id == expected_cluster_id => {}
            Some(_) => {
                return Err("endpoint belongs to a different HeteroNetwork cluster".to_string())
            }
            None if !candidate.trusted_directory => {
                return Err(
                    "manual endpoint does not report its HeteroNetwork cluster ID".to_string(),
                )
            }
            None => {}
        }
    }
    Ok(config)
}

fn expected_web_ui_cluster_id(state: &AgentHttpState) -> Option<String> {
    state
        .runtime
        .state()
        .registered_node
        .map(|node| node.cluster_id.as_str().to_string())
}

async fn set_selected_web_ui(state: &AgentHttpState, url: Option<String>) {
    *state.web_ui_selection.write().await = url;
}

async fn record_web_ui_health(state: &AgentHttpState, url: String, reachable: bool) {
    state.web_ui_health.write().await.insert(url, reachable);
}

async fn selected_web_ui_url(state: &AgentHttpState) -> Option<String> {
    state.web_ui_selection.read().await.clone()
}

async fn select_healthy_web_ui(
    state: &AgentHttpState,
) -> Result<(WebUiCandidate, Value), AgentError> {
    select_healthy_web_ui_with_scope(state, false).await
}

async fn select_healthy_web_ui_with_scope(
    state: &AgentHttpState,
    control_plane_only: bool,
) -> Result<(WebUiCandidate, Value), AgentError> {
    let candidates = web_ui_candidates(state)
        .into_iter()
        .filter(|candidate| !control_plane_only || candidate.source.starts_with("control_plane_"))
        .collect::<Vec<_>>();
    let expected_cluster_id = expected_web_ui_cluster_id(state);
    if candidates.is_empty() {
        return Err(AgentError::ControlPlaneClient(
            "no Web UI endpoint is cached; enter an initial IP address or URL".to_string(),
        ));
    }
    let selected = selected_web_ui_url(state).await;
    if let Some(candidate) = selected.as_deref().and_then(|selected| {
        candidates
            .iter()
            .find(|candidate| candidate.url == selected)
    }) {
        if let Ok(config) = fetch_web_ui_config(
            &state.control_plane_client,
            candidate,
            expected_cluster_id.as_deref(),
        )
        .await
        {
            record_web_ui_health(state, candidate.url.clone(), true).await;
            set_selected_web_ui(state, Some(candidate.url.clone())).await;
            return Ok((candidate.clone(), config));
        }
    }

    let mut probes = JoinSet::new();
    for candidate in candidates
        .into_iter()
        .filter(|candidate| Some(candidate.url.as_str()) != selected.as_deref())
    {
        let client = state.control_plane_client.clone();
        let expected_cluster_id = expected_cluster_id.clone();
        probes.spawn(async move {
            let result =
                fetch_web_ui_config(&client, &candidate, expected_cluster_id.as_deref()).await;
            (candidate, result)
        });
    }
    let mut failures = Vec::new();
    while let Some(result) = probes.join_next().await {
        match result {
            Ok((candidate, Ok(config))) => {
                probes.abort_all();
                record_web_ui_health(state, candidate.url.clone(), true).await;
                set_selected_web_ui(state, Some(candidate.url.clone())).await;
                return Ok((candidate, config));
            }
            Ok((candidate, Err(error))) => {
                record_web_ui_health(state, candidate.url.clone(), false).await;
                failures.push(format!("{}: {}", candidate.url, truncate_error(&error)))
            }
            Err(error) => failures.push(format!("probe task failed: {error}")),
        }
    }
    set_selected_web_ui(state, None).await;
    Err(AgentError::ControlPlaneClient(format!(
        "no cached Web UI endpoint is reachable: {}",
        failures.join("; ")
    )))
}

fn truncate_error(error: &str) -> String {
    error.chars().take(240).collect()
}

async fn probe_web_ui_endpoints(state: &AgentHttpState) -> WebUiEndpointsResponse {
    let candidates = web_ui_candidates(state);
    let expected_cluster_id = expected_web_ui_cluster_id(state);
    let previous_selected = selected_web_ui_url(state).await;
    let mut probes = JoinSet::new();
    for (index, candidate) in candidates.iter().cloned().enumerate() {
        let client = state.control_plane_client.clone();
        let expected_cluster_id = expected_cluster_id.clone();
        probes.spawn(async move {
            let started_at = Instant::now();
            let result =
                fetch_web_ui_config(&client, &candidate, expected_cluster_id.as_deref()).await;
            (index, candidate, started_at.elapsed(), result)
        });
    }
    let mut results = BTreeMap::new();
    while let Some(result) = probes.join_next().await {
        if let Ok((index, candidate, elapsed, probe)) = result {
            results.insert(index, (candidate, elapsed, probe));
        }
    }
    let selected = previous_selected
        .filter(|selected| {
            results
                .values()
                .any(|(candidate, _, result)| candidate.url == *selected && result.is_ok())
        })
        .or_else(|| {
            results
                .values()
                .find(|(_, _, result)| result.is_ok())
                .map(|(candidate, _, _)| candidate.url.clone())
        });
    *state.web_ui_health.write().await = results
        .values()
        .map(|(candidate, _, result)| (candidate.url.clone(), result.is_ok()))
        .collect();
    set_selected_web_ui(state, selected.clone()).await;
    let endpoints = results
        .into_values()
        .map(|(candidate, elapsed, result)| WebUiEndpointStatus {
            selected: selected.as_deref() == Some(candidate.url.as_str()),
            url: candidate.url,
            source: candidate.source,
            trusted_directory: candidate.trusted_directory,
            reachable: result.is_ok(),
            latency_ms: result
                .is_ok()
                .then_some(elapsed.as_millis().min(u128::from(u64::MAX)) as u64),
            error: result.err().map(|error| truncate_error(&error)),
        })
        .collect();
    WebUiEndpointsResponse {
        selected_url: selected,
        endpoints,
        public_gateway: match &state.public_web_gateway {
            Some(access) => access
                .status
                .read()
                .map(|status| status.clone())
                .unwrap_or_default(),
            None => PublicWebGatewayStatus::default(),
        },
    }
}

async fn web_ui_endpoints(State(state): State<AgentHttpState>) -> Json<WebUiEndpointsResponse> {
    Json(probe_web_ui_endpoints(&state).await)
}

async fn bootstrap_web_ui_endpoint(
    State(state): State<AgentHttpState>,
    Json(request): Json<WebUiEndpointRequest>,
) -> Result<Json<WebUiEndpointsResponse>, ApiError> {
    let endpoint = normalize_web_ui_base_url(&request.endpoint).map_err(ApiError::BadRequest)?;
    let candidate = WebUiCandidate {
        url: endpoint.clone(),
        source: "manual_seed",
        trusted_directory: false,
    };
    let expected_cluster_id = expected_web_ui_cluster_id(&state);
    fetch_web_ui_config(
        &state.control_plane_client,
        &candidate,
        expected_cluster_id.as_deref(),
    )
    .await
    .map_err(|error| ApiError::BadRequest(format!("Web UI endpoint validation failed: {error}")))?;
    let store = state.state_store.clone().ok_or_else(|| {
        AgentError::ControlPlaneClient(
            "agent state store is required to persist Web UI endpoints".to_string(),
        )
    })?;
    if let Some(next_state) = state
        .runtime
        .upsert_web_ui_seed_url(endpoint.clone(), chrono::Utc::now())?
    {
        store.save(&next_state)?;
    }
    set_selected_web_ui(&state, Some(endpoint)).await;
    Ok(Json(probe_web_ui_endpoints(&state).await))
}

async fn remove_web_ui_endpoint(
    State(state): State<AgentHttpState>,
    Json(request): Json<WebUiEndpointRequest>,
) -> Result<Json<WebUiEndpointsResponse>, ApiError> {
    let endpoint = normalize_web_ui_base_url(&request.endpoint).map_err(ApiError::BadRequest)?;
    let store = state.state_store.clone().ok_or_else(|| {
        AgentError::ControlPlaneClient(
            "agent state store is required to persist Web UI endpoints".to_string(),
        )
    })?;
    let Some(next_state) = state
        .runtime
        .remove_web_ui_seed_url(&endpoint, chrono::Utc::now())?
    else {
        return Err(ApiError::BadRequest(
            "endpoint is not a removable manual Web UI seed".to_string(),
        ));
    };
    store.save(&next_state)?;
    if selected_web_ui_url(&state).await.as_deref() == Some(endpoint.as_str()) {
        set_selected_web_ui(&state, None).await;
    }
    Ok(Json(probe_web_ui_endpoints(&state).await))
}

async fn select_web_ui_endpoint(
    State(state): State<AgentHttpState>,
    Json(request): Json<WebUiEndpointRequest>,
) -> Result<Json<WebUiEndpointsResponse>, ApiError> {
    let endpoint = normalize_web_ui_base_url(&request.endpoint).map_err(ApiError::BadRequest)?;
    let candidate = web_ui_candidates(&state)
        .into_iter()
        .find(|candidate| candidate.url == endpoint)
        .ok_or_else(|| {
            ApiError::BadRequest("endpoint is not in the cached directory".to_string())
        })?;
    let expected_cluster_id = expected_web_ui_cluster_id(&state);
    fetch_web_ui_config(
        &state.control_plane_client,
        &candidate,
        expected_cluster_id.as_deref(),
    )
    .await
    .map_err(|error| ApiError::BadRequest(format!("Web UI endpoint is unreachable: {error}")))?;
    set_selected_web_ui(&state, Some(endpoint)).await;
    Ok(Json(probe_web_ui_endpoints(&state).await))
}

async fn local_ui_root() -> Redirect {
    Redirect::temporary("/ui/")
}

async fn local_ui_index(State(state): State<AgentHttpState>) -> Response {
    let oidc_origin = match select_healthy_web_ui(&state).await {
        Ok((_, config)) => config
            .get("token_endpoint")
            .and_then(Value::as_str)
            .and_then(http_origin),
        Err(_) => None,
    };
    let mut response = (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../../../webui/index.html"),
    )
        .into_response();
    apply_local_ui_security_headers(&mut response, true, oidc_origin.as_deref());
    response
}

async fn local_ui_app() -> Response {
    let mut response = (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../../webui/app.js"),
    )
        .into_response();
    apply_local_ui_security_headers(&mut response, false, None);
    response
}

async fn local_ui_theme() -> Response {
    let mut response = (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../../webui/theme.js"),
    )
        .into_response();
    apply_local_ui_security_headers(&mut response, false, None);
    response
}

async fn local_ui_styles() -> Response {
    let mut response = (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../../webui/styles.css"),
    )
        .into_response();
    apply_local_ui_security_headers(&mut response, false, None);
    response
}

async fn local_ui_japanese_font() -> Response {
    let mut response = (
        [(header::CONTENT_TYPE, "font/ttf")],
        include_bytes!("../../../webui/noto-sans-jp-ui.ttf").as_slice(),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response
}

fn http_origin(value: &str) -> Option<String> {
    let url = reqwest::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

fn apply_local_ui_security_headers(
    response: &mut Response,
    include_policy: bool,
    oidc_origin: Option<&str>,
) {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    if include_policy {
        let connect_src = oidc_origin
            .map(|origin| format!("'self' {origin}"))
            .unwrap_or_else(|| "'self'".to_string());
        let policy = format!(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src {connect_src}; font-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        );
        if let Ok(value) = HeaderValue::from_str(&policy) {
            headers.insert(HeaderName::from_static("content-security-policy"), value);
        }
    }
}

async fn local_ui_config(
    State(state): State<AgentHttpState>,
    public_gateway: Option<Extension<PublicWebGatewayRequest>>,
) -> Json<Value> {
    match select_healthy_web_ui_with_scope(&state, public_gateway.is_some()).await {
        Ok((candidate, mut config)) => {
            if let Some(config) = config.as_object_mut() {
                config.insert("login_endpoint".to_string(), Value::Null);
                if config
                    .get("device_authorization_endpoint")
                    .is_some_and(|endpoint| endpoint.is_string())
                {
                    config.insert(
                        "device_login_endpoint".to_string(),
                        Value::String("/v1/web-ui/auth/device".to_string()),
                    );
                    config.insert(
                        "device_login_poll_endpoint".to_string(),
                        Value::String("/v1/web-ui/auth/device/poll".to_string()),
                    );
                }
                config.insert("local_agent".to_string(), Value::Bool(true));
                config.insert("bootstrap_required".to_string(), Value::Bool(false));
                config.insert(
                    "selected_web_ui_endpoint".to_string(),
                    Value::String(candidate.url),
                );
                config.insert(
                    "cached_web_ui_endpoint_count".to_string(),
                    json!(web_ui_candidates(&state).len()),
                );
            }
            Json(config)
        }
        Err(error) => Json(json!({
            "enabled": true,
            "auth_enabled": false,
            "operator_token_enabled": false,
            "provider": null,
            "issuer_url": null,
            "client_id": null,
            "scopes": null,
            "authorization_endpoint": null,
            "device_authorization_endpoint": null,
            "device_login_endpoint": null,
            "device_login_poll_endpoint": null,
            "token_endpoint": null,
            "logout_endpoint": null,
            "login_endpoint": null,
            "node_enrollment_enabled": false,
            "client_enrollment_enabled": false,
            "local_agent": true,
            "bootstrap_required": true,
            "selected_web_ui_endpoint": null,
            "cached_web_ui_endpoint_count": web_ui_candidates(&state).len(),
            "connection_error": truncate_error(&error.to_string())
        })),
    }
}

#[derive(Debug)]
struct ManagementProxyRequest {
    method: Method,
    path_and_query: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

async fn proxy_management_request(
    State(state): State<AgentHttpState>,
    request: Request,
) -> Response {
    let public_gateway = request
        .extensions()
        .get::<PublicWebGatewayRequest>()
        .is_some();
    let proxy_request = match management_proxy_request(request).await {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let mut candidates = web_ui_candidates(&state)
        .into_iter()
        .filter(|candidate| !public_gateway || candidate.source.starts_with("control_plane_"))
        .collect::<Vec<_>>();
    let selected = selected_web_ui_url(&state).await;
    candidates.sort_by_key(|candidate| {
        if selected.as_deref() == Some(candidate.url.as_str()) {
            0
        } else {
            1
        }
    });
    if candidates.is_empty() {
        return ApiError::Agent(AgentError::ControlPlaneClient(
            "no Web UI endpoint is cached; enter an initial IP address or URL".to_string(),
        ))
        .into_response();
    }

    if matches!(proxy_request.method, Method::GET | Method::HEAD) {
        let mut failures = Vec::new();
        for candidate in candidates {
            match forward_management_request(&state, &candidate, &proxy_request).await {
                Ok(response) if proxy_status_is_retryable(response.status()) => {
                    record_web_ui_health(&state, candidate.url.clone(), false).await;
                    failures.push(format!("{} returned {}", candidate.url, response.status()));
                }
                Ok(response) => {
                    record_web_ui_health(&state, candidate.url.clone(), true).await;
                    set_selected_web_ui(&state, Some(candidate.url)).await;
                    return response;
                }
                Err(error) => {
                    record_web_ui_health(&state, candidate.url.clone(), false).await;
                    failures.push(format!(
                        "{}: {}",
                        candidate.url,
                        truncate_error(&error.to_string())
                    ));
                }
            }
        }
        set_selected_web_ui(&state, None).await;
        return ApiError::Agent(AgentError::ControlPlaneClient(format!(
            "all cached Web UI endpoints failed: {}",
            failures.join("; ")
        )))
        .into_response();
    }

    let candidate = match select_healthy_web_ui_with_scope(&state, public_gateway).await {
        Ok((candidate, _)) => candidate,
        Err(error) => return ApiError::Agent(error).into_response(),
    };
    match forward_management_request(&state, &candidate, &proxy_request).await {
        Ok(response) => {
            record_web_ui_health(&state, candidate.url, true).await;
            response
        }
        Err(error) => {
            record_web_ui_health(&state, candidate.url, false).await;
            ApiError::Agent(error).into_response()
        }
    }
}

async fn management_proxy_request(request: Request) -> Result<ManagementProxyRequest, ApiError> {
    let method = request.method().clone();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());
    let headers = request.headers().clone();
    let body = to_bytes(request.into_body(), MAX_WEB_UI_PROXY_REQUEST_BYTES)
        .await
        .map_err(|_| ApiError::BadRequest("management request body is too large".to_string()))?;
    Ok(ManagementProxyRequest {
        method,
        path_and_query,
        headers,
        body: body.to_vec(),
    })
}

async fn forward_management_request(
    state: &AgentHttpState,
    candidate: &WebUiCandidate,
    request: &ManagementProxyRequest,
) -> Result<Response, AgentError> {
    let url = format!("{}{}", candidate.url, request.path_and_query);
    let mut builder = state
        .control_plane_client
        .request(request.method.clone(), &url)
        .timeout(state.control_plane_request_timeout)
        .body(request.body.clone());
    for name in [
        header::ACCEPT,
        header::AUTHORIZATION,
        header::CONTENT_TYPE,
        header::IF_MATCH,
        header::IF_NONE_MATCH,
    ] {
        if let Some(value) = request.headers.get(&name) {
            builder = builder.header(name, value);
        }
    }
    let response = builder.send().await.map_err(|error| {
        AgentError::ControlPlaneClient(format!("management proxy request failed: {error}"))
    })?;
    let status = response.status();
    let response_headers = response.headers().clone();
    let response_limit = if request.path_and_query.starts_with("/v1/install/") {
        MAX_NODE_INSTALL_PROXY_RESPONSE_BYTES
    } else {
        MAX_CONTROL_PLANE_RESPONSE_BYTES
    };
    let body = read_bounded_response_bytes(response, response_limit, "management proxy").await?;
    let mut proxied = Response::new(Body::from(body));
    *proxied.status_mut() = status;
    for name in [
        header::CACHE_CONTROL,
        header::CONTENT_DISPOSITION,
        header::CONTENT_LENGTH,
        header::CONTENT_TYPE,
        header::ETAG,
        header::LAST_MODIFIED,
        header::RETRY_AFTER,
        header::WWW_AUTHENTICATE,
    ] {
        if let Some(value) = response_headers.get(&name) {
            proxied.headers_mut().insert(name, value.clone());
        }
    }
    if let Some(value) = response_headers.get("x-heteronetwork-sha256") {
        proxied.headers_mut().insert(
            HeaderName::from_static("x-heteronetwork-sha256"),
            value.clone(),
        );
    }
    proxied.headers_mut().insert(
        HeaderName::from_static("x-heteronetwork-web-ui-endpoint"),
        HeaderValue::from_str(&candidate.url)
            .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
    );
    Ok(proxied)
}

async fn read_bounded_response_bytes(
    mut response: reqwest::Response,
    max_bytes: u64,
    context: &str,
) -> Result<Vec<u8>, AgentError> {
    if let Some(length) = response.content_length() {
        ensure_http_response_size(length, max_bytes, context)?;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        AgentError::ControlPlaneClient(format!("failed to read {context} response: {error}"))
    })? {
        ensure_http_response_size(body.len() as u64 + chunk.len() as u64, max_bytes, context)?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn proxy_status_is_retryable(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    )
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
        .unwrap_or_else(|| runtime_control_plane_urls(&state));
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
    state.runtime.replace_state(next_state.clone())?;

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
        .unwrap_or_else(|| runtime_control_plane_urls(&state));
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

fn runtime_control_plane_urls(state: &AgentHttpState) -> Vec<String> {
    let mut seen = BTreeSet::new();
    state
        .runtime
        .state()
        .bootstrap_endpoints
        .into_iter()
        .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
        .map(|endpoint| endpoint.url.trim_end_matches('/').to_string())
        .chain(
            state
                .control_plane_urls
                .iter()
                .map(|url| url.trim_end_matches('/').to_string()),
        )
        .filter(|url| seen.insert(url.clone()))
        .collect()
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
    let mut body = render_prometheus_metrics(&metrics);
    append_web_ui_prometheus_metrics(&mut body, &state).await;
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

async fn append_web_ui_prometheus_metrics(body: &mut String, state: &AgentHttpState) {
    let node_id = prometheus_label(state.runtime.state().node_id.as_str());
    let candidates = web_ui_candidates(state);
    let candidate_urls = candidates
        .iter()
        .map(|candidate| candidate.url.as_str())
        .collect::<BTreeSet<_>>();
    let health = state.web_ui_health.read().await;
    let reachable_count = health
        .iter()
        .filter(|(url, reachable)| **reachable && candidate_urls.contains(url.as_str()))
        .count();
    drop(health);
    let selected = selected_web_ui_url(state)
        .await
        .is_some_and(|url| candidate_urls.contains(url.as_str()));
    prometheus_line!(
        body,
        "# HELP ipars_agent_web_ui_endpoints Cached Web UI endpoints by observed state."
    );
    prometheus_line!(body, "# TYPE ipars_agent_web_ui_endpoints gauge");
    prometheus_line!(
        body,
        "ipars_agent_web_ui_endpoints{{node_id=\"{node_id}\",state=\"cached\"}} {}",
        candidate_urls.len()
    );
    prometheus_line!(
        body,
        "ipars_agent_web_ui_endpoints{{node_id=\"{node_id}\",state=\"reachable\"}} {reachable_count}"
    );
    prometheus_line!(
        body,
        "# HELP ipars_agent_web_ui_selected Whether the Agent has selected a reachable Web UI endpoint."
    );
    prometheus_line!(body, "# TYPE ipars_agent_web_ui_selected gauge");
    prometheus_line!(
        body,
        "ipars_agent_web_ui_selected{{node_id=\"{node_id}\"}} {}",
        u8::from(selected)
    );
    let gateway = match &state.public_web_gateway {
        Some(access) => access
            .status
            .read()
            .map(|status| status.clone())
            .unwrap_or_default(),
        None => PublicWebGatewayStatus::default(),
    };
    prometheus_line!(
        body,
        "# HELP ipars_agent_public_web_gateway_phase Current dynamic public Web gateway phase."
    );
    prometheus_line!(body, "# TYPE ipars_agent_public_web_gateway_phase gauge");
    for phase in [
        PublicWebGatewayPhase::Disabled,
        PublicWebGatewayPhase::Standby,
        PublicWebGatewayPhase::Provisioning,
        PublicWebGatewayPhase::Ready,
        PublicWebGatewayPhase::Error,
    ] {
        prometheus_line!(
            body,
            "ipars_agent_public_web_gateway_phase{{node_id=\"{node_id}\",phase=\"{}\"}} {}",
            phase.as_str(),
            u8::from(gateway.phase == phase)
        );
    }
    prometheus_line!(
        body,
        "# HELP ipars_agent_public_web_gateway_ready Whether the dynamic public Web gateway is externally ready."
    );
    prometheus_line!(body, "# TYPE ipars_agent_public_web_gateway_ready gauge");
    prometheus_line!(
        body,
        "ipars_agent_public_web_gateway_ready{{node_id=\"{node_id}\"}} {}",
        u8::from(gateway.phase == PublicWebGatewayPhase::Ready)
    );
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
        "# HELP ipars_agent_path_quality_observations Cached fresh-or-stale path quality observations; Signal applies its own freshness bound."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_path_quality_observations gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_path_quality_observations{{node_id=\"{node_id}\"}} {}",
        metrics.path_quality_observation_count
    );
    for (name, help, value) in [
        (
            "ipars_agent_peer_probe_measurements_total",
            "Peer path quality measurement rounds committed by the agent.",
            metrics.peer_probe_measurement_count,
        ),
        (
            "ipars_agent_peer_probe_failures_total",
            "Peer path quality measurements that failed before producing a valid round.",
            metrics.peer_probe_failure_count,
        ),
        (
            "ipars_agent_peer_probe_requests_sent_total",
            "UDP peer quality probe requests attempted by the agent.",
            metrics.peer_probe_request_sent_count,
        ),
        (
            "ipars_agent_peer_probe_responses_received_total",
            "Authenticated-path UDP peer quality probe responses received by the agent.",
            metrics.peer_probe_response_received_count,
        ),
        (
            "ipars_agent_peer_probe_timeouts_total",
            "UDP peer quality probe samples without a matching response.",
            metrics.peer_probe_timeout_count,
        ),
        (
            "ipars_agent_peer_probe_responder_requests_total",
            "Allowlisted UDP peer quality requests answered by the agent.",
            metrics.peer_probe_responder_request_count,
        ),
        (
            "ipars_agent_peer_probe_responder_invalid_total",
            "Malformed or non-request UDP peer quality packets rejected by the agent.",
            metrics.peer_probe_responder_invalid_count,
        ),
        (
            "ipars_agent_peer_probe_responder_unknown_source_total",
            "UDP peer quality packets rejected because the source VPN IP was absent from the peer map.",
            metrics.peer_probe_responder_unknown_source_count,
        ),
        (
            "ipars_agent_peer_probe_responder_rate_limited_total",
            "Allowlisted UDP peer quality requests rejected by the per-peer rate limit.",
            metrics.peer_probe_responder_rate_limited_count,
        ),
        (
            "ipars_agent_peer_probe_responder_send_failures_total",
            "UDP peer quality responses that could not be sent in full.",
            metrics.peer_probe_responder_send_failure_count,
        ),
    ] {
        prometheus_line!(&mut body, "# HELP {name} {help}");
        prometheus_line!(&mut body, "# TYPE {name} counter");
        prometheus_line!(&mut body, "{name}{{node_id=\"{node_id}\"}} {value}");
    }
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
            | AgentError::InvalidState(_)
            | AgentError::WireGuard(_)
            | AgentError::PeerProbe(_) => StatusCode::SERVICE_UNAVAILABLE,
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
    use std::sync::atomic::{AtomicUsize, Ordering};
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
        BootstrapEndpoint, CandidateSource, ClusterId, ClusterPolicy, EndpointCandidate,
        EndpointCandidateKind, NodeId, NodeRecord, PathMetrics, PathRecord, PathScore, PathState,
        PeerPathKey, Role, Route, TokenPolicy, VpnIp,
    };
    use tower::ServiceExt;

    use super::*;

    fn test_error<T, E>(result: Result<T, E>, context: &str) -> E {
        match result {
            Ok(_) => panic!("{context}"),
            Err(error) => error,
        }
    }

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
            path_quality_observation_count: 0,
            peer_probe_measurement_count: 0,
            peer_probe_failure_count: 0,
            peer_probe_request_sent_count: 0,
            peer_probe_response_received_count: 0,
            peer_probe_timeout_count: 0,
            peer_probe_responder_request_count: 0,
            peer_probe_responder_invalid_count: 0,
            peer_probe_responder_unknown_source_count: 0,
            peer_probe_responder_rate_limited_count: 0,
            peer_probe_responder_send_failure_count: 0,
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
        assert!(body.contains(&format!(
            "ipars_agent_path_quality_observations{{node_id=\"{prometheus_node_id}\"}} 0"
        )));
        assert!(body.contains(&format!(
            "ipars_agent_peer_probe_measurements_total{{node_id=\"{prometheus_node_id}\"}} 0"
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
                bootstrap_endpoints: Vec::new(),
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

    #[derive(Clone)]
    struct WebUiTestBackend {
        admin_status: StatusCode,
        admin_calls: Arc<AtomicUsize>,
        authorization: Arc<tokio::sync::Mutex<Option<String>>>,
        base_url: String,
        device_authorization_form: Arc<tokio::sync::Mutex<Option<BTreeMap<String, String>>>>,
        device_token_calls: Arc<AtomicUsize>,
        device_token_forms: Arc<tokio::sync::Mutex<Vec<BTreeMap<String, String>>>>,
    }

    async fn web_ui_test_config(State(state): State<WebUiTestBackend>) -> Json<Value> {
        Json(json!({
            "cluster_id": "cluster-a",
            "enabled": true,
            "auth_enabled": true,
            "operator_token_enabled": false,
            "provider": "keycloak",
            "issuer_url": format!("{}/realms/heteronetwork", state.base_url),
            "client_id": "heteronetwork-web",
            "scopes": "openid profile email",
            "authorization_endpoint": format!("{}/realms/heteronetwork/protocol/openid-connect/auth", state.base_url),
            "device_authorization_endpoint": format!("{}/realms/heteronetwork/protocol/openid-connect/auth/device", state.base_url),
            "token_endpoint": format!("{}/realms/heteronetwork/protocol/openid-connect/token", state.base_url),
            "logout_endpoint": format!("{}/realms/heteronetwork/protocol/openid-connect/logout", state.base_url),
            "login_endpoint": "/ui/login",
            "node_enrollment_enabled": true,
            "client_enrollment_enabled": true
        }))
    }

    async fn web_ui_test_device_authorization(
        State(state): State<WebUiTestBackend>,
        axum::extract::Form(form): axum::extract::Form<BTreeMap<String, String>>,
    ) -> Json<Value> {
        *state.device_authorization_form.lock().await = Some(form);
        Json(json!({
            "device_code": "device-code",
            "user_code": "ABCD-EFGH",
            "verification_uri": format!("{}/verify", state.base_url),
            "verification_uri_complete": format!("{}/verify?user_code=ABCD-EFGH", state.base_url),
            "expires_in": 60,
            "interval": 1
        }))
    }

    async fn web_ui_test_device_token(
        State(state): State<WebUiTestBackend>,
        axum::extract::Form(form): axum::extract::Form<BTreeMap<String, String>>,
    ) -> Response {
        state.device_token_forms.lock().await.push(form);
        if state.device_token_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "authorization_pending"})),
            )
                .into_response();
        }
        Json(json!({"access_token": "device-access-token"})).into_response()
    }

    async fn web_ui_test_admin(
        State(state): State<WebUiTestBackend>,
        headers: HeaderMap,
    ) -> Response {
        state.admin_calls.fetch_add(1, Ordering::SeqCst);
        *state.authorization.lock().await = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        (
            state.admin_status,
            Json(json!({ "backend": state.admin_status.as_u16() })),
        )
            .into_response()
    }

    async fn web_ui_test_install(
        State(state): State<WebUiTestBackend>,
        headers: HeaderMap,
    ) -> Response {
        *state.authorization.lock().await = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let mut response = (state.admin_status, "test-installer").into_response();
        response.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=test-installer"),
        );
        response.headers_mut().insert(
            HeaderName::from_static("x-heteronetwork-sha256"),
            HeaderValue::from_static("test-sha256"),
        );
        response
    }

    async fn spawn_web_ui_test_backend(
        admin_status: StatusCode,
    ) -> Result<(String, WebUiTestBackend, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>>
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let base_url = format!("http://{addr}");
        let state = WebUiTestBackend {
            admin_status,
            admin_calls: Arc::new(AtomicUsize::new(0)),
            authorization: Arc::new(tokio::sync::Mutex::new(None)),
            base_url: base_url.clone(),
            device_authorization_form: Arc::new(tokio::sync::Mutex::new(None)),
            device_token_calls: Arc::new(AtomicUsize::new(0)),
            device_token_forms: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        };
        let app = Router::new()
            .route("/ui/config", get(web_ui_test_config))
            .route("/v1/admin/overview", any(web_ui_test_admin))
            .route("/v1/install/test", get(web_ui_test_install))
            .route("/v1/clients/peers/query", post(web_ui_test_admin))
            .route(
                "/realms/heteronetwork/protocol/openid-connect/auth/device",
                post(web_ui_test_device_authorization),
            )
            .route(
                "/realms/heteronetwork/protocol/openid-connect/token",
                post(web_ui_test_device_token),
            )
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok((base_url, state, task))
    }

    #[test]
    fn web_ui_endpoint_normalization_requires_tls_for_public_addresses() {
        assert_eq!(
            normalize_web_ui_base_url("127.0.0.1:8443"),
            Ok("http://127.0.0.1:8443".to_string())
        );
        assert_eq!(
            normalize_web_ui_base_url("10.250.0.1/ui/"),
            Ok("http://10.250.0.1".to_string())
        );
        assert_eq!(
            normalize_web_ui_base_url("console.example/ui"),
            Ok("https://console.example".to_string())
        );
        assert!(normalize_web_ui_base_url("http://203.0.113.10:8443").is_err());
        assert!(normalize_web_ui_base_url("http://0.0.0.0:8443").is_err());
        assert!(normalize_web_ui_base_url("http://127.0.0.1:0").is_err());
        assert!(normalize_web_ui_base_url("https://[ff02::1]:8443").is_err());
        assert_eq!(
            normalize_web_ui_base_url("https://203.0.113.10:8443/ui/"),
            Ok("https://203.0.113.10:8443".to_string())
        );
    }

    #[tokio::test]
    async fn public_web_gateway_requires_proxy_auth_and_limits_routes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (backend_url, backend, backend_task) =
            spawn_web_ui_test_backend(StatusCode::OK).await?;
        let mut node_state = AgentNodeState::generate(Utc::now());
        node_state.bootstrap_endpoints.push(BootstrapEndpoint {
            kind: BootstrapEndpointKind::WebUi,
            url: "https://203.0.113.10".to_string(),
        });
        let runtime = Arc::new(AgentRuntime::new(node_state, ClusterPolicy::default()));
        let status = Arc::new(StdRwLock::new(PublicWebGatewayStatus {
            phase: PublicWebGatewayPhase::Ready,
            public_ip: Some("203.0.113.10".parse()?),
            url: Some("https://203.0.113.10/".to_string()),
            last_error: None,
            updated_at: Utc::now(),
        }));
        let state = AgentHttpState::with_control_plane_urls(runtime, vec![backend_url.clone()])
            .enable_local_web_ui(true)
            .with_public_web_gateway("gateway-secret".to_string(), status);
        let candidates = web_ui_candidates(&state);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].url, backend_url);
        let app = router(state);

        let missing_token = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ui/app.js")
                    .header(header::HOST, "203.0.113.10")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(missing_token.status(), StatusCode::FORBIDDEN);

        let public_asset = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ui/app.js")
                    .header(header::HOST, "203.0.113.10")
                    .header(PUBLIC_WEB_GATEWAY_HEADER, "gateway-secret")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(public_asset.status(), StatusCode::OK);

        let mutation = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/web-ui/select")
                    .header(header::HOST, "203.0.113.10")
                    .header(header::ORIGIN, "https://203.0.113.10")
                    .header(PUBLIC_WEB_GATEWAY_HEADER, "gateway-secret")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"endpoint":"https://example.com"}"#))?,
            )
            .await?;
        assert_eq!(mutation.status(), StatusCode::FORBIDDEN);

        let wrong_host = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ui/app.js")
                    .header(header::HOST, "203.0.113.11")
                    .header(PUBLIC_WEB_GATEWAY_HEADER, "gateway-secret")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(wrong_host.status(), StatusCode::FORBIDDEN);

        let install = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/install/test")
                    .header(header::HOST, "203.0.113.10")
                    .header(PUBLIC_WEB_GATEWAY_HEADER, "gateway-secret")
                    .header(header::AUTHORIZATION, "HeteroNetworkJoin enrollment-token")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(install.status(), StatusCode::OK);
        assert_eq!(
            install.headers().get(header::CONTENT_DISPOSITION),
            Some(&HeaderValue::from_static(
                "attachment; filename=test-installer"
            ))
        );
        assert_eq!(
            install.headers().get("x-heteronetwork-sha256"),
            Some(&HeaderValue::from_static("test-sha256"))
        );
        assert_eq!(
            backend.authorization.lock().await.as_deref(),
            Some("HeteroNetworkJoin enrollment-token")
        );

        let client_query = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/clients/peers/query")
                    .header(header::HOST, "203.0.113.10")
                    .header(PUBLIC_WEB_GATEWAY_HEADER, "gateway-secret")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(client_query.status(), StatusCode::OK);

        let loopback_asset = app
            .oneshot(
                Request::builder()
                    .uri("/ui/app.js")
                    .header(header::HOST, "127.0.0.1:9780")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(loopback_asset.status(), StatusCode::OK);
        backend_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn overlay_web_ui_accepts_only_the_vpn_ip_and_internal_name(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (backend_url, _, backend_task) = spawn_web_ui_test_backend(StatusCode::OK).await?;
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let state = AgentHttpState::with_control_plane_urls(runtime, vec![backend_url]);
        let listen: std::net::SocketAddr = "10.250.0.1:9781".parse()?;
        let app = overlay_web_ui_router(state, listen, "console.heteronetwork.internal");

        for host in ["10.250.0.1:9781", "console.heteronetwork.internal:9781"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/ui/app.js")
                        .header(header::HOST, host)
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
        }

        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/web-ui/healthz")
                    .header(header::HOST, "10.250.0.1:9781")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(health.status(), StatusCode::OK);

        let wrong_host = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ui/app.js")
                    .header(header::HOST, "10.250.0.2:9781")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(wrong_host.status(), StatusCode::FORBIDDEN);

        let agent_api = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header(header::HOST, "10.250.0.1:9781")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(agent_api.status(), StatusCode::NOT_FOUND);
        backend_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn manual_web_ui_endpoint_must_match_registered_cluster(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (backend_url, _, backend_task) = spawn_web_ui_test_backend(StatusCode::OK).await?;
        let candidate = WebUiCandidate {
            url: backend_url,
            source: "manual_seed",
            trusted_directory: false,
        };
        let result =
            fetch_web_ui_config(&reqwest::Client::new(), &candidate, Some("cluster-b")).await;
        let error = test_error(result, "cluster mismatch must be rejected");
        assert!(error.contains("different HeteroNetwork cluster"));
        backend_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn local_web_ui_bootstrap_persists_seed_and_rewrites_oidc_flow(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (backend_url, _, backend_task) = spawn_web_ui_test_backend(StatusCode::OK).await?;
        let state_dir = temp_state_dir("web-ui-bootstrap");
        let state_path = state_dir.join("state.json");
        let store = FileAgentStateStore::new(&state_path);
        let node_state = AgentNodeState::generate(Utc::now());
        store.save(&node_state)?;
        let runtime = Arc::new(AgentRuntime::new(node_state, ClusterPolicy::default()));
        let app = router(
            AgentHttpState::with_wireguard_key_rotation(runtime, store.clone(), Vec::new())
                .enable_local_web_ui(true),
        );

        let rejected = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/ui/config")
                    .header(header::HOST, "attacker.example")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/web-ui/bootstrap")
                    .header(header::HOST, "127.0.0.1:9780")
                    .header(header::ORIGIN, "http://127.0.0.1:9780")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&json!({
                        "endpoint": backend_url
                    }))?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(store.load()?.web_ui_seed_urls, vec![backend_url.clone()]);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/ui/config")
                    .header(header::HOST, "127.0.0.1:9780")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let config: Value = serde_json::from_slice(&body)?;
        assert_eq!(config["local_agent"], true);
        assert_eq!(config["bootstrap_required"], false);
        assert_eq!(config["selected_web_ui_endpoint"], backend_url);
        assert!(config["login_endpoint"].is_null());
        assert_eq!(config["device_login_endpoint"], "/v1/web-ui/auth/device");
        assert_eq!(
            config["device_login_poll_endpoint"],
            "/v1/web-ui/auth/device/poll"
        );

        backend_task.abort();
        let _ = std::fs::remove_dir_all(state_dir);
        Ok(())
    }

    #[tokio::test]
    async fn local_web_ui_uses_persisted_service_directory_without_runtime_flags(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (backend_url, _, backend_task) = spawn_web_ui_test_backend(StatusCode::OK).await?;
        let mut node_state = AgentNodeState::generate(Utc::now());
        node_state
            .bootstrap_endpoints
            .push(ipars_types::BootstrapEndpoint {
                kind: BootstrapEndpointKind::WebUi,
                url: backend_url.clone(),
            });
        let runtime = Arc::new(AgentRuntime::new(node_state, ClusterPolicy::default()));
        let app = router(AgentHttpState::new(runtime).enable_local_web_ui(true));

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/ui/config")
                    .header(header::HOST, "127.0.0.1:9780")
                    .body(Body::empty())?,
            )
            .await?;
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let config: Value = serde_json::from_slice(&body)?;
        assert_eq!(config["bootstrap_required"], false);
        assert_eq!(config["selected_web_ui_endpoint"], backend_url);

        backend_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn local_web_ui_completes_keycloak_device_authorization(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (backend_url, backend, backend_task) =
            spawn_web_ui_test_backend(StatusCode::OK).await?;
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let app = router(
            AgentHttpState::with_control_plane_urls(runtime, vec![backend_url])
                .enable_local_web_ui(true),
        );
        let start = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/web-ui/auth/device")
                    .header(header::HOST, "127.0.0.1:9780")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(start.status(), StatusCode::OK);
        let start: Value = serde_json::from_slice(&to_bytes(start.into_body(), usize::MAX).await?)?;
        assert_eq!(start["user_code"], "ABCD-EFGH");
        let authorization_form = backend
            .device_authorization_form
            .lock()
            .await
            .clone()
            .ok_or("device authorization form was not captured")?;
        assert_eq!(
            authorization_form
                .get("code_challenge_method")
                .map(String::as_str),
            Some("S256")
        );
        let code_challenge = authorization_form
            .get("code_challenge")
            .cloned()
            .ok_or("device authorization omitted PKCE challenge")?;
        let handle = start["handle"]
            .as_str()
            .ok_or("device response omitted handle")?;

        tokio::time::sleep(Duration::from_millis(1_050)).await;
        let first_poll = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/web-ui/auth/device/poll")
                    .header(header::HOST, "127.0.0.1:9780")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&json!({"handle": handle}))?))?,
            )
            .await?;
        assert_eq!(first_poll.status(), StatusCode::ACCEPTED);

        tokio::time::sleep(Duration::from_millis(1_050)).await;
        let second_poll = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/web-ui/auth/device/poll")
                    .header(header::HOST, "127.0.0.1:9780")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&json!({"handle": handle}))?))?,
            )
            .await?;
        assert_eq!(second_poll.status(), StatusCode::OK);
        let second_poll: Value =
            serde_json::from_slice(&to_bytes(second_poll.into_body(), usize::MAX).await?)?;
        assert_eq!(second_poll["access_token"], "device-access-token");
        assert_eq!(backend.device_token_calls.load(Ordering::SeqCst), 2);
        let token_forms = backend.device_token_forms.lock().await;
        assert_eq!(token_forms.len(), 2);
        let code_verifier = token_forms[0]
            .get("code_verifier")
            .ok_or("device token request omitted PKCE verifier")?;
        assert_eq!(token_forms[1].get("code_verifier"), Some(code_verifier));
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes())),
            code_challenge
        );
        backend_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn local_web_ui_read_proxy_fails_over_and_preserves_authorization(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (failed_url, failed, failed_task) =
            spawn_web_ui_test_backend(StatusCode::SERVICE_UNAVAILABLE).await?;
        let (healthy_url, healthy, healthy_task) =
            spawn_web_ui_test_backend(StatusCode::OK).await?;
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let app = router(
            AgentHttpState::with_control_plane_urls(
                runtime,
                vec![failed_url.clone(), healthy_url.clone()],
            )
            .enable_local_web_ui(true),
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/overview")
                    .header(header::HOST, "localhost")
                    .header(header::AUTHORIZATION, "Bearer oidc-token")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-heteronetwork-web-ui-endpoint")
                .and_then(|value| value.to_str().ok()),
            Some(healthy_url.as_str())
        );
        assert_eq!(failed.admin_calls.load(Ordering::SeqCst), 1);
        assert_eq!(healthy.admin_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            healthy.authorization.lock().await.as_deref(),
            Some("Bearer oidc-token")
        );

        let metrics = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .body(Body::empty())?,
            )
            .await?;
        let metrics = to_bytes(metrics.into_body(), usize::MAX).await?;
        let metrics = String::from_utf8(metrics.to_vec())?;
        assert!(metrics.contains("ipars_agent_web_ui_endpoints"));
        assert!(metrics.contains("state=\"cached\"} 2"));
        assert!(metrics.contains("state=\"reachable\"} 1"));
        assert!(metrics.contains("ipars_agent_web_ui_selected"));

        failed_task.abort();
        healthy_task.abort();
        Ok(())
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

        let error = test_error(
            send_wireguard_key_rotation_to_control_planes(
                &reqwest::Client::new(),
                DEFAULT_CONTROL_PLANE_REQUEST_TIMEOUT,
                &[control_plane_url],
                request,
            )
            .await,
            "oversized WireGuard key rotation response should be rejected",
        );

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
        let error = test_error(
            read_bounded_json_response::<serde_json::Value>(
                response,
                10,
                "test control-plane JSON",
            )
            .await,
            "oversized chunked control-plane body should be rejected",
        );

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
            bootstrap_endpoints: Vec::new(),
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
            .await?;
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
                bootstrap_endpoints: Vec::new(),
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
