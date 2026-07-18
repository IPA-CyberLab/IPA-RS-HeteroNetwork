use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use ipars_control_plane::{
    ControlPlane, ControlPlaneError, ControlPlaneJoinService, ControlPlaneStore, TokenLedger,
};
use ipars_types::api::{
    ControlPlaneMetricsResponse, ControlPlaneNodeOverview, ControlPlaneNodeQueryKind,
    ControlPlaneNodeQueryRequest, ControlPlaneOverviewResponse, ControlPlanePathsResponse,
    ControlPlanePolicyResponse, HeartbeatRequest, HeartbeatResponse, JoinNodeRequest, PeerMap,
    RegisterNodeResponse, RemoveNodeRequest, RemoveNodeResponse, RevokeTokenRequest,
    RevokeTokenResponse, RotateWireGuardKeyRequest, RotateWireGuardKeyResponse,
    SignalNodeAuthenticationResponse, SignalNodeUpsertRequest,
};
use ipars_types::{ClusterPolicy, NodeId, PathRecord, PathState, TokenLedgerMetrics};
use rand_core::{OsRng, RngCore};
use reqwest::redirect::Policy as RedirectPolicy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tokio::time::timeout;
use url::Url;

const MAX_OPERATOR_API_BEARER_TOKEN_BYTES: usize = 512;
const MAX_WEB_OIDC_LOGIN_STATES: usize = 1024;
const WEB_OIDC_LOGIN_STATE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_WEB_OIDC_TOKEN_RESPONSE_BYTES: usize = 1024 * 1024;
const WEB_OIDC_STATE_COOKIE: &str = "heteronetwork_oidc_state";
const WEB_OIDC_ACCESS_TOKEN_STORAGE_KEY: &str = "heteronetwork_access_token";

macro_rules! prometheus_line {
    ($body:expr, $($arg:tt)*) => {{
        let _ = writeln!($body, $($arg)*);
    }};
}

pub struct ControlPlaneHttpState<S, L> {
    plane: Arc<ControlPlane<S>>,
    join_service: Arc<ControlPlaneJoinService<S, L>>,
    operator_api_bearer_token: Option<Arc<str>>,
    web_ui_auth: Option<Arc<WebUiAuthConfig>>,
}

impl<S, L> Clone for ControlPlaneHttpState<S, L> {
    fn clone(&self) -> Self {
        Self {
            plane: self.plane.clone(),
            join_service: self.join_service.clone(),
            operator_api_bearer_token: self.operator_api_bearer_token.clone(),
            web_ui_auth: self.web_ui_auth.clone(),
        }
    }
}

impl<S, L> ControlPlaneHttpState<S, L> {
    pub fn new(
        plane: Arc<ControlPlane<S>>,
        join_service: Arc<ControlPlaneJoinService<S, L>>,
    ) -> Self {
        Self {
            plane,
            join_service,
            operator_api_bearer_token: None,
            web_ui_auth: None,
        }
    }

    pub fn require_operator_api_bearer_token(mut self, token: String) -> Self {
        self.operator_api_bearer_token = Some(Arc::from(token));
        self
    }

    pub fn enable_web_ui(mut self, auth: WebUiAuthConfig) -> Self {
        self.web_ui_auth = Some(Arc::new(auth));
        self
    }
}

pub fn router<S, L>(state: ControlPlaneHttpState<S, L>) -> Router
where
    S: ControlPlaneStore + 'static,
    L: TokenLedger + 'static,
{
    let protocol = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/join", post(join::<S, L>))
        .route("/v1/heartbeat", post(heartbeat::<S, L>))
        .route("/v1/peers/query", post(peers::<S, L>))
        .route("/v1/paths/query", post(paths::<S, L>))
        .route(
            "/v1/nodes/authenticate-signal-upsert",
            post(authenticate_signal_node_upsert::<S, L>),
        )
        .route("/v1/nodes/{node_id}", delete(remove_node::<S, L>))
        .route(
            "/v1/nodes/{node_id}/wireguard-key",
            put(rotate_wireguard_key::<S, L>),
        )
        .route("/v1/tokens/revoke", post(revoke_token::<S, L>));

    let management_auth = Arc::new(ManagementAuth {
        operator_api_bearer_token: state.operator_api_bearer_token.clone(),
        web_ui_auth: state.web_ui_auth.clone(),
    });
    let admin = Router::new()
        .route("/v1/admin/overview", get(admin_overview::<S, L>))
        .route("/v1/admin/services", get(admin_services::<S, L>))
        .route("/v1/admin/nodes", get(admin_nodes::<S, L>))
        .route("/v1/admin/paths", get(admin_paths::<S, L>))
        .route(
            "/v1/admin/policy",
            get(admin_policy::<S, L>).put(update_admin_policy::<S, L>),
        )
        .route(
            "/v1/admin/nodes/{node_id}",
            delete(admin_remove_node::<S, L>),
        )
        .route(
            "/v1/admin/paths/{local_node_id}/{remote_node_id}/pin",
            post(admin_pin_path::<S, L>),
        )
        .route_layer(middleware::from_fn_with_state(
            management_auth,
            require_management_auth,
        ));

    let app = if let Some(token) = state.operator_api_bearer_token.clone() {
        let operator = Router::new()
            .route("/metrics", get(prometheus_metrics::<S, L>))
            .route("/v1/metrics", get(metrics::<S, L>))
            .route("/v1/policy", get(policy::<S, L>))
            .route_layer(middleware::from_fn_with_state(
                token,
                require_operator_api_bearer,
            ));
        protocol.merge(operator).merge(admin)
    } else {
        protocol.merge(admin)
    };
    app.route("/ui", get(ui_index))
        .route("/ui/", get(ui_index))
        .route("/ui/login", get(ui_login::<S, L>))
        .route("/ui/callback", get(ui_callback::<S, L>))
        .route("/ui/app.js", get(ui_app))
        .route("/ui/styles.css", get(ui_styles))
        .route("/ui/config", get(ui_config::<S, L>))
        .with_state(state)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WebAuthProvider {
    Keycloak,
    Cognito,
}

impl WebAuthProvider {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "keycloak" => Ok(Self::Keycloak),
            "cognito" => Ok(Self::Cognito),
            other => Err(format!(
                "unsupported web auth provider {other:?}; expected keycloak or cognito"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Keycloak => "keycloak",
            Self::Cognito => "cognito",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WebUiAuthConfig {
    provider: WebAuthProvider,
    issuer_url: String,
    client_id: String,
    scopes: String,
    public_url: Option<String>,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    logout_endpoint: String,
    client: Client,
    login_states: Arc<Mutex<HashMap<String, OidcLoginState>>>,
}

#[derive(Debug)]
struct OidcLoginState {
    verifier: String,
    redirect_uri: String,
    created_at: Instant,
}

#[derive(Debug)]
struct OidcLoginStart {
    location: String,
    state_cookie: header::HeaderValue,
}

#[derive(Debug)]
struct WebAuthFlowError {
    status: StatusCode,
    message: String,
}

impl WebAuthFlowError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl WebUiAuthConfig {
    pub fn new(
        provider: WebAuthProvider,
        issuer_url: String,
        client_id: String,
        auth_base_url: Option<String>,
        scopes: String,
    ) -> Result<Self, String> {
        let issuer_url = validate_web_auth_base_url(issuer_url, "issuer URL")?;
        let auth_base_url = match auth_base_url {
            Some(value) => validate_web_auth_base_url(value, "OIDC auth base URL")?,
            None => issuer_url.clone(),
        };
        let client_id = client_id.trim().to_string();
        if client_id.is_empty() || client_id.len() > 256 || client_id.chars().any(char::is_control)
        {
            return Err("OIDC client ID must be 1 to 256 non-control characters".to_string());
        }
        let scopes = scopes.trim().to_string();
        if scopes.is_empty() || scopes.chars().any(char::is_control) {
            return Err(
                "OIDC scopes must be non-empty and contain no control characters".to_string(),
            );
        }
        let (authorization_suffix, token_suffix, userinfo_suffix, logout_suffix) = match provider {
            WebAuthProvider::Keycloak => (
                "/protocol/openid-connect/auth",
                "/protocol/openid-connect/token",
                "/protocol/openid-connect/userinfo",
                "/protocol/openid-connect/logout",
            ),
            WebAuthProvider::Cognito => (
                "/oauth2/authorize",
                "/oauth2/token",
                "/oauth2/userInfo",
                "/logout",
            ),
        };
        let client = Client::builder()
            .redirect(RedirectPolicy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| format!("failed to build OIDC HTTP client: {error}"))?;
        Ok(Self {
            provider,
            issuer_url: issuer_url.clone(),
            client_id,
            scopes,
            public_url: None,
            authorization_endpoint: endpoint_url(&auth_base_url, authorization_suffix),
            token_endpoint: endpoint_url(&auth_base_url, token_suffix),
            userinfo_endpoint: endpoint_url(&auth_base_url, userinfo_suffix),
            logout_endpoint: endpoint_url(&auth_base_url, logout_suffix),
            client,
            login_states: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn with_public_url(mut self, public_url: String) -> Result<Self, String> {
        let public_url = validate_web_auth_base_url(public_url, "web public URL")?;
        let parsed = Url::parse(&public_url)
            .map_err(|error| format!("web public URL is invalid: {error}"))?;
        if parsed.path() != "/" {
            return Err("web public URL must be an origin without a path".to_string());
        }
        self.public_url = Some(public_url);
        Ok(self)
    }

    pub async fn validate_access_token(&self, token: &str) -> bool {
        if token.is_empty() || token.len() > MAX_OPERATOR_API_BEARER_TOKEN_BYTES * 16 {
            return false;
        }
        let response = match timeout(
            Duration::from_secs(5),
            self.client
                .get(&self.userinfo_endpoint)
                .bearer_auth(token)
                .send(),
        )
        .await
        {
            Ok(Ok(response)) => response,
            _ => return false,
        };
        if !response.status().is_success() {
            return false;
        }
        let body = match bounded_response_body(response, MAX_WEB_OIDC_TOKEN_RESPONSE_BYTES).await {
            Ok(body) => body,
            Err(_) => return false,
        };
        match serde_json::from_slice::<Value>(&body) {
            Ok(claims) => claims
                .get("sub")
                .and_then(Value::as_str)
                .is_some_and(|subject| !subject.is_empty()),
            Err(_) => false,
        }
    }

    async fn begin_login(&self) -> Result<OidcLoginStart, WebAuthFlowError> {
        let public_url = self.public_url.as_deref().ok_or_else(|| {
            WebAuthFlowError::new(
                StatusCode::NOT_FOUND,
                "server-side OIDC login is not configured",
            )
        })?;
        let redirect_uri = format!("{public_url}/ui/callback");
        let verifier = random_oidc_value(32);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let state = random_oidc_value(24);
        let now = Instant::now();
        {
            let mut states = self.login_states.lock().await;
            states
                .retain(|_, entry| now.duration_since(entry.created_at) < WEB_OIDC_LOGIN_STATE_TTL);
            if states.len() >= MAX_WEB_OIDC_LOGIN_STATES {
                return Err(WebAuthFlowError::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many pending OIDC logins",
                ));
            }
            if states.contains_key(&state) {
                return Err(WebAuthFlowError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "failed to allocate a unique OIDC state",
                ));
            }
            states.insert(
                state.clone(),
                OidcLoginState {
                    verifier,
                    redirect_uri: redirect_uri.clone(),
                    created_at: now,
                },
            );
        }
        let mut authorization_url = Url::parse(&self.authorization_endpoint).map_err(|error| {
            WebAuthFlowError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("OIDC authorization endpoint is invalid: {error}"),
            )
        })?;
        authorization_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", &self.scopes)
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        let secure = public_url.starts_with("https://");
        let secure_attribute = if secure { "; Secure" } else { "" };
        let state_cookie = header::HeaderValue::from_str(&format!(
            "{WEB_OIDC_STATE_COOKIE}={state}; Path=/ui/callback; Max-Age={}; HttpOnly; SameSite=Lax{secure_attribute}",
            WEB_OIDC_LOGIN_STATE_TTL.as_secs()
        ))
        .map_err(|_| {
            WebAuthFlowError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build the OIDC state cookie",
            )
        })?;
        Ok(OidcLoginStart {
            location: authorization_url.into(),
            state_cookie,
        })
    }

    async fn complete_login(
        &self,
        query: OidcCallbackQuery,
        state_cookie: Option<&str>,
    ) -> Result<String, WebAuthFlowError> {
        let state = query
            .state
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                WebAuthFlowError::new(StatusCode::BAD_REQUEST, "missing or expired OIDC state")
            })?;
        if state.len() > 128
            || !state_cookie.is_some_and(|cookie| bounded_constant_time_matches(state, cookie, 128))
        {
            return Err(WebAuthFlowError::new(
                StatusCode::BAD_REQUEST,
                "missing or expired OIDC state",
            ));
        }
        if query
            .code
            .as_deref()
            .is_some_and(|code| code.len() > 16 * 1024)
            || query
                .error
                .as_deref()
                .is_some_and(|error| error.len() > 1024)
            || query
                .error_description
                .as_deref()
                .is_some_and(|description| description.len() > 4096)
        {
            return Err(WebAuthFlowError::new(
                StatusCode::BAD_REQUEST,
                "OIDC callback parameters exceed their size limit",
            ));
        }
        let login = {
            let mut states = self.login_states.lock().await;
            let now = Instant::now();
            states
                .retain(|_, entry| now.duration_since(entry.created_at) < WEB_OIDC_LOGIN_STATE_TTL);
            states.remove(state)
        }
        .ok_or_else(|| {
            WebAuthFlowError::new(StatusCode::BAD_REQUEST, "missing or expired OIDC state")
        })?;

        if let Some(error) = query.error.as_deref() {
            let description = query.error_description.as_deref().unwrap_or(error);
            return Err(WebAuthFlowError::new(
                StatusCode::UNAUTHORIZED,
                format!("OIDC authorization was rejected: {description}"),
            ));
        }
        let code = query
            .code
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                WebAuthFlowError::new(StatusCode::BAD_REQUEST, "OIDC callback is missing a code")
            })?;

        let response = self
            .client
            .post(&self.token_endpoint)
            .header(header::ACCEPT, "application/json")
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", self.client_id.as_str()),
                ("code", code),
                ("redirect_uri", login.redirect_uri.as_str()),
                ("code_verifier", login.verifier.as_str()),
            ])
            .send()
            .await
            .map_err(|error| {
                WebAuthFlowError::new(
                    StatusCode::BAD_GATEWAY,
                    format!("OIDC token exchange failed: {error}"),
                )
            })?;
        if !response.status().is_success() {
            return Err(WebAuthFlowError::new(
                StatusCode::UNAUTHORIZED,
                format!("OIDC token exchange failed ({})", response.status()),
            ));
        }
        let body = bounded_response_body(response, MAX_WEB_OIDC_TOKEN_RESPONSE_BYTES).await?;
        let tokens: OidcTokenResponse = serde_json::from_slice(&body).map_err(|error| {
            WebAuthFlowError::new(
                StatusCode::BAD_GATEWAY,
                format!("OIDC token response is invalid: {error}"),
            )
        })?;
        if !self.validate_access_token(&tokens.access_token).await {
            return Err(WebAuthFlowError::new(
                StatusCode::UNAUTHORIZED,
                "OIDC access token failed provider validation",
            ));
        }
        Ok(tokens.access_token)
    }

    fn public_config(&self) -> WebUiPublicConfig {
        WebUiPublicConfig {
            enabled: true,
            auth_enabled: true,
            operator_token_enabled: false,
            provider: Some(self.provider.as_str().to_string()),
            issuer_url: Some(self.issuer_url.clone()),
            client_id: Some(self.client_id.clone()),
            scopes: Some(self.scopes.clone()),
            authorization_endpoint: Some(self.authorization_endpoint.clone()),
            token_endpoint: Some(self.token_endpoint.clone()),
            logout_endpoint: Some(self.logout_endpoint.clone()),
            login_endpoint: self.public_url.as_ref().map(|_| "/ui/login".to_string()),
        }
    }
}

fn validate_web_auth_base_url(value: String, name: &str) -> Result<String, String> {
    let value = value.trim().trim_end_matches('/').to_string();
    let parsed = Url::parse(&value).map_err(|error| format!("{name} is invalid: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(format!(
            "{name} must be an http(s) URL with a host and no credentials, query, or fragment"
        ));
    }
    if parsed.scheme() == "http" && !web_auth_plain_http_host_allowed(&parsed) {
        return Err(format!(
            "{name} must use https unless its host is loopback, private, link-local, or CGNAT"
        ));
    }
    Ok(value)
}

fn web_auth_plain_http_host_allowed(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => web_auth_plain_http_ipv4_allowed(address),
        Ok(std::net::IpAddr::V6(address)) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return web_auth_plain_http_ipv4_allowed(mapped);
            }
            let first = address.segments()[0];
            !address.is_unspecified()
                && !address.is_multicast()
                && (address.is_loopback() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80)
        }
        Err(_) => {
            host.eq_ignore_ascii_case("localhost")
                || host.to_ascii_lowercase().ends_with(".localhost")
        }
    }
}

fn web_auth_plain_http_ipv4_allowed(address: std::net::Ipv4Addr) -> bool {
    let octets = address.octets();
    !address.is_unspecified()
        && !address.is_multicast()
        && (address.is_loopback()
            || address.is_private()
            || address.is_link_local()
            || (octets[0] == 100 && (64..=127).contains(&octets[1])))
}

fn endpoint_url(base: &str, suffix: &str) -> String {
    format!("{base}{suffix}")
}

fn random_oidc_value(byte_count: usize) -> String {
    let mut bytes = vec![0_u8; byte_count];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn bounded_response_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, WebAuthFlowError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(WebAuthFlowError::new(
            StatusCode::BAD_GATEWAY,
            "OIDC token response exceeds its size limit",
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        WebAuthFlowError::new(
            StatusCode::BAD_GATEWAY,
            format!("failed to read OIDC token response: {error}"),
        )
    })? {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(WebAuthFlowError::new(
                StatusCode::BAD_GATEWAY,
                "OIDC token response exceeds its size limit",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Debug, Deserialize)]
struct OidcCallbackQuery {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    access_token: String,
}

#[derive(Debug, Serialize)]
struct WebUiPublicConfig {
    enabled: bool,
    auth_enabled: bool,
    operator_token_enabled: bool,
    provider: Option<String>,
    issuer_url: Option<String>,
    client_id: Option<String>,
    scopes: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    logout_endpoint: Option<String>,
    login_endpoint: Option<String>,
}

#[derive(Clone)]
struct ManagementAuth {
    operator_api_bearer_token: Option<Arc<str>>,
    web_ui_auth: Option<Arc<WebUiAuthConfig>>,
}

async fn require_management_auth(
    State(auth): State<Arc<ManagementAuth>>,
    request: Request,
    next: Next,
) -> Response {
    let provided = bearer_token_from_headers(request.headers());
    let operator_authenticated = auth
        .operator_api_bearer_token
        .as_deref()
        .zip(provided)
        .is_some_and(|(expected, provided)| operator_api_token_matches(expected, provided));
    let oidc_authenticated = if operator_authenticated {
        false
    } else if let (Some(oidc), Some(token)) = (auth.web_ui_auth.as_deref(), provided) {
        oidc.validate_access_token(token).await
    } else {
        false
    };
    if !operator_authenticated && !oidc_authenticated {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(ErrorResponse {
                error: "management API authentication was rejected".to_string(),
            }),
        )
            .into_response();
    }
    next.run(request).await
}

async fn ui_index() -> impl IntoResponse {
    let mut response = (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../../../webui/index.html"),
    )
        .into_response();
    apply_ui_security_headers(&mut response, true);
    response
}

async fn ui_app() -> impl IntoResponse {
    let mut response = (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../../webui/app.js"),
    )
        .into_response();
    apply_ui_security_headers(&mut response, false);
    response
}

async fn ui_styles() -> impl IntoResponse {
    let mut response = (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../../webui/styles.css"),
    )
        .into_response();
    apply_ui_security_headers(&mut response, false);
    response
}

fn apply_ui_security_headers(response: &mut Response, include_policy: bool) {
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("referrer-policy"),
        header::HeaderValue::from_static("no-referrer"),
    );
    if include_policy {
        headers.insert(
            header::HeaderName::from_static("content-security-policy"),
            header::HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            ),
        );
    }
}

async fn ui_login<S, L>(State(state): State<ControlPlaneHttpState<S, L>>) -> Response
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let Some(auth) = state.web_ui_auth.as_deref() else {
        return web_auth_flow_error_response(WebAuthFlowError::new(
            StatusCode::NOT_FOUND,
            "web OIDC authentication is not configured",
        ));
    };
    match auth.begin_login().await {
        Ok(login) => {
            let mut response = Redirect::temporary(&login.location).into_response();
            let headers = response.headers_mut();
            headers.insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );
            headers.insert(header::SET_COOKIE, login.state_cookie);
            headers.insert(
                header::HeaderName::from_static("referrer-policy"),
                header::HeaderValue::from_static("no-referrer"),
            );
            response
        }
        Err(error) => web_auth_flow_error_response(error),
    }
}

async fn ui_callback<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    headers: HeaderMap,
    Query(query): Query<OidcCallbackQuery>,
) -> Response
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let Some(auth) = state.web_ui_auth.as_deref() else {
        return web_auth_flow_error_response(WebAuthFlowError::new(
            StatusCode::NOT_FOUND,
            "web OIDC authentication is not configured",
        ));
    };
    let state_cookie = oidc_state_cookie(&headers);
    let clear_state_cookie = query.state.as_deref().is_some_and(|state| {
        state_cookie
            .as_deref()
            .is_some_and(|cookie| bounded_constant_time_matches(state, cookie, 128))
    });
    let mut response = match auth.complete_login(query, state_cookie.as_deref()).await {
        Ok(access_token) => {
            let html = oidc_callback_html(&access_token);
            let mut response = Html(html).into_response();
            let headers = response.headers_mut();
            headers.insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );
            headers.insert(
                header::HeaderName::from_static("content-security-policy"),
                header::HeaderValue::from_static(
                    "default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
                ),
            );
            headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                header::HeaderValue::from_static("nosniff"),
            );
            headers.insert(
                header::HeaderName::from_static("referrer-policy"),
                header::HeaderValue::from_static("no-referrer"),
            );
            response
        }
        Err(error) => web_auth_flow_error_response(error),
    };
    if clear_state_cookie {
        let secure_attribute = if auth
            .public_url
            .as_deref()
            .is_some_and(|url| url.starts_with("https://"))
        {
            "; Secure"
        } else {
            ""
        };
        if let Ok(cookie) = header::HeaderValue::from_str(&format!(
            "{WEB_OIDC_STATE_COOKIE}=; Path=/ui/callback; Max-Age=0; HttpOnly; SameSite=Lax{secure_attribute}"
        )) {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
        }
    }
    response
}

fn oidc_callback_html(access_token: &str) -> String {
    let token_json = serde_json::to_string(access_token)
        .unwrap_or_else(|_| "\"\"".to_string())
        .replace('<', "\\u003c");
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>HeteroNetwork Login</title><script>sessionStorage.setItem(\"{WEB_OIDC_ACCESS_TOKEN_STORAGE_KEY}\",{token_json});location.replace(\"/ui/\");</script>"
    )
}

fn oidc_state_cookie(headers: &HeaderMap) -> Option<String> {
    let mut state = None;
    for header_value in headers.get_all(header::COOKIE) {
        let header_value = header_value.to_str().ok()?;
        for pair in header_value.split(';') {
            let (name, value) = pair.trim().split_once('=')?;
            if name != WEB_OIDC_STATE_COOKIE {
                continue;
            }
            if state.is_some()
                || value.is_empty()
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return None;
            }
            state = Some(value.to_string());
        }
    }
    state
}

fn web_auth_flow_error_response(error: WebAuthFlowError) -> Response {
    let mut response = (
        error.status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(ErrorResponse {
            error: error.message,
        }),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("referrer-policy"),
        header::HeaderValue::from_static("no-referrer"),
    );
    response
}

async fn ui_config<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
) -> Json<WebUiPublicConfig>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let mut config = state
        .web_ui_auth
        .as_deref()
        .map(WebUiAuthConfig::public_config)
        .unwrap_or_else(|| WebUiPublicConfig {
            enabled: state.operator_api_bearer_token.is_some(),
            auth_enabled: false,
            operator_token_enabled: state.operator_api_bearer_token.is_some(),
            provider: None,
            issuer_url: None,
            client_id: None,
            scopes: None,
            authorization_endpoint: None,
            token_endpoint: None,
            logout_endpoint: None,
            login_endpoint: None,
        });
    config.operator_token_enabled = state.operator_api_bearer_token.is_some();
    Json(config)
}

#[derive(Debug, Deserialize)]
struct AdminPolicyRequest {
    cluster_policy: ClusterPolicy,
}

#[derive(Debug, Deserialize)]
struct AdminPathPinRequest {
    pinned: bool,
}

async fn admin_node_snapshot<S>(
    plane: &ControlPlane<S>,
) -> Result<Vec<ControlPlaneNodeOverview>, ControlPlaneError>
where
    S: ControlPlaneStore,
{
    let nodes = plane.list_nodes().await?;
    let mut snapshot = Vec::with_capacity(nodes.len());
    for node in nodes {
        snapshot.push(ControlPlaneNodeOverview {
            health: plane.health_for_node(&node.node_id).await?,
            nat_classification: plane.nat_classification_for(&node.node_id).await?,
            node,
        });
    }
    Ok(snapshot)
}

async fn admin_overview<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
) -> Result<Json<ControlPlaneOverviewResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let generated_at = Utc::now();
    let config = state.plane.config();
    Ok(Json(ControlPlaneOverviewResponse {
        cluster_id: config.cluster_id.clone(),
        vpn_pool: config.vpn_pool,
        cluster_policy: state.plane.cluster_policy()?,
        metrics: control_plane_metrics(&state).await?,
        nodes: admin_node_snapshot(&state.plane).await?,
        paths: state.plane.list_paths().await?,
        nat_discovery: state.plane.nat_discovery_overview().await?,
        service_directory: state.plane.service_directory().await?,
        generated_at,
    }))
}

async fn admin_services<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
) -> Result<Json<ipars_types::ServiceDirectory>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    Ok(Json(state.plane.service_directory().await?))
}

async fn admin_nodes<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
) -> Result<Json<Vec<ControlPlaneNodeOverview>>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    Ok(Json(admin_node_snapshot(&state.plane).await?))
}

async fn admin_paths<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
) -> Result<Json<Vec<PathRecord>>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    Ok(Json(state.plane.list_paths().await?))
}

async fn admin_policy<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
) -> Result<Json<ControlPlanePolicyResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let config = state.plane.config();
    Ok(Json(ControlPlanePolicyResponse {
        cluster_id: config.cluster_id.clone(),
        vpn_pool: config.vpn_pool,
        cluster_policy: state.plane.cluster_policy()?,
        generated_at: Utc::now(),
    }))
}

async fn update_admin_policy<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<AdminPolicyRequest>,
) -> Result<Json<ControlPlanePolicyResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let cluster_policy = state.plane.set_cluster_policy(request.cluster_policy)?;
    let config = state.plane.config();
    Ok(Json(ControlPlanePolicyResponse {
        cluster_id: config.cluster_id.clone(),
        vpn_pool: config.vpn_pool,
        cluster_policy,
        generated_at: Utc::now(),
    }))
}

async fn admin_remove_node<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Path(node_id): Path<String>,
) -> Result<Json<RemoveNodeResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    Ok(Json(
        state
            .plane
            .admin_remove_node(&NodeId::from_string(node_id))
            .await?,
    ))
}

async fn admin_pin_path<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Path((local_node_id, remote_node_id)): Path<(String, String)>,
    Json(request): Json<AdminPathPinRequest>,
) -> Result<Json<PathRecord>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    Ok(Json(
        state
            .plane
            .set_admin_path_pin(
                NodeId::from_string(local_node_id),
                NodeId::from_string(remote_node_id),
                request.pinned,
            )
            .await?,
    ))
}

async fn require_operator_api_bearer(
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
                error: "control-plane operator API bearer token was rejected".to_string(),
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
    bounded_constant_time_matches(expected, provided, MAX_OPERATOR_API_BEARER_TOKEN_BYTES)
}

fn bounded_constant_time_matches(expected: &str, provided: &str, max_bytes: usize) -> bool {
    if expected.is_empty()
        || provided.is_empty()
        || expected.len() > max_bytes
        || provided.len() > max_bytes
    {
        return false;
    }

    let expected = expected.as_bytes();
    let provided = provided.as_bytes();
    let mut diff = expected.len() ^ provided.len();
    for index in 0..max_bytes {
        let expected_byte = expected.get(index).copied().unwrap_or_default();
        let provided_byte = provided.get(index).copied().unwrap_or_default();
        diff |= usize::from(expected_byte ^ provided_byte);
    }
    diff == 0
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn metrics<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
) -> Result<Json<ControlPlaneMetricsResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    Ok(Json(control_plane_metrics(&state).await?))
}

async fn policy<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
) -> Result<Json<ControlPlanePolicyResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let config = state.plane.config();
    Ok(Json(ControlPlanePolicyResponse {
        cluster_id: config.cluster_id.clone(),
        vpn_pool: config.vpn_pool,
        cluster_policy: state.plane.cluster_policy()?,
        generated_at: Utc::now(),
    }))
}

async fn prometheus_metrics<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
) -> Result<impl IntoResponse, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let metrics = control_plane_metrics(&state).await?;
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render_prometheus_metrics(&metrics),
    ))
}

async fn control_plane_metrics<S, L>(
    state: &ControlPlaneHttpState<S, L>,
) -> Result<ControlPlaneMetricsResponse, ControlPlaneError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let mut metrics = state.plane.metrics().await?;
    let token_metrics = state
        .join_service
        .token_metrics(&metrics.cluster_id, Utc::now())
        .await?;
    apply_token_ledger_metrics(&mut metrics, token_metrics);
    Ok(metrics)
}

fn apply_token_ledger_metrics(
    metrics: &mut ControlPlaneMetricsResponse,
    token_metrics: TokenLedgerMetrics,
) {
    metrics.token_ledger_issued_count = token_metrics.issued_count;
    metrics.token_ledger_active_count = token_metrics.active_count;
    metrics.token_ledger_revoked_count = token_metrics.revoked_count;
    metrics.token_ledger_expired_count = token_metrics.expired_count;
    metrics.token_ledger_exhausted_count = token_metrics.exhausted_count;
    metrics.token_ledger_use_count = token_metrics.use_count;
}

async fn join<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<JoinNodeRequest>,
) -> Result<(StatusCode, Json<RegisterNodeResponse>), ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let response = state
        .join_service
        .join(request.token, request.registration, Utc::now())
        .await?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn revoke_token<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<RevokeTokenRequest>,
) -> Result<Json<RevokeTokenResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let outcome = state
        .join_service
        .revoke_token(&request, Utc::now())
        .await?;
    Ok(Json(RevokeTokenResponse {
        revocation: outcome.revocation,
        record: outcome.record,
        status: ipars_types::TokenStatus::Revoked,
    }))
}

async fn authenticate_signal_node_upsert<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<SignalNodeUpsertRequest>,
) -> Result<Json<SignalNodeAuthenticationResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let authenticated_at = Utc::now();
    let node = state
        .plane
        .authenticate_signal_node_upsert(&request, authenticated_at)
        .await?;
    Ok(Json(SignalNodeAuthenticationResponse {
        node,
        authenticated_at,
    }))
}

async fn peers<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<ControlPlaneNodeQueryRequest>,
) -> Result<Json<PeerMap>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    state
        .plane
        .authenticate_node_query(&request, ControlPlaneNodeQueryKind::PeerMap, Utc::now())
        .await?;
    let response = state.plane.peer_map_for(&request.node_id).await?;
    Ok(Json(response))
}

async fn paths<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<ControlPlaneNodeQueryRequest>,
) -> Result<Json<ControlPlanePathsResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    state
        .plane
        .authenticate_node_query(&request, ControlPlaneNodeQueryKind::Paths, Utc::now())
        .await?;
    let response = state.plane.paths_for(&request.node_id).await?;
    Ok(Json(response))
}

async fn remove_node<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Path(node_id): Path<String>,
    Json(request): Json<RemoveNodeRequest>,
) -> Result<Json<RemoveNodeResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let path_node_id = NodeId::from_string(node_id);
    if request.node_id != path_node_id {
        return Err(ControlPlaneError::NodeUpdateRejected {
            node_id: request.node_id.clone(),
            reason: format!(
                "path node ID {path_node_id} does not match request node ID {}",
                request.node_id
            ),
        }
        .into());
    }
    let response = state.plane.remove_node(request).await?;
    Ok(Json(response))
}

async fn heartbeat<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    Ok(Json(state.plane.heartbeat(request).await?))
}

async fn rotate_wireguard_key<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Path(node_id): Path<String>,
    Json(request): Json<RotateWireGuardKeyRequest>,
) -> Result<Json<RotateWireGuardKeyResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let path_node_id = NodeId::from_string(node_id);
    if request.node_id != path_node_id {
        return Err(ControlPlaneError::NodeUpdateRejected {
            node_id: request.node_id.clone(),
            reason: format!(
                "path node ID {path_node_id} does not match request node ID {}",
                request.node_id
            ),
        }
        .into());
    }
    Ok(Json(state.plane.rotate_wireguard_key(request).await?))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

fn render_prometheus_metrics(metrics: &ControlPlaneMetricsResponse) -> String {
    let cluster_id = prometheus_label(metrics.cluster_id.as_str());
    let mut body = String::new();
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_metrics_generated_timestamp_seconds Unix timestamp of the control-plane metrics snapshot."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_metrics_generated_timestamp_seconds gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_metrics_generated_timestamp_seconds{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.generated_at.timestamp().max(0)
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_nodes Number of registered nodes."
    );
    prometheus_line!(&mut body, "# TYPE ipars_control_plane_nodes gauge");
    prometheus_line!(
        &mut body,
        "ipars_control_plane_nodes{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.node_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_relay_candidates Number of relay-capable registered nodes."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_relay_candidates gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_relay_candidates{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.relay_candidate_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_ha_ready Whether every required public service has at least two active instances."
    );
    prometheus_line!(&mut body, "# TYPE ipars_control_plane_ha_ready gauge");
    prometheus_line!(
        &mut body,
        "ipars_control_plane_ha_ready{{cluster_id=\"{cluster_id}\"}} {}",
        usize::from(metrics.ha_ready)
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_service_instances Number of active leased public service instances."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_service_instances gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_service_instances{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.active_service_instance_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_service_endpoints Active leased instances by public service kind."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_service_endpoints gauge"
    );
    for (service, count) in [
        ("control_plane", metrics.active_control_plane_count),
        ("signal", metrics.active_signal_count),
        ("stun", metrics.active_stun_count),
        ("relay", metrics.active_relay_count),
    ] {
        prometheus_line!(
            &mut body,
            "ipars_control_plane_service_endpoints{{cluster_id=\"{cluster_id}\",service=\"{service}\"}} {count}"
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_stale_endpoint_candidates Number of endpoint candidates older than the control-plane candidate TTL."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_stale_endpoint_candidates gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_stale_endpoint_candidates{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.stale_endpoint_candidate_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_endpoint_candidate_ttl_seconds Endpoint candidate freshness window used by control-plane peer maps."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_endpoint_candidate_ttl_seconds gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_endpoint_candidate_ttl_seconds{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.endpoint_candidate_ttl_seconds
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_path_state_ttl_seconds Path-state freshness window used by control-plane status and metrics."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_path_state_ttl_seconds gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_path_state_ttl_seconds{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.path_state_ttl_seconds
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_vpn_pool_total Usable VPN IP addresses in the configured pool."
    );
    prometheus_line!(&mut body, "# TYPE ipars_control_plane_vpn_pool_total gauge");
    prometheus_line!(
        &mut body,
        "ipars_control_plane_vpn_pool_total{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.vpn_pool_total_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_vpn_pool_allocated Allocated VPN IP addresses in the configured pool."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_vpn_pool_allocated gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_vpn_pool_allocated{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.vpn_pool_allocated_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_vpn_pool_available Unallocated usable VPN IP addresses in the configured pool."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_vpn_pool_available gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_vpn_pool_available{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.vpn_pool_available_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_join_tokens Issued join tokens by current status."
    );
    prometheus_line!(&mut body, "# TYPE ipars_control_plane_join_tokens gauge");
    for (status, count) in [
        ("active", metrics.token_ledger_active_count),
        ("revoked", metrics.token_ledger_revoked_count),
        ("expired", metrics.token_ledger_expired_count),
        ("exhausted", metrics.token_ledger_exhausted_count),
    ] {
        prometheus_line!(
            &mut body,
            "ipars_control_plane_join_tokens{{cluster_id=\"{cluster_id}\",status=\"{status}\"}} {count}"
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_join_tokens_issued Total join-token ledger records."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_join_tokens_issued gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_join_tokens_issued{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.token_ledger_issued_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_join_token_uses Total accepted join-token uses recorded by the ledger."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_join_token_uses gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_join_token_uses{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.token_ledger_use_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_wireguard_key_rotations_total Control-plane WireGuard key rotation requests by result."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_wireguard_key_rotations_total counter"
    );
    for (result, count) in [
        ("success", metrics.wireguard_key_rotation_success_count),
        ("failure", metrics.wireguard_key_rotation_failure_count),
    ] {
        prometheus_line!(
            &mut body,
            "ipars_control_plane_wireguard_key_rotations_total{{cluster_id=\"{cluster_id}\",result=\"{result}\"}} {count}"
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_node_removals_total Control-plane signed node removal requests by result."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_node_removals_total counter"
    );
    for (result, count) in [
        ("success", metrics.node_removal_success_count),
        ("failure", metrics.node_removal_failure_count),
    ] {
        prometheus_line!(
            &mut body,
            "ipars_control_plane_node_removals_total{{cluster_id=\"{cluster_id}\",result=\"{result}\"}} {count}"
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_peer_map_candidates Source-target peer-map candidates before ACL filtering."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_peer_map_candidates gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_peer_map_candidates{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.peer_map_candidate_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_peer_map_visible Source-target peer-map entries visible after ACL filtering."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_peer_map_visible gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_peer_map_visible{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.peer_map_visible_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_peer_map_acl_denied Source-target peer-map entries hidden by ACL filtering."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_peer_map_acl_denied gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_peer_map_acl_denied{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.peer_map_acl_denied_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_peer_map_route_candidates Advertised route candidates considered for peer maps before ACL filtering."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_peer_map_route_candidates gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_peer_map_route_candidates{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.peer_map_route_candidate_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_peer_map_routes_visible Advertised routes visible in peer maps after ACL filtering."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_peer_map_routes_visible gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_peer_map_routes_visible{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.peer_map_route_visible_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_peer_map_routes_acl_denied Advertised routes hidden by peer-map ACL filtering."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_peer_map_routes_acl_denied gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_peer_map_routes_acl_denied{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.peer_map_route_acl_denied_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_node_health Registered nodes by last reported health."
    );
    prometheus_line!(&mut body, "# TYPE ipars_control_plane_node_health gauge");
    prometheus_line!(
        &mut body,
        "ipars_control_plane_node_health{{cluster_id=\"{cluster_id}\",state=\"healthy\"}} {}",
        metrics.healthy_node_count
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_node_health{{cluster_id=\"{cluster_id}\",state=\"degraded\"}} {}",
        metrics.degraded_node_count
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_node_health{{cluster_id=\"{cluster_id}\",state=\"unhealthy\"}} {}",
        metrics.unhealthy_node_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_paths Number of pair-scoped paths persisted by the control plane."
    );
    prometheus_line!(&mut body, "# TYPE ipars_control_plane_paths gauge");
    prometheus_line!(
        &mut body,
        "ipars_control_plane_paths{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.path_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_stale_paths Number of pair-scoped paths older than the control-plane path-state TTL."
    );
    prometheus_line!(&mut body, "# TYPE ipars_control_plane_stale_paths gauge");
    prometheus_line!(
        &mut body,
        "ipars_control_plane_stale_paths{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.stale_path_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_path_state_count Pair-scoped paths by selected state."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_path_state_count gauge"
    );
    for state_count in &metrics.path_state_counts {
        prometheus_line!(
            &mut body,
            "ipars_control_plane_path_state_count{{cluster_id=\"{cluster_id}\",state=\"{}\"}} {}",
            path_state_label(state_count.state),
            state_count.count
        );
    }
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

fn prometheus_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[derive(Debug)]
pub struct ApiError(ControlPlaneError);

impl From<ControlPlaneError> for ApiError {
    fn from(error: ControlPlaneError) -> Self {
        Self(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            ControlPlaneError::JoinDenied
            | ControlPlaneError::RelayDenied
            | ControlPlaneError::RouteDenied(_)
            | ControlPlaneError::TokenRejected { .. } => StatusCode::FORBIDDEN,
            ControlPlaneError::TokenNotFound(_) | ControlPlaneError::IssuerKeyNotFound { .. } => {
                StatusCode::UNAUTHORIZED
            }
            ControlPlaneError::NodeSignatureRequired(_)
            | ControlPlaneError::NodeSignatureRejected { .. } => StatusCode::UNAUTHORIZED,
            ControlPlaneError::NodeRequestReplay(_) => StatusCode::CONFLICT,
            ControlPlaneError::NodeRequestAuthenticationCapacity => StatusCode::SERVICE_UNAVAILABLE,
            ControlPlaneError::TokenVerification(_) => StatusCode::UNAUTHORIZED,
            ControlPlaneError::NodeAlreadyExists(_)
            | ControlPlaneError::VpnIpAlreadyAllocated(_) => StatusCode::CONFLICT,
            ControlPlaneError::NodeUpdateRejected { .. }
            | ControlPlaneError::NodeRegistrationRejected { .. } => StatusCode::FORBIDDEN,
            ControlPlaneError::NodeNotFound(_) => StatusCode::NOT_FOUND,
            ControlPlaneError::PathNotFound { .. } => StatusCode::NOT_FOUND,
            ControlPlaneError::InvalidClusterPolicy(_) => StatusCode::BAD_REQUEST,
            ControlPlaneError::VpnPoolExhausted | ControlPlaneError::Store(_) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        };
        let body = Json(ErrorResponse {
            error: self.0.to_string(),
        });
        (status, body).into_response()
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
    use ipars_control_plane::{
        ControlPlaneConfig, ControlPlaneJoinService, InMemoryStore, InMemoryTokenLedger,
        IssuerKeyRing,
    };
    use ipars_crypto::{encode_bytes, IdentityKeyPair};
    use ipars_types::api::{
        ControlPlaneMetricsResponse, ControlPlaneNodeQueryKind, ControlPlaneNodeQueryRequest,
        ControlPlaneOverviewResponse, ControlPlanePathsResponse, ControlPlanePolicyResponse,
        HeartbeatRequest, HeartbeatResponse, JoinNodeRequest, RegisterNodeRequest,
        RegisterNodeResponse, RemoveNodeRequest, RemoveNodeResponse, RevokeTokenRequest,
        RevokeTokenResponse, RotateWireGuardKeyRequest, RotateWireGuardKeyResponse,
        SignalNodeAuthenticationResponse, SignalNodeUpsertRequest,
    };
    use ipars_types::{
        AclAction, AclRule, BootstrapEndpoint, BootstrapEndpointKind, CandidateSource, ClusterId,
        EndpointCandidate, EndpointCandidateKind, HealthState, JoinTokenClaims, KeyId,
        NatClassification, NatProbeObservation, NodeHealth, NodeId, PathMetrics, PathRecord,
        PathScore, PathState, PeerPathKey, Role, Tag, TokenPolicy, TokenStatus, TransportProtocol,
    };
    use ipnet::Ipv4Net;
    use tower::ServiceExt;

    const OPERATOR_API_BEARER_TOKEN: &str = "control-plane-test-operator-token-32-bytes";

    use super::*;

    #[test]
    fn web_auth_config_derives_keycloak_and_cognito_endpoints() {
        let keycloak = match WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "http://localhost:8080/realms/heteronetwork".to_string(),
            "heteronetwork-web".to_string(),
            None,
            "openid profile email".to_string(),
        ) {
            Ok(config) => config,
            Err(error) => panic!("keycloak config should be valid: {error}"),
        };
        let keycloak_config = keycloak.public_config();
        assert_eq!(
            keycloak_config.authorization_endpoint.as_deref(),
            Some("http://localhost:8080/realms/heteronetwork/protocol/openid-connect/auth")
        );
        assert_eq!(keycloak_config.login_endpoint, None);
        let cognito = match WebUiAuthConfig::new(
            WebAuthProvider::Cognito,
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example".to_string(),
            "heteronetwork-web".to_string(),
            Some("https://login.example.com".to_string()),
            "openid".to_string(),
        ) {
            Ok(config) => config,
            Err(error) => panic!("cognito config should be valid: {error}"),
        };
        let cognito_config = cognito.public_config();
        assert_eq!(
            cognito_config.authorization_endpoint.as_deref(),
            Some("https://login.example.com/oauth2/authorize")
        );
        assert_eq!(
            cognito_config.token_endpoint.as_deref(),
            Some("https://login.example.com/oauth2/token")
        );
        assert!(WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "ftp://localhost/realm".to_string(),
            "heteronetwork-web".to_string(),
            None,
            "openid".to_string(),
        )
        .is_err());
        assert!(WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "http://203.0.113.10:8080/realms/ipars".to_string(),
            "ipars-web".to_string(),
            None,
            "openid".to_string(),
        )
        .is_err());
    }

    #[tokio::test]
    async fn server_side_oidc_login_uses_public_callback_and_pkce() {
        let config = WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "http://localhost:8080/realms/ipars".to_string(),
            "ipars-web".to_string(),
            None,
            "openid profile email".to_string(),
        )
        .and_then(|config| config.with_public_url("http://100.64.0.10:8443".to_string()))
        .unwrap_or_else(|error| panic!("server-side OIDC config should be valid: {error}"));
        assert!(config
            .clone()
            .with_public_url("http://203.0.113.10:8443".to_string())
            .is_err());
        assert_eq!(
            config.public_config().login_endpoint.as_deref(),
            Some("/ui/login")
        );

        let login = config
            .begin_login()
            .await
            .unwrap_or_else(|error| panic!("OIDC login should begin: {}", error.message));
        let state_cookie = login
            .state_cookie
            .to_str()
            .unwrap_or_else(|error| panic!("OIDC state cookie should be ASCII: {error}"));
        assert!(state_cookie.starts_with("heteronetwork_oidc_state="));
        assert!(state_cookie.contains("; HttpOnly; SameSite=Lax"));
        assert!(!state_cookie.contains("; Secure"));
        let location = Url::parse(&login.location)
            .unwrap_or_else(|error| panic!("authorization URL should parse: {error}"));
        let query = location.query_pairs().collect::<HashMap<_, _>>();
        assert_eq!(
            query.get("client_id").map(|value| value.as_ref()),
            Some("ipars-web")
        );
        assert_eq!(
            query.get("redirect_uri").map(|value| value.as_ref()),
            Some("http://100.64.0.10:8443/ui/callback")
        );
        assert_eq!(
            query
                .get("code_challenge_method")
                .map(|value| value.as_ref()),
            Some("S256")
        );
        assert!(query.get("state").is_some_and(|value| value.len() >= 32));
        assert!(query
            .get("code_challenge")
            .is_some_and(|value| value.len() >= 43));
        assert_eq!(config.login_states.lock().await.len(), 1);

        let valid_state = query
            .get("state")
            .map(|value| value.to_string())
            .unwrap_or_else(|| panic!("authorization URL should contain state"));
        let error = match config
            .complete_login(
                OidcCallbackQuery {
                    state: Some(valid_state),
                    code: Some("code".to_string()),
                    error: None,
                    error_description: None,
                },
                None,
            )
            .await
        {
            Ok(_) => panic!("a callback without the browser-bound cookie must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(config.login_states.lock().await.len(), 1);

        let error = match config
            .complete_login(
                OidcCallbackQuery {
                    state: Some("unknown".to_string()),
                    code: Some("code".to_string()),
                    error: None,
                    error_description: None,
                },
                Some("unknown"),
            )
            .await
        {
            Ok(_) => panic!("an unknown state must be rejected before token exchange"),
            Err(error) => error,
        };
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn server_side_oidc_callback_uses_current_ui_storage_key() {
        let html = oidc_callback_html("access-token");
        assert!(html.contains("sessionStorage.setItem(\"heteronetwork_access_token\""));
        assert!(!html.contains("ipars_access_token"));
    }

    fn claims(cluster_id: ClusterId, issuer: NodeId, key_id: KeyId) -> JoinTokenClaims {
        let now = Utc::now();
        let mut tags = BTreeSet::new();
        tags.insert(Tag::from_string("edge"));
        JoinTokenClaims {
            cluster_id,
            bootstrap_endpoints: vec![BootstrapEndpoint {
                url: "https://203.0.113.10:8443".to_string(),
                kind: BootstrapEndpointKind::ControlPlane,
            }],
            expires_at: now + chrono::Duration::minutes(5),
            not_before: now - chrono::Duration::seconds(1),
            role: Role::edge(),
            tags,
            issuer,
            key_id,
            policy: TokenPolicy::default(),
            nonce: "http-join".to_string(),
        }
    }

    fn registration(node_id: &str) -> RegisterNodeRequest {
        let identity = identity_for_node(node_id);
        RegisterNodeRequest {
            node_id: identity.node_id(),
            identity_public_key: identity.public_key_b64(),
            wireguard_public_key: wireguard_public_key_for_node(node_id),
            candidates: Vec::new(),
            nat_classification: None,
            relay_capability: None,
            requested_routes: Vec::new(),
        }
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

    fn wireguard_public_key_for_node(node_id: &str) -> String {
        let mut bytes = [0_u8; 32];
        for (index, byte) in format!("wg-{node_id}").as_bytes().iter().enumerate() {
            bytes[index % 32] = bytes[index % 32].wrapping_add(*byte);
        }
        if bytes.iter().all(|byte| *byte == 0) {
            bytes[0] = 1;
        }
        encode_bytes(&bytes)
    }

    fn node_id(label: &str) -> NodeId {
        identity_for_node(label).node_id()
    }

    fn candidate(node_id: &str) -> EndpointCandidate {
        EndpointCandidate {
            node_id: self::node_id(node_id),
            kind: EndpointCandidateKind::StunReflexive,
            addr: std::net::SocketAddr::from(([203, 0, 113, 10], 51820)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::StunProbe,
        }
    }

    fn signed_heartbeat(label: &str, request: HeartbeatRequest) -> HeartbeatRequest {
        signed_heartbeat_at(label, request, Utc::now())
    }

    fn signed_heartbeat_at(
        label: &str,
        mut request: HeartbeatRequest,
        signed_at: chrono::DateTime<Utc>,
    ) -> HeartbeatRequest {
        let identity = identity_for_node(label);
        request.node_signature = Some(match identity.sign_heartbeat_request(&request, signed_at) {
            Ok(signature) => signature,
            Err(error) => panic!("test identity should sign heartbeat: {error}"),
        });
        request
    }

    fn path(local: &str, remote: &str) -> PathRecord {
        PathRecord {
            key: PeerPathKey::new(node_id(local), node_id(remote)),
            selected_state: PathState::DirectNatTraversal,
            selected_candidate: None,
            relay_node: None,
            score: PathScore::calculate(
                PathState::DirectNatTraversal,
                &PathMetrics::default(),
                true,
                0,
            ),
            updated_at: Utc::now(),
            pinned: false,
        }
    }

    fn signed_wireguard_key_rotation(
        label: &str,
        previous_wireguard_public_key: String,
        next_wireguard_public_key: String,
    ) -> RotateWireGuardKeyRequest {
        let identity = identity_for_node(label);
        let mut request = RotateWireGuardKeyRequest {
            node_id: identity.node_id(),
            previous_wireguard_public_key,
            next_wireguard_public_key,
            node_signature: None,
        };
        request.node_signature = Some(
            match identity.sign_wireguard_key_rotation_request(&request, Utc::now()) {
                Ok(signature) => signature,
                Err(error) => panic!("test identity should sign wireguard key rotation: {error}"),
            },
        );
        request
    }

    fn signed_node_query(
        label: &str,
        kind: ControlPlaneNodeQueryKind,
    ) -> ControlPlaneNodeQueryRequest {
        let identity = identity_for_node(label);
        let mut request = ControlPlaneNodeQueryRequest {
            node_id: identity.node_id(),
            request_signature: None,
        };
        request.request_signature = Some(
            match identity.sign_control_plane_node_query_request(&request, kind, Utc::now()) {
                Ok(signature) => signature,
                Err(error) => panic!("test identity should sign node query: {error}"),
            },
        );
        request
    }

    fn signed_remove_node(label: &str) -> RemoveNodeRequest {
        let identity = identity_for_node(label);
        let mut request = RemoveNodeRequest {
            node_id: identity.node_id(),
            node_signature: None,
        };
        request.node_signature = Some(
            match identity.sign_remove_node_request(&request, Utc::now()) {
                Ok(signature) => signature,
                Err(error) => panic!("test identity should sign node removal: {error}"),
            },
        );
        request
    }

    fn signed_token_revocation(
        issuer: &IdentityKeyPair,
        cluster_id: ClusterId,
        nonce: String,
        key_id: KeyId,
    ) -> RevokeTokenRequest {
        let mut request = RevokeTokenRequest {
            cluster_id,
            nonce,
            issuer: issuer.node_id(),
            key_id,
            issuer_signature: None,
        };
        request.issuer_signature = Some(
            match issuer.sign_token_revocation_request(&request, Utc::now()) {
                Ok(signature) => signature,
                Err(error) => panic!("test issuer should sign token revocation: {error}"),
            },
        );
        request
    }

    fn nat_classification(
        local_addr: SocketAddr,
        stun_server: SocketAddr,
        reflexive_addrs: &[SocketAddr],
    ) -> NatClassification {
        let assessed_at = Utc::now();
        NatClassification::from_observations(
            local_addr,
            reflexive_addrs
                .iter()
                .enumerate()
                .map(|(index, reflexive_addr)| NatProbeObservation {
                    local_addr,
                    stun_server: SocketAddr::new(
                        stun_server.ip(),
                        stun_server.port() + index as u16,
                    ),
                    reflexive_addr: *reflexive_addr,
                    observed_at: assessed_at,
                })
                .collect(),
            assessed_at,
        )
    }

    #[tokio::test]
    async fn http_admin_overview_updates_for_three_node_nat_discovery(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("root");
        let cluster_id = ClusterId::new();
        let store = Arc::new(InMemoryStore::default());
        let ledger = Arc::new(InMemoryTokenLedger::default());
        let plane = Arc::new(ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store,
        ));
        let mut key_ring = IssuerKeyRing::default();
        key_ring.insert(issuer.node_id(), key_id.clone(), issuer.public_key_b64());
        let join_service = Arc::new(ControlPlaneJoinService::new(
            plane.clone(),
            ledger,
            key_ring,
        ));
        let app = router(
            ControlPlaneHttpState::new(plane, join_service)
                .require_operator_api_bearer_token(OPERATOR_API_BEARER_TOKEN.to_string()),
        );
        let public_endpoint = SocketAddr::from(([203, 0, 113, 10], 40_000));
        let nat_endpoint = SocketAddr::from(([203, 0, 113, 11], 40_001));
        let relay_endpoint_a = SocketAddr::from(([203, 0, 113, 12], 40_002));
        let relay_endpoint_b = SocketAddr::from(([203, 0, 113, 13], 40_003));
        let classifications = [
            (
                "node-public",
                nat_classification(
                    public_endpoint,
                    SocketAddr::from(([198, 51, 100, 1], 3478)),
                    &[public_endpoint, public_endpoint],
                ),
            ),
            (
                "node-nat",
                nat_classification(
                    SocketAddr::from(([10, 0, 0, 11], 51_001)),
                    SocketAddr::from(([198, 51, 100, 1], 3478)),
                    &[nat_endpoint, nat_endpoint],
                ),
            ),
            (
                "node-relay",
                nat_classification(
                    SocketAddr::from(([10, 0, 0, 12], 51_002)),
                    SocketAddr::from(([198, 51, 100, 2], 3478)),
                    &[relay_endpoint_a, relay_endpoint_b],
                ),
            ),
        ];
        for (label, classification) in classifications {
            let mut token_claims = claims(cluster_id.clone(), issuer.node_id(), key_id.clone());
            token_claims.nonce = format!("nat-{label}");
            let mut registration = registration(label);
            registration.nat_classification = Some(classification);
            let request = JoinNodeRequest {
                token: issuer.sign_join_token(token_claims)?,
                registration,
            };
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/join")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(serde_json::to_vec(&request)?))?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/overview")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let overview: ControlPlaneOverviewResponse =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)?;
        assert_eq!(overview.nodes.len(), 3);
        assert_eq!(overview.nat_discovery.nat_classification_count, 3);
        assert!(overview
            .nodes
            .iter()
            .all(|entry| entry.nat_classification.is_some()));
        assert!(overview
            .nat_discovery
            .fresh_nat_classification_strategy_counts
            .iter()
            .any(|entry| entry.count > 0));

        let mut updated = nat_classification(
            SocketAddr::from(([10, 0, 0, 12], 51_002)),
            SocketAddr::from(([198, 51, 100, 2], 3478)),
            &[relay_endpoint_a, relay_endpoint_a],
        );
        updated.assessed_at = Utc::now();
        let heartbeat = signed_heartbeat(
            "node-relay",
            HeartbeatRequest {
                node_id: node_id("node-relay"),
                health: NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now(),
                    latency_ms: None,
                    relay_load: None,
                    message: None,
                },
                candidates: Vec::new(),
                relay_capability: None,
                routes: None,
                path_state: Vec::new(),
                nat_classification: Some(updated),
                node_signature: None,
            },
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/heartbeat")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&heartbeat)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/overview")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        let overview: ControlPlaneOverviewResponse =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)?;
        let relay_node = overview
            .nodes
            .iter()
            .find(|entry| entry.node.node_id == node_id("node-relay"))
            .ok_or("updated node missing from overview")?;
        assert_eq!(
            relay_node
                .nat_classification
                .as_ref()
                .map(|classification| classification.observed_endpoint),
            Some(Some(relay_endpoint_a))
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_heartbeat_rejects_direct_path_candidate_kind_mismatch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("root");
        let cluster_id = ClusterId::new();
        let store = Arc::new(InMemoryStore::default());
        let ledger = Arc::new(InMemoryTokenLedger::default());
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(std::net::Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = Arc::new(ControlPlane::new(config, store));
        let mut key_ring = IssuerKeyRing::default();
        key_ring.insert(issuer.node_id(), key_id.clone(), issuer.public_key_b64());
        let join_service = Arc::new(ControlPlaneJoinService::new(
            plane.clone(),
            ledger,
            key_ring,
        ));
        let app = router(ControlPlaneHttpState::new(plane.clone(), join_service));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/metrics")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut claims = claims(cluster_id, issuer.node_id(), key_id);
        claims.nonce = "http-path-node".to_string();
        plane
            .register_with_claims(claims, registration("node-http"))
            .await?;

        let mut reported_path = path("node-http", "node-peer");
        reported_path.selected_state = PathState::DirectPublic;
        reported_path.selected_candidate = Some(candidate("node-peer"));

        let heartbeat = signed_heartbeat(
            "node-http",
            HeartbeatRequest {
                node_id: node_id("node-http"),
                health: NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now(),
                    latency_ms: Some(1.0),
                    relay_load: None,
                    message: None,
                },
                candidates: Vec::new(),
                relay_capability: None,
                routes: None,
                path_state: vec![reported_path],
                nat_classification: None,
                node_signature: None,
            },
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/heartbeat")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&heartbeat)?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("selected state DirectPublic"));
        assert!(body.contains("selected candidate kind StunReflexive"));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/paths/query")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&signed_node_query(
                        "node-http",
                        ControlPlaneNodeQueryKind::Paths,
                    ))?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let paths: ControlPlanePathsResponse = serde_json::from_slice(&body)?;
        assert!(paths.paths.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn http_join_registers_node() -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("root");
        let cluster_id = ClusterId::new();
        let store = Arc::new(InMemoryStore::default());
        let ledger = Arc::new(InMemoryTokenLedger::default());
        let vpn_pool = Ipv4Net::new(std::net::Ipv4Addr::new(100, 64, 0, 0), 29)?;
        let mut config = ControlPlaneConfig::new(cluster_id.clone(), vpn_pool);
        config.cluster_policy.allow_relay_fallback = false;
        let mut from_roles = BTreeSet::new();
        from_roles.insert(Role::edge());
        config.cluster_policy.acl_rules = vec![AclRule {
            id: "allow-edge".to_string(),
            from_roles,
            from_tags: BTreeSet::new(),
            to_roles: BTreeSet::new(),
            to_tags: BTreeSet::new(),
            routes: Vec::new(),
            protocol: TransportProtocol::Any,
            action: AclAction::Allow,
        }];
        let plane = Arc::new(ControlPlane::new(config, store));
        let mut key_ring = IssuerKeyRing::default();
        key_ring.insert(issuer.node_id(), key_id.clone(), issuer.public_key_b64());
        let join_service = Arc::new(ControlPlaneJoinService::new(
            plane.clone(),
            ledger,
            key_ring,
        ));
        let app = router(
            ControlPlaneHttpState::new(plane.clone(), join_service)
                .require_operator_api_bearer_token(OPERATOR_API_BEARER_TOKEN.to_string()),
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/policy")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE),
            Some(&header::HeaderValue::from_static("Bearer"))
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/metrics")
                    .header(header::AUTHORIZATION, "Bearer wrong-operator-token")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/policy")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let policy: ControlPlanePolicyResponse = serde_json::from_slice(&body)?;
        assert_eq!(policy.cluster_id, cluster_id);
        assert_eq!(policy.vpn_pool, vpn_pool);
        assert!(!policy.cluster_policy.allow_relay_fallback);
        assert_eq!(policy.cluster_policy.acl_rules.len(), 1);
        assert_eq!(policy.cluster_policy.acl_rules[0].id, "allow-edge");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/overview")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/overview")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let overview: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)?;
        assert_eq!(overview["cluster_policy"]["allow_relay_fallback"], false);
        assert_eq!(overview["metrics"]["ha_ready"], false);
        assert_eq!(
            overview["service_directory"]["cluster_id"],
            cluster_id.as_str()
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/services")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/services")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let services: ipars_types::ServiceDirectory =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)?;
        assert_eq!(services.cluster_id, cluster_id);
        assert!(services.instances.is_empty());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/ui/")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("script-src 'self'")));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("HeteroNetwork"));
        assert!(body.contains("Public nodes"));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/ui/app.js")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("function renderServices()"));
        assert!(body.contains("service_directory"));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/ui/config")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let ui_config: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)?;
        assert_eq!(ui_config["enabled"], true);
        assert_eq!(ui_config["operator_token_enabled"], true);

        let request_body = JoinNodeRequest {
            token: issuer.sign_join_token(claims(
                cluster_id.clone(),
                issuer.node_id(),
                key_id.clone(),
            ))?,
            registration: registration("node-http"),
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/join")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&request_body)?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response: RegisterNodeResponse = serde_json::from_slice(&body)?;
        assert_eq!(response.node.node_id, node_id("node-http"));

        let mut signal_upsert = SignalNodeUpsertRequest {
            node: response.node.clone(),
            nat_classification: None,
            health: Some(NodeHealth {
                state: HealthState::Healthy,
                last_seen_at: Utc::now(),
                latency_ms: None,
                relay_load: None,
                message: None,
            }),
            request_signature: None,
        };
        let unsigned_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/nodes/authenticate-signal-upsert")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&signal_upsert)?))?,
            )
            .await?;
        assert_eq!(unsigned_response.status(), StatusCode::UNAUTHORIZED);

        let node_identity = identity_for_node("node-http");
        signal_upsert.request_signature =
            Some(node_identity.sign_signal_node_upsert_request(&signal_upsert, Utc::now())?);
        let authenticated_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/nodes/authenticate-signal-upsert")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&signal_upsert)?))?,
            )
            .await?;
        assert_eq!(authenticated_response.status(), StatusCode::OK);
        let authenticated_body =
            axum::body::to_bytes(authenticated_response.into_body(), usize::MAX).await?;
        let authenticated: SignalNodeAuthenticationResponse =
            serde_json::from_slice(&authenticated_body)?;
        assert_eq!(authenticated.node, response.node);

        signal_upsert.health = None;
        let tampered_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/nodes/authenticate-signal-upsert")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&signal_upsert)?))?,
            )
            .await?;
        assert_eq!(tampered_response.status(), StatusCode::UNAUTHORIZED);

        let previous_wireguard_public_key = response.node.wireguard_public_key.clone();
        let next_wireguard_public_key = wireguard_public_key_for_node("node-http-rotated");

        let rotation = signed_wireguard_key_rotation(
            "node-http",
            previous_wireguard_public_key,
            next_wireguard_public_key.clone(),
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/nodes/{}/wireguard-key", node_id("node-http")))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&rotation)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response: RotateWireGuardKeyResponse = serde_json::from_slice(&body)?;
        assert_eq!(
            response.node.wireguard_public_key,
            next_wireguard_public_key
        );

        let unsigned_revocation = RevokeTokenRequest {
            cluster_id: request_body.token.claims.cluster_id.clone(),
            nonce: request_body.token.claims.nonce.clone(),
            issuer: issuer.node_id(),
            key_id: key_id.clone(),
            issuer_signature: None,
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens/revoke")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&unsigned_revocation)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let revocation = signed_token_revocation(
            &issuer,
            request_body.token.claims.cluster_id.clone(),
            request_body.token.claims.nonce.clone(),
            key_id,
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens/revoke")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&revocation)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response: RevokeTokenResponse = serde_json::from_slice(&body)?;
        assert_eq!(response.status, TokenStatus::Revoked);
        assert!(response.record.is_some());
        assert_eq!(response.revocation.nonce, request_body.token.claims.nonce);

        let rejected_join = JoinNodeRequest {
            token: request_body.token.clone(),
            registration: registration("node-revoked"),
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/join")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&rejected_join)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let heartbeat = signed_heartbeat(
            "node-http",
            HeartbeatRequest {
                node_id: node_id("node-http"),
                health: NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now(),
                    latency_ms: Some(1.0),
                    relay_load: None,
                    message: None,
                },
                candidates: Vec::new(),
                relay_capability: None,
                routes: None,
                path_state: Vec::new(),
                nat_classification: None,
                node_signature: None,
            },
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/heartbeat")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&heartbeat)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response: HeartbeatResponse = serde_json::from_slice(&body)?;
        assert!(response.accepted);

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
        let metrics: ControlPlaneMetricsResponse = serde_json::from_slice(&body)?;
        assert_eq!(metrics.node_count, 1);
        assert_eq!(metrics.healthy_node_count, 1);
        assert_eq!(metrics.stale_endpoint_candidate_count, 0);
        assert_eq!(metrics.endpoint_candidate_ttl_seconds, 120);
        assert_eq!(metrics.stale_path_count, 0);
        assert_eq!(metrics.path_state_ttl_seconds, 600);
        assert_eq!(metrics.path_state_counts.len(), 5);
        assert!(metrics
            .path_state_counts
            .iter()
            .all(|entry| entry.count == 0));
        assert_eq!(metrics.vpn_pool_total_count, 6);
        assert_eq!(metrics.vpn_pool_allocated_count, 1);
        assert_eq!(metrics.vpn_pool_available_count, 5);
        assert_eq!(metrics.token_ledger_issued_count, 1);
        assert_eq!(metrics.token_ledger_active_count, 0);
        assert_eq!(metrics.token_ledger_revoked_count, 1);
        assert_eq!(metrics.token_ledger_expired_count, 0);
        assert_eq!(metrics.token_ledger_exhausted_count, 0);
        assert_eq!(metrics.token_ledger_use_count, 1);
        assert_eq!(metrics.wireguard_key_rotation_success_count, 1);
        assert_eq!(metrics.wireguard_key_rotation_failure_count, 0);
        assert_eq!(metrics.node_removal_success_count, 0);
        assert_eq!(metrics.node_removal_failure_count, 0);

        let mut peer_claims = claims(
            request_body.token.claims.cluster_id.clone(),
            issuer.node_id(),
            KeyId::from_string("root"),
        );
        peer_claims.nonce = "http-peer".to_string();
        plane
            .register_with_claims(peer_claims, registration("node-peer"))
            .await?;

        let unsigned_query = ControlPlaneNodeQueryRequest {
            node_id: node_id("node-http"),
            request_signature: None,
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/peers/query")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&unsigned_query)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/peers/{}", node_id("node-http")))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let peer_query = signed_node_query("node-http", ControlPlaneNodeQueryKind::PeerMap);
        let peer_query_body = serde_json::to_vec(&peer_query)?;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/paths/query")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(peer_query_body.clone()))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/peers/query")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(peer_query_body.clone()))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let peer_map: PeerMap = serde_json::from_slice(&body)?;
        assert_eq!(peer_map.peers.len(), 1);
        assert_eq!(peer_map.peers[0].node_id, node_id("node-peer"));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/peers/query")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(peer_query_body))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let path_reported_at = Utc::now() + chrono::Duration::seconds(1);
        let heartbeat = signed_heartbeat_at(
            "node-http",
            HeartbeatRequest {
                node_id: node_id("node-http"),
                health: NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: path_reported_at,
                    latency_ms: Some(1.0),
                    relay_load: None,
                    message: None,
                },
                candidates: Vec::new(),
                relay_capability: None,
                routes: None,
                path_state: vec![path("node-http", "node-peer")],
                nat_classification: None,
                node_signature: None,
            },
            path_reported_at,
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/heartbeat")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&heartbeat)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/paths/query")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&signed_node_query(
                        "node-http",
                        ControlPlaneNodeQueryKind::Paths,
                    ))?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let paths: ControlPlanePathsResponse = serde_json::from_slice(&body)?;
        assert_eq!(paths.node_id, node_id("node-http"));
        assert_eq!(paths.paths.len(), 1);
        assert_eq!(paths.paths[0].key.remote, node_id("node-peer"));
        assert_eq!(paths.stale_path_count, 0);
        assert_eq!(paths.path_state_ttl_seconds, 600);

        let response = app
            .clone()
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
        assert!(body.contains("ipars_control_plane_metrics_generated_timestamp_seconds"));
        assert!(body.contains("ipars_control_plane_nodes"));
        assert!(body.contains("ipars_control_plane_ha_ready"));
        assert!(body.contains("ipars_control_plane_service_instances"));
        assert!(body.contains("ipars_control_plane_service_endpoints"));
        assert!(body.contains("ipars_control_plane_stale_endpoint_candidates"));
        assert!(body.contains("ipars_control_plane_endpoint_candidate_ttl_seconds"));
        assert!(body.contains("ipars_control_plane_stale_paths"));
        assert!(body.contains("ipars_control_plane_path_state_ttl_seconds"));
        assert!(body.contains("ipars_control_plane_vpn_pool_total"));
        assert!(body.contains("ipars_control_plane_vpn_pool_allocated"));
        assert!(body.contains("ipars_control_plane_vpn_pool_available"));
        assert!(body.contains("ipars_control_plane_join_tokens"));
        assert!(body.contains("ipars_control_plane_join_tokens_issued"));
        assert!(body.contains("ipars_control_plane_join_token_uses"));
        assert!(body.contains("ipars_control_plane_wireguard_key_rotations_total"));
        assert!(body.contains("ipars_control_plane_node_removals_total"));
        assert!(body.contains("ipars_control_plane_peer_map_candidates"));
        assert!(body.contains("ipars_control_plane_peer_map_visible"));
        assert!(body.contains("ipars_control_plane_peer_map_acl_denied"));
        assert!(body.contains("ipars_control_plane_peer_map_route_candidates"));
        assert!(body.contains("ipars_control_plane_peer_map_routes_visible"));
        assert!(body.contains("ipars_control_plane_peer_map_routes_acl_denied"));
        assert!(body.contains("ipars_control_plane_node_health"));
        let prometheus_cluster_id = prometheus_label(cluster_id.as_str());
        assert!(body.contains(&format!(
            "ipars_control_plane_metrics_generated_timestamp_seconds{{cluster_id=\"{prometheus_cluster_id}\"}} "
        )));
        assert!(body.contains(&format!(
            "ipars_control_plane_path_state_count{{cluster_id=\"{prometheus_cluster_id}\",state=\"DIRECT_NAT_TRAVERSAL\"}} 1"
        )));
        assert!(body.contains(&format!(
            "ipars_control_plane_path_state_count{{cluster_id=\"{prometheus_cluster_id}\",state=\"RELAY\"}} 0"
        )));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/nodes/{}", node_id("node-http")))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&RemoveNodeRequest {
                        node_id: node_id("node-http"),
                        node_signature: None,
                    })?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/nodes/{}", node_id("node-http")))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&signed_remove_node(
                        "node-http",
                    ))?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let removed: RemoveNodeResponse = serde_json::from_slice(&body)?;
        assert_eq!(removed.node.node_id, node_id("node-http"));
        assert_eq!(removed.removed_path_count, 1);
        assert!(removed.removed_health);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/paths/query")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&signed_node_query(
                        "node-http",
                        ControlPlaneNodeQueryKind::Paths,
                    ))?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let metrics = plane.metrics().await?;
        assert_eq!(metrics.node_count, 1);
        assert_eq!(metrics.path_count, 0);
        assert_eq!(metrics.vpn_pool_allocated_count, 1);
        assert_eq!(metrics.node_removal_success_count, 1);
        assert_eq!(metrics.node_removal_failure_count, 1);
        let mut reclaim_claims = claims(
            cluster_id.clone(),
            issuer.node_id(),
            KeyId::from_string("root"),
        );
        reclaim_claims.nonce = "http-reclaim".to_string();
        let reclaimed = plane
            .register_with_claims(reclaim_claims, registration("node-reclaim"))
            .await?;
        assert_eq!(
            reclaimed.node.vpn_ip.0,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
        );
        Ok(())
    }
}
