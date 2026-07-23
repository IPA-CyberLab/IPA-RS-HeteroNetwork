use std::collections::{BTreeSet, HashMap};
use std::fmt::Write;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ipars_control_plane::{
    node_enrollment_role_is_allowed, ControlPlane, ControlPlaneError, ControlPlaneJoinService,
    ControlPlaneStore, TokenLedger, MAX_NODE_ENROLLMENT_TOKEN_USES,
};
use ipars_crypto::IdentityKeyPair;
use ipars_types::api::{
    ClientControlRequest, ClientRequestKind, ControlPlaneMetricsResponse, ControlPlaneNodeOverview,
    ControlPlaneNodeQueryKind, ControlPlaneNodeQueryRequest, ControlPlaneOverviewResponse,
    ControlPlanePathsResponse, ControlPlanePolicyResponse, HeartbeatRequest, HeartbeatResponse,
    JoinClientRequest, JoinNodeRequest, PeerMap, RegisterClientResponse, RegisterNodeResponse,
    RemoveClientResponse, RemoveNodeRequest, RemoveNodeResponse, RevokeTokenRequest,
    RevokeTokenResponse, RotateWireGuardKeyRequest, RotateWireGuardKeyResponse,
    SignalNodeAuthenticationResponse, SignalNodeUpsertRequest,
};
use ipars_types::{
    socket_addr_is_globally_routable, BootstrapEndpoint, BootstrapEndpointKind, ClusterPolicy,
    JoinTokenClaims, KeyId, NatConnectivityState, NodeId, PathRecord, PathState, Role,
    ServiceInstance, SignedJoinToken, Tag, TokenLedgerMetrics, TokenPolicy,
    JOIN_TOKEN_NOT_BEFORE_SKEW_SECONDS, MAX_JOIN_TOKEN_TAGS, MAX_JOIN_TOKEN_TTL_SECONDS,
};
use rand_core::{OsRng, RngCore};
use reqwest::redirect::Policy as RedirectPolicy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_util::io::ReaderStream;
use url::Url;

const MAX_OPERATOR_API_BEARER_TOKEN_BYTES: usize = 512;
const MAX_WEB_OIDC_LOGIN_STATES: usize = 1024;
const WEB_OIDC_LOGIN_STATE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_WEB_OIDC_TOKEN_RESPONSE_BYTES: usize = 1024 * 1024;
const WEB_OIDC_STATE_COOKIE: &str = "heteronetwork_oidc_state";
const WEB_OIDC_ACCESS_TOKEN_STORAGE_KEY: &str = "heteronetwork_access_token";
const MIN_NODE_ENROLLMENT_TTL_SECONDS: u64 = 5 * 60;
const DEFAULT_REUSABLE_NODE_ENROLLMENT_USES: u32 = 10;
const MAX_NODE_ENROLLMENT_REQUEST_BYTES: usize = 16 * 1024;
const MAX_NODE_ENROLLMENT_AUTHORIZATION_BYTES: usize = 24 * 1024;
const MAX_NODE_ENROLLMENT_BINARY_BYTES: u64 = 128 * 1024 * 1024;
const NODE_ENROLLMENT_AUTH_SCHEME: &str = "HeteroNetworkJoin";
const NODE_ENROLLMENT_ARCH: &str = "linux-amd64";
const KUBERNETES_HA_SETUP_TAG_PREFIX: &str = "kubernetes-ha-";
const KUBERNETES_HA_CONTROL_PLANE_COUNT: u32 = 3;
const KUBEADM_HA_NODE_SCRIPT: &str = include_str!("../../../scripts/kubeadm-ha-node.sh");
const KUBEADM_HA_AUTOPILOT_SCRIPT: &str = include_str!("../../../scripts/kubeadm-ha-autopilot.sh");
const MAX_HEARTBEAT_CONNECTION_INTENT_WAIT_SECONDS: u64 = 20;
const MAX_DYNAMIC_WEB_GATEWAY_CONFIG_BYTES: u64 = 256 * 1024;
const NODE_ENROLLMENT_CADDY_VERSION: &str = "2.11.4";
const NODE_ENROLLMENT_CADDY_SHA256: &str =
    "527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9";

macro_rules! prometheus_line {
    ($body:expr, $($arg:tt)*) => {{
        let _ = writeln!($body, $($arg)*);
    }};
}

#[derive(Clone)]
pub struct NodeEnrollmentConfig {
    issuer: IdentityKeyPair,
    key_id: KeyId,
    install_base_url: Arc<str>,
    binary_path: Arc<PathBuf>,
    binary: Arc<std::fs::File>,
    binary_sha256: Arc<str>,
    binary_size: u64,
    max_ttl_seconds: u64,
}

impl NodeEnrollmentConfig {
    pub fn new(
        issuer: IdentityKeyPair,
        key_id: String,
        install_base_url: String,
        binary_path: PathBuf,
        max_ttl_seconds: u64,
    ) -> Result<Self, String> {
        validate_enrollment_identifier(&key_id, "node enrollment issuer key ID")?;
        if !(MIN_NODE_ENROLLMENT_TTL_SECONDS..=MAX_JOIN_TOKEN_TTL_SECONDS as u64)
            .contains(&max_ttl_seconds)
        {
            return Err(format!(
                "node enrollment maximum TTL must be between {MIN_NODE_ENROLLMENT_TTL_SECONDS} and {MAX_JOIN_TOKEN_TTL_SECONDS} seconds"
            ));
        }
        if std::env::consts::OS != "linux" || std::env::consts::ARCH != "x86_64" {
            return Err(format!(
                "node enrollment binary serving currently requires Linux x86_64; got {} {}",
                std::env::consts::OS,
                std::env::consts::ARCH,
            ));
        }

        let install_base_url =
            validate_web_auth_base_url(install_base_url, "node enrollment public URL")?;
        let parsed = Url::parse(&install_base_url)
            .map_err(|error| format!("node enrollment public URL is invalid: {error}"))?;
        if !matches!(parsed.path(), "" | "/") {
            return Err("node enrollment public URL must not contain a path".to_string());
        }

        let path_metadata = std::fs::symlink_metadata(&binary_path).map_err(|error| {
            format!(
                "failed to inspect node enrollment binary {}: {error}",
                binary_path.display()
            )
        })?;
        if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
            return Err(format!(
                "node enrollment binary {} must be a regular non-symlink file",
                binary_path.display()
            ));
        }
        let mut binary = std::fs::File::open(&binary_path).map_err(|error| {
            format!(
                "failed to open node enrollment binary {}: {error}",
                binary_path.display()
            )
        })?;
        let metadata = binary.metadata().map_err(|error| {
            format!(
                "failed to inspect opened node enrollment binary {}: {error}",
                binary_path.display()
            )
        })?;
        if !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_NODE_ENROLLMENT_BINARY_BYTES
        {
            return Err(format!(
                "node enrollment binary {} must be a non-empty regular file no larger than {MAX_NODE_ENROLLMENT_BINARY_BYTES} bytes",
                binary_path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if path_metadata.dev() != metadata.dev() || path_metadata.ino() != metadata.ino() {
                return Err(format!(
                    "node enrollment binary {} changed while it was opened",
                    binary_path.display()
                ));
            }
        }

        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = binary.read(&mut buffer).map_err(|error| {
                format!(
                    "failed to hash node enrollment binary {}: {error}",
                    binary_path.display()
                )
            })?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        binary.seek(SeekFrom::Start(0)).map_err(|error| {
            format!(
                "failed to rewind node enrollment binary {}: {error}",
                binary_path.display()
            )
        })?;

        Ok(Self {
            issuer,
            key_id: KeyId::from_string(key_id),
            install_base_url: Arc::from(install_base_url),
            binary_path: Arc::new(binary_path),
            binary: Arc::new(binary),
            binary_sha256: Arc::from(format!("{:x}", digest.finalize())),
            binary_size: metadata.len(),
            max_ttl_seconds,
        })
    }

    pub fn issuer_node_id(&self) -> NodeId {
        self.issuer.node_id()
    }

    pub fn issuer_key_id(&self) -> KeyId {
        self.key_id.clone()
    }

    pub fn issuer_public_key_b64(&self) -> String {
        self.issuer.public_key_b64()
    }

    pub fn max_ttl_seconds(&self) -> u64 {
        self.max_ttl_seconds
    }

    fn open_binary(&self) -> Result<std::fs::File, String> {
        let path_metadata =
            std::fs::symlink_metadata(self.binary_path.as_ref()).map_err(|error| {
                format!(
                    "failed to inspect node enrollment binary {}: {error}",
                    self.binary_path.display()
                )
            })?;
        if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
            return Err(format!(
                "node enrollment binary {} is no longer a regular non-symlink file",
                self.binary_path.display()
            ));
        }
        let binary = std::fs::File::open(self.binary_path.as_ref()).map_err(|error| {
            format!(
                "failed to open node enrollment binary {}: {error}",
                self.binary_path.display()
            )
        })?;
        let original = self.binary.metadata().map_err(|error| {
            format!(
                "failed to inspect pinned node enrollment binary {}: {error}",
                self.binary_path.display()
            )
        })?;
        let opened = binary.metadata().map_err(|error| {
            format!(
                "failed to inspect opened node enrollment binary {}: {error}",
                self.binary_path.display()
            )
        })?;
        if !opened.is_file() || opened.len() != self.binary_size {
            return Err(format!(
                "node enrollment binary {} changed after startup",
                self.binary_path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if path_metadata.dev() != opened.dev()
                || path_metadata.ino() != opened.ino()
                || original.dev() != opened.dev()
                || original.ino() != opened.ino()
            {
                return Err(format!(
                    "node enrollment binary {} changed after startup",
                    self.binary_path.display()
                ));
            }
        }
        Ok(binary)
    }
}

fn validate_enrollment_identifier(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > ipars_types::MAX_JOIN_TOKEN_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} must be 1 to {} non-control characters",
            ipars_types::MAX_JOIN_TOKEN_IDENTIFIER_BYTES
        ));
    }
    Ok(())
}

pub struct ControlPlaneHttpState<S, L> {
    plane: Arc<ControlPlane<S>>,
    join_service: Arc<ControlPlaneJoinService<S, L>>,
    operator_api_bearer_token: Option<Arc<str>>,
    web_ui_auth: Option<Arc<WebUiAuthConfig>>,
    node_enrollment: Option<Arc<NodeEnrollmentConfig>>,
    dynamic_web_gateway: Option<Arc<DynamicWebGatewayConfig>>,
}

#[derive(Clone)]
pub struct DynamicWebGatewayConfig {
    client: Client,
    probe_timeout: Duration,
    lease_ttl: ChronoDuration,
    classification_max_age: ChronoDuration,
}

impl DynamicWebGatewayConfig {
    pub fn new(
        probe_timeout: Duration,
        lease_ttl: Duration,
        classification_max_age: Duration,
    ) -> Result<Self, String> {
        if probe_timeout.is_zero() || lease_ttl.is_zero() || classification_max_age.is_zero() {
            return Err("dynamic Web gateway durations must be greater than zero".to_string());
        }
        let lease_ttl = ChronoDuration::from_std(lease_ttl)
            .map_err(|error| format!("invalid dynamic Web gateway lease TTL: {error}"))?;
        let classification_max_age = ChronoDuration::from_std(classification_max_age)
            .map_err(|error| format!("invalid dynamic Web gateway classification age: {error}"))?;
        let client = Client::builder()
            .connect_timeout(probe_timeout)
            .timeout(probe_timeout)
            .redirect(RedirectPolicy::none())
            .no_proxy()
            .build()
            .map_err(|error| format!("failed to build dynamic Web gateway client: {error}"))?;
        Ok(Self {
            client,
            probe_timeout,
            lease_ttl,
            classification_max_age,
        })
    }
}

impl<S, L> Clone for ControlPlaneHttpState<S, L> {
    fn clone(&self) -> Self {
        Self {
            plane: self.plane.clone(),
            join_service: self.join_service.clone(),
            operator_api_bearer_token: self.operator_api_bearer_token.clone(),
            web_ui_auth: self.web_ui_auth.clone(),
            node_enrollment: self.node_enrollment.clone(),
            dynamic_web_gateway: self.dynamic_web_gateway.clone(),
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
            node_enrollment: None,
            dynamic_web_gateway: None,
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

    pub fn enable_node_enrollment(mut self, config: NodeEnrollmentConfig) -> Self {
        self.node_enrollment = Some(Arc::new(config));
        self
    }

    pub fn enable_dynamic_web_gateway(mut self, config: DynamicWebGatewayConfig) -> Self {
        self.dynamic_web_gateway = Some(Arc::new(config));
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
        .route("/v1/clients/join", post(join_client::<S, L>))
        .route("/v1/clients/peers/query", post(client_peers::<S, L>))
        .route("/v1/clients/{client_id}", delete(remove_client::<S, L>))
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
        .route("/v1/tokens/revoke", post(revoke_token::<S, L>))
        .route(
            "/v1/install/linux-amd64.sh",
            get(node_enrollment_linux_script::<S, L>),
        )
        .route(
            "/v1/install/iparsd-linux-amd64",
            get(node_enrollment_binary::<S, L>),
        );

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
            "/v1/admin/enrollment",
            post(admin_create_node_enrollment::<S, L>)
                .layer(DefaultBodyLimit::max(MAX_NODE_ENROLLMENT_REQUEST_BYTES)),
        )
        .route(
            "/v1/admin/client-enrollment",
            post(admin_create_client_enrollment::<S, L>)
                .layer(DefaultBodyLimit::max(MAX_NODE_ENROLLMENT_REQUEST_BYTES)),
        )
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
    app.route("/", get(ui_root))
        .route("/ui", get(ui_index))
        .route("/ui/", get(ui_index))
        .route("/ui/login", get(ui_login::<S, L>))
        .route("/ui/callback", get(ui_callback::<S, L>))
        .route("/ui/app.js", get(ui_app))
        .route("/ui/theme.js", get(ui_theme))
        .route("/ui/styles.css", get(ui_styles))
        .route("/ui/fonts/noto-sans-jp-ui.ttf", get(ui_japanese_font))
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
    device_authorization_endpoint: Option<String>,
    token_endpoint: String,
    backchannel_token_endpoints: Vec<String>,
    backchannel_userinfo_endpoints: Vec<String>,
    backchannel_host: header::HeaderValue,
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
        backchannel_base_url: Option<String>,
        scopes: String,
    ) -> Result<Self, String> {
        let issuer_url = validate_web_auth_base_url(issuer_url, "issuer URL")?;
        let backchannel_host = web_auth_host_header(&issuer_url, "issuer URL")?;
        let auth_base_url = match auth_base_url {
            Some(value) => validate_web_auth_base_url(value, "OIDC auth base URL")?,
            None => issuer_url.clone(),
        };
        let backchannel_base_url = match backchannel_base_url {
            Some(value) => validate_web_auth_base_url(value, "OIDC backchannel base URL")?,
            None => auth_base_url.clone(),
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
        let (
            authorization_suffix,
            device_authorization_suffix,
            token_suffix,
            userinfo_suffix,
            logout_suffix,
        ) = match provider {
            WebAuthProvider::Keycloak => (
                "/protocol/openid-connect/auth",
                Some("/protocol/openid-connect/auth/device"),
                "/protocol/openid-connect/token",
                "/protocol/openid-connect/userinfo",
                "/protocol/openid-connect/logout",
            ),
            WebAuthProvider::Cognito => (
                "/oauth2/authorize",
                None,
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
            device_authorization_endpoint: device_authorization_suffix
                .map(|suffix| endpoint_url(&auth_base_url, suffix)),
            token_endpoint: endpoint_url(&auth_base_url, token_suffix),
            backchannel_token_endpoints: vec![endpoint_url(&backchannel_base_url, token_suffix)],
            backchannel_userinfo_endpoints: vec![endpoint_url(
                &backchannel_base_url,
                userinfo_suffix,
            )],
            backchannel_host,
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

    pub fn with_backchannel_fallback_base_urls(
        mut self,
        fallback_base_urls: Vec<String>,
    ) -> Result<Self, String> {
        let (token_suffix, userinfo_suffix) = match self.provider {
            WebAuthProvider::Keycloak => (
                "/protocol/openid-connect/token",
                "/protocol/openid-connect/userinfo",
            ),
            WebAuthProvider::Cognito => ("/oauth2/token", "/oauth2/userInfo"),
        };
        for base_url in fallback_base_urls {
            let base_url =
                validate_web_auth_base_url(base_url, "OIDC backchannel fallback base URL")?;
            let token_endpoint = endpoint_url(&base_url, token_suffix);
            let userinfo_endpoint = endpoint_url(&base_url, userinfo_suffix);
            if !self
                .backchannel_token_endpoints
                .iter()
                .any(|endpoint| endpoint == &token_endpoint)
            {
                self.backchannel_token_endpoints.push(token_endpoint);
                self.backchannel_userinfo_endpoints.push(userinfo_endpoint);
            }
        }
        Ok(self)
    }

    pub async fn validate_access_token(&self, token: &str) -> bool {
        if token.is_empty() || token.len() > MAX_OPERATOR_API_BEARER_TOKEN_BYTES * 16 {
            return false;
        }
        let Some(backchannel_host) = self.access_token_backchannel_host(token) else {
            return false;
        };
        for endpoint in &self.backchannel_userinfo_endpoints {
            let response = match timeout(
                Duration::from_secs(5),
                self.client
                    .get(endpoint)
                    .header(header::HOST, backchannel_host.clone())
                    .bearer_auth(token)
                    .send(),
            )
            .await
            {
                Ok(Ok(response)) => response,
                _ => continue,
            };
            if !response.status().is_success() {
                continue;
            }
            let body =
                match bounded_response_body(response, MAX_WEB_OIDC_TOKEN_RESPONSE_BYTES).await {
                    Ok(body) => body,
                    Err(_) => continue,
                };
            if serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|claims| {
                    claims
                        .get("sub")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .is_some_and(|subject| !subject.is_empty())
            {
                return true;
            }
        }
        false
    }

    fn access_token_backchannel_host(&self, token: &str) -> Option<header::HeaderValue> {
        let Some(issuer) = unverified_jwt_issuer(token) else {
            return Some(self.backchannel_host.clone());
        };
        let issuer = validate_web_auth_base_url(issuer, "access token issuer").ok()?;
        let configured = Url::parse(&self.issuer_url).ok()?;
        let candidate = Url::parse(&issuer).ok()?;
        let accepted = match self.provider {
            WebAuthProvider::Keycloak => {
                configured.scheme() == candidate.scheme()
                    && configured.path().trim_end_matches('/')
                        == candidate.path().trim_end_matches('/')
                    && configured.port_or_known_default() == candidate.port_or_known_default()
            }
            WebAuthProvider::Cognito => {
                configured.as_str().trim_end_matches('/')
                    == candidate.as_str().trim_end_matches('/')
            }
        };
        accepted.then(|| web_auth_host_header(&issuer, "access token issuer").ok())?
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

        let mut failures = Vec::new();
        let mut token_response = None;
        for endpoint in &self.backchannel_token_endpoints {
            let response = match self
                .client
                .post(endpoint)
                .header(header::HOST, self.backchannel_host.clone())
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
            {
                Ok(response) => response,
                Err(error) => {
                    failures.push(format!("{endpoint}: {error}"));
                    continue;
                }
            };
            if response.status().is_success() {
                token_response = Some(response);
                break;
            }
            if response.status().is_server_error() {
                failures.push(format!("{endpoint}: HTTP {}", response.status()));
                continue;
            }
            return Err(WebAuthFlowError::new(
                StatusCode::UNAUTHORIZED,
                format!("OIDC token exchange failed ({})", response.status()),
            ));
        }
        let response = token_response.ok_or_else(|| {
            WebAuthFlowError::new(
                StatusCode::BAD_GATEWAY,
                format!(
                    "OIDC token exchange failed on every backchannel: {}",
                    failures.join("; ")
                ),
            )
        })?;
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

    fn public_config(&self, cluster_id: String) -> WebUiPublicConfig {
        WebUiPublicConfig {
            cluster_id,
            enabled: true,
            auth_enabled: true,
            operator_token_enabled: false,
            provider: Some(self.provider.as_str().to_string()),
            issuer_url: Some(self.issuer_url.clone()),
            client_id: Some(self.client_id.clone()),
            scopes: Some(self.scopes.clone()),
            authorization_endpoint: Some(self.authorization_endpoint.clone()),
            device_authorization_endpoint: self.device_authorization_endpoint.clone(),
            token_endpoint: Some(self.token_endpoint.clone()),
            logout_endpoint: Some(self.logout_endpoint.clone()),
            login_endpoint: self.public_url.as_ref().map(|_| "/ui/login".to_string()),
            node_enrollment_enabled: false,
            client_enrollment_enabled: false,
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

fn web_auth_host_header(value: &str, name: &str) -> Result<header::HeaderValue, String> {
    let parsed = Url::parse(value).map_err(|error| format!("{name} is invalid: {error}"))?;
    let host = match parsed.host() {
        Some(url::Host::Domain(host)) => host.to_string(),
        Some(url::Host::Ipv4(host)) => host.to_string(),
        Some(url::Host::Ipv6(host)) => format!("[{host}]"),
        None => return Err(format!("{name} does not contain a host")),
    };
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    header::HeaderValue::from_str(&authority)
        .map_err(|_| format!("{name} host is not valid for an HTTP Host header"))
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

fn unverified_jwt_issuer(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() || payload.is_empty() {
        return None;
    }
    let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&payload).ok()?;
    claims
        .get("iss")
        .and_then(Value::as_str)
        .filter(|issuer| !issuer.is_empty())
        .map(str::to_string)
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
    cluster_id: String,
    enabled: bool,
    auth_enabled: bool,
    operator_token_enabled: bool,
    provider: Option<String>,
    issuer_url: Option<String>,
    client_id: Option<String>,
    scopes: Option<String>,
    authorization_endpoint: Option<String>,
    device_authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    logout_endpoint: Option<String>,
    login_endpoint: Option<String>,
    node_enrollment_enabled: bool,
    client_enrollment_enabled: bool,
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

async fn ui_root() -> Redirect {
    Redirect::temporary("/ui/")
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

async fn ui_theme() -> impl IntoResponse {
    let mut response = (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../../webui/theme.js"),
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

async fn ui_japanese_font() -> impl IntoResponse {
    let mut response = (
        [(header::CONTENT_TYPE, "font/ttf")],
        include_bytes!("../../../webui/noto-sans-jp-ui.ttf").as_slice(),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
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
    let cluster_id = state.plane.config().cluster_id.as_str().to_string();
    let mut config = state
        .web_ui_auth
        .as_deref()
        .map(|auth| auth.public_config(cluster_id.clone()))
        .unwrap_or_else(|| WebUiPublicConfig {
            cluster_id,
            enabled: state.operator_api_bearer_token.is_some(),
            auth_enabled: false,
            operator_token_enabled: state.operator_api_bearer_token.is_some(),
            provider: None,
            issuer_url: None,
            client_id: None,
            scopes: None,
            authorization_endpoint: None,
            device_authorization_endpoint: None,
            token_endpoint: None,
            logout_endpoint: None,
            login_endpoint: None,
            node_enrollment_enabled: false,
            client_enrollment_enabled: false,
        });
    config.operator_token_enabled = state.operator_api_bearer_token.is_some();
    config.node_enrollment_enabled = state.node_enrollment.is_some();
    config.client_enrollment_enabled = state.node_enrollment.is_some();
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminNodeEnrollmentRequest {
    expires_in_seconds: u64,
    #[serde(default = "default_node_enrollment_role")]
    role: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    allow_relay: bool,
    #[serde(default)]
    reusable: bool,
    max_uses: Option<u32>,
    #[serde(default)]
    setup: NodeEnrollmentSetup,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NodeEnrollmentSetup {
    #[default]
    NetworkOnly,
    KubernetesHaControlPlane,
}

#[derive(Debug, Serialize)]
struct AdminNodeEnrollmentResponse {
    token: SignedJoinToken,
    expires_at: DateTime<Utc>,
    max_uses: u32,
    install_command: String,
    install_script: String,
    binary_sha256: String,
    architecture: &'static str,
    setup: NodeEnrollmentSetup,
}

#[derive(Debug)]
struct KubernetesHaEnrollmentSetup {
    cohort_tag: String,
    expected_control_planes: u32,
    bundle_bearer_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminClientEnrollmentRequest {
    expires_in_seconds: u64,
}

#[derive(Debug, Serialize)]
struct AdminClientEnrollmentResponse {
    token: SignedJoinToken,
    expires_at: DateTime<Utc>,
    enrollment_uri: String,
}

fn default_node_enrollment_role() -> String {
    Role::edge().as_str().to_string()
}

#[derive(Debug)]
struct NodeEnrollmentApiError {
    status: StatusCode,
    message: String,
}

impl NodeEnrollmentApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, message)
    }
}

impl IntoResponse for NodeEnrollmentApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response();
        apply_node_enrollment_security_headers(&mut response);
        response
    }
}

async fn admin_create_node_enrollment<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<AdminNodeEnrollmentRequest>,
) -> Result<Response, NodeEnrollmentApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let enrollment = state
        .node_enrollment
        .as_deref()
        .ok_or_else(|| NodeEnrollmentApiError::unavailable("node enrollment is not configured"))?;
    let role = request.role.trim();
    validate_enrollment_identifier(role, "node role")
        .map_err(NodeEnrollmentApiError::bad_request)?;
    let role = Role::from_string(role);
    if !node_enrollment_role_is_allowed(&role) {
        return Err(NodeEnrollmentApiError::bad_request(
            "node role must be edge, worker, or gateway",
        ));
    }
    let max_uses = node_enrollment_max_uses(&request)?;
    if request.setup == NodeEnrollmentSetup::KubernetesHaControlPlane
        && (!request.reusable || max_uses != KUBERNETES_HA_CONTROL_PLANE_COUNT)
    {
        return Err(NodeEnrollmentApiError::bad_request(format!(
            "Kubernetes HA control-plane enrollment must be reusable with exactly {KUBERNETES_HA_CONTROL_PLANE_COUNT} uses"
        )));
    }
    if request.tags.len() > MAX_JOIN_TOKEN_TAGS {
        return Err(NodeEnrollmentApiError::bad_request(format!(
            "no more than {MAX_JOIN_TOKEN_TAGS} tags may be requested"
        )));
    }
    let mut tags = BTreeSet::new();
    for value in request.tags {
        let value = value.trim();
        validate_enrollment_identifier(value, "node tag")
            .map_err(NodeEnrollmentApiError::bad_request)?;
        if value.starts_with(KUBERNETES_HA_SETUP_TAG_PREFIX) {
            return Err(NodeEnrollmentApiError::bad_request(format!(
                "node tags beginning with {KUBERNETES_HA_SETUP_TAG_PREFIX} are reserved"
            )));
        }
        if !tags.insert(Tag::from_string(value)) {
            return Err(NodeEnrollmentApiError::bad_request(format!(
                "duplicate node tag: {value}"
            )));
        }
    }
    if !(MIN_NODE_ENROLLMENT_TTL_SECONDS..=enrollment.max_ttl_seconds)
        .contains(&request.expires_in_seconds)
    {
        return Err(NodeEnrollmentApiError::bad_request(format!(
            "enrollment token lifetime must be between {MIN_NODE_ENROLLMENT_TTL_SECONDS} and {} seconds",
            enrollment.max_ttl_seconds
        )));
    }
    let directory = state
        .plane
        .enrollment_service_directory(Duration::from_secs(enrollment.max_ttl_seconds))
        .await
        .map_err(|error| NodeEnrollmentApiError::unavailable(error.to_string()))?;
    require_ha_node_enrollment_directory(&directory, request.allow_relay)?;

    let now = Utc::now();
    let expires_at = now
        .checked_add_signed(ChronoDuration::seconds(request.expires_in_seconds as i64))
        .ok_or_else(|| NodeEnrollmentApiError::bad_request("token expiration is out of range"))?;
    let bootstrap_endpoints = directory.bootstrap_endpoints;
    let nonce = format!("enroll-{}", random_oidc_value(24));
    if request.setup == NodeEnrollmentSetup::KubernetesHaControlPlane {
        tags.insert(Tag::kubernetes_control_plane());
        tags.insert(Tag::from_string(kubernetes_ha_cohort_tag(&nonce)));
        if tags.len() > MAX_JOIN_TOKEN_TAGS {
            return Err(NodeEnrollmentApiError::bad_request(format!(
                "no more than {MAX_JOIN_TOKEN_TAGS} tags, including setup tags, may be requested"
            )));
        }
    }
    let claims = JoinTokenClaims {
        cluster_id: state.plane.config().cluster_id.clone(),
        bootstrap_endpoints: bootstrap_endpoints.clone(),
        expires_at,
        not_before: now - ChronoDuration::seconds(JOIN_TOKEN_NOT_BEFORE_SKEW_SECONDS),
        role,
        tags: tags.clone(),
        issuer: enrollment.issuer.node_id(),
        key_id: enrollment.key_id.clone(),
        policy: TokenPolicy {
            allow_join: true,
            allow_relay: request.allow_relay,
            allowed_routes: Vec::new(),
            allowed_tags: tags,
            max_token_uses: Some(max_uses),
        },
        nonce,
    };
    let token = enrollment
        .issuer
        .sign_join_token(claims)
        .map_err(|error| NodeEnrollmentApiError::bad_request(error.to_string()))?;
    state
        .join_service
        .issue_join_token(&token, now)
        .await
        .map_err(|error| NodeEnrollmentApiError::unavailable(error.to_string()))?;
    let encoded_token = encode_node_enrollment_authorization(&token)?;
    let install_script =
        node_enrollment_install_script(enrollment, &token, &encoded_token, &bootstrap_endpoints);
    let install_command =
        node_enrollment_install_command(enrollment, &encoded_token, &bootstrap_endpoints);
    let payload = AdminNodeEnrollmentResponse {
        token,
        expires_at,
        max_uses,
        install_command,
        install_script,
        binary_sha256: enrollment.binary_sha256.to_string(),
        architecture: NODE_ENROLLMENT_ARCH,
        setup: request.setup,
    };
    let mut response = Json(payload).into_response();
    apply_node_enrollment_security_headers(&mut response);
    Ok(response)
}

async fn admin_create_client_enrollment<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<AdminClientEnrollmentRequest>,
) -> Result<Response, NodeEnrollmentApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let enrollment = state.node_enrollment.as_deref().ok_or_else(|| {
        NodeEnrollmentApiError::unavailable("client enrollment is not configured")
    })?;
    if !(MIN_NODE_ENROLLMENT_TTL_SECONDS..=enrollment.max_ttl_seconds)
        .contains(&request.expires_in_seconds)
    {
        return Err(NodeEnrollmentApiError::bad_request(format!(
            "client enrollment token lifetime must be between {MIN_NODE_ENROLLMENT_TTL_SECONDS} and {} seconds",
            enrollment.max_ttl_seconds
        )));
    }
    state
        .plane
        .require_client_gateway()
        .await
        .map_err(|error| NodeEnrollmentApiError::unavailable(error.to_string()))?;
    let directory = state
        .plane
        .enrollment_service_directory(Duration::from_secs(enrollment.max_ttl_seconds))
        .await
        .map_err(|error| NodeEnrollmentApiError::unavailable(error.to_string()))?;
    require_ha_client_enrollment_directory(&directory)?;

    let now = Utc::now();
    let expires_at = now
        .checked_add_signed(ChronoDuration::seconds(request.expires_in_seconds as i64))
        .ok_or_else(|| NodeEnrollmentApiError::bad_request("token expiration is out of range"))?;
    let claims = JoinTokenClaims {
        cluster_id: state.plane.config().cluster_id.clone(),
        bootstrap_endpoints: directory.bootstrap_endpoints,
        expires_at,
        not_before: now - ChronoDuration::seconds(JOIN_TOKEN_NOT_BEFORE_SKEW_SECONDS),
        role: Role::client(),
        tags: BTreeSet::new(),
        issuer: enrollment.issuer.node_id(),
        key_id: enrollment.key_id.clone(),
        policy: TokenPolicy {
            allow_join: true,
            allow_relay: false,
            allowed_routes: Vec::new(),
            allowed_tags: BTreeSet::new(),
            max_token_uses: Some(1),
        },
        nonce: format!("client-enroll-{}", random_oidc_value(24)),
    };
    let token = enrollment
        .issuer
        .sign_join_token(claims)
        .map_err(|error| NodeEnrollmentApiError::bad_request(error.to_string()))?;
    state
        .join_service
        .issue_join_token(&token, now)
        .await
        .map_err(|error| NodeEnrollmentApiError::unavailable(error.to_string()))?;
    let token_json = serde_json::to_vec(&token)
        .map_err(|error| NodeEnrollmentApiError::bad_request(error.to_string()))?;
    let enrollment_uri = format!(
        "heteronetwork://enroll?token={}",
        URL_SAFE_NO_PAD.encode(token_json)
    );
    let mut response = Json(AdminClientEnrollmentResponse {
        token,
        expires_at,
        enrollment_uri,
    })
    .into_response();
    apply_node_enrollment_security_headers(&mut response);
    Ok(response)
}

fn node_enrollment_max_uses(
    request: &AdminNodeEnrollmentRequest,
) -> Result<u32, NodeEnrollmentApiError> {
    if !request.reusable {
        if request.max_uses.is_some_and(|uses| uses != 1) {
            return Err(NodeEnrollmentApiError::bad_request(
                "max_uses must be 1 for a single-use token",
            ));
        }
        return Ok(1);
    }
    let max_uses = request
        .max_uses
        .unwrap_or(DEFAULT_REUSABLE_NODE_ENROLLMENT_USES);
    if !(2..=MAX_NODE_ENROLLMENT_TOKEN_USES).contains(&max_uses) {
        return Err(NodeEnrollmentApiError::bad_request(format!(
            "a reusable token must allow between 2 and {MAX_NODE_ENROLLMENT_TOKEN_USES} uses"
        )));
    }
    Ok(max_uses)
}

fn require_ha_node_enrollment_directory(
    directory: &ipars_types::ServiceDirectory,
    require_relay: bool,
) -> Result<(), NodeEnrollmentApiError> {
    let required_kinds = required_node_enrollment_service_kinds(require_relay);
    if !directory.instances.iter().any(|instance| {
        instance.lease_expires_at > directory.generated_at
            && service_instance_has_kinds(instance, &required_kinds)
    }) {
        return Err(NodeEnrollmentApiError::unavailable(
            "cannot issue an HA enrollment token without an active complete public service instance",
        ));
    }

    let mut missing = Vec::new();
    for kind in required_kinds {
        if service_instance_count(directory, kind) < 2
            || service_endpoint_count(directory, kind) < 2
        {
            missing.push(kind.to_string());
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(NodeEnrollmentApiError::unavailable(format!(
            "cannot issue an HA enrollment token until at least two active or recently advertised service instances provide distinct endpoints for each required kind; insufficient: {}",
            missing.join(", ")
        )))
    }
}

fn require_ha_client_enrollment_directory(
    directory: &ipars_types::ServiceDirectory,
) -> Result<(), NodeEnrollmentApiError> {
    let has_active_control_plane = directory.instances.iter().any(|instance| {
        instance.lease_expires_at > directory.generated_at
            && service_instance_has_kinds(instance, &[BootstrapEndpointKind::ControlPlane])
    });
    if !has_active_control_plane {
        return Err(NodeEnrollmentApiError::unavailable(
            "client enrollment requires an active control-plane endpoint",
        ));
    }
    let count = directory
        .bootstrap_endpoints
        .iter()
        .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
        .filter_map(|endpoint| ipars_types::canonical_bootstrap_endpoint_url(&endpoint.url))
        .collect::<BTreeSet<_>>()
        .len();
    if count < 2 {
        return Err(NodeEnrollmentApiError::unavailable(
            "client enrollment requires at least two active or recently advertised control-plane endpoints",
        ));
    }
    Ok(())
}

fn required_node_enrollment_service_kinds(require_relay: bool) -> Vec<BootstrapEndpointKind> {
    let mut kinds = vec![
        BootstrapEndpointKind::ControlPlane,
        BootstrapEndpointKind::Signal,
        BootstrapEndpointKind::Stun,
    ];
    if require_relay {
        kinds.push(BootstrapEndpointKind::Relay);
    }
    kinds
}

fn service_instance_has_kinds(
    instance: &ipars_types::ServiceInstance,
    required_kinds: &[BootstrapEndpointKind],
) -> bool {
    required_kinds.iter().all(|kind| {
        instance
            .endpoints
            .iter()
            .any(|endpoint| endpoint.kind == *kind)
    })
}

fn service_instance_count(
    directory: &ipars_types::ServiceDirectory,
    kind: BootstrapEndpointKind,
) -> usize {
    directory
        .instances
        .iter()
        .filter(|instance| {
            instance
                .endpoints
                .iter()
                .any(|endpoint| endpoint.kind == kind)
        })
        .map(|instance| instance.instance_id.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

fn service_endpoint_count(
    directory: &ipars_types::ServiceDirectory,
    kind: BootstrapEndpointKind,
) -> usize {
    directory
        .instances
        .iter()
        .flat_map(|instance| instance.endpoints.iter())
        .filter(|endpoint| endpoint.kind == kind)
        .map(|endpoint| endpoint.url.trim_end_matches('/'))
        .collect::<BTreeSet<_>>()
        .len()
}

fn encode_node_enrollment_authorization(
    token: &SignedJoinToken,
) -> Result<String, NodeEnrollmentApiError> {
    let encoded = serde_json::to_vec(token)
        .map(|json| STANDARD.encode(json))
        .map_err(|error| NodeEnrollmentApiError::bad_request(error.to_string()))?;
    if encoded.len() > MAX_NODE_ENROLLMENT_AUTHORIZATION_BYTES {
        return Err(NodeEnrollmentApiError::bad_request(
            "enrollment token exceeds its authorization header size limit",
        ));
    }
    Ok(encoded)
}

fn decode_node_enrollment_authorization(
    headers: &HeaderMap,
) -> Result<SignedJoinToken, NodeEnrollmentApiError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| {
            NodeEnrollmentApiError::new(
                StatusCode::UNAUTHORIZED,
                "missing node enrollment authorization",
            )
        })?
        .to_str()
        .map_err(|_| {
            NodeEnrollmentApiError::new(
                StatusCode::UNAUTHORIZED,
                "invalid node enrollment authorization",
            )
        })?;
    if value.len() > MAX_NODE_ENROLLMENT_AUTHORIZATION_BYTES {
        return Err(NodeEnrollmentApiError::new(
            StatusCode::UNAUTHORIZED,
            "node enrollment authorization exceeds its size limit",
        ));
    }
    let (scheme, encoded) = value.split_once(' ').ok_or_else(|| {
        NodeEnrollmentApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid node enrollment authorization scheme",
        )
    })?;
    if scheme != NODE_ENROLLMENT_AUTH_SCHEME
        || encoded.is_empty()
        || encoded.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(NodeEnrollmentApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid node enrollment authorization",
        ));
    }
    let decoded = STANDARD.decode(encoded).map_err(|_| {
        NodeEnrollmentApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid node enrollment authorization encoding",
        )
    })?;
    if decoded.len() > MAX_NODE_ENROLLMENT_REQUEST_BYTES {
        return Err(NodeEnrollmentApiError::new(
            StatusCode::UNAUTHORIZED,
            "node enrollment token exceeds its size limit",
        ));
    }
    serde_json::from_slice(&decoded).map_err(|_| {
        NodeEnrollmentApiError::new(StatusCode::UNAUTHORIZED, "invalid node enrollment token")
    })
}

async fn authorize_node_enrollment<S, L>(
    state: &ControlPlaneHttpState<S, L>,
    headers: &HeaderMap,
) -> Result<Arc<NodeEnrollmentConfig>, NodeEnrollmentApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let enrollment = state.node_enrollment.clone().ok_or_else(|| {
        NodeEnrollmentApiError::new(StatusCode::NOT_FOUND, "node enrollment is not configured")
    })?;
    let token = decode_node_enrollment_authorization(headers)?;
    if token.claims.issuer != enrollment.issuer.node_id()
        || token.claims.key_id != enrollment.key_id
    {
        return Err(NodeEnrollmentApiError::new(
            StatusCode::UNAUTHORIZED,
            "node enrollment authorization was rejected",
        ));
    }
    state
        .join_service
        .validate_issued_join_token(&token, Utc::now())
        .await
        .map_err(|_| {
            NodeEnrollmentApiError::new(
                StatusCode::UNAUTHORIZED,
                "node enrollment authorization was rejected",
            )
        })?;
    Ok(enrollment)
}

async fn node_enrollment_linux_script<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    headers: HeaderMap,
) -> Result<Response, NodeEnrollmentApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let enrollment = authorize_node_enrollment(&state, &headers).await?;
    let token = decode_node_enrollment_authorization(&headers)?;
    let encoded_token = encode_node_enrollment_authorization(&token)?;
    let script = node_enrollment_install_script(
        &enrollment,
        &token,
        &encoded_token,
        &token.claims.bootstrap_endpoints,
    );
    let mut response = (
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        script,
    )
        .into_response();
    apply_node_enrollment_security_headers(&mut response);
    Ok(response)
}

async fn node_enrollment_binary<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    headers: HeaderMap,
) -> Result<Response, NodeEnrollmentApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let enrollment = authorize_node_enrollment(&state, &headers).await?;
    let binary = enrollment
        .open_binary()
        .map_err(NodeEnrollmentApiError::unavailable)?;
    let stream = ReaderStream::new(tokio::fs::File::from_std(binary));
    let mut response = Response::new(Body::from_stream(stream));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        header::HeaderValue::from_static("attachment; filename=iparsd-linux-amd64"),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        header::HeaderValue::from_str(&enrollment.binary_size.to_string()).map_err(|_| {
            NodeEnrollmentApiError::unavailable("invalid node enrollment binary size")
        })?,
    );
    headers.insert(
        header::HeaderName::from_static("x-heteronetwork-sha256"),
        header::HeaderValue::from_str(&enrollment.binary_sha256).map_err(|_| {
            NodeEnrollmentApiError::unavailable("invalid node enrollment binary checksum")
        })?,
    );
    apply_node_enrollment_security_headers(&mut response);
    Ok(response)
}

fn apply_node_enrollment_security_headers(response: &mut Response) {
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
}

fn node_enrollment_install_script(
    enrollment: &NodeEnrollmentConfig,
    token: &SignedJoinToken,
    encoded_token: &str,
    bootstrap_endpoints: &[BootstrapEndpoint],
) -> String {
    const TEMPLATE: &str = r#"#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "HeteroNetwork installation must run as root" >&2
  exit 1
fi
if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "This installer supports Linux x86_64 only" >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "HeteroNetwork requires systemd" >&2
  exit 1
fi
if ! command -v systemd-sysusers >/dev/null 2>&1; then
  echo "HeteroNetwork requires systemd-sysusers" >&2
  exit 1
fi

install_dependencies() {
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates coreutils curl iproute2 tar wireguard-tools
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates coreutils curl iproute tar wireguard-tools
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates coreutils curl iproute tar wireguard-tools
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install ca-certificates coreutils curl iproute2 tar wireguard-tools
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm ca-certificates coreutils curl iproute2 tar wireguard-tools
  else
    echo "Unsupported package manager; install curl, CA certificates, coreutils, iproute2, tar, and wireguard-tools" >&2
    exit 1
  fi
}

for command in base64 curl ip sha256sum tar wg; do
  if ! command -v "$command" >/dev/null 2>&1; then
    install_dependencies
    break
  fi
done
command -v modprobe >/dev/null 2>&1 && modprobe wireguard 2>/dev/null || true

umask 077
install -d -m 0755 /opt/heteronetwork/bin
install -d -m 0700 /var/lib/heteronetwork
tmp_dir=$(mktemp -d /var/lib/heteronetwork/install.XXXXXX)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
auth='__AUTH__'
binary="$tmp_dir/iparsd"
download_bases='__DOWNLOAD_BASES__'
downloaded=
for encoded_base in $download_bases; do
  base=$(printf '%s' "$encoded_base" | base64 -d) || continue
  rm -f "$binary"
  if curl -fsS -H "Authorization: HeteroNetworkJoin $auth" \
    "$base/v1/install/iparsd-linux-amd64" -o "$binary"; then
    actual_sha=$(sha256sum "$binary" | awk '{print $1}')
    if [ "$actual_sha" = '__SHA256__' ]; then
      downloaded=1
      break
    fi
  fi
done
if [ -z "$downloaded" ]; then
  echo "HeteroNetwork binary download failed on every control-plane endpoint" >&2
  exit 1
fi
chmod 0755 "$binary"
install -m 0755 "$binary" /opt/heteronetwork/bin/.iparsd.new
mv -f /opt/heteronetwork/bin/.iparsd.new /opt/heteronetwork/bin/iparsd

caddy_archive="$tmp_dir/caddy.tar.gz"
curl --proto '=https' --proto-redir '=https' -fsSL \
  'https://github.com/caddyserver/caddy/releases/download/v__CADDY_VERSION__/caddy___CADDY_VERSION___linux_amd64.tar.gz' \
  -o "$caddy_archive"
caddy_sha=$(sha256sum "$caddy_archive" | awk '{print $1}')
if [ "$caddy_sha" != '__CADDY_SHA256__' ]; then
  echo "Caddy download checksum verification failed" >&2
  exit 1
fi
tar -xzf "$caddy_archive" -C "$tmp_dir" caddy
chmod 0755 "$tmp_dir/caddy"
install -m 0755 "$tmp_dir/caddy" /opt/heteronetwork/bin/.caddy.new
mv -f /opt/heteronetwork/bin/.caddy.new /opt/heteronetwork/bin/caddy

token_file="$tmp_dir/join-token.json"
printf '%s' "$auth" | base64 -d >"$token_file"
chmod 0600 "$token_file"
/opt/heteronetwork/bin/iparsd agent --join-token-path "$token_file" --enroll-only
rm -f "$token_file"

install -d -o root -g root -m 0755 /etc/heteronetwork
install -d -o root -g root -m 0755 /etc/sysusers.d
cat >/etc/sysusers.d/heteronetwork-gateway.conf <<'SYSUSERS'
u heteronetwork-gateway - "HeteroNetwork Dynamic Public Web Gateway" /var/lib/heteronetwork-gateway
SYSUSERS
systemd-sysusers /etc/sysusers.d/heteronetwork-gateway.conf
cat >/etc/heteronetwork/gateway.Caddyfile <<'CADDYFILE'
{
  admin unix//run/heteronetwork-gateway/admin.sock|0660
  persist_config off
}
CADDYFILE
chown root:root /etc/heteronetwork/gateway.Caddyfile
chmod 0644 /etc/heteronetwork/gateway.Caddyfile

cat >/etc/systemd/system/heteronetwork-gateway.service <<'GATEWAY_UNIT'
[Unit]
Description=HeteroNetwork Dynamic Public Web Gateway
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
User=heteronetwork-gateway
Group=heteronetwork-gateway
ExecStart=/opt/heteronetwork/bin/caddy run --environ --config /etc/heteronetwork/gateway.Caddyfile --adapter caddyfile
ExecReload=/opt/heteronetwork/bin/caddy reload --config /etc/heteronetwork/gateway.Caddyfile --adapter caddyfile --address unix//run/heteronetwork-gateway/admin.sock
Restart=on-failure
RestartSec=5s
TimeoutStopSec=5s
RuntimeDirectory=heteronetwork-gateway
RuntimeDirectoryMode=0750
StateDirectory=heteronetwork-gateway
StateDirectoryMode=0700
Environment=XDG_DATA_HOME=/var/lib/heteronetwork-gateway
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
GATEWAY_UNIT

cat >/etc/systemd/system/heteronetwork-agent.service <<'UNIT'
[Unit]
Description=HeteroNetwork Agent
Wants=network-online.target heteronetwork-gateway.service
After=network-online.target heteronetwork-gateway.service

[Service]
Type=simple
SupplementaryGroups=heteronetwork-gateway
ExecStart=/opt/heteronetwork/bin/iparsd agent --apply-peer-map --wireguard-backend kernel-netlink --route-backend kernel-netlink --packet-flow-detector conntrack-netlink-events --packet-flow-poll-interval-seconds 1
Restart=on-failure
RestartSec=5s
StateDirectory=heteronetwork
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
ReadWritePaths=/var/lib/heteronetwork
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable heteronetwork-gateway.service heteronetwork-agent.service
systemctl restart heteronetwork-gateway.service
systemctl restart heteronetwork-agent.service
__SETUP_INSTALL__
echo "HeteroNetwork node enrolled and started"
"#;
    let download_bases = node_enrollment_download_bases(enrollment, bootstrap_endpoints)
        .into_iter()
        .map(|base| STANDARD.encode(base.as_bytes()))
        .collect::<Vec<_>>()
        .join(" ");
    let setup_install = kubernetes_ha_enrollment_setup(token, encoded_token)
        .map(kubernetes_ha_install_script)
        .unwrap_or_default();
    TEMPLATE
        .replace("__AUTH__", encoded_token)
        .replace("__DOWNLOAD_BASES__", &download_bases)
        .replace("__SHA256__", &enrollment.binary_sha256)
        .replace("__CADDY_VERSION__", NODE_ENROLLMENT_CADDY_VERSION)
        .replace("__CADDY_SHA256__", NODE_ENROLLMENT_CADDY_SHA256)
        .replace("__SETUP_INSTALL__", &setup_install)
}

fn kubernetes_ha_cohort_tag(nonce: &str) -> String {
    let digest = Sha256::digest(nonce.as_bytes());
    format!(
        "{KUBERNETES_HA_SETUP_TAG_PREFIX}{}",
        digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn kubernetes_ha_enrollment_setup(
    token: &SignedJoinToken,
    encoded_token: &str,
) -> Option<KubernetesHaEnrollmentSetup> {
    let mut setup_tags = token
        .claims
        .tags
        .iter()
        .filter(|tag| tag.as_str().starts_with(KUBERNETES_HA_SETUP_TAG_PREFIX));
    let cohort_tag = setup_tags.next()?.as_str().to_string();
    if setup_tags.next().is_some()
        || cohort_tag != kubernetes_ha_cohort_tag(&token.claims.nonce)
        || token.claims.policy.max_token_uses != Some(KUBERNETES_HA_CONTROL_PLANE_COUNT)
    {
        return None;
    }
    let mut digest = Sha256::new();
    digest.update(b"heteronetwork-kubernetes-ha-bundle-v1\0");
    digest.update(encoded_token.as_bytes());
    let bundle_bearer_token = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Some(KubernetesHaEnrollmentSetup {
        cohort_tag,
        expected_control_planes: KUBERNETES_HA_CONTROL_PLANE_COUNT,
        bundle_bearer_token,
    })
}

fn kubernetes_ha_install_script(setup: KubernetesHaEnrollmentSetup) -> String {
    let helper = STANDARD.encode(KUBEADM_HA_NODE_SCRIPT.as_bytes());
    let autopilot = STANDARD.encode(KUBEADM_HA_AUTOPILOT_SCRIPT.as_bytes());
    format!(
        r#"install -d -o root -g root -m 0755 /opt/heteronetwork/libexec
install -d -o root -g root -m 0700 /etc/heteronetwork/kubernetes
printf '%s' '{helper}' | base64 -d >/opt/heteronetwork/libexec/kubeadm-ha-node.sh
printf '%s' '{autopilot}' | base64 -d >/opt/heteronetwork/libexec/kubeadm-ha-autopilot.sh
chown root:root /opt/heteronetwork/libexec/kubeadm-ha-node.sh /opt/heteronetwork/libexec/kubeadm-ha-autopilot.sh
chmod 0755 /opt/heteronetwork/libexec/kubeadm-ha-node.sh /opt/heteronetwork/libexec/kubeadm-ha-autopilot.sh
cat >/etc/heteronetwork/kubernetes/autopilot.env <<'AUTOPILOT_ENV'
HETERONETWORK_KUBEADM_COHORT_TAG={cohort_tag}
HETERONETWORK_KUBEADM_EXPECTED_CONTROL_PLANES={expected_control_planes}
HETERONETWORK_KUBEADM_BUNDLE_BEARER_TOKEN={bundle_bearer_token}
AUTOPILOT_ENV
chown root:root /etc/heteronetwork/kubernetes/autopilot.env
chmod 0600 /etc/heteronetwork/kubernetes/autopilot.env
cat >/etc/systemd/system/heteronetwork-kubeadm-autopilot.service <<'AUTOPILOT_UNIT'
[Unit]
Description=HeteroNetwork automatic Kubernetes HA control-plane setup
Wants=network-online.target
After=network-online.target heteronetwork-agent.service
Requires=heteronetwork-agent.service
StartLimitIntervalSec=0

[Service]
Type=oneshot
EnvironmentFile=-/etc/heteronetwork/kubernetes/autopilot.env
ExecStart=/opt/heteronetwork/libexec/kubeadm-ha-autopilot.sh run
Restart=on-failure
RestartSec=15s
TimeoutStartSec=infinity
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
AUTOPILOT_UNIT
systemctl daemon-reload
systemctl enable --now --no-block heteronetwork-kubeadm-autopilot.service
echo "Automatic three-control-plane Kubernetes HA setup scheduled"
"#,
        helper = helper,
        autopilot = autopilot,
        cohort_tag = setup.cohort_tag,
        expected_control_planes = setup.expected_control_planes,
        bundle_bearer_token = setup.bundle_bearer_token,
    )
}

fn node_enrollment_install_command(
    enrollment: &NodeEnrollmentConfig,
    encoded_token: &str,
    bootstrap_endpoints: &[BootstrapEndpoint],
) -> String {
    let script_bases = node_enrollment_download_bases(enrollment, bootstrap_endpoints)
        .into_iter()
        .map(|base| STANDARD.encode(base.as_bytes()))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "sh -c 'set -eu; tmp=$(mktemp); trap \"rm -f \\\"$tmp\\\"\" EXIT HUP INT TERM; auth=\"{encoded_token}\"; for encoded_base in {script_bases}; do base=$(printf \"%s\" \"$encoded_base\" | base64 -d) || continue; if curl -fsS -H \"Authorization: {NODE_ENROLLMENT_AUTH_SCHEME} $auth\" \"$base/v1/install/linux-amd64.sh\" -o \"$tmp\"; then sudo sh \"$tmp\"; exit; fi; done; echo \"HeteroNetwork installer download failed on every control-plane endpoint\" >&2; exit 1'"
    )
}

fn node_enrollment_download_bases(
    enrollment: &NodeEnrollmentConfig,
    bootstrap_endpoints: &[BootstrapEndpoint],
) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut bases = Vec::new();
    for base in std::iter::once(enrollment.install_base_url.as_ref()).chain(
        bootstrap_endpoints
            .iter()
            .filter(|endpoint| {
                matches!(
                    endpoint.kind,
                    BootstrapEndpointKind::ControlPlane | BootstrapEndpointKind::WebUi
                )
            })
            .map(|endpoint| endpoint.url.as_str()),
    ) {
        let base = base.trim_end_matches('/').to_string();
        if seen.insert(base.clone()) {
            bases.push(base);
        }
    }
    bases
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

async fn join_client<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<JoinClientRequest>,
) -> Result<(StatusCode, Json<RegisterClientResponse>), ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let response = state
        .join_service
        .join_client(request.token, request.registration, Utc::now())
        .await?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn client_peers<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<ClientControlRequest>,
) -> Result<Json<RegisterClientResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let client = state
        .plane
        .authenticate_client_request(&request, ClientRequestKind::PeerMap, Utc::now())
        .await?;
    state
        .plane
        .update_client_gateway_selection(
            &client,
            request.active_gateway_node_id.as_ref(),
            Utc::now(),
        )
        .await?;
    let peer_map = state.plane.peer_map_for(&request.client_id).await?;
    let cluster_policy = state.plane.cluster_policy()?;
    Ok(Json(RegisterClientResponse {
        client,
        peer_map,
        cluster_policy,
    }))
}

async fn remove_client<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Path(client_id): Path<String>,
    Json(request): Json<ClientControlRequest>,
) -> Result<Json<RemoveClientResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let path_client_id = NodeId::from_string(client_id);
    if request.client_id != path_client_id {
        return Err(ControlPlaneError::NodeUpdateRejected {
            node_id: request.client_id.clone(),
            reason: format!(
                "path client ID {path_client_id} does not match request client ID {}",
                request.client_id
            ),
        }
        .into());
    }
    Ok(Json(state.plane.remove_client(request).await?))
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

fn dynamic_web_gateway_instance_id(node_id: &NodeId) -> String {
    let digest = Sha256::digest(node_id.as_str().as_bytes());
    format!("agent-web-ui-{digest:x}")
}

fn dynamic_web_gateway_url(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(ip) => format!("https://{ip}"),
        std::net::IpAddr::V6(ip) => format!("https://[{ip}]"),
    }
}

fn dynamic_web_gateway_oidc_discovery(
    body: &Value,
    gateway_url: &str,
) -> Result<Option<(String, String)>, String> {
    if body.get("auth_enabled").and_then(Value::as_bool) != Some(true) {
        return Ok(None);
    }
    if body.get("provider").and_then(Value::as_str) != Some("keycloak") {
        return Ok(None);
    }
    let issuer = body
        .get("issuer_url")
        .and_then(Value::as_str)
        .filter(|issuer| !issuer.is_empty())
        .ok_or_else(|| "UI config omitted the OIDC issuer".to_string())?;
    let gateway = Url::parse(gateway_url)
        .map_err(|error| format!("dynamic Web gateway URL is invalid: {error}"))?;
    let mut discovery =
        Url::parse(issuer).map_err(|error| format!("UI config OIDC issuer is invalid: {error}"))?;
    if discovery.origin() != gateway.origin() {
        return Err("UI config OIDC issuer uses a different origin".to_string());
    }
    if discovery.query().is_some() || discovery.fragment().is_some() {
        return Err("UI config OIDC issuer must not contain a query or fragment".to_string());
    }
    let path = format!(
        "{}/.well-known/openid-configuration",
        discovery.path().trim_end_matches('/')
    );
    discovery.set_path(&path);
    Ok(Some((
        issuer.trim_end_matches('/').to_string(),
        discovery.to_string(),
    )))
}

async fn probe_dynamic_web_gateway(
    config: &DynamicWebGatewayConfig,
    url: &str,
    expected_cluster_id: &str,
) -> Result<(), String> {
    let mut response = config
        .client
        .get(format!("{url}/ui/config"))
        .header(header::ACCEPT, "application/json")
        .timeout(config.probe_timeout)
        .send()
        .await
        .map_err(|error| format!("connection failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("UI config returned HTTP {}", response.status()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_DYNAMIC_WEB_GATEWAY_CONFIG_BYTES)
    {
        return Err("UI config response exceeds its size limit".to_string());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("failed to read UI config: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_DYNAMIC_WEB_GATEWAY_CONFIG_BYTES as usize {
            return Err("UI config response exceeds its size limit".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    let body: Value = serde_json::from_slice(&body)
        .map_err(|error| format!("UI config is invalid JSON: {error}"))?;
    if body.get("enabled").and_then(Value::as_bool) != Some(true) {
        return Err("UI config reports that the Web UI is disabled".to_string());
    }
    if body.get("cluster_id").and_then(Value::as_str) != Some(expected_cluster_id) {
        return Err("UI config belongs to a different cluster".to_string());
    }
    if let Some((expected_issuer, discovery_url)) = dynamic_web_gateway_oidc_discovery(&body, url)?
    {
        let mut response = config
            .client
            .get(discovery_url)
            .header(header::ACCEPT, "application/json")
            .timeout(config.probe_timeout)
            .send()
            .await
            .map_err(|error| format!("OIDC discovery connection failed: {error}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "OIDC discovery returned HTTP {}",
                response.status()
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_DYNAMIC_WEB_GATEWAY_CONFIG_BYTES)
        {
            return Err("OIDC discovery response exceeds its size limit".to_string());
        }
        let mut discovery_body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| format!("failed to read OIDC discovery response: {error}"))?
        {
            if discovery_body.len().saturating_add(chunk.len())
                > MAX_DYNAMIC_WEB_GATEWAY_CONFIG_BYTES as usize
            {
                return Err("OIDC discovery response exceeds its size limit".to_string());
            }
            discovery_body.extend_from_slice(&chunk);
        }
        let discovery: Value = serde_json::from_slice(&discovery_body)
            .map_err(|error| format!("OIDC discovery response is invalid JSON: {error}"))?;
        let issuer = discovery
            .get("issuer")
            .and_then(Value::as_str)
            .map(|issuer| issuer.trim_end_matches('/'));
        if issuer != Some(expected_issuer.as_str()) {
            return Err("OIDC discovery returned a different issuer".to_string());
        }
    }
    Ok(())
}

async fn reconcile_dynamic_web_gateway<S, L>(
    state: &ControlPlaneHttpState<S, L>,
    node_id: &NodeId,
) -> Result<(), ControlPlaneError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let Some(config) = state.dynamic_web_gateway.as_ref() else {
        return Ok(());
    };
    let instance_id = dynamic_web_gateway_instance_id(node_id);
    let now = Utc::now();
    let classification = state.plane.nat_classification_for(node_id).await?;
    let public_ip = classification.as_ref().and_then(|classification| {
        let age = now.signed_duration_since(classification.assessed_at);
        (classification.connectivity_state == NatConnectivityState::Public
            && classification.public_state_is_supported()
            && socket_addr_is_globally_routable(classification.local_addr)
            && age >= ChronoDuration::zero()
            && age <= config.classification_max_age)
            .then_some(classification.local_addr.ip())
    });
    let Some(public_ip) = public_ip else {
        state.plane.withdraw_service_instance(&instance_id).await?;
        return Ok(());
    };
    let url = dynamic_web_gateway_url(public_ip);
    if let Err(error) =
        probe_dynamic_web_gateway(config, &url, state.plane.config().cluster_id.as_str()).await
    {
        state.plane.withdraw_service_instance(&instance_id).await?;
        tracing::warn!(
            %node_id,
            %public_ip,
            %error,
            "withdrew unreachable dynamic Web UI gateway"
        );
        return Ok(());
    }
    state
        .plane
        .advertise_service_instance(ServiceInstance {
            cluster_id: state.plane.config().cluster_id.clone(),
            instance_id,
            endpoints: vec![BootstrapEndpoint {
                kind: BootstrapEndpointKind::WebUi,
                url,
            }],
            lease_expires_at: now + config.lease_ttl,
            updated_at: now,
        })
        .await
}

async fn heartbeat<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Query(query): Query<HeartbeatQuery>,
    Json(request): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let node_id = request.node_id.clone();
    let wait = Duration::from_secs(
        query
            .wait_seconds
            .min(MAX_HEARTBEAT_CONNECTION_INTENT_WAIT_SECONDS),
    );
    let mut response = state.plane.heartbeat(request).await?;
    reconcile_dynamic_web_gateway(&state, &node_id).await?;
    response.bootstrap_endpoints = state.plane.service_directory().await?.bootstrap_endpoints;
    Ok(Json(
        state
            .plane
            .wait_for_connection_intents(&node_id, response, wait)
            .await?,
    ))
}

#[derive(Debug, Deserialize)]
struct HeartbeatQuery {
    #[serde(default)]
    wait_seconds: u64,
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
        "# HELP ipars_control_plane_clients Number of registered control-only VPN clients."
    );
    prometheus_line!(&mut body, "# TYPE ipars_control_plane_clients gauge");
    prometheus_line!(
        &mut body,
        "ipars_control_plane_clients{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.client_count
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
        ("web_ui", metrics.active_web_ui_count),
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
    use std::io::Write as _;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::process::Stdio;

    use axum::body::Body;
    use axum::http::{header, Request};
    use ipars_control_plane::{
        ControlPlaneConfig, ControlPlaneJoinService, InMemoryStore, InMemoryTokenLedger,
        IssuerKeyRing,
    };
    use ipars_crypto::{encode_bytes, IdentityKeyPair};
    use ipars_types::api::{
        ClientControlRequest, ClientRequestKind, ControlPlaneMetricsResponse,
        ControlPlaneNodeQueryKind, ControlPlaneNodeQueryRequest, ControlPlaneOverviewResponse,
        ControlPlanePathsResponse, ControlPlanePolicyResponse, HeartbeatRequest, HeartbeatResponse,
        JoinClientRequest, JoinNodeRequest, RegisterClientRequest, RegisterClientResponse,
        RegisterNodeRequest, RegisterNodeResponse, RemoveClientResponse, RemoveNodeRequest,
        RemoveNodeResponse, RevokeTokenRequest, RevokeTokenResponse, RotateWireGuardKeyRequest,
        RotateWireGuardKeyResponse, SignalNodeAuthenticationResponse, SignalNodeUpsertRequest,
    };
    use ipars_types::{
        AclAction, AclRule, BootstrapEndpoint, BootstrapEndpointKind, CandidateSource, ClusterId,
        EndpointCandidate, EndpointCandidateKind, HealthState, JoinTokenClaims, KeyId,
        NatClassification, NatProbeObservation, NodeHealth, NodeId, PathMetrics, PathRecord,
        PathScore, PathState, PeerPathKey, Role, ServiceInstance, Tag, TokenPolicy, TokenStatus,
        TransportProtocol,
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
            None,
            "openid profile email".to_string(),
        ) {
            Ok(config) => config,
            Err(error) => panic!("keycloak config should be valid: {error}"),
        };
        let keycloak_config = keycloak.public_config("cluster-a".to_string());
        assert_eq!(
            keycloak_config.authorization_endpoint.as_deref(),
            Some("http://localhost:8080/realms/heteronetwork/protocol/openid-connect/auth")
        );
        assert_eq!(
            keycloak_config.device_authorization_endpoint.as_deref(),
            Some("http://localhost:8080/realms/heteronetwork/protocol/openid-connect/auth/device")
        );
        assert_eq!(keycloak_config.login_endpoint, None);
        let cognito = match WebUiAuthConfig::new(
            WebAuthProvider::Cognito,
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example".to_string(),
            "heteronetwork-web".to_string(),
            Some("https://login.example.com".to_string()),
            None,
            "openid".to_string(),
        ) {
            Ok(config) => config,
            Err(error) => panic!("cognito config should be valid: {error}"),
        };
        let cognito_config = cognito.public_config("cluster-a".to_string());
        assert_eq!(
            cognito_config.authorization_endpoint.as_deref(),
            Some("https://login.example.com/oauth2/authorize")
        );
        assert_eq!(
            cognito_config.token_endpoint.as_deref(),
            Some("https://login.example.com/oauth2/token")
        );
        assert_eq!(cognito_config.device_authorization_endpoint, None);
        let backchannel = WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "https://idp.example/realms/heteronetwork".to_string(),
            "heteronetwork-web".to_string(),
            None,
            Some("http://10.0.0.5:8080/realms/heteronetwork".to_string()),
            "openid".to_string(),
        )
        .and_then(|config| {
            config.with_backchannel_fallback_base_urls(vec![
                "https://idp-b.example/realms/heteronetwork".to_string(),
                "http://10.0.0.5:8080/realms/heteronetwork".to_string(),
            ])
        })
        .unwrap_or_else(|error| panic!("backchannel config should be valid: {error}"));
        assert_eq!(
            backchannel
                .public_config("cluster-a".to_string())
                .token_endpoint
                .as_deref(),
            Some("https://idp.example/realms/heteronetwork/protocol/openid-connect/token")
        );
        assert_eq!(
            backchannel.backchannel_token_endpoints,
            vec![
                "http://10.0.0.5:8080/realms/heteronetwork/protocol/openid-connect/token",
                "https://idp-b.example/realms/heteronetwork/protocol/openid-connect/token",
            ]
        );
        assert_eq!(
            backchannel.backchannel_userinfo_endpoints,
            vec![
                "http://10.0.0.5:8080/realms/heteronetwork/protocol/openid-connect/userinfo",
                "https://idp-b.example/realms/heteronetwork/protocol/openid-connect/userinfo",
            ]
        );
        assert!(WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "ftp://localhost/realm".to_string(),
            "heteronetwork-web".to_string(),
            None,
            None,
            "openid".to_string(),
        )
        .is_err());
        assert!(WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "http://203.0.113.10:8080/realms/ipars".to_string(),
            "ipars-web".to_string(),
            None,
            None,
            "openid".to_string(),
        )
        .is_err());
    }

    #[tokio::test]
    async fn oidc_backchannel_fallback_preserves_issuer_host(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let primary_listener =
            tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let primary_address = primary_listener.local_addr()?;
        let primary_task = tokio::spawn(async move {
            let app = Router::new().route(
                "/realms/heteronetwork/protocol/openid-connect/userinfo",
                get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
            );
            let _ = axum::serve(primary_listener, app).await;
        });
        let fallback_listener =
            tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let fallback_address = fallback_listener.local_addr()?;
        let fallback_task = tokio::spawn(async move {
            let app = Router::new().route(
                "/realms/heteronetwork/protocol/openid-connect/userinfo",
                get(|headers: HeaderMap| async move {
                    if matches!(
                        headers
                            .get(header::HOST)
                            .and_then(|value| value.to_str().ok()),
                        Some("issuer.example" | "203.0.113.52")
                    ) {
                        (StatusCode::OK, Json(serde_json::json!({"sub": "user-a"}))).into_response()
                    } else {
                        StatusCode::UNAUTHORIZED.into_response()
                    }
                }),
            );
            let _ = axum::serve(fallback_listener, app).await;
        });
        let config = WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "https://issuer.example/realms/heteronetwork".to_string(),
            "heteronetwork-web".to_string(),
            None,
            Some(format!("http://{primary_address}/realms/heteronetwork")),
            "openid".to_string(),
        )?
        .with_backchannel_fallback_base_urls(vec![format!(
            "http://{fallback_address}/realms/heteronetwork"
        )])?;

        assert!(config.validate_access_token("access-token").await);
        let dynamic_issuer_token = format!(
            "e30.{}.signature",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({
                "iss": "https://203.0.113.52/realms/heteronetwork"
            }))?)
        );
        assert!(config.validate_access_token(&dynamic_issuer_token).await);
        let foreign_realm_token = format!(
            "e30.{}.signature",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({
                "iss": "https://203.0.113.52/realms/other"
            }))?)
        );
        assert!(!config.validate_access_token(&foreign_realm_token).await);
        primary_task.abort();
        fallback_task.abort();
        Ok(())
    }

    #[test]
    fn dynamic_web_gateway_oidc_probe_stays_on_the_gateway_origin() {
        let authenticated = serde_json::json!({
            "auth_enabled": true,
            "provider": "keycloak",
            "issuer_url": "https://203.0.113.10/realms/kakurizai/"
        });
        assert_eq!(
            dynamic_web_gateway_oidc_discovery(&authenticated, "https://203.0.113.10"),
            Ok(Some((
                "https://203.0.113.10/realms/kakurizai".to_string(),
                "https://203.0.113.10/realms/kakurizai/.well-known/openid-configuration"
                    .to_string(),
            )))
        );

        let foreign_issuer = serde_json::json!({
            "auth_enabled": true,
            "provider": "keycloak",
            "issuer_url": "https://idp.example/realms/kakurizai"
        });
        assert!(
            dynamic_web_gateway_oidc_discovery(&foreign_issuer, "https://203.0.113.10").is_err()
        );

        let unauthenticated = serde_json::json!({"auth_enabled": false});
        assert_eq!(
            dynamic_web_gateway_oidc_discovery(&unauthenticated, "https://203.0.113.10"),
            Ok(None)
        );

        let external_provider = serde_json::json!({
            "auth_enabled": true,
            "provider": "cognito",
            "issuer_url": "https://cognito-idp.example/pool"
        });
        assert_eq!(
            dynamic_web_gateway_oidc_discovery(&external_provider, "https://203.0.113.10"),
            Ok(None)
        );
    }

    #[tokio::test]
    async fn server_side_oidc_login_uses_public_callback_and_pkce() {
        let config = WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "http://localhost:8080/realms/ipars".to_string(),
            "ipars-web".to_string(),
            None,
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
            config
                .public_config("cluster-a".to_string())
                .login_endpoint
                .as_deref(),
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

    fn enrollment_service_instance(
        cluster_id: &ClusterId,
        instance_id: &str,
        host: &str,
    ) -> ServiceInstance {
        let now = Utc::now();
        ServiceInstance {
            cluster_id: cluster_id.clone(),
            instance_id: instance_id.to_string(),
            endpoints: vec![
                BootstrapEndpoint {
                    kind: BootstrapEndpointKind::ControlPlane,
                    url: format!("https://{host}:8443"),
                },
                BootstrapEndpoint {
                    kind: BootstrapEndpointKind::Signal,
                    url: format!("https://{host}:9443"),
                },
                BootstrapEndpoint {
                    kind: BootstrapEndpointKind::Stun,
                    url: format!("udp://{host}:3478"),
                },
                BootstrapEndpoint {
                    kind: BootstrapEndpointKind::Relay,
                    url: format!("udp://{host}:51820"),
                },
            ],
            lease_expires_at: now + chrono::Duration::minutes(5),
            updated_at: now,
        }
    }

    #[test]
    fn node_enrollment_downloads_through_dynamic_web_gateways(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let binary_path = std::env::temp_dir().join(format!(
            "heteronetwork-enrollment-bases-test-{}",
            random_oidc_value(12)
        ));
        std::fs::write(&binary_path, b"test-binary")?;
        let enrollment = NodeEnrollmentConfig::new(
            IdentityKeyPair::generate(),
            "web-enrollment".to_string(),
            "https://static.example".to_string(),
            binary_path.clone(),
            3600,
        )?;
        let endpoints = vec![
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "https://control.example:8443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::WebUi,
                url: "https://203.0.113.10".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Signal,
                url: "https://signal.example:9443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::WebUi,
                url: "https://static.example".to_string(),
            },
        ];
        assert_eq!(
            node_enrollment_download_bases(&enrollment, &endpoints),
            vec![
                "https://static.example".to_string(),
                "https://control.example:8443".to_string(),
                "https://203.0.113.10".to_string(),
            ]
        );
        drop(enrollment);
        std::fs::remove_file(binary_path)?;
        Ok(())
    }

    #[tokio::test]
    async fn node_enrollment_issues_ha_single_use_token_and_protects_artifacts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let issuer_private_key = issuer.signing_key_b64();
        let key_id = KeyId::from_string("web-enrollment");
        let cluster_id = ClusterId::from_string("cluster-enrollment");
        let store = Arc::new(InMemoryStore::default());
        let ledger = Arc::new(InMemoryTokenLedger::default());
        let plane = Arc::new(ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store,
        ));
        for (instance_id, host) in [
            ("public-a", "public-a.example"),
            ("public-b", "public-b.example"),
        ] {
            plane
                .advertise_service_instance(enrollment_service_instance(
                    &cluster_id,
                    instance_id,
                    host,
                ))
                .await?;
        }
        let mut gateway_claims = claims(cluster_id.clone(), issuer.node_id(), key_id.clone());
        gateway_claims.role = Role::gateway();
        let mut gateway_registration = registration("mac-client-gateway");
        gateway_registration.candidates = vec![candidate("mac-client-gateway")];
        gateway_registration.candidates[0].kind = EndpointCandidateKind::PublicUdp;
        gateway_registration.candidates[0].addr = "8.8.8.8:51820".parse()?;
        let gateway = plane
            .register_with_claims(gateway_claims, gateway_registration)
            .await?
            .node;

        let mut key_ring = IssuerKeyRing::default();
        key_ring.insert_node_enrollment_key(
            issuer.node_id(),
            key_id.clone(),
            issuer.public_key_b64(),
            7 * 24 * 60 * 60,
        );
        let join_service = Arc::new(ControlPlaneJoinService::new(
            plane.clone(),
            ledger,
            key_ring,
        ));
        let binary_contents = b"test-iparsd-linux-amd64";
        let binary_path = std::env::temp_dir().join(format!(
            "heteronetwork-enrollment-test-{}",
            random_oidc_value(12)
        ));
        std::fs::write(&binary_path, binary_contents)?;
        let enrollment = NodeEnrollmentConfig::new(
            issuer,
            key_id.as_str().to_string(),
            "http://127.0.0.1:8443".to_string(),
            binary_path.clone(),
            7 * 24 * 60 * 60,
        )?;
        let expected_sha256 = enrollment.binary_sha256.to_string();
        let app = router(
            ControlPlaneHttpState::new(plane.clone(), join_service)
                .require_operator_api_bearer_token(OPERATOR_API_BEARER_TOKEN.to_string())
                .enable_node_enrollment(enrollment),
        );
        let request_body = serde_json::json!({
            "expires_in_seconds": 86_400,
            "role": "edge",
            "tags": ["production", "linux"],
            "allow_relay": true,
            "reusable": false,
            "max_uses": 1
        });

        let unauthenticated = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/enrollment")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&request_body)?))?,
            )
            .await?;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers().get(header::LOCATION),
            Some(&header::HeaderValue::from_static("/ui/"))
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/enrollment")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::from(serde_json::to_vec(&request_body)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&header::HeaderValue::from_static("no-store"))
        );
        let response_body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response_body: Value = serde_json::from_slice(&response_body)?;
        assert_eq!(response_body["max_uses"], 1);
        assert_eq!(response_body["architecture"], NODE_ENROLLMENT_ARCH);
        assert_eq!(response_body["binary_sha256"], expected_sha256);
        let install_command = response_body["install_command"]
            .as_str()
            .ok_or("node enrollment response omitted the install command")?;
        let generated_script = response_body["install_script"]
            .as_str()
            .ok_or("node enrollment response omitted the install script")?;
        for expected_base in [
            "http://127.0.0.1:8443",
            "https://public-a.example:8443",
            "https://public-b.example:8443",
        ] {
            let encoded_base = STANDARD.encode(expected_base.as_bytes());
            assert!(install_command.contains(&encoded_base));
            assert!(generated_script.contains(&encoded_base));
        }
        let command_syntax = std::process::Command::new("sh")
            .args(["-n", "-c", install_command])
            .output()?;
        assert!(
            command_syntax.status.success(),
            "generated install command is not valid POSIX shell: {}",
            String::from_utf8_lossy(&command_syntax.stderr)
        );
        let token: SignedJoinToken = serde_json::from_value(response_body["token"].clone())?;
        assert_eq!(token.claims.bootstrap_endpoints.len(), 8);
        assert_eq!(token.claims.policy.max_token_uses, Some(1));
        assert!(token.claims.policy.allow_relay);
        assert_eq!(response_body["setup"], "network_only");
        assert!(!generated_script.contains("kubeadm-ha-autopilot"));
        assert!(generated_script.contains("systemctl restart heteronetwork-gateway.service"));
        assert!(generated_script.contains("systemctl restart heteronetwork-agent.service"));

        let kubernetes_request_body = serde_json::json!({
            "expires_in_seconds": 86_400,
            "role": "worker",
            "tags": ["production"],
            "allow_relay": true,
            "reusable": true,
            "max_uses": KUBERNETES_HA_CONTROL_PLANE_COUNT,
            "setup": "kubernetes_ha_control_plane"
        });
        let kubernetes_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/enrollment")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::from(serde_json::to_vec(&kubernetes_request_body)?))?,
            )
            .await?;
        assert_eq!(kubernetes_response.status(), StatusCode::OK);
        let kubernetes_response =
            axum::body::to_bytes(kubernetes_response.into_body(), usize::MAX).await?;
        let kubernetes_response: Value = serde_json::from_slice(&kubernetes_response)?;
        assert_eq!(kubernetes_response["setup"], "kubernetes_ha_control_plane");
        let kubernetes_token: SignedJoinToken =
            serde_json::from_value(kubernetes_response["token"].clone())?;
        let cohort_tags = kubernetes_token
            .claims
            .tags
            .iter()
            .filter(|tag| tag.as_str().starts_with(KUBERNETES_HA_SETUP_TAG_PREFIX))
            .collect::<Vec<_>>();
        assert_eq!(cohort_tags.len(), 1);
        assert!(kubernetes_token
            .claims
            .tags
            .contains(&Tag::kubernetes_control_plane()));
        assert_eq!(
            cohort_tags[0].as_str(),
            kubernetes_ha_cohort_tag(&kubernetes_token.claims.nonce)
        );
        let kubernetes_script = kubernetes_response["install_script"]
            .as_str()
            .ok_or("Kubernetes enrollment response omitted the install script")?;
        assert!(kubernetes_script.contains("heteronetwork-kubeadm-autopilot.service"));
        assert!(!kubernetes_script.contains("KUBERNETES_HA_SETUP_TAG_PREFIX"));
        let script_syntax = std::process::Command::new("sh")
            .args(["-n", "-c", kubernetes_script])
            .output()?;
        assert!(
            script_syntax.status.success(),
            "generated Kubernetes install script is not valid POSIX shell: {}",
            String::from_utf8_lossy(&script_syntax.stderr)
        );

        let invalid_kubernetes_request = serde_json::json!({
            "expires_in_seconds": 86_400,
            "role": "worker",
            "tags": [],
            "allow_relay": true,
            "reusable": true,
            "max_uses": 4,
            "setup": "kubernetes_ha_control_plane"
        });
        let invalid_kubernetes_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/enrollment")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::from(serde_json::to_vec(&invalid_kubernetes_request)?))?,
            )
            .await?;
        assert_eq!(
            invalid_kubernetes_response.status(),
            StatusCode::BAD_REQUEST
        );

        let reserved_tag_request = serde_json::json!({
            "expires_in_seconds": 86_400,
            "role": "edge",
            "tags": ["kubernetes-ha-0123456789abcdef"],
            "allow_relay": false,
            "reusable": false,
            "max_uses": 1
        });
        let reserved_tag_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/enrollment")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::from(serde_json::to_vec(&reserved_tag_request)?))?,
            )
            .await?;
        assert_eq!(reserved_tag_response.status(), StatusCode::BAD_REQUEST);

        let degraded_at = Utc::now();
        let mut expired_public_a =
            enrollment_service_instance(&cluster_id, "public-a", "public-a.example");
        expired_public_a.updated_at = degraded_at - ChronoDuration::seconds(60);
        expired_public_a.lease_expires_at = degraded_at - ChronoDuration::seconds(30);
        plane.advertise_service_instance(expired_public_a).await?;
        let active_directory = plane.service_directory().await?;
        assert_eq!(active_directory.instances.len(), 1);
        assert_eq!(active_directory.instances[0].instance_id, "public-b");
        assert!(!plane.metrics().await?.ha_ready);

        let degraded_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/enrollment")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::from(serde_json::to_vec(&request_body)?))?,
            )
            .await?;
        assert_eq!(degraded_response.status(), StatusCode::OK);
        let degraded_response =
            axum::body::to_bytes(degraded_response.into_body(), usize::MAX).await?;
        let degraded_response: Value = serde_json::from_slice(&degraded_response)?;
        let degraded_token: SignedJoinToken =
            serde_json::from_value(degraded_response["token"].clone())?;
        assert_eq!(degraded_token.claims.bootstrap_endpoints.len(), 8);
        for host in ["public-a.example", "public-b.example"] {
            assert!(degraded_token
                .claims
                .bootstrap_endpoints
                .iter()
                .any(|endpoint| endpoint.url.contains(host)));
        }

        let encoded_token = encode_node_enrollment_authorization(&token)
            .map_err(|error| std::io::Error::other(error.message))?;
        let authorization = format!("{NODE_ENROLLMENT_AUTH_SCHEME} {encoded_token}");

        let missing_script_auth = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/install/linux-amd64.sh")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(missing_script_auth.status(), StatusCode::UNAUTHORIZED);
        let script_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/install/linux-amd64.sh")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(script_response.status(), StatusCode::OK);
        assert_eq!(
            script_response.headers().get(header::CACHE_CONTROL),
            Some(&header::HeaderValue::from_static("no-store"))
        );
        let script = String::from_utf8(
            axum::body::to_bytes(script_response.into_body(), usize::MAX)
                .await?
                .to_vec(),
        )?;
        assert!(script.contains("--enroll-only"));
        assert!(script.contains("--packet-flow-detector conntrack-netlink-events"));
        assert!(script.contains("--packet-flow-poll-interval-seconds 1"));
        assert!(script.contains("heteronetwork-gateway.service"));
        assert!(script.contains("systemd-sysusers"));
        assert!(script.contains("User=heteronetwork-gateway"));
        assert!(script.contains("SupplementaryGroups=heteronetwork-gateway"));
        assert!(
            script.contains("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE")
        );
        assert!(script.contains("admin unix//run/heteronetwork-gateway/admin.sock|0660"));
        assert!(script.contains(&format!(
            "caddy_{NODE_ENROLLMENT_CADDY_VERSION}_linux_amd64.tar.gz"
        )));
        assert!(script.contains(NODE_ENROLLMENT_CADDY_SHA256));
        assert!(!script.contains("__CADDY_VERSION__"));
        assert!(!script.contains("__CADDY_SHA256__"));
        assert!(script.contains(&expected_sha256));
        assert!(script.contains(&encoded_token));
        assert!(!script.contains(&issuer_private_key));
        let mut shell = std::process::Command::new("sh")
            .arg("-n")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        shell
            .stdin
            .take()
            .ok_or("shell syntax checker stdin is unavailable")?
            .write_all(script.as_bytes())?;
        let shell_output = shell.wait_with_output()?;
        assert!(
            shell_output.status.success(),
            "generated installer is not valid POSIX shell: {}",
            String::from_utf8_lossy(&shell_output.stderr)
        );

        let binary_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/install/iparsd-linux-amd64")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(binary_response.status(), StatusCode::OK);
        assert_eq!(
            binary_response
                .headers()
                .get("x-heteronetwork-sha256")
                .and_then(|value| value.to_str().ok()),
            Some(expected_sha256.as_str())
        );
        assert_eq!(
            axum::body::to_bytes(binary_response.into_body(), usize::MAX).await?,
            binary_contents.as_slice()
        );

        let first_join = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/join")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&JoinNodeRequest {
                        token: token.clone(),
                        registration: registration("enrolled-a"),
                    })?))?,
            )
            .await?;
        assert_eq!(first_join.status(), StatusCode::CREATED);
        let second_join = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/join")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&JoinNodeRequest {
                        token,
                        registration: registration("enrolled-b"),
                    })?))?,
            )
            .await?;
        assert_eq!(second_join.status(), StatusCode::FORBIDDEN);
        let exhausted_artifact = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/install/linux-amd64.sh")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(exhausted_artifact.status(), StatusCode::UNAUTHORIZED);

        let client_enrollment = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/client-enrollment")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::from(r#"{"expires_in_seconds":3600}"#))?,
            )
            .await?;
        assert_eq!(client_enrollment.status(), StatusCode::OK);
        let client_enrollment_body =
            axum::body::to_bytes(client_enrollment.into_body(), usize::MAX).await?;
        let client_enrollment_body: Value = serde_json::from_slice(&client_enrollment_body)?;
        assert!(client_enrollment_body["enrollment_uri"]
            .as_str()
            .is_some_and(|uri| uri.starts_with("heteronetwork://enroll?token=")));
        let client_token: SignedJoinToken =
            serde_json::from_value(client_enrollment_body["token"].clone())?;
        assert!(client_token.claims.role.is_client());
        assert!(client_token.claims.tags.is_empty());
        assert!(!client_token.claims.policy.allow_relay);
        assert!(client_token.claims.policy.allowed_routes.is_empty());
        assert!(client_token.claims.policy.allowed_tags.is_empty());
        assert_eq!(client_token.claims.policy.max_token_uses, Some(1));

        let wrong_endpoint = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/join")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&JoinNodeRequest {
                        token: client_token.clone(),
                        registration: registration("wrong-client-endpoint"),
                    })?))?,
            )
            .await?;
        assert_eq!(wrong_endpoint.status(), StatusCode::FORBIDDEN);

        let client_identity = identity_for_node("native-mac-client");
        let client_join = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/clients/join")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&JoinClientRequest {
                        token: client_token,
                        registration: RegisterClientRequest {
                            client_id: client_identity.node_id(),
                            identity_public_key: client_identity.public_key_b64(),
                            wireguard_public_key: wireguard_public_key_for_node(
                                "native-mac-client",
                            ),
                        },
                    })?))?,
            )
            .await?;
        assert_eq!(client_join.status(), StatusCode::CREATED);
        let client_join_body = axum::body::to_bytes(client_join.into_body(), usize::MAX).await?;
        let client_join: RegisterClientResponse = serde_json::from_slice(&client_join_body)?;
        assert!(client_join.client.role.is_client());
        assert_eq!(client_join.peer_map.peers.len(), 1);
        assert_eq!(client_join.peer_map.peers[0].node_id, gateway.node_id);

        let client_heartbeat = signed_heartbeat(
            "native-mac-client",
            HeartbeatRequest {
                node_id: client_join.client.node_id.clone(),
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
                nat_classification: None,
                node_signature: None,
            },
        );
        let heartbeat_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/heartbeat")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&client_heartbeat)?))?,
            )
            .await?;
        assert_eq!(heartbeat_response.status(), StatusCode::FORBIDDEN);

        for (path, kind) in [
            ("/v1/peers/query", ControlPlaneNodeQueryKind::PeerMap),
            ("/v1/paths/query", ControlPlaneNodeQueryKind::Paths),
        ] {
            let query_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(serde_json::to_vec(&signed_node_query(
                            "native-mac-client",
                            kind,
                        ))?))?,
                )
                .await?;
            assert_eq!(query_response.status(), StatusCode::UNAUTHORIZED);
        }

        let mut signal_upsert = SignalNodeUpsertRequest {
            node: client_join.client.clone(),
            nat_classification: None,
            health: None,
            request_signature: None,
        };
        signal_upsert.request_signature =
            Some(client_identity.sign_signal_node_upsert_request(&signal_upsert, Utc::now())?);
        let signal_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/nodes/authenticate-signal-upsert")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&signal_upsert)?))?,
            )
            .await?;
        assert_eq!(signal_response.status(), StatusCode::FORBIDDEN);

        let normal_removal_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/nodes/{}", client_join.client.node_id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&signed_remove_node(
                        "native-mac-client",
                    ))?))?,
            )
            .await?;
        assert_eq!(normal_removal_response.status(), StatusCode::FORBIDDEN);

        let normal_rotation_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/v1/nodes/{}/wireguard-key",
                        client_join.client.node_id
                    ))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(
                        &signed_wireguard_key_rotation(
                            "native-mac-client",
                            client_join.client.wireguard_public_key.clone(),
                            wireguard_public_key_for_node("native-mac-client-rotated"),
                        ),
                    )?))?,
            )
            .await?;
        assert_eq!(normal_rotation_response.status(), StatusCode::FORBIDDEN);

        let mut query = ClientControlRequest {
            client_id: client_join.client.node_id.clone(),
            active_gateway_node_id: None,
            request_signature: None,
        };
        query.request_signature = Some(client_identity.sign_client_control_request(
            &query,
            ClientRequestKind::PeerMap,
            Utc::now(),
        ));
        let peer_map = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/clients/peers/query")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&query)?))?,
            )
            .await?;
        assert_eq!(peer_map.status(), StatusCode::OK);
        let peer_map_body = axum::body::to_bytes(peer_map.into_body(), usize::MAX).await?;
        let client_configuration: RegisterClientResponse = serde_json::from_slice(&peer_map_body)?;
        assert_eq!(client_configuration.client, client_join.client);
        assert_eq!(client_configuration.peer_map.peers.len(), 1);
        assert_eq!(
            client_configuration.peer_map.peers[0].node_id,
            gateway.node_id
        );
        assert_eq!(
            client_configuration.cluster_policy,
            client_join.cluster_policy
        );

        let admin_nodes = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/nodes")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(admin_nodes.status(), StatusCode::OK);
        let admin_nodes = axum::body::to_bytes(admin_nodes.into_body(), usize::MAX).await?;
        let admin_nodes: Value = serde_json::from_slice(&admin_nodes)?;
        assert!(admin_nodes.as_array().is_some_and(|nodes| nodes
            .iter()
            .all(|entry| { entry["node"]["role"].as_str() != Some("client") })));

        let metrics = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/metrics")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(metrics.status(), StatusCode::OK);
        let metrics = axum::body::to_bytes(metrics.into_body(), usize::MAX).await?;
        let metrics: ControlPlaneMetricsResponse = serde_json::from_slice(&metrics)?;
        assert_eq!(metrics.client_count, 1);
        assert_eq!(metrics.node_count, 2);

        let stale_lease = Utc::now() - ChronoDuration::days(8);
        let mut stale_public_a =
            enrollment_service_instance(&cluster_id, "public-a", "public-a.example");
        stale_public_a.updated_at = stale_lease - ChronoDuration::seconds(30);
        stale_public_a.lease_expires_at = stale_lease;
        plane.advertise_service_instance(stale_public_a).await?;
        let stale_enrollment = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/enrollment")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::from(serde_json::to_vec(&request_body)?))?,
            )
            .await?;
        assert_eq!(stale_enrollment.status(), StatusCode::SERVICE_UNAVAILABLE);

        let mut removal = ClientControlRequest {
            client_id: client_join.client.node_id.clone(),
            active_gateway_node_id: None,
            request_signature: None,
        };
        removal.request_signature = Some(client_identity.sign_client_control_request(
            &removal,
            ClientRequestKind::Remove,
            Utc::now(),
        ));
        let removal_response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/clients/{}", removal.client_id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&removal)?))?,
            )
            .await?;
        assert_eq!(removal_response.status(), StatusCode::OK);
        let removal_body = axum::body::to_bytes(removal_response.into_body(), usize::MAX).await?;
        let removed: RemoveClientResponse = serde_json::from_slice(&removal_body)?;
        assert_eq!(removed.client.node_id, client_join.client.node_id);
        std::fs::remove_file(binary_path)?;
        Ok(())
    }

    #[test]
    fn node_enrollment_requires_redundant_service_kinds_and_bounded_uses(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-enrollment-degraded");
        let instance = enrollment_service_instance(&cluster_id, "public-a", "public-a.example");
        let directory = ipars_types::ServiceDirectory {
            cluster_id,
            bootstrap_endpoints: instance.endpoints.clone(),
            instances: vec![instance],
            generated_at: Utc::now(),
        };
        let error = match require_ha_node_enrollment_directory(&directory, true) {
            Ok(_) => return Err("a single public service instance issued an HA token".into()),
            Err(error) => error,
        };
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(error.message.contains("control_plane"));
        assert!(error.message.contains("relay"));

        let mut duplicate_instance = directory.instances[0].clone();
        duplicate_instance.instance_id = "public-b".to_string();
        let duplicate_directory = ipars_types::ServiceDirectory {
            instances: vec![directory.instances[0].clone(), duplicate_instance],
            bootstrap_endpoints: directory.bootstrap_endpoints.clone(),
            ..directory.clone()
        };
        let duplicate_error = match require_ha_node_enrollment_directory(&duplicate_directory, true)
        {
            Ok(_) => return Err("duplicate service URLs counted as independent endpoints".into()),
            Err(error) => error,
        };
        assert_eq!(duplicate_error.status, StatusCode::SERVICE_UNAVAILABLE);

        let generated_at = Utc::now();
        let mut recently_expired =
            enrollment_service_instance(&directory.cluster_id, "public-a", "public-a.example");
        recently_expired.updated_at = generated_at - ChronoDuration::seconds(60);
        recently_expired.lease_expires_at = generated_at - ChronoDuration::seconds(30);
        let active =
            enrollment_service_instance(&directory.cluster_id, "public-b", "public-b.example");
        let degraded_directory = ipars_types::ServiceDirectory {
            cluster_id: directory.cluster_id.clone(),
            bootstrap_endpoints: recently_expired
                .endpoints
                .iter()
                .chain(active.endpoints.iter())
                .cloned()
                .collect(),
            instances: vec![recently_expired.clone(), active.clone()],
            generated_at,
        };
        require_ha_node_enrollment_directory(&degraded_directory, true)
            .map_err(|error| error.message)?;
        require_ha_client_enrollment_directory(&degraded_directory)
            .map_err(|error| error.message)?;

        let mut inactive = active;
        inactive.updated_at = generated_at - ChronoDuration::seconds(60);
        inactive.lease_expires_at = generated_at - ChronoDuration::seconds(30);
        let inactive_directory = ipars_types::ServiceDirectory {
            instances: vec![recently_expired, inactive],
            ..degraded_directory
        };
        assert!(require_ha_node_enrollment_directory(&inactive_directory, true).is_err());
        assert!(require_ha_client_enrollment_directory(&inactive_directory).is_err());

        let invalid = AdminNodeEnrollmentRequest {
            expires_in_seconds: 86_400,
            role: "edge".to_string(),
            tags: Vec::new(),
            allow_relay: false,
            reusable: true,
            max_uses: Some(1),
            setup: NodeEnrollmentSetup::NetworkOnly,
        };
        assert!(node_enrollment_max_uses(&invalid).is_err());
        let valid = AdminNodeEnrollmentRequest {
            max_uses: Some(MAX_NODE_ENROLLMENT_TOKEN_USES),
            ..invalid
        };
        assert_eq!(
            node_enrollment_max_uses(&valid).map_err(|error| error.message),
            Ok(MAX_NODE_ENROLLMENT_TOKEN_USES)
        );
        Ok(())
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
        let public_endpoint = SocketAddr::from(([8, 8, 8, 10], 40_000));
        let nat_endpoint = SocketAddr::from(([8, 8, 8, 11], 40_001));
        let relay_endpoint_a = SocketAddr::from(([8, 8, 8, 12], 40_002));
        let relay_endpoint_b = SocketAddr::from(([8, 8, 8, 13], 40_003));
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
        assert!(body.contains("function renderEnrollment()"));
        assert!(body.contains("heteronetwork_locale"));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/ui/theme.js")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("prefers-color-scheme: dark"));
        assert!(body.contains("heteronetwork_theme"));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/ui/fonts/noto-sans-jp-ui.ttf")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("font/ttf")
        );
        assert!(response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("immutable")));
        assert!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await?
                .len()
                > 100_000
        );

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
        assert_eq!(ui_config["node_enrollment_enabled"], false);

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
