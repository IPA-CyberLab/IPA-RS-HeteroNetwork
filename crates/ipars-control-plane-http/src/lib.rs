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
    ControlPlanePathsResponse, ControlPlanePolicyResponse, ControlPlaneTopologyResponse,
    HeartbeatRequest, HeartbeatResponse, JoinClientRequest, JoinNodeRequest, PeerMap,
    RegisterClientResponse, RegisterNodeResponse, RemoveClientResponse, RemoveNodeRequest,
    RemoveNodeResponse, RevokeTokenRequest, RevokeTokenResponse, RotateWireGuardKeyRequest,
    RotateWireGuardKeyResponse, SignalNodeAuthenticationResponse, SignalNodeUpsertRequest,
    SponsoredClientRegistrationRequest,
};
use ipars_types::{
    bootstrap_endpoints_include_core_services, socket_addr_is_globally_routable, BootstrapEndpoint,
    BootstrapEndpointKind, ClusterId, ClusterPolicy, HealthState, JoinTokenClaims, KeyId,
    NatConnectivityState, NeighborMap, NodeHealth, NodeId, NodeRecord, OverlayPath,
    OverlayPathQuery, PathRecord, PathState, Role, ServiceInstance, SignedJoinToken, Tag,
    TokenLedgerMetrics, TokenPolicy, VpnIp, JOIN_TOKEN_NOT_BEFORE_SKEW_SECONDS,
    MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND, MAX_JOIN_TOKEN_TAGS, MAX_JOIN_TOKEN_TTL_SECONDS,
};
use rand_core::{OsRng, RngCore};
use reqwest::redirect::Policy as RedirectPolicy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, OnceCell};
use tokio::time::timeout;
use tokio_util::io::ReaderStream;
use url::Url;

const MAX_OPERATOR_API_BEARER_TOKEN_BYTES: usize = 512;
const AUTOPILOT_API_BEARER_TOKEN_HEX_BYTES: usize = 64;
const MIN_RELAY_ADMISSION_BEARER_TOKEN_BYTES: usize = 32;
const MAX_RELAY_ADMISSION_BEARER_TOKEN_BYTES: usize = 512;
const MAX_WEB_OIDC_LOGIN_STATES: usize = 1024;
const WEB_OIDC_LOGIN_STATE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_WEB_OIDC_TOKEN_RESPONSE_BYTES: usize = 1024 * 1024;
const WEB_OIDC_STATE_COOKIE: &str = "heteronetwork_oidc_state";
const WEB_OIDC_ACCESS_TOKEN_STORAGE_KEY: &str = "heteronetwork_access_token";
const WEB_OIDC_ACCESS_TOKEN_EXPIRES_AT_STORAGE_KEY: &str = "heteronetwork_access_token_expires_at";
const WEB_OIDC_REFRESH_COOKIE: &str = "heteronetwork_web_refresh";
const WEB_OIDC_REFRESH_COOKIE_PATH: &str = "/ui/auth";
const MAX_WEB_OIDC_ACCESS_TOKEN_BYTES: usize = 16 * 1024;
const MAX_WEB_OIDC_REFRESH_TOKEN_BYTES: usize = 2_800;
const MAX_WEB_OIDC_REFRESH_COOKIE_BYTES: usize = 4_096;
const MAX_WEB_OIDC_SESSION_SECONDS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_WEB_OIDC_REFRESH_COOKIE_SECONDS: u64 = 24 * 60 * 60;
const MAX_WEB_OIDC_REFRESH_CACHE_ENTRIES: usize = 256;
const MAX_WEB_OIDC_REFRESH_REVOCATIONS: usize = 256;
const WEB_OIDC_REFRESH_REPLAY_TTL: Duration = Duration::from_secs(5);
const WEB_OIDC_REFRESH_REVOCATION_TTL: Duration = Duration::from_secs(5 * 60);
const MIN_NODE_ENROLLMENT_TTL_SECONDS: u64 = 5 * 60;
const DEFAULT_REUSABLE_NODE_ENROLLMENT_USES: u32 = 10;
const MAX_NODE_ENROLLMENT_REQUEST_BYTES: usize = 16 * 1024;
const MAX_SPONSORED_CLIENT_REGISTRATION_REQUEST_BYTES: usize = 64 * 1024;
const MAX_DATABASE_AUTOPILOT_REQUEST_BYTES: usize = 8 * 1024;
const MAX_DATABASE_AUTOPILOT_MEMBER_IDS: usize = 32;
const MAX_DATABASE_AUTOPILOT_CANDIDATES: usize = 64;
const DATABASE_AUTOPILOT_REGISTRY_CACHE_TTL: Duration = Duration::from_secs(1);
const MAX_KEYCLOAK_AUTOPILOT_REQUEST_BYTES: usize = 4 * 1024;
const KEYCLOAK_AUTOPILOT_VERSION: &str = "26.6.4";
const KEYCLOAK_AUTOPILOT_DESIRED_REPLICAS: usize = 3;
const KEYCLOAK_AUTOPILOT_MAX_CANDIDATES: usize = 64;
const KEYCLOAK_AUTOPILOT_LEASE_SECONDS: u64 = 45;
const KEYCLOAK_AUTOPILOT_RECONCILE_SECONDS: u64 = 15;
const MAX_NODE_ENROLLMENT_AUTHORIZATION_BYTES: usize = 24 * 1024;
const MAX_NODE_ENROLLMENT_BINARY_BYTES: u64 = 128 * 1024 * 1024;
const NODE_ENROLLMENT_AUTH_SCHEME: &str = "HeteroNetworkJoin";
const NODE_ENROLLMENT_ARCH: &str = "linux-amd64";
const KUBERNETES_HA_SETUP_TAG_PREFIX: &str = "kubernetes-ha-";
const KUBERNETES_HA_CONTROL_PLANE_COUNT: u32 = 3;
const KUBEADM_HA_NODE_SCRIPT: &str = include_str!("../../../scripts/kubeadm-ha-node.sh");
const KUBEADM_HA_AUTOPILOT_SCRIPT: &str = include_str!("../../../scripts/kubeadm-ha-autopilot.sh");
const POSTGRES_HA_NODE_SCRIPT: &str = include_str!("../../../scripts/postgres-ha-node.sh");
const POSTGRES_HA_AUTOPILOT_SCRIPT: &str =
    include_str!("../../../scripts/postgres-ha-autopilot.sh");
const POSTGRES_HA_AUTOPILOT_UNIT: &str =
    include_str!("../../../deploy/systemd/heteronetwork-postgres-autopilot.service");
const KEYCLOAK_HA_NODE_SCRIPT: &str = include_str!("../../../scripts/keycloak-ha-node.sh");
const KEYCLOAK_AUTOPILOT_SCRIPT: &str = include_str!("../../../scripts/keycloak-autopilot.sh");
const KEYCLOAK_AUTOPILOT_UNIT: &str =
    include_str!("../../../deploy/systemd/heteronetwork-keycloak-autopilot.service");
const KEYCLOAK_AUTOPILOT_TIMER: &str =
    include_str!("../../../deploy/systemd/heteronetwork-keycloak-autopilot.timer");
const KEYCLOAK_PREPARE_UNIT: &str =
    include_str!("../../../deploy/systemd/heteronetwork-keycloak-prepare.service");
const PUBLIC_SERVICES_AUTOPILOT_SCRIPT: &str =
    include_str!("../../../scripts/public-services-autopilot.sh");
const PUBLIC_SERVICES_CONTROL_PLANE_UNIT: &str =
    include_str!("../../../deploy/systemd/heteronetwork-control-plane.service");
const PUBLIC_SERVICES_SIGNAL_UNIT: &str =
    include_str!("../../../deploy/systemd/heteronetwork-signal.service");
const PUBLIC_SERVICES_STUN_UNIT: &str =
    include_str!("../../../deploy/systemd/heteronetwork-stun.service");
const PUBLIC_SERVICES_AUTOPILOT_UNIT: &str =
    include_str!("../../../deploy/systemd/heteronetwork-public-services-autopilot.service");
const PUBLIC_SERVICES_AUTOPILOT_TIMER: &str =
    include_str!("../../../deploy/systemd/heteronetwork-public-services-autopilot.timer");
const MAX_HEARTBEAT_CONNECTION_INTENT_WAIT_SECONDS: u64 = 20;
const MAX_DYNAMIC_WEB_GATEWAY_CONFIG_BYTES: u64 = 256 * 1024;
const NODE_ENROLLMENT_CADDY_VERSION: &str = "2.11.4";
const NODE_ENROLLMENT_CADDY_SHA256: &str =
    "527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9";
const KEYCLOAK_AUTOPILOT_ARCHIVE_URL: &str =
    "https://github.com/keycloak/keycloak/releases/download/26.6.4/keycloak-26.6.4.tar.gz";
const KEYCLOAK_AUTOPILOT_ARCHIVE_SHA256: &str =
    "386b566bbea05527226e275c43e5cf6f218896ad2441ac4be5c39f1226772e8f";
const KEYCLOAK_AUTOPILOT_EDGE_PORT: u16 = 18_079;
const MANAGED_KEYCLOAK_OVERLAY_ORIGIN: &str = "http://console.heteronetwork.internal:18079";
const NODE_ENROLLMENT_RELAY_UDP_PORT: u16 = 18_445;
const NODE_ENROLLMENT_RELAY_HTTP_PORT: u16 = 18_447;
const NODE_ENROLLMENT_RELAY_CLASSIFICATION_MAX_AGE_SECONDS: u64 = 45;
const NODE_ENROLLMENT_RELAY_RECONCILE_INTERVAL_SECONDS: u64 = 15;
const NODE_ENROLLMENT_PUBLIC_SERVICES_CLASSIFICATION_MAX_AGE_SECONDS: u64 = 45;
const NODE_ENROLLMENT_PUBLIC_SERVICES_RECONCILE_INTERVAL_SECONDS: u64 = 15;

#[derive(Clone, Debug)]
pub struct NodePublicServicesConfig {
    pub vpn_pool: String,
    pub issuer_node_id: String,
    pub issuer_key_id: String,
    pub issuer_public_key: String,
    pub trusted_issuer_keys: Vec<String>,
    pub trusted_node_enrollment_issuer_keys: Vec<String>,
    pub oidc_issuer_url: String,
    pub oidc_client_id: String,
    pub oidc_auth_base_url: Option<String>,
    pub oidc_backchannel_base_url: Option<String>,
    pub oidc_backchannel_fallback_base_urls: Vec<String>,
    pub oidc_scopes: String,
}

macro_rules! prometheus_line {
    ($body:expr, $($arg:tt)*) => {{
        let _ = writeln!($body, $($arg)*);
    }};
}

#[derive(Clone)]
struct PinnedEnrollmentBinary {
    label: Arc<str>,
    path: Arc<PathBuf>,
    file: Arc<std::fs::File>,
    sha256: Arc<str>,
    size: u64,
}

impl PinnedEnrollmentBinary {
    fn new(path: PathBuf, label: &str) -> Result<Self, String> {
        let path_metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
        if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
            return Err(format!(
                "{label} {} must be a regular non-symlink file",
                path.display()
            ));
        }
        let mut file = std::fs::File::open(&path)
            .map_err(|error| format!("failed to open {label} {}: {error}", path.display()))?;
        let metadata = file.metadata().map_err(|error| {
            format!(
                "failed to inspect opened {label} {}: {error}",
                path.display()
            )
        })?;
        if !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_NODE_ENROLLMENT_BINARY_BYTES
        {
            return Err(format!(
                "{label} {} must be a non-empty regular file no larger than {MAX_NODE_ENROLLMENT_BINARY_BYTES} bytes",
                path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if path_metadata.dev() != metadata.dev() || path_metadata.ino() != metadata.ino() {
                return Err(format!(
                    "{label} {} changed while it was opened",
                    path.display()
                ));
            }
        }

        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| format!("failed to hash {label} {}: {error}", path.display()))?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|error| format!("failed to rewind {label} {}: {error}", path.display()))?;

        Ok(Self {
            label: Arc::from(label),
            path: Arc::new(path),
            file: Arc::new(file),
            sha256: Arc::from(format!("{:x}", digest.finalize())),
            size: metadata.len(),
        })
    }

    fn open(&self) -> Result<std::fs::File, String> {
        let path_metadata = std::fs::symlink_metadata(self.path.as_ref()).map_err(|error| {
            format!(
                "failed to inspect {} {}: {error}",
                self.label,
                self.path.display()
            )
        })?;
        if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
            return Err(format!(
                "{} {} is no longer a regular non-symlink file",
                self.label,
                self.path.display()
            ));
        }
        let file = std::fs::File::open(self.path.as_ref()).map_err(|error| {
            format!(
                "failed to open {} {}: {error}",
                self.label,
                self.path.display()
            )
        })?;
        let original = self.file.metadata().map_err(|error| {
            format!(
                "failed to inspect pinned {} {}: {error}",
                self.label,
                self.path.display()
            )
        })?;
        let opened = file.metadata().map_err(|error| {
            format!(
                "failed to inspect opened {} {}: {error}",
                self.label,
                self.path.display()
            )
        })?;
        if !opened.is_file() || opened.len() != self.size {
            return Err(format!(
                "{} {} changed after startup",
                self.label,
                self.path.display()
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
                    "{} {} changed after startup",
                    self.label,
                    self.path.display()
                ));
            }
        }
        Ok(file)
    }
}

#[derive(Clone)]
pub struct NodeEnrollmentConfig {
    issuer: IdentityKeyPair,
    key_id: KeyId,
    install_base_url: Arc<str>,
    daemon_binary: PinnedEnrollmentBinary,
    cli_binary: PinnedEnrollmentBinary,
    max_ttl_seconds: u64,
    relay_admission_bearer_token: Arc<str>,
    public_services: Option<Arc<NodePublicServicesConfig>>,
}

impl NodeEnrollmentConfig {
    pub fn new(
        issuer: IdentityKeyPair,
        key_id: String,
        install_base_url: String,
        binary_path: PathBuf,
        cli_binary_path: PathBuf,
        max_ttl_seconds: u64,
        relay_admission_bearer_token: String,
    ) -> Result<Self, String> {
        validate_enrollment_identifier(&key_id, "node enrollment issuer key ID")?;
        validate_relay_admission_bearer_token(
            &relay_admission_bearer_token,
            "node enrollment relay admission bearer token",
        )?;
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

        let daemon_binary =
            PinnedEnrollmentBinary::new(binary_path, "node enrollment daemon binary")?;
        let cli_binary =
            PinnedEnrollmentBinary::new(cli_binary_path, "node enrollment CLI binary")?;

        Ok(Self {
            issuer,
            key_id: KeyId::from_string(key_id),
            install_base_url: Arc::from(install_base_url),
            daemon_binary,
            cli_binary,
            max_ttl_seconds,
            relay_admission_bearer_token: Arc::from(relay_admission_bearer_token),
            public_services: None,
        })
    }

    pub fn with_public_services(mut self, config: NodePublicServicesConfig) -> Self {
        self.public_services = Some(Arc::new(config));
        self
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

fn validate_relay_admission_bearer_token(value: &str, label: &str) -> Result<(), String> {
    if value.len() < MIN_RELAY_ADMISSION_BEARER_TOKEN_BYTES {
        return Err(format!(
            "{label} must contain at least {MIN_RELAY_ADMISSION_BEARER_TOKEN_BYTES} bytes"
        ));
    }
    if value.len() > MAX_RELAY_ADMISSION_BEARER_TOKEN_BYTES {
        return Err(format!(
            "{label} exceeds {MAX_RELAY_ADMISSION_BEARER_TOKEN_BYTES} bytes"
        ));
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(format!(
            "{label} must not contain whitespace or control characters"
        ));
    }
    Ok(())
}

fn validate_autopilot_api_bearer_token(value: &str, label: &str) -> Result<(), String> {
    if value.len() != AUTOPILOT_API_BEARER_TOKEN_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must contain exactly {AUTOPILOT_API_BEARER_TOKEN_HEX_BYTES} lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

pub struct ControlPlaneHttpState<S, L> {
    plane: Arc<ControlPlane<S>>,
    join_service: Arc<ControlPlaneJoinService<S, L>>,
    operator_api_bearer_token: Option<Arc<str>>,
    database_autopilot_bearer_token: Option<Arc<str>>,
    keycloak_autopilot_bearer_token: Option<Arc<str>>,
    web_ui_auth: Option<Arc<WebUiAuthConfig>>,
    node_enrollment: Option<Arc<NodeEnrollmentConfig>>,
    dynamic_web_gateway: Option<Arc<DynamicWebGatewayConfig>>,
    database_autopilot_registry_cache: Arc<Mutex<Option<Arc<DatabaseAutopilotRegistrySnapshot>>>>,
}

#[derive(Clone)]
pub struct DynamicWebGatewayConfig {
    client: Client,
    probe_timeout: Duration,
    lease_ttl: ChronoDuration,
    classification_max_age: ChronoDuration,
    trusted_oidc_issuer: Option<String>,
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
            trusted_oidc_issuer: None,
        })
    }

    pub fn with_trusted_oidc_issuer(mut self, issuer: String) -> Result<Self, String> {
        self.trusted_oidc_issuer = Some(validate_web_auth_base_url(
            issuer,
            "trusted OIDC issuer URL",
        )?);
        Ok(self)
    }
}

impl<S, L> Clone for ControlPlaneHttpState<S, L> {
    fn clone(&self) -> Self {
        Self {
            plane: self.plane.clone(),
            join_service: self.join_service.clone(),
            operator_api_bearer_token: self.operator_api_bearer_token.clone(),
            database_autopilot_bearer_token: self.database_autopilot_bearer_token.clone(),
            keycloak_autopilot_bearer_token: self.keycloak_autopilot_bearer_token.clone(),
            web_ui_auth: self.web_ui_auth.clone(),
            node_enrollment: self.node_enrollment.clone(),
            dynamic_web_gateway: self.dynamic_web_gateway.clone(),
            database_autopilot_registry_cache: self.database_autopilot_registry_cache.clone(),
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
            database_autopilot_bearer_token: None,
            keycloak_autopilot_bearer_token: None,
            web_ui_auth: None,
            node_enrollment: None,
            dynamic_web_gateway: None,
            database_autopilot_registry_cache: Arc::new(Mutex::new(None)),
        }
    }

    pub fn require_operator_api_bearer_token(mut self, token: String) -> Self {
        self.operator_api_bearer_token = Some(Arc::from(token));
        self
    }

    pub fn require_database_autopilot_bearer_token(
        mut self,
        token: String,
    ) -> Result<Self, String> {
        validate_autopilot_api_bearer_token(&token, "database autopilot API bearer token")?;
        self.database_autopilot_bearer_token = Some(Arc::from(token));
        Ok(self)
    }

    pub fn require_keycloak_autopilot_bearer_token(
        mut self,
        token: String,
    ) -> Result<Self, String> {
        validate_autopilot_api_bearer_token(&token, "Keycloak autopilot API bearer token")?;
        self.keycloak_autopilot_bearer_token = Some(Arc::from(token));
        Ok(self)
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

    fn resolved_database_autopilot_bearer_token(&self) -> Option<Arc<str>>
    where
        S: ControlPlaneStore,
    {
        self.database_autopilot_bearer_token.clone().or_else(|| {
            self.node_enrollment.as_deref().map(|enrollment| {
                Arc::from(derive_node_enrollment_cluster_secret(
                    enrollment,
                    &self.plane.config().cluster_id,
                    b"heteronetwork-postgres-ha-autopilot-v1",
                ))
            })
        })
    }

    fn resolved_keycloak_autopilot_bearer_token(&self) -> Option<Arc<str>>
    where
        S: ControlPlaneStore,
    {
        self.keycloak_autopilot_bearer_token.clone().or_else(|| {
            self.node_enrollment.as_deref().map(|enrollment| {
                Arc::from(derive_node_enrollment_cluster_secret(
                    enrollment,
                    &self.plane.config().cluster_id,
                    b"heteronetwork-keycloak-autopilot-v1",
                ))
            })
        })
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
        .route(
            "/v1/clients/sponsored-enrollment",
            post(sponsored_client_enrollment::<S, L>).layer(DefaultBodyLimit::max(
                MAX_SPONSORED_CLIENT_REGISTRATION_REQUEST_BYTES,
            )),
        )
        .route("/v1/clients/peers/query", post(client_peers::<S, L>))
        .route("/v1/clients/{client_id}", delete(remove_client::<S, L>))
        .route("/v1/heartbeat", post(heartbeat::<S, L>))
        .route("/v1/peers/query", post(peers::<S, L>))
        .route("/v1/neighbors/query", post(neighbors::<S, L>))
        .route("/v1/paths/query", post(paths::<S, L>))
        .route("/v1/overlay-paths/query", post(overlay_paths::<S, L>))
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
        )
        .route(
            "/v1/install/ipars-linux-amd64",
            get(node_enrollment_cli_binary::<S, L>),
        );
    let database_autopilot_bearer_token = state.resolved_database_autopilot_bearer_token();
    let protocol = if let Some(bearer_token) = database_autopilot_bearer_token {
        let database_autopilot = Router::new()
            .route(
                "/v1/database-autopilot/nodes",
                post(database_autopilot_nodes::<S, L>)
                    .layer(DefaultBodyLimit::max(MAX_DATABASE_AUTOPILOT_REQUEST_BYTES)),
            )
            .route_layer(middleware::from_fn_with_state(
                bearer_token,
                require_database_autopilot_bearer,
            ));
        protocol.merge(database_autopilot)
    } else {
        protocol
    };
    let keycloak_autopilot_bearer_token = state.resolved_keycloak_autopilot_bearer_token();
    let protocol = if let Some(base_secret) = keycloak_autopilot_bearer_token {
        let auth = Arc::new(KeycloakAutopilotAuth {
            base_secret,
            cluster_id: state.plane.config().cluster_id.clone(),
        });
        let keycloak_autopilot = Router::new()
            .route(
                "/v1/keycloak-autopilot/reconcile",
                post(keycloak_autopilot_reconcile::<S, L>)
                    .layer(DefaultBodyLimit::max(MAX_KEYCLOAK_AUTOPILOT_REQUEST_BYTES)),
            )
            .route_layer(middleware::from_fn_with_state(
                auth,
                require_keycloak_autopilot_bearer,
            ));
        protocol.merge(keycloak_autopilot)
    } else {
        protocol
    };

    let management_auth = Arc::new(ManagementAuth {
        operator_api_bearer_token: state.operator_api_bearer_token.clone(),
        web_ui_auth: state.web_ui_auth.clone(),
    });
    let admin = Router::new()
        .route("/v1/admin/overview", get(admin_overview::<S, L>))
        .route("/v1/admin/topology", get(admin_topology::<S, L>))
        .route("/v1/admin/services", get(admin_services::<S, L>))
        .route(
            "/v1/admin/keycloak-placement",
            get(admin_keycloak_placement::<S, L>),
        )
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
        .route("/ui/auth/refresh", post(ui_session_refresh::<S, L>))
        .route("/ui/auth/logout", post(ui_session_logout::<S, L>))
        .route("/ui/app.js", get(ui_app))
        .route("/ui/theme.js", get(ui_theme))
        .route("/ui/styles.css", get(ui_styles))
        .route("/ui/vendor/mermaid.min.js", get(ui_mermaid))
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
    refresh_cache: Arc<Mutex<WebOidcRefreshCache>>,
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

#[derive(Debug, Clone)]
struct WebAuthFlowError {
    status: StatusCode,
    message: String,
}

#[derive(Debug, Clone)]
struct WebSessionRefreshError {
    error: WebAuthFlowError,
    clear_cookie: bool,
}

type WebOidcRefreshResult = Result<OidcTokenResponse, WebSessionRefreshError>;

#[derive(Debug, Default)]
struct WebOidcRefreshCache {
    entries: HashMap<[u8; 32], WebOidcRefreshCacheEntry>,
    revocations: HashMap<[u8; 32], Instant>,
}

#[derive(Debug)]
enum WebOidcRefreshCacheEntry {
    InFlight {
        operation: Arc<OnceCell<WebOidcRefreshResult>>,
    },
    Ready {
        tokens: Arc<OidcTokenResponse>,
        expires_at: Instant,
    },
    Rejected {
        expires_at: Instant,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessTokenValidation {
    Valid,
    Invalid,
    Unavailable,
}

impl WebAuthFlowError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl WebSessionRefreshError {
    fn preserve(error: WebAuthFlowError) -> Self {
        Self {
            error,
            clear_cookie: false,
        }
    }

    fn reject(message: impl Into<String>) -> Self {
        Self {
            error: WebAuthFlowError::new(StatusCode::UNAUTHORIZED, message),
            clear_cookie: true,
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
            refresh_cache: Arc::new(Mutex::new(WebOidcRefreshCache::default())),
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
        self.access_token_validation(token).await == AccessTokenValidation::Valid
    }

    async fn access_token_validation(&self, token: &str) -> AccessTokenValidation {
        if token.is_empty() || token.len() > MAX_OPERATOR_API_BEARER_TOKEN_BYTES * 16 {
            return AccessTokenValidation::Invalid;
        }
        let Some(backchannel_host) = self.access_token_backchannel_host(token) else {
            return AccessTokenValidation::Invalid;
        };
        let mut rejected = false;
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
                if matches!(
                    response.status(),
                    StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                ) {
                    rejected = true;
                }
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
                return AccessTokenValidation::Valid;
            }
        }
        if rejected {
            AccessTokenValidation::Invalid
        } else {
            AccessTokenValidation::Unavailable
        }
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
        let secure = web_oidc_url_is_secure(public_url);
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
    ) -> Result<OidcTokenResponse, WebAuthFlowError> {
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
        let tokens = parse_oidc_token_response(&body, "OIDC token")?;
        match self.access_token_validation(&tokens.access_token).await {
            AccessTokenValidation::Valid => {}
            AccessTokenValidation::Invalid => {
                return Err(WebAuthFlowError::new(
                    StatusCode::UNAUTHORIZED,
                    "OIDC access token failed provider validation",
                ));
            }
            AccessTokenValidation::Unavailable => {
                return Err(WebAuthFlowError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "identity provider is temporarily unavailable",
                ));
            }
        }
        Ok(tokens)
    }

    async fn refresh_session(
        &self,
        refresh_token: &str,
    ) -> Result<OidcTokenResponse, WebSessionRefreshError> {
        if !valid_web_oidc_refresh_token(refresh_token) {
            return Err(WebSessionRefreshError::reject(
                "Web UI refresh session is missing or invalid",
            ));
        }

        let digest: [u8; 32] = Sha256::digest(refresh_token.as_bytes()).into();
        let operation = {
            let mut cache = self.refresh_cache.lock().await;
            let now = Instant::now();
            cache.revocations.retain(|_, expires_at| *expires_at > now);
            if cache.revocations.contains_key(&digest) {
                return Err(WebSessionRefreshError::reject(
                    "Web UI refresh session expired or was rejected",
                ));
            }
            cache.entries.retain(|_, entry| match entry {
                WebOidcRefreshCacheEntry::InFlight { .. } => true,
                WebOidcRefreshCacheEntry::Ready { expires_at, .. }
                | WebOidcRefreshCacheEntry::Rejected { expires_at } => *expires_at > now,
            });
            match cache.entries.get(&digest) {
                Some(WebOidcRefreshCacheEntry::Ready { tokens, .. }) => {
                    return Ok(tokens.as_ref().clone());
                }
                Some(WebOidcRefreshCacheEntry::Rejected { .. }) => {
                    return Err(WebSessionRefreshError::reject(
                        "Web UI refresh session expired or was rejected",
                    ));
                }
                Some(WebOidcRefreshCacheEntry::InFlight { operation, .. }) => operation.clone(),
                None => {
                    if cache.entries.len() >= MAX_WEB_OIDC_REFRESH_CACHE_ENTRIES {
                        let oldest_ready = cache
                            .entries
                            .iter()
                            .filter_map(|(digest, entry)| match entry {
                                WebOidcRefreshCacheEntry::Ready { expires_at, .. } => {
                                    Some((*digest, *expires_at))
                                }
                                WebOidcRefreshCacheEntry::Rejected { expires_at } => {
                                    Some((*digest, *expires_at))
                                }
                                WebOidcRefreshCacheEntry::InFlight { .. } => None,
                            })
                            .min_by_key(|(_, expires_at)| *expires_at)
                            .map(|(digest, _)| digest);
                        if let Some(oldest_ready) = oldest_ready {
                            cache.entries.remove(&oldest_ready);
                        }
                    }
                    if cache.entries.len() >= MAX_WEB_OIDC_REFRESH_CACHE_ENTRIES {
                        return Err(WebSessionRefreshError::preserve(WebAuthFlowError::new(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "too many concurrent Web UI refresh requests",
                        )));
                    }
                    let operation = Arc::new(OnceCell::new());
                    cache.entries.insert(
                        digest,
                        WebOidcRefreshCacheEntry::InFlight {
                            operation: operation.clone(),
                        },
                    );
                    operation
                }
            }
        };

        let result = operation
            .get_or_init(|| self.refresh_session_uncached(refresh_token))
            .await
            .clone();
        let mut cache = self.refresh_cache.lock().await;
        let now = Instant::now();
        cache.revocations.retain(|_, expires_at| *expires_at > now);
        if cache.revocations.contains_key(&digest) {
            return Err(WebSessionRefreshError::reject(
                "Web UI refresh session expired or was rejected",
            ));
        }
        if matches!(
            cache.entries.get(&digest),
            Some(WebOidcRefreshCacheEntry::Rejected { .. })
        ) {
            return Err(WebSessionRefreshError::reject(
                "Web UI refresh session expired or was rejected",
            ));
        }
        let is_current = cache.entries.get(&digest).is_some_and(|entry| {
            matches!(
                entry,
                WebOidcRefreshCacheEntry::InFlight {
                    operation: current,
                    ..
                } if Arc::ptr_eq(current, &operation)
            )
        });
        if is_current {
            match &result {
                Ok(tokens) => {
                    cache.entries.insert(
                        digest,
                        WebOidcRefreshCacheEntry::Ready {
                            tokens: Arc::new(tokens.clone()),
                            expires_at: now + WEB_OIDC_REFRESH_REPLAY_TTL,
                        },
                    );
                }
                Err(_) => {
                    cache.entries.remove(&digest);
                }
            }
        }
        result
    }

    async fn invalidate_refresh_session(&self, refresh_token: &str) {
        if !valid_web_oidc_refresh_token(refresh_token) {
            return;
        }
        let digest: [u8; 32] = Sha256::digest(refresh_token.as_bytes()).into();
        let mut cache = self.refresh_cache.lock().await;
        let now = Instant::now();
        cache.revocations.retain(|_, expires_at| *expires_at > now);
        cache.entries.retain(|_, entry| match entry {
            WebOidcRefreshCacheEntry::InFlight { .. } => true,
            WebOidcRefreshCacheEntry::Ready { expires_at, .. }
            | WebOidcRefreshCacheEntry::Rejected { expires_at } => *expires_at > now,
        });
        let mut revoked_digests = vec![digest];
        for (candidate_digest, entry) in &cache.entries {
            let issued_logout_token = match entry {
                WebOidcRefreshCacheEntry::Ready { tokens, .. } => tokens
                    .refresh_token
                    .as_deref()
                    .is_some_and(|token| token == refresh_token),
                _ => false,
            };
            if issued_logout_token && !revoked_digests.contains(candidate_digest) {
                revoked_digests.push(*candidate_digest);
            }
        }
        for revoked_digest in &revoked_digests {
            if cache.entries.contains_key(revoked_digest) {
                cache.entries.insert(
                    *revoked_digest,
                    WebOidcRefreshCacheEntry::Rejected {
                        expires_at: now + WEB_OIDC_REFRESH_REVOCATION_TTL,
                    },
                );
            }
        }
        for revoked_digest in revoked_digests {
            record_web_oidc_refresh_revocation(&mut cache, revoked_digest, now);
        }
    }

    async fn refresh_session_uncached(&self, refresh_token: &str) -> WebOidcRefreshResult {
        let mut failures = Vec::new();
        for endpoint in &self.backchannel_token_endpoints {
            let response = match self
                .client
                .post(endpoint)
                .header(header::HOST, self.backchannel_host.clone())
                .header(header::ACCEPT, "application/json")
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("client_id", self.client_id.as_str()),
                    ("refresh_token", refresh_token),
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
            let status = response.status();
            if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                failures.push(format!("{endpoint}: HTTP {status}"));
                continue;
            }
            let body = bounded_response_body(response, MAX_WEB_OIDC_TOKEN_RESPONSE_BYTES)
                .await
                .map_err(WebSessionRefreshError::preserve)?;
            if status.is_success() {
                return parse_oidc_token_response(&body, "OIDC refresh token")
                    .map_err(WebSessionRefreshError::preserve);
            }

            let error = serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|body| {
                    body.get("error")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .unwrap_or_default();
            if matches!(
                error.as_str(),
                "invalid_grant" | "invalid_token" | "expired_token"
            ) {
                return Err(WebSessionRefreshError::reject(
                    "Web UI refresh session expired or was rejected",
                ));
            }
            return Err(WebSessionRefreshError::preserve(WebAuthFlowError::new(
                StatusCode::BAD_GATEWAY,
                format!("OIDC refresh request returned HTTP {status}"),
            )));
        }

        Err(WebSessionRefreshError::preserve(WebAuthFlowError::new(
            StatusCode::BAD_GATEWAY,
            format!(
                "OIDC refresh request failed on every backchannel: {}",
                failures.join("; ")
            ),
        )))
    }

    fn public_config(&self, cluster_id: String) -> WebUiPublicConfig {
        let server_side_session = self.public_url.is_some();
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
            session_refresh_endpoint: server_side_session.then(|| "/ui/auth/refresh".to_string()),
            session_logout_endpoint: server_side_session.then(|| "/ui/auth/logout".to_string()),
            node_enrollment_enabled: false,
            client_enrollment_enabled: false,
        }
    }
}

fn record_web_oidc_refresh_revocation(
    cache: &mut WebOidcRefreshCache,
    digest: [u8; 32],
    now: Instant,
) {
    if !cache.revocations.contains_key(&digest)
        && cache.revocations.len() >= MAX_WEB_OIDC_REFRESH_REVOCATIONS
    {
        if let Some(oldest) = cache
            .revocations
            .iter()
            .min_by_key(|(_, expires_at)| **expires_at)
            .map(|(digest, _)| *digest)
        {
            cache.revocations.remove(&oldest);
        }
    }
    cache
        .revocations
        .insert(digest, now + WEB_OIDC_REFRESH_REVOCATION_TTL);
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
                || host.eq_ignore_ascii_case("console.heteronetwork.internal")
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

#[derive(Debug, Clone, Deserialize)]
struct OidcTokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: u64,
    #[serde(default)]
    refresh_expires_in: Option<u64>,
}

fn parse_oidc_token_response(
    body: &[u8],
    context: &str,
) -> Result<OidcTokenResponse, WebAuthFlowError> {
    let tokens: OidcTokenResponse = serde_json::from_slice(body).map_err(|error| {
        WebAuthFlowError::new(
            StatusCode::BAD_GATEWAY,
            format!("{context} response is invalid: {error}"),
        )
    })?;
    if tokens.access_token.is_empty()
        || tokens.access_token.len() > MAX_WEB_OIDC_ACCESS_TOKEN_BYTES
        || tokens.access_token.contains(char::is_whitespace)
        || tokens.access_token.chars().any(char::is_control)
        || tokens.expires_in == 0
        || tokens.expires_in > MAX_WEB_OIDC_SESSION_SECONDS
    {
        return Err(WebAuthFlowError::new(
            StatusCode::BAD_GATEWAY,
            format!("{context} response contained invalid access token parameters"),
        ));
    }
    if tokens
        .refresh_token
        .as_deref()
        .is_some_and(|token| !valid_web_oidc_refresh_token(token))
    {
        return Err(WebAuthFlowError::new(
            StatusCode::BAD_GATEWAY,
            format!("{context} response contained an invalid refresh token"),
        ));
    }
    Ok(tokens)
}

fn valid_web_oidc_refresh_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_WEB_OIDC_REFRESH_TOKEN_BYTES
        && !token.contains(char::is_whitespace)
        && !token.chars().any(char::is_control)
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
    session_refresh_endpoint: Option<String>,
    session_logout_endpoint: Option<String>,
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
    let oidc_validation = if operator_authenticated {
        None
    } else if let (Some(oidc), Some(token)) = (auth.web_ui_auth.as_deref(), provided) {
        Some(oidc.access_token_validation(token).await)
    } else {
        None
    };
    if operator_authenticated || oidc_validation == Some(AccessTokenValidation::Valid) {
        return next.run(request).await;
    }
    if oidc_validation == Some(AccessTokenValidation::Unavailable) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "5")],
            Json(ErrorResponse {
                error: "identity provider is temporarily unavailable".to_string(),
            }),
        )
            .into_response();
    }
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(ErrorResponse {
            error: "management API authentication was rejected".to_string(),
        }),
    )
        .into_response()
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

async fn ui_mermaid() -> impl IntoResponse {
    let mut response = (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../../webui/vendor/mermaid.min.js"),
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
    let secure = web_oidc_secure_cookie(auth);
    let mut response = match auth.complete_login(query, state_cookie.as_deref()).await {
        Ok(tokens) => {
            let refresh_cookie = match tokens.refresh_token.as_deref() {
                Some(refresh_token) => {
                    web_oidc_refresh_cookie(refresh_token, tokens.refresh_expires_in, secure)
                }
                None => Ok(clear_web_oidc_refresh_cookie(secure)),
            };
            match refresh_cookie {
                Ok(refresh_cookie) => {
                    let html = oidc_callback_html(&tokens.access_token, tokens.expires_in);
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
                    headers.append(header::SET_COOKIE, refresh_cookie);
                    response
                }
                Err(error) => {
                    let mut response = web_auth_flow_error_response(error);
                    response
                        .headers_mut()
                        .append(header::SET_COOKIE, clear_web_oidc_refresh_cookie(secure));
                    response
                }
            }
        }
        Err(error) => web_auth_flow_error_response(error),
    };
    if clear_state_cookie {
        let secure_attribute = if secure { "; Secure" } else { "" };
        if let Ok(cookie) = header::HeaderValue::from_str(&format!(
            "{WEB_OIDC_STATE_COOKIE}=; Path=/ui/callback; Max-Age=0; HttpOnly; SameSite=Lax{secure_attribute}"
        )) {
            response.headers_mut().append(header::SET_COOKIE, cookie);
        }
    }
    response
}

async fn ui_session_refresh<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    headers: HeaderMap,
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
    if let Err(error) = validate_web_oidc_session_request(auth, &headers) {
        return web_auth_flow_error_response(error);
    }
    let secure = web_oidc_secure_cookie(auth);
    let Some(refresh_token) = web_oidc_refresh_token(&headers) else {
        let mut response = web_auth_flow_error_response(WebAuthFlowError::new(
            StatusCode::UNAUTHORIZED,
            "Web UI refresh session is missing or invalid",
        ));
        response
            .headers_mut()
            .append(header::SET_COOKIE, clear_web_oidc_refresh_cookie(secure));
        return response;
    };

    match auth.refresh_session(&refresh_token).await {
        Ok(tokens) => {
            let cookie_token = tokens.refresh_token.as_deref().unwrap_or(&refresh_token);
            let cookie =
                match web_oidc_refresh_cookie(cookie_token, tokens.refresh_expires_in, secure) {
                    Ok(cookie) => cookie,
                    Err(error) => return web_auth_flow_error_response(error),
                };
            let mut response = Json(serde_json::json!({
                "access_token": tokens.access_token,
                "expires_in": tokens.expires_in
            }))
            .into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );
            response.headers_mut().append(header::SET_COOKIE, cookie);
            response
        }
        Err(error) => {
            let clear_cookie = error.clear_cookie;
            let mut response = web_auth_flow_error_response(error.error);
            if clear_cookie {
                response
                    .headers_mut()
                    .append(header::SET_COOKIE, clear_web_oidc_refresh_cookie(secure));
            }
            response
        }
    }
}

async fn ui_session_logout<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    headers: HeaderMap,
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
    if let Err(error) = validate_web_oidc_session_request(auth, &headers) {
        return web_auth_flow_error_response(error);
    }
    if let Some(refresh_token) = web_oidc_refresh_token(&headers) {
        auth.invalidate_refresh_session(&refresh_token).await;
    }
    let mut response = Json(serde_json::json!({"status": "logged_out"})).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        clear_web_oidc_refresh_cookie(web_oidc_secure_cookie(auth)),
    );
    response
}

fn oidc_callback_html(access_token: &str, expires_in: u64) -> String {
    let token_json = serde_json::to_string(access_token)
        .unwrap_or_else(|_| "\"\"".to_string())
        .replace('<', "\\u003c");
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>HeteroNetwork Login</title><script>sessionStorage.setItem(\"{WEB_OIDC_ACCESS_TOKEN_STORAGE_KEY}\",{token_json});sessionStorage.setItem(\"{WEB_OIDC_ACCESS_TOKEN_EXPIRES_AT_STORAGE_KEY}\",String(Date.now()+{expires_in}*1000));location.replace(\"/ui/\");</script>"
    )
}

fn web_oidc_url_is_secure(url: &str) -> bool {
    Url::parse(url).is_ok_and(|url| url.scheme().eq_ignore_ascii_case("https"))
}

fn web_oidc_secure_cookie(auth: &WebUiAuthConfig) -> bool {
    auth.public_url
        .as_deref()
        .is_some_and(web_oidc_url_is_secure)
}

fn web_oidc_refresh_cookie(
    refresh_token: &str,
    refresh_expires_in: Option<u64>,
    secure: bool,
) -> Result<header::HeaderValue, WebAuthFlowError> {
    if !valid_web_oidc_refresh_token(refresh_token) {
        return Err(WebAuthFlowError::new(
            StatusCode::BAD_GATEWAY,
            "OIDC token response contained an invalid refresh token",
        ));
    }
    let encoded = URL_SAFE_NO_PAD.encode(refresh_token.as_bytes());
    let seconds = match refresh_expires_in {
        Some(0) | None => DEFAULT_WEB_OIDC_REFRESH_COOKIE_SECONDS,
        Some(seconds) => seconds.min(MAX_WEB_OIDC_SESSION_SECONDS),
    };
    let max_age_attribute = format!("; Max-Age={seconds}");
    let secure_attribute = if secure { "; Secure" } else { "" };
    let cookie = format!(
        "{WEB_OIDC_REFRESH_COOKIE}={encoded}; Path={WEB_OIDC_REFRESH_COOKIE_PATH}{max_age_attribute}; HttpOnly; SameSite=Strict{secure_attribute}"
    );
    if cookie.len() > MAX_WEB_OIDC_REFRESH_COOKIE_BYTES {
        return Err(WebAuthFlowError::new(
            StatusCode::BAD_GATEWAY,
            "OIDC refresh token exceeds the safe Web UI cookie limit",
        ));
    }
    header::HeaderValue::from_str(&cookie).map_err(|_| {
        WebAuthFlowError::new(
            StatusCode::BAD_GATEWAY,
            "failed to build the Web UI refresh cookie",
        )
    })
}

fn clear_web_oidc_refresh_cookie(secure: bool) -> header::HeaderValue {
    if secure {
        header::HeaderValue::from_static(
            "heteronetwork_web_refresh=; Path=/ui/auth; Max-Age=0; HttpOnly; SameSite=Strict; Secure",
        )
    } else {
        header::HeaderValue::from_static(
            "heteronetwork_web_refresh=; Path=/ui/auth; Max-Age=0; HttpOnly; SameSite=Strict",
        )
    }
}

fn web_oidc_refresh_token(headers: &HeaderMap) -> Option<String> {
    let mut encoded = None;
    for header_value in headers.get_all(header::COOKIE) {
        let header_value = header_value.to_str().ok()?;
        for pair in header_value.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name != WEB_OIDC_REFRESH_COOKIE {
                continue;
            }
            if encoded.replace(value).is_some() {
                return None;
            }
        }
    }
    let encoded = encoded?;
    if encoded.is_empty()
        || encoded.len() > (MAX_WEB_OIDC_REFRESH_TOKEN_BYTES * 4 / 3 + 4)
        || encoded.len() > MAX_WEB_OIDC_REFRESH_COOKIE_BYTES
    {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let refresh_token = String::from_utf8(decoded).ok()?;
    valid_web_oidc_refresh_token(&refresh_token).then_some(refresh_token)
}

fn validate_web_oidc_session_request(
    auth: &WebUiAuthConfig,
    headers: &HeaderMap,
) -> Result<(), WebAuthFlowError> {
    let public_url = auth.public_url.as_deref().ok_or_else(|| {
        WebAuthFlowError::new(
            StatusCode::NOT_FOUND,
            "server-side OIDC login is not configured",
        )
    })?;
    let expected = Url::parse(public_url).map_err(|_| {
        WebAuthFlowError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "web public URL is invalid",
        )
    })?;

    let mut origins = headers.get_all(header::ORIGIN).iter();
    let origin = origins
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            WebAuthFlowError::new(
                StatusCode::FORBIDDEN,
                "same-origin Web UI request is required",
            )
        })?;
    if origins.next().is_some() {
        return Err(WebAuthFlowError::new(
            StatusCode::FORBIDDEN,
            "same-origin Web UI request is required",
        ));
    }
    let origin = Url::parse(origin).map_err(|_| {
        WebAuthFlowError::new(
            StatusCode::FORBIDDEN,
            "same-origin Web UI request is required",
        )
    })?;
    if origin.origin() != expected.origin()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.username() != ""
        || origin.password().is_some()
    {
        return Err(WebAuthFlowError::new(
            StatusCode::FORBIDDEN,
            "same-origin Web UI request is required",
        ));
    }

    let fetch_site = header::HeaderName::from_static("sec-fetch-site");
    let mut fetch_sites = headers.get_all(fetch_site).iter();
    let same_origin = fetch_sites
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("same-origin"));
    if !same_origin || fetch_sites.next().is_some() {
        return Err(WebAuthFlowError::new(
            StatusCode::FORBIDDEN,
            "same-origin Web UI request is required",
        ));
    }
    Ok(())
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
            session_refresh_endpoint: None,
            session_logout_endpoint: None,
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
    cli_binary_sha256: String,
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
        if value == Tag::kubernetes_control_plane().as_str() {
            return Err(NodeEnrollmentApiError::bad_request(
                "the kubernetes-control-plane tag is reserved for Kubernetes HA control-plane enrollment",
            ));
        }
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
    require_ha_node_enrollment_directory(&directory, true)?;

    let now = Utc::now();
    let expires_at = now
        .checked_add_signed(ChronoDuration::seconds(request.expires_in_seconds as i64))
        .ok_or_else(|| NodeEnrollmentApiError::bad_request("token expiration is out of range"))?;
    let bootstrap_endpoints = node_enrollment_bootstrap_endpoints(
        enrollment.install_base_url.as_ref(),
        &directory.bootstrap_endpoints,
        &state.plane.config().vpn_pool,
    )?;
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
            allow_relay: true,
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
    let database_autopilot_bearer_token = state
        .resolved_database_autopilot_bearer_token()
        .ok_or_else(|| {
            NodeEnrollmentApiError::unavailable(
                "database autopilot API bearer token is not configured",
            )
        })?;
    let keycloak_autopilot_bearer_token = state
        .resolved_keycloak_autopilot_bearer_token()
        .ok_or_else(|| {
            NodeEnrollmentApiError::unavailable(
                "Keycloak autopilot API bearer token is not configured",
            )
        })?;
    let install_script = node_enrollment_install_script(
        enrollment,
        &token,
        &encoded_token,
        &bootstrap_endpoints,
        &database_autopilot_bearer_token,
        &keycloak_autopilot_bearer_token,
    );
    let install_command =
        node_enrollment_install_command(enrollment, &encoded_token, &bootstrap_endpoints);
    let payload = AdminNodeEnrollmentResponse {
        token,
        expires_at,
        max_uses,
        install_command,
        install_script,
        binary_sha256: enrollment.daemon_binary.sha256.to_string(),
        cli_binary_sha256: enrollment.cli_binary.sha256.to_string(),
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
    let bootstrap_endpoints = node_enrollment_bootstrap_endpoints(
        enrollment.install_base_url.as_ref(),
        &directory.bootstrap_endpoints,
        &state.plane.config().vpn_pool,
    )?;
    let claims = JoinTokenClaims {
        cluster_id: state.plane.config().cluster_id.clone(),
        bootstrap_endpoints,
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
        if service_host_count(directory, kind) < 2 || service_endpoint_count(directory, kind) < 2 {
            missing.push(kind.to_string());
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(NodeEnrollmentApiError::unavailable(format!(
            "cannot issue an HA enrollment token until at least two active or recently advertised service hosts provide distinct endpoints for each required kind; insufficient: {}",
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
    if service_host_count(directory, BootstrapEndpointKind::ControlPlane) < 2
        || service_endpoint_count(directory, BootstrapEndpointKind::ControlPlane) < 2
    {
        return Err(NodeEnrollmentApiError::unavailable(
            "client enrollment requires at least two independently owned active or recently advertised control-plane endpoints",
        ));
    }
    Ok(())
}

fn node_enrollment_bootstrap_endpoints(
    install_base_url: &str,
    service_endpoints: &[BootstrapEndpoint],
    vpn_pool: &ipnet::Ipv4Net,
) -> Result<Vec<BootstrapEndpoint>, NodeEnrollmentApiError> {
    let mut bootstrap_endpoints = Vec::new();
    let mut seen = BTreeSet::new();
    let gateway_urls = std::iter::once(install_base_url).chain(
        service_endpoints
            .iter()
            .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::WebUi)
            .map(|endpoint| endpoint.url.as_str()),
    );
    for url in gateway_urls.filter_map(|url| node_enrollment_gateway_url(url, vpn_pool)) {
        if seen.insert((BootstrapEndpointKind::ControlPlane, url.clone())) {
            bootstrap_endpoints.push(BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url,
            });
            if bootstrap_endpoints.len() == MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND {
                break;
            }
        }
    }
    if bootstrap_endpoints.len() < 2 {
        return Err(NodeEnrollmentApiError::unavailable(
            "node enrollment requires at least two HTTP(S) public Gateways outside the HeteroNetwork VPN pool",
        ));
    }

    for endpoint in service_endpoints {
        if endpoint.kind == BootstrapEndpointKind::ControlPlane {
            continue;
        }
        let endpoint = if endpoint.kind == BootstrapEndpointKind::WebUi {
            let Some(url) = node_enrollment_gateway_url(&endpoint.url, vpn_pool) else {
                continue;
            };
            BootstrapEndpoint {
                kind: endpoint.kind,
                url,
            }
        } else {
            endpoint.clone()
        };
        let canonical_url = ipars_types::canonical_bootstrap_endpoint_url(&endpoint.url)
            .unwrap_or_else(|| endpoint.url.clone());
        if seen.insert((endpoint.kind, canonical_url)) {
            bootstrap_endpoints.push(endpoint);
        }
    }
    Ok(bootstrap_endpoints)
}

fn node_enrollment_gateway_url(url: &str, vpn_pool: &ipnet::Ipv4Net) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !matches!(parsed.path(), "" | "/")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    match parsed.host()? {
        url::Host::Ipv4(ip)
            if vpn_pool.contains(&ip)
                || ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip == std::net::Ipv4Addr::BROADCAST =>
        {
            return None;
        }
        url::Host::Ipv6(ip)
            if ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.segments()[0] & 0xffc0 == 0xfe80
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| vpn_pool.contains(&mapped)) =>
        {
            return None;
        }
        _ => {}
    }
    Some(parsed.as_str().trim_end_matches('/').to_string())
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

fn service_host_count(
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
        .map(|instance| instance.owner_host_id.as_str())
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
        .filter_map(|endpoint| ipars_types::canonical_bootstrap_endpoint_url(&endpoint.url))
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
    let database_autopilot_bearer_token = state
        .resolved_database_autopilot_bearer_token()
        .ok_or_else(|| {
            NodeEnrollmentApiError::unavailable(
                "database autopilot API bearer token is not configured",
            )
        })?;
    let keycloak_autopilot_bearer_token = state
        .resolved_keycloak_autopilot_bearer_token()
        .ok_or_else(|| {
            NodeEnrollmentApiError::unavailable(
                "Keycloak autopilot API bearer token is not configured",
            )
        })?;
    let script = node_enrollment_install_script(
        &enrollment,
        &token,
        &encoded_token,
        &token.claims.bootstrap_endpoints,
        &database_autopilot_bearer_token,
        &keycloak_autopilot_bearer_token,
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
    enrollment_binary_response(
        &enrollment.daemon_binary,
        "iparsd-linux-amd64",
        "node enrollment daemon binary",
    )
}

async fn node_enrollment_cli_binary<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    headers: HeaderMap,
) -> Result<Response, NodeEnrollmentApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let enrollment = authorize_node_enrollment(&state, &headers).await?;
    enrollment_binary_response(
        &enrollment.cli_binary,
        "ipars-linux-amd64",
        "node enrollment CLI binary",
    )
}

fn enrollment_binary_response(
    artifact: &PinnedEnrollmentBinary,
    filename: &'static str,
    label: &'static str,
) -> Result<Response, NodeEnrollmentApiError> {
    let binary = artifact
        .open()
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
        header::HeaderValue::from_str(&format!("attachment; filename={filename}"))
            .map_err(|_| NodeEnrollmentApiError::unavailable("invalid binary filename"))?,
    );
    headers.insert(
        header::CONTENT_LENGTH,
        header::HeaderValue::from_str(&artifact.size.to_string())
            .map_err(|_| NodeEnrollmentApiError::unavailable(format!("invalid {label} size")))?,
    );
    headers.insert(
        header::HeaderName::from_static("x-heteronetwork-sha256"),
        header::HeaderValue::from_str(&artifact.sha256).map_err(|_| {
            NodeEnrollmentApiError::unavailable(format!("invalid {label} checksum"))
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
    database_autopilot_bearer_token: &str,
    keycloak_autopilot_bearer_token: &str,
) -> String {
    const TEMPLATE: &str = r#"#!/bin/sh
set -eu

relay_enabled=1
public_services_enabled=1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --disable-relay)
      relay_enabled=0
      public_services_enabled=0
      ;;
    --disable-public-services)
      public_services_enabled=0
      ;;
    *)
      echo "Unknown HeteroNetwork installer argument: $1" >&2
      echo "Usage: $0 [--disable-relay] [--disable-public-services]" >&2
      exit 2
      ;;
  esac
  shift
done

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
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates coreutils curl iproute2 jq tar wireguard-tools
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates coreutils curl iproute jq tar wireguard-tools
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates coreutils curl iproute jq tar wireguard-tools
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install ca-certificates coreutils curl iproute2 jq tar wireguard-tools
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm ca-certificates coreutils curl iproute2 jq tar wireguard-tools
  else
    echo "Unsupported package manager; install curl, CA certificates, coreutils, iproute2, jq, tar, and wireguard-tools" >&2
    exit 1
  fi
}

for command in base64 curl ip jq sha256sum tar wg; do
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
iparsd_path=/opt/heteronetwork/bin/iparsd
iparsd_previous_snapshot="$tmp_dir/iparsd.previous"
iparsd_snapshot_ready=0
iparsd_was_present=0
iparsd_replaced=0
ipars_path=/usr/local/bin/ipars
ipars_previous_snapshot="$tmp_dir/ipars.previous"
ipars_snapshot_ready=0
ipars_was_present=0
ipars_replaced=0
relay_autopilot_transaction_active=0
relay_autopilot_timer_enable_state=not-found
relay_autopilot_timer_was_active=0
relay_autopilot_service_was_active=0
relay_service_was_active=0
relay_agent_enable_state=not-found
relay_agent_was_active=0
relay_snapshot_ready=0
relay_snapshot_dir="$tmp_dir/relay-rollback"
relay_snapshot_manifest="$relay_snapshot_dir/manifest"
relay_snapshot_directory_manifest="$relay_snapshot_dir/directories"
relay_transaction_paths='
/etc/sysusers.d/heteronetwork-relay.conf
/etc/heteronetwork/relay-admission.token
/etc/heteronetwork/relay-server-admission.token
/etc/heteronetwork/relay-autopilot/relay.env
/etc/systemd/system/heteronetwork-agent.service.d/10-relay-admission.conf
/etc/systemd/system/heteronetwork-agent.service.d/20-relay-autopilot.conf
/opt/heteronetwork/libexec/relay-autopilot.sh
/etc/systemd/system/heteronetwork-relay.service
/etc/systemd/system/heteronetwork-relay-autopilot.service
/etc/systemd/system/heteronetwork-relay-autopilot.timer
'
relay_transaction_temporary_paths='
/etc/heteronetwork/.relay-admission.token.new
/etc/heteronetwork/.relay-server-admission.token.new
/etc/systemd/system/heteronetwork-agent.service.d/.10-relay-admission.conf.new
/etc/systemd/system/.heteronetwork-relay.service.new
/etc/systemd/system/.heteronetwork-relay-autopilot.service.new
/etc/systemd/system/.heteronetwork-relay-autopilot.timer.new
/etc/sysusers.d/.heteronetwork-relay.conf.new
/opt/heteronetwork/libexec/.relay-autopilot.sh.new
'
relay_transaction_random_temporary_globs='
/etc/heteronetwork/relay-autopilot/.relay.env.*
/etc/systemd/system/heteronetwork-agent.service.d/.20-relay-autopilot.conf.*
'
relay_transaction_directories='
/etc/heteronetwork/relay-autopilot
/etc/systemd/system/heteronetwork-agent.service.d
/opt/heteronetwork/libexec
'

verify_systemd_unit_stopped() (
  unit_name=$1
  unit_load_state=
  unit_state=
  if ! unit_load_state=$(systemctl show \
    --property=LoadState --value "$unit_name" 2>/dev/null); then
    echo "Unable to inspect $unit_name" >&2
    return 1
  fi
  if [ "$unit_load_state" = "not-found" ]; then
    return 0
  fi
  if ! unit_state=$(systemctl show --property=ActiveState --value "$unit_name" 2>/dev/null); then
    echo "Unable to verify that $unit_name stopped" >&2
    return 1
  fi
  case "$unit_state" in
    inactive|failed)
      return 0
      ;;
    *)
      echo "$unit_name remains in $unit_state state" >&2
      return 1
      ;;
  esac
)

stop_systemd_unit_with_kill() {
  unit_name=$1
  stop_reported_error=0
  if ! systemctl stop "$unit_name"; then
    stop_reported_error=1
  fi
  if verify_systemd_unit_stopped "$unit_name"; then
    if [ "$stop_reported_error" -eq 1 ]; then
      echo "$unit_name reported a stop error but is no longer active" >&2
    fi
    return 0
  fi

  echo "$unit_name did not stop normally; forcing its remaining processes down" >&2
  if ! systemctl kill --kill-whom=all --signal=SIGKILL "$unit_name"; then
    echo "Unable to send SIGKILL to $unit_name" >&2
  fi
  if ! systemctl stop "$unit_name"; then
    echo "Unable to complete the forced stop job for $unit_name" >&2
  fi
  verify_systemd_unit_stopped "$unit_name"
}

systemd_unit_enable_state() {
  unit_name=$1
  unit_enable_state=
  if unit_enable_state=$(systemctl is-enabled "$unit_name" 2>/dev/null); then
    :
  elif [ -z "$unit_enable_state" ]; then
    unit_load_state=
    if ! unit_load_state=$(systemctl show \
      --property=LoadState --value "$unit_name" 2>/dev/null); then
      echo "Unable to inspect enablement for $unit_name" >&2
      return 1
    fi
    if [ "$unit_load_state" = "not-found" ]; then
      unit_enable_state=not-found
    else
      echo "Unable to determine enablement for $unit_name" >&2
      return 1
    fi
  fi
  case "$unit_enable_state" in
    enabled|enabled-runtime|linked|linked-runtime|alias|static|indirect|disabled|\
masked|masked-runtime|generated|transient|not-found)
      printf '%s\n' "$unit_enable_state"
      ;;
    *)
      echo "Unsupported enablement state '$unit_enable_state' for $unit_name" >&2
      return 1
      ;;
  esac
}

restore_systemd_unit_enable_state() {
  unit_name=$1
  expected_enable_state=$2
  case "$expected_enable_state" in
    enabled)
      systemctl unmask "$unit_name" >/dev/null 2>&1 || true
      systemctl unmask --runtime "$unit_name" >/dev/null 2>&1 || true
      systemctl disable "$unit_name" >/dev/null 2>&1 || true
      systemctl enable "$unit_name" >/dev/null
      ;;
    enabled-runtime)
      systemctl unmask "$unit_name" >/dev/null 2>&1 || true
      systemctl unmask --runtime "$unit_name" >/dev/null 2>&1 || true
      systemctl disable "$unit_name" >/dev/null 2>&1 || true
      systemctl enable --runtime "$unit_name" >/dev/null
      ;;
    disabled)
      systemctl unmask "$unit_name" >/dev/null 2>&1 || true
      systemctl unmask --runtime "$unit_name" >/dev/null 2>&1 || true
      systemctl disable "$unit_name" >/dev/null 2>&1 || true
      ;;
    masked)
      systemctl disable "$unit_name" >/dev/null 2>&1 || true
      systemctl unmask --runtime "$unit_name" >/dev/null 2>&1 || true
      systemctl mask "$unit_name" >/dev/null
      ;;
    masked-runtime)
      systemctl disable "$unit_name" >/dev/null 2>&1 || true
      systemctl unmask "$unit_name" >/dev/null 2>&1 || true
      systemctl mask --runtime "$unit_name" >/dev/null
      ;;
    linked|linked-runtime|alias|static|indirect|generated|transient|not-found)
      systemctl disable "$unit_name" >/dev/null 2>&1 || true
      ;;
    *)
      echo "Refusing to restore unsupported enablement state '$expected_enable_state' for $unit_name" >&2
      return 1
      ;;
  esac
  actual_enable_state=$(systemd_unit_enable_state "$unit_name") || return 1
  if [ "$actual_enable_state" != "$expected_enable_state" ]; then
    echo "Unable to restore $unit_name enablement: expected $expected_enable_state, got $actual_enable_state" >&2
    return 1
  fi
}

remove_relay_transaction_temporary_files() {
  relay_temporary_cleanup_failed=0
  for relay_path in $relay_transaction_temporary_paths; do
    if ! rm -f "$relay_path"; then
      relay_temporary_cleanup_failed=1
    fi
  done
  for relay_path in $relay_transaction_random_temporary_globs; do
    if ! rm -f "$relay_path"; then
      relay_temporary_cleanup_failed=1
    fi
  done
  [ "$relay_temporary_cleanup_failed" -eq 0 ]
}

snapshot_iparsd_binary() {
  rm -f "$iparsd_previous_snapshot"
  iparsd_was_present=0
  if [ -e "$iparsd_path" ] || [ -L "$iparsd_path" ]; then
    if [ ! -f "$iparsd_path" ] && [ ! -L "$iparsd_path" ]; then
      echo "Refusing to replace non-file HeteroNetwork binary path $iparsd_path" >&2
      return 1
    fi
    cp -a -- "$iparsd_path" "$iparsd_previous_snapshot"
    iparsd_was_present=1
  fi
  iparsd_snapshot_ready=1
}

restore_iparsd_binary() {
  if [ "$iparsd_snapshot_ready" -ne 1 ]; then
    return 0
  fi
  iparsd_restore_path="$iparsd_path.rollback.new"
  if [ "$iparsd_was_present" -eq 1 ]; then
    if [ ! -e "$iparsd_previous_snapshot" ] \
      && [ ! -L "$iparsd_previous_snapshot" ]; then
      echo "Previous HeteroNetwork binary snapshot is missing" >&2
      return 1
    fi
    if ! rm -f "$iparsd_restore_path" \
      || ! cp -a -- "$iparsd_previous_snapshot" "$iparsd_restore_path" \
      || ! mv -f -- "$iparsd_restore_path" "$iparsd_path"; then
      echo "Unable to restore the previous HeteroNetwork binary" >&2
      rm -f "$iparsd_restore_path"
      return 1
    fi
  elif ! rm -f "$iparsd_path" "$iparsd_restore_path"; then
    echo "Unable to remove the HeteroNetwork binary created by the failed install" >&2
    return 1
  fi
  iparsd_replaced=0
}

discard_iparsd_snapshot() {
  rm -f "$iparsd_previous_snapshot"
  iparsd_snapshot_ready=0
  iparsd_was_present=0
}

snapshot_ipars_binary() {
  rm -f "$ipars_previous_snapshot"
  ipars_was_present=0
  if [ -e "$ipars_path" ] || [ -L "$ipars_path" ]; then
    if [ ! -f "$ipars_path" ] && [ ! -L "$ipars_path" ]; then
      echo "Refusing to replace non-file HeteroNetwork CLI path $ipars_path" >&2
      return 1
    fi
    cp -a -- "$ipars_path" "$ipars_previous_snapshot"
    ipars_was_present=1
  fi
  ipars_snapshot_ready=1
}

restore_ipars_binary() {
  if [ "$ipars_snapshot_ready" -ne 1 ]; then
    return 0
  fi
  ipars_restore_path="$ipars_path.rollback.new"
  if [ "$ipars_was_present" -eq 1 ]; then
    if [ ! -e "$ipars_previous_snapshot" ] \
      && [ ! -L "$ipars_previous_snapshot" ]; then
      echo "Previous HeteroNetwork CLI snapshot is missing" >&2
      return 1
    fi
    if ! rm -f "$ipars_restore_path" \
      || ! cp -a -- "$ipars_previous_snapshot" "$ipars_restore_path" \
      || ! mv -f -- "$ipars_restore_path" "$ipars_path"; then
      echo "Unable to restore the previous HeteroNetwork CLI" >&2
      rm -f "$ipars_restore_path"
      return 1
    fi
  elif ! rm -f "$ipars_path" "$ipars_restore_path"; then
    echo "Unable to remove the HeteroNetwork CLI created by the failed install" >&2
    return 1
  fi
  ipars_replaced=0
}

discard_ipars_snapshot() {
  rm -f "$ipars_previous_snapshot"
  ipars_snapshot_ready=0
  ipars_was_present=0
}

snapshot_relay_transaction_files() {
  rm -rf "$relay_snapshot_dir"
  install -d -m 0700 "$relay_snapshot_dir/files"
  : >"$relay_snapshot_manifest"
  : >"$relay_snapshot_directory_manifest"
  for relay_path in $relay_transaction_directories; do
    if [ -e "$relay_path" ] || [ -L "$relay_path" ]; then
      if [ ! -d "$relay_path" ] || [ -L "$relay_path" ]; then
        echo "Refusing to snapshot non-directory Relay path $relay_path" >&2
        return 1
      fi
      relay_directory_mode=$(stat -c '%a' "$relay_path")
      relay_directory_uid=$(stat -c '%u' "$relay_path")
      relay_directory_gid=$(stat -c '%g' "$relay_path")
      printf 'present %s %s %s %s\n' \
        "$relay_directory_mode" \
        "$relay_directory_uid" \
        "$relay_directory_gid" \
        "$relay_path" >>"$relay_snapshot_directory_manifest"
    else
      printf 'absent - - - %s\n' "$relay_path" >>"$relay_snapshot_directory_manifest"
    fi
  done
  for relay_path in $relay_transaction_paths; do
    if [ -e "$relay_path" ] || [ -L "$relay_path" ]; then
      if [ ! -f "$relay_path" ] && [ ! -L "$relay_path" ]; then
        echo "Refusing to snapshot non-file Relay path $relay_path" >&2
        return 1
      fi
      relay_snapshot_path="$relay_snapshot_dir/files$relay_path"
      install -d -m 0700 "$(dirname "$relay_snapshot_path")"
      cp -a -- "$relay_path" "$relay_snapshot_path"
      printf 'present %s\n' "$relay_path" >>"$relay_snapshot_manifest"
    else
      printf 'absent %s\n' "$relay_path" >>"$relay_snapshot_manifest"
    fi
  done
  relay_snapshot_ready=1
}

restore_relay_transaction_directories() {
  relay_directory_restore_failed=0
  while read -r relay_directory_state relay_directory_mode relay_directory_uid \
    relay_directory_gid relay_path relay_extra; do
    if [ -z "$relay_directory_state" ] || [ -z "$relay_path" ] || [ -n "$relay_extra" ]; then
      echo "Invalid Relay directory rollback manifest entry" >&2
      relay_directory_restore_failed=1
      continue
    fi
    case "$relay_directory_state" in
      present)
        if [ ! -d "$relay_path" ] || [ -L "$relay_path" ]; then
          echo "Relay rollback directory is missing $relay_path" >&2
          relay_directory_restore_failed=1
          continue
        fi
        relay_current_owner=$(stat -c '%u:%g' "$relay_path")
        if [ "$relay_current_owner" != "$relay_directory_uid:$relay_directory_gid" ] \
          && ! chown "$relay_directory_uid:$relay_directory_gid" "$relay_path"; then
          echo "Unable to restore Relay directory ownership for $relay_path" >&2
          relay_directory_restore_failed=1
        fi
        if ! chmod "$relay_directory_mode" "$relay_path"; then
          echo "Unable to restore Relay directory mode for $relay_path" >&2
          relay_directory_restore_failed=1
        fi
        ;;
      absent)
        if ! rmdir "$relay_path" 2>/dev/null \
          && { [ -e "$relay_path" ] || [ -L "$relay_path" ]; }; then
          echo "Unable to remove Relay directory created by the failed upgrade: $relay_path" >&2
          relay_directory_restore_failed=1
        fi
        ;;
      *)
        echo "Invalid Relay directory rollback state for $relay_path" >&2
        relay_directory_restore_failed=1
        ;;
    esac
  done <"$relay_snapshot_directory_manifest"
  [ "$relay_directory_restore_failed" -eq 0 ]
}

restore_relay_transaction_files() {
  if [ "$relay_snapshot_ready" -ne 1 ] \
    || [ ! -f "$relay_snapshot_manifest" ] \
    || [ ! -f "$relay_snapshot_directory_manifest" ]; then
    return 0
  fi
  relay_restore_failed=0
  while read -r relay_snapshot_state relay_path relay_extra; do
    if [ -z "$relay_snapshot_state" ] || [ -z "$relay_path" ] || [ -n "$relay_extra" ]; then
      echo "Invalid Relay rollback manifest entry" >&2
      relay_restore_failed=1
      continue
    fi
    case "$relay_snapshot_state" in
      present)
        relay_snapshot_path="$relay_snapshot_dir/files$relay_path"
        relay_restore_path="$relay_path.relay-rollback.new"
        if [ ! -e "$relay_snapshot_path" ] && [ ! -L "$relay_snapshot_path" ]; then
          echo "Relay rollback snapshot is missing $relay_path" >&2
          relay_restore_failed=1
          continue
        fi
        if ! mkdir -p "$(dirname "$relay_path")" \
          || ! rm -f "$relay_restore_path" \
          || ! cp -a -- "$relay_snapshot_path" "$relay_restore_path" \
          || ! mv -f -- "$relay_restore_path" "$relay_path"; then
          echo "Unable to restore Relay path $relay_path" >&2
          rm -f "$relay_restore_path"
          relay_restore_failed=1
        fi
        ;;
      absent)
        if ! rm -f "$relay_path" "$relay_path.relay-rollback.new"; then
          echo "Unable to restore absent Relay path $relay_path" >&2
          relay_restore_failed=1
        fi
        ;;
      *)
        echo "Invalid Relay rollback state for $relay_path" >&2
        relay_restore_failed=1
        ;;
    esac
  done <"$relay_snapshot_manifest"
  if ! remove_relay_transaction_temporary_files; then
    relay_restore_failed=1
  fi
  if ! restore_relay_transaction_directories; then
    relay_restore_failed=1
  fi
  [ "$relay_restore_failed" -eq 0 ]
}

begin_relay_autopilot_transaction() {
  relay_autopilot_timer_enable_state=$(
    systemd_unit_enable_state heteronetwork-relay-autopilot.timer
  )
  relay_agent_enable_state=$(
    systemd_unit_enable_state heteronetwork-agent.service
  )
  relay_autopilot_timer_was_active=0
  relay_autopilot_service_was_active=0
  relay_service_was_active=0
  relay_agent_was_active=0
  if systemctl is-active --quiet heteronetwork-relay-autopilot.timer; then
    relay_autopilot_timer_was_active=1
  fi
  if systemctl is-active --quiet heteronetwork-relay-autopilot.service; then
    relay_autopilot_service_was_active=1
  fi
  if systemctl is-active --quiet heteronetwork-relay.service; then
    relay_service_was_active=1
  fi
  if systemctl is-active --quiet heteronetwork-agent.service; then
    relay_agent_was_active=1
  fi
  relay_autopilot_transaction_active=1
  stop_systemd_unit_with_kill heteronetwork-relay-autopilot.timer
  stop_systemd_unit_with_kill heteronetwork-relay-autopilot.service
  remove_relay_transaction_temporary_files
  snapshot_relay_transaction_files
}

restore_relay_autopilot_transaction() {
  relay_mutators_quiesced=1
  if ! stop_systemd_unit_with_kill heteronetwork-relay-autopilot.timer; then
    relay_mutators_quiesced=0
  fi
  if ! stop_systemd_unit_with_kill heteronetwork-relay-autopilot.service; then
    relay_mutators_quiesced=0
  fi
  if [ "$relay_mutators_quiesced" -ne 1 ]; then
    echo "Refusing Relay rollback because an autopilot mutator could not be stopped" >&2
    return 1
  fi
  if ! stop_systemd_unit_with_kill heteronetwork-agent.service; then
    echo "Refusing Relay rollback because the Agent advertisement could not be quiesced" >&2
    return 1
  fi
  if ! stop_systemd_unit_with_kill heteronetwork-relay.service; then
    echo "Refusing Relay rollback because the Relay runtime could not be stopped" >&2
    return 1
  fi

  relay_rollback_failed=0
  systemctl disable heteronetwork-relay-autopilot.timer >/dev/null 2>&1 || true
  systemctl disable heteronetwork-agent.service >/dev/null 2>&1 || true
  if ! restore_relay_transaction_files; then
    echo "Unable to restore the previous Relay files" >&2
    relay_rollback_failed=1
  fi
  if ! restore_iparsd_binary; then
    relay_rollback_failed=1
  fi
  if ! restore_ipars_binary; then
    relay_rollback_failed=1
  fi
  if [ "$relay_rollback_failed" -ne 0 ]; then
    return 1
  fi
  if ! systemctl daemon-reload; then
    echo "Unable to reload systemd after restoring Relay files" >&2
    return 1
  fi
  if ! restore_systemd_unit_enable_state \
    heteronetwork-relay-autopilot.timer \
    "$relay_autopilot_timer_enable_state"; then
    relay_rollback_failed=1
  fi
  if ! restore_systemd_unit_enable_state \
    heteronetwork-agent.service \
    "$relay_agent_enable_state"; then
    relay_rollback_failed=1
  fi
  if [ "$relay_rollback_failed" -ne 0 ]; then
    return 1
  fi

  if [ "$relay_service_was_active" -eq 1 ]; then
    if ! systemctl start heteronetwork-relay.service; then
      echo "Unable to restore the previously active Relay service" >&2
      return 1
    fi
  fi

  if [ "$relay_agent_was_active" -eq 1 ]; then
    if ! systemctl start heteronetwork-agent.service; then
      echo "Unable to restore the previously active HeteroNetwork Agent" >&2
      return 1
    fi
  fi

  if [ "$relay_autopilot_timer_was_active" -eq 1 ]; then
    if ! systemctl start heteronetwork-relay-autopilot.timer; then
      echo "Unable to restore the active Relay autopilot timer" >&2
      return 1
    fi
  fi
  if [ "$relay_autopilot_service_was_active" -eq 1 ]; then
    if ! systemctl start --no-block heteronetwork-relay-autopilot.service; then
      echo "Unable to restart the previously active Relay autopilot reconciliation" >&2
      return 1
    fi
  fi
  relay_autopilot_transaction_active=0
}

commit_installer_transaction() {
  relay_autopilot_transaction_active=0
  discard_iparsd_snapshot
  discard_ipars_snapshot
}

installer_exit_cleanup() {
  installer_status=$?
  trap - EXIT HUP INT TERM
  set +e
  if [ "$installer_status" -ne 0 ] \
    && [ "$relay_autopilot_transaction_active" -eq 1 ]; then
    if ! restore_relay_autopilot_transaction; then
      echo "Relay upgrade rollback did not fully restore the previous state" >&2
    fi
  elif [ "$installer_status" -ne 0 ] \
    && { [ "$iparsd_replaced" -eq 1 ] || [ "$ipars_replaced" -eq 1 ]; }; then
    if ! restore_iparsd_binary; then
      echo "Installer rollback could not restore the previous HeteroNetwork binary" >&2
    fi
    if ! restore_ipars_binary; then
      echo "Installer rollback could not restore the previous HeteroNetwork CLI" >&2
    fi
  fi
  rm -rf "$tmp_dir"
  exit "$installer_status"
}
trap installer_exit_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
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
snapshot_iparsd_binary
install -m 0755 "$binary" "$iparsd_path.new"
mv -f "$iparsd_path.new" "$iparsd_path"
iparsd_replaced=1

cli_binary="$tmp_dir/ipars"
cli_downloaded=
for encoded_base in $download_bases; do
  base=$(printf '%s' "$encoded_base" | base64 -d) || continue
  rm -f "$cli_binary"
  if curl -fsS -H "Authorization: HeteroNetworkJoin $auth" \
    "$base/v1/install/ipars-linux-amd64" -o "$cli_binary"; then
    actual_sha=$(sha256sum "$cli_binary" | awk '{print $1}')
    if [ "$actual_sha" = '__CLI_SHA256__' ]; then
      cli_downloaded=1
      break
    fi
  fi
done
if [ -z "$cli_downloaded" ]; then
  echo "HeteroNetwork CLI download failed on every control-plane endpoint" >&2
  exit 1
fi
chmod 0755 "$cli_binary"
snapshot_ipars_binary
install -m 0755 "$cli_binary" "$ipars_path.new"
mv -f "$ipars_path.new" "$ipars_path"
ipars_replaced=1

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
heteronetwork_enrolled_node_id=$(
  jq -er '.node_id | select(type == "string" and length > 0 and length <= 255)' \
    /var/lib/heteronetwork/agent.json
)
case "$heteronetwork_enrolled_node_id" in
  *[!A-Za-z0-9_.-]*)
    echo "Enrolled HeteroNetwork node ID is invalid" >&2
    exit 1
    ;;
esac
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
Wants=network-online.target
Requires=heteronetwork-gateway.service
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

__RELAY_ADMISSION_INSTALL__
__PUBLIC_SERVICES_INSTALL__
__KEYCLOAK_INSTALL__
systemctl daemon-reload
systemctl enable heteronetwork-gateway.service heteronetwork-agent.service
systemctl restart heteronetwork-gateway.service
systemctl restart heteronetwork-agent.service
__RELAY_AUTOPILOT_START__
__DATABASE_INSTALL__
__KEYCLOAK_START__
__PUBLIC_SERVICES_START__
__SETUP_INSTALL__
commit_installer_transaction
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
    let database_install =
        postgres_ha_install_script(enrollment, token, database_autopilot_bearer_token);
    let relay_admission_install = relay_admission_install_script(enrollment, token);
    let relay_autopilot_start = relay_autopilot_start_script(token);
    let public_services_install = public_services_install_script(
        enrollment,
        token,
        bootstrap_endpoints,
        database_autopilot_bearer_token,
        keycloak_autopilot_bearer_token,
    );
    let public_services_start = public_services_start_script(enrollment);
    let keycloak_install =
        keycloak_autopilot_install_script(enrollment, token, keycloak_autopilot_bearer_token);
    let keycloak_start = keycloak_autopilot_start_script(enrollment);
    TEMPLATE
        .replace("__AUTH__", encoded_token)
        .replace("__DOWNLOAD_BASES__", &download_bases)
        .replace("__SHA256__", &enrollment.daemon_binary.sha256)
        .replace("__CLI_SHA256__", &enrollment.cli_binary.sha256)
        .replace("__CADDY_VERSION__", NODE_ENROLLMENT_CADDY_VERSION)
        .replace("__CADDY_SHA256__", NODE_ENROLLMENT_CADDY_SHA256)
        .replace("__RELAY_ADMISSION_INSTALL__", &relay_admission_install)
        .replace("__PUBLIC_SERVICES_INSTALL__", &public_services_install)
        .replace("__KEYCLOAK_INSTALL__", &keycloak_install)
        .replace("__RELAY_AUTOPILOT_START__", &relay_autopilot_start)
        .replace("__DATABASE_INSTALL__", &database_install)
        .replace("__KEYCLOAK_START__", &keycloak_start)
        .replace("__PUBLIC_SERVICES_START__", &public_services_start)
        .replace("__SETUP_INSTALL__", &setup_install)
}

fn derive_node_enrollment_cluster_secret(
    enrollment: &NodeEnrollmentConfig,
    cluster_id: &ClusterId,
    purpose: &[u8],
) -> String {
    let mut digest = Sha256::new();
    digest.update(purpose);
    digest.update(b"\0");
    digest.update(enrollment.issuer.signing_key_b64().as_bytes());
    digest.update(b"\0");
    digest.update(cluster_id.as_str().as_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn relay_admission_install_script(
    enrollment: &NodeEnrollmentConfig,
    token: &SignedJoinToken,
) -> String {
    const CLEANUP: &str = r#"relay_cleanup_failed=0
relay_advertisement_drop_in=/etc/systemd/system/heteronetwork-agent.service.d/20-relay-autopilot.conf
relay_admission_drop_in=/etc/systemd/system/heteronetwork-agent.service.d/10-relay-admission.conf
relay_runtime_env=/etc/heteronetwork/relay-autopilot/relay.env

refresh_agent_after_relay_config_change() {
  relay_config_change_ready=$1
  relay_config_change_description=$2
  relay_config_reloaded=0
  if [ "$relay_config_change_ready" -eq 1 ]; then
    if systemctl daemon-reload; then
      relay_config_reloaded=1
    else
      echo "Unable to reload systemd after $relay_config_change_description" >&2
    fi
  fi
  if [ "$relay_config_reloaded" -eq 1 ]; then
    if systemctl is-active --quiet heteronetwork-agent.service; then
      if systemctl restart heteronetwork-agent.service; then
        return 0
      fi
      echo "Unable to restart heteronetwork-agent.service after $relay_config_change_description" >&2
    elif verify_systemd_unit_stopped heteronetwork-agent.service; then
      return 0
    fi
  fi
  if stop_systemd_unit_with_kill heteronetwork-agent.service; then
    return 0
  fi
  echo "Unable to apply $relay_config_change_description or verify a stopped HeteroNetwork Agent" >&2
  return 1
}

if ! systemctl disable heteronetwork-relay-autopilot.timer \
  heteronetwork-relay.service >/dev/null 2>&1; then
  echo "Relay cleanup disable command reported an error; verifying final state" >&2
fi
if systemctl is-enabled --quiet heteronetwork-relay-autopilot.timer \
  || systemctl is-enabled --quiet heteronetwork-relay.service; then
  echo "A Relay unit remains enabled; refusing destructive cleanup" >&2
  exit 1
fi
if ! stop_systemd_unit_with_kill heteronetwork-relay-autopilot.timer; then
  echo "Unable to stop the Relay autopilot timer; preserving Relay state" >&2
  exit 1
fi
if ! stop_systemd_unit_with_kill heteronetwork-relay-autopilot.service; then
  echo "Unable to stop the Relay autopilot mutator; preserving Relay state" >&2
  exit 1
fi
if ! remove_relay_transaction_temporary_files; then
  relay_cleanup_failed=1
fi

relay_advertisement_removed=1
if [ -e "$relay_advertisement_drop_in" ] || [ -L "$relay_advertisement_drop_in" ]; then
  if ! rm -f "$relay_advertisement_drop_in"; then
    echo "Unable to remove the Relay advertisement after stopping its autopilot" >&2
    relay_advertisement_removed=0
    relay_cleanup_failed=1
  fi
fi
if ! refresh_agent_after_relay_config_change \
  "$relay_advertisement_removed" \
  "withdrawing Relay advertisement"; then
  echo "Preserving the running Relay and its environment because advertisement withdrawal is unconfirmed" >&2
  exit 1
fi
if [ "$relay_advertisement_removed" -ne 1 ]; then
  echo "Preserving the running Relay and its environment because the advertisement remains on disk" >&2
  exit 1
fi

relay_admission_removed=1
if [ -e "$relay_admission_drop_in" ] || [ -L "$relay_admission_drop_in" ]; then
  if ! rm -f "$relay_admission_drop_in"; then
    echo "Unable to remove Relay admission configuration from heteronetwork-agent.service" >&2
    relay_admission_removed=0
    relay_cleanup_failed=1
  fi
fi
if ! refresh_agent_after_relay_config_change \
  "$relay_admission_removed" \
  "removing Relay admission configuration"; then
  echo "Preserving the running Relay, its environment, and admission tokens because Agent refresh is unconfirmed" >&2
  exit 1
fi
if [ "$relay_admission_removed" -ne 1 ]; then
  echo "Preserving the running Relay, its environment, and admission tokens because admission configuration remains on disk" >&2
  exit 1
fi

if ! stop_systemd_unit_with_kill heteronetwork-relay.service; then
  echo "Preserving Relay runtime environment and admission tokens because the service remains active" >&2
  exit 1
fi

if ! rm -f \
  "$relay_runtime_env" \
  /etc/heteronetwork/relay-admission.token \
  /etc/heteronetwork/.relay-admission.token.new \
  /etc/heteronetwork/relay-server-admission.token \
  /etc/heteronetwork/.relay-server-admission.token.new \
  "$relay_admission_drop_in" \
  /etc/systemd/system/heteronetwork-agent.service.d/.10-relay-admission.conf.new \
  "$relay_advertisement_drop_in" \
  /etc/systemd/system/heteronetwork-relay.service \
  /etc/systemd/system/.heteronetwork-relay.service.new \
  /etc/systemd/system/heteronetwork-relay-autopilot.service \
  /etc/systemd/system/.heteronetwork-relay-autopilot.service.new \
  /etc/systemd/system/heteronetwork-relay-autopilot.timer \
  /etc/systemd/system/.heteronetwork-relay-autopilot.timer.new \
  /etc/sysusers.d/.heteronetwork-relay.conf.new \
  /etc/sysusers.d/heteronetwork-relay.conf \
  /opt/heteronetwork/libexec/.relay-autopilot.sh.new \
  /opt/heteronetwork/libexec/relay-autopilot.sh; then
  relay_cleanup_failed=1
fi
if ! remove_relay_transaction_temporary_files; then
  relay_cleanup_failed=1
fi
rmdir /etc/heteronetwork/relay-autopilot >/dev/null 2>&1 || true
if ! systemctl daemon-reload; then
  echo "Unable to reload systemd after removing stopped Relay units" >&2
  relay_cleanup_failed=1
fi

if [ "$relay_cleanup_failed" -ne 0 ]; then
  exit 1
fi
"#;
    const TEMPLATE: &str = r#"relay_restart_required=$iparsd_replaced
if [ "$relay_enabled" -eq 1 ]; then
  begin_relay_autopilot_transaction
  install -d -o root -g root -m 0755 /etc/systemd/system/heteronetwork-agent.service.d
  install -d -o root -g root -m 0755 /opt/heteronetwork/libexec

  cat >"$tmp_dir/heteronetwork-relay.sysusers" <<'HETERONETWORK_RELAY_SYSUSERS'
u heteronetwork-relay - "HeteroNetwork Relay" /nonexistent
HETERONETWORK_RELAY_SYSUSERS
  install -o root -g root -m 0644 "$tmp_dir/heteronetwork-relay.sysusers" \
    /etc/sysusers.d/.heteronetwork-relay.conf.new
  mv -f /etc/sysusers.d/.heteronetwork-relay.conf.new \
    /etc/sysusers.d/heteronetwork-relay.conf
  systemd-sysusers /etc/sysusers.d/heteronetwork-relay.conf
  install -d -o root -g heteronetwork-relay -m 0750 \
    /etc/heteronetwork/relay-autopilot

  printf '%s' '__RELAY_TOKEN_B64__' | base64 -d >"$tmp_dir/relay-admission.token"
  install -o root -g root -m 0400 \
    "$tmp_dir/relay-admission.token" \
    /etc/heteronetwork/.relay-admission.token.new
  mv -f /etc/heteronetwork/.relay-admission.token.new \
    /etc/heteronetwork/relay-admission.token
  install -o heteronetwork-relay -g heteronetwork-relay -m 0400 \
    "$tmp_dir/relay-admission.token" \
    /etc/heteronetwork/.relay-server-admission.token.new
  if [ ! -f /etc/heteronetwork/relay-server-admission.token ] \
    || ! cmp -s /etc/heteronetwork/.relay-server-admission.token.new \
      /etc/heteronetwork/relay-server-admission.token; then
    relay_restart_required=1
  fi
  mv -f /etc/heteronetwork/.relay-server-admission.token.new \
    /etc/heteronetwork/relay-server-admission.token

  cat >"$tmp_dir/10-relay-admission.conf" <<'HETERONETWORK_RELAY_ADMISSION_UNIT'
[Service]
Environment=HETERONETWORK_AGENT_RELAY_ADMISSION_BEARER_TOKEN_PATH=/etc/heteronetwork/relay-admission.token
Environment=HETERONETWORK_AGENT_RELAY_FORWARDER_BIND=127.0.0.1:0
HETERONETWORK_RELAY_ADMISSION_UNIT
  install -o root -g root -m 0644 "$tmp_dir/10-relay-admission.conf" \
    /etc/systemd/system/heteronetwork-agent.service.d/.10-relay-admission.conf.new
  mv -f \
    /etc/systemd/system/heteronetwork-agent.service.d/.10-relay-admission.conf.new \
    /etc/systemd/system/heteronetwork-agent.service.d/10-relay-admission.conf

  cat >"$tmp_dir/relay-autopilot.sh" <<'HETERONETWORK_RELAY_AUTOPILOT'
#!/bin/sh
set -eu

agent_status_url=http://127.0.0.1:9780/v1/status
agent_service=heteronetwork-agent.service
relay_service=heteronetwork-relay.service
relay_env_dir=/etc/heteronetwork/relay-autopilot
relay_env="$relay_env_dir/relay.env"
agent_drop_in_dir=/etc/systemd/system/heteronetwork-agent.service.d
agent_drop_in="$agent_drop_in_dir/20-relay-autopilot.conf"
status_file=
relay_env_tmp=
agent_drop_in_tmp=
runtime_transaction_active=0
runtime_transaction_dir=
runtime_relay_env_state=absent
runtime_agent_drop_in_state=absent
runtime_relay_was_active=0
runtime_agent_was_active=0

cleanup_temporary_files() {
  [ -z "$status_file" ] || rm -f "$status_file"
  [ -z "$relay_env_tmp" ] || rm -f "$relay_env_tmp"
  [ -z "$agent_drop_in_tmp" ] || rm -f "$agent_drop_in_tmp"
  [ -z "$runtime_transaction_dir" ] || rm -rf "$runtime_transaction_dir"
}

cleanup_random_temporary_files() {
  rm -f \
    "$relay_env_dir"/.relay.env.* \
    "$agent_drop_in_dir"/.20-relay-autopilot.conf.*
}

verify_systemd_unit_stopped() (
  unit_name=$1
  unit_load_state=
  unit_state=
  if ! unit_load_state=$(systemctl show \
    --property=LoadState --value "$unit_name" 2>/dev/null); then
    echo "Unable to inspect $unit_name" >&2
    return 1
  fi
  if [ "$unit_load_state" = "not-found" ]; then
    return 0
  fi
  if ! unit_state=$(systemctl show \
    --property=ActiveState --value "$unit_name" 2>/dev/null); then
    echo "Unable to verify that $unit_name stopped" >&2
    return 1
  fi
  case "$unit_state" in
    inactive|failed)
      return 0
      ;;
    *)
      echo "$unit_name remains in $unit_state state" >&2
      return 1
      ;;
  esac
)

stop_systemd_unit_with_kill() {
  unit_name=$1
  stop_reported_error=0
  if ! systemctl stop "$unit_name"; then
    stop_reported_error=1
  fi
  if verify_systemd_unit_stopped "$unit_name"; then
    if [ "$stop_reported_error" -eq 1 ]; then
      echo "$unit_name reported a stop error but is no longer active" >&2
    fi
    return 0
  fi

  echo "$unit_name did not stop normally; forcing its remaining processes down" >&2
  if ! systemctl kill --kill-whom=all --signal=SIGKILL "$unit_name"; then
    echo "Unable to send SIGKILL to $unit_name" >&2
  fi
  if ! systemctl stop "$unit_name"; then
    echo "Unable to complete the forced stop job for $unit_name" >&2
  fi
  verify_systemd_unit_stopped "$unit_name"
}

refresh_agent_after_relay_config_change() {
  relay_config_change_ready=$1
  relay_config_change_description=$2
  relay_config_reloaded=0
  if [ "$relay_config_change_ready" -eq 1 ]; then
    if systemctl daemon-reload; then
      relay_config_reloaded=1
    else
      echo "Unable to reload systemd after $relay_config_change_description" >&2
    fi
  fi
  if [ "$relay_config_reloaded" -eq 1 ]; then
    if systemctl is-active --quiet "$agent_service"; then
      if systemctl restart "$agent_service"; then
        return 0
      fi
      echo "Unable to restart $agent_service after $relay_config_change_description" >&2
    elif verify_systemd_unit_stopped "$agent_service"; then
      return 0
    fi
  fi
  if stop_systemd_unit_with_kill "$agent_service"; then
    return 0
  fi
  echo "Unable to apply $relay_config_change_description or verify a stopped HeteroNetwork Agent" >&2
  return 1
}

snapshot_runtime_relay_transaction() {
  runtime_transaction_dir=$(mktemp -d \
    /run/heteronetwork-relay-autopilot/rollback.XXXXXX)
  runtime_relay_env_state=absent
  runtime_agent_drop_in_state=absent
  if [ -e "$relay_env" ] || [ -L "$relay_env" ]; then
    if [ ! -f "$relay_env" ] && [ ! -L "$relay_env" ]; then
      echo "Refusing to snapshot non-file Relay runtime environment" >&2
      return 1
    fi
    cp -a -- "$relay_env" "$runtime_transaction_dir/relay.env"
    runtime_relay_env_state=present
  fi
  if [ -e "$agent_drop_in" ] || [ -L "$agent_drop_in" ]; then
    if [ ! -f "$agent_drop_in" ] && [ ! -L "$agent_drop_in" ]; then
      echo "Refusing to snapshot non-file Relay advertisement" >&2
      return 1
    fi
    cp -a -- "$agent_drop_in" "$runtime_transaction_dir/agent.conf"
    runtime_agent_drop_in_state=present
  fi
  runtime_relay_was_active=0
  runtime_agent_was_active=0
  if systemctl is-active --quiet "$relay_service"; then
    runtime_relay_was_active=1
  fi
  if systemctl is-active --quiet "$agent_service"; then
    runtime_agent_was_active=1
  fi
}

restore_runtime_relay_path() {
  runtime_restore_path=$1
  runtime_snapshot_path=$2
  runtime_snapshot_state=$3
  runtime_restore_tmp="$runtime_restore_path.relay-rollback.new"
  case "$runtime_snapshot_state" in
    present)
      if ! rm -f "$runtime_restore_tmp" \
        || ! cp -a -- "$runtime_snapshot_path" "$runtime_restore_tmp" \
        || ! mv -f -- "$runtime_restore_tmp" "$runtime_restore_path"; then
        rm -f "$runtime_restore_tmp"
        return 1
      fi
      ;;
    absent)
      rm -f "$runtime_restore_path" "$runtime_restore_tmp"
      ;;
    *)
      return 1
      ;;
  esac
}

begin_runtime_relay_transaction() {
  snapshot_runtime_relay_transaction
  runtime_transaction_active=1
  if ! stop_systemd_unit_with_kill "$agent_service"; then
    echo "Unable to quiesce the Agent before changing Relay endpoint state" >&2
    return 1
  fi
  if ! stop_systemd_unit_with_kill "$relay_service"; then
    echo "Unable to quiesce the Relay before changing its endpoint state" >&2
    return 1
  fi
}

rollback_runtime_relay_transaction() {
  if ! stop_systemd_unit_with_kill "$agent_service"; then
    echo "Refusing runtime Relay rollback because the Agent advertisement remains active" >&2
    return 1
  fi
  if ! stop_systemd_unit_with_kill "$relay_service"; then
    echo "Refusing runtime Relay rollback because the Relay runtime remains active" >&2
    return 1
  fi
  if ! restore_runtime_relay_path \
    "$relay_env" \
    "$runtime_transaction_dir/relay.env" \
    "$runtime_relay_env_state"; then
    echo "Unable to restore the previous Relay runtime environment" >&2
    return 1
  fi
  if ! restore_runtime_relay_path \
    "$agent_drop_in" \
    "$runtime_transaction_dir/agent.conf" \
    "$runtime_agent_drop_in_state"; then
    echo "Unable to restore the previous Relay advertisement" >&2
    return 1
  fi
  cleanup_random_temporary_files
  if ! systemctl daemon-reload; then
    echo "Unable to reload systemd after restoring Relay runtime state" >&2
    return 1
  fi
  if [ "$runtime_agent_was_active" -eq 1 ] \
    && ! systemctl start "$agent_service"; then
    echo "Unable to restore the previously active Agent" >&2
    return 1
  fi
  if [ "$runtime_relay_was_active" -eq 1 ] \
    && ! systemctl start "$relay_service"; then
    echo "Unable to restore the previously active Relay runtime" >&2
    return 1
  fi
  runtime_transaction_active=0
}

commit_runtime_relay_transaction() {
  runtime_transaction_active=0
  rm -rf "$runtime_transaction_dir"
  runtime_transaction_dir=
}

autopilot_exit_cleanup() {
  autopilot_status=$?
  trap - EXIT HUP INT TERM
  set +e
  if [ "$autopilot_status" -ne 0 ] \
    && [ "$runtime_transaction_active" -eq 1 ]; then
    if ! rollback_runtime_relay_transaction; then
      echo "Relay autopilot rollback did not restore the previous endpoint state" >&2
    fi
  fi
  cleanup_temporary_files
  exit "$autopilot_status"
}
trap autopilot_exit_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

withdraw_relay() {
  relay_advertisement_removed=1
  if [ -e "$agent_drop_in" ] || [ -L "$agent_drop_in" ]; then
    if ! rm -f "$agent_drop_in"; then
      echo "Unable to remove the Relay advertisement from $agent_service" >&2
      relay_advertisement_removed=0
    fi
  fi
  if ! refresh_agent_after_relay_config_change \
    "$relay_advertisement_removed" \
    "withdrawing Relay capability"; then
    echo "Preserving the Relay runtime because advertisement withdrawal is unconfirmed" >&2
    return 1
  fi
  if [ "$relay_advertisement_removed" -ne 1 ]; then
    echo "Preserving the Relay runtime because its advertisement remains on disk" >&2
    return 1
  fi
  if ! stop_systemd_unit_with_kill "$relay_service"; then
    echo "Preserving the Relay runtime configuration because its service is still active" >&2
    return 1
  fi
  if ! rm -f "$relay_env"; then
    echo "Unable to remove the stopped Relay runtime configuration" >&2
    return 1
  fi
}

withdraw_relay_and_exit() {
  if withdraw_relay; then
    exit 0
  fi
  exit 1
}

install -d -o root -g root -m 0755 /run/heteronetwork-relay-autopilot
cleanup_random_temporary_files
status_file=$(mktemp /run/heteronetwork-relay-autopilot/status.XXXXXX)
if ! curl --fail --silent --show-error --max-time 5 --max-filesize 1048576 \
  "$agent_status_url" >"$status_file"; then
  withdraw_relay_and_exit
fi

if ! jq -e '
  . as $status
  | .nat_classification as $nat
  | (try ($nat.assessed_at
      | sub("\\.[0-9]+Z$"; "Z")
      | fromdateiso8601) catch null) as $assessed
  | ($status.node_id
      | type == "string"
        and length > 0
        and length <= 255
        and test("^[A-Za-z0-9_.-]+$"))
    and ($status.vpn_ip
      | type == "string"
        and length > 0
        and length <= 64
        and test("^[0-9A-Fa-f:.]+$"))
    and ($nat | type == "object")
    and ($nat.connectivity_state == "public")
    and ($nat.mapping_behavior == "no_nat")
    and ($nat.strategy == "direct_candidate")
    and ($nat.local_addr | type == "string")
    and ($nat.observed_endpoint == $nat.local_addr)
    and ($nat.observations | type == "array" and length > 0)
    and all($nat.observations[];
      .local_addr == $nat.local_addr
      and .reflexive_addr == $nat.local_addr)
    and ($assessed != null)
    and ($assessed <= (now + 5))
    and ($assessed >= (now - __RELAY_CLASSIFICATION_MAX_AGE_SECONDS__))
' "$status_file" >/dev/null; then
  withdraw_relay_and_exit
fi

node_id=$(jq -r '.node_id' "$status_file")
vpn_ip=$(jq -r '.vpn_ip' "$status_file")
public_ip=$(jq -er '
  .nat_classification.local_addr
  | if startswith("[") then
      capture("^\\[(?<host>[0-9A-Fa-f:.]+)\\]:[0-9]+$").host
    else
      capture("^(?<host>[0-9.]+):[0-9]+$").host
    end
' "$status_file") || {
  withdraw_relay_and_exit
}

case "$public_ip" in
  *:*)
    case "$public_ip" in
      ''|*[!0-9A-Fa-f:.]*) withdraw_relay_and_exit ;;
    esac
    relay_udp_listen="[::]:__RELAY_UDP_PORT__"
    relay_public_endpoint="[$public_ip]:__RELAY_UDP_PORT__"
    ;;
  *)
    case "$public_ip" in
      ''|*[!0-9.]*) withdraw_relay_and_exit ;;
    esac
    relay_udp_listen="0.0.0.0:__RELAY_UDP_PORT__"
    relay_public_endpoint="$public_ip:__RELAY_UDP_PORT__"
    ;;
esac

case "$vpn_ip" in
  *:*)
    case "$vpn_ip" in
      ''|*[!0-9A-Fa-f:.]*) withdraw_relay_and_exit ;;
    esac
    relay_http_listen="[$vpn_ip]:__RELAY_HTTP_PORT__"
    relay_http_url="http://[$vpn_ip]:__RELAY_HTTP_PORT__"
    ;;
  *)
    case "$vpn_ip" in
      ''|*[!0-9.]*) withdraw_relay_and_exit ;;
    esac
    relay_http_listen="$vpn_ip:__RELAY_HTTP_PORT__"
    relay_http_url="http://$vpn_ip:__RELAY_HTTP_PORT__"
    ;;
esac

install -d -o root -g heteronetwork-relay -m 0750 "$relay_env_dir"
relay_env_tmp=$(mktemp "$relay_env_dir/.relay.env.XXXXXX")
cat >"$relay_env_tmp" <<HETERONETWORK_RELAY_ENV
HETERONETWORK_RELAY_NODE_ID=$node_id
HETERONETWORK_RELAY_UDP_LISTEN=$relay_udp_listen
HETERONETWORK_RELAY_HTTP_LISTEN=$relay_http_listen
HETERONETWORK_RELAY_PUBLIC_ENDPOINT=$relay_public_endpoint
HETERONETWORK_RELAY_ADMISSION_URL=$relay_http_url
HETERONETWORK_RELAY_ADMISSION_BEARER_TOKEN_PATH=/etc/heteronetwork/relay-server-admission.token
HETERONETWORK_RELAY_ENV
chown root:heteronetwork-relay "$relay_env_tmp"
chmod 0640 "$relay_env_tmp"
relay_changed=0
if [ -f "$relay_env" ] && cmp -s "$relay_env_tmp" "$relay_env"; then
  rm -f "$relay_env_tmp"
  relay_env_tmp=
else
  relay_changed=1
fi

install -d -o root -g root -m 0755 "$agent_drop_in_dir"
agent_drop_in_tmp=$(mktemp "$agent_drop_in_dir/.20-relay-autopilot.conf.XXXXXX")
cat >"$agent_drop_in_tmp" <<HETERONETWORK_AGENT_RELAY_UNIT
[Service]
Environment="HETERONETWORK_AGENT_RELAY_PUBLIC_ENDPOINT=$relay_public_endpoint"
Environment="HETERONETWORK_AGENT_RELAY_ADMISSION_URL=$relay_http_url"
Environment="HETERONETWORK_AGENT_RELAY_STATUS_URL=$relay_http_url"
HETERONETWORK_AGENT_RELAY_UNIT
chown root:root "$agent_drop_in_tmp"
chmod 0644 "$agent_drop_in_tmp"
agent_changed=0
if [ -f "$agent_drop_in" ] && cmp -s "$agent_drop_in_tmp" "$agent_drop_in"; then
  rm -f "$agent_drop_in_tmp"
  agent_drop_in_tmp=
else
  agent_changed=1
fi

relay_was_active_now=0
if systemctl is-active --quiet "$relay_service"; then
  relay_was_active_now=1
fi
if [ "$relay_changed" -eq 1 ] \
  || [ "$agent_changed" -eq 1 ] \
  || [ "$relay_was_active_now" -ne 1 ]; then
  begin_runtime_relay_transaction
  if [ "$relay_changed" -eq 1 ]; then
    mv -f "$relay_env_tmp" "$relay_env"
    relay_env_tmp=
  fi
  if [ "$agent_changed" -eq 1 ]; then
    mv -f "$agent_drop_in_tmp" "$agent_drop_in"
    agent_drop_in_tmp=
  fi
  systemctl daemon-reload
  systemctl restart "$agent_service"
  if [ "$runtime_relay_was_active" -eq 1 ]; then
    systemctl restart "$relay_service"
  else
    systemctl start "$relay_service"
  fi
  commit_runtime_relay_transaction
fi
HETERONETWORK_RELAY_AUTOPILOT
  install -o root -g root -m 0755 "$tmp_dir/relay-autopilot.sh" \
    /opt/heteronetwork/libexec/.relay-autopilot.sh.new
  mv -f /opt/heteronetwork/libexec/.relay-autopilot.sh.new \
    /opt/heteronetwork/libexec/relay-autopilot.sh

  cat >"$tmp_dir/heteronetwork-relay.service" <<'HETERONETWORK_RELAY_UNIT'
[Unit]
Description=HeteroNetwork Relay
Wants=network-online.target heteronetwork-agent.service
After=network-online.target heteronetwork-agent.service
ConditionPathExists=/etc/heteronetwork/relay-autopilot/relay.env

[Service]
Type=simple
User=heteronetwork-relay
Group=heteronetwork-relay
EnvironmentFile=/etc/heteronetwork/relay-autopilot/relay.env
ExecStart=/opt/heteronetwork/bin/iparsd relay
Restart=on-failure
RestartSec=5s
TimeoutStopSec=20s
UMask=0077
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
HETERONETWORK_RELAY_UNIT
  install -o root -g root -m 0644 "$tmp_dir/heteronetwork-relay.service" \
    /etc/systemd/system/.heteronetwork-relay.service.new
  if [ -f /etc/systemd/system/heteronetwork-relay.service ] \
    && cmp -s /etc/systemd/system/.heteronetwork-relay.service.new \
      /etc/systemd/system/heteronetwork-relay.service; then
    rm -f /etc/systemd/system/.heteronetwork-relay.service.new
  else
    mv -f /etc/systemd/system/.heteronetwork-relay.service.new \
      /etc/systemd/system/heteronetwork-relay.service
    relay_restart_required=1
  fi

  cat >"$tmp_dir/heteronetwork-relay-autopilot.service" <<'HETERONETWORK_RELAY_AUTOPILOT_UNIT'
[Unit]
Description=Reconcile HeteroNetwork Relay capability
Wants=heteronetwork-agent.service
After=heteronetwork-agent.service

[Service]
Type=oneshot
ExecStart=/opt/heteronetwork/libexec/relay-autopilot.sh
RuntimeDirectory=heteronetwork-relay-autopilot
RuntimeDirectoryMode=0700
TimeoutStartSec=30s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
ReadWritePaths=/etc/heteronetwork/relay-autopilot /etc/systemd/system/heteronetwork-agent.service.d
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
HETERONETWORK_RELAY_AUTOPILOT_UNIT
  install -o root -g root -m 0644 \
    "$tmp_dir/heteronetwork-relay-autopilot.service" \
    /etc/systemd/system/.heteronetwork-relay-autopilot.service.new
  mv -f /etc/systemd/system/.heteronetwork-relay-autopilot.service.new \
    /etc/systemd/system/heteronetwork-relay-autopilot.service

  cat >"$tmp_dir/heteronetwork-relay-autopilot.timer" <<'HETERONETWORK_RELAY_AUTOPILOT_TIMER'
[Unit]
Description=Periodically reconcile HeteroNetwork Relay capability

[Timer]
OnBootSec=5s
OnUnitInactiveSec=__RELAY_RECONCILE_INTERVAL_SECONDS__s
RandomizedDelaySec=2s
AccuracySec=1s
Unit=heteronetwork-relay-autopilot.service

[Install]
WantedBy=timers.target
HETERONETWORK_RELAY_AUTOPILOT_TIMER
  install -o root -g root -m 0644 \
    "$tmp_dir/heteronetwork-relay-autopilot.timer" \
    /etc/systemd/system/.heteronetwork-relay-autopilot.timer.new
  mv -f /etc/systemd/system/.heteronetwork-relay-autopilot.timer.new \
    /etc/systemd/system/heteronetwork-relay-autopilot.timer
else
__RELAY_CLEANUP__fi
"#;
    if !token.claims.policy.allow_relay {
        return CLEANUP.to_string();
    }
    let encoded_bearer_token = STANDARD.encode(enrollment.relay_admission_bearer_token.as_bytes());
    TEMPLATE
        .replace("__RELAY_TOKEN_B64__", &encoded_bearer_token)
        .replace(
            "__RELAY_CLASSIFICATION_MAX_AGE_SECONDS__",
            &NODE_ENROLLMENT_RELAY_CLASSIFICATION_MAX_AGE_SECONDS.to_string(),
        )
        .replace(
            "__RELAY_RECONCILE_INTERVAL_SECONDS__",
            &NODE_ENROLLMENT_RELAY_RECONCILE_INTERVAL_SECONDS.to_string(),
        )
        .replace(
            "__RELAY_UDP_PORT__",
            &NODE_ENROLLMENT_RELAY_UDP_PORT.to_string(),
        )
        .replace(
            "__RELAY_HTTP_PORT__",
            &NODE_ENROLLMENT_RELAY_HTTP_PORT.to_string(),
        )
        .replace("__RELAY_CLEANUP__", CLEANUP)
}

fn relay_autopilot_start_script(token: &SignedJoinToken) -> String {
    if !token.claims.policy.allow_relay {
        return String::new();
    }
    r#"if [ "$relay_enabled" -eq 1 ]; then
  if [ "$relay_restart_required" -eq 1 ] \
    && systemctl is-active --quiet heteronetwork-relay.service; then
    systemctl restart heteronetwork-relay.service
  fi
  systemctl enable --now heteronetwork-relay-autopilot.timer
  systemctl start heteronetwork-relay-autopilot.service
fi
"#
    .to_string()
}

fn public_services_install_script(
    enrollment: &NodeEnrollmentConfig,
    token: &SignedJoinToken,
    bootstrap_endpoints: &[BootstrapEndpoint],
    database_autopilot_bearer_token: &str,
    keycloak_autopilot_bearer_token: &str,
) -> String {
    let Some(config) = enrollment.public_services.as_deref() else {
        return String::new();
    };
    let encode = |value: &str| STANDARD.encode(value.as_bytes());
    let mut seen_control_plane_urls = BTreeSet::new();
    let control_plane_urls = std::iter::once(enrollment.install_base_url.as_ref())
        .chain(
            bootstrap_endpoints
                .iter()
                .chain(token.claims.bootstrap_endpoints.iter())
                .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
                .map(|endpoint| endpoint.url.as_str()),
        )
        .map(|url| url.trim_end_matches('/').to_string())
        .filter(|url| seen_control_plane_urls.insert(url.clone()))
        .collect::<Vec<_>>()
        .join(",");
    let trusted_issuer_keys = config.trusted_issuer_keys.join(";");
    let mut enrollment_trusted_issuer_keys = config.trusted_node_enrollment_issuer_keys.clone();
    let enrollment_signer_entry = format!(
        "{},{},{},{}",
        enrollment.issuer_node_id(),
        enrollment.issuer_key_id(),
        enrollment.issuer_public_key_b64(),
        enrollment.max_ttl_seconds(),
    );
    if !enrollment_trusted_issuer_keys.contains(&enrollment_signer_entry) {
        enrollment_trusted_issuer_keys.push(enrollment_signer_entry);
    }
    let enrollment_trusted_issuer_keys = enrollment_trusted_issuer_keys.join(";");
    let oidc_auth_base_url = config.oidc_auth_base_url.as_deref().unwrap_or_default();
    let oidc_backchannel_base_url = managed_keycloak_edge_base_url(&config.oidc_issuer_url)
        .or_else(|| config.oidc_backchannel_base_url.clone())
        .unwrap_or_default();
    let mut seen_backchannel_fallbacks = BTreeSet::new();
    let oidc_backchannel_fallback_base_urls = config
        .oidc_backchannel_base_url
        .iter()
        .chain(config.oidc_backchannel_fallback_base_urls.iter())
        .filter(|url| {
            url.as_str() != oidc_backchannel_base_url
                && seen_backchannel_fallbacks.insert((*url).clone())
        })
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    let autopilot = STANDARD.encode(PUBLIC_SERVICES_AUTOPILOT_SCRIPT.as_bytes());
    format!(
        r#"if [ "$public_services_enabled" -eq 1 ]; then
  install -d -o root -g root -m 0755 /opt/heteronetwork/libexec
  install -d -o root -g root -m 0755 /etc/sysusers.d
  cat >/etc/sysusers.d/heteronetwork-services.conf <<'HETERONETWORK_PUBLIC_SERVICES_SYSUSERS'
u heteronetwork-services - "HeteroNetwork automatic public services" /nonexistent
HETERONETWORK_PUBLIC_SERVICES_SYSUSERS
  systemd-sysusers /etc/sysusers.d/heteronetwork-services.conf
  install -d -o root -g heteronetwork-services -m 0750 /etc/heteronetwork/public-services
  printf '%s' '{autopilot}' | base64 -d >/opt/heteronetwork/libexec/.public-services-autopilot.sh.new
  chown root:root /opt/heteronetwork/libexec/.public-services-autopilot.sh.new
  chmod 0755 /opt/heteronetwork/libexec/.public-services-autopilot.sh.new
  mv -f /opt/heteronetwork/libexec/.public-services-autopilot.sh.new /opt/heteronetwork/libexec/public-services-autopilot.sh
  cat >/etc/heteronetwork/public-services/.bootstrap.env.new <<'HETERONETWORK_PUBLIC_SERVICES_ENV'
HETERONETWORK_PUBLIC_SERVICES_CLUSTER_ID_B64={cluster_id}
HETERONETWORK_PUBLIC_SERVICES_VPN_POOL_B64={vpn_pool}
HETERONETWORK_PUBLIC_SERVICES_ISSUER_NODE_ID_B64={issuer_node_id}
HETERONETWORK_PUBLIC_SERVICES_ISSUER_KEY_ID_B64={issuer_key_id}
HETERONETWORK_PUBLIC_SERVICES_ISSUER_PUBLIC_KEY_B64={issuer_public_key}
HETERONETWORK_PUBLIC_SERVICES_TRUSTED_ISSUER_KEYS_B64={trusted_issuer_keys}
HETERONETWORK_PUBLIC_SERVICES_ENROLLMENT_TRUSTED_ISSUER_KEY_B64={enrollment_trusted_issuer_keys}
HETERONETWORK_PUBLIC_SERVICES_OIDC_ISSUER_URL_B64={oidc_issuer_url}
HETERONETWORK_PUBLIC_SERVICES_OIDC_CLIENT_ID_B64={oidc_client_id}
HETERONETWORK_PUBLIC_SERVICES_OIDC_AUTH_BASE_URL_B64={oidc_auth_base_url}
HETERONETWORK_PUBLIC_SERVICES_OIDC_BACKCHANNEL_BASE_URL_B64={oidc_backchannel_base_url}
HETERONETWORK_PUBLIC_SERVICES_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS_B64={oidc_backchannel_fallback_base_urls}
HETERONETWORK_PUBLIC_SERVICES_OIDC_SCOPES_B64={oidc_scopes}
HETERONETWORK_PUBLIC_SERVICES_CONTROL_PLANE_URLS_B64={control_plane_urls}
HETERONETWORK_PUBLIC_SERVICES_DATABASE_AUTOPILOT_BEARER_TOKEN={database_autopilot_bearer_token}
HETERONETWORK_PUBLIC_SERVICES_KEYCLOAK_AUTOPILOT_BEARER_TOKEN={keycloak_autopilot_bearer_token}
HETERONETWORK_PUBLIC_SERVICES_RECONCILE_INTERVAL_SECONDS={reconcile_interval}
HETERONETWORK_PUBLIC_SERVICES_CLASSIFICATION_MAX_AGE_SECONDS={classification_max_age}
HETERONETWORK_PUBLIC_SERVICES_ENV
  chown root:root /etc/heteronetwork/public-services/.bootstrap.env.new
  chmod 0600 /etc/heteronetwork/public-services/.bootstrap.env.new
  mv -f /etc/heteronetwork/public-services/.bootstrap.env.new /etc/heteronetwork/public-services/bootstrap.env
  cat >/etc/systemd/system/heteronetwork-control-plane.service <<'HETERONETWORK_CONTROL_PLANE_UNIT'
{control_plane_unit}
HETERONETWORK_CONTROL_PLANE_UNIT
  cat >/etc/systemd/system/heteronetwork-signal.service <<'HETERONETWORK_SIGNAL_UNIT'
{signal_unit}
HETERONETWORK_SIGNAL_UNIT
  cat >/etc/systemd/system/heteronetwork-stun.service <<'HETERONETWORK_STUN_UNIT'
{stun_unit}
HETERONETWORK_STUN_UNIT
  cat >/etc/systemd/system/heteronetwork-public-services-autopilot.service <<'HETERONETWORK_PUBLIC_SERVICES_AUTOPILOT_UNIT'
{autopilot_unit}
HETERONETWORK_PUBLIC_SERVICES_AUTOPILOT_UNIT
  cat >/etc/systemd/system/heteronetwork-public-services-autopilot.timer <<'HETERONETWORK_PUBLIC_SERVICES_AUTOPILOT_TIMER'
{autopilot_timer}
HETERONETWORK_PUBLIC_SERVICES_AUTOPILOT_TIMER
  chown root:root \
    /etc/systemd/system/heteronetwork-control-plane.service \
    /etc/systemd/system/heteronetwork-signal.service \
    /etc/systemd/system/heteronetwork-stun.service \
    /etc/systemd/system/heteronetwork-public-services-autopilot.service \
    /etc/systemd/system/heteronetwork-public-services-autopilot.timer
  chmod 0644 \
    /etc/systemd/system/heteronetwork-control-plane.service \
    /etc/systemd/system/heteronetwork-signal.service \
    /etc/systemd/system/heteronetwork-stun.service \
    /etc/systemd/system/heteronetwork-public-services-autopilot.service \
    /etc/systemd/system/heteronetwork-public-services-autopilot.timer
else
  if ! systemctl disable heteronetwork-public-services-autopilot.timer >/dev/null 2>&1; then
    echo "Automatic public-service timer was already disabled" >&2
  fi
  stop_systemd_unit_with_kill heteronetwork-public-services-autopilot.timer
  stop_systemd_unit_with_kill heteronetwork-public-services-autopilot.service
  stop_systemd_unit_with_kill heteronetwork-control-plane.service
  stop_systemd_unit_with_kill heteronetwork-signal.service
  stop_systemd_unit_with_kill heteronetwork-stun.service
  rm -f \
    /etc/systemd/system/heteronetwork-agent.service.d/30-public-services.conf \
    /etc/heteronetwork/public-services/bootstrap.env \
    /etc/heteronetwork/public-services/services.env \
    /etc/heteronetwork/public-services/database-url \
    /etc/heteronetwork/public-services/database-autopilot.token \
    /etc/heteronetwork/public-services/keycloak-autopilot.token \
    /opt/heteronetwork/libexec/public-services-autopilot.sh \
    /etc/systemd/system/heteronetwork-control-plane.service \
    /etc/systemd/system/heteronetwork-signal.service \
    /etc/systemd/system/heteronetwork-stun.service \
    /etc/systemd/system/heteronetwork-public-services-autopilot.service \
    /etc/systemd/system/heteronetwork-public-services-autopilot.timer
fi
"#,
        autopilot = autopilot,
        cluster_id = encode(token.claims.cluster_id.as_str()),
        vpn_pool = encode(&config.vpn_pool),
        issuer_node_id = encode(&config.issuer_node_id),
        issuer_key_id = encode(&config.issuer_key_id),
        issuer_public_key = encode(&config.issuer_public_key),
        trusted_issuer_keys = encode(&trusted_issuer_keys),
        enrollment_trusted_issuer_keys = encode(&enrollment_trusted_issuer_keys),
        oidc_issuer_url = encode(&config.oidc_issuer_url),
        oidc_client_id = encode(&config.oidc_client_id),
        oidc_auth_base_url = encode(oidc_auth_base_url),
        oidc_backchannel_base_url = encode(&oidc_backchannel_base_url),
        oidc_backchannel_fallback_base_urls = encode(&oidc_backchannel_fallback_base_urls),
        oidc_scopes = encode(&config.oidc_scopes),
        control_plane_urls = encode(&control_plane_urls),
        database_autopilot_bearer_token = database_autopilot_bearer_token,
        keycloak_autopilot_bearer_token = keycloak_autopilot_bearer_token,
        reconcile_interval = NODE_ENROLLMENT_PUBLIC_SERVICES_RECONCILE_INTERVAL_SECONDS,
        classification_max_age = NODE_ENROLLMENT_PUBLIC_SERVICES_CLASSIFICATION_MAX_AGE_SECONDS,
        control_plane_unit = PUBLIC_SERVICES_CONTROL_PLANE_UNIT,
        signal_unit = PUBLIC_SERVICES_SIGNAL_UNIT,
        stun_unit = PUBLIC_SERVICES_STUN_UNIT,
        autopilot_unit = PUBLIC_SERVICES_AUTOPILOT_UNIT,
        autopilot_timer = PUBLIC_SERVICES_AUTOPILOT_TIMER,
    )
}

fn managed_keycloak_edge_base_url(issuer_url: &str) -> Option<String> {
    let issuer_url = validate_web_auth_base_url(issuer_url.to_string(), "OIDC issuer URL").ok()?;
    let issuer_url = Url::parse(&issuer_url).ok()?;
    let issuer_path = issuer_url.path().trim_end_matches('/');
    Some(format!(
        "http://127.0.0.1:{KEYCLOAK_AUTOPILOT_EDGE_PORT}{issuer_path}"
    ))
}

pub fn managed_keycloak_overlay_issuer_url(issuer_url: &str) -> Option<String> {
    let issuer_url = validate_web_auth_base_url(issuer_url.to_string(), "OIDC issuer URL").ok()?;
    let issuer_url = Url::parse(&issuer_url).ok()?;
    let issuer_path = issuer_url.path().trim_end_matches('/');
    let realm = issuer_path.strip_prefix("/realms/")?;
    if realm.is_empty() || realm.contains('/') {
        return None;
    }
    Some(format!("{MANAGED_KEYCLOAK_OVERLAY_ORIGIN}{issuer_path}"))
}

fn public_services_start_script(enrollment: &NodeEnrollmentConfig) -> String {
    if enrollment.public_services.is_none() {
        return String::new();
    }
    r#"if [ "$public_services_enabled" -eq 1 ]; then
  stop_systemd_unit_with_kill heteronetwork-control-plane.service
  stop_systemd_unit_with_kill heteronetwork-signal.service
  stop_systemd_unit_with_kill heteronetwork-stun.service
  systemctl enable --now heteronetwork-public-services-autopilot.timer
  systemctl start --no-block heteronetwork-public-services-autopilot.service
  echo "Automatic public-service promotion scheduled"
fi
"#
    .to_string()
}

fn postgres_ha_install_script(
    enrollment: &NodeEnrollmentConfig,
    token: &SignedJoinToken,
    bearer_token: &str,
) -> String {
    let helper = STANDARD.encode(POSTGRES_HA_NODE_SCRIPT.as_bytes());
    let autopilot = STANDARD.encode(POSTGRES_HA_AUTOPILOT_SCRIPT.as_bytes());
    let cluster_id = STANDARD.encode(token.claims.cluster_id.as_str().as_bytes());
    let mut seen_control_plane_bases = BTreeSet::new();
    let control_plane_urls_b64 = std::iter::once(enrollment.install_base_url.as_ref())
        .chain(
            token
                .claims
                .bootstrap_endpoints
                .iter()
                .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
                .map(|endpoint| endpoint.url.as_str()),
        )
        .filter_map(|base| {
            let base = base.trim_end_matches('/');
            seen_control_plane_bases
                .insert(base.to_string())
                .then(|| STANDARD.encode(base.as_bytes()))
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"install -d -o root -g root -m 0755 /opt/heteronetwork/libexec
install -d -o root -g root -m 0700 /etc/heteronetwork/postgres-autopilot
printf '%s' '{helper}' | base64 -d >/opt/heteronetwork/libexec/postgres-ha-node.sh
printf '%s' '{autopilot}' | base64 -d >/opt/heteronetwork/libexec/postgres-ha-autopilot.sh
chown root:root /opt/heteronetwork/libexec/postgres-ha-node.sh /opt/heteronetwork/libexec/postgres-ha-autopilot.sh
chmod 0755 /opt/heteronetwork/libexec/postgres-ha-node.sh /opt/heteronetwork/libexec/postgres-ha-autopilot.sh
cat >/etc/heteronetwork/postgres-autopilot/autopilot.env <<'POSTGRES_AUTOPILOT_ENV'
HETERONETWORK_DB_AUTOPILOT_BEARER_TOKEN={bearer_token}
HETERONETWORK_DB_CLUSTER_ID_B64={cluster_id}
HETERONETWORK_DB_LOCAL_ROLE={role}
HETERONETWORK_DB_CONTROL_PLANE_URLS_B64='{control_plane_urls_b64}'
POSTGRES_AUTOPILOT_ENV
chown root:root /etc/heteronetwork/postgres-autopilot/autopilot.env
chmod 0600 /etc/heteronetwork/postgres-autopilot/autopilot.env
cat >/etc/systemd/system/heteronetwork-postgres-autopilot.service <<'POSTGRES_AUTOPILOT_UNIT'
{autopilot_unit}
POSTGRES_AUTOPILOT_UNIT
systemctl daemon-reload
systemctl enable heteronetwork-postgres-autopilot.service
systemctl restart --no-block heteronetwork-postgres-autopilot.service
echo "Automatic PostgreSQL HA placement scheduled"
"#,
        helper = helper,
        autopilot = autopilot,
        autopilot_unit = POSTGRES_HA_AUTOPILOT_UNIT,
        bearer_token = bearer_token,
        cluster_id = cluster_id,
        role = token.claims.role.as_str(),
        control_plane_urls_b64 = control_plane_urls_b64,
    )
}

fn keycloak_autopilot_install_script(
    enrollment: &NodeEnrollmentConfig,
    token: &SignedJoinToken,
    bearer_token: &str,
) -> String {
    let Some(public_services) = enrollment.public_services.as_deref() else {
        return String::new();
    };
    let Ok(issuer_url) = Url::parse(&public_services.oidc_issuer_url) else {
        return String::new();
    };
    let issuer_path = issuer_url.path().trim_end_matches('/');
    let oidc_probe_path = format!("{issuer_path}/.well-known/openid-configuration");
    let helper = STANDARD.encode(KEYCLOAK_HA_NODE_SCRIPT.as_bytes());
    let autopilot = STANDARD.encode(KEYCLOAK_AUTOPILOT_SCRIPT.as_bytes());
    let cluster_id = STANDARD.encode(token.claims.cluster_id.as_str().as_bytes());
    let archive_url = STANDARD.encode(KEYCLOAK_AUTOPILOT_ARCHIVE_URL.as_bytes());
    let oidc_probe_path = STANDARD.encode(oidc_probe_path.as_bytes());
    let mut seen_control_plane_bases = BTreeSet::new();
    let control_plane_urls_b64 = std::iter::once(enrollment.install_base_url.as_ref())
        .chain(
            token
                .claims
                .bootstrap_endpoints
                .iter()
                .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
                .map(|endpoint| endpoint.url.as_str()),
        )
        .filter_map(|base| {
            let base = base.trim_end_matches('/');
            seen_control_plane_bases
                .insert(base.to_string())
                .then(|| STANDARD.encode(base.as_bytes()))
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"if [ "$public_services_enabled" -eq 1 ]; then
  heteronetwork_keycloak_cluster_id=$(printf '%s' '{cluster_id}' | base64 -d)
  keycloak_autopilot_bearer_token=$(
    {{
      printf '%s\0' 'heteronetwork-keycloak-autopilot-node-v1'
      printf '%s\0' '{bearer_token}'
      printf '%s\0' "$heteronetwork_keycloak_cluster_id"
      printf '%s' "$heteronetwork_enrolled_node_id"
    }} | sha256sum | awk '{{print $1}}'
  )
  install -d -o root -g root -m 0755 /opt/heteronetwork/libexec
  install -d -o root -g root -m 0755 /etc/heteronetwork
  printf '%s' '{helper}' | base64 -d >/opt/heteronetwork/libexec/.keycloak-ha-node.sh.new
  printf '%s' '{autopilot}' | base64 -d >/opt/heteronetwork/libexec/.keycloak-autopilot.sh.new
  chown root:root \
    /opt/heteronetwork/libexec/.keycloak-ha-node.sh.new \
    /opt/heteronetwork/libexec/.keycloak-autopilot.sh.new
  chmod 0755 \
    /opt/heteronetwork/libexec/.keycloak-ha-node.sh.new \
    /opt/heteronetwork/libexec/.keycloak-autopilot.sh.new
  mv -f /opt/heteronetwork/libexec/.keycloak-ha-node.sh.new \
    /opt/heteronetwork/libexec/keycloak-ha-node.sh
  mv -f /opt/heteronetwork/libexec/.keycloak-autopilot.sh.new \
    /opt/heteronetwork/libexec/keycloak-autopilot.sh
  printf 'HETERONETWORK_KEYCLOAK_AUTOPILOT_BEARER_TOKEN=%s\n' \
    "$keycloak_autopilot_bearer_token" \
    >/etc/heteronetwork/.keycloak-autopilot.env.new
  cat >>/etc/heteronetwork/.keycloak-autopilot.env.new <<'KEYCLOAK_AUTOPILOT_ENV'
HETERONETWORK_KEYCLOAK_CLUSTER_ID_B64={cluster_id}
HETERONETWORK_KEYCLOAK_CONTROL_PLANE_URLS_B64='{control_plane_urls_b64}'
HETERONETWORK_KEYCLOAK_VERSION={keycloak_version}
HETERONETWORK_KEYCLOAK_ARCHIVE_URL_B64={archive_url}
HETERONETWORK_KEYCLOAK_ARCHIVE_SHA256={archive_sha256}
HETERONETWORK_KEYCLOAK_OIDC_PROBE_PATH_B64={oidc_probe_path}
KEYCLOAK_AUTOPILOT_ENV
  chown root:root /etc/heteronetwork/.keycloak-autopilot.env.new
  chmod 0600 /etc/heteronetwork/.keycloak-autopilot.env.new
  mv -f /etc/heteronetwork/.keycloak-autopilot.env.new \
    /etc/heteronetwork/keycloak-autopilot.env
  cat >/etc/systemd/system/heteronetwork-keycloak-prepare.service <<'KEYCLOAK_PREPARE_UNIT'
{prepare_unit}
KEYCLOAK_PREPARE_UNIT
  cat >/etc/systemd/system/heteronetwork-keycloak-autopilot.service <<'KEYCLOAK_AUTOPILOT_UNIT'
{autopilot_unit}
KEYCLOAK_AUTOPILOT_UNIT
  cat >/etc/systemd/system/heteronetwork-keycloak-autopilot.timer <<'KEYCLOAK_AUTOPILOT_TIMER'
{autopilot_timer}
KEYCLOAK_AUTOPILOT_TIMER
  chown root:root \
    /etc/systemd/system/heteronetwork-keycloak-prepare.service \
    /etc/systemd/system/heteronetwork-keycloak-autopilot.service \
    /etc/systemd/system/heteronetwork-keycloak-autopilot.timer
  chmod 0644 \
    /etc/systemd/system/heteronetwork-keycloak-prepare.service \
    /etc/systemd/system/heteronetwork-keycloak-autopilot.service \
    /etc/systemd/system/heteronetwork-keycloak-autopilot.timer
else
  systemctl disable heteronetwork-keycloak-prepare.service \
    heteronetwork-keycloak-autopilot.timer >/dev/null 2>&1 || true
  stop_systemd_unit_with_kill heteronetwork-keycloak-autopilot.timer
  stop_systemd_unit_with_kill heteronetwork-keycloak-autopilot.service
  stop_systemd_unit_with_kill heteronetwork-keycloak.service
  stop_systemd_unit_with_kill heteronetwork-keycloak-backchannel.service
  stop_systemd_unit_with_kill heteronetwork-keycloak-edge-proxy.service
  rm -f \
    /etc/systemd/system/heteronetwork-agent.service.d/30-keycloak-gateway.conf \
    /etc/heteronetwork/keycloak-autopilot.env \
    /opt/heteronetwork/libexec/keycloak-autopilot.sh \
    /opt/heteronetwork/libexec/keycloak-ha-node.sh \
    /etc/systemd/system/heteronetwork-keycloak-prepare.service \
    /etc/systemd/system/heteronetwork-keycloak-autopilot.service \
    /etc/systemd/system/heteronetwork-keycloak-autopilot.timer
fi
"#,
        helper = helper,
        autopilot = autopilot,
        bearer_token = bearer_token,
        cluster_id = cluster_id,
        control_plane_urls_b64 = control_plane_urls_b64,
        keycloak_version = KEYCLOAK_AUTOPILOT_VERSION,
        archive_url = archive_url,
        archive_sha256 = KEYCLOAK_AUTOPILOT_ARCHIVE_SHA256,
        oidc_probe_path = oidc_probe_path,
        prepare_unit = KEYCLOAK_PREPARE_UNIT,
        autopilot_unit = KEYCLOAK_AUTOPILOT_UNIT,
        autopilot_timer = KEYCLOAK_AUTOPILOT_TIMER,
    )
}

fn keycloak_autopilot_start_script(enrollment: &NodeEnrollmentConfig) -> String {
    if enrollment.public_services.is_none() {
        return String::new();
    }
    r#"if [ "$public_services_enabled" -eq 1 ]; then
  systemctl enable heteronetwork-keycloak-prepare.service heteronetwork-keycloak-autopilot.timer
  systemctl restart --no-block heteronetwork-keycloak-prepare.service
  systemctl start heteronetwork-keycloak-autopilot.timer
  echo "Automatic Keycloak HA placement scheduled"
fi
"#
    .to_string()
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
        || !token.claims.tags.contains(&Tag::kubernetes_control_plane())
        || token.claims.tags != token.claims.policy.allowed_tags
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
        "sh -c 'set -eu; tmp=$(mktemp); trap \"rm -f \\\"$tmp\\\"\" EXIT HUP INT TERM; auth=\"{encoded_token}\"; for encoded_base in {script_bases}; do base=$(printf \"%s\" \"$encoded_base\" | base64 -d) || continue; if curl -fsS -H \"Authorization: {NODE_ENROLLMENT_AUTH_SCHEME} $auth\" \"$base/v1/install/linux-amd64.sh\" -o \"$tmp\"; then sudo sh \"$tmp\" \"$@\"; exit; fi; done; echo \"HeteroNetwork installer download failed on every control-plane endpoint\" >&2; exit 1' sh"
    )
}

fn node_enrollment_download_bases(
    enrollment: &NodeEnrollmentConfig,
    bootstrap_endpoints: &[BootstrapEndpoint],
) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut bases = Vec::new();
    let install_base_url = enrollment.install_base_url.trim_end_matches('/');
    let install_base_is_allowed = bootstrap_endpoints.iter().any(|endpoint| {
        endpoint.kind == BootstrapEndpointKind::ControlPlane
            && endpoint.url.trim_end_matches('/') == install_base_url
    });
    for base in install_base_is_allowed
        .then_some(install_base_url)
        .into_iter()
        .chain(
            bootstrap_endpoints
                .iter()
                .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::WebUi)
                .map(|endpoint| endpoint.url.as_str()),
        )
    {
        let base = base.trim_end_matches('/').to_string();
        if seen.insert(base.clone()) {
            bases.push(base);
        }
    }
    bases
}

#[derive(Debug, Clone, Serialize)]
struct DatabaseAutopilotRegistryNode {
    node_id: String,
    vpn_ip: String,
    role: String,
    active: bool,
}

#[derive(Debug, Serialize)]
struct DatabaseAutopilotRegistryResponse {
    cluster_id: String,
    vpn_cidr: String,
    selection_epoch: u64,
    nodes: Vec<DatabaseAutopilotRegistryNode>,
    generated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DatabaseAutopilotRegistryRequest {
    selection_epoch: u64,
    member_node_ids: Vec<NodeId>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeycloakAutopilotRequest {
    node_id: NodeId,
    vpn_ip: VpnIp,
    eligible: bool,
    ready: bool,
    version: String,
    generation: i64,
}

#[derive(Debug, Serialize)]
struct KeycloakAutopilotReplica {
    node_id: String,
    vpn_ip: String,
    version: String,
    ready: bool,
    lease_expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct KeycloakAutopilotResponse {
    cluster_id: String,
    placement_id: String,
    desired_replicas: usize,
    lease_ttl_seconds: u64,
    reconcile_after_seconds: u64,
    generation: i64,
    assigned: bool,
    replicas: Vec<KeycloakAutopilotReplica>,
    generated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct KeycloakAdminPlacementResponse {
    cluster_id: String,
    placement_id: String,
    desired_replicas: usize,
    replicas: Vec<KeycloakAutopilotReplica>,
    generated_at: DateTime<Utc>,
}

#[derive(Debug)]
struct DatabaseAutopilotRegistrySnapshot {
    loaded_at: Instant,
    health_ttl: Duration,
    generated_at: DateTime<Utc>,
    nodes_by_id: HashMap<NodeId, DatabaseAutopilotRegistryNode>,
    active_node_ids: Vec<NodeId>,
}

fn database_autopilot_node_is_active(
    node: &NodeRecord,
    health: Option<&NodeHealth>,
    generated_at: DateTime<Utc>,
    ttl: Duration,
) -> bool {
    if node.role.is_client() {
        return false;
    }
    let last_seen_at = match health {
        Some(health) if health.state == HealthState::Unhealthy => return false,
        Some(health) => health.last_seen_at,
        None => node.registered_at,
    };
    match generated_at.signed_duration_since(last_seen_at).to_std() {
        Ok(age) => age <= ttl,
        Err(_) => true,
    }
}

fn select_database_autopilot_registry_nodes(
    snapshot: &DatabaseAutopilotRegistrySnapshot,
    member_node_ids: &[NodeId],
    selection_epoch: u64,
) -> Result<Vec<DatabaseAutopilotRegistryNode>, ControlPlaneError> {
    let mut selected = Vec::with_capacity(MAX_DATABASE_AUTOPILOT_CANDIDATES);
    let mut selected_ids = BTreeSet::new();
    for node_id in member_node_ids {
        let node = snapshot.nodes_by_id.get(node_id).ok_or_else(|| {
            ControlPlaneError::InvalidClusterPolicy(format!(
                "persisted database member {node_id} is not registered"
            ))
        })?;
        selected.push(node.clone());
        selected_ids.insert(node_id.clone());
    }
    let slots = MAX_DATABASE_AUTOPILOT_CANDIDATES.saturating_sub(selected.len());
    if !snapshot.active_node_ids.is_empty() && slots > 0 {
        let active_len = snapshot.active_node_ids.len();
        let mut excluded_active_indices = member_node_ids
            .iter()
            .filter_map(|node_id| snapshot.active_node_ids.binary_search(node_id).ok())
            .collect::<Vec<_>>();
        excluded_active_indices.sort_unstable();
        let available_len = active_len.saturating_sub(excluded_active_indices.len());
        if available_len == 0 {
            return Ok(selected);
        }
        let offset = ((selection_epoch as u128 % available_len as u128)
            * (slots as u128 % available_len as u128)
            % available_len as u128) as usize;
        let mut active_index = offset;
        for excluded_index in &excluded_active_indices {
            if *excluded_index > active_index {
                break;
            }
            active_index += 1;
        }
        let mut examined = 0;
        while selected.len() < MAX_DATABASE_AUTOPILOT_CANDIDATES && examined < active_len {
            let node_id = &snapshot.active_node_ids[(active_index + examined) % active_len];
            if selected_ids.insert(node_id.clone()) {
                let node = snapshot.nodes_by_id.get(node_id).ok_or_else(|| {
                    ControlPlaneError::Store(format!(
                        "active database node {node_id} is absent from the cached registry"
                    ))
                })?;
                selected.push(node.clone());
            }
            examined += 1;
        }
    }
    Ok(selected)
}

async fn database_autopilot_registry_snapshot<S, L>(
    state: &ControlPlaneHttpState<S, L>,
    health_ttl: Duration,
) -> Result<Arc<DatabaseAutopilotRegistrySnapshot>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let mut cached = state.database_autopilot_registry_cache.lock().await;
    if let Some(snapshot) = cached.as_ref().filter(|snapshot| {
        snapshot.loaded_at.elapsed() <= DATABASE_AUTOPILOT_REGISTRY_CACHE_TTL
            && snapshot.health_ttl == health_ttl
    }) {
        return Ok(Arc::clone(snapshot));
    }

    let generated_at = Utc::now();
    let cluster_id = &state.plane.config().cluster_id;
    let (nodes, health_by_node) = state.plane.registered_nodes_with_health().await?;
    let mut nodes_by_id = HashMap::with_capacity(nodes.len());
    let mut active_node_ids = Vec::new();
    for node in nodes
        .into_iter()
        .filter(|node| node.cluster_id == *cluster_id)
    {
        let active = database_autopilot_node_is_active(
            &node,
            health_by_node.get(&node.node_id),
            generated_at,
            health_ttl,
        );
        let node_id = node.node_id.clone();
        let registry_node = DatabaseAutopilotRegistryNode {
            node_id: node_id.to_string(),
            vpn_ip: node.vpn_ip.to_string(),
            role: node.role.to_string(),
            active,
        };
        if active {
            active_node_ids.push(node_id.clone());
        }
        nodes_by_id.insert(node_id, registry_node);
    }
    active_node_ids.sort();
    let snapshot = Arc::new(DatabaseAutopilotRegistrySnapshot {
        loaded_at: Instant::now(),
        health_ttl,
        generated_at,
        nodes_by_id,
        active_node_ids,
    });
    *cached = Some(Arc::clone(&snapshot));
    Ok(snapshot)
}

async fn database_autopilot_nodes<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<DatabaseAutopilotRegistryRequest>,
) -> Result<Json<DatabaseAutopilotRegistryResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    if request.member_node_ids.len() > MAX_DATABASE_AUTOPILOT_MEMBER_IDS
        || request
            .member_node_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != request.member_node_ids.len()
    {
        return Err(ControlPlaneError::InvalidClusterPolicy(
            "database autopilot member IDs must be unique and contain at most 32 entries"
                .to_string(),
        )
        .into());
    }
    let config = state.plane.config();
    let cluster_id = config.cluster_id.clone();
    let vpn_cidr = config.vpn_pool.to_string();
    let policy = state.plane.current_cluster_policy().await?;
    let ttl = Duration::from_secs(policy.relay_health_ttl_seconds);
    let snapshot = database_autopilot_registry_snapshot(&state, ttl).await?;
    let nodes = select_database_autopilot_registry_nodes(
        &snapshot,
        &request.member_node_ids,
        request.selection_epoch,
    )?;
    Ok(Json(DatabaseAutopilotRegistryResponse {
        cluster_id: cluster_id.to_string(),
        vpn_cidr,
        selection_epoch: request.selection_epoch,
        nodes,
        generated_at: snapshot.generated_at,
    }))
}

async fn keycloak_autopilot_reconcile<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<KeycloakAutopilotRequest>,
) -> Result<Json<KeycloakAutopilotResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    if request.version != KEYCLOAK_AUTOPILOT_VERSION {
        return Err(ControlPlaneError::InvalidClusterPolicy(format!(
            "Keycloak candidate version must be {KEYCLOAK_AUTOPILOT_VERSION}"
        ))
        .into());
    }
    if !request.eligible && request.ready {
        return Err(ControlPlaneError::InvalidClusterPolicy(
            "an ineligible Keycloak candidate cannot report ready".to_string(),
        )
        .into());
    }
    let generated_at = Utc::now();
    let placement = state
        .plane
        .reconcile_keycloak_placement(
            &request.node_id,
            request.vpn_ip,
            &request.version,
            request.eligible,
            request.ready,
            request.generation,
            Duration::from_secs(KEYCLOAK_AUTOPILOT_LEASE_SECONDS),
            KEYCLOAK_AUTOPILOT_DESIRED_REPLICAS,
            KEYCLOAK_AUTOPILOT_MAX_CANDIDATES,
            generated_at,
        )
        .await?;
    let assigned = placement
        .replicas
        .iter()
        .any(|replica| replica.node_id == request.node_id);
    let replicas = placement
        .replicas
        .into_iter()
        .map(|replica| KeycloakAutopilotReplica {
            node_id: replica.node_id.to_string(),
            vpn_ip: replica.vpn_ip.to_string(),
            version: replica.version,
            ready: replica.ready,
            lease_expires_at: replica.lease_expires_at,
        })
        .collect();
    Ok(Json(KeycloakAutopilotResponse {
        cluster_id: state.plane.config().cluster_id.to_string(),
        placement_id: placement.placement_id,
        desired_replicas: KEYCLOAK_AUTOPILOT_DESIRED_REPLICAS,
        lease_ttl_seconds: KEYCLOAK_AUTOPILOT_LEASE_SECONDS,
        reconcile_after_seconds: KEYCLOAK_AUTOPILOT_RECONCILE_SECONDS,
        generation: request.generation,
        assigned,
        replicas,
        generated_at,
    }))
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
        cluster_policy: state.plane.current_cluster_policy().await?,
        metrics: control_plane_metrics(&state).await?,
        nodes: admin_node_snapshot(&state.plane).await?,
        paths: state.plane.list_paths().await?,
        nat_discovery: state.plane.nat_discovery_overview().await?,
        service_directory: state.plane.service_directory().await?,
        generated_at,
    }))
}

async fn admin_topology<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
) -> Result<Json<ControlPlaneTopologyResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    Ok(Json(state.plane.overlay_topology_snapshot().await?))
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

async fn admin_keycloak_placement<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
) -> Result<Json<KeycloakAdminPlacementResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let generated_at = Utc::now();
    let placement = state
        .plane
        .keycloak_placement(
            KEYCLOAK_AUTOPILOT_VERSION,
            KEYCLOAK_AUTOPILOT_DESIRED_REPLICAS,
            KEYCLOAK_AUTOPILOT_MAX_CANDIDATES,
            generated_at,
        )
        .await?;
    Ok(Json(KeycloakAdminPlacementResponse {
        cluster_id: state.plane.config().cluster_id.to_string(),
        placement_id: placement.placement_id,
        desired_replicas: KEYCLOAK_AUTOPILOT_DESIRED_REPLICAS,
        replicas: placement
            .replicas
            .into_iter()
            .map(|replica| KeycloakAutopilotReplica {
                node_id: replica.node_id.to_string(),
                vpn_ip: replica.vpn_ip.to_string(),
                version: replica.version,
                ready: replica.ready,
                lease_expires_at: replica.lease_expires_at,
            })
            .collect(),
        generated_at,
    }))
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
        cluster_policy: state.plane.current_cluster_policy().await?,
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
    let cluster_policy = state
        .plane
        .set_cluster_policy(request.cluster_policy)
        .await?;
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

async fn require_database_autopilot_bearer(
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
                error: "database autopilot API bearer token was rejected".to_string(),
            }),
        )
            .into_response();
    }
    next.run(request).await
}

#[derive(Debug)]
struct KeycloakAutopilotAuth {
    base_secret: Arc<str>,
    cluster_id: ClusterId,
}

async fn require_keycloak_autopilot_bearer(
    State(auth): State<Arc<KeycloakAutopilotAuth>>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let body = match axum::body::to_bytes(body, MAX_KEYCLOAK_AUTOPILOT_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Keycloak autopilot request body is invalid or too large".to_string(),
                }),
            )
                .into_response();
        }
    };
    let claimed_node_id = match serde_json::from_slice::<KeycloakAutopilotRequest>(&body) {
        Ok(request) => request.node_id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Keycloak autopilot request body is invalid".to_string(),
                }),
            )
                .into_response();
        }
    };
    let expected =
        derive_keycloak_node_bearer(&auth.base_secret, &auth.cluster_id, &claimed_node_id);
    let provided = bearer_token_from_headers(&parts.headers);
    if !provided.is_some_and(|provided| operator_api_token_matches(&expected, provided)) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(ErrorResponse {
                error: "Keycloak autopilot API bearer token was rejected".to_string(),
            }),
        )
            .into_response();
    }
    next.run(Request::from_parts(parts, Body::from(body))).await
}

fn derive_keycloak_node_bearer(
    base_secret: &str,
    cluster_id: &ClusterId,
    node_id: &NodeId,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"heteronetwork-keycloak-autopilot-node-v1");
    digest.update(b"\0");
    digest.update(base_secret.as_bytes());
    digest.update(b"\0");
    digest.update(cluster_id.as_str().as_bytes());
    digest.update(b"\0");
    digest.update(node_id.as_str().as_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
        cluster_policy: state.plane.current_cluster_policy().await?,
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
    let keycloak_placement = state
        .plane
        .keycloak_placement(
            KEYCLOAK_AUTOPILOT_VERSION,
            KEYCLOAK_AUTOPILOT_DESIRED_REPLICAS,
            KEYCLOAK_AUTOPILOT_MAX_CANDIDATES,
            Utc::now(),
        )
        .await?;
    metrics.ha_ready = metrics.ha_ready
        && keycloak_placement.replicas.len() == KEYCLOAK_AUTOPILOT_DESIRED_REPLICAS
        && keycloak_placement
            .replicas
            .iter()
            .all(|replica| replica.ready);
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

async fn sponsored_client_enrollment<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<SponsoredClientRegistrationRequest>,
) -> Result<(StatusCode, Json<RegisterClientResponse>), ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let response = state
        .plane
        .register_sponsored_client(request, Utc::now())
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
    let cluster_policy = state.plane.current_cluster_policy().await?;
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

async fn neighbors<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<ControlPlaneNodeQueryRequest>,
) -> Result<Json<NeighborMap>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    state
        .plane
        .authenticate_node_query(&request, ControlPlaneNodeQueryKind::NeighborMap, Utc::now())
        .await?;
    let response = state.plane.neighbor_map_for(&request.node_id).await?;
    Ok(Json(response))
}

async fn overlay_paths<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<OverlayPathQuery>,
) -> Result<Json<OverlayPath>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    state
        .plane
        .authenticate_overlay_path_query(&request, Utc::now())
        .await?;
    let response = state.plane.overlay_path_for(&request).await?;
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
    trusted_oidc_issuer: Option<&str>,
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
    let issuer = issuer.trim_end_matches('/');
    let mut discovery =
        Url::parse(issuer).map_err(|error| format!("UI config OIDC issuer is invalid: {error}"))?;
    if discovery.origin() != gateway.origin() && trusted_oidc_issuer != Some(issuer) {
        return Err("UI config OIDC issuer is not trusted by this Control Plane".to_string());
    }
    if discovery.query().is_some() || discovery.fragment().is_some() {
        return Err("UI config OIDC issuer must not contain a query or fragment".to_string());
    }
    let path = format!(
        "{}/.well-known/openid-configuration",
        discovery.path().trim_end_matches('/')
    );
    discovery.set_path(&path);
    Ok(Some((issuer.to_string(), discovery.to_string())))
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
    if let Some((expected_issuer, discovery_url)) =
        dynamic_web_gateway_oidc_discovery(&body, url, config.trusted_oidc_issuer.as_deref())?
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
    let directory = state.plane.service_directory().await?;
    if !bootstrap_endpoints_include_core_services(&directory.bootstrap_endpoints) {
        state.plane.withdraw_service_instance(&instance_id).await?;
        return Ok(());
    }
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
            owner_host_id: node_id.as_str().to_string(),
            owner_node_id: Some(node_id.clone()),
            enrollment_signer: false,
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
        "# HELP ipars_control_plane_ha_ready Whether public services are redundant and every desired Keycloak replica is ready."
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
        "# HELP ipars_control_plane_service_hosts Number of hosts with active public service leases."
    );
    prometheus_line!(&mut body, "# TYPE ipars_control_plane_service_hosts gauge");
    prometheus_line!(
        &mut body,
        "ipars_control_plane_service_hosts{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.active_service_host_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_service_endpoints Independent active service hosts with distinct endpoints by public service kind."
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
            ControlPlaneError::NodeRequestReplay(_)
            | ControlPlaneError::ClusterPolicyChanged
            | ControlPlaneError::OverlayRouteCatalogChanged
            | ControlPlaneError::NodeStateChanged(_)
            | ControlPlaneError::KeycloakCandidateGenerationConflict { .. } => StatusCode::CONFLICT,
            ControlPlaneError::NodeRequestAuthenticationCapacity => StatusCode::SERVICE_UNAVAILABLE,
            ControlPlaneError::TokenVerification(_) => StatusCode::UNAUTHORIZED,
            ControlPlaneError::NodeAlreadyExists(_)
            | ControlPlaneError::VpnIpAlreadyAllocated(_) => StatusCode::CONFLICT,
            ControlPlaneError::NodeUpdateRejected { .. }
            | ControlPlaneError::NodeRegistrationRejected { .. } => StatusCode::FORBIDDEN,
            ControlPlaneError::NodeNotFound(_)
            | ControlPlaneError::PathNotFound { .. }
            | ControlPlaneError::OverlayDestinationNotFound(_)
            | ControlPlaneError::OverlayPathUnavailable { .. } => StatusCode::NOT_FOUND,
            ControlPlaneError::InvalidClusterPolicy(_) => StatusCode::BAD_REQUEST,
            ControlPlaneError::VpnPoolExhausted
            | ControlPlaneError::BoundedTopology(_)
            | ControlPlaneError::Store(_) => StatusCode::SERVICE_UNAVAILABLE,
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
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Write as _;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::process::Stdio;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        ControlPlanePathsResponse, ControlPlanePolicyResponse, ControlPlaneTopologyEdgeStatus,
        HeartbeatRequest, HeartbeatResponse, JoinClientRequest, JoinNodeRequest,
        RegisterClientRequest, RegisterClientResponse, RegisterNodeRequest, RegisterNodeResponse,
        RemoveClientResponse, RemoveNodeRequest, RemoveNodeResponse, RevokeTokenRequest,
        RevokeTokenResponse, RotateWireGuardKeyRequest, RotateWireGuardKeyResponse,
        SignalNodeAuthenticationResponse, SignalNodeUpsertRequest,
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
    const RELAY_ADMISSION_BEARER_TOKEN: &str = "control-plane-test-relay-admission-token-32-bytes";
    const DATABASE_AUTOPILOT_BEARER_TOKEN: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const KEYCLOAK_AUTOPILOT_BEARER_TOKEN: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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
        assert!(WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "http://console.heteronetwork.internal:18079/realms/heteronetwork".to_string(),
            "heteronetwork-web".to_string(),
            None,
            None,
            "openid".to_string(),
        )
        .is_ok());
        assert!(WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "http://idp.heteronetwork.internal:18079/realms/heteronetwork".to_string(),
            "heteronetwork-web".to_string(),
            None,
            None,
            "openid".to_string(),
        )
        .is_err());
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

    #[test]
    fn managed_keycloak_issuer_is_rewritten_to_the_private_overlay() {
        assert_eq!(
            managed_keycloak_overlay_issuer_url("https://203.0.113.10/realms/heteronetwork/")
                .as_deref(),
            Some("http://console.heteronetwork.internal:18079/realms/heteronetwork")
        );
        assert_eq!(
            managed_keycloak_overlay_issuer_url(
                "http://console.heteronetwork.internal:18079/realms/heteronetwork"
            )
            .as_deref(),
            Some("http://console.heteronetwork.internal:18079/realms/heteronetwork")
        );
        assert!(managed_keycloak_overlay_issuer_url("https://idp.example/not-a-realm").is_none());
        assert!(
            managed_keycloak_overlay_issuer_url("https://idp.example/realms/a/nested").is_none()
        );
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

    #[tokio::test]
    async fn oidc_validation_distinguishes_rejection_from_provider_outage(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let app = Router::new().route(
                "/realms/heteronetwork/protocol/openid-connect/userinfo",
                get(|headers: HeaderMap| async move {
                    if headers
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        == Some("Bearer rejected-token")
                    {
                        StatusCode::UNAUTHORIZED
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                }),
            );
            let _ = axum::serve(listener, app).await;
        });
        let config = WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "https://issuer.example/realms/heteronetwork".to_string(),
            "heteronetwork-web".to_string(),
            None,
            Some(format!("http://{address}/realms/heteronetwork")),
            "openid".to_string(),
        )?;

        assert_eq!(
            config.access_token_validation("rejected-token").await,
            AccessTokenValidation::Invalid
        );
        assert_eq!(
            config.access_token_validation("outage-token").await,
            AccessTokenValidation::Unavailable
        );

        let auth = Arc::new(ManagementAuth {
            operator_api_bearer_token: None,
            web_ui_auth: Some(Arc::new(config)),
        });
        let app = Router::new()
            .route("/", get(|| async { StatusCode::OK }))
            .route_layer(middleware::from_fn_with_state(
                auth,
                require_management_auth,
            ));
        let unavailable = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::AUTHORIZATION, "Bearer outage-token")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            unavailable.headers().get(header::RETRY_AFTER),
            Some(&header::HeaderValue::from_static("5"))
        );
        assert!(unavailable
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .is_none());

        let rejected = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::AUTHORIZATION, "Bearer rejected-token")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.headers().get(header::WWW_AUTHENTICATE),
            Some(&header::HeaderValue::from_static("Bearer"))
        );
        task.abort();
        Ok(())
    }

    #[test]
    fn dynamic_web_gateway_oidc_probe_accepts_only_gateway_or_configured_issuer() {
        let authenticated = serde_json::json!({
            "auth_enabled": true,
            "provider": "keycloak",
            "issuer_url": "https://203.0.113.10/realms/heteronetwork/"
        });
        assert_eq!(
            dynamic_web_gateway_oidc_discovery(&authenticated, "https://203.0.113.10", None),
            Ok(Some((
                "https://203.0.113.10/realms/heteronetwork".to_string(),
                "https://203.0.113.10/realms/heteronetwork/.well-known/openid-configuration"
                    .to_string(),
            )))
        );

        let foreign_issuer = serde_json::json!({
            "auth_enabled": true,
            "provider": "keycloak",
            "issuer_url": "https://idp.example/realms/heteronetwork"
        });
        assert_eq!(
            dynamic_web_gateway_oidc_discovery(
                &foreign_issuer,
                "https://203.0.113.10",
                Some("https://idp.example/realms/heteronetwork"),
            ),
            Ok(Some((
                "https://idp.example/realms/heteronetwork".to_string(),
                "https://idp.example/realms/heteronetwork/.well-known/openid-configuration"
                    .to_string(),
            )))
        );
        assert!(dynamic_web_gateway_oidc_discovery(
            &foreign_issuer,
            "https://203.0.113.10",
            Some("https://other-idp.example/realms/heteronetwork"),
        )
        .is_err());

        let unauthenticated = serde_json::json!({"auth_enabled": false});
        assert_eq!(
            dynamic_web_gateway_oidc_discovery(&unauthenticated, "https://203.0.113.10", None,),
            Ok(None)
        );

        let external_provider = serde_json::json!({
            "auth_enabled": true,
            "provider": "cognito",
            "issuer_url": "https://cognito-idp.example/pool"
        });
        assert_eq!(
            dynamic_web_gateway_oidc_discovery(&external_provider, "https://203.0.113.10", None,),
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
        assert_eq!(
            config
                .public_config("cluster-a".to_string())
                .session_refresh_endpoint
                .as_deref(),
            Some("/ui/auth/refresh")
        );
        assert_eq!(
            config
                .public_config("cluster-a".to_string())
                .session_logout_endpoint
                .as_deref(),
            Some("/ui/auth/logout")
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
        let html = oidc_callback_html("access-token", 300);
        assert!(html.contains("sessionStorage.setItem(\"heteronetwork_access_token\""));
        assert!(html.contains(
            "sessionStorage.setItem(\"heteronetwork_access_token_expires_at\",String(Date.now()+300*1000))"
        ));
        assert!(!html.contains("refresh-token"));
        assert!(!html.contains("ipars_access_token"));
    }

    #[test]
    fn web_oidc_refresh_cookie_is_bounded_encoded_and_secure() {
        let cookie = web_oidc_refresh_cookie(
            "refresh-token-value",
            Some(MAX_WEB_OIDC_SESSION_SECONDS + 1),
            true,
        )
        .unwrap_or_else(|error| panic!("refresh cookie should be valid: {}", error.message));
        let cookie = cookie
            .to_str()
            .unwrap_or_else(|error| panic!("refresh cookie should be ASCII: {error}"));
        assert!(cookie.starts_with("heteronetwork_web_refresh="));
        assert!(cookie.contains("; Path=/ui/auth"));
        assert!(cookie.contains(&format!("; Max-Age={MAX_WEB_OIDC_SESSION_SECONDS}")));
        assert!(cookie.contains("; HttpOnly; SameSite=Strict; Secure"));
        assert!(!cookie.contains("refresh-token-value"));
        assert!(cookie.len() <= MAX_WEB_OIDC_REFRESH_COOKIE_BYTES);

        let mut headers = HeaderMap::new();
        let cookie_pair = cookie
            .split(';')
            .next()
            .unwrap_or_else(|| panic!("refresh cookie should contain a name-value pair"));
        headers.insert(
            header::COOKIE,
            header::HeaderValue::from_str(cookie_pair)
                .unwrap_or_else(|error| panic!("cookie pair should be a valid header: {error}")),
        );
        assert_eq!(
            web_oidc_refresh_token(&headers).as_deref(),
            Some("refresh-token-value")
        );

        let non_expiring = web_oidc_refresh_cookie("refresh-token-value", Some(0), true)
            .unwrap_or_else(|error| {
                panic!(
                    "non-expiring provider token should receive the local cap: {}",
                    error.message
                )
            });
        assert!(non_expiring
            .to_str()
            .is_ok_and(|cookie| cookie.contains(&format!(
                "; Max-Age={DEFAULT_WEB_OIDC_REFRESH_COOKIE_SECONDS}"
            ))));
        let missing_expiry = web_oidc_refresh_cookie("refresh-token-value", None, true)
            .unwrap_or_else(|error| {
                panic!(
                    "a provider without refresh_expires_in should receive a bounded fallback: {}",
                    error.message
                )
            });
        assert!(missing_expiry
            .to_str()
            .is_ok_and(|cookie| cookie.contains(&format!(
                "; Max-Age={DEFAULT_WEB_OIDC_REFRESH_COOKIE_SECONDS}"
            ))));

        assert!(web_oidc_url_is_secure("HTTPS://console.example"));
        assert!(web_oidc_url_is_secure("https://console.example"));
        assert!(!web_oidc_url_is_secure("http://console.example"));
        assert!(!web_oidc_url_is_secure("not a URL"));
    }

    #[test]
    fn web_oidc_session_mutations_require_exact_browser_origin() {
        let auth = WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "https://issuer.example/realms/heteronetwork".to_string(),
            "heteronetwork-web".to_string(),
            None,
            None,
            "openid".to_string(),
        )
        .and_then(|config| config.with_public_url("https://console.example".to_string()))
        .unwrap_or_else(|error| panic!("server-side OIDC config should be valid: {error}"));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            header::HeaderValue::from_static("https://console.example"),
        );
        headers.insert(
            header::HeaderName::from_static("sec-fetch-site"),
            header::HeaderValue::from_static("same-origin"),
        );
        assert!(validate_web_oidc_session_request(&auth, &headers).is_ok());

        headers.insert(
            header::ORIGIN,
            header::HeaderValue::from_static("https://attacker.example"),
        );
        let error = match validate_web_oidc_session_request(&auth, &headers) {
            Ok(()) => panic!("a foreign Origin must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.status, StatusCode::FORBIDDEN);

        headers.insert(
            header::ORIGIN,
            header::HeaderValue::from_static("https://console.example"),
        );
        headers.remove(header::HeaderName::from_static("sec-fetch-site"));
        let error = match validate_web_oidc_session_request(&auth, &headers) {
            Ok(()) => panic!("a non-browser mutation without fetch metadata must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn web_oidc_refresh_fails_over_rotates_without_calling_userinfo(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let token_path = "/realms/heteronetwork/protocol/openid-connect/token";
        let userinfo_path = "/realms/heteronetwork/protocol/openid-connect/userinfo";
        let primary_token_calls = Arc::new(AtomicUsize::new(0));
        let primary_listener =
            tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let primary_address = primary_listener.local_addr()?;
        let primary_calls = primary_token_calls.clone();
        let primary_task = tokio::spawn(async move {
            let app = Router::new().route(
                token_path,
                post(move || {
                    let calls = primary_calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                }),
            );
            let _ = axum::serve(primary_listener, app).await;
        });

        let fallback_token_calls = Arc::new(AtomicUsize::new(0));
        let fallback_userinfo_calls = Arc::new(AtomicUsize::new(0));
        let fallback_listener =
            tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let fallback_address = fallback_listener.local_addr()?;
        let token_calls = fallback_token_calls.clone();
        let userinfo_calls = fallback_userinfo_calls.clone();
        let fallback_task = tokio::spawn(async move {
            let token_app = post(
                move |axum::extract::Form(form): axum::extract::Form<BTreeMap<String, String>>| {
                    let calls = token_calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        if form.get("grant_type").map(String::as_str) != Some("refresh_token")
                            || form.get("client_id").map(String::as_str)
                                != Some("heteronetwork-web")
                        {
                            return StatusCode::BAD_REQUEST.into_response();
                        }
                        let rejected_error = match form.get("refresh_token").map(String::as_str) {
                            Some("invalid-grant-refresh-token") => Some("invalid_grant"),
                            Some("invalid-token-refresh-token") => Some("invalid_token"),
                            Some("expired-token-refresh-token") => Some("expired_token"),
                            _ => None,
                        };
                        if let Some(rejected_error) = rejected_error {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({"error": rejected_error})),
                            )
                                .into_response();
                        }
                        Json(serde_json::json!({
                            "access_token": "refreshed-access-token",
                            "refresh_token": "rotated-refresh-token",
                            "expires_in": 300,
                            "refresh_expires_in": 3600
                        }))
                        .into_response()
                    }
                },
            );
            let userinfo_app = get(move || {
                let calls = userinfo_calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    StatusCode::SERVICE_UNAVAILABLE
                }
            });
            let app = Router::new()
                .route(token_path, token_app)
                .route(userinfo_path, userinfo_app);
            let _ = axum::serve(fallback_listener, app).await;
        });

        let auth = WebUiAuthConfig::new(
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

        let refreshed = auth
            .refresh_session("refresh-token")
            .await
            .map_err(|error| {
                format!(
                    "refresh should fail over successfully: {}",
                    error.error.message
                )
            })?;
        assert_eq!(refreshed.access_token, "refreshed-access-token");
        assert_eq!(
            refreshed.refresh_token.as_deref(),
            Some("rotated-refresh-token")
        );
        assert_eq!(refreshed.refresh_expires_in, Some(3600));

        for refresh_token in [
            "invalid-grant-refresh-token",
            "invalid-token-refresh-token",
            "expired-token-refresh-token",
        ] {
            let rejected = match auth.refresh_session(refresh_token).await {
                Ok(_) => panic!("{refresh_token} must reject the browser session"),
                Err(error) => error,
            };
            assert_eq!(rejected.error.status, StatusCode::UNAUTHORIZED);
            assert!(rejected.clear_cookie);
        }
        assert_eq!(primary_token_calls.load(Ordering::SeqCst), 4);
        assert_eq!(fallback_token_calls.load(Ordering::SeqCst), 4);
        assert_eq!(fallback_userinfo_calls.load(Ordering::SeqCst), 0);

        primary_task.abort();
        fallback_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn web_oidc_refresh_coalesces_cloned_config_requests_and_replays_success(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let token_path = "/realms/heteronetwork/protocol/openid-connect/token";
        let token_calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let address = listener.local_addr()?;
        let calls = token_calls.clone();
        let server_task = tokio::spawn(async move {
            let app = Router::new().route(
                token_path,
                post(
                    move |axum::extract::Form(form): axum::extract::Form<
                        BTreeMap<String, String>,
                    >| {
                        let calls = calls.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(75)).await;
                            if form.get("refresh_token").map(String::as_str)
                                != Some("shared-refresh-token")
                            {
                                return StatusCode::BAD_REQUEST.into_response();
                            }
                            Json(serde_json::json!({
                                "access_token": "coalesced-access-token",
                                "refresh_token": "coalesced-rotated-token",
                                "expires_in": 300,
                                "refresh_expires_in": 3600
                            }))
                            .into_response()
                        }
                    },
                ),
            );
            let _ = axum::serve(listener, app).await;
        });

        let auth = WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "https://issuer.example/realms/heteronetwork".to_string(),
            "heteronetwork-web".to_string(),
            None,
            Some(format!("http://{address}/realms/heteronetwork")),
            "openid".to_string(),
        )?;
        let cloned_auth = auth.clone();
        let (first, second) = tokio::join!(
            auth.refresh_session("shared-refresh-token"),
            cloned_auth.refresh_session("shared-refresh-token")
        );
        let first = first.map_err(|error| error.error.message)?;
        let second = second.map_err(|error| error.error.message)?;
        assert_eq!(first.access_token, "coalesced-access-token");
        assert_eq!(second.access_token, first.access_token);
        assert_eq!(second.refresh_token, first.refresh_token);
        assert_eq!(token_calls.load(Ordering::SeqCst), 1);

        let replayed = cloned_auth
            .refresh_session("shared-refresh-token")
            .await
            .map_err(|error| error.error.message)?;
        assert_eq!(replayed.access_token, first.access_token);
        assert_eq!(replayed.refresh_token, first.refresh_token);
        assert_eq!(token_calls.load(Ordering::SeqCst), 1);
        assert_eq!(auth.refresh_cache.lock().await.entries.len(), 1);

        auth.invalidate_refresh_session("coalesced-rotated-token")
            .await;
        let stale_replay = match auth.refresh_session("shared-refresh-token").await {
            Ok(_) => panic!("logout with the rotated token must revoke the predecessor replay"),
            Err(error) => error,
        };
        assert!(stale_replay.clear_cookie);
        assert_eq!(token_calls.load(Ordering::SeqCst), 1);

        server_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn web_oidc_logout_rejects_an_in_flight_refresh() -> Result<(), Box<dyn std::error::Error>>
    {
        let token_path = "/realms/heteronetwork/protocol/openid-connect/token";
        let token_calls = Arc::new(AtomicUsize::new(0));
        let refresh_started = Arc::new(tokio::sync::Notify::new());
        let release_refresh = Arc::new(tokio::sync::Notify::new());
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let address = listener.local_addr()?;
        let calls = token_calls.clone();
        let started = refresh_started.clone();
        let release = release_refresh.clone();
        let server_task = tokio::spawn(async move {
            let app = Router::new().route(
                token_path,
                post(move || {
                    let calls = calls.clone();
                    let started = started.clone();
                    let release = release.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        started.notify_one();
                        release.notified().await;
                        Json(serde_json::json!({
                            "access_token": "late-access-token",
                            "refresh_token": "late-rotated-token",
                            "expires_in": 300,
                            "refresh_expires_in": 3600
                        }))
                    }
                }),
            );
            let _ = axum::serve(listener, app).await;
        });

        let auth = WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "https://issuer.example/realms/heteronetwork".to_string(),
            "heteronetwork-web".to_string(),
            None,
            Some(format!("http://{address}/realms/heteronetwork")),
            "openid".to_string(),
        )?;
        let refresh_auth = auth.clone();
        let refresh_task = tokio::spawn(async move {
            refresh_auth
                .refresh_session("logout-race-refresh-token")
                .await
        });
        refresh_started.notified().await;
        auth.invalidate_refresh_session("logout-race-refresh-token")
            .await;
        release_refresh.notify_one();

        let error = match refresh_task.await? {
            Ok(_) => panic!("logout must reject an in-flight refresh result"),
            Err(error) => error,
        };
        assert!(error.clear_cookie);
        assert_eq!(error.error.status, StatusCode::UNAUTHORIZED);
        let replay = match auth.refresh_session("logout-race-refresh-token").await {
            Ok(_) => panic!("logout tombstone must reject a replay"),
            Err(error) => error,
        };
        assert!(replay.clear_cookie);
        assert_eq!(token_calls.load(Ordering::SeqCst), 1);

        server_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn web_oidc_refresh_preserves_cookie_for_transient_provider_failures(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let token_path = "/realms/heteronetwork/protocol/openid-connect/token";
        let token_calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let address = listener.local_addr()?;
        let calls = token_calls.clone();
        let server_task = tokio::spawn(async move {
            let app = Router::new().route(
                token_path,
                post(
                    move |axum::extract::Form(form): axum::extract::Form<
                        BTreeMap<String, String>,
                    >| {
                        let calls = calls.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            match form.get("refresh_token").map(String::as_str) {
                                Some("invalid-client") => (
                                    StatusCode::UNAUTHORIZED,
                                    Json(serde_json::json!({"error": "invalid_client"})),
                                )
                                    .into_response(),
                                Some("generic-unauthorized") => {
                                    StatusCode::UNAUTHORIZED.into_response()
                                }
                                Some("generic-forbidden") => StatusCode::FORBIDDEN.into_response(),
                                Some("server-error") => {
                                    StatusCode::SERVICE_UNAVAILABLE.into_response()
                                }
                                _ => StatusCode::BAD_REQUEST.into_response(),
                            }
                        }
                    },
                ),
            );
            let _ = axum::serve(listener, app).await;
        });

        let auth = WebUiAuthConfig::new(
            WebAuthProvider::Keycloak,
            "https://issuer.example/realms/heteronetwork".to_string(),
            "heteronetwork-web".to_string(),
            None,
            Some(format!("http://{address}/realms/heteronetwork")),
            "openid".to_string(),
        )?;
        for refresh_token in [
            "invalid-client",
            "generic-unauthorized",
            "generic-forbidden",
            "server-error",
        ] {
            let error = match auth.refresh_session(refresh_token).await {
                Ok(_) => panic!("{refresh_token} must not produce a successful refresh"),
                Err(error) => error,
            };
            assert!(
                !error.clear_cookie,
                "{refresh_token} must preserve the refresh cookie"
            );
            assert_ne!(error.error.status, StatusCode::UNAUTHORIZED);
        }
        assert_eq!(token_calls.load(Ordering::SeqCst), 4);

        server_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn web_oidc_refresh_fails_over_after_rate_limit() -> Result<(), Box<dyn std::error::Error>>
    {
        let token_path = "/realms/heteronetwork/protocol/openid-connect/token";
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let primary_listener =
            tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let primary_address = primary_listener.local_addr()?;
        let calls = primary_calls.clone();
        let primary_task = tokio::spawn(async move {
            let app = Router::new().route(
                token_path,
                post(move || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        StatusCode::TOO_MANY_REQUESTS
                    }
                }),
            );
            let _ = axum::serve(primary_listener, app).await;
        });

        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let fallback_listener =
            tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let fallback_address = fallback_listener.local_addr()?;
        let calls = fallback_calls.clone();
        let fallback_task = tokio::spawn(async move {
            let app = Router::new().route(
                token_path,
                post(move || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({
                            "access_token": "fallback-access-token",
                            "refresh_token": "fallback-rotated-token",
                            "expires_in": 300
                        }))
                    }
                }),
            );
            let _ = axum::serve(fallback_listener, app).await;
        });

        let auth = WebUiAuthConfig::new(
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
        let refreshed = auth
            .refresh_session("rate-limited-refresh-token")
            .await
            .map_err(|error| error.error.message)?;
        assert_eq!(refreshed.access_token, "fallback-access-token");
        assert_eq!(
            refreshed.refresh_token.as_deref(),
            Some("fallback-rotated-token")
        );
        assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);

        primary_task.abort();
        fallback_task.abort();
        Ok(())
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
        let owner_node_id = node_id(instance_id);
        ServiceInstance {
            cluster_id: cluster_id.clone(),
            instance_id: instance_id.to_string(),
            owner_host_id: owner_node_id.to_string(),
            owner_node_id: Some(owner_node_id),
            enrollment_signer: true,
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
                BootstrapEndpoint {
                    kind: BootstrapEndpointKind::WebUi,
                    url: format!("https://{host}:8443"),
                },
            ],
            lease_expires_at: now + chrono::Duration::minutes(5),
            updated_at: now,
        }
    }

    #[test]
    fn node_enrollment_bootstrap_uses_gateways_without_mutating_service_directory(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let service_endpoints = vec![
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "http://10.250.0.4:19088".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "https://direct-control.example:8443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Signal,
                url: "http://10.250.0.4:19443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Stun,
                url: "udp://203.0.113.10:19444".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Relay,
                url: "udp://203.0.113.10:18445".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::WebUi,
                url: "https://gateway.example".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::WebUi,
                url: "http://10.250.0.4:18088".to_string(),
            },
        ];
        let enrollment_endpoints = node_enrollment_bootstrap_endpoints(
            "https://enroll.example",
            &service_endpoints,
            &Ipv4Net::new(Ipv4Addr::new(10, 250, 0, 0), 16)?,
        )
        .map_err(|error| error.message)?;

        let enrollment_control_planes = enrollment_endpoints
            .iter()
            .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
            .map(|endpoint| endpoint.url.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            enrollment_control_planes,
            vec!["https://enroll.example", "https://gateway.example"]
        );
        assert!(enrollment_endpoints.iter().any(|endpoint| {
            endpoint.kind == BootstrapEndpointKind::Signal
                && endpoint.url == "http://10.250.0.4:19443"
        }));
        assert!(!enrollment_endpoints.iter().any(|endpoint| {
            endpoint.kind == BootstrapEndpointKind::WebUi
                && endpoint.url == "http://10.250.0.4:18088"
        }));
        assert!(service_endpoints.iter().any(|endpoint| {
            endpoint.kind == BootstrapEndpointKind::ControlPlane
                && endpoint.url == "http://10.250.0.4:19088"
        }));
        Ok(())
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
            binary_path.clone(),
            3600,
            RELAY_ADMISSION_BEARER_TOKEN.to_string(),
        )?;
        let endpoints = vec![
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "https://static.example".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "https://control.example:8443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "http://10.250.0.4:19088".to_string(),
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
                "https://203.0.113.10".to_string(),
            ]
        );
        drop(enrollment);
        std::fs::remove_file(binary_path)?;
        Ok(())
    }

    #[test]
    fn database_autopilot_registry_is_bounded_and_rotates_large_candidate_sets(
    ) -> Result<(), ControlPlaneError> {
        let identities = (0..1_000)
            .map(|index| node_id(&format!("database-candidate-{index:04}")))
            .collect::<Vec<_>>();
        let nodes = identities
            .iter()
            .enumerate()
            .map(|(index, node_id)| DatabaseAutopilotRegistryNode {
                node_id: node_id.to_string(),
                vpn_ip: format!("10.250.{}.{}", index / 250, index % 250 + 1),
                role: "worker".to_string(),
                active: index != 999,
            })
            .collect::<Vec<_>>();
        let mut active_node_ids = identities[..999].to_vec();
        active_node_ids.sort();
        let snapshot = DatabaseAutopilotRegistrySnapshot {
            loaded_at: Instant::now(),
            health_ttl: Duration::from_secs(30),
            generated_at: Utc::now(),
            nodes_by_id: identities.iter().cloned().zip(nodes).collect(),
            active_node_ids,
        };
        let members = vec![identities[999].clone()];
        let first = select_database_autopilot_registry_nodes(&snapshot, &members, 0)?;
        let second = select_database_autopilot_registry_nodes(&snapshot, &members, 1)?;
        assert_eq!(first.len(), MAX_DATABASE_AUTOPILOT_CANDIDATES);
        assert_eq!(second.len(), MAX_DATABASE_AUTOPILOT_CANDIDATES);
        assert_eq!(first[0].node_id, identities[999].as_str());
        assert!(!first[0].active);
        assert_eq!(second[0].node_id, identities[999].as_str());
        assert_ne!(
            first
                .iter()
                .map(|node| node.node_id.as_str())
                .collect::<BTreeSet<_>>(),
            second
                .iter()
                .map(|node| node.node_id.as_str())
                .collect::<BTreeSet<_>>()
        );

        let active_members = snapshot.active_node_ids[..MAX_DATABASE_AUTOPILOT_MEMBER_IDS].to_vec();
        let active_member_first =
            select_database_autopilot_registry_nodes(&snapshot, &active_members, 0)?;
        let active_member_second =
            select_database_autopilot_registry_nodes(&snapshot, &active_members, 1)?;
        assert_eq!(
            active_member_first[..MAX_DATABASE_AUTOPILOT_MEMBER_IDS]
                .iter()
                .map(|node| node.node_id.as_str())
                .collect::<Vec<_>>(),
            active_members
                .iter()
                .map(NodeId::as_str)
                .collect::<Vec<_>>()
        );
        assert_ne!(
            active_member_first
                .iter()
                .skip(MAX_DATABASE_AUTOPILOT_MEMBER_IDS)
                .map(|node| node.node_id.as_str())
                .collect::<BTreeSet<_>>(),
            active_member_second
                .iter()
                .skip(MAX_DATABASE_AUTOPILOT_MEMBER_IDS)
                .map(|node| node.node_id.as_str())
                .collect::<BTreeSet<_>>()
        );
        Ok(())
    }

    #[test]
    fn explicit_autopilot_bearer_builders_require_lowercase_sha256_hex(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(InMemoryStore::default());
        let plane = Arc::new(ControlPlane::new(
            ControlPlaneConfig::new(
                ClusterId::from_string("cluster-autopilot-auth"),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store,
        ));
        let join_service = Arc::new(ControlPlaneJoinService::new(
            plane.clone(),
            Arc::new(InMemoryTokenLedger::default()),
            IssuerKeyRing::default(),
        ));
        let state = ControlPlaneHttpState::new(plane, join_service);

        assert!(state
            .clone()
            .require_database_autopilot_bearer_token(DATABASE_AUTOPILOT_BEARER_TOKEN.to_string())
            .is_ok());
        assert!(state
            .clone()
            .require_keycloak_autopilot_bearer_token(KEYCLOAK_AUTOPILOT_BEARER_TOKEN.to_string())
            .is_ok());
        for invalid in [
            "a".repeat(AUTOPILOT_API_BEARER_TOKEN_HEX_BYTES - 1),
            "a".repeat(AUTOPILOT_API_BEARER_TOKEN_HEX_BYTES + 1),
            format!("{}A", "a".repeat(AUTOPILOT_API_BEARER_TOKEN_HEX_BYTES - 1)),
            format!("{}g", "a".repeat(AUTOPILOT_API_BEARER_TOKEN_HEX_BYTES - 1)),
        ] {
            assert!(state
                .clone()
                .require_database_autopilot_bearer_token(invalid.clone())
                .is_err());
            assert!(state
                .clone()
                .require_keycloak_autopilot_bearer_token(invalid)
                .is_err());
        }
        Ok(())
    }

    #[test]
    fn keycloak_node_bearer_derivation_is_stable_and_identity_bound() {
        let cluster_id = ClusterId::from_string("cluster-a");
        let node_a = NodeId::from_string("node-a");
        let node_b = NodeId::from_string("node-b");
        assert_eq!(
            derive_keycloak_node_bearer("base-secret", &cluster_id, &node_a),
            "4419de1b821a1e4f6b651995ec5268f59104c394b79eb544ed7fbca04b48bde1"
        );
        assert_ne!(
            derive_keycloak_node_bearer("base-secret", &cluster_id, &node_a),
            derive_keycloak_node_bearer("base-secret", &cluster_id, &node_b)
        );
    }

    #[tokio::test]
    async fn explicit_autopilot_bearers_work_without_node_enrollment(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("root");
        let cluster_id = ClusterId::from_string("cluster-explicit-autopilot-auth");
        let store = Arc::new(InMemoryStore::default());
        let plane = Arc::new(ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store.clone(),
        ));
        let node = plane
            .register_with_claims(
                claims(cluster_id.clone(), issuer.node_id(), key_id),
                registration("explicit-autopilot-node"),
            )
            .await?
            .node;
        let other_node = plane
            .register_with_claims(
                claims(
                    cluster_id.clone(),
                    issuer.node_id(),
                    KeyId::from_string("root"),
                ),
                registration("explicit-autopilot-other-node"),
            )
            .await?
            .node;
        store
            .upsert_health(
                node.node_id.clone(),
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now(),
                    latency_ms: Some(1.0),
                    relay_load: Some(0.0),
                    message: None,
                },
            )
            .await?;
        store
            .upsert_health(
                other_node.node_id.clone(),
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now(),
                    latency_ms: Some(1.0),
                    relay_load: Some(0.0),
                    message: None,
                },
            )
            .await?;
        let join_service = Arc::new(ControlPlaneJoinService::new(
            plane.clone(),
            Arc::new(InMemoryTokenLedger::default()),
            IssuerKeyRing::default(),
        ));
        let state = ControlPlaneHttpState::new(plane, join_service)
            .require_database_autopilot_bearer_token(DATABASE_AUTOPILOT_BEARER_TOKEN.to_string())
            .map_err(std::io::Error::other)?
            .require_keycloak_autopilot_bearer_token(KEYCLOAK_AUTOPILOT_BEARER_TOKEN.to_string())
            .map_err(std::io::Error::other)?;
        assert!(state.node_enrollment.is_none());
        let app = router(state);
        let keycloak_node_bearer = derive_keycloak_node_bearer(
            KEYCLOAK_AUTOPILOT_BEARER_TOKEN,
            &cluster_id,
            &node.node_id,
        );

        let database_request = serde_json::to_vec(&serde_json::json!({
            "selection_epoch": 1,
            "member_node_ids": [node.node_id.as_str()]
        }))?;
        for (authorization, expected_status) in [
            (None, StatusCode::UNAUTHORIZED),
            (
                Some(keycloak_node_bearer.as_str()),
                StatusCode::UNAUTHORIZED,
            ),
            (Some(DATABASE_AUTOPILOT_BEARER_TOKEN), StatusCode::OK),
        ] {
            let mut request = Request::builder()
                .method("POST")
                .uri("/v1/database-autopilot/nodes")
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(token) = authorization {
                request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from(database_request.clone()))?)
                .await?;
            assert_eq!(response.status(), expected_status);
        }

        let keycloak_request = serde_json::to_vec(&serde_json::json!({
            "node_id": node.node_id.as_str(),
            "vpn_ip": node.vpn_ip.to_string(),
            "eligible": true,
            "ready": false,
            "version": KEYCLOAK_AUTOPILOT_VERSION,
            "generation": 1
        }))?;
        for (authorization, expected_status) in [
            (None, StatusCode::UNAUTHORIZED),
            (
                Some(DATABASE_AUTOPILOT_BEARER_TOKEN),
                StatusCode::UNAUTHORIZED,
            ),
            (
                Some(KEYCLOAK_AUTOPILOT_BEARER_TOKEN),
                StatusCode::UNAUTHORIZED,
            ),
            (Some(keycloak_node_bearer.as_str()), StatusCode::OK),
        ] {
            let mut request = Request::builder()
                .method("POST")
                .uri("/v1/keycloak-autopilot/reconcile")
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(token) = authorization {
                request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from(keycloak_request.clone()))?)
                .await?;
            assert_eq!(response.status(), expected_status);
        }
        let withdrawal = serde_json::to_vec(&serde_json::json!({
            "node_id": node.node_id.as_str(),
            "vpn_ip": node.vpn_ip.to_string(),
            "eligible": false,
            "ready": false,
            "version": KEYCLOAK_AUTOPILOT_VERSION,
            "generation": 2
        }))?;
        let withdrawal_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/keycloak-autopilot/reconcile")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {keycloak_node_bearer}"),
                    )
                    .body(Body::from(withdrawal))?,
            )
            .await?;
        assert_eq!(withdrawal_response.status(), StatusCode::OK);
        let withdrawal_response =
            axum::body::to_bytes(withdrawal_response.into_body(), usize::MAX).await?;
        let withdrawal_response: Value = serde_json::from_slice(&withdrawal_response)?;
        assert_eq!(withdrawal_response["generation"], 2);

        let delayed_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/keycloak-autopilot/reconcile")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {keycloak_node_bearer}"),
                    )
                    .body(Body::from(keycloak_request))?,
            )
            .await?;
        assert_eq!(delayed_response.status(), StatusCode::CONFLICT);

        let cross_node_request = serde_json::to_vec(&serde_json::json!({
            "node_id": other_node.node_id.as_str(),
            "vpn_ip": other_node.vpn_ip.to_string(),
            "eligible": true,
            "ready": false,
            "version": KEYCLOAK_AUTOPILOT_VERSION,
            "generation": 1
        }))?;
        let cross_node_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/keycloak-autopilot/reconcile")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {keycloak_node_bearer}"),
                    )
                    .body(Body::from(cross_node_request))?,
            )
            .await?;
        assert_eq!(cross_node_response.status(), StatusCode::UNAUTHORIZED);
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
            store.clone(),
        ));
        for (index, (instance_id, host)) in [
            ("public-a", "public-a.example"),
            ("public-b", "public-b.example"),
        ]
        .into_iter()
        .enumerate()
        {
            let public_addr =
                SocketAddr::from(([8, 8, 4, 20 + u8::try_from(index).unwrap_or(0)], 51_820));
            let assessed_at = Utc::now();
            let classification = NatClassification::from_observations(
                public_addr,
                vec![NatProbeObservation {
                    local_addr: public_addr,
                    stun_server: SocketAddr::from(([1, 1, 1, 1], 3478)),
                    reflexive_addr: public_addr,
                    observed_at: assessed_at,
                }],
                assessed_at,
            );
            let mut service_registration = registration(instance_id);
            service_registration.candidates = vec![EndpointCandidate {
                node_id: node_id(instance_id),
                kind: EndpointCandidateKind::PublicUdp,
                addr: public_addr,
                observed_at: assessed_at,
                priority: 100,
                cost: 10,
                source: CandidateSource::StunProbe,
            }];
            service_registration.nat_classification = Some(classification);
            let mut service_claims = claims(cluster_id.clone(), issuer.node_id(), key_id.clone());
            service_claims.role = Role::from_string("worker");
            let service_node = plane
                .register_with_claims(service_claims, service_registration)
                .await?
                .node;
            store
                .upsert_health(
                    service_node.node_id,
                    NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: assessed_at,
                        latency_ms: Some(1.0),
                        relay_load: Some(0.0),
                        message: None,
                    },
                )
                .await?;
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
        store
            .upsert_health(
                gateway.node_id.clone(),
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now(),
                    latency_ms: Some(1.0),
                    relay_load: Some(0.0),
                    message: None,
                },
            )
            .await?;

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
        let root_issuer = identity_for_node("enrollment-root");
        let trusted_enrollment_signer = format!(
            "{},{},{},{}",
            issuer.node_id(),
            key_id,
            issuer.public_key_b64(),
            7 * 24 * 60 * 60,
        );
        let enrollment = NodeEnrollmentConfig::new(
            issuer,
            key_id.as_str().to_string(),
            "http://127.0.0.1:8443".to_string(),
            binary_path.clone(),
            binary_path.clone(),
            7 * 24 * 60 * 60,
            RELAY_ADMISSION_BEARER_TOKEN.to_string(),
        )?
        .with_public_services(NodePublicServicesConfig {
            vpn_pool: "100.64.0.0/29".to_string(),
            issuer_node_id: root_issuer.node_id().to_string(),
            issuer_key_id: "root".to_string(),
            issuer_public_key: root_issuer.public_key_b64(),
            trusted_issuer_keys: Vec::new(),
            trusted_node_enrollment_issuer_keys: vec![trusted_enrollment_signer.clone()],
            oidc_issuer_url: "https://sso.example/realms/heteronetwork".to_string(),
            oidc_client_id: "heteronetwork-web".to_string(),
            oidc_auth_base_url: None,
            oidc_backchannel_base_url: Some(
                "http://10.250.0.1:8080/realms/heteronetwork".to_string(),
            ),
            oidc_backchannel_fallback_base_urls: vec![
                "https://sso-b.example/realms/heteronetwork".to_string()
            ],
            oidc_scopes: "openid profile email".to_string(),
        });
        let expected_sha256 = enrollment.daemon_binary.sha256.to_string();
        let enrollment_signing_key = enrollment.issuer.signing_key_b64().to_string();
        let database_autopilot_bearer = derive_node_enrollment_cluster_secret(
            &enrollment,
            &cluster_id,
            b"heteronetwork-postgres-ha-autopilot-v1",
        );
        let keycloak_autopilot_bearer = derive_node_enrollment_cluster_secret(
            &enrollment,
            &cluster_id,
            b"heteronetwork-keycloak-autopilot-v1",
        );
        let app = router(
            ControlPlaneHttpState::new(plane.clone(), join_service)
                .require_operator_api_bearer_token(OPERATOR_API_BEARER_TOKEN.to_string())
                .enable_node_enrollment(enrollment),
        );
        let request_body = serde_json::json!({
            "expires_in_seconds": 86_400,
            "role": "edge",
            "tags": ["production", "linux"],
            "reusable": false,
            "max_uses": 1
        });
        let registry_request = serde_json::to_vec(&serde_json::json!({
            "selection_epoch": 7,
            "member_node_ids": [gateway.node_id.as_str()]
        }))?;

        let unauthenticated_registry = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/database-autopilot/nodes")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(registry_request.clone()))?,
            )
            .await?;
        assert_eq!(unauthenticated_registry.status(), StatusCode::UNAUTHORIZED);
        let authenticated_registry = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/database-autopilot/nodes")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {database_autopilot_bearer}"),
                    )
                    .body(Body::from(registry_request))?,
            )
            .await?;
        assert_eq!(authenticated_registry.status(), StatusCode::OK);
        let authenticated_registry =
            axum::body::to_bytes(authenticated_registry.into_body(), usize::MAX).await?;
        let authenticated_registry: Value = serde_json::from_slice(&authenticated_registry)?;
        assert_eq!(authenticated_registry["cluster_id"], cluster_id.as_str());
        assert_eq!(authenticated_registry["vpn_cidr"], "100.64.0.0/29");
        assert_eq!(authenticated_registry["selection_epoch"], 7);
        assert_eq!(
            authenticated_registry["nodes"][0]["node_id"],
            gateway.node_id.as_str()
        );
        assert_eq!(authenticated_registry["nodes"][0]["active"], true);

        let keycloak_request = serde_json::to_vec(&serde_json::json!({
            "node_id": gateway.node_id.as_str(),
            "vpn_ip": gateway.vpn_ip.to_string(),
            "eligible": true,
            "ready": false,
            "version": KEYCLOAK_AUTOPILOT_VERSION,
            "generation": 1
        }))?;
        let keycloak_node_bearer =
            derive_keycloak_node_bearer(&keycloak_autopilot_bearer, &cluster_id, &gateway.node_id);
        let unauthenticated_keycloak = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/keycloak-autopilot/reconcile")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(keycloak_request.clone()))?,
            )
            .await?;
        assert_eq!(unauthenticated_keycloak.status(), StatusCode::UNAUTHORIZED);
        let authenticated_keycloak = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/keycloak-autopilot/reconcile")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {keycloak_node_bearer}"),
                    )
                    .body(Body::from(keycloak_request))?,
            )
            .await?;
        assert_eq!(authenticated_keycloak.status(), StatusCode::OK);
        let authenticated_keycloak =
            axum::body::to_bytes(authenticated_keycloak.into_body(), usize::MAX).await?;
        let authenticated_keycloak: Value = serde_json::from_slice(&authenticated_keycloak)?;
        assert_eq!(authenticated_keycloak["cluster_id"], cluster_id.as_str());
        assert_eq!(
            authenticated_keycloak["desired_replicas"],
            KEYCLOAK_AUTOPILOT_DESIRED_REPLICAS
        );
        assert_eq!(authenticated_keycloak["assigned"], true);
        assert_eq!(authenticated_keycloak["generation"], 1);
        assert_eq!(
            authenticated_keycloak["replicas"][0]["node_id"],
            gateway.node_id.as_str()
        );
        assert_eq!(authenticated_keycloak["replicas"][0]["ready"], false);
        let admin_keycloak = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/keycloak-placement")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(admin_keycloak.status(), StatusCode::OK);
        let admin_keycloak = axum::body::to_bytes(admin_keycloak.into_body(), usize::MAX).await?;
        let admin_keycloak: Value = serde_json::from_slice(&admin_keycloak)?;
        assert_eq!(
            admin_keycloak["placement_id"],
            authenticated_keycloak["placement_id"]
        );
        assert_eq!(
            admin_keycloak["replicas"][0]["node_id"],
            gateway.node_id.as_str()
        );
        assert!(
            plane.metrics().await?.ha_ready,
            "public-service redundancy precondition was not established"
        );
        let gated_metrics = app
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
        assert_eq!(gated_metrics.status(), StatusCode::OK);
        let gated_metrics = axum::body::to_bytes(gated_metrics.into_body(), usize::MAX).await?;
        let gated_metrics: ControlPlaneMetricsResponse = serde_json::from_slice(&gated_metrics)?;
        assert!(
            !gated_metrics.ha_ready,
            "HTTP HA metrics ignored an unready Keycloak placement"
        );

        let too_many_member_ids = (0..=MAX_DATABASE_AUTOPILOT_MEMBER_IDS)
            .map(|index| format!("database-member-{index}"))
            .collect::<Vec<_>>();
        for (request, expected_status) in [
            (
                serde_json::json!({"selection_epoch": 7}),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                serde_json::json!({
                    "selection_epoch": 7,
                    "member_node_id": [gateway.node_id.as_str()]
                }),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                serde_json::json!({
                    "selection_epoch": 7,
                    "member_node_ids": [gateway.node_id.as_str()],
                    "unexpected": true
                }),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                serde_json::json!({
                    "selection_epoch": 7,
                    "member_node_ids": [
                        gateway.node_id.as_str(),
                        gateway.node_id.as_str()
                    ]
                }),
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::json!({
                    "selection_epoch": 7,
                    "member_node_ids": ["missing-database-member"]
                }),
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::json!({
                    "selection_epoch": 7,
                    "member_node_ids": too_many_member_ids
                }),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/database-autopilot/nodes")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(
                            header::AUTHORIZATION,
                            format!("Bearer {database_autopilot_bearer}"),
                        )
                        .body(Body::from(serde_json::to_vec(&request)?))?,
                )
                .await?;
            assert_eq!(response.status(), expected_status, "request: {request}");
        }
        let oversized_registry_request = format!(
            "{{\"selection_epoch\":7,\"member_node_ids\":[],\"padding\":\"{}\"}}",
            "x".repeat(MAX_DATABASE_AUTOPILOT_REQUEST_BYTES)
        );
        let oversized_registry_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/database-autopilot/nodes")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {database_autopilot_bearer}"),
                    )
                    .body(Body::from(oversized_registry_request))?,
            )
            .await?;
        assert_eq!(
            oversized_registry_response.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );

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

        let legacy_relay_toggle = app
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
                    .body(Body::from(
                        r#"{"expires_in_seconds":86400,"allow_relay":true}"#,
                    ))?,
            )
            .await?;
        assert_eq!(
            legacy_relay_toggle.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );

        let enrollment_relay_toggle = app
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
                    .body(Body::from(
                        r#"{"expires_in_seconds":86400,"disable_relay":true}"#,
                    ))?,
            )
            .await?;
        assert_eq!(
            enrollment_relay_toggle.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );

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
        let mut installer_shell = std::process::Command::new("sh")
            .arg("-n")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        installer_shell
            .stdin
            .take()
            .ok_or("node installer shell syntax checker stdin is unavailable")?
            .write_all(generated_script.as_bytes())?;
        let installer_syntax = installer_shell.wait_with_output()?;
        assert!(
            installer_syntax.status.success(),
            "generated node installer is not valid POSIX shell: {}",
            String::from_utf8_lossy(&installer_syntax.stderr)
        );
        for expected_base in [
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
        assert_eq!(token.claims.bootstrap_endpoints.len(), 10);
        assert_eq!(
            token
                .claims
                .bootstrap_endpoints
                .iter()
                .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
                .map(|endpoint| endpoint.url.as_str())
                .collect::<Vec<_>>(),
            vec![
                "https://public-a.example:8443",
                "https://public-b.example:8443",
            ]
        );
        assert_eq!(token.claims.policy.max_token_uses, Some(1));
        assert!(token.claims.policy.allow_relay);
        assert_eq!(response_body["setup"], "network_only");
        assert!(!generated_script.contains("kubeadm-ha-autopilot"));
        assert!(generated_script.contains("heteronetwork-postgres-autopilot.service"));
        assert!(generated_script.contains("postgres-ha-node.sh"));
        assert!(generated_script.contains("postgres-ha-autopilot.sh"));
        assert!(generated_script.contains("HETERONETWORK_DB_CONTROL_PLANE_URLS_B64='"));
        assert!(generated_script.contains("Automatic PostgreSQL HA placement scheduled"));
        assert!(generated_script.contains("heteronetwork-keycloak-prepare.service"));
        assert!(generated_script.contains("heteronetwork-keycloak-autopilot.service"));
        assert!(generated_script.contains("heteronetwork-keycloak-autopilot.timer"));
        assert!(generated_script.contains("keycloak-ha-node.sh"));
        assert!(generated_script.contains("keycloak-autopilot.sh"));
        assert!(generated_script.contains(
            "jq -er '.node_id | select(type == \"string\" and length > 0 and length <= 255)'"
        ));
        assert!(generated_script.contains("heteronetwork-keycloak-autopilot-node-v1"));
        assert!(generated_script
            .contains("printf 'HETERONETWORK_KEYCLOAK_AUTOPILOT_BEARER_TOKEN=%s\\n'"));
        assert!(generated_script.contains("HETERONETWORK_KEYCLOAK_CONTROL_PLANE_URLS_B64='"));
        assert!(generated_script.contains(&format!(
            "HETERONETWORK_KEYCLOAK_VERSION={KEYCLOAK_AUTOPILOT_VERSION}"
        )));
        assert!(generated_script.contains(&format!(
            "HETERONETWORK_KEYCLOAK_ARCHIVE_SHA256={KEYCLOAK_AUTOPILOT_ARCHIVE_SHA256}"
        )));
        assert!(generated_script
            .contains("systemctl restart --no-block heteronetwork-keycloak-prepare.service"));
        assert!(generated_script.contains("Automatic Keycloak HA placement scheduled"));
        assert!(!generated_script.contains(&enrollment_signing_key));
        assert!(generated_script.contains("systemctl restart heteronetwork-gateway.service"));
        assert!(generated_script.contains("systemctl restart heteronetwork-agent.service"));
        assert!(
            generated_script.contains("Usage: $0 [--disable-relay] [--disable-public-services]")
        );
        assert!(generated_script.contains("public_services_enabled=1"));
        assert!(generated_script.contains("--disable-public-services"));
        assert!(generated_script.contains(
            "--disable-relay)\n      relay_enabled=0\n      public_services_enabled=0\n      ;;"
        ));
        assert!(generated_script.contains("heteronetwork-public-services-autopilot.service"));
        assert!(generated_script.contains("heteronetwork-public-services-autopilot.timer"));
        assert!(generated_script.contains("u heteronetwork-services -"));
        assert!(generated_script.contains("User=heteronetwork-services"));
        assert!(generated_script
            .contains("HETERONETWORK_PUBLIC_SERVICES_ENROLLMENT_TRUSTED_ISSUER_KEY_B64="));
        assert!(generated_script.contains(&format!(
            "HETERONETWORK_PUBLIC_SERVICES_ENROLLMENT_TRUSTED_ISSUER_KEY_B64={}",
            STANDARD.encode(trusted_enrollment_signer.as_bytes())
        )));
        assert!(generated_script
            .contains("HETERONETWORK_PUBLIC_SERVICES_CLASSIFICATION_MAX_AGE_SECONDS=45"));
        assert!(generated_script
            .contains("HETERONETWORK_PUBLIC_SERVICES_RECONCILE_INTERVAL_SECONDS=15"));
        let managed_keycloak_backchannel =
            STANDARD.encode("http://127.0.0.1:18079/realms/heteronetwork");
        assert!(generated_script.contains(&format!(
            "HETERONETWORK_PUBLIC_SERVICES_OIDC_BACKCHANNEL_BASE_URL_B64={managed_keycloak_backchannel}"
        )));
        let configured_keycloak_fallbacks = STANDARD.encode(
            "http://10.250.0.1:8080/realms/heteronetwork,https://sso-b.example/realms/heteronetwork",
        );
        assert!(generated_script.contains(&format!(
            "HETERONETWORK_PUBLIC_SERVICES_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS_B64={configured_keycloak_fallbacks}"
        )));
        assert!(generated_script.contains(&format!(
            "HETERONETWORK_PUBLIC_SERVICES_DATABASE_AUTOPILOT_BEARER_TOKEN={database_autopilot_bearer}"
        )));
        assert!(generated_script.contains(&format!(
            "HETERONETWORK_PUBLIC_SERVICES_KEYCLOAK_AUTOPILOT_BEARER_TOKEN={keycloak_autopilot_bearer}"
        )));
        assert!(generated_script
            .contains("/etc/heteronetwork/public-services/database-autopilot.token"));
        assert!(generated_script
            .contains("/etc/heteronetwork/public-services/keycloak-autopilot.token"));
        assert!(generated_script.contains("Automatic public-service promotion scheduled"));
        assert!(generated_script.contains("if [ \"$relay_enabled\" -eq 1 ]; then"));
        assert!(generated_script.contains(
            "apt-get install -y ca-certificates coreutils curl iproute2 jq tar wireguard-tools"
        ));
        assert!(generated_script.contains("/etc/heteronetwork/relay-admission.token"));
        assert!(generated_script.contains("/etc/heteronetwork/relay-server-admission.token"));
        assert!(generated_script.contains("install -o root -g root -m 0400"));
        assert!(generated_script
            .contains("install -o heteronetwork-relay -g heteronetwork-relay -m 0400"));
        assert!(generated_script.contains(
            "HETERONETWORK_AGENT_RELAY_ADMISSION_BEARER_TOKEN_PATH=/etc/heteronetwork/relay-admission.token"
        ));
        assert!(generated_script.contains("HETERONETWORK_AGENT_RELAY_FORWARDER_BIND=127.0.0.1:0"));
        assert!(
            !generated_script.contains("HETERONETWORK_AGENT_RELAY_FORWARDER_WIREGUARD_ENDPOINT=")
        );
        assert!(generated_script.contains(
            "HETERONETWORK_RELAY_ADMISSION_BEARER_TOKEN_PATH=/etc/heteronetwork/relay-server-admission.token"
        ));
        assert!(!generated_script.lines().any(|line| {
            line == "HETERONETWORK_RELAY_ADMISSION_BEARER_TOKEN_PATH=/etc/heteronetwork/relay-admission.token"
        }));
        assert!(generated_script.contains("iparsd_replaced=0"));
        assert!(generated_script.contains(
            "snapshot_iparsd_binary\ninstall -m 0755 \"$binary\" \"$iparsd_path.new\"\nmv -f \"$iparsd_path.new\" \"$iparsd_path\"\niparsd_replaced=1"
        ));
        assert!(generated_script.contains("restore_iparsd_binary"));
        assert!(generated_script.contains("discard_iparsd_snapshot"));
        assert!(generated_script.contains("commit_installer_transaction"));
        assert!(generated_script.contains("relay_restart_required=$iparsd_replaced"));
        assert!(generated_script
            .contains("cmp -s /etc/heteronetwork/.relay-server-admission.token.new"));
        assert!(generated_script.contains("if [ \"$relay_restart_required\" -eq 1 ]"));
        assert!(generated_script.contains("relay_autopilot_transaction_active=1"));
        assert!(generated_script.contains("relay_autopilot_transaction_active=0"));
        assert!(generated_script.contains("relay_autopilot_timer_enable_state"));
        assert!(generated_script.contains("relay_agent_enable_state"));
        assert!(generated_script.contains("relay_autopilot_service_was_active"));
        assert!(generated_script.contains("enabled-runtime"));
        assert!(generated_script.contains("masked-runtime"));
        assert!(
            generated_script.contains("if [ \"$relay_autopilot_timer_was_active\" -eq 1 ]; then")
        );
        assert!(generated_script.contains("snapshot_relay_transaction_files"));
        assert!(generated_script.contains("restore_relay_transaction_files"));
        assert!(generated_script.contains("systemctl enable \"$unit_name\""));
        assert!(generated_script.contains("systemctl enable --runtime \"$unit_name\""));
        assert!(generated_script.contains("systemctl disable heteronetwork-relay-autopilot.timer"));
        assert!(generated_script
            .contains("Refusing Relay rollback because an autopilot mutator could not be stopped"));
        assert!(generated_script.contains("exit \"$installer_status\""));
        assert!(generated_script
            .contains("u heteronetwork-relay - \"HeteroNetwork Relay\" /nonexistent"));
        assert!(generated_script.contains("User=heteronetwork-relay"));
        assert!(generated_script.contains("Group=heteronetwork-relay"));
        assert!(generated_script.contains("heteronetwork-relay-autopilot.service"));
        assert!(generated_script.contains("heteronetwork-relay-autopilot.timer"));
        assert!(generated_script.contains("OnUnitInactiveSec=15s"));
        assert!(generated_script.contains("RuntimeDirectory=heteronetwork-relay-autopilot"));
        assert!(generated_script.contains(
            "ReadWritePaths=/etc/heteronetwork/relay-autopilot /etc/systemd/system/heteronetwork-agent.service.d"
        ));
        assert!(generated_script.contains("($nat.connectivity_state == \"public\")"));
        assert!(generated_script.contains("($nat.mapping_behavior == \"no_nat\")"));
        assert!(generated_script.contains("($nat.strategy == \"direct_candidate\")"));
        assert!(generated_script.contains("sub(\"\\\\.[0-9]+Z$\"; \"Z\")"));
        assert!(generated_script.contains("($assessed >= (now - 45))"));
        assert!(generated_script.contains("relay_udp_listen=\"0.0.0.0:18445\""));
        assert!(generated_script.contains("relay_udp_listen=\"[::]:18445\""));
        assert!(generated_script.contains("relay_http_listen=\"$vpn_ip:18447\""));
        assert!(generated_script.contains("relay_http_listen=\"[$vpn_ip]:18447\""));
        assert!(generated_script.contains(
            "Environment=\"HETERONETWORK_AGENT_RELAY_PUBLIC_ENDPOINT=$relay_public_endpoint\""
        ));
        assert!(generated_script
            .contains("Environment=\"HETERONETWORK_AGENT_RELAY_ADMISSION_URL=$relay_http_url\""));
        assert!(generated_script
            .contains("Environment=\"HETERONETWORK_AGENT_RELAY_STATUS_URL=$relay_http_url\""));
        assert!(generated_script.contains("cmp -s \"$relay_env_tmp\" \"$relay_env\""));
        assert!(generated_script.contains("cmp -s \"$agent_drop_in_tmp\" \"$agent_drop_in\""));
        assert!(generated_script.contains("begin_runtime_relay_transaction"));
        assert!(generated_script.contains("rollback_runtime_relay_transaction"));
        assert!(generated_script.contains("commit_runtime_relay_transaction"));
        assert!(generated_script.contains("\"$relay_env_dir\"/.relay.env.*"));
        assert!(generated_script.contains("\"$agent_drop_in_dir\"/.20-relay-autopilot.conf.*"));
        assert!(generated_script.contains("if ! systemctl disable"));
        assert!(generated_script
            .contains("stop_systemd_unit_with_kill heteronetwork-relay-autopilot.timer"));
        assert!(
            generated_script.contains("stop_systemd_unit_with_kill heteronetwork-relay.service")
        );
        assert!(generated_script
            .contains("if [ \"$unit_load_state\" = \"not-found\" ]; then\n    return 0"));
        assert!(generated_script.contains("stop_systemd_unit_with_kill \"$relay_service\""));
        assert!(generated_script.contains("systemctl kill --kill-whom=all --signal=SIGKILL"));
        assert!(!generated_script.contains("systemctl stop \"$relay_service\" || true"));
        assert!(
            generated_script.contains("systemctl enable --now heteronetwork-relay-autopilot.timer")
        );
        assert!(!generated_script.contains("__RELAY_"));
        let encoded_relay_bearer = STANDARD.encode(RELAY_ADMISSION_BEARER_TOKEN.as_bytes());
        assert!(generated_script.contains(&format!(
            "printf '%s' '{encoded_relay_bearer}' | base64 -d >\"$tmp_dir/relay-admission.token\""
        )));
        assert!(!generated_script.contains(RELAY_ADMISSION_BEARER_TOKEN));
        assert!(install_command.contains("sudo sh \"$tmp\" \"$@\""));
        assert!(install_command.ends_with("' sh"));
        let relay_autopilot = generated_script
            .split_once("cat >\"$tmp_dir/relay-autopilot.sh\" <<'HETERONETWORK_RELAY_AUTOPILOT'\n")
            .and_then(|(_, tail)| {
                tail.split_once("\nHETERONETWORK_RELAY_AUTOPILOT\n")
                    .map(|(script, _)| script)
            })
            .ok_or("generated installer omitted the relay autopilot helper")?;
        let runtime_reconcile = relay_autopilot
            .split_once("relay_was_active_now=0\n")
            .map(|(_, transaction)| transaction)
            .ok_or("generated Relay autopilot omitted its runtime reconciliation")?;
        let begin_transaction = relay_autopilot
            .split_once("begin_runtime_relay_transaction() {\n")
            .and_then(|(_, tail)| tail.split_once("\n}\n").map(|(transaction, _)| transaction))
            .ok_or("generated Relay autopilot omitted its transaction begin function")?;
        let agent_stop = begin_transaction
            .find("stop_systemd_unit_with_kill \"$agent_service\"")
            .ok_or("Relay transaction did not stop the Agent")?;
        let relay_stop = begin_transaction
            .find("stop_systemd_unit_with_kill \"$relay_service\"")
            .ok_or("Relay transaction did not stop the Relay")?;
        assert!(agent_stop < relay_stop);
        let relay_env_install = runtime_reconcile
            .find("mv -f \"$relay_env_tmp\" \"$relay_env\"")
            .ok_or("Relay reconciliation omitted its runtime environment install")?;
        let agent_drop_in_install = runtime_reconcile
            .find("mv -f \"$agent_drop_in_tmp\" \"$agent_drop_in\"")
            .ok_or("Relay reconciliation omitted its Agent drop-in install")?;
        let daemon_reload = runtime_reconcile
            .find("systemctl daemon-reload")
            .ok_or("Relay reconciliation omitted daemon-reload")?;
        let agent_restart = runtime_reconcile
            .find("systemctl restart \"$agent_service\"")
            .ok_or("Relay reconciliation omitted the Agent restart")?;
        let relay_restart = runtime_reconcile
            .find("systemctl restart \"$relay_service\"")
            .ok_or("Relay reconciliation omitted the Relay restart")?;
        let relay_start = runtime_reconcile
            .find("systemctl start \"$relay_service\"")
            .ok_or("Relay reconciliation omitted the Relay start")?;
        assert!(relay_env_install < agent_drop_in_install);
        assert!(agent_drop_in_install < daemon_reload);
        assert!(daemon_reload < agent_restart);
        assert!(agent_restart < relay_restart);
        assert!(agent_restart < relay_start);
        assert!(!runtime_reconcile.contains("systemctl start \"$agent_service\""));
        let mut relay_shell = std::process::Command::new("sh")
            .arg("-n")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        relay_shell
            .stdin
            .take()
            .ok_or("relay autopilot shell syntax checker stdin is unavailable")?
            .write_all(relay_autopilot.as_bytes())?;
        let relay_syntax = relay_shell.wait_with_output()?;
        assert!(
            relay_syntax.status.success(),
            "generated relay autopilot is not valid POSIX shell: {}",
            String::from_utf8_lossy(&relay_syntax.stderr)
        );

        let installer_transaction_support = generated_script
            .split_once("iparsd_path=/opt/heteronetwork/bin/iparsd\n")
            .and_then(|(_, tail)| {
                tail.split_once("auth='").map(|(support, _)| {
                    format!("iparsd_path=/opt/heteronetwork/bin/iparsd\n{support}")
                })
            })
            .ok_or("generated installer omitted its Relay transaction support")?;
        for (timer_enable_state, agent_enable_state, timer_was_active, autopilot_was_active) in [
            ("enabled", "disabled", false, true),
            ("enabled-runtime", "enabled-runtime", true, true),
            ("masked", "masked", false, false),
            ("masked-runtime", "masked-runtime", false, false),
            ("disabled", "enabled", true, false),
        ] {
            let case_id = random_oidc_value(12);
            let cleanup_dir =
                std::env::temp_dir().join(format!("heteronetwork-installer-cleanup-{case_id}"));
            let target_dir =
                std::env::temp_dir().join(format!("heteronetwork-installer-target-{case_id}"));
            let systemctl_state = std::env::temp_dir()
                .join(format!("heteronetwork-installer-systemctl-{case_id}.state"));
            let systemctl_log = std::env::temp_dir()
                .join(format!("heteronetwork-installer-systemctl-{case_id}.log"));
            std::fs::create_dir(&cleanup_dir)?;
            std::fs::create_dir(&target_dir)?;
            std::fs::write(target_dir.join("existing"), b"before-upgrade")?;
            let cleanup_harness = format!(
                r#"set -eu
tmp_dir=$1
target_dir=$2
systemctl_state=$3
systemctl_log=$4
timer_enable_state=$5
timer_active=$6
agent_enable_state=$7
autopilot_active=$8
relay_active=1
agent_active=1
fail_mutator_stop=0

persist_systemd_state() {{
  printf '%s %s %s %s %s %s\n' \
    "$timer_enable_state" "$timer_active" "$relay_active" \
    "$agent_enable_state" "$agent_active" "$autopilot_active" \
    >"$systemctl_state"
}}

unit_is_active() {{
  case "$1" in
    heteronetwork-relay-autopilot.timer)
      [ "$timer_active" -eq 1 ]
      ;;
    heteronetwork-relay-autopilot.service)
      [ "$autopilot_active" -eq 1 ]
      ;;
    heteronetwork-relay.service)
      [ "$relay_active" -eq 1 ]
      ;;
    heteronetwork-agent.service)
      [ "$agent_active" -eq 1 ]
      ;;
    *)
      return 1
      ;;
  esac
}}

set_unit_active() {{
  case "$1" in
    heteronetwork-relay-autopilot.timer)
      timer_active=$2
      ;;
    heteronetwork-relay-autopilot.service)
      autopilot_active=$2
      ;;
    heteronetwork-relay.service)
      relay_active=$2
      ;;
    heteronetwork-agent.service)
      agent_active=$2
      ;;
  esac
  persist_systemd_state
}}

unit_enable_state() {{
  case "$1" in
    heteronetwork-relay-autopilot.timer)
      printf '%s\n' "$timer_enable_state"
      ;;
    heteronetwork-agent.service)
      printf '%s\n' "$agent_enable_state"
      ;;
    *)
      printf '%s\n' not-found
      ;;
  esac
}}

set_unit_enable_state() {{
  case "$1" in
    heteronetwork-relay-autopilot.timer)
      timer_enable_state=$2
      ;;
    heteronetwork-agent.service)
      agent_enable_state=$2
      ;;
  esac
  persist_systemd_state
}}

systemctl() {{
  printf '%s\n' "$*" >>"$systemctl_log"
  systemctl_command=$1
  shift
  systemctl_unit=
  systemctl_runtime=0
  for systemctl_argument in "$@"; do
    [ "$systemctl_argument" != --runtime ] || systemctl_runtime=1
    systemctl_unit=$systemctl_argument
  done
  case "$systemctl_command" in
    is-enabled)
      current_enable_state=$(unit_enable_state "$systemctl_unit")
      printf '%s\n' "$current_enable_state"
      case "$current_enable_state" in
        enabled|enabled-runtime|linked|linked-runtime|alias) return 0 ;;
        *) return 1 ;;
      esac
      ;;
    is-active)
      unit_is_active "$systemctl_unit"
      ;;
    show)
      case "$1" in
        --property=LoadState)
          if [ "$(unit_enable_state "$systemctl_unit")" = not-found ]; then
            printf '%s\n' not-found
          else
            printf '%s\n' loaded
          fi
          ;;
        --property=ActiveState)
          if unit_is_active "$systemctl_unit"; then
            printf '%s\n' active
          else
            printf '%s\n' inactive
          fi
          ;;
        *)
          return 1
          ;;
      esac
      ;;
    stop|kill)
      if [ "$systemctl_unit" = heteronetwork-relay-autopilot.service ] \
        && [ "$fail_mutator_stop" -eq 1 ]; then
        return 1
      fi
      set_unit_active "$systemctl_unit" 0
      ;;
    start|restart)
      set_unit_active "$systemctl_unit" 1
      ;;
    enable)
      if [ "$systemctl_runtime" -eq 1 ]; then
        set_unit_enable_state "$systemctl_unit" enabled-runtime
      else
        set_unit_enable_state "$systemctl_unit" enabled
      fi
      ;;
    disable)
      set_unit_enable_state "$systemctl_unit" disabled
      ;;
    mask)
      if [ "$systemctl_runtime" -eq 1 ]; then
        set_unit_enable_state "$systemctl_unit" masked-runtime
      else
        set_unit_enable_state "$systemctl_unit" masked
      fi
      ;;
    unmask)
      case "$(unit_enable_state "$systemctl_unit")" in
        masked)
          [ "$systemctl_runtime" -eq 1 ] \
            || set_unit_enable_state "$systemctl_unit" disabled
          ;;
        masked-runtime)
          [ "$systemctl_runtime" -ne 1 ] \
            || set_unit_enable_state "$systemctl_unit" disabled
          ;;
      esac
      ;;
    daemon-reload)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}}
persist_systemd_state
{installer_transaction_support}
iparsd_path="$target_dir/iparsd"
iparsd_previous_snapshot="$tmp_dir/iparsd.previous"
relay_transaction_paths="$target_dir/existing $target_dir/created"
relay_transaction_temporary_paths="$target_dir/temporary.new"
relay_transaction_random_temporary_globs="$target_dir/.relay.env.* $target_dir/.agent.conf.*"
relay_transaction_directories="$target_dir/existing-dir $target_dir/created-dir"
relay_snapshot_dir="$tmp_dir/relay-rollback"
relay_snapshot_manifest="$relay_snapshot_dir/manifest"
relay_snapshot_directory_manifest="$relay_snapshot_dir/directories"
mkdir "$target_dir/existing-dir"
chmod 0750 "$target_dir/existing-dir"
printf '%s\n' old-binary >"$iparsd_path"
snapshot_iparsd_binary
printf '%s\n' new-binary >"$iparsd_path"
iparsd_replaced=1
begin_relay_autopilot_transaction
printf '%s\n' after-upgrade >"$target_dir/existing"
printf '%s\n' created-during-upgrade >"$target_dir/created"
printf '%s\n' partial-temporary >"$target_dir/temporary.new"
printf '%s\n' stale-random >"$target_dir/.relay.env.orphan"
chmod 0777 "$target_dir/existing-dir"
mkdir "$target_dir/created-dir"
systemctl enable heteronetwork-relay-autopilot.timer
systemctl enable heteronetwork-agent.service
exit 37
"#
            );
            let cleanup_result = std::process::Command::new("sh")
                .args(["-c", &cleanup_harness, "sh"])
                .arg(&cleanup_dir)
                .arg(&target_dir)
                .arg(&systemctl_state)
                .arg(&systemctl_log)
                .arg(timer_enable_state)
                .arg(if timer_was_active { "1" } else { "0" })
                .arg(agent_enable_state)
                .arg(if autopilot_was_active { "1" } else { "0" })
                .output()?;
            assert_eq!(
                cleanup_result.status.code(),
                Some(37),
                "installer cleanup changed the original failure status: {}",
                String::from_utf8_lossy(&cleanup_result.stderr)
            );
            assert!(
                !cleanup_dir.exists(),
                "installer cleanup left its temporary directory behind"
            );
            assert_eq!(
                std::fs::read(target_dir.join("existing"))?,
                b"before-upgrade"
            );
            assert_eq!(
                std::fs::read(target_dir.join("iparsd"))?,
                b"old-binary\n",
                "rollback did not restore the previous binary"
            );
            assert!(!target_dir.join("created").exists());
            assert!(!target_dir.join("temporary.new").exists());
            assert!(!target_dir.join(".relay.env.orphan").exists());
            assert!(!target_dir.join("created-dir").exists());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                assert_eq!(
                    std::fs::metadata(target_dir.join("existing-dir"))?
                        .permissions()
                        .mode()
                        & 0o777,
                    0o750
                );
            }
            let expected_state = format!(
                "{} {} 1 {} 1 {}\n",
                timer_enable_state,
                u8::from(timer_was_active),
                agent_enable_state,
                u8::from(autopilot_was_active)
            );
            assert_eq!(
                std::fs::read_to_string(&systemctl_state)?,
                expected_state,
                "rollback did not restore exact systemd state"
            );
            std::fs::remove_dir_all(target_dir)?;
            std::fs::remove_file(systemctl_state)?;
            std::fs::remove_file(systemctl_log)?;
        }

        let mutator_case_id = random_oidc_value(12);
        let mutator_cleanup_dir = std::env::temp_dir().join(format!(
            "heteronetwork-installer-mutator-cleanup-{mutator_case_id}"
        ));
        let mutator_target_dir = std::env::temp_dir().join(format!(
            "heteronetwork-installer-mutator-target-{mutator_case_id}"
        ));
        let mutator_state = std::env::temp_dir().join(format!(
            "heteronetwork-installer-mutator-{mutator_case_id}.state"
        ));
        let mutator_log = std::env::temp_dir().join(format!(
            "heteronetwork-installer-mutator-{mutator_case_id}.log"
        ));
        std::fs::create_dir(&mutator_cleanup_dir)?;
        std::fs::create_dir(&mutator_target_dir)?;
        std::fs::write(mutator_target_dir.join("existing"), b"before-upgrade")?;
        let mutator_harness = format!(
            r#"set -eu
tmp_dir=$1
target_dir=$2
systemctl_state=$3
systemctl_log=$4
timer_enable_state=enabled
timer_active=1
agent_enable_state=enabled
autopilot_active=1
relay_active=1
agent_active=1
fail_mutator_stop=0

persist_systemd_state() {{
  printf '%s\n' "$autopilot_active" >"$systemctl_state"
}}
unit_is_active() {{
  case "$1" in
    heteronetwork-relay-autopilot.timer) [ "$timer_active" -eq 1 ] ;;
    heteronetwork-relay-autopilot.service) [ "$autopilot_active" -eq 1 ] ;;
    heteronetwork-relay.service) [ "$relay_active" -eq 1 ] ;;
    heteronetwork-agent.service) [ "$agent_active" -eq 1 ] ;;
    *) return 1 ;;
  esac
}}
set_unit_active() {{
  case "$1" in
    heteronetwork-relay-autopilot.timer) timer_active=$2 ;;
    heteronetwork-relay-autopilot.service) autopilot_active=$2 ;;
    heteronetwork-relay.service) relay_active=$2 ;;
    heteronetwork-agent.service) agent_active=$2 ;;
  esac
  persist_systemd_state
}}
systemctl() {{
  printf '%s\n' "$*" >>"$systemctl_log"
  command=$1
  shift
  unit=
  for argument in "$@"; do unit=$argument; done
  case "$command" in
    is-enabled) printf '%s\n' enabled ;;
    is-active) unit_is_active "$unit" ;;
    show)
      case "$1" in
        --property=LoadState) printf '%s\n' loaded ;;
        --property=ActiveState)
          if unit_is_active "$unit"; then printf '%s\n' active; else printf '%s\n' inactive; fi
          ;;
      esac
      ;;
    stop|kill)
      if [ "$unit" = heteronetwork-relay-autopilot.service ] \
        && [ "$fail_mutator_stop" -eq 1 ]; then
        return 1
      fi
      set_unit_active "$unit" 0
      ;;
    start|restart) set_unit_active "$unit" 1 ;;
    enable|disable|mask|unmask|daemon-reload) return 0 ;;
    *) return 1 ;;
  esac
}}
{installer_transaction_support}
iparsd_path="$target_dir/iparsd"
iparsd_previous_snapshot="$tmp_dir/iparsd.previous"
relay_transaction_paths="$target_dir/existing"
relay_transaction_temporary_paths="$target_dir/temporary.new"
relay_transaction_random_temporary_globs="$target_dir/.relay.env.*"
relay_transaction_directories="$target_dir"
relay_snapshot_dir="$tmp_dir/relay-rollback"
relay_snapshot_manifest="$relay_snapshot_dir/manifest"
relay_snapshot_directory_manifest="$relay_snapshot_dir/directories"
printf '%s\n' old-binary >"$iparsd_path"
snapshot_iparsd_binary
printf '%s\n' new-binary >"$iparsd_path"
iparsd_replaced=1
begin_relay_autopilot_transaction
printf '%s\n' after-upgrade >"$target_dir/existing"
autopilot_active=1
fail_mutator_stop=1
exit 41
"#
        );
        let mutator_result = std::process::Command::new("sh")
            .args(["-c", &mutator_harness, "sh"])
            .arg(&mutator_cleanup_dir)
            .arg(&mutator_target_dir)
            .arg(&mutator_state)
            .arg(&mutator_log)
            .output()?;
        assert_eq!(mutator_result.status.code(), Some(41));
        assert_eq!(
            std::fs::read(mutator_target_dir.join("existing"))?,
            b"after-upgrade\n",
            "rollback restored files while a mutator remained active"
        );
        assert_eq!(
            std::fs::read(mutator_target_dir.join("iparsd"))?,
            b"new-binary\n",
            "rollback restored the executable while a mutator remained active"
        );
        std::fs::remove_dir_all(mutator_target_dir)?;
        std::fs::remove_file(mutator_state)?;
        std::fs::remove_file(mutator_log)?;

        let disable_cleanup = generated_script
            .split_once("relay_cleanup_failed=0\n")
            .and_then(|(_, tail)| {
                tail.split_once("\nif [ \"$relay_cleanup_failed\" -ne 0 ]; then")
                    .map(|(cleanup, _)| format!("relay_cleanup_failed=0\n{cleanup}"))
            })
            .ok_or("generated installer omitted its Relay disable cleanup")?;
        let disable_advertisement_remove = disable_cleanup
            .find("rm -f \"$relay_advertisement_drop_in\"")
            .ok_or("Relay disable cleanup does not remove its advertisement")?;
        let disable_admission_remove =
            disable_cleanup
                .find("rm -f \"$relay_admission_drop_in\"")
                .ok_or("Relay disable cleanup does not remove Agent admission configuration")?;
        let disable_relay_stop = disable_cleanup
            .find("stop_systemd_unit_with_kill heteronetwork-relay.service")
            .ok_or("Relay disable cleanup does not stop its service")?;
        let disable_env_remove = disable_cleanup
            .find("\"$relay_runtime_env\"")
            .ok_or("Relay disable cleanup does not remove its runtime environment")?;
        assert!(disable_advertisement_remove < disable_relay_stop);
        assert!(disable_advertisement_remove < disable_admission_remove);
        assert!(disable_admission_remove < disable_relay_stop);
        assert!(disable_relay_stop < disable_env_remove);
        assert!(disable_cleanup.contains("\"withdrawing Relay advertisement\""));
        assert!(disable_cleanup.contains("\"removing Relay admission configuration\""));
        assert!(disable_cleanup.contains(
            "Preserving the running Relay and its environment because advertisement withdrawal is unconfirmed"
        ));
        assert!(disable_cleanup.contains(
            "Preserving the running Relay, its environment, and admission tokens because Agent refresh is unconfirmed"
        ));

        let disable_failure_dir = std::env::temp_dir().join(format!(
            "heteronetwork-relay-disable-failure-{}",
            random_oidc_value(12)
        ));
        std::fs::create_dir(&disable_failure_dir)?;
        let disable_agent_drop_in = disable_failure_dir.join("agent-advertisement.conf");
        let disable_admission_drop_in = disable_failure_dir.join("agent-admission.conf");
        let disable_relay_env = disable_failure_dir.join("relay.env");
        let disable_log = disable_failure_dir.join("systemctl.log");
        std::fs::write(&disable_agent_drop_in, b"old-advertisement")?;
        std::fs::write(&disable_admission_drop_in, b"old-admission")?;
        std::fs::write(&disable_relay_env, b"old-runtime")?;
        let disable_failure_script = disable_cleanup
            .replace(
                "/etc/systemd/system/heteronetwork-agent.service.d/20-relay-autopilot.conf",
                &disable_agent_drop_in.display().to_string(),
            )
            .replace(
                "/etc/systemd/system/heteronetwork-agent.service.d/10-relay-admission.conf",
                &disable_admission_drop_in.display().to_string(),
            )
            .replace(
                "/etc/heteronetwork/relay-autopilot/relay.env",
                &disable_relay_env.display().to_string(),
            );
        let disable_failure_harness = format!(
            r#"set -eu
relay_active=1
agent_active=1
systemctl_log=$1
agent_drop_in_path=$2
admission_drop_in_path=$3
relay_env_path=$4
restart_fail_on=$5
restart_count=0

verify_systemd_unit_stopped() {{
  [ "$1" != heteronetwork-agent.service ] || [ "$agent_active" -eq 0 ]
}}
stop_systemd_unit_with_kill() {{
  printf 'stop %s\n' "$1" >>"$systemctl_log"
  case "$1" in
    heteronetwork-agent.service)
      return 1
      ;;
    heteronetwork-relay.service)
      relay_active=0
      ;;
  esac
}}
remove_relay_transaction_temporary_files() {{
  return 0
}}
systemctl() {{
  printf '%s\n' "$*" >>"$systemctl_log"
  command_name=$1
  shift
  unit=
  for argument in "$@"; do unit=$argument; done
  case "$command_name" in
    disable|daemon-reload)
      return 0
      ;;
    is-enabled)
      return 1
      ;;
    is-active)
      [ "$unit" = heteronetwork-agent.service ] && [ "$agent_active" -eq 1 ]
      ;;
    restart)
      restart_count=$((restart_count + 1))
      [ "$restart_count" -ne "$restart_fail_on" ] || return 1
      return 0
      ;;
    *)
      return 0
      ;;
  esac
}}
rm() {{
  remove_status=0
  for remove_path in "$@"; do
    case "$remove_path" in
      -*)
        ;;
      "$agent_drop_in_path"|"$admission_drop_in_path"|"$relay_env_path")
        /bin/rm -f "$remove_path" || remove_status=1
        ;;
    esac
  done
  return "$remove_status"
}}
rmdir() {{
  return 0
}}
{disable_failure_script}
[ "$relay_active" -eq 1 ]
[ -e "$relay_env_path" ]
"#
        );
        for restart_fail_on in [1, 2] {
            std::fs::write(&disable_agent_drop_in, b"old-advertisement")?;
            std::fs::write(&disable_admission_drop_in, b"old-admission")?;
            std::fs::write(&disable_relay_env, b"old-runtime")?;
            let _ = std::fs::remove_file(&disable_log);
            let disable_failure = std::process::Command::new("sh")
                .args(["-c", &disable_failure_harness, "sh"])
                .arg(&disable_log)
                .arg(&disable_agent_drop_in)
                .arg(&disable_admission_drop_in)
                .arg(&disable_relay_env)
                .arg(restart_fail_on.to_string())
                .output()?;
            assert_eq!(
                disable_failure.status.code(),
                Some(1),
                "disable should fail when Agent refresh {restart_fail_on} and stop both fail: {}",
                String::from_utf8_lossy(&disable_failure.stderr)
            );
            assert!(disable_relay_env.exists());
            assert!(!std::fs::read_to_string(&disable_log)?
                .contains("stop heteronetwork-relay.service"));
        }
        std::fs::remove_dir_all(disable_failure_dir)?;

        let relay_withdrawal_functions = relay_autopilot
            .split_once("verify_systemd_unit_stopped() (\n")
            .and_then(|(_, tail)| {
                tail.split_once(
                    "\ninstall -d -o root -g root -m 0755 /run/heteronetwork-relay-autopilot",
                )
                .map(|(functions, _)| format!("verify_systemd_unit_stopped() (\n{functions}"))
            })
            .ok_or("generated Relay autopilot omitted its withdrawal functions")?;
        for (
            relay_forced_kill_succeeds,
            agent_restart_succeeds,
            agent_stop_succeeds,
            withdrawal_should_succeed,
        ) in [
            (true, true, true, true),
            (false, true, true, false),
            (true, false, false, false),
        ] {
            let withdrawal_dir = std::env::temp_dir().join(format!(
                "heteronetwork-relay-withdrawal-{}",
                random_oidc_value(12)
            ));
            let systemctl_log = withdrawal_dir.join("systemctl.log");
            std::fs::create_dir(&withdrawal_dir)?;
            let agent_drop_in = withdrawal_dir.join("agent.conf");
            let relay_env = withdrawal_dir.join("relay.env");
            std::fs::write(&agent_drop_in, b"advertised")?;
            std::fs::write(&relay_env, b"configured")?;
            let withdrawal_harness = format!(
                r#"set -eu
relay_service=heteronetwork-relay.service
agent_service=heteronetwork-agent.service
agent_drop_in=$1
relay_env=$2
systemctl_log=$3
relay_forced_kill_succeeds=$4
agent_restart_succeeds=$5
agent_stop_succeeds=$6
withdrawal_should_succeed=$7
relay_active=1
agent_active=1
runtime_transaction_active=0
status_file=
relay_env_tmp=
agent_drop_in_tmp=
runtime_transaction_dir=

cleanup_temporary_files() {{
  return 0
}}
cleanup_random_temporary_files() {{
  return 0
}}

systemctl() {{
  printf '%s\n' "$*" >>"$systemctl_log"
  systemctl_command=$1
  shift
  systemctl_unit=
  for systemctl_argument in "$@"; do
    systemctl_unit=$systemctl_argument
  done
  if [ "$systemctl_command" = show ]; then
    case "$1" in
      --property=LoadState)
        printf '%s\n' loaded
        return 0
        ;;
      --property=ActiveState)
        if [ "$systemctl_unit" = "$relay_service" ] \
          && [ "$relay_active" -eq 1 ]; then
          printf '%s\n' active
        elif [ "$systemctl_unit" = "$agent_service" ] \
          && [ "$agent_active" -eq 1 ]; then
          printf '%s\n' active
        else
          printf '%s\n' inactive
        fi
        return 0
        ;;
    esac
  fi
  if [ "$systemctl_command" = is-active ]; then
    [ "$systemctl_unit" = "$agent_service" ] && [ "$agent_active" -eq 1 ]
    return
  fi
  if [ "$systemctl_command" = daemon-reload ]; then
    return 0
  fi
  if [ "$systemctl_command" = restart ] && [ "$systemctl_unit" = "$agent_service" ]; then
    [ "$agent_restart_succeeds" -eq 1 ] || return 1
    agent_active=1
    return
  fi
  if [ "$systemctl_command" = stop ] && [ "$systemctl_unit" = "$agent_service" ]; then
    [ "$agent_stop_succeeds" -eq 1 ] || return 1
    agent_active=0
    return
  fi
  if [ "$systemctl_command" = kill ] && [ "$systemctl_unit" = "$agent_service" ]; then
    [ "$agent_stop_succeeds" -eq 1 ] || return 1
    agent_active=0
    return
  fi
  if [ "$systemctl_command" = stop ] && [ "$systemctl_unit" = "$relay_service" ]; then
    [ ! -e "$agent_drop_in" ] || printf '%s\n' advertisement-order-violation >>"$systemctl_log"
    [ -e "$relay_env" ] || printf '%s\n' env-order-violation >>"$systemctl_log"
    [ "$relay_active" -eq 0 ]
    return
  fi
  if [ "$systemctl_command" = kill ] && [ "$systemctl_unit" = "$relay_service" ]; then
    if [ "$relay_forced_kill_succeeds" -eq 1 ]; then
      relay_active=0
      return 0
    fi
    return 1
  fi
  return 0
}}
{relay_withdrawal_functions}
if [ "$withdrawal_should_succeed" -eq 1 ]; then
  withdraw_relay
  [ ! -e "$relay_env" ]
else
  if withdraw_relay; then
    echo "withdrawal unexpectedly succeeded while Relay remained active" >&2
    exit 1
  fi
  [ -e "$relay_env" ]
fi
[ ! -e "$agent_drop_in" ]
"#
            );
            let withdrawal_result = std::process::Command::new("sh")
                .args(["-c", &withdrawal_harness, "sh"])
                .arg(&agent_drop_in)
                .arg(&relay_env)
                .arg(&systemctl_log)
                .arg(if relay_forced_kill_succeeds { "1" } else { "0" })
                .arg(if agent_restart_succeeds { "1" } else { "0" })
                .arg(if agent_stop_succeeds { "1" } else { "0" })
                .arg(if withdrawal_should_succeed { "1" } else { "0" })
                .output()?;
            assert!(
                withdrawal_result.status.success(),
                "Relay withdrawal ordering/fallback failed: {}",
                String::from_utf8_lossy(&withdrawal_result.stderr)
            );
            let systemctl_calls = std::fs::read_to_string(&systemctl_log)?;
            assert!(!systemctl_calls.contains("order-violation"));
            if agent_restart_succeeds {
                let agent_restart = systemctl_calls
                    .find("restart heteronetwork-agent.service")
                    .ok_or("Relay withdrawal did not restart the Agent")?;
                let relay_stop = systemctl_calls
                    .find("stop heteronetwork-relay.service")
                    .ok_or("Relay withdrawal did not stop the Relay")?;
                assert!(agent_restart < relay_stop);
            } else {
                assert!(
                    !systemctl_calls.contains("stop heteronetwork-relay.service"),
                    "Relay stopped while Agent advertisement withdrawal was unconfirmed"
                );
            }
            if agent_restart_succeeds {
                assert!(systemctl_calls
                    .contains("kill --kill-whom=all --signal=SIGKILL heteronetwork-relay.service"));
            }
            std::fs::remove_dir_all(withdrawal_dir)?;
        }

        for rollback_can_quiesce in [true, false] {
            let transaction_dir = std::env::temp_dir().join(format!(
                "heteronetwork-relay-runtime-transaction-{}",
                random_oidc_value(12)
            ));
            std::fs::create_dir(&transaction_dir)?;
            let runtime_relay_env = transaction_dir.join("relay.env");
            let runtime_agent_drop_in = transaction_dir.join("agent.conf");
            let runtime_state = transaction_dir.join("systemctl.state");
            let runtime_log = transaction_dir.join("systemctl.log");
            std::fs::write(&runtime_relay_env, b"old-endpoint")?;
            std::fs::write(&runtime_agent_drop_in, b"old-endpoint")?;
            let runtime_transaction_harness = format!(
                r#"set -eu
transaction_root=$1
relay_env=$2
agent_drop_in=$3
systemctl_state=$4
systemctl_log=$5
rollback_can_quiesce=$6
relay_service=heteronetwork-relay.service
agent_service=heteronetwork-agent.service
relay_active=1
agent_active=1
runtime_transaction_active=0
runtime_transaction_dir=
runtime_relay_env_state=absent
runtime_agent_drop_in_state=absent
runtime_relay_was_active=0
runtime_agent_was_active=0
status_file=
relay_env_tmp=
agent_drop_in_tmp=

persist_runtime_state() {{
  printf '%s %s\n' "$relay_active" "$agent_active" >"$systemctl_state"
}}
cleanup_temporary_files() {{
  [ -z "$runtime_transaction_dir" ] || /bin/rm -rf "$runtime_transaction_dir"
}}
cleanup_random_temporary_files() {{
  return 0
}}
mktemp() {{
  command mktemp -d "$transaction_root/rollback.XXXXXX"
}}
systemctl() {{
  printf '%s\n' "$*" >>"$systemctl_log"
  command_name=$1
  shift
  unit=
  for argument in "$@"; do unit=$argument; done
  case "$command_name" in
    show)
      case "$1" in
        --property=LoadState) printf '%s\n' loaded ;;
        --property=ActiveState)
          if [ "$unit" = "$relay_service" ] && [ "$relay_active" -eq 1 ]; then
            printf '%s\n' active
          elif [ "$unit" = "$agent_service" ] && [ "$agent_active" -eq 1 ]; then
            printf '%s\n' active
          else
            printf '%s\n' inactive
          fi
          ;;
      esac
      ;;
    is-active)
      if [ "$unit" = "$relay_service" ]; then
        [ "$relay_active" -eq 1 ]
      else
        [ "$agent_active" -eq 1 ]
      fi
      ;;
    stop|kill)
      if [ "$unit" = "$agent_service" ]; then
        [ "$rollback_can_quiesce" -eq 1 ] || return 1
        agent_active=0
      else
        relay_active=0
      fi
      persist_runtime_state
      ;;
    start|restart)
      if [ "$unit" = "$agent_service" ]; then
        agent_active=1
      else
        relay_active=1
      fi
      persist_runtime_state
      ;;
    daemon-reload)
      return 0
      ;;
    *)
      return 0
      ;;
  esac
}}
{relay_withdrawal_functions}
rollback_can_quiesce=1
begin_runtime_relay_transaction
: >"$systemctl_log"
printf '%s\n' new-endpoint >"$relay_env"
printf '%s\n' new-endpoint >"$agent_drop_in"
relay_active=1
if [ "$6" -eq 0 ]; then
  agent_active=1
  rollback_can_quiesce=0
fi
persist_runtime_state
exit 47
"#
            );
            let runtime_result = std::process::Command::new("sh")
                .args(["-c", &runtime_transaction_harness, "sh"])
                .arg(&transaction_dir)
                .arg(&runtime_relay_env)
                .arg(&runtime_agent_drop_in)
                .arg(&runtime_state)
                .arg(&runtime_log)
                .arg(if rollback_can_quiesce { "1" } else { "0" })
                .output()?;
            assert_eq!(
                runtime_result.status.code(),
                Some(47),
                "runtime rollback changed original failure status: {}",
                String::from_utf8_lossy(&runtime_result.stderr)
            );
            let expected_endpoint = if rollback_can_quiesce {
                b"old-endpoint".as_slice()
            } else {
                b"new-endpoint\n".as_slice()
            };
            assert_eq!(std::fs::read(&runtime_relay_env)?, expected_endpoint);
            assert_eq!(std::fs::read(&runtime_agent_drop_in)?, expected_endpoint);
            assert_eq!(
                std::fs::read_to_string(&runtime_state)?,
                "1 1\n",
                "runtime rollback did not preserve service state"
            );
            if !rollback_can_quiesce {
                assert!(
                    !std::fs::read_to_string(&runtime_log)?
                        .contains("stop heteronetwork-relay.service"),
                    "runtime rollback stopped Relay while Agent advertisement remained active"
                );
            }
            std::fs::remove_dir_all(transaction_dir)?;
        }

        let kubernetes_request_body = serde_json::json!({
            "expires_in_seconds": 86_400,
            "role": "worker",
            "tags": ["production"],
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
        let mut missing_control_plane_tag = kubernetes_token.clone();
        missing_control_plane_tag
            .claims
            .tags
            .remove(&Tag::kubernetes_control_plane());
        missing_control_plane_tag
            .claims
            .policy
            .allowed_tags
            .remove(&Tag::kubernetes_control_plane());
        assert!(kubernetes_ha_enrollment_setup(&missing_control_plane_tag, "encoded").is_none());
        let kubernetes_script = kubernetes_response["install_script"]
            .as_str()
            .ok_or("Kubernetes enrollment response omitted the install script")?;
        assert!(kubernetes_script.contains("heteronetwork-kubeadm-autopilot.service"));
        assert!(!kubernetes_script.contains("KUBERNETES_HA_SETUP_TAG_PREFIX"));
        let database_bearer = generated_script
            .lines()
            .find_map(|line| line.strip_prefix("HETERONETWORK_DB_AUTOPILOT_BEARER_TOKEN="))
            .ok_or("standard enrollment omitted the database autopilot bearer")?;
        let kubernetes_database_bearer = kubernetes_script
            .lines()
            .find_map(|line| line.strip_prefix("HETERONETWORK_DB_AUTOPILOT_BEARER_TOKEN="))
            .ok_or("Kubernetes enrollment omitted the database autopilot bearer")?;
        assert_eq!(database_bearer, kubernetes_database_bearer);
        assert_eq!(database_bearer.len(), 64);
        assert_ne!(RELAY_ADMISSION_BEARER_TOKEN, database_bearer);
        let mut script_shell = std::process::Command::new("sh")
            .arg("-n")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        script_shell
            .stdin
            .take()
            .ok_or("Kubernetes shell syntax checker stdin is unavailable")?
            .write_all(kubernetes_script.as_bytes())?;
        let script_syntax = script_shell.wait_with_output()?;
        assert!(
            script_syntax.status.success(),
            "generated Kubernetes install script is not valid POSIX shell: {}",
            String::from_utf8_lossy(&script_syntax.stderr)
        );

        let invalid_kubernetes_request = serde_json::json!({
            "expires_in_seconds": 86_400,
            "role": "worker",
            "tags": [],
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

        let reserved_control_plane_tag_request = serde_json::json!({
            "expires_in_seconds": 86_400,
            "role": "worker",
            "tags": ["kubernetes-control-plane"],
            "reusable": false,
            "max_uses": 1
        });
        let reserved_control_plane_tag_response = app
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
                    .body(Body::from(serde_json::to_vec(
                        &reserved_control_plane_tag_request,
                    )?))?,
            )
            .await?;
        assert_eq!(
            reserved_control_plane_tag_response.status(),
            StatusCode::BAD_REQUEST
        );
        let reserved_control_plane_tag_response =
            axum::body::to_bytes(reserved_control_plane_tag_response.into_body(), usize::MAX)
                .await?;
        let reserved_control_plane_tag_response: Value =
            serde_json::from_slice(&reserved_control_plane_tag_response)?;
        assert_eq!(
            reserved_control_plane_tag_response["error"],
            "the kubernetes-control-plane tag is reserved for Kubernetes HA control-plane enrollment"
        );

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
        assert_eq!(degraded_token.claims.bootstrap_endpoints.len(), 10);
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
        assert!(script.contains("heteronetwork-postgres-autopilot.service"));
        assert!(script.contains("HETERONETWORK_DB_AUTOPILOT_BEARER_TOKEN="));
        assert!(script.contains("HETERONETWORK_DB_CLUSTER_ID_B64="));
        assert!(script.contains("HETERONETWORK_DB_LOCAL_ROLE=edge"));
        assert!(script.contains("Requires=heteronetwork-gateway.service"));
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
        assert_eq!(client_join.peer_map.peers.len(), 3);
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
        assert_eq!(client_configuration.peer_map.peers.len(), 3);
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
        assert_eq!(metrics.node_count, 4);

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

        let same_host_instance =
            enrollment_service_instance(&directory.cluster_id, "public-b", "public-b.example");
        let same_host_directory = ipars_types::ServiceDirectory {
            instances: vec![
                directory.instances[0].clone(),
                ServiceInstance {
                    owner_host_id: directory.instances[0].owner_host_id.clone(),
                    enrollment_signer: true,
                    ..same_host_instance.clone()
                },
            ],
            bootstrap_endpoints: directory.instances[0]
                .endpoints
                .iter()
                .chain(same_host_instance.endpoints.iter())
                .cloned()
                .collect(),
            ..directory.clone()
        };
        let same_host_error = match require_ha_node_enrollment_directory(&same_host_directory, true)
        {
            Ok(_) => return Err("two leases on one host counted as HA".into()),
            Err(error) => error,
        };
        assert_eq!(same_host_error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(require_ha_client_enrollment_directory(&same_host_directory).is_err());

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
    async fn http_bounded_overlay_queries_require_bound_signatures(
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
        let join_service = Arc::new(ControlPlaneJoinService::new(
            plane.clone(),
            ledger,
            IssuerKeyRing::default(),
        ));
        let app = router(ControlPlaneHttpState::new(plane.clone(), join_service));

        let mut source_claims = claims(cluster_id.clone(), issuer.node_id(), key_id.clone());
        source_claims.nonce = "overlay-source".to_string();
        let source = plane
            .register_with_claims(source_claims, registration("overlay-source"))
            .await?
            .node;
        let mut destination_claims = claims(cluster_id, issuer.node_id(), key_id);
        destination_claims.nonce = "overlay-destination".to_string();
        let destination = plane
            .register_with_claims(destination_claims, registration("overlay-destination"))
            .await?
            .node;

        let unsigned = ControlPlaneNodeQueryRequest {
            node_id: source.node_id.clone(),
            request_signature: None,
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/neighbors/query")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&unsigned)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let wrong_operation =
            signed_node_query("overlay-source", ControlPlaneNodeQueryKind::PeerMap);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/neighbors/query")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&wrong_operation)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/neighbors/query")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&signed_node_query(
                        "overlay-source",
                        ControlPlaneNodeQueryKind::NeighborMap,
                    ))?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let neighbor_map: NeighborMap = serde_json::from_slice(&body)?;
        neighbor_map.validate()?;
        assert_eq!(neighbor_map.node_id, source.node_id);
        assert!(neighbor_map
            .neighbors
            .iter()
            .any(|neighbor| neighbor.node.node_id == destination.node_id));

        let mut tampered_path_query = identity_for_node("overlay-source")
            .sign_overlay_path_query(destination.vpn_ip.0, Utc::now())?;
        tampered_path_query.destination = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 250));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/overlay-paths/query")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&tampered_path_query)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let path_query = identity_for_node("overlay-source")
            .sign_overlay_path_query(destination.vpn_ip.0, Utc::now())?;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/overlay-paths/query")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&path_query)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let overlay_path: OverlayPath = serde_json::from_slice(&body)?;
        overlay_path.validate()?;
        assert_eq!(overlay_path.source, source.node_id);
        assert_eq!(overlay_path.destination, destination.vpn_ip.0);
        assert_eq!(overlay_path.ordered_nodes.first(), Some(&source.node_id));
        assert_eq!(
            overlay_path.ordered_nodes.last(),
            Some(&destination.node_id)
        );

        let missing_destination = identity_for_node("overlay-source")
            .sign_overlay_path_query(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 250)), Utc::now())?;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/overlay-paths/query")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&missing_destination)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn http_admin_topology_updates_block_size_without_restart(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("root");
        let cluster_id = ClusterId::new();
        let store = Arc::new(InMemoryStore::default());
        let ledger = Arc::new(InMemoryTokenLedger::default());
        let plane = Arc::new(ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 24)?,
            ),
            store.clone(),
        ));
        let join_service = Arc::new(ControlPlaneJoinService::new(
            plane.clone(),
            ledger,
            IssuerKeyRing::default(),
        ));
        let app = router(
            ControlPlaneHttpState::new(plane.clone(), join_service)
                .require_operator_api_bearer_token(OPERATOR_API_BEARER_TOKEN.to_string()),
        );

        for index in 0..10 {
            let label = format!("topology-node-{index}");
            let mut node_claims = claims(cluster_id.clone(), issuer.node_id(), key_id.clone());
            node_claims.nonce = format!("topology-node-{index}");
            plane
                .register_with_claims(node_claims, registration(&label))
                .await?;
        }

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/topology")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/topology")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let initial: ControlPlaneTopologyResponse =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)?;
        assert_eq!(initial.fanout, 4);
        assert!(initial.group_count >= 1);
        assert_eq!(initial.groups.len(), initial.group_count);
        assert_eq!(initial.nodes.len(), 10);
        assert!(initial.max_observed_degree <= usize::from(initial.max_degree));
        assert!(initial
            .edges
            .iter()
            .any(|edge| edge.placements.iter().any(|placement| {
                placement.kind == ipars_types::api::ControlPlaneTopologyEdgeKind::SiblingCycle
            })));
        assert!(initial
            .groups
            .iter()
            .filter(|group| group.parent_group_id.is_some())
            .all(|group| !group.representatives.is_empty()));
        let observed_edge = initial
            .edges
            .first()
            .cloned()
            .ok_or("topology must contain an edge")?;
        for (local, remote) in [
            (observed_edge.source.clone(), observed_edge.target.clone()),
            (observed_edge.target.clone(), observed_edge.source.clone()),
        ] {
            store
                .upsert_path(PathRecord {
                    key: PeerPathKey::new(local, remote),
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
                })
                .await?;
        }
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/topology")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        let observed: ControlPlaneTopologyResponse =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)?;
        assert!(observed.edges.iter().any(|edge| {
            edge.source == observed_edge.source
                && edge.target == observed_edge.target
                && edge.observed_status == ControlPlaneTopologyEdgeStatus::Connected
        }));

        let mut policy = plane.current_cluster_policy().await?;
        policy.overlay_block_size = 6;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/admin/policy")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(
                        &serde_json::json!({ "cluster_policy": policy }),
                    )?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let updated_policy: ControlPlanePolicyResponse =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)?;
        assert_eq!(updated_policy.cluster_policy.overlay_block_size, 6);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/topology")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        let updated: ControlPlaneTopologyResponse =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)?;
        assert_eq!(updated.fanout, 6);
        assert_eq!(updated.groups.len(), updated.group_count);
        assert_ne!(initial.topology_epoch, updated.topology_epoch);

        let mut invalid_policy = updated_policy.cluster_policy;
        invalid_policy.overlay_block_size = 3;
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/admin/policy")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {OPERATOR_API_BEARER_TOKEN}"),
                    )
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(
                        &serde_json::json!({ "cluster_policy": invalid_policy }),
                    )?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(plane.current_cluster_policy().await?.overlay_block_size, 6);

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
        assert!(response
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.contains("'unsafe-eval'")));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("HeteroNetwork"));
        assert!(!body.contains("Node services"));
        let Some(mermaid_script) = body.find("/ui/vendor/mermaid.min.js") else {
            return Err("Web UI must load the self-origin Mermaid bundle".into());
        };
        let Some(app_script) = body.find("/ui/app.js") else {
            return Err("Web UI must load the application bundle".into());
        };
        assert!(mermaid_script < app_script);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/ui/vendor/mermaid.min.js")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/javascript; charset=utf-8")
        );
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        assert!(body.len() > 100_000);
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("globalThis.mermaid="));

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
        assert!(body.contains("Cloudscape"));
        assert!(body.contains("AppLayout"));
        assert!(body.contains("service_directory"));
        assert!(body.contains("client-enrollment"));
        assert!(!body.contains("function renderServices()"));

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
        assert_eq!(ui_config["session_refresh_endpoint"], Value::Null);
        assert_eq!(ui_config["session_logout_endpoint"], Value::Null);

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
        assert!(body.contains("ipars_control_plane_service_hosts"));
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
