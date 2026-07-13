use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, Stdio};

use anyhow::Context;
use chrono::{Duration, Utc};
use clap::{Args, Parser, Subcommand};
use ipars_agent::FileAgentStateStore;
use ipars_crypto::{IdentityKeyPair, WireGuardKeyPair};
use ipars_relay::encode_relay_datagram_with_route;
use ipars_stun::UdpStunProbe;
use ipars_types::api::{
    AgentNodeRemovalRequest, AgentNodeRemovalResponse, AgentPathEventsResponse,
    AgentPathProbeRequest, AgentPathProbeResponse, AgentPathsResponse, AgentPeerActivityRequest,
    AgentPeerActivityResponse, AgentStatusResponse, AgentWireGuardKeyRotationRequest,
    AgentWireGuardKeyRotationResponse, ControlPlaneMetricsResponse, ControlPlaneNodeQueryKind,
    ControlPlaneNodeQueryRequest, ControlPlanePathsResponse, ControlPlanePolicyResponse,
    JoinNodeRequest, PeerMap, RegisterNodeRequest, RegisterNodeResponse, RelayAdmissionRequest,
    RelayAdmissionResponse, RelayStatusResponse, RevokeTokenRequest, RevokeTokenResponse,
};
use ipars_types::{
    endpoint_addr_is_usable, http_url_is_usable_endpoint, validate_join_token_bootstrap_endpoints,
    BootstrapEndpoint, BootstrapEndpointKind, CandidateSource, ClusterId, EndpointCandidate,
    EndpointCandidateKind, JoinTokenClaims, KeyId, NatProbeObservation, NodeId, PathMetrics,
    PathState, Role, Route, SignedJoinToken, Tag, TokenPolicy, JOIN_TOKEN_NOT_BEFORE_SKEW_SECONDS,
    MAX_JOIN_TOKEN_ALLOWED_ROUTES, MAX_JOIN_TOKEN_IDENTIFIER_BYTES, MAX_JOIN_TOKEN_TAGS,
    MAX_JOIN_TOKEN_TTL_SECONDS,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

const MAX_ISSUER_PRIVATE_KEY_FILE_BYTES: u64 = 64 * 1024;
const MAX_USERSPACE_WIREGUARD_LIFECYCLE_TIMEOUT_SECONDS: u64 = 60 * 60;
const MAX_USERSPACE_WIREGUARD_COMMAND_BYTES: usize = 4096;
const MAX_USERSPACE_WIREGUARD_ARGS: usize = 128;
const MAX_USERSPACE_WIREGUARD_ARG_BYTES: usize = 4096;
const MAX_CLI_HTTP_JSON_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const SANITIZED_INIT_DAEMON_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const SANITIZED_INIT_DAEMON_LOCALE: &str = "C";
const DEFAULT_LOCAL_AGENT_URL: &str = "http://127.0.0.1:9780";
const DEFAULT_LOCAL_RELAY_URL: &str = "http://127.0.0.1:9580";
const DEFAULT_LOCAL_RELAY_UDP: &str = "127.0.0.1:51820";
const DEFAULT_LOCAL_STUN_UDP: &str = "127.0.0.1:3478";
const DEFAULT_AGENT_API_BEARER_TOKEN_SECRET_KEY: &str = "agent-api-token";
const DEFAULT_RELAY_PROBE_TIMEOUT_MS: u64 = 2_000;
const MAX_RELAY_PROBE_TIMEOUT_MS: u64 = 60_000;
const MAX_RELAY_PROBE_PAYLOAD_BYTES: usize = 16 * 1024;
const MIN_RELAY_ADMISSION_BEARER_TOKEN_BYTES: usize = 32;
const MAX_RELAY_ADMISSION_BEARER_TOKEN_BYTES: usize = 512;
const MIN_API_BEARER_TOKEN_BYTES: usize = 32;
const MAX_API_BEARER_TOKEN_BYTES: usize = 512;
const MAX_API_BEARER_TOKEN_FILE_BYTES: u64 = 1024;
const DEFAULT_RELAY_FORWARDER_MAX_SESSIONS: usize = 1024;
const DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS: u64 = 5;
const DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS: u64 = 60;
const DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW: u32 = 3;
const DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS: u64 = 60;
const DEFAULT_RELAY_MAX_SESSIONS: u32 = 10_000;
const DEFAULT_RELAY_MAX_SESSIONS_PER_NODE: u32 = 0;
const DEFAULT_RELAY_MAX_MBPS: u32 = 1000;
const DEFAULT_RELAY_SESSION_TTL_SECONDS: u64 = 300;
const DEFAULT_RELAY_ADMISSION_RATE_LIMIT: u32 = 4096;
const DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS: u64 = 60;
const MAX_RELAY_SESSION_TTL_SECONDS: u64 = 24 * 60 * 60;
const MAX_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS: u64 = 24 * 60 * 60;
const DEFAULT_STUN_ALTERNATE_LISTEN: &str = "0.0.0.0:3480";
const DEFAULT_DOCKER_HOST_INTERFACE: &str = "docker0";
const DEFAULT_DOCKER_ROUTE_INTERVAL_SECONDS: u64 = 60;
const DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS: u64 = 5;
const DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS: u64 = 30;
const MAX_AGENT_HTTP_TIMEOUT_SECONDS: u64 = 60 * 60;
const DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS: u64 = 120;
const DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS: u64 = 180;
const MAX_AGENT_DIRECT_PATH_VERIFICATION_SECONDS: u64 = 24 * 60 * 60;
const DEFAULT_AGENT_PEER_MAP_POLL_INTERVAL_SECONDS: u64 = 30;
const DEFAULT_AGENT_SIGNAL_PATH_INTERVAL_SECONDS: u64 = 30;
const DEFAULT_DOCKER_AGENT_WIREGUARD_LISTEN_PORT: u16 = 51_821;
const DEFAULT_DOCKER_AGENT_PEER_PROBE_PORT: u16 = 51_822;
const DEFAULT_K8S_AGENT_WIREGUARD_LISTEN_PORT: u16 = 51_820;
const DEFAULT_K8S_AGENT_PEER_PROBE_PORT: u16 = 51_821;
const DEFAULT_AGENT_PEER_PROBE_INTERVAL_SECONDS: u64 = 30;
const DEFAULT_AGENT_PEER_PROBE_SAMPLE_COUNT: u16 = 5;
const DEFAULT_AGENT_PEER_PROBE_RESPONSE_TIMEOUT_MILLIS: u64 = 500;
const DEFAULT_AGENT_PEER_PROBE_SAMPLE_INTERVAL_MILLIS: u64 = 20;
const DEFAULT_AGENT_PEER_PROBE_MAX_CONCURRENCY: usize = 32;
const DEFAULT_AGENT_PEER_PROBE_RESPONDER_MAX_REQUESTS_PER_SECOND: u32 = 100;
const DEFAULT_AGENT_PEER_PROBE_OBSERVATION_MAX_AGE_SECONDS: u64 = 120;
const MAX_AGENT_PEER_PROBE_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
const MAX_AGENT_PEER_PROBE_SAMPLE_COUNT: u16 = 64;
const MAX_AGENT_PEER_PROBE_TIMEOUT_MILLIS: u64 = 10_000;
const MAX_AGENT_PEER_PROBE_SAMPLE_INTERVAL_MILLIS: u64 = 10_000;
const MAX_AGENT_PEER_PROBE_MAX_CONCURRENCY: usize = 1024;
const MAX_AGENT_PEER_PROBE_RESPONDER_MAX_REQUESTS_PER_SECOND: u32 = 100_000;
const MAX_AGENT_PEER_PROBE_OBSERVATION_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;
const DEFAULT_USERSPACE_WIREGUARD_READY_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_USERSPACE_WIREGUARD_SHUTDOWN_TIMEOUT_SECONDS: u64 = 5;
const DOCKER_ROOTLESS_COMPOSE_FILE: &str = "docker/compose.rootless.yaml";
const DOCKER_DISCOVERY_COMPOSE_FILE: &str = "docker/compose.docker-discovery.yaml";
const DOCKER_NETWORK_DRIVER_TEMPLATE: &str = "'{{.Driver}}'";
const DOCKER_NETWORK_SUBNETS_TEMPLATE: &str =
    "'{{range .IPAM.Config}}{{if .Subnet}}{{.Subnet}} {{end}}{{end}}'";

#[derive(Debug, Parser)]
#[command(name = "ipars")]
#[command(about = "IPA-RS-HeteroNetwork P2P VPN control CLI")]
struct Cli {
    #[arg(
        long,
        global = true,
        env = "IPARS_AGENT_API_BEARER_TOKEN",
        conflicts_with = "agent_api_bearer_token_path"
    )]
    agent_api_bearer_token: Option<String>,
    #[arg(long, global = true, env = "IPARS_AGENT_API_BEARER_TOKEN_PATH")]
    agent_api_bearer_token_path: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        env = "IPARS_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN",
        conflicts_with = "control_plane_operator_api_bearer_token_path"
    )]
    control_plane_operator_api_bearer_token: Option<String>,
    #[arg(
        long,
        global = true,
        env = "IPARS_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN_PATH"
    )]
    control_plane_operator_api_bearer_token_path: Option<PathBuf>,
    #[arg(long, global = true, env = "IPARS_AGENT_STATE_PATH")]
    agent_state_path: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Default)]
struct AgentApiAuth {
    bearer_token: Option<String>,
}

impl AgentApiAuth {
    fn from_sources(inline: Option<String>, path: Option<PathBuf>) -> anyhow::Result<Self> {
        let bearer_token = match (inline, path) {
            (Some(token), None) => {
                validate_api_bearer_token(&token, "--agent-api-bearer-token")?;
                Some(token)
            }
            (None, Some(path)) => Some(read_api_bearer_token_file(&path, "agent API")?),
            (None, None) => None,
            (Some(_), Some(_)) => {
                anyhow::bail!(
                    "--agent-api-bearer-token conflicts with --agent-api-bearer-token-path"
                )
            }
        };
        Ok(Self { bearer_token })
    }

    fn bearer_token(&self) -> Option<&str> {
        self.bearer_token.as_deref()
    }
}

fn validate_api_bearer_token(token: &str, label: &str) -> anyhow::Result<()> {
    if token.len() < MIN_API_BEARER_TOKEN_BYTES {
        anyhow::bail!("{label} must contain at least {MIN_API_BEARER_TOKEN_BYTES} bytes");
    }
    if token.len() > MAX_API_BEARER_TOKEN_BYTES {
        anyhow::bail!("{label} must not exceed {MAX_API_BEARER_TOKEN_BYTES} bytes");
    }
    if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        anyhow::bail!("{label} must contain only printable non-whitespace ASCII characters");
    }
    Ok(())
}

fn read_api_bearer_token_file(path: &Path, api_label: &str) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path).with_context(|| {
        format!(
            "failed to open {api_label} bearer token file {}",
            path.display()
        )
    })?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect {api_label} bearer token file {}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        anyhow::bail!(
            "{api_label} bearer token path {} must resolve to a regular file",
            path.display()
        );
    }
    if metadata.len() > MAX_API_BEARER_TOKEN_FILE_BYTES {
        anyhow::bail!(
            "{api_label} bearer token file {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_API_BEARER_TOKEN_FILE_BYTES
        );
    }

    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_API_BEARER_TOKEN_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| {
            format!(
                "failed to read {api_label} bearer token from {}",
                path.display()
            )
        })?;
    if bytes.len() as u64 > MAX_API_BEARER_TOKEN_FILE_BYTES {
        anyhow::bail!(
            "{api_label} bearer token file {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_API_BEARER_TOKEN_FILE_BYTES
        );
    }
    let token = String::from_utf8(bytes).with_context(|| {
        format!(
            "failed to decode {api_label} bearer token file {} as UTF-8",
            path.display()
        )
    })?;
    let token = token.trim();
    validate_api_bearer_token(
        token,
        &format!("{api_label} bearer token file {}", path.display()),
    )?;
    Ok(token.to_string())
}

#[derive(Debug, Clone, Default)]
struct ControlPlaneOperatorApiAuth {
    bearer_token: Option<String>,
}

impl ControlPlaneOperatorApiAuth {
    fn from_sources(inline: Option<String>, path: Option<PathBuf>) -> anyhow::Result<Self> {
        let bearer_token = match (inline, path) {
            (Some(token), None) => {
                validate_api_bearer_token(
                    &token,
                    "--control-plane-operator-api-bearer-token",
                )?;
                Some(token)
            }
            (None, Some(path)) => Some(read_api_bearer_token_file(
                &path,
                "control-plane operator API",
            )?),
            (None, None) => None,
            (Some(_), Some(_)) => anyhow::bail!(
                "--control-plane-operator-api-bearer-token conflicts with --control-plane-operator-api-bearer-token-path"
            ),
        };
        Ok(Self { bearer_token })
    }

    fn bearer_token(&self) -> Option<&str> {
        self.bearer_token.as_deref()
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    Init(Box<InitArgs>),
    Join(JoinArgs),
    Status(StatusArgs),
    Peers(PeersArgs),
    Routes(RoutesArgs),
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    Stun {
        #[command(subcommand)]
        command: StunCommand,
    },
    Path {
        #[command(subcommand)]
        command: PathCommand,
    },
    Docker {
        #[command(subcommand)]
        command: DockerCommand,
    },
    K8s {
        #[command(subcommand)]
        command: K8sCommand,
    },
}

#[derive(Debug, Args)]
struct InitArgs {
    #[arg(long)]
    public_endpoint: SocketAddr,
    #[arg(long, default_value = "http", value_parser = parse_bootstrap_scheme)]
    bootstrap_scheme: String,
    #[arg(long, env = "IPARS_ISSUER_KEY_ID", default_value = "root")]
    issuer_key_id: String,
    #[arg(long, env = "IPARS_ISSUER_PRIVATE_KEY")]
    issuer_private_key_b64: Option<String>,
    #[arg(long, env = "IPARS_ISSUER_PRIVATE_KEY_PATH")]
    issuer_private_key_path: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    emit_issuer_private_key: bool,
    #[arg(long, default_value_t = 86_400)]
    token_ttl_seconds: i64,
    #[arg(long, default_value = "edge")]
    default_role: String,
    #[arg(long = "tag")]
    tags: Vec<String>,
    #[arg(long = "allowed-route")]
    allowed_routes: Vec<ipnet::IpNet>,
    #[arg(long, default_value_t = false)]
    allow_relay: bool,
    #[arg(long, conflicts_with = "unlimited_uses")]
    max_uses: Option<u32>,
    #[arg(long, default_value_t = false)]
    unlimited_uses: bool,
    #[arg(long, default_value_t = false)]
    spawn_daemons: bool,
    #[arg(long, env = "IPARS_IPARSD_BIN", default_value = "iparsd")]
    daemon_binary: PathBuf,
    #[arg(long, default_value = "/var/lib/ipars/bootstrap")]
    daemon_state_dir: PathBuf,
    #[arg(long, default_value = "0.0.0.0:8443")]
    control_plane_listen: SocketAddr,
    #[arg(long)]
    control_plane_database_url: Option<String>,
    #[arg(long, env = "IPARS_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN_PATH")]
    control_plane_operator_api_bearer_token_path: Option<PathBuf>,
    #[arg(long, default_value = "0.0.0.0:9443")]
    signal_listen: SocketAddr,
    #[arg(long, default_value = "0.0.0.0:3478")]
    stun_listen: SocketAddr,
    #[arg(long)]
    stun_alternate_listen: Option<SocketAddr>,
    #[arg(long, default_value = "0.0.0.0:3479")]
    stun_http_listen: SocketAddr,
    #[arg(long, default_value = "0.0.0.0:51820")]
    relay_udp_listen: SocketAddr,
    #[arg(long, default_value = "0.0.0.0:9580")]
    relay_http_listen: SocketAddr,
    #[arg(long)]
    relay_admission_url: Option<String>,
}

#[derive(Debug, Args)]
struct JoinArgs {
    token: String,
    #[arg(long)]
    control_plane_url: Option<String>,
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct StatusArgs {
    #[arg(long, env = "IPARS_AGENT_URL", conflicts_with = "control_plane_url")]
    agent_url: Option<String>,
    #[arg(long, env = "IPARS_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,
}

#[derive(Debug, Args)]
struct PeersArgs {
    #[arg(long, env = "IPARS_AGENT_URL", conflicts_with = "control_plane_url")]
    agent_url: Option<String>,
    #[arg(long, env = "IPARS_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,
    #[arg(long, env = "IPARS_NODE_ID")]
    node_id: Option<String>,
}

#[derive(Debug, Args)]
struct RoutesArgs {
    #[arg(long, env = "IPARS_AGENT_URL", conflicts_with = "control_plane_url")]
    agent_url: Option<String>,
    #[arg(long, env = "IPARS_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,
    #[arg(long, env = "IPARS_NODE_ID")]
    node_id: Option<String>,
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    Create(Box<TokenCreateArgs>),
    Revoke(TokenRevokeArgs),
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    Rotate(KeyRotateArgs),
}

#[derive(Debug, Args)]
struct KeyRotateArgs {
    #[arg(long, env = "IPARS_AGENT_URL")]
    agent_url: Option<String>,
    #[arg(long, env = "IPARS_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,
}

#[derive(Debug, Subcommand)]
enum NodeCommand {
    Remove(NodeRemoveArgs),
}

#[derive(Debug, Args)]
struct NodeRemoveArgs {
    #[arg(long, env = "IPARS_AGENT_URL")]
    agent_url: Option<String>,
    #[arg(long, env = "IPARS_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,
}

#[derive(Debug, Args)]
struct TokenCreateArgs {
    #[arg(long)]
    cluster_id: Option<String>,
    #[arg(long, env = "IPARS_ISSUER_KEY_ID", default_value = "root")]
    issuer_key_id: String,
    #[arg(long, env = "IPARS_ISSUER_PRIVATE_KEY")]
    issuer_private_key_b64: Option<String>,
    #[arg(long, env = "IPARS_ISSUER_PRIVATE_KEY_PATH")]
    issuer_private_key_path: Option<PathBuf>,
    #[arg(long, default_value = "edge")]
    role: String,
    #[arg(long = "tag")]
    tags: Vec<String>,
    #[arg(long = "allowed-route")]
    allowed_routes: Vec<ipnet::IpNet>,
    #[arg(long, default_value_t = 86_400)]
    ttl_seconds: i64,
    #[arg(long = "bootstrap")]
    bootstrap_endpoints: Vec<String>,
    #[arg(long = "control-plane-bootstrap")]
    control_plane_bootstrap_endpoints: Vec<String>,
    #[arg(long = "signal-bootstrap")]
    signal_bootstrap_endpoints: Vec<String>,
    #[arg(long = "stun-bootstrap")]
    stun_bootstrap_endpoints: Vec<String>,
    #[arg(long = "relay-bootstrap")]
    relay_bootstrap_endpoints: Vec<String>,
    #[arg(long, default_value_t = false)]
    allow_relay: bool,
    #[arg(long, conflicts_with = "unlimited_uses")]
    max_uses: Option<u32>,
    #[arg(long, default_value_t = false)]
    unlimited_uses: bool,
}

#[derive(Debug, Args)]
struct TokenRevokeArgs {
    #[arg(long)]
    control_plane_url: String,
    #[arg(long)]
    cluster_id: String,
    #[arg(long)]
    nonce: String,
    #[arg(long, env = "IPARS_ISSUER_KEY_ID", default_value = "root")]
    issuer_key_id: String,
    #[arg(long, env = "IPARS_ISSUER_PRIVATE_KEY")]
    issuer_private_key_b64: Option<String>,
    #[arg(long, env = "IPARS_ISSUER_PRIVATE_KEY_PATH")]
    issuer_private_key_path: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum RelayCommand {
    Status(RelayStatusArgs),
    Probe(Box<RelayProbeArgs>),
}

#[derive(Debug, Args)]
struct RelayStatusArgs {
    #[arg(long, env = "IPARS_RELAY_URL")]
    relay_url: Option<String>,
}

#[derive(Debug, Args)]
struct RelayProbeArgs {
    #[arg(long, env = "IPARS_RELAY_URL")]
    relay_url: Option<String>,
    #[arg(long, env = "IPARS_RELAY_ADMISSION_BEARER_TOKEN")]
    relay_admission_bearer_token: Option<String>,
    #[arg(long, env = "IPARS_RELAY_UDP", default_value = DEFAULT_LOCAL_RELAY_UDP)]
    relay_udp: SocketAddr,
    #[arg(long, default_value = "probe-left")]
    left_node_id: String,
    #[arg(long, default_value = "probe-right")]
    right_node_id: String,
    #[arg(long, default_value = "127.0.0.1:0")]
    left_bind: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:0")]
    right_bind: SocketAddr,
    #[arg(long, default_value = "ipars-relay-probe")]
    payload: String,
    #[arg(long)]
    send_invalid_credential: bool,
    #[arg(long, default_value_t = DEFAULT_RELAY_PROBE_TIMEOUT_MS)]
    timeout_ms: u64,
}

#[derive(Debug, Subcommand)]
enum StunCommand {
    Probe(StunProbeArgs),
}

#[derive(Debug, Args)]
struct StunProbeArgs {
    #[arg(long, env = "IPARS_STUN_SERVER", default_value = DEFAULT_LOCAL_STUN_UDP)]
    stun_server: SocketAddr,
    #[arg(long, default_value = "0.0.0.0:0")]
    local_bind: SocketAddr,
}

#[derive(Debug, Subcommand)]
enum PathCommand {
    Status(PathStatusArgs),
    Events(PathEventsArgs),
    Activity(PathActivityArgs),
    Probe(PathProbeArgs),
}

#[derive(Debug, Args)]
struct PathStatusArgs {
    #[arg(long, env = "IPARS_AGENT_URL", conflicts_with = "control_plane_url")]
    agent_url: Option<String>,
    #[arg(long, env = "IPARS_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,
    #[arg(long, env = "IPARS_NODE_ID")]
    node_id: Option<String>,
}

#[derive(Debug, Args)]
struct PathEventsArgs {
    #[arg(long, env = "IPARS_AGENT_URL")]
    agent_url: Option<String>,
}

#[derive(Debug, Args)]
struct PathActivityArgs {
    #[arg(long, env = "IPARS_AGENT_URL")]
    agent_url: Option<String>,
    #[arg(long)]
    peer: String,
    #[arg(long, default_value_t = false)]
    pin: bool,
}

#[derive(Debug, Args)]
struct PathProbeArgs {
    #[arg(long, env = "IPARS_AGENT_URL")]
    agent_url: Option<String>,
    #[arg(long)]
    peer: String,
    #[arg(long, value_parser = parse_path_state)]
    state: PathState,
    #[arg(long)]
    latency_ms: Option<f32>,
    #[arg(long, default_value_t = 0)]
    loss_ppm: u32,
    #[arg(long)]
    jitter_ms: Option<f32>,
    #[arg(long)]
    relay_load: Option<f32>,
    #[arg(long, default_value_t = 1.0)]
    stability: f32,
    #[arg(long, default_value_t = 0)]
    cost: u32,
    #[arg(long, default_value_t = false)]
    policy_denied: bool,
    #[arg(long, default_value_t = false)]
    pin: bool,
    #[arg(long)]
    relay_node: Option<String>,
    #[arg(long)]
    candidate_addr: Option<SocketAddr>,
    #[arg(long, value_parser = parse_candidate_kind)]
    candidate_kind: Option<EndpointCandidateKind>,
    #[arg(long)]
    candidate_priority: Option<u16>,
    #[arg(long)]
    candidate_cost: Option<u32>,
    #[arg(long, value_parser = parse_candidate_source)]
    candidate_source: Option<CandidateSource>,
}

#[derive(Debug, Subcommand)]
enum DockerCommand {
    Install(Box<DockerInstallArgs>),
}

#[derive(Debug, Subcommand)]
enum K8sCommand {
    Install(Box<K8sInstallArgs>),
}

#[derive(Debug, Args, Clone, Copy, PartialEq, Eq)]
struct AgentPeerProbeInstallArgs {
    #[arg(long = "disable-agent-peer-probe", default_value_t = false)]
    disabled: bool,
    #[arg(long = "agent-peer-probe-port")]
    port: Option<u16>,
    #[arg(
        long = "agent-peer-probe-interval-seconds",
        default_value_t = DEFAULT_AGENT_PEER_PROBE_INTERVAL_SECONDS
    )]
    interval_seconds: u64,
    #[arg(
        long = "agent-peer-probe-sample-count",
        default_value_t = DEFAULT_AGENT_PEER_PROBE_SAMPLE_COUNT
    )]
    sample_count: u16,
    #[arg(
        long = "agent-peer-probe-response-timeout-millis",
        default_value_t = DEFAULT_AGENT_PEER_PROBE_RESPONSE_TIMEOUT_MILLIS
    )]
    response_timeout_millis: u64,
    #[arg(
        long = "agent-peer-probe-sample-interval-millis",
        default_value_t = DEFAULT_AGENT_PEER_PROBE_SAMPLE_INTERVAL_MILLIS
    )]
    sample_interval_millis: u64,
    #[arg(
        long = "agent-peer-probe-max-concurrency",
        default_value_t = DEFAULT_AGENT_PEER_PROBE_MAX_CONCURRENCY
    )]
    max_concurrency: usize,
    #[arg(
        long = "agent-peer-probe-responder-max-requests-per-second",
        default_value_t = DEFAULT_AGENT_PEER_PROBE_RESPONDER_MAX_REQUESTS_PER_SECOND
    )]
    responder_max_requests_per_second: u32,
    #[arg(
        long = "agent-peer-probe-observation-max-age-seconds",
        default_value_t = DEFAULT_AGENT_PEER_PROBE_OBSERVATION_MAX_AGE_SECONDS
    )]
    observation_max_age_seconds: u64,
}

impl Default for AgentPeerProbeInstallArgs {
    fn default() -> Self {
        Self {
            disabled: false,
            port: None,
            interval_seconds: DEFAULT_AGENT_PEER_PROBE_INTERVAL_SECONDS,
            sample_count: DEFAULT_AGENT_PEER_PROBE_SAMPLE_COUNT,
            response_timeout_millis: DEFAULT_AGENT_PEER_PROBE_RESPONSE_TIMEOUT_MILLIS,
            sample_interval_millis: DEFAULT_AGENT_PEER_PROBE_SAMPLE_INTERVAL_MILLIS,
            max_concurrency: DEFAULT_AGENT_PEER_PROBE_MAX_CONCURRENCY,
            responder_max_requests_per_second:
                DEFAULT_AGENT_PEER_PROBE_RESPONDER_MAX_REQUESTS_PER_SECOND,
            observation_max_age_seconds: DEFAULT_AGENT_PEER_PROBE_OBSERVATION_MAX_AGE_SECONDS,
        }
    }
}

#[derive(Debug, Args)]
struct DockerInstallArgs {
    #[arg(long, default_value = "docker/compose.yaml")]
    compose_file: PathBuf,
    #[arg(long, default_value = "ipars")]
    project_name: String,
    #[arg(long, default_value_t = false)]
    rootless: bool,
    #[arg(long, default_value_t = false)]
    docker_discover_networks: bool,
    #[arg(long = "docker-network")]
    docker_networks: Vec<String>,
    #[arg(long)]
    docker_api_socket: Option<PathBuf>,
    #[arg(long)]
    docker_container_namespace: Option<String>,
    #[arg(long, default_value = "docker0")]
    docker_host_interface: String,
    #[arg(long = "docker-container-cidr")]
    docker_container_cidrs: Vec<ipnet::IpNet>,
    #[arg(long = "disable-docker-expose-host-routes", default_value_t = false)]
    disable_docker_expose_host_routes: bool,
    #[arg(long = "docker-route-interval-seconds", default_value_t = 60)]
    docker_route_interval_seconds: u64,
    #[arg(
        long = "agent-http-connect-timeout-seconds",
        default_value_t = DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS
    )]
    agent_http_connect_timeout_seconds: u64,
    #[arg(
        long = "agent-http-request-timeout-seconds",
        default_value_t = DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS
    )]
    agent_http_request_timeout_seconds: u64,
    #[arg(
        long = "agent-direct-path-probe-timeout-seconds",
        default_value_t = DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS
    )]
    agent_direct_path_probe_timeout_seconds: u64,
    #[arg(
        long = "agent-direct-handshake-max-age-seconds",
        default_value_t = DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS
    )]
    agent_direct_handshake_max_age_seconds: u64,
    #[command(flatten)]
    agent_peer_probe: AgentPeerProbeInstallArgs,
    #[arg(
        long = "agent-runtime-backend",
        default_value = "linux-command",
        value_parser = parse_agent_runtime_backend
    )]
    agent_runtime_backend: String,
    #[arg(long = "route-backend", default_value = "command", value_parser = parse_route_backend)]
    route_backend: String,
    #[arg(long)]
    userspace_wireguard_command: Option<String>,
    #[arg(long = "userspace-wireguard-arg")]
    userspace_wireguard_args: Vec<String>,
    #[arg(
        long = "userspace-wireguard-ready-timeout-seconds",
        default_value_t = DEFAULT_USERSPACE_WIREGUARD_READY_TIMEOUT_SECONDS
    )]
    userspace_wireguard_ready_timeout_seconds: u64,
    #[arg(
        long = "userspace-wireguard-shutdown-timeout-seconds",
        default_value_t = DEFAULT_USERSPACE_WIREGUARD_SHUTDOWN_TIMEOUT_SECONDS
    )]
    userspace_wireguard_shutdown_timeout_seconds: u64,
    #[arg(long = "relay-public-endpoint")]
    relay_public_endpoint: Option<String>,
    #[arg(long = "relay-admission-url")]
    relay_admission_url: Option<String>,
    #[arg(long = "relay-status-url")]
    relay_status_url: Option<String>,
    #[arg(long = "relay-max-sessions", default_value_t = DEFAULT_RELAY_MAX_SESSIONS)]
    relay_max_sessions: u32,
    #[arg(long = "relay-max-sessions-per-node", default_value_t = DEFAULT_RELAY_MAX_SESSIONS_PER_NODE)]
    relay_max_sessions_per_node: u32,
    #[arg(long = "relay-max-mbps", default_value_t = DEFAULT_RELAY_MAX_MBPS)]
    relay_max_mbps: u32,
    #[arg(long = "relay-session-ttl-seconds", default_value_t = DEFAULT_RELAY_SESSION_TTL_SECONDS)]
    relay_session_ttl_seconds: u64,
    #[arg(long = "relay-admission-rate-limit", default_value_t = DEFAULT_RELAY_ADMISSION_RATE_LIMIT)]
    relay_admission_rate_limit: u32,
    #[arg(long = "relay-admission-rate-limit-window-seconds", default_value_t = DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS)]
    relay_admission_rate_limit_window_seconds: u64,
    #[arg(long = "relay-forwarder-endpoint")]
    relay_forwarder_endpoint: Option<String>,
    #[arg(
        long = "relay-forwarder-bind",
        requires = "relay_forwarder_wireguard_endpoint"
    )]
    relay_forwarder_bind: Option<String>,
    #[arg(
        long = "relay-forwarder-wireguard-endpoint",
        requires = "relay_forwarder_bind"
    )]
    relay_forwarder_wireguard_endpoint: Option<String>,
    #[arg(long = "relay-forwarder-netns", requires = "relay_forwarder_bind")]
    relay_forwarder_netns: Option<String>,
    #[arg(long = "relay-forwarder-max-sessions", default_value_t = DEFAULT_RELAY_FORWARDER_MAX_SESSIONS)]
    relay_forwarder_max_sessions: usize,
    #[arg(long = "relay-forwarder-restart-backoff-seconds", default_value_t = DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS)]
    relay_forwarder_restart_backoff_seconds: u64,
    #[arg(long = "relay-forwarder-crash-window-seconds", default_value_t = DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS)]
    relay_forwarder_crash_window_seconds: u64,
    #[arg(long = "relay-forwarder-max-crashes-per-window", default_value_t = DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW)]
    relay_forwarder_max_crashes_per_window: u32,
    #[arg(long = "relay-forwarder-crash-cooldown-seconds", default_value_t = DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS)]
    relay_forwarder_crash_cooldown_seconds: u64,
}

#[derive(Debug, Args, Clone, Default)]
struct K8sProbeArgs {
    #[arg(long = "agent-liveness-path", value_parser = parse_kubernetes_http_probe_path)]
    liveness_path: Option<String>,
    #[arg(long = "agent-liveness-initial-delay-seconds", value_parser = parse_kubernetes_non_negative_i32)]
    liveness_initial_delay_seconds: Option<u32>,
    #[arg(long = "agent-liveness-period-seconds", value_parser = parse_kubernetes_non_negative_i32)]
    liveness_period_seconds: Option<u32>,
    #[arg(long = "agent-liveness-timeout-seconds", value_parser = parse_kubernetes_non_negative_i32)]
    liveness_timeout_seconds: Option<u32>,
    #[arg(long = "agent-liveness-failure-threshold", value_parser = parse_kubernetes_non_negative_i32)]
    liveness_failure_threshold: Option<u32>,
    #[arg(long = "agent-readiness-path", value_parser = parse_kubernetes_http_probe_path)]
    readiness_path: Option<String>,
    #[arg(long = "agent-readiness-initial-delay-seconds", value_parser = parse_kubernetes_non_negative_i32)]
    readiness_initial_delay_seconds: Option<u32>,
    #[arg(long = "agent-readiness-period-seconds", value_parser = parse_kubernetes_non_negative_i32)]
    readiness_period_seconds: Option<u32>,
    #[arg(long = "agent-readiness-timeout-seconds", value_parser = parse_kubernetes_non_negative_i32)]
    readiness_timeout_seconds: Option<u32>,
    #[arg(long = "agent-readiness-failure-threshold", value_parser = parse_kubernetes_non_negative_i32)]
    readiness_failure_threshold: Option<u32>,
    #[arg(long = "agent-startup-path", value_parser = parse_kubernetes_http_probe_path)]
    startup_path: Option<String>,
    #[arg(long = "agent-startup-initial-delay-seconds", value_parser = parse_kubernetes_non_negative_i32)]
    startup_initial_delay_seconds: Option<u32>,
    #[arg(long = "agent-startup-period-seconds", value_parser = parse_kubernetes_non_negative_i32)]
    startup_period_seconds: Option<u32>,
    #[arg(long = "agent-startup-timeout-seconds", value_parser = parse_kubernetes_non_negative_i32)]
    startup_timeout_seconds: Option<u32>,
    #[arg(long = "agent-startup-failure-threshold", value_parser = parse_kubernetes_non_negative_i32)]
    startup_failure_threshold: Option<u32>,
}

impl K8sProbeArgs {
    fn liveness_configured(&self) -> bool {
        self.liveness_path.is_some()
            || self.liveness_initial_delay_seconds.is_some()
            || self.liveness_period_seconds.is_some()
            || self.liveness_timeout_seconds.is_some()
            || self.liveness_failure_threshold.is_some()
    }

    fn readiness_configured(&self) -> bool {
        self.readiness_path.is_some()
            || self.readiness_initial_delay_seconds.is_some()
            || self.readiness_period_seconds.is_some()
            || self.readiness_timeout_seconds.is_some()
            || self.readiness_failure_threshold.is_some()
    }

    fn startup_configured(&self) -> bool {
        self.startup_path.is_some()
            || self.startup_initial_delay_seconds.is_some()
            || self.startup_period_seconds.is_some()
            || self.startup_timeout_seconds.is_some()
            || self.startup_failure_threshold.is_some()
    }
}

#[derive(Debug, Args)]
struct K8sInstallArgs {
    #[arg(long, default_value = "ipars")]
    release: String,
    #[arg(long, default_value = "ipars-system")]
    namespace: String,
    #[arg(long, default_value = "charts/ipars")]
    chart: PathBuf,
    #[arg(long = "chart-name-override", value_parser = parse_kubernetes_chart_name_override)]
    chart_name_override: Option<String>,
    #[arg(long = "chart-fullname-override", value_parser = parse_kubernetes_chart_name_override)]
    chart_fullname_override: Option<String>,
    #[arg(long, default_value = "ipars-join-token")]
    join_token_secret: String,
    #[arg(long, default_value = "token")]
    join_token_key: String,
    #[arg(long = "cluster-control-plane-url", value_parser = parse_kubernetes_http_api_base_url)]
    cluster_control_plane_url: Option<String>,
    #[arg(long = "cluster-signal-url", value_parser = parse_kubernetes_http_api_base_url)]
    cluster_signal_url: Option<String>,
    #[arg(long = "cluster-stun-endpoint", value_parser = parse_kubernetes_stun_endpoint)]
    cluster_stun_endpoint: Option<String>,
    #[arg(long = "image-repository", value_parser = parse_container_image_repository)]
    image_repository: Option<String>,
    #[arg(long = "image-tag", value_parser = parse_container_image_tag)]
    image_tag: Option<String>,
    #[arg(long = "image-pull-policy", value_parser = parse_kubernetes_image_pull_policy)]
    image_pull_policy: Option<String>,
    #[arg(long = "image-pull-secret", value_parser = parse_kubernetes_image_pull_secret_name)]
    image_pull_secrets: Vec<String>,
    #[arg(long = "agent-privileged", default_value_t = false)]
    agent_privileged: bool,
    #[arg(long = "agent-add-capability", value_parser = parse_linux_capability)]
    agent_add_capabilities: Vec<String>,
    #[arg(long = "agent-drop-capability", value_parser = parse_linux_capability)]
    agent_drop_capabilities: Vec<String>,
    #[arg(long = "disable-agent-privilege-escalation", default_value_t = false)]
    disable_agent_privilege_escalation: bool,
    #[arg(long = "agent-read-only-root-filesystem", default_value_t = false)]
    agent_read_only_root_filesystem: bool,
    #[arg(long = "agent-seccomp-profile", value_parser = parse_kubernetes_seccomp_profile_type)]
    agent_seccomp_profile: Option<String>,
    #[arg(long = "agent-seccomp-localhost-profile", value_parser = parse_kubernetes_seccomp_localhost_profile)]
    agent_seccomp_localhost_profile: Option<String>,
    #[arg(long = "agent-run-as-user", value_parser = parse_kubernetes_non_negative_i64)]
    agent_run_as_user: Option<u64>,
    #[arg(long = "agent-run-as-group", value_parser = parse_kubernetes_non_negative_i64)]
    agent_run_as_group: Option<u64>,
    #[arg(long = "agent-run-as-non-root", default_value_t = false)]
    agent_run_as_non_root: bool,
    #[arg(long = "agent-fs-group", value_parser = parse_kubernetes_non_negative_i64)]
    agent_fs_group: Option<u64>,
    #[arg(long = "agent-fs-group-change-policy", value_parser = parse_kubernetes_fs_group_change_policy)]
    agent_fs_group_change_policy: Option<String>,
    #[arg(long = "agent-supplemental-group", value_parser = parse_kubernetes_non_negative_i64)]
    agent_supplemental_groups: Vec<u64>,
    #[arg(long, default_value_t = false)]
    kubernetes_discover_services: bool,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    kubernetes_discover_api_server: bool,
    #[arg(long = "kubernetes-api-server-cidr")]
    kubernetes_api_server_cidrs: Vec<ipnet::IpNet>,
    #[arg(long = "kubernetes-service-cidr")]
    kubernetes_service_cidrs: Vec<ipnet::IpNet>,
    #[arg(long = "kubernetes-namespace")]
    kubernetes_namespaces: Vec<String>,
    #[arg(long)]
    kubernetes_service_label_selector: Option<String>,
    #[arg(long)]
    kubernetes_route_provider: Option<String>,
    #[arg(long, default_value_t = 60)]
    kubernetes_route_interval_seconds: u64,
    #[arg(
        long = "agent-runtime-backend",
        default_value = "linux-command",
        value_parser = parse_agent_runtime_backend
    )]
    agent_runtime_backend: String,
    #[arg(long = "agent-wireguard-listen-port", value_parser = parse_kubernetes_service_port)]
    agent_wireguard_listen_port: Option<u16>,
    #[arg(long = "agent-stun-bind", value_parser = parse_kubernetes_agent_stun_bind)]
    agent_stun_bind: Option<String>,
    #[arg(long = "route-backend", default_value = "command", value_parser = parse_route_backend)]
    route_backend: String,
    #[arg(long = "disable-agent-peer-map", default_value_t = false)]
    disable_agent_peer_map: bool,
    #[arg(long = "agent-peer-map-poll-interval-seconds", default_value_t = 30)]
    agent_peer_map_poll_interval_seconds: u64,
    #[arg(
        long = "agent-http-connect-timeout-seconds",
        default_value_t = DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS
    )]
    agent_http_connect_timeout_seconds: u64,
    #[arg(
        long = "agent-http-request-timeout-seconds",
        default_value_t = DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS
    )]
    agent_http_request_timeout_seconds: u64,
    #[arg(
        long = "agent-direct-path-probe-timeout-seconds",
        default_value_t = DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS
    )]
    agent_direct_path_probe_timeout_seconds: u64,
    #[arg(
        long = "agent-direct-handshake-max-age-seconds",
        default_value_t = DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS
    )]
    agent_direct_handshake_max_age_seconds: u64,
    #[command(flatten)]
    agent_peer_probe: AgentPeerProbeInstallArgs,
    #[arg(long, default_value_t = false)]
    expose_agent_api: bool,
    #[arg(long, default_value_t = false)]
    allow_public_service_exposure: bool,
    #[arg(long, default_value_t = false)]
    allow_unrestricted_load_balancer: bool,
    #[arg(long, default_value_t = false)]
    allow_cluster_external_traffic_policy: bool,
    #[arg(long = "enable-network-policy", default_value_t = false)]
    enable_network_policy: bool,
    #[arg(
        long = "network-policy-acknowledge-host-network",
        default_value_t = false,
        requires = "enable_network_policy"
    )]
    network_policy_acknowledge_host_network: bool,
    #[arg(long = "disable-rbac", default_value_t = false)]
    disable_rbac: bool,
    #[arg(long = "disable-service-account-creation", default_value_t = false)]
    disable_service_account_creation: bool,
    #[arg(long = "service-account-name", value_parser = parse_kubernetes_service_account_name)]
    service_account_name: Option<String>,
    #[arg(long = "service-account-annotation", value_parser = parse_key_value)]
    service_account_annotations: Vec<KeyValueArg>,
    #[arg(long = "agent-pod-label", value_parser = parse_kubernetes_label_pair)]
    agent_pod_labels: Vec<KeyValueArg>,
    #[arg(long = "agent-pod-annotation", value_parser = parse_key_value)]
    agent_pod_annotations: Vec<KeyValueArg>,
    #[arg(long = "agent-priority-class", value_parser = parse_kubernetes_priority_class_name)]
    agent_priority_class: Option<String>,
    #[arg(long = "agent-scheduler-name", value_parser = parse_kubernetes_scheduler_name)]
    agent_scheduler_name: Option<String>,
    #[arg(long = "agent-runtime-class", value_parser = parse_kubernetes_runtime_class_name)]
    agent_runtime_class: Option<String>,
    #[arg(long = "agent-node-selector", value_parser = parse_kubernetes_label_pair)]
    agent_node_selectors: Vec<KeyValueArg>,
    #[arg(long = "agent-node-affinity-required", value_parser = parse_kubernetes_node_affinity_required_arg)]
    agent_node_affinity_required: Vec<KubernetesNodeAffinityExpressionArg>,
    #[arg(long = "agent-node-affinity-preferred", value_parser = parse_kubernetes_node_affinity_preferred_arg)]
    agent_node_affinity_preferred: Vec<KubernetesPreferredNodeAffinityArg>,
    #[arg(long = "agent-pod-affinity-required", value_parser = parse_kubernetes_pod_affinity_required_arg)]
    agent_pod_affinity_required: Vec<KubernetesPodAffinityTermArg>,
    #[arg(long = "agent-pod-affinity-preferred", value_parser = parse_kubernetes_pod_affinity_preferred_arg)]
    agent_pod_affinity_preferred: Vec<KubernetesPreferredPodAffinityArg>,
    #[arg(long = "agent-pod-anti-affinity-required", value_parser = parse_kubernetes_pod_affinity_required_arg)]
    agent_pod_anti_affinity_required: Vec<KubernetesPodAffinityTermArg>,
    #[arg(long = "agent-pod-anti-affinity-preferred", value_parser = parse_kubernetes_pod_affinity_preferred_arg)]
    agent_pod_anti_affinity_preferred: Vec<KubernetesPreferredPodAffinityArg>,
    #[arg(long = "agent-toleration", value_parser = parse_kubernetes_toleration_arg)]
    agent_tolerations: Vec<KubernetesTolerationArg>,
    #[arg(long = "agent-topology-spread", value_parser = parse_kubernetes_topology_spread_arg)]
    agent_topology_spreads: Vec<KubernetesTopologySpreadArg>,
    #[arg(long = "disable-agent-host-network", default_value_t = false)]
    disable_agent_host_network: bool,
    #[arg(long = "disable-agent-service-account-token", default_value_t = false)]
    disable_agent_service_account_token: bool,
    #[arg(long = "agent-dns-policy", value_parser = parse_kubernetes_dns_policy)]
    agent_dns_policy: Option<String>,
    #[arg(long = "agent-state-host-path", value_parser = parse_kubernetes_absolute_path)]
    agent_state_host_path: Option<String>,
    #[arg(long = "agent-state-mount-path", value_parser = parse_kubernetes_absolute_path)]
    agent_state_mount_path: Option<String>,
    #[arg(long = "agent-state-host-path-type", value_parser = parse_kubernetes_host_path_type)]
    agent_state_host_path_type: Option<String>,
    #[arg(long = "disable-agent-liveness-probe", default_value_t = false)]
    disable_agent_liveness_probe: bool,
    #[arg(long = "disable-agent-readiness-probe", default_value_t = false)]
    disable_agent_readiness_probe: bool,
    #[arg(long = "disable-agent-startup-probe", default_value_t = false)]
    disable_agent_startup_probe: bool,
    #[command(flatten)]
    agent_probes: K8sProbeArgs,
    #[arg(long = "agent-pre-stop-sleep-seconds", value_parser = parse_kubernetes_positive_i32)]
    agent_pre_stop_sleep_seconds: Option<u32>,
    #[arg(long = "agent-termination-grace-period-seconds", value_parser = parse_kubernetes_non_negative_i64)]
    agent_termination_grace_period_seconds: Option<u64>,
    #[arg(long = "agent-resource-request-cpu", value_parser = parse_kubernetes_resource_quantity)]
    agent_resource_request_cpu: Option<String>,
    #[arg(long = "agent-resource-request-memory", value_parser = parse_kubernetes_resource_quantity)]
    agent_resource_request_memory: Option<String>,
    #[arg(long = "agent-resource-limit-cpu", value_parser = parse_kubernetes_resource_quantity)]
    agent_resource_limit_cpu: Option<String>,
    #[arg(long = "agent-resource-limit-memory", value_parser = parse_kubernetes_resource_quantity)]
    agent_resource_limit_memory: Option<String>,
    #[arg(long = "agent-update-strategy", value_parser = parse_kubernetes_daemonset_update_strategy)]
    agent_update_strategy: Option<String>,
    #[arg(long = "agent-rollout-max-unavailable", value_parser = parse_kubernetes_int_or_percent)]
    agent_rollout_max_unavailable: Option<String>,
    #[arg(long = "agent-rollout-max-surge", value_parser = parse_kubernetes_int_or_percent)]
    agent_rollout_max_surge: Option<String>,
    #[arg(long = "agent-min-ready-seconds", value_parser = parse_kubernetes_non_negative_i32)]
    agent_min_ready_seconds: Option<u32>,
    #[arg(long = "agent-revision-history-limit", value_parser = parse_kubernetes_non_negative_i32)]
    agent_revision_history_limit: Option<u32>,
    #[arg(long = "agent-pdb-min-available", value_parser = parse_kubernetes_int_or_percent)]
    agent_pdb_min_available: Option<String>,
    #[arg(long = "agent-pdb-max-unavailable", value_parser = parse_kubernetes_int_or_percent)]
    agent_pdb_max_unavailable: Option<String>,
    #[arg(long, default_value = "ClusterIP", value_parser = parse_kubernetes_service_type)]
    agent_api_service_type: String,
    #[arg(long = "agent-api-cluster-ip", value_parser = parse_kubernetes_service_ip, requires = "expose_agent_api")]
    agent_api_cluster_ip: Option<IpAddr>,
    #[arg(long = "agent-api-secondary-cluster-ip", value_parser = parse_kubernetes_service_ip, requires_all = ["expose_agent_api", "agent_api_cluster_ip"])]
    agent_api_secondary_cluster_ip: Option<IpAddr>,
    #[arg(long = "agent-api-port", value_parser = parse_kubernetes_service_port, requires = "expose_agent_api")]
    agent_api_port: Option<u16>,
    #[arg(long = "agent-api-target-port", value_parser = parse_kubernetes_service_port)]
    agent_api_target_port: Option<u16>,
    #[arg(long = "agent-api-node-port", value_parser = parse_kubernetes_node_port, requires = "expose_agent_api")]
    agent_api_node_port: Option<u16>,
    #[arg(long = "agent-api-app-protocol", value_parser = parse_kubernetes_app_protocol, requires = "expose_agent_api")]
    agent_api_app_protocol: Option<String>,
    #[arg(
        long = "agent-api-publish-not-ready-addresses",
        default_value_t = false,
        requires = "expose_agent_api"
    )]
    agent_api_publish_not_ready_addresses: bool,
    #[arg(long = "agent-api-load-balancer-class", value_parser = parse_kubernetes_load_balancer_class, requires = "expose_agent_api")]
    agent_api_load_balancer_class: Option<String>,
    #[arg(long = "agent-api-load-balancer-ip", value_parser = parse_kubernetes_service_ip, requires = "expose_agent_api")]
    agent_api_load_balancer_ip: Option<IpAddr>,
    #[arg(long = "agent-api-external-ip", value_parser = parse_kubernetes_service_ip, requires = "expose_agent_api")]
    agent_api_external_ips: Vec<IpAddr>,
    #[arg(long = "agent-api-health-check-node-port", value_parser = parse_kubernetes_node_port, requires = "expose_agent_api")]
    agent_api_health_check_node_port: Option<u16>,
    #[arg(
        long = "agent-api-disable-load-balancer-node-ports",
        default_value_t = false,
        requires = "expose_agent_api"
    )]
    agent_api_disable_load_balancer_node_ports: bool,
    #[arg(long = "agent-api-ip-family-policy", value_parser = parse_kubernetes_ip_family_policy, requires = "expose_agent_api")]
    agent_api_ip_family_policy: Option<String>,
    #[arg(long = "agent-api-ip-family", value_parser = parse_kubernetes_ip_family, requires = "expose_agent_api")]
    agent_api_ip_families: Vec<String>,
    #[arg(long = "agent-api-allow-source-cidr", requires = "expose_agent_api")]
    agent_api_allow_source_cidrs: Vec<ipnet::IpNet>,
    #[arg(
        long = "agent-api-network-policy-cidr",
        requires_all = ["enable_network_policy", "expose_agent_api"]
    )]
    agent_api_network_policy_cidrs: Vec<ipnet::IpNet>,
    #[arg(long = "agent-api-internal-traffic-policy", value_parser = parse_kubernetes_internal_traffic_policy, requires = "expose_agent_api")]
    agent_api_internal_traffic_policy: Option<String>,
    #[arg(long = "agent-api-traffic-distribution", value_parser = parse_kubernetes_traffic_distribution, requires = "expose_agent_api")]
    agent_api_traffic_distribution: Option<String>,
    #[arg(long = "agent-api-session-affinity", value_parser = parse_kubernetes_session_affinity, requires = "expose_agent_api")]
    agent_api_session_affinity: Option<String>,
    #[arg(long = "agent-api-session-affinity-timeout-seconds", value_parser = parse_kubernetes_session_affinity_timeout_seconds, requires = "expose_agent_api")]
    agent_api_session_affinity_timeout_seconds: Option<u32>,
    #[arg(long, default_value = "Local", value_parser = parse_kubernetes_external_traffic_policy)]
    agent_api_external_traffic_policy: String,
    #[arg(long = "agent-api-service-annotation", value_parser = parse_key_value, requires = "expose_agent_api")]
    agent_api_service_annotations: Vec<KeyValueArg>,
    #[arg(
        long,
        default_value_t = false,
        requires_all = ["relay_public_endpoint", "relay_admission_url"]
    )]
    expose_relay: bool,
    #[arg(long, default_value = "LoadBalancer", value_parser = parse_kubernetes_service_type)]
    relay_service_type: String,
    #[arg(long = "relay-cluster-ip", value_parser = parse_kubernetes_service_ip, requires = "expose_relay")]
    relay_cluster_ip: Option<IpAddr>,
    #[arg(long = "relay-secondary-cluster-ip", value_parser = parse_kubernetes_service_ip, requires_all = ["expose_relay", "relay_cluster_ip"])]
    relay_secondary_cluster_ip: Option<IpAddr>,
    #[arg(long = "relay-udp-port", value_parser = parse_kubernetes_service_port, requires = "expose_relay")]
    relay_udp_port: Option<u16>,
    #[arg(long = "relay-udp-target-port", value_parser = parse_kubernetes_service_port, requires = "expose_relay")]
    relay_udp_target_port: Option<u16>,
    #[arg(long = "relay-http-port", value_parser = parse_kubernetes_service_port, requires = "expose_relay")]
    relay_http_port: Option<u16>,
    #[arg(long = "relay-http-target-port", value_parser = parse_kubernetes_service_port, requires = "expose_relay")]
    relay_http_target_port: Option<u16>,
    #[arg(long = "relay-udp-node-port", value_parser = parse_kubernetes_node_port, requires = "expose_relay")]
    relay_udp_node_port: Option<u16>,
    #[arg(long = "relay-http-node-port", value_parser = parse_kubernetes_node_port, requires = "expose_relay")]
    relay_http_node_port: Option<u16>,
    #[arg(long = "relay-udp-app-protocol", value_parser = parse_kubernetes_app_protocol, requires = "expose_relay")]
    relay_udp_app_protocol: Option<String>,
    #[arg(long = "relay-http-app-protocol", value_parser = parse_kubernetes_app_protocol, requires = "expose_relay")]
    relay_http_app_protocol: Option<String>,
    #[arg(
        long = "relay-publish-not-ready-addresses",
        default_value_t = false,
        requires = "expose_relay"
    )]
    relay_publish_not_ready_addresses: bool,
    #[arg(long = "relay-load-balancer-class", value_parser = parse_kubernetes_load_balancer_class, requires = "expose_relay")]
    relay_load_balancer_class: Option<String>,
    #[arg(long = "relay-load-balancer-ip", value_parser = parse_kubernetes_service_ip, requires = "expose_relay")]
    relay_load_balancer_ip: Option<IpAddr>,
    #[arg(long = "relay-external-ip", value_parser = parse_kubernetes_service_ip, requires = "expose_relay")]
    relay_external_ips: Vec<IpAddr>,
    #[arg(long = "relay-health-check-node-port", value_parser = parse_kubernetes_node_port, requires = "expose_relay")]
    relay_health_check_node_port: Option<u16>,
    #[arg(
        long = "relay-disable-load-balancer-node-ports",
        default_value_t = false,
        requires = "expose_relay"
    )]
    relay_disable_load_balancer_node_ports: bool,
    #[arg(long = "relay-ip-family-policy", value_parser = parse_kubernetes_ip_family_policy, requires = "expose_relay")]
    relay_ip_family_policy: Option<String>,
    #[arg(long = "relay-ip-family", value_parser = parse_kubernetes_ip_family, requires = "expose_relay")]
    relay_ip_families: Vec<String>,
    #[arg(long = "relay-allow-source-cidr", requires = "expose_relay")]
    relay_allow_source_cidrs: Vec<ipnet::IpNet>,
    #[arg(
        long = "relay-network-policy-cidr",
        requires_all = ["enable_network_policy", "expose_relay"]
    )]
    relay_network_policy_cidrs: Vec<ipnet::IpNet>,
    #[arg(long = "relay-internal-traffic-policy", value_parser = parse_kubernetes_internal_traffic_policy, requires = "expose_relay")]
    relay_internal_traffic_policy: Option<String>,
    #[arg(long = "relay-traffic-distribution", value_parser = parse_kubernetes_traffic_distribution, requires = "expose_relay")]
    relay_traffic_distribution: Option<String>,
    #[arg(long = "relay-session-affinity", value_parser = parse_kubernetes_session_affinity, requires = "expose_relay")]
    relay_session_affinity: Option<String>,
    #[arg(long = "relay-session-affinity-timeout-seconds", value_parser = parse_kubernetes_session_affinity_timeout_seconds, requires = "expose_relay")]
    relay_session_affinity_timeout_seconds: Option<u32>,
    #[arg(long, default_value = "Local", value_parser = parse_kubernetes_external_traffic_policy)]
    relay_external_traffic_policy: String,
    #[arg(long = "relay-service-annotation", value_parser = parse_key_value, requires = "expose_relay")]
    relay_service_annotations: Vec<KeyValueArg>,
    #[arg(long = "relay-admission-bearer-token-secret")]
    relay_admission_bearer_token_secret: Option<String>,
    #[arg(long = "relay-admission-bearer-token-key")]
    relay_admission_bearer_token_key: Option<String>,
    #[arg(long, requires = "expose_relay")]
    relay_public_endpoint: Option<String>,
    #[arg(long, requires = "expose_relay")]
    relay_admission_url: Option<String>,
    #[arg(long, requires = "expose_relay")]
    relay_status_url: Option<String>,
    #[arg(long = "relay-max-sessions", default_value_t = DEFAULT_RELAY_MAX_SESSIONS)]
    relay_max_sessions: u32,
    #[arg(long = "relay-max-mbps", default_value_t = DEFAULT_RELAY_MAX_MBPS)]
    relay_max_mbps: u32,
    #[arg(long = "relay-forwarder-endpoint")]
    relay_forwarder_endpoint: Option<String>,
    #[arg(
        long = "relay-forwarder-bind",
        requires = "relay_forwarder_wireguard_endpoint"
    )]
    relay_forwarder_bind: Option<String>,
    #[arg(
        long = "relay-forwarder-wireguard-endpoint",
        requires = "relay_forwarder_bind"
    )]
    relay_forwarder_wireguard_endpoint: Option<String>,
    #[arg(long = "relay-forwarder-netns", requires = "relay_forwarder_bind")]
    relay_forwarder_netns: Option<String>,
    #[arg(long = "relay-forwarder-max-sessions", default_value_t = DEFAULT_RELAY_FORWARDER_MAX_SESSIONS)]
    relay_forwarder_max_sessions: usize,
    #[arg(long = "relay-forwarder-restart-backoff-seconds", default_value_t = DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS)]
    relay_forwarder_restart_backoff_seconds: u64,
    #[arg(long = "relay-forwarder-crash-window-seconds", default_value_t = DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS)]
    relay_forwarder_crash_window_seconds: u64,
    #[arg(long = "relay-forwarder-max-crashes-per-window", default_value_t = DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW)]
    relay_forwarder_max_crashes_per_window: u32,
    #[arg(long = "relay-forwarder-crash-cooldown-seconds", default_value_t = DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS)]
    relay_forwarder_crash_cooldown_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyValueArg {
    key: String,
    value: String,
}

#[derive(Debug, Clone, Copy)]
struct RelayForwarderInstallSettings<'a> {
    endpoint: Option<&'a str>,
    bind: Option<&'a str>,
    wireguard_endpoint: Option<&'a str>,
    netns: Option<&'a str>,
    max_sessions: usize,
    restart_backoff_seconds: u64,
    crash_window_seconds: u64,
    max_crashes_per_window: u32,
    crash_cooldown_seconds: u64,
}

impl<'a> RelayForwarderInstallSettings<'a> {
    fn from_docker(args: &'a DockerInstallArgs) -> Self {
        Self {
            endpoint: args.relay_forwarder_endpoint.as_deref(),
            bind: args.relay_forwarder_bind.as_deref(),
            wireguard_endpoint: args.relay_forwarder_wireguard_endpoint.as_deref(),
            netns: args.relay_forwarder_netns.as_deref(),
            max_sessions: args.relay_forwarder_max_sessions,
            restart_backoff_seconds: args.relay_forwarder_restart_backoff_seconds,
            crash_window_seconds: args.relay_forwarder_crash_window_seconds,
            max_crashes_per_window: args.relay_forwarder_max_crashes_per_window,
            crash_cooldown_seconds: args.relay_forwarder_crash_cooldown_seconds,
        }
    }

    fn from_k8s(args: &'a K8sInstallArgs) -> Self {
        Self {
            endpoint: args.relay_forwarder_endpoint.as_deref(),
            bind: args.relay_forwarder_bind.as_deref(),
            wireguard_endpoint: args.relay_forwarder_wireguard_endpoint.as_deref(),
            netns: args.relay_forwarder_netns.as_deref(),
            max_sessions: args.relay_forwarder_max_sessions,
            restart_backoff_seconds: args.relay_forwarder_restart_backoff_seconds,
            crash_window_seconds: args.relay_forwarder_crash_window_seconds,
            max_crashes_per_window: args.relay_forwarder_max_crashes_per_window,
            crash_cooldown_seconds: args.relay_forwarder_crash_cooldown_seconds,
        }
    }

    fn active(self) -> bool {
        self.endpoint.is_some() || self.bind.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KubernetesTolerationArg {
    key: Option<String>,
    operator: Option<String>,
    value: Option<String>,
    effect: Option<String>,
    toleration_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KubernetesNodeAffinityExpressionArg {
    key: String,
    operator: String,
    values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KubernetesPreferredNodeAffinityArg {
    weight: u8,
    expression: KubernetesNodeAffinityExpressionArg,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KubernetesLabelSelectorExpressionArg {
    key: String,
    operator: String,
    values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KubernetesPodAffinityTermArg {
    topology_key: String,
    match_expressions: Vec<KubernetesLabelSelectorExpressionArg>,
    namespaces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KubernetesPreferredPodAffinityArg {
    weight: u8,
    term: KubernetesPodAffinityTermArg,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KubernetesTopologySpreadArg {
    topology_key: String,
    max_skew: u32,
    when_unsatisfiable: String,
    min_domains: Option<u32>,
    node_affinity_policy: Option<String>,
    node_taints_policy: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Cli {
        agent_api_bearer_token,
        agent_api_bearer_token_path,
        control_plane_operator_api_bearer_token,
        control_plane_operator_api_bearer_token_path,
        agent_state_path,
        command,
    } = Cli::parse();
    if matches!(&command, Command::Init(_)) && control_plane_operator_api_bearer_token.is_some() {
        anyhow::bail!(
            "ipars init requires --control-plane-operator-api-bearer-token-path so the credential is not placed in daemon arguments"
        );
    }
    let agent_api_auth =
        AgentApiAuth::from_sources(agent_api_bearer_token, agent_api_bearer_token_path)?;
    let control_plane_operator_api_auth = ControlPlaneOperatorApiAuth::from_sources(
        control_plane_operator_api_bearer_token,
        control_plane_operator_api_bearer_token_path,
    )?;
    match command {
        Command::Init(args) => print_json(&init(*args)?)?,
        Command::Join(args) => print_json(&join(args).await?)?,
        Command::Status(args) => {
            match (args.agent_url.as_deref(), args.control_plane_url.as_deref()) {
                (Some(agent_url), None) => print_json(
                    &agent_status_with_bearer(agent_url, agent_api_auth.bearer_token()).await?,
                )?,
                (None, Some(control_plane_url)) => print_json(
                    &control_plane_status(
                        control_plane_url,
                        control_plane_operator_api_auth.bearer_token(),
                    )
                    .await?,
                )?,
                (None, None) => print_json(
                    &agent_status_with_bearer(
                        defaulted_agent_url(None),
                        agent_api_auth.bearer_token(),
                    )
                    .await?,
                )?,
                (Some(_), Some(_)) => unreachable!("clap prevents conflicting status URLs"),
            }
        }
        Command::Peers(args) => {
            match (args.agent_url.as_deref(), args.control_plane_url.as_deref()) {
                (Some(agent_url), None) if args.node_id.is_none() => print_json(
                    &agent_peer_map_with_bearer(agent_url, agent_api_auth.bearer_token()).await?,
                )?,
                (None, Some(control_plane_url)) => print_json(
                    &peer_map(control_plane_url, &args, agent_state_path.as_deref()).await?,
                )?,
                (None, None) if args.node_id.is_none() => print_json(
                    &agent_peer_map_with_bearer(
                        defaulted_agent_url(None),
                        agent_api_auth.bearer_token(),
                    )
                    .await?,
                )?,
                (Some(_), None) => {
                    anyhow::bail!("ipars peers cannot use --node-id with --agent-url")
                }
                (None, None) => {
                    anyhow::bail!("ipars peers requires --control-plane-url with --node-id")
                }
                (Some(_), Some(_)) => unreachable!("clap prevents conflicting peer-map URLs"),
            }
        }
        Command::Routes(args) => {
            match (args.agent_url.as_deref(), args.control_plane_url.as_deref()) {
                (Some(agent_url), None) if args.node_id.is_none() => print_json(
                    &agent_routes_with_bearer(agent_url, agent_api_auth.bearer_token()).await?,
                )?,
                (None, Some(control_plane_url)) => print_json(
                    &routes(control_plane_url, &args, agent_state_path.as_deref()).await?,
                )?,
                (None, None) if args.node_id.is_none() => print_json(
                    &agent_routes_with_bearer(
                        defaulted_agent_url(None),
                        agent_api_auth.bearer_token(),
                    )
                    .await?,
                )?,
                (Some(_), None) => {
                    anyhow::bail!("ipars routes cannot use --node-id with --agent-url")
                }
                (None, None) => {
                    anyhow::bail!("ipars routes requires --control-plane-url with --node-id")
                }
                (Some(_), Some(_)) => unreachable!("clap prevents conflicting route URLs"),
            }
        }
        Command::Token { command } => match command {
            TokenCommand::Create(args) => print_json(&create_token(*args)?)?,
            TokenCommand::Revoke(args) => print_json(&revoke_token(args).await?)?,
        },
        Command::Key { command } => match command {
            KeyCommand::Rotate(args) => {
                let agent_url = defaulted_agent_url(args.agent_url.as_deref());
                print_json(
                    &rotate_wireguard_key_with_bearer(
                        agent_url,
                        &args,
                        agent_api_auth.bearer_token(),
                    )
                    .await?,
                )?
            }
        },
        Command::Node { command } => match command {
            NodeCommand::Remove(args) => {
                let agent_url = defaulted_agent_url(args.agent_url.as_deref());
                print_json(
                    &remove_node_with_bearer(agent_url, &args, agent_api_auth.bearer_token())
                        .await?,
                )?
            }
        },
        Command::Relay { command } => match command {
            RelayCommand::Status(args) => match args.relay_url.as_deref() {
                Some(relay_url) => print_json(&relay_status(relay_url).await?)?,
                None => print_json(&relay_status(defaulted_relay_url(None)).await?)?,
            },
            RelayCommand::Probe(args) => print_json(&relay_probe(*args).await?)?,
        },
        Command::Stun { command } => match command {
            StunCommand::Probe(args) => print_json(&stun_probe(args).await?)?,
        },
        Command::Path { command } => match command {
            PathCommand::Status(args) => match args.agent_url.as_deref() {
                Some(agent_url) => print_json(
                    &path_status_with_bearer(agent_url, agent_api_auth.bearer_token()).await?,
                )?,
                None if args.control_plane_url.is_some() => print_json(
                    &control_plane_path_status(&args, agent_state_path.as_deref()).await?,
                )?,
                None if args.node_id.is_some() => {
                    anyhow::bail!("ipars path status requires --control-plane-url with --node-id")
                }
                None => print_json(
                    &path_status_with_bearer(
                        defaulted_agent_url(None),
                        agent_api_auth.bearer_token(),
                    )
                    .await?,
                )?,
            },
            PathCommand::Events(args) => {
                let agent_url = defaulted_agent_url(args.agent_url.as_deref());
                print_json(
                    &path_events_with_bearer(agent_url, agent_api_auth.bearer_token()).await?,
                )?
            }
            PathCommand::Activity(args) => {
                let agent_url = defaulted_agent_url(args.agent_url.as_deref());
                print_json(
                    &path_activity_with_bearer(agent_url, &args, agent_api_auth.bearer_token())
                        .await?,
                )?
            }
            PathCommand::Probe(args) => {
                let agent_url = defaulted_agent_url(args.agent_url.as_deref());
                print_json(
                    &path_probe_with_bearer(agent_url, &args, agent_api_auth.bearer_token())
                        .await?,
                )?
            }
        },
        Command::Docker {
            command: DockerCommand::Install(args),
        } => print_json(&docker_install_plan(*args)?)?,
        Command::K8s {
            command: K8sCommand::Install(args),
        } => print_json(&k8s_install_plan(*args)?)?,
    };
    Ok(())
}

fn init(args: InitArgs) -> anyhow::Result<InitOutput> {
    validate_init_bootstrap_inputs(&args)?;
    let identity = issuer_key_from_source(
        args.issuer_private_key_b64.as_deref(),
        args.issuer_private_key_path.as_deref(),
        MissingIssuerPath::GenerateAndWrite,
    )?;
    let wireguard = WireGuardKeyPair::generate();
    let cluster_id = ClusterId::new();
    let bootstrap_endpoints = bootstrap_from_public_endpoint(&args);
    let issuer_key_id = args.issuer_key_id.clone();
    let issuer_public_key = identity.public_key_b64();
    let issuer = TokenIssuer {
        node_id: identity.node_id(),
        key_id: KeyId::from_string(issuer_key_id.clone()),
    };
    let claims = claims(
        cluster_id.clone(),
        issuer.clone(),
        args.default_role.clone(),
        args.tags.clone(),
        args.token_ttl_seconds,
        bootstrap_endpoints.clone(),
        TokenPolicyInput {
            allow_relay: args.allow_relay,
            allowed_routes: args.allowed_routes.clone(),
            max_token_uses: max_token_uses(args.max_uses, args.unlimited_uses),
        },
    )?;
    let token = identity.sign_join_token(claims)?;
    let daemon_specs = init_daemon_specs(
        &args,
        &cluster_id,
        &identity.node_id(),
        &issuer_key_id,
        &issuer_public_key,
    );
    let daemon_commands = daemon_specs
        .iter()
        .map(|spec| spec.command_output(&args.daemon_binary))
        .collect::<Vec<_>>();
    let daemon_processes = if args.spawn_daemons {
        spawn_init_daemons(&args.daemon_binary, &args.daemon_state_dir, &daemon_specs)?
    } else {
        Vec::new()
    };

    Ok(InitOutput {
        cluster_id,
        node_id: identity.node_id(),
        issuer_node_id: identity.node_id(),
        issuer_key_id: KeyId::from_string(issuer_key_id),
        issuer_public_key,
        issuer_private_key_b64: args
            .emit_issuer_private_key
            .then(|| identity.signing_key_b64()),
        issuer_private_key_path: args.issuer_private_key_path,
        control_plane_operator_api_bearer_token_path: args
            .control_plane_operator_api_bearer_token_path,
        identity_public_key: identity.public_key_b64(),
        wireguard_public_key: wireguard.public_key_b64,
        bootstrap_endpoints,
        join_token: token,
        services: vec![
            "control-plane".to_string(),
            "signal".to_string(),
            "stun".to_string(),
            "relay".to_string(),
        ],
        daemon_state_dir: args.daemon_state_dir,
        daemon_commands,
        daemon_processes,
    })
}

fn validate_init_bootstrap_inputs(args: &InitArgs) -> anyhow::Result<()> {
    if !endpoint_addr_is_usable(args.public_endpoint) {
        anyhow::bail!(
            "--public-endpoint must use a usable nonzero, non-unspecified, non-multicast, non-broadcast socket address"
        );
    }
    validate_listen_port_for_bootstrap(args.control_plane_listen, "--control-plane-listen")?;
    validate_listen_port_for_bootstrap(args.signal_listen, "--signal-listen")?;
    validate_listen_port_for_bootstrap(args.stun_listen, "--stun-listen")?;
    if args.relay_http_listen.port() == 0 && args.relay_admission_url.is_none() {
        anyhow::bail!(
            "--relay-http-listen must use a nonzero port when --relay-admission-url is omitted"
        );
    }
    if let Some(path) = args.control_plane_operator_api_bearer_token_path.as_deref() {
        read_api_bearer_token_file(path, "control-plane operator API")?;
    }
    Ok(())
}

fn validate_listen_port_for_bootstrap(addr: SocketAddr, flag: &str) -> anyhow::Result<()> {
    if addr.port() == 0 {
        anyhow::bail!("{flag} must use a nonzero port for bootstrap token generation");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InitDaemonSpec {
    service: &'static str,
    args: Vec<String>,
    log_path: PathBuf,
}

impl InitDaemonSpec {
    fn command_output(&self, binary: &Path) -> InitDaemonCommand {
        InitDaemonCommand {
            service: self.service.to_string(),
            command: self.command(binary),
            log_path: self.log_path.clone(),
        }
    }

    fn command(&self, binary: &Path) -> Vec<String> {
        let mut command = Vec::with_capacity(self.args.len() + 1);
        command.push(binary.display().to_string());
        command.extend(self.args.iter().cloned());
        command
    }
}

fn init_daemon_specs(
    args: &InitArgs,
    cluster_id: &ClusterId,
    node_id: &NodeId,
    issuer_key_id: &str,
    issuer_public_key: &str,
) -> Vec<InitDaemonSpec> {
    let log_dir = args.daemon_state_dir.join("logs");
    let control_plane_database_url = effective_control_plane_database_url(args);
    let relay_admission_url = args.relay_admission_url.clone().unwrap_or_else(|| {
        format!(
            "{}://{}:{}",
            args.bootstrap_scheme,
            args.public_endpoint.ip(),
            args.relay_http_listen.port()
        )
    });
    let mut stun_args = vec![
        "stun".to_string(),
        "--listen".to_string(),
        args.stun_listen.to_string(),
    ];
    if let Some(stun_alternate_listen) = args.stun_alternate_listen {
        stun_args.push("--alternate-listen".to_string());
        stun_args.push(stun_alternate_listen.to_string());
    }
    stun_args.extend([
        "--http-listen".to_string(),
        args.stun_http_listen.to_string(),
    ]);

    let mut control_plane_args = vec![
        "control-plane".to_string(),
        "--listen".to_string(),
        args.control_plane_listen.to_string(),
        "--cluster-id".to_string(),
        cluster_id.as_str().to_string(),
        "--issuer-node-id".to_string(),
        node_id.as_str().to_string(),
        "--issuer-key-id".to_string(),
        issuer_key_id.to_string(),
        "--issuer-public-key".to_string(),
        issuer_public_key.to_string(),
        "--database-url".to_string(),
        control_plane_database_url,
    ];
    if let Some(path) = args.control_plane_operator_api_bearer_token_path.as_ref() {
        control_plane_args.push("--operator-api-bearer-token-path".to_string());
        control_plane_args.push(path.display().to_string());
    }

    vec![
        InitDaemonSpec {
            service: "control-plane",
            args: control_plane_args,
            log_path: log_dir.join("control-plane.log"),
        },
        InitDaemonSpec {
            service: "signal",
            args: vec![
                "signal".to_string(),
                "--listen".to_string(),
                args.signal_listen.to_string(),
            ],
            log_path: log_dir.join("signal.log"),
        },
        InitDaemonSpec {
            service: "stun",
            args: stun_args,
            log_path: log_dir.join("stun.log"),
        },
        InitDaemonSpec {
            service: "relay",
            args: vec![
                "relay".to_string(),
                "--relay-node-id".to_string(),
                node_id.as_str().to_string(),
                "--udp-listen".to_string(),
                args.relay_udp_listen.to_string(),
                "--http-listen".to_string(),
                args.relay_http_listen.to_string(),
                "--public-endpoint".to_string(),
                args.public_endpoint.to_string(),
                "--admission-url".to_string(),
                relay_admission_url,
            ],
            log_path: log_dir.join("relay.log"),
        },
    ]
}

fn effective_control_plane_database_url(args: &InitArgs) -> String {
    args.control_plane_database_url
        .clone()
        .unwrap_or_else(|| sqlite_database_url(&args.daemon_state_dir.join("control-plane.sqlite")))
}

fn sqlite_database_url(path: &Path) -> String {
    format!("sqlite://{}?mode=rwc", path.display())
}

fn spawn_init_daemons(
    binary: &Path,
    state_dir: &Path,
    specs: &[InitDaemonSpec],
) -> anyhow::Result<Vec<InitDaemonProcess>> {
    prepare_init_daemon_directory(state_dir, "daemon state dir")?;
    let log_dir = state_dir.join("logs");
    prepare_init_daemon_directory(&log_dir, "daemon log dir")?;

    let mut processes = Vec::with_capacity(specs.len());
    let mut spawned: Vec<Child> = Vec::with_capacity(specs.len());
    for spec in specs {
        let child = match spawn_init_daemon(binary, spec) {
            Ok(child) => child,
            Err(error) => {
                for mut child in spawned {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                return Err(error);
            }
        };
        processes.push(InitDaemonProcess {
            service: spec.service.to_string(),
            pid: child.id(),
            command: spec.command(binary),
            log_path: spec.log_path.clone(),
        });
        spawned.push(child);
    }

    Ok(processes)
}

fn spawn_init_daemon(binary: &Path, spec: &InitDaemonSpec) -> anyhow::Result<Child> {
    let log = open_init_daemon_log(&spec.log_path)?;
    let stdout = log.try_clone().with_context(|| {
        format!(
            "failed to clone daemon log handle {}",
            spec.log_path.display()
        )
    })?;
    let mut command = ProcessCommand::new(binary);
    configure_init_daemon_process(&mut command);
    command
        .args(&spec.args)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(log));
    command.spawn().with_context(|| {
        format!(
            "failed to spawn {} using {}",
            spec.service,
            binary.display()
        )
    })
}

fn configure_init_daemon_process(command: &mut ProcessCommand) {
    command
        .env_clear()
        .env("PATH", SANITIZED_INIT_DAEMON_PATH)
        .env("LANG", SANITIZED_INIT_DAEMON_LOCALE)
        .env("LC_ALL", SANITIZED_INIT_DAEMON_LOCALE);
}

fn prepare_init_daemon_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("failed to create {label} {}", path.display()))?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("{label} {} must not be a symlink", path.display());
    }
    if !metadata.is_dir() {
        anyhow::bail!("{label} {} must be a directory", path.display());
    }
    set_owner_only_directory_permissions(path, label)?;
    Ok(())
}

fn open_init_daemon_log(path: &Path) -> anyhow::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        prepare_init_daemon_directory(parent, "daemon log dir")?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("daemon log {} must not be a symlink", path.display());
            }
            if !metadata.is_file() {
                anyhow::bail!("daemon log {} must be a regular file", path.display());
            }
            reject_multi_linked_log(path, &metadata)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect daemon log {}", path.display()));
        }
    }
    let log = init_daemon_log_open_options()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open daemon log {}", path.display()))?;
    set_owner_only_open_file_permissions(&log, path, "daemon log")?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect daemon log {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("daemon log {} must not be a symlink", path.display());
    }
    if !metadata.is_file() {
        anyhow::bail!("daemon log {} must be a regular file", path.display());
    }
    reject_multi_linked_log(path, &metadata)?;
    Ok(log)
}

fn init_daemon_log_open_options() -> std::fs::OpenOptions {
    let mut options = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn set_owner_only_directory_permissions(path: &Path, label: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "failed to set owner-only permissions on {label} {}",
                    path.display()
                )
            },
        )?;
    }
    Ok(())
}

fn set_owner_only_open_file_permissions(
    file: &std::fs::File,
    path: &Path,
    label: &str,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "failed to set owner-only permissions on {label} {}",
                    path.display()
                )
            })?;
    }
    Ok(())
}

fn reject_multi_linked_log(path: &Path, metadata: &std::fs::Metadata) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            anyhow::bail!(
                "daemon log {} must not have multiple hard links",
                path.display()
            );
        }
    }
    Ok(())
}

async fn join(args: JoinArgs) -> anyhow::Result<JoinOutput> {
    let token: SignedJoinToken =
        serde_json::from_str(&args.token).context("join token must be JSON signed token")?;
    token
        .claims
        .validate_shape()
        .context("join token claim validation failed")?;
    let identity = IdentityKeyPair::generate();
    let wireguard = WireGuardKeyPair::generate();
    let control_plane_urls = control_plane_join_urls(&token, args.control_plane_url.as_deref())?;
    let registration = RegisterNodeRequest {
        node_id: identity.node_id(),
        identity_public_key: identity.public_key_b64(),
        wireguard_public_key: wireguard.public_key_b64.clone(),
        candidates: Vec::new(),
        relay_capability: None,
        requested_routes: Vec::new(),
    };
    let join_request = JoinNodeRequest {
        token: token.clone(),
        registration,
    };
    let (control_plane_url, registration_response) = if args.dry_run {
        (
            control_plane_urls
                .first()
                .cloned()
                .context("no control-plane join URL available")?,
            None,
        )
    } else {
        let (url, response) =
            post_join_request(&reqwest::Client::new(), &control_plane_urls, &join_request).await?;
        (url, Some(response))
    };

    Ok(JoinOutput {
        cluster_id: token.claims.cluster_id,
        node_id: identity.node_id(),
        role: token.claims.role,
        tags: token.claims.tags,
        bootstrap_endpoints: token.claims.bootstrap_endpoints,
        identity_public_key: identity.public_key_b64(),
        wireguard_public_key: wireguard.public_key_b64,
        control_plane_url,
        registered: registration_response.is_some(),
        registration: registration_response,
    })
}

async fn post_join_request(
    client: &reqwest::Client,
    join_urls: &[String],
    request: &JoinNodeRequest,
) -> anyhow::Result<(String, RegisterNodeResponse)> {
    let mut failures = Vec::new();
    for join_url in join_urls {
        let response = match client.post(join_url).json(request).send().await {
            Ok(response) => response,
            Err(error) => {
                failures.push(format!("{join_url}: send failed: {error}"));
                continue;
            }
        };
        let response = match response.error_for_status() {
            Ok(response) => response,
            Err(error) => {
                failures.push(format!("{join_url}: rejected: {error}"));
                continue;
            }
        };
        match read_bounded_json_response(response, "control-plane join").await {
            Ok(response) => return Ok((join_url.clone(), response)),
            Err(error) => failures.push(format!("{join_url}: decode failed: {error}")),
        }
    }

    Err(anyhow::anyhow!(
        "all control-plane join endpoints failed: {}",
        failures.join("; ")
    ))
}

fn create_token(args: TokenCreateArgs) -> anyhow::Result<SignedJoinToken> {
    let issuer = issuer_key_from_source(
        args.issuer_private_key_b64.as_deref(),
        args.issuer_private_key_path.as_deref(),
        MissingIssuerPath::GenerateEphemeral,
    )?;
    let bootstrap_endpoints = token_create_bootstrap_endpoints(&args)?;
    let cluster_id = args
        .cluster_id
        .map(ClusterId::from_string)
        .unwrap_or_default();
    let token = issuer.sign_join_token(claims(
        cluster_id,
        TokenIssuer {
            node_id: issuer.node_id(),
            key_id: KeyId::from_string(args.issuer_key_id),
        },
        args.role,
        args.tags,
        args.ttl_seconds,
        bootstrap_endpoints,
        TokenPolicyInput {
            allow_relay: args.allow_relay,
            allowed_routes: args.allowed_routes,
            max_token_uses: max_token_uses(args.max_uses, args.unlimited_uses),
        },
    )?)?;
    Ok(token)
}

fn token_create_bootstrap_endpoints(
    args: &TokenCreateArgs,
) -> anyhow::Result<Vec<BootstrapEndpoint>> {
    let mut endpoints = Vec::new();
    for url in args
        .bootstrap_endpoints
        .iter()
        .chain(args.control_plane_bootstrap_endpoints.iter())
    {
        endpoints.push(validated_bootstrap_endpoint(
            url,
            BootstrapEndpointKind::ControlPlane,
            "--bootstrap/--control-plane-bootstrap",
        )?);
    }
    for url in &args.signal_bootstrap_endpoints {
        endpoints.push(validated_bootstrap_endpoint(
            url,
            BootstrapEndpointKind::Signal,
            "--signal-bootstrap",
        )?);
    }
    for url in &args.stun_bootstrap_endpoints {
        endpoints.push(validated_bootstrap_endpoint(
            url,
            BootstrapEndpointKind::Stun,
            "--stun-bootstrap",
        )?);
    }
    for url in &args.relay_bootstrap_endpoints {
        endpoints.push(validated_bootstrap_endpoint(
            url,
            BootstrapEndpointKind::Relay,
            "--relay-bootstrap",
        )?);
    }
    validate_join_token_bootstrap_endpoints(&endpoints)?;
    Ok(endpoints)
}

fn validated_bootstrap_endpoint(
    url: &str,
    kind: BootstrapEndpointKind,
    flag: &str,
) -> anyhow::Result<BootstrapEndpoint> {
    match kind {
        BootstrapEndpointKind::ControlPlane | BootstrapEndpointKind::Signal => {
            validate_http_bootstrap_url(url, flag)?;
        }
        BootstrapEndpointKind::Stun | BootstrapEndpointKind::Relay => {
            validate_udp_bootstrap_url(url, flag)?;
        }
    }
    Ok(BootstrapEndpoint {
        url: url.to_string(),
        kind,
    })
}

fn validate_http_bootstrap_url(url: &str, flag: &str) -> anyhow::Result<()> {
    let parsed =
        reqwest::Url::parse(url).with_context(|| format!("{flag} must be an absolute URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("{flag} must use http or https");
    }
    if parsed.host_str().is_none() {
        anyhow::bail!("{flag} must include a host");
    }
    validate_literal_bootstrap_socket(&parsed, flag)?;
    if !http_url_is_usable_endpoint(url) {
        anyhow::bail!(
            "{flag} must use a nonzero port and a usable non-unspecified, non-multicast, non-broadcast HTTP bootstrap endpoint"
        );
    }
    Ok(())
}

fn normalize_http_api_base_url(base_url: &str, name: &str) -> anyhow::Result<String> {
    let parsed =
        reqwest::Url::parse(base_url).with_context(|| format!("{name} must be an absolute URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("{name} must use http or https");
    }
    if parsed.host_str().is_none() {
        anyhow::bail!("{name} must include a host");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        anyhow::bail!("{name} must not include a query or fragment");
    }
    if !http_url_is_usable_endpoint(base_url) {
        anyhow::bail!(
            "{name} must use a nonzero port and a usable non-unspecified, non-multicast, non-broadcast numeric host"
        );
    }
    Ok(base_url.trim_end_matches('/').to_string())
}

fn validate_udp_bootstrap_url(url: &str, flag: &str) -> anyhow::Result<()> {
    let parsed =
        reqwest::Url::parse(url).with_context(|| format!("{flag} must be an absolute URL"))?;
    if parsed.scheme() != "udp" {
        anyhow::bail!("{flag} must use udp");
    }
    if parsed.host_str().is_none() {
        anyhow::bail!("{flag} must include a host");
    }
    if parsed.port().is_none() {
        anyhow::bail!("{flag} must include a port");
    }
    validate_literal_bootstrap_socket(&parsed, flag)?;
    Ok(())
}

fn validate_literal_bootstrap_socket(parsed: &reqwest::Url, flag: &str) -> anyhow::Result<()> {
    let Some(host) = parsed.host_str() else {
        return Ok(());
    };
    let Ok(ip) = host.parse::<IpAddr>() else {
        return Ok(());
    };
    let port = parsed
        .port_or_known_default()
        .with_context(|| format!("{flag} must include a port"))?;
    let addr = SocketAddr::new(ip, port);
    if !endpoint_addr_is_usable(addr) {
        anyhow::bail!(
            "{flag} must use a usable nonzero, non-unspecified, non-multicast, non-broadcast bootstrap address"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingIssuerPath {
    GenerateEphemeral,
    GenerateAndWrite,
    RequireExisting,
}

fn issuer_key_from_source(
    private_key_b64: Option<&str>,
    private_key_path: Option<&Path>,
    missing_path: MissingIssuerPath,
) -> anyhow::Result<IdentityKeyPair> {
    if private_key_b64.is_some() && private_key_path.is_some() {
        anyhow::bail!("use only one of --issuer-private-key-b64 or --issuer-private-key-path");
    }
    if let Some(private_key_b64) = private_key_b64 {
        return IdentityKeyPair::from_signing_key_b64(private_key_b64.trim())
            .context("failed to load issuer private key from --issuer-private-key-b64");
    }
    if let Some(path) = private_key_path {
        return issuer_key_from_path(path, missing_path);
    }
    match missing_path {
        MissingIssuerPath::RequireExisting => anyhow::bail!(
            "token revocation requires --issuer-private-key-b64 or --issuer-private-key-path"
        ),
        MissingIssuerPath::GenerateEphemeral | MissingIssuerPath::GenerateAndWrite => {
            Ok(IdentityKeyPair::generate())
        }
    }
}

fn issuer_key_from_path(
    path: &Path,
    missing_path: MissingIssuerPath,
) -> anyhow::Result<IdentityKeyPair> {
    match read_issuer_private_key_file(path) {
        Ok(value) => IdentityKeyPair::from_signing_key_b64(value.trim())
            .with_context(|| format!("failed to load issuer private key from {}", path.display())),
        Err(error) if is_not_found_error(&error) => match missing_path {
            MissingIssuerPath::GenerateEphemeral | MissingIssuerPath::RequireExisting => Err(error)
                .with_context(|| {
                    format!("issuer private key path {} does not exist", path.display())
                }),
            MissingIssuerPath::GenerateAndWrite => {
                let key = IdentityKeyPair::generate();
                write_issuer_private_key(path, &key)?;
                Ok(key)
            }
        },
        Err(error) => Err(error)
            .with_context(|| format!("failed to read issuer private key from {}", path.display())),
    }
}

fn read_issuer_private_key_file(path: &Path) -> anyhow::Result<String> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect issuer private key {}", path.display()))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        anyhow::bail!(
            "issuer private key path {} must not be a symlink",
            path.display()
        );
    }
    if !file_type.is_file() {
        anyhow::bail!(
            "issuer private key path {} must be a regular file",
            path.display()
        );
    }
    ensure_issuer_private_key_file_size(path, metadata.len())?;

    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open issuer private key {}", path.display()))?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect opened issuer private key {}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        anyhow::bail!(
            "issuer private key path {} must be a regular file",
            path.display()
        );
    }
    ensure_issuer_private_key_file_size(path, metadata.len())?;

    let mut bytes = Vec::new();
    let mut reader = file.take(MAX_ISSUER_PRIVATE_KEY_FILE_BYTES + 1);
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read issuer private key {}", path.display()))?;
    if bytes.len() as u64 > MAX_ISSUER_PRIVATE_KEY_FILE_BYTES {
        anyhow::bail!(
            "issuer private key file {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_ISSUER_PRIVATE_KEY_FILE_BYTES
        );
    }
    String::from_utf8(bytes).with_context(|| {
        format!(
            "failed to decode issuer private key {} as UTF-8",
            path.display()
        )
    })
}

fn ensure_issuer_private_key_file_size(path: &Path, size: u64) -> anyhow::Result<()> {
    if size > MAX_ISSUER_PRIVATE_KEY_FILE_BYTES {
        anyhow::bail!(
            "issuer private key file {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_ISSUER_PRIVATE_KEY_FILE_BYTES
        );
    }
    Ok(())
}

fn is_not_found_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn write_issuer_private_key(path: &Path, key: &IdentityKeyPair) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create issuer private key directory {}",
                parent.display()
            )
        })?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create issuer private key {}", path.display()))?;
    file.write_all(key.signing_key_b64().as_bytes())
        .with_context(|| format!("failed to write issuer private key {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to finish issuer private key {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).with_context(
            || {
                format!(
                    "failed to restrict issuer private key permissions for {}",
                    path.display()
                )
            },
        )?;
    }
    Ok(())
}

async fn revoke_token(args: TokenRevokeArgs) -> anyhow::Result<RevokeTokenResponse> {
    let request = token_revocation_request(&args, Utc::now())?;
    let url = control_plane_token_revoke_url(&args.control_plane_url)?;
    let response = reqwest::Client::new()
        .post(&url)
        .json(&request)
        .send()
        .await
        .context("failed to send token revoke request")?
        .error_for_status()
        .context("control plane rejected token revoke request")?;
    read_bounded_json_response(response, "token revoke").await
}

fn token_revocation_request(
    args: &TokenRevokeArgs,
    signed_at: chrono::DateTime<Utc>,
) -> anyhow::Result<RevokeTokenRequest> {
    validate_token_identifier(&args.cluster_id, "--cluster-id")?;
    validate_token_identifier(&args.nonce, "--nonce")?;
    validate_token_identifier(&args.issuer_key_id, "--issuer-key-id")?;
    let issuer = issuer_key_from_source(
        args.issuer_private_key_b64.as_deref(),
        args.issuer_private_key_path.as_deref(),
        MissingIssuerPath::RequireExisting,
    )?;
    let mut request = RevokeTokenRequest {
        cluster_id: ClusterId::from_string(args.cluster_id.clone()),
        nonce: args.nonce.clone(),
        issuer: issuer.node_id(),
        key_id: KeyId::from_string(args.issuer_key_id.clone()),
        issuer_signature: None,
    };
    request.issuer_signature = Some(
        issuer
            .sign_token_revocation_request(&request, signed_at)
            .context("failed to sign token revocation request")?,
    );
    Ok(request)
}

async fn agent_status_with_bearer(
    agent_url: &str,
    bearer_token: Option<&str>,
) -> anyhow::Result<AgentStatusResponse> {
    get_json_with_bearer(agent_url, "/v1/status", "agent status", bearer_token).await
}

async fn rotate_wireguard_key_with_bearer(
    agent_url: &str,
    args: &KeyRotateArgs,
    bearer_token: Option<&str>,
) -> anyhow::Result<AgentWireGuardKeyRotationResponse> {
    let request = AgentWireGuardKeyRotationRequest {
        control_plane_url: args.control_plane_url.clone(),
    };
    post_json_with_bearer(
        agent_url,
        "/v1/wireguard-key/rotate",
        "agent WireGuard key rotation",
        &request,
        bearer_token,
    )
    .await
}

#[cfg(test)]
async fn rotate_wireguard_key(
    agent_url: &str,
    args: &KeyRotateArgs,
) -> anyhow::Result<AgentWireGuardKeyRotationResponse> {
    rotate_wireguard_key_with_bearer(agent_url, args, None).await
}

async fn remove_node_with_bearer(
    agent_url: &str,
    args: &NodeRemoveArgs,
    bearer_token: Option<&str>,
) -> anyhow::Result<AgentNodeRemovalResponse> {
    let request = AgentNodeRemovalRequest {
        control_plane_url: args.control_plane_url.clone(),
    };
    post_json_with_bearer(
        agent_url,
        "/v1/node/remove",
        "agent node removal",
        &request,
        bearer_token,
    )
    .await
}

#[cfg(test)]
async fn remove_node(
    agent_url: &str,
    args: &NodeRemoveArgs,
) -> anyhow::Result<AgentNodeRemovalResponse> {
    remove_node_with_bearer(agent_url, args, None).await
}

fn defaulted_agent_url(agent_url: Option<&str>) -> &str {
    agent_url.unwrap_or(DEFAULT_LOCAL_AGENT_URL)
}

fn defaulted_relay_url(relay_url: Option<&str>) -> &str {
    relay_url.unwrap_or(DEFAULT_LOCAL_RELAY_URL)
}

#[derive(Debug, Serialize)]
struct ControlPlaneStatus {
    metrics: ControlPlaneMetricsResponse,
    policy: ControlPlanePolicyResponse,
}

async fn control_plane_status(
    control_plane_url: &str,
    operator_api_bearer_token: Option<&str>,
) -> anyhow::Result<ControlPlaneStatus> {
    Ok(ControlPlaneStatus {
        metrics: get_json_with_bearer(
            control_plane_url,
            "/v1/metrics",
            "control-plane metrics",
            operator_api_bearer_token,
        )
        .await?,
        policy: get_json_with_bearer(
            control_plane_url,
            "/v1/policy",
            "control-plane policy",
            operator_api_bearer_token,
        )
        .await?,
    })
}

async fn peer_map(
    control_plane_url: &str,
    args: &PeersArgs,
    agent_state_path: Option<&Path>,
) -> anyhow::Result<PeerMap> {
    let node_id = required_node_id(args.node_id.as_deref(), "peers")?;
    let request = signed_control_plane_node_query(
        node_id,
        agent_state_path,
        ControlPlaneNodeQueryKind::PeerMap,
        "peers",
    )?;
    post_json_with_bearer(
        control_plane_url,
        "/v1/peers/query",
        "control-plane peer map",
        &request,
        None,
    )
    .await
}

async fn agent_peer_map_with_bearer(
    agent_url: &str,
    bearer_token: Option<&str>,
) -> anyhow::Result<PeerMap> {
    get_json_with_bearer(agent_url, "/v1/peers", "agent peer map", bearer_token).await
}

async fn routes(
    control_plane_url: &str,
    args: &RoutesArgs,
    agent_state_path: Option<&Path>,
) -> anyhow::Result<RoutesOutput> {
    let node_id = required_node_id(args.node_id.as_deref(), "routes")?;
    let request = signed_control_plane_node_query(
        node_id.clone(),
        agent_state_path,
        ControlPlaneNodeQueryKind::PeerMap,
        "routes",
    )?;
    let peer_map: PeerMap = post_json_with_bearer(
        control_plane_url,
        "/v1/peers/query",
        "control-plane peer map",
        &request,
        None,
    )
    .await?;
    Ok(routes_output(node_id, peer_map))
}

fn signed_control_plane_node_query(
    node_id: NodeId,
    agent_state_path: Option<&Path>,
    kind: ControlPlaneNodeQueryKind,
    command: &str,
) -> anyhow::Result<ControlPlaneNodeQueryRequest> {
    let state_path = agent_state_path.with_context(|| {
        format!("ipars {command} requires --agent-state-path for a direct control-plane node query")
    })?;
    let state = FileAgentStateStore::new(state_path)
        .load()
        .with_context(|| {
            format!(
                "failed to load agent identity from {}",
                state_path.display()
            )
        })?;
    anyhow::ensure!(
        state.node_id == node_id,
        "--node-id {node_id} does not match agent state node {}",
        state.node_id
    );
    let identity = state
        .identity_key_pair()
        .context("failed to load node identity key from agent state")?;
    let mut request = ControlPlaneNodeQueryRequest {
        node_id,
        request_signature: None,
    };
    request.request_signature = Some(
        identity
            .sign_control_plane_node_query_request(&request, kind, Utc::now())
            .context("failed to sign control-plane node query")?,
    );
    Ok(request)
}

async fn agent_routes_with_bearer(
    agent_url: &str,
    bearer_token: Option<&str>,
) -> anyhow::Result<RoutesOutput> {
    let status = agent_status_with_bearer(agent_url, bearer_token).await?;
    let peer_map = agent_peer_map_with_bearer(agent_url, bearer_token).await?;
    Ok(routes_output(status.node_id, peer_map))
}

async fn relay_status(relay_url: &str) -> anyhow::Result<RelayStatusResponse> {
    get_json(relay_url, "/v1/status", "relay status").await
}

async fn stun_probe(args: StunProbeArgs) -> anyhow::Result<NatProbeObservation> {
    validate_stun_probe_args(&args)?;
    UdpStunProbe
        .observe_binding(args.local_bind, args.stun_server)
        .await
        .with_context(|| {
            format!(
                "failed to complete STUN Binding probe from {} to {}",
                args.local_bind, args.stun_server
            )
        })
}

fn validate_stun_probe_args(args: &StunProbeArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        endpoint_addr_is_usable(args.stun_server),
        "--stun-server must be a usable UDP socket address"
    );
    anyhow::ensure!(
        !args.local_bind.ip().is_multicast(),
        "--local-bind must not use a multicast address"
    );
    Ok(())
}

#[derive(Debug, Serialize)]
struct RelayProbeOutput {
    relay_node: NodeId,
    session_id: String,
    relay_udp: SocketAddr,
    left: NodeId,
    right: NodeId,
    left_addr: SocketAddr,
    right_addr: SocketAddr,
    payload_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    invalid_credential_drop: Option<RelayProbeInvalidCredentialOutput>,
    left_to_right: RelayProbeDirectionOutput,
    right_to_left: RelayProbeDirectionOutput,
    status_after_probe: RelayStatusResponse,
}

#[derive(Debug, Serialize)]
struct RelayProbeInvalidCredentialOutput {
    source: NodeId,
    destination: NodeId,
    bytes_sent: usize,
}

#[derive(Debug, Serialize)]
struct RelayProbeDirectionOutput {
    source: NodeId,
    destination: NodeId,
    bytes_sent: usize,
    bytes_received: usize,
}

async fn relay_probe(args: RelayProbeArgs) -> anyhow::Result<RelayProbeOutput> {
    validate_relay_probe_args(&args)?;
    let relay_url = defaulted_relay_url(args.relay_url.as_deref());
    let relay_admission_bearer_token = args.relay_admission_bearer_token.as_deref();
    let left = validated_node_id(&args.left_node_id, "--left-node-id")?;
    let right = validated_node_id(&args.right_node_id, "--right-node-id")?;
    anyhow::ensure!(
        left != right,
        "--left-node-id and --right-node-id must be different"
    );

    let timeout = std::time::Duration::from_millis(args.timeout_ms);
    let left_socket = bind_probe_socket(args.left_bind, timeout, "--left-bind")?;
    let right_socket = bind_probe_socket(args.right_bind, timeout, "--right-bind")?;
    let left_addr = left_socket
        .local_addr()
        .context("failed to read left probe socket address")?;
    let right_addr = right_socket
        .local_addr()
        .context("failed to read right probe socket address")?;
    anyhow::ensure!(
        endpoint_addr_is_usable(left_addr),
        "left probe socket resolved to unusable relay target address {left_addr}; use --left-bind with an explicit local interface address"
    );
    anyhow::ensure!(
        endpoint_addr_is_usable(right_addr),
        "right probe socket resolved to unusable relay target address {right_addr}; use --right-bind with an explicit local interface address"
    );
    anyhow::ensure!(
        left_addr != right_addr,
        "left and right probe sockets resolved to the same local address {left_addr}"
    );

    let admission: RelayAdmissionResponse = post_json_with_bearer(
        relay_url,
        "/v1/sessions",
        "relay session admission",
        &RelayAdmissionRequest {
            left: left.clone(),
            right: right.clone(),
            left_addr,
            right_addr,
        },
        relay_admission_bearer_token,
    )
    .await?;

    anyhow::ensure!(
        admission.left == left
            && admission.right == right
            && admission.left_addr == left_addr
            && admission.right_addr == right_addr,
        "relay admission response did not echo the requested session endpoints"
    );

    let payload = args.payload.as_bytes();
    let left_to_right_route = RelayProbeRoute {
        relay_udp: args.relay_udp,
        session_id: &admission.session_id,
        session_token: &admission.session_token,
        source: &left,
        destination: &right,
    };
    let invalid_credential_drop = if args.send_invalid_credential {
        Some(relay_probe_invalid_credential(
            &left_socket,
            &left_to_right_route,
            payload,
        )?)
    } else {
        None
    };
    let left_to_right =
        relay_probe_direction(&left_socket, &right_socket, &left_to_right_route, payload)?;
    let right_to_left_payload = reversed_probe_payload(payload);
    let right_to_left_route = RelayProbeRoute {
        source: &right,
        destination: &left,
        ..left_to_right_route
    };
    let right_to_left = relay_probe_direction(
        &right_socket,
        &left_socket,
        &right_to_left_route,
        &right_to_left_payload,
    )?;

    let status_after_probe = relay_status(relay_url).await?;
    anyhow::ensure!(
        status_after_probe.dataplane.datagrams_forwarded >= 2,
        "relay dataplane forwarded counter did not record the bidirectional probe: {:?}",
        status_after_probe.dataplane
    );
    anyhow::ensure!(
        status_after_probe.dataplane.payload_bytes_forwarded
            >= (payload.len() + right_to_left_payload.len()) as u64,
        "relay dataplane forwarded-byte counter did not record the bidirectional probe: {:?}",
        status_after_probe.dataplane
    );
    if args.send_invalid_credential {
        let invalid_credential_drops = status_after_probe
            .dataplane
            .drops_by_reason
            .get(&ipars_types::api::RelayDataplaneDropReason::InvalidSessionCredential)
            .copied()
            .unwrap_or_default();
        anyhow::ensure!(
            status_after_probe.dataplane.datagrams_dropped >= 1 && invalid_credential_drops >= 1,
            "relay dataplane did not record invalid-credential drop after probe: {:?}",
            status_after_probe.dataplane
        );
    }

    Ok(RelayProbeOutput {
        relay_node: admission.relay_node,
        session_id: admission.session_id,
        relay_udp: args.relay_udp,
        left,
        right,
        left_addr,
        right_addr,
        payload_bytes: payload.len(),
        invalid_credential_drop,
        left_to_right,
        right_to_left,
        status_after_probe,
    })
}

fn validate_relay_probe_args(args: &RelayProbeArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        endpoint_addr_is_usable(args.relay_udp),
        "--relay-udp must be a usable UDP socket address"
    );
    anyhow::ensure!(
        args.timeout_ms > 0 && args.timeout_ms <= MAX_RELAY_PROBE_TIMEOUT_MS,
        "--timeout-ms must be between 1 and {MAX_RELAY_PROBE_TIMEOUT_MS}"
    );
    anyhow::ensure!(!args.payload.is_empty(), "--payload must not be empty");
    anyhow::ensure!(
        args.payload.len() <= MAX_RELAY_PROBE_PAYLOAD_BYTES,
        "--payload exceeds {MAX_RELAY_PROBE_PAYLOAD_BYTES} bytes"
    );
    if let Some(token) = args.relay_admission_bearer_token.as_deref() {
        validate_relay_admission_bearer_token(token, "--relay-admission-bearer-token")?;
    }
    Ok(())
}

fn validate_relay_admission_bearer_token(value: &str, label: &str) -> anyhow::Result<()> {
    if value.len() < MIN_RELAY_ADMISSION_BEARER_TOKEN_BYTES {
        anyhow::bail!(
            "{label} must contain at least {MIN_RELAY_ADMISSION_BEARER_TOKEN_BYTES} bytes"
        );
    }
    if value.len() > MAX_RELAY_ADMISSION_BEARER_TOKEN_BYTES {
        anyhow::bail!("{label} exceeds {MAX_RELAY_ADMISSION_BEARER_TOKEN_BYTES} bytes");
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        anyhow::bail!("{label} must not contain whitespace or control characters");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct RelayProbeRoute<'a> {
    relay_udp: SocketAddr,
    session_id: &'a str,
    session_token: &'a str,
    source: &'a NodeId,
    destination: &'a NodeId,
}

fn relay_probe_invalid_credential(
    send_socket: &UdpSocket,
    route: &RelayProbeRoute<'_>,
    payload: &[u8],
) -> anyhow::Result<RelayProbeInvalidCredentialOutput> {
    let invalid_session_token = format!("{}-invalid", route.session_token);
    let datagram = encode_relay_datagram_with_route(
        route.session_id,
        &invalid_session_token,
        route.source,
        route.destination,
        payload,
    )
    .context("failed to encode invalid-credential relay probe datagram")?;
    let bytes_sent = send_socket
        .send_to(&datagram, route.relay_udp)
        .with_context(|| {
            format!(
                "failed to send invalid-credential relay probe datagram to {}",
                route.relay_udp
            )
        })?;
    anyhow::ensure!(
        bytes_sent == datagram.len(),
        "invalid-credential relay probe sent {bytes_sent} of {} encoded bytes",
        datagram.len()
    );

    Ok(RelayProbeInvalidCredentialOutput {
        source: route.source.clone(),
        destination: route.destination.clone(),
        bytes_sent,
    })
}

fn bind_probe_socket(
    bind_addr: SocketAddr,
    timeout: std::time::Duration,
    label: &str,
) -> anyhow::Result<UdpSocket> {
    let socket = UdpSocket::bind(bind_addr)
        .with_context(|| format!("failed to bind relay probe socket for {label} at {bind_addr}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .with_context(|| format!("failed to set read timeout on {label} probe socket"))?;
    Ok(socket)
}

fn relay_probe_direction(
    send_socket: &UdpSocket,
    recv_socket: &UdpSocket,
    route: &RelayProbeRoute<'_>,
    payload: &[u8],
) -> anyhow::Result<RelayProbeDirectionOutput> {
    let datagram = encode_relay_datagram_with_route(
        route.session_id,
        route.session_token,
        route.source,
        route.destination,
        payload,
    )
    .context("failed to encode relay probe datagram")?;
    let bytes_sent = send_socket
        .send_to(&datagram, route.relay_udp)
        .with_context(|| format!("failed to send relay probe datagram to {}", route.relay_udp))?;
    anyhow::ensure!(
        bytes_sent == datagram.len(),
        "relay probe sent {bytes_sent} of {} encoded bytes",
        datagram.len()
    );

    let mut received = vec![0_u8; payload.len().saturating_add(1024).max(2048)];
    let (bytes_received, remote_addr) =
        recv_socket.recv_from(&mut received).with_context(|| {
            format!(
                "timed out waiting for relay probe payload from {}",
                route.source
            )
        })?;
    anyhow::ensure!(
        bytes_received == payload.len(),
        "relay probe received {bytes_received} bytes from {remote_addr}, expected {}",
        payload.len()
    );
    anyhow::ensure!(
        &received[..bytes_received] == payload,
        "relay probe payload from {remote_addr} did not match the sent opaque payload"
    );

    Ok(RelayProbeDirectionOutput {
        source: route.source.clone(),
        destination: route.destination.clone(),
        bytes_sent,
        bytes_received,
    })
}

fn reversed_probe_payload(payload: &[u8]) -> Vec<u8> {
    payload.iter().rev().copied().collect()
}

async fn path_status_with_bearer(
    agent_url: &str,
    bearer_token: Option<&str>,
) -> anyhow::Result<AgentPathsResponse> {
    get_json_with_bearer(agent_url, "/v1/paths", "agent path status", bearer_token).await
}

async fn path_events_with_bearer(
    agent_url: &str,
    bearer_token: Option<&str>,
) -> anyhow::Result<AgentPathEventsResponse> {
    get_json_with_bearer(
        agent_url,
        "/v1/path-events",
        "agent path events",
        bearer_token,
    )
    .await
}

#[cfg(test)]
async fn path_events(agent_url: &str) -> anyhow::Result<AgentPathEventsResponse> {
    path_events_with_bearer(agent_url, None).await
}

async fn control_plane_path_status(
    args: &PathStatusArgs,
    agent_state_path: Option<&Path>,
) -> anyhow::Result<ControlPlanePathsResponse> {
    let control_plane_url = args
        .control_plane_url
        .as_deref()
        .context("ipars path status requires --control-plane-url")?;
    let node_id = required_node_id(args.node_id.as_deref(), "path status")?;
    let request = signed_control_plane_node_query(
        node_id,
        agent_state_path,
        ControlPlaneNodeQueryKind::Paths,
        "path status",
    )?;
    post_json_with_bearer(
        control_plane_url,
        "/v1/paths/query",
        "control-plane path status",
        &request,
        None,
    )
    .await
}

async fn path_activity_with_bearer(
    agent_url: &str,
    args: &PathActivityArgs,
    bearer_token: Option<&str>,
) -> anyhow::Result<AgentPeerActivityResponse> {
    let request = path_activity_request(args)?;
    post_json_with_bearer(
        agent_url,
        "/v1/peer-activity",
        "agent peer activity",
        &request,
        bearer_token,
    )
    .await
}

fn path_activity_request(args: &PathActivityArgs) -> anyhow::Result<AgentPeerActivityRequest> {
    Ok(AgentPeerActivityRequest {
        peer: validated_node_id(&args.peer, "--peer")?,
        pin: args.pin,
    })
}

async fn path_probe_with_bearer(
    agent_url: &str,
    args: &PathProbeArgs,
    bearer_token: Option<&str>,
) -> anyhow::Result<AgentPathProbeResponse> {
    let request = path_probe_request(args, Utc::now())?;
    post_json_with_bearer(
        agent_url,
        "/v1/path-probe",
        "agent path probe",
        &request,
        bearer_token,
    )
    .await
}

fn path_probe_request(
    args: &PathProbeArgs,
    observed_at: chrono::DateTime<Utc>,
) -> anyhow::Result<AgentPathProbeRequest> {
    let peer = validated_node_id(&args.peer, "--peer")?;
    let relay_node = args
        .relay_node
        .as_deref()
        .map(|relay_node| validated_node_id(relay_node, "--relay-node"))
        .transpose()?;
    let request = AgentPathProbeRequest {
        peer: peer.clone(),
        selected_state: args.state,
        selected_candidate: path_probe_candidate(args, observed_at, &peer)?,
        relay_node,
        metrics: PathMetrics {
            latency_ms: args.latency_ms,
            loss_ppm: args.loss_ppm,
            jitter_ms: args.jitter_ms,
            relay_load: args.relay_load,
            stability: args.stability,
        },
        policy_allowed: !args.policy_denied,
        cost: args.cost,
        pin: args.pin,
    };
    request.metrics.validate()?;
    validate_path_probe_request_shape(&request)?;
    Ok(request)
}

fn validate_path_probe_request_shape(request: &AgentPathProbeRequest) -> anyhow::Result<()> {
    match request.selected_state {
        PathState::Relay => {
            if request.selected_candidate.is_some() {
                anyhow::bail!("relay path probe must not carry a direct selected candidate");
            }
            let Some(relay_node) = request.relay_node.as_ref() else {
                anyhow::bail!("relay path probe requires --relay-node");
            };
            if relay_node == &request.peer {
                anyhow::bail!("relay path probe uses path peer {relay_node} as relay");
            }
        }
        PathState::Unreachable => {
            if request.selected_candidate.is_some() {
                anyhow::bail!("unreachable path probe must not carry a selected candidate");
            }
            if request.relay_node.is_some() {
                anyhow::bail!("unreachable path probe must not carry a relay node");
            }
        }
        PathState::DirectPublic | PathState::DirectIpv6 | PathState::DirectNatTraversal => {
            if request.relay_node.is_some() {
                anyhow::bail!("direct path probe must not carry a relay node");
            }
        }
    }

    let Some(candidate) = request.selected_candidate.as_ref() else {
        return Ok(());
    };
    if request.selected_state.is_direct()
        && !request
            .selected_state
            .allows_selected_candidate_kind(candidate.kind)
    {
        anyhow::bail!(
            "path probe selected state {:?} does not allow selected candidate kind {:?}",
            request.selected_state,
            candidate.kind
        );
    }
    Ok(())
}

fn path_probe_candidate(
    args: &PathProbeArgs,
    observed_at: chrono::DateTime<Utc>,
    peer: &NodeId,
) -> anyhow::Result<Option<EndpointCandidate>> {
    let Some(addr) = args.candidate_addr else {
        if args.candidate_kind.is_some()
            || args.candidate_priority.is_some()
            || args.candidate_cost.is_some()
            || args.candidate_source.is_some()
        {
            anyhow::bail!("candidate metadata requires --candidate-addr");
        }
        return Ok(None);
    };

    let candidate = EndpointCandidate {
        node_id: peer.clone(),
        kind: args
            .candidate_kind
            .unwrap_or(EndpointCandidateKind::PublicUdp),
        addr,
        observed_at,
        priority: args.candidate_priority.unwrap_or(100),
        cost: args.candidate_cost.unwrap_or(args.cost),
        source: args
            .candidate_source
            .unwrap_or(CandidateSource::ControlPlane),
    };
    if let Err(reason) = candidate.validate_kind_address() {
        anyhow::bail!(
            "selected candidate {:?} at {} is invalid: {reason}",
            candidate.kind,
            candidate.addr
        );
    }
    if !endpoint_addr_is_usable(candidate.addr) {
        anyhow::bail!(
            "selected candidate {:?} at {} is unusable",
            candidate.kind,
            candidate.addr
        );
    }
    Ok(Some(candidate))
}

async fn get_json<T>(base_url: &str, path: &str, label: &str) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    get_json_with_bearer(base_url, path, label, None).await
}

async fn get_json_with_bearer<T>(
    base_url: &str,
    path: &str,
    label: &str,
    bearer_token: Option<&str>,
) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let url = api_url(base_url, path, label)?;
    let mut request = reqwest::Client::new().get(&url);
    if let Some(token) = bearer_token {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("failed to send {label} request to {url}"))?
        .error_for_status()
        .with_context(|| format!("{label} request to {url} returned an error status"))?;
    read_bounded_json_response(response, label)
        .await
        .with_context(|| format!("failed to decode {label} response from {url}"))
}

async fn post_json_with_bearer<Request, Response>(
    base_url: &str,
    path: &str,
    label: &str,
    request: &Request,
    bearer_token: Option<&str>,
) -> anyhow::Result<Response>
where
    Request: Serialize + ?Sized,
    Response: DeserializeOwned,
{
    let url = api_url(base_url, path, label)?;
    let mut request_builder = reqwest::Client::new().post(&url).json(request);
    if let Some(token) = bearer_token {
        request_builder = request_builder.bearer_auth(token);
    }
    let response = request_builder
        .send()
        .await
        .with_context(|| format!("failed to send {label} request to {url}"))?
        .error_for_status()
        .with_context(|| format!("{label} request to {url} returned an error status"))?;
    read_bounded_json_response(response, label)
        .await
        .with_context(|| format!("failed to decode {label} response from {url}"))
}

fn api_url(base_url: &str, path: &str, label: &str) -> anyhow::Result<String> {
    let base_url = normalize_http_api_base_url(base_url, &format!("{label} URL"))?;
    Ok(format!("{}/{}", base_url, path.trim_start_matches('/')))
}

async fn read_bounded_json_response<T>(
    response: reqwest::Response,
    label: &str,
) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    read_bounded_json_response_with_limit(response, label, MAX_CLI_HTTP_JSON_RESPONSE_BYTES).await
}

async fn read_bounded_json_response_with_limit<T>(
    mut response: reqwest::Response,
    label: &str,
    max_bytes: u64,
) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    if let Some(length) = response.content_length() {
        ensure_cli_http_json_response_size(length, label, max_bytes)?;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("failed to read {label} response"))?
    {
        let next_len = body.len() as u64 + chunk.len() as u64;
        ensure_cli_http_json_response_size(next_len, label, max_bytes)?;
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).with_context(|| format!("failed to decode {label} response"))
}

fn ensure_cli_http_json_response_size(
    size: u64,
    label: &str,
    max_bytes: u64,
) -> anyhow::Result<()> {
    if size > max_bytes {
        anyhow::bail!("{label} response exceeds maximum size of {max_bytes} bytes");
    }
    Ok(())
}

fn parse_path_state(value: &str) -> Result<PathState, String> {
    match normalized_enum_arg(value).as_str() {
        "direct_public" => Ok(PathState::DirectPublic),
        "direct_ipv6" => Ok(PathState::DirectIpv6),
        "direct_nat_traversal" => Ok(PathState::DirectNatTraversal),
        "relay" => Ok(PathState::Relay),
        "unreachable" => Ok(PathState::Unreachable),
        _ => Err(format!(
            "path state must be one of DIRECT_PUBLIC, DIRECT_IPV6, DIRECT_NAT_TRAVERSAL, RELAY, or UNREACHABLE; got {value}"
        )),
    }
}

fn parse_candidate_kind(value: &str) -> Result<EndpointCandidateKind, String> {
    match normalized_enum_arg(value).as_str() {
        "public_udp" => Ok(EndpointCandidateKind::PublicUdp),
        "ipv6" => Ok(EndpointCandidateKind::Ipv6),
        "stun_reflexive" => Ok(EndpointCandidateKind::StunReflexive),
        "local_udp" => Ok(EndpointCandidateKind::LocalUdp),
        "relay" => Ok(EndpointCandidateKind::Relay),
        _ => Err(format!(
            "candidate kind must be one of public_udp, ipv6, stun_reflexive, local_udp, or relay; got {value}"
        )),
    }
}

fn parse_candidate_source(value: &str) -> Result<CandidateSource, String> {
    match normalized_enum_arg(value).as_str() {
        "interface_scan" => Ok(CandidateSource::InterfaceScan),
        "stun_probe" => Ok(CandidateSource::StunProbe),
        "control_plane" => Ok(CandidateSource::ControlPlane),
        "relay_map" => Ok(CandidateSource::RelayMap),
        _ => Err(format!(
            "candidate source must be one of interface_scan, stun_probe, control_plane, or relay_map; got {value}"
        )),
    }
}

fn normalized_enum_arg(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn parse_bootstrap_scheme(value: &str) -> Result<String, String> {
    match value {
        "http" | "https" => Ok(value.to_string()),
        _ => Err(format!(
            "bootstrap scheme must be http or https; got {value}"
        )),
    }
}

fn parse_route_backend(value: &str) -> Result<String, String> {
    match value {
        "command" | "kernel-netlink" => Ok(value.to_string()),
        _ => Err(format!(
            "route backend must be command or kernel-netlink; got {value}"
        )),
    }
}

fn parse_agent_runtime_backend(value: &str) -> Result<String, String> {
    match value {
        "linux-command" | "dry-run" => Ok(value.to_string()),
        _ => Err(format!(
            "agent runtime backend must be linux-command or dry-run; got {value}"
        )),
    }
}

fn parse_kubernetes_service_type(value: &str) -> Result<String, String> {
    match value {
        "ClusterIP" | "NodePort" | "LoadBalancer" => Ok(value.to_string()),
        _ => Err(format!(
            "service type must be one of ClusterIP, NodePort, or LoadBalancer; got {value}"
        )),
    }
}

fn parse_kubernetes_external_traffic_policy(value: &str) -> Result<String, String> {
    match value {
        "Cluster" | "Local" => Ok(value.to_string()),
        _ => Err(format!(
            "external traffic policy must be Cluster or Local; got {value}"
        )),
    }
}

fn parse_kubernetes_internal_traffic_policy(value: &str) -> Result<String, String> {
    match value {
        "Cluster" | "Local" => Ok(value.to_string()),
        _ => Err(format!(
            "internal traffic policy must be Cluster or Local; got {value}"
        )),
    }
}

fn parse_kubernetes_traffic_distribution(value: &str) -> Result<String, String> {
    match value {
        "PreferSameZone" | "PreferSameNode" | "PreferClose" => Ok(value.to_string()),
        _ => Err(format!(
            "traffic distribution must be PreferSameZone, PreferSameNode, or PreferClose; got {value}"
        )),
    }
}

fn parse_kubernetes_session_affinity(value: &str) -> Result<String, String> {
    match value {
        "None" | "ClientIP" => Ok(value.to_string()),
        _ => Err(format!(
            "session affinity must be None or ClientIP; got {value}"
        )),
    }
}

fn parse_kubernetes_dns_policy(value: &str) -> Result<String, String> {
    match value {
        "ClusterFirstWithHostNet" | "ClusterFirst" | "Default" | "None" => Ok(value.to_string()),
        _ => Err(format!(
            "dnsPolicy must be ClusterFirstWithHostNet, ClusterFirst, Default, or None; got {value}"
        )),
    }
}

fn parse_kubernetes_seccomp_profile_type(value: &str) -> Result<String, String> {
    match value {
        "RuntimeDefault" | "Localhost" | "Unconfined" => Ok(value.to_string()),
        _ => Err(format!(
            "seccomp profile type must be RuntimeDefault, Localhost, or Unconfined; got {value}"
        )),
    }
}

fn parse_kubernetes_fs_group_change_policy(value: &str) -> Result<String, String> {
    match value {
        "Always" | "OnRootMismatch" => Ok(value.to_string()),
        _ => Err(format!(
            "fsGroupChangePolicy must be Always or OnRootMismatch; got {value}"
        )),
    }
}

fn parse_kubernetes_host_path_type(value: &str) -> Result<String, String> {
    match value {
        "DirectoryOrCreate" | "Directory" => Ok(value.to_string()),
        _ => Err(format!(
            "hostPath type must be DirectoryOrCreate or Directory; got {value}"
        )),
    }
}

fn parse_kubernetes_absolute_path(value: &str) -> Result<String, String> {
    validate_kubernetes_absolute_path(value, "Kubernetes path")?;
    Ok(value.to_string())
}

fn parse_kubernetes_seccomp_localhost_profile(value: &str) -> Result<String, String> {
    validate_kubernetes_seccomp_localhost_profile(value)?;
    Ok(value.to_string())
}

const KUBERNETES_SESSION_AFFINITY_TIMEOUT_SECONDS_MIN: u32 = 1;
const KUBERNETES_SESSION_AFFINITY_TIMEOUT_SECONDS_MAX: u32 = 86_400;

fn parse_kubernetes_session_affinity_timeout_seconds(value: &str) -> Result<u32, String> {
    let timeout = value.parse::<u32>().map_err(|_| {
        format!(
            "session affinity timeout must be an integer between {KUBERNETES_SESSION_AFFINITY_TIMEOUT_SECONDS_MIN} and {KUBERNETES_SESSION_AFFINITY_TIMEOUT_SECONDS_MAX}; got {value}"
        )
    })?;
    if (KUBERNETES_SESSION_AFFINITY_TIMEOUT_SECONDS_MIN
        ..=KUBERNETES_SESSION_AFFINITY_TIMEOUT_SECONDS_MAX)
        .contains(&timeout)
    {
        Ok(timeout)
    } else {
        Err(format!(
            "session affinity timeout must be between {KUBERNETES_SESSION_AFFINITY_TIMEOUT_SECONDS_MIN} and {KUBERNETES_SESSION_AFFINITY_TIMEOUT_SECONDS_MAX}; got {value}"
        ))
    }
}

fn parse_kubernetes_ip_family_policy(value: &str) -> Result<String, String> {
    match value {
        "SingleStack" | "PreferDualStack" | "RequireDualStack" => Ok(value.to_string()),
        _ => Err(format!(
            "ipFamilyPolicy must be SingleStack, PreferDualStack, or RequireDualStack; got {value}"
        )),
    }
}

fn parse_kubernetes_ip_family(value: &str) -> Result<String, String> {
    match value {
        "IPv4" | "IPv6" => Ok(value.to_string()),
        _ => Err(format!("ipFamily must be IPv4 or IPv6; got {value}")),
    }
}

fn parse_kubernetes_service_ip(value: &str) -> Result<IpAddr, String> {
    let ip = value
        .parse::<IpAddr>()
        .map_err(|_| format!("Service IP address must be IPv4 or IPv6; got {value}"))?;
    if let Some(reason) = kubernetes_service_ip_rejection_reason(ip) {
        return Err(format!(
            "Service IP address must not use {reason} address {ip}"
        ));
    }
    Ok(ip)
}

const KUBERNETES_NODE_PORT_MIN: u16 = 30000;
const KUBERNETES_NODE_PORT_MAX: u16 = 32767;
const KUBERNETES_SERVICE_PORT_MIN: u16 = 1;
const KUBERNETES_SERVICE_PORT_MAX: u16 = 65535;

fn parse_kubernetes_service_port(value: &str) -> Result<u16, String> {
    let port = value.parse::<u16>().map_err(|_| {
        format!(
            "Service port must be an integer between {KUBERNETES_SERVICE_PORT_MIN} and {KUBERNETES_SERVICE_PORT_MAX}; got {value}"
        )
    })?;
    if (KUBERNETES_SERVICE_PORT_MIN..=KUBERNETES_SERVICE_PORT_MAX).contains(&port) {
        Ok(port)
    } else {
        Err(format!(
            "Service port must be between {KUBERNETES_SERVICE_PORT_MIN} and {KUBERNETES_SERVICE_PORT_MAX}; got {value}"
        ))
    }
}

fn validate_kubernetes_service_port_value(port: u16, flag: &str) -> anyhow::Result<()> {
    if (KUBERNETES_SERVICE_PORT_MIN..=KUBERNETES_SERVICE_PORT_MAX).contains(&port) {
        Ok(())
    } else {
        anyhow::bail!(
            "{flag} must be between {KUBERNETES_SERVICE_PORT_MIN} and {KUBERNETES_SERVICE_PORT_MAX}"
        );
    }
}

fn parse_kubernetes_node_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| format!("nodePort must be an integer between {KUBERNETES_NODE_PORT_MIN} and {KUBERNETES_NODE_PORT_MAX}; got {value}"))?;
    if (KUBERNETES_NODE_PORT_MIN..=KUBERNETES_NODE_PORT_MAX).contains(&port) {
        Ok(port)
    } else {
        Err(format!(
            "nodePort must be between {KUBERNETES_NODE_PORT_MIN} and {KUBERNETES_NODE_PORT_MAX}; got {value}"
        ))
    }
}

fn parse_kubernetes_load_balancer_class(value: &str) -> Result<String, String> {
    validate_kubernetes_load_balancer_class(value)?;
    Ok(value.to_string())
}

fn parse_kubernetes_app_protocol(value: &str) -> Result<String, String> {
    validate_kubernetes_app_protocol(value)?;
    Ok(value.to_string())
}

fn is_external_kubernetes_service_type(service_type: &str) -> bool {
    matches!(service_type, "NodePort" | "LoadBalancer")
}

fn parse_key_value(value: &str) -> Result<KeyValueArg, String> {
    let (key, annotation_value) = value
        .split_once('=')
        .ok_or_else(|| "annotation must use key=value syntax".to_string())?;
    validate_kubernetes_annotation_key(key)?;
    validate_kubernetes_annotation_value(annotation_value)?;
    Ok(KeyValueArg {
        key: key.to_string(),
        value: annotation_value.to_string(),
    })
}

fn parse_kubernetes_label_pair(value: &str) -> Result<KeyValueArg, String> {
    let (key, label_value) = value
        .split_once('=')
        .ok_or_else(|| "label must use key=value syntax".to_string())?;
    validate_kubernetes_label_key(key)?;
    validate_kubernetes_label_value(label_value)?;
    Ok(KeyValueArg {
        key: key.to_string(),
        value: label_value.to_string(),
    })
}

fn parse_kubernetes_node_affinity_required_arg(
    value: &str,
) -> Result<KubernetesNodeAffinityExpressionArg, String> {
    parse_kubernetes_node_affinity_expression_arg(value)
}

fn parse_kubernetes_node_affinity_preferred_arg(
    value: &str,
) -> Result<KubernetesPreferredNodeAffinityArg, String> {
    if value.is_empty() {
        return Err("preferred node affinity must not be empty".to_string());
    }
    let mut weight = None;
    let mut expression_fields = Vec::new();
    for part in value.split(',') {
        let (field, field_value) = part.split_once('=').ok_or_else(|| {
            "preferred node affinity fields must use name=value syntax".to_string()
        })?;
        if field_value.is_empty() {
            return Err(format!(
                "preferred node affinity field {field} must not be empty"
            ));
        }
        if field == "weight" {
            let parsed = parse_kubernetes_node_affinity_weight(field_value)?;
            if weight.replace(parsed).is_some() {
                return Err("duplicate preferred node affinity field weight".to_string());
            }
        } else {
            expression_fields.push(part);
        }
    }
    let expression = parse_kubernetes_node_affinity_expression_arg(&expression_fields.join(","))?;
    Ok(KubernetesPreferredNodeAffinityArg {
        weight: weight
            .ok_or_else(|| "preferred node affinity field weight is required".to_string())?,
        expression,
    })
}

fn parse_kubernetes_node_affinity_expression_arg(
    value: &str,
) -> Result<KubernetesNodeAffinityExpressionArg, String> {
    if value.is_empty() {
        return Err("node affinity expression must not be empty".to_string());
    }
    let mut key = None;
    let mut operator = None;
    let mut values = None;
    for part in value.split(',') {
        let (field, field_value) = part.split_once('=').ok_or_else(|| {
            "node affinity expression fields must use name=value syntax".to_string()
        })?;
        if field_value.is_empty() {
            return Err(format!(
                "node affinity expression field {field} must not be empty"
            ));
        }
        match field {
            "key" => set_node_affinity_string_field(&mut key, field, field_value)?,
            "operator" => set_node_affinity_string_field(&mut operator, field, field_value)?,
            "values" => {
                let parsed = parse_kubernetes_node_affinity_values(field_value)?;
                if values.replace(parsed).is_some() {
                    return Err("duplicate node affinity expression field values".to_string());
                }
            }
            _ => {
                return Err(format!(
                    "unknown node affinity expression field {field}; expected key, operator, or values"
                ));
            }
        }
    }
    let expression = KubernetesNodeAffinityExpressionArg {
        key: key.ok_or_else(|| "node affinity expression field key is required".to_string())?,
        operator: operator
            .ok_or_else(|| "node affinity expression field operator is required".to_string())?,
        values: values.unwrap_or_default(),
    };
    validate_kubernetes_node_affinity_expression_arg(&expression)?;
    Ok(expression)
}

fn parse_kubernetes_node_affinity_values(value: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for item in value.split('|') {
        if item.is_empty() {
            return Err(
                "node affinity expression values must not contain empty entries".to_string(),
            );
        }
        values.push(item.to_string());
    }
    if values.is_empty() {
        return Err("node affinity expression values must not be empty".to_string());
    }
    Ok(values)
}

fn parse_kubernetes_node_affinity_weight(value: &str) -> Result<u8, String> {
    let parsed = value.parse::<u8>().map_err(|_| {
        "preferred node affinity weight must be an integer from 1 to 100".to_string()
    })?;
    if !(1..=100).contains(&parsed) {
        return Err("preferred node affinity weight must be an integer from 1 to 100".to_string());
    }
    Ok(parsed)
}

fn parse_kubernetes_pod_affinity_required_arg(
    value: &str,
) -> Result<KubernetesPodAffinityTermArg, String> {
    parse_kubernetes_pod_affinity_term_arg(value)
}

fn parse_kubernetes_pod_affinity_preferred_arg(
    value: &str,
) -> Result<KubernetesPreferredPodAffinityArg, String> {
    if value.is_empty() {
        return Err("preferred pod affinity must not be empty".to_string());
    }
    let mut weight = None;
    let mut term_fields = Vec::new();
    for part in value.split(',') {
        let (field, field_value) = part.split_once('=').ok_or_else(|| {
            "preferred pod affinity fields must use name=value syntax".to_string()
        })?;
        if field_value.is_empty() {
            return Err(format!(
                "preferred pod affinity field {field} must not be empty"
            ));
        }
        if field == "weight" {
            let parsed = parse_kubernetes_pod_affinity_weight(field_value)?;
            if weight.replace(parsed).is_some() {
                return Err("duplicate preferred pod affinity field weight".to_string());
            }
        } else {
            term_fields.push(part);
        }
    }
    let term = parse_kubernetes_pod_affinity_term_arg(&term_fields.join(","))?;
    Ok(KubernetesPreferredPodAffinityArg {
        weight: weight
            .ok_or_else(|| "preferred pod affinity field weight is required".to_string())?,
        term,
    })
}

fn parse_kubernetes_pod_affinity_term_arg(
    value: &str,
) -> Result<KubernetesPodAffinityTermArg, String> {
    if value.is_empty() {
        return Err("pod affinity term must not be empty".to_string());
    }
    let mut topology_key = None;
    let mut namespaces = None;
    let mut expression_fields = Vec::new();
    for part in value.split(',') {
        let (field, field_value) = part
            .split_once('=')
            .ok_or_else(|| "pod affinity term fields must use name=value syntax".to_string())?;
        if field_value.is_empty() {
            return Err(format!("pod affinity term field {field} must not be empty"));
        }
        match field {
            "topologyKey" | "topology-key" => {
                set_pod_affinity_string_field(&mut topology_key, field, field_value)?
            }
            "namespaces" => {
                let parsed = parse_kubernetes_pod_affinity_namespaces(field_value)?;
                if namespaces.replace(parsed).is_some() {
                    return Err("duplicate pod affinity term field namespaces".to_string());
                }
            }
            "key" | "operator" | "values" => expression_fields.push(part),
            _ => {
                return Err(format!(
                    "unknown pod affinity term field {field}; expected topologyKey, namespaces, key, operator, or values"
                ));
            }
        }
    }
    let expression = parse_kubernetes_label_selector_expression_arg(&expression_fields.join(","))?;
    let term = KubernetesPodAffinityTermArg {
        topology_key: topology_key
            .ok_or_else(|| "pod affinity term field topologyKey is required".to_string())?,
        match_expressions: vec![expression],
        namespaces: namespaces.unwrap_or_default(),
    };
    validate_kubernetes_pod_affinity_term_arg(&term)?;
    Ok(term)
}

fn parse_kubernetes_label_selector_expression_arg(
    value: &str,
) -> Result<KubernetesLabelSelectorExpressionArg, String> {
    if value.is_empty() {
        return Err("pod affinity label selector expression must not be empty".to_string());
    }
    let mut key = None;
    let mut operator = None;
    let mut values = None;
    for part in value.split(',') {
        let (field, field_value) = part.split_once('=').ok_or_else(|| {
            "pod affinity label selector fields must use name=value syntax".to_string()
        })?;
        if field_value.is_empty() {
            return Err(format!(
                "pod affinity label selector field {field} must not be empty"
            ));
        }
        match field {
            "key" => set_label_selector_string_field(&mut key, field, field_value)?,
            "operator" => set_label_selector_string_field(&mut operator, field, field_value)?,
            "values" => {
                let parsed = parse_kubernetes_label_selector_values(field_value)?;
                if values.replace(parsed).is_some() {
                    return Err("duplicate pod affinity label selector field values".to_string());
                }
            }
            _ => {
                return Err(format!(
                    "unknown pod affinity label selector field {field}; expected key, operator, or values"
                ));
            }
        }
    }
    let expression = KubernetesLabelSelectorExpressionArg {
        key: key.ok_or_else(|| "pod affinity label selector field key is required".to_string())?,
        operator: operator
            .ok_or_else(|| "pod affinity label selector field operator is required".to_string())?,
        values: values.unwrap_or_default(),
    };
    validate_kubernetes_label_selector_expression_arg(&expression)?;
    Ok(expression)
}

fn parse_kubernetes_label_selector_values(value: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for item in value.split('|') {
        if item.is_empty() {
            return Err(
                "pod affinity label selector values must not contain empty entries".to_string(),
            );
        }
        values.push(item.to_string());
    }
    if values.is_empty() {
        return Err("pod affinity label selector values must not be empty".to_string());
    }
    Ok(values)
}

fn parse_kubernetes_pod_affinity_namespaces(value: &str) -> Result<Vec<String>, String> {
    let mut namespaces = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for item in value.split('|') {
        if item.is_empty() {
            return Err("pod affinity namespaces must not contain empty entries".to_string());
        }
        validate_kubernetes_namespace(item).map_err(|error| error.to_string())?;
        if !seen.insert(item) {
            return Err(format!(
                "pod affinity namespace `{item}` must not be repeated"
            ));
        }
        namespaces.push(item.to_string());
    }
    if namespaces.is_empty() {
        return Err("pod affinity namespaces must not be empty".to_string());
    }
    Ok(namespaces)
}

fn parse_kubernetes_pod_affinity_weight(value: &str) -> Result<u8, String> {
    let parsed = value.parse::<u8>().map_err(|_| {
        "preferred pod affinity weight must be an integer from 1 to 100".to_string()
    })?;
    if !(1..=100).contains(&parsed) {
        return Err("preferred pod affinity weight must be an integer from 1 to 100".to_string());
    }
    Ok(parsed)
}

fn parse_kubernetes_toleration_arg(value: &str) -> Result<KubernetesTolerationArg, String> {
    if value.is_empty() {
        return Err("toleration must not be empty".to_string());
    }
    let mut toleration = KubernetesTolerationArg {
        key: None,
        operator: None,
        value: None,
        effect: None,
        toleration_seconds: None,
    };
    for part in value.split(',') {
        let (field, field_value) = part
            .split_once('=')
            .ok_or_else(|| "toleration fields must use name=value syntax".to_string())?;
        if field_value.is_empty() {
            return Err(format!("toleration field {field} must not be empty"));
        }
        match field {
            "key" => set_toleration_string_field(&mut toleration.key, field, field_value)?,
            "operator" => {
                set_toleration_string_field(&mut toleration.operator, field, field_value)?
            }
            "value" => set_toleration_string_field(&mut toleration.value, field, field_value)?,
            "effect" => set_toleration_string_field(&mut toleration.effect, field, field_value)?,
            "tolerationSeconds" | "toleration-seconds" => {
                let seconds = field_value.parse::<u64>().map_err(|_| {
                    format!("toleration field {field} must be a non-negative integer")
                })?;
                if toleration.toleration_seconds.replace(seconds).is_some() {
                    return Err(format!("duplicate toleration field {field}"));
                }
            }
            _ => {
                return Err(format!(
                    "unknown toleration field {field}; expected key, operator, value, effect, or tolerationSeconds"
                ));
            }
        }
    }
    validate_kubernetes_toleration_arg(&toleration)?;
    Ok(toleration)
}

fn parse_kubernetes_topology_spread_arg(
    value: &str,
) -> Result<KubernetesTopologySpreadArg, String> {
    if value.is_empty() {
        return Err("topology spread constraint must not be empty".to_string());
    }
    let mut topology_key = None;
    let mut max_skew = None;
    let mut when_unsatisfiable = None;
    let mut min_domains = None;
    let mut node_affinity_policy = None;
    let mut node_taints_policy = None;
    for part in value.split(',') {
        let (field, field_value) = part
            .split_once('=')
            .ok_or_else(|| "topology spread fields must use name=value syntax".to_string())?;
        if field_value.is_empty() {
            return Err(format!("topology spread field {field} must not be empty"));
        }
        match field {
            "topologyKey" | "topology-key" => {
                set_topology_spread_string_field(&mut topology_key, field, field_value)?
            }
            "maxSkew" | "max-skew" => {
                let value =
                    parse_kubernetes_positive_i32_u32(field_value, "topology spread maxSkew")?;
                if max_skew.replace(value).is_some() {
                    return Err(format!("duplicate topology spread field {field}"));
                }
            }
            "whenUnsatisfiable" | "when-unsatisfiable" => {
                set_topology_spread_string_field(&mut when_unsatisfiable, field, field_value)?
            }
            "minDomains" | "min-domains" => {
                let value =
                    parse_kubernetes_positive_i32_u32(field_value, "topology spread minDomains")?;
                if min_domains.replace(value).is_some() {
                    return Err(format!("duplicate topology spread field {field}"));
                }
            }
            "nodeAffinityPolicy" | "node-affinity-policy" => {
                set_topology_spread_string_field(&mut node_affinity_policy, field, field_value)?
            }
            "nodeTaintsPolicy" | "node-taints-policy" => {
                set_topology_spread_string_field(&mut node_taints_policy, field, field_value)?
            }
            _ => {
                return Err(format!(
                    "unknown topology spread field {field}; expected topologyKey, maxSkew, whenUnsatisfiable, minDomains, nodeAffinityPolicy, or nodeTaintsPolicy"
                ));
            }
        }
    }
    let constraint = KubernetesTopologySpreadArg {
        topology_key: topology_key
            .ok_or_else(|| "topology spread field topologyKey is required".to_string())?,
        max_skew: max_skew
            .ok_or_else(|| "topology spread field maxSkew is required".to_string())?,
        when_unsatisfiable: when_unsatisfiable
            .ok_or_else(|| "topology spread field whenUnsatisfiable is required".to_string())?,
        min_domains,
        node_affinity_policy,
        node_taints_policy,
    };
    validate_kubernetes_topology_spread_arg(&constraint)?;
    Ok(constraint)
}

fn set_toleration_string_field(
    slot: &mut Option<String>,
    field: &str,
    value: &str,
) -> Result<(), String> {
    if slot.replace(value.to_string()).is_some() {
        Err(format!("duplicate toleration field {field}"))
    } else {
        Ok(())
    }
}

fn set_node_affinity_string_field(
    slot: &mut Option<String>,
    field: &str,
    value: &str,
) -> Result<(), String> {
    if slot.replace(value.to_string()).is_some() {
        Err(format!("duplicate node affinity expression field {field}"))
    } else {
        Ok(())
    }
}

fn set_pod_affinity_string_field(
    slot: &mut Option<String>,
    field: &str,
    value: &str,
) -> Result<(), String> {
    if slot.replace(value.to_string()).is_some() {
        Err(format!("duplicate pod affinity term field {field}"))
    } else {
        Ok(())
    }
}

fn set_label_selector_string_field(
    slot: &mut Option<String>,
    field: &str,
    value: &str,
) -> Result<(), String> {
    if slot.replace(value.to_string()).is_some() {
        Err(format!(
            "duplicate pod affinity label selector field {field}"
        ))
    } else {
        Ok(())
    }
}

fn set_topology_spread_string_field(
    slot: &mut Option<String>,
    field: &str,
    value: &str,
) -> Result<(), String> {
    if slot.replace(value.to_string()).is_some() {
        Err(format!("duplicate topology spread field {field}"))
    } else {
        Ok(())
    }
}

fn parse_kubernetes_positive_i32_u32(value: &str, label: &str) -> Result<u32, String> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| format!("{label} must be a positive integer no greater than 2147483647"))?;
    if parsed == 0 || parsed > i32::MAX as u32 {
        return Err(format!(
            "{label} must be a positive integer no greater than 2147483647"
        ));
    }
    Ok(parsed)
}

fn parse_kubernetes_positive_i32(value: &str) -> Result<u32, String> {
    parse_kubernetes_positive_i32_u32(value, "value")
}

fn parse_kubernetes_priority_class_name(value: &str) -> Result<String, String> {
    validate_kubernetes_dns_subdomain(value, "priorityClassName")?;
    Ok(value.to_string())
}

fn parse_kubernetes_scheduler_name(value: &str) -> Result<String, String> {
    validate_kubernetes_dns_subdomain(value, "schedulerName")?;
    Ok(value.to_string())
}

fn parse_kubernetes_runtime_class_name(value: &str) -> Result<String, String> {
    validate_kubernetes_dns_subdomain(value, "runtimeClassName")?;
    Ok(value.to_string())
}

fn parse_kubernetes_service_account_name(value: &str) -> Result<String, String> {
    validate_kubernetes_dns_subdomain(value, "serviceAccount.name")?;
    Ok(value.to_string())
}

fn parse_kubernetes_image_pull_secret_name(value: &str) -> Result<String, String> {
    validate_kubernetes_dns_subdomain(value, "imagePullSecrets entry")?;
    Ok(value.to_string())
}

fn parse_container_image_repository(value: &str) -> Result<String, String> {
    validate_container_image_repository(value, "image repository")?;
    Ok(value.to_string())
}

fn parse_container_image_tag(value: &str) -> Result<String, String> {
    validate_container_image_tag(value, "image tag")?;
    Ok(value.to_string())
}

fn parse_kubernetes_image_pull_policy(value: &str) -> Result<String, String> {
    match value {
        "Always" | "IfNotPresent" | "Never" => Ok(value.to_string()),
        _ => Err(format!(
            "image pull policy must be Always, IfNotPresent, or Never; got {value}"
        )),
    }
}

fn parse_linux_capability(value: &str) -> Result<String, String> {
    validate_linux_capability_name(value, "Linux capability")?;
    Ok(value.to_string())
}

fn parse_kubernetes_resource_quantity(value: &str) -> Result<String, String> {
    validate_kubernetes_resource_quantity(value, "resource quantity")?;
    Ok(value.to_string())
}

fn parse_kubernetes_chart_name_override(value: &str) -> Result<String, String> {
    validate_kubernetes_dns_label_with_max(value, "chart name override", 53)?;
    Ok(value.to_string())
}

fn parse_kubernetes_http_api_base_url(value: &str) -> Result<String, String> {
    normalize_kubernetes_http_api_base_url(value, "Kubernetes cluster HTTP endpoint URL")
        .map_err(|error| error.to_string())
}

fn parse_kubernetes_stun_endpoint(value: &str) -> Result<String, String> {
    validate_kubernetes_stun_endpoint(value, "Kubernetes cluster STUN endpoint")?;
    Ok(value.to_string())
}

fn parse_kubernetes_agent_stun_bind(value: &str) -> Result<String, String> {
    validate_relay_forwarder_bind_arg(value, "agent STUN bind")
        .map_err(|error| error.to_string())?;
    Ok(value.to_string())
}

fn parse_kubernetes_http_probe_path(value: &str) -> Result<String, String> {
    validate_kubernetes_http_probe_path(value, "probe HTTP path")?;
    Ok(value.to_string())
}

fn parse_kubernetes_daemonset_update_strategy(value: &str) -> Result<String, String> {
    match value {
        "RollingUpdate" | "OnDelete" => Ok(value.to_string()),
        _ => Err(format!(
            "DaemonSet update strategy must be RollingUpdate or OnDelete; got {value}"
        )),
    }
}

const KUBERNETES_INT32_MAX: u32 = 2_147_483_647;
const KUBERNETES_INT64_MAX: u64 = 9_223_372_036_854_775_807;

fn parse_kubernetes_non_negative_i32(value: &str) -> Result<u32, String> {
    let parsed = value.parse::<u32>().map_err(|_| {
        format!("value must be a non-negative integer up to {KUBERNETES_INT32_MAX}; got {value}")
    })?;
    if parsed <= KUBERNETES_INT32_MAX {
        Ok(parsed)
    } else {
        Err(format!(
            "value must be a non-negative integer up to {KUBERNETES_INT32_MAX}; got {value}"
        ))
    }
}

fn parse_kubernetes_non_negative_i64(value: &str) -> Result<u64, String> {
    validate_kubernetes_non_negative_integer_text(value, "value", Some(KUBERNETES_INT64_MAX))
}

fn parse_kubernetes_int_or_percent(value: &str) -> Result<String, String> {
    validate_kubernetes_int_or_percent(value, "rollout value")?;
    Ok(value.to_string())
}

fn validate_kubernetes_int_or_percent(value: &str, label: &str) -> Result<(), String> {
    if let Some(percent) = value.strip_suffix('%') {
        validate_kubernetes_non_negative_integer_text(percent, label, Some(100)).map(|_| ())
    } else {
        validate_kubernetes_non_negative_integer_text(
            value,
            label,
            Some(u64::from(KUBERNETES_INT32_MAX)),
        )
        .map(|_| ())
    }
}

fn kubernetes_int_or_percent_is_zero(value: &str) -> bool {
    matches!(value, "0" | "0%")
}

fn validate_kubernetes_non_negative_integer_text(
    value: &str,
    label: &str,
    max: Option<u64>,
) -> Result<u64, String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.len() > 1 && value.starts_with('0') {
        return Err(format!("{label} must not use leading zeroes"));
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{label} must be a non-negative integer"));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{label} must be a non-negative integer"))?;
    if let Some(max) = max {
        if parsed > max {
            return Err(format!("{label} must be between 0 and {max}"));
        }
    }
    Ok(parsed)
}

fn validate_kubernetes_annotation_key(key: &str) -> Result<(), String> {
    let (prefix, name) = match key.split_once('/') {
        Some((prefix, name)) => {
            if name.contains('/') {
                return Err("annotation key must contain at most one '/' separator".to_string());
            }
            (Some(prefix), name)
        }
        None => (None, key),
    };
    if let Some(prefix) = prefix {
        validate_kubernetes_dns_subdomain(prefix, "annotation prefix")?;
    }
    validate_kubernetes_qualified_name(name, "annotation name")
}

fn validate_kubernetes_label_key(key: &str) -> Result<(), String> {
    let (prefix, name) = match key.split_once('/') {
        Some((prefix, name)) => {
            if name.contains('/') {
                return Err("label key must contain at most one '/' separator".to_string());
            }
            (Some(prefix), name)
        }
        None => (None, key),
    };
    if let Some(prefix) = prefix {
        validate_kubernetes_dns_subdomain(prefix, "label prefix")?;
    }
    validate_kubernetes_qualified_name(name, "label name")
}

fn validate_kubernetes_label_value(value: &str) -> Result<(), String> {
    if value.len() > 63 {
        return Err("label value exceeds 63 bytes".to_string());
    }
    if value.is_empty() {
        return Ok(());
    }
    let valid_body = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    let valid_edges = value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
    if !valid_body || !valid_edges {
        return Err(
            "label value must be empty or use ASCII letters, digits, '-', '_' or '.', with alphanumeric edges"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_kubernetes_node_affinity_expression_arg(
    expression: &KubernetesNodeAffinityExpressionArg,
) -> Result<(), String> {
    validate_kubernetes_label_key(&expression.key)?;
    match expression.operator.as_str() {
        "In" | "NotIn" => {
            if expression.values.is_empty() {
                return Err(format!(
                    "node affinity values are required when operator is {}",
                    expression.operator
                ));
            }
            for value in &expression.values {
                validate_kubernetes_label_value(value)?;
            }
        }
        "Exists" | "DoesNotExist" => {
            if !expression.values.is_empty() {
                return Err(format!(
                    "node affinity values must be omitted when operator is {}",
                    expression.operator
                ));
            }
        }
        "Gt" | "Lt" => {
            if expression.values.len() != 1 {
                return Err(format!(
                    "node affinity values must contain exactly one integer when operator is {}",
                    expression.operator
                ));
            }
            expression.values[0].parse::<i64>().map_err(|_| {
                format!(
                    "node affinity value `{}` must be an integer when operator is {}",
                    expression.values[0], expression.operator
                )
            })?;
        }
        _ => {
            return Err(
                "node affinity operator must be In, NotIn, Exists, DoesNotExist, Gt, or Lt"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn validate_kubernetes_preferred_node_affinity_arg(
    preference: &KubernetesPreferredNodeAffinityArg,
) -> Result<(), String> {
    if !(1..=100).contains(&preference.weight) {
        return Err("preferred node affinity weight must be an integer from 1 to 100".to_string());
    }
    validate_kubernetes_node_affinity_expression_arg(&preference.expression)
}

fn validate_kubernetes_label_selector_expression_arg(
    expression: &KubernetesLabelSelectorExpressionArg,
) -> Result<(), String> {
    validate_kubernetes_label_key(&expression.key)?;
    match expression.operator.as_str() {
        "In" | "NotIn" => {
            if expression.values.is_empty() {
                return Err(format!(
                    "pod affinity label selector values are required when operator is {}",
                    expression.operator
                ));
            }
            for value in &expression.values {
                validate_kubernetes_label_value(value)?;
            }
        }
        "Exists" | "DoesNotExist" => {
            if !expression.values.is_empty() {
                return Err(format!(
                    "pod affinity label selector values must be omitted when operator is {}",
                    expression.operator
                ));
            }
        }
        _ => {
            return Err(
                "pod affinity label selector operator must be In, NotIn, Exists, or DoesNotExist"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn validate_kubernetes_pod_affinity_term_arg(
    term: &KubernetesPodAffinityTermArg,
) -> Result<(), String> {
    validate_kubernetes_label_key(&term.topology_key)?;
    if term.match_expressions.is_empty() {
        return Err("pod affinity term requires at least one match expression".to_string());
    }
    for expression in &term.match_expressions {
        validate_kubernetes_label_selector_expression_arg(expression)?;
    }
    let mut namespaces = std::collections::BTreeSet::new();
    for namespace in &term.namespaces {
        validate_kubernetes_namespace(namespace).map_err(|error| error.to_string())?;
        if !namespaces.insert(namespace.as_str()) {
            return Err(format!(
                "pod affinity namespace `{namespace}` must not be repeated"
            ));
        }
    }
    Ok(())
}

fn validate_kubernetes_preferred_pod_affinity_arg(
    preference: &KubernetesPreferredPodAffinityArg,
) -> Result<(), String> {
    if !(1..=100).contains(&preference.weight) {
        return Err("preferred pod affinity weight must be an integer from 1 to 100".to_string());
    }
    validate_kubernetes_pod_affinity_term_arg(&preference.term)
}

fn validate_kubernetes_toleration_arg(toleration: &KubernetesTolerationArg) -> Result<(), String> {
    let operator = toleration.operator.as_deref().unwrap_or("Equal");
    match operator {
        "Exists" | "Equal" => {}
        _ => return Err("toleration operator must be Exists or Equal".to_string()),
    }

    if let Some(key) = toleration.key.as_deref() {
        validate_kubernetes_label_key(key)?;
    } else if operator != "Exists" {
        return Err("toleration with no key requires operator Exists".to_string());
    }

    if toleration.value.is_some() && operator == "Exists" {
        return Err("toleration value must be omitted when operator is Exists".to_string());
    }
    if let Some(value) = toleration.value.as_deref() {
        validate_kubernetes_label_value(value)?;
    }

    if let Some(effect) = toleration.effect.as_deref() {
        match effect {
            "NoSchedule" | "PreferNoSchedule" | "NoExecute" => {}
            _ => {
                return Err(
                    "toleration effect must be NoSchedule, PreferNoSchedule, or NoExecute"
                        .to_string(),
                );
            }
        }
    }

    if toleration.toleration_seconds.is_some() && toleration.effect.as_deref() != Some("NoExecute")
    {
        return Err("tolerationSeconds requires effect NoExecute".to_string());
    }

    Ok(())
}

fn validate_kubernetes_topology_spread_arg(
    constraint: &KubernetesTopologySpreadArg,
) -> Result<(), String> {
    validate_kubernetes_label_key(&constraint.topology_key)?;
    if constraint.max_skew == 0 || constraint.max_skew > i32::MAX as u32 {
        return Err("topology spread maxSkew must be between 1 and 2147483647".to_string());
    }
    match constraint.when_unsatisfiable.as_str() {
        "DoNotSchedule" | "ScheduleAnyway" => {}
        _ => {
            return Err(
                "topology spread whenUnsatisfiable must be DoNotSchedule or ScheduleAnyway"
                    .to_string(),
            );
        }
    }
    if let Some(min_domains) = constraint.min_domains {
        if min_domains == 0 || min_domains > i32::MAX as u32 {
            return Err("topology spread minDomains must be between 1 and 2147483647".to_string());
        }
        if constraint.when_unsatisfiable != "DoNotSchedule" {
            return Err(
                "topology spread minDomains requires whenUnsatisfiable=DoNotSchedule".to_string(),
            );
        }
    }
    if let Some(policy) = constraint.node_affinity_policy.as_deref() {
        match policy {
            "Honor" | "Ignore" => {}
            _ => {
                return Err(
                    "topology spread nodeAffinityPolicy must be Honor or Ignore".to_string()
                );
            }
        }
    }
    if let Some(policy) = constraint.node_taints_policy.as_deref() {
        match policy {
            "Honor" | "Ignore" => {}
            _ => {
                return Err("topology spread nodeTaintsPolicy must be Honor or Ignore".to_string());
            }
        }
    }
    Ok(())
}

fn validate_kubernetes_load_balancer_class(value: &str) -> Result<(), String> {
    let (prefix, name) = match value.split_once('/') {
        Some((prefix, name)) => {
            if name.contains('/') {
                return Err("loadBalancerClass must contain at most one '/' separator".to_string());
            }
            (Some(prefix), name)
        }
        None => (None, value),
    };
    if let Some(prefix) = prefix {
        validate_kubernetes_dns_subdomain(prefix, "loadBalancerClass prefix")?;
    }
    validate_kubernetes_qualified_name(name, "loadBalancerClass name")
}

fn validate_kubernetes_app_protocol(value: &str) -> Result<(), String> {
    let (prefix, name) = match value.split_once('/') {
        Some((prefix, name)) => {
            if name.contains('/') {
                return Err("appProtocol must contain at most one '/' separator".to_string());
            }
            (Some(prefix), name)
        }
        None => (None, value),
    };
    if let Some(prefix) = prefix {
        validate_kubernetes_dns_subdomain(prefix, "appProtocol prefix")?;
    }
    validate_kubernetes_qualified_name(name, "appProtocol name")
}

fn validate_kubernetes_dns_subdomain(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.len() > 253 {
        return Err(format!("{label} exceeds 253 bytes"));
    }
    for part in value.split('.') {
        if part.is_empty() {
            return Err(format!("{label} must not contain empty DNS labels"));
        }
        if part.len() > 63 {
            return Err(format!("{label} DNS label `{part}` exceeds 63 bytes"));
        }
        let valid_body = part
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        let valid_edges = part
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && part
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
        if !valid_body || !valid_edges {
            return Err(format!(
                "{label} `{value}` must be a DNS subdomain using lowercase ASCII letters, digits, and '-' with alphanumeric label edges"
            ));
        }
    }
    Ok(())
}

fn validate_kubernetes_dns_label_with_max(
    value: &str,
    label: &str,
    max_bytes: usize,
) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.len() > max_bytes {
        return Err(format!("{label} exceeds {max_bytes} bytes"));
    }
    let valid_body = value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    let valid_edges = value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if !valid_body || !valid_edges {
        return Err(format!(
            "{label} `{value}` must be a DNS label using lowercase ASCII letters, digits, and '-' with alphanumeric edges"
        ));
    }
    Ok(())
}

fn validate_kubernetes_qualified_name(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.len() > 63 {
        return Err(format!("{label} exceeds 63 bytes"));
    }
    let valid_body = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    let valid_edges = value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
    if !valid_body || !valid_edges {
        return Err(format!(
            "{label} `{value}` must use ASCII letters, digits, '-', '_', or '.', with alphanumeric edges"
        ));
    }
    Ok(())
}

const KUBERNETES_ANNOTATION_VALUE_MAX_BYTES: usize = 262_144;

fn validate_kubernetes_annotation_value(value: &str) -> Result<(), String> {
    if value.len() > KUBERNETES_ANNOTATION_VALUE_MAX_BYTES {
        return Err(format!(
            "annotation value exceeds {KUBERNETES_ANNOTATION_VALUE_MAX_BYTES} bytes"
        ));
    }
    if value.chars().any(char::is_control) {
        return Err("annotation value cannot contain control characters".to_string());
    }
    if value.chars().any(char::is_whitespace) {
        return Err(
            "annotation value cannot contain whitespace in generated Helm --set-string commands"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_kubernetes_annotation_args(
    flag: &str,
    annotations: &[KeyValueArg],
) -> anyhow::Result<()> {
    let mut seen = BTreeSet::new();
    for annotation in annotations {
        validate_kubernetes_annotation_key(&annotation.key)
            .map_err(|error| anyhow::anyhow!("{flag} {error}"))?;
        validate_kubernetes_annotation_value(&annotation.value)
            .map_err(|error| anyhow::anyhow!("{flag} {error}"))?;
        if !seen.insert(annotation.key.as_str()) {
            anyhow::bail!("{flag} must not repeat annotation key {}", annotation.key);
        }
    }
    Ok(())
}

fn validate_kubernetes_service_annotation_args(
    flag: &str,
    annotations: &[KeyValueArg],
) -> anyhow::Result<()> {
    validate_kubernetes_annotation_args(flag, annotations)?;
    for annotation in annotations {
        if kubernetes_service_annotation_controls_source_ranges(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not configure LoadBalancer source ranges; use --agent-api-allow-source-cidr or --relay-allow-source-cidr instead",
                annotation.key
            );
        }
        if kubernetes_service_annotation_controls_fixed_addresses(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not configure LoadBalancer fixed addresses; use --agent-api-load-balancer-ip, --agent-api-external-ip, --relay-load-balancer-ip, or --relay-external-ip instead",
                annotation.key
            );
        }
        if kubernetes_service_annotation_controls_proxy_protocol(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not enable PROXY protocol; IPARS Services do not accept PROXY protocol headers",
                annotation.key
            );
        }
        if kubernetes_service_annotation_controls_health_checks(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not configure LoadBalancer health checks; use typed Service health-check controls instead",
                annotation.key
            );
        }
        if kubernetes_service_annotation_controls_listener_protocol(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not configure LoadBalancer TLS, listeners, or backend protocols; use typed Service ports/appProtocol and plain IPARS listeners instead",
                annotation.key
            );
        }
        if kubernetes_service_annotation_controls_load_balancer_scope(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not configure LoadBalancer scope or implementation type; use typed Service type, loadBalancerClass, exposure acknowledgement, and source-range controls instead",
                annotation.key
            );
        }
        if kubernetes_service_annotation_controls_firewall_policy(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not configure LoadBalancer firewall or security groups; use --agent-api-allow-source-cidr, --relay-allow-source-cidr, or NetworkPolicy controls instead",
                annotation.key
            );
        }
        if kubernetes_service_annotation_controls_network_placement(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not configure LoadBalancer network placement; use typed Service type, loadBalancerClass, source-range, and exposure controls instead",
                annotation.key
            );
        }
        if kubernetes_service_annotation_controls_operational_attributes(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not configure LoadBalancer operational attributes; use typed Service traffic policy, appProtocol, and IPARS listener controls instead",
                annotation.key
            );
        }
        if kubernetes_service_annotation_controls_dns_publication(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not publish LoadBalancer DNS names; use typed relay advertisement and explicit Service exposure controls instead",
                annotation.key
            );
        }
        if kubernetes_service_annotation_controls_resource_selection(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not configure LoadBalancer resource identity, tags, or address pools; use typed Service exposure controls and explicit fixed-address values instead",
                annotation.key
            );
        }
        if kubernetes_service_annotation_controls_private_link(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not configure LoadBalancer Private Link or endpoint-service publishing; use typed Service exposure controls and relay advertisement instead",
                annotation.key
            );
        }
        if kubernetes_service_annotation_controls_backend_target_selection(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not configure LoadBalancer backend target selection; use DaemonSet scheduling, externalTrafficPolicy, and typed Service exposure controls instead",
                annotation.key
            );
        }
        if kubernetes_service_annotation_controls_source_nat(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not configure LoadBalancer source NAT behavior; use internal/externalTrafficPolicy, source ranges, and NetworkPolicy controls instead",
                annotation.key
            );
        }
        if kubernetes_service_annotation_controls_traffic_distribution(&annotation.key) {
            anyhow::bail!(
                "{flag} annotation key {} must not configure LoadBalancer traffic distribution; use internal/externalTrafficPolicy and trafficDistribution controls instead",
                annotation.key
            );
        }
    }
    Ok(())
}

fn kubernetes_service_annotation_controls_source_ranges(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("source-range") || key.contains("inbound-cidr")
}

fn kubernetes_service_annotation_controls_fixed_addresses(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("load-balancer-ip")
        || key.contains("loadbalancerip")
        || key.contains("load-balancer-eip")
        || key.contains("eip-allocations")
        || key.ends_with("/load-balancer-address")
        || key.ends_with("/loadbalancer-address")
        || key.contains("static-ip")
        || key.contains("ip-address")
        || key.contains("private-ipv4-address")
        || key.contains("pip-name")
        || key.contains("pip-prefix")
        || key.contains("public-ip-prefix")
        || key.contains("public-ips")
        || key.contains("lb-ipam-ips")
}

fn kubernetes_service_annotation_controls_proxy_protocol(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("proxy-protocol") || key.contains("proxyprotocol")
}

fn kubernetes_service_annotation_controls_health_checks(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("healthcheck")
        || key.contains("health-check")
        || key.contains("health_probe")
        || key.contains("health-probe")
}

fn kubernetes_service_annotation_controls_listener_protocol(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("ssl-cert")
        || key.contains("ssl-ports")
        || key.contains("ssl-negotiation-policy")
        || key.contains("tls-cert")
        || key.contains("tls-ports")
        || key.contains("certificate-arn")
        || key.contains("certificate")
        || key.contains("load-balancer-protocol")
        || key.contains("loadbalancer-protocol")
        || key.contains("backend-protocol")
        || key.contains("backend-protocol-version")
        || key.contains("app-protocol")
        || key.contains("app_protocol")
        || key.contains("http2-ports")
        || key.contains("http3-ports")
        || key.contains("redirect-http")
        || key.contains("listener")
        || key.contains("alpn-policy")
        || key.contains("high-availability-ports")
        || key.contains("ha-ports")
        || key.contains("enable-icmp")
}

fn kubernetes_service_annotation_controls_load_balancer_scope(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("load-balancer-scheme")
        || key.contains("loadbalancer-scheme")
        || key.contains("load-balancer-internal")
        || key.contains("loadbalancer-internal")
        || key.contains("internal-load-balancer")
        || key.contains("load-balancer-type")
        || key.contains("loadbalancer-type")
        || key.contains("load-balancer-address-type")
        || key.contains("loadbalancer-address-type")
        || key.contains("load-balancer-class")
        || key.contains("loadbalancerclass")
        || key.contains("load-balancer-shape")
        || key.contains("loadbalancer-shape")
        || key.contains("load-balancer-cloud-provider-ip-type")
        || key.contains("nlb-target-type")
        || key.contains("l4-rbs")
        || key.contains("global-access")
        || key.contains("allow-global-access")
}

fn kubernetes_service_annotation_controls_firewall_policy(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("security-group")
        || key.contains("securitygroup")
        || key.contains("firewall")
        || key.contains("waf")
        || key.contains("web-acl")
        || key.contains("webacl")
        || key.contains("security-policy")
        || key.contains("securitypolicy")
        || key.contains("security-list")
        || key.contains("allowed-service-tags")
        || key.contains("allowed-ip-ranges")
        || key.contains("shared-securityrule")
}

fn kubernetes_service_annotation_controls_network_placement(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("subnet")
        || key.contains("vlan")
        || key.contains("network-tier")
        || key.contains("network-endpoint-group")
        || key.contains("cloud.google.com/neg")
        || key.contains("resource-group")
        || key.contains("availability-zone")
        || key.contains("cloud-provider-zone")
}

fn kubernetes_service_annotation_controls_operational_attributes(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("load-balancer-attributes")
        || key.contains("loadbalancer-attributes")
        || key.contains("backend-config")
        || key.contains("target-group-attributes")
        || key.contains("targetgroup-attributes")
        || key.contains("access-log")
        || key.contains("accesslog")
        || key.contains("enable-features")
        || key.contains("idle-timeout")
        || key.contains("connection-draining")
        || key.contains("deregistration-delay")
        || key.contains("cross-zone")
        || key.contains("preserve-client-ip")
        || key.contains("tcp-reset")
        || key.contains("size-unit")
        || key.contains("flavor-id")
}

fn kubernetes_service_annotation_controls_dns_publication(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("external-dns")
        || key.contains("dns-name")
        || key.contains("dns-label")
        || key.contains("dns-record")
        || key.contains("load-balancer-hostname")
        || key.contains("loadbalancer-hostname")
        || key.contains("domain-name")
        || key.contains("domainname")
        || key.contains("fqdn")
}

fn kubernetes_service_annotation_controls_resource_selection(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("load-balancer-name")
        || key.contains("loadbalancer-name")
        || key.contains("target-group-name")
        || key.contains("targetgroup-name")
        || key.contains("load-balancer-configuration")
        || key.contains("load-balancer-mode")
        || key.contains("resource-tags")
        || key.contains("additional-resource-tags")
        || key.contains("defined-tags")
        || key.contains("freeform-tags")
        || key.contains("pip-ip-tags")
        || key.contains("pip-tags")
        || key.contains("address-pool")
        || key.contains("addresspool")
        || key.contains("ip-pool")
        || key.contains("ippool")
}

fn kubernetes_service_annotation_controls_private_link(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("azure-pls")
        || key.contains("private-link")
        || key.contains("privatelink")
        || key.contains("private-service-connect")
        || key.contains("endpoint-service")
        || key.contains("service-attachment")
}

fn kubernetes_service_annotation_controls_backend_target_selection(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("target-node-label")
        || key.contains("target-node-selector")
        || key.contains("backend-node-label")
        || key.contains("backend-node-selector")
        || key.contains("node-selector")
        || key.contains("node-labels")
}

fn kubernetes_service_annotation_controls_source_nat(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("source-nat")
        || key.contains("disable-load-balancer-snat")
        || key.contains("disable-snat")
        || key.contains("outbound-snat")
        || key.contains("enable-prefix-for-ipv6-source-nat")
}

fn kubernetes_service_annotation_controls_traffic_distribution(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("traffic-distribution")
        || key.contains("traffic_distribution")
        || key.contains("weighted-load-balancing")
        || key.contains("load-balancing-policy")
        || key.contains("loadbalancing-policy")
        || key.contains("load-balancer-policy")
        || key.contains("loadbalancer-policy")
        || key.contains("load-balancing-algorithm")
        || key.contains("traffic-policy")
        || key.contains("traffic_policy")
        || key.contains("topology-mode")
        || key.contains("topology-aware")
}

fn validate_kubernetes_resource_quantity(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.len() > 64 {
        return Err(format!("{label} exceeds 64 bytes"));
    }
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_digit()) {
        return Err(format!("{label} must start with a digit"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
    {
        return Err(format!("{label} must not contain whitespace or separators"));
    }
    if !value
        .bytes()
        .last()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(format!("{label} must end with a digit or suffix letter"));
    }
    Ok(())
}

fn normalize_kubernetes_http_api_base_url(value: &str, label: &str) -> anyhow::Result<String> {
    let parsed =
        reqwest::Url::parse(value).with_context(|| format!("{label} must be an absolute URL"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("{label} must not include userinfo");
    }
    normalize_http_api_base_url(value, label)
}

fn validate_kubernetes_stun_endpoint(value: &str, label: &str) -> Result<(), String> {
    let endpoint = value
        .parse::<SocketAddr>()
        .map_err(|_| format!("{label} must be an IPv4 host:port or [IPv6]:port socket address"))?;
    if !endpoint_addr_is_usable(endpoint) {
        return Err(format!(
            "{label} must use a usable nonzero, non-unspecified, non-multicast, non-broadcast socket address"
        ));
    }
    Ok(())
}

fn validate_kubernetes_http_probe_path(path: &str, label: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if !path.starts_with('/') {
        return Err(format!("{label} `{path}` must be absolute"));
    }
    if path.len() > 256 {
        return Err(format!("{label} `{path}` exceeds 256 bytes"));
    }
    if !path.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'/' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'%'
                    | b'-'
            )
    }) {
        return Err(format!(
            "{label} `{path}` must contain only HTTP path-safe ASCII characters"
        ));
    }
    Ok(())
}

fn validate_container_image_repository(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.len() > 255 {
        return Err(format!("{label} exceeds 255 bytes"));
    }
    if value.starts_with('/') || value.ends_with('/') || value.contains("//") {
        return Err(format!(
            "{label} must be a non-empty slash-separated image repository path"
        ));
    }
    if value.contains('@') {
        return Err(format!(
            "{label} must not include a digest; pin an immutable tag with --image-tag"
        ));
    }
    if value.bytes().any(|byte| {
        !matches!(
            byte,
            b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b'/' | b':'
        )
    }) {
        return Err(format!(
            "{label} may contain only lowercase ASCII letters, digits, '.', '_', '-', '/', and registry port ':'"
        ));
    }
    let components = value.split('/').collect::<Vec<_>>();
    if components
        .last()
        .is_some_and(|segment| segment.contains(':'))
    {
        return Err(format!(
            "{label} must not include a tag; use --image-tag instead"
        ));
    }
    for (index, component) in components.iter().enumerate() {
        if let Some((_, port)) = component.rsplit_once(':') {
            if index != 0 || components.len() == 1 || port.is_empty() {
                return Err(format!(
                    "{label} registry port may only appear before the first '/'"
                ));
            }
            if !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!("{label} registry port must be numeric"));
            }
        }
    }
    Ok(())
}

fn validate_container_image_tag(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.len() > 128 {
        return Err(format!("{label} exceeds 128 bytes"));
    }
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(format!("{label} must not be empty"));
    };
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return Err(format!(
            "{label} must start with an ASCII letter, digit, or '_'"
        ));
    }
    if bytes.any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))) {
        return Err(format!(
            "{label} may contain only ASCII letters, digits, '_', '.', and '-'"
        ));
    }
    Ok(())
}

fn validate_token_identifier(value: &str, label: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("{label} cannot be empty");
    }
    if value.len() > MAX_JOIN_TOKEN_IDENTIFIER_BYTES {
        anyhow::bail!("{label} exceeds {MAX_JOIN_TOKEN_IDENTIFIER_BYTES} bytes");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        anyhow::bail!("{label} must contain only ASCII letters, digits, '_', '.' or '-'");
    }
    Ok(())
}

fn validate_join_token_ttl(ttl_seconds: i64) -> anyhow::Result<()> {
    if ttl_seconds <= 0 {
        anyhow::bail!("join token TTL must be greater than zero seconds");
    }
    if ttl_seconds > MAX_JOIN_TOKEN_TTL_SECONDS {
        anyhow::bail!("join token TTL must not exceed {MAX_JOIN_TOKEN_TTL_SECONDS} seconds");
    }
    Ok(())
}

fn validate_join_token_allowed_routes(flag: &str, cidrs: &[ipnet::IpNet]) -> anyhow::Result<()> {
    if cidrs.len() > MAX_JOIN_TOKEN_ALLOWED_ROUTES {
        anyhow::bail!("{flag} may be repeated at most {MAX_JOIN_TOKEN_ALLOWED_ROUTES} times");
    }
    let mut seen = BTreeSet::new();
    let mut routes = Vec::new();
    for cidr in cidrs {
        if let Some(reason) = restricted_route_cidr_reason(cidr) {
            anyhow::bail!("{flag} must not include {reason} join-token allowed route {cidr}");
        }
        let route = cidr.trunc();
        if cidr != &route {
            anyhow::bail!("{flag} must use canonical join-token allowed route {route}, not {cidr}");
        }
        if !seen.insert(route) {
            anyhow::bail!("{flag} must not repeat join-token allowed route {route}");
        }
        if let Some(overlap) = routes
            .iter()
            .find(|existing| ip_cidrs_overlap(existing, &route))
        {
            anyhow::bail!(
                "{flag} must not include overlapping join-token allowed routes {overlap} and {route}"
            );
        }
        routes.push(route);
    }
    Ok(())
}

fn helm_set_key(key: &str) -> String {
    let mut escaped = String::with_capacity(key.len());
    for value in key.chars() {
        if matches!(value, '.' | '[' | ']' | '\\') {
            escaped.push('\\');
        }
        escaped.push(value);
    }
    escaped
}

fn helm_set_string_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace(',', "\\,")
}

fn append_helm_set_string(command: &mut String, key: &str, value: &str) {
    let assignment = format!("{key}={}", helm_set_string_value(value));
    command.push_str(&format!(" --set-string {}", shell_word(&assignment)));
}

fn append_helm_ipnet_list(command: &mut String, key: &str, values: &[ipnet::IpNet]) {
    for (index, value) in values.iter().enumerate() {
        append_helm_set_string(command, &format!("{key}[{index}]"), &value.to_string());
    }
}

fn append_helm_string_list(command: &mut String, key: &str, values: &[String]) {
    for (index, value) in values.iter().enumerate() {
        append_helm_set_string(command, &format!("{key}[{index}]"), value);
    }
}

fn append_helm_ipaddr_list(command: &mut String, key: &str, values: &[IpAddr]) {
    for (index, value) in values.iter().enumerate() {
        append_helm_set_string(command, &format!("{key}[{index}]"), &value.to_string());
    }
}

fn append_helm_literal_list(command: &mut String, key: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    let assignment = format!("{key}={{{}}}", values.join(","));
    command.push_str(&format!(" --set {}", shell_word(&assignment)));
}

fn shell_word(value: &str) -> String {
    if !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-'
                )
        })
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn required_node_id(value: Option<&str>, command: &str) -> anyhow::Result<NodeId> {
    let value = value
        .with_context(|| format!("ipars {command} requires --node-id with --control-plane-url"))?;
    validated_node_id(value, "--node-id")
}

fn validated_node_id(value: &str, label: &str) -> anyhow::Result<NodeId> {
    validate_token_identifier(value, label)?;
    Ok(NodeId::from_string(value))
}

fn routes_output(node_id: NodeId, peer_map: PeerMap) -> RoutesOutput {
    let routes = peer_map
        .peers
        .iter()
        .flat_map(|peer| {
            peer.routes.iter().cloned().map(|route| RouteEntry {
                peer: peer.node_id.clone(),
                route,
            })
        })
        .collect();
    RoutesOutput {
        cluster_id: peer_map.cluster_id,
        node_id,
        generated_at: peer_map.generated_at,
        routes,
    }
}

#[derive(Debug, Clone)]
struct TokenIssuer {
    node_id: NodeId,
    key_id: KeyId,
}

#[derive(Debug, Clone)]
struct TokenPolicyInput {
    allow_relay: bool,
    allowed_routes: Vec<ipnet::IpNet>,
    max_token_uses: Option<u32>,
}

fn max_token_uses(max_uses: Option<u32>, unlimited_uses: bool) -> Option<u32> {
    if unlimited_uses {
        None
    } else {
        max_uses.or(TokenPolicy::default().max_token_uses)
    }
}

fn claims(
    cluster_id: ClusterId,
    issuer: TokenIssuer,
    role: String,
    tags: Vec<String>,
    ttl_seconds: i64,
    bootstrap_endpoints: Vec<BootstrapEndpoint>,
    policy_input: TokenPolicyInput,
) -> anyhow::Result<JoinTokenClaims> {
    validate_token_identifier(cluster_id.as_str(), "--cluster-id")?;
    validate_token_identifier(issuer.node_id.as_str(), "issuer node ID")?;
    validate_token_identifier(issuer.key_id.as_str(), "--issuer-key-id")?;
    validate_token_identifier(&role, "--role")?;
    validate_join_token_ttl(ttl_seconds)?;
    if tags.len() > MAX_JOIN_TOKEN_TAGS {
        anyhow::bail!("--tag may be repeated at most {MAX_JOIN_TOKEN_TAGS} times");
    }
    for tag in &tags {
        validate_token_identifier(tag, "--tag")?;
    }
    validate_join_token_allowed_routes("--allowed-route", &policy_input.allowed_routes)?;
    let now = Utc::now();
    let ttl = Duration::seconds(ttl_seconds);
    let tag_set = tags
        .into_iter()
        .map(Tag::from_string)
        .collect::<BTreeSet<_>>();
    let policy = TokenPolicy {
        allow_relay: policy_input.allow_relay,
        allowed_routes: policy_input.allowed_routes,
        allowed_tags: tag_set.clone(),
        max_token_uses: policy_input.max_token_uses,
        ..TokenPolicy::default()
    };

    let claims = JoinTokenClaims {
        cluster_id,
        bootstrap_endpoints,
        expires_at: now + ttl,
        not_before: now - Duration::seconds(JOIN_TOKEN_NOT_BEFORE_SKEW_SECONDS),
        role: Role::from_string(role),
        tags: tag_set,
        issuer: issuer.node_id,
        key_id: issuer.key_id,
        policy,
        nonce: format!("nonce-{}", now.timestamp_nanos_opt().unwrap_or_default()),
    };
    claims.validate_shape()?;
    Ok(claims)
}

fn bootstrap_from_public_endpoint(args: &InitArgs) -> Vec<BootstrapEndpoint> {
    let host = args.public_endpoint.ip();
    let control_plane = SocketAddr::new(host, args.control_plane_listen.port());
    let signal = SocketAddr::new(host, args.signal_listen.port());
    let stun = SocketAddr::new(host, args.stun_listen.port());
    vec![
        BootstrapEndpoint {
            url: format!("{}://{control_plane}", args.bootstrap_scheme),
            kind: BootstrapEndpointKind::ControlPlane,
        },
        BootstrapEndpoint {
            url: format!("{}://{signal}", args.bootstrap_scheme),
            kind: BootstrapEndpointKind::Signal,
        },
        BootstrapEndpoint {
            url: format!("udp://{stun}"),
            kind: BootstrapEndpointKind::Stun,
        },
        BootstrapEndpoint {
            url: format!("udp://{}", args.public_endpoint),
            kind: BootstrapEndpointKind::Relay,
        },
    ]
}

#[cfg(test)]
fn control_plane_join_url(
    token: &SignedJoinToken,
    override_url: Option<&str>,
) -> anyhow::Result<String> {
    control_plane_join_urls(token, override_url)?
        .into_iter()
        .next()
        .context("join token does not contain a control-plane bootstrap URL")
}

fn control_plane_join_urls(
    token: &SignedJoinToken,
    override_url: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let (base_urls, name) = if let Some(url) = override_url {
        (vec![url.to_string()], "control-plane URL")
    } else {
        (
            token
                .claims
                .bootstrap_endpoints
                .iter()
                .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
                .map(|endpoint| endpoint.url.clone())
                .collect(),
            "control-plane bootstrap URL",
        )
    };
    if base_urls.is_empty() {
        anyhow::bail!("join token does not contain a control-plane bootstrap URL");
    }
    base_urls
        .into_iter()
        .map(|base_url| {
            normalize_http_api_base_url(&base_url, name)
                .map(|base_url| format!("{base_url}/v1/join"))
        })
        .collect()
}

fn control_plane_token_revoke_url(control_plane_url: &str) -> anyhow::Result<String> {
    let control_plane_url = normalize_http_api_base_url(control_plane_url, "control-plane URL")?;
    Ok(format!("{control_plane_url}/v1/tokens/revoke"))
}

fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[derive(Debug, Serialize)]
struct InitOutput {
    cluster_id: ClusterId,
    node_id: NodeId,
    issuer_node_id: NodeId,
    issuer_key_id: KeyId,
    issuer_public_key: String,
    issuer_private_key_b64: Option<String>,
    issuer_private_key_path: Option<PathBuf>,
    control_plane_operator_api_bearer_token_path: Option<PathBuf>,
    identity_public_key: String,
    wireguard_public_key: String,
    bootstrap_endpoints: Vec<BootstrapEndpoint>,
    join_token: SignedJoinToken,
    services: Vec<String>,
    daemon_state_dir: PathBuf,
    daemon_commands: Vec<InitDaemonCommand>,
    daemon_processes: Vec<InitDaemonProcess>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct InitDaemonCommand {
    service: String,
    command: Vec<String>,
    log_path: PathBuf,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct InitDaemonProcess {
    service: String,
    pid: u32,
    command: Vec<String>,
    log_path: PathBuf,
}

#[derive(Debug, Serialize)]
struct JoinOutput {
    cluster_id: ClusterId,
    node_id: NodeId,
    role: Role,
    tags: BTreeSet<Tag>,
    bootstrap_endpoints: Vec<BootstrapEndpoint>,
    identity_public_key: String,
    wireguard_public_key: String,
    control_plane_url: String,
    registered: bool,
    registration: Option<RegisterNodeResponse>,
}

#[derive(Debug, Serialize)]
struct RoutesOutput {
    cluster_id: ClusterId,
    node_id: NodeId,
    generated_at: chrono::DateTime<Utc>,
    routes: Vec<RouteEntry>,
}

#[derive(Debug, Serialize)]
struct RouteEntry {
    peer: NodeId,
    route: Route,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct InstallPlan {
    platform: String,
    manifest: String,
    commands: Vec<String>,
    environment: Vec<InstallEnvironment>,
    prerequisites: Vec<String>,
    security: Vec<String>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct InstallEnvironment {
    name: String,
    value: String,
}

fn docker_install_plan(args: DockerInstallArgs) -> anyhow::Result<InstallPlan> {
    validate_docker_install_args(&args)?;
    let compose_file = args.compose_file.display().to_string();
    let mut compose_prefix = format!("docker compose -p {}", shell_word(&args.project_name));
    for compose_file in docker_install_compose_files(&args) {
        compose_prefix.push_str(" -f ");
        compose_prefix.push_str(&shell_word(&compose_file));
    }
    let environment = docker_install_environment(&args);
    let mut prerequisites = vec![
        "Docker Engine with the Compose plugin".to_string(),
        "A reusable issuer private key for init/token create workflows".to_string(),
        "A separate 32-512 byte control-plane operator API Bearer token in docker/control-plane-operator-api.token, or IPARS_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN_FILE pointing to an equivalent owner-restricted file".to_string(),
        "A separate 32-512 byte signal operator API Bearer token in docker/signal-operator-api.token, or IPARS_SIGNAL_OPERATOR_API_BEARER_TOKEN_FILE pointing to an equivalent owner-restricted file".to_string(),
        "A separate 32-512 byte STUN operator API Bearer token in docker/stun-operator-api.token, or IPARS_STUN_OPERATOR_API_BEARER_TOKEN_FILE pointing to an equivalent owner-restricted file".to_string(),
        "A separate 32-512 byte relay operator API Bearer token in docker/relay-operator-api.token, or IPARS_RELAY_OPERATOR_API_BEARER_TOKEN_FILE pointing to an equivalent owner-restricted file".to_string(),
        "A separate 32-512 byte relay admission Bearer token in docker/relay-admission.token, or IPARS_RELAY_ADMISSION_BEARER_TOKEN_FILE pointing to an equivalent owner-restricted file shared only with authorized agents".to_string(),
        "A separate 32-512 byte agent API Bearer token in docker/agent-api.token, or IPARS_AGENT_API_BEARER_TOKEN_FILE pointing to an equivalent owner-restricted file".to_string(),
    ];
    if args.rootless {
        prerequisites.push(
            "Rootless Docker Engine for Compose services that cannot receive host kernel capabilities"
                .to_string(),
        );
        prerequisites.push(
            "Rootless mode is limited to non-mutating control-plane and peer-map validation; use a rootful agent for a WireGuard data plane".to_string(),
        );
    } else {
        prerequisites.push("net.ipv4.ip_forward=1 on Docker route-provider agents, plus net.ipv6.conf.all.forwarding=1 when routing IPv6 container CIDRs".to_string());
        prerequisites.push("/dev/net/tun available on agent/relay hosts".to_string());
        prerequisites.push("CAP_NET_ADMIN and CAP_NET_RAW for host dataplane mutation".to_string());
    }
    if args.docker_discover_networks {
        prerequisites
            .push("Docker API access from the agent for bridge-network IPAM discovery".to_string());
    }
    if args.relay_forwarder_bind.is_some() {
        prerequisites.push(
            "A reachable local WireGuard UDP endpoint for relay forwarder proxying".to_string(),
        );
    }
    if args.relay_forwarder_netns.is_some() {
        prerequisites.push(
            "CAP_SYS_ADMIN and a host /var/run/netns bind mount for relay forwarder namespace placement".to_string(),
        );
    }
    let mut notes = Vec::new();
    if args.rootless {
        notes.push("The rootless agent service runs with host networking for colocated service access, but docker/compose.rootless.yaml forces the non-mutating dry-run backend because it removes Linux capabilities and /dev/net/tun mounts".to_string());
    } else {
        notes.push("The agent service runs with host networking so it can manage WireGuard and Docker bridge routes".to_string());
    }
    notes.extend([
        "The bundled Compose file uses healthchecks and host-network loopback URLs for colocated control-plane, signal, relay, and agent HTTP endpoints".to_string(),
        "The bundled Compose file reads the agent join token from docker/join.token through a file-backed Compose secret and IPARS_AGENT_JOIN_TOKEN_PATH".to_string(),
        "The bundled Compose file reads a distinct control-plane operator API Bearer token from docker/control-plane-operator-api.token (or IPARS_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN_FILE) and protects metrics and policy routes".to_string(),
        "The bundled Compose file reads a distinct signal operator API Bearer token from docker/signal-operator-api.token (or IPARS_SIGNAL_OPERATOR_API_BEARER_TOKEN_FILE) and protects JSON and Prometheus metrics".to_string(),
        "The bundled Compose file reads a distinct STUN operator API Bearer token from docker/stun-operator-api.token (or IPARS_STUN_OPERATOR_API_BEARER_TOKEN_FILE) and protects JSON and Prometheus metrics without affecting UDP Binding requests".to_string(),
        "The bundled Compose file reads a distinct relay operator API Bearer token from docker/relay-operator-api.token (or IPARS_RELAY_OPERATOR_API_BEARER_TOKEN_FILE) and protects Prometheus metrics without changing the public capability status contract or admission authentication".to_string(),
        "The bundled Compose file mounts docker/relay-admission.token (or IPARS_RELAY_ADMISSION_BEARER_TOKEN_FILE) into the Relay and Agent as one shared file-backed admission credential without placing it in either service environment".to_string(),
        "The bundled Compose file reads a separate agent API Bearer token from docker/agent-api.token (or IPARS_AGENT_API_BEARER_TOKEN_FILE) through a file-backed Compose secret and protects every endpoint except /healthz".to_string(),
        "The bundled Compose file enables RFC5780 STUN filtering probes by passing IPARS_STUN_ALTERNATE_LISTEN and publishing the alternate UDP port".to_string(),
        "The bundled Compose file can pass userspace WireGuard launch/readiness/shutdown settings through IPARS_AGENT_USERSPACE_WIREGUARD_COMMAND, IPARS_AGENT_USERSPACE_WIREGUARD_ARGS, IPARS_AGENT_USERSPACE_WIREGUARD_READY_TIMEOUT_SECONDS, and IPARS_AGENT_USERSPACE_WIREGUARD_SHUTDOWN_TIMEOUT_SECONDS".to_string(),
        "The bundled Compose file passes relay daemon advertisement through IPARS_RELAY_PUBLIC_ENDPOINT/IPARS_RELAY_ADMISSION_URL and agent relay capability advertisement through IPARS_AGENT_RELAY_PUBLIC_ENDPOINT/IPARS_AGENT_RELAY_ADMISSION_URL; ipars docker install --relay-public-endpoint and --relay-admission-url emit both sides together so advertised relay metadata stays consistent".to_string(),
        "The bundled Compose file passes the relay admission secret through IPARS_RELAY_ADMISSION_BEARER_TOKEN_PATH and IPARS_AGENT_RELAY_ADMISSION_BEARER_TOKEN_PATH, and exposes relay admission abuse controls through IPARS_RELAY_MAX_SESSIONS_PER_NODE, IPARS_RELAY_ADMISSION_RATE_LIMIT, and IPARS_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS".to_string(),
        "The bundled Compose file can pass relay forwarder endpoint, bind, WireGuard endpoint, namespace placement, capacity, restart backoff, and crash-loop cooldown settings through IPARS_AGENT_RELAY_FORWARDER_* environment variables".to_string(),
    ]);
    if !args.rootless {
        notes.push("Docker network discovery plans add docker/compose.docker-discovery.yaml so the agent receives IPARS_DOCKER_API_SOCKET=/run/ipars/docker.sock and a read-only IPARS_DOCKER_API_SOCKET_HOST bind mount only when discovery is enabled".to_string());
        notes.push("Use --docker-discover-networks with repeated --docker-network values for multi-network Compose deployments".to_string());
    }
    if args.docker_discover_networks {
        notes.push("Docker network discovery plans include a host-side socket preflight command that checks IPARS_DOCKER_API_SOCKET_HOST, the explicit --docker-api-socket path, the rootless XDG runtime socket, or /var/run/docker.sock as an absolute dot-component-free non-symlink Unix socket before the discovery Compose override bind-mounts it into the agent".to_string());
    }
    if args.rootless {
        notes.push("Rootless Docker install plans add docker/compose.rootless.yaml so the agent and relay services do not request kernel capabilities or /dev/net/tun device mounts from rootless Docker".to_string());
        notes.push("Rootless Docker install plans reject userspace WireGuard process settings rather than advertising a data plane that cannot create a TUN interface without host capabilities".to_string());
        notes.push("Use a separate rootful agent for WireGuard data-plane and Docker container CIDR reachability; rootless install plans reject Docker route, Docker API discovery, and userspace WireGuard process settings instead of emitting an unusable runtime".to_string());
    } else {
        notes.push("For rootless Docker container CIDR reachability, run a separate rootful route-provider agent or an equivalent userspace routing layer instead of the rootless Compose override".to_string());
    }
    if args.relay_forwarder_netns.is_some() {
        notes.push("Relay forwarder namespace placement keeps the base Compose service least-privileged; add CAP_SYS_ADMIN and bind-mount the host /var/run/netns directory when enabling IPARS_AGENT_RELAY_FORWARDER_NETNS".to_string());
    }

    let mut commands = Vec::new();
    if args.docker_discover_networks {
        commands.push(docker_api_socket_preflight_command(&args));
    }
    commands.push(format!("{compose_prefix} config"));
    commands.push(format!("{compose_prefix} up -d --build"));

    Ok(InstallPlan {
        platform: "docker-compose".to_string(),
        manifest: compose_file,
        commands,
        environment,
        prerequisites,
        security: vec![
            "The bundled Compose file uses plain HTTP on a private development network".to_string(),
            "Expose control-plane, signal, relay, or agent APIs through an external TLS proxy before using public networks".to_string(),
            "Control-plane metrics and policy require IPARS_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN_FILE; do not reuse issuer, join-token, or node identity material".to_string(),
            "Signal metrics require IPARS_SIGNAL_OPERATOR_API_BEARER_TOKEN_FILE; keep it distinct from the control-plane operator credential and node identity material".to_string(),
            "STUN metrics require IPARS_STUN_OPERATOR_API_BEARER_TOKEN_FILE; keep it distinct from other operator credentials while leaving the public UDP Binding service credentialless".to_string(),
            "Relay metrics require IPARS_RELAY_OPERATOR_API_BEARER_TOKEN_FILE; do not reuse the separately scoped relay admission credential".to_string(),
            "Agent API requests require the separate IPARS_AGENT_API_BEARER_TOKEN_FILE secret; do not reuse the signed join token".to_string(),
            "Relay admission uses the shared IPARS_RELAY_ADMISSION_BEARER_TOKEN_FILE secret; rotate it independently from operator, issuer, join-token, node identity, and Agent API credentials".to_string(),
            "Relay use still requires signed join-token policy permission".to_string(),
        ],
        notes,
    })
}

fn docker_install_compose_files(args: &DockerInstallArgs) -> Vec<String> {
    let mut files = vec![args.compose_file.display().to_string()];
    if args.rootless {
        files.push(DOCKER_ROOTLESS_COMPOSE_FILE.to_string());
    }
    if args.docker_discover_networks {
        files.push(DOCKER_DISCOVERY_COMPOSE_FILE.to_string());
    }
    files
}

fn docker_api_socket_preflight_command(args: &DockerInstallArgs) -> String {
    let fallback = if let Some(socket) = args.docker_api_socket.as_ref() {
        format!(
            "docker_socket={}",
            shell_word(&socket.display().to_string())
        )
    } else if args.rootless {
        ": \"${XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR must be set}\"; docker_socket=\"${XDG_RUNTIME_DIR}/docker.sock\"".to_string()
    } else {
        "docker_socket=/var/run/docker.sock".to_string()
    };
    let mut command = format!(
        "docker_socket=${{IPARS_DOCKER_API_SOCKET_HOST:-}}; if [ -z \"$docker_socket\" ]; then {fallback}; fi; case \"$docker_socket\" in /*) ;; *) echo \"Docker API socket path must be an absolute Unix socket path\" >&2; exit 1;; esac; case \"$docker_socket\" in */../*|*/..|*/./*|*/.) echo \"Docker API socket path must not contain '.' or '..' path components\" >&2; exit 1;; esac; test ! -L \"$docker_socket\" && test -S \"$docker_socket\" && docker --host \"unix://$docker_socket\" version >/dev/null"
    );
    if !args.docker_networks.is_empty() {
        command.push_str("; docker_discovered_subnets=''");
    }
    for network in &args.docker_networks {
        command.push_str("; ");
        command.push_str(&docker_network_filter_preflight_command(network));
    }
    command
}

fn docker_network_filter_preflight_command(network: &str) -> String {
    let network = shell_word(network);
    format!(
        "docker_network={network}; docker_network_driver=$(docker --host \"unix://$docker_socket\" network inspect \"$docker_network\" --format {DOCKER_NETWORK_DRIVER_TEMPLATE} 2>/dev/null) || {{ echo \"Docker network filter $docker_network was not found\" >&2; exit 1; }}; if [ \"$docker_network_driver\" != \"bridge\" ]; then echo \"Docker network filter $docker_network is not a bridge network\" >&2; exit 1; fi; docker_network_subnets=$(docker --host \"unix://$docker_socket\" network inspect \"$docker_network\" --format {DOCKER_NETWORK_SUBNETS_TEMPLATE} 2>/dev/null) || exit 1; if [ -z \"$docker_network_subnets\" ]; then echo \"Docker network filter $docker_network has no IPAM subnets\" >&2; exit 1; fi; for docker_network_subnet in $docker_network_subnets; do case \" $docker_discovered_subnets \" in *\" $docker_network_subnet \"*) echo \"Docker network filters expose duplicate IPAM subnet $docker_network_subnet\" >&2; exit 1;; esac; docker_discovered_subnets=\"${{docker_discovered_subnets}}${{docker_network_subnet}} \"; done"
    )
}

fn validate_docker_install_args(args: &DockerInstallArgs) -> anyhow::Result<()> {
    parse_agent_runtime_backend(&args.agent_runtime_backend).map_err(anyhow::Error::msg)?;
    validate_linux_interface_name(&args.docker_host_interface)?;
    if let Some(namespace) = args.docker_container_namespace.as_deref() {
        validate_linux_namespace_name(namespace)?;
    }
    if let Some(socket) = args.docker_api_socket.as_ref() {
        validate_docker_api_socket_path(socket)?;
        if !args.docker_discover_networks {
            anyhow::bail!("--docker-api-socket requires --docker-discover-networks");
        }
    }
    validate_positive_docker_seconds(
        args.docker_route_interval_seconds,
        "--docker-route-interval-seconds",
    )?;
    validate_agent_http_timeout_settings(
        args.agent_http_connect_timeout_seconds,
        args.agent_http_request_timeout_seconds,
    )?;
    validate_agent_direct_path_verification_settings(
        args.agent_direct_path_probe_timeout_seconds,
        args.agent_direct_handshake_max_age_seconds,
        (!args.rootless && args.agent_runtime_backend == "linux-command")
            .then_some(DEFAULT_AGENT_PEER_MAP_POLL_INTERVAL_SECONDS),
    )?;
    validate_agent_peer_probe_settings(
        &args.agent_peer_probe,
        !args.rootless && args.agent_runtime_backend == "linux-command",
        DEFAULT_DOCKER_AGENT_WIREGUARD_LISTEN_PORT,
        DEFAULT_DOCKER_AGENT_PEER_PROBE_PORT,
    )?;
    validate_docker_userspace_wireguard_args(args)?;
    validate_docker_relay_advertisement(args)?;
    validate_relay_forwarder_install_settings(RelayForwarderInstallSettings::from_docker(args))?;
    validate_rootless_docker_install_args(args)?;
    if !args.docker_discover_networks && !args.docker_networks.is_empty() {
        anyhow::bail!("--docker-network requires --docker-discover-networks");
    }
    if args.docker_discover_networks && !args.docker_container_cidrs.is_empty() {
        anyhow::bail!(
            "--docker-discover-networks cannot be combined with explicit --docker-container-cidr values"
        );
    }
    validate_docker_container_cidrs("--docker-container-cidr", &args.docker_container_cidrs)?;
    validate_docker_network_filters(&args.docker_networks)?;
    Ok(())
}

fn validate_docker_relay_advertisement(args: &DockerInstallArgs) -> anyhow::Result<()> {
    if args.relay_max_sessions == 0 {
        anyhow::bail!("--relay-max-sessions must be greater than zero");
    }
    if args.relay_max_mbps == 0 {
        anyhow::bail!("--relay-max-mbps must be greater than zero");
    }
    if args.relay_max_sessions_per_node > args.relay_max_sessions {
        anyhow::bail!(
            "--relay-max-sessions-per-node must be less than or equal to --relay-max-sessions"
        );
    }
    validate_bounded_docker_seconds(
        args.relay_session_ttl_seconds,
        "--relay-session-ttl-seconds",
        MAX_RELAY_SESSION_TTL_SECONDS,
    )?;
    if args.relay_admission_rate_limit > 0 {
        validate_bounded_docker_seconds(
            args.relay_admission_rate_limit_window_seconds,
            "--relay-admission-rate-limit-window-seconds",
            MAX_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
        )?;
    }

    let advertises_relay =
        args.relay_public_endpoint.is_some() || args.relay_admission_url.is_some();
    if args.relay_status_url.is_some() && !advertises_relay {
        anyhow::bail!(
            "--relay-status-url requires --relay-public-endpoint and --relay-admission-url"
        );
    }
    if !advertises_relay {
        return Ok(());
    }
    let public_endpoint = args
        .relay_public_endpoint
        .as_deref()
        .context("--relay-public-endpoint and --relay-admission-url must be set together")?;
    let admission_url = args
        .relay_admission_url
        .as_deref()
        .context("--relay-public-endpoint and --relay-admission-url must be set together")?;
    validate_relay_public_endpoint_arg(public_endpoint, "--relay-public-endpoint")?;
    validate_relay_http_url_arg(admission_url, "--relay-admission-url")?;
    if let Some(status_url) = args.relay_status_url.as_deref() {
        validate_relay_http_url_arg(status_url, "--relay-status-url")?;
    }
    Ok(())
}

fn validate_rootless_docker_install_args(args: &DockerInstallArgs) -> anyhow::Result<()> {
    if !args.rootless {
        return Ok(());
    }
    if args.userspace_wireguard_command.is_some() || !args.userspace_wireguard_args.is_empty() {
        anyhow::bail!(
            "--rootless does not support --userspace-wireguard-command or --userspace-wireguard-arg because docker/compose.rootless.yaml cannot create a TUN interface"
        );
    }
    if args.userspace_wireguard_ready_timeout_seconds
        != DEFAULT_USERSPACE_WIREGUARD_READY_TIMEOUT_SECONDS
        || args.userspace_wireguard_shutdown_timeout_seconds
            != DEFAULT_USERSPACE_WIREGUARD_SHUTDOWN_TIMEOUT_SECONDS
    {
        anyhow::bail!(
            "--rootless does not support userspace WireGuard lifecycle timeout settings because docker/compose.rootless.yaml uses the dry-run backend"
        );
    }
    let has_docker_route_settings = args.docker_discover_networks
        || !args.docker_networks.is_empty()
        || args.docker_api_socket.is_some()
        || args.docker_container_namespace.is_some()
        || !args.docker_container_cidrs.is_empty()
        || args.docker_host_interface != DEFAULT_DOCKER_HOST_INTERFACE
        || args.disable_docker_expose_host_routes
        || args.docker_route_interval_seconds != DEFAULT_DOCKER_ROUTE_INTERVAL_SECONDS
        || args.route_backend != "command";
    if has_docker_route_settings {
        anyhow::bail!(
            "--rootless cannot be combined with Docker route or discovery settings because docker/compose.rootless.yaml removes NET_ADMIN and /dev/net/tun; remove Docker route flags or run a rootful route-provider agent for Docker container CIDR reachability"
        );
    }
    if args.relay_forwarder_netns.is_some() {
        anyhow::bail!(
            "--rootless cannot be combined with --relay-forwarder-netns because docker/compose.rootless.yaml removes the CAP_SYS_ADMIN and host namespace access required for namespaced relay forwarders"
        );
    }
    let has_relay_forwarder_settings = args.relay_forwarder_endpoint.is_some()
        || args.relay_forwarder_bind.is_some()
        || args.relay_forwarder_wireguard_endpoint.is_some()
        || args.relay_forwarder_max_sessions != DEFAULT_RELAY_FORWARDER_MAX_SESSIONS
        || args.relay_forwarder_restart_backoff_seconds
            != DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS
        || args.relay_forwarder_crash_window_seconds
            != DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS
        || args.relay_forwarder_max_crashes_per_window
            != DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW
        || args.relay_forwarder_crash_cooldown_seconds
            != DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS;
    if has_relay_forwarder_settings {
        anyhow::bail!(
            "--rootless cannot be combined with relay forwarder settings because docker/compose.rootless.yaml uses the in-memory dry-run WireGuard backend"
        );
    }
    Ok(())
}

fn validate_docker_api_socket_path(path: &Path) -> anyhow::Result<()> {
    if !path.is_absolute() {
        anyhow::bail!("--docker-api-socket must be an absolute Unix socket path");
    }
    let value = path
        .as_os_str()
        .to_str()
        .context("--docker-api-socket must be valid UTF-8")?;
    if value.chars().any(char::is_control) {
        anyhow::bail!("--docker-api-socket must not contain control characters");
    }
    validate_docker_api_socket_path_components(value, "--docker-api-socket")?;
    Ok(())
}

fn validate_docker_api_socket_path_components(value: &str, label: &str) -> anyhow::Result<()> {
    if value
        .split('/')
        .any(|component| component == "." || component == "..")
    {
        anyhow::bail!("{label} must not contain '.' or '..' path components");
    }
    Ok(())
}

fn validate_docker_container_cidrs(flag: &str, cidrs: &[ipnet::IpNet]) -> anyhow::Result<()> {
    let mut seen = BTreeSet::new();
    let mut routes = Vec::new();
    for cidr in cidrs {
        if let Some(reason) = restricted_route_cidr_reason(cidr) {
            anyhow::bail!("{flag} must not include {reason} Docker container CIDR {cidr}");
        }
        let route = cidr.trunc();
        if cidr != &route {
            anyhow::bail!(
                "{flag} must use canonical Docker container CIDR route {route}, not {cidr}"
            );
        }
        if !seen.insert(route) {
            anyhow::bail!("{flag} must not repeat Docker container CIDR route {route}");
        }
        if let Some(overlap) = routes
            .iter()
            .find(|existing| ip_cidrs_overlap(existing, &route))
        {
            anyhow::bail!(
                "{flag} must not include overlapping Docker container CIDR routes {overlap} and {route}"
            );
        }
        routes.push(route);
    }
    Ok(())
}

fn restricted_route_cidr_reason(cidr: &ipnet::IpNet) -> Option<&'static str> {
    if cidr.prefix_len() == 0 {
        return Some("unrestricted");
    }
    match cidr {
        ipnet::IpNet::V4(network) => restricted_docker_ipv4_cidr_reason(network),
        ipnet::IpNet::V6(network) => restricted_docker_ipv6_cidr_reason(network),
    }
}

fn restricted_docker_ipv4_cidr_reason(network: &ipnet::Ipv4Net) -> Option<&'static str> {
    let restricted = [
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(0, 0, 0, 0), 8),
            "unspecified",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 0), 8),
            "loopback",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(169, 254, 0, 0), 16),
            "link-local",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(224, 0, 0, 0), 4),
            "multicast",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(255, 255, 255, 255), 32),
            "broadcast",
        ),
    ];
    restricted
        .iter()
        .find_map(|(restricted, reason)| ipv4_cidrs_overlap(network, restricted).then_some(*reason))
}

fn restricted_docker_ipv6_cidr_reason(network: &ipnet::Ipv6Net) -> Option<&'static str> {
    let restricted = [
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 128),
            "unspecified",
        ),
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::LOCALHOST, 128),
            "loopback",
        ),
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
            "link-local",
        ),
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
            "multicast",
        ),
    ];
    restricted
        .iter()
        .find_map(|(restricted, reason)| ipv6_cidrs_overlap(network, restricted).then_some(*reason))
}

fn ip_cidrs_overlap(left: &ipnet::IpNet, right: &ipnet::IpNet) -> bool {
    match (left, right) {
        (ipnet::IpNet::V4(left), ipnet::IpNet::V4(right)) => ipv4_cidrs_overlap(left, right),
        (ipnet::IpNet::V6(left), ipnet::IpNet::V6(right)) => ipv6_cidrs_overlap(left, right),
        _ => false,
    }
}

fn ipv4_cidrs_overlap(left: &ipnet::Ipv4Net, right: &ipnet::Ipv4Net) -> bool {
    left.contains(&right.network())
        || left.contains(&right.broadcast())
        || right.contains(&left.network())
        || right.contains(&left.broadcast())
}

fn ipv6_cidrs_overlap(left: &ipnet::Ipv6Net, right: &ipnet::Ipv6Net) -> bool {
    left.contains(&right.network())
        || left.contains(&right.broadcast())
        || right.contains(&left.network())
        || right.contains(&left.broadcast())
}

fn validate_docker_userspace_wireguard_args(args: &DockerInstallArgs) -> anyhow::Result<()> {
    validate_bounded_docker_seconds(
        args.userspace_wireguard_ready_timeout_seconds,
        "--userspace-wireguard-ready-timeout-seconds",
        MAX_USERSPACE_WIREGUARD_LIFECYCLE_TIMEOUT_SECONDS,
    )?;
    validate_bounded_docker_seconds(
        args.userspace_wireguard_shutdown_timeout_seconds,
        "--userspace-wireguard-shutdown-timeout-seconds",
        MAX_USERSPACE_WIREGUARD_LIFECYCLE_TIMEOUT_SECONDS,
    )?;
    if !args.userspace_wireguard_args.is_empty() && args.userspace_wireguard_command.is_none() {
        anyhow::bail!("--userspace-wireguard-arg requires --userspace-wireguard-command");
    }
    if let Some(command) = args.userspace_wireguard_command.as_deref() {
        validate_docker_runtime_program_token(command, "--userspace-wireguard-command")?;
    }
    anyhow::ensure!(
        args.userspace_wireguard_args.len() <= MAX_USERSPACE_WIREGUARD_ARGS,
        "--userspace-wireguard-arg may be repeated at most {MAX_USERSPACE_WIREGUARD_ARGS} times"
    );
    for argument in &args.userspace_wireguard_args {
        if argument.is_empty() {
            anyhow::bail!("--userspace-wireguard-arg cannot be empty");
        }
        if argument.len() > MAX_USERSPACE_WIREGUARD_ARG_BYTES {
            anyhow::bail!(
                "--userspace-wireguard-arg exceeds {MAX_USERSPACE_WIREGUARD_ARG_BYTES} bytes"
            );
        }
        if argument.chars().any(char::is_control) {
            anyhow::bail!("--userspace-wireguard-arg must not contain control characters");
        }
        if argument.contains(',') {
            anyhow::bail!(
                "--userspace-wireguard-arg must not contain ',' because Docker Compose passes userspace WireGuard arguments through comma-delimited IPARS_AGENT_USERSPACE_WIREGUARD_ARGS"
            );
        }
    }
    Ok(())
}

fn validate_docker_runtime_program_token(value: &str, label: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("{label} cannot be empty");
    }
    if value.len() > MAX_USERSPACE_WIREGUARD_COMMAND_BYTES {
        anyhow::bail!("{label} exceeds {MAX_USERSPACE_WIREGUARD_COMMAND_BYTES} bytes");
    }
    if value.chars().any(char::is_control) {
        anyhow::bail!("{label} must not contain control characters");
    }
    if value.chars().any(char::is_whitespace) {
        anyhow::bail!("{label} must not contain whitespace");
    }
    if value.contains('/') && !Path::new(value).is_absolute() {
        anyhow::bail!("{label} must be a bare command name or an absolute path");
    }
    validate_docker_runtime_program_name(value, label)?;
    Ok(())
}

fn validate_docker_runtime_program_name(value: &str, label: &str) -> anyhow::Result<()> {
    let program_name = if value.contains('/') {
        let program_path = Path::new(value);
        if value
            .split('/')
            .any(|component| matches!(component, "." | ".."))
        {
            anyhow::bail!("{label} path must not contain '.' or '..' components");
        }
        program_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("{label} path must name an executable"))?
    } else {
        value
    };
    if matches!(program_name, "." | "..") {
        anyhow::bail!("{label} program name must not be '.' or '..'");
    }
    if program_name.starts_with('-') {
        anyhow::bail!("{label} program name must not start with '-'");
    }
    Ok(())
}

fn validate_bounded_docker_seconds(value: u64, label: &str, max: u64) -> anyhow::Result<()> {
    if value == 0 {
        anyhow::bail!("{label} must be greater than zero");
    }
    if value > max {
        anyhow::bail!("{label} must not exceed {max}");
    }
    Ok(())
}

fn validate_agent_http_timeout_settings(
    connect_timeout_seconds: u64,
    request_timeout_seconds: u64,
) -> anyhow::Result<()> {
    validate_bounded_docker_seconds(
        connect_timeout_seconds,
        "--agent-http-connect-timeout-seconds",
        MAX_AGENT_HTTP_TIMEOUT_SECONDS,
    )?;
    validate_bounded_docker_seconds(
        request_timeout_seconds,
        "--agent-http-request-timeout-seconds",
        MAX_AGENT_HTTP_TIMEOUT_SECONDS,
    )?;
    anyhow::ensure!(
        connect_timeout_seconds <= request_timeout_seconds,
        "--agent-http-connect-timeout-seconds must not exceed --agent-http-request-timeout-seconds"
    );
    Ok(())
}

fn validate_agent_direct_path_verification_settings(
    probe_timeout_seconds: u64,
    handshake_max_age_seconds: u64,
    peer_map_poll_interval_seconds: Option<u64>,
) -> anyhow::Result<()> {
    validate_bounded_docker_seconds(
        probe_timeout_seconds,
        "--agent-direct-path-probe-timeout-seconds",
        MAX_AGENT_DIRECT_PATH_VERIFICATION_SECONDS,
    )?;
    validate_bounded_docker_seconds(
        handshake_max_age_seconds,
        "--agent-direct-handshake-max-age-seconds",
        MAX_AGENT_DIRECT_PATH_VERIFICATION_SECONDS,
    )?;
    anyhow::ensure!(
        handshake_max_age_seconds >= DEFAULT_AGENT_SIGNAL_PATH_INTERVAL_SECONDS,
        "--agent-direct-handshake-max-age-seconds must be at least the {DEFAULT_AGENT_SIGNAL_PATH_INTERVAL_SECONDS}-second signal path interval"
    );
    if let Some(peer_map_poll_interval_seconds) = peer_map_poll_interval_seconds {
        let minimum = peer_map_poll_interval_seconds
            .saturating_add(DEFAULT_AGENT_SIGNAL_PATH_INTERVAL_SECONDS.saturating_mul(2));
        anyhow::ensure!(
            probe_timeout_seconds >= minimum,
            "--agent-direct-path-probe-timeout-seconds must be at least the peer-map poll interval plus two {DEFAULT_AGENT_SIGNAL_PATH_INTERVAL_SECONDS}-second signal path intervals ({minimum}s)"
        );
    }
    Ok(())
}

fn validate_agent_peer_probe_settings(
    settings: &AgentPeerProbeInstallArgs,
    linux_peer_map_active: bool,
    wireguard_listen_port: u16,
    default_probe_port: u16,
) -> anyhow::Result<u16> {
    let probe_port = settings.port.unwrap_or(default_probe_port);
    anyhow::ensure!(
        probe_port > 0,
        "--agent-peer-probe-port must be greater than zero"
    );
    validate_bounded_docker_seconds(
        settings.interval_seconds,
        "--agent-peer-probe-interval-seconds",
        MAX_AGENT_PEER_PROBE_INTERVAL_SECONDS,
    )?;
    anyhow::ensure!(
        (1..=MAX_AGENT_PEER_PROBE_SAMPLE_COUNT).contains(&settings.sample_count),
        "--agent-peer-probe-sample-count must be between 1 and {MAX_AGENT_PEER_PROBE_SAMPLE_COUNT}"
    );
    validate_bounded_docker_seconds(
        settings.response_timeout_millis,
        "--agent-peer-probe-response-timeout-millis",
        MAX_AGENT_PEER_PROBE_TIMEOUT_MILLIS,
    )?;
    anyhow::ensure!(
        settings.sample_interval_millis <= MAX_AGENT_PEER_PROBE_SAMPLE_INTERVAL_MILLIS,
        "--agent-peer-probe-sample-interval-millis must not exceed {MAX_AGENT_PEER_PROBE_SAMPLE_INTERVAL_MILLIS}"
    );
    anyhow::ensure!(
        (1..=MAX_AGENT_PEER_PROBE_MAX_CONCURRENCY).contains(&settings.max_concurrency),
        "--agent-peer-probe-max-concurrency must be between 1 and {MAX_AGENT_PEER_PROBE_MAX_CONCURRENCY}"
    );
    anyhow::ensure!(
        (1..=MAX_AGENT_PEER_PROBE_RESPONDER_MAX_REQUESTS_PER_SECOND)
            .contains(&settings.responder_max_requests_per_second),
        "--agent-peer-probe-responder-max-requests-per-second must be between 1 and {MAX_AGENT_PEER_PROBE_RESPONDER_MAX_REQUESTS_PER_SECOND}"
    );
    validate_bounded_docker_seconds(
        settings.observation_max_age_seconds,
        "--agent-peer-probe-observation-max-age-seconds",
        MAX_AGENT_PEER_PROBE_OBSERVATION_MAX_AGE_SECONDS,
    )?;
    if linux_peer_map_active && !settings.disabled {
        anyhow::ensure!(
            probe_port != wireguard_listen_port,
            "--agent-peer-probe-port must differ from the effective WireGuard listen port {wireguard_listen_port}"
        );
        let minimum_observation_age = settings
            .interval_seconds
            .max(DEFAULT_AGENT_SIGNAL_PATH_INTERVAL_SECONDS);
        anyhow::ensure!(
            settings.observation_max_age_seconds >= minimum_observation_age,
            "--agent-peer-probe-observation-max-age-seconds must be at least both --agent-peer-probe-interval-seconds and the {DEFAULT_AGENT_SIGNAL_PATH_INTERVAL_SECONDS}-second signal path interval"
        );
    }
    Ok(probe_port)
}

fn validate_positive_docker_seconds(value: u64, label: &str) -> anyhow::Result<()> {
    if value == 0 {
        anyhow::bail!("{label} must be greater than zero");
    }
    Ok(())
}

fn validate_linux_interface_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("linux interface name cannot be empty");
    }
    if name.len() > 15 {
        anyhow::bail!("linux interface name `{name}` exceeds 15 bytes");
    }
    if matches!(name, "." | "..") {
        anyhow::bail!("linux interface name `{name}` must not be '.' or '..'");
    }
    if name.starts_with('-') {
        anyhow::bail!("linux interface name `{name}` must not start with '-'");
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        anyhow::bail!(
            "linux interface name `{name}` must contain only ASCII letters, digits, '.', '_' or '-'"
        );
    }
    Ok(())
}

fn validate_linux_namespace_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("linux network namespace name cannot be empty");
    }
    if name.len() > 64 {
        anyhow::bail!("linux network namespace name `{name}` exceeds 64 bytes");
    }
    if matches!(name, "." | "..") {
        anyhow::bail!("linux network namespace name `{name}` must not be '.' or '..'");
    }
    if name.starts_with('-') {
        anyhow::bail!("linux network namespace name `{name}` must not start with '-'");
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        anyhow::bail!(
            "linux network namespace name `{name}` must contain only ASCII letters, digits, '.', '_' or '-'"
        );
    }
    Ok(())
}

fn validate_linux_capability_name(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.len() > 64 {
        return Err(format!("{label} `{value}` exceeds 64 bytes"));
    }
    let valid = value
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase());
    if !valid {
        return Err(format!(
            "{label} `{value}` must contain only uppercase ASCII letters, digits, and '_' and start with a letter"
        ));
    }
    Ok(())
}

fn validate_docker_network_filter(filter: &str) -> anyhow::Result<()> {
    if filter.is_empty() {
        anyhow::bail!("Docker network filter cannot be empty");
    }
    if filter.len() > 255 {
        anyhow::bail!("Docker network filter `{filter}` exceeds 255 bytes");
    }
    if !filter
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        anyhow::bail!(
            "Docker network filter `{filter}` must contain only ASCII letters, digits, '.', '_' or '-'"
        );
    }
    Ok(())
}

fn validate_docker_network_filters(filters: &[String]) -> anyhow::Result<()> {
    let mut seen = BTreeSet::new();
    for filter in filters {
        validate_docker_network_filter(filter)?;
        if !seen.insert(filter.as_str()) {
            anyhow::bail!("--docker-network `{filter}` must not be repeated");
        }
    }
    Ok(())
}

fn docker_install_environment(args: &DockerInstallArgs) -> Vec<InstallEnvironment> {
    let apply_docker_routes = !args.rootless;
    let agent_runtime_backend = if args.rootless {
        "dry-run"
    } else {
        args.agent_runtime_backend.as_str()
    };
    let mut environment = vec![
        InstallEnvironment {
            name: "IPARS_AGENT_RUNTIME_BACKEND".to_string(),
            value: agent_runtime_backend.to_string(),
        },
        InstallEnvironment {
            name: "IPARS_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS".to_string(),
            value: args.agent_http_connect_timeout_seconds.to_string(),
        },
        InstallEnvironment {
            name: "IPARS_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS".to_string(),
            value: args.agent_http_request_timeout_seconds.to_string(),
        },
        InstallEnvironment {
            name: "IPARS_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS".to_string(),
            value: args.agent_direct_path_probe_timeout_seconds.to_string(),
        },
        InstallEnvironment {
            name: "IPARS_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS".to_string(),
            value: args.agent_direct_handshake_max_age_seconds.to_string(),
        },
        InstallEnvironment {
            name: "IPARS_AGENT_DISABLE_PEER_PROBE".to_string(),
            value: (args.agent_peer_probe.disabled
                || args.rootless
                || args.agent_runtime_backend != "linux-command")
                .to_string(),
        },
        InstallEnvironment {
            name: "IPARS_AGENT_PEER_PROBE_PORT".to_string(),
            value: args
                .agent_peer_probe
                .port
                .unwrap_or(DEFAULT_DOCKER_AGENT_PEER_PROBE_PORT)
                .to_string(),
        },
        InstallEnvironment {
            name: "IPARS_AGENT_PEER_PROBE_INTERVAL_SECONDS".to_string(),
            value: args.agent_peer_probe.interval_seconds.to_string(),
        },
        InstallEnvironment {
            name: "IPARS_AGENT_PEER_PROBE_SAMPLE_COUNT".to_string(),
            value: args.agent_peer_probe.sample_count.to_string(),
        },
        InstallEnvironment {
            name: "IPARS_AGENT_PEER_PROBE_RESPONSE_TIMEOUT_MILLIS".to_string(),
            value: args.agent_peer_probe.response_timeout_millis.to_string(),
        },
        InstallEnvironment {
            name: "IPARS_AGENT_PEER_PROBE_SAMPLE_INTERVAL_MILLIS".to_string(),
            value: args.agent_peer_probe.sample_interval_millis.to_string(),
        },
        InstallEnvironment {
            name: "IPARS_AGENT_PEER_PROBE_MAX_CONCURRENCY".to_string(),
            value: args.agent_peer_probe.max_concurrency.to_string(),
        },
        InstallEnvironment {
            name: "IPARS_AGENT_PEER_PROBE_RESPONDER_MAX_REQUESTS_PER_SECOND".to_string(),
            value: args
                .agent_peer_probe
                .responder_max_requests_per_second
                .to_string(),
        },
        InstallEnvironment {
            name: "IPARS_AGENT_PEER_PROBE_OBSERVATION_MAX_AGE_SECONDS".to_string(),
            value: args
                .agent_peer_probe
                .observation_max_age_seconds
                .to_string(),
        },
        InstallEnvironment {
            name: "IPARS_SIGNAL_PATH_QUALITY_OBSERVATION_TTL_SECONDS".to_string(),
            value: args
                .agent_peer_probe
                .observation_max_age_seconds
                .to_string(),
        },
        InstallEnvironment {
            name: "IPARS_AGENT_APPLY_DOCKER_ROUTES".to_string(),
            value: apply_docker_routes.to_string(),
        },
        InstallEnvironment {
            name: "IPARS_STUN_ALTERNATE_LISTEN".to_string(),
            value: DEFAULT_STUN_ALTERNATE_LISTEN.to_string(),
        },
    ];
    if apply_docker_routes {
        environment.push(InstallEnvironment {
            name: "IPARS_DOCKER_EXPOSE_HOST_ROUTES".to_string(),
            value: (!args.disable_docker_expose_host_routes).to_string(),
        });
        environment.push(InstallEnvironment {
            name: "IPARS_DOCKER_ROUTE_INTERVAL_SECONDS".to_string(),
            value: args.docker_route_interval_seconds.to_string(),
        });
        environment.push(InstallEnvironment {
            name: "IPARS_AGENT_ROUTE_BACKEND".to_string(),
            value: args.route_backend.clone(),
        });
        if args.docker_discover_networks {
            environment.push(InstallEnvironment {
                name: "IPARS_DOCKER_DISCOVER_NETWORKS".to_string(),
                value: "true".to_string(),
            });
            environment.push(InstallEnvironment {
                name: "IPARS_DOCKER_API_SOCKET".to_string(),
                value: "/run/ipars/docker.sock".to_string(),
            });
        }
        if !args.docker_networks.is_empty() {
            environment.push(InstallEnvironment {
                name: "IPARS_DOCKER_NETWORKS".to_string(),
                value: args.docker_networks.join(","),
            });
        }
        if let Some(socket) = args.docker_api_socket.as_ref() {
            environment.push(InstallEnvironment {
                name: "IPARS_DOCKER_API_SOCKET_HOST".to_string(),
                value: socket.display().to_string(),
            });
        }
        let container_namespace = args
            .docker_container_namespace
            .clone()
            .unwrap_or_else(|| "compose-default".to_string());
        environment.push(InstallEnvironment {
            name: "IPARS_DOCKER_CONTAINER_NAMESPACE".to_string(),
            value: container_namespace,
        });
        environment.push(InstallEnvironment {
            name: "IPARS_DOCKER_HOST_INTERFACE".to_string(),
            value: args.docker_host_interface.clone(),
        });
        if !args.docker_discover_networks {
            let container_cidrs = if args.docker_container_cidrs.is_empty() {
                "172.18.0.0/16".to_string()
            } else {
                args.docker_container_cidrs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            environment.push(InstallEnvironment {
                name: "IPARS_DOCKER_CONTAINER_CIDRS".to_string(),
                value: container_cidrs,
            });
        }
    }
    if args.userspace_wireguard_command.is_some() {
        environment.push(InstallEnvironment {
            name: "IPARS_AGENT_WIREGUARD_BACKEND".to_string(),
            value: "userspace-command".to_string(),
        });
    }
    if let Some(command) = args.userspace_wireguard_command.as_deref() {
        environment.push(InstallEnvironment {
            name: "IPARS_AGENT_USERSPACE_WIREGUARD_COMMAND".to_string(),
            value: command.to_string(),
        });
    }
    if !args.userspace_wireguard_args.is_empty() {
        environment.push(InstallEnvironment {
            name: "IPARS_AGENT_USERSPACE_WIREGUARD_ARGS".to_string(),
            value: args.userspace_wireguard_args.join(","),
        });
    }
    if args.userspace_wireguard_command.is_some() {
        environment.push(InstallEnvironment {
            name: "IPARS_AGENT_USERSPACE_WIREGUARD_READY_TIMEOUT_SECONDS".to_string(),
            value: args.userspace_wireguard_ready_timeout_seconds.to_string(),
        });
        environment.push(InstallEnvironment {
            name: "IPARS_AGENT_USERSPACE_WIREGUARD_SHUTDOWN_TIMEOUT_SECONDS".to_string(),
            value: args
                .userspace_wireguard_shutdown_timeout_seconds
                .to_string(),
        });
    }
    append_docker_relay_advertisement_environment(&mut environment, args);
    if !args.rootless {
        append_docker_relay_forwarder_environment(&mut environment, args);
    }
    environment
}

fn append_docker_relay_advertisement_environment(
    environment: &mut Vec<InstallEnvironment>,
    args: &DockerInstallArgs,
) {
    if let Some(public_endpoint) = args.relay_public_endpoint.as_deref() {
        environment.push(InstallEnvironment {
            name: "IPARS_RELAY_PUBLIC_ENDPOINT".to_string(),
            value: public_endpoint.to_string(),
        });
        environment.push(InstallEnvironment {
            name: "IPARS_AGENT_RELAY_PUBLIC_ENDPOINT".to_string(),
            value: public_endpoint.to_string(),
        });
    }
    if let Some(admission_url) = args.relay_admission_url.as_deref() {
        environment.push(InstallEnvironment {
            name: "IPARS_RELAY_ADMISSION_URL".to_string(),
            value: admission_url.to_string(),
        });
        environment.push(InstallEnvironment {
            name: "IPARS_AGENT_RELAY_ADMISSION_URL".to_string(),
            value: admission_url.to_string(),
        });
    }
    if let Some(status_url) = args.relay_status_url.as_deref() {
        environment.push(InstallEnvironment {
            name: "IPARS_AGENT_RELAY_STATUS_URL".to_string(),
            value: status_url.to_string(),
        });
    }
    environment.push(InstallEnvironment {
        name: "IPARS_RELAY_MAX_SESSIONS".to_string(),
        value: args.relay_max_sessions.to_string(),
    });
    environment.push(InstallEnvironment {
        name: "IPARS_AGENT_RELAY_MAX_SESSIONS".to_string(),
        value: args.relay_max_sessions.to_string(),
    });
    environment.push(InstallEnvironment {
        name: "IPARS_RELAY_MAX_SESSIONS_PER_NODE".to_string(),
        value: args.relay_max_sessions_per_node.to_string(),
    });
    environment.push(InstallEnvironment {
        name: "IPARS_RELAY_MAX_MBPS".to_string(),
        value: args.relay_max_mbps.to_string(),
    });
    environment.push(InstallEnvironment {
        name: "IPARS_AGENT_RELAY_MAX_MBPS".to_string(),
        value: args.relay_max_mbps.to_string(),
    });
    environment.push(InstallEnvironment {
        name: "IPARS_RELAY_SESSION_TTL_SECONDS".to_string(),
        value: args.relay_session_ttl_seconds.to_string(),
    });
    environment.push(InstallEnvironment {
        name: "IPARS_RELAY_ADMISSION_RATE_LIMIT".to_string(),
        value: args.relay_admission_rate_limit.to_string(),
    });
    environment.push(InstallEnvironment {
        name: "IPARS_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS".to_string(),
        value: args.relay_admission_rate_limit_window_seconds.to_string(),
    });
}

fn append_docker_relay_forwarder_environment(
    environment: &mut Vec<InstallEnvironment>,
    args: &DockerInstallArgs,
) {
    if let Some(endpoint) = args.relay_forwarder_endpoint.as_deref() {
        environment.push(InstallEnvironment {
            name: "IPARS_AGENT_RELAY_FORWARDER_ENDPOINT".to_string(),
            value: endpoint.to_string(),
        });
    }
    let Some(bind) = args.relay_forwarder_bind.as_deref() else {
        return;
    };
    environment.push(InstallEnvironment {
        name: "IPARS_AGENT_RELAY_FORWARDER_BIND".to_string(),
        value: bind.to_string(),
    });
    if let Some(wireguard_endpoint) = args.relay_forwarder_wireguard_endpoint.as_deref() {
        environment.push(InstallEnvironment {
            name: "IPARS_AGENT_RELAY_FORWARDER_WIREGUARD_ENDPOINT".to_string(),
            value: wireguard_endpoint.to_string(),
        });
    }
    if let Some(namespace) = args.relay_forwarder_netns.as_deref() {
        environment.push(InstallEnvironment {
            name: "IPARS_AGENT_RELAY_FORWARDER_NETNS".to_string(),
            value: namespace.to_string(),
        });
    }
    environment.push(InstallEnvironment {
        name: "IPARS_AGENT_RELAY_FORWARDER_MAX_SESSIONS".to_string(),
        value: args.relay_forwarder_max_sessions.to_string(),
    });
    environment.push(InstallEnvironment {
        name: "IPARS_AGENT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS".to_string(),
        value: args.relay_forwarder_restart_backoff_seconds.to_string(),
    });
    environment.push(InstallEnvironment {
        name: "IPARS_AGENT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS".to_string(),
        value: args.relay_forwarder_crash_window_seconds.to_string(),
    });
    environment.push(InstallEnvironment {
        name: "IPARS_AGENT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW".to_string(),
        value: args.relay_forwarder_max_crashes_per_window.to_string(),
    });
    environment.push(InstallEnvironment {
        name: "IPARS_AGENT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS".to_string(),
        value: args.relay_forwarder_crash_cooldown_seconds.to_string(),
    });
}

fn k8s_install_plan(args: K8sInstallArgs) -> anyhow::Result<InstallPlan> {
    validate_k8s_install_metadata(&args)?;
    validate_k8s_cluster_endpoints(&args)?;
    validate_k8s_image_pull_secrets(&args)?;
    validate_k8s_relay_admission_bearer_token_secret(&args)?;
    validate_k8s_relay_advertisement(&args)?;
    validate_k8s_relay_forwarder(&args)?;
    validate_k8s_service_account_options(&args)?;
    validate_k8s_agent_pod_options(&args)?;
    validate_k8s_agent_security_context(&args)?;
    validate_k8s_agent_rollout_options(&args)?;
    validate_k8s_agent_pdb_options(&args)?;
    validate_k8s_service_exposure(&args)?;
    validate_k8s_network_policy(&args)?;
    validate_k8s_route_discovery(&args)?;
    validate_k8s_agent_wireguard_endpoint_config(&args)?;
    validate_k8s_agent_peer_probe_config(&args)?;
    let chart = args.chart.display().to_string();
    let mut helm_command = format!(
        "helm upgrade --install {} {} --namespace {} --set agent.joinTokenSecretName={} --set agent.joinTokenSecretKey={} --set agent.apiBearerTokenSecretKey={}",
        args.release,
        shell_word(&chart),
        args.namespace,
        args.join_token_secret,
        args.join_token_key,
        DEFAULT_AGENT_API_BEARER_TOKEN_SECRET_KEY
    );
    append_k8s_chart_metadata_values(&mut helm_command, &args);
    append_k8s_cluster_values(&mut helm_command, &args);
    append_k8s_image_values(&mut helm_command, &args);
    append_k8s_service_account_values(&mut helm_command, &args);
    append_k8s_route_discovery_values(&mut helm_command, &args);
    append_k8s_relay_forwarder_values(&mut helm_command, &args);
    append_k8s_agent_pod_values(&mut helm_command, &args);
    append_k8s_relay_admission_bearer_token_values(&mut helm_command, &args);
    if args.enable_network_policy {
        helm_command.push_str(" --set networkPolicy.enabled=true");
        if args.network_policy_acknowledge_host_network {
            helm_command.push_str(" --set networkPolicy.acknowledgeHostNetwork=true");
        }
        if !args.agent_api_network_policy_cidrs.is_empty() {
            helm_command.push_str(" --set networkPolicy.agentApi.enabled=true");
            append_helm_ipnet_list(
                &mut helm_command,
                "networkPolicy.agentApi.allowedCidrs",
                &args.agent_api_network_policy_cidrs,
            );
        }
        if !args.relay_network_policy_cidrs.is_empty() {
            helm_command.push_str(" --set networkPolicy.relay.enabled=true");
            append_helm_ipnet_list(
                &mut helm_command,
                "networkPolicy.relay.allowedCidrs",
                &args.relay_network_policy_cidrs,
            );
        }
    }
    if let Some(port) = args.agent_api_target_port {
        helm_command.push_str(&format!(" --set agent.apiService.targetPort={port}"));
    }
    if args.expose_agent_api {
        helm_command.push_str(" --set agent.apiService.enabled=true");
        helm_command.push_str(&format!(
            " --set agent.apiService.type={}",
            args.agent_api_service_type
        ));
        if let Some(cluster_ip) = args.agent_api_cluster_ip {
            append_helm_set_string(
                &mut helm_command,
                "agent.apiService.clusterIP",
                &cluster_ip.to_string(),
            );
            if let Some(secondary_cluster_ip) = args.agent_api_secondary_cluster_ip {
                append_helm_set_string(
                    &mut helm_command,
                    "agent.apiService.clusterIPs[0]",
                    &cluster_ip.to_string(),
                );
                append_helm_set_string(
                    &mut helm_command,
                    "agent.apiService.clusterIPs[1]",
                    &secondary_cluster_ip.to_string(),
                );
            }
        }
        if let Some(port) = args.agent_api_port {
            helm_command.push_str(&format!(" --set agent.apiService.port={port}"));
        }
        if let Some(node_port) = args.agent_api_node_port {
            helm_command.push_str(&format!(" --set agent.apiService.nodePort={node_port}"));
        }
        if let Some(app_protocol) = args.agent_api_app_protocol.as_deref() {
            append_helm_set_string(
                &mut helm_command,
                "agent.apiService.appProtocol",
                app_protocol,
            );
        }
        if args.agent_api_publish_not_ready_addresses {
            helm_command.push_str(" --set agent.apiService.publishNotReadyAddresses=true");
        }
        if let Some(load_balancer_class) = args.agent_api_load_balancer_class.as_deref() {
            append_helm_set_string(
                &mut helm_command,
                "agent.apiService.loadBalancerClass",
                load_balancer_class,
            );
        }
        if let Some(load_balancer_ip) = args.agent_api_load_balancer_ip {
            append_helm_set_string(
                &mut helm_command,
                "agent.apiService.loadBalancerIP",
                &load_balancer_ip.to_string(),
            );
        }
        append_helm_ipaddr_list(
            &mut helm_command,
            "agent.apiService.externalIPs",
            &args.agent_api_external_ips,
        );
        if let Some(health_check_node_port) = args.agent_api_health_check_node_port {
            helm_command.push_str(&format!(
                " --set agent.apiService.healthCheckNodePort={health_check_node_port}"
            ));
        }
        if args.agent_api_disable_load_balancer_node_ports {
            helm_command.push_str(" --set agent.apiService.allocateLoadBalancerNodePorts=false");
        }
        if let Some(ip_family_policy) = args.agent_api_ip_family_policy.as_deref() {
            helm_command.push_str(&format!(
                " --set agent.apiService.ipFamilyPolicy={ip_family_policy}"
            ));
        }
        append_helm_string_list(
            &mut helm_command,
            "agent.apiService.ipFamilies",
            &args.agent_api_ip_families,
        );
        if let Some(internal_traffic_policy) = args.agent_api_internal_traffic_policy.as_deref() {
            helm_command.push_str(&format!(
                " --set agent.apiService.internalTrafficPolicy={internal_traffic_policy}"
            ));
        }
        if let Some(traffic_distribution) = args.agent_api_traffic_distribution.as_deref() {
            helm_command.push_str(&format!(
                " --set agent.apiService.trafficDistribution={traffic_distribution}"
            ));
        }
        if let Some(session_affinity) = args.agent_api_session_affinity.as_deref() {
            helm_command.push_str(&format!(
                " --set agent.apiService.sessionAffinity={session_affinity}"
            ));
        }
        if let Some(timeout_seconds) = args.agent_api_session_affinity_timeout_seconds {
            helm_command.push_str(&format!(
                " --set agent.apiService.sessionAffinityTimeoutSeconds={timeout_seconds}"
            ));
        }
        if is_external_kubernetes_service_type(&args.agent_api_service_type)
            || !args.agent_api_external_ips.is_empty()
        {
            helm_command.push_str(" --set agent.apiService.exposureAcknowledged=true");
        }
        if is_external_kubernetes_service_type(&args.agent_api_service_type) {
            helm_command.push_str(&format!(
                " --set agent.apiService.externalTrafficPolicy={}",
                args.agent_api_external_traffic_policy
            ));
            if args.agent_api_external_traffic_policy == "Cluster" {
                helm_command
                    .push_str(" --set agent.apiService.allowClusterExternalTrafficPolicy=true");
            }
        }
        if args.agent_api_service_type == "LoadBalancer"
            && args.agent_api_allow_source_cidrs.is_empty()
            && args.allow_unrestricted_load_balancer
        {
            helm_command.push_str(" --set agent.apiService.allowUnrestrictedLoadBalancer=true");
        }
        append_helm_ipnet_list(
            &mut helm_command,
            "agent.apiService.loadBalancerSourceRanges",
            &args.agent_api_allow_source_cidrs,
        );
        for annotation in &args.agent_api_service_annotations {
            append_helm_set_string(
                &mut helm_command,
                &format!(
                    "agent.apiService.annotations.{}",
                    helm_set_key(&annotation.key)
                ),
                &annotation.value,
            );
        }
    }
    if args.expose_relay {
        let relay_public_endpoint = args
            .relay_public_endpoint
            .as_deref()
            .context("--expose-relay requires --relay-public-endpoint")?;
        let relay_admission_url = args
            .relay_admission_url
            .as_deref()
            .context("--expose-relay requires --relay-admission-url")?;
        helm_command.push_str(
            " --set agent.relayAdvertisement.enabled=true --set agent.relayService.enabled=true",
        );
        helm_command.push_str(&format!(
            " --set agent.relayService.type={}",
            args.relay_service_type
        ));
        if let Some(cluster_ip) = args.relay_cluster_ip {
            append_helm_set_string(
                &mut helm_command,
                "agent.relayService.clusterIP",
                &cluster_ip.to_string(),
            );
            if let Some(secondary_cluster_ip) = args.relay_secondary_cluster_ip {
                append_helm_set_string(
                    &mut helm_command,
                    "agent.relayService.clusterIPs[0]",
                    &cluster_ip.to_string(),
                );
                append_helm_set_string(
                    &mut helm_command,
                    "agent.relayService.clusterIPs[1]",
                    &secondary_cluster_ip.to_string(),
                );
            }
        }
        if let Some(port) = args.relay_udp_port {
            helm_command.push_str(&format!(" --set agent.relayService.udpPort={port}"));
        }
        if let Some(port) = args.relay_udp_target_port {
            helm_command.push_str(&format!(" --set agent.relayService.udpTargetPort={port}"));
        }
        if let Some(port) = args.relay_http_port {
            helm_command.push_str(&format!(" --set agent.relayService.httpPort={port}"));
        }
        if let Some(port) = args.relay_http_target_port {
            helm_command.push_str(&format!(" --set agent.relayService.httpTargetPort={port}"));
        }
        if let Some(node_port) = args.relay_udp_node_port {
            helm_command.push_str(&format!(
                " --set agent.relayService.udpNodePort={node_port}"
            ));
        }
        if let Some(node_port) = args.relay_http_node_port {
            helm_command.push_str(&format!(
                " --set agent.relayService.httpNodePort={node_port}"
            ));
        }
        if let Some(app_protocol) = args.relay_udp_app_protocol.as_deref() {
            append_helm_set_string(
                &mut helm_command,
                "agent.relayService.udpAppProtocol",
                app_protocol,
            );
        }
        if let Some(app_protocol) = args.relay_http_app_protocol.as_deref() {
            append_helm_set_string(
                &mut helm_command,
                "agent.relayService.httpAppProtocol",
                app_protocol,
            );
        }
        if args.relay_publish_not_ready_addresses {
            helm_command.push_str(" --set agent.relayService.publishNotReadyAddresses=true");
        }
        if let Some(load_balancer_class) = args.relay_load_balancer_class.as_deref() {
            append_helm_set_string(
                &mut helm_command,
                "agent.relayService.loadBalancerClass",
                load_balancer_class,
            );
        }
        if let Some(load_balancer_ip) = args.relay_load_balancer_ip {
            append_helm_set_string(
                &mut helm_command,
                "agent.relayService.loadBalancerIP",
                &load_balancer_ip.to_string(),
            );
        }
        append_helm_ipaddr_list(
            &mut helm_command,
            "agent.relayService.externalIPs",
            &args.relay_external_ips,
        );
        if let Some(health_check_node_port) = args.relay_health_check_node_port {
            helm_command.push_str(&format!(
                " --set agent.relayService.healthCheckNodePort={health_check_node_port}"
            ));
        }
        if args.relay_disable_load_balancer_node_ports {
            helm_command.push_str(" --set agent.relayService.allocateLoadBalancerNodePorts=false");
        }
        if let Some(ip_family_policy) = args.relay_ip_family_policy.as_deref() {
            helm_command.push_str(&format!(
                " --set agent.relayService.ipFamilyPolicy={ip_family_policy}"
            ));
        }
        append_helm_string_list(
            &mut helm_command,
            "agent.relayService.ipFamilies",
            &args.relay_ip_families,
        );
        if let Some(internal_traffic_policy) = args.relay_internal_traffic_policy.as_deref() {
            helm_command.push_str(&format!(
                " --set agent.relayService.internalTrafficPolicy={internal_traffic_policy}"
            ));
        }
        if let Some(traffic_distribution) = args.relay_traffic_distribution.as_deref() {
            helm_command.push_str(&format!(
                " --set agent.relayService.trafficDistribution={traffic_distribution}"
            ));
        }
        if let Some(session_affinity) = args.relay_session_affinity.as_deref() {
            helm_command.push_str(&format!(
                " --set agent.relayService.sessionAffinity={session_affinity}"
            ));
        }
        if let Some(timeout_seconds) = args.relay_session_affinity_timeout_seconds {
            helm_command.push_str(&format!(
                " --set agent.relayService.sessionAffinityTimeoutSeconds={timeout_seconds}"
            ));
        }
        if is_external_kubernetes_service_type(&args.relay_service_type)
            || !args.relay_external_ips.is_empty()
        {
            helm_command.push_str(" --set agent.relayService.exposureAcknowledged=true");
        }
        if is_external_kubernetes_service_type(&args.relay_service_type) {
            helm_command.push_str(&format!(
                " --set agent.relayService.externalTrafficPolicy={}",
                args.relay_external_traffic_policy
            ));
            if args.relay_external_traffic_policy == "Cluster" {
                helm_command
                    .push_str(" --set agent.relayService.allowClusterExternalTrafficPolicy=true");
            }
        }
        if args.relay_service_type == "LoadBalancer"
            && args.relay_allow_source_cidrs.is_empty()
            && args.allow_unrestricted_load_balancer
        {
            helm_command.push_str(" --set agent.relayService.allowUnrestrictedLoadBalancer=true");
        }
        append_helm_ipnet_list(
            &mut helm_command,
            "agent.relayService.loadBalancerSourceRanges",
            &args.relay_allow_source_cidrs,
        );
        append_helm_set_string(
            &mut helm_command,
            "agent.relayAdvertisement.publicEndpoint",
            relay_public_endpoint,
        );
        append_helm_set_string(
            &mut helm_command,
            "agent.relayAdvertisement.admissionUrl",
            relay_admission_url,
        );
        if let Some(relay_status_url) = args.relay_status_url.as_deref() {
            append_helm_set_string(
                &mut helm_command,
                "agent.relayAdvertisement.statusUrl",
                relay_status_url,
            );
        }
        helm_command.push_str(&format!(
            " --set agent.relayAdvertisement.maxSessions={}",
            args.relay_max_sessions
        ));
        helm_command.push_str(&format!(
            " --set agent.relayAdvertisement.maxMbps={}",
            args.relay_max_mbps
        ));
        for annotation in &args.relay_service_annotations {
            append_helm_set_string(
                &mut helm_command,
                &format!(
                    "agent.relayService.annotations.{}",
                    helm_set_key(&annotation.key)
                ),
                &annotation.value,
            );
        }
    }

    Ok(InstallPlan {
        platform: "kubernetes-helm".to_string(),
        manifest: chart,
        commands: vec![
            format!(
                "kubectl create namespace {} --dry-run=client -o yaml | kubectl apply -f -",
                args.namespace
            ),
            format!(
                "kubectl -n {} create secret generic {} --from-file={}=./join.token --from-file={}=./agent-api.token --dry-run=client -o yaml | kubectl apply -f -",
                args.namespace,
                args.join_token_secret,
                args.join_token_key,
                DEFAULT_AGENT_API_BEARER_TOKEN_SECRET_KEY
            ),
            helm_command,
        ],
        environment: Vec::new(),
        prerequisites: vec![
            "kubectl access with permission to create namespaces, Secrets, DaemonSets, and RBAC when Kubernetes Service discovery is enabled".to_string(),
            "Helm 3".to_string(),
            "Kernel WireGuard support plus a writable agent state hostPath available on every scheduled node; the chart initContainer creates/chmods the mounted state directory to 0700".to_string(),
            "NET_ADMIN and NET_RAW capability allowance, or equivalent --agent-add-capability overrides, for the DaemonSet agent".to_string(),
            "net.ipv4.ip_forward=1 on Kubernetes route-provider nodes, plus net.ipv6.conf.all.forwarding=1 when routing IPv6 Service/API CIDRs".to_string(),
            "A Kubernetes network plugin that enforces NetworkPolicy when --enable-network-policy is used".to_string(),
        ],
        security: vec![
            "Store the signed join token and a separate 32-512 byte agent API Bearer token in the configured Secret; do not bake either secret into an image".to_string(),
            "Agent API and relay Services are disabled by default and must be explicitly enabled".to_string(),
            "NodePort or LoadBalancer exposure requires --allow-public-service-exposure and sets chart exposure acknowledgement".to_string(),
            "Service externalIPs require --allow-public-service-exposure because they can route traffic to the exposed Service outside the cluster".to_string(),
            "LoadBalancer IP and externalIPs reject unspecified, loopback, link-local, multicast, broadcast, and duplicate fixed external addresses".to_string(),
            "LoadBalancer source ranges and NetworkPolicy CIDR allowlists reject unrestricted all-source CIDRs".to_string(),
            "LoadBalancer exposure requires source CIDR ranges unless --allow-unrestricted-load-balancer is set".to_string(),
            "externalTrafficPolicy=Cluster requires --allow-cluster-external-traffic-policy because source addresses may be hidden by cross-node forwarding".to_string(),
            "NetworkPolicy allowlists are opt-in and require explicit hostNetwork limitation acknowledgement when host networking remains enabled because enforcement is CNI-dependent for host-networked pods".to_string(),
            "Use --disable-agent-service-account-token only when Kubernetes Service API discovery is not required".to_string(),
            "ServiceAccount creation can be disabled only when an equivalent ServiceAccount already exists in the target namespace".to_string(),
            "RBAC is rendered only for Kubernetes Service discovery; --disable-rbac assumes equivalent external RBAC is already managed".to_string(),
            "Agent securityContext capability add/drop, privilege escalation, and privileged mode flags should match the selected runtime backend and cluster Pod Security admission policy".to_string(),
            "Agent state directories are owner-only; pre-existing hostPath directories must allow the chart initContainer to chmod them to 0700".to_string(),
            "Relay advertisement remains ineffective unless the join token allows relay".to_string(),
        ],
        notes: vec![
            "This chart installs a node-underlay VPN agent, not a Kubernetes CNI".to_string(),
            "Use --expose-agent-api and --expose-relay only for nodes that should publish those endpoints".to_string(),
            "Chart nameOverride and fullnameOverride values map directly to Helm chart metadata and must remain Kubernetes DNS labels".to_string(),
            "Cluster control-plane, signal, and STUN endpoint overrides map directly to chart cluster values and are validated before rendering".to_string(),
            "Image repository, tag, pull policy, and pull Secret names map to the DaemonSet container image and imagePullSecrets values for pinned or private registry deployments".to_string(),
            "ServiceAccount creation/name/annotations plus agent service-account token automounting, securityContext capability, read-only-root, and seccomp controls, DNS policy, persistent state hostPath, HTTP liveness/readiness/startup probes, preStop lifecycle sleep, pod labels, annotations, priority class, scheduler/runtime class, node selectors, node affinity, pod affinity/anti-affinity, tolerations, topology spread constraints, termination grace period, resource requests/limits, and DaemonSet rollout settings map directly to chart values".to_string(),
            "Optional agent PodDisruptionBudget settings protect the DaemonSet during voluntary disruptions such as node drains".to_string(),
            "Service type, ClusterIP/clusterIPs, NodePort, LoadBalancer class/IP, externalIPs, LoadBalancer node-port allocation, source range, traffic policy/distribution, and annotation flags map directly to the chart's agent.apiService and agent.relayService values".to_string(),
            "NetworkPolicy CIDR allowlists select the agent pods and restrict ingress to the configured agent API and relay listener ports; source IP visibility still depends on Service traffic policy and the cluster network plugin".to_string(),
            "Relay exposure requires the public relay UDP endpoint and HTTP admission URL that peers should use".to_string(),
        ],
    })
}

fn append_k8s_chart_metadata_values(command: &mut String, args: &K8sInstallArgs) {
    if let Some(name_override) = args.chart_name_override.as_deref() {
        append_helm_set_string(command, "nameOverride", name_override);
    }
    if let Some(fullname_override) = args.chart_fullname_override.as_deref() {
        append_helm_set_string(command, "fullnameOverride", fullname_override);
    }
}

fn append_k8s_cluster_values(command: &mut String, args: &K8sInstallArgs) {
    if let Some(url) = args.cluster_control_plane_url.as_deref() {
        append_helm_set_string(command, "cluster.controlPlaneUrl", url);
    }
    if let Some(url) = args.cluster_signal_url.as_deref() {
        append_helm_set_string(command, "cluster.signalUrl", url);
    }
    if let Some(endpoint) = args.cluster_stun_endpoint.as_deref() {
        append_helm_set_string(command, "cluster.stunEndpoint", endpoint);
    }
}

fn append_k8s_image_values(command: &mut String, args: &K8sInstallArgs) {
    if let Some(repository) = args.image_repository.as_deref() {
        append_helm_set_string(command, "image.repository", repository);
    }
    if let Some(tag) = args.image_tag.as_deref() {
        append_helm_set_string(command, "image.tag", tag);
    }
    if let Some(pull_policy) = args.image_pull_policy.as_deref() {
        append_helm_set_string(command, "image.pullPolicy", pull_policy);
    }
    for (index, secret) in args.image_pull_secrets.iter().enumerate() {
        append_helm_set_string(command, &format!("imagePullSecrets[{index}]"), secret);
    }
}

fn append_k8s_service_account_values(command: &mut String, args: &K8sInstallArgs) {
    if args.disable_service_account_creation {
        command.push_str(" --set serviceAccount.create=false");
    }
    if let Some(name) = args.service_account_name.as_deref() {
        append_helm_set_string(command, "serviceAccount.name", name);
    }
    for annotation in &args.service_account_annotations {
        append_helm_set_string(
            command,
            &format!(
                "serviceAccount.annotations.{}",
                helm_set_key(&annotation.key)
            ),
            &annotation.value,
        );
    }
}

fn append_k8s_relay_admission_bearer_token_values(command: &mut String, args: &K8sInstallArgs) {
    if let Some(secret) = args.relay_admission_bearer_token_secret.as_deref() {
        append_helm_set_string(
            command,
            "agent.relayAdmissionBearerTokenSecret.name",
            secret,
        );
    }
    if let Some(key) = args.relay_admission_bearer_token_key.as_deref() {
        append_helm_set_string(command, "agent.relayAdmissionBearerTokenSecret.key", key);
    }
}

fn append_k8s_route_discovery_values(command: &mut String, args: &K8sInstallArgs) {
    if args.disable_rbac {
        command.push_str(" --set rbac.create=false");
    }
    command.push_str(&format!(
        " --set agent.runtimeBackend={}",
        args.agent_runtime_backend
    ));
    let stun_bind_port = args
        .agent_stun_bind
        .as_deref()
        .and_then(|value| value.parse::<SocketAddr>().ok())
        .map(|address| address.port());
    if let Some(port) = args.agent_wireguard_listen_port.or(stun_bind_port) {
        command.push_str(&format!(" --set agent.wireguardListenPort={port}"));
    }
    if let Some(stun_bind) = args.agent_stun_bind.as_deref() {
        append_helm_set_string(command, "agent.stunBind", stun_bind);
    } else if let Some(port) = args.agent_wireguard_listen_port {
        append_helm_set_string(command, "agent.stunBind", &format!("0.0.0.0:{port}"));
    }
    command.push_str(&format!(" --set agent.routeBackend={}", args.route_backend));
    command.push_str(&format!(
        " --set serviceExposure.discoverApiServer={}",
        args.kubernetes_discover_api_server
    ));
    command.push_str(&format!(
        " --set serviceExposure.routeIntervalSeconds={}",
        args.kubernetes_route_interval_seconds
    ));
    if args.kubernetes_discover_services {
        command.push_str(" --set serviceExposure.discoverServices=true");
    }
    append_helm_ipnet_list(
        command,
        "serviceExposure.apiServerCidrs",
        &args.kubernetes_api_server_cidrs,
    );
    append_helm_ipnet_list(
        command,
        "serviceExposure.serviceCidrs",
        &args.kubernetes_service_cidrs,
    );
    for (index, namespace) in args.kubernetes_namespaces.iter().enumerate() {
        append_helm_set_string(
            command,
            &format!("serviceExposure.namespaces[{index}]"),
            namespace,
        );
    }
    if let Some(selector) = args.kubernetes_service_label_selector.as_deref() {
        append_helm_set_string(command, "serviceExposure.serviceLabelSelector", selector);
    }
    if let Some(route_provider) = args.kubernetes_route_provider.as_deref() {
        command.push_str(" --set agent.routeProvider=false");
        append_helm_set_string(
            command,
            "serviceExposure.routeProviderNodeId",
            route_provider,
        );
    } else {
        command.push_str(" --set agent.routeProvider=true");
    }
}

fn append_k8s_relay_forwarder_values(command: &mut String, args: &K8sInstallArgs) {
    if args.relay_forwarder_endpoint.is_none() && args.relay_forwarder_bind.is_none() {
        return;
    }
    command.push_str(" --set agent.relayForwarder.enabled=true");
    if let Some(endpoint) = args.relay_forwarder_endpoint.as_deref() {
        append_helm_set_string(command, "agent.relayForwarder.endpoint", endpoint);
    }
    if let Some(bind) = args.relay_forwarder_bind.as_deref() {
        append_helm_set_string(command, "agent.relayForwarder.bind", bind);
        if let Some(wireguard_endpoint) = args.relay_forwarder_wireguard_endpoint.as_deref() {
            append_helm_set_string(
                command,
                "agent.relayForwarder.wireguardEndpoint",
                wireguard_endpoint,
            );
        }
        if let Some(namespace) = args.relay_forwarder_netns.as_deref() {
            append_helm_set_string(command, "agent.relayForwarder.netns", namespace);
        }
        command.push_str(&format!(
            " --set agent.relayForwarder.maxSessions={}",
            args.relay_forwarder_max_sessions
        ));
        command.push_str(&format!(
            " --set agent.relayForwarder.restartBackoffSeconds={}",
            args.relay_forwarder_restart_backoff_seconds
        ));
        command.push_str(&format!(
            " --set agent.relayForwarder.crashWindowSeconds={}",
            args.relay_forwarder_crash_window_seconds
        ));
        command.push_str(&format!(
            " --set agent.relayForwarder.maxCrashesPerWindow={}",
            args.relay_forwarder_max_crashes_per_window
        ));
        command.push_str(&format!(
            " --set agent.relayForwarder.crashCooldownSeconds={}",
            args.relay_forwarder_crash_cooldown_seconds
        ));
    }
}

fn append_k8s_probe_values(
    command: &mut String,
    prefix: &str,
    path: Option<&str>,
    initial_delay_seconds: Option<u32>,
    period_seconds: Option<u32>,
    timeout_seconds: Option<u32>,
    failure_threshold: Option<u32>,
) {
    if let Some(path) = path {
        append_helm_set_string(command, &format!("{prefix}.path"), path);
    }
    if let Some(seconds) = initial_delay_seconds {
        command.push_str(&format!(" --set {prefix}.initialDelaySeconds={seconds}"));
    }
    if let Some(seconds) = period_seconds {
        command.push_str(&format!(" --set {prefix}.periodSeconds={seconds}"));
    }
    if let Some(seconds) = timeout_seconds {
        command.push_str(&format!(" --set {prefix}.timeoutSeconds={seconds}"));
    }
    if let Some(threshold) = failure_threshold {
        command.push_str(&format!(" --set {prefix}.failureThreshold={threshold}"));
    }
}

fn append_k8s_agent_pod_values(command: &mut String, args: &K8sInstallArgs) {
    if args.disable_agent_peer_map {
        command.push_str(" --set agent.peerMap.enabled=false");
    }
    command.push_str(&format!(
        " --set agent.peerMap.pollIntervalSeconds={}",
        args.agent_peer_map_poll_interval_seconds
    ));
    command.push_str(&format!(
        " --set agent.http.connectTimeoutSeconds={}",
        args.agent_http_connect_timeout_seconds
    ));
    command.push_str(&format!(
        " --set agent.http.requestTimeoutSeconds={}",
        args.agent_http_request_timeout_seconds
    ));
    command.push_str(&format!(
        " --set agent.directPathVerification.probeTimeoutSeconds={}",
        args.agent_direct_path_probe_timeout_seconds
    ));
    command.push_str(&format!(
        " --set agent.directPathVerification.handshakeMaxAgeSeconds={}",
        args.agent_direct_handshake_max_age_seconds
    ));
    let peer_probe_enabled = !args.agent_peer_probe.disabled
        && !args.disable_agent_peer_map
        && args.agent_runtime_backend == "linux-command";
    command.push_str(&format!(
        " --set agent.peerProbe.enabled={peer_probe_enabled}"
    ));
    command.push_str(&format!(
        " --set agent.peerProbe.port={}",
        args.agent_peer_probe
            .port
            .unwrap_or(DEFAULT_K8S_AGENT_PEER_PROBE_PORT)
    ));
    command.push_str(&format!(
        " --set agent.peerProbe.intervalSeconds={}",
        args.agent_peer_probe.interval_seconds
    ));
    command.push_str(&format!(
        " --set agent.peerProbe.sampleCount={}",
        args.agent_peer_probe.sample_count
    ));
    command.push_str(&format!(
        " --set agent.peerProbe.responseTimeoutMillis={}",
        args.agent_peer_probe.response_timeout_millis
    ));
    command.push_str(&format!(
        " --set agent.peerProbe.sampleIntervalMillis={}",
        args.agent_peer_probe.sample_interval_millis
    ));
    command.push_str(&format!(
        " --set agent.peerProbe.maxConcurrency={}",
        args.agent_peer_probe.max_concurrency
    ));
    command.push_str(&format!(
        " --set agent.peerProbe.responderMaxRequestsPerSecond={}",
        args.agent_peer_probe.responder_max_requests_per_second
    ));
    command.push_str(&format!(
        " --set agent.peerProbe.observationMaxAgeSeconds={}",
        args.agent_peer_probe.observation_max_age_seconds
    ));
    if args.disable_agent_host_network {
        command.push_str(" --set agent.hostNetwork=false");
    }
    if args.disable_agent_service_account_token {
        command.push_str(" --set agent.automountServiceAccountToken=false");
    }
    if let Some(dns_policy) = args.agent_dns_policy.as_deref() {
        command.push_str(&format!(" --set agent.dnsPolicy={dns_policy}"));
    } else if args.disable_agent_host_network {
        command.push_str(" --set agent.dnsPolicy=ClusterFirst");
    }
    if let Some(host_path) = args.agent_state_host_path.as_deref() {
        append_helm_set_string(command, "agent.state.hostPath", host_path);
    }
    if let Some(mount_path) = args.agent_state_mount_path.as_deref() {
        append_helm_set_string(command, "agent.state.mountPath", mount_path);
    }
    if let Some(host_path_type) = args.agent_state_host_path_type.as_deref() {
        command.push_str(&format!(" --set agent.state.hostPathType={host_path_type}"));
    }
    if args.disable_agent_liveness_probe {
        command.push_str(" --set agent.probes.liveness.enabled=false");
    }
    if args.disable_agent_readiness_probe {
        command.push_str(" --set agent.probes.readiness.enabled=false");
    }
    if args.disable_agent_startup_probe {
        command.push_str(" --set agent.probes.startup.enabled=false");
    }
    append_k8s_probe_values(
        command,
        "agent.probes.liveness",
        args.agent_probes.liveness_path.as_deref(),
        args.agent_probes.liveness_initial_delay_seconds,
        args.agent_probes.liveness_period_seconds,
        args.agent_probes.liveness_timeout_seconds,
        args.agent_probes.liveness_failure_threshold,
    );
    append_k8s_probe_values(
        command,
        "agent.probes.readiness",
        args.agent_probes.readiness_path.as_deref(),
        args.agent_probes.readiness_initial_delay_seconds,
        args.agent_probes.readiness_period_seconds,
        args.agent_probes.readiness_timeout_seconds,
        args.agent_probes.readiness_failure_threshold,
    );
    append_k8s_probe_values(
        command,
        "agent.probes.startup",
        args.agent_probes.startup_path.as_deref(),
        args.agent_probes.startup_initial_delay_seconds,
        args.agent_probes.startup_period_seconds,
        args.agent_probes.startup_timeout_seconds,
        args.agent_probes.startup_failure_threshold,
    );
    if args.agent_privileged {
        command.push_str(" --set agent.privileged=true");
    }
    if args.disable_agent_privilege_escalation {
        command.push_str(" --set agent.securityContext.allowPrivilegeEscalation=false");
    }
    if args.agent_read_only_root_filesystem {
        command.push_str(" --set agent.securityContext.readOnlyRootFilesystem=true");
    }
    if let Some(seccomp_type) = args.agent_seccomp_profile.as_deref() {
        append_helm_set_string(
            command,
            "agent.securityContext.seccompProfile.type",
            seccomp_type,
        );
    }
    if let Some(localhost_profile) = args.agent_seccomp_localhost_profile.as_deref() {
        append_helm_set_string(
            command,
            "agent.securityContext.seccompProfile.localhostProfile",
            localhost_profile,
        );
    }
    if let Some(uid) = args.agent_run_as_user {
        command.push_str(&format!(" --set agent.podSecurityContext.runAsUser={uid}"));
    }
    if let Some(gid) = args.agent_run_as_group {
        command.push_str(&format!(" --set agent.podSecurityContext.runAsGroup={gid}"));
    }
    if args.agent_run_as_non_root {
        command.push_str(" --set agent.podSecurityContext.runAsNonRoot=true");
    }
    if let Some(group) = args.agent_fs_group {
        command.push_str(&format!(" --set agent.podSecurityContext.fsGroup={group}"));
    }
    if let Some(policy) = args.agent_fs_group_change_policy.as_deref() {
        append_helm_set_string(
            command,
            "agent.podSecurityContext.fsGroupChangePolicy",
            policy,
        );
    }
    for (index, group) in args.agent_supplemental_groups.iter().enumerate() {
        command.push_str(&format!(
            " --set 'agent.podSecurityContext.supplementalGroups[{index}]={group}'"
        ));
    }
    append_helm_literal_list(
        command,
        "agent.securityContext.capabilities.add",
        &args.agent_add_capabilities,
    );
    append_helm_literal_list(
        command,
        "agent.securityContext.capabilities.drop",
        &args.agent_drop_capabilities,
    );
    for label in &args.agent_pod_labels {
        append_helm_set_string(
            command,
            &format!("agent.podLabels.{}", helm_set_key(&label.key)),
            &label.value,
        );
    }
    for annotation in &args.agent_pod_annotations {
        append_helm_set_string(
            command,
            &format!("agent.podAnnotations.{}", helm_set_key(&annotation.key)),
            &annotation.value,
        );
    }
    if let Some(priority_class) = args.agent_priority_class.as_deref() {
        append_helm_set_string(command, "agent.priorityClassName", priority_class);
    }
    if let Some(scheduler_name) = args.agent_scheduler_name.as_deref() {
        append_helm_set_string(command, "agent.schedulerName", scheduler_name);
    }
    if let Some(runtime_class) = args.agent_runtime_class.as_deref() {
        append_helm_set_string(command, "agent.runtimeClassName", runtime_class);
    }
    for selector in &args.agent_node_selectors {
        append_helm_set_string(
            command,
            &format!("agent.nodeSelector.{}", helm_set_key(&selector.key)),
            &selector.value,
        );
    }
    for (index, expression) in args.agent_node_affinity_required.iter().enumerate() {
        append_k8s_node_affinity_expression_values(
            command,
            &format!("agent.nodeAffinity.required.matchExpressions[{index}]"),
            expression,
        );
    }
    for (index, preference) in args.agent_node_affinity_preferred.iter().enumerate() {
        command.push_str(&format!(
            " --set 'agent.nodeAffinity.preferred[{index}].weight={}'",
            preference.weight
        ));
        append_k8s_node_affinity_expression_values(
            command,
            &format!("agent.nodeAffinity.preferred[{index}].matchExpressions[0]"),
            &preference.expression,
        );
    }
    for (index, term) in args.agent_pod_affinity_required.iter().enumerate() {
        append_k8s_pod_affinity_term_values(
            command,
            &format!("agent.podAffinity.required[{index}]"),
            term,
        );
    }
    for (index, preference) in args.agent_pod_affinity_preferred.iter().enumerate() {
        command.push_str(&format!(
            " --set 'agent.podAffinity.preferred[{index}].weight={}'",
            preference.weight
        ));
        append_k8s_pod_affinity_term_values(
            command,
            &format!("agent.podAffinity.preferred[{index}]"),
            &preference.term,
        );
    }
    for (index, term) in args.agent_pod_anti_affinity_required.iter().enumerate() {
        append_k8s_pod_affinity_term_values(
            command,
            &format!("agent.podAntiAffinity.required[{index}]"),
            term,
        );
    }
    for (index, preference) in args.agent_pod_anti_affinity_preferred.iter().enumerate() {
        command.push_str(&format!(
            " --set 'agent.podAntiAffinity.preferred[{index}].weight={}'",
            preference.weight
        ));
        append_k8s_pod_affinity_term_values(
            command,
            &format!("agent.podAntiAffinity.preferred[{index}]"),
            &preference.term,
        );
    }
    for (index, toleration) in args.agent_tolerations.iter().enumerate() {
        if let Some(key) = toleration.key.as_deref() {
            append_helm_set_string(command, &format!("agent.tolerations[{index}].key"), key);
        }
        if let Some(operator) = toleration.operator.as_deref() {
            append_helm_set_string(
                command,
                &format!("agent.tolerations[{index}].operator"),
                operator,
            );
        }
        if let Some(value) = toleration.value.as_deref() {
            append_helm_set_string(command, &format!("agent.tolerations[{index}].value"), value);
        }
        if let Some(effect) = toleration.effect.as_deref() {
            append_helm_set_string(
                command,
                &format!("agent.tolerations[{index}].effect"),
                effect,
            );
        }
        if let Some(seconds) = toleration.toleration_seconds {
            append_helm_set_string(
                command,
                &format!("agent.tolerations[{index}].tolerationSeconds"),
                &seconds.to_string(),
            );
        }
    }
    for (index, constraint) in args.agent_topology_spreads.iter().enumerate() {
        append_helm_set_string(
            command,
            &format!("agent.topologySpreadConstraints[{index}].topologyKey"),
            &constraint.topology_key,
        );
        command.push_str(&format!(
            " --set 'agent.topologySpreadConstraints[{index}].maxSkew={}'",
            constraint.max_skew
        ));
        append_helm_set_string(
            command,
            &format!("agent.topologySpreadConstraints[{index}].whenUnsatisfiable"),
            &constraint.when_unsatisfiable,
        );
        if let Some(min_domains) = constraint.min_domains {
            command.push_str(&format!(
                " --set 'agent.topologySpreadConstraints[{index}].minDomains={min_domains}'"
            ));
        }
        if let Some(policy) = constraint.node_affinity_policy.as_deref() {
            append_helm_set_string(
                command,
                &format!("agent.topologySpreadConstraints[{index}].nodeAffinityPolicy"),
                policy,
            );
        }
        if let Some(policy) = constraint.node_taints_policy.as_deref() {
            append_helm_set_string(
                command,
                &format!("agent.topologySpreadConstraints[{index}].nodeTaintsPolicy"),
                policy,
            );
        }
    }
    if let Some(seconds) = args.agent_termination_grace_period_seconds {
        command.push_str(&format!(
            " --set agent.terminationGracePeriodSeconds={seconds}"
        ));
    }
    if let Some(seconds) = args.agent_pre_stop_sleep_seconds {
        command.push_str(&format!(
            " --set agent.lifecycle.preStopSleepSeconds={seconds}"
        ));
    }
    if let Some(cpu) = args.agent_resource_request_cpu.as_deref() {
        append_helm_set_string(command, "agent.resources.requests.cpu", cpu);
    }
    if let Some(memory) = args.agent_resource_request_memory.as_deref() {
        append_helm_set_string(command, "agent.resources.requests.memory", memory);
    }
    if let Some(cpu) = args.agent_resource_limit_cpu.as_deref() {
        append_helm_set_string(command, "agent.resources.limits.cpu", cpu);
    }
    if let Some(memory) = args.agent_resource_limit_memory.as_deref() {
        append_helm_set_string(command, "agent.resources.limits.memory", memory);
    }
    let rolling_update_configured =
        args.agent_rollout_max_unavailable.is_some() || args.agent_rollout_max_surge.is_some();
    if let Some(update_strategy) = args
        .agent_update_strategy
        .as_deref()
        .or_else(|| rolling_update_configured.then_some("RollingUpdate"))
    {
        command.push_str(&format!(
            " --set agent.rollout.updateStrategy={update_strategy}"
        ));
    }
    if let Some(max_unavailable) = args.agent_rollout_max_unavailable.as_deref() {
        append_helm_set_string(command, "agent.rollout.maxUnavailable", max_unavailable);
    }
    if let Some(max_surge) = args.agent_rollout_max_surge.as_deref() {
        append_helm_set_string(command, "agent.rollout.maxSurge", max_surge);
    }
    if let Some(min_ready_seconds) = args.agent_min_ready_seconds {
        command.push_str(&format!(
            " --set agent.rollout.minReadySeconds={min_ready_seconds}"
        ));
    }
    if let Some(revision_history_limit) = args.agent_revision_history_limit {
        command.push_str(&format!(
            " --set agent.rollout.revisionHistoryLimit={revision_history_limit}"
        ));
    }
    if args.agent_pdb_min_available.is_some() || args.agent_pdb_max_unavailable.is_some() {
        command.push_str(" --set agent.podDisruptionBudget.enabled=true");
    }
    if let Some(min_available) = args.agent_pdb_min_available.as_deref() {
        append_helm_set_string(
            command,
            "agent.podDisruptionBudget.minAvailable",
            min_available,
        );
    }
    if let Some(max_unavailable) = args.agent_pdb_max_unavailable.as_deref() {
        append_helm_set_string(
            command,
            "agent.podDisruptionBudget.maxUnavailable",
            max_unavailable,
        );
    }
}

fn append_k8s_node_affinity_expression_values(
    command: &mut String,
    prefix: &str,
    expression: &KubernetesNodeAffinityExpressionArg,
) {
    append_helm_set_string(command, &format!("{prefix}.key"), &expression.key);
    append_helm_set_string(command, &format!("{prefix}.operator"), &expression.operator);
    for (index, value) in expression.values.iter().enumerate() {
        append_helm_set_string(command, &format!("{prefix}.values[{index}]"), value);
    }
}

fn append_k8s_pod_affinity_term_values(
    command: &mut String,
    prefix: &str,
    term: &KubernetesPodAffinityTermArg,
) {
    append_helm_set_string(
        command,
        &format!("{prefix}.topologyKey"),
        &term.topology_key,
    );
    for (index, namespace) in term.namespaces.iter().enumerate() {
        append_helm_set_string(command, &format!("{prefix}.namespaces[{index}]"), namespace);
    }
    for (index, expression) in term.match_expressions.iter().enumerate() {
        append_k8s_label_selector_expression_values(
            command,
            &format!("{prefix}.matchExpressions[{index}]"),
            expression,
        );
    }
}

fn append_k8s_label_selector_expression_values(
    command: &mut String,
    prefix: &str,
    expression: &KubernetesLabelSelectorExpressionArg,
) {
    append_helm_set_string(command, &format!("{prefix}.key"), &expression.key);
    append_helm_set_string(command, &format!("{prefix}.operator"), &expression.operator);
    for (index, value) in expression.values.iter().enumerate() {
        append_helm_set_string(command, &format!("{prefix}.values[{index}]"), value);
    }
}

fn validate_k8s_route_discovery(args: &K8sInstallArgs) -> anyhow::Result<()> {
    parse_agent_runtime_backend(&args.agent_runtime_backend).map_err(anyhow::Error::msg)?;
    let mut namespaces = BTreeSet::new();
    for namespace in &args.kubernetes_namespaces {
        validate_kubernetes_namespace(namespace)?;
        if !namespaces.insert(namespace) {
            anyhow::bail!("--kubernetes-namespace `{namespace}` must not be repeated");
        }
    }
    if let Some(selector) = args.kubernetes_service_label_selector.as_deref() {
        validate_kubernetes_label_selector(selector)?;
    }
    if let Some(route_provider) = args.kubernetes_route_provider.as_deref() {
        validate_token_identifier(route_provider, "--kubernetes-route-provider")?;
    }
    if !args.kubernetes_discover_services {
        if !args.kubernetes_namespaces.is_empty() {
            anyhow::bail!("--kubernetes-namespace requires --kubernetes-discover-services");
        }
        if args.kubernetes_service_label_selector.is_some() {
            anyhow::bail!(
                "--kubernetes-service-label-selector requires --kubernetes-discover-services"
            );
        }
    }
    if args.disable_agent_service_account_token && args.kubernetes_discover_services {
        anyhow::bail!(
            "--disable-agent-service-account-token cannot be used with --kubernetes-discover-services"
        );
    }
    if args.kubernetes_route_interval_seconds == 0 {
        anyhow::bail!("--kubernetes-route-interval-seconds must be greater than zero");
    }
    let mut route_cidrs = BTreeSet::new();
    validate_kubernetes_underlay_route_cidrs(
        "--kubernetes-api-server-cidr",
        "Kubernetes API server CIDR",
        &args.kubernetes_api_server_cidrs,
        &mut route_cidrs,
    )?;
    validate_kubernetes_underlay_route_cidrs(
        "--kubernetes-service-cidr",
        "Kubernetes Service CIDR",
        &args.kubernetes_service_cidrs,
        &mut route_cidrs,
    )?;
    Ok(())
}

fn validate_k8s_agent_wireguard_endpoint_config(args: &K8sInstallArgs) -> anyhow::Result<()> {
    if let Some(port) = args.agent_wireguard_listen_port {
        validate_kubernetes_service_port_value(port, "--agent-wireguard-listen-port")?;
    }
    let Some(stun_bind) = args.agent_stun_bind.as_deref() else {
        return Ok(());
    };
    validate_relay_forwarder_bind_arg(stun_bind, "--agent-stun-bind")?;
    let stun_bind = stun_bind.parse::<SocketAddr>().with_context(|| {
        "--agent-stun-bind must be an IPv4 host:port or [IPv6]:port bind socket address"
    })?;
    if let Some(listen_port) = args.agent_wireguard_listen_port {
        anyhow::ensure!(
            listen_port == stun_bind.port(),
            "--agent-stun-bind port must equal --agent-wireguard-listen-port"
        );
    }
    Ok(())
}

fn validate_k8s_agent_peer_probe_config(args: &K8sInstallArgs) -> anyhow::Result<()> {
    let wireguard_listen_port = args
        .agent_wireguard_listen_port
        .or_else(|| {
            args.agent_stun_bind
                .as_deref()
                .and_then(|bind| bind.parse::<SocketAddr>().ok())
                .map(|bind| bind.port())
        })
        .unwrap_or(DEFAULT_K8S_AGENT_WIREGUARD_LISTEN_PORT);
    validate_agent_peer_probe_settings(
        &args.agent_peer_probe,
        !args.disable_agent_peer_map && args.agent_runtime_backend == "linux-command",
        wireguard_listen_port,
        DEFAULT_K8S_AGENT_PEER_PROBE_PORT,
    )?;
    Ok(())
}

fn validate_k8s_install_metadata(args: &K8sInstallArgs) -> anyhow::Result<()> {
    validate_helm_release_name(&args.release).map_err(anyhow::Error::msg)?;
    validate_kubernetes_namespace(&args.namespace)?;
    if let Some(name_override) = args.chart_name_override.as_deref() {
        validate_kubernetes_dns_label_with_max(name_override, "--chart-name-override", 53)
            .map_err(anyhow::Error::msg)?;
    }
    if let Some(fullname_override) = args.chart_fullname_override.as_deref() {
        validate_kubernetes_dns_label_with_max(fullname_override, "--chart-fullname-override", 53)
            .map_err(anyhow::Error::msg)?;
    }
    validate_kubernetes_dns_subdomain(&args.join_token_secret, "join token Secret name")
        .map_err(anyhow::Error::msg)?;
    validate_kubernetes_secret_key(&args.join_token_key).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        args.join_token_key != DEFAULT_AGENT_API_BEARER_TOKEN_SECRET_KEY,
        "join token Secret key must differ from agent API Bearer token Secret key {DEFAULT_AGENT_API_BEARER_TOKEN_SECRET_KEY}"
    );
    Ok(())
}

fn validate_k8s_cluster_endpoints(args: &K8sInstallArgs) -> anyhow::Result<()> {
    if let Some(url) = args.cluster_control_plane_url.as_deref() {
        normalize_kubernetes_http_api_base_url(url, "--cluster-control-plane-url")?;
    }
    if let Some(url) = args.cluster_signal_url.as_deref() {
        normalize_kubernetes_http_api_base_url(url, "--cluster-signal-url")?;
    }
    if let Some(endpoint) = args.cluster_stun_endpoint.as_deref() {
        validate_kubernetes_stun_endpoint(endpoint, "--cluster-stun-endpoint")
            .map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

fn validate_k8s_image_pull_secrets(args: &K8sInstallArgs) -> anyhow::Result<()> {
    if let Some(repository) = args.image_repository.as_deref() {
        validate_container_image_repository(repository, "image repository")
            .map_err(anyhow::Error::msg)?;
    }
    if let Some(tag) = args.image_tag.as_deref() {
        validate_container_image_tag(tag, "image tag").map_err(anyhow::Error::msg)?;
    }
    if let Some(pull_policy) = args.image_pull_policy.as_deref() {
        parse_kubernetes_image_pull_policy(pull_policy).map_err(anyhow::Error::msg)?;
    }
    let mut names = BTreeSet::new();
    for secret in &args.image_pull_secrets {
        validate_kubernetes_dns_subdomain(secret, "image pull Secret name")
            .map_err(anyhow::Error::msg)?;
        if !names.insert(secret) {
            anyhow::bail!("--image-pull-secret `{secret}` must not be repeated");
        }
    }
    Ok(())
}

fn validate_k8s_relay_admission_bearer_token_secret(args: &K8sInstallArgs) -> anyhow::Result<()> {
    match (
        args.relay_admission_bearer_token_secret.as_deref(),
        args.relay_admission_bearer_token_key.as_deref(),
    ) {
        (Some(secret), Some(key)) => {
            validate_kubernetes_dns_subdomain(secret, "relay admission bearer token Secret name")
                .map_err(anyhow::Error::msg)?;
            validate_kubernetes_secret_key_for_label(
                key,
                "relay admission bearer token Secret key",
            )
            .map_err(anyhow::Error::msg)?;
            Ok(())
        }
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!(
                "--relay-admission-bearer-token-secret and --relay-admission-bearer-token-key must be provided together"
            );
        }
    }
}

fn validate_k8s_relay_advertisement(args: &K8sInstallArgs) -> anyhow::Result<()> {
    if !args.expose_relay {
        if args.relay_public_endpoint.is_some() {
            anyhow::bail!("--relay-public-endpoint requires --expose-relay");
        }
        if args.relay_admission_url.is_some() {
            anyhow::bail!("--relay-admission-url requires --expose-relay");
        }
        if args.relay_status_url.is_some() {
            anyhow::bail!("--relay-status-url requires --expose-relay");
        }
        if args.relay_max_sessions != DEFAULT_RELAY_MAX_SESSIONS {
            anyhow::bail!("--relay-max-sessions requires --expose-relay");
        }
        if args.relay_max_mbps != DEFAULT_RELAY_MAX_MBPS {
            anyhow::bail!("--relay-max-mbps requires --expose-relay");
        }
        return Ok(());
    }

    if args.relay_max_sessions == 0 {
        anyhow::bail!("--relay-max-sessions must be greater than zero");
    }
    if args.relay_max_mbps == 0 {
        anyhow::bail!("--relay-max-mbps must be greater than zero");
    }

    let public_endpoint = args
        .relay_public_endpoint
        .as_deref()
        .context("--expose-relay requires --relay-public-endpoint")?;
    validate_k8s_relay_advertised_public_endpoint_arg(public_endpoint, "--relay-public-endpoint")?;

    let admission_url = args
        .relay_admission_url
        .as_deref()
        .context("--expose-relay requires --relay-admission-url")?;
    validate_k8s_relay_advertised_http_url_arg(admission_url, "--relay-admission-url")?;

    if let Some(status_url) = args.relay_status_url.as_deref() {
        validate_k8s_relay_advertised_http_url_arg(status_url, "--relay-status-url")?;
    }

    Ok(())
}

fn validate_k8s_relay_forwarder(args: &K8sInstallArgs) -> anyhow::Result<()> {
    validate_relay_forwarder_install_settings(RelayForwarderInstallSettings::from_k8s(args))
}

fn validate_relay_forwarder_install_settings(
    settings: RelayForwarderInstallSettings<'_>,
) -> anyhow::Result<()> {
    if !settings.active() {
        if settings.wireguard_endpoint.is_some() {
            anyhow::bail!("--relay-forwarder-wireguard-endpoint requires --relay-forwarder-bind");
        }
        if settings.netns.is_some() {
            anyhow::bail!("--relay-forwarder-netns requires --relay-forwarder-bind");
        }
        if settings.max_sessions != DEFAULT_RELAY_FORWARDER_MAX_SESSIONS {
            anyhow::bail!("--relay-forwarder-max-sessions requires --relay-forwarder-bind");
        }
        if settings.restart_backoff_seconds != DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS {
            anyhow::bail!(
                "--relay-forwarder-restart-backoff-seconds requires --relay-forwarder-bind"
            );
        }
        if settings.crash_window_seconds != DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS {
            anyhow::bail!("--relay-forwarder-crash-window-seconds requires --relay-forwarder-bind");
        }
        if settings.max_crashes_per_window != DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW {
            anyhow::bail!(
                "--relay-forwarder-max-crashes-per-window requires --relay-forwarder-bind"
            );
        }
        if settings.crash_cooldown_seconds != DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS {
            anyhow::bail!(
                "--relay-forwarder-crash-cooldown-seconds requires --relay-forwarder-bind"
            );
        }
        return Ok(());
    }

    if let Some(endpoint) = settings.endpoint {
        validate_relay_public_endpoint_arg(endpoint, "--relay-forwarder-endpoint")?;
    }
    if let Some(bind) = settings.bind {
        validate_relay_forwarder_bind_arg(bind, "--relay-forwarder-bind")?;

        let wireguard_endpoint = settings.wireguard_endpoint.context(
            "--relay-forwarder-wireguard-endpoint is required with --relay-forwarder-bind",
        )?;
        validate_relay_public_endpoint_arg(
            wireguard_endpoint,
            "--relay-forwarder-wireguard-endpoint",
        )?;

        if let Some(namespace) = settings.netns {
            validate_linux_namespace_name(namespace)?;
        }
        if settings.max_sessions == 0 {
            anyhow::bail!("--relay-forwarder-max-sessions must be greater than zero");
        }
        if settings.restart_backoff_seconds == 0 {
            anyhow::bail!("--relay-forwarder-restart-backoff-seconds must be greater than zero");
        }
        if settings.crash_window_seconds == 0 {
            anyhow::bail!("--relay-forwarder-crash-window-seconds must be greater than zero");
        }
        if settings.max_crashes_per_window == 0 {
            anyhow::bail!("--relay-forwarder-max-crashes-per-window must be greater than zero");
        }
        if settings.crash_cooldown_seconds == 0 {
            anyhow::bail!("--relay-forwarder-crash-cooldown-seconds must be greater than zero");
        }
    } else {
        if settings.wireguard_endpoint.is_some() {
            anyhow::bail!("--relay-forwarder-wireguard-endpoint requires --relay-forwarder-bind");
        }
        if settings.netns.is_some() {
            anyhow::bail!("--relay-forwarder-netns requires --relay-forwarder-bind");
        }
        if settings.max_sessions != DEFAULT_RELAY_FORWARDER_MAX_SESSIONS {
            anyhow::bail!("--relay-forwarder-max-sessions requires --relay-forwarder-bind");
        }
        if settings.restart_backoff_seconds != DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS {
            anyhow::bail!(
                "--relay-forwarder-restart-backoff-seconds requires --relay-forwarder-bind"
            );
        }
        if settings.crash_window_seconds != DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS {
            anyhow::bail!("--relay-forwarder-crash-window-seconds requires --relay-forwarder-bind");
        }
        if settings.max_crashes_per_window != DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW {
            anyhow::bail!(
                "--relay-forwarder-max-crashes-per-window requires --relay-forwarder-bind"
            );
        }
        if settings.crash_cooldown_seconds != DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS {
            anyhow::bail!(
                "--relay-forwarder-crash-cooldown-seconds requires --relay-forwarder-bind"
            );
        }
    }
    Ok(())
}

fn validate_relay_public_endpoint_arg(value: &str, flag: &str) -> anyhow::Result<()> {
    let endpoint = value.parse::<SocketAddr>().with_context(|| {
        format!("{flag} must be an IPv4 host:port or [IPv6]:port socket address")
    })?;
    if !endpoint_addr_is_usable(endpoint) {
        anyhow::bail!(
            "{flag} must use a usable nonzero, non-unspecified, non-multicast, non-broadcast socket address"
        );
    }
    Ok(())
}

fn validate_k8s_relay_advertised_public_endpoint_arg(
    value: &str,
    flag: &str,
) -> anyhow::Result<()> {
    validate_relay_public_endpoint_arg(value, flag)?;
    let endpoint = value.parse::<SocketAddr>().with_context(|| {
        format!("{flag} must be an IPv4 host:port or [IPv6]:port socket address")
    })?;
    validate_k8s_relay_advertised_ip(endpoint.ip(), flag)
}

fn validate_relay_forwarder_bind_arg(value: &str, flag: &str) -> anyhow::Result<()> {
    let endpoint = value.parse::<SocketAddr>().with_context(|| {
        format!("{flag} must be an IPv4 host:port or [IPv6]:port bind socket address")
    })?;
    if endpoint.port() == 0 {
        anyhow::bail!("{flag} must use a nonzero port");
    }
    if endpoint.ip().is_multicast() {
        anyhow::bail!("{flag} must not use a multicast bind address");
    }
    if endpoint.ip() == IpAddr::V4(Ipv4Addr::BROADCAST) {
        anyhow::bail!("{flag} must not use a broadcast bind address");
    }
    Ok(())
}

fn validate_relay_http_url_arg(value: &str, flag: &str) -> anyhow::Result<()> {
    let url =
        reqwest::Url::parse(value).with_context(|| format!("{flag} must be an absolute URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        anyhow::bail!("{flag} must use http or https");
    }
    if url.host_str().is_none() {
        anyhow::bail!("{flag} must include a host");
    }
    if !http_url_is_usable_endpoint(value) {
        anyhow::bail!(
            "{flag} must use a nonzero port and a usable non-unspecified, non-multicast, non-broadcast endpoint"
        );
    }
    Ok(())
}

fn validate_k8s_relay_advertised_http_url_arg(value: &str, flag: &str) -> anyhow::Result<()> {
    validate_relay_http_url_arg(value, flag)?;
    let url =
        reqwest::Url::parse(value).with_context(|| format!("{flag} must be an absolute URL"))?;
    if let Some(host) = url.host_str() {
        if let Ok(ip) = host.parse::<IpAddr>() {
            validate_k8s_relay_advertised_ip(ip, &format!("{flag} host"))?;
        }
    }
    Ok(())
}

fn validate_k8s_relay_advertised_ip(ip: IpAddr, flag: &str) -> anyhow::Result<()> {
    if let Some(reason) = k8s_relay_advertised_ip_rejection_reason(ip) {
        anyhow::bail!("{flag} must not use {reason} address {ip}");
    }
    Ok(())
}

fn k8s_relay_advertised_ip_rejection_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(ip) if ip.is_loopback() => Some("loopback"),
        IpAddr::V4(ip) if ip.is_link_local() => Some("link-local"),
        IpAddr::V6(ip) if ip.is_loopback() => Some("loopback"),
        IpAddr::V6(ip) if ip.is_unicast_link_local() => Some("link-local"),
        _ => None,
    }
}

fn validate_k8s_service_account_options(args: &K8sInstallArgs) -> anyhow::Result<()> {
    if let Some(name) = args.service_account_name.as_deref() {
        validate_kubernetes_dns_subdomain(name, "ServiceAccount name")
            .map_err(anyhow::Error::msg)?;
    }
    if args.disable_service_account_creation && !args.service_account_annotations.is_empty() {
        anyhow::bail!(
            "--service-account-annotation requires ServiceAccount creation; remove --disable-service-account-creation"
        );
    }
    validate_kubernetes_annotation_args(
        "--service-account-annotation",
        &args.service_account_annotations,
    )?;
    Ok(())
}

fn validate_helm_release_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Helm release name must not be empty".to_string());
    }
    if name.len() > 53 {
        return Err("Helm release name exceeds 53 bytes".to_string());
    }
    let valid_body = name
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    let valid_edges = name
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && name
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if !valid_body || !valid_edges {
        return Err(
            "Helm release name must be a DNS label using lowercase ASCII letters, digits, and '-' with alphanumeric edges"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_kubernetes_secret_key(key: &str) -> Result<(), String> {
    validate_kubernetes_secret_key_for_label(key, "join token Secret key")
}

fn validate_kubernetes_secret_key_for_label(key: &str, label: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if key.len() > 253 {
        return Err(format!("{label} exceeds 253 bytes"));
    }
    let valid = key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid {
        return Err(format!(
            "{label} must contain only ASCII letters, digits, '-', '_' or '.'"
        ));
    }
    Ok(())
}

fn validate_kubernetes_namespace(namespace: &str) -> anyhow::Result<()> {
    if namespace.is_empty() {
        anyhow::bail!("Kubernetes namespace cannot be empty");
    }
    if namespace.len() > 63 {
        anyhow::bail!("Kubernetes namespace `{namespace}` exceeds 63 bytes");
    }
    let valid_body = namespace
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    let valid_edges = namespace
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && namespace
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if !valid_body || !valid_edges {
        anyhow::bail!(
            "Kubernetes namespace `{namespace}` must be a DNS label using lowercase ASCII letters, digits, and '-' with alphanumeric edges"
        );
    }
    Ok(())
}

fn validate_kubernetes_label_selector(selector: &str) -> anyhow::Result<()> {
    if selector.is_empty() {
        anyhow::bail!("Kubernetes service label selector cannot be empty");
    }
    if selector.len() > 1024 {
        anyhow::bail!("Kubernetes service label selector exceeds 1024 bytes");
    }
    if selector.chars().any(char::is_control) {
        anyhow::bail!("Kubernetes service label selector cannot contain control characters");
    }
    Ok(())
}

fn validate_kubernetes_absolute_path(path: &str, label: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if !path.starts_with('/') {
        return Err(format!("{label} `{path}` must be absolute"));
    }
    if path == "/" {
        return Err(format!("{label} must not be '/'"));
    }
    if path.ends_with('/') {
        return Err(format!("{label} `{path}` must not end with '/'"));
    }
    if path.len() > 4096 {
        return Err(format!("{label} `{path}` exceeds 4096 bytes"));
    }
    if path.split('/').any(|segment| segment == "..") {
        return Err(format!("{label} `{path}` must not contain '..' segments"));
    }
    if !path.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'/' | b'.' | b'_' | b'-' | b'@' | b'%' | b'+' | b'=' | b':' | b','
            )
    }) {
        return Err(format!(
            "{label} `{path}` must contain only path-safe ASCII characters"
        ));
    }
    Ok(())
}

fn validate_kubernetes_agent_state_host_path(path: &str) -> Result<(), String> {
    validate_kubernetes_absolute_path(path, "agent state host path")?;
    validate_kubernetes_path_not_sensitive(
        path,
        "agent state host path",
        &[
            "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/proc", "/root", "/run",
            "/sbin", "/sys", "/tmp", "/usr", "/var/run", "/var/tmp",
        ],
    )
}

fn validate_kubernetes_agent_state_mount_path(path: &str) -> Result<(), String> {
    validate_kubernetes_absolute_path(path, "agent state mount path")?;
    validate_kubernetes_path_not_sensitive(
        path,
        "agent state mount path",
        &[
            "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/proc", "/root", "/sbin",
            "/sys", "/usr",
        ],
    )
}

fn validate_kubernetes_path_not_sensitive(
    path: &str,
    label: &str,
    disallowed_prefixes: &[&str],
) -> Result<(), String> {
    if disallowed_prefixes
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
    {
        return Err(format!(
            "{label} `{path}` must not be a sensitive system path; choose a dedicated IPARS state directory such as /var/lib/ipars or /opt/ipars/state"
        ));
    }
    Ok(())
}

fn validate_kubernetes_seccomp_localhost_profile(profile: &str) -> Result<(), String> {
    if profile.is_empty() {
        return Err("seccomp localhost profile must not be empty".to_string());
    }
    if profile.starts_with('/') {
        return Err(
            "seccomp localhost profile must be relative to the kubelet seccomp root".to_string(),
        );
    }
    if profile.ends_with('/') {
        return Err("seccomp localhost profile must not end with '/'".to_string());
    }
    if profile.len() > 255 {
        return Err("seccomp localhost profile exceeds 255 bytes".to_string());
    }
    if profile
        .split('/')
        .any(|segment| segment.is_empty() || segment == "..")
    {
        return Err(
            "seccomp localhost profile must not contain empty or '..' path segments".to_string(),
        );
    }
    if !profile.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'/' | b'.' | b'_' | b'-' | b'@' | b'%' | b'+' | b'=' | b':' | b','
            )
    }) {
        return Err(
            "seccomp localhost profile must contain only path-safe ASCII characters".to_string(),
        );
    }
    Ok(())
}

fn validate_kubernetes_service_ip_families(
    flag_prefix: &str,
    policy: Option<&str>,
    families: &[String],
) -> anyhow::Result<()> {
    if let Some(policy) = policy {
        parse_kubernetes_ip_family_policy(policy).map_err(anyhow::Error::msg)?;
    }
    if families.len() > 2 {
        anyhow::bail!("{flag_prefix} accepts at most two --{flag_prefix}-ip-family values");
    }
    for family in families {
        parse_kubernetes_ip_family(family).map_err(anyhow::Error::msg)?;
    }

    let has_ipv4 = families.iter().any(|family| family == "IPv4");
    let has_ipv6 = families.iter().any(|family| family == "IPv6");
    if families.len() == 2 && !(has_ipv4 && has_ipv6) {
        anyhow::bail!("{flag_prefix} ipFamilies cannot repeat the same family");
    }
    if policy == Some("SingleStack") && families.len() > 1 {
        anyhow::bail!("{flag_prefix} ipFamilyPolicy=SingleStack cannot use both IPv4 and IPv6");
    }
    if policy == Some("RequireDualStack") && families.len() != 2 {
        anyhow::bail!(
            "{flag_prefix} ipFamilyPolicy=RequireDualStack requires both IPv4 and IPv6 families"
        );
    }
    if families.len() == 2 && !matches!(policy, Some("PreferDualStack" | "RequireDualStack")) {
        anyhow::bail!(
            "{flag_prefix} with both IPv4 and IPv6 requires ipFamilyPolicy=PreferDualStack or RequireDualStack"
        );
    }
    Ok(())
}

fn kubernetes_ip_family(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "IPv4",
        IpAddr::V6(_) => "IPv6",
    }
}

fn kubernetes_service_ip_rejection_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(ip) if ip.is_unspecified() => Some("unspecified"),
        IpAddr::V4(ip) if ip.is_loopback() => Some("loopback"),
        IpAddr::V4(ip) if ip.is_link_local() => Some("link-local"),
        IpAddr::V4(ip) if ip.is_multicast() => Some("multicast"),
        IpAddr::V4(ip) if ip == Ipv4Addr::BROADCAST => Some("broadcast"),
        IpAddr::V6(ip) if ip.is_unspecified() => Some("unspecified"),
        IpAddr::V6(ip) if ip.is_loopback() => Some("loopback"),
        IpAddr::V6(ip) if ip.is_unicast_link_local() => Some("link-local"),
        IpAddr::V6(ip) if ip.is_multicast() => Some("multicast"),
        _ => None,
    }
}

fn validate_kubernetes_service_ip(flag: &str, ip: IpAddr) -> anyhow::Result<()> {
    if let Some(reason) = kubernetes_service_ip_rejection_reason(ip) {
        anyhow::bail!("{flag} must not use {reason} address {ip}");
    }
    Ok(())
}

fn validate_kubernetes_external_service_ip(flag: &str, ip: IpAddr) -> anyhow::Result<()> {
    validate_kubernetes_service_ip(flag, ip)
}

fn validate_kubernetes_external_service_ips(flag: &str, ips: &[IpAddr]) -> anyhow::Result<()> {
    let mut seen = BTreeSet::new();
    for &ip in ips {
        validate_kubernetes_external_service_ip(flag, ip)?;
        if !seen.insert(ip) {
            anyhow::bail!("{flag} must not repeat external Service IP address {ip}");
        }
    }
    Ok(())
}

fn validate_kubernetes_service_ip_family_member(
    flag: &str,
    ip: IpAddr,
    service_flag_prefix: &str,
    families: &[String],
) -> anyhow::Result<()> {
    if families.is_empty() {
        return Ok(());
    }
    let ip_family = kubernetes_ip_family(ip);
    if !families.iter().any(|family| family == ip_family) {
        anyhow::bail!(
            "{flag} address {ip} family {ip_family} must be included in --{service_flag_prefix}-ip-family values"
        );
    }
    Ok(())
}

fn validate_kubernetes_external_service_ip_families(
    service_flag_prefix: &str,
    load_balancer_flag: &str,
    load_balancer_ip: Option<IpAddr>,
    external_ip_flag: &str,
    external_ips: &[IpAddr],
    families: &[String],
) -> anyhow::Result<()> {
    if let Some(ip) = load_balancer_ip {
        validate_kubernetes_service_ip_family_member(
            load_balancer_flag,
            ip,
            service_flag_prefix,
            families,
        )?;
    }
    for &ip in external_ips {
        validate_kubernetes_service_ip_family_member(
            external_ip_flag,
            ip,
            service_flag_prefix,
            families,
        )?;
    }
    Ok(())
}

fn record_kubernetes_external_service_ip(
    assigned: &mut BTreeMap<IpAddr, &'static str>,
    flag: &'static str,
    ip: IpAddr,
) -> anyhow::Result<()> {
    if let Some(existing_flag) = assigned.get(&ip) {
        anyhow::bail!(
            "{flag} must not reuse external Service IP address {ip} already assigned by {existing_flag}"
        );
    }
    assigned.insert(ip, flag);
    Ok(())
}

fn validate_kubernetes_external_service_ip_disjoint(
    agent_api_load_balancer_ip: Option<IpAddr>,
    agent_api_external_ips: &[IpAddr],
    relay_load_balancer_ip: Option<IpAddr>,
    relay_external_ips: &[IpAddr],
) -> anyhow::Result<()> {
    let mut assigned = BTreeMap::new();
    if let Some(ip) = agent_api_load_balancer_ip {
        record_kubernetes_external_service_ip(&mut assigned, "--agent-api-load-balancer-ip", ip)?;
    }
    for &ip in agent_api_external_ips {
        record_kubernetes_external_service_ip(&mut assigned, "--agent-api-external-ip", ip)?;
    }
    if let Some(ip) = relay_load_balancer_ip {
        record_kubernetes_external_service_ip(&mut assigned, "--relay-load-balancer-ip", ip)?;
    }
    for &ip in relay_external_ips {
        record_kubernetes_external_service_ip(&mut assigned, "--relay-external-ip", ip)?;
    }
    Ok(())
}

fn validate_kubernetes_restricted_cidrs(
    flag: &str,
    cidrs: &[ipnet::IpNet],
    guidance: &str,
    duplicate_label: &str,
) -> anyhow::Result<()> {
    let mut seen = BTreeSet::new();
    for cidr in cidrs {
        if let Some(reason) = restricted_route_cidr_reason(cidr) {
            if reason == "unrestricted" {
                anyhow::bail!("{flag} must not include unrestricted CIDR {cidr}; {guidance}");
            }
            anyhow::bail!("{flag} must not include {reason} CIDR {cidr}; {guidance}");
        }
        let canonical = cidr.trunc();
        if cidr != &canonical {
            anyhow::bail!("{flag} must use canonical CIDR {canonical}, not {cidr}");
        }
        if !seen.insert(canonical) {
            anyhow::bail!("{flag} must not repeat {duplicate_label} {canonical}");
        }
    }
    Ok(())
}

fn ip_cidr_contains(outer: &ipnet::IpNet, inner: &ipnet::IpNet) -> bool {
    match (outer, inner) {
        (ipnet::IpNet::V4(outer), ipnet::IpNet::V4(inner)) => {
            outer.prefix_len() <= inner.prefix_len()
                && outer.contains(&inner.network())
                && outer.contains(&inner.broadcast())
        }
        (ipnet::IpNet::V6(outer), ipnet::IpNet::V6(inner)) => {
            outer.prefix_len() <= inner.prefix_len()
                && outer.contains(&inner.network())
                && outer.contains(&inner.broadcast())
        }
        _ => false,
    }
}

fn validate_kubernetes_network_policy_within_source_ranges(
    network_policy_flag: &str,
    network_policy_cidrs: &[ipnet::IpNet],
    source_range_flag: &str,
    source_ranges: &[ipnet::IpNet],
) -> anyhow::Result<()> {
    if network_policy_cidrs.is_empty() || source_ranges.is_empty() {
        return Ok(());
    }
    for cidr in network_policy_cidrs {
        if !source_ranges
            .iter()
            .any(|source_range| ip_cidr_contains(source_range, cidr))
        {
            anyhow::bail!(
                "{network_policy_flag} {cidr} must be contained by one of {source_range_flag} values because NetworkPolicy must not allow sources broader than the LoadBalancer source ranges"
            );
        }
    }
    Ok(())
}

fn validate_kubernetes_underlay_route_cidrs(
    flag: &str,
    label: &str,
    cidrs: &[ipnet::IpNet],
    seen: &mut BTreeSet<ipnet::IpNet>,
) -> anyhow::Result<()> {
    for cidr in cidrs {
        if let Some(reason) = restricted_route_cidr_reason(cidr) {
            anyhow::bail!("{flag} must not include {reason} {label} {cidr}");
        }
        let route = cidr.trunc();
        if cidr != &route {
            anyhow::bail!("{flag} must use canonical {label} route {route}, not {cidr}");
        }
        if !seen.insert(route) {
            anyhow::bail!("{flag} must not repeat Kubernetes underlay route CIDR {route}");
        }
    }
    Ok(())
}

fn validate_kubernetes_service_cluster_ips(
    flag_prefix: &str,
    cluster_ip: Option<IpAddr>,
    secondary_cluster_ip: Option<IpAddr>,
    policy: Option<&str>,
    families: &[String],
) -> anyhow::Result<()> {
    let Some(cluster_ip) = cluster_ip else {
        if secondary_cluster_ip.is_some() {
            anyhow::bail!(
                "--{flag_prefix}-secondary-cluster-ip requires --{flag_prefix}-cluster-ip"
            );
        }
        return Ok(());
    };
    validate_kubernetes_service_ip(&format!("--{flag_prefix}-cluster-ip"), cluster_ip)?;
    let cluster_ip_family = kubernetes_ip_family(cluster_ip);
    if let Some(primary_family) = families.first() {
        if primary_family != cluster_ip_family {
            anyhow::bail!(
                "{flag_prefix} clusterIP family {cluster_ip_family} must match the first --{flag_prefix}-ip-family value {primary_family}"
            );
        }
    }
    if let Some(secondary_cluster_ip) = secondary_cluster_ip {
        validate_kubernetes_service_ip(
            &format!("--{flag_prefix}-secondary-cluster-ip"),
            secondary_cluster_ip,
        )?;
        let secondary_cluster_ip_family = kubernetes_ip_family(secondary_cluster_ip);
        if secondary_cluster_ip_family == cluster_ip_family {
            anyhow::bail!(
                "{flag_prefix} secondary clusterIP family {secondary_cluster_ip_family} must differ from primary clusterIP family {cluster_ip_family}"
            );
        }
        if !matches!(policy, Some("PreferDualStack" | "RequireDualStack")) {
            anyhow::bail!(
                "--{flag_prefix}-secondary-cluster-ip requires --{flag_prefix}-ip-family-policy PreferDualStack or RequireDualStack"
            );
        }
        if families.len() != 2 {
            anyhow::bail!(
                "--{flag_prefix}-secondary-cluster-ip requires exactly two --{flag_prefix}-ip-family values"
            );
        }
        if let Some(secondary_family) = families.get(1) {
            if secondary_family != secondary_cluster_ip_family {
                anyhow::bail!(
                    "{flag_prefix} secondary clusterIP family {secondary_cluster_ip_family} must match the second --{flag_prefix}-ip-family value {secondary_family}"
                );
            }
        }
    }
    Ok(())
}

fn validate_kubernetes_service_cluster_ip_disjoint(
    left_flag_prefix: &str,
    left_cluster_ip: Option<IpAddr>,
    left_secondary_cluster_ip: Option<IpAddr>,
    right_flag_prefix: &str,
    right_cluster_ip: Option<IpAddr>,
    right_secondary_cluster_ip: Option<IpAddr>,
) -> anyhow::Result<()> {
    let mut left_ips = BTreeMap::new();
    if let Some(ip) = left_cluster_ip {
        left_ips.insert(ip, format!("--{left_flag_prefix}-cluster-ip"));
    }
    if let Some(ip) = left_secondary_cluster_ip {
        left_ips.insert(ip, format!("--{left_flag_prefix}-secondary-cluster-ip"));
    }

    for (ip, right_flag) in [
        (
            right_cluster_ip,
            format!("--{right_flag_prefix}-cluster-ip"),
        ),
        (
            right_secondary_cluster_ip,
            format!("--{right_flag_prefix}-secondary-cluster-ip"),
        ),
    ]
    .into_iter()
    .filter_map(|(ip, flag)| ip.map(|ip| (ip, flag)))
    {
        if let Some(left_flag) = left_ips.get(&ip) {
            anyhow::bail!(
                "{right_flag} must not reuse Kubernetes Service clusterIP {ip} already assigned by {left_flag}"
            );
        }
    }

    Ok(())
}

fn validate_kubernetes_session_affinity_options(
    flag_prefix: &str,
    affinity: Option<&str>,
    timeout_seconds: Option<u32>,
) -> anyhow::Result<()> {
    if let Some(affinity) = affinity {
        parse_kubernetes_session_affinity(affinity).map_err(anyhow::Error::msg)?;
    }
    if let Some(timeout_seconds) = timeout_seconds {
        if !(KUBERNETES_SESSION_AFFINITY_TIMEOUT_SECONDS_MIN
            ..=KUBERNETES_SESSION_AFFINITY_TIMEOUT_SECONDS_MAX)
            .contains(&timeout_seconds)
        {
            anyhow::bail!(
                "{flag_prefix} session affinity timeout must be between {KUBERNETES_SESSION_AFFINITY_TIMEOUT_SECONDS_MIN} and {KUBERNETES_SESSION_AFFINITY_TIMEOUT_SECONDS_MAX}"
            );
        }
        if affinity != Some("ClientIP") {
            anyhow::bail!(
                "--{flag_prefix}-session-affinity-timeout-seconds requires --{flag_prefix}-session-affinity ClientIP"
            );
        }
    }
    Ok(())
}

const DEFAULT_AGENT_CAPABILITIES: [&str; 2] = ["NET_ADMIN", "NET_RAW"];

fn validate_k8s_agent_security_context(args: &K8sInstallArgs) -> anyhow::Result<()> {
    let mut added = BTreeSet::new();
    for capability in &args.agent_add_capabilities {
        validate_linux_capability_name(capability, "agent add capability")
            .map_err(anyhow::Error::msg)?;
        if !added.insert(capability.as_str()) {
            anyhow::bail!("--agent-add-capability `{capability}` must not be repeated");
        }
    }

    let effective_added: BTreeSet<&str> = if args.agent_add_capabilities.is_empty() {
        DEFAULT_AGENT_CAPABILITIES.into_iter().collect()
    } else {
        added.iter().copied().collect()
    };

    let mut dropped = BTreeSet::new();
    for capability in &args.agent_drop_capabilities {
        validate_linux_capability_name(capability, "agent drop capability")
            .map_err(anyhow::Error::msg)?;
        if !dropped.insert(capability.as_str()) {
            anyhow::bail!("--agent-drop-capability `{capability}` must not be repeated");
        }
        if (capability == "ALL" && effective_added.contains("ALL"))
            || (capability != "ALL" && effective_added.contains(capability.as_str()))
        {
            anyhow::bail!(
                "--agent-drop-capability `{capability}` conflicts with the agent capability add list"
            );
        }
    }

    if args.disable_agent_privilege_escalation {
        if args.agent_privileged {
            anyhow::bail!(
                "--disable-agent-privilege-escalation cannot be used with --agent-privileged"
            );
        }
        if effective_added.contains("SYS_ADMIN") || effective_added.contains("CAP_SYS_ADMIN") {
            anyhow::bail!(
                "--disable-agent-privilege-escalation cannot be used when SYS_ADMIN is added"
            );
        }
    }
    if args.relay_forwarder_netns.is_some()
        && !args.agent_privileged
        && !(effective_added.contains("ALL")
            || effective_added.contains("SYS_ADMIN")
            || effective_added.contains("CAP_SYS_ADMIN"))
    {
        anyhow::bail!(
            "--relay-forwarder-netns requires --agent-privileged or --agent-add-capability SYS_ADMIN"
        );
    }

    if let Some(seccomp_profile) = args.agent_seccomp_profile.as_deref() {
        parse_kubernetes_seccomp_profile_type(seccomp_profile).map_err(anyhow::Error::msg)?;
    }
    if let Some(localhost_profile) = args.agent_seccomp_localhost_profile.as_deref() {
        validate_kubernetes_seccomp_localhost_profile(localhost_profile)
            .map_err(anyhow::Error::msg)?;
    }
    match (
        args.agent_seccomp_profile.as_deref(),
        args.agent_seccomp_localhost_profile.as_deref(),
    ) {
        (Some("Localhost"), None) => {
            anyhow::bail!(
                "--agent-seccomp-profile Localhost requires --agent-seccomp-localhost-profile"
            );
        }
        (Some("Localhost"), Some(_)) | (_, None) => {}
        (_, Some(_)) => {
            anyhow::bail!(
                "--agent-seccomp-localhost-profile requires --agent-seccomp-profile Localhost"
            );
        }
    }

    for (flag, value) in [
        ("--agent-run-as-user", args.agent_run_as_user),
        ("--agent-run-as-group", args.agent_run_as_group),
        ("--agent-fs-group", args.agent_fs_group),
    ] {
        if let Some(value) = value {
            if value > KUBERNETES_INT64_MAX {
                anyhow::bail!("{flag} must be a non-negative Kubernetes int64");
            }
        }
    }
    if args.agent_run_as_non_root && args.agent_run_as_user == Some(0) {
        anyhow::bail!("--agent-run-as-non-root cannot be used with --agent-run-as-user 0");
    }
    if let Some(policy) = args.agent_fs_group_change_policy.as_deref() {
        parse_kubernetes_fs_group_change_policy(policy).map_err(anyhow::Error::msg)?;
        if args.agent_fs_group.is_none() {
            anyhow::bail!("--agent-fs-group-change-policy requires --agent-fs-group");
        }
    }
    let mut supplemental_groups = BTreeSet::new();
    for group in &args.agent_supplemental_groups {
        if *group > KUBERNETES_INT64_MAX {
            anyhow::bail!("--agent-supplemental-group must be a non-negative Kubernetes int64");
        }
        if !supplemental_groups.insert(*group) {
            anyhow::bail!("--agent-supplemental-group `{group}` must not be repeated");
        }
    }

    Ok(())
}

fn validate_k8s_agent_pod_options(args: &K8sInstallArgs) -> anyhow::Result<()> {
    if args.agent_peer_map_poll_interval_seconds == 0 {
        anyhow::bail!("--agent-peer-map-poll-interval-seconds must be greater than zero");
    }
    validate_agent_http_timeout_settings(
        args.agent_http_connect_timeout_seconds,
        args.agent_http_request_timeout_seconds,
    )?;
    validate_agent_direct_path_verification_settings(
        args.agent_direct_path_probe_timeout_seconds,
        args.agent_direct_handshake_max_age_seconds,
        (!args.disable_agent_peer_map && args.agent_runtime_backend == "linux-command")
            .then_some(args.agent_peer_map_poll_interval_seconds),
    )?;
    for label in &args.agent_pod_labels {
        validate_kubernetes_label_key(&label.key).map_err(anyhow::Error::msg)?;
        validate_kubernetes_label_value(&label.value).map_err(anyhow::Error::msg)?;
    }
    validate_kubernetes_annotation_args("--agent-pod-annotation", &args.agent_pod_annotations)?;
    if let Some(priority_class) = args.agent_priority_class.as_deref() {
        validate_kubernetes_dns_subdomain(priority_class, "agent priority class")
            .map_err(anyhow::Error::msg)?;
    }
    if let Some(scheduler_name) = args.agent_scheduler_name.as_deref() {
        validate_kubernetes_dns_subdomain(scheduler_name, "agent scheduler name")
            .map_err(anyhow::Error::msg)?;
    }
    if let Some(runtime_class) = args.agent_runtime_class.as_deref() {
        validate_kubernetes_dns_subdomain(runtime_class, "agent runtime class")
            .map_err(anyhow::Error::msg)?;
    }
    for selector in &args.agent_node_selectors {
        validate_kubernetes_label_key(&selector.key).map_err(anyhow::Error::msg)?;
        validate_kubernetes_label_value(&selector.value).map_err(anyhow::Error::msg)?;
    }
    for expression in &args.agent_node_affinity_required {
        validate_kubernetes_node_affinity_expression_arg(expression).map_err(anyhow::Error::msg)?;
    }
    for preference in &args.agent_node_affinity_preferred {
        validate_kubernetes_preferred_node_affinity_arg(preference).map_err(anyhow::Error::msg)?;
    }
    for term in &args.agent_pod_affinity_required {
        validate_kubernetes_pod_affinity_term_arg(term).map_err(anyhow::Error::msg)?;
    }
    for preference in &args.agent_pod_affinity_preferred {
        validate_kubernetes_preferred_pod_affinity_arg(preference).map_err(anyhow::Error::msg)?;
    }
    for term in &args.agent_pod_anti_affinity_required {
        validate_kubernetes_pod_affinity_term_arg(term).map_err(anyhow::Error::msg)?;
    }
    for preference in &args.agent_pod_anti_affinity_preferred {
        validate_kubernetes_preferred_pod_affinity_arg(preference).map_err(anyhow::Error::msg)?;
    }
    for toleration in &args.agent_tolerations {
        validate_kubernetes_toleration_arg(toleration).map_err(anyhow::Error::msg)?;
    }
    let mut topology_spread_keys = std::collections::BTreeSet::new();
    for constraint in &args.agent_topology_spreads {
        validate_kubernetes_topology_spread_arg(constraint).map_err(anyhow::Error::msg)?;
        if !topology_spread_keys.insert(constraint.topology_key.as_str()) {
            anyhow::bail!(
                "--agent-topology-spread must not repeat topologyKey {}",
                constraint.topology_key
            );
        }
    }
    if let Some(dns_policy) = args.agent_dns_policy.as_deref() {
        parse_kubernetes_dns_policy(dns_policy).map_err(anyhow::Error::msg)?;
        if args.disable_agent_host_network && dns_policy == "ClusterFirstWithHostNet" {
            anyhow::bail!(
                "--agent-dns-policy ClusterFirstWithHostNet requires hostNetwork; omit it or choose ClusterFirst/Default/None when --disable-agent-host-network is set"
            );
        }
    }
    if let Some(host_path) = args.agent_state_host_path.as_deref() {
        validate_kubernetes_agent_state_host_path(host_path).map_err(anyhow::Error::msg)?;
    }
    if let Some(mount_path) = args.agent_state_mount_path.as_deref() {
        validate_kubernetes_agent_state_mount_path(mount_path).map_err(anyhow::Error::msg)?;
    }
    if let Some(host_path_type) = args.agent_state_host_path_type.as_deref() {
        parse_kubernetes_host_path_type(host_path_type).map_err(anyhow::Error::msg)?;
    }
    validate_k8s_probe_config(
        "agent liveness probe",
        args.disable_agent_liveness_probe,
        args.agent_probes.liveness_configured(),
        args.agent_probes.liveness_path.as_deref(),
        args.agent_probes.liveness_period_seconds,
        args.agent_probes.liveness_timeout_seconds,
        args.agent_probes.liveness_failure_threshold,
    )?;
    validate_k8s_probe_config(
        "agent readiness probe",
        args.disable_agent_readiness_probe,
        args.agent_probes.readiness_configured(),
        args.agent_probes.readiness_path.as_deref(),
        args.agent_probes.readiness_period_seconds,
        args.agent_probes.readiness_timeout_seconds,
        args.agent_probes.readiness_failure_threshold,
    )?;
    validate_k8s_probe_config(
        "agent startup probe",
        args.disable_agent_startup_probe,
        args.agent_probes.startup_configured(),
        args.agent_probes.startup_path.as_deref(),
        args.agent_probes.startup_period_seconds,
        args.agent_probes.startup_timeout_seconds,
        args.agent_probes.startup_failure_threshold,
    )?;
    if let Some(seconds) = args.agent_termination_grace_period_seconds {
        if seconds > KUBERNETES_INT64_MAX {
            anyhow::bail!("--agent-termination-grace-period-seconds must be a non-negative int64");
        }
    }
    if args.agent_pre_stop_sleep_seconds == Some(0) {
        anyhow::bail!("--agent-pre-stop-sleep-seconds must be greater than zero");
    }
    for (label, quantity) in [
        (
            "agent resource request cpu",
            args.agent_resource_request_cpu.as_deref(),
        ),
        (
            "agent resource request memory",
            args.agent_resource_request_memory.as_deref(),
        ),
        (
            "agent resource limit cpu",
            args.agent_resource_limit_cpu.as_deref(),
        ),
        (
            "agent resource limit memory",
            args.agent_resource_limit_memory.as_deref(),
        ),
    ] {
        if let Some(quantity) = quantity {
            validate_kubernetes_resource_quantity(quantity, label).map_err(anyhow::Error::msg)?;
        }
    }
    Ok(())
}

fn validate_k8s_probe_config(
    label: &str,
    disabled: bool,
    configured: bool,
    path: Option<&str>,
    period_seconds: Option<u32>,
    timeout_seconds: Option<u32>,
    failure_threshold: Option<u32>,
) -> anyhow::Result<()> {
    if disabled && configured {
        anyhow::bail!("{label} settings require the probe to be enabled");
    }
    if let Some(path) = path {
        validate_kubernetes_http_probe_path(path, label).map_err(anyhow::Error::msg)?;
    }
    for (field, value) in [
        ("period seconds", period_seconds),
        ("timeout seconds", timeout_seconds),
        ("failure threshold", failure_threshold),
    ] {
        if value == Some(0) {
            anyhow::bail!("{label} {field} must be greater than zero");
        }
    }
    Ok(())
}

fn validate_k8s_agent_rollout_options(args: &K8sInstallArgs) -> anyhow::Result<()> {
    if let Some(update_strategy) = args.agent_update_strategy.as_deref() {
        parse_kubernetes_daemonset_update_strategy(update_strategy).map_err(anyhow::Error::msg)?;
    }
    if let Some(max_unavailable) = args.agent_rollout_max_unavailable.as_deref() {
        validate_kubernetes_int_or_percent(max_unavailable, "agent rollout maxUnavailable")
            .map_err(anyhow::Error::msg)?;
    }
    if let Some(max_surge) = args.agent_rollout_max_surge.as_deref() {
        validate_kubernetes_int_or_percent(max_surge, "agent rollout maxSurge")
            .map_err(anyhow::Error::msg)?;
    }
    if args.agent_update_strategy.as_deref() == Some("OnDelete")
        && (args.agent_rollout_max_unavailable.is_some() || args.agent_rollout_max_surge.is_some())
    {
        anyhow::bail!(
            "--agent-rollout-max-unavailable and --agent-rollout-max-surge require --agent-update-strategy RollingUpdate or no explicit strategy"
        );
    }
    if args
        .agent_rollout_max_unavailable
        .as_deref()
        .is_some_and(kubernetes_int_or_percent_is_zero)
        && args
            .agent_rollout_max_surge
            .as_deref()
            .is_none_or(kubernetes_int_or_percent_is_zero)
    {
        anyhow::bail!(
            "--agent-rollout-max-unavailable cannot be zero when --agent-rollout-max-surge is zero or unset"
        );
    }
    Ok(())
}

fn validate_k8s_agent_pdb_options(args: &K8sInstallArgs) -> anyhow::Result<()> {
    if let Some(min_available) = args.agent_pdb_min_available.as_deref() {
        validate_kubernetes_int_or_percent(min_available, "agent PodDisruptionBudget minAvailable")
            .map_err(anyhow::Error::msg)?;
    }
    if let Some(max_unavailable) = args.agent_pdb_max_unavailable.as_deref() {
        validate_kubernetes_int_or_percent(
            max_unavailable,
            "agent PodDisruptionBudget maxUnavailable",
        )
        .map_err(anyhow::Error::msg)?;
    }
    if args.agent_pdb_min_available.is_some() && args.agent_pdb_max_unavailable.is_some() {
        anyhow::bail!(
            "--agent-pdb-min-available and --agent-pdb-max-unavailable are mutually exclusive"
        );
    }
    Ok(())
}

fn validate_k8s_network_policy(args: &K8sInstallArgs) -> anyhow::Result<()> {
    if args.network_policy_acknowledge_host_network && !args.enable_network_policy {
        anyhow::bail!("--network-policy-acknowledge-host-network requires --enable-network-policy");
    }
    if args.network_policy_acknowledge_host_network && args.disable_agent_host_network {
        anyhow::bail!(
            "--network-policy-acknowledge-host-network only applies when agent host networking is enabled; remove it with --disable-agent-host-network"
        );
    }
    if !args.agent_api_network_policy_cidrs.is_empty() && !args.enable_network_policy {
        anyhow::bail!("--agent-api-network-policy-cidr requires --enable-network-policy");
    }
    if !args.relay_network_policy_cidrs.is_empty() && !args.enable_network_policy {
        anyhow::bail!("--relay-network-policy-cidr requires --enable-network-policy");
    }
    if !args.agent_api_network_policy_cidrs.is_empty() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-network-policy-cidr requires --expose-agent-api");
    }
    if !args.relay_network_policy_cidrs.is_empty() && !args.expose_relay {
        anyhow::bail!("--relay-network-policy-cidr requires --expose-relay");
    }
    if args.enable_network_policy
        && args.agent_api_network_policy_cidrs.is_empty()
        && args.relay_network_policy_cidrs.is_empty()
    {
        anyhow::bail!(
            "--enable-network-policy requires at least one --agent-api-network-policy-cidr or --relay-network-policy-cidr"
        );
    }
    if args.enable_network_policy
        && !args.disable_agent_host_network
        && !args.network_policy_acknowledge_host_network
    {
        anyhow::bail!(
            "--enable-network-policy requires --network-policy-acknowledge-host-network because the chart runs agents with hostNetwork=true and NetworkPolicy enforcement is CNI-dependent"
        );
    }
    validate_kubernetes_restricted_cidrs(
        "--agent-api-network-policy-cidr",
        &args.agent_api_network_policy_cidrs,
        "NetworkPolicy allowlists must narrow ingress sources",
        "NetworkPolicy CIDR allowlist",
    )?;
    validate_kubernetes_restricted_cidrs(
        "--relay-network-policy-cidr",
        &args.relay_network_policy_cidrs,
        "NetworkPolicy allowlists must narrow ingress sources",
        "NetworkPolicy CIDR allowlist",
    )?;
    validate_kubernetes_network_policy_within_source_ranges(
        "--agent-api-network-policy-cidr",
        &args.agent_api_network_policy_cidrs,
        "--agent-api-allow-source-cidr",
        &args.agent_api_allow_source_cidrs,
    )?;
    validate_kubernetes_network_policy_within_source_ranges(
        "--relay-network-policy-cidr",
        &args.relay_network_policy_cidrs,
        "--relay-allow-source-cidr",
        &args.relay_allow_source_cidrs,
    )?;
    Ok(())
}

fn validate_k8s_service_exposure(args: &K8sInstallArgs) -> anyhow::Result<()> {
    let agent_api_public_exposure = k8s_agent_api_public_exposure_requires_ack(args);
    let relay_public_exposure = k8s_relay_public_exposure_requires_ack(args);
    let agent_api_unrestricted_load_balancer_ack =
        k8s_agent_api_unrestricted_load_balancer_ack_applies(args);
    let relay_unrestricted_load_balancer_ack =
        k8s_relay_unrestricted_load_balancer_ack_applies(args);
    let agent_api_cluster_external_traffic_policy_ack =
        k8s_agent_api_cluster_external_traffic_policy_ack_applies(args);
    let relay_cluster_external_traffic_policy_ack =
        k8s_relay_cluster_external_traffic_policy_ack_applies(args);

    for (port, flag) in [
        (args.agent_api_port, "--agent-api-port"),
        (args.agent_api_target_port, "--agent-api-target-port"),
        (args.relay_udp_port, "--relay-udp-port"),
        (args.relay_udp_target_port, "--relay-udp-target-port"),
        (args.relay_http_port, "--relay-http-port"),
        (args.relay_http_target_port, "--relay-http-target-port"),
    ] {
        if let Some(port) = port {
            validate_kubernetes_service_port_value(port, flag)?;
        }
    }

    if args.agent_api_cluster_ip.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-cluster-ip requires --expose-agent-api");
    }
    if args.agent_api_secondary_cluster_ip.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-secondary-cluster-ip requires --expose-agent-api");
    }
    if args.agent_api_service_type != "ClusterIP" && !args.expose_agent_api {
        anyhow::bail!("--agent-api-service-type requires --expose-agent-api");
    }
    if args.agent_api_port.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-port requires --expose-agent-api");
    }
    if args.agent_api_target_port.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-target-port requires --expose-agent-api");
    }
    if args.agent_api_node_port.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-node-port requires --expose-agent-api");
    }
    if args.agent_api_app_protocol.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-app-protocol requires --expose-agent-api");
    }
    if args.agent_api_publish_not_ready_addresses && !args.expose_agent_api {
        anyhow::bail!("--agent-api-publish-not-ready-addresses requires --expose-agent-api");
    }
    if args.agent_api_load_balancer_class.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-load-balancer-class requires --expose-agent-api");
    }
    if args.agent_api_load_balancer_ip.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-load-balancer-ip requires --expose-agent-api");
    }
    if !args.agent_api_external_ips.is_empty() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-external-ip requires --expose-agent-api");
    }
    if !args.agent_api_allow_source_cidrs.is_empty() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-allow-source-cidr requires --expose-agent-api");
    }
    if args.agent_api_health_check_node_port.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-health-check-node-port requires --expose-agent-api");
    }
    if args.agent_api_disable_load_balancer_node_ports && !args.expose_agent_api {
        anyhow::bail!("--agent-api-disable-load-balancer-node-ports requires --expose-agent-api");
    }
    if args.agent_api_ip_family_policy.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-ip-family-policy requires --expose-agent-api");
    }
    if !args.agent_api_ip_families.is_empty() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-ip-family requires --expose-agent-api");
    }
    if args.agent_api_internal_traffic_policy.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-internal-traffic-policy requires --expose-agent-api");
    }
    if args.agent_api_traffic_distribution.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-traffic-distribution requires --expose-agent-api");
    }
    if args.agent_api_session_affinity.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-session-affinity requires --expose-agent-api");
    }
    if args.agent_api_session_affinity_timeout_seconds.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-session-affinity-timeout-seconds requires --expose-agent-api");
    }
    if !args.agent_api_service_annotations.is_empty() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-service-annotation requires --expose-agent-api");
    }
    if args.relay_cluster_ip.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-cluster-ip requires --expose-relay");
    }
    if args.relay_secondary_cluster_ip.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-secondary-cluster-ip requires --expose-relay");
    }
    if args.relay_service_type != "LoadBalancer" && !args.expose_relay {
        anyhow::bail!("--relay-service-type requires --expose-relay");
    }
    if args.relay_udp_port.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-udp-port requires --expose-relay");
    }
    if args.relay_udp_target_port.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-udp-target-port requires --expose-relay");
    }
    if args.relay_http_port.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-http-port requires --expose-relay");
    }
    if args.relay_http_target_port.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-http-target-port requires --expose-relay");
    }
    if args.relay_udp_node_port.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-udp-node-port requires --expose-relay");
    }
    if args.relay_http_node_port.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-http-node-port requires --expose-relay");
    }
    if args.relay_udp_app_protocol.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-udp-app-protocol requires --expose-relay");
    }
    if args.relay_http_app_protocol.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-http-app-protocol requires --expose-relay");
    }
    if args.relay_publish_not_ready_addresses && !args.expose_relay {
        anyhow::bail!("--relay-publish-not-ready-addresses requires --expose-relay");
    }
    if args.relay_load_balancer_class.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-load-balancer-class requires --expose-relay");
    }
    if args.relay_load_balancer_ip.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-load-balancer-ip requires --expose-relay");
    }
    if !args.relay_external_ips.is_empty() && !args.expose_relay {
        anyhow::bail!("--relay-external-ip requires --expose-relay");
    }
    if !args.relay_allow_source_cidrs.is_empty() && !args.expose_relay {
        anyhow::bail!("--relay-allow-source-cidr requires --expose-relay");
    }
    if args.relay_health_check_node_port.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-health-check-node-port requires --expose-relay");
    }
    if args.relay_disable_load_balancer_node_ports && !args.expose_relay {
        anyhow::bail!("--relay-disable-load-balancer-node-ports requires --expose-relay");
    }
    if args.relay_ip_family_policy.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-ip-family-policy requires --expose-relay");
    }
    if !args.relay_ip_families.is_empty() && !args.expose_relay {
        anyhow::bail!("--relay-ip-family requires --expose-relay");
    }
    if args.relay_internal_traffic_policy.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-internal-traffic-policy requires --expose-relay");
    }
    if args.relay_traffic_distribution.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-traffic-distribution requires --expose-relay");
    }
    if args.relay_session_affinity.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-session-affinity requires --expose-relay");
    }
    if args.relay_session_affinity_timeout_seconds.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-session-affinity-timeout-seconds requires --expose-relay");
    }
    if !args.relay_service_annotations.is_empty() && !args.expose_relay {
        anyhow::bail!("--relay-service-annotation requires --expose-relay");
    }
    validate_kubernetes_service_annotation_args(
        "--agent-api-service-annotation",
        &args.agent_api_service_annotations,
    )?;
    validate_kubernetes_service_annotation_args(
        "--relay-service-annotation",
        &args.relay_service_annotations,
    )?;
    validate_kubernetes_service_ip_families(
        "agent-api",
        args.agent_api_ip_family_policy.as_deref(),
        &args.agent_api_ip_families,
    )?;
    validate_kubernetes_service_ip_families(
        "relay",
        args.relay_ip_family_policy.as_deref(),
        &args.relay_ip_families,
    )?;
    validate_kubernetes_service_cluster_ips(
        "agent-api",
        args.agent_api_cluster_ip,
        args.agent_api_secondary_cluster_ip,
        args.agent_api_ip_family_policy.as_deref(),
        &args.agent_api_ip_families,
    )?;
    validate_kubernetes_service_cluster_ips(
        "relay",
        args.relay_cluster_ip,
        args.relay_secondary_cluster_ip,
        args.relay_ip_family_policy.as_deref(),
        &args.relay_ip_families,
    )?;
    validate_kubernetes_service_cluster_ip_disjoint(
        "agent-api",
        args.agent_api_cluster_ip,
        args.agent_api_secondary_cluster_ip,
        "relay",
        args.relay_cluster_ip,
        args.relay_secondary_cluster_ip,
    )?;
    validate_kubernetes_session_affinity_options(
        "agent-api",
        args.agent_api_session_affinity.as_deref(),
        args.agent_api_session_affinity_timeout_seconds,
    )?;
    validate_kubernetes_session_affinity_options(
        "relay",
        args.relay_session_affinity.as_deref(),
        args.relay_session_affinity_timeout_seconds,
    )?;
    if let Some(traffic_distribution) = args.agent_api_traffic_distribution.as_deref() {
        parse_kubernetes_traffic_distribution(traffic_distribution).map_err(anyhow::Error::msg)?;
    }
    if let Some(traffic_distribution) = args.relay_traffic_distribution.as_deref() {
        parse_kubernetes_traffic_distribution(traffic_distribution).map_err(anyhow::Error::msg)?;
    }
    if let Some(app_protocol) = args.agent_api_app_protocol.as_deref() {
        validate_kubernetes_app_protocol(app_protocol)
            .map_err(|error| anyhow::anyhow!("--agent-api-app-protocol {error}"))?;
    }
    if let Some(app_protocol) = args.relay_udp_app_protocol.as_deref() {
        validate_kubernetes_app_protocol(app_protocol)
            .map_err(|error| anyhow::anyhow!("--relay-udp-app-protocol {error}"))?;
    }
    if let Some(app_protocol) = args.relay_http_app_protocol.as_deref() {
        validate_kubernetes_app_protocol(app_protocol)
            .map_err(|error| anyhow::anyhow!("--relay-http-app-protocol {error}"))?;
    }
    if args.expose_agent_api
        && is_external_kubernetes_service_type(&args.agent_api_service_type)
        && !args.allow_public_service_exposure
    {
        anyhow::bail!(
            "--expose-agent-api with {} requires --allow-public-service-exposure",
            args.agent_api_service_type
        );
    }
    if args.expose_relay
        && is_external_kubernetes_service_type(&args.relay_service_type)
        && !args.allow_public_service_exposure
    {
        anyhow::bail!(
            "--expose-relay with {} requires --allow-public-service-exposure",
            args.relay_service_type
        );
    }
    if args.allow_public_service_exposure && !(agent_api_public_exposure || relay_public_exposure) {
        anyhow::bail!(
            "--allow-public-service-exposure requires an exposed NodePort/LoadBalancer Service or Service externalIPs"
        );
    }
    if !args.agent_api_allow_source_cidrs.is_empty()
        && args.agent_api_service_type != "LoadBalancer"
    {
        anyhow::bail!("--agent-api-allow-source-cidr only applies to LoadBalancer services");
    }
    if !args.relay_allow_source_cidrs.is_empty() && args.relay_service_type != "LoadBalancer" {
        anyhow::bail!("--relay-allow-source-cidr only applies to LoadBalancer services");
    }
    validate_kubernetes_restricted_cidrs(
        "--agent-api-allow-source-cidr",
        &args.agent_api_allow_source_cidrs,
        "use --allow-unrestricted-load-balancer without source ranges to acknowledge unrestricted LoadBalancer exposure",
        "LoadBalancer source CIDR",
    )?;
    validate_kubernetes_restricted_cidrs(
        "--relay-allow-source-cidr",
        &args.relay_allow_source_cidrs,
        "use --allow-unrestricted-load-balancer without source ranges to acknowledge unrestricted LoadBalancer exposure",
        "LoadBalancer source CIDR",
    )?;
    if args.agent_api_node_port.is_some()
        && !is_external_kubernetes_service_type(&args.agent_api_service_type)
    {
        anyhow::bail!("--agent-api-node-port only applies to NodePort or LoadBalancer services");
    }
    if (args.relay_udp_node_port.is_some() || args.relay_http_node_port.is_some())
        && !is_external_kubernetes_service_type(&args.relay_service_type)
    {
        anyhow::bail!(
            "--relay-udp-node-port and --relay-http-node-port only apply to NodePort or LoadBalancer services"
        );
    }
    if args.agent_api_external_traffic_policy == "Cluster"
        && !k8s_agent_api_external_traffic_policy_applies(args)
    {
        anyhow::bail!(
            "--agent-api-external-traffic-policy Cluster requires --expose-agent-api with NodePort or LoadBalancer service type"
        );
    }
    if args.relay_external_traffic_policy == "Cluster"
        && !k8s_relay_external_traffic_policy_applies(args)
    {
        anyhow::bail!(
            "--relay-external-traffic-policy Cluster requires --expose-relay with NodePort or LoadBalancer service type"
        );
    }
    if args.relay_udp_node_port.is_some()
        && args.relay_http_node_port.is_some()
        && args.relay_udp_node_port == args.relay_http_node_port
    {
        anyhow::bail!("--relay-udp-node-port and --relay-http-node-port must be different");
    }
    if args.agent_api_load_balancer_class.is_some() && args.agent_api_service_type != "LoadBalancer"
    {
        anyhow::bail!("--agent-api-load-balancer-class only applies to LoadBalancer services");
    }
    if args.relay_load_balancer_class.is_some() && args.relay_service_type != "LoadBalancer" {
        anyhow::bail!("--relay-load-balancer-class only applies to LoadBalancer services");
    }
    if args.agent_api_load_balancer_ip.is_some() && args.agent_api_service_type != "LoadBalancer" {
        anyhow::bail!("--agent-api-load-balancer-ip only applies to LoadBalancer services");
    }
    if args.relay_load_balancer_ip.is_some() && args.relay_service_type != "LoadBalancer" {
        anyhow::bail!("--relay-load-balancer-ip only applies to LoadBalancer services");
    }
    if !args.agent_api_external_ips.is_empty() && !args.allow_public_service_exposure {
        anyhow::bail!(
            "--agent-api-external-ip requires --allow-public-service-exposure because externalIPs can expose the Service outside the cluster"
        );
    }
    if !args.relay_external_ips.is_empty() && !args.allow_public_service_exposure {
        anyhow::bail!(
            "--relay-external-ip requires --allow-public-service-exposure because externalIPs can expose the Service outside the cluster"
        );
    }
    if let Some(ip) = args.agent_api_load_balancer_ip {
        validate_kubernetes_external_service_ip("--agent-api-load-balancer-ip", ip)?;
    }
    if let Some(ip) = args.relay_load_balancer_ip {
        validate_kubernetes_external_service_ip("--relay-load-balancer-ip", ip)?;
    }
    validate_kubernetes_external_service_ips(
        "--agent-api-external-ip",
        &args.agent_api_external_ips,
    )?;
    validate_kubernetes_external_service_ips("--relay-external-ip", &args.relay_external_ips)?;
    validate_kubernetes_external_service_ip_families(
        "agent-api",
        "--agent-api-load-balancer-ip",
        args.agent_api_load_balancer_ip,
        "--agent-api-external-ip",
        &args.agent_api_external_ips,
        &args.agent_api_ip_families,
    )?;
    validate_kubernetes_external_service_ip_families(
        "relay",
        "--relay-load-balancer-ip",
        args.relay_load_balancer_ip,
        "--relay-external-ip",
        &args.relay_external_ips,
        &args.relay_ip_families,
    )?;
    validate_kubernetes_external_service_ip_disjoint(
        args.agent_api_load_balancer_ip,
        &args.agent_api_external_ips,
        args.relay_load_balancer_ip,
        &args.relay_external_ips,
    )?;
    if args.agent_api_health_check_node_port.is_some()
        && args.agent_api_service_type != "LoadBalancer"
    {
        anyhow::bail!("--agent-api-health-check-node-port only applies to LoadBalancer services");
    }
    if args.relay_health_check_node_port.is_some() && args.relay_service_type != "LoadBalancer" {
        anyhow::bail!("--relay-health-check-node-port only applies to LoadBalancer services");
    }
    if args.agent_api_health_check_node_port.is_some()
        && args.agent_api_external_traffic_policy != "Local"
    {
        anyhow::bail!(
            "--agent-api-health-check-node-port requires --agent-api-external-traffic-policy Local"
        );
    }
    if args.relay_health_check_node_port.is_some() && args.relay_external_traffic_policy != "Local"
    {
        anyhow::bail!(
            "--relay-health-check-node-port requires --relay-external-traffic-policy Local"
        );
    }
    if args.agent_api_health_check_node_port.is_some()
        && args.agent_api_health_check_node_port == args.agent_api_node_port
    {
        anyhow::bail!("--agent-api-health-check-node-port must differ from --agent-api-node-port");
    }
    if args.relay_health_check_node_port.is_some()
        && (args.relay_health_check_node_port == args.relay_udp_node_port
            || args.relay_health_check_node_port == args.relay_http_node_port)
    {
        anyhow::bail!("--relay-health-check-node-port must differ from relay NodePort overrides");
    }
    validate_kubernetes_node_port_uniqueness(args)?;
    if args.agent_api_disable_load_balancer_node_ports
        && args.agent_api_service_type != "LoadBalancer"
    {
        anyhow::bail!(
            "--agent-api-disable-load-balancer-node-ports only applies to LoadBalancer services"
        );
    }
    if args.relay_disable_load_balancer_node_ports && args.relay_service_type != "LoadBalancer" {
        anyhow::bail!(
            "--relay-disable-load-balancer-node-ports only applies to LoadBalancer services"
        );
    }
    if args.agent_api_disable_load_balancer_node_ports && args.agent_api_node_port.is_some() {
        anyhow::bail!(
            "--agent-api-disable-load-balancer-node-ports cannot be combined with --agent-api-node-port"
        );
    }
    if args.relay_disable_load_balancer_node_ports
        && (args.relay_udp_node_port.is_some() || args.relay_http_node_port.is_some())
    {
        anyhow::bail!(
            "--relay-disable-load-balancer-node-ports cannot be combined with relay NodePort overrides"
        );
    }
    if args.expose_agent_api
        && args.agent_api_service_type == "LoadBalancer"
        && args.agent_api_allow_source_cidrs.is_empty()
        && !args.allow_unrestricted_load_balancer
    {
        anyhow::bail!(
            "--expose-agent-api with LoadBalancer requires --agent-api-allow-source-cidr or --allow-unrestricted-load-balancer"
        );
    }
    if args.expose_relay
        && args.relay_service_type == "LoadBalancer"
        && args.relay_allow_source_cidrs.is_empty()
        && !args.allow_unrestricted_load_balancer
    {
        anyhow::bail!(
            "--expose-relay with LoadBalancer requires --relay-allow-source-cidr or --allow-unrestricted-load-balancer"
        );
    }
    if args.allow_unrestricted_load_balancer
        && !(agent_api_unrestricted_load_balancer_ack || relay_unrestricted_load_balancer_ack)
    {
        anyhow::bail!(
            "--allow-unrestricted-load-balancer requires at least one exposed LoadBalancer Service without source CIDR ranges"
        );
    }
    if args.expose_agent_api
        && is_external_kubernetes_service_type(&args.agent_api_service_type)
        && args.agent_api_external_traffic_policy == "Cluster"
        && !args.allow_cluster_external_traffic_policy
    {
        anyhow::bail!(
            "--expose-agent-api with externalTrafficPolicy=Cluster requires --allow-cluster-external-traffic-policy"
        );
    }
    if args.expose_relay
        && is_external_kubernetes_service_type(&args.relay_service_type)
        && args.relay_external_traffic_policy == "Cluster"
        && !args.allow_cluster_external_traffic_policy
    {
        anyhow::bail!(
            "--expose-relay with externalTrafficPolicy=Cluster requires --allow-cluster-external-traffic-policy"
        );
    }
    if args.allow_cluster_external_traffic_policy
        && !(agent_api_cluster_external_traffic_policy_ack
            || relay_cluster_external_traffic_policy_ack)
    {
        anyhow::bail!(
            "--allow-cluster-external-traffic-policy requires at least one exposed NodePort or LoadBalancer Service with externalTrafficPolicy=Cluster"
        );
    }
    Ok(())
}

fn k8s_agent_api_public_exposure_requires_ack(args: &K8sInstallArgs) -> bool {
    args.expose_agent_api
        && (is_external_kubernetes_service_type(&args.agent_api_service_type)
            || !args.agent_api_external_ips.is_empty())
}

fn k8s_relay_public_exposure_requires_ack(args: &K8sInstallArgs) -> bool {
    args.expose_relay
        && (is_external_kubernetes_service_type(&args.relay_service_type)
            || !args.relay_external_ips.is_empty())
}

fn k8s_agent_api_unrestricted_load_balancer_ack_applies(args: &K8sInstallArgs) -> bool {
    args.expose_agent_api
        && args.agent_api_service_type == "LoadBalancer"
        && args.agent_api_allow_source_cidrs.is_empty()
}

fn k8s_relay_unrestricted_load_balancer_ack_applies(args: &K8sInstallArgs) -> bool {
    args.expose_relay
        && args.relay_service_type == "LoadBalancer"
        && args.relay_allow_source_cidrs.is_empty()
}

fn k8s_agent_api_external_traffic_policy_applies(args: &K8sInstallArgs) -> bool {
    args.expose_agent_api && is_external_kubernetes_service_type(&args.agent_api_service_type)
}

fn k8s_relay_external_traffic_policy_applies(args: &K8sInstallArgs) -> bool {
    args.expose_relay && is_external_kubernetes_service_type(&args.relay_service_type)
}

fn k8s_agent_api_cluster_external_traffic_policy_ack_applies(args: &K8sInstallArgs) -> bool {
    k8s_agent_api_external_traffic_policy_applies(args)
        && args.agent_api_external_traffic_policy == "Cluster"
}

fn k8s_relay_cluster_external_traffic_policy_ack_applies(args: &K8sInstallArgs) -> bool {
    k8s_relay_external_traffic_policy_applies(args)
        && args.relay_external_traffic_policy == "Cluster"
}

fn validate_kubernetes_node_port_uniqueness(args: &K8sInstallArgs) -> anyhow::Result<()> {
    let mut node_ports = Vec::new();
    add_unique_kubernetes_node_port(
        &mut node_ports,
        "--agent-api-node-port",
        args.agent_api_node_port,
    )?;
    add_unique_kubernetes_node_port(
        &mut node_ports,
        "--agent-api-health-check-node-port",
        args.agent_api_health_check_node_port,
    )?;
    add_unique_kubernetes_node_port(
        &mut node_ports,
        "--relay-udp-node-port",
        args.relay_udp_node_port,
    )?;
    add_unique_kubernetes_node_port(
        &mut node_ports,
        "--relay-http-node-port",
        args.relay_http_node_port,
    )?;
    add_unique_kubernetes_node_port(
        &mut node_ports,
        "--relay-health-check-node-port",
        args.relay_health_check_node_port,
    )?;
    Ok(())
}

fn add_unique_kubernetes_node_port(
    node_ports: &mut Vec<(u16, &'static str)>,
    label: &'static str,
    port: Option<u16>,
) -> anyhow::Result<()> {
    let Some(port) = port else {
        return Ok(());
    };
    if let Some((_, existing_label)) = node_ports
        .iter()
        .find(|(existing_port, _)| *existing_port == port)
    {
        anyhow::bail!(
            "{label} must not reuse Kubernetes NodePort {port} already assigned to {existing_label}"
        );
    }
    node_ports.push((port, label));
    Ok(())
}

#[cfg(test)]
mod tests {
    use ipars_agent::AgentNodeState;
    use ipars_crypto::{verify_control_plane_node_query_signature, verify_join_token};

    use super::*;

    fn test_error<T, E>(result: Result<T, E>, context: &str) -> E {
        match result {
            Ok(_) => panic!("{context}"),
            Err(error) => error,
        }
    }

    fn token_with_bootstrap(endpoints: Vec<BootstrapEndpoint>) -> anyhow::Result<SignedJoinToken> {
        Ok(SignedJoinToken {
            claims: claims(
                ClusterId::from_string("cluster-a"),
                TokenIssuer {
                    node_id: NodeId::from_string("issuer"),
                    key_id: KeyId::from_string("root"),
                },
                "edge".to_string(),
                Vec::new(),
                300,
                endpoints,
                TokenPolicyInput {
                    allow_relay: false,
                    allowed_routes: Vec::new(),
                    max_token_uses: Some(1),
                },
            )?,
            signature: "signature".to_string(),
        })
    }

    fn valid_init_args() -> InitArgs {
        InitArgs {
            public_endpoint: SocketAddr::from(([203, 0, 113, 10], 51820)),
            bootstrap_scheme: "http".to_string(),
            issuer_key_id: "root".to_string(),
            issuer_private_key_b64: None,
            issuer_private_key_path: None,
            emit_issuer_private_key: false,
            token_ttl_seconds: 300,
            default_role: "edge".to_string(),
            tags: Vec::new(),
            allowed_routes: Vec::new(),
            allow_relay: true,
            max_uses: Some(10),
            unlimited_uses: false,
            spawn_daemons: false,
            daemon_binary: PathBuf::from("iparsd"),
            daemon_state_dir: temp_path("state"),
            control_plane_listen: SocketAddr::from(([0, 0, 0, 0], 8443)),
            control_plane_database_url: None,
            control_plane_operator_api_bearer_token_path: None,
            signal_listen: SocketAddr::from(([0, 0, 0, 0], 9443)),
            stun_listen: SocketAddr::from(([0, 0, 0, 0], 3478)),
            stun_alternate_listen: None,
            stun_http_listen: SocketAddr::from(([0, 0, 0, 0], 3479)),
            relay_udp_listen: SocketAddr::from(([0, 0, 0, 0], 51820)),
            relay_http_listen: SocketAddr::from(([0, 0, 0, 0], 9580)),
            relay_admission_url: None,
        }
    }

    async fn spawn_raw_http_response(
        response: String,
    ) -> anyhow::Result<(String, tokio::task::JoinHandle<anyhow::Result<()>>)> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
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

    async fn spawn_raw_http_response_with_request(
        response: String,
    ) -> anyhow::Result<(
        String,
        tokio::task::JoinHandle<anyhow::Result<()>>,
        tokio::sync::oneshot::Receiver<Vec<u8>>,
    )> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let (request_tx, request_rx) = tokio::sync::oneshot::channel();
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
            let _ = request_tx.send(request);
            stream.write_all(response.as_bytes()).await?;
            Ok(())
        });
        Ok((format!("http://{addr}"), task, request_rx))
    }

    async fn spawn_raw_http_response_with_complete_request(
        response: String,
    ) -> anyhow::Result<(
        String,
        tokio::task::JoinHandle<anyhow::Result<()>>,
        tokio::sync::oneshot::Receiver<Vec<u8>>,
    )> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let (request_tx, request_rx) = tokio::sync::oneshot::channel();
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
                if http_request_body_is_complete(&request) {
                    break;
                }
            }
            let _ = request_tx.send(request);
            stream.write_all(response.as_bytes()).await?;
            Ok(())
        });
        Ok((format!("http://{addr}"), task, request_rx))
    }

    fn http_request_body_is_complete(request: &[u8]) -> bool {
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        });
        match content_length {
            Some(content_length) => request.len() >= header_end + 4 + content_length,
            None => true,
        }
    }

    fn http_request_body(request: &[u8]) -> anyhow::Result<&[u8]> {
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .context("raw HTTP request did not include a header terminator")?;
        Ok(&request[header_end + 4..])
    }

    fn cli_test_node_record(node_id: NodeId) -> ipars_types::NodeRecord {
        ipars_types::NodeRecord {
            node_id,
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: ipars_types::VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
            identity_public_key: "identity-public".to_string(),
            wireguard_public_key: "wireguard-public".to_string(),
            role: Role::edge(),
            tags: BTreeSet::new(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn cli_bounded_json_response_rejects_oversized_responses() -> anyhow::Result<()> {
        let body = r#"{"ok":true}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let (url, server) = spawn_raw_http_response(response).await?;
        let response = reqwest::Client::new().get(&url).send().await?;
        let value: serde_json::Value =
            read_bounded_json_response_with_limit(response, "test CLI JSON", 64).await?;
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .context("timed out waiting for bounded CLI JSON test server")???;
        assert_eq!(value["ok"], true);

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            65
        );
        let (url, server) = spawn_raw_http_response(response).await?;
        let response = reqwest::Client::new().get(&url).send().await?;
        let error = test_error(
            read_bounded_json_response_with_limit::<serde_json::Value>(
                response,
                "test CLI JSON",
                64,
            )
            .await,
            "oversized Content-Length should be rejected",
        );
        assert!(error
            .to_string()
            .contains("test CLI JSON response exceeds maximum size of 64 bytes"));
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .context("timed out waiting for oversized Content-Length CLI JSON test server")???;

        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\n{\"ok\"\r\n5\r\n:true\r\n1\r\n}\r\n0\r\n\r\n"
            .to_string();
        let (url, server) = spawn_raw_http_response(response).await?;
        let response = reqwest::Client::new().get(&url).send().await?;
        let error = test_error(
            read_bounded_json_response_with_limit::<serde_json::Value>(
                response,
                "test CLI JSON chunked",
                10,
            )
            .await,
            "oversized chunked body should be rejected",
        );
        assert!(error
            .to_string()
            .contains("test CLI JSON chunked response exceeds maximum size of 10 bytes"));
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .context("timed out waiting for oversized chunked CLI JSON test server")???;
        Ok(())
    }

    #[tokio::test]
    async fn cli_get_json_rejects_oversized_http_response() -> anyhow::Result<()> {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_CLI_HTTP_JSON_RESPONSE_BYTES + 1
        );
        let (url, server) = spawn_raw_http_response(response).await?;
        let error = test_error(
            get_json::<serde_json::Value>(&url, "/v1/status", "test endpoint").await,
            "oversized CLI HTTP response should be rejected",
        );
        assert!(format!("{error:#}").contains("test endpoint response exceeds maximum size"));
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .context("timed out waiting for oversized CLI get_json test server")???;
        Ok(())
    }

    #[tokio::test]
    async fn path_events_reads_agent_endpoint() -> anyhow::Result<()> {
        let body = r#"{"events":[],"generated_at":"2026-07-09T00:00:00Z"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let (url, server, request_rx) = spawn_raw_http_response_with_request(response).await?;

        let events = path_events(&url).await?;

        assert!(events.events.is_empty());
        assert_eq!(
            events.generated_at,
            "2026-07-09T00:00:00Z".parse::<chrono::DateTime<Utc>>()?
        );
        let request = request_rx.await?;
        let request = String::from_utf8_lossy(&request);
        assert!(
            request.starts_with("GET /v1/path-events HTTP/1.1\r\n"),
            "unexpected request: {request}"
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .context("timed out waiting for path events CLI test server")???;
        Ok(())
    }

    #[tokio::test]
    async fn key_rotate_posts_agent_request() -> anyhow::Result<()> {
        let node_id = NodeId::from_string("node-cli");
        let body = serde_json::to_string(&AgentWireGuardKeyRotationResponse {
            node_id: node_id.clone(),
            previous_wireguard_public_key: "previous-wireguard".to_string(),
            next_wireguard_public_key: "next-wireguard".to_string(),
            control_plane_node: cli_test_node_record(node_id.clone()),
            rotated_at: Utc::now(),
            state_updated_at: Utc::now(),
        })?;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let (url, server, request_rx) =
            spawn_raw_http_response_with_complete_request(response).await?;

        let output = rotate_wireguard_key(
            &url,
            &KeyRotateArgs {
                agent_url: None,
                control_plane_url: Some("http://127.0.0.1:8443".to_string()),
            },
        )
        .await?;

        assert_eq!(output.node_id, node_id);
        assert_eq!(output.next_wireguard_public_key, "next-wireguard");
        let request = request_rx.await?;
        let request_line = String::from_utf8_lossy(&request);
        assert!(
            request_line.starts_with("POST /v1/wireguard-key/rotate HTTP/1.1\r\n"),
            "unexpected request: {request_line}"
        );
        let posted: AgentWireGuardKeyRotationRequest =
            serde_json::from_slice(http_request_body(&request)?)?;
        assert_eq!(
            posted.control_plane_url.as_deref(),
            Some("http://127.0.0.1:8443")
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .context("timed out waiting for key rotate CLI test server")???;
        Ok(())
    }

    #[tokio::test]
    async fn node_remove_posts_agent_request() -> anyhow::Result<()> {
        let node_id = NodeId::from_string("node-cli");
        let body = serde_json::to_string(&AgentNodeRemovalResponse {
            node_id: node_id.clone(),
            control_plane_node: cli_test_node_record(node_id.clone()),
            removed_path_count: 3,
            removed_health: true,
            removed_at: Utc::now(),
        })?;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let (url, server, request_rx) =
            spawn_raw_http_response_with_complete_request(response).await?;

        let output = remove_node(
            &url,
            &NodeRemoveArgs {
                agent_url: None,
                control_plane_url: Some("http://127.0.0.1:8443".to_string()),
            },
        )
        .await?;

        assert_eq!(output.node_id, node_id);
        assert_eq!(output.removed_path_count, 3);
        assert!(output.removed_health);
        let request = request_rx.await?;
        let request_line = String::from_utf8_lossy(&request);
        assert!(
            request_line.starts_with("POST /v1/node/remove HTTP/1.1\r\n"),
            "unexpected request: {request_line}"
        );
        let posted: AgentNodeRemovalRequest = serde_json::from_slice(http_request_body(&request)?)?;
        assert_eq!(
            posted.control_plane_url.as_deref(),
            Some("http://127.0.0.1:8443")
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .context("timed out waiting for node remove CLI test server")???;
        Ok(())
    }

    #[test]
    fn join_url_uses_control_plane_bootstrap_endpoint() -> anyhow::Result<()> {
        let token = token_with_bootstrap(vec![
            BootstrapEndpoint {
                url: "udp://203.0.113.10:51820".to_string(),
                kind: BootstrapEndpointKind::Relay,
            },
            BootstrapEndpoint {
                url: "https://203.0.113.10:8443/".to_string(),
                kind: BootstrapEndpointKind::ControlPlane,
            },
        ])?;

        assert_eq!(
            control_plane_join_url(&token, None)?,
            "https://203.0.113.10:8443/v1/join"
        );
        Ok(())
    }

    #[test]
    fn join_urls_include_all_control_plane_bootstrap_endpoints() -> anyhow::Result<()> {
        let token = token_with_bootstrap(vec![
            BootstrapEndpoint {
                url: "https://203.0.113.10:9443".to_string(),
                kind: BootstrapEndpointKind::Signal,
            },
            BootstrapEndpoint {
                url: "https://203.0.113.10:8443/".to_string(),
                kind: BootstrapEndpointKind::ControlPlane,
            },
            BootstrapEndpoint {
                url: "https://203.0.113.11:8443".to_string(),
                kind: BootstrapEndpointKind::ControlPlane,
            },
        ])?;

        assert_eq!(
            control_plane_join_urls(&token, None)?,
            vec![
                "https://203.0.113.10:8443/v1/join".to_string(),
                "https://203.0.113.11:8443/v1/join".to_string(),
            ]
        );
        Ok(())
    }

    #[test]
    fn join_url_override_takes_precedence() -> anyhow::Result<()> {
        let token = token_with_bootstrap(Vec::new())?;

        assert_eq!(
            control_plane_join_url(&token, Some("http://127.0.0.1:8443"))?,
            "http://127.0.0.1:8443/v1/join"
        );
        Ok(())
    }

    #[test]
    fn join_url_requires_control_plane_endpoint() -> anyhow::Result<()> {
        let token = token_with_bootstrap(Vec::new())?;
        let result = control_plane_join_url(&token, None);

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn join_urls_reject_unusable_control_plane_endpoints() -> anyhow::Result<()> {
        let error = match token_with_bootstrap(vec![BootstrapEndpoint {
            url: "http://0.0.0.0:8443".to_string(),
            kind: BootstrapEndpointKind::ControlPlane,
        }]) {
            Ok(_) => panic!("unusable token control-plane bootstrap should fail before signing"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("does not match its control_plane service kind"));

        let token = token_with_bootstrap(Vec::new())?;
        let error = match control_plane_join_url(&token, Some("udp://127.0.0.1:8443")) {
            Ok(_) => panic!("non-HTTP control-plane override should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("control-plane URL"));
        assert!(error.to_string().contains("must use http or https"));
        Ok(())
    }

    #[test]
    fn token_revoke_url_trims_control_plane_base_url() -> anyhow::Result<()> {
        assert_eq!(
            control_plane_token_revoke_url("http://127.0.0.1:8443/")?,
            "http://127.0.0.1:8443/v1/tokens/revoke"
        );
        let error = match control_plane_token_revoke_url("http://0.0.0.0:8443") {
            Ok(_) => anyhow::bail!("unusable control-plane revoke URL should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("control-plane URL"));
        assert!(error.to_string().contains("usable non-unspecified"));
        Ok(())
    }

    #[test]
    fn token_revocation_request_requires_and_uses_existing_issuer_key() -> anyhow::Result<()> {
        let issuer = IdentityKeyPair::generate();
        let signed_at = Utc::now();
        let args = TokenRevokeArgs {
            control_plane_url: "http://127.0.0.1:8443".to_string(),
            cluster_id: "cluster-a".to_string(),
            nonce: "token-nonce".to_string(),
            issuer_key_id: "root".to_string(),
            issuer_private_key_b64: Some(issuer.signing_key_b64()),
            issuer_private_key_path: None,
        };

        let request = token_revocation_request(&args, signed_at)?;
        assert_eq!(request.cluster_id, ClusterId::from_string("cluster-a"));
        assert_eq!(request.nonce, "token-nonce");
        assert_eq!(request.issuer, issuer.node_id());
        assert_eq!(request.key_id, KeyId::from_string("root"));
        assert_eq!(
            request
                .issuer_signature
                .as_ref()
                .map(|signature| signature.signed_at),
            Some(signed_at)
        );
        ipars_crypto::verify_token_revocation_signature(&request, &issuer.public_key_b64())?;

        let missing_key = TokenRevokeArgs {
            issuer_private_key_b64: None,
            ..args
        };
        let error = match token_revocation_request(&missing_key, signed_at) {
            Ok(_) => anyhow::bail!("unsigned token revocation request should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("requires --issuer-private-key-b64 or --issuer-private-key-path"));
        Ok(())
    }

    #[test]
    fn token_create_uses_supplied_issuer_key_and_key_id() -> anyhow::Result<()> {
        let issuer = IdentityKeyPair::generate();
        let token = create_token(TokenCreateArgs {
            cluster_id: Some("cluster-a".to_string()),
            issuer_key_id: "join-2026q3".to_string(),
            issuer_private_key_b64: Some(issuer.signing_key_b64()),
            issuer_private_key_path: None,
            role: "edge".to_string(),
            tags: vec!["edge".to_string()],
            allowed_routes: vec!["10.42.0.0/16".parse()?],
            ttl_seconds: 300,
            bootstrap_endpoints: vec!["https://203.0.113.10:8443".to_string()],
            control_plane_bootstrap_endpoints: Vec::new(),
            signal_bootstrap_endpoints: Vec::new(),
            stun_bootstrap_endpoints: Vec::new(),
            relay_bootstrap_endpoints: Vec::new(),
            allow_relay: true,
            max_uses: Some(7),
            unlimited_uses: false,
        })?;

        assert_eq!(token.claims.issuer, issuer.node_id());
        assert_eq!(token.claims.key_id, KeyId::from_string("join-2026q3"));
        assert!(token.claims.policy.allow_relay);
        assert_eq!(
            token.claims.policy.allowed_routes,
            vec!["10.42.0.0/16".parse()?]
        );
        assert_eq!(token.claims.policy.max_token_uses, Some(7));
        verify_join_token(
            &token,
            &issuer.public_key_b64(),
            Utc::now(),
            &ClusterId::from_string("cluster-a"),
        )?;
        Ok(())
    }

    #[test]
    fn token_create_rejects_invalid_claim_inputs() -> anyhow::Result<()> {
        fn token_args(issuer: &IdentityKeyPair) -> TokenCreateArgs {
            TokenCreateArgs {
                cluster_id: Some("cluster-a".to_string()),
                issuer_key_id: "root".to_string(),
                issuer_private_key_b64: Some(issuer.signing_key_b64()),
                issuer_private_key_path: None,
                role: "edge".to_string(),
                tags: Vec::new(),
                allowed_routes: Vec::new(),
                ttl_seconds: 300,
                bootstrap_endpoints: vec!["https://203.0.113.10:8443".to_string()],
                control_plane_bootstrap_endpoints: Vec::new(),
                signal_bootstrap_endpoints: Vec::new(),
                stun_bootstrap_endpoints: Vec::new(),
                relay_bootstrap_endpoints: Vec::new(),
                allow_relay: false,
                max_uses: Some(1),
                unlimited_uses: false,
            }
        }

        let issuer = IdentityKeyPair::generate();
        let oversized_identifier = "x".repeat(MAX_JOIN_TOKEN_IDENTIFIER_BYTES + 1);
        let too_many_tags = (0..=MAX_JOIN_TOKEN_TAGS)
            .map(|index| format!("tag-{index}"))
            .collect::<Vec<_>>();
        let too_many_routes = (0..=MAX_JOIN_TOKEN_ALLOWED_ROUTES)
            .map(|index| format!("10.0.{}.{}/32", index / 256, index % 256).parse::<ipnet::IpNet>())
            .collect::<Result<Vec<_>, _>>()?;
        let cases = vec![
            (
                TokenCreateArgs {
                    cluster_id: Some("bad/cluster".to_string()),
                    ..token_args(&issuer)
                },
                "--cluster-id must contain only ASCII letters, digits, '_', '.' or '-'".to_string(),
            ),
            (
                TokenCreateArgs {
                    issuer_key_id: oversized_identifier,
                    ..token_args(&issuer)
                },
                format!(
                    "--issuer-key-id exceeds {MAX_JOIN_TOKEN_IDENTIFIER_BYTES} bytes"
                ),
            ),
            (
                TokenCreateArgs {
                    role: "edge role".to_string(),
                    ..token_args(&issuer)
                },
                "--role must contain only ASCII letters, digits, '_', '.' or '-'".to_string(),
            ),
            (
                TokenCreateArgs {
                    tags: vec!["edge/tag".to_string()],
                    ..token_args(&issuer)
                },
                "--tag must contain only ASCII letters, digits, '_', '.' or '-'".to_string(),
            ),
            (
                TokenCreateArgs {
                    tags: too_many_tags,
                    ..token_args(&issuer)
                },
                format!("--tag may be repeated at most {MAX_JOIN_TOKEN_TAGS} times"),
            ),
            (
                TokenCreateArgs {
                    ttl_seconds: 0,
                    ..token_args(&issuer)
                },
                "join token TTL must be greater than zero seconds".to_string(),
            ),
            (
                TokenCreateArgs {
                    ttl_seconds: MAX_JOIN_TOKEN_TTL_SECONDS + 1,
                    ..token_args(&issuer)
                },
                format!("join token TTL must not exceed {MAX_JOIN_TOKEN_TTL_SECONDS} seconds"),
            ),
            (
                TokenCreateArgs {
                    allowed_routes: vec!["0.0.0.0/0".parse()?],
                    ..token_args(&issuer)
                },
                "--allowed-route must not include unrestricted join-token allowed route 0.0.0.0/0"
                    .to_string(),
            ),
            (
                TokenCreateArgs {
                    allowed_routes: vec!["10.42.0.1/24".parse()?],
                    ..token_args(&issuer)
                },
                "--allowed-route must use canonical join-token allowed route 10.42.0.0/24, not 10.42.0.1/24"
                    .to_string(),
            ),
            (
                TokenCreateArgs {
                    allowed_routes: vec![
                        "10.42.0.0/16".parse()?,
                        "10.42.0.0/16".parse()?,
                    ],
                    ..token_args(&issuer)
                },
                "--allowed-route must not repeat join-token allowed route 10.42.0.0/16"
                    .to_string(),
            ),
            (
                TokenCreateArgs {
                    allowed_routes: vec![
                        "10.42.0.0/16".parse()?,
                        "10.42.1.0/24".parse()?,
                    ],
                    ..token_args(&issuer)
                },
                "--allowed-route must not include overlapping join-token allowed routes 10.42.0.0/16 and 10.42.1.0/24"
                    .to_string(),
            ),
            (
                TokenCreateArgs {
                    allowed_routes: too_many_routes,
                    ..token_args(&issuer)
                },
                format!("--allowed-route may be repeated at most {MAX_JOIN_TOKEN_ALLOWED_ROUTES} times"),
            ),
        ];

        for (args, expected) in cases {
            let error = match create_token(args) {
                Ok(token) => anyhow::bail!("unexpected valid token: {token:?}"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(&expected),
                "expected {expected}, got {error}"
            );
        }
        Ok(())
    }

    #[test]
    fn init_rejects_invalid_default_token_claim_inputs() -> anyhow::Result<()> {
        let error = match init(InitArgs {
            default_role: "edge role".to_string(),
            ..valid_init_args()
        }) {
            Ok(output) => anyhow::bail!("unexpected valid init output: {output:?}"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--role must contain only ASCII letters"));

        let error = match init(InitArgs {
            allowed_routes: vec!["0.0.0.0/0".parse()?],
            ..valid_init_args()
        }) {
            Ok(output) => anyhow::bail!("unexpected valid init output: {output:?}"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--allowed-route must not include unrestricted"));
        Ok(())
    }

    #[test]
    fn token_create_accepts_typed_bootstrap_endpoints() -> anyhow::Result<()> {
        let issuer = IdentityKeyPair::generate();
        let token = create_token(TokenCreateArgs {
            cluster_id: Some("cluster-a".to_string()),
            issuer_key_id: "root".to_string(),
            issuer_private_key_b64: Some(issuer.signing_key_b64()),
            issuer_private_key_path: None,
            role: "edge".to_string(),
            tags: Vec::new(),
            allowed_routes: Vec::new(),
            ttl_seconds: 300,
            bootstrap_endpoints: vec!["https://203.0.113.10:8443".to_string()],
            control_plane_bootstrap_endpoints: vec!["https://203.0.113.11:8443".to_string()],
            signal_bootstrap_endpoints: vec!["https://203.0.113.10:9443".to_string()],
            stun_bootstrap_endpoints: vec!["udp://203.0.113.10:3478".to_string()],
            relay_bootstrap_endpoints: vec!["udp://203.0.113.10:51820".to_string()],
            allow_relay: false,
            max_uses: Some(1),
            unlimited_uses: false,
        })?;

        assert_eq!(
            token.claims.bootstrap_endpoints,
            vec![
                BootstrapEndpoint {
                    url: "https://203.0.113.10:8443".to_string(),
                    kind: BootstrapEndpointKind::ControlPlane,
                },
                BootstrapEndpoint {
                    url: "https://203.0.113.11:8443".to_string(),
                    kind: BootstrapEndpointKind::ControlPlane,
                },
                BootstrapEndpoint {
                    url: "https://203.0.113.10:9443".to_string(),
                    kind: BootstrapEndpointKind::Signal,
                },
                BootstrapEndpoint {
                    url: "udp://203.0.113.10:3478".to_string(),
                    kind: BootstrapEndpointKind::Stun,
                },
                BootstrapEndpoint {
                    url: "udp://203.0.113.10:51820".to_string(),
                    kind: BootstrapEndpointKind::Relay,
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn token_create_rejects_unbounded_or_duplicate_bootstrap_endpoints() {
        let control_plane_bootstrap_endpoints = (0
            ..=ipars_types::MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND)
            .map(|index| format!("https://control-{index}.example:8443"))
            .collect();
        let args = TokenCreateArgs {
            cluster_id: Some("cluster-a".to_string()),
            issuer_key_id: "root".to_string(),
            issuer_private_key_b64: None,
            issuer_private_key_path: None,
            role: "edge".to_string(),
            tags: Vec::new(),
            allowed_routes: Vec::new(),
            ttl_seconds: 300,
            bootstrap_endpoints: Vec::new(),
            control_plane_bootstrap_endpoints,
            signal_bootstrap_endpoints: Vec::new(),
            stun_bootstrap_endpoints: Vec::new(),
            relay_bootstrap_endpoints: Vec::new(),
            allow_relay: false,
            max_uses: Some(1),
            unlimited_uses: false,
        };
        let error = match token_create_bootstrap_endpoints(&args) {
            Ok(_) => panic!("unbounded control-plane bootstrap set should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("endpoint count 9 exceeds maximum 8"));

        let duplicate = TokenCreateArgs {
            control_plane_bootstrap_endpoints: vec![
                "https://control.example:8443".to_string(),
                "https://control.example:8443/".to_string(),
            ],
            ..args
        };
        let error = match token_create_bootstrap_endpoints(&duplicate) {
            Ok(_) => panic!("normalized duplicate bootstrap should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("duplicates"));
    }

    #[test]
    fn token_policy_flags_parse_from_cli() -> anyhow::Result<()> {
        let init = Cli::try_parse_from([
            "ipars",
            "init",
            "--public-endpoint",
            "203.0.113.10:51820",
            "--allowed-route",
            "10.43.0.0/16",
            "--allow-relay",
            "--unlimited-uses",
        ])?;
        if let Command::Init(args) = init.command {
            assert_eq!(args.allowed_routes, vec!["10.43.0.0/16".parse()?]);
            assert!(args.allow_relay);
            assert!(args.unlimited_uses);
        } else {
            anyhow::bail!("expected init command");
        }

        let token = Cli::try_parse_from([
            "ipars",
            "token",
            "create",
            "--allowed-route",
            "10.42.0.0/16",
            "--max-uses",
            "7",
            "--bootstrap",
            "https://203.0.113.10:8443",
            "--control-plane-bootstrap",
            "https://203.0.113.11:8443",
            "--signal-bootstrap",
            "https://203.0.113.10:9443",
            "--stun-bootstrap",
            "udp://203.0.113.10:3478",
            "--relay-bootstrap",
            "udp://203.0.113.10:51820",
        ])?;
        if let Command::Token {
            command: TokenCommand::Create(args),
        } = token.command
        {
            assert_eq!(args.allowed_routes, vec!["10.42.0.0/16".parse()?]);
            assert_eq!(args.max_uses, Some(7));
            assert!(!args.unlimited_uses);
            assert_eq!(
                token_create_bootstrap_endpoints(&args)?,
                vec![
                    BootstrapEndpoint {
                        url: "https://203.0.113.10:8443".to_string(),
                        kind: BootstrapEndpointKind::ControlPlane,
                    },
                    BootstrapEndpoint {
                        url: "https://203.0.113.11:8443".to_string(),
                        kind: BootstrapEndpointKind::ControlPlane,
                    },
                    BootstrapEndpoint {
                        url: "https://203.0.113.10:9443".to_string(),
                        kind: BootstrapEndpointKind::Signal,
                    },
                    BootstrapEndpoint {
                        url: "udp://203.0.113.10:3478".to_string(),
                        kind: BootstrapEndpointKind::Stun,
                    },
                    BootstrapEndpoint {
                        url: "udp://203.0.113.10:51820".to_string(),
                        kind: BootstrapEndpointKind::Relay,
                    },
                ]
            );
            return Ok(());
        }

        anyhow::bail!("expected token create command")
    }

    #[test]
    fn token_create_rejects_bootstrap_endpoint_scheme_mismatches() -> anyhow::Result<()> {
        let http_for_stun = TokenCreateArgs {
            cluster_id: None,
            issuer_key_id: "root".to_string(),
            issuer_private_key_b64: None,
            issuer_private_key_path: None,
            role: "edge".to_string(),
            tags: Vec::new(),
            allowed_routes: Vec::new(),
            ttl_seconds: 300,
            bootstrap_endpoints: Vec::new(),
            control_plane_bootstrap_endpoints: Vec::new(),
            signal_bootstrap_endpoints: Vec::new(),
            stun_bootstrap_endpoints: vec!["https://203.0.113.10:3478".to_string()],
            relay_bootstrap_endpoints: Vec::new(),
            allow_relay: false,
            max_uses: Some(1),
            unlimited_uses: false,
        };
        let Err(error) = token_create_bootstrap_endpoints(&http_for_stun) else {
            anyhow::bail!("http STUN bootstrap should be rejected");
        };
        let error = error.to_string();
        assert!(error.contains("--stun-bootstrap"));
        assert!(error.contains("must use udp"));

        let udp_for_signal = TokenCreateArgs {
            signal_bootstrap_endpoints: vec!["udp://203.0.113.10:9443".to_string()],
            stun_bootstrap_endpoints: Vec::new(),
            ..http_for_stun
        };
        let Err(error) = token_create_bootstrap_endpoints(&udp_for_signal) else {
            anyhow::bail!("udp signal bootstrap should be rejected");
        };
        let error = error.to_string();
        assert!(error.contains("--signal-bootstrap"));
        assert!(error.contains("must use http or https"));
        Ok(())
    }

    #[test]
    fn token_create_rejects_unusable_bootstrap_addresses() -> anyhow::Result<()> {
        fn token_args() -> TokenCreateArgs {
            TokenCreateArgs {
                cluster_id: None,
                issuer_key_id: "root".to_string(),
                issuer_private_key_b64: None,
                issuer_private_key_path: None,
                role: "edge".to_string(),
                tags: Vec::new(),
                allowed_routes: Vec::new(),
                ttl_seconds: 300,
                bootstrap_endpoints: Vec::new(),
                control_plane_bootstrap_endpoints: Vec::new(),
                signal_bootstrap_endpoints: Vec::new(),
                stun_bootstrap_endpoints: Vec::new(),
                relay_bootstrap_endpoints: Vec::new(),
                allow_relay: false,
                max_uses: Some(1),
                unlimited_uses: false,
            }
        }

        let http_unspecified = TokenCreateArgs {
            bootstrap_endpoints: vec!["https://0.0.0.0:8443".to_string()],
            ..token_args()
        };
        let Err(error) = token_create_bootstrap_endpoints(&http_unspecified) else {
            anyhow::bail!("unspecified HTTP bootstrap should be rejected");
        };
        let error = error.to_string();
        assert!(error.contains("--bootstrap/--control-plane-bootstrap"));
        assert!(error.contains("usable nonzero"));

        let http_zero_port = TokenCreateArgs {
            signal_bootstrap_endpoints: vec!["https://203.0.113.10:0".to_string()],
            ..token_args()
        };
        let Err(error) = token_create_bootstrap_endpoints(&http_zero_port) else {
            anyhow::bail!("port-zero signal bootstrap should be rejected");
        };
        let error = error.to_string();
        assert!(error.contains("--signal-bootstrap"));
        assert!(error.contains("usable nonzero"));

        let http_domain_zero_port = TokenCreateArgs {
            control_plane_bootstrap_endpoints: vec!["https://control.example:0".to_string()],
            ..token_args()
        };
        let Err(error) = token_create_bootstrap_endpoints(&http_domain_zero_port) else {
            anyhow::bail!("port-zero domain control-plane bootstrap should be rejected");
        };
        let error = error.to_string();
        assert!(error.contains("--control-plane-bootstrap"));
        assert!(error.contains("nonzero port"));

        let udp_multicast = TokenCreateArgs {
            stun_bootstrap_endpoints: vec!["udp://224.0.0.1:3478".to_string()],
            ..token_args()
        };
        let Err(error) = token_create_bootstrap_endpoints(&udp_multicast) else {
            anyhow::bail!("multicast STUN bootstrap should be rejected");
        };
        let error = error.to_string();
        assert!(error.contains("--stun-bootstrap"));
        assert!(error.contains("usable nonzero"));

        let udp_zero_port = TokenCreateArgs {
            relay_bootstrap_endpoints: vec!["udp://203.0.113.10:0".to_string()],
            ..token_args()
        };
        let Err(error) = token_create_bootstrap_endpoints(&udp_zero_port) else {
            anyhow::bail!("port-zero relay bootstrap should be rejected");
        };
        let error = error.to_string();
        assert!(error.contains("--relay-bootstrap"));
        assert!(error.contains("usable nonzero"));

        Ok(())
    }

    #[test]
    fn init_rejects_unusable_bootstrap_generation_inputs() {
        let mut unusable_public = valid_init_args();
        unusable_public.public_endpoint = SocketAddr::from(([0, 0, 0, 0], 51820));
        let Err(error) = init(unusable_public) else {
            panic!("unspecified public endpoint should fail");
        };
        assert!(error.to_string().contains("--public-endpoint"));
        assert!(error.to_string().contains("usable nonzero"));

        let mut zero_control = valid_init_args();
        zero_control.control_plane_listen = SocketAddr::from(([0, 0, 0, 0], 0));
        let Err(error) = init(zero_control) else {
            panic!("port-zero control-plane listen should fail");
        };
        assert!(error.to_string().contains("--control-plane-listen"));
        assert!(error
            .to_string()
            .contains("nonzero port for bootstrap token generation"));

        let mut zero_signal = valid_init_args();
        zero_signal.signal_listen = SocketAddr::from(([0, 0, 0, 0], 0));
        let Err(error) = init(zero_signal) else {
            panic!("port-zero signal listen should fail");
        };
        assert!(error.to_string().contains("--signal-listen"));
        assert!(error
            .to_string()
            .contains("nonzero port for bootstrap token generation"));

        let mut zero_stun = valid_init_args();
        zero_stun.stun_listen = SocketAddr::from(([0, 0, 0, 0], 0));
        let Err(error) = init(zero_stun) else {
            panic!("port-zero STUN listen should fail");
        };
        assert!(error.to_string().contains("--stun-listen"));
        assert!(error
            .to_string()
            .contains("nonzero port for bootstrap token generation"));

        let mut zero_relay_http = valid_init_args();
        zero_relay_http.relay_http_listen = SocketAddr::from(([0, 0, 0, 0], 0));
        let Err(error) = init(zero_relay_http) else {
            panic!("port-zero relay HTTP listen should fail");
        };
        assert!(error.to_string().contains("--relay-http-listen"));
        assert!(error
            .to_string()
            .contains("nonzero port when --relay-admission-url is omitted"));

        let mut explicit_admission = valid_init_args();
        explicit_admission.relay_http_listen = SocketAddr::from(([0, 0, 0, 0], 0));
        explicit_admission.relay_admission_url = Some("http://relay.example.test:9580".to_string());
        assert!(init(explicit_admission).is_ok());
    }

    #[test]
    fn init_bootstrap_urls_use_service_ports_and_bracket_ipv6() -> anyhow::Result<()> {
        let mut args = valid_init_args();
        args.public_endpoint = "[2001:db8::10]:51820".parse()?;
        let endpoints = bootstrap_from_public_endpoint(&args);

        assert_eq!(
            endpoints
                .iter()
                .map(|endpoint| endpoint.url.as_str())
                .collect::<Vec<_>>(),
            vec![
                "http://[2001:db8::10]:8443",
                "http://[2001:db8::10]:9443",
                "udp://[2001:db8::10]:3478",
                "udp://[2001:db8::10]:51820",
            ]
        );
        Ok(())
    }

    #[test]
    fn init_can_persist_generated_issuer_key() -> anyhow::Result<()> {
        let key_path = temp_path("issuer.key");
        let output = init(InitArgs {
            public_endpoint: SocketAddr::from(([203, 0, 113, 10], 51820)),
            bootstrap_scheme: "http".to_string(),
            issuer_key_id: "root".to_string(),
            issuer_private_key_b64: None,
            issuer_private_key_path: Some(key_path.clone()),
            emit_issuer_private_key: false,
            token_ttl_seconds: 300,
            default_role: "edge".to_string(),
            tags: Vec::new(),
            allowed_routes: vec!["10.43.0.0/16".parse()?],
            allow_relay: true,
            max_uses: None,
            unlimited_uses: true,
            spawn_daemons: false,
            daemon_binary: PathBuf::from("iparsd"),
            daemon_state_dir: temp_path("state"),
            control_plane_listen: SocketAddr::from(([0, 0, 0, 0], 8443)),
            control_plane_database_url: None,
            control_plane_operator_api_bearer_token_path: None,
            signal_listen: SocketAddr::from(([0, 0, 0, 0], 9443)),
            stun_listen: SocketAddr::from(([0, 0, 0, 0], 3478)),
            stun_alternate_listen: None,
            stun_http_listen: SocketAddr::from(([0, 0, 0, 0], 3479)),
            relay_udp_listen: SocketAddr::from(([0, 0, 0, 0], 51820)),
            relay_http_listen: SocketAddr::from(([0, 0, 0, 0], 9580)),
            relay_admission_url: None,
        })?;

        assert_eq!(output.issuer_private_key_path, Some(key_path.clone()));
        assert!(output.issuer_private_key_b64.is_none());
        let restored =
            IdentityKeyPair::from_signing_key_b64(std::fs::read_to_string(&key_path)?.trim())?;
        assert_eq!(output.issuer_node_id, restored.node_id());
        assert_eq!(output.issuer_public_key, restored.public_key_b64());
        assert_eq!(
            output.join_token.claims.policy.allowed_routes,
            vec!["10.43.0.0/16".parse()?]
        );
        assert_eq!(output.join_token.claims.policy.max_token_uses, None);
        assert!(output.join_token.claims.policy.allow_relay);
        verify_join_token(
            &output.join_token,
            &output.issuer_public_key,
            Utc::now(),
            &output.cluster_id,
        )?;
        let _ = std::fs::remove_file(key_path);
        Ok(())
    }

    #[test]
    fn issuer_private_key_path_loads_regular_files_and_rejects_unsafe_paths() -> anyhow::Result<()>
    {
        let key = IdentityKeyPair::generate();
        let key_path = temp_path("issuer-existing.key");
        std::fs::write(&key_path, format!("{}\n", key.signing_key_b64()))?;
        let restored = issuer_key_from_path(&key_path, MissingIssuerPath::GenerateEphemeral)?;
        assert_eq!(restored.node_id(), key.node_id());
        let _ = std::fs::remove_file(&key_path);

        let dir_path = temp_path("issuer-key-dir");
        std::fs::create_dir_all(&dir_path)?;
        let Err(error) = issuer_key_from_path(&dir_path, MissingIssuerPath::GenerateEphemeral)
        else {
            anyhow::bail!("directory issuer private key path should be rejected");
        };
        assert!(format!("{error:#}").contains("must be a regular file"));
        let _ = std::fs::remove_dir_all(&dir_path);

        let oversized_path = temp_path("issuer-oversized.key");
        std::fs::write(
            &oversized_path,
            vec![b'a'; MAX_ISSUER_PRIVATE_KEY_FILE_BYTES as usize + 1],
        )?;
        let Err(error) =
            issuer_key_from_path(&oversized_path, MissingIssuerPath::GenerateEphemeral)
        else {
            anyhow::bail!("oversized issuer private key path should be rejected");
        };
        assert!(format!("{error:#}").contains("exceeds maximum size"));
        let _ = std::fs::remove_file(&oversized_path);

        #[cfg(unix)]
        {
            let target_path = temp_path("issuer-target.key");
            let link_path = temp_path("issuer-link.key");
            let target_key = IdentityKeyPair::generate();
            std::fs::write(&target_path, format!("{}\n", target_key.signing_key_b64()))?;
            std::os::unix::fs::symlink(&target_path, &link_path)?;
            let Err(error) = issuer_key_from_path(&link_path, MissingIssuerPath::GenerateEphemeral)
            else {
                anyhow::bail!("symlink issuer private key path should be rejected");
            };
            assert!(format!("{error:#}").contains("must not be a symlink"));
            let _ = std::fs::remove_file(&link_path);
            let _ = std::fs::remove_file(&target_path);
        }

        Ok(())
    }

    #[test]
    fn init_outputs_daemon_commands_for_bootstrap_services() -> anyhow::Result<()> {
        let key_path = temp_path("issuer-bootstrap.key");
        let operator_token_path = temp_path("control-plane-operator-api.token");
        std::fs::write(
            &operator_token_path,
            "control-plane-operator-secret-with-32-bytes\n",
        )?;
        let state_dir = temp_path("bootstrap-state");
        let output = init(InitArgs {
            public_endpoint: SocketAddr::from(([203, 0, 113, 10], 51820)),
            bootstrap_scheme: "http".to_string(),
            issuer_key_id: "root".to_string(),
            issuer_private_key_b64: None,
            issuer_private_key_path: Some(key_path.clone()),
            emit_issuer_private_key: false,
            token_ttl_seconds: 300,
            default_role: "edge".to_string(),
            tags: Vec::new(),
            allowed_routes: Vec::new(),
            allow_relay: true,
            max_uses: Some(10),
            unlimited_uses: false,
            spawn_daemons: false,
            daemon_binary: PathBuf::from("iparsd"),
            daemon_state_dir: state_dir.clone(),
            control_plane_listen: "127.0.0.1:18443".parse()?,
            control_plane_database_url: None,
            control_plane_operator_api_bearer_token_path: Some(operator_token_path.clone()),
            signal_listen: "127.0.0.1:19443".parse()?,
            stun_listen: "0.0.0.0:13478".parse()?,
            stun_alternate_listen: Some("127.0.0.1:13480".parse()?),
            stun_http_listen: "127.0.0.1:13479".parse()?,
            relay_udp_listen: "0.0.0.0:15182".parse()?,
            relay_http_listen: "127.0.0.1:19580".parse()?,
            relay_admission_url: None,
        })?;

        assert!(output.daemon_processes.is_empty());
        assert_eq!(output.daemon_commands.len(), 4);
        assert_eq!(
            output
                .join_token
                .claims
                .bootstrap_endpoints
                .iter()
                .find(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
                .map(|endpoint| endpoint.url.as_str()),
            Some("http://203.0.113.10:18443")
        );
        assert_eq!(
            output
                .join_token
                .claims
                .bootstrap_endpoints
                .iter()
                .find(|endpoint| endpoint.kind == BootstrapEndpointKind::Signal)
                .map(|endpoint| endpoint.url.as_str()),
            Some("http://203.0.113.10:19443")
        );
        assert_eq!(
            output
                .join_token
                .claims
                .bootstrap_endpoints
                .iter()
                .find(|endpoint| endpoint.kind == BootstrapEndpointKind::Stun)
                .map(|endpoint| endpoint.url.as_str()),
            Some("udp://203.0.113.10:13478")
        );
        assert_eq!(
            output
                .join_token
                .claims
                .bootstrap_endpoints
                .iter()
                .find(|endpoint| endpoint.kind == BootstrapEndpointKind::Relay)
                .map(|endpoint| endpoint.url.as_str()),
            Some("udp://203.0.113.10:51820")
        );

        let control_plane = output
            .daemon_commands
            .iter()
            .find(|command| command.service == "control-plane")
            .context("expected control-plane daemon command")?;
        assert_eq!(
            control_plane.log_path,
            state_dir.join("logs").join("control-plane.log")
        );
        assert!(control_plane.command.contains(&"control-plane".to_string()));
        assert!(control_plane
            .command
            .contains(&output.cluster_id.as_str().to_string()));
        assert!(control_plane
            .command
            .contains(&output.issuer_public_key.to_string()));
        assert!(control_plane.command.iter().any(|value| {
            value.starts_with("sqlite://") && value.ends_with("control-plane.sqlite?mode=rwc")
        }));
        assert!(control_plane
            .command
            .contains(&"--operator-api-bearer-token-path".to_string()));
        assert!(control_plane
            .command
            .contains(&operator_token_path.display().to_string()));
        assert_eq!(
            output.control_plane_operator_api_bearer_token_path.as_ref(),
            Some(&operator_token_path)
        );

        let stun = output
            .daemon_commands
            .iter()
            .find(|command| command.service == "stun")
            .context("expected stun daemon command")?;
        assert!(stun.command.contains(&"stun".to_string()));
        assert!(stun.command.contains(&"0.0.0.0:13478".to_string()));
        assert!(stun.command.contains(&"127.0.0.1:13480".to_string()));
        assert!(stun.command.contains(&"127.0.0.1:13479".to_string()));

        let relay = output
            .daemon_commands
            .iter()
            .find(|command| command.service == "relay")
            .context("expected relay daemon command")?;
        assert!(relay.command.contains(&"relay".to_string()));
        assert!(relay.command.contains(&"203.0.113.10:51820".to_string()));
        assert!(relay
            .command
            .contains(&"http://203.0.113.10:19580".to_string()));

        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(operator_token_path);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn init_spawn_paths_are_owner_only_and_reject_linked_logs() -> anyhow::Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let state_dir = temp_path("spawn-state-hardening");
        let log_dir = state_dir.join("logs");
        prepare_init_daemon_directory(&state_dir, "daemon state dir")?;
        prepare_init_daemon_directory(&log_dir, "daemon log dir")?;

        assert_eq!(
            std::fs::metadata(&state_dir)?.permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&log_dir)?.permissions().mode() & 0o777,
            0o700
        );

        let log_path = log_dir.join("control-plane.log");
        let mut log = open_init_daemon_log(&log_path)?;
        writeln!(&mut log, "bootstrap log")?;
        drop(log);
        let log_metadata = std::fs::metadata(&log_path)?;
        assert_eq!(log_metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(log_metadata.nlink(), 1);

        let symlink_target = log_dir.join("symlink-target.log");
        std::fs::write(&symlink_target, b"target\n")?;
        let symlink_path = log_dir.join("symlink.log");
        std::os::unix::fs::symlink(&symlink_target, &symlink_path)?;
        let symlink_error = match open_init_daemon_log(&symlink_path) {
            Ok(_) => anyhow::bail!("symlinked daemon log should be rejected"),
            Err(error) => error,
        };
        assert!(symlink_error.to_string().contains("must not be a symlink"));

        let symlink_dir_target = temp_path("spawn-state-target");
        std::fs::create_dir_all(&symlink_dir_target)?;
        let symlink_dir = temp_path("spawn-state-link");
        std::os::unix::fs::symlink(&symlink_dir_target, &symlink_dir)?;
        let dir_error = match prepare_init_daemon_directory(&symlink_dir, "daemon state dir") {
            Ok(()) => anyhow::bail!("symlinked daemon state dir should be rejected"),
            Err(error) => error,
        };
        assert!(dir_error.to_string().contains("must not be a symlink"));

        let hard_target = log_dir.join("hard-target.log");
        let hard_link = log_dir.join("hard-link.log");
        std::fs::write(&hard_target, b"hard\n")?;
        std::fs::hard_link(&hard_target, &hard_link)?;
        let hard_error = match open_init_daemon_log(&hard_target) {
            Ok(_) => anyhow::bail!("multi-linked daemon log should be rejected"),
            Err(error) => error,
        };
        assert!(hard_error
            .to_string()
            .contains("must not have multiple hard links"));

        let _ = std::fs::remove_dir_all(&state_dir);
        let _ = std::fs::remove_dir_all(&symlink_dir_target);
        let _ = std::fs::remove_file(&symlink_dir);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn init_daemon_process_uses_sanitized_environment() -> anyhow::Result<()> {
        let temp_dir = temp_path("spawn-env-hardening");
        std::fs::create_dir_all(&temp_dir)?;
        let status_path = temp_dir.join("env.status");
        let status_arg = status_path.display().to_string();
        let shell_script = r#"
if test "${PATH:-}" = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" &&
   test "${LANG:-}" = "C" &&
   test "${LC_ALL:-}" = "C" &&
   test -z "${HOME+x}" &&
   test -z "${IPARS_ISSUER_PRIVATE_KEY+x}" &&
   test -z "${IPARS_ISSUER_PRIVATE_KEY_PATH+x}" &&
   test -z "${LD_PRELOAD+x}"; then
    printf 'ok\n' > "$1"
else
    {
        printf 'PATH=%s\n' "${PATH-<unset>}"
        printf 'LANG=%s\n' "${LANG-<unset>}"
        printf 'LC_ALL=%s\n' "${LC_ALL-<unset>}"
        printf 'HOME=%s\n' "${HOME-<unset>}"
        printf 'IPARS_ISSUER_PRIVATE_KEY=%s\n' "${IPARS_ISSUER_PRIVATE_KEY-<unset>}"
        printf 'IPARS_ISSUER_PRIVATE_KEY_PATH=%s\n' "${IPARS_ISSUER_PRIVATE_KEY_PATH-<unset>}"
        printf 'LD_PRELOAD=%s\n' "${LD_PRELOAD-<unset>}"
    } > "$1"
    exit 1
fi
"#;
        let mut command = ProcessCommand::new("/bin/sh");
        command
            .env("HOME", "/tmp/ipars-parent-home")
            .env("IPARS_ISSUER_PRIVATE_KEY", "secret-signing-key")
            .env("IPARS_ISSUER_PRIVATE_KEY_PATH", "/tmp/issuer.key")
            .env("LD_PRELOAD", "/tmp/injected.so");
        configure_init_daemon_process(&mut command);
        let status = command
            .arg("-c")
            .arg(shell_script)
            .arg("ipars-init-env")
            .arg(&status_arg)
            .status()
            .context("failed to run sanitized init daemon environment test child")?;
        let output = std::fs::read_to_string(&status_path)
            .with_context(|| format!("failed to read {}", status_path.display()))?;
        assert!(
            status.success(),
            "init daemon process inherited unexpected environment:\n{output}"
        );
        assert_eq!(output.trim(), "ok");
        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[test]
    fn api_url_trims_base_and_path_slashes() -> anyhow::Result<()> {
        assert_eq!(
            api_url("http://127.0.0.1:9780/", "/v1/status", "agent status")?,
            "http://127.0.0.1:9780/v1/status"
        );
        let error = match api_url("http://0.0.0.0:9780", "/v1/status", "agent status") {
            Ok(_) => anyhow::bail!("unusable API base URL should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("agent status URL"));
        assert!(error.to_string().contains("usable non-unspecified"));
        let error = match api_url(
            "http://127.0.0.1:9780?debug=true",
            "/v1/status",
            "agent status",
        ) {
            Ok(_) => anyhow::bail!("query-bearing API base URL should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("must not include a query or fragment"));
        Ok(())
    }

    #[test]
    fn local_status_defaults_match_daemon_http_listeners() -> anyhow::Result<()> {
        assert_eq!(defaulted_agent_url(None), "http://127.0.0.1:9780");
        assert_eq!(
            defaulted_agent_url(Some("http://127.0.0.1:19780")),
            "http://127.0.0.1:19780"
        );
        assert_eq!(
            api_url(defaulted_agent_url(None), "/v1/status", "agent status")?,
            "http://127.0.0.1:9780/v1/status"
        );
        assert_eq!(defaulted_relay_url(None), "http://127.0.0.1:9580");
        assert_eq!(
            defaulted_relay_url(Some("http://127.0.0.1:19580")),
            "http://127.0.0.1:19580"
        );
        assert_eq!(
            api_url(defaulted_relay_url(None), "/v1/status", "relay status")?,
            "http://127.0.0.1:9580/v1/status"
        );
        assert_eq!(DEFAULT_LOCAL_RELAY_UDP, "127.0.0.1:51820");
        assert_eq!(DEFAULT_LOCAL_STUN_UDP, "127.0.0.1:3478");
        Ok(())
    }

    #[test]
    fn agent_api_auth_accepts_global_inline_and_file_sources() -> anyhow::Result<()> {
        let token = "agent-api-secret-with-at-least-32-bytes";
        let cli = Cli::try_parse_from(["ipars", "status", "--agent-api-bearer-token", token])?;
        assert_eq!(cli.agent_api_bearer_token.as_deref(), Some(token));
        assert!(cli.agent_api_bearer_token_path.is_none());
        let auth = AgentApiAuth::from_sources(cli.agent_api_bearer_token, None)?;
        assert_eq!(auth.bearer_token(), Some(token));

        let path = temp_path("agent-api-token");
        std::fs::write(&path, format!("{token}\n"))?;
        let auth = AgentApiAuth::from_sources(None, Some(path.clone()))?;
        assert_eq!(auth.bearer_token(), Some(token));

        let error = match AgentApiAuth::from_sources(Some("too-short".to_string()), None) {
            Ok(_) => anyhow::bail!("short agent API bearer token should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("at least 32 bytes"));
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn control_plane_operator_api_auth_accepts_global_inline_and_file_sources() -> anyhow::Result<()>
    {
        let token = "control-plane-operator-secret-with-32-bytes";
        let cli = Cli::try_parse_from([
            "ipars",
            "status",
            "--control-plane-url",
            "http://127.0.0.1:8443",
            "--control-plane-operator-api-bearer-token",
            token,
        ])?;
        assert_eq!(
            cli.control_plane_operator_api_bearer_token.as_deref(),
            Some(token)
        );
        assert!(cli.control_plane_operator_api_bearer_token_path.is_none());
        let auth = ControlPlaneOperatorApiAuth::from_sources(
            cli.control_plane_operator_api_bearer_token,
            None,
        )?;
        assert_eq!(auth.bearer_token(), Some(token));

        let path = temp_path("control-plane-operator-api-token");
        std::fs::write(&path, format!("{token}\n"))?;
        let auth = ControlPlaneOperatorApiAuth::from_sources(None, Some(path.clone()))?;
        assert_eq!(auth.bearer_token(), Some(token));

        let error =
            match ControlPlaneOperatorApiAuth::from_sources(Some("too-short".to_string()), None) {
                Ok(_) => anyhow::bail!("short control-plane operator token should be rejected"),
                Err(error) => error,
            };
        assert!(error.to_string().contains("at least 32 bytes"));

        let cli = Cli::try_parse_from([
            "ipars",
            "init",
            "--public-endpoint",
            "203.0.113.10:51820",
            "--control-plane-operator-api-bearer-token-path",
            "/run/secrets/control-plane-operator-api.token",
        ])?;
        assert_eq!(
            cli.control_plane_operator_api_bearer_token_path.as_deref(),
            Some(Path::new("/run/secrets/control-plane-operator-api.token"))
        );
        let Command::Init(args) = cli.command else {
            anyhow::bail!("expected init command");
        };
        assert_eq!(
            args.control_plane_operator_api_bearer_token_path.as_deref(),
            Some(Path::new("/run/secrets/control-plane-operator-api.token"))
        );

        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn agent_api_client_sends_bearer_authorization() -> anyhow::Result<()> {
        let token = "agent-api-secret-with-at-least-32-bytes";
        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}".to_string();
        let (url, server, request_rx) = spawn_raw_http_response_with_request(response).await?;

        let body: serde_json::Value =
            get_json_with_bearer(&url, "/v1/status", "agent status", Some(token)).await?;
        assert_eq!(body, serde_json::json!({ "ok": true }));
        let request = String::from_utf8(request_rx.await?)?;
        assert!(request.contains(&format!("authorization: Bearer {token}\r\n")));
        server.await??;
        Ok(())
    }

    #[test]
    fn status_and_path_args_accept_agent_url() -> anyhow::Result<()> {
        let status =
            Cli::try_parse_from(["ipars", "status", "--agent-url", "http://127.0.0.1:9780"])?;
        if let Command::Status(args) = status.command {
            assert_eq!(args.agent_url.as_deref(), Some("http://127.0.0.1:9780"));
            assert_eq!(args.control_plane_url, None);
        } else {
            anyhow::bail!("expected status command");
        }

        let status = Cli::try_parse_from([
            "ipars",
            "status",
            "--control-plane-url",
            "http://127.0.0.1:8443",
        ])?;
        if let Command::Status(args) = status.command {
            assert_eq!(args.agent_url, None);
            assert_eq!(
                args.control_plane_url.as_deref(),
                Some("http://127.0.0.1:8443")
            );
        } else {
            anyhow::bail!("expected status command");
        }

        assert!(Cli::try_parse_from([
            "ipars",
            "status",
            "--agent-url",
            "http://127.0.0.1:9780",
            "--control-plane-url",
            "http://127.0.0.1:8443",
        ])
        .is_err());

        let path = Cli::try_parse_from([
            "ipars",
            "path",
            "status",
            "--agent-url",
            "http://127.0.0.1:9780",
        ])?;
        if let Command::Path {
            command: PathCommand::Status(args),
        } = path.command
        {
            assert_eq!(args.agent_url.as_deref(), Some("http://127.0.0.1:9780"));
            assert_eq!(args.control_plane_url, None);
        } else {
            anyhow::bail!("expected path status command");
        }

        let path = Cli::try_parse_from([
            "ipars",
            "path",
            "status",
            "--control-plane-url",
            "http://127.0.0.1:8443",
            "--node-id",
            "node-a",
        ])?;
        if let Command::Path {
            command: PathCommand::Status(args),
        } = path.command
        {
            assert_eq!(args.agent_url, None);
            assert_eq!(
                args.control_plane_url.as_deref(),
                Some("http://127.0.0.1:8443")
            );
            assert_eq!(args.node_id.as_deref(), Some("node-a"));
        } else {
            anyhow::bail!("expected path status command");
        }

        assert!(Cli::try_parse_from([
            "ipars",
            "path",
            "status",
            "--agent-url",
            "http://127.0.0.1:9780",
            "--control-plane-url",
            "http://127.0.0.1:8443",
            "--node-id",
            "node-a",
        ])
        .is_err());

        let events = Cli::try_parse_from([
            "ipars",
            "path",
            "events",
            "--agent-url",
            "http://127.0.0.1:9780",
        ])?;
        if let Command::Path {
            command: PathCommand::Events(args),
        } = events.command
        {
            assert_eq!(args.agent_url.as_deref(), Some("http://127.0.0.1:9780"));
        } else {
            anyhow::bail!("expected path events command");
        }

        let activity = Cli::try_parse_from([
            "ipars",
            "path",
            "activity",
            "--agent-url",
            "http://127.0.0.1:9780",
            "--peer",
            "peer-a",
        ])?;
        if let Command::Path {
            command: PathCommand::Activity(args),
        } = activity.command
        {
            assert_eq!(args.agent_url.as_deref(), Some("http://127.0.0.1:9780"));
            return Ok(());
        }

        anyhow::bail!("expected path activity command")
    }

    #[test]
    fn key_and_node_args_accept_agent_and_control_plane_urls() -> anyhow::Result<()> {
        let key = Cli::try_parse_from([
            "ipars",
            "key",
            "rotate",
            "--agent-url",
            "http://127.0.0.1:19780",
            "--control-plane-url",
            "http://127.0.0.1:8443",
        ])?;
        let Command::Key {
            command: KeyCommand::Rotate(args),
        } = key.command
        else {
            anyhow::bail!("expected key rotate command");
        };
        assert_eq!(args.agent_url.as_deref(), Some("http://127.0.0.1:19780"));
        assert_eq!(
            args.control_plane_url.as_deref(),
            Some("http://127.0.0.1:8443")
        );

        let node = Cli::try_parse_from([
            "ipars",
            "node",
            "remove",
            "--agent-url",
            "http://127.0.0.1:19780",
            "--control-plane-url",
            "http://127.0.0.1:8443",
        ])?;
        let Command::Node {
            command: NodeCommand::Remove(args),
        } = node.command
        else {
            anyhow::bail!("expected node remove command");
        };
        assert_eq!(args.agent_url.as_deref(), Some("http://127.0.0.1:19780"));
        assert_eq!(
            args.control_plane_url.as_deref(),
            Some("http://127.0.0.1:8443")
        );

        Ok(())
    }

    #[test]
    fn path_activity_args_build_typed_request() -> anyhow::Result<()> {
        let path = Cli::try_parse_from([
            "ipars",
            "path",
            "activity",
            "--agent-url",
            "http://127.0.0.1:9780",
            "--peer",
            "peer-a",
            "--pin",
        ])?;
        let Command::Path {
            command: PathCommand::Activity(args),
        } = path.command
        else {
            anyhow::bail!("expected path activity command");
        };

        assert_eq!(args.agent_url.as_deref(), Some("http://127.0.0.1:9780"));
        let request = path_activity_request(&args)?;
        assert_eq!(request.peer, NodeId::from_string("peer-a"));
        assert!(request.pin);
        Ok(())
    }

    #[test]
    fn path_activity_rejects_path_unsafe_peer_id() -> anyhow::Result<()> {
        let path = Cli::try_parse_from([
            "ipars",
            "path",
            "activity",
            "--agent-url",
            "http://127.0.0.1:9780",
            "--peer",
            "peer/a",
        ])?;
        let Command::Path {
            command: PathCommand::Activity(args),
        } = path.command
        else {
            anyhow::bail!("expected path activity command");
        };

        let error = match path_activity_request(&args) {
            Ok(_) => anyhow::bail!("path-unsafe peer ID should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--peer must contain only"));
        Ok(())
    }

    #[test]
    fn path_probe_args_build_typed_request() -> anyhow::Result<()> {
        let path = Cli::try_parse_from([
            "ipars",
            "path",
            "probe",
            "--agent-url",
            "http://127.0.0.1:9780",
            "--peer",
            "peer-a",
            "--state",
            "DIRECT_NAT_TRAVERSAL",
            "--latency-ms",
            "23.5",
            "--loss-ppm",
            "100",
            "--jitter-ms",
            "3.25",
            "--relay-load",
            "0.4",
            "--stability",
            "0.8",
            "--cost",
            "25",
            "--policy-denied",
            "--pin",
            "--candidate-addr",
            "198.51.100.10:51820",
            "--candidate-kind",
            "stun-reflexive",
            "--candidate-priority",
            "90",
            "--candidate-cost",
            "9",
            "--candidate-source",
            "stun-probe",
        ])?;
        let Command::Path {
            command: PathCommand::Probe(args),
        } = path.command
        else {
            anyhow::bail!("expected path probe command");
        };
        assert_eq!(args.agent_url.as_deref(), Some("http://127.0.0.1:9780"));

        let observed_at = Utc::now();
        let request = path_probe_request(&args, observed_at)?;
        assert_eq!(request.peer, NodeId::from_string("peer-a"));
        assert_eq!(request.selected_state, PathState::DirectNatTraversal);
        assert_eq!(request.relay_node, None);
        assert_eq!(request.metrics.latency_ms, Some(23.5));
        assert_eq!(request.metrics.loss_ppm, 100);
        assert_eq!(request.metrics.jitter_ms, Some(3.25));
        assert_eq!(request.metrics.relay_load, Some(0.4));
        assert_eq!(request.metrics.stability, 0.8);
        assert!(!request.policy_allowed);
        assert_eq!(request.cost, 25);
        assert!(request.pin);

        let candidate = request
            .selected_candidate
            .context("expected selected candidate")?;
        assert_eq!(candidate.node_id, NodeId::from_string("peer-a"));
        assert_eq!(candidate.kind, EndpointCandidateKind::StunReflexive);
        assert_eq!(candidate.addr, "198.51.100.10:51820".parse()?);
        assert_eq!(candidate.observed_at, observed_at);
        assert_eq!(candidate.priority, 90);
        assert_eq!(candidate.cost, 9);
        assert_eq!(candidate.source, CandidateSource::StunProbe);
        Ok(())
    }

    #[test]
    fn path_probe_rejects_candidate_metadata_without_addr() -> anyhow::Result<()> {
        let path = Cli::try_parse_from([
            "ipars",
            "path",
            "probe",
            "--peer",
            "peer-a",
            "--state",
            "relay",
            "--candidate-kind",
            "relay",
        ])?;
        let Command::Path {
            command: PathCommand::Probe(args),
        } = path.command
        else {
            anyhow::bail!("expected path probe command");
        };

        let error = match path_probe_request(&args, Utc::now()) {
            Ok(_) => anyhow::bail!("candidate metadata without address should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("candidate metadata requires --candidate-addr"));
        Ok(())
    }

    #[test]
    fn path_probe_rejects_path_unsafe_peer_and_relay_ids() -> anyhow::Result<()> {
        let peer_path = Cli::try_parse_from([
            "ipars", "path", "probe", "--peer", "peer/a", "--state", "relay",
        ])?;
        let Command::Path {
            command: PathCommand::Probe(peer_args),
        } = peer_path.command
        else {
            anyhow::bail!("expected path probe command");
        };

        let error = match path_probe_request(&peer_args, Utc::now()) {
            Ok(_) => anyhow::bail!("path-unsafe peer ID should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--peer must contain only"));

        let relay_path = Cli::try_parse_from([
            "ipars",
            "path",
            "probe",
            "--peer",
            "peer-a",
            "--state",
            "relay",
            "--relay-node",
            "relay/a",
        ])?;
        let Command::Path {
            command: PathCommand::Probe(relay_args),
        } = relay_path.command
        else {
            anyhow::bail!("expected path probe command");
        };

        let error = match path_probe_request(&relay_args, Utc::now()) {
            Ok(_) => anyhow::bail!("path-unsafe relay node ID should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--relay-node must contain only"));
        Ok(())
    }

    #[test]
    fn path_probe_rejects_invalid_candidate_kind_address() -> anyhow::Result<()> {
        let path = Cli::try_parse_from([
            "ipars",
            "path",
            "probe",
            "--peer",
            "peer-a",
            "--state",
            "DIRECT_IPV6",
            "--candidate-kind",
            "ipv6",
            "--candidate-addr",
            "198.51.100.10:51820",
        ])?;
        let Command::Path {
            command: PathCommand::Probe(args),
        } = path.command
        else {
            anyhow::bail!("expected path probe command");
        };

        let error = match path_probe_request(&args, Utc::now()) {
            Ok(_) => anyhow::bail!("invalid candidate kind/address should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("IPv6 candidates must use an IPv6 socket address"));
        Ok(())
    }

    #[test]
    fn path_probe_rejects_unusable_candidate_address() -> anyhow::Result<()> {
        let path = Cli::try_parse_from([
            "ipars",
            "path",
            "probe",
            "--peer",
            "peer-a",
            "--state",
            "DIRECT_PUBLIC",
            "--candidate-addr",
            "203.0.113.10:0",
        ])?;
        let Command::Path {
            command: PathCommand::Probe(args),
        } = path.command
        else {
            anyhow::bail!("expected path probe command");
        };

        let error = match path_probe_request(&args, Utc::now()) {
            Ok(_) => anyhow::bail!("unusable candidate address should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("selected candidate"));
        assert!(error.to_string().contains("is unusable"));
        Ok(())
    }

    #[test]
    fn path_probe_rejects_candidate_kind_mismatched_to_direct_state() -> anyhow::Result<()> {
        let path = Cli::try_parse_from([
            "ipars",
            "path",
            "probe",
            "--peer",
            "peer-a",
            "--state",
            "DIRECT_PUBLIC",
            "--candidate-kind",
            "stun-reflexive",
            "--candidate-addr",
            "198.51.100.10:51820",
        ])?;
        let Command::Path {
            command: PathCommand::Probe(args),
        } = path.command
        else {
            anyhow::bail!("expected path probe command");
        };

        let error = match path_probe_request(&args, Utc::now()) {
            Ok(_) => anyhow::bail!("candidate kind mismatched to direct state should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("selected state DirectPublic"));
        assert!(error
            .to_string()
            .contains("selected candidate kind StunReflexive"));
        Ok(())
    }

    #[test]
    fn path_probe_rejects_inconsistent_relay_and_unreachable_shape() -> anyhow::Result<()> {
        let relay_missing = Cli::try_parse_from([
            "ipars", "path", "probe", "--peer", "peer-a", "--state", "relay",
        ])?;
        let Command::Path {
            command: PathCommand::Probe(relay_missing_args),
        } = relay_missing.command
        else {
            anyhow::bail!("expected path probe command");
        };
        let error = match path_probe_request(&relay_missing_args, Utc::now()) {
            Ok(_) => anyhow::bail!("relay path without relay node should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("requires --relay-node"));

        let direct_relay_node = Cli::try_parse_from([
            "ipars",
            "path",
            "probe",
            "--peer",
            "peer-a",
            "--state",
            "DIRECT_PUBLIC",
            "--relay-node",
            "relay-a",
        ])?;
        let Command::Path {
            command: PathCommand::Probe(direct_relay_node_args),
        } = direct_relay_node.command
        else {
            anyhow::bail!("expected path probe command");
        };
        let error = match path_probe_request(&direct_relay_node_args, Utc::now()) {
            Ok(_) => anyhow::bail!("direct path with relay node should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("direct path probe must not carry a relay node"));

        let relay_candidate = Cli::try_parse_from([
            "ipars",
            "path",
            "probe",
            "--peer",
            "peer-a",
            "--state",
            "relay",
            "--relay-node",
            "relay-a",
            "--candidate-addr",
            "198.51.100.10:51820",
        ])?;
        let Command::Path {
            command: PathCommand::Probe(relay_candidate_args),
        } = relay_candidate.command
        else {
            anyhow::bail!("expected path probe command");
        };
        let error = match path_probe_request(&relay_candidate_args, Utc::now()) {
            Ok(_) => anyhow::bail!("relay path with selected candidate should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("relay path probe must not carry a direct selected candidate"));

        let unreachable_candidate = Cli::try_parse_from([
            "ipars",
            "path",
            "probe",
            "--peer",
            "peer-a",
            "--state",
            "unreachable",
            "--candidate-addr",
            "198.51.100.10:51820",
        ])?;
        let Command::Path {
            command: PathCommand::Probe(unreachable_candidate_args),
        } = unreachable_candidate.command
        else {
            anyhow::bail!("expected path probe command");
        };
        let error = match path_probe_request(&unreachable_candidate_args, Utc::now()) {
            Ok(_) => anyhow::bail!("unreachable path with selected candidate should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("unreachable path probe must not carry a selected candidate"));
        Ok(())
    }

    #[test]
    fn path_probe_rejects_invalid_metrics() -> anyhow::Result<()> {
        let path = Cli::try_parse_from([
            "ipars",
            "path",
            "probe",
            "--peer",
            "peer-a",
            "--state",
            "DIRECT_PUBLIC",
            "--latency-ms=-1",
        ])?;
        let Command::Path {
            command: PathCommand::Probe(args),
        } = path.command
        else {
            anyhow::bail!("expected path probe command");
        };

        let error = match path_probe_request(&args, Utc::now()) {
            Ok(_) => panic!("negative latency must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("latency_ms"));
        Ok(())
    }

    #[test]
    fn peers_routes_and_relay_args_accept_api_urls() -> anyhow::Result<()> {
        let peers = Cli::try_parse_from([
            "ipars",
            "peers",
            "--control-plane-url",
            "http://127.0.0.1:8443",
            "--node-id",
            "node-a",
        ])?;
        if let Command::Peers(args) = peers.command {
            assert_eq!(args.agent_url, None);
            assert_eq!(
                args.control_plane_url.as_deref(),
                Some("http://127.0.0.1:8443")
            );
            assert_eq!(args.node_id.as_deref(), Some("node-a"));
        } else {
            anyhow::bail!("expected peers command");
        }

        let peers =
            Cli::try_parse_from(["ipars", "peers", "--agent-url", "http://127.0.0.1:9780"])?;
        if let Command::Peers(args) = peers.command {
            assert_eq!(args.agent_url.as_deref(), Some("http://127.0.0.1:9780"));
            assert_eq!(args.control_plane_url, None);
            assert_eq!(args.node_id, None);
        } else {
            anyhow::bail!("expected peers command");
        }

        assert!(Cli::try_parse_from([
            "ipars",
            "peers",
            "--agent-url",
            "http://127.0.0.1:9780",
            "--control-plane-url",
            "http://127.0.0.1:8443",
            "--node-id",
            "node-a",
        ])
        .is_err());

        let routes = Cli::try_parse_from([
            "ipars",
            "routes",
            "--control-plane-url",
            "http://127.0.0.1:8443",
            "--node-id",
            "node-a",
        ])?;
        if let Command::Routes(args) = routes.command {
            assert_eq!(args.agent_url, None);
            assert_eq!(
                args.control_plane_url.as_deref(),
                Some("http://127.0.0.1:8443")
            );
            assert_eq!(args.node_id.as_deref(), Some("node-a"));
        } else {
            anyhow::bail!("expected routes command");
        }

        let routes =
            Cli::try_parse_from(["ipars", "routes", "--agent-url", "http://127.0.0.1:9780"])?;
        if let Command::Routes(args) = routes.command {
            assert_eq!(args.agent_url.as_deref(), Some("http://127.0.0.1:9780"));
            assert_eq!(args.control_plane_url, None);
            assert_eq!(args.node_id, None);
        } else {
            anyhow::bail!("expected routes command");
        }

        assert!(Cli::try_parse_from([
            "ipars",
            "routes",
            "--agent-url",
            "http://127.0.0.1:9780",
            "--control-plane-url",
            "http://127.0.0.1:8443",
            "--node-id",
            "node-a",
        ])
        .is_err());

        let relay = Cli::try_parse_from([
            "ipars",
            "relay",
            "status",
            "--relay-url",
            "http://127.0.0.1:9580",
        ])?;
        if let Command::Relay {
            command: RelayCommand::Status(args),
        } = relay.command
        {
            assert_eq!(args.relay_url.as_deref(), Some("http://127.0.0.1:9580"));
            return Ok(());
        }

        anyhow::bail!("expected relay status command")
    }

    #[test]
    fn relay_probe_args_build_valid_dataplane_probe() -> anyhow::Result<()> {
        let relay = Cli::try_parse_from([
            "ipars",
            "relay",
            "probe",
            "--relay-url",
            "http://127.0.0.1:9580",
            "--relay-admission-bearer-token",
            "cluster-relay-secret-with-at-least-32-bytes",
            "--relay-udp",
            "127.0.0.1:51820",
            "--left-node-id",
            "left-a",
            "--right-node-id",
            "right-b",
            "--left-bind",
            "127.0.0.1:0",
            "--right-bind",
            "127.0.0.1:0",
            "--payload",
            "opaque",
            "--send-invalid-credential",
            "--timeout-ms",
            "1000",
        ])?;
        let Command::Relay {
            command: RelayCommand::Probe(args),
        } = relay.command
        else {
            anyhow::bail!("expected relay probe command");
        };

        assert_eq!(args.relay_url.as_deref(), Some("http://127.0.0.1:9580"));
        assert_eq!(
            args.relay_admission_bearer_token.as_deref(),
            Some("cluster-relay-secret-with-at-least-32-bytes")
        );
        assert_eq!(args.relay_udp, "127.0.0.1:51820".parse()?);
        assert_eq!(args.left_node_id, "left-a");
        assert_eq!(args.right_node_id, "right-b");
        assert_eq!(args.left_bind, "127.0.0.1:0".parse()?);
        assert_eq!(args.right_bind, "127.0.0.1:0".parse()?);
        assert_eq!(args.payload, "opaque");
        assert!(args.send_invalid_credential);
        assert_eq!(args.timeout_ms, 1000);
        validate_relay_probe_args(&args)?;
        Ok(())
    }

    #[test]
    fn relay_probe_rejects_unusable_endpoint_and_payload() -> anyhow::Result<()> {
        let relay = Cli::try_parse_from([
            "ipars",
            "relay",
            "probe",
            "--relay-udp",
            "0.0.0.0:51820",
            "--payload",
            "opaque",
        ])?;
        let Command::Relay {
            command: RelayCommand::Probe(mut args),
        } = relay.command
        else {
            anyhow::bail!("expected relay probe command");
        };

        let error = match validate_relay_probe_args(&args) {
            Ok(_) => anyhow::bail!("unusable relay UDP endpoint should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--relay-udp must be a usable"));

        args.relay_udp = "127.0.0.1:51820".parse()?;
        args.payload.clear();
        let error = match validate_relay_probe_args(&args) {
            Ok(_) => anyhow::bail!("empty relay probe payload should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--payload must not be empty"));

        args.payload = "opaque".to_string();
        args.timeout_ms = MAX_RELAY_PROBE_TIMEOUT_MS + 1;
        let error = match validate_relay_probe_args(&args) {
            Ok(_) => anyhow::bail!("oversized relay probe timeout should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--timeout-ms must be between"));

        args.timeout_ms = DEFAULT_RELAY_PROBE_TIMEOUT_MS;
        args.relay_admission_bearer_token = Some("too-short".to_string());
        let error = match validate_relay_probe_args(&args) {
            Ok(_) => anyhow::bail!("short relay admission bearer token should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("must contain at least 32 bytes"));

        args.relay_admission_bearer_token =
            Some("relay admission token with whitespace and sufficient length".to_string());
        let error = match validate_relay_probe_args(&args) {
            Ok(_) => anyhow::bail!("whitespace-bearing bearer token should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--relay-admission-bearer-token must not contain whitespace"));
        Ok(())
    }

    #[test]
    fn stun_probe_args_build_udp_probe() -> anyhow::Result<()> {
        let stun = Cli::try_parse_from([
            "ipars",
            "stun",
            "probe",
            "--stun-server",
            "127.0.0.1:3478",
            "--local-bind",
            "0.0.0.0:0",
        ])?;
        let Command::Stun {
            command: StunCommand::Probe(args),
        } = stun.command
        else {
            anyhow::bail!("expected stun probe command");
        };

        assert_eq!(args.stun_server, "127.0.0.1:3478".parse()?);
        assert_eq!(args.local_bind, "0.0.0.0:0".parse()?);
        validate_stun_probe_args(&args)?;
        Ok(())
    }

    #[test]
    fn stun_probe_rejects_unusable_server_and_multicast_bind() -> anyhow::Result<()> {
        let stun =
            Cli::try_parse_from(["ipars", "stun", "probe", "--stun-server", "0.0.0.0:3478"])?;
        let Command::Stun {
            command: StunCommand::Probe(mut args),
        } = stun.command
        else {
            anyhow::bail!("expected stun probe command");
        };

        let error = match validate_stun_probe_args(&args) {
            Ok(_) => anyhow::bail!("unusable STUN server should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--stun-server must be a usable"));

        args.stun_server = "127.0.0.1:3478".parse()?;
        args.local_bind = "224.0.0.1:0".parse()?;
        let error = match validate_stun_probe_args(&args) {
            Ok(_) => anyhow::bail!("multicast local bind should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--local-bind must not use a multicast"));
        Ok(())
    }

    #[test]
    fn control_plane_node_id_rejects_path_unsafe_values() -> anyhow::Result<()> {
        let error = match required_node_id(Some("node/a"), "peers") {
            Ok(_) => anyhow::bail!("path-unsafe node ID should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--node-id must contain only"));

        let error = match required_node_id(Some(""), "path status") {
            Ok(_) => anyhow::bail!("empty node ID should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--node-id cannot be empty"));
        Ok(())
    }

    #[test]
    fn routes_output_flattens_peer_map_routes() -> anyhow::Result<()> {
        let local = NodeId::from_string("node-a");
        let peer = NodeId::from_string("node-b");
        let route = Route {
            id: "route-b".to_string(),
            cidr: "10.42.0.0/16".parse()?,
            advertised_by: peer.clone(),
            via: Some(peer.clone()),
            metric: 50,
            tags: Default::default(),
        };
        let generated_at = Utc::now();
        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: vec![ipars_types::NodeRecord {
                node_id: peer.clone(),
                cluster_id: ClusterId::from_string("cluster-a"),
                vpn_ip: ipars_types::VpnIp(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    100, 64, 0, 2,
                ))),
                identity_public_key: "identity".to_string(),
                wireguard_public_key: "wireguard".to_string(),
                role: Role::edge(),
                tags: Default::default(),
                endpoint_candidates: Vec::new(),
                relay_capability: None,
                token_policy: TokenPolicy::default(),
                routes: vec![route.clone()],
                registered_at: generated_at,
            }],
            generated_at,
        };

        let output = routes_output(local.clone(), peer_map);

        assert_eq!(output.node_id, local);
        assert_eq!(output.routes.len(), 1);
        assert_eq!(output.routes[0].peer, peer);
        assert_eq!(output.routes[0].route, route);
        Ok(())
    }

    #[test]
    fn direct_control_plane_node_query_uses_owner_only_agent_identity() -> anyhow::Result<()> {
        let state = AgentNodeState::generate(Utc::now());
        let state_dir = temp_path("node-query-state");
        let state_path = state_dir.join("agent.json");
        FileAgentStateStore::new(&state_path).save(&state)?;

        let request = signed_control_plane_node_query(
            state.node_id.clone(),
            Some(&state_path),
            ControlPlaneNodeQueryKind::PeerMap,
            "peers",
        )?;
        verify_control_plane_node_query_signature(
            &request,
            ControlPlaneNodeQueryKind::PeerMap,
            &state.identity_public_key_b64,
        )?;
        assert!(signed_control_plane_node_query(
            NodeId::from_string("wrong-node"),
            Some(&state_path),
            ControlPlaneNodeQueryKind::PeerMap,
            "peers",
        )
        .is_err());
        assert!(signed_control_plane_node_query(
            state.node_id,
            None,
            ControlPlaneNodeQueryKind::Paths,
            "path status",
        )
        .is_err());

        std::fs::remove_dir_all(state_dir)?;
        Ok(())
    }

    fn docker_install_test_args() -> DockerInstallArgs {
        DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose.yaml"),
            project_name: "edge".to_string(),
            rootless: false,
            docker_discover_networks: false,
            docker_networks: Vec::new(),
            docker_api_socket: None,
            docker_container_namespace: None,
            docker_host_interface: "docker0".to_string(),
            docker_container_cidrs: Vec::new(),
            disable_docker_expose_host_routes: false,
            docker_route_interval_seconds: 60,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            agent_runtime_backend: "linux-command".to_string(),
            route_backend: "command".to_string(),
            userspace_wireguard_command: None,
            userspace_wireguard_args: Vec::new(),
            userspace_wireguard_ready_timeout_seconds: 10,
            userspace_wireguard_shutdown_timeout_seconds: 5,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_sessions_per_node: DEFAULT_RELAY_MAX_SESSIONS_PER_NODE,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_session_ttl_seconds: DEFAULT_RELAY_SESSION_TTL_SECONDS,
            relay_admission_rate_limit: DEFAULT_RELAY_ADMISSION_RATE_LIMIT,
            relay_admission_rate_limit_window_seconds:
                DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        }
    }

    #[test]
    fn docker_install_plan_lists_compose_commands_and_requirements() -> anyhow::Result<()> {
        let plan = docker_install_plan(DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose.yaml"),
            project_name: "edge".to_string(),
            rootless: false,
            docker_discover_networks: false,
            docker_networks: Vec::new(),
            docker_api_socket: None,
            docker_container_namespace: None,
            docker_host_interface: "docker0".to_string(),
            docker_container_cidrs: Vec::new(),
            disable_docker_expose_host_routes: false,
            docker_route_interval_seconds: 60,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            agent_runtime_backend: "linux-command".to_string(),
            route_backend: "command".to_string(),
            userspace_wireguard_command: None,
            userspace_wireguard_args: Vec::new(),
            userspace_wireguard_ready_timeout_seconds: 10,
            userspace_wireguard_shutdown_timeout_seconds: 5,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_sessions_per_node: DEFAULT_RELAY_MAX_SESSIONS_PER_NODE,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_session_ttl_seconds: DEFAULT_RELAY_SESSION_TTL_SECONDS,
            relay_admission_rate_limit: DEFAULT_RELAY_ADMISSION_RATE_LIMIT,
            relay_admission_rate_limit_window_seconds:
                DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        })?;

        assert_eq!(plan.platform, "docker-compose");
        assert_eq!(plan.manifest, "ops/compose.yaml");
        assert_eq!(
            plan.commands,
            vec![
                "docker compose -p edge -f ops/compose.yaml config",
                "docker compose -p edge -f ops/compose.yaml up -d --build",
            ]
        );
        assert!(plan
            .prerequisites
            .iter()
            .any(|requirement| requirement.contains("CAP_NET_ADMIN")));
        assert!(plan
            .prerequisites
            .iter()
            .any(|requirement| requirement.contains("net.ipv4.ip_forward")));
        assert!(plan.prerequisites.iter().any(|requirement| {
            requirement.contains("docker/signal-operator-api.token")
                && requirement.contains("IPARS_SIGNAL_OPERATOR_API_BEARER_TOKEN_FILE")
        }));
        assert!(plan.prerequisites.iter().any(|requirement| {
            requirement.contains("docker/stun-operator-api.token")
                && requirement.contains("IPARS_STUN_OPERATOR_API_BEARER_TOKEN_FILE")
        }));
        assert!(plan.prerequisites.iter().any(|requirement| {
            requirement.contains("docker/relay-operator-api.token")
                && requirement.contains("IPARS_RELAY_OPERATOR_API_BEARER_TOKEN_FILE")
        }));
        assert!(plan.prerequisites.iter().any(|requirement| {
            requirement.contains("docker/relay-admission.token")
                && requirement.contains("IPARS_RELAY_ADMISSION_BEARER_TOKEN_FILE")
        }));
        assert!(plan.environment.iter().any(|environment| {
            environment.name == "IPARS_AGENT_APPLY_DOCKER_ROUTES" && environment.value == "true"
        }));
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_EXPOSE_HOST_ROUTES"),
            Some("true")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_ROUTE_INTERVAL_SECONDS"),
            Some("60")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_ROUTE_BACKEND"),
            Some("command")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_STUN_ALTERNATE_LISTEN"),
            Some(DEFAULT_STUN_ALTERNATE_LISTEN)
        );
        assert_eq!(environment_value(&plan, "IPARS_DOCKER_API_SOCKET"), None);
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_API_SOCKET_HOST"),
            None
        );
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_CONTAINER_NAMESPACE"),
            Some("compose-default")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_CONTAINER_CIDRS"),
            Some("172.18.0.0/16")
        );
        assert!(plan
            .security
            .iter()
            .any(|requirement| requirement.contains("plain HTTP")));
        assert!(plan.security.iter().any(|requirement| {
            requirement.contains("IPARS_RELAY_ADMISSION_BEARER_TOKEN_FILE")
                && requirement.contains("rotate it independently")
        }));
        assert!(plan
            .notes
            .iter()
            .any(|note| note.contains("healthchecks") && note.contains("loopback URLs")));
        assert!(plan.notes.iter().any(|note| {
            note.contains("IPARS_STUN_ALTERNATE_LISTEN") && note.contains("alternate UDP port")
        }));
        assert!(plan
            .notes
            .iter()
            .any(|note| note.contains("join token") && note.contains("Compose secret")));
        assert!(plan.notes.iter().any(|note| {
            note.contains("docker/signal-operator-api.token")
                && note.contains("JSON and Prometheus metrics")
        }));
        assert!(plan.notes.iter().any(|note| {
            note.contains("docker/stun-operator-api.token") && note.contains("UDP Binding requests")
        }));
        assert!(plan.notes.iter().any(|note| {
            note.contains("docker/relay-operator-api.token")
                && note.contains("capability status")
                && note.contains("admission authentication")
        }));
        assert!(plan.notes.iter().any(|note| {
            note.contains("docker/relay-admission.token")
                && note.contains("shared file-backed admission credential")
        }));
        assert!(plan.security.iter().any(|requirement| {
            requirement.contains("IPARS_SIGNAL_OPERATOR_API_BEARER_TOKEN_FILE")
                && requirement.contains("control-plane operator credential")
        }));
        assert!(plan.security.iter().any(|requirement| {
            requirement.contains("IPARS_STUN_OPERATOR_API_BEARER_TOKEN_FILE")
                && requirement.contains("UDP Binding service")
        }));
        assert!(plan.security.iter().any(|requirement| {
            requirement.contains("IPARS_RELAY_OPERATOR_API_BEARER_TOKEN_FILE")
                && requirement.contains("relay admission credential")
        }));
        assert!(plan.notes.iter().any(|note| {
            note.contains("IPARS_RELAY_PUBLIC_ENDPOINT")
                && note.contains("IPARS_RELAY_ADMISSION_URL")
                && note.contains("IPARS_AGENT_RELAY_PUBLIC_ENDPOINT")
                && note.contains("IPARS_AGENT_RELAY_ADMISSION_URL")
        }));
        assert!(plan.notes.iter().any(|note| {
            note.contains("IPARS_RELAY_ADMISSION_BEARER_TOKEN_PATH")
                && note.contains("IPARS_AGENT_RELAY_ADMISSION_BEARER_TOKEN_PATH")
                && note.contains("IPARS_RELAY_MAX_SESSIONS_PER_NODE")
                && note.contains("IPARS_RELAY_ADMISSION_RATE_LIMIT")
        }));
        assert!(plan
            .notes
            .iter()
            .any(|note| note.contains("IPARS_AGENT_RELAY_FORWARDER_*")));
        Ok(())
    }

    #[test]
    fn docker_compose_enables_agent_peer_map_application() {
        let compose = include_str!("../../../docker/compose.yaml");
        assert!(compose.contains("      - --apply-peer-map\n"));
    }

    #[test]
    fn docker_install_plan_quotes_compose_manifest_path() -> anyhow::Result<()> {
        let plan = docker_install_plan(DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose file.yaml"),
            project_name: "edge".to_string(),
            rootless: false,
            docker_discover_networks: false,
            docker_networks: Vec::new(),
            docker_api_socket: None,
            docker_container_namespace: None,
            docker_host_interface: "docker0".to_string(),
            docker_container_cidrs: Vec::new(),
            disable_docker_expose_host_routes: false,
            docker_route_interval_seconds: 60,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            agent_runtime_backend: "linux-command".to_string(),
            route_backend: "command".to_string(),
            userspace_wireguard_command: None,
            userspace_wireguard_args: Vec::new(),
            userspace_wireguard_ready_timeout_seconds: 10,
            userspace_wireguard_shutdown_timeout_seconds: 5,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_sessions_per_node: DEFAULT_RELAY_MAX_SESSIONS_PER_NODE,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_session_ttl_seconds: DEFAULT_RELAY_SESSION_TTL_SECONDS,
            relay_admission_rate_limit: DEFAULT_RELAY_ADMISSION_RATE_LIMIT,
            relay_admission_rate_limit_window_seconds:
                DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        })?;

        assert_eq!(
            plan.commands[0],
            "docker compose -p edge -f 'ops/compose file.yaml' config"
        );
        Ok(())
    }

    #[test]
    fn docker_install_plan_wires_route_advertisement_controls() -> anyhow::Result<()> {
        let plan = docker_install_plan(DockerInstallArgs {
            disable_docker_expose_host_routes: true,
            docker_route_interval_seconds: 15,
            ..docker_install_test_args()
        })?;

        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_EXPOSE_HOST_ROUTES"),
            Some("false")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_ROUTE_INTERVAL_SECONDS"),
            Some("15")
        );

        let error = match docker_install_plan(DockerInstallArgs {
            docker_route_interval_seconds: 0,
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("zero Docker route interval should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--docker-route-interval-seconds must be greater than zero"));
        Ok(())
    }

    #[test]
    fn docker_install_plan_wires_and_validates_agent_http_timeouts() -> anyhow::Result<()> {
        let plan = docker_install_plan(DockerInstallArgs {
            agent_http_connect_timeout_seconds: 7,
            agent_http_request_timeout_seconds: 45,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            ..docker_install_test_args()
        })?;
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS"),
            Some("7")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS"),
            Some("45")
        );

        for (connect, request, expected) in [
            (0, 30, "--agent-http-connect-timeout-seconds must be greater than zero"),
            (5, 0, "--agent-http-request-timeout-seconds must be greater than zero"),
            (3_601, 3_601, "--agent-http-connect-timeout-seconds must not exceed 3600"),
            (31, 30, "--agent-http-connect-timeout-seconds must not exceed --agent-http-request-timeout-seconds"),
        ] {
            let error = match docker_install_plan(DockerInstallArgs {
                agent_http_connect_timeout_seconds: connect,
                agent_http_request_timeout_seconds: request,
                agent_direct_path_probe_timeout_seconds: DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
                agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
                ..docker_install_test_args()
            }) {
                Ok(_) => anyhow::bail!("invalid Agent HTTP timeout settings should be rejected"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(expected),
                "expected `{expected}` in `{error:#}`"
            );
        }
        Ok(())
    }

    #[test]
    fn docker_install_plan_wires_and_validates_direct_path_verification() -> anyhow::Result<()> {
        let plan = docker_install_plan(DockerInstallArgs {
            agent_direct_path_probe_timeout_seconds: 90,
            agent_direct_handshake_max_age_seconds: 240,
            ..docker_install_test_args()
        })?;
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS"),
            Some("90")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS"),
            Some("240")
        );

        for (probe_timeout, handshake_max_age, expected) in [
            (
                0,
                180,
                "--agent-direct-path-probe-timeout-seconds must be greater than zero",
            ),
            (
                120,
                0,
                "--agent-direct-handshake-max-age-seconds must be greater than zero",
            ),
            (
                86_401,
                180,
                "--agent-direct-path-probe-timeout-seconds must not exceed 86400",
            ),
            (
                120,
                29,
                "--agent-direct-handshake-max-age-seconds must be at least the 30-second signal path interval",
            ),
            (
                59,
                180,
                "--agent-direct-path-probe-timeout-seconds must be at least the peer-map poll interval",
            ),
        ] {
            let error = test_error(
                docker_install_plan(DockerInstallArgs {
                    agent_direct_path_probe_timeout_seconds: probe_timeout,
                    agent_direct_handshake_max_age_seconds: handshake_max_age,
                    ..docker_install_test_args()
                }),
                "invalid direct path verification settings should be rejected",
            );
            assert!(
                error.to_string().contains(expected),
                "expected `{expected}` in `{error:#}`"
            );
        }
        Ok(())
    }

    #[test]
    fn docker_install_plan_wires_and_validates_peer_probe() -> anyhow::Result<()> {
        let settings = AgentPeerProbeInstallArgs {
            disabled: false,
            port: Some(51_900),
            interval_seconds: 45,
            sample_count: 7,
            response_timeout_millis: 750,
            sample_interval_millis: 25,
            max_concurrency: 8,
            responder_max_requests_per_second: 200,
            observation_max_age_seconds: 90,
        };
        let plan = docker_install_plan(DockerInstallArgs {
            agent_peer_probe: settings,
            ..docker_install_test_args()
        })?;
        for (name, expected) in [
            ("IPARS_AGENT_DISABLE_PEER_PROBE", "false"),
            ("IPARS_AGENT_PEER_PROBE_PORT", "51900"),
            ("IPARS_AGENT_PEER_PROBE_INTERVAL_SECONDS", "45"),
            ("IPARS_AGENT_PEER_PROBE_SAMPLE_COUNT", "7"),
            ("IPARS_AGENT_PEER_PROBE_RESPONSE_TIMEOUT_MILLIS", "750"),
            ("IPARS_AGENT_PEER_PROBE_SAMPLE_INTERVAL_MILLIS", "25"),
            ("IPARS_AGENT_PEER_PROBE_MAX_CONCURRENCY", "8"),
            (
                "IPARS_AGENT_PEER_PROBE_RESPONDER_MAX_REQUESTS_PER_SECOND",
                "200",
            ),
            ("IPARS_AGENT_PEER_PROBE_OBSERVATION_MAX_AGE_SECONDS", "90"),
            ("IPARS_SIGNAL_PATH_QUALITY_OBSERVATION_TTL_SECONDS", "90"),
        ] {
            assert_eq!(environment_value(&plan, name), Some(expected));
        }

        let rootless = docker_install_plan(DockerInstallArgs {
            rootless: true,
            agent_peer_probe: settings,
            ..docker_install_test_args()
        })?;
        assert_eq!(
            environment_value(&rootless, "IPARS_AGENT_DISABLE_PEER_PROBE"),
            Some("true")
        );

        for (settings, expected) in [
            (
                AgentPeerProbeInstallArgs {
                    port: Some(DEFAULT_DOCKER_AGENT_WIREGUARD_LISTEN_PORT),
                    ..AgentPeerProbeInstallArgs::default()
                },
                "--agent-peer-probe-port must differ from the effective WireGuard listen port",
            ),
            (
                AgentPeerProbeInstallArgs {
                    sample_count: 0,
                    ..AgentPeerProbeInstallArgs::default()
                },
                "--agent-peer-probe-sample-count must be between 1 and 64",
            ),
            (
                AgentPeerProbeInstallArgs {
                    response_timeout_millis: 0,
                    ..AgentPeerProbeInstallArgs::default()
                },
                "--agent-peer-probe-response-timeout-millis must be greater than zero",
            ),
            (
                AgentPeerProbeInstallArgs {
                    sample_interval_millis: 10_001,
                    ..AgentPeerProbeInstallArgs::default()
                },
                "--agent-peer-probe-sample-interval-millis must not exceed 10000",
            ),
            (
                AgentPeerProbeInstallArgs {
                    max_concurrency: 0,
                    ..AgentPeerProbeInstallArgs::default()
                },
                "--agent-peer-probe-max-concurrency must be between 1 and 1024",
            ),
            (
                AgentPeerProbeInstallArgs {
                    responder_max_requests_per_second: 0,
                    ..AgentPeerProbeInstallArgs::default()
                },
                "--agent-peer-probe-responder-max-requests-per-second must be between 1 and 100000",
            ),
            (
                AgentPeerProbeInstallArgs {
                    interval_seconds: 60,
                    observation_max_age_seconds: 59,
                    ..AgentPeerProbeInstallArgs::default()
                },
                "--agent-peer-probe-observation-max-age-seconds must be at least both",
            ),
        ] {
            let error = test_error(
                docker_install_plan(DockerInstallArgs {
                    agent_peer_probe: settings,
                    ..docker_install_test_args()
                }),
                "invalid peer probe settings should be rejected",
            );
            assert!(
                error.to_string().contains(expected),
                "expected `{expected}` in `{error:#}`"
            );
        }
        Ok(())
    }

    #[test]
    fn docker_install_plan_wires_route_backend_selection() -> anyhow::Result<()> {
        let plan = docker_install_plan(DockerInstallArgs {
            route_backend: "kernel-netlink".to_string(),
            ..docker_install_test_args()
        })?;

        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_ROUTE_BACKEND"),
            Some("kernel-netlink")
        );
        assert!(
            Cli::try_parse_from(["ipars", "docker", "install", "--route-backend", "invalid"])
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn docker_install_plan_wires_runtime_backend_and_forces_rootless_dry_run() -> anyhow::Result<()>
    {
        let plan = docker_install_plan(DockerInstallArgs {
            agent_runtime_backend: "dry-run".to_string(),
            ..docker_install_test_args()
        })?;

        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RUNTIME_BACKEND"),
            Some("dry-run")
        );
        assert!(Cli::try_parse_from([
            "ipars",
            "docker",
            "install",
            "--agent-runtime-backend",
            "invalid",
        ])
        .is_err());

        let rootless = docker_install_plan(DockerInstallArgs {
            rootless: true,
            ..docker_install_test_args()
        })?;
        assert_eq!(
            environment_value(&rootless, "IPARS_AGENT_RUNTIME_BACKEND"),
            Some("dry-run")
        );
        Ok(())
    }

    #[test]
    fn docker_install_plan_wires_relay_advertisement_consistently() -> anyhow::Result<()> {
        let plan = docker_install_plan(DockerInstallArgs {
            relay_public_endpoint: Some("203.0.113.30:51820".to_string()),
            relay_admission_url: Some("https://relay.example.com:9580".to_string()),
            relay_status_url: Some("https://relay.example.com:9580".to_string()),
            relay_max_sessions: 250,
            relay_max_sessions_per_node: 25,
            relay_max_mbps: 750,
            relay_session_ttl_seconds: 900,
            relay_admission_rate_limit: 123,
            relay_admission_rate_limit_window_seconds: 30,
            ..docker_install_test_args()
        })?;

        assert_eq!(
            environment_value(&plan, "IPARS_RELAY_PUBLIC_ENDPOINT"),
            Some("203.0.113.30:51820")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RELAY_PUBLIC_ENDPOINT"),
            Some("203.0.113.30:51820")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_RELAY_ADMISSION_URL"),
            Some("https://relay.example.com:9580")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RELAY_ADMISSION_URL"),
            Some("https://relay.example.com:9580")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RELAY_STATUS_URL"),
            Some("https://relay.example.com:9580")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_RELAY_MAX_SESSIONS"),
            Some("250")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RELAY_MAX_SESSIONS"),
            Some("250")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_RELAY_MAX_SESSIONS_PER_NODE"),
            Some("25")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_RELAY_MAX_MBPS"),
            Some("750")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RELAY_MAX_MBPS"),
            Some("750")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_RELAY_SESSION_TTL_SECONDS"),
            Some("900")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_RELAY_ADMISSION_RATE_LIMIT"),
            Some("123")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS"),
            Some("30")
        );
        assert!(plan.notes.iter().any(|note| {
            note.contains("--relay-public-endpoint")
                && note.contains("--relay-admission-url")
                && note.contains("both sides")
        }));

        let missing_admission = match docker_install_plan(DockerInstallArgs {
            relay_public_endpoint: Some("203.0.113.30:51820".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => {
                anyhow::bail!("Docker relay public endpoint without admission URL should fail")
            }
            Err(error) => error,
        };
        assert!(missing_admission
            .to_string()
            .contains("--relay-public-endpoint and --relay-admission-url must be set together"));

        let invalid_status = match docker_install_plan(DockerInstallArgs {
            relay_public_endpoint: Some("203.0.113.30:51820".to_string()),
            relay_admission_url: Some("https://relay.example.com:9580".to_string()),
            relay_status_url: Some("ftp://relay.example.com:9580".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("Docker relay status URL with non-HTTP scheme should fail"),
            Err(error) => error,
        };
        assert!(invalid_status
            .to_string()
            .contains("--relay-status-url must use http or https"));

        let zero_sessions = match docker_install_plan(DockerInstallArgs {
            relay_max_sessions: 0,
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("zero relay max sessions should be rejected"),
            Err(error) => error,
        };
        assert!(zero_sessions
            .to_string()
            .contains("--relay-max-sessions must be greater than zero"));

        let per_node_over_capacity = match docker_install_plan(DockerInstallArgs {
            relay_max_sessions: 10,
            relay_max_sessions_per_node: 11,
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("per-node relay sessions above total capacity should fail"),
            Err(error) => error,
        };
        assert!(per_node_over_capacity.to_string().contains(
            "--relay-max-sessions-per-node must be less than or equal to --relay-max-sessions"
        ));

        let zero_mbps = match docker_install_plan(DockerInstallArgs {
            relay_max_mbps: 0,
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("zero relay max Mbps should be rejected"),
            Err(error) => error,
        };
        assert!(zero_mbps
            .to_string()
            .contains("--relay-max-mbps must be greater than zero"));

        let zero_session_ttl = match docker_install_plan(DockerInstallArgs {
            relay_session_ttl_seconds: 0,
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("zero relay session TTL should be rejected"),
            Err(error) => error,
        };
        assert!(zero_session_ttl
            .to_string()
            .contains("--relay-session-ttl-seconds must be greater than zero"));

        let zero_rate_limit_window = match docker_install_plan(DockerInstallArgs {
            relay_admission_rate_limit: 1,
            relay_admission_rate_limit_window_seconds: 0,
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("zero relay admission rate-limit window should be rejected"),
            Err(error) => error,
        };
        assert!(zero_rate_limit_window
            .to_string()
            .contains("--relay-admission-rate-limit-window-seconds must be greater than zero"));
        Ok(())
    }

    #[test]
    fn docker_install_plan_wires_and_validates_relay_forwarder_settings() -> anyhow::Result<()> {
        let endpoint_only = docker_install_plan(DockerInstallArgs {
            relay_forwarder_endpoint: Some("127.0.0.1:45182".to_string()),
            ..docker_install_test_args()
        })?;
        assert_eq!(
            environment_value(&endpoint_only, "IPARS_AGENT_RELAY_FORWARDER_ENDPOINT"),
            Some("127.0.0.1:45182")
        );
        assert_eq!(
            environment_value(&endpoint_only, "IPARS_AGENT_RELAY_FORWARDER_BIND"),
            None
        );
        assert_eq!(
            environment_value(&endpoint_only, "IPARS_AGENT_RELAY_FORWARDER_MAX_SESSIONS"),
            None
        );

        let plan = docker_install_plan(DockerInstallArgs {
            relay_forwarder_endpoint: Some("127.0.0.1:45182".to_string()),
            relay_forwarder_bind: Some("0.0.0.0:45182".to_string()),
            relay_forwarder_wireguard_endpoint: Some("127.0.0.1:51820".to_string()),
            relay_forwarder_netns: Some("relay-fw".to_string()),
            relay_forwarder_max_sessions: 7,
            relay_forwarder_restart_backoff_seconds: 11,
            relay_forwarder_crash_window_seconds: 22,
            relay_forwarder_max_crashes_per_window: 4,
            relay_forwarder_crash_cooldown_seconds: 33,
            ..docker_install_test_args()
        })?;
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RELAY_FORWARDER_BIND"),
            Some("0.0.0.0:45182")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RELAY_FORWARDER_WIREGUARD_ENDPOINT"),
            Some("127.0.0.1:51820")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RELAY_FORWARDER_NETNS"),
            Some("relay-fw")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RELAY_FORWARDER_MAX_SESSIONS"),
            Some("7")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS"),
            Some("11")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS"),
            Some("22")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW"),
            Some("4")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS"),
            Some("33")
        );
        assert!(plan
            .prerequisites
            .iter()
            .any(|requirement| requirement.contains("CAP_SYS_ADMIN")));
        assert!(plan
            .notes
            .iter()
            .any(|note| note.contains("IPARS_AGENT_RELAY_FORWARDER_NETNS")));

        let invalid_endpoint = match docker_install_plan(DockerInstallArgs {
            relay_forwarder_endpoint: Some("0.0.0.0:45182".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("unusable relay forwarder endpoint should be rejected"),
            Err(error) => error,
        };
        assert!(invalid_endpoint
            .to_string()
            .contains("--relay-forwarder-endpoint"));

        let missing_wireguard_endpoint = match docker_install_plan(DockerInstallArgs {
            relay_forwarder_bind: Some("0.0.0.0:45182".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("relay forwarder bind without WireGuard endpoint should fail"),
            Err(error) => error,
        };
        assert!(missing_wireguard_endpoint
            .to_string()
            .contains("--relay-forwarder-wireguard-endpoint is required"));

        let invalid_bind = match docker_install_plan(DockerInstallArgs {
            relay_forwarder_bind: Some("239.1.1.1:45182".to_string()),
            relay_forwarder_wireguard_endpoint: Some("127.0.0.1:51820".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("multicast relay forwarder bind should be rejected"),
            Err(error) => error,
        };
        assert!(invalid_bind.to_string().contains("multicast bind address"));

        let inactive_capacity = match docker_install_plan(DockerInstallArgs {
            relay_forwarder_endpoint: Some("127.0.0.1:45182".to_string()),
            relay_forwarder_max_sessions: 7,
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("forwarder capacity without bind should be rejected"),
            Err(error) => error,
        };
        assert!(inactive_capacity
            .to_string()
            .contains("--relay-forwarder-max-sessions requires --relay-forwarder-bind"));
        Ok(())
    }

    #[test]
    fn docker_install_plan_exports_rootless_dry_run_settings_without_docker_routes(
    ) -> anyhow::Result<()> {
        let plan = docker_install_plan(DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose.yaml"),
            project_name: "edge".to_string(),
            rootless: true,
            docker_discover_networks: false,
            docker_networks: Vec::new(),
            docker_api_socket: None,
            docker_container_namespace: None,
            docker_host_interface: DEFAULT_DOCKER_HOST_INTERFACE.to_string(),
            docker_container_cidrs: Vec::new(),
            disable_docker_expose_host_routes: false,
            docker_route_interval_seconds: DEFAULT_DOCKER_ROUTE_INTERVAL_SECONDS,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            agent_runtime_backend: "linux-command".to_string(),
            route_backend: "command".to_string(),
            userspace_wireguard_command: None,
            userspace_wireguard_args: Vec::new(),
            userspace_wireguard_ready_timeout_seconds:
                DEFAULT_USERSPACE_WIREGUARD_READY_TIMEOUT_SECONDS,
            userspace_wireguard_shutdown_timeout_seconds:
                DEFAULT_USERSPACE_WIREGUARD_SHUTDOWN_TIMEOUT_SECONDS,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_sessions_per_node: DEFAULT_RELAY_MAX_SESSIONS_PER_NODE,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_session_ttl_seconds: DEFAULT_RELAY_SESSION_TTL_SECONDS,
            relay_admission_rate_limit: DEFAULT_RELAY_ADMISSION_RATE_LIMIT,
            relay_admission_rate_limit_window_seconds:
                DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        })?;

        assert!(plan
            .prerequisites
            .iter()
            .any(|requirement| requirement.contains("Rootless Docker Engine")));
        assert!(plan
            .prerequisites
            .iter()
            .any(|requirement| requirement.contains("non-mutating control-plane")));
        assert!(!plan
            .prerequisites
            .iter()
            .any(|requirement| requirement.contains("Docker API access")));
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_APPLY_DOCKER_ROUTES"),
            Some("false")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_DISCOVER_NETWORKS"),
            None
        );
        assert_eq!(environment_value(&plan, "IPARS_DOCKER_API_SOCKET"), None);
        assert_eq!(environment_value(&plan, "IPARS_DOCKER_NETWORKS"), None);
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_API_SOCKET_HOST"),
            None
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_WIREGUARD_BACKEND"),
            None
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_RUNTIME_BACKEND"),
            Some("dry-run")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_USERSPACE_WIREGUARD_COMMAND"),
            None
        );
        assert_eq!(
            environment_value(&plan, "IPARS_AGENT_USERSPACE_WIREGUARD_ARGS"),
            None
        );
        assert_eq!(
            environment_value(
                &plan,
                "IPARS_AGENT_USERSPACE_WIREGUARD_READY_TIMEOUT_SECONDS"
            ),
            None
        );
        assert_eq!(
            environment_value(
                &plan,
                "IPARS_AGENT_USERSPACE_WIREGUARD_SHUTDOWN_TIMEOUT_SECONDS"
            ),
            None
        );
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_CONTAINER_NAMESPACE"),
            None
        );
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_HOST_INTERFACE"),
            None
        );
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_CONTAINER_CIDRS"),
            None
        );
        assert_eq!(
            plan.commands[0],
            "docker compose -p edge -f ops/compose.yaml -f docker/compose.rootless.yaml config"
        );
        assert!(plan
            .notes
            .iter()
            .any(|note| note.contains("non-mutating dry-run backend")));
        assert!(plan
            .notes
            .iter()
            .any(|note| note.contains("do not request kernel capabilities")));
        assert!(plan
            .notes
            .iter()
            .any(|note| note.contains("separate rootful agent")));

        let namespaced_forwarder = match docker_install_plan(DockerInstallArgs {
            rootless: true,
            relay_forwarder_bind: Some("0.0.0.0:45182".to_string()),
            relay_forwarder_wireguard_endpoint: Some("127.0.0.1:51820".to_string()),
            relay_forwarder_netns: Some("relay-fw".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!(
                "rootless namespaced relay forwarder should be rejected before Compose rendering"
            ),
            Err(error) => error,
        };
        assert!(namespaced_forwarder
            .to_string()
            .contains("--rootless cannot be combined with --relay-forwarder-netns"));

        let relay_forwarder = match docker_install_plan(DockerInstallArgs {
            rootless: true,
            relay_forwarder_bind: Some("0.0.0.0:45182".to_string()),
            relay_forwarder_wireguard_endpoint: Some("127.0.0.1:51820".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("rootless relay forwarder should be rejected"),
            Err(error) => error,
        };
        assert!(relay_forwarder
            .to_string()
            .contains("--rootless cannot be combined with relay forwarder settings"));

        let userspace_command = match docker_install_plan(DockerInstallArgs {
            rootless: true,
            userspace_wireguard_command: Some("wireguard-go".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("rootless userspace WireGuard command should be rejected"),
            Err(error) => error,
        };
        assert!(userspace_command
            .to_string()
            .contains("--rootless does not support --userspace-wireguard-command"));
        Ok(())
    }

    #[test]
    fn bundled_compose_consumes_docker_install_environment_contract() -> anyhow::Result<()> {
        let compose_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docker/compose.yaml")
            .canonicalize()?;
        let compose = std::fs::read_to_string(compose_path)?;
        let discovery_compose_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docker/compose.docker-discovery.yaml")
            .canonicalize()?;
        let discovery_compose = std::fs::read_to_string(discovery_compose_path)?;
        let rootless_compose_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docker/compose.rootless.yaml")
            .canonicalize()?;
        let rootless_compose = std::fs::read_to_string(rootless_compose_path)?;

        assert!(compose
            .contains("IPARS_AGENT_APPLY_DOCKER_ROUTES=${IPARS_AGENT_APPLY_DOCKER_ROUTES:-false}"));
        assert!(compose
            .contains("IPARS_AGENT_WIREGUARD_BACKEND=${IPARS_AGENT_WIREGUARD_BACKEND:-command}"));
        assert!(compose.contains("IPARS_AGENT_ROUTE_BACKEND=${IPARS_AGENT_ROUTE_BACKEND:-command}"));
        assert!(compose.contains("IPARS_AGENT_USERSPACE_WIREGUARD_COMMAND"));
        assert!(compose.contains("IPARS_AGENT_USERSPACE_WIREGUARD_ARGS"));
        assert!(compose.contains("IPARS_AGENT_USERSPACE_WIREGUARD_READY_TIMEOUT_SECONDS"));
        assert!(compose.contains("IPARS_AGENT_USERSPACE_WIREGUARD_SHUTDOWN_TIMEOUT_SECONDS"));
        assert!(compose.contains(
            "IPARS_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS=${IPARS_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS:-120}"
        ));
        assert!(compose.contains(
            "IPARS_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS=${IPARS_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS:-180}"
        ));
        assert!(compose
            .contains("IPARS_DOCKER_DISCOVER_NETWORKS=${IPARS_DOCKER_DISCOVER_NETWORKS:-false}"));
        assert!(!compose.contains("IPARS_DOCKER_API_SOCKET=/run/ipars/docker.sock"));
        assert!(compose.contains("IPARS_DOCKER_NETWORKS"));
        assert!(compose.contains("IPARS_DOCKER_CONTAINER_NAMESPACE"));
        assert!(compose.contains("IPARS_DOCKER_CONTAINER_CIDRS"));
        assert!(compose
            .contains("IPARS_DOCKER_EXPOSE_HOST_ROUTES=${IPARS_DOCKER_EXPOSE_HOST_ROUTES:-true}"));
        assert!(compose.contains(
            "IPARS_DOCKER_ROUTE_INTERVAL_SECONDS=${IPARS_DOCKER_ROUTE_INTERVAL_SECONDS:-60}"
        ));
        assert!(compose.contains(
            "IPARS_RELAY_ADMISSION_BEARER_TOKEN_PATH=/run/secrets/ipars-relay-admission-bearer-token"
        ));
        assert!(compose.contains(
            "IPARS_AGENT_RELAY_ADMISSION_BEARER_TOKEN_PATH=/run/secrets/ipars-relay-admission-bearer-token"
        ));
        assert!(compose.contains("IPARS_RELAY_ADMISSION_BEARER_TOKEN_FILE"));
        assert!(compose.contains("IPARS_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN_PATH"));
        assert!(compose.contains("ipars-control-plane-operator-api-bearer-token"));
        assert!(compose.contains("IPARS_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN_FILE"));
        assert!(compose.contains("IPARS_RELAY_PUBLIC_ENDPOINT"));
        assert!(compose.contains("IPARS_RELAY_ADMISSION_URL"));
        assert!(compose.contains(
            "IPARS_AGENT_RELAY_PUBLIC_ENDPOINT=${IPARS_AGENT_RELAY_PUBLIC_ENDPOINT:-127.0.0.1:51820}"
        ));
        assert!(compose.contains(
            "IPARS_AGENT_RELAY_ADMISSION_URL=${IPARS_AGENT_RELAY_ADMISSION_URL:-http://127.0.0.1:9580}"
        ));
        assert!(compose.contains(
            "IPARS_AGENT_RELAY_STATUS_URL=${IPARS_AGENT_RELAY_STATUS_URL:-http://127.0.0.1:9580}"
        ));
        assert!(compose.contains("IPARS_RELAY_MAX_SESSIONS=${IPARS_RELAY_MAX_SESSIONS:-10000}"));
        assert!(compose
            .contains("IPARS_AGENT_RELAY_MAX_SESSIONS=${IPARS_AGENT_RELAY_MAX_SESSIONS:-10000}"));
        assert!(compose.contains("IPARS_RELAY_MAX_MBPS=${IPARS_RELAY_MAX_MBPS:-1000}"));
        assert!(compose.contains("IPARS_AGENT_RELAY_MAX_MBPS=${IPARS_AGENT_RELAY_MAX_MBPS:-1000}"));
        assert!(compose.contains("IPARS_RELAY_MAX_SESSIONS_PER_NODE"));
        assert!(compose
            .contains("IPARS_RELAY_SESSION_TTL_SECONDS=${IPARS_RELAY_SESSION_TTL_SECONDS:-300}"));
        assert!(compose.contains("IPARS_RELAY_ADMISSION_RATE_LIMIT"));
        assert!(compose.contains("IPARS_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS"));
        assert!(compose
            .contains("IPARS_STUN_ALTERNATE_LISTEN: ${IPARS_STUN_ALTERNATE_LISTEN:-0.0.0.0:3480}"));
        assert!(compose.contains("\"3480:3480/udp\""));
        assert!(compose.contains("--http-listen"));
        assert!(compose.contains("0.0.0.0:3479"));
        assert!(compose.contains("127.0.0.1:3479/healthz"));
        assert!(compose.contains("IPARS_AGENT_RELAY_FORWARDER_ENDPOINT"));
        assert!(compose.contains("IPARS_AGENT_RELAY_FORWARDER_BIND"));
        assert!(compose.contains("IPARS_AGENT_RELAY_FORWARDER_WIREGUARD_ENDPOINT"));
        assert!(compose.contains("IPARS_AGENT_RELAY_FORWARDER_NETNS"));
        assert!(compose.contains(
            "IPARS_AGENT_RELAY_FORWARDER_MAX_SESSIONS=${IPARS_AGENT_RELAY_FORWARDER_MAX_SESSIONS:-1024}"
        ));
        assert!(compose.contains("IPARS_AGENT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS"));
        assert!(compose.contains("IPARS_AGENT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW"));
        assert!(compose.contains("IPARS_AGENT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS"));
        assert!(!compose.contains(
            "${IPARS_DOCKER_API_SOCKET_HOST:-/var/run/docker.sock}:/run/ipars/docker.sock:ro"
        ));
        assert!(discovery_compose.contains("IPARS_DOCKER_API_SOCKET=/run/ipars/docker.sock"));
        assert!(discovery_compose.contains("type: bind"));
        assert!(discovery_compose
            .contains("source: ${IPARS_DOCKER_API_SOCKET_HOST:-/var/run/docker.sock}"));
        assert!(discovery_compose.contains("target: /run/ipars/docker.sock"));
        assert!(discovery_compose.contains("read_only: true"));
        assert!(discovery_compose.contains("create_host_path: false"));
        assert!(rootless_compose.contains("cap_add: !reset []"));
        assert!(rootless_compose.contains("devices: !reset []"));
        assert!(rootless_compose.contains("environment: !override"));
        assert!(rootless_compose.contains("IPARS_AGENT_RUNTIME_BACKEND=dry-run"));
        assert!(rootless_compose.contains(
            "IPARS_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS=${IPARS_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS:-5}"
        ));
        assert!(rootless_compose.contains(
            "IPARS_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS=${IPARS_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS:-120}"
        ));
        assert!(rootless_compose.contains("IPARS_AGENT_DISABLE_PEER_PROBE=true"));
        assert!(rootless_compose
            .contains("IPARS_AGENT_PEER_PROBE_PORT=${IPARS_AGENT_PEER_PROBE_PORT:-51822}"));
        assert!(rootless_compose.contains(
            "IPARS_AGENT_PEER_PROBE_OBSERVATION_MAX_AGE_SECONDS=${IPARS_AGENT_PEER_PROBE_OBSERVATION_MAX_AGE_SECONDS:-120}"
        ));
        assert!(rootless_compose.contains(
            "IPARS_AGENT_RELAY_ADMISSION_BEARER_TOKEN_PATH=/run/secrets/ipars-relay-admission-bearer-token"
        ));
        assert!(rootless_compose.contains("IPARS_AGENT_WIREGUARD_BACKEND=command"));
        assert!(rootless_compose.contains("IPARS_AGENT_ROUTE_BACKEND=command"));
        assert!(rootless_compose.contains("IPARS_AGENT_APPLY_DOCKER_ROUTES=false"));
        assert!(rootless_compose.contains("IPARS_DOCKER_DISCOVER_NETWORKS=false"));
        assert!(!rootless_compose.contains("IPARS_AGENT_USERSPACE_WIREGUARD_COMMAND"));
        assert!(!rootless_compose.contains("IPARS_AGENT_USERSPACE_WIREGUARD_READY_TIMEOUT_SECONDS"));
        assert!(!rootless_compose.contains("IPARS_DOCKER_NETWORKS"));
        assert!(!rootless_compose.contains("IPARS_DOCKER_CONTAINER_CIDRS"));
        assert!(!rootless_compose.contains("IPARS_DOCKER_API_SOCKET"));
        assert!(!rootless_compose.contains("IPARS_AGENT_RELAY_FORWARDER_"));
        assert!(rootless_compose.contains(
            "IPARS_AGENT_RELAY_PUBLIC_ENDPOINT=${IPARS_AGENT_RELAY_PUBLIC_ENDPOINT:-127.0.0.1:51820}"
        ));
        assert!(rootless_compose.contains(
            "IPARS_AGENT_RELAY_ADMISSION_URL=${IPARS_AGENT_RELAY_ADMISSION_URL:-http://127.0.0.1:9580}"
        ));
        assert!(!rootless_compose.contains("IPARS_AGENT_RELAY_FORWARDER_NETNS"));
        Ok(())
    }

    #[test]
    fn docker_install_plan_wires_explicit_api_socket_preflight() -> anyhow::Result<()> {
        let plan = docker_install_plan(DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose.yaml"),
            project_name: "edge".to_string(),
            rootless: false,
            docker_discover_networks: true,
            docker_networks: Vec::new(),
            docker_api_socket: Some(PathBuf::from("/run/user/1000/docker.sock")),
            docker_container_namespace: None,
            docker_host_interface: "docker0".to_string(),
            docker_container_cidrs: Vec::new(),
            disable_docker_expose_host_routes: false,
            docker_route_interval_seconds: 60,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            agent_runtime_backend: "linux-command".to_string(),
            route_backend: "command".to_string(),
            userspace_wireguard_command: None,
            userspace_wireguard_args: Vec::new(),
            userspace_wireguard_ready_timeout_seconds: 10,
            userspace_wireguard_shutdown_timeout_seconds: 5,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_sessions_per_node: DEFAULT_RELAY_MAX_SESSIONS_PER_NODE,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_session_ttl_seconds: DEFAULT_RELAY_SESSION_TTL_SECONDS,
            relay_admission_rate_limit: DEFAULT_RELAY_ADMISSION_RATE_LIMIT,
            relay_admission_rate_limit_window_seconds:
                DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        })?;

        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_API_SOCKET_HOST"),
            Some("/run/user/1000/docker.sock")
        );
        assert!(plan.commands[0].contains("IPARS_DOCKER_API_SOCKET_HOST"));
        assert!(plan.commands[0].contains("/run/user/1000/docker.sock"));
        assert!(plan.commands[0].contains("test ! -L \"$docker_socket\""));
        assert!(plan.commands[0].contains("test -S \"$docker_socket\""));
        assert!(plan.commands[0].contains("case \"$docker_socket\" in /*)"));
        assert!(plan.commands[0]
            .contains("Docker API socket path must be an absolute Unix socket path"));
        assert!(plan.commands[0]
            .contains("Docker API socket path must not contain '.' or '..' path components"));
        assert!(plan.commands[0].contains("docker --host \"unix://$docker_socket\""));
        Ok(())
    }

    #[test]
    fn docker_install_plan_preflights_requested_docker_networks() -> anyhow::Result<()> {
        let plan = docker_install_plan(DockerInstallArgs {
            docker_discover_networks: true,
            docker_networks: vec!["edge_default".to_string(), "edge_backend".to_string()],
            ..docker_install_test_args()
        })?;

        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_NETWORKS"),
            Some("edge_default,edge_backend")
        );
        assert!(plan.commands[0].contains("docker_network=edge_default"));
        assert!(plan.commands[0].contains("docker_network=edge_backend"));
        assert!(plan.commands[0].contains("docker_discovered_subnets=''"));
        assert!(
            plan.commands[0].contains("network inspect \"$docker_network\" --format '{{.Driver}}'")
        );
        assert!(plan.commands[0].contains(
            "network inspect \"$docker_network\" --format '{{range .IPAM.Config}}{{if .Subnet}}{{.Subnet}} {{end}}{{end}}'"
        ));
        assert!(plan.commands[0].contains("was not found"));
        assert!(plan.commands[0].contains("is not a bridge network"));
        assert!(plan.commands[0].contains("has no IPAM subnets"));
        assert!(plan.commands[0].contains(
            "Docker network filters expose duplicate IPAM subnet $docker_network_subnet"
        ));
        Ok(())
    }

    #[test]
    fn docker_install_plan_rejects_ambiguous_or_unused_docker_network_settings(
    ) -> anyhow::Result<()> {
        let ambiguous = match docker_install_plan(DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose.yaml"),
            project_name: "edge".to_string(),
            rootless: false,
            docker_discover_networks: true,
            docker_networks: vec!["edge_default".to_string()],
            docker_api_socket: None,
            docker_container_namespace: None,
            docker_host_interface: "docker0".to_string(),
            docker_container_cidrs: vec!["172.20.0.0/16".parse()?],
            disable_docker_expose_host_routes: false,
            docker_route_interval_seconds: 60,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            agent_runtime_backend: "linux-command".to_string(),
            route_backend: "command".to_string(),
            userspace_wireguard_command: None,
            userspace_wireguard_args: Vec::new(),
            userspace_wireguard_ready_timeout_seconds: 10,
            userspace_wireguard_shutdown_timeout_seconds: 5,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_sessions_per_node: DEFAULT_RELAY_MAX_SESSIONS_PER_NODE,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_session_ttl_seconds: DEFAULT_RELAY_SESSION_TTL_SECONDS,
            relay_admission_rate_limit: DEFAULT_RELAY_ADMISSION_RATE_LIMIT,
            relay_admission_rate_limit_window_seconds:
                DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        }) {
            Ok(_) => anyhow::bail!("ambiguous Docker install settings should be rejected"),
            Err(error) => error,
        };
        assert!(ambiguous
            .to_string()
            .contains("cannot be combined with explicit --docker-container-cidr"));

        let unused_filter = match docker_install_plan(DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose.yaml"),
            project_name: "edge".to_string(),
            rootless: false,
            docker_discover_networks: false,
            docker_networks: vec!["edge_default".to_string()],
            docker_api_socket: None,
            docker_container_namespace: None,
            docker_host_interface: "docker0".to_string(),
            docker_container_cidrs: Vec::new(),
            disable_docker_expose_host_routes: false,
            docker_route_interval_seconds: 60,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            agent_runtime_backend: "linux-command".to_string(),
            route_backend: "command".to_string(),
            userspace_wireguard_command: None,
            userspace_wireguard_args: Vec::new(),
            userspace_wireguard_ready_timeout_seconds: 10,
            userspace_wireguard_shutdown_timeout_seconds: 5,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_sessions_per_node: DEFAULT_RELAY_MAX_SESSIONS_PER_NODE,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_session_ttl_seconds: DEFAULT_RELAY_SESSION_TTL_SECONDS,
            relay_admission_rate_limit: DEFAULT_RELAY_ADMISSION_RATE_LIMIT,
            relay_admission_rate_limit_window_seconds:
                DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        }) {
            Ok(_) => anyhow::bail!("unused Docker network filter should be rejected"),
            Err(error) => error,
        };
        assert!(unused_filter
            .to_string()
            .contains("--docker-network requires --docker-discover-networks"));

        let invalid_filter = match docker_install_plan(DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose.yaml"),
            project_name: "edge".to_string(),
            rootless: false,
            docker_discover_networks: true,
            docker_networks: vec!["edge/default".to_string()],
            docker_api_socket: None,
            docker_container_namespace: None,
            docker_host_interface: "docker0".to_string(),
            docker_container_cidrs: Vec::new(),
            disable_docker_expose_host_routes: false,
            docker_route_interval_seconds: 60,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            agent_runtime_backend: "linux-command".to_string(),
            route_backend: "command".to_string(),
            userspace_wireguard_command: None,
            userspace_wireguard_args: Vec::new(),
            userspace_wireguard_ready_timeout_seconds: 10,
            userspace_wireguard_shutdown_timeout_seconds: 5,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_sessions_per_node: DEFAULT_RELAY_MAX_SESSIONS_PER_NODE,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_session_ttl_seconds: DEFAULT_RELAY_SESSION_TTL_SECONDS,
            relay_admission_rate_limit: DEFAULT_RELAY_ADMISSION_RATE_LIMIT,
            relay_admission_rate_limit_window_seconds:
                DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        }) {
            Ok(_) => anyhow::bail!("invalid Docker network filter should be rejected"),
            Err(error) => error,
        };
        assert!(invalid_filter
            .to_string()
            .contains("must contain only ASCII letters"));

        let duplicate_filter = match docker_install_plan(DockerInstallArgs {
            docker_discover_networks: true,
            docker_networks: vec!["edge_default".to_string(), "edge_default".to_string()],
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("duplicate Docker network filter should be rejected"),
            Err(error) => error,
        };
        assert!(duplicate_filter
            .to_string()
            .contains("--docker-network `edge_default` must not be repeated"));

        let invalid_host_interface = match docker_install_plan(DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose.yaml"),
            project_name: "edge".to_string(),
            rootless: false,
            docker_discover_networks: false,
            docker_networks: Vec::new(),
            docker_api_socket: None,
            docker_container_namespace: None,
            docker_host_interface: "docker/0".to_string(),
            docker_container_cidrs: Vec::new(),
            disable_docker_expose_host_routes: false,
            docker_route_interval_seconds: 60,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            agent_runtime_backend: "linux-command".to_string(),
            route_backend: "command".to_string(),
            userspace_wireguard_command: None,
            userspace_wireguard_args: Vec::new(),
            userspace_wireguard_ready_timeout_seconds: 10,
            userspace_wireguard_shutdown_timeout_seconds: 5,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_sessions_per_node: DEFAULT_RELAY_MAX_SESSIONS_PER_NODE,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_session_ttl_seconds: DEFAULT_RELAY_SESSION_TTL_SECONDS,
            relay_admission_rate_limit: DEFAULT_RELAY_ADMISSION_RATE_LIMIT,
            relay_admission_rate_limit_window_seconds:
                DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        }) {
            Ok(_) => anyhow::bail!("invalid Docker host interface should be rejected"),
            Err(error) => error,
        };
        assert!(invalid_host_interface
            .to_string()
            .contains("linux interface name"));

        for interface in [".", "..", "-docker0"] {
            let invalid_special_interface = match docker_install_plan(DockerInstallArgs {
                docker_host_interface: interface.to_string(),
                ..docker_install_test_args()
            }) {
                Ok(_) => {
                    anyhow::bail!("special Docker host interface {interface} should be rejected")
                }
                Err(error) => error,
            };
            assert!(
                invalid_special_interface
                    .to_string()
                    .contains("linux interface name"),
                "unexpected error for {interface}: {invalid_special_interface}"
            );
        }

        let invalid_namespace = match docker_install_plan(DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose.yaml"),
            project_name: "edge".to_string(),
            rootless: false,
            docker_discover_networks: false,
            docker_networks: Vec::new(),
            docker_api_socket: None,
            docker_container_namespace: Some("../compose".to_string()),
            docker_host_interface: "docker0".to_string(),
            docker_container_cidrs: Vec::new(),
            disable_docker_expose_host_routes: false,
            docker_route_interval_seconds: 60,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            agent_runtime_backend: "linux-command".to_string(),
            route_backend: "command".to_string(),
            userspace_wireguard_command: None,
            userspace_wireguard_args: Vec::new(),
            userspace_wireguard_ready_timeout_seconds: 10,
            userspace_wireguard_shutdown_timeout_seconds: 5,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_sessions_per_node: DEFAULT_RELAY_MAX_SESSIONS_PER_NODE,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_session_ttl_seconds: DEFAULT_RELAY_SESSION_TTL_SECONDS,
            relay_admission_rate_limit: DEFAULT_RELAY_ADMISSION_RATE_LIMIT,
            relay_admission_rate_limit_window_seconds:
                DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        }) {
            Ok(_) => anyhow::bail!("invalid Docker container namespace should be rejected"),
            Err(error) => error,
        };
        assert!(invalid_namespace
            .to_string()
            .contains("linux network namespace name"));

        for namespace in [".", "..", "-compose"] {
            let invalid_special_namespace = match docker_install_plan(DockerInstallArgs {
                docker_container_namespace: Some(namespace.to_string()),
                ..docker_install_test_args()
            }) {
                Ok(_) => {
                    anyhow::bail!(
                        "special Docker container namespace {namespace} should be rejected"
                    )
                }
                Err(error) => error,
            };
            assert!(
                invalid_special_namespace
                    .to_string()
                    .contains("linux network namespace name"),
                "unexpected error for {namespace}: {invalid_special_namespace}"
            );
        }

        let relative_api_socket = match docker_install_plan(DockerInstallArgs {
            docker_discover_networks: true,
            docker_api_socket: Some(PathBuf::from("run/docker.sock")),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("relative Docker API socket path should be rejected"),
            Err(error) => error,
        };
        assert!(relative_api_socket
            .to_string()
            .contains("--docker-api-socket must be an absolute Unix socket path"));

        let dot_component_api_socket = match docker_install_plan(DockerInstallArgs {
            docker_discover_networks: true,
            docker_api_socket: Some(PathBuf::from("/run/user/1000/../docker.sock")),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("dot-component Docker API socket path should be rejected"),
            Err(error) => error,
        };
        assert!(dot_component_api_socket
            .to_string()
            .contains("--docker-api-socket must not contain '.' or '..' path components"));

        let inactive_api_socket = match docker_install_plan(DockerInstallArgs {
            docker_api_socket: Some(PathBuf::from("/run/user/1000/docker.sock")),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("Docker API socket without discovery should be rejected"),
            Err(error) => error,
        };
        assert!(inactive_api_socket
            .to_string()
            .contains("--docker-api-socket requires --docker-discover-networks"));

        let invalid_ready_timeout = match docker_install_plan(DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose.yaml"),
            project_name: "edge".to_string(),
            rootless: true,
            docker_discover_networks: true,
            docker_networks: Vec::new(),
            docker_api_socket: None,
            docker_container_namespace: None,
            docker_host_interface: "docker0".to_string(),
            docker_container_cidrs: Vec::new(),
            disable_docker_expose_host_routes: false,
            docker_route_interval_seconds: 60,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            agent_runtime_backend: "linux-command".to_string(),
            route_backend: "command".to_string(),
            userspace_wireguard_command: Some("wireguard-go".to_string()),
            userspace_wireguard_args: Vec::new(),
            userspace_wireguard_ready_timeout_seconds: 0,
            userspace_wireguard_shutdown_timeout_seconds: 5,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_sessions_per_node: DEFAULT_RELAY_MAX_SESSIONS_PER_NODE,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_session_ttl_seconds: DEFAULT_RELAY_SESSION_TTL_SECONDS,
            relay_admission_rate_limit: DEFAULT_RELAY_ADMISSION_RATE_LIMIT,
            relay_admission_rate_limit_window_seconds:
                DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        }) {
            Ok(_) => anyhow::bail!("zero userspace WireGuard ready timeout should be rejected"),
            Err(error) => error,
        };
        assert!(invalid_ready_timeout
            .to_string()
            .contains("--userspace-wireguard-ready-timeout-seconds"));

        let invalid_shutdown_timeout = match docker_install_plan(DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose.yaml"),
            project_name: "edge".to_string(),
            rootless: true,
            docker_discover_networks: true,
            docker_networks: Vec::new(),
            docker_api_socket: None,
            docker_container_namespace: None,
            docker_host_interface: "docker0".to_string(),
            docker_container_cidrs: Vec::new(),
            disable_docker_expose_host_routes: false,
            docker_route_interval_seconds: 60,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            agent_runtime_backend: "linux-command".to_string(),
            route_backend: "command".to_string(),
            userspace_wireguard_command: Some("wireguard-go".to_string()),
            userspace_wireguard_args: Vec::new(),
            userspace_wireguard_ready_timeout_seconds: 10,
            userspace_wireguard_shutdown_timeout_seconds: 0,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_sessions_per_node: DEFAULT_RELAY_MAX_SESSIONS_PER_NODE,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_session_ttl_seconds: DEFAULT_RELAY_SESSION_TTL_SECONDS,
            relay_admission_rate_limit: DEFAULT_RELAY_ADMISSION_RATE_LIMIT,
            relay_admission_rate_limit_window_seconds:
                DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        }) {
            Ok(_) => anyhow::bail!("zero userspace WireGuard shutdown timeout should be rejected"),
            Err(error) => error,
        };
        assert!(invalid_shutdown_timeout
            .to_string()
            .contains("--userspace-wireguard-shutdown-timeout-seconds"));

        let oversized_ready_timeout = match docker_install_plan(DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose.yaml"),
            project_name: "edge".to_string(),
            rootless: true,
            docker_discover_networks: true,
            docker_networks: Vec::new(),
            docker_api_socket: None,
            docker_container_namespace: None,
            docker_host_interface: "docker0".to_string(),
            docker_container_cidrs: Vec::new(),
            disable_docker_expose_host_routes: false,
            docker_route_interval_seconds: 60,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            agent_runtime_backend: "linux-command".to_string(),
            route_backend: "command".to_string(),
            userspace_wireguard_command: Some("wireguard-go".to_string()),
            userspace_wireguard_args: Vec::new(),
            userspace_wireguard_ready_timeout_seconds: 3601,
            userspace_wireguard_shutdown_timeout_seconds: 5,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_sessions_per_node: DEFAULT_RELAY_MAX_SESSIONS_PER_NODE,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_session_ttl_seconds: DEFAULT_RELAY_SESSION_TTL_SECONDS,
            relay_admission_rate_limit: DEFAULT_RELAY_ADMISSION_RATE_LIMIT,
            relay_admission_rate_limit_window_seconds:
                DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        }) {
            Ok(_) => {
                anyhow::bail!("oversized userspace WireGuard ready timeout should be rejected")
            }
            Err(error) => error,
        };
        assert!(oversized_ready_timeout
            .to_string()
            .contains("--userspace-wireguard-ready-timeout-seconds must not exceed 3600"));

        let oversized_shutdown_timeout = match docker_install_plan(DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose.yaml"),
            project_name: "edge".to_string(),
            rootless: true,
            docker_discover_networks: true,
            docker_networks: Vec::new(),
            docker_api_socket: None,
            docker_container_namespace: None,
            docker_host_interface: "docker0".to_string(),
            docker_container_cidrs: Vec::new(),
            disable_docker_expose_host_routes: false,
            docker_route_interval_seconds: 60,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            agent_runtime_backend: "linux-command".to_string(),
            route_backend: "command".to_string(),
            userspace_wireguard_command: Some("wireguard-go".to_string()),
            userspace_wireguard_args: Vec::new(),
            userspace_wireguard_ready_timeout_seconds: 10,
            userspace_wireguard_shutdown_timeout_seconds: 3601,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_sessions_per_node: DEFAULT_RELAY_MAX_SESSIONS_PER_NODE,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_session_ttl_seconds: DEFAULT_RELAY_SESSION_TTL_SECONDS,
            relay_admission_rate_limit: DEFAULT_RELAY_ADMISSION_RATE_LIMIT,
            relay_admission_rate_limit_window_seconds:
                DEFAULT_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        }) {
            Ok(_) => {
                anyhow::bail!("oversized userspace WireGuard shutdown timeout should be rejected")
            }
            Err(error) => error,
        };
        assert!(oversized_shutdown_timeout
            .to_string()
            .contains("--userspace-wireguard-shutdown-timeout-seconds must not exceed 3600"));

        let relative_command = match docker_install_plan(DockerInstallArgs {
            userspace_wireguard_command: Some("./wireguard-go".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("relative userspace WireGuard command should be rejected"),
            Err(error) => error,
        };
        assert!(relative_command.to_string().contains(
            "--userspace-wireguard-command must be a bare command name or an absolute path"
        ));

        let whitespace_command = match docker_install_plan(DockerInstallArgs {
            userspace_wireguard_command: Some("wireguard go".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("whitespace userspace WireGuard command should be rejected"),
            Err(error) => error,
        };
        assert!(whitespace_command
            .to_string()
            .contains("--userspace-wireguard-command must not contain whitespace"));

        let option_prefixed_command = match docker_install_plan(DockerInstallArgs {
            userspace_wireguard_command: Some("-wireguard-go".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => {
                anyhow::bail!("option-prefixed userspace WireGuard command should be rejected")
            }
            Err(error) => error,
        };
        assert!(option_prefixed_command
            .to_string()
            .contains("--userspace-wireguard-command program name must not start with '-'"));

        let special_command = match docker_install_plan(DockerInstallArgs {
            userspace_wireguard_command: Some(".".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("special userspace WireGuard command should be rejected"),
            Err(error) => error,
        };
        assert!(special_command
            .to_string()
            .contains("--userspace-wireguard-command program name must not be '.' or '..'"));

        let current_component_command = match docker_install_plan(DockerInstallArgs {
            userspace_wireguard_command: Some("/usr/local/./bin/wireguard-go".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => {
                anyhow::bail!("current-component userspace WireGuard command should be rejected")
            }
            Err(error) => error,
        };
        assert!(current_component_command.to_string().contains(
            "--userspace-wireguard-command path must not contain '.' or '..' components"
        ));

        let parent_component_command = match docker_install_plan(DockerInstallArgs {
            userspace_wireguard_command: Some("/usr/local/../bin/wireguard-go".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => {
                anyhow::bail!("parent-component userspace WireGuard command should be rejected")
            }
            Err(error) => error,
        };
        assert!(parent_component_command.to_string().contains(
            "--userspace-wireguard-command path must not contain '.' or '..' components"
        ));

        let oversized_command = match docker_install_plan(DockerInstallArgs {
            userspace_wireguard_command: Some(
                "x".repeat(MAX_USERSPACE_WIREGUARD_COMMAND_BYTES + 1),
            ),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("oversized userspace WireGuard command should be rejected"),
            Err(error) => error,
        };
        assert!(oversized_command
            .to_string()
            .contains("--userspace-wireguard-command exceeds 4096 bytes"));

        let mut too_many_args = Vec::new();
        for index in 0..=MAX_USERSPACE_WIREGUARD_ARGS {
            too_many_args.push(format!("arg-{index}"));
        }
        let too_many_args = match docker_install_plan(DockerInstallArgs {
            userspace_wireguard_command: Some("wireguard-go".to_string()),
            userspace_wireguard_args: too_many_args,
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("too many userspace WireGuard args should be rejected"),
            Err(error) => error,
        };
        assert!(too_many_args
            .to_string()
            .contains("--userspace-wireguard-arg may be repeated at most 128 times"));

        let invalid_arg = match docker_install_plan(DockerInstallArgs {
            userspace_wireguard_command: Some("wireguard-go".to_string()),
            userspace_wireguard_args: vec!["ipars0\n--unexpected".to_string()],
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("control-character userspace WireGuard arg should be rejected"),
            Err(error) => error,
        };
        assert!(invalid_arg
            .to_string()
            .contains("--userspace-wireguard-arg must not contain control characters"));

        let comma_arg = match docker_install_plan(DockerInstallArgs {
            userspace_wireguard_command: Some("wireguard-go".to_string()),
            userspace_wireguard_args: vec!["--option=a,b".to_string()],
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("comma userspace WireGuard arg should be rejected"),
            Err(error) => error,
        };
        assert!(comma_arg.to_string().contains(
            "--userspace-wireguard-arg must not contain ',' because Docker Compose passes"
        ));

        let oversized_arg = match docker_install_plan(DockerInstallArgs {
            userspace_wireguard_command: Some("wireguard-go".to_string()),
            userspace_wireguard_args: vec!["x".repeat(MAX_USERSPACE_WIREGUARD_ARG_BYTES + 1)],
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("oversized userspace WireGuard arg should be rejected"),
            Err(error) => error,
        };
        assert!(oversized_arg
            .to_string()
            .contains("--userspace-wireguard-arg exceeds 4096 bytes"));
        Ok(())
    }

    #[test]
    fn docker_install_plan_rejects_rootless_docker_route_settings() -> anyhow::Result<()> {
        let static_routes = match docker_install_plan(DockerInstallArgs {
            rootless: true,
            docker_container_namespace: Some("compose-edge".to_string()),
            docker_container_cidrs: vec!["172.20.0.0/16".parse()?],
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("rootless static Docker routes should be rejected"),
            Err(error) => error,
        };
        assert!(static_routes
            .to_string()
            .contains("--rootless cannot be combined with Docker route or discovery settings"));

        let discovery = match docker_install_plan(DockerInstallArgs {
            rootless: true,
            docker_discover_networks: true,
            docker_networks: vec!["edge_default".to_string()],
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("rootless Docker discovery should be rejected"),
            Err(error) => error,
        };
        assert!(discovery
            .to_string()
            .contains("--rootless cannot be combined with Docker route or discovery settings"));

        let userspace_command = match docker_install_plan(DockerInstallArgs {
            rootless: true,
            userspace_wireguard_command: Some("wireguard-go".to_string()),
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("rootless userspace WireGuard command should be rejected"),
            Err(error) => error,
        };
        assert!(userspace_command
            .to_string()
            .contains("--rootless does not support --userspace-wireguard-command"));
        Ok(())
    }

    #[test]
    fn docker_install_plan_rejects_unsafe_container_cidrs() -> anyhow::Result<()> {
        let unrestricted = match docker_install_plan(DockerInstallArgs {
            docker_container_cidrs: vec!["0.0.0.0/0".parse()?],
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("unrestricted Docker container CIDR should be rejected"),
            Err(error) => error,
        };
        assert!(unrestricted.to_string().contains(
            "--docker-container-cidr must not include unrestricted Docker container CIDR 0.0.0.0/0"
        ));

        let loopback = match docker_install_plan(DockerInstallArgs {
            docker_container_cidrs: vec!["127.0.0.0/8".parse()?],
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("loopback Docker container CIDR should be rejected"),
            Err(error) => error,
        };
        assert!(loopback.to_string().contains(
            "--docker-container-cidr must not include loopback Docker container CIDR 127.0.0.0/8"
        ));

        let non_canonical = match docker_install_plan(DockerInstallArgs {
            docker_container_cidrs: vec!["172.20.10.1/24".parse()?],
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("non-canonical Docker container CIDR should be rejected"),
            Err(error) => error,
        };
        assert!(non_canonical.to_string().contains(
            "--docker-container-cidr must use canonical Docker container CIDR route 172.20.10.0/24, not 172.20.10.1/24"
        ));

        let duplicate = match docker_install_plan(DockerInstallArgs {
            docker_container_cidrs: vec!["172.20.0.0/16".parse()?, "172.20.0.0/16".parse()?],
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("duplicate Docker container CIDR should be rejected"),
            Err(error) => error,
        };
        assert!(duplicate.to_string().contains(
            "--docker-container-cidr must not repeat Docker container CIDR route 172.20.0.0/16"
        ));

        let overlapping = match docker_install_plan(DockerInstallArgs {
            docker_container_cidrs: vec!["172.20.0.0/16".parse()?, "172.20.10.0/24".parse()?],
            ..docker_install_test_args()
        }) {
            Ok(_) => anyhow::bail!("overlapping Docker container CIDRs should be rejected"),
            Err(error) => error,
        };
        assert!(overlapping.to_string().contains(
            "--docker-container-cidr must not include overlapping Docker container CIDR routes 172.20.0.0/16 and 172.20.10.0/24"
        ));
        Ok(())
    }

    fn environment_value<'a>(plan: &'a InstallPlan, name: &str) -> Option<&'a str> {
        plan.environment
            .iter()
            .find(|environment| environment.name == name)
            .map(|environment| environment.value.as_str())
    }

    #[test]
    fn k8s_install_plan_wires_join_secret_and_optional_services() -> anyhow::Result<()> {
        let plan = k8s_install_plan(K8sInstallArgs {
            release: "edge".to_string(),
            namespace: "edge-system".to_string(),
            chart: PathBuf::from("charts/ipars"),
            chart_name_override: None,
            chart_fullname_override: None,
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            cluster_control_plane_url: None,
            cluster_signal_url: None,
            cluster_stun_endpoint: None,
            image_repository: None,
            image_tag: None,
            image_pull_policy: None,
            image_pull_secrets: Vec::new(),
            agent_privileged: false,
            agent_add_capabilities: vec![
                "NET_ADMIN".to_string(),
                "NET_RAW".to_string(),
                "SYS_ADMIN".to_string(),
            ],
            agent_drop_capabilities: Vec::new(),
            disable_agent_privilege_escalation: false,
            agent_read_only_root_filesystem: false,
            agent_seccomp_profile: None,
            agent_seccomp_localhost_profile: None,
            agent_run_as_user: None,
            agent_run_as_group: None,
            agent_run_as_non_root: false,
            agent_fs_group: None,
            agent_fs_group_change_policy: None,
            agent_supplemental_groups: Vec::new(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            agent_runtime_backend: "linux-command".to_string(),
            agent_wireguard_listen_port: None,
            agent_stun_bind: None,
            route_backend: "command".to_string(),
            disable_agent_peer_map: false,
            agent_peer_map_poll_interval_seconds: 30,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            expose_agent_api: true,
            allow_public_service_exposure: true,
            allow_unrestricted_load_balancer: false,
            allow_cluster_external_traffic_policy: false,
            enable_network_policy: true,
            network_policy_acknowledge_host_network: true,
            disable_rbac: false,
            disable_service_account_creation: false,
            service_account_name: None,
            service_account_annotations: Vec::new(),
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_scheduler_name: None,
            agent_runtime_class: None,
            agent_node_selectors: Vec::new(),
            agent_node_affinity_required: Vec::new(),
            agent_node_affinity_preferred: Vec::new(),
            agent_pod_affinity_required: Vec::new(),
            agent_pod_affinity_preferred: Vec::new(),
            agent_pod_anti_affinity_required: Vec::new(),
            agent_pod_anti_affinity_preferred: Vec::new(),
            agent_tolerations: Vec::new(),
            agent_topology_spreads: Vec::new(),
            disable_agent_host_network: false,
            disable_agent_service_account_token: false,
            agent_dns_policy: None,
            agent_state_host_path: None,
            agent_state_mount_path: None,
            agent_state_host_path_type: None,
            disable_agent_liveness_probe: false,
            disable_agent_readiness_probe: false,
            disable_agent_startup_probe: false,
            agent_probes: K8sProbeArgs::default(),
            agent_pre_stop_sleep_seconds: None,
            agent_termination_grace_period_seconds: None,
            agent_resource_request_cpu: None,
            agent_resource_request_memory: None,
            agent_resource_limit_cpu: None,
            agent_resource_limit_memory: None,
            agent_update_strategy: None,
            agent_rollout_max_unavailable: None,
            agent_rollout_max_surge: None,
            agent_min_ready_seconds: None,
            agent_revision_history_limit: None,
            agent_pdb_min_available: None,
            agent_pdb_max_unavailable: None,
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_cluster_ip: Some("10.96.0.40".parse()?),
            agent_api_secondary_cluster_ip: Some("2001:db8::40".parse()?),
            agent_api_port: Some(9781),
            agent_api_target_port: Some(9790),
            agent_api_node_port: Some(31080),
            agent_api_app_protocol: Some("ipars.io/agent-http".to_string()),
            agent_api_publish_not_ready_addresses: true,
            agent_api_load_balancer_class: Some("example.com/internal-api".to_string()),
            agent_api_load_balancer_ip: Some("198.51.100.10".parse()?),
            agent_api_external_ips: vec!["198.51.100.11".parse()?, "2001:db8::11".parse()?],
            agent_api_health_check_node_port: Some(31081),
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: Some("RequireDualStack".to_string()),
            agent_api_ip_families: vec!["IPv4".to_string(), "IPv6".to_string()],
            agent_api_allow_source_cidrs: vec!["198.51.100.0/24".parse()?],
            agent_api_network_policy_cidrs: vec!["198.51.100.0/24".parse()?],
            agent_api_internal_traffic_policy: Some("Local".to_string()),
            agent_api_traffic_distribution: Some("PreferSameNode".to_string()),
            agent_api_session_affinity: Some("ClientIP".to_string()),
            agent_api_session_affinity_timeout_seconds: Some(600),
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: vec![KeyValueArg {
                key: "example.com/lb-profile".to_string(),
                value: "public,api".to_string(),
            }],
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_cluster_ip: Some("2001:db8::41".parse()?),
            relay_secondary_cluster_ip: Some("10.96.0.41".parse()?),
            relay_udp_port: Some(51821),
            relay_udp_target_port: Some(51820),
            relay_http_port: Some(9581),
            relay_http_target_port: Some(9580),
            relay_udp_node_port: Some(31820),
            relay_http_node_port: Some(31580),
            relay_udp_app_protocol: Some("ipars.io/relay-udp".to_string()),
            relay_http_app_protocol: Some("http".to_string()),
            relay_publish_not_ready_addresses: true,
            relay_load_balancer_class: Some("example.com/internal-relay".to_string()),
            relay_load_balancer_ip: Some("203.0.113.10".parse()?),
            relay_external_ips: vec!["203.0.113.11".parse()?],
            relay_health_check_node_port: Some(31821),
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: Some("PreferDualStack".to_string()),
            relay_ip_families: vec!["IPv6".to_string(), "IPv4".to_string()],
            relay_allow_source_cidrs: vec!["203.0.113.0/24".parse()?],
            relay_network_policy_cidrs: vec!["203.0.113.0/24".parse()?],
            relay_internal_traffic_policy: Some("Cluster".to_string()),
            relay_traffic_distribution: Some("PreferSameZone".to_string()),
            relay_session_affinity: Some("ClientIP".to_string()),
            relay_session_affinity_timeout_seconds: Some(900),
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: vec![KeyValueArg {
                key: "example.com/relay-profile".to_string(),
                value: "public".to_string(),
            }],
            relay_admission_bearer_token_secret: Some("relay-admission-token".to_string()),
            relay_admission_bearer_token_key: Some("token".to_string()),
            relay_public_endpoint: Some("203.0.113.10:51820".to_string()),
            relay_admission_url: Some("http://203.0.113.10:9580".to_string()),
            relay_status_url: Some("http://203.0.113.10:9580".to_string()),
            relay_max_sessions: 4321,
            relay_max_mbps: 876,
            relay_forwarder_endpoint: Some("127.0.0.1:45182".to_string()),
            relay_forwarder_bind: Some("0.0.0.0:45182".to_string()),
            relay_forwarder_wireguard_endpoint: Some("127.0.0.1:51820".to_string()),
            relay_forwarder_netns: Some("relay-fw".to_string()),
            relay_forwarder_max_sessions: 7,
            relay_forwarder_restart_backoff_seconds: 11,
            relay_forwarder_crash_window_seconds: 22,
            relay_forwarder_max_crashes_per_window: 4,
            relay_forwarder_crash_cooldown_seconds: 33,
        })?;

        assert_eq!(plan.platform, "kubernetes-helm");
        assert_eq!(plan.manifest, "charts/ipars");
        assert!(plan
            .prerequisites
            .iter()
            .any(|requirement| requirement.contains("net.ipv4.ip_forward")));
        assert_eq!(
            plan.commands[1],
            "kubectl -n edge-system create secret generic edge-token --from-file=signed-token=./join.token --from-file=agent-api-token=./agent-api.token --dry-run=client -o yaml | kubectl apply -f -"
        );
        assert!(plan.commands[2].contains("helm upgrade --install edge"));
        assert!(plan.commands[2].contains("--set agent.apiBearerTokenSecretKey=agent-api-token"));
        assert!(plan.commands[2].contains("--set serviceExposure.discoverApiServer=true"));
        assert!(plan.commands[2].contains("--set serviceExposure.routeIntervalSeconds=60"));
        assert!(plan.commands[2].contains("--set agent.routeBackend=command"));
        assert!(plan.commands[2].contains("--set agent.peerMap.pollIntervalSeconds=30"));
        assert!(plan.commands[2].contains("--set networkPolicy.enabled=true"));
        assert!(plan.commands[2].contains("--set networkPolicy.acknowledgeHostNetwork=true"));
        assert!(plan.commands[2].contains("--set networkPolicy.agentApi.enabled=true"));
        assert!(plan.commands[2]
            .contains("--set-string 'networkPolicy.agentApi.allowedCidrs[0]=198.51.100.0/24'"));
        assert!(plan.commands[2].contains("--set agent.apiService.enabled=true"));
        assert!(plan.commands[2].contains("--set agent.apiService.type=LoadBalancer"));
        assert!(plan.commands[2].contains("--set-string agent.apiService.clusterIP=10.96.0.40"));
        assert!(
            plan.commands[2].contains("--set-string 'agent.apiService.clusterIPs[0]=10.96.0.40'")
        );
        assert!(
            plan.commands[2].contains("--set-string 'agent.apiService.clusterIPs[1]=2001:db8::40'")
        );
        assert!(plan.commands[2].contains("--set agent.apiService.port=9781"));
        assert!(plan.commands[2].contains("--set agent.apiService.targetPort=9790"));
        assert!(plan.commands[2].contains("--set agent.apiService.nodePort=31080"));
        assert!(plan.commands[2]
            .contains("--set-string agent.apiService.appProtocol=ipars.io/agent-http"));
        assert!(plan.commands[2].contains("--set agent.apiService.publishNotReadyAddresses=true"));
        assert!(plan.commands[2]
            .contains("--set-string agent.apiService.loadBalancerClass=example.com/internal-api"));
        assert!(
            plan.commands[2].contains("--set-string agent.apiService.loadBalancerIP=198.51.100.10")
        );
        assert!(plan.commands[2]
            .contains("--set-string 'agent.apiService.externalIPs[0]=198.51.100.11'"));
        assert!(plan.commands[2]
            .contains("--set-string 'agent.apiService.externalIPs[1]=2001:db8::11'"));
        assert!(plan.commands[2].contains("--set agent.apiService.healthCheckNodePort=31081"));
        assert!(plan.commands[2].contains("--set agent.apiService.ipFamilyPolicy=RequireDualStack"));
        assert!(plan.commands[2].contains("--set-string 'agent.apiService.ipFamilies[0]=IPv4'"));
        assert!(plan.commands[2].contains("--set-string 'agent.apiService.ipFamilies[1]=IPv6'"));
        assert!(plan.commands[2].contains("--set agent.apiService.internalTrafficPolicy=Local"));
        assert!(
            plan.commands[2].contains("--set agent.apiService.trafficDistribution=PreferSameNode")
        );
        assert!(plan.commands[2].contains("--set agent.apiService.sessionAffinity=ClientIP"));
        assert!(
            plan.commands[2].contains("--set agent.apiService.sessionAffinityTimeoutSeconds=600")
        );
        assert!(plan.commands[2].contains("--set agent.apiService.exposureAcknowledged=true"));
        assert!(plan.commands[2].contains("--set agent.apiService.externalTrafficPolicy=Local"));
        assert!(plan.commands[2].contains(
            "--set-string 'agent.apiService.loadBalancerSourceRanges[0]=198.51.100.0/24'"
        ));
        assert!(plan.commands[2].contains(
            "--set-string 'agent.apiService.annotations.example\\.com/lb-profile=public\\,api'"
        ));
        assert!(plan.commands[2].contains("--set agent.relayService.enabled=true"));
        assert!(plan.commands[2].contains("--set networkPolicy.relay.enabled=true"));
        assert!(plan.commands[2]
            .contains("--set-string 'networkPolicy.relay.allowedCidrs[0]=203.0.113.0/24'"));
        assert!(plan.commands[2].contains("--set agent.relayService.type=LoadBalancer"));
        assert!(plan.commands[2].contains("--set-string agent.relayService.clusterIP=2001:db8::41"));
        assert!(plan.commands[2]
            .contains("--set-string 'agent.relayService.clusterIPs[0]=2001:db8::41'"));
        assert!(
            plan.commands[2].contains("--set-string 'agent.relayService.clusterIPs[1]=10.96.0.41'")
        );
        assert!(plan.commands[2].contains("--set agent.relayService.udpPort=51821"));
        assert!(plan.commands[2].contains("--set agent.relayService.udpTargetPort=51820"));
        assert!(plan.commands[2].contains("--set agent.relayService.httpPort=9581"));
        assert!(plan.commands[2].contains("--set agent.relayService.httpTargetPort=9580"));
        assert!(plan.commands[2].contains("--set agent.relayService.udpNodePort=31820"));
        assert!(plan.commands[2].contains("--set agent.relayService.httpNodePort=31580"));
        assert!(plan.commands[2]
            .contains("--set-string agent.relayService.udpAppProtocol=ipars.io/relay-udp"));
        assert!(plan.commands[2].contains("--set-string agent.relayService.httpAppProtocol=http"));
        assert!(plan.commands[2].contains("--set agent.relayService.publishNotReadyAddresses=true"));
        assert!(plan.commands[2].contains(
            "--set-string agent.relayService.loadBalancerClass=example.com/internal-relay"
        ));
        assert!(plan.commands[2]
            .contains("--set-string agent.relayService.loadBalancerIP=203.0.113.10"));
        assert!(plan.commands[2]
            .contains("--set-string 'agent.relayService.externalIPs[0]=203.0.113.11'"));
        assert!(plan.commands[2].contains("--set agent.relayService.healthCheckNodePort=31821"));
        assert!(
            plan.commands[2].contains("--set agent.relayService.ipFamilyPolicy=PreferDualStack")
        );
        assert!(plan.commands[2].contains("--set-string 'agent.relayService.ipFamilies[0]=IPv6'"));
        assert!(plan.commands[2].contains("--set-string 'agent.relayService.ipFamilies[1]=IPv4'"));
        assert!(plan.commands[2].contains("--set agent.relayService.internalTrafficPolicy=Cluster"));
        assert!(plan.commands[2]
            .contains("--set agent.relayService.trafficDistribution=PreferSameZone"));
        assert!(plan.commands[2].contains("--set agent.relayService.sessionAffinity=ClientIP"));
        assert!(
            plan.commands[2].contains("--set agent.relayService.sessionAffinityTimeoutSeconds=900")
        );
        assert!(plan.commands[2].contains("--set agent.relayService.exposureAcknowledged=true"));
        assert!(plan.commands[2].contains("--set agent.relayService.externalTrafficPolicy=Local"));
        assert!(plan.commands[2].contains(
            "--set-string 'agent.relayService.loadBalancerSourceRanges[0]=203.0.113.0/24'"
        ));
        assert!(plan.commands[2]
            .contains("--set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820"));
        assert!(plan.commands[2].contains(
            "--set-string agent.relayAdvertisement.admissionUrl=http://203.0.113.10:9580"
        ));
        assert!(plan.commands[2]
            .contains("--set-string agent.relayAdvertisement.statusUrl=http://203.0.113.10:9580"));
        assert!(plan.commands[2].contains("--set agent.relayAdvertisement.maxSessions=4321"));
        assert!(plan.commands[2].contains("--set agent.relayAdvertisement.maxMbps=876"));
        assert!(plan.commands[2].contains(
            "--set-string agent.relayAdmissionBearerTokenSecret.name=relay-admission-token"
        ));
        assert!(plan.commands[2]
            .contains("--set-string agent.relayAdmissionBearerTokenSecret.key=token"));
        assert!(plan.commands[2].contains(
            "--set-string 'agent.relayService.annotations.example\\.com/relay-profile=public'"
        ));
        assert!(plan.commands[2].contains("--set agent.relayForwarder.enabled=true"));
        assert!(
            plan.commands[2].contains("--set-string agent.relayForwarder.endpoint=127.0.0.1:45182")
        );
        assert!(plan.commands[2].contains("--set-string agent.relayForwarder.bind=0.0.0.0:45182"));
        assert!(plan.commands[2]
            .contains("--set-string agent.relayForwarder.wireguardEndpoint=127.0.0.1:51820"));
        assert!(plan.commands[2].contains("--set-string agent.relayForwarder.netns=relay-fw"));
        assert!(plan.commands[2].contains("--set agent.relayForwarder.maxSessions=7"));
        assert!(plan.commands[2].contains("--set agent.relayForwarder.restartBackoffSeconds=11"));
        assert!(plan.commands[2].contains("--set agent.relayForwarder.crashWindowSeconds=22"));
        assert!(plan.commands[2].contains("--set agent.relayForwarder.maxCrashesPerWindow=4"));
        assert!(plan.commands[2].contains("--set agent.relayForwarder.crashCooldownSeconds=33"));
        assert!(plan.commands[2].contains(
            "--set 'agent.securityContext.capabilities.add={NET_ADMIN,NET_RAW,SYS_ADMIN}'"
        ));
        assert!(plan
            .security
            .iter()
            .any(|requirement| requirement.contains("disabled by default")));
        Ok(())
    }

    #[test]
    fn k8s_install_plan_wires_cluster_endpoints() -> anyhow::Result<()> {
        assert_eq!(
            parse_kubernetes_http_api_base_url("https://control.example.com:8443/")
                .map_err(anyhow::Error::msg)?,
            "https://control.example.com:8443"
        );
        assert!(
            parse_kubernetes_http_api_base_url("https://user:pass@control.example.com:8443")
                .is_err()
        );
        assert!(parse_kubernetes_stun_endpoint("0.0.0.0:3478").is_err());

        let mut args = base_k8s_install_args();
        args.cluster_control_plane_url = Some("https://control.example.com:8443".to_string());
        args.cluster_signal_url = Some("https://signal.example.com:9443".to_string());
        args.cluster_stun_endpoint = Some("203.0.113.53:3478".to_string());

        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];

        assert!(
            helm.contains("--set-string cluster.controlPlaneUrl=https://control.example.com:8443")
        );
        assert!(helm.contains("--set-string cluster.signalUrl=https://signal.example.com:9443"));
        assert!(helm.contains("--set-string cluster.stunEndpoint=203.0.113.53:3478"));

        let mut userinfo = base_k8s_install_args();
        userinfo.cluster_signal_url = Some("https://user:pass@signal.example.com:9443".to_string());
        let error = match k8s_install_plan(userinfo) {
            Ok(_) => anyhow::bail!("cluster signal URL userinfo should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--cluster-signal-url must not include userinfo"));
        Ok(())
    }

    #[test]
    fn k8s_install_validates_service_annotations_from_plan_args() -> anyhow::Result<()> {
        let mut missing_agent_exposure = base_k8s_install_args();
        missing_agent_exposure.agent_api_service_annotations = vec![KeyValueArg {
            key: "example.com/lb-profile".to_string(),
            value: "public".to_string(),
        }];
        let error = match k8s_install_plan(missing_agent_exposure) {
            Ok(_) => panic!("agent API Service annotations should require exposed service"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-service-annotation requires --expose-agent-api"));

        let mut invalid_agent_key = base_k8s_install_args();
        invalid_agent_key.expose_agent_api = true;
        invalid_agent_key.agent_api_service_annotations = vec![KeyValueArg {
            key: "Example.com/lb".to_string(),
            value: "nlb".to_string(),
        }];
        let error = match k8s_install_plan(invalid_agent_key) {
            Ok(_) => panic!("invalid agent API Service annotation key should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-service-annotation annotation prefix"));

        let mut duplicate_agent_key = base_k8s_install_args();
        duplicate_agent_key.expose_agent_api = true;
        duplicate_agent_key.agent_api_service_annotations = vec![
            KeyValueArg {
                key: "service.beta.kubernetes.io/aws-load-balancer-type".to_string(),
                value: "nlb".to_string(),
            },
            KeyValueArg {
                key: "service.beta.kubernetes.io/aws-load-balancer-type".to_string(),
                value: "nlb-ip".to_string(),
            },
        ];
        let error = match k8s_install_plan(duplicate_agent_key) {
            Ok(_) => panic!("duplicate agent API Service annotation keys should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation must not repeat annotation key service.beta.kubernetes.io/aws-load-balancer-type"
        ));

        let mut agent_source_range_annotation = base_k8s_install_args();
        agent_source_range_annotation.expose_agent_api = true;
        agent_source_range_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/load-balancer-source-ranges".to_string(),
            value: "198.51.100.0/24".to_string(),
        }];
        let error = match k8s_install_plan(agent_source_range_annotation) {
            Ok(_) => panic!("agent API source range annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/load-balancer-source-ranges must not configure LoadBalancer source ranges"
        ));

        let mut agent_fixed_ip_annotation = base_k8s_install_args();
        agent_fixed_ip_annotation.expose_agent_api = true;
        agent_fixed_ip_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "metallb.io/loadBalancerIPs".to_string(),
            value: "198.51.100.10".to_string(),
        }];
        let error = match k8s_install_plan(agent_fixed_ip_annotation) {
            Ok(_) => panic!("agent API fixed IP annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key metallb.io/loadBalancerIPs must not configure LoadBalancer fixed addresses"
        ));

        let mut agent_openstack_address_annotation = base_k8s_install_args();
        agent_openstack_address_annotation.expose_agent_api = true;
        agent_openstack_address_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "loadbalancer.openstack.org/load-balancer-address".to_string(),
            value: "198.51.100.15".to_string(),
        }];
        let error = match k8s_install_plan(agent_openstack_address_annotation) {
            Ok(_) => panic!("agent API OpenStack address annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key loadbalancer.openstack.org/load-balancer-address must not configure LoadBalancer fixed addresses"
        ));

        let mut agent_pip_prefix_annotation = base_k8s_install_args();
        agent_pip_prefix_annotation.expose_agent_api = true;
        agent_pip_prefix_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/azure-pip-prefix-id".to_string(),
            value: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/edge/providers/Microsoft.Network/publicIPPrefixes/prefix".to_string(),
        }];
        let error = match k8s_install_plan(agent_pip_prefix_annotation) {
            Ok(_) => panic!("agent API public IP prefix annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/azure-pip-prefix-id must not configure LoadBalancer fixed addresses"
        ));

        let mut agent_proxy_protocol_annotation = base_k8s_install_args();
        agent_proxy_protocol_annotation.expose_agent_api = true;
        agent_proxy_protocol_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-proxy-protocol".to_string(),
            value: "*".to_string(),
        }];
        let error = match k8s_install_plan(agent_proxy_protocol_annotation) {
            Ok(_) => panic!("agent API PROXY protocol annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-proxy-protocol must not enable PROXY protocol"
        ));

        let mut agent_health_check_annotation = base_k8s_install_args();
        agent_health_check_annotation.expose_agent_api = true;
        agent_health_check_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-healthcheck-port".to_string(),
            value: "traffic-port".to_string(),
        }];
        let error = match k8s_install_plan(agent_health_check_annotation) {
            Ok(_) => panic!("agent API health-check annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-healthcheck-port must not configure LoadBalancer health checks"
        ));

        let mut agent_tls_listener_annotation = base_k8s_install_args();
        agent_tls_listener_annotation.expose_agent_api = true;
        agent_tls_listener_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-ssl-cert".to_string(),
            value: "arn:aws:acm:us-east-1:123456789012:certificate/abcdef".to_string(),
        }];
        let error = match k8s_install_plan(agent_tls_listener_annotation) {
            Ok(_) => panic!("agent API TLS listener annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-ssl-cert must not configure LoadBalancer TLS, listeners, or backend protocols"
        ));

        let mut agent_do_protocol_annotation = base_k8s_install_args();
        agent_do_protocol_annotation.expose_agent_api = true;
        agent_do_protocol_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/do-loadbalancer-protocol".to_string(),
            value: "http".to_string(),
        }];
        let error = match k8s_install_plan(agent_do_protocol_annotation) {
            Ok(_) => panic!("agent API DigitalOcean protocol annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/do-loadbalancer-protocol must not configure LoadBalancer TLS, listeners, or backend protocols"
        ));

        let mut agent_ha_ports_annotation = base_k8s_install_args();
        agent_ha_ports_annotation.expose_agent_api = true;
        agent_ha_ports_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/azure-load-balancer-enable-high-availability-ports"
                .to_string(),
            value: "true".to_string(),
        }];
        let error = match k8s_install_plan(agent_ha_ports_annotation) {
            Ok(_) => panic!("agent API high-availability ports annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/azure-load-balancer-enable-high-availability-ports must not configure LoadBalancer TLS, listeners, or backend protocols"
        ));

        let mut agent_lb_scope_annotation = base_k8s_install_args();
        agent_lb_scope_annotation.expose_agent_api = true;
        agent_lb_scope_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-scheme".to_string(),
            value: "internet-facing".to_string(),
        }];
        let error = match k8s_install_plan(agent_lb_scope_annotation) {
            Ok(_) => panic!("agent API LoadBalancer scope annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-scheme must not configure LoadBalancer scope or implementation type"
        ));

        let mut agent_oci_shape_annotation = base_k8s_install_args();
        agent_oci_shape_annotation.expose_agent_api = true;
        agent_oci_shape_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "oci.oraclecloud.com/load-balancer-shape".to_string(),
            value: "flexible".to_string(),
        }];
        let error = match k8s_install_plan(agent_oci_shape_annotation) {
            Ok(_) => panic!("agent API OCI shape annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key oci.oraclecloud.com/load-balancer-shape must not configure LoadBalancer scope or implementation type"
        ));

        let mut agent_global_access_annotation = base_k8s_install_args();
        agent_global_access_annotation.expose_agent_api = true;
        agent_global_access_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "networking.gke.io/load-balancer-allow-global-access".to_string(),
            value: "true".to_string(),
        }];
        let error = match k8s_install_plan(agent_global_access_annotation) {
            Ok(_) => panic!("agent API LoadBalancer global access annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key networking.gke.io/load-balancer-allow-global-access must not configure LoadBalancer scope or implementation type"
        ));

        let mut agent_l4_rbs_annotation = base_k8s_install_args();
        agent_l4_rbs_annotation.expose_agent_api = true;
        agent_l4_rbs_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "cloud.google.com/l4-rbs".to_string(),
            value: "enabled".to_string(),
        }];
        let error = match k8s_install_plan(agent_l4_rbs_annotation) {
            Ok(_) => panic!("agent API L4 RBS annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key cloud.google.com/l4-rbs must not configure LoadBalancer scope or implementation type"
        ));

        let mut agent_security_group_annotation = base_k8s_install_args();
        agent_security_group_annotation.expose_agent_api = true;
        agent_security_group_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-security-groups".to_string(),
            value: "sg-0123456789abcdef0".to_string(),
        }];
        let error = match k8s_install_plan(agent_security_group_annotation) {
            Ok(_) => panic!("agent API security group annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-security-groups must not configure LoadBalancer firewall or security groups"
        ));

        let mut agent_waf_annotation = base_k8s_install_args();
        agent_waf_annotation.expose_agent_api = true;
        agent_waf_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-enable-waf".to_string(),
            value: "true".to_string(),
        }];
        let error = match k8s_install_plan(agent_waf_annotation) {
            Ok(_) => panic!("agent API WAF annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-enable-waf must not configure LoadBalancer firewall or security groups"
        ));

        let mut agent_web_acl_annotation = base_k8s_install_args();
        agent_web_acl_annotation.expose_agent_api = true;
        agent_web_acl_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "example.com/load-balancer-web-acl".to_string(),
            value: "web-acl-0123456789abcdef0".to_string(),
        }];
        let error = match k8s_install_plan(agent_web_acl_annotation) {
            Ok(_) => panic!("agent API Web ACL annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key example.com/load-balancer-web-acl must not configure LoadBalancer firewall or security groups"
        ));

        let mut agent_subnet_annotation = base_k8s_install_args();
        agent_subnet_annotation.expose_agent_api = true;
        agent_subnet_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-subnets".to_string(),
            value: "subnet-0123456789abcdef0".to_string(),
        }];
        let error = match k8s_install_plan(agent_subnet_annotation) {
            Ok(_) => panic!("agent API subnet annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-subnets must not configure LoadBalancer network placement"
        ));

        let mut agent_lb_attributes_annotation = base_k8s_install_args();
        agent_lb_attributes_annotation.expose_agent_api = true;
        agent_lb_attributes_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-attributes".to_string(),
            value: "deletion_protection.enabled=true".to_string(),
        }];
        let error = match k8s_install_plan(agent_lb_attributes_annotation) {
            Ok(_) => panic!("agent API LoadBalancer attributes annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-attributes must not configure LoadBalancer operational attributes"
        ));

        let mut agent_backend_config_annotation = base_k8s_install_args();
        agent_backend_config_annotation.expose_agent_api = true;
        agent_backend_config_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "cloud.google.com/backend-config".to_string(),
            value: "{\"default\":\"ipars-backend\"}".to_string(),
        }];
        let error = match k8s_install_plan(agent_backend_config_annotation) {
            Ok(_) => panic!("agent API backend config annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key cloud.google.com/backend-config must not configure LoadBalancer operational attributes"
        ));

        let mut agent_tcp_reset_annotation = base_k8s_install_args();
        agent_tcp_reset_annotation.expose_agent_api = true;
        agent_tcp_reset_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/azure-load-balancer-disable-tcp-reset".to_string(),
            value: "true".to_string(),
        }];
        let error = match k8s_install_plan(agent_tcp_reset_annotation) {
            Ok(_) => panic!("agent API TCP reset annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/azure-load-balancer-disable-tcp-reset must not configure LoadBalancer operational attributes"
        ));

        let mut agent_dns_publication_annotation = base_k8s_install_args();
        agent_dns_publication_annotation.expose_agent_api = true;
        agent_dns_publication_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "external-dns.alpha.kubernetes.io/hostname".to_string(),
            value: "api.example.com".to_string(),
        }];
        let error = match k8s_install_plan(agent_dns_publication_annotation) {
            Ok(_) => panic!("agent API DNS publication annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key external-dns.alpha.kubernetes.io/hostname must not publish LoadBalancer DNS names"
        ));

        let mut agent_resource_name_annotation = base_k8s_install_args();
        agent_resource_name_annotation.expose_agent_api = true;
        agent_resource_name_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-name".to_string(),
            value: "edge-api".to_string(),
        }];
        let error = match k8s_install_plan(agent_resource_name_annotation) {
            Ok(_) => panic!("agent API LoadBalancer resource name annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-name must not configure LoadBalancer resource identity, tags, or address pools"
        ));

        let mut agent_load_balancer_mode_annotation = base_k8s_install_args();
        agent_load_balancer_mode_annotation.expose_agent_api = true;
        agent_load_balancer_mode_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/azure-load-balancer-mode".to_string(),
            value: "__auto__".to_string(),
        }];
        let error = match k8s_install_plan(agent_load_balancer_mode_annotation) {
            Ok(_) => panic!("agent API LoadBalancer mode annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/azure-load-balancer-mode must not configure LoadBalancer resource identity, tags, or address pools"
        ));

        let mut agent_private_link_annotation = base_k8s_install_args();
        agent_private_link_annotation.expose_agent_api = true;
        agent_private_link_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/azure-pls-create".to_string(),
            value: "true".to_string(),
        }];
        let error = match k8s_install_plan(agent_private_link_annotation) {
            Ok(_) => panic!("agent API Private Link annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/azure-pls-create must not configure LoadBalancer Private Link or endpoint-service publishing"
        ));

        let mut agent_target_node_annotation = base_k8s_install_args();
        agent_target_node_annotation.expose_agent_api = true;
        agent_target_node_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-target-node-labels".to_string(),
            value: "ipars.io/edge=true".to_string(),
        }];
        let error = match k8s_install_plan(agent_target_node_annotation) {
            Ok(_) => panic!("agent API target-node annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-target-node-labels must not configure LoadBalancer backend target selection"
        ));

        let mut agent_source_nat_annotation = base_k8s_install_args();
        agent_source_nat_annotation.expose_agent_api = true;
        agent_source_nat_annotation.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/azure-disable-load-balancer-snat".to_string(),
            value: "true".to_string(),
        }];
        let error = match k8s_install_plan(agent_source_nat_annotation) {
            Ok(_) => panic!("agent API source NAT annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-service-annotation annotation key service.beta.kubernetes.io/azure-disable-load-balancer-snat must not configure LoadBalancer source NAT behavior"
        ));

        let mut invalid_relay_value = base_k8s_install_args();
        invalid_relay_value.expose_relay = true;
        invalid_relay_value.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        invalid_relay_value.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        invalid_relay_value.relay_service_annotations = vec![KeyValueArg {
            key: "metallb.universe.tf/address-pool".to_string(),
            value: "public pool".to_string(),
        }];
        let error = match k8s_install_plan(invalid_relay_value) {
            Ok(_) => panic!("relay Service annotation value whitespace should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("--relay-service-annotation annotation value cannot contain whitespace")
        );

        let mut oversized_agent_value = base_k8s_install_args();
        oversized_agent_value.expose_agent_api = true;
        oversized_agent_value.agent_api_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-name".to_string(),
            value: "a".repeat(KUBERNETES_ANNOTATION_VALUE_MAX_BYTES + 1),
        }];
        let error = match k8s_install_plan(oversized_agent_value) {
            Ok(_) => panic!("oversized agent API Service annotation value should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("--agent-api-service-annotation annotation value exceeds 262144 bytes")
        );

        let mut duplicate_relay_key = base_k8s_install_args();
        duplicate_relay_key.expose_relay = true;
        duplicate_relay_key.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        duplicate_relay_key.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        duplicate_relay_key.relay_service_annotations = vec![
            KeyValueArg {
                key: "metallb.universe.tf/address-pool".to_string(),
                value: "public".to_string(),
            },
            KeyValueArg {
                key: "metallb.universe.tf/address-pool".to_string(),
                value: "private".to_string(),
            },
        ];
        let error = match k8s_install_plan(duplicate_relay_key) {
            Ok(_) => panic!("duplicate relay Service annotation keys should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation must not repeat annotation key metallb.universe.tf/address-pool"
        ));

        let mut relay_inbound_cidr_annotation = base_k8s_install_args();
        relay_inbound_cidr_annotation.expose_relay = true;
        relay_inbound_cidr_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_inbound_cidr_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_inbound_cidr_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-inbound-cidrs".to_string(),
            value: "203.0.113.0/24".to_string(),
        }];
        let error = match k8s_install_plan(relay_inbound_cidr_annotation) {
            Ok(_) => panic!("relay inbound CIDR annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-inbound-cidrs must not configure LoadBalancer source ranges"
        ));

        let mut relay_eip_annotation = base_k8s_install_args();
        relay_eip_annotation.expose_relay = true;
        relay_eip_annotation.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        relay_eip_annotation.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        relay_eip_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-eip-allocations".to_string(),
            value: "eipalloc-0123456789abcdef0".to_string(),
        }];
        let error = match k8s_install_plan(relay_eip_annotation) {
            Ok(_) => panic!("relay EIP annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-eip-allocations must not configure LoadBalancer fixed addresses"
        ));

        let mut relay_additional_public_ips_annotation = base_k8s_install_args();
        relay_additional_public_ips_annotation.expose_relay = true;
        relay_additional_public_ips_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_additional_public_ips_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_additional_public_ips_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/azure-additional-public-ips".to_string(),
            value: "198.51.100.80".to_string(),
        }];
        let error = match k8s_install_plan(relay_additional_public_ips_annotation) {
            Ok(_) => panic!("relay additional public IPs annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key service.beta.kubernetes.io/azure-additional-public-ips must not configure LoadBalancer fixed addresses"
        ));

        let mut relay_proxy_protocol_annotation = base_k8s_install_args();
        relay_proxy_protocol_annotation.expose_relay = true;
        relay_proxy_protocol_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_proxy_protocol_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_proxy_protocol_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "haproxy.org/proxy-protocol".to_string(),
            value: "v2".to_string(),
        }];
        let error = match k8s_install_plan(relay_proxy_protocol_annotation) {
            Ok(_) => panic!("relay PROXY protocol annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key haproxy.org/proxy-protocol must not enable PROXY protocol"
        ));

        let mut relay_health_probe_annotation = base_k8s_install_args();
        relay_health_probe_annotation.expose_relay = true;
        relay_health_probe_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_health_probe_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_health_probe_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/azure-load-balancer-health-probe-request-path"
                .to_string(),
            value: "/healthz".to_string(),
        }];
        let error = match k8s_install_plan(relay_health_probe_annotation) {
            Ok(_) => panic!("relay health-probe annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key service.beta.kubernetes.io/azure-load-balancer-health-probe-request-path must not configure LoadBalancer health checks"
        ));

        let mut relay_backend_protocol_annotation = base_k8s_install_args();
        relay_backend_protocol_annotation.expose_relay = true;
        relay_backend_protocol_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_backend_protocol_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_backend_protocol_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-backend-protocol".to_string(),
            value: "ssl".to_string(),
        }];
        let error = match k8s_install_plan(relay_backend_protocol_annotation) {
            Ok(_) => panic!("relay backend protocol annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-backend-protocol must not configure LoadBalancer TLS, listeners, or backend protocols"
        ));

        let mut relay_lb_type_annotation = base_k8s_install_args();
        relay_lb_type_annotation.expose_relay = true;
        relay_lb_type_annotation.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        relay_lb_type_annotation.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        relay_lb_type_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "cloud.google.com/load-balancer-type".to_string(),
            value: "Internal".to_string(),
        }];
        let error = match k8s_install_plan(relay_lb_type_annotation) {
            Ok(_) => panic!("relay LoadBalancer type annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key cloud.google.com/load-balancer-type must not configure LoadBalancer scope or implementation type"
        ));

        let mut relay_global_access_annotation = base_k8s_install_args();
        relay_global_access_annotation.expose_relay = true;
        relay_global_access_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_global_access_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_global_access_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "networking.gke.io/load-balancer-global-access".to_string(),
            value: "true".to_string(),
        }];
        let error = match k8s_install_plan(relay_global_access_annotation) {
            Ok(_) => panic!("relay LoadBalancer global access annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key networking.gke.io/load-balancer-global-access must not configure LoadBalancer scope or implementation type"
        ));

        let mut relay_firewall_annotation = base_k8s_install_args();
        relay_firewall_annotation.expose_relay = true;
        relay_firewall_annotation.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        relay_firewall_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_firewall_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/azure-allowed-service-tags".to_string(),
            value: "AzureCloud".to_string(),
        }];
        let error = match k8s_install_plan(relay_firewall_annotation) {
            Ok(_) => panic!("relay firewall annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key service.beta.kubernetes.io/azure-allowed-service-tags must not configure LoadBalancer firewall or security groups"
        ));

        let mut relay_security_policy_annotation = base_k8s_install_args();
        relay_security_policy_annotation.expose_relay = true;
        relay_security_policy_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_security_policy_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_security_policy_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "networking.gke.io/security-policy".to_string(),
            value: "edge-armor-policy".to_string(),
        }];
        let error = match k8s_install_plan(relay_security_policy_annotation) {
            Ok(_) => panic!("relay security policy annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key networking.gke.io/security-policy must not configure LoadBalancer firewall or security groups"
        ));

        let mut relay_network_tier_annotation = base_k8s_install_args();
        relay_network_tier_annotation.expose_relay = true;
        relay_network_tier_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_network_tier_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_network_tier_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "cloud.google.com/network-tier".to_string(),
            value: "Premium".to_string(),
        }];
        let error = match k8s_install_plan(relay_network_tier_annotation) {
            Ok(_) => panic!("relay network tier annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key cloud.google.com/network-tier must not configure LoadBalancer network placement"
        ));

        let mut relay_target_group_attributes_annotation = base_k8s_install_args();
        relay_target_group_attributes_annotation.expose_relay = true;
        relay_target_group_attributes_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_target_group_attributes_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_target_group_attributes_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-target-group-attributes".to_string(),
            value: "preserve_client_ip.enabled=true".to_string(),
        }];
        let error = match k8s_install_plan(relay_target_group_attributes_annotation) {
            Ok(_) => panic!("relay target group attributes annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-target-group-attributes must not configure LoadBalancer operational attributes"
        ));

        let mut relay_tcp_reset_annotation = base_k8s_install_args();
        relay_tcp_reset_annotation.expose_relay = true;
        relay_tcp_reset_annotation.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        relay_tcp_reset_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_tcp_reset_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/azure-load-balancer-disable-tcp-reset".to_string(),
            value: "true".to_string(),
        }];
        let error = match k8s_install_plan(relay_tcp_reset_annotation) {
            Ok(_) => panic!("relay TCP reset annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key service.beta.kubernetes.io/azure-load-balancer-disable-tcp-reset must not configure LoadBalancer operational attributes"
        ));

        let mut relay_dns_publication_annotation = base_k8s_install_args();
        relay_dns_publication_annotation.expose_relay = true;
        relay_dns_publication_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_dns_publication_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_dns_publication_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/azure-dns-label-name".to_string(),
            value: "relay-edge".to_string(),
        }];
        let error = match k8s_install_plan(relay_dns_publication_annotation) {
            Ok(_) => panic!("relay DNS publication annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key service.beta.kubernetes.io/azure-dns-label-name must not publish LoadBalancer DNS names"
        ));

        let mut relay_address_pool_annotation = base_k8s_install_args();
        relay_address_pool_annotation.expose_relay = true;
        relay_address_pool_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_address_pool_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_address_pool_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "metallb.universe.tf/address-pool".to_string(),
            value: "public".to_string(),
        }];
        let error = match k8s_install_plan(relay_address_pool_annotation) {
            Ok(_) => panic!("relay address pool annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key metallb.universe.tf/address-pool must not configure LoadBalancer resource identity, tags, or address pools"
        ));

        let mut relay_lb_configuration_annotation = base_k8s_install_args();
        relay_lb_configuration_annotation.expose_relay = true;
        relay_lb_configuration_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_lb_configuration_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_lb_configuration_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/azure-load-balancer-configurations".to_string(),
            value: "edge-lb".to_string(),
        }];
        let error = match k8s_install_plan(relay_lb_configuration_annotation) {
            Ok(_) => panic!("relay LoadBalancer configuration annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key service.beta.kubernetes.io/azure-load-balancer-configurations must not configure LoadBalancer resource identity, tags, or address pools"
        ));

        let mut relay_service_attachment_annotation = base_k8s_install_args();
        relay_service_attachment_annotation.expose_relay = true;
        relay_service_attachment_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_service_attachment_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_service_attachment_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "networking.gke.io/service-attachment".to_string(),
            value: "psc-relay".to_string(),
        }];
        let error = match k8s_install_plan(relay_service_attachment_annotation) {
            Ok(_) => panic!("relay service attachment annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key networking.gke.io/service-attachment must not configure LoadBalancer Private Link or endpoint-service publishing"
        ));

        let mut relay_backend_node_selector_annotation = base_k8s_install_args();
        relay_backend_node_selector_annotation.expose_relay = true;
        relay_backend_node_selector_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_backend_node_selector_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_backend_node_selector_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "example.com/backend-node-selector".to_string(),
            value: "role=relay".to_string(),
        }];
        let error = match k8s_install_plan(relay_backend_node_selector_annotation) {
            Ok(_) => panic!("relay backend node selector annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key example.com/backend-node-selector must not configure LoadBalancer backend target selection"
        ));

        let mut relay_source_nat_annotation = base_k8s_install_args();
        relay_source_nat_annotation.expose_relay = true;
        relay_source_nat_annotation.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        relay_source_nat_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_source_nat_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "service.beta.kubernetes.io/aws-load-balancer-enable-prefix-for-ipv6-source-nat"
                .to_string(),
            value: "on".to_string(),
        }];
        let error = match k8s_install_plan(relay_source_nat_annotation) {
            Ok(_) => panic!("relay source NAT annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key service.beta.kubernetes.io/aws-load-balancer-enable-prefix-for-ipv6-source-nat must not configure LoadBalancer source NAT behavior"
        ));

        let mut relay_traffic_distribution_annotation = base_k8s_install_args();
        relay_traffic_distribution_annotation.expose_relay = true;
        relay_traffic_distribution_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_traffic_distribution_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_traffic_distribution_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "networking.gke.io/weighted-load-balancing".to_string(),
            value: "pods-per-node".to_string(),
        }];
        let error = match k8s_install_plan(relay_traffic_distribution_annotation) {
            Ok(_) => panic!("relay traffic-distribution annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key networking.gke.io/weighted-load-balancing must not configure LoadBalancer traffic distribution"
        ));

        let mut relay_topology_mode_annotation = base_k8s_install_args();
        relay_topology_mode_annotation.expose_relay = true;
        relay_topology_mode_annotation.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_topology_mode_annotation.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        relay_topology_mode_annotation.relay_service_annotations = vec![KeyValueArg {
            key: "service.kubernetes.io/topology-mode".to_string(),
            value: "auto".to_string(),
        }];
        let error = match k8s_install_plan(relay_topology_mode_annotation) {
            Ok(_) => panic!("relay topology mode annotation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-service-annotation annotation key service.kubernetes.io/topology-mode must not configure LoadBalancer traffic distribution"
        ));

        Ok(())
    }

    #[test]
    fn k8s_install_plan_quotes_chart_path() -> anyhow::Result<()> {
        let mut args = base_k8s_install_args();
        args.chart = PathBuf::from("charts/ipars chart");

        let plan = k8s_install_plan(args)?;

        assert_eq!(plan.manifest, "charts/ipars chart");
        assert!(plan.commands[2]
            .contains("helm upgrade --install edge 'charts/ipars chart' --namespace edge-system"));
        Ok(())
    }

    #[test]
    fn k8s_install_plan_wires_chart_metadata_overrides() -> anyhow::Result<()> {
        assert!(parse_kubernetes_chart_name_override("edge-ipars").is_ok());
        assert!(parse_kubernetes_chart_name_override("Edge").is_err());

        let mut args = base_k8s_install_args();
        args.chart_name_override = Some("edge-agent".to_string());
        args.chart_fullname_override = Some("edge-ipars-agent".to_string());

        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];

        assert!(helm.contains("--set-string nameOverride=edge-agent"));
        assert!(helm.contains("--set-string fullnameOverride=edge-ipars-agent"));
        assert!(plan
            .notes
            .iter()
            .any(|note| note.contains("Chart nameOverride and fullnameOverride")));
        Ok(())
    }

    #[test]
    fn k8s_install_validates_relay_advertisement_endpoints() -> anyhow::Result<()> {
        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--relay-public-endpoint",
            "203.0.113.10:51820",
        ]);
        assert!(parsed.is_err());

        let mut domain_public_endpoint = base_k8s_install_args();
        domain_public_endpoint.expose_relay = true;
        domain_public_endpoint.relay_public_endpoint = Some("relay.example.test:51820".to_string());
        domain_public_endpoint.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(domain_public_endpoint) {
            Ok(_) => panic!("domain relay public endpoint should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("IPv4 host:port or [IPv6]:port socket address"));

        let mut unspecified_public_endpoint = base_k8s_install_args();
        unspecified_public_endpoint.expose_relay = true;
        unspecified_public_endpoint.relay_public_endpoint = Some("0.0.0.0:51820".to_string());
        unspecified_public_endpoint.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(unspecified_public_endpoint) {
            Ok(_) => panic!("unspecified relay public endpoint should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("usable nonzero"));

        let mut loopback_public_endpoint = base_k8s_install_args();
        loopback_public_endpoint.expose_relay = true;
        loopback_public_endpoint.relay_public_endpoint = Some("127.0.0.1:51820".to_string());
        loopback_public_endpoint.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(loopback_public_endpoint) {
            Ok(_) => panic!("loopback relay public endpoint should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-public-endpoint must not use loopback address 127.0.0.1"));

        let mut unusable_admission_url = base_k8s_install_args();
        unusable_admission_url.expose_relay = true;
        unusable_admission_url.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        unusable_admission_url.relay_admission_url = Some("http://0.0.0.0:9580".to_string());
        let error = match k8s_install_plan(unusable_admission_url) {
            Ok(_) => panic!("unusable relay admission URL should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-admission-url must use a nonzero port"));

        let mut loopback_admission_url = base_k8s_install_args();
        loopback_admission_url.expose_relay = true;
        loopback_admission_url.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        loopback_admission_url.relay_admission_url = Some("http://127.0.0.1:9580".to_string());
        let error = match k8s_install_plan(loopback_admission_url) {
            Ok(_) => panic!("loopback relay admission URL should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("--relay-admission-url host must not use loopback address 127.0.0.1")
        );

        let mut invalid_status_url = base_k8s_install_args();
        invalid_status_url.expose_relay = true;
        invalid_status_url.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        invalid_status_url.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        invalid_status_url.relay_status_url = Some("ftp://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(invalid_status_url) {
            Ok(_) => panic!("invalid relay status URL should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-status-url must use http or https"));

        let mut link_local_status_url = base_k8s_install_args();
        link_local_status_url.expose_relay = true;
        link_local_status_url.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        link_local_status_url.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        link_local_status_url.relay_status_url = Some("http://169.254.169.254:9580".to_string());
        let error = match k8s_install_plan(link_local_status_url) {
            Ok(_) => panic!("link-local relay status URL should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error
            .contains("--relay-status-url host must not use link-local address 169.254.169.254"));

        let mut inactive_capacity = base_k8s_install_args();
        inactive_capacity.relay_max_sessions = 4321;
        let error = match k8s_install_plan(inactive_capacity) {
            Ok(_) => panic!("inactive relay advertisement capacity should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-max-sessions requires --expose-relay"));

        let mut zero_capacity = base_k8s_install_args();
        zero_capacity.expose_relay = true;
        zero_capacity.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        zero_capacity.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        zero_capacity.relay_max_sessions = 0;
        let error = match k8s_install_plan(zero_capacity) {
            Ok(_) => panic!("zero relay max sessions should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-max-sessions must be greater than zero"));

        let mut zero_bandwidth = base_k8s_install_args();
        zero_bandwidth.expose_relay = true;
        zero_bandwidth.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        zero_bandwidth.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        zero_bandwidth.relay_max_mbps = 0;
        let error = match k8s_install_plan(zero_bandwidth) {
            Ok(_) => panic!("zero relay max Mbps should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-max-mbps must be greater than zero"));

        let mut valid_ipv6 = base_k8s_install_args();
        valid_ipv6.expose_relay = true;
        valid_ipv6.relay_service_type = "ClusterIP".to_string();
        valid_ipv6.relay_public_endpoint = Some("[2001:db8::10]:51820".to_string());
        valid_ipv6.relay_admission_url = Some("https://relay.example.test:9580".to_string());
        valid_ipv6.relay_status_url = Some("http://[2001:db8::10]:9580".to_string());
        let plan = k8s_install_plan(valid_ipv6)?;
        assert!(plan.commands[2].contains(
            "--set-string 'agent.relayAdvertisement.publicEndpoint=[2001:db8::10]:51820'"
        ));
        Ok(())
    }

    #[test]
    fn k8s_install_wires_and_validates_relay_forwarder_settings() -> anyhow::Result<()> {
        let mut endpoint_only = base_k8s_install_args();
        endpoint_only.relay_forwarder_endpoint = Some("127.0.0.1:45182".to_string());
        let plan = k8s_install_plan(endpoint_only)?;
        let helm = &plan.commands[2];
        assert!(helm.contains("--set agent.relayForwarder.enabled=true"));
        assert!(helm.contains("--set-string agent.relayForwarder.endpoint=127.0.0.1:45182"));
        assert!(!helm.contains("agent.relayForwarder.bind"));
        assert!(!helm.contains("agent.relayForwarder.maxSessions"));

        let mut invalid_endpoint = base_k8s_install_args();
        invalid_endpoint.relay_forwarder_endpoint = Some("0.0.0.0:45182".to_string());
        let error = match k8s_install_plan(invalid_endpoint) {
            Ok(_) => panic!("unusable relay forwarder endpoint should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-forwarder-endpoint"));

        let mut missing_wireguard_endpoint = base_k8s_install_args();
        missing_wireguard_endpoint.relay_forwarder_bind = Some("0.0.0.0:45182".to_string());
        let error = match k8s_install_plan(missing_wireguard_endpoint) {
            Ok(_) => panic!("relay forwarder bind without WireGuard endpoint should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-forwarder-wireguard-endpoint is required"));

        let mut invalid_bind = base_k8s_install_args();
        invalid_bind.relay_forwarder_bind = Some("239.1.1.1:45182".to_string());
        invalid_bind.relay_forwarder_wireguard_endpoint = Some("127.0.0.1:51820".to_string());
        let error = match k8s_install_plan(invalid_bind) {
            Ok(_) => panic!("multicast relay forwarder bind should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("multicast bind address"));

        let mut inactive_capacity = base_k8s_install_args();
        inactive_capacity.relay_forwarder_endpoint = Some("127.0.0.1:45182".to_string());
        inactive_capacity.relay_forwarder_max_sessions = 7;
        let error = match k8s_install_plan(inactive_capacity) {
            Ok(_) => panic!("supervisor capacity without bind should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-forwarder-max-sessions requires --relay-forwarder-bind"));

        let mut netns_without_sys_admin = base_k8s_install_args();
        netns_without_sys_admin.relay_forwarder_bind = Some("0.0.0.0:45182".to_string());
        netns_without_sys_admin.relay_forwarder_wireguard_endpoint =
            Some("127.0.0.1:51820".to_string());
        netns_without_sys_admin.relay_forwarder_netns = Some("relay-fw".to_string());
        let error = match k8s_install_plan(netns_without_sys_admin) {
            Ok(_) => panic!("relay forwarder netns without SYS_ADMIN should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-forwarder-netns requires"));

        Ok(())
    }

    #[test]
    fn bundled_chart_validates_load_balancer_source_ranges() -> anyhow::Result<()> {
        let helpers_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/_helpers.tpl")
            .canonicalize()?;
        let service_template_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/service.yaml")
            .canonicalize()?;
        let network_policy_template_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/networkpolicy.yaml")
            .canonicalize()?;
        let helpers = std::fs::read_to_string(helpers_path)?;
        let service_template = std::fs::read_to_string(service_template_path)?;
        let network_policy_template = std::fs::read_to_string(network_policy_template_path)?;

        assert!(helpers.contains("ipars.validateRestrictedCidr"));
        assert!(helpers.contains("define \"ipars.validateCidrContainedBySourceRanges\""));
        assert!(helpers.contains("define \"ipars.ipv6AddressNibbles\""));
        assert!(helpers.contains("define \"ipars.ipv6CidrBits\""));
        assert!(helpers.contains(
            "NetworkPolicy must not allow sources broader than the LoadBalancer source ranges"
        ));
        assert!(helpers.contains("must not be an unrestricted CIDR"));
        assert!(helpers.contains("must be a canonical IPv4 CIDR"));
        assert!(helpers.contains("must be a canonical IPv6 CIDR"));
        assert!(helpers.contains("must not include unspecified CIDRs"));
        assert!(helpers.contains("must not include loopback CIDRs"));
        assert!(helpers.contains("must not include link-local CIDRs"));
        assert!(helpers.contains("must not include multicast CIDRs"));
        assert!(helpers.contains("must not include broadcast CIDRs"));
        assert!(service_template.contains(
            "ipars.validateRestrictedCidr\" (dict \"path\" \"agent.apiService.loadBalancerSourceRanges\""
        ));
        assert!(service_template
            .contains("agent.apiService.loadBalancerSourceRanges entry %q must not be repeated"));
        assert!(service_template.contains(
            "ipars.validateRestrictedCidr\" (dict \"path\" \"agent.relayService.loadBalancerSourceRanges\""
        ));
        assert!(service_template
            .contains("agent.relayService.loadBalancerSourceRanges entry %q must not be repeated"));
        assert!(network_policy_template.contains(
            "ipars.validateRestrictedCidr\" (dict \"path\" \"networkPolicy.agentApi.allowedCidrs\""
        ));
        assert!(network_policy_template.contains(
            "ipars.validateCidrContainedBySourceRanges\" (dict \"path\" \"networkPolicy.agentApi.allowedCidrs\""
        ));
        assert!(network_policy_template
            .contains("\"sourcePath\" \"agent.apiService.loadBalancerSourceRanges\""));
        assert!(network_policy_template.contains(
            "networkPolicy.acknowledgeHostNetwork=true requires networkPolicy.enabled=true"
        ));
        assert!(network_policy_template.contains(
            "networkPolicy.acknowledgeHostNetwork=true only applies when agent.hostNetwork=true"
        ));
        assert!(network_policy_template.contains(
            "networkPolicy.agentApi.allowedCidrs require networkPolicy.enabled=true and networkPolicy.agentApi.enabled=true"
        ));
        assert!(network_policy_template.contains(
            "networkPolicy.relay.allowedCidrs require networkPolicy.enabled=true and networkPolicy.relay.enabled=true"
        ));
        assert!(network_policy_template
            .contains("networkPolicy.agentApi.allowedCidrs entry %q must not be repeated"));
        assert!(network_policy_template.contains("port: {{ .Values.agent.apiService.targetPort }}"));
        assert!(!network_policy_template.contains("port: {{ .Values.agent.apiService.port }}"));
        assert!(network_policy_template
            .contains("port: {{ .Values.agent.relayService.udpTargetPort }}"));
        assert!(network_policy_template
            .contains("port: {{ .Values.agent.relayService.httpTargetPort }}"));
        assert!(!network_policy_template.contains("port: {{ .Values.agent.relayService.udpPort }}"));
        assert!(
            !network_policy_template.contains("port: {{ .Values.agent.relayService.httpPort }}")
        );
        assert!(!network_policy_template.contains("port: 9780"));
        assert!(network_policy_template.contains(
            "ipars.validateRestrictedCidr\" (dict \"path\" \"networkPolicy.relay.allowedCidrs\""
        ));
        assert!(network_policy_template.contains(
            "ipars.validateCidrContainedBySourceRanges\" (dict \"path\" \"networkPolicy.relay.allowedCidrs\""
        ));
        assert!(network_policy_template
            .contains("\"sourcePath\" \"agent.relayService.loadBalancerSourceRanges\""));
        assert!(network_policy_template
            .contains("networkPolicy.relay.allowedCidrs entry %q must not be repeated"));
        Ok(())
    }

    #[test]
    fn bundled_chart_validates_metadata_names() -> anyhow::Result<()> {
        let helpers_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/_helpers.tpl")
            .canonicalize()?;
        let daemonset_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/daemonset.yaml")
            .canonicalize()?;
        let values_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/values.yaml")
            .canonicalize()?;
        let helpers = std::fs::read_to_string(helpers_path)?;
        let daemonset = std::fs::read_to_string(daemonset_path)?;
        let values = std::fs::read_to_string(values_path)?;

        assert!(helpers.contains("define \"ipars.validateChartMetadata\""));
        assert!(helpers.contains("define \"ipars.validateDnsLabelWithMax\""));
        assert!(helpers.contains("\"path\" \"Release.Name\""));
        assert!(helpers.contains("\"path\" \"Release.Namespace\""));
        assert!(helpers.contains("\"path\" \"nameOverride\""));
        assert!(helpers.contains("\"path\" \"fullnameOverride\""));
        assert!(helpers.contains("must be a DNS label of at most %d bytes"));
        assert!(helpers.contains("\"maxBytes\" 53"));
        assert!(helpers.contains("\"maxBytes\" 63"));
        assert!(helpers.contains("contains $name .Release.Name"));
        assert!(helpers.contains("printf \"%s-%s\" .Release.Name $name"));
        assert!(helpers.contains(".Values.fullnameOverride | trunc 53"));
        assert!(values.contains("nameOverride: \"\""));
        assert!(values.contains("fullnameOverride: \"\""));
        assert!(values.contains("nodeAffinity:"));
        assert!(values.contains("podAffinity:"));
        assert!(values.contains("podAntiAffinity:"));
        assert!(values.contains("schedulerName: \"\""));
        assert!(values.contains("runtimeClassName: \"\""));
        assert!(values.contains("topologySpreadConstraints: []"));
        assert!(daemonset.contains("include \"ipars.validateChartMetadata\" ."));
        assert!(helpers.contains("define \"ipars.validateNodeSelectorExpression\""));
        assert!(helpers.contains("define \"ipars.validatePodAffinityTerm\""));
        assert!(daemonset.contains("agent.nodeAffinity.required.matchExpressions[%d]"));
        assert!(daemonset.contains("agent.podAffinity.required[%d]"));
        assert!(daemonset.contains("podAntiAffinity:"));
        assert!(daemonset.contains("schedulerName: {{ .Values.agent.schedulerName | quote }}"));
        assert!(
            daemonset.contains("runtimeClassName: {{ .Values.agent.runtimeClassName | quote }}")
        );
        assert!(daemonset.contains("preferredDuringSchedulingIgnoredDuringExecution"));
        Ok(())
    }

    #[test]
    fn bundled_chart_scopes_release_instance_labels_and_selectors() -> anyhow::Result<()> {
        let templates_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates")
            .canonicalize()?;
        let service_account = std::fs::read_to_string(templates_path.join("serviceaccount.yaml"))?;
        let rbac = std::fs::read_to_string(templates_path.join("rbac.yaml"))?;
        let daemonset = std::fs::read_to_string(templates_path.join("daemonset.yaml"))?;
        let service_template = std::fs::read_to_string(templates_path.join("service.yaml"))?;
        let network_policy_template =
            std::fs::read_to_string(templates_path.join("networkpolicy.yaml"))?;
        let pdb = std::fs::read_to_string(templates_path.join("poddisruptionbudget.yaml"))?;
        let instance_label = "app.kubernetes.io/instance: {{ .Release.Name | quote }}";
        let rbac_instance_label = "app.kubernetes.io/instance: {{ $root.Release.Name | quote }}";

        assert!(service_account.contains(instance_label));
        assert!(rbac.matches(rbac_instance_label).count() >= 4);
        assert!(daemonset.matches(instance_label).count() >= 3);
        assert!(service_template.matches(instance_label).count() >= 4);
        assert!(network_policy_template.matches(instance_label).count() >= 4);
        assert!(pdb.matches(instance_label).count() >= 2);
        assert!(daemonset.contains("name: {{ include \"ipars.fullname\" . }}"));
        assert!(service_template.contains("name: {{ include \"ipars.fullname\" . }}-agent"));
        assert!(service_template.contains("name: {{ include \"ipars.fullname\" . }}-relay"));
        assert!(
            network_policy_template.contains("name: {{ include \"ipars.fullname\" . }}-agent-api")
        );
        assert!(network_policy_template.contains("name: {{ include \"ipars.fullname\" . }}-relay"));
        Ok(())
    }

    #[test]
    fn bundled_chart_validates_annotation_values() -> anyhow::Result<()> {
        let helpers_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/_helpers.tpl")
            .canonicalize()?;
        let daemonset_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/daemonset.yaml")
            .canonicalize()?;
        let service_template_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/service.yaml")
            .canonicalize()?;
        let helpers = std::fs::read_to_string(helpers_path)?;
        let daemonset = std::fs::read_to_string(daemonset_path)?;
        let service_template = std::fs::read_to_string(service_template_path)?;

        assert!(helpers.contains("define \"ipars.validateAnnotationValue\""));
        assert!(helpers.contains("define \"ipars.validateServiceAnnotationKey\""));
        assert!(helpers.contains("annotation value must be a string"));
        assert!(helpers.contains("annotation value exceeds 262144 bytes"));
        assert!(helpers.contains("annotation value must not contain control characters"));
        assert!(helpers.contains("must not configure LoadBalancer source ranges"));
        assert!(helpers.contains("must not configure LoadBalancer fixed addresses"));
        assert!(daemonset.contains(
            "ipars.validateAnnotationValue\" (dict \"path\" (printf \"serviceAccount.annotations.%s\""
        ));
        assert!(daemonset.contains(
            "ipars.validateAnnotationValue\" (dict \"path\" (printf \"agent.podAnnotations.%s\""
        ));
        assert!(service_template.contains(
            "ipars.validateServiceAnnotationKey\" (dict \"path\" \"agent.apiService.annotations\""
        ));
        assert!(service_template.contains(
            "ipars.validateAnnotationValue\" (dict \"path\" (printf \"agent.apiService.annotations.%s\""
        ));
        assert!(service_template.contains(
            "ipars.validateServiceAnnotationKey\" (dict \"path\" \"agent.relayService.annotations\""
        ));
        assert!(service_template.contains(
            "ipars.validateAnnotationValue\" (dict \"path\" (printf \"agent.relayService.annotations.%s\""
        ));
        Ok(())
    }

    #[test]
    fn bundled_chart_validates_exposure_booleans() -> anyhow::Result<()> {
        let helpers_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/_helpers.tpl")
            .canonicalize()?;
        let service_template_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/service.yaml")
            .canonicalize()?;
        let network_policy_template_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/networkpolicy.yaml")
            .canonicalize()?;
        let daemonset_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/daemonset.yaml")
            .canonicalize()?;
        let rbac_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/rbac.yaml")
            .canonicalize()?;
        let service_account_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/serviceaccount.yaml")
            .canonicalize()?;
        let pdb_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/poddisruptionbudget.yaml")
            .canonicalize()?;
        let helpers = std::fs::read_to_string(helpers_path)?;
        let service_template = std::fs::read_to_string(service_template_path)?;
        let network_policy_template = std::fs::read_to_string(network_policy_template_path)?;
        let daemonset = std::fs::read_to_string(daemonset_path)?;
        let rbac = std::fs::read_to_string(rbac_path)?;
        let service_account = std::fs::read_to_string(service_account_path)?;
        let pdb = std::fs::read_to_string(pdb_path)?;

        assert!(helpers.contains("define \"ipars.validateBoolean\""));
        assert!(helpers.contains("define \"ipars.validateOptionalBoolean\""));
        assert!(helpers.contains("kindIs \"bool\" .value"));
        assert!(helpers.contains("%s must be true or false"));
        assert!(helpers.contains("%s must be true, false, or empty"));
        for path in [
            "agent.apiService.enabled",
            "agent.apiService.exposureAcknowledged",
            "agent.apiService.allowUnrestrictedLoadBalancer",
            "agent.apiService.allowClusterExternalTrafficPolicy",
            "agent.apiService.allocateLoadBalancerNodePorts",
            "agent.apiService.publishNotReadyAddresses",
            "agent.relayService.enabled",
            "agent.relayService.exposureAcknowledged",
            "agent.relayService.allowUnrestrictedLoadBalancer",
            "agent.relayService.allowClusterExternalTrafficPolicy",
            "agent.relayService.allocateLoadBalancerNodePorts",
            "agent.relayService.publishNotReadyAddresses",
            "agent.relayAdvertisement.enabled",
        ] {
            assert!(
                service_template.contains(&format!("\"path\" \"{path}\"")),
                "{path} should be strictly validated as a Service exposure boolean"
            );
        }
        for path in [
            "rbac.create",
            "serviceAccount.create",
            "agent.hostNetwork",
            "agent.automountServiceAccountToken",
            "agent.privileged",
            "agent.routeProvider",
            "agent.securityContext.allowPrivilegeEscalation",
            "agent.securityContext.readOnlyRootFilesystem",
            "agent.peerMap.enabled",
            "agent.relayForwarder.enabled",
            "agent.probes.liveness.enabled",
            "agent.probes.readiness.enabled",
            "agent.probes.startup.enabled",
        ] {
            assert!(
                daemonset.contains(&format!("\"path\" \"{path}\"")),
                "{path} should be strictly validated as a DaemonSet boolean"
            );
        }
        for path in [
            "networkPolicy.enabled",
            "networkPolicy.acknowledgeHostNetwork",
            "networkPolicy.agentApi.enabled",
            "networkPolicy.relay.enabled",
            "agent.hostNetwork",
        ] {
            assert!(
                network_policy_template.contains(&format!("\"path\" \"{path}\"")),
                "{path} should be strictly validated as a NetworkPolicy boolean"
            );
        }
        for path in [
            "serviceExposure.enabled",
            "serviceExposure.discoverServices",
            "serviceExposure.discoverApiServer",
        ] {
            assert!(
                daemonset.contains(&format!("\"path\" \"{path}\"")),
                "{path} should be strictly validated as a Service exposure route boolean"
            );
        }
        assert!(rbac.contains("\"path\" \"rbac.create\""));
        assert!(rbac.contains("\"path\" \"serviceExposure.enabled\""));
        assert!(rbac.contains("\"path\" \"serviceExposure.discoverServices\""));
        assert!(rbac.contains(
            "and $rbacCreate .Values.serviceExposure.enabled .Values.serviceExposure.discoverServices"
        ));
        assert!(service_account.contains("\"path\" \"serviceAccount.create\""));
        assert!(pdb.contains("\"path\" \"agent.podDisruptionBudget.enabled\""));
        Ok(())
    }

    #[test]
    fn bundled_chart_validates_agent_state_paths() -> anyhow::Result<()> {
        let daemonset_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/daemonset.yaml")
            .canonicalize()?;
        let daemonset = std::fs::read_to_string(daemonset_path)?;

        assert!(daemonset.contains("agent.state.hostPath must be an absolute host path"));
        assert!(daemonset.contains("agent.state.mountPath must be an absolute container path"));
        assert!(daemonset.contains("agent.state.hostPath must not be a sensitive system path"));
        assert!(daemonset.contains("agent.state.mountPath must not be a sensitive system path"));
        assert!(daemonset.contains("(hasPrefix \"/etc/\" $agentStateHostPath)"));
        assert!(daemonset.contains("(hasPrefix \"/proc/\" $agentStateMountPath)"));
        assert!(daemonset.contains("(eq $agentStateHostPath \"/var/run\")"));
        assert!(!daemonset.contains("(hasPrefix \"/run/\" $agentStateMountPath)"));
        Ok(())
    }

    #[test]
    fn bundled_chart_validates_daemon_socket_addresses() -> anyhow::Result<()> {
        let helpers_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/_helpers.tpl")
            .canonicalize()?;
        let daemonset_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/daemonset.yaml")
            .canonicalize()?;
        let helpers = std::fs::read_to_string(helpers_path)?;
        let daemonset = std::fs::read_to_string(daemonset_path)?;

        assert!(helpers.contains("define \"ipars.validateSocketAddress\""));
        assert!(helpers.contains("define \"ipars.validateAdvertisedSocketAddress\""));
        assert!(helpers.contains("define \"ipars.validateBindSocketAddress\""));
        assert!(helpers.contains("must be an IPv4 host:port or [IPv6]:port socket address"));
        assert!(helpers.contains("must be an IPv4 host:port or [IPv6]:port bind socket address"));
        assert!(helpers.contains("must not use an unspecified address"));
        assert!(helpers.contains("must not use a multicast address"));
        assert!(helpers.contains("must not use a broadcast address"));
        assert!(daemonset
            .contains("ipars.validateSocketAddress\" (dict \"path\" \"cluster.stunEndpoint\""));
        assert!(daemonset.contains(
            "ipars.validateAdvertisedSocketAddress\" (dict \"path\" \"agent.relayAdvertisement.publicEndpoint\""
        ));
        assert!(daemonset.contains(
            "ipars.validateBindSocketAddress\" (dict \"path\" \"agent.relayForwarder.bind\""
        ));
        assert!(daemonset.contains("{{- if .Values.agent.relayForwarder.bind }}"));
        assert!(daemonset.contains("- --relay-forwarder-bind"));
        assert!(daemonset.contains("- --relay-forwarder-wireguard-endpoint"));
        assert!(daemonset.contains("- --relay-forwarder-max-sessions"));
        assert!(daemonset
            .contains("agent.relayForwarder.netns requires agent.privileged=true or SYS_ADMIN"));
        assert!(daemonset.contains("- name: host-netns"));
        assert!(daemonset.contains("mountPath: /var/run/netns"));
        assert!(daemonset.contains("path: /var/run/netns"));
        assert!(daemonset.contains("\"path\" \"agent.apiService.targetPort\""));
        assert!(daemonset.contains("printf \"0.0.0.0:%d\" $agentApiTargetPort"));
        assert_eq!(
            daemonset.matches("port: {{ $agentApiTargetPort }}").count(),
            3
        );
        assert!(!daemonset.contains("port: 9780"));
        assert!(!daemonset.contains("0.0.0.0:9780"));
        assert!(!daemonset.contains("cluster.relayEndpoint"));
        assert!(!daemonset.contains("IPARS_RELAY_ENDPOINT"));
        Ok(())
    }

    #[test]
    fn bundled_chart_validates_http_endpoint_urls() -> anyhow::Result<()> {
        let helpers_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/_helpers.tpl")
            .canonicalize()?;
        let daemonset_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/daemonset.yaml")
            .canonicalize()?;
        let helpers = std::fs::read_to_string(helpers_path)?;
        let daemonset = std::fs::read_to_string(daemonset_path)?;

        assert!(helpers.contains("define \"ipars.validateHttpEndpointURL\""));
        assert!(helpers.contains("define \"ipars.validateAdvertisedHttpEndpointURL\""));
        assert!(helpers.contains("must be an absolute HTTP(S) URL with a host"));
        assert!(helpers.contains("must not include userinfo"));
        assert!(helpers.contains("port must be between 1 and 65535"));
        assert!(helpers.contains("host must not be an unspecified address"));
        assert!(helpers.contains("host must not be a multicast address"));
        assert!(helpers.contains("host must not be a broadcast address"));
        assert!(daemonset.contains(
            "ipars.validateHttpEndpointURL\" (dict \"path\" \"cluster.controlPlaneUrl\""
        ));
        assert!(daemonset
            .contains("ipars.validateHttpEndpointURL\" (dict \"path\" \"cluster.signalUrl\""));
        assert!(daemonset.contains(
            "ipars.validateAdvertisedHttpEndpointURL\" (dict \"path\" \"agent.relayAdvertisement.admissionUrl\""
        ));
        assert!(daemonset.contains(
            "ipars.validateAdvertisedHttpEndpointURL\" (dict \"path\" \"agent.relayAdvertisement.statusUrl\""
        ));
        assert!(!daemonset.contains("$clusterUrlPattern"));
        Ok(())
    }

    #[test]
    fn bundled_chart_uses_relay_advertisement_instead_of_static_relay_endpoint(
    ) -> anyhow::Result<()> {
        let values_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/values.yaml")
            .canonicalize()?;
        let daemonset_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/daemonset.yaml")
            .canonicalize()?;
        let values = std::fs::read_to_string(values_path)?;
        let daemonset = std::fs::read_to_string(daemonset_path)?;

        assert!(!values.contains("relayEndpoint:"));
        assert!(!values.contains("relayAdmissionUrl:"));
        assert!(!values.contains("IPARS_RELAY_ENDPOINT"));
        assert!(values.contains("relayAdvertisement:"));
        assert!(values.contains("publicEndpoint: \"\""));
        assert!(values.contains("admissionUrl: \"\""));
        assert!(daemonset.contains("- --relay-public-endpoint"));
        assert!(
            daemonset.contains("- {{ .Values.agent.relayAdvertisement.publicEndpoint | quote }}")
        );
        assert!(daemonset.contains("- --relay-admission-url"));
        assert!(daemonset.contains("- {{ .Values.agent.relayAdvertisement.admissionUrl | quote }}"));
        assert!(!daemonset.contains("cluster.relayEndpoint"));
        assert!(!daemonset.contains("cluster.relayAdmissionUrl"));
        assert!(!daemonset.contains("IPARS_RELAY_ENDPOINT"));
        Ok(())
    }

    #[test]
    fn bundled_chart_bounds_daemon_numeric_values_before_int_conversion() -> anyhow::Result<()> {
        let helpers_template_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/_helpers.tpl")
            .canonicalize()?;
        let daemonset_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/daemonset.yaml")
            .canonicalize()?;
        let helpers_template = std::fs::read_to_string(helpers_template_path)?;
        let daemonset = std::fs::read_to_string(daemonset_path)?;

        assert!(helpers_template.contains("define \"ipars.validateNonNegativeIntegerMax\""));
        assert!(helpers_template.contains("define \"ipars.validateOptionalNonNegativeIntegerMax\""));
        for (path, value, max) in [
            (
                "agent.peerMap.pollIntervalSeconds",
                "$agentPeerMapPollIntervalSeconds",
                "9223372036854775807",
            ),
            (
                "agent.http.connectTimeoutSeconds",
                "$agentHttpConnectTimeoutSeconds",
                "3600",
            ),
            (
                "agent.http.requestTimeoutSeconds",
                "$agentHttpRequestTimeoutSeconds",
                "3600",
            ),
            (
                "agent.relayForwarder.maxSessions",
                "$agentRelayForwarderMaxSessions",
                "9223372036854775807",
            ),
            (
                "agent.relayForwarder.restartBackoffSeconds",
                "$agentRelayForwarderRestartBackoffSeconds",
                "9223372036854775807",
            ),
            (
                "agent.relayForwarder.crashWindowSeconds",
                "$agentRelayForwarderCrashWindowSeconds",
                "9223372036854775807",
            ),
            (
                "agent.relayForwarder.maxCrashesPerWindow",
                "$agentRelayForwarderMaxCrashesPerWindow",
                "4294967295",
            ),
            (
                "agent.relayForwarder.crashCooldownSeconds",
                "$agentRelayForwarderCrashCooldownSeconds",
                "9223372036854775807",
            ),
            (
                "agent.relayAdvertisement.maxSessions",
                "$relayAdvertisementMaxSessions",
                "4294967295",
            ),
            (
                "agent.relayAdvertisement.maxMbps",
                "$relayAdvertisementMaxMbps",
                "4294967295",
            ),
            (
                "serviceExposure.routeIntervalSeconds",
                "$serviceExposureRouteIntervalSeconds",
                "9223372036854775807",
            ),
        ] {
            assert!(
                daemonset.contains(&format!("\"{path}\" \"value\" {value} \"max\" {max}")),
                "{path} should validate as a bounded integer before int conversion"
            );
        }
        assert!(daemonset.contains(
            "agent.http.connectTimeoutSeconds must not exceed agent.http.requestTimeoutSeconds"
        ));
        for probe_field in [
            "initialDelaySeconds",
            "periodSeconds",
            "timeoutSeconds",
            "failureThreshold",
        ] {
            assert!(
                daemonset.contains(&format!(
                    "printf \"agent.probes.%s.{probe_field}\" $probeName"
                )) && daemonset.contains(&format!("\"value\" ${probe_field} \"max\" 2147483647")),
                "agent probe {probe_field} should validate as a bounded int32 before rendering"
            );
        }
        assert!(daemonset.contains(
            "ipars.validateNonNegativeInt64\" (dict \"path\" \"agent.terminationGracePeriodSeconds\""
        ));
        assert!(daemonset.contains(
            "\"agent.lifecycle.preStopSleepSeconds\" \"value\" $agentPreStopSleepSeconds \"max\" 2147483647"
        ));
        assert!(daemonset
            .contains("agent.lifecycle.preStopSleepSeconds must be greater than zero when set"));
        assert!(daemonset.contains(
            "ipars.validateNonNegativeInt64\" (dict \"path\" (printf \"%s.tolerationSeconds\" $path)"
        ));
        assert!(daemonset.contains("agent.topologySpreadConstraints[%d]"));
        assert!(daemonset.contains("\"%s.maxSkew\" $path"));
        assert!(daemonset.contains("\"%s.minDomains\" $path"));
        assert!(daemonset.contains("topologySpreadConstraints:"));
        assert!(daemonset.contains("labelSelector:"));
        assert!(daemonset.contains(
            "\"agent.rollout.minReadySeconds\" \"value\" $agentMinReadySeconds \"max\" 2147483647"
        ));
        assert!(daemonset.contains(
            "\"agent.rollout.revisionHistoryLimit\" \"value\" $agentRevisionHistoryLimit \"max\" 2147483647"
        ));
        assert!(!daemonset.contains("ipars.validateNonNegativeInteger\" (dict"));
        Ok(())
    }

    #[test]
    fn bundled_chart_bounds_int_or_percent_values_before_int_conversion() -> anyhow::Result<()> {
        let helpers_template_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/_helpers.tpl")
            .canonicalize()?;
        let daemonset_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/daemonset.yaml")
            .canonicalize()?;
        let pdb_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/poddisruptionbudget.yaml")
            .canonicalize()?;
        let helpers_template = std::fs::read_to_string(helpers_template_path)?;
        let daemonset = std::fs::read_to_string(daemonset_path)?;
        let pdb = std::fs::read_to_string(pdb_path)?;

        assert!(helpers_template.contains("define \"ipars.validateIntOrPercent\""));
        assert!(helpers_template.contains("no greater than 2147483647"));
        assert!(helpers_template.contains("percentage from 0%% to 100%%"));
        for path in ["agent.rollout.maxUnavailable", "agent.rollout.maxSurge"] {
            assert!(
                daemonset.contains(&format!(
                    "ipars.validateIntOrPercent\" (dict \"path\" \"{path}\""
                )),
                "{path} should validate as bounded IntOrString before rendering"
            );
        }
        for path in [
            "agent.podDisruptionBudget.minAvailable",
            "agent.podDisruptionBudget.maxUnavailable",
        ] {
            assert!(
                pdb.contains(&format!(
                    "ipars.validateIntOrPercent\" (dict \"path\" \"{path}\""
                )),
                "{path} should validate as bounded IntOrString before rendering"
            );
        }
        Ok(())
    }

    #[test]
    fn bundled_chart_rejects_inconsistent_service_exposure_values() -> anyhow::Result<()> {
        let service_template_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/service.yaml")
            .canonicalize()?;
        let helpers_template_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/_helpers.tpl")
            .canonicalize()?;
        let service_template = std::fs::read_to_string(service_template_path)?;
        let helpers_template = std::fs::read_to_string(helpers_template_path)?;

        assert!(service_template.contains(
            "agent.apiService exposure-specific values require agent.apiService.enabled=true"
        ));
        assert!(service_template.contains(
            "agent.relayService exposure-specific values require agent.relayService.enabled=true and agent.relayAdvertisement.enabled=true"
        ));
        assert!(service_template.contains(
            "agent.relayService.enabled=true requires agent.relayAdvertisement.enabled=true so the Service exposes an advertised relay endpoint"
        ));
        assert!(service_template.contains(
            "and .Values.agent.relayService.enabled (not .Values.agent.relayAdvertisement.enabled)"
        ));
        assert!(service_template.contains("(ne .Values.agent.apiService.type \"ClusterIP\")"));
        assert!(service_template.contains("(ne $agentApiPort 9780)"));
        assert!(service_template.contains("(ne .Values.agent.apiService.appProtocol \"http\")"));
        assert!(service_template.contains("(ne .Values.agent.relayService.type \"LoadBalancer\")"));
        assert!(service_template.contains("(ne $relayUdpPort 51820)"));
        assert!(service_template.contains("(ne $relayUdpTargetPort 51820)"));
        assert!(service_template.contains("(ne $relayHttpPort 9580)"));
        assert!(service_template.contains("(ne $relayHttpTargetPort 9580)"));
        assert!(service_template
            .contains("(ne .Values.agent.relayService.udpAppProtocol \"ipars.io/relay-udp\")"));
        assert!(
            service_template.contains("(ne .Values.agent.relayService.httpAppProtocol \"http\")")
        );
        assert!(service_template.contains(
            "$agentApiExternalIPs $agentApiLoadBalancerSourceRanges (ne $agentApiHealthCheckNodePort 0)"
        ));
        assert!(service_template.contains(
            "$relayExternalIPs $relayLoadBalancerSourceRanges (ne $relayHealthCheckNodePort 0)"
        ));
        assert!(service_template.contains(
            ".Values.agent.apiService.annotations .Values.agent.apiService.exposureAcknowledged"
        ));
        assert!(service_template.contains(
            ".Values.agent.relayService.annotations .Values.agent.relayService.exposureAcknowledged"
        ));
        assert!(helpers_template.contains(
            "must not publish LoadBalancer DNS names; use relayAdvertisement values and explicit Service exposure controls instead"
        ));
        assert!(helpers_template.contains(
            "must not configure LoadBalancer resource identity, tags, or address pools; use typed Service exposure controls and explicit fixed-address values instead"
        ));
        assert!(helpers_template.contains(
            "must not configure LoadBalancer Private Link or endpoint-service publishing; use typed Service exposure controls and relayAdvertisement values instead"
        ));
        assert!(helpers_template.contains(
            "must not configure LoadBalancer backend target selection; use DaemonSet scheduling, externalTrafficPolicy values, and typed Service exposure controls instead"
        ));
        assert!(helpers_template.contains(
            "must not configure LoadBalancer source NAT behavior; use internal/externalTrafficPolicy, source ranges, and NetworkPolicy values instead"
        ));
        assert!(helpers_template.contains(
            "must not configure LoadBalancer traffic distribution; use internal/externalTrafficPolicy and trafficDistribution values instead"
        ));
        assert!(service_template
            .contains("(ne .Values.agent.apiService.externalTrafficPolicy \"Local\")"));
        assert!(service_template
            .contains("(ne .Values.agent.relayService.externalTrafficPolicy \"Local\")"));
        assert!(service_template.contains(
            "agent.apiService.loadBalancerSourceRanges requires agent.apiService.type LoadBalancer"
        ));
        assert!(service_template.contains(
            "agent.relayService.loadBalancerSourceRanges requires agent.relayService.type LoadBalancer"
        ));
        assert!(service_template.contains(
            "agent.apiService.allowUnrestrictedLoadBalancer=true cannot be combined with agent.apiService.loadBalancerSourceRanges"
        ));
        assert!(service_template.contains(
            "agent.relayService.allowUnrestrictedLoadBalancer=true cannot be combined with agent.relayService.loadBalancerSourceRanges"
        ));
        assert!(service_template.contains(
            "agent.apiService.allowClusterExternalTrafficPolicy=true requires NodePort or LoadBalancer type with externalTrafficPolicy=Cluster"
        ));
        assert!(service_template.contains(
            "agent.relayService.allowClusterExternalTrafficPolicy=true requires NodePort or LoadBalancer type with externalTrafficPolicy=Cluster"
        ));
        assert!(service_template.contains(
            "agent.apiService.externalTrafficPolicy requires agent.apiService.type NodePort or LoadBalancer"
        ));
        assert!(service_template.contains(
            "agent.relayService.externalTrafficPolicy requires agent.relayService.type NodePort or LoadBalancer"
        ));
        assert!(helpers_template.contains(
            "must not enable PROXY protocol; IPARS Services do not accept PROXY protocol headers"
        ));
        assert!(helpers_template.contains(
            "must not configure LoadBalancer health checks; use typed Service health-check controls instead"
        ));
        assert!(helpers_template.contains(
            "must not configure LoadBalancer TLS, listeners, or backend protocols; use typed Service ports/appProtocol and plain IPARS listeners instead"
        ));
        assert!(helpers_template.contains(
            "must not configure LoadBalancer scope or implementation type; use typed Service type, loadBalancerClass, exposure acknowledgement, and source-range controls instead"
        ));
        assert!(helpers_template.contains(
            "must not configure LoadBalancer firewall or security groups; use loadBalancerSourceRanges or NetworkPolicy values instead"
        ));
        assert!(helpers_template.contains(
            "must not configure LoadBalancer network placement; use typed Service type, loadBalancerClass, source-range, and exposure controls instead"
        ));
        assert!(helpers_template.contains(
            "must not configure LoadBalancer operational attributes; use typed Service traffic policy, appProtocol, and IPARS listener controls instead"
        ));
        assert!(helpers_template.contains("define \"ipars.validateNonNegativeIntegerMax\""));
        assert!(helpers_template.contains("must be a non-negative integer no greater than %s"));
        for path in [
            "agent.apiService.port",
            "agent.apiService.targetPort",
            "agent.apiService.nodePort",
            "agent.apiService.healthCheckNodePort",
            "agent.apiService.sessionAffinityTimeoutSeconds",
            "agent.relayService.udpPort",
            "agent.relayService.udpTargetPort",
            "agent.relayService.httpPort",
            "agent.relayService.httpTargetPort",
            "agent.relayService.udpNodePort",
            "agent.relayService.httpNodePort",
            "agent.relayService.healthCheckNodePort",
            "agent.relayService.sessionAffinityTimeoutSeconds",
        ] {
            assert!(
                service_template.contains(&format!(
                    "ipars.validateNonNegativeIntegerMax\" (dict \"path\" \"{path}\""
                )),
                "{path} should validate as a bounded integer before int conversion"
            );
        }
        assert!(service_template.contains(
            "agent.apiService.exposureAcknowledged=true requires external Service type or externalIPs"
        ));
        assert!(service_template.contains(
            "agent.relayService.exposureAcknowledged=true requires external Service type or externalIPs"
        ));
        assert!(service_template.contains(
            "agent.relayService.udpNodePort must not reuse Kubernetes NodePort %d already assigned to %s"
        ));
        assert!(service_template.contains(
            "agent.relayService.healthCheckNodePort must not reuse Kubernetes NodePort %d already assigned to %s"
        ));
        assert!(service_template.contains(
            "agent.relayService.clusterIP %q must not reuse agent.apiService clusterIPs"
        ));
        assert!(service_template.contains(
            "agent.relayService.clusterIPs entry %q must not reuse agent.apiService clusterIPs"
        ));
        assert!(service_template.contains("targetPort: {{ .Values.agent.apiService.targetPort }}"));
        assert!(!service_template.contains("targetPort: 9780"));
        assert!(
            service_template.contains("targetPort: {{ .Values.agent.relayService.udpTargetPort }}")
        );
        assert!(service_template
            .contains("targetPort: {{ .Values.agent.relayService.httpTargetPort }}"));
        assert!(!service_template.contains("targetPort: {{ .Values.agent.relayService.udpPort }}"));
        assert!(!service_template.contains("targetPort: {{ .Values.agent.relayService.httpPort }}"));
        Ok(())
    }

    #[test]
    fn bundled_chart_wires_route_backend_selection() -> anyhow::Result<()> {
        let values_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/values.yaml")
            .canonicalize()?;
        let daemonset_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/daemonset.yaml")
            .canonicalize()?;
        let values = std::fs::read_to_string(values_path)?;
        let daemonset = std::fs::read_to_string(daemonset_path)?;

        assert!(values.contains("routeBackend: command"));
        assert!(values.contains("runtimeBackend: linux-command"));
        assert!(values.contains("wireguardListenPort: 51820"));
        assert!(values.contains("stunBind: \"0.0.0.0:51820\""));
        assert!(!values.contains("  apiServer:"));
        assert!(daemonset.contains("agent.runtimeBackend must be linux-command or dry-run"));
        assert!(daemonset.contains("agent.routeBackend must be command or kernel-netlink"));
        assert!(daemonset.contains("agent.stunBind port must equal agent.wireguardListenPort"));
        assert!(daemonset.contains(
            "serviceExposure.apiServer is not supported; use serviceExposure.discoverApiServer and serviceExposure.apiServerCidrs"
        ));
        assert!(daemonset
            .contains("serviceExposure.discoverServices requires serviceExposure.enabled=true"));
        assert!(daemonset.contains(
            "serviceExposure.namespaces requires serviceExposure.enabled=true and serviceExposure.discoverServices=true"
        ));
        assert!(daemonset.contains(
            "serviceExposure.serviceLabelSelector requires serviceExposure.enabled=true and serviceExposure.discoverServices=true"
        ));
        assert!(daemonset
            .contains("serviceExposure.routeProviderNodeId requires serviceExposure.enabled=true"));
        assert!(daemonset.contains(
            "serviceExposure.routeProviderNodeId must contain only ASCII letters, digits, '_', '.' or '-' and must not exceed 255 bytes"
        ));
        assert!(values.contains("peerMap:"));
        assert!(values.contains("enabled: true"));
        assert!(values.contains("pollIntervalSeconds: 30"));
        assert!(daemonset.contains("agent.peerMap.enabled must be true or false"));
        assert!(daemonset.contains(
            "agent.peerMap.pollIntervalSeconds must be greater than zero when agent.peerMap.enabled=true"
        ));
        assert!(daemonset.contains(
            "agent.routeBackend=kernel-netlink requires agent.peerMap.enabled=true or serviceExposure.enabled=true"
        ));
        assert!(daemonset.contains("- --apply-peer-map"));
        assert!(daemonset.contains("- --peer-map-poll-interval-seconds"));
        assert!(daemonset.contains("- {{ $agentPeerMapPollIntervalSeconds | quote }}"));
        assert!(daemonset.contains("- --route-backend"));
        assert!(daemonset.contains("- {{ $agentRouteBackend | quote }}"));
        assert!(daemonset.contains("- --runtime-backend"));
        assert!(daemonset.contains("- {{ $agentRuntimeBackend | quote }}"));
        assert!(daemonset.contains("- --wireguard-listen-port"));
        assert!(daemonset.contains("- {{ $agentWireguardListenPortValue | quote }}"));
        assert!(daemonset.contains("- --stun-bind"));
        assert!(daemonset.contains("- {{ $agentStunBind | quote }}"));
        assert!(!daemonset.contains("mountPath: /dev/net/tun"));
        assert!(!daemonset.contains("type: CharDevice"));
        Ok(())
    }

    #[test]
    fn bundled_chart_rejects_unsafe_external_service_ips() -> anyhow::Result<()> {
        let helpers_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/_helpers.tpl")
            .canonicalize()?;
        let service_template_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../charts/ipars/templates/service.yaml")
            .canonicalize()?;
        let helpers = std::fs::read_to_string(helpers_path)?;
        let service_template = std::fs::read_to_string(service_template_path)?;

        assert!(helpers.contains("ipars.validateUsableServiceIPAddress"));
        assert!(helpers.contains("ipars.validateExternalServiceIPAddress"));
        assert!(helpers.contains("must not be an unspecified address"));
        assert!(helpers.contains("must not be a loopback address"));
        assert!(helpers.contains("must not be a link-local address"));
        assert!(helpers.contains("must not be a multicast address"));
        assert!(helpers.contains("must not be a broadcast address"));
        assert!(service_template.contains(
            "ipars.validateUsableServiceIPAddress\" (dict \"path\" \"agent.apiService.clusterIP\""
        ));
        assert!(service_template.contains(
            "ipars.validateUsableServiceIPAddress\" (dict \"path\" \"agent.apiService.clusterIPs\""
        ));
        assert!(service_template.contains(
            "ipars.validateUsableServiceIPAddress\" (dict \"path\" \"agent.relayService.clusterIP\""
        ));
        assert!(service_template.contains(
            "ipars.validateUsableServiceIPAddress\" (dict \"path\" \"agent.relayService.clusterIPs\""
        ));
        assert!(service_template.contains(
            "ipars.validateExternalServiceIPAddress\" (dict \"path\" \"agent.apiService.loadBalancerIP\""
        ));
        assert!(service_template.contains(
            "ipars.validateExternalServiceIPAddress\" (dict \"path\" \"agent.relayService.loadBalancerIP\""
        ));
        assert!(service_template.contains(
            "agent.relayService.loadBalancerIP %q must not reuse fixed external IP assigned by %s"
        ));
        assert!(service_template.contains(
            "agent.apiService.externalIPs entry %q must not reuse fixed external IP assigned by %s"
        ));
        assert!(service_template.contains(
            "agent.relayService.externalIPs entry %q must not reuse fixed external IP assigned by %s"
        ));
        assert!(service_template.contains(
            "agent.apiService.loadBalancerIP family %s must be included in agent.apiService.ipFamilies"
        ));
        assert!(service_template.contains(
            "agent.apiService.externalIPs entry %q family %s must be included in agent.apiService.ipFamilies"
        ));
        assert!(service_template.contains(
            "agent.relayService.loadBalancerIP family %s must be included in agent.relayService.ipFamilies"
        ));
        assert!(service_template.contains(
            "agent.relayService.externalIPs entry %q family %s must be included in agent.relayService.ipFamilies"
        ));
        assert!(
            service_template.contains("agent.apiService.externalIPs entry %q must not be repeated")
        );
        assert!(service_template
            .contains("agent.relayService.externalIPs entry %q must not be repeated"));
        assert!(service_template.contains(
            "agent.relayService.externalIPs entry %q must not reuse agent.apiService.externalIPs"
        ));
        Ok(())
    }

    fn base_k8s_install_args() -> K8sInstallArgs {
        K8sInstallArgs {
            release: "edge".to_string(),
            namespace: "edge-system".to_string(),
            chart: PathBuf::from("charts/ipars"),
            chart_name_override: None,
            chart_fullname_override: None,
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            cluster_control_plane_url: None,
            cluster_signal_url: None,
            cluster_stun_endpoint: None,
            image_repository: None,
            image_tag: None,
            image_pull_policy: None,
            image_pull_secrets: Vec::new(),
            agent_privileged: false,
            agent_add_capabilities: Vec::new(),
            agent_drop_capabilities: Vec::new(),
            disable_agent_privilege_escalation: false,
            agent_read_only_root_filesystem: false,
            agent_seccomp_profile: None,
            agent_seccomp_localhost_profile: None,
            agent_run_as_user: None,
            agent_run_as_group: None,
            agent_run_as_non_root: false,
            agent_fs_group: None,
            agent_fs_group_change_policy: None,
            agent_supplemental_groups: Vec::new(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            agent_runtime_backend: "linux-command".to_string(),
            agent_wireguard_listen_port: None,
            agent_stun_bind: None,
            route_backend: "command".to_string(),
            disable_agent_peer_map: false,
            agent_peer_map_poll_interval_seconds: 30,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            expose_agent_api: false,
            allow_public_service_exposure: false,
            allow_unrestricted_load_balancer: false,
            allow_cluster_external_traffic_policy: false,
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            disable_rbac: false,
            disable_service_account_creation: false,
            service_account_name: None,
            service_account_annotations: Vec::new(),
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_scheduler_name: None,
            agent_runtime_class: None,
            agent_node_selectors: Vec::new(),
            agent_node_affinity_required: Vec::new(),
            agent_node_affinity_preferred: Vec::new(),
            agent_pod_affinity_required: Vec::new(),
            agent_pod_affinity_preferred: Vec::new(),
            agent_pod_anti_affinity_required: Vec::new(),
            agent_pod_anti_affinity_preferred: Vec::new(),
            agent_tolerations: Vec::new(),
            agent_topology_spreads: Vec::new(),
            disable_agent_host_network: false,
            disable_agent_service_account_token: false,
            agent_dns_policy: None,
            agent_state_host_path: None,
            agent_state_mount_path: None,
            agent_state_host_path_type: None,
            disable_agent_liveness_probe: false,
            disable_agent_readiness_probe: false,
            disable_agent_startup_probe: false,
            agent_probes: K8sProbeArgs::default(),
            agent_pre_stop_sleep_seconds: None,
            agent_termination_grace_period_seconds: None,
            agent_resource_request_cpu: None,
            agent_resource_request_memory: None,
            agent_resource_limit_cpu: None,
            agent_resource_limit_memory: None,
            agent_update_strategy: None,
            agent_rollout_max_unavailable: None,
            agent_rollout_max_surge: None,
            agent_min_ready_seconds: None,
            agent_revision_history_limit: None,
            agent_pdb_min_available: None,
            agent_pdb_max_unavailable: None,
            agent_api_service_type: "ClusterIP".to_string(),
            agent_api_cluster_ip: None,
            agent_api_secondary_cluster_ip: None,
            agent_api_port: None,
            agent_api_target_port: None,
            agent_api_node_port: None,
            agent_api_app_protocol: None,
            agent_api_publish_not_ready_addresses: false,
            agent_api_load_balancer_class: None,
            agent_api_load_balancer_ip: None,
            agent_api_external_ips: Vec::new(),
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_traffic_distribution: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: false,
            relay_service_type: "LoadBalancer".to_string(),
            relay_cluster_ip: None,
            relay_secondary_cluster_ip: None,
            relay_udp_port: None,
            relay_udp_target_port: None,
            relay_http_port: None,
            relay_http_target_port: None,
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_udp_app_protocol: None,
            relay_http_app_protocol: None,
            relay_publish_not_ready_addresses: false,
            relay_load_balancer_class: None,
            relay_load_balancer_ip: None,
            relay_external_ips: Vec::new(),
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: Vec::new(),
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_traffic_distribution: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: Vec::new(),
            relay_admission_bearer_token_secret: None,
            relay_admission_bearer_token_key: None,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        }
    }

    #[test]
    fn k8s_install_plan_rejects_agent_api_target_port_without_service_exposure(
    ) -> anyhow::Result<()> {
        let mut args = base_k8s_install_args();
        args.agent_api_target_port = Some(9790);

        let error = match k8s_install_plan(args) {
            Ok(_) => anyhow::bail!("inactive agent API targetPort override should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--agent-api-target-port requires --expose-agent-api"));
        Ok(())
    }

    #[test]
    fn k8s_install_plan_wires_route_discovery_settings() -> anyhow::Result<()> {
        let mut args = base_k8s_install_args();
        args.kubernetes_discover_services = true;
        args.kubernetes_discover_api_server = false;
        args.kubernetes_api_server_cidrs = vec!["10.0.0.1/32".parse()?];
        args.kubernetes_service_cidrs = vec!["10.96.0.0/12".parse()?];
        args.kubernetes_namespaces = vec!["default".to_string(), "platform".to_string()];
        args.kubernetes_service_label_selector = Some("ipars.io/expose=true".to_string());
        args.kubernetes_route_provider = Some("route-provider-a".to_string());
        args.kubernetes_route_interval_seconds = 15;
        args.agent_runtime_backend = "dry-run".to_string();
        args.route_backend = "kernel-netlink".to_string();
        args.agent_peer_map_poll_interval_seconds = 45;
        args.disable_rbac = true;

        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];

        assert!(helm.contains("--set rbac.create=false"));
        assert!(helm.contains("--set agent.runtimeBackend=dry-run"));
        assert!(helm.contains("--set agent.routeBackend=kernel-netlink"));
        assert!(helm.contains("--set agent.peerMap.pollIntervalSeconds=45"));
        assert!(helm.contains("--set serviceExposure.discoverServices=true"));
        assert!(helm.contains("--set serviceExposure.discoverApiServer=false"));
        assert!(helm.contains("--set serviceExposure.routeIntervalSeconds=15"));
        assert!(helm.contains("--set-string 'serviceExposure.apiServerCidrs[0]=10.0.0.1/32'"));
        assert!(helm.contains("--set-string 'serviceExposure.serviceCidrs[0]=10.96.0.0/12'"));
        assert!(helm.contains("--set-string 'serviceExposure.namespaces[0]=default'"));
        assert!(helm.contains("--set-string 'serviceExposure.namespaces[1]=platform'"));
        assert!(
            helm.contains("--set-string serviceExposure.serviceLabelSelector=ipars.io/expose=true")
        );
        assert!(helm.contains("--set agent.routeProvider=false"));
        assert!(helm.contains("--set-string serviceExposure.routeProviderNodeId=route-provider-a"));
        Ok(())
    }

    #[test]
    fn k8s_install_plan_wires_and_validates_agent_http_timeouts() -> anyhow::Result<()> {
        let mut args = base_k8s_install_args();
        args.agent_http_connect_timeout_seconds = 7;
        args.agent_http_request_timeout_seconds = 45;
        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];
        assert!(helm.contains("--set agent.http.connectTimeoutSeconds=7"));
        assert!(helm.contains("--set agent.http.requestTimeoutSeconds=45"));

        let mut mismatch = base_k8s_install_args();
        mismatch.agent_http_connect_timeout_seconds = 31;
        mismatch.agent_http_request_timeout_seconds = 30;
        let error = match k8s_install_plan(mismatch) {
            Ok(_) => anyhow::bail!("Agent HTTP timeout ordering should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(
            "--agent-http-connect-timeout-seconds must not exceed --agent-http-request-timeout-seconds"
        ));

        let mut oversized = base_k8s_install_args();
        oversized.agent_http_request_timeout_seconds = 3_601;
        let error = match k8s_install_plan(oversized) {
            Ok(_) => anyhow::bail!("oversized Agent HTTP request timeout should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--agent-http-request-timeout-seconds must not exceed 3600"));
        Ok(())
    }

    #[test]
    fn k8s_install_plan_wires_and_validates_direct_path_verification() -> anyhow::Result<()> {
        let mut args = base_k8s_install_args();
        args.agent_direct_path_probe_timeout_seconds = 90;
        args.agent_direct_handshake_max_age_seconds = 240;
        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];
        assert!(helm.contains("--set agent.directPathVerification.probeTimeoutSeconds=90"));
        assert!(helm.contains("--set agent.directPathVerification.handshakeMaxAgeSeconds=240"));

        let mut short = base_k8s_install_args();
        short.agent_direct_path_probe_timeout_seconds = 59;
        let error = test_error(
            k8s_install_plan(short),
            "probe timeout shorter than poll plus signal interval should fail",
        );
        assert!(error.to_string().contains(
            "--agent-direct-path-probe-timeout-seconds must be at least the peer-map poll interval"
        ));

        let mut stale = base_k8s_install_args();
        stale.agent_direct_handshake_max_age_seconds = 29;
        let error = test_error(
            k8s_install_plan(stale),
            "handshake age shorter than signal interval should fail",
        );
        assert!(error
            .to_string()
            .contains("--agent-direct-handshake-max-age-seconds must be at least the 30-second signal path interval"));
        Ok(())
    }

    #[test]
    fn k8s_install_plan_wires_and_validates_peer_probe() -> anyhow::Result<()> {
        let mut args = base_k8s_install_args();
        args.agent_peer_probe = AgentPeerProbeInstallArgs {
            disabled: false,
            port: Some(51_900),
            interval_seconds: 45,
            sample_count: 7,
            response_timeout_millis: 750,
            sample_interval_millis: 25,
            max_concurrency: 8,
            responder_max_requests_per_second: 200,
            observation_max_age_seconds: 90,
        };
        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];
        for expected in [
            "--set agent.peerProbe.enabled=true",
            "--set agent.peerProbe.port=51900",
            "--set agent.peerProbe.intervalSeconds=45",
            "--set agent.peerProbe.sampleCount=7",
            "--set agent.peerProbe.responseTimeoutMillis=750",
            "--set agent.peerProbe.sampleIntervalMillis=25",
            "--set agent.peerProbe.maxConcurrency=8",
            "--set agent.peerProbe.responderMaxRequestsPerSecond=200",
            "--set agent.peerProbe.observationMaxAgeSeconds=90",
        ] {
            assert!(helm.contains(expected), "missing `{expected}` in `{helm}`");
        }

        let mut dry_run = base_k8s_install_args();
        dry_run.agent_runtime_backend = "dry-run".to_string();
        let plan = k8s_install_plan(dry_run)?;
        assert!(plan.commands[2].contains("--set agent.peerProbe.enabled=false"));

        let mut peer_map_disabled = base_k8s_install_args();
        peer_map_disabled.disable_agent_peer_map = true;
        let plan = k8s_install_plan(peer_map_disabled)?;
        assert!(plan.commands[2].contains("--set agent.peerProbe.enabled=false"));

        let mut port_conflict = base_k8s_install_args();
        port_conflict.agent_wireguard_listen_port = Some(DEFAULT_K8S_AGENT_PEER_PROBE_PORT);
        let error = test_error(
            k8s_install_plan(port_conflict),
            "peer probe and WireGuard ports must differ",
        );
        assert!(error.to_string().contains(
            "--agent-peer-probe-port must differ from the effective WireGuard listen port 51821"
        ));

        let mut stale = base_k8s_install_args();
        stale.agent_peer_probe.interval_seconds = 60;
        stale.agent_peer_probe.observation_max_age_seconds = 59;
        let error = test_error(
            k8s_install_plan(stale),
            "observation freshness shorter than probe interval must fail",
        );
        assert!(error
            .to_string()
            .contains("--agent-peer-probe-observation-max-age-seconds must be at least both"));
        Ok(())
    }

    #[test]
    fn install_commands_parse_peer_probe_options() -> anyhow::Result<()> {
        for command in ["docker", "k8s"] {
            let cli = Cli::try_parse_from([
                "ipars",
                command,
                "install",
                "--disable-agent-peer-probe",
                "--agent-peer-probe-port",
                "51900",
                "--agent-peer-probe-interval-seconds",
                "45",
                "--agent-peer-probe-sample-count",
                "7",
                "--agent-peer-probe-response-timeout-millis",
                "750",
                "--agent-peer-probe-sample-interval-millis",
                "25",
                "--agent-peer-probe-max-concurrency",
                "8",
                "--agent-peer-probe-responder-max-requests-per-second",
                "200",
                "--agent-peer-probe-observation-max-age-seconds",
                "90",
            ])?;
            let settings = match cli.command {
                Command::Docker {
                    command: DockerCommand::Install(args),
                } => args.agent_peer_probe,
                Command::K8s {
                    command: K8sCommand::Install(args),
                } => args.agent_peer_probe,
                _ => anyhow::bail!("expected {command} install command"),
            };
            assert_eq!(
                settings,
                AgentPeerProbeInstallArgs {
                    disabled: true,
                    port: Some(51_900),
                    interval_seconds: 45,
                    sample_count: 7,
                    response_timeout_millis: 750,
                    sample_interval_millis: 25,
                    max_concurrency: 8,
                    responder_max_requests_per_second: 200,
                    observation_max_age_seconds: 90,
                }
            );
        }
        Ok(())
    }

    #[test]
    fn k8s_install_plan_wires_agent_wireguard_and_stun_bind_ports() -> anyhow::Result<()> {
        let mut explicit = base_k8s_install_args();
        explicit.agent_wireguard_listen_port = Some(51830);
        explicit.agent_stun_bind = Some("0.0.0.0:51830".to_string());
        let plan = k8s_install_plan(explicit)?;
        let helm = &plan.commands[2];
        assert!(helm.contains("--set agent.wireguardListenPort=51830"));
        assert!(helm.contains("--set-string agent.stunBind=0.0.0.0:51830"));

        let mut listen_only = base_k8s_install_args();
        listen_only.agent_wireguard_listen_port = Some(51831);
        let plan = k8s_install_plan(listen_only)?;
        let helm = &plan.commands[2];
        assert!(helm.contains("--set agent.wireguardListenPort=51831"));
        assert!(helm.contains("--set-string agent.stunBind=0.0.0.0:51831"));

        let mut bind_only = base_k8s_install_args();
        bind_only.agent_stun_bind = Some("[::]:51832".to_string());
        let plan = k8s_install_plan(bind_only)?;
        let helm = &plan.commands[2];
        assert!(helm.contains("--set agent.wireguardListenPort=51832"));
        assert!(helm.contains("--set-string 'agent.stunBind=[::]:51832'"));

        let mut mismatch = base_k8s_install_args();
        mismatch.agent_wireguard_listen_port = Some(51833);
        mismatch.agent_stun_bind = Some("0.0.0.0:51834".to_string());
        let error = test_error(
            k8s_install_plan(mismatch),
            "mismatched WireGuard and STUN ports should fail",
        );
        assert!(error
            .to_string()
            .contains("--agent-stun-bind port must equal --agent-wireguard-listen-port"));

        assert!(Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--agent-wireguard-listen-port",
            "0",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--agent-stun-bind",
            "239.1.1.1:51820",
        ])
        .is_err());
        Ok(())
    }

    #[test]
    fn k8s_install_plan_rejects_invalid_route_provider() -> anyhow::Result<()> {
        let mut args = base_k8s_install_args();
        args.kubernetes_route_provider = Some("route provider".to_string());

        let error = match k8s_install_plan(args) {
            Ok(_) => anyhow::bail!("invalid Kubernetes route provider should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--kubernetes-route-provider must contain only ASCII letters, digits, '_', '.' or '-'"
        ));
        Ok(())
    }

    #[test]
    fn k8s_install_plan_rejects_invalid_route_backend() {
        assert!(
            Cli::try_parse_from(["ipars", "k8s", "install", "--route-backend", "invalid"]).is_err()
        );
        assert!(Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--agent-runtime-backend",
            "invalid",
        ])
        .is_err());

        let mut invalid_runtime_backend = base_k8s_install_args();
        invalid_runtime_backend.agent_runtime_backend = "invalid".to_string();
        let error = test_error(
            k8s_install_plan(invalid_runtime_backend),
            "invalid runtime backend should fail",
        );
        assert!(error
            .to_string()
            .contains("agent runtime backend must be linux-command or dry-run"));
    }

    #[test]
    fn k8s_install_plan_wires_agent_peer_map_sync() -> anyhow::Result<()> {
        let mut args = base_k8s_install_args();
        args.disable_agent_peer_map = true;
        args.agent_peer_map_poll_interval_seconds = 45;

        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];

        assert!(helm.contains("--set agent.peerMap.enabled=false"));
        assert!(helm.contains("--set agent.peerMap.pollIntervalSeconds=45"));

        let mut invalid_interval = base_k8s_install_args();
        invalid_interval.agent_peer_map_poll_interval_seconds = 0;
        let error = match k8s_install_plan(invalid_interval) {
            Ok(_) => anyhow::bail!("zero agent peer-map poll interval should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--agent-peer-map-poll-interval-seconds must be greater than zero"));
        Ok(())
    }

    #[test]
    fn k8s_install_plan_wires_image_pull_secrets() -> anyhow::Result<()> {
        let mut args = base_k8s_install_args();
        args.image_repository = Some("registry.example.com/platform/ipars".to_string());
        args.image_tag = Some("2026.07.05".to_string());
        args.image_pull_policy = Some("Always".to_string());
        args.image_pull_secrets = vec!["registry-cred".to_string(), "mirror.cred".to_string()];

        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];

        assert!(helm.contains("--set-string image.repository=registry.example.com/platform/ipars"));
        assert!(helm.contains("--set-string image.tag=2026.07.05"));
        assert!(helm.contains("--set-string image.pullPolicy=Always"));
        assert!(helm.contains("--set-string 'imagePullSecrets[0]=registry-cred'"));
        assert!(helm.contains("--set-string 'imagePullSecrets[1]=mirror.cred'"));

        let mut duplicate = base_k8s_install_args();
        duplicate.image_pull_secrets =
            vec!["registry-cred".to_string(), "registry-cred".to_string()];
        let error = match k8s_install_plan(duplicate) {
            Ok(_) => panic!("duplicate image pull Secret should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--image-pull-secret"));

        assert!(Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--image-pull-secret",
            "bad secret",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--image-repository",
            "registry.example.com/platform/ipars:latest",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--image-repository",
            "registry.example.com:https/platform/ipars",
        ])
        .is_err());
        assert!(
            Cli::try_parse_from(["ipars", "k8s", "install", "--image-tag", "bad tag",]).is_err()
        );
        assert!(Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--image-pull-policy",
            "Sometimes",
        ])
        .is_err());

        Ok(())
    }

    #[test]
    fn k8s_install_plan_wires_agent_security_context() -> anyhow::Result<()> {
        let mut args = base_k8s_install_args();
        args.agent_add_capabilities = vec![
            "NET_ADMIN".to_string(),
            "NET_RAW".to_string(),
            "SYS_TIME".to_string(),
        ];
        args.agent_drop_capabilities = vec!["MKNOD".to_string()];
        args.disable_agent_privilege_escalation = true;
        args.agent_read_only_root_filesystem = true;
        args.agent_seccomp_profile = Some("Localhost".to_string());
        args.agent_seccomp_localhost_profile = Some("profiles/ipars-agent.json".to_string());
        args.agent_run_as_user = Some(1000);
        args.agent_run_as_group = Some(1000);
        args.agent_run_as_non_root = true;
        args.agent_fs_group = Some(2000);
        args.agent_fs_group_change_policy = Some("OnRootMismatch".to_string());
        args.agent_supplemental_groups = vec![2001, 2002];

        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];

        assert!(helm.contains("--set agent.securityContext.allowPrivilegeEscalation=false"));
        assert!(helm.contains("--set agent.securityContext.readOnlyRootFilesystem=true"));
        assert!(helm.contains("--set-string agent.securityContext.seccompProfile.type=Localhost"));
        assert!(helm.contains(
            "--set-string agent.securityContext.seccompProfile.localhostProfile=profiles/ipars-agent.json"
        ));
        assert!(helm.contains("--set agent.podSecurityContext.runAsUser=1000"));
        assert!(helm.contains("--set agent.podSecurityContext.runAsGroup=1000"));
        assert!(helm.contains("--set agent.podSecurityContext.runAsNonRoot=true"));
        assert!(helm.contains("--set agent.podSecurityContext.fsGroup=2000"));
        assert!(helm
            .contains("--set-string agent.podSecurityContext.fsGroupChangePolicy=OnRootMismatch"));
        assert!(helm.contains("--set 'agent.podSecurityContext.supplementalGroups[0]=2001'"));
        assert!(helm.contains("--set 'agent.podSecurityContext.supplementalGroups[1]=2002'"));
        assert!(helm.contains(
            "--set 'agent.securityContext.capabilities.add={NET_ADMIN,NET_RAW,SYS_TIME}'"
        ));
        assert!(helm.contains("--set 'agent.securityContext.capabilities.drop={MKNOD}'"));

        let mut privileged = base_k8s_install_args();
        privileged.agent_privileged = true;
        let plan = k8s_install_plan(privileged)?;
        assert!(plan.commands[2].contains("--set agent.privileged=true"));

        let mut duplicate = base_k8s_install_args();
        duplicate.agent_add_capabilities = vec!["NET_ADMIN".to_string(), "NET_ADMIN".to_string()];
        let error = match k8s_install_plan(duplicate) {
            Ok(_) => panic!("duplicate agent capability should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-add-capability"));

        let mut drop_default = base_k8s_install_args();
        drop_default.agent_drop_capabilities = vec!["NET_RAW".to_string()];
        let error = match k8s_install_plan(drop_default) {
            Ok(_) => panic!("dropping a default added capability should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-drop-capability"));

        let mut privilege_escalation_conflict = base_k8s_install_args();
        privilege_escalation_conflict.agent_privileged = true;
        privilege_escalation_conflict.disable_agent_privilege_escalation = true;
        let error = match k8s_install_plan(privilege_escalation_conflict) {
            Ok(_) => panic!("privileged pod should not disable privilege escalation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--disable-agent-privilege-escalation"));

        let mut missing_localhost_profile = base_k8s_install_args();
        missing_localhost_profile.agent_seccomp_profile = Some("Localhost".to_string());
        let error = match k8s_install_plan(missing_localhost_profile) {
            Ok(_) => panic!("Localhost seccomp profile should require a localhost profile path"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-seccomp-localhost-profile"));

        let mut extra_localhost_profile = base_k8s_install_args();
        extra_localhost_profile.agent_seccomp_profile = Some("RuntimeDefault".to_string());
        extra_localhost_profile.agent_seccomp_localhost_profile =
            Some("profiles/ipars-agent.json".to_string());
        let error = match k8s_install_plan(extra_localhost_profile) {
            Ok(_) => panic!("non-Localhost seccomp profile should reject localhostProfile"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-seccomp-localhost-profile"));

        let mut non_root_with_root_uid = base_k8s_install_args();
        non_root_with_root_uid.agent_run_as_user = Some(0);
        non_root_with_root_uid.agent_run_as_non_root = true;
        let error = match k8s_install_plan(non_root_with_root_uid) {
            Ok(_) => panic!("runAsNonRoot should reject runAsUser=0"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-run-as-non-root"));

        let mut missing_fs_group = base_k8s_install_args();
        missing_fs_group.agent_fs_group_change_policy = Some("OnRootMismatch".to_string());
        let error = match k8s_install_plan(missing_fs_group) {
            Ok(_) => panic!("fsGroupChangePolicy should require fsGroup"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-fs-group-change-policy"));

        let mut duplicate_supplemental_group = base_k8s_install_args();
        duplicate_supplemental_group.agent_supplemental_groups = vec![2001, 2001];
        let error = match k8s_install_plan(duplicate_supplemental_group) {
            Ok(_) => panic!("duplicate supplemental groups should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-supplemental-group"));

        assert!(Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--agent-add-capability",
            "net_admin",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--agent-seccomp-profile",
            "Default",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--agent-seccomp-localhost-profile",
            "../profile.json",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--agent-fs-group-change-policy",
            "Eventually",
        ])
        .is_err());

        Ok(())
    }

    #[test]
    fn k8s_install_plan_wires_service_account_options() -> anyhow::Result<()> {
        let mut args = base_k8s_install_args();
        args.service_account_name = Some("edge-agent".to_string());
        args.service_account_annotations = vec![KeyValueArg {
            key: "eks.amazonaws.com/role-arn".to_string(),
            value: "arn:aws:iam::123456789012:role/ipars-agent".to_string(),
        }];

        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];

        assert!(helm.contains("--set-string serviceAccount.name=edge-agent"));
        assert!(helm.contains(
            "--set-string 'serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn=arn:aws:iam::123456789012:role/ipars-agent'"
        ));

        let mut external = base_k8s_install_args();
        external.disable_service_account_creation = true;
        external.service_account_name = Some("existing-agent".to_string());
        let plan = k8s_install_plan(external)?;
        let helm = &plan.commands[2];
        assert!(helm.contains("--set serviceAccount.create=false"));
        assert!(helm.contains("--set-string serviceAccount.name=existing-agent"));

        let mut invalid_name = base_k8s_install_args();
        invalid_name.service_account_name = Some("system/agent".to_string());
        let error = match k8s_install_plan(invalid_name) {
            Ok(_) => panic!("invalid ServiceAccount name should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("ServiceAccount name"));

        let mut invalid_annotation = base_k8s_install_args();
        invalid_annotation.disable_service_account_creation = true;
        invalid_annotation.service_account_annotations = vec![KeyValueArg {
            key: "eks.amazonaws.com/role-arn".to_string(),
            value: "arn:aws:iam::123456789012:role/ipars-agent".to_string(),
        }];
        let error = match k8s_install_plan(invalid_annotation) {
            Ok(_) => panic!("annotations without ServiceAccount creation should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--service-account-annotation"));

        let mut duplicate_annotation = base_k8s_install_args();
        duplicate_annotation.service_account_annotations = vec![
            KeyValueArg {
                key: "eks.amazonaws.com/role-arn".to_string(),
                value: "arn:aws:iam::123456789012:role/ipars-agent".to_string(),
            },
            KeyValueArg {
                key: "eks.amazonaws.com/role-arn".to_string(),
                value: "arn:aws:iam::123456789012:role/ipars-agent-v2".to_string(),
            },
        ];
        let error = match k8s_install_plan(duplicate_annotation) {
            Ok(_) => panic!("duplicate ServiceAccount annotation keys should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--service-account-annotation must not repeat annotation key eks.amazonaws.com/role-arn"
        ));

        Ok(())
    }

    #[test]
    fn k8s_install_plan_wires_agent_pod_scheduling_options() -> anyhow::Result<()> {
        let mut args = base_k8s_install_args();
        args.agent_pod_labels = vec![KeyValueArg {
            key: "ipars.io/role".to_string(),
            value: "agent".to_string(),
        }];
        args.agent_pod_annotations = vec![KeyValueArg {
            key: "prometheus.io/scrape".to_string(),
            value: "true".to_string(),
        }];
        args.agent_priority_class = Some("ipars-agent-critical".to_string());
        args.agent_scheduler_name = Some("ipars-scheduler".to_string());
        args.agent_runtime_class = Some("ipars-runtime".to_string());
        args.agent_node_selectors = vec![KeyValueArg {
            key: "kubernetes.io/os".to_string(),
            value: "linux".to_string(),
        }];
        args.agent_node_affinity_required = vec![KubernetesNodeAffinityExpressionArg {
            key: "node-role.kubernetes.io/worker".to_string(),
            operator: "Exists".to_string(),
            values: Vec::new(),
        }];
        args.agent_node_affinity_preferred = vec![KubernetesPreferredNodeAffinityArg {
            weight: 75,
            expression: KubernetesNodeAffinityExpressionArg {
                key: "node.kubernetes.io/instance-type".to_string(),
                operator: "In".to_string(),
                values: vec!["m7i.large".to_string(), "m7i.xlarge".to_string()],
            },
        }];
        args.agent_pod_affinity_required = vec![KubernetesPodAffinityTermArg {
            topology_key: "kubernetes.io/hostname".to_string(),
            match_expressions: vec![KubernetesLabelSelectorExpressionArg {
                key: "app.kubernetes.io/name".to_string(),
                operator: "In".to_string(),
                values: vec!["ipars".to_string()],
            }],
            namespaces: vec!["ipars-system".to_string()],
        }];
        args.agent_pod_anti_affinity_preferred = vec![KubernetesPreferredPodAffinityArg {
            weight: 90,
            term: KubernetesPodAffinityTermArg {
                topology_key: "topology.kubernetes.io/zone".to_string(),
                match_expressions: vec![KubernetesLabelSelectorExpressionArg {
                    key: "ipars.io/role".to_string(),
                    operator: "Exists".to_string(),
                    values: Vec::new(),
                }],
                namespaces: Vec::new(),
            },
        }];
        args.agent_tolerations = vec![
            KubernetesTolerationArg {
                key: Some("node-role.kubernetes.io/control-plane".to_string()),
                operator: Some("Exists".to_string()),
                value: None,
                effect: Some("NoSchedule".to_string()),
                toleration_seconds: None,
            },
            KubernetesTolerationArg {
                key: Some("node.kubernetes.io/unreachable".to_string()),
                operator: Some("Exists".to_string()),
                value: None,
                effect: Some("NoExecute".to_string()),
                toleration_seconds: Some(600),
            },
        ];
        args.agent_topology_spreads = vec![KubernetesTopologySpreadArg {
            topology_key: "topology.kubernetes.io/zone".to_string(),
            max_skew: 1,
            when_unsatisfiable: "ScheduleAnyway".to_string(),
            min_domains: None,
            node_affinity_policy: Some("Honor".to_string()),
            node_taints_policy: Some("Honor".to_string()),
        }];
        args.agent_termination_grace_period_seconds = Some(45);
        args.agent_pre_stop_sleep_seconds = Some(20);
        args.disable_agent_service_account_token = true;
        args.agent_dns_policy = Some("Default".to_string());
        args.agent_state_host_path = Some("/opt/ipars/state".to_string());
        args.agent_state_mount_path = Some("/run/ipars/state".to_string());
        args.agent_state_host_path_type = Some("Directory".to_string());
        args.disable_agent_liveness_probe = true;
        args.disable_agent_readiness_probe = true;
        args.disable_agent_startup_probe = true;
        args.agent_resource_request_cpu = Some("100m".to_string());
        args.agent_resource_request_memory = Some("128Mi".to_string());
        args.agent_resource_limit_cpu = Some("500m".to_string());
        args.agent_resource_limit_memory = Some("512Mi".to_string());

        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];

        assert!(!helm.contains("--set agent.hostNetwork=false"));
        assert!(helm.contains("--set-string 'agent.podLabels.ipars\\.io/role=agent'"));
        assert!(helm.contains("--set-string 'agent.podAnnotations.prometheus\\.io/scrape=true'"));
        assert!(helm.contains("--set-string agent.priorityClassName=ipars-agent-critical"));
        assert!(helm.contains("--set-string 'agent.nodeSelector.kubernetes\\.io/os=linux'"));
        assert!(helm.contains("--set-string agent.schedulerName=ipars-scheduler"));
        assert!(helm.contains("--set-string agent.runtimeClassName=ipars-runtime"));
        assert!(helm.contains(
            "--set-string 'agent.nodeAffinity.required.matchExpressions[0].key=node-role.kubernetes.io/worker'"
        ));
        assert!(helm.contains(
            "--set-string 'agent.nodeAffinity.required.matchExpressions[0].operator=Exists'"
        ));
        assert!(helm.contains("--set 'agent.nodeAffinity.preferred[0].weight=75'"));
        assert!(helm.contains(
            "--set-string 'agent.nodeAffinity.preferred[0].matchExpressions[0].key=node.kubernetes.io/instance-type'"
        ));
        assert!(helm.contains(
            "--set-string 'agent.nodeAffinity.preferred[0].matchExpressions[0].operator=In'"
        ));
        assert!(helm.contains(
            "--set-string 'agent.nodeAffinity.preferred[0].matchExpressions[0].values[0]=m7i.large'"
        ));
        assert!(helm.contains(
            "--set-string 'agent.nodeAffinity.preferred[0].matchExpressions[0].values[1]=m7i.xlarge'"
        ));
        assert!(helm.contains(
            "--set-string 'agent.podAffinity.required[0].topologyKey=kubernetes.io/hostname'"
        ));
        assert!(helm
            .contains("--set-string 'agent.podAffinity.required[0].namespaces[0]=ipars-system'"));
        assert!(helm.contains(
            "--set-string 'agent.podAffinity.required[0].matchExpressions[0].key=app.kubernetes.io/name'"
        ));
        assert!(helm.contains(
            "--set-string 'agent.podAffinity.required[0].matchExpressions[0].operator=In'"
        ));
        assert!(helm.contains(
            "--set-string 'agent.podAffinity.required[0].matchExpressions[0].values[0]=ipars'"
        ));
        assert!(helm.contains("--set 'agent.podAntiAffinity.preferred[0].weight=90'"));
        assert!(helm.contains(
            "--set-string 'agent.podAntiAffinity.preferred[0].topologyKey=topology.kubernetes.io/zone'"
        ));
        assert!(helm.contains(
            "--set-string 'agent.podAntiAffinity.preferred[0].matchExpressions[0].key=ipars.io/role'"
        ));
        assert!(helm.contains(
            "--set-string 'agent.podAntiAffinity.preferred[0].matchExpressions[0].operator=Exists'"
        ));
        assert!(helm.contains(
            "--set-string 'agent.tolerations[0].key=node-role.kubernetes.io/control-plane'"
        ));
        assert!(helm.contains("--set-string 'agent.tolerations[0].operator=Exists'"));
        assert!(helm.contains("--set-string 'agent.tolerations[0].effect=NoSchedule'"));
        assert!(
            helm.contains("--set-string 'agent.tolerations[1].key=node.kubernetes.io/unreachable'")
        );
        assert!(helm.contains("--set-string 'agent.tolerations[1].effect=NoExecute'"));
        assert!(helm.contains("--set-string 'agent.tolerations[1].tolerationSeconds=600'"));
        assert!(helm.contains(
            "--set-string 'agent.topologySpreadConstraints[0].topologyKey=topology.kubernetes.io/zone'"
        ));
        assert!(helm.contains("--set 'agent.topologySpreadConstraints[0].maxSkew=1'"));
        assert!(helm.contains(
            "--set-string 'agent.topologySpreadConstraints[0].whenUnsatisfiable=ScheduleAnyway'"
        ));
        assert!(helm.contains(
            "--set-string 'agent.topologySpreadConstraints[0].nodeAffinityPolicy=Honor'"
        ));
        assert!(helm
            .contains("--set-string 'agent.topologySpreadConstraints[0].nodeTaintsPolicy=Honor'"));
        assert!(helm.contains("--set agent.automountServiceAccountToken=false"));
        assert!(helm.contains("--set agent.dnsPolicy=Default"));
        assert!(helm.contains("--set-string agent.state.hostPath=/opt/ipars/state"));
        assert!(helm.contains("--set-string agent.state.mountPath=/run/ipars/state"));
        assert!(helm.contains("--set agent.state.hostPathType=Directory"));
        assert!(helm.contains("--set agent.probes.liveness.enabled=false"));
        assert!(helm.contains("--set agent.probes.readiness.enabled=false"));
        assert!(helm.contains("--set agent.probes.startup.enabled=false"));
        assert!(helm.contains("--set agent.terminationGracePeriodSeconds=45"));
        assert!(helm.contains("--set agent.lifecycle.preStopSleepSeconds=20"));
        assert!(helm.contains("--set-string agent.resources.requests.cpu=100m"));
        assert!(helm.contains("--set-string agent.resources.requests.memory=128Mi"));
        assert!(helm.contains("--set-string agent.resources.limits.cpu=500m"));
        assert!(helm.contains("--set-string agent.resources.limits.memory=512Mi"));

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--agent-pod-label",
            "Example.com/role=agent",
        ]);
        assert!(parsed.is_err());
        assert!(parse_kubernetes_dns_policy("ClusterDefault").is_err());
        assert!(parse_kubernetes_absolute_path("relative/ipars").is_err());
        assert!(parse_kubernetes_host_path_type("File").is_err());
        assert!(parse_kubernetes_resource_quantity("100 m").is_err());
        assert!(parse_kubernetes_http_probe_path("healthz").is_err());

        let mut probe_config = base_k8s_install_args();
        probe_config.agent_probes.liveness_path = Some("/livez".to_string());
        probe_config.agent_probes.liveness_initial_delay_seconds = Some(15);
        probe_config.agent_probes.liveness_period_seconds = Some(20);
        probe_config.agent_probes.liveness_timeout_seconds = Some(2);
        probe_config.agent_probes.liveness_failure_threshold = Some(5);
        probe_config.agent_probes.readiness_path = Some("/readyz".to_string());
        probe_config.agent_probes.readiness_initial_delay_seconds = Some(3);
        probe_config.agent_probes.readiness_period_seconds = Some(4);
        probe_config.agent_probes.readiness_timeout_seconds = Some(1);
        probe_config.agent_probes.readiness_failure_threshold = Some(2);
        probe_config.agent_probes.startup_path = Some("/startupz".to_string());
        probe_config.agent_probes.startup_initial_delay_seconds = Some(0);
        probe_config.agent_probes.startup_period_seconds = Some(5);
        probe_config.agent_probes.startup_timeout_seconds = Some(1);
        probe_config.agent_probes.startup_failure_threshold = Some(30);
        let plan = k8s_install_plan(probe_config)?;
        let helm = &plan.commands[2];
        assert!(helm.contains("--set-string agent.probes.liveness.path=/livez"));
        assert!(helm.contains("--set agent.probes.liveness.initialDelaySeconds=15"));
        assert!(helm.contains("--set agent.probes.liveness.periodSeconds=20"));
        assert!(helm.contains("--set agent.probes.liveness.timeoutSeconds=2"));
        assert!(helm.contains("--set agent.probes.liveness.failureThreshold=5"));
        assert!(helm.contains("--set-string agent.probes.readiness.path=/readyz"));
        assert!(helm.contains("--set agent.probes.readiness.initialDelaySeconds=3"));
        assert!(helm.contains("--set agent.probes.readiness.periodSeconds=4"));
        assert!(helm.contains("--set agent.probes.readiness.timeoutSeconds=1"));
        assert!(helm.contains("--set agent.probes.readiness.failureThreshold=2"));
        assert!(helm.contains("--set-string agent.probes.startup.path=/startupz"));
        assert!(helm.contains("--set agent.probes.startup.initialDelaySeconds=0"));
        assert!(helm.contains("--set agent.probes.startup.periodSeconds=5"));
        assert!(helm.contains("--set agent.probes.startup.timeoutSeconds=1"));
        assert!(helm.contains("--set agent.probes.startup.failureThreshold=30"));

        let mut disabled_probe_config = base_k8s_install_args();
        disabled_probe_config.disable_agent_liveness_probe = true;
        disabled_probe_config.agent_probes.liveness_path = Some("/livez".to_string());
        let error = match k8s_install_plan(disabled_probe_config) {
            Ok(_) => panic!("disabled liveness probe should reject liveness settings"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("agent liveness probe settings require the probe to be enabled"));

        let mut disabled_startup_probe_config = base_k8s_install_args();
        disabled_startup_probe_config.disable_agent_startup_probe = true;
        disabled_startup_probe_config.agent_probes.startup_path = Some("/startupz".to_string());
        let error = match k8s_install_plan(disabled_startup_probe_config) {
            Ok(_) => panic!("disabled startup probe should reject startup settings"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("agent startup probe settings require the probe to be enabled"));

        let mut zero_probe_period = base_k8s_install_args();
        zero_probe_period.agent_probes.readiness_period_seconds = Some(0);
        let error = match k8s_install_plan(zero_probe_period) {
            Ok(_) => panic!("zero readiness period should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("agent readiness probe period seconds must be greater than zero"));

        let mut zero_startup_threshold = base_k8s_install_args();
        zero_startup_threshold
            .agent_probes
            .startup_failure_threshold = Some(0);
        let error = match k8s_install_plan(zero_startup_threshold) {
            Ok(_) => panic!("zero startup threshold should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("agent startup probe failure threshold must be greater than zero"));

        let mut unsafe_host_path = base_k8s_install_args();
        unsafe_host_path.agent_state_host_path = Some("/etc/ipars".to_string());
        let error = match k8s_install_plan(unsafe_host_path) {
            Ok(_) => panic!("sensitive host state path should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("agent state host path"));
        assert!(error.contains("sensitive system path"));

        let mut unsafe_mount_path = base_k8s_install_args();
        unsafe_mount_path.agent_state_mount_path = Some("/proc/ipars".to_string());
        let error = match k8s_install_plan(unsafe_mount_path) {
            Ok(_) => panic!("sensitive container state mount path should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("agent state mount path"));
        assert!(error.contains("sensitive system path"));

        let mut duplicate_pod_annotation = base_k8s_install_args();
        duplicate_pod_annotation.agent_pod_annotations = vec![
            KeyValueArg {
                key: "prometheus.io/scrape".to_string(),
                value: "true".to_string(),
            },
            KeyValueArg {
                key: "prometheus.io/scrape".to_string(),
                value: "false".to_string(),
            },
        ];
        let error = match k8s_install_plan(duplicate_pod_annotation) {
            Ok(_) => panic!("duplicate agent pod annotation keys should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-pod-annotation must not repeat annotation key prometheus.io/scrape"
        ));

        let mut pod_network = base_k8s_install_args();
        pod_network.disable_agent_host_network = true;
        let plan = k8s_install_plan(pod_network)?;
        assert!(plan.commands[2].contains("--set agent.hostNetwork=false"));
        assert!(plan.commands[2].contains("--set agent.dnsPolicy=ClusterFirst"));

        let mut invalid_dns_policy = base_k8s_install_args();
        invalid_dns_policy.disable_agent_host_network = true;
        invalid_dns_policy.agent_dns_policy = Some("ClusterFirstWithHostNet".to_string());
        let error = match k8s_install_plan(invalid_dns_policy) {
            Ok(_) => panic!("ClusterFirstWithHostNet should require hostNetwork"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("ClusterFirstWithHostNet requires hostNetwork"));

        let mut invalid_selector = base_k8s_install_args();
        invalid_selector.agent_node_selectors = vec![KeyValueArg {
            key: "kubernetes.io/os".to_string(),
            value: "-linux".to_string(),
        }];
        let error = match k8s_install_plan(invalid_selector) {
            Ok(_) => panic!("invalid node selector label value should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("label value"));

        let mut invalid_required_affinity = base_k8s_install_args();
        invalid_required_affinity.agent_node_affinity_required =
            vec![KubernetesNodeAffinityExpressionArg {
                key: "kubernetes.io/os".to_string(),
                operator: "In".to_string(),
                values: Vec::new(),
            }];
        let error = match k8s_install_plan(invalid_required_affinity) {
            Ok(_) => panic!("node affinity In without values should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("values are required"));

        let mut invalid_preferred_affinity = base_k8s_install_args();
        invalid_preferred_affinity.agent_node_affinity_preferred =
            vec![KubernetesPreferredNodeAffinityArg {
                weight: 101,
                expression: KubernetesNodeAffinityExpressionArg {
                    key: "node.kubernetes.io/instance-type".to_string(),
                    operator: "Exists".to_string(),
                    values: Vec::new(),
                },
            }];
        let error = match k8s_install_plan(invalid_preferred_affinity) {
            Ok(_) => panic!("preferred node affinity weight over 100 should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("preferred node affinity weight"));

        let mut invalid_pod_affinity = base_k8s_install_args();
        invalid_pod_affinity.agent_pod_affinity_required = vec![KubernetesPodAffinityTermArg {
            topology_key: "kubernetes.io/hostname".to_string(),
            match_expressions: vec![KubernetesLabelSelectorExpressionArg {
                key: "app.kubernetes.io/name".to_string(),
                operator: "Gt".to_string(),
                values: vec!["1".to_string()],
            }],
            namespaces: Vec::new(),
        }];
        let error = match k8s_install_plan(invalid_pod_affinity) {
            Ok(_) => panic!("pod affinity Gt operator should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("pod affinity label selector operator"));

        let mut invalid_pod_anti_affinity = base_k8s_install_args();
        invalid_pod_anti_affinity.agent_pod_anti_affinity_preferred =
            vec![KubernetesPreferredPodAffinityArg {
                weight: 0,
                term: KubernetesPodAffinityTermArg {
                    topology_key: "kubernetes.io/hostname".to_string(),
                    match_expressions: vec![KubernetesLabelSelectorExpressionArg {
                        key: "app.kubernetes.io/name".to_string(),
                        operator: "Exists".to_string(),
                        values: Vec::new(),
                    }],
                    namespaces: Vec::new(),
                },
            }];
        let error = match k8s_install_plan(invalid_pod_anti_affinity) {
            Ok(_) => panic!("preferred pod anti-affinity zero weight should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("preferred pod affinity weight"));

        let mut invalid_priority = base_k8s_install_args();
        invalid_priority.agent_priority_class = Some("system/node-critical".to_string());
        let error = match k8s_install_plan(invalid_priority) {
            Ok(_) => panic!("invalid priority class should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("agent priority class"));

        let mut invalid_scheduler = base_k8s_install_args();
        invalid_scheduler.agent_scheduler_name = Some("system/scheduler".to_string());
        let error = match k8s_install_plan(invalid_scheduler) {
            Ok(_) => panic!("invalid scheduler name should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("agent scheduler name"));

        let mut invalid_runtime_class = base_k8s_install_args();
        invalid_runtime_class.agent_runtime_class = Some("Runtime_Class".to_string());
        let error = match k8s_install_plan(invalid_runtime_class) {
            Ok(_) => panic!("invalid runtime class should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("agent runtime class"));

        let mut invalid_toleration = base_k8s_install_args();
        invalid_toleration.agent_tolerations = vec![KubernetesTolerationArg {
            key: None,
            operator: None,
            value: None,
            effect: Some("NoSchedule".to_string()),
            toleration_seconds: None,
        }];
        let error = match k8s_install_plan(invalid_toleration) {
            Ok(_) => panic!("keyless toleration without Exists should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("no key requires operator Exists"));

        let mut invalid_topology_spread = base_k8s_install_args();
        invalid_topology_spread.agent_topology_spreads = vec![KubernetesTopologySpreadArg {
            topology_key: "Topology.kubernetes.io/zone".to_string(),
            max_skew: 1,
            when_unsatisfiable: "ScheduleAnyway".to_string(),
            min_domains: None,
            node_affinity_policy: None,
            node_taints_policy: None,
        }];
        let error = match k8s_install_plan(invalid_topology_spread) {
            Ok(_) => panic!("invalid topology spread should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("label prefix"));

        let mut invalid_min_domains = base_k8s_install_args();
        invalid_min_domains.agent_topology_spreads = vec![KubernetesTopologySpreadArg {
            topology_key: "topology.kubernetes.io/zone".to_string(),
            max_skew: 1,
            when_unsatisfiable: "ScheduleAnyway".to_string(),
            min_domains: Some(2),
            node_affinity_policy: None,
            node_taints_policy: None,
        }];
        let error = match k8s_install_plan(invalid_min_domains) {
            Ok(_) => panic!("invalid minDomains topology spread should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("minDomains requires"));

        let mut invalid_grace = base_k8s_install_args();
        invalid_grace.agent_termination_grace_period_seconds = Some(u64::MAX);
        let error = match k8s_install_plan(invalid_grace) {
            Ok(_) => panic!("termination grace period over int64 should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("termination-grace-period"));

        let mut invalid_pre_stop = base_k8s_install_args();
        invalid_pre_stop.agent_pre_stop_sleep_seconds = Some(0);
        let error = match k8s_install_plan(invalid_pre_stop) {
            Ok(_) => panic!("zero preStop sleep should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("agent-pre-stop-sleep-seconds"));

        let mut invalid_token_automount = base_k8s_install_args();
        invalid_token_automount.disable_agent_service_account_token = true;
        invalid_token_automount.kubernetes_discover_services = true;
        let error = match k8s_install_plan(invalid_token_automount) {
            Ok(_) => panic!("service discovery without service account token should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("disable-agent-service-account-token"));

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--disable-agent-host-network",
            "--disable-agent-service-account-token",
        ])?;
        if let Command::K8s {
            command: K8sCommand::Install(args),
        } = parsed.command
        {
            assert!(args.disable_agent_host_network);
            assert!(args.disable_agent_service_account_token);
        } else {
            anyhow::bail!("expected k8s install command");
        }

        Ok(())
    }

    #[test]
    fn k8s_install_plan_wires_and_validates_agent_rollout_options() -> anyhow::Result<()> {
        let mut args = base_k8s_install_args();
        args.agent_update_strategy = Some("RollingUpdate".to_string());
        args.agent_rollout_max_unavailable = Some("10%".to_string());
        args.agent_rollout_max_surge = Some("1".to_string());
        args.agent_min_ready_seconds = Some(15);
        args.agent_revision_history_limit = Some(5);

        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];

        assert!(helm.contains("--set agent.rollout.updateStrategy=RollingUpdate"));
        assert!(helm.contains("--set-string agent.rollout.maxUnavailable=10%"));
        assert!(helm.contains("--set-string agent.rollout.maxSurge=1"));
        assert!(helm.contains("--set agent.rollout.minReadySeconds=15"));
        assert!(helm.contains("--set agent.rollout.revisionHistoryLimit=5"));

        let mut inferred_strategy = base_k8s_install_args();
        inferred_strategy.agent_rollout_max_unavailable = Some("25%".to_string());
        let plan = k8s_install_plan(inferred_strategy)?;
        assert!(plan.commands[2].contains("--set agent.rollout.updateStrategy=RollingUpdate"));
        assert!(plan.commands[2].contains("--set-string agent.rollout.maxUnavailable=25%"));

        let invalid_strategy = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--agent-update-strategy",
            "Recreate",
        ]);
        assert!(invalid_strategy.is_err());
        let invalid_percent = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--agent-rollout-max-unavailable",
            "101%",
        ]);
        assert!(invalid_percent.is_err());
        let invalid_i32 = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--agent-min-ready-seconds",
            "2147483648",
        ]);
        assert!(invalid_i32.is_err());

        let mut on_delete_with_rolling_update = base_k8s_install_args();
        on_delete_with_rolling_update.agent_update_strategy = Some("OnDelete".to_string());
        on_delete_with_rolling_update.agent_rollout_max_surge = Some("1".to_string());
        let error = match k8s_install_plan(on_delete_with_rolling_update) {
            Ok(_) => panic!("OnDelete with rollingUpdate fields should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("require --agent-update-strategy RollingUpdate"));

        let mut zero_without_surge = base_k8s_install_args();
        zero_without_surge.agent_rollout_max_unavailable = Some("0".to_string());
        let error = match k8s_install_plan(zero_without_surge) {
            Ok(_) => panic!("zero maxUnavailable without maxSurge should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("cannot be zero"));

        let mut zero_with_surge = base_k8s_install_args();
        zero_with_surge.agent_rollout_max_unavailable = Some("0".to_string());
        zero_with_surge.agent_rollout_max_surge = Some("1".to_string());
        k8s_install_plan(zero_with_surge)?;

        Ok(())
    }

    #[test]
    fn k8s_install_plan_wires_and_validates_agent_pdb_options() -> anyhow::Result<()> {
        let mut args = base_k8s_install_args();
        args.agent_pdb_min_available = Some("80%".to_string());

        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];

        assert!(helm.contains("--set agent.podDisruptionBudget.enabled=true"));
        assert!(helm.contains("--set-string agent.podDisruptionBudget.minAvailable=80%"));

        let mut max_unavailable = base_k8s_install_args();
        max_unavailable.agent_pdb_max_unavailable = Some("1".to_string());
        let plan = k8s_install_plan(max_unavailable)?;
        assert!(
            plan.commands[2].contains("--set-string agent.podDisruptionBudget.maxUnavailable=1")
        );

        let both = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--agent-pdb-min-available",
            "1",
            "--agent-pdb-max-unavailable",
            "1",
        ])?;
        if let Command::K8s {
            command: K8sCommand::Install(args),
        } = both.command
        {
            let error = match k8s_install_plan(*args) {
                Ok(_) => panic!("PDB minAvailable and maxUnavailable should be exclusive"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("mutually exclusive"));
        } else {
            anyhow::bail!("expected k8s install command");
        }

        let invalid_percent = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--agent-pdb-min-available",
            "101%",
        ]);
        assert!(invalid_percent.is_err());
        Ok(())
    }

    #[test]
    fn k8s_install_plan_rejects_invalid_install_metadata() {
        let mut invalid_release = base_k8s_install_args();
        invalid_release.release = "Edge".to_string();
        let error = match k8s_install_plan(invalid_release) {
            Ok(_) => panic!("invalid Helm release should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("Helm release name"));

        let mut invalid_namespace = base_k8s_install_args();
        invalid_namespace.namespace = "edge_system".to_string();
        let error = match k8s_install_plan(invalid_namespace) {
            Ok(_) => panic!("invalid install namespace should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("Kubernetes namespace"));

        let mut invalid_name_override = base_k8s_install_args();
        invalid_name_override.chart_name_override = Some("Edge".to_string());
        let error = match k8s_install_plan(invalid_name_override) {
            Ok(_) => panic!("invalid chart name override should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--chart-name-override"));

        let mut invalid_fullname_override = base_k8s_install_args();
        invalid_fullname_override.chart_fullname_override = Some("-edge-ipars".to_string());
        let error = match k8s_install_plan(invalid_fullname_override) {
            Ok(_) => panic!("invalid chart fullname override should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--chart-fullname-override"));

        let mut invalid_secret = base_k8s_install_args();
        invalid_secret.join_token_secret = "bad secret".to_string();
        let error = match k8s_install_plan(invalid_secret) {
            Ok(_) => panic!("invalid join token Secret name should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("join token Secret name"));

        let mut invalid_key = base_k8s_install_args();
        invalid_key.join_token_key = "../token".to_string();
        let error = match k8s_install_plan(invalid_key) {
            Ok(_) => panic!("invalid join token Secret key should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("join token Secret key"));

        let mut reused_agent_api_key = base_k8s_install_args();
        reused_agent_api_key.join_token_key = DEFAULT_AGENT_API_BEARER_TOKEN_SECRET_KEY.to_string();
        let error = match k8s_install_plan(reused_agent_api_key) {
            Ok(_) => panic!("agent API token key reused for join token should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("must differ from agent API Bearer token Secret key"));

        let mut missing_bearer_key = base_k8s_install_args();
        missing_bearer_key.relay_admission_bearer_token_secret =
            Some("relay-admission-token".to_string());
        let error = match k8s_install_plan(missing_bearer_key) {
            Ok(_) => panic!("relay admission bearer token Secret key should be required"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-admission-bearer-token-secret"));

        let mut invalid_bearer_secret = base_k8s_install_args();
        invalid_bearer_secret.relay_admission_bearer_token_secret = Some("bad secret".to_string());
        invalid_bearer_secret.relay_admission_bearer_token_key = Some("token".to_string());
        let error = match k8s_install_plan(invalid_bearer_secret) {
            Ok(_) => panic!("invalid relay admission bearer token Secret name should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("relay admission bearer token Secret name"));

        let mut invalid_bearer_key = base_k8s_install_args();
        invalid_bearer_key.relay_admission_bearer_token_secret =
            Some("relay-admission-token".to_string());
        invalid_bearer_key.relay_admission_bearer_token_key = Some("../token".to_string());
        let error = match k8s_install_plan(invalid_bearer_key) {
            Ok(_) => panic!("invalid relay admission bearer token Secret key should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("relay admission bearer token Secret key"));
    }

    #[test]
    fn k8s_install_plan_rejects_invalid_route_discovery_settings() -> anyhow::Result<()> {
        let mut namespace_without_discovery = base_k8s_install_args();
        namespace_without_discovery.kubernetes_namespaces = vec!["default".to_string()];
        let error = match k8s_install_plan(namespace_without_discovery) {
            Ok(_) => panic!("namespace without discovery should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--kubernetes-namespace requires --kubernetes-discover-services"));

        let mut selector_without_discovery = base_k8s_install_args();
        selector_without_discovery.kubernetes_service_label_selector =
            Some("ipars.io/expose=true".to_string());
        let error = match k8s_install_plan(selector_without_discovery) {
            Ok(_) => panic!("selector without discovery should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(
            "--kubernetes-service-label-selector requires --kubernetes-discover-services"
        ));

        let mut invalid_namespace = base_k8s_install_args();
        invalid_namespace.kubernetes_discover_services = true;
        invalid_namespace.kubernetes_namespaces = vec!["Platform".to_string()];
        let error = match k8s_install_plan(invalid_namespace) {
            Ok(_) => panic!("invalid namespace should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("must be a DNS label using lowercase ASCII letters"));

        let mut duplicate_namespace = base_k8s_install_args();
        duplicate_namespace.kubernetes_discover_services = true;
        duplicate_namespace.kubernetes_namespaces =
            vec!["platform".to_string(), "platform".to_string()];
        let error = match k8s_install_plan(duplicate_namespace) {
            Ok(_) => panic!("duplicate namespace should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("must not be repeated"));

        let mut invalid_selector = base_k8s_install_args();
        invalid_selector.kubernetes_discover_services = true;
        invalid_selector.kubernetes_service_label_selector =
            Some("ipars.io/expose=true\n".to_string());
        let error = match k8s_install_plan(invalid_selector) {
            Ok(_) => panic!("invalid selector should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("cannot contain control characters"));

        let mut invalid_interval = base_k8s_install_args();
        invalid_interval.kubernetes_route_interval_seconds = 0;
        let error = match k8s_install_plan(invalid_interval) {
            Ok(_) => panic!("zero route interval should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--kubernetes-route-interval-seconds must be greater than zero"));

        let mut unrestricted_api_cidr = base_k8s_install_args();
        unrestricted_api_cidr.kubernetes_api_server_cidrs = vec!["0.0.0.0/0".parse()?];
        let error = match k8s_install_plan(unrestricted_api_cidr) {
            Ok(_) => panic!("unrestricted API server CIDR should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(
            "--kubernetes-api-server-cidr must not include unrestricted Kubernetes API server CIDR 0.0.0.0/0"
        ));

        let mut loopback_service_cidr = base_k8s_install_args();
        loopback_service_cidr.kubernetes_service_cidrs = vec!["127.0.0.0/8".parse()?];
        let error = match k8s_install_plan(loopback_service_cidr) {
            Ok(_) => panic!("loopback Service CIDR should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(
            "--kubernetes-service-cidr must not include loopback Kubernetes Service CIDR 127.0.0.0/8"
        ));

        let mut non_canonical_service_cidr = base_k8s_install_args();
        non_canonical_service_cidr.kubernetes_service_cidrs = vec!["10.96.0.1/12".parse()?];
        let error = match k8s_install_plan(non_canonical_service_cidr) {
            Ok(_) => panic!("non-canonical Service CIDR should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(
            "--kubernetes-service-cidr must use canonical Kubernetes Service CIDR route 10.96.0.0/12, not 10.96.0.1/12"
        ));

        let mut duplicate_route_cidr = base_k8s_install_args();
        duplicate_route_cidr.kubernetes_api_server_cidrs = vec!["10.96.0.1/32".parse()?];
        duplicate_route_cidr.kubernetes_service_cidrs = vec!["10.96.0.1/32".parse()?];
        let error = match k8s_install_plan(duplicate_route_cidr) {
            Ok(_) => panic!("duplicate Kubernetes route CIDR should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(
            "--kubernetes-service-cidr must not repeat Kubernetes underlay route CIDR 10.96.0.1/32"
        ));

        Ok(())
    }

    #[test]
    fn install_commands_accept_plan_options() -> anyhow::Result<()> {
        let docker = Cli::try_parse_from([
            "ipars",
            "docker",
            "install",
            "--compose-file",
            "ops/compose.yaml",
            "--project-name",
            "edge",
            "--rootless",
            "--docker-discover-networks",
            "--docker-network",
            "edge_default",
            "--docker-network",
            "edge_apps",
            "--docker-api-socket",
            "/run/user/1000/docker.sock",
            "--docker-container-namespace",
            "compose-edge",
            "--docker-host-interface",
            "br-edge",
            "--disable-docker-expose-host-routes",
            "--docker-route-interval-seconds",
            "15",
            "--agent-http-connect-timeout-seconds",
            "7",
            "--agent-http-request-timeout-seconds",
            "45",
            "--agent-direct-path-probe-timeout-seconds",
            "90",
            "--agent-direct-handshake-max-age-seconds",
            "240",
            "--route-backend",
            "kernel-netlink",
            "--userspace-wireguard-command",
            "wireguard-go",
            "--userspace-wireguard-arg",
            "ipars0",
            "--userspace-wireguard-ready-timeout-seconds",
            "30",
            "--userspace-wireguard-shutdown-timeout-seconds",
            "20",
        ])?;
        if let Command::Docker {
            command: DockerCommand::Install(args),
        } = docker.command
        {
            assert_eq!(args.compose_file, PathBuf::from("ops/compose.yaml"));
            assert_eq!(args.project_name, "edge");
            assert!(args.rootless);
            assert!(args.docker_discover_networks);
            assert_eq!(args.docker_networks, vec!["edge_default", "edge_apps"]);
            assert_eq!(
                args.docker_api_socket,
                Some(PathBuf::from("/run/user/1000/docker.sock"))
            );
            assert_eq!(
                args.docker_container_namespace.as_deref(),
                Some("compose-edge")
            );
            assert_eq!(args.docker_host_interface, "br-edge");
            assert!(args.docker_container_cidrs.is_empty());
            assert!(args.disable_docker_expose_host_routes);
            assert_eq!(args.docker_route_interval_seconds, 15);
            assert_eq!(args.agent_http_connect_timeout_seconds, 7);
            assert_eq!(args.agent_http_request_timeout_seconds, 45);
            assert_eq!(args.agent_direct_path_probe_timeout_seconds, 90);
            assert_eq!(args.agent_direct_handshake_max_age_seconds, 240);
            assert_eq!(args.route_backend, "kernel-netlink");
            assert_eq!(
                args.userspace_wireguard_command.as_deref(),
                Some("wireguard-go")
            );
            assert_eq!(args.userspace_wireguard_args, vec!["ipars0".to_string()]);
            assert_eq!(args.userspace_wireguard_ready_timeout_seconds, 30);
            assert_eq!(args.userspace_wireguard_shutdown_timeout_seconds, 20);
        } else {
            anyhow::bail!("expected docker install command");
        }

        let k8s = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--release",
            "edge",
            "--namespace",
            "edge-system",
            "--chart-name-override",
            "edge-agent",
            "--chart-fullname-override",
            "edge-ipars-agent",
            "--join-token-secret",
            "edge-token",
            "--join-token-key",
            "signed-token",
            "--cluster-control-plane-url",
            "https://control.example.com:8443/",
            "--cluster-signal-url",
            "https://signal.example.com:9443",
            "--cluster-stun-endpoint",
            "203.0.113.53:3478",
            "--image-repository",
            "registry.example.com/platform/ipars",
            "--image-tag",
            "2026.07.05",
            "--image-pull-policy",
            "Always",
            "--image-pull-secret",
            "registry-cred",
            "--agent-privileged",
            "--agent-add-capability",
            "NET_ADMIN",
            "--agent-add-capability",
            "NET_RAW",
            "--agent-add-capability",
            "SYS_TIME",
            "--agent-drop-capability",
            "MKNOD",
            "--agent-read-only-root-filesystem",
            "--agent-seccomp-profile",
            "RuntimeDefault",
            "--agent-run-as-user",
            "1000",
            "--agent-run-as-group",
            "1000",
            "--agent-run-as-non-root",
            "--agent-fs-group",
            "2000",
            "--agent-fs-group-change-policy",
            "OnRootMismatch",
            "--agent-supplemental-group",
            "2001",
            "--agent-supplemental-group",
            "2002",
            "--kubernetes-discover-services",
            "--kubernetes-discover-api-server",
            "false",
            "--kubernetes-api-server-cidr",
            "10.0.0.1/32",
            "--kubernetes-service-cidr",
            "10.96.0.0/12",
            "--kubernetes-namespace",
            "default",
            "--kubernetes-service-label-selector",
            "ipars.io/expose=true",
            "--kubernetes-route-provider",
            "route-provider-a",
            "--kubernetes-route-interval-seconds",
            "15",
            "--agent-runtime-backend",
            "dry-run",
            "--route-backend",
            "kernel-netlink",
            "--disable-agent-peer-map",
            "--agent-peer-map-poll-interval-seconds",
            "45",
            "--agent-http-connect-timeout-seconds",
            "7",
            "--agent-http-request-timeout-seconds",
            "45",
            "--agent-direct-path-probe-timeout-seconds",
            "90",
            "--agent-direct-handshake-max-age-seconds",
            "240",
            "--allow-public-service-exposure",
            "--allow-unrestricted-load-balancer",
            "--allow-cluster-external-traffic-policy",
            "--enable-network-policy",
            "--network-policy-acknowledge-host-network",
            "--disable-rbac",
            "--service-account-name",
            "edge-agent",
            "--service-account-annotation",
            "eks.amazonaws.com/role-arn=arn:aws:iam::123456789012:role/ipars-agent",
            "--agent-pod-label",
            "ipars.io/role=agent",
            "--agent-pod-annotation",
            "prometheus.io/scrape=true",
            "--agent-priority-class",
            "ipars-agent-critical",
            "--agent-scheduler-name",
            "ipars-scheduler",
            "--agent-runtime-class",
            "ipars-runtime",
            "--agent-node-selector",
            "kubernetes.io/os=linux",
            "--agent-node-affinity-required",
            "key=node-role.kubernetes.io/worker,operator=Exists",
            "--agent-node-affinity-preferred",
            "weight=75,key=node.kubernetes.io/instance-type,operator=In,values=m7i.large|m7i.xlarge",
            "--agent-pod-affinity-required",
            "topologyKey=kubernetes.io/hostname,key=app.kubernetes.io/name,operator=In,values=ipars,namespaces=edge-system",
            "--agent-pod-affinity-preferred",
            "weight=60,topologyKey=topology.kubernetes.io/zone,key=ipars.io/role,operator=Exists",
            "--agent-pod-anti-affinity-required",
            "topologyKey=kubernetes.io/hostname,key=ipars.io/role,operator=In,values=relay",
            "--agent-pod-anti-affinity-preferred",
            "weight=90,topologyKey=topology.kubernetes.io/zone,key=app.kubernetes.io/name,operator=NotIn,values=legacy",
            "--agent-toleration",
            "key=node-role.kubernetes.io/control-plane,operator=Exists,effect=NoSchedule",
            "--agent-topology-spread",
            "topologyKey=topology.kubernetes.io/zone,maxSkew=1,whenUnsatisfiable=DoNotSchedule,minDomains=2,nodeAffinityPolicy=Honor,nodeTaintsPolicy=Honor",
            "--agent-dns-policy",
            "ClusterFirstWithHostNet",
            "--agent-state-host-path",
            "/opt/ipars/state",
            "--agent-state-mount-path",
            "/run/ipars/state",
            "--agent-state-host-path-type",
            "Directory",
            "--disable-agent-liveness-probe",
            "--disable-agent-readiness-probe",
            "--disable-agent-startup-probe",
            "--agent-termination-grace-period-seconds",
            "45",
            "--agent-pre-stop-sleep-seconds",
            "20",
            "--agent-resource-request-cpu",
            "100m",
            "--agent-resource-request-memory",
            "128Mi",
            "--agent-resource-limit-cpu",
            "500m",
            "--agent-resource-limit-memory",
            "512Mi",
            "--agent-update-strategy",
            "RollingUpdate",
            "--agent-rollout-max-unavailable",
            "10%",
            "--agent-rollout-max-surge",
            "1",
            "--agent-min-ready-seconds",
            "15",
            "--agent-revision-history-limit",
            "5",
            "--agent-pdb-min-available",
            "80%",
            "--expose-agent-api",
            "--agent-api-service-type",
            "LoadBalancer",
            "--agent-api-port",
            "9781",
            "--agent-api-target-port",
            "9790",
            "--agent-api-node-port",
            "31080",
            "--agent-api-load-balancer-class",
            "example.com/internal-api",
            "--agent-api-health-check-node-port",
            "31081",
            "--agent-api-ip-family-policy",
            "RequireDualStack",
            "--agent-api-ip-family",
            "IPv4",
            "--agent-api-ip-family",
            "IPv6",
            "--agent-api-allow-source-cidr",
            "198.51.100.0/24",
            "--agent-api-network-policy-cidr",
            "10.0.0.0/8",
            "--agent-api-internal-traffic-policy",
            "Local",
            "--agent-api-traffic-distribution",
            "PreferSameZone",
            "--agent-api-session-affinity",
            "ClientIP",
            "--agent-api-session-affinity-timeout-seconds",
            "600",
            "--agent-api-external-traffic-policy",
            "Cluster",
            "--agent-api-service-annotation",
            "example.com/lb-profile=public",
            "--expose-relay",
            "--relay-service-type",
            "LoadBalancer",
            "--relay-udp-port",
            "51821",
            "--relay-udp-target-port",
            "51820",
            "--relay-http-port",
            "9581",
            "--relay-http-target-port",
            "9580",
            "--relay-udp-node-port",
            "31820",
            "--relay-http-node-port",
            "31580",
            "--relay-load-balancer-class",
            "example.com/internal-relay",
            "--relay-health-check-node-port",
            "31821",
            "--relay-ip-family-policy",
            "PreferDualStack",
            "--relay-ip-family",
            "IPv6",
            "--relay-allow-source-cidr",
            "203.0.113.0/24",
            "--relay-network-policy-cidr",
            "203.0.113.0/24",
            "--relay-internal-traffic-policy",
            "Cluster",
            "--relay-traffic-distribution",
            "PreferClose",
            "--relay-session-affinity",
            "ClientIP",
            "--relay-session-affinity-timeout-seconds",
            "900",
            "--relay-external-traffic-policy",
            "Local",
            "--relay-service-annotation",
            "example.com/relay-profile=public",
            "--relay-admission-bearer-token-secret",
            "relay-admission-token",
            "--relay-admission-bearer-token-key",
            "token",
            "--relay-public-endpoint",
            "203.0.113.10:51820",
            "--relay-admission-url",
            "http://203.0.113.10:9580",
        ])?;
        if let Command::K8s {
            command: K8sCommand::Install(args),
        } = k8s.command
        {
            assert_eq!(args.release, "edge");
            assert_eq!(args.namespace, "edge-system");
            assert_eq!(args.chart_name_override.as_deref(), Some("edge-agent"));
            assert_eq!(
                args.chart_fullname_override.as_deref(),
                Some("edge-ipars-agent")
            );
            assert_eq!(args.join_token_secret, "edge-token");
            assert_eq!(args.join_token_key, "signed-token");
            assert_eq!(
                args.cluster_control_plane_url.as_deref(),
                Some("https://control.example.com:8443")
            );
            assert_eq!(
                args.cluster_signal_url.as_deref(),
                Some("https://signal.example.com:9443")
            );
            assert_eq!(
                args.cluster_stun_endpoint.as_deref(),
                Some("203.0.113.53:3478")
            );
            assert_eq!(
                args.image_repository.as_deref(),
                Some("registry.example.com/platform/ipars")
            );
            assert_eq!(args.image_tag.as_deref(), Some("2026.07.05"));
            assert_eq!(args.image_pull_policy.as_deref(), Some("Always"));
            assert_eq!(args.image_pull_secrets, vec!["registry-cred"]);
            assert!(args.agent_privileged);
            assert_eq!(
                args.agent_add_capabilities,
                vec!["NET_ADMIN", "NET_RAW", "SYS_TIME"]
            );
            assert_eq!(args.agent_drop_capabilities, vec!["MKNOD"]);
            assert!(!args.disable_agent_privilege_escalation);
            assert!(args.agent_read_only_root_filesystem);
            assert_eq!(
                args.agent_seccomp_profile.as_deref(),
                Some("RuntimeDefault")
            );
            assert_eq!(args.agent_seccomp_localhost_profile, None);
            assert_eq!(args.agent_run_as_user, Some(1000));
            assert_eq!(args.agent_run_as_group, Some(1000));
            assert!(args.agent_run_as_non_root);
            assert_eq!(args.agent_fs_group, Some(2000));
            assert_eq!(
                args.agent_fs_group_change_policy.as_deref(),
                Some("OnRootMismatch")
            );
            assert_eq!(args.agent_supplemental_groups, vec![2001, 2002]);
            assert!(args.kubernetes_discover_services);
            assert!(!args.kubernetes_discover_api_server);
            assert_eq!(
                args.kubernetes_api_server_cidrs,
                vec!["10.0.0.1/32".parse::<ipnet::IpNet>()?]
            );
            assert_eq!(
                args.kubernetes_service_cidrs,
                vec!["10.96.0.0/12".parse::<ipnet::IpNet>()?]
            );
            assert_eq!(args.kubernetes_namespaces, vec!["default"]);
            assert_eq!(
                args.kubernetes_service_label_selector.as_deref(),
                Some("ipars.io/expose=true")
            );
            assert_eq!(
                args.kubernetes_route_provider.as_deref(),
                Some("route-provider-a")
            );
            assert_eq!(args.kubernetes_route_interval_seconds, 15);
            assert_eq!(args.agent_runtime_backend, "dry-run");
            assert_eq!(args.route_backend, "kernel-netlink");
            assert!(args.disable_agent_peer_map);
            assert_eq!(args.agent_peer_map_poll_interval_seconds, 45);
            assert_eq!(args.agent_http_connect_timeout_seconds, 7);
            assert_eq!(args.agent_http_request_timeout_seconds, 45);
            assert_eq!(args.agent_direct_path_probe_timeout_seconds, 90);
            assert_eq!(args.agent_direct_handshake_max_age_seconds, 240);
            assert!(args.allow_public_service_exposure);
            assert!(args.allow_unrestricted_load_balancer);
            assert!(args.allow_cluster_external_traffic_policy);
            assert!(args.enable_network_policy);
            assert!(args.network_policy_acknowledge_host_network);
            assert!(args.disable_rbac);
            assert!(!args.disable_service_account_creation);
            assert_eq!(args.service_account_name.as_deref(), Some("edge-agent"));
            assert_eq!(
                args.service_account_annotations,
                vec![KeyValueArg {
                    key: "eks.amazonaws.com/role-arn".to_string(),
                    value: "arn:aws:iam::123456789012:role/ipars-agent".to_string(),
                }]
            );
            assert_eq!(
                args.agent_pod_labels,
                vec![KeyValueArg {
                    key: "ipars.io/role".to_string(),
                    value: "agent".to_string(),
                }]
            );
            assert_eq!(
                args.agent_pod_annotations,
                vec![KeyValueArg {
                    key: "prometheus.io/scrape".to_string(),
                    value: "true".to_string(),
                }]
            );
            assert_eq!(
                args.agent_priority_class.as_deref(),
                Some("ipars-agent-critical")
            );
            assert_eq!(
                args.agent_scheduler_name.as_deref(),
                Some("ipars-scheduler")
            );
            assert_eq!(args.agent_runtime_class.as_deref(), Some("ipars-runtime"));
            assert_eq!(
                args.agent_node_selectors,
                vec![KeyValueArg {
                    key: "kubernetes.io/os".to_string(),
                    value: "linux".to_string(),
                }]
            );
            assert_eq!(
                args.agent_node_affinity_required,
                vec![KubernetesNodeAffinityExpressionArg {
                    key: "node-role.kubernetes.io/worker".to_string(),
                    operator: "Exists".to_string(),
                    values: Vec::new(),
                }]
            );
            assert_eq!(
                args.agent_node_affinity_preferred,
                vec![KubernetesPreferredNodeAffinityArg {
                    weight: 75,
                    expression: KubernetesNodeAffinityExpressionArg {
                        key: "node.kubernetes.io/instance-type".to_string(),
                        operator: "In".to_string(),
                        values: vec!["m7i.large".to_string(), "m7i.xlarge".to_string()],
                    },
                }]
            );
            assert_eq!(
                args.agent_pod_affinity_required,
                vec![KubernetesPodAffinityTermArg {
                    topology_key: "kubernetes.io/hostname".to_string(),
                    match_expressions: vec![KubernetesLabelSelectorExpressionArg {
                        key: "app.kubernetes.io/name".to_string(),
                        operator: "In".to_string(),
                        values: vec!["ipars".to_string()],
                    }],
                    namespaces: vec!["edge-system".to_string()],
                }]
            );
            assert_eq!(
                args.agent_pod_affinity_preferred,
                vec![KubernetesPreferredPodAffinityArg {
                    weight: 60,
                    term: KubernetesPodAffinityTermArg {
                        topology_key: "topology.kubernetes.io/zone".to_string(),
                        match_expressions: vec![KubernetesLabelSelectorExpressionArg {
                            key: "ipars.io/role".to_string(),
                            operator: "Exists".to_string(),
                            values: Vec::new(),
                        }],
                        namespaces: Vec::new(),
                    },
                }]
            );
            assert_eq!(
                args.agent_pod_anti_affinity_required,
                vec![KubernetesPodAffinityTermArg {
                    topology_key: "kubernetes.io/hostname".to_string(),
                    match_expressions: vec![KubernetesLabelSelectorExpressionArg {
                        key: "ipars.io/role".to_string(),
                        operator: "In".to_string(),
                        values: vec!["relay".to_string()],
                    }],
                    namespaces: Vec::new(),
                }]
            );
            assert_eq!(
                args.agent_pod_anti_affinity_preferred,
                vec![KubernetesPreferredPodAffinityArg {
                    weight: 90,
                    term: KubernetesPodAffinityTermArg {
                        topology_key: "topology.kubernetes.io/zone".to_string(),
                        match_expressions: vec![KubernetesLabelSelectorExpressionArg {
                            key: "app.kubernetes.io/name".to_string(),
                            operator: "NotIn".to_string(),
                            values: vec!["legacy".to_string()],
                        }],
                        namespaces: Vec::new(),
                    },
                }]
            );
            assert_eq!(
                args.agent_tolerations,
                vec![KubernetesTolerationArg {
                    key: Some("node-role.kubernetes.io/control-plane".to_string()),
                    operator: Some("Exists".to_string()),
                    value: None,
                    effect: Some("NoSchedule".to_string()),
                    toleration_seconds: None,
                }]
            );
            assert_eq!(
                args.agent_topology_spreads,
                vec![KubernetesTopologySpreadArg {
                    topology_key: "topology.kubernetes.io/zone".to_string(),
                    max_skew: 1,
                    when_unsatisfiable: "DoNotSchedule".to_string(),
                    min_domains: Some(2),
                    node_affinity_policy: Some("Honor".to_string()),
                    node_taints_policy: Some("Honor".to_string()),
                }]
            );
            assert_eq!(
                args.agent_dns_policy.as_deref(),
                Some("ClusterFirstWithHostNet")
            );
            assert_eq!(
                args.agent_state_host_path.as_deref(),
                Some("/opt/ipars/state")
            );
            assert_eq!(
                args.agent_state_mount_path.as_deref(),
                Some("/run/ipars/state")
            );
            assert_eq!(
                args.agent_state_host_path_type.as_deref(),
                Some("Directory")
            );
            assert!(args.disable_agent_liveness_probe);
            assert!(args.disable_agent_readiness_probe);
            assert!(args.disable_agent_startup_probe);
            assert_eq!(args.agent_termination_grace_period_seconds, Some(45));
            assert_eq!(args.agent_pre_stop_sleep_seconds, Some(20));
            assert_eq!(args.agent_resource_request_cpu.as_deref(), Some("100m"));
            assert_eq!(args.agent_resource_request_memory.as_deref(), Some("128Mi"));
            assert_eq!(args.agent_resource_limit_cpu.as_deref(), Some("500m"));
            assert_eq!(args.agent_resource_limit_memory.as_deref(), Some("512Mi"));
            assert_eq!(args.agent_update_strategy.as_deref(), Some("RollingUpdate"));
            assert_eq!(args.agent_rollout_max_unavailable.as_deref(), Some("10%"));
            assert_eq!(args.agent_rollout_max_surge.as_deref(), Some("1"));
            assert_eq!(args.agent_min_ready_seconds, Some(15));
            assert_eq!(args.agent_revision_history_limit, Some(5));
            assert_eq!(args.agent_pdb_min_available.as_deref(), Some("80%"));
            assert_eq!(args.agent_pdb_max_unavailable, None);
            assert!(args.expose_agent_api);
            assert_eq!(args.agent_api_service_type, "LoadBalancer");
            assert_eq!(args.agent_api_port, Some(9781));
            assert_eq!(args.agent_api_target_port, Some(9790));
            assert_eq!(args.agent_api_node_port, Some(31080));
            assert_eq!(
                args.agent_api_load_balancer_class.as_deref(),
                Some("example.com/internal-api")
            );
            assert_eq!(args.agent_api_health_check_node_port, Some(31081));
            assert_eq!(
                args.agent_api_ip_family_policy.as_deref(),
                Some("RequireDualStack")
            );
            assert_eq!(args.agent_api_ip_families, vec!["IPv4", "IPv6"]);
            assert_eq!(
                args.agent_api_allow_source_cidrs,
                vec!["198.51.100.0/24".parse::<ipnet::IpNet>()?]
            );
            assert_eq!(
                args.agent_api_network_policy_cidrs,
                vec!["10.0.0.0/8".parse::<ipnet::IpNet>()?]
            );
            assert_eq!(
                args.agent_api_internal_traffic_policy.as_deref(),
                Some("Local")
            );
            assert_eq!(
                args.agent_api_traffic_distribution.as_deref(),
                Some("PreferSameZone")
            );
            assert_eq!(args.agent_api_session_affinity.as_deref(), Some("ClientIP"));
            assert_eq!(args.agent_api_session_affinity_timeout_seconds, Some(600));
            assert_eq!(args.agent_api_external_traffic_policy, "Cluster");
            assert_eq!(
                args.agent_api_service_annotations,
                vec![KeyValueArg {
                    key: "example.com/lb-profile".to_string(),
                    value: "public".to_string(),
                }]
            );
            assert!(args.expose_relay);
            assert_eq!(args.relay_service_type, "LoadBalancer");
            assert_eq!(args.relay_udp_port, Some(51821));
            assert_eq!(args.relay_udp_target_port, Some(51820));
            assert_eq!(args.relay_http_port, Some(9581));
            assert_eq!(args.relay_http_target_port, Some(9580));
            assert_eq!(args.relay_udp_node_port, Some(31820));
            assert_eq!(args.relay_http_node_port, Some(31580));
            assert_eq!(
                args.relay_load_balancer_class.as_deref(),
                Some("example.com/internal-relay")
            );
            assert_eq!(args.relay_health_check_node_port, Some(31821));
            assert_eq!(
                args.relay_ip_family_policy.as_deref(),
                Some("PreferDualStack")
            );
            assert_eq!(args.relay_ip_families, vec!["IPv6"]);
            assert_eq!(
                args.relay_allow_source_cidrs,
                vec!["203.0.113.0/24".parse::<ipnet::IpNet>()?]
            );
            assert_eq!(
                args.relay_network_policy_cidrs,
                vec!["203.0.113.0/24".parse::<ipnet::IpNet>()?]
            );
            assert_eq!(
                args.relay_internal_traffic_policy.as_deref(),
                Some("Cluster")
            );
            assert_eq!(
                args.relay_traffic_distribution.as_deref(),
                Some("PreferClose")
            );
            assert_eq!(args.relay_session_affinity.as_deref(), Some("ClientIP"));
            assert_eq!(args.relay_session_affinity_timeout_seconds, Some(900));
            assert_eq!(args.relay_external_traffic_policy, "Local");
            assert_eq!(
                args.relay_service_annotations,
                vec![KeyValueArg {
                    key: "example.com/relay-profile".to_string(),
                    value: "public".to_string(),
                }]
            );
            assert_eq!(
                args.relay_admission_bearer_token_secret.as_deref(),
                Some("relay-admission-token")
            );
            assert_eq!(
                args.relay_admission_bearer_token_key.as_deref(),
                Some("token")
            );
            assert_eq!(
                args.relay_public_endpoint.as_deref(),
                Some("203.0.113.10:51820")
            );
            assert_eq!(
                args.relay_admission_url.as_deref(),
                Some("http://203.0.113.10:9580")
            );
            return Ok(());
        }

        anyhow::bail!("expected k8s install command")
    }

    #[test]
    fn k8s_install_rejects_relay_exposure_without_endpoints() {
        let parsed = Cli::try_parse_from(["ipars", "k8s", "install", "--expose-relay"]);
        assert!(parsed.is_err());

        let plan = k8s_install_plan(K8sInstallArgs {
            release: "edge".to_string(),
            namespace: "edge-system".to_string(),
            chart: PathBuf::from("charts/ipars"),
            chart_name_override: None,
            chart_fullname_override: None,
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            cluster_control_plane_url: None,
            cluster_signal_url: None,
            cluster_stun_endpoint: None,
            image_repository: None,
            image_tag: None,
            image_pull_policy: None,
            image_pull_secrets: Vec::new(),
            agent_privileged: false,
            agent_add_capabilities: Vec::new(),
            agent_drop_capabilities: Vec::new(),
            disable_agent_privilege_escalation: false,
            agent_read_only_root_filesystem: false,
            agent_seccomp_profile: None,
            agent_seccomp_localhost_profile: None,
            agent_run_as_user: None,
            agent_run_as_group: None,
            agent_run_as_non_root: false,
            agent_fs_group: None,
            agent_fs_group_change_policy: None,
            agent_supplemental_groups: Vec::new(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            agent_runtime_backend: "linux-command".to_string(),
            agent_wireguard_listen_port: None,
            agent_stun_bind: None,
            route_backend: "command".to_string(),
            disable_agent_peer_map: false,
            agent_peer_map_poll_interval_seconds: 30,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            expose_agent_api: false,
            allow_public_service_exposure: true,
            allow_unrestricted_load_balancer: true,
            allow_cluster_external_traffic_policy: false,
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            disable_rbac: false,
            disable_service_account_creation: false,
            service_account_name: None,
            service_account_annotations: Vec::new(),
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_scheduler_name: None,
            agent_runtime_class: None,
            agent_node_selectors: Vec::new(),
            agent_node_affinity_required: Vec::new(),
            agent_node_affinity_preferred: Vec::new(),
            agent_pod_affinity_required: Vec::new(),
            agent_pod_affinity_preferred: Vec::new(),
            agent_pod_anti_affinity_required: Vec::new(),
            agent_pod_anti_affinity_preferred: Vec::new(),
            agent_tolerations: Vec::new(),
            agent_topology_spreads: Vec::new(),
            disable_agent_host_network: false,
            disable_agent_service_account_token: false,
            agent_dns_policy: None,
            agent_state_host_path: None,
            agent_state_mount_path: None,
            agent_state_host_path_type: None,
            disable_agent_liveness_probe: false,
            disable_agent_readiness_probe: false,
            disable_agent_startup_probe: false,
            agent_probes: K8sProbeArgs::default(),
            agent_pre_stop_sleep_seconds: None,
            agent_termination_grace_period_seconds: None,
            agent_resource_request_cpu: None,
            agent_resource_request_memory: None,
            agent_resource_limit_cpu: None,
            agent_resource_limit_memory: None,
            agent_update_strategy: None,
            agent_rollout_max_unavailable: None,
            agent_rollout_max_surge: None,
            agent_min_ready_seconds: None,
            agent_revision_history_limit: None,
            agent_pdb_min_available: None,
            agent_pdb_max_unavailable: None,
            agent_api_service_type: "ClusterIP".to_string(),
            agent_api_cluster_ip: None,
            agent_api_secondary_cluster_ip: None,
            agent_api_port: None,
            agent_api_target_port: None,
            agent_api_node_port: None,
            agent_api_app_protocol: None,
            agent_api_publish_not_ready_addresses: false,
            agent_api_load_balancer_class: None,
            agent_api_load_balancer_ip: None,
            agent_api_external_ips: Vec::new(),
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_traffic_distribution: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_cluster_ip: None,
            relay_secondary_cluster_ip: None,
            relay_udp_port: None,
            relay_udp_target_port: None,
            relay_http_port: None,
            relay_http_target_port: None,
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_udp_app_protocol: None,
            relay_http_app_protocol: None,
            relay_publish_not_ready_addresses: false,
            relay_load_balancer_class: None,
            relay_load_balancer_ip: None,
            relay_external_ips: Vec::new(),
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: Vec::new(),
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_traffic_distribution: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: Vec::new(),
            relay_admission_bearer_token_secret: None,
            relay_admission_bearer_token_key: None,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        });
        assert!(plan.is_err());
    }

    #[test]
    fn k8s_install_requires_acknowledgement_for_public_service_exposure() {
        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--expose-agent-api",
            "--agent-api-service-type",
            "LoadBalancer",
        ]);
        assert!(parsed.is_ok());

        let plan = k8s_install_plan(K8sInstallArgs {
            release: "edge".to_string(),
            namespace: "edge-system".to_string(),
            chart: PathBuf::from("charts/ipars"),
            chart_name_override: None,
            chart_fullname_override: None,
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            cluster_control_plane_url: None,
            cluster_signal_url: None,
            cluster_stun_endpoint: None,
            image_repository: None,
            image_tag: None,
            image_pull_policy: None,
            image_pull_secrets: Vec::new(),
            agent_privileged: false,
            agent_add_capabilities: Vec::new(),
            agent_drop_capabilities: Vec::new(),
            disable_agent_privilege_escalation: false,
            agent_read_only_root_filesystem: false,
            agent_seccomp_profile: None,
            agent_seccomp_localhost_profile: None,
            agent_run_as_user: None,
            agent_run_as_group: None,
            agent_run_as_non_root: false,
            agent_fs_group: None,
            agent_fs_group_change_policy: None,
            agent_supplemental_groups: Vec::new(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            agent_runtime_backend: "linux-command".to_string(),
            agent_wireguard_listen_port: None,
            agent_stun_bind: None,
            route_backend: "command".to_string(),
            disable_agent_peer_map: false,
            agent_peer_map_poll_interval_seconds: 30,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            expose_agent_api: true,
            allow_public_service_exposure: false,
            allow_unrestricted_load_balancer: false,
            allow_cluster_external_traffic_policy: false,
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            disable_rbac: false,
            disable_service_account_creation: false,
            service_account_name: None,
            service_account_annotations: Vec::new(),
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_scheduler_name: None,
            agent_runtime_class: None,
            agent_node_selectors: Vec::new(),
            agent_node_affinity_required: Vec::new(),
            agent_node_affinity_preferred: Vec::new(),
            agent_pod_affinity_required: Vec::new(),
            agent_pod_affinity_preferred: Vec::new(),
            agent_pod_anti_affinity_required: Vec::new(),
            agent_pod_anti_affinity_preferred: Vec::new(),
            agent_tolerations: Vec::new(),
            agent_topology_spreads: Vec::new(),
            disable_agent_host_network: false,
            disable_agent_service_account_token: false,
            agent_dns_policy: None,
            agent_state_host_path: None,
            agent_state_mount_path: None,
            agent_state_host_path_type: None,
            disable_agent_liveness_probe: false,
            disable_agent_readiness_probe: false,
            disable_agent_startup_probe: false,
            agent_probes: K8sProbeArgs::default(),
            agent_pre_stop_sleep_seconds: None,
            agent_termination_grace_period_seconds: None,
            agent_resource_request_cpu: None,
            agent_resource_request_memory: None,
            agent_resource_limit_cpu: None,
            agent_resource_limit_memory: None,
            agent_update_strategy: None,
            agent_rollout_max_unavailable: None,
            agent_rollout_max_surge: None,
            agent_min_ready_seconds: None,
            agent_revision_history_limit: None,
            agent_pdb_min_available: None,
            agent_pdb_max_unavailable: None,
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_cluster_ip: None,
            agent_api_secondary_cluster_ip: None,
            agent_api_port: None,
            agent_api_target_port: None,
            agent_api_node_port: None,
            agent_api_app_protocol: None,
            agent_api_publish_not_ready_addresses: false,
            agent_api_load_balancer_class: None,
            agent_api_load_balancer_ip: None,
            agent_api_external_ips: Vec::new(),
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_traffic_distribution: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: false,
            relay_service_type: "LoadBalancer".to_string(),
            relay_cluster_ip: None,
            relay_secondary_cluster_ip: None,
            relay_udp_port: None,
            relay_udp_target_port: None,
            relay_http_port: None,
            relay_http_target_port: None,
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_udp_app_protocol: None,
            relay_http_app_protocol: None,
            relay_publish_not_ready_addresses: false,
            relay_load_balancer_class: None,
            relay_load_balancer_ip: None,
            relay_external_ips: Vec::new(),
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: Vec::new(),
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_traffic_distribution: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: Vec::new(),
            relay_admission_bearer_token_secret: None,
            relay_admission_bearer_token_key: None,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        });
        assert!(plan.is_err());
    }

    #[test]
    fn k8s_install_wires_and_validates_node_ports() -> anyhow::Result<()> {
        let mut valid = base_k8s_install_args();
        valid.expose_agent_api = true;
        valid.allow_public_service_exposure = true;
        valid.agent_api_service_type = "NodePort".to_string();
        valid.agent_api_node_port = Some(31080);
        valid.expose_relay = true;
        valid.relay_service_type = "NodePort".to_string();
        valid.relay_udp_node_port = Some(31820);
        valid.relay_http_node_port = Some(31580);
        valid.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        valid.relay_admission_url = Some("http://203.0.113.10:9580".to_string());

        let plan = k8s_install_plan(valid)?;
        assert!(plan.commands[2].contains("--set agent.apiService.nodePort=31080"));
        assert!(plan.commands[2].contains("--set agent.relayService.udpNodePort=31820"));
        assert!(plan.commands[2].contains("--set agent.relayService.httpNodePort=31580"));

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--expose-agent-api",
            "--agent-api-node-port",
            "29999",
        ]);
        assert!(parsed.is_err());

        let mut cluster_ip_agent = base_k8s_install_args();
        cluster_ip_agent.expose_agent_api = true;
        cluster_ip_agent.agent_api_service_type = "ClusterIP".to_string();
        cluster_ip_agent.agent_api_node_port = Some(31080);
        let error = match k8s_install_plan(cluster_ip_agent) {
            Ok(_) => panic!("ClusterIP agent nodePort should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-node-port only applies"));

        let mut cluster_ip_relay = base_k8s_install_args();
        cluster_ip_relay.expose_relay = true;
        cluster_ip_relay.relay_service_type = "ClusterIP".to_string();
        cluster_ip_relay.relay_udp_node_port = Some(31820);
        cluster_ip_relay.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        cluster_ip_relay.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(cluster_ip_relay) {
            Ok(_) => panic!("ClusterIP relay nodePort should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-udp-node-port and --relay-http-node-port only apply"));

        let mut duplicate_relay = base_k8s_install_args();
        duplicate_relay.expose_relay = true;
        duplicate_relay.allow_public_service_exposure = true;
        duplicate_relay.relay_service_type = "NodePort".to_string();
        duplicate_relay.relay_udp_node_port = Some(31820);
        duplicate_relay.relay_http_node_port = Some(31820);
        duplicate_relay.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        duplicate_relay.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(duplicate_relay) {
            Ok(_) => panic!("duplicate relay nodePorts should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("--relay-udp-node-port and --relay-http-node-port must be different")
        );

        let mut duplicate_agent_relay = base_k8s_install_args();
        duplicate_agent_relay.expose_agent_api = true;
        duplicate_agent_relay.allow_public_service_exposure = true;
        duplicate_agent_relay.agent_api_service_type = "NodePort".to_string();
        duplicate_agent_relay.agent_api_node_port = Some(31080);
        duplicate_agent_relay.expose_relay = true;
        duplicate_agent_relay.relay_service_type = "NodePort".to_string();
        duplicate_agent_relay.relay_udp_node_port = Some(31080);
        duplicate_agent_relay.relay_http_node_port = Some(31580);
        duplicate_agent_relay.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        duplicate_agent_relay.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(duplicate_agent_relay) {
            Ok(_) => panic!("agent and relay NodePorts should be cluster-unique"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-udp-node-port must not reuse Kubernetes NodePort 31080 already assigned to --agent-api-node-port"
        ));

        Ok(())
    }

    #[test]
    fn k8s_install_wires_and_validates_service_app_protocols() -> anyhow::Result<()> {
        let mut valid = base_k8s_install_args();
        valid.expose_agent_api = true;
        valid.agent_api_service_type = "ClusterIP".to_string();
        valid.agent_api_app_protocol = Some("ipars.io/agent-http".to_string());
        valid.expose_relay = true;
        valid.relay_service_type = "ClusterIP".to_string();
        valid.relay_udp_app_protocol = Some("ipars.io/relay-udp".to_string());
        valid.relay_http_app_protocol = Some("http".to_string());
        valid.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        valid.relay_admission_url = Some("http://203.0.113.10:9580".to_string());

        let plan = k8s_install_plan(valid)?;
        assert!(plan.commands[2]
            .contains("--set-string agent.apiService.appProtocol=ipars.io/agent-http"));
        assert!(plan.commands[2]
            .contains("--set-string agent.relayService.udpAppProtocol=ipars.io/relay-udp"));
        assert!(plan.commands[2].contains("--set-string agent.relayService.httpAppProtocol=http"));

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--expose-agent-api",
            "--agent-api-app-protocol",
            "bad/proto/extra",
        ]);
        assert!(parsed.is_err());

        let mut missing_agent_exposure = base_k8s_install_args();
        missing_agent_exposure.agent_api_app_protocol = Some("http".to_string());
        let error = match k8s_install_plan(missing_agent_exposure) {
            Ok(_) => panic!("agent API appProtocol requires exposed agent API Service"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-app-protocol requires"));

        let mut missing_relay_exposure = base_k8s_install_args();
        missing_relay_exposure.relay_udp_app_protocol = Some("ipars.io/relay-udp".to_string());
        let error = match k8s_install_plan(missing_relay_exposure) {
            Ok(_) => panic!("relay appProtocol requires exposed relay Service"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-udp-app-protocol requires"));

        let mut direct_invalid = base_k8s_install_args();
        direct_invalid.expose_relay = true;
        direct_invalid.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        direct_invalid.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        direct_invalid.relay_http_app_protocol = Some("bad/proto/extra".to_string());
        let error = match k8s_install_plan(direct_invalid) {
            Ok(_) => panic!("invalid relay HTTP appProtocol should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-http-app-protocol"));

        Ok(())
    }

    #[test]
    fn k8s_install_wires_and_validates_publish_not_ready_addresses() -> anyhow::Result<()> {
        let mut valid = base_k8s_install_args();
        valid.expose_agent_api = true;
        valid.agent_api_service_type = "ClusterIP".to_string();
        valid.agent_api_publish_not_ready_addresses = true;
        valid.expose_relay = true;
        valid.relay_service_type = "ClusterIP".to_string();
        valid.relay_publish_not_ready_addresses = true;
        valid.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        valid.relay_admission_url = Some("http://203.0.113.10:9580".to_string());

        let plan = k8s_install_plan(valid)?;
        assert!(plan.commands[2].contains("--set agent.apiService.publishNotReadyAddresses=true"));
        assert!(plan.commands[2].contains("--set agent.relayService.publishNotReadyAddresses=true"));

        let mut missing_agent_exposure = base_k8s_install_args();
        missing_agent_exposure.agent_api_publish_not_ready_addresses = true;
        let error = match k8s_install_plan(missing_agent_exposure) {
            Ok(_) => {
                panic!("agent API publishNotReadyAddresses requires exposed agent API Service")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-publish-not-ready-addresses requires"));

        let mut missing_relay_exposure = base_k8s_install_args();
        missing_relay_exposure.relay_publish_not_ready_addresses = true;
        let error = match k8s_install_plan(missing_relay_exposure) {
            Ok(_) => panic!("relay publishNotReadyAddresses requires exposed relay Service"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-publish-not-ready-addresses requires"));

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--agent-api-publish-not-ready-addresses",
        ]);
        assert!(parsed.is_err());

        Ok(())
    }

    #[test]
    fn k8s_install_wires_and_validates_load_balancer_classes() -> anyhow::Result<()> {
        let mut valid = base_k8s_install_args();
        valid.expose_agent_api = true;
        valid.allow_public_service_exposure = true;
        valid.allow_unrestricted_load_balancer = true;
        valid.agent_api_service_type = "LoadBalancer".to_string();
        valid.agent_api_load_balancer_class = Some("example.com/internal-api".to_string());
        valid.agent_api_disable_load_balancer_node_ports = true;
        valid.expose_relay = true;
        valid.relay_service_type = "LoadBalancer".to_string();
        valid.relay_load_balancer_class = Some("example.com/internal-relay".to_string());
        valid.relay_disable_load_balancer_node_ports = true;
        valid.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        valid.relay_admission_url = Some("http://203.0.113.10:9580".to_string());

        let plan = k8s_install_plan(valid)?;
        assert!(plan.commands[2]
            .contains("--set-string agent.apiService.loadBalancerClass=example.com/internal-api"));
        assert!(plan.commands[2].contains(
            "--set-string agent.relayService.loadBalancerClass=example.com/internal-relay"
        ));
        assert!(
            plan.commands[2].contains("--set agent.apiService.allocateLoadBalancerNodePorts=false")
        );
        assert!(plan.commands[2]
            .contains("--set agent.relayService.allocateLoadBalancerNodePorts=false"));

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--expose-agent-api",
            "--agent-api-load-balancer-class",
            "Example.com/internal-api",
        ]);
        assert!(parsed.is_err());

        let mut node_port_agent = base_k8s_install_args();
        node_port_agent.expose_agent_api = true;
        node_port_agent.allow_public_service_exposure = true;
        node_port_agent.agent_api_service_type = "NodePort".to_string();
        node_port_agent.agent_api_load_balancer_class =
            Some("example.com/internal-api".to_string());
        let error = match k8s_install_plan(node_port_agent) {
            Ok(_) => panic!("NodePort agent loadBalancerClass should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-load-balancer-class only applies"));

        let mut node_port_relay = base_k8s_install_args();
        node_port_relay.expose_relay = true;
        node_port_relay.allow_public_service_exposure = true;
        node_port_relay.relay_service_type = "NodePort".to_string();
        node_port_relay.relay_load_balancer_class = Some("example.com/internal-relay".to_string());
        node_port_relay.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        node_port_relay.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(node_port_relay) {
            Ok(_) => panic!("NodePort relay loadBalancerClass should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-load-balancer-class only applies"));

        let mut conflicting_agent = base_k8s_install_args();
        conflicting_agent.expose_agent_api = true;
        conflicting_agent.allow_public_service_exposure = true;
        conflicting_agent.allow_unrestricted_load_balancer = true;
        conflicting_agent.agent_api_service_type = "LoadBalancer".to_string();
        conflicting_agent.agent_api_node_port = Some(31080);
        conflicting_agent.agent_api_disable_load_balancer_node_ports = true;
        let error = match k8s_install_plan(conflicting_agent) {
            Ok(_) => {
                panic!("disabled LoadBalancer node ports should reject explicit agent nodePort")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("cannot be combined with --agent-api-node-port"));

        let mut node_port_relay_disable = base_k8s_install_args();
        node_port_relay_disable.expose_relay = true;
        node_port_relay_disable.allow_public_service_exposure = true;
        node_port_relay_disable.relay_service_type = "NodePort".to_string();
        node_port_relay_disable.relay_disable_load_balancer_node_ports = true;
        node_port_relay_disable.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        node_port_relay_disable.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(node_port_relay_disable) {
            Ok(_) => panic!("NodePort relay cannot disable LoadBalancer node ports"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-disable-load-balancer-node-ports only applies"));

        Ok(())
    }

    #[test]
    fn k8s_install_wires_and_validates_service_external_addresses() -> anyhow::Result<()> {
        let mut valid = base_k8s_install_args();
        valid.expose_agent_api = true;
        valid.allow_public_service_exposure = true;
        valid.allow_unrestricted_load_balancer = true;
        valid.agent_api_service_type = "LoadBalancer".to_string();
        valid.agent_api_load_balancer_ip = Some("198.51.100.10".parse()?);
        valid.agent_api_external_ips = vec!["198.51.100.11".parse()?, "2001:db8::11".parse()?];
        valid.expose_relay = true;
        valid.relay_service_type = "LoadBalancer".to_string();
        valid.relay_load_balancer_ip = Some("203.0.113.10".parse()?);
        valid.relay_external_ips = vec!["203.0.113.11".parse()?];
        valid.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        valid.relay_admission_url = Some("http://203.0.113.10:9580".to_string());

        let plan = k8s_install_plan(valid)?;
        assert!(
            plan.commands[2].contains("--set-string agent.apiService.loadBalancerIP=198.51.100.10")
        );
        assert!(plan.commands[2]
            .contains("--set-string 'agent.apiService.externalIPs[0]=198.51.100.11'"));
        assert!(plan.commands[2]
            .contains("--set-string 'agent.apiService.externalIPs[1]=2001:db8::11'"));
        assert!(plan.commands[2]
            .contains("--set-string agent.relayService.loadBalancerIP=203.0.113.10"));
        assert!(plan.commands[2]
            .contains("--set-string 'agent.relayService.externalIPs[0]=203.0.113.11'"));

        let mut cluster_ip_external = base_k8s_install_args();
        cluster_ip_external.expose_agent_api = true;
        cluster_ip_external.allow_public_service_exposure = true;
        cluster_ip_external.agent_api_service_type = "ClusterIP".to_string();
        cluster_ip_external.agent_api_external_ips = vec!["198.51.100.12".parse()?];
        let cluster_ip_external_plan = k8s_install_plan(cluster_ip_external)?;
        assert!(cluster_ip_external_plan.commands[2]
            .contains("--set agent.apiService.exposureAcknowledged=true"));
        assert!(cluster_ip_external_plan.commands[2]
            .contains("--set-string 'agent.apiService.externalIPs[0]=198.51.100.12'"));

        let mut cluster_ip_agent = base_k8s_install_args();
        cluster_ip_agent.expose_agent_api = true;
        cluster_ip_agent.agent_api_service_type = "ClusterIP".to_string();
        cluster_ip_agent.agent_api_load_balancer_ip = Some("198.51.100.10".parse()?);
        let error = match k8s_install_plan(cluster_ip_agent) {
            Ok(_) => panic!("ClusterIP agent loadBalancerIP should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-load-balancer-ip only applies"));

        let mut cluster_ip_relay = base_k8s_install_args();
        cluster_ip_relay.expose_relay = true;
        cluster_ip_relay.relay_service_type = "ClusterIP".to_string();
        cluster_ip_relay.relay_load_balancer_ip = Some("203.0.113.10".parse()?);
        cluster_ip_relay.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        cluster_ip_relay.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(cluster_ip_relay) {
            Ok(_) => panic!("ClusterIP relay loadBalancerIP should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-load-balancer-ip only applies"));

        let mut unacknowledged_agent_external_ip = base_k8s_install_args();
        unacknowledged_agent_external_ip.expose_agent_api = true;
        unacknowledged_agent_external_ip.agent_api_external_ips = vec!["198.51.100.11".parse()?];
        let error = match k8s_install_plan(unacknowledged_agent_external_ip) {
            Ok(_) => panic!("agent externalIPs should require exposure acknowledgement"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-external-ip requires --allow-public-service-exposure"));

        let mut missing_relay_exposure = base_k8s_install_args();
        missing_relay_exposure.relay_external_ips = vec!["203.0.113.11".parse()?];
        let error = match k8s_install_plan(missing_relay_exposure) {
            Ok(_) => panic!("relay externalIPs require exposed relay Service"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-external-ip requires --expose-relay"));

        let mut unspecified_agent_lb = base_k8s_install_args();
        unspecified_agent_lb.expose_agent_api = true;
        unspecified_agent_lb.allow_public_service_exposure = true;
        unspecified_agent_lb.allow_unrestricted_load_balancer = true;
        unspecified_agent_lb.agent_api_service_type = "LoadBalancer".to_string();
        unspecified_agent_lb.agent_api_load_balancer_ip = Some("0.0.0.0".parse()?);
        let error = match k8s_install_plan(unspecified_agent_lb) {
            Ok(_) => panic!("agent LoadBalancerIP should reject unspecified addresses"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-load-balancer-ip must not use unspecified address"));

        let mut link_local_relay_external_ip = base_k8s_install_args();
        link_local_relay_external_ip.expose_relay = true;
        link_local_relay_external_ip.allow_public_service_exposure = true;
        link_local_relay_external_ip.allow_unrestricted_load_balancer = true;
        link_local_relay_external_ip.relay_service_type = "LoadBalancer".to_string();
        link_local_relay_external_ip.relay_external_ips = vec!["fe80::1".parse()?];
        link_local_relay_external_ip.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        link_local_relay_external_ip.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(link_local_relay_external_ip) {
            Ok(_) => panic!("relay externalIPs should reject link-local addresses"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-external-ip must not use link-local address"));

        let mut duplicate_agent_external_ip = base_k8s_install_args();
        duplicate_agent_external_ip.expose_agent_api = true;
        duplicate_agent_external_ip.allow_public_service_exposure = true;
        duplicate_agent_external_ip.agent_api_external_ips =
            vec!["198.51.100.11".parse()?, "198.51.100.11".parse()?];
        let error = match k8s_install_plan(duplicate_agent_external_ip) {
            Ok(_) => panic!("agent externalIPs should reject duplicate addresses"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-external-ip must not repeat external Service IP address 198.51.100.11"
        ));

        let mut duplicate_cross_service_external_ip = base_k8s_install_args();
        duplicate_cross_service_external_ip.expose_agent_api = true;
        duplicate_cross_service_external_ip.expose_relay = true;
        duplicate_cross_service_external_ip.allow_public_service_exposure = true;
        duplicate_cross_service_external_ip.agent_api_external_ips = vec!["198.51.100.11".parse()?];
        duplicate_cross_service_external_ip.relay_external_ips = vec!["198.51.100.11".parse()?];
        duplicate_cross_service_external_ip.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        duplicate_cross_service_external_ip.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(duplicate_cross_service_external_ip) {
            Ok(_) => panic!("agent and relay externalIPs should be disjoint"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-external-ip must not reuse external Service IP address 198.51.100.11 already assigned by --agent-api-external-ip"
        ));

        let mut duplicate_load_balancer_ip = base_k8s_install_args();
        duplicate_load_balancer_ip.expose_agent_api = true;
        duplicate_load_balancer_ip.allow_public_service_exposure = true;
        duplicate_load_balancer_ip.allow_unrestricted_load_balancer = true;
        duplicate_load_balancer_ip.agent_api_service_type = "LoadBalancer".to_string();
        duplicate_load_balancer_ip.agent_api_load_balancer_ip = Some("198.51.100.20".parse()?);
        duplicate_load_balancer_ip.expose_relay = true;
        duplicate_load_balancer_ip.relay_service_type = "LoadBalancer".to_string();
        duplicate_load_balancer_ip.relay_load_balancer_ip = Some("198.51.100.20".parse()?);
        duplicate_load_balancer_ip.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        duplicate_load_balancer_ip.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(duplicate_load_balancer_ip) {
            Ok(_) => panic!("agent and relay loadBalancerIP should be disjoint"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-load-balancer-ip must not reuse external Service IP address 198.51.100.20 already assigned by --agent-api-load-balancer-ip"
        ));

        let mut agent_external_reuses_load_balancer_ip = base_k8s_install_args();
        agent_external_reuses_load_balancer_ip.expose_agent_api = true;
        agent_external_reuses_load_balancer_ip.allow_public_service_exposure = true;
        agent_external_reuses_load_balancer_ip.allow_unrestricted_load_balancer = true;
        agent_external_reuses_load_balancer_ip.agent_api_service_type = "LoadBalancer".to_string();
        agent_external_reuses_load_balancer_ip.agent_api_load_balancer_ip =
            Some("198.51.100.21".parse()?);
        agent_external_reuses_load_balancer_ip.agent_api_external_ips =
            vec!["198.51.100.21".parse()?];
        let error = match k8s_install_plan(agent_external_reuses_load_balancer_ip) {
            Ok(_) => panic!("agent externalIPs should not reuse agent loadBalancerIP"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-external-ip must not reuse external Service IP address 198.51.100.21 already assigned by --agent-api-load-balancer-ip"
        ));

        let mut relay_external_reuses_agent_load_balancer_ip = base_k8s_install_args();
        relay_external_reuses_agent_load_balancer_ip.expose_agent_api = true;
        relay_external_reuses_agent_load_balancer_ip.allow_public_service_exposure = true;
        relay_external_reuses_agent_load_balancer_ip.allow_unrestricted_load_balancer = true;
        relay_external_reuses_agent_load_balancer_ip.agent_api_service_type =
            "LoadBalancer".to_string();
        relay_external_reuses_agent_load_balancer_ip.agent_api_load_balancer_ip =
            Some("198.51.100.22".parse()?);
        relay_external_reuses_agent_load_balancer_ip.expose_relay = true;
        relay_external_reuses_agent_load_balancer_ip.relay_external_ips =
            vec!["198.51.100.22".parse()?];
        relay_external_reuses_agent_load_balancer_ip.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_external_reuses_agent_load_balancer_ip.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(relay_external_reuses_agent_load_balancer_ip) {
            Ok(_) => panic!("relay externalIPs should not reuse agent loadBalancerIP"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-external-ip must not reuse external Service IP address 198.51.100.22 already assigned by --agent-api-load-balancer-ip"
        ));

        let mut agent_load_balancer_ip_family_mismatch = base_k8s_install_args();
        agent_load_balancer_ip_family_mismatch.expose_agent_api = true;
        agent_load_balancer_ip_family_mismatch.allow_public_service_exposure = true;
        agent_load_balancer_ip_family_mismatch.allow_unrestricted_load_balancer = true;
        agent_load_balancer_ip_family_mismatch.agent_api_service_type = "LoadBalancer".to_string();
        agent_load_balancer_ip_family_mismatch.agent_api_ip_families = vec!["IPv4".to_string()];
        agent_load_balancer_ip_family_mismatch.agent_api_load_balancer_ip =
            Some("2001:db8::23".parse()?);
        let error = match k8s_install_plan(agent_load_balancer_ip_family_mismatch) {
            Ok(_) => panic!("agent loadBalancerIP should match configured ipFamilies"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-load-balancer-ip address 2001:db8::23 family IPv6 must be included in --agent-api-ip-family values"
        ));

        let mut relay_external_ip_family_mismatch = base_k8s_install_args();
        relay_external_ip_family_mismatch.expose_relay = true;
        relay_external_ip_family_mismatch.allow_public_service_exposure = true;
        relay_external_ip_family_mismatch.relay_service_type = "ClusterIP".to_string();
        relay_external_ip_family_mismatch.relay_ip_families = vec!["IPv6".to_string()];
        relay_external_ip_family_mismatch.relay_external_ips = vec!["203.0.113.23".parse()?];
        relay_external_ip_family_mismatch.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        relay_external_ip_family_mismatch.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(relay_external_ip_family_mismatch) {
            Ok(_) => panic!("relay externalIPs should match configured ipFamilies"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-external-ip address 203.0.113.23 family IPv4 must be included in --relay-ip-family values"
        ));

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--expose-agent-api",
            "--agent-api-load-balancer-ip",
            "198.51.100.10/32",
        ]);
        assert!(parsed.is_err());

        Ok(())
    }

    #[test]
    fn k8s_install_wires_and_validates_health_check_node_ports() -> anyhow::Result<()> {
        let mut valid = base_k8s_install_args();
        valid.expose_agent_api = true;
        valid.allow_public_service_exposure = true;
        valid.allow_unrestricted_load_balancer = true;
        valid.agent_api_service_type = "LoadBalancer".to_string();
        valid.agent_api_health_check_node_port = Some(31081);
        valid.expose_relay = true;
        valid.relay_service_type = "LoadBalancer".to_string();
        valid.relay_health_check_node_port = Some(31821);
        valid.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        valid.relay_admission_url = Some("http://203.0.113.10:9580".to_string());

        let plan = k8s_install_plan(valid)?;
        assert!(plan.commands[2].contains("--set agent.apiService.healthCheckNodePort=31081"));
        assert!(plan.commands[2].contains("--set agent.relayService.healthCheckNodePort=31821"));

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--expose-agent-api",
            "--agent-api-health-check-node-port",
            "29999",
        ]);
        assert!(parsed.is_err());

        let mut node_port_agent = base_k8s_install_args();
        node_port_agent.expose_agent_api = true;
        node_port_agent.allow_public_service_exposure = true;
        node_port_agent.agent_api_service_type = "NodePort".to_string();
        node_port_agent.agent_api_health_check_node_port = Some(31081);
        let error = match k8s_install_plan(node_port_agent) {
            Ok(_) => panic!("NodePort agent healthCheckNodePort should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-health-check-node-port only applies"));

        let mut cluster_relay = base_k8s_install_args();
        cluster_relay.expose_relay = true;
        cluster_relay.allow_public_service_exposure = true;
        cluster_relay.allow_cluster_external_traffic_policy = true;
        cluster_relay.relay_service_type = "LoadBalancer".to_string();
        cluster_relay.relay_external_traffic_policy = "Cluster".to_string();
        cluster_relay.relay_health_check_node_port = Some(31821);
        cluster_relay.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        cluster_relay.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(cluster_relay) {
            Ok(_) => panic!("Cluster relay healthCheckNodePort should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-health-check-node-port requires"));

        let mut duplicate_agent = base_k8s_install_args();
        duplicate_agent.expose_agent_api = true;
        duplicate_agent.allow_public_service_exposure = true;
        duplicate_agent.allow_unrestricted_load_balancer = true;
        duplicate_agent.agent_api_service_type = "LoadBalancer".to_string();
        duplicate_agent.agent_api_node_port = Some(31081);
        duplicate_agent.agent_api_health_check_node_port = Some(31081);
        let error = match k8s_install_plan(duplicate_agent) {
            Ok(_) => panic!("agent healthCheckNodePort should not reuse nodePort"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("must differ from --agent-api-node-port"));

        let mut duplicate_relay = base_k8s_install_args();
        duplicate_relay.expose_relay = true;
        duplicate_relay.allow_public_service_exposure = true;
        duplicate_relay.allow_unrestricted_load_balancer = true;
        duplicate_relay.relay_service_type = "LoadBalancer".to_string();
        duplicate_relay.relay_udp_node_port = Some(31821);
        duplicate_relay.relay_health_check_node_port = Some(31821);
        duplicate_relay.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        duplicate_relay.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(duplicate_relay) {
            Ok(_) => panic!("relay healthCheckNodePort should not reuse service nodePort"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("must differ from relay NodePort overrides"));

        let mut duplicate_cross_service_health = base_k8s_install_args();
        duplicate_cross_service_health.expose_agent_api = true;
        duplicate_cross_service_health.allow_public_service_exposure = true;
        duplicate_cross_service_health.allow_unrestricted_load_balancer = true;
        duplicate_cross_service_health.agent_api_service_type = "LoadBalancer".to_string();
        duplicate_cross_service_health.agent_api_health_check_node_port = Some(31821);
        duplicate_cross_service_health.expose_relay = true;
        duplicate_cross_service_health.relay_service_type = "LoadBalancer".to_string();
        duplicate_cross_service_health.relay_health_check_node_port = Some(31821);
        duplicate_cross_service_health.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        duplicate_cross_service_health.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(duplicate_cross_service_health) {
            Ok(_) => panic!("agent and relay healthCheckNodePorts should be cluster-unique"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-health-check-node-port must not reuse Kubernetes NodePort 31821 already assigned to --agent-api-health-check-node-port"
        ));

        Ok(())
    }

    #[test]
    fn k8s_install_wires_and_validates_internal_traffic_policy() -> anyhow::Result<()> {
        let mut valid = base_k8s_install_args();
        valid.expose_agent_api = true;
        valid.agent_api_service_type = "ClusterIP".to_string();
        valid.agent_api_internal_traffic_policy = Some("Local".to_string());
        valid.expose_relay = true;
        valid.relay_service_type = "ClusterIP".to_string();
        valid.relay_internal_traffic_policy = Some("Cluster".to_string());
        valid.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        valid.relay_admission_url = Some("http://203.0.113.10:9580".to_string());

        let plan = k8s_install_plan(valid)?;
        assert!(plan.commands[2].contains("--set agent.apiService.internalTrafficPolicy=Local"));
        assert!(plan.commands[2].contains("--set agent.relayService.internalTrafficPolicy=Cluster"));

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--expose-agent-api",
            "--agent-api-internal-traffic-policy",
            "Public",
        ]);
        assert!(parsed.is_err());

        let mut missing_agent_exposure = base_k8s_install_args();
        missing_agent_exposure.agent_api_internal_traffic_policy = Some("Local".to_string());
        let error = match k8s_install_plan(missing_agent_exposure) {
            Ok(_) => panic!("agent internalTrafficPolicy requires exposed agent API Service"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-internal-traffic-policy requires"));

        let mut missing_relay_exposure = base_k8s_install_args();
        missing_relay_exposure.relay_internal_traffic_policy = Some("Local".to_string());
        let error = match k8s_install_plan(missing_relay_exposure) {
            Ok(_) => panic!("relay internalTrafficPolicy requires exposed relay Service"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-internal-traffic-policy requires"));

        Ok(())
    }

    #[test]
    fn k8s_install_wires_and_validates_traffic_distribution() -> anyhow::Result<()> {
        let mut valid = base_k8s_install_args();
        valid.expose_agent_api = true;
        valid.agent_api_service_type = "ClusterIP".to_string();
        valid.agent_api_traffic_distribution = Some("PreferSameNode".to_string());
        valid.expose_relay = true;
        valid.relay_service_type = "ClusterIP".to_string();
        valid.relay_traffic_distribution = Some("PreferClose".to_string());
        valid.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        valid.relay_admission_url = Some("http://203.0.113.10:9580".to_string());

        let plan = k8s_install_plan(valid)?;
        assert!(
            plan.commands[2].contains("--set agent.apiService.trafficDistribution=PreferSameNode")
        );
        assert!(
            plan.commands[2].contains("--set agent.relayService.trafficDistribution=PreferClose")
        );

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--expose-agent-api",
            "--agent-api-traffic-distribution",
            "Random",
        ]);
        assert!(parsed.is_err());

        let mut missing_agent_exposure = base_k8s_install_args();
        missing_agent_exposure.agent_api_traffic_distribution = Some("PreferSameZone".to_string());
        let error = match k8s_install_plan(missing_agent_exposure) {
            Ok(_) => panic!("agent trafficDistribution requires exposed agent API Service"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-traffic-distribution requires"));

        let mut missing_relay_exposure = base_k8s_install_args();
        missing_relay_exposure.relay_traffic_distribution = Some("PreferSameZone".to_string());
        let error = match k8s_install_plan(missing_relay_exposure) {
            Ok(_) => panic!("relay trafficDistribution requires exposed relay Service"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-traffic-distribution requires"));

        Ok(())
    }

    #[test]
    fn k8s_install_wires_and_validates_session_affinity() -> anyhow::Result<()> {
        let mut valid = base_k8s_install_args();
        valid.expose_agent_api = true;
        valid.agent_api_service_type = "ClusterIP".to_string();
        valid.agent_api_session_affinity = Some("ClientIP".to_string());
        valid.agent_api_session_affinity_timeout_seconds = Some(600);
        valid.expose_relay = true;
        valid.relay_service_type = "ClusterIP".to_string();
        valid.relay_session_affinity = Some("ClientIP".to_string());
        valid.relay_session_affinity_timeout_seconds = Some(900);
        valid.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        valid.relay_admission_url = Some("http://203.0.113.10:9580".to_string());

        let plan = k8s_install_plan(valid)?;
        assert!(plan.commands[2].contains("--set agent.apiService.sessionAffinity=ClientIP"));
        assert!(
            plan.commands[2].contains("--set agent.apiService.sessionAffinityTimeoutSeconds=600")
        );
        assert!(plan.commands[2].contains("--set agent.relayService.sessionAffinity=ClientIP"));
        assert!(
            plan.commands[2].contains("--set agent.relayService.sessionAffinityTimeoutSeconds=900")
        );

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--expose-agent-api",
            "--agent-api-session-affinity",
            "Cookie",
        ]);
        assert!(parsed.is_err());

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--expose-agent-api",
            "--agent-api-session-affinity-timeout-seconds",
            "0",
        ]);
        assert!(parsed.is_err());

        let mut missing_agent_affinity = base_k8s_install_args();
        missing_agent_affinity.expose_agent_api = true;
        missing_agent_affinity.agent_api_session_affinity_timeout_seconds = Some(600);
        let error = match k8s_install_plan(missing_agent_affinity) {
            Ok(_) => panic!("agent session affinity timeout should require ClientIP affinity"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-session-affinity-timeout-seconds requires"));

        let mut none_relay_affinity = base_k8s_install_args();
        none_relay_affinity.expose_relay = true;
        none_relay_affinity.relay_service_type = "ClusterIP".to_string();
        none_relay_affinity.relay_session_affinity = Some("None".to_string());
        none_relay_affinity.relay_session_affinity_timeout_seconds = Some(900);
        none_relay_affinity.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        none_relay_affinity.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(none_relay_affinity) {
            Ok(_) => panic!("relay session affinity timeout should reject None affinity"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-session-affinity-timeout-seconds requires"));

        let mut invalid_timeout = base_k8s_install_args();
        invalid_timeout.expose_agent_api = true;
        invalid_timeout.agent_api_session_affinity = Some("ClientIP".to_string());
        invalid_timeout.agent_api_session_affinity_timeout_seconds = Some(86_401);
        let error = match k8s_install_plan(invalid_timeout) {
            Ok(_) => panic!("agent session affinity timeout over 86400 should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("session affinity timeout must be between"));

        let mut missing_relay_exposure = base_k8s_install_args();
        missing_relay_exposure.relay_session_affinity = Some("ClientIP".to_string());
        let error = match k8s_install_plan(missing_relay_exposure) {
            Ok(_) => panic!("relay session affinity requires exposed relay Service"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-session-affinity requires"));

        Ok(())
    }

    #[test]
    fn k8s_install_wires_and_validates_network_policy() -> anyhow::Result<()> {
        let mut valid = base_k8s_install_args();
        valid.enable_network_policy = true;
        valid.network_policy_acknowledge_host_network = true;
        valid.expose_agent_api = true;
        valid.agent_api_service_type = "ClusterIP".to_string();
        valid.agent_api_port = Some(9781);
        valid.agent_api_target_port = Some(9790);
        valid.agent_api_network_policy_cidrs = vec!["10.0.0.0/8".parse()?];
        valid.expose_relay = true;
        valid.relay_service_type = "ClusterIP".to_string();
        valid.relay_udp_port = Some(51821);
        valid.relay_udp_target_port = Some(51820);
        valid.relay_http_port = Some(9581);
        valid.relay_http_target_port = Some(9580);
        valid.relay_network_policy_cidrs = vec!["203.0.113.0/24".parse()?];
        valid.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        valid.relay_admission_url = Some("http://203.0.113.10:9580".to_string());

        let plan = k8s_install_plan(valid)?;
        assert!(plan.commands[2].contains("--set networkPolicy.enabled=true"));
        assert!(plan.commands[2].contains("--set networkPolicy.acknowledgeHostNetwork=true"));
        assert!(plan.commands[2].contains("--set networkPolicy.agentApi.enabled=true"));
        assert!(plan.commands[2]
            .contains("--set-string 'networkPolicy.agentApi.allowedCidrs[0]=10.0.0.0/8'"));
        assert!(plan.commands[2].contains("--set agent.apiService.port=9781"));
        assert!(plan.commands[2].contains("--set agent.apiService.targetPort=9790"));
        assert!(plan.commands[2].contains("--set networkPolicy.relay.enabled=true"));
        assert!(plan.commands[2]
            .contains("--set-string 'networkPolicy.relay.allowedCidrs[0]=203.0.113.0/24'"));
        assert!(plan.commands[2].contains("--set agent.relayService.udpPort=51821"));
        assert!(plan.commands[2].contains("--set agent.relayService.udpTargetPort=51820"));
        assert!(plan.commands[2].contains("--set agent.relayService.httpPort=9581"));
        assert!(plan.commands[2].contains("--set agent.relayService.httpTargetPort=9580"));
        assert!(plan
            .notes
            .iter()
            .any(|note| note.contains("listener ports")));

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--enable-network-policy",
            "--network-policy-acknowledge-host-network",
            "--expose-agent-api",
            "--agent-api-network-policy-cidr",
            "not-a-cidr",
        ]);
        assert!(parsed.is_err());

        let mut missing_ack = base_k8s_install_args();
        missing_ack.enable_network_policy = true;
        missing_ack.expose_agent_api = true;
        missing_ack.agent_api_network_policy_cidrs = vec!["10.0.0.0/8".parse()?];
        let error = match k8s_install_plan(missing_ack) {
            Ok(_) => panic!("NetworkPolicy on hostNetwork agents should require acknowledgement"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--network-policy-acknowledge-host-network"));

        let mut pod_network_policy = base_k8s_install_args();
        pod_network_policy.disable_agent_host_network = true;
        pod_network_policy.enable_network_policy = true;
        pod_network_policy.expose_agent_api = true;
        pod_network_policy.agent_api_network_policy_cidrs = vec!["10.0.0.0/8".parse()?];
        let plan = k8s_install_plan(pod_network_policy)?;
        assert!(plan.commands[2].contains("--set agent.hostNetwork=false"));
        assert!(!plan.commands[2].contains("--set networkPolicy.acknowledgeHostNetwork=true"));

        let mut pod_network_policy_with_irrelevant_ack = base_k8s_install_args();
        pod_network_policy_with_irrelevant_ack.disable_agent_host_network = true;
        pod_network_policy_with_irrelevant_ack.enable_network_policy = true;
        pod_network_policy_with_irrelevant_ack.network_policy_acknowledge_host_network = true;
        pod_network_policy_with_irrelevant_ack.expose_agent_api = true;
        pod_network_policy_with_irrelevant_ack.agent_api_network_policy_cidrs =
            vec!["10.0.0.0/8".parse()?];
        let error = match k8s_install_plan(pod_network_policy_with_irrelevant_ack) {
            Ok(_) => panic!("hostNetwork acknowledgement should not apply to pod-network agents"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--network-policy-acknowledge-host-network only applies"));

        let mut no_cidrs = base_k8s_install_args();
        no_cidrs.enable_network_policy = true;
        no_cidrs.network_policy_acknowledge_host_network = true;
        let error = match k8s_install_plan(no_cidrs) {
            Ok(_) => panic!("NetworkPolicy without CIDR allowlists should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("requires at least one"));

        let mut missing_agent_exposure = base_k8s_install_args();
        missing_agent_exposure.enable_network_policy = true;
        missing_agent_exposure.network_policy_acknowledge_host_network = true;
        missing_agent_exposure.agent_api_network_policy_cidrs = vec!["10.0.0.0/8".parse()?];
        let error = match k8s_install_plan(missing_agent_exposure) {
            Ok(_) => panic!("agent API NetworkPolicy CIDRs should require agent API exposure"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-network-policy-cidr requires --expose-agent-api"));

        let mut missing_relay_exposure = base_k8s_install_args();
        missing_relay_exposure.enable_network_policy = true;
        missing_relay_exposure.network_policy_acknowledge_host_network = true;
        missing_relay_exposure.relay_network_policy_cidrs = vec!["203.0.113.0/24".parse()?];
        let error = match k8s_install_plan(missing_relay_exposure) {
            Ok(_) => panic!("relay NetworkPolicy CIDRs should require relay exposure"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-network-policy-cidr requires --expose-relay"));

        let mut unrestricted_agent_policy = base_k8s_install_args();
        unrestricted_agent_policy.enable_network_policy = true;
        unrestricted_agent_policy.network_policy_acknowledge_host_network = true;
        unrestricted_agent_policy.expose_agent_api = true;
        unrestricted_agent_policy.agent_api_network_policy_cidrs = vec!["0.0.0.0/0".parse()?];
        let error = match k8s_install_plan(unrestricted_agent_policy) {
            Ok(_) => panic!("agent API NetworkPolicy should reject unrestricted CIDRs"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-network-policy-cidr must not include unrestricted CIDR 0.0.0.0/0"
        ));

        let mut loopback_agent_policy = base_k8s_install_args();
        loopback_agent_policy.enable_network_policy = true;
        loopback_agent_policy.network_policy_acknowledge_host_network = true;
        loopback_agent_policy.expose_agent_api = true;
        loopback_agent_policy.agent_api_network_policy_cidrs = vec!["127.0.0.0/8".parse()?];
        let error = match k8s_install_plan(loopback_agent_policy) {
            Ok(_) => panic!("agent API NetworkPolicy should reject loopback CIDRs"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-network-policy-cidr must not include loopback CIDR 127.0.0.0/8"
        ));

        let mut noncanonical_agent_policy = base_k8s_install_args();
        noncanonical_agent_policy.enable_network_policy = true;
        noncanonical_agent_policy.network_policy_acknowledge_host_network = true;
        noncanonical_agent_policy.expose_agent_api = true;
        noncanonical_agent_policy.agent_api_network_policy_cidrs = vec!["10.0.0.1/8".parse()?];
        let error = match k8s_install_plan(noncanonical_agent_policy) {
            Ok(_) => panic!("agent API NetworkPolicy should reject non-canonical CIDRs"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-network-policy-cidr must use canonical CIDR 10.0.0.0/8, not 10.0.0.1/8"
        ));

        let mut unrestricted_relay_policy = base_k8s_install_args();
        unrestricted_relay_policy.enable_network_policy = true;
        unrestricted_relay_policy.network_policy_acknowledge_host_network = true;
        unrestricted_relay_policy.expose_relay = true;
        unrestricted_relay_policy.relay_service_type = "ClusterIP".to_string();
        unrestricted_relay_policy.relay_network_policy_cidrs = vec!["::/0".parse()?];
        unrestricted_relay_policy.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        unrestricted_relay_policy.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(unrestricted_relay_policy) {
            Ok(_) => panic!("relay NetworkPolicy should reject unrestricted CIDRs"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("--relay-network-policy-cidr must not include unrestricted CIDR ::/0")
        );

        let mut duplicate_agent_policy = base_k8s_install_args();
        duplicate_agent_policy.enable_network_policy = true;
        duplicate_agent_policy.network_policy_acknowledge_host_network = true;
        duplicate_agent_policy.expose_agent_api = true;
        duplicate_agent_policy.agent_api_network_policy_cidrs =
            vec!["10.0.0.0/8".parse()?, "10.0.0.0/8".parse()?];
        let error = match k8s_install_plan(duplicate_agent_policy) {
            Ok(_) => panic!("agent API NetworkPolicy should reject duplicate CIDRs"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-network-policy-cidr must not repeat NetworkPolicy CIDR allowlist 10.0.0.0/8"
        ));

        let mut duplicate_relay_policy = base_k8s_install_args();
        duplicate_relay_policy.enable_network_policy = true;
        duplicate_relay_policy.network_policy_acknowledge_host_network = true;
        duplicate_relay_policy.expose_relay = true;
        duplicate_relay_policy.relay_service_type = "ClusterIP".to_string();
        duplicate_relay_policy.relay_network_policy_cidrs =
            vec!["203.0.113.0/24".parse()?, "203.0.113.0/24".parse()?];
        duplicate_relay_policy.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        duplicate_relay_policy.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(duplicate_relay_policy) {
            Ok(_) => panic!("relay NetworkPolicy should reject duplicate CIDRs"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-network-policy-cidr must not repeat NetworkPolicy CIDR allowlist 203.0.113.0/24"
        ));

        let mut broad_agent_policy = base_k8s_install_args();
        broad_agent_policy.enable_network_policy = true;
        broad_agent_policy.network_policy_acknowledge_host_network = true;
        broad_agent_policy.expose_agent_api = true;
        broad_agent_policy.allow_public_service_exposure = true;
        broad_agent_policy.agent_api_service_type = "LoadBalancer".to_string();
        broad_agent_policy.agent_api_allow_source_cidrs = vec!["198.51.100.0/24".parse()?];
        broad_agent_policy.agent_api_network_policy_cidrs = vec!["198.51.0.0/16".parse()?];
        let error = match k8s_install_plan(broad_agent_policy) {
            Ok(_) => panic!("agent API NetworkPolicy should not exceed LoadBalancer source ranges"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-network-policy-cidr 198.51.0.0/16 must be contained by one of --agent-api-allow-source-cidr values"
        ));

        let mut valid_ipv6_agent_policy = base_k8s_install_args();
        valid_ipv6_agent_policy.enable_network_policy = true;
        valid_ipv6_agent_policy.network_policy_acknowledge_host_network = true;
        valid_ipv6_agent_policy.expose_agent_api = true;
        valid_ipv6_agent_policy.allow_public_service_exposure = true;
        valid_ipv6_agent_policy.agent_api_service_type = "LoadBalancer".to_string();
        valid_ipv6_agent_policy.agent_api_allow_source_cidrs = vec!["2001:db8:10::/48".parse()?];
        valid_ipv6_agent_policy.agent_api_network_policy_cidrs =
            vec!["2001:db8:10:1::/64".parse()?];
        let plan = k8s_install_plan(valid_ipv6_agent_policy)?;
        assert!(plan.commands[2]
            .contains("--set-string 'networkPolicy.agentApi.allowedCidrs[0]=2001:db8:10:1::/64'"));

        let mut broad_ipv6_agent_policy = base_k8s_install_args();
        broad_ipv6_agent_policy.enable_network_policy = true;
        broad_ipv6_agent_policy.network_policy_acknowledge_host_network = true;
        broad_ipv6_agent_policy.expose_agent_api = true;
        broad_ipv6_agent_policy.allow_public_service_exposure = true;
        broad_ipv6_agent_policy.agent_api_service_type = "LoadBalancer".to_string();
        broad_ipv6_agent_policy.agent_api_allow_source_cidrs = vec!["2001:db8:10::/48".parse()?];
        broad_ipv6_agent_policy.agent_api_network_policy_cidrs = vec!["2001:db8::/32".parse()?];
        let error = match k8s_install_plan(broad_ipv6_agent_policy) {
            Ok(_) => {
                panic!("agent API IPv6 NetworkPolicy should not exceed LoadBalancer source ranges")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-network-policy-cidr 2001:db8::/32 must be contained by one of --agent-api-allow-source-cidr values"
        ));

        let mut broad_relay_policy = base_k8s_install_args();
        broad_relay_policy.enable_network_policy = true;
        broad_relay_policy.network_policy_acknowledge_host_network = true;
        broad_relay_policy.expose_relay = true;
        broad_relay_policy.allow_public_service_exposure = true;
        broad_relay_policy.relay_service_type = "LoadBalancer".to_string();
        broad_relay_policy.relay_allow_source_cidrs = vec!["203.0.113.0/24".parse()?];
        broad_relay_policy.relay_network_policy_cidrs = vec!["203.0.0.0/16".parse()?];
        broad_relay_policy.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        broad_relay_policy.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(broad_relay_policy) {
            Ok(_) => panic!("relay NetworkPolicy should not exceed LoadBalancer source ranges"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-network-policy-cidr 203.0.0.0/16 must be contained by one of --relay-allow-source-cidr values"
        ));

        let mut broad_ipv6_relay_policy = base_k8s_install_args();
        broad_ipv6_relay_policy.enable_network_policy = true;
        broad_ipv6_relay_policy.network_policy_acknowledge_host_network = true;
        broad_ipv6_relay_policy.expose_relay = true;
        broad_ipv6_relay_policy.allow_public_service_exposure = true;
        broad_ipv6_relay_policy.relay_service_type = "LoadBalancer".to_string();
        broad_ipv6_relay_policy.relay_allow_source_cidrs = vec!["2001:db8:20::/48".parse()?];
        broad_ipv6_relay_policy.relay_network_policy_cidrs = vec!["2001:db8::/32".parse()?];
        broad_ipv6_relay_policy.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        broad_ipv6_relay_policy.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(broad_ipv6_relay_policy) {
            Ok(_) => {
                panic!("relay IPv6 NetworkPolicy should not exceed LoadBalancer source ranges")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-network-policy-cidr 2001:db8::/32 must be contained by one of --relay-allow-source-cidr values"
        ));

        Ok(())
    }

    #[test]
    fn k8s_install_wires_and_validates_ip_families() -> anyhow::Result<()> {
        let mut valid = base_k8s_install_args();
        valid.expose_agent_api = true;
        valid.agent_api_service_type = "ClusterIP".to_string();
        valid.agent_api_ip_family_policy = Some("RequireDualStack".to_string());
        valid.agent_api_ip_families = vec!["IPv4".to_string(), "IPv6".to_string()];
        valid.expose_relay = true;
        valid.relay_service_type = "ClusterIP".to_string();
        valid.relay_ip_family_policy = Some("PreferDualStack".to_string());
        valid.relay_ip_families = vec!["IPv6".to_string()];
        valid.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        valid.relay_admission_url = Some("http://203.0.113.10:9580".to_string());

        let plan = k8s_install_plan(valid)?;
        assert!(plan.commands[2].contains("--set agent.apiService.ipFamilyPolicy=RequireDualStack"));
        assert!(plan.commands[2].contains("--set-string 'agent.apiService.ipFamilies[0]=IPv4'"));
        assert!(plan.commands[2].contains("--set-string 'agent.apiService.ipFamilies[1]=IPv6'"));
        assert!(
            plan.commands[2].contains("--set agent.relayService.ipFamilyPolicy=PreferDualStack")
        );
        assert!(plan.commands[2].contains("--set-string 'agent.relayService.ipFamilies[0]=IPv6'"));

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--expose-agent-api",
            "--agent-api-ip-family",
            "IPv5",
        ]);
        assert!(parsed.is_err());

        let mut missing_dual_family = base_k8s_install_args();
        missing_dual_family.expose_agent_api = true;
        missing_dual_family.agent_api_ip_family_policy = Some("RequireDualStack".to_string());
        missing_dual_family.agent_api_ip_families = vec!["IPv6".to_string()];
        let error = match k8s_install_plan(missing_dual_family) {
            Ok(_) => panic!("RequireDualStack without both families should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("RequireDualStack requires both IPv4 and IPv6 families"));

        let mut duplicate_family = base_k8s_install_args();
        duplicate_family.expose_agent_api = true;
        duplicate_family.agent_api_ip_family_policy = Some("PreferDualStack".to_string());
        duplicate_family.agent_api_ip_families = vec!["IPv6".to_string(), "IPv6".to_string()];
        let error = match k8s_install_plan(duplicate_family) {
            Ok(_) => panic!("duplicate ipFamilies should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("ipFamilies cannot repeat"));

        let mut missing_policy = base_k8s_install_args();
        missing_policy.expose_agent_api = true;
        missing_policy.agent_api_ip_families = vec!["IPv4".to_string(), "IPv6".to_string()];
        let error = match k8s_install_plan(missing_policy) {
            Ok(_) => panic!("two ipFamilies without dual-stack policy should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("requires ipFamilyPolicy=PreferDualStack or RequireDualStack"));

        Ok(())
    }

    #[test]
    fn k8s_install_wires_and_validates_cluster_ips() -> anyhow::Result<()> {
        let mut valid = base_k8s_install_args();
        valid.expose_agent_api = true;
        valid.agent_api_service_type = "ClusterIP".to_string();
        valid.agent_api_cluster_ip = Some("10.96.0.40".parse()?);
        valid.agent_api_secondary_cluster_ip = Some("2001:db8::40".parse()?);
        valid.agent_api_ip_family_policy = Some("RequireDualStack".to_string());
        valid.agent_api_ip_families = vec!["IPv4".to_string(), "IPv6".to_string()];
        valid.expose_relay = true;
        valid.relay_service_type = "ClusterIP".to_string();
        valid.relay_cluster_ip = Some("2001:db8::41".parse()?);
        valid.relay_secondary_cluster_ip = Some("10.96.0.41".parse()?);
        valid.relay_ip_family_policy = Some("PreferDualStack".to_string());
        valid.relay_ip_families = vec!["IPv6".to_string(), "IPv4".to_string()];
        valid.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        valid.relay_admission_url = Some("http://203.0.113.10:9580".to_string());

        let plan = k8s_install_plan(valid)?;
        assert!(plan.commands[2].contains("--set-string agent.apiService.clusterIP=10.96.0.40"));
        assert!(
            plan.commands[2].contains("--set-string 'agent.apiService.clusterIPs[0]=10.96.0.40'")
        );
        assert!(
            plan.commands[2].contains("--set-string 'agent.apiService.clusterIPs[1]=2001:db8::40'")
        );
        assert!(plan.commands[2].contains("--set-string agent.relayService.clusterIP=2001:db8::41"));
        assert!(plan.commands[2]
            .contains("--set-string 'agent.relayService.clusterIPs[0]=2001:db8::41'"));
        assert!(
            plan.commands[2].contains("--set-string 'agent.relayService.clusterIPs[1]=10.96.0.41'")
        );

        let mut mismatched_agent_family = base_k8s_install_args();
        mismatched_agent_family.expose_agent_api = true;
        mismatched_agent_family.agent_api_cluster_ip = Some("2001:db8::40".parse()?);
        mismatched_agent_family.agent_api_ip_families = vec!["IPv4".to_string()];
        let error = match k8s_install_plan(mismatched_agent_family) {
            Ok(_) => panic!("agent clusterIP family mismatch should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("agent-api clusterIP family IPv6 must match"));

        let mut missing_dual_stack_policy = base_k8s_install_args();
        missing_dual_stack_policy.expose_agent_api = true;
        missing_dual_stack_policy.agent_api_cluster_ip = Some("10.96.0.40".parse()?);
        missing_dual_stack_policy.agent_api_secondary_cluster_ip = Some("2001:db8::40".parse()?);
        missing_dual_stack_policy.agent_api_ip_family_policy = Some("SingleStack".to_string());
        missing_dual_stack_policy.agent_api_ip_families = vec!["IPv4".to_string()];
        let error = match k8s_install_plan(missing_dual_stack_policy) {
            Ok(_) => panic!("secondary clusterIP should require dual-stack policy"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-secondary-cluster-ip requires"));

        let mut same_family_secondary = base_k8s_install_args();
        same_family_secondary.expose_relay = true;
        same_family_secondary.relay_cluster_ip = Some("10.96.0.40".parse()?);
        same_family_secondary.relay_secondary_cluster_ip = Some("10.96.0.41".parse()?);
        same_family_secondary.relay_ip_family_policy = Some("PreferDualStack".to_string());
        same_family_secondary.relay_ip_families = vec!["IPv4".to_string(), "IPv6".to_string()];
        same_family_secondary.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        same_family_secondary.relay_admission_url = Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(same_family_secondary) {
            Ok(_) => panic!("secondary clusterIP family should differ from primary"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("secondary clusterIP family IPv4 must differ"));

        let mut missing_agent_exposure = base_k8s_install_args();
        missing_agent_exposure.agent_api_cluster_ip = Some("10.96.0.40".parse()?);
        let error = match k8s_install_plan(missing_agent_exposure) {
            Ok(_) => panic!("agent clusterIP should require exposed agent API Service"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-cluster-ip requires --expose-agent-api"));

        let mut missing_relay_exposure = base_k8s_install_args();
        missing_relay_exposure.relay_cluster_ip = Some("10.96.0.41".parse()?);
        let error = match k8s_install_plan(missing_relay_exposure) {
            Ok(_) => panic!("relay clusterIP should require exposed relay Service"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-cluster-ip requires --expose-relay"));

        let mut duplicate_cross_service_primary = base_k8s_install_args();
        duplicate_cross_service_primary.expose_agent_api = true;
        duplicate_cross_service_primary.agent_api_cluster_ip = Some("10.96.0.40".parse()?);
        duplicate_cross_service_primary.expose_relay = true;
        duplicate_cross_service_primary.relay_cluster_ip = Some("10.96.0.40".parse()?);
        duplicate_cross_service_primary.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        duplicate_cross_service_primary.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(duplicate_cross_service_primary) {
            Ok(_) => panic!("agent and relay primary clusterIPs should be disjoint"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-cluster-ip must not reuse Kubernetes Service clusterIP 10.96.0.40 already assigned by --agent-api-cluster-ip"
        ));

        let mut duplicate_cross_service_secondary = base_k8s_install_args();
        duplicate_cross_service_secondary.expose_agent_api = true;
        duplicate_cross_service_secondary.agent_api_cluster_ip = Some("10.96.0.40".parse()?);
        duplicate_cross_service_secondary.agent_api_secondary_cluster_ip =
            Some("2001:db8::40".parse()?);
        duplicate_cross_service_secondary.agent_api_ip_family_policy =
            Some("RequireDualStack".to_string());
        duplicate_cross_service_secondary.agent_api_ip_families =
            vec!["IPv4".to_string(), "IPv6".to_string()];
        duplicate_cross_service_secondary.expose_relay = true;
        duplicate_cross_service_secondary.relay_cluster_ip = Some("10.96.0.41".parse()?);
        duplicate_cross_service_secondary.relay_secondary_cluster_ip =
            Some("2001:db8::40".parse()?);
        duplicate_cross_service_secondary.relay_ip_family_policy =
            Some("PreferDualStack".to_string());
        duplicate_cross_service_secondary.relay_ip_families =
            vec!["IPv4".to_string(), "IPv6".to_string()];
        duplicate_cross_service_secondary.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        duplicate_cross_service_secondary.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(duplicate_cross_service_secondary) {
            Ok(_) => panic!("agent and relay secondary clusterIPs should be disjoint"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-secondary-cluster-ip must not reuse Kubernetes Service clusterIP 2001:db8::40 already assigned by --agent-api-secondary-cluster-ip"
        ));

        let mut missing_primary = base_k8s_install_args();
        missing_primary.expose_agent_api = true;
        missing_primary.agent_api_secondary_cluster_ip = Some("2001:db8::40".parse()?);
        let error = match k8s_install_plan(missing_primary) {
            Ok(_) => panic!("secondary clusterIP should require primary clusterIP"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-secondary-cluster-ip requires --agent-api-cluster-ip"));

        let mut loopback_cluster_ip = base_k8s_install_args();
        loopback_cluster_ip.expose_agent_api = true;
        loopback_cluster_ip.agent_api_cluster_ip = Some("127.0.0.1".parse()?);
        let error = match k8s_install_plan(loopback_cluster_ip) {
            Ok(_) => panic!("loopback clusterIP should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-cluster-ip must not use loopback address 127.0.0.1"));

        let mut link_local_secondary_cluster_ip = base_k8s_install_args();
        link_local_secondary_cluster_ip.expose_agent_api = true;
        link_local_secondary_cluster_ip.agent_api_cluster_ip = Some("10.96.0.40".parse()?);
        link_local_secondary_cluster_ip.agent_api_secondary_cluster_ip = Some("fe80::40".parse()?);
        link_local_secondary_cluster_ip.agent_api_ip_family_policy =
            Some("RequireDualStack".to_string());
        link_local_secondary_cluster_ip.agent_api_ip_families =
            vec!["IPv4".to_string(), "IPv6".to_string()];
        let error = match k8s_install_plan(link_local_secondary_cluster_ip) {
            Ok(_) => panic!("link-local secondary clusterIP should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error
            .contains("--agent-api-secondary-cluster-ip must not use link-local address fe80::40"));

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--expose-agent-api",
            "--agent-api-cluster-ip",
            "127.0.0.1",
        ]);
        assert!(parsed.is_err());

        let parsed = Cli::try_parse_from([
            "ipars",
            "k8s",
            "install",
            "--expose-agent-api",
            "--agent-api-cluster-ip",
            "None",
        ]);
        assert!(parsed.is_err());

        Ok(())
    }

    #[test]
    fn k8s_install_requires_acknowledgement_for_cluster_external_traffic_policy(
    ) -> anyhow::Result<()> {
        let without_ack = k8s_install_plan(K8sInstallArgs {
            release: "edge".to_string(),
            namespace: "edge-system".to_string(),
            chart: PathBuf::from("charts/ipars"),
            chart_name_override: None,
            chart_fullname_override: None,
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            cluster_control_plane_url: None,
            cluster_signal_url: None,
            cluster_stun_endpoint: None,
            image_repository: None,
            image_tag: None,
            image_pull_policy: None,
            image_pull_secrets: Vec::new(),
            agent_privileged: false,
            agent_add_capabilities: Vec::new(),
            agent_drop_capabilities: Vec::new(),
            disable_agent_privilege_escalation: false,
            agent_read_only_root_filesystem: false,
            agent_seccomp_profile: None,
            agent_seccomp_localhost_profile: None,
            agent_run_as_user: None,
            agent_run_as_group: None,
            agent_run_as_non_root: false,
            agent_fs_group: None,
            agent_fs_group_change_policy: None,
            agent_supplemental_groups: Vec::new(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            agent_runtime_backend: "linux-command".to_string(),
            agent_wireguard_listen_port: None,
            agent_stun_bind: None,
            route_backend: "command".to_string(),
            disable_agent_peer_map: false,
            agent_peer_map_poll_interval_seconds: 30,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            expose_agent_api: true,
            allow_public_service_exposure: true,
            allow_unrestricted_load_balancer: false,
            allow_cluster_external_traffic_policy: false,
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            disable_rbac: false,
            disable_service_account_creation: false,
            service_account_name: None,
            service_account_annotations: Vec::new(),
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_scheduler_name: None,
            agent_runtime_class: None,
            agent_node_selectors: Vec::new(),
            agent_node_affinity_required: Vec::new(),
            agent_node_affinity_preferred: Vec::new(),
            agent_pod_affinity_required: Vec::new(),
            agent_pod_affinity_preferred: Vec::new(),
            agent_pod_anti_affinity_required: Vec::new(),
            agent_pod_anti_affinity_preferred: Vec::new(),
            agent_tolerations: Vec::new(),
            agent_topology_spreads: Vec::new(),
            disable_agent_host_network: false,
            disable_agent_service_account_token: false,
            agent_dns_policy: None,
            agent_state_host_path: None,
            agent_state_mount_path: None,
            agent_state_host_path_type: None,
            disable_agent_liveness_probe: false,
            disable_agent_readiness_probe: false,
            disable_agent_startup_probe: false,
            agent_probes: K8sProbeArgs::default(),
            agent_pre_stop_sleep_seconds: None,
            agent_termination_grace_period_seconds: None,
            agent_resource_request_cpu: None,
            agent_resource_request_memory: None,
            agent_resource_limit_cpu: None,
            agent_resource_limit_memory: None,
            agent_update_strategy: None,
            agent_rollout_max_unavailable: None,
            agent_rollout_max_surge: None,
            agent_min_ready_seconds: None,
            agent_revision_history_limit: None,
            agent_pdb_min_available: None,
            agent_pdb_max_unavailable: None,
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_cluster_ip: None,
            agent_api_secondary_cluster_ip: None,
            agent_api_port: None,
            agent_api_target_port: None,
            agent_api_node_port: None,
            agent_api_app_protocol: None,
            agent_api_publish_not_ready_addresses: false,
            agent_api_load_balancer_class: None,
            agent_api_load_balancer_ip: None,
            agent_api_external_ips: Vec::new(),
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: vec!["198.51.100.0/24".parse()?],
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_traffic_distribution: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Cluster".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_cluster_ip: None,
            relay_secondary_cluster_ip: None,
            relay_udp_port: None,
            relay_udp_target_port: None,
            relay_http_port: None,
            relay_http_target_port: None,
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_udp_app_protocol: None,
            relay_http_app_protocol: None,
            relay_publish_not_ready_addresses: false,
            relay_load_balancer_class: None,
            relay_load_balancer_ip: None,
            relay_external_ips: Vec::new(),
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: vec!["203.0.113.0/24".parse()?],
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_traffic_distribution: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
            relay_external_traffic_policy: "Cluster".to_string(),
            relay_service_annotations: Vec::new(),
            relay_admission_bearer_token_secret: None,
            relay_admission_bearer_token_key: None,
            relay_public_endpoint: Some("203.0.113.10:51820".to_string()),
            relay_admission_url: Some("http://203.0.113.10:9580".to_string()),
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        });
        assert!(without_ack.is_err());

        let acknowledged = k8s_install_plan(K8sInstallArgs {
            release: "edge".to_string(),
            namespace: "edge-system".to_string(),
            chart: PathBuf::from("charts/ipars"),
            chart_name_override: None,
            chart_fullname_override: None,
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            cluster_control_plane_url: None,
            cluster_signal_url: None,
            cluster_stun_endpoint: None,
            image_repository: None,
            image_tag: None,
            image_pull_policy: None,
            image_pull_secrets: Vec::new(),
            agent_privileged: false,
            agent_add_capabilities: Vec::new(),
            agent_drop_capabilities: Vec::new(),
            disable_agent_privilege_escalation: false,
            agent_read_only_root_filesystem: false,
            agent_seccomp_profile: None,
            agent_seccomp_localhost_profile: None,
            agent_run_as_user: None,
            agent_run_as_group: None,
            agent_run_as_non_root: false,
            agent_fs_group: None,
            agent_fs_group_change_policy: None,
            agent_supplemental_groups: Vec::new(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            agent_runtime_backend: "linux-command".to_string(),
            agent_wireguard_listen_port: None,
            agent_stun_bind: None,
            route_backend: "command".to_string(),
            disable_agent_peer_map: false,
            agent_peer_map_poll_interval_seconds: 30,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            expose_agent_api: true,
            allow_public_service_exposure: true,
            allow_unrestricted_load_balancer: false,
            allow_cluster_external_traffic_policy: true,
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            disable_rbac: false,
            disable_service_account_creation: false,
            service_account_name: None,
            service_account_annotations: Vec::new(),
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_scheduler_name: None,
            agent_runtime_class: None,
            agent_node_selectors: Vec::new(),
            agent_node_affinity_required: Vec::new(),
            agent_node_affinity_preferred: Vec::new(),
            agent_pod_affinity_required: Vec::new(),
            agent_pod_affinity_preferred: Vec::new(),
            agent_pod_anti_affinity_required: Vec::new(),
            agent_pod_anti_affinity_preferred: Vec::new(),
            agent_tolerations: Vec::new(),
            agent_topology_spreads: Vec::new(),
            disable_agent_host_network: false,
            disable_agent_service_account_token: false,
            agent_dns_policy: None,
            agent_state_host_path: None,
            agent_state_mount_path: None,
            agent_state_host_path_type: None,
            disable_agent_liveness_probe: false,
            disable_agent_readiness_probe: false,
            disable_agent_startup_probe: false,
            agent_probes: K8sProbeArgs::default(),
            agent_pre_stop_sleep_seconds: None,
            agent_termination_grace_period_seconds: None,
            agent_resource_request_cpu: None,
            agent_resource_request_memory: None,
            agent_resource_limit_cpu: None,
            agent_resource_limit_memory: None,
            agent_update_strategy: None,
            agent_rollout_max_unavailable: None,
            agent_rollout_max_surge: None,
            agent_min_ready_seconds: None,
            agent_revision_history_limit: None,
            agent_pdb_min_available: None,
            agent_pdb_max_unavailable: None,
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_cluster_ip: None,
            agent_api_secondary_cluster_ip: None,
            agent_api_port: None,
            agent_api_target_port: None,
            agent_api_node_port: None,
            agent_api_app_protocol: None,
            agent_api_publish_not_ready_addresses: false,
            agent_api_load_balancer_class: None,
            agent_api_load_balancer_ip: None,
            agent_api_external_ips: Vec::new(),
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: vec!["198.51.100.0/24".parse()?],
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_traffic_distribution: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Cluster".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_cluster_ip: None,
            relay_secondary_cluster_ip: None,
            relay_udp_port: None,
            relay_udp_target_port: None,
            relay_http_port: None,
            relay_http_target_port: None,
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_udp_app_protocol: None,
            relay_http_app_protocol: None,
            relay_publish_not_ready_addresses: false,
            relay_load_balancer_class: None,
            relay_load_balancer_ip: None,
            relay_external_ips: Vec::new(),
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: vec!["203.0.113.0/24".parse()?],
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_traffic_distribution: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
            relay_external_traffic_policy: "Cluster".to_string(),
            relay_service_annotations: Vec::new(),
            relay_admission_bearer_token_secret: None,
            relay_admission_bearer_token_key: None,
            relay_public_endpoint: Some("203.0.113.10:51820".to_string()),
            relay_admission_url: Some("http://203.0.113.10:9580".to_string()),
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        })?;
        assert!(acknowledged.commands[2]
            .contains("--set agent.apiService.allowClusterExternalTrafficPolicy=true"));
        assert!(acknowledged.commands[2]
            .contains("--set agent.relayService.allowClusterExternalTrafficPolicy=true"));
        Ok(())
    }

    #[test]
    fn k8s_install_rejects_irrelevant_service_exposure_acknowledgements() -> anyhow::Result<()> {
        let mut public_ack_without_public_service = base_k8s_install_args();
        public_ack_without_public_service.expose_agent_api = true;
        public_ack_without_public_service.allow_public_service_exposure = true;
        let error = match k8s_install_plan(public_ack_without_public_service) {
            Ok(_) => {
                panic!("public exposure acknowledgement should require public Service exposure")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--allow-public-service-exposure requires an exposed NodePort/LoadBalancer Service or Service externalIPs"
        ));

        let mut unrestricted_ack_with_source_ranges = base_k8s_install_args();
        unrestricted_ack_with_source_ranges.expose_agent_api = true;
        unrestricted_ack_with_source_ranges.allow_public_service_exposure = true;
        unrestricted_ack_with_source_ranges.allow_unrestricted_load_balancer = true;
        unrestricted_ack_with_source_ranges.agent_api_service_type = "LoadBalancer".to_string();
        unrestricted_ack_with_source_ranges.agent_api_allow_source_cidrs =
            vec!["198.51.100.0/24".parse()?];
        let error = match k8s_install_plan(unrestricted_ack_with_source_ranges) {
            Ok(_) => panic!("unrestricted LoadBalancer acknowledgement should require unrestricted LoadBalancer exposure"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--allow-unrestricted-load-balancer requires at least one exposed LoadBalancer Service without source CIDR ranges"
        ));

        let mut cluster_policy_ack_without_cluster_policy = base_k8s_install_args();
        cluster_policy_ack_without_cluster_policy.expose_agent_api = true;
        cluster_policy_ack_without_cluster_policy.allow_public_service_exposure = true;
        cluster_policy_ack_without_cluster_policy.allow_cluster_external_traffic_policy = true;
        cluster_policy_ack_without_cluster_policy.agent_api_service_type = "NodePort".to_string();
        let error = match k8s_install_plan(cluster_policy_ack_without_cluster_policy) {
            Ok(_) => panic!("cluster external traffic policy acknowledgement should require Cluster externalTrafficPolicy"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--allow-cluster-external-traffic-policy requires at least one exposed NodePort or LoadBalancer Service with externalTrafficPolicy=Cluster"
        ));

        Ok(())
    }

    #[test]
    fn k8s_install_rejects_inactive_service_type_and_target_port_overrides() -> anyhow::Result<()> {
        let mut inactive_agent_type = base_k8s_install_args();
        inactive_agent_type.agent_api_service_type = "NodePort".to_string();
        let error = match k8s_install_plan(inactive_agent_type) {
            Ok(_) => panic!("inactive agent API Service type override should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-service-type requires --expose-agent-api"));

        let mut inactive_agent_target_port = base_k8s_install_args();
        inactive_agent_target_port.agent_api_target_port = Some(9790);
        let error = match k8s_install_plan(inactive_agent_target_port) {
            Ok(_) => panic!("inactive agent API targetPort override should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-target-port requires --expose-agent-api"));

        let mut inactive_agent_source_range = base_k8s_install_args();
        inactive_agent_source_range.agent_api_allow_source_cidrs = vec!["198.51.100.0/24".parse()?];
        let error = match k8s_install_plan(inactive_agent_source_range) {
            Ok(_) => panic!("inactive agent API source range should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--agent-api-allow-source-cidr requires --expose-agent-api"));

        let mut inactive_relay_type = base_k8s_install_args();
        inactive_relay_type.relay_service_type = "ClusterIP".to_string();
        let error = match k8s_install_plan(inactive_relay_type) {
            Ok(_) => panic!("inactive relay Service type override should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-service-type requires --expose-relay"));

        let mut inactive_relay_source_range = base_k8s_install_args();
        inactive_relay_source_range.relay_allow_source_cidrs = vec!["203.0.113.0/24".parse()?];
        let error = match k8s_install_plan(inactive_relay_source_range) {
            Ok(_) => panic!("inactive relay source range should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-allow-source-cidr requires --expose-relay"));

        Ok(())
    }

    #[test]
    fn k8s_install_rejects_cluster_external_traffic_policy_on_inactive_services(
    ) -> anyhow::Result<()> {
        let mut cluster_policy_without_agent_service = base_k8s_install_args();
        cluster_policy_without_agent_service.agent_api_external_traffic_policy =
            "Cluster".to_string();
        let error = match k8s_install_plan(cluster_policy_without_agent_service) {
            Ok(_) => panic!(
                "agent externalTrafficPolicy=Cluster should require exposed external Service"
            ),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-external-traffic-policy Cluster requires --expose-agent-api with NodePort or LoadBalancer service type"
        ));

        let mut cluster_policy_on_cluster_ip = base_k8s_install_args();
        cluster_policy_on_cluster_ip.expose_relay = true;
        cluster_policy_on_cluster_ip.relay_service_type = "ClusterIP".to_string();
        cluster_policy_on_cluster_ip.relay_external_traffic_policy = "Cluster".to_string();
        cluster_policy_on_cluster_ip.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        cluster_policy_on_cluster_ip.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(cluster_policy_on_cluster_ip) {
            Ok(_) => panic!(
                "relay externalTrafficPolicy=Cluster should require exposed external Service"
            ),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--relay-external-traffic-policy Cluster requires --expose-relay with NodePort or LoadBalancer service type"
        ));

        Ok(())
    }

    #[test]
    fn k8s_install_rejects_source_ranges_without_load_balancer() -> anyhow::Result<()> {
        let plan = k8s_install_plan(K8sInstallArgs {
            release: "edge".to_string(),
            namespace: "edge-system".to_string(),
            chart: PathBuf::from("charts/ipars"),
            chart_name_override: None,
            chart_fullname_override: None,
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            cluster_control_plane_url: None,
            cluster_signal_url: None,
            cluster_stun_endpoint: None,
            image_repository: None,
            image_tag: None,
            image_pull_policy: None,
            image_pull_secrets: Vec::new(),
            agent_privileged: false,
            agent_add_capabilities: Vec::new(),
            agent_drop_capabilities: Vec::new(),
            disable_agent_privilege_escalation: false,
            agent_read_only_root_filesystem: false,
            agent_seccomp_profile: None,
            agent_seccomp_localhost_profile: None,
            agent_run_as_user: None,
            agent_run_as_group: None,
            agent_run_as_non_root: false,
            agent_fs_group: None,
            agent_fs_group_change_policy: None,
            agent_supplemental_groups: Vec::new(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            agent_runtime_backend: "linux-command".to_string(),
            agent_wireguard_listen_port: None,
            agent_stun_bind: None,
            route_backend: "command".to_string(),
            disable_agent_peer_map: false,
            agent_peer_map_poll_interval_seconds: 30,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            expose_agent_api: true,
            allow_public_service_exposure: false,
            allow_unrestricted_load_balancer: false,
            allow_cluster_external_traffic_policy: false,
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            disable_rbac: false,
            disable_service_account_creation: false,
            service_account_name: None,
            service_account_annotations: Vec::new(),
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_scheduler_name: None,
            agent_runtime_class: None,
            agent_node_selectors: Vec::new(),
            agent_node_affinity_required: Vec::new(),
            agent_node_affinity_preferred: Vec::new(),
            agent_pod_affinity_required: Vec::new(),
            agent_pod_affinity_preferred: Vec::new(),
            agent_pod_anti_affinity_required: Vec::new(),
            agent_pod_anti_affinity_preferred: Vec::new(),
            agent_tolerations: Vec::new(),
            agent_topology_spreads: Vec::new(),
            disable_agent_host_network: false,
            disable_agent_service_account_token: false,
            agent_dns_policy: None,
            agent_state_host_path: None,
            agent_state_mount_path: None,
            agent_state_host_path_type: None,
            disable_agent_liveness_probe: false,
            disable_agent_readiness_probe: false,
            disable_agent_startup_probe: false,
            agent_probes: K8sProbeArgs::default(),
            agent_pre_stop_sleep_seconds: None,
            agent_termination_grace_period_seconds: None,
            agent_resource_request_cpu: None,
            agent_resource_request_memory: None,
            agent_resource_limit_cpu: None,
            agent_resource_limit_memory: None,
            agent_update_strategy: None,
            agent_rollout_max_unavailable: None,
            agent_rollout_max_surge: None,
            agent_min_ready_seconds: None,
            agent_revision_history_limit: None,
            agent_pdb_min_available: None,
            agent_pdb_max_unavailable: None,
            agent_api_service_type: "ClusterIP".to_string(),
            agent_api_cluster_ip: None,
            agent_api_secondary_cluster_ip: None,
            agent_api_port: None,
            agent_api_target_port: None,
            agent_api_node_port: None,
            agent_api_app_protocol: None,
            agent_api_publish_not_ready_addresses: false,
            agent_api_load_balancer_class: None,
            agent_api_load_balancer_ip: None,
            agent_api_external_ips: Vec::new(),
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: vec!["198.51.100.0/24".parse()?],
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_traffic_distribution: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: false,
            relay_service_type: "LoadBalancer".to_string(),
            relay_cluster_ip: None,
            relay_secondary_cluster_ip: None,
            relay_udp_port: None,
            relay_udp_target_port: None,
            relay_http_port: None,
            relay_http_target_port: None,
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_udp_app_protocol: None,
            relay_http_app_protocol: None,
            relay_publish_not_ready_addresses: false,
            relay_load_balancer_class: None,
            relay_load_balancer_ip: None,
            relay_external_ips: Vec::new(),
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: Vec::new(),
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_traffic_distribution: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: Vec::new(),
            relay_admission_bearer_token_secret: None,
            relay_admission_bearer_token_key: None,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        });
        assert!(plan.is_err());
        Ok(())
    }

    #[test]
    fn k8s_install_requires_load_balancer_source_ranges_or_explicit_unrestricted_ack(
    ) -> anyhow::Result<()> {
        let without_ranges = k8s_install_plan(K8sInstallArgs {
            release: "edge".to_string(),
            namespace: "edge-system".to_string(),
            chart: PathBuf::from("charts/ipars"),
            chart_name_override: None,
            chart_fullname_override: None,
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            cluster_control_plane_url: None,
            cluster_signal_url: None,
            cluster_stun_endpoint: None,
            image_repository: None,
            image_tag: None,
            image_pull_policy: None,
            image_pull_secrets: Vec::new(),
            agent_privileged: false,
            agent_add_capabilities: Vec::new(),
            agent_drop_capabilities: Vec::new(),
            disable_agent_privilege_escalation: false,
            agent_read_only_root_filesystem: false,
            agent_seccomp_profile: None,
            agent_seccomp_localhost_profile: None,
            agent_run_as_user: None,
            agent_run_as_group: None,
            agent_run_as_non_root: false,
            agent_fs_group: None,
            agent_fs_group_change_policy: None,
            agent_supplemental_groups: Vec::new(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            agent_runtime_backend: "linux-command".to_string(),
            agent_wireguard_listen_port: None,
            agent_stun_bind: None,
            route_backend: "command".to_string(),
            disable_agent_peer_map: false,
            agent_peer_map_poll_interval_seconds: 30,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            expose_agent_api: true,
            allow_public_service_exposure: true,
            allow_unrestricted_load_balancer: false,
            allow_cluster_external_traffic_policy: false,
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            disable_rbac: false,
            disable_service_account_creation: false,
            service_account_name: None,
            service_account_annotations: Vec::new(),
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_scheduler_name: None,
            agent_runtime_class: None,
            agent_node_selectors: Vec::new(),
            agent_node_affinity_required: Vec::new(),
            agent_node_affinity_preferred: Vec::new(),
            agent_pod_affinity_required: Vec::new(),
            agent_pod_affinity_preferred: Vec::new(),
            agent_pod_anti_affinity_required: Vec::new(),
            agent_pod_anti_affinity_preferred: Vec::new(),
            agent_tolerations: Vec::new(),
            agent_topology_spreads: Vec::new(),
            disable_agent_host_network: false,
            disable_agent_service_account_token: false,
            agent_dns_policy: None,
            agent_state_host_path: None,
            agent_state_mount_path: None,
            agent_state_host_path_type: None,
            disable_agent_liveness_probe: false,
            disable_agent_readiness_probe: false,
            disable_agent_startup_probe: false,
            agent_probes: K8sProbeArgs::default(),
            agent_pre_stop_sleep_seconds: None,
            agent_termination_grace_period_seconds: None,
            agent_resource_request_cpu: None,
            agent_resource_request_memory: None,
            agent_resource_limit_cpu: None,
            agent_resource_limit_memory: None,
            agent_update_strategy: None,
            agent_rollout_max_unavailable: None,
            agent_rollout_max_surge: None,
            agent_min_ready_seconds: None,
            agent_revision_history_limit: None,
            agent_pdb_min_available: None,
            agent_pdb_max_unavailable: None,
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_cluster_ip: None,
            agent_api_secondary_cluster_ip: None,
            agent_api_port: None,
            agent_api_target_port: None,
            agent_api_node_port: None,
            agent_api_app_protocol: None,
            agent_api_publish_not_ready_addresses: false,
            agent_api_load_balancer_class: None,
            agent_api_load_balancer_ip: None,
            agent_api_external_ips: Vec::new(),
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_traffic_distribution: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: false,
            relay_service_type: "LoadBalancer".to_string(),
            relay_cluster_ip: None,
            relay_secondary_cluster_ip: None,
            relay_udp_port: None,
            relay_udp_target_port: None,
            relay_http_port: None,
            relay_http_target_port: None,
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_udp_app_protocol: None,
            relay_http_app_protocol: None,
            relay_publish_not_ready_addresses: false,
            relay_load_balancer_class: None,
            relay_load_balancer_ip: None,
            relay_external_ips: Vec::new(),
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: Vec::new(),
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_traffic_distribution: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: Vec::new(),
            relay_admission_bearer_token_secret: None,
            relay_admission_bearer_token_key: None,
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        });
        assert!(without_ranges.is_err());

        let unrestricted = k8s_install_plan(K8sInstallArgs {
            release: "edge".to_string(),
            namespace: "edge-system".to_string(),
            chart: PathBuf::from("charts/ipars"),
            chart_name_override: None,
            chart_fullname_override: None,
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            cluster_control_plane_url: None,
            cluster_signal_url: None,
            cluster_stun_endpoint: None,
            image_repository: None,
            image_tag: None,
            image_pull_policy: None,
            image_pull_secrets: Vec::new(),
            agent_privileged: false,
            agent_add_capabilities: Vec::new(),
            agent_drop_capabilities: Vec::new(),
            disable_agent_privilege_escalation: false,
            agent_read_only_root_filesystem: false,
            agent_seccomp_profile: None,
            agent_seccomp_localhost_profile: None,
            agent_run_as_user: None,
            agent_run_as_group: None,
            agent_run_as_non_root: false,
            agent_fs_group: None,
            agent_fs_group_change_policy: None,
            agent_supplemental_groups: Vec::new(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            agent_runtime_backend: "linux-command".to_string(),
            agent_wireguard_listen_port: None,
            agent_stun_bind: None,
            route_backend: "command".to_string(),
            disable_agent_peer_map: false,
            agent_peer_map_poll_interval_seconds: 30,
            agent_http_connect_timeout_seconds: DEFAULT_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS,
            agent_http_request_timeout_seconds: DEFAULT_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS,
            agent_direct_path_probe_timeout_seconds:
                DEFAULT_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS,
            agent_direct_handshake_max_age_seconds: DEFAULT_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS,
            agent_peer_probe: AgentPeerProbeInstallArgs::default(),
            expose_agent_api: true,
            allow_public_service_exposure: true,
            allow_unrestricted_load_balancer: true,
            allow_cluster_external_traffic_policy: false,
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            disable_rbac: false,
            disable_service_account_creation: false,
            service_account_name: None,
            service_account_annotations: Vec::new(),
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_scheduler_name: None,
            agent_runtime_class: None,
            agent_node_selectors: Vec::new(),
            agent_node_affinity_required: Vec::new(),
            agent_node_affinity_preferred: Vec::new(),
            agent_pod_affinity_required: Vec::new(),
            agent_pod_affinity_preferred: Vec::new(),
            agent_pod_anti_affinity_required: Vec::new(),
            agent_pod_anti_affinity_preferred: Vec::new(),
            agent_tolerations: Vec::new(),
            agent_topology_spreads: Vec::new(),
            disable_agent_host_network: false,
            disable_agent_service_account_token: false,
            agent_dns_policy: None,
            agent_state_host_path: None,
            agent_state_mount_path: None,
            agent_state_host_path_type: None,
            disable_agent_liveness_probe: false,
            disable_agent_readiness_probe: false,
            disable_agent_startup_probe: false,
            agent_probes: K8sProbeArgs::default(),
            agent_pre_stop_sleep_seconds: None,
            agent_termination_grace_period_seconds: None,
            agent_resource_request_cpu: None,
            agent_resource_request_memory: None,
            agent_resource_limit_cpu: None,
            agent_resource_limit_memory: None,
            agent_update_strategy: None,
            agent_rollout_max_unavailable: None,
            agent_rollout_max_surge: None,
            agent_min_ready_seconds: None,
            agent_revision_history_limit: None,
            agent_pdb_min_available: None,
            agent_pdb_max_unavailable: None,
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_cluster_ip: None,
            agent_api_secondary_cluster_ip: None,
            agent_api_port: None,
            agent_api_target_port: None,
            agent_api_node_port: None,
            agent_api_app_protocol: None,
            agent_api_publish_not_ready_addresses: false,
            agent_api_load_balancer_class: None,
            agent_api_load_balancer_ip: None,
            agent_api_external_ips: Vec::new(),
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_traffic_distribution: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_cluster_ip: None,
            relay_secondary_cluster_ip: None,
            relay_udp_port: None,
            relay_udp_target_port: None,
            relay_http_port: None,
            relay_http_target_port: None,
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_udp_app_protocol: None,
            relay_http_app_protocol: None,
            relay_publish_not_ready_addresses: false,
            relay_load_balancer_class: None,
            relay_load_balancer_ip: None,
            relay_external_ips: Vec::new(),
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: Vec::new(),
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_traffic_distribution: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: Vec::new(),
            relay_admission_bearer_token_secret: None,
            relay_admission_bearer_token_key: None,
            relay_public_endpoint: Some("203.0.113.10:51820".to_string()),
            relay_admission_url: Some("http://203.0.113.10:9580".to_string()),
            relay_status_url: None,
            relay_max_sessions: DEFAULT_RELAY_MAX_SESSIONS,
            relay_max_mbps: DEFAULT_RELAY_MAX_MBPS,
            relay_forwarder_endpoint: None,
            relay_forwarder_bind: None,
            relay_forwarder_wireguard_endpoint: None,
            relay_forwarder_netns: None,
            relay_forwarder_max_sessions: DEFAULT_RELAY_FORWARDER_MAX_SESSIONS,
            relay_forwarder_restart_backoff_seconds:
                DEFAULT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS,
            relay_forwarder_crash_window_seconds: DEFAULT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS,
            relay_forwarder_max_crashes_per_window: DEFAULT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW,
            relay_forwarder_crash_cooldown_seconds: DEFAULT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS,
        })?;
        assert!(unrestricted.commands[2]
            .contains("--set agent.apiService.allowUnrestrictedLoadBalancer=true"));
        assert!(unrestricted.commands[2]
            .contains("--set agent.relayService.allowUnrestrictedLoadBalancer=true"));

        let mut unrestricted_agent_source_range = base_k8s_install_args();
        unrestricted_agent_source_range.expose_agent_api = true;
        unrestricted_agent_source_range.allow_public_service_exposure = true;
        unrestricted_agent_source_range.agent_api_service_type = "LoadBalancer".to_string();
        unrestricted_agent_source_range.agent_api_allow_source_cidrs = vec!["0.0.0.0/0".parse()?];
        let error = match k8s_install_plan(unrestricted_agent_source_range) {
            Ok(_) => panic!("agent API source ranges should reject unrestricted CIDRs"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-allow-source-cidr must not include unrestricted CIDR 0.0.0.0/0"
        ));

        let mut unrestricted_relay_source_range = base_k8s_install_args();
        unrestricted_relay_source_range.expose_relay = true;
        unrestricted_relay_source_range.allow_public_service_exposure = true;
        unrestricted_relay_source_range.relay_service_type = "LoadBalancer".to_string();
        unrestricted_relay_source_range.relay_allow_source_cidrs = vec!["::/0".parse()?];
        unrestricted_relay_source_range.relay_public_endpoint =
            Some("203.0.113.10:51820".to_string());
        unrestricted_relay_source_range.relay_admission_url =
            Some("http://203.0.113.10:9580".to_string());
        let error = match k8s_install_plan(unrestricted_relay_source_range) {
            Ok(_) => panic!("relay source ranges should reject unrestricted CIDRs"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--relay-allow-source-cidr must not include unrestricted CIDR ::/0"));

        let mut link_local_agent_source_range = base_k8s_install_args();
        link_local_agent_source_range.expose_agent_api = true;
        link_local_agent_source_range.allow_public_service_exposure = true;
        link_local_agent_source_range.agent_api_service_type = "LoadBalancer".to_string();
        link_local_agent_source_range.agent_api_allow_source_cidrs =
            vec!["169.254.0.0/16".parse()?];
        let error = match k8s_install_plan(link_local_agent_source_range) {
            Ok(_) => panic!("agent API source ranges should reject link-local CIDRs"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-allow-source-cidr must not include link-local CIDR 169.254.0.0/16"
        ));

        let mut noncanonical_agent_source_range = base_k8s_install_args();
        noncanonical_agent_source_range.expose_agent_api = true;
        noncanonical_agent_source_range.allow_public_service_exposure = true;
        noncanonical_agent_source_range.agent_api_service_type = "LoadBalancer".to_string();
        noncanonical_agent_source_range.agent_api_allow_source_cidrs =
            vec!["198.51.100.1/24".parse()?];
        let error = match k8s_install_plan(noncanonical_agent_source_range) {
            Ok(_) => panic!("agent API source ranges should reject non-canonical CIDRs"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-allow-source-cidr must use canonical CIDR 198.51.100.0/24, not 198.51.100.1/24"
        ));

        let mut duplicate_agent_source_range = base_k8s_install_args();
        duplicate_agent_source_range.expose_agent_api = true;
        duplicate_agent_source_range.allow_public_service_exposure = true;
        duplicate_agent_source_range.agent_api_service_type = "LoadBalancer".to_string();
        duplicate_agent_source_range.agent_api_allow_source_cidrs =
            vec!["198.51.100.0/24".parse()?, "198.51.100.0/24".parse()?];
        let error = match k8s_install_plan(duplicate_agent_source_range) {
            Ok(_) => panic!("agent API source ranges should reject duplicate CIDRs"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(
            "--agent-api-allow-source-cidr must not repeat LoadBalancer source CIDR 198.51.100.0/24"
        ));
        Ok(())
    }

    #[test]
    fn install_plan_parsers_validate_service_types_and_annotations() {
        assert_eq!(
            parse_kubernetes_service_type("ClusterIP"),
            Ok("ClusterIP".to_string())
        );
        assert!(parse_kubernetes_service_type("ExternalName").is_err());
        assert_eq!(
            parse_kubernetes_external_traffic_policy("Local"),
            Ok("Local".to_string())
        );
        assert!(parse_kubernetes_external_traffic_policy("Public").is_err());
        assert_eq!(
            parse_kubernetes_internal_traffic_policy("Cluster"),
            Ok("Cluster".to_string())
        );
        assert!(parse_kubernetes_internal_traffic_policy("Public").is_err());
        assert_eq!(
            parse_kubernetes_traffic_distribution("PreferSameZone"),
            Ok("PreferSameZone".to_string())
        );
        assert!(parse_kubernetes_traffic_distribution("PreferRandom").is_err());
        assert_eq!(
            parse_kubernetes_session_affinity("ClientIP"),
            Ok("ClientIP".to_string())
        );
        assert_eq!(
            parse_kubernetes_session_affinity("None"),
            Ok("None".to_string())
        );
        assert!(parse_kubernetes_session_affinity("Cookie").is_err());
        assert_eq!(
            parse_kubernetes_session_affinity_timeout_seconds("1"),
            Ok(1)
        );
        assert_eq!(
            parse_kubernetes_session_affinity_timeout_seconds("86400"),
            Ok(86_400)
        );
        assert!(parse_kubernetes_session_affinity_timeout_seconds("0").is_err());
        assert!(parse_kubernetes_session_affinity_timeout_seconds("86401").is_err());
        assert_eq!(
            parse_kubernetes_fs_group_change_policy("OnRootMismatch"),
            Ok("OnRootMismatch".to_string())
        );
        assert_eq!(
            parse_kubernetes_fs_group_change_policy("Always"),
            Ok("Always".to_string())
        );
        assert!(parse_kubernetes_fs_group_change_policy("Sometimes").is_err());
        assert_eq!(
            parse_kubernetes_label_pair("ipars.io/role=agent"),
            Ok(KeyValueArg {
                key: "ipars.io/role".to_string(),
                value: "agent".to_string(),
            })
        );
        assert!(parse_kubernetes_label_pair("Example.com/role=agent").is_err());
        assert!(parse_kubernetes_label_pair("ipars.io/role=-agent").is_err());
        assert_eq!(
            parse_kubernetes_node_affinity_required_arg(
                "key=node-role.kubernetes.io/worker,operator=Exists"
            ),
            Ok(KubernetesNodeAffinityExpressionArg {
                key: "node-role.kubernetes.io/worker".to_string(),
                operator: "Exists".to_string(),
                values: Vec::new(),
            })
        );
        assert_eq!(
            parse_kubernetes_node_affinity_preferred_arg(
                "weight=75,key=node.kubernetes.io/instance-type,operator=In,values=m7i.large|m7i.xlarge"
            ),
            Ok(KubernetesPreferredNodeAffinityArg {
                weight: 75,
                expression: KubernetesNodeAffinityExpressionArg {
                    key: "node.kubernetes.io/instance-type".to_string(),
                    operator: "In".to_string(),
                    values: vec!["m7i.large".to_string(), "m7i.xlarge".to_string()],
                },
            })
        );
        assert!(
            parse_kubernetes_node_affinity_required_arg("key=kubernetes.io/os,operator=In")
                .is_err()
        );
        assert!(parse_kubernetes_node_affinity_required_arg(
            "key=kubernetes.io/os,operator=Exists,values=linux"
        )
        .is_err());
        assert!(parse_kubernetes_node_affinity_required_arg(
            "key=kubernetes.io/os,operator=Gt,values=linux"
        )
        .is_err());
        assert!(parse_kubernetes_node_affinity_preferred_arg(
            "weight=0,key=kubernetes.io/os,operator=Exists"
        )
        .is_err());
        assert_eq!(
            parse_kubernetes_pod_affinity_required_arg(
                "topologyKey=kubernetes.io/hostname,key=app.kubernetes.io/name,operator=In,values=ipars,namespaces=default|ipars-system"
            ),
            Ok(KubernetesPodAffinityTermArg {
                topology_key: "kubernetes.io/hostname".to_string(),
                match_expressions: vec![KubernetesLabelSelectorExpressionArg {
                    key: "app.kubernetes.io/name".to_string(),
                    operator: "In".to_string(),
                    values: vec!["ipars".to_string()],
                }],
                namespaces: vec!["default".to_string(), "ipars-system".to_string()],
            })
        );
        assert_eq!(
            parse_kubernetes_pod_affinity_preferred_arg(
                "weight=90,topologyKey=topology.kubernetes.io/zone,key=ipars.io/role,operator=Exists"
            ),
            Ok(KubernetesPreferredPodAffinityArg {
                weight: 90,
                term: KubernetesPodAffinityTermArg {
                    topology_key: "topology.kubernetes.io/zone".to_string(),
                    match_expressions: vec![KubernetesLabelSelectorExpressionArg {
                        key: "ipars.io/role".to_string(),
                        operator: "Exists".to_string(),
                        values: Vec::new(),
                    }],
                    namespaces: Vec::new(),
                },
            })
        );
        assert!(parse_kubernetes_pod_affinity_required_arg(
            "topologyKey=kubernetes.io/hostname,key=app.kubernetes.io/name,operator=In"
        )
        .is_err());
        assert!(parse_kubernetes_pod_affinity_required_arg(
            "topologyKey=kubernetes.io/hostname,key=app.kubernetes.io/name,operator=Exists,values=ipars"
        )
        .is_err());
        assert!(parse_kubernetes_pod_affinity_required_arg(
            "topologyKey=kubernetes.io/hostname,key=app.kubernetes.io/name,operator=Gt,values=1"
        )
        .is_err());
        assert!(parse_kubernetes_pod_affinity_required_arg(
            "topologyKey=kubernetes.io/hostname,key=app.kubernetes.io/name,operator=Exists,namespaces=default|default"
        )
        .is_err());
        assert!(parse_kubernetes_pod_affinity_preferred_arg(
            "weight=101,topologyKey=kubernetes.io/hostname,key=app.kubernetes.io/name,operator=Exists"
        )
        .is_err());
        assert_eq!(
            parse_kubernetes_toleration_arg(
                "key=node-role.kubernetes.io/control-plane,operator=Exists,effect=NoSchedule"
            ),
            Ok(KubernetesTolerationArg {
                key: Some("node-role.kubernetes.io/control-plane".to_string()),
                operator: Some("Exists".to_string()),
                value: None,
                effect: Some("NoSchedule".to_string()),
                toleration_seconds: None,
            })
        );
        assert_eq!(
            parse_kubernetes_toleration_arg(
                "key=node.kubernetes.io/unreachable,operator=Exists,effect=NoExecute,tolerationSeconds=600"
            ),
            Ok(KubernetesTolerationArg {
                key: Some("node.kubernetes.io/unreachable".to_string()),
                operator: Some("Exists".to_string()),
                value: None,
                effect: Some("NoExecute".to_string()),
                toleration_seconds: Some(600),
            })
        );
        assert!(parse_kubernetes_toleration_arg("operator=Equal").is_err());
        assert!(parse_kubernetes_toleration_arg(
            "key=node-role.kubernetes.io/control-plane,operator=Exists,value=true"
        )
        .is_err());
        assert!(parse_kubernetes_toleration_arg(
            "key=node-role.kubernetes.io/control-plane,effect=NoSchedule,tolerationSeconds=600"
        )
        .is_err());
        assert!(parse_kubernetes_toleration_arg("key=Example.com/role").is_err());
        assert_eq!(
            parse_kubernetes_topology_spread_arg(
                "topologyKey=topology.kubernetes.io/zone,maxSkew=1,whenUnsatisfiable=DoNotSchedule,minDomains=2,nodeAffinityPolicy=Honor,nodeTaintsPolicy=Ignore"
            ),
            Ok(KubernetesTopologySpreadArg {
                topology_key: "topology.kubernetes.io/zone".to_string(),
                max_skew: 1,
                when_unsatisfiable: "DoNotSchedule".to_string(),
                min_domains: Some(2),
                node_affinity_policy: Some("Honor".to_string()),
                node_taints_policy: Some("Ignore".to_string()),
            })
        );
        assert!(parse_kubernetes_topology_spread_arg(
            "topologyKey=topology.kubernetes.io/zone,maxSkew=0,whenUnsatisfiable=DoNotSchedule"
        )
        .is_err());
        assert!(parse_kubernetes_topology_spread_arg(
            "topologyKey=Topology.kubernetes.io/zone,maxSkew=1,whenUnsatisfiable=DoNotSchedule"
        )
        .is_err());
        assert!(parse_kubernetes_topology_spread_arg(
            "topologyKey=topology.kubernetes.io/zone,maxSkew=1,whenUnsatisfiable=ScheduleAnyway,minDomains=2"
        )
        .is_err());
        assert!(parse_kubernetes_topology_spread_arg(
            "topologyKey=topology.kubernetes.io/zone,maxSkew=1,whenUnsatisfiable=DoNotSchedule,nodeAffinityPolicy=Prefer"
        )
        .is_err());
        assert_eq!(
            parse_kubernetes_priority_class_name("ipars-agent-critical"),
            Ok("ipars-agent-critical".to_string())
        );
        assert!(parse_kubernetes_priority_class_name("system/node-critical").is_err());
        assert_eq!(
            parse_kubernetes_scheduler_name("ipars-scheduler"),
            Ok("ipars-scheduler".to_string())
        );
        assert!(parse_kubernetes_scheduler_name("system/scheduler").is_err());
        assert_eq!(
            parse_kubernetes_runtime_class_name("ipars-runtime"),
            Ok("ipars-runtime".to_string())
        );
        assert!(parse_kubernetes_runtime_class_name("Runtime_Class").is_err());
        assert_eq!(
            parse_kubernetes_resource_quantity("128Mi"),
            Ok("128Mi".to_string())
        );
        assert!(parse_kubernetes_resource_quantity("128 Mi").is_err());
        assert_eq!(
            parse_kubernetes_daemonset_update_strategy("RollingUpdate"),
            Ok("RollingUpdate".to_string())
        );
        assert_eq!(
            parse_kubernetes_daemonset_update_strategy("OnDelete"),
            Ok("OnDelete".to_string())
        );
        assert!(parse_kubernetes_daemonset_update_strategy("Recreate").is_err());
        assert_eq!(parse_kubernetes_int_or_percent("0"), Ok("0".to_string()));
        assert_eq!(
            parse_kubernetes_int_or_percent("100%"),
            Ok("100%".to_string())
        );
        assert!(parse_kubernetes_int_or_percent("101%").is_err());
        assert!(parse_kubernetes_int_or_percent("01%").is_err());
        assert!(parse_kubernetes_int_or_percent("1.5").is_err());
        assert_eq!(
            parse_kubernetes_non_negative_i32("2147483647"),
            Ok(2_147_483_647)
        );
        assert!(parse_kubernetes_non_negative_i32("2147483648").is_err());
        assert_eq!(
            parse_kubernetes_non_negative_i64("9223372036854775807"),
            Ok(9_223_372_036_854_775_807)
        );
        assert!(parse_kubernetes_non_negative_i64("9223372036854775808").is_err());
        assert_eq!(parse_kubernetes_node_port("30000"), Ok(30000));
        assert_eq!(parse_kubernetes_node_port("32767"), Ok(32767));
        assert!(parse_kubernetes_node_port("29999").is_err());
        assert!(parse_kubernetes_node_port("32768").is_err());
        assert_eq!(parse_kubernetes_service_port("1"), Ok(1));
        assert_eq!(parse_kubernetes_service_port("65535"), Ok(65_535));
        assert!(parse_kubernetes_service_port("0").is_err());
        assert!(parse_kubernetes_service_port("65536").is_err());
        assert_eq!(
            parse_kubernetes_ip_family_policy("RequireDualStack"),
            Ok("RequireDualStack".to_string())
        );
        assert!(parse_kubernetes_ip_family_policy("DualStack").is_err());
        assert_eq!(parse_kubernetes_ip_family("IPv6"), Ok("IPv6".to_string()));
        assert!(parse_kubernetes_ip_family("IPv5").is_err());
        assert_eq!(
            parse_kubernetes_load_balancer_class("example.com/internal-api"),
            Ok("example.com/internal-api".to_string())
        );
        assert_eq!(
            parse_kubernetes_load_balancer_class("internal_api"),
            Ok("internal_api".to_string())
        );
        assert!(parse_kubernetes_load_balancer_class("Example.com/internal-api").is_err());
        assert!(parse_kubernetes_load_balancer_class("example.com/internal/api").is_err());
        assert_eq!(
            parse_key_value("example.com/lb-profile=public"),
            Ok(KeyValueArg {
                key: "example.com/lb-profile".to_string(),
                value: "public".to_string(),
            })
        );
        assert_eq!(
            parse_key_value("example.com/team.alpha_1=blue"),
            Ok(KeyValueArg {
                key: "example.com/team.alpha_1".to_string(),
                value: "blue".to_string(),
            })
        );
        assert!(parse_key_value("missing-equals").is_err());
        assert!(parse_key_value("Upper.example.com/key=value").is_err());
        assert!(parse_key_value("example.com/-bad=value").is_err());
        assert!(parse_key_value("example.com/bad?=value").is_err());
        assert!(parse_key_value("example.com/key=two words").is_err());
        assert!(parse_key_value("example.com/key=line\nbreak").is_err());
        let oversized_annotation = format!(
            "example.com/key={}",
            "a".repeat(KUBERNETES_ANNOTATION_VALUE_MAX_BYTES + 1)
        );
        assert!(parse_key_value(&oversized_annotation).is_err());
        assert_eq!(
            helm_set_key("example.com/lb-profile"),
            "example\\.com/lb-profile"
        );
        assert_eq!(helm_set_string_value("nlb,ip"), "nlb\\,ip");
        assert_eq!(shell_word("charts/ipars"), "charts/ipars");
        assert_eq!(shell_word("charts/ipars chart"), "'charts/ipars chart'");
        assert_eq!(shell_word("charts/ipars'chart"), "'charts/ipars'\\''chart'");
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ipars-cli-{name}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ))
    }
}
