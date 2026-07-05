use std::collections::BTreeSet;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, Stdio};

use anyhow::Context;
use chrono::{Duration, Utc};
use clap::{Args, Parser, Subcommand};
use ipars_crypto::{IdentityKeyPair, WireGuardKeyPair};
use ipars_types::api::{
    AgentPathProbeRequest, AgentPathProbeResponse, AgentPathsResponse, AgentStatusResponse,
    ControlPlaneMetricsResponse, ControlPlanePolicyResponse, JoinNodeRequest, PeerMap,
    RegisterNodeRequest, RegisterNodeResponse, RelayStatusResponse, RevokeTokenRequest,
    RevokeTokenResponse,
};
use ipars_types::{
    BootstrapEndpoint, BootstrapEndpointKind, CandidateSource, ClusterId, EndpointCandidate,
    EndpointCandidateKind, JoinTokenClaims, KeyId, NodeId, PathMetrics, PathState, Role, Route,
    SignedJoinToken, Tag, TokenPolicy,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(name = "ipars")]
#[command(about = "IPA-RS-HeteroNetwork P2P VPN control CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init(InitArgs),
    Join(JoinArgs),
    Status(StatusArgs),
    Peers(PeersArgs),
    Routes(RoutesArgs),
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
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
    #[arg(long, default_value = "0.0.0.0:9443")]
    signal_listen: SocketAddr,
    #[arg(long, default_value = "0.0.0.0:3478")]
    stun_listen: SocketAddr,
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
    #[arg(long, env = "IPARS_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,
    #[arg(long, env = "IPARS_NODE_ID")]
    node_id: Option<String>,
}

#[derive(Debug, Args)]
struct RoutesArgs {
    #[arg(long, env = "IPARS_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,
    #[arg(long, env = "IPARS_NODE_ID")]
    node_id: Option<String>,
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    Create(TokenCreateArgs),
    Revoke(TokenRevokeArgs),
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
}

#[derive(Debug, Subcommand)]
enum RelayCommand {
    Status(RelayStatusArgs),
}

#[derive(Debug, Args)]
struct RelayStatusArgs {
    #[arg(long, env = "IPARS_RELAY_URL")]
    relay_url: Option<String>,
}

#[derive(Debug, Subcommand)]
enum PathCommand {
    Status(PathStatusArgs),
    Probe(PathProbeArgs),
}

#[derive(Debug, Args)]
struct PathStatusArgs {
    #[arg(long, env = "IPARS_AGENT_URL")]
    agent_url: Option<String>,
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
    Install(DockerInstallArgs),
}

#[derive(Debug, Subcommand)]
enum K8sCommand {
    Install(K8sInstallArgs),
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
}

#[derive(Debug, Args)]
struct K8sInstallArgs {
    #[arg(long, default_value = "ipars")]
    release: String,
    #[arg(long, default_value = "ipars-system")]
    namespace: String,
    #[arg(long, default_value = "charts/ipars")]
    chart: PathBuf,
    #[arg(long, default_value = "ipars-join-token")]
    join_token_secret: String,
    #[arg(long, default_value = "token")]
    join_token_key: String,
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
    #[arg(long, default_value_t = false)]
    expose_agent_api: bool,
    #[arg(long, default_value_t = false)]
    allow_public_service_exposure: bool,
    #[arg(long, default_value_t = false)]
    allow_unrestricted_load_balancer: bool,
    #[arg(long, default_value_t = false)]
    allow_cluster_external_traffic_policy: bool,
    #[arg(long, default_value = "ClusterIP", value_parser = parse_kubernetes_service_type)]
    agent_api_service_type: String,
    #[arg(long = "agent-api-allow-source-cidr", requires = "expose_agent_api")]
    agent_api_allow_source_cidrs: Vec<ipnet::IpNet>,
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
    #[arg(long = "relay-allow-source-cidr", requires = "expose_relay")]
    relay_allow_source_cidrs: Vec<ipnet::IpNet>,
    #[arg(long, default_value = "Local", value_parser = parse_kubernetes_external_traffic_policy)]
    relay_external_traffic_policy: String,
    #[arg(long = "relay-service-annotation", value_parser = parse_key_value, requires = "expose_relay")]
    relay_service_annotations: Vec<KeyValueArg>,
    #[arg(long)]
    relay_public_endpoint: Option<String>,
    #[arg(long)]
    relay_admission_url: Option<String>,
    #[arg(long)]
    relay_status_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyValueArg {
    key: String,
    value: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init(args) => print_json(&init(args)?)?,
        Command::Join(args) => print_json(&join(args).await?)?,
        Command::Status(args) => {
            match (args.agent_url.as_deref(), args.control_plane_url.as_deref()) {
                (Some(agent_url), None) => print_json(&agent_status(agent_url).await?)?,
                (None, Some(control_plane_url)) => {
                    print_json(&control_plane_status(control_plane_url).await?)?
                }
                (None, None) => print_json(&StaticStatus::status())?,
                (Some(_), Some(_)) => unreachable!("clap prevents conflicting status URLs"),
            }
        }
        Command::Peers(args) => match args.control_plane_url.as_deref() {
            Some(control_plane_url) => print_json(&peer_map(control_plane_url, &args).await?)?,
            None if args.node_id.is_some() => {
                anyhow::bail!("ipars peers requires --control-plane-url with --node-id")
            }
            None => print_json(&StaticStatus::peers())?,
        },
        Command::Routes(args) => match args.control_plane_url.as_deref() {
            Some(control_plane_url) => print_json(&routes(control_plane_url, &args).await?)?,
            None if args.node_id.is_some() => {
                anyhow::bail!("ipars routes requires --control-plane-url with --node-id")
            }
            None => print_json(&StaticStatus::routes())?,
        },
        Command::Token { command } => match command {
            TokenCommand::Create(args) => print_json(&create_token(args)?)?,
            TokenCommand::Revoke(args) => print_json(&revoke_token(args).await?)?,
        },
        Command::Relay {
            command: RelayCommand::Status(args),
        } => match args.relay_url.as_deref() {
            Some(relay_url) => print_json(&relay_status(relay_url).await?)?,
            None => print_json(&StaticStatus::relay())?,
        },
        Command::Path { command } => match command {
            PathCommand::Status(args) => match args.agent_url.as_deref() {
                Some(agent_url) => print_json(&path_status(agent_url).await?)?,
                None => print_json(&StaticStatus::path())?,
            },
            PathCommand::Probe(args) => {
                let agent_url = args
                    .agent_url
                    .as_deref()
                    .context("ipars path probe requires --agent-url or IPARS_AGENT_URL")?;
                print_json(&path_probe(agent_url, &args).await?)?
            }
        },
        Command::Docker {
            command: DockerCommand::Install(args),
        } => print_json(&docker_install_plan(args)?)?,
        Command::K8s {
            command: K8sCommand::Install(args),
        } => print_json(&k8s_install_plan(args)?)?,
    };
    Ok(())
}

fn init(args: InitArgs) -> anyhow::Result<InitOutput> {
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
    );
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

    vec![
        InitDaemonSpec {
            service: "control-plane",
            args: vec![
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
            ],
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
            args: vec![
                "stun".to_string(),
                "--listen".to_string(),
                args.stun_listen.to_string(),
            ],
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
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("failed to create daemon state dir {}", state_dir.display()))?;
    let log_dir = state_dir.join("logs");
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("failed to create daemon log dir {}", log_dir.display()))?;

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
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&spec.log_path)
        .with_context(|| format!("failed to open daemon log {}", spec.log_path.display()))?;
    let stdout = log.try_clone().with_context(|| {
        format!(
            "failed to clone daemon log handle {}",
            spec.log_path.display()
        )
    })?;
    ProcessCommand::new(binary)
        .args(&spec.args)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(log))
        .spawn()
        .with_context(|| {
            format!(
                "failed to spawn {} using {}",
                spec.service,
                binary.display()
            )
        })
}

async fn join(args: JoinArgs) -> anyhow::Result<JoinOutput> {
    let token: SignedJoinToken =
        serde_json::from_str(&args.token).context("join token must be JSON signed token")?;
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
        match response.json::<RegisterNodeResponse>().await {
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
    let cluster_id = args
        .cluster_id
        .map(ClusterId::from_string)
        .unwrap_or_default();
    let bootstrap_endpoints = args
        .bootstrap_endpoints
        .into_iter()
        .map(|url| BootstrapEndpoint {
            url,
            kind: BootstrapEndpointKind::ControlPlane,
        })
        .collect();
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
    ))?;
    Ok(token)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingIssuerPath {
    GenerateEphemeral,
    GenerateAndWrite,
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
    Ok(IdentityKeyPair::generate())
}

fn issuer_key_from_path(
    path: &Path,
    missing_path: MissingIssuerPath,
) -> anyhow::Result<IdentityKeyPair> {
    match std::fs::read_to_string(path) {
        Ok(value) => IdentityKeyPair::from_signing_key_b64(value.trim())
            .with_context(|| format!("failed to load issuer private key from {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => match missing_path {
            MissingIssuerPath::GenerateEphemeral => Err(error).with_context(|| {
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
    let request = RevokeTokenRequest {
        cluster_id: ClusterId::from_string(args.cluster_id),
        nonce: args.nonce,
    };
    reqwest::Client::new()
        .post(control_plane_token_revoke_url(&args.control_plane_url))
        .json(&request)
        .send()
        .await
        .context("failed to send token revoke request")?
        .error_for_status()
        .context("control plane rejected token revoke request")?
        .json::<RevokeTokenResponse>()
        .await
        .context("failed to decode token revoke response")
}

async fn agent_status(agent_url: &str) -> anyhow::Result<AgentStatusResponse> {
    get_json(agent_url, "/v1/status", "agent status").await
}

#[derive(Debug, Serialize)]
struct ControlPlaneStatus {
    metrics: ControlPlaneMetricsResponse,
    policy: ControlPlanePolicyResponse,
}

async fn control_plane_status(control_plane_url: &str) -> anyhow::Result<ControlPlaneStatus> {
    Ok(ControlPlaneStatus {
        metrics: get_json(control_plane_url, "/v1/metrics", "control-plane metrics").await?,
        policy: get_json(control_plane_url, "/v1/policy", "control-plane policy").await?,
    })
}

async fn peer_map(control_plane_url: &str, args: &PeersArgs) -> anyhow::Result<PeerMap> {
    let node_id = required_node_id(args.node_id.as_deref(), "peers")?;
    get_json(
        control_plane_url,
        &format!("/v1/peers/{node_id}"),
        "control-plane peer map",
    )
    .await
}

async fn routes(control_plane_url: &str, args: &RoutesArgs) -> anyhow::Result<RoutesOutput> {
    let node_id = required_node_id(args.node_id.as_deref(), "routes")?;
    let peer_map: PeerMap = get_json(
        control_plane_url,
        &format!("/v1/peers/{node_id}"),
        "control-plane peer map",
    )
    .await?;
    Ok(routes_output(node_id, peer_map))
}

async fn relay_status(relay_url: &str) -> anyhow::Result<RelayStatusResponse> {
    get_json(relay_url, "/v1/status", "relay status").await
}

async fn path_status(agent_url: &str) -> anyhow::Result<AgentPathsResponse> {
    get_json(agent_url, "/v1/paths", "agent path status").await
}

async fn path_probe(
    agent_url: &str,
    args: &PathProbeArgs,
) -> anyhow::Result<AgentPathProbeResponse> {
    let request = path_probe_request(args, Utc::now())?;
    post_json(agent_url, "/v1/path-probe", "agent path probe", &request).await
}

fn path_probe_request(
    args: &PathProbeArgs,
    observed_at: chrono::DateTime<Utc>,
) -> anyhow::Result<AgentPathProbeRequest> {
    Ok(AgentPathProbeRequest {
        peer: NodeId::from_string(args.peer.clone()),
        selected_state: args.state,
        selected_candidate: path_probe_candidate(args, observed_at)?,
        relay_node: args.relay_node.clone().map(NodeId::from_string),
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
    })
}

fn path_probe_candidate(
    args: &PathProbeArgs,
    observed_at: chrono::DateTime<Utc>,
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

    Ok(Some(EndpointCandidate {
        node_id: NodeId::from_string(args.peer.clone()),
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
    }))
}

async fn get_json<T>(base_url: &str, path: &str, label: &str) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let url = api_url(base_url, path);
    reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to send {label} request to {url}"))?
        .error_for_status()
        .with_context(|| format!("{label} request to {url} returned an error status"))?
        .json::<T>()
        .await
        .with_context(|| format!("failed to decode {label} response from {url}"))
}

async fn post_json<Request, Response>(
    base_url: &str,
    path: &str,
    label: &str,
    request: &Request,
) -> anyhow::Result<Response>
where
    Request: Serialize + ?Sized,
    Response: DeserializeOwned,
{
    let url = api_url(base_url, path);
    reqwest::Client::new()
        .post(&url)
        .json(request)
        .send()
        .await
        .with_context(|| format!("failed to send {label} request to {url}"))?
        .error_for_status()
        .with_context(|| format!("{label} request to {url} returned an error status"))?
        .json::<Response>()
        .await
        .with_context(|| format!("failed to decode {label} response from {url}"))
}

fn api_url(base_url: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
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

fn is_external_kubernetes_service_type(service_type: &str) -> bool {
    matches!(service_type, "NodePort" | "LoadBalancer")
}

fn parse_key_value(value: &str) -> Result<KeyValueArg, String> {
    let (key, annotation_value) = value
        .split_once('=')
        .ok_or_else(|| "annotation must use key=value syntax".to_string())?;
    if key.trim().is_empty() {
        return Err("annotation key must not be empty".to_string());
    }
    Ok(KeyValueArg {
        key: key.to_string(),
        value: annotation_value.to_string(),
    })
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
    command.push_str(&format!(
        " --set-string {key}={}",
        helm_set_string_value(value)
    ));
}

fn append_helm_ipnet_list(command: &mut String, key: &str, values: &[ipnet::IpNet]) {
    for (index, value) in values.iter().enumerate() {
        append_helm_set_string(command, &format!("{key}[{index}]"), &value.to_string());
    }
}

fn required_node_id(value: Option<&str>, command: &str) -> anyhow::Result<NodeId> {
    value
        .map(NodeId::from_string)
        .with_context(|| format!("ipars {command} requires --node-id with --control-plane-url"))
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
) -> JoinTokenClaims {
    let now = Utc::now();
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

    JoinTokenClaims {
        cluster_id,
        bootstrap_endpoints,
        expires_at: now + Duration::seconds(ttl_seconds),
        not_before: now - Duration::seconds(5),
        role: Role::from_string(role),
        tags: tag_set,
        issuer: issuer.node_id,
        key_id: issuer.key_id,
        policy,
        nonce: format!("nonce-{}", now.timestamp_nanos_opt().unwrap_or_default()),
    }
}

fn bootstrap_from_public_endpoint(args: &InitArgs) -> Vec<BootstrapEndpoint> {
    let host = args.public_endpoint.ip();
    vec![
        BootstrapEndpoint {
            url: format!(
                "{}://{host}:{}",
                args.bootstrap_scheme,
                args.control_plane_listen.port()
            ),
            kind: BootstrapEndpointKind::ControlPlane,
        },
        BootstrapEndpoint {
            url: format!(
                "{}://{host}:{}",
                args.bootstrap_scheme,
                args.signal_listen.port()
            ),
            kind: BootstrapEndpointKind::Signal,
        },
        BootstrapEndpoint {
            url: format!("udp://{}", args.public_endpoint),
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
    let base_urls = override_url
        .map(|url| vec![url.to_string()])
        .unwrap_or_else(|| {
            token
                .claims
                .bootstrap_endpoints
                .iter()
                .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
                .map(|endpoint| endpoint.url.clone())
                .collect()
        });
    if base_urls.is_empty() {
        anyhow::bail!("join token does not contain a control-plane bootstrap URL");
    }
    Ok(base_urls
        .into_iter()
        .map(|base_url| format!("{}/v1/join", base_url.trim_end_matches('/')))
        .collect())
}

fn control_plane_token_revoke_url(control_plane_url: &str) -> String {
    format!(
        "{}/v1/tokens/revoke",
        control_plane_url.trim_end_matches('/')
    )
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
    let compose_prefix = format!(
        "docker compose -p {} -f {}",
        args.project_name, compose_file
    );
    let environment = docker_install_environment(&args);
    let mut prerequisites = vec![
        "Docker Engine with the Compose plugin".to_string(),
        "/dev/net/tun available on agent/relay hosts".to_string(),
        "CAP_NET_ADMIN and CAP_NET_RAW for host dataplane mutation".to_string(),
        "A reusable issuer private key for init/token create workflows".to_string(),
    ];
    if args.rootless {
        prerequisites.push(
            "Rootless Docker Engine with a reachable user Docker socket for network discovery"
                .to_string(),
        );
    }
    if args.docker_discover_networks {
        prerequisites
            .push("Docker API access from the agent for bridge-network IPAM discovery".to_string());
    }
    let mut notes = vec![
        "The agent service runs with host networking so it can manage WireGuard and Docker bridge routes".to_string(),
        "Use --docker-discover-networks with repeated --docker-network values for multi-network Compose deployments".to_string(),
    ];
    if args.rootless {
        notes.push("Rootless Docker network discovery can use the user socket, but full rootless dataplane mutation still needs a userspace WireGuard backend".to_string());
    } else {
        notes.push("Rootless Docker discovery is supported, but full rootless dataplane mutation still needs a userspace WireGuard backend".to_string());
    }

    Ok(InstallPlan {
        platform: "docker-compose".to_string(),
        manifest: compose_file,
        commands: vec![
            format!("{compose_prefix} config"),
            format!("{compose_prefix} up -d --build"),
        ],
        environment,
        prerequisites,
        security: vec![
            "The bundled Compose file uses plain HTTP on a private development network".to_string(),
            "Expose control-plane, signal, relay, or agent APIs through an external TLS proxy before using public networks".to_string(),
            "Relay use still requires signed join-token policy permission".to_string(),
        ],
        notes,
    })
}

fn validate_docker_install_args(args: &DockerInstallArgs) -> anyhow::Result<()> {
    if !args.docker_discover_networks && !args.docker_networks.is_empty() {
        anyhow::bail!("--docker-network requires --docker-discover-networks");
    }
    if args.docker_discover_networks && !args.docker_container_cidrs.is_empty() {
        anyhow::bail!(
            "--docker-discover-networks cannot be combined with explicit --docker-container-cidr values"
        );
    }
    for filter in &args.docker_networks {
        validate_docker_network_filter(filter)?;
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

fn docker_install_environment(args: &DockerInstallArgs) -> Vec<InstallEnvironment> {
    let mut environment = vec![InstallEnvironment {
        name: "IPARS_AGENT_APPLY_DOCKER_ROUTES".to_string(),
        value: "true".to_string(),
    }];
    if args.docker_discover_networks {
        environment.push(InstallEnvironment {
            name: "IPARS_DOCKER_DISCOVER_NETWORKS".to_string(),
            value: "true".to_string(),
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
            name: "IPARS_DOCKER_API_SOCKET".to_string(),
            value: socket.display().to_string(),
        });
    } else if args.rootless {
        environment.push(InstallEnvironment {
            name: "IPARS_DOCKER_API_SOCKET".to_string(),
            value: "${XDG_RUNTIME_DIR}/docker.sock".to_string(),
        });
    }
    if let Some(namespace) = args.docker_container_namespace.as_ref() {
        environment.push(InstallEnvironment {
            name: "IPARS_DOCKER_CONTAINER_NAMESPACE".to_string(),
            value: namespace.clone(),
        });
    }
    environment.push(InstallEnvironment {
        name: "IPARS_DOCKER_HOST_INTERFACE".to_string(),
        value: args.docker_host_interface.clone(),
    });
    if !args.docker_container_cidrs.is_empty() {
        environment.push(InstallEnvironment {
            name: "IPARS_DOCKER_CONTAINER_CIDRS".to_string(),
            value: args
                .docker_container_cidrs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        });
    }
    environment
}

fn k8s_install_plan(args: K8sInstallArgs) -> anyhow::Result<InstallPlan> {
    validate_k8s_service_exposure(&args)?;
    validate_k8s_route_discovery(&args)?;
    let chart = args.chart.display().to_string();
    let mut helm_command = format!(
        "helm upgrade --install {} {} --namespace {} --set agent.joinTokenSecretName={} --set agent.joinTokenSecretKey={}",
        args.release, chart, args.namespace, args.join_token_secret, args.join_token_key
    );
    append_k8s_route_discovery_values(&mut helm_command, &args);
    if args.expose_agent_api {
        helm_command.push_str(" --set agent.apiService.enabled=true");
        helm_command.push_str(&format!(
            " --set agent.apiService.type={}",
            args.agent_api_service_type
        ));
        if is_external_kubernetes_service_type(&args.agent_api_service_type) {
            helm_command.push_str(" --set agent.apiService.exposureAcknowledged=true");
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
        if is_external_kubernetes_service_type(&args.relay_service_type) {
            helm_command.push_str(" --set agent.relayService.exposureAcknowledged=true");
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
                "kubectl -n {} create secret generic {} --from-file={}=./join.token --dry-run=client -o yaml | kubectl apply -f -",
                args.namespace, args.join_token_secret, args.join_token_key
            ),
            helm_command,
        ],
        environment: Vec::new(),
        prerequisites: vec![
            "kubectl access with permission to create namespaces, Secrets, RBAC, and DaemonSets".to_string(),
            "Helm 3".to_string(),
            "/dev/net/tun available on every scheduled node".to_string(),
            "NET_ADMIN and NET_RAW capability allowance for the DaemonSet agent".to_string(),
        ],
        security: vec![
            "Store the signed join token in the configured Secret; do not bake it into an image".to_string(),
            "Agent API and relay Services are disabled by default and must be explicitly enabled".to_string(),
            "NodePort or LoadBalancer exposure requires --allow-public-service-exposure and sets chart exposure acknowledgement".to_string(),
            "LoadBalancer exposure requires source CIDR ranges unless --allow-unrestricted-load-balancer is set".to_string(),
            "externalTrafficPolicy=Cluster requires --allow-cluster-external-traffic-policy because source addresses may be hidden by cross-node forwarding".to_string(),
            "Relay advertisement remains ineffective unless the join token allows relay".to_string(),
        ],
        notes: vec![
            "This chart installs a node-underlay VPN agent, not a Kubernetes CNI".to_string(),
            "Use --expose-agent-api and --expose-relay only for nodes that should publish those endpoints".to_string(),
            "Service type, source range, traffic policy, and annotation flags map directly to the chart's agent.apiService and agent.relayService values".to_string(),
            "Relay exposure requires the public relay UDP endpoint and HTTP admission URL that peers should use".to_string(),
        ],
    })
}

fn append_k8s_route_discovery_values(command: &mut String, args: &K8sInstallArgs) {
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
        append_helm_set_string(
            command,
            "serviceExposure.routeProviderNodeId",
            route_provider,
        );
    }
}

fn validate_k8s_route_discovery(args: &K8sInstallArgs) -> anyhow::Result<()> {
    for namespace in &args.kubernetes_namespaces {
        validate_kubernetes_namespace(namespace)?;
    }
    if let Some(selector) = args.kubernetes_service_label_selector.as_deref() {
        validate_kubernetes_label_selector(selector)?;
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
    if args.kubernetes_route_interval_seconds == 0 {
        anyhow::bail!("--kubernetes-route-interval-seconds must be greater than zero");
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

fn validate_k8s_service_exposure(args: &K8sInstallArgs) -> anyhow::Result<()> {
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
    if !args.agent_api_allow_source_cidrs.is_empty()
        && args.agent_api_service_type != "LoadBalancer"
    {
        anyhow::bail!("--agent-api-allow-source-cidr only applies to LoadBalancer services");
    }
    if !args.relay_allow_source_cidrs.is_empty() && args.relay_service_type != "LoadBalancer" {
        anyhow::bail!("--relay-allow-source-cidr only applies to LoadBalancer services");
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
    Ok(())
}

#[derive(Debug, Serialize)]
struct StaticStatus<'a> {
    subsystem: &'a str,
    status: &'a str,
    detail: &'a str,
}

impl StaticStatus<'static> {
    fn status() -> Self {
        Self {
            subsystem: "agent",
            status: "not_connected",
            detail: "daemon RPC wiring is the next implementation milestone",
        }
    }

    fn peers() -> Self {
        Self {
            subsystem: "peer_map",
            status: "empty",
            detail: "peer map is supplied by the control plane after join",
        }
    }

    fn routes() -> Self {
        Self {
            subsystem: "routes",
            status: "empty",
            detail: "routes are installed by the route-manager daemon",
        }
    }

    fn relay() -> Self {
        Self {
            subsystem: "relay",
            status: "not_running",
            detail: "relay daemon wiring is the next implementation milestone",
        }
    }

    fn path() -> Self {
        Self {
            subsystem: "path_state",
            status: "empty",
            detail: "path state is created lazily on first flow or pinned peer",
        }
    }
}

#[cfg(test)]
mod tests {
    use ipars_crypto::verify_join_token;

    use super::*;

    fn token_with_bootstrap(endpoints: Vec<BootstrapEndpoint>) -> SignedJoinToken {
        SignedJoinToken {
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
            ),
            signature: "signature".to_string(),
        }
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
        ]);

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
        ]);

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
        let token = token_with_bootstrap(Vec::new());

        assert_eq!(
            control_plane_join_url(&token, Some("http://127.0.0.1:8443"))?,
            "http://127.0.0.1:8443/v1/join"
        );
        Ok(())
    }

    #[test]
    fn join_url_requires_control_plane_endpoint() {
        let token = token_with_bootstrap(Vec::new());
        let result = control_plane_join_url(&token, None);

        assert!(result.is_err());
    }

    #[test]
    fn token_revoke_url_trims_control_plane_base_url() {
        assert_eq!(
            control_plane_token_revoke_url("http://127.0.0.1:8443/"),
            "http://127.0.0.1:8443/v1/tokens/revoke"
        );
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
        ])?;
        if let Command::Token {
            command: TokenCommand::Create(args),
        } = token.command
        {
            assert_eq!(args.allowed_routes, vec!["10.42.0.0/16".parse()?]);
            assert_eq!(args.max_uses, Some(7));
            assert!(!args.unlimited_uses);
            return Ok(());
        }

        anyhow::bail!("expected token create command")
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
            signal_listen: SocketAddr::from(([0, 0, 0, 0], 9443)),
            stun_listen: SocketAddr::from(([0, 0, 0, 0], 3478)),
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
    fn init_outputs_daemon_commands_for_bootstrap_services() -> anyhow::Result<()> {
        let key_path = temp_path("issuer-bootstrap.key");
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
            signal_listen: "127.0.0.1:19443".parse()?,
            stun_listen: "0.0.0.0:13478".parse()?,
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
        Ok(())
    }

    #[test]
    fn api_url_trims_base_and_path_slashes() {
        assert_eq!(
            api_url("http://127.0.0.1:9780/", "/v1/status"),
            "http://127.0.0.1:9780/v1/status"
        );
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
            return Ok(());
        }

        anyhow::bail!("expected path status command")
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
            "--relay-node",
            "relay-a",
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
        assert_eq!(request.relay_node, Some(NodeId::from_string("relay-a")));
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
            assert_eq!(
                args.control_plane_url.as_deref(),
                Some("http://127.0.0.1:8443")
            );
            assert_eq!(args.node_id.as_deref(), Some("node-a"));
        } else {
            anyhow::bail!("expected peers command");
        }

        let routes = Cli::try_parse_from([
            "ipars",
            "routes",
            "--control-plane-url",
            "http://127.0.0.1:8443",
            "--node-id",
            "node-a",
        ])?;
        if let Command::Routes(args) = routes.command {
            assert_eq!(
                args.control_plane_url.as_deref(),
                Some("http://127.0.0.1:8443")
            );
            assert_eq!(args.node_id.as_deref(), Some("node-a"));
        } else {
            anyhow::bail!("expected routes command");
        }

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
        assert!(plan.environment.iter().any(|environment| {
            environment.name == "IPARS_AGENT_APPLY_DOCKER_ROUTES" && environment.value == "true"
        }));
        assert!(plan
            .security
            .iter()
            .any(|requirement| requirement.contains("plain HTTP")));
        Ok(())
    }

    #[test]
    fn docker_install_plan_exports_rootless_multi_network_settings() -> anyhow::Result<()> {
        let plan = docker_install_plan(DockerInstallArgs {
            compose_file: PathBuf::from("ops/compose.yaml"),
            project_name: "edge".to_string(),
            rootless: true,
            docker_discover_networks: true,
            docker_networks: vec!["edge_default".to_string(), "edge_apps".to_string()],
            docker_api_socket: None,
            docker_container_namespace: Some("compose-edge".to_string()),
            docker_host_interface: "br-edge".to_string(),
            docker_container_cidrs: Vec::new(),
        })?;

        assert!(plan
            .prerequisites
            .iter()
            .any(|requirement| requirement.contains("Rootless Docker Engine")));
        assert!(plan
            .prerequisites
            .iter()
            .any(|requirement| requirement.contains("Docker API access")));
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_DISCOVER_NETWORKS"),
            Some("true")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_NETWORKS"),
            Some("edge_default,edge_apps")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_API_SOCKET"),
            Some("${XDG_RUNTIME_DIR}/docker.sock")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_CONTAINER_NAMESPACE"),
            Some("compose-edge")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_HOST_INTERFACE"),
            Some("br-edge")
        );
        assert_eq!(
            environment_value(&plan, "IPARS_DOCKER_CONTAINER_CIDRS"),
            None
        );
        assert!(plan
            .notes
            .iter()
            .any(|note| note.contains("userspace WireGuard backend")));
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
        }) {
            Ok(_) => anyhow::bail!("invalid Docker network filter should be rejected"),
            Err(error) => error,
        };
        assert!(invalid_filter
            .to_string()
            .contains("must contain only ASCII letters"));
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
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            expose_agent_api: true,
            allow_public_service_exposure: true,
            allow_unrestricted_load_balancer: false,
            allow_cluster_external_traffic_policy: false,
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_allow_source_cidrs: vec!["198.51.100.0/24".parse()?],
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: vec![KeyValueArg {
                key: "service.beta.kubernetes.io/aws-load-balancer-type".to_string(),
                value: "nlb,ip".to_string(),
            }],
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_allow_source_cidrs: vec!["203.0.113.0/24".parse()?],
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: vec![KeyValueArg {
                key: "metallb.universe.tf/address-pool".to_string(),
                value: "public".to_string(),
            }],
            relay_public_endpoint: Some("203.0.113.10:51820".to_string()),
            relay_admission_url: Some("http://203.0.113.10:9580".to_string()),
            relay_status_url: Some("http://203.0.113.10:9580".to_string()),
        })?;

        assert_eq!(plan.platform, "kubernetes-helm");
        assert_eq!(plan.manifest, "charts/ipars");
        assert_eq!(
            plan.commands[1],
            "kubectl -n edge-system create secret generic edge-token --from-file=signed-token=./join.token --dry-run=client -o yaml | kubectl apply -f -"
        );
        assert!(plan.commands[2].contains("helm upgrade --install edge"));
        assert!(plan.commands[2].contains("--set serviceExposure.discoverApiServer=true"));
        assert!(plan.commands[2].contains("--set serviceExposure.routeIntervalSeconds=60"));
        assert!(plan.commands[2].contains("--set agent.apiService.enabled=true"));
        assert!(plan.commands[2].contains("--set agent.apiService.type=LoadBalancer"));
        assert!(plan.commands[2].contains("--set agent.apiService.exposureAcknowledged=true"));
        assert!(plan.commands[2].contains("--set agent.apiService.externalTrafficPolicy=Local"));
        assert!(plan.commands[2]
            .contains("--set-string agent.apiService.loadBalancerSourceRanges[0]=198.51.100.0/24"));
        assert!(plan.commands[2].contains(
            "--set-string agent.apiService.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-type=nlb\\,ip"
        ));
        assert!(plan.commands[2].contains("--set agent.relayService.enabled=true"));
        assert!(plan.commands[2].contains("--set agent.relayService.type=LoadBalancer"));
        assert!(plan.commands[2].contains("--set agent.relayService.exposureAcknowledged=true"));
        assert!(plan.commands[2].contains("--set agent.relayService.externalTrafficPolicy=Local"));
        assert!(plan.commands[2].contains(
            "--set-string agent.relayService.loadBalancerSourceRanges[0]=203.0.113.0/24"
        ));
        assert!(plan.commands[2]
            .contains("--set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820"));
        assert!(plan.commands[2].contains(
            "--set-string agent.relayAdvertisement.admissionUrl=http://203.0.113.10:9580"
        ));
        assert!(plan.commands[2]
            .contains("--set-string agent.relayAdvertisement.statusUrl=http://203.0.113.10:9580"));
        assert!(plan.commands[2].contains(
            "--set-string agent.relayService.annotations.metallb\\.universe\\.tf/address-pool=public"
        ));
        assert!(plan
            .security
            .iter()
            .any(|requirement| requirement.contains("disabled by default")));
        Ok(())
    }

    fn base_k8s_install_args() -> K8sInstallArgs {
        K8sInstallArgs {
            release: "edge".to_string(),
            namespace: "edge-system".to_string(),
            chart: PathBuf::from("charts/ipars"),
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            expose_agent_api: false,
            allow_public_service_exposure: false,
            allow_unrestricted_load_balancer: false,
            allow_cluster_external_traffic_policy: false,
            agent_api_service_type: "ClusterIP".to_string(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: false,
            relay_service_type: "LoadBalancer".to_string(),
            relay_allow_source_cidrs: Vec::new(),
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: Vec::new(),
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
        }
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

        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];

        assert!(helm.contains("--set serviceExposure.discoverServices=true"));
        assert!(helm.contains("--set serviceExposure.discoverApiServer=false"));
        assert!(helm.contains("--set serviceExposure.routeIntervalSeconds=15"));
        assert!(helm.contains("--set-string serviceExposure.apiServerCidrs[0]=10.0.0.1/32"));
        assert!(helm.contains("--set-string serviceExposure.serviceCidrs[0]=10.96.0.0/12"));
        assert!(helm.contains("--set-string serviceExposure.namespaces[0]=default"));
        assert!(helm.contains("--set-string serviceExposure.namespaces[1]=platform"));
        assert!(
            helm.contains("--set-string serviceExposure.serviceLabelSelector=ipars.io/expose=true")
        );
        assert!(helm.contains("--set-string serviceExposure.routeProviderNodeId=route-provider-a"));
        Ok(())
    }

    #[test]
    fn k8s_install_plan_rejects_invalid_route_discovery_settings() {
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
            "--join-token-secret",
            "edge-token",
            "--join-token-key",
            "signed-token",
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
            "--allow-public-service-exposure",
            "--allow-unrestricted-load-balancer",
            "--allow-cluster-external-traffic-policy",
            "--expose-agent-api",
            "--agent-api-service-type",
            "LoadBalancer",
            "--agent-api-allow-source-cidr",
            "198.51.100.0/24",
            "--agent-api-external-traffic-policy",
            "Cluster",
            "--agent-api-service-annotation",
            "service.beta.kubernetes.io/aws-load-balancer-type=nlb",
            "--expose-relay",
            "--relay-service-type",
            "LoadBalancer",
            "--relay-allow-source-cidr",
            "203.0.113.0/24",
            "--relay-external-traffic-policy",
            "Local",
            "--relay-service-annotation",
            "metallb.universe.tf/address-pool=public",
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
            assert_eq!(args.join_token_secret, "edge-token");
            assert_eq!(args.join_token_key, "signed-token");
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
            assert!(args.allow_public_service_exposure);
            assert!(args.allow_unrestricted_load_balancer);
            assert!(args.allow_cluster_external_traffic_policy);
            assert!(args.expose_agent_api);
            assert_eq!(args.agent_api_service_type, "LoadBalancer");
            assert_eq!(
                args.agent_api_allow_source_cidrs,
                vec!["198.51.100.0/24".parse::<ipnet::IpNet>()?]
            );
            assert_eq!(args.agent_api_external_traffic_policy, "Cluster");
            assert_eq!(
                args.agent_api_service_annotations,
                vec![KeyValueArg {
                    key: "service.beta.kubernetes.io/aws-load-balancer-type".to_string(),
                    value: "nlb".to_string(),
                }]
            );
            assert!(args.expose_relay);
            assert_eq!(args.relay_service_type, "LoadBalancer");
            assert_eq!(
                args.relay_allow_source_cidrs,
                vec!["203.0.113.0/24".parse::<ipnet::IpNet>()?]
            );
            assert_eq!(args.relay_external_traffic_policy, "Local");
            assert_eq!(
                args.relay_service_annotations,
                vec![KeyValueArg {
                    key: "metallb.universe.tf/address-pool".to_string(),
                    value: "public".to_string(),
                }]
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
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            expose_agent_api: false,
            allow_public_service_exposure: true,
            allow_unrestricted_load_balancer: true,
            allow_cluster_external_traffic_policy: false,
            agent_api_service_type: "ClusterIP".to_string(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_allow_source_cidrs: Vec::new(),
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: Vec::new(),
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
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
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            expose_agent_api: true,
            allow_public_service_exposure: false,
            allow_unrestricted_load_balancer: false,
            allow_cluster_external_traffic_policy: false,
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: false,
            relay_service_type: "LoadBalancer".to_string(),
            relay_allow_source_cidrs: Vec::new(),
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: Vec::new(),
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
        });
        assert!(plan.is_err());
    }

    #[test]
    fn k8s_install_requires_acknowledgement_for_cluster_external_traffic_policy(
    ) -> anyhow::Result<()> {
        let without_ack = k8s_install_plan(K8sInstallArgs {
            release: "edge".to_string(),
            namespace: "edge-system".to_string(),
            chart: PathBuf::from("charts/ipars"),
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            expose_agent_api: true,
            allow_public_service_exposure: true,
            allow_unrestricted_load_balancer: false,
            allow_cluster_external_traffic_policy: false,
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_allow_source_cidrs: vec!["198.51.100.0/24".parse()?],
            agent_api_external_traffic_policy: "Cluster".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_allow_source_cidrs: vec!["203.0.113.0/24".parse()?],
            relay_external_traffic_policy: "Cluster".to_string(),
            relay_service_annotations: Vec::new(),
            relay_public_endpoint: Some("203.0.113.10:51820".to_string()),
            relay_admission_url: Some("http://203.0.113.10:9580".to_string()),
            relay_status_url: None,
        });
        assert!(without_ack.is_err());

        let acknowledged = k8s_install_plan(K8sInstallArgs {
            release: "edge".to_string(),
            namespace: "edge-system".to_string(),
            chart: PathBuf::from("charts/ipars"),
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            expose_agent_api: true,
            allow_public_service_exposure: true,
            allow_unrestricted_load_balancer: false,
            allow_cluster_external_traffic_policy: true,
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_allow_source_cidrs: vec!["198.51.100.0/24".parse()?],
            agent_api_external_traffic_policy: "Cluster".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_allow_source_cidrs: vec!["203.0.113.0/24".parse()?],
            relay_external_traffic_policy: "Cluster".to_string(),
            relay_service_annotations: Vec::new(),
            relay_public_endpoint: Some("203.0.113.10:51820".to_string()),
            relay_admission_url: Some("http://203.0.113.10:9580".to_string()),
            relay_status_url: None,
        })?;
        assert!(acknowledged.commands[2]
            .contains("--set agent.apiService.allowClusterExternalTrafficPolicy=true"));
        assert!(acknowledged.commands[2]
            .contains("--set agent.relayService.allowClusterExternalTrafficPolicy=true"));
        Ok(())
    }

    #[test]
    fn k8s_install_rejects_source_ranges_without_load_balancer() -> anyhow::Result<()> {
        let plan = k8s_install_plan(K8sInstallArgs {
            release: "edge".to_string(),
            namespace: "edge-system".to_string(),
            chart: PathBuf::from("charts/ipars"),
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            expose_agent_api: true,
            allow_public_service_exposure: false,
            allow_unrestricted_load_balancer: false,
            allow_cluster_external_traffic_policy: false,
            agent_api_service_type: "ClusterIP".to_string(),
            agent_api_allow_source_cidrs: vec!["198.51.100.0/24".parse()?],
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: false,
            relay_service_type: "LoadBalancer".to_string(),
            relay_allow_source_cidrs: Vec::new(),
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: Vec::new(),
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
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
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            expose_agent_api: true,
            allow_public_service_exposure: true,
            allow_unrestricted_load_balancer: false,
            allow_cluster_external_traffic_policy: false,
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: false,
            relay_service_type: "LoadBalancer".to_string(),
            relay_allow_source_cidrs: Vec::new(),
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: Vec::new(),
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
        });
        assert!(without_ranges.is_err());

        let unrestricted = k8s_install_plan(K8sInstallArgs {
            release: "edge".to_string(),
            namespace: "edge-system".to_string(),
            chart: PathBuf::from("charts/ipars"),
            join_token_secret: "edge-token".to_string(),
            join_token_key: "signed-token".to_string(),
            kubernetes_discover_services: false,
            kubernetes_discover_api_server: true,
            kubernetes_api_server_cidrs: Vec::new(),
            kubernetes_service_cidrs: Vec::new(),
            kubernetes_namespaces: Vec::new(),
            kubernetes_service_label_selector: None,
            kubernetes_route_provider: None,
            kubernetes_route_interval_seconds: 60,
            expose_agent_api: true,
            allow_public_service_exposure: true,
            allow_unrestricted_load_balancer: true,
            allow_cluster_external_traffic_policy: false,
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_allow_source_cidrs: Vec::new(),
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: Vec::new(),
            relay_public_endpoint: Some("203.0.113.10:51820".to_string()),
            relay_admission_url: Some("http://203.0.113.10:9580".to_string()),
            relay_status_url: None,
        })?;
        assert!(unrestricted.commands[2]
            .contains("--set agent.apiService.allowUnrestrictedLoadBalancer=true"));
        assert!(unrestricted.commands[2]
            .contains("--set agent.relayService.allowUnrestrictedLoadBalancer=true"));
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
            parse_key_value("service.beta.kubernetes.io/aws-load-balancer-type=nlb"),
            Ok(KeyValueArg {
                key: "service.beta.kubernetes.io/aws-load-balancer-type".to_string(),
                value: "nlb".to_string(),
            })
        );
        assert!(parse_key_value("missing-equals").is_err());
        assert_eq!(
            helm_set_key("service.beta.kubernetes.io/aws-load-balancer-type"),
            "service\\.beta\\.kubernetes\\.io/aws-load-balancer-type"
        );
        assert_eq!(helm_set_string_value("nlb,ip"), "nlb\\,ip");
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ipars-cli-{name}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ))
    }
}
