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
    Init(Box<InitArgs>),
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
    Install(Box<K8sInstallArgs>),
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
    #[arg(long = "enable-network-policy", default_value_t = false)]
    enable_network_policy: bool,
    #[arg(
        long = "network-policy-acknowledge-host-network",
        default_value_t = false,
        requires = "enable_network_policy"
    )]
    network_policy_acknowledge_host_network: bool,
    #[arg(long = "agent-pod-label", value_parser = parse_kubernetes_label_pair)]
    agent_pod_labels: Vec<KeyValueArg>,
    #[arg(long = "agent-pod-annotation", value_parser = parse_key_value)]
    agent_pod_annotations: Vec<KeyValueArg>,
    #[arg(long = "agent-priority-class", value_parser = parse_kubernetes_priority_class_name)]
    agent_priority_class: Option<String>,
    #[arg(long = "agent-node-selector", value_parser = parse_kubernetes_label_pair)]
    agent_node_selectors: Vec<KeyValueArg>,
    #[arg(long = "agent-toleration", value_parser = parse_kubernetes_toleration_arg)]
    agent_tolerations: Vec<KubernetesTolerationArg>,
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
    #[arg(long, default_value = "ClusterIP", value_parser = parse_kubernetes_service_type)]
    agent_api_service_type: String,
    #[arg(long = "agent-api-node-port", value_parser = parse_kubernetes_node_port, requires = "expose_agent_api")]
    agent_api_node_port: Option<u16>,
    #[arg(long = "agent-api-load-balancer-class", value_parser = parse_kubernetes_load_balancer_class, requires = "expose_agent_api")]
    agent_api_load_balancer_class: Option<String>,
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
    #[arg(long = "relay-udp-node-port", value_parser = parse_kubernetes_node_port, requires = "expose_relay")]
    relay_udp_node_port: Option<u16>,
    #[arg(long = "relay-http-node-port", value_parser = parse_kubernetes_node_port, requires = "expose_relay")]
    relay_http_node_port: Option<u16>,
    #[arg(long = "relay-load-balancer-class", value_parser = parse_kubernetes_load_balancer_class, requires = "expose_relay")]
    relay_load_balancer_class: Option<String>,
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
    #[arg(long = "relay-session-affinity", value_parser = parse_kubernetes_session_affinity, requires = "expose_relay")]
    relay_session_affinity: Option<String>,
    #[arg(long = "relay-session-affinity-timeout-seconds", value_parser = parse_kubernetes_session_affinity_timeout_seconds, requires = "expose_relay")]
    relay_session_affinity_timeout_seconds: Option<u32>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct KubernetesTolerationArg {
    key: Option<String>,
    operator: Option<String>,
    value: Option<String>,
    effect: Option<String>,
    toleration_seconds: Option<u64>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init(args) => print_json(&init(*args)?)?,
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
        } => print_json(&k8s_install_plan(*args)?)?,
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

fn parse_kubernetes_internal_traffic_policy(value: &str) -> Result<String, String> {
    match value {
        "Cluster" | "Local" => Ok(value.to_string()),
        _ => Err(format!(
            "internal traffic policy must be Cluster or Local; got {value}"
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

const KUBERNETES_NODE_PORT_MIN: u16 = 30000;
const KUBERNETES_NODE_PORT_MAX: u16 = 32767;

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

fn parse_kubernetes_priority_class_name(value: &str) -> Result<String, String> {
    validate_kubernetes_dns_subdomain(value, "priorityClassName")?;
    Ok(value.to_string())
}

fn parse_kubernetes_resource_quantity(value: &str) -> Result<String, String> {
    validate_kubernetes_resource_quantity(value, "resource quantity")?;
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

fn validate_kubernetes_annotation_value(value: &str) -> Result<(), String> {
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
        shell_word(&args.project_name),
        shell_word(&compose_file)
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
    validate_linux_interface_name(&args.docker_host_interface)?;
    if let Some(namespace) = args.docker_container_namespace.as_deref() {
        validate_linux_namespace_name(namespace)?;
    }
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

fn validate_linux_interface_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("linux interface name cannot be empty");
    }
    if name.len() > 15 {
        anyhow::bail!("linux interface name `{name}` exceeds 15 bytes");
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
    validate_k8s_install_metadata(&args)?;
    validate_k8s_agent_pod_options(&args)?;
    validate_k8s_agent_rollout_options(&args)?;
    validate_k8s_service_exposure(&args)?;
    validate_k8s_network_policy(&args)?;
    validate_k8s_route_discovery(&args)?;
    let chart = args.chart.display().to_string();
    let mut helm_command = format!(
        "helm upgrade --install {} {} --namespace {} --set agent.joinTokenSecretName={} --set agent.joinTokenSecretKey={}",
        args.release,
        shell_word(&chart),
        args.namespace,
        args.join_token_secret,
        args.join_token_key
    );
    append_k8s_route_discovery_values(&mut helm_command, &args);
    append_k8s_agent_pod_values(&mut helm_command, &args);
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
    if args.expose_agent_api {
        helm_command.push_str(" --set agent.apiService.enabled=true");
        helm_command.push_str(&format!(
            " --set agent.apiService.type={}",
            args.agent_api_service_type
        ));
        if let Some(node_port) = args.agent_api_node_port {
            helm_command.push_str(&format!(" --set agent.apiService.nodePort={node_port}"));
        }
        if let Some(load_balancer_class) = args.agent_api_load_balancer_class.as_deref() {
            append_helm_set_string(
                &mut helm_command,
                "agent.apiService.loadBalancerClass",
                load_balancer_class,
            );
        }
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
        if let Some(load_balancer_class) = args.relay_load_balancer_class.as_deref() {
            append_helm_set_string(
                &mut helm_command,
                "agent.relayService.loadBalancerClass",
                load_balancer_class,
            );
        }
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
            "A Kubernetes network plugin that enforces NetworkPolicy when --enable-network-policy is used".to_string(),
        ],
        security: vec![
            "Store the signed join token in the configured Secret; do not bake it into an image".to_string(),
            "Agent API and relay Services are disabled by default and must be explicitly enabled".to_string(),
            "NodePort or LoadBalancer exposure requires --allow-public-service-exposure and sets chart exposure acknowledgement".to_string(),
            "LoadBalancer exposure requires source CIDR ranges unless --allow-unrestricted-load-balancer is set".to_string(),
            "externalTrafficPolicy=Cluster requires --allow-cluster-external-traffic-policy because source addresses may be hidden by cross-node forwarding".to_string(),
            "NetworkPolicy allowlists are opt-in and require explicit hostNetwork limitation acknowledgement because enforcement is CNI-dependent for host-networked pods".to_string(),
            "Relay advertisement remains ineffective unless the join token allows relay".to_string(),
        ],
        notes: vec![
            "This chart installs a node-underlay VPN agent, not a Kubernetes CNI".to_string(),
            "Use --expose-agent-api and --expose-relay only for nodes that should publish those endpoints".to_string(),
            "Agent pod labels, annotations, priority class, node selectors, tolerations, termination grace period, resource requests/limits, and DaemonSet rollout settings map directly to chart values".to_string(),
            "Service type, NodePort, LoadBalancer class, LoadBalancer node-port allocation, source range, traffic policy, and annotation flags map directly to the chart's agent.apiService and agent.relayService values".to_string(),
            "NetworkPolicy CIDR allowlists select the agent pods and restrict ingress to the configured agent API and relay ports; source IP visibility still depends on Service traffic policy and the cluster network plugin".to_string(),
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

fn append_k8s_agent_pod_values(command: &mut String, args: &K8sInstallArgs) {
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
    for selector in &args.agent_node_selectors {
        append_helm_set_string(
            command,
            &format!("agent.nodeSelector.{}", helm_set_key(&selector.key)),
            &selector.value,
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
    if let Some(seconds) = args.agent_termination_grace_period_seconds {
        command.push_str(&format!(
            " --set agent.terminationGracePeriodSeconds={seconds}"
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

fn validate_k8s_install_metadata(args: &K8sInstallArgs) -> anyhow::Result<()> {
    validate_helm_release_name(&args.release).map_err(anyhow::Error::msg)?;
    validate_kubernetes_namespace(&args.namespace)?;
    validate_kubernetes_dns_subdomain(&args.join_token_secret, "join token Secret name")
        .map_err(anyhow::Error::msg)?;
    validate_kubernetes_secret_key(&args.join_token_key).map_err(anyhow::Error::msg)?;
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
    if key.is_empty() {
        return Err("join token Secret key must not be empty".to_string());
    }
    if key.len() > 253 {
        return Err("join token Secret key exceeds 253 bytes".to_string());
    }
    let valid = key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid {
        return Err(
            "join token Secret key must contain only ASCII letters, digits, '-', '_' or '.'"
                .to_string(),
        );
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

fn validate_k8s_agent_pod_options(args: &K8sInstallArgs) -> anyhow::Result<()> {
    for label in &args.agent_pod_labels {
        validate_kubernetes_label_key(&label.key).map_err(anyhow::Error::msg)?;
        validate_kubernetes_label_value(&label.value).map_err(anyhow::Error::msg)?;
    }
    for annotation in &args.agent_pod_annotations {
        validate_kubernetes_annotation_key(&annotation.key).map_err(anyhow::Error::msg)?;
        validate_kubernetes_annotation_value(&annotation.value).map_err(anyhow::Error::msg)?;
    }
    if let Some(priority_class) = args.agent_priority_class.as_deref() {
        validate_kubernetes_dns_subdomain(priority_class, "agent priority class")
            .map_err(anyhow::Error::msg)?;
    }
    for selector in &args.agent_node_selectors {
        validate_kubernetes_label_key(&selector.key).map_err(anyhow::Error::msg)?;
        validate_kubernetes_label_value(&selector.value).map_err(anyhow::Error::msg)?;
    }
    for toleration in &args.agent_tolerations {
        validate_kubernetes_toleration_arg(toleration).map_err(anyhow::Error::msg)?;
    }
    if let Some(seconds) = args.agent_termination_grace_period_seconds {
        if seconds > KUBERNETES_INT64_MAX {
            anyhow::bail!("--agent-termination-grace-period-seconds must be a non-negative int64");
        }
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
            .map_or(true, kubernetes_int_or_percent_is_zero)
    {
        anyhow::bail!(
            "--agent-rollout-max-unavailable cannot be zero when --agent-rollout-max-surge is zero or unset"
        );
    }
    Ok(())
}

fn validate_k8s_network_policy(args: &K8sInstallArgs) -> anyhow::Result<()> {
    if args.network_policy_acknowledge_host_network && !args.enable_network_policy {
        anyhow::bail!("--network-policy-acknowledge-host-network requires --enable-network-policy");
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
    if args.enable_network_policy && !args.network_policy_acknowledge_host_network {
        anyhow::bail!(
            "--enable-network-policy requires --network-policy-acknowledge-host-network because the chart runs agents with hostNetwork=true and NetworkPolicy enforcement is CNI-dependent"
        );
    }
    Ok(())
}

fn validate_k8s_service_exposure(args: &K8sInstallArgs) -> anyhow::Result<()> {
    if args.agent_api_node_port.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-node-port requires --expose-agent-api");
    }
    if args.agent_api_load_balancer_class.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-load-balancer-class requires --expose-agent-api");
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
    if args.agent_api_session_affinity.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-session-affinity requires --expose-agent-api");
    }
    if args.agent_api_session_affinity_timeout_seconds.is_some() && !args.expose_agent_api {
        anyhow::bail!("--agent-api-session-affinity-timeout-seconds requires --expose-agent-api");
    }
    if args.relay_udp_node_port.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-udp-node-port requires --expose-relay");
    }
    if args.relay_http_node_port.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-http-node-port requires --expose-relay");
    }
    if args.relay_load_balancer_class.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-load-balancer-class requires --expose-relay");
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
    if args.relay_session_affinity.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-session-affinity requires --expose-relay");
    }
    if args.relay_session_affinity_timeout_seconds.is_some() && !args.expose_relay {
        anyhow::bail!("--relay-session-affinity-timeout-seconds requires --expose-relay");
    }
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
        })?;

        assert_eq!(
            plan.commands[0],
            "docker compose -p edge -f 'ops/compose file.yaml' config"
        );
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
        }) {
            Ok(_) => anyhow::bail!("invalid Docker host interface should be rejected"),
            Err(error) => error,
        };
        assert!(invalid_host_interface
            .to_string()
            .contains("linux interface name"));

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
        }) {
            Ok(_) => anyhow::bail!("invalid Docker container namespace should be rejected"),
            Err(error) => error,
        };
        assert!(invalid_namespace
            .to_string()
            .contains("linux network namespace name"));
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
            enable_network_policy: true,
            network_policy_acknowledge_host_network: true,
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_node_selectors: Vec::new(),
            agent_tolerations: Vec::new(),
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
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_node_port: Some(31080),
            agent_api_load_balancer_class: Some("example.com/internal-api".to_string()),
            agent_api_health_check_node_port: Some(31081),
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: Some("RequireDualStack".to_string()),
            agent_api_ip_families: vec!["IPv4".to_string(), "IPv6".to_string()],
            agent_api_allow_source_cidrs: vec!["198.51.100.0/24".parse()?],
            agent_api_network_policy_cidrs: vec!["10.0.0.0/8".parse()?],
            agent_api_internal_traffic_policy: Some("Local".to_string()),
            agent_api_session_affinity: Some("ClientIP".to_string()),
            agent_api_session_affinity_timeout_seconds: Some(600),
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: vec![KeyValueArg {
                key: "service.beta.kubernetes.io/aws-load-balancer-type".to_string(),
                value: "nlb,ip".to_string(),
            }],
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_udp_node_port: Some(31820),
            relay_http_node_port: Some(31580),
            relay_load_balancer_class: Some("example.com/internal-relay".to_string()),
            relay_health_check_node_port: Some(31821),
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: Some("PreferDualStack".to_string()),
            relay_ip_families: vec!["IPv6".to_string()],
            relay_allow_source_cidrs: vec!["203.0.113.0/24".parse()?],
            relay_network_policy_cidrs: vec!["203.0.113.0/24".parse()?],
            relay_internal_traffic_policy: Some("Cluster".to_string()),
            relay_session_affinity: Some("ClientIP".to_string()),
            relay_session_affinity_timeout_seconds: Some(900),
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
        assert!(plan.commands[2].contains("--set networkPolicy.enabled=true"));
        assert!(plan.commands[2].contains("--set networkPolicy.acknowledgeHostNetwork=true"));
        assert!(plan.commands[2].contains("--set networkPolicy.agentApi.enabled=true"));
        assert!(plan.commands[2]
            .contains("--set-string 'networkPolicy.agentApi.allowedCidrs[0]=10.0.0.0/8'"));
        assert!(plan.commands[2].contains("--set agent.apiService.enabled=true"));
        assert!(plan.commands[2].contains("--set agent.apiService.type=LoadBalancer"));
        assert!(plan.commands[2].contains("--set agent.apiService.nodePort=31080"));
        assert!(plan.commands[2]
            .contains("--set-string agent.apiService.loadBalancerClass=example.com/internal-api"));
        assert!(plan.commands[2].contains("--set agent.apiService.healthCheckNodePort=31081"));
        assert!(plan.commands[2].contains("--set agent.apiService.ipFamilyPolicy=RequireDualStack"));
        assert!(plan.commands[2].contains("--set-string 'agent.apiService.ipFamilies[0]=IPv4'"));
        assert!(plan.commands[2].contains("--set-string 'agent.apiService.ipFamilies[1]=IPv6'"));
        assert!(plan.commands[2].contains("--set agent.apiService.internalTrafficPolicy=Local"));
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
            "--set-string 'agent.apiService.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-type=nlb\\,ip'"
        ));
        assert!(plan.commands[2].contains("--set agent.relayService.enabled=true"));
        assert!(plan.commands[2].contains("--set networkPolicy.relay.enabled=true"));
        assert!(plan.commands[2]
            .contains("--set-string 'networkPolicy.relay.allowedCidrs[0]=203.0.113.0/24'"));
        assert!(plan.commands[2].contains("--set agent.relayService.type=LoadBalancer"));
        assert!(plan.commands[2].contains("--set agent.relayService.udpNodePort=31820"));
        assert!(plan.commands[2].contains("--set agent.relayService.httpNodePort=31580"));
        assert!(plan.commands[2].contains(
            "--set-string agent.relayService.loadBalancerClass=example.com/internal-relay"
        ));
        assert!(plan.commands[2].contains("--set agent.relayService.healthCheckNodePort=31821"));
        assert!(
            plan.commands[2].contains("--set agent.relayService.ipFamilyPolicy=PreferDualStack")
        );
        assert!(plan.commands[2].contains("--set-string 'agent.relayService.ipFamilies[0]=IPv6'"));
        assert!(plan.commands[2].contains("--set agent.relayService.internalTrafficPolicy=Cluster"));
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
        assert!(plan.commands[2].contains(
            "--set-string 'agent.relayService.annotations.metallb\\.universe\\.tf/address-pool=public'"
        ));
        assert!(plan
            .security
            .iter()
            .any(|requirement| requirement.contains("disabled by default")));
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
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_node_selectors: Vec::new(),
            agent_tolerations: Vec::new(),
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
            agent_api_service_type: "ClusterIP".to_string(),
            agent_api_node_port: None,
            agent_api_load_balancer_class: None,
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: false,
            relay_service_type: "LoadBalancer".to_string(),
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_load_balancer_class: None,
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: Vec::new(),
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
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
        assert!(helm.contains("--set-string 'serviceExposure.apiServerCidrs[0]=10.0.0.1/32'"));
        assert!(helm.contains("--set-string 'serviceExposure.serviceCidrs[0]=10.96.0.0/12'"));
        assert!(helm.contains("--set-string 'serviceExposure.namespaces[0]=default'"));
        assert!(helm.contains("--set-string 'serviceExposure.namespaces[1]=platform'"));
        assert!(
            helm.contains("--set-string serviceExposure.serviceLabelSelector=ipars.io/expose=true")
        );
        assert!(helm.contains("--set-string serviceExposure.routeProviderNodeId=route-provider-a"));
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
        args.agent_node_selectors = vec![KeyValueArg {
            key: "kubernetes.io/os".to_string(),
            value: "linux".to_string(),
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
        args.agent_termination_grace_period_seconds = Some(45);
        args.agent_resource_request_cpu = Some("100m".to_string());
        args.agent_resource_request_memory = Some("128Mi".to_string());
        args.agent_resource_limit_cpu = Some("500m".to_string());
        args.agent_resource_limit_memory = Some("512Mi".to_string());

        let plan = k8s_install_plan(args)?;
        let helm = &plan.commands[2];

        assert!(helm.contains("--set-string 'agent.podLabels.ipars\\.io/role=agent'"));
        assert!(helm.contains("--set-string 'agent.podAnnotations.prometheus\\.io/scrape=true'"));
        assert!(helm.contains("--set-string agent.priorityClassName=ipars-agent-critical"));
        assert!(helm.contains("--set-string 'agent.nodeSelector.kubernetes\\.io/os=linux'"));
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
        assert!(helm.contains("--set agent.terminationGracePeriodSeconds=45"));
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
        assert!(parse_kubernetes_resource_quantity("100 m").is_err());

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

        let mut invalid_priority = base_k8s_install_args();
        invalid_priority.agent_priority_class = Some("system/node-critical".to_string());
        let error = match k8s_install_plan(invalid_priority) {
            Ok(_) => panic!("invalid priority class should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("agent priority class"));

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

        let mut invalid_grace = base_k8s_install_args();
        invalid_grace.agent_termination_grace_period_seconds = Some(u64::MAX);
        let error = match k8s_install_plan(invalid_grace) {
            Ok(_) => panic!("termination grace period over int64 should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("termination-grace-period"));

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
            "--enable-network-policy",
            "--network-policy-acknowledge-host-network",
            "--agent-pod-label",
            "ipars.io/role=agent",
            "--agent-pod-annotation",
            "prometheus.io/scrape=true",
            "--agent-priority-class",
            "ipars-agent-critical",
            "--agent-node-selector",
            "kubernetes.io/os=linux",
            "--agent-toleration",
            "key=node-role.kubernetes.io/control-plane,operator=Exists,effect=NoSchedule",
            "--agent-termination-grace-period-seconds",
            "45",
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
            "--expose-agent-api",
            "--agent-api-service-type",
            "LoadBalancer",
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
            "--agent-api-session-affinity",
            "ClientIP",
            "--agent-api-session-affinity-timeout-seconds",
            "600",
            "--agent-api-external-traffic-policy",
            "Cluster",
            "--agent-api-service-annotation",
            "service.beta.kubernetes.io/aws-load-balancer-type=nlb",
            "--expose-relay",
            "--relay-service-type",
            "LoadBalancer",
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
            "--relay-session-affinity",
            "ClientIP",
            "--relay-session-affinity-timeout-seconds",
            "900",
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
            assert!(args.enable_network_policy);
            assert!(args.network_policy_acknowledge_host_network);
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
                args.agent_node_selectors,
                vec![KeyValueArg {
                    key: "kubernetes.io/os".to_string(),
                    value: "linux".to_string(),
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
            assert_eq!(args.agent_termination_grace_period_seconds, Some(45));
            assert_eq!(args.agent_resource_request_cpu.as_deref(), Some("100m"));
            assert_eq!(args.agent_resource_request_memory.as_deref(), Some("128Mi"));
            assert_eq!(args.agent_resource_limit_cpu.as_deref(), Some("500m"));
            assert_eq!(args.agent_resource_limit_memory.as_deref(), Some("512Mi"));
            assert_eq!(args.agent_update_strategy.as_deref(), Some("RollingUpdate"));
            assert_eq!(args.agent_rollout_max_unavailable.as_deref(), Some("10%"));
            assert_eq!(args.agent_rollout_max_surge.as_deref(), Some("1"));
            assert_eq!(args.agent_min_ready_seconds, Some(15));
            assert_eq!(args.agent_revision_history_limit, Some(5));
            assert!(args.expose_agent_api);
            assert_eq!(args.agent_api_service_type, "LoadBalancer");
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
            assert_eq!(args.agent_api_session_affinity.as_deref(), Some("ClientIP"));
            assert_eq!(args.agent_api_session_affinity_timeout_seconds, Some(600));
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
            assert_eq!(args.relay_session_affinity.as_deref(), Some("ClientIP"));
            assert_eq!(args.relay_session_affinity_timeout_seconds, Some(900));
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
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_node_selectors: Vec::new(),
            agent_tolerations: Vec::new(),
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
            agent_api_service_type: "ClusterIP".to_string(),
            agent_api_node_port: None,
            agent_api_load_balancer_class: None,
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_load_balancer_class: None,
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: Vec::new(),
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
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
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_node_selectors: Vec::new(),
            agent_tolerations: Vec::new(),
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
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_node_port: None,
            agent_api_load_balancer_class: None,
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: false,
            relay_service_type: "LoadBalancer".to_string(),
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_load_balancer_class: None,
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: Vec::new(),
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
            relay_external_traffic_policy: "Local".to_string(),
            relay_service_annotations: Vec::new(),
            relay_public_endpoint: None,
            relay_admission_url: None,
            relay_status_url: None,
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
        valid.agent_api_network_policy_cidrs = vec!["10.0.0.0/8".parse()?];
        valid.expose_relay = true;
        valid.relay_service_type = "ClusterIP".to_string();
        valid.relay_network_policy_cidrs = vec!["203.0.113.0/24".parse()?];
        valid.relay_public_endpoint = Some("203.0.113.10:51820".to_string());
        valid.relay_admission_url = Some("http://203.0.113.10:9580".to_string());

        let plan = k8s_install_plan(valid)?;
        assert!(plan.commands[2].contains("--set networkPolicy.enabled=true"));
        assert!(plan.commands[2].contains("--set networkPolicy.acknowledgeHostNetwork=true"));
        assert!(plan.commands[2].contains("--set networkPolicy.agentApi.enabled=true"));
        assert!(plan.commands[2]
            .contains("--set-string 'networkPolicy.agentApi.allowedCidrs[0]=10.0.0.0/8'"));
        assert!(plan.commands[2].contains("--set networkPolicy.relay.enabled=true"));
        assert!(plan.commands[2]
            .contains("--set-string 'networkPolicy.relay.allowedCidrs[0]=203.0.113.0/24'"));

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
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_node_selectors: Vec::new(),
            agent_tolerations: Vec::new(),
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
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_node_port: None,
            agent_api_load_balancer_class: None,
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: vec!["198.51.100.0/24".parse()?],
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Cluster".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_load_balancer_class: None,
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: vec!["203.0.113.0/24".parse()?],
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
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
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_node_selectors: Vec::new(),
            agent_tolerations: Vec::new(),
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
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_node_port: None,
            agent_api_load_balancer_class: None,
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: vec!["198.51.100.0/24".parse()?],
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Cluster".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_load_balancer_class: None,
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: vec!["203.0.113.0/24".parse()?],
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
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
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_node_selectors: Vec::new(),
            agent_tolerations: Vec::new(),
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
            agent_api_service_type: "ClusterIP".to_string(),
            agent_api_node_port: None,
            agent_api_load_balancer_class: None,
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: vec!["198.51.100.0/24".parse()?],
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: false,
            relay_service_type: "LoadBalancer".to_string(),
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_load_balancer_class: None,
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: Vec::new(),
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
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
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_node_selectors: Vec::new(),
            agent_tolerations: Vec::new(),
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
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_node_port: None,
            agent_api_load_balancer_class: None,
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: false,
            relay_service_type: "LoadBalancer".to_string(),
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_load_balancer_class: None,
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: Vec::new(),
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
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
            enable_network_policy: false,
            network_policy_acknowledge_host_network: false,
            agent_pod_labels: Vec::new(),
            agent_pod_annotations: Vec::new(),
            agent_priority_class: None,
            agent_node_selectors: Vec::new(),
            agent_tolerations: Vec::new(),
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
            agent_api_service_type: "LoadBalancer".to_string(),
            agent_api_node_port: None,
            agent_api_load_balancer_class: None,
            agent_api_health_check_node_port: None,
            agent_api_disable_load_balancer_node_ports: false,
            agent_api_ip_family_policy: None,
            agent_api_ip_families: Vec::new(),
            agent_api_allow_source_cidrs: Vec::new(),
            agent_api_network_policy_cidrs: Vec::new(),
            agent_api_internal_traffic_policy: None,
            agent_api_session_affinity: None,
            agent_api_session_affinity_timeout_seconds: None,
            agent_api_external_traffic_policy: "Local".to_string(),
            agent_api_service_annotations: Vec::new(),
            expose_relay: true,
            relay_service_type: "LoadBalancer".to_string(),
            relay_udp_node_port: None,
            relay_http_node_port: None,
            relay_load_balancer_class: None,
            relay_health_check_node_port: None,
            relay_disable_load_balancer_node_ports: false,
            relay_ip_family_policy: None,
            relay_ip_families: Vec::new(),
            relay_allow_source_cidrs: Vec::new(),
            relay_network_policy_cidrs: Vec::new(),
            relay_internal_traffic_policy: None,
            relay_session_affinity: None,
            relay_session_affinity_timeout_seconds: None,
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
            parse_kubernetes_internal_traffic_policy("Cluster"),
            Ok("Cluster".to_string())
        );
        assert!(parse_kubernetes_internal_traffic_policy("Public").is_err());
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
            parse_kubernetes_label_pair("ipars.io/role=agent"),
            Ok(KeyValueArg {
                key: "ipars.io/role".to_string(),
                value: "agent".to_string(),
            })
        );
        assert!(parse_kubernetes_label_pair("Example.com/role=agent").is_err());
        assert!(parse_kubernetes_label_pair("ipars.io/role=-agent").is_err());
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
            parse_kubernetes_priority_class_name("ipars-agent-critical"),
            Ok("ipars-agent-critical".to_string())
        );
        assert!(parse_kubernetes_priority_class_name("system/node-critical").is_err());
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
            parse_key_value("service.beta.kubernetes.io/aws-load-balancer-type=nlb"),
            Ok(KeyValueArg {
                key: "service.beta.kubernetes.io/aws-load-balancer-type".to_string(),
                value: "nlb".to_string(),
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
        assert_eq!(
            helm_set_key("service.beta.kubernetes.io/aws-load-balancer-type"),
            "service\\.beta\\.kubernetes\\.io/aws-load-balancer-type"
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
