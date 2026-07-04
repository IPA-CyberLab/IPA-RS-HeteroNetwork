use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use axum::Router;
use clap::{Args, Parser, Subcommand};
use ipars_agent::{
    AgentError, AgentRuntime, FileAgentStateStore, LinuxCommandRunner, LinuxWireGuardBackend,
    NamespacedLinuxCommandRunner, PeerMapApplier, PeerMapSink, PeerMapSource, PeerMapSync,
    RelayForwarderStats, RelaySessionState, RuntimePeerEndpointResolver, SystemCommandRunner,
    UdpHolePuncher, UdpRelayFrameForwarder,
};
use ipars_agent_http::{router as agent_router, AgentHttpState};
use ipars_control_plane::{
    ControlPlane, ControlPlaneConfig, ControlPlaneJoinService, ControlPlaneStore, InMemoryStore,
    InMemoryTokenLedger, IssuerKeyRing, TokenLedger,
};
use ipars_control_plane_http::{router, ControlPlaneHttpState};
use ipars_relay::{RelayService, UdpRelay};
use ipars_relay_http::{router as relay_router, RelayHttpState};
use ipars_route_manager::{
    DockerNetworkIntent, KubernetesUnderlayIntent, LinuxNetworkNamespace, LinuxRouteCommandRunner,
    LinuxRouteManager, NamespacedLinuxRouteCommandRunner, RouteManager, SystemRouteCommandRunner,
};
use ipars_signal::SignalRegistry;
use ipars_signal_http::{router as signal_router, SignalHttpState};
use ipars_store::{PostgresControlPlaneStore, SqliteControlPlaneStore};
use ipars_stun::BindingStunServer;
use ipars_types::api::{
    HeartbeatRequest, HeartbeatResponse, JoinNodeRequest, PeerMap, RegisterNodeRequest,
    RegisterNodeResponse, RelayAdmissionRequest, RelayAdmissionResponse,
    SignalHolePunchPlanResponse, SignalNodeUpsertRequest, SignalNodeUpsertResponse,
    SignalPathRequest, SignalPathResponse,
};
use ipars_types::{
    BootstrapEndpointKind, ClusterId, ClusterPolicy, EndpointCandidate, HealthState, KeyId,
    NodeHealth, NodeId, NodeRecord, PathRecord, PathState, RelayCapability, SignedJoinToken,
};

#[derive(Debug, Parser)]
#[command(name = "iparsd")]
#[command(about = "IPA-RS-HeteroNetwork daemon processes")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    ControlPlane(ControlPlaneArgs),
    Signal(SignalArgs),
    Stun(StunArgs),
    Relay(RelayArgs),
    Agent(Box<AgentArgs>),
}

#[derive(Debug, Args, Clone)]
struct ControlPlaneArgs {
    #[arg(long, env = "IPARS_LISTEN", default_value = "0.0.0.0:8443")]
    listen: SocketAddr,
    #[arg(long, env = "IPARS_CLUSTER_ID")]
    cluster_id: String,
    #[arg(long, env = "IPARS_VPN_POOL", default_value = "100.64.0.0/10")]
    vpn_pool: ipnet::Ipv4Net,
    #[arg(long, env = "IPARS_DATABASE_URL")]
    database_url: Option<String>,
    #[arg(long, env = "IPARS_ISSUER_NODE_ID")]
    issuer_node_id: String,
    #[arg(long, env = "IPARS_ISSUER_KEY_ID")]
    issuer_key_id: String,
    #[arg(long, env = "IPARS_ISSUER_PUBLIC_KEY")]
    issuer_public_key: String,
}

#[derive(Debug, Args, Clone)]
struct SignalArgs {
    #[arg(long, env = "IPARS_SIGNAL_LISTEN", default_value = "0.0.0.0:9443")]
    listen: SocketAddr,
    #[arg(long, env = "IPARS_SIGNAL_IDLE_TIMEOUT_SECONDS", default_value_t = 300)]
    idle_timeout_seconds: u64,
    #[arg(
        long,
        env = "IPARS_SIGNAL_DISABLE_IPV6_DIRECT",
        default_value_t = false
    )]
    disable_ipv6_direct: bool,
    #[arg(
        long,
        env = "IPARS_SIGNAL_DISABLE_NAT_TRAVERSAL",
        default_value_t = false
    )]
    disable_nat_traversal: bool,
    #[arg(
        long,
        env = "IPARS_SIGNAL_DISABLE_RELAY_FALLBACK",
        default_value_t = false
    )]
    disable_relay_fallback: bool,
}

#[derive(Debug, Args, Clone)]
struct StunArgs {
    #[arg(long, env = "IPARS_STUN_LISTEN", default_value = "0.0.0.0:3478")]
    listen: SocketAddr,
}

#[derive(Debug, Args, Clone)]
struct RelayArgs {
    #[arg(long, env = "IPARS_RELAY_NODE_ID")]
    relay_node_id: String,
    #[arg(long, env = "IPARS_RELAY_UDP_LISTEN", default_value = "0.0.0.0:51820")]
    udp_listen: SocketAddr,
    #[arg(long, env = "IPARS_RELAY_HTTP_LISTEN", default_value = "0.0.0.0:9580")]
    http_listen: SocketAddr,
    #[arg(long, env = "IPARS_RELAY_PUBLIC_ENDPOINT")]
    public_endpoint: Option<SocketAddr>,
    #[arg(long, env = "IPARS_RELAY_ADMISSION_URL")]
    admission_url: Option<String>,
    #[arg(long, env = "IPARS_RELAY_MAX_SESSIONS", default_value_t = 10_000)]
    max_sessions: u32,
    #[arg(long, env = "IPARS_RELAY_MAX_MBPS", default_value_t = 1000)]
    max_mbps: u32,
    #[arg(long, env = "IPARS_RELAY_SESSION_TTL_SECONDS", default_value_t = 300)]
    session_ttl_seconds: u64,
}

#[derive(Debug, Args, Clone)]
struct AgentArgs {
    #[arg(long, env = "IPARS_AGENT_LISTEN", default_value = "0.0.0.0:9780")]
    listen: SocketAddr,
    #[arg(
        long,
        env = "IPARS_AGENT_STATE_PATH",
        default_value = "/var/lib/ipars/agent.json"
    )]
    state_path: std::path::PathBuf,
    #[arg(
        long = "stun-server",
        env = "IPARS_AGENT_STUN_SERVER",
        value_delimiter = ','
    )]
    stun_servers: Vec<SocketAddr>,
    #[arg(long, env = "IPARS_AGENT_STUN_BIND", default_value = "0.0.0.0:0")]
    stun_bind: SocketAddr,
    #[arg(long, env = "IPARS_AGENT_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,
    #[arg(long, env = "IPARS_AGENT_SIGNAL_URL")]
    signal_url: Option<String>,
    #[arg(long, env = "IPARS_AGENT_JOIN_TOKEN")]
    join_token: Option<String>,
    #[arg(long, env = "IPARS_AGENT_APPLY_PEER_MAP", default_value_t = false)]
    apply_peer_map: bool,
    #[arg(
        long,
        env = "IPARS_AGENT_PEER_MAP_POLL_INTERVAL_SECONDS",
        default_value_t = 30
    )]
    peer_map_poll_interval_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_HEARTBEAT_INTERVAL_SECONDS",
        default_value_t = 15
    )]
    heartbeat_interval_seconds: u64,
    #[arg(long, env = "IPARS_AGENT_DISABLE_HEARTBEAT", default_value_t = false)]
    disable_heartbeat: bool,
    #[arg(
        long,
        env = "IPARS_AGENT_SIGNAL_REGISTRATION_INTERVAL_SECONDS",
        default_value_t = 30
    )]
    signal_registration_interval_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_DISABLE_SIGNAL_REGISTRATION",
        default_value_t = false
    )]
    disable_signal_registration: bool,
    #[arg(
        long,
        env = "IPARS_AGENT_SIGNAL_PATH_INTERVAL_SECONDS",
        default_value_t = 30
    )]
    signal_path_interval_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_RELAY_SESSION_RENEW_BEFORE_SECONDS",
        default_value_t = 60
    )]
    relay_session_renew_before_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_DISABLE_SIGNAL_PATHS",
        default_value_t = false
    )]
    disable_signal_paths: bool,
    #[arg(long, env = "IPARS_AGENT_HOLE_PUNCH_BIND", default_value = "0.0.0.0:0")]
    hole_punch_bind: SocketAddr,
    #[arg(long, env = "IPARS_AGENT_HOLE_PUNCH_ATTEMPTS", default_value_t = 5)]
    hole_punch_attempts: usize,
    #[arg(
        long,
        env = "IPARS_AGENT_HOLE_PUNCH_INTERVAL_MILLIS",
        default_value_t = 100
    )]
    hole_punch_interval_millis: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_WIREGUARD_INTERFACE",
        default_value = "ipars0"
    )]
    wireguard_interface: String,
    #[arg(long, env = "IPARS_AGENT_LINUX_NETNS")]
    linux_netns: Option<String>,
    #[arg(long, env = "IPARS_AGENT_RELAY_FORWARDER_ENDPOINT")]
    relay_forwarder_endpoint: Option<SocketAddr>,
    #[arg(long, env = "IPARS_AGENT_RELAY_FORWARDER_BIND")]
    relay_forwarder_bind: Option<SocketAddr>,
    #[arg(long, env = "IPARS_AGENT_RELAY_FORWARDER_WIREGUARD_ENDPOINT")]
    relay_forwarder_wireguard_endpoint: Option<SocketAddr>,
    #[arg(long, env = "IPARS_AGENT_RELAY_FORWARDER_NETNS")]
    relay_forwarder_netns: Option<String>,
    #[arg(
        long,
        env = "IPARS_AGENT_RELAY_FORWARDER_MAX_SESSIONS",
        default_value_t = 1024
    )]
    relay_forwarder_max_sessions: usize,
    #[arg(
        long,
        env = "IPARS_AGENT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS",
        default_value_t = 5
    )]
    relay_forwarder_restart_backoff_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS",
        default_value_t = 60
    )]
    relay_forwarder_crash_window_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW",
        default_value_t = 3
    )]
    relay_forwarder_max_crashes_per_window: u32,
    #[arg(
        long,
        env = "IPARS_AGENT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS",
        default_value_t = 60
    )]
    relay_forwarder_crash_cooldown_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_APPLY_KUBERNETES_UNDERLAY",
        default_value_t = false
    )]
    apply_kubernetes_underlay: bool,
    #[arg(long, env = "IPARS_AGENT_APPLY_DOCKER_ROUTES", default_value_t = false)]
    apply_docker_routes: bool,
    #[arg(long, env = "IPARS_DOCKER_CONTAINER_NAMESPACE")]
    docker_container_namespace: Option<String>,
    #[arg(long, env = "IPARS_DOCKER_HOST_INTERFACE", default_value = "docker0")]
    docker_host_interface: String,
    #[arg(
        long = "docker-container-cidr",
        env = "IPARS_DOCKER_CONTAINER_CIDRS",
        value_delimiter = ','
    )]
    docker_container_cidrs: Vec<ipnet::IpNet>,
    #[arg(long, env = "IPARS_DOCKER_EXPOSE_HOST_ROUTES", default_value_t = true)]
    docker_expose_host_routes: bool,
    #[arg(
        long,
        env = "IPARS_DOCKER_ROUTE_INTERVAL_SECONDS",
        default_value_t = 60
    )]
    docker_route_interval_seconds: u64,
    #[arg(long, env = "IPARS_KUBERNETES_NODE_NAME")]
    kubernetes_node_name: Option<String>,
    #[arg(
        long = "kubernetes-api-server-cidr",
        env = "IPARS_KUBERNETES_API_SERVER_CIDRS",
        value_delimiter = ','
    )]
    kubernetes_api_server_cidrs: Vec<ipnet::IpNet>,
    #[arg(
        long = "kubernetes-service-cidr",
        env = "IPARS_KUBERNETES_SERVICE_CIDRS",
        value_delimiter = ','
    )]
    kubernetes_service_cidrs: Vec<ipnet::IpNet>,
    #[arg(long, env = "IPARS_KUBERNETES_ROUTE_PROVIDER")]
    kubernetes_route_provider: Option<String>,
    #[arg(
        long,
        env = "IPARS_KUBERNETES_ROUTE_INTERVAL_SECONDS",
        default_value_t = 60
    )]
    kubernetes_route_interval_seconds: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ControlPlane(args) => run_control_plane(args).await,
        Command::Signal(args) => run_signal(args).await,
        Command::Stun(args) => run_stun(args).await,
        Command::Relay(args) => run_relay(args).await,
        Command::Agent(args) => run_agent(*args).await,
    }
}

async fn run_control_plane(args: ControlPlaneArgs) -> anyhow::Result<()> {
    match database_kind(args.database_url.as_deref()) {
        DatabaseKind::Postgres => {
            let database_url = args
                .database_url
                .as_deref()
                .context("postgres database URL is required")?;
            let store = Arc::new(PostgresControlPlaneStore::connect(database_url).await?);
            serve_with_store(args, store.clone(), store).await
        }
        DatabaseKind::Sqlite => {
            let database_url = args
                .database_url
                .as_deref()
                .context("sqlite database URL is required")?;
            let store = Arc::new(SqliteControlPlaneStore::connect(database_url).await?);
            serve_with_store(args, store.clone(), store).await
        }
        DatabaseKind::Memory => {
            let store = Arc::new(InMemoryStore::default());
            let ledger = Arc::new(InMemoryTokenLedger::default());
            serve_with_store(args, store, ledger).await
        }
    }
}

async fn serve_with_store<S, L>(
    args: ControlPlaneArgs,
    store: Arc<S>,
    token_ledger: Arc<L>,
) -> anyhow::Result<()>
where
    S: ControlPlaneStore + 'static,
    L: TokenLedger + 'static,
{
    let config = ControlPlaneConfig::new(ClusterId::from_string(args.cluster_id), args.vpn_pool);
    let plane = Arc::new(ControlPlane::new(config, store));
    let mut key_ring = IssuerKeyRing::default();
    key_ring.insert(
        NodeId::from_string(args.issuer_node_id),
        KeyId::from_string(args.issuer_key_id),
        args.issuer_public_key,
    );
    let join_service = Arc::new(ControlPlaneJoinService::new(
        plane.clone(),
        token_ledger,
        key_ring,
    ));
    serve_router(
        args.listen,
        router(ControlPlaneHttpState::new(plane, join_service)),
    )
    .await
}

async fn serve_router(listen: SocketAddr, app: Router) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "control-plane listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn run_signal(args: SignalArgs) -> anyhow::Result<()> {
    let policy = ClusterPolicy {
        allow_ipv6_direct: !args.disable_ipv6_direct,
        allow_nat_traversal: !args.disable_nat_traversal,
        allow_relay_fallback: !args.disable_relay_fallback,
        idle_timeout_seconds: args.idle_timeout_seconds,
        ..ClusterPolicy::default()
    };
    let registry = Arc::new(SignalRegistry::new(policy));
    serve_router(args.listen, signal_router(SignalHttpState::new(registry))).await
}

async fn run_stun(args: StunArgs) -> anyhow::Result<()> {
    let server = BindingStunServer::bind(args.listen).await?;
    let listen = server.local_addr()?;
    tracing::info!(%listen, "stun listening");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let shutdown_task = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });
    let result = server.serve(shutdown_rx).await;
    shutdown_task.abort();
    result?;
    Ok(())
}

async fn run_relay(args: RelayArgs) -> anyhow::Result<()> {
    let udp_relay = UdpRelay::bind(args.udp_listen).await?;
    let udp_addr = udp_relay.local_addr()?;
    let public_endpoint = args.public_endpoint.unwrap_or(udp_addr);
    let admission_url = args
        .admission_url
        .clone()
        .unwrap_or_else(|| format!("http://{}", args.http_listen));
    let service = Arc::new(RelayService::with_session_ttl(
        NodeId::from_string(args.relay_node_id),
        RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(public_endpoint),
            admission_url: Some(admission_url),
            max_sessions: args.max_sessions,
            active_sessions: 0,
            max_mbps: args.max_mbps,
            e2e_only: true,
        },
        chrono::Duration::seconds(args.session_ttl_seconds.max(1) as i64),
    ));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let udp_task = tokio::spawn(udp_relay.serve(service.table(), shutdown_rx));
    tracing::info!(%udp_addr, http_listen = %args.http_listen, "relay listening");
    let http_result =
        serve_router(args.http_listen, relay_router(RelayHttpState::new(service))).await;
    udp_task.abort();
    http_result
}

async fn run_agent(args: AgentArgs) -> anyhow::Result<()> {
    let store = FileAgentStateStore::new(args.state_path.clone());
    let state = store.load_or_create(chrono::Utc::now())?;
    let runtime = Arc::new(AgentRuntime::new(state, ClusterPolicy::default()));
    if args.stun_servers.len() > 1 {
        runtime
            .classify_nat(args.stun_bind, args.stun_servers.clone())
            .await?;
    } else if let Some(stun_server) = args.stun_servers.first().copied() {
        runtime.probe_stun(args.stun_bind, stun_server).await?;
    }
    let join_token = args
        .join_token
        .as_deref()
        .map(serde_json::from_str::<SignedJoinToken>)
        .transpose()
        .context("agent join token must be JSON signed token")?;
    let registered_node = if let Some(token) = &join_token {
        let response = register_agent(runtime.as_ref(), token, args.control_plane_url.as_deref())
            .await
            .context("failed to register agent with control plane")?;
        let registered_node = response.node.clone();
        tracing::info!(
            node_id = %response.node.node_id,
            vpn_ip = %response.node.vpn_ip,
            peer_count = response.peer_map.peers.len(),
            relay_count = response.relay_map.relays.len(),
            "registered agent with control plane"
        );
        Some(registered_node)
    } else {
        None
    };
    let control_plane_base =
        control_plane_base_url(join_token.as_ref(), args.control_plane_url.as_deref()).ok();
    let signal_base = signal_base_url(join_token.as_ref(), args.signal_url.as_deref()).ok();
    let relay_forwarder_supervisor = relay_forwarder_supervisor(&args)?;
    let mut background_tasks = Vec::new();
    if !args.disable_heartbeat {
        if let Some(control_plane_url) = control_plane_base.clone() {
            background_tasks.push(start_heartbeat_reporting(
                runtime.clone(),
                control_plane_url,
                Duration::from_secs(args.heartbeat_interval_seconds.max(1)),
            ));
        }
    }
    let peer_map_task = if args.apply_peer_map {
        let control_plane_url = control_plane_base
            .clone()
            .context("control-plane URL is required when --apply-peer-map is set")?;
        Some(start_peer_map_sync(&args, runtime.clone(), control_plane_url).await?)
    } else {
        None
    };
    if let Some(task) = peer_map_task {
        background_tasks.push(task);
    }
    if args.apply_docker_routes {
        background_tasks.push(start_docker_routes(&args).await?);
    }
    if args.apply_kubernetes_underlay {
        background_tasks
            .push(start_kubernetes_underlay_routes(&args, runtime.state().node_id.clone()).await?);
    }
    if !args.disable_signal_registration {
        if let (Some(node), Some(signal_url)) = (registered_node.clone(), signal_base.clone()) {
            background_tasks.push(start_signal_registration(
                runtime.clone(),
                node,
                signal_url,
                Duration::from_secs(args.signal_registration_interval_seconds.max(1)),
            ));
        }
    }
    if !args.disable_signal_paths {
        if let (Some(control_plane_url), Some(signal_url)) = (control_plane_base, signal_base) {
            let hole_puncher = UdpHolePuncher::new(args.hole_punch_bind)
                .with_attempts(args.hole_punch_attempts)
                .with_interval(Duration::from_millis(args.hole_punch_interval_millis));
            background_tasks.push(start_signal_path_negotiation(
                runtime.clone(),
                control_plane_url,
                signal_url,
                hole_puncher,
                relay_forwarder_supervisor.clone(),
                Duration::from_secs(args.relay_session_renew_before_seconds.max(1)),
                Duration::from_secs(args.signal_path_interval_seconds.max(1)),
            ));
        }
    }
    tracing::info!(node_id = %runtime.state().node_id, listen = %args.listen, "agent listening");
    let result = serve_router(
        args.listen,
        agent_router(AgentHttpState::new(runtime.clone())),
    )
    .await;
    for task in background_tasks {
        task.abort();
    }
    if let Some(supervisor) = relay_forwarder_supervisor {
        supervisor.shutdown_all(runtime.as_ref()).await;
    }
    result
}

async fn start_peer_map_sync(
    args: &AgentArgs,
    runtime: Arc<AgentRuntime>,
    control_plane_url: String,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let namespace = args
        .linux_netns
        .as_deref()
        .map(LinuxNetworkNamespace::from_name)
        .transpose()?;
    if let Some(namespace) = namespace {
        start_peer_map_sync_with_runners(
            args,
            runtime,
            control_plane_url,
            NamespacedLinuxCommandRunner::new(namespace.clone(), SystemCommandRunner),
            NamespacedLinuxRouteCommandRunner::new(namespace, SystemRouteCommandRunner),
        )
        .await
    } else {
        start_peer_map_sync_with_runners(
            args,
            runtime,
            control_plane_url,
            SystemCommandRunner,
            SystemRouteCommandRunner,
        )
        .await
    }
}

async fn start_docker_routes(args: &AgentArgs) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let namespace = args
        .linux_netns
        .as_deref()
        .map(LinuxNetworkNamespace::from_name)
        .transpose()?;
    let intent = docker_network_intent(args)?;
    let interval = Duration::from_secs(args.docker_route_interval_seconds.max(1));
    if let Some(namespace) = namespace {
        let manager = LinuxRouteManager::new(NamespacedLinuxRouteCommandRunner::new(
            namespace,
            SystemRouteCommandRunner,
        ));
        Ok(tokio::spawn(async move {
            run_docker_route_loop(manager, intent, interval).await;
        }))
    } else {
        let manager = LinuxRouteManager::new(SystemRouteCommandRunner);
        Ok(tokio::spawn(async move {
            run_docker_route_loop(manager, intent, interval).await;
        }))
    }
}

fn docker_network_intent(args: &AgentArgs) -> anyhow::Result<DockerNetworkIntent> {
    let container_namespace = args
        .docker_container_namespace
        .clone()
        .context("--apply-docker-routes requires --docker-container-namespace")?;
    if args.docker_container_cidrs.is_empty() {
        anyhow::bail!("--apply-docker-routes requires at least one --docker-container-cidr");
    }

    Ok(DockerNetworkIntent {
        container_namespace,
        host_interface: args.docker_host_interface.clone(),
        overlay_interface: args.wireguard_interface.clone(),
        container_cidrs: args.docker_container_cidrs.clone(),
        expose_host_routes: args.docker_expose_host_routes,
    })
}

async fn run_docker_route_loop<R>(
    manager: LinuxRouteManager<R>,
    intent: DockerNetworkIntent,
    interval: Duration,
) where
    R: LinuxRouteCommandRunner + 'static,
{
    loop {
        match manager.apply_docker_intent(intent.clone()).await {
            Ok(plan) => tracing::info!(
                container_namespace = %intent.container_namespace,
                host_interface = %intent.host_interface,
                routes = plan.routes.len(),
                policy_rules = plan.policy_rules.len(),
                "applied Docker overlay routes"
            ),
            Err(error) => tracing::warn!(
                %error,
                container_namespace = %intent.container_namespace,
                "failed to apply Docker overlay routes; will retry"
            ),
        }
        tokio::time::sleep(interval).await;
    }
}

async fn start_kubernetes_underlay_routes(
    args: &AgentArgs,
    local_node_id: NodeId,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let namespace = args
        .linux_netns
        .as_deref()
        .map(LinuxNetworkNamespace::from_name)
        .transpose()?;
    let intent = kubernetes_underlay_intent(args, local_node_id)?;
    let interval = Duration::from_secs(args.kubernetes_route_interval_seconds.max(1));
    if let Some(namespace) = namespace {
        let manager = LinuxRouteManager::new(NamespacedLinuxRouteCommandRunner::new(
            namespace,
            SystemRouteCommandRunner,
        ));
        Ok(tokio::spawn(async move {
            run_kubernetes_underlay_route_loop(manager, intent, interval).await;
        }))
    } else {
        let manager = LinuxRouteManager::new(SystemRouteCommandRunner);
        Ok(tokio::spawn(async move {
            run_kubernetes_underlay_route_loop(manager, intent, interval).await;
        }))
    }
}

fn kubernetes_underlay_intent(
    args: &AgentArgs,
    local_node_id: NodeId,
) -> anyhow::Result<KubernetesUnderlayIntent> {
    if args.kubernetes_api_server_cidrs.is_empty() && args.kubernetes_service_cidrs.is_empty() {
        anyhow::bail!(
            "--apply-kubernetes-underlay requires at least one --kubernetes-api-server-cidr or --kubernetes-service-cidr"
        );
    }
    let route_provider = args
        .kubernetes_route_provider
        .clone()
        .map(NodeId::from_string)
        .unwrap_or(local_node_id);
    Ok(KubernetesUnderlayIntent {
        node_name: args
            .kubernetes_node_name
            .clone()
            .unwrap_or_else(|| "unknown-node".to_string()),
        overlay_interface: args.wireguard_interface.clone(),
        api_server_cidrs: args.kubernetes_api_server_cidrs.clone(),
        service_cidrs: args.kubernetes_service_cidrs.clone(),
        route_provider,
    })
}

async fn run_kubernetes_underlay_route_loop<R>(
    manager: LinuxRouteManager<R>,
    intent: KubernetesUnderlayIntent,
    interval: Duration,
) where
    R: LinuxRouteCommandRunner + 'static,
{
    loop {
        match manager.apply_kubernetes_intent(intent.clone()).await {
            Ok(plan) => tracing::info!(
                node_name = %intent.node_name,
                route_provider = %intent.route_provider,
                routes = plan.routes.len(),
                policy_rules = plan.policy_rules.len(),
                "applied Kubernetes underlay routes"
            ),
            Err(error) => tracing::warn!(
                %error,
                node_name = %intent.node_name,
                "failed to apply Kubernetes underlay routes; will retry"
            ),
        }
        tokio::time::sleep(interval).await;
    }
}

async fn start_peer_map_sync_with_runners<W, R>(
    args: &AgentArgs,
    runtime: Arc<AgentRuntime>,
    control_plane_url: String,
    wireguard_runner: W,
    route_runner: R,
) -> anyhow::Result<tokio::task::JoinHandle<()>>
where
    W: LinuxCommandRunner + 'static,
    R: LinuxRouteCommandRunner + 'static,
{
    let wireguard = LinuxWireGuardBackend::new(args.wireguard_interface.clone(), wireguard_runner);
    wireguard.ensure_interface().await?;
    let route_manager = LinuxRouteManager::new(route_runner);
    let mut applier =
        PeerMapApplier::new(args.wireguard_interface.clone(), wireguard, route_manager);
    if args.relay_forwarder_endpoint.is_some() || args.relay_forwarder_bind.is_some() {
        let mut resolver = RuntimePeerEndpointResolver::new(runtime.clone());
        if let Some(endpoint) = args.relay_forwarder_endpoint {
            resolver = resolver.with_relay_forwarder_endpoint(endpoint);
        }
        tracing::info!(
            relay_forwarder_endpoint = ?args.relay_forwarder_endpoint,
            relay_forwarder_bind = ?args.relay_forwarder_bind,
            "using relay-aware endpoint resolver for WireGuard peers"
        );
        applier = applier.with_endpoint_resolver(resolver);
    }
    let sync = PeerMapSync::new(
        runtime.state().node_id.clone(),
        HttpPeerMapSource::new(control_plane_url),
        applier,
    );
    let interval = Duration::from_secs(args.peer_map_poll_interval_seconds.max(1));
    let interface = args.wireguard_interface.clone();
    Ok(tokio::spawn(async move {
        run_peer_map_sync_loop(sync, interval, interface).await;
    }))
}

fn relay_forwarder_supervisor(
    args: &AgentArgs,
) -> anyhow::Result<Option<Arc<RelayForwarderSupervisor>>> {
    let Some(bind_addr) = args.relay_forwarder_bind else {
        return Ok(None);
    };
    let wireguard_endpoint = args
        .relay_forwarder_wireguard_endpoint
        .context("--relay-forwarder-wireguard-endpoint is required with --relay-forwarder-bind")?;
    let placement = relay_forwarder_placement(args)?;
    Ok(Some(Arc::new(RelayForwarderSupervisor::new(
        RelayForwarderConfig {
            bind_addr,
            wireguard_endpoint,
            placement,
            max_sessions: args.relay_forwarder_max_sessions,
            restart_backoff: Duration::from_secs(args.relay_forwarder_restart_backoff_seconds),
            crash_policy: RelayForwarderCrashPolicy {
                window: Duration::from_secs(args.relay_forwarder_crash_window_seconds),
                max_crashes_per_window: args.relay_forwarder_max_crashes_per_window,
                cooldown: Duration::from_secs(args.relay_forwarder_crash_cooldown_seconds),
            },
        },
    ))))
}

fn relay_forwarder_placement(args: &AgentArgs) -> anyhow::Result<RelayForwarderPlacement> {
    let namespace = args
        .relay_forwarder_netns
        .as_deref()
        .or(args.linux_netns.as_deref());
    let namespace = namespace
        .map(LinuxNetworkNamespace::from_name)
        .transpose()
        .map_err(anyhow::Error::from)?;
    Ok(namespace
        .map(RelayForwarderPlacement::from)
        .unwrap_or(RelayForwarderPlacement::CurrentProcess))
}

#[derive(Debug, Clone)]
struct RelayForwarderConfig {
    bind_addr: SocketAddr,
    wireguard_endpoint: SocketAddr,
    placement: RelayForwarderPlacement,
    max_sessions: usize,
    restart_backoff: Duration,
    crash_policy: RelayForwarderCrashPolicy,
}

#[derive(Debug, Clone, Copy)]
struct RelayForwarderCrashPolicy {
    window: Duration,
    max_crashes_per_window: u32,
    cooldown: Duration,
}

impl RelayForwarderCrashPolicy {
    fn enabled(&self) -> bool {
        !self.window.is_zero() && self.max_crashes_per_window > 0 && !self.cooldown.is_zero()
    }
}

#[derive(Debug, Clone)]
struct RelayForwarderCrashState {
    window_started_at: chrono::DateTime<chrono::Utc>,
    crashes_in_window: u32,
    cooldown_until: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RelayForwarderPlacement {
    CurrentProcess,
    LinuxNetns(LinuxNetworkNamespace),
}

impl From<LinuxNetworkNamespace> for RelayForwarderPlacement {
    fn from(namespace: LinuxNetworkNamespace) -> Self {
        Self::LinuxNetns(namespace)
    }
}

impl RelayForwarderPlacement {
    fn description(&self) -> String {
        match self {
            Self::CurrentProcess => "current-process".to_string(),
            Self::LinuxNetns(namespace) => format!("netns:{}", namespace.name()),
        }
    }

    fn validate_current_process(&self) -> anyhow::Result<()> {
        match self {
            Self::CurrentProcess => Ok(()),
            Self::LinuxNetns(namespace) => ensure_process_in_netns(namespace),
        }
    }
}

#[derive(Debug)]
struct RelayForwarderSupervisor {
    config: RelayForwarderConfig,
    handles: tokio::sync::Mutex<std::collections::BTreeMap<NodeId, RelayForwarderTask>>,
    restart_backoff_until:
        tokio::sync::Mutex<std::collections::BTreeMap<NodeId, chrono::DateTime<chrono::Utc>>>,
    crash_state: tokio::sync::Mutex<std::collections::BTreeMap<NodeId, RelayForwarderCrashState>>,
}

impl RelayForwarderSupervisor {
    fn new(config: RelayForwarderConfig) -> Self {
        Self {
            config,
            handles: tokio::sync::Mutex::new(std::collections::BTreeMap::new()),
            restart_backoff_until: tokio::sync::Mutex::new(std::collections::BTreeMap::new()),
            crash_state: tokio::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    async fn upsert(
        &self,
        runtime: &AgentRuntime,
        session: RelaySessionState,
    ) -> anyhow::Result<SocketAddr> {
        self.reap_finished(runtime).await;
        let existing_endpoint = {
            let handles = self.handles.lock().await;
            handles.get(&session.peer).and_then(|handle| {
                if handle.session_id == session.session_id
                    && handle.relay_endpoint == session.relay_endpoint
                {
                    Some(handle.local_endpoint)
                } else {
                    None
                }
            })
        };
        if let Some(endpoint) = existing_endpoint {
            runtime
                .upsert_relay_forwarder_endpoint(session.peer, endpoint)
                .await;
            return Ok(endpoint);
        }

        self.ensure_capacity(&session.peer).await?;
        self.ensure_start_allowed(&session.peer).await?;
        self.remove_forwarder(runtime, &session.peer, false).await;
        let socket = match self.bind_socket().await {
            Ok(socket) => socket,
            Err(error) => {
                self.record_start_failure(&session.peer).await;
                return Err(error);
            }
        };
        let local_endpoint = socket
            .local_addr()
            .context("failed to read relay forwarder local endpoint")?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let metrics = Arc::new(RelayForwarderStats::new(
            session.peer.clone(),
            session.relay_node.clone(),
            session.relay_endpoint,
            local_endpoint,
        ));
        let forwarder =
            UdpRelayFrameForwarder::new(session.clone(), self.config.wireguard_endpoint)
                .with_metrics(metrics.clone());
        let task = tokio::spawn(forwarder.serve(socket, shutdown_rx));
        self.handles.lock().await.insert(
            session.peer.clone(),
            RelayForwarderTask {
                session_id: session.session_id.clone(),
                relay_endpoint: session.relay_endpoint,
                local_endpoint,
                shutdown_tx,
                task,
            },
        );
        runtime
            .upsert_relay_forwarder_endpoint(session.peer.clone(), local_endpoint)
            .await;
        runtime.register_relay_forwarder_metrics(metrics).await;
        tracing::info!(
            peer = %session.peer,
            relay = %session.relay_node,
            local_endpoint = %local_endpoint,
            wireguard_endpoint = %self.config.wireguard_endpoint,
            placement = %self.config.placement.description(),
            "started relay forwarder"
        );
        Ok(local_endpoint)
    }

    async fn reap_finished(&self, runtime: &AgentRuntime) -> usize {
        let finished = {
            let mut handles = self.handles.lock().await;
            let finished_peers = handles
                .iter()
                .filter_map(|(peer, handle)| handle.task.is_finished().then_some(peer.clone()))
                .collect::<Vec<_>>();
            finished_peers
                .into_iter()
                .filter_map(|peer| handles.remove(&peer).map(|handle| (peer, handle)))
                .collect::<Vec<_>>()
        };
        let finished_count = finished.len();
        for (peer, handle) in finished {
            runtime.remove_relay_forwarder_endpoint(&peer).await;
            self.record_start_failure(&peer).await;
            if let Err(error) = handle.stop().await {
                tracing::warn!(
                    %error,
                    peer = %peer,
                    "relay forwarder exited and was removed from supervisor"
                );
            } else {
                tracing::warn!(
                    peer = %peer,
                    "relay forwarder exited without an explicit supervisor stop"
                );
            }
        }
        finished_count
    }

    async fn bind_socket(&self) -> anyhow::Result<tokio::net::UdpSocket> {
        self.config.placement.validate_current_process()?;
        tokio::net::UdpSocket::bind(self.config.bind_addr)
            .await
            .with_context(|| {
                format!(
                    "failed to bind relay forwarder UDP socket in {}",
                    self.config.placement.description()
                )
            })
    }

    async fn ensure_capacity(&self, peer: &NodeId) -> anyhow::Result<()> {
        let handles = self.handles.lock().await;
        if handles.contains_key(peer) || handles.len() < self.config.max_sessions {
            return Ok(());
        }
        anyhow::bail!(
            "relay forwarder capacity exceeded: active={} max={}",
            handles.len(),
            self.config.max_sessions
        );
    }

    async fn ensure_start_allowed(&self, peer: &NodeId) -> anyhow::Result<()> {
        let now = chrono::Utc::now();
        let mut backoff = self.restart_backoff_until.lock().await;
        if let Some(until) = backoff.get(peer).copied() {
            if now < until {
                anyhow::bail!(
                    "relay forwarder restart backoff active until {until} for peer {peer}"
                );
            } else {
                backoff.remove(peer);
            }
        }
        drop(backoff);

        if !self.config.crash_policy.enabled() {
            return Ok(());
        }

        let mut crash_state = self.crash_state.lock().await;
        match crash_state.get(peer) {
            Some(state) if state.cooldown_until.is_some_and(|until| now < until) => {
                let until = state.cooldown_until.unwrap_or(now);
                anyhow::bail!(
                    "relay forwarder crash-loop cooldown active until {until} for peer {peer}"
                );
            }
            Some(state) if state.cooldown_until.is_some() => {
                if let Some(until) = state.cooldown_until {
                    tracing::info!(
                        peer = %peer,
                        cooldown_until = %until,
                        "relay forwarder crash-loop cooldown expired"
                    );
                }
                crash_state.remove(peer);
            }
            Some(state)
                if now.signed_duration_since(state.window_started_at)
                    > chrono::Duration::from_std(self.config.crash_policy.window)
                        .unwrap_or_else(|_| chrono::Duration::seconds(i64::MAX)) =>
            {
                crash_state.remove(peer);
            }
            _ => {}
        };
        Ok(())
    }

    async fn record_start_failure(&self, peer: &NodeId) {
        let now = chrono::Utc::now();
        if self.config.restart_backoff.is_zero() {
            self.restart_backoff_until.lock().await.remove(peer);
        } else {
            let backoff = chrono::Duration::from_std(self.config.restart_backoff)
                .unwrap_or_else(|_| chrono::Duration::seconds(i64::MAX));
            self.restart_backoff_until
                .lock()
                .await
                .insert(peer.clone(), now + backoff);
        }

        if !self.config.crash_policy.enabled() {
            return;
        }

        let window = chrono::Duration::from_std(self.config.crash_policy.window)
            .unwrap_or_else(|_| chrono::Duration::seconds(i64::MAX));
        let cooldown = chrono::Duration::from_std(self.config.crash_policy.cooldown)
            .unwrap_or_else(|_| chrono::Duration::seconds(i64::MAX));
        let mut crash_state = self.crash_state.lock().await;
        let state = crash_state
            .entry(peer.clone())
            .and_modify(|state| {
                if now.signed_duration_since(state.window_started_at) > window
                    || state.cooldown_until.is_some_and(|until| now >= until)
                {
                    state.window_started_at = now;
                    state.crashes_in_window = 0;
                    state.cooldown_until = None;
                }
            })
            .or_insert(RelayForwarderCrashState {
                window_started_at: now,
                crashes_in_window: 0,
                cooldown_until: None,
            });
        state.crashes_in_window = state.crashes_in_window.saturating_add(1);
        if state.crashes_in_window >= self.config.crash_policy.max_crashes_per_window {
            let until = now + cooldown;
            state.cooldown_until = Some(until);
            tracing::warn!(
                peer = %peer,
                crashes = state.crashes_in_window,
                window_seconds = self.config.crash_policy.window.as_secs(),
                cooldown_until = %until,
                "relay forwarder entered crash-loop cooldown"
            );
        }
    }

    async fn remove(&self, runtime: &AgentRuntime, peer: &NodeId) {
        self.remove_forwarder(runtime, peer, true).await;
    }

    async fn remove_forwarder(
        &self,
        runtime: &AgentRuntime,
        peer: &NodeId,
        clear_failure_policy: bool,
    ) {
        runtime.remove_relay_forwarder_endpoint(peer).await;
        if clear_failure_policy {
            self.restart_backoff_until.lock().await.remove(peer);
            self.crash_state.lock().await.remove(peer);
        }
        let handle = self.handles.lock().await.remove(peer);
        if let Some(handle) = handle {
            if let Err(error) = handle.stop().await {
                tracing::warn!(%error, peer = %peer, "failed to stop relay forwarder");
            }
        }
    }

    async fn shutdown_all(&self, runtime: &AgentRuntime) {
        let handles = {
            let mut handles = self.handles.lock().await;
            std::mem::take(&mut *handles)
        };
        self.restart_backoff_until.lock().await.clear();
        self.crash_state.lock().await.clear();
        for (peer, handle) in handles {
            runtime.remove_relay_forwarder_endpoint(&peer).await;
            if let Err(error) = handle.stop().await {
                tracing::warn!(%error, peer = %peer, "failed to stop relay forwarder");
            }
        }
    }
}

#[cfg(unix)]
fn ensure_process_in_netns(namespace: &LinuxNetworkNamespace) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let current = std::fs::metadata("/proc/self/ns/net")
        .context("failed to inspect current network namespace")?;
    let target_path = netns_path(namespace);
    let target = std::fs::metadata(&target_path).with_context(|| {
        format!(
            "failed to inspect network namespace {}; run the agent inside it or create {}",
            namespace.name(),
            target_path.display()
        )
    })?;
    if current.dev() == target.dev() && current.ino() == target.ino() {
        return Ok(());
    }
    anyhow::bail!(
        "relay forwarder requires process network namespace {}; current process is in a different namespace",
        namespace.name()
    )
}

#[cfg(not(unix))]
fn ensure_process_in_netns(namespace: &LinuxNetworkNamespace) -> anyhow::Result<()> {
    anyhow::bail!(
        "relay forwarder network namespace placement is only supported on Unix/Linux: {}",
        namespace.name()
    )
}

fn netns_path(namespace: &LinuxNetworkNamespace) -> std::path::PathBuf {
    Path::new("/var/run/netns").join(namespace.name())
}

#[derive(Debug)]
struct RelayForwarderTask {
    session_id: String,
    relay_endpoint: SocketAddr,
    local_endpoint: SocketAddr,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<(), AgentError>>,
}

impl RelayForwarderTask {
    async fn stop(self) -> anyhow::Result<()> {
        let _ = self.shutdown_tx.send(true);
        match self.task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error).context("relay forwarder task failed"),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error).context("relay forwarder task join failed"),
        }
    }
}

async fn register_agent(
    runtime: &AgentRuntime,
    token: &SignedJoinToken,
    control_plane_url: Option<&str>,
) -> anyhow::Result<RegisterNodeResponse> {
    let join_url = control_plane_join_url(token, control_plane_url)?;
    let status = runtime.status().await;
    let request = JoinNodeRequest {
        token: token.clone(),
        registration: RegisterNodeRequest {
            node_id: status.node_id,
            identity_public_key: status.identity_public_key,
            wireguard_public_key: status.wireguard_public_key,
            candidates: status.candidates,
            relay_capability: None,
            requested_routes: Vec::new(),
        },
    };

    reqwest::Client::new()
        .post(join_url)
        .json(&request)
        .send()
        .await
        .context("failed to send agent join request")?
        .error_for_status()
        .context("control plane rejected agent join request")?
        .json()
        .await
        .context("failed to decode agent join response")
}

fn start_heartbeat_reporting(
    runtime: Arc<AgentRuntime>,
    control_plane_url: String,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_heartbeat_loop(runtime, control_plane_url, interval).await;
    })
}

async fn run_heartbeat_loop(
    runtime: Arc<AgentRuntime>,
    control_plane_url: String,
    interval: Duration,
) {
    let client = reqwest::Client::new();
    loop {
        let request = heartbeat_request(runtime.as_ref()).await;
        match send_heartbeat(&client, &control_plane_url, request).await {
            Ok(response) => tracing::info!(
                accepted = response.accepted,
                policy_version = response.policy_version,
                peer_delta_available = response.peer_delta_available,
                "reported agent heartbeat"
            ),
            Err(error) => tracing::warn!(
                %error,
                "failed to report agent heartbeat; will retry"
            ),
        }
        tokio::time::sleep(interval).await;
    }
}

async fn send_heartbeat(
    client: &reqwest::Client,
    control_plane_url: &str,
    request: HeartbeatRequest,
) -> anyhow::Result<HeartbeatResponse> {
    client
        .post(heartbeat_url(control_plane_url))
        .json(&request)
        .send()
        .await
        .context("failed to send heartbeat request")?
        .error_for_status()
        .context("control plane rejected heartbeat request")?
        .json()
        .await
        .context("failed to decode heartbeat response")
}

async fn heartbeat_request(runtime: &AgentRuntime) -> HeartbeatRequest {
    let status = runtime.status().await;
    let path_state = runtime.path_state().await;
    HeartbeatRequest {
        node_id: status.node_id,
        health: NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: chrono::Utc::now(),
            latency_ms: None,
            relay_load: None,
            message: Some("agent heartbeat".to_string()),
        },
        candidates: status.candidates,
        path_state,
    }
}

fn start_signal_registration(
    runtime: Arc<AgentRuntime>,
    node: NodeRecord,
    signal_url: String,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_signal_registration_loop(runtime, node, signal_url, interval).await;
    })
}

async fn run_signal_registration_loop(
    runtime: Arc<AgentRuntime>,
    node: NodeRecord,
    signal_url: String,
    interval: Duration,
) {
    let client = reqwest::Client::new();
    loop {
        let request = signal_node_upsert_request(runtime.as_ref(), node.clone()).await;
        match send_signal_node_upsert(&client, &signal_url, request).await {
            Ok(response) => tracing::info!(
                node_id = %response.node.node_id,
                "registered agent node with signal service"
            ),
            Err(error) => tracing::warn!(
                %error,
                "failed to register agent node with signal service; will retry"
            ),
        }
        tokio::time::sleep(interval).await;
    }
}

async fn send_signal_node_upsert(
    client: &reqwest::Client,
    signal_url: &str,
    request: SignalNodeUpsertRequest,
) -> anyhow::Result<SignalNodeUpsertResponse> {
    client
        .put(signal_node_url(signal_url, &request.node.node_id))
        .json(&request)
        .send()
        .await
        .context("failed to send signal node upsert")?
        .error_for_status()
        .context("signal service rejected node upsert")?
        .json()
        .await
        .context("failed to decode signal node upsert response")
}

async fn signal_node_upsert_request(
    runtime: &AgentRuntime,
    mut node: NodeRecord,
) -> SignalNodeUpsertRequest {
    let status = runtime.status().await;
    node.endpoint_candidates = status.candidates;
    SignalNodeUpsertRequest { node }
}

fn start_signal_path_negotiation(
    runtime: Arc<AgentRuntime>,
    control_plane_url: String,
    signal_url: String,
    hole_puncher: UdpHolePuncher,
    relay_forwarder_supervisor: Option<Arc<RelayForwarderSupervisor>>,
    relay_session_renew_before: Duration,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_signal_path_negotiation_loop(
            runtime,
            control_plane_url,
            signal_url,
            hole_puncher,
            relay_forwarder_supervisor,
            relay_session_renew_before,
            interval,
        )
        .await;
    })
}

async fn run_signal_path_negotiation_loop(
    runtime: Arc<AgentRuntime>,
    control_plane_url: String,
    signal_url: String,
    hole_puncher: UdpHolePuncher,
    relay_forwarder_supervisor: Option<Arc<RelayForwarderSupervisor>>,
    relay_session_renew_before: Duration,
    interval: Duration,
) {
    let client = reqwest::Client::new();
    loop {
        if let Err(error) = negotiate_signal_paths(
            &client,
            runtime.as_ref(),
            &control_plane_url,
            &signal_url,
            &hole_puncher,
            relay_forwarder_supervisor.as_ref(),
            relay_session_renew_before,
        )
        .await
        {
            tracing::warn!(%error, "failed to negotiate signal paths; will retry");
        }
        tokio::time::sleep(interval).await;
    }
}

async fn negotiate_signal_paths(
    client: &reqwest::Client,
    runtime: &AgentRuntime,
    control_plane_url: &str,
    signal_url: &str,
    hole_puncher: &UdpHolePuncher,
    relay_forwarder_supervisor: Option<&Arc<RelayForwarderSupervisor>>,
    relay_session_renew_before: Duration,
) -> anyhow::Result<()> {
    let status = runtime.status().await;
    let peer_map = client
        .get(peer_map_url(control_plane_url, &status.node_id))
        .send()
        .await
        .context("failed to fetch peer map for signal negotiation")?
        .error_for_status()
        .context("control plane rejected peer-map request for signal negotiation")?
        .json::<PeerMap>()
        .await
        .context("failed to decode peer map for signal negotiation")?;

    for peer in peer_map.peers {
        let request = signal_path_request(&status, &peer);
        let response = send_signal_path_request(client, signal_url, request).await?;
        let relay_candidate = selected_relay_candidate(&response);
        let record = signal_path_record(response, chrono::Utc::now());
        if record.selected_state == PathState::DirectNatTraversal {
            match fetch_hole_punch_plan(client, signal_url, &record.key).await {
                Ok(plan) => match hole_puncher.execute(&status.node_id, &plan).await {
                    Ok(attempts) => tracing::info!(
                        attempts,
                        peer = %record.key.remote,
                        "executed UDP hole punch plan"
                    ),
                    Err(error) => tracing::warn!(
                        %error,
                        peer = %record.key.remote,
                        "failed to execute UDP hole punch plan"
                    ),
                },
                Err(error) => tracing::warn!(
                    %error,
                    peer = %record.key.remote,
                    "failed to fetch UDP hole punch plan"
                ),
            }
        }
        if record.selected_state == PathState::Relay {
            match relay_candidate {
                Some(relay) => {
                    if relay_session_needs_renewal(
                        runtime,
                        &peer.node_id,
                        &relay.node_id,
                        relay_session_renew_before,
                    )
                    .await
                    {
                        match admit_relay_session(client, &status, &peer, &relay).await {
                            Ok(session) => {
                                tracing::info!(
                                    peer = %record.key.remote,
                                    relay = %session.relay_node,
                                    expires_at = %session.expires_at,
                                    "admitted relay session"
                                );
                                runtime.upsert_relay_session(session.clone()).await;
                                if let Some(supervisor) = relay_forwarder_supervisor {
                                    if let Err(error) = supervisor.upsert(runtime, session).await {
                                        tracing::warn!(
                                            %error,
                                            peer = %record.key.remote,
                                            "failed to start relay forwarder"
                                        );
                                    }
                                }
                            }
                            Err(error) => {
                                if let Some(supervisor) = relay_forwarder_supervisor {
                                    supervisor.remove(runtime, &peer.node_id).await;
                                } else {
                                    runtime.remove_relay_forwarder_endpoint(&peer.node_id).await;
                                }
                                tracing::warn!(
                                    %error,
                                    peer = %record.key.remote,
                                    "failed to admit relay session"
                                );
                            }
                        }
                    } else {
                        tracing::debug!(
                            peer = %record.key.remote,
                            relay = %relay.node_id,
                            "reusing existing relay session"
                        );
                        if let Some(supervisor) = relay_forwarder_supervisor {
                            if let Some(session) = runtime.relay_session(&peer.node_id).await {
                                if let Err(error) = supervisor.upsert(runtime, session).await {
                                    tracing::warn!(
                                        %error,
                                        peer = %record.key.remote,
                                        "failed to ensure relay forwarder"
                                    );
                                }
                            }
                        }
                    }
                }
                None => {
                    if let Some(supervisor) = relay_forwarder_supervisor {
                        supervisor.remove(runtime, &peer.node_id).await;
                    } else {
                        runtime.remove_relay_forwarder_endpoint(&peer.node_id).await;
                    }
                    tracing::warn!(
                        peer = %record.key.remote,
                        "signal selected relay path without a usable relay candidate"
                    );
                }
            }
        } else {
            let removed = runtime.remove_relay_session(&peer.node_id).await;
            if let Some(session) = removed {
                if let Some(supervisor) = relay_forwarder_supervisor {
                    supervisor.remove(runtime, &session.peer).await;
                } else {
                    runtime.remove_relay_forwarder_endpoint(&session.peer).await;
                }
                tracing::info!(
                    peer = %session.peer,
                    relay = %session.relay_node,
                    state = ?record.selected_state,
                    "removed relay session after non-relay path selection"
                );
            }
        }
        runtime.upsert_path_state(record).await;
    }
    Ok(())
}

async fn relay_session_needs_renewal(
    runtime: &AgentRuntime,
    peer: &NodeId,
    relay_node: &NodeId,
    renew_before: Duration,
) -> bool {
    runtime
        .relay_session_needs_renewal(peer, relay_node, chrono::Utc::now(), renew_before)
        .await
}

async fn admit_relay_session(
    client: &reqwest::Client,
    status: &ipars_types::api::AgentStatusResponse,
    peer: &NodeRecord,
    relay: &NodeRecord,
) -> anyhow::Result<RelaySessionState> {
    let request = relay_admission_request(status, peer)
        .context("relay session requires endpoint candidates")?;
    let relay_endpoint = relay_public_endpoint(relay)?;
    let response = client
        .post(relay_admission_url(relay)?)
        .json(&request)
        .send()
        .await
        .context("failed to send relay admission request")?
        .error_for_status()
        .context("relay rejected admission request")?
        .json::<RelayAdmissionResponse>()
        .await
        .context("failed to decode relay admission response")?;

    Ok(RelaySessionState {
        peer: peer.node_id.clone(),
        relay_node: response.relay_node,
        relay_endpoint,
        admitted_local_addr: response.left_addr,
        admitted_peer_addr: response.right_addr,
        session_id: response.session_id,
        session_token: response.session_token,
        expires_at: response.expires_at,
    })
}

fn relay_admission_request(
    status: &ipars_types::api::AgentStatusResponse,
    peer: &NodeRecord,
) -> Option<RelayAdmissionRequest> {
    Some(RelayAdmissionRequest {
        left: status.node_id.clone(),
        right: peer.node_id.clone(),
        left_addr: relay_session_endpoint(&status.candidates)?,
        right_addr: relay_session_endpoint(&peer.endpoint_candidates)?,
    })
}

fn relay_session_endpoint(candidates: &[EndpointCandidate]) -> Option<SocketAddr> {
    candidates
        .iter()
        .filter_map(|candidate| {
            relay_session_endpoint_rank(candidate).map(|rank| (rank, candidate))
        })
        .min_by(|(left_rank, left), (right_rank, right)| {
            left_rank
                .cmp(right_rank)
                .then_with(|| left.cost.cmp(&right.cost))
                .then_with(|| right.priority.cmp(&left.priority))
        })
        .map(|(_, candidate)| candidate.addr)
}

fn relay_session_endpoint_rank(candidate: &EndpointCandidate) -> Option<u8> {
    match candidate.kind {
        ipars_types::EndpointCandidateKind::StunReflexive => Some(0),
        ipars_types::EndpointCandidateKind::PublicUdp => Some(1),
        ipars_types::EndpointCandidateKind::Ipv6 => Some(2),
        ipars_types::EndpointCandidateKind::LocalUdp => Some(3),
        ipars_types::EndpointCandidateKind::Relay => None,
    }
}

fn selected_relay_candidate(response: &SignalPathResponse) -> Option<NodeRecord> {
    if response.preferred_state != PathState::Relay {
        return None;
    }
    response
        .relay_candidates
        .iter()
        .filter(|relay| {
            relay
                .relay_capability
                .as_ref()
                .map(|capability| capability.can_admit())
                .unwrap_or(false)
        })
        .min_by(|left, right| {
            let left = left.relay_capability.as_ref();
            let right = right.relay_capability.as_ref();
            left.map(|capability| capability.active_sessions)
                .cmp(&right.map(|capability| capability.active_sessions))
                .then_with(|| {
                    right
                        .map(|capability| capability.max_mbps)
                        .cmp(&left.map(|capability| capability.max_mbps))
                })
        })
        .cloned()
}

fn relay_admission_url(relay: &NodeRecord) -> anyhow::Result<String> {
    let url = relay
        .relay_capability
        .as_ref()
        .and_then(|capability| capability.admission_url.as_ref())
        .context("relay admission URL is missing")?;
    Ok(format!("{}/v1/sessions", url.trim_end_matches('/')))
}

fn relay_public_endpoint(relay: &NodeRecord) -> anyhow::Result<SocketAddr> {
    relay
        .relay_capability
        .as_ref()
        .and_then(|capability| capability.public_endpoint)
        .context("relay public UDP endpoint is missing")
}

async fn fetch_hole_punch_plan(
    client: &reqwest::Client,
    signal_url: &str,
    key: &ipars_types::PeerPathKey,
) -> anyhow::Result<SignalHolePunchPlanResponse> {
    client
        .get(signal_hole_punch_url(signal_url, &key.local, &key.remote))
        .send()
        .await
        .context("failed to fetch hole punch plan")?
        .error_for_status()
        .context("signal service rejected hole punch plan request")?
        .json()
        .await
        .context("failed to decode hole punch plan response")
}

async fn send_signal_path_request(
    client: &reqwest::Client,
    signal_url: &str,
    request: SignalPathRequest,
) -> anyhow::Result<SignalPathResponse> {
    client
        .post(signal_path_url(signal_url))
        .json(&request)
        .send()
        .await
        .context("failed to send signal path negotiation")?
        .error_for_status()
        .context("signal service rejected path negotiation")?
        .json()
        .await
        .context("failed to decode signal path response")
}

fn signal_path_request(
    status: &ipars_types::api::AgentStatusResponse,
    peer: &NodeRecord,
) -> SignalPathRequest {
    SignalPathRequest {
        source: status.node_id.clone(),
        target: peer.node_id.clone(),
        source_candidates: status.candidates.clone(),
        desired_routes: peer.routes.iter().map(|route| route.cidr).collect(),
    }
}

fn signal_path_record(
    response: SignalPathResponse,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> PathRecord {
    let selected_candidate =
        selected_path_candidate(response.preferred_state, &response.target_candidates);
    let relay_node = if response.preferred_state == PathState::Relay {
        response
            .relay_candidates
            .first()
            .map(|node| node.node_id.clone())
    } else {
        None
    };

    PathRecord {
        key: response.key,
        selected_state: response.preferred_state,
        selected_candidate,
        relay_node,
        score: response.score,
        updated_at,
        pinned: false,
    }
}

fn selected_path_candidate(
    state: PathState,
    target_candidates: &[EndpointCandidate],
) -> Option<EndpointCandidate> {
    let kind_rank = |candidate: &EndpointCandidate| match (state, candidate.kind) {
        (PathState::DirectIpv6, ipars_types::EndpointCandidateKind::Ipv6) => Some(0_u8),
        (PathState::DirectPublic, ipars_types::EndpointCandidateKind::PublicUdp) => Some(0_u8),
        (PathState::DirectNatTraversal, ipars_types::EndpointCandidateKind::StunReflexive) => {
            Some(0_u8)
        }
        (_, _) if state.is_direct() => Some(1_u8),
        _ => None,
    };
    target_candidates
        .iter()
        .filter_map(|candidate| kind_rank(candidate).map(|rank| (rank, candidate)))
        .min_by(|(left_rank, left), (right_rank, right)| {
            left_rank
                .cmp(right_rank)
                .then_with(|| left.cost.cmp(&right.cost))
                .then_with(|| right.priority.cmp(&left.priority))
        })
        .map(|(_, candidate)| candidate.clone())
}

async fn run_peer_map_sync_loop<S, A>(
    sync: PeerMapSync<S, A>,
    interval: Duration,
    interface: String,
) where
    S: PeerMapSource + 'static,
    A: PeerMapSink + 'static,
{
    loop {
        match sync.sync_once().await {
            Ok(summary) => tracing::info!(
                peers_applied = summary.peers_applied,
                routes_applied = summary.routes_applied,
                interface = %interface,
                "applied control-plane peer map"
            ),
            Err(error) => tracing::warn!(
                %error,
                interface = %interface,
                "failed to apply control-plane peer map; will retry"
            ),
        }
        tokio::time::sleep(interval).await;
    }
}

#[derive(Debug, Clone)]
struct HttpPeerMapSource {
    control_plane_url: String,
    client: reqwest::Client,
}

impl HttpPeerMapSource {
    fn new(control_plane_url: String) -> Self {
        Self {
            control_plane_url,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl PeerMapSource for HttpPeerMapSource {
    async fn fetch_peer_map(&self, node_id: &NodeId) -> Result<PeerMap, AgentError> {
        let url = peer_map_url(&self.control_plane_url, node_id);
        self.client
            .get(url)
            .send()
            .await
            .map_err(|error| AgentError::ControlPlaneClient(error.to_string()))?
            .error_for_status()
            .map_err(|error| AgentError::ControlPlaneClient(error.to_string()))?
            .json()
            .await
            .map_err(|error| AgentError::ControlPlaneClient(error.to_string()))
    }
}

fn peer_map_url(control_plane_url: &str, node_id: &NodeId) -> String {
    format!(
        "{}/v1/peers/{}",
        control_plane_url.trim_end_matches('/'),
        node_id
    )
}

fn heartbeat_url(control_plane_url: &str) -> String {
    format!("{}/v1/heartbeat", control_plane_url.trim_end_matches('/'))
}

fn signal_node_url(signal_url: &str, node_id: &NodeId) -> String {
    format!("{}/v1/nodes/{}", signal_url.trim_end_matches('/'), node_id)
}

fn signal_path_url(signal_url: &str) -> String {
    format!("{}/v1/paths/negotiate", signal_url.trim_end_matches('/'))
}

fn signal_hole_punch_url(signal_url: &str, source: &NodeId, target: &NodeId) -> String {
    format!(
        "{}/v1/hole-punch/{}/{}",
        signal_url.trim_end_matches('/'),
        source,
        target
    )
}

fn control_plane_join_url(
    token: &SignedJoinToken,
    override_url: Option<&str>,
) -> anyhow::Result<String> {
    Ok(format!(
        "{}/v1/join",
        control_plane_base_url(Some(token), override_url)?
    ))
}

fn control_plane_base_url(
    token: Option<&SignedJoinToken>,
    override_url: Option<&str>,
) -> anyhow::Result<String> {
    let base_url = override_url.map(ToOwned::to_owned).or_else(|| {
        token.and_then(|token| {
            token
                .claims
                .bootstrap_endpoints
                .iter()
                .find(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
                .map(|endpoint| endpoint.url.clone())
        })
    });
    let base_url =
        base_url.context("control-plane URL is required and no control-plane bootstrap exists")?;
    Ok(base_url.trim_end_matches('/').to_string())
}

fn signal_base_url(
    token: Option<&SignedJoinToken>,
    override_url: Option<&str>,
) -> anyhow::Result<String> {
    let base_url = override_url.map(ToOwned::to_owned).or_else(|| {
        token.and_then(|token| {
            token
                .claims
                .bootstrap_endpoints
                .iter()
                .find(|endpoint| endpoint.kind == BootstrapEndpointKind::Signal)
                .map(|endpoint| endpoint.url.clone())
        })
    });
    let base_url = base_url.context("signal URL is required and no signal bootstrap exists")?;
    Ok(base_url.trim_end_matches('/').to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseKind {
    Memory,
    Postgres,
    Sqlite,
}

fn database_kind(database_url: Option<&str>) -> DatabaseKind {
    match database_url {
        Some(url) if url.starts_with("postgres://") || url.starts_with("postgresql://") => {
            DatabaseKind::Postgres
        }
        Some(_) => DatabaseKind::Sqlite,
        None => DatabaseKind::Memory,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use chrono::{Duration as ChronoDuration, Utc};
    use ipars_agent::AgentNodeState;
    use ipars_types::{
        BootstrapEndpoint, CandidateSource, EndpointCandidate, EndpointCandidateKind,
        JoinTokenClaims, PathScore, PeerPathKey, Role, TokenPolicy, VpnIp,
    };

    use super::*;

    fn token_with_bootstrap(endpoints: Vec<BootstrapEndpoint>) -> SignedJoinToken {
        SignedJoinToken {
            claims: JoinTokenClaims {
                cluster_id: ClusterId::from_string("cluster-a"),
                bootstrap_endpoints: endpoints,
                expires_at: Utc::now() + ChronoDuration::seconds(300),
                not_before: Utc::now() - ChronoDuration::seconds(5),
                role: Role::edge(),
                tags: Default::default(),
                issuer: NodeId::from_string("issuer"),
                key_id: KeyId::from_string("key-a"),
                policy: TokenPolicy::default(),
                nonce: "nonce-a".to_string(),
            },
            signature: "signature".to_string(),
        }
    }

    fn candidate(node_id: &str, kind: EndpointCandidateKind, cost: u32) -> EndpointCandidate {
        EndpointCandidate {
            node_id: NodeId::from_string(node_id),
            kind,
            addr: SocketAddr::from(([203, 0, 113, 10], 51820)),
            observed_at: Utc::now(),
            priority: 100,
            cost,
            source: CandidateSource::ControlPlane,
        }
    }

    fn node_record(node_id: &str) -> NodeRecord {
        NodeRecord {
            node_id: NodeId::from_string(node_id),
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
            identity_public_key: format!("identity-{node_id}"),
            wireguard_public_key: format!("wg-{node_id}"),
            role: Role::edge(),
            tags: Default::default(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        }
    }

    fn test_crash_policy() -> RelayForwarderCrashPolicy {
        RelayForwarderCrashPolicy {
            window: Duration::from_secs(60),
            max_crashes_per_window: 3,
            cooldown: Duration::from_secs(60),
        }
    }

    async fn insert_dead_forwarder(
        supervisor: &RelayForwarderSupervisor,
        runtime: &AgentRuntime,
        peer: &NodeId,
        session_id: &str,
    ) {
        let local_endpoint = SocketAddr::from(([127, 0, 0, 1], 42_000));
        runtime
            .upsert_relay_forwarder_endpoint(peer.clone(), local_endpoint)
            .await;
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async {
            Err(AgentError::RelaySession(
                "synthetic forwarder death".to_string(),
            ))
        });
        supervisor.handles.lock().await.insert(
            peer.clone(),
            RelayForwarderTask {
                session_id: session_id.to_string(),
                relay_endpoint: SocketAddr::from(([127, 0, 0, 1], 40_000)),
                local_endpoint,
                shutdown_tx,
                task,
            },
        );
        tokio::task::yield_now().await;
    }

    #[test]
    fn database_kind_selects_backend_from_url() {
        assert_eq!(database_kind(None), DatabaseKind::Memory);
        assert_eq!(database_kind(Some("sqlite::memory:")), DatabaseKind::Sqlite);
        assert_eq!(
            database_kind(Some("postgres://ipars@localhost/ipars")),
            DatabaseKind::Postgres
        );
        assert_eq!(
            database_kind(Some("postgresql://ipars@localhost/ipars")),
            DatabaseKind::Postgres
        );
    }

    #[test]
    fn agent_args_accepts_linux_netns() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--linux-netns",
            "node-a",
            "--relay-session-renew-before-seconds",
            "45",
            "--relay-forwarder-endpoint",
            "127.0.0.1:52000",
            "--relay-forwarder-bind",
            "127.0.0.1:0",
            "--relay-forwarder-wireguard-endpoint",
            "127.0.0.1:51820",
            "--relay-forwarder-max-sessions",
            "7",
            "--relay-forwarder-restart-backoff-seconds",
            "11",
            "--relay-forwarder-crash-window-seconds",
            "22",
            "--relay-forwarder-max-crashes-per-window",
            "4",
            "--relay-forwarder-crash-cooldown-seconds",
            "33",
            "--apply-kubernetes-underlay",
            "--kubernetes-node-name",
            "worker-a",
            "--kubernetes-api-server-cidr",
            "10.0.0.1/32",
            "--kubernetes-service-cidr",
            "10.96.0.0/12",
            "--kubernetes-route-provider",
            "route-provider-a",
            "--kubernetes-route-interval-seconds",
            "15",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert_eq!(args.linux_netns.as_deref(), Some("node-a"));
            assert_eq!(args.relay_session_renew_before_seconds, 45);
            assert_eq!(
                args.relay_forwarder_endpoint,
                Some(SocketAddr::from(([127, 0, 0, 1], 52_000)))
            );
            assert_eq!(
                args.relay_forwarder_bind,
                Some(SocketAddr::from(([127, 0, 0, 1], 0)))
            );
            assert_eq!(
                args.relay_forwarder_wireguard_endpoint,
                Some(SocketAddr::from(([127, 0, 0, 1], 51_820)))
            );
            assert_eq!(args.relay_forwarder_max_sessions, 7);
            assert_eq!(args.relay_forwarder_restart_backoff_seconds, 11);
            assert_eq!(args.relay_forwarder_crash_window_seconds, 22);
            assert_eq!(args.relay_forwarder_max_crashes_per_window, 4);
            assert_eq!(args.relay_forwarder_crash_cooldown_seconds, 33);
            let supervisor = relay_forwarder_supervisor(&args)?.context("expected supervisor")?;
            assert_eq!(supervisor.config.max_sessions, 7);
            assert_eq!(supervisor.config.restart_backoff, Duration::from_secs(11));
            assert_eq!(
                supervisor.config.crash_policy.window,
                Duration::from_secs(22)
            );
            assert_eq!(supervisor.config.crash_policy.max_crashes_per_window, 4);
            assert_eq!(
                supervisor.config.crash_policy.cooldown,
                Duration::from_secs(33)
            );
            assert_eq!(
                supervisor.config.placement,
                RelayForwarderPlacement::LinuxNetns(LinuxNetworkNamespace::from_name("node-a")?)
            );
            assert!(args.apply_kubernetes_underlay);
            assert_eq!(args.kubernetes_node_name.as_deref(), Some("worker-a"));
            assert_eq!(
                args.kubernetes_api_server_cidrs,
                vec!["10.0.0.1/32".parse::<ipnet::IpNet>()?]
            );
            assert_eq!(
                args.kubernetes_service_cidrs,
                vec!["10.96.0.0/12".parse::<ipnet::IpNet>()?]
            );
            assert_eq!(
                args.kubernetes_route_provider.as_deref(),
                Some("route-provider-a")
            );
            assert_eq!(args.kubernetes_route_interval_seconds, 15);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[tokio::test]
    async fn relay_forwarder_supervisor_enforces_capacity() -> anyhow::Result<()> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ipars_types::ClusterPolicy::default(),
        );
        let supervisor = RelayForwarderSupervisor::new(RelayForwarderConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            wireguard_endpoint: SocketAddr::from(([127, 0, 0, 1], 51_820)),
            placement: RelayForwarderPlacement::CurrentProcess,
            max_sessions: 0,
            restart_backoff: Duration::from_secs(1),
            crash_policy: test_crash_policy(),
        });
        let session = RelaySessionState {
            peer: NodeId::from_string("peer-a"),
            relay_node: NodeId::from_string("relay-a"),
            relay_endpoint: SocketAddr::from(([127, 0, 0, 1], 40_000)),
            admitted_local_addr: SocketAddr::from(([127, 0, 0, 1], 40_001)),
            admitted_peer_addr: SocketAddr::from(([127, 0, 0, 1], 40_002)),
            session_id: "session-a".to_string(),
            session_token: "token-a".to_string(),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        };

        let error = match supervisor.upsert(&runtime, session).await {
            Ok(endpoint) => anyhow::bail!("unexpected relay forwarder endpoint: {endpoint}"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("capacity exceeded"));
        assert!(runtime.relay_forwarder_endpoints().await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn relay_forwarder_supervisor_reaps_dead_tasks_and_backs_off() -> anyhow::Result<()> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ipars_types::ClusterPolicy::default(),
        );
        let supervisor = RelayForwarderSupervisor::new(RelayForwarderConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            wireguard_endpoint: SocketAddr::from(([127, 0, 0, 1], 51_820)),
            placement: RelayForwarderPlacement::CurrentProcess,
            max_sessions: 10,
            restart_backoff: Duration::from_secs(30),
            crash_policy: test_crash_policy(),
        });
        let peer = NodeId::from_string("peer-dead");
        let local_endpoint = SocketAddr::from(([127, 0, 0, 1], 42_000));
        runtime
            .upsert_relay_forwarder_endpoint(peer.clone(), local_endpoint)
            .await;
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async {
            Err(AgentError::RelaySession(
                "synthetic forwarder death".to_string(),
            ))
        });
        supervisor.handles.lock().await.insert(
            peer.clone(),
            RelayForwarderTask {
                session_id: "session-dead".to_string(),
                relay_endpoint: SocketAddr::from(([127, 0, 0, 1], 40_000)),
                local_endpoint,
                shutdown_tx,
                task,
            },
        );
        tokio::task::yield_now().await;

        assert_eq!(supervisor.reap_finished(&runtime).await, 1);
        assert!(runtime.relay_forwarder_endpoints().await.is_empty());

        let session = RelaySessionState {
            peer,
            relay_node: NodeId::from_string("relay-a"),
            relay_endpoint: SocketAddr::from(([127, 0, 0, 1], 40_000)),
            admitted_local_addr: SocketAddr::from(([127, 0, 0, 1], 40_001)),
            admitted_peer_addr: SocketAddr::from(([127, 0, 0, 1], 40_002)),
            session_id: "session-new".to_string(),
            session_token: "token-new".to_string(),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        };
        let error = match supervisor.upsert(&runtime, session).await {
            Ok(endpoint) => anyhow::bail!("unexpected relay forwarder endpoint: {endpoint}"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("restart backoff active"));
        Ok(())
    }

    #[tokio::test]
    async fn relay_forwarder_supervisor_enters_crash_loop_cooldown() -> anyhow::Result<()> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ipars_types::ClusterPolicy::default(),
        );
        let supervisor = RelayForwarderSupervisor::new(RelayForwarderConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            wireguard_endpoint: SocketAddr::from(([127, 0, 0, 1], 51_820)),
            placement: RelayForwarderPlacement::CurrentProcess,
            max_sessions: 10,
            restart_backoff: Duration::ZERO,
            crash_policy: RelayForwarderCrashPolicy {
                window: Duration::from_secs(60),
                max_crashes_per_window: 2,
                cooldown: Duration::from_secs(30),
            },
        });
        let peer = NodeId::from_string("peer-crash-loop");

        insert_dead_forwarder(&supervisor, &runtime, &peer, "session-dead-1").await;
        assert_eq!(supervisor.reap_finished(&runtime).await, 1);
        insert_dead_forwarder(&supervisor, &runtime, &peer, "session-dead-2").await;
        assert_eq!(supervisor.reap_finished(&runtime).await, 1);

        let session = RelaySessionState {
            peer,
            relay_node: NodeId::from_string("relay-a"),
            relay_endpoint: SocketAddr::from(([127, 0, 0, 1], 40_000)),
            admitted_local_addr: SocketAddr::from(([127, 0, 0, 1], 40_001)),
            admitted_peer_addr: SocketAddr::from(([127, 0, 0, 1], 40_002)),
            session_id: "session-new".to_string(),
            session_token: "token-new".to_string(),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        };
        let error = match supervisor.upsert(&runtime, session).await {
            Ok(endpoint) => anyhow::bail!("unexpected relay forwarder endpoint: {endpoint}"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("crash-loop cooldown active"));
        Ok(())
    }

    #[tokio::test]
    async fn relay_forwarder_supervisor_counts_repeated_bind_failures() -> anyhow::Result<()> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ipars_types::ClusterPolicy::default(),
        );
        let occupied_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let supervisor = RelayForwarderSupervisor::new(RelayForwarderConfig {
            bind_addr: occupied_socket.local_addr()?,
            wireguard_endpoint: SocketAddr::from(([127, 0, 0, 1], 51_820)),
            placement: RelayForwarderPlacement::CurrentProcess,
            max_sessions: 10,
            restart_backoff: Duration::ZERO,
            crash_policy: RelayForwarderCrashPolicy {
                window: Duration::from_secs(60),
                max_crashes_per_window: 2,
                cooldown: Duration::from_secs(30),
            },
        });
        let peer = NodeId::from_string("peer-bind-loop");
        let session = || RelaySessionState {
            peer: peer.clone(),
            relay_node: NodeId::from_string("relay-a"),
            relay_endpoint: SocketAddr::from(([127, 0, 0, 1], 40_000)),
            admitted_local_addr: SocketAddr::from(([127, 0, 0, 1], 40_001)),
            admitted_peer_addr: SocketAddr::from(([127, 0, 0, 1], 40_002)),
            session_id: "session-new".to_string(),
            session_token: "token-new".to_string(),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        };

        let first_error = match supervisor.upsert(&runtime, session()).await {
            Ok(endpoint) => anyhow::bail!("unexpected relay forwarder endpoint: {endpoint}"),
            Err(error) => error,
        };
        assert!(first_error.to_string().contains("failed to bind"));
        let second_error = match supervisor.upsert(&runtime, session()).await {
            Ok(endpoint) => anyhow::bail!("unexpected relay forwarder endpoint: {endpoint}"),
            Err(error) => error,
        };
        assert!(second_error.to_string().contains("failed to bind"));
        let third_error = match supervisor.upsert(&runtime, session()).await {
            Ok(endpoint) => anyhow::bail!("unexpected relay forwarder endpoint: {endpoint}"),
            Err(error) => error,
        };

        assert!(third_error
            .to_string()
            .contains("crash-loop cooldown active"));
        Ok(())
    }

    #[test]
    fn kubernetes_underlay_intent_uses_local_node_as_default_provider() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--kubernetes-node-name",
            "worker-a",
            "--kubernetes-service-cidr",
            "10.96.0.0/12",
        ])?;

        if let Command::Agent(args) = cli.command {
            let local = NodeId::from_string("local-node");
            let intent = kubernetes_underlay_intent(&args, local.clone())?;
            assert_eq!(intent.node_name, "worker-a");
            assert_eq!(intent.overlay_interface, "ipars0");
            assert_eq!(intent.route_provider, local);
            assert!(intent.api_server_cidrs.is_empty());
            assert_eq!(
                intent.service_cidrs,
                vec!["10.96.0.0/12".parse::<ipnet::IpNet>()?]
            );
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn docker_network_intent_uses_explicit_container_routes() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-container-namespace",
            "compose-default",
            "--docker-host-interface",
            "docker0",
            "--docker-container-cidr",
            "172.18.0.0/16",
            "--docker-route-interval-seconds",
            "20",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert!(args.apply_docker_routes);
            assert_eq!(args.docker_route_interval_seconds, 20);
            let intent = docker_network_intent(&args)?;
            assert_eq!(intent.container_namespace, "compose-default");
            assert_eq!(intent.host_interface, "docker0");
            assert_eq!(intent.overlay_interface, "ipars0");
            assert_eq!(
                intent.container_cidrs,
                vec!["172.18.0.0/16".parse::<ipnet::IpNet>()?]
            );
            assert!(intent.expose_host_routes);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn docker_network_intent_requires_namespace_and_routes() -> anyhow::Result<()> {
        let missing_namespace = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-container-cidr",
            "172.18.0.0/16",
        ])?;
        if let Command::Agent(args) = missing_namespace.command {
            assert!(docker_network_intent(&args).is_err());
        }

        let missing_routes = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-container-namespace",
            "compose-default",
        ])?;
        if let Command::Agent(args) = missing_routes.command {
            assert!(docker_network_intent(&args).is_err());
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn kubernetes_underlay_intent_requires_routes() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["iparsd", "agent", "--apply-kubernetes-underlay"])?;

        if let Command::Agent(args) = cli.command {
            assert!(kubernetes_underlay_intent(&args, NodeId::from_string("local")).is_err());
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn relay_args_accepts_session_ttl() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--admission-url",
            "http://relay-a:9580",
            "--session-ttl-seconds",
            "60",
        ])?;

        if let Command::Relay(args) = cli.command {
            assert_eq!(args.session_ttl_seconds, 60);
            assert_eq!(args.admission_url.as_deref(), Some("http://relay-a:9580"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected relay command"))
    }

    #[test]
    fn peer_map_url_trims_control_plane_base_url() {
        assert_eq!(
            peer_map_url("http://127.0.0.1:8443/", &NodeId::from_string("node-a")),
            "http://127.0.0.1:8443/v1/peers/node-a"
        );
    }

    #[test]
    fn heartbeat_url_trims_control_plane_base_url() {
        assert_eq!(
            heartbeat_url("http://127.0.0.1:8443/"),
            "http://127.0.0.1:8443/v1/heartbeat"
        );
    }

    #[test]
    fn signal_node_url_trims_signal_base_url() {
        assert_eq!(
            signal_node_url("http://127.0.0.1:9443/", &NodeId::from_string("node-a")),
            "http://127.0.0.1:9443/v1/nodes/node-a"
        );
    }

    #[test]
    fn signal_path_url_trims_signal_base_url() {
        assert_eq!(
            signal_path_url("http://127.0.0.1:9443/"),
            "http://127.0.0.1:9443/v1/paths/negotiate"
        );
    }

    #[test]
    fn signal_hole_punch_url_trims_signal_base_url() {
        assert_eq!(
            signal_hole_punch_url(
                "http://127.0.0.1:9443/",
                &NodeId::from_string("node-a"),
                &NodeId::from_string("node-b"),
            ),
            "http://127.0.0.1:9443/v1/hole-punch/node-a/node-b"
        );
    }

    #[test]
    fn relay_admission_url_trims_relay_base_url() -> anyhow::Result<()> {
        let mut relay = node_record("relay-a");
        relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 30], 51820))),
            admission_url: Some("http://203.0.113.30:9580/".to_string()),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        });

        assert_eq!(
            relay_admission_url(&relay)?,
            "http://203.0.113.30:9580/v1/sessions"
        );
        assert_eq!(
            relay_public_endpoint(&relay)?,
            SocketAddr::from(([203, 0, 113, 30], 51820))
        );
        Ok(())
    }

    #[test]
    fn relay_admission_request_prefers_reflexive_endpoints() {
        let local = NodeId::from_string("local");
        let peer = NodeId::from_string("peer-a");
        let status = ipars_types::api::AgentStatusResponse {
            node_id: local.clone(),
            identity_public_key: "identity-local".to_string(),
            wireguard_public_key: "wg-local".to_string(),
            candidate_count: 2,
            candidates: vec![
                candidate("local", EndpointCandidateKind::LocalUdp, 1),
                EndpointCandidate {
                    node_id: local.clone(),
                    kind: EndpointCandidateKind::StunReflexive,
                    addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                    observed_at: Utc::now(),
                    priority: 100,
                    cost: 10,
                    source: CandidateSource::StunProbe,
                },
            ],
            nat_classification: None,
            state_updated_at: Utc::now(),
        };
        let mut peer_record = node_record("peer-a");
        peer_record.endpoint_candidates = vec![
            candidate("peer-a", EndpointCandidateKind::LocalUdp, 1),
            EndpointCandidate {
                node_id: peer.clone(),
                kind: EndpointCandidateKind::StunReflexive,
                addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::StunProbe,
            },
        ];

        let request = relay_admission_request(&status, &peer_record);

        assert_eq!(
            request,
            Some(RelayAdmissionRequest {
                left: local,
                right: peer,
                left_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                right_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
            })
        );
    }

    #[test]
    fn selected_relay_candidate_prefers_capacity_tie_breaker() {
        let mut low_bandwidth = node_record("relay-low");
        low_bandwidth.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 31], 51820))),
            admission_url: Some("http://203.0.113.31:9580".to_string()),
            max_sessions: 100,
            active_sessions: 1,
            max_mbps: 100,
            e2e_only: true,
        });
        let mut high_bandwidth = node_record("relay-high");
        high_bandwidth.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 32], 51820))),
            admission_url: Some("http://203.0.113.32:9580".to_string()),
            max_sessions: 100,
            active_sessions: 1,
            max_mbps: 1000,
            e2e_only: true,
        });
        let response = SignalPathResponse {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            target_candidates: Vec::new(),
            relay_candidates: vec![low_bandwidth, high_bandwidth],
            preferred_state: PathState::Relay,
            score: PathScore {
                value: 70.0,
                reasons: Vec::new(),
            },
        };

        let selected = selected_relay_candidate(&response);

        assert_eq!(
            selected.map(|relay| relay.node_id),
            Some(NodeId::from_string("relay-high"))
        );
    }

    #[tokio::test]
    async fn heartbeat_request_uses_runtime_state() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let node_id = runtime.state().node_id.clone();
        let path = PathRecord {
            key: PeerPathKey::new(node_id.clone(), NodeId::from_string("peer-a")),
            selected_state: PathState::DirectPublic,
            selected_candidate: None,
            relay_node: None,
            score: PathScore {
                value: 100.0,
                reasons: Vec::new(),
            },
            updated_at: Utc::now(),
            pinned: false,
        };
        runtime.upsert_path_state(path.clone()).await;

        let request = heartbeat_request(&runtime).await;

        assert_eq!(request.node_id, node_id);
        assert_eq!(request.health.state, HealthState::Healthy);
        assert!(request.candidates.is_empty());
        assert_eq!(request.path_state, vec![path]);
    }

    #[tokio::test]
    async fn signal_node_upsert_request_uses_runtime_candidates() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let node = node_record("node-a");

        let request = signal_node_upsert_request(&runtime, node).await;

        assert_eq!(request.node.node_id, NodeId::from_string("node-a"));
        assert!(request.node.endpoint_candidates.is_empty());
    }

    #[test]
    fn signal_path_record_selects_direct_candidate() {
        let response = SignalPathResponse {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            target_candidates: vec![
                candidate("peer-a", EndpointCandidateKind::StunReflexive, 1),
                candidate("peer-a", EndpointCandidateKind::PublicUdp, 50),
            ],
            relay_candidates: Vec::new(),
            preferred_state: PathState::DirectPublic,
            score: PathScore {
                value: 115.0,
                reasons: Vec::new(),
            },
        };

        let record = signal_path_record(response, Utc::now());

        assert_eq!(record.selected_state, PathState::DirectPublic);
        assert_eq!(
            record
                .selected_candidate
                .as_ref()
                .map(|candidate| candidate.kind),
            Some(EndpointCandidateKind::PublicUdp)
        );
        assert_eq!(record.relay_node, None);
    }

    #[test]
    fn signal_path_record_selects_nat_traversal_candidate() {
        let response = SignalPathResponse {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            target_candidates: vec![
                candidate("peer-a", EndpointCandidateKind::LocalUdp, 1),
                candidate("peer-a", EndpointCandidateKind::StunReflexive, 10),
            ],
            relay_candidates: Vec::new(),
            preferred_state: PathState::DirectNatTraversal,
            score: PathScore {
                value: 105.0,
                reasons: Vec::new(),
            },
        };

        let record = signal_path_record(response, Utc::now());

        assert_eq!(record.selected_state, PathState::DirectNatTraversal);
        assert_eq!(
            record
                .selected_candidate
                .as_ref()
                .map(|candidate| candidate.kind),
            Some(EndpointCandidateKind::StunReflexive)
        );
    }

    #[test]
    fn signal_path_record_selects_relay_node() {
        let mut relay = node_record("relay-a");
        relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 30], 51820))),
            admission_url: Some("http://203.0.113.30:9580".to_string()),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        });
        let response = SignalPathResponse {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            target_candidates: vec![candidate("peer-a", EndpointCandidateKind::Relay, 100)],
            relay_candidates: vec![relay],
            preferred_state: PathState::Relay,
            score: PathScore {
                value: 70.0,
                reasons: Vec::new(),
            },
        };

        let record = signal_path_record(response, Utc::now());

        assert_eq!(record.selected_state, PathState::Relay);
        assert_eq!(record.selected_candidate, None);
        assert_eq!(record.relay_node, Some(NodeId::from_string("relay-a")));
    }

    #[test]
    fn control_plane_join_url_uses_token_bootstrap() -> anyhow::Result<()> {
        let token = token_with_bootstrap(vec![BootstrapEndpoint {
            url: "https://203.0.113.10:8443/".to_string(),
            kind: BootstrapEndpointKind::ControlPlane,
        }]);

        assert_eq!(
            control_plane_join_url(&token, None)?,
            "https://203.0.113.10:8443/v1/join"
        );
        Ok(())
    }

    #[test]
    fn control_plane_base_url_override_takes_precedence() -> anyhow::Result<()> {
        let token = token_with_bootstrap(vec![BootstrapEndpoint {
            url: "https://203.0.113.10:8443".to_string(),
            kind: BootstrapEndpointKind::ControlPlane,
        }]);

        assert_eq!(
            control_plane_base_url(Some(&token), Some("http://127.0.0.1:8443/"))?,
            "http://127.0.0.1:8443"
        );
        Ok(())
    }

    #[test]
    fn signal_base_url_uses_token_bootstrap() -> anyhow::Result<()> {
        let token = token_with_bootstrap(vec![BootstrapEndpoint {
            url: "https://203.0.113.10:9443/".to_string(),
            kind: BootstrapEndpointKind::Signal,
        }]);

        assert_eq!(
            signal_base_url(Some(&token), None)?,
            "https://203.0.113.10:9443"
        );
        Ok(())
    }

    #[test]
    fn signal_base_url_override_takes_precedence() -> anyhow::Result<()> {
        let token = token_with_bootstrap(vec![BootstrapEndpoint {
            url: "https://203.0.113.10:9443".to_string(),
            kind: BootstrapEndpointKind::Signal,
        }]);

        assert_eq!(
            signal_base_url(Some(&token), Some("http://127.0.0.1:9443/"))?,
            "http://127.0.0.1:9443"
        );
        Ok(())
    }

    #[test]
    fn control_plane_base_url_requires_url_or_bootstrap() {
        assert!(control_plane_base_url(None, None).is_err());
    }
}
