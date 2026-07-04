use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use axum::Router;
use clap::{Args, Parser, Subcommand};
use ipars_agent::{
    AgentError, AgentRuntime, FileAgentStateStore, LinuxWireGuardBackend, PeerMapApplier,
    PeerMapSink, PeerMapSource, PeerMapSync, SystemCommandRunner,
};
use ipars_agent_http::{router as agent_router, AgentHttpState};
use ipars_control_plane::{
    ControlPlane, ControlPlaneConfig, ControlPlaneJoinService, ControlPlaneStore, InMemoryStore,
    InMemoryTokenLedger, IssuerKeyRing, TokenLedger,
};
use ipars_control_plane_http::{router, ControlPlaneHttpState};
use ipars_relay::{RelayService, UdpRelay};
use ipars_relay_http::{router as relay_router, RelayHttpState};
use ipars_route_manager::{LinuxRouteManager, SystemRouteCommandRunner};
use ipars_signal::SignalRegistry;
use ipars_signal_http::{router as signal_router, SignalHttpState};
use ipars_store::{PostgresControlPlaneStore, SqliteControlPlaneStore};
use ipars_stun::EchoStunServer;
use ipars_types::api::{JoinNodeRequest, PeerMap, RegisterNodeRequest, RegisterNodeResponse};
use ipars_types::{
    BootstrapEndpointKind, ClusterId, ClusterPolicy, KeyId, NodeId, RelayCapability,
    SignedJoinToken,
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
    Agent(AgentArgs),
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
    #[arg(long, env = "IPARS_RELAY_MAX_SESSIONS", default_value_t = 10_000)]
    max_sessions: u32,
    #[arg(long, env = "IPARS_RELAY_MAX_MBPS", default_value_t = 1000)]
    max_mbps: u32,
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
    #[arg(long, env = "IPARS_AGENT_STUN_SERVER")]
    stun_server: Option<SocketAddr>,
    #[arg(long, env = "IPARS_AGENT_STUN_BIND", default_value = "0.0.0.0:0")]
    stun_bind: SocketAddr,
    #[arg(long, env = "IPARS_AGENT_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,
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
        env = "IPARS_AGENT_WIREGUARD_INTERFACE",
        default_value = "ipars0"
    )]
    wireguard_interface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ControlPlane(args) => run_control_plane(args).await,
        Command::Signal(args) => run_signal(args).await,
        Command::Stun(args) => run_stun(args).await,
        Command::Relay(args) => run_relay(args).await,
        Command::Agent(args) => run_agent(args).await,
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
    let server = EchoStunServer::bind(args.listen).await?;
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
    let service = Arc::new(RelayService::new(
        NodeId::from_string(args.relay_node_id),
        RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(public_endpoint),
            max_sessions: args.max_sessions,
            active_sessions: 0,
            max_mbps: args.max_mbps,
            e2e_only: true,
        },
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
    if let Some(stun_server) = args.stun_server {
        runtime.probe_stun(args.stun_bind, stun_server).await?;
    }
    let join_token = args
        .join_token
        .as_deref()
        .map(serde_json::from_str::<SignedJoinToken>)
        .transpose()
        .context("agent join token must be JSON signed token")?;
    if let Some(token) = &join_token {
        let response = register_agent(runtime.as_ref(), token, args.control_plane_url.as_deref())
            .await
            .context("failed to register agent with control plane")?;
        tracing::info!(
            node_id = %response.node.node_id,
            vpn_ip = %response.node.vpn_ip,
            peer_count = response.peer_map.peers.len(),
            relay_count = response.relay_map.relays.len(),
            "registered agent with control plane"
        );
    }
    let peer_map_task = if args.apply_peer_map {
        let control_plane_url =
            control_plane_base_url(join_token.as_ref(), args.control_plane_url.as_deref())?;
        Some(start_peer_map_sync(&args, runtime.state().node_id.clone(), control_plane_url).await?)
    } else {
        None
    };
    tracing::info!(node_id = %runtime.state().node_id, listen = %args.listen, "agent listening");
    let result = serve_router(args.listen, agent_router(AgentHttpState::new(runtime))).await;
    if let Some(task) = peer_map_task {
        task.abort();
    }
    result
}

async fn start_peer_map_sync(
    args: &AgentArgs,
    node_id: NodeId,
    control_plane_url: String,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let wireguard =
        LinuxWireGuardBackend::new(args.wireguard_interface.clone(), SystemCommandRunner);
    wireguard.ensure_interface().await?;
    let route_manager = LinuxRouteManager::new(SystemRouteCommandRunner);
    let applier = PeerMapApplier::new(args.wireguard_interface.clone(), wireguard, route_manager);
    let sync = PeerMapSync::new(node_id, HttpPeerMapSource::new(control_plane_url), applier);
    let interval = Duration::from_secs(args.peer_map_poll_interval_seconds.max(1));
    let interface = args.wireguard_interface.clone();
    Ok(tokio::spawn(async move {
        run_peer_map_sync_loop(sync, interval, interface).await;
    }))
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
    use chrono::{Duration as ChronoDuration, Utc};
    use ipars_types::{BootstrapEndpoint, JoinTokenClaims, Role, TokenPolicy};

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
    fn peer_map_url_trims_control_plane_base_url() {
        assert_eq!(
            peer_map_url("http://127.0.0.1:8443/", &NodeId::from_string("node-a")),
            "http://127.0.0.1:8443/v1/peers/node-a"
        );
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
    fn control_plane_base_url_requires_url_or_bootstrap() {
        assert!(control_plane_base_url(None, None).is_err());
    }
}
