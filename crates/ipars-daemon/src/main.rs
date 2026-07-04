use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use clap::{Args, Parser, Subcommand};
use ipars_control_plane::{
    ControlPlane, ControlPlaneConfig, ControlPlaneJoinService, ControlPlaneStore, InMemoryStore,
    InMemoryTokenLedger, IssuerKeyRing, TokenLedger,
};
use ipars_control_plane_http::{router, ControlPlaneHttpState};
use ipars_relay::{RelayService, UdpRelay};
use ipars_relay_http::{router as relay_router, RelayHttpState};
use ipars_signal::SignalRegistry;
use ipars_signal_http::{router as signal_router, SignalHttpState};
use ipars_store::{PostgresControlPlaneStore, SqliteControlPlaneStore};
use ipars_stun::EchoStunServer;
use ipars_types::{ClusterId, ClusterPolicy, KeyId, NodeId, RelayCapability};

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ControlPlane(args) => run_control_plane(args).await,
        Command::Signal(args) => run_signal(args).await,
        Command::Stun(args) => run_stun(args).await,
        Command::Relay(args) => run_relay(args).await,
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
    use super::*;

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
}
