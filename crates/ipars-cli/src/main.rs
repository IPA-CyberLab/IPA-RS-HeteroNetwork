use std::collections::BTreeSet;
use std::net::SocketAddr;

use anyhow::Context;
use chrono::{Duration, Utc};
use clap::{Args, Parser, Subcommand};
use ipars_crypto::{IdentityKeyPair, WireGuardKeyPair};
use ipars_types::{
    BootstrapEndpoint, BootstrapEndpointKind, ClusterId, JoinTokenClaims, KeyId, NodeId, Role,
    SignedJoinToken, Tag, TokenPolicy,
};
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
    Status,
    Peers,
    Routes,
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
    #[arg(long, default_value_t = 86_400)]
    token_ttl_seconds: i64,
    #[arg(long, default_value = "edge")]
    default_role: String,
    #[arg(long = "tag")]
    tags: Vec<String>,
}

#[derive(Debug, Args)]
struct JoinArgs {
    token: String,
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    Create(TokenCreateArgs),
}

#[derive(Debug, Args)]
struct TokenCreateArgs {
    #[arg(long)]
    cluster_id: Option<String>,
    #[arg(long, default_value = "edge")]
    role: String,
    #[arg(long = "tag")]
    tags: Vec<String>,
    #[arg(long, default_value_t = 86_400)]
    ttl_seconds: i64,
    #[arg(long = "bootstrap")]
    bootstrap_endpoints: Vec<String>,
    #[arg(long, default_value_t = false)]
    allow_relay: bool,
}

#[derive(Debug, Subcommand)]
enum RelayCommand {
    Status,
}

#[derive(Debug, Subcommand)]
enum PathCommand {
    Status,
}

#[derive(Debug, Subcommand)]
enum DockerCommand {
    Install,
}

#[derive(Debug, Subcommand)]
enum K8sCommand {
    Install,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init(args) => print_json(&init(args)?)?,
        Command::Join(args) => print_json(&join(args)?)?,
        Command::Status => print_json(&StaticStatus::status())?,
        Command::Peers => print_json(&StaticStatus::peers())?,
        Command::Routes => print_json(&StaticStatus::routes())?,
        Command::Token {
            command: TokenCommand::Create(args),
        } => print_json(&create_token(args)?)?,
        Command::Relay {
            command: RelayCommand::Status,
        } => print_json(&StaticStatus::relay())?,
        Command::Path {
            command: PathCommand::Status,
        } => print_json(&StaticStatus::path())?,
        Command::Docker {
            command: DockerCommand::Install,
        } => print_manifest_hint("docker/compose.yaml")?,
        Command::K8s {
            command: K8sCommand::Install,
        } => print_manifest_hint("charts/ipars")?,
    };
    Ok(())
}

fn init(args: InitArgs) -> anyhow::Result<InitOutput> {
    let identity = IdentityKeyPair::generate();
    let wireguard = WireGuardKeyPair::generate();
    let cluster_id = ClusterId::new();
    let bootstrap_endpoints = bootstrap_from_public_endpoint(args.public_endpoint);
    let claims = claims(
        cluster_id.clone(),
        identity.node_id(),
        args.default_role,
        args.tags,
        args.token_ttl_seconds,
        bootstrap_endpoints.clone(),
        false,
    );
    let token = identity.sign_join_token(claims)?;

    Ok(InitOutput {
        cluster_id,
        node_id: identity.node_id(),
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
    })
}

fn join(args: JoinArgs) -> anyhow::Result<JoinOutput> {
    let token: SignedJoinToken =
        serde_json::from_str(&args.token).context("join token must be JSON signed token")?;
    let identity = IdentityKeyPair::generate();
    let wireguard = WireGuardKeyPair::generate();

    Ok(JoinOutput {
        cluster_id: token.claims.cluster_id,
        node_id: identity.node_id(),
        role: token.claims.role,
        tags: token.claims.tags,
        bootstrap_endpoints: token.claims.bootstrap_endpoints,
        identity_public_key: identity.public_key_b64(),
        wireguard_public_key: wireguard.public_key_b64,
        next_step: "register_with_control_plane".to_string(),
    })
}

fn create_token(args: TokenCreateArgs) -> anyhow::Result<SignedJoinToken> {
    let issuer = IdentityKeyPair::generate();
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
        issuer.node_id(),
        args.role,
        args.tags,
        args.ttl_seconds,
        bootstrap_endpoints,
        args.allow_relay,
    ))?;
    Ok(token)
}

fn claims(
    cluster_id: ClusterId,
    issuer: NodeId,
    role: String,
    tags: Vec<String>,
    ttl_seconds: i64,
    bootstrap_endpoints: Vec<BootstrapEndpoint>,
    allow_relay: bool,
) -> JoinTokenClaims {
    let now = Utc::now();
    let tag_set = tags
        .into_iter()
        .map(Tag::from_string)
        .collect::<BTreeSet<_>>();
    let policy = TokenPolicy {
        allow_relay,
        allowed_tags: tag_set.clone(),
        ..TokenPolicy::default()
    };

    JoinTokenClaims {
        cluster_id,
        bootstrap_endpoints,
        expires_at: now + Duration::seconds(ttl_seconds),
        not_before: now - Duration::seconds(5),
        role: Role::from_string(role),
        tags: tag_set,
        issuer,
        key_id: KeyId::from_string("ephemeral-cli"),
        policy,
        nonce: format!("nonce-{}", now.timestamp_nanos_opt().unwrap_or_default()),
    }
}

fn bootstrap_from_public_endpoint(public_endpoint: SocketAddr) -> Vec<BootstrapEndpoint> {
    let host = public_endpoint.ip();
    vec![
        BootstrapEndpoint {
            url: format!("https://{host}:8443"),
            kind: BootstrapEndpointKind::ControlPlane,
        },
        BootstrapEndpoint {
            url: format!("https://{host}:9443"),
            kind: BootstrapEndpointKind::Signal,
        },
        BootstrapEndpoint {
            url: format!("udp://{public_endpoint}"),
            kind: BootstrapEndpointKind::Stun,
        },
        BootstrapEndpoint {
            url: format!("udp://{public_endpoint}"),
            kind: BootstrapEndpointKind::Relay,
        },
    ]
}

fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_manifest_hint(path: &str) -> anyhow::Result<()> {
    print_json(&serde_json::json!({
        "manifest": path,
        "status": "available"
    }))
}

#[derive(Debug, Serialize)]
struct InitOutput {
    cluster_id: ClusterId,
    node_id: NodeId,
    identity_public_key: String,
    wireguard_public_key: String,
    bootstrap_endpoints: Vec<BootstrapEndpoint>,
    join_token: SignedJoinToken,
    services: Vec<String>,
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
    next_step: String,
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
