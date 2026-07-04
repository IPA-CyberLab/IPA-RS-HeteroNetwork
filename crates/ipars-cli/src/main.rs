use std::collections::BTreeSet;
use std::net::SocketAddr;

use anyhow::Context;
use chrono::{Duration, Utc};
use clap::{Args, Parser, Subcommand};
use ipars_crypto::{IdentityKeyPair, WireGuardKeyPair};
use ipars_types::api::{JoinNodeRequest, RegisterNodeRequest, RegisterNodeResponse};
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
    #[arg(long)]
    control_plane_url: Option<String>,
    #[arg(long, default_value_t = false)]
    dry_run: bool,
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
        Command::Join(args) => print_json(&join(args).await?)?,
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

async fn join(args: JoinArgs) -> anyhow::Result<JoinOutput> {
    let token: SignedJoinToken =
        serde_json::from_str(&args.token).context("join token must be JSON signed token")?;
    let identity = IdentityKeyPair::generate();
    let wireguard = WireGuardKeyPair::generate();
    let control_plane_url = control_plane_join_url(&token, args.control_plane_url.as_deref())?;
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
    let registration_response = if args.dry_run {
        None
    } else {
        Some(
            reqwest::Client::new()
                .post(&control_plane_url)
                .json(&join_request)
                .send()
                .await
                .context("failed to send join request")?
                .error_for_status()
                .context("control plane rejected join request")?
                .json::<RegisterNodeResponse>()
                .await
                .context("failed to decode join response")?,
        )
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

fn control_plane_join_url(
    token: &SignedJoinToken,
    override_url: Option<&str>,
) -> anyhow::Result<String> {
    let base_url = override_url.map(ToOwned::to_owned).or_else(|| {
        token
            .claims
            .bootstrap_endpoints
            .iter()
            .find(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
            .map(|endpoint| endpoint.url.clone())
    });
    let base_url = base_url.context("join token does not contain a control-plane bootstrap URL")?;
    Ok(format!("{}/v1/join", base_url.trim_end_matches('/')))
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
    control_plane_url: String,
    registered: bool,
    registration: Option<RegisterNodeResponse>,
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
    use super::*;

    fn token_with_bootstrap(endpoints: Vec<BootstrapEndpoint>) -> SignedJoinToken {
        SignedJoinToken {
            claims: claims(
                ClusterId::from_string("cluster-a"),
                NodeId::from_string("issuer"),
                "edge".to_string(),
                Vec::new(),
                300,
                endpoints,
                false,
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
}
