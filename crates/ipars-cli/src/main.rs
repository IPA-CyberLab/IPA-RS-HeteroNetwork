use std::collections::BTreeSet;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use chrono::{Duration, Utc};
use clap::{Args, Parser, Subcommand};
use ipars_crypto::{IdentityKeyPair, WireGuardKeyPair};
use ipars_types::api::{
    AgentPathsResponse, AgentStatusResponse, JoinNodeRequest, PeerMap, RegisterNodeRequest,
    RegisterNodeResponse, RelayStatusResponse, RevokeTokenRequest, RevokeTokenResponse,
};
use ipars_types::{
    BootstrapEndpoint, BootstrapEndpointKind, ClusterId, JoinTokenClaims, KeyId, NodeId, Role,
    Route, SignedJoinToken, Tag, TokenPolicy,
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
    #[arg(long, env = "IPARS_AGENT_URL")]
    agent_url: Option<String>,
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
}

#[derive(Debug, Args)]
struct PathStatusArgs {
    #[arg(long, env = "IPARS_AGENT_URL")]
    agent_url: Option<String>,
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
        Command::Status(args) => match args.agent_url.as_deref() {
            Some(agent_url) => print_json(&agent_status(agent_url).await?)?,
            None => print_json(&StaticStatus::status())?,
        },
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
        Command::Path {
            command: PathCommand::Status(args),
        } => match args.agent_url.as_deref() {
            Some(agent_url) => print_json(&path_status(agent_url).await?)?,
            None => print_json(&StaticStatus::path())?,
        },
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
    let identity = issuer_key_from_source(
        args.issuer_private_key_b64.as_deref(),
        args.issuer_private_key_path.as_deref(),
        MissingIssuerPath::GenerateAndWrite,
    )?;
    let wireguard = WireGuardKeyPair::generate();
    let cluster_id = ClusterId::new();
    let bootstrap_endpoints = bootstrap_from_public_endpoint(args.public_endpoint);
    let issuer = TokenIssuer {
        node_id: identity.node_id(),
        key_id: KeyId::from_string(args.issuer_key_id.clone()),
    };
    let claims = claims(
        cluster_id.clone(),
        issuer.clone(),
        args.default_role,
        args.tags,
        args.token_ttl_seconds,
        bootstrap_endpoints.clone(),
        TokenPolicyInput {
            allow_relay: args.allow_relay,
            allowed_routes: args.allowed_routes,
            max_token_uses: max_token_uses(args.max_uses, args.unlimited_uses),
        },
    );
    let token = identity.sign_join_token(claims)?;

    Ok(InitOutput {
        cluster_id,
        node_id: identity.node_id(),
        issuer_node_id: identity.node_id(),
        issuer_key_id: KeyId::from_string(args.issuer_key_id),
        issuer_public_key: identity.public_key_b64(),
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

fn api_url(base_url: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
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
        } else {
            anyhow::bail!("expected status command");
        }

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

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ipars-cli-{name}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ))
    }
}
