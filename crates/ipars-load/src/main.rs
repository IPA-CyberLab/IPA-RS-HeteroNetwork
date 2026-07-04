use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use chrono::Utc;
use clap::{Parser, ValueEnum};
use ipars_control_plane::{
    ControlPlane, ControlPlaneConfig, ControlPlaneJoinService, InMemoryStore, InMemoryTokenLedger,
    IssuerKeyRing,
};
use ipars_control_plane_http::{router as control_plane_router, ControlPlaneHttpState};
use ipars_crypto::IdentityKeyPair;
use ipars_signal::SignalRegistry;
use ipars_signal_http::{router as signal_router, SignalHttpState};
use ipars_types::api::{
    JoinNodeRequest, PeerMap, RegisterNodeRequest, RegisterNodeResponse, SignalNodeUpsertRequest,
    SignalNodeUpsertResponse, SignalPathRequest, SignalPathResponse,
};
use ipars_types::{
    BootstrapEndpoint, BootstrapEndpointKind, CandidateSource, ClusterId, ClusterPolicy,
    EndpointCandidate, EndpointCandidateKind, JoinTokenClaims, KeyId, NodeId, PathState,
    RelayCapability, Role, Route, Tag, TokenPolicy,
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::task::JoinHandle;

#[derive(Debug, Parser)]
#[command(name = "ipars-load")]
#[command(about = "IPA-RS scale/load scenario harness")]
struct Cli {
    #[arg(long, value_enum, default_value_t = ScenarioName::Ten)]
    scenario: ScenarioName,

    #[arg(long, value_enum, default_value_t = TransportMode::InMemory)]
    transport: TransportMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScenarioName {
    Three,
    Ten,
    Thousand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
enum TransportMode {
    InMemory,
    Http,
}

#[derive(Debug, Clone, Copy)]
struct Scenario {
    name: ScenarioName,
    node_count: usize,
    relay_count: usize,
    route_provider_count: usize,
    active_pair_count: usize,
}

impl Scenario {
    fn from_name(name: ScenarioName) -> Self {
        match name {
            ScenarioName::Three => Self {
                name,
                node_count: 3,
                relay_count: 1,
                route_provider_count: 1,
                active_pair_count: 6,
            },
            ScenarioName::Ten => Self {
                name,
                node_count: 10,
                relay_count: 2,
                route_provider_count: 2,
                active_pair_count: 30,
            },
            ScenarioName::Thousand => Self {
                name,
                node_count: 1_000,
                relay_count: 10,
                route_provider_count: 25,
                active_pair_count: 2_000,
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct LoadReport {
    transport: TransportMode,
    scenario: ScenarioName,
    node_count: usize,
    relay_count: usize,
    route_provider_count: usize,
    advertised_routes: usize,
    active_pair_count: usize,
    registrations: usize,
    peer_map_requests: usize,
    peer_map_edges_seen: usize,
    signal_negotiations: usize,
    relay_candidates: usize,
    direct_public_paths: usize,
    direct_ipv6_paths: usize,
    direct_nat_paths: usize,
    relay_paths: usize,
    unreachable_paths: usize,
    control_plane_http_requests: usize,
    signal_http_requests: usize,
    registration_millis: u128,
    peer_map_millis: u128,
    signal_millis: u128,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let scenario = Scenario::from_name(cli.scenario);
    let report = match cli.transport {
        TransportMode::InMemory => run_in_memory_scenario(scenario).await?,
        TransportMode::Http => run_http_scenario(scenario).await?,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn run_in_memory_scenario(scenario: Scenario) -> anyhow::Result<LoadReport> {
    let cluster_id = ClusterId::from_string(format!("load-{:?}", scenario.name));
    let config = ControlPlaneConfig::new(
        cluster_id.clone(),
        ipnet::Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 16)?,
    );
    let store = Arc::new(InMemoryStore::default());
    let plane = ControlPlane::new(config, store);
    let registry = SignalRegistry::new(ClusterPolicy::default());
    let issuer = NodeId::from_string("load-issuer");
    let key_id = KeyId::from_string("load-key");

    let registration_started = Instant::now();
    let mut nodes = Vec::with_capacity(scenario.node_count);
    for index in 0..scenario.node_count {
        let request = register_request(index, scenario)?;
        let response = plane
            .register_with_claims(
                join_claims(&cluster_id, &issuer, &key_id, index, scenario)?,
                request,
            )
            .await
            .with_context(|| format!("failed to register synthetic node {index}"))?;
        registry.upsert_node(response.node.clone()).await;
        nodes.push(response.node);
    }
    let registration_millis = registration_started.elapsed().as_millis();

    let peer_map_started = Instant::now();
    let mut peer_map_edges_seen = 0;
    for node in &nodes {
        let peer_map = plane.peer_map_for(&node.node_id).await?;
        peer_map_edges_seen += peer_map.peers.len();
    }
    let peer_map_millis = peer_map_started.elapsed().as_millis();

    let signal_started = Instant::now();
    let advertised_routes = nodes.iter().map(|node| node.routes.len()).sum();
    let mut path_counts = PathCounts::default();
    for pair_index in 0..scenario.active_pair_count {
        let (source_index, target_index) = active_pair_indices(pair_index, nodes.len());
        let source = &nodes[source_index];
        let target = &nodes[target_index];
        let response = registry
            .negotiate(SignalPathRequest {
                source: source.node_id.clone(),
                target: target.node_id.clone(),
                source_candidates: source.endpoint_candidates.clone(),
                desired_routes: target.routes.iter().map(|route| route.cidr).collect(),
            })
            .await?;
        path_counts.record(response.preferred_state);
    }
    let signal_millis = signal_started.elapsed().as_millis();

    Ok(LoadReport {
        transport: TransportMode::InMemory,
        scenario: scenario.name,
        node_count: scenario.node_count,
        relay_count: scenario.relay_count,
        route_provider_count: scenario.route_provider_count,
        advertised_routes,
        active_pair_count: scenario.active_pair_count,
        registrations: nodes.len(),
        peer_map_requests: nodes.len(),
        peer_map_edges_seen,
        signal_negotiations: scenario.active_pair_count,
        relay_candidates: registry.relay_candidates().await.len(),
        direct_public_paths: path_counts.direct_public,
        direct_ipv6_paths: path_counts.direct_ipv6,
        direct_nat_paths: path_counts.direct_nat,
        relay_paths: path_counts.relay,
        unreachable_paths: path_counts.unreachable,
        control_plane_http_requests: 0,
        signal_http_requests: 0,
        registration_millis,
        peer_map_millis,
        signal_millis,
    })
}

async fn run_http_scenario(scenario: Scenario) -> anyhow::Result<LoadReport> {
    let issuer = IdentityKeyPair::generate();
    let key_id = KeyId::from_string("load-key");
    let cluster_id = ClusterId::from_string(format!("load-{:?}", scenario.name));
    let services = NetworkedServices::start(cluster_id.clone(), &issuer, &key_id).await?;
    let client = reqwest::Client::new();

    let registration_started = Instant::now();
    let mut nodes = Vec::with_capacity(scenario.node_count);
    let mut relay_candidates = 0;
    for index in 0..scenario.node_count {
        let token = issuer.sign_join_token(join_claims(
            &cluster_id,
            &issuer.node_id(),
            &key_id,
            index,
            scenario,
        )?)?;
        let response: RegisterNodeResponse = post_json(
            &client,
            format!("{}/v1/join", services.control_plane_url),
            &JoinNodeRequest {
                token,
                registration: register_request(index, scenario)?,
            },
            "control-plane join",
        )
        .await
        .with_context(|| format!("failed to join synthetic node {index} over HTTP"))?;
        relay_candidates = response.relay_map.relays.len();
        let upsert_url = format!("{}/v1/nodes/{}", services.signal_url, response.node.node_id);
        let _: SignalNodeUpsertResponse = put_json(
            &client,
            upsert_url,
            &SignalNodeUpsertRequest {
                node: response.node.clone(),
            },
            "signal node upsert",
        )
        .await
        .with_context(|| format!("failed to upsert synthetic node {index} to signal over HTTP"))?;
        nodes.push(response.node);
    }
    let registration_millis = registration_started.elapsed().as_millis();

    let peer_map_started = Instant::now();
    let mut peer_map_edges_seen = 0;
    for node in &nodes {
        let peer_map: PeerMap = get_json(
            &client,
            format!("{}/v1/peers/{}", services.control_plane_url, node.node_id),
            "control-plane peer map",
        )
        .await?;
        peer_map_edges_seen += peer_map.peers.len();
    }
    let peer_map_millis = peer_map_started.elapsed().as_millis();

    let signal_started = Instant::now();
    let advertised_routes = nodes.iter().map(|node| node.routes.len()).sum();
    let mut path_counts = PathCounts::default();
    for pair_index in 0..scenario.active_pair_count {
        let (source_index, target_index) = active_pair_indices(pair_index, nodes.len());
        let source = &nodes[source_index];
        let target = &nodes[target_index];
        let response: SignalPathResponse = post_json(
            &client,
            format!("{}/v1/paths/negotiate", services.signal_url),
            &SignalPathRequest {
                source: source.node_id.clone(),
                target: target.node_id.clone(),
                source_candidates: source.endpoint_candidates.clone(),
                desired_routes: target.routes.iter().map(|route| route.cidr).collect(),
            },
            "signal path negotiation",
        )
        .await?;
        path_counts.record(response.preferred_state);
    }
    let signal_millis = signal_started.elapsed().as_millis();

    Ok(LoadReport {
        transport: TransportMode::Http,
        scenario: scenario.name,
        node_count: scenario.node_count,
        relay_count: scenario.relay_count,
        route_provider_count: scenario.route_provider_count,
        advertised_routes,
        active_pair_count: scenario.active_pair_count,
        registrations: nodes.len(),
        peer_map_requests: nodes.len(),
        peer_map_edges_seen,
        signal_negotiations: scenario.active_pair_count,
        relay_candidates,
        direct_public_paths: path_counts.direct_public,
        direct_ipv6_paths: path_counts.direct_ipv6,
        direct_nat_paths: path_counts.direct_nat,
        relay_paths: path_counts.relay,
        unreachable_paths: path_counts.unreachable,
        control_plane_http_requests: nodes.len() * 2,
        signal_http_requests: nodes.len() + scenario.active_pair_count,
        registration_millis,
        peer_map_millis,
        signal_millis,
    })
}

#[derive(Debug, Default)]
struct PathCounts {
    direct_public: usize,
    direct_ipv6: usize,
    direct_nat: usize,
    relay: usize,
    unreachable: usize,
}

impl PathCounts {
    fn record(&mut self, state: PathState) {
        match state {
            PathState::DirectPublic => self.direct_public += 1,
            PathState::DirectIpv6 => self.direct_ipv6 += 1,
            PathState::DirectNatTraversal => self.direct_nat += 1,
            PathState::Relay => self.relay += 1,
            PathState::Unreachable => self.unreachable += 1,
        }
    }
}

struct NetworkedServices {
    control_plane_url: String,
    signal_url: String,
    tasks: Vec<JoinHandle<std::io::Result<()>>>,
}

impl NetworkedServices {
    async fn start(
        cluster_id: ClusterId,
        issuer: &IdentityKeyPair,
        key_id: &KeyId,
    ) -> anyhow::Result<Self> {
        let mut tasks = Vec::new();
        let control_plane_url =
            Self::spawn_control_plane(cluster_id, issuer, key_id, &mut tasks).await?;
        let signal_url = Self::spawn_signal(&mut tasks).await?;
        Ok(Self {
            control_plane_url,
            signal_url,
            tasks,
        })
    }

    async fn spawn_control_plane(
        cluster_id: ClusterId,
        issuer: &IdentityKeyPair,
        key_id: &KeyId,
        tasks: &mut Vec<JoinHandle<std::io::Result<()>>>,
    ) -> anyhow::Result<String> {
        let store = Arc::new(InMemoryStore::default());
        let ledger = Arc::new(InMemoryTokenLedger::default());
        let plane = Arc::new(ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id,
                ipnet::Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 16)?,
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
        let app = control_plane_router(ControlPlaneHttpState::new(plane, join_service));
        Self::spawn_router(app, tasks).await
    }

    async fn spawn_signal(
        tasks: &mut Vec<JoinHandle<std::io::Result<()>>>,
    ) -> anyhow::Result<String> {
        let registry = Arc::new(SignalRegistry::new(ClusterPolicy::default()));
        let app = signal_router(SignalHttpState::new(registry));
        Self::spawn_router(app, tasks).await
    }

    async fn spawn_router(
        app: axum::Router,
        tasks: &mut Vec<JoinHandle<std::io::Result<()>>>,
    ) -> anyhow::Result<String> {
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        tasks.push(task);
        Ok(format!("http://{addr}"))
    }
}

impl Drop for NetworkedServices {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn get_json<Response>(
    client: &reqwest::Client,
    url: String,
    context: &str,
) -> anyhow::Result<Response>
where
    Response: DeserializeOwned,
{
    client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to send {context} request"))?
        .error_for_status()
        .with_context(|| format!("{context} request was rejected"))?
        .json()
        .await
        .with_context(|| format!("failed to decode {context} response"))
}

async fn post_json<Request, Response>(
    client: &reqwest::Client,
    url: String,
    request: &Request,
    context: &str,
) -> anyhow::Result<Response>
where
    Request: Serialize + ?Sized,
    Response: DeserializeOwned,
{
    client
        .post(url)
        .json(request)
        .send()
        .await
        .with_context(|| format!("failed to send {context} request"))?
        .error_for_status()
        .with_context(|| format!("{context} request was rejected"))?
        .json()
        .await
        .with_context(|| format!("failed to decode {context} response"))
}

async fn put_json<Request, Response>(
    client: &reqwest::Client,
    url: String,
    request: &Request,
    context: &str,
) -> anyhow::Result<Response>
where
    Request: Serialize + ?Sized,
    Response: DeserializeOwned,
{
    client
        .put(url)
        .json(request)
        .send()
        .await
        .with_context(|| format!("failed to send {context} request"))?
        .error_for_status()
        .with_context(|| format!("{context} request was rejected"))?
        .json()
        .await
        .with_context(|| format!("failed to decode {context} response"))
}

fn register_request(index: usize, scenario: Scenario) -> anyhow::Result<RegisterNodeRequest> {
    Ok(RegisterNodeRequest {
        node_id: node_id(index),
        identity_public_key: format!("identity-public-{index}"),
        wireguard_public_key: format!("wireguard-public-{index}"),
        candidates: endpoint_candidates(index, scenario),
        relay_capability: relay_capability(index, scenario),
        requested_routes: advertised_routes(index, scenario)?,
    })
}

fn join_claims(
    cluster_id: &ClusterId,
    issuer: &NodeId,
    key_id: &KeyId,
    index: usize,
    scenario: Scenario,
) -> anyhow::Result<JoinTokenClaims> {
    let now = Utc::now();
    let mut tags = BTreeSet::new();
    tags.insert(Tag::from_string(if index < scenario.relay_count {
        "public"
    } else if index < scenario.relay_count + scenario.route_provider_count {
        "route-provider"
    } else {
        "edge"
    }));
    Ok(JoinTokenClaims {
        cluster_id: cluster_id.clone(),
        bootstrap_endpoints: vec![BootstrapEndpoint {
            url: "http://127.0.0.1:8443".to_string(),
            kind: BootstrapEndpointKind::ControlPlane,
        }],
        expires_at: now + chrono::Duration::minutes(30),
        not_before: now - chrono::Duration::seconds(1),
        role: if index < scenario.relay_count {
            Role::from_string("relay")
        } else {
            Role::edge()
        },
        tags: tags.clone(),
        issuer: issuer.clone(),
        key_id: key_id.clone(),
        policy: TokenPolicy {
            allow_relay: index < scenario.relay_count,
            allowed_routes: advertised_routes(index, scenario)?
                .into_iter()
                .map(|route| route.cidr)
                .collect(),
            allowed_tags: tags,
            ..TokenPolicy::default()
        },
        nonce: format!("load-nonce-{index}"),
    })
}

fn endpoint_candidates(index: usize, scenario: Scenario) -> Vec<EndpointCandidate> {
    let kind = if index < scenario.relay_count {
        EndpointCandidateKind::PublicUdp
    } else if index % 11 == 0 {
        EndpointCandidateKind::Ipv6
    } else {
        EndpointCandidateKind::StunReflexive
    };
    vec![EndpointCandidate {
        node_id: node_id(index),
        kind,
        addr: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, (index % 250 + 1) as u8)),
            30_000 + (index % 30_000) as u16,
        ),
        observed_at: Utc::now(),
        priority: 100,
        cost: if kind == EndpointCandidateKind::PublicUdp {
            5
        } else {
            20
        },
        source: CandidateSource::ControlPlane,
    }]
}

fn advertised_routes(index: usize, scenario: Scenario) -> anyhow::Result<Vec<Route>> {
    if index < scenario.relay_count || index >= scenario.relay_count + scenario.route_provider_count
    {
        return Ok(Vec::new());
    }

    let provider_index = index - scenario.relay_count;
    let mut tags = BTreeSet::new();
    tags.insert(Tag::from_string("route-provider"));
    let cidr = ipnet::Ipv4Net::new(Ipv4Addr::new(10, 128, provider_index as u8, 0), 24)
        .with_context(|| {
            format!("failed to build synthetic route for provider {provider_index}")
        })?;

    Ok(vec![Route {
        id: format!("load-route-{provider_index:04}"),
        cidr: ipnet::IpNet::V4(cidr),
        advertised_by: node_id(index),
        via: None,
        metric: 100 + provider_index as u32,
        tags,
    }])
}

fn active_pair_indices(pair_index: usize, node_count: usize) -> (usize, usize) {
    let directed_pair_count = node_count * (node_count - 1);
    let normalized_index = pair_index % directed_pair_count;
    let source_index = normalized_index / (node_count - 1);
    let target_rank = normalized_index % (node_count - 1);
    let target_index = if target_rank >= source_index {
        target_rank + 1
    } else {
        target_rank
    };
    (source_index, target_index)
}

fn relay_capability(index: usize, scenario: Scenario) -> Option<RelayCapability> {
    (index < scenario.relay_count).then(|| RelayCapability {
        enabled_by_policy: true,
        public_endpoint: Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, (index % 250 + 1) as u8)),
            51_820,
        )),
        admission_url: Some(format!("http://relay-{index}.load.test:9580")),
        max_sessions: 10_000,
        active_sessions: index as u32,
        max_mbps: 1_000,
        e2e_only: true,
    })
}

fn node_id(index: usize) -> NodeId {
    NodeId::from_string(format!("load-node-{index:04}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn load_harness_runs_three_node_scenario() -> anyhow::Result<()> {
        let report = run_in_memory_scenario(Scenario::from_name(ScenarioName::Three)).await?;

        assert_eq!(report.transport, TransportMode::InMemory);
        assert_eq!(report.node_count, 3);
        assert_eq!(report.registrations, 3);
        assert_eq!(report.relay_candidates, 1);
        assert_eq!(report.advertised_routes, 1);
        assert_eq!(report.peer_map_edges_seen, 6);
        assert_eq!(report.signal_negotiations, 6);
        assert_eq!(report.control_plane_http_requests, 0);
        assert_eq!(report.signal_http_requests, 0);
        Ok(())
    }

    #[tokio::test]
    async fn load_harness_can_drive_networked_http_endpoints() -> anyhow::Result<()> {
        let report = run_http_scenario(Scenario::from_name(ScenarioName::Three)).await?;

        assert_eq!(report.transport, TransportMode::Http);
        assert_eq!(report.node_count, 3);
        assert_eq!(report.registrations, 3);
        assert_eq!(report.relay_candidates, 1);
        assert_eq!(report.advertised_routes, 1);
        assert_eq!(report.peer_map_edges_seen, 6);
        assert_eq!(report.signal_negotiations, 6);
        assert_eq!(report.control_plane_http_requests, 6);
        assert_eq!(report.signal_http_requests, 9);
        Ok(())
    }

    #[test]
    fn active_pair_sampler_enumerates_directed_pairs_before_wrapping() {
        let pairs = (0..6)
            .map(|pair_index| active_pair_indices(pair_index, 3))
            .collect::<BTreeSet<_>>();

        assert_eq!(pairs.len(), 6);
        assert!(!pairs.iter().any(|(source, target)| source == target));
        assert_eq!(active_pair_indices(6, 3), active_pair_indices(0, 3));
    }

    #[tokio::test]
    async fn load_harness_uses_sampled_active_pairs_for_thousand_nodes() -> anyhow::Result<()> {
        let report = run_in_memory_scenario(Scenario::from_name(ScenarioName::Thousand)).await?;

        assert_eq!(report.transport, TransportMode::InMemory);
        assert_eq!(report.node_count, 1_000);
        assert_eq!(report.relay_candidates, 10);
        assert_eq!(report.advertised_routes, 25);
        assert_eq!(report.peer_map_edges_seen, 999_000);
        assert_eq!(report.signal_negotiations, 2_000);
        assert!(report.signal_negotiations < report.peer_map_edges_seen);
        Ok(())
    }
}
