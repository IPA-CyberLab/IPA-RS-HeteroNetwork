use std::collections::BTreeSet;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use chrono::Utc;
use clap::{Parser, ValueEnum};
use ipars_control_plane::{
    ControlPlane, ControlPlaneConfig, ControlPlaneJoinService, InMemoryStore, InMemoryTokenLedger,
    IssuerKeyRing,
};
use ipars_control_plane_http::{router as control_plane_router, ControlPlaneHttpState};
use ipars_crypto::IdentityKeyPair;
use ipars_relay::{encode_relay_datagram, RelayService, UdpRelay};
use ipars_relay_http::{router as relay_router, RelayHttpState};
use ipars_signal::SignalRegistry;
use ipars_signal_http::{router as signal_router, SignalHttpState};
use ipars_types::api::{
    AgentStatusResponse, ControlPlaneMetricsResponse, HeartbeatRequest, HeartbeatResponse,
    JoinNodeRequest, PeerMap, RegisterNodeRequest, RegisterNodeResponse, RelayAdmissionRequest,
    RelayAdmissionResponse, RelayStatusResponse, SignalNodeUpsertRequest, SignalNodeUpsertResponse,
    SignalPathRequest, SignalPathResponse,
};
use ipars_types::{
    BootstrapEndpoint, BootstrapEndpointKind, CandidateSource, ClusterId, ClusterPolicy,
    EndpointCandidate, EndpointCandidateKind, HealthState, JoinTokenClaims, KeyId, NodeHealth,
    NodeId, NodeRecord, PathState, RelayCapability, Role, Route, Tag, TokenPolicy,
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;

static DAEMON_LOG_COUNTER: AtomicUsize = AtomicUsize::new(0);
const DAEMON_LOG_TAIL_BYTES: usize = 8192;
const DAEMON_LOG_TAIL_LINES: usize = 40;
const MAX_RELAY_PAYLOAD_BYTES: usize = 60_000;

#[derive(Debug, Parser)]
#[command(name = "ipars-load")]
#[command(about = "IPA-RS scale/load scenario harness")]
struct Cli {
    #[arg(long, value_enum, default_value_t = ScenarioName::Ten)]
    scenario: ScenarioName,

    #[arg(long, value_enum, default_value_t = TransportMode::InMemory)]
    transport: TransportMode,

    #[arg(long, default_value_t = 4)]
    relay_packets_per_session: usize,

    #[arg(long, default_value_t = 512)]
    relay_payload_bytes: usize,

    #[arg(long, default_value = "iparsd")]
    iparsd_bin: PathBuf,

    #[arg(long, default_value_t = 4)]
    daemon_agent_processes: usize,
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
    RelayUdp,
    Daemon,
}

#[derive(Debug, Clone, Copy)]
struct RelayLoadOptions {
    packets_per_session: usize,
    payload_bytes: usize,
}

impl RelayLoadOptions {
    fn validate(self) -> anyhow::Result<Self> {
        if self.packets_per_session == 0 {
            bail!("--relay-packets-per-session must be greater than zero");
        }
        if self.payload_bytes == 0 {
            bail!("--relay-payload-bytes must be greater than zero");
        }
        if self.payload_bytes > MAX_RELAY_PAYLOAD_BYTES {
            bail!(
                "--relay-payload-bytes must be at most {MAX_RELAY_PAYLOAD_BYTES} bytes for UDP load tests"
            );
        }
        Ok(self)
    }
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
    relay_http_requests: usize,
    relay_udp_sessions: usize,
    relay_packets_per_session: usize,
    relay_payload_bytes_per_packet: usize,
    relay_udp_packets_sent: usize,
    relay_udp_packets_received: usize,
    relay_udp_payload_bytes_sent: u64,
    relay_udp_payload_bytes_received: u64,
    relay_forwarded_bytes_reported: u64,
    relay_mbps: f64,
    daemon_processes: usize,
    daemon_agent_processes: usize,
    registration_millis: u128,
    peer_map_millis: u128,
    signal_millis: u128,
    relay_millis: u128,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let scenario = Scenario::from_name(cli.scenario);
    let report = match cli.transport {
        TransportMode::InMemory => run_in_memory_scenario(scenario).await?,
        TransportMode::Http => run_http_scenario(scenario).await?,
        TransportMode::RelayUdp => {
            run_relay_udp_scenario(
                scenario,
                RelayLoadOptions {
                    packets_per_session: cli.relay_packets_per_session,
                    payload_bytes: cli.relay_payload_bytes,
                },
            )
            .await?
        }
        TransportMode::Daemon => {
            run_daemon_scenario(
                scenario,
                &cli.iparsd_bin,
                cli.daemon_agent_processes,
                RelayLoadOptions {
                    packets_per_session: cli.relay_packets_per_session,
                    payload_bytes: cli.relay_payload_bytes,
                },
            )
            .await?
        }
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
        registry
            .upsert_node_with_nat_and_health(
                response.node.clone(),
                None,
                Some(healthy_node_health()),
            )
            .await;
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
                source_nat_classification: None,
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
        relay_http_requests: 0,
        relay_udp_sessions: 0,
        relay_packets_per_session: 0,
        relay_payload_bytes_per_packet: 0,
        relay_udp_packets_sent: 0,
        relay_udp_packets_received: 0,
        relay_udp_payload_bytes_sent: 0,
        relay_udp_payload_bytes_received: 0,
        relay_forwarded_bytes_reported: 0,
        relay_mbps: 0.0,
        daemon_processes: 0,
        daemon_agent_processes: 0,
        registration_millis,
        peer_map_millis,
        signal_millis,
        relay_millis: 0,
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
        if index < scenario.relay_count {
            let heartbeat = heartbeat_request(index, &response.node)?;
            let _: HeartbeatResponse = post_json(
                &client,
                format!("{}/v1/heartbeat", services.control_plane_url),
                &heartbeat,
                "control-plane heartbeat",
            )
            .await
            .with_context(|| format!("failed to heartbeat synthetic relay {index} over HTTP"))?;
        }
        let upsert_url = format!("{}/v1/nodes/{}", services.signal_url, response.node.node_id);
        let _: SignalNodeUpsertResponse = put_json(
            &client,
            upsert_url,
            &SignalNodeUpsertRequest {
                node: response.node.clone(),
                nat_classification: None,
                health: Some(healthy_node_health()),
            },
            "signal node upsert",
        )
        .await
        .with_context(|| format!("failed to upsert synthetic node {index} to signal over HTTP"))?;
        nodes.push(response.node);
    }
    let metrics: ControlPlaneMetricsResponse = get_json(
        &client,
        format!("{}/v1/metrics", services.control_plane_url),
        "control-plane metrics",
    )
    .await?;
    let relay_candidates = metrics.relay_candidate_count;
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
                source_nat_classification: None,
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
        control_plane_http_requests: nodes.len() * 2 + scenario.relay_count + 1,
        signal_http_requests: nodes.len() + scenario.active_pair_count,
        relay_http_requests: 0,
        relay_udp_sessions: 0,
        relay_packets_per_session: 0,
        relay_payload_bytes_per_packet: 0,
        relay_udp_packets_sent: 0,
        relay_udp_packets_received: 0,
        relay_udp_payload_bytes_sent: 0,
        relay_udp_payload_bytes_received: 0,
        relay_forwarded_bytes_reported: 0,
        relay_mbps: 0.0,
        daemon_processes: 0,
        daemon_agent_processes: 0,
        registration_millis,
        peer_map_millis,
        signal_millis,
        relay_millis: 0,
    })
}

async fn run_relay_udp_scenario(
    scenario: Scenario,
    options: RelayLoadOptions,
) -> anyhow::Result<LoadReport> {
    let options = options.validate()?;
    let services = RelayNetworkedServices::start().await?;
    let client = reqwest::Client::new();
    let left_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let right_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let left_addr = left_socket.local_addr()?;
    let right_addr = right_socket.local_addr()?;
    let mut receive_buffer = vec![0_u8; options.payload_bytes];

    let relay_started = Instant::now();
    let mut packets_sent = 0;
    let mut packets_received = 0;
    let mut payload_bytes_sent = 0_u64;
    let mut payload_bytes_received = 0_u64;
    for pair_index in 0..scenario.active_pair_count {
        let admission: RelayAdmissionResponse = post_json(
            &client,
            format!("{}/v1/sessions", services.http_url),
            &RelayAdmissionRequest {
                left: NodeId::from_string(format!("relay-left-{pair_index:04}")),
                right: NodeId::from_string(format!("relay-right-{pair_index:04}")),
                left_addr,
                right_addr,
            },
            "relay session admission",
        )
        .await?;

        for packet_index in 0..options.packets_per_session {
            let payload = relay_payload(pair_index, packet_index, options.payload_bytes);
            let datagram =
                encode_relay_datagram(&admission.session_id, &admission.session_token, &payload)?;
            left_socket.send_to(&datagram, services.udp_addr).await?;
            packets_sent += 1;
            payload_bytes_sent = payload_bytes_sent.saturating_add(payload.len() as u64);

            let (len, _) = tokio::time::timeout(
                Duration::from_secs(2),
                right_socket.recv_from(&mut receive_buffer),
            )
            .await
            .context("timed out waiting for relay UDP payload")??;
            if &receive_buffer[..len] != payload.as_slice() {
                bail!("relay UDP payload mismatch for pair {pair_index} packet {packet_index}");
            }
            packets_received += 1;
            payload_bytes_received = payload_bytes_received.saturating_add(len as u64);
        }
    }
    let relay_elapsed = relay_started.elapsed();
    let relay_millis = relay_elapsed.as_millis();
    let status: RelayStatusResponse = get_json(
        &client,
        format!("{}/v1/status", services.http_url),
        "relay status",
    )
    .await?;
    let metrics = get_text(
        &client,
        format!("{}/metrics", services.http_url),
        "relay metrics",
    )
    .await?;
    let forwarded_bytes = prometheus_metric_u64(&metrics, "ipars_relay_bytes_forwarded_total")?;
    let relay_mbps = if relay_elapsed.is_zero() {
        0.0
    } else {
        payload_bytes_received as f64 * 8.0 / relay_elapsed.as_secs_f64() / 1_000_000.0
    };

    Ok(LoadReport {
        transport: TransportMode::RelayUdp,
        scenario: scenario.name,
        node_count: scenario.node_count,
        relay_count: 1,
        route_provider_count: 0,
        advertised_routes: 0,
        active_pair_count: scenario.active_pair_count,
        registrations: 0,
        peer_map_requests: 0,
        peer_map_edges_seen: 0,
        signal_negotiations: 0,
        relay_candidates: 1,
        direct_public_paths: 0,
        direct_ipv6_paths: 0,
        direct_nat_paths: 0,
        relay_paths: scenario.active_pair_count,
        unreachable_paths: 0,
        control_plane_http_requests: 0,
        signal_http_requests: 0,
        relay_http_requests: scenario.active_pair_count + 2,
        relay_udp_sessions: status.capability.active_sessions as usize,
        relay_packets_per_session: options.packets_per_session,
        relay_payload_bytes_per_packet: options.payload_bytes,
        relay_udp_packets_sent: packets_sent,
        relay_udp_packets_received: packets_received,
        relay_udp_payload_bytes_sent: payload_bytes_sent,
        relay_udp_payload_bytes_received: payload_bytes_received,
        relay_forwarded_bytes_reported: forwarded_bytes,
        relay_mbps,
        daemon_processes: 0,
        daemon_agent_processes: 0,
        registration_millis: 0,
        peer_map_millis: 0,
        signal_millis: 0,
        relay_millis,
    })
}

async fn run_daemon_scenario(
    scenario: Scenario,
    iparsd_bin: &Path,
    requested_agent_processes: usize,
    relay_options: RelayLoadOptions,
) -> anyhow::Result<LoadReport> {
    let relay_options = relay_options.validate()?;
    let agent_processes = validate_daemon_agent_processes(requested_agent_processes, scenario)?;
    let issuer = IdentityKeyPair::generate();
    let key_id = KeyId::from_string("load-key");
    let cluster_id = ClusterId::from_string(format!("load-daemon-{:?}", scenario.name));
    let mut services = DaemonProcessGroup::start(
        iparsd_bin,
        scenario,
        cluster_id.clone(),
        &issuer,
        &key_id,
        agent_processes,
    )
    .await?;
    let client = reqwest::Client::new();

    let registration_started = Instant::now();
    let mut agent_statuses: Vec<AgentStatusResponse> = Vec::with_capacity(agent_processes);
    for url in &services.agent_urls {
        agent_statuses
            .push(get_json(&client, format!("{url}/v1/status"), "daemon agent status").await?);
    }
    services.ensure_running()?;
    let registration_millis = registration_started.elapsed().as_millis();

    let peer_map_started = Instant::now();
    let mut peer_map_edges_seen = 0;
    let mut peer_records = Vec::new();
    for status in &agent_statuses {
        let peer_map: PeerMap = get_json(
            &client,
            format!("{}/v1/peers/{}", services.control_plane_url, status.node_id),
            "daemon control-plane peer map",
        )
        .await?;
        peer_map_edges_seen += peer_map.peers.len();
        peer_records.extend(peer_map.peers);
    }
    services.ensure_running()?;
    let peer_map_millis = peer_map_started.elapsed().as_millis();

    for peer in &peer_records {
        let _: SignalNodeUpsertResponse = put_json(
            &client,
            format!("{}/v1/nodes/{}", services.signal_url, peer.node_id),
            &SignalNodeUpsertRequest {
                node: peer.clone(),
                nat_classification: None,
                health: Some(healthy_node_health()),
            },
            "daemon signal node upsert",
        )
        .await?;
    }
    services.ensure_running()?;

    let signal_started = Instant::now();
    let advertised_routes = peer_records.iter().map(|node| node.routes.len()).sum();
    let active_pair_count = if agent_statuses.len() > 1 {
        scenario.active_pair_count
    } else {
        0
    };
    let mut path_counts = PathCounts::default();
    for pair_index in 0..active_pair_count {
        let (source_index, target_index) = active_pair_indices(pair_index, agent_statuses.len());
        let source = &agent_statuses[source_index];
        let target = &agent_statuses[target_index];
        let response: SignalPathResponse = post_json(
            &client,
            format!("{}/v1/paths/negotiate", services.signal_url),
            &SignalPathRequest {
                source: source.node_id.clone(),
                target: target.node_id.clone(),
                source_candidates: source.candidates.clone(),
                source_nat_classification: source.nat_classification.clone(),
                desired_routes: Vec::new(),
            },
            "daemon signal path negotiation",
        )
        .await?;
        path_counts.record(response.preferred_state);
    }
    services.ensure_running()?;
    let signal_millis = signal_started.elapsed().as_millis();

    let relay_started = Instant::now();
    let left_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let right_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let left_addr = left_socket.local_addr()?;
    let right_addr = right_socket.local_addr()?;
    let mut relay_packets_sent = 0;
    let mut relay_packets_received = 0;
    let mut relay_payload_bytes_sent = 0_u64;
    let mut relay_payload_bytes_received = 0_u64;
    let mut receive_buffer = vec![0_u8; relay_options.payload_bytes];
    for pair_index in 0..active_pair_count {
        let admission: RelayAdmissionResponse = post_json(
            &client,
            format!("{}/v1/sessions", services.relay_http_url),
            &RelayAdmissionRequest {
                left: NodeId::from_string(format!("daemon-left-{pair_index:04}")),
                right: NodeId::from_string(format!("daemon-right-{pair_index:04}")),
                left_addr,
                right_addr,
            },
            "daemon relay admission",
        )
        .await?;
        for packet_index in 0..relay_options.packets_per_session {
            let payload = relay_payload(pair_index, packet_index, relay_options.payload_bytes);
            let datagram =
                encode_relay_datagram(&admission.session_id, &admission.session_token, &payload)?;
            left_socket
                .send_to(&datagram, services.relay_udp_addr)
                .await?;
            relay_packets_sent += 1;
            relay_payload_bytes_sent =
                relay_payload_bytes_sent.saturating_add(payload.len() as u64);
            let (len, _) = tokio::time::timeout(
                Duration::from_secs(2),
                right_socket.recv_from(&mut receive_buffer),
            )
            .await
            .context("timed out waiting for daemon relay UDP payload")??;
            if &receive_buffer[..len] != payload.as_slice() {
                bail!(
                    "daemon relay UDP payload mismatch for pair {pair_index} packet {packet_index}"
                );
            }
            relay_packets_received += 1;
            relay_payload_bytes_received = relay_payload_bytes_received.saturating_add(len as u64);
        }
    }
    services.ensure_running()?;
    let relay_elapsed = relay_started.elapsed();
    let relay_millis = relay_elapsed.as_millis();
    let status: RelayStatusResponse = get_json(
        &client,
        format!("{}/v1/status", services.relay_http_url),
        "daemon relay status",
    )
    .await?;
    let metrics = get_text(
        &client,
        format!("{}/metrics", services.relay_http_url),
        "daemon relay metrics",
    )
    .await?;
    let forwarded_bytes = prometheus_metric_u64(&metrics, "ipars_relay_bytes_forwarded_total")?;
    let relay_mbps = if relay_elapsed.is_zero() {
        0.0
    } else {
        relay_payload_bytes_received as f64 * 8.0 / relay_elapsed.as_secs_f64() / 1_000_000.0
    };

    Ok(LoadReport {
        transport: TransportMode::Daemon,
        scenario: scenario.name,
        node_count: agent_statuses.len(),
        relay_count: 1,
        route_provider_count: 0,
        advertised_routes,
        active_pair_count,
        registrations: agent_statuses.len(),
        peer_map_requests: agent_statuses.len(),
        peer_map_edges_seen,
        signal_negotiations: active_pair_count,
        relay_candidates: 1,
        direct_public_paths: path_counts.direct_public,
        direct_ipv6_paths: path_counts.direct_ipv6,
        direct_nat_paths: path_counts.direct_nat,
        relay_paths: path_counts.relay,
        unreachable_paths: path_counts.unreachable,
        control_plane_http_requests: agent_statuses.len() + agent_statuses.len(),
        signal_http_requests: peer_records.len() + active_pair_count,
        relay_http_requests: active_pair_count + 2,
        relay_udp_sessions: status.capability.active_sessions as usize,
        relay_packets_per_session: relay_options.packets_per_session,
        relay_payload_bytes_per_packet: relay_options.payload_bytes,
        relay_udp_packets_sent: relay_packets_sent,
        relay_udp_packets_received: relay_packets_received,
        relay_udp_payload_bytes_sent: relay_payload_bytes_sent,
        relay_udp_payload_bytes_received: relay_payload_bytes_received,
        relay_forwarded_bytes_reported: forwarded_bytes,
        relay_mbps,
        daemon_processes: services.process_count(),
        daemon_agent_processes: agent_processes,
        registration_millis,
        peer_map_millis,
        signal_millis,
        relay_millis,
    })
}

fn validate_daemon_agent_processes(
    requested_agent_processes: usize,
    scenario: Scenario,
) -> anyhow::Result<usize> {
    if requested_agent_processes == 0 {
        bail!("--daemon-agent-processes must be greater than zero");
    }
    if requested_agent_processes > scenario.node_count {
        bail!(
            "--daemon-agent-processes ({requested_agent_processes}) cannot exceed scenario node count ({})",
            scenario.node_count
        );
    }
    Ok(requested_agent_processes)
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

struct RelayNetworkedServices {
    http_url: String,
    udp_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    http_task: JoinHandle<std::io::Result<()>>,
    udp_task: JoinHandle<Result<(), ipars_relay::RelayError>>,
}

impl RelayNetworkedServices {
    async fn start() -> anyhow::Result<Self> {
        let udp_relay = UdpRelay::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
        let udp_addr = udp_relay.local_addr()?;
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await?;
        let http_addr = listener.local_addr()?;
        let service = Arc::new(RelayService::new(
            NodeId::from_string("relay-load"),
            RelayCapability {
                enabled_by_policy: true,
                public_endpoint: Some(udp_addr),
                admission_url: Some(format!("http://{http_addr}")),
                max_sessions: 10_000,
                active_sessions: 0,
                max_mbps: 10_000,
                e2e_only: true,
            },
        ));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let udp_task = tokio::spawn(udp_relay.serve(service.table(), shutdown_rx));
        let app = relay_router(RelayHttpState::new(service));
        let http_task = tokio::spawn(async move { axum::serve(listener, app).await });

        Ok(Self {
            http_url: format!("http://{http_addr}"),
            udp_addr,
            shutdown_tx,
            http_task,
            udp_task,
        })
    }
}

impl Drop for RelayNetworkedServices {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        self.http_task.abort();
        self.udp_task.abort();
    }
}

struct DaemonProcessGroup {
    control_plane_url: String,
    signal_url: String,
    relay_http_url: String,
    relay_udp_addr: SocketAddr,
    agent_urls: Vec<String>,
    runtime_dir: PathBuf,
    children: Vec<DaemonChild>,
}

impl DaemonProcessGroup {
    async fn start(
        iparsd_bin: &Path,
        scenario: Scenario,
        cluster_id: ClusterId,
        issuer: &IdentityKeyPair,
        key_id: &KeyId,
        agent_processes: usize,
    ) -> anyhow::Result<Self> {
        if !iparsd_bin.exists() && iparsd_bin.components().count() > 1 {
            bail!("iparsd binary does not exist at {}", iparsd_bin.display());
        }
        let runtime_dir = daemon_runtime_dir()?;
        std::fs::create_dir_all(&runtime_dir)?;
        let mut startup = DaemonStartupGuard::new(runtime_dir.clone());
        let control_addr = reserve_tcp_addr().await?;
        let signal_addr = reserve_tcp_addr().await?;
        let relay_http_addr = reserve_tcp_addr().await?;
        let relay_udp_addr = reserve_udp_addr().await?;
        let stun_addr = reserve_udp_addr().await?;
        let control_plane_url = format!("http://{control_addr}");
        let signal_url = format!("http://{signal_addr}");
        let relay_http_url = format!("http://{relay_http_addr}");
        startup.children.push(spawn_iparsd(
            iparsd_bin,
            &[
                "control-plane".to_string(),
                "--listen".to_string(),
                control_addr.to_string(),
                "--cluster-id".to_string(),
                cluster_id.to_string(),
                "--issuer-node-id".to_string(),
                issuer.node_id().to_string(),
                "--issuer-key-id".to_string(),
                key_id.to_string(),
                "--issuer-public-key".to_string(),
                issuer.public_key_b64(),
            ],
            "control-plane",
            &runtime_dir,
        )?);
        startup.children.push(spawn_iparsd(
            iparsd_bin,
            &[
                "signal".to_string(),
                "--listen".to_string(),
                signal_addr.to_string(),
            ],
            "signal",
            &runtime_dir,
        )?);
        startup.children.push(spawn_iparsd(
            iparsd_bin,
            &[
                "relay".to_string(),
                "--relay-node-id".to_string(),
                "daemon-relay".to_string(),
                "--udp-listen".to_string(),
                relay_udp_addr.to_string(),
                "--http-listen".to_string(),
                relay_http_addr.to_string(),
                "--public-endpoint".to_string(),
                relay_udp_addr.to_string(),
                "--admission-url".to_string(),
                relay_http_url.clone(),
                "--max-sessions".to_string(),
                "10000".to_string(),
                "--max-mbps".to_string(),
                "10000".to_string(),
            ],
            "relay",
            &runtime_dir,
        )?);
        startup.children.push(spawn_iparsd(
            iparsd_bin,
            &[
                "stun".to_string(),
                "--listen".to_string(),
                stun_addr.to_string(),
            ],
            "stun",
            &runtime_dir,
        )?);

        let client = reqwest::Client::new();
        wait_for_http_ok(
            &client,
            format!("{control_plane_url}/healthz"),
            "control-plane",
            &mut startup.children,
        )
        .await?;
        wait_for_http_ok(
            &client,
            format!("{signal_url}/healthz"),
            "signal",
            &mut startup.children,
        )
        .await?;
        wait_for_http_ok(
            &client,
            format!("{relay_http_url}/healthz"),
            "relay",
            &mut startup.children,
        )
        .await?;

        let mut agent_urls = Vec::with_capacity(agent_processes);
        for index in 0..agent_processes {
            let agent_addr = reserve_tcp_addr().await?;
            let agent_url = format!("http://{agent_addr}");
            let state_path = runtime_dir.join(format!("agent-{index:04}.json"));
            let token = issuer.sign_join_token(join_claims(
                &cluster_id,
                &issuer.node_id(),
                key_id,
                index,
                scenario,
            )?)?;
            let token_path = write_daemon_join_token(&runtime_dir, index, &token)?;
            startup.children.push(spawn_iparsd(
                iparsd_bin,
                &[
                    "agent".to_string(),
                    "--listen".to_string(),
                    agent_addr.to_string(),
                    "--state-path".to_string(),
                    state_path.display().to_string(),
                    "--join-token-path".to_string(),
                    token_path.display().to_string(),
                    "--control-plane-url".to_string(),
                    control_plane_url.clone(),
                    "--signal-url".to_string(),
                    signal_url.clone(),
                    "--stun-server".to_string(),
                    stun_addr.to_string(),
                    "--runtime-backend".to_string(),
                    "dry-run".to_string(),
                    "--skip-runtime-preflight".to_string(),
                    "--apply-peer-map".to_string(),
                    "--peer-map-poll-interval-seconds".to_string(),
                    "1".to_string(),
                    "--heartbeat-interval-seconds".to_string(),
                    "1".to_string(),
                    "--signal-registration-interval-seconds".to_string(),
                    "1".to_string(),
                    "--signal-path-interval-seconds".to_string(),
                    "1".to_string(),
                ],
                "agent",
                &runtime_dir,
            )?);
            wait_for_http_ok(
                &client,
                format!("{agent_url}/healthz"),
                "agent",
                &mut startup.children,
            )
            .await?;
            agent_urls.push(agent_url);
        }
        wait_for_daemon_agents_ready(
            &client,
            &control_plane_url,
            &signal_url,
            &agent_urls,
            &mut startup.children,
        )
        .await?;

        let children = startup.finish();
        Ok(Self {
            control_plane_url,
            signal_url,
            relay_http_url,
            relay_udp_addr,
            agent_urls,
            runtime_dir,
            children,
        })
    }

    fn process_count(&self) -> usize {
        self.children.len()
    }

    fn ensure_running(&mut self) -> anyhow::Result<()> {
        ensure_daemon_children_running(&mut self.children)
    }
}

impl Drop for DaemonProcessGroup {
    fn drop(&mut self) {
        kill_daemon_children(&mut self.children);
        let _ = std::fs::remove_dir_all(&self.runtime_dir);
    }
}

struct DaemonStartupGuard {
    runtime_dir: PathBuf,
    children: Vec<DaemonChild>,
    active: bool,
}

impl DaemonStartupGuard {
    fn new(runtime_dir: PathBuf) -> Self {
        Self {
            runtime_dir,
            children: Vec::new(),
            active: true,
        }
    }

    fn finish(mut self) -> Vec<DaemonChild> {
        self.active = false;
        std::mem::take(&mut self.children)
    }
}

impl Drop for DaemonStartupGuard {
    fn drop(&mut self) {
        if self.active {
            kill_daemon_children(&mut self.children);
            let _ = std::fs::remove_dir_all(&self.runtime_dir);
        }
    }
}

struct DaemonChild {
    role: String,
    child: Child,
    log_path: Option<PathBuf>,
}

fn spawn_iparsd(
    iparsd_bin: &Path,
    args: &[String],
    role: &str,
    runtime_dir: &Path,
) -> anyhow::Result<DaemonChild> {
    let log_path = daemon_child_log_path(runtime_dir, role);
    let mut log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("failed to open iparsd {role} log at {}", log_path.display()))?;
    writeln!(log_file, "ipars-load starting iparsd {role}")
        .with_context(|| format!("failed to write iparsd {role} log header"))?;
    let stdout = log_file
        .try_clone()
        .with_context(|| format!("failed to clone iparsd {role} log for stdout"))?;
    let stderr = log_file
        .try_clone()
        .with_context(|| format!("failed to clone iparsd {role} log for stderr"))?;
    let child = Command::new(iparsd_bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| {
            format!(
                "failed to spawn iparsd {role} process; log={}",
                log_path.display()
            )
        })?;
    Ok(DaemonChild {
        role: role.to_string(),
        child,
        log_path: Some(log_path),
    })
}

fn kill_daemon_children(children: &mut [DaemonChild]) {
    for daemon_child in children {
        let _ = daemon_child.child.kill();
        let _ = daemon_child.child.wait();
    }
}

fn ensure_daemon_children_running(children: &mut [DaemonChild]) -> anyhow::Result<()> {
    for daemon_child in children {
        if let Some(status) = daemon_child.child.try_wait().with_context(|| {
            format!(
                "failed to inspect iparsd {} process status",
                daemon_child.role
            )
        })? {
            let log_tail = daemon_child
                .log_tail()
                .map(|tail| format!("\n{tail}"))
                .unwrap_or_default();
            bail!(
                "iparsd {} process exited before daemon load scenario completed: {}{}",
                daemon_child.role,
                status,
                log_tail
            );
        }
    }
    Ok(())
}

impl DaemonChild {
    fn log_tail(&self) -> Option<String> {
        let path = self.log_path.as_ref()?;
        match daemon_log_tail(path) {
            Ok(tail) if !tail.trim().is_empty() => Some(format!(
                "iparsd {} log tail ({}):\n{}",
                self.role,
                path.display(),
                tail
            )),
            Ok(_) => Some(format!(
                "iparsd {} log tail ({}) is empty",
                self.role,
                path.display()
            )),
            Err(error) => Some(format!(
                "iparsd {} log tail unavailable ({}): {error}",
                self.role,
                path.display()
            )),
        }
    }
}

fn daemon_children_log_summary(children: &[DaemonChild]) -> String {
    let summaries = children
        .iter()
        .filter_map(DaemonChild::log_tail)
        .collect::<Vec<_>>();
    if summaries.is_empty() {
        "daemon logs unavailable".to_string()
    } else {
        summaries.join("\n---\n")
    }
}

fn daemon_log_tail(path: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read daemon log {}", path.display()))?;
    let start = bytes.len().saturating_sub(DAEMON_LOG_TAIL_BYTES);
    let text = String::from_utf8_lossy(&bytes[start..]);
    let mut lines = text
        .lines()
        .rev()
        .take(DAEMON_LOG_TAIL_LINES)
        .collect::<Vec<_>>();
    lines.reverse();
    Ok(lines.join("\n"))
}

fn daemon_child_log_path(runtime_dir: &Path, role: &str) -> PathBuf {
    let serial = DAEMON_LOG_COUNTER.fetch_add(1, Ordering::Relaxed);
    let sanitized_role = role
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    runtime_dir.join(format!("{serial:04}-{sanitized_role}.log"))
}

fn write_daemon_join_token<Token: Serialize>(
    runtime_dir: &Path,
    agent_index: usize,
    token: &Token,
) -> anyhow::Result<PathBuf> {
    let token_path = runtime_dir.join(format!("agent-{agent_index:04}.join-token.json"));
    let token_json = serde_json::to_vec(token).context("failed to serialize daemon join token")?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&token_path).with_context(|| {
        format!(
            "failed to create daemon join token {}",
            token_path.display()
        )
    })?;
    file.write_all(&token_json)
        .with_context(|| format!("failed to write daemon join token {}", token_path.display()))?;
    file.write_all(b"\n").with_context(|| {
        format!(
            "failed to finalize daemon join token {}",
            token_path.display()
        )
    })?;
    file.sync_all()
        .with_context(|| format!("failed to sync daemon join token {}", token_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "failed to set daemon join token permissions on {}",
                    token_path.display()
                )
            })?;
    }
    Ok(token_path)
}

fn daemon_runtime_dir() -> anyhow::Result<PathBuf> {
    let unique = format!(
        "ipars-load-daemon-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    Ok(std::env::temp_dir().join(unique))
}

async fn reserve_tcp_addr() -> anyhow::Result<SocketAddr> {
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    Ok(listener.local_addr()?)
}

async fn reserve_udp_addr() -> anyhow::Result<SocketAddr> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    Ok(socket.local_addr()?)
}

async fn wait_for_http_ok(
    client: &reqwest::Client,
    url: String,
    context: &str,
    children: &mut [DaemonChild],
) -> anyhow::Result<()> {
    let mut last_error = None;
    for _ in 0..100 {
        ensure_daemon_children_running(children)?;
        match client.get(&url).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => {
                last_error = Some(anyhow::anyhow!(
                    "{context} readiness returned {}",
                    response.status()
                ));
            }
            Err(error) => {
                last_error = Some(error.into());
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let error = last_error.unwrap_or_else(|| anyhow::anyhow!("{context} readiness timed out"));
    bail!(
        "{context} readiness failed: {error}\n{}",
        daemon_children_log_summary(children)
    )
}

async fn wait_for_daemon_agents_ready(
    client: &reqwest::Client,
    control_plane_url: &str,
    signal_url: &str,
    agent_urls: &[String],
    children: &mut [DaemonChild],
) -> anyhow::Result<()> {
    let mut last_error = None;
    for _ in 0..150 {
        ensure_daemon_children_running(children)?;
        match daemon_agent_statuses(client, agent_urls).await {
            Ok(statuses) => match check_daemon_agent_control_and_signal_readiness(
                client,
                control_plane_url,
                signal_url,
                &statuses,
            )
            .await
            {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            },
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let error = last_error.unwrap_or_else(|| anyhow::anyhow!("daemon agent readiness timed out"));
    bail!(
        "daemon agent readiness failed: {error}\n{}",
        daemon_children_log_summary(children)
    )
}

async fn daemon_agent_statuses(
    client: &reqwest::Client,
    agent_urls: &[String],
) -> anyhow::Result<Vec<AgentStatusResponse>> {
    let mut statuses = Vec::with_capacity(agent_urls.len());
    for url in agent_urls {
        statuses.push(
            get_json(
                client,
                format!("{url}/v1/status"),
                "daemon agent readiness status",
            )
            .await?,
        );
    }
    Ok(statuses)
}

async fn check_daemon_agent_control_and_signal_readiness(
    client: &reqwest::Client,
    control_plane_url: &str,
    signal_url: &str,
    statuses: &[AgentStatusResponse],
) -> anyhow::Result<()> {
    for status in statuses {
        let peer_map: PeerMap = get_json(
            client,
            format!("{control_plane_url}/v1/peers/{}", status.node_id),
            "daemon control-plane readiness peer map",
        )
        .await?;
        let expected_peer_count = statuses.len().saturating_sub(1);
        if peer_map.peers.len() < expected_peer_count {
            bail!(
                "daemon control-plane peer map for {} has {} peers; expected at least {}",
                status.node_id,
                peer_map.peers.len(),
                expected_peer_count
            );
        }
    }

    if statuses.len() >= 2 {
        let source = &statuses[0];
        let target = &statuses[1];
        let _: SignalPathResponse = post_json(
            client,
            format!("{signal_url}/v1/paths/negotiate"),
            &SignalPathRequest {
                source: source.node_id.clone(),
                target: target.node_id.clone(),
                source_candidates: source.candidates.clone(),
                source_nat_classification: source.nat_classification.clone(),
                desired_routes: Vec::new(),
            },
            "daemon signal readiness negotiation",
        )
        .await?;
    }

    Ok(())
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

async fn get_text(client: &reqwest::Client, url: String, context: &str) -> anyhow::Result<String> {
    client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to send {context} request"))?
        .error_for_status()
        .with_context(|| format!("{context} request was rejected"))?
        .text()
        .await
        .with_context(|| format!("failed to decode {context} response"))
}

fn prometheus_metric_u64(body: &str, metric_name: &str) -> anyhow::Result<u64> {
    for line in body.lines() {
        if line.starts_with(metric_name) {
            let value = line
                .split_whitespace()
                .last()
                .with_context(|| format!("missing value for metric {metric_name}"))?;
            return value
                .parse()
                .with_context(|| format!("failed to parse metric {metric_name} value"));
        }
    }

    bail!("metric {metric_name} was not present in relay metrics response")
}

fn relay_payload(pair_index: usize, packet_index: usize, payload_bytes: usize) -> Vec<u8> {
    let mut payload = vec![0_u8; payload_bytes];
    for (offset, byte) in payload.iter_mut().enumerate() {
        *byte = ((pair_index + packet_index + offset) % 251) as u8;
    }
    payload
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
    let identity = identity_for_index(index);
    let node_id = identity.node_id();
    Ok(RegisterNodeRequest {
        node_id,
        identity_public_key: identity.public_key_b64(),
        wireguard_public_key: format!("wireguard-public-{index}"),
        candidates: endpoint_candidates(index, scenario),
        relay_capability: relay_capability(index, scenario),
        requested_routes: advertised_routes(index, scenario)?,
    })
}

fn heartbeat_request(index: usize, node: &NodeRecord) -> anyhow::Result<HeartbeatRequest> {
    let mut request = HeartbeatRequest {
        node_id: node.node_id.clone(),
        health: healthy_node_health(),
        candidates: node.endpoint_candidates.clone(),
        relay_capability: None,
        path_state: Vec::new(),
        node_signature: None,
    };
    request.node_signature = Some(
        identity_for_index(index)
            .sign_heartbeat_request(&request, Utc::now())
            .context("failed to sign synthetic load heartbeat")?,
    );
    Ok(request)
}

fn healthy_node_health() -> NodeHealth {
    NodeHealth {
        state: HealthState::Healthy,
        last_seen_at: Utc::now(),
        latency_ms: Some(1.0),
        relay_load: Some(0.10),
        message: None,
    }
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
    } else if index.is_multiple_of(11) {
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
    identity_for_index(index).node_id()
}

fn identity_for_index(index: usize) -> IdentityKeyPair {
    let label = format!("load-node-{index:04}");
    let mut seed = [0_u8; 32];
    for (index, byte) in label.as_bytes().iter().enumerate() {
        seed[index % seed.len()] = seed[index % seed.len()].wrapping_add(*byte);
    }
    if seed.iter().all(|byte| *byte == 0) {
        seed[0] = 1;
    }
    IdentityKeyPair::from_signing_bytes(seed)
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
        assert_eq!(report.control_plane_http_requests, 8);
        assert_eq!(report.signal_http_requests, 9);
        Ok(())
    }

    #[tokio::test]
    async fn load_harness_can_measure_relay_udp_throughput() -> anyhow::Result<()> {
        let report = run_relay_udp_scenario(
            Scenario::from_name(ScenarioName::Three),
            RelayLoadOptions {
                packets_per_session: 2,
                payload_bytes: 64,
            },
        )
        .await?;

        assert_eq!(report.transport, TransportMode::RelayUdp);
        assert_eq!(report.relay_udp_sessions, 6);
        assert_eq!(report.relay_packets_per_session, 2);
        assert_eq!(report.relay_payload_bytes_per_packet, 64);
        assert_eq!(report.relay_udp_packets_sent, 12);
        assert_eq!(report.relay_udp_packets_received, 12);
        assert_eq!(report.relay_udp_payload_bytes_sent, 768);
        assert_eq!(report.relay_udp_payload_bytes_received, 768);
        assert_eq!(report.relay_forwarded_bytes_reported, 768);
        assert_eq!(report.relay_http_requests, 8);
        Ok(())
    }

    #[test]
    fn relay_load_options_reject_invalid_bounds() -> anyhow::Result<()> {
        let zero_packets = match (RelayLoadOptions {
            packets_per_session: 0,
            payload_bytes: 64,
        }
        .validate())
        {
            Ok(_) => bail!("zero relay packet count should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(zero_packets.contains("--relay-packets-per-session"));

        let zero_payload = match (RelayLoadOptions {
            packets_per_session: 1,
            payload_bytes: 0,
        }
        .validate())
        {
            Ok(_) => bail!("zero relay payload size should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(zero_payload.contains("--relay-payload-bytes"));

        let oversized_payload = match (RelayLoadOptions {
            packets_per_session: 1,
            payload_bytes: MAX_RELAY_PAYLOAD_BYTES + 1,
        }
        .validate())
        {
            Ok(_) => bail!("oversized relay payload should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(oversized_payload.contains("at most 60000 bytes"));

        let valid = RelayLoadOptions {
            packets_per_session: 3,
            payload_bytes: MAX_RELAY_PAYLOAD_BYTES,
        }
        .validate()?;
        assert_eq!(valid.packets_per_session, 3);
        assert_eq!(valid.payload_bytes, MAX_RELAY_PAYLOAD_BYTES);
        Ok(())
    }

    #[test]
    fn daemon_agent_processes_reject_invalid_scenario_bounds() -> anyhow::Result<()> {
        let scenario = Scenario::from_name(ScenarioName::Three);

        let zero = match validate_daemon_agent_processes(0, scenario) {
            Ok(_) => bail!("zero daemon agent process count should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(zero.contains("--daemon-agent-processes"));

        let too_many = match validate_daemon_agent_processes(4, scenario) {
            Ok(_) => bail!("oversized daemon agent process count should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(too_many.contains("cannot exceed scenario node count"));

        assert_eq!(validate_daemon_agent_processes(3, scenario)?, 3);
        Ok(())
    }

    #[test]
    fn daemon_join_claims_follow_requested_scenario_distribution() -> anyhow::Result<()> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("load-key");
        let cluster_id = ClusterId::from_string("load-scenario");
        let three_node_claims = join_claims(
            &cluster_id,
            &issuer.node_id(),
            &key_id,
            1,
            Scenario::from_name(ScenarioName::Three),
        )?;
        let ten_node_claims = join_claims(
            &cluster_id,
            &issuer.node_id(),
            &key_id,
            1,
            Scenario::from_name(ScenarioName::Ten),
        )?;

        assert!(!three_node_claims.policy.allow_relay);
        assert!(three_node_claims
            .tags
            .contains(&Tag::from_string("route-provider")));
        assert!(ten_node_claims.policy.allow_relay);
        assert_eq!(ten_node_claims.role, Role::from_string("relay"));
        assert!(ten_node_claims.tags.contains(&Tag::from_string("public")));
        Ok(())
    }

    #[tokio::test]
    async fn daemon_readiness_checks_control_plane_and_signal_visibility() -> anyhow::Result<()> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("load-key");
        let cluster_id = ClusterId::from_string("load-readiness");
        let scenario = Scenario::from_name(ScenarioName::Three);
        let services = NetworkedServices::start(cluster_id.clone(), &issuer, &key_id).await?;
        let client = reqwest::Client::new();
        let mut statuses = Vec::new();

        for index in 0..2 {
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
                "readiness control-plane join",
            )
            .await?;
            let _: SignalNodeUpsertResponse = put_json(
                &client,
                format!("{}/v1/nodes/{}", services.signal_url, response.node.node_id),
                &SignalNodeUpsertRequest {
                    node: response.node.clone(),
                    nat_classification: None,
                    health: Some(healthy_node_health()),
                },
                "readiness signal node upsert",
            )
            .await?;
            statuses.push(AgentStatusResponse {
                node_id: response.node.node_id.clone(),
                identity_public_key: response.node.identity_public_key,
                wireguard_public_key: response.node.wireguard_public_key,
                candidate_count: response.node.endpoint_candidates.len(),
                candidates: response.node.endpoint_candidates,
                nat_classification: None,
                state_updated_at: Utc::now(),
            });
        }

        check_daemon_agent_control_and_signal_readiness(
            &client,
            &services.control_plane_url,
            &services.signal_url,
            &statuses,
        )
        .await
    }

    #[test]
    fn daemon_child_liveness_reports_role_and_exit_status() -> anyhow::Result<()> {
        let log_path = std::env::temp_dir().join(format!(
            "ipars-load-synthetic-child-{}-{}.log",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&log_path, "first line\nchild diagnostic line\n").with_context(|| {
            format!("failed to write synthetic child log {}", log_path.display())
        })?;
        let child = Command::new("sh")
            .args(["-c", "exit 7"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn synthetic daemon child")?;
        let mut children = vec![DaemonChild {
            role: "synthetic".to_string(),
            child,
            log_path: Some(log_path.clone()),
        }];

        for _ in 0..50 {
            match ensure_daemon_children_running(&mut children) {
                Ok(()) => std::thread::sleep(Duration::from_millis(10)),
                Err(error) => {
                    let message = error.to_string();
                    assert!(message.contains("iparsd synthetic process exited"));
                    assert!(message.contains("7"));
                    assert!(message.contains("child diagnostic line"));
                    let _ = std::fs::remove_file(&log_path);
                    return Ok(());
                }
            }
        }

        let _ = children[0].child.kill();
        let _ = children[0].child.wait();
        let _ = std::fs::remove_file(&log_path);
        bail!("synthetic daemon child did not exit before liveness timeout")
    }

    #[test]
    fn daemon_join_token_writer_uses_private_runtime_file() -> anyhow::Result<()> {
        let runtime_dir = std::env::temp_dir().join(format!(
            "ipars-load-token-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&runtime_dir)?;
        let token = serde_json::json!({
            "token": "sensitive",
            "signature": "test-signature",
        });

        let token_path = write_daemon_join_token(&runtime_dir, 7, &token)?;

        assert_eq!(
            token_path.file_name().and_then(|name| name.to_str()),
            Some("agent-0007.join-token.json")
        );
        let contents = std::fs::read_to_string(&token_path)?;
        assert!(contents.contains("\"sensitive\""));
        assert!(contents.ends_with('\n'));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&token_path)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn load_harness_can_drive_daemon_processes_when_binary_is_provided() -> anyhow::Result<()>
    {
        let Some(iparsd_bin) = std::env::var_os("IPARS_TEST_IPARSD_BIN").map(PathBuf::from) else {
            return Ok(());
        };

        let report = run_daemon_scenario(
            Scenario::from_name(ScenarioName::Three),
            &iparsd_bin,
            2,
            RelayLoadOptions {
                packets_per_session: 1,
                payload_bytes: 64,
            },
        )
        .await?;

        assert_eq!(report.transport, TransportMode::Daemon);
        assert_eq!(report.daemon_agent_processes, 2);
        assert_eq!(report.registrations, 2);
        assert_eq!(report.daemon_processes, 6);
        assert_eq!(report.relay_udp_packets_sent, report.active_pair_count);
        assert_eq!(report.relay_udp_packets_received, report.active_pair_count);
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
