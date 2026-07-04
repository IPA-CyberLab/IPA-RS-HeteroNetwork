use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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
    fn normalized(self) -> Self {
        Self {
            packets_per_session: self.packets_per_session.max(1),
            payload_bytes: self.payload_bytes.clamp(1, 60_000),
        }
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
            let _: HeartbeatResponse = post_json(
                &client,
                format!("{}/v1/heartbeat", services.control_plane_url),
                &heartbeat_request(&response.node),
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
    let options = options.normalized();
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
    let relay_options = relay_options.normalized();
    let agent_processes = requested_agent_processes.clamp(1, scenario.node_count);
    let issuer = IdentityKeyPair::generate();
    let key_id = KeyId::from_string("load-key");
    let cluster_id = ClusterId::from_string(format!("load-daemon-{:?}", scenario.name));
    let services = DaemonProcessGroup::start(
        iparsd_bin,
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
    let peer_map_millis = peer_map_started.elapsed().as_millis();

    for peer in &peer_records {
        let _: SignalNodeUpsertResponse = put_json(
            &client,
            format!("{}/v1/nodes/{}", services.signal_url, peer.node_id),
            &SignalNodeUpsertRequest {
                node: peer.clone(),
                nat_classification: None,
            },
            "daemon signal node upsert",
        )
        .await?;
    }

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
    children: Vec<Child>,
}

impl DaemonProcessGroup {
    async fn start(
        iparsd_bin: &Path,
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
        let control_addr = reserve_tcp_addr().await?;
        let signal_addr = reserve_tcp_addr().await?;
        let relay_http_addr = reserve_tcp_addr().await?;
        let relay_udp_addr = reserve_udp_addr().await?;
        let stun_addr = reserve_udp_addr().await?;
        let control_plane_url = format!("http://{control_addr}");
        let signal_url = format!("http://{signal_addr}");
        let relay_http_url = format!("http://{relay_http_addr}");
        let mut children = vec![
            spawn_iparsd(
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
            )?,
            spawn_iparsd(
                iparsd_bin,
                &[
                    "signal".to_string(),
                    "--listen".to_string(),
                    signal_addr.to_string(),
                ],
                "signal",
            )?,
            spawn_iparsd(
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
            )?,
            spawn_iparsd(
                iparsd_bin,
                &[
                    "stun".to_string(),
                    "--listen".to_string(),
                    stun_addr.to_string(),
                ],
                "stun",
            )?,
        ];

        let client = reqwest::Client::new();
        wait_for_http_ok(
            &client,
            format!("{control_plane_url}/healthz"),
            "control-plane",
        )
        .await?;
        wait_for_http_ok(&client, format!("{signal_url}/healthz"), "signal").await?;
        wait_for_http_ok(&client, format!("{relay_http_url}/healthz"), "relay").await?;

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
                Scenario::from_name(ScenarioName::Three),
            )?)?;
            children.push(spawn_iparsd(
                iparsd_bin,
                &[
                    "agent".to_string(),
                    "--listen".to_string(),
                    agent_addr.to_string(),
                    "--state-path".to_string(),
                    state_path.display().to_string(),
                    "--join-token".to_string(),
                    serde_json::to_string(&token)?,
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
            )?);
            wait_for_http_ok(&client, format!("{agent_url}/healthz"), "agent").await?;
            agent_urls.push(agent_url);
        }

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
}

impl Drop for DaemonProcessGroup {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.runtime_dir);
    }
}

fn spawn_iparsd(iparsd_bin: &Path, args: &[String], role: &str) -> anyhow::Result<Child> {
    Command::new(iparsd_bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to spawn iparsd {role} process"))
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
) -> anyhow::Result<()> {
    let mut last_error = None;
    for _ in 0..100 {
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
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("{context} readiness timed out")))
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
    Ok(RegisterNodeRequest {
        node_id: node_id(index),
        identity_public_key: format!("identity-public-{index}"),
        wireguard_public_key: format!("wireguard-public-{index}"),
        candidates: endpoint_candidates(index, scenario),
        relay_capability: relay_capability(index, scenario),
        requested_routes: advertised_routes(index, scenario)?,
    })
}

fn heartbeat_request(node: &NodeRecord) -> HeartbeatRequest {
    HeartbeatRequest {
        node_id: node.node_id.clone(),
        health: NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: Utc::now(),
            latency_ms: Some(1.0),
            relay_load: Some(0.10),
            message: None,
        },
        candidates: node.endpoint_candidates.clone(),
        relay_capability: None,
        path_state: Vec::new(),
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
