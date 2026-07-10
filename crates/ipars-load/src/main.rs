use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
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
use ipars_crypto::{encode_bytes, IdentityKeyPair};
use ipars_relay::{encode_relay_datagram, RelayService, UdpRelay};
use ipars_relay_http::{router as relay_router, RelayHttpState};
use ipars_signal::SignalRegistry;
use ipars_signal_http::{router as signal_router, SignalHttpState};
use ipars_types::api::{
    AgentPathsResponse, AgentPeerActivityRequest, AgentPeerActivityResponse, AgentStatusResponse,
    ControlPlaneMetricsResponse, ControlPlanePathsResponse, HeartbeatRequest, HeartbeatResponse,
    JoinNodeRequest, PeerMap, RegisterNodeRequest, RegisterNodeResponse,
    RelayAdmissionFailureReason, RelayAdmissionRequest, RelayAdmissionResponse,
    RelayDataplaneDropReason, RelayStatusResponse, SignalMetricsResponse, SignalNodeUpsertRequest,
    SignalNodeUpsertResponse, SignalPathRequest, SignalPathResponse, StunMetricsResponse,
};
use ipars_types::{
    BootstrapEndpoint, BootstrapEndpointKind, CandidateSource, ClusterId, ClusterPolicy,
    EndpointCandidate, EndpointCandidateKind, HealthState, JoinTokenClaims, KeyId, NodeHealth,
    NodeId, NodeRecord, PathState, RelayCapability, Role, Route, Tag, TokenPolicy,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;

static DAEMON_LOG_COUNTER: AtomicUsize = AtomicUsize::new(0);
static DAEMON_MANIFEST_COUNTER: AtomicUsize = AtomicUsize::new(0);
const DAEMON_LOG_TAIL_BYTES: usize = 8192;
const DAEMON_LOG_TAIL_LINES: usize = 40;
const MAX_DAEMON_RUNTIME_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const DAEMON_RUNTIME_MANIFEST_FILE: &str = "run-manifest.json";
const DAEMON_CONTROL_PLANE_SQLITE_FILE: &str = "control-plane.sqlite";
const DAEMON_JOIN_TOKEN_FILE_SUFFIX: &str = ".join-token.json";
const DAEMON_AGENT_STATE_FILE_SUFFIX: &str = ".state.json";
const DAEMON_REDACTED_ARG: &str = "<redacted>";
const MAX_DAEMON_REDACTED_ARG_BYTES: usize = 4096;
const MAX_DAEMON_REDACTED_ARG_COUNT: usize = 256;
const SANITIZED_DAEMON_CHILD_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const SANITIZED_DAEMON_CHILD_LOCALE: &str = "C";
const MAX_RELAY_PAYLOAD_BYTES: usize = 60_000;
const MAX_DAEMON_CONTROL_PLANE_PROCESSES: usize = 8;
const MAX_DAEMON_READINESS_TIMEOUT_SECONDS: u64 = 3_600;
const MAX_LOAD_HTTP_JSON_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_LOAD_HTTP_TEXT_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_DAEMON_HTTP_READINESS_TIMEOUT_SECONDS: u64 = 5;
const DEFAULT_DAEMON_AGENT_READINESS_TIMEOUT_SECONDS: u64 = 15;

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

    #[arg(long, default_value_t = 1)]
    daemon_control_plane_processes: usize,

    #[arg(long)]
    daemon_keep_runtime_dir: bool,

    #[arg(long, default_value_t = DEFAULT_DAEMON_HTTP_READINESS_TIMEOUT_SECONDS)]
    daemon_http_readiness_timeout_seconds: u64,

    #[arg(long, default_value_t = DEFAULT_DAEMON_AGENT_READINESS_TIMEOUT_SECONDS)]
    daemon_agent_readiness_timeout_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
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
struct DaemonLoadOptions {
    control_plane_processes: usize,
    agent_processes: usize,
    keep_runtime_dir: bool,
    http_readiness_timeout: Duration,
    agent_readiness_timeout: Duration,
    relay_options: RelayLoadOptions,
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

#[derive(Debug, Clone, Serialize)]
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
    stun_http_requests: usize,
    relay_udp_sessions: usize,
    relay_packets_per_session: usize,
    relay_payload_bytes_per_packet: usize,
    relay_udp_packets_sent: usize,
    relay_udp_packets_received: usize,
    relay_udp_payload_bytes_sent: u64,
    relay_udp_payload_bytes_received: u64,
    daemon_failover_relay_udp_packets_sent: usize,
    daemon_failover_relay_udp_packets_received: usize,
    daemon_failover_relay_udp_payload_bytes_sent: u64,
    daemon_failover_relay_udp_payload_bytes_received: u64,
    relay_dataplane_datagrams_received_reported: u64,
    relay_dataplane_datagrams_forwarded_reported: u64,
    relay_dataplane_datagrams_dropped_reported: u64,
    relay_dataplane_invalid_session_credential_drops_reported: u64,
    relay_dataplane_invalid_session_credential_drops_prometheus_reported: u64,
    relay_forwarded_bytes_reported: u64,
    relay_active_sessions_reported: usize,
    relay_available_sessions_reported: usize,
    relay_max_sessions_reported: usize,
    relay_max_mbps_reported: u32,
    relay_enabled_by_policy_reported: bool,
    relay_e2e_only_reported: bool,
    relay_admission_attempts_reported: u64,
    relay_admission_successes_reported: u64,
    relay_admission_failures_reported: u64,
    relay_admission_failures_by_reason_reported: BTreeMap<RelayAdmissionFailureReason, u64>,
    relay_mbps: f64,
    daemon_processes: usize,
    daemon_runtime_dir: Option<PathBuf>,
    daemon_runtime_manifest: Option<PathBuf>,
    daemon_http_readiness_timeout_seconds: u64,
    daemon_agent_readiness_timeout_seconds: u64,
    daemon_agent_processes: usize,
    daemon_agent_status_endpoints: usize,
    daemon_agent_candidate_count_min: usize,
    daemon_agent_candidate_count_max: usize,
    daemon_agent_path_status_endpoints: usize,
    daemon_agent_paths_total: usize,
    daemon_agent_reachable_paths_total: usize,
    daemon_agent_path_count_min: usize,
    daemon_agent_path_count_max: usize,
    daemon_agent_failover_status_endpoints: usize,
    daemon_agent_failover_candidate_count_min: usize,
    daemon_agent_failover_candidate_count_max: usize,
    daemon_agent_failover_path_status_endpoints: usize,
    daemon_agent_failover_paths_total: usize,
    daemon_agent_failover_reachable_paths_total: usize,
    daemon_agent_failover_path_count_min: usize,
    daemon_agent_failover_path_count_max: usize,
    daemon_control_plane_processes: usize,
    daemon_control_plane_metrics_endpoints: usize,
    daemon_control_plane_peer_map_endpoints: usize,
    daemon_control_plane_peer_map_edges_min: usize,
    daemon_control_plane_peer_map_edges_max: usize,
    daemon_control_plane_peer_maps_consistent: bool,
    daemon_control_plane_failover_checked: bool,
    daemon_control_plane_failover_survivor_endpoints: usize,
    daemon_control_plane_failover_peer_map_edges_min: usize,
    daemon_control_plane_failover_peer_map_edges_max: usize,
    daemon_control_plane_failover_peer_maps_consistent: bool,
    daemon_control_plane_failover_metrics_endpoints: usize,
    daemon_control_plane_failover_metrics_consistent: bool,
    daemon_control_plane_failover_relay_candidates_min: usize,
    daemon_control_plane_failover_relay_candidates_max: usize,
    daemon_control_plane_failover_path_count_min: usize,
    daemon_control_plane_failover_path_count_max: usize,
    daemon_control_plane_failover_reachable_path_count_min: usize,
    daemon_control_plane_failover_reachable_path_count_max: usize,
    daemon_control_plane_failover_path_status_requests: usize,
    daemon_control_plane_failover_path_status_count_min: usize,
    daemon_control_plane_failover_path_status_count_max: usize,
    daemon_control_plane_failover_path_status_reachable_count_min: usize,
    daemon_control_plane_failover_path_status_reachable_count_max: usize,
    daemon_control_plane_failover_path_status_stale_count_max: usize,
    daemon_control_plane_failover_healthy_nodes_min: usize,
    daemon_control_plane_failover_healthy_nodes_max: usize,
    daemon_control_plane_failover_degraded_nodes_min: usize,
    daemon_control_plane_failover_degraded_nodes_max: usize,
    daemon_control_plane_failover_unhealthy_nodes_min: usize,
    daemon_control_plane_failover_unhealthy_nodes_max: usize,
    daemon_control_plane_relay_candidates_min: usize,
    daemon_control_plane_relay_candidates_max: usize,
    daemon_control_plane_path_count_min: usize,
    daemon_control_plane_path_count_max: usize,
    daemon_control_plane_reachable_path_count_min: usize,
    daemon_control_plane_reachable_path_count_max: usize,
    daemon_control_plane_path_status_requests: usize,
    daemon_control_plane_path_status_count_min: usize,
    daemon_control_plane_path_status_count_max: usize,
    daemon_control_plane_path_status_reachable_count_min: usize,
    daemon_control_plane_path_status_reachable_count_max: usize,
    daemon_control_plane_path_status_stale_count_max: usize,
    daemon_control_plane_healthy_nodes: usize,
    daemon_control_plane_healthy_nodes_min: usize,
    daemon_control_plane_healthy_nodes_max: usize,
    daemon_control_plane_degraded_nodes: usize,
    daemon_control_plane_degraded_nodes_min: usize,
    daemon_control_plane_degraded_nodes_max: usize,
    daemon_control_plane_unhealthy_nodes: usize,
    daemon_control_plane_unhealthy_nodes_min: usize,
    daemon_control_plane_unhealthy_nodes_max: usize,
    daemon_control_plane_metrics_consistent: bool,
    daemon_signal_health_reports: usize,
    daemon_signal_healthy_nodes: usize,
    daemon_signal_degraded_nodes: usize,
    daemon_signal_unhealthy_nodes: usize,
    daemon_stun: DaemonStunReport,
    registration_millis: u128,
    peer_map_millis: u128,
    signal_millis: u128,
    relay_millis: u128,
}

#[derive(Debug, Clone, Default, Serialize)]
struct DaemonStunReport {
    metrics_endpoints: usize,
    listen_matches_expected: bool,
    alternate_listen_matches_expected: bool,
    prometheus_alternate_listener_reported: bool,
    binding_requests_reported: u64,
    binding_responses_reported: u64,
    invalid_packets_reported: u64,
    socket_receive_errors_reported: u64,
    socket_send_errors_reported: u64,
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
                DaemonLoadOptions {
                    control_plane_processes: cli.daemon_control_plane_processes,
                    agent_processes: cli.daemon_agent_processes,
                    keep_runtime_dir: cli.daemon_keep_runtime_dir,
                    http_readiness_timeout: daemon_timeout_from_seconds(
                        cli.daemon_http_readiness_timeout_seconds,
                        "--daemon-http-readiness-timeout-seconds",
                    )?,
                    agent_readiness_timeout: daemon_timeout_from_seconds(
                        cli.daemon_agent_readiness_timeout_seconds,
                        "--daemon-agent-readiness-timeout-seconds",
                    )?,
                    relay_options: RelayLoadOptions {
                        packets_per_session: cli.relay_packets_per_session,
                        payload_bytes: cli.relay_payload_bytes,
                    },
                },
            )
            .await?
        }
    };
    report.validate_success()?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

impl LoadReport {
    fn validate_success(&self) -> anyhow::Result<()> {
        match self.transport {
            TransportMode::InMemory | TransportMode::Http => {
                self.validate_registration_and_paths("load scenario", true, self.node_count)?;
                if self.relay_count > 0 && self.relay_candidates < self.relay_count {
                    bail!(
                        "load scenario reported {} relay candidates, expected at least {}",
                        self.relay_candidates,
                        self.relay_count
                    );
                }
            }
            TransportMode::RelayUdp => {
                self.validate_relay_measurement("relay UDP scenario")?;
            }
            TransportMode::Daemon => {
                let expected_peer_map_requests = self
                    .node_count
                    .saturating_mul(self.daemon_control_plane_processes)
                    .saturating_add(
                        self.node_count
                            .saturating_mul(self.daemon_control_plane_processes.saturating_sub(1)),
                    );
                self.validate_registration_and_paths(
                    "daemon load scenario",
                    false,
                    expected_peer_map_requests,
                )?;
                self.validate_relay_measurement("daemon load scenario")?;
                let expected_processes =
                    self.daemon_agent_processes + self.daemon_control_plane_processes + 3;
                if self.daemon_processes != expected_processes {
                    bail!(
                        "daemon load scenario reported {} processes, expected {expected_processes}",
                        self.daemon_processes
                    );
                }
                if self.node_count != self.daemon_agent_processes
                    || self.daemon_agent_status_endpoints != self.daemon_agent_processes
                {
                    bail!(
                        "daemon load scenario checked {} agent status endpoints and registered {} nodes, expected {} agents",
                        self.daemon_agent_status_endpoints,
                        self.node_count,
                        self.daemon_agent_processes
                    );
                }
                if self.daemon_agent_candidate_count_min == 0
                    || self.daemon_agent_candidate_count_max < self.daemon_agent_candidate_count_min
                {
                    bail!(
                        "daemon load scenario agent endpoint candidate mismatch: min/max={}/{}, expected every agent to advertise at least one candidate",
                        self.daemon_agent_candidate_count_min,
                        self.daemon_agent_candidate_count_max
                    );
                }
                let expected_agent_path_count =
                    expected_daemon_agent_path_count(self.active_pair_count, self.node_count);
                if self.daemon_agent_path_status_endpoints != self.daemon_agent_processes {
                    bail!(
                        "daemon load scenario checked {} agent path endpoints, expected {}",
                        self.daemon_agent_path_status_endpoints,
                        self.daemon_agent_processes
                    );
                }
                if self.daemon_agent_paths_total < expected_agent_path_count
                    || self.daemon_agent_reachable_paths_total < expected_agent_path_count
                {
                    bail!(
                        "daemon load scenario agent path state mismatch: total={}, reachable={}, expected at least {expected_agent_path_count}",
                        self.daemon_agent_paths_total,
                        self.daemon_agent_reachable_paths_total
                    );
                }
                if self.daemon_agent_path_count_max < self.daemon_agent_path_count_min {
                    bail!(
                        "daemon load scenario agent path min/max is invalid: min={}, max={}",
                        self.daemon_agent_path_count_min,
                        self.daemon_agent_path_count_max
                    );
                }
                if !self.daemon_control_plane_metrics_consistent {
                    bail!("daemon load scenario control-plane metrics are inconsistent");
                }
                if self.daemon_control_plane_metrics_endpoints
                    != self.daemon_control_plane_processes
                {
                    bail!(
                        "daemon load scenario checked {} control-plane metrics endpoints, expected {}",
                        self.daemon_control_plane_metrics_endpoints,
                        self.daemon_control_plane_processes
                    );
                }
                if self.daemon_control_plane_relay_candidates_min != self.relay_count
                    || self.daemon_control_plane_relay_candidates_max != self.relay_count
                {
                    bail!(
                        "daemon load scenario relay candidate mismatch: min/max={}/{}, expected {}",
                        self.daemon_control_plane_relay_candidates_min,
                        self.daemon_control_plane_relay_candidates_max,
                        self.relay_count
                    );
                }
                if self.daemon_control_plane_path_count_min < expected_agent_path_count
                    || self.daemon_control_plane_reachable_path_count_min
                        < expected_agent_path_count
                {
                    bail!(
                        "daemon load scenario control-plane path-state mismatch: path min/max={}/{}, reachable min/max={}/{}, expected at least {expected_agent_path_count}",
                        self.daemon_control_plane_path_count_min,
                        self.daemon_control_plane_path_count_max,
                        self.daemon_control_plane_reachable_path_count_min,
                        self.daemon_control_plane_reachable_path_count_max
                    );
                }
                let expected_path_status_requests = self
                    .daemon_control_plane_processes
                    .saturating_mul(self.daemon_agent_processes);
                if self.daemon_control_plane_path_status_requests != expected_path_status_requests {
                    bail!(
                        "daemon load scenario checked {} control-plane path status requests, expected {expected_path_status_requests}",
                        self.daemon_control_plane_path_status_requests
                    );
                }
                if self.daemon_control_plane_path_status_count_min < expected_agent_path_count
                    || self.daemon_control_plane_path_status_reachable_count_min
                        < expected_agent_path_count
                    || self.daemon_control_plane_path_status_stale_count_max != 0
                {
                    bail!(
                        "daemon load scenario control-plane path status mismatch: path min/max={}/{}, reachable min/max={}/{}, stale max={}, expected at least {expected_agent_path_count} fresh reachable paths",
                        self.daemon_control_plane_path_status_count_min,
                        self.daemon_control_plane_path_status_count_max,
                        self.daemon_control_plane_path_status_reachable_count_min,
                        self.daemon_control_plane_path_status_reachable_count_max,
                        self.daemon_control_plane_path_status_stale_count_max
                    );
                }
                if self.daemon_control_plane_peer_map_endpoints
                    != self.daemon_control_plane_processes
                {
                    bail!(
                        "daemon load scenario checked {} peer-map endpoints, expected {}",
                        self.daemon_control_plane_peer_map_endpoints,
                        self.daemon_control_plane_processes
                    );
                }
                let expected_peer_edges = self
                    .node_count
                    .saturating_mul(self.node_count.saturating_sub(1));
                if !self.daemon_control_plane_peer_maps_consistent {
                    bail!("daemon load scenario control-plane peer maps are inconsistent");
                }
                if self.daemon_control_plane_peer_map_edges_min != expected_peer_edges
                    || self.daemon_control_plane_peer_map_edges_max != expected_peer_edges
                {
                    bail!(
                        "daemon load scenario peer-map edge mismatch: min/max={}/{}, expected {expected_peer_edges}",
                        self.daemon_control_plane_peer_map_edges_min,
                        self.daemon_control_plane_peer_map_edges_max
                    );
                }
                if self.daemon_control_plane_processes > 1 {
                    if !self.daemon_control_plane_failover_checked {
                        bail!("daemon load scenario did not check control-plane failover");
                    }
                    let expected_survivor_endpoints =
                        self.daemon_control_plane_processes.saturating_sub(1);
                    if self.daemon_control_plane_failover_survivor_endpoints
                        != expected_survivor_endpoints
                    {
                        bail!(
                            "daemon load scenario failover checked {} survivor endpoints, expected {expected_survivor_endpoints}",
                            self.daemon_control_plane_failover_survivor_endpoints
                        );
                    }
                    if !self.daemon_control_plane_failover_peer_maps_consistent {
                        bail!(
                            "daemon load scenario failover control-plane peer maps are inconsistent"
                        );
                    }
                    if self.daemon_agent_failover_status_endpoints != self.daemon_agent_processes {
                        bail!(
                            "daemon load scenario failover checked {} agent status endpoints, expected {}",
                            self.daemon_agent_failover_status_endpoints,
                            self.daemon_agent_processes
                        );
                    }
                    if self.daemon_agent_failover_candidate_count_min == 0
                        || self.daemon_agent_failover_candidate_count_max
                            < self.daemon_agent_failover_candidate_count_min
                    {
                        bail!(
                            "daemon load scenario failover agent endpoint candidate mismatch: min/max={}/{}, expected every agent to keep at least one candidate",
                            self.daemon_agent_failover_candidate_count_min,
                            self.daemon_agent_failover_candidate_count_max
                        );
                    }
                    if self.daemon_agent_failover_path_status_endpoints
                        != self.daemon_agent_processes
                    {
                        bail!(
                            "daemon load scenario failover checked {} agent path endpoints, expected {}",
                            self.daemon_agent_failover_path_status_endpoints,
                            self.daemon_agent_processes
                        );
                    }
                    if self.daemon_agent_failover_paths_total < expected_agent_path_count
                        || self.daemon_agent_failover_reachable_paths_total
                            < expected_agent_path_count
                    {
                        bail!(
                            "daemon load scenario failover agent path state mismatch: total={}, reachable={}, expected at least {expected_agent_path_count}",
                            self.daemon_agent_failover_paths_total,
                            self.daemon_agent_failover_reachable_paths_total
                        );
                    }
                    if self.daemon_agent_failover_path_count_max
                        < self.daemon_agent_failover_path_count_min
                    {
                        bail!(
                            "daemon load scenario failover agent path min/max is invalid: min={}, max={}",
                            self.daemon_agent_failover_path_count_min,
                            self.daemon_agent_failover_path_count_max
                        );
                    }
                    let expected_failover_relay_packets = self.active_pair_count;
                    if self.daemon_failover_relay_udp_packets_sent
                        != expected_failover_relay_packets
                    {
                        bail!(
                            "daemon load scenario failover relay dataplane sent {} packets, expected {expected_failover_relay_packets}",
                            self.daemon_failover_relay_udp_packets_sent
                        );
                    }
                    if self.daemon_failover_relay_udp_packets_received
                        != expected_failover_relay_packets
                    {
                        bail!(
                            "daemon load scenario failover relay dataplane received {} packets, expected {expected_failover_relay_packets}",
                            self.daemon_failover_relay_udp_packets_received
                        );
                    }
                    if self.daemon_failover_relay_udp_payload_bytes_sent
                        != self.daemon_failover_relay_udp_payload_bytes_received
                    {
                        bail!(
                            "daemon load scenario failover relay payload byte mismatch: sent {}, received {}",
                            self.daemon_failover_relay_udp_payload_bytes_sent,
                            self.daemon_failover_relay_udp_payload_bytes_received
                        );
                    }
                    if self.daemon_control_plane_failover_peer_map_edges_min != expected_peer_edges
                        || self.daemon_control_plane_failover_peer_map_edges_max
                            != expected_peer_edges
                    {
                        bail!(
                            "daemon load scenario failover peer-map edge mismatch: min/max={}/{}, expected {expected_peer_edges}",
                            self.daemon_control_plane_failover_peer_map_edges_min,
                            self.daemon_control_plane_failover_peer_map_edges_max
                        );
                    }
                    if self.daemon_control_plane_failover_metrics_endpoints
                        != expected_survivor_endpoints
                    {
                        bail!(
                            "daemon load scenario failover checked {} survivor metrics endpoints, expected {expected_survivor_endpoints}",
                            self.daemon_control_plane_failover_metrics_endpoints
                        );
                    }
                    if !self.daemon_control_plane_failover_metrics_consistent {
                        bail!(
                            "daemon load scenario failover control-plane metrics are inconsistent"
                        );
                    }
                    if self.daemon_control_plane_failover_relay_candidates_min != self.relay_count
                        || self.daemon_control_plane_failover_relay_candidates_max
                            != self.relay_count
                    {
                        bail!(
                            "daemon load scenario failover relay candidate mismatch: min/max={}/{}, expected {}",
                            self.daemon_control_plane_failover_relay_candidates_min,
                            self.daemon_control_plane_failover_relay_candidates_max,
                            self.relay_count
                        );
                    }
                    if self.daemon_control_plane_failover_path_count_min < expected_agent_path_count
                        || self.daemon_control_plane_failover_reachable_path_count_min
                            < expected_agent_path_count
                    {
                        bail!(
                            "daemon load scenario failover control-plane path-state mismatch: path min/max={}/{}, reachable min/max={}/{}, expected at least {expected_agent_path_count}",
                            self.daemon_control_plane_failover_path_count_min,
                            self.daemon_control_plane_failover_path_count_max,
                            self.daemon_control_plane_failover_reachable_path_count_min,
                            self.daemon_control_plane_failover_reachable_path_count_max
                        );
                    }
                    let expected_failover_path_status_requests =
                        expected_survivor_endpoints.saturating_mul(self.daemon_agent_processes);
                    if self.daemon_control_plane_failover_path_status_requests
                        != expected_failover_path_status_requests
                    {
                        bail!(
                            "daemon load scenario failover checked {} control-plane path status requests, expected {expected_failover_path_status_requests}",
                            self.daemon_control_plane_failover_path_status_requests
                        );
                    }
                    if self.daemon_control_plane_failover_path_status_count_min
                        < expected_agent_path_count
                        || self.daemon_control_plane_failover_path_status_reachable_count_min
                            < expected_agent_path_count
                        || self.daemon_control_plane_failover_path_status_stale_count_max != 0
                    {
                        bail!(
                            "daemon load scenario failover control-plane path status mismatch: path min/max={}/{}, reachable min/max={}/{}, stale max={}, expected at least {expected_agent_path_count} fresh reachable paths",
                            self.daemon_control_plane_failover_path_status_count_min,
                            self.daemon_control_plane_failover_path_status_count_max,
                            self.daemon_control_plane_failover_path_status_reachable_count_min,
                            self.daemon_control_plane_failover_path_status_reachable_count_max,
                            self.daemon_control_plane_failover_path_status_stale_count_max
                        );
                    }
                    if self.daemon_control_plane_failover_healthy_nodes_min != self.node_count
                        || self.daemon_control_plane_failover_healthy_nodes_max != self.node_count
                        || self.daemon_control_plane_failover_degraded_nodes_max != 0
                        || self.daemon_control_plane_failover_unhealthy_nodes_max != 0
                    {
                        bail!(
                            "daemon load scenario failover health mismatch: healthy min/max={}/{}, degraded max={}, unhealthy max={}, expected {} healthy nodes",
                            self.daemon_control_plane_failover_healthy_nodes_min,
                            self.daemon_control_plane_failover_healthy_nodes_max,
                            self.daemon_control_plane_failover_degraded_nodes_max,
                            self.daemon_control_plane_failover_unhealthy_nodes_max,
                            self.node_count
                        );
                    }
                }
                if self.daemon_control_plane_healthy_nodes_min != self.node_count
                    || self.daemon_control_plane_healthy_nodes_max != self.node_count
                    || self.daemon_control_plane_degraded_nodes_max != 0
                    || self.daemon_control_plane_unhealthy_nodes_max != 0
                {
                    bail!(
                        "daemon load scenario health mismatch: healthy min/max={}/{}, degraded max={}, unhealthy max={}, expected {} healthy nodes",
                        self.daemon_control_plane_healthy_nodes_min,
                        self.daemon_control_plane_healthy_nodes_max,
                        self.daemon_control_plane_degraded_nodes_max,
                        self.daemon_control_plane_unhealthy_nodes_max,
                        self.node_count
                    );
                }
                if self.daemon_signal_health_reports < self.node_count
                    || self.daemon_signal_healthy_nodes != self.node_count
                    || self.daemon_signal_degraded_nodes != 0
                    || self.daemon_signal_unhealthy_nodes != 0
                {
                    bail!(
                        "daemon load scenario signal health mismatch: reports={}, healthy={}, degraded={}, unhealthy={}, expected {} healthy nodes",
                        self.daemon_signal_health_reports,
                        self.daemon_signal_healthy_nodes,
                        self.daemon_signal_degraded_nodes,
                        self.daemon_signal_unhealthy_nodes,
                        self.node_count
                    );
                }
                if self.stun_http_requests != 2 {
                    bail!(
                        "daemon load scenario checked {} STUN HTTP endpoints, expected 2 metrics requests",
                        self.stun_http_requests
                    );
                }
                if self.daemon_stun.metrics_endpoints != 1 {
                    bail!(
                        "daemon load scenario checked {} STUN metrics endpoints, expected 1",
                        self.daemon_stun.metrics_endpoints
                    );
                }
                if !self.daemon_stun.listen_matches_expected
                    || !self.daemon_stun.alternate_listen_matches_expected
                    || !self.daemon_stun.prometheus_alternate_listener_reported
                {
                    bail!(
                        "daemon load scenario STUN listener metrics mismatch: listen={}, alternate={}, prometheus_alternate={}",
                        self.daemon_stun.listen_matches_expected,
                        self.daemon_stun.alternate_listen_matches_expected,
                        self.daemon_stun.prometheus_alternate_listener_reported
                    );
                }
                if self.daemon_stun.binding_requests_reported < self.node_count as u64
                    || self.daemon_stun.binding_responses_reported < self.node_count as u64
                    || self.daemon_stun.binding_responses_reported
                        > self.daemon_stun.binding_requests_reported
                {
                    bail!(
                        "daemon load scenario STUN binding counters mismatch: requests={}, responses={}, expected at least {} successful startup probes",
                        self.daemon_stun.binding_requests_reported,
                        self.daemon_stun.binding_responses_reported,
                        self.node_count
                    );
                }
                if self.daemon_stun.invalid_packets_reported != 0
                    || self.daemon_stun.socket_receive_errors_reported != 0
                    || self.daemon_stun.socket_send_errors_reported != 0
                {
                    bail!(
                        "daemon load scenario STUN error counters are nonzero: invalid={}, recv_errors={}, send_errors={}",
                        self.daemon_stun.invalid_packets_reported,
                        self.daemon_stun.socket_receive_errors_reported,
                        self.daemon_stun.socket_send_errors_reported
                    );
                }
                self.validate_daemon_retained_manifest()?;
            }
        }
        Ok(())
    }

    fn validate_registration_and_paths(
        &self,
        context: &str,
        allow_partial_unreachable: bool,
        expected_peer_map_requests: usize,
    ) -> anyhow::Result<()> {
        if self.registrations != self.node_count {
            bail!(
                "{context} registered {} nodes, expected {}",
                self.registrations,
                self.node_count
            );
        }
        if self.peer_map_requests != expected_peer_map_requests {
            bail!(
                "{context} made {} peer-map requests, expected {expected_peer_map_requests}",
                self.peer_map_requests
            );
        }
        let expected_peer_edges = self
            .node_count
            .saturating_mul(self.node_count.saturating_sub(1));
        if self.peer_map_edges_seen != expected_peer_edges {
            bail!(
                "{context} saw {} peer-map edges, expected {expected_peer_edges}",
                self.peer_map_edges_seen
            );
        }
        if self.advertised_routes != self.route_provider_count {
            bail!(
                "{context} advertised {} routes, expected {} route-provider routes",
                self.advertised_routes,
                self.route_provider_count
            );
        }
        if self.signal_negotiations != self.active_pair_count {
            bail!(
                "{context} completed {} signal negotiations, expected {}",
                self.signal_negotiations,
                self.active_pair_count
            );
        }
        let observed_paths = self.direct_public_paths
            + self.direct_ipv6_paths
            + self.direct_nat_paths
            + self.relay_paths
            + self.unreachable_paths;
        if observed_paths != self.signal_negotiations {
            bail!(
                "{context} reported {observed_paths} path results for {} negotiations",
                self.signal_negotiations
            );
        }
        let reachable_paths = observed_paths.saturating_sub(self.unreachable_paths);
        if reachable_paths == 0 && self.signal_negotiations > 0 {
            bail!("{context} reported no reachable paths");
        }
        if self.unreachable_paths != 0 && !allow_partial_unreachable {
            bail!(
                "{context} reported {} unreachable paths",
                self.unreachable_paths
            );
        }
        Ok(())
    }

    fn validate_relay_measurement(&self, context: &str) -> anyhow::Result<()> {
        let expected_packets = self
            .active_pair_count
            .saturating_mul(self.relay_packets_per_session);
        if expected_packets == 0 {
            bail!("{context} did not schedule relay packets");
        }
        if self.relay_udp_packets_sent != expected_packets {
            bail!(
                "{context} sent {} relay UDP packets, expected {expected_packets}",
                self.relay_udp_packets_sent
            );
        }
        if self.relay_udp_packets_received != expected_packets {
            bail!(
                "{context} received {} relay UDP packets, expected {expected_packets}",
                self.relay_udp_packets_received
            );
        }
        if self.relay_udp_payload_bytes_sent != self.relay_udp_payload_bytes_received {
            bail!(
                "{context} relay payload byte mismatch: sent {}, received {}",
                self.relay_udp_payload_bytes_sent,
                self.relay_udp_payload_bytes_received
            );
        }
        if self.relay_forwarded_bytes_reported < self.relay_udp_payload_bytes_received {
            bail!(
                "{context} relay metrics reported {} forwarded bytes, below received payload bytes {}",
                self.relay_forwarded_bytes_reported,
                self.relay_udp_payload_bytes_received
            );
        }
        if self.relay_dataplane_datagrams_forwarded_reported
            < self.relay_udp_packets_received as u64
        {
            bail!(
                "{context} relay dataplane reported {} forwarded datagrams, below received valid packets {}",
                self.relay_dataplane_datagrams_forwarded_reported,
                self.relay_udp_packets_received
            );
        }
        if self.relay_dataplane_invalid_session_credential_drops_reported == 0
            || self.relay_dataplane_datagrams_dropped_reported
                < self.relay_dataplane_invalid_session_credential_drops_reported
        {
            bail!(
                "{context} relay dataplane did not report invalid credential abuse drops: dropped={}, invalid_credential={}",
                self.relay_dataplane_datagrams_dropped_reported,
                self.relay_dataplane_invalid_session_credential_drops_reported
            );
        }
        if self.relay_dataplane_invalid_session_credential_drops_prometheus_reported
            < self.relay_dataplane_invalid_session_credential_drops_reported
        {
            bail!(
                "{context} relay Prometheus metrics reported {} invalid credential drops, below status drops {}",
                self.relay_dataplane_invalid_session_credential_drops_prometheus_reported,
                self.relay_dataplane_invalid_session_credential_drops_reported
            );
        }
        let minimum_datagrams_received = self.relay_udp_packets_received as u64
            + self.relay_dataplane_datagrams_dropped_reported;
        if self.relay_dataplane_datagrams_received_reported < minimum_datagrams_received {
            bail!(
                "{context} relay dataplane reported {} received datagrams, below forwarded valid packets plus drops {}",
                self.relay_dataplane_datagrams_received_reported,
                minimum_datagrams_received
            );
        }
        if self.relay_udp_sessions != self.active_pair_count
            || self.relay_active_sessions_reported != self.active_pair_count
        {
            bail!(
                "{context} relay session mismatch: udp_sessions={}, active_sessions={}, expected {}",
                self.relay_udp_sessions,
                self.relay_active_sessions_reported,
                self.active_pair_count
            );
        }
        if self.relay_max_sessions_reported == 0
            || self.relay_active_sessions_reported > self.relay_max_sessions_reported
        {
            bail!(
                "{context} relay capacity snapshot is invalid: active={}, max={}",
                self.relay_active_sessions_reported,
                self.relay_max_sessions_reported
            );
        }
        let expected_available_sessions = self
            .relay_max_sessions_reported
            .saturating_sub(self.relay_active_sessions_reported);
        if self.relay_available_sessions_reported != expected_available_sessions {
            bail!(
                "{context} relay capacity snapshot reported {} available sessions, expected {expected_available_sessions}",
                self.relay_available_sessions_reported
            );
        }
        if self.relay_max_mbps_reported == 0
            || !self.relay_enabled_by_policy_reported
            || !self.relay_e2e_only_reported
        {
            bail!(
                "{context} relay capability snapshot is not production-usable: max_mbps={}, enabled_by_policy={}, e2e_only={}",
                self.relay_max_mbps_reported,
                self.relay_enabled_by_policy_reported,
                self.relay_e2e_only_reported
            );
        }
        if self.relay_admission_attempts_reported != self.active_pair_count as u64
            || self.relay_admission_successes_reported != self.active_pair_count as u64
            || self.relay_admission_failures_reported != 0
            || self
                .relay_admission_failures_by_reason_reported
                .values()
                .any(|count| *count != 0)
        {
            bail!(
                "{context} relay admission mismatch: attempts={}, successes={}, failures={}, failures_by_reason={:?}",
                self.relay_admission_attempts_reported,
                self.relay_admission_successes_reported,
                self.relay_admission_failures_reported,
                self.relay_admission_failures_by_reason_reported
            );
        }
        Ok(())
    }

    fn validate_daemon_retained_manifest(&self) -> anyhow::Result<()> {
        let (runtime_dir, manifest_path) = match (
            &self.daemon_runtime_dir,
            &self.daemon_runtime_manifest,
        ) {
            (None, None) => return Ok(()),
            (Some(runtime_dir), Some(manifest_path)) => (runtime_dir, manifest_path),
            _ => bail!(
                "daemon load scenario retained runtime directory and manifest path must be set together"
            ),
        };

        let expected_manifest_path = daemon_runtime_manifest_path(runtime_dir);
        if manifest_path != &expected_manifest_path {
            bail!(
                "daemon load scenario retained manifest path {} does not match expected {}",
                manifest_path.display(),
                expected_manifest_path.display()
            );
        }
        let runtime_metadata = std::fs::symlink_metadata(runtime_dir).with_context(|| {
            format!(
                "daemon load scenario retained runtime directory {} is not accessible",
                runtime_dir.display()
            )
        })?;
        if runtime_metadata.file_type().is_symlink() || !runtime_metadata.is_dir() {
            bail!(
                "daemon load scenario retained runtime path {} is not a directory",
                runtime_dir.display()
            );
        }
        validate_daemon_retained_path_mode(
            runtime_dir,
            &runtime_metadata,
            0o700,
            "retained runtime directory",
        )?;
        let manifest_metadata = std::fs::symlink_metadata(manifest_path).with_context(|| {
            format!(
                "daemon load scenario retained manifest {} is not accessible",
                manifest_path.display()
            )
        })?;
        if manifest_metadata.file_type().is_symlink() || !manifest_metadata.is_file() {
            bail!(
                "daemon load scenario retained manifest {} is not a regular file",
                manifest_path.display()
            );
        }
        validate_daemon_retained_path_mode(
            manifest_path,
            &manifest_metadata,
            0o600,
            "retained manifest",
        )?;
        let manifest_bytes = read_bounded_regular_file(
            manifest_path,
            "daemon load scenario retained manifest",
            MAX_DAEMON_RUNTIME_MANIFEST_BYTES,
        )?;
        let manifest: DaemonRuntimeManifest = serde_json::from_slice(&manifest_bytes)
            .context("failed to parse daemon load scenario retained runtime manifest")?;

        if manifest.phase != DaemonRuntimePhase::Completed {
            bail!(
                "daemon load scenario retained manifest ended in {:?}, expected {:?}",
                manifest.phase,
                DaemonRuntimePhase::Completed
            );
        }
        if manifest.scenario != self.scenario {
            bail!(
                "daemon load scenario retained manifest scenario {:?} does not match report {:?}",
                manifest.scenario,
                self.scenario
            );
        }
        if manifest.runtime_dir != *runtime_dir {
            bail!(
                "daemon load scenario retained manifest runtime_dir {} does not match report {}",
                manifest.runtime_dir.display(),
                runtime_dir.display()
            );
        }
        if !manifest.keep_runtime_dir {
            bail!("daemon load scenario retained manifest did not record keep_runtime_dir=true");
        }
        if manifest.updated_at < manifest.started_at {
            bail!(
                "daemon load scenario retained manifest timestamp order is invalid: started_at={}, updated_at={}",
                manifest.started_at,
                manifest.updated_at
            );
        }
        if manifest.generated_at != manifest.updated_at {
            bail!(
                "daemon load scenario retained manifest generated_at {} does not match updated_at {}",
                manifest.generated_at,
                manifest.updated_at
            );
        }
        validate_daemon_manifest_iparsd_binary(&manifest.iparsd_binary)?;

        let workload = manifest.workload;
        let expected_scenario = Scenario::from_name(self.scenario);
        if workload.scenario_node_count != expected_scenario.node_count
            || workload.scenario_relay_node_count != expected_scenario.relay_count
            || workload.scenario_route_provider_count != expected_scenario.route_provider_count
            || workload.scenario_active_pair_count != expected_scenario.active_pair_count
        {
            bail!(
                "daemon load scenario retained manifest scenario workload does not match {:?}: nodes={}/{}, relays={}/{}, route_providers={}/{}, active_pairs={}/{}",
                self.scenario,
                workload.scenario_node_count,
                expected_scenario.node_count,
                workload.scenario_relay_node_count,
                expected_scenario.relay_count,
                workload.scenario_route_provider_count,
                expected_scenario.route_provider_count,
                workload.scenario_active_pair_count,
                expected_scenario.active_pair_count
            );
        }
        if workload.daemon_agent_processes != self.daemon_agent_processes
            || workload.daemon_control_plane_processes != self.daemon_control_plane_processes
            || workload.relay_packets_per_session != self.relay_packets_per_session
            || workload.relay_payload_bytes != self.relay_payload_bytes_per_packet
        {
            bail!(
                "daemon load scenario retained manifest daemon workload does not match report: agents={}/{}, control_planes={}/{}, relay_packets={}/{}, relay_payload={}/{}",
                workload.daemon_agent_processes,
                self.daemon_agent_processes,
                workload.daemon_control_plane_processes,
                self.daemon_control_plane_processes,
                workload.relay_packets_per_session,
                self.relay_packets_per_session,
                workload.relay_payload_bytes,
                self.relay_payload_bytes_per_packet
            );
        }
        if workload.daemon_http_readiness_timeout_seconds
            != self.daemon_http_readiness_timeout_seconds
            || workload.daemon_agent_readiness_timeout_seconds
                != self.daemon_agent_readiness_timeout_seconds
        {
            bail!(
                "daemon load scenario retained manifest readiness timeout workload does not match report: http={}/{}, agent={}/{}",
                workload.daemon_http_readiness_timeout_seconds,
                self.daemon_http_readiness_timeout_seconds,
                workload.daemon_agent_readiness_timeout_seconds,
                self.daemon_agent_readiness_timeout_seconds
            );
        }
        let measurement = manifest.measurement.context(
            "daemon load scenario retained completed manifest is missing measurement summary",
        )?;
        if measurement.relay_udp_packets_sent != self.relay_udp_packets_sent
            || measurement.relay_udp_packets_received != self.relay_udp_packets_received
            || measurement.relay_udp_payload_bytes_sent != self.relay_udp_payload_bytes_sent
            || measurement.relay_udp_payload_bytes_received != self.relay_udp_payload_bytes_received
            || measurement.failover_relay_udp_packets_sent
                != self.daemon_failover_relay_udp_packets_sent
            || measurement.failover_relay_udp_packets_received
                != self.daemon_failover_relay_udp_packets_received
            || measurement.failover_relay_udp_payload_bytes_sent
                != self.daemon_failover_relay_udp_payload_bytes_sent
            || measurement.failover_relay_udp_payload_bytes_received
                != self.daemon_failover_relay_udp_payload_bytes_received
            || measurement.relay_dataplane_datagrams_received_reported
                != self.relay_dataplane_datagrams_received_reported
            || measurement.relay_dataplane_datagrams_forwarded_reported
                != self.relay_dataplane_datagrams_forwarded_reported
            || measurement.relay_dataplane_datagrams_dropped_reported
                != self.relay_dataplane_datagrams_dropped_reported
            || measurement.relay_dataplane_invalid_session_credential_drops_reported
                != self.relay_dataplane_invalid_session_credential_drops_reported
            || measurement.relay_dataplane_invalid_session_credential_drops_prometheus_reported
                != self.relay_dataplane_invalid_session_credential_drops_prometheus_reported
            || measurement.relay_forwarded_bytes_reported != self.relay_forwarded_bytes_reported
            || measurement.relay_active_sessions_reported != self.relay_active_sessions_reported
            || measurement.control_plane_failover_checked
                != self.daemon_control_plane_failover_checked
            || measurement.control_plane_failover_survivor_endpoints
                != self.daemon_control_plane_failover_survivor_endpoints
        {
            bail!(
                "daemon load scenario retained manifest measurement summary does not match report: relay packets {}/{}, failover relay packets {}/{}, dataplane drops {}/{}, invalid credential drops {}/{}, Prometheus invalid credential drops {}/{}, forwarded bytes {}/{}, active sessions {}/{}, failover checked {}/{}",
                measurement.relay_udp_packets_received,
                self.relay_udp_packets_received,
                measurement.failover_relay_udp_packets_received,
                self.daemon_failover_relay_udp_packets_received,
                measurement.relay_dataplane_datagrams_dropped_reported,
                self.relay_dataplane_datagrams_dropped_reported,
                measurement.relay_dataplane_invalid_session_credential_drops_reported,
                self.relay_dataplane_invalid_session_credential_drops_reported,
                measurement.relay_dataplane_invalid_session_credential_drops_prometheus_reported,
                self.relay_dataplane_invalid_session_credential_drops_prometheus_reported,
                measurement.relay_forwarded_bytes_reported,
                self.relay_forwarded_bytes_reported,
                measurement.relay_active_sessions_reported,
                self.relay_active_sessions_reported,
                measurement.control_plane_failover_checked,
                self.daemon_control_plane_failover_checked
            );
        }
        if manifest.control_plane_urls.len() != self.daemon_control_plane_processes {
            bail!(
                "daemon load scenario retained manifest recorded {} control-plane URLs, expected {}",
                manifest.control_plane_urls.len(),
                self.daemon_control_plane_processes
            );
        }
        if manifest.agent_urls.len() != self.daemon_agent_processes {
            bail!(
                "daemon load scenario retained manifest recorded {} agent URLs, expected {}",
                manifest.agent_urls.len(),
                self.daemon_agent_processes
            );
        }
        let mut seen_http_endpoints = BTreeMap::new();
        for (index, url) in manifest.control_plane_urls.iter().enumerate() {
            validate_daemon_manifest_http_endpoint(
                url,
                &format!("control-plane URL {index}"),
                &mut seen_http_endpoints,
            )?;
        }
        validate_daemon_manifest_http_endpoint(
            &manifest.signal_url,
            "signal URL",
            &mut seen_http_endpoints,
        )?;
        validate_daemon_manifest_http_endpoint(
            &manifest.relay_http_url,
            "relay HTTP URL",
            &mut seen_http_endpoints,
        )?;
        validate_daemon_manifest_http_endpoint(
            &manifest.stun_http_url,
            "STUN HTTP URL",
            &mut seen_http_endpoints,
        )?;
        for (index, url) in manifest.agent_urls.iter().enumerate() {
            validate_daemon_manifest_http_endpoint(
                url,
                &format!("agent URL {index}"),
                &mut seen_http_endpoints,
            )?;
        }
        validate_daemon_manifest_socket_addr(manifest.relay_udp_addr, "relay UDP address")?;
        validate_daemon_manifest_socket_addr(manifest.stun_addr, "STUN address")?;
        validate_daemon_manifest_socket_addr(
            manifest.stun_alternate_addr,
            "STUN alternate address",
        )?;
        let mut seen_udp_endpoints = BTreeMap::new();
        validate_daemon_manifest_unique_udp_endpoint(
            manifest.relay_udp_addr,
            "relay UDP address",
            &mut seen_udp_endpoints,
        )?;
        validate_daemon_manifest_unique_udp_endpoint(
            manifest.stun_addr,
            "STUN address",
            &mut seen_udp_endpoints,
        )?;
        validate_daemon_manifest_unique_udp_endpoint(
            manifest.stun_alternate_addr,
            "STUN alternate address",
            &mut seen_udp_endpoints,
        )?;
        if manifest.children.len() != self.daemon_processes {
            bail!(
                "daemon load scenario retained manifest recorded {} child processes, expected {}",
                manifest.children.len(),
                self.daemon_processes
            );
        }

        let canonical_runtime_dir = runtime_dir.canonicalize().with_context(|| {
            format!(
                "daemon load scenario retained runtime directory {} cannot be canonicalized",
                runtime_dir.display()
            )
        })?;
        let mut expected_runtime_entries = expected_daemon_retained_runtime_entries();
        let mut child_roles = Vec::with_capacity(manifest.children.len());
        let mut exited_roles = Vec::new();
        let mut running_roles = Vec::new();
        let mut seen_log_paths = BTreeSet::new();
        let mut seen_log_serials = BTreeSet::new();
        let mut seen_child_pids = BTreeMap::new();
        let mut previous_log_serial = None;
        for child in &manifest.children {
            child_roles.push(child.role.clone());
            validate_daemon_manifest_child_command(child, &manifest.iparsd_binary.path)?;
            validate_daemon_manifest_child_lifecycle(
                child,
                manifest.started_at,
                manifest.updated_at,
            )?;
            let Some(log_path) = &child.log_path else {
                bail!(
                    "daemon load scenario retained manifest child {} is missing log path",
                    child.role
                );
            };
            let Some(recorded_log_bytes) = child.log_bytes else {
                bail!(
                    "daemon load scenario retained manifest child {} is missing log byte count",
                    child.role
                );
            };
            let Some(recorded_log_tail_sha256) = child
                .log_tail_sha256
                .as_deref()
                .filter(|value| !value.is_empty())
            else {
                bail!(
                    "daemon load scenario retained manifest child {} is missing log tail hash",
                    child.role
                );
            };
            let log_metadata = std::fs::symlink_metadata(log_path).with_context(|| {
                format!(
                    "daemon load scenario retained manifest child {} log {} is not accessible",
                    child.role,
                    log_path.display()
                )
            })?;
            if log_metadata.file_type().is_symlink() || !log_metadata.is_file() {
                bail!(
                    "daemon load scenario retained manifest child {} log {} is not a regular file",
                    child.role,
                    log_path.display()
                );
            }
            validate_daemon_retained_path_mode(
                log_path,
                &log_metadata,
                0o600,
                &format!("retained manifest child {} log", child.role),
            )?;
            let canonical_log_path = log_path.canonicalize().with_context(|| {
                format!(
                    "daemon load scenario retained manifest child {} log {} cannot be canonicalized",
                    child.role,
                    log_path.display()
                )
            })?;
            if !canonical_log_path.starts_with(&canonical_runtime_dir) {
                bail!(
                    "daemon load scenario retained manifest child {} log {} is outside retained runtime directory {}",
                    child.role,
                    canonical_log_path.display(),
                    canonical_runtime_dir.display()
                );
            }
            if !seen_log_paths.insert(canonical_log_path.clone()) {
                bail!(
                    "daemon load scenario retained manifest child {} log {} is duplicated",
                    child.role,
                    canonical_log_path.display()
                );
            }
            let log_file_name = log_path
                .file_name()
                .and_then(|name| name.to_str())
                .with_context(|| {
                    format!(
                        "daemon load scenario retained manifest child {} log {} has invalid file name",
                        child.role,
                        log_path.display()
                    )
                })?;
            let log_serial = validate_daemon_child_log_file_name(&child.role, log_file_name)?;
            if !seen_log_serials.insert(log_serial) {
                bail!(
                    "daemon load scenario retained manifest child {} log file name {} reuses serial prefix {}",
                    child.role,
                    log_file_name,
                    log_serial
                );
            }
            if let Some(previous_log_serial) = previous_log_serial {
                if log_serial <= previous_log_serial {
                    bail!(
                        "daemon load scenario retained manifest child {} log file name {} serial prefix {} is not greater than previous serial prefix {}",
                        child.role,
                        log_file_name,
                        log_serial,
                        previous_log_serial
                    );
                }
            }
            previous_log_serial = Some(log_serial);
            expected_runtime_entries.insert(log_file_name.to_string());
            let log_diagnostics = daemon_log_diagnostics(log_path).with_context(|| {
                format!(
                    "daemon load scenario retained manifest child {} log {} diagnostics are unavailable",
                    child.role,
                    log_path.display()
                )
            })?;
            if log_diagnostics.bytes != recorded_log_bytes
                || log_diagnostics.tail_sha256 != recorded_log_tail_sha256
            {
                bail!(
                    "daemon load scenario retained manifest child {} log diagnostics mismatch: bytes={}/{}, tail_sha256={}/{}",
                    child.role,
                    recorded_log_bytes,
                    log_diagnostics.bytes,
                    recorded_log_tail_sha256,
                    log_diagnostics.tail_sha256
                );
            }
            if log_diagnostics.bytes == 0 {
                bail!(
                    "daemon load scenario retained manifest child {} log {} is empty",
                    child.role,
                    log_path.display()
                );
            }
            if let Some(pid) = child.pid {
                if pid == 0 {
                    bail!(
                        "daemon load scenario retained manifest child {} recorded invalid PID 0",
                        child.role
                    );
                }
                if let Some(previous_role) = seen_child_pids.insert(pid, child.role.clone()) {
                    bail!(
                        "daemon load scenario retained manifest child {} PID {} duplicates child {}",
                        child.role,
                        pid,
                        previous_role
                    );
                }
            }
            match child.state {
                DaemonRuntimeManifestChildState::Running => {
                    if child.pid.is_none() {
                        bail!(
                            "daemon load scenario retained manifest running child {} is missing a PID",
                            child.role
                        );
                    }
                    running_roles.push(child.role.clone());
                }
                DaemonRuntimeManifestChildState::Exited => {
                    if child.pid.is_none() {
                        bail!(
                            "daemon load scenario retained manifest exited child {} is missing a PID",
                            child.role
                        );
                    }
                    let Some(exit_status) = child.exit_status.as_deref() else {
                        bail!(
                            "daemon load scenario retained manifest exited child {} is missing exit status",
                            child.role
                        );
                    };
                    if let Some(exit_code) = child.exit_code {
                        bail!(
                            "daemon load scenario retained manifest exited child {} recorded numeric exit code {exit_code}; expected harness-controlled shutdown",
                            child.role
                        );
                    }
                    if !exit_status.starts_with("signal:") {
                        bail!(
                            "daemon load scenario retained manifest exited child {} recorded non-signal exit status {exit_status}; expected harness-controlled shutdown",
                            child.role
                        );
                    }
                    exited_roles.push(child.role.clone());
                }
            }
        }
        exited_roles.sort();
        running_roles.sort();
        if !running_roles.is_empty() {
            bail!(
                "daemon load scenario retained manifest still has running child roles {:?}; expected completed manifest after child shutdown",
                running_roles
            );
        }
        if exited_roles.len() != self.daemon_processes {
            bail!(
                "daemon load scenario retained manifest exited {} child processes, expected {}",
                exited_roles.len(),
                self.daemon_processes
            );
        }
        let expected_role_sequence = self.expected_daemon_child_role_sequence();
        if child_roles != expected_role_sequence {
            bail!(
                "daemon load scenario retained manifest child role sequence {:?} does not match expected {:?}",
                child_roles,
                expected_role_sequence
            );
        }
        let expected_roles = self.expected_daemon_child_roles();
        if exited_roles != expected_roles {
            bail!(
                "daemon load scenario retained manifest child roles {:?} do not match expected {:?}",
                exited_roles,
                expected_roles
            );
        }
        validate_daemon_retained_runtime_entries(runtime_dir, &expected_runtime_entries)?;

        Ok(())
    }

    fn expected_daemon_child_roles(&self) -> Vec<String> {
        let mut roles = self.expected_daemon_child_role_sequence();
        roles.sort();
        roles
    }

    fn expected_daemon_child_role_sequence(&self) -> Vec<String> {
        let mut roles = Vec::with_capacity(self.daemon_processes);
        roles.extend(
            (0..self.daemon_control_plane_processes).map(|index| format!("control-plane-{index}")),
        );
        roles.extend(["signal", "relay", "stun"].into_iter().map(str::to_string));
        roles.extend((0..self.daemon_agent_processes).map(|_| "agent".to_string()));
        roles
    }
}

fn validate_daemon_manifest_http_endpoint(
    value: &str,
    label: &str,
    seen_http_endpoints: &mut BTreeMap<String, String>,
) -> anyhow::Result<()> {
    let parsed = reqwest::Url::parse(value).with_context(|| {
        format!("daemon load scenario retained manifest {label} must be an absolute HTTP(S) URL")
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!(
            "daemon load scenario retained manifest {label} uses unsupported URL scheme {}",
            parsed.scheme()
        );
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("daemon load scenario retained manifest {label} must not include credentials");
    }
    let Some(host) = parsed.host_str().filter(|host| !host.is_empty()) else {
        bail!("daemon load scenario retained manifest {label} is missing a host");
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        validate_daemon_manifest_ip_addr(ip, label)?;
    }
    let Some(port) = parsed.port() else {
        bail!("daemon load scenario retained manifest {label} must include an explicit port");
    };
    if port == 0 {
        bail!("daemon load scenario retained manifest {label} uses port zero");
    }
    if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
        bail!(
            "daemon load scenario retained manifest {label} must be a base URL without path, query, or fragment"
        );
    }

    let endpoint_key = format!("{}://{}:{port}", parsed.scheme(), host.to_ascii_lowercase());
    if let Some(existing_label) =
        seen_http_endpoints.insert(endpoint_key.clone(), label.to_string())
    {
        bail!(
            "daemon load scenario retained manifest duplicate HTTP endpoint {endpoint_key} for {existing_label} and {label}"
        );
    }

    Ok(())
}

fn validate_daemon_manifest_socket_addr(addr: SocketAddr, label: &str) -> anyhow::Result<()> {
    if addr.port() == 0 {
        bail!("daemon load scenario retained manifest {label} uses port zero");
    }
    validate_daemon_manifest_ip_addr(addr.ip(), label)
}

fn validate_daemon_manifest_ip_addr(ip: IpAddr, label: &str) -> anyhow::Result<()> {
    let unusable = match ip {
        IpAddr::V4(addr) => addr.is_unspecified() || addr.is_multicast() || addr.is_broadcast(),
        IpAddr::V6(addr) => addr.is_unspecified() || addr.is_multicast(),
    };
    if unusable {
        bail!("daemon load scenario retained manifest {label} uses unusable IP address {ip}");
    }
    Ok(())
}

fn validate_daemon_manifest_unique_udp_endpoint(
    addr: SocketAddr,
    label: &'static str,
    seen_udp_endpoints: &mut BTreeMap<SocketAddr, &'static str>,
) -> anyhow::Result<()> {
    if let Some(existing_label) = seen_udp_endpoints.insert(addr, label) {
        bail!(
            "daemon load scenario retained manifest duplicate UDP endpoint {addr} for {existing_label} and {label}"
        );
    }
    Ok(())
}

fn validate_daemon_retained_path_mode(
    path: &Path,
    metadata: &std::fs::Metadata,
    expected_mode: u32,
    label: &str,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != expected_mode {
            bail!(
                "daemon load scenario {label} {} permissions are {mode:o}; expected {expected_mode:o}",
                path.display()
            );
        }
        validate_daemon_retained_path_owner(
            path,
            metadata,
            nix::unistd::geteuid().as_raw(),
            label,
        )?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, metadata, expected_mode, label);
    }
    Ok(())
}

fn read_bounded_regular_file(path: &Path, label: &str, max_bytes: u64) -> anyhow::Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("{label} {} is not accessible", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{label} {} is not a regular file", path.display());
    }
    if metadata.len() > max_bytes {
        bail!(
            "{label} {} exceeds maximum size of {max_bytes} bytes",
            path.display()
        );
    }

    let file = std::fs::File::open(path)
        .with_context(|| format!("{label} {} is not readable", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("{label} {} cannot be inspected after open", path.display()))?;
    if !metadata.is_file() {
        bail!("{label} {} is not a regular file", path.display());
    }
    if metadata.len() > max_bytes {
        bail!(
            "{label} {} exceeds maximum size of {max_bytes} bytes",
            path.display()
        );
    }

    let mut bytes = Vec::new();
    let mut reader = file.take(max_bytes + 1);
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("{label} {} is not readable", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        bail!(
            "{label} {} exceeds maximum size of {max_bytes} bytes",
            path.display()
        );
    }
    Ok(bytes)
}

fn expected_daemon_retained_runtime_entries() -> BTreeSet<String> {
    [
        DAEMON_RUNTIME_MANIFEST_FILE,
        DAEMON_CONTROL_PLANE_SQLITE_FILE,
        "control-plane.sqlite-wal",
        "control-plane.sqlite-shm",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn validate_daemon_retained_runtime_entries(
    runtime_dir: &Path,
    expected_entries: &BTreeSet<String>,
) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(runtime_dir).with_context(|| {
        format!(
            "daemon load scenario retained runtime directory {} cannot be scanned",
            runtime_dir.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "daemon load scenario retained runtime directory {} contains unreadable entry",
                runtime_dir.display()
            )
        })?;
        let Some(file_name) = entry.file_name().to_str().map(str::to_string) else {
            bail!(
                "daemon load scenario retained runtime directory {} contains non-UTF-8 entry name",
                runtime_dir.display()
            );
        };
        if file_name.ends_with(DAEMON_JOIN_TOKEN_FILE_SUFFIX) {
            bail!(
                "daemon load scenario retained runtime directory {} still contains join token file {} after agent startup",
                runtime_dir.display(),
                entry.path().display()
            );
        }
        if file_name.ends_with(DAEMON_AGENT_STATE_FILE_SUFFIX) {
            bail!(
                "daemon load scenario retained runtime directory {} still contains agent state file {} after child shutdown",
                runtime_dir.display(),
                entry.path().display()
            );
        }
        if is_daemon_runtime_manifest_temp_name(&file_name) {
            bail!(
                "daemon load scenario retained runtime directory {} still contains temporary manifest file {} after atomic manifest replacement",
                runtime_dir.display(),
                entry.path().display()
            );
        }
        if !expected_entries.contains(&file_name) {
            bail!(
                "daemon load scenario retained runtime directory {} contains unexpected entry {}",
                runtime_dir.display(),
                entry.path().display()
            );
        }
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).with_context(|| {
            format!(
                "daemon load scenario retained runtime entry {} is not accessible",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "daemon load scenario retained runtime entry {} is not a regular file",
                path.display()
            );
        }
        validate_daemon_retained_path_mode(&path, &metadata, 0o600, "retained runtime entry")?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_daemon_retained_path_owner(
    path: &Path,
    metadata: &std::fs::Metadata,
    expected_uid: u32,
    label: &str,
) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let owner_uid = metadata.uid();
    if owner_uid != expected_uid {
        bail!(
            "daemon load scenario {label} {} owner uid is {owner_uid}; expected current process uid {expected_uid}",
            path.display()
        );
    }
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
            .await
            .with_context(|| format!("failed to upsert synthetic signal node {index}"))?;
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
        stun_http_requests: 0,
        relay_udp_sessions: 0,
        relay_packets_per_session: 0,
        relay_payload_bytes_per_packet: 0,
        relay_udp_packets_sent: 0,
        relay_udp_packets_received: 0,
        relay_udp_payload_bytes_sent: 0,
        relay_udp_payload_bytes_received: 0,
        daemon_failover_relay_udp_packets_sent: 0,
        daemon_failover_relay_udp_packets_received: 0,
        daemon_failover_relay_udp_payload_bytes_sent: 0,
        daemon_failover_relay_udp_payload_bytes_received: 0,
        relay_dataplane_datagrams_received_reported: 0,
        relay_dataplane_datagrams_forwarded_reported: 0,
        relay_dataplane_datagrams_dropped_reported: 0,
        relay_dataplane_invalid_session_credential_drops_reported: 0,
        relay_dataplane_invalid_session_credential_drops_prometheus_reported: 0,
        relay_forwarded_bytes_reported: 0,
        relay_active_sessions_reported: 0,
        relay_available_sessions_reported: 0,
        relay_max_sessions_reported: 0,
        relay_max_mbps_reported: 0,
        relay_enabled_by_policy_reported: false,
        relay_e2e_only_reported: false,
        relay_admission_attempts_reported: 0,
        relay_admission_successes_reported: 0,
        relay_admission_failures_reported: 0,
        relay_admission_failures_by_reason_reported: BTreeMap::new(),
        relay_mbps: 0.0,
        daemon_processes: 0,
        daemon_runtime_dir: None,
        daemon_runtime_manifest: None,
        daemon_http_readiness_timeout_seconds: 0,
        daemon_agent_readiness_timeout_seconds: 0,
        daemon_agent_processes: 0,
        daemon_agent_status_endpoints: 0,
        daemon_agent_candidate_count_min: 0,
        daemon_agent_candidate_count_max: 0,
        daemon_agent_path_status_endpoints: 0,
        daemon_agent_paths_total: 0,
        daemon_agent_reachable_paths_total: 0,
        daemon_agent_path_count_min: 0,
        daemon_agent_path_count_max: 0,
        daemon_agent_failover_status_endpoints: 0,
        daemon_agent_failover_candidate_count_min: 0,
        daemon_agent_failover_candidate_count_max: 0,
        daemon_agent_failover_path_status_endpoints: 0,
        daemon_agent_failover_paths_total: 0,
        daemon_agent_failover_reachable_paths_total: 0,
        daemon_agent_failover_path_count_min: 0,
        daemon_agent_failover_path_count_max: 0,
        daemon_control_plane_processes: 0,
        daemon_control_plane_metrics_endpoints: 0,
        daemon_control_plane_peer_map_endpoints: 0,
        daemon_control_plane_peer_map_edges_min: 0,
        daemon_control_plane_peer_map_edges_max: 0,
        daemon_control_plane_peer_maps_consistent: false,
        daemon_control_plane_failover_checked: false,
        daemon_control_plane_failover_survivor_endpoints: 0,
        daemon_control_plane_failover_peer_map_edges_min: 0,
        daemon_control_plane_failover_peer_map_edges_max: 0,
        daemon_control_plane_failover_peer_maps_consistent: false,
        daemon_control_plane_failover_metrics_endpoints: 0,
        daemon_control_plane_failover_metrics_consistent: false,
        daemon_control_plane_failover_relay_candidates_min: 0,
        daemon_control_plane_failover_relay_candidates_max: 0,
        daemon_control_plane_failover_path_count_min: 0,
        daemon_control_plane_failover_path_count_max: 0,
        daemon_control_plane_failover_reachable_path_count_min: 0,
        daemon_control_plane_failover_reachable_path_count_max: 0,
        daemon_control_plane_failover_path_status_requests: 0,
        daemon_control_plane_failover_path_status_count_min: 0,
        daemon_control_plane_failover_path_status_count_max: 0,
        daemon_control_plane_failover_path_status_reachable_count_min: 0,
        daemon_control_plane_failover_path_status_reachable_count_max: 0,
        daemon_control_plane_failover_path_status_stale_count_max: 0,
        daemon_control_plane_failover_healthy_nodes_min: 0,
        daemon_control_plane_failover_healthy_nodes_max: 0,
        daemon_control_plane_failover_degraded_nodes_min: 0,
        daemon_control_plane_failover_degraded_nodes_max: 0,
        daemon_control_plane_failover_unhealthy_nodes_min: 0,
        daemon_control_plane_failover_unhealthy_nodes_max: 0,
        daemon_control_plane_relay_candidates_min: 0,
        daemon_control_plane_relay_candidates_max: 0,
        daemon_control_plane_path_count_min: 0,
        daemon_control_plane_path_count_max: 0,
        daemon_control_plane_reachable_path_count_min: 0,
        daemon_control_plane_reachable_path_count_max: 0,
        daemon_control_plane_path_status_requests: 0,
        daemon_control_plane_path_status_count_min: 0,
        daemon_control_plane_path_status_count_max: 0,
        daemon_control_plane_path_status_reachable_count_min: 0,
        daemon_control_plane_path_status_reachable_count_max: 0,
        daemon_control_plane_path_status_stale_count_max: 0,
        daemon_control_plane_healthy_nodes: 0,
        daemon_control_plane_healthy_nodes_min: 0,
        daemon_control_plane_healthy_nodes_max: 0,
        daemon_control_plane_degraded_nodes: 0,
        daemon_control_plane_degraded_nodes_min: 0,
        daemon_control_plane_degraded_nodes_max: 0,
        daemon_control_plane_unhealthy_nodes: 0,
        daemon_control_plane_unhealthy_nodes_min: 0,
        daemon_control_plane_unhealthy_nodes_max: 0,
        daemon_control_plane_metrics_consistent: false,
        daemon_signal_health_reports: 0,
        daemon_signal_healthy_nodes: 0,
        daemon_signal_degraded_nodes: 0,
        daemon_signal_unhealthy_nodes: 0,
        daemon_stun: DaemonStunReport::default(),
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
        stun_http_requests: 0,
        relay_udp_sessions: 0,
        relay_packets_per_session: 0,
        relay_payload_bytes_per_packet: 0,
        relay_udp_packets_sent: 0,
        relay_udp_packets_received: 0,
        relay_udp_payload_bytes_sent: 0,
        relay_udp_payload_bytes_received: 0,
        daemon_failover_relay_udp_packets_sent: 0,
        daemon_failover_relay_udp_packets_received: 0,
        daemon_failover_relay_udp_payload_bytes_sent: 0,
        daemon_failover_relay_udp_payload_bytes_received: 0,
        relay_dataplane_datagrams_received_reported: 0,
        relay_dataplane_datagrams_forwarded_reported: 0,
        relay_dataplane_datagrams_dropped_reported: 0,
        relay_dataplane_invalid_session_credential_drops_reported: 0,
        relay_dataplane_invalid_session_credential_drops_prometheus_reported: 0,
        relay_forwarded_bytes_reported: 0,
        relay_active_sessions_reported: 0,
        relay_available_sessions_reported: 0,
        relay_max_sessions_reported: 0,
        relay_max_mbps_reported: 0,
        relay_enabled_by_policy_reported: false,
        relay_e2e_only_reported: false,
        relay_admission_attempts_reported: 0,
        relay_admission_successes_reported: 0,
        relay_admission_failures_reported: 0,
        relay_admission_failures_by_reason_reported: BTreeMap::new(),
        relay_mbps: 0.0,
        daemon_processes: 0,
        daemon_runtime_dir: None,
        daemon_runtime_manifest: None,
        daemon_http_readiness_timeout_seconds: 0,
        daemon_agent_readiness_timeout_seconds: 0,
        daemon_agent_processes: 0,
        daemon_agent_status_endpoints: 0,
        daemon_agent_candidate_count_min: 0,
        daemon_agent_candidate_count_max: 0,
        daemon_agent_path_status_endpoints: 0,
        daemon_agent_paths_total: 0,
        daemon_agent_reachable_paths_total: 0,
        daemon_agent_path_count_min: 0,
        daemon_agent_path_count_max: 0,
        daemon_agent_failover_status_endpoints: 0,
        daemon_agent_failover_candidate_count_min: 0,
        daemon_agent_failover_candidate_count_max: 0,
        daemon_agent_failover_path_status_endpoints: 0,
        daemon_agent_failover_paths_total: 0,
        daemon_agent_failover_reachable_paths_total: 0,
        daemon_agent_failover_path_count_min: 0,
        daemon_agent_failover_path_count_max: 0,
        daemon_control_plane_processes: 0,
        daemon_control_plane_metrics_endpoints: 0,
        daemon_control_plane_peer_map_endpoints: 0,
        daemon_control_plane_peer_map_edges_min: 0,
        daemon_control_plane_peer_map_edges_max: 0,
        daemon_control_plane_peer_maps_consistent: false,
        daemon_control_plane_failover_checked: false,
        daemon_control_plane_failover_survivor_endpoints: 0,
        daemon_control_plane_failover_peer_map_edges_min: 0,
        daemon_control_plane_failover_peer_map_edges_max: 0,
        daemon_control_plane_failover_peer_maps_consistent: false,
        daemon_control_plane_failover_metrics_endpoints: 0,
        daemon_control_plane_failover_metrics_consistent: false,
        daemon_control_plane_failover_relay_candidates_min: 0,
        daemon_control_plane_failover_relay_candidates_max: 0,
        daemon_control_plane_failover_path_count_min: 0,
        daemon_control_plane_failover_path_count_max: 0,
        daemon_control_plane_failover_reachable_path_count_min: 0,
        daemon_control_plane_failover_reachable_path_count_max: 0,
        daemon_control_plane_failover_path_status_requests: 0,
        daemon_control_plane_failover_path_status_count_min: 0,
        daemon_control_plane_failover_path_status_count_max: 0,
        daemon_control_plane_failover_path_status_reachable_count_min: 0,
        daemon_control_plane_failover_path_status_reachable_count_max: 0,
        daemon_control_plane_failover_path_status_stale_count_max: 0,
        daemon_control_plane_failover_healthy_nodes_min: 0,
        daemon_control_plane_failover_healthy_nodes_max: 0,
        daemon_control_plane_failover_degraded_nodes_min: 0,
        daemon_control_plane_failover_degraded_nodes_max: 0,
        daemon_control_plane_failover_unhealthy_nodes_min: 0,
        daemon_control_plane_failover_unhealthy_nodes_max: 0,
        daemon_control_plane_relay_candidates_min: 0,
        daemon_control_plane_relay_candidates_max: 0,
        daemon_control_plane_path_count_min: 0,
        daemon_control_plane_path_count_max: 0,
        daemon_control_plane_reachable_path_count_min: 0,
        daemon_control_plane_reachable_path_count_max: 0,
        daemon_control_plane_path_status_requests: 0,
        daemon_control_plane_path_status_count_min: 0,
        daemon_control_plane_path_status_count_max: 0,
        daemon_control_plane_path_status_reachable_count_min: 0,
        daemon_control_plane_path_status_reachable_count_max: 0,
        daemon_control_plane_path_status_stale_count_max: 0,
        daemon_control_plane_healthy_nodes: 0,
        daemon_control_plane_healthy_nodes_min: 0,
        daemon_control_plane_healthy_nodes_max: 0,
        daemon_control_plane_degraded_nodes: 0,
        daemon_control_plane_degraded_nodes_min: 0,
        daemon_control_plane_degraded_nodes_max: 0,
        daemon_control_plane_unhealthy_nodes: 0,
        daemon_control_plane_unhealthy_nodes_min: 0,
        daemon_control_plane_unhealthy_nodes_max: 0,
        daemon_control_plane_metrics_consistent: false,
        daemon_signal_health_reports: 0,
        daemon_signal_healthy_nodes: 0,
        daemon_signal_degraded_nodes: 0,
        daemon_signal_unhealthy_nodes: 0,
        daemon_stun: DaemonStunReport::default(),
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
    let mut first_admission = None;
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
        first_admission.get_or_insert_with(|| admission.clone());

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
    if let Some(admission) = &first_admission {
        send_invalid_relay_session_credential_datagram(
            &left_socket,
            services.udp_addr,
            admission,
            options.payload_bytes,
        )
        .await?;
    }
    let relay_elapsed = relay_started.elapsed();
    let relay_millis = relay_elapsed.as_millis();
    let expected_invalid_credential_drops = u64::from(first_admission.is_some());
    let status = wait_for_relay_status_with_invalid_credential_drop(
        &client,
        &services.http_url,
        expected_invalid_credential_drops,
        Duration::from_secs(2),
    )
    .await?;
    let metrics = get_text(
        &client,
        format!("{}/metrics", services.http_url),
        "relay metrics",
    )
    .await?;
    let forwarded_bytes = prometheus_metric_u64(&metrics, "ipars_relay_bytes_forwarded_total")?;
    let prometheus_invalid_credential_drops = prometheus_metric_labeled_u64(
        &metrics,
        "ipars_relay_datagrams_dropped_by_reason_total",
        &[(
            "reason",
            RelayDataplaneDropReason::InvalidSessionCredential.as_str(),
        )],
    )?;
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
        stun_http_requests: 0,
        relay_udp_sessions: status.capability.active_sessions as usize,
        relay_packets_per_session: options.packets_per_session,
        relay_payload_bytes_per_packet: options.payload_bytes,
        relay_udp_packets_sent: packets_sent,
        relay_udp_packets_received: packets_received,
        relay_udp_payload_bytes_sent: payload_bytes_sent,
        relay_udp_payload_bytes_received: payload_bytes_received,
        daemon_failover_relay_udp_packets_sent: 0,
        daemon_failover_relay_udp_packets_received: 0,
        daemon_failover_relay_udp_payload_bytes_sent: 0,
        daemon_failover_relay_udp_payload_bytes_received: 0,
        relay_dataplane_datagrams_received_reported: status.dataplane.datagrams_received,
        relay_dataplane_datagrams_forwarded_reported: status.dataplane.datagrams_forwarded,
        relay_dataplane_datagrams_dropped_reported: status.dataplane.datagrams_dropped,
        relay_dataplane_invalid_session_credential_drops_reported:
            relay_invalid_session_credential_drops(&status),
        relay_dataplane_invalid_session_credential_drops_prometheus_reported:
            prometheus_invalid_credential_drops,
        relay_forwarded_bytes_reported: forwarded_bytes,
        relay_active_sessions_reported: status.capability.active_sessions as usize,
        relay_available_sessions_reported: status.capability.available_capacity() as usize,
        relay_max_sessions_reported: status.capability.max_sessions as usize,
        relay_max_mbps_reported: status.capability.max_mbps,
        relay_enabled_by_policy_reported: status.capability.enabled_by_policy,
        relay_e2e_only_reported: status.capability.e2e_only,
        relay_admission_attempts_reported: status.admission_attempt_count,
        relay_admission_successes_reported: status.admission_success_count,
        relay_admission_failures_reported: status.admission_failure_count,
        relay_admission_failures_by_reason_reported: status.admission_failures_by_reason,
        relay_mbps,
        daemon_processes: 0,
        daemon_runtime_dir: None,
        daemon_runtime_manifest: None,
        daemon_http_readiness_timeout_seconds: 0,
        daemon_agent_readiness_timeout_seconds: 0,
        daemon_agent_processes: 0,
        daemon_agent_status_endpoints: 0,
        daemon_agent_candidate_count_min: 0,
        daemon_agent_candidate_count_max: 0,
        daemon_agent_path_status_endpoints: 0,
        daemon_agent_paths_total: 0,
        daemon_agent_reachable_paths_total: 0,
        daemon_agent_path_count_min: 0,
        daemon_agent_path_count_max: 0,
        daemon_agent_failover_status_endpoints: 0,
        daemon_agent_failover_candidate_count_min: 0,
        daemon_agent_failover_candidate_count_max: 0,
        daemon_agent_failover_path_status_endpoints: 0,
        daemon_agent_failover_paths_total: 0,
        daemon_agent_failover_reachable_paths_total: 0,
        daemon_agent_failover_path_count_min: 0,
        daemon_agent_failover_path_count_max: 0,
        daemon_control_plane_processes: 0,
        daemon_control_plane_metrics_endpoints: 0,
        daemon_control_plane_peer_map_endpoints: 0,
        daemon_control_plane_peer_map_edges_min: 0,
        daemon_control_plane_peer_map_edges_max: 0,
        daemon_control_plane_peer_maps_consistent: false,
        daemon_control_plane_failover_checked: false,
        daemon_control_plane_failover_survivor_endpoints: 0,
        daemon_control_plane_failover_peer_map_edges_min: 0,
        daemon_control_plane_failover_peer_map_edges_max: 0,
        daemon_control_plane_failover_peer_maps_consistent: false,
        daemon_control_plane_failover_metrics_endpoints: 0,
        daemon_control_plane_failover_metrics_consistent: false,
        daemon_control_plane_failover_relay_candidates_min: 0,
        daemon_control_plane_failover_relay_candidates_max: 0,
        daemon_control_plane_failover_path_count_min: 0,
        daemon_control_plane_failover_path_count_max: 0,
        daemon_control_plane_failover_reachable_path_count_min: 0,
        daemon_control_plane_failover_reachable_path_count_max: 0,
        daemon_control_plane_failover_path_status_requests: 0,
        daemon_control_plane_failover_path_status_count_min: 0,
        daemon_control_plane_failover_path_status_count_max: 0,
        daemon_control_plane_failover_path_status_reachable_count_min: 0,
        daemon_control_plane_failover_path_status_reachable_count_max: 0,
        daemon_control_plane_failover_path_status_stale_count_max: 0,
        daemon_control_plane_failover_healthy_nodes_min: 0,
        daemon_control_plane_failover_healthy_nodes_max: 0,
        daemon_control_plane_failover_degraded_nodes_min: 0,
        daemon_control_plane_failover_degraded_nodes_max: 0,
        daemon_control_plane_failover_unhealthy_nodes_min: 0,
        daemon_control_plane_failover_unhealthy_nodes_max: 0,
        daemon_control_plane_relay_candidates_min: 0,
        daemon_control_plane_relay_candidates_max: 0,
        daemon_control_plane_path_count_min: 0,
        daemon_control_plane_path_count_max: 0,
        daemon_control_plane_reachable_path_count_min: 0,
        daemon_control_plane_reachable_path_count_max: 0,
        daemon_control_plane_path_status_requests: 0,
        daemon_control_plane_path_status_count_min: 0,
        daemon_control_plane_path_status_count_max: 0,
        daemon_control_plane_path_status_reachable_count_min: 0,
        daemon_control_plane_path_status_reachable_count_max: 0,
        daemon_control_plane_path_status_stale_count_max: 0,
        daemon_control_plane_healthy_nodes: 0,
        daemon_control_plane_healthy_nodes_min: 0,
        daemon_control_plane_healthy_nodes_max: 0,
        daemon_control_plane_degraded_nodes: 0,
        daemon_control_plane_degraded_nodes_min: 0,
        daemon_control_plane_degraded_nodes_max: 0,
        daemon_control_plane_unhealthy_nodes: 0,
        daemon_control_plane_unhealthy_nodes_min: 0,
        daemon_control_plane_unhealthy_nodes_max: 0,
        daemon_control_plane_metrics_consistent: false,
        daemon_signal_health_reports: 0,
        daemon_signal_healthy_nodes: 0,
        daemon_signal_degraded_nodes: 0,
        daemon_signal_unhealthy_nodes: 0,
        daemon_stun: DaemonStunReport::default(),
        registration_millis: 0,
        peer_map_millis: 0,
        signal_millis: 0,
        relay_millis,
    })
}

async fn send_invalid_relay_session_credential_datagram(
    socket: &UdpSocket,
    relay_addr: SocketAddr,
    admission: &RelayAdmissionResponse,
    payload_bytes: usize,
) -> anyhow::Result<()> {
    let payload = relay_payload(0, 0, payload_bytes);
    let datagram = encode_relay_datagram(
        &admission.session_id,
        "ipars-load-invalid-session-token",
        &payload,
    )?;
    socket
        .send_to(&datagram, relay_addr)
        .await
        .context("failed to send invalid relay credential probe")?;
    Ok(())
}

async fn wait_for_relay_status_with_invalid_credential_drop(
    client: &reqwest::Client,
    relay_http_url: &str,
    expected_invalid_credential_drops: u64,
    timeout: Duration,
) -> anyhow::Result<RelayStatusResponse> {
    let started_at = Instant::now();
    loop {
        let status: RelayStatusResponse = get_json(
            client,
            format!("{relay_http_url}/v1/status"),
            "relay status",
        )
        .await?;
        if relay_invalid_session_credential_drops(&status) >= expected_invalid_credential_drops {
            return Ok(status);
        }
        if started_at.elapsed() >= timeout {
            bail!(
                "relay status did not report {expected_invalid_credential_drops} invalid credential drops before timeout; latest drops={:?}",
                status.dataplane.drops_by_reason
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn relay_invalid_session_credential_drops(status: &RelayStatusResponse) -> u64 {
    status
        .dataplane
        .drops_by_reason
        .get(&RelayDataplaneDropReason::InvalidSessionCredential)
        .copied()
        .unwrap_or_default()
}

async fn run_daemon_scenario(
    scenario: Scenario,
    iparsd_bin: &Path,
    options: DaemonLoadOptions,
) -> anyhow::Result<LoadReport> {
    let relay_options = options.relay_options.validate()?;
    let control_plane_processes =
        validate_daemon_control_plane_processes(options.control_plane_processes)?;
    let agent_processes = validate_daemon_agent_processes(options.agent_processes, scenario)?;
    let http_readiness_timeout = validate_daemon_timeout(
        options.http_readiness_timeout,
        "--daemon-http-readiness-timeout-seconds",
    )?;
    let agent_readiness_timeout = validate_daemon_timeout(
        options.agent_readiness_timeout,
        "--daemon-agent-readiness-timeout-seconds",
    )?;
    let issuer = IdentityKeyPair::generate();
    let key_id = KeyId::from_string("load-key");
    let cluster_id = ClusterId::from_string(format!("load-daemon-{:?}", scenario.name));
    let mut services = DaemonProcessGroup::start(
        iparsd_bin,
        scenario,
        cluster_id.clone(),
        &issuer,
        &key_id,
        DaemonLoadOptions {
            control_plane_processes,
            agent_processes,
            keep_runtime_dir: options.keep_runtime_dir,
            http_readiness_timeout,
            agent_readiness_timeout,
            relay_options,
        },
    )
    .await?;
    let client = reqwest::Client::new();

    services.write_manifest(DaemonRuntimePhase::RegistrationProbe)?;
    let registration_started = Instant::now();
    let mut agent_statuses: Vec<AgentStatusResponse> = Vec::with_capacity(agent_processes);
    for url in &services.agent_urls {
        agent_statuses
            .push(get_json(&client, format!("{url}/v1/status"), "daemon agent status").await?);
    }
    let agent_status_summary = daemon_agent_status_summary(&agent_statuses)?;
    services.ensure_running(DaemonRuntimePhase::RegistrationProbe)?;
    let registration_millis = registration_started.elapsed().as_millis();

    services.write_manifest(DaemonRuntimePhase::PeerMapProbe)?;
    let peer_map_started = Instant::now();
    let peer_map_probe =
        daemon_peer_map_probe(&client, &services.control_plane_urls, &agent_statuses).await?;
    let peer_map_requests = agent_statuses.len() * services.control_plane_urls.len();
    let peer_map_edges_seen = peer_map_probe.canonical_edge_count;
    let peer_records = peer_map_probe.canonical_peer_records;
    let peer_map_summary = peer_map_probe.summary;
    services.ensure_running(DaemonRuntimePhase::PeerMapProbe)?;
    let peer_map_millis = peer_map_started.elapsed().as_millis();

    services.write_manifest(DaemonRuntimePhase::SignalUpsert)?;
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
    services.ensure_running(DaemonRuntimePhase::SignalUpsert)?;

    services.write_manifest(DaemonRuntimePhase::SignalNegotiation)?;
    let signal_started = Instant::now();
    let advertised_routes = daemon_advertised_route_count(&peer_records);
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
    services.ensure_running(DaemonRuntimePhase::SignalNegotiation)?;
    let signal_millis = signal_started.elapsed().as_millis();

    services.write_manifest(DaemonRuntimePhase::AgentPathValidation)?;
    let expected_agent_path_count =
        expected_daemon_agent_path_count(active_pair_count, agent_statuses.len());
    drive_daemon_agent_peer_activity(
        &client,
        &services.agent_urls,
        &agent_statuses,
        active_pair_count,
    )
    .await?;
    let agent_path_summary = wait_for_daemon_agent_path_summary(
        &client,
        &services.agent_urls,
        &agent_statuses,
        expected_agent_path_count,
        agent_readiness_timeout,
    )
    .await?;
    let control_path_summary = wait_for_daemon_control_plane_path_summary(
        &client,
        &services.control_plane_urls,
        expected_agent_path_count,
        agent_readiness_timeout,
    )
    .await?;
    let control_path_status_summary = wait_for_daemon_control_plane_path_status_summary(
        &client,
        &services.control_plane_urls,
        &agent_statuses,
        expected_agent_path_count,
        agent_readiness_timeout,
    )
    .await?;
    services.ensure_running(DaemonRuntimePhase::AgentPathValidation)?;

    services.write_manifest(DaemonRuntimePhase::RelayMeasurement)?;
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
    let mut relay_admissions = Vec::with_capacity(active_pair_count);
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
        relay_admissions.push(admission.clone());
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
    if let Some(admission) = relay_admissions.first() {
        send_invalid_relay_session_credential_datagram(
            &left_socket,
            services.relay_udp_addr,
            admission,
            relay_options.payload_bytes,
        )
        .await?;
    }
    services.ensure_running(DaemonRuntimePhase::RelayMeasurement)?;
    let relay_elapsed = relay_started.elapsed();
    let relay_millis = relay_elapsed.as_millis();
    services.write_manifest(DaemonRuntimePhase::FinalMetrics)?;
    let expected_invalid_credential_drops = u64::from(!relay_admissions.is_empty());
    let status = wait_for_relay_status_with_invalid_credential_drop(
        &client,
        &services.relay_http_url,
        expected_invalid_credential_drops,
        agent_readiness_timeout,
    )
    .await?;
    let metrics = get_text(
        &client,
        format!("{}/metrics", services.relay_http_url),
        "daemon relay metrics",
    )
    .await?;
    let forwarded_bytes = prometheus_metric_u64(&metrics, "ipars_relay_bytes_forwarded_total")?;
    let prometheus_invalid_credential_drops = prometheus_metric_labeled_u64(
        &metrics,
        "ipars_relay_datagrams_dropped_by_reason_total",
        &[(
            "reason",
            RelayDataplaneDropReason::InvalidSessionCredential.as_str(),
        )],
    )?;
    let relay_mbps = if relay_elapsed.is_zero() {
        0.0
    } else {
        relay_payload_bytes_received as f64 * 8.0 / relay_elapsed.as_secs_f64() / 1_000_000.0
    };
    let control_summary =
        control_plane_health_summary(&client, &services.control_plane_urls, "daemon").await?;
    let signal_metrics: SignalMetricsResponse = get_json(
        &client,
        format!("{}/v1/metrics", services.signal_url),
        "daemon signal metrics",
    )
    .await?;
    let stun_metrics: StunMetricsResponse = get_json(
        &client,
        format!("{}/v1/metrics", services.stun_http_url),
        "daemon STUN metrics",
    )
    .await?;
    let stun_prometheus = get_text(
        &client,
        format!("{}/metrics", services.stun_http_url),
        "daemon STUN Prometheus metrics",
    )
    .await?;
    let daemon_stun = daemon_stun_report(
        &stun_metrics,
        &stun_prometheus,
        services.stun_addr,
        services.stun_alternate_addr,
    );
    services.ensure_running(DaemonRuntimePhase::FinalMetrics)?;
    let daemon_relay_count = daemon_relay_agent_count(scenario, agent_processes);
    let daemon_route_provider_count = daemon_route_provider_agent_count(scenario, agent_processes);
    let mut total_peer_map_requests = peer_map_requests;
    let mut control_plane_http_requests =
        agent_statuses.len() + peer_map_requests + control_summary.endpoint_count;
    let mut failover_checked = false;
    let mut failover_survivor_endpoints = 0;
    let mut failover_peer_map_edges_min = 0;
    let mut failover_peer_map_edges_max = 0;
    let mut failover_peer_maps_consistent = false;
    let mut failover_metrics_endpoints = 0;
    let mut failover_metrics_consistent = false;
    let mut failover_relay_candidates_min = 0;
    let mut failover_relay_candidates_max = 0;
    let mut failover_path_count_min = 0;
    let mut failover_path_count_max = 0;
    let mut failover_reachable_path_count_min = 0;
    let mut failover_reachable_path_count_max = 0;
    let mut failover_path_status_requests = 0;
    let mut failover_path_status_count_min = 0;
    let mut failover_path_status_count_max = 0;
    let mut failover_path_status_reachable_count_min = 0;
    let mut failover_path_status_reachable_count_max = 0;
    let mut failover_path_status_stale_count_max = 0;
    let mut failover_healthy_nodes_min = 0;
    let mut failover_healthy_nodes_max = 0;
    let mut failover_degraded_nodes_min = 0;
    let mut failover_degraded_nodes_max = 0;
    let mut failover_unhealthy_nodes_min = 0;
    let mut failover_unhealthy_nodes_max = 0;
    let mut failover_agent_status_endpoints = 0;
    let mut failover_agent_candidate_count_min = 0;
    let mut failover_agent_candidate_count_max = 0;
    let mut failover_agent_path_status_endpoints = 0;
    let mut failover_agent_paths_total = 0;
    let mut failover_agent_reachable_paths_total = 0;
    let mut failover_agent_path_count_min = 0;
    let mut failover_agent_path_count_max = 0;
    let mut failover_relay_udp_packets_sent = 0;
    let mut failover_relay_udp_packets_received = 0;
    let mut failover_relay_udp_payload_bytes_sent = 0_u64;
    let mut failover_relay_udp_payload_bytes_received = 0_u64;
    if services.control_plane_urls.len() > 1 {
        services.write_manifest(DaemonRuntimePhase::ControlPlaneFailover)?;
        let (stopped_role, survivor_urls) = services.stop_control_plane_for_failover(0)?;
        failover_survivor_endpoints = survivor_urls.len();
        let mut failover_agent_statuses = Vec::with_capacity(services.agent_urls.len());
        for (index, (url, previous_status)) in
            services.agent_urls.iter().zip(&agent_statuses).enumerate()
        {
            let status: AgentStatusResponse = get_json(
                &client,
                format!("{url}/v1/status"),
                "daemon failover agent status",
            )
            .await
            .with_context(|| {
                format!("daemon agent status probe {index} failed after stopping {stopped_role}")
            })?;
            if status.node_id != previous_status.node_id {
                bail!(
                    "daemon failover agent status endpoint {index} returned node {} instead of {} after stopping {stopped_role}",
                    status.node_id,
                    previous_status.node_id
                );
            }
            failover_agent_statuses.push(status);
        }
        let failover_agent_status_summary = daemon_agent_status_summary(&failover_agent_statuses)?;
        failover_agent_status_endpoints = failover_agent_status_summary.endpoint_count;
        failover_agent_candidate_count_min = failover_agent_status_summary.candidate_count_min;
        failover_agent_candidate_count_max = failover_agent_status_summary.candidate_count_max;
        let failover_agent_path_summary = wait_for_daemon_agent_path_summary(
            &client,
            &services.agent_urls,
            &failover_agent_statuses,
            expected_agent_path_count,
            agent_readiness_timeout,
        )
        .await
        .with_context(|| {
            format!("daemon agent path-state probe failed after stopping {stopped_role}")
        })?;
        failover_agent_path_status_endpoints = failover_agent_path_summary.endpoint_count;
        failover_agent_paths_total = failover_agent_path_summary.path_count_total;
        failover_agent_reachable_paths_total =
            failover_agent_path_summary.reachable_path_count_total;
        failover_agent_path_count_min = failover_agent_path_summary.path_count_min;
        failover_agent_path_count_max = failover_agent_path_summary.path_count_max;
        for (pair_index, admission) in relay_admissions.iter().enumerate() {
            let packet_index = relay_options.packets_per_session;
            let payload = relay_payload(pair_index, packet_index, relay_options.payload_bytes);
            let datagram =
                encode_relay_datagram(&admission.session_id, &admission.session_token, &payload)?;
            left_socket
                .send_to(&datagram, services.relay_udp_addr)
                .await?;
            failover_relay_udp_packets_sent += 1;
            failover_relay_udp_payload_bytes_sent =
                failover_relay_udp_payload_bytes_sent.saturating_add(payload.len() as u64);
            let (len, _) = tokio::time::timeout(
                Duration::from_secs(2),
                right_socket.recv_from(&mut receive_buffer),
            )
            .await
            .with_context(|| {
                format!(
                    "timed out waiting for daemon relay UDP failover payload after stopping {stopped_role}"
                )
            })??;
            if &receive_buffer[..len] != payload.as_slice() {
                bail!(
                    "daemon relay UDP failover payload mismatch for pair {pair_index} after stopping {stopped_role}"
                );
            }
            failover_relay_udp_packets_received += 1;
            failover_relay_udp_payload_bytes_received =
                failover_relay_udp_payload_bytes_received.saturating_add(len as u64);
        }
        let failover_probe = daemon_peer_map_probe(&client, &survivor_urls, &agent_statuses)
            .await
            .with_context(|| {
                format!("daemon control-plane failover probe failed after stopping {stopped_role}")
            })?;
        let failover_peer_map_requests = agent_statuses.len() * survivor_urls.len();
        total_peer_map_requests += failover_peer_map_requests;
        control_plane_http_requests += failover_peer_map_requests;
        failover_checked = true;
        failover_peer_map_edges_min = failover_probe.summary.edge_count_min;
        failover_peer_map_edges_max = failover_probe.summary.edge_count_max;
        failover_peer_maps_consistent = failover_probe.summary.maps_consistent;
        let failover_metrics_context = format!(
            "daemon control-plane failover metrics probe failed after stopping {stopped_role}"
        );
        let failover_control_summary =
            control_plane_health_summary(&client, &survivor_urls, "daemon control-plane failover")
                .await
                .context(failover_metrics_context)?;
        failover_metrics_endpoints = failover_control_summary.endpoint_count;
        failover_metrics_consistent = failover_control_summary.metrics_consistent();
        failover_relay_candidates_min = failover_control_summary.relay_candidate_count_min;
        failover_relay_candidates_max = failover_control_summary.relay_candidate_count_max;
        failover_path_count_min = failover_control_summary.path_count_min;
        failover_path_count_max = failover_control_summary.path_count_max;
        failover_reachable_path_count_min = failover_control_summary.reachable_path_count_min;
        failover_reachable_path_count_max = failover_control_summary.reachable_path_count_max;
        failover_healthy_nodes_min = failover_control_summary.healthy_node_count_min;
        failover_healthy_nodes_max = failover_control_summary.healthy_node_count_max;
        failover_degraded_nodes_min = failover_control_summary.degraded_node_count_min;
        failover_degraded_nodes_max = failover_control_summary.degraded_node_count_max;
        failover_unhealthy_nodes_min = failover_control_summary.unhealthy_node_count_min;
        failover_unhealthy_nodes_max = failover_control_summary.unhealthy_node_count_max;
        control_plane_http_requests += failover_control_summary.endpoint_count;
        let failover_path_status = daemon_control_plane_path_status_summary(
            &client,
            &survivor_urls,
            &agent_statuses,
        )
        .await
        .with_context(|| {
            format!(
                "daemon control-plane failover path status probe failed after stopping {stopped_role}"
            )
        })?;
        failover_path_status_requests = failover_path_status.request_count;
        failover_path_status_count_min = failover_path_status.path_count_min;
        failover_path_status_count_max = failover_path_status.path_count_max;
        failover_path_status_reachable_count_min = failover_path_status.reachable_path_count_min;
        failover_path_status_reachable_count_max = failover_path_status.reachable_path_count_max;
        failover_path_status_stale_count_max = failover_path_status.stale_path_count_max;
        control_plane_http_requests += failover_path_status.request_count;
        services.ensure_running_allowing_roles(
            DaemonRuntimePhase::ControlPlaneFailover,
            &[stopped_role.as_str()],
        )?;
        services.write_manifest(DaemonRuntimePhase::ControlPlaneFailover)?;
    }
    let completed_measurement = DaemonRuntimeManifestMeasurement {
        relay_udp_packets_sent: relay_packets_sent,
        relay_udp_packets_received: relay_packets_received,
        relay_udp_payload_bytes_sent: relay_payload_bytes_sent,
        relay_udp_payload_bytes_received: relay_payload_bytes_received,
        failover_relay_udp_packets_sent,
        failover_relay_udp_packets_received,
        failover_relay_udp_payload_bytes_sent,
        failover_relay_udp_payload_bytes_received,
        relay_dataplane_datagrams_received_reported: status.dataplane.datagrams_received,
        relay_dataplane_datagrams_forwarded_reported: status.dataplane.datagrams_forwarded,
        relay_dataplane_datagrams_dropped_reported: status.dataplane.datagrams_dropped,
        relay_dataplane_invalid_session_credential_drops_reported:
            relay_invalid_session_credential_drops(&status),
        relay_dataplane_invalid_session_credential_drops_prometheus_reported:
            prometheus_invalid_credential_drops,
        relay_forwarded_bytes_reported: forwarded_bytes,
        relay_active_sessions_reported: status.capability.active_sessions as usize,
        control_plane_failover_checked: failover_checked,
        control_plane_failover_survivor_endpoints: failover_survivor_endpoints,
    };
    let completed_manifest_path =
        services.stop_all_for_completed_manifest(completed_measurement)?;

    Ok(LoadReport {
        transport: TransportMode::Daemon,
        scenario: scenario.name,
        node_count: agent_statuses.len(),
        relay_count: daemon_relay_count,
        route_provider_count: daemon_route_provider_count,
        advertised_routes,
        active_pair_count,
        registrations: agent_statuses.len(),
        peer_map_requests: total_peer_map_requests,
        peer_map_edges_seen,
        signal_negotiations: active_pair_count,
        relay_candidates: control_summary.relay_candidate_count_min,
        direct_public_paths: path_counts.direct_public,
        direct_ipv6_paths: path_counts.direct_ipv6,
        direct_nat_paths: path_counts.direct_nat,
        relay_paths: path_counts.relay,
        unreachable_paths: path_counts.unreachable,
        control_plane_http_requests,
        signal_http_requests: peer_records.len() + active_pair_count + 1,
        relay_http_requests: active_pair_count + 2,
        stun_http_requests: 2,
        relay_udp_sessions: status.capability.active_sessions as usize,
        relay_packets_per_session: relay_options.packets_per_session,
        relay_payload_bytes_per_packet: relay_options.payload_bytes,
        relay_udp_packets_sent: relay_packets_sent,
        relay_udp_packets_received: relay_packets_received,
        relay_udp_payload_bytes_sent: relay_payload_bytes_sent,
        relay_udp_payload_bytes_received: relay_payload_bytes_received,
        daemon_failover_relay_udp_packets_sent: failover_relay_udp_packets_sent,
        daemon_failover_relay_udp_packets_received: failover_relay_udp_packets_received,
        daemon_failover_relay_udp_payload_bytes_sent: failover_relay_udp_payload_bytes_sent,
        daemon_failover_relay_udp_payload_bytes_received: failover_relay_udp_payload_bytes_received,
        relay_dataplane_datagrams_received_reported: status.dataplane.datagrams_received,
        relay_dataplane_datagrams_forwarded_reported: status.dataplane.datagrams_forwarded,
        relay_dataplane_datagrams_dropped_reported: status.dataplane.datagrams_dropped,
        relay_dataplane_invalid_session_credential_drops_reported:
            relay_invalid_session_credential_drops(&status),
        relay_dataplane_invalid_session_credential_drops_prometheus_reported:
            prometheus_invalid_credential_drops,
        relay_forwarded_bytes_reported: forwarded_bytes,
        relay_active_sessions_reported: status.capability.active_sessions as usize,
        relay_available_sessions_reported: status.capability.available_capacity() as usize,
        relay_max_sessions_reported: status.capability.max_sessions as usize,
        relay_max_mbps_reported: status.capability.max_mbps,
        relay_enabled_by_policy_reported: status.capability.enabled_by_policy,
        relay_e2e_only_reported: status.capability.e2e_only,
        relay_admission_attempts_reported: status.admission_attempt_count,
        relay_admission_successes_reported: status.admission_success_count,
        relay_admission_failures_reported: status.admission_failure_count,
        relay_admission_failures_by_reason_reported: status.admission_failures_by_reason,
        relay_mbps,
        daemon_processes: services.process_count(),
        daemon_runtime_dir: options
            .keep_runtime_dir
            .then(|| services.runtime_dir.clone()),
        daemon_runtime_manifest: options.keep_runtime_dir.then_some(completed_manifest_path),
        daemon_http_readiness_timeout_seconds: http_readiness_timeout.as_secs(),
        daemon_agent_readiness_timeout_seconds: agent_readiness_timeout.as_secs(),
        daemon_agent_processes: agent_processes,
        daemon_agent_status_endpoints: agent_status_summary.endpoint_count,
        daemon_agent_candidate_count_min: agent_status_summary.candidate_count_min,
        daemon_agent_candidate_count_max: agent_status_summary.candidate_count_max,
        daemon_agent_path_status_endpoints: agent_path_summary.endpoint_count,
        daemon_agent_paths_total: agent_path_summary.path_count_total,
        daemon_agent_reachable_paths_total: agent_path_summary.reachable_path_count_total,
        daemon_agent_path_count_min: agent_path_summary.path_count_min,
        daemon_agent_path_count_max: agent_path_summary.path_count_max,
        daemon_agent_failover_status_endpoints: failover_agent_status_endpoints,
        daemon_agent_failover_candidate_count_min: failover_agent_candidate_count_min,
        daemon_agent_failover_candidate_count_max: failover_agent_candidate_count_max,
        daemon_agent_failover_path_status_endpoints: failover_agent_path_status_endpoints,
        daemon_agent_failover_paths_total: failover_agent_paths_total,
        daemon_agent_failover_reachable_paths_total: failover_agent_reachable_paths_total,
        daemon_agent_failover_path_count_min: failover_agent_path_count_min,
        daemon_agent_failover_path_count_max: failover_agent_path_count_max,
        daemon_control_plane_processes: services.control_plane_urls.len(),
        daemon_control_plane_metrics_endpoints: control_summary.endpoint_count,
        daemon_control_plane_peer_map_endpoints: peer_map_summary.endpoint_count,
        daemon_control_plane_peer_map_edges_min: peer_map_summary.edge_count_min,
        daemon_control_plane_peer_map_edges_max: peer_map_summary.edge_count_max,
        daemon_control_plane_peer_maps_consistent: peer_map_summary.maps_consistent,
        daemon_control_plane_failover_checked: failover_checked,
        daemon_control_plane_failover_survivor_endpoints: failover_survivor_endpoints,
        daemon_control_plane_failover_peer_map_edges_min: failover_peer_map_edges_min,
        daemon_control_plane_failover_peer_map_edges_max: failover_peer_map_edges_max,
        daemon_control_plane_failover_peer_maps_consistent: failover_peer_maps_consistent,
        daemon_control_plane_failover_metrics_endpoints: failover_metrics_endpoints,
        daemon_control_plane_failover_metrics_consistent: failover_metrics_consistent,
        daemon_control_plane_failover_relay_candidates_min: failover_relay_candidates_min,
        daemon_control_plane_failover_relay_candidates_max: failover_relay_candidates_max,
        daemon_control_plane_failover_path_count_min: failover_path_count_min,
        daemon_control_plane_failover_path_count_max: failover_path_count_max,
        daemon_control_plane_failover_reachable_path_count_min: failover_reachable_path_count_min,
        daemon_control_plane_failover_reachable_path_count_max: failover_reachable_path_count_max,
        daemon_control_plane_failover_path_status_requests: failover_path_status_requests,
        daemon_control_plane_failover_path_status_count_min: failover_path_status_count_min,
        daemon_control_plane_failover_path_status_count_max: failover_path_status_count_max,
        daemon_control_plane_failover_path_status_reachable_count_min:
            failover_path_status_reachable_count_min,
        daemon_control_plane_failover_path_status_reachable_count_max:
            failover_path_status_reachable_count_max,
        daemon_control_plane_failover_path_status_stale_count_max:
            failover_path_status_stale_count_max,
        daemon_control_plane_failover_healthy_nodes_min: failover_healthy_nodes_min,
        daemon_control_plane_failover_healthy_nodes_max: failover_healthy_nodes_max,
        daemon_control_plane_failover_degraded_nodes_min: failover_degraded_nodes_min,
        daemon_control_plane_failover_degraded_nodes_max: failover_degraded_nodes_max,
        daemon_control_plane_failover_unhealthy_nodes_min: failover_unhealthy_nodes_min,
        daemon_control_plane_failover_unhealthy_nodes_max: failover_unhealthy_nodes_max,
        daemon_control_plane_relay_candidates_min: control_summary.relay_candidate_count_min,
        daemon_control_plane_relay_candidates_max: control_summary.relay_candidate_count_max,
        daemon_control_plane_path_count_min: control_path_summary.path_count_min,
        daemon_control_plane_path_count_max: control_path_summary.path_count_max,
        daemon_control_plane_reachable_path_count_min: control_path_summary
            .reachable_path_count_min,
        daemon_control_plane_reachable_path_count_max: control_path_summary
            .reachable_path_count_max,
        daemon_control_plane_path_status_requests: control_path_status_summary.request_count,
        daemon_control_plane_path_status_count_min: control_path_status_summary.path_count_min,
        daemon_control_plane_path_status_count_max: control_path_status_summary.path_count_max,
        daemon_control_plane_path_status_reachable_count_min: control_path_status_summary
            .reachable_path_count_min,
        daemon_control_plane_path_status_reachable_count_max: control_path_status_summary
            .reachable_path_count_max,
        daemon_control_plane_path_status_stale_count_max: control_path_status_summary
            .stale_path_count_max,
        daemon_control_plane_healthy_nodes: control_summary.healthy_node_count_min,
        daemon_control_plane_healthy_nodes_min: control_summary.healthy_node_count_min,
        daemon_control_plane_healthy_nodes_max: control_summary.healthy_node_count_max,
        daemon_control_plane_degraded_nodes: control_summary.degraded_node_count_max,
        daemon_control_plane_degraded_nodes_min: control_summary.degraded_node_count_min,
        daemon_control_plane_degraded_nodes_max: control_summary.degraded_node_count_max,
        daemon_control_plane_unhealthy_nodes: control_summary.unhealthy_node_count_max,
        daemon_control_plane_unhealthy_nodes_min: control_summary.unhealthy_node_count_min,
        daemon_control_plane_unhealthy_nodes_max: control_summary.unhealthy_node_count_max,
        daemon_control_plane_metrics_consistent: control_summary.metrics_consistent(),
        daemon_signal_health_reports: signal_metrics.health_report_count,
        daemon_signal_healthy_nodes: signal_metrics.healthy_node_count,
        daemon_signal_degraded_nodes: signal_metrics.degraded_node_count,
        daemon_signal_unhealthy_nodes: signal_metrics.unhealthy_node_count,
        daemon_stun,
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

fn daemon_relay_agent_count(scenario: Scenario, agent_processes: usize) -> usize {
    agent_processes.min(scenario.relay_count)
}

fn daemon_route_provider_agent_count(scenario: Scenario, agent_processes: usize) -> usize {
    agent_processes
        .saturating_sub(scenario.relay_count)
        .min(scenario.route_provider_count)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DaemonAgentStatusSummary {
    endpoint_count: usize,
    candidate_count_min: usize,
    candidate_count_max: usize,
}

fn daemon_agent_status_summary(
    statuses: &[AgentStatusResponse],
) -> anyhow::Result<DaemonAgentStatusSummary> {
    let first = statuses
        .first()
        .context("daemon agent status summary was empty")?;
    let first_candidate_count = daemon_agent_status_candidate_count(first)?;
    let mut summary = DaemonAgentStatusSummary {
        endpoint_count: statuses.len(),
        candidate_count_min: first_candidate_count,
        candidate_count_max: first_candidate_count,
    };

    for status in &statuses[1..] {
        let candidate_count = daemon_agent_status_candidate_count(status)?;
        summary.candidate_count_min = summary.candidate_count_min.min(candidate_count);
        summary.candidate_count_max = summary.candidate_count_max.max(candidate_count);
    }

    Ok(summary)
}

fn daemon_agent_status_candidate_count(status: &AgentStatusResponse) -> anyhow::Result<usize> {
    if status.candidate_count != status.candidates.len() {
        bail!(
            "daemon agent status for {} reported candidate_count={} but returned {} candidates",
            status.node_id,
            status.candidate_count,
            status.candidates.len()
        );
    }
    Ok(status.candidate_count)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DaemonAgentPathSummary {
    endpoint_count: usize,
    path_count_total: usize,
    reachable_path_count_total: usize,
    path_count_min: usize,
    path_count_max: usize,
}

fn expected_daemon_agent_path_count(active_pair_count: usize, node_count: usize) -> usize {
    if node_count < 2 {
        return 0;
    }
    active_pair_count.min(node_count.saturating_mul(node_count.saturating_sub(1)))
}

fn daemon_agent_activity_pairs(
    statuses: &[AgentStatusResponse],
    active_pair_count: usize,
) -> Vec<(usize, NodeId)> {
    let mut seen = BTreeSet::new();
    let mut pairs = Vec::new();
    if statuses.len() < 2 {
        return pairs;
    }
    for pair_index in 0..active_pair_count {
        let (source_index, target_index) = active_pair_indices(pair_index, statuses.len());
        let target = statuses[target_index].node_id.clone();
        if seen.insert((source_index, target.clone())) {
            pairs.push((source_index, target));
        }
    }
    pairs
}

async fn drive_daemon_agent_peer_activity(
    client: &reqwest::Client,
    agent_urls: &[String],
    statuses: &[AgentStatusResponse],
    active_pair_count: usize,
) -> anyhow::Result<usize> {
    if agent_urls.len() != statuses.len() {
        bail!(
            "daemon agent activity probe has {} URLs for {} statuses",
            agent_urls.len(),
            statuses.len()
        );
    }
    let pairs = daemon_agent_activity_pairs(statuses, active_pair_count);
    for (source_index, peer) in &pairs {
        let _: AgentPeerActivityResponse = post_json(
            client,
            format!("{}/v1/peer-activity", agent_urls[*source_index]),
            &AgentPeerActivityRequest {
                peer: peer.clone(),
                pin: false,
            },
            "daemon agent peer activity",
        )
        .await?;
    }
    Ok(pairs.len())
}

async fn wait_for_daemon_agent_path_summary(
    client: &reqwest::Client,
    agent_urls: &[String],
    statuses: &[AgentStatusResponse],
    expected_path_count: usize,
    timeout: Duration,
) -> anyhow::Result<DaemonAgentPathSummary> {
    let started = Instant::now();
    loop {
        let summary = daemon_agent_path_summary(client, agent_urls, statuses).await?;
        if summary.path_count_total >= expected_path_count
            && summary.reachable_path_count_total >= expected_path_count
        {
            return Ok(summary);
        }
        if started.elapsed() >= timeout {
            bail!(
                "daemon agent path validation observed total={}, reachable={}, expected at least {} within {}s",
                summary.path_count_total,
                summary.reachable_path_count_total,
                expected_path_count,
                timeout.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn daemon_agent_path_summary(
    client: &reqwest::Client,
    agent_urls: &[String],
    statuses: &[AgentStatusResponse],
) -> anyhow::Result<DaemonAgentPathSummary> {
    if agent_urls.len() != statuses.len() {
        bail!(
            "daemon agent path probe has {} URLs for {} statuses",
            agent_urls.len(),
            statuses.len()
        );
    }
    let mut summary = DaemonAgentPathSummary {
        endpoint_count: agent_urls.len(),
        path_count_total: 0,
        reachable_path_count_total: 0,
        path_count_min: 0,
        path_count_max: 0,
    };
    for (index, (url, status)) in agent_urls.iter().zip(statuses).enumerate() {
        let response: AgentPathsResponse =
            get_json(client, format!("{url}/v1/paths"), "daemon agent paths").await?;
        for path in &response.paths {
            if path.key.local != status.node_id {
                bail!(
                    "daemon agent path endpoint {index} for {} returned path owned by {}",
                    status.node_id,
                    path.key.local
                );
            }
        }
        let path_count = response.paths.len();
        let reachable_count = response
            .paths
            .iter()
            .filter(|path| path.selected_state != PathState::Unreachable)
            .count();
        summary.path_count_total = summary.path_count_total.saturating_add(path_count);
        summary.reachable_path_count_total = summary
            .reachable_path_count_total
            .saturating_add(reachable_count);
        if index == 0 {
            summary.path_count_min = path_count;
            summary.path_count_max = path_count;
        } else {
            summary.path_count_min = summary.path_count_min.min(path_count);
            summary.path_count_max = summary.path_count_max.max(path_count);
        }
    }
    Ok(summary)
}

fn daemon_advertised_route_count(peer_records: &[NodeRecord]) -> usize {
    peer_records
        .iter()
        .flat_map(|node| {
            node.routes.iter().map(|route| {
                (
                    route.advertised_by.to_string(),
                    route.id.clone(),
                    route.cidr.to_string(),
                )
            })
        })
        .collect::<BTreeSet<_>>()
        .len()
}

fn validate_daemon_control_plane_processes(
    requested_control_plane_processes: usize,
) -> anyhow::Result<usize> {
    if requested_control_plane_processes == 0 {
        bail!("--daemon-control-plane-processes must be greater than zero");
    }
    if requested_control_plane_processes > MAX_DAEMON_CONTROL_PLANE_PROCESSES {
        bail!(
            "--daemon-control-plane-processes ({requested_control_plane_processes}) cannot exceed {MAX_DAEMON_CONTROL_PLANE_PROCESSES}"
        );
    }
    Ok(requested_control_plane_processes)
}

fn daemon_timeout_from_seconds(seconds: u64, flag: &str) -> anyhow::Result<Duration> {
    if seconds == 0 {
        bail!("{flag} must be greater than zero");
    }
    if seconds > MAX_DAEMON_READINESS_TIMEOUT_SECONDS {
        bail!("{flag} must be at most {MAX_DAEMON_READINESS_TIMEOUT_SECONDS} seconds");
    }
    Ok(Duration::from_secs(seconds))
}

fn validate_daemon_timeout(timeout: Duration, flag: &str) -> anyhow::Result<Duration> {
    if timeout.is_zero() {
        bail!("{flag} must be greater than zero");
    }
    if timeout.as_secs() > MAX_DAEMON_READINESS_TIMEOUT_SECONDS {
        bail!("{flag} must be at most {MAX_DAEMON_READINESS_TIMEOUT_SECONDS} seconds");
    }
    Ok(timeout)
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
    control_plane_urls: Vec<String>,
    signal_url: String,
    relay_http_url: String,
    relay_udp_addr: SocketAddr,
    stun_http_url: String,
    stun_addr: SocketAddr,
    stun_alternate_addr: SocketAddr,
    agent_urls: Vec<String>,
    runtime_dir: PathBuf,
    manifest_seed: DaemonRuntimeManifestSeed,
    keep_runtime_dir: bool,
    children: Vec<DaemonChild>,
    agent_state_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DaemonRuntimePhase {
    ReservedEndpoints,
    ControlPlaneStartup,
    ServiceStartup,
    AgentStartup,
    StartupReadiness,
    StartupReady,
    RegistrationProbe,
    PeerMapProbe,
    SignalUpsert,
    SignalNegotiation,
    AgentPathValidation,
    RelayMeasurement,
    FinalMetrics,
    ControlPlaneFailover,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DaemonRuntimeManifest {
    scenario: ScenarioName,
    phase: DaemonRuntimePhase,
    workload: DaemonRuntimeManifestWorkload,
    measurement: Option<DaemonRuntimeManifestMeasurement>,
    runtime_dir: PathBuf,
    iparsd_binary: DaemonBinaryIdentity,
    control_plane_urls: Vec<String>,
    signal_url: String,
    relay_http_url: String,
    stun_http_url: String,
    relay_udp_addr: SocketAddr,
    stun_addr: SocketAddr,
    stun_alternate_addr: SocketAddr,
    agent_urls: Vec<String>,
    keep_runtime_dir: bool,
    started_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
    generated_at: chrono::DateTime<Utc>,
    children: Vec<DaemonRuntimeManifestChild>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct DaemonRuntimeManifestWorkload {
    scenario_node_count: usize,
    scenario_relay_node_count: usize,
    scenario_route_provider_count: usize,
    scenario_active_pair_count: usize,
    daemon_control_plane_processes: usize,
    daemon_agent_processes: usize,
    daemon_http_readiness_timeout_seconds: u64,
    daemon_agent_readiness_timeout_seconds: u64,
    relay_packets_per_session: usize,
    relay_payload_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct DaemonRuntimeManifestMeasurement {
    relay_udp_packets_sent: usize,
    relay_udp_packets_received: usize,
    relay_udp_payload_bytes_sent: u64,
    relay_udp_payload_bytes_received: u64,
    failover_relay_udp_packets_sent: usize,
    failover_relay_udp_packets_received: usize,
    failover_relay_udp_payload_bytes_sent: u64,
    failover_relay_udp_payload_bytes_received: u64,
    relay_dataplane_datagrams_received_reported: u64,
    relay_dataplane_datagrams_forwarded_reported: u64,
    relay_dataplane_datagrams_dropped_reported: u64,
    relay_dataplane_invalid_session_credential_drops_reported: u64,
    relay_dataplane_invalid_session_credential_drops_prometheus_reported: u64,
    relay_forwarded_bytes_reported: u64,
    relay_active_sessions_reported: usize,
    control_plane_failover_checked: bool,
    control_plane_failover_survivor_endpoints: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DaemonBinaryIdentity {
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DaemonRuntimeManifestChild {
    role: String,
    pid: Option<u32>,
    started_at: chrono::DateTime<Utc>,
    exited_at: Option<chrono::DateTime<Utc>>,
    runtime_ms: Option<u64>,
    redacted_argv: Vec<String>,
    redacted_argv_sha256: String,
    log_path: Option<PathBuf>,
    log_bytes: Option<u64>,
    log_tail_sha256: Option<String>,
    state: DaemonRuntimeManifestChildState,
    exit_status: Option<String>,
    exit_code: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DaemonRuntimeManifestChildState {
    Running,
    Exited,
}

#[derive(Debug, Clone)]
struct DaemonRuntimeManifestSeed {
    scenario: ScenarioName,
    workload: DaemonRuntimeManifestWorkload,
    runtime_dir: PathBuf,
    iparsd_binary: DaemonBinaryIdentity,
    control_plane_urls: Vec<String>,
    signal_url: String,
    relay_http_url: String,
    stun_http_url: String,
    relay_udp_addr: SocketAddr,
    stun_addr: SocketAddr,
    stun_alternate_addr: SocketAddr,
    keep_runtime_dir: bool,
    started_at: chrono::DateTime<Utc>,
}

impl DaemonRuntimeManifestSeed {
    fn write(
        &self,
        phase: DaemonRuntimePhase,
        agent_urls: &[String],
        children: &[DaemonChild],
    ) -> anyhow::Result<PathBuf> {
        self.write_with_measurement(phase, agent_urls, children, None)
    }

    fn write_with_measurement(
        &self,
        phase: DaemonRuntimePhase,
        agent_urls: &[String],
        children: &[DaemonChild],
        measurement: Option<DaemonRuntimeManifestMeasurement>,
    ) -> anyhow::Result<PathBuf> {
        let updated_at = Utc::now();
        write_daemon_runtime_manifest(
            &self.runtime_dir,
            DaemonRuntimeManifest {
                scenario: self.scenario,
                phase,
                workload: self.workload,
                measurement,
                runtime_dir: self.runtime_dir.clone(),
                iparsd_binary: self.iparsd_binary.clone(),
                control_plane_urls: self.control_plane_urls.clone(),
                signal_url: self.signal_url.clone(),
                relay_http_url: self.relay_http_url.clone(),
                stun_http_url: self.stun_http_url.clone(),
                relay_udp_addr: self.relay_udp_addr,
                stun_addr: self.stun_addr,
                stun_alternate_addr: self.stun_alternate_addr,
                agent_urls: agent_urls.to_vec(),
                keep_runtime_dir: self.keep_runtime_dir,
                started_at: self.started_at,
                updated_at,
                generated_at: updated_at,
                children: children
                    .iter()
                    .map(DaemonRuntimeManifestChild::from_child)
                    .collect(),
            },
        )
    }
}

impl DaemonRuntimeManifestChild {
    fn from_child(child: &DaemonChild) -> Self {
        let (state, exited_at, runtime_ms, exit_status, exit_code) =
            if let Some(exit) = &child.last_exit {
                (
                    DaemonRuntimeManifestChildState::Exited,
                    Some(exit.exited_at),
                    Some(daemon_child_runtime_ms(child.started_at, exit.exited_at)),
                    Some(exit.status.clone()),
                    exit.code,
                )
            } else {
                (
                    DaemonRuntimeManifestChildState::Running,
                    None,
                    None,
                    None,
                    None,
                )
            };
        let diagnostics = child.log_path.as_deref().and_then(daemon_log_diagnostics);
        Self {
            role: child.role.clone(),
            pid: Some(child.child.id()),
            started_at: child.started_at,
            exited_at,
            runtime_ms,
            redacted_argv: child.redacted_argv.clone(),
            redacted_argv_sha256: child.redacted_argv_sha256.clone(),
            log_path: child.log_path.clone(),
            log_bytes: diagnostics.as_ref().map(|diagnostics| diagnostics.bytes),
            log_tail_sha256: diagnostics.map(|diagnostics| diagnostics.tail_sha256),
            state,
            exit_status,
            exit_code,
        }
    }
}

impl DaemonProcessGroup {
    async fn start(
        iparsd_bin: &Path,
        scenario: Scenario,
        cluster_id: ClusterId,
        issuer: &IdentityKeyPair,
        key_id: &KeyId,
        options: DaemonLoadOptions,
    ) -> anyhow::Result<Self> {
        let iparsd_binary = daemon_binary_identity(iparsd_bin)?;
        let runtime_dir = daemon_runtime_dir()?;
        std::fs::create_dir_all(&runtime_dir)?;
        secure_daemon_runtime_dir(&runtime_dir)?;
        let mut startup = DaemonStartupGuard::new(runtime_dir.clone(), options.keep_runtime_dir);
        let control_addrs = reserve_tcp_addrs(options.control_plane_processes).await?;
        let signal_addr = reserve_tcp_addr().await?;
        let relay_http_addr = reserve_tcp_addr().await?;
        let stun_http_addr = reserve_tcp_addr().await?;
        let relay_udp_addr = reserve_udp_addr().await?;
        let stun_addr = reserve_udp_addr().await?;
        let stun_alternate_addr = reserve_udp_addr().await?;
        let control_plane_urls = control_addrs
            .iter()
            .map(|addr| format!("http://{addr}"))
            .collect::<Vec<_>>();
        control_plane_urls
            .first()
            .context("at least one daemon control-plane URL is required")?;
        let signal_url = format!("http://{signal_addr}");
        let relay_http_url = format!("http://{relay_http_addr}");
        let stun_http_url = format!("http://{stun_http_addr}");
        let mut agent_urls = Vec::with_capacity(options.agent_processes);
        let manifest_seed = DaemonRuntimeManifestSeed {
            scenario: scenario.name,
            workload: DaemonRuntimeManifestWorkload {
                scenario_node_count: scenario.node_count,
                scenario_relay_node_count: scenario.relay_count,
                scenario_route_provider_count: scenario.route_provider_count,
                scenario_active_pair_count: scenario.active_pair_count,
                daemon_control_plane_processes: options.control_plane_processes,
                daemon_agent_processes: options.agent_processes,
                daemon_http_readiness_timeout_seconds: options.http_readiness_timeout.as_secs(),
                daemon_agent_readiness_timeout_seconds: options.agent_readiness_timeout.as_secs(),
                relay_packets_per_session: options.relay_options.packets_per_session,
                relay_payload_bytes: options.relay_options.payload_bytes,
            },
            runtime_dir: runtime_dir.clone(),
            iparsd_binary,
            control_plane_urls: control_plane_urls.clone(),
            signal_url: signal_url.clone(),
            relay_http_url: relay_http_url.clone(),
            stun_http_url: stun_http_url.clone(),
            relay_udp_addr,
            stun_addr,
            stun_alternate_addr,
            keep_runtime_dir: options.keep_runtime_dir,
            started_at: Utc::now(),
        };
        manifest_seed.write(
            DaemonRuntimePhase::ReservedEndpoints,
            &agent_urls,
            &startup.children,
        )?;
        let control_plane_database_url =
            daemon_sqlite_database_url(&runtime_dir.join(DAEMON_CONTROL_PLANE_SQLITE_FILE));
        let client = reqwest::Client::new();
        for (index, control_addr) in control_addrs.iter().enumerate() {
            let role = format!("control-plane-{index}");
            startup.children.push(spawn_iparsd(
                &manifest_seed.iparsd_binary.path,
                &[
                    "control-plane".to_string(),
                    "--listen".to_string(),
                    control_addr.to_string(),
                    "--cluster-id".to_string(),
                    cluster_id.to_string(),
                    "--database-url".to_string(),
                    control_plane_database_url.clone(),
                    "--issuer-node-id".to_string(),
                    issuer.node_id().to_string(),
                    "--issuer-key-id".to_string(),
                    key_id.to_string(),
                    "--issuer-public-key".to_string(),
                    issuer.public_key_b64(),
                ],
                &role,
                &runtime_dir,
            )?);
            manifest_seed.write(
                DaemonRuntimePhase::ControlPlaneStartup,
                &agent_urls,
                &startup.children,
            )?;
            wait_for_http_ok_or_manifest_failure(
                &client,
                format!("{}/healthz", control_plane_urls[index]),
                &role,
                &mut startup.children,
                DaemonHttpReadinessManifestContext {
                    manifest_seed: &manifest_seed,
                    phase: DaemonRuntimePhase::ControlPlaneStartup,
                    agent_urls: &agent_urls,
                    timeout: options.http_readiness_timeout,
                },
            )
            .await?;
        }
        startup.children.push(spawn_iparsd(
            &manifest_seed.iparsd_binary.path,
            &[
                "signal".to_string(),
                "--listen".to_string(),
                signal_addr.to_string(),
            ],
            "signal",
            &runtime_dir,
        )?);
        manifest_seed.write(
            DaemonRuntimePhase::ServiceStartup,
            &agent_urls,
            &startup.children,
        )?;
        startup.children.push(spawn_iparsd(
            &manifest_seed.iparsd_binary.path,
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
        manifest_seed.write(
            DaemonRuntimePhase::ServiceStartup,
            &agent_urls,
            &startup.children,
        )?;
        let stun_args = daemon_stun_args(stun_addr, stun_alternate_addr, stun_http_addr);
        startup.children.push(spawn_iparsd(
            &manifest_seed.iparsd_binary.path,
            &stun_args,
            "stun",
            &runtime_dir,
        )?);
        manifest_seed.write(
            DaemonRuntimePhase::ServiceStartup,
            &agent_urls,
            &startup.children,
        )?;

        wait_for_http_ok_or_manifest_failure(
            &client,
            format!("{signal_url}/healthz"),
            "signal",
            &mut startup.children,
            DaemonHttpReadinessManifestContext {
                manifest_seed: &manifest_seed,
                phase: DaemonRuntimePhase::ServiceStartup,
                agent_urls: &agent_urls,
                timeout: options.http_readiness_timeout,
            },
        )
        .await?;
        wait_for_http_ok_or_manifest_failure(
            &client,
            format!("{relay_http_url}/healthz"),
            "relay",
            &mut startup.children,
            DaemonHttpReadinessManifestContext {
                manifest_seed: &manifest_seed,
                phase: DaemonRuntimePhase::ServiceStartup,
                agent_urls: &agent_urls,
                timeout: options.http_readiness_timeout,
            },
        )
        .await?;
        wait_for_http_ok_or_manifest_failure(
            &client,
            format!("{stun_http_url}/healthz"),
            "stun",
            &mut startup.children,
            DaemonHttpReadinessManifestContext {
                manifest_seed: &manifest_seed,
                phase: DaemonRuntimePhase::ServiceStartup,
                agent_urls: &agent_urls,
                timeout: options.http_readiness_timeout,
            },
        )
        .await?;

        for index in 0..options.agent_processes {
            let agent_addr = reserve_tcp_addr().await?;
            let agent_url = format!("http://{agent_addr}");
            let state_path = daemon_agent_state_path(&runtime_dir, index);
            startup.record_agent_state_path(state_path.clone());
            let token = issuer.sign_join_token(join_claims_with_control_plane_urls(
                &cluster_id,
                &issuer.node_id(),
                key_id,
                index,
                scenario,
                &control_plane_urls,
            )?)?;
            let token_path = write_daemon_join_token(&runtime_dir, index, &token)?;
            startup.record_join_token_path(token_path.clone());
            let mut agent_args = vec![
                "agent".to_string(),
                "--listen".to_string(),
                agent_addr.to_string(),
                "--state-path".to_string(),
                state_path.display().to_string(),
                "--join-token-path".to_string(),
                token_path.display().to_string(),
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
            ];
            if index < scenario.relay_count {
                agent_args.extend([
                    "--relay-public-endpoint".to_string(),
                    relay_udp_addr.to_string(),
                    "--relay-admission-url".to_string(),
                    relay_http_url.clone(),
                    "--relay-status-url".to_string(),
                    relay_http_url.clone(),
                    "--relay-max-sessions".to_string(),
                    "10000".to_string(),
                    "--relay-max-mbps".to_string(),
                    "10000".to_string(),
                ]);
            }
            let route_provider_routes = advertised_routes(index, scenario)?;
            if !route_provider_routes.is_empty() {
                agent_args.extend([
                    "--apply-docker-routes".to_string(),
                    "--docker-container-namespace".to_string(),
                    format!("ipars-load-agent-{index:04}"),
                ]);
                for route in route_provider_routes {
                    agent_args.extend([
                        "--docker-container-cidr".to_string(),
                        route.cidr.to_string(),
                    ]);
                }
            }
            startup.children.push(spawn_iparsd(
                &manifest_seed.iparsd_binary.path,
                &agent_args,
                "agent",
                &runtime_dir,
            )?);
            agent_urls.push(agent_url);
            manifest_seed.write(
                DaemonRuntimePhase::AgentStartup,
                &agent_urls,
                &startup.children,
            )?;
            wait_for_http_ok_or_manifest_failure(
                &client,
                format!(
                    "{}/healthz",
                    agent_urls.last().context("agent URL was not recorded")?
                ),
                "agent",
                &mut startup.children,
                DaemonHttpReadinessManifestContext {
                    manifest_seed: &manifest_seed,
                    phase: DaemonRuntimePhase::AgentStartup,
                    agent_urls: &agent_urls,
                    timeout: options.http_readiness_timeout,
                },
            )
            .await?;
        }
        manifest_seed.write(
            DaemonRuntimePhase::StartupReadiness,
            &agent_urls,
            &startup.children,
        )?;
        wait_for_daemon_agents_ready_or_manifest_failure(
            &client,
            &control_plane_urls,
            &signal_url,
            &agent_urls,
            &mut startup.children,
            &manifest_seed,
            options.agent_readiness_timeout,
        )
        .await?;
        startup.remove_join_token_files()?;
        manifest_seed.write(
            DaemonRuntimePhase::StartupReady,
            &agent_urls,
            &startup.children,
        )?;

        let (children, agent_state_paths) = startup.finish();
        Ok(Self {
            control_plane_urls,
            signal_url,
            relay_http_url,
            relay_udp_addr,
            stun_http_url,
            stun_addr,
            stun_alternate_addr,
            agent_urls,
            runtime_dir,
            manifest_seed,
            keep_runtime_dir: options.keep_runtime_dir,
            children,
            agent_state_paths,
        })
    }

    fn process_count(&self) -> usize {
        self.children.len()
    }

    fn ensure_running(&mut self, phase: DaemonRuntimePhase) -> anyhow::Result<()> {
        match ensure_daemon_children_running(&mut self.children) {
            Ok(()) => Ok(()),
            Err(error) => {
                if let Err(manifest_error) = self.write_manifest(phase) {
                    bail!(
                        "{error}; additionally failed to update daemon runtime manifest after liveness failure: {manifest_error}"
                    );
                }
                Err(error)
            }
        }
    }

    fn ensure_running_allowing_roles(
        &mut self,
        phase: DaemonRuntimePhase,
        allowed_exited_roles: &[&str],
    ) -> anyhow::Result<()> {
        match ensure_daemon_children_running_allowing_roles(
            &mut self.children,
            allowed_exited_roles,
        ) {
            Ok(()) => Ok(()),
            Err(error) => {
                if let Err(manifest_error) = self.write_manifest(phase) {
                    bail!(
                        "{error}; additionally failed to update daemon runtime manifest after liveness failure: {manifest_error}"
                    );
                }
                Err(error)
            }
        }
    }

    fn stop_control_plane_for_failover(
        &mut self,
        control_plane_index: usize,
    ) -> anyhow::Result<(String, Vec<String>)> {
        let stopped_url = self
            .control_plane_urls
            .get(control_plane_index)
            .with_context(|| {
                format!("daemon control-plane index {control_plane_index} is not available")
            })?
            .clone();
        let stopped_role = format!("control-plane-{control_plane_index}");
        let child = self
            .children
            .iter_mut()
            .find(|child| child.role == stopped_role)
            .with_context(|| {
                format!("daemon control-plane failover child {stopped_role} was not found")
            })?;
        if child.last_exit.is_some() {
            bail!("daemon control-plane failover child {stopped_role} already exited");
        }
        child
            .child
            .kill()
            .with_context(|| format!("failed to stop iparsd {stopped_role} for failover probe"))?;
        let status = child.child.wait().with_context(|| {
            format!("failed to wait for iparsd {stopped_role} during failover probe")
        })?;
        child.last_exit = Some(daemon_child_exit(status));
        let survivor_urls = self
            .control_plane_urls
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != control_plane_index)
            .map(|(_, url)| url.clone())
            .collect::<Vec<_>>();
        if survivor_urls.is_empty() {
            bail!("daemon control-plane failover stopped {stopped_url} without survivors");
        }
        Ok((stopped_role, survivor_urls))
    }

    fn write_manifest(&self, phase: DaemonRuntimePhase) -> anyhow::Result<PathBuf> {
        self.manifest_seed
            .write(phase, &self.agent_urls, &self.children)
    }

    fn stop_all_for_completed_manifest(
        &mut self,
        measurement: DaemonRuntimeManifestMeasurement,
    ) -> anyhow::Result<PathBuf> {
        stop_daemon_children(&mut self.children)?;
        remove_daemon_agent_state_files(&self.runtime_dir, &mut self.agent_state_paths)?;
        secure_daemon_retained_runtime_file_modes(&self.runtime_dir)?;
        self.manifest_seed.write_with_measurement(
            DaemonRuntimePhase::Completed,
            &self.agent_urls,
            &self.children,
            Some(measurement),
        )
    }
}

impl Drop for DaemonProcessGroup {
    fn drop(&mut self) {
        kill_daemon_children(&mut self.children);
        let _ = remove_daemon_agent_state_files(&self.runtime_dir, &mut self.agent_state_paths);
        let _ = secure_daemon_retained_runtime_file_modes(&self.runtime_dir);
        if !self.keep_runtime_dir {
            let _ = std::fs::remove_dir_all(&self.runtime_dir);
        }
    }
}

struct DaemonStartupGuard {
    runtime_dir: PathBuf,
    children: Vec<DaemonChild>,
    join_token_paths: Vec<PathBuf>,
    agent_state_paths: Vec<PathBuf>,
    active: bool,
    keep_runtime_dir: bool,
}

impl DaemonStartupGuard {
    fn new(runtime_dir: PathBuf, keep_runtime_dir: bool) -> Self {
        Self {
            runtime_dir,
            children: Vec::new(),
            join_token_paths: Vec::new(),
            agent_state_paths: Vec::new(),
            active: true,
            keep_runtime_dir,
        }
    }

    fn record_join_token_path(&mut self, path: PathBuf) {
        self.join_token_paths.push(path);
    }

    fn record_agent_state_path(&mut self, path: PathBuf) {
        self.agent_state_paths.push(path);
    }

    fn remove_join_token_files(&mut self) -> anyhow::Result<()> {
        remove_daemon_join_token_files(&self.runtime_dir, &mut self.join_token_paths)
    }

    fn finish(mut self) -> (Vec<DaemonChild>, Vec<PathBuf>) {
        self.active = false;
        self.join_token_paths.clear();
        (
            std::mem::take(&mut self.children),
            std::mem::take(&mut self.agent_state_paths),
        )
    }
}

impl Drop for DaemonStartupGuard {
    fn drop(&mut self) {
        if self.active {
            kill_daemon_children(&mut self.children);
            let _ = remove_daemon_join_token_files(&self.runtime_dir, &mut self.join_token_paths);
            let _ = remove_daemon_agent_state_files(&self.runtime_dir, &mut self.agent_state_paths);
            let _ = secure_daemon_retained_runtime_file_modes(&self.runtime_dir);
            if !self.keep_runtime_dir {
                let _ = std::fs::remove_dir_all(&self.runtime_dir);
            }
        }
    }
}

fn daemon_stun_args(
    stun_addr: SocketAddr,
    stun_alternate_addr: SocketAddr,
    stun_http_addr: SocketAddr,
) -> Vec<String> {
    vec![
        "stun".to_string(),
        "--listen".to_string(),
        stun_addr.to_string(),
        "--alternate-listen".to_string(),
        stun_alternate_addr.to_string(),
        "--http-listen".to_string(),
        stun_http_addr.to_string(),
    ]
}

struct DaemonChild {
    role: String,
    child: Child,
    started_at: chrono::DateTime<Utc>,
    redacted_argv: Vec<String>,
    redacted_argv_sha256: String,
    log_path: Option<PathBuf>,
    last_exit: Option<DaemonChildExit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DaemonChildExit {
    status: String,
    code: Option<i32>,
    exited_at: chrono::DateTime<Utc>,
}

fn spawn_iparsd(
    iparsd_bin: &Path,
    args: &[String],
    role: &str,
    runtime_dir: &Path,
) -> anyhow::Result<DaemonChild> {
    let log_path = daemon_child_log_path(runtime_dir, role);
    let redacted_argv = redacted_daemon_argv(iparsd_bin, args);
    let redacted_argv_sha256 = daemon_argv_sha256(&redacted_argv);
    let mut log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .private_on_unix()
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
    let mut command = Command::new(iparsd_bin);
    configure_daemon_child_process(&mut command);
    let child = command
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
        started_at: Utc::now(),
        redacted_argv,
        redacted_argv_sha256,
        log_path: Some(log_path),
        last_exit: None,
    })
}

fn configure_daemon_child_process(command: &mut Command) {
    command
        .env_clear()
        .env("PATH", SANITIZED_DAEMON_CHILD_PATH)
        .env("LANG", SANITIZED_DAEMON_CHILD_LOCALE)
        .env("LC_ALL", SANITIZED_DAEMON_CHILD_LOCALE);
}

fn kill_daemon_children(children: &mut [DaemonChild]) {
    for daemon_child in children {
        if daemon_child.last_exit.is_some() {
            continue;
        }
        let _ = daemon_child.child.kill();
        if let Ok(status) = daemon_child.child.wait() {
            daemon_child.last_exit = Some(daemon_child_exit(status));
        }
    }
}

fn stop_daemon_children(children: &mut [DaemonChild]) -> anyhow::Result<()> {
    for daemon_child in children {
        if daemon_child.last_exit.is_some() {
            continue;
        }
        if let Some(status) = daemon_child.child.try_wait().with_context(|| {
            format!(
                "failed to inspect iparsd {} process status before completed manifest",
                daemon_child.role
            )
        })? {
            daemon_child.last_exit = Some(daemon_child_exit(status));
            let log_tail = daemon_child
                .log_tail()
                .map(|tail| format!("\n{tail}"))
                .unwrap_or_default();
            bail!(
                "iparsd {} process exited before completed manifest shutdown: {}{}",
                daemon_child.role,
                status,
                log_tail
            );
        }
        daemon_child.child.kill().with_context(|| {
            format!(
                "failed to stop iparsd {} after daemon load scenario",
                daemon_child.role
            )
        })?;
        let status = daemon_child.child.wait().with_context(|| {
            format!(
                "failed to wait for iparsd {} after daemon load scenario",
                daemon_child.role
            )
        })?;
        daemon_child.last_exit = Some(daemon_child_exit(status));
    }
    Ok(())
}

fn ensure_daemon_children_running(children: &mut [DaemonChild]) -> anyhow::Result<()> {
    ensure_daemon_children_running_allowing_roles(children, &[])
}

fn ensure_daemon_children_running_allowing_roles(
    children: &mut [DaemonChild],
    allowed_exited_roles: &[&str],
) -> anyhow::Result<()> {
    for daemon_child in children {
        if daemon_child.last_exit.is_some()
            && allowed_exited_roles.contains(&daemon_child.role.as_str())
        {
            continue;
        }
        if let Some(exit) = &daemon_child.last_exit {
            let log_tail = daemon_child
                .log_tail()
                .map(|tail| format!("\n{tail}"))
                .unwrap_or_default();
            bail!(
                "iparsd {} process exited before daemon load scenario completed: {}{}",
                daemon_child.role,
                exit.status,
                log_tail
            );
        }
        if let Some(status) = daemon_child.child.try_wait().with_context(|| {
            format!(
                "failed to inspect iparsd {} process status",
                daemon_child.role
            )
        })? {
            let exit = daemon_child_exit(status);
            daemon_child.last_exit = Some(exit.clone());
            let log_tail = daemon_child
                .log_tail()
                .map(|tail| format!("\n{tail}"))
                .unwrap_or_default();
            bail!(
                "iparsd {} process exited before daemon load scenario completed: {}{}",
                daemon_child.role,
                exit.status,
                log_tail
            );
        }
    }
    Ok(())
}

fn daemon_child_exit(status: ExitStatus) -> DaemonChildExit {
    DaemonChildExit {
        status: status.to_string(),
        code: status.code(),
        exited_at: Utc::now(),
    }
}

fn daemon_child_runtime_ms(
    started_at: chrono::DateTime<Utc>,
    exited_at: chrono::DateTime<Utc>,
) -> u64 {
    exited_at
        .signed_duration_since(started_at)
        .num_milliseconds()
        .max(0) as u64
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
    let bytes = daemon_log_tail_bytes(path)
        .with_context(|| format!("failed to read daemon log tail {}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let mut lines = text
        .lines()
        .rev()
        .take(DAEMON_LOG_TAIL_LINES)
        .collect::<Vec<_>>();
    lines.reverse();
    Ok(lines.join("\n"))
}

fn daemon_log_tail_bytes(path: &Path) -> anyhow::Result<Vec<u8>> {
    let path_metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect daemon log {}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        bail!("daemon log {} is not a regular file", path.display());
    }
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open daemon log {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect daemon log {}", path.display()))?;
    if !metadata.is_file() {
        bail!("daemon log {} is not a regular file", path.display());
    }
    let start = metadata.len().saturating_sub(DAEMON_LOG_TAIL_BYTES as u64);
    file.seek(SeekFrom::Start(start))
        .with_context(|| format!("failed to seek daemon log {}", path.display()))?;
    let mut bytes = Vec::new();
    let mut reader = file.take(DAEMON_LOG_TAIL_BYTES as u64);
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read daemon log tail {}", path.display()))?;
    Ok(bytes)
}

struct DaemonLogDiagnostics {
    bytes: u64,
    tail_sha256: String,
}

fn daemon_log_diagnostics(path: &Path) -> Option<DaemonLogDiagnostics> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return None;
    }
    let bytes = daemon_log_tail_bytes(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let tail_sha256 = format!("{:x}", hasher.finalize());
    Some(DaemonLogDiagnostics {
        bytes: metadata.len(),
        tail_sha256,
    })
}

fn daemon_binary_identity(iparsd_bin: &Path) -> anyhow::Result<DaemonBinaryIdentity> {
    let path = resolve_daemon_binary_path(iparsd_bin)?;
    let (bytes, sha256) = daemon_file_sha256(&path)?;
    if bytes == 0 {
        bail!("iparsd binary {} is empty", path.display());
    }
    Ok(DaemonBinaryIdentity {
        path,
        bytes,
        sha256,
    })
}

fn resolve_daemon_binary_path(iparsd_bin: &Path) -> anyhow::Result<PathBuf> {
    if iparsd_bin.as_os_str().is_empty() {
        bail!("iparsd binary path must not be empty");
    }
    if iparsd_bin.components().count() > 1 || iparsd_bin.is_absolute() {
        return canonical_daemon_binary_path(iparsd_bin);
    }
    let binary_name = iparsd_bin
        .to_str()
        .filter(|value| !value.is_empty())
        .context("iparsd binary name must be valid UTF-8")?;
    let path_env = std::env::var_os("PATH").context("PATH is not set; cannot resolve iparsd")?;
    let mut rejected_candidates = Vec::new();
    for directory in std::env::split_paths(&path_env) {
        if directory.as_os_str().is_empty() {
            continue;
        }
        let candidate = directory.join(binary_name);
        if !candidate.exists() {
            continue;
        }
        match canonical_daemon_binary_path(&candidate) {
            Ok(path) => return Ok(path),
            Err(error) => {
                rejected_candidates.push(format!("{} ({error})", candidate.display()));
            }
        }
    }
    if rejected_candidates.is_empty() {
        bail!("iparsd binary {binary_name} was not found on PATH");
    }
    bail!(
        "iparsd binary {binary_name} was found on PATH but not as an executable regular file: {}",
        rejected_candidates.join(", ")
    )
}

fn canonical_daemon_binary_path(path: &Path) -> anyhow::Result<PathBuf> {
    std::fs::symlink_metadata(path)
        .with_context(|| format!("iparsd binary {} is not accessible", path.display()))?;
    let canonical = path
        .canonicalize()
        .with_context(|| format!("iparsd binary {} cannot be canonicalized", path.display()))?;
    let canonical_metadata = std::fs::symlink_metadata(&canonical).with_context(|| {
        format!(
            "canonical iparsd binary {} is not accessible",
            canonical.display()
        )
    })?;
    if canonical_metadata.file_type().is_symlink() || !canonical_metadata.is_file() {
        bail!(
            "canonical iparsd binary {} must resolve to a regular file",
            canonical.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if canonical_metadata.permissions().mode() & 0o111 == 0 {
            bail!(
                "canonical iparsd binary {} is not executable",
                canonical.display()
            );
        }
    }
    Ok(canonical)
}

fn validate_daemon_manifest_iparsd_binary(identity: &DaemonBinaryIdentity) -> anyhow::Result<()> {
    if identity.path.as_os_str().is_empty() {
        bail!("daemon load scenario retained manifest iparsd binary path is empty");
    }
    if !identity.path.is_absolute() {
        bail!(
            "daemon load scenario retained manifest iparsd binary path {} is not absolute",
            identity.path.display()
        );
    }
    let canonical = canonical_daemon_binary_path(&identity.path).with_context(|| {
        format!(
            "daemon load scenario retained manifest iparsd binary {} failed validation",
            identity.path.display()
        )
    })?;
    if canonical != identity.path {
        bail!(
            "daemon load scenario retained manifest iparsd binary path {} is not canonical {}",
            identity.path.display(),
            canonical.display()
        );
    }
    let (actual_bytes, actual_sha256) = daemon_file_sha256(&identity.path)?;
    if identity.bytes == 0 {
        bail!("daemon load scenario retained manifest iparsd binary recorded zero bytes");
    }
    if identity.bytes != actual_bytes || identity.sha256 != actual_sha256 {
        bail!(
            "daemon load scenario retained manifest iparsd binary digest mismatch: bytes={}/{}, sha256={}/{}",
            identity.bytes,
            actual_bytes,
            identity.sha256,
            actual_sha256
        );
    }
    Ok(())
}

fn validate_daemon_manifest_child_command(
    child: &DaemonRuntimeManifestChild,
    iparsd_binary: &Path,
) -> anyhow::Result<()> {
    if child.redacted_argv.is_empty() {
        bail!(
            "daemon load scenario retained manifest child {} is missing redacted argv",
            child.role
        );
    }
    if child.redacted_argv.len() > MAX_DAEMON_REDACTED_ARG_COUNT {
        bail!(
            "daemon load scenario retained manifest child {} recorded {} argv entries, max {}",
            child.role,
            child.redacted_argv.len(),
            MAX_DAEMON_REDACTED_ARG_COUNT
        );
    }
    let expected_binary = iparsd_binary.display().to_string();
    if child.redacted_argv.first() != Some(&expected_binary) {
        bail!(
            "daemon load scenario retained manifest child {} argv binary {:?} does not match manifest iparsd binary {}",
            child.role,
            child.redacted_argv.first(),
            expected_binary
        );
    }
    let expected_subcommand = expected_daemon_subcommand_for_child_role(&child.role)?;
    if child.redacted_argv.get(1).map(String::as_str) != Some(expected_subcommand) {
        bail!(
            "daemon load scenario retained manifest child {} argv subcommand {:?} does not match expected {}",
            child.role,
            child.redacted_argv.get(1),
            expected_subcommand
        );
    }
    for argument in &child.redacted_argv {
        validate_daemon_redacted_arg_text(&child.role, argument)?;
    }
    validate_redacted_daemon_argv_secrets(&child.role, &child.redacted_argv)?;
    let expected_sha256 = daemon_argv_sha256(&child.redacted_argv);
    if child.redacted_argv_sha256 != expected_sha256 {
        bail!(
            "daemon load scenario retained manifest child {} redacted argv hash mismatch: {}/{}",
            child.role,
            child.redacted_argv_sha256,
            expected_sha256
        );
    }
    Ok(())
}

fn validate_daemon_manifest_child_lifecycle(
    child: &DaemonRuntimeManifestChild,
    manifest_started_at: chrono::DateTime<Utc>,
    manifest_updated_at: chrono::DateTime<Utc>,
) -> anyhow::Result<()> {
    if child.started_at < manifest_started_at {
        bail!(
            "daemon load scenario retained manifest child {} started_at {} is before run started_at {}",
            child.role,
            child.started_at,
            manifest_started_at
        );
    }
    if child.started_at > manifest_updated_at {
        bail!(
            "daemon load scenario retained manifest child {} started_at {} is after manifest updated_at {}",
            child.role,
            child.started_at,
            manifest_updated_at
        );
    }
    match child.state {
        DaemonRuntimeManifestChildState::Running => {
            if child.exited_at.is_some() || child.runtime_ms.is_some() {
                bail!(
                    "daemon load scenario retained manifest running child {} recorded exit timing",
                    child.role
                );
            }
        }
        DaemonRuntimeManifestChildState::Exited => {
            let exited_at = child.exited_at.with_context(|| {
                format!(
                    "daemon load scenario retained manifest exited child {} is missing exited_at",
                    child.role
                )
            })?;
            if exited_at < child.started_at {
                bail!(
                    "daemon load scenario retained manifest child {} exited_at {} is before started_at {}",
                    child.role,
                    exited_at,
                    child.started_at
                );
            }
            if exited_at > manifest_updated_at {
                bail!(
                    "daemon load scenario retained manifest child {} exited_at {} is after manifest updated_at {}",
                    child.role,
                    exited_at,
                    manifest_updated_at
                );
            }
            let expected_runtime_ms = daemon_child_runtime_ms(child.started_at, exited_at);
            if child.runtime_ms != Some(expected_runtime_ms) {
                bail!(
                    "daemon load scenario retained manifest child {} runtime_ms {:?} does not match timestamps {}",
                    child.role,
                    child.runtime_ms,
                    expected_runtime_ms
                );
            }
        }
    }
    Ok(())
}

fn expected_daemon_subcommand_for_child_role(role: &str) -> anyhow::Result<&'static str> {
    if role.starts_with("control-plane-") {
        return Ok("control-plane");
    }
    match role {
        "signal" => Ok("signal"),
        "relay" => Ok("relay"),
        "stun" => Ok("stun"),
        "agent" => Ok("agent"),
        _ => bail!(
            "daemon load scenario retained manifest child role {role} has no expected iparsd subcommand"
        ),
    }
}

fn validate_daemon_redacted_arg_text(child_role: &str, argument: &str) -> anyhow::Result<()> {
    if argument.is_empty() {
        bail!(
            "daemon load scenario retained manifest child {child_role} contains an empty argv entry"
        );
    }
    if argument.len() > MAX_DAEMON_REDACTED_ARG_BYTES {
        bail!(
            "daemon load scenario retained manifest child {child_role} argv entry is {} bytes, max {}",
            argument.len(),
            MAX_DAEMON_REDACTED_ARG_BYTES
        );
    }
    if argument
        .chars()
        .any(|ch| ch == '\0' || (ch.is_control() && ch != '\t'))
    {
        bail!(
            "daemon load scenario retained manifest child {child_role} argv entry contains control characters"
        );
    }
    Ok(())
}

fn validate_redacted_daemon_argv_secrets(child_role: &str, argv: &[String]) -> anyhow::Result<()> {
    let mut redact_next_for: Option<&str> = None;
    for argument in argv.iter().skip(1) {
        if let Some(flag) = redact_next_for.take() {
            if argument != DAEMON_REDACTED_ARG {
                bail!(
                    "daemon load scenario retained manifest child {child_role} argv flag {flag} did not redact its value"
                );
            }
            continue;
        }
        if let Some((flag, value)) = argument.split_once('=') {
            if is_sensitive_daemon_arg_name(flag) && value != DAEMON_REDACTED_ARG {
                bail!(
                    "daemon load scenario retained manifest child {child_role} argv flag {flag} did not redact its inline value"
                );
            }
            continue;
        }
        if is_sensitive_daemon_arg_name(argument) {
            redact_next_for = Some(argument);
        }
    }
    if let Some(flag) = redact_next_for {
        bail!(
            "daemon load scenario retained manifest child {child_role} argv flag {flag} is missing its redacted value"
        );
    }
    Ok(())
}

fn redacted_daemon_argv(iparsd_bin: &Path, args: &[String]) -> Vec<String> {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(iparsd_bin.display().to_string());
    let mut redact_next = false;
    for argument in args {
        if redact_next {
            argv.push(DAEMON_REDACTED_ARG.to_string());
            redact_next = false;
            continue;
        }
        if let Some((flag, _value)) = argument.split_once('=') {
            if is_sensitive_daemon_arg_name(flag) {
                argv.push(format!("{flag}={DAEMON_REDACTED_ARG}"));
            } else {
                argv.push(argument.clone());
            }
            continue;
        }
        if is_sensitive_daemon_arg_name(argument) {
            argv.push(argument.clone());
            redact_next = true;
        } else {
            argv.push(argument.clone());
        }
    }
    argv
}

fn is_sensitive_daemon_arg_name(argument: &str) -> bool {
    let name = argument
        .trim_start_matches('-')
        .split_once('=')
        .map_or(argument.trim_start_matches('-'), |(name, _value)| name)
        .to_ascii_lowercase();
    name.contains("token")
        || name.contains("private-key")
        || name.contains("bearer")
        || name.contains("password")
        || name.contains("secret")
        || name == "database-url"
        || name.ends_with("-database-url")
}

fn daemon_argv_sha256(argv: &[String]) -> String {
    let mut hasher = Sha256::new();
    for argument in argv {
        hasher.update((argument.len() as u64).to_le_bytes());
        hasher.update(argument.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn daemon_file_sha256(path: &Path) -> anyhow::Result<(u64, String)> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open {} for SHA-256", path.display()))?;
    let mut buffer = [0u8; 64 * 1024];
    let mut bytes = 0u64;
    let mut hasher = Sha256::new();
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {} for SHA-256", path.display()))?;
        if read == 0 {
            break;
        }
        bytes += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok((bytes, format!("{:x}", hasher.finalize())))
}

fn sanitized_daemon_child_role(role: &str) -> String {
    role.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn validate_daemon_child_log_file_name(
    child_role: &str,
    log_file_name: &str,
) -> anyhow::Result<usize> {
    let sanitized_role = sanitized_daemon_child_role(child_role);
    let expected_suffix = format!("-{sanitized_role}.log");
    let Some(serial_prefix) = log_file_name.strip_suffix(&expected_suffix) else {
        bail!(
            "daemon load scenario retained manifest child {child_role} log file name {log_file_name} does not match child role"
        );
    };
    if serial_prefix.len() < 4 || !serial_prefix.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!(
            "daemon load scenario retained manifest child {child_role} log file name {log_file_name} has invalid serial prefix"
        );
    }
    serial_prefix.parse::<usize>().with_context(|| {
        format!(
            "daemon load scenario retained manifest child {child_role} log file name {log_file_name} has invalid serial prefix"
        )
    })
}

fn daemon_child_log_path(runtime_dir: &Path, role: &str) -> PathBuf {
    let serial = DAEMON_LOG_COUNTER.fetch_add(1, Ordering::Relaxed);
    let sanitized_role = sanitized_daemon_child_role(role);
    runtime_dir.join(format!("{serial:04}-{sanitized_role}.log"))
}

fn daemon_runtime_manifest_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join(DAEMON_RUNTIME_MANIFEST_FILE)
}

fn daemon_runtime_manifest_temp_path(runtime_dir: &Path) -> PathBuf {
    let serial = DAEMON_MANIFEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    runtime_dir.join(format!(
        ".{DAEMON_RUNTIME_MANIFEST_FILE}.{}.{serial}.tmp",
        std::process::id()
    ))
}

fn is_daemon_runtime_manifest_temp_name(name: &str) -> bool {
    name.contains(DAEMON_RUNTIME_MANIFEST_FILE) && name.ends_with(".tmp")
}

fn write_daemon_runtime_manifest(
    runtime_dir: &Path,
    manifest: DaemonRuntimeManifest,
) -> anyhow::Result<PathBuf> {
    let manifest_path = daemon_runtime_manifest_path(runtime_dir);
    let manifest_tmp_path = daemon_runtime_manifest_temp_path(runtime_dir);
    let manifest_json = serde_json::to_vec_pretty(&manifest)
        .context("failed to serialize daemon runtime manifest")?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .private_on_unix()
        .open(&manifest_tmp_path)
        .with_context(|| {
            format!(
                "failed to open temporary daemon runtime manifest {}",
                manifest_tmp_path.display()
            )
        })?;
    file.write_all(&manifest_json).with_context(|| {
        format!(
            "failed to write temporary daemon runtime manifest {}",
            manifest_tmp_path.display()
        )
    })?;
    file.write_all(b"\n").with_context(|| {
        format!(
            "failed to finalize temporary daemon runtime manifest {}",
            manifest_tmp_path.display()
        )
    })?;
    file.sync_all().with_context(|| {
        format!(
            "failed to sync temporary daemon runtime manifest {}",
            manifest_tmp_path.display()
        )
    })?;
    drop(file);
    if let Err(error) = std::fs::rename(&manifest_tmp_path, &manifest_path) {
        let _ = std::fs::remove_file(&manifest_tmp_path);
        bail!(
            "failed to atomically replace daemon runtime manifest {} with {}: {error}",
            manifest_path.display(),
            manifest_tmp_path.display()
        );
    }
    sync_daemon_runtime_dir(runtime_dir)?;
    Ok(manifest_path)
}

fn sync_daemon_runtime_dir(runtime_dir: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(runtime_dir)
            .with_context(|| {
                format!(
                    "failed to open daemon runtime dir {}",
                    runtime_dir.display()
                )
            })?
            .sync_all()
            .with_context(|| {
                format!(
                    "failed to sync daemon runtime dir {}",
                    runtime_dir.display()
                )
            })?;
    }
    #[cfg(not(unix))]
    {
        let _ = runtime_dir;
    }
    Ok(())
}

trait PrivateOpenOptionsExt {
    fn private_on_unix(&mut self) -> &mut Self;
}

impl PrivateOpenOptionsExt for std::fs::OpenOptions {
    fn private_on_unix(&mut self) -> &mut Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            self.mode(0o600);
        }
        self
    }
}

fn write_daemon_join_token<Token: Serialize>(
    runtime_dir: &Path,
    agent_index: usize,
    token: &Token,
) -> anyhow::Result<PathBuf> {
    let token_path = daemon_join_token_path(runtime_dir, agent_index);
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
    validate_daemon_join_token_file(runtime_dir, &token_path)?;
    Ok(token_path)
}

fn daemon_join_token_path(runtime_dir: &Path, agent_index: usize) -> PathBuf {
    runtime_dir.join(format!(
        "agent-{agent_index:04}{DAEMON_JOIN_TOKEN_FILE_SUFFIX}"
    ))
}

fn daemon_agent_state_path(runtime_dir: &Path, agent_index: usize) -> PathBuf {
    runtime_dir.join(format!(
        "agent-{agent_index:04}{DAEMON_AGENT_STATE_FILE_SUFFIX}"
    ))
}

fn remove_daemon_join_token_files(
    runtime_dir: &Path,
    token_paths: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    remove_daemon_runtime_files(
        runtime_dir,
        token_paths,
        "join token",
        DAEMON_JOIN_TOKEN_FILE_SUFFIX,
        "after agent startup",
    )
}

fn remove_daemon_agent_state_files(
    runtime_dir: &Path,
    state_paths: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    remove_daemon_runtime_files(
        runtime_dir,
        state_paths,
        "agent state",
        DAEMON_AGENT_STATE_FILE_SUFFIX,
        "after child shutdown",
    )
}

fn remove_daemon_runtime_files(
    runtime_dir: &Path,
    paths: &mut Vec<PathBuf>,
    label: &str,
    expected_suffix: &str,
    context: &str,
) -> anyhow::Result<()> {
    let canonical_runtime_dir =
        canonical_daemon_runtime_dir_for_cleanup(runtime_dir, label, context)?;
    let mut pending = std::mem::take(paths).into_iter();
    while let Some(path) = pending.next() {
        match daemon_runtime_cleanup_path_exists(
            &canonical_runtime_dir,
            &path,
            label,
            expected_suffix,
            context,
        ) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(error) => {
                paths.push(path);
                paths.extend(pending);
                return Err(error);
            }
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                let path_display = path.display().to_string();
                paths.push(path);
                paths.extend(pending);
                bail!(
                    "failed to remove daemon {label} {} {context}: {error}",
                    path_display
                );
            }
        }
    }
    Ok(())
}

fn canonical_daemon_runtime_dir_for_cleanup(
    runtime_dir: &Path,
    label: &str,
    context: &str,
) -> anyhow::Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(runtime_dir).with_context(|| {
        format!(
            "failed to inspect daemon {label} runtime directory {} {context}",
            runtime_dir.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "daemon {label} runtime directory {} must be a real directory {context}",
            runtime_dir.display()
        );
    }
    runtime_dir.canonicalize().with_context(|| {
        format!(
            "daemon {label} runtime directory {} cannot be canonicalized {context}",
            runtime_dir.display()
        )
    })
}

fn daemon_runtime_cleanup_path_exists(
    canonical_runtime_dir: &Path,
    path: &Path,
    label: &str,
    expected_suffix: &str,
    context: &str,
) -> anyhow::Result<bool> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        bail!(
            "daemon {label} cleanup path {} must have a UTF-8 file name {context}",
            path.display()
        );
    };
    if !file_name.ends_with(expected_suffix) {
        bail!(
            "daemon {label} cleanup path {} has unexpected file name; expected suffix {expected_suffix} {context}",
            path.display()
        );
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            bail!(
                "failed to inspect daemon {label} cleanup path {} {context}: {error}",
                path.display()
            );
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "daemon {label} cleanup path {} must be a regular file {context}",
            path.display()
        );
    }
    let canonical_path = path.canonicalize().with_context(|| {
        format!(
            "daemon {label} cleanup path {} cannot be canonicalized {context}",
            path.display()
        )
    })?;
    if !canonical_path.starts_with(canonical_runtime_dir) {
        bail!(
            "daemon {label} cleanup path {} is outside runtime directory {} {context}",
            canonical_path.display(),
            canonical_runtime_dir.display()
        );
    }
    Ok(true)
}

fn validate_daemon_join_token_file(runtime_dir: &Path, token_path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(token_path).with_context(|| {
        format!(
            "daemon join token {} is not accessible after creation",
            token_path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "daemon join token {} must be a regular file",
            token_path.display()
        );
    }
    let canonical_runtime_dir = runtime_dir.canonicalize().with_context(|| {
        format!(
            "daemon join token runtime directory {} cannot be canonicalized",
            runtime_dir.display()
        )
    })?;
    let canonical_token_path = token_path.canonicalize().with_context(|| {
        format!(
            "daemon join token {} cannot be canonicalized",
            token_path.display()
        )
    })?;
    if !canonical_token_path.starts_with(&canonical_runtime_dir) {
        bail!(
            "daemon join token {} is outside runtime directory {}",
            canonical_token_path.display(),
            canonical_runtime_dir.display()
        );
    }
    if metadata.len() == 0 {
        bail!("daemon join token {} is empty", token_path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            bail!(
                "daemon join token {} permissions are {mode:o}; expected 600",
                token_path.display()
            );
        }
    }
    Ok(())
}

fn daemon_runtime_dir() -> anyhow::Result<PathBuf> {
    let unique = format!(
        "ipars-load-daemon-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    Ok(std::env::temp_dir().join(unique))
}

fn secure_daemon_runtime_dir(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to secure daemon runtime dir {}", path.display()))?;
    }
    Ok(())
}

fn secure_daemon_retained_runtime_file_modes(runtime_dir: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        for entry in std::fs::read_dir(runtime_dir).with_context(|| {
            format!(
                "failed to scan daemon runtime dir {} for retained file hardening",
                runtime_dir.display()
            )
        })? {
            let entry = entry.with_context(|| {
                format!(
                    "failed to inspect daemon runtime dir {} while hardening retained files",
                    runtime_dir.display()
                )
            })?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).with_context(|| {
                format!(
                    "failed to inspect retained daemon runtime entry {}",
                    path.display()
                )
            })?;
            if metadata.file_type().is_symlink() {
                bail!(
                    "retained daemon runtime entry {} must not be a symlink",
                    path.display()
                );
            }
            if !metadata.is_file() {
                bail!(
                    "retained daemon runtime entry {} must be a regular file",
                    path.display()
                );
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).with_context(
                || {
                    format!(
                        "failed to secure retained daemon runtime entry {}",
                        path.display()
                    )
                },
            )?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = runtime_dir;
    }
    Ok(())
}

async fn reserve_tcp_addr() -> anyhow::Result<SocketAddr> {
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    Ok(listener.local_addr()?)
}

async fn reserve_tcp_addrs(count: usize) -> anyhow::Result<Vec<SocketAddr>> {
    let mut listeners = Vec::with_capacity(count);
    let mut addrs = Vec::with_capacity(count);
    for _ in 0..count {
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await?;
        addrs.push(listener.local_addr()?);
        listeners.push(listener);
    }
    Ok(addrs)
}

async fn reserve_udp_addr() -> anyhow::Result<SocketAddr> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    Ok(socket.local_addr()?)
}

fn daemon_sqlite_database_url(path: &Path) -> String {
    format!("sqlite://{}?mode=rwc", path.display())
}

async fn wait_for_http_ok(
    client: &reqwest::Client,
    url: String,
    context: &str,
    children: &mut [DaemonChild],
    timeout: Duration,
) -> anyhow::Result<()> {
    let mut last_error = None;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
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
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        tokio::time::sleep((deadline - now).min(Duration::from_millis(50))).await;
    }
    let error = last_error.unwrap_or_else(|| anyhow::anyhow!("{context} readiness timed out"));
    bail!(
        "{context} readiness failed: {error}\n{}",
        daemon_children_log_summary(children)
    )
}

struct DaemonHttpReadinessManifestContext<'a> {
    manifest_seed: &'a DaemonRuntimeManifestSeed,
    phase: DaemonRuntimePhase,
    agent_urls: &'a [String],
    timeout: Duration,
}

async fn wait_for_http_ok_or_manifest_failure(
    client: &reqwest::Client,
    url: String,
    context: &str,
    children: &mut [DaemonChild],
    manifest_context: DaemonHttpReadinessManifestContext<'_>,
) -> anyhow::Result<()> {
    match wait_for_http_ok(client, url, context, children, manifest_context.timeout).await {
        Ok(()) => Ok(()),
        Err(error) => {
            if let Err(manifest_error) = write_daemon_manifest_after_startup_failure(
                manifest_context.manifest_seed,
                manifest_context.phase,
                manifest_context.agent_urls,
                children,
            ) {
                bail!(
                    "{error}; additionally failed to update daemon runtime manifest after {context} failure: {manifest_error}"
                );
            }
            Err(error)
        }
    }
}

async fn wait_for_daemon_agents_ready(
    client: &reqwest::Client,
    control_plane_urls: &[String],
    signal_url: &str,
    agent_urls: &[String],
    children: &mut [DaemonChild],
    timeout: Duration,
) -> anyhow::Result<()> {
    let mut last_error = None;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        ensure_daemon_children_running(children)?;
        match daemon_agent_statuses(client, agent_urls).await {
            Ok(statuses) => match check_daemon_agent_control_and_signal_readiness(
                client,
                control_plane_urls,
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
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        tokio::time::sleep((deadline - now).min(Duration::from_millis(100))).await;
    }
    let error = last_error.unwrap_or_else(|| anyhow::anyhow!("daemon agent readiness timed out"));
    bail!(
        "daemon agent readiness failed: {error}\n{}",
        daemon_children_log_summary(children)
    )
}

async fn wait_for_daemon_agents_ready_or_manifest_failure(
    client: &reqwest::Client,
    control_plane_urls: &[String],
    signal_url: &str,
    agent_urls: &[String],
    children: &mut [DaemonChild],
    manifest_seed: &DaemonRuntimeManifestSeed,
    timeout: Duration,
) -> anyhow::Result<()> {
    match wait_for_daemon_agents_ready(
        client,
        control_plane_urls,
        signal_url,
        agent_urls,
        children,
        timeout,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(error) => {
            if let Err(manifest_error) = write_daemon_manifest_after_startup_failure(
                manifest_seed,
                DaemonRuntimePhase::StartupReadiness,
                agent_urls,
                children,
            ) {
                bail!(
                    "{error}; additionally failed to update daemon runtime manifest after daemon readiness failure: {manifest_error}"
                );
            }
            Err(error)
        }
    }
}

fn write_daemon_manifest_after_startup_failure(
    manifest_seed: &DaemonRuntimeManifestSeed,
    phase: DaemonRuntimePhase,
    agent_urls: &[String],
    children: &[DaemonChild],
) -> anyhow::Result<PathBuf> {
    manifest_seed.write(phase, agent_urls, children)
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

#[derive(Debug, Clone, Copy)]
struct ControlPlaneHealthSummary {
    endpoint_count: usize,
    relay_candidate_count_min: usize,
    relay_candidate_count_max: usize,
    path_count_min: usize,
    path_count_max: usize,
    reachable_path_count_min: usize,
    reachable_path_count_max: usize,
    healthy_node_count_min: usize,
    healthy_node_count_max: usize,
    degraded_node_count_min: usize,
    degraded_node_count_max: usize,
    unhealthy_node_count_min: usize,
    unhealthy_node_count_max: usize,
}

impl ControlPlaneHealthSummary {
    fn from_metrics(metrics: &[ControlPlaneMetricsResponse]) -> anyhow::Result<Self> {
        let first = metrics
            .first()
            .context("daemon control-plane metrics summary was empty")?;
        let mut summary = Self {
            endpoint_count: metrics.len(),
            relay_candidate_count_min: first.relay_candidate_count,
            relay_candidate_count_max: first.relay_candidate_count,
            path_count_min: first.path_count,
            path_count_max: first.path_count,
            reachable_path_count_min: control_plane_reachable_path_count(first),
            reachable_path_count_max: control_plane_reachable_path_count(first),
            healthy_node_count_min: first.healthy_node_count,
            healthy_node_count_max: first.healthy_node_count,
            degraded_node_count_min: first.degraded_node_count,
            degraded_node_count_max: first.degraded_node_count,
            unhealthy_node_count_min: first.unhealthy_node_count,
            unhealthy_node_count_max: first.unhealthy_node_count,
        };

        for metrics in &metrics[1..] {
            summary.relay_candidate_count_min = summary
                .relay_candidate_count_min
                .min(metrics.relay_candidate_count);
            summary.relay_candidate_count_max = summary
                .relay_candidate_count_max
                .max(metrics.relay_candidate_count);
            summary.path_count_min = summary.path_count_min.min(metrics.path_count);
            summary.path_count_max = summary.path_count_max.max(metrics.path_count);
            let reachable_path_count = control_plane_reachable_path_count(metrics);
            summary.reachable_path_count_min =
                summary.reachable_path_count_min.min(reachable_path_count);
            summary.reachable_path_count_max =
                summary.reachable_path_count_max.max(reachable_path_count);
            summary.healthy_node_count_min = summary
                .healthy_node_count_min
                .min(metrics.healthy_node_count);
            summary.healthy_node_count_max = summary
                .healthy_node_count_max
                .max(metrics.healthy_node_count);
            summary.degraded_node_count_min = summary
                .degraded_node_count_min
                .min(metrics.degraded_node_count);
            summary.degraded_node_count_max = summary
                .degraded_node_count_max
                .max(metrics.degraded_node_count);
            summary.unhealthy_node_count_min = summary
                .unhealthy_node_count_min
                .min(metrics.unhealthy_node_count);
            summary.unhealthy_node_count_max = summary
                .unhealthy_node_count_max
                .max(metrics.unhealthy_node_count);
        }

        Ok(summary)
    }

    fn metrics_consistent(&self) -> bool {
        self.relay_candidate_count_min == self.relay_candidate_count_max
            && self.path_count_min == self.path_count_max
            && self.reachable_path_count_min == self.reachable_path_count_max
            && self.healthy_node_count_min == self.healthy_node_count_max
            && self.degraded_node_count_min == self.degraded_node_count_max
            && self.unhealthy_node_count_min == self.unhealthy_node_count_max
    }
}

fn control_plane_reachable_path_count(metrics: &ControlPlaneMetricsResponse) -> usize {
    metrics
        .path_state_counts
        .iter()
        .filter(|count| count.state != PathState::Unreachable)
        .map(|count| count.count)
        .sum()
}

async fn control_plane_health_summary(
    client: &reqwest::Client,
    control_plane_urls: &[String],
    context: &str,
) -> anyhow::Result<ControlPlaneHealthSummary> {
    if control_plane_urls.is_empty() {
        bail!("at least one daemon control-plane URL is required");
    }

    let mut metrics_samples = Vec::with_capacity(control_plane_urls.len());
    for control_plane_url in control_plane_urls {
        let request_context = format!("{context} control-plane metrics");
        let metrics: ControlPlaneMetricsResponse = get_json(
            client,
            format!("{control_plane_url}/v1/metrics"),
            &request_context,
        )
        .await?;
        metrics_samples.push(metrics);
    }

    ControlPlaneHealthSummary::from_metrics(&metrics_samples)
}

async fn wait_for_daemon_control_plane_path_summary(
    client: &reqwest::Client,
    control_plane_urls: &[String],
    expected_path_count: usize,
    timeout: Duration,
) -> anyhow::Result<ControlPlaneHealthSummary> {
    let started = Instant::now();
    loop {
        let summary =
            control_plane_health_summary(client, control_plane_urls, "daemon path-state").await?;
        if summary.path_count_min >= expected_path_count
            && summary.reachable_path_count_min >= expected_path_count
        {
            return Ok(summary);
        }
        if started.elapsed() >= timeout {
            bail!(
                "daemon control-plane path-state validation observed path min/max={}/{}, reachable min/max={}/{}, expected at least {} within {}s",
                summary.path_count_min,
                summary.path_count_max,
                summary.reachable_path_count_min,
                summary.reachable_path_count_max,
                expected_path_count,
                timeout.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DaemonControlPlanePathStatusSummary {
    request_count: usize,
    path_count_min: usize,
    path_count_max: usize,
    reachable_path_count_min: usize,
    reachable_path_count_max: usize,
    stale_path_count_max: usize,
}

async fn wait_for_daemon_control_plane_path_status_summary(
    client: &reqwest::Client,
    control_plane_urls: &[String],
    statuses: &[AgentStatusResponse],
    expected_path_count: usize,
    timeout: Duration,
) -> anyhow::Result<DaemonControlPlanePathStatusSummary> {
    let started = Instant::now();
    loop {
        let summary =
            daemon_control_plane_path_status_summary(client, control_plane_urls, statuses).await?;
        if summary.path_count_min >= expected_path_count
            && summary.reachable_path_count_min >= expected_path_count
            && summary.stale_path_count_max == 0
        {
            return Ok(summary);
        }
        if started.elapsed() >= timeout {
            bail!(
                "daemon control-plane path status validation observed path min/max={}/{}, reachable min/max={}/{}, stale max={}, expected at least {} fresh reachable paths within {}s",
                summary.path_count_min,
                summary.path_count_max,
                summary.reachable_path_count_min,
                summary.reachable_path_count_max,
                summary.stale_path_count_max,
                expected_path_count,
                timeout.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn daemon_control_plane_path_status_summary(
    client: &reqwest::Client,
    control_plane_urls: &[String],
    statuses: &[AgentStatusResponse],
) -> anyhow::Result<DaemonControlPlanePathStatusSummary> {
    if control_plane_urls.is_empty() {
        bail!("at least one daemon control-plane URL is required");
    }
    let first = control_plane_path_status_endpoint_summary(
        client,
        control_plane_urls
            .first()
            .context("at least one daemon control-plane URL is required")?,
        statuses,
    )
    .await?;
    let mut summary = DaemonControlPlanePathStatusSummary {
        request_count: first.request_count,
        path_count_min: first.path_count,
        path_count_max: first.path_count,
        reachable_path_count_min: first.reachable_path_count,
        reachable_path_count_max: first.reachable_path_count,
        stale_path_count_max: first.stale_path_count,
    };
    for control_plane_url in &control_plane_urls[1..] {
        let endpoint =
            control_plane_path_status_endpoint_summary(client, control_plane_url, statuses).await?;
        summary.request_count = summary.request_count.saturating_add(endpoint.request_count);
        summary.path_count_min = summary.path_count_min.min(endpoint.path_count);
        summary.path_count_max = summary.path_count_max.max(endpoint.path_count);
        summary.reachable_path_count_min = summary
            .reachable_path_count_min
            .min(endpoint.reachable_path_count);
        summary.reachable_path_count_max = summary
            .reachable_path_count_max
            .max(endpoint.reachable_path_count);
        summary.stale_path_count_max = summary.stale_path_count_max.max(endpoint.stale_path_count);
    }
    Ok(summary)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DaemonControlPlanePathStatusEndpointSummary {
    request_count: usize,
    path_count: usize,
    reachable_path_count: usize,
    stale_path_count: usize,
}

async fn control_plane_path_status_endpoint_summary(
    client: &reqwest::Client,
    control_plane_url: &str,
    statuses: &[AgentStatusResponse],
) -> anyhow::Result<DaemonControlPlanePathStatusEndpointSummary> {
    let mut summary = DaemonControlPlanePathStatusEndpointSummary {
        request_count: 0,
        path_count: 0,
        reachable_path_count: 0,
        stale_path_count: 0,
    };
    for (index, status) in statuses.iter().enumerate() {
        let response: ControlPlanePathsResponse = get_json(
            client,
            format!("{control_plane_url}/v1/paths/{}", status.node_id),
            "daemon control-plane path status",
        )
        .await?;
        if response.node_id != status.node_id {
            bail!(
                "daemon control-plane path status endpoint {control_plane_url} request {index} returned node {} instead of {}",
                response.node_id,
                status.node_id
            );
        }
        for path in &response.paths {
            if path.key.local != status.node_id && path.key.remote != status.node_id {
                bail!(
                    "daemon control-plane path status endpoint {control_plane_url} for {} returned unrelated path {} -> {}",
                    status.node_id,
                    path.key.local,
                    path.key.remote
                );
            }
        }
        summary.request_count += 1;
        summary.path_count = summary.path_count.saturating_add(response.paths.len());
        summary.reachable_path_count = summary.reachable_path_count.saturating_add(
            response
                .paths
                .iter()
                .filter(|path| path.selected_state != PathState::Unreachable)
                .count(),
        );
        summary.stale_path_count = summary
            .stale_path_count
            .saturating_add(response.stale_path_count);
    }
    Ok(summary)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DaemonPeerMapEndpointSummary {
    edge_count: usize,
    edges: BTreeMap<(String, String), usize>,
}

impl DaemonPeerMapEndpointSummary {
    fn record_edge(&mut self, source_node_id: impl ToString, peer_node_id: impl ToString) {
        self.edge_count += 1;
        *self
            .edges
            .entry((source_node_id.to_string(), peer_node_id.to_string()))
            .or_insert(0) += 1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DaemonPeerMapSummary {
    endpoint_count: usize,
    edge_count_min: usize,
    edge_count_max: usize,
    maps_consistent: bool,
}

impl DaemonPeerMapSummary {
    fn from_endpoint_summaries(
        endpoint_summaries: &[DaemonPeerMapEndpointSummary],
    ) -> anyhow::Result<Self> {
        let first = endpoint_summaries
            .first()
            .context("daemon control-plane peer-map summary was empty")?;
        let mut summary = Self {
            endpoint_count: endpoint_summaries.len(),
            edge_count_min: first.edge_count,
            edge_count_max: first.edge_count,
            maps_consistent: true,
        };

        for endpoint in &endpoint_summaries[1..] {
            summary.edge_count_min = summary.edge_count_min.min(endpoint.edge_count);
            summary.edge_count_max = summary.edge_count_max.max(endpoint.edge_count);
            if endpoint != first {
                summary.maps_consistent = false;
            }
        }

        Ok(summary)
    }
}

#[derive(Debug)]
struct DaemonPeerMapProbe {
    canonical_peer_records: Vec<NodeRecord>,
    canonical_edge_count: usize,
    summary: DaemonPeerMapSummary,
}

async fn daemon_peer_map_probe(
    client: &reqwest::Client,
    control_plane_urls: &[String],
    agent_statuses: &[AgentStatusResponse],
) -> anyhow::Result<DaemonPeerMapProbe> {
    if control_plane_urls.is_empty() {
        bail!("at least one daemon control-plane URL is required");
    }

    let mut endpoint_summaries = Vec::with_capacity(control_plane_urls.len());
    let mut canonical_peer_records = Vec::new();
    let mut canonical_edge_count = 0;
    for (endpoint_index, control_plane_url) in control_plane_urls.iter().enumerate() {
        let mut endpoint_summary = DaemonPeerMapEndpointSummary::default();
        for status in agent_statuses {
            let request_context =
                format!("daemon control-plane peer map endpoint {endpoint_index}");
            let peer_map: PeerMap = get_json(
                client,
                format!("{control_plane_url}/v1/peers/{}", status.node_id),
                &request_context,
            )
            .await?;
            for peer in &peer_map.peers {
                endpoint_summary.record_edge(&status.node_id, &peer.node_id);
            }
            if endpoint_index == 0 {
                canonical_edge_count += peer_map.peers.len();
                canonical_peer_records.extend(peer_map.peers);
            }
        }
        endpoint_summaries.push(endpoint_summary);
    }

    Ok(DaemonPeerMapProbe {
        canonical_peer_records,
        canonical_edge_count,
        summary: DaemonPeerMapSummary::from_endpoint_summaries(&endpoint_summaries)?,
    })
}

async fn check_daemon_agent_control_and_signal_readiness(
    client: &reqwest::Client,
    control_plane_urls: &[String],
    signal_url: &str,
    statuses: &[AgentStatusResponse],
) -> anyhow::Result<()> {
    let expected_agent_count = statuses.len();
    if expected_agent_count > 0 {
        let control_summary =
            control_plane_health_summary(client, control_plane_urls, "daemon readiness").await?;
        if control_summary.healthy_node_count_min < expected_agent_count {
            bail!(
                "daemon control-plane endpoints report at least {} healthy nodes; expected at least {}",
                control_summary.healthy_node_count_min,
                expected_agent_count
            );
        }
        if control_summary.degraded_node_count_max > 0
            || control_summary.unhealthy_node_count_max > 0
        {
            bail!(
                "daemon control-plane endpoints report degraded={} unhealthy={} nodes during readiness",
                control_summary.degraded_node_count_max,
                control_summary.unhealthy_node_count_max
            );
        }
    }

    for control_plane_url in control_plane_urls {
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
                    "daemon control-plane peer map at {control_plane_url} for {} has {} peers; expected at least {}",
                    status.node_id,
                    peer_map.peers.len(),
                    expected_peer_count
                );
            }
        }
    }

    if expected_agent_count > 0 {
        let signal_metrics: SignalMetricsResponse = get_json(
            client,
            format!("{signal_url}/v1/metrics"),
            "daemon signal readiness metrics",
        )
        .await?;
        if signal_metrics.health_report_count < expected_agent_count {
            bail!(
                "daemon signal reports {} health records; expected at least {}",
                signal_metrics.health_report_count,
                expected_agent_count
            );
        }
        if signal_metrics.healthy_node_count < expected_agent_count {
            bail!(
                "daemon signal reports {} healthy nodes; expected at least {}",
                signal_metrics.healthy_node_count,
                expected_agent_count
            );
        }
        if signal_metrics.degraded_node_count > 0 || signal_metrics.unhealthy_node_count > 0 {
            bail!(
                "daemon signal reports degraded={} unhealthy={} nodes during readiness",
                signal_metrics.degraded_node_count,
                signal_metrics.unhealthy_node_count
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
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to send {context} request"))?
        .error_for_status()
        .with_context(|| format!("{context} request was rejected"))?;
    read_bounded_json_response(response, context, MAX_LOAD_HTTP_JSON_RESPONSE_BYTES).await
}

async fn get_text(client: &reqwest::Client, url: String, context: &str) -> anyhow::Result<String> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to send {context} request"))?
        .error_for_status()
        .with_context(|| format!("{context} request was rejected"))?;
    read_bounded_text_response(response, context, MAX_LOAD_HTTP_TEXT_RESPONSE_BYTES).await
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

fn prometheus_metric_labeled_u64(
    body: &str,
    metric_name: &str,
    labels: &[(&str, &str)],
) -> anyhow::Result<u64> {
    let mut total = 0_u64;
    let mut found = false;
    for line in body.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((sample_labels, value)) = prometheus_sample(line, metric_name) else {
            continue;
        };
        if labels
            .iter()
            .all(|(key, value)| prometheus_labels_contain(sample_labels, key, value))
        {
            let parsed = value
                .parse::<u64>()
                .with_context(|| format!("failed to parse metric {metric_name} value"))?;
            total = total
                .checked_add(parsed)
                .with_context(|| format!("metric {metric_name} value overflowed u64"))?;
            found = true;
        }
    }

    if found {
        return Ok(total);
    }

    let label_summary = labels
        .iter()
        .map(|(key, value)| format!("{key}=\"{value}\""))
        .collect::<Vec<_>>()
        .join(",");
    bail!("metric {metric_name} with labels {{{label_summary}}} was not present in relay metrics response")
}

fn prometheus_sample<'a>(line: &'a str, metric_name: &str) -> Option<(&'a str, &'a str)> {
    let mut parts = line.split_whitespace();
    let sample = parts.next()?;
    let value = parts.next()?;
    if sample == metric_name {
        return Some(("", value));
    }
    let suffix = sample.strip_prefix(metric_name)?;
    let labels = suffix.strip_prefix('{')?.strip_suffix('}')?;
    Some((labels, value))
}

fn prometheus_labels_contain(labels: &str, key: &str, value: &str) -> bool {
    labels.split(',').any(|label| {
        let Some((label_key, label_value)) = label.split_once('=') else {
            return false;
        };
        label_key.trim() == key && label_value.trim().trim_matches('"') == value
    })
}

fn daemon_stun_report(
    metrics: &StunMetricsResponse,
    prometheus: &str,
    expected_listen: SocketAddr,
    expected_alternate_listen: SocketAddr,
) -> DaemonStunReport {
    let expected_alternate_label = format!("alternate_listen=\"{expected_alternate_listen}\"");
    DaemonStunReport {
        metrics_endpoints: 1,
        listen_matches_expected: metrics.listen == expected_listen,
        alternate_listen_matches_expected: metrics.alternate_listen
            == Some(expected_alternate_listen),
        prometheus_alternate_listener_reported: prometheus
            .contains("ipars_stun_rfc5780_alternate_server_active")
            && prometheus.contains(&expected_alternate_label),
        binding_requests_reported: metrics.binding_request_count,
        binding_responses_reported: metrics.binding_response_count,
        invalid_packets_reported: metrics.invalid_packet_count,
        socket_receive_errors_reported: metrics.socket_receive_error_count,
        socket_send_errors_reported: metrics.socket_send_error_count,
    }
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
    let response = client
        .post(url)
        .json(request)
        .send()
        .await
        .with_context(|| format!("failed to send {context} request"))?
        .error_for_status()
        .with_context(|| format!("{context} request was rejected"))?;
    read_bounded_json_response(response, context, MAX_LOAD_HTTP_JSON_RESPONSE_BYTES).await
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
    let response = client
        .put(url)
        .json(request)
        .send()
        .await
        .with_context(|| format!("failed to send {context} request"))?
        .error_for_status()
        .with_context(|| format!("{context} request was rejected"))?;
    read_bounded_json_response(response, context, MAX_LOAD_HTTP_JSON_RESPONSE_BYTES).await
}

async fn read_bounded_json_response<Response>(
    response: reqwest::Response,
    context: &str,
    max_bytes: u64,
) -> anyhow::Result<Response>
where
    Response: DeserializeOwned,
{
    let body = read_bounded_response_body(response, context, max_bytes).await?;
    serde_json::from_slice(&body).with_context(|| format!("failed to decode {context} response"))
}

async fn read_bounded_text_response(
    response: reqwest::Response,
    context: &str,
    max_bytes: u64,
) -> anyhow::Result<String> {
    let body = read_bounded_response_body(response, context, max_bytes).await?;
    String::from_utf8(body).with_context(|| format!("failed to decode {context} response"))
}

async fn read_bounded_response_body(
    mut response: reqwest::Response,
    context: &str,
    max_bytes: u64,
) -> anyhow::Result<Vec<u8>> {
    if let Some(length) = response.content_length() {
        ensure_load_http_response_size(length, context, max_bytes)?;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("failed to read {context} response"))?
    {
        let next_len = body.len() as u64 + chunk.len() as u64;
        ensure_load_http_response_size(next_len, context, max_bytes)?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn ensure_load_http_response_size(size: u64, context: &str, max_bytes: u64) -> anyhow::Result<()> {
    if size > max_bytes {
        bail!("{context} response exceeds maximum size of {max_bytes} bytes");
    }
    Ok(())
}

fn register_request(index: usize, scenario: Scenario) -> anyhow::Result<RegisterNodeRequest> {
    let identity = identity_for_index(index);
    let node_id = identity.node_id();
    Ok(RegisterNodeRequest {
        node_id,
        identity_public_key: identity.public_key_b64(),
        wireguard_public_key: wireguard_public_key_for_index(index),
        candidates: endpoint_candidates(index, scenario),
        relay_capability: relay_capability(index, scenario),
        requested_routes: advertised_routes(index, scenario)?,
    })
}

fn wireguard_public_key_for_index(index: usize) -> String {
    let mut bytes = [0_u8; 32];
    for (offset, byte) in index.to_le_bytes().iter().enumerate() {
        bytes[offset] = *byte;
    }
    bytes[8] = 0x77;
    bytes[9] = 0x67;
    encode_bytes(&bytes)
}

fn heartbeat_request(index: usize, node: &NodeRecord) -> anyhow::Result<HeartbeatRequest> {
    let mut request = HeartbeatRequest {
        node_id: node.node_id.clone(),
        health: healthy_node_health(),
        candidates: node.endpoint_candidates.clone(),
        relay_capability: node.relay_capability.clone(),
        routes: Some(node.routes.clone()),
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
    join_claims_with_control_plane_urls(
        cluster_id,
        issuer,
        key_id,
        index,
        scenario,
        &["http://127.0.0.1:8443".to_string()],
    )
}

fn join_claims_with_control_plane_urls(
    cluster_id: &ClusterId,
    issuer: &NodeId,
    key_id: &KeyId,
    index: usize,
    scenario: Scenario,
    control_plane_urls: &[String],
) -> anyhow::Result<JoinTokenClaims> {
    if control_plane_urls.is_empty() {
        bail!("join token requires at least one control-plane bootstrap URL");
    }
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
        bootstrap_endpoints: control_plane_urls
            .iter()
            .map(|url| BootstrapEndpoint {
                url: url.clone(),
                kind: BootstrapEndpointKind::ControlPlane,
            })
            .collect(),
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
        addr: endpoint_candidate_addr(kind, index),
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

fn endpoint_candidate_addr(kind: EndpointCandidateKind, index: usize) -> SocketAddr {
    let port = 30_000 + (index % 30_000) as u16;
    match kind {
        EndpointCandidateKind::Ipv6 => SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0x0db8,
                ((index >> 48) & 0xffff) as u16,
                ((index >> 32) & 0xffff) as u16,
                ((index >> 16) & 0xffff) as u16,
                (index & 0xffff) as u16,
                0,
                1,
            )),
            port,
        ),
        _ => SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, (index % 250 + 1) as u8)),
            port,
        ),
    }
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

    fn assert_zero_filled_relay_admission_failure_reasons(report: &LoadReport) {
        assert_eq!(
            report.relay_admission_failures_by_reason_reported.len(),
            RelayAdmissionFailureReason::ALL.len()
        );
        for reason in RelayAdmissionFailureReason::ALL {
            assert_eq!(
                report
                    .relay_admission_failures_by_reason_reported
                    .get(&reason),
                Some(&0),
                "{reason:?} should be zero-filled"
            );
        }
    }

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
        assert_eq!(report.daemon_control_plane_healthy_nodes, 0);
        assert_eq!(report.daemon_signal_health_reports, 0);
        report.validate_success()?;
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
        assert_eq!(report.daemon_control_plane_healthy_nodes, 0);
        assert_eq!(report.daemon_signal_health_reports, 0);
        report.validate_success()?;
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
        assert_eq!(
            report.relay_dataplane_invalid_session_credential_drops_reported,
            1
        );
        assert_eq!(
            report.relay_dataplane_invalid_session_credential_drops_prometheus_reported,
            1
        );
        assert_eq!(report.relay_active_sessions_reported, 6);
        assert_eq!(report.relay_available_sessions_reported, 9_994);
        assert_eq!(report.relay_max_sessions_reported, 10_000);
        assert_eq!(report.relay_max_mbps_reported, 10_000);
        assert!(report.relay_enabled_by_policy_reported);
        assert!(report.relay_e2e_only_reported);
        assert_eq!(report.relay_admission_attempts_reported, 6);
        assert_eq!(report.relay_admission_successes_reported, 6);
        assert_eq!(report.relay_admission_failures_reported, 0);
        assert_zero_filled_relay_admission_failure_reasons(&report);
        assert_eq!(report.relay_http_requests, 8);
        assert_eq!(report.daemon_control_plane_healthy_nodes, 0);
        assert_eq!(report.daemon_signal_health_reports, 0);
        report.validate_success()?;
        Ok(())
    }

    #[test]
    fn prometheus_labeled_metric_sums_matching_samples() -> anyhow::Result<()> {
        let body = r#"
# HELP ipars_relay_datagrams_dropped_by_reason_total Drops by reason.
# TYPE ipars_relay_datagrams_dropped_by_reason_total counter
ipars_relay_datagrams_dropped_by_reason_total{relay_node="relay-a",reason="invalid_session_credential"} 1
ipars_relay_datagrams_dropped_by_reason_total{reason="invalid_session_credential",relay_node="relay-b"} 2
ipars_relay_datagrams_dropped_by_reason_total{relay_node="relay-a",reason="unknown_session"} 5
"#;

        let drops = prometheus_metric_labeled_u64(
            body,
            "ipars_relay_datagrams_dropped_by_reason_total",
            &[(
                "reason",
                RelayDataplaneDropReason::InvalidSessionCredential.as_str(),
            )],
        )?;

        assert_eq!(drops, 3);
        Ok(())
    }

    #[test]
    fn daemon_retained_manifest_reader_rejects_oversized_and_symlinked_files() -> anyhow::Result<()>
    {
        let base = daemon_runtime_dir()?;
        std::fs::create_dir_all(&base)?;
        let manifest = base.join("manifest.json");
        let oversized = base.join("oversized-manifest.json");
        std::fs::write(&manifest, b"{\"phase\":\"completed\"}")?;
        assert_eq!(
            read_bounded_regular_file(
                &manifest,
                "daemon load scenario retained manifest",
                MAX_DAEMON_RUNTIME_MANIFEST_BYTES,
            )?,
            b"{\"phase\":\"completed\"}"
        );

        std::fs::write(
            &oversized,
            vec![b'{'; MAX_DAEMON_RUNTIME_MANIFEST_BYTES as usize + 1],
        )?;
        let error = match read_bounded_regular_file(
            &oversized,
            "daemon load scenario retained manifest",
            MAX_DAEMON_RUNTIME_MANIFEST_BYTES,
        ) {
            Ok(_) => bail!("oversized retained manifest should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds maximum size"));

        #[cfg(unix)]
        {
            let link = base.join("manifest-link.json");
            std::os::unix::fs::symlink(&manifest, &link)?;
            let error = match read_bounded_regular_file(
                &link,
                "daemon load scenario retained manifest",
                MAX_DAEMON_RUNTIME_MANIFEST_BYTES,
            ) {
                Ok(_) => bail!("symlinked retained manifest should be rejected"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("is not a regular file"));
        }

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn daemon_log_diagnostics_hashes_only_bounded_tail() -> anyhow::Result<()> {
        let base = daemon_runtime_dir()?;
        std::fs::create_dir_all(&base)?;
        let log_path = base.join("0000-control-plane-0.log");
        let mut contents = Vec::new();
        contents.extend_from_slice(b"first-line\n");
        contents.extend(std::iter::repeat_n(b'x', DAEMON_LOG_TAIL_BYTES * 2));
        contents.extend_from_slice(b"\nfinal-line\n");
        std::fs::write(&log_path, &contents)?;

        let tail = daemon_log_tail(&log_path)?;
        assert!(tail.contains("final-line"));
        assert!(!tail.contains("first-line"));

        let diagnostics =
            daemon_log_diagnostics(&log_path).context("log diagnostics should be available")?;
        assert_eq!(diagnostics.bytes, contents.len() as u64);
        let expected_tail = &contents[contents.len() - DAEMON_LOG_TAIL_BYTES..];
        let mut hasher = Sha256::new();
        hasher.update(expected_tail);
        assert_eq!(diagnostics.tail_sha256, format!("{:x}", hasher.finalize()));

        #[cfg(unix)]
        {
            let link = base.join("log-link");
            std::os::unix::fs::symlink(&log_path, &link)?;
            let error = match daemon_log_tail(&link) {
                Ok(_) => bail!("symlinked daemon log should be rejected"),
                Err(error) => error,
            };
            assert!(format!("{error:#}").contains("not a regular file"));
            assert!(daemon_log_diagnostics(&link).is_none());
        }

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[tokio::test]
    async fn load_report_success_validation_rejects_degraded_results() -> anyhow::Result<()> {
        let report = run_in_memory_scenario(Scenario::from_name(ScenarioName::Three)).await?;

        let mut all_unreachable = report.clone();
        all_unreachable.direct_public_paths = 0;
        all_unreachable.direct_ipv6_paths = 0;
        all_unreachable.direct_nat_paths = 0;
        all_unreachable.relay_paths = 0;
        all_unreachable.unreachable_paths = all_unreachable.signal_negotiations;
        let error = match all_unreachable.validate_success() {
            Ok(_) => bail!("all-unreachable load paths should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("no reachable paths"));

        let mut missing_advertised_route = report.clone();
        missing_advertised_route.advertised_routes = 0;
        let error = match missing_advertised_route.validate_success() {
            Ok(_) => bail!("missing advertised route should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("advertised"));

        let relay_report = run_relay_udp_scenario(
            Scenario::from_name(ScenarioName::Three),
            RelayLoadOptions {
                packets_per_session: 1,
                payload_bytes: 64,
            },
        )
        .await?;
        let mut dropped_packet = relay_report.clone();
        dropped_packet.relay_udp_packets_received -= 1;
        let error = match dropped_packet.validate_success() {
            Ok(_) => bail!("dropped relay packet should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("received"));

        let mut missing_relay_session = relay_report.clone();
        missing_relay_session.relay_active_sessions_reported -= 1;
        let error = match missing_relay_session.validate_success() {
            Ok(_) => bail!("missing relay active session should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("relay session mismatch"));

        let mut skewed_relay_capacity = relay_report.clone();
        skewed_relay_capacity.relay_available_sessions_reported -= 1;
        let error = match skewed_relay_capacity.validate_success() {
            Ok(_) => bail!("skewed relay capacity should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("relay capacity snapshot"));

        let mut disabled_relay_policy = relay_report.clone();
        disabled_relay_policy.relay_enabled_by_policy_reported = false;
        let error = match disabled_relay_policy.validate_success() {
            Ok(_) => bail!("disabled relay policy should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("relay capability snapshot"));

        let mut skewed_admission_counters = relay_report.clone();
        skewed_admission_counters.relay_admission_attempts_reported -= 1;
        skewed_admission_counters
            .relay_admission_failures_by_reason_reported
            .insert(RelayAdmissionFailureReason::RateLimited, 1);
        let error = match skewed_admission_counters.validate_success() {
            Ok(_) => bail!("skewed relay admission counters should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("relay admission mismatch"));

        let mut missing_prometheus_drop = relay_report.clone();
        missing_prometheus_drop
            .relay_dataplane_invalid_session_credential_drops_prometheus_reported = 0;
        let error = match missing_prometheus_drop.validate_success() {
            Ok(_) => bail!("missing Prometheus invalid credential drop should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("Prometheus metrics"));

        let daemon_report = valid_daemon_report_for_validation().await?;
        daemon_report.validate_success()?;

        let mut missing_daemon_agent_status = daemon_report.clone();
        missing_daemon_agent_status.daemon_agent_status_endpoints -= 1;
        let error = match missing_daemon_agent_status.validate_success() {
            Ok(_) => bail!("daemon report with missing agent status should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("agent status endpoints"));

        let mut missing_daemon_candidate = daemon_report.clone();
        missing_daemon_candidate.daemon_agent_candidate_count_min = 0;
        let error = match missing_daemon_candidate.validate_success() {
            Ok(_) => bail!("daemon report with missing endpoint candidate should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("endpoint candidate"));

        let mut missing_daemon_metrics_endpoint = daemon_report.clone();
        missing_daemon_metrics_endpoint.daemon_control_plane_metrics_endpoints = 1;
        let error = match missing_daemon_metrics_endpoint.validate_success() {
            Ok(_) => bail!("daemon report with missing metrics endpoint should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("metrics endpoints"));

        let mut missing_daemon_relay_candidate = daemon_report.clone();
        missing_daemon_relay_candidate.daemon_control_plane_relay_candidates_min = 0;
        let error = match missing_daemon_relay_candidate.validate_success() {
            Ok(_) => bail!("daemon report with missing relay candidate should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("relay candidate mismatch"));

        let mut missing_daemon_stun_metrics = daemon_report.clone();
        missing_daemon_stun_metrics.daemon_stun.metrics_endpoints = 0;
        let error = match missing_daemon_stun_metrics.validate_success() {
            Ok(_) => bail!("daemon report with missing STUN metrics should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("STUN metrics endpoints"));

        let mut missing_daemon_stun_probe = daemon_report.clone();
        missing_daemon_stun_probe
            .daemon_stun
            .binding_responses_reported = 0;
        let error = match missing_daemon_stun_probe.validate_success() {
            Ok(_) => bail!("daemon report with missing STUN probes should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("STUN binding counters"));

        let mut missing_daemon_stun_alternate = daemon_report.clone();
        missing_daemon_stun_alternate
            .daemon_stun
            .prometheus_alternate_listener_reported = false;
        let error = match missing_daemon_stun_alternate.validate_success() {
            Ok(_) => bail!("daemon report without STUN alternate listener should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("STUN listener metrics"));

        let mut retained_manifest = daemon_report.clone();
        let (retained_runtime_dir, retained_manifest_path) =
            write_synthetic_retained_daemon_manifest(
                &retained_manifest,
                DaemonRuntimePhase::Completed,
                &[
                    "control-plane-0",
                    "control-plane-1",
                    "signal",
                    "relay",
                    "stun",
                    "agent",
                ],
            )?;
        retained_manifest.daemon_runtime_dir = Some(retained_runtime_dir.clone());
        retained_manifest.daemon_runtime_manifest = Some(retained_manifest_path.clone());
        retained_manifest.validate_success()?;
        let retained_contents = std::fs::read_to_string(&retained_manifest_path)?;
        assert!(!retained_contents.contains(DAEMON_JOIN_TOKEN_FILE_SUFFIX));
        let retained_decoded: DaemonRuntimeManifest = serde_json::from_str(&retained_contents)?;
        assert_ne!(
            retained_decoded.stun_addr,
            retained_decoded.stun_alternate_addr
        );
        assert!(retained_decoded.children.iter().all(|child| {
            child.state == DaemonRuntimeManifestChildState::Exited
                && child.exited_at.is_some()
                && child.runtime_ms.is_some()
        }));
        let agent_command = retained_decoded
            .children
            .iter()
            .find(|child| child.role == "agent")
            .context("synthetic retained manifest did not include an agent child")?;
        assert!(agent_command
            .redacted_argv
            .windows(2)
            .any(|window| window[0] == "--join-token-path" && window[1] == DAEMON_REDACTED_ARG));
        assert_eq!(
            agent_command.redacted_argv_sha256,
            daemon_argv_sha256(&agent_command.redacted_argv)
        );

        let mut mismatched_iparsd_binary_digest = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &mismatched_iparsd_binary_digest,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        mismatched_iparsd_binary_digest.daemon_runtime_dir = Some(runtime_dir.clone());
        mismatched_iparsd_binary_digest.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.iparsd_binary.sha256 = "0".repeat(64);
        })?;
        let error = match mismatched_iparsd_binary_digest.validate_success() {
            Ok(_) => bail!("retained manifest with mismatched iparsd binary digest should fail"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("iparsd binary digest mismatch"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut relative_iparsd_binary_path = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &relative_iparsd_binary_path,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        relative_iparsd_binary_path.daemon_runtime_dir = Some(runtime_dir.clone());
        relative_iparsd_binary_path.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.iparsd_binary.path = PathBuf::from("iparsd");
        })?;
        let error = match relative_iparsd_binary_path.validate_success() {
            Ok(_) => bail!("retained manifest with relative iparsd binary path should fail"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("iparsd binary path"));
        assert!(error.contains("not absolute"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut unredacted_child_secret = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &unredacted_child_secret,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        unredacted_child_secret.daemon_runtime_dir = Some(runtime_dir.clone());
        unredacted_child_secret.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            if let Some(agent) = manifest
                .children
                .iter_mut()
                .find(|child| child.role == "agent")
            {
                if let Some(index) = agent
                    .redacted_argv
                    .iter()
                    .position(|argument| argument == "--join-token-path")
                {
                    agent.redacted_argv[index + 1] =
                        "/tmp/ipars-load-agent-0000.join-token.json".to_string();
                    agent.redacted_argv_sha256 = daemon_argv_sha256(&agent.redacted_argv);
                }
            }
        })?;
        let error = match unredacted_child_secret.validate_success() {
            Ok(_) => bail!("retained manifest with unredacted child argv should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("did not redact"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut mismatched_child_argv_hash = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &mismatched_child_argv_hash,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        mismatched_child_argv_hash.daemon_runtime_dir = Some(runtime_dir.clone());
        mismatched_child_argv_hash.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.children[0].redacted_argv_sha256 = "0".repeat(64);
        })?;
        let error = match mismatched_child_argv_hash.validate_success() {
            Ok(_) => bail!("retained manifest with mismatched child argv hash should fail"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("redacted argv hash mismatch"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut missing_child_exit_timing = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &missing_child_exit_timing,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        missing_child_exit_timing.daemon_runtime_dir = Some(runtime_dir.clone());
        missing_child_exit_timing.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.children[0].exited_at = None;
        })?;
        let error = match missing_child_exit_timing.validate_success() {
            Ok(_) => bail!("retained manifest with missing child exit timing should fail"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("missing exited_at"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut mismatched_child_runtime = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &mismatched_child_runtime,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        mismatched_child_runtime.daemon_runtime_dir = Some(runtime_dir.clone());
        mismatched_child_runtime.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.children[0].runtime_ms = Some(
                manifest.children[0]
                    .runtime_ms
                    .unwrap_or_default()
                    .saturating_add(1),
            );
        })?;
        let error = match mismatched_child_runtime.validate_success() {
            Ok(_) => bail!("retained manifest with mismatched child runtime should fail"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("runtime_ms"));
        std::fs::remove_dir_all(&runtime_dir)?;

        std::fs::write(
            retained_runtime_dir.join("0000-control-plane-0.log"),
            "tampered retained log\n",
        )?;
        let error = match retained_manifest.validate_success() {
            Ok(_) => {
                bail!("retained manifest with mismatched log diagnostics should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("log diagnostics mismatch"));
        std::fs::remove_dir_all(&retained_runtime_dir)?;

        let mut mismatched_manifest_measurement = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &mismatched_manifest_measurement,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        mismatched_manifest_measurement.daemon_runtime_dir = Some(runtime_dir.clone());
        mismatched_manifest_measurement.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            if let Some(measurement) = manifest.measurement.as_mut() {
                measurement.failover_relay_udp_packets_received -= 1;
            }
        })?;
        let error = match mismatched_manifest_measurement.validate_success() {
            Ok(_) => bail!(
                "retained manifest with mismatched measurement summary should fail validation"
            ),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("measurement summary"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut missing_manifest_measurement = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &missing_manifest_measurement,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        missing_manifest_measurement.daemon_runtime_dir = Some(runtime_dir.clone());
        missing_manifest_measurement.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.measurement = None;
        })?;
        let error = match missing_manifest_measurement.validate_success() {
            Ok(_) => bail!("retained manifest without measurement summary should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("missing measurement summary"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut duplicate_child_log_path = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &duplicate_child_log_path,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        duplicate_child_log_path.daemon_runtime_dir = Some(runtime_dir.clone());
        duplicate_child_log_path.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            let duplicate_log_path = manifest.children[0].log_path.clone();
            let duplicate_log_bytes = manifest.children[0].log_bytes;
            let duplicate_log_tail_sha256 = manifest.children[0].log_tail_sha256.clone();
            manifest.children[1].log_path = duplicate_log_path;
            manifest.children[1].log_bytes = duplicate_log_bytes;
            manifest.children[1].log_tail_sha256 = duplicate_log_tail_sha256;
        })?;
        let error = match duplicate_child_log_path.validate_success() {
            Ok(_) => {
                bail!("retained manifest with duplicate child log path should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("duplicated"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut duplicate_child_log_serial = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &duplicate_child_log_serial,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        duplicate_child_log_serial.daemon_runtime_dir = Some(runtime_dir.clone());
        duplicate_child_log_serial.daemon_runtime_manifest = Some(manifest_path.clone());
        let duplicate_serial_log_path = runtime_dir.join("0000-signal.log");
        std::fs::rename(
            runtime_dir.join("0002-signal.log"),
            &duplicate_serial_log_path,
        )?;
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.children[2].log_path = Some(duplicate_serial_log_path);
        })?;
        let error = match duplicate_child_log_serial.validate_success() {
            Ok(_) => {
                bail!("retained manifest with duplicate child log serial should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("reuses serial prefix"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut invalid_child_log_serial = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &invalid_child_log_serial,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        invalid_child_log_serial.daemon_runtime_dir = Some(runtime_dir.clone());
        invalid_child_log_serial.daemon_runtime_manifest = Some(manifest_path.clone());
        let invalid_serial_log_path = runtime_dir.join("2-signal.log");
        std::fs::rename(
            runtime_dir.join("0002-signal.log"),
            &invalid_serial_log_path,
        )?;
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.children[2].log_path = Some(invalid_serial_log_path);
        })?;
        let error = match invalid_child_log_serial.validate_success() {
            Ok(_) => {
                bail!("retained manifest with invalid child log serial should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("invalid serial prefix"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut out_of_order_child_roles = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &out_of_order_child_roles,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        out_of_order_child_roles.daemon_runtime_dir = Some(runtime_dir.clone());
        out_of_order_child_roles.daemon_runtime_manifest = Some(manifest_path.clone());
        let relay_log_path = runtime_dir.join("0002-relay.log");
        let signal_log_path = runtime_dir.join("0003-signal.log");
        std::fs::rename(runtime_dir.join("0002-signal.log"), &relay_log_path)?;
        std::fs::rename(runtime_dir.join("0003-relay.log"), &signal_log_path)?;
        let relay_log_diagnostics =
            daemon_log_diagnostics(&relay_log_path).context("renamed relay log was unreadable")?;
        let signal_log_diagnostics = daemon_log_diagnostics(&signal_log_path)
            .context("renamed signal log was unreadable")?;
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.children[2].role = "relay".to_string();
            manifest.children[2].redacted_argv = synthetic_child_redacted_argv("relay");
            manifest.children[2].redacted_argv_sha256 =
                synthetic_child_redacted_argv_sha256("relay");
            manifest.children[2].log_path = Some(relay_log_path);
            manifest.children[2].log_bytes = Some(relay_log_diagnostics.bytes);
            manifest.children[2].log_tail_sha256 = Some(relay_log_diagnostics.tail_sha256);
            manifest.children[3].role = "signal".to_string();
            manifest.children[3].redacted_argv = synthetic_child_redacted_argv("signal");
            manifest.children[3].redacted_argv_sha256 =
                synthetic_child_redacted_argv_sha256("signal");
            manifest.children[3].log_path = Some(signal_log_path);
            manifest.children[3].log_bytes = Some(signal_log_diagnostics.bytes);
            manifest.children[3].log_tail_sha256 = Some(signal_log_diagnostics.tail_sha256);
        })?;
        let error = match out_of_order_child_roles.validate_success() {
            Ok(_) => {
                bail!("retained manifest with out-of-order child roles should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("child role sequence"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut out_of_order_child_log_serial = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &out_of_order_child_log_serial,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        out_of_order_child_log_serial.daemon_runtime_dir = Some(runtime_dir.clone());
        out_of_order_child_log_serial.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            let first_agent_log_path = manifest.children[5].log_path.clone();
            let first_agent_log_bytes = manifest.children[5].log_bytes;
            let first_agent_log_tail_sha256 = manifest.children[5].log_tail_sha256.clone();
            let second_agent_log_path = manifest.children[6].log_path.clone();
            let second_agent_log_bytes = manifest.children[6].log_bytes;
            let second_agent_log_tail_sha256 = manifest.children[6].log_tail_sha256.clone();

            manifest.children[5].log_path = second_agent_log_path;
            manifest.children[5].log_bytes = second_agent_log_bytes;
            manifest.children[5].log_tail_sha256 = second_agent_log_tail_sha256;
            manifest.children[6].log_path = first_agent_log_path;
            manifest.children[6].log_bytes = first_agent_log_bytes;
            manifest.children[6].log_tail_sha256 = first_agent_log_tail_sha256;
        })?;
        let error = match out_of_order_child_log_serial.validate_success() {
            Ok(_) => {
                bail!("retained manifest with out-of-order child log serial should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("not greater than previous serial prefix"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut role_mismatched_child_log_path = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &role_mismatched_child_log_path,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        role_mismatched_child_log_path.daemon_runtime_dir = Some(runtime_dir.clone());
        role_mismatched_child_log_path.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            let first_log_path = manifest.children[0].log_path.clone();
            let first_log_bytes = manifest.children[0].log_bytes;
            let first_log_tail_sha256 = manifest.children[0].log_tail_sha256.clone();
            let second_log_path = manifest.children[1].log_path.clone();
            let second_log_bytes = manifest.children[1].log_bytes;
            let second_log_tail_sha256 = manifest.children[1].log_tail_sha256.clone();

            manifest.children[0].log_path = second_log_path;
            manifest.children[0].log_bytes = second_log_bytes;
            manifest.children[0].log_tail_sha256 = second_log_tail_sha256;
            manifest.children[1].log_path = first_log_path;
            manifest.children[1].log_bytes = first_log_bytes;
            manifest.children[1].log_tail_sha256 = first_log_tail_sha256;
        })?;
        let error = match role_mismatched_child_log_path.validate_success() {
            Ok(_) => {
                bail!("retained manifest with role-mismatched child logs should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("log file name"));
        assert!(error.contains("child role"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut empty_child_log = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &empty_child_log,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        empty_child_log.daemon_runtime_dir = Some(runtime_dir.clone());
        empty_child_log.daemon_runtime_manifest = Some(manifest_path.clone());
        let empty_log_path = runtime_dir.join("0000-control-plane-0.log");
        let empty_log_file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&empty_log_path)?;
        empty_log_file.sync_all()?;
        drop(empty_log_file);
        let empty_log_diagnostics =
            daemon_log_diagnostics(&empty_log_path).context("empty child log was unreadable")?;
        let empty_log_bytes = empty_log_diagnostics.bytes;
        let empty_log_tail_sha256 = empty_log_diagnostics.tail_sha256;
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.children[0].log_bytes = Some(empty_log_bytes);
            manifest.children[0].log_tail_sha256 = Some(empty_log_tail_sha256.clone());
        })?;
        let error = match empty_child_log.validate_success() {
            Ok(_) => bail!("retained manifest with empty child log should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("is empty"));
        std::fs::remove_dir_all(&runtime_dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            let mut world_readable_runtime_dir = daemon_report.clone();
            let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
                &world_readable_runtime_dir,
                DaemonRuntimePhase::Completed,
                &[
                    "control-plane-0",
                    "control-plane-1",
                    "signal",
                    "relay",
                    "stun",
                    "agent",
                ],
            )?;
            world_readable_runtime_dir.daemon_runtime_dir = Some(runtime_dir.clone());
            world_readable_runtime_dir.daemon_runtime_manifest = Some(manifest_path);
            std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o755))?;
            let error = match world_readable_runtime_dir.validate_success() {
                Ok(_) => bail!("world-readable retained runtime dir should fail validation"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("retained runtime directory"));
            assert!(error.contains("permissions"));
            std::fs::remove_dir_all(&runtime_dir)?;

            let mut world_readable_manifest = daemon_report.clone();
            let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
                &world_readable_manifest,
                DaemonRuntimePhase::Completed,
                &[
                    "control-plane-0",
                    "control-plane-1",
                    "signal",
                    "relay",
                    "stun",
                    "agent",
                ],
            )?;
            world_readable_manifest.daemon_runtime_dir = Some(runtime_dir.clone());
            world_readable_manifest.daemon_runtime_manifest = Some(manifest_path.clone());
            std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(0o644))?;
            let error = match world_readable_manifest.validate_success() {
                Ok(_) => bail!("world-readable retained manifest should fail validation"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("retained manifest"));
            assert!(error.contains("permissions"));
            std::fs::remove_dir_all(&runtime_dir)?;

            let mut world_readable_child_log = daemon_report.clone();
            let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
                &world_readable_child_log,
                DaemonRuntimePhase::Completed,
                &[
                    "control-plane-0",
                    "control-plane-1",
                    "signal",
                    "relay",
                    "stun",
                    "agent",
                ],
            )?;
            world_readable_child_log.daemon_runtime_dir = Some(runtime_dir.clone());
            world_readable_child_log.daemon_runtime_manifest = Some(manifest_path.clone());
            std::fs::set_permissions(
                runtime_dir.join("0000-control-plane-0.log"),
                std::fs::Permissions::from_mode(0o644),
            )?;
            let error = match world_readable_child_log.validate_success() {
                Ok(_) => bail!("world-readable retained child log should fail validation"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("child control-plane-0 log"));
            assert!(error.contains("permissions"));
            std::fs::remove_dir_all(&runtime_dir)?;

            let (runtime_dir, _manifest_path) = write_synthetic_retained_daemon_manifest(
                &daemon_report,
                DaemonRuntimePhase::Completed,
                &[
                    "control-plane-0",
                    "control-plane-1",
                    "signal",
                    "relay",
                    "stun",
                    "agent",
                ],
            )?;
            let metadata = std::fs::symlink_metadata(&runtime_dir)?;
            let mismatched_uid = if metadata.uid() == 0 { 1 } else { 0 };
            let error = match validate_daemon_retained_path_owner(
                &runtime_dir,
                &metadata,
                mismatched_uid,
                "retained runtime directory",
            ) {
                Ok(_) => bail!("retained runtime owner UID mismatch should fail validation"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("owner uid"));
            assert!(error.contains("retained runtime directory"));
            std::fs::remove_dir_all(&runtime_dir)?;

            let mut world_readable_runtime_entry = daemon_report.clone();
            let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
                &world_readable_runtime_entry,
                DaemonRuntimePhase::Completed,
                &[
                    "control-plane-0",
                    "control-plane-1",
                    "signal",
                    "relay",
                    "stun",
                    "agent",
                ],
            )?;
            world_readable_runtime_entry.daemon_runtime_dir = Some(runtime_dir.clone());
            world_readable_runtime_entry.daemon_runtime_manifest = Some(manifest_path);
            let sqlite_path = runtime_dir.join("control-plane.sqlite");
            std::fs::write(&sqlite_path, "sqlite diagnostic")?;
            std::fs::set_permissions(&sqlite_path, std::fs::Permissions::from_mode(0o644))?;
            let error = match world_readable_runtime_entry.validate_success() {
                Ok(_) => bail!("world-readable retained runtime entry should fail validation"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("retained runtime entry"));
            assert!(error.contains("permissions"));
            std::fs::remove_dir_all(&runtime_dir)?;
        }

        let mut retained_join_token = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &retained_join_token,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        retained_join_token.daemon_runtime_dir = Some(runtime_dir.clone());
        retained_join_token.daemon_runtime_manifest = Some(manifest_path);
        std::fs::write(
            daemon_join_token_path(&runtime_dir, 0),
            "{\"token\":\"left-behind\"}\n",
        )?;
        let error = match retained_join_token.validate_success() {
            Ok(_) => bail!("retained runtime with leftover join token should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("join token"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut retained_agent_state = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &retained_agent_state,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        retained_agent_state.daemon_runtime_dir = Some(runtime_dir.clone());
        retained_agent_state.daemon_runtime_manifest = Some(manifest_path);
        std::fs::write(
            daemon_agent_state_path(&runtime_dir, 0),
            "{\"identity_private_key\":\"left-behind\"}\n",
        )?;
        let error = match retained_agent_state.validate_success() {
            Ok(_) => bail!("retained runtime with leftover agent state should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("agent state"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut retained_manifest_temp = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &retained_manifest_temp,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        retained_manifest_temp.daemon_runtime_dir = Some(runtime_dir.clone());
        retained_manifest_temp.daemon_runtime_manifest = Some(manifest_path);
        std::fs::write(
            runtime_dir.join(format!(".{DAEMON_RUNTIME_MANIFEST_FILE}.synthetic.tmp")),
            "{}\n",
        )?;
        let error = match retained_manifest_temp.validate_success() {
            Ok(_) => bail!("retained runtime with temporary manifest should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("temporary manifest"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut retained_unexpected_entry = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &retained_unexpected_entry,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        retained_unexpected_entry.daemon_runtime_dir = Some(runtime_dir.clone());
        retained_unexpected_entry.daemon_runtime_manifest = Some(manifest_path);
        let unexpected_path = runtime_dir.join("unexpected-debug.txt");
        let mut unexpected_file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .private_on_unix()
            .open(&unexpected_path)?;
        unexpected_file.write_all(b"unexpected retained artifact\n")?;
        unexpected_file.sync_all()?;
        let error = match retained_unexpected_entry.validate_success() {
            Ok(_) => bail!("retained runtime with unexpected entry should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("unexpected entry"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut retained_sqlite_sidecars = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &retained_sqlite_sidecars,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        retained_sqlite_sidecars.daemon_runtime_dir = Some(runtime_dir.clone());
        retained_sqlite_sidecars.daemon_runtime_manifest = Some(manifest_path);
        for name in [
            DAEMON_CONTROL_PLANE_SQLITE_FILE,
            "control-plane.sqlite-wal",
            "control-plane.sqlite-shm",
        ] {
            let mut sqlite_file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .private_on_unix()
                .open(runtime_dir.join(name))?;
            sqlite_file.write_all(b"sqlite retained artifact\n")?;
            sqlite_file.sync_all()?;
        }
        retained_sqlite_sidecars.validate_success()?;
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut stale_generated_timestamp = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &stale_generated_timestamp,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        stale_generated_timestamp.daemon_runtime_dir = Some(runtime_dir.clone());
        stale_generated_timestamp.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.generated_at = manifest.updated_at - chrono::Duration::seconds(1);
        })?;
        let error = match stale_generated_timestamp.validate_success() {
            Ok(_) => {
                bail!("retained manifest with stale generated timestamp should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("generated_at"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut mismatched_scenario_workload = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &mismatched_scenario_workload,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        mismatched_scenario_workload.daemon_runtime_dir = Some(runtime_dir.clone());
        mismatched_scenario_workload.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.workload.scenario_node_count += 1;
        })?;
        let error = match mismatched_scenario_workload.validate_success() {
            Ok(_) => {
                bail!("retained manifest with mismatched scenario workload should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("scenario workload"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut mismatched_readiness_timeout = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &mismatched_readiness_timeout,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        mismatched_readiness_timeout.daemon_runtime_dir = Some(runtime_dir.clone());
        mismatched_readiness_timeout.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.workload.daemon_http_readiness_timeout_seconds += 1;
        })?;
        let error = match mismatched_readiness_timeout.validate_success() {
            Ok(_) => {
                bail!("retained manifest with mismatched readiness timeout should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("readiness timeout"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut mismatched_child_roles = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &mismatched_child_roles,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        mismatched_child_roles.daemon_runtime_dir = Some(runtime_dir.clone());
        mismatched_child_roles.daemon_runtime_manifest = Some(manifest_path.clone());
        let relabeled_relay_log_path = runtime_dir.join("0003-agent.log");
        std::fs::rename(
            runtime_dir.join("0003-relay.log"),
            &relabeled_relay_log_path,
        )?;
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            if let Some(relay) = manifest
                .children
                .iter_mut()
                .find(|child| child.role == "relay")
            {
                relay.role = "agent".to_string();
                relay.redacted_argv = synthetic_child_redacted_argv("agent");
                relay.redacted_argv_sha256 = synthetic_child_redacted_argv_sha256("agent");
                relay.log_path = Some(relabeled_relay_log_path);
            }
        })?;
        let error = match mismatched_child_roles.validate_success() {
            Ok(_) => bail!("retained manifest with mismatched child roles should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("child role"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut missing_child_pid = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &missing_child_pid,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        missing_child_pid.daemon_runtime_dir = Some(runtime_dir.clone());
        missing_child_pid.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            if let Some(agent) = manifest
                .children
                .iter_mut()
                .find(|child| child.role == "agent")
            {
                agent.pid = None;
            }
        })?;
        let error = match missing_child_pid.validate_success() {
            Ok(_) => {
                bail!("retained manifest with missing exited child PID should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("missing a PID"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut invalid_child_pid = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &invalid_child_pid,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        invalid_child_pid.daemon_runtime_dir = Some(runtime_dir.clone());
        invalid_child_pid.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            if let Some(agent) = manifest
                .children
                .iter_mut()
                .find(|child| child.role == "agent")
            {
                agent.pid = Some(0);
            }
        })?;
        let error = match invalid_child_pid.validate_success() {
            Ok(_) => bail!("retained manifest with invalid child PID should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("invalid PID 0"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut duplicate_child_pid = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &duplicate_child_pid,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        duplicate_child_pid.daemon_runtime_dir = Some(runtime_dir.clone());
        duplicate_child_pid.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            let duplicate_pid = manifest.children[0].pid;
            if let Some(agent) = manifest
                .children
                .iter_mut()
                .find(|child| child.role == "agent")
            {
                agent.pid = duplicate_pid;
            }
        })?;
        let error = match duplicate_child_pid.validate_success() {
            Ok(_) => bail!("retained manifest with duplicate child PID should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("duplicates child"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut numeric_child_exit_code = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &numeric_child_exit_code,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        numeric_child_exit_code.daemon_runtime_dir = Some(runtime_dir.clone());
        numeric_child_exit_code.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            if let Some(agent) = manifest
                .children
                .iter_mut()
                .find(|child| child.role == "agent")
            {
                agent.exit_status = Some("exit status: 7".to_string());
                agent.exit_code = Some(7);
            }
        })?;
        let error = match numeric_child_exit_code.validate_success() {
            Ok(_) => bail!("retained manifest with numeric child exit code should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("numeric exit code"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut nonsignal_child_exit_status = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &nonsignal_child_exit_status,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        nonsignal_child_exit_status.daemon_runtime_dir = Some(runtime_dir.clone());
        nonsignal_child_exit_status.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            if let Some(agent) = manifest
                .children
                .iter_mut()
                .find(|child| child.role == "agent")
            {
                agent.exit_status = Some("exit status: 0".to_string());
                agent.exit_code = None;
            }
        })?;
        let error = match nonsignal_child_exit_status.validate_success() {
            Ok(_) => {
                bail!("retained manifest with non-signal child exit status should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("non-signal exit status"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut duplicated_manifest_endpoint = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &duplicated_manifest_endpoint,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        duplicated_manifest_endpoint.daemon_runtime_dir = Some(runtime_dir.clone());
        duplicated_manifest_endpoint.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            if let Some(control_plane_url) = manifest.control_plane_urls.first().cloned() {
                manifest.signal_url = control_plane_url;
            }
        })?;
        let error = match duplicated_manifest_endpoint.validate_success() {
            Ok(_) => {
                bail!("retained manifest with duplicate HTTP endpoints should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("duplicate HTTP endpoint"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut duplicated_manifest_udp_endpoint = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &duplicated_manifest_udp_endpoint,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        duplicated_manifest_udp_endpoint.daemon_runtime_dir = Some(runtime_dir.clone());
        duplicated_manifest_udp_endpoint.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.stun_alternate_addr = manifest.stun_addr;
        })?;
        let error = match duplicated_manifest_udp_endpoint.validate_success() {
            Ok(_) => {
                bail!("retained manifest with duplicate STUN UDP endpoints should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("duplicate UDP endpoint"));
        assert!(error.contains("STUN alternate address"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut unusable_manifest_socket = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &unusable_manifest_socket,
            DaemonRuntimePhase::Completed,
            &[
                "control-plane-0",
                "control-plane-1",
                "signal",
                "relay",
                "stun",
                "agent",
            ],
        )?;
        unusable_manifest_socket.daemon_runtime_dir = Some(runtime_dir.clone());
        unusable_manifest_socket.daemon_runtime_manifest = Some(manifest_path.clone());
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            manifest.relay_udp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        })?;
        let error = match unusable_manifest_socket.validate_success() {
            Ok(_) => {
                bail!("retained manifest with unusable relay UDP address should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("relay UDP address"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut incomplete_retained_manifest_fields = daemon_report.clone();
        incomplete_retained_manifest_fields.daemon_runtime_dir =
            Some(synthetic_runtime_dir("manifest-missing-path"));
        let error = match incomplete_retained_manifest_fields.validate_success() {
            Ok(_) => bail!("partial retained manifest fields should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("must be set together"));

        let mut incomplete_manifest = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &incomplete_manifest,
            DaemonRuntimePhase::StartupReady,
            &[],
        )?;
        incomplete_manifest.daemon_runtime_dir = Some(runtime_dir.clone());
        incomplete_manifest.daemon_runtime_manifest = Some(manifest_path);
        let error = match incomplete_manifest.validate_success() {
            Ok(_) => bail!("incomplete retained manifest should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("retained manifest ended"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut running_completed_manifest = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
            &running_completed_manifest,
            DaemonRuntimePhase::Completed,
            &["control-plane-0"],
        )?;
        running_completed_manifest.daemon_runtime_dir = Some(runtime_dir.clone());
        running_completed_manifest.daemon_runtime_manifest = Some(manifest_path);
        let error = match running_completed_manifest.validate_success() {
            Ok(_) => {
                bail!("completed retained manifest with running children should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("still has running child roles"));
        std::fs::remove_dir_all(&runtime_dir)?;

        let mut missing_failover = daemon_report.clone();
        missing_failover.daemon_control_plane_failover_checked = false;
        let error = match missing_failover.validate_success() {
            Ok(_) => bail!("daemon report without control-plane failover should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("failover"));

        let mut skewed_failover = daemon_report.clone();
        skewed_failover.daemon_control_plane_failover_peer_map_edges_min -= 1;
        let error = match skewed_failover.validate_success() {
            Ok(_) => bail!("daemon report with failover peer-map edge loss should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("failover peer-map"));

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

    async fn spawn_raw_http_response(
        response: String,
    ) -> anyhow::Result<(String, tokio::task::JoinHandle<anyhow::Result<()>>)> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener =
            tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream.write_all(response.as_bytes()).await?;
            Ok(())
        });
        Ok((format!("http://{addr}"), task))
    }

    #[tokio::test]
    async fn load_http_json_reader_rejects_oversized_responses() -> anyhow::Result<()> {
        let body = r#"{"ok":true}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let (url, server) = spawn_raw_http_response(response).await?;
        let value: serde_json::Value =
            get_json(&reqwest::Client::new(), url, "load JSON test").await?;
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .context("timed out waiting for small load JSON test server")???;
        assert_eq!(value["ok"], true);

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_LOAD_HTTP_JSON_RESPONSE_BYTES + 1
        );
        let (url, server) = spawn_raw_http_response(response).await?;
        let error =
            get_json::<serde_json::Value>(&reqwest::Client::new(), url, "load oversized JSON test")
                .await
                .expect_err("oversized load JSON response should be rejected");
        assert!(
            format!("{error:#}").contains("load oversized JSON test response exceeds maximum size")
        );
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .context("timed out waiting for oversized load JSON test server")???;

        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\n{\"ok\"\r\n5\r\n:true\r\n1\r\n}\r\n0\r\n\r\n"
            .to_string();
        let (url, server) = spawn_raw_http_response(response).await?;
        let response = reqwest::Client::new().get(url).send().await?;
        let error =
            read_bounded_json_response::<serde_json::Value>(response, "load chunked JSON test", 10)
                .await
                .expect_err("oversized chunked load JSON response should be rejected");
        assert!(error
            .to_string()
            .contains("load chunked JSON test response exceeds maximum size of 10 bytes"));
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .context("timed out waiting for oversized chunked load JSON test server")???;
        Ok(())
    }

    #[tokio::test]
    async fn load_http_text_reader_rejects_oversized_responses() -> anyhow::Result<()> {
        let body = "metric 1\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let (url, server) = spawn_raw_http_response(response).await?;
        let value = get_text(&reqwest::Client::new(), url, "load text test").await?;
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .context("timed out waiting for small load text test server")???;
        assert_eq!(value, body);

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_LOAD_HTTP_TEXT_RESPONSE_BYTES + 1
        );
        let (url, server) = spawn_raw_http_response(response).await?;
        let error = get_text(&reqwest::Client::new(), url, "load oversized text test")
            .await
            .expect_err("oversized load text response should be rejected");
        assert!(
            format!("{error:#}").contains("load oversized text test response exceeds maximum size")
        );
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .context("timed out waiting for oversized load text test server")???;
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
    fn daemon_role_counts_follow_launched_agent_prefix() {
        let ten = Scenario::from_name(ScenarioName::Ten);
        assert_eq!(daemon_relay_agent_count(ten, 1), 1);
        assert_eq!(daemon_relay_agent_count(ten, 2), 2);
        assert_eq!(daemon_relay_agent_count(ten, 4), 2);
        assert_eq!(daemon_route_provider_agent_count(ten, 1), 0);
        assert_eq!(daemon_route_provider_agent_count(ten, 2), 0);
        assert_eq!(daemon_route_provider_agent_count(ten, 3), 1);
        assert_eq!(daemon_route_provider_agent_count(ten, 4), 2);

        let thousand = Scenario::from_name(ScenarioName::Thousand);
        assert_eq!(daemon_relay_agent_count(thousand, 4), 4);
        assert_eq!(daemon_route_provider_agent_count(thousand, 4), 0);
    }

    #[test]
    fn daemon_advertised_route_count_deduplicates_peer_map_views() -> anyhow::Result<()> {
        let route_provider = NodeId::from_string("route-provider-a");
        let route = Route {
            id: "docker-0".to_string(),
            cidr: "10.128.0.0/24".parse()?,
            advertised_by: route_provider.clone(),
            via: Some(route_provider.clone()),
            metric: 100,
            tags: BTreeSet::new(),
        };
        let mut first_view = node_record_with_routes("peer-view-a", vec![route.clone()]);
        let second_view = node_record_with_routes("peer-view-b", vec![route.clone()]);
        assert_eq!(
            daemon_advertised_route_count(&[first_view.clone(), second_view]),
            1
        );

        first_view.routes.push(Route {
            id: "docker-1".to_string(),
            cidr: "10.128.1.0/24".parse()?,
            advertised_by: route_provider,
            via: None,
            metric: 100,
            tags: BTreeSet::new(),
        });
        assert_eq!(daemon_advertised_route_count(&[first_view]), 2);
        Ok(())
    }

    #[test]
    fn daemon_agent_status_summary_reports_candidate_ranges() -> anyhow::Result<()> {
        let first = agent_status_for_summary(0, 1);
        let second = agent_status_for_summary(1, 2);
        let summary = daemon_agent_status_summary(&[first.clone(), second])?;
        assert_eq!(summary.endpoint_count, 2);
        assert_eq!(summary.candidate_count_min, 1);
        assert_eq!(summary.candidate_count_max, 2);

        let error = match daemon_agent_status_summary(&[]) {
            Ok(_) => bail!("empty daemon agent status summary should fail"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("summary was empty"));

        let mut inconsistent = first;
        inconsistent.candidate_count += 1;
        let error = match daemon_agent_status_summary(&[inconsistent]) {
            Ok(_) => bail!("inconsistent daemon agent candidate count should fail"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("candidate_count"));
        Ok(())
    }

    #[test]
    fn daemon_control_plane_processes_reject_invalid_bounds() -> anyhow::Result<()> {
        let zero = match validate_daemon_control_plane_processes(0) {
            Ok(_) => bail!("zero daemon control-plane process count should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(zero.contains("--daemon-control-plane-processes"));

        let too_many =
            match validate_daemon_control_plane_processes(MAX_DAEMON_CONTROL_PLANE_PROCESSES + 1) {
                Ok(_) => {
                    bail!("oversized daemon control-plane process count should fail validation")
                }
                Err(error) => error.to_string(),
            };
        assert!(too_many.contains("cannot exceed"));

        assert_eq!(validate_daemon_control_plane_processes(2)?, 2);
        Ok(())
    }

    #[test]
    fn daemon_readiness_timeouts_reject_zero_seconds() -> anyhow::Result<()> {
        let zero_http =
            match daemon_timeout_from_seconds(0, "--daemon-http-readiness-timeout-seconds") {
                Ok(_) => bail!("zero daemon HTTP readiness timeout should fail validation"),
                Err(error) => error.to_string(),
            };
        assert!(zero_http.contains("--daemon-http-readiness-timeout-seconds"));

        let zero_agent = match validate_daemon_timeout(
            Duration::ZERO,
            "--daemon-agent-readiness-timeout-seconds",
        ) {
            Ok(_) => bail!("zero daemon agent readiness timeout should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(zero_agent.contains("--daemon-agent-readiness-timeout-seconds"));

        let oversized =
            match daemon_timeout_from_seconds(3_601, "--daemon-http-readiness-timeout-seconds") {
                Ok(_) => bail!("oversized daemon HTTP readiness timeout should fail validation"),
                Err(error) => error.to_string(),
            };
        assert!(oversized.contains("at most 3600 seconds"));

        assert_eq!(
            daemon_timeout_from_seconds(7, "--daemon-http-readiness-timeout-seconds")?,
            Duration::from_secs(7)
        );
        assert_eq!(
            validate_daemon_timeout(
                Duration::from_secs(11),
                "--daemon-agent-readiness-timeout-seconds"
            )?,
            Duration::from_secs(11)
        );
        Ok(())
    }

    #[test]
    fn daemon_control_plane_summary_reports_endpoint_ranges() -> anyhow::Result<()> {
        let consistent = ControlPlaneHealthSummary::from_metrics(&[
            control_plane_metrics(2, 6, 6, 3, 0, 0),
            control_plane_metrics(2, 6, 6, 3, 0, 0),
        ])?;
        assert_eq!(consistent.endpoint_count, 2);
        assert_eq!(consistent.relay_candidate_count_min, 2);
        assert_eq!(consistent.relay_candidate_count_max, 2);
        assert_eq!(consistent.path_count_min, 6);
        assert_eq!(consistent.path_count_max, 6);
        assert_eq!(consistent.reachable_path_count_min, 6);
        assert_eq!(consistent.reachable_path_count_max, 6);
        assert_eq!(consistent.healthy_node_count_min, 3);
        assert_eq!(consistent.healthy_node_count_max, 3);
        assert!(consistent.metrics_consistent());

        let skewed = ControlPlaneHealthSummary::from_metrics(&[
            control_plane_metrics(1, 4, 4, 2, 0, 0),
            control_plane_metrics(2, 6, 5, 3, 1, 0),
        ])?;
        assert_eq!(skewed.relay_candidate_count_min, 1);
        assert_eq!(skewed.relay_candidate_count_max, 2);
        assert_eq!(skewed.path_count_min, 4);
        assert_eq!(skewed.path_count_max, 6);
        assert_eq!(skewed.reachable_path_count_min, 4);
        assert_eq!(skewed.reachable_path_count_max, 5);
        assert_eq!(skewed.healthy_node_count_min, 2);
        assert_eq!(skewed.healthy_node_count_max, 3);
        assert_eq!(skewed.degraded_node_count_min, 0);
        assert_eq!(skewed.degraded_node_count_max, 1);
        assert!(!skewed.metrics_consistent());

        let empty = match ControlPlaneHealthSummary::from_metrics(&[]) {
            Ok(_) => bail!("empty control-plane metrics summary should fail"),
            Err(error) => error,
        };
        assert!(empty.to_string().contains("summary was empty"));
        Ok(())
    }

    #[test]
    fn daemon_peer_map_summary_reports_endpoint_ranges_and_consistency() -> anyhow::Result<()> {
        let first = daemon_peer_map_endpoint_summary(&[
            ("load-node-0000", "load-node-0001"),
            ("load-node-0001", "load-node-0000"),
        ]);
        let consistent =
            DaemonPeerMapSummary::from_endpoint_summaries(&[first.clone(), first.clone()])?;
        assert_eq!(consistent.endpoint_count, 2);
        assert_eq!(consistent.edge_count_min, 2);
        assert_eq!(consistent.edge_count_max, 2);
        assert!(consistent.maps_consistent);

        let different_edges = daemon_peer_map_endpoint_summary(&[
            ("load-node-0000", "load-node-0002"),
            ("load-node-0001", "load-node-0000"),
        ]);
        let skewed = DaemonPeerMapSummary::from_endpoint_summaries(&[
            first.clone(),
            different_edges,
            daemon_peer_map_endpoint_summary(&[("load-node-0000", "load-node-0001")]),
        ])?;
        assert_eq!(skewed.endpoint_count, 3);
        assert_eq!(skewed.edge_count_min, 1);
        assert_eq!(skewed.edge_count_max, 2);
        assert!(!skewed.maps_consistent);

        let empty = match DaemonPeerMapSummary::from_endpoint_summaries(&[]) {
            Ok(_) => bail!("empty control-plane peer-map summary should fail"),
            Err(error) => error,
        };
        assert!(empty.to_string().contains("summary was empty"));
        Ok(())
    }

    #[test]
    fn daemon_runtime_cleanup_policy_removes_or_retains_directory() -> anyhow::Result<()> {
        let cleanup_dir = synthetic_runtime_dir("cleanup");
        std::fs::create_dir_all(&cleanup_dir)?;
        std::fs::write(cleanup_dir.join("marker.log"), "cleanup")?;
        {
            let _group = synthetic_daemon_group(cleanup_dir.clone(), false);
        }
        assert!(!cleanup_dir.exists());

        let retained_dir = synthetic_runtime_dir("retained");
        std::fs::create_dir_all(&retained_dir)?;
        std::fs::write(retained_dir.join("marker.log"), "retain")?;
        {
            let _group = synthetic_daemon_group(retained_dir.clone(), true);
        }
        assert!(retained_dir.join("marker.log").exists());
        std::fs::remove_dir_all(&retained_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_control_plane_failover_stop_records_exit_and_survivors() -> anyhow::Result<()> {
        let runtime_dir = synthetic_runtime_dir("failover-stop");
        std::fs::create_dir_all(&runtime_dir)?;
        let mut group = synthetic_daemon_group(runtime_dir.clone(), false);
        group.control_plane_urls = vec![
            "http://127.0.0.1:31001".to_string(),
            "http://127.0.0.1:31002".to_string(),
        ];
        group.children.push(synthetic_sleep_child(
            "control-plane-0",
            runtime_dir.join("0000-control-plane-0.log"),
        )?);
        group.children.push(synthetic_sleep_child(
            "control-plane-1",
            runtime_dir.join("0001-control-plane-1.log"),
        )?);

        let (stopped_role, survivor_urls) = group.stop_control_plane_for_failover(0)?;

        assert_eq!(stopped_role, "control-plane-0");
        assert_eq!(survivor_urls, vec!["http://127.0.0.1:31002"]);
        assert!(group.children[0].last_exit.is_some());
        group.ensure_running_allowing_roles(
            DaemonRuntimePhase::ControlPlaneFailover,
            &[stopped_role.as_str()],
        )?;
        let error = match group.ensure_running(DaemonRuntimePhase::ControlPlaneFailover) {
            Ok(_) => bail!("normal daemon liveness should reject the stopped control-plane"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("control-plane-0"));
        Ok(())
    }

    #[test]
    fn daemon_completed_manifest_records_stopped_children_and_final_logs() -> anyhow::Result<()> {
        let runtime_dir = synthetic_runtime_dir("completed-stop");
        std::fs::create_dir_all(&runtime_dir)?;
        let mut group = synthetic_daemon_group(runtime_dir.clone(), true);
        group.agent_urls = vec!["http://127.0.0.1:31006".to_string()];
        group.children.push(synthetic_sleep_child(
            "agent",
            runtime_dir.join("0000-agent.log"),
        )?);

        let measurement = synthetic_manifest_measurement();
        let manifest_path = group.stop_all_for_completed_manifest(measurement)?;
        let contents = std::fs::read_to_string(&manifest_path)?;
        let manifest: DaemonRuntimeManifest = serde_json::from_str(&contents)?;

        assert_eq!(manifest.phase, DaemonRuntimePhase::Completed);
        assert_eq!(manifest.measurement, Some(measurement));
        assert_eq!(manifest.children.len(), 1);
        assert_eq!(manifest.children[0].role, "agent");
        assert_eq!(
            manifest.children[0].state,
            DaemonRuntimeManifestChildState::Exited
        );
        assert!(group.children[0].last_exit.is_some());
        let log_path = manifest.children[0]
            .log_path
            .as_ref()
            .context("completed manifest child log path missing")?;
        let diagnostics =
            daemon_log_diagnostics(log_path).context("completed manifest log missing")?;
        assert_eq!(manifest.children[0].log_bytes, Some(diagnostics.bytes));
        assert_eq!(
            manifest.children[0].log_tail_sha256.as_deref(),
            Some(diagnostics.tail_sha256.as_str())
        );
        drop(group);
        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_completed_manifest_scrubs_agent_state_before_retaining_runtime_dir(
    ) -> anyhow::Result<()> {
        let runtime_dir = synthetic_runtime_dir("completed-state-cleanup");
        std::fs::create_dir_all(&runtime_dir)?;
        let state_path = daemon_agent_state_path(&runtime_dir, 0);
        std::fs::write(&state_path, "{\"identity_private_key\":\"synthetic\"}\n")?;
        let mut group = synthetic_daemon_group(runtime_dir.clone(), true);
        group.agent_urls = vec!["http://127.0.0.1:31006".to_string()];
        group.agent_state_paths.push(state_path.clone());
        group.children.push(synthetic_sleep_child(
            "agent",
            runtime_dir.join("0000-agent.log"),
        )?);

        let manifest_path =
            group.stop_all_for_completed_manifest(synthetic_manifest_measurement())?;

        assert!(manifest_path.exists());
        assert!(!state_path.exists());
        drop(group);
        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_completed_manifest_secures_retained_runtime_files() -> anyhow::Result<()> {
        let runtime_dir = synthetic_runtime_dir("completed-retained-file-mode");
        std::fs::create_dir_all(&runtime_dir)?;
        let sqlite_path = runtime_dir.join("control-plane.sqlite");
        std::fs::write(&sqlite_path, "sqlite diagnostic")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sqlite_path, std::fs::Permissions::from_mode(0o644))?;
        }
        let mut group = synthetic_daemon_group(runtime_dir.clone(), true);
        group.agent_urls = vec!["http://127.0.0.1:31006".to_string()];
        group.children.push(synthetic_sleep_child(
            "agent",
            runtime_dir.join("0000-agent.log"),
        )?);

        let manifest_path =
            group.stop_all_for_completed_manifest(synthetic_manifest_measurement())?;

        assert!(manifest_path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let sqlite_mode = std::fs::metadata(&sqlite_path)?.permissions().mode() & 0o777;
            let log_mode = std::fs::metadata(runtime_dir.join("0000-agent.log"))?
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(sqlite_mode, 0o600);
            assert_eq!(log_mode, 0o600);
        }
        drop(group);
        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_completed_manifest_rejects_pre_shutdown_child_exit() -> anyhow::Result<()> {
        let runtime_dir = synthetic_runtime_dir("completed-pre-shutdown-exit");
        std::fs::create_dir_all(&runtime_dir)?;
        let mut group = synthetic_daemon_group(runtime_dir.clone(), true);
        group.agent_urls = vec!["http://127.0.0.1:31006".to_string()];
        let log_path = runtime_dir.join("0000-agent.log");
        std::fs::write(&log_path, "agent exited before shutdown\n")?;
        let mut child = Command::new("sh")
            .args(["-c", "exit 13"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn synthetic pre-shutdown child")?;
        let status = child
            .wait()
            .context("failed to wait for synthetic pre-shutdown child")?;
        assert_eq!(status.code(), Some(13));
        group.children.push(DaemonChild {
            role: "agent".to_string(),
            child,
            started_at: Utc::now(),
            redacted_argv: synthetic_child_redacted_argv("agent"),
            redacted_argv_sha256: synthetic_child_redacted_argv_sha256("agent"),
            log_path: Some(log_path),
            last_exit: None,
        });

        let error = match group.stop_all_for_completed_manifest(synthetic_manifest_measurement()) {
            Ok(_) => bail!("pre-shutdown child exit should fail completed manifest generation"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("exited before completed manifest shutdown"));
        assert!(error.contains("13"));
        assert_eq!(
            group.children[0]
                .last_exit
                .as_ref()
                .map(|exit| exit.status.as_str()),
            Some("exit status: 13")
        );
        assert_eq!(
            group.children[0]
                .last_exit
                .as_ref()
                .and_then(|exit| exit.code),
            Some(13)
        );
        drop(group);
        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_runtime_dir_is_owner_only() -> anyhow::Result<()> {
        let runtime_dir = synthetic_runtime_dir("secure-runtime");
        std::fs::create_dir_all(&runtime_dir)?;
        secure_daemon_runtime_dir(&runtime_dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&runtime_dir)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }

        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_stun_args_enable_rfc5780_alternate_listener() {
        let stun_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 34_780);
        let stun_alternate_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 34_781);
        let stun_http_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 34_782);

        let args = daemon_stun_args(stun_addr, stun_alternate_addr, stun_http_addr);

        assert_eq!(
            args,
            vec![
                "stun".to_string(),
                "--listen".to_string(),
                "127.0.0.1:34780".to_string(),
                "--alternate-listen".to_string(),
                "127.0.0.1:34781".to_string(),
                "--http-listen".to_string(),
                "127.0.0.1:34782".to_string(),
            ]
        );
    }

    #[test]
    fn daemon_startup_guard_cleanup_policy_removes_or_retains_failed_runtime_dir(
    ) -> anyhow::Result<()> {
        let cleanup_dir = synthetic_runtime_dir("startup-cleanup");
        std::fs::create_dir_all(&cleanup_dir)?;
        {
            let _guard = DaemonStartupGuard::new(cleanup_dir.clone(), false);
        }
        assert!(!cleanup_dir.exists());

        let retained_dir = synthetic_runtime_dir("startup-retained");
        std::fs::create_dir_all(&retained_dir)?;
        {
            let _guard = DaemonStartupGuard::new(retained_dir.clone(), true);
        }
        assert!(retained_dir.exists());
        std::fs::remove_dir_all(&retained_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_startup_guard_removes_join_tokens_before_retaining_runtime_dir() -> anyhow::Result<()>
    {
        let runtime_dir = synthetic_runtime_dir("startup-token-cleanup");
        std::fs::create_dir_all(&runtime_dir)?;
        let token_path = write_daemon_join_token(
            &runtime_dir,
            0,
            &serde_json::json!({ "token": "startup-secret" }),
        )?;
        {
            let mut guard = DaemonStartupGuard::new(runtime_dir.clone(), true);
            guard.record_join_token_path(token_path.clone());
        }

        assert!(runtime_dir.exists());
        assert!(!token_path.exists());
        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_startup_guard_removes_agent_state_before_retaining_runtime_dir() -> anyhow::Result<()>
    {
        let runtime_dir = synthetic_runtime_dir("startup-state-cleanup");
        std::fs::create_dir_all(&runtime_dir)?;
        let state_path = daemon_agent_state_path(&runtime_dir, 0);
        std::fs::write(
            &state_path,
            "{\"wireguard_private_key\":\"startup-secret\"}\n",
        )?;
        {
            let mut guard = DaemonStartupGuard::new(runtime_dir.clone(), true);
            guard.record_agent_state_path(state_path.clone());
        }

        assert!(runtime_dir.exists());
        assert!(!state_path.exists());
        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_join_token_removal_ignores_already_removed_files() -> anyhow::Result<()> {
        let runtime_dir = synthetic_runtime_dir("token-removal");
        std::fs::create_dir_all(&runtime_dir)?;
        let token_path = daemon_join_token_path(&runtime_dir, 0);
        let mut paths = vec![token_path];

        remove_daemon_join_token_files(&runtime_dir, &mut paths)?;

        assert!(paths.is_empty());
        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_agent_state_removal_ignores_already_removed_files() -> anyhow::Result<()> {
        let runtime_dir = synthetic_runtime_dir("state-removal");
        std::fs::create_dir_all(&runtime_dir)?;
        let state_path = daemon_agent_state_path(&runtime_dir, 0);
        let mut paths = vec![state_path];

        remove_daemon_agent_state_files(&runtime_dir, &mut paths)?;

        assert!(paths.is_empty());
        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_runtime_secret_cleanup_rejects_paths_outside_runtime_dir() -> anyhow::Result<()> {
        let runtime_dir = synthetic_runtime_dir("token-cleanup-runtime");
        let outside_dir = synthetic_runtime_dir("token-cleanup-outside");
        std::fs::create_dir_all(&runtime_dir)?;
        std::fs::create_dir_all(&outside_dir)?;
        let outside_token_path = outside_dir.join("agent-0000.join-token.json");
        std::fs::write(&outside_token_path, "{\"token\":\"outside\"}\n")?;
        let mut paths = vec![outside_token_path.clone()];

        let error = match remove_daemon_join_token_files(&runtime_dir, &mut paths) {
            Ok(_) => bail!("outside join token cleanup path should fail validation"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("outside runtime directory"));
        assert!(outside_token_path.exists());
        assert_eq!(paths, vec![outside_token_path]);
        std::fs::remove_dir_all(&runtime_dir)?;
        std::fs::remove_dir_all(&outside_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_runtime_secret_cleanup_rejects_unexpected_suffix() -> anyhow::Result<()> {
        let runtime_dir = synthetic_runtime_dir("token-cleanup-suffix");
        std::fs::create_dir_all(&runtime_dir)?;
        let wrong_path = runtime_dir.join("agent-0000.state.json");
        std::fs::write(&wrong_path, "{\"identity_private_key\":\"still-secret\"}\n")?;
        let mut paths = vec![wrong_path.clone()];

        let error = match remove_daemon_join_token_files(&runtime_dir, &mut paths) {
            Ok(_) => bail!("unexpected join token cleanup suffix should fail validation"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("unexpected file name"));
        assert!(wrong_path.exists());
        assert_eq!(paths, vec![wrong_path]);
        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_runtime_manifest_writer_records_diagnostics_without_token_paths() -> anyhow::Result<()>
    {
        let runtime_dir = synthetic_runtime_dir("manifest");
        std::fs::create_dir_all(&runtime_dir)?;
        let log_path = runtime_dir.join("0000-control-plane-0.log");
        std::fs::write(&log_path, "control-plane diagnostic\n")?;
        let manifest = synthetic_manifest(runtime_dir.clone(), log_path.clone());
        let stale_manifest_path = daemon_runtime_manifest_path(&runtime_dir);
        std::fs::write(&stale_manifest_path, "stale manifest")?;

        let manifest_path = write_daemon_runtime_manifest(&runtime_dir, manifest.clone())?;
        assert_eq!(manifest_path, stale_manifest_path);
        assert_eq!(
            manifest_path.file_name().and_then(|name| name.to_str()),
            Some(DAEMON_RUNTIME_MANIFEST_FILE)
        );
        let contents = std::fs::read_to_string(&manifest_path)?;
        assert!(contents.contains("control-plane-0"));
        assert!(contents.contains("127.0.0.1:31001"));
        assert!(!contents.contains("stale manifest"));
        assert!(!contents.contains("join-token"));
        let stale_temp_manifest_count = std::fs::read_dir(&runtime_dir)?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(is_daemon_runtime_manifest_temp_name)
            })
            .count();
        assert_eq!(stale_temp_manifest_count, 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&manifest_path)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let decoded: DaemonRuntimeManifest = serde_json::from_str(&contents)?;
        assert_eq!(decoded.scenario, manifest.scenario);
        assert_eq!(decoded.phase, DaemonRuntimePhase::StartupReady);
        assert_eq!(decoded.workload, manifest.workload);
        assert_eq!(decoded.measurement, None);
        assert_eq!(decoded.runtime_dir, runtime_dir);
        assert_eq!(decoded.started_at, manifest.started_at);
        assert_eq!(decoded.updated_at, manifest.updated_at);
        assert_eq!(decoded.generated_at, manifest.updated_at);
        assert_eq!(decoded.children.len(), 1);
        assert_eq!(decoded.children[0].role, "control-plane-0");
        assert_eq!(decoded.children[0].pid, Some(4242));
        assert_eq!(
            decoded.children[0].redacted_argv,
            synthetic_child_redacted_argv("control-plane-0")
        );
        assert_eq!(
            decoded.children[0].redacted_argv_sha256,
            synthetic_child_redacted_argv_sha256("control-plane-0")
        );
        assert_eq!(decoded.children[0].log_path.as_ref(), Some(&log_path));
        assert_eq!(
            decoded.children[0].log_bytes,
            Some("control-plane diagnostic\n".len() as u64)
        );
        assert_eq!(
            decoded.children[0].log_tail_sha256.as_deref(),
            daemon_log_diagnostics(&log_path)
                .as_ref()
                .map(|diagnostics| diagnostics.tail_sha256.as_str())
        );
        assert_eq!(
            decoded.children[0].state,
            DaemonRuntimeManifestChildState::Running
        );
        assert_eq!(decoded.children[0].exit_status, None);
        assert_eq!(decoded.children[0].exit_code, None);

        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_runtime_manifest_seed_updates_partial_startup_state() -> anyhow::Result<()> {
        let runtime_dir = synthetic_runtime_dir("manifest-seed");
        std::fs::create_dir_all(&runtime_dir)?;
        let seed = synthetic_manifest_seed(runtime_dir.clone());

        let manifest_path = seed.write(DaemonRuntimePhase::ReservedEndpoints, &[], &[])?;
        let initial: DaemonRuntimeManifest =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
        assert_eq!(initial.phase, DaemonRuntimePhase::ReservedEndpoints);
        assert_eq!(initial.workload, seed.workload);
        assert_eq!(initial.measurement, None);
        assert_eq!(initial.started_at, seed.started_at);
        assert!(initial.updated_at >= initial.started_at);
        assert_eq!(initial.generated_at, initial.updated_at);
        assert!(initial.agent_urls.is_empty());
        assert!(initial.children.is_empty());

        let log_path = runtime_dir.join("0001-signal.log");
        std::fs::write(&log_path, "signal log\n")?;
        let child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn synthetic daemon child for manifest seed test")?;
        let pid = child.id();
        let mut children = vec![DaemonChild {
            role: "signal".to_string(),
            child,
            started_at: Utc::now(),
            redacted_argv: synthetic_child_redacted_argv("signal"),
            redacted_argv_sha256: synthetic_child_redacted_argv_sha256("signal"),
            log_path: Some(log_path.clone()),
            last_exit: None,
        }];

        let agent_urls = vec!["http://127.0.0.1:31006".to_string()];
        seed.write(
            DaemonRuntimePhase::SignalNegotiation,
            &agent_urls,
            &children,
        )?;
        let updated: DaemonRuntimeManifest =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
        assert_eq!(updated.phase, DaemonRuntimePhase::SignalNegotiation);
        assert_eq!(updated.workload, seed.workload);
        assert_eq!(updated.measurement, None);
        assert_eq!(updated.started_at, seed.started_at);
        assert!(updated.updated_at >= initial.updated_at);
        assert_eq!(updated.generated_at, updated.updated_at);
        assert_eq!(updated.agent_urls, agent_urls);
        assert_eq!(updated.children.len(), 1);
        assert_eq!(updated.children[0].role, "signal");
        assert_eq!(updated.children[0].pid, Some(pid));
        assert_eq!(
            updated.children[0].redacted_argv,
            synthetic_child_redacted_argv("signal")
        );
        assert_eq!(
            updated.children[0].redacted_argv_sha256,
            synthetic_child_redacted_argv_sha256("signal")
        );
        assert_eq!(updated.children[0].log_path.as_ref(), Some(&log_path));
        assert_eq!(
            updated.children[0].log_bytes,
            Some("signal log\n".len() as u64)
        );
        assert_eq!(
            updated.children[0].log_tail_sha256.as_deref(),
            daemon_log_diagnostics(&log_path)
                .as_ref()
                .map(|diagnostics| diagnostics.tail_sha256.as_str())
        );
        assert_eq!(
            updated.children[0].state,
            DaemonRuntimeManifestChildState::Running
        );
        assert_eq!(updated.children[0].exit_status, None);
        assert_eq!(updated.children[0].exit_code, None);

        let _ = children[0].child.kill();
        let _ = children[0].child.wait();
        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_startup_failure_manifest_records_phase_and_exited_child() -> anyhow::Result<()> {
        let runtime_dir = synthetic_runtime_dir("manifest-startup-failure");
        std::fs::create_dir_all(&runtime_dir)?;
        let seed = synthetic_manifest_seed(runtime_dir.clone());
        let log_path = runtime_dir.join("0002-agent.log");
        std::fs::write(&log_path, "agent exited during readiness\n")?;
        let child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn synthetic daemon child for startup failure manifest test")?;
        let pid = child.id();
        let mut children = vec![DaemonChild {
            role: "agent".to_string(),
            child,
            started_at: Utc::now(),
            redacted_argv: synthetic_child_redacted_argv("agent"),
            redacted_argv_sha256: synthetic_child_redacted_argv_sha256("agent"),
            log_path: Some(log_path.clone()),
            last_exit: Some(DaemonChildExit {
                status: "exit status: 11".to_string(),
                code: Some(11),
                exited_at: Utc::now(),
            }),
        }];
        let agent_urls = vec!["http://127.0.0.1:31006".to_string()];

        let manifest_path = write_daemon_manifest_after_startup_failure(
            &seed,
            DaemonRuntimePhase::StartupReadiness,
            &agent_urls,
            &children,
        )?;
        let decoded: DaemonRuntimeManifest =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
        assert_eq!(decoded.phase, DaemonRuntimePhase::StartupReadiness);
        assert_eq!(decoded.workload, seed.workload);
        assert_eq!(decoded.started_at, seed.started_at);
        assert!(decoded.updated_at >= decoded.started_at);
        assert_eq!(decoded.agent_urls, agent_urls);
        assert_eq!(decoded.children.len(), 1);
        assert_eq!(decoded.children[0].role, "agent");
        assert_eq!(decoded.children[0].pid, Some(pid));
        assert_eq!(
            decoded.children[0].redacted_argv,
            synthetic_child_redacted_argv("agent")
        );
        assert_eq!(
            decoded.children[0].redacted_argv_sha256,
            synthetic_child_redacted_argv_sha256("agent")
        );
        assert_eq!(decoded.children[0].log_path.as_ref(), Some(&log_path));
        assert_eq!(
            decoded.children[0].log_bytes,
            Some("agent exited during readiness\n".len() as u64)
        );
        assert_eq!(
            decoded.children[0].log_tail_sha256.as_deref(),
            daemon_log_diagnostics(&log_path)
                .as_ref()
                .map(|diagnostics| diagnostics.tail_sha256.as_str())
        );
        assert_eq!(
            decoded.children[0].state,
            DaemonRuntimeManifestChildState::Exited
        );
        assert_eq!(
            decoded.children[0].exit_status.as_deref(),
            Some("exit status: 11")
        );
        assert_eq!(decoded.children[0].exit_code, Some(11));

        let _ = children[0].child.kill();
        let _ = children[0].child.wait();
        std::fs::remove_dir_all(&runtime_dir)?;
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

    #[test]
    fn daemon_join_claims_include_runtime_control_plane_bootstrap_urls() -> anyhow::Result<()> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("load-key");
        let cluster_id = ClusterId::from_string("load-daemon-bootstrap");
        let urls = vec![
            "http://127.0.0.1:31001".to_string(),
            "http://127.0.0.1:31002".to_string(),
        ];

        let claims = join_claims_with_control_plane_urls(
            &cluster_id,
            &issuer.node_id(),
            &key_id,
            0,
            Scenario::from_name(ScenarioName::Three),
            &urls,
        )?;

        let claim_urls = claims
            .bootstrap_endpoints
            .iter()
            .map(|endpoint| endpoint.url.clone())
            .collect::<Vec<_>>();
        assert_eq!(claim_urls, urls);
        assert!(claims
            .bootstrap_endpoints
            .iter()
            .all(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane));
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
            let heartbeat = heartbeat_request(index, &response.node)?;
            let _: HeartbeatResponse = post_json(
                &client,
                format!("{}/v1/heartbeat", services.control_plane_url),
                &heartbeat,
                "readiness control-plane heartbeat",
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
                userspace_wireguard_process: None,
                state_updated_at: Utc::now(),
            });
        }

        check_daemon_agent_control_and_signal_readiness(
            &client,
            std::slice::from_ref(&services.control_plane_url),
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
            started_at: Utc::now(),
            redacted_argv: synthetic_child_redacted_argv("synthetic"),
            redacted_argv_sha256: synthetic_child_redacted_argv_sha256("synthetic"),
            log_path: Some(log_path.clone()),
            last_exit: None,
        }];

        for _ in 0..50 {
            match ensure_daemon_children_running(&mut children) {
                Ok(()) => std::thread::sleep(Duration::from_millis(10)),
                Err(error) => {
                    let message = error.to_string();
                    assert!(message.contains("iparsd synthetic process exited"));
                    assert!(message.contains("7"));
                    assert!(message.contains("child diagnostic line"));
                    assert_eq!(
                        children[0]
                            .last_exit
                            .as_ref()
                            .map(|exit| exit.status.as_str()),
                        Some("exit status: 7")
                    );
                    assert_eq!(
                        children[0].last_exit.as_ref().and_then(|exit| exit.code),
                        Some(7)
                    );
                    let manifest_child = DaemonRuntimeManifestChild::from_child(&children[0]);
                    assert_eq!(
                        manifest_child.state,
                        DaemonRuntimeManifestChildState::Exited
                    );
                    assert_eq!(
                        manifest_child.exit_status.as_deref(),
                        Some("exit status: 7")
                    );
                    assert_eq!(manifest_child.exit_code, Some(7));
                    assert_eq!(
                        manifest_child.log_bytes,
                        Some("first line\nchild diagnostic line\n".len() as u64)
                    );
                    assert_eq!(
                        manifest_child.log_tail_sha256.as_deref(),
                        daemon_log_diagnostics(&log_path)
                            .as_ref()
                            .map(|diagnostics| diagnostics.tail_sha256.as_str())
                    );
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
    fn daemon_spawned_child_log_is_owner_only_and_sanitized() -> anyhow::Result<()> {
        let runtime_dir = synthetic_runtime_dir("private-log");
        std::fs::create_dir_all(&runtime_dir)?;
        let env_status_path = runtime_dir.join("env.status");
        let env_status_arg = env_status_path.display().to_string();
        let shell_script = r#"
if test "${PATH:-}" = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" &&
   test "${LANG:-}" = "C" &&
   test "${LC_ALL:-}" = "C" &&
   test -z "${HOME+x}" &&
   test -z "${IPARS_ISSUER_PRIVATE_KEY+x}" &&
   test -z "${IPARS_ISSUER_PRIVATE_KEY_PATH+x}" &&
   test -z "${LD_PRELOAD+x}"; then
    printf 'ok\n' > "$1"
else
    {
        printf 'PATH=%s\n' "${PATH-<unset>}"
        printf 'LANG=%s\n' "${LANG-<unset>}"
        printf 'LC_ALL=%s\n' "${LC_ALL-<unset>}"
        printf 'HOME=%s\n' "${HOME-<unset>}"
        printf 'IPARS_ISSUER_PRIVATE_KEY=%s\n' "${IPARS_ISSUER_PRIVATE_KEY-<unset>}"
        printf 'IPARS_ISSUER_PRIVATE_KEY_PATH=%s\n' "${IPARS_ISSUER_PRIVATE_KEY_PATH-<unset>}"
        printf 'LD_PRELOAD=%s\n' "${LD_PRELOAD-<unset>}"
    } > "$1"
    exit 1
fi
"#;
        let mut child = spawn_iparsd(
            Path::new("sh"),
            &[
                "-c".to_string(),
                shell_script.to_string(),
                "ipars-load-env".to_string(),
                env_status_arg,
            ],
            "agent/with spaces",
            &runtime_dir,
        )?;
        let status = child
            .child
            .wait()
            .context("failed to wait for sanitized daemon child")?;
        let env_status = std::fs::read_to_string(&env_status_path)
            .with_context(|| format!("failed to read {}", env_status_path.display()))?;
        assert!(
            status.success(),
            "daemon child inherited unexpected environment:\n{env_status}"
        );
        assert_eq!(env_status.trim(), "ok");
        let log_path = child
            .log_path
            .clone()
            .context("spawned daemon child did not record a log path")?;

        assert!(log_path.starts_with(&runtime_dir));
        assert!(log_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.contains("agent_with_spaces")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&log_path)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_command_redaction_covers_secret_like_arguments() -> anyhow::Result<()> {
        let argv = redacted_daemon_argv(
            Path::new("/opt/ipars/bin/iparsd"),
            &[
                "agent".to_string(),
                "--join-token".to_string(),
                "signed-token-material".to_string(),
                "--database-url=postgres://user:password@example.internal/ipars".to_string(),
                "--relay-admission-bearer-token".to_string(),
                "relay-secret".to_string(),
                "--issuer-public-key".to_string(),
                "public-key-material".to_string(),
            ],
        );

        assert!(argv.contains(&DAEMON_REDACTED_ARG.to_string()));
        assert!(argv.contains(&format!("--database-url={DAEMON_REDACTED_ARG}")));
        assert!(!argv
            .iter()
            .any(|argument| argument.contains("signed-token")));
        assert!(!argv.iter().any(|argument| argument.contains("password")));
        assert!(!argv
            .iter()
            .any(|argument| argument.contains("relay-secret")));
        assert!(argv
            .iter()
            .any(|argument| argument == "public-key-material"));
        let child = DaemonRuntimeManifestChild {
            role: "agent".to_string(),
            pid: Some(42),
            started_at: Utc::now(),
            exited_at: None,
            runtime_ms: None,
            redacted_argv_sha256: daemon_argv_sha256(&argv),
            redacted_argv: argv,
            log_path: None,
            log_bytes: None,
            log_tail_sha256: None,
            state: DaemonRuntimeManifestChildState::Running,
            exit_status: None,
            exit_code: None,
        };
        validate_daemon_manifest_child_command(&child, Path::new("/opt/ipars/bin/iparsd"))?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn daemon_binary_identity_records_canonical_symlink_target() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let runtime_dir = synthetic_runtime_dir("binary-symlink");
        std::fs::create_dir_all(&runtime_dir)?;
        let target_path = runtime_dir.join("iparsd-target");
        let mut target_file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .private_on_unix()
            .open(&target_path)?;
        target_file.write_all(b"#!/bin/sh\nexit 0\n")?;
        target_file.sync_all()?;
        drop(target_file);
        std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(0o700))?;
        let symlink_path = runtime_dir.join("iparsd-link");
        std::os::unix::fs::symlink(&target_path, &symlink_path)?;

        let identity = daemon_binary_identity(&symlink_path)?;

        assert_eq!(identity.path, target_path.canonicalize()?);
        assert_eq!(identity.bytes, "#!/bin/sh\nexit 0\n".len() as u64);
        assert_eq!(identity.sha256.len(), 64);
        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
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
        let metadata = std::fs::symlink_metadata(&token_path)?;
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());
        validate_daemon_join_token_file(&runtime_dir, &token_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&token_path)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        std::fs::remove_dir_all(&runtime_dir)?;
        Ok(())
    }

    #[test]
    fn daemon_join_token_file_validation_rejects_unsafe_paths() -> anyhow::Result<()> {
        let runtime_dir = synthetic_runtime_dir("token-validation");
        std::fs::create_dir_all(&runtime_dir)?;

        let directory_token_path = runtime_dir.join("agent-0000.join-token.json");
        std::fs::create_dir_all(&directory_token_path)?;
        let error = match validate_daemon_join_token_file(&runtime_dir, &directory_token_path) {
            Ok(_) => bail!("directory join token path should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("regular file"));
        std::fs::remove_dir_all(&directory_token_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let world_readable_token_path = runtime_dir.join("agent-0001.join-token.json");
            std::fs::write(&world_readable_token_path, "{}\n")?;
            std::fs::set_permissions(
                &world_readable_token_path,
                std::fs::Permissions::from_mode(0o644),
            )?;
            let error =
                match validate_daemon_join_token_file(&runtime_dir, &world_readable_token_path) {
                    Ok(_) => bail!("world-readable join token path should fail validation"),
                    Err(error) => error.to_string(),
                };
            assert!(error.contains("permissions"));
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
            DaemonLoadOptions {
                control_plane_processes: 2,
                agent_processes: 2,
                keep_runtime_dir: true,
                http_readiness_timeout: Duration::from_secs(5),
                agent_readiness_timeout: Duration::from_secs(15),
                relay_options: RelayLoadOptions {
                    packets_per_session: 1,
                    payload_bytes: 64,
                },
            },
        )
        .await?;

        assert_eq!(report.transport, TransportMode::Daemon);
        assert_eq!(report.daemon_control_plane_processes, 2);
        assert_eq!(report.daemon_control_plane_metrics_endpoints, 2);
        assert_eq!(report.daemon_agent_processes, 2);
        assert_eq!(report.daemon_agent_status_endpoints, 2);
        assert!(report.daemon_agent_candidate_count_min > 0);
        assert!(report.daemon_agent_candidate_count_max >= report.daemon_agent_candidate_count_min);
        assert_eq!(report.relay_count, 1);
        assert_eq!(report.route_provider_count, 1);
        assert_eq!(report.advertised_routes, 1);
        assert_eq!(report.registrations, 2);
        assert_eq!(report.peer_map_requests, 6);
        assert_eq!(report.peer_map_edges_seen, 2);
        assert_eq!(report.daemon_processes, 7);
        let runtime_dir = report
            .daemon_runtime_dir
            .clone()
            .context("daemon transport report did not retain runtime dir")?;
        let manifest_path = report
            .daemon_runtime_manifest
            .clone()
            .context("daemon transport report did not retain runtime manifest")?;
        assert_eq!(manifest_path, daemon_runtime_manifest_path(&runtime_dir));
        let manifest: DaemonRuntimeManifest =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
        assert_eq!(manifest.phase, DaemonRuntimePhase::Completed);
        let manifest_measurement = manifest
            .measurement
            .context("daemon completed manifest did not record measurement summary")?;
        assert_eq!(
            manifest_measurement.failover_relay_udp_packets_received,
            report.active_pair_count
        );
        assert_eq!(
            manifest_measurement.failover_relay_udp_payload_bytes_received,
            report.daemon_failover_relay_udp_payload_bytes_received
        );
        assert_eq!(manifest.children.len(), report.daemon_processes);
        assert!(manifest
            .children
            .iter()
            .all(|child| child.state == DaemonRuntimeManifestChildState::Exited));
        assert_eq!(report.daemon_control_plane_peer_map_endpoints, 2);
        assert_eq!(report.daemon_control_plane_peer_map_edges_min, 2);
        assert_eq!(report.daemon_control_plane_peer_map_edges_max, 2);
        assert!(report.daemon_control_plane_peer_maps_consistent);
        assert!(report.daemon_control_plane_failover_checked);
        assert_eq!(report.daemon_control_plane_failover_survivor_endpoints, 1);
        assert_eq!(report.daemon_agent_failover_status_endpoints, 2);
        assert!(report.daemon_agent_failover_candidate_count_min > 0);
        assert!(
            report.daemon_agent_failover_candidate_count_max
                >= report.daemon_agent_failover_candidate_count_min
        );
        assert_eq!(report.daemon_agent_failover_path_status_endpoints, 2);
        assert!(report.daemon_agent_failover_paths_total >= 2);
        assert!(report.daemon_agent_failover_reachable_paths_total >= 2);
        assert!(
            report.daemon_agent_failover_path_count_max
                >= report.daemon_agent_failover_path_count_min
        );
        assert_eq!(report.daemon_control_plane_failover_peer_map_edges_min, 2);
        assert_eq!(report.daemon_control_plane_failover_peer_map_edges_max, 2);
        assert!(report.daemon_control_plane_failover_peer_maps_consistent);
        assert_eq!(report.daemon_control_plane_failover_metrics_endpoints, 1);
        assert!(report.daemon_control_plane_failover_metrics_consistent);
        assert_eq!(report.daemon_control_plane_failover_relay_candidates_min, 1);
        assert_eq!(report.daemon_control_plane_failover_relay_candidates_max, 1);
        assert!(report.daemon_control_plane_failover_path_count_min >= 2);
        assert!(report.daemon_control_plane_failover_reachable_path_count_min >= 2);
        assert_eq!(report.daemon_control_plane_failover_path_status_requests, 2);
        assert!(report.daemon_control_plane_failover_path_status_count_min >= 2);
        assert!(report.daemon_control_plane_failover_path_status_reachable_count_min >= 2);
        assert_eq!(
            report.daemon_control_plane_failover_path_status_stale_count_max,
            0
        );
        assert!(report.daemon_control_plane_failover_healthy_nodes_min >= 2);
        assert_eq!(
            report.daemon_control_plane_failover_healthy_nodes_min,
            report.daemon_control_plane_failover_healthy_nodes_max
        );
        assert_eq!(report.daemon_control_plane_failover_degraded_nodes_max, 0);
        assert_eq!(report.daemon_control_plane_failover_unhealthy_nodes_max, 0);
        assert_eq!(report.daemon_control_plane_relay_candidates_min, 1);
        assert_eq!(report.daemon_control_plane_relay_candidates_max, 1);
        assert!(report.daemon_control_plane_healthy_nodes >= 2);
        assert_eq!(
            report.daemon_control_plane_healthy_nodes_min,
            report.daemon_control_plane_healthy_nodes
        );
        assert_eq!(
            report.daemon_control_plane_healthy_nodes_max,
            report.daemon_control_plane_healthy_nodes
        );
        assert_eq!(report.daemon_control_plane_degraded_nodes, 0);
        assert_eq!(report.daemon_control_plane_degraded_nodes_min, 0);
        assert_eq!(report.daemon_control_plane_degraded_nodes_max, 0);
        assert_eq!(report.daemon_control_plane_unhealthy_nodes, 0);
        assert_eq!(report.daemon_control_plane_unhealthy_nodes_min, 0);
        assert_eq!(report.daemon_control_plane_unhealthy_nodes_max, 0);
        assert!(report.daemon_control_plane_metrics_consistent);
        assert!(report.daemon_signal_health_reports >= 2);
        assert!(report.daemon_signal_healthy_nodes >= 2);
        assert_eq!(report.daemon_signal_degraded_nodes, 0);
        assert_eq!(report.daemon_signal_unhealthy_nodes, 0);
        assert_eq!(report.stun_http_requests, 2);
        assert_eq!(report.daemon_stun.metrics_endpoints, 1);
        assert!(report.daemon_stun.listen_matches_expected);
        assert!(report.daemon_stun.alternate_listen_matches_expected);
        assert!(report.daemon_stun.prometheus_alternate_listener_reported);
        assert!(report.daemon_stun.binding_requests_reported >= report.node_count as u64);
        assert!(report.daemon_stun.binding_responses_reported >= report.node_count as u64);
        assert_eq!(report.daemon_stun.invalid_packets_reported, 0);
        assert_eq!(report.daemon_stun.socket_receive_errors_reported, 0);
        assert_eq!(report.daemon_stun.socket_send_errors_reported, 0);
        assert_eq!(report.relay_udp_packets_sent, report.active_pair_count);
        assert_eq!(report.relay_udp_packets_received, report.active_pair_count);
        assert_eq!(
            report.daemon_failover_relay_udp_packets_sent,
            report.active_pair_count
        );
        assert_eq!(
            report.daemon_failover_relay_udp_packets_received,
            report.active_pair_count
        );
        assert_eq!(
            report.daemon_failover_relay_udp_payload_bytes_sent,
            report.daemon_failover_relay_udp_payload_bytes_received
        );
        assert_eq!(
            report.relay_active_sessions_reported,
            report.active_pair_count
        );
        assert_eq!(report.relay_available_sessions_reported, 9_994);
        assert_eq!(report.relay_max_sessions_reported, 10_000);
        assert_eq!(report.relay_max_mbps_reported, 10_000);
        assert!(report.relay_enabled_by_policy_reported);
        assert!(report.relay_e2e_only_reported);
        assert_eq!(
            report.relay_admission_attempts_reported,
            report.active_pair_count as u64
        );
        assert_eq!(
            report.relay_admission_successes_reported,
            report.active_pair_count as u64
        );
        assert_eq!(report.relay_admission_failures_reported, 0);
        assert_zero_filled_relay_admission_failure_reasons(&report);
        report.validate_success()?;
        std::fs::remove_dir_all(runtime_dir)?;
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

    #[test]
    fn daemon_agent_path_expectation_caps_wrapped_active_pairs() {
        assert_eq!(expected_daemon_agent_path_count(30, 4), 12);
        assert_eq!(expected_daemon_agent_path_count(6, 3), 6);
        assert_eq!(expected_daemon_agent_path_count(30, 1), 0);
    }

    #[test]
    fn daemon_agent_activity_pairs_deduplicate_wrapped_pairs() {
        let statuses = (0..4)
            .map(|index| agent_status_for_summary(index, 1))
            .collect::<Vec<_>>();

        let pairs = daemon_agent_activity_pairs(&statuses, 30);

        assert_eq!(pairs.len(), 12);
        assert_eq!(pairs.iter().collect::<BTreeSet<_>>().len(), pairs.len());
        assert!(!pairs
            .iter()
            .any(|(source, target)| statuses[*source].node_id == *target));
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

    async fn valid_daemon_report_for_validation() -> anyhow::Result<LoadReport> {
        let mut report = run_in_memory_scenario(Scenario::from_name(ScenarioName::Three)).await?;
        let expected_peer_edges = report.node_count * report.node_count.saturating_sub(1);
        report.transport = TransportMode::Daemon;
        report.peer_map_requests = report.node_count * 3;
        report.direct_public_paths = 0;
        report.direct_ipv6_paths = 0;
        report.direct_nat_paths = report.active_pair_count;
        report.relay_paths = 0;
        report.unreachable_paths = 0;
        report.relay_packets_per_session = 1;
        report.relay_udp_packets_sent = report.active_pair_count;
        report.relay_udp_packets_received = report.active_pair_count;
        report.relay_udp_payload_bytes_sent = report.active_pair_count as u64 * 64;
        report.relay_udp_payload_bytes_received = report.relay_udp_payload_bytes_sent;
        report.daemon_failover_relay_udp_packets_sent = report.active_pair_count;
        report.daemon_failover_relay_udp_packets_received = report.active_pair_count;
        report.daemon_failover_relay_udp_payload_bytes_sent = report.active_pair_count as u64 * 64;
        report.daemon_failover_relay_udp_payload_bytes_received =
            report.daemon_failover_relay_udp_payload_bytes_sent;
        report.relay_dataplane_datagrams_received_reported =
            report.relay_udp_packets_received as u64 + 1;
        report.relay_dataplane_datagrams_forwarded_reported =
            report.relay_udp_packets_received as u64;
        report.relay_dataplane_datagrams_dropped_reported = 1;
        report.relay_dataplane_invalid_session_credential_drops_reported = 1;
        report.relay_dataplane_invalid_session_credential_drops_prometheus_reported = 1;
        report.relay_forwarded_bytes_reported = report.relay_udp_payload_bytes_received;
        report.relay_udp_sessions = report.active_pair_count;
        report.relay_active_sessions_reported = report.active_pair_count;
        report.relay_max_sessions_reported = 10_000;
        report.relay_available_sessions_reported =
            report.relay_max_sessions_reported - report.relay_active_sessions_reported;
        report.relay_max_mbps_reported = 10_000;
        report.relay_enabled_by_policy_reported = true;
        report.relay_e2e_only_reported = true;
        report.relay_admission_attempts_reported = report.active_pair_count as u64;
        report.relay_admission_successes_reported = report.active_pair_count as u64;
        report.stun_http_requests = 2;
        report.daemon_stun = DaemonStunReport {
            metrics_endpoints: 1,
            listen_matches_expected: true,
            alternate_listen_matches_expected: true,
            prometheus_alternate_listener_reported: true,
            binding_requests_reported: report.node_count as u64,
            binding_responses_reported: report.node_count as u64,
            invalid_packets_reported: 0,
            socket_receive_errors_reported: 0,
            socket_send_errors_reported: 0,
        };
        report.daemon_processes = 8;
        report.daemon_http_readiness_timeout_seconds = 5;
        report.daemon_agent_readiness_timeout_seconds = 15;
        report.daemon_agent_processes = report.node_count;
        report.daemon_agent_status_endpoints = report.daemon_agent_processes;
        report.daemon_agent_candidate_count_min = 1;
        report.daemon_agent_candidate_count_max = 1;
        let expected_agent_path_count =
            expected_daemon_agent_path_count(report.active_pair_count, report.node_count);
        report.daemon_agent_path_status_endpoints = report.daemon_agent_processes;
        report.daemon_agent_paths_total = expected_agent_path_count;
        report.daemon_agent_reachable_paths_total = expected_agent_path_count;
        report.daemon_agent_path_count_min = expected_agent_path_count / report.node_count;
        report.daemon_agent_path_count_max = expected_agent_path_count / report.node_count;
        report.daemon_control_plane_processes = 2;
        report.daemon_control_plane_metrics_endpoints = 2;
        report.daemon_control_plane_peer_map_endpoints = 2;
        report.daemon_control_plane_peer_map_edges_min = expected_peer_edges;
        report.daemon_control_plane_peer_map_edges_max = expected_peer_edges;
        report.daemon_control_plane_peer_maps_consistent = true;
        report.daemon_control_plane_failover_checked = true;
        report.daemon_control_plane_failover_survivor_endpoints = 1;
        report.daemon_agent_failover_status_endpoints = report.daemon_agent_processes;
        report.daemon_agent_failover_candidate_count_min = 1;
        report.daemon_agent_failover_candidate_count_max = 1;
        report.daemon_agent_failover_path_status_endpoints = report.daemon_agent_processes;
        report.daemon_agent_failover_paths_total = expected_agent_path_count;
        report.daemon_agent_failover_reachable_paths_total = expected_agent_path_count;
        report.daemon_agent_failover_path_count_min = report.daemon_agent_path_count_min;
        report.daemon_agent_failover_path_count_max = report.daemon_agent_path_count_max;
        report.daemon_control_plane_failover_peer_map_edges_min = expected_peer_edges;
        report.daemon_control_plane_failover_peer_map_edges_max = expected_peer_edges;
        report.daemon_control_plane_failover_peer_maps_consistent = true;
        report.daemon_control_plane_failover_metrics_endpoints = 1;
        report.daemon_control_plane_failover_metrics_consistent = true;
        report.daemon_control_plane_failover_relay_candidates_min = report.relay_count;
        report.daemon_control_plane_failover_relay_candidates_max = report.relay_count;
        report.daemon_control_plane_failover_path_count_min = expected_agent_path_count;
        report.daemon_control_plane_failover_path_count_max = expected_agent_path_count;
        report.daemon_control_plane_failover_reachable_path_count_min = expected_agent_path_count;
        report.daemon_control_plane_failover_reachable_path_count_max = expected_agent_path_count;
        report.daemon_control_plane_failover_path_status_requests =
            report.daemon_control_plane_failover_survivor_endpoints * report.daemon_agent_processes;
        report.daemon_control_plane_failover_path_status_count_min = expected_agent_path_count;
        report.daemon_control_plane_failover_path_status_count_max = expected_agent_path_count;
        report.daemon_control_plane_failover_path_status_reachable_count_min =
            expected_agent_path_count;
        report.daemon_control_plane_failover_path_status_reachable_count_max =
            expected_agent_path_count;
        report.daemon_control_plane_failover_path_status_stale_count_max = 0;
        report.daemon_control_plane_failover_healthy_nodes_min = report.node_count;
        report.daemon_control_plane_failover_healthy_nodes_max = report.node_count;
        report.daemon_control_plane_failover_degraded_nodes_min = 0;
        report.daemon_control_plane_failover_degraded_nodes_max = 0;
        report.daemon_control_plane_failover_unhealthy_nodes_min = 0;
        report.daemon_control_plane_failover_unhealthy_nodes_max = 0;
        report.daemon_control_plane_relay_candidates_min = report.relay_count;
        report.daemon_control_plane_relay_candidates_max = report.relay_count;
        report.daemon_control_plane_path_count_min = expected_agent_path_count;
        report.daemon_control_plane_path_count_max = expected_agent_path_count;
        report.daemon_control_plane_reachable_path_count_min = expected_agent_path_count;
        report.daemon_control_plane_reachable_path_count_max = expected_agent_path_count;
        report.daemon_control_plane_path_status_requests =
            report.daemon_control_plane_processes * report.daemon_agent_processes;
        report.daemon_control_plane_path_status_count_min = expected_agent_path_count;
        report.daemon_control_plane_path_status_count_max = expected_agent_path_count;
        report.daemon_control_plane_path_status_reachable_count_min = expected_agent_path_count;
        report.daemon_control_plane_path_status_reachable_count_max = expected_agent_path_count;
        report.daemon_control_plane_path_status_stale_count_max = 0;
        report.daemon_control_plane_healthy_nodes = report.node_count;
        report.daemon_control_plane_healthy_nodes_min = report.node_count;
        report.daemon_control_plane_healthy_nodes_max = report.node_count;
        report.daemon_control_plane_degraded_nodes = 0;
        report.daemon_control_plane_degraded_nodes_min = 0;
        report.daemon_control_plane_degraded_nodes_max = 0;
        report.daemon_control_plane_unhealthy_nodes = 0;
        report.daemon_control_plane_unhealthy_nodes_min = 0;
        report.daemon_control_plane_unhealthy_nodes_max = 0;
        report.daemon_control_plane_metrics_consistent = true;
        report.daemon_signal_health_reports = report.node_count;
        report.daemon_signal_healthy_nodes = report.node_count;
        report.daemon_signal_degraded_nodes = 0;
        report.daemon_signal_unhealthy_nodes = 0;
        Ok(report)
    }

    fn control_plane_metrics(
        relay_candidate_count: usize,
        path_count: usize,
        reachable_path_count: usize,
        healthy_node_count: usize,
        degraded_node_count: usize,
        unhealthy_node_count: usize,
    ) -> ControlPlaneMetricsResponse {
        let mut path_state_counts = Vec::new();
        if reachable_path_count > 0 {
            path_state_counts.push(ipars_types::api::PathStateCount {
                state: PathState::DirectPublic,
                count: reachable_path_count,
            });
        }
        if path_count > reachable_path_count {
            path_state_counts.push(ipars_types::api::PathStateCount {
                state: PathState::Unreachable,
                count: path_count - reachable_path_count,
            });
        }
        ControlPlaneMetricsResponse {
            cluster_id: ClusterId::from_string("load-summary-test"),
            node_count: healthy_node_count + degraded_node_count + unhealthy_node_count,
            relay_candidate_count,
            healthy_node_count,
            degraded_node_count,
            unhealthy_node_count,
            stale_endpoint_candidate_count: 0,
            vpn_pool_total_count: 0,
            vpn_pool_allocated_count: 0,
            vpn_pool_available_count: 0,
            token_ledger_issued_count: 0,
            token_ledger_active_count: 0,
            token_ledger_revoked_count: 0,
            token_ledger_expired_count: 0,
            token_ledger_exhausted_count: 0,
            token_ledger_use_count: 0,
            wireguard_key_rotation_success_count: 0,
            wireguard_key_rotation_failure_count: 0,
            node_removal_success_count: 0,
            node_removal_failure_count: 0,
            peer_map_candidate_count: 0,
            peer_map_visible_count: 0,
            peer_map_acl_denied_count: 0,
            peer_map_route_candidate_count: 0,
            peer_map_route_visible_count: 0,
            peer_map_route_acl_denied_count: 0,
            stale_path_count: 0,
            path_count,
            path_state_counts,
            endpoint_candidate_ttl_seconds: 0,
            path_state_ttl_seconds: 0,
            generated_at: Utc::now(),
        }
    }

    fn daemon_peer_map_endpoint_summary(edges: &[(&str, &str)]) -> DaemonPeerMapEndpointSummary {
        let mut summary = DaemonPeerMapEndpointSummary::default();
        for (source, peer) in edges {
            summary.record_edge(source, peer);
        }
        summary
    }

    fn node_record_with_routes(label: &str, routes: Vec<Route>) -> NodeRecord {
        NodeRecord {
            node_id: NodeId::from_string(label),
            cluster_id: ClusterId::from_string("load-route-count-test"),
            vpn_ip: ipars_types::VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10))),
            identity_public_key: "identity-public-key".to_string(),
            wireguard_public_key: "wireguard-public-key".to_string(),
            role: Role::edge(),
            tags: BTreeSet::new(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes,
            registered_at: Utc::now(),
        }
    }

    fn agent_status_for_summary(index: usize, candidate_count: usize) -> AgentStatusResponse {
        let mut candidates = endpoint_candidates(index, Scenario::from_name(ScenarioName::Ten));
        while candidates.len() < candidate_count {
            let mut candidate = candidates[0].clone();
            candidate
                .addr
                .set_port(candidate.addr.port() + candidates.len() as u16);
            candidate.priority = candidate.priority.saturating_sub(candidates.len() as u16);
            candidates.push(candidate);
        }
        AgentStatusResponse {
            node_id: node_id(index),
            identity_public_key: identity_for_index(index).public_key_b64(),
            wireguard_public_key: wireguard_public_key_for_index(index),
            candidate_count: candidates.len(),
            candidates,
            nat_classification: None,
            userspace_wireguard_process: None,
            state_updated_at: Utc::now(),
        }
    }

    fn synthetic_sleep_child(role: &str, log_path: PathBuf) -> anyhow::Result<DaemonChild> {
        std::fs::write(&log_path, format!("{role} synthetic log\n"))?;
        let child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to spawn synthetic daemon child {role}"))?;
        Ok(DaemonChild {
            role: role.to_string(),
            child,
            started_at: Utc::now(),
            redacted_argv: synthetic_child_redacted_argv(role),
            redacted_argv_sha256: synthetic_child_redacted_argv_sha256(role),
            log_path: Some(log_path),
            last_exit: None,
        })
    }

    fn synthetic_runtime_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ipars-load-{label}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ))
    }

    fn synthetic_daemon_binary_identity() -> DaemonBinaryIdentity {
        static IDENTITY: std::sync::OnceLock<DaemonBinaryIdentity> = std::sync::OnceLock::new();
        IDENTITY
            .get_or_init(|| match daemon_binary_identity(Path::new("sh")) {
                Ok(identity) => identity,
                Err(error) => {
                    panic!("failed to compute synthetic daemon binary identity: {error}")
                }
            })
            .clone()
    }

    fn synthetic_child_redacted_argv(role: &str) -> Vec<String> {
        let binary = synthetic_daemon_binary_identity()
            .path
            .display()
            .to_string();
        let subcommand = if role.starts_with("control-plane-") {
            "control-plane"
        } else {
            role
        };
        let mut argv = vec![binary, subcommand.to_string()];
        if role == "agent" {
            argv.extend([
                "--join-token-path".to_string(),
                DAEMON_REDACTED_ARG.to_string(),
                "--state-path".to_string(),
                "/tmp/ipars-load-agent.state.json".to_string(),
            ]);
        }
        argv
    }

    fn synthetic_child_redacted_argv_sha256(role: &str) -> String {
        daemon_argv_sha256(&synthetic_child_redacted_argv(role))
    }

    fn synthetic_daemon_group(runtime_dir: PathBuf, keep_runtime_dir: bool) -> DaemonProcessGroup {
        let manifest_seed = synthetic_manifest_seed(runtime_dir.clone());
        DaemonProcessGroup {
            control_plane_urls: Vec::new(),
            signal_url: "http://127.0.0.1:1".to_string(),
            relay_http_url: "http://127.0.0.1:1".to_string(),
            relay_udp_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            stun_http_url: "http://127.0.0.1:1".to_string(),
            stun_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            stun_alternate_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2),
            agent_urls: Vec::new(),
            runtime_dir,
            manifest_seed,
            keep_runtime_dir,
            children: Vec::new(),
            agent_state_paths: Vec::new(),
        }
    }

    fn synthetic_manifest_seed(runtime_dir: PathBuf) -> DaemonRuntimeManifestSeed {
        DaemonRuntimeManifestSeed {
            scenario: ScenarioName::Three,
            workload: synthetic_manifest_workload(),
            runtime_dir,
            iparsd_binary: synthetic_daemon_binary_identity(),
            control_plane_urls: vec!["http://127.0.0.1:31001".to_string()],
            signal_url: "http://127.0.0.1:31002".to_string(),
            relay_http_url: "http://127.0.0.1:31003".to_string(),
            stun_http_url: "http://127.0.0.1:31004".to_string(),
            relay_udp_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31004),
            stun_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31005),
            stun_alternate_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31007),
            keep_runtime_dir: true,
            started_at: Utc::now(),
        }
    }

    fn synthetic_manifest(runtime_dir: PathBuf, log_path: PathBuf) -> DaemonRuntimeManifest {
        let now = Utc::now();
        let log_diagnostics = daemon_log_diagnostics(&log_path);
        let child_started_at = now;
        DaemonRuntimeManifest {
            scenario: ScenarioName::Three,
            phase: DaemonRuntimePhase::StartupReady,
            workload: synthetic_manifest_workload(),
            measurement: None,
            runtime_dir,
            iparsd_binary: synthetic_daemon_binary_identity(),
            control_plane_urls: vec!["http://127.0.0.1:31001".to_string()],
            signal_url: "http://127.0.0.1:31002".to_string(),
            relay_http_url: "http://127.0.0.1:31003".to_string(),
            stun_http_url: "http://127.0.0.1:31004".to_string(),
            relay_udp_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31004),
            stun_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31005),
            stun_alternate_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31007),
            agent_urls: vec!["http://127.0.0.1:31006".to_string()],
            keep_runtime_dir: true,
            started_at: now,
            updated_at: now,
            generated_at: now,
            children: vec![DaemonRuntimeManifestChild {
                role: "control-plane-0".to_string(),
                pid: Some(4242),
                started_at: child_started_at,
                exited_at: None,
                runtime_ms: None,
                redacted_argv: synthetic_child_redacted_argv("control-plane-0"),
                redacted_argv_sha256: synthetic_child_redacted_argv_sha256("control-plane-0"),
                log_path: Some(log_path),
                log_bytes: log_diagnostics
                    .as_ref()
                    .map(|diagnostics| diagnostics.bytes),
                log_tail_sha256: log_diagnostics.map(|diagnostics| diagnostics.tail_sha256),
                state: DaemonRuntimeManifestChildState::Running,
                exit_status: None,
                exit_code: None,
            }],
        }
    }

    fn synthetic_manifest_workload() -> DaemonRuntimeManifestWorkload {
        DaemonRuntimeManifestWorkload {
            scenario_node_count: 3,
            scenario_relay_node_count: 1,
            scenario_route_provider_count: 1,
            scenario_active_pair_count: 6,
            daemon_control_plane_processes: 2,
            daemon_agent_processes: 2,
            daemon_http_readiness_timeout_seconds: 5,
            daemon_agent_readiness_timeout_seconds: 15,
            relay_packets_per_session: 1,
            relay_payload_bytes: 64,
        }
    }

    fn synthetic_manifest_measurement() -> DaemonRuntimeManifestMeasurement {
        DaemonRuntimeManifestMeasurement {
            relay_udp_packets_sent: 6,
            relay_udp_packets_received: 6,
            relay_udp_payload_bytes_sent: 384,
            relay_udp_payload_bytes_received: 384,
            failover_relay_udp_packets_sent: 6,
            failover_relay_udp_packets_received: 6,
            failover_relay_udp_payload_bytes_sent: 384,
            failover_relay_udp_payload_bytes_received: 384,
            relay_dataplane_datagrams_received_reported: 7,
            relay_dataplane_datagrams_forwarded_reported: 6,
            relay_dataplane_datagrams_dropped_reported: 1,
            relay_dataplane_invalid_session_credential_drops_reported: 1,
            relay_dataplane_invalid_session_credential_drops_prometheus_reported: 1,
            relay_forwarded_bytes_reported: 384,
            relay_active_sessions_reported: 6,
            control_plane_failover_checked: true,
            control_plane_failover_survivor_endpoints: 1,
        }
    }

    fn write_synthetic_retained_daemon_manifest(
        report: &LoadReport,
        phase: DaemonRuntimePhase,
        exited_roles: &[&str],
    ) -> anyhow::Result<(PathBuf, PathBuf)> {
        let runtime_dir = synthetic_runtime_dir("retained-manifest");
        std::fs::create_dir_all(&runtime_dir)?;
        secure_daemon_runtime_dir(&runtime_dir)?;
        let exited_roles = exited_roles.iter().copied().collect::<BTreeSet<_>>();
        let started_at = Utc::now();
        let mut children = Vec::with_capacity(report.daemon_processes);
        for index in 0..report.daemon_control_plane_processes {
            let role = format!("control-plane-{index}");
            children.push(synthetic_manifest_child(
                &runtime_dir,
                children.len(),
                &role,
                exited_roles.contains(role.as_str()),
            )?);
        }
        for role in ["signal", "relay", "stun"] {
            children.push(synthetic_manifest_child(
                &runtime_dir,
                children.len(),
                role,
                exited_roles.contains(role),
            )?);
        }
        for _index in 0..report.daemon_agent_processes {
            children.push(synthetic_manifest_child(
                &runtime_dir,
                children.len(),
                "agent",
                exited_roles.contains("agent"),
            )?);
        }

        let updated_at = Utc::now();
        let manifest = DaemonRuntimeManifest {
            scenario: report.scenario,
            phase,
            workload: DaemonRuntimeManifestWorkload {
                scenario_node_count: report.node_count,
                scenario_relay_node_count: report.relay_count,
                scenario_route_provider_count: report.route_provider_count,
                scenario_active_pair_count: report.active_pair_count,
                daemon_control_plane_processes: report.daemon_control_plane_processes,
                daemon_agent_processes: report.daemon_agent_processes,
                daemon_http_readiness_timeout_seconds: 5,
                daemon_agent_readiness_timeout_seconds: 15,
                relay_packets_per_session: report.relay_packets_per_session,
                relay_payload_bytes: report.relay_payload_bytes_per_packet,
            },
            measurement: Some(DaemonRuntimeManifestMeasurement {
                relay_udp_packets_sent: report.relay_udp_packets_sent,
                relay_udp_packets_received: report.relay_udp_packets_received,
                relay_udp_payload_bytes_sent: report.relay_udp_payload_bytes_sent,
                relay_udp_payload_bytes_received: report.relay_udp_payload_bytes_received,
                failover_relay_udp_packets_sent: report.daemon_failover_relay_udp_packets_sent,
                failover_relay_udp_packets_received: report
                    .daemon_failover_relay_udp_packets_received,
                failover_relay_udp_payload_bytes_sent: report
                    .daemon_failover_relay_udp_payload_bytes_sent,
                failover_relay_udp_payload_bytes_received: report
                    .daemon_failover_relay_udp_payload_bytes_received,
                relay_dataplane_datagrams_received_reported: report
                    .relay_dataplane_datagrams_received_reported,
                relay_dataplane_datagrams_forwarded_reported: report
                    .relay_dataplane_datagrams_forwarded_reported,
                relay_dataplane_datagrams_dropped_reported: report
                    .relay_dataplane_datagrams_dropped_reported,
                relay_dataplane_invalid_session_credential_drops_reported: report
                    .relay_dataplane_invalid_session_credential_drops_reported,
                relay_dataplane_invalid_session_credential_drops_prometheus_reported: report
                    .relay_dataplane_invalid_session_credential_drops_prometheus_reported,
                relay_forwarded_bytes_reported: report.relay_forwarded_bytes_reported,
                relay_active_sessions_reported: report.relay_active_sessions_reported,
                control_plane_failover_checked: report.daemon_control_plane_failover_checked,
                control_plane_failover_survivor_endpoints: report
                    .daemon_control_plane_failover_survivor_endpoints,
            }),
            runtime_dir: runtime_dir.clone(),
            iparsd_binary: synthetic_daemon_binary_identity(),
            control_plane_urls: (0..report.daemon_control_plane_processes)
                .map(|index| format!("http://127.0.0.1:31{index:03}"))
                .collect(),
            signal_url: "http://127.0.0.1:32000".to_string(),
            relay_http_url: "http://127.0.0.1:32001".to_string(),
            stun_http_url: "http://127.0.0.1:32002".to_string(),
            relay_udp_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32_002),
            stun_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32_003),
            stun_alternate_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32_004),
            agent_urls: (0..report.daemon_agent_processes)
                .map(|index| format!("http://127.0.0.1:33{index:03}"))
                .collect(),
            keep_runtime_dir: true,
            started_at,
            updated_at,
            generated_at: updated_at,
            children,
        };
        let manifest_path = write_daemon_runtime_manifest(&runtime_dir, manifest)?;
        Ok((runtime_dir, manifest_path))
    }

    fn mutate_retained_daemon_manifest(
        manifest_path: &Path,
        mutate: impl FnOnce(&mut DaemonRuntimeManifest),
    ) -> anyhow::Result<()> {
        let mut manifest: DaemonRuntimeManifest =
            serde_json::from_str(&std::fs::read_to_string(manifest_path)?)?;
        mutate(&mut manifest);
        let runtime_dir = manifest.runtime_dir.clone();
        write_daemon_runtime_manifest(&runtime_dir, manifest)?;
        Ok(())
    }

    fn synthetic_manifest_child(
        runtime_dir: &Path,
        index: usize,
        role: &str,
        exited: bool,
    ) -> anyhow::Result<DaemonRuntimeManifestChild> {
        let log_path = runtime_dir.join(format!("{index:04}-{role}.log"));
        let mut log_file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .private_on_unix()
            .open(&log_path)?;
        log_file.write_all(format!("{role} retained manifest log\n").as_bytes())?;
        log_file.sync_all()?;
        let log_diagnostics =
            daemon_log_diagnostics(&log_path).context("synthetic manifest log was unreadable")?;
        let started_at = Utc::now();
        let exited_at = if exited { Some(Utc::now()) } else { None };
        let runtime_ms = exited_at.map(|exited_at| daemon_child_runtime_ms(started_at, exited_at));
        Ok(DaemonRuntimeManifestChild {
            role: role.to_string(),
            pid: Some(40_000 + index as u32),
            started_at,
            exited_at,
            runtime_ms,
            redacted_argv: synthetic_child_redacted_argv(role),
            redacted_argv_sha256: synthetic_child_redacted_argv_sha256(role),
            log_path: Some(log_path),
            log_bytes: Some(log_diagnostics.bytes),
            log_tail_sha256: Some(log_diagnostics.tail_sha256),
            state: if exited {
                DaemonRuntimeManifestChildState::Exited
            } else {
                DaemonRuntimeManifestChildState::Running
            },
            exit_status: exited.then(|| "signal: 15 (SIGTERM)".to_string()),
            exit_code: None,
        })
    }
}
