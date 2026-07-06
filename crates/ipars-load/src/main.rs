use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
use ipars_crypto::{encode_bytes, IdentityKeyPair};
use ipars_relay::{encode_relay_datagram, RelayService, UdpRelay};
use ipars_relay_http::{router as relay_router, RelayHttpState};
use ipars_signal::SignalRegistry;
use ipars_signal_http::{router as signal_router, SignalHttpState};
use ipars_types::api::{
    AgentStatusResponse, ControlPlaneMetricsResponse, HeartbeatRequest, HeartbeatResponse,
    JoinNodeRequest, PeerMap, RegisterNodeRequest, RegisterNodeResponse,
    RelayAdmissionFailureReason, RelayAdmissionRequest, RelayAdmissionResponse,
    RelayStatusResponse, SignalMetricsResponse, SignalNodeUpsertRequest, SignalNodeUpsertResponse,
    SignalPathRequest, SignalPathResponse,
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
const DAEMON_RUNTIME_MANIFEST_FILE: &str = "run-manifest.json";
const DAEMON_JOIN_TOKEN_FILE_SUFFIX: &str = ".join-token.json";
const DAEMON_AGENT_STATE_FILE_SUFFIX: &str = ".state.json";
const MAX_RELAY_PAYLOAD_BYTES: usize = 60_000;
const MAX_DAEMON_CONTROL_PLANE_PROCESSES: usize = 8;
const MAX_DAEMON_READINESS_TIMEOUT_SECONDS: u64 = 3_600;
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
    relay_udp_sessions: usize,
    relay_packets_per_session: usize,
    relay_payload_bytes_per_packet: usize,
    relay_udp_packets_sent: usize,
    relay_udp_packets_received: usize,
    relay_udp_payload_bytes_sent: u64,
    relay_udp_payload_bytes_received: u64,
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
    daemon_control_plane_relay_candidates_min: usize,
    daemon_control_plane_relay_candidates_max: usize,
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
            || !self.relay_admission_failures_by_reason_reported.is_empty()
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
        let manifest_bytes = std::fs::read(manifest_path).with_context(|| {
            format!(
                "daemon load scenario retained manifest {} is not readable",
                manifest_path.display()
            )
        })?;
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
        for (index, url) in manifest.agent_urls.iter().enumerate() {
            validate_daemon_manifest_http_endpoint(
                url,
                &format!("agent URL {index}"),
                &mut seen_http_endpoints,
            )?;
        }
        validate_daemon_manifest_socket_addr(manifest.relay_udp_addr, "relay UDP address")?;
        validate_daemon_manifest_socket_addr(manifest.stun_addr, "STUN address")?;
        if manifest.relay_udp_addr == manifest.stun_addr {
            bail!(
                "daemon load scenario retained manifest reuses UDP socket {} for relay and STUN",
                manifest.relay_udp_addr
            );
        }
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
        let mut exited_roles = Vec::new();
        let mut running_roles = Vec::new();
        for child in &manifest.children {
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
        let expected_roles = self.expected_daemon_child_roles();
        if exited_roles != expected_roles {
            bail!(
                "daemon load scenario retained manifest child roles {:?} do not match expected {:?}",
                exited_roles,
                expected_roles
            );
        }
        validate_daemon_retained_runtime_has_no_transient_files(runtime_dir)?;

        Ok(())
    }

    fn expected_daemon_child_roles(&self) -> Vec<String> {
        let mut roles = Vec::with_capacity(self.daemon_processes);
        roles.extend(
            (0..self.daemon_control_plane_processes).map(|index| format!("control-plane-{index}")),
        );
        roles.extend(["relay", "signal", "stun"].into_iter().map(str::to_string));
        roles.extend((0..self.daemon_agent_processes).map(|_| "agent".to_string()));
        roles.sort();
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

fn validate_daemon_retained_runtime_has_no_transient_files(
    runtime_dir: &Path,
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
            continue;
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
        relay_udp_sessions: 0,
        relay_packets_per_session: 0,
        relay_payload_bytes_per_packet: 0,
        relay_udp_packets_sent: 0,
        relay_udp_packets_received: 0,
        relay_udp_payload_bytes_sent: 0,
        relay_udp_payload_bytes_received: 0,
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
        daemon_control_plane_relay_candidates_min: 0,
        daemon_control_plane_relay_candidates_max: 0,
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
        daemon_control_plane_relay_candidates_min: 0,
        daemon_control_plane_relay_candidates_max: 0,
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
        daemon_control_plane_relay_candidates_min: 0,
        daemon_control_plane_relay_candidates_max: 0,
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
        registration_millis: 0,
        peer_map_millis: 0,
        signal_millis: 0,
        relay_millis,
    })
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
    services.ensure_running(DaemonRuntimePhase::RelayMeasurement)?;
    let relay_elapsed = relay_started.elapsed();
    let relay_millis = relay_elapsed.as_millis();
    services.write_manifest(DaemonRuntimePhase::FinalMetrics)?;
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
    let control_summary =
        control_plane_health_summary(&client, &services.control_plane_urls, "daemon").await?;
    let signal_metrics: SignalMetricsResponse = get_json(
        &client,
        format!("{}/v1/metrics", services.signal_url),
        "daemon signal metrics",
    )
    .await?;
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
    if services.control_plane_urls.len() > 1 {
        services.write_manifest(DaemonRuntimePhase::ControlPlaneFailover)?;
        let (stopped_role, survivor_urls) = services.stop_control_plane_for_failover(0)?;
        failover_survivor_endpoints = survivor_urls.len();
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
        services.ensure_running_allowing_roles(
            DaemonRuntimePhase::ControlPlaneFailover,
            &[stopped_role.as_str()],
        )?;
        services.write_manifest(DaemonRuntimePhase::ControlPlaneFailover)?;
    }
    let completed_manifest_path = services.stop_all_for_completed_manifest()?;

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
        relay_udp_sessions: status.capability.active_sessions as usize,
        relay_packets_per_session: relay_options.packets_per_session,
        relay_payload_bytes_per_packet: relay_options.payload_bytes,
        relay_udp_packets_sent: relay_packets_sent,
        relay_udp_packets_received: relay_packets_received,
        relay_udp_payload_bytes_sent: relay_payload_bytes_sent,
        relay_udp_payload_bytes_received: relay_payload_bytes_received,
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
        daemon_control_plane_relay_candidates_min: control_summary.relay_candidate_count_min,
        daemon_control_plane_relay_candidates_max: control_summary.relay_candidate_count_max,
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
    runtime_dir: PathBuf,
    control_plane_urls: Vec<String>,
    signal_url: String,
    relay_http_url: String,
    relay_udp_addr: SocketAddr,
    stun_addr: SocketAddr,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DaemonRuntimeManifestChild {
    role: String,
    pid: Option<u32>,
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
    control_plane_urls: Vec<String>,
    signal_url: String,
    relay_http_url: String,
    relay_udp_addr: SocketAddr,
    stun_addr: SocketAddr,
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
        let updated_at = Utc::now();
        write_daemon_runtime_manifest(
            &self.runtime_dir,
            DaemonRuntimeManifest {
                scenario: self.scenario,
                phase,
                workload: self.workload,
                runtime_dir: self.runtime_dir.clone(),
                control_plane_urls: self.control_plane_urls.clone(),
                signal_url: self.signal_url.clone(),
                relay_http_url: self.relay_http_url.clone(),
                relay_udp_addr: self.relay_udp_addr,
                stun_addr: self.stun_addr,
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
        let (state, exit_status, exit_code) = if let Some(exit) = &child.last_exit {
            (
                DaemonRuntimeManifestChildState::Exited,
                Some(exit.status.clone()),
                exit.code,
            )
        } else {
            (DaemonRuntimeManifestChildState::Running, None, None)
        };
        let diagnostics = child.log_path.as_deref().and_then(daemon_log_diagnostics);
        Self {
            role: child.role.clone(),
            pid: Some(child.child.id()),
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
        if !iparsd_bin.exists() && iparsd_bin.components().count() > 1 {
            bail!("iparsd binary does not exist at {}", iparsd_bin.display());
        }
        let runtime_dir = daemon_runtime_dir()?;
        std::fs::create_dir_all(&runtime_dir)?;
        secure_daemon_runtime_dir(&runtime_dir)?;
        let mut startup = DaemonStartupGuard::new(runtime_dir.clone(), options.keep_runtime_dir);
        let control_addrs = reserve_tcp_addrs(options.control_plane_processes).await?;
        let signal_addr = reserve_tcp_addr().await?;
        let relay_http_addr = reserve_tcp_addr().await?;
        let relay_udp_addr = reserve_udp_addr().await?;
        let stun_addr = reserve_udp_addr().await?;
        let control_plane_urls = control_addrs
            .iter()
            .map(|addr| format!("http://{addr}"))
            .collect::<Vec<_>>();
        control_plane_urls
            .first()
            .context("at least one daemon control-plane URL is required")?;
        let signal_url = format!("http://{signal_addr}");
        let relay_http_url = format!("http://{relay_http_addr}");
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
            control_plane_urls: control_plane_urls.clone(),
            signal_url: signal_url.clone(),
            relay_http_url: relay_http_url.clone(),
            relay_udp_addr,
            stun_addr,
            keep_runtime_dir: options.keep_runtime_dir,
            started_at: Utc::now(),
        };
        manifest_seed.write(
            DaemonRuntimePhase::ReservedEndpoints,
            &agent_urls,
            &startup.children,
        )?;
        let control_plane_database_url =
            daemon_sqlite_database_url(&runtime_dir.join("control-plane.sqlite"));
        let client = reqwest::Client::new();
        for (index, control_addr) in control_addrs.iter().enumerate() {
            let role = format!("control-plane-{index}");
            startup.children.push(spawn_iparsd(
                iparsd_bin,
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
            iparsd_bin,
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
        manifest_seed.write(
            DaemonRuntimePhase::ServiceStartup,
            &agent_urls,
            &startup.children,
        )?;
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
                iparsd_bin,
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
        child.last_exit = Some(DaemonChildExit {
            status: status.to_string(),
            code: status.code(),
        });
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

    fn stop_all_for_completed_manifest(&mut self) -> anyhow::Result<PathBuf> {
        stop_daemon_children(&mut self.children)?;
        remove_daemon_agent_state_files(&mut self.agent_state_paths)?;
        secure_daemon_retained_runtime_file_modes(&self.runtime_dir)?;
        self.write_manifest(DaemonRuntimePhase::Completed)
    }
}

impl Drop for DaemonProcessGroup {
    fn drop(&mut self) {
        kill_daemon_children(&mut self.children);
        let _ = remove_daemon_agent_state_files(&mut self.agent_state_paths);
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
        remove_daemon_join_token_files(&mut self.join_token_paths)
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
            let _ = remove_daemon_join_token_files(&mut self.join_token_paths);
            let _ = remove_daemon_agent_state_files(&mut self.agent_state_paths);
            let _ = secure_daemon_retained_runtime_file_modes(&self.runtime_dir);
            if !self.keep_runtime_dir {
                let _ = std::fs::remove_dir_all(&self.runtime_dir);
            }
        }
    }
}

struct DaemonChild {
    role: String,
    child: Child,
    log_path: Option<PathBuf>,
    last_exit: Option<DaemonChildExit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DaemonChildExit {
    status: String,
    code: Option<i32>,
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
        last_exit: None,
    })
}

fn kill_daemon_children(children: &mut [DaemonChild]) {
    for daemon_child in children {
        if daemon_child.last_exit.is_some() {
            continue;
        }
        let _ = daemon_child.child.kill();
        if let Ok(status) = daemon_child.child.wait() {
            daemon_child.last_exit = Some(DaemonChildExit {
                status: status.to_string(),
                code: status.code(),
            });
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
            daemon_child.last_exit = Some(DaemonChildExit {
                status: status.to_string(),
                code: status.code(),
            });
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
        daemon_child.last_exit = Some(DaemonChildExit {
            status: status.to_string(),
            code: status.code(),
        });
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
            let exit = DaemonChildExit {
                status: status.to_string(),
                code: status.code(),
            };
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

struct DaemonLogDiagnostics {
    bytes: u64,
    tail_sha256: String,
}

fn daemon_log_diagnostics(path: &Path) -> Option<DaemonLogDiagnostics> {
    let bytes = std::fs::read(path).ok()?;
    let start = bytes.len().saturating_sub(DAEMON_LOG_TAIL_BYTES);
    let mut hasher = Sha256::new();
    hasher.update(&bytes[start..]);
    let tail_sha256 = format!("{:x}", hasher.finalize());
    Some(DaemonLogDiagnostics {
        bytes: bytes.len() as u64,
        tail_sha256,
    })
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

fn remove_daemon_join_token_files(token_paths: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    remove_daemon_runtime_files(token_paths, "join token", "after agent startup")
}

fn remove_daemon_agent_state_files(state_paths: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    remove_daemon_runtime_files(state_paths, "agent state", "after child shutdown")
}

fn remove_daemon_runtime_files(
    paths: &mut Vec<PathBuf>,
    label: &str,
    context: &str,
) -> anyhow::Result<()> {
    for path in paths.drain(..) {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                bail!(
                    "failed to remove daemon {label} {} {context}: {error}",
                    path.display()
                );
            }
        }
    }
    Ok(())
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
            && self.healthy_node_count_min == self.healthy_node_count_max
            && self.degraded_node_count_min == self.degraded_node_count_max
            && self.unhealthy_node_count_min == self.unhealthy_node_count_max
    }
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
        assert_eq!(report.relay_active_sessions_reported, 6);
        assert_eq!(report.relay_available_sessions_reported, 9_994);
        assert_eq!(report.relay_max_sessions_reported, 10_000);
        assert_eq!(report.relay_max_mbps_reported, 10_000);
        assert!(report.relay_enabled_by_policy_reported);
        assert!(report.relay_e2e_only_reported);
        assert_eq!(report.relay_admission_attempts_reported, 6);
        assert_eq!(report.relay_admission_successes_reported, 6);
        assert_eq!(report.relay_admission_failures_reported, 0);
        assert!(report
            .relay_admission_failures_by_reason_reported
            .is_empty());
        assert_eq!(report.relay_http_requests, 8);
        assert_eq!(report.daemon_control_plane_healthy_nodes, 0);
        assert_eq!(report.daemon_signal_health_reports, 0);
        report.validate_success()?;
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

        let mut retained_manifest = daemon_report.clone();
        let (runtime_dir, manifest_path) = write_synthetic_retained_daemon_manifest(
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
        retained_manifest.daemon_runtime_dir = Some(runtime_dir.clone());
        retained_manifest.daemon_runtime_manifest = Some(manifest_path);
        retained_manifest.validate_success()?;
        std::fs::write(
            runtime_dir.join("0000-control-plane-0.log"),
            "tampered retained log\n",
        )?;
        let error = match retained_manifest.validate_success() {
            Ok(_) => {
                bail!("retained manifest with mismatched log diagnostics should fail validation")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("log diagnostics mismatch"));
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
        mutate_retained_daemon_manifest(&manifest_path, |manifest| {
            if let Some(relay) = manifest
                .children
                .iter_mut()
                .find(|child| child.role == "relay")
            {
                relay.role = "agent".to_string();
            }
        })?;
        let error = match mismatched_child_roles.validate_success() {
            Ok(_) => bail!("retained manifest with mismatched child roles should fail validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("child roles"));
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
            control_plane_metrics(2, 3, 0, 0),
            control_plane_metrics(2, 3, 0, 0),
        ])?;
        assert_eq!(consistent.endpoint_count, 2);
        assert_eq!(consistent.relay_candidate_count_min, 2);
        assert_eq!(consistent.relay_candidate_count_max, 2);
        assert_eq!(consistent.healthy_node_count_min, 3);
        assert_eq!(consistent.healthy_node_count_max, 3);
        assert!(consistent.metrics_consistent());

        let skewed = ControlPlaneHealthSummary::from_metrics(&[
            control_plane_metrics(1, 2, 0, 0),
            control_plane_metrics(2, 3, 1, 0),
        ])?;
        assert_eq!(skewed.relay_candidate_count_min, 1);
        assert_eq!(skewed.relay_candidate_count_max, 2);
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

        let manifest_path = group.stop_all_for_completed_manifest()?;
        let contents = std::fs::read_to_string(&manifest_path)?;
        let manifest: DaemonRuntimeManifest = serde_json::from_str(&contents)?;

        assert_eq!(manifest.phase, DaemonRuntimePhase::Completed);
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

        let manifest_path = group.stop_all_for_completed_manifest()?;

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

        let manifest_path = group.stop_all_for_completed_manifest()?;

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
            log_path: Some(log_path),
            last_exit: None,
        });

        let error = match group.stop_all_for_completed_manifest() {
            Ok(_) => bail!("pre-shutdown child exit should fail completed manifest generation"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("exited before completed manifest shutdown"));
        assert!(error.contains("13"));
        assert_eq!(
            group.children[0].last_exit,
            Some(DaemonChildExit {
                status: "exit status: 13".to_string(),
                code: Some(13),
            })
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

        remove_daemon_join_token_files(&mut paths)?;

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

        remove_daemon_agent_state_files(&mut paths)?;

        assert!(paths.is_empty());
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
        assert_eq!(decoded.runtime_dir, runtime_dir);
        assert_eq!(decoded.started_at, manifest.started_at);
        assert_eq!(decoded.updated_at, manifest.updated_at);
        assert_eq!(decoded.generated_at, manifest.updated_at);
        assert_eq!(decoded.children.len(), 1);
        assert_eq!(decoded.children[0].role, "control-plane-0");
        assert_eq!(decoded.children[0].pid, Some(4242));
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
        assert_eq!(updated.started_at, seed.started_at);
        assert!(updated.updated_at >= initial.updated_at);
        assert_eq!(updated.generated_at, updated.updated_at);
        assert_eq!(updated.agent_urls, agent_urls);
        assert_eq!(updated.children.len(), 1);
        assert_eq!(updated.children[0].role, "signal");
        assert_eq!(updated.children[0].pid, Some(pid));
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
            log_path: Some(log_path.clone()),
            last_exit: Some(DaemonChildExit {
                status: "exit status: 11".to_string(),
                code: Some(11),
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
                        children[0].last_exit,
                        Some(DaemonChildExit {
                            status: "exit status: 7".to_string(),
                            code: Some(7),
                        })
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
        let mut child = spawn_iparsd(
            Path::new("sh"),
            &["-c".to_string(), "sleep 30".to_string()],
            "agent/with spaces",
            &runtime_dir,
        )?;
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

        let _ = child.child.kill();
        let _ = child.child.wait();
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
        assert_eq!(report.daemon_control_plane_failover_peer_map_edges_min, 2);
        assert_eq!(report.daemon_control_plane_failover_peer_map_edges_max, 2);
        assert!(report.daemon_control_plane_failover_peer_maps_consistent);
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
        assert_eq!(report.relay_udp_packets_sent, report.active_pair_count);
        assert_eq!(report.relay_udp_packets_received, report.active_pair_count);
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
        assert!(report
            .relay_admission_failures_by_reason_reported
            .is_empty());
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
        report.daemon_processes = 8;
        report.daemon_http_readiness_timeout_seconds = 5;
        report.daemon_agent_readiness_timeout_seconds = 15;
        report.daemon_agent_processes = report.node_count;
        report.daemon_agent_status_endpoints = report.daemon_agent_processes;
        report.daemon_agent_candidate_count_min = 1;
        report.daemon_agent_candidate_count_max = 1;
        report.daemon_control_plane_processes = 2;
        report.daemon_control_plane_metrics_endpoints = 2;
        report.daemon_control_plane_peer_map_endpoints = 2;
        report.daemon_control_plane_peer_map_edges_min = expected_peer_edges;
        report.daemon_control_plane_peer_map_edges_max = expected_peer_edges;
        report.daemon_control_plane_peer_maps_consistent = true;
        report.daemon_control_plane_failover_checked = true;
        report.daemon_control_plane_failover_survivor_endpoints = 1;
        report.daemon_control_plane_failover_peer_map_edges_min = expected_peer_edges;
        report.daemon_control_plane_failover_peer_map_edges_max = expected_peer_edges;
        report.daemon_control_plane_failover_peer_maps_consistent = true;
        report.daemon_control_plane_relay_candidates_min = report.relay_count;
        report.daemon_control_plane_relay_candidates_max = report.relay_count;
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
        healthy_node_count: usize,
        degraded_node_count: usize,
        unhealthy_node_count: usize,
    ) -> ControlPlaneMetricsResponse {
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
            peer_map_candidate_count: 0,
            peer_map_visible_count: 0,
            peer_map_acl_denied_count: 0,
            peer_map_route_candidate_count: 0,
            peer_map_route_visible_count: 0,
            peer_map_route_acl_denied_count: 0,
            stale_path_count: 0,
            path_count: 0,
            path_state_counts: Vec::new(),
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

    fn synthetic_daemon_group(runtime_dir: PathBuf, keep_runtime_dir: bool) -> DaemonProcessGroup {
        let manifest_seed = synthetic_manifest_seed(runtime_dir.clone());
        DaemonProcessGroup {
            control_plane_urls: Vec::new(),
            signal_url: "http://127.0.0.1:1".to_string(),
            relay_http_url: "http://127.0.0.1:1".to_string(),
            relay_udp_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
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
            control_plane_urls: vec!["http://127.0.0.1:31001".to_string()],
            signal_url: "http://127.0.0.1:31002".to_string(),
            relay_http_url: "http://127.0.0.1:31003".to_string(),
            relay_udp_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31004),
            stun_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31005),
            keep_runtime_dir: true,
            started_at: Utc::now(),
        }
    }

    fn synthetic_manifest(runtime_dir: PathBuf, log_path: PathBuf) -> DaemonRuntimeManifest {
        let now = Utc::now();
        let log_diagnostics = daemon_log_diagnostics(&log_path);
        DaemonRuntimeManifest {
            scenario: ScenarioName::Three,
            phase: DaemonRuntimePhase::StartupReady,
            workload: synthetic_manifest_workload(),
            runtime_dir,
            control_plane_urls: vec!["http://127.0.0.1:31001".to_string()],
            signal_url: "http://127.0.0.1:31002".to_string(),
            relay_http_url: "http://127.0.0.1:31003".to_string(),
            relay_udp_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31004),
            stun_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31005),
            agent_urls: vec!["http://127.0.0.1:31006".to_string()],
            keep_runtime_dir: true,
            started_at: now,
            updated_at: now,
            generated_at: now,
            children: vec![DaemonRuntimeManifestChild {
                role: "control-plane-0".to_string(),
                pid: Some(4242),
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

    fn write_synthetic_retained_daemon_manifest(
        report: &LoadReport,
        phase: DaemonRuntimePhase,
        exited_roles: &[&str],
    ) -> anyhow::Result<(PathBuf, PathBuf)> {
        let runtime_dir = synthetic_runtime_dir("retained-manifest");
        std::fs::create_dir_all(&runtime_dir)?;
        secure_daemon_runtime_dir(&runtime_dir)?;
        let exited_roles = exited_roles.iter().copied().collect::<BTreeSet<_>>();
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

        let now = Utc::now();
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
            runtime_dir: runtime_dir.clone(),
            control_plane_urls: (0..report.daemon_control_plane_processes)
                .map(|index| format!("http://127.0.0.1:31{index:03}"))
                .collect(),
            signal_url: "http://127.0.0.1:32000".to_string(),
            relay_http_url: "http://127.0.0.1:32001".to_string(),
            relay_udp_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32_002),
            stun_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32_003),
            agent_urls: (0..report.daemon_agent_processes)
                .map(|index| format!("http://127.0.0.1:33{index:03}"))
                .collect(),
            keep_runtime_dir: true,
            started_at: now,
            updated_at: now,
            generated_at: now,
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
        Ok(DaemonRuntimeManifestChild {
            role: role.to_string(),
            pid: (!exited).then_some(40_000 + index as u32),
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
