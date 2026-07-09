use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt::{self, Write as _};
use std::io::{Read, SeekFrom};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use async_trait::async_trait;
use axum::Router;
use aya::maps::{MapData, RingBuf};
use aya::programs::TracePoint;
use aya::{Ebpf, EbpfLoader};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ipars_agent::{
    AgentError, AgentRuntime, FileAgentStateStore, KernelWireGuardBackend, LinuxCommand,
    LinuxCommandRunner, LinuxWireGuardBackend, MemoryWireGuardBackend,
    NamespacedLinuxCommandRunner, PathSelector, PeerMapApplier, PeerMapSink, PeerMapSource,
    PeerMapSync, RelayForwarderStats, RelaySessionState, RuntimePeerEndpointResolver,
    TimedSystemCommandRunner, UdpHolePuncher, UdpRelayFrameForwarder, UserspaceWireGuardBackend,
    WireGuardBackend,
};
use ipars_agent_http::{router as agent_router, AgentHttpState};
use ipars_control_plane::{
    ControlPlane, ControlPlaneConfig, ControlPlaneJoinService, ControlPlaneStore, InMemoryStore,
    InMemoryTokenLedger, IssuerKeyRing, TokenLedger,
};
use ipars_control_plane_http::{router, ControlPlaneHttpState};
use ipars_crypto::IdentityKeyPair;
use ipars_relay::{
    encode_relay_datagram, RelayAdmissionRateLimit, RelayService, RelaySessionId, UdpRelay,
};
use ipars_relay_http::{router as relay_router, RelayHttpState};
use ipars_route_manager::{
    checked_docker_route_plan, checked_kubernetes_route_plan, kubernetes_route_plan,
    DockerNetworkIntent, DryRunLinuxRouteManager, KubernetesUnderlayIntent,
    LinuxNetlinkRouteManager, LinuxNetworkNamespace, LinuxRouteCommandRunner, LinuxRouteManager,
    NamespacedLinuxRouteCommandRunner, RouteManager, RouteManagerError, RoutePlan,
    TimedSystemRouteCommandRunner,
};
use ipars_signal::SignalRegistry;
use ipars_signal_http::{router as signal_router, SignalHttpState};
use ipars_store::{PostgresControlPlaneStore, SqliteControlPlaneStore};
use ipars_stun::{
    BindingStunServer, Rfc5780StunServer, StunServerMetricsSnapshot, StunServerStats,
};
use ipars_types::api::{
    packet_flow_destination_drop_reason, AgentManagedProcessState, AgentMetricsResponse,
    AgentPacketFlowApplication, AgentPacketFlowClassification, AgentPacketFlowConntrackStatus,
    AgentPacketFlowDropReason, AgentPacketFlowDuplicateSource, AgentPacketFlowObservation,
    AgentPacketFlowTcpState, AgentRelayAdmissionFailureReason, AgentRelayForwarderMetrics,
    ControlPlaneMetricsResponse, HeartbeatRequest, HeartbeatResponse, JoinNodeRequest,
    NatTraversalStrategyCount, PathStateCount, PeerMap, RegisterNodeRequest, RegisterNodeResponse,
    RelayAdmissionFailureReason, RelayAdmissionRequest, RelayAdmissionResponse,
    RelayDataplaneDropReason, RelayDataplaneMetrics, RelayStatusResponse,
    SignalHolePunchPlanResponse, SignalMetricsResponse, SignalNodeUpsertRequest,
    SignalNodeUpsertResponse, SignalPathRequest, SignalPathResponse, StunMetricsResponse,
};
#[cfg(test)]
use ipars_types::ebpf::PACKET_FLOW_EVENT_LEN;
use ipars_types::ebpf::{
    PacketFlowEvent, PACKET_FLOW_CONNTRACK_ASSURED, PACKET_FLOW_CONNTRACK_UNREPLIED,
    PACKET_FLOW_EVENT_VERSION, PACKET_FLOW_IP_FAMILY_IPV4, PACKET_FLOW_IP_FAMILY_IPV6,
    PACKET_FLOW_PROTOCOL_AH, PACKET_FLOW_PROTOCOL_ESP, PACKET_FLOW_PROTOCOL_GRE,
    PACKET_FLOW_PROTOCOL_ICMP, PACKET_FLOW_PROTOCOL_ICMPV6, PACKET_FLOW_PROTOCOL_IPIP,
    PACKET_FLOW_PROTOCOL_IPV6_ENCAP, PACKET_FLOW_PROTOCOL_SCTP, PACKET_FLOW_PROTOCOL_TCP,
    PACKET_FLOW_PROTOCOL_UDP, PACKET_FLOW_PROTOCOL_UNKNOWN, PACKET_FLOW_RINGBUF_MAP,
    PACKET_FLOW_TCP_STATE_CLOSE, PACKET_FLOW_TCP_STATE_CLOSE_WAIT,
    PACKET_FLOW_TCP_STATE_ESTABLISHED, PACKET_FLOW_TCP_STATE_FIN_WAIT,
    PACKET_FLOW_TCP_STATE_LAST_ACK, PACKET_FLOW_TCP_STATE_LISTEN, PACKET_FLOW_TCP_STATE_SYN_RECV,
    PACKET_FLOW_TCP_STATE_SYN_SENT, PACKET_FLOW_TCP_STATE_SYN_SENT2,
    PACKET_FLOW_TCP_STATE_TIME_WAIT, PACKET_FLOW_TCP_STATE_UNKNOWN,
};
use ipars_types::{
    endpoint_addr_is_usable, http_url_is_usable_endpoint, AclRule, BootstrapEndpointKind,
    ClusterId, ClusterPolicy, EndpointCandidate, HealthState, KeyId, NatTraversalStrategy,
    NodeHealth, NodeId, NodeRecord, PathMetrics, PathRecord, PathScore, PathState, RelayCapability,
    Route, SignedJoinToken, TokenLedgerMetrics, TransportProtocol,
};
use netlink_sys::{
    protocols::{NETLINK_GENERIC, NETLINK_NETFILTER, NETLINK_ROUTE},
    Socket, SocketAddr as NetlinkSocketAddr,
};
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Gauge};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::{
    logs::SdkLoggerProvider, metrics::SdkMeterProvider, trace::SdkTracerProvider, Resource,
};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::{de::DeserializeOwned, Deserialize};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Layer};

const CAP_NET_ADMIN_BIT: u8 = 12;
const CAP_NET_RAW_BIT: u8 = 13;
const CAP_SYS_ADMIN_BIT: u8 = 21;
const CAP_PERFMON_BIT: u8 = 38;
const CAP_BPF_BIT: u8 = 39;
const MAX_AGENT_JOIN_TOKEN_BYTES: u64 = 64 * 1024;
const MAX_KUBERNETES_SERVICE_ACCOUNT_TOKEN_BYTES: u64 = 64 * 1024;
const MAX_KUBERNETES_CA_CERT_BYTES: u64 = 1024 * 1024;
const MAX_KUBERNETES_SERVICES_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DOCKER_API_NETWORKS_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_AGENT_CONTROL_PLANE_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_AGENT_SIGNAL_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_AGENT_RELAY_HTTP_RESPONSE_BYTES: u64 = 1024 * 1024;
const DEFAULT_PACKET_FLOW_PROCFS_MAX_BYTES: u64 = 8 * 1024 * 1024;
const DEFAULT_PACKET_FLOW_PROCFS_MAX_LINE_BYTES: usize = 4096;
const DEFAULT_PACKET_FLOW_PROCFS_MAX_FLOWS: usize = 131_072;
const DEFAULT_PACKET_FLOW_NETLINK_MAX_FLOWS: usize = 131_072;
const DEFAULT_PACKET_FLOW_EBPF_EVENT_MAX_BYTES: u64 = 1024 * 1024;
const DEFAULT_PACKET_FLOW_EBPF_EVENT_MAX_LINE_BYTES: usize = 2048;
const DEFAULT_PACKET_FLOW_EBPF_EVENT_MAX_FLOWS: usize = 131_072;
const DEFAULT_PACKET_FLOW_EBPF_RINGBUF_MAX_EVENTS: usize = 4096;
const DEFAULT_PACKET_FLOW_EBPF_RINGBUF_MAP: &str = PACKET_FLOW_RINGBUF_MAP;
const MAX_PACKET_FLOW_EBPF_ATTACH_SPECS: usize = 32;
const MAX_PACKET_FLOW_READ_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PACKET_FLOW_LINE_BYTES: usize = 64 * 1024;
const MAX_PACKET_FLOW_RECORDS: usize = 1_048_576;
const MAX_PACKET_FLOW_EBPF_RINGBUF_EVENTS_PER_WAKE: usize = 65_536;
const MAX_PACKET_FLOW_DEDUP_TTL_SECONDS: u64 = 24 * 60 * 60;
const MAX_PACKET_FLOW_DEDUP_FINGERPRINTS: usize = 1_048_576;
const MAX_RELAY_ADMISSION_BEARER_TOKEN_BYTES: usize = 512;
const MAX_RELAY_SESSION_TTL_SECONDS: u64 = 24 * 60 * 60;
const MAX_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS: u64 = 24 * 60 * 60;
const MAX_RUNTIME_COMMAND_TIMEOUT_SECONDS: u64 = 60 * 60;
const MAX_USERSPACE_WIREGUARD_LIFECYCLE_TIMEOUT_SECONDS: u64 = 60 * 60;
const MAX_RUNTIME_COMMAND_OUTPUT_MAX_BYTES: usize = 1024 * 1024;
const MAX_RUNTIME_PROGRAM_TOKEN_BYTES: usize = 4096;
const MAX_DAEMON_IDENTIFIER_BYTES: usize = 255;
const MAX_USERSPACE_WIREGUARD_ARGS: usize = 128;
const MAX_USERSPACE_WIREGUARD_SPAWN_ARGS: usize = MAX_USERSPACE_WIREGUARD_ARGS + 4;
const MAX_USERSPACE_WIREGUARD_ARG_BYTES: usize = 4096;
const SANITIZED_RUNTIME_COMMAND_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const SANITIZED_RUNTIME_COMMAND_LOCALE: &str = "C";
const PROC_SYS_IPV4_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
const PROC_SYS_IPV6_FORWARDING: &str = "/proc/sys/net/ipv6/conf/all/forwarding";
const MAX_PROC_SYSCTL_FLAG_BYTES: u64 = 64;
const MAX_PROC_SELF_STATUS_BYTES: u64 = 64 * 1024;
const MAX_EBPF_TRACEPOINT_ID_BYTES: usize = 64;
const TRACEFS_EVENT_ROOTS: [&str; 2] = [
    "/sys/kernel/tracing/events",
    "/sys/kernel/debug/tracing/events",
];

macro_rules! prometheus_line {
    ($body:expr, $($arg:tt)*) => {{
        let _ = writeln!($body, $($arg)*);
    }};
}

fn prometheus_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[derive(Debug, Parser)]
#[command(name = "iparsd")]
#[command(about = "IPA-RS-HeteroNetwork daemon processes")]
struct Cli {
    #[command(flatten)]
    observability: ObservabilityArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    ControlPlane(ControlPlaneArgs),
    Signal(SignalArgs),
    Stun(StunArgs),
    Relay(RelayArgs),
    Agent(Box<AgentArgs>),
}

impl Command {
    fn component(&self) -> &'static str {
        match self {
            Self::ControlPlane(_) => "control-plane",
            Self::Signal(_) => "signal",
            Self::Stun(_) => "stun",
            Self::Relay(_) => "relay",
            Self::Agent(_) => "agent",
        }
    }
}

#[derive(Debug, Args, Clone)]
struct ObservabilityArgs {
    #[arg(long, env = "IPARS_OTEL_ENABLED", default_value_t = false)]
    otel_enabled: bool,
    #[arg(long, env = "IPARS_OTEL_ENDPOINT")]
    otel_endpoint: Option<String>,
    #[arg(long, env = "IPARS_OTEL_SERVICE_NAME")]
    otel_service_name: Option<String>,
    #[arg(
        long,
        env = "IPARS_OTEL_METRICS_POLL_INTERVAL_SECONDS",
        default_value_t = 15
    )]
    otel_metrics_poll_interval_seconds: u64,
    #[arg(long, env = "IPARS_LOG_FILTER", default_value = "info")]
    log_filter: String,
}

impl ObservabilityArgs {
    fn otel_active(&self) -> bool {
        self.otel_enabled || self.otel_endpoint.is_some()
    }

    fn service_name(&self, component: &str) -> String {
        self.otel_service_name
            .clone()
            .unwrap_or_else(|| format!("iparsd-{component}"))
    }
}

fn parse_trusted_issuer_key(value: &str) -> Result<TrustedIssuerKeyArg, String> {
    let mut parts = value.splitn(3, ',');
    let issuer_node_id = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "trusted issuer key must use issuer_node_id,key_id,public_key".to_string()
        })?;
    let key_id = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "trusted issuer key must use issuer_node_id,key_id,public_key".to_string()
        })?;
    let public_key = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "trusted issuer key must use issuer_node_id,key_id,public_key".to_string()
        })?;
    Ok(TrustedIssuerKeyArg {
        issuer_node_id: issuer_node_id.to_string(),
        key_id: key_id.to_string(),
        public_key: public_key.to_string(),
    })
}

fn parse_acl_rule(value: &str) -> Result<AclRule, String> {
    serde_json::from_str(value).map_err(|error| format!("ACL rule must be JSON AclRule: {error}"))
}

#[derive(Debug, Default)]
struct ObservabilityGuard {
    tracer_provider: Option<SdkTracerProvider>,
    logger_provider: Option<SdkLoggerProvider>,
    meter_provider: Option<SdkMeterProvider>,
}

impl Drop for ObservabilityGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.logger_provider.take() {
            let _ = provider.shutdown();
        }
        if let Some(provider) = self.meter_provider.take() {
            let _ = provider.shutdown();
        }
        if let Some(provider) = self.tracer_provider.take() {
            let _ = provider.shutdown();
        }
    }
}

fn validate_observability_config(args: &ObservabilityArgs) -> anyhow::Result<()> {
    validate_positive_seconds(
        args.otel_metrics_poll_interval_seconds,
        "--otel-metrics-poll-interval-seconds",
    )
}

#[derive(Debug, Args, Clone)]
struct ControlPlaneArgs {
    #[arg(long, env = "IPARS_LISTEN", default_value = "0.0.0.0:8443")]
    listen: SocketAddr,
    #[arg(long, env = "IPARS_CLUSTER_ID")]
    cluster_id: String,
    #[arg(long, env = "IPARS_VPN_POOL", default_value = "100.64.0.0/10")]
    vpn_pool: ipnet::Ipv4Net,
    #[arg(long, env = "IPARS_RELAY_HEALTH_TTL_SECONDS", default_value_t = 90)]
    relay_health_ttl_seconds: u64,
    #[arg(
        long,
        env = "IPARS_ENDPOINT_CANDIDATE_TTL_SECONDS",
        default_value_t = 120
    )]
    endpoint_candidate_ttl_seconds: u64,
    #[arg(long, env = "IPARS_PATH_STATE_TTL_SECONDS", default_value_t = 600)]
    path_state_ttl_seconds: u64,
    #[arg(long, env = "IPARS_DATABASE_URL")]
    database_url: Option<String>,
    #[arg(long, env = "IPARS_ISSUER_NODE_ID")]
    issuer_node_id: String,
    #[arg(long, env = "IPARS_ISSUER_KEY_ID")]
    issuer_key_id: String,
    #[arg(long, env = "IPARS_ISSUER_PUBLIC_KEY")]
    issuer_public_key: String,
    #[arg(
        long = "trusted-issuer-key",
        env = "IPARS_TRUSTED_ISSUER_KEYS",
        value_delimiter = ';',
        value_parser = parse_trusted_issuer_key
    )]
    trusted_issuer_keys: Vec<TrustedIssuerKeyArg>,
    #[arg(
        long = "acl-rule",
        env = "IPARS_ACL_RULES",
        value_delimiter = ';',
        value_parser = parse_acl_rule
    )]
    acl_rules: Vec<AclRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustedIssuerKeyArg {
    issuer_node_id: String,
    key_id: String,
    public_key: String,
}

#[derive(Debug, Args, Clone)]
struct SignalArgs {
    #[arg(long, env = "IPARS_SIGNAL_LISTEN", default_value = "0.0.0.0:9443")]
    listen: SocketAddr,
    #[arg(long, env = "IPARS_SIGNAL_IDLE_TIMEOUT_SECONDS", default_value_t = 300)]
    idle_timeout_seconds: u64,
    #[arg(
        long,
        env = "IPARS_SIGNAL_RELAY_HEALTH_TTL_SECONDS",
        default_value_t = 90
    )]
    relay_health_ttl_seconds: u64,
    #[arg(
        long,
        env = "IPARS_SIGNAL_ENDPOINT_CANDIDATE_TTL_SECONDS",
        default_value_t = 120
    )]
    endpoint_candidate_ttl_seconds: u64,
    #[arg(
        long,
        env = "IPARS_SIGNAL_NAT_CLASSIFICATION_TTL_SECONDS",
        default_value_t = 300
    )]
    nat_classification_ttl_seconds: u64,
    #[arg(
        long,
        env = "IPARS_SIGNAL_NAT_CLASSIFICATION_MIN_CONFIDENCE_PERCENT",
        default_value_t = 50
    )]
    nat_classification_min_confidence_percent: u8,
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
    #[arg(long, env = "IPARS_STUN_ALTERNATE_LISTEN")]
    alternate_listen: Option<SocketAddr>,
    #[arg(long, env = "IPARS_STUN_HTTP_LISTEN", default_value = "0.0.0.0:3479")]
    http_listen: SocketAddr,
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
    #[arg(long, env = "IPARS_RELAY_ADMISSION_URL")]
    admission_url: Option<String>,
    #[arg(long, env = "IPARS_RELAY_MAX_SESSIONS", default_value_t = 10_000)]
    max_sessions: u32,
    #[arg(long, env = "IPARS_RELAY_MAX_SESSIONS_PER_NODE", default_value_t = 0)]
    max_sessions_per_node: u32,
    #[arg(long, env = "IPARS_RELAY_MAX_MBPS", default_value_t = 1000)]
    max_mbps: u32,
    #[arg(long, env = "IPARS_RELAY_SESSION_TTL_SECONDS", default_value_t = 300)]
    session_ttl_seconds: u64,
    #[arg(long, env = "IPARS_RELAY_ADMISSION_RATE_LIMIT", default_value_t = 4096)]
    admission_rate_limit: u32,
    #[arg(
        long,
        env = "IPARS_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS",
        default_value_t = 60
    )]
    admission_rate_limit_window_seconds: u64,
    #[arg(long, env = "IPARS_RELAY_ADMISSION_BEARER_TOKEN")]
    admission_bearer_token: Option<String>,
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
    #[arg(
        long = "stun-server",
        env = "IPARS_AGENT_STUN_SERVER",
        value_delimiter = ','
    )]
    stun_servers: Vec<SocketAddr>,
    #[arg(long, env = "IPARS_AGENT_STUN_BIND", default_value = "0.0.0.0:0")]
    stun_bind: SocketAddr,
    #[arg(long, env = "IPARS_AGENT_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,
    #[arg(long, env = "IPARS_AGENT_SIGNAL_URL")]
    signal_url: Option<String>,
    #[arg(
        long,
        env = "IPARS_AGENT_JOIN_TOKEN",
        conflicts_with = "join_token_path"
    )]
    join_token: Option<String>,
    #[arg(long, env = "IPARS_AGENT_JOIN_TOKEN_PATH")]
    join_token_path: Option<PathBuf>,
    #[arg(
        long,
        env = "IPARS_AGENT_RELAY_PUBLIC_ENDPOINT",
        requires = "relay_admission_url"
    )]
    relay_public_endpoint: Option<SocketAddr>,
    #[arg(
        long,
        env = "IPARS_AGENT_RELAY_ADMISSION_URL",
        requires = "relay_public_endpoint"
    )]
    relay_admission_url: Option<String>,
    #[arg(long, env = "IPARS_AGENT_RELAY_STATUS_URL")]
    relay_status_url: Option<String>,
    #[arg(long, env = "IPARS_AGENT_RELAY_ADMISSION_BEARER_TOKEN")]
    relay_admission_bearer_token: Option<String>,
    #[arg(long, env = "IPARS_AGENT_RELAY_MAX_SESSIONS", default_value_t = 10_000)]
    relay_max_sessions: u32,
    #[arg(long, env = "IPARS_AGENT_RELAY_MAX_MBPS", default_value_t = 1000)]
    relay_max_mbps: u32,
    #[arg(long, env = "IPARS_AGENT_APPLY_PEER_MAP", default_value_t = false)]
    apply_peer_map: bool,
    #[arg(
        long,
        env = "IPARS_AGENT_RUNTIME_BACKEND",
        value_enum,
        default_value_t = AgentRuntimeBackend::LinuxCommand
    )]
    runtime_backend: AgentRuntimeBackend,
    #[arg(
        long,
        env = "IPARS_AGENT_SKIP_RUNTIME_PREFLIGHT",
        default_value_t = false
    )]
    skip_runtime_preflight: bool,
    #[arg(
        long,
        env = "IPARS_AGENT_RUNTIME_COMMAND_TIMEOUT_SECONDS",
        default_value_t = 30
    )]
    runtime_command_timeout_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_RUNTIME_COMMAND_OUTPUT_MAX_BYTES",
        default_value_t = 65_536
    )]
    runtime_command_output_max_bytes: usize,
    #[arg(
        long,
        env = "IPARS_AGENT_PEER_MAP_POLL_INTERVAL_SECONDS",
        default_value_t = 30
    )]
    peer_map_poll_interval_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_HEARTBEAT_INTERVAL_SECONDS",
        default_value_t = 15
    )]
    heartbeat_interval_seconds: u64,
    #[arg(long, env = "IPARS_AGENT_DISABLE_HEARTBEAT", default_value_t = false)]
    disable_heartbeat: bool,
    #[arg(
        long,
        env = "IPARS_AGENT_SIGNAL_REGISTRATION_INTERVAL_SECONDS",
        default_value_t = 30
    )]
    signal_registration_interval_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_DISABLE_SIGNAL_REGISTRATION",
        default_value_t = false
    )]
    disable_signal_registration: bool,
    #[arg(
        long,
        env = "IPARS_AGENT_SIGNAL_PATH_INTERVAL_SECONDS",
        default_value_t = 30
    )]
    signal_path_interval_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_PACKET_FLOW_DETECTOR",
        value_enum,
        default_value_t = PacketFlowDetector::Disabled
    )]
    packet_flow_detector: PacketFlowDetector,
    #[arg(long, env = "IPARS_AGENT_PACKET_FLOW_CONNTRACK_PATH")]
    packet_flow_conntrack_path: Option<PathBuf>,
    #[arg(long, env = "IPARS_AGENT_PACKET_FLOW_EBPF_EVENT_PATH")]
    packet_flow_ebpf_event_path: Option<PathBuf>,
    #[arg(long, env = "IPARS_AGENT_PACKET_FLOW_EBPF_OBJECT_PATH")]
    packet_flow_ebpf_object_path: Option<PathBuf>,
    #[arg(
        long,
        env = "IPARS_AGENT_PACKET_FLOW_EBPF_RINGBUF_MAP",
        default_value = DEFAULT_PACKET_FLOW_EBPF_RINGBUF_MAP
    )]
    packet_flow_ebpf_ringbuf_map: String,
    #[arg(
        long,
        env = "IPARS_AGENT_PACKET_FLOW_EBPF_ATTACH",
        value_name = "PROGRAM:CATEGORY:NAME"
    )]
    packet_flow_ebpf_attach: Vec<String>,
    #[arg(
        long,
        env = "IPARS_AGENT_PACKET_FLOW_POLL_INTERVAL_SECONDS",
        default_value_t = 5
    )]
    packet_flow_poll_interval_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_PACKET_FLOW_DEDUP_TTL_SECONDS",
        default_value_t = 30
    )]
    packet_flow_dedup_ttl_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_PACKET_FLOW_PROCFS_MAX_BYTES",
        default_value_t = DEFAULT_PACKET_FLOW_PROCFS_MAX_BYTES
    )]
    packet_flow_procfs_max_bytes: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_PACKET_FLOW_PROCFS_MAX_LINE_BYTES",
        default_value_t = DEFAULT_PACKET_FLOW_PROCFS_MAX_LINE_BYTES
    )]
    packet_flow_procfs_max_line_bytes: usize,
    #[arg(
        long,
        env = "IPARS_AGENT_PACKET_FLOW_PROCFS_MAX_FLOWS",
        default_value_t = DEFAULT_PACKET_FLOW_PROCFS_MAX_FLOWS
    )]
    packet_flow_procfs_max_flows: usize,
    #[arg(
        long,
        env = "IPARS_AGENT_PACKET_FLOW_NETLINK_MAX_FLOWS",
        default_value_t = DEFAULT_PACKET_FLOW_NETLINK_MAX_FLOWS
    )]
    packet_flow_netlink_max_flows: usize,
    #[arg(
        long,
        env = "IPARS_AGENT_PACKET_FLOW_EBPF_EVENT_MAX_BYTES",
        default_value_t = DEFAULT_PACKET_FLOW_EBPF_EVENT_MAX_BYTES
    )]
    packet_flow_ebpf_event_max_bytes: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_PACKET_FLOW_EBPF_EVENT_MAX_LINE_BYTES",
        default_value_t = DEFAULT_PACKET_FLOW_EBPF_EVENT_MAX_LINE_BYTES
    )]
    packet_flow_ebpf_event_max_line_bytes: usize,
    #[arg(
        long,
        env = "IPARS_AGENT_PACKET_FLOW_EBPF_EVENT_MAX_FLOWS",
        default_value_t = DEFAULT_PACKET_FLOW_EBPF_EVENT_MAX_FLOWS
    )]
    packet_flow_ebpf_event_max_flows: usize,
    #[arg(
        long,
        env = "IPARS_AGENT_PACKET_FLOW_EBPF_RINGBUF_MAX_EVENTS",
        default_value_t = DEFAULT_PACKET_FLOW_EBPF_RINGBUF_MAX_EVENTS
    )]
    packet_flow_ebpf_ringbuf_max_events: usize,
    #[arg(long, env = "IPARS_AGENT_PACKET_FLOW_PIN", default_value_t = false)]
    packet_flow_pin: bool,
    #[arg(
        long,
        env = "IPARS_AGENT_RELAY_SESSION_RENEW_BEFORE_SECONDS",
        default_value_t = 60
    )]
    relay_session_renew_before_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_DISABLE_SIGNAL_PATHS",
        default_value_t = false
    )]
    disable_signal_paths: bool,
    #[arg(long, env = "IPARS_AGENT_HOLE_PUNCH_BIND", default_value = "0.0.0.0:0")]
    hole_punch_bind: SocketAddr,
    #[arg(long, env = "IPARS_AGENT_HOLE_PUNCH_ATTEMPTS", default_value_t = 5)]
    hole_punch_attempts: usize,
    #[arg(
        long,
        env = "IPARS_AGENT_HOLE_PUNCH_INTERVAL_MILLIS",
        default_value_t = 100
    )]
    hole_punch_interval_millis: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_WIREGUARD_INTERFACE",
        default_value = "ipars0"
    )]
    wireguard_interface: String,
    #[arg(
        long,
        env = "IPARS_AGENT_WIREGUARD_BACKEND",
        default_value_t = WireGuardApplyBackend::Command
    )]
    wireguard_backend: WireGuardApplyBackend,
    #[arg(long, env = "IPARS_AGENT_USERSPACE_WIREGUARD_COMMAND")]
    userspace_wireguard_command: Option<String>,
    #[arg(
        long = "userspace-wireguard-arg",
        env = "IPARS_AGENT_USERSPACE_WIREGUARD_ARGS",
        value_delimiter = ','
    )]
    userspace_wireguard_args: Vec<String>,
    #[arg(
        long,
        env = "IPARS_AGENT_USERSPACE_WIREGUARD_READY_TIMEOUT_SECONDS",
        default_value_t = 10
    )]
    userspace_wireguard_ready_timeout_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_USERSPACE_WIREGUARD_SHUTDOWN_TIMEOUT_SECONDS",
        default_value_t = 5
    )]
    userspace_wireguard_shutdown_timeout_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_ROUTE_BACKEND",
        default_value_t = RouteApplyBackend::Command
    )]
    route_backend: RouteApplyBackend,
    #[arg(long, env = "IPARS_AGENT_LINUX_NETNS")]
    linux_netns: Option<String>,
    #[arg(long, env = "IPARS_AGENT_RELAY_FORWARDER_ENDPOINT")]
    relay_forwarder_endpoint: Option<SocketAddr>,
    #[arg(long, env = "IPARS_AGENT_RELAY_FORWARDER_BIND")]
    relay_forwarder_bind: Option<SocketAddr>,
    #[arg(long, env = "IPARS_AGENT_RELAY_FORWARDER_WIREGUARD_ENDPOINT")]
    relay_forwarder_wireguard_endpoint: Option<SocketAddr>,
    #[arg(long, env = "IPARS_AGENT_RELAY_FORWARDER_NETNS")]
    relay_forwarder_netns: Option<String>,
    #[arg(
        long,
        env = "IPARS_AGENT_RELAY_FORWARDER_MAX_SESSIONS",
        default_value_t = 1024
    )]
    relay_forwarder_max_sessions: usize,
    #[arg(
        long,
        env = "IPARS_AGENT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS",
        default_value_t = 5
    )]
    relay_forwarder_restart_backoff_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS",
        default_value_t = 60
    )]
    relay_forwarder_crash_window_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW",
        default_value_t = 3
    )]
    relay_forwarder_max_crashes_per_window: u32,
    #[arg(
        long,
        env = "IPARS_AGENT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS",
        default_value_t = 60
    )]
    relay_forwarder_crash_cooldown_seconds: u64,
    #[arg(
        long,
        env = "IPARS_AGENT_APPLY_KUBERNETES_UNDERLAY",
        default_value_t = false
    )]
    apply_kubernetes_underlay: bool,
    #[arg(long, env = "IPARS_AGENT_APPLY_DOCKER_ROUTES", default_value_t = false)]
    apply_docker_routes: bool,
    #[arg(long, env = "IPARS_DOCKER_DISCOVER_NETWORKS", default_value_t = false)]
    docker_discover_networks: bool,
    #[arg(long, env = "IPARS_DOCKER_API_SOCKET")]
    docker_api_socket: Option<PathBuf>,
    #[arg(long, env = "IPARS_DOCKER_API_VERSION", default_value = "v1.43")]
    docker_api_version: String,
    #[arg(
        long = "docker-network",
        env = "IPARS_DOCKER_NETWORKS",
        value_delimiter = ','
    )]
    docker_networks: Vec<String>,
    #[arg(long, env = "IPARS_DOCKER_CONTAINER_NAMESPACE")]
    docker_container_namespace: Option<String>,
    #[arg(long, env = "IPARS_DOCKER_HOST_INTERFACE", default_value = "docker0")]
    docker_host_interface: String,
    #[arg(
        long = "docker-container-cidr",
        env = "IPARS_DOCKER_CONTAINER_CIDRS",
        value_delimiter = ','
    )]
    docker_container_cidrs: Vec<ipnet::IpNet>,
    #[arg(long, env = "IPARS_DOCKER_EXPOSE_HOST_ROUTES", default_value_t = true)]
    docker_expose_host_routes: bool,
    #[arg(
        long,
        env = "IPARS_DOCKER_ROUTE_INTERVAL_SECONDS",
        default_value_t = 60
    )]
    docker_route_interval_seconds: u64,
    #[arg(long, env = "IPARS_KUBERNETES_NODE_NAME")]
    kubernetes_node_name: Option<String>,
    #[arg(
        long,
        env = "IPARS_KUBERNETES_DISCOVER_SERVICES",
        default_value_t = false
    )]
    kubernetes_discover_services: bool,
    #[arg(long, env = "IPARS_KUBERNETES_API_URL")]
    kubernetes_api_url: Option<String>,
    #[arg(
        long,
        env = "IPARS_KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH",
        default_value = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    )]
    kubernetes_service_account_token_path: PathBuf,
    #[arg(long, env = "IPARS_KUBERNETES_CA_CERT_PATH")]
    kubernetes_ca_cert_path: Option<PathBuf>,
    #[arg(
        long = "kubernetes-namespace",
        env = "IPARS_KUBERNETES_NAMESPACES",
        value_delimiter = ','
    )]
    kubernetes_namespaces: Vec<String>,
    #[arg(long, env = "IPARS_KUBERNETES_SERVICE_LABEL_SELECTOR")]
    kubernetes_service_label_selector: Option<String>,
    #[arg(
        long,
        env = "IPARS_KUBERNETES_DISCOVER_API_SERVER",
        default_value_t = true,
        action = clap::ArgAction::Set
    )]
    kubernetes_discover_api_server: bool,
    #[arg(
        long = "kubernetes-api-server-cidr",
        env = "IPARS_KUBERNETES_API_SERVER_CIDRS",
        value_delimiter = ','
    )]
    kubernetes_api_server_cidrs: Vec<ipnet::IpNet>,
    #[arg(
        long = "kubernetes-service-cidr",
        env = "IPARS_KUBERNETES_SERVICE_CIDRS",
        value_delimiter = ','
    )]
    kubernetes_service_cidrs: Vec<ipnet::IpNet>,
    #[arg(long, env = "IPARS_KUBERNETES_ROUTE_PROVIDER")]
    kubernetes_route_provider: Option<String>,
    #[arg(
        long,
        env = "IPARS_KUBERNETES_ROUTE_INTERVAL_SECONDS",
        default_value_t = 60
    )]
    kubernetes_route_interval_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AgentRuntimeBackend {
    #[value(name = "linux-command")]
    LinuxCommand,
    #[value(name = "dry-run")]
    DryRun,
}

impl AgentRuntimeBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::LinuxCommand => "linux-command",
            Self::DryRun => "dry-run",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum WireGuardApplyBackend {
    Command,
    #[value(name = "kernel-netlink")]
    KernelNetlink,
    #[value(name = "userspace-command")]
    UserspaceCommand,
}

impl WireGuardApplyBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::KernelNetlink => "kernel-netlink",
            Self::UserspaceCommand => "userspace-command",
        }
    }
}

impl std::fmt::Display for WireGuardApplyBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum RouteApplyBackend {
    Command,
    #[value(name = "kernel-netlink")]
    KernelNetlink,
}

impl RouteApplyBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::KernelNetlink => "kernel-netlink",
        }
    }
}

impl std::fmt::Display for RouteApplyBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PacketFlowDetector {
    Disabled,
    #[value(name = "proc-net-conntrack")]
    ProcNetConntrack,
    #[value(name = "conntrack-netlink")]
    ConntrackNetlink,
    #[value(name = "conntrack-netlink-events")]
    ConntrackNetlinkEvents,
    #[value(name = "ebpf-jsonl")]
    EbpfJsonl,
    #[value(name = "ebpf-ringbuf")]
    EbpfRingbuf,
}

impl PacketFlowDetector {
    fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ProcNetConntrack => "proc-net-conntrack",
            Self::ConntrackNetlink => "conntrack-netlink",
            Self::ConntrackNetlinkEvents => "conntrack-netlink-events",
            Self::EbpfJsonl => "ebpf-jsonl",
            Self::EbpfRingbuf => "ebpf-ringbuf",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimePreflightNeeds {
    ip_command: bool,
    wg_command: bool,
    userspace_wireguard_command: bool,
    route_netlink: bool,
    generic_netlink: bool,
    netfilter_netlink: bool,
    docker_api_socket: bool,
    conntrack_procfs_path: bool,
    ebpf_jsonl_event_path: bool,
    ipv4_forwarding: bool,
    ipv6_forwarding: bool,
    cap_net_admin: bool,
    cap_net_raw: bool,
    cap_sys_admin: bool,
    cap_perfmon: bool,
    cap_bpf: bool,
    linux_netns: bool,
    relay_forwarder_netns: bool,
}

impl RuntimePreflightNeeds {
    fn none() -> Self {
        Self {
            ip_command: false,
            wg_command: false,
            userspace_wireguard_command: false,
            route_netlink: false,
            generic_netlink: false,
            netfilter_netlink: false,
            docker_api_socket: false,
            conntrack_procfs_path: false,
            ebpf_jsonl_event_path: false,
            ipv4_forwarding: false,
            ipv6_forwarding: false,
            cap_net_admin: false,
            cap_net_raw: false,
            cap_sys_admin: false,
            cap_perfmon: false,
            cap_bpf: false,
            linux_netns: false,
            relay_forwarder_netns: false,
        }
    }

    fn is_empty(self) -> bool {
        !self.ip_command
            && !self.wg_command
            && !self.userspace_wireguard_command
            && !self.route_netlink
            && !self.generic_netlink
            && !self.netfilter_netlink
            && !self.docker_api_socket
            && !self.conntrack_procfs_path
            && !self.ebpf_jsonl_event_path
            && !self.ipv4_forwarding
            && !self.ipv6_forwarding
            && !self.cap_net_admin
            && !self.cap_net_raw
            && !self.cap_sys_admin
            && !self.cap_perfmon
            && !self.cap_bpf
            && !self.linux_netns
            && !self.relay_forwarder_netns
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeNetlinkProtocol {
    Route,
    Generic,
    Netfilter,
}

impl RuntimeNetlinkProtocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Route => "NETLINK_ROUTE",
            Self::Generic => "NETLINK_GENERIC",
            Self::Netfilter => "NETLINK_NETFILTER",
        }
    }

    fn protocol(self) -> isize {
        match self {
            Self::Route => NETLINK_ROUTE,
            Self::Generic => NETLINK_GENERIC,
            Self::Netfilter => NETLINK_NETFILTER,
        }
    }
}

#[derive(Clone, Copy)]
struct RuntimePreflightChecks {
    cap_net_admin: fn() -> anyhow::Result<()>,
    cap_net_raw: fn() -> anyhow::Result<()>,
    cap_sys_admin: fn() -> anyhow::Result<()>,
    cap_perfmon: fn() -> anyhow::Result<()>,
    cap_bpf: fn() -> anyhow::Result<()>,
    ebpf_object: fn(&Path) -> anyhow::Result<()>,
    ebpf_tracepoint: fn(&EbpfTracepointAttachSpec) -> anyhow::Result<()>,
    linux_netns: fn(&LinuxNetworkNamespace) -> anyhow::Result<()>,
    relay_forwarder_netns: fn(&LinuxNetworkNamespace) -> anyhow::Result<()>,
    netlink: fn(RuntimeNetlinkProtocol) -> anyhow::Result<()>,
    docker_api_socket: fn(&Path) -> anyhow::Result<()>,
    conntrack_procfs_path: fn(&Path) -> anyhow::Result<()>,
    ipv4_forwarding: fn() -> anyhow::Result<()>,
    ipv6_forwarding: fn() -> anyhow::Result<()>,
}

impl RuntimePreflightChecks {
    const fn system() -> Self {
        Self {
            cap_net_admin: ensure_cap_net_admin_if_known,
            cap_net_raw: ensure_cap_net_raw_if_known,
            cap_sys_admin: ensure_cap_sys_admin_if_known,
            cap_perfmon: ensure_cap_perfmon_if_known,
            cap_bpf: ensure_cap_bpf_if_known,
            ebpf_object: ensure_ebpf_object_file_ready,
            ebpf_tracepoint: ensure_ebpf_tracepoint_ready,
            linux_netns: ensure_linux_netns_ready,
            relay_forwarder_netns: ensure_relay_forwarder_netns_ready,
            netlink: ensure_netlink_protocol_ready,
            docker_api_socket: ensure_docker_api_socket_ready,
            conntrack_procfs_path: ensure_conntrack_procfs_path_ready,
            ipv4_forwarding: ensure_ipv4_forwarding_if_known,
            ipv6_forwarding: ensure_ipv6_forwarding_if_known,
        }
    }
}

fn preflight_agent_runtime(args: &AgentArgs) -> anyhow::Result<()> {
    let path = std::env::var_os("PATH");
    preflight_agent_runtime_with_path(args, path.as_deref())
}

fn init_observability(
    args: &ObservabilityArgs,
    component: &str,
) -> anyhow::Result<ObservabilityGuard> {
    let filter = EnvFilter::try_new(args.log_filter.as_str())
        .with_context(|| format!("invalid tracing filter `{}`", args.log_filter))?;
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_names(true)
        .with_filter(filter);

    if !args.otel_active() {
        tracing_subscriber::registry()
            .with(fmt_layer)
            .try_init()
            .context("failed to initialize tracing subscriber")?;
        return Ok(ObservabilityGuard::default());
    }

    let service_name = args.service_name(component);
    let resource = Resource::builder()
        .with_service_name(service_name)
        .with_attribute(KeyValue::new("service.namespace", "ipars"))
        .with_attribute(KeyValue::new("ipars.component", component.to_string()))
        .build();

    let span_exporter = build_span_exporter(args.otel_endpoint.as_deref())?;
    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_batch_exporter(span_exporter)
        .build();
    let tracer = tracer_provider.tracer("iparsd");
    let traces_layer = tracing_opentelemetry::layer()
        .with_tracer(tracer)
        .with_filter(EnvFilter::try_new(args.log_filter.as_str())?);

    let log_exporter = build_log_exporter(args.otel_endpoint.as_deref())?;
    let logger_provider = SdkLoggerProvider::builder()
        .with_resource(resource.clone())
        .with_batch_exporter(log_exporter)
        .build();
    let logs_layer = OpenTelemetryTracingBridge::new(&logger_provider)
        .with_filter(EnvFilter::try_new(args.log_filter.as_str())?);

    let metric_exporter = build_metric_exporter(args.otel_endpoint.as_deref())?;
    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_periodic_exporter(metric_exporter)
        .build();
    global::set_meter_provider(meter_provider.clone());

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(traces_layer)
        .with(logs_layer)
        .try_init()
        .context("failed to initialize tracing subscriber")?;

    Ok(ObservabilityGuard {
        tracer_provider: Some(tracer_provider),
        logger_provider: Some(logger_provider),
        meter_provider: Some(meter_provider),
    })
}

fn build_span_exporter(endpoint: Option<&str>) -> anyhow::Result<opentelemetry_otlp::SpanExporter> {
    let builder = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary);
    let builder = if let Some(endpoint) = endpoint {
        builder.with_endpoint(otlp_http_signal_endpoint(endpoint, "traces"))
    } else {
        builder
    };
    builder
        .build()
        .context("failed to build OTLP span exporter")
}

fn build_log_exporter(endpoint: Option<&str>) -> anyhow::Result<opentelemetry_otlp::LogExporter> {
    let builder = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary);
    let builder = if let Some(endpoint) = endpoint {
        builder.with_endpoint(otlp_http_signal_endpoint(endpoint, "logs"))
    } else {
        builder
    };
    builder.build().context("failed to build OTLP log exporter")
}

fn build_metric_exporter(
    endpoint: Option<&str>,
) -> anyhow::Result<opentelemetry_otlp::MetricExporter> {
    let builder = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary);
    let builder = if let Some(endpoint) = endpoint {
        builder.with_endpoint(otlp_http_signal_endpoint(endpoint, "metrics"))
    } else {
        builder
    };
    builder
        .build()
        .context("failed to build OTLP metric exporter")
}

fn otlp_http_signal_endpoint(base_endpoint: &str, signal: &str) -> String {
    format!("{}/v1/{signal}", base_endpoint.trim_end_matches('/'))
}

fn preflight_agent_runtime_with_path(args: &AgentArgs, path: Option<&OsStr>) -> anyhow::Result<()> {
    preflight_agent_runtime_with_path_and_checks(args, path, RuntimePreflightChecks::system())
}

fn preflight_agent_runtime_with_path_and_checks(
    args: &AgentArgs,
    path: Option<&OsStr>,
    checks: RuntimePreflightChecks,
) -> anyhow::Result<()> {
    validate_agent_runtime_config(args)?;
    if args.skip_runtime_preflight {
        tracing::warn!(
            backend = args.runtime_backend.as_str(),
            "skipping runtime backend preflight by operator request"
        );
        return Ok(());
    }

    let needs = runtime_preflight_needs(args);
    if needs.is_empty() {
        return Ok(());
    }
    if needs.ip_command {
        ensure_program_in_path("ip", path)?;
    }
    if needs.wg_command {
        ensure_program_in_path("wg", path)?;
    }
    if needs.userspace_wireguard_command {
        let command = args
            .userspace_wireguard_command
            .as_deref()
            .context("userspace WireGuard command preflight requested without command")?;
        ensure_runtime_program_ready(command, path)?;
    }
    if needs.route_netlink {
        (checks.netlink)(RuntimeNetlinkProtocol::Route)?;
    }
    if needs.generic_netlink {
        (checks.netlink)(RuntimeNetlinkProtocol::Generic)?;
    }
    if needs.netfilter_netlink {
        (checks.netlink)(RuntimeNetlinkProtocol::Netfilter)?;
    }
    if needs.docker_api_socket {
        let socket = docker_api_socket_path(args)?;
        (checks.docker_api_socket)(&socket)?;
    }
    if needs.conntrack_procfs_path {
        let path = args
            .packet_flow_conntrack_path
            .as_deref()
            .context("--packet-flow-conntrack-path is required")?;
        (checks.conntrack_procfs_path)(path)?;
    }
    if needs.ebpf_jsonl_event_path {
        let event_path = args
            .packet_flow_ebpf_event_path
            .as_deref()
            .context("--packet-flow-ebpf-event-path is required")?;
        ensure_ebpf_jsonl_event_path_ready(event_path)?;
    }
    if needs.ipv4_forwarding {
        (checks.ipv4_forwarding)()?;
    }
    if needs.ipv6_forwarding {
        (checks.ipv6_forwarding)()?;
    }
    if needs.cap_net_admin {
        (checks.cap_net_admin)()?;
    }
    if needs.cap_net_raw {
        (checks.cap_net_raw)()?;
    }
    if needs.cap_sys_admin {
        (checks.cap_sys_admin)()?;
    }
    if needs.cap_perfmon {
        (checks.cap_perfmon)()?;
    }
    if needs.cap_bpf {
        (checks.cap_bpf)()?;
    }
    if args.packet_flow_detector == PacketFlowDetector::EbpfRingbuf {
        let config = EbpfRingbufConfig::from_args(args)?;
        (checks.ebpf_object)(&config.object_path)?;
        for attachment in &config.attachments {
            (checks.ebpf_tracepoint)(attachment)?;
        }
    }
    if needs.linux_netns {
        let namespace_name = args
            .linux_netns
            .as_deref()
            .context("linux namespace preflight requested without --linux-netns")?;
        let namespace = LinuxNetworkNamespace::from_name(namespace_name)?;
        (checks.linux_netns)(&namespace)?;
    }
    if needs.relay_forwarder_netns {
        let namespace_name = args
            .relay_forwarder_netns
            .as_deref()
            .or(args.linux_netns.as_deref())
            .context("relay forwarder namespace preflight requested without --relay-forwarder-netns or --linux-netns")?;
        let namespace = LinuxNetworkNamespace::from_name(namespace_name)?;
        (checks.relay_forwarder_netns)(&namespace)?;
    }

    tracing::info!(
        backend = args.runtime_backend.as_str(),
        wireguard_backend = args.wireguard_backend.as_str(),
        route_backend = args.route_backend.as_str(),
        needs_ip = needs.ip_command,
        needs_wg = needs.wg_command,
        needs_userspace_wireguard_command = needs.userspace_wireguard_command,
        needs_route_netlink = needs.route_netlink,
        needs_generic_netlink = needs.generic_netlink,
        needs_netfilter_netlink = needs.netfilter_netlink,
        needs_docker_api_socket = needs.docker_api_socket,
        needs_conntrack_procfs_path = needs.conntrack_procfs_path,
        needs_ebpf_jsonl_event_path = needs.ebpf_jsonl_event_path,
        needs_ipv4_forwarding = needs.ipv4_forwarding,
        needs_ipv6_forwarding = needs.ipv6_forwarding,
        needs_cap_net_admin = needs.cap_net_admin,
        needs_cap_net_raw = needs.cap_net_raw,
        needs_cap_sys_admin = needs.cap_sys_admin,
        needs_cap_perfmon = needs.cap_perfmon,
        needs_cap_bpf = needs.cap_bpf,
        needs_relay_forwarder_netns = needs.relay_forwarder_netns,
        linux_netns = ?args.linux_netns,
        relay_forwarder_netns = ?args.relay_forwarder_netns,
        "runtime backend preflight passed"
    );
    Ok(())
}

fn validate_agent_runtime_config(args: &AgentArgs) -> anyhow::Result<()> {
    validate_linux_interface_name(&args.wireguard_interface)?;
    if !args.disable_heartbeat {
        validate_positive_seconds(
            args.heartbeat_interval_seconds,
            "--heartbeat-interval-seconds",
        )?;
    }
    if args.apply_peer_map {
        validate_positive_seconds(
            args.peer_map_poll_interval_seconds,
            "--peer-map-poll-interval-seconds",
        )?;
    }
    if !args.disable_signal_registration {
        validate_positive_seconds(
            args.signal_registration_interval_seconds,
            "--signal-registration-interval-seconds",
        )?;
    }
    if !args.disable_signal_paths {
        validate_positive_seconds(
            args.signal_path_interval_seconds,
            "--signal-path-interval-seconds",
        )?;
        validate_positive_seconds(
            args.relay_session_renew_before_seconds,
            "--relay-session-renew-before-seconds",
        )?;
        validate_positive_usize(args.hole_punch_attempts, "--hole-punch-attempts")?;
        validate_positive_millis(
            args.hole_punch_interval_millis,
            "--hole-punch-interval-millis",
        )?;
    }
    validate_bounded_u64(
        args.runtime_command_timeout_seconds,
        "--runtime-command-timeout-seconds",
        MAX_RUNTIME_COMMAND_TIMEOUT_SECONDS,
    )?;
    validate_userspace_wireguard_config(args)?;
    validate_runtime_backend_specific_args(args)?;
    validate_positive_usize(
        args.runtime_command_output_max_bytes,
        "--runtime-command-output-max-bytes",
    )?;
    anyhow::ensure!(
        args.runtime_command_output_max_bytes <= MAX_RUNTIME_COMMAND_OUTPUT_MAX_BYTES,
        "--runtime-command-output-max-bytes must not exceed {MAX_RUNTIME_COMMAND_OUTPUT_MAX_BYTES}"
    );
    if args.packet_flow_detector != PacketFlowDetector::Disabled {
        validate_positive_seconds(
            args.packet_flow_poll_interval_seconds,
            "--packet-flow-poll-interval-seconds",
        )?;
    }
    validate_packet_flow_dedup_ttl_seconds(args.packet_flow_dedup_ttl_seconds)?;
    validate_packet_flow_detector_specific_args(args)?;
    if args.packet_flow_detector == PacketFlowDetector::ProcNetConntrack {
        validate_bounded_u64(
            args.packet_flow_procfs_max_bytes,
            "--packet-flow-procfs-max-bytes",
            MAX_PACKET_FLOW_READ_BYTES,
        )?;
        validate_bounded_usize(
            args.packet_flow_procfs_max_line_bytes,
            "--packet-flow-procfs-max-line-bytes",
            MAX_PACKET_FLOW_LINE_BYTES,
        )?;
        validate_bounded_usize(
            args.packet_flow_procfs_max_flows,
            "--packet-flow-procfs-max-flows",
            MAX_PACKET_FLOW_RECORDS,
        )?;
    }
    if matches!(
        args.packet_flow_detector,
        PacketFlowDetector::ConntrackNetlink | PacketFlowDetector::ConntrackNetlinkEvents
    ) {
        validate_bounded_usize(
            args.packet_flow_netlink_max_flows,
            "--packet-flow-netlink-max-flows",
            MAX_PACKET_FLOW_RECORDS,
        )?;
    }
    if args.packet_flow_detector == PacketFlowDetector::EbpfJsonl {
        anyhow::ensure!(
            args.packet_flow_ebpf_event_path.is_some(),
            "--packet-flow-ebpf-event-path is required when --packet-flow-detector ebpf-jsonl is set"
        );
        validate_bounded_u64(
            args.packet_flow_ebpf_event_max_bytes,
            "--packet-flow-ebpf-event-max-bytes",
            MAX_PACKET_FLOW_READ_BYTES,
        )?;
        validate_bounded_usize(
            args.packet_flow_ebpf_event_max_line_bytes,
            "--packet-flow-ebpf-event-max-line-bytes",
            MAX_PACKET_FLOW_LINE_BYTES,
        )?;
        validate_bounded_usize(
            args.packet_flow_ebpf_event_max_flows,
            "--packet-flow-ebpf-event-max-flows",
            MAX_PACKET_FLOW_RECORDS,
        )?;
    }
    if args.packet_flow_detector == PacketFlowDetector::EbpfRingbuf {
        anyhow::ensure!(
            args.packet_flow_ebpf_object_path.is_some(),
            "--packet-flow-ebpf-object-path is required when --packet-flow-detector ebpf-ringbuf is set"
        );
        validate_ebpf_identifier(
            &args.packet_flow_ebpf_ringbuf_map,
            "--packet-flow-ebpf-ringbuf-map",
        )?;
        anyhow::ensure!(
            !args.packet_flow_ebpf_attach.is_empty(),
            "--packet-flow-ebpf-attach must be set at least once when --packet-flow-detector ebpf-ringbuf is set"
        );
        validate_packet_flow_ebpf_attach_specs(&args.packet_flow_ebpf_attach)?;
        validate_bounded_usize(
            args.packet_flow_ebpf_ringbuf_max_events,
            "--packet-flow-ebpf-ringbuf-max-events",
            MAX_PACKET_FLOW_EBPF_RINGBUF_EVENTS_PER_WAKE,
        )?;
    }
    if args.apply_docker_routes {
        validate_linux_interface_name(&args.docker_host_interface)?;
        validate_positive_seconds(
            args.docker_route_interval_seconds,
            "--docker-route-interval-seconds",
        )?;
        if let Some(namespace) = args.docker_container_namespace.as_deref() {
            LinuxNetworkNamespace::from_name(namespace)?;
        }
        if args.docker_discover_networks {
            validate_docker_discovery_config(args)?;
        } else if args.docker_api_socket.is_some() {
            anyhow::bail!("--docker-api-socket requires --docker-discover-networks");
        } else if !args.docker_networks.is_empty() {
            anyhow::bail!("--docker-network requires --docker-discover-networks");
        } else {
            anyhow::ensure!(
                args.docker_container_namespace.is_some(),
                "--apply-docker-routes requires --docker-container-namespace unless --docker-discover-networks is set"
            );
            anyhow::ensure!(
                !args.docker_container_cidrs.is_empty(),
                "--apply-docker-routes requires at least one --docker-container-cidr unless --docker-discover-networks is set"
            );
            validate_docker_container_cidrs(
                "--docker-container-cidr",
                &args.docker_container_cidrs,
            )?;
        }
    } else {
        validate_inactive_docker_route_config(args)?;
    }
    if args.apply_kubernetes_underlay {
        validate_kubernetes_underlay_config(args)?;
    }
    if let Some(namespace) = args.linux_netns.as_deref() {
        LinuxNetworkNamespace::from_name(namespace)?;
    }
    if let Some(namespace) = args.relay_forwarder_netns.as_deref() {
        LinuxNetworkNamespace::from_name(namespace)?;
    }
    validate_agent_relay_capability_config(args)?;
    validate_relay_forwarder_config(args)?;
    if let Some(token) = args.relay_admission_bearer_token.as_deref() {
        validate_relay_admission_bearer_token(token, "--relay-admission-bearer-token")?;
    }
    Ok(())
}

fn validate_runtime_backend_specific_args(args: &AgentArgs) -> anyhow::Result<()> {
    let applies_wireguard = args.apply_peer_map;
    let applies_routes =
        args.apply_peer_map || args.apply_docker_routes || args.apply_kubernetes_underlay;
    let manages_userspace_wireguard = args.userspace_wireguard_command.is_some();
    let uses_relay_forwarder_namespace = args.relay_forwarder_bind.is_some();

    if args.runtime_backend != AgentRuntimeBackend::LinuxCommand {
        anyhow::ensure!(
            args.wireguard_backend == WireGuardApplyBackend::Command,
            "--wireguard-backend requires --runtime-backend linux-command"
        );
        anyhow::ensure!(
            args.route_backend == RouteApplyBackend::Command,
            "--route-backend requires --runtime-backend linux-command"
        );
    }

    if args.wireguard_backend == WireGuardApplyBackend::KernelNetlink {
        anyhow::ensure!(
            applies_wireguard,
            "--wireguard-backend kernel-netlink requires --apply-peer-map"
        );
    }
    if args.wireguard_backend == WireGuardApplyBackend::UserspaceCommand {
        anyhow::ensure!(
            applies_wireguard || manages_userspace_wireguard,
            "--wireguard-backend userspace-command requires --apply-peer-map or --userspace-wireguard-command"
        );
    }
    if args.route_backend == RouteApplyBackend::KernelNetlink {
        anyhow::ensure!(
            applies_routes,
            "--route-backend kernel-netlink requires --apply-peer-map, --apply-docker-routes, or --apply-kubernetes-underlay"
        );
    }
    if args.linux_netns.is_some() {
        let uses_linux_netns = args.runtime_backend == AgentRuntimeBackend::LinuxCommand
            && (applies_routes || manages_userspace_wireguard);
        anyhow::ensure!(
            uses_linux_netns || uses_relay_forwarder_namespace,
            "--linux-netns requires an active Linux dataplane loop, --userspace-wireguard-command, or --relay-forwarder-bind"
        );
    }

    Ok(())
}

fn validate_packet_flow_ebpf_attach_specs(values: &[String]) -> anyhow::Result<()> {
    let _ = parse_packet_flow_ebpf_attach_specs(values)?;
    Ok(())
}

fn parse_packet_flow_ebpf_attach_specs(
    values: &[String],
) -> anyhow::Result<Vec<EbpfTracepointAttachSpec>> {
    anyhow::ensure!(
        values.len() <= MAX_PACKET_FLOW_EBPF_ATTACH_SPECS,
        "--packet-flow-ebpf-attach may be repeated at most {MAX_PACKET_FLOW_EBPF_ATTACH_SPECS} times"
    );
    let mut seen = BTreeSet::new();
    let mut specs = Vec::with_capacity(values.len());
    for value in values {
        let spec = EbpfTracepointAttachSpec::parse(value)?;
        let key = (
            spec.program.clone(),
            spec.category.clone(),
            spec.name.clone(),
        );
        anyhow::ensure!(
            seen.insert(key.clone()),
            "--packet-flow-ebpf-attach must not repeat {}:{}:{}",
            key.0,
            key.1,
            key.2
        );
        specs.push(spec);
    }
    Ok(specs)
}

fn validate_packet_flow_detector_specific_args(args: &AgentArgs) -> anyhow::Result<()> {
    if args.packet_flow_detector != PacketFlowDetector::ProcNetConntrack {
        anyhow::ensure!(
            args.packet_flow_conntrack_path.is_none(),
            "--packet-flow-conntrack-path requires --packet-flow-detector proc-net-conntrack"
        );
    }
    if args.packet_flow_detector != PacketFlowDetector::EbpfJsonl {
        anyhow::ensure!(
            args.packet_flow_ebpf_event_path.is_none(),
            "--packet-flow-ebpf-event-path requires --packet-flow-detector ebpf-jsonl"
        );
    }
    if args.packet_flow_detector != PacketFlowDetector::EbpfRingbuf {
        anyhow::ensure!(
            args.packet_flow_ebpf_object_path.is_none(),
            "--packet-flow-ebpf-object-path requires --packet-flow-detector ebpf-ringbuf"
        );
        anyhow::ensure!(
            args.packet_flow_ebpf_attach.is_empty(),
            "--packet-flow-ebpf-attach requires --packet-flow-detector ebpf-ringbuf"
        );
    }
    if args.packet_flow_detector == PacketFlowDetector::Disabled {
        anyhow::ensure!(
            !args.packet_flow_pin,
            "--packet-flow-pin requires --packet-flow-detector to be enabled"
        );
    }
    Ok(())
}

fn validate_packet_flow_dedup_ttl_seconds(value: u64) -> anyhow::Result<()> {
    if value > MAX_PACKET_FLOW_DEDUP_TTL_SECONDS {
        anyhow::bail!(
            "--packet-flow-dedup-ttl-seconds must not exceed {MAX_PACKET_FLOW_DEDUP_TTL_SECONDS}"
        );
    }
    Ok(())
}

fn validate_relay_forwarder_config(args: &AgentArgs) -> anyhow::Result<()> {
    if let Some(endpoint) = args.relay_forwarder_endpoint {
        validate_usable_socket_endpoint(endpoint, "--relay-forwarder-endpoint")?;
    }

    if args.relay_forwarder_bind.is_some() {
        let wireguard_endpoint = args.relay_forwarder_wireguard_endpoint.context(
            "--relay-forwarder-wireguard-endpoint is required with --relay-forwarder-bind",
        )?;
        validate_usable_socket_endpoint(
            wireguard_endpoint,
            "--relay-forwarder-wireguard-endpoint",
        )?;
        validate_positive_usize(
            args.relay_forwarder_max_sessions,
            "--relay-forwarder-max-sessions",
        )?;
        validate_positive_seconds(
            args.relay_forwarder_restart_backoff_seconds,
            "--relay-forwarder-restart-backoff-seconds",
        )?;
        validate_positive_seconds(
            args.relay_forwarder_crash_window_seconds,
            "--relay-forwarder-crash-window-seconds",
        )?;
        if args.relay_forwarder_max_crashes_per_window == 0 {
            anyhow::bail!("--relay-forwarder-max-crashes-per-window must be greater than zero");
        }
        validate_positive_seconds(
            args.relay_forwarder_crash_cooldown_seconds,
            "--relay-forwarder-crash-cooldown-seconds",
        )?;
    } else {
        anyhow::ensure!(
            args.relay_forwarder_wireguard_endpoint.is_none(),
            "--relay-forwarder-wireguard-endpoint requires --relay-forwarder-bind"
        );
        anyhow::ensure!(
            args.relay_forwarder_netns.is_none(),
            "--relay-forwarder-netns requires --relay-forwarder-bind"
        );
    }

    Ok(())
}

fn validate_usable_socket_endpoint(endpoint: SocketAddr, label: &str) -> anyhow::Result<()> {
    if !endpoint_addr_is_usable(endpoint) {
        anyhow::bail!(
            "{label} must use a usable nonzero, non-unspecified, non-multicast, non-broadcast socket address"
        );
    }
    Ok(())
}

fn validate_userspace_wireguard_config(args: &AgentArgs) -> anyhow::Result<()> {
    validate_bounded_u64(
        args.userspace_wireguard_ready_timeout_seconds,
        "--userspace-wireguard-ready-timeout-seconds",
        MAX_USERSPACE_WIREGUARD_LIFECYCLE_TIMEOUT_SECONDS,
    )?;
    validate_bounded_u64(
        args.userspace_wireguard_shutdown_timeout_seconds,
        "--userspace-wireguard-shutdown-timeout-seconds",
        MAX_USERSPACE_WIREGUARD_LIFECYCLE_TIMEOUT_SECONDS,
    )?;

    let has_userspace_process_config =
        args.userspace_wireguard_command.is_some() || !args.userspace_wireguard_args.is_empty();
    if !has_userspace_process_config {
        return Ok(());
    }
    anyhow::ensure!(
        args.runtime_backend == AgentRuntimeBackend::LinuxCommand,
        "--userspace-wireguard-command and --userspace-wireguard-arg require --runtime-backend linux-command"
    );
    anyhow::ensure!(
        args.wireguard_backend == WireGuardApplyBackend::UserspaceCommand,
        "--userspace-wireguard-command and --userspace-wireguard-arg require --wireguard-backend userspace-command"
    );
    if let Some(command) = args.userspace_wireguard_command.as_deref() {
        validate_runtime_program_token(command, "--userspace-wireguard-command")?;
    } else {
        anyhow::bail!("--userspace-wireguard-arg requires --userspace-wireguard-command");
    }
    anyhow::ensure!(
        args.userspace_wireguard_args.len() <= MAX_USERSPACE_WIREGUARD_ARGS,
        "--userspace-wireguard-arg may be repeated at most {MAX_USERSPACE_WIREGUARD_ARGS} times"
    );
    for argument in &args.userspace_wireguard_args {
        if argument.is_empty() {
            anyhow::bail!("--userspace-wireguard-arg cannot be empty");
        }
        if argument.len() > MAX_USERSPACE_WIREGUARD_ARG_BYTES {
            anyhow::bail!(
                "--userspace-wireguard-arg exceeds {MAX_USERSPACE_WIREGUARD_ARG_BYTES} bytes"
            );
        }
        if argument.chars().any(char::is_control) {
            anyhow::bail!("--userspace-wireguard-arg must not contain control characters");
        }
    }
    Ok(())
}

fn validate_runtime_program_token(value: &str, label: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("{label} cannot be empty");
    }
    if value.len() > MAX_RUNTIME_PROGRAM_TOKEN_BYTES {
        anyhow::bail!("{label} exceeds {MAX_RUNTIME_PROGRAM_TOKEN_BYTES} bytes");
    }
    if value.chars().any(char::is_control) {
        anyhow::bail!("{label} must not contain control characters");
    }
    if value.chars().any(char::is_whitespace) {
        anyhow::bail!("{label} must not contain whitespace");
    }
    if value.contains('/') && !Path::new(value).is_absolute() {
        anyhow::bail!("{label} must be a bare command name or an absolute path");
    }
    validate_runtime_program_name(value, label)?;
    Ok(())
}

fn validate_runtime_program_name(value: &str, label: &str) -> anyhow::Result<()> {
    let program_name = if value.contains('/') {
        let program_path = Path::new(value);
        if value
            .split('/')
            .any(|component| matches!(component, "." | ".."))
        {
            anyhow::bail!("{label} path must not contain '.' or '..' components");
        }
        program_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("{label} path must name an executable"))?
    } else {
        value
    };
    if matches!(program_name, "." | "..") {
        anyhow::bail!("{label} program name must not be '.' or '..'");
    }
    if program_name.starts_with('-') {
        anyhow::bail!("{label} program name must not start with '-'");
    }
    Ok(())
}

fn validate_positive_seconds(value: u64, name: &str) -> anyhow::Result<()> {
    if value == 0 {
        anyhow::bail!("{name} must be greater than zero");
    }
    Ok(())
}

fn validate_positive_millis(value: u64, name: &str) -> anyhow::Result<()> {
    if value == 0 {
        anyhow::bail!("{name} must be greater than zero");
    }
    Ok(())
}

fn validate_percent(value: u8, name: &str) -> anyhow::Result<()> {
    if value > 100 {
        anyhow::bail!("{name} must be between 0 and 100");
    }
    Ok(())
}

fn validate_positive_usize(value: usize, name: &str) -> anyhow::Result<()> {
    if value == 0 {
        anyhow::bail!("{name} must be greater than zero");
    }
    Ok(())
}

fn validate_bounded_u64(value: u64, name: &str, max: u64) -> anyhow::Result<()> {
    if value == 0 {
        anyhow::bail!("{name} must be greater than zero");
    }
    if value > max {
        anyhow::bail!("{name} must not exceed {max}");
    }
    Ok(())
}

fn validate_bounded_usize(value: usize, name: &str, max: usize) -> anyhow::Result<()> {
    if value == 0 {
        anyhow::bail!("{name} must be greater than zero");
    }
    if value > max {
        anyhow::bail!("{name} must not exceed {max}");
    }
    Ok(())
}

fn validate_relay_admission_bearer_token(value: &str, name: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("{name} cannot be empty");
    }
    if value.len() > MAX_RELAY_ADMISSION_BEARER_TOKEN_BYTES {
        anyhow::bail!("{name} exceeds {MAX_RELAY_ADMISSION_BEARER_TOKEN_BYTES} bytes");
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        anyhow::bail!("{name} must not contain whitespace or control characters");
    }
    Ok(())
}

fn validate_daemon_identifier(value: &str, name: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("{name} cannot be empty");
    }
    if value.len() > MAX_DAEMON_IDENTIFIER_BYTES {
        anyhow::bail!("{name} exceeds {MAX_DAEMON_IDENTIFIER_BYTES} bytes");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        anyhow::bail!("{name} must contain only ASCII letters, digits, '_', '.' or '-'");
    }
    Ok(())
}

fn validate_ebpf_identifier(value: &str, name: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("{name} cannot be empty");
    }
    if value.len() > 255 {
        anyhow::bail!("{name} `{value}` exceeds 255 bytes");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        anyhow::bail!("{name} `{value}` must contain only ASCII letters, digits, '_', '.' or '-'");
    }
    Ok(())
}

fn validate_agent_relay_capability_config(args: &AgentArgs) -> anyhow::Result<()> {
    let advertises_relay =
        args.relay_public_endpoint.is_some() || args.relay_admission_url.is_some();
    if args.relay_status_url.is_some() && !advertises_relay {
        anyhow::bail!(
            "--relay-status-url requires --relay-public-endpoint and --relay-admission-url"
        );
    }
    if !advertises_relay {
        return Ok(());
    }
    if args.relay_public_endpoint.is_none() || args.relay_admission_url.is_none() {
        anyhow::bail!(
            "--relay-public-endpoint and --relay-admission-url must be set together for relay capability advertisement"
        );
    }
    if let Some(public_endpoint) = args.relay_public_endpoint {
        validate_usable_socket_endpoint(public_endpoint, "--relay-public-endpoint")?;
    }
    if let Some(admission_url) = args.relay_admission_url.as_deref() {
        validate_http_url(admission_url, "--relay-admission-url")?;
    }
    if let Some(status_url) = args.relay_status_url.as_deref() {
        validate_http_url(status_url, "--relay-status-url")?;
    }
    if args.relay_max_sessions == 0 {
        anyhow::bail!(
            "--relay-max-sessions must be greater than zero when relay capability is advertised"
        );
    }
    if args.relay_max_mbps == 0 {
        anyhow::bail!(
            "--relay-max-mbps must be greater than zero when relay capability is advertised"
        );
    }
    Ok(())
}

fn validate_http_url(value: &str, name: &str) -> anyhow::Result<()> {
    let url =
        reqwest::Url::parse(value).with_context(|| format!("{name} must be an absolute URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        anyhow::bail!("{name} must use http or https");
    }
    if url.host_str().is_none() {
        anyhow::bail!("{name} must include a host");
    }
    if !http_url_is_usable_endpoint(value) {
        anyhow::bail!(
            "{name} must use a nonzero port and a usable non-unspecified, non-multicast, non-broadcast numeric host"
        );
    }
    Ok(())
}

fn runtime_preflight_needs(args: &AgentArgs) -> RuntimePreflightNeeds {
    let netfilter_netlink = matches!(
        args.packet_flow_detector,
        PacketFlowDetector::ConntrackNetlink | PacketFlowDetector::ConntrackNetlinkEvents
    );
    let conntrack_procfs_path = args.packet_flow_detector == PacketFlowDetector::ProcNetConntrack
        && args.packet_flow_conntrack_path.is_some();
    let ebpf_ringbuf = args.packet_flow_detector == PacketFlowDetector::EbpfRingbuf;
    let ebpf_jsonl = args.packet_flow_detector == PacketFlowDetector::EbpfJsonl;
    let docker_api_socket = args.apply_docker_routes && args.docker_discover_networks;
    let relay_forwarder_netns = args.relay_forwarder_bind.is_some()
        && (args.relay_forwarder_netns.is_some() || args.linux_netns.is_some());
    if args.runtime_backend == AgentRuntimeBackend::DryRun {
        return RuntimePreflightNeeds {
            netfilter_netlink,
            docker_api_socket,
            conntrack_procfs_path,
            ebpf_jsonl_event_path: ebpf_jsonl,
            cap_net_admin: netfilter_netlink,
            cap_sys_admin: relay_forwarder_netns,
            cap_perfmon: ebpf_ringbuf,
            cap_bpf: ebpf_ringbuf,
            relay_forwarder_netns,
            ..RuntimePreflightNeeds::none()
        };
    }
    if args.runtime_backend != AgentRuntimeBackend::LinuxCommand {
        return RuntimePreflightNeeds {
            docker_api_socket,
            conntrack_procfs_path,
            ebpf_jsonl_event_path: ebpf_jsonl,
            cap_sys_admin: relay_forwarder_netns,
            relay_forwarder_netns,
            ..RuntimePreflightNeeds::none()
        };
    }
    let applies_routes =
        args.apply_peer_map || args.apply_docker_routes || args.apply_kubernetes_underlay;
    let applies_wireguard = args.apply_peer_map;
    let applies_routes_with_command =
        applies_routes && args.route_backend == RouteApplyBackend::Command;
    let applies_wireguard_with_command =
        applies_wireguard && args.wireguard_backend == WireGuardApplyBackend::Command;
    let applies_wireguard_with_userspace_command =
        applies_wireguard && args.wireguard_backend == WireGuardApplyBackend::UserspaceCommand;
    let applies_routes_with_netlink =
        applies_routes && args.route_backend == RouteApplyBackend::KernelNetlink;
    let applies_wireguard_with_netlink =
        applies_wireguard && args.wireguard_backend == WireGuardApplyBackend::KernelNetlink;
    let starts_userspace_wireguard = args.userspace_wireguard_command.is_some();
    let uses_namespaced_userspace_wireguard_commands = args.linux_netns.is_some()
        && (applies_wireguard_with_userspace_command || starts_userspace_wireguard);
    let ipv4_forwarding = agent_routes_may_forward_ipv4(args);
    let ipv6_forwarding = agent_routes_may_forward_ipv6(args);
    RuntimePreflightNeeds {
        ip_command: applies_routes_with_command
            || applies_wireguard_with_command
            || uses_namespaced_userspace_wireguard_commands,
        wg_command: applies_wireguard_with_command
            || applies_wireguard_with_userspace_command
            || starts_userspace_wireguard,
        userspace_wireguard_command: starts_userspace_wireguard,
        route_netlink: applies_routes_with_netlink || applies_wireguard_with_netlink,
        generic_netlink: applies_wireguard_with_netlink,
        netfilter_netlink,
        docker_api_socket,
        conntrack_procfs_path,
        ebpf_jsonl_event_path: ebpf_jsonl,
        ipv4_forwarding,
        ipv6_forwarding,
        cap_net_admin: applies_routes
            || (applies_wireguard && !applies_wireguard_with_userspace_command)
            || netfilter_netlink,
        cap_net_raw: applies_wireguard && !applies_wireguard_with_userspace_command,
        cap_sys_admin: (args.linux_netns.is_some()
            && (applies_routes || applies_wireguard || starts_userspace_wireguard))
            || relay_forwarder_netns,
        cap_perfmon: ebpf_ringbuf,
        cap_bpf: ebpf_ringbuf,
        linux_netns: args.linux_netns.is_some()
            && (applies_routes || applies_wireguard || starts_userspace_wireguard),
        relay_forwarder_netns,
    }
}

fn agent_routes_may_forward_ipv4(args: &AgentArgs) -> bool {
    docker_routes_may_forward_ipv4(args) || kubernetes_routes_may_forward_ipv4(args)
}

fn agent_routes_may_forward_ipv6(args: &AgentArgs) -> bool {
    docker_routes_may_forward_ipv6(args) || kubernetes_routes_may_forward_ipv6(args)
}

fn docker_routes_may_forward_ipv4(args: &AgentArgs) -> bool {
    args.apply_docker_routes
        && (args.docker_discover_networks
            || args
                .docker_container_cidrs
                .iter()
                .any(|cidr| matches!(cidr, ipnet::IpNet::V4(_))))
}

fn docker_routes_may_forward_ipv6(args: &AgentArgs) -> bool {
    args.apply_docker_routes
        && args
            .docker_container_cidrs
            .iter()
            .any(|cidr| matches!(cidr, ipnet::IpNet::V6(_)))
}

fn kubernetes_routes_may_forward_ipv4(args: &AgentArgs) -> bool {
    args.apply_kubernetes_underlay
        && (args.kubernetes_discover_services
            || args.kubernetes_discover_api_server
            || args
                .kubernetes_service_cidrs
                .iter()
                .chain(args.kubernetes_api_server_cidrs.iter())
                .any(|cidr| matches!(cidr, ipnet::IpNet::V4(_))))
}

fn kubernetes_routes_may_forward_ipv6(args: &AgentArgs) -> bool {
    args.apply_kubernetes_underlay
        && args
            .kubernetes_service_cidrs
            .iter()
            .chain(args.kubernetes_api_server_cidrs.iter())
            .any(|cidr| matches!(cidr, ipnet::IpNet::V6(_)))
}

fn validate_linux_interface_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("linux interface name cannot be empty");
    }
    if name.len() > 15 {
        anyhow::bail!("linux interface name `{name}` exceeds 15 bytes");
    }
    if matches!(name, "." | "..") {
        anyhow::bail!("linux interface name `{name}` must not be '.' or '..'");
    }
    if name.starts_with('-') {
        anyhow::bail!("linux interface name `{name}` must not start with '-'");
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        anyhow::bail!(
            "linux interface name `{name}` must contain only ASCII letters, digits, '.', '_' or '-'"
        );
    }
    Ok(())
}

fn validate_docker_discovery_config(args: &AgentArgs) -> anyhow::Result<()> {
    validate_docker_api_version(&args.docker_api_version)?;
    if let Some(socket) = args.docker_api_socket.as_deref() {
        validate_docker_api_socket_path(socket, "--docker-api-socket")?;
    }
    validate_docker_network_filters(&args.docker_networks)?;
    if !args.docker_container_cidrs.is_empty() {
        anyhow::bail!(
            "--docker-discover-networks cannot be combined with explicit --docker-container-cidr values"
        );
    }
    Ok(())
}

fn validate_inactive_docker_route_config(args: &AgentArgs) -> anyhow::Result<()> {
    if args.docker_discover_networks {
        anyhow::bail!("--docker-discover-networks requires --apply-docker-routes");
    }
    if args.docker_api_socket.is_some() {
        anyhow::bail!("--docker-api-socket requires --docker-discover-networks");
    }
    if !args.docker_networks.is_empty() {
        anyhow::bail!("--docker-network requires --docker-discover-networks");
    }
    if args.docker_container_namespace.is_some() {
        anyhow::bail!("--docker-container-namespace requires --apply-docker-routes");
    }
    if !args.docker_container_cidrs.is_empty() {
        anyhow::bail!("--docker-container-cidr requires --apply-docker-routes");
    }
    if args.docker_host_interface != "docker0" {
        anyhow::bail!("--docker-host-interface requires --apply-docker-routes");
    }
    if args.docker_route_interval_seconds != 60 {
        anyhow::bail!("--docker-route-interval-seconds requires --apply-docker-routes");
    }
    if !args.docker_expose_host_routes {
        anyhow::bail!("--docker-expose-host-routes=false requires --apply-docker-routes");
    }
    Ok(())
}

fn validate_docker_container_cidrs(flag: &str, cidrs: &[ipnet::IpNet]) -> anyhow::Result<()> {
    let mut seen = BTreeSet::new();
    let mut routes = Vec::new();
    for cidr in cidrs {
        if let Some(reason) = restricted_route_cidr_reason(cidr) {
            anyhow::bail!("{flag} must not include {reason} Docker container CIDR {cidr}");
        }
        let route = cidr.trunc();
        if cidr != &route {
            anyhow::bail!(
                "{flag} must use canonical Docker container CIDR route {route}, not {cidr}"
            );
        }
        if !seen.insert(route) {
            anyhow::bail!("{flag} must not repeat Docker container CIDR route {route}");
        }
        if let Some(overlap) = routes
            .iter()
            .find(|existing| ip_cidrs_overlap(existing, &route))
        {
            anyhow::bail!(
                "{flag} must not include overlapping Docker container CIDR routes {overlap} and {route}"
            );
        }
        routes.push(route);
    }
    Ok(())
}

fn restricted_route_cidr_reason(cidr: &ipnet::IpNet) -> Option<&'static str> {
    if cidr.prefix_len() == 0 {
        return Some("unrestricted");
    }
    match cidr {
        ipnet::IpNet::V4(network) => restricted_docker_ipv4_cidr_reason(network),
        ipnet::IpNet::V6(network) => restricted_docker_ipv6_cidr_reason(network),
    }
}

fn restricted_docker_ipv4_cidr_reason(network: &ipnet::Ipv4Net) -> Option<&'static str> {
    let restricted = [
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(0, 0, 0, 0), 8),
            "unspecified",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 0), 8),
            "loopback",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(169, 254, 0, 0), 16),
            "link-local",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(224, 0, 0, 0), 4),
            "multicast",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(255, 255, 255, 255), 32),
            "broadcast",
        ),
    ];
    restricted
        .iter()
        .find_map(|(restricted, reason)| ipv4_cidrs_overlap(network, restricted).then_some(*reason))
}

fn restricted_docker_ipv6_cidr_reason(network: &ipnet::Ipv6Net) -> Option<&'static str> {
    let restricted = [
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 128),
            "unspecified",
        ),
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::LOCALHOST, 128),
            "loopback",
        ),
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
            "link-local",
        ),
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
            "multicast",
        ),
    ];
    restricted
        .iter()
        .find_map(|(restricted, reason)| ipv6_cidrs_overlap(network, restricted).then_some(*reason))
}

fn ip_cidrs_overlap(left: &ipnet::IpNet, right: &ipnet::IpNet) -> bool {
    match (left, right) {
        (ipnet::IpNet::V4(left), ipnet::IpNet::V4(right)) => ipv4_cidrs_overlap(left, right),
        (ipnet::IpNet::V6(left), ipnet::IpNet::V6(right)) => ipv6_cidrs_overlap(left, right),
        _ => false,
    }
}

fn ipv4_cidrs_overlap(left: &ipnet::Ipv4Net, right: &ipnet::Ipv4Net) -> bool {
    left.contains(&right.network())
        || left.contains(&right.broadcast())
        || right.contains(&left.network())
        || right.contains(&left.broadcast())
}

fn ipv6_cidrs_overlap(left: &ipnet::Ipv6Net, right: &ipnet::Ipv6Net) -> bool {
    left.contains(&right.network())
        || left.contains(&right.broadcast())
        || right.contains(&left.network())
        || right.contains(&left.broadcast())
}

fn validate_docker_api_version(version: &str) -> anyhow::Result<()> {
    let version = version.trim_matches('/');
    if version.is_empty() {
        return Ok(());
    }
    if version.len() > 16 {
        anyhow::bail!("Docker API version `{version}` is too long");
    }
    let Some(rest) = version.strip_prefix('v') else {
        anyhow::bail!(
            "Docker API version `{version}` must be empty or use v<major>.<minor> format"
        );
    };
    let mut parts = rest.split('.');
    let major = parts.next().unwrap_or_default();
    let minor = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        anyhow::bail!(
            "Docker API version `{version}` must be empty or use v<major>.<minor> format"
        );
    }
    Ok(())
}

fn validate_docker_network_filter(filter: &str) -> anyhow::Result<()> {
    validate_docker_network_token(filter, "Docker network filter")
}

fn validate_docker_network_filters(filters: &[String]) -> anyhow::Result<()> {
    let mut seen = BTreeSet::new();
    for filter in filters {
        validate_docker_network_filter(filter)?;
        if !seen.insert(filter.as_str()) {
            anyhow::bail!("--docker-network `{filter}` must not be repeated");
        }
    }
    Ok(())
}

fn validate_docker_network_name(name: &str) -> anyhow::Result<()> {
    validate_docker_network_token(name, "Docker network name")
}

fn validate_docker_network_id(id: &str) -> anyhow::Result<()> {
    validate_docker_network_token(id, "Docker network ID")
}

fn validate_docker_network_token(value: &str, label: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("{label} cannot be empty");
    }
    if value.len() > 255 {
        anyhow::bail!("{label} `{value}` exceeds 255 bytes");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        anyhow::bail!("{label} `{value}` must contain only ASCII letters, digits, '.', '_' or '-'");
    }
    Ok(())
}

fn validate_kubernetes_underlay_config(args: &AgentArgs) -> anyhow::Result<()> {
    validate_positive_seconds(
        args.kubernetes_route_interval_seconds,
        "--kubernetes-route-interval-seconds",
    )?;
    let mut namespaces = BTreeSet::new();
    for namespace in &args.kubernetes_namespaces {
        validate_kubernetes_namespace(namespace)?;
        if !namespaces.insert(namespace.as_str()) {
            anyhow::bail!("--kubernetes-namespace `{namespace}` must not be repeated");
        }
    }
    if let Some(selector) = args.kubernetes_service_label_selector.as_deref() {
        validate_kubernetes_label_selector(selector)?;
    }
    if let Some(route_provider) = args.kubernetes_route_provider.as_deref() {
        validate_daemon_identifier(route_provider, "--kubernetes-route-provider")?;
    }
    if let Some(api_url) = args.kubernetes_api_url.as_deref() {
        validate_http_url(api_url, "--kubernetes-api-url")?;
    }
    if !args.kubernetes_discover_services {
        if !args.kubernetes_namespaces.is_empty() {
            anyhow::bail!("--kubernetes-namespace requires --kubernetes-discover-services");
        }
        if args.kubernetes_service_label_selector.is_some() {
            anyhow::bail!(
                "--kubernetes-service-label-selector requires --kubernetes-discover-services"
            );
        }
        if !args.kubernetes_discover_api_server
            && args.kubernetes_api_server_cidrs.is_empty()
            && args.kubernetes_service_cidrs.is_empty()
        {
            anyhow::bail!(
                "--apply-kubernetes-underlay requires at least one --kubernetes-api-server-cidr or --kubernetes-service-cidr unless --kubernetes-discover-services or --kubernetes-discover-api-server is set"
            );
        }
    }
    let mut route_cidrs = BTreeSet::new();
    validate_kubernetes_underlay_route_cidrs(
        "--kubernetes-api-server-cidr",
        "Kubernetes API server CIDR",
        &args.kubernetes_api_server_cidrs,
        &mut route_cidrs,
    )?;
    validate_kubernetes_underlay_route_cidrs(
        "--kubernetes-service-cidr",
        "Kubernetes Service CIDR",
        &args.kubernetes_service_cidrs,
        &mut route_cidrs,
    )?;
    Ok(())
}

fn validate_kubernetes_underlay_route_cidrs(
    flag: &str,
    label: &str,
    cidrs: &[ipnet::IpNet],
    seen: &mut BTreeSet<ipnet::IpNet>,
) -> anyhow::Result<()> {
    for cidr in cidrs {
        if let Some(reason) = restricted_route_cidr_reason(cidr) {
            anyhow::bail!("{flag} must not include {reason} {label} {cidr}");
        }
        let route = cidr.trunc();
        if cidr != &route {
            anyhow::bail!("{flag} must use canonical {label} route {route}, not {cidr}");
        }
        if !seen.insert(route) {
            anyhow::bail!("{flag} must not repeat Kubernetes underlay route CIDR {route}");
        }
    }
    Ok(())
}

fn validate_kubernetes_namespace(namespace: &str) -> anyhow::Result<()> {
    if namespace.is_empty() {
        anyhow::bail!("Kubernetes namespace cannot be empty");
    }
    if namespace.len() > 63 {
        anyhow::bail!("Kubernetes namespace `{namespace}` exceeds 63 bytes");
    }
    let valid_body = namespace
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    let valid_edges = namespace
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && namespace
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if !valid_body || !valid_edges {
        anyhow::bail!(
            "Kubernetes namespace `{namespace}` must be a DNS label using lowercase ASCII letters, digits, and '-' with alphanumeric edges"
        );
    }
    Ok(())
}

fn validate_kubernetes_label_selector(selector: &str) -> anyhow::Result<()> {
    if selector.is_empty() {
        anyhow::bail!("Kubernetes service label selector cannot be empty");
    }
    if selector.len() > 1024 {
        anyhow::bail!("Kubernetes service label selector exceeds 1024 bytes");
    }
    if selector.chars().any(char::is_control) {
        anyhow::bail!("Kubernetes service label selector cannot contain control characters");
    }
    Ok(())
}

fn ensure_program_in_path(program: &str, path: Option<&OsStr>) -> anyhow::Result<()> {
    resolve_program_in_path(program, path).map(|_| ())
}

fn resolve_program_in_path(program: &str, path: Option<&OsStr>) -> anyhow::Result<PathBuf> {
    ensure_runtime_command_path_is_absolute(path)?;
    let Some(path) = path else {
        anyhow::bail!("missing required Linux runtime command `{program}` in PATH");
    };
    if path.is_empty() {
        anyhow::bail!("missing required Linux runtime command `{program}` in PATH");
    }
    for directory in std::env::split_paths(path) {
        let candidate = directory.join(program);
        match candidate.symlink_metadata() {
            Ok(_) => {
                ensure_runtime_executable_file(
                    &candidate,
                    &format!("required Linux runtime command `{program}`"),
                )?;
                return Ok(candidate);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect Linux runtime command `{program}` at {}",
                        candidate.display()
                    )
                });
            }
        }
    }
    anyhow::bail!("missing required Linux runtime command `{program}` in PATH");
}

fn ensure_runtime_command_path_is_absolute(path: Option<&OsStr>) -> anyhow::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if path.is_empty() {
        return Ok(());
    }
    for directory in std::env::split_paths(path) {
        anyhow::ensure!(
            !directory.as_os_str().is_empty() && directory.is_absolute(),
            "Linux runtime command PATH entry `{}` must be an absolute directory",
            directory.display()
        );
        anyhow::ensure!(
            !path_has_special_component(&directory),
            "Linux runtime command PATH entry `{}` must not contain '.' or '..' components",
            directory.display()
        );
        ensure_runtime_command_path_directory_ready(&directory)?;
    }
    Ok(())
}

fn path_has_special_component(path: &Path) -> bool {
    path.as_os_str()
        .to_string_lossy()
        .split(['/', '\\'])
        .any(|component| matches!(component, "." | ".."))
}

fn ensure_runtime_program_ready(program: &str, path: Option<&OsStr>) -> anyhow::Result<()> {
    resolve_runtime_program_ready(program, path).map(|_| ())
}

fn resolve_runtime_program_ready(program: &str, path: Option<&OsStr>) -> anyhow::Result<PathBuf> {
    validate_runtime_program_token(program, "configured userspace WireGuard command")?;
    if program.contains('/') {
        let program_path = Path::new(program);
        anyhow::ensure!(
            program_path.is_absolute(),
            "configured userspace WireGuard command `{program}` must be a bare command name or an absolute path"
        );
        return ensure_runtime_executable_file(
            program_path,
            &format!("configured userspace WireGuard command `{program}`"),
        )
        .map(|()| program_path.to_path_buf());
    }
    resolve_program_in_path(program, path)
}

#[cfg(unix)]
fn ensure_runtime_command_path_directory_ready(directory: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let label = "Linux runtime command PATH entry";
    ensure_runtime_directory_chain_has_no_symlinks(label, directory)?;
    let metadata = directory
        .metadata()
        .with_context(|| format!("failed to inspect {label} {}", directory.display()))?;
    anyhow::ensure!(
        metadata.is_dir(),
        "{label} {} must be a directory",
        directory.display()
    );
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    ensure_runtime_path_owner_trusted(label, "at", directory, metadata.uid(), effective_uid)?;
    anyhow::ensure!(
        metadata.permissions().mode() & 0o022 == 0,
        "{label} at {} must not be group- or world-writable",
        directory.display()
    );

    let mut ancestor = directory.parent();
    while let Some(directory) = ancestor {
        let metadata = directory.metadata().with_context(|| {
            format!(
                "failed to inspect runtime command PATH ancestor {}",
                directory.display()
            )
        })?;
        ensure_runtime_parent_directory_safe(label, directory, &metadata, false, effective_uid)?;
        ancestor = directory.parent();
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_runtime_command_path_directory_ready(directory: &Path) -> anyhow::Result<()> {
    let metadata = directory.symlink_metadata().with_context(|| {
        format!(
            "failed to inspect Linux runtime command PATH entry {}",
            directory.display()
        )
    })?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "Linux runtime command PATH entry {} must be a directory",
        directory.display()
    );
    Ok(())
}

#[cfg(unix)]
fn ensure_runtime_executable_file(path: &Path, label: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("failed to inspect {label} at {}", path.display()))?;
    let mode = metadata.permissions().mode();
    anyhow::ensure!(
        metadata.file_type().is_file() && mode & 0o111 != 0,
        "{label} at {} expected an executable regular file",
        path.display()
    );
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    ensure_runtime_path_owner_trusted(label, "at", path, metadata.uid(), effective_uid)?;
    anyhow::ensure!(
        mode & 0o022 == 0,
        "{label} at {} must not be group- or world-writable",
        path.display()
    );
    let parent = path.parent().with_context(|| {
        format!(
            "failed to locate parent directory for {label} at {}",
            path.display()
        )
    })?;
    ensure_runtime_directory_chain_has_no_symlinks(label, parent)?;
    let parent_metadata = parent
        .metadata()
        .with_context(|| format!("failed to inspect parent directory {}", parent.display()))?;
    ensure_runtime_parent_directory_safe(label, parent, &parent_metadata, true, effective_uid)?;
    let mut ancestor = parent.parent();
    while let Some(directory) = ancestor {
        let metadata = directory.metadata().with_context(|| {
            format!(
                "failed to inspect ancestor directory {}",
                directory.display()
            )
        })?;
        ensure_runtime_parent_directory_safe(label, directory, &metadata, false, effective_uid)?;
        ancestor = directory.parent();
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_runtime_directory_chain_has_no_symlinks(
    label: &str,
    directory: &Path,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        directory.is_absolute(),
        "{label} parent {} must be an absolute directory",
        directory.display()
    );

    let mut current = PathBuf::new();
    for component in directory.components() {
        match component {
            std::path::Component::RootDir => current.push(component.as_os_str()),
            std::path::Component::Normal(part) => {
                current.push(part);
                let metadata = current.symlink_metadata().with_context(|| {
                    format!(
                        "failed to inspect runtime command directory {}",
                        current.display()
                    )
                })?;
                let relationship = if current == directory {
                    "parent"
                } else {
                    "ancestor"
                };
                anyhow::ensure!(
                    !metadata.file_type().is_symlink(),
                    "{label} {relationship} {} must not be a symlink",
                    current.display()
                );
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                anyhow::bail!(
                    "{label} parent {} must not contain '..' components",
                    directory.display()
                );
            }
            std::path::Component::Prefix(prefix) => current.push(prefix.as_os_str()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_runtime_parent_directory_safe(
    label: &str,
    directory: &Path,
    metadata: &std::fs::Metadata,
    immediate_parent: bool,
    effective_uid: u32,
) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let relationship = if immediate_parent {
        "parent"
    } else {
        "ancestor"
    };
    anyhow::ensure!(
        metadata.is_dir(),
        "{label} {relationship} {} must be a directory",
        directory.display()
    );
    ensure_runtime_path_owner_trusted(
        label,
        relationship,
        directory,
        metadata.uid(),
        effective_uid,
    )?;
    let mode = metadata.permissions().mode();
    if immediate_parent {
        anyhow::ensure!(
            mode & 0o022 == 0,
            "{label} parent {} must not be group- or world-writable",
            directory.display()
        );
    } else {
        anyhow::ensure!(
            mode & 0o022 == 0,
            "{label} ancestor {} must not be group- or world-writable",
            directory.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_runtime_path_owner_trusted(
    label: &str,
    relationship: &str,
    path: &Path,
    owner_uid: u32,
    effective_uid: u32,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        owner_uid == 0 || owner_uid == effective_uid,
        "{label} {relationship} {} must be owned by root or the current effective user",
        path.display()
    );
    Ok(())
}

#[cfg(not(unix))]
fn ensure_runtime_executable_file(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("failed to inspect {label} at {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "{label} at {} expected an executable regular file",
        path.display()
    );
    Ok(())
}

fn ensure_cap_net_admin_if_known() -> anyhow::Result<()> {
    if let Some(false) = process_has_capability(CAP_NET_ADMIN_BIT)? {
        anyhow::bail!(
            "agent runtime preflight requires CAP_NET_ADMIN for kernel networking or conntrack netlink access"
        );
    }
    Ok(())
}

fn ensure_cap_net_raw_if_known() -> anyhow::Result<()> {
    if let Some(false) = process_has_capability(CAP_NET_RAW_BIT)? {
        anyhow::bail!(
            "linux-command runtime backend requires CAP_NET_RAW for WireGuard dataplane sockets"
        );
    }
    Ok(())
}

fn ensure_cap_sys_admin_if_known() -> anyhow::Result<()> {
    if let Some(false) = process_has_capability(CAP_SYS_ADMIN_BIT)? {
        anyhow::bail!(
            "linux network namespace runtime backend requires CAP_SYS_ADMIN for setns/ip netns exec"
        );
    }
    Ok(())
}

fn ensure_cap_perfmon_if_known() -> anyhow::Result<()> {
    if let Some(false) = process_has_any_capability(&[CAP_PERFMON_BIT, CAP_SYS_ADMIN_BIT])? {
        anyhow::bail!(
            "eBPF packet-flow detector requires CAP_PERFMON or CAP_SYS_ADMIN for tracepoint attachment"
        );
    }
    Ok(())
}

fn ensure_cap_bpf_if_known() -> anyhow::Result<()> {
    if let Some(false) = process_has_any_capability(&[CAP_BPF_BIT, CAP_SYS_ADMIN_BIT])? {
        anyhow::bail!(
            "eBPF packet-flow detector requires CAP_BPF or CAP_SYS_ADMIN for BPF object loading"
        );
    }
    Ok(())
}

fn ensure_ebpf_object_file_ready(path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("eBPF packet-flow object {} is not readable", path.display()))?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "eBPF packet-flow object {} must not be a symlink",
        path.display()
    );
    anyhow::ensure!(
        metadata.is_file(),
        "eBPF packet-flow object {} must be a regular file",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() > 0,
        "eBPF packet-flow object {} is empty",
        path.display()
    );
    Ok(())
}

fn ensure_ebpf_jsonl_event_path_ready(path: &Path) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "eBPF packet-flow JSONL event path {} is not readable",
                    path.display()
                )
            })
        }
    };
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "eBPF packet-flow JSONL event path {} must not be a symlink",
        path.display()
    );
    anyhow::ensure!(
        metadata.is_file(),
        "eBPF packet-flow JSONL event path {} must be a regular file when it exists",
        path.display()
    );
    Ok(())
}

fn ensure_conntrack_procfs_path_ready(path: &Path) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "conntrack procfs packet-flow path {} is not readable",
                    path.display()
                )
            })
        }
    };
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "conntrack procfs packet-flow path {} must not be a symlink",
        path.display()
    );
    anyhow::ensure!(
        metadata.is_file(),
        "conntrack procfs packet-flow path {} must be a regular file when it exists",
        path.display()
    );
    Ok(())
}

fn ensure_docker_api_socket_ready(path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("Docker API socket {} is not readable", path.display()))?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "Docker API socket {} must not be a symlink",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;

        anyhow::ensure!(
            metadata.file_type().is_socket(),
            "Docker API socket {} must be a Unix domain socket",
            path.display()
        );
    }
    #[cfg(not(unix))]
    {
        anyhow::ensure!(
            metadata.is_file(),
            "Docker API socket {} must be a regular file on this platform",
            path.display()
        );
    }
    Ok(())
}

fn ensure_ebpf_tracepoint_ready(attachment: &EbpfTracepointAttachSpec) -> anyhow::Result<()> {
    let roots = TRACEFS_EVENT_ROOTS.iter().map(|root| Path::new(*root));
    ensure_ebpf_tracepoint_ready_in_roots(attachment, roots)
}

fn ensure_ebpf_tracepoint_ready_in_roots<'a>(
    attachment: &EbpfTracepointAttachSpec,
    roots: impl IntoIterator<Item = &'a Path>,
) -> anyhow::Result<()> {
    let mut checked = Vec::new();
    for root in roots {
        let tracepoint_id = root
            .join(&attachment.category)
            .join(&attachment.name)
            .join("id");
        checked.push(tracepoint_id.display().to_string());
        match std::fs::symlink_metadata(&tracepoint_id) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                anyhow::bail!(
                    "eBPF tracepoint `{}/{}` for program `{}` has symlink id path {}",
                    attachment.category,
                    attachment.name,
                    attachment.program,
                    tracepoint_id.display()
                );
            }
            Ok(metadata) if metadata.is_file() => {
                validate_ebpf_tracepoint_id_file(attachment, &tracepoint_id)?;
                return Ok(());
            }
            Ok(_) => {
                anyhow::bail!(
                    "eBPF tracepoint `{}/{}` for program `{}` has non-file id path {}",
                    attachment.category,
                    attachment.name,
                    attachment.program,
                    tracepoint_id.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect eBPF tracepoint `{}/{}` for program `{}` at {}",
                        attachment.category,
                        attachment.name,
                        attachment.program,
                        tracepoint_id.display()
                    )
                });
            }
        }
    }
    anyhow::bail!(
        "eBPF tracepoint `{}/{}` for program `{}` was not found; checked {}",
        attachment.category,
        attachment.name,
        attachment.program,
        checked.join(", ")
    )
}

fn validate_ebpf_tracepoint_id_file(
    attachment: &EbpfTracepointAttachSpec,
    path: &Path,
) -> anyhow::Result<u64> {
    let mut file = std::fs::File::open(path).with_context(|| {
        format!(
            "failed to open eBPF tracepoint `{}/{}` id for program `{}` at {}",
            attachment.category,
            attachment.name,
            attachment.program,
            path.display()
        )
    })?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_EBPF_TRACEPOINT_ID_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| {
            format!(
                "failed to read eBPF tracepoint `{}/{}` id for program `{}` at {}",
                attachment.category,
                attachment.name,
                attachment.program,
                path.display()
            )
        })?;
    if bytes.len() > MAX_EBPF_TRACEPOINT_ID_BYTES {
        anyhow::bail!(
            "eBPF tracepoint `{}/{}` id for program `{}` at {} exceeds {MAX_EBPF_TRACEPOINT_ID_BYTES} bytes",
            attachment.category,
            attachment.name,
            attachment.program,
            path.display()
        );
    }
    let contents = std::str::from_utf8(&bytes).with_context(|| {
        format!(
            "eBPF tracepoint `{}/{}` id for program `{}` at {} is not UTF-8",
            attachment.category,
            attachment.name,
            attachment.program,
            path.display()
        )
    })?;
    let value = contents.trim();
    if value.is_empty() {
        anyhow::bail!(
            "eBPF tracepoint `{}/{}` id for program `{}` at {} is empty",
            attachment.category,
            attachment.name,
            attachment.program,
            path.display()
        );
    }
    let id = value.parse::<u64>().with_context(|| {
        format!(
            "eBPF tracepoint `{}/{}` id for program `{}` at {} is not numeric: {value}",
            attachment.category,
            attachment.name,
            attachment.program,
            path.display()
        )
    })?;
    if id == 0 {
        anyhow::bail!(
            "eBPF tracepoint `{}/{}` id for program `{}` at {} must be greater than zero",
            attachment.category,
            attachment.name,
            attachment.program,
            path.display()
        );
    }
    Ok(id)
}

fn ensure_ipv4_forwarding_if_known() -> anyhow::Result<()> {
    ensure_proc_sysctl_enabled_if_known(
        Path::new(PROC_SYS_IPV4_FORWARD),
        "net.ipv4.ip_forward",
        "Docker/Kubernetes route forwarding",
    )
}

fn ensure_ipv6_forwarding_if_known() -> anyhow::Result<()> {
    ensure_proc_sysctl_enabled_if_known(
        Path::new(PROC_SYS_IPV6_FORWARDING),
        "net.ipv6.conf.all.forwarding",
        "IPv6 Docker/Kubernetes route forwarding",
    )
}

fn ensure_proc_sysctl_enabled_if_known(
    path: &Path,
    sysctl_name: &str,
    reason: &str,
) -> anyhow::Result<()> {
    if let Some(false) = proc_sysctl_flag(path)? {
        anyhow::bail!("agent runtime preflight requires {sysctl_name}=1 for {reason}");
    }
    Ok(())
}

fn proc_sysctl_flag(path: &Path) -> anyhow::Result<Option<bool>> {
    let Some(value) =
        read_optional_bounded_utf8_file(path, "Linux runtime sysctl", MAX_PROC_SYSCTL_FLAG_BYTES)?
    else {
        return Ok(None);
    };
    match value.trim() {
        "0" => Ok(Some(false)),
        "1" => Ok(Some(true)),
        value => anyhow::bail!(
            "Linux runtime sysctl `{}` contains unsupported boolean value `{}`",
            path.display(),
            value
        ),
    }
}

fn process_has_capability(bit: u8) -> anyhow::Result<Option<bool>> {
    let Some(status) = read_process_status_file(Path::new("/proc/self/status"))? else {
        return Ok(None);
    };
    process_status_has_capability(&status, bit)
}

fn process_has_any_capability(bits: &[u8]) -> anyhow::Result<Option<bool>> {
    let Some(status) = read_process_status_file(Path::new("/proc/self/status"))? else {
        return Ok(None);
    };
    process_status_has_any_capability(&status, bits)
}

fn read_process_status_file(path: &Path) -> anyhow::Result<Option<String>> {
    read_optional_bounded_utf8_file(path, "Linux process status", MAX_PROC_SELF_STATUS_BYTES)
}

fn read_optional_bounded_utf8_file(
    path: &Path,
    label: &str,
    max_bytes: u64,
) -> anyhow::Result<Option<String>> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to open {label} `{}`", path.display()))
        }
    };
    let mut bytes = Vec::new();
    file.by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label} `{}`", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!(
            "{label} `{}` exceeds maximum size of {max_bytes} bytes",
            path.display()
        );
    }
    let value = String::from_utf8(bytes)
        .with_context(|| format!("{label} `{}` is not valid UTF-8", path.display()))?;
    Ok(Some(value))
}

fn process_status_has_capability(status: &str, bit: u8) -> anyhow::Result<Option<bool>> {
    Ok(process_status_capability_mask(status)?.map(|mask| mask & (1_u64 << bit) != 0))
}

fn process_status_has_any_capability(status: &str, bits: &[u8]) -> anyhow::Result<Option<bool>> {
    Ok(process_status_capability_mask(status)?
        .map(|mask| bits.iter().any(|bit| mask & (1_u64 << *bit) != 0)))
}

fn process_status_capability_mask(status: &str) -> anyhow::Result<Option<u64>> {
    let cap_eff = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(str::trim);
    let Some(cap_eff) = cap_eff else {
        return Ok(None);
    };
    let mask = u64::from_str_radix(cap_eff, 16)
        .with_context(|| format!("failed to parse CapEff from /proc/self/status: {cap_eff}"))?;
    Ok(Some(mask))
}

fn ensure_netlink_protocol_ready(protocol: RuntimeNetlinkProtocol) -> anyhow::Result<()> {
    let mut socket = Socket::new(protocol.protocol())
        .with_context(|| format!("failed to open {} socket", protocol.as_str()))?;
    socket
        .bind_auto()
        .with_context(|| format!("failed to bind {} socket", protocol.as_str()))?;
    socket
        .connect(&NetlinkSocketAddr::new(0, 0))
        .with_context(|| format!("failed to connect {} socket to kernel", protocol.as_str()))?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxNetnsPathReport {
    same_as_current: Option<bool>,
}

fn ensure_linux_netns_ready(namespace: &LinuxNetworkNamespace) -> anyhow::Result<()> {
    let path = netns_path(namespace);
    let current_path = current_process_netns_path();
    let report = inspect_linux_netns_path(namespace, &path, current_path.as_deref())?;
    if report.same_as_current == Some(true) {
        tracing::warn!(
            namespace = namespace.name(),
            path = %path.display(),
            "configured linux network namespace resolves to the current process namespace"
        );
    }
    Ok(())
}

fn ensure_relay_forwarder_netns_ready(namespace: &LinuxNetworkNamespace) -> anyhow::Result<()> {
    ensure_process_in_netns(namespace).with_context(|| {
        format!(
            "relay forwarder namespace `{}` is not active in the current process",
            namespace.name()
        )
    })
}

fn current_process_netns_path() -> Option<PathBuf> {
    let thread_self = PathBuf::from("/proc/thread-self/ns/net");
    if thread_self.exists() {
        return Some(thread_self);
    }
    let self_netns = PathBuf::from("/proc/self/ns/net");
    self_netns.exists().then_some(self_netns)
}

fn inspect_linux_netns_path(
    namespace: &LinuxNetworkNamespace,
    path: &Path,
    current_netns_path: Option<&Path>,
) -> anyhow::Result<LinuxNetnsPathReport> {
    let symlink_metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "linux network namespace `{}` does not exist at {}",
                namespace.name(),
                path.display()
            );
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect linux network namespace `{}` at {}",
                    namespace.name(),
                    path.display()
                )
            })
        }
    };
    let file_type = symlink_metadata.file_type();
    if file_type.is_symlink() {
        anyhow::bail!(
            "linux network namespace `{}` at {} must not be a symlink",
            namespace.name(),
            path.display()
        );
    }
    if file_type.is_dir() {
        anyhow::bail!(
            "linux network namespace `{}` at {} must be a namespace bind mount, not a directory",
            namespace.name(),
            path.display()
        );
    }
    ensure_linux_netns_nsfs(namespace, path)?;

    let same_as_current = current_netns_path
        .map(|current_netns_path| same_file_identity(path, current_netns_path))
        .transpose()?;
    Ok(LinuxNetnsPathReport { same_as_current })
}

#[cfg(target_os = "linux")]
fn ensure_linux_netns_nsfs(namespace: &LinuxNetworkNamespace, path: &Path) -> anyhow::Result<()> {
    if !is_linux_nsfs_path(path)? {
        anyhow::bail!(
            "linux network namespace `{}` at {} must be an nsfs namespace bind mount",
            namespace.name(),
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_linux_netns_nsfs(_namespace: &LinuxNetworkNamespace, _path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_linux_nsfs_path(path: &Path) -> anyhow::Result<bool> {
    let stat = nix::sys::statfs::statfs(path)
        .with_context(|| format!("failed to stat filesystem for {}", path.display()))?;
    Ok(stat.filesystem_type() == nix::sys::statfs::NSFS_MAGIC)
}

#[cfg(unix)]
fn same_file_identity(left: &Path, right: &Path) -> anyhow::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let left =
        std::fs::metadata(left).with_context(|| format!("failed to stat {}", left.display()))?;
    let right =
        std::fs::metadata(right).with_context(|| format!("failed to stat {}", right.display()))?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(not(unix))]
fn same_file_identity(_left: &Path, _right: &Path) -> anyhow::Result<bool> {
    Ok(false)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let component = cli.command.component();
    validate_observability_config(&cli.observability)?;
    let _observability = init_observability(&cli.observability, component)?;
    let otel_metrics_enabled = cli.observability.otel_active();
    let otel_metrics_interval =
        Duration::from_secs(cli.observability.otel_metrics_poll_interval_seconds);
    tracing::info!(
        component,
        otel_enabled = cli.observability.otel_active(),
        "observability initialized"
    );
    match cli.command {
        Command::ControlPlane(args) => {
            run_control_plane(args, otel_metrics_enabled, otel_metrics_interval).await
        }
        Command::Signal(args) => {
            run_signal(args, otel_metrics_enabled, otel_metrics_interval).await
        }
        Command::Stun(args) => run_stun(args, otel_metrics_enabled, otel_metrics_interval).await,
        Command::Relay(args) => run_relay(args, otel_metrics_enabled, otel_metrics_interval).await,
        Command::Agent(args) => run_agent(*args, otel_metrics_enabled, otel_metrics_interval).await,
    }
}

async fn run_control_plane(
    args: ControlPlaneArgs,
    otel_metrics_enabled: bool,
    otel_metrics_interval: Duration,
) -> anyhow::Result<()> {
    match database_kind(args.database_url.as_deref()) {
        DatabaseKind::Postgres => {
            let database_url = args
                .database_url
                .as_deref()
                .context("postgres database URL is required")?;
            let store = Arc::new(PostgresControlPlaneStore::connect(database_url).await?);
            serve_with_store(
                args,
                store.clone(),
                store,
                otel_metrics_enabled,
                otel_metrics_interval,
            )
            .await
        }
        DatabaseKind::Sqlite => {
            let database_url = args
                .database_url
                .as_deref()
                .context("sqlite database URL is required")?;
            let store = Arc::new(SqliteControlPlaneStore::connect(database_url).await?);
            serve_with_store(
                args,
                store.clone(),
                store,
                otel_metrics_enabled,
                otel_metrics_interval,
            )
            .await
        }
        DatabaseKind::Memory => {
            let store = Arc::new(InMemoryStore::default());
            let ledger = Arc::new(InMemoryTokenLedger::default());
            serve_with_store(
                args,
                store,
                ledger,
                otel_metrics_enabled,
                otel_metrics_interval,
            )
            .await
        }
    }
}

async fn serve_with_store<S, L>(
    args: ControlPlaneArgs,
    store: Arc<S>,
    token_ledger: Arc<L>,
    otel_metrics_enabled: bool,
    otel_metrics_interval: Duration,
) -> anyhow::Result<()>
where
    S: ControlPlaneStore + 'static,
    L: TokenLedger + 'static,
{
    validate_control_plane_runtime_config(&args)?;
    let mut config =
        ControlPlaneConfig::new(ClusterId::from_string(args.cluster_id), args.vpn_pool);
    config.cluster_policy.relay_health_ttl_seconds = args.relay_health_ttl_seconds;
    config.cluster_policy.endpoint_candidate_ttl_seconds = args.endpoint_candidate_ttl_seconds;
    config.cluster_policy.path_state_ttl_seconds = args.path_state_ttl_seconds;
    config.cluster_policy.acl_rules = args.acl_rules;
    let plane = Arc::new(ControlPlane::new(config, store));
    let mut key_ring = IssuerKeyRing::default();
    key_ring.insert(
        NodeId::from_string(args.issuer_node_id),
        KeyId::from_string(args.issuer_key_id),
        args.issuer_public_key,
    );
    for trusted in args.trusted_issuer_keys {
        key_ring.insert(
            NodeId::from_string(trusted.issuer_node_id),
            KeyId::from_string(trusted.key_id),
            trusted.public_key,
        );
    }
    let join_service = Arc::new(ControlPlaneJoinService::new(
        plane.clone(),
        token_ledger,
        key_ring,
    ));
    let otel_metrics_task = otel_metrics_enabled.then(|| {
        start_control_plane_otel_metrics_export(
            plane.clone(),
            join_service.clone(),
            otel_metrics_interval.max(Duration::from_secs(1)),
        )
    });
    let result = serve_router(
        args.listen,
        router(ControlPlaneHttpState::new(plane, join_service)),
    )
    .await;
    if let Some(task) = otel_metrics_task {
        task.abort();
    }
    result
}

fn validate_control_plane_runtime_config(args: &ControlPlaneArgs) -> anyhow::Result<()> {
    validate_daemon_identifier(&args.cluster_id, "--cluster-id")?;
    validate_daemon_identifier(&args.issuer_node_id, "--issuer-node-id")?;
    validate_daemon_identifier(&args.issuer_key_id, "--issuer-key-id")?;
    for trusted in &args.trusted_issuer_keys {
        validate_daemon_identifier(
            &trusted.issuer_node_id,
            "--trusted-issuer-key issuer_node_id",
        )?;
        validate_daemon_identifier(&trusted.key_id, "--trusted-issuer-key key_id")?;
    }
    validate_positive_seconds(args.relay_health_ttl_seconds, "--relay-health-ttl-seconds")?;
    validate_positive_seconds(
        args.endpoint_candidate_ttl_seconds,
        "--endpoint-candidate-ttl-seconds",
    )?;
    validate_positive_seconds(args.path_state_ttl_seconds, "--path-state-ttl-seconds")
}

async fn serve_router(listen: SocketAddr, app: Router) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "control-plane listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn run_signal(
    args: SignalArgs,
    otel_metrics_enabled: bool,
    otel_metrics_interval: Duration,
) -> anyhow::Result<()> {
    validate_signal_runtime_config(&args)?;
    let policy = ClusterPolicy {
        allow_ipv6_direct: !args.disable_ipv6_direct,
        allow_nat_traversal: !args.disable_nat_traversal,
        allow_relay_fallback: !args.disable_relay_fallback,
        idle_timeout_seconds: args.idle_timeout_seconds,
        relay_health_ttl_seconds: args.relay_health_ttl_seconds,
        endpoint_candidate_ttl_seconds: args.endpoint_candidate_ttl_seconds,
        nat_classification_ttl_seconds: args.nat_classification_ttl_seconds,
        nat_classification_min_confidence_percent: args.nat_classification_min_confidence_percent,
        ..ClusterPolicy::default()
    };
    let registry = Arc::new(SignalRegistry::new(policy));
    let otel_metrics_task = otel_metrics_enabled.then(|| {
        start_signal_otel_metrics_export(
            registry.clone(),
            otel_metrics_interval.max(Duration::from_secs(1)),
        )
    });
    let result = serve_router(args.listen, signal_router(SignalHttpState::new(registry))).await;
    if let Some(task) = otel_metrics_task {
        task.abort();
    }
    result
}

fn validate_signal_runtime_config(args: &SignalArgs) -> anyhow::Result<()> {
    validate_positive_seconds(args.idle_timeout_seconds, "--idle-timeout-seconds")?;
    validate_positive_seconds(args.relay_health_ttl_seconds, "--relay-health-ttl-seconds")?;
    validate_positive_seconds(
        args.endpoint_candidate_ttl_seconds,
        "--endpoint-candidate-ttl-seconds",
    )?;
    validate_positive_seconds(
        args.nat_classification_ttl_seconds,
        "--nat-classification-ttl-seconds",
    )?;
    validate_percent(
        args.nat_classification_min_confidence_percent,
        "--nat-classification-min-confidence-percent",
    )
}

async fn run_stun(
    args: StunArgs,
    otel_metrics_enabled: bool,
    otel_metrics_interval: Duration,
) -> anyhow::Result<()> {
    let stats = Arc::new(StunServerStats::default());
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (listen, alternate_listen, udp_task) = if let Some(alternate_listen) = args.alternate_listen
    {
        let server = Rfc5780StunServer::bind(args.listen, alternate_listen).await?;
        let listen = server.primary_addr()?;
        let alternate_listen = server.alternate_addr()?;
        (
            listen,
            Some(alternate_listen),
            tokio::spawn(server.serve_with_stats(shutdown_rx, stats.clone())),
        )
    } else {
        let server = BindingStunServer::bind(args.listen).await?;
        let listen = server.local_addr()?;
        (
            listen,
            None,
            tokio::spawn(server.serve_with_stats(shutdown_rx, stats.clone())),
        )
    };
    let otel_metrics_task = otel_metrics_enabled.then(|| {
        start_stun_otel_metrics_export(
            stats.clone(),
            listen,
            alternate_listen,
            otel_metrics_interval.max(Duration::from_secs(1)),
        )
    });
    tracing::info!(%listen, ?alternate_listen, http_listen = %args.http_listen, "stun listening");
    let result = serve_router(
        args.http_listen,
        stun_router(StunHttpState::new(listen, alternate_listen, stats)),
    )
    .await;
    udp_task.abort();
    if let Some(task) = otel_metrics_task {
        task.abort();
    }
    result
}

#[derive(Debug, Clone)]
struct StunHttpState {
    listen: SocketAddr,
    alternate_listen: Option<SocketAddr>,
    stats: Arc<StunServerStats>,
}

impl StunHttpState {
    fn new(
        listen: SocketAddr,
        alternate_listen: Option<SocketAddr>,
        stats: Arc<StunServerStats>,
    ) -> Self {
        Self {
            listen,
            alternate_listen,
            stats,
        }
    }

    fn metrics(&self) -> StunMetricsResponse {
        let snapshot = self.stats.snapshot();
        StunMetricsResponse {
            listen: self.listen,
            alternate_listen: self.alternate_listen,
            binding_request_count: snapshot.binding_request_count,
            binding_response_count: snapshot.binding_response_count,
            invalid_packet_count: snapshot.invalid_packet_count,
            socket_receive_error_count: snapshot.socket_receive_error_count,
            socket_send_error_count: snapshot.socket_send_error_count,
            generated_at: chrono::Utc::now(),
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct StunHealthResponse {
    status: &'static str,
}

fn stun_router(state: StunHttpState) -> Router {
    Router::new()
        .route("/healthz", axum::routing::get(stun_healthz))
        .route("/v1/metrics", axum::routing::get(stun_metrics))
        .route("/metrics", axum::routing::get(stun_prometheus_metrics))
        .with_state(state)
}

async fn stun_healthz() -> axum::Json<StunHealthResponse> {
    axum::Json(StunHealthResponse { status: "ok" })
}

async fn stun_metrics(
    axum::extract::State(state): axum::extract::State<StunHttpState>,
) -> axum::Json<StunMetricsResponse> {
    axum::Json(state.metrics())
}

async fn stun_prometheus_metrics(
    axum::extract::State(state): axum::extract::State<StunHttpState>,
) -> impl axum::response::IntoResponse {
    let metrics = state.metrics();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render_stun_prometheus_metrics(&metrics),
    )
}

fn render_stun_prometheus_metrics(metrics: &StunMetricsResponse) -> String {
    let listen = prometheus_label(&metrics.listen.to_string());
    let mut body = String::new();
    prometheus_line!(
        &mut body,
        "# HELP ipars_stun_metrics_generated_timestamp_seconds Unix timestamp of the STUN metrics snapshot."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_stun_metrics_generated_timestamp_seconds gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_stun_metrics_generated_timestamp_seconds{{listen=\"{listen}\"}} {}",
        metrics.generated_at.timestamp().max(0)
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_stun_server_active STUN server process active state."
    );
    prometheus_line!(&mut body, "# TYPE ipars_stun_server_active gauge");
    prometheus_line!(
        &mut body,
        "ipars_stun_server_active{{listen=\"{listen}\"}} 1"
    );
    if let Some(alternate_listen) = metrics.alternate_listen {
        let alternate_listen = prometheus_label(&alternate_listen.to_string());
        prometheus_line!(
            &mut body,
            "# HELP ipars_stun_rfc5780_alternate_server_active STUN RFC5780 alternate socket active state."
        );
        prometheus_line!(
            &mut body,
            "# TYPE ipars_stun_rfc5780_alternate_server_active gauge"
        );
        prometheus_line!(
            &mut body,
            "ipars_stun_rfc5780_alternate_server_active{{listen=\"{listen}\",alternate_listen=\"{alternate_listen}\"}} 1"
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_stun_binding_requests_total Valid STUN Binding requests received by the server."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_stun_binding_requests_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_stun_binding_requests_total{{listen=\"{listen}\"}} {}",
        metrics.binding_request_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_stun_binding_responses_total STUN Binding success responses sent by the server."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_stun_binding_responses_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_stun_binding_responses_total{{listen=\"{listen}\"}} {}",
        metrics.binding_response_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_stun_invalid_packets_total Malformed or unsupported STUN packets received by the server."
    );
    prometheus_line!(&mut body, "# TYPE ipars_stun_invalid_packets_total counter");
    prometheus_line!(
        &mut body,
        "ipars_stun_invalid_packets_total{{listen=\"{listen}\"}} {}",
        metrics.invalid_packet_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_stun_socket_receive_errors_total STUN server UDP receive errors."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_stun_socket_receive_errors_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_stun_socket_receive_errors_total{{listen=\"{listen}\"}} {}",
        metrics.socket_receive_error_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_stun_socket_send_errors_total STUN server UDP send errors."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_stun_socket_send_errors_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_stun_socket_send_errors_total{{listen=\"{listen}\"}} {}",
        metrics.socket_send_error_count
    );
    body
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StunOtelSnapshot {
    binding_request_count: u64,
    binding_response_count: u64,
    invalid_packet_count: u64,
    socket_receive_error_count: u64,
    socket_send_error_count: u64,
}

impl From<&StunServerMetricsSnapshot> for StunOtelSnapshot {
    fn from(snapshot: &StunServerMetricsSnapshot) -> Self {
        Self {
            binding_request_count: snapshot.binding_request_count,
            binding_response_count: snapshot.binding_response_count,
            invalid_packet_count: snapshot.invalid_packet_count,
            socket_receive_error_count: snapshot.socket_receive_error_count,
            socket_send_error_count: snapshot.socket_send_error_count,
        }
    }
}

#[derive(Debug)]
struct StunOtelMetrics {
    server_active: Gauge<u64>,
    rfc5780_alternate_server_active: Gauge<u64>,
    metrics_generated_timestamp_seconds: Gauge<u64>,
    binding_requests: Counter<u64>,
    binding_responses: Counter<u64>,
    invalid_packets: Counter<u64>,
    socket_receive_errors: Counter<u64>,
    socket_send_errors: Counter<u64>,
}

impl StunOtelMetrics {
    fn new() -> Self {
        let meter = global::meter("iparsd.stun");
        Self {
            server_active: meter
                .u64_gauge("ipars.stun.server.active")
                .with_description("STUN server process active state.")
                .build(),
            rfc5780_alternate_server_active: meter
                .u64_gauge("ipars.stun.rfc5780_alternate_server.active")
                .with_description("STUN RFC5780 alternate socket active state.")
                .build(),
            metrics_generated_timestamp_seconds: meter
                .u64_gauge("ipars.stun.metrics.generated_timestamp_seconds")
                .with_description("Unix timestamp of the STUN metrics snapshot exported to OTLP.")
                .build(),
            binding_requests: meter
                .u64_counter("ipars.stun.binding_requests")
                .with_description("Valid STUN Binding requests received by the server.")
                .build(),
            binding_responses: meter
                .u64_counter("ipars.stun.binding_responses")
                .with_description("STUN Binding success responses sent by the server.")
                .build(),
            invalid_packets: meter
                .u64_counter("ipars.stun.invalid_packets")
                .with_description("Malformed or unsupported STUN packets received by the server.")
                .build(),
            socket_receive_errors: meter
                .u64_counter("ipars.stun.socket_receive_errors")
                .with_description("STUN server UDP receive errors.")
                .build(),
            socket_send_errors: meter
                .u64_counter("ipars.stun.socket_send_errors")
                .with_description("STUN server UDP send errors.")
                .build(),
        }
    }

    fn record_status(
        &self,
        listen: SocketAddr,
        alternate_listen: Option<SocketAddr>,
        snapshot: &StunServerMetricsSnapshot,
        generated_at: chrono::DateTime<chrono::Utc>,
        previous: Option<&StunOtelSnapshot>,
    ) {
        let labels = StunOtelStatusLabels::new(listen, alternate_listen);
        let attrs = labels.primary_attrs();
        self.server_active.record(1, &attrs);
        self.metrics_generated_timestamp_seconds
            .record(otel_generated_timestamp_seconds(&generated_at), &attrs);
        if let Some(alternate_attrs) = labels.alternate_attrs() {
            self.rfc5780_alternate_server_active
                .record(1, &alternate_attrs);
        }
        self.binding_requests.add(
            counter_delta(
                snapshot.binding_request_count,
                previous.map(|previous| previous.binding_request_count),
            ),
            &attrs,
        );
        self.binding_responses.add(
            counter_delta(
                snapshot.binding_response_count,
                previous.map(|previous| previous.binding_response_count),
            ),
            &attrs,
        );
        self.invalid_packets.add(
            counter_delta(
                snapshot.invalid_packet_count,
                previous.map(|previous| previous.invalid_packet_count),
            ),
            &attrs,
        );
        self.socket_receive_errors.add(
            counter_delta(
                snapshot.socket_receive_error_count,
                previous.map(|previous| previous.socket_receive_error_count),
            ),
            &attrs,
        );
        self.socket_send_errors.add(
            counter_delta(
                snapshot.socket_send_error_count,
                previous.map(|previous| previous.socket_send_error_count),
            ),
            &attrs,
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StunOtelStatusLabels {
    listen: String,
    alternate_listen: Option<String>,
}

impl StunOtelStatusLabels {
    fn new(listen: SocketAddr, alternate_listen: Option<SocketAddr>) -> Self {
        Self {
            listen: listen.to_string(),
            alternate_listen: alternate_listen.map(|address| address.to_string()),
        }
    }

    fn primary_attrs(&self) -> [KeyValue; 1] {
        [KeyValue::new("listen", self.listen.clone())]
    }

    fn alternate_attrs(&self) -> Option<[KeyValue; 2]> {
        self.alternate_listen.as_ref().map(|alternate_listen| {
            [
                KeyValue::new("listen", self.listen.clone()),
                KeyValue::new("alternate_listen", alternate_listen.clone()),
            ]
        })
    }
}

fn start_stun_otel_metrics_export(
    stats: Arc<StunServerStats>,
    listen: SocketAddr,
    alternate_listen: Option<SocketAddr>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let metrics = StunOtelMetrics::new();
        let mut previous = None;
        loop {
            let snapshot = stats.snapshot();
            metrics.record_status(
                listen,
                alternate_listen,
                &snapshot,
                chrono::Utc::now(),
                previous.as_ref(),
            );
            previous = Some(StunOtelSnapshot::from(&snapshot));
            tokio::time::sleep(interval).await;
        }
    })
}

#[derive(Debug)]
struct ControlPlaneOtelMetrics {
    nodes: Gauge<u64>,
    relay_candidates: Gauge<u64>,
    stale_endpoint_candidates: Gauge<u64>,
    endpoint_candidate_ttl_seconds: Gauge<u64>,
    stale_paths: Gauge<u64>,
    path_state_ttl_seconds: Gauge<u64>,
    metrics_generated_timestamp_seconds: Gauge<u64>,
    vpn_pool_total: Gauge<u64>,
    vpn_pool_allocated: Gauge<u64>,
    vpn_pool_available: Gauge<u64>,
    join_tokens: Gauge<u64>,
    join_tokens_issued: Gauge<u64>,
    join_token_uses: Gauge<u64>,
    peer_map_candidates: Gauge<u64>,
    peer_map_visible: Gauge<u64>,
    peer_map_acl_denied: Gauge<u64>,
    peer_map_route_candidates: Gauge<u64>,
    peer_map_routes_visible: Gauge<u64>,
    peer_map_routes_acl_denied: Gauge<u64>,
    node_health: Gauge<u64>,
    paths: Gauge<u64>,
    paths_by_state: Gauge<u64>,
}

impl ControlPlaneOtelMetrics {
    fn new() -> Self {
        let meter = global::meter("iparsd.control_plane");
        Self {
            nodes: meter
                .u64_gauge("ipars.control_plane.nodes")
                .with_description("Registered control-plane nodes.")
                .build(),
            relay_candidates: meter
                .u64_gauge("ipars.control_plane.relay_candidates")
                .with_description("Relay-capable nodes accepted into relay maps.")
                .build(),
            stale_endpoint_candidates: meter
                .u64_gauge("ipars.control_plane.stale_endpoint_candidates")
                .with_description("Control-plane endpoint candidates older than the candidate TTL.")
                .build(),
            endpoint_candidate_ttl_seconds: meter
                .u64_gauge("ipars.control_plane.endpoint_candidate_ttl_seconds")
                .with_description(
                    "Endpoint candidate freshness window used by control-plane peer maps.",
                )
                .build(),
            stale_paths: meter
                .u64_gauge("ipars.control_plane.stale_paths")
                .with_description("Control-plane paths older than the path-state TTL.")
                .build(),
            path_state_ttl_seconds: meter
                .u64_gauge("ipars.control_plane.path_state_ttl_seconds")
                .with_description(
                    "Path-state freshness window used by control-plane status and metrics.",
                )
                .build(),
            metrics_generated_timestamp_seconds: meter
                .u64_gauge("ipars.control_plane.metrics.generated_timestamp_seconds")
                .with_description(
                    "Unix timestamp of the control-plane metrics snapshot exported to OTLP.",
                )
                .build(),
            vpn_pool_total: meter
                .u64_gauge("ipars.control_plane.vpn_pool.total")
                .with_description("Usable VPN IP addresses in the configured pool.")
                .build(),
            vpn_pool_allocated: meter
                .u64_gauge("ipars.control_plane.vpn_pool.allocated")
                .with_description("Allocated VPN IP addresses in the configured pool.")
                .build(),
            vpn_pool_available: meter
                .u64_gauge("ipars.control_plane.vpn_pool.available")
                .with_description("Unallocated usable VPN IP addresses in the configured pool.")
                .build(),
            join_tokens: meter
                .u64_gauge("ipars.control_plane.join_tokens")
                .with_description("Join tokens by current token-ledger status.")
                .build(),
            join_tokens_issued: meter
                .u64_gauge("ipars.control_plane.join_tokens.issued")
                .with_description("Total join-token ledger records.")
                .build(),
            join_token_uses: meter
                .u64_gauge("ipars.control_plane.join_token_uses")
                .with_description("Total accepted join-token uses recorded by the ledger.")
                .build(),
            peer_map_candidates: meter
                .u64_gauge("ipars.control_plane.peer_map.candidates")
                .with_description("Source-target peer-map candidates before ACL filtering.")
                .build(),
            peer_map_visible: meter
                .u64_gauge("ipars.control_plane.peer_map.visible")
                .with_description("Source-target peer-map entries visible after ACL filtering.")
                .build(),
            peer_map_acl_denied: meter
                .u64_gauge("ipars.control_plane.peer_map.acl_denied")
                .with_description("Source-target peer-map entries hidden by ACL filtering.")
                .build(),
            peer_map_route_candidates: meter
                .u64_gauge("ipars.control_plane.peer_map.routes.candidates")
                .with_description(
                    "Advertised route candidates considered for peer maps before ACL filtering.",
                )
                .build(),
            peer_map_routes_visible: meter
                .u64_gauge("ipars.control_plane.peer_map.routes.visible")
                .with_description("Advertised routes visible in peer maps after ACL filtering.")
                .build(),
            peer_map_routes_acl_denied: meter
                .u64_gauge("ipars.control_plane.peer_map.routes.acl_denied")
                .with_description("Advertised routes hidden by peer-map ACL filtering.")
                .build(),
            node_health: meter
                .u64_gauge("ipars.control_plane.node_health")
                .with_description("Registered nodes by last reported health state.")
                .build(),
            paths: meter
                .u64_gauge("ipars.control_plane.paths")
                .with_description("Pair-scoped paths persisted by the control plane.")
                .build(),
            paths_by_state: meter
                .u64_gauge("ipars.control_plane.paths.by_state")
                .with_description(
                    "Pair-scoped paths persisted by the control plane, by selected state.",
                )
                .build(),
        }
    }

    fn record_status(&self, metrics: &ControlPlaneMetricsResponse) {
        let cluster_id = metrics.cluster_id.as_str().to_string();
        let cluster_attrs = [KeyValue::new("cluster_id", cluster_id.clone())];
        self.metrics_generated_timestamp_seconds.record(
            otel_generated_timestamp_seconds(&metrics.generated_at),
            &cluster_attrs,
        );
        self.nodes.record(metrics.node_count as u64, &cluster_attrs);
        self.relay_candidates
            .record(metrics.relay_candidate_count as u64, &cluster_attrs);
        self.stale_endpoint_candidates.record(
            metrics.stale_endpoint_candidate_count as u64,
            &cluster_attrs,
        );
        self.endpoint_candidate_ttl_seconds
            .record(metrics.endpoint_candidate_ttl_seconds, &cluster_attrs);
        self.stale_paths
            .record(metrics.stale_path_count as u64, &cluster_attrs);
        self.path_state_ttl_seconds
            .record(metrics.path_state_ttl_seconds, &cluster_attrs);
        self.vpn_pool_total
            .record(metrics.vpn_pool_total_count, &cluster_attrs);
        self.vpn_pool_allocated
            .record(metrics.vpn_pool_allocated_count, &cluster_attrs);
        self.vpn_pool_available
            .record(metrics.vpn_pool_available_count, &cluster_attrs);
        self.join_tokens_issued
            .record(metrics.token_ledger_issued_count, &cluster_attrs);
        self.join_token_uses
            .record(metrics.token_ledger_use_count, &cluster_attrs);
        self.peer_map_candidates
            .record(metrics.peer_map_candidate_count as u64, &cluster_attrs);
        self.peer_map_visible
            .record(metrics.peer_map_visible_count as u64, &cluster_attrs);
        self.peer_map_acl_denied
            .record(metrics.peer_map_acl_denied_count as u64, &cluster_attrs);
        self.peer_map_route_candidates.record(
            metrics.peer_map_route_candidate_count as u64,
            &cluster_attrs,
        );
        self.peer_map_routes_visible
            .record(metrics.peer_map_route_visible_count as u64, &cluster_attrs);
        self.peer_map_routes_acl_denied.record(
            metrics.peer_map_route_acl_denied_count as u64,
            &cluster_attrs,
        );
        self.paths.record(metrics.path_count as u64, &cluster_attrs);

        for (status, count) in [
            ("active", metrics.token_ledger_active_count),
            ("revoked", metrics.token_ledger_revoked_count),
            ("expired", metrics.token_ledger_expired_count),
            ("exhausted", metrics.token_ledger_exhausted_count),
        ] {
            let attrs = [
                KeyValue::new("cluster_id", cluster_id.clone()),
                KeyValue::new("status", status),
            ];
            self.join_tokens.record(count, &attrs);
        }

        for (state, count) in [
            (HealthState::Healthy, metrics.healthy_node_count),
            (HealthState::Degraded, metrics.degraded_node_count),
            (HealthState::Unhealthy, metrics.unhealthy_node_count),
        ] {
            let attrs = [
                KeyValue::new("cluster_id", cluster_id.clone()),
                KeyValue::new("state", health_label(state)),
            ];
            self.node_health.record(count as u64, &attrs);
        }

        for state in [
            PathState::DirectPublic,
            PathState::DirectIpv6,
            PathState::DirectNatTraversal,
            PathState::Relay,
            PathState::Unreachable,
        ] {
            let attrs = [
                KeyValue::new("cluster_id", cluster_id.clone()),
                KeyValue::new("state", path_state_label(state)),
            ];
            self.paths_by_state.record(
                control_plane_path_state_count(metrics, state) as u64,
                &attrs,
            );
        }
    }
}

fn control_plane_path_state_count(
    metrics: &ControlPlaneMetricsResponse,
    state: PathState,
) -> usize {
    metrics
        .path_state_counts
        .iter()
        .find(|entry| entry.state == state)
        .map(|entry| entry.count)
        .unwrap_or(0)
}

fn start_control_plane_otel_metrics_export<S, L>(
    plane: Arc<ControlPlane<S>>,
    join_service: Arc<ControlPlaneJoinService<S, L>>,
    interval: Duration,
) -> tokio::task::JoinHandle<()>
where
    S: ControlPlaneStore + 'static,
    L: TokenLedger + 'static,
{
    tokio::spawn(async move {
        let metrics = ControlPlaneOtelMetrics::new();
        loop {
            match plane.metrics().await {
                Ok(mut status) => {
                    match join_service
                        .token_metrics(&status.cluster_id, chrono::Utc::now())
                        .await
                    {
                        Ok(token_metrics) => {
                            apply_token_ledger_metrics(&mut status, token_metrics);
                            metrics.record_status(&status);
                        }
                        Err(error) => {
                            tracing::warn!(%error, "failed to collect control-plane token-ledger OTLP metrics")
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to collect control-plane OTLP metrics")
                }
            }
            tokio::time::sleep(interval).await;
        }
    })
}

fn apply_token_ledger_metrics(
    metrics: &mut ControlPlaneMetricsResponse,
    token_metrics: TokenLedgerMetrics,
) {
    metrics.token_ledger_issued_count = token_metrics.issued_count;
    metrics.token_ledger_active_count = token_metrics.active_count;
    metrics.token_ledger_revoked_count = token_metrics.revoked_count;
    metrics.token_ledger_expired_count = token_metrics.expired_count;
    metrics.token_ledger_exhausted_count = token_metrics.exhausted_count;
    metrics.token_ledger_use_count = token_metrics.use_count;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SignalOtelSnapshot {
    node_upsert_count: u64,
    path_negotiation_count: u64,
    path_acl_denied_count: u64,
    relay_candidate_acl_denied_count: u64,
    fresh_nat_classification_strategy_counts: Vec<NatTraversalStrategyCount>,
    path_negotiation_state_counts: Vec<PathStateCount>,
    hole_punch_plan_count: u64,
    hole_punch_acl_denied_count: u64,
    hole_punch_nat_suppressed_count: u64,
    hole_punch_nat_suppressed_strategy_counts: Vec<NatTraversalStrategyCount>,
}

impl From<&SignalMetricsResponse> for SignalOtelSnapshot {
    fn from(metrics: &SignalMetricsResponse) -> Self {
        Self {
            node_upsert_count: metrics.node_upsert_count,
            path_negotiation_count: metrics.path_negotiation_count,
            path_acl_denied_count: metrics.path_acl_denied_count,
            relay_candidate_acl_denied_count: metrics.relay_candidate_acl_denied_count,
            fresh_nat_classification_strategy_counts: metrics
                .fresh_nat_classification_strategy_counts
                .clone(),
            path_negotiation_state_counts: metrics.path_negotiation_state_counts.clone(),
            hole_punch_plan_count: metrics.hole_punch_plan_count,
            hole_punch_acl_denied_count: metrics.hole_punch_acl_denied_count,
            hole_punch_nat_suppressed_count: metrics.hole_punch_nat_suppressed_count,
            hole_punch_nat_suppressed_strategy_counts: metrics
                .hole_punch_nat_suppressed_strategy_counts
                .clone(),
        }
    }
}

#[derive(Debug)]
struct SignalOtelMetrics {
    nodes: Gauge<u64>,
    relay_candidates: Gauge<u64>,
    nat_classifications: Gauge<u64>,
    fresh_nat_classifications_by_strategy: Gauge<u64>,
    fresh_low_confidence_nat_classifications: Gauge<u64>,
    stale_nat_classifications: Gauge<u64>,
    health_report_total: Gauge<u64>,
    health_reports: Gauge<u64>,
    stale_health_reports: Gauge<u64>,
    relay_health_ttl_seconds: Gauge<u64>,
    stale_endpoint_candidates: Gauge<u64>,
    endpoint_candidate_ttl_seconds: Gauge<u64>,
    nat_classification_ttl_seconds: Gauge<u64>,
    nat_classification_min_confidence_percent: Gauge<u64>,
    metrics_generated_timestamp_seconds: Gauge<u64>,
    node_upserts: Counter<u64>,
    path_negotiations: Counter<u64>,
    path_acl_denials: Counter<u64>,
    relay_candidate_acl_denials: Counter<u64>,
    path_negotiations_by_state: Counter<u64>,
    hole_punch_plans: Counter<u64>,
    hole_punch_acl_denials: Counter<u64>,
    hole_punch_nat_suppressions: Counter<u64>,
    hole_punch_nat_suppressions_by_strategy: Counter<u64>,
}

impl SignalOtelMetrics {
    fn new() -> Self {
        let meter = global::meter("iparsd.signal");
        Self {
            nodes: meter
                .u64_gauge("ipars.signal.nodes")
                .with_description("Nodes registered with the signal service.")
                .build(),
            relay_candidates: meter
                .u64_gauge("ipars.signal.relay_candidates")
                .with_description("Relay candidates available for signal path negotiation.")
                .build(),
            nat_classifications: meter
                .u64_gauge("ipars.signal.nat_classifications")
                .with_description("Nodes with NAT classification registered in signal.")
                .build(),
            fresh_nat_classifications_by_strategy: meter
                .u64_gauge("ipars.signal.nat_classifications.fresh.by_strategy")
                .with_description("Fresh signal NAT classifications by traversal strategy.")
                .build(),
            fresh_low_confidence_nat_classifications: meter
                .u64_gauge("ipars.signal.nat_classifications.fresh.low_confidence")
                .with_description(
                    "Fresh signal NAT classifications below the configured confidence threshold.",
                )
                .build(),
            stale_nat_classifications: meter
                .u64_gauge("ipars.signal.stale_nat_classifications")
                .with_description(
                    "Signal NAT classifications older than the NAT classification TTL.",
                )
                .build(),
            health_report_total: meter
                .u64_gauge("ipars.signal.health_reports.total")
                .with_description("Total signal health reports stored.")
                .build(),
            health_reports: meter
                .u64_gauge("ipars.signal.health_reports")
                .with_description("Signal health reports by state.")
                .build(),
            stale_health_reports: meter
                .u64_gauge("ipars.signal.stale_health_reports")
                .with_description("Signal health reports older than the relay health TTL.")
                .build(),
            relay_health_ttl_seconds: meter
                .u64_gauge("ipars.signal.relay_health_ttl_seconds")
                .with_description("Relay health freshness window used by signal.")
                .build(),
            stale_endpoint_candidates: meter
                .u64_gauge("ipars.signal.stale_endpoint_candidates")
                .with_description("Signal endpoint candidates older than the candidate TTL.")
                .build(),
            endpoint_candidate_ttl_seconds: meter
                .u64_gauge("ipars.signal.endpoint_candidate_ttl_seconds")
                .with_description("Endpoint candidate freshness window used by signal.")
                .build(),
            nat_classification_ttl_seconds: meter
                .u64_gauge("ipars.signal.nat_classification_ttl_seconds")
                .with_description("NAT classification freshness window used by signal.")
                .build(),
            nat_classification_min_confidence_percent: meter
                .u64_gauge("ipars.signal.nat_classification_min_confidence_percent")
                .with_description(
                    "Minimum NAT classification confidence percentage required by signal.",
                )
                .build(),
            metrics_generated_timestamp_seconds: meter
                .u64_gauge("ipars.signal.metrics.generated_timestamp_seconds")
                .with_description("Unix timestamp of the signal metrics snapshot exported to OTLP.")
                .build(),
            node_upserts: meter
                .u64_counter("ipars.signal.node_upserts")
                .with_description("Signal node upsert requests handled.")
                .build(),
            path_negotiations: meter
                .u64_counter("ipars.signal.path_negotiations")
                .with_description("Signal path negotiation requests handled.")
                .build(),
            path_acl_denials: meter
                .u64_counter("ipars.signal.path_acl_denials")
                .with_description("Signal path negotiations hidden by cluster ACL policy.")
                .build(),
            relay_candidate_acl_denials: meter
                .u64_counter("ipars.signal.relay_candidate_acl_denials")
                .with_description(
                    "Eligible relay candidates removed from signal negotiation by cluster ACL policy.",
                )
                .build(),
            path_negotiations_by_state: meter
                .u64_counter("ipars.signal.path_negotiations.by_state")
                .with_description("Successful signal path negotiations by selected state.")
                .build(),
            hole_punch_plans: meter
                .u64_counter("ipars.signal.hole_punch_plans")
                .with_description("Signal hole-punch plan requests handled.")
                .build(),
            hole_punch_acl_denials: meter
                .u64_counter("ipars.signal.hole_punch_acl_denials")
                .with_description("Signal hole-punch plans hidden by cluster ACL policy.")
                .build(),
            hole_punch_nat_suppressions: meter
                .u64_counter("ipars.signal.hole_punch_nat_suppressions")
                .with_description("Signal hole-punch plans suppressed by NAT classification.")
                .build(),
            hole_punch_nat_suppressions_by_strategy: meter
                .u64_counter("ipars.signal.hole_punch_nat_suppressions.by_strategy")
                .with_description(
                    "Hole-punch suppressing NAT classifications observed during suppressed plans by traversal strategy.",
                )
                .build(),
        }
    }

    fn record_status(
        &self,
        metrics: &SignalMetricsResponse,
        previous: Option<&SignalOtelSnapshot>,
    ) {
        self.metrics_generated_timestamp_seconds
            .record(otel_generated_timestamp_seconds(&metrics.generated_at), &[]);
        self.nodes.record(metrics.node_count as u64, &[]);
        self.relay_candidates
            .record(metrics.relay_candidate_count as u64, &[]);
        self.nat_classifications
            .record(metrics.nat_classification_count as u64, &[]);
        for strategy in NatTraversalStrategy::ALL {
            let attrs = [KeyValue::new("strategy", strategy.as_str())];
            self.fresh_nat_classifications_by_strategy
                .record(signal_nat_strategy_count(metrics, strategy) as u64, &attrs);
        }
        self.fresh_low_confidence_nat_classifications.record(
            metrics.fresh_low_confidence_nat_classification_count as u64,
            &[],
        );
        self.stale_nat_classifications
            .record(metrics.stale_nat_classification_count as u64, &[]);
        self.health_report_total
            .record(metrics.health_report_count as u64, &[]);
        self.stale_health_reports
            .record(metrics.stale_health_report_count as u64, &[]);
        self.relay_health_ttl_seconds
            .record(metrics.relay_health_ttl_seconds, &[]);
        self.stale_endpoint_candidates
            .record(metrics.stale_endpoint_candidate_count as u64, &[]);
        self.endpoint_candidate_ttl_seconds
            .record(metrics.endpoint_candidate_ttl_seconds, &[]);
        self.nat_classification_ttl_seconds
            .record(metrics.nat_classification_ttl_seconds, &[]);
        self.nat_classification_min_confidence_percent.record(
            metrics.nat_classification_min_confidence_percent as u64,
            &[],
        );

        for (state, count) in [
            (HealthState::Healthy, metrics.healthy_node_count),
            (HealthState::Degraded, metrics.degraded_node_count),
            (HealthState::Unhealthy, metrics.unhealthy_node_count),
        ] {
            let attrs = [KeyValue::new("state", health_label(state))];
            self.health_reports.record(count as u64, &attrs);
        }

        self.node_upserts.add(
            counter_delta(
                metrics.node_upsert_count,
                previous.map(|previous| previous.node_upsert_count),
            ),
            &[],
        );
        self.path_negotiations.add(
            counter_delta(
                metrics.path_negotiation_count,
                previous.map(|previous| previous.path_negotiation_count),
            ),
            &[],
        );
        self.path_acl_denials.add(
            counter_delta(
                metrics.path_acl_denied_count,
                previous.map(|previous| previous.path_acl_denied_count),
            ),
            &[],
        );
        self.relay_candidate_acl_denials.add(
            counter_delta(
                metrics.relay_candidate_acl_denied_count,
                previous.map(|previous| previous.relay_candidate_acl_denied_count),
            ),
            &[],
        );
        for state in [
            PathState::DirectPublic,
            PathState::DirectIpv6,
            PathState::DirectNatTraversal,
            PathState::Relay,
            PathState::Unreachable,
        ] {
            let attrs = [KeyValue::new("state", path_state_label(state))];
            self.path_negotiations_by_state.add(
                counter_delta(
                    signal_path_state_count(metrics, state) as u64,
                    previous
                        .map(|previous| signal_snapshot_path_state_count(previous, state) as u64),
                ),
                &attrs,
            );
        }
        self.hole_punch_plans.add(
            counter_delta(
                metrics.hole_punch_plan_count,
                previous.map(|previous| previous.hole_punch_plan_count),
            ),
            &[],
        );
        self.hole_punch_acl_denials.add(
            counter_delta(
                metrics.hole_punch_acl_denied_count,
                previous.map(|previous| previous.hole_punch_acl_denied_count),
            ),
            &[],
        );
        self.hole_punch_nat_suppressions.add(
            counter_delta(
                metrics.hole_punch_nat_suppressed_count,
                previous.map(|previous| previous.hole_punch_nat_suppressed_count),
            ),
            &[],
        );
        for strategy in NatTraversalStrategy::ALL {
            let attrs = [KeyValue::new("strategy", strategy.as_str())];
            self.hole_punch_nat_suppressions_by_strategy.add(
                counter_delta(
                    signal_hole_punch_nat_suppression_strategy_count(metrics, strategy) as u64,
                    previous.map(|previous| {
                        signal_snapshot_hole_punch_nat_suppression_strategy_count(
                            previous, strategy,
                        ) as u64
                    }),
                ),
                &attrs,
            );
        }
    }
}

fn start_signal_otel_metrics_export(
    registry: Arc<SignalRegistry>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let metrics = SignalOtelMetrics::new();
        let mut previous = None;
        loop {
            let status = registry.metrics().await;
            metrics.record_status(&status, previous.as_ref());
            previous = Some(SignalOtelSnapshot::from(&status));
            tokio::time::sleep(interval).await;
        }
    })
}

fn signal_path_state_count(metrics: &SignalMetricsResponse, state: PathState) -> usize {
    metrics
        .path_negotiation_state_counts
        .iter()
        .find(|entry| entry.state == state)
        .map(|entry| entry.count)
        .unwrap_or(0)
}

fn signal_snapshot_path_state_count(snapshot: &SignalOtelSnapshot, state: PathState) -> usize {
    snapshot
        .path_negotiation_state_counts
        .iter()
        .find(|entry| entry.state == state)
        .map(|entry| entry.count)
        .unwrap_or(0)
}

fn signal_nat_strategy_count(
    metrics: &SignalMetricsResponse,
    strategy: NatTraversalStrategy,
) -> usize {
    metrics
        .fresh_nat_classification_strategy_counts
        .iter()
        .find(|entry| entry.strategy == strategy)
        .map(|entry| entry.count)
        .unwrap_or(0)
}

#[cfg(test)]
fn signal_snapshot_nat_strategy_count(
    snapshot: &SignalOtelSnapshot,
    strategy: NatTraversalStrategy,
) -> usize {
    snapshot
        .fresh_nat_classification_strategy_counts
        .iter()
        .find(|entry| entry.strategy == strategy)
        .map(|entry| entry.count)
        .unwrap_or(0)
}

fn signal_hole_punch_nat_suppression_strategy_count(
    metrics: &SignalMetricsResponse,
    strategy: NatTraversalStrategy,
) -> usize {
    metrics
        .hole_punch_nat_suppressed_strategy_counts
        .iter()
        .find(|entry| entry.strategy == strategy)
        .map(|entry| entry.count)
        .unwrap_or(0)
}

fn signal_snapshot_hole_punch_nat_suppression_strategy_count(
    snapshot: &SignalOtelSnapshot,
    strategy: NatTraversalStrategy,
) -> usize {
    snapshot
        .hole_punch_nat_suppressed_strategy_counts
        .iter()
        .find(|entry| entry.strategy == strategy)
        .map(|entry| entry.count)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RelayOtelSnapshot {
    admission_attempt_count: u64,
    admission_success_count: u64,
    admission_failure_count: u64,
    admission_failures_by_reason: BTreeMap<RelayAdmissionFailureReason, u64>,
    dataplane: RelayDataplaneMetrics,
}

impl From<&RelayStatusResponse> for RelayOtelSnapshot {
    fn from(status: &RelayStatusResponse) -> Self {
        Self {
            admission_attempt_count: status.admission_attempt_count,
            admission_success_count: status.admission_success_count,
            admission_failure_count: status.admission_failure_count,
            admission_failures_by_reason: status.admission_failures_by_reason.clone(),
            dataplane: status.dataplane.clone(),
        }
    }
}

#[derive(Debug)]
struct RelayOtelMetrics {
    admission_attempts: Counter<u64>,
    admission_success: Counter<u64>,
    admission_failures: Counter<u64>,
    admission_failures_by_reason: Counter<u64>,
    datagrams_received: Counter<u64>,
    datagram_bytes_received: Counter<u64>,
    datagrams_forwarded: Counter<u64>,
    datagrams_dropped: Counter<u64>,
    datagrams_dropped_by_reason: Counter<u64>,
    datagram_bytes_dropped: Counter<u64>,
    payload_bytes_forwarded: Counter<u64>,
    active_sessions: Gauge<u64>,
    max_sessions: Gauge<u64>,
    available_sessions: Gauge<u64>,
    max_sessions_per_node: Gauge<u64>,
    max_mbps: Gauge<u64>,
    enabled_by_policy: Gauge<u64>,
    e2e_only: Gauge<u64>,
    health: Gauge<u64>,
    status_generated_timestamp_seconds: Gauge<u64>,
}

impl RelayOtelMetrics {
    fn new() -> Self {
        let meter = global::meter("iparsd.relay");
        Self {
            admission_attempts: meter
                .u64_counter("ipars.relay.admission.attempts")
                .with_description("Relay session admission attempts.")
                .build(),
            admission_success: meter
                .u64_counter("ipars.relay.admission.success")
                .with_description("Relay session admissions accepted.")
                .build(),
            admission_failures: meter
                .u64_counter("ipars.relay.admission.failures")
                .with_description("Relay session admission failures.")
                .build(),
            admission_failures_by_reason: meter
                .u64_counter("ipars.relay.admission.failures_by_reason")
                .with_description("Relay session admission failures, by reason.")
                .build(),
            datagrams_received: meter
                .u64_counter("ipars.relay.datagrams.received")
                .with_description("UDP relay datagrams received.")
                .build(),
            datagram_bytes_received: meter
                .u64_counter("ipars.relay.datagram.bytes.received")
                .with_description("UDP relay datagram bytes received, including relay metadata.")
                .with_unit("By")
                .build(),
            datagrams_forwarded: meter
                .u64_counter("ipars.relay.datagrams.forwarded")
                .with_description("UDP relay datagrams accepted for forwarding.")
                .build(),
            datagrams_dropped: meter
                .u64_counter("ipars.relay.datagrams.dropped")
                .with_description("UDP relay datagrams dropped before forwarding.")
                .build(),
            datagrams_dropped_by_reason: meter
                .u64_counter("ipars.relay.datagrams.dropped_by_reason")
                .with_description("UDP relay datagrams dropped before forwarding, by reason.")
                .build(),
            datagram_bytes_dropped: meter
                .u64_counter("ipars.relay.datagram.bytes.dropped")
                .with_description("UDP relay datagram bytes dropped, including relay metadata.")
                .with_unit("By")
                .build(),
            payload_bytes_forwarded: meter
                .u64_counter("ipars.relay.payload.bytes.forwarded")
                .with_description("Opaque payload bytes accepted for relay forwarding.")
                .with_unit("By")
                .build(),
            active_sessions: meter
                .u64_gauge("ipars.relay.sessions.active")
                .with_description("Active relay sessions.")
                .build(),
            max_sessions: meter
                .u64_gauge("ipars.relay.sessions.max")
                .with_description("Configured relay session capacity.")
                .build(),
            available_sessions: meter
                .u64_gauge("ipars.relay.sessions.available")
                .with_description("Available relay session capacity.")
                .build(),
            max_sessions_per_node: meter
                .u64_gauge("ipars.relay.sessions.max_per_node")
                .with_description(
                    "Configured active relay session cap per participating node. Zero means disabled.",
                )
                .build(),
            max_mbps: meter
                .u64_gauge("ipars.relay.max_mbps")
                .with_description("Configured relay throughput budget.")
                .with_unit("Mbit/s")
                .build(),
            enabled_by_policy: meter
                .u64_gauge("ipars.relay.enabled_by_policy")
                .with_description("Whether relay admission is enabled by policy.")
                .build(),
            e2e_only: meter
                .u64_gauge("ipars.relay.e2e_only")
                .with_description(
                    "Whether relay forwarding is restricted to end-to-end encrypted opaque payloads.",
                )
                .build(),
            health: meter
                .u64_gauge("ipars.relay.health")
                .with_description("Relay health state as a labeled gauge.")
                .build(),
            status_generated_timestamp_seconds: meter
                .u64_gauge("ipars.relay.status.generated_timestamp_seconds")
                .with_description("Unix timestamp of the relay status snapshot exported to OTLP.")
                .build(),
        }
    }

    fn record_status(&self, status: &RelayStatusResponse, previous: Option<&RelayOtelSnapshot>) {
        let delta = relay_dataplane_delta(
            &status.dataplane,
            previous.map(|snapshot| &snapshot.dataplane),
        );
        let relay_node = status.relay_node.as_str().to_string();
        let relay_attrs = [KeyValue::new("relay_node", relay_node.clone())];
        self.status_generated_timestamp_seconds.record(
            otel_generated_timestamp_seconds(&status.generated_at),
            &relay_attrs,
        );
        let admission_attempt_delta = counter_delta(
            status.admission_attempt_count,
            previous.map(|snapshot| snapshot.admission_attempt_count),
        );
        if admission_attempt_delta > 0 {
            self.admission_attempts
                .add(admission_attempt_delta, &relay_attrs);
        }
        let admission_success_delta = counter_delta(
            status.admission_success_count,
            previous.map(|snapshot| snapshot.admission_success_count),
        );
        if admission_success_delta > 0 {
            self.admission_success
                .add(admission_success_delta, &relay_attrs);
        }
        let admission_failure_delta = counter_delta(
            status.admission_failure_count,
            previous.map(|snapshot| snapshot.admission_failure_count),
        );
        if admission_failure_delta > 0 {
            self.admission_failures
                .add(admission_failure_delta, &relay_attrs);
        }
        let admission_failure_reason_delta = relay_admission_failure_reason_delta(
            &status.admission_failures_by_reason,
            previous.map(|snapshot| &snapshot.admission_failures_by_reason),
        );
        for (reason, count) in admission_failure_reason_delta {
            let attrs = [
                KeyValue::new("relay_node", relay_node.clone()),
                KeyValue::new("reason", reason.as_str()),
            ];
            self.admission_failures_by_reason.add(count, &attrs);
        }
        self.datagrams_received
            .add(delta.datagrams_received, &relay_attrs);
        self.datagram_bytes_received
            .add(delta.datagram_bytes_received, &relay_attrs);
        self.datagrams_forwarded
            .add(delta.datagrams_forwarded, &relay_attrs);
        self.datagrams_dropped
            .add(delta.datagrams_dropped, &relay_attrs);
        self.datagram_bytes_dropped
            .add(delta.datagram_bytes_dropped, &relay_attrs);
        self.payload_bytes_forwarded
            .add(delta.payload_bytes_forwarded, &relay_attrs);
        for (reason, count) in delta.drops_by_reason {
            let attrs = [
                KeyValue::new("relay_node", relay_node.clone()),
                KeyValue::new("reason", reason.as_str()),
            ];
            self.datagrams_dropped_by_reason.add(count, &attrs);
        }

        self.active_sessions
            .record(status.capability.active_sessions as u64, &relay_attrs);
        self.max_sessions
            .record(status.capability.max_sessions as u64, &relay_attrs);
        self.available_sessions
            .record(status.capability.available_capacity() as u64, &relay_attrs);
        self.max_sessions_per_node.record(
            status.max_sessions_per_node.unwrap_or_default() as u64,
            &relay_attrs,
        );
        self.max_mbps
            .record(status.capability.max_mbps as u64, &relay_attrs);
        self.enabled_by_policy
            .record(u64::from(status.capability.enabled_by_policy), &relay_attrs);
        self.e2e_only
            .record(u64::from(status.capability.e2e_only), &relay_attrs);
        for state in [
            HealthState::Healthy,
            HealthState::Degraded,
            HealthState::Unhealthy,
        ] {
            let attrs = [
                KeyValue::new("relay_node", relay_node.clone()),
                KeyValue::new("state", health_label(state)),
            ];
            self.health
                .record(u64::from(status.health == state), &attrs);
        }
    }
}

fn relay_dataplane_delta(
    current: &RelayDataplaneMetrics,
    previous: Option<&RelayDataplaneMetrics>,
) -> RelayDataplaneMetrics {
    let mut drops_by_reason = BTreeMap::new();
    for reason in RelayDataplaneDropReason::ALL {
        let current_count = current.drops_by_reason.get(&reason).copied().unwrap_or(0);
        let previous_count = previous
            .and_then(|previous| previous.drops_by_reason.get(&reason))
            .copied()
            .unwrap_or(0);
        drops_by_reason.insert(reason, current_count.saturating_sub(previous_count));
    }
    RelayDataplaneMetrics {
        datagrams_received: counter_delta(
            current.datagrams_received,
            previous.map(|previous| previous.datagrams_received),
        ),
        datagrams_forwarded: counter_delta(
            current.datagrams_forwarded,
            previous.map(|previous| previous.datagrams_forwarded),
        ),
        datagrams_dropped: counter_delta(
            current.datagrams_dropped,
            previous.map(|previous| previous.datagrams_dropped),
        ),
        datagram_bytes_received: counter_delta(
            current.datagram_bytes_received,
            previous.map(|previous| previous.datagram_bytes_received),
        ),
        payload_bytes_forwarded: counter_delta(
            current.payload_bytes_forwarded,
            previous.map(|previous| previous.payload_bytes_forwarded),
        ),
        datagram_bytes_dropped: counter_delta(
            current.datagram_bytes_dropped,
            previous.map(|previous| previous.datagram_bytes_dropped),
        ),
        drops_by_reason,
    }
}

fn relay_admission_failure_reason_delta(
    current: &BTreeMap<RelayAdmissionFailureReason, u64>,
    previous: Option<&BTreeMap<RelayAdmissionFailureReason, u64>>,
) -> BTreeMap<RelayAdmissionFailureReason, u64> {
    let mut delta_by_reason = BTreeMap::new();
    for reason in RelayAdmissionFailureReason::ALL {
        let current_count = current.get(&reason).copied().unwrap_or(0);
        let previous_count = previous
            .and_then(|previous| previous.get(&reason))
            .copied()
            .unwrap_or(0);
        delta_by_reason.insert(reason, current_count.saturating_sub(previous_count));
    }
    delta_by_reason
}

fn counter_delta(current: u64, previous: Option<u64>) -> u64 {
    current.saturating_sub(previous.unwrap_or(0))
}

fn otel_generated_timestamp_seconds(generated_at: &chrono::DateTime<chrono::Utc>) -> u64 {
    generated_at.timestamp().max(0) as u64
}

fn health_label(state: HealthState) -> &'static str {
    match state {
        HealthState::Healthy => "healthy",
        HealthState::Degraded => "degraded",
        HealthState::Unhealthy => "unhealthy",
    }
}

fn path_state_label(state: PathState) -> &'static str {
    match state {
        PathState::DirectPublic => "direct_public",
        PathState::DirectIpv6 => "direct_ipv6",
        PathState::DirectNatTraversal => "direct_nat_traversal",
        PathState::Relay => "relay",
        PathState::Unreachable => "unreachable",
    }
}

fn start_relay_otel_metrics_export(
    service: Arc<RelayService>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let metrics = RelayOtelMetrics::new();
        let mut previous = None;
        loop {
            let status = service.status().await;
            metrics.record_status(&status, previous.as_ref());
            previous = Some(RelayOtelSnapshot::from(&status));
            tokio::time::sleep(interval).await;
        }
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AgentOtelSnapshot {
    relay_forwarders: BTreeMap<(NodeId, NodeId), AgentRelayForwarderMetrics>,
    relay_admission_attempt_count: u64,
    relay_admission_success_count: u64,
    relay_admission_failure_count: u64,
    relay_admission_failure_reason_counts: BTreeMap<AgentRelayAdmissionFailureReason, u64>,
    path_probe_record_count: u64,
    peer_activity_record_count: u64,
    packet_flow_observation_count: u64,
    packet_flow_match_count: u64,
    packet_flow_unmatched_count: u64,
    packet_flow_filtered_count: u64,
    packet_flow_filtered_reason_counts: BTreeMap<AgentPacketFlowDropReason, u64>,
    packet_flow_duplicate_suppression_count: u64,
    packet_flow_duplicate_suppression_counts: BTreeMap<AgentPacketFlowDuplicateSource, u64>,
    packet_flow_classification_counts: BTreeMap<AgentPacketFlowClassification, u64>,
    packet_flow_application_counts: BTreeMap<AgentPacketFlowApplication, u64>,
}

impl From<&AgentMetricsResponse> for AgentOtelSnapshot {
    fn from(metrics: &AgentMetricsResponse) -> Self {
        Self {
            relay_forwarders: metrics
                .relay_forwarders
                .iter()
                .cloned()
                .map(|forwarder| {
                    (
                        (forwarder.peer.clone(), forwarder.relay_node.clone()),
                        forwarder,
                    )
                })
                .collect(),
            relay_admission_attempt_count: metrics.relay_admission_attempt_count,
            relay_admission_success_count: metrics.relay_admission_success_count,
            relay_admission_failure_count: metrics.relay_admission_failure_count,
            relay_admission_failure_reason_counts: metrics
                .relay_admission_failure_reason_counts
                .iter()
                .map(|entry| (entry.reason, entry.count))
                .collect(),
            path_probe_record_count: metrics.path_probe_record_count,
            peer_activity_record_count: metrics.peer_activity_record_count,
            packet_flow_observation_count: metrics.packet_flow_observation_count,
            packet_flow_match_count: metrics.packet_flow_match_count,
            packet_flow_unmatched_count: metrics.packet_flow_unmatched_count,
            packet_flow_filtered_count: metrics.packet_flow_filtered_count,
            packet_flow_filtered_reason_counts: metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .map(|entry| (entry.reason, entry.count))
                .collect(),
            packet_flow_duplicate_suppression_count: metrics
                .packet_flow_duplicate_suppression_count,
            packet_flow_duplicate_suppression_counts: metrics
                .packet_flow_duplicate_suppression_counts
                .iter()
                .map(|entry| (entry.source, entry.count))
                .collect(),
            packet_flow_classification_counts: metrics
                .packet_flow_classification_counts
                .iter()
                .map(|entry| (entry.classification, entry.count))
                .collect(),
            packet_flow_application_counts: metrics
                .packet_flow_application_counts
                .iter()
                .map(|entry| (entry.application, entry.count))
                .collect(),
        }
    }
}

#[derive(Debug)]
struct AgentOtelMetrics {
    candidates: Gauge<u64>,
    peer_map_synced: Gauge<u64>,
    peer_map_peers: Gauge<u64>,
    peer_map_routes: Gauge<u64>,
    peer_map_generated_timestamp_seconds: Gauge<u64>,
    paths: Gauge<u64>,
    paths_by_state: Gauge<u64>,
    relay_sessions: Gauge<u64>,
    relay_forwarders: Gauge<u64>,
    userspace_wireguard_process_state: Gauge<u64>,
    path_change_events: Gauge<u64>,
    metrics_generated_timestamp_seconds: Gauge<u64>,
    lazy_active_peers: Gauge<u64>,
    lazy_pinned_peers: Gauge<u64>,
    lazy_observed_peer_vpn_ips: Gauge<u64>,
    lazy_observed_route_peers: Gauge<u64>,
    lazy_observed_routes: Gauge<u64>,
    relay_admission_attempts: Counter<u64>,
    relay_admission_success: Counter<u64>,
    relay_admission_failures: Counter<u64>,
    relay_admission_failures_by_reason: Counter<u64>,
    path_probe_records: Counter<u64>,
    peer_activity_records: Counter<u64>,
    packet_flow_observations: Counter<u64>,
    packet_flow_matches: Counter<u64>,
    packet_flow_unmatched: Counter<u64>,
    packet_flow_filtered: Counter<u64>,
    packet_flow_filtered_by_reason: Counter<u64>,
    packet_flow_duplicate_suppressions: Counter<u64>,
    packet_flow_duplicate_suppressions_by_source: Counter<u64>,
    packet_flow_classified_by_lifecycle: Counter<u64>,
    packet_flow_classified_by_application: Counter<u64>,
    forwarder_outbound_packets: Counter<u64>,
    forwarder_socket_receive_errors: Counter<u64>,
    forwarder_outbound_payload_bytes: Counter<u64>,
    forwarder_outbound_datagram_bytes: Counter<u64>,
    forwarder_outbound_dropped_unexpected_source_packets: Counter<u64>,
    forwarder_outbound_dropped_unexpected_source_payload_bytes: Counter<u64>,
    forwarder_outbound_dropped_expired_session_packets: Counter<u64>,
    forwarder_outbound_dropped_expired_session_payload_bytes: Counter<u64>,
    forwarder_outbound_dropped_oversized_packets: Counter<u64>,
    forwarder_outbound_dropped_oversized_payload_bytes: Counter<u64>,
    forwarder_outbound_dropped_oversized_datagram_bytes: Counter<u64>,
    forwarder_outbound_dropped_socket_error_packets: Counter<u64>,
    forwarder_outbound_dropped_socket_error_payload_bytes: Counter<u64>,
    forwarder_outbound_dropped_socket_error_datagram_bytes: Counter<u64>,
    forwarder_outbound_dropped_non_wireguard_packets: Counter<u64>,
    forwarder_outbound_dropped_non_wireguard_payload_bytes: Counter<u64>,
    forwarder_inbound_packets: Counter<u64>,
    forwarder_inbound_payload_bytes: Counter<u64>,
    forwarder_inbound_dropped_expired_session_packets: Counter<u64>,
    forwarder_inbound_dropped_expired_session_payload_bytes: Counter<u64>,
    forwarder_inbound_dropped_oversized_packets: Counter<u64>,
    forwarder_inbound_dropped_oversized_payload_bytes: Counter<u64>,
    forwarder_inbound_dropped_socket_error_packets: Counter<u64>,
    forwarder_inbound_dropped_socket_error_payload_bytes: Counter<u64>,
    forwarder_inbound_dropped_non_wireguard_packets: Counter<u64>,
    forwarder_inbound_dropped_non_wireguard_payload_bytes: Counter<u64>,
}

impl AgentOtelMetrics {
    fn new() -> Self {
        let meter = global::meter("iparsd.agent");
        Self {
            candidates: meter
                .u64_gauge("ipars.agent.candidates")
                .with_description("Endpoint candidates currently known by the agent.")
                .build(),
            peer_map_synced: meter
                .u64_gauge("ipars.agent.peer_map.synced")
                .with_description("Whether the agent has successfully applied at least one peer map.")
                .build(),
            peer_map_peers: meter
                .u64_gauge("ipars.agent.peer_map.peers")
                .with_description("Peers in the last successfully applied peer map.")
                .build(),
            peer_map_routes: meter
                .u64_gauge("ipars.agent.peer_map.routes")
                .with_description(
                    "Advertised routes in the last successfully applied peer map.",
                )
                .build(),
            peer_map_generated_timestamp_seconds: meter
                .u64_gauge("ipars.agent.peer_map.generated_timestamp_seconds")
                .with_description(
                    "Unix timestamp of the control-plane peer map currently held by the agent, or 0 before the first successful sync.",
                )
                .build(),
            paths: meter
                .u64_gauge("ipars.agent.paths")
                .with_description("Peer paths currently tracked by the agent.")
                .build(),
            paths_by_state: meter
                .u64_gauge("ipars.agent.paths.by_state")
                .with_description("Peer paths currently tracked by the agent, by selected state.")
                .build(),
            relay_sessions: meter
                .u64_gauge("ipars.agent.relay.sessions")
                .with_description("Active relay sessions held by the agent.")
                .build(),
            relay_forwarders: meter
                .u64_gauge("ipars.agent.relay.forwarders")
                .with_description("Supervised relay forwarder endpoints.")
                .build(),
            userspace_wireguard_process_state: meter
                .u64_gauge("ipars.agent.userspace_wireguard.process.state")
                .with_description(
                    "Managed userspace WireGuard process state, exported as one-hot gauges.",
                )
                .build(),
            path_change_events: meter
                .u64_gauge("ipars.agent.path_change_events")
                .with_description("Retained path change events.")
                .build(),
            metrics_generated_timestamp_seconds: meter
                .u64_gauge("ipars.agent.metrics.generated_timestamp_seconds")
                .with_description("Unix timestamp of the agent metrics snapshot exported to OTLP.")
                .build(),
            lazy_active_peers: meter
                .u64_gauge("ipars.agent.lazy_connect.active_peers")
                .with_description("Peers with recent lazy-connect activity.")
                .build(),
            lazy_pinned_peers: meter
                .u64_gauge("ipars.agent.lazy_connect.pinned_peers")
                .with_description("Peers pinned in lazy-connect state.")
                .build(),
            lazy_observed_peer_vpn_ips: meter
                .u64_gauge("ipars.agent.lazy_connect.observed_peer_vpn_ips")
                .with_description("Peer VPN IPs indexed for packet-flow resolution.")
                .build(),
            lazy_observed_route_peers: meter
                .u64_gauge("ipars.agent.lazy_connect.observed_route_peers")
                .with_description(
                    "Peers with advertised routes indexed for packet-flow resolution.",
                )
                .build(),
            lazy_observed_routes: meter
                .u64_gauge("ipars.agent.lazy_connect.observed_routes")
                .with_description("Advertised routes indexed for packet-flow resolution.")
                .build(),
            relay_admission_attempts: meter
                .u64_counter("ipars.agent.relay.admission.attempts")
                .with_description("Relay admission candidate attempts made by the agent.")
                .build(),
            relay_admission_success: meter
                .u64_counter("ipars.agent.relay.admission.success")
                .with_description("Relay admission candidate attempts accepted by relays.")
                .build(),
            relay_admission_failures: meter
                .u64_counter("ipars.agent.relay.admission.failures")
                .with_description("Relay admission candidate attempts rejected or unreachable.")
                .build(),
            relay_admission_failures_by_reason: meter
                .u64_counter("ipars.agent.relay.admission.failures.by_reason")
                .with_description(
                    "Relay admission candidate failures by agent-observed reason.",
                )
                .build(),
            path_probe_records: meter
                .u64_counter("ipars.agent.path_probe.records")
                .with_description("Path probe records accepted by the agent.")
                .build(),
            peer_activity_records: meter
                .u64_counter("ipars.agent.peer_activity.records")
                .with_description("Peer activity records accepted by the agent.")
                .build(),
            packet_flow_observations: meter
                .u64_counter("ipars.agent.packet_flow.observations")
                .with_description("Packet-flow observations submitted to lazy-connect resolution.")
                .build(),
            packet_flow_matches: meter
                .u64_counter("ipars.agent.packet_flow.matches")
                .with_description("Packet-flow observations that resolved to a peer.")
                .build(),
            packet_flow_unmatched: meter
                .u64_counter("ipars.agent.packet_flow.unmatched")
                .with_description("Packet-flow observations that did not resolve to a peer.")
                .build(),
            packet_flow_filtered: meter
                .u64_counter("ipars.agent.packet_flow.filtered")
                .with_description(
                    "Packet-flow observations filtered before or after lazy-connect resolution.",
                )
                .build(),
            packet_flow_filtered_by_reason: meter
                .u64_counter("ipars.agent.packet_flow.filtered.by_reason")
                .with_description(
                    "Packet-flow observations filtered before or after lazy-connect resolution, by reason.",
                )
                .build(),
            packet_flow_duplicate_suppressions: meter
                .u64_counter("ipars.agent.packet_flow.duplicate_suppressions")
                .with_description(
                    "Duplicate packet-flow observations suppressed before lazy-connect resolution.",
                )
                .build(),
            packet_flow_duplicate_suppressions_by_source: meter
                .u64_counter("ipars.agent.packet_flow.duplicate_suppressions.by_source")
                .with_description(
                    "Duplicate packet-flow observations suppressed before lazy-connect resolution, by detector source.",
                )
                .build(),
            packet_flow_classified_by_lifecycle: meter
                .u64_counter("ipars.agent.packet_flow.classified.by_lifecycle")
                .with_description(
                    "Packet-flow observations classified by inferred conntrack lifecycle.",
                )
                .build(),
            packet_flow_classified_by_application: meter
                .u64_counter("ipars.agent.packet_flow.classified.by_application")
                .with_description(
                    "Packet-flow observations classified by inferred application protocol.",
                )
                .build(),
            forwarder_outbound_packets: meter
                .u64_counter("ipars.agent.relay.forwarder.outbound.packets")
                .with_description("Relay forwarder packets sent from local WireGuard to relay.")
                .build(),
            forwarder_socket_receive_errors: meter
                .u64_counter("ipars.agent.relay.forwarder.socket_receive.errors")
                .with_description(
                    "Relay forwarder recoverable UDP receive errors that did not stop the forwarder.",
                )
                .build(),
            forwarder_outbound_payload_bytes: meter
                .u64_counter("ipars.agent.relay.forwarder.outbound.payload.bytes")
                .with_description(
                    "Relay forwarder opaque payload bytes sent from local WireGuard to relay.",
                )
                .with_unit("By")
                .build(),
            forwarder_outbound_datagram_bytes: meter
                .u64_counter("ipars.agent.relay.forwarder.outbound.datagram.bytes")
                .with_description("Relay forwarder framed datagram bytes sent to relay.")
                .with_unit("By")
                .build(),
            forwarder_outbound_dropped_unexpected_source_packets: meter
                .u64_counter(
                    "ipars.agent.relay.forwarder.outbound.dropped.unexpected_source.packets",
                )
                .with_description(
                    "Relay forwarder packets dropped before relay because the sender did not match the configured local WireGuard endpoint.",
                )
                .build(),
            forwarder_outbound_dropped_unexpected_source_payload_bytes: meter
                .u64_counter(
                    "ipars.agent.relay.forwarder.outbound.dropped.unexpected_source.payload.bytes",
                )
                .with_description(
                    "Relay forwarder payload bytes dropped before relay because the sender did not match the configured local WireGuard endpoint.",
                )
                .with_unit("By")
                .build(),
            forwarder_outbound_dropped_expired_session_packets: meter
                .u64_counter(
                    "ipars.agent.relay.forwarder.outbound.dropped.expired_session.packets",
                )
                .with_description(
                    "Relay forwarder local packets dropped before relay because the relay session credential expired.",
                )
                .build(),
            forwarder_outbound_dropped_expired_session_payload_bytes: meter
                .u64_counter(
                    "ipars.agent.relay.forwarder.outbound.dropped.expired_session.payload.bytes",
                )
                .with_description(
                    "Relay forwarder local payload bytes dropped before relay because the relay session credential expired.",
                )
                .with_unit("By")
                .build(),
            forwarder_outbound_dropped_oversized_packets: meter
                .u64_counter("ipars.agent.relay.forwarder.outbound.dropped.oversized.packets")
                .with_description(
                    "Relay forwarder local packets dropped before relay because the framed relay datagram would exceed the UDP payload limit.",
                )
                .build(),
            forwarder_outbound_dropped_oversized_payload_bytes: meter
                .u64_counter(
                    "ipars.agent.relay.forwarder.outbound.dropped.oversized.payload.bytes",
                )
                .with_description(
                    "Relay forwarder local payload bytes dropped before relay because the framed relay datagram would exceed the UDP payload limit.",
                )
                .with_unit("By")
                .build(),
            forwarder_outbound_dropped_oversized_datagram_bytes: meter
                .u64_counter(
                    "ipars.agent.relay.forwarder.outbound.dropped.oversized.datagram.bytes",
                )
                .with_description(
                    "Relay forwarder framed datagram bytes dropped before relay because they would exceed the UDP payload limit.",
                )
                .with_unit("By")
                .build(),
            forwarder_outbound_dropped_socket_error_packets: meter
                .u64_counter("ipars.agent.relay.forwarder.outbound.dropped.socket_error.packets")
                .with_description(
                    "Relay forwarder local packets dropped because sending the framed relay datagram failed.",
                )
                .build(),
            forwarder_outbound_dropped_socket_error_payload_bytes: meter
                .u64_counter(
                    "ipars.agent.relay.forwarder.outbound.dropped.socket_error.payload.bytes",
                )
                .with_description(
                    "Relay forwarder local payload bytes dropped because sending the framed relay datagram failed.",
                )
                .with_unit("By")
                .build(),
            forwarder_outbound_dropped_socket_error_datagram_bytes: meter
                .u64_counter(
                    "ipars.agent.relay.forwarder.outbound.dropped.socket_error.datagram.bytes",
                )
                .with_description(
                    "Relay forwarder framed datagram bytes dropped because sending them to the relay failed.",
                )
                .with_unit("By")
                .build(),
            forwarder_outbound_dropped_non_wireguard_packets: meter
                .u64_counter("ipars.agent.relay.forwarder.outbound.dropped.non_wireguard.packets")
                .with_description(
                    "Relay forwarder local packets dropped before relay because they were not WireGuard datagrams.",
                )
                .build(),
            forwarder_outbound_dropped_non_wireguard_payload_bytes: meter
                .u64_counter("ipars.agent.relay.forwarder.outbound.dropped.non_wireguard.payload.bytes")
                .with_description(
                    "Relay forwarder local payload bytes dropped before relay because they were not WireGuard datagrams.",
                )
                .with_unit("By")
                .build(),
            forwarder_inbound_packets: meter
                .u64_counter("ipars.agent.relay.forwarder.inbound.packets")
                .with_description(
                    "Relay forwarder packets received from relay and sent to local WireGuard.",
                )
                .build(),
            forwarder_inbound_payload_bytes: meter
                .u64_counter("ipars.agent.relay.forwarder.inbound.payload.bytes")
                .with_description("Relay forwarder opaque payload bytes received from relay.")
                .with_unit("By")
                .build(),
            forwarder_inbound_dropped_expired_session_packets: meter
                .u64_counter(
                    "ipars.agent.relay.forwarder.inbound.dropped.expired_session.packets",
                )
                .with_description(
                    "Relay forwarder relay packets dropped before local WireGuard because the relay session credential expired.",
                )
                .build(),
            forwarder_inbound_dropped_expired_session_payload_bytes: meter
                .u64_counter(
                    "ipars.agent.relay.forwarder.inbound.dropped.expired_session.payload.bytes",
                )
                .with_description(
                    "Relay forwarder relay payload bytes dropped before local WireGuard because the relay session credential expired.",
                )
                .with_unit("By")
                .build(),
            forwarder_inbound_dropped_oversized_packets: meter
                .u64_counter("ipars.agent.relay.forwarder.inbound.dropped.oversized.packets")
                .with_description(
                    "Relay forwarder relay packets dropped before local WireGuard because the payload exceeds the UDP payload limit.",
                )
                .build(),
            forwarder_inbound_dropped_oversized_payload_bytes: meter
                .u64_counter(
                    "ipars.agent.relay.forwarder.inbound.dropped.oversized.payload.bytes",
                )
                .with_description(
                    "Relay forwarder relay payload bytes dropped before local WireGuard because the payload exceeds the UDP payload limit.",
                )
                .with_unit("By")
                .build(),
            forwarder_inbound_dropped_socket_error_packets: meter
                .u64_counter("ipars.agent.relay.forwarder.inbound.dropped.socket_error.packets")
                .with_description(
                    "Relay forwarder relay packets dropped because sending the payload to local WireGuard failed.",
                )
                .build(),
            forwarder_inbound_dropped_socket_error_payload_bytes: meter
                .u64_counter(
                    "ipars.agent.relay.forwarder.inbound.dropped.socket_error.payload.bytes",
                )
                .with_description(
                    "Relay forwarder relay payload bytes dropped because sending the payload to local WireGuard failed.",
                )
                .with_unit("By")
                .build(),
            forwarder_inbound_dropped_non_wireguard_packets: meter
                .u64_counter("ipars.agent.relay.forwarder.inbound.dropped.non_wireguard.packets")
                .with_description(
                    "Relay forwarder relay packets dropped before local WireGuard because they were not WireGuard datagrams.",
                )
                .build(),
            forwarder_inbound_dropped_non_wireguard_payload_bytes: meter
                .u64_counter("ipars.agent.relay.forwarder.inbound.dropped.non_wireguard.payload.bytes")
                .with_description(
                    "Relay forwarder relay payload bytes dropped before local WireGuard because they were not WireGuard datagrams.",
                )
                .with_unit("By")
                .build(),
        }
    }

    fn record_status(&self, metrics: &AgentMetricsResponse, previous: Option<&AgentOtelSnapshot>) {
        let node_id = metrics.node_id.as_str().to_string();
        let node_attrs = [KeyValue::new("node_id", node_id.clone())];
        self.metrics_generated_timestamp_seconds.record(
            otel_generated_timestamp_seconds(&metrics.generated_at),
            &node_attrs,
        );
        self.candidates
            .record(metrics.candidate_count as u64, &node_attrs);
        self.peer_map_synced
            .record(if metrics.peer_map_synced { 1 } else { 0 }, &node_attrs);
        self.peer_map_peers
            .record(metrics.peer_map_peer_count as u64, &node_attrs);
        self.peer_map_routes
            .record(metrics.peer_map_route_count as u64, &node_attrs);
        self.peer_map_generated_timestamp_seconds.record(
            metrics
                .peer_map_generated_at
                .map(|generated_at| generated_at.timestamp().max(0) as u64)
                .unwrap_or_default(),
            &node_attrs,
        );
        self.paths.record(metrics.path_count as u64, &node_attrs);
        self.relay_sessions
            .record(metrics.relay_session_count as u64, &node_attrs);
        self.relay_forwarders
            .record(metrics.relay_forwarder_count as u64, &node_attrs);
        let userspace_wireguard_state = metrics
            .userspace_wireguard_process
            .as_ref()
            .map(|status| status.state)
            .unwrap_or(AgentManagedProcessState::Disabled);
        for state in AgentManagedProcessState::ALL {
            let attrs = [
                KeyValue::new("node_id", node_id.clone()),
                KeyValue::new("state", state.as_str()),
            ];
            let value = if state == userspace_wireguard_state {
                1
            } else {
                0
            };
            self.userspace_wireguard_process_state.record(value, &attrs);
        }
        self.path_change_events
            .record(metrics.path_change_event_count as u64, &node_attrs);
        self.lazy_active_peers
            .record(metrics.lazy_connect.active_peer_count as u64, &node_attrs);
        self.lazy_pinned_peers
            .record(metrics.lazy_connect.pinned_peer_count as u64, &node_attrs);
        self.lazy_observed_peer_vpn_ips.record(
            metrics.lazy_connect.observed_peer_vpn_ip_count as u64,
            &node_attrs,
        );
        self.lazy_observed_route_peers.record(
            metrics.lazy_connect.observed_route_peer_count as u64,
            &node_attrs,
        );
        self.lazy_observed_routes.record(
            metrics.lazy_connect.observed_route_count as u64,
            &node_attrs,
        );

        let relay_admission_attempt_delta = counter_delta(
            metrics.relay_admission_attempt_count,
            previous.map(|previous| previous.relay_admission_attempt_count),
        );
        if relay_admission_attempt_delta > 0 {
            self.relay_admission_attempts
                .add(relay_admission_attempt_delta, &node_attrs);
        }
        let relay_admission_success_delta = counter_delta(
            metrics.relay_admission_success_count,
            previous.map(|previous| previous.relay_admission_success_count),
        );
        if relay_admission_success_delta > 0 {
            self.relay_admission_success
                .add(relay_admission_success_delta, &node_attrs);
        }
        let relay_admission_failure_delta = counter_delta(
            metrics.relay_admission_failure_count,
            previous.map(|previous| previous.relay_admission_failure_count),
        );
        if relay_admission_failure_delta > 0 {
            self.relay_admission_failures
                .add(relay_admission_failure_delta, &node_attrs);
        }
        for (reason, delta) in agent_relay_admission_failure_reason_delta(metrics, previous) {
            let attrs = [
                KeyValue::new("node_id", node_id.clone()),
                KeyValue::new("reason", reason.as_str()),
            ];
            self.relay_admission_failures_by_reason.add(delta, &attrs);
        }

        let path_probe_delta = counter_delta(
            metrics.path_probe_record_count,
            previous.map(|previous| previous.path_probe_record_count),
        );
        if path_probe_delta > 0 {
            self.path_probe_records.add(path_probe_delta, &node_attrs);
        }
        let peer_activity_delta = counter_delta(
            metrics.peer_activity_record_count,
            previous.map(|previous| previous.peer_activity_record_count),
        );
        if peer_activity_delta > 0 {
            self.peer_activity_records
                .add(peer_activity_delta, &node_attrs);
        }
        let packet_flow_observation_delta = counter_delta(
            metrics.packet_flow_observation_count,
            previous.map(|previous| previous.packet_flow_observation_count),
        );
        if packet_flow_observation_delta > 0 {
            self.packet_flow_observations
                .add(packet_flow_observation_delta, &node_attrs);
        }
        let packet_flow_match_delta = counter_delta(
            metrics.packet_flow_match_count,
            previous.map(|previous| previous.packet_flow_match_count),
        );
        if packet_flow_match_delta > 0 {
            self.packet_flow_matches
                .add(packet_flow_match_delta, &node_attrs);
        }
        let packet_flow_unmatched_delta = counter_delta(
            metrics.packet_flow_unmatched_count,
            previous.map(|previous| previous.packet_flow_unmatched_count),
        );
        if packet_flow_unmatched_delta > 0 {
            self.packet_flow_unmatched
                .add(packet_flow_unmatched_delta, &node_attrs);
        }
        let packet_flow_filtered_delta = counter_delta(
            metrics.packet_flow_filtered_count,
            previous.map(|previous| previous.packet_flow_filtered_count),
        );
        if packet_flow_filtered_delta > 0 {
            self.packet_flow_filtered
                .add(packet_flow_filtered_delta, &node_attrs);
        }
        for (reason, delta) in agent_packet_flow_filtered_reason_delta(metrics, previous) {
            let attrs = [
                KeyValue::new("node_id", node_id.clone()),
                KeyValue::new("reason", reason.as_str()),
            ];
            self.packet_flow_filtered_by_reason.add(delta, &attrs);
        }
        let packet_flow_duplicate_suppression_delta = counter_delta(
            metrics.packet_flow_duplicate_suppression_count,
            previous.map(|previous| previous.packet_flow_duplicate_suppression_count),
        );
        if packet_flow_duplicate_suppression_delta > 0 {
            self.packet_flow_duplicate_suppressions
                .add(packet_flow_duplicate_suppression_delta, &node_attrs);
        }
        for (source, delta) in
            agent_packet_flow_duplicate_suppression_source_delta(metrics, previous)
        {
            let attrs = [
                KeyValue::new("node_id", node_id.clone()),
                KeyValue::new("source", source.as_str()),
            ];
            self.packet_flow_duplicate_suppressions_by_source
                .add(delta, &attrs);
        }
        for (classification, delta) in agent_packet_flow_classification_delta(metrics, previous) {
            let attrs = [
                KeyValue::new("node_id", node_id.clone()),
                KeyValue::new("classification", classification.as_str()),
            ];
            self.packet_flow_classified_by_lifecycle.add(delta, &attrs);
        }
        for (application, delta) in agent_packet_flow_application_delta(metrics, previous) {
            let attrs = [
                KeyValue::new("node_id", node_id.clone()),
                KeyValue::new("application", application.as_str()),
            ];
            self.packet_flow_classified_by_application
                .add(delta, &attrs);
        }

        for state in [
            PathState::DirectPublic,
            PathState::DirectIpv6,
            PathState::DirectNatTraversal,
            PathState::Relay,
            PathState::Unreachable,
        ] {
            let count = metrics
                .path_state_counts
                .iter()
                .find(|entry| entry.state == state)
                .map(|entry| entry.count)
                .unwrap_or(0);
            let attrs = [
                KeyValue::new("node_id", node_id.clone()),
                KeyValue::new("state", path_state_label(state)),
            ];
            self.paths_by_state.record(count as u64, &attrs);
        }

        for forwarder in agent_forwarder_deltas(metrics, previous) {
            let attrs = [
                KeyValue::new("node_id", node_id.clone()),
                KeyValue::new("peer", forwarder.peer.as_str().to_string()),
                KeyValue::new("relay_node", forwarder.relay_node.as_str().to_string()),
            ];
            self.forwarder_socket_receive_errors
                .add(forwarder.socket_receive_errors, &attrs);
            self.forwarder_outbound_packets
                .add(forwarder.outbound_packets, &attrs);
            self.forwarder_outbound_payload_bytes
                .add(forwarder.outbound_payload_bytes, &attrs);
            self.forwarder_outbound_datagram_bytes
                .add(forwarder.outbound_datagram_bytes, &attrs);
            self.forwarder_outbound_dropped_unexpected_source_packets
                .add(forwarder.outbound_dropped_unexpected_source_packets, &attrs);
            self.forwarder_outbound_dropped_unexpected_source_payload_bytes
                .add(
                    forwarder.outbound_dropped_unexpected_source_payload_bytes,
                    &attrs,
                );
            self.forwarder_outbound_dropped_expired_session_packets
                .add(forwarder.outbound_dropped_expired_session_packets, &attrs);
            self.forwarder_outbound_dropped_expired_session_payload_bytes
                .add(
                    forwarder.outbound_dropped_expired_session_payload_bytes,
                    &attrs,
                );
            self.forwarder_outbound_dropped_oversized_packets
                .add(forwarder.outbound_dropped_oversized_packets, &attrs);
            self.forwarder_outbound_dropped_oversized_payload_bytes
                .add(forwarder.outbound_dropped_oversized_payload_bytes, &attrs);
            self.forwarder_outbound_dropped_oversized_datagram_bytes
                .add(forwarder.outbound_dropped_oversized_datagram_bytes, &attrs);
            self.forwarder_outbound_dropped_socket_error_packets
                .add(forwarder.outbound_dropped_socket_error_packets, &attrs);
            self.forwarder_outbound_dropped_socket_error_payload_bytes
                .add(
                    forwarder.outbound_dropped_socket_error_payload_bytes,
                    &attrs,
                );
            self.forwarder_outbound_dropped_socket_error_datagram_bytes
                .add(
                    forwarder.outbound_dropped_socket_error_datagram_bytes,
                    &attrs,
                );
            self.forwarder_outbound_dropped_non_wireguard_packets
                .add(forwarder.outbound_dropped_non_wireguard_packets, &attrs);
            self.forwarder_outbound_dropped_non_wireguard_payload_bytes
                .add(
                    forwarder.outbound_dropped_non_wireguard_payload_bytes,
                    &attrs,
                );
            self.forwarder_inbound_packets
                .add(forwarder.inbound_packets, &attrs);
            self.forwarder_inbound_payload_bytes
                .add(forwarder.inbound_payload_bytes, &attrs);
            self.forwarder_inbound_dropped_expired_session_packets
                .add(forwarder.inbound_dropped_expired_session_packets, &attrs);
            self.forwarder_inbound_dropped_expired_session_payload_bytes
                .add(
                    forwarder.inbound_dropped_expired_session_payload_bytes,
                    &attrs,
                );
            self.forwarder_inbound_dropped_oversized_packets
                .add(forwarder.inbound_dropped_oversized_packets, &attrs);
            self.forwarder_inbound_dropped_oversized_payload_bytes
                .add(forwarder.inbound_dropped_oversized_payload_bytes, &attrs);
            self.forwarder_inbound_dropped_socket_error_packets
                .add(forwarder.inbound_dropped_socket_error_packets, &attrs);
            self.forwarder_inbound_dropped_socket_error_payload_bytes
                .add(forwarder.inbound_dropped_socket_error_payload_bytes, &attrs);
            self.forwarder_inbound_dropped_non_wireguard_packets
                .add(forwarder.inbound_dropped_non_wireguard_packets, &attrs);
            self.forwarder_inbound_dropped_non_wireguard_payload_bytes
                .add(
                    forwarder.inbound_dropped_non_wireguard_payload_bytes,
                    &attrs,
                );
        }
    }
}

fn agent_relay_admission_failure_reason_delta(
    metrics: &AgentMetricsResponse,
    previous: Option<&AgentOtelSnapshot>,
) -> BTreeMap<AgentRelayAdmissionFailureReason, u64> {
    let mut delta_by_reason = BTreeMap::new();
    for reason in AgentRelayAdmissionFailureReason::ALL {
        let current_count = metrics
            .relay_admission_failure_reason_counts
            .iter()
            .find(|entry| entry.reason == reason)
            .map(|entry| entry.count)
            .unwrap_or(0);
        let previous_count = previous.and_then(|previous| {
            previous
                .relay_admission_failure_reason_counts
                .get(&reason)
                .copied()
        });
        delta_by_reason.insert(reason, counter_delta(current_count, previous_count));
    }
    delta_by_reason
}

fn agent_packet_flow_filtered_reason_delta(
    metrics: &AgentMetricsResponse,
    previous: Option<&AgentOtelSnapshot>,
) -> BTreeMap<AgentPacketFlowDropReason, u64> {
    let mut delta_by_reason = BTreeMap::new();
    for reason in AgentPacketFlowDropReason::ALL {
        let current_count = metrics
            .packet_flow_filtered_reason_counts
            .iter()
            .find(|entry| entry.reason == reason)
            .map(|entry| entry.count)
            .unwrap_or(0);
        let previous_count = previous.and_then(|previous| {
            previous
                .packet_flow_filtered_reason_counts
                .get(&reason)
                .copied()
        });
        delta_by_reason.insert(reason, counter_delta(current_count, previous_count));
    }
    delta_by_reason
}

fn agent_packet_flow_duplicate_suppression_source_delta(
    metrics: &AgentMetricsResponse,
    previous: Option<&AgentOtelSnapshot>,
) -> BTreeMap<AgentPacketFlowDuplicateSource, u64> {
    let mut delta_by_source = BTreeMap::new();
    for source in AgentPacketFlowDuplicateSource::ALL {
        let current_count = metrics
            .packet_flow_duplicate_suppression_counts
            .iter()
            .find(|entry| entry.source == source)
            .map(|entry| entry.count)
            .unwrap_or(0);
        let previous_count = previous.and_then(|previous| {
            previous
                .packet_flow_duplicate_suppression_counts
                .get(&source)
                .copied()
        });
        delta_by_source.insert(source, counter_delta(current_count, previous_count));
    }
    delta_by_source
}

fn agent_packet_flow_classification_delta(
    metrics: &AgentMetricsResponse,
    previous: Option<&AgentOtelSnapshot>,
) -> BTreeMap<AgentPacketFlowClassification, u64> {
    let mut delta_by_classification = BTreeMap::new();
    for classification in AgentPacketFlowClassification::ALL {
        let current_count = metrics
            .packet_flow_classification_counts
            .iter()
            .find(|entry| entry.classification == classification)
            .map(|entry| entry.count)
            .unwrap_or(0);
        let previous_count = previous.and_then(|previous| {
            previous
                .packet_flow_classification_counts
                .get(&classification)
                .copied()
        });
        delta_by_classification
            .insert(classification, counter_delta(current_count, previous_count));
    }
    delta_by_classification
}

fn agent_packet_flow_application_delta(
    metrics: &AgentMetricsResponse,
    previous: Option<&AgentOtelSnapshot>,
) -> BTreeMap<AgentPacketFlowApplication, u64> {
    let mut delta_by_application = BTreeMap::new();
    for application in AgentPacketFlowApplication::ALL {
        let current_count = metrics
            .packet_flow_application_counts
            .iter()
            .find(|entry| entry.application == application)
            .map(|entry| entry.count)
            .unwrap_or(0);
        let previous_count = previous.and_then(|previous| {
            previous
                .packet_flow_application_counts
                .get(&application)
                .copied()
        });
        delta_by_application.insert(application, counter_delta(current_count, previous_count));
    }
    delta_by_application
}

fn agent_forwarder_deltas(
    metrics: &AgentMetricsResponse,
    previous: Option<&AgentOtelSnapshot>,
) -> Vec<AgentRelayForwarderMetrics> {
    metrics
        .relay_forwarders
        .iter()
        .filter_map(|current| {
            let previous = previous.and_then(|snapshot| {
                snapshot
                    .relay_forwarders
                    .get(&(current.peer.clone(), current.relay_node.clone()))
            });
            let delta = agent_forwarder_delta(current, previous);
            has_agent_forwarder_delta(&delta).then_some(delta)
        })
        .collect()
}

fn agent_forwarder_delta(
    current: &AgentRelayForwarderMetrics,
    previous: Option<&AgentRelayForwarderMetrics>,
) -> AgentRelayForwarderMetrics {
    AgentRelayForwarderMetrics {
        peer: current.peer.clone(),
        relay_node: current.relay_node.clone(),
        relay_endpoint: current.relay_endpoint,
        local_endpoint: current.local_endpoint,
        socket_receive_errors: counter_delta(
            current.socket_receive_errors,
            previous.map(|previous| previous.socket_receive_errors),
        ),
        outbound_packets: counter_delta(
            current.outbound_packets,
            previous.map(|previous| previous.outbound_packets),
        ),
        outbound_payload_bytes: counter_delta(
            current.outbound_payload_bytes,
            previous.map(|previous| previous.outbound_payload_bytes),
        ),
        outbound_datagram_bytes: counter_delta(
            current.outbound_datagram_bytes,
            previous.map(|previous| previous.outbound_datagram_bytes),
        ),
        outbound_dropped_unexpected_source_packets: counter_delta(
            current.outbound_dropped_unexpected_source_packets,
            previous.map(|previous| previous.outbound_dropped_unexpected_source_packets),
        ),
        outbound_dropped_unexpected_source_payload_bytes: counter_delta(
            current.outbound_dropped_unexpected_source_payload_bytes,
            previous.map(|previous| previous.outbound_dropped_unexpected_source_payload_bytes),
        ),
        outbound_dropped_expired_session_packets: counter_delta(
            current.outbound_dropped_expired_session_packets,
            previous.map(|previous| previous.outbound_dropped_expired_session_packets),
        ),
        outbound_dropped_expired_session_payload_bytes: counter_delta(
            current.outbound_dropped_expired_session_payload_bytes,
            previous.map(|previous| previous.outbound_dropped_expired_session_payload_bytes),
        ),
        outbound_dropped_oversized_packets: counter_delta(
            current.outbound_dropped_oversized_packets,
            previous.map(|previous| previous.outbound_dropped_oversized_packets),
        ),
        outbound_dropped_oversized_payload_bytes: counter_delta(
            current.outbound_dropped_oversized_payload_bytes,
            previous.map(|previous| previous.outbound_dropped_oversized_payload_bytes),
        ),
        outbound_dropped_oversized_datagram_bytes: counter_delta(
            current.outbound_dropped_oversized_datagram_bytes,
            previous.map(|previous| previous.outbound_dropped_oversized_datagram_bytes),
        ),
        outbound_dropped_socket_error_packets: counter_delta(
            current.outbound_dropped_socket_error_packets,
            previous.map(|previous| previous.outbound_dropped_socket_error_packets),
        ),
        outbound_dropped_socket_error_payload_bytes: counter_delta(
            current.outbound_dropped_socket_error_payload_bytes,
            previous.map(|previous| previous.outbound_dropped_socket_error_payload_bytes),
        ),
        outbound_dropped_socket_error_datagram_bytes: counter_delta(
            current.outbound_dropped_socket_error_datagram_bytes,
            previous.map(|previous| previous.outbound_dropped_socket_error_datagram_bytes),
        ),
        outbound_dropped_non_wireguard_packets: counter_delta(
            current.outbound_dropped_non_wireguard_packets,
            previous.map(|previous| previous.outbound_dropped_non_wireguard_packets),
        ),
        outbound_dropped_non_wireguard_payload_bytes: counter_delta(
            current.outbound_dropped_non_wireguard_payload_bytes,
            previous.map(|previous| previous.outbound_dropped_non_wireguard_payload_bytes),
        ),
        inbound_packets: counter_delta(
            current.inbound_packets,
            previous.map(|previous| previous.inbound_packets),
        ),
        inbound_payload_bytes: counter_delta(
            current.inbound_payload_bytes,
            previous.map(|previous| previous.inbound_payload_bytes),
        ),
        inbound_dropped_expired_session_packets: counter_delta(
            current.inbound_dropped_expired_session_packets,
            previous.map(|previous| previous.inbound_dropped_expired_session_packets),
        ),
        inbound_dropped_expired_session_payload_bytes: counter_delta(
            current.inbound_dropped_expired_session_payload_bytes,
            previous.map(|previous| previous.inbound_dropped_expired_session_payload_bytes),
        ),
        inbound_dropped_oversized_packets: counter_delta(
            current.inbound_dropped_oversized_packets,
            previous.map(|previous| previous.inbound_dropped_oversized_packets),
        ),
        inbound_dropped_oversized_payload_bytes: counter_delta(
            current.inbound_dropped_oversized_payload_bytes,
            previous.map(|previous| previous.inbound_dropped_oversized_payload_bytes),
        ),
        inbound_dropped_socket_error_packets: counter_delta(
            current.inbound_dropped_socket_error_packets,
            previous.map(|previous| previous.inbound_dropped_socket_error_packets),
        ),
        inbound_dropped_socket_error_payload_bytes: counter_delta(
            current.inbound_dropped_socket_error_payload_bytes,
            previous.map(|previous| previous.inbound_dropped_socket_error_payload_bytes),
        ),
        inbound_dropped_non_wireguard_packets: counter_delta(
            current.inbound_dropped_non_wireguard_packets,
            previous.map(|previous| previous.inbound_dropped_non_wireguard_packets),
        ),
        inbound_dropped_non_wireguard_payload_bytes: counter_delta(
            current.inbound_dropped_non_wireguard_payload_bytes,
            previous.map(|previous| previous.inbound_dropped_non_wireguard_payload_bytes),
        ),
        last_forwarded_at: current.last_forwarded_at,
    }
}

fn has_agent_forwarder_delta(delta: &AgentRelayForwarderMetrics) -> bool {
    delta.outbound_packets > 0
        || delta.socket_receive_errors > 0
        || delta.outbound_payload_bytes > 0
        || delta.outbound_datagram_bytes > 0
        || delta.outbound_dropped_unexpected_source_packets > 0
        || delta.outbound_dropped_unexpected_source_payload_bytes > 0
        || delta.outbound_dropped_expired_session_packets > 0
        || delta.outbound_dropped_expired_session_payload_bytes > 0
        || delta.outbound_dropped_oversized_packets > 0
        || delta.outbound_dropped_oversized_payload_bytes > 0
        || delta.outbound_dropped_oversized_datagram_bytes > 0
        || delta.outbound_dropped_socket_error_packets > 0
        || delta.outbound_dropped_socket_error_payload_bytes > 0
        || delta.outbound_dropped_socket_error_datagram_bytes > 0
        || delta.outbound_dropped_non_wireguard_packets > 0
        || delta.outbound_dropped_non_wireguard_payload_bytes > 0
        || delta.inbound_packets > 0
        || delta.inbound_payload_bytes > 0
        || delta.inbound_dropped_expired_session_packets > 0
        || delta.inbound_dropped_expired_session_payload_bytes > 0
        || delta.inbound_dropped_oversized_packets > 0
        || delta.inbound_dropped_oversized_payload_bytes > 0
        || delta.inbound_dropped_socket_error_packets > 0
        || delta.inbound_dropped_socket_error_payload_bytes > 0
        || delta.inbound_dropped_non_wireguard_packets > 0
        || delta.inbound_dropped_non_wireguard_payload_bytes > 0
}

fn start_agent_otel_metrics_export(
    runtime: Arc<AgentRuntime>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let metrics = AgentOtelMetrics::new();
        let mut previous = None;
        loop {
            let status = runtime.metrics().await;
            metrics.record_status(&status, previous.as_ref());
            previous = Some(AgentOtelSnapshot::from(&status));
            tokio::time::sleep(interval).await;
        }
    })
}

#[derive(Debug, Clone)]
struct AgentRegistration {
    control_plane_url: String,
    response: RegisterNodeResponse,
}

async fn run_relay(
    args: RelayArgs,
    otel_metrics_enabled: bool,
    otel_metrics_interval: Duration,
) -> anyhow::Result<()> {
    validate_relay_config(&args)?;
    let udp_relay = UdpRelay::bind(args.udp_listen).await?;
    let udp_addr = udp_relay.local_addr()?;
    let public_endpoint = args
        .public_endpoint
        .context("--public-endpoint is required for relay advertisement")?;
    let admission_url = args
        .admission_url
        .clone()
        .context("--admission-url is required for relay advertisement")?;
    let admission_rate_limit = if args.admission_rate_limit > 0 {
        Some(RelayAdmissionRateLimit {
            max_attempts: args.admission_rate_limit,
            window: chrono_duration_seconds(
                args.admission_rate_limit_window_seconds,
                "--admission-rate-limit-window-seconds",
            )?,
        })
    } else {
        None
    };
    let max_sessions_per_node =
        (args.max_sessions_per_node > 0).then_some(args.max_sessions_per_node);
    let service = Arc::new(RelayService::with_session_ttl_admission_controls(
        NodeId::from_string(args.relay_node_id),
        RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(public_endpoint),
            admission_url: Some(admission_url),
            max_sessions: args.max_sessions,
            active_sessions: 0,
            max_mbps: args.max_mbps,
            e2e_only: true,
        },
        chrono_duration_seconds(args.session_ttl_seconds, "--session-ttl-seconds")?,
        admission_rate_limit,
        max_sessions_per_node,
    ));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let udp_task = tokio::spawn(udp_relay.serve(service.table(), shutdown_rx));
    let otel_metrics_task = otel_metrics_enabled.then(|| {
        start_relay_otel_metrics_export(
            service.clone(),
            otel_metrics_interval.max(Duration::from_secs(1)),
        )
    });
    tracing::info!(%udp_addr, http_listen = %args.http_listen, "relay listening");
    let mut http_state = RelayHttpState::new(service);
    if let Some(token) = args.admission_bearer_token {
        http_state = http_state.require_admission_bearer_token(token);
    }
    let http_result = serve_router(args.http_listen, relay_router(http_state)).await;
    udp_task.abort();
    if let Some(task) = otel_metrics_task {
        task.abort();
    }
    http_result
}

fn validate_relay_config(args: &RelayArgs) -> anyhow::Result<()> {
    validate_daemon_identifier(&args.relay_node_id, "--relay-node-id")?;
    let public_endpoint = args
        .public_endpoint
        .context("--public-endpoint is required for relay advertisement")?;
    validate_usable_socket_endpoint(public_endpoint, "--public-endpoint")?;
    let admission_url = args
        .admission_url
        .as_deref()
        .context("--admission-url is required for relay advertisement")?;
    validate_http_url(admission_url, "--admission-url")?;
    if args.max_sessions == 0 {
        anyhow::bail!("--max-sessions must be greater than zero");
    }
    if args.max_mbps == 0 {
        anyhow::bail!("--max-mbps must be greater than zero");
    }
    if args.max_sessions_per_node > args.max_sessions {
        anyhow::bail!("--max-sessions-per-node must be less than or equal to --max-sessions");
    }
    validate_bounded_u64(
        args.session_ttl_seconds,
        "--session-ttl-seconds",
        MAX_RELAY_SESSION_TTL_SECONDS,
    )?;
    if args.admission_rate_limit > 0 {
        validate_bounded_u64(
            args.admission_rate_limit_window_seconds,
            "--admission-rate-limit-window-seconds",
            MAX_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
        )?;
    }
    if let Some(token) = args.admission_bearer_token.as_deref() {
        validate_relay_admission_bearer_token(token, "--admission-bearer-token")?;
    }
    Ok(())
}

fn chrono_duration_seconds(value: u64, name: &str) -> anyhow::Result<chrono::Duration> {
    let seconds = i64::try_from(value).with_context(|| format!("{name} is too large"))?;
    Ok(chrono::Duration::seconds(seconds))
}

async fn run_agent(
    args: AgentArgs,
    otel_metrics_enabled: bool,
    otel_metrics_interval: Duration,
) -> anyhow::Result<()> {
    validate_agent_runtime_config(&args)?;
    let store = FileAgentStateStore::new(args.state_path.clone());
    let state = store.load_or_create(chrono::Utc::now())?;
    let runtime = Arc::new(AgentRuntime::new(state, ClusterPolicy::default()));
    let relay_capability_reporter = agent_relay_capability_reporter(&args)?;
    let relay_capability = relay_capability_reporter
        .as_ref()
        .map(|reporter| reporter.advertised.clone());
    let join_token = agent_join_token(&args)?;
    let stun_servers = agent_stun_servers(&args, join_token.as_ref()).await?;
    if stun_servers.len() > 1 {
        if let Err(error) = runtime
            .classify_nat(args.stun_bind, stun_servers.clone())
            .await
        {
            tracing::warn!(
                %error,
                stun_servers = stun_servers.len(),
                "startup STUN NAT classification failed; continuing without initial NAT classification"
            );
        }
    } else if let Some(stun_server) = stun_servers.first().copied() {
        if let Err(error) = runtime.probe_stun(args.stun_bind, stun_server).await {
            tracing::warn!(
                %error,
                %stun_server,
                "startup STUN probe failed; continuing without initial reflexive candidate"
            );
        }
    }
    let mut registered_control_plane_base = None;
    let registered_node = if let Some(token) = &join_token {
        let requested_routes = agent_requested_routes(&args, runtime.state().node_id.clone())
            .await
            .context("failed to build agent requested routes")?;
        let registration = register_agent(
            runtime.as_ref(),
            token,
            args.control_plane_url.as_deref(),
            relay_capability.clone(),
            requested_routes,
        )
        .await
        .context("failed to register agent with control plane")?;
        let response = registration.response;
        registered_control_plane_base = Some(registration.control_plane_url);
        let registered_node = response.node.clone();
        tracing::info!(
            node_id = %response.node.node_id,
            vpn_ip = %response.node.vpn_ip,
            peer_count = response.peer_map.peers.len(),
            relay_count = response.relay_map.relays.len(),
            "registered agent with control plane"
        );
        Some(registered_node)
    } else {
        None
    };
    let control_plane_bases = agent_control_plane_base_urls(
        join_token.as_ref(),
        args.control_plane_url.as_deref(),
        registered_control_plane_base.as_deref(),
    )?;
    let signal_bases =
        signal_base_urls(join_token.as_ref(), args.signal_url.as_deref()).unwrap_or_default();
    preflight_agent_runtime(&args)?;
    let userspace_wireguard_process =
        start_userspace_wireguard_process(&args, runtime.clone()).await?;
    let relay_forwarder_supervisor = relay_forwarder_supervisor(&args)?;
    let mut background_tasks = Vec::new();
    if otel_metrics_enabled {
        background_tasks.push(start_agent_otel_metrics_export(
            runtime.clone(),
            otel_metrics_interval.max(Duration::from_secs(1)),
        ));
    }
    if !args.disable_heartbeat && !control_plane_bases.is_empty() {
        let heartbeat_route_reporter =
            heartbeat_route_reporter(&args, runtime.state().node_id.clone());
        background_tasks.push(start_heartbeat_reporting(
            runtime.clone(),
            runtime
                .state()
                .identity_key_pair()
                .context("failed to load agent identity key for heartbeat signing")?,
            control_plane_bases.clone(),
            Duration::from_secs(args.heartbeat_interval_seconds),
            relay_capability_reporter.clone(),
            heartbeat_route_reporter,
        ));
    }
    let peer_map_task = if args.apply_peer_map {
        anyhow::ensure!(
            !control_plane_bases.is_empty(),
            "control-plane URL is required when --apply-peer-map is set"
        );
        Some(start_peer_map_sync(&args, runtime.clone(), control_plane_bases.clone()).await?)
    } else {
        None
    };
    if let Some(task) = peer_map_task {
        background_tasks.push(task);
    }
    if args.apply_docker_routes {
        background_tasks.push(start_docker_routes(&args).await?);
    }
    if args.apply_kubernetes_underlay {
        background_tasks
            .push(start_kubernetes_underlay_routes(&args, runtime.state().node_id.clone()).await?);
    }
    match args.packet_flow_detector {
        PacketFlowDetector::Disabled => {}
        PacketFlowDetector::ProcNetConntrack => {
            let limits = ProcNetConntrackReadLimits::from_args(&args)?;
            tracing::info!(
                detector = args.packet_flow_detector.as_str(),
                conntrack_path = ?args.packet_flow_conntrack_path,
                interval_seconds = args.packet_flow_poll_interval_seconds,
                dedup_ttl_seconds = args.packet_flow_dedup_ttl_seconds,
                max_bytes = limits.max_bytes,
                max_line_bytes = limits.max_line_bytes,
                max_flows = limits.max_flows,
                pin = args.packet_flow_pin,
                "starting packet-flow detector"
            );
            background_tasks.push(start_proc_net_conntrack_packet_flow_detector(
                runtime.clone(),
                conntrack_paths(args.packet_flow_conntrack_path.clone()),
                Duration::from_secs(args.packet_flow_poll_interval_seconds),
                packet_flow_dedup_ttl(args.packet_flow_dedup_ttl_seconds),
                limits,
                args.packet_flow_pin,
            ));
        }
        PacketFlowDetector::ConntrackNetlink => {
            let limits = ConntrackNetlinkReadLimits::from_args(&args)?;
            tracing::info!(
                detector = args.packet_flow_detector.as_str(),
                interval_seconds = args.packet_flow_poll_interval_seconds,
                dedup_ttl_seconds = args.packet_flow_dedup_ttl_seconds,
                max_flows = limits.max_flows,
                pin = args.packet_flow_pin,
                "starting packet-flow detector"
            );
            background_tasks.push(start_conntrack_netlink_packet_flow_detector(
                runtime.clone(),
                Duration::from_secs(args.packet_flow_poll_interval_seconds),
                packet_flow_dedup_ttl(args.packet_flow_dedup_ttl_seconds),
                limits,
                args.packet_flow_pin,
            ));
        }
        PacketFlowDetector::ConntrackNetlinkEvents => {
            let limits = ConntrackNetlinkReadLimits::from_args(&args)?;
            tracing::info!(
                detector = args.packet_flow_detector.as_str(),
                idle_poll_interval_seconds = args.packet_flow_poll_interval_seconds,
                dedup_ttl_seconds = args.packet_flow_dedup_ttl_seconds,
                max_flows = limits.max_flows,
                pin = args.packet_flow_pin,
                "starting packet-flow detector"
            );
            background_tasks.push(start_conntrack_netlink_event_packet_flow_detector(
                runtime.clone(),
                Duration::from_secs(args.packet_flow_poll_interval_seconds),
                packet_flow_dedup_ttl(args.packet_flow_dedup_ttl_seconds),
                limits,
                args.packet_flow_pin,
            ));
        }
        PacketFlowDetector::EbpfJsonl => {
            let limits = EbpfJsonlReadLimits::from_args(&args)?;
            let event_path = args
                .packet_flow_ebpf_event_path
                .clone()
                .context("--packet-flow-ebpf-event-path is required")?;
            tracing::info!(
                detector = args.packet_flow_detector.as_str(),
                event_path = %event_path.display(),
                interval_seconds = args.packet_flow_poll_interval_seconds,
                dedup_ttl_seconds = args.packet_flow_dedup_ttl_seconds,
                max_bytes = limits.max_bytes,
                max_line_bytes = limits.max_line_bytes,
                max_flows = limits.max_flows,
                pin = args.packet_flow_pin,
                "starting packet-flow detector"
            );
            background_tasks.push(start_ebpf_jsonl_packet_flow_detector(
                runtime.clone(),
                event_path,
                Duration::from_secs(args.packet_flow_poll_interval_seconds),
                packet_flow_dedup_ttl(args.packet_flow_dedup_ttl_seconds),
                limits,
                args.packet_flow_pin,
            ));
        }
        PacketFlowDetector::EbpfRingbuf => {
            let config = EbpfRingbufConfig::from_args(&args)?;
            let limits = EbpfRingbufReadLimits::from_args(&args)?;
            tracing::info!(
                detector = args.packet_flow_detector.as_str(),
                object_path = %config.object_path.display(),
                ringbuf_map = %config.ringbuf_map,
                attachments = config.attachments.len(),
                retry_interval_seconds = args.packet_flow_poll_interval_seconds,
                max_events_per_wake = limits.max_events_per_wake,
                dedup_ttl_seconds = args.packet_flow_dedup_ttl_seconds,
                pin = args.packet_flow_pin,
                "starting packet-flow detector"
            );
            background_tasks.push(start_ebpf_ringbuf_packet_flow_detector(
                runtime.clone(),
                config,
                limits,
                Duration::from_secs(args.packet_flow_poll_interval_seconds),
                packet_flow_dedup_ttl(args.packet_flow_dedup_ttl_seconds),
                args.packet_flow_pin,
            ));
        }
    }
    if !args.disable_signal_registration {
        if let Some(node) = registered_node.clone().filter(|_| !signal_bases.is_empty()) {
            background_tasks.push(start_signal_registration(
                runtime.clone(),
                node,
                signal_bases.clone(),
                Duration::from_secs(args.signal_registration_interval_seconds),
                relay_capability_reporter.clone(),
            ));
        }
    }
    if !args.disable_signal_paths && !signal_bases.is_empty() {
        let hole_puncher = UdpHolePuncher::new(args.hole_punch_bind)
            .with_attempts(args.hole_punch_attempts)
            .with_interval(Duration::from_millis(args.hole_punch_interval_millis));
        if !control_plane_bases.is_empty() {
            background_tasks.push(start_signal_path_negotiation(
                runtime.clone(),
                control_plane_bases.clone(),
                signal_bases,
                hole_puncher,
                SignalPathNegotiationOptions {
                    relay_forwarder_supervisor: relay_forwarder_supervisor.clone(),
                    relay_admission_bearer_token: args.relay_admission_bearer_token.clone(),
                    relay_session_renew_before: Duration::from_secs(
                        args.relay_session_renew_before_seconds,
                    ),
                    interval: Duration::from_secs(args.signal_path_interval_seconds),
                },
            ));
        }
    }
    tracing::info!(node_id = %runtime.state().node_id, listen = %args.listen, "agent listening");
    let result = serve_router(
        args.listen,
        agent_router(AgentHttpState::with_wireguard_key_rotation(
            runtime.clone(),
            store,
            control_plane_bases,
        )),
    )
    .await;
    for task in background_tasks {
        task.abort();
    }
    if let Some(supervisor) = relay_forwarder_supervisor {
        supervisor.shutdown_all(runtime.as_ref()).await;
    }
    if let Some(process) = userspace_wireguard_process {
        process.shutdown().await;
    }
    result
}

struct ManagedUserspaceWireGuardProcess {
    label: String,
    pid: Option<u32>,
    runtime: Arc<AgentRuntime>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl ManagedUserspaceWireGuardProcess {
    async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            if shutdown.send(()).is_err() {
                tracing::info!(
                    command = %self.label,
                    pid = ?self.pid,
                    "userspace WireGuard process monitor already stopped"
                );
            }
        }

        if let Err(error) = self.task.await {
            tracing::warn!(
                command = %self.label,
                pid = ?self.pid,
                %error,
                "userspace WireGuard process monitor task failed"
            );
            self.runtime
                .record_userspace_wireguard_process_status(
                    AgentManagedProcessState::Failed,
                    self.pid,
                    None,
                    Some(error.to_string()),
                )
                .await;
        }
    }
}

async fn start_userspace_wireguard_process(
    args: &AgentArgs,
    runtime: Arc<AgentRuntime>,
) -> anyhow::Result<Option<ManagedUserspaceWireGuardProcess>> {
    let Some(command) = userspace_wireguard_launch_command(args)? else {
        runtime
            .record_userspace_wireguard_process_status(
                AgentManagedProcessState::Disabled,
                None,
                None,
                None,
            )
            .await;
        return Ok(None);
    };
    let label = runtime_command_label(&command.program, &command.args);
    let mut child = spawn_userspace_wireguard_process(&command)
        .with_context(|| format!("failed to start userspace WireGuard process `{label}`"))?;
    let pid = child.id();
    runtime
        .record_userspace_wireguard_process_status(
            AgentManagedProcessState::Starting,
            pid,
            None,
            None,
        )
        .await;
    tracing::info!(
        command = %label,
        pid = ?pid,
        interface = %args.wireguard_interface,
        "started userspace WireGuard process"
    );
    let shutdown_timeout = Duration::from_secs(args.userspace_wireguard_shutdown_timeout_seconds);
    if let Err(error) = wait_for_userspace_wireguard_ready(args, &mut child, &label).await {
        let message = error.to_string();
        let status =
            cleanup_unready_userspace_wireguard_process(child, label.clone(), shutdown_timeout)
                .await;
        runtime
            .record_userspace_wireguard_process_status(
                AgentManagedProcessState::Failed,
                pid,
                status.map(|status| status.to_string()),
                Some(message),
            )
            .await;
        return Err(error);
    }
    runtime
        .record_userspace_wireguard_process_status(AgentManagedProcessState::Ready, pid, None, None)
        .await;
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(monitor_userspace_wireguard_process(
        child,
        label.clone(),
        pid,
        runtime.clone(),
        shutdown_rx,
        shutdown_timeout,
    ));
    Ok(Some(ManagedUserspaceWireGuardProcess {
        label,
        pid,
        runtime,
        shutdown: Some(shutdown),
        task,
    }))
}

fn spawn_userspace_wireguard_process(
    command: &LinuxCommand,
) -> anyhow::Result<tokio::process::Child> {
    let command = resolve_userspace_wireguard_spawn_command(command)?;
    let mut child_command = tokio::process::Command::new(&command.program);
    child_command
        .args(&command.args)
        .env_clear()
        .env("PATH", SANITIZED_RUNTIME_COMMAND_PATH)
        .env("LANG", SANITIZED_RUNTIME_COMMAND_LOCALE)
        .env("LC_ALL", SANITIZED_RUNTIME_COMMAND_LOCALE)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    configure_userspace_wireguard_process_group(&mut child_command);

    let child = child_command.spawn()?;
    Ok(child)
}

fn resolve_userspace_wireguard_spawn_command(
    command: &LinuxCommand,
) -> anyhow::Result<LinuxCommand> {
    let path = Some(OsStr::new(SANITIZED_RUNTIME_COMMAND_PATH));
    let original_program = command.program.clone();
    let resolved_program = if runtime_command_program_name(&original_program) == Some("ip") {
        resolve_program_in_path("ip", path)?
    } else {
        resolve_runtime_program_ready(&original_program, path)?
    };
    let mut resolved = LinuxCommand {
        program: runtime_command_path_to_string(&resolved_program, "userspace WireGuard command")?,
        args: command.args.clone(),
    };

    if runtime_command_program_name(&original_program) == Some("ip")
        && resolved.args.len() >= 4
        && resolved.args[0] == "netns"
        && resolved.args[1] == "exec"
    {
        let inner_program = resolve_runtime_program_ready(&resolved.args[3], path)?;
        resolved.args[3] =
            runtime_command_path_to_string(&inner_program, "userspace WireGuard netns command")?;
    }

    validate_userspace_wireguard_spawn_command(&resolved)?;
    Ok(resolved)
}

fn validate_userspace_wireguard_spawn_command(command: &LinuxCommand) -> anyhow::Result<()> {
    anyhow::ensure!(
        command.args.len() <= MAX_USERSPACE_WIREGUARD_SPAWN_ARGS,
        "userspace WireGuard spawn command has too many arguments: {} > {MAX_USERSPACE_WIREGUARD_SPAWN_ARGS}",
        command.args.len()
    );
    for (index, argument) in command.args.iter().enumerate() {
        anyhow::ensure!(
            argument.len() <= MAX_USERSPACE_WIREGUARD_ARG_BYTES,
            "userspace WireGuard spawn command argument {index} exceeds {MAX_USERSPACE_WIREGUARD_ARG_BYTES} bytes"
        );
        anyhow::ensure!(
            !argument.as_bytes().contains(&0),
            "userspace WireGuard spawn command argument {index} must not contain NUL bytes"
        );
    }
    Ok(())
}

fn runtime_command_path_to_string(path: &Path, label: &str) -> anyhow::Result<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .with_context(|| format!("resolved {label} path {} is not UTF-8", path.display()))
}

fn runtime_command_program_name(program: &str) -> Option<&str> {
    if program.contains('/') {
        Path::new(program)
            .file_name()
            .and_then(|name| name.to_str())
    } else {
        Some(program)
    }
}

fn configure_userspace_wireguard_process_group(_command: &mut tokio::process::Command) {
    #[cfg(target_os = "linux")]
    {
        _command.process_group(0);
    }
}

async fn cleanup_unready_userspace_wireguard_process(
    child: tokio::process::Child,
    label: String,
    shutdown_timeout: Duration,
) -> Option<std::process::ExitStatus> {
    tracing::warn!(
        command = %label,
        "stopping userspace WireGuard process after readiness failure"
    );
    let mut child = child;
    stop_userspace_wireguard_child(&mut child, &label, shutdown_timeout).await
}

async fn monitor_userspace_wireguard_process(
    mut child: tokio::process::Child,
    label: String,
    pid: Option<u32>,
    runtime: Arc<AgentRuntime>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
    shutdown_timeout: Duration,
) {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                tracing::warn!(
                    command = %label,
                    pid = ?pid,
                    %status,
                    "userspace WireGuard process exited unexpectedly"
                );
                runtime
                    .record_userspace_wireguard_process_status(
                        AgentManagedProcessState::Exited,
                        pid,
                        Some(status.to_string()),
                        None,
                    )
                    .await;
                return;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    command = %label,
                    pid = ?pid,
                    %error,
                    "failed to inspect userspace WireGuard process"
                );
            }
        }

        tokio::select! {
            _ = &mut shutdown => {
                runtime
                    .record_userspace_wireguard_process_status(
                        AgentManagedProcessState::Stopping,
                        pid,
                        None,
                        None,
                    )
                    .await;
                let status = stop_userspace_wireguard_child(&mut child, &label, shutdown_timeout).await;
                let stopped = status.is_some();
                runtime
                    .record_userspace_wireguard_process_status(
                        if stopped {
                            AgentManagedProcessState::Stopped
                        } else {
                            AgentManagedProcessState::Failed
                        },
                        pid,
                        status.map(|status| status.to_string()),
                        if stopped {
                            None
                        } else {
                            Some("failed to stop userspace WireGuard process cleanly".to_string())
                        },
                    )
                    .await;
                return;
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

async fn stop_userspace_wireguard_child(
    child: &mut tokio::process::Child,
    label: &str,
    shutdown_timeout: Duration,
) -> Option<std::process::ExitStatus> {
    match child.try_wait() {
        Ok(Some(status)) => {
            tracing::info!(
                command = %label,
                %status,
                "userspace WireGuard process already exited"
            );
            return Some(status);
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(
                command = %label,
                %error,
                "failed to inspect userspace WireGuard process before shutdown"
            );
        }
    }

    match signal_userspace_wireguard_child_shutdown(
        child,
        UserspaceWireGuardShutdownSignal::Terminate,
    ) {
        Ok(Some(warning)) => {
            tracing::warn!(
                command = %label,
                warning = %warning,
                "fell back while signaling userspace WireGuard process shutdown"
            );
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(
                command = %label,
                %error,
                "failed to signal userspace WireGuard process shutdown"
            );
            return None;
        }
    }
    match tokio::time::timeout(shutdown_timeout, child.wait()).await {
        Ok(Ok(status)) => {
            tracing::info!(
                command = %label,
                %status,
                "userspace WireGuard process stopped"
            );
            Some(status)
        }
        Ok(Err(error)) => {
            tracing::warn!(
                command = %label,
                %error,
                "failed waiting for userspace WireGuard process shutdown"
            );
            None
        }
        Err(_) => {
            tracing::warn!(
                command = %label,
                timeout_seconds = shutdown_timeout.as_secs(),
                "timed out waiting for graceful userspace WireGuard process shutdown"
            );
            force_stop_userspace_wireguard_child(child, label, shutdown_timeout).await
        }
    }
}

async fn force_stop_userspace_wireguard_child(
    child: &mut tokio::process::Child,
    label: &str,
    shutdown_timeout: Duration,
) -> Option<std::process::ExitStatus> {
    match signal_userspace_wireguard_child_shutdown(child, UserspaceWireGuardShutdownSignal::Kill) {
        Ok(Some(warning)) => {
            tracing::warn!(
                command = %label,
                warning = %warning,
                "fell back while force-stopping userspace WireGuard process"
            );
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(
                command = %label,
                %error,
                "failed to force-stop userspace WireGuard process"
            );
            return None;
        }
    }

    match tokio::time::timeout(shutdown_timeout, child.wait()).await {
        Ok(Ok(status)) => {
            tracing::info!(
                command = %label,
                %status,
                "userspace WireGuard process force-stopped"
            );
            Some(status)
        }
        Ok(Err(error)) => {
            tracing::warn!(
                command = %label,
                %error,
                "failed waiting for force-stopped userspace WireGuard process"
            );
            None
        }
        Err(_) => {
            tracing::warn!(
                command = %label,
                timeout_seconds = shutdown_timeout.as_secs(),
                "timed out waiting for force-stopped userspace WireGuard process"
            );
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserspaceWireGuardShutdownSignal {
    Terminate,
    Kill,
}

fn signal_userspace_wireguard_child_shutdown(
    child: &mut tokio::process::Child,
    signal: UserspaceWireGuardShutdownSignal,
) -> Result<Option<String>, std::io::Error> {
    #[cfg(target_os = "linux")]
    if let Some(pid) = child.id() {
        match signal_userspace_wireguard_process_group(pid, signal) {
            Ok(()) => return Ok(None),
            Err(group_error) => {
                return match signal_userspace_wireguard_direct_child(pid, signal) {
                    Ok(()) => Ok(Some(format!(
                        "process group {pid}: {group_error}; direct child signal succeeded"
                    ))),
                    Err(child_error) => Err(std::io::Error::other(format!(
                        "process group {pid}: {group_error}; direct child: {child_error}"
                    ))),
                };
            }
        }
    }

    match signal {
        UserspaceWireGuardShutdownSignal::Terminate | UserspaceWireGuardShutdownSignal::Kill => {
            child.start_kill().map(|()| None)
        }
    }
}

#[cfg(target_os = "linux")]
fn signal_userspace_wireguard_process_group(
    pid: u32,
    signal: UserspaceWireGuardShutdownSignal,
) -> std::io::Result<()> {
    let pgid: i32 = pid
        .try_into()
        .map_err(|_| std::io::Error::other(format!("child pid {pid} exceeds pid_t range")))?;
    nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(pgid),
        userspace_wireguard_shutdown_signal(signal),
    )
    .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
}

#[cfg(target_os = "linux")]
fn signal_userspace_wireguard_direct_child(
    pid: u32,
    signal: UserspaceWireGuardShutdownSignal,
) -> std::io::Result<()> {
    let pid: i32 = pid
        .try_into()
        .map_err(|_| std::io::Error::other(format!("child pid {pid} exceeds pid_t range")))?;
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        userspace_wireguard_shutdown_signal(signal),
    )
    .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
}

#[cfg(target_os = "linux")]
fn userspace_wireguard_shutdown_signal(
    signal: UserspaceWireGuardShutdownSignal,
) -> nix::sys::signal::Signal {
    match signal {
        UserspaceWireGuardShutdownSignal::Terminate => nix::sys::signal::Signal::SIGTERM,
        UserspaceWireGuardShutdownSignal::Kill => nix::sys::signal::Signal::SIGKILL,
    }
}

async fn wait_for_userspace_wireguard_ready(
    args: &AgentArgs,
    child: &mut tokio::process::Child,
    label: &str,
) -> anyhow::Result<()> {
    let ready_command = userspace_wireguard_ready_command(args)?;
    let runner = TimedSystemCommandRunner::with_output_max_bytes(
        runtime_command_timeout(args),
        runtime_command_output_max_bytes(args),
    );
    let timeout = Duration::from_secs(args.userspace_wireguard_ready_timeout_seconds);
    let started = Instant::now();
    let mut last_ready_error: Option<String>;
    loop {
        match runner.run(ready_command.clone()).await {
            Ok(()) => {
                tracing::info!(
                    command = %label,
                    interface = %args.wireguard_interface,
                    "userspace WireGuard interface is ready"
                );
                return Ok(());
            }
            Err(error) => {
                last_ready_error = Some(error.to_string());
            }
        }
        if let Some(status) = child
            .try_wait()
            .context("failed to inspect userspace WireGuard process readiness")?
        {
            let readiness_context =
                userspace_wireguard_readiness_context(last_ready_error.as_deref());
            anyhow::bail!(
                "userspace WireGuard process `{label}` exited before interface {} became ready: {status}{readiness_context}",
                args.wireguard_interface,
            );
        }
        if started.elapsed() >= timeout {
            let readiness_context =
                userspace_wireguard_readiness_context(last_ready_error.as_deref());
            anyhow::bail!(
                "userspace WireGuard process `{label}` did not expose interface {} within {} seconds{readiness_context}",
                args.wireguard_interface,
                args.userspace_wireguard_ready_timeout_seconds
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn userspace_wireguard_readiness_context(last_ready_error: Option<&str>) -> String {
    last_ready_error
        .filter(|error| !error.is_empty())
        .map(|error| format!("; last readiness check failed: {error}"))
        .unwrap_or_default()
}

fn userspace_wireguard_launch_command(args: &AgentArgs) -> anyhow::Result<Option<LinuxCommand>> {
    let Some(program) = args.userspace_wireguard_command.as_deref() else {
        return Ok(None);
    };
    let command_args = if args.userspace_wireguard_args.is_empty() {
        vec![args.wireguard_interface.clone()]
    } else {
        args.userspace_wireguard_args.clone()
    };
    let command = LinuxCommand::new(program, command_args);
    Ok(Some(userspace_wireguard_namespaced_command(args, command)?))
}

fn userspace_wireguard_ready_command(args: &AgentArgs) -> anyhow::Result<LinuxCommand> {
    userspace_wireguard_namespaced_command(
        args,
        LinuxCommand::new("wg", ["show", args.wireguard_interface.as_str()]),
    )
}

fn userspace_wireguard_namespaced_command(
    args: &AgentArgs,
    command: LinuxCommand,
) -> anyhow::Result<LinuxCommand> {
    if let Some(namespace) = args.linux_netns.as_deref() {
        Ok(command.in_namespace(&LinuxNetworkNamespace::from_name(namespace)?))
    } else {
        Ok(command)
    }
}

fn runtime_command_label(program: &str, args: &[String]) -> String {
    let program = runtime_command_diagnostic_component(program);
    if args.is_empty() {
        program
    } else {
        let args = args
            .iter()
            .map(|arg| runtime_command_diagnostic_component(arg))
            .collect::<Vec<_>>()
            .join(" ");
        format!("{program} {args}")
    }
}

fn runtime_command_diagnostic_component(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

async fn start_peer_map_sync(
    args: &AgentArgs,
    runtime: Arc<AgentRuntime>,
    control_plane_urls: Vec<String>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let command_timeout = runtime_command_timeout(args);
    let command_output_max_bytes = runtime_command_output_max_bytes(args);
    match args.runtime_backend {
        AgentRuntimeBackend::LinuxCommand => {
            let namespace = args
                .linux_netns
                .as_deref()
                .map(LinuxNetworkNamespace::from_name)
                .transpose()?;
            match (args.wireguard_backend, args.route_backend, namespace) {
                (WireGuardApplyBackend::Command, RouteApplyBackend::Command, Some(namespace)) => {
                    start_peer_map_sync_with_runners(
                        args,
                        runtime,
                        control_plane_urls,
                        NamespacedLinuxCommandRunner::new(
                            namespace.clone(),
                            TimedSystemCommandRunner::with_output_max_bytes(
                                command_timeout,
                                command_output_max_bytes,
                            ),
                        ),
                        NamespacedLinuxRouteCommandRunner::new(
                            namespace,
                            TimedSystemRouteCommandRunner::with_output_max_bytes(
                                command_timeout,
                                command_output_max_bytes,
                            ),
                        ),
                    )
                    .await
                }
                (WireGuardApplyBackend::Command, RouteApplyBackend::Command, None) => {
                    start_peer_map_sync_with_runners(
                        args,
                        runtime,
                        control_plane_urls,
                        TimedSystemCommandRunner::with_output_max_bytes(
                            command_timeout,
                            command_output_max_bytes,
                        ),
                        TimedSystemRouteCommandRunner::with_output_max_bytes(
                            command_timeout,
                            command_output_max_bytes,
                        ),
                    )
                    .await
                }
                (
                    WireGuardApplyBackend::Command,
                    RouteApplyBackend::KernelNetlink,
                    Some(namespace),
                ) => {
                    start_peer_map_sync_with_command_wireguard_netlink_routes(
                        args,
                        runtime,
                        control_plane_urls,
                        NamespacedLinuxCommandRunner::new(
                            namespace.clone(),
                            TimedSystemCommandRunner::with_output_max_bytes(
                                command_timeout,
                                command_output_max_bytes,
                            ),
                        ),
                        Some(namespace),
                    )
                    .await
                }
                (WireGuardApplyBackend::Command, RouteApplyBackend::KernelNetlink, None) => {
                    start_peer_map_sync_with_command_wireguard_netlink_routes(
                        args,
                        runtime,
                        control_plane_urls,
                        TimedSystemCommandRunner::with_output_max_bytes(
                            command_timeout,
                            command_output_max_bytes,
                        ),
                        None,
                    )
                    .await
                }
                (
                    WireGuardApplyBackend::UserspaceCommand,
                    RouteApplyBackend::Command,
                    Some(namespace),
                ) => {
                    start_peer_map_sync_with_userspace_wireguard(
                        args,
                        runtime,
                        control_plane_urls,
                        NamespacedLinuxCommandRunner::new(
                            namespace.clone(),
                            TimedSystemCommandRunner::with_output_max_bytes(
                                command_timeout,
                                command_output_max_bytes,
                            ),
                        ),
                        LinuxRouteManager::new(NamespacedLinuxRouteCommandRunner::new(
                            namespace,
                            TimedSystemRouteCommandRunner::with_output_max_bytes(
                                command_timeout,
                                command_output_max_bytes,
                            ),
                        )),
                    )
                    .await
                }
                (WireGuardApplyBackend::UserspaceCommand, RouteApplyBackend::Command, None) => {
                    start_peer_map_sync_with_userspace_wireguard(
                        args,
                        runtime,
                        control_plane_urls,
                        TimedSystemCommandRunner::with_output_max_bytes(
                            command_timeout,
                            command_output_max_bytes,
                        ),
                        LinuxRouteManager::new(
                            TimedSystemRouteCommandRunner::with_output_max_bytes(
                                command_timeout,
                                command_output_max_bytes,
                            ),
                        ),
                    )
                    .await
                }
                (
                    WireGuardApplyBackend::UserspaceCommand,
                    RouteApplyBackend::KernelNetlink,
                    Some(namespace),
                ) => {
                    start_peer_map_sync_with_userspace_wireguard(
                        args,
                        runtime,
                        control_plane_urls,
                        NamespacedLinuxCommandRunner::new(
                            namespace.clone(),
                            TimedSystemCommandRunner::with_output_max_bytes(
                                command_timeout,
                                command_output_max_bytes,
                            ),
                        ),
                        LinuxNetlinkRouteManager::new_in_namespace(namespace),
                    )
                    .await
                }
                (
                    WireGuardApplyBackend::UserspaceCommand,
                    RouteApplyBackend::KernelNetlink,
                    None,
                ) => {
                    start_peer_map_sync_with_userspace_wireguard(
                        args,
                        runtime,
                        control_plane_urls,
                        TimedSystemCommandRunner::with_output_max_bytes(
                            command_timeout,
                            command_output_max_bytes,
                        ),
                        LinuxNetlinkRouteManager::new(),
                    )
                    .await
                }
                (
                    WireGuardApplyBackend::KernelNetlink,
                    RouteApplyBackend::Command,
                    Some(namespace),
                ) => {
                    start_peer_map_sync_with_kernel_wireguard(
                        args,
                        runtime,
                        control_plane_urls,
                        NamespacedLinuxRouteCommandRunner::new(
                            namespace.clone(),
                            TimedSystemRouteCommandRunner::with_output_max_bytes(
                                command_timeout,
                                command_output_max_bytes,
                            ),
                        ),
                        Some(namespace),
                    )
                    .await
                }
                (WireGuardApplyBackend::KernelNetlink, RouteApplyBackend::Command, None) => {
                    start_peer_map_sync_with_kernel_wireguard(
                        args,
                        runtime,
                        control_plane_urls,
                        TimedSystemRouteCommandRunner::with_output_max_bytes(
                            command_timeout,
                            command_output_max_bytes,
                        ),
                        None,
                    )
                    .await
                }
                (
                    WireGuardApplyBackend::KernelNetlink,
                    RouteApplyBackend::KernelNetlink,
                    namespace,
                ) => {
                    start_peer_map_sync_with_kernel_backends(
                        args,
                        runtime,
                        control_plane_urls,
                        namespace,
                    )
                    .await
                }
            }
        }
        AgentRuntimeBackend::DryRun => {
            if let Some(namespace) = args.linux_netns.as_deref() {
                LinuxNetworkNamespace::from_name(namespace)?;
            }
            tracing::info!(
                backend = args.runtime_backend.as_str(),
                wireguard_backend = args.wireguard_backend.as_str(),
                route_backend = args.route_backend.as_str(),
                linux_netns = ?args.linux_netns,
                "starting peer-map sync with dry-run runtime backend"
            );
            let applier = PeerMapApplier::new(
                args.wireguard_interface.clone(),
                MemoryWireGuardBackend::default(),
                DryRunLinuxRouteManager,
            );
            let applier = configure_peer_map_endpoint_resolver(args, runtime.clone(), applier);
            Ok(start_peer_map_sync_with_sink(
                args,
                runtime,
                control_plane_urls,
                applier,
            ))
        }
    }
}

fn runtime_command_timeout(args: &AgentArgs) -> Duration {
    Duration::from_secs(args.runtime_command_timeout_seconds)
}

fn runtime_command_output_max_bytes(args: &AgentArgs) -> usize {
    args.runtime_command_output_max_bytes
}

#[derive(Debug, Clone)]
enum DockerRouteSource {
    Explicit(DockerNetworkIntent),
    Api(DockerApiNetworkDiscovery),
}

impl DockerRouteSource {
    async fn resolve_intent(&self) -> anyhow::Result<DockerNetworkIntent> {
        match self {
            Self::Explicit(intent) => Ok(intent.clone()),
            Self::Api(discovery) => discovery.discover_intent().await,
        }
    }

    fn source_label(&self) -> &'static str {
        match self {
            Self::Explicit(_) => "explicit",
            Self::Api(_) => "docker-api",
        }
    }
}

#[derive(Debug, Clone)]
struct DockerApiNetworkDiscovery {
    client: reqwest::Client,
    api_version: String,
    network_filters: Vec<String>,
    container_namespace: Option<String>,
    host_interface: String,
    overlay_interface: String,
    expose_host_routes: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct DockerApiNetwork {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Driver", default)]
    driver: String,
    #[serde(rename = "IPAM", default)]
    ipam: DockerApiIpam,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DockerApiIpam {
    #[serde(rename = "Config", default)]
    config: Vec<DockerApiIpamConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct DockerApiIpamConfig {
    #[serde(rename = "Subnet", default)]
    subnet: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerDiscoveredRoutes {
    network_names: Vec<String>,
    cidrs: Vec<ipnet::IpNet>,
}

impl DockerApiNetworkDiscovery {
    fn new(args: &AgentArgs) -> anyhow::Result<Self> {
        let socket = docker_api_socket_path(args)?;
        let client = reqwest::Client::builder()
            .unix_socket(socket)
            .build()
            .context("failed to build Docker API client")?;
        Ok(Self {
            client,
            api_version: args.docker_api_version.clone(),
            network_filters: args.docker_networks.clone(),
            container_namespace: args.docker_container_namespace.clone(),
            host_interface: args.docker_host_interface.clone(),
            overlay_interface: args.wireguard_interface.clone(),
            expose_host_routes: args.docker_expose_host_routes,
        })
    }

    async fn discover_intent(&self) -> anyhow::Result<DockerNetworkIntent> {
        let response = self
            .client
            .get(docker_api_networks_url(&self.api_version))
            .send()
            .await
            .context("failed to query Docker networks")?
            .error_for_status()
            .context("Docker networks API returned an error")?;
        let networks = read_docker_api_networks_response(response).await?;
        let discovered = docker_discovered_routes(&networks, &self.network_filters)?;
        let container_namespace = self
            .container_namespace
            .clone()
            .unwrap_or_else(|| docker_namespace_from_networks(&discovered.network_names));
        Ok(DockerNetworkIntent {
            container_namespace,
            host_interface: self.host_interface.clone(),
            overlay_interface: self.overlay_interface.clone(),
            container_cidrs: discovered.cidrs,
            expose_host_routes: self.expose_host_routes,
        })
    }
}

async fn read_docker_api_networks_response(
    mut response: reqwest::Response,
) -> anyhow::Result<Vec<DockerApiNetwork>> {
    if let Some(length) = response.content_length() {
        ensure_docker_api_networks_response_size(length)?;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read Docker networks response")?
    {
        let next_len = body.len() as u64 + chunk.len() as u64;
        ensure_docker_api_networks_response_size(next_len)?;
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).context("failed to decode Docker networks response")
}

fn ensure_docker_api_networks_response_size(size: u64) -> anyhow::Result<()> {
    if size > MAX_DOCKER_API_NETWORKS_RESPONSE_BYTES {
        anyhow::bail!(
            "Docker networks API response exceeds maximum size of {} bytes",
            MAX_DOCKER_API_NETWORKS_RESPONSE_BYTES
        );
    }
    Ok(())
}

fn docker_route_source(args: &AgentArgs) -> anyhow::Result<DockerRouteSource> {
    if args.docker_discover_networks {
        Ok(DockerRouteSource::Api(DockerApiNetworkDiscovery::new(
            args,
        )?))
    } else {
        Ok(DockerRouteSource::Explicit(docker_network_intent(args)?))
    }
}

async fn agent_requested_routes(args: &AgentArgs, node_id: NodeId) -> anyhow::Result<Vec<Route>> {
    let expose_docker_routes = args.apply_docker_routes && args.docker_expose_host_routes;
    if !expose_docker_routes && !args.apply_kubernetes_underlay {
        return Ok(Vec::new());
    }
    validate_agent_runtime_config(args)?;
    let mut routes = Vec::new();
    if expose_docker_routes {
        let intent = docker_route_source(args)?.resolve_intent().await?;
        routes.extend(docker_advertised_routes(&node_id, intent.container_cidrs));
    }
    if args.apply_kubernetes_underlay {
        let intent = kubernetes_route_source(args, node_id.clone())?
            .resolve_intent()
            .await?;
        routes.extend(kubernetes_route_plan(intent).routes);
    }
    Ok(routes)
}

fn docker_advertised_routes(node_id: &NodeId, cidrs: Vec<ipnet::IpNet>) -> Vec<Route> {
    let mut cidrs = cidrs;
    cidrs.sort();
    cidrs
        .into_iter()
        .map(|cidr| Route {
            id: docker_route_id(&cidr),
            cidr,
            advertised_by: node_id.clone(),
            via: Some(node_id.clone()),
            metric: 100,
            tags: Default::default(),
        })
        .collect()
}

fn docker_route_id(cidr: &ipnet::IpNet) -> String {
    match cidr {
        ipnet::IpNet::V4(network) => {
            let octets = network.network().octets();
            format!(
                "docker-v4-{}-{}-{}-{}-{}",
                octets[0],
                octets[1],
                octets[2],
                octets[3],
                network.prefix_len()
            )
        }
        ipnet::IpNet::V6(network) => {
            let segments = network.network().segments();
            format!(
                "docker-v6-{:x}-{:x}-{:x}-{:x}-{:x}-{:x}-{:x}-{:x}-{}",
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
                network.prefix_len()
            )
        }
    }
}

#[derive(Debug, Clone)]
struct HeartbeatRouteReporter {
    args: AgentArgs,
    node_id: NodeId,
}

fn heartbeat_route_reporter(args: &AgentArgs, node_id: NodeId) -> Option<HeartbeatRouteReporter> {
    let reports_routes = (args.apply_docker_routes && args.docker_expose_host_routes)
        || args.apply_kubernetes_underlay;
    reports_routes.then(|| HeartbeatRouteReporter {
        args: args.clone(),
        node_id,
    })
}

async fn heartbeat_routes(reporter: Option<&HeartbeatRouteReporter>) -> Option<Vec<Route>> {
    let reporter = reporter?;
    match agent_requested_routes(&reporter.args, reporter.node_id.clone()).await {
        Ok(routes) => Some(routes),
        Err(error) => {
            tracing::warn!(
                %error,
                "failed to refresh advertised routes for heartbeat; preserving control-plane route state"
            );
            None
        }
    }
}

fn docker_api_networks_url(api_version: &str) -> String {
    let version = api_version.trim_matches('/');
    if version.is_empty() {
        "http://docker/networks".to_string()
    } else {
        format!("http://docker/{version}/networks")
    }
}

fn docker_api_socket_path(args: &AgentArgs) -> anyhow::Result<PathBuf> {
    resolve_docker_api_socket(
        args.docker_api_socket.as_deref(),
        std::env::var_os("DOCKER_HOST").as_deref(),
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        |path| path.exists(),
    )
}

fn resolve_docker_api_socket(
    configured: Option<&Path>,
    docker_host: Option<&OsStr>,
    xdg_runtime_dir: Option<&OsStr>,
    exists: impl Fn(&Path) -> bool,
) -> anyhow::Result<PathBuf> {
    if let Some(configured) = configured {
        validate_docker_api_socket_path(configured, "--docker-api-socket")?;
        return Ok(configured.to_path_buf());
    }
    if let Some(path) = docker_host
        .map(docker_host_unix_socket_path)
        .transpose()?
        .flatten()
    {
        return Ok(path);
    }

    let rootful = PathBuf::from("/var/run/docker.sock");
    if exists(&rootful) {
        return Ok(rootful);
    }

    if let Some(runtime_dir) = xdg_runtime_dir {
        let rootless = PathBuf::from(runtime_dir).join("docker.sock");
        if exists(&rootless) {
            validate_docker_api_socket_path(&rootless, "XDG_RUNTIME_DIR/docker.sock")?;
            return Ok(rootless);
        }
    }

    Ok(rootful)
}

fn docker_host_unix_socket_path(docker_host: &OsStr) -> anyhow::Result<Option<PathBuf>> {
    let docker_host = docker_host
        .to_str()
        .context("DOCKER_HOST must be valid UTF-8 for Docker API discovery")?;
    if docker_host.trim().is_empty() {
        return Ok(None);
    }
    if let Some(path) = docker_host.strip_prefix("unix://") {
        if path.is_empty() {
            anyhow::bail!("DOCKER_HOST unix:// value must include a socket path");
        }
        let path = PathBuf::from(path);
        validate_docker_api_socket_path(&path, "DOCKER_HOST unix:// socket path")?;
        return Ok(Some(path));
    }
    anyhow::bail!(
        "Docker API discovery only supports unix:// DOCKER_HOST values; set --docker-api-socket for a local Unix socket"
    )
}

fn validate_docker_api_socket_path(path: &Path, label: &str) -> anyhow::Result<()> {
    if !path.is_absolute() {
        anyhow::bail!("{label} must be an absolute Unix socket path");
    }
    let value = path
        .as_os_str()
        .to_str()
        .with_context(|| format!("{label} must be valid UTF-8"))?;
    if value.chars().any(char::is_control) {
        anyhow::bail!("{label} must not contain control characters");
    }
    validate_docker_api_socket_path_components(value, label)?;
    Ok(())
}

fn validate_docker_api_socket_path_components(value: &str, label: &str) -> anyhow::Result<()> {
    if value
        .split('/')
        .any(|component| component == "." || component == "..")
    {
        anyhow::bail!("{label} must not contain '.' or '..' path components");
    }
    Ok(())
}

fn docker_discovered_routes(
    networks: &[DockerApiNetwork],
    filters: &[String],
) -> anyhow::Result<DockerDiscoveredRoutes> {
    let mut network_names = BTreeSet::new();
    let mut network_ids = BTreeSet::new();
    let mut cidrs = Vec::<ipnet::IpNet>::new();
    let requested_filters = filters.iter().cloned().collect::<BTreeSet<_>>();
    let mut matched_filters = BTreeSet::new();
    let mut bridge_matched_filters = BTreeSet::new();
    let mut subnet_matched_filters = BTreeSet::new();
    let mut filter_matches = BTreeMap::<String, BTreeSet<String>>::new();
    for network in networks {
        let matching_filters = docker_network_matching_filters(network, filters);
        if !matching_filters.is_empty() {
            let identity = docker_network_identity(network);
            for filter in &matching_filters {
                filter_matches
                    .entry((*filter).clone())
                    .or_default()
                    .insert(identity.clone());
            }
        }
        if filters.is_empty() {
            if network.driver != "bridge" {
                continue;
            }
        } else {
            if matching_filters.is_empty() {
                continue;
            }
            matched_filters.extend(matching_filters.iter().map(|filter| (*filter).clone()));
            if network.driver != "bridge" {
                continue;
            }
            bridge_matched_filters.extend(matching_filters.iter().map(|filter| (*filter).clone()));
        }
        if !docker_network_matches(network, filters) {
            continue;
        }
        validate_docker_network_id(&network.id)?;
        validate_docker_network_name(&network.name)?;
        if !network_ids.insert(network.id.as_str()) {
            anyhow::bail!(
                "Docker network discovery returned duplicate network ID `{}`",
                network.id
            );
        }
        if network_names.contains(&network.name) {
            anyhow::bail!(
                "Docker network discovery returned duplicate network name `{}`",
                network.name
            );
        }
        let mut found_subnet = false;
        for config in &network.ipam.config {
            let Some(subnet) = config.subnet.as_deref() else {
                continue;
            };
            let cidr = subnet.parse::<ipnet::IpNet>().with_context(|| {
                format!(
                    "Docker network `{}` has invalid subnet `{subnet}`",
                    network.name
                )
            })?;
            cidrs.push(cidr);
            found_subnet = true;
        }
        if found_subnet {
            subnet_matched_filters.extend(matching_filters.iter().map(|filter| (*filter).clone()));
            network_names.insert(network.name.clone());
        }
    }
    if !requested_filters.is_empty() {
        if let Some((filter, matches)) =
            filter_matches.iter().find(|(_, matches)| matches.len() > 1)
        {
            anyhow::bail!(
                "Docker network discovery filter `{filter}` matched multiple Docker networks: {}",
                matches.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        }

        let missing_filters = requested_filters
            .difference(&matched_filters)
            .cloned()
            .collect::<Vec<_>>();
        if !missing_filters.is_empty() {
            anyhow::bail!(
                "Docker network discovery did not find requested network filters: {}",
                missing_filters.join(",")
            );
        }

        let non_bridge_filters = requested_filters
            .difference(&bridge_matched_filters)
            .cloned()
            .collect::<Vec<_>>();
        if !non_bridge_filters.is_empty() {
            anyhow::bail!(
                "Docker network discovery requested non-bridge networks: {}",
                non_bridge_filters.join(",")
            );
        }

        let subnetless_filters = requested_filters
            .difference(&subnet_matched_filters)
            .cloned()
            .collect::<Vec<_>>();
        if !subnetless_filters.is_empty() {
            anyhow::bail!(
                "Docker network discovery requested networks without IPAM subnets: {}",
                subnetless_filters.join(",")
            );
        }
    }
    if cidrs.is_empty() {
        anyhow::bail!("Docker network discovery found no bridge networks with IPAM subnets");
    }
    validate_docker_container_cidrs("Docker network discovery", &cidrs)?;
    cidrs.sort();
    Ok(DockerDiscoveredRoutes {
        network_names: network_names.into_iter().collect(),
        cidrs,
    })
}

fn docker_network_identity(network: &DockerApiNetwork) -> String {
    if network.id.is_empty() {
        network.name.clone()
    } else {
        format!("{} ({})", network.name, network.id)
    }
}

fn docker_network_matches(network: &DockerApiNetwork, filters: &[String]) -> bool {
    if network.driver != "bridge" {
        return false;
    }
    filters.is_empty()
        || filters
            .iter()
            .any(|filter| filter == &network.name || filter == &network.id)
}

fn docker_network_matching_filters<'a>(
    network: &DockerApiNetwork,
    filters: &'a [String],
) -> Vec<&'a String> {
    filters
        .iter()
        .filter(|filter| *filter == &network.name || *filter == &network.id)
        .collect()
}

fn docker_namespace_from_networks(network_names: &[String]) -> String {
    if network_names.is_empty() {
        return "docker-api".to_string();
    }
    let joined = network_names.join("+");
    format!("docker:{joined}")
}

async fn start_docker_routes(args: &AgentArgs) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let source = docker_route_source(args)?;
    let interval = Duration::from_secs(args.docker_route_interval_seconds);
    let command_timeout = runtime_command_timeout(args);
    let command_output_max_bytes = runtime_command_output_max_bytes(args);
    match args.runtime_backend {
        AgentRuntimeBackend::LinuxCommand => {
            let namespace = args
                .linux_netns
                .as_deref()
                .map(LinuxNetworkNamespace::from_name)
                .transpose()?;
            if let Some(namespace) = namespace {
                match args.route_backend {
                    RouteApplyBackend::Command => {
                        let manager =
                            LinuxRouteManager::new(NamespacedLinuxRouteCommandRunner::new(
                                namespace,
                                TimedSystemRouteCommandRunner::with_output_max_bytes(
                                    command_timeout,
                                    command_output_max_bytes,
                                ),
                            ));
                        Ok(tokio::spawn(async move {
                            run_docker_route_loop(manager, source, interval).await;
                        }))
                    }
                    RouteApplyBackend::KernelNetlink => {
                        let manager = LinuxNetlinkRouteManager::new_in_namespace(namespace);
                        Ok(tokio::spawn(async move {
                            run_docker_route_loop(manager, source, interval).await;
                        }))
                    }
                }
            } else {
                match args.route_backend {
                    RouteApplyBackend::Command => {
                        let manager = LinuxRouteManager::new(
                            TimedSystemRouteCommandRunner::with_output_max_bytes(
                                command_timeout,
                                command_output_max_bytes,
                            ),
                        );
                        Ok(tokio::spawn(async move {
                            run_docker_route_loop(manager, source, interval).await;
                        }))
                    }
                    RouteApplyBackend::KernelNetlink => {
                        let manager = LinuxNetlinkRouteManager::new();
                        Ok(tokio::spawn(async move {
                            run_docker_route_loop(manager, source, interval).await;
                        }))
                    }
                }
            }
        }
        AgentRuntimeBackend::DryRun => {
            if let Some(namespace) = args.linux_netns.as_deref() {
                LinuxNetworkNamespace::from_name(namespace)?;
            }
            tracing::info!(
                backend = args.runtime_backend.as_str(),
                route_backend = args.route_backend.as_str(),
                route_source = source.source_label(),
                "starting Docker route loop with dry-run runtime backend"
            );
            Ok(tokio::spawn(async move {
                run_docker_route_loop(DryRunLinuxRouteManager, source, interval).await;
            }))
        }
    }
}

fn docker_network_intent(args: &AgentArgs) -> anyhow::Result<DockerNetworkIntent> {
    let container_namespace = args
        .docker_container_namespace
        .clone()
        .context("--apply-docker-routes requires --docker-container-namespace")?;
    if args.docker_container_cidrs.is_empty() {
        anyhow::bail!("--apply-docker-routes requires at least one --docker-container-cidr");
    }
    validate_docker_container_cidrs("--docker-container-cidr", &args.docker_container_cidrs)?;

    Ok(DockerNetworkIntent {
        container_namespace,
        host_interface: args.docker_host_interface.clone(),
        overlay_interface: args.wireguard_interface.clone(),
        container_cidrs: args.docker_container_cidrs.clone(),
        expose_host_routes: args.docker_expose_host_routes,
    })
}

async fn run_docker_route_loop<M>(manager: M, source: DockerRouteSource, interval: Duration)
where
    M: RouteManager + 'static,
{
    let mut applied_plan = None;
    loop {
        match source.resolve_intent().await {
            Ok(intent) => {
                let result = match checked_docker_route_plan(intent.clone()) {
                    Ok(plan) => apply_managed_route_plan(&manager, &mut applied_plan, plan).await,
                    Err(error) => Err(error),
                };
                match result {
                    Ok(summary) => tracing::info!(
                        route_source = source.source_label(),
                        container_namespace = %intent.container_namespace,
                        host_interface = %intent.host_interface,
                        routes = summary.plan.routes.len(),
                        policy_rules = summary.plan.policy_rules.len(),
                        routes_removed = summary.routes_removed,
                        policy_rules_removed = summary.policy_rules_removed,
                        "applied Docker overlay routes"
                    ),
                    Err(error) => tracing::warn!(
                        %error,
                        route_source = source.source_label(),
                        container_namespace = %intent.container_namespace,
                        "failed to apply Docker overlay routes; will retry"
                    ),
                }
            }
            Err(error) => tracing::warn!(
                %error,
                route_source = source.source_label(),
                "failed to resolve Docker overlay routes; will retry"
            ),
        }
        tokio::time::sleep(interval).await;
    }
}

async fn apply_managed_route_plan<M>(
    manager: &M,
    applied_plan: &mut Option<RoutePlan>,
    plan: RoutePlan,
) -> Result<ManagedRouteApplySummary, RouteManagerError>
where
    M: RouteManager + ?Sized,
{
    let mut routes_removed = 0;
    let mut policy_rules_removed = 0;
    if let Some(previous) = applied_plan.as_ref().cloned() {
        let stale = stale_managed_route_plan(&previous, &plan);
        if !stale.routes.is_empty() || !stale.policy_rules.is_empty() {
            routes_removed = stale.routes.len();
            policy_rules_removed = stale.policy_rules.len();
            manager.remove_routes(stale).await?;
            *applied_plan = Some(retained_managed_route_plan(&previous, &plan));
        }
    }
    manager.apply_routes(plan.clone()).await?;
    *applied_plan = Some(plan.clone());
    Ok(ManagedRouteApplySummary {
        plan,
        routes_removed,
        policy_rules_removed,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedRouteApplySummary {
    plan: RoutePlan,
    routes_removed: usize,
    policy_rules_removed: usize,
}

fn stale_managed_route_plan(previous: &RoutePlan, current: &RoutePlan) -> RoutePlan {
    if previous.interface != current.interface {
        return previous.clone();
    }
    RoutePlan {
        interface: previous.interface.clone(),
        routes: previous
            .routes
            .iter()
            .filter(|route| {
                !current
                    .routes
                    .iter()
                    .any(|current| current.cidr == route.cidr)
            })
            .cloned()
            .collect(),
        policy_rules: previous
            .policy_rules
            .iter()
            .filter(|rule| !current.policy_rules.contains(rule))
            .cloned()
            .collect(),
    }
}

fn retained_managed_route_plan(previous: &RoutePlan, current: &RoutePlan) -> RoutePlan {
    if previous.interface != current.interface {
        return RoutePlan {
            interface: current.interface.clone(),
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
    }
    RoutePlan {
        interface: previous.interface.clone(),
        routes: previous
            .routes
            .iter()
            .filter(|route| {
                current
                    .routes
                    .iter()
                    .any(|current| current.cidr == route.cidr)
            })
            .cloned()
            .collect(),
        policy_rules: previous
            .policy_rules
            .iter()
            .filter(|rule| current.policy_rules.contains(rule))
            .cloned()
            .collect(),
    }
}

async fn start_kubernetes_underlay_routes(
    args: &AgentArgs,
    local_node_id: NodeId,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let source = kubernetes_route_source(args, local_node_id)?;
    let interval = Duration::from_secs(args.kubernetes_route_interval_seconds);
    let command_timeout = runtime_command_timeout(args);
    let command_output_max_bytes = runtime_command_output_max_bytes(args);
    match args.runtime_backend {
        AgentRuntimeBackend::LinuxCommand => {
            let namespace = args
                .linux_netns
                .as_deref()
                .map(LinuxNetworkNamespace::from_name)
                .transpose()?;
            if let Some(namespace) = namespace {
                match args.route_backend {
                    RouteApplyBackend::Command => {
                        let manager =
                            LinuxRouteManager::new(NamespacedLinuxRouteCommandRunner::new(
                                namespace,
                                TimedSystemRouteCommandRunner::with_output_max_bytes(
                                    command_timeout,
                                    command_output_max_bytes,
                                ),
                            ));
                        Ok(tokio::spawn(async move {
                            run_kubernetes_underlay_route_loop(manager, source, interval).await;
                        }))
                    }
                    RouteApplyBackend::KernelNetlink => {
                        let manager = LinuxNetlinkRouteManager::new_in_namespace(namespace);
                        Ok(tokio::spawn(async move {
                            run_kubernetes_underlay_route_loop(manager, source, interval).await;
                        }))
                    }
                }
            } else {
                match args.route_backend {
                    RouteApplyBackend::Command => {
                        let manager = LinuxRouteManager::new(
                            TimedSystemRouteCommandRunner::with_output_max_bytes(
                                command_timeout,
                                command_output_max_bytes,
                            ),
                        );
                        Ok(tokio::spawn(async move {
                            run_kubernetes_underlay_route_loop(manager, source, interval).await;
                        }))
                    }
                    RouteApplyBackend::KernelNetlink => {
                        let manager = LinuxNetlinkRouteManager::new();
                        Ok(tokio::spawn(async move {
                            run_kubernetes_underlay_route_loop(manager, source, interval).await;
                        }))
                    }
                }
            }
        }
        AgentRuntimeBackend::DryRun => {
            if let Some(namespace) = args.linux_netns.as_deref() {
                LinuxNetworkNamespace::from_name(namespace)?;
            }
            tracing::info!(
                backend = args.runtime_backend.as_str(),
                route_backend = args.route_backend.as_str(),
                route_source = source.source_label(),
                "starting Kubernetes underlay route loop with dry-run runtime backend"
            );
            Ok(tokio::spawn(async move {
                run_kubernetes_underlay_route_loop(DryRunLinuxRouteManager, source, interval).await;
            }))
        }
    }
}

#[derive(Debug, Clone)]
enum KubernetesRouteSource {
    Explicit(KubernetesUnderlayIntent),
    Api(KubernetesApiRouteDiscovery),
}

impl KubernetesRouteSource {
    async fn resolve_intent(&self) -> anyhow::Result<KubernetesUnderlayIntent> {
        match self {
            Self::Explicit(intent) => Ok(intent.clone()),
            Self::Api(discovery) => discovery.discover_intent().await,
        }
    }

    fn source_label(&self) -> &'static str {
        match self {
            Self::Explicit(_) => "explicit",
            Self::Api(_) => "kubernetes-api",
        }
    }
}

#[derive(Debug, Clone)]
struct KubernetesApiRouteDiscovery {
    client: reqwest::Client,
    api_url: String,
    namespaces: Vec<String>,
    service_label_selector: Option<String>,
    include_api_server: bool,
    node_name: String,
    overlay_interface: String,
    route_provider: NodeId,
    explicit_api_server_cidrs: Vec<ipnet::IpNet>,
    explicit_service_cidrs: Vec<ipnet::IpNet>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct KubernetesServiceList {
    #[serde(default)]
    items: Vec<KubernetesService>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct KubernetesService {
    #[serde(default)]
    spec: KubernetesServiceSpec,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct KubernetesServiceSpec {
    #[serde(rename = "clusterIP", default)]
    cluster_ip: Option<String>,
    #[serde(rename = "clusterIPs", default)]
    cluster_ips: Vec<String>,
}

impl KubernetesApiRouteDiscovery {
    fn new(args: &AgentArgs, local_node_id: NodeId) -> anyhow::Result<Self> {
        let api_url = kubernetes_api_base_url(
            args.kubernetes_api_url.as_deref(),
            std::env::var_os("KUBERNETES_SERVICE_HOST").as_deref(),
            std::env::var_os("KUBERNETES_SERVICE_PORT").as_deref(),
        )?;
        let token =
            read_kubernetes_service_account_token(&args.kubernetes_service_account_token_path)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))
                .context("Kubernetes service account token is not a valid HTTP header value")?,
        );
        let ca_cert_path = args
            .kubernetes_ca_cert_path
            .clone()
            .or_else(default_kubernetes_service_account_ca_cert);
        let mut client = reqwest::Client::builder().default_headers(headers);
        if let Some(ca_cert_path) = ca_cert_path.as_deref() {
            let ca = read_kubernetes_ca_certificate(ca_cert_path)?;
            client = client.add_root_certificate(
                reqwest::Certificate::from_pem(&ca)
                    .context("failed to parse Kubernetes CA certificate")?,
            );
        }
        let route_provider = args
            .kubernetes_route_provider
            .clone()
            .map(NodeId::from_string)
            .unwrap_or(local_node_id);
        Ok(Self {
            client: client
                .build()
                .context("failed to build Kubernetes API client")?,
            api_url,
            namespaces: args.kubernetes_namespaces.clone(),
            service_label_selector: args.kubernetes_service_label_selector.clone(),
            include_api_server: args.kubernetes_discover_api_server,
            node_name: args
                .kubernetes_node_name
                .clone()
                .unwrap_or_else(|| "unknown-node".to_string()),
            overlay_interface: args.wireguard_interface.clone(),
            route_provider,
            explicit_api_server_cidrs: args.kubernetes_api_server_cidrs.clone(),
            explicit_service_cidrs: args.kubernetes_service_cidrs.clone(),
        })
    }

    async fn discover_intent(&self) -> anyhow::Result<KubernetesUnderlayIntent> {
        let mut service_cidrs = self.explicit_service_cidrs.clone();
        for namespace in kubernetes_service_namespaces(&self.namespaces) {
            let services = self.fetch_services(namespace.as_deref()).await?;
            service_cidrs.extend(kubernetes_service_route_cidrs(&services)?);
        }
        service_cidrs.sort();
        service_cidrs.dedup();

        let mut api_server_cidrs = self.explicit_api_server_cidrs.clone();
        if self.include_api_server {
            if let Some(api_server_cidr) = kubernetes_api_server_env_cidr(
                std::env::var_os("KUBERNETES_SERVICE_HOST").as_deref(),
            )? {
                api_server_cidrs.push(api_server_cidr);
                api_server_cidrs.sort();
                api_server_cidrs.dedup();
            }
        }
        if api_server_cidrs.is_empty() && service_cidrs.is_empty() {
            anyhow::bail!("Kubernetes API discovery found no service or API server routes");
        }
        let mut route_cidrs = BTreeSet::new();
        validate_kubernetes_underlay_route_cidrs(
            "Kubernetes API discovery",
            "Kubernetes API server CIDR",
            &api_server_cidrs,
            &mut route_cidrs,
        )?;
        validate_kubernetes_underlay_route_cidrs(
            "Kubernetes API discovery",
            "Kubernetes Service CIDR",
            &service_cidrs,
            &mut route_cidrs,
        )?;
        Ok(KubernetesUnderlayIntent {
            node_name: self.node_name.clone(),
            overlay_interface: self.overlay_interface.clone(),
            api_server_cidrs,
            service_cidrs,
            route_provider: self.route_provider.clone(),
        })
    }

    async fn fetch_services(
        &self,
        namespace: Option<&str>,
    ) -> anyhow::Result<KubernetesServiceList> {
        let mut request = self
            .client
            .get(kubernetes_services_url(&self.api_url, namespace));
        if let Some(selector) = self.service_label_selector.as_deref() {
            request = request.query(&[("labelSelector", selector)]);
        }
        let response = request
            .send()
            .await
            .context("failed to query Kubernetes services")?
            .error_for_status()
            .context("Kubernetes services API returned an error")?;
        read_kubernetes_services_response(response).await
    }
}

async fn read_kubernetes_services_response(
    mut response: reqwest::Response,
) -> anyhow::Result<KubernetesServiceList> {
    if let Some(length) = response.content_length() {
        ensure_kubernetes_services_response_size(length)?;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read Kubernetes services response")?
    {
        let next_len = body.len() as u64 + chunk.len() as u64;
        ensure_kubernetes_services_response_size(next_len)?;
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).context("failed to decode Kubernetes services response")
}

fn ensure_kubernetes_services_response_size(size: u64) -> anyhow::Result<()> {
    if size > MAX_KUBERNETES_SERVICES_RESPONSE_BYTES {
        anyhow::bail!(
            "Kubernetes services API response exceeds maximum size of {} bytes",
            MAX_KUBERNETES_SERVICES_RESPONSE_BYTES
        );
    }
    Ok(())
}

fn kubernetes_route_source(
    args: &AgentArgs,
    local_node_id: NodeId,
) -> anyhow::Result<KubernetesRouteSource> {
    if args.kubernetes_discover_services {
        Ok(KubernetesRouteSource::Api(
            KubernetesApiRouteDiscovery::new(args, local_node_id)?,
        ))
    } else {
        Ok(KubernetesRouteSource::Explicit(kubernetes_underlay_intent(
            args,
            local_node_id,
        )?))
    }
}

fn kubernetes_service_namespaces(namespaces: &[String]) -> Vec<Option<String>> {
    if namespaces.is_empty() {
        vec![None]
    } else {
        namespaces.iter().cloned().map(Some).collect()
    }
}

fn kubernetes_services_url(api_url: &str, namespace: Option<&str>) -> String {
    let api_url = api_url.trim_end_matches('/');
    if let Some(namespace) = namespace {
        format!("{api_url}/api/v1/namespaces/{namespace}/services")
    } else {
        format!("{api_url}/api/v1/services")
    }
}

fn kubernetes_api_base_url(
    configured: Option<&str>,
    service_host: Option<&OsStr>,
    service_port: Option<&OsStr>,
) -> anyhow::Result<String> {
    if let Some(configured) = configured {
        validate_http_url(configured, "--kubernetes-api-url")?;
        return Ok(configured.trim_end_matches('/').to_string());
    }
    let Some(host) = service_host else {
        anyhow::bail!(
            "--kubernetes-discover-services requires --kubernetes-api-url or KUBERNETES_SERVICE_HOST"
        );
    };
    let host = host
        .to_str()
        .context("KUBERNETES_SERVICE_HOST must be valid UTF-8")?;
    if host.is_empty() {
        anyhow::bail!(
            "--kubernetes-discover-services requires --kubernetes-api-url or KUBERNETES_SERVICE_HOST"
        );
    }
    let port = kubernetes_service_port(service_port)?;
    let host = match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) if !host.starts_with('[') => format!("[{host}]"),
        _ => host.to_string(),
    };
    let api_url = format!("https://{host}:{port}");
    validate_http_url(&api_url, "KUBERNETES_SERVICE_HOST/KUBERNETES_SERVICE_PORT")?;
    Ok(api_url)
}

fn kubernetes_service_port(service_port: Option<&OsStr>) -> anyhow::Result<u16> {
    let Some(port) = service_port else {
        return Ok(443);
    };
    let port = port
        .to_str()
        .context("KUBERNETES_SERVICE_PORT must be valid UTF-8")?;
    if port.is_empty() {
        return Ok(443);
    }
    let port = port
        .parse::<u16>()
        .with_context(|| format!("KUBERNETES_SERVICE_PORT `{port}` must be an integer port"))?;
    if port == 0 {
        anyhow::bail!("KUBERNETES_SERVICE_PORT must be greater than zero");
    }
    Ok(port)
}

fn default_kubernetes_service_account_ca_cert() -> Option<PathBuf> {
    let path = PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt");
    path.exists().then_some(path)
}

fn read_kubernetes_ca_certificate(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path).with_context(|| {
        format!(
            "failed to open Kubernetes CA certificate from {}",
            path.display()
        )
    })?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect Kubernetes CA certificate from {}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        anyhow::bail!(
            "Kubernetes CA certificate path {} must resolve to a regular file",
            path.display()
        );
    }
    ensure_kubernetes_ca_certificate_size(metadata.len(), path)?;

    let mut ca = Vec::new();
    let mut reader = file.by_ref().take(MAX_KUBERNETES_CA_CERT_BYTES + 1);
    reader.read_to_end(&mut ca).with_context(|| {
        format!(
            "failed to read Kubernetes CA certificate from {}",
            path.display()
        )
    })?;
    ensure_kubernetes_ca_certificate_size(ca.len() as u64, path)?;
    if ca.is_empty() {
        anyhow::bail!("Kubernetes CA certificate at {} is empty", path.display());
    }
    Ok(ca)
}

fn ensure_kubernetes_ca_certificate_size(size: u64, path: &Path) -> anyhow::Result<()> {
    if size > MAX_KUBERNETES_CA_CERT_BYTES {
        anyhow::bail!(
            "Kubernetes CA certificate file {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_KUBERNETES_CA_CERT_BYTES
        );
    }
    Ok(())
}

fn read_kubernetes_service_account_token(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path).with_context(|| {
        format!(
            "failed to open Kubernetes service account token from {}",
            path.display()
        )
    })?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect Kubernetes service account token from {}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        anyhow::bail!(
            "Kubernetes service account token path {} must resolve to a regular file",
            path.display()
        );
    }
    ensure_kubernetes_service_account_token_size(metadata.len(), path)?;

    let mut token = String::new();
    let mut reader = file
        .by_ref()
        .take(MAX_KUBERNETES_SERVICE_ACCOUNT_TOKEN_BYTES + 1);
    reader.read_to_string(&mut token).with_context(|| {
        format!(
            "failed to read Kubernetes service account token from {}",
            path.display()
        )
    })?;
    ensure_kubernetes_service_account_token_size(token.len() as u64, path)?;
    let token = token.trim();
    if token.is_empty() {
        anyhow::bail!(
            "Kubernetes service account token at {} is empty",
            path.display()
        );
    }
    Ok(token.to_string())
}

fn ensure_kubernetes_service_account_token_size(size: u64, path: &Path) -> anyhow::Result<()> {
    if size > MAX_KUBERNETES_SERVICE_ACCOUNT_TOKEN_BYTES {
        anyhow::bail!(
            "Kubernetes service account token file {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_KUBERNETES_SERVICE_ACCOUNT_TOKEN_BYTES
        );
    }
    Ok(())
}

fn kubernetes_service_route_cidrs(
    services: &KubernetesServiceList,
) -> anyhow::Result<Vec<ipnet::IpNet>> {
    let mut cidrs = Vec::new();
    for service in &services.items {
        for cluster_ip in kubernetes_service_cluster_ips(service) {
            cidrs.push(ip_addr_to_host_cidr(cluster_ip)?);
        }
    }
    cidrs.sort();
    cidrs.dedup();
    Ok(cidrs)
}

fn kubernetes_service_cluster_ips(service: &KubernetesService) -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    for value in service
        .spec
        .cluster_ips
        .iter()
        .chain(service.spec.cluster_ip.iter())
    {
        if value == "None" || value.is_empty() {
            continue;
        }
        if let Ok(addr) = value.parse::<IpAddr>() {
            addresses.push(addr);
        }
    }
    addresses.sort();
    addresses.dedup();
    addresses
}

fn kubernetes_api_server_env_cidr(
    service_host: Option<&OsStr>,
) -> anyhow::Result<Option<ipnet::IpNet>> {
    let Some(host) = service_host.and_then(OsStr::to_str) else {
        return Ok(None);
    };
    if host.is_empty() {
        return Ok(None);
    }
    Ok(Some(ip_addr_to_host_cidr(
        host.parse::<IpAddr>()
            .with_context(|| format!("KUBERNETES_SERVICE_HOST `{host}` is not an IP address"))?,
    )?))
}

fn ip_addr_to_host_cidr(addr: IpAddr) -> anyhow::Result<ipnet::IpNet> {
    let prefix_len = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    ipnet::IpNet::new(addr, prefix_len).context("failed to build host route CIDR")
}

fn kubernetes_underlay_intent(
    args: &AgentArgs,
    local_node_id: NodeId,
) -> anyhow::Result<KubernetesUnderlayIntent> {
    kubernetes_underlay_intent_with_api_server_host(
        args,
        local_node_id,
        std::env::var_os("KUBERNETES_SERVICE_HOST").as_deref(),
    )
}

fn kubernetes_underlay_intent_with_api_server_host(
    args: &AgentArgs,
    local_node_id: NodeId,
    service_host: Option<&OsStr>,
) -> anyhow::Result<KubernetesUnderlayIntent> {
    let mut api_server_cidrs = args.kubernetes_api_server_cidrs.clone();
    if args.kubernetes_discover_api_server {
        if let Some(api_server_cidr) = kubernetes_api_server_env_cidr(service_host)? {
            api_server_cidrs.push(api_server_cidr);
            api_server_cidrs.sort();
            api_server_cidrs.dedup();
        }
    }

    if api_server_cidrs.is_empty() && args.kubernetes_service_cidrs.is_empty() {
        anyhow::bail!(
            "--apply-kubernetes-underlay requires at least one --kubernetes-api-server-cidr, --kubernetes-service-cidr, or KUBERNETES_SERVICE_HOST when --kubernetes-discover-api-server is enabled"
        );
    }
    let mut route_cidrs = BTreeSet::new();
    validate_kubernetes_underlay_route_cidrs(
        "--kubernetes-api-server-cidr",
        "Kubernetes API server CIDR",
        &api_server_cidrs,
        &mut route_cidrs,
    )?;
    validate_kubernetes_underlay_route_cidrs(
        "--kubernetes-service-cidr",
        "Kubernetes Service CIDR",
        &args.kubernetes_service_cidrs,
        &mut route_cidrs,
    )?;
    let route_provider = args
        .kubernetes_route_provider
        .clone()
        .map(NodeId::from_string)
        .unwrap_or(local_node_id);
    Ok(KubernetesUnderlayIntent {
        node_name: args
            .kubernetes_node_name
            .clone()
            .unwrap_or_else(|| "unknown-node".to_string()),
        overlay_interface: args.wireguard_interface.clone(),
        api_server_cidrs,
        service_cidrs: args.kubernetes_service_cidrs.clone(),
        route_provider,
    })
}

async fn run_kubernetes_underlay_route_loop<M>(
    manager: M,
    source: KubernetesRouteSource,
    interval: Duration,
) where
    M: RouteManager + 'static,
{
    let mut applied_plan = None;
    loop {
        match source.resolve_intent().await {
            Ok(intent) => {
                let result = match checked_kubernetes_route_plan(intent.clone()) {
                    Ok(plan) => apply_managed_route_plan(&manager, &mut applied_plan, plan).await,
                    Err(error) => Err(error),
                };
                match result {
                    Ok(summary) => tracing::info!(
                        route_source = source.source_label(),
                        node_name = %intent.node_name,
                        route_provider = %intent.route_provider,
                        routes = summary.plan.routes.len(),
                        policy_rules = summary.plan.policy_rules.len(),
                        routes_removed = summary.routes_removed,
                        policy_rules_removed = summary.policy_rules_removed,
                        "applied Kubernetes underlay routes"
                    ),
                    Err(error) => tracing::warn!(
                        %error,
                        route_source = source.source_label(),
                        node_name = %intent.node_name,
                        "failed to apply Kubernetes underlay routes; will retry"
                    ),
                }
            }
            Err(error) => tracing::warn!(
                %error,
                route_source = source.source_label(),
                "failed to resolve Kubernetes underlay routes; will retry"
            ),
        }
        tokio::time::sleep(interval).await;
    }
}

async fn start_peer_map_sync_with_runners<W, R>(
    args: &AgentArgs,
    runtime: Arc<AgentRuntime>,
    control_plane_urls: Vec<String>,
    wireguard_runner: W,
    route_runner: R,
) -> anyhow::Result<tokio::task::JoinHandle<()>>
where
    W: LinuxCommandRunner + 'static,
    R: LinuxRouteCommandRunner + 'static,
{
    let wireguard = LinuxWireGuardBackend::new(args.wireguard_interface.clone(), wireguard_runner);
    wireguard.ensure_interface().await?;
    let route_manager = LinuxRouteManager::new(route_runner);
    let applier = PeerMapApplier::new(args.wireguard_interface.clone(), wireguard, route_manager);
    let applier = configure_peer_map_endpoint_resolver(args, runtime.clone(), applier);
    tracing::info!(
        backend = args.runtime_backend.as_str(),
        wireguard_backend = args.wireguard_backend.as_str(),
        route_backend = args.route_backend.as_str(),
        linux_netns = ?args.linux_netns,
        "starting peer-map sync with Linux command runtime backend"
    );
    Ok(start_peer_map_sync_with_sink(
        args,
        runtime,
        control_plane_urls,
        applier,
    ))
}

async fn start_peer_map_sync_with_kernel_wireguard<R>(
    args: &AgentArgs,
    runtime: Arc<AgentRuntime>,
    control_plane_urls: Vec<String>,
    route_runner: R,
    namespace: Option<LinuxNetworkNamespace>,
) -> anyhow::Result<tokio::task::JoinHandle<()>>
where
    R: LinuxRouteCommandRunner + 'static,
{
    let wireguard = kernel_wireguard_backend(args.wireguard_interface.clone(), namespace);
    wireguard.ensure_interface().await?;
    let route_manager = LinuxRouteManager::new(route_runner);
    let applier = PeerMapApplier::new(args.wireguard_interface.clone(), wireguard, route_manager);
    let applier = configure_peer_map_endpoint_resolver(args, runtime.clone(), applier);
    tracing::info!(
        backend = args.runtime_backend.as_str(),
        wireguard_backend = args.wireguard_backend.as_str(),
        route_backend = args.route_backend.as_str(),
        linux_netns = ?args.linux_netns,
        "starting peer-map sync with kernel WireGuard netlink backend"
    );
    Ok(start_peer_map_sync_with_sink(
        args,
        runtime,
        control_plane_urls,
        applier,
    ))
}

async fn start_peer_map_sync_with_command_wireguard_netlink_routes<W>(
    args: &AgentArgs,
    runtime: Arc<AgentRuntime>,
    control_plane_urls: Vec<String>,
    wireguard_runner: W,
    namespace: Option<LinuxNetworkNamespace>,
) -> anyhow::Result<tokio::task::JoinHandle<()>>
where
    W: LinuxCommandRunner + 'static,
{
    let wireguard = LinuxWireGuardBackend::new(args.wireguard_interface.clone(), wireguard_runner);
    wireguard.ensure_interface().await?;
    let route_manager = linux_netlink_route_manager(namespace);
    let applier = PeerMapApplier::new(args.wireguard_interface.clone(), wireguard, route_manager);
    let applier = configure_peer_map_endpoint_resolver(args, runtime.clone(), applier);
    tracing::info!(
        backend = args.runtime_backend.as_str(),
        wireguard_backend = args.wireguard_backend.as_str(),
        route_backend = args.route_backend.as_str(),
        linux_netns = ?args.linux_netns,
        "starting peer-map sync with command WireGuard and kernel route netlink backends"
    );
    Ok(start_peer_map_sync_with_sink(
        args,
        runtime,
        control_plane_urls,
        applier,
    ))
}

async fn start_peer_map_sync_with_userspace_wireguard<W, R>(
    args: &AgentArgs,
    runtime: Arc<AgentRuntime>,
    control_plane_urls: Vec<String>,
    wireguard_runner: W,
    route_manager: R,
) -> anyhow::Result<tokio::task::JoinHandle<()>>
where
    W: LinuxCommandRunner + 'static,
    R: RouteManager + 'static,
{
    let wireguard =
        UserspaceWireGuardBackend::new(args.wireguard_interface.clone(), wireguard_runner);
    wireguard.ensure_interface().await?;
    let applier = PeerMapApplier::new(args.wireguard_interface.clone(), wireguard, route_manager);
    let applier = configure_peer_map_endpoint_resolver(args, runtime.clone(), applier);
    tracing::info!(
        backend = args.runtime_backend.as_str(),
        wireguard_backend = args.wireguard_backend.as_str(),
        route_backend = args.route_backend.as_str(),
        linux_netns = ?args.linux_netns,
        "starting peer-map sync with userspace WireGuard command backend"
    );
    Ok(start_peer_map_sync_with_sink(
        args,
        runtime,
        control_plane_urls,
        applier,
    ))
}

async fn start_peer_map_sync_with_kernel_backends(
    args: &AgentArgs,
    runtime: Arc<AgentRuntime>,
    control_plane_urls: Vec<String>,
    namespace: Option<LinuxNetworkNamespace>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let wireguard = kernel_wireguard_backend(args.wireguard_interface.clone(), namespace.clone());
    wireguard.ensure_interface().await?;
    let route_manager = linux_netlink_route_manager(namespace);
    let applier = PeerMapApplier::new(args.wireguard_interface.clone(), wireguard, route_manager);
    let applier = configure_peer_map_endpoint_resolver(args, runtime.clone(), applier);
    tracing::info!(
        backend = args.runtime_backend.as_str(),
        wireguard_backend = args.wireguard_backend.as_str(),
        route_backend = args.route_backend.as_str(),
        linux_netns = ?args.linux_netns,
        "starting peer-map sync with kernel WireGuard and route netlink backends"
    );
    Ok(start_peer_map_sync_with_sink(
        args,
        runtime,
        control_plane_urls,
        applier,
    ))
}

fn kernel_wireguard_backend(
    interface: String,
    namespace: Option<LinuxNetworkNamespace>,
) -> KernelWireGuardBackend {
    match namespace {
        Some(namespace) => KernelWireGuardBackend::new_in_namespace(interface, namespace),
        None => KernelWireGuardBackend::new(interface),
    }
}

fn linux_netlink_route_manager(
    namespace: Option<LinuxNetworkNamespace>,
) -> LinuxNetlinkRouteManager {
    match namespace {
        Some(namespace) => LinuxNetlinkRouteManager::new_in_namespace(namespace),
        None => LinuxNetlinkRouteManager::new(),
    }
}

fn configure_peer_map_endpoint_resolver<W, R>(
    args: &AgentArgs,
    runtime: Arc<AgentRuntime>,
    mut applier: PeerMapApplier<W, R>,
) -> PeerMapApplier<W, R>
where
    W: WireGuardBackend,
    R: RouteManager,
{
    if args.relay_forwarder_endpoint.is_some() || args.relay_forwarder_bind.is_some() {
        let mut resolver = RuntimePeerEndpointResolver::new(runtime.clone());
        if let Some(endpoint) = args.relay_forwarder_endpoint {
            resolver = resolver.with_relay_forwarder_endpoint(endpoint);
        }
        tracing::info!(
            relay_forwarder_endpoint = ?args.relay_forwarder_endpoint,
            relay_forwarder_bind = ?args.relay_forwarder_bind,
            "using relay-aware endpoint resolver for WireGuard peers"
        );
        applier = applier.with_endpoint_resolver(resolver);
    }
    applier.with_lazy_connect_runtime(runtime)
}

fn start_peer_map_sync_with_sink<A>(
    args: &AgentArgs,
    runtime: Arc<AgentRuntime>,
    control_plane_urls: Vec<String>,
    sink: A,
) -> tokio::task::JoinHandle<()>
where
    A: PeerMapSink + 'static,
{
    let sync = PeerMapSync::new(
        runtime.state().node_id.clone(),
        HttpPeerMapSource::new(control_plane_urls),
        sink,
    );
    let interval = Duration::from_secs(args.peer_map_poll_interval_seconds);
    let interface = args.wireguard_interface.clone();
    tokio::spawn(async move {
        run_peer_map_sync_loop(sync, interval, interface).await;
    })
}

fn relay_forwarder_supervisor(
    args: &AgentArgs,
) -> anyhow::Result<Option<Arc<RelayForwarderSupervisor>>> {
    let Some(bind_addr) = args.relay_forwarder_bind else {
        return Ok(None);
    };
    let wireguard_endpoint = args
        .relay_forwarder_wireguard_endpoint
        .context("--relay-forwarder-wireguard-endpoint is required with --relay-forwarder-bind")?;
    let placement = relay_forwarder_placement(args)?;
    Ok(Some(Arc::new(RelayForwarderSupervisor::new(
        RelayForwarderConfig {
            bind_addr,
            wireguard_endpoint,
            placement,
            max_sessions: args.relay_forwarder_max_sessions,
            restart_backoff: Duration::from_secs(args.relay_forwarder_restart_backoff_seconds),
            crash_policy: RelayForwarderCrashPolicy {
                window: Duration::from_secs(args.relay_forwarder_crash_window_seconds),
                max_crashes_per_window: args.relay_forwarder_max_crashes_per_window,
                cooldown: Duration::from_secs(args.relay_forwarder_crash_cooldown_seconds),
            },
        },
    ))))
}

fn relay_forwarder_placement(args: &AgentArgs) -> anyhow::Result<RelayForwarderPlacement> {
    let namespace = args
        .relay_forwarder_netns
        .as_deref()
        .or(args.linux_netns.as_deref());
    let namespace = namespace
        .map(LinuxNetworkNamespace::from_name)
        .transpose()
        .map_err(anyhow::Error::from)?;
    Ok(namespace
        .map(RelayForwarderPlacement::from)
        .unwrap_or(RelayForwarderPlacement::CurrentProcess))
}

#[derive(Debug, Clone)]
struct RelayForwarderConfig {
    bind_addr: SocketAddr,
    wireguard_endpoint: SocketAddr,
    placement: RelayForwarderPlacement,
    max_sessions: usize,
    restart_backoff: Duration,
    crash_policy: RelayForwarderCrashPolicy,
}

#[derive(Debug, Clone, Copy)]
struct RelayForwarderCrashPolicy {
    window: Duration,
    max_crashes_per_window: u32,
    cooldown: Duration,
}

impl RelayForwarderCrashPolicy {
    fn enabled(&self) -> bool {
        !self.window.is_zero() && self.max_crashes_per_window > 0 && !self.cooldown.is_zero()
    }
}

#[derive(Debug, Clone)]
struct RelayForwarderCrashState {
    window_started_at: chrono::DateTime<chrono::Utc>,
    crashes_in_window: u32,
    cooldown_until: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RelayForwarderPlacement {
    CurrentProcess,
    LinuxNetns(LinuxNetworkNamespace),
}

impl From<LinuxNetworkNamespace> for RelayForwarderPlacement {
    fn from(namespace: LinuxNetworkNamespace) -> Self {
        Self::LinuxNetns(namespace)
    }
}

impl RelayForwarderPlacement {
    fn description(&self) -> String {
        match self {
            Self::CurrentProcess => "current-process".to_string(),
            Self::LinuxNetns(namespace) => format!("netns:{}", namespace.name()),
        }
    }

    fn validate_current_process(&self) -> anyhow::Result<()> {
        match self {
            Self::CurrentProcess => Ok(()),
            Self::LinuxNetns(namespace) => ensure_process_in_netns(namespace),
        }
    }
}

#[derive(Debug)]
struct RelayForwarderSupervisor {
    config: RelayForwarderConfig,
    handles: tokio::sync::Mutex<std::collections::BTreeMap<NodeId, RelayForwarderTask>>,
    restart_backoff_until:
        tokio::sync::Mutex<std::collections::BTreeMap<NodeId, chrono::DateTime<chrono::Utc>>>,
    crash_state: tokio::sync::Mutex<std::collections::BTreeMap<NodeId, RelayForwarderCrashState>>,
}

impl RelayForwarderSupervisor {
    fn new(config: RelayForwarderConfig) -> Self {
        Self {
            config,
            handles: tokio::sync::Mutex::new(std::collections::BTreeMap::new()),
            restart_backoff_until: tokio::sync::Mutex::new(std::collections::BTreeMap::new()),
            crash_state: tokio::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    async fn upsert(
        &self,
        runtime: &AgentRuntime,
        session: RelaySessionState,
    ) -> anyhow::Result<SocketAddr> {
        self.reap_finished(runtime).await;
        let existing_endpoint = {
            let handles = self.handles.lock().await;
            handles.get(&session.peer).and_then(|handle| {
                if handle.session_id == session.session_id
                    && handle.relay_endpoint == session.relay_endpoint
                {
                    Some(handle.local_endpoint)
                } else {
                    None
                }
            })
        };
        if let Some(endpoint) = existing_endpoint {
            runtime
                .upsert_relay_forwarder_endpoint(session.peer, endpoint)
                .await;
            return Ok(endpoint);
        }

        self.ensure_capacity(&session.peer).await?;
        self.ensure_start_allowed(&session.peer).await?;
        self.remove_forwarder(runtime, &session.peer, false).await;
        let socket = match self.bind_socket().await {
            Ok(socket) => socket,
            Err(error) => {
                self.record_start_failure(&session.peer).await;
                return Err(error);
            }
        };
        let local_endpoint = socket
            .local_addr()
            .context("failed to read relay forwarder local endpoint")?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let metrics = Arc::new(RelayForwarderStats::new(
            session.peer.clone(),
            session.relay_node.clone(),
            session.relay_endpoint,
            local_endpoint,
        ));
        let forwarder =
            UdpRelayFrameForwarder::new(session.clone(), self.config.wireguard_endpoint)
                .with_metrics(metrics.clone());
        let task = tokio::spawn(forwarder.serve(socket, shutdown_rx));
        self.handles.lock().await.insert(
            session.peer.clone(),
            RelayForwarderTask {
                session_id: session.session_id.clone(),
                relay_endpoint: session.relay_endpoint,
                local_endpoint,
                shutdown_tx,
                task,
            },
        );
        runtime
            .upsert_relay_forwarder_endpoint(session.peer.clone(), local_endpoint)
            .await;
        runtime.register_relay_forwarder_metrics(metrics).await;
        tracing::info!(
            peer = %session.peer,
            relay = %session.relay_node,
            local_endpoint = %local_endpoint,
            wireguard_endpoint = %self.config.wireguard_endpoint,
            placement = %self.config.placement.description(),
            "started relay forwarder"
        );
        Ok(local_endpoint)
    }

    async fn reap_finished(&self, runtime: &AgentRuntime) -> usize {
        let finished = {
            let mut handles = self.handles.lock().await;
            let finished_peers = handles
                .iter()
                .filter_map(|(peer, handle)| handle.task.is_finished().then_some(peer.clone()))
                .collect::<Vec<_>>();
            finished_peers
                .into_iter()
                .filter_map(|peer| handles.remove(&peer).map(|handle| (peer, handle)))
                .collect::<Vec<_>>()
        };
        let finished_count = finished.len();
        for (peer, handle) in finished {
            runtime.remove_relay_forwarder_endpoint(&peer).await;
            self.record_start_failure(&peer).await;
            if let Err(error) = handle.stop().await {
                tracing::warn!(
                    %error,
                    peer = %peer,
                    "relay forwarder exited and was removed from supervisor"
                );
            } else {
                tracing::warn!(
                    peer = %peer,
                    "relay forwarder exited without an explicit supervisor stop"
                );
            }
        }
        finished_count
    }

    async fn bind_socket(&self) -> anyhow::Result<tokio::net::UdpSocket> {
        self.config.placement.validate_current_process()?;
        tokio::net::UdpSocket::bind(self.config.bind_addr)
            .await
            .with_context(|| {
                format!(
                    "failed to bind relay forwarder UDP socket in {}",
                    self.config.placement.description()
                )
            })
    }

    async fn ensure_capacity(&self, peer: &NodeId) -> anyhow::Result<()> {
        let handles = self.handles.lock().await;
        if handles.contains_key(peer) || handles.len() < self.config.max_sessions {
            return Ok(());
        }
        anyhow::bail!(
            "relay forwarder capacity exceeded: active={} max={}",
            handles.len(),
            self.config.max_sessions
        );
    }

    async fn ensure_start_allowed(&self, peer: &NodeId) -> anyhow::Result<()> {
        let now = chrono::Utc::now();
        let mut backoff = self.restart_backoff_until.lock().await;
        if let Some(until) = backoff.get(peer).copied() {
            if now < until {
                anyhow::bail!(
                    "relay forwarder restart backoff active until {until} for peer {peer}"
                );
            } else {
                backoff.remove(peer);
            }
        }
        drop(backoff);

        if !self.config.crash_policy.enabled() {
            return Ok(());
        }

        let mut crash_state = self.crash_state.lock().await;
        match crash_state.get(peer) {
            Some(state) if state.cooldown_until.is_some_and(|until| now < until) => {
                let until = state.cooldown_until.unwrap_or(now);
                anyhow::bail!(
                    "relay forwarder crash-loop cooldown active until {until} for peer {peer}"
                );
            }
            Some(state) if state.cooldown_until.is_some() => {
                if let Some(until) = state.cooldown_until {
                    tracing::info!(
                        peer = %peer,
                        cooldown_until = %until,
                        "relay forwarder crash-loop cooldown expired"
                    );
                }
                crash_state.remove(peer);
            }
            Some(state)
                if now.signed_duration_since(state.window_started_at)
                    > chrono::Duration::from_std(self.config.crash_policy.window)
                        .unwrap_or_else(|_| chrono::Duration::seconds(i64::MAX)) =>
            {
                crash_state.remove(peer);
            }
            _ => {}
        };
        Ok(())
    }

    async fn record_start_failure(&self, peer: &NodeId) {
        let now = chrono::Utc::now();
        if self.config.restart_backoff.is_zero() {
            self.restart_backoff_until.lock().await.remove(peer);
        } else {
            let backoff = chrono::Duration::from_std(self.config.restart_backoff)
                .unwrap_or_else(|_| chrono::Duration::seconds(i64::MAX));
            self.restart_backoff_until
                .lock()
                .await
                .insert(peer.clone(), now + backoff);
        }

        if !self.config.crash_policy.enabled() {
            return;
        }

        let window = chrono::Duration::from_std(self.config.crash_policy.window)
            .unwrap_or_else(|_| chrono::Duration::seconds(i64::MAX));
        let cooldown = chrono::Duration::from_std(self.config.crash_policy.cooldown)
            .unwrap_or_else(|_| chrono::Duration::seconds(i64::MAX));
        let mut crash_state = self.crash_state.lock().await;
        let state = crash_state
            .entry(peer.clone())
            .and_modify(|state| {
                if now.signed_duration_since(state.window_started_at) > window
                    || state.cooldown_until.is_some_and(|until| now >= until)
                {
                    state.window_started_at = now;
                    state.crashes_in_window = 0;
                    state.cooldown_until = None;
                }
            })
            .or_insert(RelayForwarderCrashState {
                window_started_at: now,
                crashes_in_window: 0,
                cooldown_until: None,
            });
        state.crashes_in_window = state.crashes_in_window.saturating_add(1);
        if state.crashes_in_window >= self.config.crash_policy.max_crashes_per_window {
            let until = now + cooldown;
            state.cooldown_until = Some(until);
            tracing::warn!(
                peer = %peer,
                crashes = state.crashes_in_window,
                window_seconds = self.config.crash_policy.window.as_secs(),
                cooldown_until = %until,
                "relay forwarder entered crash-loop cooldown"
            );
        }
    }

    async fn remove(&self, runtime: &AgentRuntime, peer: &NodeId) {
        self.remove_forwarder(runtime, peer, true).await;
    }

    async fn remove_forwarder(
        &self,
        runtime: &AgentRuntime,
        peer: &NodeId,
        clear_failure_policy: bool,
    ) {
        runtime.remove_relay_forwarder_endpoint(peer).await;
        if clear_failure_policy {
            self.restart_backoff_until.lock().await.remove(peer);
            self.crash_state.lock().await.remove(peer);
        }
        let handle = self.handles.lock().await.remove(peer);
        if let Some(handle) = handle {
            if let Err(error) = handle.stop().await {
                tracing::warn!(%error, peer = %peer, "failed to stop relay forwarder");
            }
        }
    }

    async fn shutdown_all(&self, runtime: &AgentRuntime) {
        let handles = {
            let mut handles = self.handles.lock().await;
            std::mem::take(&mut *handles)
        };
        self.restart_backoff_until.lock().await.clear();
        self.crash_state.lock().await.clear();
        for (peer, handle) in handles {
            runtime.remove_relay_forwarder_endpoint(&peer).await;
            if let Err(error) = handle.stop().await {
                tracing::warn!(%error, peer = %peer, "failed to stop relay forwarder");
            }
        }
    }
}

#[cfg(unix)]
fn ensure_process_in_netns(namespace: &LinuxNetworkNamespace) -> anyhow::Result<()> {
    let target_path = netns_path(namespace);
    let current_path =
        current_process_netns_path().context("failed to locate current network namespace")?;
    ensure_process_in_netns_path(namespace, &target_path, &current_path)
}

#[cfg(unix)]
fn ensure_process_in_netns_path(
    namespace: &LinuxNetworkNamespace,
    target_path: &Path,
    current_netns_path: &Path,
) -> anyhow::Result<()> {
    let report = inspect_linux_netns_path(namespace, target_path, Some(current_netns_path))
        .with_context(|| {
            format!(
                "failed to inspect network namespace {}; run the agent inside it or create {}",
                namespace.name(),
                target_path.display()
            )
        })?;
    ensure_relay_forwarder_current_netns_match(namespace, target_path, &report)
}

#[cfg(unix)]
fn ensure_relay_forwarder_current_netns_match(
    namespace: &LinuxNetworkNamespace,
    target_path: &Path,
    report: &LinuxNetnsPathReport,
) -> anyhow::Result<()> {
    if report.same_as_current == Some(true) {
        return Ok(());
    }
    anyhow::bail!(
        "relay forwarder requires process network namespace {}; current process is in a different namespace than {}",
        namespace.name(),
        target_path.display()
    )
}

#[cfg(not(unix))]
fn ensure_process_in_netns(namespace: &LinuxNetworkNamespace) -> anyhow::Result<()> {
    anyhow::bail!(
        "relay forwarder network namespace placement is only supported on Unix/Linux: {}",
        namespace.name()
    )
}

fn netns_path(namespace: &LinuxNetworkNamespace) -> std::path::PathBuf {
    namespace.path()
}

#[derive(Debug)]
struct RelayForwarderTask {
    session_id: String,
    relay_endpoint: SocketAddr,
    local_endpoint: SocketAddr,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<(), AgentError>>,
}

impl RelayForwarderTask {
    async fn stop(self) -> anyhow::Result<()> {
        let _ = self.shutdown_tx.send(true);
        match self.task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error).context("relay forwarder task failed"),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error).context("relay forwarder task join failed"),
        }
    }
}

async fn register_agent(
    runtime: &AgentRuntime,
    token: &SignedJoinToken,
    control_plane_url: Option<&str>,
    relay_capability: Option<RelayCapability>,
    requested_routes: Vec<Route>,
) -> anyhow::Result<AgentRegistration> {
    let control_plane_urls = control_plane_base_urls(Some(token), control_plane_url)?;
    let status = runtime.status().await;
    let request = JoinNodeRequest {
        token: token.clone(),
        registration: RegisterNodeRequest {
            node_id: status.node_id,
            identity_public_key: status.identity_public_key,
            wireguard_public_key: status.wireguard_public_key,
            candidates: status.candidates,
            relay_capability,
            requested_routes,
        },
    };

    let client = reqwest::Client::new();
    let mut failures = Vec::new();
    for control_plane_url in control_plane_urls {
        let join_url = control_plane_join_url_from_base(&control_plane_url);
        let response = match client.post(&join_url).json(&request).send().await {
            Ok(response) => response,
            Err(error) => {
                failures.push(format!("{join_url}: send failed: {error}"));
                continue;
            }
        };
        let response = match response.error_for_status() {
            Ok(response) => response,
            Err(error) => {
                failures.push(format!("{join_url}: rejected: {error}"));
                continue;
            }
        };
        match read_bounded_agent_json_response(
            response,
            MAX_AGENT_CONTROL_PLANE_RESPONSE_BYTES,
            "control-plane join",
        )
        .await
        {
            Ok(response) => {
                return Ok(AgentRegistration {
                    control_plane_url,
                    response,
                });
            }
            Err(error) => failures.push(format!("{join_url}: decode failed: {error}")),
        }
    }

    Err(anyhow::anyhow!(
        "all control-plane join endpoints failed: {}",
        failures.join("; ")
    ))
}

fn start_heartbeat_reporting(
    runtime: Arc<AgentRuntime>,
    identity: IdentityKeyPair,
    control_plane_urls: Vec<String>,
    interval: Duration,
    relay_capability_reporter: Option<RelayCapabilityReporter>,
    route_reporter: Option<HeartbeatRouteReporter>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_heartbeat_loop(
            runtime,
            identity,
            control_plane_urls,
            interval,
            relay_capability_reporter,
            route_reporter,
        )
        .await;
    })
}

async fn run_heartbeat_loop(
    runtime: Arc<AgentRuntime>,
    identity: IdentityKeyPair,
    control_plane_urls: Vec<String>,
    interval: Duration,
    relay_capability_reporter: Option<RelayCapabilityReporter>,
    route_reporter: Option<HeartbeatRouteReporter>,
) {
    let client = reqwest::Client::new();
    loop {
        let relay_capability =
            heartbeat_relay_capability(&client, relay_capability_reporter.as_ref()).await;
        let routes = heartbeat_routes(route_reporter.as_ref()).await;
        let request = match heartbeat_request(
            runtime.as_ref(),
            &identity,
            relay_capability.clone(),
            routes,
        )
        .await
        {
            Ok(request) => request,
            Err(error) => {
                tracing::warn!(%error, "failed to sign agent heartbeat; will retry");
                tokio::time::sleep(interval).await;
                continue;
            }
        };
        match send_heartbeat_to_control_planes(&client, &control_plane_urls, request).await {
            Ok(response) => tracing::info!(
                accepted = response.accepted,
                policy_version = response.policy_version,
                peer_delta_available = response.peer_delta_available,
                "reported agent heartbeat"
            ),
            Err(error) => tracing::warn!(
                %error,
                "failed to report agent heartbeat; will retry"
            ),
        }
        tokio::time::sleep(interval).await;
    }
}

async fn send_heartbeat_to_control_planes(
    client: &reqwest::Client,
    control_plane_urls: &[String],
    request: HeartbeatRequest,
) -> anyhow::Result<HeartbeatResponse> {
    anyhow::ensure!(
        !control_plane_urls.is_empty(),
        "control-plane URL is required for heartbeat reporting"
    );
    let mut failures = Vec::new();
    for control_plane_url in control_plane_urls {
        match send_heartbeat(client, control_plane_url, request.clone()).await {
            Ok(response) => return Ok(response),
            Err(error) => failures.push(format!("{}: {error:#}", heartbeat_url(control_plane_url))),
        }
    }
    anyhow::bail!(
        "all control-plane heartbeat endpoints failed: {}",
        failures.join("; ")
    )
}

async fn send_heartbeat(
    client: &reqwest::Client,
    control_plane_url: &str,
    request: HeartbeatRequest,
) -> anyhow::Result<HeartbeatResponse> {
    let response = client
        .post(heartbeat_url(control_plane_url))
        .json(&request)
        .send()
        .await
        .context("failed to send heartbeat request")?
        .error_for_status()
        .context("control plane rejected heartbeat request")?;
    read_bounded_agent_json_response(
        response,
        MAX_AGENT_CONTROL_PLANE_RESPONSE_BYTES,
        "control-plane heartbeat",
    )
    .await
}

async fn heartbeat_request(
    runtime: &AgentRuntime,
    identity: &IdentityKeyPair,
    relay_capability: Option<RelayCapability>,
    routes: Option<Vec<Route>>,
) -> anyhow::Result<HeartbeatRequest> {
    let status = runtime.status().await;
    let path_state = runtime.path_state().await;
    let health = agent_health_from_status(&status, "agent heartbeat");
    let mut request = HeartbeatRequest {
        node_id: status.node_id,
        health,
        candidates: status.candidates,
        relay_capability,
        routes,
        path_state,
        node_signature: None,
    };
    request.node_signature = Some(
        identity
            .sign_heartbeat_request(&request, chrono::Utc::now())
            .context("failed to sign agent heartbeat request")?,
    );
    Ok(request)
}

fn start_signal_registration(
    runtime: Arc<AgentRuntime>,
    node: NodeRecord,
    signal_urls: Vec<String>,
    interval: Duration,
    relay_capability_reporter: Option<RelayCapabilityReporter>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_signal_registration_loop(
            runtime,
            node,
            signal_urls,
            interval,
            relay_capability_reporter,
        )
        .await;
    })
}

async fn run_signal_registration_loop(
    runtime: Arc<AgentRuntime>,
    node: NodeRecord,
    signal_urls: Vec<String>,
    interval: Duration,
    relay_capability_reporter: Option<RelayCapabilityReporter>,
) {
    let client = reqwest::Client::new();
    loop {
        let relay_capability =
            heartbeat_relay_capability(&client, relay_capability_reporter.as_ref()).await;
        let request =
            signal_node_upsert_request(runtime.as_ref(), node.clone(), relay_capability).await;
        match send_signal_node_upsert_to_signal_services(&client, &signal_urls, request).await {
            Ok(successes) => tracing::info!(
                node_id = %node.node_id,
                signal_services = successes,
                "registered agent node with signal services"
            ),
            Err(error) => tracing::warn!(
                %error,
                "failed to register agent node with signal service; will retry"
            ),
        }
        tokio::time::sleep(interval).await;
    }
}

async fn send_signal_node_upsert_to_signal_services(
    client: &reqwest::Client,
    signal_urls: &[String],
    request: SignalNodeUpsertRequest,
) -> anyhow::Result<usize> {
    let mut successes = 0_usize;
    let mut errors = Vec::new();
    for signal_url in signal_urls {
        match send_signal_node_upsert(client, signal_url, request.clone()).await {
            Ok(response) => {
                successes += 1;
                tracing::debug!(
                    signal_url,
                    node_id = %response.node.node_id,
                    "registered agent node with signal service"
                );
            }
            Err(error) => errors.push(format!("{signal_url}: {error:#}")),
        }
    }

    if successes == 0 {
        anyhow::bail!(
            "all signal services failed node upsert: {}",
            errors.join("; ")
        );
    }
    if !errors.is_empty() {
        tracing::warn!(
            successes,
            failures = errors.len(),
            errors = ?errors,
            "registered agent node with a subset of signal services"
        );
    }
    Ok(successes)
}

async fn send_signal_node_upsert(
    client: &reqwest::Client,
    signal_url: &str,
    request: SignalNodeUpsertRequest,
) -> anyhow::Result<SignalNodeUpsertResponse> {
    let response = client
        .put(signal_node_url(signal_url, &request.node.node_id))
        .json(&request)
        .send()
        .await
        .context("failed to send signal node upsert")?
        .error_for_status()
        .context("signal service rejected node upsert")?;
    read_bounded_agent_json_response(
        response,
        MAX_AGENT_SIGNAL_RESPONSE_BYTES,
        "signal node upsert",
    )
    .await
}

async fn signal_node_upsert_request(
    runtime: &AgentRuntime,
    mut node: NodeRecord,
    relay_capability: Option<RelayCapability>,
) -> SignalNodeUpsertRequest {
    let status = runtime.status().await;
    let health = agent_health_from_status(&status, "agent signal registration");
    node.endpoint_candidates = status.candidates;
    node.relay_capability =
        signal_relay_capability(node.relay_capability.as_ref(), relay_capability);
    SignalNodeUpsertRequest {
        node,
        nat_classification: status.nat_classification,
        health: Some(health),
    }
}

fn signal_relay_capability(
    registered_capability: Option<&RelayCapability>,
    refreshed_capability: Option<RelayCapability>,
) -> Option<RelayCapability> {
    let registered_capability = registered_capability?;
    if !registered_capability.enabled_by_policy {
        return None;
    }
    let mut refreshed_capability = refreshed_capability?;
    refreshed_capability.enabled_by_policy = true;
    Some(refreshed_capability)
}

fn agent_health_from_status(
    status: &ipars_types::api::AgentStatusResponse,
    healthy_message: &str,
) -> NodeHealth {
    let mut health = NodeHealth {
        state: HealthState::Healthy,
        last_seen_at: chrono::Utc::now(),
        latency_ms: None,
        relay_load: None,
        message: Some(healthy_message.to_string()),
    };
    let Some(process) = status.userspace_wireguard_process.as_ref() else {
        return health;
    };

    match process.state {
        AgentManagedProcessState::Disabled | AgentManagedProcessState::Ready => health,
        AgentManagedProcessState::Starting
        | AgentManagedProcessState::Stopping
        | AgentManagedProcessState::Stopped => {
            health.state = HealthState::Degraded;
            health.message = Some(format!(
                "userspace WireGuard process state={}",
                process.state.as_str()
            ));
            health
        }
        AgentManagedProcessState::Exited | AgentManagedProcessState::Failed => {
            health.state = HealthState::Unhealthy;
            health.message = Some(format!(
                "userspace WireGuard process state={}{}{}",
                process.state.as_str(),
                process
                    .exit_status
                    .as_deref()
                    .map(|status| format!(", exit_status={status}"))
                    .unwrap_or_default(),
                process
                    .message
                    .as_deref()
                    .map(|message| format!(", message={message}"))
                    .unwrap_or_default()
            ));
            health
        }
    }
}

struct SignalPathNegotiationOptions {
    relay_forwarder_supervisor: Option<Arc<RelayForwarderSupervisor>>,
    relay_admission_bearer_token: Option<String>,
    relay_session_renew_before: Duration,
    interval: Duration,
}

fn start_signal_path_negotiation(
    runtime: Arc<AgentRuntime>,
    control_plane_urls: Vec<String>,
    signal_urls: Vec<String>,
    hole_puncher: UdpHolePuncher,
    options: SignalPathNegotiationOptions,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_signal_path_negotiation_loop(
            runtime,
            control_plane_urls,
            signal_urls,
            hole_puncher,
            options,
        )
        .await;
    })
}

async fn run_signal_path_negotiation_loop(
    runtime: Arc<AgentRuntime>,
    control_plane_urls: Vec<String>,
    signal_urls: Vec<String>,
    hole_puncher: UdpHolePuncher,
    options: SignalPathNegotiationOptions,
) {
    let client = reqwest::Client::new();
    loop {
        if let Err(error) = negotiate_signal_paths(
            &client,
            runtime.as_ref(),
            &control_plane_urls,
            &signal_urls,
            &hole_puncher,
            &options,
        )
        .await
        {
            tracing::warn!(%error, "failed to negotiate signal paths; will retry");
        }
        tokio::time::sleep(options.interval).await;
    }
}

async fn negotiate_signal_paths(
    client: &reqwest::Client,
    runtime: &AgentRuntime,
    control_plane_urls: &[String],
    signal_urls: &[String],
    hole_puncher: &UdpHolePuncher,
    options: &SignalPathNegotiationOptions,
) -> anyhow::Result<()> {
    let status = runtime.status().await;
    let peer_map = fetch_peer_map_from_control_planes(client, control_plane_urls, &status.node_id)
        .await
        .context("failed to fetch peer map for signal negotiation")?;

    let peer_set = signal_negotiation_peer_set(runtime, peer_map).await;
    for peer in peer_set.skipped {
        remove_relay_session_for_peer(
            runtime,
            options.relay_forwarder_supervisor.as_ref(),
            &peer,
            None,
            "removed relay session for idle lazy-connect peer",
        )
        .await;
    }

    for peer in peer_set.active {
        let request = signal_path_request(&status, &peer);
        let (signal_url, response) =
            send_signal_path_request_to_signal_services(client, signal_urls, request).await?;
        let mut relay_candidates = selected_relay_candidates(&response);
        promote_active_relay_candidate(runtime, &peer.node_id, &mut relay_candidates).await;
        let candidate_record = signal_path_record(response, chrono::Utc::now());
        let (mut record, mut path_selection) =
            stable_signal_path_record(runtime, candidate_record).await;
        if record.selected_state == PathState::DirectNatTraversal {
            let hole_punch_result = match fetch_hole_punch_plan(client, &signal_url, &record.key)
                .await
            {
                Ok(plan) => hole_puncher
                    .execute(&status.node_id, &plan)
                    .await
                    .map(|attempts| {
                        tracing::info!(
                            attempts,
                            peer = %record.key.remote,
                            "executed UDP hole punch plan"
                        );
                    }),
                Err(error) => Err(AgentError::HolePunch(format!(
                    "failed to fetch UDP hole punch plan: {error:#}"
                ))),
            };
            if let Err(error) = hole_punch_result {
                tracing::warn!(
                    %error,
                    peer = %record.key.remote,
                    "failed to prepare direct NAT traversal path"
                );
                if let Some(fallback) = relay_fallback_path_record(&record, &relay_candidates) {
                    tracing::warn!(
                        peer = %record.key.remote,
                        relay = ?fallback.relay_node,
                        "falling back to relay after direct NAT traversal setup failed"
                    );
                    record = fallback;
                    path_selection = StableSignalPathSelection::Candidate;
                } else {
                    record = unreachable_path_record(
                        &record,
                        "direct_nat_traversal_failed",
                        chrono::Utc::now(),
                    );
                    path_selection = StableSignalPathSelection::Candidate;
                    tracing::warn!(
                        peer = %record.key.remote,
                        "direct NAT traversal setup failed and no relay fallback candidate was available; marking path unreachable"
                    );
                }
            }
        }
        if record.selected_state == PathState::Relay
            && path_selection == StableSignalPathSelection::Candidate
        {
            if let Some(preferred_relay) = relay_candidates.first() {
                record.relay_node = Some(preferred_relay.node_id.clone());
            }
        }
        if record.selected_state == PathState::Relay {
            match relay_candidates.first() {
                Some(preferred_relay) => {
                    if relay_session_needs_renewal(
                        runtime,
                        &peer.node_id,
                        &preferred_relay.node_id,
                        options.relay_session_renew_before,
                    )
                    .await
                    {
                        match admit_relay_session_from_candidates(
                            client,
                            runtime,
                            &status,
                            &peer,
                            &relay_candidates,
                            options.relay_admission_bearer_token.as_deref(),
                        )
                        .await
                        {
                            Ok(session) => {
                                record.relay_node = Some(session.relay_node.clone());
                                tracing::info!(
                                    peer = %record.key.remote,
                                    relay = %session.relay_node,
                                    expires_at = %session.expires_at,
                                    "admitted relay session"
                                );
                                runtime.upsert_relay_session(session.clone()).await;
                                if let Some(supervisor) =
                                    options.relay_forwarder_supervisor.as_ref()
                                {
                                    if let Err(error) = supervisor.upsert(runtime, session).await {
                                        tracing::warn!(
                                            %error,
                                            peer = %record.key.remote,
                                            "failed to start relay forwarder"
                                        );
                                    }
                                }
                            }
                            Err(error) => {
                                if let Some(session) =
                                    active_relay_session(runtime, &peer.node_id).await
                                {
                                    record.relay_node = Some(session.relay_node.clone());
                                    tracing::warn!(
                                        %error,
                                        peer = %record.key.remote,
                                        relay = %session.relay_node,
                                        expires_at = %session.expires_at,
                                        "failed relay admission renewal; retaining existing relay session"
                                    );
                                    if let Some(supervisor) =
                                        options.relay_forwarder_supervisor.as_ref()
                                    {
                                        if let Err(error) =
                                            supervisor.upsert(runtime, session).await
                                        {
                                            tracing::warn!(
                                                %error,
                                                peer = %record.key.remote,
                                                "failed to ensure existing relay forwarder"
                                            );
                                        }
                                    }
                                } else {
                                    remove_relay_session_for_peer(
                                        runtime,
                                        options.relay_forwarder_supervisor.as_ref(),
                                        &peer.node_id,
                                        Some(PathState::Unreachable),
                                        "removed relay session after relay admission failed",
                                    )
                                    .await;
                                    record = unreachable_path_record(
                                        &record,
                                        "relay_admission_failed",
                                        chrono::Utc::now(),
                                    );
                                    tracing::warn!(
                                        %error,
                                        peer = %record.key.remote,
                                        "failed to admit relay session; marking path unreachable"
                                    );
                                }
                            }
                        }
                    } else {
                        tracing::debug!(
                            peer = %record.key.remote,
                            relay = %preferred_relay.node_id,
                            "reusing existing relay session"
                        );
                        if let Some(session) = runtime.relay_session(&peer.node_id).await {
                            record.relay_node = Some(session.relay_node.clone());
                            if let Some(supervisor) = options.relay_forwarder_supervisor.as_ref() {
                                if let Err(error) = supervisor.upsert(runtime, session).await {
                                    tracing::warn!(
                                        %error,
                                        peer = %record.key.remote,
                                        "failed to ensure relay forwarder"
                                    );
                                }
                            }
                        }
                    }
                }
                None => {
                    let mut retained_existing_session = false;
                    if path_selection == StableSignalPathSelection::CurrentRelay {
                        if let Some(session) = active_relay_session(runtime, &peer.node_id).await {
                            record.relay_node = Some(session.relay_node.clone());
                            retained_existing_session = true;
                            tracing::debug!(
                                peer = %record.key.remote,
                                relay = %session.relay_node,
                                "keeping existing relay path without fresh relay candidates"
                            );
                            if let Some(supervisor) = options.relay_forwarder_supervisor.as_ref() {
                                if let Err(error) = supervisor.upsert(runtime, session).await {
                                    tracing::warn!(
                                        %error,
                                        peer = %record.key.remote,
                                        "failed to ensure existing relay forwarder"
                                    );
                                }
                            }
                        }
                    }
                    if !retained_existing_session {
                        remove_relay_session_for_peer(
                            runtime,
                            options.relay_forwarder_supervisor.as_ref(),
                            &peer.node_id,
                            Some(PathState::Unreachable),
                            "removed relay session after relay candidates disappeared",
                        )
                        .await;
                        record = unreachable_path_record(
                            &record,
                            "no_usable_relay_candidate",
                            chrono::Utc::now(),
                        );
                        tracing::warn!(
                            peer = %record.key.remote,
                            "signal selected relay path without a usable relay candidate; marking path unreachable"
                        );
                    }
                }
            }
        } else {
            remove_relay_session_for_peer(
                runtime,
                options.relay_forwarder_supervisor.as_ref(),
                &peer.node_id,
                Some(record.selected_state),
                "removed relay session after non-relay path selection",
            )
            .await;
        }
        runtime.upsert_path_state(record).await?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StableSignalPathSelection {
    Candidate,
    CurrentRelay,
}

async fn stable_signal_path_record(
    runtime: &AgentRuntime,
    candidate: PathRecord,
) -> (PathRecord, StableSignalPathSelection) {
    if let Some(mut current) = runtime.path_record_for_peer(&candidate.key.remote).await {
        if current.selected_state == PathState::Relay
            && candidate.selected_state.is_direct()
            && !PathSelector::should_promote(&current, &candidate)
        {
            if let Some(session) = active_relay_session(runtime, &candidate.key.remote).await {
                current.updated_at = candidate.updated_at;
                current.relay_node = Some(session.relay_node.clone());
                tracing::debug!(
                    peer = %candidate.key.remote,
                    relay = %session.relay_node,
                    relay_score = current.score.value,
                    direct_score = candidate.score.value,
                    "keeping relay path until direct candidate score clears promotion margin"
                );
                return (current, StableSignalPathSelection::CurrentRelay);
            }
            tracing::debug!(
                peer = %candidate.key.remote,
                relay_score = current.score.value,
                direct_score = candidate.score.value,
                "accepting direct candidate because current relay path has no active session"
            );
        }
    }

    (candidate, StableSignalPathSelection::Candidate)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SignalNegotiationPeerSet {
    active: Vec<NodeRecord>,
    skipped: Vec<NodeId>,
}

async fn signal_negotiation_peer_set(
    runtime: &AgentRuntime,
    peer_map: PeerMap,
) -> SignalNegotiationPeerSet {
    let mut skipped = runtime
        .take_idle_peers_to_close(chrono::Utc::now())
        .await
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    runtime
        .observe_peer_map_for_lazy_connect(&peer_map.peers)
        .await;
    let mut active = Vec::new();
    for peer in peer_map.peers {
        if runtime.should_connect_peer(&peer).await {
            active.push(peer);
        } else {
            skipped.insert(peer.node_id);
        }
    }
    SignalNegotiationPeerSet {
        active,
        skipped: skipped.into_iter().collect(),
    }
}

async fn remove_relay_session_for_peer(
    runtime: &AgentRuntime,
    relay_forwarder_supervisor: Option<&Arc<RelayForwarderSupervisor>>,
    peer: &NodeId,
    selected_state: Option<PathState>,
    message: &'static str,
) {
    let removed = runtime.remove_relay_session(peer).await;
    if let Some(session) = removed {
        if let Some(supervisor) = relay_forwarder_supervisor {
            supervisor.remove(runtime, &session.peer).await;
        } else {
            runtime.remove_relay_forwarder_endpoint(&session.peer).await;
        }
        tracing::info!(
            peer = %session.peer,
            relay = %session.relay_node,
            state = ?selected_state,
            "{message}"
        );
    } else if let Some(supervisor) = relay_forwarder_supervisor {
        supervisor.remove(runtime, peer).await;
    } else {
        runtime.remove_relay_forwarder_endpoint(peer).await;
    }
}

fn agent_join_token(args: &AgentArgs) -> anyhow::Result<Option<SignedJoinToken>> {
    let Some(token) = raw_agent_join_token(args)? else {
        return Ok(None);
    };
    serde_json::from_str(&token)
        .map(Some)
        .context("agent join token must be JSON signed token")
}

fn raw_agent_join_token(args: &AgentArgs) -> anyhow::Result<Option<String>> {
    if let Some(token) = args.join_token.as_deref() {
        ensure_agent_join_token_size(token.len() as u64, "inline agent join token")?;
        return Ok(Some(token.to_string()));
    }
    let Some(path) = args.join_token_path.as_deref() else {
        return Ok(None);
    };
    let token = read_agent_join_token_file(path)?;
    let token = token.trim();
    if token.is_empty() {
        anyhow::bail!("agent join token file {} is empty", path.display());
    }
    Ok(Some(token.to_string()))
}

fn read_agent_join_token_file(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open agent join token file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect agent join token file {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!(
            "agent join token path {} must resolve to a regular file",
            path.display()
        );
    }
    ensure_agent_join_token_size(
        metadata.len(),
        &format!("agent join token file {}", path.display()),
    )?;

    let mut token = String::new();
    let mut reader = file.by_ref().take(MAX_AGENT_JOIN_TOKEN_BYTES + 1);
    reader
        .read_to_string(&mut token)
        .with_context(|| format!("failed to read agent join token from {}", path.display()))?;
    ensure_agent_join_token_size(
        token.len() as u64,
        &format!("agent join token file {}", path.display()),
    )?;
    Ok(token)
}

fn ensure_agent_join_token_size(size: u64, context: &str) -> anyhow::Result<()> {
    if size > MAX_AGENT_JOIN_TOKEN_BYTES {
        anyhow::bail!(
            "{context} exceeds maximum size of {} bytes",
            MAX_AGENT_JOIN_TOKEN_BYTES
        );
    }
    Ok(())
}

async fn read_bounded_agent_json_response<Response>(
    mut response: reqwest::Response,
    max_bytes: u64,
    context: &str,
) -> anyhow::Result<Response>
where
    Response: DeserializeOwned,
{
    if let Some(length) = response.content_length() {
        ensure_agent_http_response_size(length, max_bytes, context)?;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("failed to read {context} response"))?
    {
        let next_len = body.len() as u64 + chunk.len() as u64;
        ensure_agent_http_response_size(next_len, max_bytes, context)?;
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).with_context(|| format!("failed to decode {context} response"))
}

fn ensure_agent_http_response_size(size: u64, max_bytes: u64, context: &str) -> anyhow::Result<()> {
    if size > max_bytes {
        anyhow::bail!("{context} response exceeds maximum size of {max_bytes} bytes");
    }
    Ok(())
}

fn agent_relay_capability(args: &AgentArgs) -> Option<RelayCapability> {
    let public_endpoint = args.relay_public_endpoint?;
    let admission_url = args.relay_admission_url.clone()?;
    Some(RelayCapability {
        enabled_by_policy: false,
        public_endpoint: Some(public_endpoint),
        admission_url: Some(admission_url),
        max_sessions: args.relay_max_sessions,
        active_sessions: 0,
        max_mbps: args.relay_max_mbps,
        e2e_only: true,
    })
}

#[derive(Debug, Clone)]
struct RelayCapabilityReporter {
    advertised: RelayCapability,
    status_url: Option<String>,
}

fn agent_relay_capability_reporter(
    args: &AgentArgs,
) -> anyhow::Result<Option<RelayCapabilityReporter>> {
    validate_agent_relay_capability_config(args)?;
    let Some(advertised) = agent_relay_capability(args) else {
        return Ok(None);
    };
    let status_url = args
        .relay_status_url
        .clone()
        .or_else(|| args.relay_admission_url.clone());
    Ok(Some(RelayCapabilityReporter {
        advertised,
        status_url,
    }))
}

async fn heartbeat_relay_capability(
    client: &reqwest::Client,
    reporter: Option<&RelayCapabilityReporter>,
) -> Option<RelayCapability> {
    let reporter = reporter?;
    let Some(status_url) = reporter.status_url.as_deref() else {
        return Some(reporter.advertised.clone());
    };
    match fetch_relay_status(client, status_url).await {
        Ok(status) if status.health == HealthState::Healthy => {
            Some(relay_capability_from_status(&reporter.advertised, &status))
        }
        Ok(status) => {
            tracing::warn!(
                status_url,
                health = ?status.health,
                "relay status is not healthy; omitting relay capability from reports"
            );
            None
        }
        Err(error) => {
            tracing::warn!(
                %error,
                status_url,
                "failed to refresh relay status; omitting relay capability from reports"
            );
            None
        }
    }
}

async fn fetch_relay_status(
    client: &reqwest::Client,
    relay_url: &str,
) -> anyhow::Result<RelayStatusResponse> {
    let url = relay_status_url(relay_url);
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to send relay status request to {url}"))?
        .error_for_status()
        .with_context(|| format!("relay status request to {url} returned an error status"))?;
    read_bounded_agent_json_response(
        response,
        MAX_AGENT_RELAY_HTTP_RESPONSE_BYTES,
        "relay status",
    )
    .await
    .with_context(|| format!("failed to decode relay status response from {url}"))
}

fn relay_capability_from_status(
    advertised: &RelayCapability,
    status: &RelayStatusResponse,
) -> RelayCapability {
    RelayCapability {
        enabled_by_policy: advertised.enabled_by_policy,
        public_endpoint: advertised.public_endpoint,
        admission_url: advertised.admission_url.clone(),
        max_sessions: status.capability.max_sessions,
        active_sessions: status.capability.active_sessions,
        max_mbps: status.capability.max_mbps,
        e2e_only: status.capability.e2e_only,
    }
}

async fn relay_session_needs_renewal(
    runtime: &AgentRuntime,
    peer: &NodeId,
    relay_node: &NodeId,
    renew_before: Duration,
) -> bool {
    runtime
        .relay_session_needs_renewal(peer, relay_node, chrono::Utc::now(), renew_before)
        .await
}

async fn active_relay_session(runtime: &AgentRuntime, peer: &NodeId) -> Option<RelaySessionState> {
    runtime.active_relay_session(peer, chrono::Utc::now()).await
}

#[derive(Debug)]
enum AgentRelayAdmissionError {
    NoEndpointCandidate,
    InvalidRelayCandidate(anyhow::Error),
    Unavailable(anyhow::Error),
    Rejected(anyhow::Error),
    InvalidResponse(anyhow::Error),
}

impl AgentRelayAdmissionError {
    fn reason(&self) -> AgentRelayAdmissionFailureReason {
        match self {
            Self::NoEndpointCandidate => AgentRelayAdmissionFailureReason::NoEndpointCandidate,
            Self::InvalidRelayCandidate(_) => {
                AgentRelayAdmissionFailureReason::InvalidRelayCandidate
            }
            Self::Unavailable(_) => AgentRelayAdmissionFailureReason::Unavailable,
            Self::Rejected(_) => AgentRelayAdmissionFailureReason::Rejected,
            Self::InvalidResponse(_) => AgentRelayAdmissionFailureReason::InvalidResponse,
        }
    }
}

impl fmt::Display for AgentRelayAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEndpointCandidate => {
                write!(formatter, "relay session requires endpoint candidates")
            }
            Self::InvalidRelayCandidate(error) => {
                write!(formatter, "invalid relay candidate: {error:#}")
            }
            Self::Unavailable(error) => {
                write!(
                    formatter,
                    "failed to send relay admission request: {error:#}"
                )
            }
            Self::Rejected(error) => {
                write!(formatter, "relay rejected admission request: {error:#}")
            }
            Self::InvalidResponse(error) => {
                write!(formatter, "invalid relay admission response: {error:#}")
            }
        }
    }
}

impl std::error::Error for AgentRelayAdmissionError {}

async fn admit_relay_session(
    client: &reqwest::Client,
    status: &ipars_types::api::AgentStatusResponse,
    peer: &NodeRecord,
    relay: &NodeRecord,
    relay_admission_bearer_token: Option<&str>,
) -> Result<RelaySessionState, AgentRelayAdmissionError> {
    let request = relay_admission_request(status, peer)
        .ok_or(AgentRelayAdmissionError::NoEndpointCandidate)?;
    let relay_endpoint =
        relay_public_endpoint(relay).map_err(AgentRelayAdmissionError::InvalidRelayCandidate)?;
    let admission_url =
        relay_admission_url(relay).map_err(AgentRelayAdmissionError::InvalidRelayCandidate)?;
    let mut request_builder = client.post(admission_url).json(&request);
    if let Some(token) = relay_admission_bearer_token {
        request_builder = request_builder.bearer_auth(token);
    }
    let response = request_builder
        .send()
        .await
        .map_err(|error| AgentRelayAdmissionError::Unavailable(anyhow::Error::new(error)))?
        .error_for_status()
        .map_err(|error| AgentRelayAdmissionError::Rejected(anyhow::Error::new(error)))?;
    let response = read_bounded_agent_json_response(
        response,
        MAX_AGENT_RELAY_HTTP_RESPONSE_BYTES,
        "relay admission",
    )
    .await
    .map_err(AgentRelayAdmissionError::InvalidResponse)?;

    relay_session_state_from_admission(
        peer,
        relay,
        &request,
        response,
        relay_endpoint,
        chrono::Utc::now(),
    )
    .map_err(AgentRelayAdmissionError::InvalidResponse)
}

async fn admit_relay_session_from_candidates(
    client: &reqwest::Client,
    runtime: &AgentRuntime,
    status: &ipars_types::api::AgentStatusResponse,
    peer: &NodeRecord,
    relays: &[NodeRecord],
    relay_admission_bearer_token: Option<&str>,
) -> anyhow::Result<RelaySessionState> {
    let mut errors = Vec::new();
    for relay in relays {
        runtime.record_relay_admission_attempt();
        match admit_relay_session(client, status, peer, relay, relay_admission_bearer_token).await {
            Ok(session) => {
                runtime.record_relay_admission_success();
                return Ok(session);
            }
            Err(error) => {
                runtime.record_relay_admission_failure_reason(error.reason());
                errors.push(format!("{}: {error:#}", relay.node_id));
                tracing::warn!(
                    relay = %relay.node_id,
                    peer = %peer.node_id,
                    %error,
                    "failed relay admission candidate; trying next relay"
                );
            }
        }
    }

    anyhow::bail!(
        "all relay admission candidates failed: {}",
        errors.join("; ")
    )
}

fn relay_session_state_from_admission(
    peer: &NodeRecord,
    relay: &NodeRecord,
    request: &RelayAdmissionRequest,
    response: RelayAdmissionResponse,
    relay_endpoint: SocketAddr,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<RelaySessionState> {
    validate_relay_admission_response(peer, request, &response, now)?;
    let (admitted_local_addr, admitted_peer_addr) = if response.left == peer.node_id {
        (response.right_addr, response.left_addr)
    } else {
        (response.left_addr, response.right_addr)
    };
    Ok(RelaySessionState {
        peer: peer.node_id.clone(),
        relay_node: relay.node_id.clone(),
        relay_endpoint,
        admitted_local_addr,
        admitted_peer_addr,
        session_id: response.session_id,
        session_token: response.session_token,
        expires_at: response.expires_at,
    })
}

fn validate_relay_admission_response(
    peer: &NodeRecord,
    request: &RelayAdmissionRequest,
    response: &RelayAdmissionResponse,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<()> {
    if response.left != request.left || response.right != request.right {
        anyhow::bail!(
            "relay admission response node pair mismatch: expected {} -> {}, got {} -> {}",
            request.left,
            request.right,
            response.left,
            response.right
        );
    }
    if response.left != peer.node_id && response.right != peer.node_id {
        anyhow::bail!(
            "relay admission response target mismatch: expected peer {} in node pair {} -> {}",
            peer.node_id,
            response.left,
            response.right
        );
    }
    if response.left_addr != request.left_addr || response.right_addr != request.right_addr {
        anyhow::bail!(
            "relay admission response endpoint mismatch: expected {} -> {}, got {} -> {}",
            request.left_addr,
            request.right_addr,
            response.left_addr,
            response.right_addr
        );
    }
    let expected_session_id = RelaySessionId::new(&request.left, &request.right);
    if response.session_id != expected_session_id.as_str() {
        anyhow::bail!(
            "relay admission response session id mismatch: expected {}, got {}",
            expected_session_id.as_str(),
            response.session_id
        );
    }
    if response.expires_at <= now {
        anyhow::bail!(
            "relay admission response already expired at {}",
            response.expires_at
        );
    }
    encode_relay_datagram(&response.session_id, &response.session_token, &[0])
        .context("relay admission response returned invalid session credential")?;
    Ok(())
}

fn relay_admission_request(
    status: &ipars_types::api::AgentStatusResponse,
    peer: &NodeRecord,
) -> Option<RelayAdmissionRequest> {
    let local_addr = relay_session_endpoint(&status.candidates)?;
    let peer_addr = relay_session_endpoint(&peer.endpoint_candidates)?;
    let local_is_left = status.node_id <= peer.node_id;
    let (left, right, left_addr, right_addr) = if local_is_left {
        (
            status.node_id.clone(),
            peer.node_id.clone(),
            local_addr,
            peer_addr,
        )
    } else {
        (
            peer.node_id.clone(),
            status.node_id.clone(),
            peer_addr,
            local_addr,
        )
    };

    Some(RelayAdmissionRequest {
        left,
        right,
        left_addr,
        right_addr,
    })
}

fn relay_session_endpoint(candidates: &[EndpointCandidate]) -> Option<SocketAddr> {
    candidates
        .iter()
        .filter(|candidate| endpoint_addr_is_usable(candidate.addr))
        .filter_map(|candidate| {
            relay_session_endpoint_rank(candidate).map(|rank| (rank, candidate))
        })
        .min_by(|(left_rank, left), (right_rank, right)| {
            left_rank
                .cmp(right_rank)
                .then_with(|| left.cost.cmp(&right.cost))
                .then_with(|| right.priority.cmp(&left.priority))
        })
        .map(|(_, candidate)| candidate.addr)
}

fn relay_session_endpoint_rank(candidate: &EndpointCandidate) -> Option<u8> {
    match candidate.kind {
        ipars_types::EndpointCandidateKind::StunReflexive => Some(0),
        ipars_types::EndpointCandidateKind::PublicUdp => Some(1),
        ipars_types::EndpointCandidateKind::Ipv6 => Some(2),
        ipars_types::EndpointCandidateKind::LocalUdp => Some(3),
        ipars_types::EndpointCandidateKind::Relay => None,
    }
}

fn selected_relay_candidates(response: &SignalPathResponse) -> Vec<NodeRecord> {
    let mut candidates = response
        .relay_candidates
        .iter()
        .filter(|relay| {
            relay
                .relay_capability
                .as_ref()
                .map(|capability| capability.can_admit())
                .unwrap_or(false)
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by(relay_candidate_ordering);
    candidates
}

fn relay_candidate_ordering(left: &NodeRecord, right: &NodeRecord) -> std::cmp::Ordering {
    match (
        left.relay_capability.as_ref(),
        right.relay_capability.as_ref(),
    ) {
        (Some(left), Some(right)) => relay_utilization_ordering(left, right)
            .then_with(|| right.available_capacity().cmp(&left.available_capacity()))
            .then_with(|| right.max_mbps.cmp(&left.max_mbps))
            .then_with(|| left.active_sessions.cmp(&right.active_sessions)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn relay_utilization_ordering(
    left: &RelayCapability,
    right: &RelayCapability,
) -> std::cmp::Ordering {
    let left_numerator = u64::from(left.active_sessions) * u64::from(right.max_sessions);
    let right_numerator = u64::from(right.active_sessions) * u64::from(left.max_sessions);
    left_numerator.cmp(&right_numerator)
}

async fn promote_active_relay_candidate(
    runtime: &AgentRuntime,
    peer: &NodeId,
    candidates: &mut Vec<NodeRecord>,
) -> Option<NodeId> {
    let session = active_relay_session(runtime, peer).await?;
    let position = candidates
        .iter()
        .position(|relay| relay.node_id == session.relay_node)?;
    if position > 0 {
        let relay = candidates.remove(position);
        candidates.insert(0, relay);
    }
    Some(session.relay_node)
}

fn unreachable_path_record(
    previous: &PathRecord,
    reason: &'static str,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> PathRecord {
    let mut score = PathScore::calculate(PathState::Unreachable, &PathMetrics::default(), true, 0);
    score.reasons.push(reason.to_string());
    PathRecord {
        key: previous.key.clone(),
        selected_state: PathState::Unreachable,
        selected_candidate: None,
        relay_node: None,
        score,
        updated_at,
        pinned: previous.pinned,
    }
}

fn relay_fallback_path_record(
    direct_record: &PathRecord,
    relay_candidates: &[NodeRecord],
) -> Option<PathRecord> {
    let relay = relay_candidates.first()?;
    let relay_load = relay.relay_capability.as_ref().map(|capability| {
        if capability.max_sessions == 0 {
            1.0
        } else {
            capability.active_sessions as f32 / capability.max_sessions as f32
        }
    });
    let mut score = PathScore::calculate(
        PathState::Relay,
        &PathMetrics {
            relay_load,
            ..PathMetrics::default()
        },
        true,
        0,
    );
    score
        .reasons
        .push("direct_nat_traversal_failed".to_string());
    Some(PathRecord {
        key: direct_record.key.clone(),
        selected_state: PathState::Relay,
        selected_candidate: None,
        relay_node: Some(relay.node_id.clone()),
        score,
        updated_at: chrono::Utc::now(),
        pinned: direct_record.pinned,
    })
}

fn relay_admission_url(relay: &NodeRecord) -> anyhow::Result<String> {
    let url = relay
        .relay_capability
        .as_ref()
        .and_then(|capability| capability.admission_url.as_ref())
        .context("relay admission URL is missing")?;
    Ok(format!("{}/v1/sessions", url.trim_end_matches('/')))
}

fn relay_public_endpoint(relay: &NodeRecord) -> anyhow::Result<SocketAddr> {
    relay
        .relay_capability
        .as_ref()
        .and_then(|capability| capability.public_endpoint)
        .context("relay public UDP endpoint is missing")
}

async fn fetch_hole_punch_plan(
    client: &reqwest::Client,
    signal_url: &str,
    key: &ipars_types::PeerPathKey,
) -> anyhow::Result<SignalHolePunchPlanResponse> {
    let response = client
        .get(signal_hole_punch_url(signal_url, &key.local, &key.remote))
        .send()
        .await
        .context("failed to fetch hole punch plan")?
        .error_for_status()
        .context("signal service rejected hole punch plan request")?;
    read_bounded_agent_json_response(
        response,
        MAX_AGENT_SIGNAL_RESPONSE_BYTES,
        "signal hole punch plan",
    )
    .await
}

async fn send_signal_path_request(
    client: &reqwest::Client,
    signal_url: &str,
    request: SignalPathRequest,
) -> anyhow::Result<SignalPathResponse> {
    let response = client
        .post(signal_path_url(signal_url))
        .json(&request)
        .send()
        .await
        .context("failed to send signal path negotiation")?
        .error_for_status()
        .context("signal service rejected path negotiation")?;
    read_bounded_agent_json_response(
        response,
        MAX_AGENT_SIGNAL_RESPONSE_BYTES,
        "signal path negotiation",
    )
    .await
}

async fn send_signal_path_request_to_signal_services(
    client: &reqwest::Client,
    signal_urls: &[String],
    request: SignalPathRequest,
) -> anyhow::Result<(String, SignalPathResponse)> {
    let mut errors = Vec::new();
    for signal_url in signal_urls {
        match send_signal_path_request(client, signal_url, request.clone()).await {
            Ok(response) => return Ok((signal_url.clone(), response)),
            Err(error) => errors.push(format!("{signal_url}: {error:#}")),
        }
    }
    anyhow::bail!(
        "all signal services failed path negotiation: {}",
        errors.join("; ")
    )
}

fn signal_path_request(
    status: &ipars_types::api::AgentStatusResponse,
    peer: &NodeRecord,
) -> SignalPathRequest {
    SignalPathRequest {
        source: status.node_id.clone(),
        target: peer.node_id.clone(),
        source_candidates: status.candidates.clone(),
        source_nat_classification: status.nat_classification.clone(),
        desired_routes: peer.routes.iter().map(|route| route.cidr).collect(),
    }
}

fn signal_path_record(
    response: SignalPathResponse,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> PathRecord {
    let selected_candidate =
        selected_path_candidate(response.preferred_state, &response.target_candidates);
    let relay_node = if response.preferred_state == PathState::Relay {
        response
            .relay_candidates
            .first()
            .map(|node| node.node_id.clone())
    } else {
        None
    };

    PathRecord {
        key: response.key,
        selected_state: response.preferred_state,
        selected_candidate,
        relay_node,
        score: response.score,
        updated_at,
        pinned: false,
    }
}

fn selected_path_candidate(
    state: PathState,
    target_candidates: &[EndpointCandidate],
) -> Option<EndpointCandidate> {
    target_candidates
        .iter()
        .filter(|candidate| state.allows_selected_candidate_kind(candidate.kind))
        .min_by(|left, right| {
            left.cost
                .cmp(&right.cost)
                .then_with(|| right.priority.cmp(&left.priority))
        })
        .cloned()
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
                peers_removed = summary.peers_removed,
                routes_applied = summary.routes_applied,
                routes_removed = summary.routes_removed,
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

fn start_proc_net_conntrack_packet_flow_detector(
    runtime: Arc<AgentRuntime>,
    paths: Vec<PathBuf>,
    interval: Duration,
    dedup_ttl: Option<Duration>,
    limits: ProcNetConntrackReadLimits,
    pin: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut deduper = PacketFlowDeduper::new(dedup_ttl);
        loop {
            match read_conntrack_packet_flows(&paths, limits).await {
                Ok(flows) => {
                    let (flows, duplicate_count) = deduper.retain_new(flows);
                    record_packet_flow_duplicate_suppressions(
                        runtime.as_ref(),
                        duplicate_count,
                        AgentPacketFlowDuplicateSource::ProcNetConntrack,
                    );
                    let matched_count = record_packet_flow_observations(
                        runtime.as_ref(),
                        flows,
                        pin,
                        "proc-net-conntrack",
                    )
                    .await;
                    if matched_count > 0 {
                        tracing::info!(
                            matched = matched_count,
                            "recorded packet-flow lazy-connect activity from conntrack"
                        );
                    }
                }
                Err(error) => tracing::warn!(
                    %error,
                    "failed to read conntrack packet-flow table; will retry"
                ),
            }
            tokio::time::sleep(interval).await;
        }
    })
}

fn start_conntrack_netlink_packet_flow_detector(
    runtime: Arc<AgentRuntime>,
    interval: Duration,
    dedup_ttl: Option<Duration>,
    limits: ConntrackNetlinkReadLimits,
    pin: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut deduper = PacketFlowDeduper::new(dedup_ttl);
        loop {
            match read_conntrack_netlink_packet_flows(limits).await {
                Ok(flows) => {
                    let (flows, duplicate_count) = deduper.retain_new(flows);
                    record_packet_flow_duplicate_suppressions(
                        runtime.as_ref(),
                        duplicate_count,
                        AgentPacketFlowDuplicateSource::ConntrackNetlink,
                    );
                    let matched_count = record_packet_flow_observations(
                        runtime.as_ref(),
                        flows,
                        pin,
                        "conntrack-netlink",
                    )
                    .await;
                    if matched_count > 0 {
                        tracing::info!(
                            matched = matched_count,
                            "recorded packet-flow lazy-connect activity from conntrack netlink"
                        );
                    }
                }
                Err(error) => tracing::warn!(
                    %error,
                    "failed to read conntrack netlink packet-flow table; will retry"
                ),
            }
            tokio::time::sleep(interval).await;
        }
    })
}

fn start_conntrack_netlink_event_packet_flow_detector(
    runtime: Arc<AgentRuntime>,
    idle_poll_interval: Duration,
    dedup_ttl: Option<Duration>,
    limits: ConntrackNetlinkReadLimits,
    pin: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut deduper = PacketFlowDeduper::new(dedup_ttl);
        loop {
            match open_conntrack_netlink_event_socket() {
                Ok(socket) => {
                    if let Err(error) = run_conntrack_netlink_event_detector_once(
                        runtime.as_ref(),
                        &socket,
                        idle_poll_interval,
                        &mut deduper,
                        limits,
                        pin,
                    )
                    .await
                    {
                        tracing::warn!(
                            %error,
                            "conntrack netlink event detector failed; reopening socket"
                        );
                    }
                }
                Err(error) => tracing::warn!(
                    %error,
                    "failed to open conntrack netlink event socket; will retry"
                ),
            }
            tokio::time::sleep(idle_poll_interval).await;
        }
    })
}

fn start_ebpf_jsonl_packet_flow_detector(
    runtime: Arc<AgentRuntime>,
    event_path: PathBuf,
    interval: Duration,
    dedup_ttl: Option<Duration>,
    limits: EbpfJsonlReadLimits,
    pin: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut cursor = EbpfJsonlReadCursor::default();
        let mut deduper = PacketFlowDeduper::new(dedup_ttl);
        loop {
            match read_ebpf_jsonl_packet_flows(&event_path, &mut cursor, limits).await {
                Ok(flows) => {
                    let (flows, duplicate_count) = deduper.retain_new(flows);
                    record_packet_flow_duplicate_suppressions(
                        runtime.as_ref(),
                        duplicate_count,
                        AgentPacketFlowDuplicateSource::EbpfJsonl,
                    );
                    let matched_count =
                        record_packet_flow_observations(runtime.as_ref(), flows, pin, "ebpf-jsonl")
                            .await;
                    if matched_count > 0 {
                        tracing::info!(
                            matched = matched_count,
                            event_path = %event_path.display(),
                            "recorded packet-flow lazy-connect activity from eBPF JSONL events"
                        );
                    }
                }
                Err(error) => tracing::warn!(
                    %error,
                    event_path = %event_path.display(),
                    "failed to read eBPF packet-flow event file; will retry"
                ),
            }
            tokio::time::sleep(interval).await;
        }
    })
}

fn start_ebpf_ringbuf_packet_flow_detector(
    runtime: Arc<AgentRuntime>,
    config: EbpfRingbufConfig,
    limits: EbpfRingbufReadLimits,
    retry_interval: Duration,
    dedup_ttl: Option<Duration>,
    pin: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match run_ebpf_ringbuf_packet_flow_detector_once(
                runtime.as_ref(),
                &config,
                limits,
                dedup_ttl,
                pin,
            )
            .await
            {
                Ok(()) => tracing::warn!("eBPF packet-flow ring buffer detector stopped"),
                Err(error) => tracing::warn!(
                    %error,
                    object_path = %config.object_path.display(),
                    ringbuf_map = %config.ringbuf_map,
                    "eBPF packet-flow ring buffer detector failed; will retry"
                ),
            }
            tokio::time::sleep(retry_interval).await;
        }
    })
}

async fn run_ebpf_ringbuf_packet_flow_detector_once(
    runtime: &AgentRuntime,
    config: &EbpfRingbufConfig,
    limits: EbpfRingbufReadLimits,
    dedup_ttl: Option<Duration>,
    pin: bool,
) -> anyhow::Result<()> {
    let mut reader = load_ebpf_ringbuf_packet_flow_reader(config)?;
    let mut deduper = PacketFlowDeduper::new(dedup_ttl);
    loop {
        let mut guard = reader.ringbuf.readable_mut().await.with_context(|| {
            format!(
                "failed to wait for eBPF packet-flow ring buffer `{}`",
                config.ringbuf_map
            )
        })?;
        let flows = drain_ebpf_ringbuf_packet_flows(guard.get_inner_mut(), limits)?;
        guard.clear_ready();
        let (flows, duplicate_count) = deduper.retain_new(flows);
        record_packet_flow_duplicate_suppressions(
            runtime,
            duplicate_count,
            AgentPacketFlowDuplicateSource::EbpfRingbuf,
        );
        let matched_count =
            record_packet_flow_observations(runtime, flows, pin, "ebpf-ringbuf").await;
        if matched_count > 0 {
            tracing::info!(
                matched = matched_count,
                object_path = %config.object_path.display(),
                ringbuf_map = %config.ringbuf_map,
                "recorded packet-flow lazy-connect activity from eBPF ring buffer events"
            );
        }
    }
}

struct EbpfRingbufPacketFlowReader {
    _bpf: Ebpf,
    ringbuf: AsyncFd<RingBuf<MapData>>,
}

fn load_ebpf_ringbuf_packet_flow_reader(
    config: &EbpfRingbufConfig,
) -> anyhow::Result<EbpfRingbufPacketFlowReader> {
    let mut bpf = EbpfLoader::new()
        .load_file(&config.object_path)
        .with_context(|| {
            format!(
                "failed to load eBPF packet-flow object {}",
                config.object_path.display()
            )
        })?;
    for attachment in &config.attachments {
        let program: &mut TracePoint = bpf
            .program_mut(&attachment.program)
            .with_context(|| {
                format!(
                    "eBPF packet-flow object {} does not contain tracepoint program `{}`",
                    config.object_path.display(),
                    attachment.program
                )
            })?
            .try_into()
            .with_context(|| {
                format!(
                    "eBPF program `{}` is not a tracepoint program",
                    attachment.program
                )
            })?;
        program.load().with_context(|| {
            format!(
                "failed to load eBPF tracepoint program `{}`",
                attachment.program
            )
        })?;
        program
            .attach(&attachment.category, &attachment.name)
            .with_context(|| {
                format!(
                    "failed to attach eBPF program `{}` to tracepoint `{}/{}`",
                    attachment.program, attachment.category, attachment.name
                )
            })?;
    }

    let map = bpf.take_map(&config.ringbuf_map).with_context(|| {
        format!(
            "eBPF packet-flow object {} does not contain ring buffer map `{}`",
            config.object_path.display(),
            config.ringbuf_map
        )
    })?;
    let ringbuf = RingBuf::try_from(map)
        .with_context(|| format!("eBPF map `{}` is not a ring buffer", config.ringbuf_map))?;
    let ringbuf = AsyncFd::new(ringbuf).with_context(|| {
        format!(
            "failed to register eBPF packet-flow ring buffer `{}` with tokio",
            config.ringbuf_map
        )
    })?;

    Ok(EbpfRingbufPacketFlowReader { _bpf: bpf, ringbuf })
}

fn packet_flow_dedup_ttl(seconds: u64) -> Option<Duration> {
    (seconds > 0).then(|| Duration::from_secs(seconds))
}

fn record_packet_flow_duplicate_suppressions(
    runtime: &AgentRuntime,
    duplicate_count: usize,
    source: AgentPacketFlowDuplicateSource,
) {
    if duplicate_count > 0 {
        runtime.record_packet_flow_duplicate_suppression(source, duplicate_count as u64);
        tracing::debug!(
            suppressed = duplicate_count,
            source = source.as_str(),
            "suppressed duplicate packet-flow observations"
        );
    }
}

#[derive(Debug)]
struct PacketFlowDeduper {
    ttl: Option<Duration>,
    max_entries: usize,
    seen: BTreeMap<PacketFlowFingerprint, Instant>,
}

impl PacketFlowDeduper {
    fn new(ttl: Option<Duration>) -> Self {
        Self {
            ttl,
            max_entries: MAX_PACKET_FLOW_DEDUP_FINGERPRINTS,
            seen: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    fn with_max_entries(ttl: Option<Duration>, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries,
            seen: BTreeMap::new(),
        }
    }

    fn retain_new(&mut self, flows: Vec<PacketFlowRecord>) -> (Vec<PacketFlowRecord>, usize) {
        let Some(ttl) = self.ttl else {
            return (flows, 0);
        };
        let now = Instant::now();
        self.seen
            .retain(|_, last_seen| now.saturating_duration_since(*last_seen) < ttl);

        let mut retained = Vec::with_capacity(flows.len());
        let mut duplicate_count = 0_usize;
        for flow in flows {
            let fingerprint = PacketFlowFingerprint::from(&flow);
            if self.seen.contains_key(&fingerprint) {
                duplicate_count += 1;
                continue;
            }
            self.seen.insert(fingerprint, now);
            retained.push(flow);
        }
        self.prune_to_max_entries();
        (retained, duplicate_count)
    }

    fn prune_to_max_entries(&mut self) {
        let excess = self.seen.len().saturating_sub(self.max_entries);
        if excess == 0 {
            return;
        }

        let mut oldest = self
            .seen
            .iter()
            .map(|(fingerprint, last_seen)| (fingerprint.clone(), *last_seen))
            .collect::<Vec<_>>();
        oldest.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
        for (fingerprint, _) in oldest.into_iter().take(excess) {
            self.seen.remove(&fingerprint);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PacketFlowFingerprint {
    destination: IpAddr,
    source: Option<IpAddr>,
    protocol: Option<u8>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    application: AgentPacketFlowApplication,
    conntrack_status: Vec<AgentPacketFlowConntrackStatus>,
    tcp_state: Option<AgentPacketFlowTcpState>,
}

impl From<&PacketFlowRecord> for PacketFlowFingerprint {
    fn from(flow: &PacketFlowRecord) -> Self {
        Self {
            destination: flow.destination,
            source: flow.observation.source,
            protocol: flow.observation.protocol.map(transport_protocol_number),
            source_port: flow.observation.source_port,
            destination_port: flow.observation.destination_port,
            application: flow.observation.application(),
            conntrack_status: flow.observation.conntrack_status.clone(),
            tcp_state: flow.observation.tcp_state,
        }
    }
}

fn transport_protocol_number(protocol: TransportProtocol) -> u8 {
    match protocol {
        TransportProtocol::Any => 0,
        TransportProtocol::IpInIp => 4,
        TransportProtocol::Icmp => 1,
        TransportProtocol::Tcp => 6,
        TransportProtocol::Udp => 17,
        TransportProtocol::Sctp => 132,
        TransportProtocol::Ipv6Encap => 41,
        TransportProtocol::Gre => 47,
        TransportProtocol::Esp => 50,
        TransportProtocol::Ah => 51,
    }
}

async fn run_conntrack_netlink_event_detector_once(
    runtime: &AgentRuntime,
    socket: &Socket,
    idle_poll_interval: Duration,
    deduper: &mut PacketFlowDeduper,
    limits: ConntrackNetlinkReadLimits,
    pin: bool,
) -> anyhow::Result<()> {
    let mut buffer = vec![0_u8; CONNTRACK_NETLINK_RECV_BUFFER_BYTES];
    loop {
        let mut recorded_any = false;
        while let Some(flows) =
            read_conntrack_netlink_event_packet_flows(socket, &mut buffer, limits)?
        {
            recorded_any = true;
            let (flows, duplicate_count) = deduper.retain_new(flows);
            record_packet_flow_duplicate_suppressions(
                runtime,
                duplicate_count,
                AgentPacketFlowDuplicateSource::ConntrackNetlinkEvents,
            );
            let matched_count =
                record_packet_flow_observations(runtime, flows, pin, "conntrack-netlink-events")
                    .await;
            if matched_count > 0 {
                tracing::info!(
                    matched = matched_count,
                    "recorded packet-flow lazy-connect activity from conntrack netlink events"
                );
            }
        }
        if !recorded_any {
            tokio::time::sleep(idle_poll_interval).await;
        }
    }
}

async fn record_packet_flow_observations(
    runtime: &AgentRuntime,
    flows: Vec<PacketFlowRecord>,
    pin: bool,
    source: &'static str,
) -> usize {
    let now = chrono::Utc::now();
    let mut matched_count = 0_usize;
    for flow in flows {
        if let Some(reason) = packet_flow_destination_drop_reason(flow.destination) {
            runtime.record_packet_flow_filtered(reason);
            tracing::debug!(
                destination = %flow.destination,
                reason = reason.as_str(),
                source,
                "ignored packet-flow observation before lazy-connect resolution"
            );
            continue;
        }
        let mut observation = flow.observation;
        if observation.detector.is_none() {
            observation.detector = Some(source.to_string());
        }
        if let Some(matched) = runtime
            .record_packet_flow_observation(flow.destination, observation.clone(), now, pin)
            .await
        {
            matched_count += 1;
            tracing::debug!(
                destination = %flow.destination,
                source_addr = ?observation.source,
                protocol = ?observation.protocol,
                source_port = ?observation.source_port,
                destination_port = ?observation.destination_port,
                conntrack_status = ?observation.conntrack_status,
                tcp_state = ?observation.tcp_state,
                peer = %matched.peer,
                kind = ?matched.kind,
                route = ?matched.route,
                pinned = matched.pinned,
                source,
                "recorded packet-flow lazy-connect activity"
            );
        }
    }
    matched_count
}

fn conntrack_paths(custom_path: Option<PathBuf>) -> Vec<PathBuf> {
    custom_path.map_or_else(
        || {
            vec![
                PathBuf::from("/proc/net/nf_conntrack"),
                PathBuf::from("/proc/net/ip_conntrack"),
            ]
        },
        |path| vec![path],
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcNetConntrackReadLimits {
    max_bytes: u64,
    max_line_bytes: usize,
    max_flows: usize,
}

impl ProcNetConntrackReadLimits {
    fn from_args(args: &AgentArgs) -> anyhow::Result<Self> {
        validate_bounded_u64(
            args.packet_flow_procfs_max_bytes,
            "--packet-flow-procfs-max-bytes",
            MAX_PACKET_FLOW_READ_BYTES,
        )?;
        validate_bounded_usize(
            args.packet_flow_procfs_max_line_bytes,
            "--packet-flow-procfs-max-line-bytes",
            MAX_PACKET_FLOW_LINE_BYTES,
        )?;
        validate_bounded_usize(
            args.packet_flow_procfs_max_flows,
            "--packet-flow-procfs-max-flows",
            MAX_PACKET_FLOW_RECORDS,
        )?;
        Ok(Self {
            max_bytes: args.packet_flow_procfs_max_bytes,
            max_line_bytes: args.packet_flow_procfs_max_line_bytes,
            max_flows: args.packet_flow_procfs_max_flows,
        })
    }
}

impl Default for ProcNetConntrackReadLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_PACKET_FLOW_PROCFS_MAX_BYTES,
            max_line_bytes: DEFAULT_PACKET_FLOW_PROCFS_MAX_LINE_BYTES,
            max_flows: DEFAULT_PACKET_FLOW_PROCFS_MAX_FLOWS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConntrackNetlinkReadLimits {
    max_flows: usize,
}

impl ConntrackNetlinkReadLimits {
    fn from_args(args: &AgentArgs) -> anyhow::Result<Self> {
        validate_bounded_usize(
            args.packet_flow_netlink_max_flows,
            "--packet-flow-netlink-max-flows",
            MAX_PACKET_FLOW_RECORDS,
        )?;
        Ok(Self {
            max_flows: args.packet_flow_netlink_max_flows,
        })
    }
}

impl Default for ConntrackNetlinkReadLimits {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_PACKET_FLOW_NETLINK_MAX_FLOWS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EbpfJsonlReadLimits {
    max_bytes: u64,
    max_line_bytes: usize,
    max_flows: usize,
}

impl EbpfJsonlReadLimits {
    fn from_args(args: &AgentArgs) -> anyhow::Result<Self> {
        validate_bounded_u64(
            args.packet_flow_ebpf_event_max_bytes,
            "--packet-flow-ebpf-event-max-bytes",
            MAX_PACKET_FLOW_READ_BYTES,
        )?;
        validate_bounded_usize(
            args.packet_flow_ebpf_event_max_line_bytes,
            "--packet-flow-ebpf-event-max-line-bytes",
            MAX_PACKET_FLOW_LINE_BYTES,
        )?;
        validate_bounded_usize(
            args.packet_flow_ebpf_event_max_flows,
            "--packet-flow-ebpf-event-max-flows",
            MAX_PACKET_FLOW_RECORDS,
        )?;
        Ok(Self {
            max_bytes: args.packet_flow_ebpf_event_max_bytes,
            max_line_bytes: args.packet_flow_ebpf_event_max_line_bytes,
            max_flows: args.packet_flow_ebpf_event_max_flows,
        })
    }
}

impl Default for EbpfJsonlReadLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_PACKET_FLOW_EBPF_EVENT_MAX_BYTES,
            max_line_bytes: DEFAULT_PACKET_FLOW_EBPF_EVENT_MAX_LINE_BYTES,
            max_flows: DEFAULT_PACKET_FLOW_EBPF_EVENT_MAX_FLOWS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EbpfRingbufConfig {
    object_path: PathBuf,
    ringbuf_map: String,
    attachments: Vec<EbpfTracepointAttachSpec>,
}

impl EbpfRingbufConfig {
    fn from_args(args: &AgentArgs) -> anyhow::Result<Self> {
        let object_path = args
            .packet_flow_ebpf_object_path
            .clone()
            .context("--packet-flow-ebpf-object-path is required")?;
        validate_ebpf_identifier(
            &args.packet_flow_ebpf_ringbuf_map,
            "--packet-flow-ebpf-ringbuf-map",
        )?;
        anyhow::ensure!(
            !args.packet_flow_ebpf_attach.is_empty(),
            "--packet-flow-ebpf-attach must be set at least once when --packet-flow-detector ebpf-ringbuf is set"
        );
        let attachments = parse_packet_flow_ebpf_attach_specs(&args.packet_flow_ebpf_attach)?;
        Ok(Self {
            object_path,
            ringbuf_map: args.packet_flow_ebpf_ringbuf_map.clone(),
            attachments,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EbpfTracepointAttachSpec {
    program: String,
    category: String,
    name: String,
}

impl EbpfTracepointAttachSpec {
    fn parse(value: &str) -> anyhow::Result<Self> {
        let mut parts = value.split(':');
        let program = parts.next().unwrap_or_default();
        let category = parts.next().unwrap_or_default();
        let name = parts.next().unwrap_or_default();
        if parts.next().is_some() || program.is_empty() || category.is_empty() || name.is_empty() {
            anyhow::bail!(
                "--packet-flow-ebpf-attach must use PROGRAM:CATEGORY:NAME format, got `{value}`"
            );
        }
        validate_ebpf_identifier(program, "--packet-flow-ebpf-attach program")?;
        validate_ebpf_identifier(category, "--packet-flow-ebpf-attach category")?;
        validate_ebpf_identifier(name, "--packet-flow-ebpf-attach name")?;
        Ok(Self {
            program: program.to_string(),
            category: category.to_string(),
            name: name.to_string(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EbpfRingbufReadLimits {
    max_events_per_wake: usize,
}

impl EbpfRingbufReadLimits {
    fn from_args(args: &AgentArgs) -> anyhow::Result<Self> {
        validate_bounded_usize(
            args.packet_flow_ebpf_ringbuf_max_events,
            "--packet-flow-ebpf-ringbuf-max-events",
            MAX_PACKET_FLOW_EBPF_RINGBUF_EVENTS_PER_WAKE,
        )?;
        Ok(Self {
            max_events_per_wake: args.packet_flow_ebpf_ringbuf_max_events,
        })
    }
}

impl Default for EbpfRingbufReadLimits {
    fn default() -> Self {
        Self {
            max_events_per_wake: DEFAULT_PACKET_FLOW_EBPF_RINGBUF_MAX_EVENTS,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct EbpfJsonlReadCursor {
    offset: u64,
    partial_line: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PacketFlowRecord {
    destination: IpAddr,
    observation: AgentPacketFlowObservation,
}

fn drain_ebpf_ringbuf_packet_flows(
    ringbuf: &mut RingBuf<MapData>,
    limits: EbpfRingbufReadLimits,
) -> anyhow::Result<Vec<PacketFlowRecord>> {
    let mut flows = Vec::new();
    while flows.len() < limits.max_events_per_wake {
        let Some(item) = ringbuf.next() else {
            break;
        };
        flows.push(parse_ebpf_ringbuf_packet_flow_event(&item)?);
    }
    Ok(flows)
}

fn parse_ebpf_ringbuf_packet_flow_event(bytes: &[u8]) -> anyhow::Result<PacketFlowRecord> {
    let event = PacketFlowEvent::from_bytes(bytes).map_err(|error| anyhow::anyhow!(error))?;
    anyhow::ensure!(
        event.version == PACKET_FLOW_EVENT_VERSION,
        "unsupported eBPF packet-flow event version {}",
        event.version
    );
    validate_ebpf_packet_flow_unused_fields(&event)?;
    let protocol = ebpf_packet_flow_protocol(event.protocol)?;
    let tcp_state = ebpf_packet_flow_tcp_state(event.tcp_state)?;
    validate_ebpf_packet_flow_transport_metadata(&event)?;
    let conntrack_status = ebpf_packet_flow_conntrack_status(event.conntrack_status)?;
    let source_port = optional_nonzero_port(event.source_port());
    let destination_port = optional_nonzero_port(event.destination_port());
    let source = optional_ebpf_packet_flow_source(event.ip_family, &event.source)?;
    let destination = ebpf_packet_flow_ip(event.ip_family, "destination", &event.destination)?;
    Ok(PacketFlowRecord {
        destination,
        observation: AgentPacketFlowObservation {
            source,
            protocol,
            source_port,
            destination_port,
            detector: Some("ebpf-ringbuf".to_string()),
            application: None,
            payload_prefix: Vec::new(),
            conntrack_status,
            tcp_state,
        },
    })
}

fn validate_ebpf_packet_flow_unused_fields(event: &PacketFlowEvent) -> anyhow::Result<()> {
    anyhow::ensure!(
        event.flags == 0,
        "unsupported eBPF packet-flow event flags 0x{:02x}",
        event.flags
    );
    anyhow::ensure!(
        event.reserved.iter().all(|byte| *byte == 0),
        "unsupported eBPF packet-flow reserved bytes"
    );
    Ok(())
}

fn ebpf_packet_flow_protocol(value: u8) -> anyhow::Result<Option<TransportProtocol>> {
    let protocol = match value {
        PACKET_FLOW_PROTOCOL_UNKNOWN => None,
        PACKET_FLOW_PROTOCOL_ICMP | PACKET_FLOW_PROTOCOL_ICMPV6 => Some(TransportProtocol::Icmp),
        PACKET_FLOW_PROTOCOL_IPIP => Some(TransportProtocol::IpInIp),
        PACKET_FLOW_PROTOCOL_TCP => Some(TransportProtocol::Tcp),
        PACKET_FLOW_PROTOCOL_UDP => Some(TransportProtocol::Udp),
        PACKET_FLOW_PROTOCOL_IPV6_ENCAP => Some(TransportProtocol::Ipv6Encap),
        PACKET_FLOW_PROTOCOL_SCTP => Some(TransportProtocol::Sctp),
        PACKET_FLOW_PROTOCOL_GRE => Some(TransportProtocol::Gre),
        PACKET_FLOW_PROTOCOL_ESP => Some(TransportProtocol::Esp),
        PACKET_FLOW_PROTOCOL_AH => Some(TransportProtocol::Ah),
        _ => anyhow::bail!("unsupported eBPF packet-flow protocol code {value}"),
    };
    Ok(protocol)
}

fn ebpf_packet_flow_tcp_state(value: u8) -> anyhow::Result<Option<AgentPacketFlowTcpState>> {
    let state = match value {
        PACKET_FLOW_TCP_STATE_UNKNOWN => None,
        PACKET_FLOW_TCP_STATE_SYN_SENT => Some(AgentPacketFlowTcpState::SynSent),
        PACKET_FLOW_TCP_STATE_SYN_RECV => Some(AgentPacketFlowTcpState::SynRecv),
        PACKET_FLOW_TCP_STATE_ESTABLISHED => Some(AgentPacketFlowTcpState::Established),
        PACKET_FLOW_TCP_STATE_FIN_WAIT => Some(AgentPacketFlowTcpState::FinWait),
        PACKET_FLOW_TCP_STATE_TIME_WAIT => Some(AgentPacketFlowTcpState::TimeWait),
        PACKET_FLOW_TCP_STATE_CLOSE => Some(AgentPacketFlowTcpState::Close),
        PACKET_FLOW_TCP_STATE_CLOSE_WAIT => Some(AgentPacketFlowTcpState::CloseWait),
        PACKET_FLOW_TCP_STATE_LAST_ACK => Some(AgentPacketFlowTcpState::LastAck),
        PACKET_FLOW_TCP_STATE_LISTEN => Some(AgentPacketFlowTcpState::Listen),
        PACKET_FLOW_TCP_STATE_SYN_SENT2 => Some(AgentPacketFlowTcpState::SynSent2),
        _ => anyhow::bail!("unsupported eBPF packet-flow TCP state code {value}"),
    };
    Ok(state)
}

fn validate_ebpf_packet_flow_transport_metadata(event: &PacketFlowEvent) -> anyhow::Result<()> {
    anyhow::ensure!(
        event.protocol == PACKET_FLOW_PROTOCOL_TCP
            || event.tcp_state == PACKET_FLOW_TCP_STATE_UNKNOWN,
        "unsupported eBPF packet-flow TCP state {} for non-TCP protocol code {}",
        event.tcp_state,
        event.protocol
    );
    let protocol_has_ports = matches!(
        event.protocol,
        PACKET_FLOW_PROTOCOL_TCP | PACKET_FLOW_PROTOCOL_UDP | PACKET_FLOW_PROTOCOL_SCTP
    );
    anyhow::ensure!(
        protocol_has_ports || (event.source_port() == 0 && event.destination_port() == 0),
        "unsupported eBPF packet-flow port metadata for protocol code {}",
        event.protocol
    );
    Ok(())
}

fn ebpf_packet_flow_conntrack_status(
    value: u8,
) -> anyhow::Result<Vec<AgentPacketFlowConntrackStatus>> {
    let known_bits = PACKET_FLOW_CONNTRACK_UNREPLIED | PACKET_FLOW_CONNTRACK_ASSURED;
    let unsupported_bits = value & !known_bits;
    anyhow::ensure!(
        unsupported_bits == 0,
        "unsupported eBPF packet-flow conntrack status bits 0x{:02x}",
        unsupported_bits
    );
    let mut status = Vec::new();
    if value & PACKET_FLOW_CONNTRACK_UNREPLIED != 0 {
        status.push(AgentPacketFlowConntrackStatus::Unreplied);
    }
    if value & PACKET_FLOW_CONNTRACK_ASSURED != 0 {
        status.push(AgentPacketFlowConntrackStatus::Assured);
    }
    Ok(status)
}

fn optional_nonzero_port(value: u16) -> Option<u16> {
    (value != 0).then_some(value)
}

fn ebpf_packet_flow_ip(ip_family: u8, field: &str, bytes: &[u8]) -> anyhow::Result<IpAddr> {
    let octets: [u8; 16] = bytes
        .try_into()
        .with_context(|| format!("eBPF packet-flow {field} IP field had invalid length"))?;
    match ip_family {
        PACKET_FLOW_IP_FAMILY_IPV4 => {
            anyhow::ensure!(
                octets[4..].iter().all(|byte| *byte == 0),
                "unsupported eBPF packet-flow IPv4 {field} padding bytes"
            );
            Ok(IpAddr::V4(Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )))
        }
        PACKET_FLOW_IP_FAMILY_IPV6 => Ok(IpAddr::V6(Ipv6Addr::from(octets))),
        _ => anyhow::bail!("unsupported eBPF packet-flow IP family {ip_family}"),
    }
}

fn optional_ebpf_packet_flow_source(ip_family: u8, bytes: &[u8]) -> anyhow::Result<Option<IpAddr>> {
    let source = ebpf_packet_flow_ip(ip_family, "source", bytes)?;
    Ok((!source.is_unspecified()).then_some(source))
}

async fn read_conntrack_netlink_packet_flows(
    limits: ConntrackNetlinkReadLimits,
) -> anyhow::Result<Vec<PacketFlowRecord>> {
    tokio::task::spawn_blocking(move || dump_conntrack_netlink_packet_flows(limits))
        .await
        .context("conntrack netlink reader task failed")?
}

fn dump_conntrack_netlink_packet_flows(
    limits: ConntrackNetlinkReadLimits,
) -> anyhow::Result<Vec<PacketFlowRecord>> {
    let mut socket =
        Socket::new(NETLINK_NETFILTER).context("failed to open NETLINK_NETFILTER socket")?;
    socket
        .bind_auto()
        .context("failed to bind NETLINK_NETFILTER socket")?;
    socket
        .connect(&NetlinkSocketAddr::new(0, 0))
        .context("failed to connect NETLINK_NETFILTER socket to kernel")?;

    let request = conntrack_netlink_dump_request(1);
    let sent = socket
        .send(&request, 0)
        .context("failed to send conntrack netlink dump request")?;
    anyhow::ensure!(
        sent == request.len(),
        "short conntrack netlink dump request write: sent {sent} of {} bytes",
        request.len()
    );

    let mut flows = Vec::new();
    let mut buffer = vec![0_u8; CONNTRACK_NETLINK_RECV_BUFFER_BYTES];
    loop {
        let received = socket
            .recv(&mut &mut buffer[..], 0)
            .context("failed to receive conntrack netlink dump response")?;
        let remaining_capacity = limits.max_flows.saturating_sub(flows.len());
        if remaining_capacity == 0 {
            return Ok(flows);
        }
        let result =
            parse_conntrack_netlink_datagram_packet_flows(&buffer[..received], remaining_capacity)?;
        flows.extend(result.flows);
        if result.truncated || flows.len() >= limits.max_flows {
            return Ok(flows);
        }
        if result.done {
            return Ok(flows);
        }
    }
}

fn open_conntrack_netlink_event_socket() -> anyhow::Result<Socket> {
    let mut socket =
        Socket::new(NETLINK_NETFILTER).context("failed to open NETLINK_NETFILTER socket")?;
    socket
        .bind(&NetlinkSocketAddr::new(
            0,
            conntrack_netlink_event_group_mask(),
        ))
        .context("failed to bind NETLINK_NETFILTER socket to conntrack event groups")?;
    socket
        .set_non_blocking(true)
        .context("failed to set NETLINK_NETFILTER event socket nonblocking")?;
    Ok(socket)
}

fn read_conntrack_netlink_event_packet_flows(
    socket: &Socket,
    buffer: &mut [u8],
    limits: ConntrackNetlinkReadLimits,
) -> anyhow::Result<Option<Vec<PacketFlowRecord>>> {
    match socket.recv(&mut &mut buffer[..], 0) {
        Ok(received) => {
            let datagram = parse_conntrack_netlink_datagram_packet_flows(
                &buffer[..received],
                limits.max_flows,
            )?;
            Ok(Some(datagram.flows))
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error).context("failed to receive conntrack netlink event"),
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ConntrackNetlinkDatagram {
    flows: Vec<PacketFlowRecord>,
    done: bool,
    truncated: bool,
}

const CONNTRACK_NETLINK_RECV_BUFFER_BYTES: usize = 256 * 1024;
const NLMSG_HDR_LEN: usize = 16;
const NLA_HDR_LEN: usize = 4;
const NFGENMSG_LEN: usize = 4;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const NFNLGRP_CONNTRACK_NEW: u32 = 1;
const NFNLGRP_CONNTRACK_UPDATE: u32 = 2;
const IPCTNL_MSG_CT_GET: u16 = 1;
const NFNETLINK_V0: u8 = 0;
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_STATUS: u16 = 3;
const CTA_PROTOINFO: u16 = 4;
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
const CTA_PROTOINFO_TCP: u16 = 1;
const CTA_PROTOINFO_TCP_STATE: u16 = 1;
const NLA_TYPE_MASK: u16 = 0x3fff;
const IPS_SEEN_REPLY: u32 = 1 << 1;
const IPS_ASSURED: u32 = 1 << 2;
const TCP_CONNTRACK_NONE: u8 = 0;
const TCP_CONNTRACK_SYN_SENT: u8 = 1;
const TCP_CONNTRACK_SYN_RECV: u8 = 2;
const TCP_CONNTRACK_ESTABLISHED: u8 = 3;
const TCP_CONNTRACK_FIN_WAIT: u8 = 4;
const TCP_CONNTRACK_CLOSE_WAIT: u8 = 5;
const TCP_CONNTRACK_LAST_ACK: u8 = 6;
const TCP_CONNTRACK_TIME_WAIT: u8 = 7;
const TCP_CONNTRACK_CLOSE: u8 = 8;
const TCP_CONNTRACK_LISTEN: u8 = 9;
const TCP_CONNTRACK_SYN_SENT2: u8 = 10;

fn conntrack_netlink_event_group_mask() -> u32 {
    netlink_group_mask(NFNLGRP_CONNTRACK_NEW) | netlink_group_mask(NFNLGRP_CONNTRACK_UPDATE)
}

fn netlink_group_mask(group: u32) -> u32 {
    if group == 0 || group > 32 {
        0
    } else {
        1_u32 << (group - 1)
    }
}

fn conntrack_netlink_dump_request(sequence_number: u32) -> Vec<u8> {
    let mut request = Vec::with_capacity(NLMSG_HDR_LEN + NFGENMSG_LEN);
    push_u32_ne(&mut request, (NLMSG_HDR_LEN + NFGENMSG_LEN) as u32);
    push_u16_ne(&mut request, ctnetlink_message_type(IPCTNL_MSG_CT_GET));
    push_u16_ne(&mut request, NLM_F_REQUEST | NLM_F_DUMP);
    push_u32_ne(&mut request, sequence_number);
    push_u32_ne(&mut request, 0);
    request.push(0);
    request.push(NFNETLINK_V0);
    push_u16_be(&mut request, 0);
    request
}

fn parse_conntrack_netlink_datagram_packet_flows(
    datagram: &[u8],
    max_flows: usize,
) -> anyhow::Result<ConntrackNetlinkDatagram> {
    let mut result = ConntrackNetlinkDatagram::default();
    let mut offset = 0_usize;
    while offset < datagram.len() {
        if result.flows.len() >= max_flows {
            result.truncated = true;
            break;
        }
        let remaining = &datagram[offset..];
        if remaining.len() < NLMSG_HDR_LEN {
            if remaining.iter().all(|byte| *byte == 0) {
                break;
            }
            anyhow::bail!(
                "truncated conntrack netlink header: {} trailing bytes",
                remaining.len()
            );
        }

        let message_len = read_u32_ne(remaining, 0)? as usize;
        if message_len == 0 {
            if remaining.iter().all(|byte| *byte == 0) {
                break;
            }
            anyhow::bail!("conntrack netlink message has zero length");
        }
        if message_len < NLMSG_HDR_LEN {
            anyhow::bail!("conntrack netlink message is too short: {message_len} bytes");
        }
        let message_end = offset
            .checked_add(message_len)
            .context("conntrack netlink message length overflow")?;
        if message_end > datagram.len() {
            anyhow::bail!(
                "conntrack netlink message length {message_len} exceeds datagram remainder {}",
                remaining.len()
            );
        }

        let message_type = read_u16_ne(remaining, 4)?;
        let payload = &datagram[offset + NLMSG_HDR_LEN..message_end];
        match message_type {
            NLMSG_DONE => result.done = true,
            NLMSG_ERROR => handle_netlink_error(payload)?,
            message_type if ctnetlink_subsystem(message_type) == NFNL_SUBSYS_CTNETLINK => {
                let remaining_capacity = max_flows.saturating_sub(result.flows.len());
                let mut flows = parse_ctnetlink_packet_flows(payload)?;
                if flows.len() > remaining_capacity {
                    flows.truncate(remaining_capacity);
                    result.truncated = true;
                }
                result.flows.extend(flows);
            }
            _ => {}
        }

        let aligned_len = align_to_4(message_len);
        let next_offset = offset
            .checked_add(aligned_len)
            .context("conntrack netlink aligned length overflow")?;
        if next_offset > datagram.len() {
            offset = message_end;
        } else {
            offset = next_offset;
        }
    }
    Ok(result)
}

fn handle_netlink_error(payload: &[u8]) -> anyhow::Result<()> {
    if payload.len() < 4 {
        anyhow::bail!("truncated conntrack netlink error payload");
    }
    let code = i32::from_ne_bytes(payload[..4].try_into()?);
    if code == 0 {
        return Ok(());
    }
    let raw_error = code.checked_neg().unwrap_or(code);
    anyhow::bail!(
        "conntrack netlink dump request failed: {}",
        std::io::Error::from_raw_os_error(raw_error)
    )
}

fn parse_ctnetlink_packet_flows(payload: &[u8]) -> anyhow::Result<Vec<PacketFlowRecord>> {
    if payload.len() < NFGENMSG_LEN {
        anyhow::bail!("truncated conntrack netlink nfgenmsg payload");
    }
    let attributes = netlink_attributes(&payload[NFGENMSG_LEN..])?;
    let mut conntrack_status = Vec::new();
    let mut tcp_state = None;
    for attribute in &attributes {
        match attribute.kind {
            CTA_STATUS => {
                conntrack_status = parse_conntrack_netlink_status(attribute.value)?;
            }
            CTA_PROTOINFO => {
                tcp_state = parse_conntrack_protoinfo_tcp_state(attribute.value)?;
            }
            _ => {}
        }
    }

    let mut flows = Vec::new();
    for attribute in attributes {
        match attribute.kind {
            CTA_TUPLE_ORIG | CTA_TUPLE_REPLY => {
                if let Some(flow) = parse_conntrack_tuple_packet_flow(
                    attribute.value,
                    &conntrack_status,
                    tcp_state,
                )? {
                    flows.push(flow);
                }
            }
            _ => {}
        }
    }
    Ok(flows)
}

fn parse_conntrack_netlink_status(
    payload: &[u8],
) -> anyhow::Result<Vec<AgentPacketFlowConntrackStatus>> {
    anyhow::ensure!(
        payload.len() == 4,
        "invalid conntrack netlink status attribute length: {}",
        payload.len()
    );
    let bits = u32::from_be_bytes(payload.try_into()?);
    let mut status = Vec::new();
    if bits & IPS_SEEN_REPLY == 0 {
        status.push(AgentPacketFlowConntrackStatus::Unreplied);
    }
    if bits & IPS_ASSURED != 0 {
        status.push(AgentPacketFlowConntrackStatus::Assured);
    }
    Ok(status)
}

fn parse_conntrack_protoinfo_tcp_state(
    payload: &[u8],
) -> anyhow::Result<Option<AgentPacketFlowTcpState>> {
    for attribute in netlink_attributes(payload)? {
        if attribute.kind != CTA_PROTOINFO_TCP {
            continue;
        }
        for tcp_attribute in netlink_attributes(attribute.value)? {
            if tcp_attribute.kind != CTA_PROTOINFO_TCP_STATE {
                continue;
            }
            anyhow::ensure!(
                tcp_attribute.value.len() == 1,
                "invalid conntrack netlink TCP state attribute length: {}",
                tcp_attribute.value.len()
            );
            return Ok(conntrack_tcp_state(tcp_attribute.value[0]));
        }
    }
    Ok(None)
}

fn conntrack_tcp_state(value: u8) -> Option<AgentPacketFlowTcpState> {
    match value {
        TCP_CONNTRACK_NONE => None,
        TCP_CONNTRACK_SYN_SENT => Some(AgentPacketFlowTcpState::SynSent),
        TCP_CONNTRACK_SYN_RECV => Some(AgentPacketFlowTcpState::SynRecv),
        TCP_CONNTRACK_ESTABLISHED => Some(AgentPacketFlowTcpState::Established),
        TCP_CONNTRACK_FIN_WAIT => Some(AgentPacketFlowTcpState::FinWait),
        TCP_CONNTRACK_CLOSE_WAIT => Some(AgentPacketFlowTcpState::CloseWait),
        TCP_CONNTRACK_LAST_ACK => Some(AgentPacketFlowTcpState::LastAck),
        TCP_CONNTRACK_TIME_WAIT => Some(AgentPacketFlowTcpState::TimeWait),
        TCP_CONNTRACK_CLOSE => Some(AgentPacketFlowTcpState::Close),
        TCP_CONNTRACK_LISTEN => Some(AgentPacketFlowTcpState::Listen),
        TCP_CONNTRACK_SYN_SENT2 => Some(AgentPacketFlowTcpState::SynSent2),
        _ => None,
    }
}

fn parse_conntrack_tuple_packet_flow(
    payload: &[u8],
    conntrack_status: &[AgentPacketFlowConntrackStatus],
    tcp_state: Option<AgentPacketFlowTcpState>,
) -> anyhow::Result<Option<PacketFlowRecord>> {
    let mut tuple = ConntrackTupleFields {
        conntrack_status: conntrack_status.to_vec(),
        tcp_state,
        ..Default::default()
    };
    for attribute in netlink_attributes(payload)? {
        match attribute.kind {
            CTA_TUPLE_IP => parse_conntrack_ip_tuple(attribute.value, &mut tuple)?,
            CTA_TUPLE_PROTO => parse_conntrack_proto_tuple(attribute.value, &mut tuple)?,
            _ => {}
        }
    }
    Ok(tuple.into_packet_flow())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ConntrackTupleFields {
    source: Option<IpAddr>,
    destination: Option<IpAddr>,
    protocol: Option<TransportProtocol>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    conntrack_status: Vec<AgentPacketFlowConntrackStatus>,
    tcp_state: Option<AgentPacketFlowTcpState>,
}

impl ConntrackTupleFields {
    fn into_packet_flow(self) -> Option<PacketFlowRecord> {
        self.destination.map(|destination| PacketFlowRecord {
            destination,
            observation: AgentPacketFlowObservation {
                source: self.source,
                protocol: self.protocol,
                source_port: self.source_port,
                destination_port: self.destination_port,
                detector: None,
                application: None,
                payload_prefix: Vec::new(),
                conntrack_status: self.conntrack_status,
                tcp_state: self.tcp_state,
            },
        })
    }
}

fn parse_conntrack_ip_tuple(
    payload: &[u8],
    tuple: &mut ConntrackTupleFields,
) -> anyhow::Result<()> {
    for attribute in netlink_attributes(payload)? {
        match attribute.kind {
            CTA_IP_V4_SRC => {
                anyhow::ensure!(
                    attribute.value.len() == 4,
                    "invalid conntrack IPv4 source attribute length: {}",
                    attribute.value.len()
                );
                tuple.source = Some(IpAddr::from(<[u8; 4]>::try_from(attribute.value)?));
            }
            CTA_IP_V4_DST => {
                anyhow::ensure!(
                    attribute.value.len() == 4,
                    "invalid conntrack IPv4 destination attribute length: {}",
                    attribute.value.len()
                );
                tuple.destination = Some(IpAddr::from(<[u8; 4]>::try_from(attribute.value)?));
            }
            CTA_IP_V6_SRC => {
                anyhow::ensure!(
                    attribute.value.len() == 16,
                    "invalid conntrack IPv6 source attribute length: {}",
                    attribute.value.len()
                );
                tuple.source = Some(IpAddr::from(<[u8; 16]>::try_from(attribute.value)?));
            }
            CTA_IP_V6_DST => {
                anyhow::ensure!(
                    attribute.value.len() == 16,
                    "invalid conntrack IPv6 destination attribute length: {}",
                    attribute.value.len()
                );
                tuple.destination = Some(IpAddr::from(<[u8; 16]>::try_from(attribute.value)?));
            }
            _ => {}
        }
    }
    Ok(())
}

fn parse_conntrack_proto_tuple(
    payload: &[u8],
    tuple: &mut ConntrackTupleFields,
) -> anyhow::Result<()> {
    for attribute in netlink_attributes(payload)? {
        match attribute.kind {
            CTA_PROTO_NUM => {
                anyhow::ensure!(
                    attribute.value.len() == 1,
                    "invalid conntrack protocol number attribute length: {}",
                    attribute.value.len()
                );
                tuple.protocol = transport_protocol_from_ip_number(attribute.value[0]);
            }
            CTA_PROTO_SRC_PORT => {
                anyhow::ensure!(
                    attribute.value.len() == 2,
                    "invalid conntrack source port attribute length: {}",
                    attribute.value.len()
                );
                tuple.source_port = Some(u16::from_be_bytes(attribute.value.try_into()?));
            }
            CTA_PROTO_DST_PORT => {
                anyhow::ensure!(
                    attribute.value.len() == 2,
                    "invalid conntrack destination port attribute length: {}",
                    attribute.value.len()
                );
                tuple.destination_port = Some(u16::from_be_bytes(attribute.value.try_into()?));
            }
            _ => {}
        }
    }
    Ok(())
}

fn transport_protocol_from_ip_number(number: u8) -> Option<TransportProtocol> {
    match number {
        1 => Some(TransportProtocol::Icmp),
        4 => Some(TransportProtocol::IpInIp),
        6 => Some(TransportProtocol::Tcp),
        17 => Some(TransportProtocol::Udp),
        41 => Some(TransportProtocol::Ipv6Encap),
        132 => Some(TransportProtocol::Sctp),
        47 => Some(TransportProtocol::Gre),
        50 => Some(TransportProtocol::Esp),
        51 => Some(TransportProtocol::Ah),
        58 => Some(TransportProtocol::Icmp),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct NetlinkAttribute<'a> {
    kind: u16,
    value: &'a [u8],
}

fn netlink_attributes(payload: &[u8]) -> anyhow::Result<Vec<NetlinkAttribute<'_>>> {
    let mut attributes = Vec::new();
    let mut offset = 0_usize;
    while offset < payload.len() {
        let remaining = &payload[offset..];
        if remaining.len() < NLA_HDR_LEN {
            if remaining.iter().all(|byte| *byte == 0) {
                break;
            }
            anyhow::bail!(
                "truncated conntrack netlink attribute header: {} trailing bytes",
                remaining.len()
            );
        }

        let attribute_len = read_u16_ne(remaining, 0)? as usize;
        if attribute_len == 0 {
            if remaining.iter().all(|byte| *byte == 0) {
                break;
            }
            anyhow::bail!("conntrack netlink attribute has zero length");
        }
        if attribute_len < NLA_HDR_LEN {
            anyhow::bail!("conntrack netlink attribute is too short: {attribute_len} bytes");
        }
        let attribute_end = offset
            .checked_add(attribute_len)
            .context("conntrack netlink attribute length overflow")?;
        if attribute_end > payload.len() {
            anyhow::bail!(
                "conntrack netlink attribute length {attribute_len} exceeds payload remainder {}",
                remaining.len()
            );
        }

        let kind = read_u16_ne(remaining, 2)? & NLA_TYPE_MASK;
        attributes.push(NetlinkAttribute {
            kind,
            value: &payload[offset + NLA_HDR_LEN..attribute_end],
        });

        let aligned_len = align_to_4(attribute_len);
        let next_offset = offset
            .checked_add(aligned_len)
            .context("conntrack netlink aligned attribute length overflow")?;
        if next_offset > payload.len() {
            offset = attribute_end;
        } else {
            offset = next_offset;
        }
    }
    Ok(attributes)
}

fn ctnetlink_message_type(message: u16) -> u16 {
    (NFNL_SUBSYS_CTNETLINK << 8) | message
}

fn ctnetlink_subsystem(message_type: u16) -> u16 {
    (message_type & 0xff00) >> 8
}

fn align_to_4(len: usize) -> usize {
    (len + 3) & !3
}

fn read_u16_ne(buffer: &[u8], offset: usize) -> anyhow::Result<u16> {
    let bytes = buffer
        .get(offset..offset + 2)
        .context("buffer too short for u16 field")?;
    Ok(u16::from_ne_bytes(bytes.try_into()?))
}

fn read_u32_ne(buffer: &[u8], offset: usize) -> anyhow::Result<u32> {
    let bytes = buffer
        .get(offset..offset + 4)
        .context("buffer too short for u32 field")?;
    Ok(u32::from_ne_bytes(bytes.try_into()?))
}

fn push_u16_ne(buffer: &mut Vec<u8>, value: u16) {
    buffer.extend_from_slice(&value.to_ne_bytes());
}

fn push_u16_be(buffer: &mut Vec<u8>, value: u16) {
    buffer.extend_from_slice(&value.to_be_bytes());
}

fn push_u32_ne(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_ne_bytes());
}

async fn read_conntrack_packet_flows(
    paths: &[PathBuf],
    limits: ProcNetConntrackReadLimits,
) -> anyhow::Result<Vec<PacketFlowRecord>> {
    let mut attempted = Vec::new();
    let mut last_error = None;
    for path in paths {
        attempted.push(path.display().to_string());
        let file = match tokio::fs::File::open(path).await {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let read_limit = limits
            .max_bytes
            .checked_add(1)
            .context("conntrack procfs read byte limit overflow")?;
        let mut contents = String::new();
        file.take(read_limit)
            .read_to_string(&mut contents)
            .await
            .with_context(|| {
                format!(
                    "failed to read conntrack flow table from {}",
                    path.display()
                )
            })?;
        anyhow::ensure!(
            contents.len() as u64 <= limits.max_bytes,
            "conntrack flow table {} exceeds configured --packet-flow-procfs-max-bytes ({})",
            path.display(),
            limits.max_bytes
        );
        return parse_conntrack_packet_flows(&contents, limits);
    }

    if let Some(error) = last_error {
        anyhow::bail!(
            "failed to read conntrack flow table from {}: {error}",
            attempted.join(", ")
        );
    }
    anyhow::bail!("no conntrack flow table found at {}", attempted.join(", "))
}

async fn read_ebpf_jsonl_packet_flows(
    path: &Path,
    cursor: &mut EbpfJsonlReadCursor,
    limits: EbpfJsonlReadLimits,
) -> anyhow::Result<Vec<PacketFlowRecord>> {
    ensure_ebpf_jsonl_event_path_ready(path)?;
    let mut file = tokio::fs::File::open(path).await.with_context(|| {
        format!(
            "failed to open eBPF packet-flow event file {}",
            path.display()
        )
    })?;
    let file_len = file
        .metadata()
        .await
        .with_context(|| {
            format!(
                "failed to stat eBPF packet-flow event file {}",
                path.display()
            )
        })?
        .len();
    if cursor.offset > file_len {
        cursor.offset = 0;
        cursor.partial_line.clear();
    }

    file.seek(SeekFrom::Start(cursor.offset))
        .await
        .with_context(|| {
            format!(
                "failed to seek eBPF packet-flow event file {}",
                path.display()
            )
        })?;
    let mut bytes = Vec::new();
    let read = file
        .take(limits.max_bytes)
        .read_to_end(&mut bytes)
        .await
        .with_context(|| {
            format!(
                "failed to read eBPF packet-flow event file {}",
                path.display()
            )
        })?;
    cursor.offset = cursor
        .offset
        .checked_add(read as u64)
        .context("eBPF packet-flow event file offset overflow")?;
    parse_ebpf_jsonl_packet_flow_bytes(&bytes, cursor, limits)
}

fn parse_ebpf_jsonl_packet_flow_bytes(
    bytes: &[u8],
    cursor: &mut EbpfJsonlReadCursor,
    limits: EbpfJsonlReadLimits,
) -> anyhow::Result<Vec<PacketFlowRecord>> {
    let mut input = std::mem::take(&mut cursor.partial_line);
    input.extend_from_slice(bytes);

    let mut flows = Vec::new();
    let mut line_start = 0_usize;
    for (index, byte) in input.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }
        if flows.len() >= limits.max_flows {
            return Ok(flows);
        }
        let line = trim_jsonl_line(&input[line_start..index]);
        if !line.is_empty() {
            flows.push(parse_ebpf_jsonl_packet_flow_line(line, limits)?);
        }
        line_start = index + 1;
    }

    if line_start < input.len() {
        let remaining = &input[line_start..];
        anyhow::ensure!(
            remaining.len() <= limits.max_line_bytes,
            "eBPF packet-flow event line exceeds configured --packet-flow-ebpf-event-max-line-bytes ({})",
            limits.max_line_bytes
        );
        cursor.partial_line.extend_from_slice(remaining);
    }

    Ok(flows)
}

fn parse_ebpf_jsonl_packet_flow_line(
    line: &[u8],
    limits: EbpfJsonlReadLimits,
) -> anyhow::Result<PacketFlowRecord> {
    anyhow::ensure!(
        line.len() <= limits.max_line_bytes,
        "eBPF packet-flow event line exceeds configured --packet-flow-ebpf-event-max-line-bytes ({})",
        limits.max_line_bytes
    );
    let event: EbpfJsonlPacketFlowEvent =
        serde_json::from_slice(line).context("failed to parse eBPF packet-flow JSON event")?;
    event
        .observation
        .validate_transport_metadata()
        .map_err(anyhow::Error::msg)
        .context("invalid eBPF packet-flow JSON event metadata")?;
    Ok(PacketFlowRecord {
        destination: event.destination,
        observation: event.observation,
    })
}

fn trim_jsonl_line(mut line: &[u8]) -> &[u8] {
    while matches!(line.first(), Some(b' ' | b'\t' | b'\r')) {
        line = &line[1..];
    }
    while matches!(line.last(), Some(b' ' | b'\t' | b'\r')) {
        line = &line[..line.len() - 1];
    }
    line
}

#[derive(Debug, Deserialize)]
struct EbpfJsonlPacketFlowEvent {
    destination: IpAddr,
    #[serde(default, flatten)]
    observation: AgentPacketFlowObservation,
}

fn parse_conntrack_packet_flows(
    contents: &str,
    limits: ProcNetConntrackReadLimits,
) -> anyhow::Result<Vec<PacketFlowRecord>> {
    let mut flows = Vec::new();
    for (line_index, line) in contents.lines().enumerate() {
        anyhow::ensure!(
            line.len() <= limits.max_line_bytes,
            "conntrack flow table line {} exceeds configured --packet-flow-procfs-max-line-bytes ({})",
            line_index + 1,
            limits.max_line_bytes
        );
        flows.extend(parse_conntrack_line_packet_flows(line));
        if flows.len() >= limits.max_flows {
            flows.truncate(limits.max_flows);
            break;
        }
    }
    Ok(flows)
}

fn parse_conntrack_line_packet_flows(line: &str) -> Vec<PacketFlowRecord> {
    let protocol = line
        .split_whitespace()
        .find_map(transport_protocol_from_conntrack_token);
    let conntrack_status = line
        .split_whitespace()
        .filter_map(conntrack_status_from_conntrack_token)
        .collect::<Vec<_>>();
    let tcp_state = line
        .split_whitespace()
        .find_map(tcp_state_from_conntrack_token);
    let mut flows = Vec::new();
    let mut tuple = ConntrackTupleFields {
        protocol,
        conntrack_status: conntrack_status.clone(),
        tcp_state,
        ..ConntrackTupleFields::default()
    };

    for field in line.split_whitespace() {
        if let Some(value) = field.strip_prefix("src=") {
            if tuple.source.is_some() || tuple.destination.is_some() {
                if let Some(flow) = tuple.into_packet_flow() {
                    flows.push(flow);
                }
                tuple = ConntrackTupleFields {
                    protocol,
                    conntrack_status: conntrack_status.clone(),
                    tcp_state,
                    ..ConntrackTupleFields::default()
                };
            }
            tuple.source = value.parse::<IpAddr>().ok();
        } else if let Some(value) = field.strip_prefix("dst=") {
            tuple.destination = value.parse::<IpAddr>().ok();
        } else if let Some(value) = field.strip_prefix("sport=") {
            tuple.source_port = value.parse::<u16>().ok();
        } else if let Some(value) = field.strip_prefix("dport=") {
            tuple.destination_port = value.parse::<u16>().ok();
        }
    }

    if let Some(flow) = tuple.into_packet_flow() {
        flows.push(flow);
    }
    flows
}

fn transport_protocol_from_conntrack_token(token: &str) -> Option<TransportProtocol> {
    match token {
        "ipip" | "ipencap" => Some(TransportProtocol::IpInIp),
        "tcp" => Some(TransportProtocol::Tcp),
        "udp" => Some(TransportProtocol::Udp),
        "sctp" => Some(TransportProtocol::Sctp),
        "ipv6-encap" | "ipv6_encap" => Some(TransportProtocol::Ipv6Encap),
        "icmp" | "icmpv6" | "ipv6-icmp" => Some(TransportProtocol::Icmp),
        "gre" => Some(TransportProtocol::Gre),
        "esp" => Some(TransportProtocol::Esp),
        "ah" => Some(TransportProtocol::Ah),
        _ => None,
    }
}

fn conntrack_status_from_conntrack_token(token: &str) -> Option<AgentPacketFlowConntrackStatus> {
    match token {
        "[UNREPLIED]" => Some(AgentPacketFlowConntrackStatus::Unreplied),
        "[ASSURED]" => Some(AgentPacketFlowConntrackStatus::Assured),
        _ => None,
    }
}

fn tcp_state_from_conntrack_token(token: &str) -> Option<AgentPacketFlowTcpState> {
    match token {
        "SYN_SENT" => Some(AgentPacketFlowTcpState::SynSent),
        "SYN_RECV" => Some(AgentPacketFlowTcpState::SynRecv),
        "ESTABLISHED" => Some(AgentPacketFlowTcpState::Established),
        "FIN_WAIT" => Some(AgentPacketFlowTcpState::FinWait),
        "TIME_WAIT" => Some(AgentPacketFlowTcpState::TimeWait),
        "CLOSE" => Some(AgentPacketFlowTcpState::Close),
        "CLOSE_WAIT" => Some(AgentPacketFlowTcpState::CloseWait),
        "LAST_ACK" => Some(AgentPacketFlowTcpState::LastAck),
        "LISTEN" => Some(AgentPacketFlowTcpState::Listen),
        "SYN_SENT2" => Some(AgentPacketFlowTcpState::SynSent2),
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct HttpPeerMapSource {
    control_plane_urls: Vec<String>,
    client: reqwest::Client,
}

impl HttpPeerMapSource {
    fn new(control_plane_urls: Vec<String>) -> Self {
        Self {
            control_plane_urls,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl PeerMapSource for HttpPeerMapSource {
    async fn fetch_peer_map(&self, node_id: &NodeId) -> Result<PeerMap, AgentError> {
        fetch_peer_map_from_control_planes(&self.client, &self.control_plane_urls, node_id)
            .await
            .map_err(|error| AgentError::ControlPlaneClient(format!("{error:#}")))
    }
}

async fn fetch_peer_map_from_control_planes(
    client: &reqwest::Client,
    control_plane_urls: &[String],
    node_id: &NodeId,
) -> anyhow::Result<PeerMap> {
    anyhow::ensure!(
        !control_plane_urls.is_empty(),
        "control-plane URL is required for peer-map fetch"
    );
    let mut failures = Vec::new();
    for control_plane_url in control_plane_urls {
        let url = peer_map_url(control_plane_url, node_id);
        let response = match client.get(&url).send().await {
            Ok(response) => response,
            Err(error) => {
                failures.push(format!("{url}: send failed: {error}"));
                continue;
            }
        };
        let response = match response.error_for_status() {
            Ok(response) => response,
            Err(error) => {
                failures.push(format!("{url}: rejected: {error}"));
                continue;
            }
        };
        match read_bounded_agent_json_response(
            response,
            MAX_AGENT_CONTROL_PLANE_RESPONSE_BYTES,
            "control-plane peer map",
        )
        .await
        {
            Ok(peer_map) => return Ok(peer_map),
            Err(error) => failures.push(format!("{url}: decode failed: {error}")),
        }
    }
    anyhow::bail!(
        "all control-plane peer-map endpoints failed: {}",
        failures.join("; ")
    )
}

fn peer_map_url(control_plane_url: &str, node_id: &NodeId) -> String {
    format!(
        "{}/v1/peers/{}",
        control_plane_url.trim_end_matches('/'),
        node_id
    )
}

fn heartbeat_url(control_plane_url: &str) -> String {
    format!("{}/v1/heartbeat", control_plane_url.trim_end_matches('/'))
}

fn relay_status_url(relay_url: &str) -> String {
    let relay_url = relay_url.trim_end_matches('/');
    if relay_url.ends_with("/v1/status") {
        relay_url.to_string()
    } else {
        format!("{relay_url}/v1/status")
    }
}

fn signal_node_url(signal_url: &str, node_id: &NodeId) -> String {
    format!("{}/v1/nodes/{}", signal_url.trim_end_matches('/'), node_id)
}

fn signal_path_url(signal_url: &str) -> String {
    format!("{}/v1/paths/negotiate", signal_url.trim_end_matches('/'))
}

fn signal_hole_punch_url(signal_url: &str, source: &NodeId, target: &NodeId) -> String {
    format!(
        "{}/v1/hole-punch/{}/{}",
        signal_url.trim_end_matches('/'),
        source,
        target
    )
}

#[cfg(test)]
fn control_plane_join_url(
    token: &SignedJoinToken,
    override_url: Option<&str>,
) -> anyhow::Result<String> {
    Ok(control_plane_join_url_from_base(&control_plane_base_url(
        Some(token),
        override_url,
    )?))
}

fn control_plane_join_url_from_base(base_url: &str) -> String {
    format!("{}/v1/join", base_url.trim_end_matches('/'))
}

#[cfg(test)]
fn control_plane_base_url(
    token: Option<&SignedJoinToken>,
    override_url: Option<&str>,
) -> anyhow::Result<String> {
    control_plane_base_urls(token, override_url)?
        .into_iter()
        .next()
        .context("control-plane URL is required and no control-plane bootstrap exists")
}

fn agent_control_plane_base_urls(
    token: Option<&SignedJoinToken>,
    override_url: Option<&str>,
    registered_url: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    if override_url.is_some() {
        return control_plane_base_urls(token, override_url);
    }

    let mut base_urls = Vec::new();
    if let Some(registered_url) = registered_url {
        base_urls.push(normalize_base_url(registered_url));
    }
    if let Some(token) = token {
        base_urls.extend(control_plane_base_urls(Some(token), None)?);
    }
    Ok(dedupe_urls_preserve_order(base_urls))
}

fn control_plane_base_urls(
    token: Option<&SignedJoinToken>,
    override_url: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let (base_urls, name) = if let Some(url) = override_url {
        (vec![url.to_string()], "control-plane URL")
    } else if let Some(token) = token {
        (
            token
                .claims
                .bootstrap_endpoints
                .iter()
                .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
                .map(|endpoint| endpoint.url.clone())
                .collect::<Vec<_>>(),
            "control-plane bootstrap endpoint",
        )
    } else {
        anyhow::bail!("control-plane URL is required and no control-plane bootstrap exists");
    };
    let base_urls = normalize_http_base_urls(base_urls, name)?;
    if base_urls.is_empty() {
        anyhow::bail!("control-plane URL is required and no control-plane bootstrap exists");
    }
    Ok(base_urls)
}

fn normalize_http_base_urls(
    base_urls: impl IntoIterator<Item = String>,
    name: &str,
) -> anyhow::Result<Vec<String>> {
    Ok(dedupe_urls_preserve_order(
        base_urls
            .into_iter()
            .map(|base_url| normalize_http_base_url(&base_url, name))
            .collect::<anyhow::Result<Vec<_>>>()?,
    ))
}

fn normalize_http_base_url(base_url: &str, name: &str) -> anyhow::Result<String> {
    validate_http_url(base_url, name)?;
    Ok(normalize_base_url(base_url))
}

fn normalize_base_url(base_url: &str) -> String {
    base_url.trim_end_matches('/').to_string()
}

fn dedupe_urls_preserve_order(base_urls: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for base_url in base_urls {
        if seen.insert(base_url.clone()) {
            deduped.push(base_url);
        }
    }
    deduped
}

#[cfg(test)]
fn signal_base_url(
    token: Option<&SignedJoinToken>,
    override_url: Option<&str>,
) -> anyhow::Result<String> {
    signal_base_urls(token, override_url)?
        .into_iter()
        .next()
        .context("signal URL is required and no signal bootstrap exists")
}

fn signal_base_urls(
    token: Option<&SignedJoinToken>,
    override_url: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let (base_urls, name) = if let Some(url) = override_url {
        (vec![url.to_string()], "signal URL")
    } else if let Some(token) = token {
        (
            token
                .claims
                .bootstrap_endpoints
                .iter()
                .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::Signal)
                .map(|endpoint| endpoint.url.clone())
                .collect::<Vec<_>>(),
            "signal bootstrap endpoint",
        )
    } else {
        anyhow::bail!("signal URL is required and no signal bootstrap exists");
    };
    let base_urls = normalize_http_base_urls(base_urls, name)?;
    if base_urls.is_empty() {
        anyhow::bail!("signal URL is required and no signal bootstrap exists");
    }
    Ok(base_urls)
}

async fn agent_stun_servers(
    args: &AgentArgs,
    token: Option<&SignedJoinToken>,
) -> anyhow::Result<Vec<SocketAddr>> {
    let mut servers = Vec::new();
    for server in &args.stun_servers {
        if !endpoint_addr_is_usable(*server) {
            anyhow::bail!(
                "--stun-server must use a usable nonzero, non-unspecified, non-multicast, non-broadcast socket address"
            );
        }
        servers.push(*server);
    }
    if let Some(token) = token {
        for endpoint in token
            .claims
            .bootstrap_endpoints
            .iter()
            .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::Stun)
        {
            servers
                .extend(resolve_udp_bootstrap_socket_addrs(&endpoint.url, "STUN bootstrap").await?);
        }
    }
    Ok(dedupe_socket_addrs_preserve_order(servers))
}

async fn resolve_udp_bootstrap_socket_addrs(
    url: &str,
    name: &str,
) -> anyhow::Result<Vec<SocketAddr>> {
    let parsed =
        reqwest::Url::parse(url).with_context(|| format!("{name} must be an absolute URL"))?;
    if parsed.scheme() != "udp" {
        anyhow::bail!("{name} must use udp");
    }
    let host = parsed
        .host_str()
        .with_context(|| format!("{name} must include a host"))?;
    let port = parsed
        .port()
        .with_context(|| format!("{name} must include a port"))?;
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve {name} {url}"))?
        .filter(|addr| endpoint_addr_is_usable(*addr))
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        anyhow::bail!("{name} {url} resolved to no usable socket addresses");
    }
    Ok(addrs)
}

fn dedupe_socket_addrs_preserve_order(
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> Vec<SocketAddr> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for addr in addrs {
        if seen.insert(addr) {
            deduped.push(addr);
        }
    }
    deduped
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use async_trait::async_trait;
    use chrono::{Duration as ChronoDuration, TimeZone, Utc};
    use ipars_agent::AgentNodeState;
    use ipars_route_manager::PolicyRule;
    use ipars_types::api::{
        AgentMetricsResponse, AgentPacketFlowApplicationCount, AgentPacketFlowClassificationCount,
        AgentPacketFlowDropReasonCount, AgentPacketFlowDuplicateSourceCount,
        AgentRelayAdmissionFailureReasonCount, AgentRelayForwarderMetrics, LazyConnectMetrics,
        PathStateCount, RelayAdmissionResponse, RelayDataplaneMetrics,
    };
    use ipars_types::{
        AclAction, BootstrapEndpoint, CandidateSource, EndpointCandidate, EndpointCandidateKind,
        JoinTokenClaims, PathScore, PeerPathKey, Role, Route, Tag, TokenPolicy, TransportProtocol,
        VpnIp,
    };

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

    fn candidate(node_id: &str, kind: EndpointCandidateKind, cost: u32) -> EndpointCandidate {
        EndpointCandidate {
            node_id: NodeId::from_string(node_id),
            kind,
            addr: SocketAddr::from(([203, 0, 113, 10], 51820)),
            observed_at: Utc::now(),
            priority: 100,
            cost,
            source: CandidateSource::ControlPlane,
        }
    }

    fn ipv6_candidate(node_id: &str, cost: u32) -> EndpointCandidate {
        EndpointCandidate {
            addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x10)),
                51820,
            ),
            ..candidate(node_id, EndpointCandidateKind::Ipv6, cost)
        }
    }

    fn agent_status(
        node_id: &str,
        candidates: Vec<EndpointCandidate>,
    ) -> ipars_types::api::AgentStatusResponse {
        ipars_types::api::AgentStatusResponse {
            node_id: NodeId::from_string(node_id),
            identity_public_key: format!("identity-{node_id}"),
            wireguard_public_key: format!("wg-{node_id}"),
            candidate_count: candidates.len(),
            candidates,
            nat_classification: None,
            userspace_wireguard_process: None,
            state_updated_at: Utc::now(),
        }
    }

    fn node_record(node_id: &str) -> NodeRecord {
        NodeRecord {
            node_id: NodeId::from_string(node_id),
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
            identity_public_key: format!("identity-{node_id}"),
            wireguard_public_key: format!("wg-{node_id}"),
            role: Role::edge(),
            tags: Default::default(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        }
    }

    fn test_route_plan(
        interface: &str,
        cidrs: &[&str],
        priorities: &[u32],
    ) -> anyhow::Result<RoutePlan> {
        Ok(RoutePlan {
            interface: interface.to_string(),
            routes: cidrs
                .iter()
                .enumerate()
                .map(|(index, cidr)| {
                    Ok(Route {
                        id: format!("test-route-{index}"),
                        cidr: cidr
                            .parse()
                            .with_context(|| format!("test route CIDR {cidr} should parse"))?,
                        advertised_by: NodeId::from_string("route-provider"),
                        via: Some(NodeId::from_string("route-provider")),
                        metric: 50,
                        tags: Default::default(),
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?,
            policy_rules: priorities
                .iter()
                .map(|priority| PolicyRule {
                    table: 10_064,
                    priority: *priority,
                    from: None,
                    to: None,
                    fwmark: None,
                })
                .collect(),
        })
    }

    #[derive(Debug, Default)]
    struct RecordingManagedRouteManager {
        applied: tokio::sync::RwLock<Vec<RoutePlan>>,
        removed: tokio::sync::RwLock<Vec<RoutePlan>>,
    }

    #[async_trait]
    impl RouteManager for RecordingManagedRouteManager {
        async fn apply_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError> {
            self.applied.write().await.push(plan);
            Ok(())
        }

        async fn remove_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError> {
            self.removed.write().await.push(plan);
            Ok(())
        }

        async fn apply_docker_intent(
            &self,
            _intent: DockerNetworkIntent,
        ) -> Result<RoutePlan, RouteManagerError> {
            Err(RouteManagerError::Backend(
                "docker intent is not used by daemon route reconciliation tests".to_string(),
            ))
        }

        async fn apply_kubernetes_intent(
            &self,
            _intent: KubernetesUnderlayIntent,
        ) -> Result<RoutePlan, RouteManagerError> {
            Err(RouteManagerError::Backend(
                "kubernetes intent is not used by daemon route reconciliation tests".to_string(),
            ))
        }
    }

    fn test_relay_capability(max_sessions: u32, active_sessions: u32) -> RelayCapability {
        RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 30], 51_820))),
            admission_url: Some("http://203.0.113.30:9580".to_string()),
            max_sessions,
            active_sessions,
            max_mbps: 1000,
            e2e_only: true,
        }
    }

    fn test_relay_status_response(
        health: HealthState,
        max_sessions: u32,
        active_sessions: u32,
    ) -> RelayStatusResponse {
        RelayStatusResponse {
            relay_node: NodeId::from_string("relay-a"),
            capability: test_relay_capability(max_sessions, active_sessions),
            health,
            admission_attempt_count: 0,
            admission_success_count: 0,
            admission_failure_count: 0,
            admission_failures_by_reason: BTreeMap::new(),
            max_sessions_per_node: Some(20),
            dataplane: RelayDataplaneMetrics::default(),
            generated_at: Utc::now(),
        }
    }

    fn test_crash_policy() -> RelayForwarderCrashPolicy {
        RelayForwarderCrashPolicy {
            window: Duration::from_secs(60),
            max_crashes_per_window: 3,
            cooldown: Duration::from_secs(60),
        }
    }

    async fn spawn_test_signal_service(
        registry: Arc<SignalRegistry>,
    ) -> anyhow::Result<(String, tokio::task::JoinHandle<anyhow::Result<()>>)> {
        spawn_test_http_service(signal_router(SignalHttpState::new(registry))).await
    }

    async fn spawn_test_http_service(
        app: Router,
    ) -> anyhow::Result<(String, tokio::task::JoinHandle<anyhow::Result<()>>)> {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .context("test HTTP service failed")
        });
        Ok((format!("http://{addr}"), task))
    }

    fn assert_agent_relay_admission_failure_reason(
        metrics: &AgentMetricsResponse,
        reason: AgentRelayAdmissionFailureReason,
        count: u64,
    ) {
        assert!(
            metrics
                .relay_admission_failure_reason_counts
                .iter()
                .any(|entry| entry.reason == reason && entry.count == count),
            "missing relay admission failure reason {reason:?}={count}: {:?}",
            metrics.relay_admission_failure_reason_counts
        );
    }

    async fn unused_http_base_url() -> anyhow::Result<String> {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        drop(listener);
        Ok(format!("http://{addr}"))
    }

    async fn spawn_raw_http_response(
        response: String,
    ) -> anyhow::Result<(String, tokio::task::JoinHandle<anyhow::Result<()>>)> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
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
            let request_text = String::from_utf8_lossy(&request);
            anyhow::ensure!(
                request_text.starts_with("GET "),
                "unexpected raw HTTP test request: {request_text}"
            );
            stream.write_all(response.as_bytes()).await?;
            Ok(())
        });
        Ok((format!("http://{addr}"), task))
    }

    #[tokio::test]
    async fn bounded_agent_json_response_reads_small_body_and_rejects_oversized_header(
    ) -> anyhow::Result<()> {
        let body = r#"{"accepted":true,"policy_version":7,"peer_delta_available":false}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let (url, server) = spawn_raw_http_response(response).await?;
        let response = reqwest::Client::new().get(&url).send().await?;
        let decoded: HeartbeatResponse = read_bounded_agent_json_response(
            response,
            MAX_AGENT_RELAY_HTTP_RESPONSE_BYTES,
            "test heartbeat",
        )
        .await?;
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .context("timed out waiting for bounded JSON test server")???;
        assert!(decoded.accepted);
        assert_eq!(decoded.policy_version, 7);
        assert!(!decoded.peer_delta_available);

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_AGENT_RELAY_HTTP_RESPONSE_BYTES + 1
        );
        let (url, server) = spawn_raw_http_response(response).await?;
        let response = reqwest::Client::new().get(&url).send().await?;
        let error = read_bounded_agent_json_response::<HeartbeatResponse>(
            response,
            MAX_AGENT_RELAY_HTTP_RESPONSE_BYTES,
            "test heartbeat",
        )
        .await
        .expect_err("oversized agent HTTP JSON response should be rejected");
        assert!(error
            .to_string()
            .contains("test heartbeat response exceeds maximum size"));
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .context("timed out waiting for oversized bounded JSON test server")???;
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_fetch_rejects_oversized_control_plane_response() -> anyhow::Result<()> {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_AGENT_CONTROL_PLANE_RESPONSE_BYTES + 1
        );
        let (url, server) = spawn_raw_http_response(response).await?;
        let error = fetch_peer_map_from_control_planes(
            &reqwest::Client::new(),
            &[url],
            &NodeId::from_string("local"),
        )
        .await
        .expect_err("oversized control-plane peer map response should be rejected");
        assert!(error
            .to_string()
            .contains("control-plane peer map response exceeds maximum size"));
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .context("timed out waiting for oversized peer-map test server")???;
        Ok(())
    }

    #[test]
    fn stale_managed_route_plan_tracks_dropped_routes_and_rules() -> anyhow::Result<()> {
        let previous = test_route_plan(
            "ipars0",
            &["10.10.0.0/16", "10.11.0.0/16"],
            &[10_050, 10_051],
        )?;
        let current = test_route_plan("ipars0", &["10.11.0.0/16"], &[10_051])?;

        let stale = stale_managed_route_plan(&previous, &current);

        assert_eq!(stale.interface, "ipars0");
        assert_eq!(stale.routes.len(), 1);
        assert_eq!(
            stale.routes[0].cidr,
            "10.10.0.0/16".parse::<ipnet::IpNet>()?
        );
        assert_eq!(stale.policy_rules.len(), 1);
        assert_eq!(stale.policy_rules[0].priority, 10_050);
        Ok(())
    }

    #[test]
    fn stale_managed_route_plan_removes_all_previous_routes_on_interface_change(
    ) -> anyhow::Result<()> {
        let previous = test_route_plan("ipars0", &["10.10.0.0/16"], &[10_050])?;
        let current = test_route_plan("ipars1", &["10.10.0.0/16"], &[10_050])?;

        assert_eq!(stale_managed_route_plan(&previous, &current), previous);
        Ok(())
    }

    #[test]
    fn retained_managed_route_plan_keeps_only_routes_still_present_by_cidr() -> anyhow::Result<()> {
        let previous = test_route_plan(
            "ipars0",
            &["10.10.0.0/16", "10.11.0.0/16"],
            &[10_050, 10_051],
        )?;
        let current = test_route_plan("ipars0", &["10.11.0.0/16"], &[10_051])?;

        let retained = retained_managed_route_plan(&previous, &current);

        assert_eq!(retained.interface, "ipars0");
        assert_eq!(retained.routes.len(), 1);
        assert_eq!(
            retained.routes[0].cidr,
            "10.11.0.0/16".parse::<ipnet::IpNet>()?
        );
        assert_eq!(retained.policy_rules.len(), 1);
        assert_eq!(retained.policy_rules[0].priority, 10_051);
        Ok(())
    }

    #[test]
    fn retained_managed_route_plan_clears_state_on_interface_change() -> anyhow::Result<()> {
        let previous = test_route_plan("ipars0", &["10.10.0.0/16"], &[10_050])?;
        let current = test_route_plan("ipars1", &["10.10.0.0/16"], &[10_050])?;

        let retained = retained_managed_route_plan(&previous, &current);

        assert_eq!(retained.interface, "ipars1");
        assert!(retained.routes.is_empty());
        assert!(retained.policy_rules.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn managed_route_plan_reconciles_removed_routes_and_rules_before_apply(
    ) -> anyhow::Result<()> {
        let manager = RecordingManagedRouteManager::default();
        let mut applied_plan = None;
        let first = test_route_plan(
            "ipars0",
            &["10.10.0.0/16", "10.11.0.0/16"],
            &[10_050, 10_051],
        )?;
        let second = test_route_plan("ipars0", &["10.11.0.0/16"], &[10_051])?;

        let first_summary =
            apply_managed_route_plan(&manager, &mut applied_plan, first.clone()).await?;
        let second_summary =
            apply_managed_route_plan(&manager, &mut applied_plan, second.clone()).await?;

        assert_eq!(applied_plan, Some(second.clone()));
        assert_eq!(
            first_summary,
            ManagedRouteApplySummary {
                plan: first.clone(),
                routes_removed: 0,
                policy_rules_removed: 0,
            }
        );
        assert_eq!(
            second_summary,
            ManagedRouteApplySummary {
                plan: second.clone(),
                routes_removed: 1,
                policy_rules_removed: 1,
            }
        );
        assert_eq!(manager.applied.read().await.as_slice(), &[first, second]);
        let removed = manager.removed.read().await;
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].routes.len(), 1);
        assert_eq!(
            removed[0].routes[0].cidr,
            "10.10.0.0/16".parse::<ipnet::IpNet>()?
        );
        assert_eq!(removed[0].policy_rules.len(), 1);
        assert_eq!(removed[0].policy_rules[0].priority, 10_050);
        Ok(())
    }

    #[test]
    fn observability_defaults_service_name_to_command_component() {
        let args = ObservabilityArgs {
            otel_enabled: false,
            otel_endpoint: None,
            otel_service_name: None,
            otel_metrics_poll_interval_seconds: 15,
            log_filter: "info".to_string(),
        };

        assert!(!args.otel_active());
        assert_eq!(args.service_name("relay"), "iparsd-relay");
    }

    #[test]
    fn observability_rejects_zero_metrics_poll_interval() -> anyhow::Result<()> {
        let args = ObservabilityArgs {
            otel_enabled: true,
            otel_endpoint: None,
            otel_service_name: None,
            otel_metrics_poll_interval_seconds: 0,
            log_filter: "info".to_string(),
        };

        let error = match validate_observability_config(&args) {
            Ok(()) => anyhow::bail!("zero OTEL metrics poll interval should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--otel-metrics-poll-interval-seconds must be greater than zero"));
        Ok(())
    }

    #[test]
    fn observability_endpoint_implies_otel_and_uses_signal_paths() {
        let args = ObservabilityArgs {
            otel_enabled: false,
            otel_endpoint: Some("http://collector:4318/".to_string()),
            otel_service_name: Some("custom-ipars".to_string()),
            otel_metrics_poll_interval_seconds: 5,
            log_filter: "ipars=debug".to_string(),
        };

        assert!(args.otel_active());
        assert_eq!(args.service_name("agent"), "custom-ipars");
        assert_eq!(
            otlp_http_signal_endpoint(args.otel_endpoint.as_deref().unwrap_or_default(), "traces"),
            "http://collector:4318/v1/traces"
        );
        assert_eq!(
            otlp_http_signal_endpoint(args.otel_endpoint.as_deref().unwrap_or_default(), "logs"),
            "http://collector:4318/v1/logs"
        );
    }

    #[test]
    fn control_plane_otel_path_state_count_defaults_missing_states_to_zero() {
        let metrics = ControlPlaneMetricsResponse {
            cluster_id: ClusterId::from_string("cluster-a"),
            node_count: 2,
            relay_candidate_count: 1,
            healthy_node_count: 1,
            degraded_node_count: 1,
            unhealthy_node_count: 0,
            stale_endpoint_candidate_count: 0,
            vpn_pool_total_count: 6,
            vpn_pool_allocated_count: 2,
            vpn_pool_available_count: 4,
            token_ledger_issued_count: 3,
            token_ledger_active_count: 1,
            token_ledger_revoked_count: 1,
            token_ledger_expired_count: 0,
            token_ledger_exhausted_count: 1,
            token_ledger_use_count: 7,
            peer_map_candidate_count: 2,
            peer_map_visible_count: 1,
            peer_map_acl_denied_count: 1,
            peer_map_route_candidate_count: 3,
            peer_map_route_visible_count: 2,
            peer_map_route_acl_denied_count: 1,
            stale_path_count: 0,
            path_count: 3,
            path_state_counts: vec![PathStateCount {
                state: PathState::Relay,
                count: 3,
            }],
            endpoint_candidate_ttl_seconds: 120,
            path_state_ttl_seconds: 600,
            generated_at: Utc::now(),
        };

        assert_eq!(
            control_plane_path_state_count(&metrics, PathState::Relay),
            3
        );
        assert_eq!(
            control_plane_path_state_count(&metrics, PathState::DirectPublic),
            0
        );
    }

    #[test]
    fn daemon_root_observability_args_parse_before_subcommand() {
        let cli = Cli::parse_from([
            "iparsd",
            "--otel-enabled",
            "--otel-endpoint",
            "http://collector:4318",
            "--otel-service-name",
            "ipars-agent-prod",
            "--otel-metrics-poll-interval-seconds",
            "3",
            "--log-filter",
            "ipars=debug",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
        ]);

        assert!(cli.observability.otel_active());
        assert_eq!(
            cli.observability.otel_endpoint.as_deref(),
            Some("http://collector:4318")
        );
        assert_eq!(
            cli.observability.otel_service_name.as_deref(),
            Some("ipars-agent-prod")
        );
        assert_eq!(cli.observability.otel_metrics_poll_interval_seconds, 3);
        assert_eq!(cli.observability.log_filter, "ipars=debug");
        assert_eq!(cli.command.component(), "agent");
    }

    #[test]
    fn stun_command_accepts_root_observability_args() {
        let cli = Cli::parse_from([
            "iparsd",
            "--otel-enabled",
            "--otel-metrics-poll-interval-seconds",
            "2",
            "stun",
            "--listen",
            "127.0.0.1:0",
        ]);

        let Command::Stun(args) = cli.command else {
            panic!("expected stun command");
        };
        assert!(cli.observability.otel_active());
        assert_eq!(cli.observability.otel_metrics_poll_interval_seconds, 2);
        assert_eq!(args.listen, SocketAddr::from(([127, 0, 0, 1], 0)));
    }

    #[test]
    fn stun_command_accepts_http_listen() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "stun",
            "--listen",
            "0.0.0.0:3478",
            "--alternate-listen",
            "127.0.0.1:3480",
            "--http-listen",
            "127.0.0.1:3479",
        ])?;

        let Command::Stun(args) = cli.command else {
            anyhow::bail!("expected stun command");
        };
        assert_eq!(args.listen, SocketAddr::from(([0, 0, 0, 0], 3478)));
        assert_eq!(
            args.alternate_listen,
            Some(SocketAddr::from(([127, 0, 0, 1], 3480)))
        );
        assert_eq!(args.http_listen, SocketAddr::from(([127, 0, 0, 1], 3479)));
        Ok(())
    }

    #[tokio::test]
    async fn stun_http_metrics_json_reports_listener_and_stats() -> anyhow::Result<()> {
        let state = StunHttpState::new(
            SocketAddr::from(([127, 0, 0, 1], 3478)),
            Some(SocketAddr::from(([127, 0, 0, 1], 3480))),
            Arc::new(StunServerStats::default()),
        );

        let axum::Json(metrics) = stun_metrics(axum::extract::State(state)).await;

        assert_eq!(metrics.listen, SocketAddr::from(([127, 0, 0, 1], 3478)));
        assert_eq!(
            metrics.alternate_listen,
            Some(SocketAddr::from(([127, 0, 0, 1], 3480)))
        );
        assert_eq!(metrics.binding_request_count, 0);
        assert_eq!(metrics.binding_response_count, 0);
        assert_eq!(metrics.invalid_packet_count, 0);
        assert_eq!(metrics.socket_receive_error_count, 0);
        assert_eq!(metrics.socket_send_error_count, 0);
        Ok(())
    }

    #[test]
    fn stun_prometheus_metrics_render_all_server_counters() {
        let generated_at = Utc::now();
        let metrics = StunMetricsResponse {
            listen: SocketAddr::from(([127, 0, 0, 1], 3478)),
            alternate_listen: Some(SocketAddr::from(([127, 0, 0, 1], 3480))),
            binding_request_count: 7,
            binding_response_count: 6,
            invalid_packet_count: 2,
            socket_receive_error_count: 1,
            socket_send_error_count: 3,
            generated_at,
        };

        let rendered = render_stun_prometheus_metrics(&metrics);

        assert!(rendered.contains(&format!(
            "ipars_stun_metrics_generated_timestamp_seconds{{listen=\"127.0.0.1:3478\"}} {}",
            generated_at.timestamp()
        )));
        assert!(rendered.contains("ipars_stun_server_active{listen=\"127.0.0.1:3478\"} 1"));
        assert!(rendered.contains(
            "ipars_stun_rfc5780_alternate_server_active{listen=\"127.0.0.1:3478\",alternate_listen=\"127.0.0.1:3480\"} 1"
        ));
        assert!(rendered.contains("ipars_stun_binding_requests_total{listen=\"127.0.0.1:3478\"} 7"));
        assert!(
            rendered.contains("ipars_stun_binding_responses_total{listen=\"127.0.0.1:3478\"} 6")
        );
        assert!(rendered.contains("ipars_stun_invalid_packets_total{listen=\"127.0.0.1:3478\"} 2"));
        assert!(rendered
            .contains("ipars_stun_socket_receive_errors_total{listen=\"127.0.0.1:3478\"} 1"));
        assert!(
            rendered.contains("ipars_stun_socket_send_errors_total{listen=\"127.0.0.1:3478\"} 3")
        );
    }

    #[test]
    fn stun_otel_snapshot_copies_server_metrics() {
        let snapshot = StunServerMetricsSnapshot {
            binding_request_count: 7,
            binding_response_count: 6,
            invalid_packet_count: 2,
            socket_receive_error_count: 1,
            socket_send_error_count: 3,
        };

        assert_eq!(
            StunOtelSnapshot::from(&snapshot),
            StunOtelSnapshot {
                binding_request_count: 7,
                binding_response_count: 6,
                invalid_packet_count: 2,
                socket_receive_error_count: 1,
                socket_send_error_count: 3,
            }
        );
    }

    #[test]
    fn stun_otel_status_labels_include_rfc5780_alternate_listener() {
        let labels = StunOtelStatusLabels::new(
            SocketAddr::from(([127, 0, 0, 1], 3478)),
            Some(SocketAddr::from(([127, 0, 0, 1], 3480))),
        );

        assert_eq!(
            labels,
            StunOtelStatusLabels {
                listen: "127.0.0.1:3478".to_string(),
                alternate_listen: Some("127.0.0.1:3480".to_string()),
            }
        );
        let primary_attrs = labels.primary_attrs();
        assert_eq!(primary_attrs.len(), 1);
        let Some(alternate_attrs) = labels.alternate_attrs() else {
            panic!("alternate listener should produce OTLP labels");
        };
        assert_eq!(alternate_attrs.len(), 2);

        let no_alternate =
            StunOtelStatusLabels::new(SocketAddr::from(([127, 0, 0, 1], 3478)), None);
        assert!(no_alternate.alternate_attrs().is_none());
    }

    #[test]
    fn stun_otel_delta_records_first_snapshot_and_handles_counter_reset() {
        let previous = StunOtelSnapshot {
            binding_request_count: 10,
            binding_response_count: 8,
            invalid_packet_count: 3,
            socket_receive_error_count: 2,
            socket_send_error_count: 1,
        };
        let current = StunServerMetricsSnapshot {
            binding_request_count: 12,
            binding_response_count: 9,
            invalid_packet_count: 1,
            socket_receive_error_count: 2,
            socket_send_error_count: 4,
        };

        assert_eq!(counter_delta(current.binding_request_count, None), 12);
        assert_eq!(
            counter_delta(
                current.binding_request_count,
                Some(previous.binding_request_count),
            ),
            2
        );
        assert_eq!(
            counter_delta(
                current.invalid_packet_count,
                Some(previous.invalid_packet_count)
            ),
            0
        );
        assert_eq!(
            counter_delta(
                current.socket_send_error_count,
                Some(previous.socket_send_error_count),
            ),
            3
        );
    }

    #[test]
    fn control_plane_args_accept_trusted_issuer_keys() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "control-plane",
            "--cluster-id",
            "cluster-a",
            "--issuer-node-id",
            "issuer-a",
            "--issuer-key-id",
            "root",
            "--issuer-public-key",
            "pub-a",
            "--trusted-issuer-key",
            "issuer-a,root-next,pub-b",
            "--trusted-issuer-key",
            " issuer-b , root , pub-c ",
        ])?;

        let Command::ControlPlane(args) = cli.command else {
            anyhow::bail!("expected control-plane command");
        };
        assert_eq!(
            args.trusted_issuer_keys,
            vec![
                TrustedIssuerKeyArg {
                    issuer_node_id: "issuer-a".to_string(),
                    key_id: "root-next".to_string(),
                    public_key: "pub-b".to_string(),
                },
                TrustedIssuerKeyArg {
                    issuer_node_id: "issuer-b".to_string(),
                    key_id: "root".to_string(),
                    public_key: "pub-c".to_string(),
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn trusted_issuer_key_parser_rejects_incomplete_values() {
        assert!(parse_trusted_issuer_key("issuer,key").is_err());
        assert!(parse_trusted_issuer_key("issuer,,pub").is_err());
        assert!(parse_trusted_issuer_key(",key,pub").is_err());
        assert!(parse_trusted_issuer_key("issuer,key,").is_err());
    }

    #[test]
    fn control_plane_runtime_identifiers_must_be_path_safe() -> anyhow::Result<()> {
        let oversized_key_id = "x".repeat(MAX_DAEMON_IDENTIFIER_BYTES + 1);
        let cases = vec![
            (
                vec![
                    "iparsd".to_string(),
                    "control-plane".to_string(),
                    "--cluster-id".to_string(),
                    "bad/cluster".to_string(),
                    "--issuer-node-id".to_string(),
                    "issuer-a".to_string(),
                    "--issuer-key-id".to_string(),
                    "root".to_string(),
                    "--issuer-public-key".to_string(),
                    "pub-a".to_string(),
                ],
                "--cluster-id must contain only ASCII letters, digits, '_', '.' or '-'".to_string(),
            ),
            (
                vec![
                    "iparsd".to_string(),
                    "control-plane".to_string(),
                    "--cluster-id".to_string(),
                    "cluster-a".to_string(),
                    "--issuer-node-id".to_string(),
                    "issuer a".to_string(),
                    "--issuer-key-id".to_string(),
                    "root".to_string(),
                    "--issuer-public-key".to_string(),
                    "pub-a".to_string(),
                ],
                "--issuer-node-id must contain only ASCII letters, digits, '_', '.' or '-'"
                    .to_string(),
            ),
            (
                vec![
                    "iparsd".to_string(),
                    "control-plane".to_string(),
                    "--cluster-id".to_string(),
                    "cluster-a".to_string(),
                    "--issuer-node-id".to_string(),
                    "issuer-a".to_string(),
                    "--issuer-key-id".to_string(),
                    oversized_key_id,
                    "--issuer-public-key".to_string(),
                    "pub-a".to_string(),
                ],
                format!("--issuer-key-id exceeds {MAX_DAEMON_IDENTIFIER_BYTES} bytes"),
            ),
            (
                vec![
                    "iparsd".to_string(),
                    "control-plane".to_string(),
                    "--cluster-id".to_string(),
                    "cluster-a".to_string(),
                    "--issuer-node-id".to_string(),
                    "issuer-a".to_string(),
                    "--issuer-key-id".to_string(),
                    "root".to_string(),
                    "--issuer-public-key".to_string(),
                    "pub-a".to_string(),
                    "--trusted-issuer-key".to_string(),
                    "issuer/b,root-next,pub-b".to_string(),
                ],
                "--trusted-issuer-key issuer_node_id must contain only ASCII letters, digits, '_', '.' or '-'".to_string(),
            ),
        ];

        for (argv, expected) in cases {
            let cli = Cli::try_parse_from(argv)?;
            let Command::ControlPlane(args) = cli.command else {
                anyhow::bail!("expected control-plane command");
            };
            let error = match validate_control_plane_runtime_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid control-plane runtime config"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(&expected),
                "expected {expected}, got {error}"
            );
        }
        Ok(())
    }

    #[test]
    fn control_plane_args_accept_acl_rules() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "control-plane",
            "--cluster-id",
            "cluster-a",
            "--issuer-node-id",
            "issuer-a",
            "--issuer-key-id",
            "root",
            "--issuer-public-key",
            "pub-a",
            "--relay-health-ttl-seconds",
            "45",
            "--endpoint-candidate-ttl-seconds",
            "75",
            "--path-state-ttl-seconds",
            "180",
            "--acl-rule",
            r#"{"id":"edge-to-db","from_roles":["edge"],"from_tags":["app"],"to_roles":["database"],"to_tags":["db"],"routes":["10.42.0.0/16"],"protocol":"any","action":"allow"}"#,
        ])?;

        let Command::ControlPlane(args) = cli.command else {
            anyhow::bail!("expected control-plane command");
        };
        assert_eq!(args.relay_health_ttl_seconds, 45);
        assert_eq!(args.endpoint_candidate_ttl_seconds, 75);
        assert_eq!(args.path_state_ttl_seconds, 180);
        validate_control_plane_runtime_config(&args)?;
        assert_eq!(args.acl_rules.len(), 1);
        let rule = &args.acl_rules[0];
        assert_eq!(rule.id, "edge-to-db");
        assert!(rule.from_roles.contains(&Role::edge()));
        assert!(rule.from_tags.contains(&Tag::from_string("app")));
        assert!(rule.to_roles.contains(&Role::from_string("database")));
        assert!(rule.to_tags.contains(&Tag::from_string("db")));
        assert_eq!(rule.routes, vec!["10.42.0.0/16".parse()?]);
        assert_eq!(rule.protocol, TransportProtocol::Any);
        assert_eq!(rule.action, AclAction::Allow);
        Ok(())
    }

    #[test]
    fn signal_args_accept_relay_health_ttl() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "signal",
            "--relay-health-ttl-seconds",
            "45",
            "--endpoint-candidate-ttl-seconds",
            "75",
            "--nat-classification-ttl-seconds",
            "180",
            "--nat-classification-min-confidence-percent",
            "75",
            "--disable-relay-fallback",
        ])?;

        let Command::Signal(args) = cli.command else {
            anyhow::bail!("expected signal command");
        };
        assert_eq!(args.relay_health_ttl_seconds, 45);
        assert_eq!(args.endpoint_candidate_ttl_seconds, 75);
        assert_eq!(args.nat_classification_ttl_seconds, 180);
        assert_eq!(args.nat_classification_min_confidence_percent, 75);
        assert!(args.disable_relay_fallback);
        validate_signal_runtime_config(&args)?;
        Ok(())
    }

    #[test]
    fn control_plane_candidate_ttl_must_be_positive() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "control-plane",
            "--cluster-id",
            "cluster-a",
            "--issuer-node-id",
            "issuer-a",
            "--issuer-key-id",
            "root",
            "--issuer-public-key",
            "pub-a",
            "--endpoint-candidate-ttl-seconds",
            "0",
        ])?;

        let Command::ControlPlane(args) = cli.command else {
            anyhow::bail!("expected control-plane command");
        };
        let error = match validate_control_plane_runtime_config(&args) {
            Ok(()) => anyhow::bail!("unexpected valid control-plane runtime config"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--endpoint-candidate-ttl-seconds must be greater than zero"));
        Ok(())
    }

    #[test]
    fn control_plane_path_state_ttl_must_be_positive() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "control-plane",
            "--cluster-id",
            "cluster-a",
            "--issuer-node-id",
            "issuer-a",
            "--issuer-key-id",
            "root",
            "--issuer-public-key",
            "pub-a",
            "--path-state-ttl-seconds",
            "0",
        ])?;

        let Command::ControlPlane(args) = cli.command else {
            anyhow::bail!("expected control-plane command");
        };
        let error = match validate_control_plane_runtime_config(&args) {
            Ok(()) => anyhow::bail!("unexpected valid control-plane runtime config"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--path-state-ttl-seconds must be greater than zero"));
        Ok(())
    }

    #[test]
    fn signal_candidate_ttl_must_be_positive() -> anyhow::Result<()> {
        let cli =
            Cli::try_parse_from(["iparsd", "signal", "--endpoint-candidate-ttl-seconds", "0"])?;

        let Command::Signal(args) = cli.command else {
            anyhow::bail!("expected signal command");
        };
        let error = match validate_signal_runtime_config(&args) {
            Ok(()) => anyhow::bail!("unexpected valid signal runtime config"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--endpoint-candidate-ttl-seconds must be greater than zero"));
        Ok(())
    }

    #[test]
    fn signal_nat_classification_ttl_must_be_positive() -> anyhow::Result<()> {
        let cli =
            Cli::try_parse_from(["iparsd", "signal", "--nat-classification-ttl-seconds", "0"])?;

        let Command::Signal(args) = cli.command else {
            anyhow::bail!("expected signal command");
        };
        let error = match validate_signal_runtime_config(&args) {
            Ok(()) => anyhow::bail!("unexpected valid signal runtime config"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--nat-classification-ttl-seconds must be greater than zero"));
        Ok(())
    }

    #[test]
    fn signal_nat_classification_min_confidence_must_be_percent() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "signal",
            "--nat-classification-min-confidence-percent",
            "101",
        ])?;

        let Command::Signal(args) = cli.command else {
            anyhow::bail!("expected signal command");
        };
        let error = match validate_signal_runtime_config(&args) {
            Ok(()) => anyhow::bail!("unexpected valid signal runtime config"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--nat-classification-min-confidence-percent must be between 0 and 100"));
        Ok(())
    }

    #[test]
    fn acl_rule_parser_rejects_invalid_json() {
        assert!(parse_acl_rule("not json").is_err());
    }

    #[test]
    fn signal_otel_nat_suppression_strategy_counts_default_missing_strategies() {
        let metrics = SignalMetricsResponse {
            node_count: 0,
            relay_candidate_count: 0,
            nat_classification_count: 0,
            stale_nat_classification_count: 0,
            fresh_low_confidence_nat_classification_count: 0,
            fresh_nat_classification_strategy_counts: vec![NatTraversalStrategyCount {
                strategy: NatTraversalStrategy::CoordinatedHolePunch,
                count: 3,
            }],
            health_report_count: 0,
            healthy_node_count: 0,
            degraded_node_count: 0,
            unhealthy_node_count: 0,
            stale_health_report_count: 0,
            stale_endpoint_candidate_count: 0,
            node_upsert_count: 0,
            path_negotiation_count: 0,
            path_acl_denied_count: 0,
            relay_candidate_acl_denied_count: 0,
            path_negotiation_state_counts: Vec::new(),
            hole_punch_plan_count: 1,
            hole_punch_acl_denied_count: 0,
            hole_punch_nat_suppressed_count: 1,
            hole_punch_nat_suppressed_strategy_counts: vec![NatTraversalStrategyCount {
                strategy: NatTraversalStrategy::RelayPreferred,
                count: 2,
            }],
            relay_health_ttl_seconds: 30,
            endpoint_candidate_ttl_seconds: 120,
            nat_classification_ttl_seconds: 300,
            nat_classification_min_confidence_percent: 50,
            generated_at: Utc::now(),
        };
        let snapshot = SignalOtelSnapshot::from(&metrics);

        assert_eq!(
            signal_nat_strategy_count(&metrics, NatTraversalStrategy::CoordinatedHolePunch),
            3
        );
        assert_eq!(
            signal_nat_strategy_count(&metrics, NatTraversalStrategy::DirectCandidate),
            0
        );
        assert_eq!(
            signal_snapshot_nat_strategy_count(
                &snapshot,
                NatTraversalStrategy::CoordinatedHolePunch,
            ),
            3
        );
        assert_eq!(
            signal_snapshot_nat_strategy_count(&snapshot, NatTraversalStrategy::RelayPreferred),
            0
        );
        assert_eq!(
            signal_hole_punch_nat_suppression_strategy_count(
                &metrics,
                NatTraversalStrategy::RelayPreferred,
            ),
            2
        );
        assert_eq!(
            signal_hole_punch_nat_suppression_strategy_count(
                &metrics,
                NatTraversalStrategy::DirectCandidate,
            ),
            0
        );
        assert_eq!(
            signal_snapshot_hole_punch_nat_suppression_strategy_count(
                &snapshot,
                NatTraversalStrategy::RelayPreferred,
            ),
            2
        );
        assert_eq!(
            signal_snapshot_hole_punch_nat_suppression_strategy_count(
                &snapshot,
                NatTraversalStrategy::InsufficientData,
            ),
            0
        );
    }

    #[test]
    fn relay_otel_delta_records_first_snapshot_as_counter_increment() {
        let mut current = RelayDataplaneMetrics {
            datagrams_received: 10,
            datagrams_forwarded: 8,
            datagrams_dropped: 2,
            datagram_bytes_received: 1000,
            payload_bytes_forwarded: 640,
            datagram_bytes_dropped: 360,
            ..RelayDataplaneMetrics::default()
        };
        current
            .drops_by_reason
            .insert(RelayDataplaneDropReason::MalformedFrame, 2);

        let delta = relay_dataplane_delta(&current, None);

        assert_eq!(delta.datagrams_received, 10);
        assert_eq!(delta.datagrams_forwarded, 8);
        assert_eq!(delta.datagrams_dropped, 2);
        assert_eq!(delta.datagram_bytes_received, 1000);
        assert_eq!(delta.payload_bytes_forwarded, 640);
        assert_eq!(delta.datagram_bytes_dropped, 360);
        assert_eq!(
            delta
                .drops_by_reason
                .get(&RelayDataplaneDropReason::MalformedFrame),
            Some(&2)
        );
        assert_eq!(
            delta.drops_by_reason.len(),
            RelayDataplaneDropReason::ALL.len()
        );
        assert_eq!(
            delta
                .drops_by_reason
                .get(&RelayDataplaneDropReason::UnknownSession),
            Some(&0)
        );
    }

    #[test]
    fn relay_otel_delta_records_only_increments_since_previous_snapshot() {
        let mut previous = RelayDataplaneMetrics {
            datagrams_received: 10,
            datagrams_forwarded: 8,
            datagrams_dropped: 2,
            datagram_bytes_received: 1000,
            payload_bytes_forwarded: 640,
            datagram_bytes_dropped: 360,
            ..RelayDataplaneMetrics::default()
        };
        previous
            .drops_by_reason
            .insert(RelayDataplaneDropReason::MalformedFrame, 2);

        let mut current = RelayDataplaneMetrics {
            datagrams_received: 14,
            datagrams_forwarded: 11,
            datagrams_dropped: 3,
            datagram_bytes_received: 1550,
            payload_bytes_forwarded: 900,
            datagram_bytes_dropped: 410,
            drops_by_reason: previous.drops_by_reason.clone(),
        };
        current
            .drops_by_reason
            .insert(RelayDataplaneDropReason::MalformedFrame, 3);
        current
            .drops_by_reason
            .insert(RelayDataplaneDropReason::RateLimited, 4);

        let delta = relay_dataplane_delta(&current, Some(&previous));

        assert_eq!(delta.datagrams_received, 4);
        assert_eq!(delta.datagrams_forwarded, 3);
        assert_eq!(delta.datagrams_dropped, 1);
        assert_eq!(delta.datagram_bytes_received, 550);
        assert_eq!(delta.payload_bytes_forwarded, 260);
        assert_eq!(delta.datagram_bytes_dropped, 50);
        assert_eq!(
            delta
                .drops_by_reason
                .get(&RelayDataplaneDropReason::MalformedFrame),
            Some(&1)
        );
        assert_eq!(
            delta
                .drops_by_reason
                .get(&RelayDataplaneDropReason::RateLimited),
            Some(&4)
        );
        assert_eq!(
            delta.drops_by_reason.len(),
            RelayDataplaneDropReason::ALL.len()
        );
        assert_eq!(
            delta
                .drops_by_reason
                .get(&RelayDataplaneDropReason::SessionExpired),
            Some(&0)
        );
    }

    #[test]
    fn relay_admission_failure_reason_delta_records_counter_increments() {
        let mut previous = BTreeMap::new();
        previous.insert(RelayAdmissionFailureReason::Unauthorized, 2);
        previous.insert(RelayAdmissionFailureReason::AdmissionDenied, 1);
        let mut current = previous.clone();
        current.insert(RelayAdmissionFailureReason::Unauthorized, 5);
        current.insert(RelayAdmissionFailureReason::InvalidAdmissionRequest, 2);
        current.insert(RelayAdmissionFailureReason::InvalidSessionCredential, 1);

        let delta = relay_admission_failure_reason_delta(&current, Some(&previous));

        assert_eq!(
            delta.get(&RelayAdmissionFailureReason::Unauthorized),
            Some(&3)
        );
        assert_eq!(
            delta.get(&RelayAdmissionFailureReason::InvalidAdmissionRequest),
            Some(&2)
        );
        assert_eq!(
            delta.get(&RelayAdmissionFailureReason::InvalidSessionCredential),
            Some(&1)
        );
        assert_eq!(
            delta.get(&RelayAdmissionFailureReason::AdmissionDenied),
            Some(&0)
        );
        assert_eq!(delta.len(), RelayAdmissionFailureReason::ALL.len());
    }

    fn agent_forwarder_metrics(
        peer: &str,
        relay_node: &str,
        outbound_packets: u64,
        outbound_payload_bytes: u64,
        outbound_datagram_bytes: u64,
        inbound_packets: u64,
        inbound_payload_bytes: u64,
    ) -> AgentRelayForwarderMetrics {
        AgentRelayForwarderMetrics {
            peer: NodeId::from_string(peer),
            relay_node: NodeId::from_string(relay_node),
            relay_endpoint: SocketAddr::from(([203, 0, 113, 10], 51_820)),
            local_endpoint: SocketAddr::from(([127, 0, 0, 1], 52_000)),
            socket_receive_errors: 0,
            outbound_packets,
            outbound_payload_bytes,
            outbound_datagram_bytes,
            outbound_dropped_unexpected_source_packets: 0,
            outbound_dropped_unexpected_source_payload_bytes: 0,
            outbound_dropped_expired_session_packets: 0,
            outbound_dropped_expired_session_payload_bytes: 0,
            outbound_dropped_oversized_packets: 0,
            outbound_dropped_oversized_payload_bytes: 0,
            outbound_dropped_oversized_datagram_bytes: 0,
            outbound_dropped_socket_error_packets: 0,
            outbound_dropped_socket_error_payload_bytes: 0,
            outbound_dropped_socket_error_datagram_bytes: 0,
            outbound_dropped_non_wireguard_packets: 0,
            outbound_dropped_non_wireguard_payload_bytes: 0,
            inbound_packets,
            inbound_payload_bytes,
            inbound_dropped_expired_session_packets: 0,
            inbound_dropped_expired_session_payload_bytes: 0,
            inbound_dropped_oversized_packets: 0,
            inbound_dropped_oversized_payload_bytes: 0,
            inbound_dropped_socket_error_packets: 0,
            inbound_dropped_socket_error_payload_bytes: 0,
            inbound_dropped_non_wireguard_packets: 0,
            inbound_dropped_non_wireguard_payload_bytes: 0,
            last_forwarded_at: None,
        }
    }

    fn agent_metrics_with_category_counts(
        forwarder: AgentRelayForwarderMetrics,
    ) -> AgentMetricsResponse {
        AgentMetricsResponse {
            node_id: NodeId::from_string("node-a"),
            candidate_count: 2,
            peer_map_synced: true,
            peer_map_peer_count: 3,
            peer_map_route_count: 4,
            peer_map_generated_at: Some(Utc::now()),
            path_count: 1,
            relay_session_count: 1,
            relay_admission_attempt_count: 3,
            relay_admission_success_count: 2,
            relay_admission_failure_count: 1,
            relay_admission_failure_reason_counts: vec![AgentRelayAdmissionFailureReasonCount {
                reason: AgentRelayAdmissionFailureReason::Rejected,
                count: 1,
            }],
            relay_forwarder_count: 1,
            relay_forwarders: vec![forwarder],
            path_change_event_count: 1,
            path_state_counts: vec![PathStateCount {
                state: PathState::Relay,
                count: 1,
            }],
            lazy_connect: LazyConnectMetrics {
                active_peer_count: 1,
                pinned_peer_count: 1,
                observed_peer_vpn_ip_count: 1,
                observed_route_peer_count: 1,
                observed_route_count: 2,
            },
            path_probe_record_count: 4,
            peer_activity_record_count: 2,
            packet_flow_observation_count: 3,
            packet_flow_match_count: 2,
            packet_flow_unmatched_count: 1,
            packet_flow_filtered_count: 3,
            packet_flow_filtered_reason_counts: vec![AgentPacketFlowDropReasonCount {
                reason: AgentPacketFlowDropReason::Multicast,
                count: 3,
            }],
            packet_flow_duplicate_suppression_count: 5,
            packet_flow_duplicate_suppression_counts: vec![AgentPacketFlowDuplicateSourceCount {
                source: AgentPacketFlowDuplicateSource::EbpfRingbuf,
                count: 5,
            }],
            packet_flow_classification_counts: vec![AgentPacketFlowClassificationCount {
                classification: AgentPacketFlowClassification::Established,
                count: 2,
            }],
            packet_flow_application_counts: vec![AgentPacketFlowApplicationCount {
                application: AgentPacketFlowApplication::WireGuard,
                count: 2,
            }],
            userspace_wireguard_process: None,
            generated_at: Utc::now(),
        }
    }

    #[test]
    fn agent_otel_delta_records_first_forwarder_snapshot_as_counter_increment() {
        let mut current = agent_forwarder_metrics("peer-a", "relay-a", 5, 500, 620, 3, 300);
        current.socket_receive_errors = 2;
        current.outbound_dropped_unexpected_source_packets = 1;
        current.outbound_dropped_unexpected_source_payload_bytes = 32;
        current.outbound_dropped_expired_session_packets = 1;
        current.outbound_dropped_expired_session_payload_bytes = 64;
        current.outbound_dropped_oversized_packets = 1;
        current.outbound_dropped_oversized_payload_bytes = 80;
        current.outbound_dropped_oversized_datagram_bytes = 120;
        current.outbound_dropped_socket_error_packets = 1;
        current.outbound_dropped_socket_error_payload_bytes = 88;
        current.outbound_dropped_socket_error_datagram_bytes = 132;
        current.outbound_dropped_non_wireguard_packets = 2;
        current.outbound_dropped_non_wireguard_payload_bytes = 42;
        current.inbound_dropped_expired_session_packets = 1;
        current.inbound_dropped_expired_session_payload_bytes = 48;
        current.inbound_dropped_oversized_packets = 1;
        current.inbound_dropped_oversized_payload_bytes = 72;
        current.inbound_dropped_socket_error_packets = 1;
        current.inbound_dropped_socket_error_payload_bytes = 56;
        current.inbound_dropped_non_wireguard_packets = 1;
        current.inbound_dropped_non_wireguard_payload_bytes = 24;

        let delta = agent_forwarder_delta(&current, None);

        assert_eq!(delta.socket_receive_errors, 2);
        assert_eq!(delta.outbound_packets, 5);
        assert_eq!(delta.outbound_payload_bytes, 500);
        assert_eq!(delta.outbound_datagram_bytes, 620);
        assert_eq!(delta.outbound_dropped_unexpected_source_packets, 1);
        assert_eq!(delta.outbound_dropped_unexpected_source_payload_bytes, 32);
        assert_eq!(delta.outbound_dropped_expired_session_packets, 1);
        assert_eq!(delta.outbound_dropped_expired_session_payload_bytes, 64);
        assert_eq!(delta.outbound_dropped_oversized_packets, 1);
        assert_eq!(delta.outbound_dropped_oversized_payload_bytes, 80);
        assert_eq!(delta.outbound_dropped_oversized_datagram_bytes, 120);
        assert_eq!(delta.outbound_dropped_socket_error_packets, 1);
        assert_eq!(delta.outbound_dropped_socket_error_payload_bytes, 88);
        assert_eq!(delta.outbound_dropped_socket_error_datagram_bytes, 132);
        assert_eq!(delta.outbound_dropped_non_wireguard_packets, 2);
        assert_eq!(delta.outbound_dropped_non_wireguard_payload_bytes, 42);
        assert_eq!(delta.inbound_packets, 3);
        assert_eq!(delta.inbound_payload_bytes, 300);
        assert_eq!(delta.inbound_dropped_expired_session_packets, 1);
        assert_eq!(delta.inbound_dropped_expired_session_payload_bytes, 48);
        assert_eq!(delta.inbound_dropped_oversized_packets, 1);
        assert_eq!(delta.inbound_dropped_oversized_payload_bytes, 72);
        assert_eq!(delta.inbound_dropped_socket_error_packets, 1);
        assert_eq!(delta.inbound_dropped_socket_error_payload_bytes, 56);
        assert_eq!(delta.inbound_dropped_non_wireguard_packets, 1);
        assert_eq!(delta.inbound_dropped_non_wireguard_payload_bytes, 24);
        assert!(has_agent_forwarder_delta(&delta));
    }

    #[test]
    fn agent_otel_delta_records_only_forwarder_increments_since_previous_snapshot() {
        let mut previous = agent_forwarder_metrics("peer-a", "relay-a", 5, 500, 620, 3, 300);
        previous.socket_receive_errors = 2;
        previous.outbound_dropped_unexpected_source_packets = 1;
        previous.outbound_dropped_unexpected_source_payload_bytes = 32;
        previous.outbound_dropped_expired_session_packets = 1;
        previous.outbound_dropped_expired_session_payload_bytes = 64;
        previous.outbound_dropped_oversized_packets = 1;
        previous.outbound_dropped_oversized_payload_bytes = 80;
        previous.outbound_dropped_oversized_datagram_bytes = 120;
        previous.outbound_dropped_socket_error_packets = 1;
        previous.outbound_dropped_socket_error_payload_bytes = 88;
        previous.outbound_dropped_socket_error_datagram_bytes = 132;
        previous.outbound_dropped_non_wireguard_packets = 2;
        previous.outbound_dropped_non_wireguard_payload_bytes = 100;
        previous.inbound_dropped_expired_session_packets = 1;
        previous.inbound_dropped_expired_session_payload_bytes = 48;
        previous.inbound_dropped_oversized_packets = 1;
        previous.inbound_dropped_oversized_payload_bytes = 72;
        previous.inbound_dropped_socket_error_packets = 1;
        previous.inbound_dropped_socket_error_payload_bytes = 56;
        previous.inbound_dropped_non_wireguard_packets = 1;
        previous.inbound_dropped_non_wireguard_payload_bytes = 50;
        let mut current = agent_forwarder_metrics("peer-a", "relay-a", 9, 850, 1050, 7, 700);
        current.socket_receive_errors = 5;
        current.outbound_dropped_unexpected_source_packets = 3;
        current.outbound_dropped_unexpected_source_payload_bytes = 96;
        current.outbound_dropped_expired_session_packets = 4;
        current.outbound_dropped_expired_session_payload_bytes = 160;
        current.outbound_dropped_oversized_packets = 5;
        current.outbound_dropped_oversized_payload_bytes = 208;
        current.outbound_dropped_oversized_datagram_bytes = 280;
        current.outbound_dropped_socket_error_packets = 4;
        current.outbound_dropped_socket_error_payload_bytes = 168;
        current.outbound_dropped_socket_error_datagram_bytes = 252;
        current.outbound_dropped_non_wireguard_packets = 5;
        current.outbound_dropped_non_wireguard_payload_bytes = 140;
        current.inbound_dropped_expired_session_packets = 5;
        current.inbound_dropped_expired_session_payload_bytes = 144;
        current.inbound_dropped_oversized_packets = 3;
        current.inbound_dropped_oversized_payload_bytes = 136;
        current.inbound_dropped_socket_error_packets = 5;
        current.inbound_dropped_socket_error_payload_bytes = 184;
        current.inbound_dropped_non_wireguard_packets = 3;
        current.inbound_dropped_non_wireguard_payload_bytes = 90;

        let delta = agent_forwarder_delta(&current, Some(&previous));

        assert_eq!(delta.socket_receive_errors, 3);
        assert_eq!(delta.outbound_packets, 4);
        assert_eq!(delta.outbound_payload_bytes, 350);
        assert_eq!(delta.outbound_datagram_bytes, 430);
        assert_eq!(delta.outbound_dropped_unexpected_source_packets, 2);
        assert_eq!(delta.outbound_dropped_unexpected_source_payload_bytes, 64);
        assert_eq!(delta.outbound_dropped_expired_session_packets, 3);
        assert_eq!(delta.outbound_dropped_expired_session_payload_bytes, 96);
        assert_eq!(delta.outbound_dropped_oversized_packets, 4);
        assert_eq!(delta.outbound_dropped_oversized_payload_bytes, 128);
        assert_eq!(delta.outbound_dropped_oversized_datagram_bytes, 160);
        assert_eq!(delta.outbound_dropped_socket_error_packets, 3);
        assert_eq!(delta.outbound_dropped_socket_error_payload_bytes, 80);
        assert_eq!(delta.outbound_dropped_socket_error_datagram_bytes, 120);
        assert_eq!(delta.outbound_dropped_non_wireguard_packets, 3);
        assert_eq!(delta.outbound_dropped_non_wireguard_payload_bytes, 40);
        assert_eq!(delta.inbound_packets, 4);
        assert_eq!(delta.inbound_payload_bytes, 400);
        assert_eq!(delta.inbound_dropped_expired_session_packets, 4);
        assert_eq!(delta.inbound_dropped_expired_session_payload_bytes, 96);
        assert_eq!(delta.inbound_dropped_oversized_packets, 2);
        assert_eq!(delta.inbound_dropped_oversized_payload_bytes, 64);
        assert_eq!(delta.inbound_dropped_socket_error_packets, 4);
        assert_eq!(delta.inbound_dropped_socket_error_payload_bytes, 128);
        assert_eq!(delta.inbound_dropped_non_wireguard_packets, 2);
        assert_eq!(delta.inbound_dropped_non_wireguard_payload_bytes, 40);
        assert!(has_agent_forwarder_delta(&delta));
    }

    #[test]
    fn agent_otel_delta_skips_unchanged_forwarders() {
        let forwarder = agent_forwarder_metrics("peer-a", "relay-a", 5, 500, 620, 3, 300);
        let metrics = agent_metrics_with_category_counts(forwarder);
        let previous = AgentOtelSnapshot::from(&metrics);

        assert_eq!(
            previous
                .relay_admission_failure_reason_counts
                .get(&AgentRelayAdmissionFailureReason::Rejected),
            Some(&1)
        );
        assert_eq!(
            previous
                .packet_flow_duplicate_suppression_counts
                .get(&AgentPacketFlowDuplicateSource::EbpfRingbuf),
            Some(&5)
        );
        assert!(agent_forwarder_deltas(&metrics, Some(&previous)).is_empty());
    }

    #[test]
    fn agent_otel_category_deltas_zero_fill_all_known_labels() {
        let forwarder = agent_forwarder_metrics("peer-a", "relay-a", 5, 500, 620, 3, 300);
        let metrics = agent_metrics_with_category_counts(forwarder);

        let relay_admission_delta = agent_relay_admission_failure_reason_delta(&metrics, None);
        assert_eq!(
            relay_admission_delta.len(),
            AgentRelayAdmissionFailureReason::ALL.len()
        );
        assert_eq!(
            relay_admission_delta.get(&AgentRelayAdmissionFailureReason::Rejected),
            Some(&1)
        );
        assert_eq!(
            relay_admission_delta.get(&AgentRelayAdmissionFailureReason::Unavailable),
            Some(&0)
        );

        let filtered_delta = agent_packet_flow_filtered_reason_delta(&metrics, None);
        assert_eq!(filtered_delta.len(), AgentPacketFlowDropReason::ALL.len());
        assert_eq!(
            filtered_delta.get(&AgentPacketFlowDropReason::Multicast),
            Some(&3)
        );
        assert_eq!(
            filtered_delta.get(&AgentPacketFlowDropReason::NoOverlayMatch),
            Some(&0)
        );

        let duplicate_delta = agent_packet_flow_duplicate_suppression_source_delta(&metrics, None);
        assert_eq!(
            duplicate_delta.len(),
            AgentPacketFlowDuplicateSource::ALL.len()
        );
        assert_eq!(
            duplicate_delta.get(&AgentPacketFlowDuplicateSource::EbpfRingbuf),
            Some(&5)
        );
        assert_eq!(
            duplicate_delta.get(&AgentPacketFlowDuplicateSource::ProcNetConntrack),
            Some(&0)
        );

        let classification_delta = agent_packet_flow_classification_delta(&metrics, None);
        assert_eq!(
            classification_delta.len(),
            AgentPacketFlowClassification::ALL.len()
        );
        assert_eq!(
            classification_delta.get(&AgentPacketFlowClassification::Established),
            Some(&2)
        );
        assert_eq!(
            classification_delta.get(&AgentPacketFlowClassification::Closed),
            Some(&0)
        );

        let application_delta = agent_packet_flow_application_delta(&metrics, None);
        assert_eq!(
            application_delta.len(),
            AgentPacketFlowApplication::ALL.len()
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::WireGuard),
            Some(&2)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Dns),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Dhcp),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Ike),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Ipsec),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Gre),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Consul),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Vault),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Nomad),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Jaeger),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Loki),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Tempo),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Zipkin),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::ClickHouse),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::InfluxDb),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Nfs),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Syslog),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Snmp),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Kerberos),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Ntp),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Radius),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Tacacs),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Bgp),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Bfd),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Vxlan),
            Some(&0)
        );
        assert_eq!(
            application_delta.get(&AgentPacketFlowApplication::Geneve),
            Some(&0)
        );

        let previous = AgentOtelSnapshot::from(&metrics);
        assert!(
            agent_relay_admission_failure_reason_delta(&metrics, Some(&previous))
                .values()
                .all(|count| *count == 0)
        );
        assert!(
            agent_packet_flow_filtered_reason_delta(&metrics, Some(&previous))
                .values()
                .all(|count| *count == 0)
        );
        assert!(
            agent_packet_flow_duplicate_suppression_source_delta(&metrics, Some(&previous))
                .values()
                .all(|count| *count == 0)
        );
        assert!(
            agent_packet_flow_classification_delta(&metrics, Some(&previous))
                .values()
                .all(|count| *count == 0)
        );
        assert!(
            agent_packet_flow_application_delta(&metrics, Some(&previous))
                .values()
                .all(|count| *count == 0)
        );
    }

    #[test]
    fn otel_generated_timestamp_seconds_uses_unix_seconds_and_clamps_pre_epoch() {
        let generated_at = Utc
            .timestamp_opt(1_725_000_123, 987_000_000)
            .single()
            .unwrap();
        let pre_epoch = Utc.timestamp_opt(-1, 0).single().unwrap();

        assert_eq!(
            otel_generated_timestamp_seconds(&generated_at),
            1_725_000_123
        );
        assert_eq!(otel_generated_timestamp_seconds(&pre_epoch), 0);
    }

    async fn insert_dead_forwarder(
        supervisor: &RelayForwarderSupervisor,
        runtime: &AgentRuntime,
        peer: &NodeId,
        session_id: &str,
    ) {
        let local_endpoint = SocketAddr::from(([127, 0, 0, 1], 42_000));
        runtime
            .upsert_relay_forwarder_endpoint(peer.clone(), local_endpoint)
            .await;
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async {
            Err(AgentError::RelaySession(
                "synthetic forwarder death".to_string(),
            ))
        });
        supervisor.handles.lock().await.insert(
            peer.clone(),
            RelayForwarderTask {
                session_id: session_id.to_string(),
                relay_endpoint: SocketAddr::from(([127, 0, 0, 1], 40_000)),
                local_endpoint,
                shutdown_tx,
                task,
            },
        );
        tokio::task::yield_now().await;
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
    fn agent_args_accepts_linux_netns() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--join-token-path",
            "/var/lib/ipars/token/token",
            "--relay-public-endpoint",
            "203.0.113.30:51820",
            "--relay-admission-url",
            "http://relay-a:9580",
            "--relay-status-url",
            "http://relay-a:9580",
            "--relay-admission-bearer-token",
            "cluster-relay-secret",
            "--relay-max-sessions",
            "500",
            "--relay-max-mbps",
            "250",
            "--linux-netns",
            "node-a",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-session-renew-before-seconds",
            "45",
            "--relay-forwarder-endpoint",
            "127.0.0.1:52000",
            "--relay-forwarder-bind",
            "127.0.0.1:0",
            "--relay-forwarder-wireguard-endpoint",
            "127.0.0.1:51820",
            "--relay-forwarder-max-sessions",
            "7",
            "--relay-forwarder-restart-backoff-seconds",
            "11",
            "--relay-forwarder-crash-window-seconds",
            "22",
            "--relay-forwarder-max-crashes-per-window",
            "4",
            "--relay-forwarder-crash-cooldown-seconds",
            "33",
            "--apply-kubernetes-underlay",
            "--kubernetes-node-name",
            "worker-a",
            "--kubernetes-api-server-cidr",
            "10.0.0.1/32",
            "--kubernetes-service-cidr",
            "10.96.0.0/12",
            "--kubernetes-route-provider",
            "route-provider-a",
            "--kubernetes-route-interval-seconds",
            "15",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert_eq!(
                args.join_token_path.as_deref(),
                Some(Path::new("/var/lib/ipars/token/token"))
            );
            let relay_capability =
                agent_relay_capability(&args).context("expected relay capability")?;
            assert_eq!(
                relay_capability.public_endpoint,
                Some(SocketAddr::from(([203, 0, 113, 30], 51_820)))
            );
            assert_eq!(
                relay_capability.admission_url.as_deref(),
                Some("http://relay-a:9580")
            );
            let reporter =
                agent_relay_capability_reporter(&args)?.context("expected relay reporter")?;
            assert_eq!(reporter.status_url.as_deref(), Some("http://relay-a:9580"));
            assert_eq!(
                args.relay_admission_bearer_token.as_deref(),
                Some("cluster-relay-secret")
            );
            assert!(!relay_capability.enabled_by_policy);
            assert_eq!(relay_capability.max_sessions, 500);
            assert_eq!(relay_capability.max_mbps, 250);
            assert_eq!(args.linux_netns.as_deref(), Some("node-a"));
            assert_eq!(args.runtime_backend, AgentRuntimeBackend::DryRun);
            assert!(args.skip_runtime_preflight);
            assert_eq!(args.relay_session_renew_before_seconds, 45);
            assert_eq!(
                args.relay_forwarder_endpoint,
                Some(SocketAddr::from(([127, 0, 0, 1], 52_000)))
            );
            assert_eq!(
                args.relay_forwarder_bind,
                Some(SocketAddr::from(([127, 0, 0, 1], 0)))
            );
            assert_eq!(
                args.relay_forwarder_wireguard_endpoint,
                Some(SocketAddr::from(([127, 0, 0, 1], 51_820)))
            );
            assert_eq!(args.relay_forwarder_max_sessions, 7);
            assert_eq!(args.relay_forwarder_restart_backoff_seconds, 11);
            assert_eq!(args.relay_forwarder_crash_window_seconds, 22);
            assert_eq!(args.relay_forwarder_max_crashes_per_window, 4);
            assert_eq!(args.relay_forwarder_crash_cooldown_seconds, 33);
            let supervisor = relay_forwarder_supervisor(&args)?.context("expected supervisor")?;
            assert_eq!(supervisor.config.max_sessions, 7);
            assert_eq!(supervisor.config.restart_backoff, Duration::from_secs(11));
            assert_eq!(
                supervisor.config.crash_policy.window,
                Duration::from_secs(22)
            );
            assert_eq!(supervisor.config.crash_policy.max_crashes_per_window, 4);
            assert_eq!(
                supervisor.config.crash_policy.cooldown,
                Duration::from_secs(33)
            );
            assert_eq!(
                supervisor.config.placement,
                RelayForwarderPlacement::LinuxNetns(LinuxNetworkNamespace::from_name("node-a")?)
            );
            assert!(args.apply_kubernetes_underlay);
            assert_eq!(args.kubernetes_node_name.as_deref(), Some("worker-a"));
            assert_eq!(
                args.kubernetes_api_server_cidrs,
                vec!["10.0.0.1/32".parse::<ipnet::IpNet>()?]
            );
            assert_eq!(
                args.kubernetes_service_cidrs,
                vec!["10.96.0.0/12".parse::<ipnet::IpNet>()?]
            );
            assert_eq!(
                args.kubernetes_route_provider.as_deref(),
                Some("route-provider-a")
            );
            assert_eq!(args.kubernetes_route_interval_seconds, 15);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn agent_relay_capability_requires_endpoint_and_admission_url() {
        let missing_url = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--relay-public-endpoint",
            "203.0.113.30:51820",
        ]);
        assert!(missing_url.is_err());

        let missing_endpoint = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--relay-admission-url",
            "http://relay-a:9580",
        ]);
        assert!(missing_endpoint.is_err());
    }

    #[test]
    fn agent_relay_capability_reporter_validates_advertisement_config() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-public-endpoint",
            "203.0.113.30:51820",
            "--relay-admission-url",
            "http://0.0.0.0:9580",
        ])?;
        let Command::Agent(args) = cli.command else {
            anyhow::bail!("expected agent command");
        };

        let error = match agent_relay_capability_reporter(&args) {
            Ok(_) => anyhow::bail!("unexpected valid relay capability reporter"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--relay-admission-url"));
        assert!(error.to_string().contains("usable non-unspecified"));
        Ok(())
    }

    #[test]
    fn agent_relay_capability_config_rejects_incomplete_or_zero_capacity() -> anyhow::Result<()> {
        let status_without_advertisement = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-status-url",
            "http://relay-a:9580",
        ])?;
        if let Command::Agent(args) = status_without_advertisement.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(
                "--relay-status-url requires --relay-public-endpoint and --relay-admission-url"
            ));
        } else {
            anyhow::bail!("expected agent command");
        }

        let zero_sessions = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-public-endpoint",
            "203.0.113.30:51820",
            "--relay-admission-url",
            "http://relay-a:9580",
            "--relay-max-sessions",
            "0",
        ])?;
        if let Command::Agent(args) = zero_sessions.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--relay-max-sessions must be greater than zero"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let zero_mbps = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-public-endpoint",
            "203.0.113.30:51820",
            "--relay-admission-url",
            "http://relay-a:9580",
            "--relay-max-mbps",
            "0",
        ])?;
        if let Command::Agent(args) = zero_mbps.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--relay-max-mbps must be greater than zero"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let unusable_public_endpoint = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-public-endpoint",
            "0.0.0.0:51820",
            "--relay-admission-url",
            "http://relay-a:9580",
        ])?;
        if let Command::Agent(args) = unusable_public_endpoint.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("--relay-public-endpoint"));
            assert!(error.to_string().contains("usable nonzero"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let invalid_admission_url = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-public-endpoint",
            "203.0.113.30:51820",
            "--relay-admission-url",
            "relay-a",
        ])?;
        if let Command::Agent(args) = invalid_admission_url.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--relay-admission-url must be an absolute URL"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let unusable_admission_url = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-public-endpoint",
            "203.0.113.30:51820",
            "--relay-admission-url",
            "http://0.0.0.0:9580",
        ])?;
        if let Command::Agent(args) = unusable_admission_url.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("--relay-admission-url"));
            assert!(error.to_string().contains("usable non-unspecified"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let invalid_status_url = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-public-endpoint",
            "203.0.113.30:51820",
            "--relay-admission-url",
            "http://relay-a:9580",
            "--relay-status-url",
            "ftp://relay-a/status",
        ])?;
        if let Command::Agent(args) = invalid_status_url.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--relay-status-url must use http or https"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let unusable_status_url = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-public-endpoint",
            "203.0.113.30:51820",
            "--relay-admission-url",
            "http://relay-a:9580",
            "--relay-status-url",
            "http://0.0.0.0:9580",
        ])?;
        if let Command::Agent(args) = unusable_status_url.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("--relay-status-url"));
            assert!(error.to_string().contains("usable non-unspecified"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let invalid_bearer = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-admission-bearer-token",
            "not allowed",
        ])?;
        if let Command::Agent(args) = invalid_bearer.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--relay-admission-bearer-token must not contain whitespace"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn agent_join_token_can_be_loaded_from_file() -> anyhow::Result<()> {
        let path = std::env::temp_dir().join(format!(
            "iparsd-agent-token-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let token = serde_json::to_string(&token_with_bootstrap(Vec::new()))?;
        std::fs::write(&path, format!(" {token}\n"))?;
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--join-token-path",
            path.to_str()
                .context("temporary token path must be valid UTF-8")?,
        ])?;

        let loaded = if let Command::Agent(args) = cli.command {
            agent_join_token(&args)?
        } else {
            anyhow::bail!("expected agent command");
        };

        assert_eq!(
            loaded.map(|token| token.claims.cluster_id),
            Some(ClusterId::from_string("cluster-a"))
        );
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn agent_join_token_path_rejects_directory_and_oversized_file() -> anyhow::Result<()> {
        let base = unique_test_dir("agent-token-path-validation")?;
        let directory_token = base.join("token-dir");
        std::fs::create_dir(&directory_token)?;
        let directory_error = match read_agent_join_token_file(&directory_token) {
            Ok(_) => anyhow::bail!("directory token path should be rejected"),
            Err(error) => error,
        };
        assert!(directory_error
            .to_string()
            .contains("must resolve to a regular file"));

        let oversized_token = base.join("oversized-token.json");
        std::fs::write(
            &oversized_token,
            "x".repeat(MAX_AGENT_JOIN_TOKEN_BYTES as usize + 1),
        )?;
        let oversized_error = match read_agent_join_token_file(&oversized_token) {
            Ok(_) => anyhow::bail!("oversized token file should be rejected"),
            Err(error) => error,
        };
        assert!(oversized_error.to_string().contains("exceeds maximum size"));

        std::fs::remove_dir_all(base)?;
        Ok(())
    }

    #[test]
    fn agent_join_token_rejects_oversized_inline_token() -> anyhow::Result<()> {
        let oversized_token = "x".repeat(MAX_AGENT_JOIN_TOKEN_BYTES as usize + 1);
        let cli =
            Cli::try_parse_from(["iparsd", "agent", "--join-token", oversized_token.as_str()])?;

        if let Command::Agent(args) = cli.command {
            let error = match raw_agent_join_token(&args) {
                Ok(_) => anyhow::bail!("oversized inline token should fail"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("exceeds maximum size"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn agent_join_token_rejects_inline_and_path_together() {
        let result = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--join-token",
            "{}",
            "--join-token-path",
            "/var/lib/ipars/token/token",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn relay_session_state_uses_advertised_relay_node() -> anyhow::Result<()> {
        let peer = node_record("node-b");
        let relay = node_record("relay-advertised");
        let relay_endpoint = SocketAddr::from(([203, 0, 113, 30], 51_820));
        let request = RelayAdmissionRequest {
            left: NodeId::from_string("node-a"),
            right: peer.node_id.clone(),
            left_addr: SocketAddr::from(([203, 0, 113, 10], 51_820)),
            right_addr: SocketAddr::from(([203, 0, 113, 11], 51_820)),
        };
        let now = Utc::now();
        let response = RelayAdmissionResponse {
            relay_node: NodeId::from_string("relay-daemon-local-name"),
            session_id: "node-a:node-b".to_string(),
            session_token: "relay-secret".to_string(),
            expires_at: now + ChronoDuration::seconds(300),
            left: request.left.clone(),
            right: request.right.clone(),
            left_addr: request.left_addr,
            right_addr: request.right_addr,
        };

        let session = relay_session_state_from_admission(
            &peer,
            &relay,
            &request,
            response,
            relay_endpoint,
            now,
        )?;

        assert_eq!(session.peer, NodeId::from_string("node-b"));
        assert_eq!(session.relay_node, NodeId::from_string("relay-advertised"));
        assert_eq!(session.relay_endpoint, relay_endpoint);
        assert_eq!(
            session.admitted_local_addr,
            SocketAddr::from(([203, 0, 113, 10], 51_820))
        );
        assert_eq!(
            session.admitted_peer_addr,
            SocketAddr::from(([203, 0, 113, 11], 51_820))
        );
        Ok(())
    }

    #[test]
    fn relay_session_state_maps_admitted_addrs_to_local_view() -> anyhow::Result<()> {
        let peer = node_record("node-a");
        let relay = node_record("relay-advertised");
        let relay_endpoint = SocketAddr::from(([203, 0, 113, 30], 51_820));
        let now = Utc::now();
        let request = RelayAdmissionRequest {
            left: peer.node_id.clone(),
            right: NodeId::from_string("node-z"),
            left_addr: SocketAddr::from(([203, 0, 113, 11], 51_820)),
            right_addr: SocketAddr::from(([203, 0, 113, 10], 51_820)),
        };
        let response = RelayAdmissionResponse {
            relay_node: NodeId::from_string("relay-daemon-local-name"),
            session_id: "node-a:node-z".to_string(),
            session_token: "relay-secret".to_string(),
            expires_at: now + ChronoDuration::seconds(300),
            left: request.left.clone(),
            right: request.right.clone(),
            left_addr: request.left_addr,
            right_addr: request.right_addr,
        };

        let session = relay_session_state_from_admission(
            &peer,
            &relay,
            &request,
            response,
            relay_endpoint,
            now,
        )?;

        assert_eq!(
            session.admitted_local_addr,
            SocketAddr::from(([203, 0, 113, 10], 51_820))
        );
        assert_eq!(
            session.admitted_peer_addr,
            SocketAddr::from(([203, 0, 113, 11], 51_820))
        );
        Ok(())
    }

    #[test]
    fn relay_session_state_rejects_inconsistent_admission_response() -> anyhow::Result<()> {
        let peer = node_record("node-b");
        let relay = node_record("relay-a");
        let request = RelayAdmissionRequest {
            left: NodeId::from_string("node-a"),
            right: peer.node_id.clone(),
            left_addr: SocketAddr::from(([203, 0, 113, 10], 51_820)),
            right_addr: SocketAddr::from(([203, 0, 113, 11], 51_820)),
        };
        let now = Utc::now();
        let valid_response = RelayAdmissionResponse {
            relay_node: relay.node_id.clone(),
            session_id: "node-a:node-b".to_string(),
            session_token: "relay-secret".to_string(),
            expires_at: now + ChronoDuration::seconds(300),
            left: request.left.clone(),
            right: request.right.clone(),
            left_addr: request.left_addr,
            right_addr: request.right_addr,
        };
        let relay_endpoint = SocketAddr::from(([203, 0, 113, 30], 51_820));

        let mut wrong_pair = valid_response.clone();
        wrong_pair.right = NodeId::from_string("node-c");
        let error = match relay_session_state_from_admission(
            &peer,
            &relay,
            &request,
            wrong_pair,
            relay_endpoint,
            now,
        ) {
            Ok(session) => anyhow::bail!("wrong node pair should be rejected: {session:?}"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("node pair mismatch"));

        let mut wrong_endpoint = valid_response.clone();
        wrong_endpoint.right_addr = SocketAddr::from(([203, 0, 113, 99], 51_820));
        let error = match relay_session_state_from_admission(
            &peer,
            &relay,
            &request,
            wrong_endpoint,
            relay_endpoint,
            now,
        ) {
            Ok(session) => anyhow::bail!("wrong endpoint should be rejected: {session:?}"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("endpoint mismatch"));

        let mut wrong_session_id = valid_response.clone();
        wrong_session_id.session_id = "node-a:node-c".to_string();
        let error = match relay_session_state_from_admission(
            &peer,
            &relay,
            &request,
            wrong_session_id,
            relay_endpoint,
            now,
        ) {
            Ok(session) => anyhow::bail!("wrong session id should be rejected: {session:?}"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("session id mismatch"));

        let mut expired = valid_response.clone();
        expired.expires_at = now - ChronoDuration::seconds(1);
        let error = match relay_session_state_from_admission(
            &peer,
            &relay,
            &request,
            expired,
            relay_endpoint,
            now,
        ) {
            Ok(session) => anyhow::bail!("expired credential should be rejected: {session:?}"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("already expired"));

        let mut invalid_credential = valid_response;
        invalid_credential.session_token.clear();
        let error = match relay_session_state_from_admission(
            &peer,
            &relay,
            &request,
            invalid_credential,
            relay_endpoint,
            now,
        ) {
            Ok(session) => anyhow::bail!("invalid credential should be rejected: {session:?}"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("invalid session credential"));
        Ok(())
    }

    #[test]
    fn relay_status_url_accepts_base_or_full_status_url() {
        assert_eq!(
            relay_status_url("http://127.0.0.1:9580/"),
            "http://127.0.0.1:9580/v1/status"
        );
        assert_eq!(
            relay_status_url("http://127.0.0.1:9580/v1/status"),
            "http://127.0.0.1:9580/v1/status"
        );
    }

    #[test]
    fn relay_capability_status_refresh_preserves_advertised_endpoints() {
        let advertised = RelayCapability {
            enabled_by_policy: false,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 30], 51_820))),
            admission_url: Some("http://public-relay:9580".to_string()),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        };
        let status = RelayStatusResponse {
            relay_node: NodeId::from_string("relay-a"),
            capability: RelayCapability {
                enabled_by_policy: true,
                public_endpoint: Some(SocketAddr::from(([127, 0, 0, 1], 51_820))),
                admission_url: Some("http://127.0.0.1:9580".to_string()),
                max_sessions: 250,
                active_sessions: 12,
                max_mbps: 500,
                e2e_only: true,
            },
            health: HealthState::Healthy,
            admission_attempt_count: 0,
            admission_success_count: 0,
            admission_failure_count: 0,
            admission_failures_by_reason: BTreeMap::new(),
            max_sessions_per_node: Some(20),
            dataplane: RelayDataplaneMetrics::default(),
            generated_at: Utc::now(),
        };

        let refreshed = relay_capability_from_status(&advertised, &status);

        assert_eq!(refreshed.public_endpoint, advertised.public_endpoint);
        assert_eq!(refreshed.admission_url, advertised.admission_url);
        assert!(!refreshed.enabled_by_policy);
        assert_eq!(refreshed.max_sessions, 250);
        assert_eq!(refreshed.active_sessions, 12);
        assert_eq!(refreshed.max_mbps, 500);
    }

    #[tokio::test]
    async fn heartbeat_relay_capability_omits_unhealthy_status() -> anyhow::Result<()> {
        async fn degraded_status() -> axum::Json<RelayStatusResponse> {
            axum::Json(test_relay_status_response(HealthState::Degraded, 250, 12))
        }

        let (relay_base, relay_task) = spawn_test_http_service(
            Router::new().route("/v1/status", axum::routing::get(degraded_status)),
        )
        .await?;
        let reporter = RelayCapabilityReporter {
            advertised: test_relay_capability(100, 0),
            status_url: Some(relay_base),
        };

        let capability = heartbeat_relay_capability(&reqwest::Client::new(), Some(&reporter)).await;

        assert!(capability.is_none());
        relay_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_relay_capability_omits_unreachable_status_url() -> anyhow::Result<()> {
        let reporter = RelayCapabilityReporter {
            advertised: test_relay_capability(100, 0),
            status_url: Some(unused_http_base_url().await?),
        };

        let capability = heartbeat_relay_capability(&reqwest::Client::new(), Some(&reporter)).await;

        assert!(capability.is_none());
        Ok(())
    }

    #[test]
    fn agent_args_default_to_linux_command_runtime_backend() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["iparsd", "agent"])?;

        if let Command::Agent(args) = cli.command {
            assert_eq!(args.runtime_backend, AgentRuntimeBackend::LinuxCommand);
            assert_eq!(args.runtime_backend.as_str(), "linux-command");
            assert_eq!(args.wireguard_backend, WireGuardApplyBackend::Command);
            assert_eq!(args.wireguard_backend.as_str(), "command");
            assert_eq!(args.route_backend, RouteApplyBackend::Command);
            assert_eq!(args.route_backend.as_str(), "command");
            assert_eq!(args.runtime_command_timeout_seconds, 30);
            assert_eq!(args.runtime_command_output_max_bytes, 65_536);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn agent_args_accept_packet_flow_detector() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--packet-flow-detector",
            "proc-net-conntrack",
            "--packet-flow-conntrack-path",
            "/tmp/ipars-conntrack",
            "--packet-flow-poll-interval-seconds",
            "2",
            "--packet-flow-dedup-ttl-seconds",
            "9",
            "--packet-flow-procfs-max-bytes",
            "1048576",
            "--packet-flow-procfs-max-line-bytes",
            "2048",
            "--packet-flow-procfs-max-flows",
            "4096",
            "--packet-flow-pin",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert_eq!(
                args.packet_flow_detector,
                PacketFlowDetector::ProcNetConntrack
            );
            assert_eq!(args.packet_flow_detector.as_str(), "proc-net-conntrack");
            assert_eq!(
                args.packet_flow_conntrack_path.as_deref(),
                Some(Path::new("/tmp/ipars-conntrack"))
            );
            assert_eq!(args.packet_flow_poll_interval_seconds, 2);
            assert_eq!(args.packet_flow_dedup_ttl_seconds, 9);
            assert_eq!(args.packet_flow_procfs_max_bytes, 1_048_576);
            assert_eq!(args.packet_flow_procfs_max_line_bytes, 2048);
            assert_eq!(args.packet_flow_procfs_max_flows, 4096);
            assert_eq!(
                ProcNetConntrackReadLimits::from_args(&args)?,
                ProcNetConntrackReadLimits {
                    max_bytes: 1_048_576,
                    max_line_bytes: 2048,
                    max_flows: 4096,
                }
            );
            assert_eq!(packet_flow_dedup_ttl(0), None);
            assert_eq!(packet_flow_dedup_ttl(9), Some(Duration::from_secs(9)));
            assert!(args.packet_flow_pin);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn agent_procfs_packet_flow_limits_must_be_positive() -> anyhow::Result<()> {
        for (flag, expected) in [
            (
                "--packet-flow-procfs-max-bytes",
                "--packet-flow-procfs-max-bytes must be greater than zero",
            ),
            (
                "--packet-flow-procfs-max-line-bytes",
                "--packet-flow-procfs-max-line-bytes must be greater than zero",
            ),
            (
                "--packet-flow-procfs-max-flows",
                "--packet-flow-procfs-max-flows must be greater than zero",
            ),
        ] {
            let cli = Cli::try_parse_from([
                "iparsd",
                "agent",
                "--packet-flow-detector",
                "proc-net-conntrack",
                flag,
                "0",
            ])?;
            if let Command::Agent(args) = cli.command {
                let error = match validate_agent_runtime_config(&args) {
                    Ok(()) => anyhow::bail!("unexpected valid agent runtime config"),
                    Err(error) => error,
                };
                assert!(
                    error.to_string().contains(expected),
                    "{flag} should fail with {expected}, got {error}"
                );
            } else {
                anyhow::bail!("expected agent command");
            }
        }
        Ok(())
    }

    #[test]
    fn agent_packet_flow_dedup_ttl_may_be_disabled_but_must_be_bounded() -> anyhow::Result<()> {
        let disabled = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--packet-flow-detector",
            "proc-net-conntrack",
            "--packet-flow-dedup-ttl-seconds",
            "0",
        ])?;
        if let Command::Agent(args) = disabled.command {
            validate_agent_runtime_config(&args)?;
            assert_eq!(
                packet_flow_dedup_ttl(args.packet_flow_dedup_ttl_seconds),
                None
            );
        } else {
            anyhow::bail!("expected agent command");
        }

        let oversized = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--packet-flow-detector",
            "proc-net-conntrack",
            "--packet-flow-dedup-ttl-seconds",
            "86401",
        ])?;
        if let Command::Agent(args) = oversized.command {
            let error = match validate_agent_runtime_config(&args) {
                Ok(()) => anyhow::bail!("oversized packet-flow dedup TTL should be rejected"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--packet-flow-dedup-ttl-seconds must not exceed 86400"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn agent_procfs_packet_flow_limits_must_be_bounded() -> anyhow::Result<()> {
        let cases = vec![
            (
                "--packet-flow-procfs-max-bytes",
                (MAX_PACKET_FLOW_READ_BYTES + 1).to_string(),
                format!(
                    "--packet-flow-procfs-max-bytes must not exceed {MAX_PACKET_FLOW_READ_BYTES}"
                ),
            ),
            (
                "--packet-flow-procfs-max-line-bytes",
                (MAX_PACKET_FLOW_LINE_BYTES + 1).to_string(),
                format!(
                    "--packet-flow-procfs-max-line-bytes must not exceed {MAX_PACKET_FLOW_LINE_BYTES}"
                ),
            ),
            (
                "--packet-flow-procfs-max-flows",
                (MAX_PACKET_FLOW_RECORDS + 1).to_string(),
                format!("--packet-flow-procfs-max-flows must not exceed {MAX_PACKET_FLOW_RECORDS}"),
            ),
        ];
        for (flag, value, expected) in cases {
            let cli = Cli::try_parse_from([
                "iparsd",
                "agent",
                "--packet-flow-detector",
                "proc-net-conntrack",
                flag,
                value.as_str(),
            ])?;
            if let Command::Agent(args) = cli.command {
                let error = match validate_agent_runtime_config(&args) {
                    Ok(()) => anyhow::bail!("unexpected valid agent runtime config"),
                    Err(error) => error,
                };
                assert!(
                    error.to_string().contains(&expected),
                    "{flag} should fail with {expected}, got {error}"
                );
            } else {
                anyhow::bail!("expected agent command");
            }
        }
        Ok(())
    }

    #[test]
    fn packet_flow_detector_specific_options_require_matching_detector() -> anyhow::Result<()> {
        for (argv, expected) in [
            (
                vec![
                    "iparsd",
                    "agent",
                    "--packet-flow-detector",
                    "conntrack-netlink",
                    "--packet-flow-conntrack-path",
                    "/tmp/nf_conntrack",
                ],
                "--packet-flow-conntrack-path requires --packet-flow-detector proc-net-conntrack",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--packet-flow-detector",
                    "proc-net-conntrack",
                    "--packet-flow-ebpf-event-path",
                    "/run/ipars/events.jsonl",
                ],
                "--packet-flow-ebpf-event-path requires --packet-flow-detector ebpf-jsonl",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--packet-flow-detector",
                    "ebpf-jsonl",
                    "--packet-flow-ebpf-event-path",
                    "/run/ipars/events.jsonl",
                    "--packet-flow-ebpf-object-path",
                    "/run/ipars/ipars-packet-flow.bpf.o",
                ],
                "--packet-flow-ebpf-object-path requires --packet-flow-detector ebpf-ringbuf",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--packet-flow-detector",
                    "ebpf-jsonl",
                    "--packet-flow-ebpf-event-path",
                    "/run/ipars/events.jsonl",
                    "--packet-flow-ebpf-attach",
                    "ipars_sys_enter_connect:syscalls:sys_enter_connect",
                ],
                "--packet-flow-ebpf-attach requires --packet-flow-detector ebpf-ringbuf",
            ),
            (
                vec!["iparsd", "agent", "--packet-flow-pin"],
                "--packet-flow-pin requires --packet-flow-detector to be enabled",
            ),
        ] {
            let cli = Cli::try_parse_from(argv)?;
            if let Command::Agent(args) = cli.command {
                let error = match validate_agent_runtime_config(&args) {
                    Ok(()) => anyhow::bail!("unexpected valid packet-flow detector config"),
                    Err(error) => error,
                };
                assert!(
                    error.to_string().contains(expected),
                    "expected {expected}, got {error}"
                );
            } else {
                anyhow::bail!("expected agent command");
            }
        }
        Ok(())
    }

    #[test]
    fn agent_args_accept_conntrack_netlink_packet_flow_detector() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--packet-flow-detector",
            "conntrack-netlink",
            "--packet-flow-poll-interval-seconds",
            "3",
            "--packet-flow-netlink-max-flows",
            "8192",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert_eq!(
                args.packet_flow_detector,
                PacketFlowDetector::ConntrackNetlink
            );
            assert_eq!(args.packet_flow_detector.as_str(), "conntrack-netlink");
            assert_eq!(args.packet_flow_poll_interval_seconds, 3);
            assert_eq!(args.packet_flow_netlink_max_flows, 8192);
            assert_eq!(
                ConntrackNetlinkReadLimits::from_args(&args)?,
                ConntrackNetlinkReadLimits { max_flows: 8192 }
            );
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn agent_args_accept_conntrack_netlink_events_packet_flow_detector() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--packet-flow-detector",
            "conntrack-netlink-events",
            "--packet-flow-netlink-max-flows",
            "4096",
            "--packet-flow-pin",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert_eq!(
                args.packet_flow_detector,
                PacketFlowDetector::ConntrackNetlinkEvents
            );
            assert_eq!(
                args.packet_flow_detector.as_str(),
                "conntrack-netlink-events"
            );
            assert_eq!(args.packet_flow_netlink_max_flows, 4096);
            assert!(args.packet_flow_pin);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn agent_args_accept_ebpf_jsonl_packet_flow_detector() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--packet-flow-detector",
            "ebpf-jsonl",
            "--packet-flow-ebpf-event-path",
            "/run/ipars/ebpf-flows.jsonl",
            "--packet-flow-ebpf-event-max-bytes",
            "1048576",
            "--packet-flow-ebpf-event-max-line-bytes",
            "1024",
            "--packet-flow-ebpf-event-max-flows",
            "2048",
            "--packet-flow-pin",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert_eq!(args.packet_flow_detector, PacketFlowDetector::EbpfJsonl);
            assert_eq!(args.packet_flow_detector.as_str(), "ebpf-jsonl");
            assert_eq!(
                args.packet_flow_ebpf_event_path.as_deref(),
                Some(Path::new("/run/ipars/ebpf-flows.jsonl"))
            );
            assert_eq!(args.packet_flow_ebpf_event_max_bytes, 1_048_576);
            assert_eq!(args.packet_flow_ebpf_event_max_line_bytes, 1024);
            assert_eq!(args.packet_flow_ebpf_event_max_flows, 2048);
            assert_eq!(
                EbpfJsonlReadLimits::from_args(&args)?,
                EbpfJsonlReadLimits {
                    max_bytes: 1_048_576,
                    max_line_bytes: 1024,
                    max_flows: 2048,
                }
            );
            assert!(args.packet_flow_pin);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn agent_ebpf_jsonl_packet_flow_config_must_be_complete() -> anyhow::Result<()> {
        let missing_path =
            Cli::try_parse_from(["iparsd", "agent", "--packet-flow-detector", "ebpf-jsonl"])?;
        if let Command::Agent(args) = missing_path.command {
            let error = match validate_agent_runtime_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid agent runtime config"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--packet-flow-ebpf-event-path is required"));
        } else {
            anyhow::bail!("expected agent command");
        }

        for (flag, expected) in [
            (
                "--packet-flow-ebpf-event-max-bytes",
                "--packet-flow-ebpf-event-max-bytes must be greater than zero",
            ),
            (
                "--packet-flow-ebpf-event-max-line-bytes",
                "--packet-flow-ebpf-event-max-line-bytes must be greater than zero",
            ),
            (
                "--packet-flow-ebpf-event-max-flows",
                "--packet-flow-ebpf-event-max-flows must be greater than zero",
            ),
        ] {
            let cli = Cli::try_parse_from([
                "iparsd",
                "agent",
                "--packet-flow-detector",
                "ebpf-jsonl",
                "--packet-flow-ebpf-event-path",
                "/run/ipars/ebpf-flows.jsonl",
                flag,
                "0",
            ])?;
            if let Command::Agent(args) = cli.command {
                let error = match validate_agent_runtime_config(&args) {
                    Ok(()) => anyhow::bail!("unexpected valid agent runtime config"),
                    Err(error) => error,
                };
                assert!(
                    error.to_string().contains(expected),
                    "{flag} should fail with {expected}, got {error}"
                );
            } else {
                anyhow::bail!("expected agent command");
            }
        }
        Ok(())
    }

    #[test]
    fn agent_ebpf_jsonl_packet_flow_limits_must_be_bounded() -> anyhow::Result<()> {
        let cases = vec![
            (
                "--packet-flow-ebpf-event-max-bytes",
                (MAX_PACKET_FLOW_READ_BYTES + 1).to_string(),
                format!(
                    "--packet-flow-ebpf-event-max-bytes must not exceed {MAX_PACKET_FLOW_READ_BYTES}"
                ),
            ),
            (
                "--packet-flow-ebpf-event-max-line-bytes",
                (MAX_PACKET_FLOW_LINE_BYTES + 1).to_string(),
                format!(
                    "--packet-flow-ebpf-event-max-line-bytes must not exceed {MAX_PACKET_FLOW_LINE_BYTES}"
                ),
            ),
            (
                "--packet-flow-ebpf-event-max-flows",
                (MAX_PACKET_FLOW_RECORDS + 1).to_string(),
                format!(
                    "--packet-flow-ebpf-event-max-flows must not exceed {MAX_PACKET_FLOW_RECORDS}"
                ),
            ),
        ];
        for (flag, value, expected) in cases {
            let cli = Cli::try_parse_from([
                "iparsd",
                "agent",
                "--packet-flow-detector",
                "ebpf-jsonl",
                "--packet-flow-ebpf-event-path",
                "/run/ipars/ebpf-flows.jsonl",
                flag,
                value.as_str(),
            ])?;
            if let Command::Agent(args) = cli.command {
                let error = match validate_agent_runtime_config(&args) {
                    Ok(()) => anyhow::bail!("unexpected valid agent runtime config"),
                    Err(error) => error,
                };
                assert!(
                    error.to_string().contains(&expected),
                    "{flag} should fail with {expected}, got {error}"
                );
            } else {
                anyhow::bail!("expected agent command");
            }
        }
        Ok(())
    }

    #[test]
    fn packet_flow_read_limit_configs_revalidate_runtime_boundaries() -> anyhow::Result<()> {
        let procfs_cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--packet-flow-detector",
            "proc-net-conntrack",
            "--packet-flow-procfs-max-bytes",
            "0",
        ])?;
        if let Command::Agent(args) = procfs_cli.command {
            let error = match ProcNetConntrackReadLimits::from_args(&args) {
                Ok(limits) => anyhow::bail!("unexpected procfs read limits: {limits:?}"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--packet-flow-procfs-max-bytes must be greater than zero"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let netlink_limit = (MAX_PACKET_FLOW_RECORDS + 1).to_string();
        let netlink_cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--packet-flow-detector",
            "conntrack-netlink",
            "--packet-flow-netlink-max-flows",
            netlink_limit.as_str(),
        ])?;
        if let Command::Agent(args) = netlink_cli.command {
            let error = match ConntrackNetlinkReadLimits::from_args(&args) {
                Ok(limits) => anyhow::bail!("unexpected netlink read limits: {limits:?}"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(&format!(
                "--packet-flow-netlink-max-flows must not exceed {MAX_PACKET_FLOW_RECORDS}"
            )));
        } else {
            anyhow::bail!("expected agent command");
        }

        let jsonl_cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--packet-flow-detector",
            "ebpf-jsonl",
            "--packet-flow-ebpf-event-path",
            "/run/ipars/ebpf-flows.jsonl",
            "--packet-flow-ebpf-event-max-line-bytes",
            "0",
        ])?;
        if let Command::Agent(args) = jsonl_cli.command {
            let error = match EbpfJsonlReadLimits::from_args(&args) {
                Ok(limits) => anyhow::bail!("unexpected eBPF JSONL read limits: {limits:?}"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--packet-flow-ebpf-event-max-line-bytes must be greater than zero"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let ringbuf_limit = (MAX_PACKET_FLOW_EBPF_RINGBUF_EVENTS_PER_WAKE + 1).to_string();
        let ringbuf_cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--packet-flow-detector",
            "ebpf-ringbuf",
            "--packet-flow-ebpf-object-path",
            "/run/ipars/ipars-packet-flow.bpf.o",
            "--packet-flow-ebpf-attach",
            "ipars_ingress:net:netif_receive_skb",
            "--packet-flow-ebpf-ringbuf-max-events",
            ringbuf_limit.as_str(),
        ])?;
        if let Command::Agent(args) = ringbuf_cli.command {
            let error = match EbpfRingbufReadLimits::from_args(&args) {
                Ok(limits) => anyhow::bail!("unexpected eBPF ringbuf read limits: {limits:?}"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(&format!(
                "--packet-flow-ebpf-ringbuf-max-events must not exceed {MAX_PACKET_FLOW_EBPF_RINGBUF_EVENTS_PER_WAKE}"
            )));
        } else {
            anyhow::bail!("expected agent command");
        }

        Ok(())
    }

    #[test]
    fn runtime_preflight_checks_ebpf_jsonl_event_path() -> anyhow::Result<()> {
        let base = unique_test_dir("ebpf-jsonl-path-preflight")?;
        let regular = base.join("events.jsonl");
        std::fs::write(&regular, b"")?;
        let missing = base.join("missing.jsonl");
        let directory = base.join("events-dir");
        std::fs::create_dir(&directory)?;

        ensure_ebpf_jsonl_event_path_ready(&regular)?;
        ensure_ebpf_jsonl_event_path_ready(&missing)?;

        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--packet-flow-detector",
            "ebpf-jsonl",
            "--packet-flow-ebpf-event-path",
            directory.to_str().context("non-UTF-8 temp path")?,
        ])?;
        if let Command::Agent(args) = cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(!needs.ip_command);
            assert!(!needs.wg_command);
            assert!(needs.ebpf_jsonl_event_path);

            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful eBPF JSONL path preflight"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("must be a regular file"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn runtime_preflight_checks_procfs_conntrack_custom_path() -> anyhow::Result<()> {
        let base = unique_test_dir("conntrack-procfs-path-preflight")?;
        let regular = base.join("nf_conntrack");
        std::fs::write(&regular, b"")?;
        let missing = base.join("missing_conntrack");
        let directory = base.join("conntrack-dir");
        std::fs::create_dir(&directory)?;

        ensure_conntrack_procfs_path_ready(&regular)?;
        ensure_conntrack_procfs_path_ready(&missing)?;

        let default_cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--packet-flow-detector",
            "proc-net-conntrack",
        ])?;
        if let Command::Agent(args) = default_cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(!needs.conntrack_procfs_path);
        } else {
            anyhow::bail!("expected agent command");
        }

        let custom_cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--packet-flow-detector",
            "proc-net-conntrack",
            "--packet-flow-conntrack-path",
            directory.to_str().context("non-UTF-8 temp path")?,
        ])?;
        if let Command::Agent(args) = custom_cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(needs.conntrack_procfs_path);

            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful conntrack path preflight"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("must be a regular file"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn conntrack_procfs_path_preflight_rejects_symlink() -> anyhow::Result<()> {
        let base = unique_test_dir("conntrack-procfs-path-symlink")?;
        let target = base.join("nf_conntrack");
        let link = base.join("nf_conntrack_link");
        std::fs::write(&target, b"")?;
        std::os::unix::fs::symlink(&target, &link)?;

        let error = match ensure_conntrack_procfs_path_ready(&link) {
            Ok(()) => anyhow::bail!("unexpected successful conntrack symlink preflight"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("must not be a symlink"));

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn ebpf_jsonl_event_path_preflight_rejects_symlink() -> anyhow::Result<()> {
        let base = unique_test_dir("ebpf-jsonl-path-symlink")?;
        let target = base.join("events.jsonl");
        let link = base.join("events-link.jsonl");
        std::fs::write(&target, b"")?;
        std::os::unix::fs::symlink(&target, &link)?;

        let error = match ensure_ebpf_jsonl_event_path_ready(&link) {
            Ok(()) => anyhow::bail!("unexpected successful eBPF JSONL symlink preflight"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("must not be a symlink"));

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn agent_args_accept_ebpf_ringbuf_packet_flow_detector() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--packet-flow-detector",
            "ebpf-ringbuf",
            "--packet-flow-ebpf-object-path",
            "/run/ipars/ipars-packet-flow.bpf.o",
            "--packet-flow-ebpf-ringbuf-map",
            "IPARS_PACKET_FLOWS",
            "--packet-flow-ebpf-attach",
            "ipars_ingress:net:netif_receive_skb",
            "--packet-flow-ebpf-attach",
            "ipars_egress:net:net_dev_queue",
            "--packet-flow-ebpf-ringbuf-max-events",
            "128",
            "--packet-flow-pin",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert_eq!(args.packet_flow_detector, PacketFlowDetector::EbpfRingbuf);
            assert_eq!(args.packet_flow_detector.as_str(), "ebpf-ringbuf");
            assert_eq!(
                args.packet_flow_ebpf_object_path.as_deref(),
                Some(Path::new("/run/ipars/ipars-packet-flow.bpf.o"))
            );
            assert_eq!(args.packet_flow_ebpf_ringbuf_map, "IPARS_PACKET_FLOWS");
            assert_eq!(args.packet_flow_ebpf_attach.len(), 2);
            assert_eq!(args.packet_flow_ebpf_ringbuf_max_events, 128);
            assert_eq!(
                EbpfRingbufReadLimits::from_args(&args)?,
                EbpfRingbufReadLimits {
                    max_events_per_wake: 128,
                }
            );
            let config = EbpfRingbufConfig::from_args(&args)?;
            assert_eq!(config.attachments.len(), 2);
            assert_eq!(config.attachments[0].program, "ipars_ingress");
            assert_eq!(config.attachments[0].category, "net");
            assert_eq!(config.attachments[0].name, "netif_receive_skb");
            assert!(args.packet_flow_pin);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn ebpf_ringbuf_config_revalidates_runtime_boundaries() -> anyhow::Result<()> {
        for (argv, expected) in [
            (
                vec![
                    "iparsd",
                    "agent",
                    "--packet-flow-detector",
                    "ebpf-ringbuf",
                    "--packet-flow-ebpf-object-path",
                    "/run/ipars/ipars-packet-flow.bpf.o",
                    "--packet-flow-ebpf-ringbuf-map",
                    "bad/map",
                    "--packet-flow-ebpf-attach",
                    "ipars_ingress:net:netif_receive_skb",
                ],
                "--packet-flow-ebpf-ringbuf-map",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--packet-flow-detector",
                    "ebpf-ringbuf",
                    "--packet-flow-ebpf-object-path",
                    "/run/ipars/ipars-packet-flow.bpf.o",
                ],
                "--packet-flow-ebpf-attach must be set at least once",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--packet-flow-detector",
                    "ebpf-ringbuf",
                    "--packet-flow-ebpf-object-path",
                    "/run/ipars/ipars-packet-flow.bpf.o",
                    "--packet-flow-ebpf-attach",
                    "ipars_ingress:net:netif_receive_skb",
                    "--packet-flow-ebpf-attach",
                    "ipars_ingress:net:netif_receive_skb",
                ],
                "--packet-flow-ebpf-attach must not repeat ipars_ingress:net:netif_receive_skb",
            ),
        ] {
            let cli = Cli::try_parse_from(argv)?;
            if let Command::Agent(args) = cli.command {
                let error = match EbpfRingbufConfig::from_args(&args) {
                    Ok(config) => anyhow::bail!("unexpected valid eBPF ringbuf config: {config:?}"),
                    Err(error) => error,
                };
                assert!(
                    error.to_string().contains(expected),
                    "expected `{expected}`, got `{error}`"
                );
            } else {
                anyhow::bail!("expected agent command");
            }
        }

        Ok(())
    }

    #[test]
    fn agent_ebpf_ringbuf_packet_flow_config_must_be_complete() -> anyhow::Result<()> {
        for (argv, expected) in [
            (
                vec!["iparsd", "agent", "--packet-flow-detector", "ebpf-ringbuf"],
                "--packet-flow-ebpf-object-path is required",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--packet-flow-detector",
                    "ebpf-ringbuf",
                    "--packet-flow-ebpf-object-path",
                    "/run/ipars/ipars-packet-flow.bpf.o",
                ],
                "--packet-flow-ebpf-attach must be set at least once",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--packet-flow-detector",
                    "ebpf-ringbuf",
                    "--packet-flow-ebpf-object-path",
                    "/run/ipars/ipars-packet-flow.bpf.o",
                    "--packet-flow-ebpf-attach",
                    "bad-format",
                ],
                "--packet-flow-ebpf-attach must use PROGRAM:CATEGORY:NAME format",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--packet-flow-detector",
                    "ebpf-ringbuf",
                    "--packet-flow-ebpf-object-path",
                    "/run/ipars/ipars-packet-flow.bpf.o",
                    "--packet-flow-ebpf-attach",
                    "ipars_ingress:net:netif_receive_skb",
                    "--packet-flow-ebpf-attach",
                    "ipars_ingress:net:netif_receive_skb",
                ],
                "--packet-flow-ebpf-attach must not repeat ipars_ingress:net:netif_receive_skb",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--packet-flow-detector",
                    "ebpf-ringbuf",
                    "--packet-flow-ebpf-object-path",
                    "/run/ipars/ipars-packet-flow.bpf.o",
                    "--packet-flow-ebpf-attach",
                    "ipars_ingress:net:netif_receive_skb",
                    "--packet-flow-ebpf-ringbuf-max-events",
                    "0",
                ],
                "--packet-flow-ebpf-ringbuf-max-events must be greater than zero",
            ),
        ] {
            let cli = Cli::try_parse_from(argv)?;
            if let Command::Agent(args) = cli.command {
                let error = match validate_agent_runtime_config(&args) {
                    Ok(()) => anyhow::bail!("unexpected valid agent runtime config"),
                    Err(error) => error,
                };
                assert!(
                    error.to_string().contains(expected),
                    "expected `{expected}`, got `{error}`"
                );
            } else {
                anyhow::bail!("expected agent command");
            }
        }

        let mut too_many_attach = vec![
            "iparsd".to_string(),
            "agent".to_string(),
            "--packet-flow-detector".to_string(),
            "ebpf-ringbuf".to_string(),
            "--packet-flow-ebpf-object-path".to_string(),
            "/run/ipars/ipars-packet-flow.bpf.o".to_string(),
        ];
        for index in 0..=MAX_PACKET_FLOW_EBPF_ATTACH_SPECS {
            too_many_attach.push("--packet-flow-ebpf-attach".to_string());
            too_many_attach.push(format!("ipars_{index}:syscalls:sys_enter_sendto"));
        }
        let cli = Cli::try_parse_from(too_many_attach)?;
        if let Command::Agent(args) = cli.command {
            let error = match validate_agent_runtime_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid eBPF ringbuf config"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--packet-flow-ebpf-attach may be repeated at most 32 times"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let too_many_ringbuf_events =
            (MAX_PACKET_FLOW_EBPF_RINGBUF_EVENTS_PER_WAKE + 1).to_string();
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--packet-flow-detector",
            "ebpf-ringbuf",
            "--packet-flow-ebpf-object-path",
            "/run/ipars/ipars-packet-flow.bpf.o",
            "--packet-flow-ebpf-attach",
            "ipars_ingress:net:netif_receive_skb",
            "--packet-flow-ebpf-ringbuf-max-events",
            too_many_ringbuf_events.as_str(),
        ])?;
        if let Command::Agent(args) = cli.command {
            let error = match validate_agent_runtime_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid eBPF ringbuf config"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(&format!(
                "--packet-flow-ebpf-ringbuf-max-events must not exceed {MAX_PACKET_FLOW_EBPF_RINGBUF_EVENTS_PER_WAKE}"
            )));
        } else {
            anyhow::bail!("expected agent command");
        }
        Ok(())
    }

    #[test]
    fn agent_netlink_packet_flow_limit_must_be_positive() -> anyhow::Result<()> {
        for detector in ["conntrack-netlink", "conntrack-netlink-events"] {
            let cli = Cli::try_parse_from([
                "iparsd",
                "agent",
                "--packet-flow-detector",
                detector,
                "--packet-flow-netlink-max-flows",
                "0",
            ])?;
            if let Command::Agent(args) = cli.command {
                let error = match validate_agent_runtime_config(&args) {
                    Ok(()) => anyhow::bail!("unexpected valid agent runtime config"),
                    Err(error) => error,
                };
                assert!(error
                    .to_string()
                    .contains("--packet-flow-netlink-max-flows must be greater than zero"));
            } else {
                anyhow::bail!("expected agent command");
            }
        }
        Ok(())
    }

    #[test]
    fn agent_netlink_packet_flow_limit_must_be_bounded() -> anyhow::Result<()> {
        let too_many_flows = (MAX_PACKET_FLOW_RECORDS + 1).to_string();
        let expected =
            format!("--packet-flow-netlink-max-flows must not exceed {MAX_PACKET_FLOW_RECORDS}");
        for detector in ["conntrack-netlink", "conntrack-netlink-events"] {
            let cli = Cli::try_parse_from([
                "iparsd",
                "agent",
                "--packet-flow-detector",
                detector,
                "--packet-flow-netlink-max-flows",
                too_many_flows.as_str(),
            ])?;
            if let Command::Agent(args) = cli.command {
                let error = match validate_agent_runtime_config(&args) {
                    Ok(()) => anyhow::bail!("unexpected valid agent runtime config"),
                    Err(error) => error,
                };
                assert!(
                    error.to_string().contains(&expected),
                    "{detector} should fail with {expected}, got {error}"
                );
            } else {
                anyhow::bail!("expected agent command");
            }
        }
        Ok(())
    }

    #[test]
    fn ebpf_jsonl_parser_extracts_packet_flow_events() -> anyhow::Result<()> {
        let mut cursor = EbpfJsonlReadCursor::default();
        let flows = parse_ebpf_jsonl_packet_flow_bytes(
            br#"{"destination":"100.64.0.11","source":"192.0.2.10","protocol":"udp","source_port":50000,"destination_port":51820,"detector":"xdp-flow","application":"wire_guard","conntrack_status":["assured"]}
{"destination":"fd00::42","source":"2001:db8::1","protocol":"tcp","source_port":443,"destination_port":51820,"tcp_state":"established"}
{"destination":"100.64.0.12","protocol":"tcp","payload_prefix":"GET /metrics HTTP/1.1\r\n"}
"#,
            &mut cursor,
            EbpfJsonlReadLimits {
                max_bytes: 4096,
                max_line_bytes: 512,
                max_flows: 16,
            },
        )?;

        assert!(cursor.partial_line.is_empty());
        assert_eq!(flows.len(), 3);
        assert_eq!(flows[0].destination, "100.64.0.11".parse::<IpAddr>()?);
        assert_eq!(flows[0].observation.source, Some("192.0.2.10".parse()?));
        assert_eq!(flows[0].observation.protocol, Some(TransportProtocol::Udp));
        assert_eq!(flows[0].observation.source_port, Some(50000));
        assert_eq!(flows[0].observation.destination_port, Some(51820));
        assert_eq!(flows[0].observation.detector.as_deref(), Some("xdp-flow"));
        assert_eq!(
            flows[0].observation.application,
            Some(AgentPacketFlowApplication::WireGuard)
        );
        assert_eq!(
            flows[0].observation.application(),
            AgentPacketFlowApplication::WireGuard
        );
        assert_eq!(
            flows[0].observation.conntrack_status,
            vec![AgentPacketFlowConntrackStatus::Assured]
        );
        assert_eq!(flows[1].destination, "fd00::42".parse::<IpAddr>()?);
        assert_eq!(flows[1].observation.protocol, Some(TransportProtocol::Tcp));
        assert_eq!(
            flows[1].observation.tcp_state,
            Some(AgentPacketFlowTcpState::Established)
        );
        assert_eq!(flows[2].destination, "100.64.0.12".parse::<IpAddr>()?);
        assert_eq!(
            flows[2].observation.payload_prefix,
            b"GET /metrics HTTP/1.1\r\n"
        );
        assert_eq!(
            flows[2].observation.application(),
            AgentPacketFlowApplication::Prometheus
        );
        Ok(())
    }

    #[test]
    fn ebpf_ringbuf_parser_extracts_packet_flow_events() -> anyhow::Result<()> {
        let mut event = [0_u8; PACKET_FLOW_EVENT_LEN];
        event[0] = PACKET_FLOW_EVENT_VERSION;
        event[1] = PACKET_FLOW_IP_FAMILY_IPV4;
        event[2] = PACKET_FLOW_PROTOCOL_TCP;
        event[3] = PACKET_FLOW_TCP_STATE_ESTABLISHED;
        event[4] = PACKET_FLOW_CONNTRACK_ASSURED;
        event[6..8].copy_from_slice(&443_u16.to_be_bytes());
        event[8..10].copy_from_slice(&6443_u16.to_be_bytes());
        event[16..20].copy_from_slice(&[192, 0, 2, 10]);
        event[32..36].copy_from_slice(&[100, 64, 0, 11]);

        let flow = parse_ebpf_ringbuf_packet_flow_event(&event)?;
        assert_eq!(flow.destination, "100.64.0.11".parse::<IpAddr>()?);
        assert_eq!(flow.observation.source, Some("192.0.2.10".parse()?));
        assert_eq!(flow.observation.protocol, Some(TransportProtocol::Tcp));
        assert_eq!(flow.observation.source_port, Some(443));
        assert_eq!(flow.observation.destination_port, Some(6443));
        assert_eq!(flow.observation.detector.as_deref(), Some("ebpf-ringbuf"));
        assert_eq!(
            flow.observation.conntrack_status,
            vec![AgentPacketFlowConntrackStatus::Assured]
        );
        assert_eq!(
            flow.observation.tcp_state,
            Some(AgentPacketFlowTcpState::Established)
        );

        let mut unknown_source_event = event;
        unknown_source_event[16..32].fill(0);
        let unknown_source_flow = parse_ebpf_ringbuf_packet_flow_event(&unknown_source_event)?;
        assert_eq!(
            unknown_source_flow.destination,
            "100.64.0.11".parse::<IpAddr>()?
        );
        assert_eq!(unknown_source_flow.observation.source, None);

        let mut gre_event = event;
        gre_event[2] = PACKET_FLOW_PROTOCOL_GRE;
        gre_event[3] = PACKET_FLOW_TCP_STATE_UNKNOWN;
        gre_event[6..10].fill(0);
        let gre_flow = parse_ebpf_ringbuf_packet_flow_event(&gre_event)?;
        assert_eq!(gre_flow.observation.protocol, Some(TransportProtocol::Gre));
        assert_eq!(
            gre_flow.observation.application(),
            AgentPacketFlowApplication::Gre
        );
        assert_eq!(gre_flow.observation.source_port, None);
        assert_eq!(gre_flow.observation.destination_port, None);

        let mut esp_event = gre_event;
        esp_event[2] = PACKET_FLOW_PROTOCOL_ESP;
        let esp_flow = parse_ebpf_ringbuf_packet_flow_event(&esp_event)?;
        assert_eq!(esp_flow.observation.protocol, Some(TransportProtocol::Esp));
        assert_eq!(
            esp_flow.observation.application(),
            AgentPacketFlowApplication::Ipsec
        );

        let mut ah_event = gre_event;
        ah_event[2] = PACKET_FLOW_PROTOCOL_AH;
        let ah_flow = parse_ebpf_ringbuf_packet_flow_event(&ah_event)?;
        assert_eq!(ah_flow.observation.protocol, Some(TransportProtocol::Ah));
        assert_eq!(
            ah_flow.observation.application(),
            AgentPacketFlowApplication::Ipsec
        );

        let mut ipip_event = gre_event;
        ipip_event[2] = PACKET_FLOW_PROTOCOL_IPIP;
        let ipip_flow = parse_ebpf_ringbuf_packet_flow_event(&ipip_event)?;
        assert_eq!(
            ipip_flow.observation.protocol,
            Some(TransportProtocol::IpInIp)
        );
        assert_eq!(
            ipip_flow.observation.application(),
            AgentPacketFlowApplication::IpTunnel
        );

        let mut ipv6_encap_event = gre_event;
        ipv6_encap_event[2] = PACKET_FLOW_PROTOCOL_IPV6_ENCAP;
        let ipv6_encap_flow = parse_ebpf_ringbuf_packet_flow_event(&ipv6_encap_event)?;
        assert_eq!(
            ipv6_encap_flow.observation.protocol,
            Some(TransportProtocol::Ipv6Encap)
        );
        assert_eq!(
            ipv6_encap_flow.observation.application(),
            AgentPacketFlowApplication::IpTunnel
        );

        let mut sctp_event = event;
        sctp_event[2] = PACKET_FLOW_PROTOCOL_SCTP;
        sctp_event[3] = PACKET_FLOW_TCP_STATE_UNKNOWN;
        sctp_event[6..8].copy_from_slice(&5000_u16.to_be_bytes());
        sctp_event[8..10].copy_from_slice(&5001_u16.to_be_bytes());
        let sctp_flow = parse_ebpf_ringbuf_packet_flow_event(&sctp_event)?;
        assert_eq!(
            sctp_flow.observation.protocol,
            Some(TransportProtocol::Sctp)
        );
        assert_eq!(sctp_flow.observation.source_port, Some(5000));
        assert_eq!(sctp_flow.observation.destination_port, Some(5001));
        assert_eq!(
            sctp_flow.observation.application(),
            AgentPacketFlowApplication::Unknown
        );

        let source_v6 = "2001:db8::2".parse::<Ipv6Addr>()?;
        let destination_v6 = "fd00::51".parse::<Ipv6Addr>()?;
        let mut icmpv6_event = [0_u8; PACKET_FLOW_EVENT_LEN];
        icmpv6_event[0] = PACKET_FLOW_EVENT_VERSION;
        icmpv6_event[1] = PACKET_FLOW_IP_FAMILY_IPV6;
        icmpv6_event[2] = PACKET_FLOW_PROTOCOL_ICMPV6;
        icmpv6_event[16..32].copy_from_slice(&source_v6.octets());
        icmpv6_event[32..48].copy_from_slice(&destination_v6.octets());
        let icmpv6_flow = parse_ebpf_ringbuf_packet_flow_event(&icmpv6_event)?;
        assert_eq!(icmpv6_flow.destination, IpAddr::V6(destination_v6));
        assert_eq!(
            icmpv6_flow.observation.protocol,
            Some(TransportProtocol::Icmp)
        );
        assert_eq!(
            icmpv6_flow.observation.application(),
            AgentPacketFlowApplication::Icmp
        );
        Ok(())
    }

    #[test]
    fn ebpf_ringbuf_parser_rejects_packet_flow_ipv4_padding_bytes() -> anyhow::Result<()> {
        let mut event = [0_u8; PACKET_FLOW_EVENT_LEN];
        event[0] = PACKET_FLOW_EVENT_VERSION;
        event[1] = PACKET_FLOW_IP_FAMILY_IPV4;
        event[2] = PACKET_FLOW_PROTOCOL_UDP;
        event[16..20].copy_from_slice(&[192, 0, 2, 10]);
        event[32..36].copy_from_slice(&[100, 64, 0, 11]);

        let mut bad_source_padding = event;
        bad_source_padding[20] = 0x01;
        let error = match parse_ebpf_ringbuf_packet_flow_event(&bad_source_padding) {
            Ok(_) => anyhow::bail!("nonzero eBPF IPv4 source padding should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("unsupported eBPF packet-flow IPv4 source padding bytes"));

        let mut bad_destination_padding = event;
        bad_destination_padding[36] = 0x01;
        let error = match parse_ebpf_ringbuf_packet_flow_event(&bad_destination_padding) {
            Ok(_) => anyhow::bail!("nonzero eBPF IPv4 destination padding should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("unsupported eBPF packet-flow IPv4 destination padding bytes"));
        Ok(())
    }

    #[test]
    fn ebpf_ringbuf_parser_handles_ipv6_and_rejects_bad_events() -> anyhow::Result<()> {
        let source = "2001:db8::1".parse::<Ipv6Addr>()?;
        let destination = "fd00::42".parse::<Ipv6Addr>()?;
        let mut event = [0_u8; PACKET_FLOW_EVENT_LEN];
        event[0] = PACKET_FLOW_EVENT_VERSION;
        event[1] = PACKET_FLOW_IP_FAMILY_IPV6;
        event[2] = PACKET_FLOW_PROTOCOL_UDP;
        event[4] = PACKET_FLOW_CONNTRACK_UNREPLIED;
        event[8..10].copy_from_slice(&51820_u16.to_be_bytes());
        event[16..32].copy_from_slice(&source.octets());
        event[32..48].copy_from_slice(&destination.octets());

        let flow = parse_ebpf_ringbuf_packet_flow_event(&event)?;
        assert_eq!(flow.destination, IpAddr::V6(destination));
        assert_eq!(flow.observation.source, Some(IpAddr::V6(source)));
        assert_eq!(flow.observation.protocol, Some(TransportProtocol::Udp));
        assert_eq!(flow.observation.source_port, None);
        assert_eq!(flow.observation.destination_port, Some(51820));
        assert_eq!(
            flow.observation.conntrack_status,
            vec![AgentPacketFlowConntrackStatus::Unreplied]
        );

        let error = match parse_ebpf_ringbuf_packet_flow_event(&event[..8]) {
            Ok(_) => anyhow::bail!("short eBPF ringbuf event should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("expected 48"));

        let mut bad_version = event;
        bad_version[0] = 2;
        let error = match parse_ebpf_ringbuf_packet_flow_event(&bad_version) {
            Ok(_) => anyhow::bail!("unsupported eBPF event version should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("unsupported eBPF packet-flow event version"));

        let mut bad_flags = event;
        bad_flags[5] = 0x01;
        let error = match parse_ebpf_ringbuf_packet_flow_event(&bad_flags) {
            Ok(_) => anyhow::bail!("nonzero eBPF event flags should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("unsupported eBPF packet-flow event flags"));

        let mut bad_reserved = event;
        bad_reserved[10] = 0x01;
        let error = match parse_ebpf_ringbuf_packet_flow_event(&bad_reserved) {
            Ok(_) => anyhow::bail!("nonzero eBPF event reserved bytes should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("unsupported eBPF packet-flow reserved bytes"));

        let mut unsupported_conntrack_status = event;
        unsupported_conntrack_status[4] = PACKET_FLOW_CONNTRACK_UNREPLIED | 0x80;
        let error = match parse_ebpf_ringbuf_packet_flow_event(&unsupported_conntrack_status) {
            Ok(_) => anyhow::bail!("unsupported eBPF conntrack status bits should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("unsupported eBPF packet-flow conntrack status bits"));

        let mut inconsistent_transport_metadata = event;
        inconsistent_transport_metadata[3] = PACKET_FLOW_TCP_STATE_ESTABLISHED;
        let error = match parse_ebpf_ringbuf_packet_flow_event(&inconsistent_transport_metadata) {
            Ok(_) => anyhow::bail!("TCP state on non-TCP eBPF event should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("unsupported eBPF packet-flow TCP state"));

        let mut inconsistent_port_metadata = event;
        inconsistent_port_metadata[2] = PACKET_FLOW_PROTOCOL_ICMP;
        let error = match parse_ebpf_ringbuf_packet_flow_event(&inconsistent_port_metadata) {
            Ok(_) => anyhow::bail!("port metadata on non-port eBPF event should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("unsupported eBPF packet-flow port metadata"));

        let mut unknown_protocol = event;
        unknown_protocol[2] = PACKET_FLOW_PROTOCOL_UNKNOWN;
        unknown_protocol[8..10].copy_from_slice(&0_u16.to_be_bytes());
        let flow = parse_ebpf_ringbuf_packet_flow_event(&unknown_protocol)?;
        assert_eq!(flow.observation.protocol, None);
        assert_eq!(flow.observation.destination_port, None);

        let mut unsupported_protocol = event;
        unsupported_protocol[2] = 253;
        let error = match parse_ebpf_ringbuf_packet_flow_event(&unsupported_protocol) {
            Ok(_) => anyhow::bail!("unsupported eBPF protocol code should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("unsupported eBPF packet-flow protocol code"));
        Ok(())
    }

    #[tokio::test]
    async fn ebpf_ringbuf_privileged_attach_reads_sendto_event() -> anyhow::Result<()> {
        if !env_flag_enabled("IPARS_RUN_EBPF_ATTACH_TESTS") {
            eprintln!(
                "skipping eBPF attach integration test; set IPARS_RUN_EBPF_ATTACH_TESTS=1 to run it"
            );
            return Ok(());
        }

        let object_path = std::env::var_os("IPARS_EBPF_OBJECT_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target/ebpf/ipars-packet-flow.bpf.o"));
        let config = EbpfRingbufConfig {
            object_path,
            ringbuf_map: DEFAULT_PACKET_FLOW_EBPF_RINGBUF_MAP.to_string(),
            attachments: vec![
                EbpfTracepointAttachSpec::parse(
                    "ipars_sys_enter_connect:syscalls:sys_enter_connect",
                )?,
                EbpfTracepointAttachSpec::parse(
                    "ipars_sys_enter_sendto:syscalls:sys_enter_sendto",
                )?,
            ],
        };
        ensure_ebpf_object_file_ready(&config.object_path)?;
        for attachment in &config.attachments {
            ensure_ebpf_tracepoint_ready(attachment)?;
        }

        let mut reader = load_ebpf_ringbuf_packet_flow_reader(&config)?;
        let receiver = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let destination = receiver.local_addr()?;
        let limits = EbpfRingbufReadLimits {
            max_events_per_wake: 512,
        };
        let deadline = Instant::now() + Duration::from_secs(5);

        loop {
            sender.send_to(b"ipars-ebpf-sendto-smoke", destination)?;
            let Ok(guard_result) =
                tokio::time::timeout(Duration::from_millis(250), reader.ringbuf.readable_mut())
                    .await
            else {
                if Instant::now() >= deadline {
                    anyhow::bail!(
                        "timed out waiting for eBPF sendto event for {}",
                        destination
                    );
                }
                continue;
            };
            let mut guard = guard_result.with_context(|| {
                format!(
                    "failed to wait for eBPF packet-flow ring buffer `{}`",
                    config.ringbuf_map
                )
            })?;
            let flows = drain_ebpf_ringbuf_packet_flows(guard.get_inner_mut(), limits)?;
            guard.clear_ready();
            if flows.iter().any(|flow| {
                flow.destination == destination.ip()
                    && flow.observation.destination_port == Some(destination.port())
                    && flow.observation.detector.as_deref() == Some("ebpf-ringbuf")
            }) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let observed = flows
                    .iter()
                    .map(|flow| {
                        format!(
                            "{}:{:?}",
                            flow.destination, flow.observation.destination_port
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                anyhow::bail!(
                    "timed out waiting for eBPF sendto event for {}; last observed [{}]",
                    destination,
                    observed
                );
            }
        }
    }

    #[test]
    fn ebpf_jsonl_parser_retains_partial_lines_and_enforces_limits() -> anyhow::Result<()> {
        let limits = EbpfJsonlReadLimits {
            max_bytes: 4096,
            max_line_bytes: 128,
            max_flows: 1,
        };
        let mut cursor = EbpfJsonlReadCursor::default();
        let flows = parse_ebpf_jsonl_packet_flow_bytes(
            br#"{"destination":"100.64.0."#,
            &mut cursor,
            limits,
        )?;
        assert!(flows.is_empty());
        assert_eq!(
            cursor.partial_line,
            br#"{"destination":"100.64.0."#.to_vec()
        );

        let flows =
            parse_ebpf_jsonl_packet_flow_bytes(br#"11","protocol":"udp"}"#, &mut cursor, limits)?;
        assert!(flows.is_empty());
        assert!(!cursor.partial_line.is_empty());

        let flows = parse_ebpf_jsonl_packet_flow_bytes(
            b"\n{\"destination\":\"100.64.0.12\"}\n",
            &mut cursor,
            limits,
        )?;
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].destination, "100.64.0.11".parse::<IpAddr>()?);

        let error = match parse_ebpf_jsonl_packet_flow_bytes(
            br#"{"destination":"100.64.0.13","detector":"this-line-is-too-long-for-the-test-limit"}
"#,
            &mut EbpfJsonlReadCursor::default(),
            EbpfJsonlReadLimits {
                max_bytes: 4096,
                max_line_bytes: 32,
                max_flows: 16,
            },
        ) {
            Ok(_) => anyhow::bail!("oversized eBPF JSONL line should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("--packet-flow-ebpf-event-max-line-bytes"));

        let oversized_detector = "x".repeat(ipars_types::api::PACKET_FLOW_DETECTOR_MAX_BYTES + 1);
        let oversized_detector_line =
            format!(r#"{{"destination":"100.64.0.13","detector":"{oversized_detector}"}}"#) + "\n";
        let error = match parse_ebpf_jsonl_packet_flow_bytes(
            oversized_detector_line.as_bytes(),
            &mut EbpfJsonlReadCursor::default(),
            EbpfJsonlReadLimits {
                max_bytes: 4096,
                max_line_bytes: 512,
                max_flows: 16,
            },
        ) {
            Ok(_) => anyhow::bail!("oversized eBPF JSONL detector should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .chain()
            .any(|cause| cause.to_string().contains("packet-flow detector exceeds")));

        let error = match parse_ebpf_jsonl_packet_flow_bytes(
            b"{\"destination\":\"100.64.0.13\",\"detector\":\"\"}\n",
            &mut EbpfJsonlReadCursor::default(),
            EbpfJsonlReadLimits {
                max_bytes: 4096,
                max_line_bytes: 512,
                max_flows: 16,
            },
        ) {
            Ok(_) => anyhow::bail!("empty eBPF JSONL detector should be rejected"),
            Err(error) => error,
        };
        assert!(error.chain().any(|cause| cause
            .to_string()
            .contains("packet-flow detector must not be empty")));

        let error = match parse_ebpf_jsonl_packet_flow_bytes(
            b"{\"destination\":\"100.64.0.13\",\"detector\":\"ebpf-jsonl\\nspoof\"}\n",
            &mut EbpfJsonlReadCursor::default(),
            EbpfJsonlReadLimits {
                max_bytes: 4096,
                max_line_bytes: 512,
                max_flows: 16,
            },
        ) {
            Ok(_) => anyhow::bail!("eBPF JSONL detector control characters should be rejected"),
            Err(error) => error,
        };
        assert!(error.chain().any(|cause| cause
            .to_string()
            .contains("packet-flow detector must not contain control characters")));

        let error = match parse_ebpf_jsonl_packet_flow_bytes(
            b"{\"destination\":\"100.64.0.13\",\"detector\":\" ebpf-jsonl\"}\n",
            &mut EbpfJsonlReadCursor::default(),
            EbpfJsonlReadLimits {
                max_bytes: 4096,
                max_line_bytes: 512,
                max_flows: 16,
            },
        ) {
            Ok(_) => anyhow::bail!("eBPF JSONL detector whitespace should be rejected"),
            Err(error) => error,
        };
        assert!(error.chain().any(|cause| cause
            .to_string()
            .contains("packet-flow detector must not contain leading or trailing whitespace")));

        let error = match parse_ebpf_jsonl_packet_flow_bytes(
            b"{\"destination\":\"100.64.0.13\",\"detector\":\"ebpf jsonl\"}\n",
            &mut EbpfJsonlReadCursor::default(),
            EbpfJsonlReadLimits {
                max_bytes: 4096,
                max_line_bytes: 512,
                max_flows: 16,
            },
        ) {
            Ok(_) => anyhow::bail!("eBPF JSONL detector non-token characters should be rejected"),
            Err(error) => error,
        };
        assert!(error.chain().any(|cause| cause.to_string().contains(
            "packet-flow detector must be an ASCII token using letters, digits, '.', '_', or '-'"
        )));

        let error = match parse_ebpf_jsonl_packet_flow_bytes(
            b"{\"destination\":\"100.64.0.13\",\"source\":\"127.0.0.1\"}\n",
            &mut EbpfJsonlReadCursor::default(),
            EbpfJsonlReadLimits {
                max_bytes: 4096,
                max_line_bytes: 512,
                max_flows: 16,
            },
        ) {
            Ok(_) => anyhow::bail!("loopback eBPF JSONL source should be rejected"),
            Err(error) => error,
        };
        assert!(error.chain().any(|cause| cause
            .to_string()
            .contains("source must not use loopback address")));

        let oversized_statuses =
            ["\"assured\""; ipars_types::api::PACKET_FLOW_CONNTRACK_STATUS_MAX_FLAGS + 1].join(",");
        let oversized_status_line =
            format!(r#"{{"destination":"100.64.0.13","conntrack_status":[{oversized_statuses}]}}"#)
                + "\n";
        let error = match parse_ebpf_jsonl_packet_flow_bytes(
            oversized_status_line.as_bytes(),
            &mut EbpfJsonlReadCursor::default(),
            EbpfJsonlReadLimits {
                max_bytes: 4096,
                max_line_bytes: 512,
                max_flows: 16,
            },
        ) {
            Ok(_) => anyhow::bail!("oversized eBPF JSONL conntrack_status should be rejected"),
            Err(error) => error,
        };
        assert!(error.chain().any(|cause| cause
            .to_string()
            .contains("packet-flow conntrack_status exceeds")));

        let inconsistent_transport_line =
            br#"{"destination":"100.64.0.13","protocol":"icmp","destination_port":8}
"#;
        let error = match parse_ebpf_jsonl_packet_flow_bytes(
            inconsistent_transport_line,
            &mut EbpfJsonlReadCursor::default(),
            EbpfJsonlReadLimits {
                max_bytes: 4096,
                max_line_bytes: 512,
                max_flows: 16,
            },
        ) {
            Ok(_) => {
                anyhow::bail!("inconsistent eBPF JSONL packet-flow metadata should be rejected")
            }
            Err(error) => error,
        };
        assert!(error.chain().any(|cause| cause
            .to_string()
            .contains("port metadata requires TCP, UDP, or SCTP protocol")));

        let inconsistent_application_line =
            br#"{"destination":"100.64.0.13","protocol":"icmp","application":"postgres"}
"#;
        let error = match parse_ebpf_jsonl_packet_flow_bytes(
            inconsistent_application_line,
            &mut EbpfJsonlReadCursor::default(),
            EbpfJsonlReadLimits {
                max_bytes: 4096,
                max_line_bytes: 512,
                max_flows: 16,
            },
        ) {
            Ok(_) => anyhow::bail!(
                "protocol-incompatible eBPF JSONL application hint should be rejected"
            ),
            Err(error) => error,
        };
        assert!(error.chain().any(|cause| cause
            .to_string()
            .contains("application hint postgres requires TCP protocol")));
        Ok(())
    }

    #[tokio::test]
    async fn ebpf_jsonl_reader_tails_appended_events() -> anyhow::Result<()> {
        let path = std::env::temp_dir().join(format!(
            "ipars-ebpf-jsonl-reader-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&path, "{\"destination\":\"100.64.0.11\"}\n")?;

        let mut cursor = EbpfJsonlReadCursor::default();
        let limits = EbpfJsonlReadLimits {
            max_bytes: 4096,
            max_line_bytes: 512,
            max_flows: 16,
        };
        let flows = read_ebpf_jsonl_packet_flows(&path, &mut cursor, limits).await?;
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].destination, "100.64.0.11".parse::<IpAddr>()?);

        {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
            file.write_all(b"{\"destination\":\"100.64.0.12\",\"protocol\":\"tcp\"}\n")?;
        }

        let flows = read_ebpf_jsonl_packet_flows(&path, &mut cursor, limits).await?;
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].destination, "100.64.0.12".parse::<IpAddr>()?);
        assert_eq!(flows[0].observation.protocol, Some(TransportProtocol::Tcp));

        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ebpf_jsonl_reader_rejects_symlinked_event_path() -> anyhow::Result<()> {
        let base = unique_test_dir("ebpf-jsonl-reader-symlink")?;
        let target = base.join("events.jsonl");
        let link = base.join("events-link.jsonl");
        std::fs::write(&target, "{\"destination\":\"100.64.0.11\"}\n")?;
        std::os::unix::fs::symlink(&target, &link)?;

        let error = match read_ebpf_jsonl_packet_flows(
            &link,
            &mut EbpfJsonlReadCursor::default(),
            EbpfJsonlReadLimits {
                max_bytes: 4096,
                max_line_bytes: 512,
                max_flows: 16,
            },
        )
        .await
        {
            Ok(_) => anyhow::bail!("unexpected successful symlinked eBPF JSONL read"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("must not be a symlink"));

        let _ = std::fs::remove_dir_all(base);
        Ok(())
    }

    #[test]
    fn conntrack_paths_default_and_override() {
        assert_eq!(
            conntrack_paths(None),
            vec![
                PathBuf::from("/proc/net/nf_conntrack"),
                PathBuf::from("/proc/net/ip_conntrack")
            ]
        );
        assert_eq!(
            conntrack_paths(Some(PathBuf::from("/tmp/conntrack"))),
            vec![PathBuf::from("/tmp/conntrack")]
        );
    }

    #[test]
    fn conntrack_protocol_mapping_includes_tunnel_protocols() {
        assert_eq!(
            transport_protocol_from_ip_number(47),
            Some(TransportProtocol::Gre)
        );
        assert_eq!(
            transport_protocol_from_ip_number(50),
            Some(TransportProtocol::Esp)
        );
        assert_eq!(
            transport_protocol_from_ip_number(51),
            Some(TransportProtocol::Ah)
        );
        assert_eq!(
            transport_protocol_from_ip_number(4),
            Some(TransportProtocol::IpInIp)
        );
        assert_eq!(
            transport_protocol_from_ip_number(41),
            Some(TransportProtocol::Ipv6Encap)
        );
        assert_eq!(
            transport_protocol_from_ip_number(58),
            Some(TransportProtocol::Icmp)
        );
        assert_eq!(
            transport_protocol_from_ip_number(132),
            Some(TransportProtocol::Sctp)
        );
        assert_eq!(
            transport_protocol_from_conntrack_token("gre"),
            Some(TransportProtocol::Gre)
        );
        assert_eq!(
            transport_protocol_from_conntrack_token("esp"),
            Some(TransportProtocol::Esp)
        );
        assert_eq!(
            transport_protocol_from_conntrack_token("ah"),
            Some(TransportProtocol::Ah)
        );
        assert_eq!(
            transport_protocol_from_conntrack_token("ipencap"),
            Some(TransportProtocol::IpInIp)
        );
        assert_eq!(transport_protocol_from_conntrack_token("ipv6"), None);
        assert_eq!(
            transport_protocol_from_conntrack_token("ipv6-encap"),
            Some(TransportProtocol::Ipv6Encap)
        );
        assert_eq!(
            transport_protocol_from_conntrack_token("ipv6-icmp"),
            Some(TransportProtocol::Icmp)
        );
        assert_eq!(
            transport_protocol_from_conntrack_token("sctp"),
            Some(TransportProtocol::Sctp)
        );
    }

    #[test]
    fn conntrack_parser_extracts_destination_ips() -> anyhow::Result<()> {
        let contents = "\
ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=100.64.0.11 sport=54321 dport=51820 src=100.64.0.11 dst=192.0.2.10 sport=51820 dport=54321 [ASSURED]
ipv6 10 udp 17 29 src=2001:db8::1 dst=fd00::42 sport=50000 dport=51820 [UNREPLIED] src=fd00::42 dst=2001:db8::1 sport=51820 dport=50000
invalid no-destination-here
";
        let flows = parse_conntrack_packet_flows(contents, ProcNetConntrackReadLimits::default())?;
        let destinations = flows
            .iter()
            .map(|flow| flow.destination)
            .collect::<BTreeSet<_>>();

        assert!(destinations.contains(&"100.64.0.11".parse()?));
        assert!(destinations.contains(&"192.0.2.10".parse()?));
        assert!(destinations.contains(&"fd00::42".parse()?));
        assert!(destinations.contains(&"2001:db8::1".parse()?));
        assert_eq!(destinations.len(), 4);
        let first_destination: IpAddr = "100.64.0.11".parse()?;
        let first = flows
            .iter()
            .find(|flow| flow.destination == first_destination)
            .context("missing first conntrack flow")?;
        assert_eq!(first.observation.source, Some("192.0.2.10".parse()?));
        assert_eq!(first.observation.protocol, Some(TransportProtocol::Tcp));
        assert_eq!(first.observation.source_port, Some(54321));
        assert_eq!(first.observation.destination_port, Some(51820));
        assert_eq!(
            first.observation.conntrack_status,
            vec![AgentPacketFlowConntrackStatus::Assured]
        );
        assert_eq!(
            first.observation.tcp_state,
            Some(AgentPacketFlowTcpState::Established)
        );
        let udp_destination: IpAddr = "fd00::42".parse()?;
        let udp = flows
            .iter()
            .find(|flow| flow.destination == udp_destination)
            .context("missing udp conntrack flow")?;
        assert_eq!(
            udp.observation.conntrack_status,
            vec![AgentPacketFlowConntrackStatus::Unreplied]
        );
        assert_eq!(udp.observation.tcp_state, None);
        Ok(())
    }

    #[test]
    fn conntrack_parser_enforces_line_and_flow_limits() -> anyhow::Result<()> {
        let contents = "\
ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=100.64.0.11 sport=54321 dport=51820 src=100.64.0.11 dst=192.0.2.10 sport=51820 dport=54321 [ASSURED]
ipv4 2 udp 17 29 src=192.0.2.20 dst=100.64.0.12 sport=50000 dport=51820 src=100.64.0.12 dst=192.0.2.20 sport=51820 dport=50000
";
        let line_error = match parse_conntrack_packet_flows(
            contents,
            ProcNetConntrackReadLimits {
                max_bytes: 4096,
                max_line_bytes: 32,
                max_flows: 32,
            },
        ) {
            Ok(_) => anyhow::bail!("oversized conntrack line should be rejected"),
            Err(error) => error,
        };
        assert!(line_error
            .to_string()
            .contains("--packet-flow-procfs-max-line-bytes"));

        let flows = parse_conntrack_packet_flows(
            contents,
            ProcNetConntrackReadLimits {
                max_bytes: 4096,
                max_line_bytes: 4096,
                max_flows: 2,
            },
        )?;
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].destination, "100.64.0.11".parse::<IpAddr>()?);
        assert_eq!(flows[1].destination, "192.0.2.10".parse::<IpAddr>()?);
        Ok(())
    }

    #[tokio::test]
    async fn conntrack_reader_enforces_byte_limit() -> anyhow::Result<()> {
        let path = std::env::temp_dir().join(format!(
            "ipars-conntrack-reader-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(
            &path,
            "ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=100.64.0.11\n",
        )?;

        let error = match read_conntrack_packet_flows(
            std::slice::from_ref(&path),
            ProcNetConntrackReadLimits {
                max_bytes: 16,
                max_line_bytes: 4096,
                max_flows: 32,
            },
        )
        .await
        {
            Ok(_) => anyhow::bail!("oversized conntrack file should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--packet-flow-procfs-max-bytes"));
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn packet_flow_destination_classifier_keeps_overlay_unicast_targets() -> anyhow::Result<()> {
        for destination in [
            "100.64.0.11",
            "10.42.7.25",
            "172.20.1.10",
            "fd00::42",
            "2001:db8::42",
        ] {
            assert_eq!(
                packet_flow_destination_drop_reason(destination.parse()?),
                None,
                "{destination} should remain eligible"
            );
        }

        assert_eq!(
            packet_flow_destination_drop_reason("0.0.0.0".parse()?),
            Some(AgentPacketFlowDropReason::Unspecified)
        );
        assert_eq!(
            packet_flow_destination_drop_reason("::".parse()?),
            Some(AgentPacketFlowDropReason::Unspecified)
        );
        assert_eq!(
            packet_flow_destination_drop_reason("127.0.0.1".parse()?),
            Some(AgentPacketFlowDropReason::Loopback)
        );
        assert_eq!(
            packet_flow_destination_drop_reason("::1".parse()?),
            Some(AgentPacketFlowDropReason::Loopback)
        );
        assert_eq!(
            packet_flow_destination_drop_reason("224.0.0.1".parse()?),
            Some(AgentPacketFlowDropReason::Multicast)
        );
        assert_eq!(
            packet_flow_destination_drop_reason("ff02::1".parse()?),
            Some(AgentPacketFlowDropReason::Multicast)
        );
        assert_eq!(
            packet_flow_destination_drop_reason("255.255.255.255".parse()?),
            Some(AgentPacketFlowDropReason::Broadcast)
        );
        assert_eq!(
            packet_flow_destination_drop_reason("169.254.10.20".parse()?),
            Some(AgentPacketFlowDropReason::LinkLocal)
        );
        assert_eq!(
            packet_flow_destination_drop_reason("fe80::1".parse()?),
            Some(AgentPacketFlowDropReason::LinkLocal)
        );
        assert_eq!(AgentPacketFlowDropReason::LinkLocal.as_str(), "link_local");
        assert_eq!(
            AgentPacketFlowDropReason::NoOverlayMatch.as_str(),
            "no_overlay_match"
        );
        assert_eq!(
            AgentPacketFlowDropReason::InconsistentTransportMetadata.as_str(),
            "inconsistent_transport_metadata"
        );
        Ok(())
    }

    #[test]
    fn packet_flow_deduper_suppresses_same_flow_but_keeps_lifecycle_changes() -> anyhow::Result<()>
    {
        let base = PacketFlowRecord {
            destination: "100.64.0.11".parse()?,
            observation: AgentPacketFlowObservation {
                source: Some("192.0.2.10".parse()?),
                protocol: Some(TransportProtocol::Tcp),
                source_port: Some(54_321),
                destination_port: Some(443),
                conntrack_status: vec![AgentPacketFlowConntrackStatus::Unreplied],
                tcp_state: Some(AgentPacketFlowTcpState::SynSent),
                ..AgentPacketFlowObservation::default()
            },
        };
        let mut established = base.clone();
        established.observation.conntrack_status = vec![AgentPacketFlowConntrackStatus::Assured];
        established.observation.tcp_state = Some(AgentPacketFlowTcpState::Established);

        let mut deduper = PacketFlowDeduper::new(Some(Duration::from_secs(60)));
        let (retained, duplicates) =
            deduper.retain_new(vec![base.clone(), base.clone(), established.clone()]);
        assert_eq!(retained, vec![base.clone(), established.clone()]);
        assert_eq!(duplicates, 1);

        let (retained, duplicates) = deduper.retain_new(vec![base, established]);
        assert!(retained.is_empty());
        assert_eq!(duplicates, 2);

        let mut disabled = PacketFlowDeduper::new(None);
        let (retained, duplicates) = disabled.retain_new(vec![PacketFlowRecord {
            destination: "100.64.0.12".parse()?,
            observation: AgentPacketFlowObservation::default(),
        }]);
        assert_eq!(retained.len(), 1);
        assert_eq!(duplicates, 0);
        Ok(())
    }

    #[test]
    fn packet_flow_deduper_keeps_application_classification_changes() -> anyhow::Result<()> {
        let base = PacketFlowRecord {
            destination: "100.64.0.11".parse()?,
            observation: AgentPacketFlowObservation {
                source: Some("192.0.2.10".parse()?),
                protocol: Some(TransportProtocol::Tcp),
                source_port: Some(54_321),
                destination_port: Some(15_432),
                ..AgentPacketFlowObservation::default()
            },
        };
        let mut classified = base.clone();
        classified.observation.application = Some(AgentPacketFlowApplication::Postgres);

        let mut deduper = PacketFlowDeduper::new(Some(Duration::from_secs(60)));
        let (retained, duplicates) =
            deduper.retain_new(vec![base.clone(), classified.clone(), classified.clone()]);
        assert_eq!(retained, vec![base.clone(), classified.clone()]);
        assert_eq!(duplicates, 1);

        let (retained, duplicates) = deduper.retain_new(vec![base, classified]);
        assert!(retained.is_empty());
        assert_eq!(duplicates, 2);
        Ok(())
    }

    #[test]
    fn packet_flow_deduper_prunes_oldest_fingerprints_to_capacity() -> anyhow::Result<()> {
        let first = PacketFlowRecord {
            destination: "100.64.0.11".parse()?,
            observation: AgentPacketFlowObservation::default(),
        };
        let second = PacketFlowRecord {
            destination: "100.64.0.12".parse()?,
            observation: AgentPacketFlowObservation::default(),
        };
        let mut deduper = PacketFlowDeduper::with_max_entries(Some(Duration::from_secs(60)), 1);

        let (retained, duplicates) = deduper.retain_new(vec![first.clone()]);
        assert_eq!(retained, vec![first.clone()]);
        assert_eq!(duplicates, 0);
        assert_eq!(deduper.seen.len(), 1);
        let old_seen = Instant::now()
            .checked_sub(Duration::from_secs(30))
            .unwrap_or_else(Instant::now);
        for last_seen in deduper.seen.values_mut() {
            *last_seen = old_seen;
        }

        let (retained, duplicates) = deduper.retain_new(vec![second.clone()]);
        assert_eq!(retained, vec![second.clone()]);
        assert_eq!(duplicates, 0);
        assert_eq!(deduper.seen.len(), 1);
        assert!(deduper
            .seen
            .contains_key(&PacketFlowFingerprint::from(&second)));
        assert!(!deduper
            .seen
            .contains_key(&PacketFlowFingerprint::from(&first)));

        let (retained, duplicates) = deduper.retain_new(vec![first.clone(), second]);
        assert_eq!(retained, vec![first]);
        assert_eq!(duplicates, 1);
        assert_eq!(deduper.seen.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn packet_flow_duplicate_suppression_records_agent_metrics() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ipars_types::ClusterPolicy::default(),
        );

        record_packet_flow_duplicate_suppressions(
            &runtime,
            3,
            AgentPacketFlowDuplicateSource::ConntrackNetlinkEvents,
        );
        record_packet_flow_duplicate_suppressions(
            &runtime,
            0,
            AgentPacketFlowDuplicateSource::EbpfJsonl,
        );

        let metrics = runtime.metrics().await;
        assert_eq!(metrics.packet_flow_duplicate_suppression_count, 3);
        assert!(metrics
            .packet_flow_duplicate_suppression_counts
            .iter()
            .any(|entry| {
                entry.source == AgentPacketFlowDuplicateSource::ConntrackNetlinkEvents
                    && entry.count == 3
            }));
        assert!(metrics
            .packet_flow_duplicate_suppression_counts
            .iter()
            .any(
                |entry| entry.source == AgentPacketFlowDuplicateSource::EbpfJsonl
                    && entry.count == 0
            ));
    }

    #[tokio::test]
    async fn packet_flow_detector_filters_non_unicast_before_default_route_match(
    ) -> anyhow::Result<()> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ipars_types::ClusterPolicy::default(),
        );
        let mut peer = node_record("default-route-peer");
        peer.routes.push(Route {
            id: "default-v4".to_string(),
            cidr: "0.0.0.0/0".parse()?,
            advertised_by: peer.node_id.clone(),
            via: Some(peer.node_id.clone()),
            metric: 100,
            tags: Default::default(),
        });
        runtime
            .observe_peer_map_for_lazy_connect(std::slice::from_ref(&peer))
            .await;

        let flows = vec![
            PacketFlowRecord {
                destination: "224.0.0.1".parse()?,
                observation: AgentPacketFlowObservation::default(),
            },
            PacketFlowRecord {
                destination: "255.255.255.255".parse()?,
                observation: AgentPacketFlowObservation::default(),
            },
            PacketFlowRecord {
                destination: "10.42.7.25".parse()?,
                observation: AgentPacketFlowObservation::default(),
            },
        ];

        let matched =
            record_packet_flow_observations(&runtime, flows, false, "test-detector").await;
        let metrics = runtime.metrics().await;

        assert_eq!(matched, 1);
        assert_eq!(metrics.packet_flow_observation_count, 1);
        assert_eq!(metrics.packet_flow_match_count, 1);
        assert_eq!(metrics.packet_flow_unmatched_count, 0);
        assert_eq!(metrics.packet_flow_filtered_count, 2);
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| entry.reason == AgentPacketFlowDropReason::Multicast)
                .map(|entry| entry.count),
            Some(1)
        );
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| entry.reason == AgentPacketFlowDropReason::Broadcast)
                .map(|entry| entry.count),
            Some(1)
        );
        assert!(runtime.should_connect_peer(&peer).await);
        Ok(())
    }

    #[test]
    fn conntrack_netlink_dump_request_uses_ct_get_dump_message() -> anyhow::Result<()> {
        let request = conntrack_netlink_dump_request(42);

        assert_eq!(read_u32_ne(&request, 0)?, request.len() as u32);
        assert_eq!(
            read_u16_ne(&request, 4)?,
            ctnetlink_message_type(IPCTNL_MSG_CT_GET)
        );
        assert_eq!(read_u16_ne(&request, 6)?, NLM_F_REQUEST | NLM_F_DUMP);
        assert_eq!(read_u32_ne(&request, 8)?, 42);
        assert_eq!(read_u32_ne(&request, 12)?, 0);
        assert_eq!(&request[16..], &[0, NFNETLINK_V0, 0, 0]);
        Ok(())
    }

    #[test]
    fn conntrack_netlink_event_group_mask_subscribes_new_and_update() {
        assert_eq!(netlink_group_mask(0), 0);
        assert_eq!(netlink_group_mask(NFNLGRP_CONNTRACK_NEW), 0b01);
        assert_eq!(netlink_group_mask(NFNLGRP_CONNTRACK_UPDATE), 0b10);
        assert_eq!(netlink_group_mask(33), 0);
        assert_eq!(conntrack_netlink_event_group_mask(), 0b11);
    }

    #[test]
    fn conntrack_netlink_lifecycle_metadata_parsers_classify_status_and_tcp_state(
    ) -> anyhow::Result<()> {
        assert_eq!(
            parse_conntrack_netlink_status(&0_u32.to_be_bytes())?,
            vec![AgentPacketFlowConntrackStatus::Unreplied]
        );
        assert_eq!(
            parse_conntrack_netlink_status(&(IPS_SEEN_REPLY | IPS_ASSURED).to_be_bytes())?,
            vec![AgentPacketFlowConntrackStatus::Assured]
        );

        let protoinfo = test_nla(
            CTA_PROTOINFO_TCP | TEST_NLA_F_NESTED,
            &test_nla(CTA_PROTOINFO_TCP_STATE, &[TCP_CONNTRACK_CLOSE_WAIT]),
        );
        assert_eq!(
            parse_conntrack_protoinfo_tcp_state(&protoinfo)?,
            Some(AgentPacketFlowTcpState::CloseWait)
        );
        Ok(())
    }

    #[test]
    fn conntrack_netlink_parser_extracts_orig_and_reply_flow_metadata() -> anyhow::Result<()> {
        let ipv4_source = Ipv4Addr::new(192, 0, 2, 10);
        let ipv4_destination = Ipv4Addr::new(100, 64, 0, 42);
        let ipv6_source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let ipv6_destination = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x42);
        let orig_tuple = test_nla(
            CTA_TUPLE_ORIG | TEST_NLA_F_NESTED,
            &[
                test_nla(
                    CTA_TUPLE_IP | TEST_NLA_F_NESTED,
                    &[
                        test_nla(CTA_IP_V4_SRC, &ipv4_source.octets()),
                        test_nla(CTA_IP_V4_DST, &ipv4_destination.octets()),
                    ]
                    .concat(),
                ),
                test_nla(
                    CTA_TUPLE_PROTO | TEST_NLA_F_NESTED,
                    &[
                        test_nla(CTA_PROTO_NUM, &[6]),
                        test_nla(CTA_PROTO_SRC_PORT, &50_000_u16.to_be_bytes()),
                        test_nla(CTA_PROTO_DST_PORT, &51_820_u16.to_be_bytes()),
                    ]
                    .concat(),
                ),
            ]
            .concat(),
        );
        let reply_tuple = test_nla(
            CTA_TUPLE_REPLY | TEST_NLA_F_NESTED,
            &[
                test_nla(
                    CTA_TUPLE_IP | TEST_NLA_F_NESTED,
                    &[
                        test_nla(CTA_IP_V6_SRC, &ipv6_source.octets()),
                        test_nla(CTA_IP_V6_DST, &ipv6_destination.octets()),
                    ]
                    .concat(),
                ),
                test_nla(
                    CTA_TUPLE_PROTO | TEST_NLA_F_NESTED,
                    &[
                        test_nla(CTA_PROTO_NUM, &[6]),
                        test_nla(CTA_PROTO_SRC_PORT, &443_u16.to_be_bytes()),
                        test_nla(CTA_PROTO_DST_PORT, &60_000_u16.to_be_bytes()),
                    ]
                    .concat(),
                ),
            ]
            .concat(),
        );
        let status = test_nla(CTA_STATUS, &(IPS_SEEN_REPLY | IPS_ASSURED).to_be_bytes());
        let protoinfo = test_nla(
            CTA_PROTOINFO | TEST_NLA_F_NESTED,
            &test_nla(
                CTA_PROTOINFO_TCP | TEST_NLA_F_NESTED,
                &test_nla(CTA_PROTOINFO_TCP_STATE, &[TCP_CONNTRACK_ESTABLISHED]),
            ),
        );
        let mut payload = vec![0, NFNETLINK_V0, 0, 0];
        payload.extend(status);
        payload.extend(protoinfo);
        payload.extend(orig_tuple);
        payload.extend(reply_tuple);

        let mut datagram = test_netlink_message(ctnetlink_message_type(0), &payload);
        datagram.extend(test_netlink_message(NLMSG_DONE, &[]));

        let result = parse_conntrack_netlink_datagram_packet_flows(
            &datagram,
            ConntrackNetlinkReadLimits::default().max_flows,
        )?;
        let destinations = result
            .flows
            .iter()
            .map(|flow| flow.destination)
            .collect::<BTreeSet<_>>();

        assert!(result.done);
        assert_eq!(
            destinations,
            BTreeSet::from([
                IpAddr::from(ipv4_destination),
                IpAddr::from(ipv6_destination)
            ])
        );
        let orig = result
            .flows
            .iter()
            .find(|flow| flow.destination == IpAddr::from(ipv4_destination))
            .context("missing orig flow")?;
        assert_eq!(orig.observation.source, Some(IpAddr::from(ipv4_source)));
        assert_eq!(orig.observation.protocol, Some(TransportProtocol::Tcp));
        assert_eq!(orig.observation.source_port, Some(50_000));
        assert_eq!(orig.observation.destination_port, Some(51_820));
        assert_eq!(
            orig.observation.conntrack_status,
            vec![AgentPacketFlowConntrackStatus::Assured]
        );
        assert_eq!(
            orig.observation.tcp_state,
            Some(AgentPacketFlowTcpState::Established)
        );
        let reply = result
            .flows
            .iter()
            .find(|flow| flow.destination == IpAddr::from(ipv6_destination))
            .context("missing reply flow")?;
        assert_eq!(
            reply.observation.conntrack_status,
            vec![AgentPacketFlowConntrackStatus::Assured]
        );
        assert_eq!(
            reply.observation.tcp_state,
            Some(AgentPacketFlowTcpState::Established)
        );
        Ok(())
    }

    #[test]
    fn conntrack_netlink_parser_truncates_to_flow_limit() -> anyhow::Result<()> {
        let first_destination = Ipv4Addr::new(100, 64, 0, 44);
        let second_destination = Ipv4Addr::new(100, 64, 0, 45);
        let first_tuple = test_nla(
            CTA_TUPLE_ORIG | TEST_NLA_F_NESTED,
            &test_nla(
                CTA_TUPLE_IP | TEST_NLA_F_NESTED,
                &test_nla(CTA_IP_V4_DST, &first_destination.octets()),
            ),
        );
        let second_tuple = test_nla(
            CTA_TUPLE_REPLY | TEST_NLA_F_NESTED,
            &test_nla(
                CTA_TUPLE_IP | TEST_NLA_F_NESTED,
                &test_nla(CTA_IP_V4_DST, &second_destination.octets()),
            ),
        );
        let mut payload = vec![0, NFNETLINK_V0, 0, 0];
        payload.extend(first_tuple);
        payload.extend(second_tuple);
        let mut datagram = test_netlink_message(ctnetlink_message_type(0), &payload);
        datagram.extend(test_netlink_message(NLMSG_DONE, &[]));

        let result = parse_conntrack_netlink_datagram_packet_flows(&datagram, 1)?;

        assert!(result.truncated);
        assert!(!result.done);
        assert_eq!(result.flows.len(), 1);
        assert_eq!(result.flows[0].destination, IpAddr::from(first_destination));
        Ok(())
    }

    #[test]
    fn conntrack_netlink_event_parser_does_not_require_done_message() -> anyhow::Result<()> {
        let ipv4_destination = Ipv4Addr::new(100, 64, 0, 77);
        let tuple = test_nla(
            CTA_TUPLE_ORIG | TEST_NLA_F_NESTED,
            &test_nla(
                CTA_TUPLE_IP | TEST_NLA_F_NESTED,
                &test_nla(CTA_IP_V4_DST, &ipv4_destination.octets()),
            ),
        );
        let mut payload = vec![0, NFNETLINK_V0, 0, 0];
        payload.extend(tuple);
        let datagram = test_netlink_message(ctnetlink_message_type(0), &payload);

        let result = parse_conntrack_netlink_datagram_packet_flows(
            &datagram,
            ConntrackNetlinkReadLimits::default().max_flows,
        )?;

        assert!(!result.done);
        assert_eq!(
            result
                .flows
                .iter()
                .map(|flow| flow.destination)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([IpAddr::from(ipv4_destination)])
        );
        Ok(())
    }

    const TEST_NLA_F_NESTED: u16 = 1 << 15;

    fn test_netlink_message(message_type: u16, payload: &[u8]) -> Vec<u8> {
        let message_len = NLMSG_HDR_LEN + payload.len();
        let mut message = Vec::with_capacity(align_to_4(message_len));
        push_u32_ne(&mut message, message_len as u32);
        push_u16_ne(&mut message, message_type);
        push_u16_ne(&mut message, 0);
        push_u32_ne(&mut message, 7);
        push_u32_ne(&mut message, 0);
        message.extend_from_slice(payload);
        message.resize(align_to_4(message_len), 0);
        message
    }

    fn test_nla(kind: u16, value: &[u8]) -> Vec<u8> {
        let attribute_len = NLA_HDR_LEN + value.len();
        let mut attribute = Vec::with_capacity(align_to_4(attribute_len));
        push_u16_ne(&mut attribute, attribute_len as u16);
        push_u16_ne(&mut attribute, kind);
        attribute.extend_from_slice(value);
        attribute.resize(align_to_4(attribute_len), 0);
        attribute
    }

    #[test]
    fn runtime_preflight_allows_dry_run_without_host_tools() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--apply-peer-map",
        ])?;

        if let Command::Agent(args) = cli.command {
            preflight_agent_runtime_with_path(&args, Some(OsStr::new("")))?;
            assert_eq!(
                runtime_preflight_needs(&args),
                RuntimePreflightNeeds::none()
            );
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[cfg(unix)]
    #[test]
    fn runtime_preflight_checks_docker_api_socket_for_discovery() -> anyhow::Result<()> {
        let base = unique_test_dir("docker-api-preflight")?;
        let missing_socket = base.join("missing.sock");
        let missing_socket_arg = missing_socket.display().to_string();
        let missing_cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--apply-docker-routes",
            "--docker-discover-networks",
            "--docker-api-socket",
            missing_socket_arg.as_str(),
        ])?;

        if let Command::Agent(args) = missing_cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(needs.docker_api_socket);
            assert!(!needs.ip_command);
            assert!(!needs.wg_command);
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("missing Docker socket should fail preflight"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("Docker API socket"));
            assert!(error.to_string().contains("not readable"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let socket = base.join("docker.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket)?;
        let socket_arg = socket.display().to_string();
        let valid_cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--apply-docker-routes",
            "--docker-discover-networks",
            "--docker-api-socket",
            socket_arg.as_str(),
        ])?;
        if let Command::Agent(args) = valid_cli.command {
            preflight_agent_runtime_with_path(&args, Some(OsStr::new("")))?;
        } else {
            anyhow::bail!("expected agent command");
        }

        let link = base.join("docker-link.sock");
        std::os::unix::fs::symlink(&socket, &link)?;
        let error = match ensure_docker_api_socket_ready(&link) {
            Ok(()) => anyhow::bail!("symlinked Docker socket should fail preflight"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("must not be a symlink"));

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn runtime_preflight_requires_linux_tools_for_command_backend() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["iparsd", "agent", "--apply-peer-map"])?;

        if let Command::Agent(args) = cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(needs.ip_command);
            assert!(needs.wg_command);
            assert!(needs.cap_net_admin);
            assert!(needs.cap_net_raw);
            assert!(!needs.cap_sys_admin);
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("missing required Linux runtime command `ip`"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[cfg(unix)]
    #[test]
    fn runtime_preflight_rejects_unsafe_path_program_entries() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let base = unique_trusted_test_dir("runtime-command-preflight")?;

        let executable_bin = base.join("executable-bin");
        std::fs::create_dir(&executable_bin)?;
        std::fs::set_permissions(&executable_bin, std::fs::Permissions::from_mode(0o755))?;
        let executable = executable_bin.join("ip");
        std::fs::write(&executable, b"#!/bin/sh\n")?;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))?;
        ensure_program_in_path("ip", Some(executable_bin.as_os_str()))?;

        let unsafe_preceding_bin = base.join("unsafe-preceding-bin");
        std::fs::create_dir(&unsafe_preceding_bin)?;
        std::fs::set_permissions(
            &unsafe_preceding_bin,
            std::fs::Permissions::from_mode(0o777),
        )?;
        let unsafe_preceding_path =
            std::env::join_paths([unsafe_preceding_bin.as_os_str(), executable_bin.as_os_str()])?;
        let unsafe_preceding_error =
            match ensure_program_in_path("ip", Some(unsafe_preceding_path.as_os_str())) {
                Ok(()) => anyhow::bail!("unexpected successful unsafe preceding PATH preflight"),
                Err(error) => error,
            };
        assert!(unsafe_preceding_error
            .to_string()
            .contains("Linux runtime command PATH entry"));
        assert!(unsafe_preceding_error
            .to_string()
            .contains("must not be group- or world-writable"));

        let symlink_preceding_target = base.join("symlink-preceding-target");
        std::fs::create_dir(&symlink_preceding_target)?;
        std::fs::set_permissions(
            &symlink_preceding_target,
            std::fs::Permissions::from_mode(0o755),
        )?;
        let symlink_preceding_bin = base.join("symlink-preceding-bin");
        std::os::unix::fs::symlink(&symlink_preceding_target, &symlink_preceding_bin)?;
        let symlink_preceding_path = std::env::join_paths([
            symlink_preceding_bin.as_os_str(),
            executable_bin.as_os_str(),
        ])?;
        let symlink_preceding_error =
            match ensure_program_in_path("ip", Some(symlink_preceding_path.as_os_str())) {
                Ok(()) => anyhow::bail!("unexpected successful symlink preceding PATH preflight"),
                Err(error) => error,
            };
        assert!(symlink_preceding_error
            .to_string()
            .contains("Linux runtime command PATH entry"));
        assert!(symlink_preceding_error
            .to_string()
            .contains("must not be a symlink"));

        let non_executable_bin = base.join("non-executable-bin");
        std::fs::create_dir(&non_executable_bin)?;
        std::fs::set_permissions(&non_executable_bin, std::fs::Permissions::from_mode(0o755))?;
        let non_executable = non_executable_bin.join("ip");
        std::fs::write(&non_executable, b"#!/bin/sh\n")?;
        std::fs::set_permissions(&non_executable, std::fs::Permissions::from_mode(0o644))?;
        let non_executable_error =
            match ensure_program_in_path("ip", Some(non_executable_bin.as_os_str())) {
                Ok(()) => anyhow::bail!("unexpected successful non-executable command preflight"),
                Err(error) => error,
            };
        assert!(non_executable_error
            .to_string()
            .contains("expected an executable regular file"));

        let directory_bin = base.join("directory-bin");
        std::fs::create_dir(&directory_bin)?;
        std::fs::set_permissions(&directory_bin, std::fs::Permissions::from_mode(0o755))?;
        std::fs::create_dir(directory_bin.join("ip"))?;
        let directory_error = match ensure_program_in_path("ip", Some(directory_bin.as_os_str())) {
            Ok(()) => anyhow::bail!("unexpected successful directory command preflight"),
            Err(error) => error,
        };
        assert!(directory_error
            .to_string()
            .contains("expected an executable regular file"));

        let symlink_bin = base.join("symlink-bin");
        std::fs::create_dir(&symlink_bin)?;
        std::fs::set_permissions(&symlink_bin, std::fs::Permissions::from_mode(0o755))?;
        std::os::unix::fs::symlink(&executable, symlink_bin.join("ip"))?;
        let symlink_error = match ensure_program_in_path("ip", Some(symlink_bin.as_os_str())) {
            Ok(()) => anyhow::bail!("unexpected successful symlink command preflight"),
            Err(error) => error,
        };
        assert!(symlink_error
            .to_string()
            .contains("expected an executable regular file"));

        let symlink_parent_target = base.join("symlink-parent-target");
        std::fs::create_dir(&symlink_parent_target)?;
        std::fs::set_permissions(
            &symlink_parent_target,
            std::fs::Permissions::from_mode(0o755),
        )?;
        let symlink_parent_command = symlink_parent_target.join("ip");
        std::fs::write(&symlink_parent_command, b"#!/bin/sh\n")?;
        std::fs::set_permissions(
            &symlink_parent_command,
            std::fs::Permissions::from_mode(0o755),
        )?;
        let symlink_parent_bin = base.join("symlink-parent-bin");
        std::os::unix::fs::symlink(&symlink_parent_target, &symlink_parent_bin)?;
        let symlink_parent_error =
            match ensure_program_in_path("ip", Some(symlink_parent_bin.as_os_str())) {
                Ok(()) => anyhow::bail!("unexpected successful symlink parent preflight"),
                Err(error) => error,
            };
        assert!(symlink_parent_error.to_string().contains("parent"));
        assert!(symlink_parent_error
            .to_string()
            .contains("must not be a symlink"));

        let symlink_ancestor_target = base.join("symlink-ancestor-target");
        let symlink_ancestor_target_bin = symlink_ancestor_target.join("bin");
        std::fs::create_dir_all(&symlink_ancestor_target_bin)?;
        std::fs::set_permissions(
            &symlink_ancestor_target,
            std::fs::Permissions::from_mode(0o755),
        )?;
        std::fs::set_permissions(
            &symlink_ancestor_target_bin,
            std::fs::Permissions::from_mode(0o755),
        )?;
        let symlink_ancestor_command = symlink_ancestor_target_bin.join("ip");
        std::fs::write(&symlink_ancestor_command, b"#!/bin/sh\n")?;
        std::fs::set_permissions(
            &symlink_ancestor_command,
            std::fs::Permissions::from_mode(0o755),
        )?;
        let symlink_ancestor = base.join("symlink-ancestor");
        std::os::unix::fs::symlink(&symlink_ancestor_target, &symlink_ancestor)?;
        let symlink_ancestor_bin = symlink_ancestor.join("bin");
        let symlink_ancestor_error =
            match ensure_program_in_path("ip", Some(symlink_ancestor_bin.as_os_str())) {
                Ok(()) => anyhow::bail!("unexpected successful symlink ancestor preflight"),
                Err(error) => error,
            };
        assert!(symlink_ancestor_error.to_string().contains("ancestor"));
        assert!(symlink_ancestor_error
            .to_string()
            .contains("must not be a symlink"));

        let writable_command_bin = base.join("writable-command-bin");
        std::fs::create_dir(&writable_command_bin)?;
        std::fs::set_permissions(
            &writable_command_bin,
            std::fs::Permissions::from_mode(0o755),
        )?;
        let writable_command = writable_command_bin.join("ip");
        std::fs::write(&writable_command, b"#!/bin/sh\n")?;
        std::fs::set_permissions(&writable_command, std::fs::Permissions::from_mode(0o775))?;
        let writable_command_error =
            match ensure_program_in_path("ip", Some(writable_command_bin.as_os_str())) {
                Ok(()) => anyhow::bail!("unexpected successful writable command preflight"),
                Err(error) => error,
            };
        assert!(writable_command_error
            .to_string()
            .contains("must not be group- or world-writable"));

        let writable_parent_bin = base.join("writable-parent-bin");
        std::fs::create_dir(&writable_parent_bin)?;
        std::fs::set_permissions(&writable_parent_bin, std::fs::Permissions::from_mode(0o777))?;
        let writable_parent_command = writable_parent_bin.join("ip");
        std::fs::write(&writable_parent_command, b"#!/bin/sh\n")?;
        std::fs::set_permissions(
            &writable_parent_command,
            std::fs::Permissions::from_mode(0o755),
        )?;
        let writable_parent_error =
            match ensure_program_in_path("ip", Some(writable_parent_bin.as_os_str())) {
                Ok(()) => anyhow::bail!("unexpected successful writable parent preflight"),
                Err(error) => error,
            };
        assert!(writable_parent_error
            .to_string()
            .contains("must not be group- or world-writable"));

        let writable_ancestor_bin = base.join("writable-ancestor-bin");
        std::fs::create_dir(&writable_ancestor_bin)?;
        std::fs::set_permissions(
            &writable_ancestor_bin,
            std::fs::Permissions::from_mode(0o777),
        )?;
        let nested_bin = writable_ancestor_bin.join("bin");
        std::fs::create_dir(&nested_bin)?;
        std::fs::set_permissions(&nested_bin, std::fs::Permissions::from_mode(0o755))?;
        let nested_command = nested_bin.join("ip");
        std::fs::write(&nested_command, b"#!/bin/sh\n")?;
        std::fs::set_permissions(&nested_command, std::fs::Permissions::from_mode(0o755))?;
        let writable_ancestor_error =
            match ensure_program_in_path("ip", Some(nested_bin.as_os_str())) {
                Ok(()) => anyhow::bail!("unexpected successful writable ancestor preflight"),
                Err(error) => error,
            };
        assert!(writable_ancestor_error.to_string().contains("ancestor"));
        assert!(writable_ancestor_error
            .to_string()
            .contains("must not be group- or world-writable"));

        let sticky_ancestor_bin = base.join("sticky-ancestor-bin");
        std::fs::create_dir(&sticky_ancestor_bin)?;
        std::fs::set_permissions(
            &sticky_ancestor_bin,
            std::fs::Permissions::from_mode(0o1777),
        )?;
        let sticky_nested_bin = sticky_ancestor_bin.join("bin");
        std::fs::create_dir(&sticky_nested_bin)?;
        std::fs::set_permissions(&sticky_nested_bin, std::fs::Permissions::from_mode(0o755))?;
        let sticky_nested_command = sticky_nested_bin.join("ip");
        std::fs::write(&sticky_nested_command, b"#!/bin/sh\n")?;
        std::fs::set_permissions(
            &sticky_nested_command,
            std::fs::Permissions::from_mode(0o755),
        )?;
        let sticky_ancestor_error =
            match ensure_program_in_path("ip", Some(sticky_nested_bin.as_os_str())) {
                Ok(()) => anyhow::bail!("unexpected successful sticky ancestor preflight"),
                Err(error) => error,
            };
        assert!(sticky_ancestor_error.to_string().contains("ancestor"));
        assert!(sticky_ancestor_error
            .to_string()
            .contains("must not be group- or world-writable"));

        let relative_bin = PathBuf::from("relative-bin");
        let relative_error = match ensure_program_in_path("ip", Some(relative_bin.as_os_str())) {
            Ok(()) => anyhow::bail!("unexpected successful relative PATH command preflight"),
            Err(error) => error,
        };
        assert!(relative_error
            .to_string()
            .contains("must be an absolute directory"));

        let current_component_bin = base.join(".").join("bin");
        let current_component_error =
            match ensure_program_in_path("ip", Some(current_component_bin.as_os_str())) {
                Ok(()) => anyhow::bail!("unexpected successful current-component PATH preflight"),
                Err(error) => error,
            };
        assert!(current_component_error
            .to_string()
            .contains("must not contain '.' or '..' components"));

        let parent_component_bin = base.join("..").join("bin");
        let parent_component_error =
            match ensure_program_in_path("ip", Some(parent_component_bin.as_os_str())) {
                Ok(()) => anyhow::bail!("unexpected successful parent-component PATH preflight"),
                Err(error) => error,
            };
        assert!(parent_component_error
            .to_string()
            .contains("must not contain '.' or '..' components"));

        let empty_path_error = match ensure_program_in_path("ip", Some(OsStr::new(":"))) {
            Ok(()) => anyhow::bail!("unexpected successful empty PATH command preflight"),
            Err(error) => error,
        };
        assert!(empty_path_error
            .to_string()
            .contains("must be an absolute directory"));

        let empty_lookup_error = match ensure_program_in_path("ip", Some(OsStr::new(""))) {
            Ok(()) => anyhow::bail!("unexpected successful empty PATH command lookup"),
            Err(error) => error,
        };
        assert!(empty_lookup_error
            .to_string()
            .contains("missing required Linux runtime command `ip`"));

        let userspace_link = base.join("wireguard-go-link");
        std::os::unix::fs::symlink(&executable, &userspace_link)?;
        let userspace_link = userspace_link.display().to_string();
        let userspace_error =
            match ensure_runtime_program_ready(userspace_link.as_str(), Some(OsStr::new(""))) {
                Ok(()) => {
                    anyhow::bail!("unexpected successful symlink userspace command preflight")
                }
                Err(error) => error,
            };
        assert!(userspace_error
            .to_string()
            .contains("expected an executable regular file"));

        let userspace_ancestor = base.join("userspace-writable-ancestor");
        std::fs::create_dir(&userspace_ancestor)?;
        std::fs::set_permissions(&userspace_ancestor, std::fs::Permissions::from_mode(0o777))?;
        let userspace_bin = userspace_ancestor.join("bin");
        std::fs::create_dir(&userspace_bin)?;
        std::fs::set_permissions(&userspace_bin, std::fs::Permissions::from_mode(0o755))?;
        let userspace_command = userspace_bin.join("wireguard-go");
        std::fs::write(&userspace_command, b"#!/bin/sh\n")?;
        std::fs::set_permissions(&userspace_command, std::fs::Permissions::from_mode(0o755))?;
        let userspace_ancestor_command = userspace_command.display().to_string();
        let userspace_ancestor_error = match ensure_runtime_program_ready(
            userspace_ancestor_command.as_str(),
            Some(OsStr::new("")),
        ) {
            Ok(()) => {
                anyhow::bail!("unexpected successful writable ancestor userspace preflight")
            }
            Err(error) => error,
        };
        assert!(userspace_ancestor_error
            .to_string()
            .contains("configured userspace WireGuard command"));
        assert!(userspace_ancestor_error.to_string().contains("ancestor"));

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn runtime_preflight_rejects_untrusted_path_owners() -> anyhow::Result<()> {
        let path = Path::new("/opt/ipars/bin/ip");
        ensure_runtime_path_owner_trusted(
            "required Linux runtime command `ip`",
            "at",
            path,
            0,
            1000,
        )?;
        ensure_runtime_path_owner_trusted(
            "required Linux runtime command `ip`",
            "parent",
            path,
            1000,
            1000,
        )?;

        let error = match ensure_runtime_path_owner_trusted(
            "required Linux runtime command `ip`",
            "ancestor",
            path,
            1001,
            1000,
        ) {
            Ok(()) => anyhow::bail!("unexpected successful untrusted owner preflight"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("must be owned by root or the current effective user"));
        Ok(())
    }

    #[test]
    fn runtime_preflight_allows_kernel_netlink_without_wg_command() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-peer-map",
            "--wireguard-backend",
            "kernel-netlink",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert_eq!(args.wireguard_backend, WireGuardApplyBackend::KernelNetlink);
            assert_eq!(args.wireguard_backend.as_str(), "kernel-netlink");
            let needs = runtime_preflight_needs(&args);
            assert!(needs.ip_command);
            assert!(!needs.wg_command);
            assert!(needs.route_netlink);
            assert!(needs.generic_netlink);
            assert!(!needs.netfilter_netlink);
            assert!(needs.cap_net_admin);
            assert!(needs.cap_net_raw);
            assert!(!needs.cap_sys_admin);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn runtime_preflight_accepts_userspace_wireguard_backend() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-peer-map",
            "--wireguard-backend",
            "userspace-command",
            "--route-backend",
            "kernel-netlink",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert_eq!(
                args.wireguard_backend,
                WireGuardApplyBackend::UserspaceCommand
            );
            assert_eq!(args.wireguard_backend.as_str(), "userspace-command");
            let needs = runtime_preflight_needs(&args);
            assert!(!needs.ip_command);
            assert!(needs.wg_command);
            assert!(needs.route_netlink);
            assert!(!needs.generic_netlink);
            assert!(!needs.netfilter_netlink);
            assert!(needs.cap_net_admin);
            assert!(!needs.cap_net_raw);
            assert!(!needs.cap_sys_admin);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn runtime_backend_specific_options_require_active_linux_dataplane() -> anyhow::Result<()> {
        for (argv, expected) in [
            (
                vec![
                    "iparsd",
                    "agent",
                    "--runtime-backend",
                    "dry-run",
                    "--apply-peer-map",
                    "--wireguard-backend",
                    "kernel-netlink",
                ],
                "--wireguard-backend requires --runtime-backend linux-command",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--runtime-backend",
                    "dry-run",
                    "--apply-peer-map",
                    "--route-backend",
                    "kernel-netlink",
                ],
                "--route-backend requires --runtime-backend linux-command",
            ),
            (
                vec!["iparsd", "agent", "--wireguard-backend", "kernel-netlink"],
                "--wireguard-backend kernel-netlink requires --apply-peer-map",
            ),
            (
                vec!["iparsd", "agent", "--wireguard-backend", "userspace-command"],
                "--wireguard-backend userspace-command requires --apply-peer-map or --userspace-wireguard-command",
            ),
            (
                vec!["iparsd", "agent", "--route-backend", "kernel-netlink"],
                "--route-backend kernel-netlink requires --apply-peer-map, --apply-docker-routes, or --apply-kubernetes-underlay",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--linux-netns",
                    "node-a",
                    "--skip-runtime-preflight",
                ],
                "--linux-netns requires an active Linux dataplane loop, --userspace-wireguard-command, or --relay-forwarder-bind",
            ),
        ] {
            let cli = Cli::try_parse_from(argv)?;
            if let Command::Agent(args) = cli.command {
                let error = match validate_agent_runtime_config(&args) {
                    Ok(()) => anyhow::bail!("unexpected valid agent runtime config"),
                    Err(error) => error,
                };
                assert!(
                    error.to_string().contains(expected),
                    "expected {expected}, got {error}"
                );
            } else {
                anyhow::bail!("expected agent command");
            }
        }

        Ok(())
    }

    #[test]
    fn runtime_preflight_requires_ip_for_namespaced_userspace_wireguard_backend(
    ) -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-peer-map",
            "--wireguard-backend",
            "userspace-command",
            "--route-backend",
            "kernel-netlink",
            "--linux-netns",
            "node-a",
        ])?;

        if let Command::Agent(args) = cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(needs.ip_command);
            assert!(needs.wg_command);
            assert!(!needs.userspace_wireguard_command);
            assert!(needs.route_netlink);
            assert!(!needs.generic_netlink);
            assert!(needs.cap_net_admin);
            assert!(!needs.cap_net_raw);
            assert!(needs.cap_sys_admin);
            assert!(needs.linux_netns);
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful namespaced userspace preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("missing required Linux runtime command `ip`"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[cfg(unix)]
    #[test]
    fn runtime_preflight_checks_namespace_for_managed_userspace_wireguard_process(
    ) -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--wireguard-backend",
            "userspace-command",
            "--userspace-wireguard-command",
            "wireguard-go",
            "--linux-netns",
            "node-a",
        ])?;

        if let Command::Agent(args) = cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(needs.ip_command);
            assert!(needs.wg_command);
            assert!(needs.userspace_wireguard_command);
            assert!(!needs.route_netlink);
            assert!(!needs.generic_netlink);
            assert!(!needs.cap_net_admin);
            assert!(!needs.cap_net_raw);
            assert!(needs.cap_sys_admin);
            assert!(needs.linux_netns);

            let base = unique_trusted_test_dir("namespaced-userspace-preflight")?;
            let bin = base.join("bin");
            std::fs::create_dir(&bin)?;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
            for program in ["ip", "wg", "wireguard-go"] {
                let path = bin.join(program);
                std::fs::write(&path, b"#!/bin/sh\n")?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
            }

            let mut checks = test_preflight_checks(preflight_noop_netlink);
            checks.cap_sys_admin = preflight_fail_cap_sys_admin;
            let cap_error = match preflight_agent_runtime_with_path_and_checks(
                &args,
                Some(bin.as_os_str()),
                checks,
            ) {
                Ok(()) => {
                    anyhow::bail!("unexpected successful namespaced userspace CAP preflight")
                }
                Err(error) => error,
            };
            assert!(cap_error.to_string().contains("blocked test CAP_SYS_ADMIN"));

            let mut namespace_checks = test_preflight_checks(preflight_noop_netlink);
            namespace_checks.linux_netns = preflight_fail_linux_netns;
            let namespace_error = match preflight_agent_runtime_with_path_and_checks(
                &args,
                Some(bin.as_os_str()),
                namespace_checks,
            ) {
                Ok(()) => {
                    anyhow::bail!("unexpected successful namespaced userspace namespace preflight")
                }
                Err(error) => error,
            };
            assert!(namespace_error
                .to_string()
                .contains("blocked test netns node-a"));
            let _ = std::fs::remove_dir_all(&base);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn userspace_wireguard_launch_command_defaults_interface_and_wraps_namespace(
    ) -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--wireguard-backend",
            "userspace-command",
            "--userspace-wireguard-command",
            "wireguard-go",
            "--linux-netns",
            "node-a",
        ])?;

        if let Command::Agent(args) = cli.command {
            let command = match userspace_wireguard_launch_command(&args)? {
                Some(command) => command,
                None => anyhow::bail!("expected userspace WireGuard launch command"),
            };
            assert_eq!(command.program, "ip");
            assert_eq!(
                command.args,
                vec![
                    "netns".to_string(),
                    "exec".to_string(),
                    "node-a".to_string(),
                    "wireguard-go".to_string(),
                    "ipars0".to_string(),
                ]
            );
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn userspace_wireguard_launch_command_accepts_explicit_args() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--wireguard-backend",
            "userspace-command",
            "--userspace-wireguard-command",
            "wireguard-go",
            "--userspace-wireguard-arg=--foreground",
            "--userspace-wireguard-arg=ipars42",
        ])?;

        if let Command::Agent(args) = cli.command {
            let command = match userspace_wireguard_launch_command(&args)? {
                Some(command) => command,
                None => anyhow::bail!("expected userspace WireGuard launch command"),
            };
            assert_eq!(command.program, "wireguard-go");
            assert_eq!(
                command.args,
                vec!["--foreground".to_string(), "ipars42".to_string()]
            );
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn runtime_command_label_escapes_control_characters() {
        let label = runtime_command_label(
            "wireguard-go",
            &[
                "iface\nname".to_string(),
                "arg\tvalue".to_string(),
                r"path\part".to_string(),
            ],
        );

        assert_eq!(label, r"wireguard-go iface\nname arg\tvalue path\\part");
        assert!(!label.contains('\n'));
        assert!(!label.contains('\t'));
    }

    #[cfg(unix)]
    #[test]
    fn userspace_wireguard_spawn_command_revalidates_final_argv() -> anyhow::Result<()> {
        let temp_dir = unique_trusted_test_dir("userspace-wg-spawn-argv")?;
        let command_path = temp_dir.join("userspace-wg-spawn-argv");
        write_trusted_test_executable(&command_path, "#!/bin/sh\nexit 0\n")?;

        let nul_error = match resolve_userspace_wireguard_spawn_command(&LinuxCommand::new(
            command_path.display().to_string(),
            ["ok".to_string(), "bad\0arg".to_string()],
        )) {
            Ok(_) => anyhow::bail!("unexpected valid NUL-containing userspace argv"),
            Err(error) => error,
        };
        assert!(nul_error
            .to_string()
            .contains("argument 1 must not contain NUL bytes"));

        let too_many_error = match resolve_userspace_wireguard_spawn_command(&LinuxCommand::new(
            command_path.display().to_string(),
            std::iter::repeat_n("arg".to_string(), MAX_USERSPACE_WIREGUARD_SPAWN_ARGS + 1),
        )) {
            Ok(_) => anyhow::bail!("unexpected valid oversized userspace argv"),
            Err(error) => error,
        };
        assert!(too_many_error
            .to_string()
            .contains("userspace WireGuard spawn command has too many arguments"));

        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[test]
    fn userspace_wireguard_args_reject_control_characters() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--wireguard-backend",
            "userspace-command",
            "--userspace-wireguard-command",
            "wireguard-go",
            "--userspace-wireguard-arg",
            "ipars0\n--unexpected",
        ])?;

        if let Command::Agent(args) = cli.command {
            let error = match validate_agent_runtime_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid userspace WireGuard config"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--userspace-wireguard-arg must not contain control characters"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn userspace_wireguard_command_rejects_relative_paths() -> anyhow::Result<()> {
        for command in ["./wireguard-go", "bin/wireguard-go"] {
            let cli = Cli::try_parse_from(vec![
                "iparsd".to_string(),
                "agent".to_string(),
                "--wireguard-backend".to_string(),
                "userspace-command".to_string(),
                format!("--userspace-wireguard-command={command}"),
            ])?;

            if let Command::Agent(args) = cli.command {
                let error = match validate_agent_runtime_config(&args) {
                    Ok(()) => anyhow::bail!("unexpected valid userspace WireGuard command"),
                    Err(error) => error,
                };
                assert!(
                    error
                        .to_string()
                        .contains("--userspace-wireguard-command must be a bare command name or an absolute path"),
                    "unexpected error for {command}: {error}"
                );
            } else {
                anyhow::bail!("expected agent command");
            }
        }

        let error = match ensure_runtime_program_ready("./wireguard-go", Some(OsStr::new(""))) {
            Ok(()) => anyhow::bail!("unexpected successful relative command preflight"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("must be a bare command name or an absolute path"));

        Ok(())
    }

    #[test]
    fn userspace_wireguard_command_rejects_whitespace() -> anyhow::Result<()> {
        for command in ["wireguard go", "/usr/local/bin/wireguard go"] {
            let cli = Cli::try_parse_from(vec![
                "iparsd".to_string(),
                "agent".to_string(),
                "--wireguard-backend".to_string(),
                "userspace-command".to_string(),
                format!("--userspace-wireguard-command={command}"),
            ])?;

            if let Command::Agent(args) = cli.command {
                let error = match validate_agent_runtime_config(&args) {
                    Ok(()) => anyhow::bail!("unexpected valid userspace WireGuard command"),
                    Err(error) => error,
                };
                assert!(
                    error
                        .to_string()
                        .contains("--userspace-wireguard-command must not contain whitespace"),
                    "unexpected error for {command}: {error}"
                );
            } else {
                anyhow::bail!("expected agent command");
            }
        }

        let error = match ensure_runtime_program_ready("wireguard go", Some(OsStr::new(""))) {
            Ok(()) => anyhow::bail!("unexpected successful whitespace command preflight"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("must not contain whitespace"));

        Ok(())
    }

    #[test]
    fn userspace_wireguard_command_rejects_special_or_option_names() -> anyhow::Result<()> {
        for (command, expected) in [
            (
                ".",
                "--userspace-wireguard-command program name must not be '.' or '..'",
            ),
            (
                "..",
                "--userspace-wireguard-command program name must not be '.' or '..'",
            ),
            (
                "-wireguard-go",
                "--userspace-wireguard-command program name must not start with '-'",
            ),
            (
                "/usr/local/bin/-wireguard-go",
                "--userspace-wireguard-command program name must not start with '-'",
            ),
            (
                "/usr/local/./bin/wireguard-go",
                "--userspace-wireguard-command path must not contain '.' or '..' components",
            ),
            (
                "/usr/local/../bin/wireguard-go",
                "--userspace-wireguard-command path must not contain '.' or '..' components",
            ),
            (
                "/",
                "--userspace-wireguard-command path must name an executable",
            ),
        ] {
            let cli = Cli::try_parse_from(vec![
                "iparsd".to_string(),
                "agent".to_string(),
                "--wireguard-backend".to_string(),
                "userspace-command".to_string(),
                format!("--userspace-wireguard-command={command}"),
            ])?;

            if let Command::Agent(args) = cli.command {
                let error = match validate_agent_runtime_config(&args) {
                    Ok(()) => anyhow::bail!("unexpected valid userspace WireGuard command"),
                    Err(error) => error,
                };
                assert!(
                    error.to_string().contains(expected),
                    "unexpected error for {command}: {error}"
                );
            } else {
                anyhow::bail!("expected agent command");
            }
        }

        let error = match ensure_runtime_program_ready("-wireguard-go", Some(OsStr::new(""))) {
            Ok(()) => anyhow::bail!("unexpected successful option-prefixed command preflight"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("configured userspace WireGuard command program name must not start"));

        Ok(())
    }

    #[test]
    fn userspace_wireguard_process_config_rejects_oversized_tokens() -> anyhow::Result<()> {
        let validate = |argv: Vec<String>, expected: &str| -> anyhow::Result<()> {
            let cli = Cli::try_parse_from(argv)?;
            if let Command::Agent(args) = cli.command {
                let error = match validate_agent_runtime_config(&args) {
                    Ok(()) => anyhow::bail!("unexpected valid userspace WireGuard config"),
                    Err(error) => error,
                };
                assert!(
                    error.to_string().contains(expected),
                    "expected {expected}, got {error}"
                );
                return Ok(());
            }

            Err(anyhow::anyhow!("expected agent command"))
        };

        validate(
            vec![
                "iparsd".to_string(),
                "agent".to_string(),
                "--wireguard-backend".to_string(),
                "userspace-command".to_string(),
                "--userspace-wireguard-command".to_string(),
                "x".repeat(MAX_RUNTIME_PROGRAM_TOKEN_BYTES + 1),
            ],
            "--userspace-wireguard-command exceeds 4096 bytes",
        )?;

        let mut too_many_args = vec![
            "iparsd".to_string(),
            "agent".to_string(),
            "--wireguard-backend".to_string(),
            "userspace-command".to_string(),
            "--userspace-wireguard-command".to_string(),
            "wireguard-go".to_string(),
        ];
        for index in 0..=MAX_USERSPACE_WIREGUARD_ARGS {
            too_many_args.push("--userspace-wireguard-arg".to_string());
            too_many_args.push(format!("arg-{index}"));
        }
        validate(
            too_many_args,
            "--userspace-wireguard-arg may be repeated at most 128 times",
        )?;

        validate(
            vec![
                "iparsd".to_string(),
                "agent".to_string(),
                "--wireguard-backend".to_string(),
                "userspace-command".to_string(),
                "--userspace-wireguard-command".to_string(),
                "wireguard-go".to_string(),
                "--userspace-wireguard-arg".to_string(),
                "x".repeat(MAX_USERSPACE_WIREGUARD_ARG_BYTES + 1),
            ],
            "--userspace-wireguard-arg exceeds 4096 bytes",
        )?;

        Ok(())
    }

    #[test]
    fn userspace_wireguard_process_config_requires_userspace_backend() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--userspace-wireguard-command",
            "wireguard-go",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = cli.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--wireguard-backend userspace-command"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn runtime_preflight_checks_userspace_wireguard_command() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--wireguard-backend",
            "userspace-command",
            "--userspace-wireguard-command",
            "wireguard-go",
        ])?;

        if let Command::Agent(args) = cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(!needs.ip_command);
            assert!(needs.wg_command);
            assert!(needs.userspace_wireguard_command);
            let error = match ensure_runtime_program_ready("wireguard-go", Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful command preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("missing required Linux runtime command `wireguard-go`"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn userspace_wireguard_process_spawn_uses_sanitized_environment() -> anyhow::Result<()> {
        let temp_dir = unique_trusted_test_dir("userspace-wg-env")?;
        let status_path = temp_dir.join("env.status");
        let pid_path = temp_dir.join("child.pid");
        let command_path = temp_dir.join("userspace-wg-env");
        let status_arg = status_path.display().to_string();
        let pid_arg = pid_path.display().to_string();
        let shell_script = r#"#!/bin/sh
if test "${PATH:-}" = "/usr/sbin:/usr/bin:/sbin:/bin" &&
   test "${LANG:-}" = "C" &&
   test "${LC_ALL:-}" = "C" &&
   test -z "${HOME+x}" &&
   test -z "${LD_PRELOAD+x}"; then
    printf 'ok\n' > "$1"
else
    {
        printf 'PATH=%s\n' "${PATH-<unset>}"
        printf 'LANG=%s\n' "${LANG-<unset>}"
        printf 'LC_ALL=%s\n' "${LC_ALL-<unset>}"
        printf 'HOME=%s\n' "${HOME-<unset>}"
        printf 'LD_PRELOAD=%s\n' "${LD_PRELOAD-<unset>}"
    } > "$1"
fi
printf '%s\n' "$$" > "$2"
exec sleep 60
"#;
        write_trusted_test_executable(&command_path, shell_script)?;
        let command = LinuxCommand::new(
            command_path.display().to_string(),
            vec![status_arg, pid_arg],
        );
        let mut child = spawn_userspace_wireguard_process(&command)?;
        let pid = wait_for_pid_file(&pid_path, Duration::from_secs(2)).await?;
        let status = std::fs::read_to_string(&status_path)
            .with_context(|| format!("failed to read {}", status_path.display()))?;
        stop_userspace_wireguard_child(&mut child, "env-test", Duration::from_secs(1)).await;
        assert!(
            wait_for_process_absent(pid, Duration::from_secs(2)).await,
            "userspace WireGuard env test child process {pid} was left running"
        );
        assert_eq!(
            status.trim(),
            "ok",
            "userspace WireGuard process inherited unexpected environment:\n{status}"
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn userspace_wireguard_start_failure_stops_child_process() -> anyhow::Result<()> {
        let temp_dir = unique_trusted_test_dir("userspace-wg-start-failure")?;
        let pid_path = temp_dir.join("child.pid");
        let command_path = temp_dir.join("userspace-wg-start-failure");
        let pid_arg = pid_path.display().to_string();
        let shell_script = "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$1\"\nexec sleep 60\n";
        write_trusted_test_executable(&command_path, shell_script)?;
        let cli = Cli::try_parse_from(vec![
            "iparsd".to_string(),
            "agent".to_string(),
            "--wireguard-backend".to_string(),
            "userspace-command".to_string(),
            "--userspace-wireguard-command".to_string(),
            command_path.display().to_string(),
            "--userspace-wireguard-arg".to_string(),
            pid_arg,
            "--userspace-wireguard-ready-timeout-seconds".to_string(),
            "1".to_string(),
            "--userspace-wireguard-shutdown-timeout-seconds".to_string(),
            "1".to_string(),
            "--runtime-command-timeout-seconds".to_string(),
            "1".to_string(),
        ])?;

        if let Command::Agent(args) = cli.command {
            let runtime = Arc::new(AgentRuntime::new(
                AgentNodeState::generate(Utc::now()),
                ClusterPolicy::default(),
            ));
            let error = match start_userspace_wireguard_process(&args, runtime.clone()).await {
                Ok(Some(process)) => {
                    process.shutdown().await;
                    anyhow::bail!("unexpected ready userspace WireGuard process")
                }
                Ok(None) => anyhow::bail!("expected userspace WireGuard launch command"),
                Err(error) => error,
            };
            assert!(
                error
                    .to_string()
                    .contains("did not expose interface ipars0 within 1 seconds"),
                "unexpected readiness error: {error}"
            );
            assert!(
                error.to_string().contains("last readiness check failed"),
                "readiness error should include the last failed check: {error}"
            );
            let pid = std::fs::read_to_string(&pid_path)?
                .trim()
                .parse::<u32>()
                .context("failed to parse child pid")?;
            assert!(
                wait_for_process_absent(pid, Duration::from_secs(2)).await,
                "userspace WireGuard child process {pid} was left running after readiness failure"
            );
            let status = runtime
                .userspace_wireguard_process_status()
                .await
                .context("missing userspace WireGuard process status")?;
            assert_eq!(status.state, AgentManagedProcessState::Failed);
            assert_eq!(status.pid, Some(pid));
            assert!(status
                .message
                .as_deref()
                .unwrap_or_default()
                .contains("did not expose interface ipars0 within 1 seconds"));
            assert!(status
                .message
                .as_deref()
                .unwrap_or_default()
                .contains("last readiness check failed"));
            let _ = std::fs::remove_dir_all(&temp_dir);
            return Ok(());
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
        Err(anyhow::anyhow!("expected agent command"))
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn userspace_wireguard_shutdown_kills_process_group() -> anyhow::Result<()> {
        let temp_dir = unique_trusted_test_dir("userspace-wg-process-group")?;
        let pid_path = temp_dir.join("child.pid");
        let grandchild_pid_path = temp_dir.join("grandchild.pid");
        let command_path = temp_dir.join("userspace-wg-process-group");
        let pid_arg = pid_path.display().to_string();
        let grandchild_pid_arg = grandchild_pid_path.display().to_string();
        let shell_script = "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$1\"\nsleep 60 &\nprintf '%s\\n' \"$!\" > \"$2\"\nwait\n";
        write_trusted_test_executable(&command_path, shell_script)?;
        let command = LinuxCommand::new(
            command_path.display().to_string(),
            vec![pid_arg, grandchild_pid_arg],
        );
        let mut child = spawn_userspace_wireguard_process(&command)?;

        let pid = wait_for_pid_file(&pid_path, Duration::from_secs(2)).await?;
        let grandchild_pid =
            wait_for_pid_file(&grandchild_pid_path, Duration::from_secs(2)).await?;
        let status =
            stop_userspace_wireguard_child(&mut child, "group-test", Duration::from_secs(1)).await;

        assert!(
            status.is_some(),
            "userspace WireGuard process should be reaped after group shutdown"
        );
        assert!(
            wait_for_process_absent(pid, Duration::from_secs(2)).await,
            "userspace WireGuard process group child {pid} was left running"
        );
        assert!(
            wait_for_process_absent(grandchild_pid, Duration::from_secs(2)).await,
            "userspace WireGuard process group grandchild {grandchild_pid} was left running"
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn userspace_wireguard_shutdown_uses_sigterm_before_sigkill() -> anyhow::Result<()> {
        let temp_dir = unique_trusted_test_dir("userspace-wg-graceful-stop")?;
        let pid_path = temp_dir.join("child.pid");
        let marker_path = temp_dir.join("terminated.marker");
        let command_path = temp_dir.join("userspace-wg-graceful-stop");
        let pid_arg = pid_path.display().to_string();
        let marker_arg = marker_path.display().to_string();
        let shell_script = "#!/bin/sh\ntrap 'printf term > \"$2\"; exit 0' TERM\nprintf '%s\\n' \"$$\" > \"$1\"\nwhile :; do sleep 1; done\n";
        write_trusted_test_executable(&command_path, shell_script)?;
        let command = LinuxCommand::new(
            command_path.display().to_string(),
            vec![pid_arg, marker_arg],
        );
        let mut child = spawn_userspace_wireguard_process(&command)?;

        let pid = wait_for_pid_file(&pid_path, Duration::from_secs(2)).await?;
        let status =
            stop_userspace_wireguard_child(&mut child, "graceful-test", Duration::from_secs(2))
                .await
                .context("userspace WireGuard graceful test process was not reaped")?;

        assert!(
            status.success(),
            "SIGTERM-aware userspace WireGuard process should exit cleanly: {status}"
        );
        assert_eq!(std::fs::read_to_string(&marker_path)?.trim(), "term");
        assert!(
            wait_for_process_absent(pid, Duration::from_secs(2)).await,
            "userspace WireGuard graceful test child {pid} was left running"
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[tokio::test]
    async fn userspace_wireguard_monitor_shutdown_stops_child_process() -> anyhow::Result<()> {
        let temp_dir = std::env::temp_dir().join(format!(
            "iparsd-userspace-wg-monitor-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir(&temp_dir)?;
        let pid_path = temp_dir.join("child.pid");
        let pid_arg = pid_path.display().to_string();
        let shell_script = r#"printf '%s\n' "$$" > "$1"; exec sleep 60"#;
        let child = tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(shell_script)
            .arg("ipars-monitor")
            .arg(&pid_arg)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("failed to start monitor test child")?;
        let pid = wait_for_pid_file(&pid_path, Duration::from_secs(2)).await?;
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let task = tokio::spawn(monitor_userspace_wireguard_process(
            child,
            "monitor-test".to_string(),
            Some(pid),
            runtime.clone(),
            shutdown_rx,
            Duration::from_secs(1),
        ));

        assert!(shutdown.send(()).is_ok());
        task.await?;
        assert!(
            wait_for_process_absent(pid, Duration::from_secs(2)).await,
            "userspace WireGuard monitor child process {pid} was left running after shutdown"
        );
        let status = runtime
            .userspace_wireguard_process_status()
            .await
            .context("missing userspace WireGuard process status")?;
        assert_eq!(status.state, AgentManagedProcessState::Stopped);
        assert_eq!(status.pid, Some(pid));
        assert!(status.exit_status.is_some());
        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[tokio::test]
    async fn userspace_wireguard_monitor_records_unexpected_exit() -> anyhow::Result<()> {
        let child = tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 7")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("failed to start monitor exit test child")?;
        let pid = child.id();
        let (_shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        monitor_userspace_wireguard_process(
            child,
            "monitor-exit-test".to_string(),
            pid,
            runtime.clone(),
            shutdown_rx,
            Duration::from_secs(1),
        )
        .await;

        let status = runtime
            .userspace_wireguard_process_status()
            .await
            .context("missing userspace WireGuard process status")?;
        assert_eq!(status.state, AgentManagedProcessState::Exited);
        assert_eq!(status.pid, pid);
        assert!(status
            .exit_status
            .as_deref()
            .unwrap_or_default()
            .contains('7'));
        Ok(())
    }

    async fn wait_for_pid_file(path: &Path, timeout: Duration) -> anyhow::Result<u32> {
        let started = Instant::now();
        loop {
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    let contents = contents.trim();
                    if !contents.is_empty() {
                        match contents.parse::<u32>() {
                            Ok(pid) => return Ok(pid),
                            Err(error) if started.elapsed() >= timeout => {
                                return Err(error).context("failed to parse child pid");
                            }
                            Err(_) => {}
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to read child pid file {}", path.display())
                    });
                }
            }
            anyhow::ensure!(
                started.elapsed() < timeout,
                "timed out waiting for child pid file {}",
                path.display()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_for_process_absent(pid: u32, timeout: Duration) -> bool {
        let proc_path = PathBuf::from(format!("/proc/{pid}"));
        let started = Instant::now();
        loop {
            if !proc_path.exists() {
                return true;
            }
            if started.elapsed() >= timeout {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[test]
    fn runtime_preflight_allows_full_kernel_netlink_without_ip_or_wg_commands() -> anyhow::Result<()>
    {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-peer-map",
            "--wireguard-backend",
            "kernel-netlink",
            "--route-backend",
            "kernel-netlink",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert_eq!(args.wireguard_backend, WireGuardApplyBackend::KernelNetlink);
            assert_eq!(args.route_backend, RouteApplyBackend::KernelNetlink);
            assert_eq!(args.route_backend.as_str(), "kernel-netlink");
            let needs = runtime_preflight_needs(&args);
            assert!(!needs.ip_command);
            assert!(!needs.wg_command);
            assert!(needs.route_netlink);
            assert!(needs.generic_netlink);
            assert!(!needs.netfilter_netlink);
            assert!(needs.cap_net_admin);
            assert!(needs.cap_net_raw);
            assert!(!needs.cap_sys_admin);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn runtime_preflight_allows_namespaced_full_kernel_netlink_without_ip_or_wg_commands(
    ) -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-peer-map",
            "--linux-netns",
            "node-a",
            "--wireguard-backend",
            "kernel-netlink",
            "--route-backend",
            "kernel-netlink",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(!needs.ip_command);
            assert!(!needs.wg_command);
            assert!(needs.route_netlink);
            assert!(needs.generic_netlink);
            assert!(!needs.netfilter_netlink);
            assert!(needs.cap_net_admin);
            assert!(needs.cap_net_raw);
            assert!(needs.cap_sys_admin);
            assert!(needs.linux_netns);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn runtime_preflight_does_not_require_net_raw_for_route_only_application() -> anyhow::Result<()>
    {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--kubernetes-service-cidr",
            "10.96.0.0/12",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(needs.ip_command);
            assert!(!needs.wg_command);
            assert!(!needs.route_netlink);
            assert!(!needs.generic_netlink);
            assert!(!needs.netfilter_netlink);
            assert!(needs.ipv4_forwarding);
            assert!(!needs.ipv6_forwarding);
            assert!(needs.cap_net_admin);
            assert!(!needs.cap_net_raw);
            assert!(!needs.cap_sys_admin);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    fn preflight_noop() -> anyhow::Result<()> {
        Ok(())
    }

    fn preflight_noop_netns(_namespace: &LinuxNetworkNamespace) -> anyhow::Result<()> {
        Ok(())
    }

    fn preflight_noop_ebpf_object(_path: &Path) -> anyhow::Result<()> {
        Ok(())
    }

    fn preflight_noop_ebpf_tracepoint(
        _attachment: &EbpfTracepointAttachSpec,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn preflight_noop_path(_path: &Path) -> anyhow::Result<()> {
        Ok(())
    }

    fn preflight_fail_ebpf_object(path: &Path) -> anyhow::Result<()> {
        anyhow::bail!("blocked test eBPF object {}", path.display())
    }

    fn preflight_fail_ebpf_tracepoint(attachment: &EbpfTracepointAttachSpec) -> anyhow::Result<()> {
        anyhow::bail!(
            "blocked test eBPF tracepoint {}/{}",
            attachment.category,
            attachment.name
        )
    }

    fn preflight_fail_ipv4_forwarding() -> anyhow::Result<()> {
        anyhow::bail!("blocked test net.ipv4.ip_forward")
    }

    fn preflight_fail_ipv6_forwarding() -> anyhow::Result<()> {
        anyhow::bail!("blocked test net.ipv6.conf.all.forwarding")
    }

    fn preflight_fail_cap_sys_admin() -> anyhow::Result<()> {
        anyhow::bail!("blocked test CAP_SYS_ADMIN")
    }

    fn preflight_fail_linux_netns(namespace: &LinuxNetworkNamespace) -> anyhow::Result<()> {
        anyhow::bail!("blocked test netns {}", namespace.name())
    }

    fn preflight_fail_generic_netlink(protocol: RuntimeNetlinkProtocol) -> anyhow::Result<()> {
        if protocol == RuntimeNetlinkProtocol::Generic {
            anyhow::bail!("blocked test {}", protocol.as_str());
        }
        Ok(())
    }

    fn preflight_fail_netfilter_netlink(protocol: RuntimeNetlinkProtocol) -> anyhow::Result<()> {
        if protocol == RuntimeNetlinkProtocol::Netfilter {
            anyhow::bail!("blocked test {}", protocol.as_str());
        }
        Ok(())
    }

    fn test_preflight_checks(
        netlink: fn(RuntimeNetlinkProtocol) -> anyhow::Result<()>,
    ) -> RuntimePreflightChecks {
        RuntimePreflightChecks {
            cap_net_admin: preflight_noop,
            cap_net_raw: preflight_noop,
            cap_sys_admin: preflight_noop,
            cap_perfmon: preflight_noop,
            cap_bpf: preflight_noop,
            ebpf_object: preflight_noop_ebpf_object,
            ebpf_tracepoint: preflight_noop_ebpf_tracepoint,
            linux_netns: preflight_noop_netns,
            relay_forwarder_netns: preflight_noop_netns,
            netlink,
            docker_api_socket: preflight_noop_path,
            conntrack_procfs_path: preflight_noop_path,
            ipv4_forwarding: preflight_noop,
            ipv6_forwarding: preflight_noop,
        }
    }

    fn test_preflight_checks_with_forwarding(
        ipv4_forwarding: fn() -> anyhow::Result<()>,
        ipv6_forwarding: fn() -> anyhow::Result<()>,
    ) -> RuntimePreflightChecks {
        RuntimePreflightChecks {
            cap_net_admin: preflight_noop,
            cap_net_raw: preflight_noop,
            cap_sys_admin: preflight_noop,
            cap_perfmon: preflight_noop,
            cap_bpf: preflight_noop,
            ebpf_object: preflight_noop_ebpf_object,
            ebpf_tracepoint: preflight_noop_ebpf_tracepoint,
            linux_netns: preflight_noop_netns,
            relay_forwarder_netns: preflight_noop_netns,
            netlink: preflight_noop_netlink,
            docker_api_socket: preflight_noop_path,
            conntrack_procfs_path: preflight_noop_path,
            ipv4_forwarding,
            ipv6_forwarding,
        }
    }

    fn preflight_noop_netlink(_protocol: RuntimeNetlinkProtocol) -> anyhow::Result<()> {
        Ok(())
    }

    #[test]
    fn runtime_preflight_probes_kernel_netlink_backends() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-peer-map",
            "--wireguard-backend",
            "kernel-netlink",
            "--route-backend",
            "kernel-netlink",
        ])?;

        if let Command::Agent(args) = cli.command {
            let error = match preflight_agent_runtime_with_path_and_checks(
                &args,
                Some(OsStr::new("")),
                test_preflight_checks(preflight_fail_generic_netlink),
            ) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("blocked test NETLINK_GENERIC"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn runtime_preflight_checks_relay_forwarder_namespace() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--relay-forwarder-bind",
            "127.0.0.1:0",
            "--relay-forwarder-wireguard-endpoint",
            "127.0.0.1:51820",
            "--relay-forwarder-netns",
            "relay-a",
        ])?;

        if let Command::Agent(args) = cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(!needs.ip_command);
            assert!(!needs.wg_command);
            assert!(!needs.route_netlink);
            assert!(!needs.generic_netlink);
            assert!(!needs.netfilter_netlink);
            assert!(!needs.linux_netns);
            assert!(needs.relay_forwarder_netns);
            assert!(needs.cap_sys_admin);

            let mut cap_checks = test_preflight_checks(preflight_noop_netlink);
            cap_checks.cap_sys_admin = preflight_fail_cap_sys_admin;
            let cap_error = match preflight_agent_runtime_with_path_and_checks(
                &args,
                Some(OsStr::new("")),
                cap_checks,
            ) {
                Ok(()) => anyhow::bail!("unexpected successful relay forwarder CAP preflight"),
                Err(error) => error,
            };
            assert!(cap_error.to_string().contains("blocked test CAP_SYS_ADMIN"));

            let mut namespace_checks = test_preflight_checks(preflight_noop_netlink);
            namespace_checks.relay_forwarder_netns = preflight_fail_linux_netns;
            let namespace_error = match preflight_agent_runtime_with_path_and_checks(
                &args,
                Some(OsStr::new("")),
                namespace_checks,
            ) {
                Ok(()) => {
                    anyhow::bail!("unexpected successful relay forwarder namespace preflight")
                }
                Err(error) => error,
            };
            assert!(namespace_error
                .to_string()
                .contains("blocked test netns relay-a"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn runtime_preflight_checks_relay_forwarder_inherited_linux_namespace() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--linux-netns",
            "node-a",
            "--relay-forwarder-bind",
            "127.0.0.1:0",
            "--relay-forwarder-wireguard-endpoint",
            "127.0.0.1:51820",
        ])?;

        if let Command::Agent(args) = cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(!needs.linux_netns);
            assert!(needs.relay_forwarder_netns);
            assert!(needs.cap_sys_admin);

            let mut checks = test_preflight_checks(preflight_noop_netlink);
            checks.relay_forwarder_netns = preflight_fail_linux_netns;
            let error = match preflight_agent_runtime_with_path_and_checks(
                &args,
                Some(OsStr::new("")),
                checks,
            ) {
                Ok(()) => anyhow::bail!("unexpected successful inherited namespace preflight"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("blocked test netns node-a"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn runtime_preflight_probes_conntrack_netlink_even_for_dry_run() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--packet-flow-detector",
            "conntrack-netlink",
        ])?;

        if let Command::Agent(args) = cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(!needs.ip_command);
            assert!(!needs.wg_command);
            assert!(!needs.route_netlink);
            assert!(!needs.generic_netlink);
            assert!(needs.netfilter_netlink);
            assert!(needs.cap_net_admin);
            assert!(!needs.cap_net_raw);
            let error = match preflight_agent_runtime_with_path_and_checks(
                &args,
                Some(OsStr::new("")),
                test_preflight_checks(preflight_fail_netfilter_netlink),
            ) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("blocked test NETLINK_NETFILTER"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn runtime_preflight_requires_ebpf_caps_even_for_dry_run() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--packet-flow-detector",
            "ebpf-ringbuf",
            "--packet-flow-ebpf-object-path",
            "/run/ipars/ipars-packet-flow.bpf.o",
            "--packet-flow-ebpf-attach",
            "ipars_ingress:net:netif_receive_skb",
        ])?;

        if let Command::Agent(args) = cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(!needs.ip_command);
            assert!(!needs.wg_command);
            assert!(!needs.route_netlink);
            assert!(!needs.generic_netlink);
            assert!(!needs.netfilter_netlink);
            assert!(!needs.cap_net_admin);
            assert!(!needs.cap_net_raw);
            assert!(!needs.cap_sys_admin);
            assert!(needs.cap_perfmon);
            assert!(needs.cap_bpf);
            preflight_agent_runtime_with_path_and_checks(
                &args,
                Some(OsStr::new("")),
                test_preflight_checks(preflight_noop_netlink),
            )?;
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn runtime_preflight_requires_forwarding_for_route_underlay() -> anyhow::Result<()> {
        let docker = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--route-backend",
            "kernel-netlink",
            "--docker-container-namespace",
            "compose-default",
            "--docker-container-cidr",
            "172.18.0.0/16",
        ])?;

        if let Command::Agent(args) = docker.command {
            let needs = runtime_preflight_needs(&args);
            assert!(needs.ipv4_forwarding);
            assert!(!needs.ipv6_forwarding);
            let error = match preflight_agent_runtime_with_path_and_checks(
                &args,
                Some(OsStr::new("")),
                test_preflight_checks_with_forwarding(
                    preflight_fail_ipv4_forwarding,
                    preflight_noop,
                ),
            ) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("blocked test net.ipv4.ip_forward"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let kubernetes_ipv6 = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--route-backend",
            "kernel-netlink",
            "--kubernetes-service-cidr",
            "fd00:96::/112",
        ])?;

        if let Command::Agent(args) = kubernetes_ipv6.command {
            let needs = runtime_preflight_needs(&args);
            assert!(needs.ipv4_forwarding);
            assert!(needs.ipv6_forwarding);
            let error = match preflight_agent_runtime_with_path_and_checks(
                &args,
                Some(OsStr::new("")),
                test_preflight_checks_with_forwarding(
                    preflight_noop,
                    preflight_fail_ipv6_forwarding,
                ),
            ) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("blocked test net.ipv6.conf.all.forwarding"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn runtime_preflight_checks_ebpf_object_and_tracepoints() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--packet-flow-detector",
            "ebpf-ringbuf",
            "--packet-flow-ebpf-object-path",
            "/run/ipars/ipars-packet-flow.bpf.o",
            "--packet-flow-ebpf-attach",
            "ipars_sys_enter_connect:syscalls:sys_enter_connect",
        ])?;

        if let Command::Agent(args) = cli.command {
            let mut object_checks = test_preflight_checks(preflight_noop_netlink);
            object_checks.ebpf_object = preflight_fail_ebpf_object;
            let object_error = match preflight_agent_runtime_with_path_and_checks(
                &args,
                Some(OsStr::new("")),
                object_checks,
            ) {
                Ok(()) => anyhow::bail!("unexpected successful eBPF object preflight"),
                Err(error) => error,
            };
            assert!(object_error
                .to_string()
                .contains("blocked test eBPF object /run/ipars/ipars-packet-flow.bpf.o"));

            let mut tracepoint_checks = test_preflight_checks(preflight_noop_netlink);
            tracepoint_checks.ebpf_tracepoint = preflight_fail_ebpf_tracepoint;
            let tracepoint_error = match preflight_agent_runtime_with_path_and_checks(
                &args,
                Some(OsStr::new("")),
                tracepoint_checks,
            ) {
                Ok(()) => anyhow::bail!("unexpected successful eBPF tracepoint preflight"),
                Err(error) => error,
            };
            assert!(tracepoint_error
                .to_string()
                .contains("blocked test eBPF tracepoint syscalls/sys_enter_connect"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn ebpf_object_preflight_requires_nonempty_regular_file() -> anyhow::Result<()> {
        let base = unique_test_dir("ebpf-object-preflight")?;
        let object = base.join("ipars-packet-flow.bpf.o");
        std::fs::write(&object, b"elf bytes")?;
        ensure_ebpf_object_file_ready(&object)?;

        let empty = base.join("empty.bpf.o");
        std::fs::write(&empty, b"")?;
        let empty_error = match ensure_ebpf_object_file_ready(&empty) {
            Ok(()) => anyhow::bail!("unexpected successful empty object preflight"),
            Err(error) => error,
        };
        assert!(empty_error.to_string().contains("is empty"));

        let directory = base.join("object-dir");
        std::fs::create_dir_all(&directory)?;
        let directory_error = match ensure_ebpf_object_file_ready(&directory) {
            Ok(()) => anyhow::bail!("unexpected successful directory object preflight"),
            Err(error) => error,
        };
        assert!(directory_error
            .to_string()
            .contains("must be a regular file"));

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn ebpf_tracepoint_preflight_searches_tracefs_roots() -> anyhow::Result<()> {
        let base = unique_test_dir("ebpf-tracepoint-preflight")?;
        let first_root = base.join("first/events");
        let second_root = base.join("second/events");
        std::fs::create_dir_all(&first_root)?;
        std::fs::create_dir_all(&second_root)?;
        let roots = [first_root.as_path(), second_root.as_path()];
        let attachment =
            EbpfTracepointAttachSpec::parse("ipars_sys_enter_connect:syscalls:sys_enter_connect")?;

        let missing_error = match ensure_ebpf_tracepoint_ready_in_roots(&attachment, roots) {
            Ok(()) => anyhow::bail!("unexpected successful missing tracepoint preflight"),
            Err(error) => error,
        };
        assert!(missing_error
            .to_string()
            .contains("syscalls/sys_enter_connect"));

        let tracepoint_dir = second_root.join("syscalls/sys_enter_connect");
        std::fs::create_dir_all(&tracepoint_dir)?;
        let tracepoint_id = tracepoint_dir.join("id");
        std::fs::write(&tracepoint_id, b"123\n")?;
        ensure_ebpf_tracepoint_ready_in_roots(&attachment, roots)?;

        std::fs::write(&tracepoint_id, b"")?;
        let empty_id_error = match ensure_ebpf_tracepoint_ready_in_roots(&attachment, roots) {
            Ok(()) => anyhow::bail!("unexpected successful empty tracepoint id preflight"),
            Err(error) => error,
        };
        assert!(empty_id_error.to_string().contains("is empty"));

        std::fs::write(&tracepoint_id, b"abc\n")?;
        let non_numeric_id_error = match ensure_ebpf_tracepoint_ready_in_roots(&attachment, roots) {
            Ok(()) => anyhow::bail!("unexpected successful non-numeric tracepoint id preflight"),
            Err(error) => error,
        };
        assert!(format!("{non_numeric_id_error:#}").contains("is not numeric"));

        std::fs::write(&tracepoint_id, b"0\n")?;
        let zero_id_error = match ensure_ebpf_tracepoint_ready_in_roots(&attachment, roots) {
            Ok(()) => anyhow::bail!("unexpected successful zero tracepoint id preflight"),
            Err(error) => error,
        };
        assert!(zero_id_error
            .to_string()
            .contains("must be greater than zero"));

        std::fs::write(&tracepoint_id, vec![b'1'; MAX_EBPF_TRACEPOINT_ID_BYTES + 1])?;
        let oversized_id_error = match ensure_ebpf_tracepoint_ready_in_roots(&attachment, roots) {
            Ok(()) => anyhow::bail!("unexpected successful oversized tracepoint id preflight"),
            Err(error) => error,
        };
        assert!(oversized_id_error.to_string().contains("exceeds"));

        #[cfg(unix)]
        {
            let target = base.join("tracepoint-id-target");
            std::fs::write(&target, b"123\n")?;
            std::fs::remove_file(&tracepoint_id)?;
            std::os::unix::fs::symlink(&target, &tracepoint_id)?;
            let symlink_error = match ensure_ebpf_tracepoint_ready_in_roots(&attachment, roots) {
                Ok(()) => anyhow::bail!("unexpected successful symlink tracepoint preflight"),
                Err(error) => error,
            };
            assert!(symlink_error.to_string().contains("symlink id path"));
        }

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn proc_sysctl_flag_parses_kernel_boolean_values() -> anyhow::Result<()> {
        let base = unique_test_dir("sysctl-flag")?;
        let enabled = base.join("enabled");
        let disabled = base.join("disabled");
        let invalid = base.join("invalid");
        let oversized = base.join("oversized");
        std::fs::write(&enabled, "1\n")?;
        std::fs::write(&disabled, "0\n")?;
        std::fs::write(&invalid, "2\n")?;
        std::fs::write(
            &oversized,
            vec![b'1'; MAX_PROC_SYSCTL_FLAG_BYTES as usize + 1],
        )?;

        assert_eq!(proc_sysctl_flag(&enabled)?, Some(true));
        assert_eq!(proc_sysctl_flag(&disabled)?, Some(false));
        assert_eq!(proc_sysctl_flag(&base.join("missing"))?, None);
        let error = match proc_sysctl_flag(&invalid) {
            Ok(_) => anyhow::bail!("unexpected successful sysctl parse"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unsupported boolean value"));
        let error = match proc_sysctl_flag(&oversized) {
            Ok(_) => anyhow::bail!("unexpected successful oversized sysctl read"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds maximum size"));
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn process_status_capability_parser_handles_known_and_missing_caps() -> anyhow::Result<()> {
        let status = "Name:\tiparsd\nCapEff:\t0000000000003000\n";
        assert_eq!(
            process_status_has_capability(status, CAP_NET_ADMIN_BIT)?,
            Some(true)
        );
        assert_eq!(
            process_status_has_capability(status, CAP_NET_RAW_BIT)?,
            Some(true)
        );
        assert_eq!(
            process_status_has_capability(status, CAP_SYS_ADMIN_BIT)?,
            Some(false)
        );
        let modern_ebpf_caps = format!(
            "Name:\tiparsd\nCapEff:\t{:016x}\n",
            (1_u64 << CAP_PERFMON_BIT) | (1_u64 << CAP_BPF_BIT)
        );
        assert_eq!(
            process_status_has_any_capability(
                &modern_ebpf_caps,
                &[CAP_BPF_BIT, CAP_SYS_ADMIN_BIT]
            )?,
            Some(true)
        );
        assert_eq!(
            process_status_has_any_capability(status, &[CAP_BPF_BIT, CAP_SYS_ADMIN_BIT])?,
            Some(false)
        );
        assert_eq!(
            process_status_has_capability("Name:\tiparsd\n", CAP_NET_RAW_BIT)?,
            None
        );
        Ok(())
    }

    #[test]
    fn process_status_file_reader_bounds_proc_status_input() -> anyhow::Result<()> {
        let base = unique_test_dir("process-status-reader")?;
        let status_path = base.join("status");
        let oversized_path = base.join("oversized-status");
        std::fs::write(&status_path, "Name:\tiparsd\nCapEff:\t0000000000003000\n")?;
        std::fs::write(
            &oversized_path,
            vec![b'N'; MAX_PROC_SELF_STATUS_BYTES as usize + 1],
        )?;

        let status = read_process_status_file(&status_path)?.context("missing test status")?;
        assert_eq!(
            process_status_has_capability(&status, CAP_NET_ADMIN_BIT)?,
            Some(true)
        );
        assert!(read_process_status_file(&base.join("missing"))?.is_none());
        let error = match read_process_status_file(&oversized_path) {
            Ok(_) => anyhow::bail!("unexpected successful oversized process status read"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds maximum size"));
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn runtime_preflight_validates_linux_interface_name() -> anyhow::Result<()> {
        for (interface, expected) in [
            ("invalid/name", "must contain only ASCII letters"),
            (".", "must not be '.' or '..'"),
            ("-ipars0", "must not start with '-'"),
        ] {
            let cli = Cli::try_parse_from([
                "iparsd",
                "agent",
                "--runtime-backend",
                "dry-run",
                &format!("--wireguard-interface={interface}"),
            ])?;

            let Command::Agent(args) = cli.command else {
                anyhow::bail!("expected agent command");
            };
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight for {interface}"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(expected),
                "expected {expected}, got {error}"
            );
        }

        Ok(())
    }

    #[test]
    fn agent_hole_punch_config_must_be_positive_when_signal_paths_are_enabled() -> anyhow::Result<()>
    {
        for (flag, expected) in [
            (
                "--hole-punch-attempts",
                "--hole-punch-attempts must be greater than zero",
            ),
            (
                "--hole-punch-interval-millis",
                "--hole-punch-interval-millis must be greater than zero",
            ),
        ] {
            let cli = Cli::try_parse_from([
                "iparsd",
                "agent",
                "--runtime-backend",
                "dry-run",
                "--skip-runtime-preflight",
                flag,
                "0",
            ])?;
            if let Command::Agent(args) = cli.command {
                let error = match validate_agent_runtime_config(&args) {
                    Ok(()) => anyhow::bail!("unexpected valid agent runtime config"),
                    Err(error) => error,
                };
                assert!(
                    error.to_string().contains(expected),
                    "{flag} should fail with {expected}, got {error}"
                );
            } else {
                anyhow::bail!("expected agent command");
            }
        }

        let disabled = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--disable-signal-paths",
            "--hole-punch-attempts",
            "0",
            "--hole-punch-interval-millis",
            "0",
        ])?;
        if let Command::Agent(args) = disabled.command {
            validate_agent_runtime_config(&args)?;
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn runtime_config_validation_survives_skipped_runtime_preflight() -> anyhow::Result<()> {
        let invalid_docker_host_interface = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--apply-docker-routes",
            "--docker-discover-networks",
            "--docker-host-interface",
            "invalid/name",
        ])?;
        if let Command::Agent(args) = invalid_docker_host_interface.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("must contain only ASCII letters"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let invalid_relay_forwarder_namespace = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-forwarder-bind",
            "127.0.0.1:0",
            "--relay-forwarder-wireguard-endpoint",
            "127.0.0.1:51820",
            "--relay-forwarder-netns",
            "../node-a",
        ])?;
        if let Command::Agent(args) = invalid_relay_forwarder_namespace.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("invalid linux network namespace name"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let option_like_relay_forwarder_namespace = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-forwarder-bind",
            "127.0.0.1:0",
            "--relay-forwarder-wireguard-endpoint",
            "127.0.0.1:51820",
            "--relay-forwarder-netns=-node-a",
        ])?;
        if let Command::Agent(args) = option_like_relay_forwarder_namespace.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("invalid linux network namespace name"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let unusable_relay_forwarder_endpoint = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-forwarder-endpoint",
            "127.0.0.1:0",
        ])?;
        if let Command::Agent(args) = unusable_relay_forwarder_endpoint.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("--relay-forwarder-endpoint"));
            assert!(error.to_string().contains("usable nonzero"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let missing_forwarder_wireguard_endpoint = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-forwarder-bind",
            "127.0.0.1:0",
        ])?;
        if let Command::Agent(args) = missing_forwarder_wireguard_endpoint.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(
                "--relay-forwarder-wireguard-endpoint is required with --relay-forwarder-bind"
            ));
        } else {
            anyhow::bail!("expected agent command");
        }

        let unusable_forwarder_wireguard_endpoint = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-forwarder-bind",
            "127.0.0.1:0",
            "--relay-forwarder-wireguard-endpoint",
            "0.0.0.0:51820",
        ])?;
        if let Command::Agent(args) = unusable_forwarder_wireguard_endpoint.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--relay-forwarder-wireguard-endpoint"));
            assert!(error.to_string().contains("usable nonzero"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let inactive_forwarder_wireguard_endpoint = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-forwarder-wireguard-endpoint",
            "127.0.0.1:51820",
        ])?;
        if let Command::Agent(args) = inactive_forwarder_wireguard_endpoint.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--relay-forwarder-wireguard-endpoint requires --relay-forwarder-bind"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let zero_forwarder_capacity = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--skip-runtime-preflight",
            "--relay-forwarder-bind",
            "127.0.0.1:0",
            "--relay-forwarder-wireguard-endpoint",
            "127.0.0.1:51820",
            "--relay-forwarder-max-sessions",
            "0",
        ])?;
        if let Command::Agent(args) = zero_forwarder_capacity.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--relay-forwarder-max-sessions must be greater than zero"));
        } else {
            anyhow::bail!("expected agent command");
        }

        for (flag, expected) in [
            (
                "--relay-forwarder-restart-backoff-seconds",
                "--relay-forwarder-restart-backoff-seconds must be greater than zero",
            ),
            (
                "--relay-forwarder-crash-window-seconds",
                "--relay-forwarder-crash-window-seconds must be greater than zero",
            ),
            (
                "--relay-forwarder-max-crashes-per-window",
                "--relay-forwarder-max-crashes-per-window must be greater than zero",
            ),
            (
                "--relay-forwarder-crash-cooldown-seconds",
                "--relay-forwarder-crash-cooldown-seconds must be greater than zero",
            ),
        ] {
            let cli = Cli::try_parse_from([
                "iparsd",
                "agent",
                "--runtime-backend",
                "dry-run",
                "--skip-runtime-preflight",
                "--relay-forwarder-bind",
                "127.0.0.1:0",
                "--relay-forwarder-wireguard-endpoint",
                "127.0.0.1:51820",
                flag,
                "0",
            ])?;
            if let Command::Agent(args) = cli.command {
                let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                    Ok(()) => anyhow::bail!("unexpected successful preflight"),
                    Err(error) => error,
                };
                assert!(
                    error.to_string().contains(expected),
                    "{flag} should fail with {expected}, got {error}"
                );
            } else {
                anyhow::bail!("expected agent command");
            }
        }

        Ok(())
    }

    #[test]
    fn linux_netns_path_preflight_rejects_missing_and_directory() -> anyhow::Result<()> {
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let base = unique_test_dir("netns-preflight")?;
        let missing = base.join("missing");
        let error = match inspect_linux_netns_path(&namespace, &missing, None) {
            Ok(_) => anyhow::bail!("unexpected successful netns path inspection"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("does not exist"));

        let directory = base.join("directory");
        std::fs::create_dir(&directory)?;
        let error = match inspect_linux_netns_path(&namespace, &directory, None) {
            Ok(_) => anyhow::bail!("unexpected successful netns path inspection"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("not a directory"));
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_netns_path_preflight_rejects_regular_file() -> anyhow::Result<()> {
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let base = unique_test_dir("netns-preflight-regular-file")?;
        let path = base.join("node-a");
        std::fs::write(&path, b"netns")?;

        let error = match inspect_linux_netns_path(&namespace, &path, None) {
            Ok(_) => anyhow::bail!("unexpected successful netns path inspection"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("nsfs namespace bind mount"));
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_netns_filesystem_probe_accepts_proc_namespace_target() -> anyhow::Result<()> {
        let path = current_process_netns_path().context("missing current process net namespace")?;

        assert!(is_linux_nsfs_path(&path)?);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn linux_netns_path_identity_helper_detects_same_file() -> anyhow::Result<()> {
        let base = unique_test_dir("netns-preflight-current")?;
        let path = base.join("node-a");
        std::fs::write(&path, b"netns")?;

        assert!(same_file_identity(&path, &path)?);
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn linux_netns_path_preflight_rejects_symlink() -> anyhow::Result<()> {
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let base = unique_test_dir("netns-preflight-symlink")?;
        let target = base.join("target");
        let link = base.join("node-a");
        std::fs::write(&target, b"netns")?;
        std::os::unix::fs::symlink(&target, &link)?;

        let error = match inspect_linux_netns_path(&namespace, &link, None) {
            Ok(_) => anyhow::bail!("unexpected successful netns path inspection"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("must not be a symlink"));
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn relay_forwarder_process_netns_check_rejects_symlink_target() -> anyhow::Result<()> {
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let base = unique_test_dir("relay-forwarder-netns-symlink")?;
        let target = base.join("target");
        let link = base.join("node-a");
        let current = base.join("current");
        std::fs::write(&target, b"netns")?;
        std::fs::write(&current, b"netns")?;
        std::os::unix::fs::symlink(&target, &link)?;

        let error = match ensure_process_in_netns_path(&namespace, &link, &current) {
            Ok(_) => anyhow::bail!("unexpected successful relay forwarder netns check"),
            Err(error) => error,
        };

        assert!(format!("{error:#}").contains("must not be a symlink"));
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn relay_forwarder_netns_identity_enforces_current_process() -> anyhow::Result<()> {
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let base = unique_test_dir("relay-forwarder-netns-identity")?;
        let target = base.join("node-a");
        let current = base.join("current");
        std::fs::write(&target, b"netns")?;
        std::fs::hard_link(&target, &current)?;

        let same_namespace_report = LinuxNetnsPathReport {
            same_as_current: Some(same_file_identity(&target, &current)?),
        };
        ensure_relay_forwarder_current_netns_match(&namespace, &target, &same_namespace_report)?;

        let other = base.join("other");
        std::fs::write(&other, b"other-netns")?;
        let different_namespace_report = LinuxNetnsPathReport {
            same_as_current: Some(same_file_identity(&target, &other)?),
        };
        let error = match ensure_relay_forwarder_current_netns_match(
            &namespace,
            &target,
            &different_namespace_report,
        ) {
            Ok(_) => anyhow::bail!("unexpected successful relay forwarder netns mismatch check"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("current process is in a different namespace"));
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    fn unique_test_dir(name: &str) -> anyhow::Result<PathBuf> {
        let path = std::env::temp_dir().join(format!(
            "ipars-{name}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&path)?;
        Ok(path)
    }

    #[cfg(unix)]
    fn unique_trusted_test_dir(name: &str) -> anyhow::Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-tmp");
        std::fs::create_dir_all(&root)?;
        let root = root.canonicalize()?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))?;
        let path = root.join(format!(
            "ipars-{name}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        Ok(path)
    }

    #[cfg(unix)]
    fn write_trusted_test_executable(path: &Path, contents: &str) -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        std::fs::write(path, contents)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
        Ok(())
    }

    fn env_flag_enabled(name: &str) -> bool {
        std::env::var(name).is_ok_and(|value| {
            value == "1"
                || value.eq_ignore_ascii_case("true")
                || value.eq_ignore_ascii_case("yes")
                || value.eq_ignore_ascii_case("on")
        })
    }

    #[tokio::test]
    async fn relay_forwarder_supervisor_enforces_capacity() -> anyhow::Result<()> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ipars_types::ClusterPolicy::default(),
        );
        let supervisor = RelayForwarderSupervisor::new(RelayForwarderConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            wireguard_endpoint: SocketAddr::from(([127, 0, 0, 1], 51_820)),
            placement: RelayForwarderPlacement::CurrentProcess,
            max_sessions: 0,
            restart_backoff: Duration::from_secs(1),
            crash_policy: test_crash_policy(),
        });
        let session = RelaySessionState {
            peer: NodeId::from_string("peer-a"),
            relay_node: NodeId::from_string("relay-a"),
            relay_endpoint: SocketAddr::from(([127, 0, 0, 1], 40_000)),
            admitted_local_addr: SocketAddr::from(([127, 0, 0, 1], 40_001)),
            admitted_peer_addr: SocketAddr::from(([127, 0, 0, 1], 40_002)),
            session_id: "session-a".to_string(),
            session_token: "token-a".to_string(),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        };

        let error = match supervisor.upsert(&runtime, session).await {
            Ok(endpoint) => anyhow::bail!("unexpected relay forwarder endpoint: {endpoint}"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("capacity exceeded"));
        assert!(runtime.relay_forwarder_endpoints().await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn relay_forwarder_supervisor_reaps_dead_tasks_and_backs_off() -> anyhow::Result<()> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ipars_types::ClusterPolicy::default(),
        );
        let supervisor = RelayForwarderSupervisor::new(RelayForwarderConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            wireguard_endpoint: SocketAddr::from(([127, 0, 0, 1], 51_820)),
            placement: RelayForwarderPlacement::CurrentProcess,
            max_sessions: 10,
            restart_backoff: Duration::from_secs(30),
            crash_policy: test_crash_policy(),
        });
        let peer = NodeId::from_string("peer-dead");
        let local_endpoint = SocketAddr::from(([127, 0, 0, 1], 42_000));
        runtime
            .upsert_relay_forwarder_endpoint(peer.clone(), local_endpoint)
            .await;
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async {
            Err(AgentError::RelaySession(
                "synthetic forwarder death".to_string(),
            ))
        });
        supervisor.handles.lock().await.insert(
            peer.clone(),
            RelayForwarderTask {
                session_id: "session-dead".to_string(),
                relay_endpoint: SocketAddr::from(([127, 0, 0, 1], 40_000)),
                local_endpoint,
                shutdown_tx,
                task,
            },
        );
        tokio::task::yield_now().await;

        assert_eq!(supervisor.reap_finished(&runtime).await, 1);
        assert!(runtime.relay_forwarder_endpoints().await.is_empty());

        let session = RelaySessionState {
            peer,
            relay_node: NodeId::from_string("relay-a"),
            relay_endpoint: SocketAddr::from(([127, 0, 0, 1], 40_000)),
            admitted_local_addr: SocketAddr::from(([127, 0, 0, 1], 40_001)),
            admitted_peer_addr: SocketAddr::from(([127, 0, 0, 1], 40_002)),
            session_id: "session-new".to_string(),
            session_token: "token-new".to_string(),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        };
        let error = match supervisor.upsert(&runtime, session).await {
            Ok(endpoint) => anyhow::bail!("unexpected relay forwarder endpoint: {endpoint}"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("restart backoff active"));
        Ok(())
    }

    #[tokio::test]
    async fn relay_forwarder_supervisor_enters_crash_loop_cooldown() -> anyhow::Result<()> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ipars_types::ClusterPolicy::default(),
        );
        let supervisor = RelayForwarderSupervisor::new(RelayForwarderConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            wireguard_endpoint: SocketAddr::from(([127, 0, 0, 1], 51_820)),
            placement: RelayForwarderPlacement::CurrentProcess,
            max_sessions: 10,
            restart_backoff: Duration::ZERO,
            crash_policy: RelayForwarderCrashPolicy {
                window: Duration::from_secs(60),
                max_crashes_per_window: 2,
                cooldown: Duration::from_secs(30),
            },
        });
        let peer = NodeId::from_string("peer-crash-loop");

        insert_dead_forwarder(&supervisor, &runtime, &peer, "session-dead-1").await;
        assert_eq!(supervisor.reap_finished(&runtime).await, 1);
        insert_dead_forwarder(&supervisor, &runtime, &peer, "session-dead-2").await;
        assert_eq!(supervisor.reap_finished(&runtime).await, 1);

        let session = RelaySessionState {
            peer,
            relay_node: NodeId::from_string("relay-a"),
            relay_endpoint: SocketAddr::from(([127, 0, 0, 1], 40_000)),
            admitted_local_addr: SocketAddr::from(([127, 0, 0, 1], 40_001)),
            admitted_peer_addr: SocketAddr::from(([127, 0, 0, 1], 40_002)),
            session_id: "session-new".to_string(),
            session_token: "token-new".to_string(),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        };
        let error = match supervisor.upsert(&runtime, session).await {
            Ok(endpoint) => anyhow::bail!("unexpected relay forwarder endpoint: {endpoint}"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("crash-loop cooldown active"));
        Ok(())
    }

    #[tokio::test]
    async fn relay_forwarder_supervisor_counts_repeated_bind_failures() -> anyhow::Result<()> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ipars_types::ClusterPolicy::default(),
        );
        let occupied_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let supervisor = RelayForwarderSupervisor::new(RelayForwarderConfig {
            bind_addr: occupied_socket.local_addr()?,
            wireguard_endpoint: SocketAddr::from(([127, 0, 0, 1], 51_820)),
            placement: RelayForwarderPlacement::CurrentProcess,
            max_sessions: 10,
            restart_backoff: Duration::ZERO,
            crash_policy: RelayForwarderCrashPolicy {
                window: Duration::from_secs(60),
                max_crashes_per_window: 2,
                cooldown: Duration::from_secs(30),
            },
        });
        let peer = NodeId::from_string("peer-bind-loop");
        let session = || RelaySessionState {
            peer: peer.clone(),
            relay_node: NodeId::from_string("relay-a"),
            relay_endpoint: SocketAddr::from(([127, 0, 0, 1], 40_000)),
            admitted_local_addr: SocketAddr::from(([127, 0, 0, 1], 40_001)),
            admitted_peer_addr: SocketAddr::from(([127, 0, 0, 1], 40_002)),
            session_id: "session-new".to_string(),
            session_token: "token-new".to_string(),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        };

        let first_error = match supervisor.upsert(&runtime, session()).await {
            Ok(endpoint) => anyhow::bail!("unexpected relay forwarder endpoint: {endpoint}"),
            Err(error) => error,
        };
        assert!(first_error.to_string().contains("failed to bind"));
        let second_error = match supervisor.upsert(&runtime, session()).await {
            Ok(endpoint) => anyhow::bail!("unexpected relay forwarder endpoint: {endpoint}"),
            Err(error) => error,
        };
        assert!(second_error.to_string().contains("failed to bind"));
        let third_error = match supervisor.upsert(&runtime, session()).await {
            Ok(endpoint) => anyhow::bail!("unexpected relay forwarder endpoint: {endpoint}"),
            Err(error) => error,
        };

        assert!(third_error
            .to_string()
            .contains("crash-loop cooldown active"));
        Ok(())
    }

    #[test]
    fn kubernetes_underlay_intent_uses_local_node_as_default_provider() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--kubernetes-node-name",
            "worker-a",
            "--kubernetes-service-cidr",
            "10.96.0.0/12",
        ])?;

        if let Command::Agent(args) = cli.command {
            let local = NodeId::from_string("local-node");
            let intent = kubernetes_underlay_intent(&args, local.clone())?;
            assert_eq!(intent.node_name, "worker-a");
            assert_eq!(intent.overlay_interface, "ipars0");
            assert_eq!(intent.route_provider, local);
            assert!(intent.api_server_cidrs.is_empty());
            assert_eq!(
                intent.service_cidrs,
                vec!["10.96.0.0/12".parse::<ipnet::IpNet>()?]
            );
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn kubernetes_underlay_intent_discovers_api_server_host_route_without_service_discovery(
    ) -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--kubernetes-node-name",
            "worker-a",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert!(!args.kubernetes_discover_services);
            assert!(args.kubernetes_discover_api_server);

            let intent = kubernetes_underlay_intent_with_api_server_host(
                &args,
                NodeId::from_string("local-node"),
                Some(OsStr::new("10.96.0.1")),
            )?;
            assert_eq!(intent.node_name, "worker-a");
            assert_eq!(
                intent.api_server_cidrs,
                vec!["10.96.0.1/32".parse::<ipnet::IpNet>()?]
            );
            assert!(intent.service_cidrs.is_empty());

            let missing_host_error = match kubernetes_underlay_intent_with_api_server_host(
                &args,
                NodeId::from_string("local-node"),
                None,
            ) {
                Ok(intent) => {
                    anyhow::bail!("missing Kubernetes Service host should be rejected: {intent:?}")
                }
                Err(error) => error.to_string(),
            };
            assert!(missing_host_error.contains("KUBERNETES_SERVICE_HOST"));

            let invalid_host_error = match kubernetes_underlay_intent_with_api_server_host(
                &args,
                NodeId::from_string("local-node"),
                Some(OsStr::new("kubernetes.default.svc")),
            ) {
                Ok(intent) => {
                    anyhow::bail!("non-IP Kubernetes Service host should be rejected: {intent:?}")
                }
                Err(error) => error.to_string(),
            };
            assert!(invalid_host_error.contains("KUBERNETES_SERVICE_HOST"));
            assert!(invalid_host_error.contains("is not an IP address"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[tokio::test]
    async fn kubernetes_underlay_builds_agent_requested_routes() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--kubernetes-node-name",
            "worker-a",
            "--kubernetes-api-server-cidr",
            "10.0.0.1/32",
            "--kubernetes-service-cidr",
            "10.96.0.0/12",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = cli.command {
            let node_id = NodeId::from_string("route-provider-a");
            let routes = agent_requested_routes(&args, node_id.clone()).await?;

            assert_eq!(routes.len(), 2);
            assert_eq!(routes[0].id, "k8s-v4-10-0-0-1-32");
            assert_eq!(routes[0].cidr, "10.0.0.1/32".parse::<ipnet::IpNet>()?);
            assert_eq!(routes[0].advertised_by, node_id);
            assert_eq!(routes[0].via, Some(NodeId::from_string("route-provider-a")));
            assert_eq!(routes[1].id, "k8s-v4-10-96-0-0-12");
            assert_eq!(routes[1].cidr, "10.96.0.0/12".parse::<ipnet::IpNet>()?);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn kubernetes_discovery_validates_namespace_and_label_selector_syntax() {
        for namespace in ["default", "platform-1", "a", "ns0"] {
            assert!(
                validate_kubernetes_namespace(namespace).is_ok(),
                "{namespace} should be valid"
            );
        }
        for namespace in ["", "Platform", "platform/team", "-bad", "bad-"] {
            assert!(
                validate_kubernetes_namespace(namespace).is_err(),
                "{namespace} should be invalid"
            );
        }
        let too_long = "a".repeat(64);
        assert!(validate_kubernetes_namespace(&too_long).is_err());

        for selector in [
            "ipars.io/expose=true",
            "tier in (frontend,backend),env!=dev",
        ] {
            assert!(
                validate_kubernetes_label_selector(selector).is_ok(),
                "{selector} should be valid"
            );
        }
        for selector in ["", "ipars.io/expose=true\n"] {
            assert!(
                validate_kubernetes_label_selector(selector).is_err(),
                "{selector:?} should be invalid"
            );
        }
        let too_long = "a".repeat(1025);
        assert!(validate_kubernetes_label_selector(&too_long).is_err());
    }

    #[test]
    fn kubernetes_discovery_options_require_api_discovery() -> anyhow::Result<()> {
        let namespace_cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--kubernetes-service-cidr",
            "10.96.0.0/12",
            "--kubernetes-namespace",
            "default",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = namespace_cli.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(_) => anyhow::bail!("Kubernetes namespace without discovery should be rejected"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--kubernetes-namespace requires --kubernetes-discover-services"));
        } else {
            anyhow::bail!("expected agent command");
        }

        let selector_cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--kubernetes-service-cidr",
            "10.96.0.0/12",
            "--kubernetes-service-label-selector",
            "ipars.io/expose=true",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = selector_cli.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(_) => anyhow::bail!("Kubernetes selector without discovery should be rejected"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(
                "--kubernetes-service-label-selector requires --kubernetes-discover-services"
            ));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn kubernetes_discovery_namespaces_must_be_unique() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--kubernetes-discover-services",
            "--kubernetes-namespace",
            "default",
            "--kubernetes-namespace",
            "default",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = cli.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(_) => anyhow::bail!("duplicate Kubernetes namespace filter should be rejected"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--kubernetes-namespace `default` must not be repeated"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn kubernetes_underlay_rejects_invalid_route_provider() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--kubernetes-service-cidr",
            "10.96.0.0/12",
            "--kubernetes-route-provider",
            "route provider",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = cli.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(_) => anyhow::bail!("invalid Kubernetes route provider should be rejected"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(
                "--kubernetes-route-provider must contain only ASCII letters, digits, '_', '.' or '-'"
            ));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn kubernetes_underlay_rejects_invalid_api_url() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--kubernetes-discover-services",
            "--kubernetes-api-url",
            "udp://kubernetes.default.svc",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = cli.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(_) => anyhow::bail!("invalid Kubernetes API URL should be rejected"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--kubernetes-api-url must use http or https"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn kubernetes_service_discovery_builds_host_route_cidrs() -> anyhow::Result<()> {
        let services = KubernetesServiceList {
            items: vec![
                kubernetes_service(Some("10.96.0.1"), &[]),
                kubernetes_service(None, &["10.96.0.20", "10.96.0.20", "fd00::20"]),
                kubernetes_service(Some("None"), &[]),
            ],
        };

        assert_eq!(
            kubernetes_service_route_cidrs(&services)?,
            vec![
                "10.96.0.1/32".parse::<ipnet::IpNet>()?,
                "10.96.0.20/32".parse::<ipnet::IpNet>()?,
                "fd00::20/128".parse::<ipnet::IpNet>()?,
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn kubernetes_services_response_reader_bounds_body() -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
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
            let request_text = String::from_utf8_lossy(&request).into_owned();
            anyhow::ensure!(
                request_text.starts_with("GET /api/v1/services "),
                "unexpected Kubernetes services request line: {request_text}"
            );
            let body = r#"{"items":[{"spec":{"clusterIP":"10.96.0.10","clusterIPs":["10.96.0.10","fd00::10"]}}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;
            Ok::<(), anyhow::Error>(())
        });

        let response = reqwest::Client::new()
            .get(format!("http://{addr}/api/v1/services"))
            .send()
            .await?;
        let services = read_kubernetes_services_response(response).await?;
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .context("timed out waiting for Kubernetes services response server")???;
        assert_eq!(
            kubernetes_service_route_cidrs(&services)?,
            vec![
                "10.96.0.10/32".parse::<ipnet::IpNet>()?,
                "fd00::10/128".parse::<ipnet::IpNet>()?,
            ]
        );

        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let addr = listener.local_addr()?;
        let oversized_server = tokio::spawn(async move {
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
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_KUBERNETES_SERVICES_RESPONSE_BYTES + 1
            );
            stream.write_all(response.as_bytes()).await?;
            Ok::<(), anyhow::Error>(())
        });

        let response = reqwest::Client::new()
            .get(format!("http://{addr}/api/v1/services"))
            .send()
            .await?;
        let error = match read_kubernetes_services_response(response).await {
            Ok(services) => anyhow::bail!(
                "oversized Kubernetes services response should be rejected: {services:?}"
            ),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("Kubernetes services API response exceeds maximum size"));
        tokio::time::timeout(Duration::from_secs(5), oversized_server)
            .await
            .context("timed out waiting for oversized Kubernetes services response server")???;
        Ok(())
    }

    #[test]
    fn kubernetes_service_account_token_reader_validates_input() -> anyhow::Result<()> {
        let base = unique_test_dir("kubernetes-service-account-token")?;
        let token_path = base.join("token");
        std::fs::write(&token_path, " bearer-token\n")?;
        assert_eq!(
            read_kubernetes_service_account_token(&token_path)?,
            "bearer-token"
        );

        let directory = base.join("token-dir");
        std::fs::create_dir(&directory)?;
        let directory_error = match read_kubernetes_service_account_token(&directory) {
            Ok(_) => anyhow::bail!("directory service account token should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(directory_error.contains("must resolve to a regular file"));

        let empty_path = base.join("empty-token");
        std::fs::write(&empty_path, " \n")?;
        let empty_error = match read_kubernetes_service_account_token(&empty_path) {
            Ok(_) => anyhow::bail!("empty service account token should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(empty_error.contains("Kubernetes service account token at"));
        assert!(empty_error.contains("is empty"));

        let oversized_path = base.join("oversized-token");
        std::fs::write(
            &oversized_path,
            "x".repeat(MAX_KUBERNETES_SERVICE_ACCOUNT_TOKEN_BYTES as usize + 1),
        )?;
        let oversized_error = match read_kubernetes_service_account_token(&oversized_path) {
            Ok(_) => anyhow::bail!("oversized service account token should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(oversized_error.contains("exceeds maximum size"));

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn kubernetes_ca_certificate_reader_validates_input() -> anyhow::Result<()> {
        let base = unique_test_dir("kubernetes-ca-certificate")?;
        let ca_path = base.join("ca.crt");
        std::fs::write(&ca_path, b"-----BEGIN CERTIFICATE-----\nfixture\n")?;
        assert_eq!(
            read_kubernetes_ca_certificate(&ca_path)?,
            b"-----BEGIN CERTIFICATE-----\nfixture\n".to_vec()
        );

        let directory = base.join("ca-dir");
        std::fs::create_dir(&directory)?;
        let directory_error = match read_kubernetes_ca_certificate(&directory) {
            Ok(_) => anyhow::bail!("directory Kubernetes CA certificate should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(directory_error.contains("must resolve to a regular file"));

        let empty_path = base.join("empty-ca.crt");
        std::fs::write(&empty_path, b"")?;
        let empty_error = match read_kubernetes_ca_certificate(&empty_path) {
            Ok(_) => anyhow::bail!("empty Kubernetes CA certificate should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(empty_error.contains("Kubernetes CA certificate at"));
        assert!(empty_error.contains("is empty"));

        let oversized_path = base.join("oversized-ca.crt");
        std::fs::write(
            &oversized_path,
            vec![b'x'; MAX_KUBERNETES_CA_CERT_BYTES as usize + 1],
        )?;
        let oversized_error = match read_kubernetes_ca_certificate(&oversized_path) {
            Ok(_) => anyhow::bail!("oversized Kubernetes CA certificate should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(oversized_error.contains("exceeds maximum size"));

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn kubernetes_api_discovery_helpers_build_urls_and_api_server_routes() -> anyhow::Result<()> {
        assert_eq!(
            kubernetes_api_base_url(
                None,
                Some(std::ffi::OsStr::new("10.96.0.1")),
                Some(std::ffi::OsStr::new("6443")),
            )?,
            "https://10.96.0.1:6443"
        );
        assert_eq!(
            kubernetes_api_base_url(None, Some(std::ffi::OsStr::new("fd00::1")), None)?,
            "https://[fd00::1]:443"
        );
        assert_eq!(
            kubernetes_api_base_url(Some("https://kubernetes.default.svc/"), None, None)?,
            "https://kubernetes.default.svc"
        );
        assert_eq!(
            kubernetes_services_url("https://10.96.0.1:443", None),
            "https://10.96.0.1:443/api/v1/services"
        );
        assert_eq!(
            kubernetes_services_url("https://10.96.0.1:443", Some("platform")),
            "https://10.96.0.1:443/api/v1/namespaces/platform/services"
        );
        assert_eq!(
            kubernetes_api_server_env_cidr(Some(std::ffi::OsStr::new("10.96.0.1")))?,
            Some("10.96.0.1/32".parse::<ipnet::IpNet>()?)
        );
        let scheme_error =
            match kubernetes_api_base_url(Some("udp://kubernetes.default.svc"), None, None) {
                Ok(url) => anyhow::bail!("invalid Kubernetes API URL should be rejected: {url}"),
                Err(error) => error.to_string(),
            };
        assert!(scheme_error.contains("--kubernetes-api-url must use http or https"));
        let numeric_host_error = match kubernetes_api_base_url(Some("https://0.0.0.0"), None, None)
        {
            Ok(url) => anyhow::bail!("unusable Kubernetes API URL should be rejected: {url}"),
            Err(error) => error.to_string(),
        };
        assert!(numeric_host_error.contains(
            "--kubernetes-api-url must use a nonzero port and a usable non-unspecified, non-multicast, non-broadcast numeric host"
        ));
        let port_error = match kubernetes_api_base_url(
            None,
            Some(std::ffi::OsStr::new("10.96.0.1")),
            Some(std::ffi::OsStr::new("abc")),
        ) {
            Ok(url) => anyhow::bail!("invalid Kubernetes Service port should be rejected: {url}"),
            Err(error) => error.to_string(),
        };
        assert!(port_error.contains("KUBERNETES_SERVICE_PORT `abc` must be an integer port"));
        let zero_port_error = match kubernetes_api_base_url(
            None,
            Some(std::ffi::OsStr::new("10.96.0.1")),
            Some(std::ffi::OsStr::new("0")),
        ) {
            Ok(url) => {
                anyhow::bail!("zero Kubernetes Service port should be rejected: {url}");
            }
            Err(error) => error.to_string(),
        };
        assert!(zero_port_error.contains("KUBERNETES_SERVICE_PORT must be greater than zero"));
        let env_host_error = match kubernetes_api_base_url(
            None,
            Some(std::ffi::OsStr::new("0.0.0.0")),
            Some(std::ffi::OsStr::new("443")),
        ) {
            Ok(url) => anyhow::bail!("unusable Kubernetes Service host should be rejected: {url}"),
            Err(error) => error.to_string(),
        };
        assert!(env_host_error.contains(
            "KUBERNETES_SERVICE_HOST/KUBERNETES_SERVICE_PORT must use a nonzero port and a usable non-unspecified, non-multicast, non-broadcast numeric host"
        ));
        Ok(())
    }

    #[test]
    fn kubernetes_api_discovery_args_parse_without_explicit_routes() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--kubernetes-discover-services",
            "--kubernetes-api-url",
            "https://kubernetes.default.svc",
            "--kubernetes-namespace",
            "default",
            "--kubernetes-service-label-selector",
            "ipars.io/expose=true",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert!(args.apply_kubernetes_underlay);
            assert!(args.kubernetes_discover_services);
            assert!(args.kubernetes_api_server_cidrs.is_empty());
            assert!(args.kubernetes_service_cidrs.is_empty());
            assert_eq!(
                args.kubernetes_api_url.as_deref(),
                Some("https://kubernetes.default.svc")
            );
            assert_eq!(args.kubernetes_namespaces, vec!["default"]);
            assert_eq!(
                args.kubernetes_service_label_selector.as_deref(),
                Some("ipars.io/expose=true")
            );
            assert!(args.kubernetes_discover_api_server);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn docker_network_intent_uses_explicit_container_routes() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-container-namespace",
            "compose-default",
            "--docker-host-interface",
            "docker0",
            "--docker-container-cidr",
            "172.18.0.0/16",
            "--docker-route-interval-seconds",
            "20",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert!(args.apply_docker_routes);
            assert_eq!(args.docker_route_interval_seconds, 20);
            let intent = docker_network_intent(&args)?;
            assert_eq!(intent.container_namespace, "compose-default");
            assert_eq!(intent.host_interface, "docker0");
            assert_eq!(intent.overlay_interface, "ipars0");
            assert_eq!(
                intent.container_cidrs,
                vec!["172.18.0.0/16".parse::<ipnet::IpNet>()?]
            );
            assert!(intent.expose_host_routes);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn docker_network_intent_requires_namespace_and_routes() -> anyhow::Result<()> {
        let missing_namespace = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-container-cidr",
            "172.18.0.0/16",
        ])?;
        if let Command::Agent(args) = missing_namespace.command {
            let error = match validate_agent_runtime_config(&args) {
                Ok(()) => anyhow::bail!("missing Docker namespace should be rejected"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("--apply-docker-routes requires --docker-container-namespace"));
            assert!(docker_network_intent(&args).is_err());
        }

        let missing_routes = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-container-namespace",
            "compose-default",
        ])?;
        if let Command::Agent(args) = missing_routes.command {
            let error = match validate_agent_runtime_config(&args) {
                Ok(()) => anyhow::bail!("missing Docker CIDR should be rejected"),
                Err(error) => error.to_string(),
            };
            assert!(error
                .contains("--apply-docker-routes requires at least one --docker-container-cidr"));
            assert!(docker_network_intent(&args).is_err());
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn docker_route_settings_require_route_application() -> anyhow::Result<()> {
        let discovery_error =
            agent_runtime_config_error(vec!["iparsd", "agent", "--docker-discover-networks"])?;
        assert!(
            discovery_error.contains("--docker-discover-networks requires --apply-docker-routes")
        );

        let namespace_error = agent_runtime_config_error(vec![
            "iparsd",
            "agent",
            "--docker-container-namespace",
            "compose-default",
        ])?;
        assert!(
            namespace_error.contains("--docker-container-namespace requires --apply-docker-routes")
        );

        let cidr_error = agent_runtime_config_error(vec![
            "iparsd",
            "agent",
            "--docker-container-cidr",
            "172.18.0.0/16",
        ])?;
        assert!(cidr_error.contains("--docker-container-cidr requires --apply-docker-routes"));
        Ok(())
    }

    #[test]
    fn docker_api_socket_requires_network_discovery() -> anyhow::Result<()> {
        let static_mode_error = agent_runtime_config_error(vec![
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-api-socket",
            "/var/run/docker.sock",
            "--docker-container-namespace",
            "compose-default",
            "--docker-container-cidr",
            "172.18.0.0/16",
        ])?;
        assert!(
            static_mode_error.contains("--docker-api-socket requires --docker-discover-networks")
        );

        let inactive_error = agent_runtime_config_error(vec![
            "iparsd",
            "agent",
            "--docker-api-socket",
            "/var/run/docker.sock",
        ])?;
        assert!(inactive_error.contains("--docker-api-socket requires --docker-discover-networks"));

        let relative_error = agent_runtime_config_error(vec![
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-discover-networks",
            "--docker-api-socket",
            "docker.sock",
        ])?;
        assert!(relative_error.contains("--docker-api-socket must be an absolute Unix socket path"));
        Ok(())
    }

    #[test]
    fn kubernetes_underlay_intent_rejects_invalid_route_cidrs() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--kubernetes-service-cidr",
            "10.96.0.1/12",
        ])?;

        if let Command::Agent(args) = cli.command {
            let error = match kubernetes_underlay_intent(&args, NodeId::from_string("local")) {
                Ok(intent) => {
                    anyhow::bail!("invalid Kubernetes intent should be rejected: {intent:?}");
                }
                Err(error) => error.to_string(),
            };
            assert!(error.contains(
                "--kubernetes-service-cidr must use canonical Kubernetes Service CIDR route 10.96.0.0/12, not 10.96.0.1/12"
            ));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    fn agent_runtime_config_error(argv: Vec<&str>) -> anyhow::Result<String> {
        let cli = Cli::try_parse_from(argv)?;
        if let Command::Agent(args) = cli.command {
            return match validate_agent_runtime_config(&args) {
                Ok(()) => anyhow::bail!("agent runtime config should be rejected"),
                Err(error) => Ok(error.to_string()),
            };
        }
        anyhow::bail!("expected agent command")
    }

    #[test]
    fn docker_explicit_container_cidrs_reject_unsafe_ranges() -> anyhow::Result<()> {
        let cases = vec![
            (
                "0.0.0.0/0",
                "--docker-container-cidr must not include unrestricted Docker container CIDR 0.0.0.0/0",
            ),
            (
                "127.0.0.0/8",
                "--docker-container-cidr must not include loopback Docker container CIDR 127.0.0.0/8",
            ),
            (
                "fe80::/64",
                "--docker-container-cidr must not include link-local Docker container CIDR fe80::/64",
            ),
            (
                "172.18.10.1/24",
                "--docker-container-cidr must use canonical Docker container CIDR route 172.18.10.0/24, not 172.18.10.1/24",
            ),
        ];

        for (cidr, expected) in cases {
            let error = agent_runtime_config_error(vec![
                "iparsd",
                "agent",
                "--apply-docker-routes",
                "--docker-container-namespace",
                "compose-default",
                "--docker-container-cidr",
                cidr,
            ])?;
            assert!(
                error.contains(expected),
                "expected `{expected}` in `{error}`"
            );
        }

        let duplicate = agent_runtime_config_error(vec![
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-container-namespace",
            "compose-default",
            "--docker-container-cidr",
            "172.18.0.0/16",
            "--docker-container-cidr",
            "172.18.0.0/16",
        ])?;
        assert!(duplicate.contains(
            "--docker-container-cidr must not repeat Docker container CIDR route 172.18.0.0/16"
        ));

        let overlapping = agent_runtime_config_error(vec![
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-container-namespace",
            "compose-default",
            "--docker-container-cidr",
            "172.18.0.0/16",
            "--docker-container-cidr",
            "172.18.10.0/24",
        ])?;
        assert!(overlapping.contains(
            "--docker-container-cidr must not include overlapping Docker container CIDR routes 172.18.0.0/16 and 172.18.10.0/24"
        ));

        Ok(())
    }

    #[test]
    fn kubernetes_explicit_route_cidrs_reject_invalid_ranges() -> anyhow::Result<()> {
        let cases = vec![
            (
                "--kubernetes-api-server-cidr",
                "0.0.0.0/0",
                "--kubernetes-api-server-cidr must not include unrestricted Kubernetes API server CIDR 0.0.0.0/0",
            ),
            (
                "--kubernetes-service-cidr",
                "127.0.0.0/8",
                "--kubernetes-service-cidr must not include loopback Kubernetes Service CIDR 127.0.0.0/8",
            ),
            (
                "--kubernetes-service-cidr",
                "10.96.0.1/12",
                "--kubernetes-service-cidr must use canonical Kubernetes Service CIDR route 10.96.0.0/12, not 10.96.0.1/12",
            ),
        ];

        for (flag, cidr, expected) in cases {
            let error = agent_runtime_config_error(vec![
                "iparsd",
                "agent",
                "--apply-kubernetes-underlay",
                flag,
                cidr,
            ])?;
            assert!(
                error.contains(expected),
                "expected `{expected}` in `{error}`"
            );
        }

        let duplicate = agent_runtime_config_error(vec![
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--kubernetes-api-server-cidr",
            "10.96.0.1/32",
            "--kubernetes-service-cidr",
            "10.96.0.1/32",
        ])?;
        assert!(duplicate.contains(
            "--kubernetes-service-cidr must not repeat Kubernetes underlay route CIDR 10.96.0.1/32"
        ));

        Ok(())
    }

    #[test]
    fn agent_runtime_intervals_must_be_positive_when_enabled() -> anyhow::Result<()> {
        let cases = vec![
            (
                vec!["iparsd", "agent", "--heartbeat-interval-seconds", "0"],
                "--heartbeat-interval-seconds must be greater than zero",
            ),
            (
                vec!["iparsd", "agent", "--runtime-command-timeout-seconds", "0"],
                "--runtime-command-timeout-seconds must be greater than zero",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--runtime-command-timeout-seconds",
                    "3601",
                ],
                "--runtime-command-timeout-seconds must not exceed 3600",
            ),
            (
                vec!["iparsd", "agent", "--runtime-command-output-max-bytes", "0"],
                "--runtime-command-output-max-bytes must be greater than zero",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--runtime-command-output-max-bytes",
                    "1048577",
                ],
                "--runtime-command-output-max-bytes must not exceed 1048576",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--userspace-wireguard-ready-timeout-seconds",
                    "3601",
                ],
                "--userspace-wireguard-ready-timeout-seconds must not exceed 3600",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--userspace-wireguard-shutdown-timeout-seconds",
                    "3601",
                ],
                "--userspace-wireguard-shutdown-timeout-seconds must not exceed 3600",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--apply-peer-map",
                    "--peer-map-poll-interval-seconds",
                    "0",
                ],
                "--peer-map-poll-interval-seconds must be greater than zero",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--signal-registration-interval-seconds",
                    "0",
                ],
                "--signal-registration-interval-seconds must be greater than zero",
            ),
            (
                vec!["iparsd", "agent", "--signal-path-interval-seconds", "0"],
                "--signal-path-interval-seconds must be greater than zero",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--relay-session-renew-before-seconds",
                    "0",
                ],
                "--relay-session-renew-before-seconds must be greater than zero",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--packet-flow-detector",
                    "proc-net-conntrack",
                    "--packet-flow-poll-interval-seconds",
                    "0",
                ],
                "--packet-flow-poll-interval-seconds must be greater than zero",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--apply-docker-routes",
                    "--docker-container-namespace",
                    "compose-default",
                    "--docker-container-cidr",
                    "172.18.0.0/16",
                    "--docker-route-interval-seconds",
                    "0",
                ],
                "--docker-route-interval-seconds must be greater than zero",
            ),
            (
                vec![
                    "iparsd",
                    "agent",
                    "--apply-kubernetes-underlay",
                    "--kubernetes-service-cidr",
                    "10.96.0.0/12",
                    "--kubernetes-route-interval-seconds",
                    "0",
                ],
                "--kubernetes-route-interval-seconds must be greater than zero",
            ),
        ];

        for (argv, expected) in cases {
            let error = agent_runtime_config_error(argv)?;
            assert!(
                error.contains(expected),
                "expected `{expected}` in `{error}`"
            );
        }
        Ok(())
    }

    #[test]
    fn docker_route_source_allows_api_discovery_without_explicit_routes() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-discover-networks",
            "--docker-api-socket",
            "/run/user/1000/docker.sock",
            "--docker-network",
            "compose_default",
        ])?;

        if let Command::Agent(args) = cli.command {
            assert!(args.docker_discover_networks);
            assert!(args.docker_container_cidrs.is_empty());
            assert!(matches!(
                docker_route_source(&args)?,
                DockerRouteSource::Api(_)
            ));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn docker_api_discovery_selects_bridge_network_subnets() -> anyhow::Result<()> {
        let networks = vec![
            docker_api_network("other-id", "compose_extra", "bridge", &["172.19.0.0/16"]),
            docker_api_network("host-id", "host", "host", &["192.0.2.0/24"]),
            docker_api_network(
                "default-id",
                "compose_default",
                "bridge",
                &["172.18.0.0/16"],
            ),
        ];

        let discovered = docker_discovered_routes(&networks, &[])?;

        assert_eq!(
            discovered.network_names,
            vec!["compose_default".to_string(), "compose_extra".to_string()]
        );
        assert_eq!(
            discovered.cidrs,
            vec![
                "172.18.0.0/16".parse::<ipnet::IpNet>()?,
                "172.19.0.0/16".parse::<ipnet::IpNet>()?,
            ]
        );
        assert_eq!(
            docker_namespace_from_networks(&discovered.network_names),
            "docker:compose_default+compose_extra"
        );
        Ok(())
    }

    #[test]
    fn docker_api_discovery_filters_by_name_or_id() -> anyhow::Result<()> {
        let networks = vec![
            docker_api_network(
                "default-id",
                "compose_default",
                "bridge",
                &["172.18.0.0/16"],
            ),
            docker_api_network("extra-id", "compose_extra", "bridge", &["172.19.0.0/16"]),
        ];

        let by_name = docker_discovered_routes(&networks, &["compose_extra".to_string()])?;
        let by_id = docker_discovered_routes(&networks, &["default-id".to_string()])?;

        assert_eq!(by_name.network_names, vec!["compose_extra".to_string()]);
        assert_eq!(
            by_name.cidrs,
            vec!["172.19.0.0/16".parse::<ipnet::IpNet>()?]
        );
        assert_eq!(by_id.network_names, vec!["compose_default".to_string()]);
        assert_eq!(by_id.cidrs, vec!["172.18.0.0/16".parse::<ipnet::IpNet>()?]);
        Ok(())
    }

    #[test]
    fn docker_api_discovery_rejects_ambiguous_network_filters() -> anyhow::Result<()> {
        let networks = vec![
            docker_api_network(
                "default-id",
                "compose_default",
                "bridge",
                &["172.18.0.0/16"],
            ),
            docker_api_network(
                "compose_default",
                "compose_extra",
                "bridge",
                &["172.19.0.0/16"],
            ),
        ];

        let error = match docker_discovered_routes(&networks, &["compose_default".to_string()]) {
            Ok(_) => anyhow::bail!("ambiguous Docker network filter should fail discovery"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("matched multiple Docker networks"));
        assert!(error.contains("compose_default"));
        assert!(error.contains("compose_extra"));
        Ok(())
    }

    #[test]
    fn docker_api_discovery_rejects_unsafe_discovered_cidrs() -> anyhow::Result<()> {
        let networks = vec![docker_api_network(
            "default-id",
            "compose_default",
            "bridge",
            &["0.0.0.0/0"],
        )];

        let error = match docker_discovered_routes(&networks, &[]) {
            Ok(_) => anyhow::bail!("unsafe Docker API subnet should fail discovery"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains(
            "Docker network discovery must not include unrestricted Docker container CIDR 0.0.0.0/0"
        ));

        let non_canonical_networks = vec![docker_api_network(
            "default-id",
            "compose_default",
            "bridge",
            &["172.18.10.1/24"],
        )];
        let non_canonical = match docker_discovered_routes(&non_canonical_networks, &[]) {
            Ok(_) => anyhow::bail!("non-canonical Docker API subnet should fail discovery"),
            Err(error) => error.to_string(),
        };
        assert!(non_canonical.contains(
            "Docker network discovery must use canonical Docker container CIDR route 172.18.10.0/24, not 172.18.10.1/24"
        ));
        Ok(())
    }

    #[test]
    fn docker_api_discovery_rejects_duplicate_or_overlapping_discovered_cidrs() -> anyhow::Result<()>
    {
        let duplicate_networks = vec![
            docker_api_network(
                "default-id",
                "compose_default",
                "bridge",
                &["172.18.0.0/16"],
            ),
            docker_api_network("extra-id", "compose_extra", "bridge", &["172.18.0.0/16"]),
        ];
        let duplicate = match docker_discovered_routes(&duplicate_networks, &[]) {
            Ok(_) => anyhow::bail!("duplicate Docker API subnets should fail discovery"),
            Err(error) => error.to_string(),
        };
        assert!(duplicate.contains(
            "Docker network discovery must not repeat Docker container CIDR route 172.18.0.0/16"
        ));

        let overlapping_networks = vec![
            docker_api_network(
                "default-id",
                "compose_default",
                "bridge",
                &["172.18.0.0/16"],
            ),
            docker_api_network("extra-id", "compose_extra", "bridge", &["172.18.10.0/24"]),
        ];
        let overlapping = match docker_discovered_routes(&overlapping_networks, &[]) {
            Ok(_) => anyhow::bail!("overlapping Docker API subnets should fail discovery"),
            Err(error) => error.to_string(),
        };
        assert!(overlapping.contains(
            "Docker network discovery must not include overlapping Docker container CIDR routes 172.18.0.0/16 and 172.18.10.0/24"
        ));
        Ok(())
    }

    #[test]
    fn docker_api_discovery_reports_unmatched_filtered_networks() -> anyhow::Result<()> {
        let networks = vec![docker_api_network(
            "default-id",
            "compose_default",
            "bridge",
            &["172.18.0.0/16"],
        )];

        let error = match docker_discovered_routes(
            &networks,
            &["compose_default".to_string(), "missing".to_string()],
        ) {
            Ok(_) => anyhow::bail!("missing Docker network filter should fail discovery"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("did not find requested network filters"));
        assert!(error.contains("missing"));
        Ok(())
    }

    #[test]
    fn docker_api_discovery_reports_non_bridge_filtered_networks() -> anyhow::Result<()> {
        let networks = vec![
            docker_api_network(
                "default-id",
                "compose_default",
                "bridge",
                &["172.18.0.0/16"],
            ),
            docker_api_network("host-id", "host", "host", &["192.0.2.0/24"]),
        ];

        let error = match docker_discovered_routes(
            &networks,
            &["compose_default".to_string(), "host".to_string()],
        ) {
            Ok(_) => anyhow::bail!("non-bridge Docker network filter should fail discovery"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("requested non-bridge networks"));
        assert!(error.contains("host"));
        Ok(())
    }

    #[test]
    fn docker_api_discovery_reports_subnetless_filtered_networks() -> anyhow::Result<()> {
        let networks = vec![
            docker_api_network(
                "default-id",
                "compose_default",
                "bridge",
                &["172.18.0.0/16"],
            ),
            docker_api_network("empty-id", "compose_empty", "bridge", &[]),
        ];

        let error = match docker_discovered_routes(
            &networks,
            &["compose_default".to_string(), "empty-id".to_string()],
        ) {
            Ok(_) => anyhow::bail!("subnetless Docker network filter should fail discovery"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("without IPAM subnets"));
        assert!(error.contains("empty-id"));
        Ok(())
    }

    #[tokio::test]
    async fn docker_api_discovery_reads_networks_over_unix_socket() -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let base = unique_test_dir("docker-api-socket")?;
        let socket_path = base.join("docker.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path)?;
        let server = tokio::spawn(async move {
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
            let request_text = String::from_utf8_lossy(&request).into_owned();
            anyhow::ensure!(
                request_text.starts_with("GET /v1.43/networks "),
                "unexpected Docker API request line: {request_text}"
            );
            let body = r#"[
  {"Id":"default-id","Name":"compose_default","Driver":"bridge","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]}},
  {"Id":"extra-id","Name":"compose_extra","Driver":"bridge","IPAM":{"Config":[{"Subnet":"fd00:18::/64"}]}},
  {"Id":"host-id","Name":"host","Driver":"host","IPAM":{"Config":[{"Subnet":"192.0.2.0/24"}]}}
]"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;
            Ok::<String, anyhow::Error>(request_text)
        });

        let client = reqwest::Client::builder()
            .unix_socket(socket_path.clone())
            .build()
            .context("failed to build test Docker API client")?;
        let discovery = DockerApiNetworkDiscovery {
            client,
            api_version: "v1.43".to_string(),
            network_filters: vec!["default-id".to_string(), "compose_extra".to_string()],
            container_namespace: None,
            host_interface: "br-edge".to_string(),
            overlay_interface: "ipars0".to_string(),
            expose_host_routes: true,
        };

        let intent_result = discovery.discover_intent().await;
        let request_text = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .context("timed out waiting for mock Docker API request")???;
        assert!(request_text.to_ascii_lowercase().contains("host: docker"));
        let intent = intent_result?;
        assert_eq!(
            intent.container_namespace,
            "docker:compose_default+compose_extra"
        );
        assert_eq!(intent.host_interface, "br-edge");
        assert_eq!(intent.overlay_interface, "ipars0");
        assert!(intent.expose_host_routes);
        assert_eq!(
            intent.container_cidrs,
            vec![
                "172.18.0.0/16".parse::<ipnet::IpNet>()?,
                "fd00:18::/64".parse::<ipnet::IpNet>()?,
            ]
        );

        let routes =
            docker_advertised_routes(&NodeId::from_string("node-a"), intent.container_cidrs);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].id, "docker-v4-172-18-0-0-16");
        assert_eq!(routes[1].id, "docker-v6-fd00-18-0-0-0-0-0-0-64");
        assert_eq!(routes[0].via, Some(NodeId::from_string("node-a")));

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[tokio::test]
    async fn docker_api_discovery_rejects_oversized_network_response() -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let base = unique_test_dir("docker-api-oversized-response")?;
        let socket_path = base.join("docker.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path)?;
        let server = tokio::spawn(async move {
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
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_DOCKER_API_NETWORKS_RESPONSE_BYTES + 1
            );
            stream.write_all(response.as_bytes()).await?;
            Ok::<(), anyhow::Error>(())
        });

        let client = reqwest::Client::builder()
            .unix_socket(socket_path.clone())
            .build()
            .context("failed to build test Docker API client")?;
        let discovery = DockerApiNetworkDiscovery {
            client,
            api_version: "v1.43".to_string(),
            network_filters: Vec::new(),
            container_namespace: None,
            host_interface: "docker0".to_string(),
            overlay_interface: "ipars0".to_string(),
            expose_host_routes: true,
        };

        let error = match discovery.discover_intent().await {
            Ok(intent) => {
                anyhow::bail!("oversized Docker networks response should be rejected: {intent:?}")
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains("Docker networks API response exceeds maximum size"));
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .context("timed out waiting for oversized Docker API response server")???;
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn docker_api_discovery_rejects_invalid_discovered_network_names() -> anyhow::Result<()> {
        let networks = vec![docker_api_network(
            "default-id",
            "compose/default",
            "bridge",
            &["172.18.0.0/16"],
        )];

        let error = match docker_discovered_routes(&networks, &[]) {
            Ok(_) => anyhow::bail!("invalid Docker API network name should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("Docker network name"));
        Ok(())
    }

    #[test]
    fn docker_api_discovery_rejects_invalid_or_duplicate_network_ids() -> anyhow::Result<()> {
        let invalid_id = vec![docker_api_network(
            "default/id",
            "compose_default",
            "bridge",
            &["172.18.0.0/16"],
        )];
        let error = match docker_discovered_routes(&invalid_id, &[]) {
            Ok(_) => anyhow::bail!("invalid Docker API network ID should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("Docker network ID"));

        let duplicate_ids = vec![
            docker_api_network(
                "duplicate-id",
                "compose_default",
                "bridge",
                &["172.18.0.0/16"],
            ),
            docker_api_network(
                "duplicate-id",
                "compose_extra",
                "bridge",
                &["172.19.0.0/16"],
            ),
        ];
        let error = match docker_discovered_routes(&duplicate_ids, &[]) {
            Ok(_) => anyhow::bail!("duplicate Docker API network IDs should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("duplicate network ID `duplicate-id`"));
        Ok(())
    }

    #[test]
    fn docker_api_discovery_rejects_duplicate_network_names() -> anyhow::Result<()> {
        let networks = vec![
            docker_api_network(
                "default-id",
                "compose_default",
                "bridge",
                &["172.18.0.0/16"],
            ),
            docker_api_network("extra-id", "compose_default", "bridge", &["172.19.0.0/16"]),
        ];
        let error = match docker_discovered_routes(&networks, &[]) {
            Ok(_) => anyhow::bail!("duplicate Docker API network names should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("duplicate network name `compose_default`"));
        Ok(())
    }

    #[test]
    fn docker_api_discovery_validates_version_and_network_filters() {
        for version in ["", "v1.43", "/v1.43/"] {
            assert!(
                validate_docker_api_version(version).is_ok(),
                "{version} should be valid"
            );
        }
        for version in ["1.43", "v1", "v1.43/containers", "../v1.43"] {
            assert!(
                validate_docker_api_version(version).is_err(),
                "{version} should be invalid"
            );
        }

        for filter in ["compose_default", "network.extra-1", "abcdef012345"] {
            assert!(
                validate_docker_network_filter(filter).is_ok(),
                "{filter} should be valid"
            );
        }
        for filter in ["", "compose/default", "compose default", "compose:default"] {
            assert!(
                validate_docker_network_filter(filter).is_err(),
                "{filter} should be invalid"
            );
        }
        let too_long = "n".repeat(256);
        assert!(validate_docker_network_filter(&too_long).is_err());
    }

    #[test]
    fn docker_api_discovery_rejects_ambiguous_explicit_cidrs() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-discover-networks",
            "--docker-container-cidr",
            "172.18.0.0/16",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = cli.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(_) => anyhow::bail!("ambiguous Docker discovery config should be rejected"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("cannot be combined with explicit --docker-container-cidr"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn docker_network_filters_require_api_discovery() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-network",
            "compose_default",
            "--docker-container-namespace",
            "compose-default",
            "--docker-container-cidr",
            "172.18.0.0/16",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = cli.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(_) => {
                    anyhow::bail!("Docker network filter without discovery should be rejected")
                }
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--docker-network requires --docker-discover-networks"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn docker_network_filters_must_be_unique() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-discover-networks",
            "--docker-network",
            "compose_default",
            "--docker-network",
            "compose_default",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = cli.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(_) => anyhow::bail!("duplicate Docker network filter should be rejected"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--docker-network `compose_default` must not be repeated"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[tokio::test]
    async fn docker_explicit_cidrs_build_agent_requested_routes() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-docker-routes",
            "--docker-container-namespace",
            "compose-default",
            "--docker-container-cidr",
            "172.18.0.0/16",
            "--docker-container-cidr",
            "172.19.0.0/16",
            "--skip-runtime-preflight",
        ])?;

        if let Command::Agent(args) = cli.command {
            let node_id = NodeId::from_string("node-a");
            let routes = agent_requested_routes(&args, node_id.clone()).await?;

            assert_eq!(routes.len(), 2);
            assert_eq!(routes[0].id, "docker-v4-172-18-0-0-16");
            assert_eq!(routes[0].cidr, "172.18.0.0/16".parse::<ipnet::IpNet>()?);
            assert_eq!(routes[0].advertised_by, node_id);
            assert_eq!(routes[0].via, Some(NodeId::from_string("node-a")));
            assert_eq!(routes[1].id, "docker-v4-172-19-0-0-16");
            assert_eq!(routes[1].cidr, "172.19.0.0/16".parse::<ipnet::IpNet>()?);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn docker_advertised_routes_use_stable_cidr_derived_ids() -> anyhow::Result<()> {
        let node_id = NodeId::from_string("node-a");
        let routes = docker_advertised_routes(
            &node_id,
            vec![
                "172.19.0.0/16".parse()?,
                "fd00:18::/64".parse()?,
                "172.18.0.0/16".parse()?,
            ],
        );

        assert_eq!(
            routes
                .iter()
                .map(|route| route.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "docker-v4-172-18-0-0-16",
                "docker-v4-172-19-0-0-16",
                "docker-v6-fd00-18-0-0-0-0-0-0-64",
            ]
        );
        assert_eq!(routes[0].cidr, "172.18.0.0/16".parse::<ipnet::IpNet>()?);
        assert_eq!(routes[1].cidr, "172.19.0.0/16".parse::<ipnet::IpNet>()?);
        assert_eq!(routes[2].cidr, "fd00:18::/64".parse::<ipnet::IpNet>()?);
        assert!(routes
            .iter()
            .all(|route| route.advertised_by == node_id && route.via == Some(node_id.clone())));
        Ok(())
    }

    #[test]
    fn docker_api_socket_resolution_prefers_explicit_then_docker_host_then_rootless(
    ) -> anyhow::Result<()> {
        let explicit = Path::new("/custom/docker.sock");
        assert_eq!(
            resolve_docker_api_socket(Some(explicit), None, None, |_| false)?,
            PathBuf::from("/custom/docker.sock")
        );
        assert_eq!(
            resolve_docker_api_socket(
                None,
                Some(OsStr::new("unix:///tmp/docker.sock")),
                None,
                |_| false,
            )?,
            PathBuf::from("/tmp/docker.sock")
        );
        assert_eq!(
            resolve_docker_api_socket(None, None, Some(OsStr::new("/run/user/1000")), |path| {
                path == Path::new("/run/user/1000/docker.sock")
            })?,
            PathBuf::from("/run/user/1000/docker.sock")
        );
        Ok(())
    }

    #[test]
    fn docker_api_socket_resolution_rejects_unsupported_docker_host() -> anyhow::Result<()> {
        let error = match resolve_docker_api_socket(
            None,
            Some(OsStr::new("tcp://127.0.0.1:2375")),
            None,
            |_| false,
        ) {
            Ok(_) => anyhow::bail!("unsupported DOCKER_HOST should be rejected"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("only supports unix:// DOCKER_HOST"));
        Ok(())
    }

    #[test]
    fn docker_api_socket_resolution_requires_absolute_socket_paths() -> anyhow::Result<()> {
        let explicit_error = match resolve_docker_api_socket(
            Some(Path::new("docker.sock")),
            None,
            None,
            |_| false,
        ) {
            Ok(path) => anyhow::bail!("relative explicit socket should be rejected: {path:?}"),
            Err(error) => error.to_string(),
        };
        assert!(explicit_error.contains("--docker-api-socket must be an absolute Unix socket path"));

        let docker_host_error = match resolve_docker_api_socket(
            None,
            Some(OsStr::new("unix://docker.sock")),
            None,
            |_| false,
        ) {
            Ok(path) => anyhow::bail!("relative DOCKER_HOST socket should be rejected: {path:?}"),
            Err(error) => error.to_string(),
        };
        assert!(docker_host_error
            .contains("DOCKER_HOST unix:// socket path must be an absolute Unix socket path"));
        let rootless_error =
            match resolve_docker_api_socket(None, None, Some(OsStr::new("run/user/1000")), |path| {
                path == Path::new("run/user/1000/docker.sock")
            }) {
                Ok(path) => {
                    anyhow::bail!("relative XDG runtime socket should be rejected: {path:?}")
                }
                Err(error) => error.to_string(),
            };
        assert!(rootless_error
            .contains("XDG_RUNTIME_DIR/docker.sock must be an absolute Unix socket path"));
        Ok(())
    }

    #[test]
    fn docker_api_socket_resolution_rejects_dot_components() -> anyhow::Result<()> {
        let explicit_error = match resolve_docker_api_socket(
            Some(Path::new("/run/user/1000/../docker.sock")),
            None,
            None,
            |_| false,
        ) {
            Ok(path) => anyhow::bail!("dot-component explicit socket should be rejected: {path:?}"),
            Err(error) => error.to_string(),
        };
        assert!(
            explicit_error
                .contains("--docker-api-socket must not contain '.' or '..' path components"),
            "unexpected explicit socket error: {explicit_error}"
        );

        let docker_host_error = match resolve_docker_api_socket(
            None,
            Some(OsStr::new("unix:///tmp/../docker.sock")),
            None,
            |_| false,
        ) {
            Ok(path) => {
                anyhow::bail!("dot-component DOCKER_HOST socket should be rejected: {path:?}")
            }
            Err(error) => error.to_string(),
        };
        assert!(
            docker_host_error.contains(
                "DOCKER_HOST unix:// socket path must not contain '.' or '..' path components"
            ),
            "unexpected DOCKER_HOST socket error: {docker_host_error}"
        );

        let rootless_error = match resolve_docker_api_socket(
            None,
            None,
            Some(OsStr::new("/run/user/1000/..")),
            |path| path == Path::new("/run/user/1000/../docker.sock"),
        ) {
            Ok(path) => {
                anyhow::bail!("dot-component XDG runtime socket should be rejected: {path:?}")
            }
            Err(error) => error.to_string(),
        };
        assert!(
            rootless_error.contains(
                "XDG_RUNTIME_DIR/docker.sock must not contain '.' or '..' path components"
            ),
            "unexpected XDG runtime socket error: {rootless_error}"
        );
        Ok(())
    }

    fn docker_api_network(
        id: &str,
        name: &str,
        driver: &str,
        subnets: &[&str],
    ) -> DockerApiNetwork {
        DockerApiNetwork {
            id: id.to_string(),
            name: name.to_string(),
            driver: driver.to_string(),
            ipam: DockerApiIpam {
                config: subnets
                    .iter()
                    .map(|subnet| DockerApiIpamConfig {
                        subnet: Some((*subnet).to_string()),
                    })
                    .collect(),
            },
        }
    }

    fn kubernetes_service(cluster_ip: Option<&str>, cluster_ips: &[&str]) -> KubernetesService {
        KubernetesService {
            spec: KubernetesServiceSpec {
                cluster_ip: cluster_ip.map(str::to_string),
                cluster_ips: cluster_ips.iter().map(|ip| (*ip).to_string()).collect(),
            },
        }
    }

    #[test]
    fn kubernetes_underlay_intent_requires_routes() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--apply-kubernetes-underlay",
            "--kubernetes-discover-api-server",
            "false",
        ])?;

        if let Command::Agent(args) = cli.command {
            let error = match validate_agent_runtime_config(&args) {
                Ok(()) => anyhow::bail!("missing Kubernetes routes should be rejected"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains(
                "--apply-kubernetes-underlay requires at least one --kubernetes-api-server-cidr or --kubernetes-service-cidr unless --kubernetes-discover-services or --kubernetes-discover-api-server is set"
            ));
            assert!(kubernetes_underlay_intent(&args, NodeId::from_string("local")).is_err());
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn relay_args_accepts_session_ttl() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--public-endpoint",
            "203.0.113.10:51820",
            "--admission-url",
            "http://relay-a:9580",
            "--session-ttl-seconds",
            "60",
            "--max-sessions-per-node",
            "25",
            "--admission-rate-limit",
            "120",
            "--admission-rate-limit-window-seconds",
            "30",
            "--admission-bearer-token",
            "cluster-relay-secret",
        ])?;

        if let Command::Relay(args) = cli.command {
            assert_eq!(args.session_ttl_seconds, 60);
            assert_eq!(args.max_sessions_per_node, 25);
            assert_eq!(args.admission_rate_limit, 120);
            assert_eq!(args.admission_rate_limit_window_seconds, 30);
            assert_eq!(args.public_endpoint, Some("203.0.113.10:51820".parse()?));
            assert_eq!(args.admission_url.as_deref(), Some("http://relay-a:9580"));
            assert_eq!(
                args.admission_bearer_token.as_deref(),
                Some("cluster-relay-secret")
            );
            return Ok(());
        }

        Err(anyhow::anyhow!("expected relay command"))
    }

    #[test]
    fn relay_config_rejects_invalid_admission_url_and_zero_capacity() -> anyhow::Result<()> {
        let missing_public_endpoint = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--admission-url",
            "http://relay-a:9580",
        ])?;
        if let Command::Relay(args) = missing_public_endpoint.command {
            let error = match validate_relay_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid relay config"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("--public-endpoint is required"));
        } else {
            anyhow::bail!("expected relay command");
        }

        let missing_admission_url = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--public-endpoint",
            "203.0.113.10:51820",
        ])?;
        if let Command::Relay(args) = missing_admission_url.command {
            let error = match validate_relay_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid relay config"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("--admission-url is required"));
        } else {
            anyhow::bail!("expected relay command");
        }

        let invalid_relay_node_id = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay/a",
            "--public-endpoint",
            "203.0.113.10:51820",
            "--admission-url",
            "http://relay-a:9580",
        ])?;
        if let Command::Relay(args) = invalid_relay_node_id.command {
            let error = match validate_relay_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid relay config"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(
                "--relay-node-id must contain only ASCII letters, digits, '_', '.' or '-'"
            ));
        } else {
            anyhow::bail!("expected relay command");
        }

        let unusable_public_endpoint = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--public-endpoint",
            "0.0.0.0:51820",
            "--admission-url",
            "http://relay-a:9580",
        ])?;
        if let Command::Relay(args) = unusable_public_endpoint.command {
            let error = match validate_relay_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid relay config"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--public-endpoint must use a usable nonzero"));
        } else {
            anyhow::bail!("expected relay command");
        }

        let invalid_admission_url = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--public-endpoint",
            "203.0.113.10:51820",
            "--admission-url",
            "relay-a",
        ])?;
        if let Command::Relay(args) = invalid_admission_url.command {
            let error = match validate_relay_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid relay config"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--admission-url must be an absolute URL"));
        } else {
            anyhow::bail!("expected relay command");
        }

        let unusable_admission_url = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--public-endpoint",
            "203.0.113.10:51820",
            "--admission-url",
            "http://0.0.0.0:9580",
        ])?;
        if let Command::Relay(args) = unusable_admission_url.command {
            let error = match validate_relay_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid relay config"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("--admission-url"));
            assert!(error.to_string().contains("usable non-unspecified"));
        } else {
            anyhow::bail!("expected relay command");
        }

        let zero_sessions = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--public-endpoint",
            "203.0.113.10:51820",
            "--admission-url",
            "http://relay-a:9580",
            "--max-sessions",
            "0",
        ])?;
        if let Command::Relay(args) = zero_sessions.command {
            let error = match validate_relay_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid relay config"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--max-sessions must be greater than zero"));
        } else {
            anyhow::bail!("expected relay command");
        }

        let zero_mbps = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--public-endpoint",
            "203.0.113.10:51820",
            "--admission-url",
            "http://relay-a:9580",
            "--max-mbps",
            "0",
        ])?;
        if let Command::Relay(args) = zero_mbps.command {
            let error = match validate_relay_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid relay config"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--max-mbps must be greater than zero"));
        } else {
            anyhow::bail!("expected relay command");
        }

        let node_limit_above_capacity = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--public-endpoint",
            "203.0.113.10:51820",
            "--admission-url",
            "http://relay-a:9580",
            "--max-sessions",
            "10",
            "--max-sessions-per-node",
            "11",
        ])?;
        if let Command::Relay(args) = node_limit_above_capacity.command {
            let error = match validate_relay_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid relay config"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--max-sessions-per-node must be less than or equal to --max-sessions"));
        } else {
            anyhow::bail!("expected relay command");
        }

        let zero_ttl = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--public-endpoint",
            "203.0.113.10:51820",
            "--admission-url",
            "http://relay-a:9580",
            "--session-ttl-seconds",
            "0",
        ])?;
        if let Command::Relay(args) = zero_ttl.command {
            let error = match validate_relay_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid relay config"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--session-ttl-seconds must be greater than zero"));
        } else {
            anyhow::bail!("expected relay command");
        }

        let oversized_ttl_seconds = (MAX_RELAY_SESSION_TTL_SECONDS + 1).to_string();
        let oversized_ttl = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--public-endpoint",
            "203.0.113.10:51820",
            "--admission-url",
            "http://relay-a:9580",
            "--session-ttl-seconds",
            oversized_ttl_seconds.as_str(),
        ])?;
        if let Command::Relay(args) = oversized_ttl.command {
            let error = match validate_relay_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid relay config"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(&format!(
                "--session-ttl-seconds must not exceed {MAX_RELAY_SESSION_TTL_SECONDS}"
            )));
        } else {
            anyhow::bail!("expected relay command");
        }

        let zero_rate_window = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--public-endpoint",
            "203.0.113.10:51820",
            "--admission-url",
            "http://relay-a:9580",
            "--admission-rate-limit-window-seconds",
            "0",
        ])?;
        if let Command::Relay(args) = zero_rate_window.command {
            let error = match validate_relay_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid relay config"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--admission-rate-limit-window-seconds must be greater than zero"));
        } else {
            anyhow::bail!("expected relay command");
        }

        let oversized_rate_window_seconds =
            (MAX_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS + 1).to_string();
        let oversized_rate_window = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--public-endpoint",
            "203.0.113.10:51820",
            "--admission-url",
            "http://relay-a:9580",
            "--admission-rate-limit-window-seconds",
            oversized_rate_window_seconds.as_str(),
        ])?;
        if let Command::Relay(args) = oversized_rate_window.command {
            let error = match validate_relay_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid relay config"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(&format!(
                "--admission-rate-limit-window-seconds must not exceed {MAX_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS}"
            )));
        } else {
            anyhow::bail!("expected relay command");
        }

        let invalid_bearer = Cli::try_parse_from([
            "iparsd",
            "relay",
            "--relay-node-id",
            "relay-a",
            "--public-endpoint",
            "203.0.113.10:51820",
            "--admission-url",
            "http://relay-a:9580",
            "--admission-bearer-token",
            "not allowed",
        ])?;
        if let Command::Relay(args) = invalid_bearer.command {
            let error = match validate_relay_config(&args) {
                Ok(()) => anyhow::bail!("unexpected valid relay config"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("--admission-bearer-token must not contain whitespace"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected relay command"))
    }

    #[test]
    fn peer_map_url_trims_control_plane_base_url() {
        assert_eq!(
            peer_map_url("http://127.0.0.1:8443/", &NodeId::from_string("node-a")),
            "http://127.0.0.1:8443/v1/peers/node-a"
        );
    }

    #[test]
    fn heartbeat_url_trims_control_plane_base_url() {
        assert_eq!(
            heartbeat_url("http://127.0.0.1:8443/"),
            "http://127.0.0.1:8443/v1/heartbeat"
        );
    }

    #[test]
    fn signal_node_url_trims_signal_base_url() {
        assert_eq!(
            signal_node_url("http://127.0.0.1:9443/", &NodeId::from_string("node-a")),
            "http://127.0.0.1:9443/v1/nodes/node-a"
        );
    }

    #[test]
    fn signal_path_url_trims_signal_base_url() {
        assert_eq!(
            signal_path_url("http://127.0.0.1:9443/"),
            "http://127.0.0.1:9443/v1/paths/negotiate"
        );
    }

    #[test]
    fn signal_hole_punch_url_trims_signal_base_url() {
        assert_eq!(
            signal_hole_punch_url(
                "http://127.0.0.1:9443/",
                &NodeId::from_string("node-a"),
                &NodeId::from_string("node-b"),
            ),
            "http://127.0.0.1:9443/v1/hole-punch/node-a/node-b"
        );
    }

    #[test]
    fn relay_admission_url_trims_relay_base_url() -> anyhow::Result<()> {
        let mut relay = node_record("relay-a");
        relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 30], 51820))),
            admission_url: Some("http://203.0.113.30:9580/".to_string()),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        });

        assert_eq!(
            relay_admission_url(&relay)?,
            "http://203.0.113.30:9580/v1/sessions"
        );
        assert_eq!(
            relay_public_endpoint(&relay)?,
            SocketAddr::from(([203, 0, 113, 30], 51820))
        );
        Ok(())
    }

    #[test]
    fn relay_admission_request_prefers_reflexive_endpoints() {
        let local = NodeId::from_string("local");
        let peer = NodeId::from_string("peer-a");
        let status = ipars_types::api::AgentStatusResponse {
            node_id: local.clone(),
            identity_public_key: "identity-local".to_string(),
            wireguard_public_key: "wg-local".to_string(),
            candidate_count: 2,
            candidates: vec![
                candidate("local", EndpointCandidateKind::LocalUdp, 1),
                EndpointCandidate {
                    node_id: local.clone(),
                    kind: EndpointCandidateKind::StunReflexive,
                    addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                    observed_at: Utc::now(),
                    priority: 100,
                    cost: 10,
                    source: CandidateSource::StunProbe,
                },
            ],
            nat_classification: None,
            userspace_wireguard_process: None,
            state_updated_at: Utc::now(),
        };
        let mut peer_record = node_record("peer-a");
        peer_record.endpoint_candidates = vec![
            candidate("peer-a", EndpointCandidateKind::LocalUdp, 1),
            EndpointCandidate {
                node_id: peer.clone(),
                kind: EndpointCandidateKind::StunReflexive,
                addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::StunProbe,
            },
        ];

        let request = relay_admission_request(&status, &peer_record);

        assert_eq!(
            request,
            Some(RelayAdmissionRequest {
                left: local,
                right: peer,
                left_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                right_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
            })
        );
    }

    #[test]
    fn relay_admission_request_uses_deterministic_node_order() {
        let local = NodeId::from_string("node-z");
        let peer = NodeId::from_string("node-a");
        let status = ipars_types::api::AgentStatusResponse {
            node_id: local.clone(),
            identity_public_key: "identity-local".to_string(),
            wireguard_public_key: "wg-local".to_string(),
            candidate_count: 1,
            candidates: vec![EndpointCandidate {
                node_id: local.clone(),
                kind: EndpointCandidateKind::StunReflexive,
                addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::StunProbe,
            }],
            nat_classification: None,
            userspace_wireguard_process: None,
            state_updated_at: Utc::now(),
        };
        let mut peer_record = node_record("node-a");
        peer_record.endpoint_candidates = vec![EndpointCandidate {
            node_id: peer.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::StunProbe,
        }];

        let request = relay_admission_request(&status, &peer_record);

        assert_eq!(
            request,
            Some(RelayAdmissionRequest {
                left: peer,
                right: local,
                left_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                right_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
            })
        );
    }

    #[test]
    fn relay_admission_request_ignores_unusable_session_endpoints() {
        let local = NodeId::from_string("local");
        let peer = NodeId::from_string("peer-a");
        let status = agent_status(
            "local",
            vec![
                EndpointCandidate {
                    addr: SocketAddr::from(([0, 0, 0, 0], 40000)),
                    ..candidate("local", EndpointCandidateKind::StunReflexive, 1)
                },
                EndpointCandidate {
                    addr: SocketAddr::from(([224, 0, 0, 1], 40000)),
                    ..candidate("local", EndpointCandidateKind::PublicUdp, 1)
                },
                EndpointCandidate {
                    addr: SocketAddr::from(([198, 51, 100, 10], 50000)),
                    ..candidate("local", EndpointCandidateKind::PublicUdp, 10)
                },
            ],
        );
        let mut peer_record = node_record("peer-a");
        peer_record.endpoint_candidates = vec![
            EndpointCandidate {
                addr: SocketAddr::from(([255, 255, 255, 255], 40000)),
                ..candidate("peer-a", EndpointCandidateKind::StunReflexive, 1)
            },
            EndpointCandidate {
                addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 40000),
                ..candidate("peer-a", EndpointCandidateKind::Ipv6, 1)
            },
            EndpointCandidate {
                addr: SocketAddr::from(([198, 51, 100, 20], 50000)),
                ..candidate("peer-a", EndpointCandidateKind::PublicUdp, 10)
            },
        ];

        let request = relay_admission_request(&status, &peer_record);

        assert_eq!(
            request,
            Some(RelayAdmissionRequest {
                left: local,
                right: peer,
                left_addr: SocketAddr::from(([198, 51, 100, 10], 50000)),
                right_addr: SocketAddr::from(([198, 51, 100, 20], 50000)),
            })
        );
    }

    #[test]
    fn relay_admission_request_requires_usable_session_endpoints() {
        let status = agent_status(
            "local",
            vec![
                EndpointCandidate {
                    addr: SocketAddr::from(([0, 0, 0, 0], 40000)),
                    ..candidate("local", EndpointCandidateKind::StunReflexive, 1)
                },
                EndpointCandidate {
                    addr: SocketAddr::from(([203, 0, 113, 10], 0)),
                    ..candidate("local", EndpointCandidateKind::PublicUdp, 1)
                },
            ],
        );
        let mut peer_record = node_record("peer-a");
        peer_record.endpoint_candidates = vec![EndpointCandidate {
            addr: SocketAddr::from(([198, 51, 100, 20], 50000)),
            ..candidate("peer-a", EndpointCandidateKind::PublicUdp, 10)
        }];

        assert_eq!(relay_admission_request(&status, &peer_record), None);

        let status = agent_status(
            "local",
            vec![EndpointCandidate {
                addr: SocketAddr::from(([198, 51, 100, 10], 50000)),
                ..candidate("local", EndpointCandidateKind::PublicUdp, 10)
            }],
        );
        peer_record.endpoint_candidates = vec![EndpointCandidate {
            addr: SocketAddr::from(([224, 0, 0, 1], 40000)),
            ..candidate("peer-a", EndpointCandidateKind::PublicUdp, 1)
        }];

        assert_eq!(relay_admission_request(&status, &peer_record), None);
    }

    #[test]
    fn selected_relay_candidates_prefer_capacity_tie_breaker() {
        let mut low_bandwidth = node_record("relay-low");
        low_bandwidth.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 31], 51820))),
            admission_url: Some("http://203.0.113.31:9580".to_string()),
            max_sessions: 100,
            active_sessions: 1,
            max_mbps: 100,
            e2e_only: true,
        });
        let mut high_bandwidth = node_record("relay-high");
        high_bandwidth.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 32], 51820))),
            admission_url: Some("http://203.0.113.32:9580".to_string()),
            max_sessions: 100,
            active_sessions: 1,
            max_mbps: 1000,
            e2e_only: true,
        });
        let response = SignalPathResponse {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            target_candidates: Vec::new(),
            relay_candidates: vec![low_bandwidth, high_bandwidth],
            preferred_state: PathState::Relay,
            score: PathScore {
                value: 70.0,
                reasons: Vec::new(),
            },
        };

        let selected = selected_relay_candidates(&response).into_iter().next();

        assert_eq!(
            selected.map(|relay| relay.node_id),
            Some(NodeId::from_string("relay-high"))
        );
    }

    #[test]
    fn selected_relay_candidates_prefer_lower_utilization_over_raw_session_count() {
        let mut nearly_full_small = node_record("relay-nearly-full-small");
        nearly_full_small.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 31], 51820))),
            admission_url: Some("http://203.0.113.31:9580".to_string()),
            max_sessions: 10,
            active_sessions: 9,
            max_mbps: 1000,
            e2e_only: true,
        });
        let mut lightly_loaded_large = node_record("relay-lightly-loaded-large");
        lightly_loaded_large.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 32], 51820))),
            admission_url: Some("http://203.0.113.32:9580".to_string()),
            max_sessions: 1000,
            active_sessions: 20,
            max_mbps: 1000,
            e2e_only: true,
        });
        let response = SignalPathResponse {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            target_candidates: Vec::new(),
            relay_candidates: vec![nearly_full_small, lightly_loaded_large],
            preferred_state: PathState::Relay,
            score: PathScore {
                value: 70.0,
                reasons: Vec::new(),
            },
        };

        let selected = selected_relay_candidates(&response).into_iter().next();

        assert_eq!(
            selected.map(|relay| relay.node_id),
            Some(NodeId::from_string("relay-lightly-loaded-large"))
        );
    }

    #[test]
    fn selected_relay_candidates_remain_available_for_direct_fallback() {
        let mut relay = node_record("relay-a");
        relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 31], 51820))),
            admission_url: Some("http://203.0.113.31:9580".to_string()),
            max_sessions: 100,
            active_sessions: 1,
            max_mbps: 1000,
            e2e_only: true,
        });
        let response = SignalPathResponse {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            target_candidates: vec![candidate(
                "peer-a",
                EndpointCandidateKind::StunReflexive,
                10,
            )],
            relay_candidates: vec![relay],
            preferred_state: PathState::DirectNatTraversal,
            score: PathScore {
                value: 105.0,
                reasons: Vec::new(),
            },
        };

        let selected = selected_relay_candidates(&response);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].node_id, NodeId::from_string("relay-a"));
    }

    #[tokio::test]
    async fn active_relay_candidate_is_promoted_for_path_stability() {
        let mut low_load = node_record("relay-low-load");
        low_load.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 31], 51820))),
            admission_url: Some("http://203.0.113.31:9580".to_string()),
            max_sessions: 100,
            active_sessions: 1,
            max_mbps: 1000,
            e2e_only: true,
        });
        let mut current = node_record("relay-current");
        current.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 32], 51820))),
            admission_url: Some("http://203.0.113.32:9580".to_string()),
            max_sessions: 100,
            active_sessions: 50,
            max_mbps: 1000,
            e2e_only: true,
        });
        let response = SignalPathResponse {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            target_candidates: Vec::new(),
            relay_candidates: vec![current.clone(), low_load.clone()],
            preferred_state: PathState::Relay,
            score: PathScore {
                value: 70.0,
                reasons: Vec::new(),
            },
        };
        let mut selected = selected_relay_candidates(&response);
        assert_eq!(
            selected
                .iter()
                .map(|relay| relay.node_id.clone())
                .collect::<Vec<_>>(),
            vec![
                NodeId::from_string("relay-low-load"),
                NodeId::from_string("relay-current")
            ]
        );
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer = NodeId::from_string("peer-a");
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: peer.clone(),
                relay_node: NodeId::from_string("relay-current"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 32], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-current".to_string(),
                session_token: "token-current".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
            })
            .await;

        let promoted = promote_active_relay_candidate(&runtime, &peer, &mut selected).await;

        assert_eq!(promoted, Some(NodeId::from_string("relay-current")));
        assert_eq!(
            selected
                .iter()
                .map(|relay| relay.node_id.clone())
                .collect::<Vec<_>>(),
            vec![
                NodeId::from_string("relay-current"),
                NodeId::from_string("relay-low-load")
            ]
        );
    }

    #[test]
    fn relay_fallback_path_record_marks_direct_nat_setup_failure() -> anyhow::Result<()> {
        let mut relay = node_record("relay-a");
        relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 31], 51820))),
            admission_url: Some("http://203.0.113.31:9580".to_string()),
            max_sessions: 10,
            active_sessions: 2,
            max_mbps: 1000,
            e2e_only: true,
        });
        let direct = PathRecord {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            selected_state: PathState::DirectNatTraversal,
            selected_candidate: Some(candidate(
                "peer-a",
                EndpointCandidateKind::StunReflexive,
                10,
            )),
            relay_node: None,
            score: PathScore {
                value: 105.0,
                reasons: Vec::new(),
            },
            updated_at: Utc::now(),
            pinned: true,
        };

        let fallback = relay_fallback_path_record(&direct, &[relay])
            .context("relay fallback should be built")?;

        assert_eq!(fallback.key, direct.key);
        assert_eq!(fallback.selected_state, PathState::Relay);
        assert_eq!(fallback.selected_candidate, None);
        assert_eq!(fallback.relay_node, Some(NodeId::from_string("relay-a")));
        assert!(fallback.pinned);
        assert!(fallback
            .score
            .reasons
            .iter()
            .any(|reason| reason == "relay_load=0.20"));
        assert!(fallback
            .score
            .reasons
            .iter()
            .any(|reason| reason == "direct_nat_traversal_failed"));
        Ok(())
    }

    #[tokio::test]
    async fn relay_admission_fails_over_to_next_candidate() -> anyhow::Result<()> {
        async fn relay_admission_success(
            axum::Json(request): axum::Json<RelayAdmissionRequest>,
        ) -> axum::Json<RelayAdmissionResponse> {
            let session_id = RelaySessionId::new(&request.left, &request.right)
                .as_str()
                .to_string();
            axum::Json(RelayAdmissionResponse {
                relay_node: NodeId::from_string("relay-good"),
                session_id,
                session_token: "token-a".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
                left: request.left,
                right: request.right,
                left_addr: request.left_addr,
                right_addr: request.right_addr,
            })
        }

        let (relay_base, relay_task) = spawn_test_http_service(
            Router::new().route("/v1/sessions", axum::routing::post(relay_admission_success)),
        )
        .await?;
        let unavailable = unused_http_base_url().await?;
        let mut relay_bad = node_record("relay-bad");
        relay_bad.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 31], 51820))),
            admission_url: Some(unavailable),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        });
        let mut relay_good = node_record("relay-good");
        relay_good.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 32], 51820))),
            admission_url: Some(relay_base),
            max_sessions: 100,
            active_sessions: 1,
            max_mbps: 1000,
            e2e_only: true,
        });
        let response = SignalPathResponse {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            target_candidates: Vec::new(),
            relay_candidates: vec![relay_good.clone(), relay_bad.clone()],
            preferred_state: PathState::Relay,
            score: PathScore {
                value: 70.0,
                reasons: Vec::new(),
            },
        };
        let ordered_relays = selected_relay_candidates(&response);
        assert_eq!(
            ordered_relays
                .iter()
                .map(|relay| relay.node_id.clone())
                .collect::<Vec<_>>(),
            vec![
                NodeId::from_string("relay-bad"),
                NodeId::from_string("relay-good")
            ]
        );

        let local = NodeId::from_string("local");
        let status = ipars_types::api::AgentStatusResponse {
            node_id: local.clone(),
            identity_public_key: "identity-local".to_string(),
            wireguard_public_key: "wg-local".to_string(),
            candidate_count: 1,
            candidates: vec![EndpointCandidate {
                node_id: local,
                kind: EndpointCandidateKind::StunReflexive,
                addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::StunProbe,
            }],
            nat_classification: None,
            userspace_wireguard_process: None,
            state_updated_at: Utc::now(),
        };
        let mut peer = node_record("peer-a");
        peer.endpoint_candidates = vec![EndpointCandidate {
            node_id: peer.node_id.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::StunProbe,
        }];
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );

        let session = admit_relay_session_from_candidates(
            &reqwest::Client::new(),
            &runtime,
            &status,
            &peer,
            &ordered_relays,
            None,
        )
        .await?;

        assert_eq!(session.relay_node, NodeId::from_string("relay-good"));
        assert_eq!(
            session.relay_endpoint,
            SocketAddr::from(([203, 0, 113, 32], 51820))
        );
        let metrics = runtime.metrics().await;
        assert_eq!(metrics.relay_admission_attempt_count, 2);
        assert_eq!(metrics.relay_admission_success_count, 1);
        assert_eq!(metrics.relay_admission_failure_count, 1);
        assert_agent_relay_admission_failure_reason(
            &metrics,
            AgentRelayAdmissionFailureReason::Unavailable,
            1,
        );
        relay_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn relay_admission_fails_over_after_invalid_response() -> anyhow::Result<()> {
        async fn relay_admission_invalid_session_id(
            axum::Json(request): axum::Json<RelayAdmissionRequest>,
        ) -> axum::Json<RelayAdmissionResponse> {
            axum::Json(RelayAdmissionResponse {
                relay_node: NodeId::from_string("relay-bad"),
                session_id: "wrong-session".to_string(),
                session_token: "token-bad".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
                left: request.left,
                right: request.right,
                left_addr: request.left_addr,
                right_addr: request.right_addr,
            })
        }

        async fn relay_admission_success(
            axum::Json(request): axum::Json<RelayAdmissionRequest>,
        ) -> axum::Json<RelayAdmissionResponse> {
            let session_id = RelaySessionId::new(&request.left, &request.right)
                .as_str()
                .to_string();
            axum::Json(RelayAdmissionResponse {
                relay_node: NodeId::from_string("relay-good"),
                session_id,
                session_token: "token-good".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
                left: request.left,
                right: request.right,
                left_addr: request.left_addr,
                right_addr: request.right_addr,
            })
        }

        let (bad_base, bad_task) = spawn_test_http_service(Router::new().route(
            "/v1/sessions",
            axum::routing::post(relay_admission_invalid_session_id),
        ))
        .await?;
        let (good_base, good_task) = spawn_test_http_service(
            Router::new().route("/v1/sessions", axum::routing::post(relay_admission_success)),
        )
        .await?;
        let mut relay_bad = node_record("relay-bad");
        relay_bad.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 31], 51820))),
            admission_url: Some(bad_base),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        });
        let mut relay_good = node_record("relay-good");
        relay_good.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 32], 51820))),
            admission_url: Some(good_base),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        });
        let local = NodeId::from_string("local");
        let status = ipars_types::api::AgentStatusResponse {
            node_id: local.clone(),
            identity_public_key: "identity-local".to_string(),
            wireguard_public_key: "wg-local".to_string(),
            candidate_count: 1,
            candidates: vec![EndpointCandidate {
                node_id: local,
                kind: EndpointCandidateKind::StunReflexive,
                addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::StunProbe,
            }],
            nat_classification: None,
            userspace_wireguard_process: None,
            state_updated_at: Utc::now(),
        };
        let mut peer = node_record("peer-a");
        peer.endpoint_candidates = vec![EndpointCandidate {
            node_id: peer.node_id.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::StunProbe,
        }];
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );

        let session = admit_relay_session_from_candidates(
            &reqwest::Client::new(),
            &runtime,
            &status,
            &peer,
            &[relay_bad, relay_good],
            None,
        )
        .await?;

        assert_eq!(session.relay_node, NodeId::from_string("relay-good"));
        assert_eq!(session.session_id, "local:peer-a");
        let metrics = runtime.metrics().await;
        assert_eq!(metrics.relay_admission_attempt_count, 2);
        assert_eq!(metrics.relay_admission_success_count, 1);
        assert_eq!(metrics.relay_admission_failure_count, 1);
        assert_agent_relay_admission_failure_reason(
            &metrics,
            AgentRelayAdmissionFailureReason::InvalidResponse,
            1,
        );
        bad_task.abort();
        good_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn relay_admission_sends_configured_bearer_token() -> anyhow::Result<()> {
        async fn relay_admission_requires_bearer(
            headers: axum::http::HeaderMap,
            axum::Json(request): axum::Json<RelayAdmissionRequest>,
        ) -> Result<axum::Json<RelayAdmissionResponse>, axum::http::StatusCode> {
            if headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                != Some("Bearer cluster-relay-secret")
            {
                return Err(axum::http::StatusCode::UNAUTHORIZED);
            }
            let session_id = RelaySessionId::new(&request.left, &request.right)
                .as_str()
                .to_string();
            Ok(axum::Json(RelayAdmissionResponse {
                relay_node: NodeId::from_string("relay-secure"),
                session_id,
                session_token: "token-secure".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
                left: request.left,
                right: request.right,
                left_addr: request.left_addr,
                right_addr: request.right_addr,
            }))
        }

        let (relay_base, relay_task) = spawn_test_http_service(Router::new().route(
            "/v1/sessions",
            axum::routing::post(relay_admission_requires_bearer),
        ))
        .await?;
        let mut relay = node_record("relay-secure");
        relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 32], 51820))),
            admission_url: Some(relay_base),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        });
        let local = NodeId::from_string("local");
        let status = ipars_types::api::AgentStatusResponse {
            node_id: local.clone(),
            identity_public_key: "identity-local".to_string(),
            wireguard_public_key: "wg-local".to_string(),
            candidate_count: 1,
            candidates: vec![EndpointCandidate {
                node_id: local,
                kind: EndpointCandidateKind::StunReflexive,
                addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::StunProbe,
            }],
            nat_classification: None,
            userspace_wireguard_process: None,
            state_updated_at: Utc::now(),
        };
        let mut peer = node_record("peer-a");
        peer.endpoint_candidates = vec![EndpointCandidate {
            node_id: peer.node_id.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::StunProbe,
        }];

        let rejected =
            admit_relay_session(&reqwest::Client::new(), &status, &peer, &relay, None).await;
        assert!(rejected.is_err());

        let accepted = admit_relay_session(
            &reqwest::Client::new(),
            &status,
            &peer,
            &relay,
            Some("cluster-relay-secret"),
        )
        .await?;

        assert_eq!(accepted.relay_node, NodeId::from_string("relay-secure"));
        assert_eq!(accepted.session_id, "local:peer-a");
        relay_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn signal_negotiation_records_relay_selected_after_admission_failover(
    ) -> anyhow::Result<()> {
        async fn relay_admission_success(
            axum::Json(request): axum::Json<RelayAdmissionRequest>,
        ) -> axum::Json<RelayAdmissionResponse> {
            let session_id = RelaySessionId::new(&request.left, &request.right)
                .as_str()
                .to_string();
            axum::Json(RelayAdmissionResponse {
                relay_node: NodeId::from_string("relay-good"),
                session_id,
                session_token: "token-good".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
                left: request.left,
                right: request.right,
                left_addr: request.left_addr,
                right_addr: request.right_addr,
            })
        }

        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local = runtime.state().node_id;
        runtime
            .replace_candidates(vec![EndpointCandidate {
                node_id: local.clone(),
                kind: EndpointCandidateKind::StunReflexive,
                addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::StunProbe,
            }])
            .await;

        let mut peer = node_record("peer-a");
        peer.endpoint_candidates = vec![candidate(
            "peer-a",
            EndpointCandidateKind::StunReflexive,
            10,
        )];
        runtime
            .record_peer_activity(peer.node_id.clone(), Utc::now(), false)
            .await;

        let unavailable = unused_http_base_url().await?;
        let mut relay_bad = node_record("relay-bad");
        relay_bad.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 31], 51820))),
            admission_url: Some(unavailable),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        });
        let (relay_base, relay_task) = spawn_test_http_service(
            Router::new().route("/v1/sessions", axum::routing::post(relay_admission_success)),
        )
        .await?;
        let mut relay_good = node_record("relay-good");
        relay_good.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 32], 51820))),
            admission_url: Some(relay_base),
            max_sessions: 100,
            active_sessions: 1,
            max_mbps: 1000,
            e2e_only: true,
        });

        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: vec![peer.clone()],
            generated_at: Utc::now(),
        };
        let (control_plane_base, control_plane_task) =
            spawn_test_http_service(Router::new().route(
                "/v1/peers/{node_id}",
                axum::routing::get(move || async move { axum::Json(peer_map.clone()) }),
            ))
            .await?;
        let signal_response = SignalPathResponse {
            key: PeerPathKey::new(local, peer.node_id.clone()),
            target_candidates: Vec::new(),
            relay_candidates: vec![relay_good, relay_bad],
            preferred_state: PathState::Relay,
            score: PathScore {
                value: 70.0,
                reasons: Vec::new(),
            },
        };
        let (signal_base, signal_task) = spawn_test_http_service(Router::new().route(
            "/v1/paths/negotiate",
            axum::routing::post(move || async move { axum::Json(signal_response.clone()) }),
        ))
        .await?;

        negotiate_signal_paths(
            &reqwest::Client::new(),
            &runtime,
            &[control_plane_base],
            &[signal_base],
            &UdpHolePuncher::new(SocketAddr::from(([127, 0, 0, 1], 0))),
            &SignalPathNegotiationOptions {
                relay_forwarder_supervisor: None,
                relay_admission_bearer_token: None,
                relay_session_renew_before: Duration::from_secs(30),
                interval: Duration::from_secs(1),
            },
        )
        .await?;

        let record = runtime
            .path_record_for_peer(&peer.node_id)
            .await
            .context("relay path record should be stored")?;
        assert_eq!(record.selected_state, PathState::Relay);
        assert_eq!(record.relay_node, Some(NodeId::from_string("relay-good")));
        let session = runtime
            .relay_session(&peer.node_id)
            .await
            .context("relay session should be stored")?;
        assert_eq!(session.relay_node, NodeId::from_string("relay-good"));
        let metrics = runtime.metrics().await;
        assert_eq!(metrics.relay_admission_attempt_count, 2);
        assert_eq!(metrics.relay_admission_success_count, 1);
        assert_eq!(metrics.relay_admission_failure_count, 1);
        assert_agent_relay_admission_failure_reason(
            &metrics,
            AgentRelayAdmissionFailureReason::Unavailable,
            1,
        );

        signal_task.abort();
        control_plane_task.abort();
        relay_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn signal_negotiation_marks_relay_unreachable_when_admission_fails() -> anyhow::Result<()>
    {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local = runtime.state().node_id;
        runtime
            .replace_candidates(vec![EndpointCandidate {
                node_id: local.clone(),
                kind: EndpointCandidateKind::StunReflexive,
                addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::StunProbe,
            }])
            .await;

        let mut peer = node_record("peer-a");
        peer.endpoint_candidates = vec![candidate(
            "peer-a",
            EndpointCandidateKind::StunReflexive,
            10,
        )];
        runtime
            .record_peer_activity(peer.node_id.clone(), Utc::now(), false)
            .await;

        let mut relay = node_record("relay-a");
        relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 31], 51820))),
            admission_url: Some(unused_http_base_url().await?),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        });

        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: vec![peer.clone()],
            generated_at: Utc::now(),
        };
        let (control_plane_base, control_plane_task) =
            spawn_test_http_service(Router::new().route(
                "/v1/peers/{node_id}",
                axum::routing::get(move || async move { axum::Json(peer_map.clone()) }),
            ))
            .await?;
        let signal_response = SignalPathResponse {
            key: PeerPathKey::new(local, peer.node_id.clone()),
            target_candidates: Vec::new(),
            relay_candidates: vec![relay],
            preferred_state: PathState::Relay,
            score: PathScore {
                value: 70.0,
                reasons: Vec::new(),
            },
        };
        let (signal_base, signal_task) = spawn_test_http_service(Router::new().route(
            "/v1/paths/negotiate",
            axum::routing::post(move || async move { axum::Json(signal_response.clone()) }),
        ))
        .await?;

        negotiate_signal_paths(
            &reqwest::Client::new(),
            &runtime,
            &[control_plane_base],
            &[signal_base],
            &UdpHolePuncher::new(SocketAddr::from(([127, 0, 0, 1], 0))),
            &SignalPathNegotiationOptions {
                relay_forwarder_supervisor: None,
                relay_admission_bearer_token: None,
                relay_session_renew_before: Duration::from_secs(30),
                interval: Duration::from_secs(1),
            },
        )
        .await?;

        let record = runtime
            .path_record_for_peer(&peer.node_id)
            .await
            .context("unreachable path record should be stored")?;
        assert_eq!(record.selected_state, PathState::Unreachable);
        assert_eq!(record.relay_node, None);
        assert!(record
            .score
            .reasons
            .iter()
            .any(|reason| reason == "relay_admission_failed"));
        assert!(runtime.relay_session(&peer.node_id).await.is_none());
        let metrics = runtime.metrics().await;
        assert_eq!(metrics.relay_admission_attempt_count, 1);
        assert_eq!(metrics.relay_admission_success_count, 0);
        assert_eq!(metrics.relay_admission_failure_count, 1);
        assert_agent_relay_admission_failure_reason(
            &metrics,
            AgentRelayAdmissionFailureReason::Unavailable,
            1,
        );

        signal_task.abort();
        control_plane_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn signal_negotiation_retains_active_relay_session_when_renewal_fails(
    ) -> anyhow::Result<()> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local = runtime.state().node_id;
        runtime
            .replace_candidates(vec![EndpointCandidate {
                node_id: local.clone(),
                kind: EndpointCandidateKind::StunReflexive,
                addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::StunProbe,
            }])
            .await;

        let mut peer = node_record("peer-a");
        peer.endpoint_candidates = vec![candidate(
            "peer-a",
            EndpointCandidateKind::StunReflexive,
            10,
        )];
        runtime
            .record_peer_activity(peer.node_id.clone(), Utc::now(), false)
            .await;
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: peer.node_id.clone(),
                relay_node: NodeId::from_string("relay-old"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 30], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-old".to_string(),
                session_token: "token-old".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
            })
            .await;

        let mut relay = node_record("relay-new");
        relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 31], 51820))),
            admission_url: Some(unused_http_base_url().await?),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        });

        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: vec![peer.clone()],
            generated_at: Utc::now(),
        };
        let (control_plane_base, control_plane_task) =
            spawn_test_http_service(Router::new().route(
                "/v1/peers/{node_id}",
                axum::routing::get(move || async move { axum::Json(peer_map.clone()) }),
            ))
            .await?;
        let signal_response = SignalPathResponse {
            key: PeerPathKey::new(local, peer.node_id.clone()),
            target_candidates: Vec::new(),
            relay_candidates: vec![relay],
            preferred_state: PathState::Relay,
            score: PathScore {
                value: 70.0,
                reasons: Vec::new(),
            },
        };
        let (signal_base, signal_task) = spawn_test_http_service(Router::new().route(
            "/v1/paths/negotiate",
            axum::routing::post(move || async move { axum::Json(signal_response.clone()) }),
        ))
        .await?;

        negotiate_signal_paths(
            &reqwest::Client::new(),
            &runtime,
            &[control_plane_base],
            &[signal_base],
            &UdpHolePuncher::new(SocketAddr::from(([127, 0, 0, 1], 0))),
            &SignalPathNegotiationOptions {
                relay_forwarder_supervisor: None,
                relay_admission_bearer_token: None,
                relay_session_renew_before: Duration::from_secs(120),
                interval: Duration::from_secs(1),
            },
        )
        .await?;

        let record = runtime
            .path_record_for_peer(&peer.node_id)
            .await
            .context("relay path record should be stored")?;
        assert_eq!(record.selected_state, PathState::Relay);
        assert_eq!(record.relay_node, Some(NodeId::from_string("relay-old")));
        let session = runtime
            .relay_session(&peer.node_id)
            .await
            .context("existing relay session should be retained")?;
        assert_eq!(session.relay_node, NodeId::from_string("relay-old"));
        assert_eq!(session.session_id, "session-old");
        let metrics = runtime.metrics().await;
        assert_eq!(metrics.relay_admission_attempt_count, 1);
        assert_eq!(metrics.relay_admission_success_count, 0);
        assert_eq!(metrics.relay_admission_failure_count, 1);
        assert_agent_relay_admission_failure_reason(
            &metrics,
            AgentRelayAdmissionFailureReason::Unavailable,
            1,
        );

        signal_task.abort();
        control_plane_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn signal_negotiation_falls_back_to_relay_when_hole_punch_setup_fails(
    ) -> anyhow::Result<()> {
        async fn relay_admission_success(
            axum::Json(request): axum::Json<RelayAdmissionRequest>,
        ) -> axum::Json<RelayAdmissionResponse> {
            let session_id = RelaySessionId::new(&request.left, &request.right)
                .as_str()
                .to_string();
            axum::Json(RelayAdmissionResponse {
                relay_node: NodeId::from_string("relay-a"),
                session_id,
                session_token: "token-a".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
                left: request.left,
                right: request.right,
                left_addr: request.left_addr,
                right_addr: request.right_addr,
            })
        }

        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local = runtime.state().node_id;
        runtime
            .replace_candidates(vec![EndpointCandidate {
                node_id: local.clone(),
                kind: EndpointCandidateKind::StunReflexive,
                addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::StunProbe,
            }])
            .await;
        let mut peer = node_record("peer-a");
        peer.endpoint_candidates = vec![candidate(
            "peer-a",
            EndpointCandidateKind::StunReflexive,
            10,
        )];
        runtime
            .record_peer_activity(peer.node_id.clone(), Utc::now(), false)
            .await;

        let (relay_base, relay_task) = spawn_test_http_service(
            Router::new().route("/v1/sessions", axum::routing::post(relay_admission_success)),
        )
        .await?;
        let mut relay = node_record("relay-a");
        relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 31], 51820))),
            admission_url: Some(relay_base),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        });

        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: vec![peer.clone()],
            generated_at: Utc::now(),
        };
        let (control_plane_base, control_plane_task) =
            spawn_test_http_service(Router::new().route(
                "/v1/peers/{node_id}",
                axum::routing::get(move || async move { axum::Json(peer_map.clone()) }),
            ))
            .await?;
        let signal_response = SignalPathResponse {
            key: PeerPathKey::new(local, peer.node_id.clone()),
            target_candidates: peer.endpoint_candidates.clone(),
            relay_candidates: vec![relay],
            preferred_state: PathState::DirectNatTraversal,
            score: PathScore {
                value: 105.0,
                reasons: Vec::new(),
            },
        };
        let (signal_base, signal_task) = spawn_test_http_service(Router::new().route(
            "/v1/paths/negotiate",
            axum::routing::post(move || async move { axum::Json(signal_response.clone()) }),
        ))
        .await?;

        negotiate_signal_paths(
            &reqwest::Client::new(),
            &runtime,
            &[control_plane_base],
            &[signal_base],
            &UdpHolePuncher::new(SocketAddr::from(([127, 0, 0, 1], 0))),
            &SignalPathNegotiationOptions {
                relay_forwarder_supervisor: None,
                relay_admission_bearer_token: None,
                relay_session_renew_before: Duration::from_secs(30),
                interval: Duration::from_secs(1),
            },
        )
        .await?;

        let record = runtime
            .path_record_for_peer(&peer.node_id)
            .await
            .context("fallback path record should be stored")?;
        assert_eq!(record.selected_state, PathState::Relay);
        assert_eq!(record.relay_node, Some(NodeId::from_string("relay-a")));
        assert!(record
            .score
            .reasons
            .iter()
            .any(|reason| reason == "direct_nat_traversal_failed"));
        assert!(runtime.relay_session(&peer.node_id).await.is_some());
        let metrics = runtime.metrics().await;
        assert_eq!(metrics.relay_admission_attempt_count, 1);
        assert_eq!(metrics.relay_admission_success_count, 1);
        assert_eq!(metrics.relay_admission_failure_count, 0);

        signal_task.abort();
        control_plane_task.abort();
        relay_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn signal_negotiation_marks_nat_traversal_unreachable_without_relay_fallback(
    ) -> anyhow::Result<()> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local = runtime.state().node_id;
        runtime
            .replace_candidates(vec![EndpointCandidate {
                node_id: local.clone(),
                kind: EndpointCandidateKind::StunReflexive,
                addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::StunProbe,
            }])
            .await;

        let mut peer = node_record("peer-a");
        peer.endpoint_candidates = vec![candidate(
            "peer-a",
            EndpointCandidateKind::StunReflexive,
            10,
        )];
        runtime
            .record_peer_activity(peer.node_id.clone(), Utc::now(), false)
            .await;

        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: vec![peer.clone()],
            generated_at: Utc::now(),
        };
        let (control_plane_base, control_plane_task) =
            spawn_test_http_service(Router::new().route(
                "/v1/peers/{node_id}",
                axum::routing::get(move || async move { axum::Json(peer_map.clone()) }),
            ))
            .await?;
        let signal_response = SignalPathResponse {
            key: PeerPathKey::new(local, peer.node_id.clone()),
            target_candidates: peer.endpoint_candidates.clone(),
            relay_candidates: Vec::new(),
            preferred_state: PathState::DirectNatTraversal,
            score: PathScore {
                value: 105.0,
                reasons: Vec::new(),
            },
        };
        let (signal_base, signal_task) = spawn_test_http_service(Router::new().route(
            "/v1/paths/negotiate",
            axum::routing::post(move || async move { axum::Json(signal_response.clone()) }),
        ))
        .await?;

        negotiate_signal_paths(
            &reqwest::Client::new(),
            &runtime,
            &[control_plane_base],
            &[signal_base],
            &UdpHolePuncher::new(SocketAddr::from(([127, 0, 0, 1], 0))),
            &SignalPathNegotiationOptions {
                relay_forwarder_supervisor: None,
                relay_admission_bearer_token: None,
                relay_session_renew_before: Duration::from_secs(30),
                interval: Duration::from_secs(1),
            },
        )
        .await?;

        let record = runtime
            .path_record_for_peer(&peer.node_id)
            .await
            .context("unreachable path record should be stored")?;
        assert_eq!(record.selected_state, PathState::Unreachable);
        assert_eq!(record.selected_candidate, None);
        assert_eq!(record.relay_node, None);
        assert!(record
            .score
            .reasons
            .iter()
            .any(|reason| reason == "direct_nat_traversal_failed"));
        assert!(runtime.relay_session(&peer.node_id).await.is_none());
        let metrics = runtime.metrics().await;
        assert_eq!(metrics.relay_admission_attempt_count, 0);
        assert_eq!(metrics.relay_admission_success_count, 0);
        assert_eq!(metrics.relay_admission_failure_count, 0);

        signal_task.abort();
        control_plane_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_request_uses_runtime_state() -> anyhow::Result<()> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let node_id = runtime.state().node_id.clone();
        let path = PathRecord {
            key: PeerPathKey::new(node_id.clone(), NodeId::from_string("peer-a")),
            selected_state: PathState::DirectPublic,
            selected_candidate: None,
            relay_node: None,
            score: PathScore {
                value: 100.0,
                reasons: Vec::new(),
            },
            updated_at: Utc::now(),
            pinned: false,
        };
        runtime.upsert_path_state(path.clone()).await?;

        let identity = runtime.state().identity_key_pair()?;
        let advertised_route = Route {
            id: "route-a".to_string(),
            cidr: "10.42.0.0/16".parse()?,
            advertised_by: node_id.clone(),
            via: Some(node_id.clone()),
            metric: 100,
            tags: Default::default(),
        };
        let request = heartbeat_request(
            &runtime,
            &identity,
            None,
            Some(vec![advertised_route.clone()]),
        )
        .await?;

        assert_eq!(request.node_id, node_id);
        assert_eq!(request.health.state, HealthState::Healthy);
        assert!(request.node_signature.is_some());
        assert!(request.candidates.is_empty());
        assert!(request.relay_capability.is_none());
        assert_eq!(request.routes, Some(vec![advertised_route]));
        assert_eq!(request.path_state, vec![path]);
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_request_marks_failed_userspace_wireguard_unhealthy() -> anyhow::Result<()> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        runtime
            .record_userspace_wireguard_process_status(
                AgentManagedProcessState::Failed,
                Some(4242),
                Some("signal: 9 (SIGKILL)".to_string()),
                Some("failed to stop userspace WireGuard process cleanly".to_string()),
            )
            .await;
        let identity = runtime.state().identity_key_pair()?;

        let request = heartbeat_request(&runtime, &identity, None, None).await?;

        assert_eq!(request.health.state, HealthState::Unhealthy);
        let message = request.health.message.as_deref().unwrap_or_default();
        assert!(message.contains("state=failed"));
        assert!(message.contains("exit_status=signal: 9 (SIGKILL)"));
        assert!(message.contains("failed to stop userspace WireGuard process cleanly"));
        assert!(request.node_signature.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn signal_node_upsert_request_uses_runtime_candidates() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let node = node_record("node-a");

        let request = signal_node_upsert_request(&runtime, node, None).await;

        assert_eq!(request.node.node_id, NodeId::from_string("node-a"));
        assert!(request.node.endpoint_candidates.is_empty());
        assert_eq!(
            request.health.as_ref().map(|health| health.state),
            Some(HealthState::Healthy)
        );
    }

    #[tokio::test]
    async fn signal_node_upsert_refreshes_policy_enabled_relay_capability() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let mut node = node_record("node-a");
        node.relay_capability = Some(test_relay_capability(100, 1));
        let refreshed = RelayCapability {
            enabled_by_policy: false,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 30], 51_820))),
            admission_url: Some("http://203.0.113.30:9580".to_string()),
            max_sessions: 250,
            active_sessions: 12,
            max_mbps: 750,
            e2e_only: true,
        };

        let request = signal_node_upsert_request(&runtime, node, Some(refreshed)).await;
        let relay_capability = match request.node.relay_capability {
            Some(relay_capability) => relay_capability,
            None => panic!("policy enabled relay should remain advertised"),
        };

        assert!(relay_capability.enabled_by_policy);
        assert_eq!(relay_capability.max_sessions, 250);
        assert_eq!(relay_capability.active_sessions, 12);
        assert_eq!(relay_capability.max_mbps, 750);
    }

    #[tokio::test]
    async fn signal_node_upsert_clears_relay_capability_without_status_refresh() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let mut node = node_record("node-a");
        node.relay_capability = Some(test_relay_capability(100, 1));

        let request = signal_node_upsert_request(&runtime, node, None).await;

        assert!(request.node.relay_capability.is_none());
    }

    #[tokio::test]
    async fn signal_node_upsert_reports_userspace_wireguard_exit_health() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        runtime
            .record_userspace_wireguard_process_status(
                AgentManagedProcessState::Exited,
                Some(4242),
                Some("exit status: 1".to_string()),
                None,
            )
            .await;
        let node = node_record("node-a");

        let request = signal_node_upsert_request(&runtime, node, None).await;

        let health = match request.health {
            Some(health) => health,
            None => panic!("signal upsert should include health"),
        };
        assert_eq!(health.state, HealthState::Unhealthy);
        assert!(health
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("state=exited"));
    }

    #[tokio::test]
    async fn signal_negotiation_peer_set_uses_lazy_connect_state() -> anyhow::Result<()> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy {
                idle_timeout_seconds: 10,
                ..ClusterPolicy::default()
            },
        );
        let active_id = NodeId::from_string("peer-active");
        let stale_id = NodeId::from_string("peer-stale");
        runtime
            .record_peer_activity(active_id.clone(), Utc::now(), false)
            .await;
        runtime
            .record_peer_activity(
                stale_id.clone(),
                Utc::now() - ChronoDuration::seconds(30),
                false,
            )
            .await;
        let active = node_record("peer-active");
        let idle = node_record("peer-idle");
        let stale = node_record("peer-stale");
        let mut pinned = node_record("peer-pinned");
        pinned.role = Role::control_plane();
        let mut route_provider = node_record("peer-route");
        route_provider.routes.push(Route {
            id: "route-a".to_string(),
            cidr: "10.42.0.0/16".parse()?,
            advertised_by: route_provider.node_id.clone(),
            via: Some(route_provider.node_id.clone()),
            metric: 100,
            tags: Default::default(),
        });

        let peers = signal_negotiation_peer_set(
            &runtime,
            PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![active, idle, stale, pinned, route_provider],
                generated_at: Utc::now(),
            },
        )
        .await;

        let active_ids = peers
            .active
            .into_iter()
            .map(|peer| peer.node_id)
            .collect::<Vec<_>>();
        assert_eq!(
            active_ids,
            vec![
                NodeId::from_string("peer-active"),
                NodeId::from_string("peer-pinned"),
                NodeId::from_string("peer-route"),
            ]
        );
        assert_eq!(
            peers.skipped,
            vec![
                NodeId::from_string("peer-idle"),
                NodeId::from_string("peer-stale"),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn idle_signal_peer_cleanup_removes_relay_runtime_state() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer = NodeId::from_string("peer-idle");
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: peer.clone(),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 30], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-a".to_string(),
                session_token: "secret".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
            })
            .await;
        runtime
            .upsert_relay_forwarder_endpoint(
                peer.clone(),
                SocketAddr::from(([127, 0, 0, 1], 52000)),
            )
            .await;

        remove_relay_session_for_peer(
            &runtime,
            None,
            &peer,
            None,
            "removed relay session for idle lazy-connect peer",
        )
        .await;

        assert!(runtime.relay_session(&peer).await.is_none());
        assert!(runtime.relay_forwarder_endpoint(&peer).await.is_none());
    }

    #[tokio::test]
    async fn stable_signal_path_record_keeps_relay_when_direct_gain_is_small() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local = runtime.state().node_id.clone();
        let peer = NodeId::from_string("peer-a");
        let current = PathRecord {
            key: PeerPathKey::new(local.clone(), peer.clone()),
            selected_state: PathState::Relay,
            selected_candidate: None,
            relay_node: Some(NodeId::from_string("relay-a")),
            score: PathScore {
                value: 70.0,
                reasons: Vec::new(),
            },
            updated_at: Utc::now() - ChronoDuration::seconds(10),
            pinned: false,
        };
        runtime
            .upsert_path_state(current)
            .await
            .expect("valid relay path state should be stored");
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: peer.clone(),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 31], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-a".to_string(),
                session_token: "token-a".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
            })
            .await;
        let candidate_updated_at = Utc::now();
        let candidate_record = PathRecord {
            key: PeerPathKey::new(local, peer),
            selected_state: PathState::DirectNatTraversal,
            selected_candidate: Some(candidate(
                "peer-a",
                EndpointCandidateKind::StunReflexive,
                10,
            )),
            relay_node: None,
            score: PathScore {
                value: 74.9,
                reasons: Vec::new(),
            },
            updated_at: candidate_updated_at,
            pinned: false,
        };

        let (selected, selection) = stable_signal_path_record(&runtime, candidate_record).await;

        assert_eq!(selection, StableSignalPathSelection::CurrentRelay);
        assert_eq!(selected.selected_state, PathState::Relay);
        assert_eq!(selected.relay_node, Some(NodeId::from_string("relay-a")));
        assert_eq!(selected.updated_at, candidate_updated_at);
    }

    #[tokio::test]
    async fn stable_signal_path_record_accepts_direct_without_active_relay_session() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local = runtime.state().node_id.clone();
        let peer = NodeId::from_string("peer-a");
        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(local.clone(), peer.clone()),
                selected_state: PathState::Relay,
                selected_candidate: None,
                relay_node: Some(NodeId::from_string("relay-a")),
                score: PathScore {
                    value: 70.0,
                    reasons: Vec::new(),
                },
                updated_at: Utc::now() - ChronoDuration::seconds(10),
                pinned: false,
            })
            .await
            .expect("valid relay path state should be stored");
        let candidate_record = PathRecord {
            key: PeerPathKey::new(local, peer),
            selected_state: PathState::DirectNatTraversal,
            selected_candidate: Some(candidate(
                "peer-a",
                EndpointCandidateKind::StunReflexive,
                10,
            )),
            relay_node: None,
            score: PathScore {
                value: 74.9,
                reasons: Vec::new(),
            },
            updated_at: Utc::now(),
            pinned: false,
        };

        let (selected, selection) =
            stable_signal_path_record(&runtime, candidate_record.clone()).await;

        assert_eq!(selection, StableSignalPathSelection::Candidate);
        assert_eq!(selected, candidate_record);
    }

    #[tokio::test]
    async fn stable_signal_path_record_accepts_direct_when_relay_session_expired() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local = runtime.state().node_id.clone();
        let peer = NodeId::from_string("peer-a");
        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(local.clone(), peer.clone()),
                selected_state: PathState::Relay,
                selected_candidate: None,
                relay_node: Some(NodeId::from_string("relay-a")),
                score: PathScore {
                    value: 70.0,
                    reasons: Vec::new(),
                },
                updated_at: Utc::now() - ChronoDuration::seconds(10),
                pinned: false,
            })
            .await
            .expect("valid relay path state should be stored");
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: peer.clone(),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 31], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-a".to_string(),
                session_token: "token-a".to_string(),
                expires_at: Utc::now() - ChronoDuration::seconds(1),
            })
            .await;
        let candidate_record = PathRecord {
            key: PeerPathKey::new(local, peer),
            selected_state: PathState::DirectNatTraversal,
            selected_candidate: Some(candidate(
                "peer-a",
                EndpointCandidateKind::StunReflexive,
                10,
            )),
            relay_node: None,
            score: PathScore {
                value: 74.9,
                reasons: Vec::new(),
            },
            updated_at: Utc::now(),
            pinned: false,
        };

        let (selected, selection) =
            stable_signal_path_record(&runtime, candidate_record.clone()).await;

        assert_eq!(selection, StableSignalPathSelection::Candidate);
        assert_eq!(selected, candidate_record);
    }

    #[tokio::test]
    async fn stable_signal_path_record_accepts_direct_when_gain_clears_margin() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local = runtime.state().node_id.clone();
        let peer = NodeId::from_string("peer-a");
        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(local.clone(), peer.clone()),
                selected_state: PathState::Relay,
                selected_candidate: None,
                relay_node: Some(NodeId::from_string("relay-a")),
                score: PathScore {
                    value: 70.0,
                    reasons: Vec::new(),
                },
                updated_at: Utc::now() - ChronoDuration::seconds(10),
                pinned: false,
            })
            .await
            .expect("valid relay path state should be stored");
        let candidate_record = PathRecord {
            key: PeerPathKey::new(local, peer),
            selected_state: PathState::DirectNatTraversal,
            selected_candidate: Some(candidate(
                "peer-a",
                EndpointCandidateKind::StunReflexive,
                10,
            )),
            relay_node: None,
            score: PathScore {
                value: 75.0,
                reasons: Vec::new(),
            },
            updated_at: Utc::now(),
            pinned: false,
        };

        let (selected, selection) =
            stable_signal_path_record(&runtime, candidate_record.clone()).await;

        assert_eq!(selection, StableSignalPathSelection::Candidate);
        assert_eq!(selected, candidate_record);
    }

    #[test]
    fn signal_path_record_selects_direct_candidate() {
        let response = SignalPathResponse {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            target_candidates: vec![
                candidate("peer-a", EndpointCandidateKind::StunReflexive, 1),
                candidate("peer-a", EndpointCandidateKind::PublicUdp, 50),
            ],
            relay_candidates: Vec::new(),
            preferred_state: PathState::DirectPublic,
            score: PathScore {
                value: 115.0,
                reasons: Vec::new(),
            },
        };

        let record = signal_path_record(response, Utc::now());

        assert_eq!(record.selected_state, PathState::DirectPublic);
        assert_eq!(
            record
                .selected_candidate
                .as_ref()
                .map(|candidate| candidate.kind),
            Some(EndpointCandidateKind::PublicUdp)
        );
        assert_eq!(record.relay_node, None);
    }

    #[test]
    fn signal_path_record_selects_ipv6_candidate() {
        let response = SignalPathResponse {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            target_candidates: vec![
                candidate("peer-a", EndpointCandidateKind::PublicUdp, 1),
                ipv6_candidate("peer-a", 50),
            ],
            relay_candidates: Vec::new(),
            preferred_state: PathState::DirectIpv6,
            score: PathScore {
                value: 120.0,
                reasons: Vec::new(),
            },
        };

        let record = signal_path_record(response, Utc::now());

        assert_eq!(record.selected_state, PathState::DirectIpv6);
        assert_eq!(
            record
                .selected_candidate
                .as_ref()
                .map(|candidate| candidate.kind),
            Some(EndpointCandidateKind::Ipv6)
        );
        assert_eq!(record.relay_node, None);
    }

    #[test]
    fn signal_path_record_selects_nat_traversal_candidate() {
        let response = SignalPathResponse {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            target_candidates: vec![
                candidate("peer-a", EndpointCandidateKind::LocalUdp, 1),
                candidate("peer-a", EndpointCandidateKind::StunReflexive, 10),
            ],
            relay_candidates: Vec::new(),
            preferred_state: PathState::DirectNatTraversal,
            score: PathScore {
                value: 105.0,
                reasons: Vec::new(),
            },
        };

        let record = signal_path_record(response, Utc::now());

        assert_eq!(record.selected_state, PathState::DirectNatTraversal);
        assert_eq!(
            record
                .selected_candidate
                .as_ref()
                .map(|candidate| candidate.kind),
            Some(EndpointCandidateKind::StunReflexive)
        );
    }

    #[test]
    fn signal_path_record_does_not_select_mismatched_direct_candidate() {
        let response = SignalPathResponse {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            target_candidates: vec![
                candidate("peer-a", EndpointCandidateKind::StunReflexive, 1),
                candidate("peer-a", EndpointCandidateKind::LocalUdp, 10),
                candidate("peer-a", EndpointCandidateKind::Relay, 100),
            ],
            relay_candidates: Vec::new(),
            preferred_state: PathState::DirectPublic,
            score: PathScore {
                value: 115.0,
                reasons: Vec::new(),
            },
        };

        let record = signal_path_record(response, Utc::now());

        assert_eq!(record.selected_state, PathState::DirectPublic);
        assert_eq!(record.selected_candidate, None);
        assert_eq!(record.relay_node, None);
    }

    #[test]
    fn signal_path_record_selects_relay_node() {
        let mut relay = node_record("relay-a");
        relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 30], 51820))),
            admission_url: Some("http://203.0.113.30:9580".to_string()),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        });
        let response = SignalPathResponse {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string("peer-a")),
            target_candidates: vec![candidate("peer-a", EndpointCandidateKind::Relay, 100)],
            relay_candidates: vec![relay],
            preferred_state: PathState::Relay,
            score: PathScore {
                value: 70.0,
                reasons: Vec::new(),
            },
        };

        let record = signal_path_record(response, Utc::now());

        assert_eq!(record.selected_state, PathState::Relay);
        assert_eq!(record.selected_candidate, None);
        assert_eq!(record.relay_node, Some(NodeId::from_string("relay-a")));
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
    fn control_plane_base_urls_include_all_token_bootstraps() -> anyhow::Result<()> {
        let token = token_with_bootstrap(vec![
            BootstrapEndpoint {
                url: "https://203.0.113.10:9443".to_string(),
                kind: BootstrapEndpointKind::Signal,
            },
            BootstrapEndpoint {
                url: "https://203.0.113.10:8443/".to_string(),
                kind: BootstrapEndpointKind::ControlPlane,
            },
            BootstrapEndpoint {
                url: "https://203.0.113.11:8443".to_string(),
                kind: BootstrapEndpointKind::ControlPlane,
            },
        ]);

        assert_eq!(
            control_plane_base_urls(Some(&token), None)?,
            vec![
                "https://203.0.113.10:8443".to_string(),
                "https://203.0.113.11:8443".to_string(),
            ]
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
    fn control_plane_base_urls_reject_non_http_bootstraps() -> anyhow::Result<()> {
        let token = token_with_bootstrap(vec![BootstrapEndpoint {
            url: "udp://203.0.113.10:8443".to_string(),
            kind: BootstrapEndpointKind::ControlPlane,
        }]);

        let error = match control_plane_base_urls(Some(&token), None) {
            Ok(_) => anyhow::bail!("non-HTTP control-plane bootstrap should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("control-plane bootstrap endpoint must use http or https"));
        Ok(())
    }

    #[test]
    fn agent_control_plane_base_urls_prefer_registration_and_dedupe() -> anyhow::Result<()> {
        let token = token_with_bootstrap(vec![
            BootstrapEndpoint {
                url: "https://203.0.113.10:8443/".to_string(),
                kind: BootstrapEndpointKind::ControlPlane,
            },
            BootstrapEndpoint {
                url: "https://203.0.113.11:8443".to_string(),
                kind: BootstrapEndpointKind::ControlPlane,
            },
        ]);

        assert_eq!(
            agent_control_plane_base_urls(Some(&token), None, Some("https://203.0.113.11:8443/"))?,
            vec![
                "https://203.0.113.11:8443".to_string(),
                "https://203.0.113.10:8443".to_string(),
            ]
        );
        Ok(())
    }

    #[test]
    fn agent_control_plane_base_urls_override_takes_precedence() -> anyhow::Result<()> {
        let token = token_with_bootstrap(vec![BootstrapEndpoint {
            url: "https://203.0.113.10:8443".to_string(),
            kind: BootstrapEndpointKind::ControlPlane,
        }]);

        assert_eq!(
            agent_control_plane_base_urls(
                Some(&token),
                Some("http://127.0.0.1:8443/"),
                Some("https://203.0.113.10:8443")
            )?,
            vec!["http://127.0.0.1:8443".to_string()]
        );
        Ok(())
    }

    #[test]
    fn agent_control_plane_base_urls_can_be_empty_without_source() -> anyhow::Result<()> {
        assert_eq!(
            agent_control_plane_base_urls(None, None, None)?,
            Vec::<String>::new()
        );
        Ok(())
    }

    #[test]
    fn control_plane_base_url_override_must_be_http() -> anyhow::Result<()> {
        let error = match control_plane_base_url(None, Some("udp://127.0.0.1:8443")) {
            Ok(_) => anyhow::bail!("non-HTTP control-plane override should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("control-plane URL must use http or https"));
        Ok(())
    }

    #[test]
    fn control_plane_base_url_override_rejects_unusable_numeric_host() -> anyhow::Result<()> {
        let error = match control_plane_base_url(None, Some("http://0.0.0.0:8443")) {
            Ok(_) => anyhow::bail!("unusable control-plane override should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("control-plane URL"));
        assert!(error.to_string().contains("usable non-unspecified"));
        Ok(())
    }

    #[test]
    fn signal_base_url_uses_token_bootstrap() -> anyhow::Result<()> {
        let token = token_with_bootstrap(vec![
            BootstrapEndpoint {
                url: "https://203.0.113.10:9443/".to_string(),
                kind: BootstrapEndpointKind::Signal,
            },
            BootstrapEndpoint {
                url: "https://203.0.113.11:9443".to_string(),
                kind: BootstrapEndpointKind::Signal,
            },
        ]);

        assert_eq!(
            signal_base_url(Some(&token), None)?,
            "https://203.0.113.10:9443"
        );
        assert_eq!(
            signal_base_urls(Some(&token), None)?,
            vec![
                "https://203.0.113.10:9443".to_string(),
                "https://203.0.113.11:9443".to_string()
            ]
        );
        Ok(())
    }

    #[test]
    fn signal_base_url_override_takes_precedence() -> anyhow::Result<()> {
        let token = token_with_bootstrap(vec![BootstrapEndpoint {
            url: "https://203.0.113.10:9443".to_string(),
            kind: BootstrapEndpointKind::Signal,
        }]);

        assert_eq!(
            signal_base_url(Some(&token), Some("http://127.0.0.1:9443/"))?,
            "http://127.0.0.1:9443"
        );
        assert_eq!(
            signal_base_urls(Some(&token), Some("http://127.0.0.1:9443/"))?,
            vec!["http://127.0.0.1:9443".to_string()]
        );
        Ok(())
    }

    #[test]
    fn signal_base_urls_reject_non_http_bootstraps() -> anyhow::Result<()> {
        let token = token_with_bootstrap(vec![BootstrapEndpoint {
            url: "udp://203.0.113.10:9443".to_string(),
            kind: BootstrapEndpointKind::Signal,
        }]);

        let error = match signal_base_urls(Some(&token), None) {
            Ok(_) => anyhow::bail!("non-HTTP signal bootstrap should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("signal bootstrap endpoint must use http or https"));
        Ok(())
    }

    #[test]
    fn signal_base_url_override_must_be_http() -> anyhow::Result<()> {
        let error = match signal_base_url(None, Some("udp://127.0.0.1:9443")) {
            Ok(_) => anyhow::bail!("non-HTTP signal override should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("signal URL must use http or https"));
        Ok(())
    }

    #[test]
    fn signal_base_url_override_rejects_unusable_numeric_host() -> anyhow::Result<()> {
        let error = match signal_base_url(None, Some("http://0.0.0.0:9443")) {
            Ok(_) => anyhow::bail!("unusable signal override should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("signal URL"));
        assert!(error.to_string().contains("usable non-unspecified"));
        Ok(())
    }

    #[tokio::test]
    async fn agent_stun_servers_merge_explicit_and_token_bootstraps() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["iparsd", "agent", "--stun-server", "203.0.113.9:3478"])?;
        let Command::Agent(args) = cli.command else {
            anyhow::bail!("expected agent command");
        };
        let token = token_with_bootstrap(vec![
            BootstrapEndpoint {
                url: "udp://203.0.113.9:3478".to_string(),
                kind: BootstrapEndpointKind::Stun,
            },
            BootstrapEndpoint {
                url: "udp://203.0.113.10:3478".to_string(),
                kind: BootstrapEndpointKind::Stun,
            },
            BootstrapEndpoint {
                url: "udp://203.0.113.11:3479".to_string(),
                kind: BootstrapEndpointKind::Stun,
            },
        ]);

        assert_eq!(
            agent_stun_servers(&args, Some(&token)).await?,
            vec![
                SocketAddr::from(([203, 0, 113, 9], 3478)),
                SocketAddr::from(([203, 0, 113, 10], 3478)),
                SocketAddr::from(([203, 0, 113, 11], 3479)),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn agent_stun_servers_reject_invalid_token_bootstraps() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["iparsd", "agent"])?;
        let Command::Agent(args) = cli.command else {
            anyhow::bail!("expected agent command");
        };
        let token = token_with_bootstrap(vec![BootstrapEndpoint {
            url: "https://203.0.113.10:3478".to_string(),
            kind: BootstrapEndpointKind::Stun,
        }]);

        let error = match agent_stun_servers(&args, Some(&token)).await {
            Ok(_) => anyhow::bail!("invalid STUN bootstrap should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("STUN bootstrap must use udp"));

        let unusable_token = token_with_bootstrap(vec![BootstrapEndpoint {
            url: "udp://0.0.0.0:3478".to_string(),
            kind: BootstrapEndpointKind::Stun,
        }]);
        let error = match agent_stun_servers(&args, Some(&unusable_token)).await {
            Ok(_) => anyhow::bail!("unusable STUN bootstrap should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("resolved to no usable socket addresses"));
        Ok(())
    }

    #[tokio::test]
    async fn agent_stun_servers_reject_unusable_explicit_servers() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["iparsd", "agent", "--stun-server", "0.0.0.0:3478"])?;
        let Command::Agent(args) = cli.command else {
            anyhow::bail!("expected agent command");
        };

        let error = match agent_stun_servers(&args, None).await {
            Ok(_) => anyhow::bail!("unusable explicit STUN server should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--stun-server"));
        assert!(error.to_string().contains("usable nonzero"));
        Ok(())
    }

    #[tokio::test]
    async fn signal_node_upsert_registers_with_available_signal_services() -> anyhow::Result<()> {
        let registry_a = Arc::new(SignalRegistry::new(ClusterPolicy::default()));
        let registry_b = Arc::new(SignalRegistry::new(ClusterPolicy::default()));
        let (base_a, task_a) = spawn_test_signal_service(registry_a.clone()).await?;
        let (base_b, task_b) = spawn_test_signal_service(registry_b.clone()).await?;
        let unavailable = unused_http_base_url().await?;
        let client = reqwest::Client::new();
        let node = node_record("node-a");
        let node_id = node.node_id.clone();
        let request = SignalNodeUpsertRequest {
            node,
            nat_classification: None,
            health: None,
        };

        let successes = send_signal_node_upsert_to_signal_services(
            &client,
            &[unavailable, base_a.clone(), base_b.clone()],
            request,
        )
        .await?;

        assert_eq!(successes, 2);
        assert!(registry_a.get_node(&node_id).await.is_some());
        assert!(registry_b.get_node(&node_id).await.is_some());
        task_a.abort();
        task_b.abort();
        Ok(())
    }

    #[tokio::test]
    async fn signal_path_request_fails_over_to_available_signal_service() -> anyhow::Result<()> {
        let registry = Arc::new(SignalRegistry::new(ClusterPolicy::default()));
        registry.upsert_node(node_record("node-a")).await?;
        registry.upsert_node(node_record("node-b")).await?;
        let (base, task) = spawn_test_signal_service(registry.clone()).await?;
        let unavailable = unused_http_base_url().await?;
        let client = reqwest::Client::new();
        let source = NodeId::from_string("node-a");
        let target = NodeId::from_string("node-b");
        let request = SignalPathRequest {
            source: source.clone(),
            target: target.clone(),
            source_candidates: vec![candidate("node-a", EndpointCandidateKind::PublicUdp, 10)],
            source_nat_classification: None,
            desired_routes: Vec::new(),
        };

        let (selected_signal, response) = send_signal_path_request_to_signal_services(
            &client,
            &[unavailable, base.clone()],
            request,
        )
        .await?;

        assert_eq!(selected_signal, base);
        assert_eq!(response.key, PeerPathKey::new(source, target));
        assert_eq!(registry.metrics().await.path_negotiation_count, 1);
        task.abort();
        Ok(())
    }

    #[test]
    fn control_plane_base_url_requires_url_or_bootstrap() {
        assert!(control_plane_base_url(None, None).is_err());
    }
}
