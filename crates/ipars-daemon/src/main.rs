use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use axum::Router;
use clap::{Args, Parser, Subcommand, ValueEnum};
use ipars_agent::{
    AgentError, AgentRuntime, FileAgentStateStore, KernelWireGuardBackend, LinuxCommandRunner,
    LinuxWireGuardBackend, MemoryWireGuardBackend, NamespacedLinuxCommandRunner, PeerMapApplier,
    PeerMapSink, PeerMapSource, PeerMapSync, RelayForwarderStats, RelaySessionState,
    RuntimePeerEndpointResolver, SystemCommandRunner, UdpHolePuncher, UdpRelayFrameForwarder,
    WireGuardBackend,
};
use ipars_agent_http::{router as agent_router, AgentHttpState};
use ipars_control_plane::{
    ControlPlane, ControlPlaneConfig, ControlPlaneJoinService, ControlPlaneStore, InMemoryStore,
    InMemoryTokenLedger, IssuerKeyRing, TokenLedger,
};
use ipars_control_plane_http::{router, ControlPlaneHttpState};
use ipars_relay::{RelayService, UdpRelay};
use ipars_relay_http::{router as relay_router, RelayHttpState};
use ipars_route_manager::{
    DockerNetworkIntent, DryRunLinuxRouteManager, KubernetesUnderlayIntent,
    LinuxNetlinkRouteManager, LinuxNetworkNamespace, LinuxRouteCommandRunner, LinuxRouteManager,
    NamespacedLinuxRouteCommandRunner, RouteManager, SystemRouteCommandRunner,
};
use ipars_signal::SignalRegistry;
use ipars_signal_http::{router as signal_router, SignalHttpState};
use ipars_store::{PostgresControlPlaneStore, SqliteControlPlaneStore};
use ipars_stun::BindingStunServer;
use ipars_types::api::{
    AgentMetricsResponse, AgentPacketFlowObservation, AgentRelayForwarderMetrics,
    ControlPlaneMetricsResponse, HeartbeatRequest, HeartbeatResponse, JoinNodeRequest, PeerMap,
    RegisterNodeRequest, RegisterNodeResponse, RelayAdmissionRequest, RelayAdmissionResponse,
    RelayDataplaneMetrics, RelayStatusResponse, SignalHolePunchPlanResponse, SignalMetricsResponse,
    SignalNodeUpsertRequest, SignalNodeUpsertResponse, SignalPathRequest, SignalPathResponse,
};
use ipars_types::{
    AclRule, BootstrapEndpointKind, ClusterId, ClusterPolicy, EndpointCandidate, HealthState,
    KeyId, NodeHealth, NodeId, NodeRecord, PathRecord, PathState, RelayCapability, SignedJoinToken,
    TransportProtocol,
};
use netlink_sys::{protocols::NETLINK_NETFILTER, Socket, SocketAddr as NetlinkSocketAddr};
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
use serde::Deserialize;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Layer};

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
    #[arg(long, env = "IPARS_RELAY_ADMISSION_URL")]
    admission_url: Option<String>,
    #[arg(long, env = "IPARS_RELAY_MAX_SESSIONS", default_value_t = 10_000)]
    max_sessions: u32,
    #[arg(long, env = "IPARS_RELAY_MAX_MBPS", default_value_t = 1000)]
    max_mbps: u32,
    #[arg(long, env = "IPARS_RELAY_SESSION_TTL_SECONDS", default_value_t = 300)]
    session_ttl_seconds: u64,
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
    #[arg(
        long,
        env = "IPARS_AGENT_PACKET_FLOW_POLL_INTERVAL_SECONDS",
        default_value_t = 5
    )]
    packet_flow_poll_interval_seconds: u64,
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
        default_value_t = true
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
}

impl WireGuardApplyBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::KernelNetlink => "kernel-netlink",
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
}

impl PacketFlowDetector {
    fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ProcNetConntrack => "proc-net-conntrack",
            Self::ConntrackNetlink => "conntrack-netlink",
            Self::ConntrackNetlinkEvents => "conntrack-netlink-events",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimePreflightNeeds {
    ip_command: bool,
    wg_command: bool,
    cap_net_admin: bool,
    cap_sys_admin: bool,
    linux_netns: bool,
}

impl RuntimePreflightNeeds {
    fn none() -> Self {
        Self {
            ip_command: false,
            wg_command: false,
            cap_net_admin: false,
            cap_sys_admin: false,
            linux_netns: false,
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
    validate_linux_interface_name(&args.wireguard_interface)?;
    if let Some(namespace) = args.linux_netns.as_deref() {
        LinuxNetworkNamespace::from_name(namespace)?;
    }
    if args.skip_runtime_preflight {
        tracing::warn!(
            backend = args.runtime_backend.as_str(),
            "skipping runtime backend preflight by operator request"
        );
        return Ok(());
    }

    let needs = runtime_preflight_needs(args);
    if !needs.ip_command
        && !needs.wg_command
        && !needs.cap_net_admin
        && !needs.cap_sys_admin
        && !needs.linux_netns
    {
        return Ok(());
    }
    if needs.ip_command {
        ensure_program_in_path("ip", path)?;
    }
    if needs.wg_command {
        ensure_program_in_path("wg", path)?;
    }
    if needs.cap_net_admin {
        ensure_cap_net_admin_if_known()?;
    }
    if needs.cap_sys_admin {
        ensure_cap_sys_admin_if_known()?;
    }
    if needs.linux_netns {
        let namespace_name = args
            .linux_netns
            .as_deref()
            .context("linux namespace preflight requested without --linux-netns")?;
        let namespace = LinuxNetworkNamespace::from_name(namespace_name)?;
        ensure_linux_netns_ready(&namespace)?;
    }

    tracing::info!(
        backend = args.runtime_backend.as_str(),
        wireguard_backend = args.wireguard_backend.as_str(),
        route_backend = args.route_backend.as_str(),
        needs_ip = needs.ip_command,
        needs_wg = needs.wg_command,
        needs_cap_net_admin = needs.cap_net_admin,
        needs_cap_sys_admin = needs.cap_sys_admin,
        linux_netns = ?args.linux_netns,
        "runtime backend preflight passed"
    );
    Ok(())
}

fn runtime_preflight_needs(args: &AgentArgs) -> RuntimePreflightNeeds {
    if args.runtime_backend != AgentRuntimeBackend::LinuxCommand {
        return RuntimePreflightNeeds::none();
    }
    let applies_routes =
        args.apply_peer_map || args.apply_docker_routes || args.apply_kubernetes_underlay;
    let applies_wireguard = args.apply_peer_map;
    let applies_routes_with_command =
        applies_routes && args.route_backend == RouteApplyBackend::Command;
    let applies_wireguard_with_command =
        applies_wireguard && args.wireguard_backend == WireGuardApplyBackend::Command;
    RuntimePreflightNeeds {
        ip_command: applies_routes_with_command || applies_wireguard_with_command,
        wg_command: applies_wireguard_with_command,
        cap_net_admin: applies_routes || applies_wireguard,
        cap_sys_admin: args.linux_netns.is_some() && (applies_routes || applies_wireguard),
        linux_netns: args.linux_netns.is_some() && (applies_routes || applies_wireguard),
    }
}

fn validate_linux_interface_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("linux interface name cannot be empty");
    }
    if name.len() > 15 {
        anyhow::bail!("linux interface name `{name}` exceeds 15 bytes");
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

fn ensure_program_in_path(program: &str, path: Option<&OsStr>) -> anyhow::Result<()> {
    if program_exists_in_path(program, path) {
        Ok(())
    } else {
        anyhow::bail!("missing required Linux runtime command `{program}` in PATH");
    }
}

fn program_exists_in_path(program: &str, path: Option<&OsStr>) -> bool {
    let Some(path) = path else {
        return false;
    };
    std::env::split_paths(path).any(|directory| is_executable_file(&directory.join(program)))
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.metadata()
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn ensure_cap_net_admin_if_known() -> anyhow::Result<()> {
    if let Some(false) = process_has_capability(12)? {
        anyhow::bail!("linux-command runtime backend requires CAP_NET_ADMIN");
    }
    Ok(())
}

fn ensure_cap_sys_admin_if_known() -> anyhow::Result<()> {
    if let Some(false) = process_has_capability(21)? {
        anyhow::bail!(
            "linux network namespace runtime backend requires CAP_SYS_ADMIN for setns/ip netns exec"
        );
    }
    Ok(())
}

fn process_has_capability(bit: u8) -> anyhow::Result<Option<bool>> {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(status) => status,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let cap_eff = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(str::trim);
    let Some(cap_eff) = cap_eff else {
        return Ok(None);
    };
    let mask = u64::from_str_radix(cap_eff, 16)
        .with_context(|| format!("failed to parse CapEff from /proc/self/status: {cap_eff}"))?;
    Ok(Some(mask & (1_u64 << bit) != 0))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxNetnsPathReport {
    same_as_current: Option<bool>,
}

fn ensure_linux_netns_ready(namespace: &LinuxNetworkNamespace) -> anyhow::Result<()> {
    let path = Path::new("/var/run/netns").join(namespace.name());
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
    let _observability = init_observability(&cli.observability, component)?;
    let otel_metrics_enabled = cli.observability.otel_active();
    let otel_metrics_interval =
        Duration::from_secs(cli.observability.otel_metrics_poll_interval_seconds.max(1));
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
        Command::Stun(args) => run_stun(args).await,
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
    let mut config =
        ControlPlaneConfig::new(ClusterId::from_string(args.cluster_id), args.vpn_pool);
    config.cluster_policy.relay_health_ttl_seconds = args.relay_health_ttl_seconds;
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
    let policy = ClusterPolicy {
        allow_ipv6_direct: !args.disable_ipv6_direct,
        allow_nat_traversal: !args.disable_nat_traversal,
        allow_relay_fallback: !args.disable_relay_fallback,
        idle_timeout_seconds: args.idle_timeout_seconds,
        relay_health_ttl_seconds: args.relay_health_ttl_seconds,
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

async fn run_stun(args: StunArgs) -> anyhow::Result<()> {
    let server = BindingStunServer::bind(args.listen).await?;
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

#[derive(Debug)]
struct ControlPlaneOtelMetrics {
    nodes: Gauge<u64>,
    relay_candidates: Gauge<u64>,
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
        self.nodes.record(metrics.node_count as u64, &cluster_attrs);
        self.relay_candidates
            .record(metrics.relay_candidate_count as u64, &cluster_attrs);
        self.paths.record(metrics.path_count as u64, &cluster_attrs);

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

fn start_control_plane_otel_metrics_export<S>(
    plane: Arc<ControlPlane<S>>,
    interval: Duration,
) -> tokio::task::JoinHandle<()>
where
    S: ControlPlaneStore + 'static,
{
    tokio::spawn(async move {
        let metrics = ControlPlaneOtelMetrics::new();
        loop {
            match plane.metrics().await {
                Ok(status) => metrics.record_status(&status),
                Err(error) => {
                    tracing::warn!(%error, "failed to collect control-plane OTLP metrics")
                }
            }
            tokio::time::sleep(interval).await;
        }
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SignalOtelSnapshot {
    node_upsert_count: u64,
    path_negotiation_count: u64,
    hole_punch_plan_count: u64,
}

impl From<&SignalMetricsResponse> for SignalOtelSnapshot {
    fn from(metrics: &SignalMetricsResponse) -> Self {
        Self {
            node_upsert_count: metrics.node_upsert_count,
            path_negotiation_count: metrics.path_negotiation_count,
            hole_punch_plan_count: metrics.hole_punch_plan_count,
        }
    }
}

#[derive(Debug)]
struct SignalOtelMetrics {
    nodes: Gauge<u64>,
    relay_candidates: Gauge<u64>,
    nat_classifications: Gauge<u64>,
    health_reports: Gauge<u64>,
    stale_health_reports: Gauge<u64>,
    relay_health_ttl_seconds: Gauge<u64>,
    node_upserts: Counter<u64>,
    path_negotiations: Counter<u64>,
    hole_punch_plans: Counter<u64>,
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
            node_upserts: meter
                .u64_counter("ipars.signal.node_upserts")
                .with_description("Signal node upsert requests handled.")
                .build(),
            path_negotiations: meter
                .u64_counter("ipars.signal.path_negotiations")
                .with_description("Signal path negotiation requests handled.")
                .build(),
            hole_punch_plans: meter
                .u64_counter("ipars.signal.hole_punch_plans")
                .with_description("Signal hole-punch plan requests handled.")
                .build(),
        }
    }

    fn record_status(
        &self,
        metrics: &SignalMetricsResponse,
        previous: Option<&SignalOtelSnapshot>,
    ) {
        self.nodes.record(metrics.node_count as u64, &[]);
        self.relay_candidates
            .record(metrics.relay_candidate_count as u64, &[]);
        self.nat_classifications
            .record(metrics.nat_classification_count as u64, &[]);
        self.stale_health_reports
            .record(metrics.stale_health_report_count as u64, &[]);
        self.relay_health_ttl_seconds
            .record(metrics.relay_health_ttl_seconds, &[]);

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
        self.hole_punch_plans.add(
            counter_delta(
                metrics.hole_punch_plan_count,
                previous.map(|previous| previous.hole_punch_plan_count),
            ),
            &[],
        );
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RelayOtelSnapshot {
    dataplane: RelayDataplaneMetrics,
}

impl From<&RelayStatusResponse> for RelayOtelSnapshot {
    fn from(status: &RelayStatusResponse) -> Self {
        Self {
            dataplane: status.dataplane.clone(),
        }
    }
}

#[derive(Debug)]
struct RelayOtelMetrics {
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
    max_mbps: Gauge<u64>,
    enabled_by_policy: Gauge<u64>,
    health: Gauge<u64>,
}

impl RelayOtelMetrics {
    fn new() -> Self {
        let meter = global::meter("iparsd.relay");
        Self {
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
            max_mbps: meter
                .u64_gauge("ipars.relay.max_mbps")
                .with_description("Configured relay throughput budget.")
                .with_unit("Mbit/s")
                .build(),
            enabled_by_policy: meter
                .u64_gauge("ipars.relay.enabled_by_policy")
                .with_description("Whether relay admission is enabled by policy.")
                .build(),
            health: meter
                .u64_gauge("ipars.relay.health")
                .with_description("Relay health state as a labeled gauge.")
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
        self.max_mbps
            .record(status.capability.max_mbps as u64, &relay_attrs);
        self.enabled_by_policy
            .record(u64::from(status.capability.enabled_by_policy), &relay_attrs);
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
    for (reason, current_count) in &current.drops_by_reason {
        let previous_count = previous
            .and_then(|previous| previous.drops_by_reason.get(reason))
            .copied()
            .unwrap_or(0);
        let delta = current_count.saturating_sub(previous_count);
        if delta > 0 {
            drops_by_reason.insert(*reason, delta);
        }
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

fn counter_delta(current: u64, previous: Option<u64>) -> u64 {
    current.saturating_sub(previous.unwrap_or(0))
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
    peer_activity_record_count: u64,
    packet_flow_observation_count: u64,
    packet_flow_match_count: u64,
    packet_flow_unmatched_count: u64,
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
            peer_activity_record_count: metrics.peer_activity_record_count,
            packet_flow_observation_count: metrics.packet_flow_observation_count,
            packet_flow_match_count: metrics.packet_flow_match_count,
            packet_flow_unmatched_count: metrics.packet_flow_unmatched_count,
        }
    }
}

#[derive(Debug)]
struct AgentOtelMetrics {
    candidates: Gauge<u64>,
    paths: Gauge<u64>,
    paths_by_state: Gauge<u64>,
    relay_sessions: Gauge<u64>,
    relay_forwarders: Gauge<u64>,
    path_change_events: Gauge<u64>,
    lazy_active_peers: Gauge<u64>,
    lazy_pinned_peers: Gauge<u64>,
    lazy_observed_peer_vpn_ips: Gauge<u64>,
    lazy_observed_route_peers: Gauge<u64>,
    lazy_observed_routes: Gauge<u64>,
    relay_admission_attempts: Counter<u64>,
    relay_admission_success: Counter<u64>,
    relay_admission_failures: Counter<u64>,
    peer_activity_records: Counter<u64>,
    packet_flow_observations: Counter<u64>,
    packet_flow_matches: Counter<u64>,
    packet_flow_unmatched: Counter<u64>,
    forwarder_outbound_packets: Counter<u64>,
    forwarder_outbound_payload_bytes: Counter<u64>,
    forwarder_outbound_datagram_bytes: Counter<u64>,
    forwarder_inbound_packets: Counter<u64>,
    forwarder_inbound_payload_bytes: Counter<u64>,
}

impl AgentOtelMetrics {
    fn new() -> Self {
        let meter = global::meter("iparsd.agent");
        Self {
            candidates: meter
                .u64_gauge("ipars.agent.candidates")
                .with_description("Endpoint candidates currently known by the agent.")
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
            path_change_events: meter
                .u64_gauge("ipars.agent.path_change_events")
                .with_description("Retained path change events.")
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
            forwarder_outbound_packets: meter
                .u64_counter("ipars.agent.relay.forwarder.outbound.packets")
                .with_description("Relay forwarder packets sent from local WireGuard to relay.")
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
        }
    }

    fn record_status(&self, metrics: &AgentMetricsResponse, previous: Option<&AgentOtelSnapshot>) {
        let node_id = metrics.node_id.as_str().to_string();
        let node_attrs = [KeyValue::new("node_id", node_id.clone())];
        self.candidates
            .record(metrics.candidate_count as u64, &node_attrs);
        self.paths.record(metrics.path_count as u64, &node_attrs);
        self.relay_sessions
            .record(metrics.relay_session_count as u64, &node_attrs);
        self.relay_forwarders
            .record(metrics.relay_forwarder_count as u64, &node_attrs);
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
            self.forwarder_outbound_packets
                .add(forwarder.outbound_packets, &attrs);
            self.forwarder_outbound_payload_bytes
                .add(forwarder.outbound_payload_bytes, &attrs);
            self.forwarder_outbound_datagram_bytes
                .add(forwarder.outbound_datagram_bytes, &attrs);
            self.forwarder_inbound_packets
                .add(forwarder.inbound_packets, &attrs);
            self.forwarder_inbound_payload_bytes
                .add(forwarder.inbound_payload_bytes, &attrs);
        }
    }
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
        inbound_packets: counter_delta(
            current.inbound_packets,
            previous.map(|previous| previous.inbound_packets),
        ),
        inbound_payload_bytes: counter_delta(
            current.inbound_payload_bytes,
            previous.map(|previous| previous.inbound_payload_bytes),
        ),
        last_forwarded_at: current.last_forwarded_at,
    }
}

fn has_agent_forwarder_delta(delta: &AgentRelayForwarderMetrics) -> bool {
    delta.outbound_packets > 0
        || delta.outbound_payload_bytes > 0
        || delta.outbound_datagram_bytes > 0
        || delta.inbound_packets > 0
        || delta.inbound_payload_bytes > 0
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
    let udp_relay = UdpRelay::bind(args.udp_listen).await?;
    let udp_addr = udp_relay.local_addr()?;
    let public_endpoint = args.public_endpoint.unwrap_or(udp_addr);
    let admission_url = args
        .admission_url
        .clone()
        .unwrap_or_else(|| format!("http://{}", args.http_listen));
    let service = Arc::new(RelayService::with_session_ttl(
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
        chrono::Duration::seconds(args.session_ttl_seconds.max(1) as i64),
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
    let http_result =
        serve_router(args.http_listen, relay_router(RelayHttpState::new(service))).await;
    udp_task.abort();
    if let Some(task) = otel_metrics_task {
        task.abort();
    }
    http_result
}

async fn run_agent(
    args: AgentArgs,
    otel_metrics_enabled: bool,
    otel_metrics_interval: Duration,
) -> anyhow::Result<()> {
    let store = FileAgentStateStore::new(args.state_path.clone());
    let state = store.load_or_create(chrono::Utc::now())?;
    let runtime = Arc::new(AgentRuntime::new(state, ClusterPolicy::default()));
    let relay_capability_reporter = agent_relay_capability_reporter(&args);
    let relay_capability = relay_capability_reporter
        .as_ref()
        .map(|reporter| reporter.advertised.clone());
    if args.stun_servers.len() > 1 {
        runtime
            .classify_nat(args.stun_bind, args.stun_servers.clone())
            .await?;
    } else if let Some(stun_server) = args.stun_servers.first().copied() {
        runtime.probe_stun(args.stun_bind, stun_server).await?;
    }
    let join_token = agent_join_token(&args)?;
    let mut registered_control_plane_base = None;
    let registered_node = if let Some(token) = &join_token {
        let registration = register_agent(
            runtime.as_ref(),
            token,
            args.control_plane_url.as_deref(),
            relay_capability.clone(),
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
    let relay_forwarder_supervisor = relay_forwarder_supervisor(&args)?;
    let mut background_tasks = Vec::new();
    if otel_metrics_enabled {
        background_tasks.push(start_agent_otel_metrics_export(
            runtime.clone(),
            otel_metrics_interval.max(Duration::from_secs(1)),
        ));
    }
    if !args.disable_heartbeat && !control_plane_bases.is_empty() {
        background_tasks.push(start_heartbeat_reporting(
            runtime.clone(),
            control_plane_bases.clone(),
            Duration::from_secs(args.heartbeat_interval_seconds.max(1)),
            relay_capability_reporter.clone(),
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
            tracing::info!(
                detector = args.packet_flow_detector.as_str(),
                conntrack_path = ?args.packet_flow_conntrack_path,
                interval_seconds = args.packet_flow_poll_interval_seconds.max(1),
                pin = args.packet_flow_pin,
                "starting packet-flow detector"
            );
            background_tasks.push(start_proc_net_conntrack_packet_flow_detector(
                runtime.clone(),
                conntrack_paths(args.packet_flow_conntrack_path.clone()),
                Duration::from_secs(args.packet_flow_poll_interval_seconds.max(1)),
                args.packet_flow_pin,
            ));
        }
        PacketFlowDetector::ConntrackNetlink => {
            tracing::info!(
                detector = args.packet_flow_detector.as_str(),
                interval_seconds = args.packet_flow_poll_interval_seconds.max(1),
                pin = args.packet_flow_pin,
                "starting packet-flow detector"
            );
            background_tasks.push(start_conntrack_netlink_packet_flow_detector(
                runtime.clone(),
                Duration::from_secs(args.packet_flow_poll_interval_seconds.max(1)),
                args.packet_flow_pin,
            ));
        }
        PacketFlowDetector::ConntrackNetlinkEvents => {
            tracing::info!(
                detector = args.packet_flow_detector.as_str(),
                idle_poll_interval_seconds = args.packet_flow_poll_interval_seconds.max(1),
                pin = args.packet_flow_pin,
                "starting packet-flow detector"
            );
            background_tasks.push(start_conntrack_netlink_event_packet_flow_detector(
                runtime.clone(),
                Duration::from_secs(args.packet_flow_poll_interval_seconds.max(1)),
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
                Duration::from_secs(args.signal_registration_interval_seconds.max(1)),
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
                control_plane_bases,
                signal_bases,
                hole_puncher,
                relay_forwarder_supervisor.clone(),
                Duration::from_secs(args.relay_session_renew_before_seconds.max(1)),
                Duration::from_secs(args.signal_path_interval_seconds.max(1)),
            ));
        }
    }
    tracing::info!(node_id = %runtime.state().node_id, listen = %args.listen, "agent listening");
    let result = serve_router(
        args.listen,
        agent_router(AgentHttpState::new(runtime.clone())),
    )
    .await;
    for task in background_tasks {
        task.abort();
    }
    if let Some(supervisor) = relay_forwarder_supervisor {
        supervisor.shutdown_all(runtime.as_ref()).await;
    }
    result
}

async fn start_peer_map_sync(
    args: &AgentArgs,
    runtime: Arc<AgentRuntime>,
    control_plane_urls: Vec<String>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
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
                        NamespacedLinuxCommandRunner::new(namespace.clone(), SystemCommandRunner),
                        NamespacedLinuxRouteCommandRunner::new(namespace, SystemRouteCommandRunner),
                    )
                    .await
                }
                (WireGuardApplyBackend::Command, RouteApplyBackend::Command, None) => {
                    start_peer_map_sync_with_runners(
                        args,
                        runtime,
                        control_plane_urls,
                        SystemCommandRunner,
                        SystemRouteCommandRunner,
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
                        NamespacedLinuxCommandRunner::new(namespace.clone(), SystemCommandRunner),
                        Some(namespace),
                    )
                    .await
                }
                (WireGuardApplyBackend::Command, RouteApplyBackend::KernelNetlink, None) => {
                    start_peer_map_sync_with_command_wireguard_netlink_routes(
                        args,
                        runtime,
                        control_plane_urls,
                        SystemCommandRunner,
                        None,
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
                            SystemRouteCommandRunner,
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
                        SystemRouteCommandRunner,
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
        let socket = docker_api_socket_path(args);
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
        let networks: Vec<DockerApiNetwork> = self
            .client
            .get(docker_api_networks_url(&self.api_version))
            .send()
            .await
            .context("failed to query Docker networks")?
            .error_for_status()
            .context("Docker networks API returned an error")?
            .json()
            .await
            .context("failed to decode Docker networks response")?;
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

fn docker_route_source(args: &AgentArgs) -> anyhow::Result<DockerRouteSource> {
    if args.docker_discover_networks {
        Ok(DockerRouteSource::Api(DockerApiNetworkDiscovery::new(
            args,
        )?))
    } else {
        Ok(DockerRouteSource::Explicit(docker_network_intent(args)?))
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

fn docker_api_socket_path(args: &AgentArgs) -> PathBuf {
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
) -> PathBuf {
    if let Some(configured) = configured {
        return configured.to_path_buf();
    }
    if let Some(path) = docker_host.and_then(docker_host_unix_socket_path) {
        return path;
    }

    let rootful = PathBuf::from("/var/run/docker.sock");
    if exists(&rootful) {
        return rootful;
    }

    if let Some(runtime_dir) = xdg_runtime_dir {
        let rootless = PathBuf::from(runtime_dir).join("docker.sock");
        if exists(&rootless) {
            return rootless;
        }
    }

    rootful
}

fn docker_host_unix_socket_path(docker_host: &OsStr) -> Option<PathBuf> {
    let docker_host = docker_host.to_str()?;
    docker_host
        .strip_prefix("unix://")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn docker_discovered_routes(
    networks: &[DockerApiNetwork],
    filters: &[String],
) -> anyhow::Result<DockerDiscoveredRoutes> {
    let mut network_names = Vec::new();
    let mut cidrs = BTreeMap::<ipnet::IpNet, String>::new();
    for network in networks {
        if !docker_network_matches(network, filters) {
            continue;
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
            cidrs.entry(cidr).or_insert_with(|| network.name.clone());
            found_subnet = true;
        }
        if found_subnet {
            network_names.push(network.name.clone());
        }
    }
    if cidrs.is_empty() {
        anyhow::bail!("Docker network discovery found no bridge networks with IPAM subnets");
    }
    Ok(DockerDiscoveredRoutes {
        network_names,
        cidrs: cidrs.into_keys().collect(),
    })
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

fn docker_namespace_from_networks(network_names: &[String]) -> String {
    if network_names.is_empty() {
        return "docker-api".to_string();
    }
    let joined = network_names.join("+");
    format!("docker:{joined}")
}

async fn start_docker_routes(args: &AgentArgs) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let source = docker_route_source(args)?;
    let interval = Duration::from_secs(args.docker_route_interval_seconds.max(1));
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
                                SystemRouteCommandRunner,
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
                        let manager = LinuxRouteManager::new(SystemRouteCommandRunner);
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
    loop {
        match source.resolve_intent().await {
            Ok(intent) => match manager.apply_docker_intent(intent.clone()).await {
                Ok(plan) => tracing::info!(
                    route_source = source.source_label(),
                    container_namespace = %intent.container_namespace,
                    host_interface = %intent.host_interface,
                    routes = plan.routes.len(),
                    policy_rules = plan.policy_rules.len(),
                    "applied Docker overlay routes"
                ),
                Err(error) => tracing::warn!(
                    %error,
                    route_source = source.source_label(),
                    container_namespace = %intent.container_namespace,
                    "failed to apply Docker overlay routes; will retry"
                ),
            },
            Err(error) => tracing::warn!(
                %error,
                route_source = source.source_label(),
                "failed to resolve Docker overlay routes; will retry"
            ),
        }
        tokio::time::sleep(interval).await;
    }
}

async fn start_kubernetes_underlay_routes(
    args: &AgentArgs,
    local_node_id: NodeId,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let source = kubernetes_route_source(args, local_node_id)?;
    let interval = Duration::from_secs(args.kubernetes_route_interval_seconds.max(1));
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
                                SystemRouteCommandRunner,
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
                        let manager = LinuxRouteManager::new(SystemRouteCommandRunner);
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
        let token = std::fs::read_to_string(&args.kubernetes_service_account_token_path)
            .with_context(|| {
                format!(
                    "failed to read Kubernetes service account token from {}",
                    args.kubernetes_service_account_token_path.display()
                )
            })?;
        let token = token.trim();
        if token.is_empty() {
            anyhow::bail!(
                "Kubernetes service account token at {} is empty",
                args.kubernetes_service_account_token_path.display()
            );
        }
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
            let ca = std::fs::read(ca_cert_path).with_context(|| {
                format!(
                    "failed to read Kubernetes CA certificate from {}",
                    ca_cert_path.display()
                )
            })?;
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
        request
            .send()
            .await
            .context("failed to query Kubernetes services")?
            .error_for_status()
            .context("Kubernetes services API returned an error")?
            .json()
            .await
            .context("failed to decode Kubernetes services response")
    }
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
        return Ok(configured.trim_end_matches('/').to_string());
    }
    let host = service_host
        .and_then(OsStr::to_str)
        .filter(|host| !host.is_empty())
        .context("--kubernetes-discover-services requires --kubernetes-api-url or KUBERNETES_SERVICE_HOST")?;
    let port = service_port
        .and_then(OsStr::to_str)
        .filter(|port| !port.is_empty())
        .unwrap_or("443");
    let host = match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) if !host.starts_with('[') => format!("[{host}]"),
        _ => host.to_string(),
    };
    Ok(format!("https://{host}:{port}"))
}

fn default_kubernetes_service_account_ca_cert() -> Option<PathBuf> {
    let path = PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt");
    path.exists().then_some(path)
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
    if args.kubernetes_api_server_cidrs.is_empty() && args.kubernetes_service_cidrs.is_empty() {
        anyhow::bail!(
            "--apply-kubernetes-underlay requires at least one --kubernetes-api-server-cidr or --kubernetes-service-cidr"
        );
    }
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
        api_server_cidrs: args.kubernetes_api_server_cidrs.clone(),
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
    loop {
        match source.resolve_intent().await {
            Ok(intent) => match manager.apply_kubernetes_intent(intent.clone()).await {
                Ok(plan) => tracing::info!(
                    route_source = source.source_label(),
                    node_name = %intent.node_name,
                    route_provider = %intent.route_provider,
                    routes = plan.routes.len(),
                    policy_rules = plan.policy_rules.len(),
                    "applied Kubernetes underlay routes"
                ),
                Err(error) => tracing::warn!(
                    %error,
                    route_source = source.source_label(),
                    node_name = %intent.node_name,
                    "failed to apply Kubernetes underlay routes; will retry"
                ),
            },
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
    let interval = Duration::from_secs(args.peer_map_poll_interval_seconds.max(1));
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
    use std::os::unix::fs::MetadataExt;

    let current = std::fs::metadata("/proc/self/ns/net")
        .context("failed to inspect current network namespace")?;
    let target_path = netns_path(namespace);
    let target = std::fs::metadata(&target_path).with_context(|| {
        format!(
            "failed to inspect network namespace {}; run the agent inside it or create {}",
            namespace.name(),
            target_path.display()
        )
    })?;
    if current.dev() == target.dev() && current.ino() == target.ino() {
        return Ok(());
    }
    anyhow::bail!(
        "relay forwarder requires process network namespace {}; current process is in a different namespace",
        namespace.name()
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
    Path::new("/var/run/netns").join(namespace.name())
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
            requested_routes: Vec::new(),
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
        match response.json().await {
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
    control_plane_urls: Vec<String>,
    interval: Duration,
    relay_capability_reporter: Option<RelayCapabilityReporter>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_heartbeat_loop(
            runtime,
            control_plane_urls,
            interval,
            relay_capability_reporter,
        )
        .await;
    })
}

async fn run_heartbeat_loop(
    runtime: Arc<AgentRuntime>,
    control_plane_urls: Vec<String>,
    interval: Duration,
    relay_capability_reporter: Option<RelayCapabilityReporter>,
) {
    let client = reqwest::Client::new();
    loop {
        let relay_capability =
            heartbeat_relay_capability(&client, relay_capability_reporter.as_ref()).await;
        let request = heartbeat_request(runtime.as_ref(), relay_capability.clone()).await;
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
    client
        .post(heartbeat_url(control_plane_url))
        .json(&request)
        .send()
        .await
        .context("failed to send heartbeat request")?
        .error_for_status()
        .context("control plane rejected heartbeat request")?
        .json()
        .await
        .context("failed to decode heartbeat response")
}

async fn heartbeat_request(
    runtime: &AgentRuntime,
    relay_capability: Option<RelayCapability>,
) -> HeartbeatRequest {
    let status = runtime.status().await;
    let path_state = runtime.path_state().await;
    HeartbeatRequest {
        node_id: status.node_id,
        health: NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: chrono::Utc::now(),
            latency_ms: None,
            relay_load: None,
            message: Some("agent heartbeat".to_string()),
        },
        candidates: status.candidates,
        relay_capability,
        path_state,
    }
}

fn start_signal_registration(
    runtime: Arc<AgentRuntime>,
    node: NodeRecord,
    signal_urls: Vec<String>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_signal_registration_loop(runtime, node, signal_urls, interval).await;
    })
}

async fn run_signal_registration_loop(
    runtime: Arc<AgentRuntime>,
    node: NodeRecord,
    signal_urls: Vec<String>,
    interval: Duration,
) {
    let client = reqwest::Client::new();
    loop {
        let request = signal_node_upsert_request(runtime.as_ref(), node.clone()).await;
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
    client
        .put(signal_node_url(signal_url, &request.node.node_id))
        .json(&request)
        .send()
        .await
        .context("failed to send signal node upsert")?
        .error_for_status()
        .context("signal service rejected node upsert")?
        .json()
        .await
        .context("failed to decode signal node upsert response")
}

async fn signal_node_upsert_request(
    runtime: &AgentRuntime,
    mut node: NodeRecord,
) -> SignalNodeUpsertRequest {
    let status = runtime.status().await;
    node.endpoint_candidates = status.candidates;
    SignalNodeUpsertRequest {
        node,
        nat_classification: status.nat_classification,
        health: Some(NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: chrono::Utc::now(),
            latency_ms: None,
            relay_load: None,
            message: Some("agent signal registration".to_string()),
        }),
    }
}

fn start_signal_path_negotiation(
    runtime: Arc<AgentRuntime>,
    control_plane_urls: Vec<String>,
    signal_urls: Vec<String>,
    hole_puncher: UdpHolePuncher,
    relay_forwarder_supervisor: Option<Arc<RelayForwarderSupervisor>>,
    relay_session_renew_before: Duration,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_signal_path_negotiation_loop(
            runtime,
            control_plane_urls,
            signal_urls,
            hole_puncher,
            relay_forwarder_supervisor,
            relay_session_renew_before,
            interval,
        )
        .await;
    })
}

async fn run_signal_path_negotiation_loop(
    runtime: Arc<AgentRuntime>,
    control_plane_urls: Vec<String>,
    signal_urls: Vec<String>,
    hole_puncher: UdpHolePuncher,
    relay_forwarder_supervisor: Option<Arc<RelayForwarderSupervisor>>,
    relay_session_renew_before: Duration,
    interval: Duration,
) {
    let client = reqwest::Client::new();
    loop {
        if let Err(error) = negotiate_signal_paths(
            &client,
            runtime.as_ref(),
            &control_plane_urls,
            &signal_urls,
            &hole_puncher,
            relay_forwarder_supervisor.as_ref(),
            relay_session_renew_before,
        )
        .await
        {
            tracing::warn!(%error, "failed to negotiate signal paths; will retry");
        }
        tokio::time::sleep(interval).await;
    }
}

async fn negotiate_signal_paths(
    client: &reqwest::Client,
    runtime: &AgentRuntime,
    control_plane_urls: &[String],
    signal_urls: &[String],
    hole_puncher: &UdpHolePuncher,
    relay_forwarder_supervisor: Option<&Arc<RelayForwarderSupervisor>>,
    relay_session_renew_before: Duration,
) -> anyhow::Result<()> {
    let status = runtime.status().await;
    let peer_map = fetch_peer_map_from_control_planes(client, control_plane_urls, &status.node_id)
        .await
        .context("failed to fetch peer map for signal negotiation")?;

    let peer_set = signal_negotiation_peer_set(runtime, peer_map).await;
    for peer in peer_set.skipped {
        remove_relay_session_for_peer(
            runtime,
            relay_forwarder_supervisor,
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
        let relay_candidates = selected_relay_candidates(&response);
        let record = signal_path_record(response, chrono::Utc::now());
        if record.selected_state == PathState::DirectNatTraversal {
            match fetch_hole_punch_plan(client, &signal_url, &record.key).await {
                Ok(plan) => match hole_puncher.execute(&status.node_id, &plan).await {
                    Ok(attempts) => tracing::info!(
                        attempts,
                        peer = %record.key.remote,
                        "executed UDP hole punch plan"
                    ),
                    Err(error) => tracing::warn!(
                        %error,
                        peer = %record.key.remote,
                        "failed to execute UDP hole punch plan"
                    ),
                },
                Err(error) => tracing::warn!(
                    %error,
                    peer = %record.key.remote,
                    "failed to fetch UDP hole punch plan"
                ),
            }
        }
        if record.selected_state == PathState::Relay {
            match relay_candidates.first() {
                Some(preferred_relay) => {
                    if relay_session_needs_renewal(
                        runtime,
                        &peer.node_id,
                        &preferred_relay.node_id,
                        relay_session_renew_before,
                    )
                    .await
                    {
                        match admit_relay_session_from_candidates(
                            client,
                            runtime,
                            &status,
                            &peer,
                            &relay_candidates,
                        )
                        .await
                        {
                            Ok(session) => {
                                tracing::info!(
                                    peer = %record.key.remote,
                                    relay = %session.relay_node,
                                    expires_at = %session.expires_at,
                                    "admitted relay session"
                                );
                                runtime.upsert_relay_session(session.clone()).await;
                                if let Some(supervisor) = relay_forwarder_supervisor {
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
                                if let Some(supervisor) = relay_forwarder_supervisor {
                                    supervisor.remove(runtime, &peer.node_id).await;
                                } else {
                                    runtime.remove_relay_forwarder_endpoint(&peer.node_id).await;
                                }
                                tracing::warn!(
                                    %error,
                                    peer = %record.key.remote,
                                    "failed to admit relay session"
                                );
                            }
                        }
                    } else {
                        tracing::debug!(
                            peer = %record.key.remote,
                            relay = %preferred_relay.node_id,
                            "reusing existing relay session"
                        );
                        if let Some(supervisor) = relay_forwarder_supervisor {
                            if let Some(session) = runtime.relay_session(&peer.node_id).await {
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
                    if let Some(supervisor) = relay_forwarder_supervisor {
                        supervisor.remove(runtime, &peer.node_id).await;
                    } else {
                        runtime.remove_relay_forwarder_endpoint(&peer.node_id).await;
                    }
                    tracing::warn!(
                        peer = %record.key.remote,
                        "signal selected relay path without a usable relay candidate"
                    );
                }
            }
        } else {
            remove_relay_session_for_peer(
                runtime,
                relay_forwarder_supervisor,
                &peer.node_id,
                Some(record.selected_state),
                "removed relay session after non-relay path selection",
            )
            .await;
        }
        runtime.upsert_path_state(record).await;
    }
    Ok(())
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
        return Ok(Some(token.to_string()));
    }
    let Some(path) = args.join_token_path.as_deref() else {
        return Ok(None);
    };
    let token = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read agent join token from {}", path.display()))?;
    let token = token.trim();
    if token.is_empty() {
        anyhow::bail!("agent join token file {} is empty", path.display());
    }
    Ok(Some(token.to_string()))
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

fn agent_relay_capability_reporter(args: &AgentArgs) -> Option<RelayCapabilityReporter> {
    let advertised = agent_relay_capability(args)?;
    let status_url = args
        .relay_status_url
        .clone()
        .or_else(|| args.relay_admission_url.clone());
    Some(RelayCapabilityReporter {
        advertised,
        status_url,
    })
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
        Ok(status) => Some(relay_capability_from_status(&reporter.advertised, &status)),
        Err(error) => {
            tracing::warn!(
                %error,
                status_url,
                "failed to refresh relay status for heartbeat; using configured relay capability"
            );
            Some(reporter.advertised.clone())
        }
    }
}

async fn fetch_relay_status(
    client: &reqwest::Client,
    relay_url: &str,
) -> anyhow::Result<RelayStatusResponse> {
    let url = relay_status_url(relay_url);
    client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to send relay status request to {url}"))?
        .error_for_status()
        .with_context(|| format!("relay status request to {url} returned an error status"))?
        .json()
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

async fn admit_relay_session(
    client: &reqwest::Client,
    status: &ipars_types::api::AgentStatusResponse,
    peer: &NodeRecord,
    relay: &NodeRecord,
) -> anyhow::Result<RelaySessionState> {
    let request = relay_admission_request(status, peer)
        .context("relay session requires endpoint candidates")?;
    let relay_endpoint = relay_public_endpoint(relay)?;
    let response = client
        .post(relay_admission_url(relay)?)
        .json(&request)
        .send()
        .await
        .context("failed to send relay admission request")?
        .error_for_status()
        .context("relay rejected admission request")?
        .json::<RelayAdmissionResponse>()
        .await
        .context("failed to decode relay admission response")?;

    Ok(relay_session_state_from_admission(
        peer,
        relay,
        response,
        relay_endpoint,
    ))
}

async fn admit_relay_session_from_candidates(
    client: &reqwest::Client,
    runtime: &AgentRuntime,
    status: &ipars_types::api::AgentStatusResponse,
    peer: &NodeRecord,
    relays: &[NodeRecord],
) -> anyhow::Result<RelaySessionState> {
    let mut errors = Vec::new();
    for relay in relays {
        runtime.record_relay_admission_attempt();
        match admit_relay_session(client, status, peer, relay).await {
            Ok(session) => {
                runtime.record_relay_admission_success();
                return Ok(session);
            }
            Err(error) => {
                runtime.record_relay_admission_failure();
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
    response: RelayAdmissionResponse,
    relay_endpoint: SocketAddr,
) -> RelaySessionState {
    RelaySessionState {
        peer: peer.node_id.clone(),
        relay_node: relay.node_id.clone(),
        relay_endpoint,
        admitted_local_addr: response.left_addr,
        admitted_peer_addr: response.right_addr,
        session_id: response.session_id,
        session_token: response.session_token,
        expires_at: response.expires_at,
    }
}

fn relay_admission_request(
    status: &ipars_types::api::AgentStatusResponse,
    peer: &NodeRecord,
) -> Option<RelayAdmissionRequest> {
    Some(RelayAdmissionRequest {
        left: status.node_id.clone(),
        right: peer.node_id.clone(),
        left_addr: relay_session_endpoint(&status.candidates)?,
        right_addr: relay_session_endpoint(&peer.endpoint_candidates)?,
    })
}

fn relay_session_endpoint(candidates: &[EndpointCandidate]) -> Option<SocketAddr> {
    candidates
        .iter()
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
    if response.preferred_state != PathState::Relay {
        return Vec::new();
    }
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
    candidates.sort_by(|left, right| {
        let left = left.relay_capability.as_ref();
        let right = right.relay_capability.as_ref();
        left.map(|capability| capability.active_sessions)
            .cmp(&right.map(|capability| capability.active_sessions))
            .then_with(|| {
                right
                    .map(|capability| capability.max_mbps)
                    .cmp(&left.map(|capability| capability.max_mbps))
            })
    });
    candidates
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
    client
        .get(signal_hole_punch_url(signal_url, &key.local, &key.remote))
        .send()
        .await
        .context("failed to fetch hole punch plan")?
        .error_for_status()
        .context("signal service rejected hole punch plan request")?
        .json()
        .await
        .context("failed to decode hole punch plan response")
}

async fn send_signal_path_request(
    client: &reqwest::Client,
    signal_url: &str,
    request: SignalPathRequest,
) -> anyhow::Result<SignalPathResponse> {
    client
        .post(signal_path_url(signal_url))
        .json(&request)
        .send()
        .await
        .context("failed to send signal path negotiation")?
        .error_for_status()
        .context("signal service rejected path negotiation")?
        .json()
        .await
        .context("failed to decode signal path response")
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
    let kind_rank = |candidate: &EndpointCandidate| match (state, candidate.kind) {
        (PathState::DirectIpv6, ipars_types::EndpointCandidateKind::Ipv6) => Some(0_u8),
        (PathState::DirectPublic, ipars_types::EndpointCandidateKind::PublicUdp) => Some(0_u8),
        (PathState::DirectNatTraversal, ipars_types::EndpointCandidateKind::StunReflexive) => {
            Some(0_u8)
        }
        (_, _) if state.is_direct() => Some(1_u8),
        _ => None,
    };
    target_candidates
        .iter()
        .filter_map(|candidate| kind_rank(candidate).map(|rank| (rank, candidate)))
        .min_by(|(left_rank, left), (right_rank, right)| {
            left_rank
                .cmp(right_rank)
                .then_with(|| left.cost.cmp(&right.cost))
                .then_with(|| right.priority.cmp(&left.priority))
        })
        .map(|(_, candidate)| candidate.clone())
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
    pin: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match read_conntrack_packet_flows(&paths).await {
                Ok(flows) => {
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
    pin: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match read_conntrack_netlink_packet_flows().await {
                Ok(flows) => {
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
    pin: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match open_conntrack_netlink_event_socket() {
                Ok(socket) => {
                    if let Err(error) = run_conntrack_netlink_event_detector_once(
                        runtime.as_ref(),
                        &socket,
                        idle_poll_interval,
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

async fn run_conntrack_netlink_event_detector_once(
    runtime: &AgentRuntime,
    socket: &Socket,
    idle_poll_interval: Duration,
    pin: bool,
) -> anyhow::Result<()> {
    let mut buffer = vec![0_u8; CONNTRACK_NETLINK_RECV_BUFFER_BYTES];
    loop {
        let mut recorded_any = false;
        while let Some(flows) = read_conntrack_netlink_event_packet_flows(socket, &mut buffer)? {
            recorded_any = true;
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct PacketFlowRecord {
    destination: IpAddr,
    observation: AgentPacketFlowObservation,
}

async fn read_conntrack_netlink_packet_flows() -> anyhow::Result<Vec<PacketFlowRecord>> {
    tokio::task::spawn_blocking(dump_conntrack_netlink_packet_flows)
        .await
        .context("conntrack netlink reader task failed")?
}

fn dump_conntrack_netlink_packet_flows() -> anyhow::Result<Vec<PacketFlowRecord>> {
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
        let result = parse_conntrack_netlink_datagram_packet_flows(&buffer[..received])?;
        flows.extend(result.flows);
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
) -> anyhow::Result<Option<Vec<PacketFlowRecord>>> {
    match socket.recv(&mut &mut buffer[..], 0) {
        Ok(received) => {
            let datagram = parse_conntrack_netlink_datagram_packet_flows(&buffer[..received])?;
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
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
const NLA_TYPE_MASK: u16 = 0x3fff;

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
) -> anyhow::Result<ConntrackNetlinkDatagram> {
    let mut result = ConntrackNetlinkDatagram::default();
    let mut offset = 0_usize;
    while offset < datagram.len() {
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
                result.flows.extend(parse_ctnetlink_packet_flows(payload)?);
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
    let mut flows = Vec::new();
    for attribute in netlink_attributes(&payload[NFGENMSG_LEN..])? {
        match attribute.kind {
            CTA_TUPLE_ORIG | CTA_TUPLE_REPLY => {
                if let Some(flow) = parse_conntrack_tuple_packet_flow(attribute.value)? {
                    flows.push(flow);
                }
            }
            _ => {}
        }
    }
    Ok(flows)
}

fn parse_conntrack_tuple_packet_flow(payload: &[u8]) -> anyhow::Result<Option<PacketFlowRecord>> {
    let mut tuple = ConntrackTupleFields::default();
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
        6 => Some(TransportProtocol::Tcp),
        17 => Some(TransportProtocol::Udp),
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

async fn read_conntrack_packet_flows(paths: &[PathBuf]) -> anyhow::Result<Vec<PacketFlowRecord>> {
    let mut attempted = Vec::new();
    let mut last_error = None;
    for path in paths {
        attempted.push(path.display().to_string());
        match tokio::fs::read_to_string(path).await {
            Ok(contents) => return Ok(parse_conntrack_packet_flows(&contents)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => last_error = Some(error),
        }
    }

    if let Some(error) = last_error {
        anyhow::bail!(
            "failed to read conntrack flow table from {}: {error}",
            attempted.join(", ")
        );
    }
    anyhow::bail!("no conntrack flow table found at {}", attempted.join(", "))
}

fn parse_conntrack_packet_flows(contents: &str) -> Vec<PacketFlowRecord> {
    contents
        .lines()
        .flat_map(parse_conntrack_line_packet_flows)
        .collect()
}

fn parse_conntrack_line_packet_flows(line: &str) -> Vec<PacketFlowRecord> {
    let protocol = line
        .split_whitespace()
        .find_map(transport_protocol_from_conntrack_token);
    let mut flows = Vec::new();
    let mut tuple = ConntrackTupleFields {
        protocol,
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
        "tcp" => Some(TransportProtocol::Tcp),
        "udp" => Some(TransportProtocol::Udp),
        "icmp" | "icmpv6" => Some(TransportProtocol::Icmp),
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
        match response.json::<PeerMap>().await {
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
    let base_urls = override_url.map(|url| vec![url.to_string()]).or_else(|| {
        token.map(|token| {
            token
                .claims
                .bootstrap_endpoints
                .iter()
                .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
                .map(|endpoint| endpoint.url.clone())
                .collect::<Vec<_>>()
        })
    });
    let base_urls =
        base_urls.context("control-plane URL is required and no control-plane bootstrap exists")?;
    let base_urls = dedupe_urls_preserve_order(
        base_urls
            .into_iter()
            .map(|base_url| normalize_base_url(&base_url)),
    );
    if base_urls.is_empty() {
        anyhow::bail!("control-plane URL is required and no control-plane bootstrap exists");
    }
    Ok(base_urls)
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
    let base_urls = override_url.map(|url| vec![url.to_string()]).or_else(|| {
        token.map(|token| {
            token
                .claims
                .bootstrap_endpoints
                .iter()
                .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::Signal)
                .map(|endpoint| endpoint.url.clone())
                .collect::<Vec<_>>()
        })
    });
    let base_urls = base_urls.context("signal URL is required and no signal bootstrap exists")?;
    let base_urls = dedupe_urls_preserve_order(
        base_urls
            .into_iter()
            .map(|base_url| normalize_base_url(&base_url)),
    );
    if base_urls.is_empty() {
        anyhow::bail!("signal URL is required and no signal bootstrap exists");
    }
    Ok(base_urls)
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

    use chrono::{Duration as ChronoDuration, Utc};
    use ipars_agent::AgentNodeState;
    use ipars_types::api::{
        AgentMetricsResponse, AgentRelayForwarderMetrics, LazyConnectMetrics, PathStateCount,
        RelayAdmissionResponse, RelayDataplaneDropReason, RelayDataplaneMetrics,
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

    async fn unused_http_base_url() -> anyhow::Result<String> {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        drop(listener);
        Ok(format!("http://{addr}"))
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
            path_count: 3,
            path_state_counts: vec![PathStateCount {
                state: PathState::Relay,
                count: 3,
            }],
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
            "--acl-rule",
            r#"{"id":"edge-to-db","from_roles":["edge"],"from_tags":["app"],"to_roles":["database"],"to_tags":["db"],"routes":["10.42.0.0/16"],"protocol":"any","action":"allow"}"#,
        ])?;

        let Command::ControlPlane(args) = cli.command else {
            anyhow::bail!("expected control-plane command");
        };
        assert_eq!(args.relay_health_ttl_seconds, 45);
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
            "--disable-relay-fallback",
        ])?;

        let Command::Signal(args) = cli.command else {
            anyhow::bail!("expected signal command");
        };
        assert_eq!(args.relay_health_ttl_seconds, 45);
        assert!(args.disable_relay_fallback);
        Ok(())
    }

    #[test]
    fn acl_rule_parser_rejects_invalid_json() {
        assert!(parse_acl_rule("not json").is_err());
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
            outbound_packets,
            outbound_payload_bytes,
            outbound_datagram_bytes,
            inbound_packets,
            inbound_payload_bytes,
            last_forwarded_at: None,
        }
    }

    #[test]
    fn agent_otel_delta_records_first_forwarder_snapshot_as_counter_increment() {
        let current = agent_forwarder_metrics("peer-a", "relay-a", 5, 500, 620, 3, 300);

        let delta = agent_forwarder_delta(&current, None);

        assert_eq!(delta.outbound_packets, 5);
        assert_eq!(delta.outbound_payload_bytes, 500);
        assert_eq!(delta.outbound_datagram_bytes, 620);
        assert_eq!(delta.inbound_packets, 3);
        assert_eq!(delta.inbound_payload_bytes, 300);
        assert!(has_agent_forwarder_delta(&delta));
    }

    #[test]
    fn agent_otel_delta_records_only_forwarder_increments_since_previous_snapshot() {
        let previous = agent_forwarder_metrics("peer-a", "relay-a", 5, 500, 620, 3, 300);
        let current = agent_forwarder_metrics("peer-a", "relay-a", 9, 850, 1050, 7, 700);

        let delta = agent_forwarder_delta(&current, Some(&previous));

        assert_eq!(delta.outbound_packets, 4);
        assert_eq!(delta.outbound_payload_bytes, 350);
        assert_eq!(delta.outbound_datagram_bytes, 430);
        assert_eq!(delta.inbound_packets, 4);
        assert_eq!(delta.inbound_payload_bytes, 400);
        assert!(has_agent_forwarder_delta(&delta));
    }

    #[test]
    fn agent_otel_delta_skips_unchanged_forwarders() {
        let forwarder = agent_forwarder_metrics("peer-a", "relay-a", 5, 500, 620, 3, 300);
        let metrics = AgentMetricsResponse {
            node_id: NodeId::from_string("node-a"),
            candidate_count: 2,
            path_count: 1,
            relay_session_count: 1,
            relay_admission_attempt_count: 3,
            relay_admission_success_count: 2,
            relay_admission_failure_count: 1,
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
            peer_activity_record_count: 2,
            packet_flow_observation_count: 3,
            packet_flow_match_count: 2,
            packet_flow_unmatched_count: 1,
            generated_at: Utc::now(),
        };
        let previous = AgentOtelSnapshot::from(&metrics);

        assert!(agent_forwarder_deltas(&metrics, Some(&previous)).is_empty());
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
                agent_relay_capability_reporter(&args).context("expected relay reporter")?;
            assert_eq!(reporter.status_url.as_deref(), Some("http://relay-a:9580"));
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
    fn relay_session_state_uses_advertised_relay_node() {
        let peer = node_record("node-b");
        let relay = node_record("relay-advertised");
        let relay_endpoint = SocketAddr::from(([203, 0, 113, 30], 51_820));
        let response = RelayAdmissionResponse {
            relay_node: NodeId::from_string("relay-daemon-local-name"),
            session_id: "node-a:node-b".to_string(),
            session_token: "relay-secret".to_string(),
            expires_at: Utc::now() + ChronoDuration::seconds(300),
            left: NodeId::from_string("node-a"),
            right: peer.node_id.clone(),
            left_addr: SocketAddr::from(([203, 0, 113, 10], 51_820)),
            right_addr: SocketAddr::from(([203, 0, 113, 11], 51_820)),
        };

        let session = relay_session_state_from_admission(&peer, &relay, response, relay_endpoint);

        assert_eq!(session.peer, NodeId::from_string("node-b"));
        assert_eq!(session.relay_node, NodeId::from_string("relay-advertised"));
        assert_eq!(session.relay_endpoint, relay_endpoint);
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
            dataplane: RelayDataplaneMetrics::default(),
        };

        let refreshed = relay_capability_from_status(&advertised, &status);

        assert_eq!(refreshed.public_endpoint, advertised.public_endpoint);
        assert_eq!(refreshed.admission_url, advertised.admission_url);
        assert!(!refreshed.enabled_by_policy);
        assert_eq!(refreshed.max_sessions, 250);
        assert_eq!(refreshed.active_sessions, 12);
        assert_eq!(refreshed.max_mbps, 500);
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
            assert!(args.packet_flow_pin);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
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
        ])?;

        if let Command::Agent(args) = cli.command {
            assert_eq!(
                args.packet_flow_detector,
                PacketFlowDetector::ConntrackNetlink
            );
            assert_eq!(args.packet_flow_detector.as_str(), "conntrack-netlink");
            assert_eq!(args.packet_flow_poll_interval_seconds, 3);
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
            assert!(args.packet_flow_pin);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
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
    fn conntrack_parser_extracts_destination_ips() -> anyhow::Result<()> {
        let contents = "\
ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=100.64.0.11 sport=54321 dport=51820 src=100.64.0.11 dst=192.0.2.10 sport=51820 dport=54321
ipv6 10 udp 17 29 src=2001:db8::1 dst=fd00::42 sport=50000 dport=51820 src=fd00::42 dst=2001:db8::1 sport=51820 dport=50000
invalid no-destination-here
";
        let flows = parse_conntrack_packet_flows(contents);
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
                        test_nla(CTA_PROTO_NUM, &[17]),
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
        let mut payload = vec![0, NFNETLINK_V0, 0, 0];
        payload.extend(orig_tuple);
        payload.extend(reply_tuple);

        let mut datagram = test_netlink_message(ctnetlink_message_type(0), &payload);
        datagram.extend(test_netlink_message(NLMSG_DONE, &[]));

        let result = parse_conntrack_netlink_datagram_packet_flows(&datagram)?;
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
        assert_eq!(orig.observation.protocol, Some(TransportProtocol::Udp));
        assert_eq!(orig.observation.source_port, Some(50_000));
        assert_eq!(orig.observation.destination_port, Some(51_820));
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

        let result = parse_conntrack_netlink_datagram_packet_flows(&datagram)?;

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

    #[test]
    fn runtime_preflight_requires_linux_tools_for_command_backend() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["iparsd", "agent", "--apply-peer-map"])?;

        if let Command::Agent(args) = cli.command {
            let needs = runtime_preflight_needs(&args);
            assert!(needs.ip_command);
            assert!(needs.wg_command);
            assert!(needs.cap_net_admin);
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
            assert!(needs.cap_net_admin);
            assert!(!needs.cap_sys_admin);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
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
            assert!(needs.cap_net_admin);
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
            assert!(needs.cap_net_admin);
            assert!(needs.cap_sys_admin);
            assert!(needs.linux_netns);
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
    }

    #[test]
    fn runtime_preflight_validates_linux_interface_name() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from([
            "iparsd",
            "agent",
            "--runtime-backend",
            "dry-run",
            "--wireguard-interface",
            "invalid/name",
        ])?;

        if let Command::Agent(args) = cli.command {
            let error = match preflight_agent_runtime_with_path(&args, Some(OsStr::new(""))) {
                Ok(()) => anyhow::bail!("unexpected successful preflight"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("must contain only ASCII letters"));
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
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

    fn unique_test_dir(name: &str) -> anyhow::Result<PathBuf> {
        let path = std::env::temp_dir().join(format!(
            "ipars-{name}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&path)?;
        Ok(path)
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
            assert!(docker_network_intent(&args).is_err());
            return Ok(());
        }

        Err(anyhow::anyhow!("expected agent command"))
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
            docker_api_network(
                "default-id",
                "compose_default",
                "bridge",
                &["172.18.0.0/16"],
            ),
            docker_api_network("host-id", "host", "host", &["192.0.2.0/24"]),
            docker_api_network(
                "other-id",
                "compose_extra",
                "bridge",
                &["172.19.0.0/16", "172.18.0.0/16"],
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
    fn docker_api_socket_resolution_prefers_explicit_then_docker_host_then_rootless() {
        let explicit = Path::new("/custom/docker.sock");
        assert_eq!(
            resolve_docker_api_socket(Some(explicit), None, None, |_| false),
            PathBuf::from("/custom/docker.sock")
        );
        assert_eq!(
            resolve_docker_api_socket(
                None,
                Some(OsStr::new("unix:///tmp/docker.sock")),
                None,
                |_| false,
            ),
            PathBuf::from("/tmp/docker.sock")
        );
        assert_eq!(
            resolve_docker_api_socket(None, None, Some(OsStr::new("/run/user/1000")), |path| {
                path == Path::new("/run/user/1000/docker.sock")
            }),
            PathBuf::from("/run/user/1000/docker.sock")
        );
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
        let cli = Cli::try_parse_from(["iparsd", "agent", "--apply-kubernetes-underlay"])?;

        if let Command::Agent(args) = cli.command {
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
            "--admission-url",
            "http://relay-a:9580",
            "--session-ttl-seconds",
            "60",
        ])?;

        if let Command::Relay(args) = cli.command {
            assert_eq!(args.session_ttl_seconds, 60);
            assert_eq!(args.admission_url.as_deref(), Some("http://relay-a:9580"));
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

    #[tokio::test]
    async fn relay_admission_fails_over_to_next_candidate() -> anyhow::Result<()> {
        async fn relay_admission_success(
            axum::Json(request): axum::Json<RelayAdmissionRequest>,
        ) -> axum::Json<RelayAdmissionResponse> {
            axum::Json(RelayAdmissionResponse {
                relay_node: NodeId::from_string("relay-good"),
                session_id: "session-a".to_string(),
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
        relay_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_request_uses_runtime_state() {
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
        runtime.upsert_path_state(path.clone()).await;

        let request = heartbeat_request(&runtime, None).await;

        assert_eq!(request.node_id, node_id);
        assert_eq!(request.health.state, HealthState::Healthy);
        assert!(request.candidates.is_empty());
        assert!(request.relay_capability.is_none());
        assert_eq!(request.path_state, vec![path]);
    }

    #[tokio::test]
    async fn signal_node_upsert_request_uses_runtime_candidates() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let node = node_record("node-a");

        let request = signal_node_upsert_request(&runtime, node).await;

        assert_eq!(request.node.node_id, NodeId::from_string("node-a"));
        assert!(request.node.endpoint_candidates.is_empty());
        assert_eq!(
            request.health.as_ref().map(|health| health.state),
            Some(HealthState::Healthy)
        );
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
        registry.upsert_node(node_record("node-b")).await;
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
