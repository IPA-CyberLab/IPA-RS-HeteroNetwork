use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use futures_util::{StreamExt, TryStreamExt};
use ipars_crypto::{CryptoError, IdentityKeyPair, WireGuardKeyPair};
use ipars_relay::encode_relay_datagram_with_route;
use ipars_route_manager::{
    with_netlink_namespace, LinuxNetlinkSocket, LinuxNetworkNamespace, RouteManager,
    RouteManagerError, RoutePlan,
};
use ipars_stun::{StunError, StunProbe, UdpStunProbe};
use ipars_types::api::{
    packet_flow_destination_drop_reason, AgentManagedProcessState, AgentManagedProcessStatus,
    AgentMetricsResponse, AgentPacketFlowApplication, AgentPacketFlowApplicationCount,
    AgentPacketFlowClassification, AgentPacketFlowClassificationCount, AgentPacketFlowDropReason,
    AgentPacketFlowDropReasonCount, AgentPacketFlowDuplicateSource,
    AgentPacketFlowDuplicateSourceCount, AgentPacketFlowMatch, AgentPacketFlowMatchKind,
    AgentPacketFlowObservation, AgentPathProbeRequest, AgentRelayAdmissionFailureReason,
    AgentRelayAdmissionFailureReasonCount, AgentRelayForwarderMetrics, AgentStatusResponse,
    LazyConnectMetrics, PathStateCount, PeerMap, RotateWireGuardKeyRequest,
    SignalHolePunchPlanResponse,
};
use ipars_types::{
    endpoint_addr_is_usable, CandidateSource, ClusterPolicy, EndpointCandidate,
    EndpointCandidateKind, NatClassification, NatProbeObservation, NodeId, NodeRecord,
    PathChangeEvent, PathChangeKind, PathRecord, PathScore, PathState, Role, Route, Tag, VpnIp,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

#[cfg(target_os = "linux")]
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST};
#[cfg(target_os = "linux")]
use netlink_packet_generic::GenlMessage;
#[cfg(target_os = "linux")]
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute,
    WireguardCmd, WireguardMessage, WireguardPeer, WireguardPeerAttribute, WireguardPeerFlags,
};
#[cfg(target_os = "linux")]
use rtnetlink::{LinkUnspec, LinkWireguard};

const MAX_PATH_CHANGE_EVENTS: usize = 1024;
const DEFAULT_SYSTEM_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SYSTEM_COMMAND_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const DEFAULT_SYSTEM_COMMAND_OUTPUT_MAX_BYTES: usize = 64 * 1024;
const MAX_SYSTEM_COMMAND_OUTPUT_MAX_BYTES: usize = 1024 * 1024;
const MAX_LINUX_COMMAND_PROGRAM_BYTES: usize = 4096;
const MAX_LINUX_COMMAND_ARGS: usize = 1024;
const MAX_LINUX_COMMAND_ARG_BYTES: usize = 128 * 1024;
const MAX_LINUX_COMMAND_ARGV_BYTES: usize = 1024 * 1024;
const MAX_FORWARDER_UDP_PAYLOAD_BYTES: usize = 65_507;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("agent state io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("agent state serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("insecure agent state path: {0}")]
    InsecureStatePath(String),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("stun probe error: {0}")]
    Stun(#[from] StunError),
    #[error("route manager error: {0}")]
    RouteManager(#[from] RouteManagerError),
    #[error("route planning error: {0}")]
    RoutePlanning(String),
    #[error("control-plane client error: {0}")]
    ControlPlaneClient(String),
    #[error("hole punch error: {0}")]
    HolePunch(String),
    #[error("relay session error: {0}")]
    RelaySession(String),
    #[error("wireguard backend error: {0}")]
    WireGuard(String),
    #[error("peer path does not exist: {0}")]
    MissingPeer(NodeId),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentNodeState {
    pub node_id: NodeId,
    pub identity_private_key_b64: String,
    pub identity_public_key_b64: String,
    pub wireguard_private_key_b64: String,
    pub wireguard_public_key_b64: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AgentNodeState {
    pub fn generate(now: DateTime<Utc>) -> Self {
        let identity = IdentityKeyPair::generate();
        let wireguard = WireGuardKeyPair::generate();
        Self {
            node_id: identity.node_id(),
            identity_private_key_b64: identity.signing_key_b64(),
            identity_public_key_b64: identity.public_key_b64(),
            wireguard_private_key_b64: wireguard.private_key_b64,
            wireguard_public_key_b64: wireguard.public_key_b64,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn identity_key_pair(&self) -> Result<IdentityKeyPair, AgentError> {
        Ok(IdentityKeyPair::from_signing_key_b64(
            &self.identity_private_key_b64,
        )?)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentWireGuardKeyRotationPlan {
    pub next_state: AgentNodeState,
    pub request: RotateWireGuardKeyRequest,
    pub previous_wireguard_public_key: String,
    pub next_wireguard_public_key: String,
}

#[derive(Debug, Clone)]
pub struct FileAgentStateStore {
    path: PathBuf,
}

impl FileAgentStateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<AgentNodeState, AgentError> {
        ensure_private_agent_state_parent(&self.path)?;
        ensure_private_agent_state_file(&self.path)?;
        let bytes = std::fs::read(&self.path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save(&self, state: &AgentNodeState) -> Result<(), AgentError> {
        prepare_private_agent_state_parent(&self.path)?;
        let bytes = serde_json::to_vec_pretty(state)?;
        write_private_agent_state_file(&self.path, &bytes)?;
        Ok(())
    }

    pub fn load_or_create(&self, now: DateTime<Utc>) -> Result<AgentNodeState, AgentError> {
        match self.load() {
            Ok(state) => Ok(state),
            Err(AgentError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let state = AgentNodeState::generate(now);
                self.save(&state)?;
                Ok(state)
            }
            Err(error) => Err(error),
        }
    }
}

fn ensure_private_agent_state_file(path: &Path) -> Result<(), AgentError> {
    let metadata = std::fs::symlink_metadata(path)?;
    validate_private_agent_state_metadata(path, &metadata)
}

fn agent_state_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn ensure_private_agent_state_parent(path: &Path) -> Result<(), AgentError> {
    let Some(parent) = agent_state_parent(path) else {
        return Ok(());
    };
    let metadata = std::fs::symlink_metadata(parent)?;
    validate_private_agent_state_directory_metadata(parent, &metadata)
}

fn prepare_private_agent_state_parent(path: &Path) -> Result<(), AgentError> {
    match ensure_private_agent_state_parent(path) {
        Ok(()) => Ok(()),
        Err(AgentError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            let Some(parent) = agent_state_parent(path) else {
                return Ok(());
            };
            create_private_agent_state_directory(parent)?;
            ensure_private_agent_state_parent(path)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn create_private_agent_state_directory(path: &Path) -> Result<(), AgentError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_agent_state_directory(path: &Path) -> Result<(), AgentError> {
    std::fs::create_dir_all(path)?;
    Ok(())
}

#[cfg(unix)]
fn validate_private_agent_state_directory_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), AgentError> {
    use std::os::unix::fs::PermissionsExt;

    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(AgentError::InsecureStatePath(format!(
            "{} must not be a symbolic link",
            path.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(AgentError::InsecureStatePath(format!(
            "{} must be a directory",
            path.display()
        )));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(AgentError::InsecureStatePath(format!(
            "{} must not be readable, writable, or executable by group/other users; current mode is {mode:o}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_agent_state_directory_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), AgentError> {
    if !metadata.is_dir() {
        return Err(AgentError::InsecureStatePath(format!(
            "{} must be a directory",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_agent_state_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), AgentError> {
    use std::os::unix::fs::PermissionsExt;

    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(AgentError::InsecureStatePath(format!(
            "{} must not be a symbolic link",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(AgentError::InsecureStatePath(format!(
            "{} must be a regular file",
            path.display()
        )));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(AgentError::InsecureStatePath(format!(
            "{} must not be readable, writable, or executable by group/other users; current mode is {mode:o}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_agent_state_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), AgentError> {
    if !metadata.is_file() {
        return Err(AgentError::InsecureStatePath(format!(
            "{} must be a regular file",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn write_private_agent_state_file(path: &Path, bytes: &[u8]) -> Result<(), AgentError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    match std::fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_agent_state_metadata(path, &metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let temp_path = private_agent_state_temp_path(path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&temp_path)?;
    let metadata = file.metadata()?;
    validate_private_agent_state_metadata(&temp_path, &metadata)?;
    let result = (|| -> Result<(), AgentError> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&temp_path, path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        validate_private_agent_state_metadata(path, &metadata)?;
        sync_agent_state_parent_dir(path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

#[cfg(unix)]
fn private_agent_state_temp_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("agent-state");
    let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or_default();
    parent.join(format!(
        ".{file_name}.tmp-{}-{timestamp}",
        std::process::id()
    ))
}

#[cfg(unix)]
fn sync_agent_state_parent_dir(path: &Path) -> Result<(), AgentError> {
    let Some(parent) = agent_state_parent(path) else {
        return Ok(());
    };
    let directory = std::fs::File::open(parent)?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_agent_state_file(path: &Path, bytes: &[u8]) -> Result<(), AgentError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_agent_state_metadata(path, &metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

#[derive(Debug)]
pub struct AgentRuntime {
    state: RwLock<AgentNodeState>,
    candidates: tokio::sync::RwLock<Vec<EndpointCandidate>>,
    nat_classification: tokio::sync::RwLock<Option<NatClassification>>,
    path_state: tokio::sync::RwLock<BTreeMap<(NodeId, NodeId), PathRecord>>,
    path_change_events: tokio::sync::RwLock<VecDeque<PathChangeEvent>>,
    relay_sessions: tokio::sync::RwLock<BTreeMap<NodeId, RelaySessionState>>,
    relay_forwarder_endpoints: tokio::sync::RwLock<BTreeMap<NodeId, SocketAddr>>,
    relay_forwarder_metrics: tokio::sync::RwLock<BTreeMap<NodeId, Arc<RelayForwarderStats>>>,
    userspace_wireguard_process: tokio::sync::RwLock<Option<AgentManagedProcessStatus>>,
    lazy_connect: tokio::sync::RwLock<LazyConnectManager>,
    relay_admission_attempt_count: AtomicU64,
    relay_admission_success_count: AtomicU64,
    relay_admission_failure_count: AtomicU64,
    relay_admission_failure_reason_counters: AgentRelayAdmissionFailureReasonCounters,
    path_probe_record_count: AtomicU64,
    peer_activity_record_count: AtomicU64,
    packet_flow_observation_count: AtomicU64,
    packet_flow_match_count: AtomicU64,
    packet_flow_unmatched_count: AtomicU64,
    packet_flow_filtered_count: AtomicU64,
    packet_flow_duplicate_suppression_count: AtomicU64,
    packet_flow_duplicate_suppression_proc_net_conntrack_count: AtomicU64,
    packet_flow_duplicate_suppression_conntrack_netlink_count: AtomicU64,
    packet_flow_duplicate_suppression_conntrack_netlink_events_count: AtomicU64,
    packet_flow_duplicate_suppression_ebpf_jsonl_count: AtomicU64,
    packet_flow_duplicate_suppression_ebpf_ringbuf_count: AtomicU64,
    packet_flow_filtered_unspecified_count: AtomicU64,
    packet_flow_filtered_loopback_count: AtomicU64,
    packet_flow_filtered_multicast_count: AtomicU64,
    packet_flow_filtered_broadcast_count: AtomicU64,
    packet_flow_filtered_link_local_count: AtomicU64,
    packet_flow_filtered_no_overlay_match_count: AtomicU64,
    packet_flow_filtered_inconsistent_transport_metadata_count: AtomicU64,
    packet_flow_classification_unknown_count: AtomicU64,
    packet_flow_classification_opening_count: AtomicU64,
    packet_flow_classification_unreplied_count: AtomicU64,
    packet_flow_classification_assured_count: AtomicU64,
    packet_flow_classification_established_count: AtomicU64,
    packet_flow_classification_closing_count: AtomicU64,
    packet_flow_classification_closed_count: AtomicU64,
    packet_flow_application_unknown_count: AtomicU64,
    packet_flow_application_dns_count: AtomicU64,
    packet_flow_application_http_count: AtomicU64,
    packet_flow_application_https_count: AtomicU64,
    packet_flow_application_ssh_count: AtomicU64,
    packet_flow_application_ldap_count: AtomicU64,
    packet_flow_application_smb_count: AtomicU64,
    packet_flow_application_nfs_count: AtomicU64,
    packet_flow_application_rdp_count: AtomicU64,
    packet_flow_application_kubernetes_api_count: AtomicU64,
    packet_flow_application_etcd_count: AtomicU64,
    packet_flow_application_zookeeper_count: AtomicU64,
    packet_flow_application_consul_count: AtomicU64,
    packet_flow_application_vault_count: AtomicU64,
    packet_flow_application_nomad_count: AtomicU64,
    packet_flow_application_postgres_count: AtomicU64,
    packet_flow_application_mysql_count: AtomicU64,
    packet_flow_application_mssql_count: AtomicU64,
    packet_flow_application_oracle_count: AtomicU64,
    packet_flow_application_clickhouse_count: AtomicU64,
    packet_flow_application_influxdb_count: AtomicU64,
    packet_flow_application_redis_count: AtomicU64,
    packet_flow_application_memcached_count: AtomicU64,
    packet_flow_application_prometheus_count: AtomicU64,
    packet_flow_application_opentelemetry_count: AtomicU64,
    packet_flow_application_syslog_count: AtomicU64,
    packet_flow_application_jaeger_count: AtomicU64,
    packet_flow_application_loki_count: AtomicU64,
    packet_flow_application_tempo_count: AtomicU64,
    packet_flow_application_zipkin_count: AtomicU64,
    packet_flow_application_grpc_count: AtomicU64,
    packet_flow_application_kafka_count: AtomicU64,
    packet_flow_application_nats_count: AtomicU64,
    packet_flow_application_mqtt_count: AtomicU64,
    packet_flow_application_amqp_count: AtomicU64,
    packet_flow_application_cassandra_count: AtomicU64,
    packet_flow_application_mongodb_count: AtomicU64,
    packet_flow_application_elasticsearch_count: AtomicU64,
    packet_flow_application_wireguard_count: AtomicU64,
    packet_flow_application_icmp_count: AtomicU64,
}

#[derive(Debug, Default)]
struct AgentRelayAdmissionFailureReasonCounters {
    no_endpoint_candidate: AtomicU64,
    invalid_relay_candidate: AtomicU64,
    unavailable: AtomicU64,
    rejected: AtomicU64,
    invalid_response: AtomicU64,
}

impl AgentRelayAdmissionFailureReasonCounters {
    fn record(&self, reason: AgentRelayAdmissionFailureReason) {
        self.counter(reason).fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Vec<AgentRelayAdmissionFailureReasonCount> {
        AgentRelayAdmissionFailureReason::ALL
            .into_iter()
            .filter_map(|reason| {
                let count = self.counter(reason).load(Ordering::Relaxed);
                (count > 0).then_some(AgentRelayAdmissionFailureReasonCount { reason, count })
            })
            .collect()
    }

    fn counter(&self, reason: AgentRelayAdmissionFailureReason) -> &AtomicU64 {
        match reason {
            AgentRelayAdmissionFailureReason::NoEndpointCandidate => &self.no_endpoint_candidate,
            AgentRelayAdmissionFailureReason::InvalidRelayCandidate => {
                &self.invalid_relay_candidate
            }
            AgentRelayAdmissionFailureReason::Unavailable => &self.unavailable,
            AgentRelayAdmissionFailureReason::Rejected => &self.rejected,
            AgentRelayAdmissionFailureReason::InvalidResponse => &self.invalid_response,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySessionState {
    pub peer: NodeId,
    pub relay_node: NodeId,
    pub relay_endpoint: SocketAddr,
    pub admitted_local_addr: SocketAddr,
    pub admitted_peer_addr: SocketAddr,
    pub session_id: String,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct RelayForwarderStats {
    peer: NodeId,
    relay_node: NodeId,
    relay_endpoint: SocketAddr,
    local_endpoint: SocketAddr,
    socket_receive_errors: AtomicU64,
    outbound_packets: AtomicU64,
    outbound_payload_bytes: AtomicU64,
    outbound_datagram_bytes: AtomicU64,
    outbound_dropped_unexpected_source_packets: AtomicU64,
    outbound_dropped_unexpected_source_payload_bytes: AtomicU64,
    outbound_dropped_expired_session_packets: AtomicU64,
    outbound_dropped_expired_session_payload_bytes: AtomicU64,
    outbound_dropped_oversized_packets: AtomicU64,
    outbound_dropped_oversized_payload_bytes: AtomicU64,
    outbound_dropped_oversized_datagram_bytes: AtomicU64,
    outbound_dropped_socket_error_packets: AtomicU64,
    outbound_dropped_socket_error_payload_bytes: AtomicU64,
    outbound_dropped_socket_error_datagram_bytes: AtomicU64,
    outbound_dropped_non_wireguard_packets: AtomicU64,
    outbound_dropped_non_wireguard_payload_bytes: AtomicU64,
    inbound_packets: AtomicU64,
    inbound_payload_bytes: AtomicU64,
    inbound_dropped_expired_session_packets: AtomicU64,
    inbound_dropped_expired_session_payload_bytes: AtomicU64,
    inbound_dropped_oversized_packets: AtomicU64,
    inbound_dropped_oversized_payload_bytes: AtomicU64,
    inbound_dropped_socket_error_packets: AtomicU64,
    inbound_dropped_socket_error_payload_bytes: AtomicU64,
    inbound_dropped_non_wireguard_packets: AtomicU64,
    inbound_dropped_non_wireguard_payload_bytes: AtomicU64,
    last_forwarded_unix_millis: AtomicI64,
}

impl RelayForwarderStats {
    pub fn new(
        peer: NodeId,
        relay_node: NodeId,
        relay_endpoint: SocketAddr,
        local_endpoint: SocketAddr,
    ) -> Self {
        Self {
            peer,
            relay_node,
            relay_endpoint,
            local_endpoint,
            socket_receive_errors: AtomicU64::new(0),
            outbound_packets: AtomicU64::new(0),
            outbound_payload_bytes: AtomicU64::new(0),
            outbound_datagram_bytes: AtomicU64::new(0),
            outbound_dropped_unexpected_source_packets: AtomicU64::new(0),
            outbound_dropped_unexpected_source_payload_bytes: AtomicU64::new(0),
            outbound_dropped_expired_session_packets: AtomicU64::new(0),
            outbound_dropped_expired_session_payload_bytes: AtomicU64::new(0),
            outbound_dropped_oversized_packets: AtomicU64::new(0),
            outbound_dropped_oversized_payload_bytes: AtomicU64::new(0),
            outbound_dropped_oversized_datagram_bytes: AtomicU64::new(0),
            outbound_dropped_socket_error_packets: AtomicU64::new(0),
            outbound_dropped_socket_error_payload_bytes: AtomicU64::new(0),
            outbound_dropped_socket_error_datagram_bytes: AtomicU64::new(0),
            outbound_dropped_non_wireguard_packets: AtomicU64::new(0),
            outbound_dropped_non_wireguard_payload_bytes: AtomicU64::new(0),
            inbound_packets: AtomicU64::new(0),
            inbound_payload_bytes: AtomicU64::new(0),
            inbound_dropped_expired_session_packets: AtomicU64::new(0),
            inbound_dropped_expired_session_payload_bytes: AtomicU64::new(0),
            inbound_dropped_oversized_packets: AtomicU64::new(0),
            inbound_dropped_oversized_payload_bytes: AtomicU64::new(0),
            inbound_dropped_socket_error_packets: AtomicU64::new(0),
            inbound_dropped_socket_error_payload_bytes: AtomicU64::new(0),
            inbound_dropped_non_wireguard_packets: AtomicU64::new(0),
            inbound_dropped_non_wireguard_payload_bytes: AtomicU64::new(0),
            last_forwarded_unix_millis: AtomicI64::new(-1),
        }
    }

    pub fn peer(&self) -> &NodeId {
        &self.peer
    }

    pub fn record_socket_receive_error(&self) {
        self.socket_receive_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_outbound(&self, payload_bytes: usize, datagram_bytes: usize) {
        self.outbound_packets.fetch_add(1, Ordering::Relaxed);
        self.outbound_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
        self.outbound_datagram_bytes
            .fetch_add(datagram_bytes as u64, Ordering::Relaxed);
        self.record_forwarded_at();
    }

    pub fn record_outbound_unexpected_source_drop(&self, payload_bytes: usize) {
        self.outbound_dropped_unexpected_source_packets
            .fetch_add(1, Ordering::Relaxed);
        self.outbound_dropped_unexpected_source_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
    }

    pub fn record_outbound_expired_session_drop(&self, payload_bytes: usize) {
        self.outbound_dropped_expired_session_packets
            .fetch_add(1, Ordering::Relaxed);
        self.outbound_dropped_expired_session_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
    }

    pub fn record_outbound_oversized_drop(&self, payload_bytes: usize, datagram_bytes: usize) {
        self.outbound_dropped_oversized_packets
            .fetch_add(1, Ordering::Relaxed);
        self.outbound_dropped_oversized_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
        self.outbound_dropped_oversized_datagram_bytes
            .fetch_add(datagram_bytes as u64, Ordering::Relaxed);
    }

    pub fn record_outbound_socket_error_drop(&self, payload_bytes: usize, datagram_bytes: usize) {
        self.outbound_dropped_socket_error_packets
            .fetch_add(1, Ordering::Relaxed);
        self.outbound_dropped_socket_error_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
        self.outbound_dropped_socket_error_datagram_bytes
            .fetch_add(datagram_bytes as u64, Ordering::Relaxed);
    }

    pub fn record_outbound_drop(&self, payload_bytes: usize) {
        self.outbound_dropped_non_wireguard_packets
            .fetch_add(1, Ordering::Relaxed);
        self.outbound_dropped_non_wireguard_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
    }

    pub fn record_inbound(&self, payload_bytes: usize) {
        self.inbound_packets.fetch_add(1, Ordering::Relaxed);
        self.inbound_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
        self.record_forwarded_at();
    }

    pub fn record_inbound_expired_session_drop(&self, payload_bytes: usize) {
        self.inbound_dropped_expired_session_packets
            .fetch_add(1, Ordering::Relaxed);
        self.inbound_dropped_expired_session_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
    }

    pub fn record_inbound_oversized_drop(&self, payload_bytes: usize) {
        self.inbound_dropped_oversized_packets
            .fetch_add(1, Ordering::Relaxed);
        self.inbound_dropped_oversized_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
    }

    pub fn record_inbound_socket_error_drop(&self, payload_bytes: usize) {
        self.inbound_dropped_socket_error_packets
            .fetch_add(1, Ordering::Relaxed);
        self.inbound_dropped_socket_error_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
    }

    pub fn record_inbound_drop(&self, payload_bytes: usize) {
        self.inbound_dropped_non_wireguard_packets
            .fetch_add(1, Ordering::Relaxed);
        self.inbound_dropped_non_wireguard_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> AgentRelayForwarderMetrics {
        let last_forwarded_unix_millis = self.last_forwarded_unix_millis.load(Ordering::Relaxed);
        AgentRelayForwarderMetrics {
            peer: self.peer.clone(),
            relay_node: self.relay_node.clone(),
            relay_endpoint: self.relay_endpoint,
            local_endpoint: self.local_endpoint,
            socket_receive_errors: self.socket_receive_errors.load(Ordering::Relaxed),
            outbound_packets: self.outbound_packets.load(Ordering::Relaxed),
            outbound_payload_bytes: self.outbound_payload_bytes.load(Ordering::Relaxed),
            outbound_datagram_bytes: self.outbound_datagram_bytes.load(Ordering::Relaxed),
            outbound_dropped_unexpected_source_packets: self
                .outbound_dropped_unexpected_source_packets
                .load(Ordering::Relaxed),
            outbound_dropped_unexpected_source_payload_bytes: self
                .outbound_dropped_unexpected_source_payload_bytes
                .load(Ordering::Relaxed),
            outbound_dropped_expired_session_packets: self
                .outbound_dropped_expired_session_packets
                .load(Ordering::Relaxed),
            outbound_dropped_expired_session_payload_bytes: self
                .outbound_dropped_expired_session_payload_bytes
                .load(Ordering::Relaxed),
            outbound_dropped_oversized_packets: self
                .outbound_dropped_oversized_packets
                .load(Ordering::Relaxed),
            outbound_dropped_oversized_payload_bytes: self
                .outbound_dropped_oversized_payload_bytes
                .load(Ordering::Relaxed),
            outbound_dropped_oversized_datagram_bytes: self
                .outbound_dropped_oversized_datagram_bytes
                .load(Ordering::Relaxed),
            outbound_dropped_socket_error_packets: self
                .outbound_dropped_socket_error_packets
                .load(Ordering::Relaxed),
            outbound_dropped_socket_error_payload_bytes: self
                .outbound_dropped_socket_error_payload_bytes
                .load(Ordering::Relaxed),
            outbound_dropped_socket_error_datagram_bytes: self
                .outbound_dropped_socket_error_datagram_bytes
                .load(Ordering::Relaxed),
            outbound_dropped_non_wireguard_packets: self
                .outbound_dropped_non_wireguard_packets
                .load(Ordering::Relaxed),
            outbound_dropped_non_wireguard_payload_bytes: self
                .outbound_dropped_non_wireguard_payload_bytes
                .load(Ordering::Relaxed),
            inbound_packets: self.inbound_packets.load(Ordering::Relaxed),
            inbound_payload_bytes: self.inbound_payload_bytes.load(Ordering::Relaxed),
            inbound_dropped_expired_session_packets: self
                .inbound_dropped_expired_session_packets
                .load(Ordering::Relaxed),
            inbound_dropped_expired_session_payload_bytes: self
                .inbound_dropped_expired_session_payload_bytes
                .load(Ordering::Relaxed),
            inbound_dropped_oversized_packets: self
                .inbound_dropped_oversized_packets
                .load(Ordering::Relaxed),
            inbound_dropped_oversized_payload_bytes: self
                .inbound_dropped_oversized_payload_bytes
                .load(Ordering::Relaxed),
            inbound_dropped_socket_error_packets: self
                .inbound_dropped_socket_error_packets
                .load(Ordering::Relaxed),
            inbound_dropped_socket_error_payload_bytes: self
                .inbound_dropped_socket_error_payload_bytes
                .load(Ordering::Relaxed),
            inbound_dropped_non_wireguard_packets: self
                .inbound_dropped_non_wireguard_packets
                .load(Ordering::Relaxed),
            inbound_dropped_non_wireguard_payload_bytes: self
                .inbound_dropped_non_wireguard_payload_bytes
                .load(Ordering::Relaxed),
            last_forwarded_at: (last_forwarded_unix_millis >= 0)
                .then(|| DateTime::<Utc>::from_timestamp_millis(last_forwarded_unix_millis))
                .flatten(),
        }
    }

    fn record_forwarded_at(&self) {
        self.last_forwarded_unix_millis
            .store(Utc::now().timestamp_millis(), Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
pub struct UdpRelayFrameForwarder {
    session: RelaySessionState,
    wireguard_endpoint: SocketAddr,
    metrics: Option<Arc<RelayForwarderStats>>,
}

impl UdpRelayFrameForwarder {
    pub fn new(session: RelaySessionState, wireguard_endpoint: SocketAddr) -> Self {
        Self {
            session,
            wireguard_endpoint,
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: Arc<RelayForwarderStats>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn session(&self) -> &RelaySessionState {
        &self.session
    }

    pub fn wireguard_endpoint(&self) -> SocketAddr {
        self.wireguard_endpoint
    }

    pub fn encode_outbound(&self, payload: &[u8]) -> Result<Vec<u8>, AgentError> {
        self.ensure_session_active()?;
        let local = relay_session_local_node(&self.session.session_id, &self.session.peer)?;
        encode_relay_datagram_with_route(
            &self.session.session_id,
            &self.session.session_token,
            &local,
            &self.session.peer,
            payload,
        )
        .map_err(|error| AgentError::RelaySession(error.to_string()))
    }

    pub async fn send_to_relay(
        &self,
        socket: &tokio::net::UdpSocket,
        payload: &[u8],
    ) -> Result<usize, AgentError> {
        if !self.session_active() {
            if let Some(metrics) = &self.metrics {
                metrics.record_outbound_expired_session_drop(payload.len());
            }
            return Ok(0);
        }
        if !wireguard_datagram_payload(payload) {
            if let Some(metrics) = &self.metrics {
                metrics.record_outbound_drop(payload.len());
            }
            return Ok(0);
        }
        let datagram = self.encode_outbound(payload)?;
        if datagram.len() > MAX_FORWARDER_UDP_PAYLOAD_BYTES {
            if let Some(metrics) = &self.metrics {
                metrics.record_outbound_oversized_drop(payload.len(), datagram.len());
            }
            return Ok(0);
        }
        let bytes_sent = match socket.send_to(&datagram, self.session.relay_endpoint).await {
            Ok(bytes_sent) => bytes_sent,
            Err(_) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_outbound_socket_error_drop(payload.len(), datagram.len());
                }
                return Ok(0);
            }
        };
        if let Some(metrics) = &self.metrics {
            metrics.record_outbound(payload.len(), datagram.len());
        }
        Ok(bytes_sent)
    }

    pub async fn forward_to_wireguard(
        &self,
        socket: &tokio::net::UdpSocket,
        payload: &[u8],
    ) -> Result<usize, AgentError> {
        if !self.session_active() {
            if let Some(metrics) = &self.metrics {
                metrics.record_inbound_expired_session_drop(payload.len());
            }
            return Ok(0);
        }
        if !wireguard_datagram_payload(payload) {
            if let Some(metrics) = &self.metrics {
                metrics.record_inbound_drop(payload.len());
            }
            return Ok(0);
        }
        if payload.len() > MAX_FORWARDER_UDP_PAYLOAD_BYTES {
            if let Some(metrics) = &self.metrics {
                metrics.record_inbound_oversized_drop(payload.len());
            }
            return Ok(0);
        }
        let bytes_sent = match socket.send_to(payload, self.wireguard_endpoint).await {
            Ok(bytes_sent) => bytes_sent,
            Err(_) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_inbound_socket_error_drop(payload.len());
                }
                return Ok(0);
            }
        };
        if let Some(metrics) = &self.metrics {
            metrics.record_inbound(payload.len());
        }
        Ok(bytes_sent)
    }

    pub async fn serve(
        self,
        socket: tokio::net::UdpSocket,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), AgentError> {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                packet = socket.recv_from(&mut buffer) => {
                    let (len, peer) = match packet {
                        Ok(packet) => packet,
                        Err(error) if recoverable_udp_recv_error(&error) => {
                            if let Some(metrics) = &self.metrics {
                                metrics.record_socket_receive_error();
                            }
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    };
                    if peer == self.session.relay_endpoint {
                        self.forward_to_wireguard(&socket, &buffer[..len]).await?;
                    } else if wireguard_sender_matches_configured(self.wireguard_endpoint, peer) {
                        self.send_to_relay(&socket, &buffer[..len]).await?;
                    } else {
                        if let Some(metrics) = &self.metrics {
                            metrics.record_outbound_unexpected_source_drop(len);
                        }
                    }
                }
            }
        }
    }

    fn session_active(&self) -> bool {
        Utc::now() < self.session.expires_at
    }

    fn ensure_session_active(&self) -> Result<(), AgentError> {
        if !self.session_active() {
            return Err(AgentError::RelaySession(format!(
                "relay session {} expired at {}",
                self.session.session_id, self.session.expires_at
            )));
        }
        Ok(())
    }
}

fn relay_session_local_node(session_id: &str, peer: &NodeId) -> Result<NodeId, AgentError> {
    let Some((left, right)) = session_id.split_once(':') else {
        return Err(AgentError::RelaySession(format!(
            "relay session {session_id} does not encode left/right node ids"
        )));
    };
    if peer.as_str() == left {
        Ok(NodeId::from_string(right))
    } else if peer.as_str() == right {
        Ok(NodeId::from_string(left))
    } else {
        Err(AgentError::RelaySession(format!(
            "relay peer {peer} is not part of session {session_id}"
        )))
    }
}

fn recoverable_udp_recv_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
    )
}

fn wireguard_sender_matches_configured(configured: SocketAddr, observed: SocketAddr) -> bool {
    if configured.port() != observed.port() {
        return false;
    }
    match (configured.ip(), observed.ip()) {
        (IpAddr::V4(configured), IpAddr::V4(observed)) => {
            configured.is_unspecified() || configured == observed
        }
        (IpAddr::V6(configured), IpAddr::V6(observed)) => {
            configured.is_unspecified() || configured == observed
        }
        _ => false,
    }
}

fn wireguard_datagram_payload(payload: &[u8]) -> bool {
    if payload.len() < 4 || payload.get(1..4) != Some(&[0, 0, 0]) {
        return false;
    }
    match payload[0] {
        1 => payload.len() == 148,
        2 => payload.len() == 92,
        3 => payload.len() == 64,
        4 => payload.len() >= 32 && payload.len().is_multiple_of(16),
        _ => false,
    }
}

impl AgentRuntime {
    pub fn new(state: AgentNodeState, policy: ClusterPolicy) -> Self {
        Self {
            state: RwLock::new(state),
            candidates: tokio::sync::RwLock::new(Vec::new()),
            nat_classification: tokio::sync::RwLock::new(None),
            path_state: tokio::sync::RwLock::new(BTreeMap::new()),
            path_change_events: tokio::sync::RwLock::new(VecDeque::new()),
            relay_sessions: tokio::sync::RwLock::new(BTreeMap::new()),
            relay_forwarder_endpoints: tokio::sync::RwLock::new(BTreeMap::new()),
            relay_forwarder_metrics: tokio::sync::RwLock::new(BTreeMap::new()),
            userspace_wireguard_process: tokio::sync::RwLock::new(None),
            lazy_connect: tokio::sync::RwLock::new(LazyConnectManager::new(policy)),
            relay_admission_attempt_count: AtomicU64::new(0),
            relay_admission_success_count: AtomicU64::new(0),
            relay_admission_failure_count: AtomicU64::new(0),
            relay_admission_failure_reason_counters:
                AgentRelayAdmissionFailureReasonCounters::default(),
            path_probe_record_count: AtomicU64::new(0),
            peer_activity_record_count: AtomicU64::new(0),
            packet_flow_observation_count: AtomicU64::new(0),
            packet_flow_match_count: AtomicU64::new(0),
            packet_flow_unmatched_count: AtomicU64::new(0),
            packet_flow_filtered_count: AtomicU64::new(0),
            packet_flow_duplicate_suppression_count: AtomicU64::new(0),
            packet_flow_duplicate_suppression_proc_net_conntrack_count: AtomicU64::new(0),
            packet_flow_duplicate_suppression_conntrack_netlink_count: AtomicU64::new(0),
            packet_flow_duplicate_suppression_conntrack_netlink_events_count: AtomicU64::new(0),
            packet_flow_duplicate_suppression_ebpf_jsonl_count: AtomicU64::new(0),
            packet_flow_duplicate_suppression_ebpf_ringbuf_count: AtomicU64::new(0),
            packet_flow_filtered_unspecified_count: AtomicU64::new(0),
            packet_flow_filtered_loopback_count: AtomicU64::new(0),
            packet_flow_filtered_multicast_count: AtomicU64::new(0),
            packet_flow_filtered_broadcast_count: AtomicU64::new(0),
            packet_flow_filtered_link_local_count: AtomicU64::new(0),
            packet_flow_filtered_no_overlay_match_count: AtomicU64::new(0),
            packet_flow_filtered_inconsistent_transport_metadata_count: AtomicU64::new(0),
            packet_flow_classification_unknown_count: AtomicU64::new(0),
            packet_flow_classification_opening_count: AtomicU64::new(0),
            packet_flow_classification_unreplied_count: AtomicU64::new(0),
            packet_flow_classification_assured_count: AtomicU64::new(0),
            packet_flow_classification_established_count: AtomicU64::new(0),
            packet_flow_classification_closing_count: AtomicU64::new(0),
            packet_flow_classification_closed_count: AtomicU64::new(0),
            packet_flow_application_unknown_count: AtomicU64::new(0),
            packet_flow_application_dns_count: AtomicU64::new(0),
            packet_flow_application_http_count: AtomicU64::new(0),
            packet_flow_application_https_count: AtomicU64::new(0),
            packet_flow_application_ssh_count: AtomicU64::new(0),
            packet_flow_application_ldap_count: AtomicU64::new(0),
            packet_flow_application_smb_count: AtomicU64::new(0),
            packet_flow_application_nfs_count: AtomicU64::new(0),
            packet_flow_application_rdp_count: AtomicU64::new(0),
            packet_flow_application_kubernetes_api_count: AtomicU64::new(0),
            packet_flow_application_etcd_count: AtomicU64::new(0),
            packet_flow_application_zookeeper_count: AtomicU64::new(0),
            packet_flow_application_consul_count: AtomicU64::new(0),
            packet_flow_application_vault_count: AtomicU64::new(0),
            packet_flow_application_nomad_count: AtomicU64::new(0),
            packet_flow_application_postgres_count: AtomicU64::new(0),
            packet_flow_application_mysql_count: AtomicU64::new(0),
            packet_flow_application_mssql_count: AtomicU64::new(0),
            packet_flow_application_oracle_count: AtomicU64::new(0),
            packet_flow_application_clickhouse_count: AtomicU64::new(0),
            packet_flow_application_influxdb_count: AtomicU64::new(0),
            packet_flow_application_redis_count: AtomicU64::new(0),
            packet_flow_application_memcached_count: AtomicU64::new(0),
            packet_flow_application_prometheus_count: AtomicU64::new(0),
            packet_flow_application_opentelemetry_count: AtomicU64::new(0),
            packet_flow_application_syslog_count: AtomicU64::new(0),
            packet_flow_application_jaeger_count: AtomicU64::new(0),
            packet_flow_application_loki_count: AtomicU64::new(0),
            packet_flow_application_tempo_count: AtomicU64::new(0),
            packet_flow_application_zipkin_count: AtomicU64::new(0),
            packet_flow_application_grpc_count: AtomicU64::new(0),
            packet_flow_application_kafka_count: AtomicU64::new(0),
            packet_flow_application_nats_count: AtomicU64::new(0),
            packet_flow_application_mqtt_count: AtomicU64::new(0),
            packet_flow_application_amqp_count: AtomicU64::new(0),
            packet_flow_application_cassandra_count: AtomicU64::new(0),
            packet_flow_application_mongodb_count: AtomicU64::new(0),
            packet_flow_application_elasticsearch_count: AtomicU64::new(0),
            packet_flow_application_wireguard_count: AtomicU64::new(0),
            packet_flow_application_icmp_count: AtomicU64::new(0),
        }
    }

    pub fn state(&self) -> AgentNodeState {
        match self.state.read() {
            Ok(state) => state.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn replace_state(&self, state: AgentNodeState) {
        match self.state.write() {
            Ok(mut current) => *current = state,
            Err(poisoned) => *poisoned.into_inner() = state,
        }
    }

    pub async fn record_userspace_wireguard_process_status(
        &self,
        state: AgentManagedProcessState,
        pid: Option<u32>,
        exit_status: Option<String>,
        message: Option<String>,
    ) {
        *self.userspace_wireguard_process.write().await = Some(AgentManagedProcessStatus {
            state,
            pid,
            exit_status,
            message,
            updated_at: Utc::now(),
        });
    }

    pub async fn userspace_wireguard_process_status(&self) -> Option<AgentManagedProcessStatus> {
        self.userspace_wireguard_process.read().await.clone()
    }

    pub fn wireguard_key_rotation_request(
        &self,
        next_wireguard_public_key: String,
        signed_at: DateTime<Utc>,
    ) -> Result<RotateWireGuardKeyRequest, AgentError> {
        let state = self.state();
        let identity = state.identity_key_pair()?;
        let mut request = RotateWireGuardKeyRequest {
            node_id: state.node_id,
            previous_wireguard_public_key: state.wireguard_public_key_b64,
            next_wireguard_public_key,
            node_signature: None,
        };
        request.node_signature =
            Some(identity.sign_wireguard_key_rotation_request(&request, signed_at)?);
        Ok(request)
    }

    pub fn plan_wireguard_key_rotation(
        &self,
        signed_at: DateTime<Utc>,
    ) -> Result<AgentWireGuardKeyRotationPlan, AgentError> {
        let current_state = self.state();
        let next_wireguard = WireGuardKeyPair::generate();
        let mut next_state = current_state.clone();
        next_state.wireguard_private_key_b64 = next_wireguard.private_key_b64;
        next_state.wireguard_public_key_b64 = next_wireguard.public_key_b64.clone();
        next_state.updated_at = signed_at;
        let request =
            self.wireguard_key_rotation_request(next_wireguard.public_key_b64.clone(), signed_at)?;
        Ok(AgentWireGuardKeyRotationPlan {
            next_state,
            request,
            previous_wireguard_public_key: current_state.wireguard_public_key_b64,
            next_wireguard_public_key: next_wireguard.public_key_b64,
        })
    }

    pub async fn status(&self) -> AgentStatusResponse {
        let state = self.state();
        let candidates = self.candidates.read().await.clone();
        let nat_classification = self.nat_classification.read().await.clone();
        let userspace_wireguard_process = self.userspace_wireguard_process.read().await.clone();
        AgentStatusResponse {
            node_id: state.node_id,
            identity_public_key: state.identity_public_key_b64,
            wireguard_public_key: state.wireguard_public_key_b64,
            candidate_count: candidates.len(),
            candidates,
            nat_classification,
            userspace_wireguard_process,
            state_updated_at: state.updated_at,
        }
    }

    pub async fn replace_candidates(&self, candidates: Vec<EndpointCandidate>) {
        *self.candidates.write().await = candidates;
    }

    pub async fn probe_stun(
        &self,
        local_bind: std::net::SocketAddr,
        stun_server: std::net::SocketAddr,
    ) -> Result<EndpointCandidate, AgentError> {
        let candidate = UdpStunProbe
            .probe(self.state().node_id, local_bind, stun_server)
            .await?;
        self.candidates.write().await.push(candidate.clone());
        Ok(candidate)
    }

    pub async fn classify_nat(
        &self,
        local_bind: std::net::SocketAddr,
        stun_servers: Vec<std::net::SocketAddr>,
    ) -> Result<NatClassification, AgentError> {
        if stun_servers.is_empty() {
            return Err(AgentError::Stun(StunError::InvalidResponse(
                "at least one STUN server is required for NAT classification".to_string(),
            )));
        }

        let observations = UdpStunProbe
            .observe_binding_many(local_bind, &stun_servers)
            .await?;
        let filtering_observations = match stun_servers.first().copied() {
            Some(stun_server) => UdpStunProbe
                .observe_filtering(local_bind, stun_server)
                .await
                .unwrap_or_default(),
            None => Vec::new(),
        };
        let local_addr = observations
            .first()
            .map(|observation| observation.local_addr)
            .unwrap_or(local_bind);
        let classification = NatClassification::from_observations_with_filtering(
            local_addr,
            observations.clone(),
            filtering_observations,
            Utc::now(),
        );

        let mut candidates = self.candidates.write().await;
        candidates.extend(
            observations
                .iter()
                .map(|observation| self.stun_candidate_from_observation(observation)),
        );
        *self.nat_classification.write().await = Some(classification.clone());

        Ok(classification)
    }

    fn stun_candidate_from_observation(
        &self,
        observation: &NatProbeObservation,
    ) -> EndpointCandidate {
        EndpointCandidate {
            node_id: self.state().node_id,
            kind: EndpointCandidateKind::StunReflexive,
            addr: observation.reflexive_addr,
            observed_at: observation.observed_at,
            priority: 80,
            cost: 20,
            source: CandidateSource::StunProbe,
        }
    }

    pub async fn path_state(&self) -> Vec<PathRecord> {
        self.path_state.read().await.values().cloned().collect()
    }

    pub async fn path_change_events(&self) -> Vec<PathChangeEvent> {
        self.path_change_events
            .read()
            .await
            .iter()
            .cloned()
            .collect()
    }

    pub async fn metrics(&self) -> AgentMetricsResponse {
        self.purge_expired_relay_sessions(Utc::now()).await;
        let candidates = self.candidates.read().await;
        let path_state = self.path_state.read().await;
        let relay_sessions = self.relay_sessions.read().await;
        let relay_forwarders = self.relay_forwarder_endpoints.read().await;
        let relay_forwarder_metrics = self.relay_forwarder_metrics.read().await;
        let userspace_wireguard_process = self.userspace_wireguard_process.read().await.clone();
        let path_change_events = self.path_change_events.read().await;
        let lazy_connect = self.lazy_connect.read().await;
        let mut path_state_counts = BTreeMap::<PathState, usize>::new();
        for path in path_state.values() {
            *path_state_counts.entry(path.selected_state).or_default() += 1;
        }

        let state = self.state();
        AgentMetricsResponse {
            node_id: state.node_id,
            candidate_count: candidates.len(),
            path_count: path_state.len(),
            relay_session_count: relay_sessions.len(),
            relay_admission_attempt_count: self
                .relay_admission_attempt_count
                .load(Ordering::Relaxed),
            relay_admission_success_count: self
                .relay_admission_success_count
                .load(Ordering::Relaxed),
            relay_admission_failure_count: self
                .relay_admission_failure_count
                .load(Ordering::Relaxed),
            relay_admission_failure_reason_counts: self
                .relay_admission_failure_reason_counters
                .snapshot(),
            relay_forwarder_count: relay_forwarders.len(),
            relay_forwarders: relay_forwarder_metrics
                .values()
                .map(|metrics| metrics.snapshot())
                .collect(),
            path_change_event_count: path_change_events.len(),
            path_state_counts: PATH_STATE_METRIC_ORDER
                .into_iter()
                .map(|state| PathStateCount {
                    state,
                    count: *path_state_counts.get(&state).unwrap_or(&0),
                })
                .collect(),
            lazy_connect: lazy_connect.metrics(),
            path_probe_record_count: self.path_probe_record_count.load(Ordering::Relaxed),
            peer_activity_record_count: self.peer_activity_record_count.load(Ordering::Relaxed),
            packet_flow_observation_count: self
                .packet_flow_observation_count
                .load(Ordering::Relaxed),
            packet_flow_match_count: self.packet_flow_match_count.load(Ordering::Relaxed),
            packet_flow_unmatched_count: self.packet_flow_unmatched_count.load(Ordering::Relaxed),
            packet_flow_filtered_count: self.packet_flow_filtered_count.load(Ordering::Relaxed),
            packet_flow_filtered_reason_counts: self.packet_flow_filtered_reason_counts(),
            packet_flow_duplicate_suppression_count: self
                .packet_flow_duplicate_suppression_count
                .load(Ordering::Relaxed),
            packet_flow_duplicate_suppression_counts: self
                .packet_flow_duplicate_suppression_counts(),
            packet_flow_classification_counts: self.packet_flow_classification_counts(),
            packet_flow_application_counts: self.packet_flow_application_counts(),
            userspace_wireguard_process,
            generated_at: Utc::now(),
        }
    }

    pub async fn path_record_for_peer(&self, peer: &NodeId) -> Option<PathRecord> {
        self.path_state
            .read()
            .await
            .get(&(self.state().node_id, peer.clone()))
            .cloned()
    }

    pub async fn record_path_probe(
        &self,
        request: AgentPathProbeRequest,
        recorded_at: DateTime<Utc>,
    ) -> PathRecord {
        let path = PathRecord {
            key: ipars_types::PeerPathKey::new(self.state().node_id, request.peer),
            selected_state: request.selected_state,
            selected_candidate: request.selected_candidate,
            relay_node: request.relay_node,
            score: PathScore::calculate(
                request.selected_state,
                &request.metrics,
                request.policy_allowed,
                request.cost,
            ),
            updated_at: recorded_at,
            pinned: request.pin,
        };
        self.path_probe_record_count.fetch_add(1, Ordering::Relaxed);
        self.upsert_path_state(path.clone()).await;
        path
    }

    pub async fn upsert_path_state(&self, record: PathRecord) {
        let remote = record.key.remote.clone();
        let selected_state = record.selected_state;
        let previous = self.path_state.write().await.insert(
            (record.key.local.clone(), record.key.remote.clone()),
            record.clone(),
        );
        if record.pinned {
            self.lazy_connect
                .write()
                .await
                .pin_peer(record.key.remote.clone());
        }
        if let Some(event) = path_change_event(previous.as_ref(), &record) {
            let mut events = self.path_change_events.write().await;
            if events.len() >= MAX_PATH_CHANGE_EVENTS {
                events.pop_front();
            }
            events.push_back(event);
        }
        if selected_state != PathState::Relay {
            self.remove_relay_session(&remote).await;
        }
    }

    pub async fn upsert_relay_session(&self, session: RelaySessionState) {
        self.relay_sessions
            .write()
            .await
            .insert(session.peer.clone(), session);
    }

    pub fn record_relay_admission_attempt(&self) {
        self.relay_admission_attempt_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_relay_admission_success(&self) {
        self.relay_admission_success_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_relay_admission_failure(&self) {
        self.record_relay_admission_failure_reason(AgentRelayAdmissionFailureReason::Unavailable);
    }

    pub fn record_relay_admission_failure_reason(&self, reason: AgentRelayAdmissionFailureReason) {
        self.relay_admission_failure_count
            .fetch_add(1, Ordering::Relaxed);
        self.relay_admission_failure_reason_counters.record(reason);
    }

    pub async fn relay_session(&self, peer: &NodeId) -> Option<RelaySessionState> {
        self.active_relay_session(peer, Utc::now()).await
    }

    pub async fn relay_sessions(&self) -> Vec<RelaySessionState> {
        self.purge_expired_relay_sessions(Utc::now()).await;
        self.relay_sessions.read().await.values().cloned().collect()
    }

    pub async fn active_relay_session(
        &self,
        peer: &NodeId,
        now: DateTime<Utc>,
    ) -> Option<RelaySessionState> {
        let expired = {
            let mut relay_sessions = self.relay_sessions.write().await;
            match relay_sessions.get(peer) {
                Some(session) if session.expires_at > now => return Some(session.clone()),
                Some(_) => relay_sessions.remove(peer),
                None => None,
            }
        };
        if expired.is_some() {
            self.remove_relay_forwarder_endpoint(peer).await;
        }
        None
    }

    pub async fn purge_expired_relay_sessions(&self, now: DateTime<Utc>) -> Vec<RelaySessionState> {
        let expired = {
            let mut relay_sessions = self.relay_sessions.write().await;
            let expired_peers = relay_sessions
                .iter()
                .filter(|(_, session)| session.expires_at <= now)
                .map(|(peer, _)| peer.clone())
                .collect::<Vec<_>>();
            expired_peers
                .into_iter()
                .filter_map(|peer| relay_sessions.remove(&peer))
                .collect::<Vec<_>>()
        };
        if !expired.is_empty() {
            let mut relay_forwarder_endpoints = self.relay_forwarder_endpoints.write().await;
            let mut relay_forwarder_metrics = self.relay_forwarder_metrics.write().await;
            for session in &expired {
                relay_forwarder_endpoints.remove(&session.peer);
                relay_forwarder_metrics.remove(&session.peer);
            }
        }
        expired
    }

    pub async fn remove_relay_session(&self, peer: &NodeId) -> Option<RelaySessionState> {
        let removed = self.relay_sessions.write().await.remove(peer);
        self.remove_relay_forwarder_endpoint(peer).await;
        removed
    }

    pub async fn upsert_relay_forwarder_endpoint(&self, peer: NodeId, endpoint: SocketAddr) {
        self.relay_forwarder_endpoints
            .write()
            .await
            .insert(peer, endpoint);
    }

    pub async fn register_relay_forwarder_metrics(&self, metrics: Arc<RelayForwarderStats>) {
        self.relay_forwarder_metrics
            .write()
            .await
            .insert(metrics.peer().clone(), metrics);
    }

    pub async fn relay_forwarder_endpoint(&self, peer: &NodeId) -> Option<SocketAddr> {
        self.relay_forwarder_endpoints
            .read()
            .await
            .get(peer)
            .copied()
    }

    pub async fn remove_relay_forwarder_endpoint(&self, peer: &NodeId) -> Option<SocketAddr> {
        self.relay_forwarder_metrics.write().await.remove(peer);
        self.relay_forwarder_endpoints.write().await.remove(peer)
    }

    pub async fn relay_forwarder_endpoints(&self) -> BTreeMap<NodeId, SocketAddr> {
        self.relay_forwarder_endpoints.read().await.clone()
    }

    pub async fn relay_session_needs_renewal(
        &self,
        peer: &NodeId,
        relay_node: &NodeId,
        now: DateTime<Utc>,
        renew_before: Duration,
    ) -> bool {
        let renew_before = chrono::Duration::from_std(renew_before)
            .unwrap_or_else(|_| chrono::Duration::seconds(i64::MAX));
        self.active_relay_session(peer, now)
            .await
            .map(|session| {
                session.relay_node != *relay_node || now + renew_before >= session.expires_at
            })
            .unwrap_or(true)
    }

    pub async fn relay_forwarder_endpoint_for_peer(
        &self,
        peer: &NodeId,
        now: DateTime<Utc>,
        fallback_forwarder_endpoint: Option<SocketAddr>,
    ) -> Option<SocketAddr> {
        let path = self.path_record_for_peer(peer).await?;
        if path.selected_state != PathState::Relay {
            return None;
        }

        let session = self.active_relay_session(peer, now).await?;
        if path.relay_node.as_ref() != Some(&session.relay_node) {
            return None;
        }

        self.relay_forwarder_endpoint(peer)
            .await
            .or(fallback_forwarder_endpoint)
    }

    pub async fn idle_peers_to_close(&self, now: DateTime<Utc>) -> Vec<NodeId> {
        self.lazy_connect.read().await.idle_peers_to_close(now)
    }

    pub async fn record_peer_activity(&self, peer: NodeId, at: DateTime<Utc>, pin: bool) -> bool {
        self.peer_activity_record_count
            .fetch_add(1, Ordering::Relaxed);
        let mut lazy_connect = self.lazy_connect.write().await;
        lazy_connect.record_activity(peer.clone(), at);
        if pin {
            lazy_connect.pin_peer(peer.clone());
        }
        lazy_connect.is_pinned(&peer)
    }

    pub async fn record_packet_flow_activity(
        &self,
        destination: IpAddr,
        at: DateTime<Utc>,
        pin: bool,
    ) -> Option<AgentPacketFlowMatch> {
        self.record_packet_flow_observation(
            destination,
            AgentPacketFlowObservation::default(),
            at,
            pin,
        )
        .await
    }

    pub async fn record_packet_flow_observation(
        &self,
        destination: IpAddr,
        observation: AgentPacketFlowObservation,
        at: DateTime<Utc>,
        pin: bool,
    ) -> Option<AgentPacketFlowMatch> {
        if observation.validate_transport_metadata().is_err() {
            self.record_packet_flow_filtered(
                AgentPacketFlowDropReason::InconsistentTransportMetadata,
            );
            return None;
        }
        if let Some(reason) = packet_flow_destination_drop_reason(destination) {
            self.record_packet_flow_filtered(reason);
            return None;
        }
        self.packet_flow_observation_count
            .fetch_add(1, Ordering::Relaxed);
        self.packet_flow_classification_counter(observation.classification())
            .fetch_add(1, Ordering::Relaxed);
        self.packet_flow_application_counter(observation.application())
            .fetch_add(1, Ordering::Relaxed);
        let mut lazy_connect = self.lazy_connect.write().await;
        let Some(mut matched) = lazy_connect.resolve_packet_flow_destination(destination) else {
            self.packet_flow_unmatched_count
                .fetch_add(1, Ordering::Relaxed);
            self.record_packet_flow_filtered(AgentPacketFlowDropReason::NoOverlayMatch);
            return None;
        };
        lazy_connect.record_activity(matched.peer.clone(), at);
        if pin {
            lazy_connect.pin_peer(matched.peer.clone());
        }
        matched.pinned = lazy_connect.is_pinned(&matched.peer);
        self.packet_flow_match_count.fetch_add(1, Ordering::Relaxed);
        Some(matched)
    }

    pub fn record_packet_flow_filtered(&self, reason: AgentPacketFlowDropReason) {
        self.packet_flow_filtered_count
            .fetch_add(1, Ordering::Relaxed);
        self.packet_flow_filtered_counter(reason)
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_packet_flow_duplicate_suppression(
        &self,
        source: AgentPacketFlowDuplicateSource,
        count: u64,
    ) {
        if count == 0 {
            return;
        }
        self.packet_flow_duplicate_suppression_count
            .fetch_add(count, Ordering::Relaxed);
        self.packet_flow_duplicate_suppression_counter(source)
            .fetch_add(count, Ordering::Relaxed);
    }

    fn packet_flow_filtered_reason_counts(&self) -> Vec<AgentPacketFlowDropReasonCount> {
        AgentPacketFlowDropReason::ALL
            .into_iter()
            .map(|reason| AgentPacketFlowDropReasonCount {
                reason,
                count: self
                    .packet_flow_filtered_counter(reason)
                    .load(Ordering::Relaxed),
            })
            .collect()
    }

    fn packet_flow_filtered_counter(&self, reason: AgentPacketFlowDropReason) -> &AtomicU64 {
        match reason {
            AgentPacketFlowDropReason::Unspecified => &self.packet_flow_filtered_unspecified_count,
            AgentPacketFlowDropReason::Loopback => &self.packet_flow_filtered_loopback_count,
            AgentPacketFlowDropReason::Multicast => &self.packet_flow_filtered_multicast_count,
            AgentPacketFlowDropReason::Broadcast => &self.packet_flow_filtered_broadcast_count,
            AgentPacketFlowDropReason::LinkLocal => &self.packet_flow_filtered_link_local_count,
            AgentPacketFlowDropReason::NoOverlayMatch => {
                &self.packet_flow_filtered_no_overlay_match_count
            }
            AgentPacketFlowDropReason::InconsistentTransportMetadata => {
                &self.packet_flow_filtered_inconsistent_transport_metadata_count
            }
        }
    }

    fn packet_flow_duplicate_suppression_counts(&self) -> Vec<AgentPacketFlowDuplicateSourceCount> {
        AgentPacketFlowDuplicateSource::ALL
            .into_iter()
            .map(|source| AgentPacketFlowDuplicateSourceCount {
                source,
                count: self
                    .packet_flow_duplicate_suppression_counter(source)
                    .load(Ordering::Relaxed),
            })
            .collect()
    }

    fn packet_flow_duplicate_suppression_counter(
        &self,
        source: AgentPacketFlowDuplicateSource,
    ) -> &AtomicU64 {
        match source {
            AgentPacketFlowDuplicateSource::ProcNetConntrack => {
                &self.packet_flow_duplicate_suppression_proc_net_conntrack_count
            }
            AgentPacketFlowDuplicateSource::ConntrackNetlink => {
                &self.packet_flow_duplicate_suppression_conntrack_netlink_count
            }
            AgentPacketFlowDuplicateSource::ConntrackNetlinkEvents => {
                &self.packet_flow_duplicate_suppression_conntrack_netlink_events_count
            }
            AgentPacketFlowDuplicateSource::EbpfJsonl => {
                &self.packet_flow_duplicate_suppression_ebpf_jsonl_count
            }
            AgentPacketFlowDuplicateSource::EbpfRingbuf => {
                &self.packet_flow_duplicate_suppression_ebpf_ringbuf_count
            }
        }
    }

    fn packet_flow_classification_counts(&self) -> Vec<AgentPacketFlowClassificationCount> {
        AgentPacketFlowClassification::ALL
            .into_iter()
            .map(|classification| AgentPacketFlowClassificationCount {
                classification,
                count: self
                    .packet_flow_classification_counter(classification)
                    .load(Ordering::Relaxed),
            })
            .collect()
    }

    fn packet_flow_classification_counter(
        &self,
        classification: AgentPacketFlowClassification,
    ) -> &AtomicU64 {
        match classification {
            AgentPacketFlowClassification::Unknown => {
                &self.packet_flow_classification_unknown_count
            }
            AgentPacketFlowClassification::Opening => {
                &self.packet_flow_classification_opening_count
            }
            AgentPacketFlowClassification::Unreplied => {
                &self.packet_flow_classification_unreplied_count
            }
            AgentPacketFlowClassification::Assured => {
                &self.packet_flow_classification_assured_count
            }
            AgentPacketFlowClassification::Established => {
                &self.packet_flow_classification_established_count
            }
            AgentPacketFlowClassification::Closing => {
                &self.packet_flow_classification_closing_count
            }
            AgentPacketFlowClassification::Closed => &self.packet_flow_classification_closed_count,
        }
    }

    fn packet_flow_application_counts(&self) -> Vec<AgentPacketFlowApplicationCount> {
        AgentPacketFlowApplication::ALL
            .into_iter()
            .map(|application| AgentPacketFlowApplicationCount {
                application,
                count: self
                    .packet_flow_application_counter(application)
                    .load(Ordering::Relaxed),
            })
            .collect()
    }

    fn packet_flow_application_counter(
        &self,
        application: AgentPacketFlowApplication,
    ) -> &AtomicU64 {
        match application {
            AgentPacketFlowApplication::Unknown => &self.packet_flow_application_unknown_count,
            AgentPacketFlowApplication::Dns => &self.packet_flow_application_dns_count,
            AgentPacketFlowApplication::Http => &self.packet_flow_application_http_count,
            AgentPacketFlowApplication::Https => &self.packet_flow_application_https_count,
            AgentPacketFlowApplication::Ssh => &self.packet_flow_application_ssh_count,
            AgentPacketFlowApplication::Ldap => &self.packet_flow_application_ldap_count,
            AgentPacketFlowApplication::Smb => &self.packet_flow_application_smb_count,
            AgentPacketFlowApplication::Nfs => &self.packet_flow_application_nfs_count,
            AgentPacketFlowApplication::Rdp => &self.packet_flow_application_rdp_count,
            AgentPacketFlowApplication::KubernetesApi => {
                &self.packet_flow_application_kubernetes_api_count
            }
            AgentPacketFlowApplication::Etcd => &self.packet_flow_application_etcd_count,
            AgentPacketFlowApplication::ZooKeeper => &self.packet_flow_application_zookeeper_count,
            AgentPacketFlowApplication::Consul => &self.packet_flow_application_consul_count,
            AgentPacketFlowApplication::Vault => &self.packet_flow_application_vault_count,
            AgentPacketFlowApplication::Nomad => &self.packet_flow_application_nomad_count,
            AgentPacketFlowApplication::Postgres => &self.packet_flow_application_postgres_count,
            AgentPacketFlowApplication::Mysql => &self.packet_flow_application_mysql_count,
            AgentPacketFlowApplication::MsSql => &self.packet_flow_application_mssql_count,
            AgentPacketFlowApplication::Oracle => &self.packet_flow_application_oracle_count,
            AgentPacketFlowApplication::ClickHouse => {
                &self.packet_flow_application_clickhouse_count
            }
            AgentPacketFlowApplication::InfluxDb => &self.packet_flow_application_influxdb_count,
            AgentPacketFlowApplication::Redis => &self.packet_flow_application_redis_count,
            AgentPacketFlowApplication::Memcached => &self.packet_flow_application_memcached_count,
            AgentPacketFlowApplication::Prometheus => {
                &self.packet_flow_application_prometheus_count
            }
            AgentPacketFlowApplication::OpenTelemetry => {
                &self.packet_flow_application_opentelemetry_count
            }
            AgentPacketFlowApplication::Syslog => &self.packet_flow_application_syslog_count,
            AgentPacketFlowApplication::Jaeger => &self.packet_flow_application_jaeger_count,
            AgentPacketFlowApplication::Loki => &self.packet_flow_application_loki_count,
            AgentPacketFlowApplication::Tempo => &self.packet_flow_application_tempo_count,
            AgentPacketFlowApplication::Zipkin => &self.packet_flow_application_zipkin_count,
            AgentPacketFlowApplication::Grpc => &self.packet_flow_application_grpc_count,
            AgentPacketFlowApplication::Kafka => &self.packet_flow_application_kafka_count,
            AgentPacketFlowApplication::Nats => &self.packet_flow_application_nats_count,
            AgentPacketFlowApplication::Mqtt => &self.packet_flow_application_mqtt_count,
            AgentPacketFlowApplication::Amqp => &self.packet_flow_application_amqp_count,
            AgentPacketFlowApplication::Cassandra => &self.packet_flow_application_cassandra_count,
            AgentPacketFlowApplication::MongoDb => &self.packet_flow_application_mongodb_count,
            AgentPacketFlowApplication::Elasticsearch => {
                &self.packet_flow_application_elasticsearch_count
            }
            AgentPacketFlowApplication::WireGuard => &self.packet_flow_application_wireguard_count,
            AgentPacketFlowApplication::Icmp => &self.packet_flow_application_icmp_count,
        }
    }

    pub async fn observe_peer_map_for_lazy_connect(&self, peers: &[NodeRecord]) {
        let mut lazy_connect = self.lazy_connect.write().await;
        for peer in peers {
            lazy_connect.observe_peer(peer);
        }
    }

    pub async fn should_connect_peer(&self, peer: &NodeRecord) -> bool {
        self.lazy_connect.read().await.should_connect_peer(peer)
    }

    pub async fn take_idle_peers_to_close(&self, now: DateTime<Utc>) -> Vec<NodeId> {
        let mut lazy_connect = self.lazy_connect.write().await;
        let idle_peers = lazy_connect.idle_peers_to_close(now);
        for peer in &idle_peers {
            lazy_connect.remove_activity(peer);
        }
        idle_peers
    }
}

fn path_change_event(
    previous: Option<&PathRecord>,
    current: &PathRecord,
) -> Option<PathChangeEvent> {
    let kind = match previous {
        None => PathChangeKind::Created,
        Some(previous) if previous.selected_state != current.selected_state => {
            PathChangeKind::StateChanged
        }
        Some(previous) if previous.relay_node != current.relay_node => PathChangeKind::RelayChanged,
        Some(previous) if previous.selected_candidate != current.selected_candidate => {
            PathChangeKind::CandidateChanged
        }
        Some(previous) if previous.score != current.score => PathChangeKind::ScoreChanged,
        Some(_) => return None,
    };

    Some(PathChangeEvent {
        key: current.key.clone(),
        kind,
        previous_state: previous.map(|path| path.selected_state),
        new_state: current.selected_state,
        previous_relay_node: previous.and_then(|path| path.relay_node.clone()),
        new_relay_node: current.relay_node.clone(),
        previous_candidate: previous.and_then(|path| path.selected_candidate.clone()),
        new_candidate: current.selected_candidate.clone(),
        previous_score: previous.map(|path| path.score.clone()),
        new_score: current.score.clone(),
        changed_at: current.updated_at,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardPeerConfig {
    pub peer: NodeId,
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive_seconds: Option<u16>,
}

#[async_trait]
pub trait WireGuardBackend: Send + Sync {
    async fn upsert_peer(&self, config: WireGuardPeerConfig) -> Result<(), AgentError>;
    async fn remove_peer(&self, peer: &NodeId) -> Result<(), AgentError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl LinuxCommand {
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn in_namespace(self, namespace: &LinuxNetworkNamespace) -> Self {
        let (program, args) = namespace.wrap_program_args(&self.program, &self.args);
        Self { program, args }
    }
}

#[derive(Debug, Clone)]
pub struct UdpHolePuncher {
    local_bind: std::net::SocketAddr,
    attempts: usize,
    interval: Duration,
}

impl UdpHolePuncher {
    pub fn new(local_bind: std::net::SocketAddr) -> Self {
        Self {
            local_bind,
            attempts: 5,
            interval: Duration::from_millis(100),
        }
    }

    pub fn with_attempts(mut self, attempts: usize) -> Self {
        self.attempts = attempts.max(1);
        self
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    pub async fn execute(
        &self,
        local_node: &NodeId,
        plan: &SignalHolePunchPlanResponse,
    ) -> Result<usize, AgentError> {
        let socket = tokio::net::UdpSocket::bind(self.local_bind).await?;
        self.execute_on_socket(local_node, plan, &socket).await
    }

    pub async fn execute_on_socket(
        &self,
        local_node: &NodeId,
        plan: &SignalHolePunchPlanResponse,
        socket: &tokio::net::UdpSocket,
    ) -> Result<usize, AgentError> {
        let remote_addr = remote_reflexive_addr(local_node, plan)?;
        if Utc::now() >= plan.expires_at {
            return Err(AgentError::HolePunch("hole punch plan expired".to_string()));
        }

        if plan.start_after_millis > 0 {
            tokio::time::sleep(Duration::from_millis(plan.start_after_millis)).await;
        }

        let payload = hole_punch_payload(local_node, plan);
        for attempt in 0..self.attempts {
            socket.send_to(payload.as_bytes(), remote_addr).await?;
            if attempt + 1 < self.attempts && !self.interval.is_zero() {
                tokio::time::sleep(self.interval).await;
            }
        }
        Ok(self.attempts)
    }
}

fn remote_reflexive_addr(
    local_node: &NodeId,
    plan: &SignalHolePunchPlanResponse,
) -> Result<std::net::SocketAddr, AgentError> {
    if local_node == &plan.key.local {
        return plan
            .target_reflexive
            .as_ref()
            .map(|candidate| candidate.addr)
            .ok_or_else(|| {
                AgentError::HolePunch("target reflexive candidate missing".to_string())
            });
    }
    if local_node == &plan.key.remote {
        return plan
            .source_reflexive
            .as_ref()
            .map(|candidate| candidate.addr)
            .ok_or_else(|| {
                AgentError::HolePunch("source reflexive candidate missing".to_string())
            });
    }

    Err(AgentError::HolePunch(format!(
        "node {local_node} is not part of hole punch plan {} -> {}",
        plan.key.local, plan.key.remote
    )))
}

fn hole_punch_payload(local_node: &NodeId, plan: &SignalHolePunchPlanResponse) -> String {
    format!(
        "ipars-hole-punch-v1 source={} target={} local={}",
        plan.key.local, plan.key.remote, local_node
    )
}

#[async_trait]
pub trait LinuxCommandRunner: Send + Sync {
    async fn run(&self, command: LinuxCommand) -> Result<(), AgentError>;
}

#[derive(Debug, Clone, Default)]
pub struct SystemCommandRunner;

#[async_trait]
impl LinuxCommandRunner for SystemCommandRunner {
    async fn run(&self, command: LinuxCommand) -> Result<(), AgentError> {
        run_system_command(
            command,
            DEFAULT_SYSTEM_COMMAND_TIMEOUT,
            DEFAULT_SYSTEM_COMMAND_OUTPUT_MAX_BYTES,
        )
        .await
    }
}

#[derive(Debug, Clone)]
pub struct TimedSystemCommandRunner {
    timeout: Duration,
    output_max_bytes: usize,
}

impl TimedSystemCommandRunner {
    pub fn new(timeout: Duration) -> Self {
        Self::with_output_max_bytes(timeout, DEFAULT_SYSTEM_COMMAND_OUTPUT_MAX_BYTES)
    }

    pub fn with_output_max_bytes(timeout: Duration, output_max_bytes: usize) -> Self {
        Self {
            timeout,
            output_max_bytes,
        }
    }
}

impl Default for TimedSystemCommandRunner {
    fn default() -> Self {
        Self::new(DEFAULT_SYSTEM_COMMAND_TIMEOUT)
    }
}

#[async_trait]
impl LinuxCommandRunner for TimedSystemCommandRunner {
    async fn run(&self, command: LinuxCommand) -> Result<(), AgentError> {
        run_system_command(command, self.timeout, self.output_max_bytes).await
    }
}

async fn run_system_command(
    command: LinuxCommand,
    timeout: Duration,
    output_max_bytes: usize,
) -> Result<(), AgentError> {
    validate_system_command_runtime_bounds(timeout, output_max_bytes)?;
    validate_linux_command(&command)?;
    let command_label = command_label(&command.program, &command.args);
    let output = run_command_output(command, timeout, output_max_bytes, &command_label).await?;
    if output.status.success() {
        return Ok(());
    }

    Err(AgentError::WireGuard(format!(
        "{command_label} failed: {}",
        command_stderr_message(&output.stderr)
    )))
}

fn validate_system_command_runtime_bounds(
    timeout: Duration,
    output_max_bytes: usize,
) -> Result<(), AgentError> {
    if timeout.is_zero() {
        return Err(AgentError::WireGuard(
            "invalid linux command runtime bounds: timeout must be greater than zero".to_string(),
        ));
    }
    if timeout > MAX_SYSTEM_COMMAND_TIMEOUT {
        return Err(AgentError::WireGuard(format!(
            "invalid linux command runtime bounds: timeout must not exceed {}s",
            MAX_SYSTEM_COMMAND_TIMEOUT.as_secs()
        )));
    }
    if output_max_bytes == 0 {
        return Err(AgentError::WireGuard(
            "invalid linux command runtime bounds: output_max_bytes must be greater than zero"
                .to_string(),
        ));
    }
    if output_max_bytes > MAX_SYSTEM_COMMAND_OUTPUT_MAX_BYTES {
        return Err(AgentError::WireGuard(format!(
            "invalid linux command runtime bounds: output_max_bytes must not exceed {MAX_SYSTEM_COMMAND_OUTPUT_MAX_BYTES}"
        )));
    }
    Ok(())
}

fn validate_linux_command(command: &LinuxCommand) -> Result<(), AgentError> {
    if command.program.is_empty() {
        return Err(AgentError::WireGuard(
            "invalid linux command: program cannot be empty".to_string(),
        ));
    }
    if command.program.len() > MAX_LINUX_COMMAND_PROGRAM_BYTES {
        return Err(AgentError::WireGuard(format!(
            "invalid linux command: program exceeds {MAX_LINUX_COMMAND_PROGRAM_BYTES} bytes"
        )));
    }
    if command.program.as_bytes().contains(&0) {
        return Err(AgentError::WireGuard(
            "invalid linux command: program must not contain NUL bytes".to_string(),
        ));
    }
    if command.args.len() > MAX_LINUX_COMMAND_ARGS {
        return Err(AgentError::WireGuard(format!(
            "invalid linux command: too many arguments: {} > {MAX_LINUX_COMMAND_ARGS}",
            command.args.len()
        )));
    }

    let mut total_bytes = command.program.len();
    for (index, arg) in command.args.iter().enumerate() {
        if arg.len() > MAX_LINUX_COMMAND_ARG_BYTES {
            return Err(AgentError::WireGuard(format!(
                "invalid linux command: argument {index} exceeds {MAX_LINUX_COMMAND_ARG_BYTES} bytes"
            )));
        }
        if arg.as_bytes().contains(&0) {
            return Err(AgentError::WireGuard(format!(
                "invalid linux command: argument {index} must not contain NUL bytes"
            )));
        }
        total_bytes = total_bytes.saturating_add(arg.len());
        if total_bytes > MAX_LINUX_COMMAND_ARGV_BYTES {
            return Err(AgentError::WireGuard(format!(
                "invalid linux command: argv exceeds {MAX_LINUX_COMMAND_ARGV_BYTES} bytes"
            )));
        }
    }

    Ok(())
}

async fn run_command_output(
    command: LinuxCommand,
    timeout: Duration,
    output_max_bytes: usize,
    command_label: &str,
) -> Result<BoundedCommandOutput, AgentError> {
    collect_bounded_command_output(command, timeout, output_max_bytes, command_label).await
}

async fn collect_bounded_command_output(
    command: LinuxCommand,
    timeout: Duration,
    output_max_bytes: usize,
    command_label: &str,
) -> Result<BoundedCommandOutput, AgentError> {
    let mut child_command = Command::new(&command.program);
    child_command
        .args(&command.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_command_process_group(&mut child_command);

    let mut child = child_command.spawn().map_err(AgentError::Io)?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AgentError::Io(std::io::Error::other("child stdout was not piped")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AgentError::Io(std::io::Error::other("child stderr was not piped")))?;

    let stdout_task = tokio::spawn(read_limited_command_output(stdout, output_max_bytes));
    let stderr_task = tokio::spawn(read_limited_command_output(stderr, output_max_bytes));

    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            stdout_task.abort();
            stderr_task.abort();
            return Err(AgentError::Io(error));
        }
        Err(_) => {
            let kill_error = kill_timed_out_child(&mut child);
            let _ = child.wait().await;
            stdout_task.abort();
            stderr_task.abort();
            let mut message = format!(
                "{command_label} timed out after {}",
                command_timeout_label(timeout)
            );
            if let Some(error) = kill_error {
                message.push_str(&format!("; failed to kill timed-out child: {error}"));
            }
            return Err(AgentError::WireGuard(message));
        }
    };

    let _stdout = collect_command_output_task(stdout_task).await?;
    let stderr = collect_command_output_task(stderr_task).await?;

    Ok(BoundedCommandOutput { status, stderr })
}

fn configure_command_process_group(_command: &mut Command) {
    #[cfg(target_os = "linux")]
    {
        _command.process_group(0);
    }
}

fn kill_timed_out_child(child: &mut tokio::process::Child) -> Option<String> {
    #[cfg(target_os = "linux")]
    if let Some(pid) = child.id() {
        match kill_process_group(pid) {
            Ok(()) => return None,
            Err(error) if error.raw_os_error() == Some(nix::libc::ESRCH) => return None,
            Err(group_error) => {
                return match child.start_kill() {
                    Ok(()) => Some(format!(
                        "process group {pid}: {group_error}; direct child kill succeeded"
                    )),
                    Err(child_error) => Some(format!(
                        "process group {pid}: {group_error}; direct child: {child_error}"
                    )),
                };
            }
        }
    }

    child.start_kill().err().map(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn kill_process_group(pid: u32) -> std::io::Result<()> {
    let pgid: i32 = pid
        .try_into()
        .map_err(|_| std::io::Error::other(format!("child pid {pid} exceeds pid_t range")))?;
    nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(pgid),
        nix::sys::signal::Signal::SIGKILL,
    )
    .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
}

async fn collect_command_output_task(
    task: tokio::task::JoinHandle<std::io::Result<LimitedCommandOutput>>,
) -> Result<LimitedCommandOutput, AgentError> {
    match task.await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => Err(AgentError::Io(error)),
        Err(error) => Err(AgentError::WireGuard(format!(
            "command output reader task failed: {error}"
        ))),
    }
}

#[derive(Debug)]
struct BoundedCommandOutput {
    status: ExitStatus,
    stderr: LimitedCommandOutput,
}

#[derive(Debug)]
struct LimitedCommandOutput {
    bytes: Vec<u8>,
    truncated: bool,
    limit: usize,
}

async fn read_limited_command_output<R>(
    mut reader: R,
    limit: usize,
) -> std::io::Result<LimitedCommandOutput>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(limit.min(4096));
    let mut truncated = false;
    let mut chunk = [0_u8; 4096];

    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            break;
        }

        let remaining = limit.saturating_sub(bytes.len());
        if remaining > 0 {
            let keep = read.min(remaining);
            bytes.extend_from_slice(&chunk[..keep]);
            if keep < read {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }

    Ok(LimitedCommandOutput {
        bytes,
        truncated,
        limit,
    })
}

fn command_stderr_message(stderr: &LimitedCommandOutput) -> String {
    let text = String::from_utf8_lossy(&stderr.bytes).trim().to_string();
    if !stderr.truncated {
        return text;
    }

    let suffix = format!("stderr truncated after {} bytes", stderr.limit);
    if text.is_empty() {
        suffix
    } else {
        format!("{text} ({suffix})")
    }
}

fn command_timeout_label(timeout: Duration) -> String {
    if timeout.as_millis() < 1000 {
        format!("{}ms", timeout.as_millis())
    } else {
        format!("{}s", timeout.as_secs())
    }
}

fn command_label(program: &str, args: &[String]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{} {}", program, args.join(" "))
    }
}

#[derive(Debug, Clone)]
pub struct NamespacedLinuxCommandRunner<R> {
    namespace: LinuxNetworkNamespace,
    inner: R,
}

impl<R> NamespacedLinuxCommandRunner<R> {
    pub fn new(namespace: LinuxNetworkNamespace, inner: R) -> Self {
        Self { namespace, inner }
    }
}

#[async_trait]
impl<R> LinuxCommandRunner for NamespacedLinuxCommandRunner<R>
where
    R: LinuxCommandRunner,
{
    async fn run(&self, command: LinuxCommand) -> Result<(), AgentError> {
        self.inner.run(command.in_namespace(&self.namespace)).await
    }
}

#[derive(Debug)]
pub struct LinuxWireGuardBackend<R> {
    interface: String,
    runner: R,
    peer_public_keys: tokio::sync::RwLock<BTreeMap<NodeId, String>>,
}

impl<R> LinuxWireGuardBackend<R>
where
    R: LinuxCommandRunner,
{
    pub fn new(interface: impl Into<String>, runner: R) -> Self {
        Self {
            interface: interface.into(),
            runner,
            peer_public_keys: tokio::sync::RwLock::new(BTreeMap::new()),
        }
    }

    pub async fn ensure_interface(&self) -> Result<(), AgentError> {
        if self
            .runner
            .run(LinuxCommand::new(
                "ip",
                ["link", "show", "dev", self.interface.as_str()],
            ))
            .await
            .is_ok()
        {
            return Ok(());
        }

        self.runner
            .run(LinuxCommand::new(
                "ip",
                [
                    "link",
                    "add",
                    "dev",
                    self.interface.as_str(),
                    "type",
                    "wireguard",
                ],
            ))
            .await?;
        self.runner
            .run(LinuxCommand::new(
                "ip",
                ["link", "set", "up", "dev", self.interface.as_str()],
            ))
            .await
    }

    fn upsert_command(&self, config: &WireGuardPeerConfig) -> LinuxCommand {
        wireguard_upsert_peer_command(&self.interface, config)
    }
}

#[async_trait]
impl<R> WireGuardBackend for LinuxWireGuardBackend<R>
where
    R: LinuxCommandRunner,
{
    async fn upsert_peer(&self, config: WireGuardPeerConfig) -> Result<(), AgentError> {
        self.runner.run(self.upsert_command(&config)).await?;
        self.peer_public_keys
            .write()
            .await
            .insert(config.peer, config.public_key);
        Ok(())
    }

    async fn remove_peer(&self, peer: &NodeId) -> Result<(), AgentError> {
        let public_key = self
            .peer_public_keys
            .read()
            .await
            .get(peer)
            .cloned()
            .ok_or_else(|| AgentError::MissingPeer(peer.clone()))?;
        self.runner
            .run(wireguard_remove_peer_command(&self.interface, &public_key))
            .await?;
        self.peer_public_keys.write().await.remove(peer);
        Ok(())
    }
}

#[derive(Debug)]
pub struct UserspaceWireGuardBackend<R> {
    interface: String,
    runner: R,
    peer_public_keys: tokio::sync::RwLock<BTreeMap<NodeId, String>>,
}

impl<R> UserspaceWireGuardBackend<R>
where
    R: LinuxCommandRunner,
{
    pub fn new(interface: impl Into<String>, runner: R) -> Self {
        Self {
            interface: interface.into(),
            runner,
            peer_public_keys: tokio::sync::RwLock::new(BTreeMap::new()),
        }
    }

    pub async fn ensure_interface(&self) -> Result<(), AgentError> {
        self.runner
            .run(LinuxCommand::new("wg", ["show", self.interface.as_str()]))
            .await
    }
}

#[async_trait]
impl<R> WireGuardBackend for UserspaceWireGuardBackend<R>
where
    R: LinuxCommandRunner,
{
    async fn upsert_peer(&self, config: WireGuardPeerConfig) -> Result<(), AgentError> {
        self.runner
            .run(wireguard_upsert_peer_command(&self.interface, &config))
            .await?;
        self.peer_public_keys
            .write()
            .await
            .insert(config.peer, config.public_key);
        Ok(())
    }

    async fn remove_peer(&self, peer: &NodeId) -> Result<(), AgentError> {
        let public_key = self
            .peer_public_keys
            .read()
            .await
            .get(peer)
            .cloned()
            .ok_or_else(|| AgentError::MissingPeer(peer.clone()))?;
        self.runner
            .run(wireguard_remove_peer_command(&self.interface, &public_key))
            .await?;
        self.peer_public_keys.write().await.remove(peer);
        Ok(())
    }
}

fn wireguard_upsert_peer_command(interface: &str, config: &WireGuardPeerConfig) -> LinuxCommand {
    let mut args = vec![
        "set".to_string(),
        interface.to_string(),
        "peer".to_string(),
        config.public_key.clone(),
    ];
    if !config.allowed_ips.is_empty() {
        args.push("allowed-ips".to_string());
        args.push(config.allowed_ips.join(","));
    }
    if let Some(endpoint) = &config.endpoint {
        args.push("endpoint".to_string());
        args.push(endpoint.clone());
    }
    if let Some(keepalive) = config.persistent_keepalive_seconds {
        args.push("persistent-keepalive".to_string());
        args.push(keepalive.to_string());
    }
    LinuxCommand::new("wg", args)
}

fn wireguard_remove_peer_command(interface: &str, public_key: &str) -> LinuxCommand {
    LinuxCommand::new("wg", ["set", interface, "peer", public_key, "remove"])
}

#[derive(Debug)]
pub struct KernelWireGuardBackend {
    interface: String,
    namespace: Option<LinuxNetworkNamespace>,
    peer_public_keys: tokio::sync::RwLock<BTreeMap<NodeId, [u8; 32]>>,
}

impl KernelWireGuardBackend {
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            namespace: None,
            peer_public_keys: tokio::sync::RwLock::new(BTreeMap::new()),
        }
    }

    pub fn new_in_namespace(
        interface: impl Into<String>,
        namespace: LinuxNetworkNamespace,
    ) -> Self {
        Self {
            interface: interface.into(),
            namespace: Some(namespace),
            peer_public_keys: tokio::sync::RwLock::new(BTreeMap::new()),
        }
    }

    pub fn namespace(&self) -> Option<&LinuxNetworkNamespace> {
        self.namespace.as_ref()
    }

    #[cfg(target_os = "linux")]
    pub async fn ensure_interface(&self) -> Result<(), AgentError> {
        let (connection, handle, _) = with_netlink_namespace(self.namespace.as_ref(), || {
            rtnetlink::new_connection_with_socket::<LinuxNetlinkSocket>()
        })
        .map_err(|error| {
            AgentError::WireGuard(format!(
                "failed to open route netlink connection for WireGuard interface {}{}: {error}",
                self.interface,
                wireguard_namespace_suffix(self.namespace.as_ref())
            ))
        })?;
        tokio::spawn(connection);

        let index = match find_link_index(&handle, &self.interface).await? {
            Some(index) => index,
            None => {
                handle
                    .link()
                    .add(LinkWireguard::new(&self.interface).build())
                    .execute()
                    .await
                    .map_err(|error| {
                        AgentError::WireGuard(format!(
                            "failed to create WireGuard interface {} through rtnetlink: {error}",
                            self.interface
                        ))
                    })?;
                find_link_index(&handle, &self.interface)
                    .await?
                    .ok_or_else(|| {
                        AgentError::WireGuard(format!(
                            "WireGuard interface {} was not visible after rtnetlink create",
                            self.interface
                        ))
                    })?
            }
        };

        handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await
            .map_err(|error| {
                AgentError::WireGuard(format!(
                    "failed to set WireGuard interface {} up through rtnetlink: {error}",
                    self.interface
                ))
            })
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn ensure_interface(&self) -> Result<(), AgentError> {
        Err(AgentError::WireGuard(
            "kernel WireGuard netlink backend is only supported on Linux".to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl WireGuardBackend for KernelWireGuardBackend {
    async fn upsert_peer(&self, config: WireGuardPeerConfig) -> Result<(), AgentError> {
        let public_key = parse_wireguard_public_key(&config.public_key)?;
        let peer = netlink_peer_config(&config, public_key)?;
        apply_wireguard_netlink(
            &self.interface,
            self.namespace.as_ref(),
            vec![WireguardAttribute::Peers(vec![peer])],
        )
        .await?;
        self.peer_public_keys
            .write()
            .await
            .insert(config.peer, public_key);
        Ok(())
    }

    async fn remove_peer(&self, peer: &NodeId) -> Result<(), AgentError> {
        let public_key = self
            .peer_public_keys
            .read()
            .await
            .get(peer)
            .copied()
            .ok_or_else(|| AgentError::MissingPeer(peer.clone()))?;
        apply_wireguard_netlink(
            &self.interface,
            self.namespace.as_ref(),
            vec![WireguardAttribute::Peers(vec![WireguardPeer(vec![
                WireguardPeerAttribute::PublicKey(public_key),
                WireguardPeerAttribute::Flags(WireguardPeerFlags::RemoveMe),
            ])])],
        )
        .await?;
        self.peer_public_keys.write().await.remove(peer);
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl WireGuardBackend for KernelWireGuardBackend {
    async fn upsert_peer(&self, _config: WireGuardPeerConfig) -> Result<(), AgentError> {
        Err(AgentError::WireGuard(
            "kernel WireGuard netlink backend is only supported on Linux".to_string(),
        ))
    }

    async fn remove_peer(&self, _peer: &NodeId) -> Result<(), AgentError> {
        Err(AgentError::WireGuard(
            "kernel WireGuard netlink backend is only supported on Linux".to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
async fn find_link_index(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<Option<u32>, AgentError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links.try_next().await.map_err(|error| {
        AgentError::WireGuard(format!(
            "failed to query WireGuard interface {name} through rtnetlink: {error}"
        ))
    })?;
    Ok(link.map(|link| link.header.index))
}

#[cfg(target_os = "linux")]
fn wireguard_namespace_suffix(namespace: Option<&LinuxNetworkNamespace>) -> String {
    namespace
        .map(|namespace| format!(" in linux network namespace `{}`", namespace.name()))
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn parse_wireguard_public_key(value: &str) -> Result<[u8; 32], AgentError> {
    let decoded = BASE64_STANDARD.decode(value.trim()).map_err(|error| {
        AgentError::WireGuard(format!("invalid WireGuard public key base64: {error}"))
    })?;
    decoded.try_into().map_err(|decoded: Vec<u8>| {
        AgentError::WireGuard(format!(
            "WireGuard public key decoded to {} bytes, expected 32",
            decoded.len()
        ))
    })
}

#[cfg(target_os = "linux")]
fn netlink_peer_config(
    config: &WireGuardPeerConfig,
    public_key: [u8; 32],
) -> Result<WireguardPeer, AgentError> {
    let mut attributes = vec![
        WireguardPeerAttribute::PublicKey(public_key),
        WireguardPeerAttribute::Flags(WireguardPeerFlags::ReplaceAllowedIps),
        WireguardPeerAttribute::AllowedIps(netlink_allowed_ips(&config.allowed_ips)?),
    ];
    if let Some(endpoint) = config.endpoint.as_deref() {
        attributes.push(WireguardPeerAttribute::Endpoint(
            endpoint.parse::<SocketAddr>().map_err(|error| {
                AgentError::WireGuard(format!(
                    "kernel WireGuard netlink backend requires socket-address endpoints; `{endpoint}` is invalid: {error}"
                ))
            })?,
        ));
    }
    if let Some(keepalive) = config.persistent_keepalive_seconds {
        attributes.push(WireguardPeerAttribute::PersistentKeepalive(keepalive));
    }
    Ok(WireguardPeer(attributes))
}

#[cfg(target_os = "linux")]
fn netlink_allowed_ips(allowed_ips: &[String]) -> Result<Vec<WireguardAllowedIp>, AgentError> {
    allowed_ips
        .iter()
        .map(|allowed_ip| {
            let network = allowed_ip.parse::<ipnet::IpNet>().map_err(|error| {
                AgentError::WireGuard(format!(
                    "invalid WireGuard allowed IP `{allowed_ip}`: {error}"
                ))
            })?;
            let family = match network.addr() {
                IpAddr::V4(_) => WireguardAddressFamily::Ipv4,
                IpAddr::V6(_) => WireguardAddressFamily::Ipv6,
            };
            Ok(WireguardAllowedIp(vec![
                WireguardAllowedIpAttr::Family(family),
                WireguardAllowedIpAttr::IpAddr(network.addr()),
                WireguardAllowedIpAttr::Cidr(network.prefix_len()),
            ]))
        })
        .collect()
}

#[cfg(target_os = "linux")]
async fn apply_wireguard_netlink(
    interface: &str,
    namespace: Option<&LinuxNetworkNamespace>,
    mut attributes: Vec<WireguardAttribute>,
) -> Result<(), AgentError> {
    attributes.insert(0, WireguardAttribute::IfName(interface.to_string()));
    let (connection, mut handle, _) = with_netlink_namespace(namespace, || {
        genetlink::new_connection_with_socket::<LinuxNetlinkSocket>()
    })
    .map_err(|error| {
        AgentError::WireGuard(format!(
            "failed to open generic netlink connection for WireGuard interface {interface}{}: {error}",
            wireguard_namespace_suffix(namespace)
        ))
    })?;
    tokio::spawn(connection);

    let genlmsg = GenlMessage::from_payload(WireguardMessage {
        cmd: WireguardCmd::SetDevice,
        attributes,
    });
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

    let mut responses = handle.request(nlmsg).await.map_err(|error| {
        AgentError::WireGuard(format!(
            "failed to send WireGuard netlink request for interface {interface}: {error}"
        ))
    })?;
    while let Some(response) = responses.next().await {
        let response = response.map_err(|error| {
            AgentError::WireGuard(format!(
                "failed to decode WireGuard netlink response for interface {interface}: {error}"
            ))
        })?;
        match response.payload {
            NetlinkPayload::Error(error) if error.code.is_some() => {
                return Err(AgentError::WireGuard(format!(
                    "WireGuard netlink request for interface {interface} failed: {}",
                    error.to_io()
                )));
            }
            NetlinkPayload::Error(_) | NetlinkPayload::Done(_) => return Ok(()),
            _ => {}
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct MemoryWireGuardBackend {
    peers: tokio::sync::RwLock<BTreeMap<NodeId, WireGuardPeerConfig>>,
}

#[async_trait]
impl WireGuardBackend for MemoryWireGuardBackend {
    async fn upsert_peer(&self, config: WireGuardPeerConfig) -> Result<(), AgentError> {
        self.peers.write().await.insert(config.peer.clone(), config);
        Ok(())
    }

    async fn remove_peer(&self, peer: &NodeId) -> Result<(), AgentError> {
        self.peers.write().await.remove(peer);
        Ok(())
    }
}

#[async_trait]
pub trait PeerMapSource: Send + Sync {
    async fn fetch_peer_map(&self, node_id: &NodeId) -> Result<PeerMap, AgentError>;
}

#[async_trait]
pub trait PeerMapSink: Send + Sync {
    async fn apply_peer_map_update(
        &self,
        peer_map: PeerMap,
    ) -> Result<PeerMapApplySummary, AgentError>;
}

#[async_trait]
pub trait PeerEndpointResolver: Send + Sync + std::fmt::Debug {
    async fn endpoint_for_peer(&self, peer: &NodeRecord) -> Result<Option<String>, AgentError>;
}

#[derive(Debug, Clone, Default)]
pub struct DirectPeerEndpointResolver;

#[async_trait]
impl PeerEndpointResolver for DirectPeerEndpointResolver {
    async fn endpoint_for_peer(&self, peer: &NodeRecord) -> Result<Option<String>, AgentError> {
        Ok(preferred_endpoint(peer))
    }
}

#[derive(Debug, Clone)]
pub struct RuntimePeerEndpointResolver {
    runtime: Arc<AgentRuntime>,
    relay_forwarder_endpoint: Option<SocketAddr>,
}

impl RuntimePeerEndpointResolver {
    pub fn new(runtime: Arc<AgentRuntime>) -> Self {
        Self {
            runtime,
            relay_forwarder_endpoint: None,
        }
    }

    pub fn with_relay_forwarder_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.relay_forwarder_endpoint = Some(endpoint);
        self
    }
}

#[async_trait]
impl PeerEndpointResolver for RuntimePeerEndpointResolver {
    async fn endpoint_for_peer(&self, peer: &NodeRecord) -> Result<Option<String>, AgentError> {
        let path = self.runtime.path_record_for_peer(&peer.node_id).await;
        let Some(path) = path else {
            return Ok(preferred_endpoint(peer));
        };

        match path.selected_state {
            PathState::Relay => Ok(self
                .runtime
                .relay_forwarder_endpoint_for_peer(
                    &peer.node_id,
                    Utc::now(),
                    self.relay_forwarder_endpoint,
                )
                .await
                .map(|endpoint| endpoint.to_string())),
            PathState::Unreachable => Ok(None),
            _ => Ok(path
                .selected_candidate
                .as_ref()
                .and_then(|candidate| wireguard_endpoint_for_candidate(candidate, &peer.node_id))
                .or_else(|| preferred_endpoint(peer))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerMapApplySummary {
    pub peers_applied: usize,
    pub peers_removed: usize,
    pub routes_applied: usize,
    pub routes_removed: usize,
}

#[derive(Debug)]
pub struct PeerMapApplier<W, R> {
    interface: String,
    wireguard: W,
    route_manager: R,
    endpoint_resolver: Arc<dyn PeerEndpointResolver>,
    lazy_runtime: Option<Arc<AgentRuntime>>,
    applied_peers: tokio::sync::RwLock<BTreeSet<NodeId>>,
    applied_routes: tokio::sync::RwLock<BTreeMap<NodeId, Vec<Route>>>,
}

impl<W, R> PeerMapApplier<W, R>
where
    W: WireGuardBackend,
    R: RouteManager,
{
    pub fn new(interface: impl Into<String>, wireguard: W, route_manager: R) -> Self {
        Self {
            interface: interface.into(),
            wireguard,
            route_manager,
            endpoint_resolver: Arc::new(DirectPeerEndpointResolver),
            lazy_runtime: None,
            applied_peers: tokio::sync::RwLock::new(BTreeSet::new()),
            applied_routes: tokio::sync::RwLock::new(BTreeMap::new()),
        }
    }

    pub fn with_endpoint_resolver(
        mut self,
        endpoint_resolver: impl PeerEndpointResolver + 'static,
    ) -> Self {
        self.endpoint_resolver = Arc::new(endpoint_resolver);
        self
    }

    pub fn with_lazy_connect_runtime(mut self, runtime: Arc<AgentRuntime>) -> Self {
        self.lazy_runtime = Some(runtime);
        self
    }

    pub async fn apply_peer_map(
        &self,
        peer_map: PeerMap,
    ) -> Result<PeerMapApplySummary, AgentError> {
        if let Some(runtime) = &self.lazy_runtime {
            runtime
                .observe_peer_map_for_lazy_connect(&peer_map.peers)
                .await;
        }

        let now = Utc::now();
        let peer_map_ids = peer_map
            .peers
            .iter()
            .map(|peer| peer.node_id.clone())
            .collect::<BTreeSet<_>>();
        let mut peers_to_remove = BTreeSet::new();
        if let Some(runtime) = &self.lazy_runtime {
            peers_to_remove.extend(runtime.take_idle_peers_to_close(now).await);
        }
        let stale_peers = {
            let applied_peers = self.applied_peers.read().await;
            applied_peers
                .iter()
                .filter(|peer| !peer_map_ids.contains(*peer))
                .cloned()
                .collect::<Vec<_>>()
        };
        peers_to_remove.extend(stale_peers);

        let mut peers_removed = 0;
        let mut routes_removed = 0;
        for peer in peers_to_remove {
            let was_applied = self.applied_peers.read().await.contains(&peer);
            if !was_applied {
                continue;
            }
            let routes_to_remove = self
                .applied_routes
                .read()
                .await
                .get(&peer)
                .cloned()
                .unwrap_or_default();
            if !routes_to_remove.is_empty() {
                self.route_manager
                    .remove_routes(RoutePlan {
                        interface: self.interface.clone(),
                        routes: routes_to_remove.clone(),
                        policy_rules: Vec::new(),
                    })
                    .await?;
                routes_removed += routes_to_remove.len();
                self.applied_routes.write().await.remove(&peer);
            }
            self.wireguard.remove_peer(&peer).await?;
            self.applied_peers.write().await.remove(&peer);
            self.applied_routes.write().await.remove(&peer);
            peers_removed += 1;
        }

        let mut routes = Vec::new();
        let mut peer_routes = BTreeMap::new();
        let mut peers_applied = 0;

        for peer in peer_map.peers {
            if let Some(runtime) = &self.lazy_runtime {
                if !runtime.should_connect_peer(&peer).await {
                    continue;
                }
            }

            let allowed_ip = peer_overlay_cidr(&peer.vpn_ip);
            let endpoint = self.endpoint_resolver.endpoint_for_peer(&peer).await?;
            self.wireguard
                .upsert_peer(WireGuardPeerConfig {
                    peer: peer.node_id.clone(),
                    public_key: peer.wireguard_public_key.clone(),
                    endpoint: endpoint.clone(),
                    allowed_ips: vec![allowed_ip],
                    persistent_keepalive_seconds: endpoint.map(|_| 25),
                })
                .await?;
            self.applied_peers
                .write()
                .await
                .insert(peer.node_id.clone());
            peers_applied += 1;

            let desired_routes = peer_routes_for_record(&peer)?;
            let routes_to_remove = self
                .applied_routes
                .read()
                .await
                .get(&peer.node_id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|route| !desired_routes.contains(route))
                .collect::<Vec<_>>();
            if !routes_to_remove.is_empty() {
                self.route_manager
                    .remove_routes(RoutePlan {
                        interface: self.interface.clone(),
                        routes: routes_to_remove.clone(),
                        policy_rules: Vec::new(),
                    })
                    .await?;
                routes_removed += routes_to_remove.len();
                if let Some(applied) = self.applied_routes.write().await.get_mut(&peer.node_id) {
                    applied.retain(|route| !routes_to_remove.contains(route));
                }
            }

            routes.extend(desired_routes.iter().cloned());
            peer_routes.insert(peer.node_id.clone(), desired_routes);
        }

        let routes_applied = routes.len();
        if routes_applied > 0 {
            self.route_manager
                .apply_routes(RoutePlan {
                    interface: self.interface.clone(),
                    routes,
                    policy_rules: Vec::new(),
                })
                .await?;
            let mut applied_routes = self.applied_routes.write().await;
            for (peer, routes) in peer_routes {
                applied_routes.insert(peer, routes);
            }
        }

        Ok(PeerMapApplySummary {
            peers_applied,
            peers_removed,
            routes_applied,
            routes_removed,
        })
    }
}

#[async_trait]
impl<W, R> PeerMapSink for PeerMapApplier<W, R>
where
    W: WireGuardBackend,
    R: RouteManager,
{
    async fn apply_peer_map_update(
        &self,
        peer_map: PeerMap,
    ) -> Result<PeerMapApplySummary, AgentError> {
        self.apply_peer_map(peer_map).await
    }
}

#[derive(Debug)]
pub struct PeerMapSync<S, A> {
    node_id: NodeId,
    source: S,
    sink: A,
}

impl<S, A> PeerMapSync<S, A>
where
    S: PeerMapSource,
    A: PeerMapSink,
{
    pub fn new(node_id: NodeId, source: S, sink: A) -> Self {
        Self {
            node_id,
            source,
            sink,
        }
    }

    pub async fn sync_once(&self) -> Result<PeerMapApplySummary, AgentError> {
        let peer_map = self.source.fetch_peer_map(&self.node_id).await?;
        self.sink.apply_peer_map_update(peer_map).await
    }
}

fn peer_overlay_cidr(vpn_ip: &VpnIp) -> String {
    match vpn_ip.0 {
        std::net::IpAddr::V4(ip) => format!("{ip}/32"),
        std::net::IpAddr::V6(ip) => format!("{ip}/128"),
    }
}

fn peer_host_route(peer: &NodeRecord) -> Result<Route, AgentError> {
    let cidr = peer_overlay_cidr(&peer.vpn_ip);
    Ok(Route {
        id: format!("peer-{}", peer.node_id),
        cidr: cidr
            .parse()
            .map_err(|error| AgentError::RoutePlanning(format!("{cidr}: {error}")))?,
        advertised_by: peer.node_id.clone(),
        via: Some(peer.node_id.clone()),
        metric: 10,
        tags: peer.tags.clone(),
    })
}

fn peer_routes_for_record(peer: &NodeRecord) -> Result<Vec<Route>, AgentError> {
    let mut routes = vec![peer_host_route(peer)?];
    routes.extend(peer_owned_advertised_routes(peer).cloned());
    Ok(routes)
}

fn peer_owned_advertised_routes(peer: &NodeRecord) -> impl Iterator<Item = &Route> {
    peer.routes
        .iter()
        .filter(|route| route.advertised_by == peer.node_id)
}

fn preferred_endpoint(peer: &NodeRecord) -> Option<String> {
    peer.endpoint_candidates
        .iter()
        .filter_map(|candidate| ranked_wireguard_endpoint_for_candidate(candidate, &peer.node_id))
        .min_by(|(left_rank, left, _), (right_rank, right, _)| {
            left_rank
                .cmp(right_rank)
                .then_with(|| left.cost.cmp(&right.cost))
                .then_with(|| right.priority.cmp(&left.priority))
        })
        .map(|(_, _, endpoint)| endpoint)
}

fn wireguard_endpoint_for_candidate(
    candidate: &EndpointCandidate,
    peer_id: &NodeId,
) -> Option<String> {
    ranked_wireguard_endpoint_for_candidate(candidate, peer_id).map(|(_, _, endpoint)| endpoint)
}

fn ranked_wireguard_endpoint_for_candidate<'a>(
    candidate: &'a EndpointCandidate,
    peer_id: &NodeId,
) -> Option<(u8, &'a EndpointCandidate, String)> {
    let rank = candidate_kind_rank(candidate.kind)?;
    if &candidate.node_id != peer_id
        || candidate.validate_kind_address().is_err()
        || !endpoint_addr_is_usable(candidate.addr)
    {
        return None;
    }

    Some((rank, candidate, candidate.addr.to_string()))
}

fn candidate_kind_rank(kind: EndpointCandidateKind) -> Option<u8> {
    match kind {
        EndpointCandidateKind::Ipv6 => Some(0),
        EndpointCandidateKind::PublicUdp => Some(1),
        EndpointCandidateKind::StunReflexive => Some(2),
        EndpointCandidateKind::LocalUdp => Some(3),
        EndpointCandidateKind::Relay => None,
    }
}

#[derive(Debug, Clone)]
pub struct LazyConnectManager {
    policy: ClusterPolicy,
    pins: BTreeSet<NodeId>,
    last_used: BTreeMap<NodeId, DateTime<Utc>>,
    peer_vpn_ips: BTreeMap<IpAddr, NodeId>,
    advertised_routes: BTreeMap<NodeId, Vec<ipnet::IpNet>>,
}

impl LazyConnectManager {
    pub fn new(policy: ClusterPolicy) -> Self {
        Self {
            policy,
            pins: BTreeSet::new(),
            last_used: BTreeMap::new(),
            peer_vpn_ips: BTreeMap::new(),
            advertised_routes: BTreeMap::new(),
        }
    }

    pub fn record_activity(&mut self, peer: NodeId, at: DateTime<Utc>) {
        self.last_used.insert(peer, at);
    }

    pub fn pin_peer(&mut self, peer: NodeId) {
        self.pins.insert(peer);
    }

    pub fn is_pinned(&self, peer: &NodeId) -> bool {
        self.pins.contains(peer)
    }

    pub fn is_pinned_by_policy(&self, role: &Role, tags: &BTreeSet<Tag>) -> bool {
        self.policy.pinned_roles.contains(role)
            || tags.iter().any(|tag| self.policy.pinned_tags.contains(tag))
    }

    pub fn observe_peer(&mut self, peer: &NodeRecord) {
        self.remove_observed_peer(&peer.node_id);
        self.peer_vpn_ips
            .insert(peer.vpn_ip.0, peer.node_id.clone());
        let routes = peer_owned_advertised_routes(peer)
            .map(|route| route.cidr)
            .collect::<Vec<_>>();
        let has_owned_routes = !routes.is_empty();
        if !routes.is_empty() {
            self.advertised_routes.insert(peer.node_id.clone(), routes);
        }

        if self.is_pinned_by_policy(&peer.role, &peer.tags) || has_owned_routes {
            self.pin_peer(peer.node_id.clone());
        }
    }

    pub fn resolve_packet_flow_destination(
        &self,
        destination: IpAddr,
    ) -> Option<AgentPacketFlowMatch> {
        if let Some(peer) = self.peer_vpn_ips.get(&destination) {
            return Some(AgentPacketFlowMatch {
                peer: peer.clone(),
                kind: AgentPacketFlowMatchKind::PeerVpnIp,
                route: None,
                pinned: self.is_pinned(peer),
            });
        }

        self.advertised_routes
            .iter()
            .flat_map(|(peer, routes)| {
                routes
                    .iter()
                    .filter(move |route| route.contains(&destination))
                    .map(move |route| (peer, route))
            })
            .max_by_key(|(_, route)| route.prefix_len())
            .map(|(peer, route)| AgentPacketFlowMatch {
                peer: peer.clone(),
                kind: AgentPacketFlowMatchKind::AdvertisedRoute,
                route: Some(*route),
                pinned: self.is_pinned(peer),
            })
    }

    pub fn should_connect_peer(&self, peer: &NodeRecord) -> bool {
        self.pins.contains(&peer.node_id) || self.last_used.contains_key(&peer.node_id)
    }

    pub fn metrics(&self) -> LazyConnectMetrics {
        LazyConnectMetrics {
            active_peer_count: self.last_used.len(),
            pinned_peer_count: self.pins.len(),
            observed_peer_vpn_ip_count: self.peer_vpn_ips.len(),
            observed_route_peer_count: self.advertised_routes.len(),
            observed_route_count: self.advertised_routes.values().map(Vec::len).sum(),
        }
    }

    pub fn idle_peers_to_close(&self, now: DateTime<Utc>) -> Vec<NodeId> {
        let idle_timeout = Duration::from_secs(self.policy.idle_timeout_seconds);
        self.last_used
            .iter()
            .filter_map(|(peer, last_used)| {
                if self.pins.contains(peer) {
                    return None;
                }
                let idle_for = now.signed_duration_since(*last_used).to_std().ok()?;
                if idle_for >= idle_timeout {
                    Some(peer.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn remove_activity(&mut self, peer: &NodeId) {
        self.last_used.remove(peer);
    }

    fn remove_observed_peer(&mut self, peer: &NodeId) {
        self.peer_vpn_ips
            .retain(|_, observed_peer| observed_peer != peer);
        self.advertised_routes.remove(peer);
    }
}

#[derive(Debug, Clone)]
pub struct PathSelector;

const DIRECT_PROMOTION_SCORE_MARGIN: f32 = 5.0;
const PATH_STATE_METRIC_ORDER: [PathState; 5] = [
    PathState::DirectPublic,
    PathState::DirectIpv6,
    PathState::DirectNatTraversal,
    PathState::Relay,
    PathState::Unreachable,
];

impl PathSelector {
    pub fn best_path(paths: &[PathRecord]) -> Option<PathRecord> {
        paths
            .iter()
            .filter(|path| path.selected_state != PathState::Unreachable)
            .max_by(|left, right| compare_score(&left.score, &right.score))
            .cloned()
    }

    pub fn should_promote(current: &PathRecord, candidate: &PathRecord) -> bool {
        candidate.selected_state.is_direct()
            && current.selected_state == PathState::Relay
            && candidate.score.value >= current.score.value + DIRECT_PROMOTION_SCORE_MARGIN
    }
}

fn compare_score(left: &PathScore, right: &PathScore) -> std::cmp::Ordering {
    left.value
        .partial_cmp(&right.value)
        .unwrap_or(std::cmp::Ordering::Equal)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    #[cfg(target_os = "linux")]
    use std::time::Instant;

    use chrono::Duration as ChronoDuration;
    use ipars_relay::{encode_relay_datagram, RelayService, UdpRelay};
    use ipars_route_manager::{
        DockerNetworkIntent, KubernetesUnderlayIntent, RouteManager, RouteManagerError, RoutePlan,
    };
    use ipars_stun::{BindingStunServer, Rfc5780StunServer};
    use ipars_types::api::{
        AgentPacketFlowConntrackStatus, AgentPacketFlowTcpState, RelayAdmissionRequest,
        PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES,
    };
    use ipars_types::{
        CandidateSource, ClusterId, NatFilteringBehavior, NatMappingBehavior, NatTraversalStrategy,
        PathMetrics, PeerPathKey, RelayCapability, TokenPolicy, TransportProtocol,
    };

    use super::*;

    fn temp_state_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ipars-agent-{name}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ))
    }

    fn path(peer: &str, state: PathState, score: f32) -> PathRecord {
        PathRecord {
            key: PeerPathKey::new(NodeId::from_string("local"), NodeId::from_string(peer)),
            selected_state: state,
            selected_candidate: None,
            relay_node: None,
            score: PathScore {
                value: score,
                reasons: Vec::new(),
            },
            updated_at: Utc::now(),
            pinned: false,
        }
    }

    fn reflexive_candidate(node_id: &NodeId, addr: SocketAddr) -> EndpointCandidate {
        EndpointCandidate {
            node_id: node_id.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr,
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: ipars_types::CandidateSource::StunProbe,
        }
    }

    #[derive(Debug, Clone, Default)]
    struct RecordingRunner {
        commands: Arc<tokio::sync::RwLock<Vec<LinuxCommand>>>,
        fail_interface_show: bool,
        fail_remove: bool,
    }

    impl RecordingRunner {
        fn with_missing_interface() -> Self {
            Self {
                fail_interface_show: true,
                ..Self::default()
            }
        }

        fn with_failed_remove() -> Self {
            Self {
                fail_remove: true,
                ..Self::default()
            }
        }

        async fn commands(&self) -> Vec<LinuxCommand> {
            self.commands.read().await.clone()
        }
    }

    #[async_trait]
    impl LinuxCommandRunner for RecordingRunner {
        async fn run(&self, command: LinuxCommand) -> Result<(), AgentError> {
            let should_fail_show = self.fail_interface_show
                && command.program == "ip"
                && command
                    .args
                    .iter()
                    .map(String::as_str)
                    .eq(["link", "show", "dev", "ipars0"]);
            let should_fail_remove = self.fail_remove
                && command.program == "wg"
                && command.args.last().is_some_and(|arg| arg == "remove");
            self.commands.write().await.push(command);
            if should_fail_show {
                Err(AgentError::WireGuard("interface missing".to_string()))
            } else if should_fail_remove {
                Err(AgentError::WireGuard("remove failed".to_string()))
            } else {
                Ok(())
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_command_runner_reports_failure_stderr() {
        let runner = TimedSystemCommandRunner::new(Duration::from_secs(1));
        let error = match runner
            .run(LinuxCommand::new(
                "sh",
                ["-c", "echo wireguard-failed >&2; exit 7"],
            ))
            .await
        {
            Ok(()) => panic!("command should fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("wireguard-failed"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_command_runner_rejects_invalid_command_vectors() {
        let runner = TimedSystemCommandRunner::new(Duration::from_secs(1));

        let error = match runner.run(LinuxCommand::new("", ["show"])).await {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("program cannot be empty"));

        let error = match runner
            .run(LinuxCommand::new("wg", ["show\0bad".to_string()]))
            .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("argument 0 must not contain NUL bytes"));

        let error = match runner
            .run(LinuxCommand::new(
                "wg",
                std::iter::repeat_n("show", MAX_LINUX_COMMAND_ARGS + 1),
            ))
            .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("too many arguments"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_command_runner_rejects_invalid_runtime_bounds() {
        let error = match TimedSystemCommandRunner::new(Duration::ZERO)
            .run(LinuxCommand::new("sh", ["-c", "exit 0"]))
            .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("timeout must be greater than zero"));

        let error = match TimedSystemCommandRunner::new(
            MAX_SYSTEM_COMMAND_TIMEOUT + Duration::from_secs(1),
        )
        .run(LinuxCommand::new("sh", ["-c", "exit 0"]))
        .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("timeout must not exceed 3600s"));

        let error = match TimedSystemCommandRunner::with_output_max_bytes(Duration::from_secs(1), 0)
            .run(LinuxCommand::new("sh", ["-c", "exit 0"]))
            .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("output_max_bytes must be greater than zero"));

        let error = match TimedSystemCommandRunner::with_output_max_bytes(
            Duration::from_secs(1),
            MAX_SYSTEM_COMMAND_OUTPUT_MAX_BYTES + 1,
        )
        .run(LinuxCommand::new("sh", ["-c", "exit 0"]))
        .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("output_max_bytes must not exceed 1048576"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn timed_system_command_runner_times_out_and_reaps_child() -> Result<(), AgentError> {
        let temp_dir = std::env::temp_dir().join(format!(
            "ipars-agent-command-timeout-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir(&temp_dir)?;
        let pid_path = temp_dir.join("child.pid");
        let grandchild_pid_path = temp_dir.join("grandchild.pid");
        let script = format!(
            "printf '%s\\n' $$ > {}; sleep 60 & printf '%s\\n' $! > {}; wait",
            pid_path.display(),
            grandchild_pid_path.display()
        );
        let runner = TimedSystemCommandRunner::new(Duration::from_millis(100));
        let error = match runner.run(LinuxCommand::new("sh", ["-c", &script])).await {
            Ok(()) => panic!("command should time out"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("timed out after 100ms"));
        let pid = wait_for_pid_file(&pid_path, Duration::from_secs(1)).await?;
        let grandchild_pid =
            wait_for_pid_file(&grandchild_pid_path, Duration::from_secs(1)).await?;
        assert!(
            wait_for_process_absent(pid, Duration::from_secs(2)).await,
            "timed-out command child process {pid} was left running"
        );
        assert!(
            wait_for_process_absent(grandchild_pid, Duration::from_secs(2)).await,
            "timed-out command grandchild process {grandchild_pid} was left running"
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_command_runner_truncates_failure_stderr() {
        let runner = TimedSystemCommandRunner::with_output_max_bytes(Duration::from_secs(1), 16);
        let error = match runner
            .run(LinuxCommand::new(
                "sh",
                ["-c", "printf '0123456789abcdefEXTRA' >&2; exit 7"],
            ))
            .await
        {
            Ok(()) => panic!("command should fail"),
            Err(error) => error,
        };
        let message = error.to_string();
        let stderr = match message.rsplit_once("failed: ") {
            Some((_, stderr)) => stderr,
            None => panic!("failure should include stderr"),
        };

        assert!(stderr.contains("0123456789abcdef"));
        assert!(!stderr.contains("EXTRA"));
        assert!(stderr.contains("stderr truncated after 16 bytes"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_command_runner_drains_large_stdout_with_bound() -> Result<(), AgentError>
    {
        let runner = TimedSystemCommandRunner::with_output_max_bytes(Duration::from_secs(1), 16);

        runner
            .run(LinuxCommand::new(
                "sh",
                [
                    "-c",
                    "i=0; while [ $i -lt 5000 ]; do printf 0123456789abcdef; i=$((i + 1)); done",
                ],
            ))
            .await
    }

    #[cfg(target_os = "linux")]
    async fn wait_for_pid_file(path: &Path, timeout: Duration) -> Result<u32, AgentError> {
        let started = Instant::now();
        loop {
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    let contents = contents.trim();
                    if !contents.is_empty() {
                        return contents.parse::<u32>().map_err(|error| {
                            AgentError::WireGuard(format!("failed to parse child pid: {error}"))
                        });
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(AgentError::Io(error)),
            }
            if started.elapsed() >= timeout {
                return Err(AgentError::WireGuard(format!(
                    "timed out waiting for child pid file {}",
                    path.display()
                )));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    #[cfg(target_os = "linux")]
    async fn wait_for_process_absent(pid: u32, timeout: Duration) -> bool {
        let started = Instant::now();
        let process_path = Path::new("/proc").join(pid.to_string());
        while started.elapsed() < timeout {
            if !process_path.exists() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        !process_path.exists()
    }

    #[derive(Debug, Default)]
    struct RecordingRouteManager {
        applied: tokio::sync::RwLock<Vec<RoutePlan>>,
        removed: tokio::sync::RwLock<Vec<RoutePlan>>,
    }

    #[async_trait]
    impl RouteManager for RecordingRouteManager {
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
                "docker intent is not used by agent tests".to_string(),
            ))
        }

        async fn apply_kubernetes_intent(
            &self,
            _intent: KubernetesUnderlayIntent,
        ) -> Result<RoutePlan, RouteManagerError> {
            Err(RouteManagerError::Backend(
                "kubernetes intent is not used by agent tests".to_string(),
            ))
        }
    }

    fn peer_record(
        node_id: NodeId,
        vpn_ip: IpAddr,
        wireguard_public_key: &str,
        endpoint_candidates: Vec<EndpointCandidate>,
        routes: Vec<Route>,
    ) -> NodeRecord {
        NodeRecord {
            node_id,
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(vpn_ip),
            identity_public_key: "identity-public".to_string(),
            wireguard_public_key: wireguard_public_key.to_string(),
            role: Role::edge(),
            tags: Default::default(),
            endpoint_candidates,
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes,
            registered_at: Utc::now(),
        }
    }

    #[derive(Debug, Clone)]
    struct StaticPeerMapSource {
        expected_node_id: NodeId,
        peer_map: PeerMap,
        requests: Arc<tokio::sync::RwLock<Vec<NodeId>>>,
    }

    impl StaticPeerMapSource {
        fn new(expected_node_id: NodeId, peer_map: PeerMap) -> Self {
            Self {
                expected_node_id,
                peer_map,
                requests: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl PeerMapSource for StaticPeerMapSource {
        async fn fetch_peer_map(&self, node_id: &NodeId) -> Result<PeerMap, AgentError> {
            self.requests.write().await.push(node_id.clone());
            if node_id == &self.expected_node_id {
                Ok(self.peer_map.clone())
            } else {
                Err(AgentError::ControlPlaneClient(format!(
                    "unexpected node id {node_id}"
                )))
            }
        }
    }

    fn wireguard_transport_payload_with_len(len: usize, fill: u8) -> Vec<u8> {
        assert!(len >= 32);
        assert!(len.is_multiple_of(16));
        let mut payload = vec![fill; len];
        payload[..4].copy_from_slice(&4_u32.to_le_bytes());
        payload
    }

    fn wireguard_transport_payload(fill: u8) -> Vec<u8> {
        wireguard_transport_payload_with_len(32, fill)
    }

    fn oversized_wireguard_transport_payload(fill: u8) -> Vec<u8> {
        let len = ((MAX_FORWARDER_UDP_PAYLOAD_BYTES / 16) + 1) * 16;
        wireguard_transport_payload_with_len(len, fill)
    }

    #[test]
    fn relay_forwarder_sender_match_allows_unspecified_wireguard_address() {
        let observed_v4 = SocketAddr::from(([127, 0, 0, 1], 51_820));
        let observed_v6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 51_820));
        assert!(wireguard_sender_matches_configured(
            SocketAddr::from(([0, 0, 0, 0], 51_820)),
            observed_v4
        ));
        assert!(wireguard_sender_matches_configured(
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 51_820)),
            observed_v6
        ));
        assert!(!wireguard_sender_matches_configured(
            SocketAddr::from(([0, 0, 0, 0], 51_821)),
            observed_v4
        ));
        assert!(!wireguard_sender_matches_configured(
            SocketAddr::from(([0, 0, 0, 0], 51_820)),
            observed_v6
        ));
        assert!(!wireguard_sender_matches_configured(
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 51_820)),
            observed_v4
        ));
        assert!(!wireguard_sender_matches_configured(
            SocketAddr::from(([127, 0, 0, 2], 51_820)),
            observed_v4
        ));
    }

    #[derive(Debug, Clone)]
    struct RecordingPeerMapSink {
        summary: PeerMapApplySummary,
        applied: Arc<tokio::sync::RwLock<Vec<PeerMap>>>,
    }

    impl RecordingPeerMapSink {
        fn new(summary: PeerMapApplySummary) -> Self {
            Self {
                summary,
                applied: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl PeerMapSink for RecordingPeerMapSink {
        async fn apply_peer_map_update(
            &self,
            peer_map: PeerMap,
        ) -> Result<PeerMapApplySummary, AgentError> {
            self.applied.write().await.push(peer_map);
            Ok(self.summary.clone())
        }
    }

    #[test]
    fn lazy_manager_keeps_pinned_peers_open() {
        let mut manager = LazyConnectManager::new(ClusterPolicy {
            idle_timeout_seconds: 10,
            ..ClusterPolicy::default()
        });
        manager.record_activity(
            NodeId::from_string("peer-a"),
            Utc::now() - ChronoDuration::seconds(30),
        );
        manager.pin_peer(NodeId::from_string("peer-a"));

        assert!(manager.idle_peers_to_close(Utc::now()).is_empty());
    }

    #[test]
    fn lazy_manager_pins_default_important_peer_classes() {
        let mut manager = LazyConnectManager::new(ClusterPolicy::default());
        let mut control_plane = peer_record(
            NodeId::from_string("control-plane-a"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 20)),
            "wg-control-plane",
            Vec::new(),
            Vec::new(),
        );
        control_plane.role = Role::control_plane();
        let mut route_provider = peer_record(
            NodeId::from_string("route-provider-a"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 21)),
            "wg-route-provider",
            Vec::new(),
            Vec::new(),
        );
        route_provider.tags.insert(Tag::route_provider());
        let mut kubernetes_control_plane = peer_record(
            NodeId::from_string("kubernetes-control-plane-a"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 22)),
            "wg-kubernetes-control-plane",
            Vec::new(),
            Vec::new(),
        );
        kubernetes_control_plane
            .tags
            .insert(Tag::kubernetes_control_plane());
        let mut relay = peer_record(
            NodeId::from_string("relay-a"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 23)),
            "wg-relay",
            Vec::new(),
            Vec::new(),
        );
        relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 10], 3478))),
            admission_url: Some("https://relay-a.example.test/v1/sessions".to_string()),
            max_sessions: 100,
            active_sessions: 10,
            max_mbps: 1000,
            e2e_only: true,
        });
        let ordinary = peer_record(
            NodeId::from_string("ordinary-a"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 24)),
            "wg-ordinary",
            Vec::new(),
            Vec::new(),
        );

        for peer in [
            &control_plane,
            &route_provider,
            &kubernetes_control_plane,
            &relay,
            &ordinary,
        ] {
            manager.observe_peer(peer);
        }

        assert!(manager.should_connect_peer(&control_plane));
        assert!(manager.should_connect_peer(&route_provider));
        assert!(manager.should_connect_peer(&kubernetes_control_plane));
        assert!(!manager.should_connect_peer(&relay));
        assert!(!manager.should_connect_peer(&ordinary));
        assert_eq!(manager.metrics().pinned_peer_count, 3);
    }

    #[test]
    fn lazy_manager_does_not_auto_pin_relay_candidates() {
        let mut manager = LazyConnectManager::new(ClusterPolicy::default());
        let mut relay = peer_record(
            NodeId::from_string("relay-a"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10)),
            "wg-relay",
            Vec::new(),
            Vec::new(),
        );
        relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 10], 51820))),
            admission_url: Some("http://203.0.113.10:9580".to_string()),
            max_sessions: 1024,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        });

        manager.observe_peer(&relay);

        assert!(!manager.should_connect_peer(&relay));
        assert_eq!(manager.metrics().observed_peer_vpn_ip_count, 1);
        assert_eq!(manager.metrics().pinned_peer_count, 0);
    }

    #[test]
    fn selector_promotes_direct_path_over_relay_when_score_improves() {
        let relay = path("peer-a", PathState::Relay, 70.0);
        let direct = path("peer-a", PathState::DirectNatTraversal, 90.0);

        assert!(PathSelector::should_promote(&relay, &direct));
    }

    #[test]
    fn selector_keeps_relay_when_direct_score_gain_is_too_small() {
        let relay = path("peer-a", PathState::Relay, 70.0);
        let direct = path("peer-a", PathState::DirectNatTraversal, 74.9);

        assert!(!PathSelector::should_promote(&relay, &direct));
    }

    #[test]
    fn score_helper_keeps_metrics_type_in_scope() {
        let score = PathScore::calculate(PathState::DirectPublic, &PathMetrics::default(), true, 0);
        assert!(score.value > 0.0);
    }

    #[test]
    fn preferred_endpoint_skips_invalid_or_unusable_direct_candidates() {
        let peer_id = NodeId::from_string("peer-a");
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
            "wg-peer-a",
            vec![
                EndpointCandidate {
                    node_id: peer_id.clone(),
                    kind: EndpointCandidateKind::Ipv6,
                    addr: SocketAddr::from(([198, 51, 100, 10], 51820)),
                    observed_at: Utc::now(),
                    priority: 100,
                    cost: 1,
                    source: CandidateSource::ControlPlane,
                },
                EndpointCandidate {
                    node_id: NodeId::from_string("wrong-owner"),
                    kind: EndpointCandidateKind::PublicUdp,
                    addr: SocketAddr::from(([203, 0, 113, 10], 51820)),
                    observed_at: Utc::now(),
                    priority: 100,
                    cost: 1,
                    source: CandidateSource::ControlPlane,
                },
                EndpointCandidate {
                    node_id: peer_id.clone(),
                    kind: EndpointCandidateKind::PublicUdp,
                    addr: SocketAddr::from(([203, 0, 113, 11], 0)),
                    observed_at: Utc::now(),
                    priority: 100,
                    cost: 1,
                    source: CandidateSource::ControlPlane,
                },
                EndpointCandidate {
                    node_id: peer_id.clone(),
                    kind: EndpointCandidateKind::StunReflexive,
                    addr: SocketAddr::from(([198, 51, 100, 20], 51820)),
                    observed_at: Utc::now(),
                    priority: 10,
                    cost: 50,
                    source: CandidateSource::StunProbe,
                },
            ],
            Vec::new(),
        );

        assert_eq!(
            preferred_endpoint(&peer).as_deref(),
            Some("198.51.100.20:51820")
        );
    }

    #[tokio::test]
    async fn runtime_endpoint_resolver_falls_back_when_selected_candidate_is_unusable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let local_id = runtime.state().node_id.clone();
        let peer_id = NodeId::from_string("peer-a");
        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(local_id, peer_id.clone()),
                selected_state: PathState::DirectPublic,
                selected_candidate: Some(EndpointCandidate {
                    node_id: peer_id.clone(),
                    kind: EndpointCandidateKind::PublicUdp,
                    addr: SocketAddr::from(([203, 0, 113, 10], 0)),
                    observed_at: Utc::now(),
                    priority: 100,
                    cost: 1,
                    source: CandidateSource::ControlPlane,
                }),
                relay_node: None,
                score: PathScore {
                    value: 100.0,
                    reasons: Vec::new(),
                },
                updated_at: Utc::now(),
                pinned: false,
            })
            .await;
        let peer = peer_record(
            peer_id,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
            "wg-peer-a",
            vec![EndpointCandidate {
                node_id: NodeId::from_string("peer-a"),
                kind: EndpointCandidateKind::PublicUdp,
                addr: SocketAddr::from(([203, 0, 113, 20], 51820)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::ControlPlane,
            }],
            Vec::new(),
        );

        let endpoint = RuntimePeerEndpointResolver::new(runtime)
            .endpoint_for_peer(&peer)
            .await?;

        assert_eq!(endpoint.as_deref(), Some("203.0.113.20:51820"));
        Ok(())
    }

    #[tokio::test]
    async fn runtime_stores_latest_path_state() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let first = path("peer-a", PathState::Relay, 70.0);
        let latest = path("peer-a", PathState::DirectPublic, 115.0);

        runtime.upsert_path_state(first).await;
        runtime.upsert_path_state(latest.clone()).await;

        assert_eq!(runtime.path_state().await, vec![latest]);
    }

    #[tokio::test]
    async fn runtime_direct_path_state_clears_relay_session_and_forwarder_state() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local = runtime.state().node_id;
        let peer = NodeId::from_string("peer-a");
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: peer.clone(),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 20], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-a".to_string(),
                session_token: "secret-a".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
            })
            .await;
        runtime
            .upsert_relay_forwarder_endpoint(
                peer.clone(),
                SocketAddr::from(([127, 0, 0, 1], 50000)),
            )
            .await;

        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(local, peer.clone()),
                selected_state: PathState::DirectPublic,
                selected_candidate: None,
                relay_node: None,
                score: PathScore {
                    value: 110.0,
                    reasons: Vec::new(),
                },
                updated_at: Utc::now(),
                pinned: false,
            })
            .await;

        assert!(runtime.relay_session(&peer).await.is_none());
        assert!(runtime.relay_forwarder_endpoint(&peer).await.is_none());
    }

    #[tokio::test]
    async fn runtime_records_path_change_events_and_metrics() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let first = path("peer-a", PathState::Relay, 70.0);
        let latest = path("peer-a", PathState::DirectPublic, 115.0);
        runtime.upsert_path_state(first.clone()).await;
        runtime.upsert_path_state(first.clone()).await;
        runtime.upsert_path_state(latest.clone()).await;

        let events = runtime.path_change_events().await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, PathChangeKind::Created);
        assert_eq!(events[0].previous_state, None);
        assert_eq!(events[0].new_state, PathState::Relay);
        assert_eq!(events[1].kind, PathChangeKind::StateChanged);
        assert_eq!(events[1].previous_state, Some(PathState::Relay));
        assert_eq!(events[1].new_state, PathState::DirectPublic);

        let metrics = runtime.metrics().await;
        assert_eq!(metrics.path_count, 1);
        assert_eq!(metrics.path_change_event_count, 2);
        assert_eq!(metrics.relay_session_count, 0);
        assert_eq!(metrics.relay_admission_attempt_count, 0);
        assert_eq!(metrics.relay_admission_success_count, 0);
        assert_eq!(metrics.relay_admission_failure_count, 0);
        assert!(metrics.relay_forwarders.is_empty());
        assert_eq!(
            metrics.path_state_counts,
            vec![
                PathStateCount {
                    state: PathState::DirectPublic,
                    count: 1,
                },
                PathStateCount {
                    state: PathState::DirectIpv6,
                    count: 0,
                },
                PathStateCount {
                    state: PathState::DirectNatTraversal,
                    count: 0,
                },
                PathStateCount {
                    state: PathState::Relay,
                    count: 0,
                },
                PathStateCount {
                    state: PathState::Unreachable,
                    count: 0,
                },
            ]
        );
    }

    #[tokio::test]
    async fn runtime_records_path_probe_metrics_and_pins_peer() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer_id = NodeId::from_string("peer-a");
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
            "wg-peer-a",
            Vec::new(),
            Vec::new(),
        );
        let metrics = PathMetrics {
            latency_ms: Some(42.0),
            loss_ppm: 250,
            jitter_ms: Some(5.0),
            relay_load: None,
            stability: 0.8,
        };
        let request = AgentPathProbeRequest {
            peer: peer.node_id.clone(),
            selected_state: PathState::DirectPublic,
            selected_candidate: Some(EndpointCandidate {
                node_id: peer_id,
                kind: EndpointCandidateKind::PublicUdp,
                addr: SocketAddr::from(([203, 0, 113, 10], 51820)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::ControlPlane,
            }),
            relay_node: None,
            metrics,
            policy_allowed: true,
            cost: 10,
            pin: true,
        };
        let path = runtime.record_path_probe(request, Utc::now()).await;

        assert_eq!(path.selected_state, PathState::DirectPublic);
        assert!(path
            .score
            .reasons
            .iter()
            .any(|reason| reason == "latency_ms=42.0"));
        assert!(path
            .score
            .reasons
            .iter()
            .any(|reason| reason == "loss_ppm=250"));
        assert!(path
            .score
            .reasons
            .iter()
            .any(|reason| reason == "jitter_ms=5.0"));
        assert!(path
            .score
            .reasons
            .iter()
            .any(|reason| reason == "stability=0.80"));
        assert_eq!(runtime.metrics().await.path_probe_record_count, 1);
        assert!(runtime.should_connect_peer(&peer).await);
        assert_eq!(
            runtime.path_record_for_peer(&peer.node_id).await,
            Some(path)
        );
    }

    #[tokio::test]
    async fn runtime_records_relay_admission_metrics() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );

        runtime.record_relay_admission_attempt();
        runtime.record_relay_admission_attempt();
        runtime.record_relay_admission_success();
        runtime.record_relay_admission_failure_reason(
            AgentRelayAdmissionFailureReason::InvalidResponse,
        );

        let metrics = runtime.metrics().await;
        assert_eq!(metrics.relay_admission_attempt_count, 2);
        assert_eq!(metrics.relay_admission_success_count, 1);
        assert_eq!(metrics.relay_admission_failure_count, 1);
        assert_eq!(metrics.relay_admission_failure_reason_counts.len(), 1);
        assert_eq!(
            metrics.relay_admission_failure_reason_counts[0].reason,
            AgentRelayAdmissionFailureReason::InvalidResponse
        );
        assert_eq!(metrics.relay_admission_failure_reason_counts[0].count, 1);
    }

    #[tokio::test]
    async fn runtime_stores_relay_sessions_separately_from_path_state() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer = NodeId::from_string("peer-a");
        let session = RelaySessionState {
            peer: peer.clone(),
            relay_node: NodeId::from_string("relay-a"),
            relay_endpoint: SocketAddr::from(([203, 0, 113, 20], 51820)),
            admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
            admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
            session_id: "session-a".to_string(),
            session_token: "secret".to_string(),
            expires_at: Utc::now() + ChronoDuration::seconds(60),
        };

        runtime.upsert_relay_session(session.clone()).await;

        assert_eq!(runtime.relay_session(&peer).await, Some(session));
        assert!(runtime.path_state().await.is_empty());
    }

    #[tokio::test]
    async fn runtime_purges_expired_relay_sessions_and_forwarder_state() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let now = Utc::now();
        let expired_peer = NodeId::from_string("peer-expired");
        let active_peer = NodeId::from_string("peer-active");
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: expired_peer.clone(),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 20], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-expired".to_string(),
                session_token: "secret-expired".to_string(),
                expires_at: now - ChronoDuration::seconds(1),
            })
            .await;
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: active_peer.clone(),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 20], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 21], 40000)),
                session_id: "session-active".to_string(),
                session_token: "secret-active".to_string(),
                expires_at: now + ChronoDuration::seconds(60),
            })
            .await;
        runtime
            .upsert_relay_forwarder_endpoint(
                expired_peer.clone(),
                SocketAddr::from(([127, 0, 0, 1], 50000)),
            )
            .await;
        runtime
            .upsert_relay_forwarder_endpoint(
                active_peer.clone(),
                SocketAddr::from(([127, 0, 0, 1], 50001)),
            )
            .await;

        let removed = runtime.purge_expired_relay_sessions(now).await;

        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].peer, expired_peer);
        assert!(runtime.relay_session(&expired_peer).await.is_none());
        assert!(runtime
            .relay_forwarder_endpoint(&expired_peer)
            .await
            .is_none());
        assert!(runtime.relay_session(&active_peer).await.is_some());
        assert_eq!(
            runtime.relay_forwarder_endpoint(&active_peer).await,
            Some(SocketAddr::from(([127, 0, 0, 1], 50001)))
        );
    }

    #[tokio::test]
    async fn runtime_metrics_exclude_expired_relay_sessions() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let now = Utc::now();
        let expired_peer = NodeId::from_string("peer-expired");
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: expired_peer.clone(),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 20], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-expired".to_string(),
                session_token: "secret-expired".to_string(),
                expires_at: now - ChronoDuration::seconds(1),
            })
            .await;
        runtime
            .upsert_relay_forwarder_endpoint(
                expired_peer.clone(),
                SocketAddr::from(([127, 0, 0, 1], 50000)),
            )
            .await;

        let metrics = runtime.metrics().await;

        assert_eq!(metrics.relay_session_count, 0);
        assert_eq!(metrics.relay_forwarder_count, 0);
        assert!(runtime.relay_session(&expired_peer).await.is_none());
        assert!(runtime
            .relay_forwarder_endpoint(&expired_peer)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn runtime_active_relay_session_removes_expired_session() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let now = Utc::now();
        let peer = NodeId::from_string("peer-a");
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: peer.clone(),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 20], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-expired".to_string(),
                session_token: "secret-expired".to_string(),
                expires_at: now - ChronoDuration::seconds(1),
            })
            .await;
        runtime
            .upsert_relay_forwarder_endpoint(
                peer.clone(),
                SocketAddr::from(([127, 0, 0, 1], 50000)),
            )
            .await;

        assert!(runtime.active_relay_session(&peer, now).await.is_none());
        assert!(runtime.relay_session(&peer).await.is_none());
        assert!(runtime.relay_forwarder_endpoint(&peer).await.is_none());
    }

    #[tokio::test]
    async fn runtime_relay_session_accessor_excludes_expired_sessions() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let now = Utc::now();
        let expired_peer = NodeId::from_string("peer-expired");
        let active_peer = NodeId::from_string("peer-active");
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: expired_peer.clone(),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 20], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-expired".to_string(),
                session_token: "secret-expired".to_string(),
                expires_at: now - ChronoDuration::seconds(1),
            })
            .await;
        let active_session = RelaySessionState {
            peer: active_peer.clone(),
            relay_node: NodeId::from_string("relay-a"),
            relay_endpoint: SocketAddr::from(([203, 0, 113, 20], 51820)),
            admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
            admitted_peer_addr: SocketAddr::from(([198, 51, 100, 21], 40000)),
            session_id: "session-active".to_string(),
            session_token: "secret-active".to_string(),
            expires_at: now + ChronoDuration::seconds(60),
        };
        runtime.upsert_relay_session(active_session.clone()).await;
        runtime
            .upsert_relay_forwarder_endpoint(
                expired_peer.clone(),
                SocketAddr::from(([127, 0, 0, 1], 50000)),
            )
            .await;

        assert!(runtime.relay_session(&expired_peer).await.is_none());
        assert!(runtime
            .relay_forwarder_endpoint(&expired_peer)
            .await
            .is_none());
        assert_eq!(runtime.relay_sessions().await, vec![active_session.clone()]);
        assert_eq!(
            runtime.relay_session(&active_peer).await,
            Some(active_session)
        );
    }

    #[tokio::test]
    async fn runtime_renewal_check_purges_expired_relay_session() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let now = Utc::now();
        let peer = NodeId::from_string("peer-a");
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: peer.clone(),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 20], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-expired".to_string(),
                session_token: "secret-expired".to_string(),
                expires_at: now - ChronoDuration::seconds(1),
            })
            .await;
        runtime
            .upsert_relay_forwarder_endpoint(
                peer.clone(),
                SocketAddr::from(([127, 0, 0, 1], 50000)),
            )
            .await;

        assert!(
            runtime
                .relay_session_needs_renewal(
                    &peer,
                    &NodeId::from_string("relay-a"),
                    now,
                    std::time::Duration::from_secs(60),
                )
                .await
        );
        assert!(runtime.relay_session(&peer).await.is_none());
        assert!(runtime.relay_forwarder_endpoint(&peer).await.is_none());
    }

    #[tokio::test]
    async fn runtime_relay_forwarder_endpoint_uses_supplied_time_for_expiry() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let now = Utc::now();
        let local_id = runtime.state().node_id.clone();
        let peer = NodeId::from_string("peer-a");
        let relay_node = NodeId::from_string("relay-a");
        let forwarder_endpoint = SocketAddr::from(([127, 0, 0, 1], 50000));
        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(local_id, peer.clone()),
                selected_state: PathState::Relay,
                selected_candidate: None,
                relay_node: Some(relay_node.clone()),
                score: PathScore {
                    value: 70.0,
                    reasons: Vec::new(),
                },
                updated_at: now,
                pinned: false,
            })
            .await;
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: peer.clone(),
                relay_node,
                relay_endpoint: SocketAddr::from(([203, 0, 113, 20], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-a".to_string(),
                session_token: "secret-a".to_string(),
                expires_at: now + ChronoDuration::seconds(1),
            })
            .await;
        runtime
            .upsert_relay_forwarder_endpoint(peer.clone(), forwarder_endpoint)
            .await;

        assert_eq!(
            runtime
                .relay_forwarder_endpoint_for_peer(&peer, now, None)
                .await,
            Some(forwarder_endpoint)
        );
        assert_eq!(
            runtime
                .relay_forwarder_endpoint_for_peer(&peer, now + ChronoDuration::seconds(2), None)
                .await,
            None
        );
        assert!(runtime.relay_session(&peer).await.is_none());
        assert!(runtime.relay_forwarder_endpoint(&peer).await.is_none());
    }

    #[tokio::test]
    async fn runtime_renews_relay_sessions_before_expiry_or_relay_change() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let now = Utc::now();
        let peer = NodeId::from_string("peer-a");
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: peer.clone(),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 20], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-a".to_string(),
                session_token: "secret".to_string(),
                expires_at: now + ChronoDuration::seconds(120),
            })
            .await;
        runtime
            .upsert_relay_forwarder_endpoint(
                peer.clone(),
                SocketAddr::from(([127, 0, 0, 1], 50000)),
            )
            .await;

        assert!(
            !runtime
                .relay_session_needs_renewal(
                    &peer,
                    &NodeId::from_string("relay-a"),
                    now,
                    std::time::Duration::from_secs(60),
                )
                .await
        );
        assert!(
            runtime
                .relay_session_needs_renewal(
                    &peer,
                    &NodeId::from_string("relay-a"),
                    now + ChronoDuration::seconds(70),
                    std::time::Duration::from_secs(60),
                )
                .await
        );
        assert!(
            runtime
                .relay_session_needs_renewal(
                    &peer,
                    &NodeId::from_string("relay-b"),
                    now,
                    std::time::Duration::from_secs(60),
                )
                .await
        );
        assert!(runtime.remove_relay_session(&peer).await.is_some());
        assert!(runtime.relay_session(&peer).await.is_none());
        assert!(runtime.relay_forwarder_endpoint(&peer).await.is_none());
    }

    #[tokio::test]
    async fn relay_frame_forwarder_sends_framed_payload_to_relay(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let relay = UdpRelay::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let relay_addr = relay.local_addr()?;
        let left_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let right_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let service = RelayService::new(
            NodeId::from_string("relay-a"),
            RelayCapability {
                enabled_by_policy: true,
                public_endpoint: Some(relay_addr),
                admission_url: Some("http://127.0.0.1:9580".to_string()),
                max_sessions: 10,
                active_sessions: 0,
                max_mbps: 1000,
                e2e_only: true,
            },
        );
        let admission = service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left"),
                right: NodeId::from_string("right"),
                left_addr: left_socket.local_addr()?,
                right_addr: right_socket.local_addr()?,
            })
            .await?;
        let forwarder = UdpRelayFrameForwarder::new(
            RelaySessionState {
                peer: NodeId::from_string("right"),
                relay_node: admission.relay_node,
                relay_endpoint: relay_addr,
                admitted_local_addr: admission.left_addr,
                admitted_peer_addr: admission.right_addr,
                session_id: admission.session_id,
                session_token: admission.session_token,
                expires_at: admission.expires_at,
            },
            left_socket.local_addr()?,
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let relay_task = tokio::spawn(relay.serve(service.table(), shutdown_rx));

        let outbound_payload = wireguard_transport_payload(0xa1);
        forwarder
            .send_to_relay(&left_socket, &outbound_payload)
            .await?;
        let mut buffer = [0_u8; 128];
        let (len, _peer) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            right_socket.recv_from(&mut buffer),
        )
        .await??;

        assert_eq!(&buffer[..len], outbound_payload.as_slice());
        shutdown_tx.send(true)?;
        relay_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn relay_frame_forwarder_drops_expired_session_datagrams_without_error(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let forwarder_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let relay_receiver =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let wireguard_receiver =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let relay_addr = relay_receiver.local_addr()?;
        let wireguard_addr = wireguard_receiver.local_addr()?;
        let stats = Arc::new(RelayForwarderStats::new(
            NodeId::from_string("right"),
            NodeId::from_string("relay-a"),
            relay_addr,
            forwarder_socket.local_addr()?,
        ));
        let forwarder = UdpRelayFrameForwarder::new(
            RelaySessionState {
                peer: NodeId::from_string("right"),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: relay_addr,
                admitted_local_addr: forwarder_socket.local_addr()?,
                admitted_peer_addr: SocketAddr::from(([127, 0, 0, 1], 60_000)),
                session_id: "expired-session".to_string(),
                session_token: "expired-token".to_string(),
                expires_at: Utc::now() - ChronoDuration::seconds(1),
            },
            wireguard_addr,
        )
        .with_metrics(stats.clone());

        let outbound_payload = wireguard_transport_payload(0xe1);
        assert_eq!(
            forwarder
                .send_to_relay(&forwarder_socket, &outbound_payload)
                .await?,
            0
        );
        let inbound_payload = wireguard_transport_payload(0xe2);
        assert_eq!(
            forwarder
                .forward_to_wireguard(&forwarder_socket, &inbound_payload)
                .await?,
            0
        );
        let mut buffer = [0_u8; 128];
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            relay_receiver.recv_from(&mut buffer)
        )
        .await
        .is_err());
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            wireguard_receiver.recv_from(&mut buffer)
        )
        .await
        .is_err());

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.outbound_packets, 0);
        assert_eq!(snapshot.inbound_packets, 0);
        assert_eq!(snapshot.outbound_dropped_expired_session_packets, 1);
        assert_eq!(
            snapshot.outbound_dropped_expired_session_payload_bytes,
            outbound_payload.len() as u64
        );
        assert_eq!(snapshot.inbound_dropped_expired_session_packets, 1);
        assert_eq!(
            snapshot.inbound_dropped_expired_session_payload_bytes,
            inbound_payload.len() as u64
        );
        assert!(snapshot.last_forwarded_at.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn relay_frame_forwarder_drops_oversized_datagrams_without_error(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let forwarder_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let relay_receiver =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let wireguard_receiver =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let relay_addr = relay_receiver.local_addr()?;
        let wireguard_addr = wireguard_receiver.local_addr()?;
        let stats = Arc::new(RelayForwarderStats::new(
            NodeId::from_string("right"),
            NodeId::from_string("relay-a"),
            relay_addr,
            forwarder_socket.local_addr()?,
        ));
        let forwarder = UdpRelayFrameForwarder::new(
            RelaySessionState {
                peer: NodeId::from_string("right"),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: relay_addr,
                admitted_local_addr: forwarder_socket.local_addr()?,
                admitted_peer_addr: SocketAddr::from(([127, 0, 0, 1], 60_001)),
                session_id: "left:right".to_string(),
                session_token: "active-token".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
            },
            wireguard_addr,
        )
        .with_metrics(stats.clone());

        let outbound_payload = oversized_wireguard_transport_payload(0xe3);
        let outbound_datagram_bytes = forwarder.encode_outbound(&outbound_payload)?.len();
        assert!(outbound_datagram_bytes > MAX_FORWARDER_UDP_PAYLOAD_BYTES);
        assert_eq!(
            forwarder
                .send_to_relay(&forwarder_socket, &outbound_payload)
                .await?,
            0
        );
        let inbound_payload = oversized_wireguard_transport_payload(0xe4);
        assert_eq!(
            forwarder
                .forward_to_wireguard(&forwarder_socket, &inbound_payload)
                .await?,
            0
        );
        let mut buffer = [0_u8; 128];
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            relay_receiver.recv_from(&mut buffer)
        )
        .await
        .is_err());
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            wireguard_receiver.recv_from(&mut buffer)
        )
        .await
        .is_err());

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.outbound_packets, 0);
        assert_eq!(snapshot.inbound_packets, 0);
        assert_eq!(snapshot.outbound_dropped_oversized_packets, 1);
        assert_eq!(
            snapshot.outbound_dropped_oversized_payload_bytes,
            outbound_payload.len() as u64
        );
        assert_eq!(
            snapshot.outbound_dropped_oversized_datagram_bytes,
            outbound_datagram_bytes as u64
        );
        assert_eq!(snapshot.inbound_dropped_oversized_packets, 1);
        assert_eq!(
            snapshot.inbound_dropped_oversized_payload_bytes,
            inbound_payload.len() as u64
        );
        assert!(snapshot.last_forwarded_at.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn relay_frame_forwarder_records_socket_errors_without_error(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let forwarder_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let stats = Arc::new(RelayForwarderStats::new(
            NodeId::from_string("right"),
            NodeId::from_string("relay-a"),
            SocketAddr::from(([127, 0, 0, 1], 0)),
            forwarder_socket.local_addr()?,
        ));
        let forwarder = UdpRelayFrameForwarder::new(
            RelaySessionState {
                peer: NodeId::from_string("right"),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: SocketAddr::from(([127, 0, 0, 1], 0)),
                admitted_local_addr: forwarder_socket.local_addr()?,
                admitted_peer_addr: SocketAddr::from(([127, 0, 0, 1], 60_002)),
                session_id: "left:right".to_string(),
                session_token: "active-token".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
            },
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .with_metrics(stats.clone());

        let outbound_payload = wireguard_transport_payload(0xe5);
        let outbound_datagram_bytes = forwarder.encode_outbound(&outbound_payload)?.len();
        assert_eq!(
            forwarder
                .send_to_relay(&forwarder_socket, &outbound_payload)
                .await?,
            0
        );
        let inbound_payload = wireguard_transport_payload(0xe6);
        assert_eq!(
            forwarder
                .forward_to_wireguard(&forwarder_socket, &inbound_payload)
                .await?,
            0
        );

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.outbound_packets, 0);
        assert_eq!(snapshot.inbound_packets, 0);
        assert_eq!(snapshot.outbound_dropped_socket_error_packets, 1);
        assert_eq!(
            snapshot.outbound_dropped_socket_error_payload_bytes,
            outbound_payload.len() as u64
        );
        assert_eq!(
            snapshot.outbound_dropped_socket_error_datagram_bytes,
            outbound_datagram_bytes as u64
        );
        assert_eq!(snapshot.inbound_dropped_socket_error_packets, 1);
        assert_eq!(
            snapshot.inbound_dropped_socket_error_payload_bytes,
            inbound_payload.len() as u64
        );
        assert!(snapshot.last_forwarded_at.is_none());
        Ok(())
    }

    #[test]
    fn relay_frame_forwarder_counts_recoverable_receive_errors() {
        let stats = RelayForwarderStats::new(
            NodeId::from_string("right"),
            NodeId::from_string("relay-a"),
            SocketAddr::from(([127, 0, 0, 1], 51_820)),
            SocketAddr::from(([127, 0, 0, 1], 52_000)),
        );

        assert!(recoverable_udp_recv_error(&std::io::Error::from(
            std::io::ErrorKind::Interrupted
        )));
        assert!(recoverable_udp_recv_error(&std::io::Error::from(
            std::io::ErrorKind::WouldBlock
        )));
        assert!(!recoverable_udp_recv_error(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));

        stats.record_socket_receive_error();
        stats.record_socket_receive_error();
        assert_eq!(stats.snapshot().socket_receive_errors, 2);
    }

    #[tokio::test]
    async fn relay_frame_forwarder_proxies_wireguard_and_relay_datagrams(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let relay = UdpRelay::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let relay_addr = relay.local_addr()?;
        let forwarder_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let forwarder_addr = forwarder_socket.local_addr()?;
        let wireguard_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let wireguard_addr = wireguard_socket.local_addr()?;
        let unexpected_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let peer_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let peer_addr = peer_socket.local_addr()?;
        let service = RelayService::new(
            NodeId::from_string("relay-a"),
            RelayCapability {
                enabled_by_policy: true,
                public_endpoint: Some(relay_addr),
                admission_url: Some("http://127.0.0.1:9580".to_string()),
                max_sessions: 10,
                active_sessions: 0,
                max_mbps: 1000,
                e2e_only: true,
            },
        );
        let admission = service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left"),
                right: NodeId::from_string("right"),
                left_addr: forwarder_addr,
                right_addr: peer_addr,
            })
            .await?;
        let stats = Arc::new(RelayForwarderStats::new(
            NodeId::from_string("right"),
            admission.relay_node.clone(),
            relay_addr,
            forwarder_addr,
        ));
        let forwarder = UdpRelayFrameForwarder::new(
            RelaySessionState {
                peer: NodeId::from_string("right"),
                relay_node: admission.relay_node.clone(),
                relay_endpoint: relay_addr,
                admitted_local_addr: admission.left_addr,
                admitted_peer_addr: admission.right_addr,
                session_id: admission.session_id.clone(),
                session_token: admission.session_token.clone(),
                expires_at: admission.expires_at,
            },
            wireguard_addr,
        )
        .with_metrics(stats.clone());
        let (relay_shutdown_tx, relay_shutdown_rx) = tokio::sync::watch::channel(false);
        let (forwarder_shutdown_tx, forwarder_shutdown_rx) = tokio::sync::watch::channel(false);
        let relay_task = tokio::spawn(relay.serve(service.table(), relay_shutdown_rx));
        let forwarder_task = tokio::spawn(forwarder.serve(forwarder_socket, forwarder_shutdown_rx));

        wireguard_socket
            .send_to(b"not-wireguard", forwarder_addr)
            .await?;
        let mut buffer = [0_u8; 128];
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            peer_socket.recv_from(&mut buffer)
        )
        .await
        .is_err());

        let unexpected_source_payload = wireguard_transport_payload(0xd1);
        unexpected_socket
            .send_to(&unexpected_source_payload, forwarder_addr)
            .await?;
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            peer_socket.recv_from(&mut buffer)
        )
        .await
        .is_err());

        let outbound_payload = wireguard_transport_payload(0xb1);
        wireguard_socket
            .send_to(&outbound_payload, forwarder_addr)
            .await?;
        let (len, _peer) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_socket.recv_from(&mut buffer),
        )
        .await??;
        assert_eq!(&buffer[..len], outbound_payload.as_slice());

        let datagram = encode_relay_datagram(
            &admission.session_id,
            &admission.session_token,
            b"not-wireguard-inbound",
        )?;
        peer_socket.send_to(&datagram, relay_addr).await?;
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            wireguard_socket.recv_from(&mut buffer)
        )
        .await
        .is_err());

        let inbound_payload = wireguard_transport_payload(0xc1);
        let datagram = encode_relay_datagram(
            &admission.session_id,
            &admission.session_token,
            &inbound_payload,
        )?;
        peer_socket.send_to(&datagram, relay_addr).await?;
        let (len, _peer) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            wireguard_socket.recv_from(&mut buffer),
        )
        .await??;
        assert_eq!(&buffer[..len], inbound_payload.as_slice());
        let stats = stats.snapshot();
        assert_eq!(stats.outbound_packets, 1);
        assert_eq!(stats.outbound_payload_bytes, outbound_payload.len() as u64);
        assert!(stats.outbound_datagram_bytes > stats.outbound_payload_bytes);
        assert_eq!(stats.outbound_dropped_unexpected_source_packets, 1);
        assert_eq!(
            stats.outbound_dropped_unexpected_source_payload_bytes,
            unexpected_source_payload.len() as u64
        );
        assert_eq!(stats.outbound_dropped_non_wireguard_packets, 1);
        assert_eq!(
            stats.outbound_dropped_non_wireguard_payload_bytes,
            b"not-wireguard".len() as u64
        );
        assert_eq!(stats.inbound_packets, 1);
        assert_eq!(stats.inbound_payload_bytes, inbound_payload.len() as u64);
        assert_eq!(stats.inbound_dropped_non_wireguard_packets, 1);
        assert_eq!(
            stats.inbound_dropped_non_wireguard_payload_bytes,
            b"not-wireguard-inbound".len() as u64
        );
        assert!(stats.last_forwarded_at.is_some());

        forwarder_shutdown_tx.send(true)?;
        relay_shutdown_tx.send(true)?;
        forwarder_task.await??;
        relay_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn udp_hole_puncher_sends_to_remote_reflexive_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let local = NodeId::from_string("local");
        let remote = NodeId::from_string("remote");
        let receiver = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let target_addr = receiver.local_addr()?;
        let plan = SignalHolePunchPlanResponse {
            key: PeerPathKey::new(local.clone(), remote.clone()),
            source_reflexive: Some(reflexive_candidate(
                &local,
                SocketAddr::from(([127, 0, 0, 1], 50_000)),
            )),
            target_reflexive: Some(reflexive_candidate(&remote, target_addr)),
            start_after_millis: 0,
            expires_at: Utc::now() + ChronoDuration::seconds(5),
        };

        let sent = UdpHolePuncher::new(SocketAddr::from(([127, 0, 0, 1], 0)))
            .with_attempts(1)
            .with_interval(std::time::Duration::ZERO)
            .execute(&local, &plan)
            .await?;
        let mut buffer = [0_u8; 256];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            receiver.recv_from(&mut buffer),
        )
        .await??;
        let payload = std::str::from_utf8(&buffer[..len])?;

        assert_eq!(sent, 1);
        assert!(payload.contains("ipars-hole-punch-v1"));
        assert!(payload.contains("local=local"));
        Ok(())
    }

    #[tokio::test]
    async fn udp_hole_puncher_rejects_plan_without_remote_candidate() {
        let local = NodeId::from_string("local");
        let remote = NodeId::from_string("remote");
        let plan = SignalHolePunchPlanResponse {
            key: PeerPathKey::new(local.clone(), remote),
            source_reflexive: None,
            target_reflexive: None,
            start_after_millis: 0,
            expires_at: Utc::now() + ChronoDuration::seconds(5),
        };

        let error = UdpHolePuncher::new(SocketAddr::from(([127, 0, 0, 1], 0)))
            .execute(&local, &plan)
            .await;

        assert!(matches!(
            error,
            Err(AgentError::HolePunch(message)) if message == "target reflexive candidate missing"
        ));
    }

    #[tokio::test]
    async fn namespaced_wireguard_runner_wraps_command() -> Result<(), Box<dyn std::error::Error>> {
        let runner = RecordingRunner::default();
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let namespaced_runner = NamespacedLinuxCommandRunner::new(namespace, runner.clone());

        namespaced_runner
            .run(LinuxCommand::new("wg", ["show", "ipars0"]))
            .await?;

        assert_eq!(
            runner.commands().await,
            vec![LinuxCommand::new(
                "ip",
                ["netns", "exec", "node-a", "wg", "show", "ipars0"],
            )]
        );
        Ok(())
    }

    #[tokio::test]
    async fn linux_wireguard_backend_generates_peer_upsert_and_remove_commands(
    ) -> Result<(), AgentError> {
        let runner = RecordingRunner::default();
        let backend = LinuxWireGuardBackend::new("ipars0", runner.clone());
        let peer = NodeId::from_string("node-a");

        backend
            .upsert_peer(WireGuardPeerConfig {
                peer: peer.clone(),
                public_key: "peer-public".to_string(),
                endpoint: Some("203.0.113.10:51820".to_string()),
                allowed_ips: vec!["100.64.0.2/32".to_string()],
                persistent_keepalive_seconds: Some(25),
            })
            .await?;
        backend.remove_peer(&peer).await?;

        assert_eq!(
            runner.commands().await,
            vec![
                LinuxCommand::new(
                    "wg",
                    [
                        "set",
                        "ipars0",
                        "peer",
                        "peer-public",
                        "allowed-ips",
                        "100.64.0.2/32",
                        "endpoint",
                        "203.0.113.10:51820",
                        "persistent-keepalive",
                        "25",
                    ],
                ),
                LinuxCommand::new("wg", ["set", "ipars0", "peer", "peer-public", "remove"],),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn userspace_wireguard_backend_skips_kernel_interface_creation() -> Result<(), AgentError>
    {
        let runner = RecordingRunner::default();
        let backend = UserspaceWireGuardBackend::new("ipars0", runner.clone());
        let peer = NodeId::from_string("node-a");

        backend.ensure_interface().await?;
        backend
            .upsert_peer(WireGuardPeerConfig {
                peer: peer.clone(),
                public_key: "peer-public".to_string(),
                endpoint: Some("203.0.113.10:51820".to_string()),
                allowed_ips: vec!["100.64.0.2/32".to_string()],
                persistent_keepalive_seconds: Some(25),
            })
            .await?;
        backend.remove_peer(&peer).await?;

        assert_eq!(
            runner.commands().await,
            vec![
                LinuxCommand::new("wg", ["show", "ipars0"]),
                LinuxCommand::new(
                    "wg",
                    [
                        "set",
                        "ipars0",
                        "peer",
                        "peer-public",
                        "allowed-ips",
                        "100.64.0.2/32",
                        "endpoint",
                        "203.0.113.10:51820",
                        "persistent-keepalive",
                        "25",
                    ],
                ),
                LinuxCommand::new("wg", ["set", "ipars0", "peer", "peer-public", "remove"],),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn linux_wireguard_backend_keeps_peer_when_remove_command_fails() -> Result<(), AgentError>
    {
        let runner = RecordingRunner::with_failed_remove();
        let backend = LinuxWireGuardBackend::new("ipars0", runner);
        let peer = NodeId::from_string("node-a");

        backend
            .upsert_peer(WireGuardPeerConfig {
                peer: peer.clone(),
                public_key: "peer-public".to_string(),
                endpoint: None,
                allowed_ips: vec!["100.64.0.2/32".to_string()],
                persistent_keepalive_seconds: None,
            })
            .await?;
        let error = backend.remove_peer(&peer).await;

        assert!(matches!(
            error,
            Err(AgentError::WireGuard(message)) if message == "remove failed"
        ));
        assert_eq!(
            backend.peer_public_keys.read().await.get(&peer).cloned(),
            Some("peer-public".to_string())
        );
        Ok(())
    }

    #[tokio::test]
    async fn linux_wireguard_backend_creates_missing_interface() -> Result<(), AgentError> {
        let runner = RecordingRunner::with_missing_interface();
        let backend = LinuxWireGuardBackend::new("ipars0", runner.clone());

        backend.ensure_interface().await?;

        assert_eq!(
            runner.commands().await,
            vec![
                LinuxCommand::new("ip", ["link", "show", "dev", "ipars0"]),
                LinuxCommand::new("ip", ["link", "add", "dev", "ipars0", "type", "wireguard"],),
                LinuxCommand::new("ip", ["link", "set", "up", "dev", "ipars0"]),
            ]
        );
        Ok(())
    }

    #[test]
    fn kernel_wireguard_backend_tracks_namespace() -> Result<(), Box<dyn std::error::Error>> {
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let backend = KernelWireGuardBackend::new_in_namespace("ipars0", namespace.clone());

        assert_eq!(backend.namespace(), Some(&namespace));
        assert_eq!(KernelWireGuardBackend::new("ipars0").namespace(), None);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_wireguard_backend_builds_netlink_peer_config() -> Result<(), AgentError> {
        let public_key =
            parse_wireguard_public_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")?;
        let config = WireGuardPeerConfig {
            peer: NodeId::from_string("node-a"),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            endpoint: Some("203.0.113.10:51820".to_string()),
            allowed_ips: vec!["100.64.0.2/32".to_string(), "fd00::2/128".to_string()],
            persistent_keepalive_seconds: Some(25),
        };

        let peer = netlink_peer_config(&config, public_key)?;

        assert_eq!(public_key, [0; 32]);
        assert!(peer.0.contains(&WireguardPeerAttribute::PublicKey([0; 32])));
        assert!(peer.0.contains(&WireguardPeerAttribute::Flags(
            WireguardPeerFlags::ReplaceAllowedIps
        )));
        assert!(peer
            .0
            .contains(&WireguardPeerAttribute::Endpoint(SocketAddr::from((
                [203, 0, 113, 10],
                51_820
            )))));
        assert!(peer
            .0
            .contains(&WireguardPeerAttribute::PersistentKeepalive(25)));
        let allowed_ips = peer.0.iter().find_map(|attribute| match attribute {
            WireguardPeerAttribute::AllowedIps(allowed_ips) => Some(allowed_ips),
            _ => None,
        });
        assert_eq!(
            allowed_ips,
            Some(&vec![
                WireguardAllowedIp(vec![
                    WireguardAllowedIpAttr::Family(WireguardAddressFamily::Ipv4),
                    WireguardAllowedIpAttr::IpAddr("100.64.0.2".parse().map_err(|error| {
                        AgentError::WireGuard(format!("test IP parse failed: {error}"))
                    })?),
                    WireguardAllowedIpAttr::Cidr(32),
                ]),
                WireguardAllowedIp(vec![
                    WireguardAllowedIpAttr::Family(WireguardAddressFamily::Ipv6),
                    WireguardAllowedIpAttr::IpAddr("fd00::2".parse().map_err(|error| {
                        AgentError::WireGuard(format!("test IP parse failed: {error}"))
                    })?),
                    WireguardAllowedIpAttr::Cidr(128),
                ]),
            ])
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_wireguard_backend_rejects_unresolved_endpoint() {
        let config = WireGuardPeerConfig {
            peer: NodeId::from_string("node-a"),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            endpoint: Some("peer.example.com:51820".to_string()),
            allowed_ips: vec!["100.64.0.2/32".to_string()],
            persistent_keepalive_seconds: None,
        };

        let error = netlink_peer_config(&config, [0; 32]);

        assert!(matches!(
            error,
            Err(AgentError::WireGuard(message))
                if message.contains("requires socket-address endpoints")
        ));
    }

    #[tokio::test]
    async fn peer_map_applier_configures_wireguard_and_routes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wireguard = MemoryWireGuardBackend::default();
        let route_manager = RecordingRouteManager::default();
        let applier = PeerMapApplier::new("ipars0", wireguard, route_manager);
        let peer_id = NodeId::from_string("peer-a");
        let advertised_route = Route {
            id: "advertised-a".to_string(),
            cidr: "10.10.0.0/16".parse()?,
            advertised_by: peer_id.clone(),
            via: Some(peer_id.clone()),
            metric: 50,
            tags: Default::default(),
        };
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
            "wg-peer-public",
            vec![
                EndpointCandidate {
                    node_id: peer_id.clone(),
                    kind: EndpointCandidateKind::StunReflexive,
                    addr: SocketAddr::from(([198, 51, 100, 20], 51820)),
                    observed_at: Utc::now(),
                    priority: 100,
                    cost: 1,
                    source: CandidateSource::StunProbe,
                },
                EndpointCandidate {
                    node_id: peer_id.clone(),
                    kind: EndpointCandidateKind::PublicUdp,
                    addr: SocketAddr::from(([203, 0, 113, 10], 51820)),
                    observed_at: Utc::now(),
                    priority: 10,
                    cost: 50,
                    source: CandidateSource::ControlPlane,
                },
            ],
            vec![advertised_route],
        );

        let summary = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer],
                generated_at: Utc::now(),
            })
            .await?;

        assert_eq!(
            summary,
            PeerMapApplySummary {
                peers_applied: 1,
                peers_removed: 0,
                routes_applied: 2,
                routes_removed: 0,
            }
        );

        let wireguard_peers = applier.wireguard.peers.read().await;
        let config = wireguard_peers
            .get(&peer_id)
            .ok_or_else(|| AgentError::MissingPeer(peer_id.clone()))?;
        assert_eq!(config.public_key, "wg-peer-public");
        assert_eq!(config.allowed_ips, vec!["100.64.0.2/32"]);
        assert_eq!(config.endpoint.as_deref(), Some("203.0.113.10:51820"));
        assert_eq!(config.persistent_keepalive_seconds, Some(25));
        drop(wireguard_peers);

        let applied = applier.route_manager.applied.read().await;
        let plan = applied
            .first()
            .ok_or_else(|| AgentError::RoutePlanning("missing route plan".to_string()))?;
        assert_eq!(plan.interface, "ipars0");
        assert!(plan.policy_rules.is_empty());
        assert_eq!(plan.routes.len(), 2);
        assert_eq!(plan.routes[0].cidr, "100.64.0.2/32".parse()?);
        assert_eq!(plan.routes[0].metric, 10);
        assert_eq!(plan.routes[1].cidr, "10.10.0.0/16".parse()?);
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_ignores_routes_advertised_by_other_nodes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        );
        let peer_id = NodeId::from_string("peer-owner");
        let foreign_id = NodeId::from_string("foreign-owner");
        let foreign_route = Route {
            id: "foreign-route".to_string(),
            cidr: "10.99.0.0/16".parse()?,
            advertised_by: foreign_id,
            via: Some(peer_id.clone()),
            metric: 50,
            tags: Default::default(),
        };
        let peer = peer_record(
            peer_id,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 22)),
            "wg-peer-owner",
            Vec::new(),
            vec![foreign_route],
        );

        let summary = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer],
                generated_at: Utc::now(),
            })
            .await?;

        assert_eq!(
            summary,
            PeerMapApplySummary {
                peers_applied: 1,
                peers_removed: 0,
                routes_applied: 1,
                routes_removed: 0,
            }
        );
        let applied = applier.route_manager.applied.read().await;
        let plan = applied
            .first()
            .ok_or_else(|| AgentError::RoutePlanning("missing route plan".to_string()))?;
        assert_eq!(plan.routes.len(), 1);
        assert_eq!(plan.routes[0].cidr, "100.64.0.22/32".parse()?);
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_removes_routes_for_stale_peer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        );
        let peer_id = NodeId::from_string("peer-stale");
        let advertised_route = Route {
            id: "advertised-stale".to_string(),
            cidr: "10.11.0.0/16".parse()?,
            advertised_by: peer_id.clone(),
            via: Some(peer_id.clone()),
            metric: 50,
            tags: Default::default(),
        };
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 3)),
            "wg-peer-stale",
            Vec::new(),
            vec![advertised_route.clone()],
        );

        applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer],
                generated_at: Utc::now(),
            })
            .await?;
        let summary = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: Vec::new(),
                generated_at: Utc::now(),
            })
            .await?;

        assert_eq!(
            summary,
            PeerMapApplySummary {
                peers_applied: 0,
                peers_removed: 1,
                routes_applied: 0,
                routes_removed: 2,
            }
        );
        assert!(!applier.wireguard.peers.read().await.contains_key(&peer_id));
        let removed = applier.route_manager.removed.read().await;
        let plan = removed
            .first()
            .ok_or_else(|| AgentError::RoutePlanning("missing remove route plan".to_string()))?;
        assert_eq!(plan.interface, "ipars0");
        assert_eq!(plan.routes.len(), 2);
        assert_eq!(plan.routes[0].cidr, "100.64.0.3/32".parse()?);
        assert_eq!(plan.routes[1], advertised_route);
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_removes_dropped_advertised_routes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        );
        let peer_id = NodeId::from_string("peer-routes");
        let advertised_route = Route {
            id: "advertised-routes".to_string(),
            cidr: "10.12.0.0/16".parse()?,
            advertised_by: peer_id.clone(),
            via: Some(peer_id.clone()),
            metric: 50,
            tags: Default::default(),
        };
        let peer_with_route = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 4)),
            "wg-peer-routes",
            Vec::new(),
            vec![advertised_route.clone()],
        );
        let peer_without_route = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 4)),
            "wg-peer-routes",
            Vec::new(),
            Vec::new(),
        );

        applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer_with_route],
                generated_at: Utc::now(),
            })
            .await?;
        let summary = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer_without_route],
                generated_at: Utc::now(),
            })
            .await?;

        assert_eq!(
            summary,
            PeerMapApplySummary {
                peers_applied: 1,
                peers_removed: 0,
                routes_applied: 1,
                routes_removed: 1,
            }
        );
        let removed = applier.route_manager.removed.read().await;
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].routes, vec![advertised_route]);
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_uses_relay_forwarder_endpoint_for_active_relay_path(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let local_id = runtime.state().node_id.clone();
        let peer_id = NodeId::from_string("peer-relay");
        let relay_id = NodeId::from_string("relay-a");
        let forwarder_endpoint = SocketAddr::from(([127, 0, 0, 1], 52_000));
        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(local_id, peer_id.clone()),
                selected_state: PathState::Relay,
                selected_candidate: None,
                relay_node: Some(relay_id.clone()),
                score: PathScore {
                    value: 70.0,
                    reasons: Vec::new(),
                },
                updated_at: Utc::now(),
                pinned: false,
            })
            .await;
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: peer_id.clone(),
                relay_node: relay_id,
                relay_endpoint: SocketAddr::from(([203, 0, 113, 30], 51820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40000)),
                session_id: "session-a".to_string(),
                session_token: "secret".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
            })
            .await;
        runtime
            .upsert_relay_forwarder_endpoint(peer_id.clone(), forwarder_endpoint)
            .await;

        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        )
        .with_endpoint_resolver(RuntimePeerEndpointResolver::new(runtime));
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)),
            "wg-peer-public",
            vec![EndpointCandidate {
                node_id: peer_id.clone(),
                kind: EndpointCandidateKind::PublicUdp,
                addr: SocketAddr::from(([203, 0, 113, 10], 51820)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::ControlPlane,
            }],
            Vec::new(),
        );

        applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer],
                generated_at: Utc::now(),
            })
            .await?;

        let wireguard_peers = applier.wireguard.peers.read().await;
        let config = wireguard_peers
            .get(&peer_id)
            .ok_or_else(|| AgentError::MissingPeer(peer_id.clone()))?;
        assert_eq!(config.endpoint.as_deref(), Some("127.0.0.1:52000"));
        assert_eq!(config.persistent_keepalive_seconds, Some(25));
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_prunes_idle_unpinned_peers() -> Result<(), Box<dyn std::error::Error>>
    {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy {
                idle_timeout_seconds: 10,
                ..ClusterPolicy::default()
            },
        ));
        let active_peer_id = NodeId::from_string("peer-active");
        let inactive_peer_id = NodeId::from_string("peer-inactive");
        let pinned_peer_id = NodeId::from_string("peer-pinned");
        runtime
            .record_peer_activity(active_peer_id.clone(), Utc::now(), false)
            .await;
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        )
        .with_lazy_connect_runtime(runtime.clone());
        let active_peer = peer_record(
            active_peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10)),
            "wg-active",
            vec![EndpointCandidate {
                node_id: active_peer_id.clone(),
                kind: EndpointCandidateKind::PublicUdp,
                addr: SocketAddr::from(([203, 0, 113, 10], 51820)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::ControlPlane,
            }],
            Vec::new(),
        );
        let inactive_peer = peer_record(
            inactive_peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 11)),
            "wg-inactive",
            Vec::new(),
            Vec::new(),
        );
        let mut pinned_peer = peer_record(
            pinned_peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 12)),
            "wg-pinned",
            Vec::new(),
            Vec::new(),
        );
        pinned_peer.role = Role::control_plane();
        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: vec![active_peer, inactive_peer, pinned_peer],
            generated_at: Utc::now(),
        };

        let first = applier.apply_peer_map(peer_map.clone()).await?;

        assert_eq!(
            first,
            PeerMapApplySummary {
                peers_applied: 2,
                peers_removed: 0,
                routes_applied: 2,
                routes_removed: 0,
            }
        );
        let wireguard_peers = applier.wireguard.peers.read().await;
        assert!(wireguard_peers.contains_key(&active_peer_id));
        assert!(!wireguard_peers.contains_key(&inactive_peer_id));
        assert!(wireguard_peers.contains_key(&pinned_peer_id));
        drop(wireguard_peers);

        runtime
            .record_peer_activity(
                active_peer_id.clone(),
                Utc::now() - ChronoDuration::seconds(30),
                false,
            )
            .await;
        let second = applier.apply_peer_map(peer_map).await?;

        assert_eq!(
            second,
            PeerMapApplySummary {
                peers_applied: 1,
                peers_removed: 1,
                routes_applied: 1,
                routes_removed: 1,
            }
        );
        let wireguard_peers = applier.wireguard.peers.read().await;
        assert!(!wireguard_peers.contains_key(&active_peer_id));
        assert!(!wireguard_peers.contains_key(&inactive_peer_id));
        assert!(wireguard_peers.contains_key(&pinned_peer_id));
        Ok(())
    }

    #[tokio::test]
    async fn packet_flow_activity_resolves_peer_vpn_ip_and_routes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer_a_id = NodeId::from_string("peer-a");
        let peer_b_id = NodeId::from_string("peer-b");
        let peer_c_id = NodeId::from_string("peer-c");
        let peer_a = peer_record(
            peer_a_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10)),
            "wg-peer-a",
            Vec::new(),
            Vec::new(),
        );
        let peer_b = peer_record(
            peer_b_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 11)),
            "wg-peer-b",
            Vec::new(),
            vec![Route {
                id: "peer-b-specific".to_string(),
                cidr: "10.42.7.0/24".parse()?,
                advertised_by: peer_b_id.clone(),
                via: None,
                metric: 10,
                tags: BTreeSet::new(),
            }],
        );
        let peer_c = peer_record(
            peer_c_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 12)),
            "wg-peer-c",
            Vec::new(),
            vec![Route {
                id: "peer-c-wide".to_string(),
                cidr: "10.42.0.0/16".parse()?,
                advertised_by: peer_c_id,
                via: None,
                metric: 100,
                tags: BTreeSet::new(),
            }],
        );
        runtime
            .observe_peer_map_for_lazy_connect(&[peer_a.clone(), peer_b.clone(), peer_c])
            .await;

        let vpn_ip_match = runtime
            .record_packet_flow_activity(peer_a.vpn_ip.0, Utc::now(), false)
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_a_id.clone()))?;
        assert_eq!(vpn_ip_match.peer, peer_a_id);
        assert_eq!(vpn_ip_match.kind, AgentPacketFlowMatchKind::PeerVpnIp);
        assert_eq!(vpn_ip_match.route, None);
        assert!(!vpn_ip_match.pinned);
        assert!(runtime.should_connect_peer(&peer_a).await);

        let route_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 25)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(443),
                    conntrack_status: vec![AgentPacketFlowConntrackStatus::Assured],
                    tcp_state: Some(AgentPacketFlowTcpState::Established),
                    ..Default::default()
                },
                Utc::now(),
                true,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(route_match.peer, peer_b_id);
        assert_eq!(route_match.kind, AgentPacketFlowMatchKind::AdvertisedRoute);
        assert_eq!(route_match.route, Some("10.42.7.0/24".parse()?));
        assert!(route_match.pinned);
        assert!(runtime.should_connect_peer(&peer_b).await);

        assert!(
            runtime
                .record_packet_flow_activity(
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    Utc::now(),
                    false,
                )
                .await
                .is_none()
        );
        assert!(runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(6443),
                    conntrack_status: vec![AgentPacketFlowConntrackStatus::Unreplied],
                    tcp_state: Some(AgentPacketFlowTcpState::SynSent),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .is_none());
        let postgres_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 26)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(5432),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(postgres_match.peer, peer_b_id);
        let zookeeper_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 38)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(2181),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(zookeeper_match.peer, peer_b_id);
        let consul_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 39)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(8500),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(consul_match.peer, peer_b_id);
        let vault_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 40)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(8200),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(vault_match.peer, peer_b_id);
        let nomad_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 41)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(4646),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(nomad_match.peer, peer_b_id);
        let mssql_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 36)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(1433),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(mssql_match.peer, peer_b_id);
        let oracle_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 37)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(1521),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(oracle_match.peer, peer_b_id);
        let clickhouse_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 46)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(9000),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(clickhouse_match.peer, peer_b_id);
        let influxdb_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 47)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(8086),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(influxdb_match.peer, peer_b_id);
        let prometheus_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 27)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(9090),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(prometheus_match.peer, peer_b_id);
        let syslog_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 49)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(514),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(syslog_match.peer, peer_b_id);
        let jaeger_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 42)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(14268),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(jaeger_match.peer, peer_b_id);
        let loki_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 43)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(3100),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(loki_match.peer, peer_b_id);
        let tempo_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 44)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(3200),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(tempo_match.peer, peer_b_id);
        let zipkin_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 45)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(9411),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(zipkin_match.peer, peer_b_id);
        let kafka_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 28)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(9092),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(kafka_match.peer, peer_b_id);
        let memcached_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 30)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(11211),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(memcached_match.peer, peer_b_id);
        let grpc_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 31)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(50051),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(grpc_match.peer, peer_b_id);
        let ldap_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 32)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(389),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(ldap_match.peer, peer_b_id);
        let smb_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 33)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(445),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(smb_match.peer, peer_b_id);
        let nfs_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 48)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(2049),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(nfs_match.peer, peer_b_id);
        let rdp_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 34)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(3389),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(rdp_match.peer, peer_b_id);
        let hinted_postgres_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 29)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(443),
                    application: Some(AgentPacketFlowApplication::Postgres),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(hinted_postgres_match.peer, peer_b_id);
        let elasticsearch_transport_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 35)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    payload_prefix: vec![
                        b'E', b'S', 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 1, 0x08, 0, 122, 18, 99, 0,
                        0, 0, 0,
                    ],
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(elasticsearch_transport_match.peer, peer_b_id);
        runtime.record_packet_flow_filtered(AgentPacketFlowDropReason::Multicast);
        runtime.record_packet_flow_filtered(AgentPacketFlowDropReason::Multicast);
        runtime.record_packet_flow_filtered(AgentPacketFlowDropReason::Broadcast);
        runtime.record_packet_flow_duplicate_suppression(
            AgentPacketFlowDuplicateSource::ProcNetConntrack,
            2,
        );
        runtime.record_packet_flow_duplicate_suppression(
            AgentPacketFlowDuplicateSource::EbpfRingbuf,
            3,
        );
        runtime
            .record_packet_flow_duplicate_suppression(AgentPacketFlowDuplicateSource::EbpfJsonl, 0);
        let metrics = runtime.metrics().await;
        assert_eq!(metrics.lazy_connect.observed_peer_vpn_ip_count, 3);
        assert_eq!(metrics.lazy_connect.observed_route_peer_count, 2);
        assert_eq!(metrics.lazy_connect.observed_route_count, 2);
        assert_eq!(metrics.lazy_connect.active_peer_count, 2);
        assert_eq!(metrics.lazy_connect.pinned_peer_count, 2);
        assert_eq!(metrics.packet_flow_observation_count, 28);
        assert_eq!(metrics.packet_flow_match_count, 26);
        assert_eq!(metrics.packet_flow_unmatched_count, 2);
        let classification_count = |classification| {
            metrics
                .packet_flow_classification_counts
                .iter()
                .find(|entry| entry.classification == classification)
                .map(|entry| entry.count)
                .unwrap_or(0)
        };
        assert_eq!(
            classification_count(AgentPacketFlowClassification::Unknown),
            26
        );
        assert_eq!(
            classification_count(AgentPacketFlowClassification::Established),
            1
        );
        assert_eq!(
            classification_count(AgentPacketFlowClassification::Unreplied),
            1
        );
        let application_count = |application| {
            metrics
                .packet_flow_application_counts
                .iter()
                .find(|entry| entry.application == application)
                .map(|entry| entry.count)
                .unwrap_or(0)
        };
        assert_eq!(application_count(AgentPacketFlowApplication::Unknown), 2);
        assert_eq!(application_count(AgentPacketFlowApplication::Https), 1);
        assert_eq!(
            application_count(AgentPacketFlowApplication::KubernetesApi),
            1
        );
        assert_eq!(application_count(AgentPacketFlowApplication::Postgres), 2);
        assert_eq!(application_count(AgentPacketFlowApplication::ZooKeeper), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Consul), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Vault), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Nomad), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::MsSql), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Oracle), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::ClickHouse), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::InfluxDb), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Prometheus), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Syslog), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Jaeger), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Loki), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Tempo), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Zipkin), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Kafka), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Memcached), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Grpc), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Ldap), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Smb), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Nfs), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Rdp), 1);
        assert_eq!(
            application_count(AgentPacketFlowApplication::Elasticsearch),
            1
        );
        assert_eq!(metrics.packet_flow_filtered_count, 5);
        assert_eq!(metrics.packet_flow_duplicate_suppression_count, 5);
        let duplicate_suppression_count = |source| {
            metrics
                .packet_flow_duplicate_suppression_counts
                .iter()
                .find(|entry| entry.source == source)
                .map(|entry| entry.count)
                .unwrap_or(0)
        };
        assert_eq!(
            duplicate_suppression_count(AgentPacketFlowDuplicateSource::ProcNetConntrack),
            2
        );
        assert_eq!(
            duplicate_suppression_count(AgentPacketFlowDuplicateSource::EbpfRingbuf),
            3
        );
        assert_eq!(
            duplicate_suppression_count(AgentPacketFlowDuplicateSource::EbpfJsonl),
            0
        );
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| entry.reason == AgentPacketFlowDropReason::Multicast)
                .map(|entry| entry.count),
            Some(2)
        );
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| entry.reason == AgentPacketFlowDropReason::Broadcast)
                .map(|entry| entry.count),
            Some(1)
        );
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| entry.reason == AgentPacketFlowDropReason::NoOverlayMatch)
                .map(|entry| entry.count),
            Some(2)
        );
        assert_eq!(metrics.path_probe_record_count, 0);
        assert_eq!(metrics.peer_activity_record_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn packet_flow_ignores_routes_advertised_by_other_nodes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer_id = NodeId::from_string("peer-route");
        let foreign_id = NodeId::from_string("foreign-route-owner");
        let peer = peer_record(
            peer_id,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 40)),
            "wg-peer-route",
            Vec::new(),
            vec![Route {
                id: "foreign-route".to_string(),
                cidr: "10.88.0.0/16".parse()?,
                advertised_by: foreign_id,
                via: None,
                metric: 10,
                tags: BTreeSet::new(),
            }],
        );
        runtime
            .observe_peer_map_for_lazy_connect(std::slice::from_ref(&peer))
            .await;

        let matched = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 88, 1, 10)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(443),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await;

        assert!(matched.is_none());
        assert!(!runtime.should_connect_peer(&peer).await);
        let metrics = runtime.metrics().await;
        assert_eq!(metrics.packet_flow_match_count, 0);
        assert_eq!(metrics.packet_flow_unmatched_count, 1);
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| entry.reason == AgentPacketFlowDropReason::NoOverlayMatch)
                .map(|entry| entry.count),
            Some(1)
        );
        Ok(())
    }

    #[tokio::test]
    async fn packet_flow_observation_rejects_inconsistent_transport_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer_id = NodeId::from_string("peer-a");
        let peer = peer_record(
            peer_id,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10)),
            "wg-peer-a",
            Vec::new(),
            Vec::new(),
        );
        runtime
            .observe_peer_map_for_lazy_connect(std::slice::from_ref(&peer))
            .await;

        for observation in [
            AgentPacketFlowObservation {
                protocol: Some(TransportProtocol::Icmp),
                destination_port: Some(8),
                ..Default::default()
            },
            AgentPacketFlowObservation {
                protocol: Some(TransportProtocol::Icmp),
                application: Some(AgentPacketFlowApplication::Postgres),
                ..Default::default()
            },
        ] {
            let matched = runtime
                .record_packet_flow_observation(peer.vpn_ip.0, observation, Utc::now(), true)
                .await;

            assert!(matched.is_none());
            assert!(!runtime.should_connect_peer(&peer).await);
        }
        let metrics = runtime.metrics().await;
        assert_eq!(metrics.packet_flow_observation_count, 0);
        assert_eq!(metrics.packet_flow_match_count, 0);
        assert_eq!(metrics.packet_flow_unmatched_count, 0);
        assert_eq!(metrics.packet_flow_filtered_count, 2);
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| {
                    entry.reason == AgentPacketFlowDropReason::InconsistentTransportMetadata
                })
                .map(|entry| entry.count),
            Some(2)
        );
        assert_eq!(
            metrics
                .packet_flow_classification_counts
                .iter()
                .find(|entry| entry.classification == AgentPacketFlowClassification::Unknown)
                .map(|entry| entry.count),
            Some(0)
        );
        assert_eq!(
            metrics
                .packet_flow_application_counts
                .iter()
                .find(|entry| entry.application == AgentPacketFlowApplication::Unknown)
                .map(|entry| entry.count),
            Some(0)
        );
        Ok(())
    }

    #[tokio::test]
    async fn packet_flow_observation_rejects_any_protocol() -> Result<(), Box<dyn std::error::Error>>
    {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer_id = NodeId::from_string("peer-a");
        let peer = peer_record(
            peer_id,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10)),
            "wg-peer-a",
            Vec::new(),
            Vec::new(),
        );
        runtime
            .observe_peer_map_for_lazy_connect(std::slice::from_ref(&peer))
            .await;

        let matched = runtime
            .record_packet_flow_observation(
                peer.vpn_ip.0,
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Any),
                    ..Default::default()
                },
                Utc::now(),
                true,
            )
            .await;

        assert!(matched.is_none());
        assert!(!runtime.should_connect_peer(&peer).await);
        let metrics = runtime.metrics().await;
        assert_eq!(metrics.packet_flow_observation_count, 0);
        assert_eq!(metrics.packet_flow_match_count, 0);
        assert_eq!(metrics.packet_flow_filtered_count, 1);
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| {
                    entry.reason == AgentPacketFlowDropReason::InconsistentTransportMetadata
                })
                .map(|entry| entry.count),
            Some(1)
        );
        Ok(())
    }

    #[tokio::test]
    async fn packet_flow_observation_rejects_unbounded_or_invalid_direct_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer_id = NodeId::from_string("peer-a");
        let peer = peer_record(
            peer_id,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10)),
            "wg-peer-a",
            Vec::new(),
            Vec::new(),
        );
        runtime
            .observe_peer_map_for_lazy_connect(std::slice::from_ref(&peer))
            .await;

        for observation in [
            AgentPacketFlowObservation {
                protocol: Some(TransportProtocol::Tcp),
                destination_port: Some(443),
                payload_prefix: vec![0; PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES + 1],
                ..Default::default()
            },
            AgentPacketFlowObservation {
                protocol: Some(TransportProtocol::Tcp),
                destination_port: Some(443),
                detector: Some("sidecar\nspoof".to_string()),
                ..Default::default()
            },
            AgentPacketFlowObservation {
                source: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                protocol: Some(TransportProtocol::Tcp),
                destination_port: Some(443),
                ..Default::default()
            },
        ] {
            let matched = runtime
                .record_packet_flow_observation(peer.vpn_ip.0, observation, Utc::now(), true)
                .await;

            assert!(matched.is_none());
            assert!(!runtime.should_connect_peer(&peer).await);
        }
        let metrics = runtime.metrics().await;
        assert_eq!(metrics.packet_flow_observation_count, 0);
        assert_eq!(metrics.packet_flow_match_count, 0);
        assert_eq!(metrics.packet_flow_unmatched_count, 0);
        assert_eq!(metrics.packet_flow_filtered_count, 3);
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| {
                    entry.reason == AgentPacketFlowDropReason::InconsistentTransportMetadata
                })
                .map(|entry| entry.count),
            Some(3)
        );
        assert_eq!(
            metrics
                .packet_flow_application_counts
                .iter()
                .find(|entry| entry.application == AgentPacketFlowApplication::Https)
                .map(|entry| entry.count),
            Some(0)
        );
        Ok(())
    }

    #[tokio::test]
    async fn packet_flow_observation_filters_unusable_destinations(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer_id = NodeId::from_string("peer-a");
        let peer = peer_record(
            peer_id,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10)),
            "wg-peer-a",
            Vec::new(),
            Vec::new(),
        );
        runtime
            .observe_peer_map_for_lazy_connect(std::slice::from_ref(&peer))
            .await;

        let matched = runtime
            .record_packet_flow_activity(IpAddr::V4(Ipv4Addr::LOCALHOST), Utc::now(), true)
            .await;

        assert!(matched.is_none());
        assert!(!runtime.should_connect_peer(&peer).await);
        let metrics = runtime.metrics().await;
        assert_eq!(metrics.packet_flow_observation_count, 0);
        assert_eq!(metrics.packet_flow_match_count, 0);
        assert_eq!(metrics.packet_flow_unmatched_count, 0);
        assert_eq!(metrics.packet_flow_filtered_count, 1);
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| entry.reason == AgentPacketFlowDropReason::Loopback)
                .map(|entry| entry.count),
            Some(1)
        );
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| entry.reason == AgentPacketFlowDropReason::NoOverlayMatch)
                .map(|entry| entry.count),
            Some(0)
        );
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_sync_fetches_and_applies_once() -> Result<(), AgentError> {
        let node_id = NodeId::from_string("local");
        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: Vec::new(),
            generated_at: Utc::now(),
        };
        let source = StaticPeerMapSource::new(node_id.clone(), peer_map.clone());
        let sink = RecordingPeerMapSink::new(PeerMapApplySummary {
            peers_applied: 3,
            peers_removed: 0,
            routes_applied: 5,
            routes_removed: 0,
        });
        let sync = PeerMapSync::new(node_id.clone(), source.clone(), sink.clone());

        let summary = sync.sync_once().await?;

        assert_eq!(
            summary,
            PeerMapApplySummary {
                peers_applied: 3,
                peers_removed: 0,
                routes_applied: 5,
                routes_removed: 0,
            }
        );
        assert_eq!(source.requests.read().await.as_slice(), &[node_id]);
        assert_eq!(sink.applied.read().await.as_slice(), &[peer_map]);
        Ok(())
    }

    #[test]
    fn file_state_store_creates_and_reloads_node_identity() -> Result<(), AgentError> {
        let dir = temp_state_dir("state");
        let path = dir.join("state.json");
        let store = FileAgentStateStore::new(&path);
        let created = store.load_or_create(Utc::now())?;
        let loaded = store.load_or_create(Utc::now())?;

        assert_eq!(created.node_id, loaded.node_id);
        assert_eq!(
            created.identity_public_key_b64,
            loaded.identity_key_pair()?.public_key_b64()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let dir_mode = std::fs::metadata(&dir)?.permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
            let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn file_state_store_rejects_insecure_state_paths() -> Result<(), AgentError> {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let state = AgentNodeState::generate(Utc::now());
        let dir = temp_state_dir("state-insecure-paths");
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

        let broad = dir.join("state-broad.json");
        std::fs::write(&broad, serde_json::to_vec_pretty(&state)?)?;
        std::fs::set_permissions(&broad, std::fs::Permissions::from_mode(0o644))?;

        let error = match FileAgentStateStore::new(&broad).load() {
            Ok(_) => panic!("broadly readable state file should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("must not be readable"));

        let target = dir.join("state-target.json");
        let link = dir.join("state-link.json");
        FileAgentStateStore::new(&target).save(&state)?;
        symlink(&target, &link)?;

        let load_error = match FileAgentStateStore::new(&link).load() {
            Ok(_) => panic!("symlinked state file should be rejected"),
            Err(error) => error,
        };
        assert!(load_error.to_string().contains("symbolic link"));
        let save_error = match FileAgentStateStore::new(&link).save(&state) {
            Ok(_) => panic!("symlinked state file should not be overwritten"),
            Err(error) => error,
        };
        assert!(save_error.to_string().contains("symbolic link"));

        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn file_state_store_rejects_insecure_state_directories() -> Result<(), AgentError> {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let state = AgentNodeState::generate(Utc::now());
        let broad_dir = temp_state_dir("state-broad-dir");
        std::fs::create_dir_all(&broad_dir)?;
        std::fs::set_permissions(&broad_dir, std::fs::Permissions::from_mode(0o777))?;
        let broad_path = broad_dir.join("state.json");
        std::fs::write(&broad_path, serde_json::to_vec_pretty(&state)?)?;
        std::fs::set_permissions(&broad_path, std::fs::Permissions::from_mode(0o600))?;

        let load_error = match FileAgentStateStore::new(&broad_path).load() {
            Ok(_) => panic!("state file in broadly accessible directory should be rejected"),
            Err(error) => error,
        };
        assert!(load_error.to_string().contains("must not be readable"));
        let save_error = match FileAgentStateStore::new(&broad_path).save(&state) {
            Ok(_) => panic!("broadly accessible state directory should be rejected"),
            Err(error) => error,
        };
        assert!(save_error.to_string().contains("must not be readable"));
        std::fs::set_permissions(&broad_dir, std::fs::Permissions::from_mode(0o700))?;
        let _ = std::fs::remove_dir_all(&broad_dir);

        let target_dir = temp_state_dir("state-dir-target");
        std::fs::create_dir_all(&target_dir)?;
        std::fs::set_permissions(&target_dir, std::fs::Permissions::from_mode(0o700))?;
        let link_dir = temp_state_dir("state-dir-link");
        symlink(&target_dir, &link_dir)?;
        let link_path = link_dir.join("state.json");

        let load_error = match FileAgentStateStore::new(&link_path).load() {
            Ok(_) => panic!("state file in symlinked state directory should be rejected"),
            Err(error) => error,
        };
        assert!(load_error.to_string().contains("symbolic link"));
        let save_error = match FileAgentStateStore::new(&link_path).save(&state) {
            Ok(_) => panic!("symlinked state directory should be rejected"),
            Err(error) => error,
        };
        assert!(save_error.to_string().contains("symbolic link"));

        let _ = std::fs::remove_file(link_dir);
        let _ = std::fs::remove_dir_all(target_dir);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn file_state_store_replaces_state_atomically() -> Result<(), AgentError> {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_state_dir("state-atomic");
        let path = dir.join("state.json");
        let store = FileAgentStateStore::new(&path);
        let first = AgentNodeState::generate(Utc::now());
        let second = AgentNodeState::generate(Utc::now());

        store.save(&first)?;
        store.save(&second)?;

        let loaded = store.load()?;
        assert_eq!(loaded.node_id, second.node_id);
        assert_ne!(loaded.node_id, first.node_id);
        let dir_mode = std::fs::metadata(&dir)?.permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let temp_file_left = std::fs::read_dir(&dir)?.any(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
                .is_some_and(|name| name.starts_with(".state.json.tmp-"))
        });
        assert!(!temp_file_left);

        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_collects_stun_candidate() -> Result<(), Box<dyn std::error::Error>> {
        let server = BindingStunServer::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move { server.serve_once().await });
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );

        let candidate = runtime
            .probe_stun(SocketAddr::from(([127, 0, 0, 1], 0)), server_addr)
            .await?;
        server_task.await??;

        assert_eq!(candidate.addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(runtime.status().await.candidate_count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_can_replace_endpoint_candidates() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let node_id = runtime.state().node_id;
        let candidate = EndpointCandidate {
            node_id,
            kind: EndpointCandidateKind::StunReflexive,
            addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::StunProbe,
        };

        runtime.replace_candidates(vec![candidate.clone()]).await;

        let status = runtime.status().await;
        assert_eq!(status.candidate_count, 1);
        assert_eq!(status.candidates, vec![candidate]);
    }

    #[tokio::test]
    async fn runtime_classifies_nat_from_multiple_stun_observations(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let first_server = Rfc5780StunServer::bind(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .await?;
        let first_server_addr = first_server.primary_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let first_task = tokio::spawn(async move { first_server.serve(shutdown_rx).await });
        let second_server = BindingStunServer::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let second_server_addr = second_server.local_addr()?;
        let second_task = tokio::spawn(async move { second_server.serve_once().await });
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );

        let classification = runtime
            .classify_nat(
                SocketAddr::from(([127, 0, 0, 1], 0)),
                vec![first_server_addr, second_server_addr],
            )
            .await?;
        second_task.await??;
        shutdown_tx.send(true)?;
        first_task.await??;

        assert_eq!(classification.observations.len(), 2);
        assert!(!classification.filtering_observations.is_empty());
        assert_eq!(classification.mapping_behavior, NatMappingBehavior::NoNat);
        assert_eq!(
            classification.filtering_behavior,
            NatFilteringBehavior::EndpointIndependent
        );
        assert_eq!(
            classification.strategy,
            NatTraversalStrategy::DirectCandidate
        );
        let status = runtime.status().await;
        assert_eq!(status.candidate_count, 2);
        assert_eq!(status.nat_classification, Some(classification));
        Ok(())
    }
}
