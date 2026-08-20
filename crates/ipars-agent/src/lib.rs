pub mod overlay_forwarder;
pub mod overlay_transit;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::TryInto;
use std::ffi::OsStr;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::{StreamExt, TryStreamExt};
use ipars_crypto::{
    decode_wireguard_private_key_b64, decode_wireguard_public_key_b64, encode_bytes, CryptoError,
    IdentityKeyPair, WireGuardKeyPair,
};
use ipars_relay::{
    encode_relay_datagram_with_route, encode_relay_endpoint_announcement,
    wireguard_datagram_payload,
};
use ipars_route_manager::{
    desired_managed_route_inventory, validate_route_plan, warn_if_linux_netns_is_current,
    with_linux_network_namespace, with_netlink_namespace, LinuxNetlinkSocket,
    LinuxNetworkNamespace, RouteManager, RouteManagerError, RoutePlan, RoutePlanOwner,
};
#[cfg(test)]
use ipars_route_manager::{ManagedRoute, ManagedRouteInventory};
use ipars_stun::{StunError, UdpStunProbe};
use ipars_types::api::{
    packet_flow_destination_drop_reason, AgentBuildInfo, AgentManagedProcessState,
    AgentManagedProcessStatus, AgentMetricsResponse, AgentPacketFlowApplication,
    AgentPacketFlowApplicationCount, AgentPacketFlowClassification,
    AgentPacketFlowClassificationCount, AgentPacketFlowDropReason, AgentPacketFlowDropReasonCount,
    AgentPacketFlowDuplicateSource, AgentPacketFlowDuplicateSourceCount, AgentPacketFlowMatch,
    AgentPacketFlowMatchKind, AgentPacketFlowObservation, AgentPathProbeRequest,
    AgentRelayAdmissionFailureReason, AgentRelayAdmissionFailureReasonCount,
    AgentRelayForwarderMetrics, AgentStatusResponse, LazyConnectMetrics, PathStateCount, PeerMap,
    RemoveNodeRequest, RotateWireGuardKeyRequest, SignalHolePunchPlanResponse,
};
use ipars_types::{
    bootstrap_endpoints_include_core_services, canonical_bootstrap_endpoint_url,
    endpoint_addr_is_usable, private_ip_addrs_share_subnet, socket_addr_is_globally_routable,
    validate_join_token_bootstrap_endpoints, BootstrapEndpoint, BootstrapEndpointKind,
    CandidateSource, ClusterPolicy, EndpointCandidate, EndpointCandidateKind, NatClassification,
    NatProbeObservation, NeighborMap, NodeId, NodeRecord, OverlayPath, PathChangeEvent,
    PathChangeKind, PathQualityObservation, PathRecord, PathScore, PathState, Role, Route, Tag,
    TransportProtocol, VpnIp, MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND, MAX_OVERLAY_NODE_ROUTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

#[cfg(target_os = "linux")]
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};
#[cfg(target_os = "linux")]
use netlink_packet_generic::GenlMessage;
#[cfg(target_os = "linux")]
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute,
    WireguardCmd, WireguardMessage, WireguardPeer, WireguardPeerAttribute, WireguardPeerFlags,
};
#[cfg(target_os = "linux")]
use rtnetlink::{LinkUnspec, LinkWireguard};

const AGENT_BUILD_VERSION: &str = match option_env!("HETERONETWORK_BUILD_VERSION") {
    Some(value) if !value.is_empty() => value,
    _ => env!("CARGO_PKG_VERSION"),
};
const AGENT_BUILD_HASH: &str = match option_env!("HETERONETWORK_BUILD_HASH") {
    Some(value) if !value.is_empty() => value,
    _ => "dev",
};

fn current_agent_build_info() -> AgentBuildInfo {
    AgentBuildInfo {
        version: AGENT_BUILD_VERSION.to_string(),
        commit: AGENT_BUILD_HASH.chars().take(7).collect(),
    }
}

const MAX_PATH_CHANGE_EVENTS: usize = 1024;
pub const MAX_BOOTSTRAP_PEER_CACHE_PEERS: usize = 8;
const DEFAULT_SYSTEM_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SYSTEM_COMMAND_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const DEFAULT_SYSTEM_COMMAND_OUTPUT_MAX_BYTES: usize = 64 * 1024;
const MAX_SYSTEM_COMMAND_OUTPUT_MAX_BYTES: usize = 1024 * 1024;
const SANITIZED_SYSTEM_COMMAND_PATH: &str = "/usr/bin:/usr/sbin:/bin:/sbin";
const SANITIZED_SYSTEM_COMMAND_LOCALE: &str = "C";
const MAX_LINUX_COMMAND_PROGRAM_BYTES: usize = 4096;
const MAX_LINUX_COMMAND_ARGS: usize = 1024;
const MAX_LINUX_COMMAND_ARG_BYTES: usize = 128 * 1024;
const MAX_LINUX_COMMAND_ARGV_BYTES: usize = 1024 * 1024;
const MAX_LINUX_COMMAND_STDIN_BYTES: usize = 64 * 1024;
const MAX_FORWARDER_UDP_PAYLOAD_BYTES: usize = 65_507;
const MAX_AGENT_STATE_FILE_BYTES: u64 = 1024 * 1024;
const DIRECT_PATH_PROBE_KEEPALIVE_SECONDS: u16 = 1;
const PASSIVE_WIREGUARD_HOLD_ENDPOINT: &str = "127.0.0.1:9";
const PASSIVE_WIREGUARD_PUBLIC_KEY_DOMAIN: &[u8] =
    b"HeteroNetwork passive WireGuard quarantine key v1\0";
const OVERLAY_QUARANTINE_PUBLIC_KEY_DOMAIN: &[u8] =
    b"HeteroNetwork bounded overlay quarantine key v1\0";
const OVERLAY_QUARANTINE_NODE_ID: &str = "__overlay_quarantine__";
const MAX_RESOLVED_OVERLAY_PATHS: usize = 4_096;
const MAX_PENDING_OVERLAY_DESTINATIONS: usize = 4_096;
const MAX_RETAINED_OVERLAY_TOPOLOGIES: usize = 8;
const OVERLAY_TOPOLOGY_MIGRATION_GRACE: Duration = Duration::from_secs(120);

mod peer_probe;

#[cfg(target_os = "linux")]
mod boringtun_backend;

pub use peer_probe::{
    PeerProbeConfig, PeerProbeMeasurement, PeerQualityProbeTarget, UdpPeerProbe,
    UdpPeerProbeResponder, DEFAULT_PEER_PROBE_PORT,
};

#[cfg(target_os = "linux")]
pub use boringtun_backend::{
    BoringTunPeerInventorySource, BoringTunPeerTelemetrySource, BoringTunWireGuardBackend,
};

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("agent state io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("agent state serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("insecure agent state path: {0}")]
    InsecureStatePath(String),
    #[error("agent state is invalid: {0}")]
    InvalidState(String),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("stun probe error: {0}")]
    Stun(#[from] StunError),
    #[error("mapped public IP validation failed: {0}")]
    MappedPublic(String),
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
    #[error("path probe rejected: {0}")]
    PathProbeRejected(String),
    #[error("peer quality probe failed: {0}")]
    PeerProbe(String),
    #[error("path state rejected: {0}")]
    PathStateRejected(String),
    #[error("peer path does not exist: {0}")]
    MissingPeer(NodeId),
    #[error("peer map has not been synced for node {0}")]
    PeerMapUnavailable(NodeId),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentNodeState {
    pub node_id: NodeId,
    pub identity_private_key_b64: String,
    pub identity_public_key_b64: String,
    pub wireguard_private_key_b64: String,
    pub wireguard_public_key_b64: String,
    #[serde(default)]
    pub vpn_ip: Option<VpnIp>,
    #[serde(default)]
    pub registered_node: Option<NodeRecord>,
    /// Endpoints currently used by the Agent runtime.
    #[serde(default)]
    pub bootstrap_endpoints: Vec<BootstrapEndpoint>,
    /// Signed endpoints used only until registration or the first non-empty active directory.
    /// `None` records that signed seeds must not be reintroduced into the runtime directory.
    #[serde(default)]
    pub seed_bootstrap_endpoints: Option<Vec<BootstrapEndpoint>>,
    /// Trusted control-plane gateways retained across restarts so the Agent can fetch its first
    /// peer map before private overlay control-plane endpoints are reachable.
    #[serde(default)]
    pub control_plane_seed_urls: Vec<String>,
    #[serde(default)]
    pub web_ui_seed_urls: Vec<String>,
    /// A bounded, non-authoritative peer subset used only to restore an overlay route to the
    /// control plane after the host loses its in-kernel WireGuard state.
    #[serde(default)]
    pub bootstrap_peer_cache: Option<PeerMap>,
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
            vpn_ip: None,
            registered_node: None,
            bootstrap_endpoints: Vec::new(),
            seed_bootstrap_endpoints: Some(Vec::new()),
            control_plane_seed_urls: Vec::new(),
            web_ui_seed_urls: Vec::new(),
            bootstrap_peer_cache: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn identity_key_pair(&self) -> Result<IdentityKeyPair, AgentError> {
        let identity = IdentityKeyPair::from_signing_key_b64(&self.identity_private_key_b64)
            .map_err(|error| {
                AgentError::InvalidState(format!("identity private key is invalid: {error}"))
            })?;
        if identity.public_key_b64() != self.identity_public_key_b64 {
            return Err(AgentError::InvalidState(
                "identity public key does not match identity private key".to_string(),
            ));
        }
        if identity.node_id() != self.node_id {
            return Err(AgentError::InvalidState(format!(
                "node ID {} does not match identity key-derived node ID {}",
                self.node_id,
                identity.node_id()
            )));
        }
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), AgentError> {
        self.identity_key_pair()?;
        let wireguard = WireGuardKeyPair::from_private_key_b64(&self.wireguard_private_key_b64)
            .map_err(|error| {
                AgentError::InvalidState(format!("WireGuard private key is invalid: {error}"))
            })?;
        if wireguard.public_key_b64 != self.wireguard_public_key_b64 {
            return Err(AgentError::InvalidState(
                "WireGuard public key does not match WireGuard private key".to_string(),
            ));
        }
        if self.updated_at < self.created_at {
            return Err(AgentError::InvalidState(format!(
                "updated_at {} is before created_at {}",
                self.updated_at, self.created_at
            )));
        }
        validate_join_token_bootstrap_endpoints(&self.bootstrap_endpoints).map_err(|error| {
            AgentError::InvalidState(format!(
                "persisted bootstrap endpoints are invalid: {}",
                error.reason()
            ))
        })?;
        if self.seed_bootstrap_endpoints.is_none()
            && !self.bootstrap_endpoints.is_empty()
            && !bootstrap_endpoints_include_core_services(&self.bootstrap_endpoints)
        {
            return Err(AgentError::InvalidState(
                "persisted authoritative bootstrap endpoints must include control_plane, signal, and stun endpoints"
                    .to_string(),
            ));
        }
        if let Some(seeds) = &self.seed_bootstrap_endpoints {
            validate_join_token_bootstrap_endpoints(seeds).map_err(|error| {
                AgentError::InvalidState(format!(
                    "persisted signed seed endpoints are invalid: {}",
                    error.reason()
                ))
            })?;
        }
        validate_control_plane_seed_urls(&self.control_plane_seed_urls)?;
        validate_web_ui_seed_urls(&self.web_ui_seed_urls)?;
        if let Some(peer_map) = &self.bootstrap_peer_cache {
            let expected_cluster = self
                .registered_node
                .as_ref()
                .map(|node| &node.cluster_id)
                .unwrap_or(&peer_map.cluster_id);
            validate_bootstrap_peer_cache(peer_map, &self.node_id, expected_cluster)?;
        }
        if let Some(node) = &self.registered_node {
            if node.node_id != self.node_id {
                return Err(AgentError::InvalidState(format!(
                    "registered node ID {} does not match state node ID {}",
                    node.node_id, self.node_id
                )));
            }
            if node.identity_public_key != self.identity_public_key_b64 {
                return Err(AgentError::InvalidState(
                    "registered node identity public key does not match state identity public key"
                        .to_string(),
                ));
            }
            if node.wireguard_public_key != self.wireguard_public_key_b64 {
                return Err(AgentError::InvalidState(
                    "registered node WireGuard public key does not match state WireGuard public key"
                        .to_string(),
                ));
            }
            if self.vpn_ip != Some(node.vpn_ip) {
                return Err(AgentError::InvalidState(
                    "registered node VPN IP does not match state VPN IP".to_string(),
                ));
            }
        }
        Ok(())
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
        let bytes = read_private_agent_state_file(&self.path)?;
        let state: AgentNodeState = serde_json::from_slice(&bytes)?;
        state.validate()?;
        Ok(state)
    }

    pub fn save(&self, state: &AgentNodeState) -> Result<(), AgentError> {
        state.validate()?;
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

fn read_private_agent_state_file(path: &Path) -> Result<Vec<u8>, AgentError> {
    let metadata = std::fs::symlink_metadata(path)?;
    validate_private_agent_state_metadata(path, &metadata)?;
    ensure_private_agent_state_file_size(path, metadata.len())?;

    let mut file = open_private_agent_state_file(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(AgentError::InsecureStatePath(format!(
            "{} must be a regular file",
            path.display()
        )));
    }
    ensure_private_agent_state_file_size(path, metadata.len())?;

    let mut bytes = Vec::new();
    let mut reader = file.by_ref().take(MAX_AGENT_STATE_FILE_BYTES + 1);
    reader.read_to_end(&mut bytes)?;
    ensure_private_agent_state_file_size(path, bytes.len() as u64)?;
    Ok(bytes)
}

#[cfg(unix)]
fn open_private_agent_state_file(path: &Path) -> Result<std::fs::File, AgentError> {
    use std::os::unix::fs::OpenOptionsExt;

    Ok(std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?)
}

#[cfg(not(unix))]
fn open_private_agent_state_file(path: &Path) -> Result<std::fs::File, AgentError> {
    Ok(std::fs::File::open(path)?)
}

fn ensure_private_agent_state_file_size(path: &Path, size: u64) -> Result<(), AgentError> {
    if size > MAX_AGENT_STATE_FILE_BYTES {
        return Err(AgentError::InsecureStatePath(format!(
            "{} exceeds maximum size of {} bytes",
            path.display(),
            MAX_AGENT_STATE_FILE_BYTES
        )));
    }
    Ok(())
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

#[derive(Debug, Default)]
struct PendingOverlayDestinations {
    queue: VecDeque<IpAddr>,
    members: BTreeSet<IpAddr>,
}

impl PendingOverlayDestinations {
    fn enqueue(&mut self, destination: IpAddr) -> bool {
        if self.members.contains(&destination)
            || self.queue.len() >= MAX_PENDING_OVERLAY_DESTINATIONS
        {
            return false;
        }
        self.members.insert(destination);
        self.queue.push_back(destination);
        true
    }

    fn requeue(&mut self, destination: IpAddr) {
        if self.members.contains(&destination) {
            return;
        }
        if self.queue.len() >= MAX_PENDING_OVERLAY_DESTINATIONS {
            if let Some(displaced) = self.queue.pop_front() {
                self.members.remove(&displaced);
            }
        }
        self.members.insert(destination);
        self.queue.push_back(destination);
    }

    fn requeue_all_prioritized(&mut self, destinations: impl IntoIterator<Item = IpAddr>) {
        let previous = std::mem::take(&mut self.queue);
        let mut queue = VecDeque::with_capacity(MAX_PENDING_OVERLAY_DESTINATIONS);
        let mut members = BTreeSet::new();
        for destination in destinations.into_iter().chain(previous) {
            if queue.len() >= MAX_PENDING_OVERLAY_DESTINATIONS {
                break;
            }
            if members.insert(destination) {
                queue.push_back(destination);
            }
        }
        self.queue = queue;
        self.members = members;
    }

    fn take(&mut self, maximum: usize) -> Vec<IpAddr> {
        let mut selected = Vec::with_capacity(maximum.min(self.queue.len()));
        for _ in 0..maximum {
            let Some(destination) = self.queue.pop_front() else {
                break;
            };
            self.members.remove(&destination);
            selected.push(destination);
        }
        selected
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OverlayShortcutSnapshot {
    resolved_overlay_peers: BTreeSet<NodeId>,
    direct_shortcut_targets: BTreeSet<NodeId>,
}

impl OverlayShortcutSnapshot {
    pub fn resolved_overlay_peers(&self) -> &BTreeSet<NodeId> {
        &self.resolved_overlay_peers
    }

    pub fn direct_shortcut_targets(&self) -> &BTreeSet<NodeId> {
        &self.direct_shortcut_targets
    }

    pub fn is_resolved_overlay_peer(&self, peer: &NodeId) -> bool {
        self.resolved_overlay_peers.contains(peer)
    }

    pub fn is_direct_shortcut(&self, peer: &NodeId) -> bool {
        self.direct_shortcut_targets.contains(peer)
    }

    pub fn requires_overlay_forwarder(&self, peer: &NodeId) -> bool {
        self.is_resolved_overlay_peer(peer) && !self.is_direct_shortcut(peer)
    }
}

#[derive(Debug)]
struct CachedOverlayShortcutSnapshot {
    generation: u64,
    snapshot: Arc<OverlayShortcutSnapshot>,
}

#[derive(Debug, Clone)]
struct RetainedNeighborMap {
    topology_epoch: u64,
    neighbors: Vec<ipars_types::OverlayNeighbor>,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct ResolvedOverlayRouteLease {
    route: Route,
    destination: IpAddr,
    last_used: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct ResolvedOverlayPathLease {
    path: OverlayPath,
    resolved_at: DateTime<Utc>,
    vpn_destination_last_used: Option<DateTime<Utc>>,
    exact_routes: BTreeMap<ipnet::IpNet, ResolvedOverlayRouteLease>,
    exact_route_lru: BTreeSet<(DateTime<Utc>, ipnet::IpNet)>,
}

impl ResolvedOverlayPathLease {
    fn new(mut path: OverlayPath, exact_route: Option<Route>, resolved_at: DateTime<Utc>) -> Self {
        let vpn_destination_last_used = (exact_route.is_none()).then_some(resolved_at);
        let destination = path.destination;
        path.target.routes.clear();
        let mut lease = Self {
            path,
            resolved_at,
            vpn_destination_last_used,
            exact_routes: BTreeMap::new(),
            exact_route_lru: BTreeSet::new(),
        };
        if let Some(route) = exact_route {
            lease.upsert_exact_route(route, destination, resolved_at);
        }
        lease
    }

    fn merge(
        &mut self,
        mut path: OverlayPath,
        exact_route: Option<Route>,
        resolved_at: DateTime<Utc>,
    ) {
        debug_assert_eq!(self.path.topology_epoch, path.topology_epoch);
        debug_assert_eq!(self.path.routing_epoch, path.routing_epoch);
        let destination = path.destination;
        path.target.routes.clear();
        if let Some(route) = exact_route {
            self.upsert_exact_route(route, destination, resolved_at);
        } else {
            self.vpn_destination_last_used = Some(
                self.vpn_destination_last_used
                    .map_or(resolved_at, |last_used| last_used.max(resolved_at)),
            );
        }
        self.path = path;
        self.resolved_at = self.resolved_at.max(resolved_at);
    }

    fn exact_route_count(&self) -> usize {
        self.exact_routes.len()
    }

    fn oldest_exact_route(&self) -> Option<(ipnet::IpNet, DateTime<Utc>)> {
        self.exact_route_lru
            .first()
            .map(|(last_used, cidr)| (*cidr, *last_used))
    }

    fn remove_exact_route(&mut self, cidr: ipnet::IpNet) -> bool {
        let Some(removed) = self.exact_routes.remove(&cidr) else {
            return true;
        };
        self.exact_route_lru.remove(&(removed.last_used, cidr));
        if self.vpn_destination_last_used.is_some() {
            self.path.destination = self.path.target.vpn_ip.0;
            return true;
        }
        let Some(route) = self.exact_routes.values().next() else {
            return false;
        };
        self.path.destination = route.destination;
        true
    }

    fn upsert_exact_route(&mut self, route: Route, destination: IpAddr, used_at: DateTime<Utc>) {
        let cidr = route.cidr;
        if let Some(previous) = self.exact_routes.get(&cidr) {
            self.exact_route_lru.remove(&(previous.last_used, cidr));
        }
        let last_used = self
            .exact_routes
            .get(&cidr)
            .map_or(used_at, |previous| previous.last_used.max(used_at));
        self.exact_routes.insert(
            cidr,
            ResolvedOverlayRouteLease {
                route,
                destination,
                last_used,
            },
        );
        self.exact_route_lru.insert((last_used, cidr));
    }

    fn touch_exact_route(
        &mut self,
        cidr: ipnet::IpNet,
        used_at: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        let exact_route = self.exact_routes.get_mut(&cidr)?;
        let previous = exact_route.last_used;
        if used_at <= previous {
            return Some(previous);
        }
        self.exact_route_lru.remove(&(previous, cidr));
        exact_route.last_used = used_at;
        self.exact_route_lru.insert((used_at, cidr));
        Some(previous)
    }

    fn materialized_path(&self) -> OverlayPath {
        let mut path = self.path.clone();
        path.target.routes = self
            .exact_routes
            .values()
            .take(MAX_OVERLAY_NODE_ROUTES)
            .map(|lease| lease.route.clone())
            .collect();
        path
    }

    fn materialized_target(&self) -> NodeRecord {
        self.materialized_path().target
    }

    fn refresh_destinations(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.vpn_destination_last_used
            .is_some()
            .then_some(self.path.target.vpn_ip.0)
            .into_iter()
            .chain(self.exact_routes.values().map(|lease| lease.destination))
    }
}

#[derive(Debug, Default)]
struct ResolvedOverlayPathState {
    paths: BTreeMap<NodeId, ResolvedOverlayPathLease>,
    exact_route_lru: BTreeSet<(DateTime<Utc>, NodeId, ipnet::IpNet)>,
}

impl ResolvedOverlayPathState {
    fn remove_peer(&mut self, peer: &NodeId) -> Option<ResolvedOverlayPathLease> {
        let lease = self.paths.remove(peer)?;
        for (cidr, exact_route) in &lease.exact_routes {
            self.exact_route_lru
                .remove(&(exact_route.last_used, peer.clone(), *cidr));
        }
        Some(lease)
    }

    fn remove_exact_route(&mut self, peer: &NodeId, cidr: ipnet::IpNet) -> bool {
        let Some(last_used) = self
            .paths
            .get(peer)
            .and_then(|lease| lease.exact_routes.get(&cidr))
            .map(|lease| lease.last_used)
        else {
            return self.paths.contains_key(peer);
        };
        self.exact_route_lru
            .remove(&(last_used, peer.clone(), cidr));
        let retained = self
            .paths
            .get_mut(peer)
            .is_some_and(|lease| lease.remove_exact_route(cidr));
        if !retained {
            self.paths.remove(peer);
        }
        retained
    }

    fn touch_exact_route(&mut self, peer: &NodeId, cidr: ipnet::IpNet, used_at: DateTime<Utc>) {
        let Some(previous) = self
            .paths
            .get_mut(peer)
            .and_then(|lease| lease.touch_exact_route(cidr, used_at))
        else {
            return;
        };
        if used_at <= previous {
            return;
        }
        self.exact_route_lru.remove(&(previous, peer.clone(), cidr));
        self.exact_route_lru.insert((used_at, peer.clone(), cidr));
    }

    fn upsert_path(
        &mut self,
        peer: NodeId,
        path: OverlayPath,
        exact_route: Option<Route>,
        observed_at: DateTime<Utc>,
    ) -> NodeRecord {
        let exact_cidr = exact_route.as_ref().map(|route| route.cidr);
        if let Some(route) = exact_route.as_ref() {
            if let Some(previous) = self
                .paths
                .get(&peer)
                .and_then(|lease| lease.exact_routes.get(&route.cidr))
            {
                self.exact_route_lru
                    .remove(&(previous.last_used, peer.clone(), route.cidr));
            }
        }
        let lease = match self.paths.entry(peer.clone()) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.get_mut().merge(path, exact_route, observed_at);
                entry.into_mut()
            }
            std::collections::btree_map::Entry::Vacant(entry) => entry.insert(
                ResolvedOverlayPathLease::new(path, exact_route, observed_at),
            ),
        };
        let (route_index, target) = {
            let route_index = exact_cidr
                .and_then(|cidr| lease.exact_routes.get(&cidr))
                .map(|route| (route.last_used, route.route.cidr));
            (route_index, lease.materialized_target())
        };
        if let Some((last_used, cidr)) = route_index {
            self.exact_route_lru.insert((last_used, peer, cidr));
        }
        target
    }
}

fn trim_on_demand_overlay_paths(
    resolved: &mut ResolvedOverlayPathState,
    lazy_connect: &mut LazyConnectManager,
    backbone_peers: &BTreeSet<NodeId>,
    limit: usize,
    protected_peer: Option<&NodeId>,
) -> BTreeSet<NodeId> {
    let on_demand_count = resolved
        .paths
        .keys()
        .filter(|peer| !backbone_peers.contains(*peer))
        .count();
    let excess = on_demand_count.saturating_sub(limit);
    if excess == 0 {
        return BTreeSet::new();
    }

    let mut candidates = resolved
        .paths
        .iter()
        .filter(|(peer, _)| !backbone_peers.contains(*peer) && protected_peer != Some(*peer))
        .map(|(peer, lease)| {
            (
                lazy_connect.is_durably_pinned(peer),
                lazy_connect
                    .last_used
                    .get(peer)
                    .copied()
                    .unwrap_or(lease.resolved_at),
                peer.clone(),
            )
        })
        .collect::<Vec<_>>();
    candidates.sort();

    let mut evicted = BTreeSet::new();
    for (_, _, peer) in candidates.into_iter().take(excess) {
        resolved.remove_peer(&peer);
        lazy_connect.remove_activity(&peer);
        lazy_connect.remove_observed_peer(&peer);
        evicted.insert(peer);
    }
    evicted
}

#[derive(Debug)]
struct OverlayShortcutGenerationUpdate<'a> {
    generation: &'a AtomicU64,
}

impl<'a> OverlayShortcutGenerationUpdate<'a> {
    fn begin(generation: &'a AtomicU64) -> Self {
        let previous = generation.fetch_add(1, Ordering::AcqRel);
        debug_assert_eq!(previous % 2, 0);
        Self { generation }
    }
}

impl Drop for OverlayShortcutGenerationUpdate<'_> {
    fn drop(&mut self) {
        let previous = self.generation.fetch_add(1, Ordering::AcqRel);
        debug_assert_eq!(previous % 2, 1);
    }
}

#[derive(Debug)]
pub struct AgentRuntime {
    state: RwLock<AgentNodeState>,
    stun_refresh: tokio::sync::Mutex<()>,
    candidates: tokio::sync::RwLock<Vec<EndpointCandidate>>,
    nat_classification: tokio::sync::RwLock<Option<NatClassification>>,
    local_advertised_routes: tokio::sync::RwLock<Vec<Route>>,
    latest_peer_map: tokio::sync::RwLock<Option<PeerMap>>,
    latest_neighbor_map: tokio::sync::RwLock<Option<NeighborMap>>,
    retained_neighbor_maps: tokio::sync::RwLock<VecDeque<RetainedNeighborMap>>,
    neighbor_map_update: tokio::sync::Mutex<()>,
    resolved_overlay_paths: tokio::sync::RwLock<ResolvedOverlayPathState>,
    overlay_shortcut_generation: AtomicU64,
    overlay_shortcut_snapshot: tokio::sync::RwLock<Option<CachedOverlayShortcutSnapshot>>,
    pending_overlay_destinations: tokio::sync::Mutex<PendingOverlayDestinations>,
    peer_map_sync_notify: Arc<tokio::sync::Notify>,
    heartbeat_report_notify: Arc<tokio::sync::Notify>,
    signal_path_notify: Arc<tokio::sync::Notify>,
    wireguard_endpoint_update: tokio::sync::Mutex<()>,
    path_state: tokio::sync::RwLock<BTreeMap<(NodeId, NodeId), PathRecord>>,
    pending_direct_path_probes: tokio::sync::RwLock<BTreeMap<NodeId, PendingDirectPathProbe>>,
    direct_path_probe_retry_after: tokio::sync::RwLock<BTreeMap<NodeId, DateTime<Utc>>>,
    path_quality_observations: tokio::sync::RwLock<BTreeMap<NodeId, PathQualityObservation>>,
    path_change_events: tokio::sync::RwLock<VecDeque<PathChangeEvent>>,
    path_change_event_total_count: AtomicU64,
    path_change_event_dropped_count: AtomicU64,
    relay_sessions: tokio::sync::RwLock<BTreeMap<NodeId, RelaySessionState>>,
    relay_forwarder_endpoints: tokio::sync::RwLock<BTreeMap<NodeId, SocketAddr>>,
    relay_forwarder_metrics: tokio::sync::RwLock<BTreeMap<NodeId, Arc<RelayForwarderStats>>>,
    overlay_forwarder_endpoints: tokio::sync::RwLock<BTreeMap<NodeId, SocketAddr>>,
    userspace_wireguard_process: tokio::sync::RwLock<Option<AgentManagedProcessStatus>>,
    lazy_connect: tokio::sync::RwLock<LazyConnectManager>,
    internal_packet_flow_udp_ports: tokio::sync::RwLock<BTreeSet<u16>>,
    relay_admission_attempt_count: AtomicU64,
    relay_admission_success_count: AtomicU64,
    relay_admission_failure_count: AtomicU64,
    relay_admission_failure_reason_counters: AgentRelayAdmissionFailureReasonCounters,
    path_probe_record_count: AtomicU64,
    direct_path_probe_started_count: AtomicU64,
    direct_path_probe_confirmed_count: AtomicU64,
    direct_path_probe_timeout_count: AtomicU64,
    peer_probe_measurement_count: AtomicU64,
    peer_probe_failure_count: AtomicU64,
    peer_probe_request_sent_count: AtomicU64,
    peer_probe_response_received_count: AtomicU64,
    peer_probe_timeout_count: AtomicU64,
    peer_probe_responder_request_count: AtomicU64,
    peer_probe_responder_invalid_count: AtomicU64,
    peer_probe_responder_unknown_source_count: AtomicU64,
    peer_probe_responder_rate_limited_count: AtomicU64,
    peer_probe_responder_send_failure_count: AtomicU64,
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
    packet_flow_filtered_internal_control_traffic_count: AtomicU64,
    packet_flow_classification_unknown_count: AtomicU64,
    packet_flow_classification_opening_count: AtomicU64,
    packet_flow_classification_unreplied_count: AtomicU64,
    packet_flow_classification_assured_count: AtomicU64,
    packet_flow_classification_established_count: AtomicU64,
    packet_flow_classification_closing_count: AtomicU64,
    packet_flow_classification_closed_count: AtomicU64,
    packet_flow_application_unknown_count: AtomicU64,
    packet_flow_application_dns_count: AtomicU64,
    packet_flow_application_dhcp_count: AtomicU64,
    packet_flow_application_http_count: AtomicU64,
    packet_flow_application_https_count: AtomicU64,
    packet_flow_application_ssh_count: AtomicU64,
    packet_flow_application_ldap_count: AtomicU64,
    packet_flow_application_smb_count: AtomicU64,
    packet_flow_application_nfs_count: AtomicU64,
    packet_flow_application_rdp_count: AtomicU64,
    packet_flow_application_vnc_count: AtomicU64,
    packet_flow_application_ftp_count: AtomicU64,
    packet_flow_application_tftp_count: AtomicU64,
    packet_flow_application_rsync_count: AtomicU64,
    packet_flow_application_smtp_count: AtomicU64,
    packet_flow_application_imap_count: AtomicU64,
    packet_flow_application_pop3_count: AtomicU64,
    packet_flow_application_sip_count: AtomicU64,
    packet_flow_application_kerberos_count: AtomicU64,
    packet_flow_application_ntp_count: AtomicU64,
    packet_flow_application_radius_count: AtomicU64,
    packet_flow_application_tacacs_count: AtomicU64,
    packet_flow_application_bgp_count: AtomicU64,
    packet_flow_application_bfd_count: AtomicU64,
    packet_flow_application_ipars_control_plane_count: AtomicU64,
    packet_flow_application_ipars_signal_count: AtomicU64,
    packet_flow_application_ipars_agent_count: AtomicU64,
    packet_flow_application_ipars_relay_count: AtomicU64,
    packet_flow_application_stun_count: AtomicU64,
    packet_flow_application_turn_count: AtomicU64,
    packet_flow_application_kubernetes_api_count: AtomicU64,
    packet_flow_application_kubelet_count: AtomicU64,
    packet_flow_application_docker_api_count: AtomicU64,
    packet_flow_application_cri_count: AtomicU64,
    packet_flow_application_containerd_count: AtomicU64,
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
    packet_flow_application_couchbase_count: AtomicU64,
    packet_flow_application_prometheus_count: AtomicU64,
    packet_flow_application_opentelemetry_count: AtomicU64,
    packet_flow_application_grafana_count: AtomicU64,
    packet_flow_application_statsd_count: AtomicU64,
    packet_flow_application_graphite_count: AtomicU64,
    packet_flow_application_collectd_count: AtomicU64,
    packet_flow_application_syslog_count: AtomicU64,
    packet_flow_application_snmp_count: AtomicU64,
    packet_flow_application_jaeger_count: AtomicU64,
    packet_flow_application_loki_count: AtomicU64,
    packet_flow_application_tempo_count: AtomicU64,
    packet_flow_application_zipkin_count: AtomicU64,
    packet_flow_application_grpc_count: AtomicU64,
    packet_flow_application_kafka_count: AtomicU64,
    packet_flow_application_pulsar_count: AtomicU64,
    packet_flow_application_nats_count: AtomicU64,
    packet_flow_application_mqtt_count: AtomicU64,
    packet_flow_application_coap_count: AtomicU64,
    packet_flow_application_amqp_count: AtomicU64,
    packet_flow_application_cassandra_count: AtomicU64,
    packet_flow_application_mongodb_count: AtomicU64,
    packet_flow_application_neo4j_count: AtomicU64,
    packet_flow_application_elasticsearch_count: AtomicU64,
    packet_flow_application_opensearch_count: AtomicU64,
    packet_flow_application_solr_count: AtomicU64,
    packet_flow_application_git_count: AtomicU64,
    packet_flow_application_ike_count: AtomicU64,
    packet_flow_application_ipsec_count: AtomicU64,
    packet_flow_application_ip_tunnel_count: AtomicU64,
    packet_flow_application_gre_count: AtomicU64,
    packet_flow_application_vxlan_count: AtomicU64,
    packet_flow_application_geneve_count: AtomicU64,
    packet_flow_application_wireguard_count: AtomicU64,
    packet_flow_application_openvpn_count: AtomicU64,
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
    forwarding_enabled: Arc<AtomicBool>,
}

impl UdpRelayFrameForwarder {
    pub fn new(session: RelaySessionState, wireguard_endpoint: SocketAddr) -> Self {
        Self {
            session,
            wireguard_endpoint,
            metrics: None,
            forwarding_enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn with_metrics(mut self, metrics: Arc<RelayForwarderStats>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn with_forwarding_enabled(mut self, forwarding_enabled: Arc<AtomicBool>) -> Self {
        self.forwarding_enabled = forwarding_enabled;
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

    pub fn encode_endpoint_announcement(&self) -> Result<Vec<u8>, AgentError> {
        self.ensure_session_active()?;
        let local = relay_session_local_node(&self.session.session_id, &self.session.peer)?;
        encode_relay_endpoint_announcement(
            &self.session.session_id,
            &self.session.session_token,
            &local,
            &self.session.peer,
        )
        .map_err(|error| AgentError::RelaySession(error.to_string()))
    }

    pub async fn send_endpoint_announcement(
        &self,
        socket: &tokio::net::UdpSocket,
    ) -> Result<usize, AgentError> {
        let datagram = self.encode_endpoint_announcement()?;
        Ok(socket
            .send_to(&datagram, self.session.relay_endpoint)
            .await?)
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
        self.send_endpoint_announcement(&socket).await?;
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
                    if !self.forwarding_enabled.load(Ordering::Relaxed) {
                        continue;
                    }
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

fn validate_bootstrap_endpoint_set(
    endpoints: &[BootstrapEndpoint],
    label: &str,
) -> Result<(), AgentError> {
    validate_join_token_bootstrap_endpoints(endpoints).map_err(|error| {
        AgentError::InvalidState(format!("{label} is invalid: {}", error.reason()))
    })
}

fn validate_web_ui_seed_urls(urls: &[String]) -> Result<(), AgentError> {
    if urls.len() > MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND {
        return Err(AgentError::InvalidState(format!(
            "web UI seed URL count exceeds maximum {MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND}"
        )));
    }
    let endpoints = urls
        .iter()
        .cloned()
        .map(|url| BootstrapEndpoint {
            kind: BootstrapEndpointKind::WebUi,
            url,
        })
        .collect::<Vec<_>>();
    validate_bootstrap_endpoint_set(&endpoints, "web UI seed URL set")
}

fn validate_control_plane_seed_urls(urls: &[String]) -> Result<(), AgentError> {
    if urls.len() > MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND {
        return Err(AgentError::InvalidState(format!(
            "control-plane seed URL count exceeds maximum {MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND}"
        )));
    }
    let endpoints = urls
        .iter()
        .cloned()
        .map(|url| BootstrapEndpoint {
            kind: BootstrapEndpointKind::ControlPlane,
            url,
        })
        .collect::<Vec<_>>();
    validate_bootstrap_endpoint_set(&endpoints, "control-plane seed URL set")
}

/// Selects signed seeds only until a non-empty authoritative directory is available.
pub fn merge_bootstrap_endpoint_sets(
    active: &[BootstrapEndpoint],
    seeds: &[BootstrapEndpoint],
) -> Result<Vec<BootstrapEndpoint>, AgentError> {
    validate_bootstrap_endpoint_set(active, "control-plane service directory")?;
    validate_bootstrap_endpoint_set(seeds, "signed seed endpoint set")?;

    if active.is_empty() {
        Ok(seeds.to_vec())
    } else if !bootstrap_endpoints_include_core_services(active) {
        Err(AgentError::InvalidState(
            "control-plane service directory must include control_plane, signal, and stun endpoints"
                .to_string(),
        ))
    } else {
        Ok(active.to_vec())
    }
}

impl AgentRuntime {
    pub fn new(state: AgentNodeState, policy: ClusterPolicy) -> Self {
        let restored_candidates = state
            .registered_node
            .as_ref()
            .map(|node| {
                node.endpoint_candidates
                    .iter()
                    .filter(|candidate| candidate.node_id == state.node_id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        Self {
            state: RwLock::new(state),
            stun_refresh: tokio::sync::Mutex::new(()),
            candidates: tokio::sync::RwLock::new(restored_candidates),
            nat_classification: tokio::sync::RwLock::new(None),
            local_advertised_routes: tokio::sync::RwLock::new(Vec::new()),
            latest_peer_map: tokio::sync::RwLock::new(None),
            latest_neighbor_map: tokio::sync::RwLock::new(None),
            retained_neighbor_maps: tokio::sync::RwLock::new(VecDeque::new()),
            neighbor_map_update: tokio::sync::Mutex::new(()),
            resolved_overlay_paths: tokio::sync::RwLock::new(ResolvedOverlayPathState::default()),
            overlay_shortcut_generation: AtomicU64::new(0),
            overlay_shortcut_snapshot: tokio::sync::RwLock::new(None),
            pending_overlay_destinations: tokio::sync::Mutex::new(
                PendingOverlayDestinations::default(),
            ),
            peer_map_sync_notify: Arc::new(tokio::sync::Notify::new()),
            heartbeat_report_notify: Arc::new(tokio::sync::Notify::new()),
            signal_path_notify: Arc::new(tokio::sync::Notify::new()),
            wireguard_endpoint_update: tokio::sync::Mutex::new(()),
            path_state: tokio::sync::RwLock::new(BTreeMap::new()),
            pending_direct_path_probes: tokio::sync::RwLock::new(BTreeMap::new()),
            direct_path_probe_retry_after: tokio::sync::RwLock::new(BTreeMap::new()),
            path_quality_observations: tokio::sync::RwLock::new(BTreeMap::new()),
            path_change_events: tokio::sync::RwLock::new(VecDeque::new()),
            path_change_event_total_count: AtomicU64::new(0),
            path_change_event_dropped_count: AtomicU64::new(0),
            relay_sessions: tokio::sync::RwLock::new(BTreeMap::new()),
            relay_forwarder_endpoints: tokio::sync::RwLock::new(BTreeMap::new()),
            relay_forwarder_metrics: tokio::sync::RwLock::new(BTreeMap::new()),
            overlay_forwarder_endpoints: tokio::sync::RwLock::new(BTreeMap::new()),
            userspace_wireguard_process: tokio::sync::RwLock::new(None),
            lazy_connect: tokio::sync::RwLock::new(LazyConnectManager::new(policy)),
            internal_packet_flow_udp_ports: tokio::sync::RwLock::new(BTreeSet::new()),
            relay_admission_attempt_count: AtomicU64::new(0),
            relay_admission_success_count: AtomicU64::new(0),
            relay_admission_failure_count: AtomicU64::new(0),
            relay_admission_failure_reason_counters:
                AgentRelayAdmissionFailureReasonCounters::default(),
            path_probe_record_count: AtomicU64::new(0),
            direct_path_probe_started_count: AtomicU64::new(0),
            direct_path_probe_confirmed_count: AtomicU64::new(0),
            direct_path_probe_timeout_count: AtomicU64::new(0),
            peer_probe_measurement_count: AtomicU64::new(0),
            peer_probe_failure_count: AtomicU64::new(0),
            peer_probe_request_sent_count: AtomicU64::new(0),
            peer_probe_response_received_count: AtomicU64::new(0),
            peer_probe_timeout_count: AtomicU64::new(0),
            peer_probe_responder_request_count: AtomicU64::new(0),
            peer_probe_responder_invalid_count: AtomicU64::new(0),
            peer_probe_responder_unknown_source_count: AtomicU64::new(0),
            peer_probe_responder_rate_limited_count: AtomicU64::new(0),
            peer_probe_responder_send_failure_count: AtomicU64::new(0),
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
            packet_flow_filtered_internal_control_traffic_count: AtomicU64::new(0),
            packet_flow_classification_unknown_count: AtomicU64::new(0),
            packet_flow_classification_opening_count: AtomicU64::new(0),
            packet_flow_classification_unreplied_count: AtomicU64::new(0),
            packet_flow_classification_assured_count: AtomicU64::new(0),
            packet_flow_classification_established_count: AtomicU64::new(0),
            packet_flow_classification_closing_count: AtomicU64::new(0),
            packet_flow_classification_closed_count: AtomicU64::new(0),
            packet_flow_application_unknown_count: AtomicU64::new(0),
            packet_flow_application_dns_count: AtomicU64::new(0),
            packet_flow_application_dhcp_count: AtomicU64::new(0),
            packet_flow_application_http_count: AtomicU64::new(0),
            packet_flow_application_https_count: AtomicU64::new(0),
            packet_flow_application_ssh_count: AtomicU64::new(0),
            packet_flow_application_ldap_count: AtomicU64::new(0),
            packet_flow_application_smb_count: AtomicU64::new(0),
            packet_flow_application_nfs_count: AtomicU64::new(0),
            packet_flow_application_rdp_count: AtomicU64::new(0),
            packet_flow_application_vnc_count: AtomicU64::new(0),
            packet_flow_application_ftp_count: AtomicU64::new(0),
            packet_flow_application_tftp_count: AtomicU64::new(0),
            packet_flow_application_rsync_count: AtomicU64::new(0),
            packet_flow_application_smtp_count: AtomicU64::new(0),
            packet_flow_application_imap_count: AtomicU64::new(0),
            packet_flow_application_pop3_count: AtomicU64::new(0),
            packet_flow_application_sip_count: AtomicU64::new(0),
            packet_flow_application_kerberos_count: AtomicU64::new(0),
            packet_flow_application_ntp_count: AtomicU64::new(0),
            packet_flow_application_radius_count: AtomicU64::new(0),
            packet_flow_application_tacacs_count: AtomicU64::new(0),
            packet_flow_application_bgp_count: AtomicU64::new(0),
            packet_flow_application_bfd_count: AtomicU64::new(0),
            packet_flow_application_ipars_control_plane_count: AtomicU64::new(0),
            packet_flow_application_ipars_signal_count: AtomicU64::new(0),
            packet_flow_application_ipars_agent_count: AtomicU64::new(0),
            packet_flow_application_ipars_relay_count: AtomicU64::new(0),
            packet_flow_application_stun_count: AtomicU64::new(0),
            packet_flow_application_turn_count: AtomicU64::new(0),
            packet_flow_application_kubernetes_api_count: AtomicU64::new(0),
            packet_flow_application_kubelet_count: AtomicU64::new(0),
            packet_flow_application_docker_api_count: AtomicU64::new(0),
            packet_flow_application_cri_count: AtomicU64::new(0),
            packet_flow_application_containerd_count: AtomicU64::new(0),
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
            packet_flow_application_couchbase_count: AtomicU64::new(0),
            packet_flow_application_prometheus_count: AtomicU64::new(0),
            packet_flow_application_opentelemetry_count: AtomicU64::new(0),
            packet_flow_application_grafana_count: AtomicU64::new(0),
            packet_flow_application_statsd_count: AtomicU64::new(0),
            packet_flow_application_graphite_count: AtomicU64::new(0),
            packet_flow_application_collectd_count: AtomicU64::new(0),
            packet_flow_application_syslog_count: AtomicU64::new(0),
            packet_flow_application_snmp_count: AtomicU64::new(0),
            packet_flow_application_jaeger_count: AtomicU64::new(0),
            packet_flow_application_loki_count: AtomicU64::new(0),
            packet_flow_application_tempo_count: AtomicU64::new(0),
            packet_flow_application_zipkin_count: AtomicU64::new(0),
            packet_flow_application_grpc_count: AtomicU64::new(0),
            packet_flow_application_kafka_count: AtomicU64::new(0),
            packet_flow_application_pulsar_count: AtomicU64::new(0),
            packet_flow_application_nats_count: AtomicU64::new(0),
            packet_flow_application_mqtt_count: AtomicU64::new(0),
            packet_flow_application_coap_count: AtomicU64::new(0),
            packet_flow_application_amqp_count: AtomicU64::new(0),
            packet_flow_application_cassandra_count: AtomicU64::new(0),
            packet_flow_application_mongodb_count: AtomicU64::new(0),
            packet_flow_application_neo4j_count: AtomicU64::new(0),
            packet_flow_application_elasticsearch_count: AtomicU64::new(0),
            packet_flow_application_opensearch_count: AtomicU64::new(0),
            packet_flow_application_solr_count: AtomicU64::new(0),
            packet_flow_application_git_count: AtomicU64::new(0),
            packet_flow_application_ike_count: AtomicU64::new(0),
            packet_flow_application_ipsec_count: AtomicU64::new(0),
            packet_flow_application_ip_tunnel_count: AtomicU64::new(0),
            packet_flow_application_gre_count: AtomicU64::new(0),
            packet_flow_application_vxlan_count: AtomicU64::new(0),
            packet_flow_application_geneve_count: AtomicU64::new(0),
            packet_flow_application_wireguard_count: AtomicU64::new(0),
            packet_flow_application_openvpn_count: AtomicU64::new(0),
            packet_flow_application_icmp_count: AtomicU64::new(0),
        }
    }

    pub fn state(&self) -> AgentNodeState {
        match self.state.read() {
            Ok(state) => state.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn replace_state(&self, state: AgentNodeState) -> Result<(), AgentError> {
        state.validate()?;
        match self.state.write() {
            Ok(mut current) => *current = state,
            Err(poisoned) => *poisoned.into_inner() = state,
        }
        Ok(())
    }

    pub fn merge_active_bootstrap_endpoints(
        &self,
        active: &[BootstrapEndpoint],
        updated_at: DateTime<Utc>,
    ) -> Result<Option<AgentNodeState>, AgentError> {
        if active.is_empty() {
            return Ok(None);
        }
        validate_bootstrap_endpoint_set(active, "control-plane service directory")?;
        if !bootstrap_endpoints_include_core_services(active) {
            return Err(AgentError::InvalidState(
                "control-plane service directory must include control_plane, signal, and stun endpoints"
                    .to_string(),
            ));
        }

        let mut state = match self.state.write() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.bootstrap_endpoints == active && state.seed_bootstrap_endpoints.is_none() {
            return Ok(None);
        }
        state.bootstrap_endpoints = active.to_vec();
        state.seed_bootstrap_endpoints = None;
        state.updated_at = updated_at;
        Ok(Some(state.clone()))
    }

    pub fn replace_seed_bootstrap_endpoints(
        &self,
        seeds: &[BootstrapEndpoint],
        updated_at: DateTime<Utc>,
    ) -> Result<Option<AgentNodeState>, AgentError> {
        validate_bootstrap_endpoint_set(seeds, "signed seed endpoint set")?;
        let mut state = match self.state.write() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.seed_bootstrap_endpoints.is_none() {
            return Ok(None);
        }
        if state.registered_node.is_some() {
            state.seed_bootstrap_endpoints = None;
            state.updated_at = updated_at;
            return Ok(Some(state.clone()));
        }
        if state.seed_bootstrap_endpoints.as_deref() == Some(seeds)
            && state.bootstrap_endpoints == seeds
        {
            return Ok(None);
        }
        state.bootstrap_endpoints = seeds.to_vec();
        state.seed_bootstrap_endpoints = Some(seeds.to_vec());
        state.updated_at = updated_at;
        Ok(Some(state.clone()))
    }

    pub fn replace_control_plane_seed_urls(
        &self,
        urls: &[String],
        updated_at: DateTime<Utc>,
    ) -> Result<Option<AgentNodeState>, AgentError> {
        if urls.len() > MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND {
            return Err(AgentError::InvalidState(format!(
                "control-plane seed URL count exceeds maximum {MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND}"
            )));
        }
        let mut seen = BTreeSet::new();
        let mut canonical_urls = Vec::new();
        for url in urls {
            let canonical = canonical_bootstrap_endpoint_url(url).ok_or_else(|| {
                AgentError::InvalidState(
                    "control-plane seed URL is not an absolute URL".to_string(),
                )
            })?;
            if seen.insert(canonical.clone()) {
                canonical_urls.push(canonical);
            }
        }
        validate_control_plane_seed_urls(&canonical_urls)?;
        let mut state = match self.state.write() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.control_plane_seed_urls == canonical_urls {
            return Ok(None);
        }
        state.control_plane_seed_urls = canonical_urls;
        state.updated_at = updated_at;
        Ok(Some(state.clone()))
    }

    pub fn replace_bootstrap_peer_cache(
        &self,
        peer_map: &PeerMap,
        updated_at: DateTime<Utc>,
    ) -> Result<Option<AgentNodeState>, AgentError> {
        let local_node = self.state().node_id;
        let Some(cache) = bootstrap_peer_map_cache(peer_map, &local_node)? else {
            return Ok(None);
        };
        let mut state = match self.state.write() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state
            .bootstrap_peer_cache
            .as_ref()
            .is_some_and(|current| bootstrap_peer_cache_recovery_eq(current, &cache))
        {
            return Ok(None);
        }
        state.bootstrap_peer_cache = Some(cache);
        state.updated_at = updated_at;
        Ok(Some(state.clone()))
    }

    pub fn upsert_web_ui_seed_url(
        &self,
        url: String,
        updated_at: DateTime<Utc>,
    ) -> Result<Option<AgentNodeState>, AgentError> {
        validate_web_ui_seed_urls(std::slice::from_ref(&url))?;
        let canonical = canonical_bootstrap_endpoint_url(&url).ok_or_else(|| {
            AgentError::InvalidState("web UI seed URL is not an absolute URL".to_string())
        })?;
        let mut state = match self.state.write() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.web_ui_seed_urls.iter().any(|existing| {
            canonical_bootstrap_endpoint_url(existing).as_deref() == Some(canonical.as_str())
        }) {
            return Ok(None);
        }
        if state.web_ui_seed_urls.len() >= MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND {
            return Err(AgentError::InvalidState(format!(
                "web UI seed URL count exceeds maximum {MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND}"
            )));
        }
        state.web_ui_seed_urls.push(canonical);
        state.updated_at = updated_at;
        Ok(Some(state.clone()))
    }

    pub fn remove_web_ui_seed_url(
        &self,
        url: &str,
        updated_at: DateTime<Utc>,
    ) -> Result<Option<AgentNodeState>, AgentError> {
        let canonical = canonical_bootstrap_endpoint_url(url).ok_or_else(|| {
            AgentError::InvalidState("web UI seed URL is not an absolute URL".to_string())
        })?;
        let mut state = match self.state.write() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let previous_len = state.web_ui_seed_urls.len();
        state.web_ui_seed_urls.retain(|existing| {
            canonical_bootstrap_endpoint_url(existing).as_deref() != Some(canonical.as_str())
        });
        if state.web_ui_seed_urls.len() == previous_len {
            return Ok(None);
        }
        state.updated_at = updated_at;
        Ok(Some(state.clone()))
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

    pub fn remove_node_request(
        &self,
        signed_at: DateTime<Utc>,
    ) -> Result<RemoveNodeRequest, AgentError> {
        let state = self.state();
        let identity = state.identity_key_pair()?;
        let mut request = RemoveNodeRequest {
            node_id: state.node_id,
            node_signature: None,
        };
        request.node_signature = Some(identity.sign_remove_node_request(&request, signed_at)?);
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
            vpn_ip: state.vpn_ip,
            candidate_count: candidates.len(),
            candidates,
            nat_classification,
            userspace_wireguard_process,
            build: Some(current_agent_build_info()),
            state_updated_at: state.updated_at,
        }
    }

    pub async fn replace_candidates(&self, candidates: Vec<EndpointCandidate>) {
        *self.candidates.write().await = candidates;
    }

    /// Refresh the lease timestamp for locally observed candidates while the
    /// active WireGuard endpoint keeps the mapping alive.
    pub async fn refresh_candidate_observations(&self, observed_at: DateTime<Utc>) {
        let mut candidates = self.candidates.write().await;
        for candidate in candidates.iter_mut() {
            if candidate.source == CandidateSource::StunProbe {
                candidate.observed_at = observed_at;
            }
        }
    }

    pub async fn probe_stun(
        &self,
        local_bind: std::net::SocketAddr,
        stun_server: std::net::SocketAddr,
    ) -> Result<EndpointCandidate, AgentError> {
        let _refresh = self.stun_refresh.lock().await;
        let observation = UdpStunProbe
            .observe_binding(local_bind, stun_server)
            .await?;
        let candidate = self.stun_candidate_from_observation(&observation);
        let local_candidate = self.local_candidate_from_observation(&observation);
        self.replace_stun_candidates(vec![candidate.clone(), local_candidate])
            .await;
        if self.nat_classification.write().await.take().is_some() {
            self.request_heartbeat_report();
        }
        Ok(candidate)
    }

    pub async fn classify_nat(
        &self,
        local_bind: std::net::SocketAddr,
        stun_servers: Vec<std::net::SocketAddr>,
    ) -> Result<NatClassification, AgentError> {
        self.classify_nat_internal(local_bind, stun_servers, true)
            .await
    }

    pub async fn classify_nat_without_candidate_refresh(
        &self,
        local_bind: std::net::SocketAddr,
        stun_servers: Vec<std::net::SocketAddr>,
    ) -> Result<NatClassification, AgentError> {
        self.classify_nat_internal(local_bind, stun_servers, false)
            .await
    }

    /// Reconciles candidates after STUN had to use an ephemeral socket because
    /// the kernel WireGuard interface already owns the configured listen port.
    ///
    /// A globally routable no-NAT address can safely be rebuilt with the real
    /// WireGuard port. For NAT nodes, retain only a previously learned public
    /// reflexive mapping whose external address still matches, and rebuild the
    /// physical-LAN candidate with the real WireGuard port. The ephemeral STUN
    /// port is never advertised as a WireGuard endpoint.
    pub async fn refresh_candidates_for_wireguard_listen_port(
        &self,
        classification: &NatClassification,
        listen_port: u16,
    ) -> bool {
        if listen_port == 0 {
            return false;
        }

        let node_id = self.state().node_id;
        let observed_at = classification.assessed_at;
        let local_addr = SocketAddr::new(classification.local_addr.ip(), listen_port);
        if !endpoint_addr_is_usable(local_addr) {
            return false;
        }

        let public_ip = classification.publicly_reachable_ip();
        let mut refreshed = Vec::with_capacity(2);
        if let Some(public_ip) = public_ip {
            refreshed.push(EndpointCandidate {
                node_id: node_id.clone(),
                kind: EndpointCandidateKind::PublicUdp,
                addr: SocketAddr::new(public_ip, listen_port),
                observed_at,
                priority: 80,
                cost: 20,
                source: CandidateSource::StunProbe,
            });
        } else if let Some(observed_endpoint) = classification
            .observed_endpoint
            .filter(|addr| socket_addr_is_globally_routable(*addr))
        {
            let observed_ip = observed_endpoint.ip();
            let retained = self
                .candidates
                .read()
                .await
                .iter()
                .filter(|candidate| {
                    candidate.source == CandidateSource::StunProbe
                        && candidate.kind == EndpointCandidateKind::StunReflexive
                        && socket_addr_is_globally_routable(candidate.addr)
                        && candidate.addr.ip() == observed_ip
                })
                .cloned()
                .collect::<Vec<_>>();
            refreshed.extend(retained.into_iter().map(|mut candidate| {
                candidate.observed_at = observed_at;
                candidate
            }));
        }
        refreshed.push(EndpointCandidate {
            node_id,
            kind: EndpointCandidateKind::LocalUdp,
            addr: local_addr,
            observed_at,
            priority: 70,
            cost: 30,
            source: CandidateSource::StunProbe,
        });
        self.replace_stun_candidates(refreshed).await;
        public_ip.is_some()
    }

    pub async fn declare_mapped_public_ip(
        &self,
        expected_ip: IpAddr,
    ) -> Result<NatClassification, AgentError> {
        let classification = {
            let mut current = self.nat_classification.write().await;
            let classification = current.as_mut().ok_or_else(|| {
                AgentError::MappedPublic("a successful STUN classification is required".to_string())
            })?;
            classification
                .declare_mapped_public_ip(expected_ip)
                .map_err(AgentError::MappedPublic)?;
            classification.clone()
        };
        self.request_heartbeat_report();
        Ok(classification)
    }

    async fn classify_nat_internal(
        &self,
        local_bind: std::net::SocketAddr,
        stun_servers: Vec<std::net::SocketAddr>,
        refresh_candidates: bool,
    ) -> Result<NatClassification, AgentError> {
        let _refresh = self.stun_refresh.lock().await;
        if stun_servers.is_empty() {
            return Err(AgentError::Stun(StunError::InvalidResponse(
                "at least one STUN server is required for NAT classification".to_string(),
            )));
        }

        let observations = UdpStunProbe
            .observe_binding_many(local_bind, &stun_servers)
            .await?;
        let filtering_observations = match observations
            .first()
            .map(|observation| observation.stun_server)
        {
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

        if refresh_candidates {
            let refreshed_candidates = observations
                .iter()
                .flat_map(|observation| {
                    vec![
                        self.stun_candidate_from_observation(observation),
                        self.local_candidate_from_observation(observation),
                    ]
                })
                .collect();
            self.replace_stun_candidates(refreshed_candidates).await;
        }
        let changed = {
            let mut current = self.nat_classification.write().await;
            let changed = current.as_ref().is_none_or(|previous| {
                previous.connectivity_state != classification.connectivity_state
                    || previous.mapping_behavior != classification.mapping_behavior
                    || previous.filtering_behavior != classification.filtering_behavior
                    || previous.strategy != classification.strategy
                    || previous.local_addr.ip() != classification.local_addr.ip()
                    || previous.observed_endpoint.map(|addr| addr.ip())
                        != classification.observed_endpoint.map(|addr| addr.ip())
                    || previous.public_state_is_supported()
                        != classification.public_state_is_supported()
            });
            *current = Some(classification.clone());
            changed
        };
        if changed {
            self.request_heartbeat_report();
        }

        Ok(classification)
    }

    pub async fn clear_nat_classification(&self) -> bool {
        let removed = self.nat_classification.write().await.take().is_some();
        let mut candidates = self.candidates.write().await;
        let previous_len = candidates.len();
        candidates.retain(|candidate| candidate.source != CandidateSource::StunProbe);
        let candidates_removed = candidates.len() != previous_len;
        drop(candidates);
        if removed || candidates_removed {
            self.request_heartbeat_report();
        }
        removed || candidates_removed
    }

    async fn replace_stun_candidates(&self, refreshed: Vec<EndpointCandidate>) {
        let mut deduplicated = Vec::<EndpointCandidate>::with_capacity(refreshed.len());
        for candidate in refreshed {
            if let Some(existing) = deduplicated.iter_mut().find(|existing| {
                existing.source == CandidateSource::StunProbe
                    && existing.kind == candidate.kind
                    && existing.addr == candidate.addr
            }) {
                if candidate.observed_at >= existing.observed_at {
                    *existing = candidate;
                }
            } else {
                deduplicated.push(candidate);
            }
        }

        let mut candidates = self.candidates.write().await;
        candidates.retain(|candidate| candidate.source != CandidateSource::StunProbe);
        candidates.extend(deduplicated);
    }

    fn stun_candidate_from_observation(
        &self,
        observation: &NatProbeObservation,
    ) -> EndpointCandidate {
        let kind = if observation.reflexive_addr == observation.local_addr
            && socket_addr_is_globally_routable(observation.reflexive_addr)
        {
            EndpointCandidateKind::PublicUdp
        } else {
            EndpointCandidateKind::StunReflexive
        };
        EndpointCandidate {
            node_id: self.state().node_id,
            kind,
            addr: observation.reflexive_addr,
            observed_at: observation.observed_at,
            priority: 80,
            cost: 20,
            source: CandidateSource::StunProbe,
        }
    }

    fn local_candidate_from_observation(
        &self,
        observation: &NatProbeObservation,
    ) -> EndpointCandidate {
        EndpointCandidate {
            node_id: self.state().node_id,
            kind: EndpointCandidateKind::LocalUdp,
            addr: observation.local_addr,
            observed_at: observation.observed_at,
            priority: 70,
            cost: 30,
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

    pub async fn path_change_events_with_counts(&self) -> (Vec<PathChangeEvent>, u64, u64) {
        let events = self
            .path_change_events
            .read()
            .await
            .iter()
            .cloned()
            .collect();
        (
            events,
            self.path_change_event_total_count.load(Ordering::Relaxed),
            self.path_change_event_dropped_count.load(Ordering::Relaxed),
        )
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
        let path_quality_observations = self.path_quality_observations.read().await;
        let latest_peer_map = self.latest_peer_map.read().await;
        let peer_map_peer_count = latest_peer_map
            .as_ref()
            .map(|peer_map| peer_map.peers.len())
            .unwrap_or_default();
        let peer_map_route_count = latest_peer_map
            .as_ref()
            .map(|peer_map| peer_map.peers.iter().map(|peer| peer.routes.len()).sum())
            .unwrap_or_default();
        let peer_map_generated_at = latest_peer_map
            .as_ref()
            .map(|peer_map| peer_map.generated_at);
        let mut path_state_counts = BTreeMap::<PathState, usize>::new();
        for path in path_state.values() {
            *path_state_counts.entry(path.selected_state).or_default() += 1;
        }

        let state = self.state();
        AgentMetricsResponse {
            node_id: state.node_id,
            candidate_count: candidates.len(),
            peer_map_synced: latest_peer_map.is_some(),
            peer_map_peer_count,
            peer_map_route_count,
            peer_map_generated_at,
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
            path_change_event_total_count: self
                .path_change_event_total_count
                .load(Ordering::Relaxed),
            path_change_event_dropped_count: self
                .path_change_event_dropped_count
                .load(Ordering::Relaxed),
            path_state_counts: PATH_STATE_METRIC_ORDER
                .into_iter()
                .map(|state| PathStateCount {
                    state,
                    count: *path_state_counts.get(&state).unwrap_or(&0),
                })
                .collect(),
            lazy_connect: lazy_connect.metrics(),
            path_probe_record_count: self.path_probe_record_count.load(Ordering::Relaxed),
            direct_path_probe_started_count: self
                .direct_path_probe_started_count
                .load(Ordering::Relaxed),
            direct_path_probe_confirmed_count: self
                .direct_path_probe_confirmed_count
                .load(Ordering::Relaxed),
            direct_path_probe_timeout_count: self
                .direct_path_probe_timeout_count
                .load(Ordering::Relaxed),
            path_quality_observation_count: path_quality_observations.len(),
            peer_probe_measurement_count: self.peer_probe_measurement_count.load(Ordering::Relaxed),
            peer_probe_failure_count: self.peer_probe_failure_count.load(Ordering::Relaxed),
            peer_probe_request_sent_count: self
                .peer_probe_request_sent_count
                .load(Ordering::Relaxed),
            peer_probe_response_received_count: self
                .peer_probe_response_received_count
                .load(Ordering::Relaxed),
            peer_probe_timeout_count: self.peer_probe_timeout_count.load(Ordering::Relaxed),
            peer_probe_responder_request_count: self
                .peer_probe_responder_request_count
                .load(Ordering::Relaxed),
            peer_probe_responder_invalid_count: self
                .peer_probe_responder_invalid_count
                .load(Ordering::Relaxed),
            peer_probe_responder_unknown_source_count: self
                .peer_probe_responder_unknown_source_count
                .load(Ordering::Relaxed),
            peer_probe_responder_rate_limited_count: self
                .peer_probe_responder_rate_limited_count
                .load(Ordering::Relaxed),
            peer_probe_responder_send_failure_count: self
                .peer_probe_responder_send_failure_count
                .load(Ordering::Relaxed),
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

    pub async fn wireguard_endpoint_update_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.wireguard_endpoint_update.lock().await
    }

    pub fn peer_map_sync_notifier(&self) -> Arc<tokio::sync::Notify> {
        self.peer_map_sync_notify.clone()
    }

    pub fn heartbeat_report_notifier(&self) -> Arc<tokio::sync::Notify> {
        self.heartbeat_report_notify.clone()
    }

    pub fn signal_path_notifier(&self) -> Arc<tokio::sync::Notify> {
        self.signal_path_notify.clone()
    }

    fn request_peer_map_sync(&self) {
        self.peer_map_sync_notify.notify_one();
    }

    fn request_lazy_connect_sync(&self) {
        self.request_lazy_connect_path_sync();
        self.request_heartbeat_report();
    }

    fn request_lazy_connect_path_sync(&self) {
        self.request_peer_map_sync();
        self.signal_path_notify.notify_one();
    }

    fn request_heartbeat_report(&self) {
        self.heartbeat_report_notify.notify_one();
    }

    pub async fn peer_quality_probe_targets(&self) -> Vec<PeerQualityProbeTarget> {
        let Ok(peer_map) = self.peer_map_snapshot().await else {
            return Vec::new();
        };
        let local_node = self.state().node_id;
        let mut targets = Vec::new();
        for peer in peer_map.peers {
            if peer.node_id == local_node || !self.should_connect_peer(&peer).await {
                continue;
            }
            let Some(path) = self.path_record_for_peer(&peer.node_id).await else {
                continue;
            };
            if path.selected_state == PathState::Unreachable {
                continue;
            }
            let wake_passive_peer = self
                .recent_local_peer_activity(&peer.node_id, Utc::now())
                .await
                .is_some();
            targets.push(PeerQualityProbeTarget {
                peer,
                path,
                wake_passive_peer,
            });
        }
        targets
    }

    pub async fn record_peer_probe_measurement(
        &self,
        target: &PeerQualityProbeTarget,
        measurement: &PeerProbeMeasurement,
        observed_at: DateTime<Utc>,
    ) -> Result<Option<PathQualityObservation>, AgentError> {
        self.peer_probe_request_sent_count
            .fetch_add(u64::from(measurement.sample_count()), Ordering::Relaxed);
        self.peer_probe_response_received_count.fetch_add(
            u64::from(measurement.successful_sample_count()),
            Ordering::Relaxed,
        );
        self.peer_probe_timeout_count
            .fetch_add(u64::from(measurement.timeout_count()), Ordering::Relaxed);

        let Some(current_path) = self.path_record_for_peer(&target.peer.node_id).await else {
            return Ok(None);
        };
        if !peer_probe::path_records_same_path(&current_path, &target.path) {
            return Ok(None);
        }
        let previous = self
            .path_quality_observations
            .read()
            .await
            .get(&target.peer.node_id)
            .cloned();
        let observation =
            measurement.to_path_observation(&current_path, previous.as_ref(), observed_at)?;
        let relay_path_failed = current_path.selected_state == PathState::Relay
            && measurement.successful_sample_count() == 0;
        observation
            .metrics
            .validate()
            .map_err(|error| AgentError::PeerProbe(error.to_string()))?;
        self.path_quality_observations
            .write()
            .await
            .insert(target.peer.node_id.clone(), observation.clone());
        self.peer_probe_measurement_count
            .fetch_add(1, Ordering::Relaxed);
        if relay_path_failed {
            self.signal_path_notify.notify_one();
        }
        Ok(Some(observation))
    }

    pub async fn path_quality_observation_for_peer(
        &self,
        peer: &NodeId,
        now: DateTime<Utc>,
        max_age: Duration,
    ) -> Option<PathQualityObservation> {
        let observation = self
            .path_quality_observations
            .read()
            .await
            .get(peer)
            .cloned()?;
        let path = self.path_record_for_peer(peer).await?;
        if !peer_probe::path_matches_observation(&path, &observation) {
            return None;
        }
        let fresh = now
            .signed_duration_since(observation.observed_at)
            .to_std()
            .map(|age| age <= max_age)
            .unwrap_or(true);
        fresh.then_some(observation)
    }

    pub async fn peer_node_for_vpn_ip(&self, vpn_ip: IpAddr) -> Option<NodeId> {
        self.latest_peer_map
            .read()
            .await
            .as_ref()?
            .peers
            .iter()
            .find(|peer| peer.vpn_ip.0 == vpn_ip)
            .map(|peer| peer.node_id.clone())
    }

    pub fn record_peer_probe_failure(&self) {
        self.peer_probe_failure_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_peer_probe_responder_request(&self) {
        self.peer_probe_responder_request_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_peer_probe_responder_invalid(&self) {
        self.peer_probe_responder_invalid_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_peer_probe_responder_unknown_source(&self) {
        self.peer_probe_responder_unknown_source_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_peer_probe_responder_rate_limited(&self) {
        self.peer_probe_responder_rate_limited_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_peer_probe_responder_send_failure(&self) {
        self.peer_probe_responder_send_failure_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub async fn pending_direct_path_probe(&self, peer: &NodeId) -> Option<PendingDirectPathProbe> {
        self.pending_direct_path_probes
            .read()
            .await
            .get(peer)
            .cloned()
    }

    pub async fn upsert_pending_direct_path_probe(
        &self,
        probe: PendingDirectPathProbe,
    ) -> Result<(), AgentError> {
        let local_node = self.state().node_id;
        let peer = probe.selected_candidate.node_id.clone();
        if !probe.selected_state.is_direct() {
            return Err(AgentError::PathProbeRejected(
                "pending direct path probe requires a direct path state".to_string(),
            ));
        }
        if probe.expires_at <= probe.started_at {
            return Err(AgentError::PathProbeRejected(
                "pending direct path probe expiry must be after its start time".to_string(),
            ));
        }
        if probe.endpoint_observed_at.is_some_and(|observed_at| {
            observed_at < probe.started_at || observed_at >= probe.expires_at
        }) {
            return Err(AgentError::PathProbeRejected(
                "pending direct path probe endpoint observation must be within its active window"
                    .to_string(),
            ));
        }
        validate_path_state_shape(
            &local_node,
            &peer,
            probe.selected_state,
            Some(&probe.selected_candidate),
            None,
            "pending direct path probe",
        )
        .map_err(AgentError::PathProbeRejected)?;
        let endpoint_changed = {
            let mut pending_probes = self.pending_direct_path_probes.write().await;
            let endpoint_changed = pending_probes.get(&peer).is_none_or(|current| {
                current.selected_state != probe.selected_state
                    || current.selected_candidate != probe.selected_candidate
            });
            pending_probes.insert(peer, probe);
            endpoint_changed
        };
        if endpoint_changed {
            self.request_peer_map_sync();
        }
        Ok(())
    }

    pub async fn remove_pending_direct_path_probe(
        &self,
        peer: &NodeId,
    ) -> Option<PendingDirectPathProbe> {
        let removed = self.pending_direct_path_probes.write().await.remove(peer);
        if removed.is_some() {
            self.request_peer_map_sync();
        }
        removed
    }

    pub async fn direct_path_probe_retry_after(&self, peer: &NodeId) -> Option<DateTime<Utc>> {
        self.direct_path_probe_retry_after
            .read()
            .await
            .get(peer)
            .copied()
    }

    pub async fn defer_direct_path_probe_retry(&self, peer: NodeId, retry_after: DateTime<Utc>) {
        self.direct_path_probe_retry_after
            .write()
            .await
            .entry(peer)
            .and_modify(|current| *current = (*current).max(retry_after))
            .or_insert(retry_after);
    }

    pub async fn clear_direct_path_probe_retry(&self, peer: &NodeId) {
        self.direct_path_probe_retry_after
            .write()
            .await
            .remove(peer);
    }

    pub fn record_direct_path_probe_started(&self) {
        self.direct_path_probe_started_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_direct_path_probe_confirmed(&self) {
        self.direct_path_probe_confirmed_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_direct_path_probe_timeout(&self) {
        self.direct_path_probe_timeout_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub async fn record_path_probe(
        &self,
        request: AgentPathProbeRequest,
        recorded_at: DateTime<Utc>,
    ) -> Result<PathRecord, AgentError> {
        let local_node = self.state().node_id;
        validate_path_probe_request(&request, &local_node)?;
        let path = PathRecord {
            key: ipars_types::PeerPathKey::new(local_node, request.peer),
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
        self.upsert_path_state(path.clone()).await?;
        self.path_probe_record_count.fetch_add(1, Ordering::Relaxed);
        Ok(path)
    }

    pub async fn upsert_path_state(&self, record: PathRecord) -> Result<(), AgentError> {
        let _endpoint_update_guard = self.wireguard_endpoint_update_guard().await;
        let local_node = self.state().node_id;
        validate_path_record(&record, &local_node)?;
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
            self.invalidate_overlay_shortcut_snapshot();
        }
        let path_changed = path_change_event(previous.as_ref(), &record);
        let should_report_path_change = path_changed
            .as_ref()
            .is_some_and(|event| event.kind != PathChangeKind::ScoreChanged);
        if let Some(event) = path_changed {
            let mut events = self.path_change_events.write().await;
            if events.len() >= MAX_PATH_CHANGE_EVENTS {
                events.pop_front();
                self.path_change_event_dropped_count
                    .fetch_add(1, Ordering::Relaxed);
            }
            events.push_back(event);
            self.path_change_event_total_count
                .fetch_add(1, Ordering::Relaxed);
        }
        if selected_state != PathState::Relay {
            self.remove_relay_session(&remote).await;
        }
        if should_report_path_change {
            self.request_heartbeat_report();
        }
        Ok(())
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
            self.request_peer_map_sync();
        }
        expired
    }

    pub async fn remove_relay_session(&self, peer: &NodeId) -> Option<RelaySessionState> {
        let removed = self.relay_sessions.write().await.remove(peer);
        self.remove_relay_forwarder_endpoint(peer).await;
        removed
    }

    pub async fn upsert_relay_forwarder_endpoint(&self, peer: NodeId, endpoint: SocketAddr) {
        let endpoint_changed = self
            .relay_forwarder_endpoints
            .write()
            .await
            .insert(peer, endpoint)
            != Some(endpoint);
        if endpoint_changed {
            self.request_peer_map_sync();
        }
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

    pub async fn relay_forwarder_metrics_for_peer(
        &self,
        peer: &NodeId,
    ) -> Option<AgentRelayForwarderMetrics> {
        self.relay_forwarder_metrics
            .read()
            .await
            .get(peer)
            .map(|metrics| metrics.snapshot())
    }

    pub async fn remove_relay_forwarder_endpoint(&self, peer: &NodeId) -> Option<SocketAddr> {
        self.relay_forwarder_metrics.write().await.remove(peer);
        let removed = self.relay_forwarder_endpoints.write().await.remove(peer);
        if removed.is_some() {
            self.request_peer_map_sync();
        }
        removed
    }

    pub async fn relay_forwarder_endpoints(&self) -> BTreeMap<NodeId, SocketAddr> {
        self.relay_forwarder_endpoints.read().await.clone()
    }

    pub async fn upsert_overlay_forwarder_endpoint(&self, peer: NodeId, endpoint: SocketAddr) {
        let endpoint_changed = self
            .overlay_forwarder_endpoints
            .write()
            .await
            .insert(peer, endpoint)
            != Some(endpoint);
        if endpoint_changed {
            self.request_peer_map_sync();
        }
    }

    pub async fn overlay_forwarder_endpoint(&self, peer: &NodeId) -> Option<SocketAddr> {
        self.overlay_forwarder_endpoints
            .read()
            .await
            .get(peer)
            .copied()
    }

    pub async fn remove_overlay_forwarder_endpoint(&self, peer: &NodeId) -> Option<SocketAddr> {
        let removed = self.overlay_forwarder_endpoints.write().await.remove(peer);
        if removed.is_some() {
            self.request_peer_map_sync();
        }
        removed
    }

    pub async fn overlay_forwarder_endpoints(&self) -> BTreeMap<NodeId, SocketAddr> {
        self.overlay_forwarder_endpoints.read().await.clone()
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
        let was_active = lazy_connect.last_used.contains_key(&peer);
        let was_pinned = lazy_connect.is_pinned(&peer);
        lazy_connect.record_activity(peer.clone(), at);
        if pin {
            lazy_connect.pin_peer(peer.clone());
        }
        let pinned = lazy_connect.is_pinned(&peer);
        drop(lazy_connect);
        self.invalidate_overlay_shortcut_snapshot();
        if !was_active || (pinned && !was_pinned) {
            self.request_lazy_connect_sync();
        }
        pinned
    }

    pub async fn record_remote_peer_activity(&self, peer: NodeId, observed_at: DateTime<Utc>) {
        if peer == self.state().node_id {
            return;
        }
        let mut lazy_connect = self.lazy_connect.write().await;
        let changed = lazy_connect.record_remote_activity(peer, observed_at);
        drop(lazy_connect);
        if changed {
            self.invalidate_overlay_shortcut_snapshot();
            self.request_lazy_connect_path_sync();
        }
    }

    pub async fn wake_passive_peer_from_probe(
        &self,
        peer: NodeId,
        observed_at: DateTime<Utc>,
    ) -> bool {
        let mut lazy_connect = self.lazy_connect.write().await;
        let changed = lazy_connect.record_remote_activity_if_idle(peer, observed_at);
        drop(lazy_connect);
        if changed {
            self.invalidate_overlay_shortcut_snapshot();
            self.request_lazy_connect_path_sync();
        }
        changed
    }

    pub async fn recent_local_peer_activity(
        &self,
        peer: &NodeId,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        self.lazy_connect
            .read()
            .await
            .recent_local_activity(peer, now)
    }

    pub async fn recent_local_peer_activities(
        &self,
        now: DateTime<Utc>,
    ) -> Vec<(NodeId, DateTime<Utc>, bool)> {
        self.lazy_connect.read().await.recent_local_activities(now)
    }

    pub async fn cluster_policy_snapshot(&self) -> ClusterPolicy {
        self.lazy_connect.read().await.policy.clone()
    }

    pub async fn replace_internal_packet_flow_udp_ports(&self, ports: BTreeSet<u16>) {
        *self.internal_packet_flow_udp_ports.write().await = ports;
    }

    pub async fn has_packet_flow_destination_match(&self, destinations: &[IpAddr]) -> bool {
        let lazy_connect = self.lazy_connect.read().await;
        destinations.iter().any(|destination| {
            lazy_connect
                .resolve_packet_flow_destination(*destination)
                .is_some()
        })
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
        if self.local_vpn_destination(destination) {
            self.record_packet_flow_filtered(AgentPacketFlowDropReason::NoOverlayMatch);
            return None;
        }
        self.packet_flow_observation_count
            .fetch_add(1, Ordering::Relaxed);
        self.packet_flow_classification_counter(observation.classification())
            .fetch_add(1, Ordering::Relaxed);
        self.packet_flow_application_counter(observation.application())
            .fetch_add(1, Ordering::Relaxed);
        if observation.protocol == Some(TransportProtocol::Udp) {
            let internal_ports = self.internal_packet_flow_udp_ports.read().await;
            if observation
                .source_port
                .into_iter()
                .chain(observation.destination_port)
                .any(|port| internal_ports.contains(&port))
            {
                drop(internal_ports);
                self.record_packet_flow_filtered(AgentPacketFlowDropReason::InternalControlTraffic);
                return None;
            }
        }
        let overlay_destination = self.overlay_destination_is_resolvable(destination).await;
        let mut lazy_connect = self.lazy_connect.write().await;
        let Some(mut matched) = lazy_connect.resolve_packet_flow_destination(destination) else {
            self.packet_flow_unmatched_count
                .fetch_add(1, Ordering::Relaxed);
            drop(lazy_connect);
            if overlay_destination {
                let queued = self
                    .pending_overlay_destinations
                    .lock()
                    .await
                    .enqueue(destination);
                if queued {
                    self.request_lazy_connect_path_sync();
                }
            } else {
                self.record_packet_flow_filtered(AgentPacketFlowDropReason::NoOverlayMatch);
            }
            return None;
        };
        let was_active = lazy_connect.last_used.contains_key(&matched.peer);
        let was_pinned = lazy_connect.is_pinned(&matched.peer);
        lazy_connect.record_activity(matched.peer.clone(), at);
        if let Some(route) = matched.route {
            self.resolved_overlay_paths
                .write()
                .await
                .touch_exact_route(&matched.peer, route, at);
        }
        if pin {
            lazy_connect.pin_peer(matched.peer.clone());
        }
        matched.pinned = lazy_connect.is_pinned(&matched.peer);
        self.packet_flow_match_count.fetch_add(1, Ordering::Relaxed);
        drop(lazy_connect);
        let needs_overlay_path =
            overlay_destination && !self.has_current_overlay_route_to_peer(&matched.peer).await;
        if needs_overlay_path {
            let queued = self
                .pending_overlay_destinations
                .lock()
                .await
                .enqueue(destination);
            if queued {
                self.request_lazy_connect_path_sync();
            }
        }
        self.invalidate_overlay_shortcut_snapshot();
        if !was_active || (matched.pinned && !was_pinned) {
            self.request_lazy_connect_sync();
        }
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
            AgentPacketFlowDropReason::InternalControlTraffic => {
                &self.packet_flow_filtered_internal_control_traffic_count
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
            AgentPacketFlowApplication::Dhcp => &self.packet_flow_application_dhcp_count,
            AgentPacketFlowApplication::Http => &self.packet_flow_application_http_count,
            AgentPacketFlowApplication::Https => &self.packet_flow_application_https_count,
            AgentPacketFlowApplication::Ssh => &self.packet_flow_application_ssh_count,
            AgentPacketFlowApplication::Ldap => &self.packet_flow_application_ldap_count,
            AgentPacketFlowApplication::Smb => &self.packet_flow_application_smb_count,
            AgentPacketFlowApplication::Nfs => &self.packet_flow_application_nfs_count,
            AgentPacketFlowApplication::Rdp => &self.packet_flow_application_rdp_count,
            AgentPacketFlowApplication::Vnc => &self.packet_flow_application_vnc_count,
            AgentPacketFlowApplication::Ftp => &self.packet_flow_application_ftp_count,
            AgentPacketFlowApplication::Tftp => &self.packet_flow_application_tftp_count,
            AgentPacketFlowApplication::Rsync => &self.packet_flow_application_rsync_count,
            AgentPacketFlowApplication::Smtp => &self.packet_flow_application_smtp_count,
            AgentPacketFlowApplication::Imap => &self.packet_flow_application_imap_count,
            AgentPacketFlowApplication::Pop3 => &self.packet_flow_application_pop3_count,
            AgentPacketFlowApplication::Sip => &self.packet_flow_application_sip_count,
            AgentPacketFlowApplication::Kerberos => &self.packet_flow_application_kerberos_count,
            AgentPacketFlowApplication::Ntp => &self.packet_flow_application_ntp_count,
            AgentPacketFlowApplication::Radius => &self.packet_flow_application_radius_count,
            AgentPacketFlowApplication::Tacacs => &self.packet_flow_application_tacacs_count,
            AgentPacketFlowApplication::Bgp => &self.packet_flow_application_bgp_count,
            AgentPacketFlowApplication::Bfd => &self.packet_flow_application_bfd_count,
            AgentPacketFlowApplication::IparsControlPlane => {
                &self.packet_flow_application_ipars_control_plane_count
            }
            AgentPacketFlowApplication::IparsSignal => {
                &self.packet_flow_application_ipars_signal_count
            }
            AgentPacketFlowApplication::IparsAgent => {
                &self.packet_flow_application_ipars_agent_count
            }
            AgentPacketFlowApplication::IparsRelay => {
                &self.packet_flow_application_ipars_relay_count
            }
            AgentPacketFlowApplication::Stun => &self.packet_flow_application_stun_count,
            AgentPacketFlowApplication::Turn => &self.packet_flow_application_turn_count,
            AgentPacketFlowApplication::KubernetesApi => {
                &self.packet_flow_application_kubernetes_api_count
            }
            AgentPacketFlowApplication::Kubelet => &self.packet_flow_application_kubelet_count,
            AgentPacketFlowApplication::DockerApi => &self.packet_flow_application_docker_api_count,
            AgentPacketFlowApplication::Cri => &self.packet_flow_application_cri_count,
            AgentPacketFlowApplication::Containerd => {
                &self.packet_flow_application_containerd_count
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
            AgentPacketFlowApplication::Couchbase => &self.packet_flow_application_couchbase_count,
            AgentPacketFlowApplication::Prometheus => {
                &self.packet_flow_application_prometheus_count
            }
            AgentPacketFlowApplication::OpenTelemetry => {
                &self.packet_flow_application_opentelemetry_count
            }
            AgentPacketFlowApplication::Grafana => &self.packet_flow_application_grafana_count,
            AgentPacketFlowApplication::Statsd => &self.packet_flow_application_statsd_count,
            AgentPacketFlowApplication::Graphite => &self.packet_flow_application_graphite_count,
            AgentPacketFlowApplication::Collectd => &self.packet_flow_application_collectd_count,
            AgentPacketFlowApplication::Syslog => &self.packet_flow_application_syslog_count,
            AgentPacketFlowApplication::Snmp => &self.packet_flow_application_snmp_count,
            AgentPacketFlowApplication::Jaeger => &self.packet_flow_application_jaeger_count,
            AgentPacketFlowApplication::Loki => &self.packet_flow_application_loki_count,
            AgentPacketFlowApplication::Tempo => &self.packet_flow_application_tempo_count,
            AgentPacketFlowApplication::Zipkin => &self.packet_flow_application_zipkin_count,
            AgentPacketFlowApplication::Grpc => &self.packet_flow_application_grpc_count,
            AgentPacketFlowApplication::Kafka => &self.packet_flow_application_kafka_count,
            AgentPacketFlowApplication::Pulsar => &self.packet_flow_application_pulsar_count,
            AgentPacketFlowApplication::Nats => &self.packet_flow_application_nats_count,
            AgentPacketFlowApplication::Mqtt => &self.packet_flow_application_mqtt_count,
            AgentPacketFlowApplication::Coap => &self.packet_flow_application_coap_count,
            AgentPacketFlowApplication::Amqp => &self.packet_flow_application_amqp_count,
            AgentPacketFlowApplication::Cassandra => &self.packet_flow_application_cassandra_count,
            AgentPacketFlowApplication::MongoDb => &self.packet_flow_application_mongodb_count,
            AgentPacketFlowApplication::Neo4j => &self.packet_flow_application_neo4j_count,
            AgentPacketFlowApplication::Elasticsearch => {
                &self.packet_flow_application_elasticsearch_count
            }
            AgentPacketFlowApplication::OpenSearch => {
                &self.packet_flow_application_opensearch_count
            }
            AgentPacketFlowApplication::Solr => &self.packet_flow_application_solr_count,
            AgentPacketFlowApplication::Git => &self.packet_flow_application_git_count,
            AgentPacketFlowApplication::Ike => &self.packet_flow_application_ike_count,
            AgentPacketFlowApplication::Ipsec => &self.packet_flow_application_ipsec_count,
            AgentPacketFlowApplication::IpTunnel => &self.packet_flow_application_ip_tunnel_count,
            AgentPacketFlowApplication::Gre => &self.packet_flow_application_gre_count,
            AgentPacketFlowApplication::Vxlan => &self.packet_flow_application_vxlan_count,
            AgentPacketFlowApplication::Geneve => &self.packet_flow_application_geneve_count,
            AgentPacketFlowApplication::WireGuard => &self.packet_flow_application_wireguard_count,
            AgentPacketFlowApplication::OpenVpn => &self.packet_flow_application_openvpn_count,
            AgentPacketFlowApplication::Icmp => &self.packet_flow_application_icmp_count,
        }
    }

    pub async fn replace_local_advertised_routes(
        &self,
        routes: Vec<Route>,
    ) -> Result<(), AgentError> {
        let local_node = self.state().node_id;
        validate_local_advertised_routes(&local_node, &routes)?;
        *self.local_advertised_routes.write().await = routes;
        Ok(())
    }

    pub async fn local_advertised_routes(&self) -> Vec<Route> {
        self.local_advertised_routes.read().await.clone()
    }

    pub async fn observe_peer_map_for_lazy_connect(&self, peers: &[NodeRecord]) {
        let local_route_cidrs = self
            .local_advertised_routes
            .read()
            .await
            .iter()
            .map(|route| route.cidr)
            .collect::<BTreeSet<_>>();
        let peer_ids = peers
            .iter()
            .map(|peer| peer.node_id.clone())
            .collect::<BTreeSet<_>>();
        let active_epochs = self.active_overlay_topology_epochs().await;
        let current_routing_epoch = self.current_overlay_routing_epoch().await;
        let direct_peer_ids = self
            .latest_neighbor_map
            .read()
            .await
            .as_ref()
            .map(|neighbor_map| {
                neighbor_map
                    .neighbors
                    .iter()
                    .map(|neighbor| neighbor.node.node_id.clone())
                    .chain(
                        neighbor_map
                            .pinned_peers
                            .iter()
                            .map(|peer| peer.node_id.clone()),
                    )
                    .collect::<BTreeSet<_>>()
            });
        let resolved_peer_ids = self
            .resolved_overlay_paths
            .read()
            .await
            .paths
            .iter()
            .filter(|(_, lease)| {
                active_epochs.contains(&lease.path.topology_epoch)
                    && Some(lease.path.routing_epoch) == current_routing_epoch
            })
            .map(|(peer, _)| peer.clone())
            .collect::<BTreeSet<_>>();
        let mut lazy_connect = self.lazy_connect.write().await;
        lazy_connect.retain_observed_peers(&peer_ids);
        for peer in peers {
            let is_direct_peer = direct_peer_ids
                .as_ref()
                .is_none_or(|direct_peer_ids| direct_peer_ids.contains(&peer.node_id));
            if resolved_peer_ids.contains(&peer.node_id) || !is_direct_peer {
                lazy_connect.observe_overlay_shortcut(peer, &local_route_cidrs);
            } else {
                lazy_connect.observe_peer(peer, &local_route_cidrs);
            }
        }
        drop(lazy_connect);
        self.invalidate_overlay_shortcut_snapshot();
    }

    pub async fn record_neighbor_map_snapshot(
        &self,
        neighbor_map: NeighborMap,
    ) -> Result<(), AgentError> {
        let _update_guard = self.neighbor_map_update.lock().await;
        neighbor_map
            .validate()
            .map_err(|error| AgentError::InvalidState(error.to_string()))?;
        let local_node = self.state().node_id;
        if neighbor_map.node_id != local_node {
            return Err(AgentError::InvalidState(format!(
                "neighbor map node {} does not match local node {local_node}",
                neighbor_map.node_id
            )));
        }
        let previous = self.latest_neighbor_map.read().await.clone();
        if let Some(current) = previous.as_ref().filter(|current| {
            current.cluster_id == neighbor_map.cluster_id && current.node_id == neighbor_map.node_id
        }) {
            if neighbor_map.routing_epoch < current.routing_epoch {
                return Err(AgentError::InvalidState(format!(
                    "neighbor map routing epoch {} is older than the accepted routing epoch {}",
                    neighbor_map.routing_epoch, current.routing_epoch
                )));
            }
            if neighbor_map.generated_at < current.generated_at {
                return Err(AgentError::InvalidState(format!(
                    "neighbor map generated at {} is older than the accepted map generated at {}",
                    neighbor_map.generated_at, current.generated_at
                )));
            }
            if neighbor_map.generated_at == current.generated_at
                && (neighbor_map.topology_epoch != current.topology_epoch
                    || neighbor_map.routing_epoch != current.routing_epoch)
            {
                return Err(AgentError::InvalidState(format!(
                    "neighbor map generated at {} conflicts with accepted topology/routing epochs \
                     {}/{}",
                    neighbor_map.generated_at, current.topology_epoch, current.routing_epoch
                )));
            }
        }
        let shortcut_update =
            OverlayShortcutGenerationUpdate::begin(&self.overlay_shortcut_generation);
        let topology_changed = previous
            .as_ref()
            .is_some_and(|current| current.topology_epoch != neighbor_map.topology_epoch);
        let routing_changed = previous
            .as_ref()
            .is_some_and(|current| current.routing_epoch != neighbor_map.routing_epoch);
        let now = Instant::now();
        let (active_epochs, retained_topology_pins) = {
            let mut retained = self.retained_neighbor_maps.write().await;
            retained.retain(|previous| previous.expires_at > now);
            if topology_changed {
                if let Some(previous) = previous.as_ref() {
                    retained.retain(|retained| retained.topology_epoch != previous.topology_epoch);
                    retained.push_back(RetainedNeighborMap {
                        topology_epoch: previous.topology_epoch,
                        neighbors: previous.neighbors.clone(),
                        expires_at: now + OVERLAY_TOPOLOGY_MIGRATION_GRACE,
                    });
                    while retained.len() > MAX_RETAINED_OVERLAY_TOPOLOGIES {
                        retained.pop_front();
                    }
                }
            }

            let active_epochs = std::iter::once(neighbor_map.topology_epoch)
                .chain(retained.iter().map(|previous| previous.topology_epoch))
                .collect::<BTreeSet<_>>();
            let retained_topology_pins = retained
                .iter()
                .flat_map(|previous| previous.neighbors.iter())
                .map(|neighbor| neighbor.node.node_id.clone())
                .collect::<BTreeSet<_>>();
            (active_epochs, retained_topology_pins)
        };

        let backbone_peer_ids = neighbor_map
            .neighbors
            .iter()
            .map(|neighbor| neighbor.node.node_id.clone())
            .collect::<BTreeSet<_>>();
        let topology_pins = backbone_peer_ids
            .iter()
            .cloned()
            .chain(
                neighbor_map
                    .pinned_peers
                    .iter()
                    .map(|peer| peer.node_id.clone()),
            )
            .chain(retained_topology_pins)
            .collect::<BTreeSet<_>>();
        let on_demand_peer_limit = usize::from(neighbor_map.on_demand_peer_limit);
        {
            let mut lazy_connect = self.lazy_connect.write().await;
            lazy_connect.replace_topology_pins(topology_pins);
            lazy_connect.replace_on_demand_peer_limit(neighbor_map.on_demand_peer_limit);
        }

        let (destinations_to_refresh, expired_peers) = {
            let mut resolved = self.resolved_overlay_paths.write().await;
            let destinations_to_refresh = if topology_changed || routing_changed {
                resolved
                    .paths
                    .values()
                    .flat_map(ResolvedOverlayPathLease::refresh_destinations)
                    .collect::<BTreeSet<_>>()
            } else {
                BTreeSet::new()
            };
            let expired_peers = if routing_changed {
                resolved.paths.keys().cloned().collect::<BTreeSet<_>>()
            } else {
                resolved
                    .paths
                    .iter()
                    .filter(|(_, lease)| !active_epochs.contains(&lease.path.topology_epoch))
                    .map(|(peer, _)| peer.clone())
                    .collect::<BTreeSet<_>>()
            };
            for peer in &expired_peers {
                resolved.remove_peer(peer);
            }
            (destinations_to_refresh, expired_peers)
        };
        if !destinations_to_refresh.is_empty() {
            self.pending_overlay_destinations
                .lock()
                .await
                .requeue_all_prioritized(destinations_to_refresh);
        }
        if !expired_peers.is_empty() {
            let mut lazy_connect = self.lazy_connect.write().await;
            for peer in &expired_peers {
                lazy_connect.remove_activity(peer);
                lazy_connect.remove_observed_peer(peer);
            }
        }
        let budget_evicted_peers = {
            let mut lazy_connect = self.lazy_connect.write().await;
            let mut resolved = self.resolved_overlay_paths.write().await;
            trim_on_demand_overlay_paths(
                &mut resolved,
                &mut lazy_connect,
                &backbone_peer_ids,
                on_demand_peer_limit,
                None,
            )
        };
        let removed_peers = expired_peers
            .union(&budget_evicted_peers)
            .cloned()
            .collect::<BTreeSet<_>>();
        if !removed_peers.is_empty() {
            self.overlay_forwarder_endpoints
                .write()
                .await
                .retain(|peer, _| !removed_peers.contains(peer));
        }
        *self.latest_neighbor_map.write().await = Some(neighbor_map);
        drop(shortcut_update);
        Ok(())
    }

    pub async fn neighbor_map_snapshot(&self) -> Option<NeighborMap> {
        self.latest_neighbor_map.read().await.clone()
    }

    pub async fn retained_overlay_neighbors(&self) -> Vec<NodeRecord> {
        let current_topology_pins = self.latest_neighbor_map.read().await.as_ref().map_or_else(
            BTreeSet::new,
            |neighbor_map| {
                neighbor_map
                    .neighbors
                    .iter()
                    .map(|neighbor| neighbor.node.node_id.clone())
                    .chain(
                        neighbor_map
                            .pinned_peers
                            .iter()
                            .map(|peer| peer.node_id.clone()),
                    )
                    .collect::<BTreeSet<_>>()
            },
        );
        let now = Instant::now();
        let mut retained = self.retained_neighbor_maps.write().await;
        retained.retain(|previous| previous.expires_at > now);
        let mut selected_ids = current_topology_pins;
        let mut selected = Vec::new();
        for previous in retained.iter().rev() {
            for neighbor in &previous.neighbors {
                if selected_ids.insert(neighbor.node.node_id.clone()) {
                    selected.push(neighbor.node.clone());
                }
            }
        }
        drop(retained);
        self.lazy_connect
            .write()
            .await
            .replace_topology_pins(selected_ids);
        selected
    }

    async fn active_overlay_topology_epochs(&self) -> BTreeSet<u64> {
        let current_epoch = self
            .latest_neighbor_map
            .read()
            .await
            .as_ref()
            .map(|neighbor_map| neighbor_map.topology_epoch);
        let now = Instant::now();
        let mut retained = self.retained_neighbor_maps.write().await;
        retained.retain(|previous| previous.expires_at > now);
        current_epoch
            .into_iter()
            .chain(retained.iter().map(|previous| previous.topology_epoch))
            .collect()
    }

    async fn active_overlay_neighbor_ids(&self) -> BTreeSet<NodeId> {
        let current = self
            .latest_neighbor_map
            .read()
            .await
            .as_ref()
            .map(|neighbor_map| {
                neighbor_map
                    .neighbors
                    .iter()
                    .map(|neighbor| neighbor.node.node_id.clone())
                    .chain(
                        neighbor_map
                            .pinned_peers
                            .iter()
                            .map(|peer| peer.node_id.clone()),
                    )
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let now = Instant::now();
        let mut retained = self.retained_neighbor_maps.write().await;
        retained.retain(|previous| previous.expires_at > now);
        current
            .into_iter()
            .chain(
                retained
                    .iter()
                    .flat_map(|previous| previous.neighbors.iter())
                    .map(|neighbor| neighbor.node.node_id.clone()),
            )
            .collect()
    }

    async fn current_overlay_routing_epoch(&self) -> Option<u64> {
        self.latest_neighbor_map
            .read()
            .await
            .as_ref()
            .map(|neighbor_map| neighbor_map.routing_epoch)
    }

    pub async fn take_pending_overlay_destinations(&self, maximum: usize) -> Vec<IpAddr> {
        let local_vpn_ip = self.state().vpn_ip.map(|vpn_ip| vpn_ip.0);
        self.pending_overlay_destinations
            .lock()
            .await
            .take(maximum)
            .into_iter()
            .filter(|destination| Some(*destination) != local_vpn_ip)
            .collect()
    }

    pub async fn requeue_overlay_destination(&self, destination: IpAddr) {
        if self.local_vpn_destination(destination) {
            return;
        }
        self.pending_overlay_destinations
            .lock()
            .await
            .requeue(destination);
    }

    pub async fn record_resolved_overlay_path(
        &self,
        mut path: OverlayPath,
        observed_at: DateTime<Utc>,
    ) -> Result<(), AgentError> {
        path.validate()
            .map_err(|error| AgentError::InvalidState(error.to_string()))?;
        let _update_guard = self.neighbor_map_update.lock().await;
        let local_node = self.state().node_id;
        if path.source != local_node {
            return Err(AgentError::InvalidState(format!(
                "overlay path source {} does not match local node {local_node}",
                path.source
            )));
        }
        let neighbor_map = self
            .neighbor_map_snapshot()
            .await
            .ok_or_else(|| AgentError::PeerMapUnavailable(local_node.clone()))?;
        if path.topology_epoch != neighbor_map.topology_epoch {
            return Err(AgentError::InvalidState(format!(
                "overlay path epoch {} does not match neighbor-map epoch {}",
                path.topology_epoch, neighbor_map.topology_epoch
            )));
        }
        if path.routing_epoch != neighbor_map.routing_epoch {
            return Err(AgentError::InvalidState(format!(
                "overlay path routing epoch {} does not match neighbor-map routing epoch {}",
                path.routing_epoch, neighbor_map.routing_epoch
            )));
        }
        if path.target.cluster_id != neighbor_map.cluster_id {
            return Err(AgentError::InvalidState(format!(
                "overlay target cluster {} does not match local cluster {}",
                path.target.cluster_id, neighbor_map.cluster_id
            )));
        }
        let exact_route = normalize_resolved_overlay_path_routes(&mut path)?;

        let target_id = path.target.node_id.clone();
        let backbone_peer_ids = neighbor_map
            .neighbors
            .iter()
            .map(|neighbor| neighbor.node.node_id.clone())
            .collect::<BTreeSet<_>>();
        let is_backbone_neighbor = backbone_peer_ids.contains(&target_id);
        let on_demand_peer_limit = usize::from(neighbor_map.on_demand_peer_limit);
        if !is_backbone_neighbor && on_demand_peer_limit == 0 {
            return Err(AgentError::InvalidState(
                "on-demand overlay peer limit is zero".to_string(),
            ));
        }
        let local_route_cidrs = self
            .local_advertised_routes
            .read()
            .await
            .iter()
            .map(|route| route.cidr)
            .collect::<BTreeSet<_>>();
        let mut evicted_paths = BTreeSet::new();
        let mut lazy_connect = self.lazy_connect.write().await;
        let mut resolved = self.resolved_overlay_paths.write().await;
        if !is_backbone_neighbor || exact_route.is_some() {
            if resolved.paths.get(&target_id).is_some_and(|lease| {
                lease.path.topology_epoch != path.topology_epoch
                    || lease.path.routing_epoch != path.routing_epoch
            }) {
                resolved.remove_peer(&target_id);
                lazy_connect.remove_observed_peer(&target_id);
            }
            if !is_backbone_neighbor {
                let target_exists = resolved.paths.contains_key(&target_id);
                let retained_limit = on_demand_peer_limit - usize::from(!target_exists);
                evicted_paths.extend(trim_on_demand_overlay_paths(
                    &mut resolved,
                    &mut lazy_connect,
                    &backbone_peer_ids,
                    retained_limit,
                    target_exists.then_some(&target_id),
                ));
            }

            if let Some(route) = exact_route.as_ref() {
                let incoming_route_is_new = resolved
                    .paths
                    .get(&target_id)
                    .is_none_or(|lease| !lease.exact_routes.contains_key(&route.cidr));
                while incoming_route_is_new
                    && resolved
                        .paths
                        .get(&target_id)
                        .is_some_and(|lease| lease.exact_route_count() >= MAX_OVERLAY_NODE_ROUTES)
                {
                    let oldest_route = resolved
                        .paths
                        .get(&target_id)
                        .and_then(ResolvedOverlayPathLease::oldest_exact_route)
                        .map(|(cidr, _)| cidr)
                        .ok_or_else(|| {
                            AgentError::InvalidState(format!(
                                "overlay target {target_id} route lease state is inconsistent"
                            ))
                        })?;
                    let retained = resolved.remove_exact_route(&target_id, oldest_route);
                    if retained {
                        if let Some(target) = resolved
                            .paths
                            .get(&target_id)
                            .map(ResolvedOverlayPathLease::materialized_target)
                        {
                            lazy_connect.observe_overlay_shortcut(&target, &local_route_cidrs);
                        }
                    } else {
                        lazy_connect.remove_observed_peer(&target_id);
                    }
                }

                let incoming_route_is_new = exact_route.as_ref().is_some_and(|route| {
                    resolved
                        .paths
                        .get(&target_id)
                        .is_none_or(|lease| !lease.exact_routes.contains_key(&route.cidr))
                });
                while incoming_route_is_new
                    && resolved.exact_route_lru.len() >= MAX_RESOLVED_OVERLAY_PATHS
                {
                    let (_, evicted_peer, evicted_route) =
                        resolved.exact_route_lru.first().cloned().ok_or_else(|| {
                            AgentError::InvalidState(format!(
                                "overlay route lease count reached {MAX_RESOLVED_OVERLAY_PATHS} \
                             without an eviction candidate"
                            ))
                        })?;
                    let retained_peer = resolved.remove_exact_route(&evicted_peer, evicted_route);
                    if retained_peer {
                        if let Some(retained_target) = resolved
                            .paths
                            .get(&evicted_peer)
                            .map(ResolvedOverlayPathLease::materialized_target)
                        {
                            lazy_connect
                                .observe_overlay_shortcut(&retained_target, &local_route_cidrs);
                        }
                    } else {
                        lazy_connect.remove_observed_peer(&evicted_peer);
                        if evicted_peer != target_id {
                            lazy_connect.remove_activity(&evicted_peer);
                            evicted_paths.insert(evicted_peer);
                        }
                    }
                }
            }

            let stored_target =
                resolved.upsert_path(target_id.clone(), path, exact_route, observed_at);
            lazy_connect.observe_overlay_shortcut(&stored_target, &local_route_cidrs);
        }
        lazy_connect.record_activity(target_id, observed_at);
        drop(resolved);
        drop(lazy_connect);
        if !evicted_paths.is_empty() {
            self.overlay_forwarder_endpoints
                .write()
                .await
                .retain(|peer, _| !evicted_paths.contains(peer));
        }
        self.invalidate_overlay_shortcut_snapshot();
        self.request_lazy_connect_sync();
        Ok(())
    }

    pub async fn overlay_peer_map_snapshot(&self) -> Result<PeerMap, AgentError> {
        let mut peer_map = self.peer_map_snapshot().await?;
        let active_epochs = self.active_overlay_topology_epochs().await;
        let current_routing_epoch = self.current_overlay_routing_epoch().await;
        for lease in self.resolved_overlay_paths.read().await.paths.values() {
            if active_epochs.contains(&lease.path.topology_epoch)
                && Some(lease.path.routing_epoch) == current_routing_epoch
            {
                merge_resolved_overlay_peer(&mut peer_map.peers, lease.materialized_target());
            }
        }
        Ok(peer_map)
    }

    pub async fn resolved_overlay_peers(&self) -> Vec<NodeRecord> {
        let active_epochs = self.active_overlay_topology_epochs().await;
        let current_routing_epoch = self.current_overlay_routing_epoch().await;
        self.resolved_overlay_paths
            .read()
            .await
            .paths
            .values()
            .filter(|lease| {
                active_epochs.contains(&lease.path.topology_epoch)
                    && Some(lease.path.routing_epoch) == current_routing_epoch
            })
            .map(ResolvedOverlayPathLease::materialized_target)
            .collect()
    }

    pub async fn resolved_overlay_paths(&self) -> Vec<OverlayPath> {
        let active_epochs = self.active_overlay_topology_epochs().await;
        let current_routing_epoch = self.current_overlay_routing_epoch().await;
        self.resolved_overlay_paths
            .read()
            .await
            .paths
            .values()
            .filter(|lease| {
                active_epochs.contains(&lease.path.topology_epoch)
                    && Some(lease.path.routing_epoch) == current_routing_epoch
            })
            .map(ResolvedOverlayPathLease::materialized_path)
            .collect()
    }

    pub async fn has_current_resolved_overlay_path(&self, peer: &NodeId) -> bool {
        let current_epochs = self
            .latest_neighbor_map
            .read()
            .await
            .as_ref()
            .map(|neighbor_map| (neighbor_map.topology_epoch, neighbor_map.routing_epoch));
        self.resolved_overlay_paths
            .read()
            .await
            .paths
            .get(peer)
            .is_some_and(|lease| {
                Some((lease.path.topology_epoch, lease.path.routing_epoch)) == current_epochs
            })
    }

    pub async fn has_current_overlay_route_to_peer(&self, peer: &NodeId) -> bool {
        let current_epochs = {
            let neighbor_map = self.latest_neighbor_map.read().await;
            let Some(neighbor_map) = neighbor_map.as_ref() else {
                return false;
            };
            if neighbor_map
                .neighbors
                .iter()
                .any(|neighbor| neighbor.node.node_id == *peer)
                || neighbor_map
                    .pinned_peers
                    .iter()
                    .any(|pinned| pinned.node_id == *peer)
            {
                return true;
            }
            (neighbor_map.topology_epoch, neighbor_map.routing_epoch)
        };
        self.resolved_overlay_paths
            .read()
            .await
            .paths
            .get(peer)
            .is_some_and(|lease| {
                (lease.path.topology_epoch, lease.path.routing_epoch) == current_epochs
            })
    }

    pub async fn resolved_overlay_peer_ids(&self) -> BTreeSet<NodeId> {
        self.overlay_shortcut_snapshot()
            .await
            .resolved_overlay_peers
            .clone()
    }

    fn invalidate_overlay_shortcut_snapshot(&self) {
        self.overlay_shortcut_generation
            .fetch_add(2, Ordering::AcqRel);
    }

    pub async fn overlay_shortcut_snapshot(&self) -> Arc<OverlayShortcutSnapshot> {
        loop {
            let generation = self.overlay_shortcut_generation.load(Ordering::Acquire);
            if generation % 2 == 1 {
                tokio::task::yield_now().await;
                continue;
            }
            if let Some(snapshot) = self
                .overlay_shortcut_snapshot
                .read()
                .await
                .as_ref()
                .filter(|cached| cached.generation == generation)
                .map(|cached| cached.snapshot.clone())
            {
                if generation == self.overlay_shortcut_generation.load(Ordering::Acquire) {
                    return snapshot;
                }
                continue;
            }

            let snapshot = {
                let active_epochs = self.active_overlay_topology_epochs().await;
                let mut active_direct_peer_ids = self.active_overlay_neighbor_ids().await;
                active_direct_peer_ids
                    .extend(self.lazy_connect.read().await.direct_pinned_peer_ids());
                let current_routing_epoch = self.current_overlay_routing_epoch().await;
                let resolved = self.resolved_overlay_paths.read().await;
                let resolved_overlay_peers = resolved
                    .paths
                    .iter()
                    .filter(|(_, lease)| {
                        active_epochs.contains(&lease.path.topology_epoch)
                            && Some(lease.path.routing_epoch) == current_routing_epoch
                    })
                    .filter(|(peer, _)| !active_direct_peer_ids.contains(*peer))
                    .map(|(peer, _)| peer.clone())
                    .collect::<BTreeSet<_>>();
                Arc::new(OverlayShortcutSnapshot {
                    resolved_overlay_peers,
                    // A shortcut selected independently by each endpoint cannot
                    // guarantee the remote node's physical degree. Direct
                    // bounded-overlay links therefore come only from the
                    // authoritative neighbor map.
                    direct_shortcut_targets: BTreeSet::new(),
                })
            };
            if generation != self.overlay_shortcut_generation.load(Ordering::Acquire) {
                continue;
            }

            let mut cached = self.overlay_shortcut_snapshot.write().await;
            if generation != self.overlay_shortcut_generation.load(Ordering::Acquire) {
                continue;
            }
            *cached = Some(CachedOverlayShortcutSnapshot {
                generation,
                snapshot: snapshot.clone(),
            });
            return snapshot;
        }
    }

    pub async fn overlay_direct_shortcut_targets(&self) -> BTreeSet<NodeId> {
        self.overlay_shortcut_snapshot()
            .await
            .direct_shortcut_targets
            .clone()
    }

    pub async fn overlay_destination_is_resolvable(&self, destination: IpAddr) -> bool {
        if self.local_vpn_destination(destination) {
            return false;
        }
        self.latest_neighbor_map
            .read()
            .await
            .as_ref()
            .is_some_and(|neighbor_map| {
                neighbor_map.vpn_cidr.contains(&destination)
                    || neighbor_map
                        .aggregate_routes
                        .iter()
                        .any(|route| route.cidr.contains(&destination))
            })
    }

    fn local_vpn_destination(&self, destination: IpAddr) -> bool {
        self.state()
            .vpn_ip
            .is_some_and(|vpn_ip| vpn_ip.0 == destination)
    }

    pub async fn record_peer_map_snapshot(&self, peer_map: PeerMap) {
        let current_peers = peer_map
            .peers
            .iter()
            .map(|peer| peer.node_id.clone())
            .collect::<BTreeSet<_>>();
        self.path_quality_observations
            .write()
            .await
            .retain(|peer, _| current_peers.contains(peer));
        *self.latest_peer_map.write().await = Some(peer_map);
    }

    pub async fn peer_map_snapshot(&self) -> Result<PeerMap, AgentError> {
        self.latest_peer_map
            .read()
            .await
            .clone()
            .ok_or_else(|| AgentError::PeerMapUnavailable(self.state().node_id))
    }

    pub async fn should_connect_peer(&self, peer: &NodeRecord) -> bool {
        let lazy_connect = self.lazy_connect.read().await;
        let non_topology_pinned = lazy_connect.is_non_topology_pinned(&peer.node_id);
        let topology_pinned = lazy_connect.is_topology_pinned(&peer.node_id);
        let recently_active = lazy_connect.has_activity(&peer.node_id);
        if !non_topology_pinned && !topology_pinned && !recently_active {
            return false;
        }
        if peer.role.is_client()
            || lazy_connect.is_pinned_by_policy(&peer.role, &peer.tags)
            || non_topology_pinned
        {
            return true;
        }
        drop(lazy_connect);
        let Some(neighbor_map) = self.latest_neighbor_map.read().await.clone() else {
            return true;
        };
        if neighbor_map
            .neighbors
            .iter()
            .any(|neighbor| neighbor.node.node_id == peer.node_id)
            || neighbor_map
                .pinned_peers
                .iter()
                .any(|pinned| pinned.node_id == peer.node_id)
        {
            return true;
        }
        if topology_pinned
            && self
                .retained_overlay_neighbors()
                .await
                .iter()
                .any(|neighbor| neighbor.node_id == peer.node_id)
        {
            return true;
        }
        let active_epochs = self.active_overlay_topology_epochs().await;
        let current_routing_epoch = self.current_overlay_routing_epoch().await;
        self.resolved_overlay_paths
            .read()
            .await
            .paths
            .get(&peer.node_id)
            .is_some_and(|lease| {
                active_epochs.contains(&lease.path.topology_epoch)
                    && Some(lease.path.routing_epoch) == current_routing_epoch
            })
    }

    pub async fn expire_idle_overlay_route_leases(&self, now: DateTime<Utc>) -> Vec<NodeId> {
        let _update_guard = self.neighbor_map_update.lock().await;
        let idle_timeout = {
            let lazy_connect = self.lazy_connect.read().await;
            Duration::from_secs(lazy_connect.policy.idle_timeout_seconds)
        };
        let Ok(idle_timeout) = chrono::Duration::from_std(idle_timeout) else {
            return Vec::new();
        };
        let cutoff = now - idle_timeout;
        let physical_neighbors = self
            .latest_neighbor_map
            .read()
            .await
            .as_ref()
            .map(|neighbor_map| {
                neighbor_map
                    .neighbors
                    .iter()
                    .map(|neighbor| (neighbor.node.node_id.clone(), neighbor.node.clone()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let local_route_cidrs = self
            .local_advertised_routes
            .read()
            .await
            .iter()
            .map(|route| route.cidr)
            .collect::<BTreeSet<_>>();

        let mut lazy_connect = self.lazy_connect.write().await;
        let mut resolved = self.resolved_overlay_paths.write().await;
        let expired_routes = resolved
            .exact_route_lru
            .iter()
            .take_while(|(last_used, _, _)| *last_used <= cutoff)
            .map(|(_, peer, cidr)| (peer.clone(), *cidr))
            .collect::<Vec<_>>();
        if expired_routes.is_empty() {
            return Vec::new();
        }

        let mut removed_peers = BTreeSet::new();
        for (peer, cidr) in expired_routes {
            let retained = resolved.remove_exact_route(&peer, cidr);
            if retained {
                if let Some(target) = resolved
                    .paths
                    .get(&peer)
                    .map(ResolvedOverlayPathLease::materialized_target)
                {
                    lazy_connect.observe_overlay_shortcut(&target, &local_route_cidrs);
                }
            } else if let Some(neighbor) = physical_neighbors.get(&peer) {
                lazy_connect.observe_peer(neighbor, &local_route_cidrs);
            } else {
                lazy_connect.remove_activity(&peer);
                lazy_connect.remove_observed_peer(&peer);
                removed_peers.insert(peer);
            }
        }
        drop(resolved);
        drop(lazy_connect);

        if !removed_peers.is_empty() {
            self.overlay_forwarder_endpoints
                .write()
                .await
                .retain(|peer, _| !removed_peers.contains(peer));
        }
        self.invalidate_overlay_shortcut_snapshot();
        self.request_lazy_connect_sync();
        removed_peers.into_iter().collect()
    }

    pub async fn take_idle_peers_to_close(&self, now: DateTime<Utc>) -> Vec<NodeId> {
        let expired_route_peers = self.expire_idle_overlay_route_leases(now).await;
        let mut lazy_connect = self.lazy_connect.write().await;
        let mut idle_peers = lazy_connect
            .idle_peers_to_close(now)
            .into_iter()
            .collect::<BTreeSet<_>>();
        idle_peers.extend(expired_route_peers);
        let idle_timeout = Duration::from_secs(lazy_connect.policy.idle_timeout_seconds);
        let mut resolved = self.resolved_overlay_paths.write().await;
        idle_peers.extend(resolved.paths.iter().filter_map(|(peer, lease)| {
            if lazy_connect.is_durably_pinned(peer) {
                return None;
            }
            let last_used = lazy_connect
                .last_used
                .get(peer)
                .copied()
                .unwrap_or(lease.resolved_at);
            now.signed_duration_since(last_used)
                .to_std()
                .is_ok_and(|idle_for| idle_for >= idle_timeout)
                .then(|| peer.clone())
        }));
        for peer in &idle_peers {
            lazy_connect.remove_activity(peer);
            lazy_connect.remove_observed_peer(peer);
            resolved.remove_peer(peer);
        }
        drop(resolved);
        drop(lazy_connect);
        self.overlay_forwarder_endpoints
            .write()
            .await
            .retain(|peer, _| !idle_peers.contains(peer));
        if !idle_peers.is_empty() {
            self.invalidate_overlay_shortcut_snapshot();
            self.request_lazy_connect_sync();
        }
        idle_peers.into_iter().collect()
    }
}

fn validate_path_probe_request(
    request: &AgentPathProbeRequest,
    local_node: &NodeId,
) -> Result<(), AgentError> {
    request
        .metrics
        .validate()
        .map_err(|error| AgentError::PathProbeRejected(error.to_string()))?;

    validate_path_state_shape(
        local_node,
        &request.peer,
        request.selected_state,
        request.selected_candidate.as_ref(),
        request.relay_node.as_ref(),
        "path probe",
    )
    .map_err(AgentError::PathProbeRejected)
}

fn validate_path_record(record: &PathRecord, local_node: &NodeId) -> Result<(), AgentError> {
    if &record.key.local != local_node {
        return Err(AgentError::PathStateRejected(format!(
            "path state local node {} does not match runtime node {}",
            record.key.local, local_node
        )));
    }
    if &record.key.remote == local_node {
        return Err(AgentError::PathStateRejected(
            "path state remote node must not be the runtime node".to_string(),
        ));
    }
    validate_path_state_shape(
        local_node,
        &record.key.remote,
        record.selected_state,
        record.selected_candidate.as_ref(),
        record.relay_node.as_ref(),
        "path state",
    )
    .map_err(AgentError::PathStateRejected)
}

fn validate_path_state_shape(
    local_node: &NodeId,
    peer: &NodeId,
    selected_state: PathState,
    selected_candidate: Option<&EndpointCandidate>,
    relay_node: Option<&NodeId>,
    context: &'static str,
) -> Result<(), String> {
    match selected_state {
        PathState::Relay => {
            if selected_candidate.is_some() {
                return Err(format!(
                    "relay {context} must not carry a direct selected candidate"
                ));
            }
            let relay_node = relay_node.ok_or_else(|| {
                if context == "path probe" {
                    "relay path probe requires --relay-node".to_string()
                } else {
                    format!("relay {context} requires a relay node")
                }
            })?;
            if relay_node == local_node || relay_node == peer {
                return Err(format!(
                    "relay {context} uses endpoint {relay_node} as relay"
                ));
            }
        }
        PathState::Unreachable => {
            if selected_candidate.is_some() {
                return Err(format!(
                    "unreachable {context} must not carry a selected candidate"
                ));
            }
            if relay_node.is_some() {
                return Err(format!("unreachable {context} must not carry a relay node"));
            }
        }
        PathState::DirectPublic | PathState::DirectIpv6 | PathState::DirectNatTraversal => {
            if relay_node.is_some() {
                return Err(format!("direct {context} must not carry a relay node"));
            }
        }
    }

    let Some(candidate) = selected_candidate else {
        return Ok(());
    };
    if &candidate.node_id != peer {
        return Err(format!(
            "selected candidate belongs to node {} instead of path peer {}",
            candidate.node_id, peer
        ));
    }
    if !endpoint_addr_is_usable(candidate.addr) {
        return Err(format!(
            "selected candidate {:?} at {} is unusable",
            candidate.kind, candidate.addr
        ));
    }
    if let Err(reason) = candidate.validate_kind_address() {
        return Err(format!(
            "selected candidate {:?} at {} is invalid: {reason}",
            candidate.kind, candidate.addr
        ));
    }
    if selected_state.is_direct() && !selected_state.allows_selected_candidate_kind(candidate.kind)
    {
        return Err(format!(
            "{context} selected state {:?} does not allow selected candidate kind {:?}",
            selected_state, candidate.kind
        ));
    }
    Ok(())
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
        Some(previous)
            if !selected_candidate_path_identity_eq(
                previous.selected_candidate.as_ref(),
                current.selected_candidate.as_ref(),
            ) =>
        {
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

fn selected_candidate_path_identity_eq(
    left: Option<&EndpointCandidate>,
    right: Option<&EndpointCandidate>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.node_id == right.node_id
                && left.kind == right.kind
                && left.addr == right.addr
                && left.priority == right.priority
                && left.cost == right.cost
                && left.source == right.source
        }
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardPeerConfig {
    pub peer: NodeId,
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive_seconds: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireGuardInterfaceConfig {
    pub vpn_ip: VpnIp,
    pub mtu: u32,
    pub listen_port: u16,
}

#[async_trait]
pub trait WireGuardBackend: Send + Sync {
    async fn configure_private_key(&self, _private_key_b64: &str) -> Result<(), AgentError> {
        Ok(())
    }

    async fn recover_interface(
        &self,
        private_key_b64: &str,
        _config: &WireGuardInterfaceConfig,
    ) -> Result<(), AgentError> {
        self.configure_private_key(private_key_b64).await
    }

    async fn recreate_interface(
        &self,
        private_key_b64: &str,
        config: &WireGuardInterfaceConfig,
    ) -> Result<(), AgentError> {
        self.recover_interface(private_key_b64, config).await
    }

    async fn enable_ipv6(&self) -> Result<(), AgentError> {
        Ok(())
    }

    async fn upsert_peer(&self, config: WireGuardPeerConfig) -> Result<(), AgentError>;
    async fn remove_peer(&self, peer: &NodeId) -> Result<(), AgentError>;
    async fn remove_peer_by_public_key(&self, public_key: &str) -> Result<(), AgentError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardPeerTelemetry {
    pub public_key_b64: String,
    pub endpoint: Option<String>,
    pub latest_handshake_at: Option<DateTime<Utc>>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDirectPathProbe {
    pub selected_state: PathState,
    pub selected_candidate: EndpointCandidate,
    pub started_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub endpoint_observed_at: Option<DateTime<Utc>>,
    pub baseline_rx_bytes: Option<u64>,
    pub baseline_tx_bytes: Option<u64>,
    pub baseline_latest_handshake_at: Option<DateTime<Utc>>,
    pub baseline_relay_inbound_payload_bytes: Option<u64>,
    pub relay_forwarder_suspended: bool,
}

impl PendingDirectPathProbe {
    pub fn targets(&self, state: PathState, candidate: &EndpointCandidate) -> bool {
        self.selected_state == state
            && self.selected_candidate.node_id == candidate.node_id
            && self.selected_candidate.kind == candidate.kind
            && self.selected_candidate.addr == candidate.addr
    }

    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        now < self.expires_at
    }

    pub fn transfer_increased(&self, telemetry: &WireGuardPeerTelemetry) -> bool {
        // Outbound bytes only prove local handshake attempts; inbound bytes prove reachability.
        self.baseline_rx_bytes
            .is_some_and(|baseline| telemetry.rx_bytes > baseline)
    }
}

impl WireGuardPeerTelemetry {
    fn new(public_key_b64: String) -> Self {
        Self {
            public_key_b64,
            endpoint: None,
            latest_handshake_at: None,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }

    fn merge(&mut self, update: Self) {
        if update.endpoint.is_some() {
            self.endpoint = update.endpoint;
        }
        if update.latest_handshake_at.is_some() {
            self.latest_handshake_at = update.latest_handshake_at;
        }
        self.rx_bytes = self.rx_bytes.max(update.rx_bytes);
        self.tx_bytes = self.tx_bytes.max(update.tx_bytes);
    }
}

#[async_trait]
pub trait WireGuardPeerTelemetrySource: Send + Sync {
    async fn snapshot(&self) -> Result<BTreeMap<String, WireGuardPeerTelemetry>, AgentError>;
}

#[async_trait]
pub trait WireGuardPeerInventorySource: Send + Sync + std::fmt::Debug {
    async fn public_keys(&self) -> Result<BTreeSet<String>, AgentError>;
}

#[derive(Debug, Clone)]
pub struct CommandWireGuardPeerTelemetrySource {
    interface: String,
    namespace: Option<LinuxNetworkNamespace>,
    timeout: Duration,
    output_max_bytes: usize,
}

impl CommandWireGuardPeerTelemetrySource {
    pub fn new(interface: impl Into<String>, timeout: Duration, output_max_bytes: usize) -> Self {
        Self {
            interface: interface.into(),
            namespace: None,
            timeout,
            output_max_bytes,
        }
    }

    pub fn new_in_namespace(
        interface: impl Into<String>,
        namespace: LinuxNetworkNamespace,
        timeout: Duration,
        output_max_bytes: usize,
    ) -> Self {
        Self {
            interface: interface.into(),
            namespace: Some(namespace),
            timeout,
            output_max_bytes,
        }
    }

    async fn query(&self, field: &'static str) -> Result<Vec<u8>, AgentError> {
        let mut command = LinuxCommand::new("wg", ["show", self.interface.as_str(), field]);
        if let Some(namespace) = self.namespace.as_ref() {
            warn_if_linux_netns_is_current(namespace, "WireGuard peer telemetry");
            command = command.in_namespace(namespace);
        }
        run_system_command_capture_stdout(command, self.timeout, self.output_max_bytes).await
    }
}

#[async_trait]
impl WireGuardPeerTelemetrySource for CommandWireGuardPeerTelemetrySource {
    async fn snapshot(&self) -> Result<BTreeMap<String, WireGuardPeerTelemetry>, AgentError> {
        let (handshakes, transfers, endpoints) = tokio::try_join!(
            self.query("latest-handshakes"),
            self.query("transfer"),
            self.query("endpoints"),
        )?;
        parse_wireguard_command_telemetry(&handshakes, &transfers, &endpoints)
    }
}

#[async_trait]
impl WireGuardPeerInventorySource for CommandWireGuardPeerTelemetrySource {
    async fn public_keys(&self) -> Result<BTreeSet<String>, AgentError> {
        parse_wireguard_command_peer_inventory(&self.query("peers").await?)
    }
}

#[derive(Debug, Clone)]
pub struct KernelWireGuardPeerTelemetrySource {
    interface: String,
    namespace: Option<LinuxNetworkNamespace>,
    timeout: Duration,
}

impl KernelWireGuardPeerTelemetrySource {
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            namespace: None,
            timeout: DEFAULT_SYSTEM_COMMAND_TIMEOUT,
        }
    }

    pub fn new_in_namespace(
        interface: impl Into<String>,
        namespace: LinuxNetworkNamespace,
    ) -> Self {
        Self {
            interface: interface.into(),
            namespace: Some(namespace),
            timeout: DEFAULT_SYSTEM_COMMAND_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl WireGuardPeerTelemetrySource for KernelWireGuardPeerTelemetrySource {
    async fn snapshot(&self) -> Result<BTreeMap<String, WireGuardPeerTelemetry>, AgentError> {
        validate_system_command_runtime_bounds(self.timeout, 1)?;
        tokio::time::timeout(
            self.timeout,
            query_wireguard_peer_telemetry_netlink(&self.interface, self.namespace.as_ref()),
        )
        .await
        .map_err(|_| {
            AgentError::WireGuard(format!(
                "WireGuard netlink telemetry query for interface {} timed out after {}",
                self.interface,
                command_timeout_label(self.timeout)
            ))
        })?
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl WireGuardPeerInventorySource for KernelWireGuardPeerTelemetrySource {
    async fn public_keys(&self) -> Result<BTreeSet<String>, AgentError> {
        Ok(WireGuardPeerTelemetrySource::snapshot(self)
            .await?
            .into_keys()
            .collect())
    }
}

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl WireGuardPeerTelemetrySource for KernelWireGuardPeerTelemetrySource {
    async fn snapshot(&self) -> Result<BTreeMap<String, WireGuardPeerTelemetry>, AgentError> {
        Err(AgentError::WireGuard(
            "kernel WireGuard telemetry is only supported on Linux".to_string(),
        ))
    }
}

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl WireGuardPeerInventorySource for KernelWireGuardPeerTelemetrySource {
    async fn public_keys(&self) -> Result<BTreeSet<String>, AgentError> {
        Err(AgentError::WireGuard(
            "kernel WireGuard peer inventory is only supported on Linux".to_string(),
        ))
    }
}

fn parse_wireguard_command_peer_inventory(peers: &[u8]) -> Result<BTreeSet<String>, AgentError> {
    wireguard_command_output_rows(peers, "peers", 1)?
        .into_iter()
        .map(|fields| {
            validate_wireguard_public_key(fields[0])?;
            Ok(fields[0].to_string())
        })
        .collect()
}

fn parse_wireguard_command_telemetry(
    handshakes: &[u8],
    transfers: &[u8],
    endpoints: &[u8],
) -> Result<BTreeMap<String, WireGuardPeerTelemetry>, AgentError> {
    let mut peers = BTreeMap::new();

    for fields in wireguard_command_output_rows(handshakes, "latest-handshakes", 2)? {
        let seconds = fields[1].parse::<i64>().map_err(|error| {
            AgentError::WireGuard(format!(
                "invalid WireGuard latest-handshakes timestamp `{}`: {error}",
                fields[1]
            ))
        })?;
        let peer = wireguard_telemetry_entry(&mut peers, fields[0])?;
        peer.latest_handshake_at = wireguard_handshake_timestamp(seconds, 0)?;
    }

    for fields in wireguard_command_output_rows(transfers, "transfer", 3)? {
        let rx_bytes = fields[1].parse::<u64>().map_err(|error| {
            AgentError::WireGuard(format!(
                "invalid WireGuard transfer receive byte count `{}`: {error}",
                fields[1]
            ))
        })?;
        let tx_bytes = fields[2].parse::<u64>().map_err(|error| {
            AgentError::WireGuard(format!(
                "invalid WireGuard transfer transmit byte count `{}`: {error}",
                fields[2]
            ))
        })?;
        let peer = wireguard_telemetry_entry(&mut peers, fields[0])?;
        peer.rx_bytes = rx_bytes;
        peer.tx_bytes = tx_bytes;
    }

    for fields in wireguard_command_output_rows(endpoints, "endpoints", 2)? {
        let peer = wireguard_telemetry_entry(&mut peers, fields[0])?;
        peer.endpoint = (fields[1] != "(none)").then(|| fields[1].to_string());
    }

    Ok(peers)
}

fn wireguard_command_output_rows<'a>(
    bytes: &'a [u8],
    field: &'static str,
    expected_fields: usize,
) -> Result<Vec<Vec<&'a str>>, AgentError> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        AgentError::WireGuard(format!(
            "WireGuard {field} output was not valid UTF-8: {error}"
        ))
    })?;
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != expected_fields || fields.iter().any(|field| field.is_empty()) {
            return Err(AgentError::WireGuard(format!(
                "invalid WireGuard {field} output row {}: expected {expected_fields} non-empty tab-separated fields, got {}",
                index + 1,
                fields.len()
            )));
        }
        rows.push(fields);
    }
    Ok(rows)
}

fn wireguard_telemetry_entry<'a>(
    peers: &'a mut BTreeMap<String, WireGuardPeerTelemetry>,
    public_key_b64: &str,
) -> Result<&'a mut WireGuardPeerTelemetry, AgentError> {
    validate_wireguard_public_key(public_key_b64)?;
    Ok(peers
        .entry(public_key_b64.to_string())
        .or_insert_with(|| WireGuardPeerTelemetry::new(public_key_b64.to_string())))
}

fn wireguard_handshake_timestamp(
    seconds: i64,
    nano_seconds: i64,
) -> Result<Option<DateTime<Utc>>, AgentError> {
    if seconds == 0 && nano_seconds == 0 {
        return Ok(None);
    }
    if seconds < 0 || !(0..1_000_000_000).contains(&nano_seconds) {
        return Err(AgentError::WireGuard(format!(
            "invalid WireGuard handshake timestamp {seconds}.{nano_seconds:09}"
        )));
    }
    let nano_seconds = u32::try_from(nano_seconds).map_err(|error| {
        AgentError::WireGuard(format!(
            "invalid WireGuard handshake nanoseconds {nano_seconds}: {error}"
        ))
    })?;
    DateTime::<Utc>::from_timestamp(seconds, nano_seconds)
        .map(Some)
        .ok_or_else(|| {
            AgentError::WireGuard(format!(
                "WireGuard handshake timestamp {seconds}.{nano_seconds:09} is out of range"
            ))
        })
}

fn validate_wireguard_public_key(value: &str) -> Result<(), AgentError> {
    decode_wireguard_public_key_b64(value)
        .map_err(|error| AgentError::WireGuard(format!("invalid WireGuard public key: {error}")))?;
    Ok(())
}

fn passive_wireguard_public_key(advertised_public_key: &str) -> Result<String, AgentError> {
    derived_quarantine_wireguard_public_key(
        PASSIVE_WIREGUARD_PUBLIC_KEY_DOMAIN,
        advertised_public_key,
    )
}

fn overlay_quarantine_wireguard_public_key(local_public_key: &str) -> Result<String, AgentError> {
    derived_quarantine_wireguard_public_key(OVERLAY_QUARANTINE_PUBLIC_KEY_DOMAIN, local_public_key)
}

fn derived_quarantine_wireguard_public_key(
    domain: &[u8],
    excluded_public_key: &str,
) -> Result<String, AgentError> {
    for counter in 0..=u8::MAX {
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update(excluded_public_key.as_bytes());
        digest.update([counter]);
        let candidate = encode_bytes(&digest.finalize());
        if candidate != excluded_public_key && validate_wireguard_public_key(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(AgentError::WireGuard(
        "failed to derive a valid WireGuard quarantine public key".to_string(),
    ))
}

#[derive(Clone, PartialEq, Eq)]
pub struct LinuxCommand {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
}

impl std::fmt::Debug for LinuxCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stdin = self
            .stdin
            .as_ref()
            .map(|stdin| format!("<redacted {} bytes>", stdin.len()));
        formatter
            .debug_struct("LinuxCommand")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("stdin", &stdin)
            .finish()
    }
}

impl LinuxCommand {
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            stdin: None,
        }
    }

    pub fn with_stdin(mut self, stdin: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(stdin.into());
        self
    }

    pub fn in_namespace(self, namespace: &LinuxNetworkNamespace) -> Self {
        let (program, args) = namespace.wrap_program_args(&self.program, &self.args);
        Self {
            program,
            args,
            stdin: self.stdin,
        }
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

async fn run_system_command_capture_stdout(
    command: LinuxCommand,
    timeout: Duration,
    output_max_bytes: usize,
) -> Result<Vec<u8>, AgentError> {
    validate_system_command_runtime_bounds(timeout, output_max_bytes)?;
    validate_linux_command(&command)?;
    let command_label = command_label(&command.program, &command.args);
    let output = run_command_output(command, timeout, output_max_bytes, &command_label).await?;
    if !output.status.success() {
        return Err(AgentError::WireGuard(format!(
            "{command_label} failed: {}",
            command_stderr_message(&output.stderr)
        )));
    }
    if output.stdout.truncated {
        return Err(AgentError::WireGuard(format!(
            "{command_label} stdout exceeded {} bytes",
            output.stdout.limit
        )));
    }
    Ok(output.stdout.bytes)
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
    validate_linux_command_program(&command.program)?;
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

    if let Some(stdin) = &command.stdin {
        if stdin.len() > MAX_LINUX_COMMAND_STDIN_BYTES {
            return Err(AgentError::WireGuard(format!(
                "invalid linux command: stdin exceeds {MAX_LINUX_COMMAND_STDIN_BYTES} bytes"
            )));
        }
    }

    Ok(())
}

fn validate_linux_command_program(program: &str) -> Result<(), AgentError> {
    if program.is_empty() {
        return Err(AgentError::WireGuard(
            "invalid linux command: program cannot be empty".to_string(),
        ));
    }
    if program.len() > MAX_LINUX_COMMAND_PROGRAM_BYTES {
        return Err(AgentError::WireGuard(format!(
            "invalid linux command: program exceeds {MAX_LINUX_COMMAND_PROGRAM_BYTES} bytes"
        )));
    }
    if program.as_bytes().contains(&0) {
        return Err(AgentError::WireGuard(
            "invalid linux command: program must not contain NUL bytes".to_string(),
        ));
    }
    if program.chars().any(char::is_control) {
        return Err(AgentError::WireGuard(
            "invalid linux command: program must not contain control characters".to_string(),
        ));
    }
    if program.chars().any(char::is_whitespace) {
        return Err(AgentError::WireGuard(
            "invalid linux command: program must not contain whitespace".to_string(),
        ));
    }

    let program_name = if program.contains('/') {
        let program_path = Path::new(program);
        if !program_path.is_absolute() {
            return Err(AgentError::WireGuard(
                "invalid linux command: program must be a bare command name or an absolute path"
                    .to_string(),
            ));
        }
        if program
            .split('/')
            .any(|component| matches!(component, "." | ".."))
        {
            return Err(AgentError::WireGuard(
                "invalid linux command: program path must not contain '.' or '..' components"
                    .to_string(),
            ));
        }
        program_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                AgentError::WireGuard(
                    "invalid linux command: program path must name an executable".to_string(),
                )
            })?
    } else {
        program
    };
    if matches!(program_name, "." | "..") {
        return Err(AgentError::WireGuard(
            "invalid linux command: program name must not be '.' or '..'".to_string(),
        ));
    }
    if program_name.starts_with('-') {
        return Err(AgentError::WireGuard(
            "invalid linux command: program name must not start with '-'".to_string(),
        ));
    }

    Ok(())
}

fn resolve_trusted_linux_command_paths(
    mut command: LinuxCommand,
) -> Result<LinuxCommand, AgentError> {
    let original_program = command.program.clone();
    let resolved_program = resolve_trusted_linux_command_program(&command.program)?;
    command.program = command_path_to_string(&resolved_program)?;

    if linux_command_program_name(&original_program) == Some("ip")
        && command.args.len() >= 4
        && command.args[0] == "netns"
        && command.args[1] == "exec"
    {
        validate_linux_command_program(&command.args[3])?;
        let resolved_inner = resolve_trusted_linux_command_program(&command.args[3])?;
        command.args[3] = command_path_to_string(&resolved_inner)?;
    }

    Ok(command)
}

fn resolve_trusted_linux_command_program(program: &str) -> Result<PathBuf, AgentError> {
    if program.contains('/') {
        return ensure_trusted_linux_command_executable(
            Path::new(program),
            "linux command program",
        );
    }

    for directory in std::env::split_paths(OsStr::new(SANITIZED_SYSTEM_COMMAND_PATH)) {
        if directory.as_os_str().is_empty() || !directory.is_absolute() {
            return Err(AgentError::WireGuard(format!(
                "invalid linux command PATH entry `{}`: expected an absolute directory",
                directory.display()
            )));
        }
        if command_path_has_special_component(&directory) {
            return Err(AgentError::WireGuard(format!(
                "invalid linux command PATH entry `{}`: must not contain '.' or '..' components",
                directory.display()
            )));
        }
        if let Err(error) = ensure_trusted_linux_command_search_directory(&directory) {
            if !matches!(&error, AgentError::Io(io) if io.kind() == std::io::ErrorKind::NotFound) {
                return Err(error);
            }
            continue;
        }

        let candidate = directory.join(program);
        match candidate.symlink_metadata() {
            Ok(_) => {
                return ensure_trusted_linux_command_executable(
                    &candidate,
                    "linux command program",
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(AgentError::Io(error)),
        }
    }

    Err(AgentError::WireGuard(format!(
        "missing linux command program `{program}` in sanitized PATH"
    )))
}

fn command_path_to_string(path: &Path) -> Result<String, AgentError> {
    path.to_str().map(ToOwned::to_owned).ok_or_else(|| {
        AgentError::WireGuard(format!(
            "resolved linux command path {} is not UTF-8",
            path.display()
        ))
    })
}

fn linux_command_program_name(program: &str) -> Option<&str> {
    if program.contains('/') {
        Path::new(program)
            .file_name()
            .and_then(|name| name.to_str())
    } else {
        Some(program)
    }
}

fn command_path_has_special_component(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    })
}

#[cfg(unix)]
fn ensure_trusted_linux_command_search_directory(directory: &Path) -> Result<(), AgentError> {
    let metadata = std::fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() {
        return Err(AgentError::WireGuard(format!(
            "linux command PATH entry {} must not be a symlink",
            directory.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(AgentError::WireGuard(format!(
            "linux command PATH entry {} must be a directory",
            directory.display()
        )));
    }
    ensure_trusted_linux_command_directory_chain(directory, "linux command PATH entry")
}

#[cfg(not(unix))]
fn ensure_trusted_linux_command_search_directory(directory: &Path) -> Result<(), AgentError> {
    let metadata = std::fs::metadata(directory)?;
    if !metadata.is_dir() {
        return Err(AgentError::WireGuard(format!(
            "linux command PATH entry {} must be a directory",
            directory.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_trusted_linux_command_executable(
    path: &Path,
    label: &str,
) -> Result<PathBuf, AgentError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(AgentError::WireGuard(format!(
            "{label} at {} must not be a symlink",
            path.display()
        )));
    }
    let mode = metadata.permissions().mode();
    if !metadata.is_file() || mode & 0o111 == 0 {
        return Err(AgentError::WireGuard(format!(
            "{label} at {} expected an executable regular file",
            path.display()
        )));
    }
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    ensure_trusted_linux_command_owner(label, "at", path, metadata.uid(), effective_uid)?;
    if mode & 0o022 != 0 {
        return Err(AgentError::WireGuard(format!(
            "{label} at {} must not be group- or world-writable",
            path.display()
        )));
    }
    let parent = path.parent().ok_or_else(|| {
        AgentError::WireGuard(format!(
            "failed to locate parent directory for {label} at {}",
            path.display()
        ))
    })?;
    ensure_trusted_linux_command_directory_chain(parent, label)?;
    Ok(path.to_path_buf())
}

#[cfg(not(unix))]
fn ensure_trusted_linux_command_executable(
    path: &Path,
    label: &str,
) -> Result<PathBuf, AgentError> {
    let canonical = std::fs::canonicalize(path)?;
    let metadata = std::fs::metadata(&canonical)?;
    if !metadata.is_file() {
        return Err(AgentError::WireGuard(format!(
            "{label} at {} expected an executable regular file",
            path.display()
        )));
    }
    Ok(canonical)
}

#[cfg(unix)]
fn ensure_trusted_linux_command_directory_chain(
    directory: &Path,
    label: &str,
) -> Result<(), AgentError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let effective_uid = nix::unistd::Uid::effective().as_raw();
    let mut current = PathBuf::new();
    for component in directory.components() {
        match component {
            std::path::Component::RootDir => current.push(component.as_os_str()),
            std::path::Component::Normal(part) => {
                current.push(part);
                let metadata = std::fs::symlink_metadata(&current)?;
                if metadata.file_type().is_symlink() {
                    return Err(AgentError::WireGuard(format!(
                        "{label} parent {} must not be a symlink",
                        current.display()
                    )));
                }
                if !metadata.is_dir() {
                    return Err(AgentError::WireGuard(format!(
                        "{label} parent {} must be a directory",
                        current.display()
                    )));
                }
                ensure_trusted_linux_command_owner(
                    label,
                    "parent",
                    &current,
                    metadata.uid(),
                    effective_uid,
                )?;
                if metadata.permissions().mode() & 0o022 != 0 {
                    return Err(AgentError::WireGuard(format!(
                        "{label} parent {} must not be group- or world-writable",
                        current.display()
                    )));
                }
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(AgentError::WireGuard(format!(
                    "{label} parent {} must not contain '..' components",
                    directory.display()
                )));
            }
            std::path::Component::Prefix(prefix) => current.push(prefix.as_os_str()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_trusted_linux_command_owner(
    label: &str,
    relationship: &str,
    path: &Path,
    owner_uid: u32,
    effective_uid: u32,
) -> Result<(), AgentError> {
    if owner_uid != 0 && owner_uid != effective_uid {
        return Err(AgentError::WireGuard(format!(
            "{label} {relationship} {} must be owned by root or the current effective user",
            path.display()
        )));
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
    let command = resolve_trusted_linux_command_paths(command)?;
    let mut child_command = Command::new(&command.program);
    child_command
        .args(&command.args)
        .env_clear()
        .env("PATH", SANITIZED_SYSTEM_COMMAND_PATH)
        .env("LANG", SANITIZED_SYSTEM_COMMAND_LOCALE)
        .env("LC_ALL", SANITIZED_SYSTEM_COMMAND_LOCALE)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if command.stdin.is_some() {
        child_command.stdin(Stdio::piped());
    } else {
        child_command.stdin(Stdio::null());
    }
    configure_command_process_group(&mut child_command);

    let mut child = child_command.spawn().map_err(AgentError::Io)?;
    let stdin_task = if let Some(stdin) = command.stdin {
        let mut child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| AgentError::Io(std::io::Error::other("child stdin was not piped")))?;
        Some(tokio::spawn(async move {
            child_stdin.write_all(&stdin).await?;
            child_stdin.shutdown().await
        }))
    } else {
        None
    };

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
            if let Some(task) = stdin_task {
                task.abort();
            }
            stdout_task.abort();
            stderr_task.abort();
            return Err(AgentError::Io(error));
        }
        Err(_) => {
            let kill_error = kill_timed_out_child(&mut child);
            let _ = child.wait().await;
            if let Some(task) = stdin_task {
                task.abort();
            }
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

    let stdout = collect_command_output_task(stdout_task).await?;
    let stderr = collect_command_output_task(stderr_task).await?;
    if let Some(task) = stdin_task {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(AgentError::Io(error)),
            Err(error) => {
                return Err(AgentError::WireGuard(format!(
                    "command stdin writer task failed: {error}"
                )))
            }
        }
    }

    Ok(BoundedCommandOutput {
        status,
        stdout,
        stderr,
    })
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
    stdout: LimitedCommandOutput,
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
    let text = command_diagnostic_component(String::from_utf8_lossy(&stderr.bytes).trim());
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
    let program = command_diagnostic_component(program);
    if args.is_empty() {
        program
    } else {
        let args = args
            .iter()
            .map(|arg| command_diagnostic_component(arg))
            .collect::<Vec<_>>()
            .join(" ");
        format!("{program} {args}")
    }
}

fn command_diagnostic_component(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
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
        warn_if_linux_netns_is_current(&self.namespace, "agent command runner");
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

    pub async fn configure_interface_address(&self, vpn_ip: VpnIp) -> Result<(), AgentError> {
        self.runner
            .run(LinuxCommand::new(
                "ip",
                [
                    "address".to_string(),
                    "replace".to_string(),
                    overlay_interface_cidr(vpn_ip),
                    "dev".to_string(),
                    self.interface.clone(),
                ],
            ))
            .await
    }

    pub async fn configure_interface_mtu(&self, mtu: u32) -> Result<(), AgentError> {
        self.runner
            .run(wireguard_interface_mtu_command(&self.interface, mtu))
            .await
    }

    pub async fn configure_interface_private_key(
        &self,
        private_key_b64: &str,
    ) -> Result<(), AgentError> {
        self.runner
            .run(wireguard_private_key_command(
                &self.interface,
                private_key_b64,
            )?)
            .await
    }

    pub async fn configure_interface_listen_port(
        &self,
        listen_port: u16,
    ) -> Result<(), AgentError> {
        self.runner
            .run(LinuxCommand::new(
                "wg",
                [
                    "set".to_string(),
                    self.interface.clone(),
                    "listen-port".to_string(),
                    listen_port.to_string(),
                ],
            ))
            .await
    }

    fn upsert_command(&self, config: &WireGuardPeerConfig) -> LinuxCommand {
        wireguard_upsert_peer_command(&self.interface, config)
    }

    async fn enable_interface_ipv6(&self, interface: &str) -> Result<(), AgentError> {
        if self
            .runner
            .run(wireguard_ipv6_enabled_command(interface)?)
            .await
            .is_ok()
        {
            return Ok(());
        }
        self.runner
            .run(wireguard_enable_ipv6_command(interface)?)
            .await
    }
}

#[async_trait]
impl<R> WireGuardBackend for LinuxWireGuardBackend<R>
where
    R: LinuxCommandRunner,
{
    async fn configure_private_key(&self, private_key_b64: &str) -> Result<(), AgentError> {
        self.configure_interface_private_key(private_key_b64).await
    }

    async fn recover_interface(
        &self,
        private_key_b64: &str,
        config: &WireGuardInterfaceConfig,
    ) -> Result<(), AgentError> {
        self.ensure_interface().await?;
        self.configure_interface_mtu(config.mtu).await?;
        self.configure_interface_private_key(private_key_b64)
            .await?;
        self.configure_interface_listen_port(config.listen_port)
            .await?;
        self.configure_interface_address(config.vpn_ip).await
    }

    async fn recreate_interface(
        &self,
        private_key_b64: &str,
        config: &WireGuardInterfaceConfig,
    ) -> Result<(), AgentError> {
        self.runner
            .run(wireguard_interface_delete_command(&self.interface))
            .await?;
        self.peer_public_keys.write().await.clear();
        self.recover_interface(private_key_b64, config).await
    }

    async fn enable_ipv6(&self) -> Result<(), AgentError> {
        self.enable_interface_ipv6(&self.interface).await
    }

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
        self.remove_peer_by_public_key(&public_key).await
    }

    async fn remove_peer_by_public_key(&self, public_key: &str) -> Result<(), AgentError> {
        self.runner
            .run(wireguard_remove_peer_command(&self.interface, public_key))
            .await?;
        self.peer_public_keys
            .write()
            .await
            .retain(|_, stored_key| stored_key != public_key);
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

    pub async fn configure_interface_private_key(
        &self,
        private_key_b64: &str,
    ) -> Result<(), AgentError> {
        self.runner
            .run(wireguard_private_key_command(
                &self.interface,
                private_key_b64,
            )?)
            .await
    }

    pub async fn configure_interface_listen_port(
        &self,
        listen_port: u16,
    ) -> Result<(), AgentError> {
        self.runner
            .run(LinuxCommand::new(
                "wg",
                [
                    "set".to_string(),
                    self.interface.clone(),
                    "listen-port".to_string(),
                    listen_port.to_string(),
                ],
            ))
            .await
    }

    pub async fn configure_interface_address(&self, vpn_ip: VpnIp) -> Result<(), AgentError> {
        self.runner
            .run(LinuxCommand::new(
                "ip",
                [
                    "address".to_string(),
                    "replace".to_string(),
                    overlay_interface_cidr(vpn_ip),
                    "dev".to_string(),
                    self.interface.clone(),
                ],
            ))
            .await
    }

    pub async fn configure_interface_mtu(&self, mtu: u32) -> Result<(), AgentError> {
        self.runner
            .run(wireguard_interface_mtu_command(&self.interface, mtu))
            .await
    }
}

#[async_trait]
impl<R> WireGuardBackend for UserspaceWireGuardBackend<R>
where
    R: LinuxCommandRunner,
{
    async fn configure_private_key(&self, private_key_b64: &str) -> Result<(), AgentError> {
        self.configure_interface_private_key(private_key_b64).await
    }

    async fn recover_interface(
        &self,
        private_key_b64: &str,
        config: &WireGuardInterfaceConfig,
    ) -> Result<(), AgentError> {
        self.ensure_interface().await?;
        self.configure_interface_mtu(config.mtu).await?;
        self.configure_interface_private_key(private_key_b64)
            .await?;
        self.configure_interface_listen_port(config.listen_port)
            .await?;
        self.configure_interface_address(config.vpn_ip).await
    }

    async fn enable_ipv6(&self) -> Result<(), AgentError> {
        if self
            .runner
            .run(wireguard_ipv6_enabled_command(&self.interface)?)
            .await
            .is_ok()
        {
            return Ok(());
        }
        self.runner
            .run(wireguard_enable_ipv6_command(&self.interface)?)
            .await
    }

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
        self.remove_peer_by_public_key(&public_key).await
    }

    async fn remove_peer_by_public_key(&self, public_key: &str) -> Result<(), AgentError> {
        self.runner
            .run(wireguard_remove_peer_command(&self.interface, public_key))
            .await?;
        self.peer_public_keys
            .write()
            .await
            .retain(|_, stored_key| stored_key != public_key);
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

fn wireguard_private_key_command(
    interface: &str,
    private_key_b64: &str,
) -> Result<LinuxCommand, AgentError> {
    let mut stdin = validated_wireguard_private_key(private_key_b64)?;
    stdin.push(b'\n');
    Ok(LinuxCommand::new("wg", ["set", interface, "private-key", "/dev/stdin"]).with_stdin(stdin))
}

fn validated_wireguard_private_key(value: &str) -> Result<Vec<u8>, AgentError> {
    let trimmed = value.trim();
    decode_wireguard_private_key_b64(trimmed).map_err(|error| {
        AgentError::WireGuard(format!("invalid WireGuard private key: {error}"))
    })?;
    Ok(trimmed.as_bytes().to_vec())
}

fn wireguard_remove_peer_command(interface: &str, public_key: &str) -> LinuxCommand {
    LinuxCommand::new("wg", ["set", interface, "peer", public_key, "remove"])
}

fn wireguard_interface_mtu_command(interface: &str, mtu: u32) -> LinuxCommand {
    LinuxCommand::new(
        "ip",
        [
            "link".to_string(),
            "set".to_string(),
            "dev".to_string(),
            interface.to_string(),
            "mtu".to_string(),
            mtu.to_string(),
        ],
    )
}

fn wireguard_interface_delete_command(interface: &str) -> LinuxCommand {
    LinuxCommand::new("ip", ["link", "delete", "dev", interface])
}

fn wireguard_ipv6_sysctl_path(interface: &str) -> Result<PathBuf, AgentError> {
    if interface.is_empty()
        || interface.len() > 15
        || interface == "."
        || interface == ".."
        || interface.as_bytes().contains(&0)
        || interface.contains('/')
    {
        return Err(AgentError::WireGuard(format!(
            "invalid WireGuard interface name `{interface}` for IPv6 configuration"
        )));
    }
    Ok(Path::new("/proc/sys/net/ipv6/conf")
        .join(interface)
        .join("disable_ipv6"))
}

fn wireguard_enable_ipv6_command(interface: &str) -> Result<LinuxCommand, AgentError> {
    let path = wireguard_ipv6_sysctl_path(interface)?;
    Ok(LinuxCommand::new("tee", [path.to_string_lossy().into_owned()]).with_stdin(b"0\n".to_vec()))
}

fn wireguard_ipv6_enabled_command(interface: &str) -> Result<LinuxCommand, AgentError> {
    let path = wireguard_ipv6_sysctl_path(interface)?;
    Ok(LinuxCommand::new(
        "grep",
        ["-F", "-x", "0", path.to_string_lossy().as_ref()],
    ))
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

    #[cfg(target_os = "linux")]
    pub async fn configure_interface_address(&self, vpn_ip: VpnIp) -> Result<(), AgentError> {
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

        let index = find_link_index(&handle, &self.interface)
            .await?
            .ok_or_else(|| {
                AgentError::WireGuard(format!(
                    "WireGuard interface {} was not visible before assigning local VPN address",
                    self.interface
                ))
            })?;
        let prefix_len = overlay_interface_prefix_len(vpn_ip.0);
        handle
            .address()
            .add(index, vpn_ip.0, prefix_len)
            .replace()
            .execute()
            .await
            .map_err(|error| {
                AgentError::WireGuard(format!(
                    "failed to assign local VPN address {}/{} to WireGuard interface {} through rtnetlink: {error}",
                    vpn_ip.0, prefix_len, self.interface
                ))
            })
    }

    #[cfg(target_os = "linux")]
    pub async fn configure_interface_mtu(&self, mtu: u32) -> Result<(), AgentError> {
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

        let index = find_link_index(&handle, &self.interface)
            .await?
            .ok_or_else(|| {
                AgentError::WireGuard(format!(
                    "WireGuard interface {} was not visible before setting its MTU",
                    self.interface
                ))
            })?;
        handle
            .link()
            .set(LinkUnspec::new_with_index(index).mtu(mtu).build())
            .execute()
            .await
            .map_err(|error| {
                AgentError::WireGuard(format!(
                    "failed to set WireGuard interface {} MTU to {mtu} through rtnetlink: {error}",
                    self.interface
                ))
            })
    }

    #[cfg(target_os = "linux")]
    pub async fn configure_interface_private_key(
        &self,
        private_key_b64: &str,
    ) -> Result<(), AgentError> {
        apply_wireguard_netlink(
            &self.interface,
            self.namespace.as_ref(),
            vec![WireguardAttribute::PrivateKey(parse_wireguard_private_key(
                private_key_b64,
            )?)],
        )
        .await
    }

    #[cfg(target_os = "linux")]
    pub async fn configure_interface_listen_port(
        &self,
        listen_port: u16,
    ) -> Result<(), AgentError> {
        apply_wireguard_netlink(
            &self.interface,
            self.namespace.as_ref(),
            vec![WireguardAttribute::ListenPort(listen_port)],
        )
        .await
    }

    #[cfg(target_os = "linux")]
    pub async fn delete_interface(&self) -> Result<(), AgentError> {
        let (connection, handle, _) = with_netlink_namespace(self.namespace.as_ref(), || {
            rtnetlink::new_connection_with_socket::<LinuxNetlinkSocket>()
        })
        .map_err(|error| {
            AgentError::WireGuard(format!(
                "failed to open route netlink connection for deleting WireGuard interface {}{}: {error}",
                self.interface,
                wireguard_namespace_suffix(self.namespace.as_ref())
            ))
        })?;
        tokio::spawn(connection);

        let index = find_link_index(&handle, &self.interface)
            .await?
            .ok_or_else(|| {
                AgentError::WireGuard(format!(
                    "WireGuard interface {} was not visible before replacement",
                    self.interface
                ))
            })?;
        handle.link().del(index).execute().await.map_err(|error| {
            AgentError::WireGuard(format!(
                "failed to delete WireGuard interface {} through rtnetlink: {error}",
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

    #[cfg(not(target_os = "linux"))]
    pub async fn configure_interface_address(&self, _vpn_ip: VpnIp) -> Result<(), AgentError> {
        Err(AgentError::WireGuard(
            "kernel WireGuard netlink backend is only supported on Linux".to_string(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn configure_interface_mtu(&self, _mtu: u32) -> Result<(), AgentError> {
        Err(AgentError::WireGuard(
            "kernel WireGuard netlink backend is only supported on Linux".to_string(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn configure_interface_private_key(
        &self,
        _private_key_b64: &str,
    ) -> Result<(), AgentError> {
        Err(AgentError::WireGuard(
            "kernel WireGuard netlink backend is only supported on Linux".to_string(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn configure_interface_listen_port(
        &self,
        _listen_port: u16,
    ) -> Result<(), AgentError> {
        Err(AgentError::WireGuard(
            "kernel WireGuard netlink backend is only supported on Linux".to_string(),
        ))
    }
}

fn overlay_interface_cidr(vpn_ip: VpnIp) -> String {
    format!("{}/{}", vpn_ip.0, overlay_interface_prefix_len(vpn_ip.0))
}

fn overlay_interface_prefix_len(vpn_ip: IpAddr) -> u8 {
    match vpn_ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl WireGuardBackend for KernelWireGuardBackend {
    async fn configure_private_key(&self, private_key_b64: &str) -> Result<(), AgentError> {
        self.configure_interface_private_key(private_key_b64).await
    }

    async fn recover_interface(
        &self,
        private_key_b64: &str,
        config: &WireGuardInterfaceConfig,
    ) -> Result<(), AgentError> {
        self.ensure_interface().await?;
        self.configure_interface_mtu(config.mtu).await?;
        self.configure_interface_private_key(private_key_b64)
            .await?;
        self.configure_interface_listen_port(config.listen_port)
            .await?;
        self.configure_interface_address(config.vpn_ip).await
    }

    async fn recreate_interface(
        &self,
        private_key_b64: &str,
        config: &WireGuardInterfaceConfig,
    ) -> Result<(), AgentError> {
        self.delete_interface().await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        self.peer_public_keys.write().await.clear();
        self.recover_interface(private_key_b64, config).await
    }

    async fn enable_ipv6(&self) -> Result<(), AgentError> {
        let path = wireguard_ipv6_sysctl_path(&self.interface)?;
        with_linux_network_namespace(self.namespace.as_ref(), || {
            match std::fs::read_to_string(&path) {
                Ok(value) if value.trim() == "0" => Ok(()),
                Ok(_) => std::fs::write(&path, b"0\n"),
                Err(error) => Err(error),
            }
        })
        .map_err(|error| {
            AgentError::WireGuard(format!(
                "failed to enable IPv6 on WireGuard interface {} through {}: {error}",
                self.interface,
                path.display()
            ))
        })
    }

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
        self.remove_peer_by_public_key(&encode_bytes(&public_key))
            .await
    }

    async fn remove_peer_by_public_key(&self, public_key: &str) -> Result<(), AgentError> {
        let public_key = parse_wireguard_public_key(public_key)?;
        apply_wireguard_netlink(
            &self.interface,
            self.namespace.as_ref(),
            vec![WireguardAttribute::Peers(vec![WireguardPeer(vec![
                WireguardPeerAttribute::PublicKey(public_key),
                WireguardPeerAttribute::Flags(WireguardPeerFlags::RemoveMe),
            ])])],
        )
        .await?;
        self.peer_public_keys
            .write()
            .await
            .retain(|_, stored_key| stored_key != &public_key);
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl WireGuardBackend for KernelWireGuardBackend {
    async fn configure_private_key(&self, private_key_b64: &str) -> Result<(), AgentError> {
        self.configure_interface_private_key(private_key_b64).await
    }

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

    async fn remove_peer_by_public_key(&self, _public_key: &str) -> Result<(), AgentError> {
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
    let mut links = handle.link().get().execute();
    while let Some(link) = links.try_next().await.map_err(|error| {
        AgentError::WireGuard(format!(
            "failed to list interfaces while looking up WireGuard interface {name} through rtnetlink: {error}"
        ))
    })? {
        let matches_name = link.attributes.iter().any(|attribute| {
            matches!(
                attribute,
                rtnetlink::packet_route::link::LinkAttribute::IfName(link_name)
                    if link_name == name
            )
        });
        if matches_name {
            return Ok(Some(link.header.index));
        }
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
fn wireguard_namespace_suffix(namespace: Option<&LinuxNetworkNamespace>) -> String {
    namespace
        .map(|namespace| format!(" in linux network namespace `{}`", namespace.name()))
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn parse_wireguard_public_key(value: &str) -> Result<[u8; 32], AgentError> {
    decode_wireguard_public_key_b64(value)
        .map_err(|error| AgentError::WireGuard(format!("invalid WireGuard public key: {error}")))
}

#[cfg(target_os = "linux")]
fn parse_wireguard_private_key(value: &str) -> Result<[u8; 32], AgentError> {
    decode_wireguard_private_key_b64(value.trim())
        .map_err(|error| AgentError::WireGuard(format!("invalid WireGuard private key: {error}")))
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

#[cfg(target_os = "linux")]
async fn query_wireguard_peer_telemetry_netlink(
    interface: &str,
    namespace: Option<&LinuxNetworkNamespace>,
) -> Result<BTreeMap<String, WireGuardPeerTelemetry>, AgentError> {
    let (connection, mut handle, _) = with_netlink_namespace(namespace, || {
        genetlink::new_connection_with_socket::<LinuxNetlinkSocket>()
    })
    .map_err(|error| {
        AgentError::WireGuard(format!(
            "failed to open generic netlink connection for WireGuard telemetry on interface {interface}{}: {error}",
            wireguard_namespace_suffix(namespace)
        ))
    })?;
    tokio::spawn(connection);

    let genlmsg = GenlMessage::from_payload(WireguardMessage {
        cmd: WireguardCmd::GetDevice,
        attributes: vec![WireguardAttribute::IfName(interface.to_string())],
    });
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let mut responses = handle.request(nlmsg).await.map_err(|error| {
        AgentError::WireGuard(format!(
            "failed to query WireGuard telemetry for interface {interface}: {error}"
        ))
    })?;
    let mut peers = BTreeMap::new();
    while let Some(response) = responses.next().await {
        let response = response.map_err(|error| {
            AgentError::WireGuard(format!(
                "failed to decode WireGuard telemetry response for interface {interface}: {error}"
            ))
        })?;
        match response.payload {
            NetlinkPayload::InnerMessage(message) => {
                for attribute in message.payload.attributes {
                    let WireguardAttribute::Peers(netlink_peers) = attribute else {
                        continue;
                    };
                    for peer in netlink_peers {
                        let telemetry = wireguard_netlink_peer_telemetry(&peer)?;
                        peers
                            .entry(telemetry.public_key_b64.clone())
                            .and_modify(|current: &mut WireGuardPeerTelemetry| {
                                current.merge(telemetry.clone());
                            })
                            .or_insert(telemetry);
                    }
                }
            }
            NetlinkPayload::Error(error) if error.code.is_some() => {
                return Err(AgentError::WireGuard(format!(
                    "WireGuard telemetry query for interface {interface} failed: {}",
                    error.to_io()
                )));
            }
            NetlinkPayload::Error(_) | NetlinkPayload::Done(_) => break,
            _ => {}
        }
    }
    Ok(peers)
}

#[cfg(target_os = "linux")]
fn wireguard_netlink_peer_telemetry(
    peer: &WireguardPeer,
) -> Result<WireGuardPeerTelemetry, AgentError> {
    let public_key = peer.iter().find_map(|attribute| {
        if let WireguardPeerAttribute::PublicKey(public_key) = attribute {
            Some(*public_key)
        } else {
            None
        }
    });
    let public_key = public_key.ok_or_else(|| {
        AgentError::WireGuard(
            "WireGuard netlink telemetry peer did not include a public key".to_string(),
        )
    })?;
    let public_key_b64 = encode_bytes(&public_key);
    validate_wireguard_public_key(&public_key_b64)?;
    let mut telemetry = WireGuardPeerTelemetry::new(public_key_b64);
    for attribute in peer.iter() {
        match attribute {
            WireguardPeerAttribute::Endpoint(endpoint) => {
                telemetry.endpoint = Some(endpoint.to_string());
            }
            WireguardPeerAttribute::LastHandshake(handshake) => {
                telemetry.latest_handshake_at =
                    wireguard_handshake_timestamp(handshake.seconds, handshake.nano_seconds)?;
            }
            WireguardPeerAttribute::RxBytes(rx_bytes) => telemetry.rx_bytes = *rx_bytes,
            WireguardPeerAttribute::TxBytes(tx_bytes) => telemetry.tx_bytes = *tx_bytes,
            _ => {}
        }
    }
    Ok(telemetry)
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

    async fn remove_peer_by_public_key(&self, public_key: &str) -> Result<(), AgentError> {
        self.peers
            .write()
            .await
            .retain(|_, config| config.public_key != public_key);
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

    async fn apply_bootstrap_peer_map_update(
        &self,
        peer_map: PeerMap,
    ) -> Result<PeerMapApplySummary, AgentError> {
        self.apply_peer_map_update(peer_map).await
    }
}

#[async_trait]
pub trait PeerEndpointResolver: Send + Sync + std::fmt::Debug {
    async fn prepare_for_peer_map(&self) -> Result<(), AgentError> {
        Ok(())
    }

    async fn endpoint_for_peer(&self, peer: &NodeRecord) -> Result<Option<String>, AgentError>;

    async fn persistent_keepalive_seconds_for_peer(
        &self,
        _peer: &NodeRecord,
        endpoint: Option<&str>,
    ) -> Result<Option<u16>, AgentError> {
        Ok(endpoint.map(|_| 25))
    }
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
    prepared_overlay_shortcuts: Arc<tokio::sync::RwLock<Option<Arc<OverlayShortcutSnapshot>>>>,
}

impl RuntimePeerEndpointResolver {
    pub fn new(runtime: Arc<AgentRuntime>) -> Self {
        Self {
            runtime,
            relay_forwarder_endpoint: None,
            prepared_overlay_shortcuts: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    pub fn with_relay_forwarder_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.relay_forwarder_endpoint = Some(endpoint);
        self
    }
}

#[async_trait]
impl PeerEndpointResolver for RuntimePeerEndpointResolver {
    async fn prepare_for_peer_map(&self) -> Result<(), AgentError> {
        *self.prepared_overlay_shortcuts.write().await =
            Some(self.runtime.overlay_shortcut_snapshot().await);
        Ok(())
    }

    async fn endpoint_for_peer(&self, peer: &NodeRecord) -> Result<Option<String>, AgentError> {
        let local_candidates = self.runtime.status().await.candidates;
        let overlay_endpoint = self
            .runtime
            .overlay_forwarder_endpoint(&peer.node_id)
            .await
            .map(|endpoint| endpoint.to_string());
        let prepared_overlay_shortcuts = self.prepared_overlay_shortcuts.read().await.clone();
        let overlay_shortcuts = match prepared_overlay_shortcuts {
            Some(snapshot) => snapshot,
            None => self.runtime.overlay_shortcut_snapshot().await,
        };
        if overlay_shortcuts.requires_overlay_forwarder(&peer.node_id) {
            return Ok(overlay_endpoint);
        }
        if let Some(probe) = self
            .runtime
            .pending_direct_path_probe(&peer.node_id)
            .await
            .filter(|probe| probe.is_active_at(Utc::now()))
        {
            if probe.selected_state == PathState::DirectNatTraversal {
                if let Some(candidate) =
                    preferred_peer_local_udp_candidate(&local_candidates, &peer.endpoint_candidates)
                {
                    return Ok(wireguard_endpoint_for_candidate(&candidate, &peer.node_id));
                }
            }
            return Ok(wireguard_endpoint_for_candidate(
                &probe.selected_candidate,
                &peer.node_id,
            ));
        }
        let path = self.runtime.path_record_for_peer(&peer.node_id).await;
        let Some(path) = path else {
            return Ok(overlay_endpoint.or_else(|| {
                preferred_peer_local_udp_candidate(&local_candidates, &peer.endpoint_candidates)
                    .and_then(|candidate| {
                        wireguard_endpoint_for_candidate(&candidate, &peer.node_id)
                    })
                    .or_else(|| preferred_endpoint(peer))
            }));
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
                .map(|endpoint| endpoint.to_string())
                .or(overlay_endpoint)),
            PathState::Unreachable => Ok(overlay_endpoint),
            PathState::DirectNatTraversal => Ok(preferred_peer_local_udp_candidate(
                &local_candidates,
                &peer.endpoint_candidates,
            )
            .and_then(|candidate| wireguard_endpoint_for_candidate(&candidate, &peer.node_id))
            .or_else(|| {
                path.selected_candidate.as_ref().and_then(|candidate| {
                    wireguard_endpoint_for_candidate(candidate, &peer.node_id)
                })
            })
            .or_else(|| preferred_endpoint(peer))),
            _ => Ok(path
                .selected_candidate
                .as_ref()
                .and_then(|candidate| wireguard_endpoint_for_candidate(candidate, &peer.node_id))
                .or_else(|| preferred_endpoint(peer))),
        }
    }

    async fn persistent_keepalive_seconds_for_peer(
        &self,
        peer: &NodeRecord,
        endpoint: Option<&str>,
    ) -> Result<Option<u16>, AgentError> {
        if endpoint.is_some()
            && self
                .runtime
                .pending_direct_path_probe(&peer.node_id)
                .await
                .is_some_and(|probe| probe.is_active_at(Utc::now()))
        {
            return Ok(Some(DIRECT_PATH_PROBE_KEEPALIVE_SECONDS));
        }
        Ok(endpoint.map(|_| 25))
    }
}

/// Select a local UDP candidate only when the peer's reflexive endpoint is
/// private and both local addresses share a directly routable subnet.
pub fn preferred_local_udp_candidate(
    local_candidates: &[EndpointCandidate],
    peer_candidates: &[EndpointCandidate],
) -> Option<EndpointCandidate> {
    local_candidates
        .iter()
        .filter(|candidate| {
            candidate.kind == EndpointCandidateKind::LocalUdp
                && endpoint_addr_is_usable(candidate.addr)
        })
        .filter(|candidate| {
            peer_candidates.iter().any(|peer_candidate| {
                peer_candidate.kind == EndpointCandidateKind::LocalUdp
                    && endpoint_addr_is_usable(peer_candidate.addr)
                    && private_ip_addrs_share_subnet(candidate.addr.ip(), peer_candidate.addr.ip())
            })
        })
        .min_by(|left, right| {
            left.cost
                .cmp(&right.cost)
                .then_with(|| right.priority.cmp(&left.priority))
        })
        .cloned()
}

/// Select the peer-side local UDP candidate that is directly routable from a
/// local UDP candidate on a private subnet.
pub fn preferred_peer_local_udp_candidate(
    local_candidates: &[EndpointCandidate],
    peer_candidates: &[EndpointCandidate],
) -> Option<EndpointCandidate> {
    peer_candidates
        .iter()
        .filter(|peer_candidate| {
            peer_candidate.kind == EndpointCandidateKind::LocalUdp
                && endpoint_addr_is_usable(peer_candidate.addr)
        })
        .filter(|peer_candidate| {
            local_candidates.iter().any(|local_candidate| {
                local_candidate.kind == EndpointCandidateKind::LocalUdp
                    && endpoint_addr_is_usable(local_candidate.addr)
                    && private_ip_addrs_share_subnet(
                        local_candidate.addr.ip(),
                        peer_candidate.addr.ip(),
                    )
            })
        })
        .min_by(|left, right| {
            left.cost
                .cmp(&right.cost)
                .then_with(|| right.priority.cmp(&left.priority))
        })
        .cloned()
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
    wireguard_peer_inventory: Option<Arc<dyn WireGuardPeerInventorySource>>,
    lazy_runtime: Option<Arc<AgentRuntime>>,
    wireguard_interface_config: Option<WireGuardInterfaceConfig>,
    route_mtu_lock: Option<u32>,
    apply_lock: tokio::sync::Mutex<()>,
    applied_peers: tokio::sync::RwLock<BTreeMap<NodeId, String>>,
    applied_routes: tokio::sync::RwLock<BTreeMap<NodeId, Vec<Route>>>,
    applied_active_peers: tokio::sync::RwLock<BTreeSet<NodeId>>,
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
            wireguard_peer_inventory: None,
            lazy_runtime: None,
            wireguard_interface_config: None,
            route_mtu_lock: None,
            apply_lock: tokio::sync::Mutex::new(()),
            applied_peers: tokio::sync::RwLock::new(BTreeMap::new()),
            applied_routes: tokio::sync::RwLock::new(BTreeMap::new()),
            applied_active_peers: tokio::sync::RwLock::new(BTreeSet::new()),
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

    pub fn with_wireguard_interface_recovery(mut self, config: WireGuardInterfaceConfig) -> Self {
        self.wireguard_interface_config = Some(config);
        self
    }

    pub fn with_route_mtu_lock(mut self, mtu: u32) -> Self {
        self.route_mtu_lock = Some(mtu);
        self
    }

    pub fn with_wireguard_peer_inventory(
        mut self,
        inventory: Arc<dyn WireGuardPeerInventorySource>,
    ) -> Self {
        self.wireguard_peer_inventory = Some(inventory);
        self
    }

    pub async fn apply_peer_map(
        &self,
        peer_map: PeerMap,
    ) -> Result<PeerMapApplySummary, AgentError> {
        let _apply_guard = self.apply_lock.lock().await;
        if let Some(runtime) = &self.lazy_runtime {
            self.configure_local_wireguard(&runtime.state().wireguard_private_key_b64)
                .await?;
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
        let peer_map_public_keys = peer_map
            .peers
            .iter()
            .map(|peer| (peer.node_id.clone(), peer.wireguard_public_key.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut peers_to_remove = BTreeSet::new();
        if let Some(runtime) = &self.lazy_runtime {
            peers_to_remove.extend(runtime.take_idle_peers_to_close(now).await);
        }
        self.endpoint_resolver.prepare_for_peer_map().await?;
        let stale_peers = {
            let applied_peers = self.applied_peers.read().await;
            applied_peers
                .keys()
                .filter(|peer| !peer_map_ids.contains(*peer))
                .cloned()
                .collect::<Vec<_>>()
        };
        peers_to_remove.extend(stale_peers);
        let changed_key_peers = {
            let applied_peers = self.applied_peers.read().await;
            applied_peers
                .iter()
                .filter(|(peer, public_key)| {
                    peer_map_public_keys
                        .get(*peer)
                        .is_some_and(|desired| desired != *public_key)
                })
                .map(|(peer, _)| peer.clone())
                .collect::<Vec<_>>()
        };
        peers_to_remove.extend(changed_key_peers);

        let mut desired_active_peers = Vec::new();
        let mut desired_passive_peers = Vec::new();
        for peer in &peer_map.peers {
            if let Some(runtime) = &self.lazy_runtime {
                if !runtime.should_connect_peer(peer).await {
                    desired_passive_peers.push(peer);
                    continue;
                }
            }
            desired_active_peers.push(peer);
        }
        let desired_active_peer_ids = desired_active_peers
            .iter()
            .map(|peer| peer.node_id.clone())
            .collect::<BTreeSet<_>>();
        let mut advertised_public_keys = BTreeSet::new();
        let local_public_key = self
            .lazy_runtime
            .as_ref()
            .map(|runtime| runtime.state().wireguard_public_key_b64);
        for peer in &peer_map.peers {
            if self.wireguard_peer_inventory.is_some() {
                validate_wireguard_public_key(&peer.wireguard_public_key)?;
                if local_public_key.as_deref() == Some(peer.wireguard_public_key.as_str()) {
                    return Err(AgentError::WireGuard(format!(
                        "peer map assigns the local WireGuard public key to remote peer {}",
                        peer.node_id
                    )));
                }
                if !advertised_public_keys.insert(peer.wireguard_public_key.clone()) {
                    return Err(AgentError::WireGuard(format!(
                        "peer map assigns WireGuard public key {} to multiple peers",
                        peer.wireguard_public_key
                    )));
                }
            } else {
                advertised_public_keys.insert(peer.wireguard_public_key.clone());
            }
        }
        let mut passive_public_keys = BTreeMap::new();
        let mut desired_public_keys = desired_active_peers
            .iter()
            .map(|peer| peer.wireguard_public_key.clone())
            .collect::<BTreeSet<_>>();
        for peer in &desired_passive_peers {
            let passive_public_key = passive_wireguard_public_key(&peer.wireguard_public_key)?;
            if local_public_key.as_deref() == Some(passive_public_key.as_str())
                || !desired_public_keys.insert(passive_public_key.clone())
            {
                return Err(AgentError::WireGuard(format!(
                    "passive WireGuard quarantine public key collision for peer {}",
                    peer.node_id
                )));
            }
            passive_public_keys.insert(peer.node_id.clone(), passive_public_key);
        }
        let overlay_quarantine = match (&self.lazy_runtime, local_public_key.as_deref()) {
            (Some(runtime), Some(local_public_key)) => runtime
                .neighbor_map_snapshot()
                .await
                .map(|neighbor_map| {
                    let public_key = overlay_quarantine_wireguard_public_key(local_public_key)?;
                    if !desired_public_keys.insert(public_key.clone()) {
                        return Err(AgentError::WireGuard(
                            "bounded-overlay quarantine public key collision".to_string(),
                        ));
                    }
                    let mut cidrs = BTreeSet::from([neighbor_map.vpn_cidr]);
                    cidrs.extend(neighbor_map.aggregate_routes.iter().map(|route| route.cidr));
                    Ok((public_key, cidrs))
                })
                .transpose()?,
            _ => None,
        };
        let actual_public_keys = match &self.wireguard_peer_inventory {
            Some(inventory) => Some(inventory.public_keys().await?),
            None => None,
        };

        let local_route_cidrs = match &self.lazy_runtime {
            Some(runtime) => runtime
                .local_advertised_routes()
                .await
                .into_iter()
                .map(|route| route.cidr)
                .collect(),
            None => BTreeSet::new(),
        };
        let selected_advertised_routes =
            select_peer_advertised_routes(&desired_active_peers, &local_route_cidrs);
        let mut desired_peer_routes = BTreeMap::new();
        let mut routes = Vec::new();
        for peer in &peer_map.peers {
            let peer_routes = peer_routes_for_record(
                peer,
                if desired_active_peer_ids.contains(&peer.node_id) {
                    selected_advertised_routes
                        .get(&peer.node_id)
                        .map(Vec::as_slice)
                        .unwrap_or_default()
                } else {
                    &[]
                },
            )?;
            routes.extend(peer_routes.iter().cloned());
            desired_peer_routes.insert(peer.node_id.clone(), peer_routes);
        }
        let selected_route_cidrs = routes
            .iter()
            .map(|route| route.cidr)
            .collect::<BTreeSet<_>>();
        let overlay_quarantine = overlay_quarantine.map(|(public_key, mut cidrs)| {
            cidrs.retain(|cidr| {
                !local_route_cidrs.contains(cidr) && !selected_route_cidrs.contains(cidr)
            });
            (public_key, cidrs)
        });
        if let Some((_, cidrs)) = &overlay_quarantine {
            let quarantine_node = NodeId::from_string(OVERLAY_QUARANTINE_NODE_ID);
            routes.extend(cidrs.iter().enumerate().map(|(index, cidr)| Route {
                id: format!("overlay-quarantine-{index}"),
                cidr: *cidr,
                advertised_by: quarantine_node.clone(),
                via: Some(quarantine_node.clone()),
                metric: u32::MAX,
                tags: BTreeSet::new(),
            }));
        }
        let desired_route_plan = RoutePlan {
            owner: RoutePlanOwner::PeerMap,
            interface: self.interface.clone(),
            mtu_lock: self.route_mtu_lock,
            routes,
            policy_rules: Vec::new(),
        };
        validate_route_plan(&desired_route_plan)?;
        if desired_route_plan
            .routes
            .iter()
            .any(|route| route.cidr.addr().is_ipv6())
        {
            self.configure_local_wireguard_ipv6().await?;
        }
        let desired_managed_inventory = desired_managed_route_inventory(&desired_route_plan)?;
        let actual_managed_inventory = self
            .route_manager
            .managed_route_inventory(&desired_route_plan)
            .await?;

        let mut peers_removed = 0;
        let mut routes_removed = 0;
        if let Some(actual_managed_inventory) = &actual_managed_inventory {
            let stale_inventory = actual_managed_inventory.difference(&desired_managed_inventory);
            if !stale_inventory.is_empty() {
                self.route_manager
                    .remove_managed_route_inventory(&self.interface, &stale_inventory)
                    .await?;
                routes_removed += stale_inventory.routes.len();
            }
        }
        let mut removed_public_keys = BTreeSet::new();
        for peer in peers_to_remove {
            let applied_public_key = self.applied_peers.read().await.get(&peer).cloned();
            let Some(applied_public_key) = applied_public_key else {
                continue;
            };
            let configured_public_key = if self.applied_active_peers.read().await.contains(&peer) {
                applied_public_key.clone()
            } else {
                passive_wireguard_public_key(&applied_public_key)?
            };
            let routes_to_remove = self
                .applied_routes
                .read()
                .await
                .get(&peer)
                .cloned()
                .unwrap_or_default();
            if actual_managed_inventory.is_none() && !routes_to_remove.is_empty() {
                self.route_manager
                    .remove_routes(RoutePlan {
                        owner: RoutePlanOwner::PeerMap,
                        interface: self.interface.clone(),
                        mtu_lock: self.route_mtu_lock,
                        routes: routes_to_remove.clone(),
                        policy_rules: Vec::new(),
                    })
                    .await?;
                routes_removed += routes_to_remove.len();
                self.applied_routes.write().await.remove(&peer);
            }
            match &actual_public_keys {
                Some(actual_public_keys) if actual_public_keys.contains(&configured_public_key) => {
                    self.wireguard
                        .remove_peer_by_public_key(&configured_public_key)
                        .await?;
                    removed_public_keys.insert(configured_public_key);
                }
                Some(_) => {}
                None => self.wireguard.remove_peer(&peer).await?,
            }
            self.applied_peers.write().await.remove(&peer);
            self.applied_routes.write().await.remove(&peer);
            self.applied_active_peers.write().await.remove(&peer);
            peers_removed += 1;
        }

        if let Some(actual_public_keys) = actual_public_keys.as_ref() {
            let unexpected_public_keys = actual_public_keys
                .iter()
                .filter(|public_key| !desired_public_keys.contains(*public_key))
                .filter(|public_key| !removed_public_keys.contains(*public_key))
                .cloned()
                .collect::<Vec<_>>();
            for public_key in unexpected_public_keys {
                self.wireguard
                    .remove_peer_by_public_key(&public_key)
                    .await?;
                removed_public_keys.insert(public_key);
                peers_removed += 1;
            }
        }
        let mut peers_applied = 0;

        if let Some((public_key, cidrs)) = &overlay_quarantine {
            self.wireguard
                .upsert_peer(WireGuardPeerConfig {
                    peer: NodeId::from_string(OVERLAY_QUARANTINE_NODE_ID),
                    public_key: public_key.clone(),
                    endpoint: Some(PASSIVE_WIREGUARD_HOLD_ENDPOINT.to_string()),
                    allowed_ips: cidrs.iter().map(ToString::to_string).collect(),
                    persistent_keepalive_seconds: None,
                })
                .await?;
        }

        for peer in desired_passive_peers {
            let passive_public_key =
                passive_public_keys
                    .get(&peer.node_id)
                    .cloned()
                    .ok_or_else(|| {
                        AgentError::WireGuard(format!(
                            "missing passive WireGuard quarantine key for peer {}",
                            peer.node_id
                        ))
                    })?;
            let already_passive = {
                let applied_peers = self.applied_peers.read().await;
                applied_peers.get(&peer.node_id) == Some(&peer.wireguard_public_key)
                    && !self
                        .applied_active_peers
                        .read()
                        .await
                        .contains(&peer.node_id)
                    && actual_public_keys
                        .as_ref()
                        .is_none_or(|public_keys| public_keys.contains(&passive_public_key))
            };
            if already_passive {
                continue;
            }

            self.wireguard
                .upsert_peer(WireGuardPeerConfig {
                    peer: peer.node_id.clone(),
                    public_key: passive_public_key,
                    endpoint: Some(PASSIVE_WIREGUARD_HOLD_ENDPOINT.to_string()),
                    allowed_ips: vec![peer_overlay_cidr(&peer.vpn_ip)],
                    persistent_keepalive_seconds: None,
                })
                .await?;
            self.applied_peers
                .write()
                .await
                .insert(peer.node_id.clone(), peer.wireguard_public_key.clone());
            self.applied_active_peers
                .write()
                .await
                .remove(&peer.node_id);
            peers_applied += 1;
        }

        for peer in desired_active_peers {
            let _endpoint_update_guard = if let Some(runtime) = self.lazy_runtime.as_ref() {
                Some(runtime.wireguard_endpoint_update_guard().await)
            } else {
                None
            };
            let was_passive = {
                let applied_peers = self.applied_peers.read().await;
                applied_peers.get(&peer.node_id) == Some(&peer.wireguard_public_key)
                    && !self
                        .applied_active_peers
                        .read()
                        .await
                        .contains(&peer.node_id)
            };
            if was_passive {
                let passive_public_key = passive_wireguard_public_key(&peer.wireguard_public_key)?;
                let removed = match actual_public_keys.as_ref() {
                    Some(public_keys)
                        if public_keys.contains(&passive_public_key)
                            && !removed_public_keys.contains(&passive_public_key) =>
                    {
                        self.wireguard
                            .remove_peer_by_public_key(&passive_public_key)
                            .await?;
                        true
                    }
                    Some(_) => false,
                    None => {
                        self.wireguard.remove_peer(&peer.node_id).await?;
                        true
                    }
                };
                self.applied_peers.write().await.remove(&peer.node_id);
                self.applied_active_peers
                    .write()
                    .await
                    .remove(&peer.node_id);
                peers_removed += usize::from(removed);
            }
            let desired_routes =
                desired_peer_routes
                    .get(&peer.node_id)
                    .cloned()
                    .ok_or_else(|| {
                        AgentError::RoutePlanning(format!(
                            "missing desired route plan for peer {}",
                            peer.node_id
                        ))
                    })?;
            let allowed_ip = peer_overlay_cidr(&peer.vpn_ip);
            let mut allowed_ips = vec![allowed_ip];
            allowed_ips.extend(
                desired_routes
                    .iter()
                    .skip(1)
                    .map(|route| route.cidr.to_string()),
            );
            let endpoint = self.endpoint_resolver.endpoint_for_peer(peer).await?;
            let persistent_keepalive_seconds = self
                .endpoint_resolver
                .persistent_keepalive_seconds_for_peer(peer, endpoint.as_deref())
                .await?;
            self.wireguard
                .upsert_peer(WireGuardPeerConfig {
                    peer: peer.node_id.clone(),
                    public_key: peer.wireguard_public_key.clone(),
                    endpoint: endpoint.clone(),
                    allowed_ips,
                    persistent_keepalive_seconds,
                })
                .await?;
            self.applied_peers
                .write()
                .await
                .insert(peer.node_id.clone(), peer.wireguard_public_key.clone());
            peers_applied += 1;

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
            if actual_managed_inventory.is_none() && !routes_to_remove.is_empty() {
                self.route_manager
                    .remove_routes(RoutePlan {
                        owner: RoutePlanOwner::PeerMap,
                        interface: self.interface.clone(),
                        mtu_lock: self.route_mtu_lock,
                        routes: routes_to_remove.clone(),
                        policy_rules: Vec::new(),
                    })
                    .await?;
                routes_removed += routes_to_remove.len();
                if let Some(applied) = self.applied_routes.write().await.get_mut(&peer.node_id) {
                    applied.retain(|route| !routes_to_remove.contains(route));
                }
            }
        }

        let routes_applied = desired_route_plan.routes.len();
        if routes_applied > 0 {
            self.route_manager.apply_routes(desired_route_plan).await?;
        }
        *self.applied_routes.write().await = desired_peer_routes;
        *self.applied_active_peers.write().await = desired_active_peer_ids;

        if let Some(runtime) = &self.lazy_runtime {
            runtime.record_peer_map_snapshot(peer_map).await;
        }

        Ok(PeerMapApplySummary {
            peers_applied,
            peers_removed,
            routes_applied,
            routes_removed,
        })
    }

    async fn configure_local_wireguard(&self, private_key_b64: &str) -> Result<(), AgentError> {
        let initial_error = match self.wireguard.configure_private_key(private_key_b64).await {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        let Some(config) = self.wireguard_interface_config.as_ref() else {
            return Err(initial_error);
        };
        self.wireguard
            .recover_interface(private_key_b64, config)
            .await
            .map_err(|recovery_error| {
                AgentError::WireGuard(format!(
                    "WireGuard interface {} configuration failed ({initial_error}); recovery failed ({recovery_error})",
                    self.interface
                ))
            })
    }

    async fn configure_local_wireguard_ipv6(&self) -> Result<(), AgentError> {
        let initial_error = match self.wireguard.enable_ipv6().await {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        let Some(runtime) = self.lazy_runtime.as_ref() else {
            return Err(initial_error);
        };
        let Some(config) = self.wireguard_interface_config.as_ref() else {
            return Err(initial_error);
        };
        let private_key_b64 = runtime.state().wireguard_private_key_b64;
        self.wireguard
            .recreate_interface(&private_key_b64, config)
            .await
            .map_err(|recovery_error| {
                AgentError::WireGuard(format!(
                    "WireGuard interface {} IPv6 initialization failed ({initial_error}); interface recreation failed ({recovery_error})",
                    self.interface
                ))
            })?;
        self.wireguard.enable_ipv6().await.map_err(|retry_error| {
            AgentError::WireGuard(format!(
                "WireGuard interface {} IPv6 initialization failed ({initial_error}); retry after interface recreation failed ({retry_error})",
                self.interface
            ))
        })
    }

    /// Adds only the direct peers and host routes needed to regain the control plane. Unlike an
    /// authoritative peer-map application, this deliberately leaves existing peers and routes
    /// untouched until a fresh signed map can reconcile the complete data plane.
    pub async fn apply_bootstrap_peer_map(
        &self,
        peer_map: PeerMap,
    ) -> Result<PeerMapApplySummary, AgentError> {
        let _apply_guard = self.apply_lock.lock().await;
        let local_state = self
            .lazy_runtime
            .as_ref()
            .ok_or_else(|| {
                AgentError::InvalidState(
                    "bootstrap peer recovery requires the agent runtime".to_string(),
                )
            })?
            .state();
        let expected_cluster = local_state
            .registered_node
            .as_ref()
            .map(|node| &node.cluster_id)
            .unwrap_or(&peer_map.cluster_id);
        validate_bootstrap_peer_cache(&peer_map, &local_state.node_id, expected_cluster)?;
        self.configure_local_wireguard(&local_state.wireguard_private_key_b64)
            .await?;
        self.endpoint_resolver.prepare_for_peer_map().await?;

        let mut configs = Vec::with_capacity(peer_map.peers.len());
        let mut routes = Vec::with_capacity(peer_map.peers.len());
        for peer in &peer_map.peers {
            if local_state.wireguard_public_key_b64 == peer.wireguard_public_key {
                return Err(AgentError::WireGuard(format!(
                    "bootstrap peer {} reuses the local WireGuard public key",
                    peer.node_id
                )));
            }
            let endpoint = self.endpoint_resolver.endpoint_for_peer(peer).await?;
            if endpoint.is_none() {
                return Err(AgentError::WireGuard(format!(
                    "bootstrap peer {} has no directly usable endpoint",
                    peer.node_id
                )));
            }
            let persistent_keepalive_seconds = self
                .endpoint_resolver
                .persistent_keepalive_seconds_for_peer(peer, endpoint.as_deref())
                .await?;
            configs.push(WireGuardPeerConfig {
                peer: peer.node_id.clone(),
                public_key: peer.wireguard_public_key.clone(),
                endpoint,
                allowed_ips: vec![peer_overlay_cidr(&peer.vpn_ip)],
                persistent_keepalive_seconds,
            });
            routes.push(peer_host_route(peer)?);
        }
        let route_plan = RoutePlan {
            owner: RoutePlanOwner::PeerMap,
            interface: self.interface.clone(),
            mtu_lock: self.route_mtu_lock,
            routes,
            policy_rules: Vec::new(),
        };
        validate_route_plan(&route_plan)?;
        if route_plan
            .routes
            .iter()
            .any(|route| route.cidr.addr().is_ipv6())
        {
            self.configure_local_wireguard_ipv6().await?;
        }

        for config in configs {
            self.wireguard.upsert_peer(config.clone()).await?;
            self.applied_peers
                .write()
                .await
                .insert(config.peer.clone(), config.public_key);
            self.applied_active_peers.write().await.insert(config.peer);
        }
        let routes_applied = route_plan.routes.len();
        if routes_applied > 0 {
            self.route_manager.apply_routes(route_plan.clone()).await?;
        }
        let mut applied_routes = self.applied_routes.write().await;
        for route in route_plan.routes {
            let peer_routes = applied_routes
                .entry(route.advertised_by.clone())
                .or_default();
            if !peer_routes.contains(&route) {
                peer_routes.push(route);
            }
        }

        Ok(PeerMapApplySummary {
            peers_applied: peer_map.peers.len(),
            peers_removed: 0,
            routes_applied,
            routes_removed: 0,
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

    async fn apply_bootstrap_peer_map_update(
        &self,
        peer_map: PeerMap,
    ) -> Result<PeerMapApplySummary, AgentError> {
        self.apply_bootstrap_peer_map(peer_map).await
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

fn normalize_resolved_overlay_path_routes(
    path: &mut OverlayPath,
) -> Result<Option<Route>, AgentError> {
    if path.target.vpn_ip.0 == path.destination {
        path.target.routes.clear();
        return Ok(None);
    }

    let selected = peer_owned_advertised_routes(&path.target)
        .filter(|route| route.cidr.contains(&path.destination))
        .min_by(|left, right| {
            right
                .cidr
                .prefix_len()
                .cmp(&left.cidr.prefix_len())
                .then_with(|| left.metric.cmp(&right.metric))
                .then_with(|| left.id.cmp(&right.id))
        })
        .cloned()
        .ok_or_else(|| {
            AgentError::InvalidState(format!(
                "overlay target {} does not directly own a route for destination {}",
                path.target.node_id, path.destination
            ))
        })?;
    path.target.routes = vec![selected.clone()];
    Ok(Some(selected))
}

pub fn merge_resolved_overlay_peer(peers: &mut Vec<NodeRecord>, mut resolved: NodeRecord) {
    let resolved_routes = peer_owned_advertised_routes(&resolved)
        .cloned()
        .map(|route| (route.cidr, route))
        .collect::<BTreeMap<_, _>>();
    let Some(existing) = peers
        .iter_mut()
        .find(|peer| peer.node_id == resolved.node_id)
    else {
        resolved.routes = resolved_routes
            .into_values()
            .take(MAX_OVERLAY_NODE_ROUTES)
            .collect();
        peers.push(resolved);
        return;
    };

    let existing_routes = existing
        .routes
        .iter()
        .cloned()
        .map(|route| (route.cidr, route))
        .collect::<BTreeMap<_, _>>();
    let mut routes = resolved_routes
        .into_iter()
        .take(MAX_OVERLAY_NODE_ROUTES)
        .collect::<BTreeMap<_, _>>();
    for (cidr, route) in existing_routes {
        if routes.len() >= MAX_OVERLAY_NODE_ROUTES {
            break;
        }
        routes.entry(cidr).or_insert(route);
    }
    existing.routes = routes.into_values().collect();
}

fn peer_routes_for_record(
    peer: &NodeRecord,
    selected_advertised_routes: &[Route],
) -> Result<Vec<Route>, AgentError> {
    let mut routes = vec![peer_host_route(peer)?];
    routes.extend_from_slice(selected_advertised_routes);
    Ok(routes)
}

fn peer_owned_advertised_routes(peer: &NodeRecord) -> impl Iterator<Item = &Route> {
    peer.routes.iter().filter(|route| {
        route.advertised_by == peer.node_id
            && route.via.as_ref().is_none_or(|via| via == &peer.node_id)
    })
}

fn select_peer_advertised_routes(
    peers: &[&NodeRecord],
    local_route_cidrs: &BTreeSet<ipnet::IpNet>,
) -> BTreeMap<NodeId, Vec<Route>> {
    let mut selected = BTreeMap::<ipnet::IpNet, Route>::new();
    for peer in peers {
        for route in peer_owned_advertised_routes(peer) {
            if local_route_cidrs.contains(&route.cidr) {
                continue;
            }
            let replace = selected.get(&route.cidr).is_none_or(|current| {
                (route.metric, &route.advertised_by, route.id.as_str())
                    < (current.metric, &current.advertised_by, current.id.as_str())
            });
            if replace {
                selected.insert(route.cidr, route.clone());
            }
        }
    }

    let mut by_provider = BTreeMap::<NodeId, Vec<Route>>::new();
    for route in selected.into_values() {
        by_provider
            .entry(route.advertised_by.clone())
            .or_default()
            .push(route);
    }
    by_provider
}

fn validate_local_advertised_routes(
    local_node: &NodeId,
    routes: &[Route],
) -> Result<(), AgentError> {
    let mut route_ids = BTreeSet::new();
    let mut route_cidrs = BTreeSet::new();
    for route in routes {
        if route.advertised_by != *local_node {
            return Err(AgentError::RoutePlanning(format!(
                "local route {} is advertised by {} instead of {}",
                route.id, route.advertised_by, local_node
            )));
        }
        if let Some(via) = route.via.as_ref().filter(|via| *via != local_node) {
            return Err(AgentError::RoutePlanning(format!(
                "local route {} uses foreign provider {} instead of {}",
                route.id, via, local_node
            )));
        }
        if route.metric == 0 {
            return Err(AgentError::RoutePlanning(format!(
                "local route {} metric must be greater than zero",
                route.id
            )));
        }
        if !route_ids.insert(route.id.as_str()) {
            return Err(AgentError::RoutePlanning(format!(
                "local routes must not repeat route ID {}",
                route.id
            )));
        }
        if !route_cidrs.insert(route.cidr) {
            return Err(AgentError::RoutePlanning(format!(
                "local routes must not repeat CIDR {}",
                route.cidr
            )));
        }
    }
    Ok(())
}

pub fn bootstrap_peer_map_cache(
    peer_map: &PeerMap,
    local_node: &NodeId,
) -> Result<Option<PeerMap>, AgentError> {
    validate_join_token_bootstrap_endpoints(&peer_map.bootstrap_endpoints).map_err(|error| {
        AgentError::InvalidState(format!(
            "peer-map bootstrap endpoints are invalid: {}",
            error.reason()
        ))
    })?;

    let control_plane_role = Role::control_plane();
    let kubernetes_control_plane = Tag::kubernetes_control_plane();
    let route_provider = Tag::route_provider();
    let mut peers = peer_map
        .peers
        .iter()
        .enumerate()
        .filter(|(_, peer)| &peer.node_id != local_node && preferred_endpoint(peer).is_some())
        .map(|(index, peer)| {
            let priority = if peer.role == control_plane_role
                || peer.tags.contains(&kubernetes_control_plane)
            {
                0
            } else if peer.tags.contains(&route_provider) {
                1
            } else if peer
                .relay_capability
                .as_ref()
                .is_some_and(|relay| relay.enabled_by_policy && relay.public_endpoint.is_some())
            {
                2
            } else {
                3
            };
            (priority, index, peer.clone())
        })
        .collect::<Vec<_>>();
    peers.sort_by_key(|(priority, index, _)| (*priority, *index));
    peers.truncate(MAX_BOOTSTRAP_PEER_CACHE_PEERS);

    let peers = peers
        .into_iter()
        .map(|(_, _, mut peer)| {
            // Host routes are sufficient to recover the authoritative map and avoid retaining
            // stale workload routes across a reboot.
            peer.routes.clear();
            peer
        })
        .collect::<Vec<_>>();
    if peers.is_empty() {
        return Ok(None);
    }

    let cache = PeerMap {
        cluster_id: peer_map.cluster_id.clone(),
        peers,
        bootstrap_endpoints: peer_map.bootstrap_endpoints.clone(),
        generated_at: peer_map.generated_at,
    };
    validate_bootstrap_peer_cache(&cache, local_node, &peer_map.cluster_id)?;
    Ok(Some(cache))
}

fn bootstrap_peer_cache_recovery_eq(left: &PeerMap, right: &PeerMap) -> bool {
    left.cluster_id == right.cluster_id
        && left.bootstrap_endpoints == right.bootstrap_endpoints
        && left.peers.len() == right.peers.len()
        && left.peers.iter().zip(&right.peers).all(|(left, right)| {
            left.node_id == right.node_id
                && left.cluster_id == right.cluster_id
                && left.vpn_ip == right.vpn_ip
                && left.identity_public_key == right.identity_public_key
                && left.wireguard_public_key == right.wireguard_public_key
                && left.role == right.role
                && left.tags == right.tags
                && left.endpoint_candidates.len() == right.endpoint_candidates.len()
                && left
                    .endpoint_candidates
                    .iter()
                    .zip(&right.endpoint_candidates)
                    .all(|(left, right)| {
                        selected_candidate_path_identity_eq(Some(left), Some(right))
                    })
        })
}

fn validate_bootstrap_peer_cache(
    peer_map: &PeerMap,
    local_node: &NodeId,
    expected_cluster: &ipars_types::ClusterId,
) -> Result<(), AgentError> {
    if peer_map.cluster_id != *expected_cluster {
        return Err(AgentError::InvalidState(format!(
            "bootstrap peer cache belongs to cluster {} instead of {}",
            peer_map.cluster_id, expected_cluster
        )));
    }
    if peer_map.peers.is_empty() || peer_map.peers.len() > MAX_BOOTSTRAP_PEER_CACHE_PEERS {
        return Err(AgentError::InvalidState(format!(
            "bootstrap peer cache must contain between 1 and {MAX_BOOTSTRAP_PEER_CACHE_PEERS} peers"
        )));
    }
    validate_join_token_bootstrap_endpoints(&peer_map.bootstrap_endpoints).map_err(|error| {
        AgentError::InvalidState(format!(
            "bootstrap peer cache endpoints are invalid: {}",
            error.reason()
        ))
    })?;

    let mut node_ids = BTreeSet::new();
    let mut vpn_ips = BTreeSet::new();
    let mut wireguard_keys = BTreeSet::new();
    for peer in &peer_map.peers {
        if peer.cluster_id != peer_map.cluster_id {
            return Err(AgentError::InvalidState(format!(
                "bootstrap peer {} belongs to cluster {} instead of {}",
                peer.node_id, peer.cluster_id, peer_map.cluster_id
            )));
        }
        if &peer.node_id == local_node {
            return Err(AgentError::InvalidState(format!(
                "bootstrap peer cache cannot contain local node {local_node}"
            )));
        }
        if !node_ids.insert(peer.node_id.clone()) {
            return Err(AgentError::InvalidState(format!(
                "bootstrap peer cache repeats node {}",
                peer.node_id
            )));
        }
        if !vpn_ips.insert(peer.vpn_ip) {
            return Err(AgentError::InvalidState(format!(
                "bootstrap peer cache repeats VPN address {}",
                peer.vpn_ip
            )));
        }
        validate_wireguard_public_key(&peer.wireguard_public_key)?;
        if !wireguard_keys.insert(peer.wireguard_public_key.clone()) {
            return Err(AgentError::InvalidState(
                "bootstrap peer cache repeats a WireGuard public key".to_string(),
            ));
        }
        if !peer.routes.is_empty() {
            return Err(AgentError::InvalidState(format!(
                "bootstrap peer {} must not retain advertised routes",
                peer.node_id
            )));
        }
        if preferred_endpoint(peer).is_none() {
            return Err(AgentError::InvalidState(format!(
                "bootstrap peer {} has no usable direct endpoint",
                peer.node_id
            )));
        }
    }
    Ok(())
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
    observed_policy_pins: BTreeSet<NodeId>,
    observed_route_pins: BTreeSet<NodeId>,
    topology_pins: BTreeSet<NodeId>,
    last_used: BTreeMap<NodeId, DateTime<Utc>>,
    local_last_used: BTreeMap<NodeId, DateTime<Utc>>,
    peer_vpn_ips: BTreeMap<IpAddr, NodeId>,
    peer_vpn_ip_by_node: BTreeMap<NodeId, IpAddr>,
    advertised_routes: BTreeMap<NodeId, Vec<ipnet::IpNet>>,
}

impl LazyConnectManager {
    pub fn new(policy: ClusterPolicy) -> Self {
        Self {
            policy,
            pins: BTreeSet::new(),
            observed_policy_pins: BTreeSet::new(),
            observed_route_pins: BTreeSet::new(),
            topology_pins: BTreeSet::new(),
            last_used: BTreeMap::new(),
            local_last_used: BTreeMap::new(),
            peer_vpn_ips: BTreeMap::new(),
            peer_vpn_ip_by_node: BTreeMap::new(),
            advertised_routes: BTreeMap::new(),
        }
    }

    pub fn record_activity(&mut self, peer: NodeId, at: DateTime<Utc>) {
        let _ = insert_latest_activity(&mut self.last_used, peer.clone(), at);
        let _ = insert_latest_activity(&mut self.local_last_used, peer, at);
    }

    pub fn record_remote_activity(&mut self, peer: NodeId, at: DateTime<Utc>) -> bool {
        insert_latest_activity(&mut self.last_used, peer, at)
    }

    pub fn record_remote_activity_if_idle(&mut self, peer: NodeId, at: DateTime<Utc>) -> bool {
        if self.is_pinned(&peer) || self.last_used.contains_key(&peer) {
            return false;
        }
        insert_latest_activity(&mut self.last_used, peer, at)
    }

    pub fn recent_local_activity(
        &self,
        peer: &NodeId,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        let last_used = self.local_last_used.get(peer)?;
        now.signed_duration_since(*last_used)
            .to_std()
            .map_or(Some(*last_used), |idle_for| {
                (idle_for < Duration::from_secs(self.policy.idle_timeout_seconds))
                    .then_some(*last_used)
            })
    }

    pub fn recent_local_activities(
        &self,
        now: DateTime<Utc>,
    ) -> Vec<(NodeId, DateTime<Utc>, bool)> {
        self.local_last_used
            .keys()
            .filter_map(|peer| {
                self.recent_local_activity(peer, now)
                    .map(|observed_at| (peer.clone(), observed_at, self.is_pinned(peer)))
            })
            .collect()
    }

    pub fn pin_peer(&mut self, peer: NodeId) {
        self.pins.insert(peer);
    }

    pub fn replace_topology_pins(&mut self, peers: BTreeSet<NodeId>) {
        self.topology_pins = peers;
    }

    pub fn replace_on_demand_peer_limit(&mut self, limit: u16) {
        self.policy.overlay_on_demand_peer_limit = limit;
    }

    pub fn is_pinned(&self, peer: &NodeId) -> bool {
        self.pins.contains(peer)
            || self.observed_policy_pins.contains(peer)
            || self.observed_route_pins.contains(peer)
            || self.topology_pins.contains(peer)
    }

    fn is_non_topology_pinned(&self, peer: &NodeId) -> bool {
        self.pins.contains(peer)
            || self.observed_policy_pins.contains(peer)
            || self.observed_route_pins.contains(peer)
    }

    fn is_topology_pinned(&self, peer: &NodeId) -> bool {
        self.topology_pins.contains(peer)
    }

    fn has_activity(&self, peer: &NodeId) -> bool {
        self.last_used.contains_key(peer)
    }

    fn direct_pinned_peer_ids(&self) -> BTreeSet<NodeId> {
        self.pins
            .iter()
            .chain(&self.observed_policy_pins)
            .chain(&self.topology_pins)
            .cloned()
            .collect()
    }

    fn is_durably_pinned(&self, peer: &NodeId) -> bool {
        self.pins.contains(peer)
            || self.observed_policy_pins.contains(peer)
            || self.topology_pins.contains(peer)
    }

    pub fn is_pinned_by_policy(&self, role: &Role, tags: &BTreeSet<Tag>) -> bool {
        self.policy.pinned_roles.contains(role)
            || tags.iter().any(|tag| self.policy.pinned_tags.contains(tag))
    }

    pub fn observe_peer(&mut self, peer: &NodeRecord, local_route_cidrs: &BTreeSet<ipnet::IpNet>) {
        self.observe_peer_with_route_pin(peer, local_route_cidrs, true);
    }

    pub fn observe_overlay_shortcut(
        &mut self,
        peer: &NodeRecord,
        local_route_cidrs: &BTreeSet<ipnet::IpNet>,
    ) {
        self.observe_peer_with_route_pin(peer, local_route_cidrs, false);
    }

    fn observe_peer_with_route_pin(
        &mut self,
        peer: &NodeRecord,
        local_route_cidrs: &BTreeSet<ipnet::IpNet>,
        pin_owned_routes: bool,
    ) {
        self.remove_observed_peer(&peer.node_id);
        if let Some(displaced_peer) = self
            .peer_vpn_ips
            .insert(peer.vpn_ip.0, peer.node_id.clone())
        {
            self.peer_vpn_ip_by_node.remove(&displaced_peer);
        }
        self.peer_vpn_ip_by_node
            .insert(peer.node_id.clone(), peer.vpn_ip.0);
        let routes = peer_owned_advertised_routes(peer)
            .filter(|route| !local_route_cidrs.contains(&route.cidr))
            .map(|route| route.cidr)
            .collect::<Vec<_>>();
        let has_owned_routes = !routes.is_empty();
        if !routes.is_empty() {
            self.advertised_routes.insert(peer.node_id.clone(), routes);
        }

        if peer.role.is_client() || self.is_pinned_by_policy(&peer.role, &peer.tags) {
            self.observed_policy_pins.insert(peer.node_id.clone());
        }
        if pin_owned_routes && has_owned_routes {
            self.observed_route_pins.insert(peer.node_id.clone());
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
        self.is_pinned(&peer.node_id) || self.last_used.contains_key(&peer.node_id)
    }

    pub fn metrics(&self) -> LazyConnectMetrics {
        let pinned_peer_count = self
            .pins
            .iter()
            .chain(&self.observed_policy_pins)
            .chain(&self.observed_route_pins)
            .chain(&self.topology_pins)
            .collect::<BTreeSet<_>>()
            .len();
        LazyConnectMetrics {
            active_peer_count: self.last_used.len(),
            pinned_peer_count,
            on_demand_peer_limit: usize::from(self.policy.overlay_on_demand_peer_limit),
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
                if self.is_pinned(peer) {
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
        self.local_last_used.remove(peer);
    }

    fn remove_observed_peer(&mut self, peer: &NodeId) {
        if let Some(vpn_ip) = self.peer_vpn_ip_by_node.remove(peer) {
            self.peer_vpn_ips.remove(&vpn_ip);
        }
        self.advertised_routes.remove(peer);
        self.observed_policy_pins.remove(peer);
        self.observed_route_pins.remove(peer);
    }

    fn retain_observed_peers(&mut self, peers: &BTreeSet<NodeId>) {
        self.peer_vpn_ip_by_node
            .retain(|observed_peer, _| peers.contains(observed_peer));
        let peer_vpn_ip_by_node = &self.peer_vpn_ip_by_node;
        self.peer_vpn_ips.retain(|vpn_ip, observed_peer| {
            peers.contains(observed_peer) && peer_vpn_ip_by_node.get(observed_peer) == Some(vpn_ip)
        });
        self.advertised_routes
            .retain(|observed_peer, _| peers.contains(observed_peer));
        self.observed_policy_pins
            .retain(|observed_peer| peers.contains(observed_peer));
        self.observed_route_pins
            .retain(|observed_peer| peers.contains(observed_peer));
    }
}

fn insert_latest_activity(
    activity: &mut BTreeMap<NodeId, DateTime<Utc>>,
    peer: NodeId,
    at: DateTime<Utc>,
) -> bool {
    match activity.entry(peer) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(at);
            true
        }
        std::collections::btree_map::Entry::Occupied(mut entry) if at > *entry.get() => {
            entry.insert(at);
            true
        }
        std::collections::btree_map::Entry::Occupied(_) => false,
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
    use std::time::Instant;

    use chrono::Duration as ChronoDuration;
    use ipars_relay::{encode_relay_datagram, RelayService, UdpRelay};
    use ipars_route_manager::{
        DockerNetworkIntent, DryRunLinuxRouteManager, KubernetesUnderlayIntent, RouteManager,
        RouteManagerError, RoutePlan,
    };
    use ipars_stun::{BindingStunServer, Rfc5780StunServer};
    use ipars_types::api::{
        AgentPacketFlowConntrackStatus, AgentPacketFlowTcpState, RelayAdmissionRequest,
        PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES,
    };
    use ipars_types::{
        BootstrapEndpointKind, CandidateSource, ClusterId, NatFilteringBehavior,
        NatMappingBehavior, NatTraversalStrategy, NeighborMap, OverlayNeighbor,
        OverlayNeighborKind, OverlayPath, PathMetrics, PeerPathKey, RelayCapability, TokenPolicy,
        TransportProtocol,
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
            relay_node: (state == PathState::Relay).then(|| NodeId::from_string("relay-a")),
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
        interface_missing: Arc<std::sync::atomic::AtomicBool>,
        fail_ipv6_check: bool,
        fail_remove: bool,
    }

    impl RecordingRunner {
        fn with_missing_interface() -> Self {
            Self {
                interface_missing: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                ..Self::default()
            }
        }

        fn with_disabled_ipv6() -> Self {
            Self {
                fail_ipv6_check: true,
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
            use std::sync::atomic::Ordering;

            let interface_missing = self.interface_missing.load(Ordering::SeqCst);
            let should_fail_show = interface_missing
                && command.program == "ip"
                && command
                    .args
                    .iter()
                    .map(String::as_str)
                    .eq(["link", "show", "dev", "ipars0"]);
            let should_fail_wireguard = interface_missing
                && command.program == "wg"
                && command.args.first().is_some_and(|arg| arg == "set")
                && command.args.get(1).is_some_and(|arg| arg == "ipars0");
            let creates_interface = command.program == "ip"
                && command.args.iter().map(String::as_str).eq([
                    "link",
                    "add",
                    "dev",
                    "ipars0",
                    "type",
                    "wireguard",
                ]);
            let should_fail_remove = self.fail_remove
                && command.program == "wg"
                && command.args.last().is_some_and(|arg| arg == "remove");
            let should_fail_ipv6_check = self.fail_ipv6_check && command.program == "grep";
            self.commands.write().await.push(command);
            if creates_interface {
                self.interface_missing.store(false, Ordering::SeqCst);
            }
            if should_fail_show || should_fail_wireguard || should_fail_ipv6_check {
                Err(AgentError::WireGuard("interface missing".to_string()))
            } else if should_fail_remove {
                Err(AgentError::WireGuard("remove failed".to_string()))
            } else {
                Ok(())
            }
        }
    }

    #[cfg(unix)]
    fn trusted_test_shell() -> String {
        for candidate in ["/usr/bin/dash", "/usr/bin/bash", "/bin/dash", "/bin/bash"] {
            if ensure_trusted_linux_command_executable(Path::new(candidate), "test shell").is_ok() {
                return candidate.to_string();
            }
        }
        panic!("trusted non-symlink test shell was not found");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_command_runner_reports_failure_stderr() {
        let runner = TimedSystemCommandRunner::new(Duration::from_secs(1));
        let shell = trusted_test_shell();
        let error = match runner
            .run(LinuxCommand::new(
                shell,
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
    async fn timed_system_command_runner_uses_sanitized_environment() {
        let runner = TimedSystemCommandRunner::new(Duration::from_secs(1));
        let shell = trusted_test_shell();
        let script = r#"test "${PATH:-}" = "/usr/bin:/usr/sbin:/bin:/sbin" && test "${LANG:-}" = "C" && test "${LC_ALL:-}" = "C" && test -z "${HOME+x}" && test -z "${LD_PRELOAD+x}""#;

        match runner.run(LinuxCommand::new(shell, ["-c", script])).await {
            Ok(()) => {}
            Err(error) => panic!("command environment should be sanitized: {error}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_command_runner_passes_bounded_stdin() -> Result<(), AgentError> {
        let runner = TimedSystemCommandRunner::new(Duration::from_secs(1));
        let shell = trusted_test_shell();

        runner
            .run(
                LinuxCommand::new(
                    shell,
                    [
                        "-c",
                        "IFS= read -r secret; test \"$secret\" = wireguard-secret",
                    ],
                )
                .with_stdin(b"wireguard-secret\n".to_vec()),
            )
            .await?;
        Ok(())
    }

    #[test]
    fn command_label_escapes_control_characters() {
        let label = command_label(
            "wg",
            &[
                "set\npeer".to_string(),
                "tab\targ".to_string(),
                r"slash\arg".to_string(),
            ],
        );

        assert_eq!(label, r"wg set\npeer tab\targ slash\\arg");
        assert!(!label.contains('\n'));
        assert!(!label.contains('\t'));
    }

    #[test]
    fn linux_command_debug_redacts_stdin() {
        let command = LinuxCommand::new("wg", ["set", "ipars0", "private-key", "/dev/stdin"])
            .with_stdin(b"private-key-material".to_vec());
        let debug = format!("{command:?}");

        assert!(debug.contains("<redacted 20 bytes>"));
        assert!(!debug.contains("private-key-material"));
    }

    #[test]
    fn command_stderr_message_escapes_control_characters() {
        let stderr = LimitedCommandOutput {
            bytes: b"failed\nstderr\tfield".to_vec(),
            truncated: false,
            limit: 64,
        };

        let message = command_stderr_message(&stderr);

        assert_eq!(message, r"failed\nstderr\tfield");
        assert!(!message.contains('\n'));
        assert!(!message.contains('\t'));
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

        for (program, expected) in [
            ("wg\0bad", "program must not contain NUL bytes"),
            ("wg\nbad", "program must not contain control characters"),
            ("wg bad", "program must not contain whitespace"),
            (
                "./wg",
                "program must be a bare command name or an absolute path",
            ),
            ("/usr/bin/./wg", "program path must not contain"),
            ("/usr/bin/../wg", "program path must not contain"),
            ("/", "program path must name an executable"),
            (".", "program name must not be '.' or '..'"),
            ("..", "program name must not be '.' or '..'"),
            ("-wg", "program name must not start with '-'"),
            ("/tmp/-wg", "program name must not start with '-'"),
        ] {
            let error = match runner.run(LinuxCommand::new(program, ["show"])).await {
                Ok(()) => panic!("command should be rejected"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(expected),
                "unexpected error for {program:?}: {error}"
            );
        }

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
    async fn timed_system_command_runner_rejects_untrusted_absolute_program_path(
    ) -> Result<(), AgentError> {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = std::env::temp_dir().join(format!(
            "ipars-agent-untrusted-command-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir(&temp_dir)?;
        std::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o777))?;
        let program = temp_dir.join("fake-wg");
        std::fs::write(&program, "#!/bin/sh\nexit 0\n")?;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))?;

        let runner = TimedSystemCommandRunner::new(Duration::from_secs(1));
        let error = match runner
            .run(LinuxCommand::new(
                program.to_string_lossy().to_string(),
                std::iter::empty::<&str>(),
            ))
            .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("must not be group- or world-writable"),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_command_runner_rejects_symlinked_absolute_program_path(
    ) -> Result<(), AgentError> {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp_dir = std::env::temp_dir().join(format!(
            "ipars-agent-symlinked-command-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir(&temp_dir)?;
        std::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o700))?;
        let program = temp_dir.join("linked-shell");
        symlink(trusted_test_shell(), &program)?;

        let runner = TimedSystemCommandRunner::new(Duration::from_secs(1));
        let error = match runner
            .run(LinuxCommand::new(
                program.to_string_lossy().to_string(),
                ["-c", "exit 0"],
            ))
            .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("must not be a symlink"),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_command_runner_rejects_invalid_runtime_bounds() {
        let shell = trusted_test_shell();
        let error = match TimedSystemCommandRunner::new(Duration::ZERO)
            .run(LinuxCommand::new(shell.clone(), ["-c", "exit 0"]))
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
        .run(LinuxCommand::new(shell.clone(), ["-c", "exit 0"]))
        .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("timeout must not exceed 3600s"));

        let error = match TimedSystemCommandRunner::with_output_max_bytes(Duration::from_secs(1), 0)
            .run(LinuxCommand::new(shell.clone(), ["-c", "exit 0"]))
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
        .run(LinuxCommand::new(shell, ["-c", "exit 0"]))
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
        let shell = trusted_test_shell();
        let error = match runner.run(LinuxCommand::new(shell, ["-c", &script])).await {
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
        let shell = trusted_test_shell();
        let error = match runner
            .run(LinuxCommand::new(
                shell,
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
        let shell = trusted_test_shell();

        runner
            .run(LinuxCommand::new(
                shell,
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
        managed_inventory: tokio::sync::RwLock<Option<ManagedRouteInventory>>,
        managed_removed: tokio::sync::RwLock<Vec<ManagedRouteInventory>>,
        fail_managed_inventory: bool,
    }

    impl RecordingRouteManager {
        fn with_managed_inventory(routes: impl IntoIterator<Item = ManagedRoute>) -> Self {
            Self {
                managed_inventory: tokio::sync::RwLock::new(Some(ManagedRouteInventory {
                    routes: routes.into_iter().collect(),
                    policy_rules: BTreeSet::new(),
                })),
                ..Self::default()
            }
        }

        fn with_failed_managed_inventory() -> Self {
            Self {
                fail_managed_inventory: true,
                ..Self::default()
            }
        }
    }

    #[async_trait]
    impl RouteManager for RecordingRouteManager {
        async fn apply_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError> {
            if let Some(inventory) = self.managed_inventory.write().await.as_mut() {
                let desired = desired_managed_route_inventory(&plan)?;
                inventory.routes.extend(desired.routes);
                inventory.policy_rules.extend(desired.policy_rules);
            }
            self.applied.write().await.push(plan);
            Ok(())
        }

        async fn remove_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError> {
            self.removed.write().await.push(plan);
            Ok(())
        }

        async fn managed_route_inventory(
            &self,
            _plan: &RoutePlan,
        ) -> Result<Option<ManagedRouteInventory>, RouteManagerError> {
            if self.fail_managed_inventory {
                return Err(RouteManagerError::Backend(
                    "injected managed route inventory failure".to_string(),
                ));
            }
            Ok(self.managed_inventory.read().await.clone())
        }

        async fn remove_managed_route_inventory(
            &self,
            _interface: &str,
            stale: &ManagedRouteInventory,
        ) -> Result<(), RouteManagerError> {
            if let Some(inventory) = self.managed_inventory.write().await.as_mut() {
                inventory
                    .routes
                    .retain(|route| !stale.routes.contains(route));
                inventory
                    .policy_rules
                    .retain(|rule| !stale.policy_rules.contains(rule));
            }
            self.managed_removed.write().await.push(stale.clone());
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
            display_name: None,
            hostname: None,
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

    fn bounded_neighbor_map(
        local_node: NodeId,
        neighbors: Vec<NodeRecord>,
        topology_epoch: u64,
    ) -> NeighborMap {
        NeighborMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            node_id: local_node,
            topology_epoch,
            routing_epoch: topology_epoch,
            max_degree: 4,
            on_demand_peer_limit: 4,
            vpn_cidr: "100.64.0.0/10"
                .parse()
                .unwrap_or_else(|error| panic!("static test VPN CIDR must parse: {error}")),
            neighbors: neighbors
                .into_iter()
                .enumerate()
                .map(|(index, node)| OverlayNeighbor {
                    node,
                    kind: if index < 2 {
                        OverlayNeighborKind::BackbonePrimary
                    } else {
                        OverlayNeighborKind::BackboneSecondary
                    },
                })
                .collect(),
            pinned_peers: Vec::new(),
            aggregate_routes: Vec::new(),
            client_route_peers: Vec::new(),
            bootstrap_endpoints: Vec::new(),
            generated_at: Utc::now(),
        }
    }

    fn bounded_overlay_path(
        local_node: NodeId,
        target: NodeRecord,
        destination: IpAddr,
        topology_epoch: u64,
    ) -> OverlayPath {
        OverlayPath {
            topology_epoch,
            routing_epoch: topology_epoch,
            source: local_node.clone(),
            destination,
            ordered_nodes: vec![local_node, target.node_id.clone()],
            secondary_ordered_nodes: None,
            target,
            generated_at: Utc::now(),
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

    #[derive(Debug, Clone)]
    struct StaticWireGuardPeerInventory {
        public_keys: BTreeSet<String>,
        fail: bool,
    }

    impl StaticWireGuardPeerInventory {
        fn from_public_keys(public_keys: impl IntoIterator<Item = String>) -> Self {
            Self {
                public_keys: public_keys.into_iter().collect(),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                public_keys: BTreeSet::new(),
                fail: true,
            }
        }
    }

    #[async_trait]
    impl WireGuardPeerInventorySource for StaticWireGuardPeerInventory {
        async fn public_keys(&self) -> Result<BTreeSet<String>, AgentError> {
            if self.fail {
                Err(AgentError::WireGuard(
                    "test WireGuard peer inventory failed".to_string(),
                ))
            } else {
                Ok(self.public_keys.clone())
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
    fn remote_lazy_activity_does_not_become_a_local_connection_intent() {
        let mut manager = LazyConnectManager::new(ClusterPolicy {
            idle_timeout_seconds: 10,
            ..ClusterPolicy::default()
        });
        let peer_id = NodeId::from_string("peer-a");
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 20)),
            "wg-peer-a",
            Vec::new(),
            Vec::new(),
        );
        let now = Utc::now();

        assert!(manager.record_remote_activity(peer_id.clone(), now));
        assert!(!manager.record_remote_activity(peer_id.clone(), now));
        assert!(manager.should_connect_peer(&peer));
        assert_eq!(manager.recent_local_activity(&peer_id, now), None);

        manager.record_activity(peer_id.clone(), now);
        assert_eq!(manager.recent_local_activity(&peer_id, now), Some(now));
        assert_eq!(
            manager.recent_local_activity(&peer_id, now + ChronoDuration::seconds(10)),
            None
        );
    }

    #[tokio::test]
    async fn repeated_remote_lazy_activity_does_not_wake_signal_loop() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer_id = NodeId::from_string("peer-a");
        let observed_at = Utc::now();
        let signal_notify = runtime.signal_path_notifier();
        let heartbeat_notify = runtime.heartbeat_report_notifier();

        runtime
            .record_remote_peer_activity(peer_id.clone(), observed_at)
            .await;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), signal_notify.notified())
                .await
                .is_ok()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), heartbeat_notify.notified())
                .await
                .is_err()
        );

        runtime
            .record_remote_peer_activity(peer_id.clone(), observed_at)
            .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), signal_notify.notified())
                .await
                .is_err()
        );

        runtime
            .record_remote_peer_activity(peer_id, observed_at + ChronoDuration::milliseconds(1))
            .await;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), signal_notify.notified())
                .await
                .is_ok()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), heartbeat_notify.notified())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn repeated_local_activity_coalesces_immediate_sync() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer_id = NodeId::from_string("peer-a");
        let observed_at = Utc::now();
        let signal_notify = runtime.signal_path_notifier();
        let heartbeat_notify = runtime.heartbeat_report_notifier();

        assert!(
            !runtime
                .record_peer_activity(peer_id.clone(), observed_at, false)
                .await
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(1), signal_notify.notified())
                .await
                .is_ok()
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(1), heartbeat_notify.notified())
                .await
                .is_ok()
        );

        let refreshed_at = observed_at + ChronoDuration::milliseconds(1);
        assert!(
            !runtime
                .record_peer_activity(peer_id.clone(), refreshed_at, false)
                .await
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), signal_notify.notified())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), heartbeat_notify.notified())
                .await
                .is_err()
        );
        assert_eq!(
            runtime
                .recent_local_peer_activity(&peer_id, refreshed_at)
                .await,
            Some(refreshed_at)
        );

        assert!(
            runtime
                .record_peer_activity(
                    peer_id,
                    refreshed_at + ChronoDuration::milliseconds(1),
                    true,
                )
                .await
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(1), signal_notify.notified())
                .await
                .is_ok()
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(1), heartbeat_notify.notified())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn authenticated_probe_wakes_only_a_passive_peer() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer_id = NodeId::from_string("peer-a");
        let first_observed_at = Utc::now();

        assert!(
            runtime
                .wake_passive_peer_from_probe(peer_id.clone(), first_observed_at)
                .await
        );
        assert!(
            !runtime
                .wake_passive_peer_from_probe(
                    peer_id.clone(),
                    first_observed_at + ChronoDuration::seconds(30),
                )
                .await
        );
        assert_eq!(
            runtime.lazy_connect.read().await.last_used.get(&peer_id),
            Some(&first_observed_at)
        );
        assert_eq!(
            runtime
                .recent_local_peer_activity(&peer_id, first_observed_at)
                .await,
            None
        );
    }

    #[test]
    fn lazy_manager_pins_default_important_peer_classes() {
        let mut manager = LazyConnectManager::new(ClusterPolicy::default());
        let mut client = peer_record(
            NodeId::from_string("client-a"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 19)),
            "wg-client",
            Vec::new(),
            Vec::new(),
        );
        client.role = Role::client();
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
            &client,
            &control_plane,
            &route_provider,
            &kubernetes_control_plane,
            &relay,
            &ordinary,
        ] {
            manager.observe_peer(peer, &BTreeSet::new());
        }

        assert!(manager.should_connect_peer(&client));
        assert!(manager.should_connect_peer(&control_plane));
        assert!(manager.should_connect_peer(&route_provider));
        assert!(manager.should_connect_peer(&kubernetes_control_plane));
        assert!(!manager.should_connect_peer(&relay));
        assert!(!manager.should_connect_peer(&ordinary));
        assert_eq!(manager.metrics().pinned_peer_count, 4);
    }

    #[test]
    fn bootstrap_peer_cache_is_bounded_and_prioritizes_control_plane_peers(
    ) -> Result<(), AgentError> {
        let local_node = NodeId::from_string("local-node");
        let mut peers = Vec::new();
        for index in 0..12_u8 {
            let node_id = NodeId::from_string(format!("peer-{index}"));
            let wireguard = WireGuardKeyPair::generate();
            let mut peer = peer_record(
                node_id.clone(),
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, index.saturating_add(2))),
                &wireguard.public_key_b64,
                vec![reflexive_candidate(
                    &node_id,
                    SocketAddr::from(([8, 8, 4, index.saturating_add(1)], 51820)),
                )],
                vec![Route {
                    id: format!("route-{index}"),
                    cidr: format!("10.{index}.0.0/16").parse().map_err(|error| {
                        AgentError::RoutePlanning(format!("test route is invalid: {error}"))
                    })?,
                    advertised_by: node_id.clone(),
                    via: Some(node_id),
                    metric: 10,
                    tags: BTreeSet::new(),
                }],
            );
            if index == 11 {
                peer.tags.insert(Tag::kubernetes_control_plane());
            }
            peers.push(peer);
        }
        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers,
            bootstrap_endpoints: Vec::new(),
            generated_at: Utc::now(),
        };

        let cache = bootstrap_peer_map_cache(&peer_map, &local_node)?
            .ok_or_else(|| AgentError::InvalidState("cache should not be empty".to_string()))?;

        assert_eq!(cache.peers.len(), MAX_BOOTSTRAP_PEER_CACHE_PEERS);
        assert!(cache
            .peers
            .iter()
            .any(|peer| peer.node_id == NodeId::from_string("peer-11")));
        assert!(cache.peers.iter().all(|peer| peer.routes.is_empty()));
        validate_bootstrap_peer_cache(&cache, &local_node, &peer_map.cluster_id)?;

        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        assert!(runtime
            .replace_bootstrap_peer_cache(&peer_map, Utc::now())?
            .is_some());
        let mut refreshed = peer_map.clone();
        refreshed.generated_at += chrono::Duration::seconds(1);
        for peer in &mut refreshed.peers {
            for candidate in &mut peer.endpoint_candidates {
                candidate.observed_at += chrono::Duration::seconds(1);
            }
        }
        assert!(runtime
            .replace_bootstrap_peer_cache(&refreshed, Utc::now())?
            .is_none());
        Ok(())
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

        manager.observe_peer(&relay, &BTreeSet::new());

        assert!(!manager.should_connect_peer(&relay));
        assert_eq!(manager.metrics().observed_peer_vpn_ip_count, 1);
        assert_eq!(manager.metrics().pinned_peer_count, 0);
    }

    #[test]
    fn lazy_manager_drops_only_observed_pins_for_missing_peers() {
        let mut manager = LazyConnectManager::new(ClusterPolicy::default());
        let peer_id = NodeId::from_string("route-provider-a");
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 25)),
            "wg-route-provider",
            Vec::new(),
            vec![Route {
                id: "service-route".to_string(),
                cidr: ipnet::Ipv4Net::new_assert(Ipv4Addr::new(10, 25, 0, 0), 16).into(),
                advertised_by: peer_id.clone(),
                via: Some(peer_id.clone()),
                metric: 10,
                tags: BTreeSet::new(),
            }],
        );

        manager.observe_peer(&peer, &BTreeSet::new());
        assert!(manager.should_connect_peer(&peer));
        manager.retain_observed_peers(&BTreeSet::new());
        assert!(!manager.should_connect_peer(&peer));

        manager.pin_peer(peer_id);
        manager.observe_peer(&peer, &BTreeSet::new());
        manager.retain_observed_peers(&BTreeSet::new());
        assert!(manager.should_connect_peer(&peer));
        assert_eq!(manager.metrics().pinned_peer_count, 1);
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

    #[test]
    fn preferred_local_udp_candidate_uses_shared_private_lan_without_reflexive_candidate() {
        let peer_id = NodeId::from_string("peer-a");
        let local_candidates = vec![EndpointCandidate {
            node_id: NodeId::from_string("local"),
            kind: EndpointCandidateKind::LocalUdp,
            addr: SocketAddr::from(([172, 18, 0, 3], 51_820)),
            observed_at: Utc::now(),
            priority: 70,
            cost: 30,
            source: CandidateSource::StunProbe,
        }];
        let peer_candidates = vec![EndpointCandidate {
            node_id: peer_id,
            kind: EndpointCandidateKind::LocalUdp,
            addr: SocketAddr::from(([172, 18, 0, 2], 51_820)),
            observed_at: Utc::now(),
            priority: 70,
            cost: 30,
            source: CandidateSource::StunProbe,
        }];

        assert_eq!(
            preferred_local_udp_candidate(&local_candidates, &peer_candidates)
                .map(|candidate| candidate.addr),
            Some(SocketAddr::from(([172, 18, 0, 3], 51_820)))
        );
    }

    #[test]
    fn preferred_local_udp_candidate_excludes_shared_address_overlay() {
        let local_candidates = vec![EndpointCandidate {
            node_id: NodeId::from_string("local"),
            kind: EndpointCandidateKind::LocalUdp,
            addr: SocketAddr::from(([100, 100, 20, 30], 51_820)),
            observed_at: Utc::now(),
            priority: 70,
            cost: 30,
            source: CandidateSource::StunProbe,
        }];
        let peer_candidates = vec![EndpointCandidate {
            node_id: NodeId::from_string("peer-a"),
            kind: EndpointCandidateKind::LocalUdp,
            addr: SocketAddr::from(([100, 100, 20, 40], 51_820)),
            observed_at: Utc::now(),
            priority: 70,
            cost: 30,
            source: CandidateSource::StunProbe,
        }];

        assert!(preferred_local_udp_candidate(&local_candidates, &peer_candidates).is_none());
        assert!(preferred_peer_local_udp_candidate(&local_candidates, &peer_candidates).is_none());
    }

    #[test]
    fn preferred_local_udp_candidate_keeps_public_stun_endpoint_preferred() {
        let local_candidates = vec![EndpointCandidate {
            node_id: NodeId::from_string("local"),
            kind: EndpointCandidateKind::LocalUdp,
            addr: SocketAddr::from(([10, 0, 0, 3], 51_820)),
            observed_at: Utc::now(),
            priority: 70,
            cost: 30,
            source: CandidateSource::StunProbe,
        }];
        let peer_candidates = vec![EndpointCandidate {
            node_id: NodeId::from_string("peer-a"),
            kind: EndpointCandidateKind::StunReflexive,
            addr: SocketAddr::from(([198, 51, 100, 2], 51_820)),
            observed_at: Utc::now(),
            priority: 80,
            cost: 20,
            source: CandidateSource::StunProbe,
        }];

        assert!(preferred_local_udp_candidate(&local_candidates, &peer_candidates).is_none());
    }

    #[test]
    fn preferred_peer_local_udp_candidate_returns_peer_candidate() {
        let local_candidates = vec![EndpointCandidate {
            node_id: NodeId::from_string("local"),
            kind: EndpointCandidateKind::LocalUdp,
            addr: SocketAddr::from(([172, 18, 0, 3], 51_820)),
            observed_at: Utc::now(),
            priority: 70,
            cost: 30,
            source: CandidateSource::StunProbe,
        }];
        let peer_id = NodeId::from_string("peer-a");
        let peer_candidates = vec![
            EndpointCandidate {
                node_id: peer_id.clone(),
                kind: EndpointCandidateKind::StunReflexive,
                addr: SocketAddr::from(([10, 244, 1, 1], 18_410)),
                observed_at: Utc::now(),
                priority: 80,
                cost: 20,
                source: CandidateSource::StunProbe,
            },
            EndpointCandidate {
                node_id: peer_id.clone(),
                kind: EndpointCandidateKind::LocalUdp,
                addr: SocketAddr::from(([172, 18, 0, 2], 51_820)),
                observed_at: Utc::now(),
                priority: 70,
                cost: 30,
                source: CandidateSource::StunProbe,
            },
        ];

        assert_eq!(
            preferred_peer_local_udp_candidate(&local_candidates, &peer_candidates)
                .map(|candidate| (candidate.node_id, candidate.addr)),
            Some((peer_id, SocketAddr::from(([172, 18, 0, 2], 51_820)),))
        );
    }

    #[tokio::test]
    async fn runtime_rejects_unusable_path_state_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local_id = runtime.state().node_id.clone();
        let peer_id = NodeId::from_string("peer-a");
        let error = match runtime
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
            .await
        {
            Ok(()) => panic!("unusable selected candidate should be rejected"),
            Err(error) => error,
        };

        assert!(matches!(error, AgentError::PathStateRejected(_)));
        assert!(error.to_string().contains("selected candidate"));
        assert!(error.to_string().contains("is unusable"));
        assert!(runtime.path_state().await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn runtime_rejects_path_state_not_owned_by_local_node() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let record = PathRecord {
            key: PeerPathKey::new(
                NodeId::from_string("other-local"),
                NodeId::from_string("peer-a"),
            ),
            selected_state: PathState::DirectPublic,
            selected_candidate: None,
            relay_node: None,
            score: PathScore {
                value: 115.0,
                reasons: Vec::new(),
            },
            updated_at: Utc::now(),
            pinned: false,
        };

        let error = match runtime.upsert_path_state(record).await {
            Ok(()) => panic!("path state owned by another node should be rejected"),
            Err(error) => error,
        };

        assert!(matches!(error, AgentError::PathStateRejected(_)));
        assert!(error.to_string().contains("does not match runtime node"));
        assert!(runtime.path_state().await.is_empty());
    }

    #[tokio::test]
    async fn runtime_stores_latest_path_state() -> Result<(), AgentError> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local = runtime.state().node_id;
        let mut first = path("peer-a", PathState::Relay, 70.0);
        first.key.local = local.clone();
        let mut latest = path("peer-a", PathState::DirectPublic, 115.0);
        latest.key.local = local;

        runtime.upsert_path_state(first).await?;
        runtime.upsert_path_state(latest.clone()).await?;

        assert_eq!(runtime.path_state().await, vec![latest]);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_direct_path_state_clears_relay_session_and_forwarder_state(
    ) -> Result<(), AgentError> {
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
            .await?;

        assert!(runtime.relay_session(&peer).await.is_none());
        assert!(runtime.relay_forwarder_endpoint(&peer).await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn runtime_records_path_change_events_and_metrics() -> Result<(), AgentError> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local = runtime.state().node_id;
        let mut first = path("peer-a", PathState::Relay, 70.0);
        first.key.local = local.clone();
        let mut latest = path("peer-a", PathState::DirectPublic, 115.0);
        latest.key.local = local;
        let heartbeat_notify = runtime.heartbeat_report_notifier();
        runtime.upsert_path_state(first.clone()).await?;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), heartbeat_notify.notified())
                .await
                .is_ok()
        );
        let mut refreshed = first.clone();
        refreshed.updated_at += ChronoDuration::seconds(1);
        runtime.upsert_path_state(refreshed).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), heartbeat_notify.notified())
                .await
                .is_err()
        );
        runtime.upsert_path_state(latest.clone()).await?;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), heartbeat_notify.notified())
                .await
                .is_ok()
        );

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
        assert_eq!(metrics.path_change_event_total_count, 2);
        assert_eq!(metrics.path_change_event_dropped_count, 0);
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
        Ok(())
    }

    #[tokio::test]
    async fn path_lease_and_score_refreshes_do_not_wake_heartbeat() -> Result<(), AgentError> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local = runtime.state().node_id;
        let peer = NodeId::from_string("peer-a");
        let heartbeat_notify = runtime.heartbeat_report_notifier();
        let mut first = path("peer-a", PathState::DirectNatTraversal, 100.0);
        first.key.local = local;
        first.selected_candidate = Some(reflexive_candidate(
            &peer,
            SocketAddr::from(([8, 8, 8, 8], 51820)),
        ));

        runtime.upsert_path_state(first.clone()).await?;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), heartbeat_notify.notified())
                .await
                .is_ok()
        );

        let mut lease_refreshed = first.clone();
        lease_refreshed
            .selected_candidate
            .as_mut()
            .ok_or_else(|| AgentError::PathStateRejected("test candidate is missing".to_owned()))?
            .observed_at += ChronoDuration::seconds(30);
        lease_refreshed.updated_at += ChronoDuration::seconds(30);
        runtime.upsert_path_state(lease_refreshed.clone()).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), heartbeat_notify.notified())
                .await
                .is_err()
        );

        let mut score_refreshed = lease_refreshed.clone();
        score_refreshed.score.value = 101.0;
        score_refreshed.updated_at += ChronoDuration::seconds(1);
        runtime.upsert_path_state(score_refreshed.clone()).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), heartbeat_notify.notified())
                .await
                .is_err()
        );

        let mut endpoint_changed = score_refreshed;
        endpoint_changed
            .selected_candidate
            .as_mut()
            .ok_or_else(|| AgentError::PathStateRejected("test candidate is missing".to_owned()))?
            .addr = SocketAddr::from(([8, 8, 4, 4], 51820));
        endpoint_changed.updated_at += ChronoDuration::seconds(1);
        runtime.upsert_path_state(endpoint_changed).await?;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), heartbeat_notify.notified())
                .await
                .is_ok()
        );

        let events = runtime.path_change_events().await;
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind, PathChangeKind::Created);
        assert_eq!(events[1].kind, PathChangeKind::ScoreChanged);
        assert_eq!(events[2].kind, PathChangeKind::CandidateChanged);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_counts_dropped_path_change_events() -> Result<(), AgentError> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let local = runtime.state().node_id;
        for index in 0..(MAX_PATH_CHANGE_EVENTS + 3) {
            let mut record = path(&format!("peer-{index}"), PathState::Relay, 70.0);
            record.key.local = local.clone();
            runtime.upsert_path_state(record).await?;
        }

        let metrics = runtime.metrics().await;
        assert_eq!(metrics.path_change_event_count, MAX_PATH_CHANGE_EVENTS);
        assert_eq!(
            metrics.path_change_event_total_count,
            (MAX_PATH_CHANGE_EVENTS + 3) as u64
        );
        assert_eq!(metrics.path_change_event_dropped_count, 3);
        let (events, total_count, dropped_count) = runtime.path_change_events_with_counts().await;
        assert_eq!(events.len(), MAX_PATH_CHANGE_EVENTS);
        assert_eq!(total_count, (MAX_PATH_CHANGE_EVENTS + 3) as u64);
        assert_eq!(dropped_count, 3);
        assert_eq!(events[0].key.remote, NodeId::from_string("peer-3"));
        Ok(())
    }

    #[tokio::test]
    async fn runtime_records_path_probe_metrics_and_pins_peer() -> Result<(), AgentError> {
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
                addr: SocketAddr::from(([8, 8, 8, 10], 51820)),
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
        let path = runtime.record_path_probe(request, Utc::now()).await?;

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
        Ok(())
    }

    #[tokio::test]
    async fn runtime_rejects_inconsistent_path_probe_before_persistence() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer_id = NodeId::from_string("peer-a");
        let request = AgentPathProbeRequest {
            peer: peer_id.clone(),
            selected_state: PathState::DirectPublic,
            selected_candidate: Some(EndpointCandidate {
                node_id: peer_id,
                kind: EndpointCandidateKind::StunReflexive,
                addr: SocketAddr::from(([203, 0, 113, 10], 51820)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::ControlPlane,
            }),
            relay_node: None,
            metrics: PathMetrics::default(),
            policy_allowed: true,
            cost: 0,
            pin: false,
        };

        let error = match runtime.record_path_probe(request, Utc::now()).await {
            Ok(_) => panic!("candidate kind mismatched to direct state should be rejected"),
            Err(error) => error,
        };

        assert!(matches!(error, AgentError::PathProbeRejected(_)));
        assert!(error.to_string().contains("selected state DirectPublic"));
        assert!(error
            .to_string()
            .contains("selected candidate kind StunReflexive"));
        assert!(runtime.path_state().await.is_empty());
        assert_eq!(runtime.metrics().await.path_probe_record_count, 0);
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
    async fn runtime_relay_forwarder_endpoint_uses_supplied_time_for_expiry(
    ) -> Result<(), AgentError> {
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
            .await?;
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
        Ok(())
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

        let mut buffer = [0_u8; 128];
        wireguard_socket
            .send_to(b"not-wireguard", forwarder_addr)
            .await?;
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
        backend.configure_interface_mtu(1280).await?;
        backend
            .configure_interface_address(VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))))
            .await?;
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
                LinuxCommand::new("ip", ["link", "set", "dev", "ipars0", "mtu", "1280"]),
                LinuxCommand::new(
                    "ip",
                    ["address", "replace", "100.64.0.1/32", "dev", "ipars0"]
                ),
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

    #[tokio::test]
    async fn linux_wireguard_backend_assigns_local_vpn_ip_to_interface() -> Result<(), AgentError> {
        let runner = RecordingRunner::default();
        let backend = LinuxWireGuardBackend::new("ipars0", runner.clone());

        backend.configure_interface_mtu(1280).await?;
        backend
            .configure_interface_address(VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))))
            .await?;

        assert_eq!(
            runner.commands().await,
            vec![
                LinuxCommand::new("ip", ["link", "set", "dev", "ipars0", "mtu", "1280"]),
                LinuxCommand::new(
                    "ip",
                    ["address", "replace", "100.64.0.2/32", "dev", "ipars0"],
                ),
            ]
        );
        assert_eq!(
            overlay_interface_cidr(VpnIp(IpAddr::V6(std::net::Ipv6Addr::new(
                0xfd00, 0, 0, 0, 0, 0, 0, 2,
            )))),
            "fd00::2/128"
        );
        Ok(())
    }

    #[tokio::test]
    async fn linux_wireguard_backend_configures_private_key_without_argv_leakage(
    ) -> Result<(), AgentError> {
        let runner = RecordingRunner::default();
        let backend = LinuxWireGuardBackend::new("ipars0", runner.clone());
        let private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        backend.configure_interface_private_key(private_key).await?;
        backend.configure_interface_listen_port(51820).await?;

        assert_eq!(
            runner.commands().await,
            vec![
                LinuxCommand::new("wg", ["set", "ipars0", "private-key", "/dev/stdin"],)
                    .with_stdin(format!("{private_key}\n").into_bytes()),
                LinuxCommand::new("wg", ["set", "ipars0", "listen-port", "51820"]),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn linux_wireguard_backend_enables_ipv6_on_the_overlay_interface(
    ) -> Result<(), AgentError> {
        let runner = RecordingRunner::default();
        let backend = LinuxWireGuardBackend::new("ipars0", runner.clone());

        backend.enable_ipv6().await?;

        assert_eq!(
            runner.commands().await,
            vec![LinuxCommand::new(
                "grep",
                [
                    "-F",
                    "-x",
                    "0",
                    "/proc/sys/net/ipv6/conf/ipars0/disable_ipv6"
                ],
            )]
        );

        let runner = RecordingRunner::with_disabled_ipv6();
        let backend = LinuxWireGuardBackend::new("ipars0", runner.clone());
        backend.enable_ipv6().await?;
        assert_eq!(
            runner.commands().await,
            vec![
                LinuxCommand::new(
                    "grep",
                    [
                        "-F",
                        "-x",
                        "0",
                        "/proc/sys/net/ipv6/conf/ipars0/disable_ipv6"
                    ],
                ),
                LinuxCommand::new("tee", ["/proc/sys/net/ipv6/conf/ipars0/disable_ipv6"],)
                    .with_stdin(b"0\n".to_vec())
            ]
        );
        assert!(wireguard_enable_ipv6_command("../all").is_err());
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_application_refreshes_rotated_local_private_key() -> Result<(), AgentError> {
        let first_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let second_private_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let first_keypair = WireGuardKeyPair::from_private_key_b64(first_private_key)?;
        let second_keypair = WireGuardKeyPair::from_private_key_b64(second_private_key)?;
        let mut state = AgentNodeState::generate(Utc::now());
        state.wireguard_private_key_b64 = first_private_key.to_string();
        state.wireguard_public_key_b64 = first_keypair.public_key_b64;
        let runtime = Arc::new(AgentRuntime::new(state.clone(), ClusterPolicy::default()));
        let runner = RecordingRunner::default();
        let applier = PeerMapApplier::new(
            "ipars0",
            LinuxWireGuardBackend::new("ipars0", runner.clone()),
            DryRunLinuxRouteManager,
        )
        .with_lazy_connect_runtime(runtime.clone());
        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: Vec::new(),
            bootstrap_endpoints: Vec::new(),
            generated_at: Utc::now(),
        };

        applier.apply_peer_map(peer_map.clone()).await?;
        state.wireguard_private_key_b64 = second_private_key.to_string();
        state.wireguard_public_key_b64 = second_keypair.public_key_b64;
        runtime.replace_state(state)?;
        applier.apply_peer_map(peer_map).await?;

        assert_eq!(
            runner.commands().await,
            vec![
                LinuxCommand::new("wg", ["set", "ipars0", "private-key", "/dev/stdin"])
                    .with_stdin(format!("{first_private_key}\n").into_bytes()),
                LinuxCommand::new("wg", ["set", "ipars0", "private-key", "/dev/stdin"])
                    .with_stdin(format!("{second_private_key}\n").into_bytes()),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_application_recovers_a_missing_wireguard_interface() -> Result<(), AgentError>
    {
        let state = AgentNodeState::generate(Utc::now());
        let private_key = state.wireguard_private_key_b64.clone();
        let runtime = Arc::new(AgentRuntime::new(state, ClusterPolicy::default()));
        let runner = RecordingRunner::with_missing_interface();
        let applier = PeerMapApplier::new(
            "ipars0",
            LinuxWireGuardBackend::new("ipars0", runner.clone()),
            DryRunLinuxRouteManager,
        )
        .with_lazy_connect_runtime(runtime)
        .with_wireguard_interface_recovery(WireGuardInterfaceConfig {
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
            mtu: 1_280,
            listen_port: 51_820,
        });

        applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: Vec::new(),
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await?;

        assert_eq!(
            runner.commands().await,
            vec![
                LinuxCommand::new("wg", ["set", "ipars0", "private-key", "/dev/stdin"])
                    .with_stdin(format!("{private_key}\n").into_bytes()),
                LinuxCommand::new("ip", ["link", "show", "dev", "ipars0"]),
                LinuxCommand::new("ip", ["link", "add", "dev", "ipars0", "type", "wireguard"],),
                LinuxCommand::new("ip", ["link", "set", "up", "dev", "ipars0"]),
                LinuxCommand::new("ip", ["link", "set", "dev", "ipars0", "mtu", "1280"]),
                LinuxCommand::new("wg", ["set", "ipars0", "private-key", "/dev/stdin"])
                    .with_stdin(format!("{private_key}\n").into_bytes()),
                LinuxCommand::new("wg", ["set", "ipars0", "listen-port", "51820"]),
                LinuxCommand::new(
                    "ip",
                    ["address", "replace", "100.64.0.2/32", "dev", "ipars0"],
                ),
            ]
        );
        Ok(())
    }

    #[test]
    fn passive_wireguard_public_keys_are_valid_distinct_and_stable() -> Result<(), AgentError> {
        let first = WireGuardKeyPair::generate().public_key_b64;
        let second = WireGuardKeyPair::generate().public_key_b64;
        let first_passive = passive_wireguard_public_key(&first)?;

        validate_wireguard_public_key(&first_passive)?;
        assert_ne!(first_passive, first);
        assert_eq!(first_passive, passive_wireguard_public_key(&first)?);
        assert_ne!(first_passive, passive_wireguard_public_key(&second)?);
        Ok(())
    }

    #[test]
    fn command_wireguard_telemetry_parser_aggregates_bounded_field_outputs(
    ) -> Result<(), AgentError> {
        let first_key = encode_bytes(&[7; 32]);
        let second_key = encode_bytes(&[9; 32]);
        let handshakes = format!("{first_key}\t1710000000\n{second_key}\t0\n");
        let transfers = format!("{first_key}\t120\t340\n{second_key}\t0\t0\n");
        let endpoints = format!("{first_key}\t203.0.113.10:51820\n{second_key}\t(none)\n");

        let telemetry = parse_wireguard_command_telemetry(
            handshakes.as_bytes(),
            transfers.as_bytes(),
            endpoints.as_bytes(),
        )?;

        assert_eq!(telemetry.len(), 2);
        assert_eq!(
            telemetry.get(&first_key),
            Some(&WireGuardPeerTelemetry {
                public_key_b64: first_key,
                endpoint: Some("203.0.113.10:51820".to_string()),
                latest_handshake_at: DateTime::<Utc>::from_timestamp(1_710_000_000, 0),
                rx_bytes: 120,
                tx_bytes: 340,
            })
        );
        assert_eq!(
            telemetry.get(&second_key),
            Some(&WireGuardPeerTelemetry {
                public_key_b64: second_key,
                endpoint: None,
                latest_handshake_at: None,
                rx_bytes: 0,
                tx_bytes: 0,
            })
        );
        Ok(())
    }

    #[test]
    fn command_wireguard_telemetry_parser_rejects_malformed_or_untrusted_rows() {
        let key = encode_bytes(&[7; 32]);
        let malformed =
            parse_wireguard_command_telemetry(format!("{key} 1710000000\n").as_bytes(), b"", b"");
        assert!(matches!(
            malformed,
            Err(AgentError::WireGuard(message))
                if message.contains("expected 2 non-empty tab-separated fields")
        ));

        let invalid_key = parse_wireguard_command_telemetry(b"not-a-key\t0\n", b"", b"");
        assert!(matches!(
            invalid_key,
            Err(AgentError::WireGuard(message))
                if message.contains("invalid WireGuard public key")
        ));

        let low_order_key = format!("{}=", "A".repeat(43));
        let low_order =
            parse_wireguard_command_telemetry(format!("{low_order_key}\t0\n").as_bytes(), b"", b"");
        assert!(matches!(
            low_order,
            Err(AgentError::WireGuard(message)) if message.contains("public key has low order")
        ));
    }

    #[test]
    fn command_wireguard_peer_inventory_parser_validates_public_keys() -> Result<(), AgentError> {
        let first_key = WireGuardKeyPair::generate().public_key_b64;
        let second_key = WireGuardKeyPair::generate().public_key_b64;
        let inventory = parse_wireguard_command_peer_inventory(
            format!("{first_key}\n{second_key}\n").as_bytes(),
        )?;
        assert_eq!(
            inventory,
            BTreeSet::from([first_key.clone(), second_key.clone()])
        );

        let malformed =
            parse_wireguard_command_peer_inventory(format!("{first_key}\tunexpected\n").as_bytes());
        assert!(matches!(
            malformed,
            Err(AgentError::WireGuard(message))
                if message.contains("expected 1 non-empty tab-separated fields")
        ));
        let invalid = parse_wireguard_command_peer_inventory(b"not-a-key\n");
        assert!(matches!(
            invalid,
            Err(AgentError::WireGuard(message))
                if message.contains("invalid WireGuard public key")
        ));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_wireguard_telemetry_parser_reads_handshake_and_transfer() -> Result<(), AgentError> {
        let public_key = [7; 32];
        let peer = WireguardPeer(vec![
            WireguardPeerAttribute::PublicKey(public_key),
            WireguardPeerAttribute::Endpoint(SocketAddr::from(([203, 0, 113, 10], 51_820))),
            WireguardPeerAttribute::LastHandshake(netlink_packet_wireguard::WireguardTimeSpec {
                seconds: 1_710_000_000,
                nano_seconds: 123_000_000,
            }),
            WireguardPeerAttribute::RxBytes(120),
            WireguardPeerAttribute::TxBytes(340),
        ]);

        let telemetry = wireguard_netlink_peer_telemetry(&peer)?;

        assert_eq!(
            telemetry,
            WireGuardPeerTelemetry {
                public_key_b64: encode_bytes(&public_key),
                endpoint: Some("203.0.113.10:51820".to_string()),
                latest_handshake_at: DateTime::<Utc>::from_timestamp(1_710_000_000, 123_000_000,),
                rx_bytes: 120,
                tx_bytes: 340,
            }
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
    #[tokio::test]
    async fn kernel_wireguard_telemetry_rejects_unbounded_timeout() {
        let source = KernelWireGuardPeerTelemetrySource::new("ipars0").with_timeout(Duration::ZERO);

        let error = source.snapshot().await;

        assert!(matches!(
            error,
            Err(AgentError::WireGuard(message)) if message.contains("timeout must be greater than zero")
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_wireguard_backend_builds_netlink_peer_config() -> Result<(), AgentError> {
        let public_key_bytes = [7; 32];
        let public_key_b64 = encode_bytes(&public_key_bytes);
        let public_key = parse_wireguard_public_key(&public_key_b64)?;
        let config = WireGuardPeerConfig {
            peer: NodeId::from_string("node-a"),
            public_key: public_key_b64,
            endpoint: Some("203.0.113.10:51820".to_string()),
            allowed_ips: vec!["100.64.0.2/32".to_string(), "fd00::2/128".to_string()],
            persistent_keepalive_seconds: Some(25),
        };

        let peer = netlink_peer_config(&config, public_key)?;

        assert_eq!(public_key, public_key_bytes);
        assert!(peer
            .0
            .contains(&WireguardPeerAttribute::PublicKey(public_key_bytes)));
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
    async fn peer_map_applier_removes_unknown_stale_wireguard_peer_after_restart(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stale_key = WireGuardKeyPair::generate().public_key_b64;
        let runner = RecordingRunner::default();
        let applier = PeerMapApplier::new(
            "ipars0",
            LinuxWireGuardBackend::new("ipars0", runner.clone()),
            DryRunLinuxRouteManager,
        )
        .with_wireguard_peer_inventory(Arc::new(
            StaticWireGuardPeerInventory::from_public_keys([stale_key.clone()]),
        ));

        let summary = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: Vec::new(),
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await?;

        assert_eq!(summary.peers_removed, 1);
        assert_eq!(summary.peers_applied, 0);
        assert_eq!(
            runner.commands().await,
            vec![wireguard_remove_peer_command("ipars0", &stale_key)]
        );
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_removes_rotated_wireguard_key_before_upsert(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let old_key = WireGuardKeyPair::generate().public_key_b64;
        let new_key = WireGuardKeyPair::generate().public_key_b64;
        let peer_id = NodeId::from_string("peer-a");
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
            &new_key,
            Vec::new(),
            Vec::new(),
        );
        let runner = RecordingRunner::default();
        let applier = PeerMapApplier::new(
            "ipars0",
            LinuxWireGuardBackend::new("ipars0", runner.clone()),
            DryRunLinuxRouteManager,
        )
        .with_wireguard_peer_inventory(Arc::new(
            StaticWireGuardPeerInventory::from_public_keys([old_key.clone()]),
        ));

        let summary = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer],
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await?;

        assert_eq!(summary.peers_removed, 1);
        assert_eq!(summary.peers_applied, 1);
        assert_eq!(
            runner.commands().await,
            vec![
                wireguard_remove_peer_command("ipars0", &old_key),
                LinuxCommand::new(
                    "wg",
                    [
                        "set",
                        "ipars0",
                        "peer",
                        new_key.as_str(),
                        "allowed-ips",
                        "100.64.0.2/32",
                    ],
                ),
            ]
        );
        assert_eq!(
            applier
                .wireguard
                .peer_public_keys
                .read()
                .await
                .get(&peer_id),
            Some(&new_key)
        );
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_fails_before_upsert_when_peer_inventory_is_unavailable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let new_key = WireGuardKeyPair::generate().public_key_b64;
        let peer = peer_record(
            NodeId::from_string("peer-a"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
            &new_key,
            Vec::new(),
            Vec::new(),
        );
        let runner = RecordingRunner::default();
        let applier = PeerMapApplier::new(
            "ipars0",
            LinuxWireGuardBackend::new("ipars0", runner.clone()),
            DryRunLinuxRouteManager,
        )
        .with_wireguard_peer_inventory(Arc::new(StaticWireGuardPeerInventory::failing()));

        let result = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer],
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await;

        assert!(matches!(
            result,
            Err(AgentError::WireGuard(message))
                if message == "test WireGuard peer inventory failed"
        ));
        assert!(runner.commands().await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_rejects_duplicate_wireguard_keys_before_mutation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let shared_key = WireGuardKeyPair::generate().public_key_b64;
        let peers = vec![
            peer_record(
                NodeId::from_string("peer-a"),
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
                &shared_key,
                Vec::new(),
                Vec::new(),
            ),
            peer_record(
                NodeId::from_string("peer-b"),
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, 3)),
                &shared_key,
                Vec::new(),
                Vec::new(),
            ),
        ];
        let runner = RecordingRunner::default();
        let applier = PeerMapApplier::new(
            "ipars0",
            LinuxWireGuardBackend::new("ipars0", runner.clone()),
            DryRunLinuxRouteManager,
        )
        .with_wireguard_peer_inventory(Arc::new(
            StaticWireGuardPeerInventory::from_public_keys([]),
        ));

        let result = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers,
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await;

        assert!(matches!(
            result,
            Err(AgentError::WireGuard(message))
                if message.contains("to multiple peers")
        ));
        assert!(runner.commands().await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_rejects_local_wireguard_key_as_remote_peer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_public_key = state.wireguard_public_key_b64.clone();
        let runtime = Arc::new(AgentRuntime::new(state, ClusterPolicy::default()));
        let mut peer = peer_record(
            NodeId::from_string("peer-a"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
            &local_public_key,
            Vec::new(),
            Vec::new(),
        );
        peer.role = Role::control_plane();
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            DryRunLinuxRouteManager,
        )
        .with_wireguard_peer_inventory(Arc::new(StaticWireGuardPeerInventory::from_public_keys([])))
        .with_lazy_connect_runtime(runtime);

        let result = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer],
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await;

        assert!(matches!(
            result,
            Err(AgentError::WireGuard(message))
                if message.contains("local WireGuard public key")
        ));
        assert!(applier.wireguard.peers.read().await.is_empty());
        Ok(())
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
                    addr: SocketAddr::from(([8, 8, 8, 10], 51820)),
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
                bootstrap_endpoints: Vec::new(),
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
        assert_eq!(config.allowed_ips, vec!["100.64.0.2/32", "10.10.0.0/16"]);
        assert_eq!(config.endpoint.as_deref(), Some("8.8.8.10:51820"));
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
    async fn peer_map_applier_removes_unknown_managed_route_after_restart(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let desired =
            ManagedRoute::current(RoutePlanOwner::PeerMap, "100.64.0.70/32".parse()?, 10, 254);
        let stale =
            ManagedRoute::current(RoutePlanOwner::PeerMap, "10.70.0.0/16".parse()?, 50, 254);
        let route_manager = RecordingRouteManager::with_managed_inventory([desired, stale.clone()]);
        let applier =
            PeerMapApplier::new("ipars0", MemoryWireGuardBackend::default(), route_manager);
        let peer_id = NodeId::from_string("peer-after-restart");

        let summary = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer_record(
                    peer_id.clone(),
                    "100.64.0.70".parse()?,
                    "wg-peer-after-restart",
                    Vec::new(),
                    Vec::new(),
                )],
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await?;

        assert_eq!(summary.routes_removed, 1);
        assert_eq!(summary.routes_applied, 1);
        assert_eq!(
            applier
                .route_manager
                .managed_removed
                .read()
                .await
                .as_slice(),
            &[ManagedRouteInventory {
                routes: BTreeSet::from([stale]),
                policy_rules: BTreeSet::new(),
            }]
        );
        assert!(applier.wireguard.peers.read().await.contains_key(&peer_id));
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_route_inventory_failure_prevents_dataplane_mutation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::with_failed_managed_inventory(),
        );

        let result = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer_record(
                    NodeId::from_string("peer-inventory-failure"),
                    "100.64.0.71".parse()?,
                    "wg-peer-inventory-failure",
                    Vec::new(),
                    Vec::new(),
                )],
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await;

        assert!(matches!(
            result,
            Err(AgentError::RouteManager(RouteManagerError::Backend(message)))
                if message.contains("injected managed route inventory failure")
        ));
        assert!(applier.wireguard.peers.read().await.is_empty());
        assert!(applier.route_manager.applied.read().await.is_empty());
        assert!(applier.route_manager.removed.read().await.is_empty());
        assert!(applier
            .route_manager
            .managed_removed
            .read()
            .await
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_selects_one_provider_per_advertised_cidr(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        );
        let slower_id = NodeId::from_string("provider-a");
        let preferred_id = NodeId::from_string("provider-b");
        let cidr = "10.20.0.0/16".parse()?;
        let slower_route = Route {
            id: "service-a".to_string(),
            cidr,
            advertised_by: slower_id.clone(),
            via: Some(slower_id.clone()),
            metric: 100,
            tags: Default::default(),
        };
        let preferred_route = Route {
            id: "service-b".to_string(),
            cidr,
            advertised_by: preferred_id.clone(),
            via: Some(preferred_id.clone()),
            metric: 50,
            tags: Default::default(),
        };

        let summary = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![
                    peer_record(
                        slower_id.clone(),
                        "100.64.0.10".parse()?,
                        "wg-provider-a",
                        Vec::new(),
                        vec![slower_route],
                    ),
                    peer_record(
                        preferred_id.clone(),
                        "100.64.0.11".parse()?,
                        "wg-provider-b",
                        Vec::new(),
                        vec![preferred_route.clone()],
                    ),
                ],
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await?;

        assert_eq!(summary.routes_applied, 3);
        let peers = applier.wireguard.peers.read().await;
        assert_eq!(
            peers
                .get(&slower_id)
                .ok_or_else(|| AgentError::MissingPeer(slower_id.clone()))?
                .allowed_ips,
            vec!["100.64.0.10/32"]
        );
        assert_eq!(
            peers
                .get(&preferred_id)
                .ok_or_else(|| AgentError::MissingPeer(preferred_id.clone()))?
                .allowed_ips,
            vec!["100.64.0.11/32", "10.20.0.0/16"]
        );
        drop(peers);
        let applied = applier.route_manager.applied.read().await;
        let plan = applied
            .first()
            .ok_or_else(|| AgentError::RoutePlanning("missing route plan".to_string()))?;
        assert_eq!(
            plan.routes
                .iter()
                .filter(|route| route.cidr == cidr)
                .collect::<Vec<_>>(),
            vec![&preferred_route]
        );
        Ok(())
    }

    #[tokio::test]
    async fn bootstrap_peer_map_adds_recovery_path_without_pruning_existing_peers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wireguard = MemoryWireGuardBackend::default();
        let existing_peer = NodeId::from_string("existing-peer");
        wireguard
            .upsert_peer(WireGuardPeerConfig {
                peer: existing_peer.clone(),
                public_key: WireGuardKeyPair::generate().public_key_b64,
                endpoint: Some("8.8.8.8:51820".to_string()),
                allowed_ips: vec!["100.64.0.9/32".to_string()],
                persistent_keepalive_seconds: Some(25),
            })
            .await?;
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let recovery_peer = NodeId::from_string("recovery-peer");
        let recovery_key = WireGuardKeyPair::generate().public_key_b64;
        let peer = peer_record(
            recovery_peer.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10)),
            &recovery_key,
            vec![EndpointCandidate {
                node_id: recovery_peer.clone(),
                kind: EndpointCandidateKind::PublicUdp,
                addr: SocketAddr::from(([8, 8, 4, 4], 51820)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 1,
                source: CandidateSource::ControlPlane,
            }],
            Vec::new(),
        );
        let applier = PeerMapApplier::new("ipars0", wireguard, RecordingRouteManager::default())
            .with_lazy_connect_runtime(runtime);

        let summary = applier
            .apply_bootstrap_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer],
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await?;

        assert_eq!(summary.peers_applied, 1);
        assert_eq!(summary.peers_removed, 0);
        assert_eq!(summary.routes_applied, 1);
        assert_eq!(summary.routes_removed, 0);
        let peers = applier.wireguard.peers.read().await;
        assert!(peers.contains_key(&existing_peer));
        assert!(peers.contains_key(&recovery_peer));
        assert!(applier.route_manager.removed.read().await.is_empty());
        assert!(applier
            .route_manager
            .managed_removed
            .read()
            .await
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_moves_allowed_cidr_when_provider_disappears(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        );
        let primary_id = NodeId::from_string("provider-primary");
        let fallback_id = NodeId::from_string("provider-fallback");
        let cidr = "10.21.0.0/16".parse()?;
        let provider = |node_id: NodeId, vpn_ip: IpAddr, metric: u32| {
            peer_record(
                node_id.clone(),
                vpn_ip,
                &format!("wg-{node_id}"),
                Vec::new(),
                vec![Route {
                    id: format!("service-{node_id}"),
                    cidr,
                    advertised_by: node_id.clone(),
                    via: Some(node_id),
                    metric,
                    tags: Default::default(),
                }],
            )
        };
        let primary = provider(primary_id.clone(), "100.64.0.30".parse()?, 10);
        let fallback = provider(fallback_id.clone(), "100.64.0.31".parse()?, 20);

        applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![primary, fallback.clone()],
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await?;
        assert_eq!(
            applier
                .wireguard
                .peers
                .read()
                .await
                .get(&primary_id)
                .ok_or_else(|| AgentError::MissingPeer(primary_id.clone()))?
                .allowed_ips,
            vec!["100.64.0.30/32", "10.21.0.0/16"]
        );

        let summary = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![fallback],
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await?;

        assert_eq!(summary.peers_removed, 1);
        assert_eq!(summary.routes_removed, 2);
        let peers = applier.wireguard.peers.read().await;
        assert!(!peers.contains_key(&primary_id));
        assert_eq!(
            peers
                .get(&fallback_id)
                .ok_or(AgentError::MissingPeer(fallback_id))?
                .allowed_ips,
            vec!["100.64.0.31/32", "10.21.0.0/16"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_does_not_route_locally_advertised_cidrs_to_peers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_id = state.node_id.clone();
        let runtime = Arc::new(AgentRuntime::new(state, ClusterPolicy::default()));
        let local_route = Route {
            id: "local-service".to_string(),
            cidr: "10.30.0.0/16".parse()?,
            advertised_by: local_id.clone(),
            via: Some(local_id),
            metric: 50,
            tags: Default::default(),
        };
        runtime
            .replace_local_advertised_routes(vec![local_route.clone()])
            .await?;

        let peer_id = NodeId::from_string("provider-remote");
        runtime
            .record_peer_activity(peer_id.clone(), Utc::now(), false)
            .await;
        let remote_duplicate = Route {
            id: "remote-service".to_string(),
            cidr: local_route.cidr,
            advertised_by: peer_id.clone(),
            via: Some(peer_id.clone()),
            metric: 10,
            tags: Default::default(),
        };
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        )
        .with_lazy_connect_runtime(runtime);

        let summary = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer_record(
                    peer_id.clone(),
                    "100.64.0.20".parse()?,
                    "wg-provider-remote",
                    Vec::new(),
                    vec![remote_duplicate],
                )],
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await?;

        assert_eq!(summary.routes_applied, 1);
        let peers = applier.wireguard.peers.read().await;
        assert_eq!(
            peers
                .get(&peer_id)
                .ok_or(AgentError::MissingPeer(peer_id))?
                .allowed_ips,
            vec!["100.64.0.20/32"]
        );
        let applied = applier.route_manager.applied.read().await;
        assert!(applied
            .iter()
            .flat_map(|plan| &plan.routes)
            .all(|route| route.cidr != local_route.cidr));
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
                bootstrap_endpoints: Vec::new(),
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
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await?;
        let summary = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: Vec::new(),
                bootstrap_endpoints: Vec::new(),
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
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await?;
        let summary = applier
            .apply_peer_map(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![peer_without_route],
                bootstrap_endpoints: Vec::new(),
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
            .await?;
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
                addr: SocketAddr::from(([8, 8, 8, 10], 51820)),
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
                bootstrap_endpoints: Vec::new(),
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
    async fn pending_direct_probe_temporarily_overrides_relay_endpoint_and_expires(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let local_id = runtime.state().node_id.clone();
        let peer_id = NodeId::from_string("peer-probe");
        let direct_endpoint = SocketAddr::from(([8, 8, 8, 10], 51_820));
        let forwarder_endpoint = SocketAddr::from(([127, 0, 0, 1], 52_000));
        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(local_id, peer_id.clone()),
                selected_state: PathState::Relay,
                selected_candidate: None,
                relay_node: Some(NodeId::from_string("relay-a")),
                score: PathScore::calculate(PathState::Relay, &PathMetrics::default(), true, 0),
                updated_at: Utc::now(),
                pinned: false,
            })
            .await?;
        runtime
            .upsert_relay_forwarder_endpoint(peer_id.clone(), forwarder_endpoint)
            .await;
        runtime
            .upsert_relay_session(RelaySessionState {
                peer: peer_id.clone(),
                relay_node: NodeId::from_string("relay-a"),
                relay_endpoint: SocketAddr::from(([203, 0, 113, 30], 51_820)),
                admitted_local_addr: SocketAddr::from(([198, 51, 100, 10], 40_000)),
                admitted_peer_addr: SocketAddr::from(([198, 51, 100, 20], 40_000)),
                session_id: "session-probe".to_string(),
                session_token: "secret".to_string(),
                expires_at: Utc::now() + ChronoDuration::seconds(60),
            })
            .await;
        let candidate = EndpointCandidate {
            node_id: peer_id.clone(),
            kind: EndpointCandidateKind::PublicUdp,
            addr: direct_endpoint,
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::ControlPlane,
        };
        let now = Utc::now();
        runtime
            .upsert_pending_direct_path_probe(PendingDirectPathProbe {
                selected_state: PathState::DirectPublic,
                selected_candidate: candidate.clone(),
                started_at: now,
                expires_at: now + ChronoDuration::seconds(60),
                endpoint_observed_at: None,
                baseline_rx_bytes: Some(10),
                baseline_tx_bytes: Some(20),
                baseline_latest_handshake_at: None,
                baseline_relay_inbound_payload_bytes: None,
                relay_forwarder_suspended: false,
            })
            .await?;
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        )
        .with_endpoint_resolver(RuntimePeerEndpointResolver::new(runtime.clone()));
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)),
            "wg-peer-public",
            vec![candidate],
            Vec::new(),
        );
        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: vec![peer],
            bootstrap_endpoints: Vec::new(),
            generated_at: Utc::now(),
        };

        applier.apply_peer_map(peer_map.clone()).await?;
        assert_eq!(
            applier
                .wireguard
                .peers
                .read()
                .await
                .get(&peer_id)
                .and_then(|config| config.endpoint.as_deref()),
            Some("8.8.8.10:51820")
        );
        assert_eq!(
            applier
                .wireguard
                .peers
                .read()
                .await
                .get(&peer_id)
                .and_then(|config| config.persistent_keepalive_seconds),
            Some(1)
        );

        runtime
            .upsert_pending_direct_path_probe(PendingDirectPathProbe {
                selected_state: PathState::DirectPublic,
                selected_candidate: EndpointCandidate {
                    node_id: peer_id.clone(),
                    kind: EndpointCandidateKind::PublicUdp,
                    addr: direct_endpoint,
                    observed_at: Utc::now(),
                    priority: 100,
                    cost: 10,
                    source: CandidateSource::ControlPlane,
                },
                started_at: now - ChronoDuration::seconds(2),
                expires_at: now - ChronoDuration::seconds(1),
                endpoint_observed_at: None,
                baseline_rx_bytes: Some(10),
                baseline_tx_bytes: Some(20),
                baseline_latest_handshake_at: None,
                baseline_relay_inbound_payload_bytes: None,
                relay_forwarder_suspended: false,
            })
            .await?;
        applier.apply_peer_map(peer_map).await?;
        assert_eq!(
            applier
                .wireguard
                .peers
                .read()
                .await
                .get(&peer_id)
                .and_then(|config| config.endpoint.as_deref()),
            Some("127.0.0.1:52000")
        );
        assert_eq!(
            applier
                .wireguard
                .peers
                .read()
                .await
                .get(&peer_id)
                .and_then(|config| config.persistent_keepalive_seconds),
            Some(25)
        );
        Ok(())
    }

    #[tokio::test]
    async fn removing_pending_direct_probe_requests_endpoint_resync(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer_id = NodeId::from_string("peer-probe-resync");
        let now = Utc::now();
        let peer_map_sync = runtime.peer_map_sync_notifier();
        runtime
            .upsert_pending_direct_path_probe(PendingDirectPathProbe {
                selected_state: PathState::DirectPublic,
                selected_candidate: EndpointCandidate {
                    node_id: peer_id.clone(),
                    kind: EndpointCandidateKind::PublicUdp,
                    addr: SocketAddr::from(([8, 8, 8, 11], 51_820)),
                    observed_at: now,
                    priority: 100,
                    cost: 10,
                    source: CandidateSource::ControlPlane,
                },
                started_at: now,
                expires_at: now + ChronoDuration::seconds(60),
                endpoint_observed_at: None,
                baseline_rx_bytes: None,
                baseline_tx_bytes: None,
                baseline_latest_handshake_at: None,
                baseline_relay_inbound_payload_bytes: None,
                relay_forwarder_suspended: false,
            })
            .await?;
        tokio::time::timeout(Duration::from_secs(1), peer_map_sync.notified()).await?;

        assert!(runtime
            .remove_pending_direct_path_probe(&peer_id)
            .await
            .is_some());
        tokio::time::timeout(Duration::from_secs(1), peer_map_sync.notified()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn runtime_endpoint_resolver_uses_overlay_until_direct_path_is_selected(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let local_id = runtime.state().node_id.clone();
        let peer_id = NodeId::from_string("peer-overlay");
        let direct_candidate = EndpointCandidate {
            node_id: peer_id.clone(),
            kind: EndpointCandidateKind::PublicUdp,
            addr: SocketAddr::from(([8, 8, 8, 20], 51_820)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::ControlPlane,
        };
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 20)),
            "wg-peer-overlay",
            vec![direct_candidate.clone()],
            Vec::new(),
        );
        let overlay_endpoint = SocketAddr::from(([127, 0, 0, 1], 52_100));
        runtime
            .upsert_overlay_forwarder_endpoint(peer_id.clone(), overlay_endpoint)
            .await;
        let resolver = RuntimePeerEndpointResolver::new(runtime.clone());

        assert_eq!(
            resolver.endpoint_for_peer(&peer).await?,
            Some(overlay_endpoint.to_string())
        );

        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(local_id.clone(), peer_id.clone()),
                selected_state: PathState::DirectPublic,
                selected_candidate: Some(direct_candidate),
                relay_node: None,
                score: PathScore::calculate(
                    PathState::DirectPublic,
                    &PathMetrics::default(),
                    true,
                    0,
                ),
                updated_at: Utc::now(),
                pinned: false,
            })
            .await?;
        assert_eq!(
            resolver.endpoint_for_peer(&peer).await?,
            Some("8.8.8.20:51820".to_string())
        );

        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(local_id, peer_id.clone()),
                selected_state: PathState::Unreachable,
                selected_candidate: None,
                relay_node: None,
                score: PathScore::calculate(
                    PathState::Unreachable,
                    &PathMetrics::default(),
                    true,
                    0,
                ),
                updated_at: Utc::now(),
                pinned: false,
            })
            .await?;
        assert_eq!(
            resolver.endpoint_for_peer(&peer).await?,
            Some(overlay_endpoint.to_string())
        );
        runtime.remove_overlay_forwarder_endpoint(&peer_id).await;
        assert_eq!(resolver.endpoint_for_peer(&peer).await?, None);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_endpoint_resolver_uses_peer_local_udp_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let local_id = runtime.state().node_id.clone();
        let peer_id = NodeId::from_string("peer-local-udp");
        let local_candidate = EndpointCandidate {
            node_id: local_id.clone(),
            kind: EndpointCandidateKind::LocalUdp,
            addr: SocketAddr::from(([172, 18, 0, 3], 51_820)),
            observed_at: Utc::now(),
            priority: 70,
            cost: 30,
            source: CandidateSource::StunProbe,
        };
        let peer_reflexive_candidate = EndpointCandidate {
            node_id: peer_id.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr: SocketAddr::from(([172, 18, 0, 2], 18_410)),
            observed_at: Utc::now(),
            priority: 80,
            cost: 20,
            source: CandidateSource::StunProbe,
        };
        let peer_local_candidate = EndpointCandidate {
            node_id: peer_id.clone(),
            kind: EndpointCandidateKind::LocalUdp,
            addr: SocketAddr::from(([172, 18, 0, 2], 51_820)),
            observed_at: Utc::now(),
            priority: 70,
            cost: 30,
            source: CandidateSource::StunProbe,
        };
        runtime.replace_candidates(vec![local_candidate]).await;
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)),
            "wg-peer-local-udp",
            vec![peer_reflexive_candidate, peer_local_candidate.clone()],
            Vec::new(),
        );
        let resolver = RuntimePeerEndpointResolver::new(runtime.clone());
        let expected = Some("172.18.0.2:51820".to_string());

        assert_eq!(resolver.endpoint_for_peer(&peer).await?, expected);

        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(local_id.clone(), peer_id.clone()),
                selected_state: PathState::DirectNatTraversal,
                selected_candidate: Some(peer_local_candidate.clone()),
                relay_node: None,
                score: PathScore::calculate(
                    PathState::DirectNatTraversal,
                    &PathMetrics::default(),
                    true,
                    0,
                ),
                updated_at: Utc::now(),
                pinned: false,
            })
            .await?;
        assert_eq!(resolver.endpoint_for_peer(&peer).await?, expected);

        let now = Utc::now();
        runtime
            .upsert_pending_direct_path_probe(PendingDirectPathProbe {
                selected_state: PathState::DirectNatTraversal,
                selected_candidate: peer_local_candidate,
                started_at: now,
                expires_at: now + ChronoDuration::seconds(60),
                endpoint_observed_at: None,
                baseline_rx_bytes: None,
                baseline_tx_bytes: None,
                baseline_latest_handshake_at: None,
                baseline_relay_inbound_payload_bytes: None,
                relay_forwarder_suspended: false,
            })
            .await?;
        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(local_id, peer_id),
                selected_state: PathState::Unreachable,
                selected_candidate: None,
                relay_node: None,
                score: PathScore::calculate(
                    PathState::Unreachable,
                    &PathMetrics::default(),
                    true,
                    0,
                ),
                updated_at: Utc::now(),
                pinned: false,
            })
            .await?;
        assert_eq!(resolver.endpoint_for_peer(&peer).await?, expected);
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
                addr: SocketAddr::from(([8, 8, 8, 10], 51820)),
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
            bootstrap_endpoints: Vec::new(),
            generated_at: Utc::now(),
        };

        let first = applier.apply_peer_map(peer_map.clone()).await?;

        assert_eq!(
            first,
            PeerMapApplySummary {
                peers_applied: 3,
                peers_removed: 0,
                routes_applied: 3,
                routes_removed: 0,
            }
        );
        let wireguard_peers = applier.wireguard.peers.read().await;
        assert!(wireguard_peers.contains_key(&active_peer_id));
        let inactive_config = &wireguard_peers[&inactive_peer_id];
        assert_eq!(
            inactive_config.endpoint.as_deref(),
            Some(PASSIVE_WIREGUARD_HOLD_ENDPOINT)
        );
        assert_eq!(inactive_config.persistent_keepalive_seconds, None);
        assert_eq!(inactive_config.allowed_ips, vec!["100.64.0.11/32"]);
        assert_ne!(inactive_config.public_key, "wg-inactive");
        validate_wireguard_public_key(&inactive_config.public_key)?;
        assert!(wireguard_peers.contains_key(&pinned_peer_id));
        drop(wireguard_peers);
        assert_eq!(runtime.peer_map_snapshot().await?, peer_map);

        {
            let stale_at = Utc::now() - ChronoDuration::seconds(30);
            let mut lazy_connect = runtime.lazy_connect.write().await;
            lazy_connect
                .last_used
                .insert(active_peer_id.clone(), stale_at);
            lazy_connect
                .local_last_used
                .insert(active_peer_id.clone(), stale_at);
        }
        let second = applier.apply_peer_map(peer_map).await?;

        assert_eq!(
            second,
            PeerMapApplySummary {
                peers_applied: 2,
                peers_removed: 1,
                routes_applied: 3,
                routes_removed: 1,
            }
        );
        let wireguard_peers = applier.wireguard.peers.read().await;
        let inactive_active_config = &wireguard_peers[&active_peer_id];
        assert_eq!(
            inactive_active_config.endpoint.as_deref(),
            Some(PASSIVE_WIREGUARD_HOLD_ENDPOINT)
        );
        assert_eq!(inactive_active_config.persistent_keepalive_seconds, None);
        assert_ne!(inactive_active_config.public_key, "wg-active");
        validate_wireguard_public_key(&inactive_active_config.public_key)?;
        assert!(wireguard_peers.contains_key(&inactive_peer_id));
        assert!(wireguard_peers.contains_key(&pinned_peer_id));
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_resets_passive_handshake_when_activating(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let peer_id = NodeId::from_string("peer-on-demand");
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 20)),
            "wg-on-demand",
            vec![EndpointCandidate {
                node_id: peer_id.clone(),
                kind: EndpointCandidateKind::PublicUdp,
                addr: SocketAddr::from(([8, 8, 8, 20], 51_820)),
                observed_at: Utc::now(),
                priority: 100,
                cost: 10,
                source: CandidateSource::ControlPlane,
            }],
            Vec::new(),
        );
        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: vec![peer],
            bootstrap_endpoints: Vec::new(),
            generated_at: Utc::now(),
        };
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        )
        .with_lazy_connect_runtime(runtime.clone());

        let passive = applier.apply_peer_map(peer_map.clone()).await?;
        assert_eq!(passive.peers_applied, 1);
        assert_eq!(passive.peers_removed, 0);
        assert_eq!(passive.routes_applied, 1);
        let passive_config = applier.wireguard.peers.read().await[&peer_id].clone();
        assert_eq!(
            passive_config.endpoint.as_deref(),
            Some(PASSIVE_WIREGUARD_HOLD_ENDPOINT)
        );
        assert_ne!(passive_config.public_key, "wg-on-demand");
        validate_wireguard_public_key(&passive_config.public_key)?;

        runtime
            .record_peer_activity(peer_id.clone(), Utc::now(), false)
            .await;
        let active = applier.apply_peer_map(peer_map).await?;

        assert_eq!(active.peers_applied, 1);
        assert_eq!(active.peers_removed, 1);
        assert_eq!(active.routes_applied, 1);
        let wireguard_peers = applier.wireguard.peers.read().await;
        let active_config = &wireguard_peers[&peer_id];
        assert_eq!(active_config.endpoint.as_deref(), Some("8.8.8.20:51820"));
        assert_eq!(active_config.public_key, "wg-on-demand");
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applier_keeps_inbound_clients_ready_without_an_endpoint(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let client_id = NodeId::from_string("mac-client");
        let mut client = peer_record(
            client_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 30)),
            "wg-mac-client",
            Vec::new(),
            Vec::new(),
        );
        client.role = Role::client();
        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: vec![client],
            bootstrap_endpoints: Vec::new(),
            generated_at: Utc::now(),
        };
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        )
        .with_lazy_connect_runtime(runtime);

        let summary = applier.apply_peer_map(peer_map).await?;

        assert_eq!(summary.peers_applied, 1);
        let wireguard_peers = applier.wireguard.peers.read().await;
        let client_config = &wireguard_peers[&client_id];
        assert_eq!(client_config.public_key, "wg-mac-client");
        assert_eq!(client_config.endpoint, None);
        assert_eq!(client_config.persistent_keepalive_seconds, None);
        assert_eq!(client_config.allowed_ips, vec!["100.64.0.30/32"]);
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_queues_unknown_and_known_non_neighbor_destinations(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let local_vpn_destination = IpAddr::V4(Ipv4Addr::new(100, 64, 8, 8));
        state.vpn_ip = Some(VpnIp(local_vpn_destination));
        let runtime = AgentRuntime::new(state, ClusterPolicy::default());
        let neighbor = peer_record(
            NodeId::from_string("backbone-neighbor"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 8, 10)),
            "wg-backbone-neighbor",
            Vec::new(),
            Vec::new(),
        );
        runtime
            .record_neighbor_map_snapshot(bounded_neighbor_map(
                local_node.clone(),
                vec![neighbor.clone()],
                7,
            ))
            .await?;
        runtime
            .observe_peer_map_for_lazy_connect(std::slice::from_ref(&neighbor))
            .await;

        assert!(runtime
            .record_packet_flow_activity(local_vpn_destination, Utc::now(), false)
            .await
            .is_none());
        runtime
            .requeue_overlay_destination(local_vpn_destination)
            .await;
        runtime
            .record_remote_peer_activity(local_node, Utc::now())
            .await;
        assert!(runtime
            .take_pending_overlay_destinations(8)
            .await
            .is_empty());

        let overlay_destination = IpAddr::V4(Ipv4Addr::new(100, 64, 8, 9));
        assert!(runtime
            .record_packet_flow_activity(overlay_destination, Utc::now(), false)
            .await
            .is_none());
        assert_eq!(
            runtime.take_pending_overlay_destinations(8).await,
            vec![overlay_destination]
        );

        assert!(runtime
            .record_packet_flow_activity(neighbor.vpn_ip.0, Utc::now(), false)
            .await
            .is_some());
        assert!(runtime
            .take_pending_overlay_destinations(8)
            .await
            .is_empty());

        let non_neighbor = peer_record(
            NodeId::from_string("known-non-neighbor"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 8, 11)),
            "wg-known-non-neighbor",
            Vec::new(),
            Vec::new(),
        );
        runtime
            .observe_peer_map_for_lazy_connect(std::slice::from_ref(&non_neighbor))
            .await;
        assert!(runtime
            .record_packet_flow_activity(non_neighbor.vpn_ip.0, Utc::now(), false)
            .await
            .is_some());
        assert_eq!(
            runtime.take_pending_overlay_destinations(8).await,
            vec![non_neighbor.vpn_ip.0]
        );

        assert!(runtime
            .record_packet_flow_activity(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), Utc::now(), false,)
            .await
            .is_none());
        assert!(runtime
            .take_pending_overlay_destinations(8)
            .await
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_keeps_policy_pinned_non_neighbors_connected(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        state.vpn_ip = Some(VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 8, 8))));
        let runtime = Arc::new(AgentRuntime::new(state, ClusterPolicy::default()));
        let neighbor = peer_record(
            NodeId::from_string("backbone-neighbor"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 8, 10)),
            "wg-backbone-neighbor",
            Vec::new(),
            Vec::new(),
        );
        runtime
            .record_neighbor_map_snapshot(bounded_neighbor_map(
                local_node.clone(),
                vec![neighbor],
                7,
            ))
            .await?;

        let control_plane_id = NodeId::from_string("kubernetes-control-plane");
        let direct_endpoint = SocketAddr::from(([8, 8, 8, 8], 51_820));
        let direct_candidate = EndpointCandidate {
            node_id: control_plane_id.clone(),
            kind: EndpointCandidateKind::PublicUdp,
            addr: direct_endpoint,
            observed_at: Utc::now(),
            priority: 100,
            cost: 1,
            source: CandidateSource::ControlPlane,
        };
        let mut control_plane = peer_record(
            control_plane_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 8, 11)),
            "wg-kubernetes-control-plane",
            vec![direct_candidate.clone()],
            Vec::new(),
        );
        control_plane.tags.insert(Tag::kubernetes_control_plane());
        runtime
            .observe_peer_map_for_lazy_connect(std::slice::from_ref(&control_plane))
            .await;

        assert!(runtime.should_connect_peer(&control_plane).await);
        runtime
            .upsert_overlay_forwarder_endpoint(
                control_plane_id.clone(),
                SocketAddr::from(([127, 0, 0, 1], 52_120)),
            )
            .await;
        runtime
            .record_resolved_overlay_path(
                bounded_overlay_path(local_node, control_plane.clone(), control_plane.vpn_ip.0, 7),
                Utc::now(),
            )
            .await?;
        runtime
            .record_path_probe(
                AgentPathProbeRequest {
                    peer: control_plane_id.clone(),
                    selected_state: PathState::DirectPublic,
                    selected_candidate: Some(direct_candidate),
                    relay_node: None,
                    metrics: PathMetrics {
                        latency_ms: Some(1.0),
                        loss_ppm: 0,
                        jitter_ms: Some(0.1),
                        relay_load: None,
                        stability: 1.0,
                    },
                    policy_allowed: true,
                    cost: 1,
                    pin: false,
                },
                Utc::now(),
            )
            .await?;

        let shortcuts = runtime.overlay_shortcut_snapshot().await;
        assert!(!shortcuts.requires_overlay_forwarder(&control_plane_id));
        assert_eq!(
            RuntimePeerEndpointResolver::new(runtime)
                .endpoint_for_peer(&control_plane)
                .await?,
            Some(direct_endpoint.to_string())
        );
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_keeps_reciprocal_pinned_non_neighbors_connected(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        state.vpn_ip = Some(VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 8, 8))));
        let runtime = AgentRuntime::new(state, ClusterPolicy::default());
        let neighbor = peer_record(
            NodeId::from_string("backbone-neighbor"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 8, 10)),
            "wg-backbone-neighbor",
            Vec::new(),
            Vec::new(),
        );
        let reciprocal = peer_record(
            NodeId::from_string("reciprocal-policy-pin"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 8, 11)),
            "wg-reciprocal-policy-pin",
            Vec::new(),
            Vec::new(),
        );
        let mut neighbor_map = bounded_neighbor_map(local_node, vec![neighbor], 7);
        neighbor_map.pinned_peers.push(reciprocal.clone());
        runtime.record_neighbor_map_snapshot(neighbor_map).await?;
        runtime
            .observe_peer_map_for_lazy_connect(std::slice::from_ref(&reciprocal))
            .await;

        assert!(runtime.should_connect_peer(&reciprocal).await);
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_pending_destinations_retry_in_round_robin_order() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let destinations = (1_u8..=70)
            .map(|index| IpAddr::V4(Ipv4Addr::new(100, 64, 8, index)))
            .collect::<Vec<_>>();
        for destination in &destinations {
            runtime.requeue_overlay_destination(*destination).await;
            runtime.requeue_overlay_destination(*destination).await;
        }

        let first = runtime.take_pending_overlay_destinations(64).await;
        assert_eq!(first, destinations[..64]);
        for destination in first {
            runtime.requeue_overlay_destination(destination).await;
        }

        let second = runtime.take_pending_overlay_destinations(8).await;
        assert_eq!(
            second,
            destinations[64..70]
                .iter()
                .chain(&destinations[..2])
                .copied()
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn bounded_overlay_pending_destination_queue_has_a_hard_limit() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        for index in 1..=MAX_PENDING_OVERLAY_DESTINATIONS + 1 {
            runtime
                .requeue_overlay_destination(IpAddr::V6(std::net::Ipv6Addr::from(index as u128)))
                .await;
        }

        assert_eq!(
            runtime
                .take_pending_overlay_destinations(MAX_PENDING_OVERLAY_DESTINATIONS + 1)
                .await
                .len(),
            MAX_PENDING_OVERLAY_DESTINATIONS
        );
    }

    #[test]
    fn bounded_overlay_bulk_requeue_keeps_every_refresh_destination_when_full() {
        let mut pending = PendingOverlayDestinations::default();
        for index in 1..=MAX_PENDING_OVERLAY_DESTINATIONS {
            assert!(pending.enqueue(IpAddr::V6(std::net::Ipv6Addr::from(index as u128))));
        }
        let refresh = (1..=MAX_PENDING_OVERLAY_DESTINATIONS)
            .map(|index| {
                IpAddr::V6(std::net::Ipv6Addr::from(
                    (MAX_PENDING_OVERLAY_DESTINATIONS + index) as u128,
                ))
            })
            .collect::<Vec<_>>();

        pending.requeue_all_prioritized(refresh.iter().copied());

        assert_eq!(pending.take(MAX_PENDING_OVERLAY_DESTINATIONS + 1), refresh);
    }

    #[tokio::test]
    async fn bounded_overlay_shortcuts_expire_and_epoch_changes_migrate_them(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = ClusterPolicy {
            idle_timeout_seconds: 1,
            overlay_direct_shortcut_limit: 1,
            ..ClusterPolicy::default()
        };
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = AgentRuntime::new(state, policy);
        runtime
            .record_neighbor_map_snapshot(bounded_neighbor_map(local_node.clone(), Vec::new(), 7))
            .await?;

        let target_id = NodeId::from_string("overlay-target");
        let route = Route {
            id: "pod-cidr".to_string(),
            cidr: "10.42.8.0/24".parse()?,
            advertised_by: target_id.clone(),
            via: None,
            metric: 10,
            tags: BTreeSet::new(),
        };
        let target = peer_record(
            target_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 20)),
            "wg-overlay-target",
            Vec::new(),
            vec![route],
        );
        let observed_at = Utc::now();
        runtime
            .record_resolved_overlay_path(
                bounded_overlay_path(
                    local_node.clone(),
                    target.clone(),
                    IpAddr::V4(Ipv4Addr::new(10, 42, 8, 10)),
                    7,
                ),
                observed_at,
            )
            .await?;
        runtime
            .upsert_overlay_forwarder_endpoint(
                target_id.clone(),
                SocketAddr::from(([127, 0, 0, 1], 52_101)),
            )
            .await;
        runtime
            .observe_peer_map_for_lazy_connect(std::slice::from_ref(&target))
            .await;

        assert_eq!(runtime.resolved_overlay_peers().await, vec![target.clone()]);
        assert_eq!(runtime.metrics().await.lazy_connect.pinned_peer_count, 0);
        assert_eq!(
            runtime
                .take_idle_peers_to_close(observed_at + ChronoDuration::seconds(2))
                .await,
            vec![target_id.clone()]
        );
        assert!(runtime.resolved_overlay_peers().await.is_empty());
        assert_eq!(runtime.overlay_forwarder_endpoint(&target_id).await, None);

        let migration_destination = IpAddr::V4(Ipv4Addr::new(10, 42, 8, 11));
        runtime
            .record_resolved_overlay_path(
                bounded_overlay_path(local_node.clone(), target.clone(), migration_destination, 7),
                Utc::now(),
            )
            .await?;
        runtime
            .upsert_overlay_forwarder_endpoint(
                target_id.clone(),
                SocketAddr::from(([127, 0, 0, 1], 52_102)),
            )
            .await;
        let mut next_map = bounded_neighbor_map(local_node.clone(), Vec::new(), 8);
        next_map.routing_epoch = 7;
        runtime
            .record_neighbor_map_snapshot(next_map.clone())
            .await?;
        assert_eq!(runtime.resolved_overlay_peers().await, vec![target]);
        assert_eq!(
            runtime.overlay_forwarder_endpoint(&target_id).await,
            Some(SocketAddr::from(([127, 0, 0, 1], 52_102)))
        );
        assert_eq!(
            runtime.take_pending_overlay_destinations(8).await,
            vec![migration_destination]
        );

        for retained in runtime.retained_neighbor_maps.write().await.iter_mut() {
            retained.expires_at = Instant::now();
        }
        next_map.generated_at += ChronoDuration::milliseconds(1);
        runtime.record_neighbor_map_snapshot(next_map).await?;
        assert!(runtime.resolved_overlay_peers().await.is_empty());
        assert_eq!(runtime.overlay_forwarder_endpoint(&target_id).await, None);
        Ok(())
    }

    #[tokio::test]
    async fn rapid_epoch_changes_keep_a_bounded_set_of_previous_neighbors(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = AgentRuntime::new(state, ClusterPolicy::default());
        let generated_at = Utc::now();
        let mut neighbors = Vec::new();

        for index in 1_u8..=10 {
            let peer = peer_record(
                NodeId::from_string(format!("epoch-neighbor-{index}")),
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, index)),
                &format!("wg-epoch-neighbor-{index}"),
                Vec::new(),
                Vec::new(),
            );
            let mut neighbor_map =
                bounded_neighbor_map(local_node.clone(), vec![peer.clone()], u64::from(index));
            neighbor_map.generated_at =
                generated_at + ChronoDuration::milliseconds(i64::from(index));
            runtime.record_neighbor_map_snapshot(neighbor_map).await?;
            neighbors.push(peer);
        }

        let retained = runtime.retained_overlay_neighbors().await;
        assert_eq!(retained.len(), MAX_RETAINED_OVERLAY_TOPOLOGIES);
        assert!(retained
            .iter()
            .all(|peer| peer.node_id != neighbors[0].node_id));
        assert!(retained
            .iter()
            .any(|peer| peer.node_id == neighbors[1].node_id));
        assert!(runtime.should_connect_peer(&neighbors[1]).await);
        assert!(!runtime.should_connect_peer(&neighbors[0]).await);
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_does_not_allocate_unilateral_direct_shortcuts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = AgentRuntime::new(state, ClusterPolicy::default());
        let backbone = (1_u8..=4)
            .map(|index| {
                peer_record(
                    NodeId::from_string(format!("backbone-{index}")),
                    IpAddr::V4(Ipv4Addr::new(100, 64, 0, index)),
                    &format!("wg-backbone-{index}"),
                    Vec::new(),
                    Vec::new(),
                )
            })
            .collect::<Vec<_>>();
        let mut neighbor_map = bounded_neighbor_map(local_node.clone(), backbone.clone(), 7);
        let initial_generated_at = neighbor_map.generated_at;
        runtime.record_neighbor_map_snapshot(neighbor_map).await?;

        for index in 1_u8..=3 {
            let target = peer_record(
                NodeId::from_string(format!("shortcut-{index}")),
                IpAddr::V4(Ipv4Addr::new(100, 64, 1, index)),
                &format!("wg-shortcut-{index}"),
                Vec::new(),
                Vec::new(),
            );
            runtime
                .record_resolved_overlay_path(
                    bounded_overlay_path(
                        local_node.clone(),
                        target,
                        IpAddr::V4(Ipv4Addr::new(100, 64, 1, index)),
                        7,
                    ),
                    Utc::now(),
                )
                .await?;
        }

        let saturated = runtime.overlay_shortcut_snapshot().await;
        assert_eq!(saturated.resolved_overlay_peers().len(), 3);
        assert!(saturated.direct_shortcut_targets().is_empty());

        neighbor_map = bounded_neighbor_map(local_node, backbone[..3].to_vec(), 7);
        neighbor_map.generated_at = initial_generated_at + ChronoDuration::milliseconds(1);
        runtime.record_neighbor_map_snapshot(neighbor_map).await?;
        let unsaturated = runtime.overlay_shortcut_snapshot().await;
        assert_eq!(unsaturated.resolved_overlay_peers().len(), 3);
        assert!(unsaturated.direct_shortcut_targets().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_applies_a_lower_on_demand_peer_limit_immediately(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = AgentRuntime::new(state, ClusterPolicy::default());
        let mut neighbor_map = bounded_neighbor_map(local_node.clone(), Vec::new(), 7);
        neighbor_map.on_demand_peer_limit = 4;
        let initial_generated_at = neighbor_map.generated_at;
        runtime
            .record_neighbor_map_snapshot(neighbor_map.clone())
            .await?;

        let observed_at = Utc::now();
        for index in 1_u8..=4 {
            let target = peer_record(
                NodeId::from_string(format!("on-demand-{index}")),
                IpAddr::V4(Ipv4Addr::new(100, 64, 2, index)),
                &format!("wg-on-demand-{index}"),
                Vec::new(),
                Vec::new(),
            );
            runtime
                .record_resolved_overlay_path(
                    bounded_overlay_path(
                        local_node.clone(),
                        target,
                        IpAddr::V4(Ipv4Addr::new(100, 64, 2, index)),
                        7,
                    ),
                    observed_at + ChronoDuration::milliseconds(i64::from(index)),
                )
                .await?;
        }

        neighbor_map.on_demand_peer_limit = 2;
        neighbor_map.generated_at = initial_generated_at + ChronoDuration::milliseconds(1);
        runtime.record_neighbor_map_snapshot(neighbor_map).await?;

        let retained = runtime
            .resolved_overlay_peers()
            .await
            .into_iter()
            .map(|peer| peer.node_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            retained,
            BTreeSet::from([
                NodeId::from_string("on-demand-3"),
                NodeId::from_string("on-demand-4"),
            ])
        );
        let metrics = runtime.metrics().await.lazy_connect;
        assert_eq!(metrics.active_peer_count, 2);
        assert_eq!(metrics.on_demand_peer_limit, 2);
        Ok(())
    }

    #[tokio::test]
    async fn overlay_shortcut_snapshot_waits_for_neighbor_map_update(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let update = OverlayShortcutGenerationUpdate::begin(&runtime.overlay_shortcut_generation);
        let snapshot_runtime = runtime.clone();
        let snapshot_task =
            tokio::spawn(async move { snapshot_runtime.overlay_shortcut_snapshot().await });

        tokio::task::yield_now().await;
        assert!(!snapshot_task.is_finished());
        drop(update);

        tokio::time::timeout(Duration::from_secs(1), snapshot_task).await??;
        assert_eq!(
            runtime.overlay_shortcut_generation.load(Ordering::Acquire) % 2,
            0
        );
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_keeps_many_logical_paths_on_bounded_backbone(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = Arc::new(AgentRuntime::new(state, ClusterPolicy::default()));
        let mut neighbor_map = bounded_neighbor_map(local_node.clone(), Vec::new(), 7);
        neighbor_map.on_demand_peer_limit = 12;
        runtime.record_neighbor_map_snapshot(neighbor_map).await?;

        let observed_at = Utc::now();
        let mut targets = Vec::new();
        for index in 1_u8..=12 {
            let direct_endpoint = SocketAddr::from(([8, 8, 8, index], 51_820 + u16::from(index)));
            let overlay_endpoint = SocketAddr::from(([127, 0, 0, 1], 52_100 + u16::from(index)));
            let candidate = EndpointCandidate {
                node_id: NodeId::from_string(format!("overlay-target-{index}")),
                kind: EndpointCandidateKind::PublicUdp,
                addr: direct_endpoint,
                observed_at,
                priority: 100,
                cost: 10,
                source: CandidateSource::ControlPlane,
            };
            let target = peer_record(
                candidate.node_id.clone(),
                IpAddr::V4(Ipv4Addr::new(100, 64, 1, index)),
                &format!("wg-overlay-target-{index}"),
                vec![candidate.clone()],
                Vec::new(),
            );
            runtime
                .record_resolved_overlay_path(
                    bounded_overlay_path(
                        local_node.clone(),
                        target.clone(),
                        IpAddr::V4(Ipv4Addr::new(100, 64, 1, index)),
                        7,
                    ),
                    observed_at + ChronoDuration::milliseconds(i64::from(index)),
                )
                .await?;
            runtime
                .upsert_overlay_forwarder_endpoint(target.node_id.clone(), overlay_endpoint)
                .await;
            runtime
                .upsert_path_state(PathRecord {
                    key: PeerPathKey::new(local_node.clone(), target.node_id.clone()),
                    selected_state: PathState::DirectPublic,
                    selected_candidate: Some(candidate),
                    relay_node: None,
                    score: PathScore::calculate(
                        PathState::DirectPublic,
                        &PathMetrics::default(),
                        true,
                        0,
                    ),
                    updated_at: observed_at,
                    pinned: false,
                })
                .await?;
            targets.push((index, target, overlay_endpoint, direct_endpoint));
        }

        assert_eq!(runtime.resolved_overlay_peers().await.len(), 12);
        let initial_shortcuts = runtime.overlay_shortcut_snapshot().await;
        assert!(initial_shortcuts.direct_shortcut_targets().is_empty());
        assert!(Arc::ptr_eq(
            &initial_shortcuts,
            &runtime.overlay_shortcut_snapshot().await
        ));
        runtime
            .record_peer_activity(
                targets[0].1.node_id.clone(),
                observed_at + ChronoDuration::seconds(1),
                false,
            )
            .await;
        runtime
            .remove_overlay_forwarder_endpoint(&targets[1].1.node_id)
            .await;
        let current_shortcuts = runtime.overlay_shortcut_snapshot().await;
        assert!(!Arc::ptr_eq(&initial_shortcuts, &current_shortcuts));
        assert!(current_shortcuts.direct_shortcut_targets().is_empty());
        assert!(current_shortcuts.requires_overlay_forwarder(&targets[8].1.node_id));
        assert!(runtime
            .path_record_for_peer(&targets[8].1.node_id)
            .await
            .is_some_and(|path| path.selected_state.is_direct()));
        let resolver = RuntimePeerEndpointResolver::new(runtime);
        resolver.prepare_for_peer_map().await?;
        for (index, target, overlay_endpoint, _direct_endpoint) in targets {
            let expected = if index == 2 {
                None
            } else {
                Some(overlay_endpoint.to_string())
            };
            assert_eq!(resolver.endpoint_for_peer(&target).await?, expected);
        }
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_neighbor_map_rejects_management_plane_rollback(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = AgentRuntime::new(state, ClusterPolicy::default());
        let generated_at = Utc::now();
        let mut accepted = bounded_neighbor_map(local_node.clone(), Vec::new(), 7);
        accepted.generated_at = generated_at;
        runtime
            .record_neighbor_map_snapshot(accepted.clone())
            .await?;

        let mut older = bounded_neighbor_map(local_node.clone(), Vec::new(), 6);
        older.generated_at = generated_at - ChronoDuration::seconds(1);
        let error = match runtime.record_neighbor_map_snapshot(older).await {
            Ok(()) => panic!("older neighbor map must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, AgentError::InvalidState(message) if message.contains("older")));
        assert_eq!(
            runtime.neighbor_map_snapshot().await,
            Some(accepted.clone())
        );

        let mut conflicting = bounded_neighbor_map(local_node.clone(), Vec::new(), 8);
        conflicting.generated_at = generated_at;
        let error = match runtime.record_neighbor_map_snapshot(conflicting).await {
            Ok(()) => panic!("same-time conflicting neighbor map must be rejected"),
            Err(error) => error,
        };
        assert!(
            matches!(error, AgentError::InvalidState(message) if message.contains("conflicts"))
        );
        assert_eq!(
            runtime.neighbor_map_snapshot().await,
            Some(accepted.clone())
        );

        let mut stale_routing_epoch = bounded_neighbor_map(local_node.clone(), Vec::new(), 6);
        stale_routing_epoch.generated_at = generated_at + ChronoDuration::seconds(1);
        let error = match runtime
            .record_neighbor_map_snapshot(stale_routing_epoch)
            .await
        {
            Ok(()) => panic!("stale routing epoch must be rejected"),
            Err(error) => error,
        };
        assert!(
            matches!(error, AgentError::InvalidState(message) if message.contains("routing epoch") && message.contains("older"))
        );
        assert_eq!(runtime.neighbor_map_snapshot().await, Some(accepted));

        let mut newer = bounded_neighbor_map(local_node, Vec::new(), 8);
        newer.generated_at = generated_at + ChronoDuration::seconds(1);
        runtime.record_neighbor_map_snapshot(newer.clone()).await?;
        assert_eq!(runtime.neighbor_map_snapshot().await, Some(newer));
        Ok(())
    }

    #[tokio::test]
    async fn recording_neighbor_map_does_not_self_notify_peer_map_sync(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = AgentRuntime::new(state, ClusterPolicy::default());
        let peer_map_notify = runtime.peer_map_sync_notifier();

        runtime
            .record_neighbor_map_snapshot(bounded_neighbor_map(local_node, Vec::new(), 7))
            .await?;

        assert!(
            tokio::time::timeout(Duration::from_millis(10), peer_map_notify.notified())
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_route_owners_stay_passive_until_path_resolution(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = Arc::new(AgentRuntime::new(state, ClusterPolicy::default()));
        let backbone = (1_u8..=4)
            .map(|index| {
                peer_record(
                    NodeId::from_string(format!("backbone-{index}")),
                    IpAddr::V4(Ipv4Addr::new(100, 64, 0, index)),
                    &format!("wg-backbone-{index}"),
                    Vec::new(),
                    Vec::new(),
                )
            })
            .collect::<Vec<_>>();
        let route_owner_id = NodeId::from_string("pod-route-owner");
        let pod_route = Route {
            id: "pod-route".to_string(),
            cidr: "10.244.12.0/24".parse()?,
            advertised_by: route_owner_id.clone(),
            via: Some(route_owner_id.clone()),
            metric: 10,
            tags: BTreeSet::new(),
        };
        let route_owner = peer_record(
            route_owner_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 1, 12)),
            "wg-pod-route-owner",
            Vec::new(),
            vec![pod_route.clone()],
        );
        let mut neighbor_map = bounded_neighbor_map(local_node.clone(), backbone.clone(), 11);
        neighbor_map.aggregate_routes = vec![ipars_types::AggregateOverlayRoute {
            cidr: pod_route.cidr,
        }];
        runtime.record_neighbor_map_snapshot(neighbor_map).await?;

        let mut peers = backbone.clone();
        peers.push(route_owner.clone());
        let peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers,
            bootstrap_endpoints: Vec::new(),
            generated_at: Utc::now(),
        };
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        )
        .with_endpoint_resolver(RuntimePeerEndpointResolver::new(runtime.clone()))
        .with_lazy_connect_runtime(runtime.clone());

        applier.apply_peer_map(peer_map.clone()).await?;
        assert!(!runtime.should_connect_peer(&route_owner).await);
        let passive_config = applier
            .wireguard
            .peers
            .read()
            .await
            .get(&route_owner_id)
            .cloned()
            .ok_or_else(|| AgentError::MissingPeer(route_owner_id.clone()))?;
        assert_ne!(passive_config.public_key, route_owner.wireguard_public_key);
        assert_eq!(
            passive_config.endpoint.as_deref(),
            Some(PASSIVE_WIREGUARD_HOLD_ENDPOINT)
        );
        assert_eq!(
            passive_config.allowed_ips,
            vec![peer_overlay_cidr(&route_owner.vpn_ip)]
        );

        let overlay_endpoint = SocketAddr::from(([127, 0, 0, 1], 52_112));
        runtime
            .upsert_overlay_forwarder_endpoint(route_owner_id.clone(), overlay_endpoint)
            .await;
        let mut path = bounded_overlay_path(
            local_node.clone(),
            route_owner.clone(),
            route_owner.vpn_ip.0,
            11,
        );
        path.ordered_nodes = vec![
            local_node,
            backbone[0].node_id.clone(),
            route_owner_id.clone(),
        ];
        runtime
            .record_resolved_overlay_path(path, Utc::now())
            .await?;
        assert!(runtime.should_connect_peer(&route_owner).await);
        assert!(runtime
            .overlay_shortcut_snapshot()
            .await
            .direct_shortcut_targets()
            .is_empty());

        applier.apply_peer_map(peer_map).await?;
        let active_config = applier
            .wireguard
            .peers
            .read()
            .await
            .get(&route_owner_id)
            .cloned()
            .ok_or(AgentError::MissingPeer(route_owner_id))?;
        assert_eq!(active_config.public_key, route_owner.wireguard_public_key);
        assert_eq!(
            active_config.endpoint.as_deref(),
            Some(overlay_endpoint.to_string().as_str())
        );
        assert!(active_config
            .allowed_ips
            .contains(&pod_route.cidr.to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_adds_lazy_route_to_existing_backbone_neighbor_without_forwarder(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = AgentRuntime::new(state, ClusterPolicy::default());
        let target_id = NodeId::from_string("direct-route-owner");
        let selected_route = Route {
            id: "direct-owner-pod-cidr".to_string(),
            cidr: "10.244.30.0/24".parse()?,
            advertised_by: target_id.clone(),
            via: Some(target_id.clone()),
            metric: 10,
            tags: BTreeSet::new(),
        };
        let target = peer_record(
            target_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 1, 30)),
            "wg-direct-route-owner",
            Vec::new(),
            vec![selected_route.clone()],
        );
        let mut backbone_neighbor = target.clone();
        backbone_neighbor.routes.clear();
        let mut neighbor_map =
            bounded_neighbor_map(local_node.clone(), vec![backbone_neighbor.clone()], 30);
        neighbor_map.aggregate_routes = vec![ipars_types::AggregateOverlayRoute {
            cidr: selected_route.cidr,
        }];
        runtime.record_neighbor_map_snapshot(neighbor_map).await?;
        runtime
            .record_peer_map_snapshot(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![backbone_neighbor],
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await;

        let destination = IpAddr::V4(Ipv4Addr::new(10, 244, 30, 10));
        assert!(runtime
            .record_packet_flow_activity(destination, Utc::now(), false)
            .await
            .is_none());
        runtime
            .record_resolved_overlay_path(
                bounded_overlay_path(local_node, target, destination, 30),
                Utc::now(),
            )
            .await?;

        let peer_map = runtime.overlay_peer_map_snapshot().await?;
        assert_eq!(peer_map.peers.len(), 1);
        assert_eq!(peer_map.peers[0].node_id, target_id);
        assert_eq!(peer_map.peers[0].routes, vec![selected_route.clone()]);
        let shortcuts = runtime.overlay_shortcut_snapshot().await;
        assert!(!shortcuts.is_resolved_overlay_peer(&target_id));
        assert!(!shortcuts.requires_overlay_forwarder(&target_id));
        assert_eq!(
            runtime.resolved_overlay_paths().await[0]
                .ordered_nodes
                .len(),
            2
        );
        assert_eq!(
            runtime
                .record_packet_flow_activity(destination, Utc::now(), false)
                .await
                .map(|matched| (matched.peer, matched.route)),
            Some((target_id, Some(selected_route.cidr)))
        );
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_exact_routes_expire_independently_of_topology_pin(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = ClusterPolicy {
            idle_timeout_seconds: 1,
            ..ClusterPolicy::default()
        };
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = AgentRuntime::new(state, policy);
        let target_id = NodeId::from_string("pinned-backbone-route-owner");
        let target_vpn_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 1, 31));
        let routes = [
            Route {
                id: "pinned-backbone-route-a".to_string(),
                cidr: "10.244.31.0/24".parse()?,
                advertised_by: target_id.clone(),
                via: Some(target_id.clone()),
                metric: 10,
                tags: BTreeSet::new(),
            },
            Route {
                id: "pinned-backbone-route-b".to_string(),
                cidr: "10.244.32.0/24".parse()?,
                advertised_by: target_id.clone(),
                via: Some(target_id.clone()),
                metric: 10,
                tags: BTreeSet::new(),
            },
        ];
        let mut backbone_neighbor = peer_record(
            target_id.clone(),
            target_vpn_ip,
            "wg-pinned-backbone-route-owner",
            Vec::new(),
            Vec::new(),
        );
        backbone_neighbor.routes.clear();
        let mut neighbor_map =
            bounded_neighbor_map(local_node.clone(), vec![backbone_neighbor.clone()], 31);
        neighbor_map.aggregate_routes = vec![ipars_types::AggregateOverlayRoute {
            cidr: "10.244.0.0/16".parse()?,
        }];
        runtime.record_neighbor_map_snapshot(neighbor_map).await?;

        let observed_at = Utc::now();
        let destinations = [
            IpAddr::V4(Ipv4Addr::new(10, 244, 31, 10)),
            IpAddr::V4(Ipv4Addr::new(10, 244, 32, 10)),
        ];
        for (index, (route, destination)) in routes.iter().cloned().zip(destinations).enumerate() {
            let target = peer_record(
                target_id.clone(),
                target_vpn_ip,
                "wg-pinned-backbone-route-owner",
                Vec::new(),
                vec![route],
            );
            runtime
                .record_resolved_overlay_path(
                    bounded_overlay_path(local_node.clone(), target, destination, 31),
                    observed_at + ChronoDuration::milliseconds(index as i64 * 100),
                )
                .await?;
        }
        assert!(runtime
            .record_packet_flow_activity(
                destinations[1],
                observed_at + ChronoDuration::milliseconds(800),
                false,
            )
            .await
            .is_some());

        assert!(runtime
            .expire_idle_overlay_route_leases(observed_at + ChronoDuration::milliseconds(1_200),)
            .await
            .is_empty());
        let retained = runtime.resolved_overlay_paths().await;
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].target.routes, vec![routes[1].clone()]);

        assert!(runtime
            .expire_idle_overlay_route_leases(observed_at + ChronoDuration::milliseconds(2_000),)
            .await
            .is_empty());
        assert!(runtime.resolved_overlay_paths().await.is_empty());
        assert!(runtime.should_connect_peer(&backbone_neighbor).await);
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_merges_exact_route_leases_for_the_same_target(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = AgentRuntime::new(state, ClusterPolicy::default());
        runtime
            .record_neighbor_map_snapshot(bounded_neighbor_map(local_node.clone(), Vec::new(), 21))
            .await?;

        let target_id = NodeId::from_string("multi-podcidr-owner");
        let target_vpn_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 1, 21));
        let first_route = Route {
            id: "pod-cidr-a".to_string(),
            cidr: "10.244.21.0/24".parse()?,
            advertised_by: target_id.clone(),
            via: Some(target_id.clone()),
            metric: 10,
            tags: BTreeSet::new(),
        };
        let second_route = Route {
            id: "pod-cidr-b".to_string(),
            cidr: "10.244.22.0/24".parse()?,
            advertised_by: target_id.clone(),
            via: Some(target_id.clone()),
            metric: 10,
            tags: BTreeSet::new(),
        };
        let observed_at = Utc::now();

        for (index, route) in [first_route.clone(), second_route.clone()]
            .into_iter()
            .enumerate()
        {
            let destination = match index {
                0 => IpAddr::V4(Ipv4Addr::new(10, 244, 21, 10)),
                _ => IpAddr::V4(Ipv4Addr::new(10, 244, 22, 10)),
            };
            let target = peer_record(
                target_id.clone(),
                target_vpn_ip,
                "wg-multi-podcidr-owner",
                Vec::new(),
                vec![route],
            );
            runtime
                .record_resolved_overlay_path(
                    bounded_overlay_path(local_node.clone(), target, destination, 21),
                    observed_at + ChronoDuration::milliseconds(index as i64),
                )
                .await?;
        }

        let paths = runtime.resolved_overlay_paths().await;
        assert_eq!(paths.len(), 1);
        assert_eq!(
            paths[0]
                .target
                .routes
                .iter()
                .map(|route| route.cidr)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([first_route.cidr, second_route.cidr])
        );
        for destination in [
            IpAddr::V4(Ipv4Addr::new(10, 244, 21, 10)),
            IpAddr::V4(Ipv4Addr::new(10, 244, 22, 10)),
        ] {
            assert_eq!(
                runtime
                    .record_packet_flow_activity(
                        destination,
                        observed_at + ChronoDuration::seconds(1),
                        false,
                    )
                    .await
                    .map(|matched| matched.peer),
                Some(target_id.clone())
            );
        }
        let metrics = runtime.metrics().await.lazy_connect;
        assert_eq!(metrics.active_peer_count, 1);
        assert_eq!(metrics.observed_route_peer_count, 1);
        assert_eq!(metrics.observed_route_count, 2);
        Ok(())
    }

    #[test]
    fn resolved_overlay_peer_merge_never_exceeds_node_route_limit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let target_id = NodeId::from_string("merge-route-limit-owner");
        let route = |index: usize, segment: &str| -> Result<Route, ipnet::AddrParseError> {
            Ok(Route {
                id: format!("merge-route-{segment}-{index:03}"),
                cidr: format!("2001:db8:{segment}::{:x}/128", index + 1).parse()?,
                advertised_by: target_id.clone(),
                via: Some(target_id.clone()),
                metric: 10,
                tags: BTreeSet::new(),
            })
        };
        let existing_routes = (0..MAX_OVERLAY_NODE_ROUTES)
            .map(|index| route(index, "1"))
            .collect::<Result<Vec<_>, _>>()?;
        let resolved_route = route(0, "2")?;
        let existing = peer_record(
            target_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 1, 40)),
            "wg-merge-route-limit-owner",
            Vec::new(),
            existing_routes,
        );
        let resolved = peer_record(
            target_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 1, 40)),
            "wg-merge-route-limit-owner",
            Vec::new(),
            vec![resolved_route.clone()],
        );
        let mut peers = vec![existing];

        merge_resolved_overlay_peer(&mut peers, resolved);

        assert_eq!(peers[0].routes.len(), MAX_OVERLAY_NODE_ROUTES);
        assert!(peers[0]
            .routes
            .iter()
            .any(|route| route.cidr == resolved_route.cidr));

        let oversized = peer_record(
            target_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 1, 40)),
            "wg-merge-route-limit-owner",
            Vec::new(),
            (0..=MAX_OVERLAY_NODE_ROUTES)
                .map(|index| route(index, "3"))
                .collect::<Result<Vec<_>, _>>()?,
        );
        let mut empty = Vec::new();
        merge_resolved_overlay_peer(&mut empty, oversized);
        assert_eq!(empty[0].routes.len(), MAX_OVERLAY_NODE_ROUTES);
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_routing_epoch_change_revokes_and_requeues_exact_routes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = AgentRuntime::new(state, ClusterPolicy::default());
        let mut initial_map = bounded_neighbor_map(local_node.clone(), Vec::new(), 24);
        initial_map.routing_epoch = 240;
        initial_map.aggregate_routes = vec![ipars_types::AggregateOverlayRoute {
            cidr: "10.244.0.0/16".parse()?,
        }];
        let mut updated_map = initial_map.clone();
        updated_map.routing_epoch = 241;
        updated_map.generated_at += ChronoDuration::milliseconds(1);
        runtime.record_neighbor_map_snapshot(initial_map).await?;

        let target_id = NodeId::from_string("routing-revision-owner");
        let target_vpn_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 1, 24));
        let routes = [
            Route {
                id: "routing-revision-a".to_string(),
                cidr: "10.244.24.0/24".parse()?,
                advertised_by: target_id.clone(),
                via: Some(target_id.clone()),
                metric: 10,
                tags: BTreeSet::new(),
            },
            Route {
                id: "routing-revision-b".to_string(),
                cidr: "10.244.25.0/24".parse()?,
                advertised_by: target_id.clone(),
                via: Some(target_id.clone()),
                metric: 10,
                tags: BTreeSet::new(),
            },
        ];
        let destinations = [
            IpAddr::V4(Ipv4Addr::new(10, 244, 24, 10)),
            IpAddr::V4(Ipv4Addr::new(10, 244, 25, 10)),
        ];
        for (route, destination) in routes.iter().cloned().zip(destinations) {
            let target = peer_record(
                target_id.clone(),
                target_vpn_ip,
                "wg-routing-revision-owner",
                Vec::new(),
                vec![route],
            );
            let mut path = bounded_overlay_path(local_node.clone(), target, destination, 24);
            path.routing_epoch = 240;
            runtime
                .record_resolved_overlay_path(path, Utc::now())
                .await?;
        }
        let endpoint = SocketAddr::from(([127, 0, 0, 1], 52_124));
        runtime
            .upsert_overlay_forwarder_endpoint(target_id.clone(), endpoint)
            .await;

        runtime.record_neighbor_map_snapshot(updated_map).await?;
        assert!(runtime.resolved_overlay_paths().await.is_empty());
        assert_eq!(runtime.overlay_forwarder_endpoint(&target_id).await, None);
        let pending = runtime
            .take_pending_overlay_destinations(MAX_PENDING_OVERLAY_DESTINATIONS)
            .await
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(pending, BTreeSet::from(destinations));

        let target = peer_record(
            target_id,
            target_vpn_ip,
            "wg-routing-revision-owner",
            Vec::new(),
            vec![routes[0].clone()],
        );
        let mut path = bounded_overlay_path(local_node, target, destinations[0], 24);
        path.routing_epoch = 241;
        runtime
            .record_resolved_overlay_path(path, Utc::now())
            .await?;
        let paths = runtime.resolved_overlay_paths().await;
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].target.routes, vec![routes[0].clone()]);
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_evicts_oldest_route_within_per_peer_limit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = AgentRuntime::new(state, ClusterPolicy::default());
        let mut neighbor_map = bounded_neighbor_map(local_node.clone(), Vec::new(), 25);
        neighbor_map.aggregate_routes = vec![ipars_types::AggregateOverlayRoute {
            cidr: "10.0.0.0/8".parse()?,
        }];
        runtime.record_neighbor_map_snapshot(neighbor_map).await?;

        let target_id = NodeId::from_string("per-peer-route-limit-owner");
        let target_vpn_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 1, 25));
        let endpoint = SocketAddr::from(([127, 0, 0, 1], 52_125));
        runtime
            .upsert_overlay_forwarder_endpoint(target_id.clone(), endpoint)
            .await;
        let observed_at = Utc::now();
        let mut first_cidr = None;
        let mut last_cidr = None;
        for index in 0..=MAX_OVERLAY_NODE_ROUTES {
            let destination = IpAddr::V4(Ipv4Addr::new(
                10,
                25,
                (index / 256) as u8,
                (index % 256) as u8,
            ));
            let route = Route {
                id: format!("per-peer-route-{index:03}"),
                cidr: format!("{destination}/32").parse()?,
                advertised_by: target_id.clone(),
                via: Some(target_id.clone()),
                metric: 10,
                tags: BTreeSet::new(),
            };
            first_cidr.get_or_insert(route.cidr);
            last_cidr = Some(route.cidr);
            let target = peer_record(
                target_id.clone(),
                target_vpn_ip,
                "wg-per-peer-route-limit-owner",
                Vec::new(),
                vec![route],
            );
            runtime
                .record_resolved_overlay_path(
                    bounded_overlay_path(local_node.clone(), target, destination, 25),
                    observed_at + ChronoDuration::milliseconds(index as i64),
                )
                .await?;
        }

        let paths = runtime.resolved_overlay_paths().await;
        assert_eq!(paths.len(), 1);
        paths[0].validate()?;
        assert_eq!(paths[0].target.routes.len(), MAX_OVERLAY_NODE_ROUTES);
        assert!(!paths[0]
            .target
            .routes
            .iter()
            .any(|route| Some(route.cidr) == first_cidr));
        assert!(paths[0]
            .target
            .routes
            .iter()
            .any(|route| Some(route.cidr) == last_cidr));
        assert_eq!(
            runtime.overlay_forwarder_endpoint(&target_id).await,
            Some(endpoint)
        );
        assert_eq!(
            runtime.metrics().await.lazy_connect.observed_route_count,
            MAX_OVERLAY_NODE_ROUTES
        );
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_rejects_more_than_64_eager_route_scopes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = AgentRuntime::new(state, ClusterPolicy::default());
        let mut neighbor_map = bounded_neighbor_map(local_node, Vec::new(), 22);
        neighbor_map.aggregate_routes = (1..=ipars_types::MAX_OVERLAY_ROUTE_SCOPES + 1)
            .map(|index| {
                Ok(ipars_types::AggregateOverlayRoute {
                    cidr: format!("2001:db8::{index:x}/128").parse()?,
                })
            })
            .collect::<Result<Vec<_>, ipnet::AddrParseError>>()?;

        let error = match runtime.record_neighbor_map_snapshot(neighbor_map).await {
            Ok(()) => return Err("Agent accepted an eager route scope overflow".into()),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("aggregate route count 65 exceeds maximum 64"),
            "unexpected validation error: {error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_logical_podcidrs_and_resolved_leases_stay_bounded(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const ON_DEMAND_PEER_LIMIT: usize = 4;
        const SCALE_NODE_COUNT: usize = 1_000;

        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = Arc::new(AgentRuntime::new(state, ClusterPolicy::default()));
        let mut neighbor_map = bounded_neighbor_map(local_node.clone(), Vec::new(), 23);
        neighbor_map.aggregate_routes = vec![ipars_types::AggregateOverlayRoute {
            cidr: "10.0.0.0/8".parse()?,
        }];
        runtime.record_neighbor_map_snapshot(neighbor_map).await?;
        let empty_peer_map = PeerMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            peers: Vec::new(),
            bootstrap_endpoints: Vec::new(),
            generated_at: Utc::now(),
        };
        runtime
            .record_peer_map_snapshot(empty_peer_map.clone())
            .await;

        for index in 0..1_000_usize {
            let destination = IpAddr::V4(Ipv4Addr::new(
                10,
                1 + (index / 256) as u8,
                (index % 256) as u8,
                1,
            ));
            assert!(runtime
                .record_packet_flow_activity(destination, Utc::now(), false)
                .await
                .is_none());
        }
        assert_eq!(
            runtime.take_pending_overlay_destinations(1_001).await.len(),
            1_000
        );
        assert!(runtime.overlay_peer_map_snapshot().await?.peers.is_empty());

        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        )
        .with_lazy_connect_runtime(runtime.clone());
        applier.apply_peer_map(empty_peer_map).await?;
        let physical_peers = applier.wireguard.peers.read().await;
        assert_eq!(physical_peers.len(), 1);
        assert!(physical_peers.contains_key(&NodeId::from_string(OVERLAY_QUARANTINE_NODE_ID)));
        drop(physical_peers);

        let observed_at = Utc::now();
        let mut first_target = None;
        let mut second_target = None;
        let mut newest_target = None;
        for index in 0..SCALE_NODE_COUNT {
            let target_id = NodeId::from_string(format!("scale-route-owner-{index:04}"));
            let vpn_offset = index + 1;
            let target_vpn_ip = IpAddr::V4(Ipv4Addr::new(
                100,
                80,
                (vpn_offset / 256) as u8,
                (vpn_offset % 256) as u8,
            ));
            let destination = IpAddr::V4(Ipv4Addr::new(
                10,
                32,
                (index / 256) as u8,
                (index % 256) as u8,
            ));
            let selected_route = Route {
                id: format!("selected-pod-cidr-{index}"),
                cidr: format!("{destination}/32").parse()?,
                advertised_by: target_id.clone(),
                via: Some(target_id.clone()),
                metric: 10,
                tags: BTreeSet::new(),
            };
            let mut target_routes = vec![selected_route];
            if index == 0 {
                target_routes.extend((1..256).map(|route_index| {
                    Route {
                        id: format!("unselected-pod-cidr-{route_index}"),
                        cidr: format!("2001:db8:ffff::{route_index:x}/128")
                            .parse()
                            .unwrap_or_else(|error| {
                                panic!("static scale-test route must parse: {error}")
                            }),
                        advertised_by: target_id.clone(),
                        via: Some(target_id.clone()),
                        metric: 20,
                        tags: BTreeSet::new(),
                    }
                }));
            }
            let target = peer_record(
                target_id.clone(),
                target_vpn_ip,
                &format!("wg-scale-route-owner-{index:04}"),
                Vec::new(),
                target_routes,
            );
            runtime
                .record_resolved_overlay_path(
                    bounded_overlay_path(local_node.clone(), target, destination, 23),
                    observed_at + ChronoDuration::milliseconds(index as i64),
                )
                .await?;
            runtime
                .upsert_overlay_forwarder_endpoint(
                    target_id.clone(),
                    SocketAddr::from(([127, 0, 0, 1], 52_000_u16 + u16::try_from(index)?)),
                )
                .await;
            if index == 0 {
                runtime
                    .record_peer_activity(target_id.clone(), observed_at, true)
                    .await;
                first_target = Some(target_id);
            } else if index == 1 {
                second_target = Some(target_id);
            } else if index == SCALE_NODE_COUNT - 1 {
                newest_target = Some(target_id);
            }
        }

        {
            let resolved = runtime.resolved_overlay_paths.read().await;
            assert_eq!(resolved.exact_route_lru.len(), ON_DEMAND_PEER_LIMIT);
            assert_eq!(
                resolved
                    .paths
                    .values()
                    .map(ResolvedOverlayPathLease::exact_route_count)
                    .sum::<usize>(),
                resolved.exact_route_lru.len()
            );
        }
        let paths = runtime.resolved_overlay_paths().await;
        let retained_target_ids = paths
            .iter()
            .map(|path| path.target.node_id.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(paths.len(), ON_DEMAND_PEER_LIMIT);
        assert_eq!(
            paths
                .iter()
                .map(|path| path.target.routes.len())
                .sum::<usize>(),
            ON_DEMAND_PEER_LIMIT
        );
        assert!(retained_target_ids.contains(
            &first_target.ok_or_else(|| AgentError::InvalidState("missing first target".into()))?
        ));
        assert!(!retained_target_ids.contains(
            &second_target
                .ok_or_else(|| AgentError::InvalidState("missing second target".into()))?
        ));
        assert!(retained_target_ids.contains(
            &newest_target
                .ok_or_else(|| AgentError::InvalidState("missing newest target".into()))?
        ));
        let metrics = runtime.metrics().await.lazy_connect;
        assert_eq!(metrics.active_peer_count, ON_DEMAND_PEER_LIMIT);
        assert_eq!(metrics.on_demand_peer_limit, ON_DEMAND_PEER_LIMIT);
        assert_eq!(metrics.observed_peer_vpn_ip_count, ON_DEMAND_PEER_LIMIT);
        assert_eq!(metrics.observed_route_peer_count, ON_DEMAND_PEER_LIMIT);
        assert_eq!(metrics.observed_route_count, ON_DEMAND_PEER_LIMIT);

        applier
            .apply_peer_map(runtime.overlay_peer_map_snapshot().await?)
            .await?;
        let applied_peers = applier.wireguard.peers.read().await;
        assert_eq!(applied_peers.len(), ON_DEMAND_PEER_LIMIT + 1);
        assert!(applied_peers.contains_key(&NodeId::from_string(OVERLAY_QUARANTINE_NODE_ID)));
        Ok(())
    }

    #[tokio::test]
    async fn bounded_overlay_quarantine_does_not_duplicate_active_advertised_routes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = Arc::new(AgentRuntime::new(state, ClusterPolicy::default()));
        let old_neighbor = peer_record(
            NodeId::from_string("old-neighbor"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10)),
            "wg-old-neighbor",
            Vec::new(),
            Vec::new(),
        );
        let new_neighbor_id = NodeId::from_string("new-neighbor");
        let advertised_route = Route {
            id: "new-neighbor-pod-cidr".to_string(),
            cidr: "10.240.1.0/24".parse()?,
            advertised_by: new_neighbor_id.clone(),
            via: Some(new_neighbor_id.clone()),
            metric: 10,
            tags: BTreeSet::new(),
        };
        let resolved_neighbor = peer_record(
            new_neighbor_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 11)),
            "wg-new-neighbor",
            Vec::new(),
            vec![advertised_route.clone()],
        );
        let mut new_neighbor = resolved_neighbor.clone();
        new_neighbor.routes.clear();
        runtime
            .record_neighbor_map_snapshot(bounded_neighbor_map(
                local_node.clone(),
                vec![old_neighbor.clone()],
                7,
            ))
            .await?;
        assert!(runtime.should_connect_peer(&old_neighbor).await);

        let mut current_map =
            bounded_neighbor_map(local_node.clone(), vec![new_neighbor.clone()], 8);
        current_map.aggregate_routes = vec![ipars_types::AggregateOverlayRoute {
            cidr: advertised_route.cidr,
        }];
        runtime.record_neighbor_map_snapshot(current_map).await?;
        assert!(runtime.should_connect_peer(&old_neighbor).await);
        for retained in runtime.retained_neighbor_maps.write().await.iter_mut() {
            retained.expires_at = Instant::now();
        }
        assert!(!runtime.should_connect_peer(&old_neighbor).await);
        assert!(runtime.should_connect_peer(&new_neighbor).await);

        runtime
            .record_peer_map_snapshot(PeerMap {
                cluster_id: ClusterId::from_string("cluster-a"),
                peers: vec![new_neighbor.clone()],
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await;
        runtime
            .record_resolved_overlay_path(
                bounded_overlay_path(
                    local_node,
                    resolved_neighbor,
                    advertised_route.cidr.addr(),
                    8,
                ),
                Utc::now(),
            )
            .await?;
        let peer_map = runtime.overlay_peer_map_snapshot().await?;
        let applier = PeerMapApplier::new(
            "ipars0",
            MemoryWireGuardBackend::default(),
            RecordingRouteManager::default(),
        )
        .with_lazy_connect_runtime(runtime);
        applier.apply_peer_map(peer_map).await?;

        let peers = applier.wireguard.peers.read().await;
        assert_eq!(peers.len(), 2);
        assert_eq!(
            peers[&NodeId::from_string(OVERLAY_QUARANTINE_NODE_ID)].allowed_ips,
            vec!["100.64.0.0/10"]
        );
        assert_eq!(
            peers[&new_neighbor.node_id].allowed_ips,
            vec!["100.64.0.11/32", "10.240.1.0/24"]
        );
        drop(peers);
        let applied_routes = applier.route_manager.applied.read().await;
        let plan = applied_routes
            .last()
            .ok_or_else(|| AgentError::RoutePlanning("missing route plan".to_string()))?;
        assert!(plan.routes.iter().any(|route| {
            route.advertised_by == NodeId::from_string(OVERLAY_QUARANTINE_NODE_ID)
                && route.cidr.to_string() == "100.64.0.0/10"
        }));
        assert_eq!(
            plan.routes
                .iter()
                .filter(|route| route.cidr == advertised_route.cidr)
                .collect::<Vec<_>>(),
            vec![&advertised_route]
        );
        Ok(())
    }

    #[tokio::test]
    async fn internal_udp_control_flow_does_not_activate_lazy_peer() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer = peer_record(
            NodeId::from_string("peer-a"),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10)),
            "wg-peer-a",
            Vec::new(),
            Vec::new(),
        );
        runtime
            .observe_peer_map_for_lazy_connect(std::slice::from_ref(&peer))
            .await;
        runtime
            .replace_internal_packet_flow_udp_ports(BTreeSet::from([DEFAULT_PEER_PROBE_PORT]))
            .await;

        let matched = runtime
            .record_packet_flow_observation(
                peer.vpn_ip.0,
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    source_port: Some(49_152),
                    destination_port: Some(DEFAULT_PEER_PROBE_PORT),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await;

        assert_eq!(matched, None);
        assert!(!runtime.should_connect_peer(&peer).await);
        let metrics = runtime.metrics().await;
        assert_eq!(metrics.packet_flow_observation_count, 1);
        assert_eq!(metrics.packet_flow_match_count, 0);
        assert_eq!(metrics.packet_flow_filtered_count, 1);
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| entry.reason == AgentPacketFlowDropReason::InternalControlTraffic)
                .map(|entry| entry.count),
            Some(1)
        );
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

        let peer_map_sync = runtime.peer_map_sync_notifier();
        let heartbeat_report = runtime.heartbeat_report_notifier();
        let vpn_ip_match = runtime
            .record_packet_flow_activity(peer_a.vpn_ip.0, Utc::now(), false)
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_a_id.clone()))?;
        tokio::time::timeout(std::time::Duration::from_secs(1), peer_map_sync.notified()).await?;
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            heartbeat_report.notified(),
        )
        .await?;
        assert_eq!(vpn_ip_match.peer, peer_a_id);
        assert_eq!(vpn_ip_match.kind, AgentPacketFlowMatchKind::PeerVpnIp);
        assert_eq!(vpn_ip_match.route, None);
        assert!(!vpn_ip_match.pinned);
        assert!(runtime.should_connect_peer(&peer_a).await);

        let refreshed_at = Utc::now() + ChronoDuration::milliseconds(1);
        runtime
            .record_packet_flow_activity(peer_a.vpn_ip.0, refreshed_at, false)
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_a_id.clone()))?;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), peer_map_sync.notified())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), heartbeat_report.notified())
                .await
                .is_err()
        );
        assert_eq!(
            runtime
                .recent_local_peer_activity(&peer_a_id, refreshed_at)
                .await,
            Some(refreshed_at)
        );

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

        let dhcp_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 56)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    source_port: Some(68),
                    destination_port: Some(67),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(dhcp_match.peer, peer_b_id);
        let dhcpv6_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 57)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    source_port: Some(546),
                    destination_port: Some(547),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(dhcpv6_match.peer, peer_b_id);
        let vxlan_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 58)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(4789),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(vxlan_match.peer, peer_b_id);
        let geneve_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 59)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(6081),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(geneve_match.peer, peer_b_id);
        let openvpn_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 77)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(1194),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(openvpn_match.peer, peer_b_id);
        let ike_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 61)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(500),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(ike_match.peer, peer_b_id);
        let ipsec_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 62)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(4500),
                    payload_prefix: vec![
                        0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1, 0xa5, 0xa5, 0xa5, 0xa5,
                    ],
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(ipsec_match.peer, peer_b_id);
        let native_esp_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 63)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Esp),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(native_esp_match.peer, peer_b_id);
        let native_ah_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 65)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Ah),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(native_ah_match.peer, peer_b_id);
        let ip_tunnel_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 67)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::IpInIp),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(ip_tunnel_match.peer, peer_b_id);
        let sctp_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 66)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Sctp),
                    source_port: Some(5000),
                    destination_port: Some(5001),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(sctp_match.peer, peer_b_id);
        let gre_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 64)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Gre),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(gre_match.peer, peer_b_id);

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
        let kubelet_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 68)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(10250),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(kubelet_match.peer, peer_b_id);
        let docker_api_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 69)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(2376),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(docker_api_match.peer, peer_b_id);
        let cri_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 70)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    payload_prefix:
                        b"POST /runtime.v1.RuntimeService/ListContainers HTTP/1.1\r\ncontent-type: application/grpc\r\n"
                            .to_vec(),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(cri_match.peer, peer_b_id);
        let containerd_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 71)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    payload_prefix:
                        b"POST /containerd.services.content.v1.Content/Info HTTP/1.1\r\ncontent-type: application/grpc\r\n"
                            .to_vec(),
                    ..Default::default()
                },
                Utc::now(),
                false,
        )
        .await
        .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(containerd_match.peer, peer_b_id);
        let ipars_control_plane_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 72)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    payload_prefix: b"POST /v1/heartbeat HTTP/1.1\r\n".to_vec(),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(ipars_control_plane_match.peer, peer_b_id);
        let ipars_signal_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 73)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    payload_prefix: b"POST /v1/paths/negotiate HTTP/1.1\r\n".to_vec(),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(ipars_signal_match.peer, peer_b_id);
        let ipars_agent_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 74)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    payload_prefix: b"POST /v1/packet-flow HTTP/1.1\r\n".to_vec(),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(ipars_agent_match.peer, peer_b_id);
        let ipars_relay_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 75)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    payload_prefix: b"POST /v1/sessions HTTP/1.1\r\n".to_vec(),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(ipars_relay_match.peer, peer_b_id);
        let stun_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 76)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(3478),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(stun_match.peer, peer_b_id);
        let turn_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 79)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(5349),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(turn_match.peer, peer_b_id);
        let coap_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 80)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(5683),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(coap_match.peer, peer_b_id);
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
        let snmp_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 50)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(161),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(snmp_match.peer, peer_b_id);
        let kerberos_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 51)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(88),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(kerberos_match.peer, peer_b_id);
        let ntp_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 52)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(123),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(ntp_match.peer, peer_b_id);
        let radius_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 53)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(1812),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(radius_match.peer, peer_b_id);
        let tacacs_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 54)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(49),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(tacacs_match.peer, peer_b_id);
        let bgp_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 55)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(179),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(bgp_match.peer, peer_b_id);
        let sip_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 78)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(5060),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(sip_match.peer, peer_b_id);
        let bfd_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 60)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(3784),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(bfd_match.peer, peer_b_id);
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
        let pulsar_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 49)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(6650),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(pulsar_match.peer, peer_b_id);
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
        let couchbase_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 82)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(11210),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(couchbase_match.peer, peer_b_id);
        let grafana_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 83)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(3000),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(grafana_match.peer, peer_b_id);
        let statsd_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 84)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(8125),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(statsd_match.peer, peer_b_id);
        let graphite_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 85)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(2003),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(graphite_match.peer, peer_b_id);
        let collectd_match = runtime
            .record_packet_flow_observation(
                IpAddr::V4(Ipv4Addr::new(10, 42, 7, 86)),
                AgentPacketFlowObservation {
                    protocol: Some(TransportProtocol::Udp),
                    destination_port: Some(25826),
                    ..Default::default()
                },
                Utc::now(),
                false,
            )
            .await
            .ok_or_else(|| AgentError::MissingPeer(peer_b_id.clone()))?;
        assert_eq!(collectd_match.peer, peer_b_id);
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
        assert_eq!(metrics.packet_flow_observation_count, 66);
        assert_eq!(metrics.packet_flow_match_count, 64);
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
            64
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
        assert_eq!(application_count(AgentPacketFlowApplication::Unknown), 4);
        assert_eq!(application_count(AgentPacketFlowApplication::Dhcp), 2);
        assert_eq!(application_count(AgentPacketFlowApplication::Ike), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Ipsec), 3);
        assert_eq!(application_count(AgentPacketFlowApplication::IpTunnel), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Gre), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Vxlan), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Geneve), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::OpenVpn), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Https), 1);
        assert_eq!(
            application_count(AgentPacketFlowApplication::IparsControlPlane),
            1
        );
        assert_eq!(
            application_count(AgentPacketFlowApplication::IparsSignal),
            1
        );
        assert_eq!(application_count(AgentPacketFlowApplication::IparsAgent), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::IparsRelay), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Stun), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Turn), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Coap), 1);
        assert_eq!(
            application_count(AgentPacketFlowApplication::KubernetesApi),
            1
        );
        assert_eq!(application_count(AgentPacketFlowApplication::Kubelet), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::DockerApi), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Cri), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Containerd), 1);
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
        assert_eq!(application_count(AgentPacketFlowApplication::Snmp), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Kerberos), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Ntp), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Radius), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Tacacs), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Bgp), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Sip), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Bfd), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Jaeger), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Loki), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Tempo), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Zipkin), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Kafka), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Pulsar), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Memcached), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Couchbase), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Grafana), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Statsd), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Graphite), 1);
        assert_eq!(application_count(AgentPacketFlowApplication::Collectd), 1);
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
    async fn packet_flow_payload_prefix_metrics_cover_messaging_and_database_protocols(
    ) -> Result<(), Box<dyn std::error::Error>> {
        fn mqtt_publish_packet(topic: &[u8], value: &[u8]) -> Vec<u8> {
            let mut body = (topic.len() as u16).to_be_bytes().to_vec();
            body.extend_from_slice(topic);
            body.extend_from_slice(value);
            let mut payload = vec![0x30, body.len() as u8];
            payload.extend_from_slice(&body);
            payload
        }

        fn cassandra_startup_frame() -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&1_u16.to_be_bytes());
            body.extend_from_slice(&(b"CQL_VERSION".len() as u16).to_be_bytes());
            body.extend_from_slice(b"CQL_VERSION");
            body.extend_from_slice(&(b"3.0.0".len() as u16).to_be_bytes());
            body.extend_from_slice(b"3.0.0");

            let mut frame = vec![0x04, 0, 0, 0, 0x01];
            frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
            frame.extend_from_slice(&body);
            frame
        }

        fn mongodb_op_msg() -> Vec<u8> {
            let mut body = 0_u32.to_le_bytes().to_vec();
            body.push(0);
            body.extend_from_slice(&[5, 0, 0, 0, 0]);

            let length = (16 + body.len()) as u32;
            let mut payload = Vec::new();
            payload.extend_from_slice(&length.to_le_bytes());
            payload.extend_from_slice(&1_u32.to_le_bytes());
            payload.extend_from_slice(&0_u32.to_le_bytes());
            payload.extend_from_slice(&2013_u32.to_le_bytes());
            payload.extend_from_slice(&body);
            payload
        }

        fn clickhouse_client_hello() -> Vec<u8> {
            fn uvarint(mut value: u64) -> Vec<u8> {
                let mut encoded = Vec::new();
                loop {
                    let mut byte = (value & 0x7f) as u8;
                    value >>= 7;
                    if value != 0 {
                        byte |= 0x80;
                    }
                    encoded.push(byte);
                    if value == 0 {
                        break;
                    }
                }
                encoded
            }

            fn string(value: &[u8]) -> Vec<u8> {
                let mut encoded = uvarint(value.len() as u64);
                encoded.extend_from_slice(value);
                encoded
            }

            let mut payload = uvarint(0);
            payload.extend_from_slice(&string(b"Go Client"));
            payload.extend_from_slice(&uvarint(1));
            payload.extend_from_slice(&uvarint(10));
            payload.extend_from_slice(&uvarint(54_451));
            payload.extend_from_slice(&string(b"default"));
            payload.extend_from_slice(&string(b"default"));
            payload.extend_from_slice(&string(b""));
            payload
        }

        fn memcached_binary_get_response(value: &[u8]) -> Vec<u8> {
            let extras = [0, 0, 0, 1];
            let total_body_len = extras.len() + value.len();
            let mut payload = Vec::with_capacity(24 + total_body_len);
            payload.push(0x81);
            payload.push(0x00);
            payload.extend_from_slice(&0_u16.to_be_bytes());
            payload.push(extras.len() as u8);
            payload.push(0);
            payload.extend_from_slice(&0_u16.to_be_bytes());
            payload.extend_from_slice(&(total_body_len as u32).to_be_bytes());
            payload.extend_from_slice(&0_u32.to_be_bytes());
            payload.extend_from_slice(&0_u64.to_be_bytes());
            payload.extend_from_slice(&extras);
            payload.extend_from_slice(value);
            payload
        }

        fn turn_allocate_request() -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(&0x0003_u16.to_be_bytes());
            payload.extend_from_slice(&0_u16.to_be_bytes());
            payload.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
            payload.extend_from_slice(&[0xa5; 12]);
            payload
        }

        fn coap_get_request() -> Vec<u8> {
            vec![0x40, 0x01, 0x12, 0x34]
        }

        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let peer_id = NodeId::from_string("peer-payload");
        let peer = peer_record(
            peer_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 80)),
            "wg-peer-payload",
            Vec::new(),
            vec![Route {
                id: "payload-route".to_string(),
                cidr: "10.52.0.0/16".parse()?,
                advertised_by: peer_id.clone(),
                via: None,
                metric: 10,
                tags: BTreeSet::new(),
            }],
        );
        runtime.observe_peer_map_for_lazy_connect(&[peer]).await;

        let payloads = [
            (
                AgentPacketFlowApplication::Nats,
                TransportProtocol::Tcp,
                b"PING\r\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Mqtt,
                TransportProtocol::Tcp,
                mqtt_publish_packet(b"sensors/temp", b"22.4"),
            ),
            (
                AgentPacketFlowApplication::Amqp,
                TransportProtocol::Tcp,
                b"AMQP\0\0\x09\x01".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Cassandra,
                TransportProtocol::Tcp,
                cassandra_startup_frame(),
            ),
            (
                AgentPacketFlowApplication::MongoDb,
                TransportProtocol::Tcp,
                mongodb_op_msg(),
            ),
            (
                AgentPacketFlowApplication::Neo4j,
                TransportProtocol::Tcp,
                vec![
                    0x60, 0x60, 0xb0, 0x17, 0x00, 0x00, 0x01, 0xff, 0x00, 0x03, 0x03, 0x04, 0x00,
                    0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x03,
                ],
            ),
            (
                AgentPacketFlowApplication::ClickHouse,
                TransportProtocol::Tcp,
                clickhouse_client_hello(),
            ),
            (
                AgentPacketFlowApplication::Redis,
                TransportProtocol::Tcp,
                b"|1\r\n$3\r\nttl\r\n:60\r\n>2\r\n$7\r\nmessage\r\n$5\r\nhello\r\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Memcached,
                TransportProtocol::Tcp,
                memcached_binary_get_response(b"value"),
            ),
            (
                AgentPacketFlowApplication::Couchbase,
                TransportProtocol::Tcp,
                b"GET /pools/default/buckets HTTP/1.1\r\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Grafana,
                TransportProtocol::Tcp,
                b"GET /api/datasources HTTP/1.1\r\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Statsd,
                TransportProtocol::Udp,
                b"api.request.count:1|c\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Graphite,
                TransportProtocol::Tcp,
                b"servers.web01.cpu.load 1.5 1720051200\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Collectd,
                TransportProtocol::Udp,
                vec![
                    0, 0, 0, 12, b'n', b'o', b'd', b'e', b'-', b'0', b'1', 0, 0, 2, 0, 8, b'c',
                    b'p', b'u', 0, 0, 4, 0, 8, b'c', b'p', b'u', 0, 0, 6, 0, 15, 0, 1, 1, 0x3f,
                    0xf0, 0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                AgentPacketFlowApplication::OpenSearch,
                TransportProtocol::Tcp,
                b"HTTP/1.1 200 OK\r\nX-OpenSearch-Product: OpenSearch\r\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Solr,
                TransportProtocol::Tcp,
                b"HTTP/1.1 200 OK\r\nX-Solr-Version: 9.6.1\r\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Git,
                TransportProtocol::Tcp,
                b"GET /team/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Vnc,
                TransportProtocol::Tcp,
                b"RFB 003.008\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Ftp,
                TransportProtocol::Tcp,
                b"PASV\r\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Tftp,
                TransportProtocol::Udp,
                b"\0\x01boot.ipxe\0octet\0".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Rsync,
                TransportProtocol::Tcp,
                b"@RSYNCD: 31.0\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Smtp,
                TransportProtocol::Tcp,
                b"EHLO edge-node.example\r\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Imap,
                TransportProtocol::Tcp,
                b"A001 UID FETCH 42 BODY[]\r\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Pop3,
                TransportProtocol::Tcp,
                b"USER agent\r\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Sip,
                TransportProtocol::Udp,
                b"REGISTER sip:edge.example SIP/2.0\r\n".to_vec(),
            ),
            (
                AgentPacketFlowApplication::Turn,
                TransportProtocol::Udp,
                turn_allocate_request(),
            ),
            (
                AgentPacketFlowApplication::Coap,
                TransportProtocol::Udp,
                coap_get_request(),
            ),
        ];

        for (index, (_application, protocol, payload_prefix)) in payloads.iter().enumerate() {
            let matched = runtime
                .record_packet_flow_observation(
                    IpAddr::V4(Ipv4Addr::new(10, 52, 7, 10 + index as u8)),
                    AgentPacketFlowObservation {
                        protocol: Some(*protocol),
                        destination_port: Some(30_000 + index as u16),
                        payload_prefix: payload_prefix.clone(),
                        ..Default::default()
                    },
                    Utc::now(),
                    false,
                )
                .await
                .ok_or_else(|| AgentError::MissingPeer(peer_id.clone()))?;
            assert_eq!(matched.peer, peer_id);
        }

        let metrics = runtime.metrics().await;
        assert_eq!(metrics.packet_flow_observation_count, payloads.len() as u64);
        assert_eq!(metrics.packet_flow_match_count, payloads.len() as u64);
        assert_eq!(metrics.packet_flow_unmatched_count, 0);

        for (application, _protocol, _payload_prefix) in payloads {
            let count = metrics
                .packet_flow_application_counts
                .iter()
                .find(|entry| entry.application == application)
                .map(|entry| entry.count)
                .unwrap_or(0);
            assert_eq!(
                count, 1,
                "{application:?} should be counted from payload prefix"
            );
        }
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
                protocol: Some(TransportProtocol::Tcp),
                destination_port: Some(443),
                detector: Some(" sidecar".to_string()),
                ..Default::default()
            },
            AgentPacketFlowObservation {
                protocol: Some(TransportProtocol::Tcp),
                destination_port: Some(443),
                detector: Some("sidecar tag".to_string()),
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
        assert_eq!(metrics.packet_flow_filtered_count, 5);
        assert_eq!(
            metrics
                .packet_flow_filtered_reason_counts
                .iter()
                .find(|entry| {
                    entry.reason == AgentPacketFlowDropReason::InconsistentTransportMetadata
                })
                .map(|entry| entry.count),
            Some(5)
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
            bootstrap_endpoints: Vec::new(),
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

    #[test]
    fn agent_node_state_rejects_inconsistent_key_material_and_timestamps() {
        let now = Utc::now();
        let state = AgentNodeState::generate(now);
        let other = AgentNodeState::generate(now);
        assert!(state.validate().is_ok());

        let mut cases = Vec::new();

        let mut invalid = state.clone();
        invalid.identity_private_key_b64 = "A".repeat(64 * 1024);
        cases.push((invalid, "identity private key is invalid"));

        let mut invalid = state.clone();
        invalid.identity_public_key_b64 = other.identity_public_key_b64.clone();
        cases.push((
            invalid,
            "identity public key does not match identity private key",
        ));

        let mut invalid = state.clone();
        invalid.node_id = other.node_id;
        cases.push((invalid, "does not match identity key-derived node ID"));

        let mut invalid = state.clone();
        invalid.wireguard_private_key_b64 = "not-a-key".to_string();
        cases.push((invalid, "WireGuard private key is invalid"));

        let mut invalid = state.clone();
        invalid.wireguard_public_key_b64 = other.wireguard_public_key_b64;
        cases.push((
            invalid,
            "WireGuard public key does not match WireGuard private key",
        ));

        let mut invalid = state;
        invalid.updated_at = invalid.created_at - chrono::Duration::seconds(1);
        cases.push((invalid, "updated_at"));

        for (invalid, expected) in cases {
            let error = match invalid.validate() {
                Ok(()) => panic!("inconsistent agent state should be rejected"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(expected),
                "expected {expected}, got {error}"
            );
        }
    }

    #[test]
    fn file_state_store_rejects_inconsistent_keys_on_load_and_save() -> Result<(), AgentError> {
        let now = Utc::now();
        let mut state = AgentNodeState::generate(now);
        state.identity_public_key_b64 = AgentNodeState::generate(now).identity_public_key_b64;
        let dir = temp_state_dir("state-inconsistent-keys");
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let load_path = dir.join("load.json");
        std::fs::write(&load_path, serde_json::to_vec_pretty(&state)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&load_path, std::fs::Permissions::from_mode(0o600))?;
        }

        let load_error = match FileAgentStateStore::new(&load_path).load() {
            Ok(_) => panic!("inconsistent state file should be rejected"),
            Err(error) => error,
        };
        assert!(load_error
            .to_string()
            .contains("identity public key does not match identity private key"));

        let save_path = dir.join("save.json");
        let save_error = match FileAgentStateStore::new(&save_path).save(&state) {
            Ok(()) => panic!("inconsistent state should not be saved"),
            Err(error) => error,
        };
        assert!(save_error
            .to_string()
            .contains("identity public key does not match identity private key"));
        assert!(!save_path.exists());

        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn file_state_store_persists_registered_vpn_ip() -> Result<(), AgentError> {
        let dir = temp_state_dir("state-vpn-ip");
        let path = dir.join("state.json");
        let store = FileAgentStateStore::new(&path);
        let mut state = store.load_or_create(Utc::now())?;
        assert_eq!(state.vpn_ip, None);

        state.vpn_ip = Some(VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))));
        store.save(&state)?;

        assert_eq!(
            store.load()?.vpn_ip,
            Some(VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))))
        );
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn runtime_replaces_signed_seeds_with_authoritative_active_directory() -> Result<(), AgentError>
    {
        let mut state = AgentNodeState::generate(Utc::now());
        state.bootstrap_endpoints = vec![
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "https://seed.example:8443/".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Signal,
                url: "https://seed.example:9443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Stun,
                url: "udp://retired-stun.example:3478".to_string(),
            },
        ];
        state.seed_bootstrap_endpoints = Some(state.bootstrap_endpoints.clone());
        let runtime = AgentRuntime::new(state, ClusterPolicy::default());
        let updated_at = Utc::now() + ChronoDuration::seconds(1);
        let active = vec![
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "https://active.example:8443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Signal,
                url: "https://active.example:9443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Stun,
                url: "udp://active-stun.example:3478".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::WebUi,
                url: "https://active.example".to_string(),
            },
        ];

        let replaced = runtime
            .merge_active_bootstrap_endpoints(&active, updated_at)?
            .ok_or_else(|| {
                AgentError::InvalidState(
                    "active directory did not replace signed seeds".to_string(),
                )
            })?;
        assert_eq!(replaced.bootstrap_endpoints, active);
        assert_eq!(replaced.seed_bootstrap_endpoints, None);
        assert_eq!(replaced.updated_at, updated_at);
        replaced.validate()?;
        assert!(runtime
            .merge_active_bootstrap_endpoints(&active, updated_at)?
            .is_none());

        let replacement = vec![
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "https://replacement.example:8443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Signal,
                url: "https://replacement.example:9443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Stun,
                url: "udp://replacement.example:3478".to_string(),
            },
        ];
        let replaced = runtime
            .merge_active_bootstrap_endpoints(
                &replacement,
                updated_at + ChronoDuration::seconds(1),
            )?
            .ok_or_else(|| {
                AgentError::InvalidState("replacement directory was not applied".to_string())
            })?;
        assert_eq!(replaced.bootstrap_endpoints, replacement);
        assert!(replaced
            .bootstrap_endpoints
            .iter()
            .all(|endpoint| endpoint.kind != BootstrapEndpointKind::WebUi));

        let retired_seeds = vec![BootstrapEndpoint {
            kind: BootstrapEndpointKind::Stun,
            url: "udp://retired-stun.example:3478".to_string(),
        }];
        assert!(runtime
            .replace_seed_bootstrap_endpoints(
                &retired_seeds,
                updated_at + ChronoDuration::seconds(2),
            )?
            .is_none());
        assert_eq!(runtime.state().bootstrap_endpoints, replacement);
        Ok(())
    }

    #[test]
    fn runtime_rejects_partial_active_service_directory() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let partial = vec![BootstrapEndpoint {
            kind: BootstrapEndpointKind::ControlPlane,
            url: "https://partial.example:8443".to_string(),
        }];

        let error = match runtime.merge_active_bootstrap_endpoints(&partial, Utc::now()) {
            Ok(_) => panic!("partial active directory must be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("must include control_plane, signal, and stun"));
        assert!(runtime.state().seed_bootstrap_endpoints.is_some());
    }

    #[test]
    fn runtime_uses_and_refreshes_signed_seeds_before_active_directory() -> Result<(), AgentError> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let first = vec![
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "https://seed-a.example:8443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Stun,
                url: "udp://seed-a.example:3478".to_string(),
            },
        ];
        let first_state = runtime
            .replace_seed_bootstrap_endpoints(&first, Utc::now())?
            .ok_or_else(|| {
                AgentError::InvalidState("initial signed seeds were not applied".to_string())
            })?;
        assert_eq!(first_state.bootstrap_endpoints, first);

        let replacement = vec![
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "https://seed-b.example:8443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Stun,
                url: "udp://seed-b.example:3478".to_string(),
            },
        ];
        let replaced = runtime
            .replace_seed_bootstrap_endpoints(&replacement, Utc::now())?
            .ok_or_else(|| {
                AgentError::InvalidState("replacement signed seeds were not applied".to_string())
            })?;
        assert_eq!(replaced.bootstrap_endpoints, replacement);
        assert_eq!(
            replaced.seed_bootstrap_endpoints.as_deref(),
            Some(replacement.as_slice())
        );
        assert!(runtime
            .merge_active_bootstrap_endpoints(&[], Utc::now())?
            .is_none());
        assert_eq!(runtime.state().bootstrap_endpoints, replacement);
        Ok(())
    }

    #[test]
    fn control_plane_seeds_survive_active_directory_replacement() -> Result<(), AgentError> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let seeds = vec![
            "https://gateway.example/".to_string(),
            "https://gateway.example".to_string(),
        ];
        let seeded = runtime
            .replace_control_plane_seed_urls(&seeds, Utc::now())?
            .ok_or_else(|| {
                AgentError::InvalidState("control-plane seeds were not retained".to_string())
            })?;
        assert_eq!(
            seeded.control_plane_seed_urls,
            vec!["https://gateway.example".to_string()]
        );

        let active = vec![
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "http://10.250.0.4:19088".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Signal,
                url: "https://signal.example".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Stun,
                url: "udp://stun.example:3478".to_string(),
            },
        ];
        let active_state = runtime
            .merge_active_bootstrap_endpoints(&active, Utc::now())?
            .ok_or_else(|| {
                AgentError::InvalidState("active directory was not applied".to_string())
            })?;
        assert_eq!(
            active_state.control_plane_seed_urls,
            vec!["https://gateway.example".to_string()]
        );
        active_state.validate()?;
        Ok(())
    }

    #[test]
    fn registered_runtime_does_not_restore_seeds_over_active_directory() -> Result<(), AgentError> {
        let mut state = AgentNodeState::generate(Utc::now());
        let active = vec![BootstrapEndpoint {
            kind: BootstrapEndpointKind::ControlPlane,
            url: "https://active.example:8443".to_string(),
        }];
        state.bootstrap_endpoints = active.clone();
        state.seed_bootstrap_endpoints = Some(vec![BootstrapEndpoint {
            kind: BootstrapEndpointKind::Stun,
            url: "udp://retired-stun.example:3478".to_string(),
        }]);
        let mut node = peer_record(
            state.node_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
            &state.wireguard_public_key_b64,
            Vec::new(),
            Vec::new(),
        );
        node.identity_public_key = state.identity_public_key_b64.clone();
        state.vpn_ip = Some(node.vpn_ip);
        state.registered_node = Some(node);
        state.validate()?;

        let runtime = AgentRuntime::new(state, ClusterPolicy::default());
        let refreshed_seeds = vec![BootstrapEndpoint {
            kind: BootstrapEndpointKind::Stun,
            url: "udp://another-retired-stun.example:3478".to_string(),
        }];
        let updated = runtime
            .replace_seed_bootstrap_endpoints(&refreshed_seeds, Utc::now())?
            .ok_or_else(|| {
                AgentError::InvalidState("registered seed state was not retired".to_string())
            })?;

        assert_eq!(updated.bootstrap_endpoints, active);
        assert_eq!(updated.seed_bootstrap_endpoints, None);
        Ok(())
    }

    #[test]
    fn bootstrap_endpoint_selection_uses_seeds_only_without_an_active_directory(
    ) -> Result<(), AgentError> {
        let mut active = (0..MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND)
            .map(|index| BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: format!("https://active-{index}.example:8443"),
            })
            .collect::<Vec<_>>();
        active.extend([
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Signal,
                url: "https://active.example:9443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Stun,
                url: "udp://active.example:3478".to_string(),
            },
        ]);
        let seed = BootstrapEndpoint {
            kind: BootstrapEndpointKind::ControlPlane,
            url: "https://signed-seed.example:8443".to_string(),
        };
        let selected = merge_bootstrap_endpoint_sets(&active, std::slice::from_ref(&seed))?;
        assert_eq!(selected, active);
        assert!(!selected.contains(&seed));
        assert_eq!(
            merge_bootstrap_endpoint_sets(&[], std::slice::from_ref(&seed))?,
            vec![seed]
        );
        Ok(())
    }

    #[test]
    fn bootstrap_endpoint_selection_rejects_partial_active_directory() {
        let active = vec![BootstrapEndpoint {
            kind: BootstrapEndpointKind::ControlPlane,
            url: "https://partial.example:8443".to_string(),
        }];
        let seeds = vec![
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "https://seed.example:8443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Signal,
                url: "https://seed.example:9443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Stun,
                url: "udp://seed.example:3478".to_string(),
            },
        ];

        let error = match merge_bootstrap_endpoint_sets(&active, &seeds) {
            Ok(_) => panic!("partial active directory must be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("must include control_plane, signal, and stun"));
    }

    #[test]
    fn agent_node_state_validates_active_and_seed_directories_independently(
    ) -> Result<(), AgentError> {
        let mut state = AgentNodeState::generate(Utc::now());
        state.bootstrap_endpoints = vec![BootstrapEndpoint {
            kind: BootstrapEndpointKind::ControlPlane,
            url: "https://active.example:8443".to_string(),
        }];
        state.seed_bootstrap_endpoints = Some(vec![BootstrapEndpoint {
            kind: BootstrapEndpointKind::Stun,
            url: "udp://retired-stun.example:3478".to_string(),
        }]);

        state.validate()
    }

    #[test]
    fn agent_node_state_requires_complete_authoritative_directory() -> Result<(), AgentError> {
        let mut state = AgentNodeState::generate(Utc::now());
        state.seed_bootstrap_endpoints = None;
        state.validate()?;

        state.bootstrap_endpoints = vec![BootstrapEndpoint {
            kind: BootstrapEndpointKind::ControlPlane,
            url: "https://partial.example:8443".to_string(),
        }];
        let error = match state.validate() {
            Ok(()) => panic!("partial authoritative directory must be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("must include control_plane, signal, and stun"));

        state.bootstrap_endpoints.extend([
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Signal,
                url: "https://active.example:9443".to_string(),
            },
            BootstrapEndpoint {
                kind: BootstrapEndpointKind::Stun,
                url: "udp://active.example:3478".to_string(),
            },
        ]);
        state.validate()
    }

    #[test]
    fn file_state_store_persists_registration_and_bootstrap_state() -> Result<(), AgentError> {
        let dir = temp_state_dir("state-registration");
        let path = dir.join("state.json");
        let store = FileAgentStateStore::new(&path);
        let mut state = store.load_or_create(Utc::now())?;
        let mut node = peer_record(
            state.node_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
            &state.wireguard_public_key_b64,
            Vec::new(),
            Vec::new(),
        );
        node.identity_public_key = state.identity_public_key_b64.clone();
        state.vpn_ip = Some(node.vpn_ip);
        state.registered_node = Some(node.clone());
        state.bootstrap_endpoints = vec![
            BootstrapEndpoint {
                url: "https://203.0.113.10:8443/".to_string(),
                kind: BootstrapEndpointKind::ControlPlane,
            },
            BootstrapEndpoint {
                url: "https://203.0.113.11:9443".to_string(),
                kind: BootstrapEndpointKind::Signal,
            },
        ];

        store.save(&state)?;
        let loaded = store.load()?;

        assert_eq!(loaded.registered_node, Some(node));
        assert_eq!(loaded.bootstrap_endpoints, state.bootstrap_endpoints);
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn agent_node_state_rejects_inconsistent_registration_state() {
        fn validation_error(state: &AgentNodeState, context: &str) -> AgentError {
            match state.validate() {
                Ok(()) => panic!("{context}"),
                Err(error) => error,
            }
        }

        let mut state = AgentNodeState::generate(Utc::now());
        let mut node = peer_record(
            state.node_id.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
            &state.wireguard_public_key_b64,
            Vec::new(),
            Vec::new(),
        );
        node.identity_public_key = state.identity_public_key_b64.clone();
        state.vpn_ip = Some(node.vpn_ip);
        state.registered_node = Some(node.clone());
        assert!(state.validate().is_ok());

        let mut invalid = state.clone();
        let Some(node) = invalid.registered_node.as_mut() else {
            panic!("registration state should contain a node");
        };
        node.node_id = NodeId::from_string("other-node");
        let error = validation_error(&invalid, "registered node ID must match state");
        assert!(error.to_string().contains("registered node ID"));

        let mut invalid = state.clone();
        let Some(node) = invalid.registered_node.as_mut() else {
            panic!("registration state should contain a node");
        };
        node.identity_public_key = "different-identity".to_string();
        let error = validation_error(&invalid, "registered identity key must match state");
        assert!(error
            .to_string()
            .contains("registered node identity public key"));

        let mut invalid = state.clone();
        invalid.vpn_ip = Some(VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 3))));
        let error = validation_error(&invalid, "registered VPN IP must match state");
        assert!(error.to_string().contains("registered node VPN IP"));

        let mut invalid = state;
        invalid.bootstrap_endpoints = vec![BootstrapEndpoint {
            url: "udp://203.0.113.10:8443".to_string(),
            kind: BootstrapEndpointKind::ControlPlane,
        }];
        let error = validation_error(&invalid, "persisted bootstrap kind must be validated");
        assert!(error.to_string().contains("persisted bootstrap endpoints"));
    }

    #[test]
    fn file_state_store_rejects_oversized_state_file() -> Result<(), AgentError> {
        let dir = temp_state_dir("state-oversized");
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let path = dir.join("state.json");
        std::fs::write(&path, vec![b'{'; MAX_AGENT_STATE_FILE_BYTES as usize + 1])?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        let error = match FileAgentStateStore::new(&path).load() {
            Ok(_) => panic!("oversized state file should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds maximum size"));
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
        assert_eq!(runtime.status().await.candidate_count, 2);
        Ok(())
    }

    #[test]
    fn runtime_promotes_only_global_no_nat_observations_to_public_candidates() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let observed_at = Utc::now();
        let public_addr = SocketAddr::from(([8, 8, 8, 8], 51_820));
        let public_candidate = runtime.stun_candidate_from_observation(&NatProbeObservation {
            local_addr: public_addr,
            stun_server: SocketAddr::from(([1, 1, 1, 1], 3478)),
            reflexive_addr: public_addr,
            observed_at,
        });
        assert_eq!(public_candidate.kind, EndpointCandidateKind::PublicUdp);

        let tailscale_addr = SocketAddr::from(([100, 100, 20, 30], 51_820));
        let private_candidate = runtime.stun_candidate_from_observation(&NatProbeObservation {
            local_addr: tailscale_addr,
            stun_server: SocketAddr::from(([100, 100, 20, 40], 3478)),
            reflexive_addr: tailscale_addr,
            observed_at,
        });
        assert_eq!(private_candidate.kind, EndpointCandidateKind::StunReflexive);
    }

    #[tokio::test]
    async fn runtime_rebuilds_fixed_port_candidates_without_guessing_nat_mapping() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let assessed_at = Utc::now();
        let public_probe_addr = SocketAddr::from(([8, 8, 8, 8], 40_000));
        let public_classification = NatClassification::from_observations(
            public_probe_addr,
            vec![NatProbeObservation {
                local_addr: public_probe_addr,
                stun_server: SocketAddr::from(([1, 1, 1, 1], 3478)),
                reflexive_addr: public_probe_addr,
                observed_at: assessed_at,
            }],
            assessed_at,
        );

        assert!(
            runtime
                .refresh_candidates_for_wireguard_listen_port(&public_classification, 51_820,)
                .await
        );
        let public_candidates = runtime.status().await.candidates;
        assert_eq!(public_candidates.len(), 2);
        assert_eq!(public_candidates[0].kind, EndpointCandidateKind::PublicUdp);
        assert_eq!(
            public_candidates[0].addr,
            SocketAddr::from(([8, 8, 8, 8], 51_820))
        );

        let private_probe_addr = SocketAddr::from(([100, 100, 20, 30], 40_000));
        let private_classification = NatClassification::from_observations(
            private_probe_addr,
            vec![NatProbeObservation {
                local_addr: private_probe_addr,
                stun_server: SocketAddr::from(([100, 100, 20, 40], 3478)),
                reflexive_addr: private_probe_addr,
                observed_at: assessed_at,
            }],
            assessed_at,
        );
        let private_runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        assert!(
            !private_runtime
                .refresh_candidates_for_wireguard_listen_port(&private_classification, 51_820,)
                .await
        );
        let private_candidates = private_runtime.status().await.candidates;
        assert_eq!(private_candidates.len(), 1);
        assert_eq!(private_candidates[0].kind, EndpointCandidateKind::LocalUdp);
        assert_eq!(
            private_candidates[0].addr,
            SocketAddr::from(([100, 100, 20, 30], 51_820))
        );
    }

    #[tokio::test]
    async fn runtime_rebuilds_declared_mapped_public_candidate() -> Result<(), AgentError> {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let assessed_at = Utc::now();
        let local_addr = SocketAddr::from(([10, 10, 10, 103], 40_000));
        let mapped_ip = IpAddr::from([8, 8, 4, 4]);
        let observations = vec![
            NatProbeObservation {
                local_addr,
                stun_server: SocketAddr::from(([1, 1, 1, 1], 3478)),
                reflexive_addr: SocketAddr::new(mapped_ip, 40_000),
                observed_at: assessed_at,
            },
            NatProbeObservation {
                local_addr,
                stun_server: SocketAddr::from(([8, 8, 8, 8], 3478)),
                reflexive_addr: SocketAddr::new(mapped_ip, 40_000),
                observed_at: assessed_at,
            },
        ];
        let classification =
            NatClassification::from_observations(local_addr, observations, assessed_at);
        *runtime.nat_classification.write().await = Some(classification);
        let classification = runtime.declare_mapped_public_ip(mapped_ip).await?;

        assert!(
            runtime
                .refresh_candidates_for_wireguard_listen_port(&classification, 51_820)
                .await
        );
        let candidates = runtime.status().await.candidates;
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].kind, EndpointCandidateKind::PublicUdp);
        assert_eq!(candidates[0].addr, SocketAddr::new(mapped_ip, 51_820));
        assert_eq!(candidates[1].kind, EndpointCandidateKind::LocalUdp);
        assert_eq!(
            candidates[1].addr,
            SocketAddr::from(([10, 10, 10, 103], 51_820))
        );
        Ok(())
    }

    #[tokio::test]
    async fn runtime_retains_matching_wireguard_nat_mapping_and_replaces_overlay_candidates() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let node_id = runtime.state().node_id;
        let old_observed_at = Utc::now() - ChronoDuration::minutes(1);
        let reflexive = EndpointCandidate {
            node_id: node_id.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr: SocketAddr::from(([111, 216, 122, 15], 34_037)),
            observed_at: old_observed_at,
            priority: 80,
            cost: 20,
            source: CandidateSource::StunProbe,
        };
        runtime
            .replace_candidates(vec![
                reflexive.clone(),
                EndpointCandidate {
                    node_id: node_id.clone(),
                    kind: EndpointCandidateKind::StunReflexive,
                    addr: SocketAddr::from(([100, 89, 33, 61], 51_820)),
                    observed_at: old_observed_at,
                    priority: 80,
                    cost: 20,
                    source: CandidateSource::StunProbe,
                },
                EndpointCandidate {
                    node_id,
                    kind: EndpointCandidateKind::LocalUdp,
                    addr: SocketAddr::from(([100, 89, 33, 61], 51_820)),
                    observed_at: old_observed_at,
                    priority: 70,
                    cost: 30,
                    source: CandidateSource::StunProbe,
                },
            ])
            .await;

        let assessed_at = Utc::now();
        let local_probe = SocketAddr::from(([192, 168, 1, 18], 57_405));
        let classification = NatClassification::from_observations(
            local_probe,
            vec![NatProbeObservation {
                local_addr: local_probe,
                stun_server: SocketAddr::from(([1, 1, 1, 1], 3478)),
                reflexive_addr: SocketAddr::from(([111, 216, 122, 15], 57_405)),
                observed_at: assessed_at,
            }],
            assessed_at,
        );

        assert!(
            !runtime
                .refresh_candidates_for_wireguard_listen_port(&classification, 51_820)
                .await
        );
        let candidates = runtime.status().await.candidates;
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].kind, EndpointCandidateKind::StunReflexive);
        assert_eq!(candidates[0].addr, reflexive.addr);
        assert_eq!(candidates[0].observed_at, assessed_at);
        assert_eq!(candidates[1].kind, EndpointCandidateKind::LocalUdp);
        assert_eq!(
            candidates[1].addr,
            SocketAddr::from(([192, 168, 1, 18], 51_820))
        );
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
    async fn runtime_restores_registered_endpoint_candidates_after_restart() {
        let mut state = AgentNodeState::generate(Utc::now());
        let observed_at = Utc::now() - ChronoDuration::seconds(300);
        let candidate = EndpointCandidate {
            node_id: state.node_id.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr: SocketAddr::from(([198, 51, 100, 10], 51_820)),
            observed_at,
            priority: 80,
            cost: 20,
            source: CandidateSource::StunProbe,
        };
        let mut node = peer_record(
            state.node_id.clone(),
            IpAddr::V4(Ipv4Addr::new(10, 250, 0, 1)),
            &state.wireguard_public_key_b64,
            vec![candidate.clone()],
            Vec::new(),
        );
        node.identity_public_key = state.identity_public_key_b64.clone();
        state.vpn_ip = Some(node.vpn_ip);
        state.registered_node = Some(node);

        let runtime = AgentRuntime::new(state, ClusterPolicy::default());

        let status = runtime.status().await;
        assert_eq!(status.candidate_count, 1);
        assert_eq!(status.candidates, vec![candidate]);
    }

    #[tokio::test]
    async fn runtime_refreshes_stun_candidate_observation_leases() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let node_id = runtime.state().node_id.clone();
        let old_observed_at = Utc::now() - ChronoDuration::seconds(300);
        let refreshed_at = Utc::now();
        let stun_candidate = EndpointCandidate {
            node_id: node_id.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr: SocketAddr::from(([198, 51, 100, 10], 40000)),
            observed_at: old_observed_at,
            priority: 80,
            cost: 20,
            source: CandidateSource::StunProbe,
        };
        let interface_candidate = EndpointCandidate {
            node_id,
            kind: EndpointCandidateKind::LocalUdp,
            addr: SocketAddr::from(([10, 0, 0, 10], 51820)),
            observed_at: old_observed_at,
            priority: 70,
            cost: 30,
            source: CandidateSource::InterfaceScan,
        };
        runtime
            .replace_candidates(vec![stun_candidate, interface_candidate.clone()])
            .await;

        runtime.refresh_candidate_observations(refreshed_at).await;

        let candidates = runtime.status().await.candidates;
        assert_eq!(candidates[0].observed_at, refreshed_at);
        assert_eq!(candidates[1], interface_candidate);
    }

    #[tokio::test]
    async fn runtime_replaces_and_deduplicates_stun_candidates() {
        let runtime = AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        );
        let node_id = runtime.state().node_id;
        let observed_at = Utc::now();
        let interface_candidate = EndpointCandidate {
            node_id: node_id.clone(),
            kind: EndpointCandidateKind::LocalUdp,
            addr: SocketAddr::from(([10, 0, 0, 10], 51_820)),
            observed_at,
            priority: 100,
            cost: 1,
            source: CandidateSource::InterfaceScan,
        };
        let stale_stun_candidate = EndpointCandidate {
            node_id: node_id.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr: SocketAddr::from(([198, 51, 100, 10], 40_000)),
            observed_at,
            priority: 80,
            cost: 20,
            source: CandidateSource::StunProbe,
        };
        runtime
            .replace_candidates(vec![interface_candidate.clone(), stale_stun_candidate])
            .await;

        let duplicate_addr = SocketAddr::from(([198, 51, 100, 20], 40_001));
        let older_duplicate = EndpointCandidate {
            node_id: node_id.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr: duplicate_addr,
            observed_at: observed_at + ChronoDuration::seconds(1),
            priority: 70,
            cost: 30,
            source: CandidateSource::StunProbe,
        };
        let latest_duplicate = EndpointCandidate {
            observed_at: observed_at + ChronoDuration::seconds(2),
            priority: 90,
            cost: 10,
            ..older_duplicate.clone()
        };
        let second_stun_candidate = EndpointCandidate {
            node_id,
            kind: EndpointCandidateKind::StunReflexive,
            addr: SocketAddr::from(([198, 51, 100, 30], 40_002)),
            observed_at: observed_at + ChronoDuration::seconds(2),
            priority: 80,
            cost: 20,
            source: CandidateSource::StunProbe,
        };

        runtime
            .replace_stun_candidates(vec![
                older_duplicate,
                latest_duplicate.clone(),
                second_stun_candidate.clone(),
            ])
            .await;

        let status = runtime.status().await;
        assert_eq!(status.candidate_count, 3);
        assert_eq!(
            status.candidates,
            vec![interface_candidate, latest_duplicate, second_stun_candidate,]
        );
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
