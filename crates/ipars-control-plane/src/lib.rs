pub mod bounded_topology;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bounded_topology::{
    BoundedTopology, BoundedTopologyConfig, BoundedTopologyError, TopologyEdge,
    TopologyEdgeKind as BoundedTopologyEdgeKind, SUPPORTED_MAX_DEGREES, TOPOLOGY_ALGORITHM_VERSION,
};
use chrono::Utc;
use ipars_crypto::{
    node_id_from_public_key_b64, validate_node_api_request_nonce,
    validate_wireguard_public_key_b64, verify_client_control_request_signature,
    verify_client_registration_bundle_signature, verify_control_plane_node_query_signature,
    verify_heartbeat_request_signature, verify_join_token, verify_overlay_path_query_signature,
    verify_remove_node_signature, verify_signal_node_upsert_signature,
    verify_sponsored_client_registration_signature, verify_token_revocation_signature,
    verify_wireguard_key_rotation_signature, CryptoError,
};
use ipars_types::api::{
    ClientControlRequest, ClientGatewaySelection, ClientRequestKind, ControlPlaneMetricsResponse,
    ControlPlaneNatDiscoveryOverview, ControlPlaneNodeQueryKind, ControlPlaneNodeQueryRequest,
    ControlPlanePathsResponse, ControlPlaneTopologyEdge, ControlPlaneTopologyEdgeKind,
    ControlPlaneTopologyEdgePlacement, ControlPlaneTopologyEdgeStatus, ControlPlaneTopologyGroup,
    ControlPlaneTopologyNode, ControlPlaneTopologyRepresentative,
    ControlPlaneTopologyRepresentativeAssignment, ControlPlaneTopologyResponse, HeartbeatRequest,
    HeartbeatResponse, NatTraversalStrategyCount, PathStateCount, PeerConnectionIntent, PeerMap,
    RegisterClientRequest, RegisterClientResponse, RegisterNodeRequest, RegisterNodeResponse,
    RelayMap, RemoveClientResponse, RemoveNodeRequest, RemoveNodeResponse, RevokeTokenRequest,
    RotateWireGuardKeyRequest, RotateWireGuardKeyResponse, SignalNodeUpsertRequest,
    SponsoredClientRegistrationRequest, CLIENT_REGISTRATION_SCHEMA_VERSION,
    MAX_CLIENT_REGISTRATION_VALIDITY_SECONDS,
};
use ipars_types::{
    bootstrap_endpoints_include_core_services, canonical_bootstrap_endpoint_url,
    endpoint_addr_is_usable, literal_http_bootstrap_socket_addr, literal_udp_bootstrap_socket_addr,
    node_hostname_is_valid, relay_admission_url_is_usable, socket_addr_is_globally_routable,
    validate_join_token_bootstrap_endpoints, AclAction, AclRule, AggregateOverlayRoute,
    BootstrapEndpoint, BootstrapEndpointKind, ClusterId, ClusterPolicy, EndpointCandidate,
    EndpointCandidateKind, HealthState, JoinTokenClaims, KeyId, NatClassification,
    NatTraversalStrategy, NeighborMap, NodeHealth, NodeId, NodeRecord, OverlayNeighbor,
    OverlayNeighborKind, OverlayPath, OverlayPathQuery, PathRecord, PathState, RelayCapability,
    Role, Route, ServiceDirectory, ServiceInstance, SignedJoinToken, TokenLedgerMetrics,
    TokenLedgerRecord, TokenPolicy, TokenRevocationOutcome, TokenRevocationRecord, TokenStatus,
    TransportProtocol, VpnIp, JOIN_TOKEN_NOT_BEFORE_SKEW_SECONDS,
    LAZY_CONNECT_LOCAL_ACTIVITY_REASON_PREFIX, MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS,
    MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND, MAX_JOIN_TOKEN_TTL_SECONDS,
    MAX_OVERLAY_BLOCK_SIZE, MAX_OVERLAY_DEGREE, MAX_OVERLAY_NODE_ROUTES, MAX_OVERLAY_ROUTE_SCOPES,
    MAX_PATH_SCORE_REASONS, MIN_OVERLAY_BLOCK_SIZE,
};
use ipnet::IpNet;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{Mutex, Notify, OnceCell, RwLock};

const CONNECTION_INTENT_WAIT_FALLBACK_POLL_INTERVAL: Duration = Duration::from_secs(1);

const PATH_STATE_METRIC_ORDER: [PathState; 5] = [
    PathState::DirectPublic,
    PathState::DirectIpv6,
    PathState::DirectNatTraversal,
    PathState::Relay,
    PathState::Unreachable,
];
const MAX_PATH_SCORE_REASON_BYTES: usize = 256;
const MAX_PATH_SCORE_TOTAL_REASON_BYTES: usize = 2048;
const MAX_HEARTBEAT_PATH_STATES: usize = 4_096;
const MAX_ACCEPTED_NODE_QUERY_NONCES: usize = 131_072;
const MAX_ACTIVE_SERVICE_INSTANCES: usize = 64;
const MAX_SERVICE_LEASE_SECONDS: i64 = 300;
const HEARTBEAT_SERVICE_LEASE_SECONDS: i64 = 45;
const DEFAULT_SERVICE_HA_REPLICA_COUNT: usize = 2;
const REQUIRED_HA_SERVICE_KINDS: [BootstrapEndpointKind; 5] = [
    BootstrapEndpointKind::ControlPlane,
    BootstrapEndpointKind::Signal,
    BootstrapEndpointKind::Stun,
    BootstrapEndpointKind::Relay,
    BootstrapEndpointKind::WebUi,
];
const MAX_CLIENT_GATEWAYS: usize = 4;
const CLIENT_GATEWAY_SELECTION_ANNOUNCE_WINDOW: Duration = Duration::from_secs(60);
const OVERLAY_NODE_SNAPSHOT_CACHE_TTL: Duration = Duration::from_secs(1);
const MAX_OVERLAY_TOPOLOGY_CACHE_ENTRIES: usize = 4;
const MAX_ROUTE_CATALOG_UPDATE_RETRIES: usize = 8;
const KEYCLOAK_CANDIDATE_PAGE_SIZE: usize = 64;
pub const MAX_NODE_ENROLLMENT_TOKEN_USES: u32 = 1_000;
pub const NODE_ENROLLMENT_ALLOWED_ROLES: [&str; 3] = ["edge", "worker", "gateway"];

pub fn node_enrollment_role_is_allowed(role: &Role) -> bool {
    NODE_ENROLLMENT_ALLOWED_ROLES.contains(&role.as_str())
}

pub fn enrollment_role_is_allowed(role: &Role) -> bool {
    node_enrollment_role_is_allowed(role) || role.is_client()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeycloakCandidateLease {
    pub cluster_id: ClusterId,
    pub node_id: NodeId,
    pub vpn_ip: VpnIp,
    pub version: String,
    pub ready: bool,
    #[serde(default = "default_keycloak_candidate_eligible")]
    pub eligible: bool,
    #[serde(default)]
    pub generation: i64,
    pub lease_expires_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

fn default_keycloak_candidate_eligible() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeycloakPlacement {
    pub placement_id: String,
    pub replicas: Vec<KeycloakCandidateLease>,
}

fn client_claims_are_control_only(claims: &JoinTokenClaims) -> bool {
    claims.role.is_client()
        && claims.tags.is_empty()
        && claims.policy.allowed_tags.is_empty()
        && !claims.policy.allow_relay
        && claims.policy.allowed_routes.is_empty()
        && claims.policy.max_token_uses == Some(1)
}

#[derive(Debug, Error)]
pub enum ControlPlaneError {
    #[error("join token does not allow node registration")]
    JoinDenied,
    #[error("node {0} already exists")]
    NodeAlreadyExists(NodeId),
    #[error("VPN IP {0} is already allocated")]
    VpnIpAlreadyAllocated(VpnIp),
    #[error("node {0} request signature is required")]
    NodeSignatureRequired(NodeId),
    #[error("node {node_id} request signature rejected: {reason}")]
    NodeSignatureRejected { node_id: NodeId, reason: String },
    #[error("node {0} request nonce was already accepted")]
    NodeRequestReplay(NodeId),
    #[error("control-plane node request replay cache is full")]
    NodeRequestAuthenticationCapacity,
    #[error("node {node_id} heartbeat update rejected: {reason}")]
    NodeUpdateRejected { node_id: NodeId, reason: String },
    #[error("node {node_id} registration rejected: {reason}")]
    NodeRegistrationRejected { node_id: NodeId, reason: String },
    #[error("node not found: {0}")]
    NodeNotFound(NodeId),
    #[error("path not found: {local} -> {remote}")]
    PathNotFound { local: NodeId, remote: NodeId },
    #[error("overlay destination not found or denied: {0}")]
    OverlayDestinationNotFound(IpAddr),
    #[error("overlay path is unavailable: {source_node} -> {destination_node}")]
    OverlayPathUnavailable {
        source_node: NodeId,
        destination_node: NodeId,
    },
    #[error("bounded overlay topology failed: {0}")]
    BoundedTopology(String),
    #[error("cluster policy rejected: {0}")]
    InvalidClusterPolicy(String),
    #[error("cluster policy changed while validating a route update")]
    ClusterPolicyChanged,
    #[error("overlay route catalog changed while validating a route update")]
    OverlayRouteCatalogChanged,
    #[error("node {0} changed while applying a registration update")]
    NodeStateChanged(NodeId),
    #[error("Keycloak candidate {node_id} generation {generation} is stale")]
    KeycloakCandidateGenerationConflict { node_id: NodeId, generation: i64 },
    #[error("no available VPN IP in pool")]
    VpnPoolExhausted,
    #[error("route {0} is not permitted by token policy")]
    RouteDenied(String),
    #[error("relay capability is not permitted by token policy")]
    RelayDenied,
    #[error("token {nonce} rejected with status {status}")]
    TokenRejected { nonce: String, status: TokenStatus },
    #[error("token not found: {0}")]
    TokenNotFound(String),
    #[error("issuer key not found for issuer {issuer} key {key_id}")]
    IssuerKeyNotFound { issuer: NodeId, key_id: KeyId },
    #[error("token verification failed: {0}")]
    TokenVerification(String),
    #[error("store error: {0}")]
    Store(String),
}

impl From<CryptoError> for ControlPlaneError {
    fn from(error: CryptoError) -> Self {
        Self::TokenVerification(error.to_string())
    }
}

impl From<BoundedTopologyError> for ControlPlaneError {
    fn from(error: BoundedTopologyError) -> Self {
        Self::BoundedTopology(error.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    pub cluster_id: ClusterId,
    pub vpn_pool: Ipv4Net,
    pub cluster_policy: ClusterPolicy,
    pub require_heartbeat_signature: bool,
    pub heartbeat_signature_max_age: Duration,
    pub service_ha_replica_count: usize,
}

impl ControlPlaneConfig {
    pub fn new(cluster_id: ClusterId, vpn_pool: Ipv4Net) -> Self {
        Self {
            cluster_id,
            vpn_pool,
            cluster_policy: ClusterPolicy::default(),
            require_heartbeat_signature: true,
            heartbeat_signature_max_age: Duration::from_secs(300),
            service_ha_replica_count: DEFAULT_SERVICE_HA_REPLICA_COUNT,
        }
    }
}

#[async_trait]
pub trait ControlPlaneStore: Send + Sync {
    async fn get_cluster_policy(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<Option<ClusterPolicy>, ControlPlaneError>;
    async fn initialize_cluster_policy_if_absent(
        &self,
        cluster_id: &ClusterId,
        policy: ClusterPolicy,
    ) -> Result<ClusterPolicy, ControlPlaneError>;
    async fn get_overlay_routing_epoch(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<u64, ControlPlaneError>;
    async fn upsert_cluster_policy(
        &self,
        cluster_id: &ClusterId,
        policy: ClusterPolicy,
    ) -> Result<(), ControlPlaneError>;
    async fn upsert_cluster_policy_if_route_catalog_epoch(
        &self,
        cluster_id: &ClusterId,
        policy: ClusterPolicy,
        expected_route_catalog_epoch: u64,
    ) -> Result<bool, ControlPlaneError>;
    async fn insert_node(&self, node: NodeRecord) -> Result<(), ControlPlaneError>;
    async fn insert_node_if_cluster_policy(
        &self,
        node: NodeRecord,
        expected_cluster_policy: Option<ClusterPolicy>,
        expected_route_catalog_epoch: Option<u64>,
    ) -> Result<(), ControlPlaneError>;
    async fn get_node(&self, node_id: &NodeId) -> Result<Option<NodeRecord>, ControlPlaneError>;
    async fn get_nodes_by_ids(
        &self,
        node_ids: &BTreeSet<NodeId>,
    ) -> Result<Vec<NodeRecord>, ControlPlaneError> {
        let mut nodes = Vec::with_capacity(node_ids.len());
        for node_id in node_ids {
            if let Some(node) = self.get_node(node_id).await? {
                nodes.push(node);
            }
        }
        Ok(nodes)
    }
    async fn list_nodes(&self) -> Result<Vec<NodeRecord>, ControlPlaneError>;
    async fn remove_node(&self, node_id: &NodeId) -> Result<RemovedNode, ControlPlaneError>;
    async fn update_node_candidates(
        &self,
        node_id: &NodeId,
        candidates: Vec<EndpointCandidate>,
    ) -> Result<(), ControlPlaneError>;
    async fn update_node_relay_capability(
        &self,
        node_id: &NodeId,
        relay_capability: Option<RelayCapability>,
    ) -> Result<(), ControlPlaneError>;
    async fn update_node_routes(
        &self,
        node_id: &NodeId,
        routes: Vec<Route>,
    ) -> Result<(), ControlPlaneError>;
    async fn update_node_routes_if_cluster_policy(
        &self,
        cluster_id: &ClusterId,
        node_id: &NodeId,
        routes: Vec<Route>,
        expected_cluster_policy: Option<ClusterPolicy>,
        expected_route_catalog_epoch: Option<u64>,
    ) -> Result<(), ControlPlaneError>;
    async fn rejoin_node_if_cluster_policy(
        &self,
        update: RejoinNodeStoreUpdate,
    ) -> Result<NodeRecord, ControlPlaneError>;
    async fn rotate_node_wireguard_public_key(
        &self,
        node_id: &NodeId,
        expected_current_public_key: &str,
        next_public_key: String,
    ) -> Result<NodeRecord, ControlPlaneError>;
    async fn upsert_health(
        &self,
        node_id: NodeId,
        health: NodeHealth,
    ) -> Result<(), ControlPlaneError>;
    async fn get_health(&self, node_id: &NodeId) -> Result<Option<NodeHealth>, ControlPlaneError>;
    async fn get_health_by_node_ids(
        &self,
        node_ids: &BTreeSet<NodeId>,
    ) -> Result<BTreeMap<NodeId, NodeHealth>, ControlPlaneError> {
        let mut health_by_node = BTreeMap::new();
        for node_id in node_ids {
            if let Some(health) = self.get_health(node_id).await? {
                health_by_node.insert(node_id.clone(), health);
            }
        }
        Ok(health_by_node)
    }
    async fn get_heartbeat_signature_timestamp(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<chrono::DateTime<Utc>>, ControlPlaneError>;
    async fn list_health(&self) -> Result<BTreeMap<NodeId, NodeHealth>, ControlPlaneError> {
        let mut health_by_node = BTreeMap::new();
        for node in self.list_nodes().await? {
            if let Some(health) = self.get_health(&node.node_id).await? {
                health_by_node.insert(node.node_id, health);
            }
        }
        Ok(health_by_node)
    }
    async fn list_nodes_and_health(
        &self,
    ) -> Result<(Vec<NodeRecord>, BTreeMap<NodeId, NodeHealth>), ControlPlaneError> {
        tokio::try_join!(self.list_nodes(), self.list_health())
    }
    async fn upsert_nat_classification(
        &self,
        node_id: NodeId,
        classification: NatClassification,
    ) -> Result<(), ControlPlaneError>;
    async fn get_nat_classification(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<NatClassification>, ControlPlaneError>;
    async fn list_nat_classifications(
        &self,
    ) -> Result<BTreeMap<NodeId, NatClassification>, ControlPlaneError>;
    async fn apply_heartbeat(&self, update: HeartbeatStoreUpdate) -> Result<(), ControlPlaneError>;
    async fn upsert_path(&self, path: PathRecord) -> Result<(), ControlPlaneError>;
    async fn replace_node_paths(
        &self,
        node_id: &NodeId,
        paths: Vec<PathRecord>,
    ) -> Result<(), ControlPlaneError>;
    async fn list_paths_for(&self, node_id: &NodeId) -> Result<Vec<PathRecord>, ControlPlaneError>;
    async fn list_paths_for_pairs(
        &self,
        pairs: &BTreeSet<(NodeId, NodeId)>,
    ) -> Result<Vec<PathRecord>, ControlPlaneError> {
        if pairs.is_empty() {
            return Ok(Vec::new());
        }
        Ok(self
            .list_all_paths()
            .await?
            .into_iter()
            .filter(|path| pairs.contains(&(path.key.local.clone(), path.key.remote.clone())))
            .collect())
    }
    async fn list_all_paths(&self) -> Result<Vec<PathRecord>, ControlPlaneError> {
        let mut paths = Vec::new();
        for node in self.list_nodes().await? {
            for path in self.list_paths_for(&node.node_id).await? {
                if !paths
                    .iter()
                    .any(|current: &PathRecord| current.key == path.key)
                {
                    paths.push(path);
                }
            }
        }
        Ok(paths)
    }
    async fn upsert_service_instance(
        &self,
        instance: ServiceInstance,
    ) -> Result<(), ControlPlaneError>;
    async fn remove_service_instance(
        &self,
        cluster_id: &ClusterId,
        instance_id: &str,
    ) -> Result<bool, ControlPlaneError>;
    async fn list_service_instances(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<Vec<ServiceInstance>, ControlPlaneError>;
    async fn upsert_keycloak_candidate(
        &self,
        _candidate: KeycloakCandidateLease,
    ) -> Result<bool, ControlPlaneError> {
        Err(ControlPlaneError::Store(
            "keycloak candidate leases are unsupported by this store".to_string(),
        ))
    }
    async fn list_keycloak_candidates(
        &self,
        _cluster_id: &ClusterId,
        _lease_cutoff: chrono::DateTime<Utc>,
        _after_node_id: Option<&NodeId>,
        _limit: usize,
    ) -> Result<Vec<KeycloakCandidateLease>, ControlPlaneError> {
        Err(ControlPlaneError::Store(
            "keycloak candidate leases are unsupported by this store".to_string(),
        ))
    }
    async fn upsert_client_gateway_selection(
        &self,
        selection: ClientGatewaySelection,
    ) -> Result<(), ControlPlaneError>;
    async fn remove_client_gateway_selection(
        &self,
        client_id: &NodeId,
    ) -> Result<bool, ControlPlaneError>;
    async fn list_client_gateway_selections(
        &self,
    ) -> Result<BTreeMap<NodeId, ClientGatewaySelection>, ControlPlaneError>;
    async fn latest_client_gateway_selection_at(
        &self,
    ) -> Result<Option<chrono::DateTime<Utc>>, ControlPlaneError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedNode {
    pub node: NodeRecord,
    pub removed_path_count: usize,
    pub removed_health: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HeartbeatStoreUpdate {
    pub cluster_id: ClusterId,
    pub expected_cluster_policy: Option<ClusterPolicy>,
    pub expected_route_catalog_epoch: Option<u64>,
    pub node_id: NodeId,
    pub expected_identity_public_key: String,
    pub expected_registered_at: chrono::DateTime<Utc>,
    pub accepted_signature_at: Option<chrono::DateTime<Utc>>,
    pub hostname: Option<String>,
    pub candidates: Vec<EndpointCandidate>,
    pub nat_classification: Option<NatClassification>,
    pub relay_capability: Option<RelayCapability>,
    pub routes: Option<Vec<Route>>,
    pub health: NodeHealth,
    pub paths: Vec<PathRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejoinNodeStoreUpdate {
    pub cluster_id: ClusterId,
    pub expected_cluster_policy: Option<ClusterPolicy>,
    pub expected_route_catalog_epoch: Option<u64>,
    pub expected_node: NodeRecord,
    pub candidates: Vec<EndpointCandidate>,
    pub relay_capability: Option<RelayCapability>,
    pub routes: Vec<Route>,
}

impl HeartbeatStoreUpdate {
    pub fn ensure_matches_node_generation(
        &self,
        node: &NodeRecord,
    ) -> Result<(), ControlPlaneError> {
        if node.node_id != self.node_id || node.cluster_id != self.cluster_id {
            return Err(ControlPlaneError::NodeNotFound(self.node_id.clone()));
        }
        if node.identity_public_key != self.expected_identity_public_key
            || node.registered_at != self.expected_registered_at
        {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: self.node_id.clone(),
                reason: "node generation changed while heartbeat was being validated".to_string(),
            });
        }
        Ok(())
    }
}

#[async_trait]
pub trait TokenLedger: Send + Sync {
    async fn insert_token_if_absent(
        &self,
        record: TokenLedgerRecord,
    ) -> Result<TokenLedgerRecord, ControlPlaneError>;
    async fn get_token(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
    ) -> Result<Option<TokenLedgerRecord>, ControlPlaneError>;
    async fn admit_token(
        &self,
        record: TokenLedgerRecord,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError>;
    async fn revoke_token(
        &self,
        revocation: TokenRevocationRecord,
    ) -> Result<TokenRevocationOutcome, ControlPlaneError>;
    async fn token_metrics(
        &self,
        cluster_id: &ClusterId,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerMetrics, ControlPlaneError>;
}

#[derive(Debug, Default)]
pub struct InMemoryStore {
    cluster_policies: RwLock<BTreeMap<ClusterId, ClusterPolicy>>,
    overlay_routing_epochs: RwLock<BTreeMap<ClusterId, u64>>,
    nodes: RwLock<BTreeMap<NodeId, NodeRecord>>,
    health: RwLock<BTreeMap<NodeId, NodeHealth>>,
    heartbeat_signature_timestamps: RwLock<BTreeMap<NodeId, chrono::DateTime<Utc>>>,
    nat_classifications: RwLock<BTreeMap<NodeId, NatClassification>>,
    paths: RwLock<Vec<PathRecord>>,
    service_instances: RwLock<BTreeMap<(ClusterId, String), ServiceInstance>>,
    keycloak_candidates: RwLock<BTreeMap<(ClusterId, NodeId), KeycloakCandidateLease>>,
    client_gateway_selections: RwLock<BTreeMap<NodeId, ClientGatewaySelection>>,
}

fn advance_in_memory_overlay_routing_epoch(
    epochs: &mut BTreeMap<ClusterId, u64>,
    cluster_id: &ClusterId,
) -> Result<(), ControlPlaneError> {
    let epoch = epochs.entry(cluster_id.clone()).or_default();
    *epoch = epoch.checked_add(1).ok_or_else(|| {
        ControlPlaneError::Store(format!(
            "overlay routing epoch exhausted for cluster {cluster_id}"
        ))
    })?;
    Ok(())
}

#[async_trait]
impl ControlPlaneStore for InMemoryStore {
    async fn get_cluster_policy(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<Option<ClusterPolicy>, ControlPlaneError> {
        Ok(self.cluster_policies.read().await.get(cluster_id).cloned())
    }

    async fn initialize_cluster_policy_if_absent(
        &self,
        cluster_id: &ClusterId,
        policy: ClusterPolicy,
    ) -> Result<ClusterPolicy, ControlPlaneError> {
        let mut epochs = self.overlay_routing_epochs.write().await;
        let mut policies = self.cluster_policies.write().await;
        if let Some(stored) = policies.get(cluster_id) {
            return Ok(stored.clone());
        }
        advance_in_memory_overlay_routing_epoch(&mut epochs, cluster_id)?;
        policies.insert(cluster_id.clone(), policy.clone());
        Ok(policy)
    }

    async fn get_overlay_routing_epoch(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<u64, ControlPlaneError> {
        Ok(*self
            .overlay_routing_epochs
            .read()
            .await
            .get(cluster_id)
            .unwrap_or(&0))
    }

    async fn upsert_cluster_policy(
        &self,
        cluster_id: &ClusterId,
        policy: ClusterPolicy,
    ) -> Result<(), ControlPlaneError> {
        let mut epochs = self.overlay_routing_epochs.write().await;
        let mut policies = self.cluster_policies.write().await;
        if policies.get(cluster_id) == Some(&policy) {
            return Ok(());
        }
        advance_in_memory_overlay_routing_epoch(&mut epochs, cluster_id)?;
        policies.insert(cluster_id.clone(), policy);
        Ok(())
    }

    async fn upsert_cluster_policy_if_route_catalog_epoch(
        &self,
        cluster_id: &ClusterId,
        policy: ClusterPolicy,
        expected_route_catalog_epoch: u64,
    ) -> Result<bool, ControlPlaneError> {
        let mut epochs = self.overlay_routing_epochs.write().await;
        let mut policies = self.cluster_policies.write().await;
        let nodes = self.nodes.read().await;
        let catalog = nodes
            .values()
            .filter(|node| node.cluster_id == *cluster_id && !node.role.is_client())
            .cloned()
            .collect::<Vec<_>>();
        if overlay_route_catalog_epoch(&catalog)? != expected_route_catalog_epoch {
            return Ok(false);
        }
        if policies.get(cluster_id) == Some(&policy) {
            return Ok(true);
        }
        advance_in_memory_overlay_routing_epoch(&mut epochs, cluster_id)?;
        policies.insert(cluster_id.clone(), policy);
        Ok(true)
    }

    async fn insert_node(&self, node: NodeRecord) -> Result<(), ControlPlaneError> {
        let mut epochs = self.overlay_routing_epochs.write().await;
        let cluster_id = node.cluster_id.clone();
        let mut nodes = self.nodes.write().await;
        if nodes.contains_key(&node.node_id) {
            return Err(ControlPlaneError::NodeAlreadyExists(node.node_id));
        }
        advance_in_memory_overlay_routing_epoch(&mut epochs, &cluster_id)?;
        nodes.insert(node.node_id.clone(), node);
        Ok(())
    }

    async fn insert_node_if_cluster_policy(
        &self,
        node: NodeRecord,
        expected_cluster_policy: Option<ClusterPolicy>,
        expected_route_catalog_epoch: Option<u64>,
    ) -> Result<(), ControlPlaneError> {
        let mut epochs = self.overlay_routing_epochs.write().await;
        let cluster_id = node.cluster_id.clone();
        let policies = self.cluster_policies.read().await;
        if policies.get(&node.cluster_id).cloned() != expected_cluster_policy {
            return Err(ControlPlaneError::ClusterPolicyChanged);
        }
        let mut nodes = self.nodes.write().await;
        if let Some(expected) = expected_route_catalog_epoch {
            let catalog = nodes
                .values()
                .filter(|existing| {
                    existing.cluster_id == node.cluster_id && !existing.role.is_client()
                })
                .cloned()
                .collect::<Vec<_>>();
            if overlay_route_catalog_epoch(&catalog)? != expected {
                return Err(ControlPlaneError::OverlayRouteCatalogChanged);
            }
        }
        if nodes.contains_key(&node.node_id) {
            return Err(ControlPlaneError::NodeAlreadyExists(node.node_id));
        }
        advance_in_memory_overlay_routing_epoch(&mut epochs, &cluster_id)?;
        nodes.insert(node.node_id.clone(), node);
        Ok(())
    }

    async fn get_node(&self, node_id: &NodeId) -> Result<Option<NodeRecord>, ControlPlaneError> {
        Ok(self.nodes.read().await.get(node_id).cloned())
    }

    async fn list_nodes(&self) -> Result<Vec<NodeRecord>, ControlPlaneError> {
        Ok(self.nodes.read().await.values().cloned().collect())
    }

    async fn list_nodes_and_health(
        &self,
    ) -> Result<(Vec<NodeRecord>, BTreeMap<NodeId, NodeHealth>), ControlPlaneError> {
        let nodes = self.nodes.read().await;
        let health = self.health.read().await;
        Ok((nodes.values().cloned().collect(), health.clone()))
    }

    async fn remove_node(&self, node_id: &NodeId) -> Result<RemovedNode, ControlPlaneError> {
        let mut epochs = self.overlay_routing_epochs.write().await;
        let mut nodes = self.nodes.write().await;
        let node = nodes
            .get(node_id)
            .cloned()
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        let mut health = self.health.write().await;
        let mut heartbeat_signature_timestamps = self.heartbeat_signature_timestamps.write().await;
        let mut nat_classifications = self.nat_classifications.write().await;
        let mut client_gateway_selections = self.client_gateway_selections.write().await;
        let mut paths = self.paths.write().await;
        advance_in_memory_overlay_routing_epoch(&mut epochs, &node.cluster_id)?;

        nodes.remove(node_id);
        let removed_health = health.remove(node_id).is_some();
        heartbeat_signature_timestamps.remove(node_id);
        nat_classifications.remove(node_id);
        client_gateway_selections.retain(|client_id, selection| {
            client_id != node_id && &selection.gateway_node_id != node_id
        });
        let mut removed_path_count = 0;
        paths.retain(|path| {
            let keep = &path.key.local != node_id && &path.key.remote != node_id;
            if !keep {
                removed_path_count += 1;
            }
            keep
        });
        Ok(RemovedNode {
            node,
            removed_path_count,
            removed_health,
        })
    }

    async fn update_node_candidates(
        &self,
        node_id: &NodeId,
        candidates: Vec<EndpointCandidate>,
    ) -> Result<(), ControlPlaneError> {
        let mut nodes = self.nodes.write().await;
        let node = nodes
            .get_mut(node_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        node.endpoint_candidates = candidates;
        Ok(())
    }

    async fn update_node_relay_capability(
        &self,
        node_id: &NodeId,
        relay_capability: Option<RelayCapability>,
    ) -> Result<(), ControlPlaneError> {
        let mut nodes = self.nodes.write().await;
        let node = nodes
            .get_mut(node_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        node.relay_capability = relay_capability;
        Ok(())
    }

    async fn update_node_routes(
        &self,
        node_id: &NodeId,
        routes: Vec<Route>,
    ) -> Result<(), ControlPlaneError> {
        let mut epochs = self.overlay_routing_epochs.write().await;
        let mut nodes = self.nodes.write().await;
        let node = nodes
            .get_mut(node_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        if node.routes == routes {
            return Ok(());
        }
        advance_in_memory_overlay_routing_epoch(&mut epochs, &node.cluster_id)?;
        node.routes = routes;
        Ok(())
    }

    async fn update_node_routes_if_cluster_policy(
        &self,
        cluster_id: &ClusterId,
        node_id: &NodeId,
        routes: Vec<Route>,
        expected_cluster_policy: Option<ClusterPolicy>,
        expected_route_catalog_epoch: Option<u64>,
    ) -> Result<(), ControlPlaneError> {
        let mut epochs = self.overlay_routing_epochs.write().await;
        let policies = self.cluster_policies.read().await;
        if policies.get(cluster_id).cloned() != expected_cluster_policy {
            return Err(ControlPlaneError::ClusterPolicyChanged);
        }
        let mut nodes = self.nodes.write().await;
        if let Some(expected) = expected_route_catalog_epoch {
            let catalog = nodes
                .values()
                .filter(|node| node.cluster_id == *cluster_id && !node.role.is_client())
                .cloned()
                .collect::<Vec<_>>();
            if overlay_route_catalog_epoch(&catalog)? != expected {
                return Err(ControlPlaneError::OverlayRouteCatalogChanged);
            }
        }
        let node = nodes
            .get_mut(node_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        if node.cluster_id != *cluster_id {
            return Err(ControlPlaneError::NodeNotFound(node_id.clone()));
        }
        if node.routes == routes {
            return Ok(());
        }
        advance_in_memory_overlay_routing_epoch(&mut epochs, cluster_id)?;
        node.routes = routes;
        Ok(())
    }

    async fn rejoin_node_if_cluster_policy(
        &self,
        update: RejoinNodeStoreUpdate,
    ) -> Result<NodeRecord, ControlPlaneError> {
        let mut epochs = self.overlay_routing_epochs.write().await;
        let policies = self.cluster_policies.read().await;
        if policies.get(&update.cluster_id).cloned() != update.expected_cluster_policy {
            return Err(ControlPlaneError::ClusterPolicyChanged);
        }
        let mut nodes = self.nodes.write().await;
        if let Some(expected) = update.expected_route_catalog_epoch {
            let catalog = nodes
                .values()
                .filter(|node| node.cluster_id == update.cluster_id && !node.role.is_client())
                .cloned()
                .collect::<Vec<_>>();
            if overlay_route_catalog_epoch(&catalog)? != expected {
                return Err(ControlPlaneError::OverlayRouteCatalogChanged);
            }
        }
        let node = nodes
            .get_mut(&update.expected_node.node_id)
            .filter(|node| node.cluster_id == update.cluster_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(update.expected_node.node_id.clone()))?;
        if node != &update.expected_node {
            return Err(ControlPlaneError::NodeStateChanged(node.node_id.clone()));
        }
        let routes_changed = node.routes != update.routes;
        if routes_changed {
            advance_in_memory_overlay_routing_epoch(&mut epochs, &update.cluster_id)?;
        }
        node.endpoint_candidates = update.candidates;
        node.relay_capability = update.relay_capability;
        node.routes = update.routes;
        Ok(node.clone())
    }

    async fn rotate_node_wireguard_public_key(
        &self,
        node_id: &NodeId,
        expected_current_public_key: &str,
        next_public_key: String,
    ) -> Result<NodeRecord, ControlPlaneError> {
        let mut epochs = self.overlay_routing_epochs.write().await;
        let mut nodes = self.nodes.write().await;
        let node = nodes
            .get_mut(node_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        if node.wireguard_public_key != expected_current_public_key {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: node_id.clone(),
                reason: "wireguard public key changed before rotation completed".to_string(),
            });
        }
        if node.wireguard_public_key == next_public_key {
            return Ok(node.clone());
        }
        advance_in_memory_overlay_routing_epoch(&mut epochs, &node.cluster_id)?;
        node.wireguard_public_key = next_public_key;
        Ok(node.clone())
    }

    async fn upsert_health(
        &self,
        node_id: NodeId,
        health: NodeHealth,
    ) -> Result<(), ControlPlaneError> {
        self.health.write().await.insert(node_id, health);
        Ok(())
    }

    async fn get_health(&self, node_id: &NodeId) -> Result<Option<NodeHealth>, ControlPlaneError> {
        Ok(self.health.read().await.get(node_id).cloned())
    }

    async fn get_heartbeat_signature_timestamp(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<chrono::DateTime<Utc>>, ControlPlaneError> {
        Ok(self
            .heartbeat_signature_timestamps
            .read()
            .await
            .get(node_id)
            .copied())
    }

    async fn list_health(&self) -> Result<BTreeMap<NodeId, NodeHealth>, ControlPlaneError> {
        Ok(self.health.read().await.clone())
    }

    async fn upsert_nat_classification(
        &self,
        node_id: NodeId,
        classification: NatClassification,
    ) -> Result<(), ControlPlaneError> {
        self.nat_classifications
            .write()
            .await
            .insert(node_id, classification);
        Ok(())
    }

    async fn get_nat_classification(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<NatClassification>, ControlPlaneError> {
        Ok(self.nat_classifications.read().await.get(node_id).cloned())
    }

    async fn list_nat_classifications(
        &self,
    ) -> Result<BTreeMap<NodeId, NatClassification>, ControlPlaneError> {
        Ok(self.nat_classifications.read().await.clone())
    }

    async fn apply_heartbeat(&self, update: HeartbeatStoreUpdate) -> Result<(), ControlPlaneError> {
        let updates_routes = update.routes.is_some();
        let mut epochs = if updates_routes {
            Some(self.overlay_routing_epochs.write().await)
        } else {
            None
        };
        let policies = self.cluster_policies.read().await;
        if policies.get(&update.cluster_id).cloned() != update.expected_cluster_policy {
            return Err(ControlPlaneError::ClusterPolicyChanged);
        }
        let mut nodes = self.nodes.write().await;
        if let Some(expected) = update.expected_route_catalog_epoch {
            let catalog = nodes
                .values()
                .filter(|node| node.cluster_id == update.cluster_id && !node.role.is_client())
                .cloned()
                .collect::<Vec<_>>();
            if overlay_route_catalog_epoch(&catalog)? != expected {
                return Err(ControlPlaneError::OverlayRouteCatalogChanged);
            }
        }
        let node = nodes
            .get_mut(&update.node_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(update.node_id.clone()))?;
        update.ensure_matches_node_generation(node)?;
        let mut health = self.health.write().await;
        let mut heartbeat_signature_timestamps = self.heartbeat_signature_timestamps.write().await;
        let mut nat_classifications = self.nat_classifications.write().await;
        let mut paths = self.paths.write().await;
        ensure_heartbeat_is_newer(
            &update,
            heartbeat_signature_timestamps.get(&update.node_id).copied(),
            health.get(&update.node_id),
        )?;
        let routes_changed = update
            .routes
            .as_ref()
            .is_some_and(|routes| routes != &node.routes);
        if routes_changed {
            let Some(epochs) = epochs.as_deref_mut() else {
                return Err(ControlPlaneError::Store(
                    "route-changing heartbeat did not acquire the routing epoch lock".to_string(),
                ));
            };
            advance_in_memory_overlay_routing_epoch(epochs, &update.cluster_id)?;
        }

        node.endpoint_candidates = update.candidates;
        node.relay_capability = update.relay_capability;
        if let Some(hostname) = update.hostname {
            node.hostname = Some(hostname);
        }
        if let Some(routes) = update.routes {
            node.routes = routes;
        }
        if let Some(classification) = update.nat_classification {
            nat_classifications.insert(update.node_id.clone(), classification);
        }
        if let Some(accepted_signature_at) = update.accepted_signature_at {
            heartbeat_signature_timestamps.insert(update.node_id.clone(), accepted_signature_at);
        }
        health.insert(update.node_id.clone(), update.health);
        paths.retain(|path| path.key.local != update.node_id);
        paths.extend(update.paths);
        Ok(())
    }

    async fn upsert_path(&self, path: PathRecord) -> Result<(), ControlPlaneError> {
        let mut paths = self.paths.write().await;
        if let Some(existing) = paths.iter_mut().find(|existing| existing.key == path.key) {
            *existing = path;
        } else {
            paths.push(path);
        }
        Ok(())
    }

    async fn replace_node_paths(
        &self,
        node_id: &NodeId,
        replacement_paths: Vec<PathRecord>,
    ) -> Result<(), ControlPlaneError> {
        let mut paths = self.paths.write().await;
        paths.retain(|path| &path.key.local != node_id);
        paths.extend(replacement_paths);
        Ok(())
    }

    async fn list_paths_for(&self, node_id: &NodeId) -> Result<Vec<PathRecord>, ControlPlaneError> {
        Ok(self
            .paths
            .read()
            .await
            .iter()
            .filter(|path| &path.key.local == node_id || &path.key.remote == node_id)
            .cloned()
            .collect())
    }

    async fn list_all_paths(&self) -> Result<Vec<PathRecord>, ControlPlaneError> {
        Ok(self.paths.read().await.clone())
    }

    async fn list_paths_for_pairs(
        &self,
        pairs: &BTreeSet<(NodeId, NodeId)>,
    ) -> Result<Vec<PathRecord>, ControlPlaneError> {
        Ok(self
            .paths
            .read()
            .await
            .iter()
            .filter(|path| pairs.contains(&(path.key.local.clone(), path.key.remote.clone())))
            .cloned()
            .collect())
    }

    async fn upsert_service_instance(
        &self,
        instance: ServiceInstance,
    ) -> Result<(), ControlPlaneError> {
        self.service_instances.write().await.insert(
            (instance.cluster_id.clone(), instance.instance_id.clone()),
            instance,
        );
        Ok(())
    }

    async fn remove_service_instance(
        &self,
        cluster_id: &ClusterId,
        instance_id: &str,
    ) -> Result<bool, ControlPlaneError> {
        Ok(self
            .service_instances
            .write()
            .await
            .remove(&(cluster_id.clone(), instance_id.to_string()))
            .is_some())
    }

    async fn list_service_instances(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<Vec<ServiceInstance>, ControlPlaneError> {
        Ok(self
            .service_instances
            .read()
            .await
            .values()
            .filter(|instance| &instance.cluster_id == cluster_id)
            .cloned()
            .collect())
    }

    async fn upsert_keycloak_candidate(
        &self,
        candidate: KeycloakCandidateLease,
    ) -> Result<bool, ControlPlaneError> {
        let key = (candidate.cluster_id.clone(), candidate.node_id.clone());
        let mut candidates = self.keycloak_candidates.write().await;
        if candidates.get(&key).is_some_and(|current| {
            current.lease_expires_at > candidate.updated_at
                && current.generation >= candidate.generation
        }) {
            return Ok(false);
        }
        candidates.insert(key, candidate);
        Ok(true)
    }

    async fn list_keycloak_candidates(
        &self,
        cluster_id: &ClusterId,
        lease_cutoff: chrono::DateTime<Utc>,
        after_node_id: Option<&NodeId>,
        limit: usize,
    ) -> Result<Vec<KeycloakCandidateLease>, ControlPlaneError> {
        let mut candidates = self
            .keycloak_candidates
            .read()
            .await
            .values()
            .filter(|candidate| {
                &candidate.cluster_id == cluster_id
                    && candidate.eligible
                    && candidate.lease_expires_at > lease_cutoff
                    && after_node_id.is_none_or(|after| candidate.node_id > *after)
            })
            .cloned()
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        candidates.truncate(limit);
        Ok(candidates)
    }

    async fn upsert_client_gateway_selection(
        &self,
        selection: ClientGatewaySelection,
    ) -> Result<(), ControlPlaneError> {
        self.client_gateway_selections
            .write()
            .await
            .insert(selection.client_id.clone(), selection);
        Ok(())
    }

    async fn remove_client_gateway_selection(
        &self,
        client_id: &NodeId,
    ) -> Result<bool, ControlPlaneError> {
        Ok(self
            .client_gateway_selections
            .write()
            .await
            .remove(client_id)
            .is_some())
    }

    async fn list_client_gateway_selections(
        &self,
    ) -> Result<BTreeMap<NodeId, ClientGatewaySelection>, ControlPlaneError> {
        Ok(self.client_gateway_selections.read().await.clone())
    }

    async fn latest_client_gateway_selection_at(
        &self,
    ) -> Result<Option<chrono::DateTime<Utc>>, ControlPlaneError> {
        Ok(self
            .client_gateway_selections
            .read()
            .await
            .values()
            .map(|selection| selection.selected_at)
            .max())
    }
}

#[derive(Debug, Default)]
struct InMemoryTokenLedgerState {
    tokens: BTreeMap<String, TokenLedgerRecord>,
    revocations: BTreeMap<String, TokenRevocationRecord>,
}

#[derive(Debug, Default)]
pub struct InMemoryTokenLedger {
    state: RwLock<InMemoryTokenLedgerState>,
}

#[async_trait]
impl TokenLedger for InMemoryTokenLedger {
    async fn insert_token_if_absent(
        &self,
        record: TokenLedgerRecord,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        let mut state = self.state.write().await;
        let key = token_key(&record.cluster_id, &record.nonce);
        let revoked_at = state
            .revocations
            .get(&key)
            .map(|revocation| revocation.revoked_at);
        let stored = state.tokens.entry(key).or_insert(record.clone());
        ensure_token_definition_matches(stored, &record)?;
        if let Some(revoked_at) = revoked_at {
            stored.revoked_at = Some(revoked_at);
        }
        Ok(stored.clone())
    }

    async fn get_token(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
    ) -> Result<Option<TokenLedgerRecord>, ControlPlaneError> {
        Ok(self
            .state
            .read()
            .await
            .tokens
            .get(&token_key(cluster_id, nonce))
            .cloned())
    }

    async fn admit_token(
        &self,
        record: TokenLedgerRecord,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        let mut state = self.state.write().await;
        let key = token_key(&record.cluster_id, &record.nonce);
        let revoked_at = state
            .revocations
            .get(&key)
            .map(|revocation| revocation.revoked_at);
        let stored = state.tokens.entry(key).or_insert(record.clone());
        ensure_token_definition_matches(stored, &record)?;
        if let Some(revoked_at) = revoked_at {
            stored.revoked_at = Some(revoked_at);
        }
        let status = stored.status(now);
        if status != TokenStatus::Active {
            return Err(ControlPlaneError::TokenRejected {
                nonce: record.nonce,
                status,
            });
        }
        stored.uses = stored.uses.saturating_add(1);
        Ok(stored.clone())
    }

    async fn revoke_token(
        &self,
        revocation: TokenRevocationRecord,
    ) -> Result<TokenRevocationOutcome, ControlPlaneError> {
        let mut state = self.state.write().await;
        let key = token_key(&revocation.cluster_id, &revocation.nonce);
        let stored_revocation = state
            .revocations
            .entry(key.clone())
            .or_insert(revocation)
            .clone();
        let record = state.tokens.get_mut(&key).map(|record| {
            record.revoked_at = Some(stored_revocation.revoked_at);
            record.clone()
        });
        Ok(TokenRevocationOutcome {
            revocation: stored_revocation,
            record,
        })
    }

    async fn token_metrics(
        &self,
        cluster_id: &ClusterId,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerMetrics, ControlPlaneError> {
        let state = self.state.read().await;
        let mut metrics = TokenLedgerMetrics::default();
        for record in state
            .tokens
            .values()
            .filter(|record| &record.cluster_id == cluster_id)
        {
            metrics.observe_record(record, now);
        }
        for (key, revocation) in &state.revocations {
            if &revocation.cluster_id == cluster_id && !state.tokens.contains_key(key) {
                metrics.observe_revocation_tombstone();
            }
        }
        Ok(metrics)
    }
}

#[derive(Debug)]
pub struct TokenAdmission<L> {
    ledger: Arc<L>,
}

impl<L> TokenAdmission<L>
where
    L: TokenLedger,
{
    pub fn new(ledger: Arc<L>) -> Self {
        Self { ledger }
    }

    pub async fn issue_from_claims(
        &self,
        claims: &JoinTokenClaims,
        created_at: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        let record = TokenLedgerRecord::from_claims(claims, created_at);
        self.ledger.insert_token_if_absent(record).await
    }

    pub async fn admit_join(
        &self,
        claims: &JoinTokenClaims,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        self.ledger
            .admit_token(TokenLedgerRecord::from_claims(claims, now), now)
            .await
    }

    pub async fn validate_issued_token(
        &self,
        claims: &JoinTokenClaims,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        let requested = TokenLedgerRecord::from_claims(claims, now);
        let stored = self
            .ledger
            .get_token(&claims.cluster_id, &claims.nonce)
            .await?
            .ok_or_else(|| ControlPlaneError::TokenNotFound(claims.nonce.clone()))?;
        ensure_token_definition_matches(&stored, &requested)?;
        let status = stored.status(now);
        if status != TokenStatus::Active {
            return Err(ControlPlaneError::TokenRejected {
                nonce: claims.nonce.clone(),
                status,
            });
        }
        Ok(stored)
    }

    pub async fn revoke_token(
        &self,
        revocation: TokenRevocationRecord,
    ) -> Result<TokenRevocationOutcome, ControlPlaneError> {
        self.ledger.revoke_token(revocation).await
    }

    pub async fn token_metrics(
        &self,
        cluster_id: &ClusterId,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerMetrics, ControlPlaneError> {
        self.ledger.token_metrics(cluster_id, now).await
    }
}

pub fn ensure_token_definition_matches(
    stored: &TokenLedgerRecord,
    requested: &TokenLedgerRecord,
) -> Result<(), ControlPlaneError> {
    if stored.has_same_definition(requested) {
        return Ok(());
    }
    Err(ControlPlaneError::TokenVerification(format!(
        "token nonce {} conflicts with its durable definition",
        requested.nonce
    )))
}

#[derive(Debug, Clone)]
enum IssuerKeyPolicy {
    Unrestricted,
    NodeEnrollment { max_ttl_seconds: i64 },
}

#[derive(Debug, Clone)]
struct TrustedIssuerKey {
    public_key_b64: String,
    policy: IssuerKeyPolicy,
}

#[derive(Debug, Clone, Default)]
pub struct IssuerKeyRing {
    keys: BTreeMap<(NodeId, KeyId), TrustedIssuerKey>,
}

impl IssuerKeyRing {
    pub fn insert(&mut self, issuer: NodeId, key_id: KeyId, public_key_b64: String) {
        self.keys.insert(
            (issuer, key_id),
            TrustedIssuerKey {
                public_key_b64,
                policy: IssuerKeyPolicy::Unrestricted,
            },
        );
    }

    pub fn insert_node_enrollment_key(
        &mut self,
        issuer: NodeId,
        key_id: KeyId,
        public_key_b64: String,
        max_ttl_seconds: i64,
    ) {
        self.keys.insert(
            (issuer, key_id),
            TrustedIssuerKey {
                public_key_b64,
                policy: IssuerKeyPolicy::NodeEnrollment { max_ttl_seconds },
            },
        );
    }

    fn get(&self, issuer: &NodeId, key_id: &KeyId) -> Option<&TrustedIssuerKey> {
        self.keys.get(&(issuer.clone(), key_id.clone()))
    }
}

fn validate_issuer_key_policy(
    claims: &JoinTokenClaims,
    policy: &IssuerKeyPolicy,
) -> Result<(), ControlPlaneError> {
    let IssuerKeyPolicy::NodeEnrollment { max_ttl_seconds } = policy else {
        return Ok(());
    };
    let reject = |reason: &str| {
        ControlPlaneError::TokenVerification(format!(
            "node enrollment issuer policy rejected token: {reason}"
        ))
    };
    if *max_ttl_seconds <= 0
        || claims.expires_at.signed_duration_since(claims.not_before)
            > chrono::Duration::seconds(
                max_ttl_seconds.saturating_add(JOIN_TOKEN_NOT_BEFORE_SKEW_SECONDS),
            )
    {
        return Err(reject("validity exceeds the configured maximum"));
    }
    if !enrollment_role_is_allowed(&claims.role) {
        return Err(reject("role is not allowed"));
    }
    if claims.role.is_client() && !client_claims_are_control_only(claims) {
        return Err(reject(
            "client tokens must be single-use, untagged, route-free, and relay-free",
        ));
    }
    if claims.tags != claims.policy.allowed_tags {
        return Err(reject("claim tags and allowed tags must match"));
    }
    if !claims.policy.allowed_routes.is_empty() {
        return Err(reject("route authorization is not allowed"));
    }
    if !claims
        .policy
        .max_token_uses
        .is_some_and(|uses| (1..=MAX_NODE_ENROLLMENT_TOKEN_USES).contains(&uses))
    {
        return Err(reject("token uses must be finite and bounded"));
    }
    let required_endpoint_kinds: &[BootstrapEndpointKind] = if claims.role.is_client() {
        &[BootstrapEndpointKind::ControlPlane]
    } else {
        &[
            BootstrapEndpointKind::ControlPlane,
            BootstrapEndpointKind::Signal,
            BootstrapEndpointKind::Stun,
        ]
    };
    for kind in required_endpoint_kinds {
        if join_token_endpoint_count(claims, *kind) < 2 {
            return Err(reject("HA bootstrap endpoints are required"));
        }
    }
    if !claims.role.is_client()
        && claims.policy.allow_relay
        && join_token_endpoint_count(claims, BootstrapEndpointKind::Relay) < 2
    {
        return Err(reject("two relay bootstrap endpoints are required"));
    }
    Ok(())
}

fn join_token_endpoint_count(claims: &JoinTokenClaims, kind: BootstrapEndpointKind) -> usize {
    claims
        .bootstrap_endpoints
        .iter()
        .filter(|endpoint| endpoint.kind == kind)
        .filter_map(|endpoint| canonical_bootstrap_endpoint_url(&endpoint.url))
        .collect::<BTreeSet<_>>()
        .len()
}

#[derive(Debug)]
pub struct ControlPlaneJoinService<S, L> {
    plane: Arc<ControlPlane<S>>,
    admission: TokenAdmission<L>,
    issuer_keys: IssuerKeyRing,
}

impl<S, L> ControlPlaneJoinService<S, L>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    pub fn new(
        plane: Arc<ControlPlane<S>>,
        token_ledger: Arc<L>,
        issuer_keys: IssuerKeyRing,
    ) -> Self {
        Self {
            plane,
            admission: TokenAdmission::new(token_ledger),
            issuer_keys,
        }
    }

    pub fn validate_join_token(
        &self,
        token: &SignedJoinToken,
        now: chrono::DateTime<Utc>,
    ) -> Result<(), ControlPlaneError> {
        token
            .validate_shape()
            .map_err(|error| ControlPlaneError::TokenVerification(error.to_string()))?;
        if !token.claims.policy.allow_join {
            return Err(ControlPlaneError::JoinDenied);
        }

        let issuer_key = self
            .issuer_keys
            .get(&token.claims.issuer, &token.claims.key_id)
            .ok_or_else(|| ControlPlaneError::IssuerKeyNotFound {
                issuer: token.claims.issuer.clone(),
                key_id: token.claims.key_id.clone(),
            })?;
        verify_join_token(
            token,
            &issuer_key.public_key_b64,
            now,
            &self.plane.config.cluster_id,
        )?;
        validate_issuer_key_policy(&token.claims, &issuer_key.policy)?;
        Ok(())
    }

    pub async fn issue_join_token(
        &self,
        token: &SignedJoinToken,
        created_at: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        self.validate_join_token(token, created_at)?;
        self.admission
            .issue_from_claims(&token.claims, created_at)
            .await
    }

    pub async fn validate_issued_join_token(
        &self,
        token: &SignedJoinToken,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        self.validate_join_token(token, now)?;
        self.admission
            .validate_issued_token(&token.claims, now)
            .await
    }

    pub async fn join(
        &self,
        token: SignedJoinToken,
        request: RegisterNodeRequest,
        now: chrono::DateTime<Utc>,
    ) -> Result<RegisterNodeResponse, ControlPlaneError> {
        self.validate_join_token(&token, now)?;
        if token.claims.role.is_client() {
            return Err(ControlPlaneError::JoinDenied);
        }
        self.admission.admit_join(&token.claims, now).await?;
        self.plane.register_with_claims(token.claims, request).await
    }

    pub async fn join_client(
        &self,
        token: SignedJoinToken,
        request: RegisterClientRequest,
        now: chrono::DateTime<Utc>,
    ) -> Result<RegisterClientResponse, ControlPlaneError> {
        self.validate_join_token(&token, now)?;
        if !client_claims_are_control_only(&token.claims) {
            return Err(ControlPlaneError::JoinDenied);
        }
        self.plane.require_client_gateway().await?;
        self.admission.admit_join(&token.claims, now).await?;
        self.plane
            .register_client_with_claims(token.claims, request)
            .await
    }

    pub async fn revoke_token(
        &self,
        request: &RevokeTokenRequest,
        revoked_at: chrono::DateTime<Utc>,
    ) -> Result<TokenRevocationOutcome, ControlPlaneError> {
        if request.cluster_id != self.plane.config.cluster_id {
            return Err(ControlPlaneError::TokenVerification(format!(
                "token revocation cluster mismatch: expected {}, got {}",
                self.plane.config.cluster_id, request.cluster_id
            )));
        }
        let issuer_public_key = self
            .issuer_keys
            .get(&request.issuer, &request.key_id)
            .ok_or_else(|| ControlPlaneError::IssuerKeyNotFound {
                issuer: request.issuer.clone(),
                key_id: request.key_id.clone(),
            })?;
        if !matches!(issuer_public_key.policy, IssuerKeyPolicy::Unrestricted) {
            return Err(ControlPlaneError::TokenVerification(
                "issuer key is not authorized for token revocation".to_string(),
            ));
        }
        let signature = request.issuer_signature.as_ref().ok_or_else(|| {
            ControlPlaneError::TokenVerification(
                "token revocation issuer signature is required".to_string(),
            )
        })?;
        verify_token_revocation_signature(request, &issuer_public_key.public_key_b64)?;
        if !timestamp_within_skew(
            signature.signed_at,
            revoked_at,
            self.plane.config.heartbeat_signature_max_age,
        ) {
            return Err(ControlPlaneError::TokenVerification(format!(
                "token revocation signed_at {} is outside the allowed {}s window",
                signature.signed_at,
                self.plane.config.heartbeat_signature_max_age.as_secs()
            )));
        }
        self.admission
            .revoke_token(TokenRevocationRecord {
                cluster_id: request.cluster_id.clone(),
                nonce: request.nonce.clone(),
                issuer: request.issuer.clone(),
                key_id: request.key_id.clone(),
                revoked_at,
            })
            .await
    }

    pub async fn token_metrics(
        &self,
        cluster_id: &ClusterId,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerMetrics, ControlPlaneError> {
        self.admission.token_metrics(cluster_id, now).await
    }
}

type OverlayTopologyCacheCell = Arc<OnceCell<Result<Arc<BoundedTopology>, String>>>;
type OverlayTopologyCache = BTreeMap<OverlayTopologyCacheKey, OverlayTopologyCacheCell>;

#[derive(Debug)]
struct OverlayNodeSnapshot {
    loaded_at: Instant,
    generated_at: chrono::DateTime<Utc>,
    nodes: Vec<NodeRecord>,
    nodes_by_id: BTreeMap<NodeId, usize>,
    clients: Vec<NodeRecord>,
    health_by_node: BTreeMap<NodeId, NodeHealth>,
    active_nodes: Vec<NodeRecord>,
    active_nodes_by_id: BTreeMap<NodeId, usize>,
    health_ttl_seconds: u64,
    topology_cache_key: Arc<OverlayTopologyCacheKey>,
    aggregate_routes: Vec<AggregateOverlayRoute>,
    route_index: OverlayRouteIndex,
    routing_epoch: u64,
}

#[derive(Clone)]
enum OverlayTopologyNodeSource {
    Snapshot(Arc<OverlayNodeSnapshot>),
    #[cfg(test)]
    Owned(Arc<Vec<NodeRecord>>),
}

impl OverlayTopologyNodeSource {
    fn nodes(&self) -> &[NodeRecord] {
        match self {
            Self::Snapshot(snapshot) => &snapshot.nodes,
            #[cfg(test)]
            Self::Owned(nodes) => nodes,
        }
    }
}

#[derive(Debug, Clone)]
struct IndexedOverlayRoute {
    node_id: NodeId,
    route: Route,
}

#[derive(Debug)]
struct OverlayRouteIndex {
    vpn_owner_by_ip: BTreeMap<IpAddr, NodeId>,
    ipv4_by_prefix: Vec<BTreeMap<u32, Vec<IndexedOverlayRoute>>>,
    ipv6_by_prefix: Vec<BTreeMap<u128, Vec<IndexedOverlayRoute>>>,
}

impl OverlayRouteIndex {
    fn build(nodes: &[NodeRecord]) -> Self {
        let mut vpn_owner_by_ip = BTreeMap::new();
        let mut ipv4_by_prefix = (0..=32_u8)
            .map(|_| BTreeMap::<u32, Vec<IndexedOverlayRoute>>::new())
            .collect::<Vec<_>>();
        let mut ipv6_by_prefix = (0..=128_u8)
            .map(|_| BTreeMap::<u128, Vec<IndexedOverlayRoute>>::new())
            .collect::<Vec<_>>();
        let mut ordered_nodes = nodes.iter().collect::<Vec<_>>();
        ordered_nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));

        for node in ordered_nodes {
            vpn_owner_by_ip
                .entry(node.vpn_ip.0)
                .or_insert_with(|| node.node_id.clone());
            for route in node
                .routes
                .iter()
                .filter(|route| overlay_route_is_self_owned(node, route))
            {
                let mut canonical_route = route.clone();
                canonical_route.cidr = canonical_route.cidr.trunc();
                let indexed = IndexedOverlayRoute {
                    node_id: node.node_id.clone(),
                    route: canonical_route,
                };
                match indexed.route.cidr {
                    IpNet::V4(cidr) => {
                        ipv4_by_prefix[usize::from(cidr.prefix_len())]
                            .entry(u32::from(cidr.network()))
                            .or_default()
                            .push(indexed);
                    }
                    IpNet::V6(cidr) => {
                        ipv6_by_prefix[usize::from(cidr.prefix_len())]
                            .entry(u128::from(cidr.network()))
                            .or_default()
                            .push(indexed);
                    }
                }
            }
        }

        for candidates in ipv4_by_prefix
            .iter_mut()
            .flat_map(BTreeMap::values_mut)
            .chain(ipv6_by_prefix.iter_mut().flat_map(BTreeMap::values_mut))
        {
            candidates.sort_by(|left, right| {
                (left.route.metric, &left.node_id, left.route.id.as_str()).cmp(&(
                    right.route.metric,
                    &right.node_id,
                    right.route.id.as_str(),
                ))
            });
        }

        Self {
            vpn_owner_by_ip,
            ipv4_by_prefix,
            ipv6_by_prefix,
        }
    }

    fn resolve_destination(
        &self,
        source: &NodeRecord,
        active_nodes: &[NodeRecord],
        active_nodes_by_id: &BTreeMap<NodeId, usize>,
        destination: IpAddr,
        policy: &ClusterPolicy,
    ) -> Option<NodeRecord> {
        if let Some(target_id) = self.vpn_owner_by_ip.get(&destination) {
            let target = active_nodes.get(*active_nodes_by_id.get(target_id)?)?;
            if target.node_id == source.node_id {
                return None;
            }
            if policy.acl_rules.is_empty() {
                return Some(target.clone());
            }
            if acl_allows_peer(source, target, policy) {
                return acl_filter_peer(source, target, policy);
            }
            return None;
        }

        match destination {
            IpAddr::V4(destination) => {
                for prefix_len in (0..=32_u8).rev() {
                    let key = ipv4_prefix_key(destination, prefix_len);
                    let Some(candidates) = self.ipv4_by_prefix[usize::from(prefix_len)].get(&key)
                    else {
                        continue;
                    };
                    if let Some(target) = resolve_indexed_route(
                        source,
                        active_nodes,
                        active_nodes_by_id,
                        candidates,
                        destination.into(),
                        policy,
                    ) {
                        return Some(target);
                    }
                }
            }
            IpAddr::V6(destination) => {
                for prefix_len in (0..=128_u8).rev() {
                    let key = ipv6_prefix_key(destination, prefix_len);
                    let Some(candidates) = self.ipv6_by_prefix[usize::from(prefix_len)].get(&key)
                    else {
                        continue;
                    };
                    if let Some(target) = resolve_indexed_route(
                        source,
                        active_nodes,
                        active_nodes_by_id,
                        candidates,
                        destination.into(),
                        policy,
                    ) {
                        return Some(target);
                    }
                }
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct ControlPlane<S> {
    config: ControlPlaneConfig,
    store: Arc<S>,
    cluster_policy: StdRwLock<ClusterPolicy>,
    overlay_node_snapshot_cache: Mutex<Option<Arc<OverlayNodeSnapshot>>>,
    overlay_topology_cache: Mutex<OverlayTopologyCache>,
    allocator: RwLock<VpnAllocator>,
    accepted_node_query_nonces: Mutex<BTreeMap<(NodeId, String), chrono::DateTime<Utc>>>,
    operation_metrics: ControlPlaneOperationMetrics,
    admin_path_pins: RwLock<BTreeMap<(NodeId, NodeId), bool>>,
    connection_intent_notifiers: Mutex<BTreeMap<NodeId, Arc<Notify>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OverlayTopologyCacheKey {
    membership_epoch: u64,
    node_count: usize,
    block_size: u16,
    max_degree: u16,
    permutation_seed: String,
}

#[derive(Debug, Default)]
struct ControlPlaneOperationMetrics {
    wireguard_key_rotation_success_count: AtomicU64,
    wireguard_key_rotation_failure_count: AtomicU64,
    node_removal_success_count: AtomicU64,
    node_removal_failure_count: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
struct ControlPlaneOperationMetricsSnapshot {
    wireguard_key_rotation_success_count: u64,
    wireguard_key_rotation_failure_count: u64,
    node_removal_success_count: u64,
    node_removal_failure_count: u64,
}

impl ControlPlaneOperationMetrics {
    fn record_wireguard_key_rotation(&self, success: bool) {
        let counter = if success {
            &self.wireguard_key_rotation_success_count
        } else {
            &self.wireguard_key_rotation_failure_count
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn record_node_removal(&self, success: bool) {
        let counter = if success {
            &self.node_removal_success_count
        } else {
            &self.node_removal_failure_count
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> ControlPlaneOperationMetricsSnapshot {
        ControlPlaneOperationMetricsSnapshot {
            wireguard_key_rotation_success_count: self
                .wireguard_key_rotation_success_count
                .load(Ordering::Relaxed),
            wireguard_key_rotation_failure_count: self
                .wireguard_key_rotation_failure_count
                .load(Ordering::Relaxed),
            node_removal_success_count: self.node_removal_success_count.load(Ordering::Relaxed),
            node_removal_failure_count: self.node_removal_failure_count.load(Ordering::Relaxed),
        }
    }
}

impl<S> ControlPlane<S>
where
    S: ControlPlaneStore,
{
    pub fn new(config: ControlPlaneConfig, store: Arc<S>) -> Self {
        let cluster_policy = config.cluster_policy.clone();
        Self {
            allocator: RwLock::new(VpnAllocator::new(config.vpn_pool)),
            accepted_node_query_nonces: Mutex::new(BTreeMap::new()),
            operation_metrics: ControlPlaneOperationMetrics::default(),
            cluster_policy: StdRwLock::new(cluster_policy),
            overlay_node_snapshot_cache: Mutex::new(None),
            overlay_topology_cache: Mutex::new(BTreeMap::new()),
            admin_path_pins: RwLock::new(BTreeMap::new()),
            connection_intent_notifiers: Mutex::new(BTreeMap::new()),
            config,
            store,
        }
    }

    pub fn config(&self) -> &ControlPlaneConfig {
        &self.config
    }

    pub fn cluster_policy(&self) -> Result<ClusterPolicy, ControlPlaneError> {
        let policy = self
            .cluster_policy
            .read()
            .map(|policy| policy.clone())
            .map_err(|_| ControlPlaneError::Store("cluster policy lock is poisoned".to_string()))?;
        validate_cluster_policy(&policy)?;
        validate_overlay_route_scopes_against_vpn_pool(&policy, self.config.vpn_pool)?;
        Ok(policy)
    }

    pub async fn current_cluster_policy(&self) -> Result<ClusterPolicy, ControlPlaneError> {
        Ok(self.current_cluster_policy_state().await?.0)
    }

    async fn current_cluster_policy_state(
        &self,
    ) -> Result<(ClusterPolicy, Option<ClusterPolicy>), ControlPlaneError> {
        let persisted = self
            .store
            .get_cluster_policy(&self.config.cluster_id)
            .await?;
        if let Some(policy) = persisted {
            validate_cluster_policy(&policy)?;
            validate_overlay_route_scopes_against_vpn_pool(&policy, self.config.vpn_pool)?;
            self.cache_cluster_policy(policy.clone())?;
            return Ok((policy.clone(), Some(policy)));
        }
        let policy = self
            .store
            .initialize_cluster_policy_if_absent(&self.config.cluster_id, self.cluster_policy()?)
            .await?;
        validate_cluster_policy(&policy)?;
        validate_overlay_route_scopes_against_vpn_pool(&policy, self.config.vpn_pool)?;
        self.cache_cluster_policy(policy.clone())?;
        Ok((policy.clone(), Some(policy)))
    }

    async fn current_cluster_routing_state(
        &self,
    ) -> Result<(ClusterPolicy, Option<ClusterPolicy>, u64), ControlPlaneError> {
        for _ in 0..MAX_ROUTE_CATALOG_UPDATE_RETRIES {
            let before = self
                .store
                .get_overlay_routing_epoch(&self.config.cluster_id)
                .await?;
            let (policy, persisted) = self.current_cluster_policy_state().await?;
            let after = self
                .store
                .get_overlay_routing_epoch(&self.config.cluster_id)
                .await?;
            if before == after {
                return Ok((policy, persisted, after));
            }
        }
        Err(ControlPlaneError::ClusterPolicyChanged)
    }

    async fn current_overlay_snapshot(
        &self,
    ) -> Result<(ClusterPolicy, Arc<OverlayNodeSnapshot>), ControlPlaneError> {
        for _ in 0..MAX_ROUTE_CATALOG_UPDATE_RETRIES {
            let (policy, _, routing_epoch) = self.current_cluster_routing_state().await?;
            match self.overlay_node_snapshot(&policy, routing_epoch).await {
                Ok(snapshot) => return Ok((policy, snapshot)),
                Err(
                    ControlPlaneError::ClusterPolicyChanged
                    | ControlPlaneError::OverlayRouteCatalogChanged,
                ) => {}
                Err(error) => return Err(error),
            }
        }
        Err(ControlPlaneError::OverlayRouteCatalogChanged)
    }

    pub async fn advertise_service_instance(
        &self,
        instance: ServiceInstance,
    ) -> Result<(), ControlPlaneError> {
        validate_service_instance(&instance, &self.config.cluster_id, Utc::now())?;
        self.store.upsert_service_instance(instance).await
    }

    pub async fn withdraw_service_instance(
        &self,
        instance_id: &str,
    ) -> Result<bool, ControlPlaneError> {
        self.store
            .remove_service_instance(&self.config.cluster_id, instance_id)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile_keycloak_placement(
        &self,
        node_id: &NodeId,
        vpn_ip: VpnIp,
        version: &str,
        eligible: bool,
        ready: bool,
        generation: i64,
        lease_ttl: Duration,
        desired_replicas: usize,
        max_candidates: usize,
        now: chrono::DateTime<Utc>,
    ) -> Result<KeycloakPlacement, ControlPlaneError> {
        if !(1..=9).contains(&desired_replicas)
            || !(desired_replicas..=64).contains(&max_candidates)
        {
            return Err(ControlPlaneError::InvalidClusterPolicy(
                "Keycloak placement must request 1 to 9 replicas from at most 64 candidates"
                    .to_string(),
            ));
        }
        if generation <= 0 {
            return Err(ControlPlaneError::InvalidClusterPolicy(
                "Keycloak candidate generation must be a positive signed 63-bit integer"
                    .to_string(),
            ));
        }
        if lease_ttl < Duration::from_secs(15)
            || lease_ttl > Duration::from_secs(MAX_SERVICE_LEASE_SECONDS as u64)
        {
            return Err(ControlPlaneError::InvalidClusterPolicy(
                "Keycloak candidate lease must be between 15 and 300 seconds".to_string(),
            ));
        }
        if version.is_empty()
            || version.len() > 64
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(ControlPlaneError::InvalidClusterPolicy(
                "Keycloak version must be 1 to 64 ASCII letters, digits, '.', '_' or '-'"
                    .to_string(),
            ));
        }

        let policy = self.current_cluster_policy().await?;
        let (nodes, health_by_node) = self.registered_nodes_with_health().await?;
        let node = nodes
            .iter()
            .find(|node| node.cluster_id == self.config.cluster_id && node.node_id == *node_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        if node.role.is_client() || node.vpn_ip != vpn_ip {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: node_id.clone(),
                reason: "Keycloak candidate identity or VPN address does not match registration"
                    .to_string(),
            });
        }
        let healthy = relay_health_allows(
            health_by_node.get(node_id),
            now,
            policy.relay_health_ttl_seconds,
        );
        if eligible && !healthy {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: node_id.clone(),
                reason: "Keycloak candidate heartbeat is unhealthy or stale".to_string(),
            });
        }

        let lease_expires_at = now
            .checked_add_signed(chrono::Duration::from_std(lease_ttl).map_err(|error| {
                ControlPlaneError::Store(format!(
                    "invalid Keycloak candidate lease duration: {error}"
                ))
            })?)
            .ok_or_else(|| {
                ControlPlaneError::Store(
                    "Keycloak candidate lease expiration is out of range".to_string(),
                )
            })?;
        let applied = self
            .store
            .upsert_keycloak_candidate(KeycloakCandidateLease {
                cluster_id: self.config.cluster_id.clone(),
                node_id: node_id.clone(),
                vpn_ip,
                version: version.to_string(),
                ready,
                eligible,
                generation,
                lease_expires_at,
                updated_at: now,
            })
            .await?;
        if !applied {
            return Err(ControlPlaneError::KeycloakCandidateGenerationConflict {
                node_id: node_id.clone(),
                generation,
            });
        }

        self.keycloak_placement(version, desired_replicas, max_candidates, now)
            .await
    }

    pub async fn keycloak_placement(
        &self,
        version: &str,
        desired_replicas: usize,
        max_candidates: usize,
        now: chrono::DateTime<Utc>,
    ) -> Result<KeycloakPlacement, ControlPlaneError> {
        let policy = self.current_cluster_policy().await?;
        let (nodes, health_by_node) = self.registered_nodes_with_health().await?;
        let registered_by_id = nodes
            .iter()
            .filter(|node| node.cluster_id == self.config.cluster_id && !node.role.is_client())
            .map(|node| (&node.node_id, node))
            .collect::<BTreeMap<_, _>>();
        let mut candidates = Vec::with_capacity(max_candidates);
        let mut after_node_id = None;
        while candidates.len() < max_candidates {
            let page = self
                .store
                .list_keycloak_candidates(
                    &self.config.cluster_id,
                    now,
                    after_node_id.as_ref(),
                    KEYCLOAK_CANDIDATE_PAGE_SIZE,
                )
                .await?;
            if page.is_empty() {
                break;
            }
            after_node_id = page.last().map(|candidate| candidate.node_id.clone());
            let page_was_full = page.len() == KEYCLOAK_CANDIDATE_PAGE_SIZE;
            candidates.extend(page.into_iter().filter(|candidate| {
                candidate.version == version
                    && registered_by_id
                        .get(&candidate.node_id)
                        .is_some_and(|node| node.vpn_ip == candidate.vpn_ip)
                    && relay_health_allows(
                        health_by_node.get(&candidate.node_id),
                        now,
                        policy.relay_health_ttl_seconds,
                    )
            }));
            candidates.truncate(max_candidates);
            if !page_was_full {
                break;
            }
        }
        Ok(select_keycloak_candidates(
            &self.config.cluster_id,
            candidates,
            desired_replicas,
        ))
    }

    pub async fn service_directory(&self) -> Result<ServiceDirectory, ControlPlaneError> {
        self.service_directory_at(Utc::now()).await
    }

    pub async fn enrollment_service_directory(
        &self,
        max_staleness: Duration,
    ) -> Result<ServiceDirectory, ControlPlaneError> {
        if max_staleness > Duration::from_secs(MAX_JOIN_TOKEN_TTL_SECONDS as u64) {
            return Err(ControlPlaneError::Store(format!(
                "enrollment service staleness exceeds {MAX_JOIN_TOKEN_TTL_SECONDS} seconds"
            )));
        }
        let max_staleness = chrono::Duration::from_std(max_staleness).map_err(|error| {
            ControlPlaneError::Store(format!(
                "invalid enrollment service staleness duration: {error}"
            ))
        })?;
        let now = Utc::now();
        let lease_cutoff = now.checked_sub_signed(max_staleness).ok_or_else(|| {
            ControlPlaneError::Store("enrollment service staleness is out of range".to_string())
        })?;
        self.service_directory_since(now, lease_cutoff).await
    }

    async fn service_directory_at(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> Result<ServiceDirectory, ControlPlaneError> {
        self.service_directory_since(now, now).await
    }

    async fn service_directory_since(
        &self,
        now: chrono::DateTime<Utc>,
        lease_cutoff: chrono::DateTime<Utc>,
    ) -> Result<ServiceDirectory, ControlPlaneError> {
        let policy = self.current_cluster_policy().await?;
        let nodes = self.store.list_nodes().await?;
        let health_by_node = self.health_by_node(&nodes).await?;
        let nat_by_node = self.store.list_nat_classifications().await?;
        let eligible_owner_node_ids = eligible_service_owner_node_ids(
            &nodes,
            &health_by_node,
            &nat_by_node,
            &self.config.cluster_id,
            now,
            &policy,
        );
        let mut instances = self
            .store
            .list_service_instances(&self.config.cluster_id)
            .await?
            .into_iter()
            .filter(|instance| instance.lease_expires_at > lease_cutoff)
            .filter(|instance| {
                service_instance_owner_node_id(instance)
                    .is_some_and(|node_id| eligible_owner_node_ids.contains(node_id))
            })
            .collect::<Vec<_>>();
        instances.sort_by(|left, right| {
            let left_has_core = bootstrap_endpoints_include_core_services(&left.endpoints);
            let right_has_core = bootstrap_endpoints_include_core_services(&right.endpoints);
            right
                .enrollment_signer
                .cmp(&left.enrollment_signer)
                .then_with(|| right_has_core.cmp(&left_has_core))
                .then_with(|| right.updated_at.cmp(&left.updated_at))
                .then_with(|| left.instance_id.cmp(&right.instance_id))
        });
        instances.truncate(MAX_ACTIVE_SERVICE_INSTANCES);
        instances.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));

        let mut per_kind = BTreeMap::<BootstrapEndpointKind, usize>::new();
        let mut seen = BTreeSet::<(BootstrapEndpointKind, String)>::new();
        let mut bootstrap_endpoints = Vec::new();
        let signer_control_plane_endpoints = instances
            .iter()
            .filter(|instance| instance.enrollment_signer)
            .flat_map(|instance| {
                instance
                    .endpoints
                    .iter()
                    .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
            });
        let remaining_endpoints = instances
            .iter()
            .flat_map(|instance| instance.endpoints.iter());
        for endpoint in signer_control_plane_endpoints.chain(remaining_endpoints) {
            if bootstrap_endpoints.len() >= MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS {
                break;
            }
            let count = per_kind.entry(endpoint.kind).or_default();
            let endpoint_key = canonical_bootstrap_endpoint_url(&endpoint.url)
                .unwrap_or_else(|| endpoint.url.clone());
            if *count >= MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND
                || !seen.insert((endpoint.kind, endpoint_key))
            {
                continue;
            }
            bootstrap_endpoints.push(endpoint.clone());
            *count += 1;
        }
        if !bootstrap_endpoints_include_core_services(&bootstrap_endpoints) {
            bootstrap_endpoints.clear();
        }

        Ok(ServiceDirectory {
            cluster_id: self.config.cluster_id.clone(),
            instances,
            bootstrap_endpoints,
            generated_at: now,
        })
    }

    pub async fn set_cluster_policy(
        &self,
        policy: ClusterPolicy,
    ) -> Result<ClusterPolicy, ControlPlaneError> {
        validate_cluster_policy(&policy)?;
        validate_overlay_route_scopes_against_vpn_pool(&policy, self.config.vpn_pool)?;
        for _ in 0..3 {
            let nodes = self
                .store
                .list_nodes()
                .await?
                .into_iter()
                .filter(|node| node.cluster_id == self.config.cluster_id)
                .filter(|node| !node.role.is_client())
                .collect::<Vec<_>>();
            if !policy.overlay_route_scopes.is_empty() {
                for node in &nodes {
                    validate_routes_within_overlay_scopes(&node.routes, &policy).map_err(
                        |reason| {
                            ControlPlaneError::InvalidClusterPolicy(format!(
                                "node {} has an advertised route outside overlay_route_scopes: \
                                 {reason}",
                                node.node_id
                            ))
                        },
                    )?;
                }
            }
            let expected_route_catalog_epoch = overlay_route_catalog_epoch(&nodes)?;
            if self
                .store
                .upsert_cluster_policy_if_route_catalog_epoch(
                    &self.config.cluster_id,
                    policy.clone(),
                    expected_route_catalog_epoch,
                )
                .await?
            {
                self.cache_cluster_policy(policy.clone())?;
                return Ok(policy);
            }
        }
        Err(ControlPlaneError::ClusterPolicyChanged)
    }

    fn cache_cluster_policy(&self, policy: ClusterPolicy) -> Result<(), ControlPlaneError> {
        let mut current = self
            .cluster_policy
            .write()
            .map_err(|_| ControlPlaneError::Store("cluster policy lock is poisoned".to_string()))?;
        *current = policy;
        Ok(())
    }

    pub async fn list_nodes(&self) -> Result<Vec<NodeRecord>, ControlPlaneError> {
        Ok(self
            .store
            .list_nodes()
            .await?
            .into_iter()
            .filter(|node| !node.role.is_client())
            .collect())
    }

    pub async fn registered_nodes_with_health(
        &self,
    ) -> Result<(Vec<NodeRecord>, BTreeMap<NodeId, NodeHealth>), ControlPlaneError> {
        let (_, snapshot) = self.current_overlay_snapshot().await?;
        Ok((snapshot.nodes.clone(), snapshot.health_by_node.clone()))
    }

    pub async fn require_client_gateway(&self) -> Result<NodeRecord, ControlPlaneError> {
        let now = Utc::now();
        let policy = self.current_cluster_policy().await?;
        let nodes = self.store.list_nodes().await?;
        let health_by_node = self.health_by_node(&nodes).await?;
        select_client_gateways(&nodes, &health_by_node, now, &policy)
            .into_iter()
            .next()
            .cloned()
            .ok_or_else(|| {
                ControlPlaneError::Store("no reachable client gateway is registered".to_string())
            })
    }

    pub async fn health_for_node(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<NodeHealth>, ControlPlaneError> {
        self.store.get_health(node_id).await
    }

    pub async fn nat_classification_for(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<NatClassification>, ControlPlaneError> {
        self.store.get_nat_classification(node_id).await
    }

    pub async fn nat_classifications(
        &self,
    ) -> Result<BTreeMap<NodeId, NatClassification>, ControlPlaneError> {
        self.store.list_nat_classifications().await
    }

    pub async fn nat_discovery_overview(
        &self,
    ) -> Result<ControlPlaneNatDiscoveryOverview, ControlPlaneError> {
        let classifications = self.store.list_nat_classifications().await?;
        let policy = self.current_cluster_policy().await?;
        let now = Utc::now();
        let mut stale_count = 0;
        let mut low_confidence_count = 0;
        let mut strategy_counts = BTreeMap::<NatTraversalStrategy, usize>::new();
        for classification in classifications.values() {
            if !nat_classification_is_fresh(
                classification,
                now,
                policy.nat_classification_ttl_seconds,
            ) {
                stale_count += 1;
                continue;
            }
            if classification.confidence * 100.0
                < f32::from(policy.nat_classification_min_confidence_percent)
            {
                low_confidence_count += 1;
            }
            *strategy_counts.entry(classification.strategy).or_default() += 1;
        }
        Ok(ControlPlaneNatDiscoveryOverview {
            nat_classification_count: classifications.len(),
            stale_nat_classification_count: stale_count,
            fresh_low_confidence_nat_classification_count: low_confidence_count,
            fresh_nat_classification_strategy_counts: NatTraversalStrategy::ALL
                .into_iter()
                .map(|strategy| NatTraversalStrategyCount {
                    strategy,
                    count: *strategy_counts.get(&strategy).unwrap_or(&0),
                })
                .collect(),
            nat_classification_ttl_seconds: policy.nat_classification_ttl_seconds,
            nat_classification_min_confidence_percent: policy
                .nat_classification_min_confidence_percent,
        })
    }

    pub async fn list_paths(&self) -> Result<Vec<PathRecord>, ControlPlaneError> {
        let mut paths = self.store.list_all_paths().await?;
        paths.sort_by(|left, right| {
            left.key
                .local
                .cmp(&right.key.local)
                .then_with(|| left.key.remote.cmp(&right.key.remote))
        });
        self.apply_admin_path_pins(&mut paths).await;
        Ok(paths)
    }

    pub async fn admin_remove_node(
        &self,
        node_id: &NodeId,
    ) -> Result<RemoveNodeResponse, ControlPlaneError> {
        let result = self.store.remove_node(node_id).await?;
        self.invalidate_overlay_node_snapshot().await;
        self.admin_path_pins
            .write()
            .await
            .retain(|(local, remote), _| local != node_id && remote != node_id);
        *self.allocator.write().await = VpnAllocator::new(self.config.vpn_pool);
        self.operation_metrics.record_node_removal(true);
        Ok(RemoveNodeResponse {
            node: result.node,
            removed_path_count: result.removed_path_count,
            removed_health: result.removed_health,
            removed_at: Utc::now(),
        })
    }

    pub async fn set_admin_path_pin(
        &self,
        local: NodeId,
        remote: NodeId,
        pinned: bool,
    ) -> Result<PathRecord, ControlPlaneError> {
        self.store
            .get_node(&local)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(local.clone()))?;
        self.store
            .get_node(&remote)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(remote.clone()))?;
        let mut path = self
            .store
            .list_paths_for(&local)
            .await?
            .into_iter()
            .find(|path| path.key.local == local && path.key.remote == remote)
            .ok_or_else(|| ControlPlaneError::PathNotFound {
                local: local.clone(),
                remote: remote.clone(),
            })?;
        if pinned {
            self.admin_path_pins
                .write()
                .await
                .insert((local.clone(), remote.clone()), true);
        } else {
            self.admin_path_pins
                .write()
                .await
                .remove(&(local.clone(), remote.clone()));
        }
        path.pinned = pinned;
        self.store.upsert_path(path.clone()).await?;
        Ok(path)
    }

    async fn apply_admin_path_pins(&self, paths: &mut [PathRecord]) {
        let pins = self.admin_path_pins.read().await;
        for path in paths {
            if let Some(pinned) = pins.get(&(path.key.local.clone(), path.key.remote.clone())) {
                path.pinned = *pinned;
            }
        }
    }

    pub async fn register_with_claims(
        &self,
        claims: JoinTokenClaims,
        request: RegisterNodeRequest,
    ) -> Result<RegisterNodeResponse, ControlPlaneError> {
        if claims.role.is_client() {
            return Err(ControlPlaneError::JoinDenied);
        }
        self.register_participant_with_claims(claims, request).await
    }

    pub async fn register_client_with_claims(
        &self,
        claims: JoinTokenClaims,
        request: RegisterClientRequest,
    ) -> Result<RegisterClientResponse, ControlPlaneError> {
        if !client_claims_are_control_only(&claims) {
            return Err(ControlPlaneError::JoinDenied);
        }
        let response = self
            .register_participant_with_claims(
                claims,
                RegisterNodeRequest {
                    node_id: request.client_id,
                    identity_public_key: request.identity_public_key,
                    wireguard_public_key: request.wireguard_public_key,
                    candidates: Vec::new(),
                    nat_classification: None,
                    relay_capability: None,
                    requested_routes: Vec::new(),
                },
            )
            .await?;
        Ok(RegisterClientResponse {
            client: response.node,
            peer_map: response.peer_map,
            cluster_policy: response.cluster_policy,
        })
    }

    pub async fn register_sponsored_client(
        &self,
        request: SponsoredClientRegistrationRequest,
        now: chrono::DateTime<Utc>,
    ) -> Result<RegisterClientResponse, ControlPlaneError> {
        let reject_bundle = |reason: String| ControlPlaneError::NodeRegistrationRejected {
            node_id: request.bundle.registration.client_id.clone(),
            reason,
        };
        if request.bundle.schema_version != CLIENT_REGISTRATION_SCHEMA_VERSION {
            return Err(reject_bundle(format!(
                "unsupported client registration schema version {}",
                request.bundle.schema_version
            )));
        }
        if request.bundle.issued_at.timestamp_subsec_nanos() != 0
            || request.bundle.expires_at.timestamp_subsec_nanos() != 0
        {
            return Err(reject_bundle(
                "client registration timestamps must use whole-second precision".to_string(),
            ));
        }
        if request.bundle.expires_at <= request.bundle.issued_at
            || request
                .bundle
                .expires_at
                .signed_duration_since(request.bundle.issued_at)
                > chrono::Duration::seconds(MAX_CLIENT_REGISTRATION_VALIDITY_SECONDS)
        {
            return Err(reject_bundle(format!(
                "client registration validity must be between 1 and {MAX_CLIENT_REGISTRATION_VALIDITY_SECONDS} seconds"
            )));
        }
        if request.bundle.expires_at <= now {
            return Err(reject_bundle(
                "client registration bundle has expired".to_string(),
            ));
        }
        if !timestamp_not_after_skew(
            request.bundle.issued_at,
            now,
            self.config.heartbeat_signature_max_age,
        ) {
            return Err(reject_bundle(
                "client registration bundle was issued in the future".to_string(),
            ));
        }
        validate_node_api_request_nonce(&request.bundle.nonce).map_err(|error| {
            reject_bundle(format!("client registration nonce is invalid: {error}"))
        })?;
        verify_client_registration_bundle_signature(&request.bundle).map_err(|error| {
            reject_bundle(format!(
                "client registration ownership proof is invalid: {error}"
            ))
        })?;

        let sponsor_signature = request.request_signature.as_ref().ok_or_else(|| {
            ControlPlaneError::NodeSignatureRequired(request.sponsor_node_id.clone())
        })?;
        let sponsor = self
            .store
            .get_node(&request.sponsor_node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(request.sponsor_node_id.clone()))?;
        if sponsor.role.is_client() {
            return Err(ControlPlaneError::NodeSignatureRejected {
                node_id: request.sponsor_node_id.clone(),
                reason: "client identities cannot sponsor another client".to_string(),
            });
        }
        verify_sponsored_client_registration_signature(&request, &sponsor.identity_public_key)
            .map_err(|error| ControlPlaneError::NodeSignatureRejected {
                node_id: request.sponsor_node_id.clone(),
                reason: error.to_string(),
            })?;
        self.accept_node_query_nonce(
            &request.sponsor_node_id,
            sponsor_signature.signed_at,
            &sponsor_signature.nonce,
            now,
        )
        .await?;

        self.require_client_gateway().await?;
        let claims = JoinTokenClaims {
            cluster_id: self.config.cluster_id.clone(),
            bootstrap_endpoints: Vec::new(),
            expires_at: request.bundle.expires_at,
            not_before: request.bundle.issued_at,
            role: Role::client(),
            tags: BTreeSet::new(),
            issuer: request.sponsor_node_id,
            key_id: KeyId::from_string("ssh-client-registration"),
            policy: TokenPolicy::default(),
            nonce: request.bundle.nonce,
        };
        self.register_client_with_claims(claims, request.bundle.registration)
            .await
    }

    async fn register_participant_with_claims(
        &self,
        claims: JoinTokenClaims,
        request: RegisterNodeRequest,
    ) -> Result<RegisterNodeResponse, ControlPlaneError> {
        if !claims.policy.allow_join {
            return Err(ControlPlaneError::JoinDenied);
        }
        let now = Utc::now();
        let nat_classification = request.nat_classification.clone();
        validate_registration_request(&request, now, self.config.heartbeat_signature_max_age)?;
        for route in &request.requested_routes {
            if !route_allowed(route, &claims) {
                return Err(ControlPlaneError::RouteDenied(route.id.clone()));
            }
        }

        let relay_capability =
            relay_capability_allowed(&request.node_id, request.relay_capability.clone(), &claims)?;
        let mut node = None;
        let mut last_conflict = None;
        for _ in 0..MAX_ROUTE_CATALOG_UPDATE_RETRIES {
            let (cluster_policy, persisted_cluster_policy) =
                self.current_cluster_policy_state().await?;
            validate_routes_within_overlay_scopes(&request.requested_routes, &cluster_policy)
                .map_err(|reason| ControlPlaneError::NodeRegistrationRejected {
                    node_id: request.node_id.clone(),
                    reason,
                })?;
            let expected_route_catalog_epoch = if request.requested_routes.is_empty() {
                None
            } else {
                let (violation, expected_epoch) = self
                    .overlay_route_catalog_update_validation(
                        &request.node_id,
                        &request.requested_routes,
                        &cluster_policy,
                    )
                    .await?;
                if let Some(reason) = violation {
                    return Err(ControlPlaneError::NodeRegistrationRejected {
                        node_id: request.node_id.clone(),
                        reason,
                    });
                }
                expected_epoch
            };

            let registration = match self
                .insert_node_with_fresh_vpn_ip(
                    claims.clone(),
                    request.clone(),
                    relay_capability.clone(),
                    now,
                    persisted_cluster_policy.clone(),
                    expected_route_catalog_epoch,
                )
                .await
            {
                Ok(node) => Ok(node),
                Err(ControlPlaneError::NodeAlreadyExists(_)) => {
                    self.rejoin_existing_node(
                        claims.clone(),
                        request.clone(),
                        relay_capability.clone(),
                        persisted_cluster_policy,
                        expected_route_catalog_epoch,
                    )
                    .await
                }
                Err(error) => Err(error),
            };
            match registration {
                Ok(registered) => {
                    node = Some(registered);
                    break;
                }
                Err(
                    error @ (ControlPlaneError::ClusterPolicyChanged
                    | ControlPlaneError::OverlayRouteCatalogChanged
                    | ControlPlaneError::NodeStateChanged(_)),
                ) => last_conflict = Some(error),
                Err(error) => return Err(error),
            }
        }
        let node = node.ok_or_else(|| {
            last_conflict.unwrap_or(ControlPlaneError::OverlayRouteCatalogChanged)
        })?;
        if let Some(classification) = nat_classification {
            self.store
                .upsert_nat_classification(node.node_id.clone(), classification)
                .await?;
        }
        self.invalidate_overlay_node_snapshot().await;
        self.registration_response_for_node(node, now).await
    }

    async fn registration_response_for_node(
        &self,
        node: NodeRecord,
        now: chrono::DateTime<Utc>,
    ) -> Result<RegisterNodeResponse, ControlPlaneError> {
        let peers = self.store.list_nodes().await?;
        let health_by_node = self.health_by_node(&peers).await?;
        let client_gateway_selections = self.store.list_client_gateway_selections().await?;
        let policy = self.current_cluster_policy().await?;
        let directory = self.service_directory_at(now).await?;
        let peer_map = self.filtered_peer_map_for_node(
            &node,
            &peers,
            ClientGatewayRoutingState {
                health_by_node: &health_by_node,
                selections: &client_gateway_selections,
            },
            &policy,
            directory.bootstrap_endpoints,
            now,
        );
        let relay_map =
            self.filtered_relay_map_for_node(&node, &peers, &health_by_node, &policy, now);

        Ok(RegisterNodeResponse {
            node,
            peer_map,
            relay_map,
            cluster_policy: policy,
        })
    }

    async fn rejoin_existing_node(
        &self,
        claims: JoinTokenClaims,
        request: RegisterNodeRequest,
        relay_capability: Option<RelayCapability>,
        expected_cluster_policy: Option<ClusterPolicy>,
        expected_route_catalog_epoch: Option<u64>,
    ) -> Result<NodeRecord, ControlPlaneError> {
        let existing = self
            .store
            .get_node(&request.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(request.node_id.clone()))?;
        if existing.cluster_id != claims.cluster_id
            || existing.identity_public_key != request.identity_public_key
            || existing.wireguard_public_key != request.wireguard_public_key
            || existing.role != claims.role
            || existing.tags != claims.tags
        {
            return Err(ControlPlaneError::NodeAlreadyExists(request.node_id));
        }

        self.store
            .rejoin_node_if_cluster_policy(RejoinNodeStoreUpdate {
                cluster_id: claims.cluster_id,
                expected_cluster_policy,
                expected_route_catalog_epoch,
                expected_node: existing,
                candidates: request.candidates,
                relay_capability,
                routes: request.requested_routes,
            })
            .await
    }

    async fn insert_node_with_fresh_vpn_ip(
        &self,
        claims: JoinTokenClaims,
        request: RegisterNodeRequest,
        relay_capability: Option<RelayCapability>,
        registered_at: chrono::DateTime<Utc>,
        expected_cluster_policy: Option<ClusterPolicy>,
        expected_route_catalog_epoch: Option<u64>,
    ) -> Result<NodeRecord, ControlPlaneError> {
        loop {
            let existing_nodes = self.store.list_nodes().await?;
            let reserved_vpn_ips = assigned_ipv4_vpn_ips(&existing_nodes);
            let vpn_ip = self
                .allocator
                .write()
                .await
                .allocate_next(&reserved_vpn_ips)?;
            let node = NodeRecord {
                node_id: request.node_id.clone(),
                hostname: None,
                cluster_id: claims.cluster_id.clone(),
                vpn_ip,
                identity_public_key: request.identity_public_key.clone(),
                wireguard_public_key: request.wireguard_public_key.clone(),
                role: claims.role.clone(),
                tags: claims.tags.clone(),
                endpoint_candidates: request.candidates.clone(),
                relay_capability: relay_capability.clone(),
                token_policy: claims.policy.clone(),
                routes: request.requested_routes.clone(),
                registered_at,
            };

            match self
                .store
                .insert_node_if_cluster_policy(
                    node.clone(),
                    expected_cluster_policy.clone(),
                    expected_route_catalog_epoch,
                )
                .await
            {
                Ok(()) => return Ok(node),
                Err(ControlPlaneError::VpnIpAlreadyAllocated(_)) => continue,
                Err(error) => return Err(error),
            }
        }
    }

    pub async fn authenticate_node_query(
        &self,
        request: &ControlPlaneNodeQueryRequest,
        kind: ControlPlaneNodeQueryKind,
        now: chrono::DateTime<Utc>,
    ) -> Result<NodeRecord, ControlPlaneError> {
        let signature = request
            .request_signature
            .as_ref()
            .ok_or_else(|| ControlPlaneError::NodeSignatureRequired(request.node_id.clone()))?;
        let node = self
            .store
            .get_node(&request.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(request.node_id.clone()))?;
        if node.role.is_client() {
            return Err(ControlPlaneError::NodeSignatureRejected {
                node_id: request.node_id.clone(),
                reason: "client identities must use the client control API".to_string(),
            });
        }
        verify_control_plane_node_query_signature(request, kind, &node.identity_public_key)
            .map_err(|error| ControlPlaneError::NodeSignatureRejected {
                node_id: request.node_id.clone(),
                reason: error.to_string(),
            })?;
        if !timestamp_within_skew(
            signature.signed_at,
            now,
            self.config.heartbeat_signature_max_age,
        ) {
            return Err(ControlPlaneError::NodeSignatureRejected {
                node_id: request.node_id.clone(),
                reason: format!(
                    "signed_at {} is outside the allowed {}s window",
                    signature.signed_at,
                    self.config.heartbeat_signature_max_age.as_secs()
                ),
            });
        }

        self.accept_node_query_nonce(&request.node_id, signature.signed_at, &signature.nonce, now)
            .await?;
        Ok(node)
    }

    pub async fn authenticate_overlay_path_query(
        &self,
        request: &OverlayPathQuery,
        now: chrono::DateTime<Utc>,
    ) -> Result<NodeRecord, ControlPlaneError> {
        request
            .validate()
            .map_err(|error| ControlPlaneError::NodeSignatureRejected {
                node_id: request.source.clone(),
                reason: error.to_string(),
            })?;
        let node = self
            .store
            .get_node(&request.source)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(request.source.clone()))?;
        if node.role.is_client() {
            return Err(ControlPlaneError::NodeSignatureRejected {
                node_id: request.source.clone(),
                reason: "client identities must use the client control API".to_string(),
            });
        }
        verify_overlay_path_query_signature(request, &node.identity_public_key).map_err(
            |error| ControlPlaneError::NodeSignatureRejected {
                node_id: request.source.clone(),
                reason: error.to_string(),
            },
        )?;
        self.accept_node_query_nonce(
            &request.source,
            request.source_identity_proof.signed_at,
            &request.source_identity_proof.nonce,
            now,
        )
        .await?;
        Ok(node)
    }

    async fn accept_node_query_nonce(
        &self,
        node_id: &NodeId,
        signed_at: chrono::DateTime<Utc>,
        nonce: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<(), ControlPlaneError> {
        if !timestamp_within_skew(signed_at, now, self.config.heartbeat_signature_max_age) {
            return Err(ControlPlaneError::NodeSignatureRejected {
                node_id: node_id.clone(),
                reason: format!(
                    "signed_at {signed_at} is outside the allowed {}s window",
                    self.config.heartbeat_signature_max_age.as_secs()
                ),
            });
        }

        let key = (node_id.clone(), nonce.to_string());
        let mut accepted = self.accepted_node_query_nonces.lock().await;
        accepted.retain(|_, accepted_at| {
            now.signed_duration_since(*accepted_at)
                .to_std()
                .map_or(true, |age| age <= self.config.heartbeat_signature_max_age)
        });
        if accepted.contains_key(&key) {
            return Err(ControlPlaneError::NodeRequestReplay(node_id.clone()));
        }
        if accepted.len() >= MAX_ACCEPTED_NODE_QUERY_NONCES {
            return Err(ControlPlaneError::NodeRequestAuthenticationCapacity);
        }
        accepted.insert(key, now);
        Ok(())
    }

    pub async fn authenticate_client_request(
        &self,
        request: &ClientControlRequest,
        kind: ClientRequestKind,
        now: chrono::DateTime<Utc>,
    ) -> Result<NodeRecord, ControlPlaneError> {
        if kind == ClientRequestKind::Remove && request.active_gateway_node_id.is_some() {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: request.client_id.clone(),
                reason: "client removal must not select an active gateway".to_string(),
            });
        }
        let signature = request
            .request_signature
            .as_ref()
            .ok_or_else(|| ControlPlaneError::NodeSignatureRequired(request.client_id.clone()))?;
        let client = self
            .store
            .get_node(&request.client_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(request.client_id.clone()))?;
        if !client.role.is_client() {
            return Err(ControlPlaneError::NodeSignatureRejected {
                node_id: request.client_id.clone(),
                reason: "node identities cannot use the client control API".to_string(),
            });
        }
        verify_client_control_request_signature(request, kind, &client.identity_public_key)
            .map_err(|error| ControlPlaneError::NodeSignatureRejected {
                node_id: request.client_id.clone(),
                reason: error.to_string(),
            })?;
        if !timestamp_within_skew(
            signature.signed_at,
            now,
            self.config.heartbeat_signature_max_age,
        ) {
            return Err(ControlPlaneError::NodeSignatureRejected {
                node_id: request.client_id.clone(),
                reason: format!(
                    "signed_at {} is outside the allowed {}s window",
                    signature.signed_at,
                    self.config.heartbeat_signature_max_age.as_secs()
                ),
            });
        }

        let key = (request.client_id.clone(), signature.nonce.clone());
        let mut accepted = self.accepted_node_query_nonces.lock().await;
        accepted.retain(|_, accepted_at| {
            now.signed_duration_since(*accepted_at)
                .to_std()
                .map_or(true, |age| age <= self.config.heartbeat_signature_max_age)
        });
        if accepted.contains_key(&key) {
            return Err(ControlPlaneError::NodeRequestReplay(
                request.client_id.clone(),
            ));
        }
        if accepted.len() >= MAX_ACCEPTED_NODE_QUERY_NONCES {
            return Err(ControlPlaneError::NodeRequestAuthenticationCapacity);
        }
        accepted.insert(key, now);
        Ok(client)
    }

    pub async fn update_client_gateway_selection(
        &self,
        client: &NodeRecord,
        requested_gateway: Option<&NodeId>,
        now: chrono::DateTime<Utc>,
    ) -> Result<(), ControlPlaneError> {
        let peers = self.store.list_nodes().await?;
        let health_by_node = self.health_by_node(&peers).await?;
        let policy = self.current_cluster_policy().await?;
        let visible_nodes = peers
            .iter()
            .filter(|peer| peer.node_id != client.node_id && !peer.role.is_client())
            .filter_map(|peer| acl_filter_peer(client, peer, &policy))
            .collect::<Vec<_>>();
        let gateways = select_client_gateways(&visible_nodes, &health_by_node, now, &policy);
        let desired_gateway = requested_gateway
            .filter(|requested| {
                gateways
                    .iter()
                    .any(|gateway| &gateway.node_id == *requested)
            })
            .cloned()
            .or_else(|| gateways.first().map(|gateway| gateway.node_id.clone()));
        let previous = self
            .store
            .list_client_gateway_selections()
            .await?
            .remove(&client.node_id);
        let changed = match desired_gateway {
            Some(gateway_node_id)
                if previous
                    .as_ref()
                    .map(|selection| &selection.gateway_node_id)
                    != Some(&gateway_node_id) =>
            {
                self.store
                    .upsert_client_gateway_selection(ClientGatewaySelection {
                        client_id: client.node_id.clone(),
                        gateway_node_id,
                        selected_at: now,
                    })
                    .await?;
                true
            }
            Some(_) => false,
            None if previous.is_some() => {
                self.store
                    .remove_client_gateway_selection(&client.node_id)
                    .await?;
                true
            }
            None => false,
        };
        if changed {
            self.notify_all_connection_intent_waiters().await;
        }
        Ok(())
    }

    pub async fn peer_map_for(&self, node_id: &NodeId) -> Result<PeerMap, ControlPlaneError> {
        let source = self
            .store
            .get_node(node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        let peers = self
            .store
            .list_nodes()
            .await?
            .into_iter()
            .collect::<Vec<_>>();

        let policy = self.current_cluster_policy().await?;
        let now = Utc::now();
        let health_by_node = self.health_by_node(&peers).await?;
        let client_gateway_selections = self.store.list_client_gateway_selections().await?;
        let directory = self.service_directory_at(now).await?;
        Ok(self.filtered_peer_map_for_node(
            &source,
            &peers,
            ClientGatewayRoutingState {
                health_by_node: &health_by_node,
                selections: &client_gateway_selections,
            },
            &policy,
            directory.bootstrap_endpoints,
            now,
        ))
    }

    pub async fn neighbor_map_for(
        &self,
        node_id: &NodeId,
    ) -> Result<NeighborMap, ControlPlaneError> {
        let (policy, snapshot) = self.current_overlay_snapshot().await?;
        let now = Utc::now();
        let source = snapshot
            .nodes_by_id
            .get(node_id)
            .and_then(|index| snapshot.nodes.get(*index))
            .cloned()
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        if source.role.is_client() {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: node_id.clone(),
                reason: "clients cannot join the bounded overlay backbone".to_string(),
            });
        }

        let aggregate_routes = if policy.overlay_route_scopes.is_empty() {
            snapshot.aggregate_routes.clone()
        } else {
            policy
                .overlay_route_scopes
                .iter()
                .copied()
                .map(|cidr| AggregateOverlayRoute { cidr })
                .collect()
        };
        if aggregate_routes.len() > MAX_OVERLAY_ROUTE_SCOPES {
            return Err(ControlPlaneError::BoundedTopology(format!(
                "exact aggregate overlay route count {} exceeds the neighbor-map limit {}; configure route scopes instead of widening advertised networks",
                aggregate_routes.len(),
                MAX_OVERLAY_ROUTE_SCOPES
            )));
        }
        let topology = self
            .overlay_topology_for_snapshot(&snapshot, &policy)
            .await?;
        let neighbor_ids = topology.neighbors(node_id).ok_or_else(|| {
            ControlPlaneError::BoundedTopology(format!(
                "source node {node_id} is absent from topology"
            ))
        })?;
        let primary_neighbor_count = neighbor_ids.len().div_ceil(2);
        let neighbors = neighbor_ids
            .iter()
            .enumerate()
            .filter_map(|(index, neighbor_id)| {
                snapshot
                    .nodes_by_id
                    .get(neighbor_id)
                    .and_then(|index| snapshot.nodes.get(*index))
                    .map(|neighbor| {
                        let mut node =
                            filter_served_endpoint_candidates(neighbor.clone(), now, &policy);
                        // Backbone membership authorizes the peer's VPN host route only.
                        // Advertised routes are issued lazily by overlay_path_for after
                        // destination-specific ACL evaluation.
                        node.routes.clear();
                        OverlayNeighbor {
                            node,
                            kind: if index < primary_neighbor_count {
                                OverlayNeighborKind::BackbonePrimary
                            } else {
                                OverlayNeighborKind::BackboneSecondary
                            },
                        }
                    })
            })
            .collect::<Vec<_>>();
        let client_route_peers = if snapshot.clients.is_empty() {
            Vec::new()
        } else {
            let client_gateway_selections = self.store.list_client_gateway_selections().await?;
            node_client_route_projection(
                &source,
                &snapshot.nodes,
                &snapshot.clients,
                &snapshot.health_by_node,
                &client_gateway_selections,
                &policy,
                now,
            )
        };
        let directory = self.service_directory_at(now).await?;
        let response = NeighborMap {
            cluster_id: self.config.cluster_id.clone(),
            node_id: source.node_id,
            topology_epoch: topology.topology_epoch(),
            routing_epoch: snapshot.routing_epoch,
            max_degree: policy.overlay_max_degree,
            on_demand_peer_limit: policy.overlay_on_demand_peer_limit,
            vpn_cidr: IpNet::V4(self.config.vpn_pool),
            neighbors,
            aggregate_routes,
            client_route_peers,
            bootstrap_endpoints: directory.bootstrap_endpoints,
            generated_at: snapshot.generated_at,
        };
        response
            .validate()
            .map_err(|error| ControlPlaneError::BoundedTopology(error.to_string()))?;
        Ok(response)
    }

    pub async fn overlay_topology_snapshot(
        &self,
    ) -> Result<ControlPlaneTopologyResponse, ControlPlaneError> {
        let generated_at = Utc::now();
        let (policy, snapshot) = self.current_overlay_snapshot().await?;
        let mut nodes = snapshot.nodes.clone();
        nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let topology = self
            .overlay_topology_for_snapshot(&snapshot, &policy)
            .await?;
        let health_by_node = &snapshot.health_by_node;
        let observed_path_pairs = topology
            .edge_placements()
            .keys()
            .flat_map(|edge| {
                [
                    (edge.first().clone(), edge.second().clone()),
                    (edge.second().clone(), edge.first().clone()),
                ]
            })
            .collect::<BTreeSet<_>>();
        let observed_paths = self
            .store
            .list_paths_for_pairs(&observed_path_pairs)
            .await?;
        let mut paths_by_edge = BTreeMap::<TopologyEdge, Vec<&PathRecord>>::new();
        for path in &observed_paths {
            if let Some(edge) = TopologyEdge::new(path.key.local.clone(), path.key.remote.clone()) {
                paths_by_edge.entry(edge).or_default().push(path);
            }
        }
        let groups_by_id = topology
            .groups()
            .iter()
            .map(|group| (group.group_id().to_string(), group))
            .collect::<BTreeMap<_, _>>();
        let leaf_group_by_node = topology
            .groups()
            .iter()
            .filter(|group| group.is_leaf())
            .flat_map(|group| {
                group
                    .node_ids()
                    .iter()
                    .cloned()
                    .map(|node_id| (node_id, group.group_id().to_string()))
            })
            .collect::<BTreeMap<_, _>>();
        let mut representative_assignments =
            BTreeMap::<NodeId, Vec<ControlPlaneTopologyRepresentativeAssignment>>::new();
        for group in topology.groups() {
            for representative in group.representatives() {
                representative_assignments
                    .entry(representative.node_id().clone())
                    .or_default()
                    .push(ControlPlaneTopologyRepresentativeAssignment {
                        group_id: group.group_id().to_string(),
                        depth: group.depth(),
                        plane: u8::try_from(representative.plane()).map_err(|_| {
                            ControlPlaneError::BoundedTopology(
                                "representative plane exceeds u8".to_string(),
                            )
                        })?,
                    });
            }
        }
        for assignments in representative_assignments.values_mut() {
            assignments.sort_by(|left, right| {
                left.depth
                    .cmp(&right.depth)
                    .then_with(|| left.group_id.cmp(&right.group_id))
                    .then_with(|| left.plane.cmp(&right.plane))
            });
        }

        let mut edges = Vec::with_capacity(topology.edge_placements().len());
        for (edge, topology_placements) in topology.edge_placements() {
            let (observed_status, path_states, last_observed_at) = topology_edge_observation(
                paths_by_edge.get(edge).map(Vec::as_slice).unwrap_or(&[]),
                generated_at,
                policy.path_state_ttl_seconds,
            );
            let placements = topology_placements
                .iter()
                .map(|placement| {
                    Ok(ControlPlaneTopologyEdgePlacement {
                        group_id: placement.group_id().to_string(),
                        depth: placement.level(),
                        plane: u8::try_from(placement.plane()).map_err(|_| {
                            ControlPlaneError::BoundedTopology("edge plane exceeds u8".to_string())
                        })?,
                        kind: match placement.kind() {
                            BoundedTopologyEdgeKind::LeafCycle => {
                                ControlPlaneTopologyEdgeKind::LeafCycle
                            }
                            BoundedTopologyEdgeKind::HierarchyLink => {
                                ControlPlaneTopologyEdgeKind::SiblingCycle
                            }
                        },
                    })
                })
                .collect::<Result<Vec<_>, ControlPlaneError>>()?;
            edges.push(ControlPlaneTopologyEdge {
                source: edge.first().clone(),
                target: edge.second().clone(),
                placements,
                observed_status,
                path_states,
                last_observed_at,
            });
        }

        let groups = topology
            .groups()
            .iter()
            .map(|group| {
                let representatives = group
                    .representatives()
                    .iter()
                    .map(|representative| {
                        Ok(ControlPlaneTopologyRepresentative {
                            node_id: representative.node_id().clone(),
                            plane: u8::try_from(representative.plane()).map_err(|_| {
                                ControlPlaneError::BoundedTopology(
                                    "representative plane exceeds u8".to_string(),
                                )
                            })?,
                            role: if representative.plane() == 0 {
                                "primary".to_string()
                            } else {
                                "secondary".to_string()
                            },
                        })
                    })
                    .collect::<Result<Vec<_>, ControlPlaneError>>()?;
                Ok(ControlPlaneTopologyGroup {
                    group_id: group.group_id().to_string(),
                    depth: group.depth(),
                    parent_group_id: group.parent_group_id().map(str::to_string),
                    child_group_ids: group.child_group_ids().to_vec(),
                    node_ids: group.node_ids().to_vec(),
                    leaf: group.is_leaf(),
                    representatives,
                })
            })
            .collect::<Result<Vec<_>, ControlPlaneError>>()?;

        let topology_nodes = nodes
            .into_iter()
            .map(|node| {
                let leaf_group_id =
                    leaf_group_by_node
                        .get(&node.node_id)
                        .cloned()
                        .ok_or_else(|| {
                            ControlPlaneError::BoundedTopology(format!(
                                "node {} has no topology leaf group",
                                node.node_id
                            ))
                        })?;
                let mut ancestry = Vec::new();
                let mut group_id = Some(leaf_group_id.clone());
                while let Some(current_group_id) = group_id {
                    let group = groups_by_id.get(&current_group_id).ok_or_else(|| {
                        ControlPlaneError::BoundedTopology(format!(
                            "topology group {current_group_id} is absent"
                        ))
                    })?;
                    ancestry.push(current_group_id);
                    group_id = group.parent_group_id().map(str::to_string);
                }
                ancestry.reverse();
                let degree = topology
                    .neighbors(&node.node_id)
                    .map(BTreeSet::len)
                    .unwrap_or(0);
                let health = health_by_node.get(&node.node_id);
                let health_state = if overlay_node_health_allows(
                    &node,
                    health,
                    generated_at,
                    policy.relay_health_ttl_seconds,
                ) {
                    health.map(|health| health.state)
                } else {
                    Some(HealthState::Unhealthy)
                };
                let representative_for = representative_assignments
                    .remove(&node.node_id)
                    .unwrap_or_default();
                Ok(ControlPlaneTopologyNode {
                    node_id: node.node_id,
                    hostname: node.hostname,
                    vpn_ip: node.vpn_ip,
                    role: node.role,
                    tags: node.tags,
                    leaf_group_id,
                    ancestry,
                    degree,
                    health_state,
                    last_seen_at: health.map(|health| health.last_seen_at),
                    representative_for,
                })
            })
            .collect::<Result<Vec<_>, ControlPlaneError>>()?;
        let root_group_id = topology
            .groups()
            .iter()
            .find(|group| group.parent_group_id().is_none())
            .map(|group| group.group_id().to_string());
        let level_count = topology
            .groups()
            .iter()
            .map(|group| group.depth() + 1)
            .max()
            .unwrap_or(0);

        Ok(ControlPlaneTopologyResponse {
            cluster_id: self.config.cluster_id.clone(),
            topology_epoch: topology.topology_epoch().to_string(),
            algorithm: TOPOLOGY_ALGORITHM_VERSION.to_string(),
            root_group_id,
            fanout: policy.overlay_block_size,
            max_degree: policy.overlay_max_degree,
            direct_shortcut_limit: 0,
            on_demand_peer_limit: policy.overlay_on_demand_peer_limit,
            node_count: topology.invariants().node_count,
            group_count: groups.len(),
            level_count,
            edge_count: topology.invariants().edge_count,
            max_observed_degree: topology.invariants().max_observed_degree,
            diameter_lower_bound: topology.diameter_lower_bound(),
            groups,
            nodes: topology_nodes,
            edges,
            generated_at,
        })
    }

    pub async fn overlay_path_for(
        &self,
        request: &OverlayPathQuery,
    ) -> Result<OverlayPath, ControlPlaneError> {
        let (policy, snapshot) = self.current_overlay_snapshot().await?;
        let now = Utc::now();
        let source = snapshot
            .active_nodes_by_id
            .get(&request.source)
            .and_then(|index| snapshot.active_nodes.get(*index))
            .ok_or_else(|| ControlPlaneError::NodeNotFound(request.source.clone()))?;
        let target = snapshot
            .route_index
            .resolve_destination(
                source,
                &snapshot.active_nodes,
                &snapshot.active_nodes_by_id,
                request.destination,
                &policy,
            )
            .ok_or(ControlPlaneError::OverlayDestinationNotFound(
                request.destination,
            ))?;
        let topology = self
            .overlay_topology_for_snapshot(&snapshot, &policy)
            .await?;
        let unavailable_nodes = snapshot
            .nodes
            .iter()
            .filter(|node| !snapshot.active_nodes_by_id.contains_key(&node.node_id))
            .map(|node| node.node_id.clone())
            .collect::<BTreeSet<_>>();
        let paths = topology
            .paths_avoiding(&source.node_id, &target.node_id, &unavailable_nodes)
            .ok_or_else(|| ControlPlaneError::OverlayPathUnavailable {
                source_node: source.node_id.clone(),
                destination_node: target.node_id.clone(),
            })?;
        let response = OverlayPath {
            topology_epoch: topology.topology_epoch(),
            routing_epoch: snapshot.routing_epoch,
            source: source.node_id.clone(),
            destination: request.destination,
            target: filter_served_endpoint_candidates(target, now, &policy),
            ordered_nodes: paths.primary,
            secondary_ordered_nodes: paths.secondary.map(|path| path.nodes),
            generated_at: snapshot.generated_at,
        };
        response
            .validate()
            .map_err(|error| ControlPlaneError::BoundedTopology(error.to_string()))?;
        Ok(response)
    }

    #[cfg(test)]
    async fn overlay_nodes(&self) -> Result<Vec<NodeRecord>, ControlPlaneError> {
        let (_, snapshot) = self.current_overlay_snapshot().await?;
        Ok(snapshot.active_nodes.clone())
    }

    async fn overlay_node_snapshot(
        &self,
        policy: &ClusterPolicy,
        routing_epoch: u64,
    ) -> Result<Arc<OverlayNodeSnapshot>, ControlPlaneError> {
        let mut cached = self.overlay_node_snapshot_cache.lock().await;
        if let Some(snapshot) = cached
            .as_ref()
            .filter(|snapshot| {
                snapshot.loaded_at.elapsed() <= OVERLAY_NODE_SNAPSHOT_CACHE_TTL
                    && snapshot.health_ttl_seconds == policy.relay_health_ttl_seconds
                    && snapshot.topology_cache_key.block_size == policy.overlay_block_size
                    && snapshot.topology_cache_key.max_degree == policy.overlay_max_degree
                    && snapshot.routing_epoch == routing_epoch
            })
            .map(Arc::clone)
        {
            drop(cached);
            if self
                .store
                .get_overlay_routing_epoch(&self.config.cluster_id)
                .await?
                != routing_epoch
            {
                return Err(ControlPlaneError::OverlayRouteCatalogChanged);
            }
            return Ok(snapshot);
        }

        let (nodes, mut health_by_node) = self.store.list_nodes_and_health().await?;
        let loaded_at = Instant::now();
        let generated_at = Utc::now();
        let (nodes, clients) = nodes
            .into_iter()
            .filter(|node| node.cluster_id == self.config.cluster_id)
            .partition::<Vec<_>, _>(|node| !node.role.is_client());
        let nodes_by_id = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.node_id.clone(), index))
            .collect::<BTreeMap<_, _>>();
        let node_ids = nodes
            .iter()
            .map(|node| node.node_id.clone())
            .collect::<BTreeSet<_>>();
        health_by_node.retain(|node_id, _| node_ids.contains(node_id));
        let active_nodes = nodes
            .iter()
            .filter(|node| {
                overlay_node_health_allows(
                    node,
                    health_by_node.get(&node.node_id),
                    generated_at,
                    policy.relay_health_ttl_seconds,
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let active_nodes_by_id = active_nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.node_id.clone(), index))
            .collect::<BTreeMap<_, _>>();
        let membership_epoch = overlay_membership_epoch(nodes_by_id.keys().map(NodeId::as_str));
        let topology_cache_key = Arc::new(OverlayTopologyCacheKey {
            membership_epoch,
            node_count: nodes.len(),
            block_size: policy.overlay_block_size,
            max_degree: policy.overlay_max_degree,
            permutation_seed: self.config.cluster_id.as_str().to_string(),
        });
        let aggregate_routes = aggregate_overlay_routes(&nodes);
        let route_index = OverlayRouteIndex::build(&nodes);
        if self
            .store
            .get_overlay_routing_epoch(&self.config.cluster_id)
            .await?
            != routing_epoch
        {
            return Err(ControlPlaneError::OverlayRouteCatalogChanged);
        }
        let snapshot = Arc::new(OverlayNodeSnapshot {
            loaded_at,
            generated_at,
            nodes,
            nodes_by_id,
            clients,
            health_by_node,
            active_nodes,
            active_nodes_by_id,
            health_ttl_seconds: policy.relay_health_ttl_seconds,
            topology_cache_key,
            aggregate_routes,
            route_index,
            routing_epoch,
        });
        *cached = Some(Arc::clone(&snapshot));
        Ok(snapshot)
    }

    async fn invalidate_overlay_node_snapshot(&self) {
        self.overlay_node_snapshot_cache.lock().await.take();
    }

    async fn overlay_topology_for_snapshot(
        &self,
        snapshot: &Arc<OverlayNodeSnapshot>,
        policy: &ClusterPolicy,
    ) -> Result<Arc<BoundedTopology>, ControlPlaneError> {
        self.overlay_topology_cached(
            Arc::clone(&snapshot.topology_cache_key),
            policy,
            OverlayTopologyNodeSource::Snapshot(Arc::clone(snapshot)),
        )
        .await
    }

    #[cfg(test)]
    async fn overlay_topology(
        &self,
        nodes: &[NodeRecord],
        policy: &ClusterPolicy,
    ) -> Result<Arc<BoundedTopology>, ControlPlaneError> {
        let mut node_ids = nodes
            .iter()
            .map(|node| node.node_id.as_str())
            .collect::<Vec<_>>();
        node_ids.sort();
        self.overlay_topology_cached(
            Arc::new(OverlayTopologyCacheKey {
                membership_epoch: overlay_membership_epoch(node_ids),
                node_count: nodes.len(),
                block_size: policy.overlay_block_size,
                max_degree: policy.overlay_max_degree,
                permutation_seed: self.config.cluster_id.as_str().to_string(),
            }),
            policy,
            OverlayTopologyNodeSource::Owned(Arc::new(nodes.to_vec())),
        )
        .await
    }

    async fn overlay_topology_cached(
        &self,
        key: Arc<OverlayTopologyCacheKey>,
        policy: &ClusterPolicy,
        nodes: OverlayTopologyNodeSource,
    ) -> Result<Arc<BoundedTopology>, ControlPlaneError> {
        let cell = {
            let mut cache = self.overlay_topology_cache.lock().await;
            cache.retain(|cached_key, cell| cached_key == key.as_ref() || cell.initialized());
            while cache.len() >= MAX_OVERLAY_TOPOLOGY_CACHE_ENTRIES
                && !cache.contains_key(key.as_ref())
            {
                let Some(evicted_key) = cache.keys().next().cloned() else {
                    break;
                };
                cache.remove(&evicted_key);
            }
            while cache.len() > MAX_OVERLAY_TOPOLOGY_CACHE_ENTRIES {
                let Some(evicted_key) = cache
                    .keys()
                    .find(|cached_key| *cached_key != key.as_ref())
                    .cloned()
                else {
                    break;
                };
                cache.remove(&evicted_key);
            }
            if let Some(cell) = cache.get(key.as_ref()) {
                Arc::clone(cell)
            } else {
                let cell = Arc::new(OnceCell::new());
                cache.insert((*key).clone(), Arc::clone(&cell));
                cell
            }
        };
        let config = BoundedTopologyConfig::new(usize::from(policy.overlay_max_degree))
            .with_block_size(usize::from(policy.overlay_block_size))
            .with_permutation_seed(self.config.cluster_id.as_str());
        let topology = cell
            .get_or_init(|| async move {
                match tokio::task::spawn_blocking(move || {
                    BoundedTopology::synthesize(nodes.nodes(), &config)
                })
                .await
                {
                    Ok(Ok(topology)) => Ok(Arc::new(topology)),
                    Ok(Err(error)) => Err(error.to_string()),
                    Err(error) => Err(format!("topology synthesis task failed: {error}")),
                }
            })
            .await;
        topology
            .as_ref()
            .map(Arc::clone)
            .map_err(|error| ControlPlaneError::BoundedTopology(error.clone()))
    }

    pub async fn remove_client(
        &self,
        request: ClientControlRequest,
    ) -> Result<RemoveClientResponse, ControlPlaneError> {
        self.authenticate_client_request(&request, ClientRequestKind::Remove, Utc::now())
            .await?;
        let removed = self.store.remove_node(&request.client_id).await?;
        self.invalidate_overlay_node_snapshot().await;
        *self.allocator.write().await = VpnAllocator::new(self.config.vpn_pool);
        Ok(RemoveClientResponse {
            client: removed.node,
            removed_at: Utc::now(),
        })
    }

    pub async fn remove_node(
        &self,
        request: RemoveNodeRequest,
    ) -> Result<RemoveNodeResponse, ControlPlaneError> {
        let result = self.remove_node_inner(request).await;
        self.operation_metrics.record_node_removal(result.is_ok());
        result
    }

    async fn remove_node_inner(
        &self,
        request: RemoveNodeRequest,
    ) -> Result<RemoveNodeResponse, ControlPlaneError> {
        let node = self
            .store
            .get_node(&request.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(request.node_id.clone()))?;
        if node.role.is_client() {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: request.node_id.clone(),
                reason: "client identities must use the client control API".to_string(),
            });
        }
        self.validate_remove_node_request(&request, &node, Utc::now())?;
        let removed = self.store.remove_node(&request.node_id).await?;
        self.invalidate_overlay_node_snapshot().await;
        *self.allocator.write().await = VpnAllocator::new(self.config.vpn_pool);
        Ok(RemoveNodeResponse {
            node: removed.node,
            removed_path_count: removed.removed_path_count,
            removed_health: removed.removed_health,
            removed_at: Utc::now(),
        })
    }

    fn validate_remove_node_request(
        &self,
        request: &RemoveNodeRequest,
        node: &NodeRecord,
        now: chrono::DateTime<Utc>,
    ) -> Result<(), ControlPlaneError> {
        if request.node_signature.is_none() {
            return Err(ControlPlaneError::NodeSignatureRequired(
                request.node_id.clone(),
            ));
        }
        verify_remove_node_signature(request, &node.identity_public_key).map_err(|error| {
            ControlPlaneError::NodeSignatureRejected {
                node_id: request.node_id.clone(),
                reason: error.to_string(),
            }
        })?;
        let Some(signature) = request.node_signature.as_ref() else {
            return Err(ControlPlaneError::NodeSignatureRequired(
                request.node_id.clone(),
            ));
        };
        let signed_at = signature.signed_at;
        if !timestamp_within_skew(signed_at, now, self.config.heartbeat_signature_max_age) {
            return Err(ControlPlaneError::NodeSignatureRejected {
                node_id: request.node_id.clone(),
                reason: format!(
                    "signed_at {signed_at} is outside the allowed {}s window",
                    self.config.heartbeat_signature_max_age.as_secs()
                ),
            });
        }
        Ok(())
    }

    pub async fn paths_for(
        &self,
        node_id: &NodeId,
    ) -> Result<ControlPlanePathsResponse, ControlPlaneError> {
        let source = self
            .store
            .get_node(node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        if source.role.is_client() {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: node_id.clone(),
                reason: "clients cannot query node paths".to_string(),
            });
        }
        let peers = self.store.list_nodes().await?;
        let peers_by_id = peers
            .iter()
            .map(|peer| (peer.node_id.clone(), peer))
            .collect::<BTreeMap<_, _>>();
        let policy = self.current_cluster_policy().await?;
        let pins = self.admin_path_pins.read().await.clone();
        let now = Utc::now();
        let mut stale_path_count = 0;
        let paths = self
            .store
            .list_paths_for(node_id)
            .await?
            .into_iter()
            .filter_map(|mut path| {
                if let Some(pinned) = pins.get(&(path.key.local.clone(), path.key.remote.clone())) {
                    path.pinned = *pinned;
                }
                let peer_id = if path.key.local == source.node_id {
                    &path.key.remote
                } else if path.key.remote == source.node_id {
                    &path.key.local
                } else {
                    return None;
                };
                let visible = peers_by_id
                    .get(peer_id)
                    .is_some_and(|peer| acl_filter_peer(&source, peer, &policy).is_some());
                if !visible {
                    return None;
                }
                if path_is_fresh(&path, now, policy.path_state_ttl_seconds) {
                    Some(path)
                } else {
                    stale_path_count += 1;
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(ControlPlanePathsResponse {
            cluster_id: self.config.cluster_id.clone(),
            node_id: node_id.clone(),
            paths,
            stale_path_count,
            path_state_ttl_seconds: policy.path_state_ttl_seconds,
            generated_at: now,
        })
    }

    pub async fn authenticate_signal_node_upsert(
        &self,
        request: &SignalNodeUpsertRequest,
        now: chrono::DateTime<Utc>,
    ) -> Result<NodeRecord, ControlPlaneError> {
        let node = self
            .store
            .get_node(&request.node.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(request.node.node_id.clone()))?;
        if node.role.is_client() {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: request.node.node_id.clone(),
                reason: "clients cannot register with Signal".to_string(),
            });
        }
        let signature = request.request_signature.as_ref().ok_or_else(|| {
            ControlPlaneError::NodeSignatureRequired(request.node.node_id.clone())
        })?;
        verify_signal_node_upsert_signature(request, &node.identity_public_key).map_err(
            |error| ControlPlaneError::NodeSignatureRejected {
                node_id: request.node.node_id.clone(),
                reason: error.to_string(),
            },
        )?;
        if !timestamp_within_skew(
            signature.signed_at,
            now,
            self.config.heartbeat_signature_max_age,
        ) {
            return Err(ControlPlaneError::NodeSignatureRejected {
                node_id: request.node.node_id.clone(),
                reason: format!(
                    "signed_at {} is outside the allowed {}s window",
                    signature.signed_at,
                    self.config.heartbeat_signature_max_age.as_secs()
                ),
            });
        }
        Ok(node)
    }

    pub async fn heartbeat(
        &self,
        mut request: HeartbeatRequest,
    ) -> Result<HeartbeatResponse, ControlPlaneError> {
        let node = self
            .store
            .get_node(&request.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(request.node_id.clone()))?;
        if node.cluster_id != self.config.cluster_id {
            return Err(ControlPlaneError::NodeNotFound(request.node_id.clone()));
        }
        if node.role.is_client() {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: request.node_id.clone(),
                reason: "clients cannot submit node heartbeats".to_string(),
            });
        }
        let (policy, persisted_cluster_policy) = self.current_cluster_policy_state().await?;
        let previous_signature_at = self
            .store
            .get_heartbeat_signature_timestamp(&request.node_id)
            .await?;
        let now = Utc::now();
        self.validate_heartbeat_request(&request, &node, &policy, previous_signature_at, now)?;
        let heartbeat_service_instance =
            heartbeat_service_instance(&request, &node, &self.config.cluster_id, now)?;
        let route_catalog_update_requested = request
            .routes
            .as_ref()
            .is_some_and(|routes| routes != &node.routes);
        let expected_route_catalog_epoch = if route_catalog_update_requested {
            let (violation, expected_epoch) = self
                .overlay_route_catalog_update_validation(
                    &request.node_id,
                    request.routes.as_deref().unwrap_or_default(),
                    &policy,
                )
                .await?;
            if let Some(reason) = violation {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason,
                });
            }
            expected_epoch
        } else {
            request.routes = None;
            None
        };
        self.validate_heartbeat_path_relay_shape(&request)?;
        let path_node_ids = request
            .path_state
            .iter()
            .flat_map(|path| std::iter::once(&path.key.remote).chain(path.relay_node.as_ref()))
            .cloned()
            .collect::<BTreeSet<_>>();
        let path_nodes = if path_node_ids.is_empty() {
            None
        } else {
            Some(self.store.get_nodes_by_ids(&path_node_ids).await?)
        };
        if let Some(nodes) = path_nodes.as_ref() {
            self.validate_heartbeat_path_peers_visible(&request, &node, nodes, &policy)?;
            if request
                .path_state
                .iter()
                .any(|path| path.selected_state == PathState::Relay)
            {
                let health_by_node = self.health_by_node(nodes).await?;
                self.validate_heartbeat_path_relay_eligibility(
                    &request,
                    &node,
                    nodes,
                    &health_by_node,
                    now,
                    &policy,
                )?;
            }
        }
        {
            let pins = self.admin_path_pins.read().await;
            for path in &mut request.path_state {
                if let Some(pinned) = pins.get(&(path.key.local.clone(), path.key.remote.clone())) {
                    path.pinned = *pinned;
                }
            }
        }
        let accepted_signature_at = request
            .node_signature
            .as_ref()
            .map(|signature| signature.signed_at);
        request.health.last_seen_at = now;
        let idle_timeout_seconds = policy.idle_timeout_seconds;
        let connection_intent_targets = request
            .path_state
            .iter()
            .filter_map(|path| {
                let observed_at = lazy_connect_local_activity_at(path).ok().flatten()?;
                timestamp_is_fresh(observed_at, now, idle_timeout_seconds)
                    .then_some(path.key.remote.clone())
            })
            .collect::<BTreeSet<_>>();
        let request_node_id = request.node_id.clone();
        let hostname = request
            .service_advertisement
            .as_ref()
            .and_then(|advertisement| advertisement.hostname.clone());
        if let Some(hostname) = hostname.as_deref() {
            if !node_hostname_is_valid(hostname) {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request_node_id.clone(),
                    reason: "hostname must be 1 to 253 ASCII letters, digits, '.', '_' or '-'"
                        .to_string(),
                });
            }
        }
        let hostname_changed = hostname.is_some() && hostname != node.hostname;
        let relay_capability = request
            .relay_capability
            .map(|mut relay_capability| {
                if !node.token_policy.allow_relay {
                    return Err(ControlPlaneError::RelayDenied);
                }
                relay_capability.enabled_by_policy = true;
                validate_relay_capability_shape(&relay_capability).map_err(|reason| {
                    ControlPlaneError::NodeUpdateRejected {
                        node_id: request_node_id.clone(),
                        reason,
                    }
                })?;
                Ok(relay_capability)
            })
            .transpose()?;
        self.store
            .apply_heartbeat(HeartbeatStoreUpdate {
                cluster_id: self.config.cluster_id.clone(),
                expected_cluster_policy: persisted_cluster_policy,
                expected_route_catalog_epoch,
                node_id: request.node_id,
                expected_identity_public_key: node.identity_public_key,
                expected_registered_at: node.registered_at,
                accepted_signature_at,
                hostname,
                candidates: request.candidates,
                nat_classification: request.nat_classification,
                relay_capability,
                routes: request.routes,
                health: request.health,
                paths: request.path_state,
            })
            .await?;
        if let Some(instance) = heartbeat_service_instance {
            self.advertise_service_instance(instance).await?;
        }
        if route_catalog_update_requested || hostname_changed {
            self.invalidate_overlay_node_snapshot().await;
        }

        self.notify_connection_intent_waiters(&connection_intent_targets)
            .await;

        let directory = self.service_directory_at(now).await?;
        let connection_intents = self.connection_intents_for(&request_node_id, now).await?;
        let peer_delta_available = self.client_gateway_selection_changed_recently(now).await?;

        Ok(HeartbeatResponse {
            accepted: true,
            policy_version: 0,
            peer_delta_available,
            bootstrap_endpoints: directory.bootstrap_endpoints,
            connection_intents,
        })
    }

    pub async fn heartbeat_with_connection_intent_wait(
        &self,
        request: HeartbeatRequest,
        wait: Duration,
    ) -> Result<HeartbeatResponse, ControlPlaneError> {
        let node_id = request.node_id.clone();
        let response = self.heartbeat(request).await?;
        self.wait_for_connection_intents(&node_id, response, wait)
            .await
    }

    pub async fn wait_for_connection_intents(
        &self,
        node_id: &NodeId,
        mut response: HeartbeatResponse,
        wait: Duration,
    ) -> Result<HeartbeatResponse, ControlPlaneError> {
        if wait.is_zero() {
            return Ok(response);
        }
        let notifier = self.connection_intent_notifier(node_id).await;
        if response.peer_delta_available || !response.connection_intents.is_empty() {
            return Ok(response);
        }
        let selection_baseline = self.store.latest_client_gateway_selection_at().await?;

        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(response);
            }
            let remaining = deadline.saturating_duration_since(now);
            tokio::select! {
                _ = notifier.notified() => {}
                _ = tokio::time::sleep(remaining.min(CONNECTION_INTENT_WAIT_FALLBACK_POLL_INTERVAL)) => {}
            }

            if self.store.latest_client_gateway_selection_at().await? > selection_baseline {
                response.peer_delta_available = true;
                return Ok(response);
            }

            let intents = self.connection_intents_for(node_id, Utc::now()).await?;
            if !intents.is_empty() {
                response.connection_intents = intents;
                return Ok(response);
            }
        }
    }

    async fn connection_intent_notifier(&self, node_id: &NodeId) -> Arc<Notify> {
        let mut notifiers = self.connection_intent_notifiers.lock().await;
        notifiers
            .entry(node_id.clone())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    async fn notify_connection_intent_waiters(&self, targets: &BTreeSet<NodeId>) {
        if targets.is_empty() {
            return;
        }
        let notifiers = self.connection_intent_notifiers.lock().await;
        for target in targets {
            if let Some(notifier) = notifiers.get(target) {
                notifier.notify_one();
            }
        }
    }

    async fn notify_all_connection_intent_waiters(&self) {
        let notifiers = self.connection_intent_notifiers.lock().await;
        for notifier in notifiers.values() {
            notifier.notify_one();
        }
    }

    async fn client_gateway_selection_changed_recently(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> Result<bool, ControlPlaneError> {
        Ok(self
            .store
            .latest_client_gateway_selection_at()
            .await?
            .is_some_and(|changed_at| {
                now.signed_duration_since(changed_at)
                    .to_std()
                    .map_or(true, |age| age <= CLIENT_GATEWAY_SELECTION_ANNOUNCE_WINDOW)
            }))
    }

    async fn connection_intents_for(
        &self,
        node_id: &NodeId,
        now: chrono::DateTime<Utc>,
    ) -> Result<Vec<PeerConnectionIntent>, ControlPlaneError> {
        let policy = self.current_cluster_policy().await?;
        let target = self
            .store
            .get_node(node_id)
            .await?
            .filter(|node| node.cluster_id == self.config.cluster_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        let paths = self
            .store
            .list_paths_for(node_id)
            .await?
            .into_iter()
            .filter(|path| path.key.remote == *node_id)
            .filter(|path| path_is_fresh(path, now, policy.path_state_ttl_seconds))
            .filter_map(|path| {
                let observed_at = lazy_connect_local_activity_at(&path).ok().flatten()?;
                timestamp_is_fresh(observed_at, now, policy.idle_timeout_seconds)
                    .then_some((path, observed_at))
            })
            .collect::<Vec<_>>();
        let peer_ids = paths
            .iter()
            .map(|(path, _)| path.key.local.clone())
            .collect::<BTreeSet<_>>();
        let peers_by_id = self
            .store
            .get_nodes_by_ids(&peer_ids)
            .await?
            .into_iter()
            .filter(|node| node.cluster_id == self.config.cluster_id)
            .map(|node| (node.node_id.clone(), node))
            .collect::<BTreeMap<_, _>>();
        let mut intents = paths
            .into_iter()
            .filter_map(|(path, observed_at)| {
                let peer = peers_by_id.get(&path.key.local)?;
                acl_filter_peer(&target, peer, &policy).map(|visible| PeerConnectionIntent {
                    peer: visible.node_id,
                    peer_vpn_ip: visible.vpn_ip,
                    observed_at,
                })
            })
            .collect::<Vec<_>>();
        intents.sort_by(|left, right| left.peer.cmp(&right.peer));
        intents.dedup_by(|left, right| left.peer == right.peer);
        Ok(intents)
    }

    pub async fn rotate_wireguard_key(
        &self,
        request: RotateWireGuardKeyRequest,
    ) -> Result<RotateWireGuardKeyResponse, ControlPlaneError> {
        let result = self.rotate_wireguard_key_inner(request).await;
        self.operation_metrics
            .record_wireguard_key_rotation(result.is_ok());
        result
    }

    async fn rotate_wireguard_key_inner(
        &self,
        request: RotateWireGuardKeyRequest,
    ) -> Result<RotateWireGuardKeyResponse, ControlPlaneError> {
        let node = self
            .store
            .get_node(&request.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(request.node_id.clone()))?;
        if node.role.is_client() {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: request.node_id.clone(),
                reason: "clients cannot use node key rotation".to_string(),
            });
        }
        self.validate_wireguard_key_rotation_request(&request, &node, Utc::now())?;
        let rotated_at = Utc::now();
        let updated_node = self
            .store
            .rotate_node_wireguard_public_key(
                &request.node_id,
                &request.previous_wireguard_public_key,
                request.next_wireguard_public_key,
            )
            .await?;
        let peers = self.store.list_nodes().await?;
        let health_by_node = self.health_by_node(&peers).await?;
        let client_gateway_selections = self.store.list_client_gateway_selections().await?;
        let policy = self.current_cluster_policy().await?;
        let directory = self.service_directory_at(rotated_at).await?;
        let peer_map = self.filtered_peer_map_for_node(
            &updated_node,
            &peers,
            ClientGatewayRoutingState {
                health_by_node: &health_by_node,
                selections: &client_gateway_selections,
            },
            &policy,
            directory.bootstrap_endpoints,
            rotated_at,
        );
        let relay_map = self.filtered_relay_map_for_node(
            &updated_node,
            &peers,
            &health_by_node,
            &policy,
            rotated_at,
        );

        Ok(RotateWireGuardKeyResponse {
            node: updated_node,
            peer_map,
            relay_map,
            rotated_at,
        })
    }

    fn validate_wireguard_key_rotation_request(
        &self,
        request: &RotateWireGuardKeyRequest,
        node: &NodeRecord,
        now: chrono::DateTime<Utc>,
    ) -> Result<(), ControlPlaneError> {
        validate_wireguard_public_key_b64(&request.previous_wireguard_public_key).map_err(
            |error| ControlPlaneError::NodeUpdateRejected {
                node_id: request.node_id.clone(),
                reason: format!("previous wireguard public key is invalid: {error}"),
            },
        )?;
        validate_wireguard_public_key_b64(&request.next_wireguard_public_key).map_err(|error| {
            ControlPlaneError::NodeUpdateRejected {
                node_id: request.node_id.clone(),
                reason: format!("next wireguard public key is invalid: {error}"),
            }
        })?;
        if request.node_signature.is_none() {
            return Err(ControlPlaneError::NodeSignatureRequired(
                request.node_id.clone(),
            ));
        }
        verify_wireguard_key_rotation_signature(request, &node.identity_public_key).map_err(
            |error| ControlPlaneError::NodeSignatureRejected {
                node_id: request.node_id.clone(),
                reason: error.to_string(),
            },
        )?;
        let Some(signature) = request.node_signature.as_ref() else {
            return Err(ControlPlaneError::NodeSignatureRequired(
                request.node_id.clone(),
            ));
        };
        let signed_at = signature.signed_at;
        if !timestamp_within_skew(signed_at, now, self.config.heartbeat_signature_max_age) {
            return Err(ControlPlaneError::NodeSignatureRejected {
                node_id: request.node_id.clone(),
                reason: format!(
                    "signed_at {signed_at} is outside the allowed {}s window",
                    self.config.heartbeat_signature_max_age.as_secs()
                ),
            });
        }
        if request.previous_wireguard_public_key != node.wireguard_public_key {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: request.node_id.clone(),
                reason: "previous wireguard public key does not match registered key".to_string(),
            });
        }
        if request.next_wireguard_public_key == node.wireguard_public_key {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: request.node_id.clone(),
                reason: "next wireguard public key matches registered key".to_string(),
            });
        }
        Ok(())
    }

    fn validate_heartbeat_request(
        &self,
        request: &HeartbeatRequest,
        node: &NodeRecord,
        policy: &ClusterPolicy,
        previous_signature_at: Option<chrono::DateTime<Utc>>,
        now: chrono::DateTime<Utc>,
    ) -> Result<(), ControlPlaneError> {
        validate_node_health_shape(
            &request.health,
            now,
            self.config.heartbeat_signature_max_age,
        )
        .map_err(|reason| ControlPlaneError::NodeUpdateRejected {
            node_id: request.node_id.clone(),
            reason,
        })?;
        if let Some(classification) = request.nat_classification.as_ref() {
            validate_nat_classification_shape(
                &request.node_id,
                classification,
                now,
                self.config.heartbeat_signature_max_age,
            )
            .map_err(|reason| ControlPlaneError::NodeUpdateRejected {
                node_id: request.node_id.clone(),
                reason,
            })?;
        }
        if let Some(candidate) = request
            .candidates
            .iter()
            .find(|candidate| candidate.node_id != request.node_id)
        {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: request.node_id.clone(),
                reason: format!(
                    "candidate belongs to node {} instead of {}",
                    candidate.node_id, request.node_id
                ),
            });
        }
        if let Some((candidate, reason)) = request.candidates.iter().find_map(|candidate| {
            candidate
                .validate_kind_address()
                .err()
                .map(|reason| (candidate, reason))
        }) {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: request.node_id.clone(),
                reason: format!(
                    "candidate {:?} at {} is invalid: {reason}",
                    candidate.kind, candidate.addr
                ),
            });
        }
        if let Some(candidate) = request.candidates.iter().find(|candidate| {
            !timestamp_not_after_skew(
                candidate.observed_at,
                now,
                self.config.heartbeat_signature_max_age,
            )
        }) {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: request.node_id.clone(),
                reason: format!(
                    "candidate {:?} at {} observed_at {} is too far in the future",
                    candidate.kind, candidate.addr, candidate.observed_at
                ),
            });
        }
        if let Some(routes) = request.routes.as_ref() {
            validate_advertised_routes_shape(&request.node_id, routes).map_err(|reason| {
                ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason,
                }
            })?;
            validate_routes_within_overlay_scopes(routes, policy).map_err(|reason| {
                ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason,
                }
            })?;
            for route in routes {
                if route.advertised_by != request.node_id {
                    return Err(ControlPlaneError::NodeUpdateRejected {
                        node_id: request.node_id.clone(),
                        reason: format!(
                            "route {} is advertised by node {} instead of {}",
                            route.id, route.advertised_by, request.node_id
                        ),
                    });
                }
                if !route_allowed_by_policy(route, &node.token_policy) {
                    return Err(ControlPlaneError::RouteDenied(route.id.clone()));
                }
            }
        }
        if request.path_state.len() > MAX_HEARTBEAT_PATH_STATES {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: request.node_id.clone(),
                reason: format!(
                    "heartbeat path_state contains {} entries; maximum is {MAX_HEARTBEAT_PATH_STATES}",
                    request.path_state.len()
                ),
            });
        }
        let mut seen_path_keys = BTreeSet::new();
        for path in &request.path_state {
            let path_key = (path.key.local.clone(), path.key.remote.clone());
            if !seen_path_keys.insert(path_key) {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason: format!(
                        "path {} -> {} is repeated in heartbeat path_state",
                        path.key.local, path.key.remote
                    ),
                });
            }
            if !timestamp_not_after_skew(
                path.updated_at,
                now,
                self.config.heartbeat_signature_max_age,
            ) {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason: format!(
                        "path {} -> {} updated_at {} is too far in the future",
                        path.key.local, path.key.remote, path.updated_at
                    ),
                });
            }
            validate_path_score_shape(path).map_err(|reason| {
                ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason,
                }
            })?;
            if let Some(observed_at) = lazy_connect_local_activity_at(path).map_err(|reason| {
                ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason,
                }
            })? {
                if !timestamp_not_after_skew(
                    observed_at,
                    now,
                    self.config.heartbeat_signature_max_age,
                ) {
                    return Err(ControlPlaneError::NodeUpdateRejected {
                        node_id: request.node_id.clone(),
                        reason: format!(
                            "path {} -> {} lazy-connect activity {} is too far in the future",
                            path.key.local, path.key.remote, observed_at
                        ),
                    });
                }
            }
            if path.key.local != request.node_id {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason: format!(
                        "path {} -> {} is not owned by reporting node {}",
                        path.key.local, path.key.remote, request.node_id
                    ),
                });
            }
            if path.key.remote == request.node_id {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason: format!(
                        "path {} -> {} points back to the reporting node",
                        path.key.local, path.key.remote
                    ),
                });
            }
            let peer = &path.key.remote;
            if let Some(candidate) = &path.selected_candidate {
                if &candidate.node_id != peer {
                    return Err(ControlPlaneError::NodeUpdateRejected {
                        node_id: request.node_id.clone(),
                        reason: format!(
                            "selected candidate belongs to node {} instead of path peer {}",
                            candidate.node_id, peer
                        ),
                    });
                }
                if let Err(reason) = candidate.validate_kind_address() {
                    return Err(ControlPlaneError::NodeUpdateRejected {
                        node_id: request.node_id.clone(),
                        reason: format!(
                            "selected candidate {:?} at {} is invalid: {reason}",
                            candidate.kind, candidate.addr
                        ),
                    });
                }
                if !endpoint_addr_is_usable(candidate.addr) {
                    return Err(ControlPlaneError::NodeUpdateRejected {
                        node_id: request.node_id.clone(),
                        reason: format!(
                            "selected candidate {:?} at {} is unusable",
                            candidate.kind, candidate.addr
                        ),
                    });
                }
                if path.selected_state.is_direct()
                    && !path
                        .selected_state
                        .allows_selected_candidate_kind(candidate.kind)
                {
                    return Err(ControlPlaneError::NodeUpdateRejected {
                        node_id: request.node_id.clone(),
                        reason: format!(
                            "path {} -> {} selected state {:?} does not allow selected candidate kind {:?}",
                            path.key.local, path.key.remote, path.selected_state, candidate.kind
                        ),
                    });
                }
                if !timestamp_not_after_skew(
                    candidate.observed_at,
                    now,
                    self.config.heartbeat_signature_max_age,
                ) {
                    return Err(ControlPlaneError::NodeUpdateRejected {
                        node_id: request.node_id.clone(),
                        reason: format!(
                            "selected candidate {:?} at {} observed_at {} is too far in the future",
                            candidate.kind, candidate.addr, candidate.observed_at
                        ),
                    });
                }
                if !endpoint_candidate_is_fresh(
                    candidate,
                    now,
                    policy.endpoint_candidate_ttl_seconds,
                ) {
                    return Err(ControlPlaneError::NodeUpdateRejected {
                        node_id: request.node_id.clone(),
                        reason: format!(
                            "selected candidate {:?} at {} observed_at {} is stale",
                            candidate.kind, candidate.addr, candidate.observed_at
                        ),
                    });
                }
            }
        }
        if request.node_signature.is_none() {
            if self.config.require_heartbeat_signature {
                return Err(ControlPlaneError::NodeSignatureRequired(
                    request.node_id.clone(),
                ));
            }
            return Ok(());
        }
        verify_heartbeat_request_signature(request, &node.identity_public_key).map_err(
            |error| ControlPlaneError::NodeSignatureRejected {
                node_id: request.node_id.clone(),
                reason: error.to_string(),
            },
        )?;
        let Some(signature) = request.node_signature.as_ref() else {
            return Err(ControlPlaneError::NodeSignatureRequired(
                request.node_id.clone(),
            ));
        };
        let signed_at = signature.signed_at;
        if !timestamp_within_skew(signed_at, now, self.config.heartbeat_signature_max_age) {
            return Err(ControlPlaneError::NodeSignatureRejected {
                node_id: request.node_id.clone(),
                reason: format!(
                    "signed_at {signed_at} is outside the allowed {}s window",
                    self.config.heartbeat_signature_max_age.as_secs()
                ),
            });
        }
        if let Some(previous_signature_at) = previous_signature_at {
            if signed_at <= previous_signature_at {
                return Err(ControlPlaneError::NodeSignatureRejected {
                    node_id: request.node_id.clone(),
                    reason: format!(
                        "signed_at {signed_at} is not newer than last accepted heartbeat {}",
                        previous_signature_at
                    ),
                });
            }
        }
        Ok(())
    }

    async fn overlay_route_catalog_update_validation(
        &self,
        node_id: &NodeId,
        routes: &[Route],
        policy: &ClusterPolicy,
    ) -> Result<(Option<String>, Option<u64>), ControlPlaneError> {
        if let Err(reason) = validate_routes_against_vpn_pool(routes, self.config.vpn_pool) {
            return Ok((Some(reason), None));
        }
        if !policy.overlay_route_scopes.is_empty() || routes.is_empty() {
            return Ok((None, None));
        }

        let nodes = self
            .store
            .list_nodes()
            .await?
            .into_iter()
            .filter(|node| node.cluster_id == self.config.cluster_id && !node.role.is_client())
            .collect::<Vec<_>>();
        let expected_route_catalog_epoch = overlay_route_catalog_epoch(&nodes)?;
        let mut cidrs = nodes
            .into_iter()
            .filter(|node| node.node_id != *node_id)
            .flat_map(|node| {
                let owner = node.node_id;
                node.routes
                    .into_iter()
                    .filter(move |route| {
                        route.advertised_by == owner
                            && route.via.as_ref().is_none_or(|via| via == &owner)
                    })
                    .map(|route| route.cidr.trunc())
            })
            .collect::<Vec<_>>();
        cidrs.extend(
            routes
                .iter()
                .filter(|route| {
                    route.advertised_by == *node_id
                        && route.via.as_ref().is_none_or(|via| via == node_id)
                })
                .map(|route| route.cidr.trunc()),
        );
        let aggregate_count = IpNet::aggregate(&cidrs).len();
        if aggregate_count > MAX_OVERLAY_ROUTE_SCOPES {
            return Ok((
                Some(format!(
                    "advertised routes would require {aggregate_count} aggregate capture scopes, \
                     exceeding the maximum {MAX_OVERLAY_ROUTE_SCOPES}; configure \
                     overlay_route_scopes before advertising fragmented routes"
                )),
                Some(expected_route_catalog_epoch),
            ));
        }
        Ok((None, Some(expected_route_catalog_epoch)))
    }

    fn validate_heartbeat_path_relay_shape(
        &self,
        request: &HeartbeatRequest,
    ) -> Result<(), ControlPlaneError> {
        for path in &request.path_state {
            if path.selected_state == PathState::Relay && path.selected_candidate.is_some() {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason: format!(
                        "relay path {} -> {} must not carry a direct selected candidate",
                        path.key.local, path.key.remote
                    ),
                });
            }
            if path.selected_state == PathState::Unreachable && path.selected_candidate.is_some() {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason: format!(
                        "unreachable path {} -> {} must not carry a selected candidate",
                        path.key.local, path.key.remote
                    ),
                });
            }
            match (path.selected_state, path.relay_node.as_ref()) {
                (PathState::Relay, Some(relay_node))
                    if relay_node == &path.key.local || relay_node == &path.key.remote =>
                {
                    return Err(ControlPlaneError::NodeUpdateRejected {
                        node_id: request.node_id.clone(),
                        reason: format!(
                            "relay path {} -> {} uses endpoint {relay_node} as relay",
                            path.key.local, path.key.remote
                        ),
                    });
                }
                (PathState::Relay, Some(_)) => {}
                (PathState::Relay, None) => {
                    return Err(ControlPlaneError::NodeUpdateRejected {
                        node_id: request.node_id.clone(),
                        reason: format!(
                            "relay path {} -> {} is missing relay node",
                            path.key.local, path.key.remote
                        ),
                    });
                }
                (_, Some(relay_node)) => {
                    return Err(ControlPlaneError::NodeUpdateRejected {
                        node_id: request.node_id.clone(),
                        reason: format!(
                            "non-relay path {} -> {} carries relay node {relay_node}",
                            path.key.local, path.key.remote
                        ),
                    });
                }
                (_, None) => {}
            }
        }
        Ok(())
    }

    fn validate_heartbeat_path_peers_visible(
        &self,
        request: &HeartbeatRequest,
        reporter: &NodeRecord,
        nodes: &[NodeRecord],
        policy: &ClusterPolicy,
    ) -> Result<(), ControlPlaneError> {
        let nodes_by_id = nodes
            .iter()
            .map(|node| (node.node_id.clone(), node))
            .collect::<BTreeMap<_, _>>();
        for path in &request.path_state {
            let Some(remote) = nodes_by_id.get(&path.key.remote) else {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason: format!(
                        "path {} -> {} remote node is not registered",
                        path.key.local, path.key.remote
                    ),
                });
            };
            if acl_filter_peer(reporter, remote, policy).is_none() {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason: format!(
                        "path {} -> {} remote node is not visible to reporting node",
                        path.key.local, path.key.remote
                    ),
                });
            }
        }
        Ok(())
    }

    fn validate_heartbeat_path_relay_eligibility(
        &self,
        request: &HeartbeatRequest,
        reporter: &NodeRecord,
        nodes: &[NodeRecord],
        health_by_node: &BTreeMap<NodeId, NodeHealth>,
        now: chrono::DateTime<Utc>,
        policy: &ClusterPolicy,
    ) -> Result<(), ControlPlaneError> {
        let nodes_by_id = nodes
            .iter()
            .map(|node| (node.node_id.clone(), node))
            .collect::<BTreeMap<_, _>>();
        for path in &request.path_state {
            if path.selected_state != PathState::Relay {
                continue;
            }
            let Some(relay_node) = path.relay_node.as_ref() else {
                continue;
            };
            let Some(relay) = nodes_by_id.get(relay_node) else {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason: format!("relay node {relay_node} is not registered"),
                });
            };
            if !relay_candidate_allowed(relay, health_by_node.get(relay_node), now, policy) {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason: format!("relay node {relay_node} is not an eligible relay candidate"),
                });
            }
            if acl_filter_peer(reporter, relay, policy).is_none() {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason: format!("relay node {relay_node} is not visible to reporting node"),
                });
            }
        }
        Ok(())
    }

    pub async fn metrics(&self) -> Result<ControlPlaneMetricsResponse, ControlPlaneError> {
        let participants = self.store.list_nodes().await?;
        let client_count = participants
            .iter()
            .filter(|participant| participant.role.is_client())
            .count();
        let nodes = participants
            .iter()
            .filter(|participant| !participant.role.is_client())
            .cloned()
            .collect::<Vec<_>>();
        let health_by_node = self.health_by_node(&nodes).await?;
        let policy = self.current_cluster_policy().await?;
        let mut healthy_node_count = 0;
        let mut degraded_node_count = 0;
        let mut unhealthy_node_count = 0;
        let now = Utc::now();
        let service_directory = self.service_directory_at(now).await?;
        let active_service_host_count = service_directory
            .instances
            .iter()
            .filter_map(service_instance_owner_node_id)
            .collect::<BTreeSet<_>>()
            .len();
        let active_control_plane_count = service_instance_kind_count(
            &service_directory.instances,
            BootstrapEndpointKind::ControlPlane,
        );
        let active_signal_count = service_instance_kind_count(
            &service_directory.instances,
            BootstrapEndpointKind::Signal,
        );
        let active_stun_count =
            service_instance_kind_count(&service_directory.instances, BootstrapEndpointKind::Stun);
        let active_relay_count =
            service_instance_kind_count(&service_directory.instances, BootstrapEndpointKind::Relay);
        let active_web_ui_count =
            service_instance_kind_count(&service_directory.instances, BootstrapEndpointKind::WebUi);
        let full_service_node_count = full_service_owner_node_count(&service_directory.instances);
        let ha_ready = self.config.service_ha_replica_count > 0
            && full_service_node_count >= self.config.service_ha_replica_count;
        let relay_candidate_count = nodes
            .iter()
            .filter(|node| {
                relay_candidate_allowed(node, health_by_node.get(&node.node_id), now, &policy)
            })
            .count();
        let stale_endpoint_candidate_count = nodes
            .iter()
            .flat_map(|node| &node.endpoint_candidates)
            .filter(|candidate| {
                !endpoint_candidate_is_fresh(candidate, now, policy.endpoint_candidate_ttl_seconds)
            })
            .count();
        let vpn_pool_total_count = vpn_pool_usable_host_count(self.config.vpn_pool);
        let vpn_pool_allocated_count = assigned_ipv4_vpn_ips(&participants)
            .into_iter()
            .filter(|ip| vpn_pool_contains_usable_host(self.config.vpn_pool, *ip))
            .count() as u64;
        let vpn_pool_available_count =
            vpn_pool_total_count.saturating_sub(vpn_pool_allocated_count);
        let peer_map_metrics = peer_map_visibility_metrics(&nodes, &policy);
        let operation_metrics = self.operation_metrics.snapshot();

        let mut paths = BTreeMap::<(NodeId, NodeId), PathRecord>::new();
        for node in &nodes {
            if let Some(health) = health_by_node.get(&node.node_id) {
                match health.state {
                    HealthState::Healthy => healthy_node_count += 1,
                    HealthState::Degraded => degraded_node_count += 1,
                    HealthState::Unhealthy => unhealthy_node_count += 1,
                }
            }
            for path in self.store.list_paths_for(&node.node_id).await? {
                paths.insert((path.key.local.clone(), path.key.remote.clone()), path);
            }
        }

        let mut stale_path_count = 0;
        let mut path_state_counts = BTreeMap::<PathState, usize>::new();
        for path in paths.values() {
            if !path_is_fresh(path, now, policy.path_state_ttl_seconds) {
                stale_path_count += 1;
                continue;
            }
            *path_state_counts.entry(path.selected_state).or_default() += 1;
        }
        let path_count = paths.len().saturating_sub(stale_path_count);

        Ok(ControlPlaneMetricsResponse {
            cluster_id: self.config.cluster_id.clone(),
            node_count: nodes.len(),
            client_count,
            relay_candidate_count,
            active_service_instance_count: service_directory.instances.len(),
            active_service_host_count,
            active_control_plane_count,
            active_signal_count,
            active_stun_count,
            active_relay_count,
            active_web_ui_count,
            ha_ready,
            healthy_node_count,
            degraded_node_count,
            unhealthy_node_count,
            stale_endpoint_candidate_count,
            vpn_pool_total_count,
            vpn_pool_allocated_count,
            vpn_pool_available_count,
            token_ledger_issued_count: 0,
            token_ledger_active_count: 0,
            token_ledger_revoked_count: 0,
            token_ledger_expired_count: 0,
            token_ledger_exhausted_count: 0,
            token_ledger_use_count: 0,
            wireguard_key_rotation_success_count: operation_metrics
                .wireguard_key_rotation_success_count,
            wireguard_key_rotation_failure_count: operation_metrics
                .wireguard_key_rotation_failure_count,
            node_removal_success_count: operation_metrics.node_removal_success_count,
            node_removal_failure_count: operation_metrics.node_removal_failure_count,
            peer_map_candidate_count: peer_map_metrics.peer_candidates,
            peer_map_visible_count: peer_map_metrics.visible_peers,
            peer_map_acl_denied_count: peer_map_metrics.acl_denied_peers,
            peer_map_route_candidate_count: peer_map_metrics.route_candidates,
            peer_map_route_visible_count: peer_map_metrics.visible_routes,
            peer_map_route_acl_denied_count: peer_map_metrics.acl_denied_routes,
            stale_path_count,
            path_count,
            path_state_counts: PATH_STATE_METRIC_ORDER
                .into_iter()
                .map(|state| PathStateCount {
                    state,
                    count: *path_state_counts.get(&state).unwrap_or(&0),
                })
                .collect(),
            endpoint_candidate_ttl_seconds: policy.endpoint_candidate_ttl_seconds,
            path_state_ttl_seconds: policy.path_state_ttl_seconds,
            generated_at: now,
        })
    }

    async fn health_by_node(
        &self,
        nodes: &[NodeRecord],
    ) -> Result<BTreeMap<NodeId, NodeHealth>, ControlPlaneError> {
        let node_ids = nodes
            .iter()
            .map(|node| node.node_id.clone())
            .collect::<BTreeSet<_>>();
        self.store.get_health_by_node_ids(&node_ids).await
    }

    fn filtered_peer_map_for_node(
        &self,
        source: &NodeRecord,
        peers: &[NodeRecord],
        gateway_routing: ClientGatewayRoutingState<'_>,
        policy: &ClusterPolicy,
        bootstrap_endpoints: Vec<BootstrapEndpoint>,
        generated_at: chrono::DateTime<Utc>,
    ) -> PeerMap {
        let visible_peers = if source.role.is_client() {
            client_gateway_peer_map(
                source,
                peers,
                gateway_routing.health_by_node,
                gateway_routing.selections,
                policy,
                generated_at,
            )
        } else {
            node_peer_map_with_clients(
                source,
                peers,
                gateway_routing.health_by_node,
                gateway_routing.selections,
                policy,
                generated_at,
            )
        };
        PeerMap {
            cluster_id: self.config.cluster_id.clone(),
            peers: visible_peers,
            bootstrap_endpoints,
            generated_at,
        }
    }

    fn filtered_relay_map_for_node(
        &self,
        source: &NodeRecord,
        peers: &[NodeRecord],
        health_by_node: &BTreeMap<NodeId, NodeHealth>,
        policy: &ClusterPolicy,
        generated_at: chrono::DateTime<Utc>,
    ) -> RelayMap {
        RelayMap {
            cluster_id: self.config.cluster_id.clone(),
            relays: peers
                .iter()
                .filter(|peer| {
                    relay_candidate_allowed(
                        peer,
                        health_by_node.get(&peer.node_id),
                        generated_at,
                        policy,
                    )
                })
                .filter_map(|peer| {
                    if peer.node_id == source.node_id {
                        Some(peer.clone())
                    } else {
                        acl_filter_peer(source, peer, policy)
                    }
                })
                .map(|peer| filter_served_endpoint_candidates(peer, generated_at, policy))
                .collect(),
            generated_at,
        }
    }
}

#[derive(Clone, Copy)]
struct ClientGatewayRoutingState<'a> {
    health_by_node: &'a BTreeMap<NodeId, NodeHealth>,
    selections: &'a BTreeMap<NodeId, ClientGatewaySelection>,
}

fn client_gateway_peer_map(
    source: &NodeRecord,
    peers: &[NodeRecord],
    health_by_node: &BTreeMap<NodeId, NodeHealth>,
    client_gateway_selections: &BTreeMap<NodeId, ClientGatewaySelection>,
    policy: &ClusterPolicy,
    generated_at: chrono::DateTime<Utc>,
) -> Vec<NodeRecord> {
    let visible_nodes = peers
        .iter()
        .filter(|peer| peer.node_id != source.node_id && !peer.role.is_client())
        .filter_map(|peer| acl_filter_peer(source, peer, policy))
        .collect::<Vec<_>>();
    let mut gateways = select_client_gateways(&visible_nodes, health_by_node, generated_at, policy);
    if let Some(selected) = client_gateway_selections.get(&source.node_id) {
        if let Some(index) = gateways
            .iter()
            .position(|gateway| gateway.node_id == selected.gateway_node_id)
        {
            gateways.rotate_left(index);
        }
    }
    gateways
        .into_iter()
        .map(|gateway| project_client_gateway(gateway, &visible_nodes, generated_at, policy))
        .collect()
}

fn project_client_gateway(
    gateway: &NodeRecord,
    visible_nodes: &[NodeRecord],
    generated_at: chrono::DateTime<Utc>,
    policy: &ClusterPolicy,
) -> NodeRecord {
    let gateway_id = gateway.node_id.clone();
    let mut projected_gateway = gateway.clone();
    let mut routes = projected_gateway
        .routes
        .drain(..)
        .map(|route| (route.cidr, route))
        .collect::<BTreeMap<_, _>>();

    for node in visible_nodes {
        if node.node_id == gateway_id {
            continue;
        }
        if let Some(route) = projected_gateway_host_route(&projected_gateway, node) {
            insert_preferred_gateway_route(&mut routes, route);
        }
        for route in &node.routes {
            insert_preferred_gateway_route(
                &mut routes,
                Route {
                    id: format!("client-via-{}-{}", node.node_id, route.id),
                    cidr: route.cidr,
                    advertised_by: gateway_id.clone(),
                    via: Some(gateway_id.clone()),
                    metric: route.metric,
                    tags: route.tags.clone(),
                },
            );
        }
    }
    projected_gateway.routes = routes.into_values().collect();
    filter_client_gateway_endpoint_candidates(projected_gateway, generated_at, policy)
}

fn node_peer_map_with_clients(
    source: &NodeRecord,
    peers: &[NodeRecord],
    health_by_node: &BTreeMap<NodeId, NodeHealth>,
    client_gateway_selections: &BTreeMap<NodeId, ClientGatewaySelection>,
    policy: &ClusterPolicy,
    generated_at: chrono::DateTime<Utc>,
) -> Vec<NodeRecord> {
    let gateway_ids = select_client_gateways(peers, health_by_node, generated_at, policy)
        .into_iter()
        .map(|gateway| gateway.node_id.clone())
        .collect::<Vec<_>>();
    let visible_clients = peers
        .iter()
        .filter(|peer| peer.role.is_client())
        .filter_map(|client| {
            acl_filter_peer(source, client, policy)
                .map(|visible| (visible.node_id.clone(), visible))
        })
        .collect::<BTreeMap<_, _>>();
    let selected_gateway_by_client = visible_clients
        .values()
        .filter_map(|client| {
            client_gateway_selections
                .get(&client.node_id)
                .map(|selection| &selection.gateway_node_id)
                .filter(|gateway| gateway_ids.contains(gateway))
                .or_else(|| gateway_ids.first())
                .cloned()
                .map(|gateway| (client.node_id.clone(), gateway))
        })
        .collect::<BTreeMap<_, _>>();
    let mut client_routes_by_gateway = BTreeMap::<NodeId, Vec<Route>>::new();
    for client in visible_clients.values() {
        let Some(selected_gateway) = selected_gateway_by_client.get(&client.node_id) else {
            continue;
        };
        if selected_gateway == &source.node_id {
            continue;
        }
        if let Some(route) = gateway_route_for_client(selected_gateway, client) {
            client_routes_by_gateway
                .entry(route.advertised_by.clone())
                .or_default()
                .push(route);
        }
    }

    peers
        .iter()
        .filter(|peer| peer.node_id != source.node_id)
        .filter_map(|peer| {
            if peer.role.is_client() {
                if selected_gateway_by_client.get(&peer.node_id) != Some(&source.node_id) {
                    return None;
                }
                return visible_clients
                    .get(&peer.node_id)
                    .cloned()
                    .map(|peer| filter_served_endpoint_candidates(peer, generated_at, policy));
            }

            let mut visible = acl_filter_peer(source, peer, policy)?;
            if let Some(client_routes) = client_routes_by_gateway.get(&visible.node_id) {
                let mut routes = visible
                    .routes
                    .drain(..)
                    .map(|route| (route.cidr, route))
                    .collect::<BTreeMap<_, _>>();
                for route in client_routes {
                    insert_preferred_gateway_route(&mut routes, route.clone());
                }
                visible.routes = routes.into_values().collect();
            }
            Some(filter_served_endpoint_candidates(
                visible,
                generated_at,
                policy,
            ))
        })
        .collect()
}

fn node_client_route_projection(
    source: &NodeRecord,
    backbone_nodes: &[NodeRecord],
    clients: &[NodeRecord],
    health_by_node: &BTreeMap<NodeId, NodeHealth>,
    client_gateway_selections: &BTreeMap<NodeId, ClientGatewaySelection>,
    policy: &ClusterPolicy,
    generated_at: chrono::DateTime<Utc>,
) -> Vec<NodeRecord> {
    if clients.is_empty() {
        return Vec::new();
    }
    let gateways = select_client_gateways(backbone_nodes, health_by_node, generated_at, policy);
    let gateway_ids = gateways
        .iter()
        .map(|gateway| gateway.node_id.clone())
        .collect::<Vec<_>>();
    let gateways_by_id = gateways
        .into_iter()
        .map(|gateway| (gateway.node_id.clone(), gateway))
        .collect::<BTreeMap<_, _>>();
    let visible_clients = clients
        .iter()
        .filter_map(|client| acl_filter_peer(source, client, policy))
        .collect::<Vec<_>>();
    let mut direct_clients = Vec::new();
    let mut routes_by_gateway = BTreeMap::<NodeId, BTreeMap<IpNet, Route>>::new();

    for client in visible_clients {
        let selected_gateway = client_gateway_selections
            .get(&client.node_id)
            .map(|selection| &selection.gateway_node_id)
            .filter(|gateway| gateway_ids.contains(gateway))
            .cloned()
            .or_else(|| gateway_ids.first().cloned());
        let Some(selected_gateway) = selected_gateway else {
            continue;
        };
        if selected_gateway == source.node_id {
            direct_clients.push(filter_served_endpoint_candidates(
                client,
                generated_at,
                policy,
            ));
            continue;
        }
        let Some(route) = gateway_route_for_client(&selected_gateway, &client) else {
            continue;
        };
        insert_preferred_gateway_route(
            routes_by_gateway.entry(selected_gateway).or_default(),
            route,
        );
    }

    let mut projection = direct_clients;
    for (gateway_id, routes) in routes_by_gateway {
        let Some(gateway) = gateways_by_id.get(&gateway_id) else {
            continue;
        };
        let Some(mut projected_gateway) = acl_filter_peer(source, gateway, policy) else {
            continue;
        };
        projected_gateway.routes = routes.into_values().collect();
        projection.push(filter_served_endpoint_candidates(
            projected_gateway,
            generated_at,
            policy,
        ));
    }
    projection.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    projection
}

fn select_client_gateways<'a>(
    nodes: &'a [NodeRecord],
    health_by_node: &BTreeMap<NodeId, NodeHealth>,
    now: chrono::DateTime<Utc>,
    policy: &ClusterPolicy,
) -> Vec<&'a NodeRecord> {
    let mut candidates = nodes
        .iter()
        .filter(|node| !node.role.is_client())
        .filter(|node| client_gateway_health_allows(health_by_node.get(&node.node_id), now, policy))
        .filter_map(|node| {
            client_gateway_candidate_score(node, now, policy).map(|candidate_score| {
                (
                    node.role.as_str() != "gateway",
                    candidate_score,
                    node.node_id.as_str(),
                    node,
                )
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(right.2))
    });
    candidates
        .into_iter()
        .take(MAX_CLIENT_GATEWAYS)
        .map(|(_, _, _, node)| node)
        .collect()
}

fn client_gateway_health_allows(
    health: Option<&NodeHealth>,
    now: chrono::DateTime<Utc>,
    policy: &ClusterPolicy,
) -> bool {
    let Some(health) = health else {
        return true;
    };
    health.state == HealthState::Healthy
        && match now.signed_duration_since(health.last_seen_at).to_std() {
            Ok(age) => age <= Duration::from_secs(policy.relay_health_ttl_seconds),
            Err(_) => true,
        }
}

fn overlay_node_health_allows(
    node: &NodeRecord,
    health: Option<&NodeHealth>,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> bool {
    let last_seen_at = match health {
        Some(health) if health.state == HealthState::Unhealthy => return false,
        Some(health) => health.last_seen_at,
        None => node.registered_at,
    };
    match now.signed_duration_since(last_seen_at).to_std() {
        Ok(age) => age <= Duration::from_secs(ttl_seconds),
        Err(_) => true,
    }
}

fn client_gateway_candidate_score(
    node: &NodeRecord,
    now: chrono::DateTime<Utc>,
    policy: &ClusterPolicy,
) -> Option<(u8, u32, u16, String)> {
    node.endpoint_candidates
        .iter()
        .filter(|candidate| {
            candidate.node_id == node.node_id
                && candidate.validate_kind_address().is_ok()
                && endpoint_addr_is_usable(candidate.addr)
                && socket_addr_is_globally_routable(candidate.addr)
                && endpoint_candidate_is_fresh(
                    candidate,
                    now,
                    policy.endpoint_candidate_ttl_seconds,
                )
        })
        .filter_map(|candidate| {
            let rank = match candidate.kind {
                EndpointCandidateKind::Ipv6 if policy.allow_ipv6_direct => 0,
                EndpointCandidateKind::Ipv6 => return None,
                EndpointCandidateKind::PublicUdp => 1,
                EndpointCandidateKind::StunReflexive
                | EndpointCandidateKind::LocalUdp
                | EndpointCandidateKind::Relay => return None,
            };
            Some((
                rank,
                candidate.cost,
                u16::MAX.saturating_sub(candidate.priority),
                candidate.addr.to_string(),
            ))
        })
        .min()
}

fn filter_client_gateway_endpoint_candidates(
    mut node: NodeRecord,
    now: chrono::DateTime<Utc>,
    policy: &ClusterPolicy,
) -> NodeRecord {
    node.endpoint_candidates.retain(|candidate| {
        matches!(
            candidate.kind,
            EndpointCandidateKind::PublicUdp | EndpointCandidateKind::Ipv6
        ) && (candidate.kind != EndpointCandidateKind::Ipv6 || policy.allow_ipv6_direct)
            && candidate.node_id == node.node_id
            && candidate.validate_kind_address().is_ok()
            && socket_addr_is_globally_routable(candidate.addr)
            && endpoint_candidate_is_fresh(candidate, now, policy.endpoint_candidate_ttl_seconds)
    });
    node.relay_capability = None;
    node
}

fn projected_gateway_host_route(gateway: &NodeRecord, target: &NodeRecord) -> Option<Route> {
    Some(Route {
        id: format!("client-via-{}", target.node_id),
        cidr: vpn_host_cidr(&target.vpn_ip)?,
        advertised_by: gateway.node_id.clone(),
        via: Some(gateway.node_id.clone()),
        metric: 10,
        tags: target.tags.clone(),
    })
}

fn gateway_route_for_client(gateway_id: &NodeId, client: &NodeRecord) -> Option<Route> {
    Some(Route {
        id: format!("client-{}", client.node_id),
        cidr: vpn_host_cidr(&client.vpn_ip)?,
        advertised_by: gateway_id.clone(),
        via: Some(gateway_id.clone()),
        metric: 10,
        tags: client.tags.clone(),
    })
}

fn vpn_host_cidr(vpn_ip: &VpnIp) -> Option<IpNet> {
    match vpn_ip.0 {
        IpAddr::V4(ip) => Ipv4Net::new(ip, 32).ok().map(IpNet::V4),
        IpAddr::V6(ip) => Ipv6Net::new(ip, 128).ok().map(IpNet::V6),
    }
}

fn insert_preferred_gateway_route(routes: &mut BTreeMap<IpNet, Route>, route: Route) {
    let replace = routes.get(&route.cidr).is_none_or(|current| {
        (route.metric, route.id.as_str()) < (current.metric, current.id.as_str())
    });
    if replace {
        routes.insert(route.cidr, route);
    }
}

fn heartbeat_service_instance_id(node_id: &NodeId) -> String {
    format!("agent-services-{node_id}")
}

fn heartbeat_service_instance(
    request: &HeartbeatRequest,
    node: &NodeRecord,
    cluster_id: &ClusterId,
    now: chrono::DateTime<Utc>,
) -> Result<Option<ServiceInstance>, ControlPlaneError> {
    let Some(advertisement) = request.service_advertisement.as_ref() else {
        return Ok(None);
    };
    let reject = |reason: String| ControlPlaneError::NodeUpdateRejected {
        node_id: request.node_id.clone(),
        reason,
    };
    if advertisement.endpoints.is_empty() {
        return Ok(None);
    }
    validate_join_token_bootstrap_endpoints(&advertisement.endpoints)
        .map_err(|error| reject(error.to_string()))?;
    let public_ip = request
        .nat_classification
        .as_ref()
        .and_then(NatClassification::publicly_reachable_ip)
        .ok_or_else(|| {
            reject("service advertisement requires a public NAT classification".to_string())
        })?;
    let mut kinds = BTreeSet::new();
    for endpoint in &advertisement.endpoints {
        if !matches!(
            endpoint.kind,
            BootstrapEndpointKind::Signal
                | BootstrapEndpointKind::Stun
                | BootstrapEndpointKind::Relay
        ) {
            return Err(reject(format!(
                "heartbeat service advertisement cannot publish {}",
                endpoint.kind
            )));
        }
        if !kinds.insert(endpoint.kind) {
            return Err(reject(format!(
                "heartbeat service advertisement contains multiple {} endpoints",
                endpoint.kind
            )));
        }
        match endpoint.kind {
            BootstrapEndpointKind::Signal => {
                let advertised_addr = literal_http_bootstrap_socket_addr(&endpoint.url)
                    .ok_or_else(|| {
                        reject(
                            "heartbeat Signal endpoint must use a literal, usable VPN IP address"
                                .to_string(),
                        )
                    })?;
                if advertised_addr.ip() != node.vpn_ip.0 {
                    return Err(reject(format!(
                        "heartbeat Signal endpoint IP {} does not match node VPN IP {}",
                        advertised_addr.ip(),
                        node.vpn_ip
                    )));
                }
            }
            BootstrapEndpointKind::Stun | BootstrapEndpointKind::Relay => {
                let advertised_addr =
                    literal_udp_bootstrap_socket_addr(&endpoint.url).ok_or_else(|| {
                        reject(format!(
                            "heartbeat {} endpoint must use a literal, usable public IP address",
                            endpoint.kind
                        ))
                    })?;
                if advertised_addr.ip() != public_ip {
                    return Err(reject(format!(
                        "heartbeat {} endpoint IP {} does not match classified public IP {public_ip}",
                        endpoint.kind,
                        advertised_addr.ip()
                    )));
                }
                if endpoint.kind == BootstrapEndpointKind::Relay {
                    let relay = request.relay_capability.as_ref().ok_or_else(|| {
                        reject("Relay endpoint requires a live Relay capability report".to_string())
                    })?;
                    if validate_relay_capability_shape(relay).is_err()
                        || relay.public_endpoint != Some(advertised_addr)
                    {
                        return Err(reject(
                            "Relay endpoint does not match the live Relay capability report"
                                .to_string(),
                        ));
                    }
                }
            }
            _ => unreachable!("unsupported heartbeat service kind was rejected"),
        }
    }
    Ok(Some(ServiceInstance {
        cluster_id: cluster_id.clone(),
        instance_id: heartbeat_service_instance_id(&request.node_id),
        owner_host_id: request.node_id.as_str().to_string(),
        owner_node_id: Some(request.node_id.clone()),
        enrollment_signer: false,
        endpoints: advertisement.endpoints.clone(),
        lease_expires_at: now + chrono::Duration::seconds(HEARTBEAT_SERVICE_LEASE_SECONDS),
        updated_at: now,
    }))
}

fn validate_service_instance(
    instance: &ServiceInstance,
    cluster_id: &ClusterId,
    now: chrono::DateTime<Utc>,
) -> Result<(), ControlPlaneError> {
    if &instance.cluster_id != cluster_id {
        return Err(ControlPlaneError::Store(format!(
            "service instance {} belongs to cluster {} instead of {}",
            instance.instance_id, instance.cluster_id, cluster_id
        )));
    }
    if !valid_service_instance_identifier(&instance.instance_id) {
        return Err(ControlPlaneError::Store(
            "service instance ID must be 1 to 255 ASCII letters, digits, '_', '.' or '-'"
                .to_string(),
        ));
    }
    if !valid_service_instance_identifier(&instance.owner_host_id) {
        return Err(ControlPlaneError::Store(
            "service owner host ID must be 1 to 255 ASCII letters, digits, '_', '.' or '-'"
                .to_string(),
        ));
    }
    let owner_node_id = instance
        .owner_node_id
        .as_ref()
        .ok_or_else(|| ControlPlaneError::Store("service owner node ID is required".to_string()))?;
    if !valid_service_instance_identifier(owner_node_id.as_str()) {
        return Err(ControlPlaneError::Store(
            "service owner node ID must be 1 to 255 ASCII letters, digits, '_', '.' or '-'"
                .to_string(),
        ));
    }
    if owner_node_id.as_str() != instance.owner_host_id {
        return Err(ControlPlaneError::Store(
            "service owner host ID must equal owner node ID".to_string(),
        ));
    }
    validate_join_token_bootstrap_endpoints(&instance.endpoints)
        .map_err(|error| ControlPlaneError::Store(error.to_string()))?;
    if instance.endpoints.is_empty() {
        return Err(ControlPlaneError::Store(format!(
            "service instance {} must advertise at least one endpoint",
            instance.instance_id
        )));
    }
    if instance.enrollment_signer
        && !instance
            .endpoints
            .iter()
            .any(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
    {
        return Err(ControlPlaneError::Store(format!(
            "enrollment signer service instance {} must advertise a control-plane endpoint",
            instance.instance_id
        )));
    }
    let mut kinds = BTreeSet::new();
    if instance
        .endpoints
        .iter()
        .any(|endpoint| !kinds.insert(endpoint.kind))
    {
        return Err(ControlPlaneError::Store(format!(
            "service instance {} must advertise at most one endpoint per service kind",
            instance.instance_id
        )));
    }
    if instance.updated_at > now + chrono::Duration::seconds(5) {
        return Err(ControlPlaneError::Store(format!(
            "service instance {} update timestamp is in the future",
            instance.instance_id
        )));
    }
    if instance.lease_expires_at <= instance.updated_at {
        return Err(ControlPlaneError::Store(format!(
            "service instance {} lease must expire after its update timestamp",
            instance.instance_id
        )));
    }
    if instance
        .lease_expires_at
        .signed_duration_since(instance.updated_at)
        > chrono::Duration::seconds(MAX_SERVICE_LEASE_SECONDS)
    {
        return Err(ControlPlaneError::Store(format!(
            "service instance {} lease exceeds {} seconds",
            instance.instance_id, MAX_SERVICE_LEASE_SECONDS
        )));
    }
    Ok(())
}

fn valid_service_instance_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn select_keycloak_candidates(
    cluster_id: &ClusterId,
    candidates: Vec<KeycloakCandidateLease>,
    desired_replicas: usize,
) -> KeycloakPlacement {
    let mut ranked = candidates
        .into_iter()
        .map(|candidate| {
            let mut digest = Sha256::new();
            digest.update(b"heteronetwork-keycloak-placement-v1");
            digest.update(b"\0");
            digest.update(cluster_id.as_str().as_bytes());
            digest.update(b"\0");
            digest.update(candidate.node_id.as_str().as_bytes());
            (digest.finalize().to_vec(), candidate)
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|(left_score, left), (right_score, right)| {
        right.ready.cmp(&left.ready).then_with(|| {
            right_score
                .cmp(left_score)
                .then_with(|| left.node_id.cmp(&right.node_id))
        })
    });
    let mut replicas = ranked
        .into_iter()
        .take(desired_replicas)
        .map(|(_, candidate)| candidate)
        .collect::<Vec<_>>();
    replicas.sort_by(|left, right| left.node_id.cmp(&right.node_id));

    let mut digest = Sha256::new();
    digest.update(b"heteronetwork-keycloak-placement-id-v1");
    digest.update(b"\0");
    digest.update(cluster_id.as_str().as_bytes());
    for replica in &replicas {
        digest.update(b"\0");
        digest.update(replica.node_id.as_str().as_bytes());
    }
    let placement_id = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    KeycloakPlacement {
        placement_id,
        replicas,
    }
}

fn service_instance_owner_node_id(instance: &ServiceInstance) -> Option<&NodeId> {
    instance
        .owner_node_id
        .as_ref()
        .filter(|node_id| node_id.as_str() == instance.owner_host_id)
}

fn eligible_service_owner_node_ids(
    nodes: &[NodeRecord],
    health_by_node: &BTreeMap<NodeId, NodeHealth>,
    nat_by_node: &BTreeMap<NodeId, NatClassification>,
    cluster_id: &ClusterId,
    now: chrono::DateTime<Utc>,
    policy: &ClusterPolicy,
) -> BTreeSet<NodeId> {
    nodes
        .iter()
        .filter(|node| node.cluster_id == *cluster_id && !node.role.is_client())
        .filter(|node| {
            relay_health_allows(
                health_by_node.get(&node.node_id),
                now,
                policy.relay_health_ttl_seconds,
            )
        })
        .filter(|node| {
            nat_by_node
                .get(&node.node_id)
                .is_some_and(|classification| {
                    service_owner_is_publicly_reachable(node, classification, now, policy)
                })
        })
        .map(|node| node.node_id.clone())
        .collect()
}

fn service_owner_is_publicly_reachable(
    node: &NodeRecord,
    classification: &NatClassification,
    now: chrono::DateTime<Utc>,
    policy: &ClusterPolicy,
) -> bool {
    classification
        .publicly_reachable_ip()
        .is_some_and(|public_ip| {
            socket_addr_is_globally_routable(std::net::SocketAddr::new(public_ip, 1))
                && nat_classification_is_fresh(
                    classification,
                    now,
                    policy.nat_classification_ttl_seconds,
                )
                && classification.confidence.is_finite()
                && classification.confidence * 100.0
                    >= f32::from(policy.nat_classification_min_confidence_percent)
                && node.endpoint_candidates.iter().any(|candidate| {
                    candidate.node_id == node.node_id
                        && candidate.kind == EndpointCandidateKind::PublicUdp
                        && candidate.addr.ip() == public_ip
                        && candidate.validate_kind_address().is_ok()
                        && socket_addr_is_globally_routable(candidate.addr)
                        && endpoint_candidate_is_fresh(
                            candidate,
                            now,
                            policy.endpoint_candidate_ttl_seconds,
                        )
                })
        })
}

fn service_instance_kind_count(
    instances: &[ServiceInstance],
    kind: BootstrapEndpointKind,
) -> usize {
    instances
        .iter()
        .filter(|instance| {
            instance
                .endpoints
                .iter()
                .any(|endpoint| endpoint.kind == kind)
        })
        .filter_map(service_instance_owner_node_id)
        .collect::<BTreeSet<_>>()
        .len()
}

fn full_service_owner_node_count(instances: &[ServiceInstance]) -> usize {
    let mut kinds_by_owner = BTreeMap::<&NodeId, BTreeSet<BootstrapEndpointKind>>::new();
    for instance in instances {
        let Some(owner_node_id) = service_instance_owner_node_id(instance) else {
            continue;
        };
        let kinds = kinds_by_owner.entry(owner_node_id).or_default();
        kinds.extend(instance.endpoints.iter().map(|endpoint| endpoint.kind));
    }
    kinds_by_owner
        .values()
        .filter(|kinds| {
            REQUIRED_HA_SERVICE_KINDS
                .iter()
                .all(|kind| kinds.contains(kind))
        })
        .count()
}

fn validate_cluster_policy(policy: &ClusterPolicy) -> Result<(), ControlPlaneError> {
    if !(MIN_OVERLAY_BLOCK_SIZE..=MAX_OVERLAY_BLOCK_SIZE).contains(&policy.overlay_block_size) {
        return Err(ControlPlaneError::InvalidClusterPolicy(format!(
            "overlay_block_size must be between {MIN_OVERLAY_BLOCK_SIZE} and {MAX_OVERLAY_BLOCK_SIZE}"
        )));
    }
    if !SUPPORTED_MAX_DEGREES.contains(&usize::from(policy.overlay_max_degree)) {
        return Err(ControlPlaneError::InvalidClusterPolicy(format!(
            "overlay_max_degree must be one of {:?}",
            SUPPORTED_MAX_DEGREES
        )));
    }
    if policy.overlay_direct_shortcut_limit > MAX_OVERLAY_DEGREE {
        return Err(ControlPlaneError::InvalidClusterPolicy(format!(
            "overlay_direct_shortcut_limit must be at most {MAX_OVERLAY_DEGREE}"
        )));
    }
    if policy.overlay_on_demand_peer_limit > MAX_OVERLAY_DEGREE {
        return Err(ControlPlaneError::InvalidClusterPolicy(format!(
            "overlay_on_demand_peer_limit must be at most {MAX_OVERLAY_DEGREE}"
        )));
    }
    if policy.overlay_route_scopes.len() > MAX_OVERLAY_ROUTE_SCOPES {
        return Err(ControlPlaneError::InvalidClusterPolicy(format!(
            "overlay_route_scopes must contain at most {MAX_OVERLAY_ROUTE_SCOPES} CIDRs"
        )));
    }
    let mut accepted_scopes = Vec::new();
    for scope in &policy.overlay_route_scopes {
        if let Some(reason) = restricted_advertised_route_cidr_reason(scope) {
            return Err(ControlPlaneError::InvalidClusterPolicy(format!(
                "overlay route scope {scope} includes {reason} addresses"
            )));
        }
        let canonical = scope.trunc();
        if scope != &canonical {
            return Err(ControlPlaneError::InvalidClusterPolicy(format!(
                "overlay route scope {scope} must be canonical {canonical}"
            )));
        }
        if let Some(existing) = accepted_scopes
            .iter()
            .find(|existing| ipnets_overlap(existing, scope))
        {
            return Err(ControlPlaneError::InvalidClusterPolicy(format!(
                "overlay route scope {scope} overlaps {existing}"
            )));
        }
        accepted_scopes.push(*scope);
    }
    for (name, value) in [
        ("idle_timeout_seconds", policy.idle_timeout_seconds),
        ("relay_health_ttl_seconds", policy.relay_health_ttl_seconds),
        (
            "endpoint_candidate_ttl_seconds",
            policy.endpoint_candidate_ttl_seconds,
        ),
        ("path_state_ttl_seconds", policy.path_state_ttl_seconds),
        (
            "path_quality_observation_ttl_seconds",
            policy.path_quality_observation_ttl_seconds,
        ),
        (
            "nat_classification_ttl_seconds",
            policy.nat_classification_ttl_seconds,
        ),
    ] {
        if value == 0 {
            return Err(ControlPlaneError::InvalidClusterPolicy(format!(
                "{name} must be greater than zero"
            )));
        }
    }
    if policy.nat_classification_min_confidence_percent > 100 {
        return Err(ControlPlaneError::InvalidClusterPolicy(
            "nat_classification_min_confidence_percent must be at most 100".to_string(),
        ));
    }
    if policy.acl_rules.len() > 256 {
        return Err(ControlPlaneError::InvalidClusterPolicy(
            "acl_rules must contain at most 256 rules".to_string(),
        ));
    }

    let mut rule_ids = BTreeSet::new();
    for rule in &policy.acl_rules {
        if rule.protocol != TransportProtocol::Any {
            return Err(ControlPlaneError::InvalidClusterPolicy(format!(
                "ACL rule {:?} uses protocol {:?}; the WireGuard dataplane currently supports only protocol=any ACL rules",
                rule.id, rule.protocol
            )));
        }
        if rule.id.is_empty() || rule.id.len() > 128 {
            return Err(ControlPlaneError::InvalidClusterPolicy(format!(
                "ACL rule IDs must be 1 to 128 bytes: {:?}",
                rule.id
            )));
        }
        if rule
            .id
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(ControlPlaneError::InvalidClusterPolicy(format!(
                "ACL rule ID {:?} contains whitespace or control characters",
                rule.id
            )));
        }
        if !rule_ids.insert(&rule.id) {
            return Err(ControlPlaneError::InvalidClusterPolicy(format!(
                "ACL rule ID {:?} is duplicated",
                rule.id
            )));
        }
        if rule.routes.len() > 256 {
            return Err(ControlPlaneError::InvalidClusterPolicy(format!(
                "ACL rule {:?} contains more than 256 routes",
                rule.id
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
struct PeerMapVisibilityMetrics {
    peer_candidates: usize,
    visible_peers: usize,
    acl_denied_peers: usize,
    route_candidates: usize,
    visible_routes: usize,
    acl_denied_routes: usize,
}

fn peer_map_visibility_metrics(
    nodes: &[NodeRecord],
    policy: &ClusterPolicy,
) -> PeerMapVisibilityMetrics {
    let mut metrics = PeerMapVisibilityMetrics::default();
    for source in nodes {
        for target in nodes {
            if source.node_id == target.node_id {
                continue;
            }
            metrics.peer_candidates += 1;
            metrics.route_candidates += target.routes.len();

            if policy.acl_rules.is_empty() {
                metrics.visible_peers += 1;
                metrics.visible_routes += target.routes.len();
                continue;
            }

            let peer_allowed = acl_allows_peer(source, target, policy);
            let visible_routes = target
                .routes
                .iter()
                .filter(|route| acl_allows_route(source, target, route, policy))
                .count();
            let route_denials = target.routes.len().saturating_sub(visible_routes);
            metrics.visible_routes += visible_routes;
            metrics.acl_denied_routes += route_denials;

            if peer_allowed || visible_routes > 0 {
                metrics.visible_peers += 1;
            } else {
                metrics.acl_denied_peers += 1;
            }
        }
    }
    metrics
}

fn filter_served_endpoint_candidates(
    mut node: NodeRecord,
    now: chrono::DateTime<Utc>,
    policy: &ClusterPolicy,
) -> NodeRecord {
    node.endpoint_candidates.retain(|candidate| {
        endpoint_candidate_is_fresh(candidate, now, policy.endpoint_candidate_ttl_seconds)
            && endpoint_addr_is_usable(candidate.addr)
    });
    node
}

fn endpoint_candidate_is_fresh(
    candidate: &EndpointCandidate,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> bool {
    match now.signed_duration_since(candidate.observed_at).to_std() {
        Ok(age) => age <= Duration::from_secs(ttl_seconds),
        Err(_) => true,
    }
}

fn topology_edge_observation(
    paths: &[&PathRecord],
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> (
    ControlPlaneTopologyEdgeStatus,
    Vec<PathState>,
    Option<chrono::DateTime<Utc>>,
) {
    if paths.is_empty() {
        return (ControlPlaneTopologyEdgeStatus::Unknown, Vec::new(), None);
    }

    let path_states = paths
        .iter()
        .map(|path| path.selected_state)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let last_observed_at = paths.iter().map(|path| path.updated_at).max();
    let fresh = paths
        .iter()
        .copied()
        .filter(|path| path_is_fresh(path, now, ttl_seconds))
        .collect::<Vec<_>>();
    if fresh.is_empty() {
        return (
            ControlPlaneTopologyEdgeStatus::Stale,
            path_states,
            last_observed_at,
        );
    }

    let reachable_reporters = fresh
        .iter()
        .filter(|path| path.selected_state != PathState::Unreachable)
        .map(|path| &path.key.local)
        .collect::<BTreeSet<_>>();
    let status = if reachable_reporters.is_empty() {
        ControlPlaneTopologyEdgeStatus::Unreachable
    } else if reachable_reporters.len() >= 2 {
        ControlPlaneTopologyEdgeStatus::Connected
    } else {
        ControlPlaneTopologyEdgeStatus::Partial
    };
    (status, path_states, last_observed_at)
}

fn path_is_fresh(path: &PathRecord, now: chrono::DateTime<Utc>, ttl_seconds: u64) -> bool {
    match now.signed_duration_since(path.updated_at).to_std() {
        Ok(age) => age <= Duration::from_secs(ttl_seconds),
        Err(_) => true,
    }
}

fn timestamp_is_fresh(
    timestamp: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> bool {
    match now.signed_duration_since(timestamp).to_std() {
        Ok(age) => age <= Duration::from_secs(ttl_seconds),
        Err(_) => true,
    }
}

fn lazy_connect_local_activity_at(
    path: &PathRecord,
) -> Result<Option<chrono::DateTime<Utc>>, String> {
    let mut activity_at = None;
    for reason in &path.score.reasons {
        let Some(raw_timestamp) = reason.strip_prefix(LAZY_CONNECT_LOCAL_ACTIVITY_REASON_PREFIX)
        else {
            continue;
        };
        if activity_at.is_some() {
            return Err(format!(
                "path {} -> {} has multiple lazy-connect activity reasons",
                path.key.local, path.key.remote
            ));
        }
        let timestamp_millis = raw_timestamp.parse::<i64>().map_err(|_| {
            format!(
                "path {} -> {} has an invalid lazy-connect activity timestamp",
                path.key.local, path.key.remote
            )
        })?;
        activity_at = Some(
            chrono::DateTime::<Utc>::from_timestamp_millis(timestamp_millis).ok_or_else(|| {
                format!(
                    "path {} -> {} has an out-of-range lazy-connect activity timestamp",
                    path.key.local, path.key.remote
                )
            })?,
        );
    }
    Ok(activity_at)
}

fn nat_classification_is_fresh(
    classification: &NatClassification,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> bool {
    match now
        .signed_duration_since(classification.assessed_at)
        .to_std()
    {
        Ok(age) => age <= Duration::from_secs(ttl_seconds),
        Err(_) => true,
    }
}

fn timestamp_within_skew(
    timestamp: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
    max_skew: Duration,
) -> bool {
    let Ok(max_skew) = chrono::Duration::from_std(max_skew) else {
        return false;
    };
    timestamp >= now - max_skew && timestamp <= now + max_skew
}

fn ensure_heartbeat_is_newer(
    update: &HeartbeatStoreUpdate,
    previous_signature_at: Option<chrono::DateTime<Utc>>,
    previous_health: Option<&NodeHealth>,
) -> Result<(), ControlPlaneError> {
    if let Some(accepted_signature_at) = update.accepted_signature_at {
        if let Some(previous_signature_at) = previous_signature_at {
            if accepted_signature_at <= previous_signature_at {
                return Err(ControlPlaneError::NodeSignatureRejected {
                    node_id: update.node_id.clone(),
                    reason: format!(
                        "signed_at {accepted_signature_at} is not newer than last accepted heartbeat {previous_signature_at}"
                    ),
                });
            }
        }
    } else if previous_health
        .is_some_and(|previous| update.health.last_seen_at <= previous.last_seen_at)
    {
        return Err(ControlPlaneError::NodeSignatureRejected {
            node_id: update.node_id.clone(),
            reason: "unsigned heartbeat was received before the current health snapshot"
                .to_string(),
        });
    }
    Ok(())
}

fn timestamp_not_after_skew(
    timestamp: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
    max_skew: Duration,
) -> bool {
    let Ok(max_skew) = chrono::Duration::from_std(max_skew) else {
        return false;
    };
    timestamp <= now + max_skew
}

fn validate_node_health_shape(
    health: &NodeHealth,
    now: chrono::DateTime<Utc>,
    max_timestamp_skew: Duration,
) -> Result<(), String> {
    if !timestamp_not_after_skew(health.last_seen_at, now, max_timestamp_skew) {
        return Err(format!(
            "health last_seen_at {} is too far in the future",
            health.last_seen_at
        ));
    }
    if let Some(latency_ms) = health.latency_ms {
        if !latency_ms.is_finite() || latency_ms < 0.0 {
            return Err("health latency_ms must be a finite non-negative value".to_string());
        }
    }
    if let Some(relay_load) = health.relay_load {
        if !relay_load.is_finite() || !(0.0..=1.0).contains(&relay_load) {
            return Err("health relay_load must be a finite value between 0 and 1".to_string());
        }
    }
    Ok(())
}

fn validate_path_score_shape(path: &PathRecord) -> Result<(), String> {
    if path.score.value.is_nan() || path.score.value == f32::INFINITY {
        return Err(format!(
            "path {} -> {} score value must not be NaN or positive infinity",
            path.key.local, path.key.remote
        ));
    }
    if path.score.value == f32::NEG_INFINITY
        && !path
            .score
            .reasons
            .iter()
            .any(|reason| reason == "policy_denied")
    {
        return Err(format!(
            "path {} -> {} negative-infinity score requires policy_denied reason",
            path.key.local, path.key.remote
        ));
    }
    if path.score.reasons.len() > MAX_PATH_SCORE_REASONS {
        return Err(format!(
            "path {} -> {} score reasons must not exceed {} entries",
            path.key.local, path.key.remote, MAX_PATH_SCORE_REASONS
        ));
    }
    let mut total_bytes = 0usize;
    for reason in &path.score.reasons {
        let reason_bytes = reason.len();
        total_bytes = total_bytes.saturating_add(reason_bytes);
        if reason_bytes > MAX_PATH_SCORE_REASON_BYTES {
            return Err(format!(
                "path {} -> {} score reason must not exceed {} bytes",
                path.key.local, path.key.remote, MAX_PATH_SCORE_REASON_BYTES
            ));
        }
        if reason.chars().any(char::is_control) {
            return Err(format!(
                "path {} -> {} score reason must not contain control characters",
                path.key.local, path.key.remote
            ));
        }
    }
    if total_bytes > MAX_PATH_SCORE_TOTAL_REASON_BYTES {
        return Err(format!(
            "path {} -> {} score reasons must not exceed {} total bytes",
            path.key.local, path.key.remote, MAX_PATH_SCORE_TOTAL_REASON_BYTES
        ));
    }
    Ok(())
}

fn relay_candidate_allowed(
    node: &NodeRecord,
    health: Option<&NodeHealth>,
    now: chrono::DateTime<Utc>,
    policy: &ClusterPolicy,
) -> bool {
    node.relay_capability
        .as_ref()
        .is_some_and(|capability| capability.is_eligible_relay())
        && relay_health_allows(health, now, policy.relay_health_ttl_seconds)
}

fn relay_health_allows(
    health: Option<&NodeHealth>,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u64,
) -> bool {
    let Some(health) = health else {
        return false;
    };
    if health.state != HealthState::Healthy {
        return false;
    }
    match now.signed_duration_since(health.last_seen_at).to_std() {
        Ok(age) => age <= Duration::from_secs(ttl_seconds),
        Err(_) => true,
    }
}

fn overlay_route_is_self_owned(node: &NodeRecord, route: &Route) -> bool {
    route.advertised_by == node.node_id && route.via.as_ref().is_none_or(|via| via == &node.node_id)
}

fn aggregate_overlay_routes(nodes: &[NodeRecord]) -> Vec<AggregateOverlayRoute> {
    let canonical_cidrs = nodes
        .iter()
        .flat_map(|node| {
            node.routes
                .iter()
                .filter(|route| overlay_route_is_self_owned(node, route))
                .map(|route| route.cidr.trunc())
        })
        .collect::<Vec<_>>();
    IpNet::aggregate(&canonical_cidrs)
        .into_iter()
        .map(|cidr| AggregateOverlayRoute { cidr })
        .collect()
}

pub fn overlay_route_catalog_epoch(nodes: &[NodeRecord]) -> Result<u64, ControlPlaneError> {
    let mut ordered = nodes.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    let material = ordered
        .into_iter()
        .map(|node| {
            (
                &node.node_id,
                node.vpn_ip,
                &node.role,
                &node.tags,
                &node.wireguard_public_key,
                &node.routes,
            )
        })
        .collect::<Vec<_>>();
    let encoded = serde_json::to_vec(&material).map_err(|error| {
        ControlPlaneError::Store(format!("failed to encode overlay route catalog: {error}"))
    })?;
    Ok(overlay_epoch_digest(
        b"HeteroNetwork overlay route catalog v1",
        &encoded,
    ))
}

#[cfg(test)]
fn overlay_routing_epoch(
    route_catalog_epoch: u64,
    policy: &ClusterPolicy,
) -> Result<u64, ControlPlaneError> {
    let policy_material = serde_json::to_vec(&(&policy.acl_rules, &policy.overlay_route_scopes))
        .map_err(|error| {
            ControlPlaneError::Store(format!("failed to encode overlay routing policy: {error}"))
        })?;
    let mut material = route_catalog_epoch.to_be_bytes().to_vec();
    material.extend_from_slice(&policy_material);
    Ok(overlay_epoch_digest(
        b"HeteroNetwork overlay routing epoch v1",
        &material,
    ))
}

fn overlay_membership_epoch<'a>(node_ids: impl IntoIterator<Item = &'a str>) -> u64 {
    let mut material = Vec::new();
    for node_id in node_ids {
        material.extend_from_slice(&(node_id.len() as u64).to_be_bytes());
        material.extend_from_slice(node_id.as_bytes());
    }
    overlay_epoch_digest(b"HeteroNetwork overlay membership v1", &material)
}

fn overlay_epoch_digest(domain: &[u8], material: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((material.len() as u64).to_be_bytes());
    hasher.update(material);
    let digest = hasher.finalize();
    let mut epoch = [0_u8; 8];
    epoch.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(epoch)
}

fn ipv4_prefix_key(address: Ipv4Addr, prefix_len: u8) -> u32 {
    let address = u32::from(address);
    if prefix_len == 0 {
        0
    } else {
        address & (u32::MAX << (u32::BITS - u32::from(prefix_len)))
    }
}

fn ipv6_prefix_key(address: Ipv6Addr, prefix_len: u8) -> u128 {
    let address = u128::from(address);
    if prefix_len == 0 {
        0
    } else {
        address & (u128::MAX << (u128::BITS - u32::from(prefix_len)))
    }
}

fn resolve_indexed_route(
    source: &NodeRecord,
    active_nodes: &[NodeRecord],
    active_nodes_by_id: &BTreeMap<NodeId, usize>,
    candidates: &[IndexedOverlayRoute],
    destination: IpAddr,
    policy: &ClusterPolicy,
) -> Option<NodeRecord> {
    for candidate in candidates {
        let Some(target) = active_nodes_by_id
            .get(&candidate.node_id)
            .and_then(|index| active_nodes.get(*index))
        else {
            continue;
        };
        if target.node_id == source.node_id
            || (!policy.acl_rules.is_empty()
                && !acl_allows_route_destination(
                    source,
                    target,
                    &candidate.route,
                    destination,
                    policy,
                ))
        {
            continue;
        }
        let mut target = target.clone();
        let mut route = candidate.route.clone();
        if !policy.acl_rules.is_empty() {
            route.id = overlay_destination_route_id(destination);
            route.cidr = overlay_destination_host_cidr(destination);
        }
        target.routes = vec![route];
        return Some(target);
    }
    None
}

fn overlay_destination_route_id(destination: IpAddr) -> String {
    match destination {
        IpAddr::V4(destination) => format!("overlay-v4-{:08x}", u32::from(destination)),
        IpAddr::V6(destination) => format!("overlay-v6-{:032x}", u128::from(destination)),
    }
}

fn overlay_destination_host_cidr(destination: IpAddr) -> IpNet {
    match destination {
        IpAddr::V4(destination) => IpNet::V4(ipnet::Ipv4Net::new_assert(destination, 32)),
        IpAddr::V6(destination) => IpNet::V6(ipnet::Ipv6Net::new_assert(destination, 128)),
    }
}

fn acl_filter_peer(
    source: &NodeRecord,
    target: &NodeRecord,
    policy: &ClusterPolicy,
) -> Option<NodeRecord> {
    if policy.acl_rules.is_empty() {
        return Some(target.clone());
    }

    let peer_allowed = acl_allows_peer(source, target, policy);
    let routes = target
        .routes
        .iter()
        .filter(|route| acl_allows_route(source, target, route, policy))
        .cloned()
        .collect::<Vec<_>>();

    if !peer_allowed && routes.is_empty() {
        return None;
    }

    let mut filtered = target.clone();
    filtered.routes = routes;
    Some(filtered)
}

fn acl_allows_peer(source: &NodeRecord, target: &NodeRecord, policy: &ClusterPolicy) -> bool {
    acl_decision(source, target, None, policy).unwrap_or(false)
}

fn acl_allows_route(
    source: &NodeRecord,
    target: &NodeRecord,
    route: &Route,
    policy: &ClusterPolicy,
) -> bool {
    acl_decision(source, target, Some(route), policy).unwrap_or(false)
}

fn acl_allows_route_destination(
    source: &NodeRecord,
    target: &NodeRecord,
    _route: &Route,
    destination: IpAddr,
    policy: &ClusterPolicy,
) -> bool {
    let mut allowed = None;
    for rule in &policy.acl_rules {
        if !acl_rule_matches_destination(rule, source, target, destination) {
            continue;
        }
        match rule.action {
            AclAction::Deny => return false,
            AclAction::Allow => allowed = Some(true),
        }
    }
    allowed.unwrap_or(false)
}

fn acl_decision(
    source: &NodeRecord,
    target: &NodeRecord,
    route: Option<&Route>,
    policy: &ClusterPolicy,
) -> Option<bool> {
    let mut allowed = None;
    for rule in &policy.acl_rules {
        if !acl_rule_matches(rule, source, target, route) {
            continue;
        }
        match rule.action {
            AclAction::Deny => return Some(false),
            AclAction::Allow => allowed = Some(true),
        }
    }
    allowed
}

fn acl_rule_matches(
    rule: &AclRule,
    source: &NodeRecord,
    target: &NodeRecord,
    route: Option<&Route>,
) -> bool {
    if !acl_rule_matches_node_selectors(rule, source, target) {
        return false;
    }
    match route {
        Some(route) => {
            rule.routes.is_empty()
                || rule.routes.iter().any(|rule_route| match rule.action {
                    AclAction::Allow => ipnet_contains(rule_route, &route.cidr),
                    AclAction::Deny => ipnets_overlap(rule_route, &route.cidr),
                })
        }
        None => rule.routes.is_empty(),
    }
}

fn acl_rule_matches_destination(
    rule: &AclRule,
    source: &NodeRecord,
    target: &NodeRecord,
    destination: IpAddr,
) -> bool {
    acl_rule_matches_node_selectors(rule, source, target)
        && (rule.routes.is_empty()
            || rule
                .routes
                .iter()
                .any(|rule_route| rule_route.contains(&destination)))
}

fn acl_rule_matches_node_selectors(
    rule: &AclRule,
    source: &NodeRecord,
    target: &NodeRecord,
) -> bool {
    if rule.protocol != TransportProtocol::Any {
        return false;
    }
    if !rule.from_roles.is_empty() && !rule.from_roles.contains(&source.role) {
        return false;
    }
    if !rule.to_roles.is_empty() && !rule.to_roles.contains(&target.role) {
        return false;
    }
    if !rule.from_tags.is_empty() && rule.from_tags.is_disjoint(&source.tags) {
        return false;
    }
    if !rule.to_tags.is_empty() && rule.to_tags.is_disjoint(&target.tags) {
        return false;
    }
    true
}

fn ipnet_contains(outer: &IpNet, inner: &IpNet) -> bool {
    match (outer, inner) {
        (IpNet::V4(outer), IpNet::V4(inner)) => {
            outer.prefix_len() <= inner.prefix_len() && outer.contains(&inner.addr())
        }
        (IpNet::V6(outer), IpNet::V6(inner)) => {
            outer.prefix_len() <= inner.prefix_len() && outer.contains(&inner.addr())
        }
        _ => false,
    }
}

fn ipnets_overlap(left: &IpNet, right: &IpNet) -> bool {
    ipnet_contains(left, right) || ipnet_contains(right, left)
}

fn validate_overlay_route_scopes_against_vpn_pool(
    policy: &ClusterPolicy,
    vpn_pool: Ipv4Net,
) -> Result<(), ControlPlaneError> {
    let vpn_pool = IpNet::V4(vpn_pool);
    if let Some(scope) = policy
        .overlay_route_scopes
        .iter()
        .find(|scope| ipnets_overlap(scope, &vpn_pool))
    {
        return Err(ControlPlaneError::InvalidClusterPolicy(format!(
            "overlay route scope {scope} overlaps VPN pool {vpn_pool}"
        )));
    }
    Ok(())
}

fn validate_routes_within_overlay_scopes(
    routes: &[Route],
    policy: &ClusterPolicy,
) -> Result<(), String> {
    if policy.overlay_route_scopes.is_empty() {
        return Ok(());
    }
    if let Some(route) = routes.iter().find(|route| {
        !policy
            .overlay_route_scopes
            .iter()
            .any(|scope| ipnet_contains(scope, &route.cidr))
    }) {
        return Err(format!(
            "route {} CIDR {} is not fully contained in any configured overlay route scope",
            route.id, route.cidr
        ));
    }
    Ok(())
}

fn validate_routes_against_vpn_pool(routes: &[Route], vpn_pool: Ipv4Net) -> Result<(), String> {
    let vpn_pool = IpNet::V4(vpn_pool);
    if let Some(route) = routes
        .iter()
        .find(|route| ipnets_overlap(&route.cidr, &vpn_pool))
    {
        return Err(format!(
            "route {} CIDR {} overlaps VPN pool {vpn_pool}",
            route.id, route.cidr
        ));
    }
    Ok(())
}

fn route_allowed(route: &Route, claims: &JoinTokenClaims) -> bool {
    route_allowed_by_policy(route, &claims.policy)
}

fn route_allowed_by_policy(route: &Route, policy: &ipars_types::TokenPolicy) -> bool {
    policy
        .allowed_routes
        .iter()
        .any(|allowed_route| allowed_route.contains(&route.cidr))
}

fn relay_capability_allowed(
    node_id: &NodeId,
    relay_capability: Option<RelayCapability>,
    claims: &JoinTokenClaims,
) -> Result<Option<RelayCapability>, ControlPlaneError> {
    relay_capability
        .map(|mut capability| {
            if !claims.policy.allow_relay {
                return Err(ControlPlaneError::RelayDenied);
            }
            capability.enabled_by_policy = true;
            validate_relay_capability_shape(&capability).map_err(|reason| {
                ControlPlaneError::NodeRegistrationRejected {
                    node_id: node_id.clone(),
                    reason,
                }
            })?;
            Ok(capability)
        })
        .transpose()
}

fn validate_relay_capability_shape(capability: &RelayCapability) -> Result<(), String> {
    let endpoint = capability
        .public_endpoint
        .ok_or_else(|| "relay public endpoint is required".to_string())?;
    if !endpoint_addr_is_usable(endpoint) {
        return Err("relay public endpoint must be a usable nonzero socket address".to_string());
    }
    let admission_url = capability
        .admission_url
        .as_deref()
        .ok_or_else(|| "relay admission URL is required".to_string())?;
    if !relay_admission_url_is_usable(admission_url) {
        return Err(
            "relay admission URL must be an absolute HTTP(S) URL with a usable endpoint"
                .to_string(),
        );
    }
    if capability.max_sessions == 0 {
        return Err("relay max_sessions must be greater than zero".to_string());
    }
    if capability.active_sessions > capability.max_sessions {
        return Err("relay active_sessions must be less than or equal to max_sessions".to_string());
    }
    if capability.max_mbps == 0 {
        return Err("relay max_mbps must be greater than zero".to_string());
    }
    if !capability.e2e_only {
        return Err("relay capability must advertise e2e_only=true".to_string());
    }
    Ok(())
}

fn validate_registration_request(
    request: &RegisterNodeRequest,
    now: chrono::DateTime<Utc>,
    max_timestamp_skew: Duration,
) -> Result<(), ControlPlaneError> {
    let derived_node_id =
        node_id_from_public_key_b64(&request.identity_public_key).map_err(|error| {
            ControlPlaneError::NodeRegistrationRejected {
                node_id: request.node_id.clone(),
                reason: format!("identity public key is invalid: {error}"),
            }
        })?;
    if derived_node_id != request.node_id {
        return Err(ControlPlaneError::NodeRegistrationRejected {
            node_id: request.node_id.clone(),
            reason: format!("identity public key derives node ID {derived_node_id}"),
        });
    }
    validate_wireguard_public_key_b64(&request.wireguard_public_key).map_err(|error| {
        ControlPlaneError::NodeRegistrationRejected {
            node_id: request.node_id.clone(),
            reason: format!("wireguard public key is invalid: {error}"),
        }
    })?;
    if let Some(candidate) = request
        .candidates
        .iter()
        .find(|candidate| candidate.node_id != request.node_id)
    {
        return Err(ControlPlaneError::NodeRegistrationRejected {
            node_id: request.node_id.clone(),
            reason: format!(
                "candidate belongs to node {} instead of {}",
                candidate.node_id, request.node_id
            ),
        });
    }
    if let Some((candidate, reason)) = request.candidates.iter().find_map(|candidate| {
        candidate
            .validate_kind_address()
            .err()
            .map(|reason| (candidate, reason))
    }) {
        return Err(ControlPlaneError::NodeRegistrationRejected {
            node_id: request.node_id.clone(),
            reason: format!(
                "candidate {:?} at {} is invalid: {reason}",
                candidate.kind, candidate.addr
            ),
        });
    }
    if let Some(candidate) = request
        .candidates
        .iter()
        .find(|candidate| !timestamp_not_after_skew(candidate.observed_at, now, max_timestamp_skew))
    {
        return Err(ControlPlaneError::NodeRegistrationRejected {
            node_id: request.node_id.clone(),
            reason: format!(
                "candidate {:?} at {} observed_at {} is too far in the future",
                candidate.kind, candidate.addr, candidate.observed_at
            ),
        });
    }
    if let Some(classification) = request.nat_classification.as_ref() {
        validate_nat_classification_shape(
            &request.node_id,
            classification,
            now,
            max_timestamp_skew,
        )
        .map_err(|reason| ControlPlaneError::NodeRegistrationRejected {
            node_id: request.node_id.clone(),
            reason,
        })?;
    }
    validate_advertised_routes_shape(&request.node_id, &request.requested_routes).map_err(
        |reason| ControlPlaneError::NodeRegistrationRejected {
            node_id: request.node_id.clone(),
            reason,
        },
    )?;
    if let Some(route) = request
        .requested_routes
        .iter()
        .find(|route| route.advertised_by != request.node_id)
    {
        return Err(ControlPlaneError::NodeRegistrationRejected {
            node_id: request.node_id.clone(),
            reason: format!(
                "route {} is advertised by node {} instead of {}",
                route.id, route.advertised_by, request.node_id
            ),
        });
    }
    Ok(())
}

fn validate_nat_classification_shape(
    _node_id: &NodeId,
    classification: &NatClassification,
    now: chrono::DateTime<Utc>,
    max_timestamp_skew: Duration,
) -> Result<(), String> {
    if !classification.public_state_is_supported() {
        return Err(
            "NAT classification public state requires matching globally routable direct or explicitly mapped observations"
                .to_string(),
        );
    }
    let validate_addr = |addr: std::net::SocketAddr, label: &str| {
        endpoint_addr_is_usable(addr)
            .then_some(())
            .ok_or_else(|| format!("NAT classification {label} {addr} is unusable"))
    };
    if let Some(observed_endpoint) = classification.observed_endpoint {
        validate_addr(observed_endpoint, "observed endpoint")?;
    }
    if !timestamp_not_after_skew(classification.assessed_at, now, max_timestamp_skew) {
        return Err(format!(
            "NAT classification assessed_at {} is too far in the future",
            classification.assessed_at
        ));
    }
    if !classification.confidence.is_finite() || !(0.0..=1.0).contains(&classification.confidence) {
        return Err(
            "NAT classification confidence must be a finite value between 0 and 1".to_string(),
        );
    }
    for observation in &classification.observations {
        validate_addr(observation.stun_server, "probe STUN server")?;
        validate_addr(observation.reflexive_addr, "probe reflexive endpoint")?;
        if !timestamp_not_after_skew(observation.observed_at, now, max_timestamp_skew) {
            return Err(format!(
                "NAT probe observation observed_at {} is too far in the future",
                observation.observed_at
            ));
        }
    }
    for observation in &classification.filtering_observations {
        validate_addr(observation.stun_server, "filtering STUN server")?;
        if let Some(response_origin) = observation.response_origin {
            validate_addr(response_origin, "filtering response origin")?;
        }
        if let Some(other_address) = observation.other_address {
            validate_addr(other_address, "filtering other address")?;
        }
        if !timestamp_not_after_skew(observation.observed_at, now, max_timestamp_skew) {
            return Err(format!(
                "NAT filtering observation observed_at {} is too far in the future",
                observation.observed_at
            ));
        }
    }
    Ok(())
}

fn validate_advertised_routes_shape(node_id: &NodeId, routes: &[Route]) -> Result<(), String> {
    if routes.len() > MAX_OVERLAY_NODE_ROUTES {
        return Err(format!(
            "route list for node {node_id} contains {} routes; maximum is {MAX_OVERLAY_NODE_ROUTES}",
            routes.len()
        ));
    }
    let mut seen_route_ids = BTreeSet::new();
    let mut seen_route_cidrs = BTreeSet::new();
    for route in routes {
        validate_advertised_route_id(&route.id)?;
        if !seen_route_ids.insert(route.id.as_str()) {
            return Err(format!("route list must not repeat route ID {}", route.id));
        }
        if route.metric == 0 {
            return Err(format!(
                "route {} metric must be greater than zero",
                route.id
            ));
        }
        if let Some(reason) = restricted_advertised_route_cidr_reason(&route.cidr) {
            return Err(format!(
                "route {} must not include {reason} CIDR {}",
                route.id, route.cidr
            ));
        }
        let canonical = route.cidr.trunc();
        if route.cidr != canonical {
            return Err(format!(
                "route {} must use canonical CIDR {canonical}, not {}",
                route.id, route.cidr
            ));
        }
        if !seen_route_cidrs.insert(route.cidr) {
            return Err(format!(
                "route list for node {node_id} must not repeat CIDR {}",
                route.cidr
            ));
        }
    }
    Ok(())
}

fn restricted_advertised_route_cidr_reason(cidr: &IpNet) -> Option<&'static str> {
    if cidr.prefix_len() == 0 {
        return Some("unrestricted");
    }
    match cidr {
        IpNet::V4(network) => restricted_advertised_ipv4_route_cidr_reason(network),
        IpNet::V6(network) => restricted_advertised_ipv6_route_cidr_reason(network),
    }
}

fn restricted_advertised_ipv4_route_cidr_reason(network: &ipnet::Ipv4Net) -> Option<&'static str> {
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

fn restricted_advertised_ipv6_route_cidr_reason(network: &ipnet::Ipv6Net) -> Option<&'static str> {
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

fn validate_advertised_route_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("route ID cannot be empty".to_string());
    }
    if id.len() > 128 {
        return Err("route ID exceeds 128 bytes".to_string());
    }
    if matches!(id, "." | "..") {
        return Err("route ID must not be '.' or '..'".to_string());
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(
            "route ID must contain only ASCII letters, digits, '.', '_', ':' or '-'".to_string(),
        );
    }
    Ok(())
}

fn token_key(cluster_id: &ClusterId, nonce: &str) -> String {
    format!("{cluster_id}:{nonce}")
}

#[derive(Debug, Clone)]
struct VpnAllocator {
    pool: Ipv4Net,
    next_host_offset: u32,
}

impl VpnAllocator {
    fn new(pool: Ipv4Net) -> Self {
        Self {
            pool,
            next_host_offset: 1,
        }
    }

    fn allocate_next(&mut self, reserved: &BTreeSet<Ipv4Addr>) -> Result<VpnIp, ControlPlaneError> {
        let network = u32::from(self.pool.network());
        let broadcast = u32::from(self.pool.broadcast());

        while network.saturating_add(self.next_host_offset) < broadcast {
            let candidate = network + self.next_host_offset;
            self.next_host_offset += 1;
            let candidate = Ipv4Addr::from(candidate);
            if reserved.contains(&candidate) {
                continue;
            }
            return Ok(VpnIp(IpAddr::V4(candidate)));
        }

        Err(ControlPlaneError::VpnPoolExhausted)
    }
}

fn assigned_ipv4_vpn_ips(nodes: &[NodeRecord]) -> BTreeSet<Ipv4Addr> {
    nodes
        .iter()
        .filter_map(|node| match node.vpn_ip.0 {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect()
}

fn vpn_pool_usable_host_count(pool: Ipv4Net) -> u64 {
    let network = u32::from(pool.network());
    let broadcast = u32::from(pool.broadcast());
    broadcast.saturating_sub(network).saturating_sub(1) as u64
}

fn vpn_pool_contains_usable_host(pool: Ipv4Net, ip: Ipv4Addr) -> bool {
    let ip = u32::from(ip);
    let network = u32::from(pool.network());
    let broadcast = u32::from(pool.broadcast());
    ip > network && ip < broadcast
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, Ordering};

    use chrono::{Duration, Utc};
    use ipars_crypto::{encode_bytes, IdentityKeyPair};
    use ipars_types::api::{
        ClientControlRequest, ClientRegistrationBundle, ClientRequestKind, HeartbeatRequest,
        NodeServiceAdvertisement, RegisterClientRequest, RegisterNodeRequest, RemoveNodeRequest,
        RevokeTokenRequest, RotateWireGuardKeyRequest, SponsoredClientRegistrationRequest,
        CLIENT_REGISTRATION_SCHEMA_VERSION,
    };
    use ipars_types::{
        AclAction, AclRule, BootstrapEndpoint, BootstrapEndpointKind, CandidateSource,
        EndpointCandidate, EndpointCandidateKind, HealthState, KeyId, NatConnectivityState,
        NatProbeObservation, NodeHealth, PathMetrics, PathRecord, PathScore, PathState,
        PeerPathKey, RelayCapability, Role, Tag, TokenPolicy, TransportProtocol,
        DEFAULT_OVERLAY_BLOCK_SIZE, MAX_JOIN_TOKEN_IDENTIFIER_BYTES,
    };

    use super::*;

    fn claims(cluster_id: ClusterId) -> JoinTokenClaims {
        let mut tags = BTreeSet::new();
        tags.insert(Tag::from_string("edge"));
        JoinTokenClaims {
            cluster_id,
            bootstrap_endpoints: vec![BootstrapEndpoint {
                url: "https://203.0.113.10:8443".to_string(),
                kind: BootstrapEndpointKind::ControlPlane,
            }],
            expires_at: Utc::now() + Duration::minutes(5),
            not_before: Utc::now() - Duration::seconds(1),
            role: Role::edge(),
            tags,
            issuer: NodeId::from_string("issuer"),
            key_id: KeyId::from_string("root"),
            policy: TokenPolicy::default(),
            nonce: "test".to_string(),
        }
    }

    fn claims_for_issuer(
        cluster_id: ClusterId,
        issuer: NodeId,
        key_id: KeyId,
        nonce: &str,
    ) -> JoinTokenClaims {
        let mut claims = claims(cluster_id);
        claims.issuer = issuer;
        claims.key_id = key_id;
        claims.nonce = nonce.to_string();
        claims
    }

    fn node_enrollment_claims(
        cluster_id: ClusterId,
        issuer: NodeId,
        key_id: KeyId,
        nonce: &str,
        now: chrono::DateTime<Utc>,
    ) -> JoinTokenClaims {
        let mut tags = BTreeSet::new();
        tags.insert(Tag::from_string("edge"));
        JoinTokenClaims {
            cluster_id,
            bootstrap_endpoints: vec![
                BootstrapEndpoint {
                    url: "https://203.0.113.10:8443".to_string(),
                    kind: BootstrapEndpointKind::ControlPlane,
                },
                BootstrapEndpoint {
                    url: "https://203.0.113.11:8443".to_string(),
                    kind: BootstrapEndpointKind::ControlPlane,
                },
                BootstrapEndpoint {
                    url: "https://203.0.113.10:9443".to_string(),
                    kind: BootstrapEndpointKind::Signal,
                },
                BootstrapEndpoint {
                    url: "https://203.0.113.11:9443".to_string(),
                    kind: BootstrapEndpointKind::Signal,
                },
                BootstrapEndpoint {
                    url: "udp://203.0.113.10:3478".to_string(),
                    kind: BootstrapEndpointKind::Stun,
                },
                BootstrapEndpoint {
                    url: "udp://203.0.113.11:3478".to_string(),
                    kind: BootstrapEndpointKind::Stun,
                },
            ],
            expires_at: now + Duration::hours(1),
            not_before: now - Duration::seconds(JOIN_TOKEN_NOT_BEFORE_SKEW_SECONDS),
            role: Role::edge(),
            tags: tags.clone(),
            issuer,
            key_id,
            policy: TokenPolicy {
                allow_join: true,
                allow_relay: false,
                allowed_routes: Vec::new(),
                allowed_tags: tags,
                max_token_uses: Some(10),
            },
            nonce: nonce.to_string(),
        }
    }

    fn registration_request(node_id: &str) -> RegisterNodeRequest {
        let identity = identity_for_node(node_id);
        RegisterNodeRequest {
            node_id: identity.node_id(),
            identity_public_key: identity.public_key_b64(),
            wireguard_public_key: wireguard_public_key_for_node(node_id),
            candidates: Vec::new(),
            nat_classification: None,
            relay_capability: None,
            requested_routes: Vec::new(),
        }
    }

    fn node_record(node_id: &str) -> NodeRecord {
        let identity = identity_for_node(node_id);
        NodeRecord {
            node_id: identity.node_id(),
            hostname: None,
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
            identity_public_key: identity.public_key_b64(),
            wireguard_public_key: wireguard_public_key_for_node(node_id),
            role: Role::edge(),
            tags: BTreeSet::new(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        }
    }

    fn identity_for_node(node_id: &str) -> IdentityKeyPair {
        let mut seed = [0_u8; 32];
        for (index, byte) in node_id.as_bytes().iter().enumerate() {
            seed[index % seed.len()] = seed[index % seed.len()].wrapping_add(*byte);
        }
        if seed.iter().all(|byte| *byte == 0) {
            seed[0] = 1;
        }
        IdentityKeyPair::from_signing_bytes(seed)
    }

    fn wireguard_public_key_for_node(node_id: &str) -> String {
        let mut bytes = [0_u8; 32];
        for (index, byte) in format!("wg-{node_id}").as_bytes().iter().enumerate() {
            bytes[index % 32] = bytes[index % 32].wrapping_add(*byte);
        }
        if bytes.iter().all(|byte| *byte == 0) {
            bytes[0] = 1;
        }
        encode_bytes(&bytes)
    }

    fn node_id(label: &str) -> NodeId {
        identity_for_node(label).node_id()
    }

    #[test]
    fn keycloak_placement_is_bounded_stable_and_replaces_only_failed_replica() {
        let cluster_id = ClusterId::from_string("cluster-keycloak");
        let now = Utc::now();
        let candidates = (1..=6)
            .map(|index| KeycloakCandidateLease {
                cluster_id: cluster_id.clone(),
                node_id: NodeId::from_string(format!("keycloak-{index}")),
                vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(10, 250, 0, index))),
                version: "26.6.4".to_string(),
                ready: index <= 3,
                eligible: true,
                generation: i64::from(index),
                lease_expires_at: now + Duration::seconds(45),
                updated_at: now,
            })
            .collect::<Vec<_>>();
        let first = select_keycloak_candidates(&cluster_id, candidates.clone(), 3);
        assert_eq!(first.replicas.len(), 3);
        assert_eq!(
            first
                .replicas
                .iter()
                .filter(|candidate| candidate.ready)
                .count(),
            3
        );

        let mut reversed = candidates.clone();
        reversed.reverse();
        let reordered = select_keycloak_candidates(&cluster_id, reversed, 3);
        assert_eq!(reordered.placement_id, first.placement_id);
        assert_eq!(
            reordered
                .replicas
                .iter()
                .map(|candidate| &candidate.node_id)
                .collect::<Vec<_>>(),
            first
                .replicas
                .iter()
                .map(|candidate| &candidate.node_id)
                .collect::<Vec<_>>()
        );

        let failed = first.replicas[0].node_id.clone();
        let after_failure = select_keycloak_candidates(
            &cluster_id,
            candidates
                .into_iter()
                .filter(|candidate| candidate.node_id != failed)
                .collect(),
            3,
        );
        assert_eq!(after_failure.replicas.len(), 3);
        assert_eq!(
            first
                .replicas
                .iter()
                .filter(|candidate| {
                    after_failure
                        .replicas
                        .iter()
                        .any(|replacement| replacement.node_id == candidate.node_id)
                })
                .count(),
            2
        );
        assert_ne!(after_failure.placement_id, first.placement_id);
    }

    #[tokio::test]
    async fn keycloak_placement_scans_past_full_invalid_page(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-keycloak-pages");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 24)?,
            ),
            store.clone(),
        );
        let now = Utc::now();
        for index in 0..64_u8 {
            assert!(
                store
                    .upsert_keycloak_candidate(KeycloakCandidateLease {
                        cluster_id: cluster_id.clone(),
                        node_id: NodeId::from_string(format!("000-invalid-{index:02}")),
                        vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 1, index + 1,))),
                        version: "wrong-version".to_string(),
                        ready: true,
                        eligible: true,
                        generation: 1,
                        lease_expires_at: now + Duration::seconds(45),
                        updated_at: now,
                    })
                    .await?
            );
        }

        let mut expected = Vec::new();
        for index in 0..3 {
            let node = plane
                .register_with_claims(
                    claims(cluster_id.clone()),
                    registration_request(&format!("valid-keycloak-{index}")),
                )
                .await?
                .node;
            store
                .upsert_health(
                    node.node_id.clone(),
                    NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: now,
                        latency_ms: Some(1.0),
                        relay_load: Some(0.0),
                        message: None,
                    },
                )
                .await?;
            assert!(
                store
                    .upsert_keycloak_candidate(KeycloakCandidateLease {
                        cluster_id: cluster_id.clone(),
                        node_id: node.node_id.clone(),
                        vpn_ip: node.vpn_ip,
                        version: "26.6.4".to_string(),
                        ready: true,
                        eligible: true,
                        generation: 1,
                        lease_expires_at: now + Duration::seconds(45),
                        updated_at: now,
                    })
                    .await?
            );
            expected.push(node.node_id);
        }
        expected.sort();

        let placement = plane.keycloak_placement("26.6.4", 3, 64, now).await?;
        assert_eq!(
            placement
                .replicas
                .iter()
                .map(|candidate| candidate.node_id.clone())
                .collect::<Vec<_>>(),
            expected
        );
        Ok(())
    }

    fn signed_heartbeat(label: &str, request: HeartbeatRequest) -> HeartbeatRequest {
        signed_heartbeat_at(label, request, Utc::now())
    }

    fn signed_heartbeat_at(
        label: &str,
        mut request: HeartbeatRequest,
        signed_at: chrono::DateTime<Utc>,
    ) -> HeartbeatRequest {
        let identity = identity_for_node(label);
        request.node_signature = Some(match identity.sign_heartbeat_request(&request, signed_at) {
            Ok(signature) => signature,
            Err(error) => panic!("test identity should sign heartbeat: {error}"),
        });
        request
    }

    fn signed_wireguard_key_rotation(
        label: &str,
        previous_wireguard_public_key: String,
        next_wireguard_public_key: String,
    ) -> RotateWireGuardKeyRequest {
        let identity = identity_for_node(label);
        let mut request = RotateWireGuardKeyRequest {
            node_id: identity.node_id(),
            previous_wireguard_public_key,
            next_wireguard_public_key,
            node_signature: None,
        };
        request.node_signature = Some(
            match identity.sign_wireguard_key_rotation_request(&request, Utc::now()) {
                Ok(signature) => signature,
                Err(error) => panic!("test identity should sign wireguard key rotation: {error}"),
            },
        );
        request
    }

    fn signed_remove_node(label: &str) -> RemoveNodeRequest {
        let identity = identity_for_node(label);
        let mut request = RemoveNodeRequest {
            node_id: identity.node_id(),
            node_signature: None,
        };
        request.node_signature = Some(
            match identity.sign_remove_node_request(&request, Utc::now()) {
                Ok(signature) => signature,
                Err(error) => panic!("test identity should sign node removal: {error}"),
            },
        );
        request
    }

    fn relay_capability() -> RelayCapability {
        RelayCapability {
            enabled_by_policy: false,
            public_endpoint: Some(std::net::SocketAddr::from(([203, 0, 113, 10], 51820))),
            admission_url: Some("http://203.0.113.10:9580".to_string()),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        }
    }

    fn service_instance(
        cluster_id: &ClusterId,
        instance_id: &str,
        host: &str,
        updated_at: chrono::DateTime<Utc>,
        lease_expires_at: chrono::DateTime<Utc>,
    ) -> ServiceInstance {
        let owner_node_id = node_id(instance_id);
        ServiceInstance {
            cluster_id: cluster_id.clone(),
            instance_id: instance_id.to_string(),
            owner_host_id: owner_node_id.as_str().to_string(),
            owner_node_id: Some(owner_node_id),
            enrollment_signer: false,
            endpoints: vec![
                BootstrapEndpoint {
                    kind: BootstrapEndpointKind::ControlPlane,
                    url: format!("https://{host}:8443"),
                },
                BootstrapEndpoint {
                    kind: BootstrapEndpointKind::Signal,
                    url: format!("https://{host}:9443"),
                },
                BootstrapEndpoint {
                    kind: BootstrapEndpointKind::Stun,
                    url: format!("udp://{host}:3478"),
                },
                BootstrapEndpoint {
                    kind: BootstrapEndpointKind::Relay,
                    url: format!("udp://{host}:51820"),
                },
                BootstrapEndpoint {
                    kind: BootstrapEndpointKind::WebUi,
                    url: format!("https://{host}"),
                },
            ],
            lease_expires_at,
            updated_at,
        }
    }

    async fn insert_eligible_service_node(
        store: &InMemoryStore,
        cluster_id: &ClusterId,
        label: &str,
        public_ip: Ipv4Addr,
        observed_at: chrono::DateTime<Utc>,
    ) -> Result<NodeId, ControlPlaneError> {
        let mut node = node_record(label);
        node.cluster_id = cluster_id.clone();
        let public_addr = std::net::SocketAddr::from((public_ip, 51_820));
        node.endpoint_candidates = vec![EndpointCandidate {
            node_id: node.node_id.clone(),
            kind: EndpointCandidateKind::PublicUdp,
            addr: public_addr,
            observed_at,
            priority: 80,
            cost: 20,
            source: CandidateSource::StunProbe,
        }];
        let node_id = node.node_id.clone();
        store.insert_node(node).await?;
        store
            .upsert_health(
                node_id.clone(),
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: observed_at,
                    latency_ms: None,
                    relay_load: None,
                    message: None,
                },
            )
            .await?;
        store
            .upsert_nat_classification(
                node_id.clone(),
                NatClassification::from_observations(
                    public_addr,
                    vec![NatProbeObservation {
                        local_addr: public_addr,
                        stun_server: std::net::SocketAddr::from(([1, 1, 1, 1], 3478)),
                        reflexive_addr: public_addr,
                        observed_at,
                    }],
                    observed_at,
                ),
            )
            .await?;
        Ok(node_id)
    }

    #[tokio::test]
    async fn dynamic_block_policy_is_shared_and_advances_topology_epoch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");
        let vpn_pool = Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 24)?;
        let store = Arc::new(InMemoryStore::default());
        let plane_a = ControlPlane::new(
            ControlPlaneConfig::new(cluster_id.clone(), vpn_pool),
            store.clone(),
        );
        let plane_b =
            ControlPlane::new(ControlPlaneConfig::new(cluster_id.clone(), vpn_pool), store);

        for index in 0..12 {
            let label = format!("block-node-{index}");
            let mut node_claims = claims(cluster_id.clone());
            node_claims.nonce = format!("block-policy-{index}");
            plane_a
                .register_with_claims(node_claims, registration_request(&label))
                .await?;
        }

        let initial = plane_b.overlay_topology_snapshot().await?;
        assert_eq!(initial.fanout, DEFAULT_OVERLAY_BLOCK_SIZE);
        assert!(initial.root_group_id.is_some());
        assert_eq!(initial.groups.len(), initial.group_count);

        let mut policy = plane_a.current_cluster_policy().await?;
        policy.overlay_block_size = 8;
        policy.overlay_on_demand_peer_limit = 7;
        plane_a.set_cluster_policy(policy).await?;

        let observed = plane_b.current_cluster_policy().await?;
        assert_eq!(observed.overlay_block_size, 8);
        assert_eq!(observed.overlay_on_demand_peer_limit, 7);
        let updated = plane_b.overlay_topology_snapshot().await?;
        assert_eq!(updated.fanout, 8);
        assert_eq!(updated.on_demand_peer_limit, 7);
        assert_eq!(updated.groups.len(), updated.group_count);
        assert_ne!(initial.topology_epoch, updated.topology_epoch);
        assert!(updated.max_observed_degree <= usize::from(updated.max_degree));

        for block_size in [3, 65] {
            let mut invalid = observed.clone();
            invalid.overlay_block_size = block_size;
            assert!(matches!(
                plane_a.set_cluster_policy(invalid).await,
                Err(ControlPlaneError::InvalidClusterPolicy(_))
            ));
        }
        assert_eq!(
            plane_b.current_cluster_policy().await?.overlay_block_size,
            8
        );
        let source = plane_b
            .list_nodes()
            .await?
            .into_iter()
            .next()
            .ok_or("registered source node is missing")?;
        assert_eq!(
            plane_b
                .neighbor_map_for(&source.node_id)
                .await?
                .on_demand_peer_limit,
            7
        );

        let mut invalid = observed;
        invalid.overlay_on_demand_peer_limit = MAX_OVERLAY_DEGREE + 1;
        assert!(matches!(
            plane_a.set_cluster_policy(invalid).await,
            Err(ControlPlaneError::InvalidClusterPolicy(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn overlay_topology_cache_reuses_membership_and_rebuilds_for_membership_or_policy(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");
        let vpn_pool = Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 24)?;
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(cluster_id.clone(), vpn_pool),
            store.clone(),
        );

        for index in 0..8 {
            let mut node = node_record(&format!("topology-cache-{index}"));
            node.cluster_id = cluster_id.clone();
            node.vpn_ip = VpnIp(IpAddr::V4(Ipv4Addr::new(
                100,
                64,
                0,
                u8::try_from(index + 1)?,
            )));
            store.insert_node(node).await?;
        }

        let nodes = plane.overlay_nodes().await?;
        let policy = plane.current_cluster_policy().await?;
        let (first, concurrent) = tokio::join!(
            plane.overlay_topology(&nodes, &policy),
            plane.overlay_topology(&nodes, &policy)
        );
        let first = first?;
        let concurrent = concurrent?;
        assert!(Arc::ptr_eq(&first, &concurrent));

        let mut reordered = nodes.clone();
        reordered.reverse();
        let reordered_topology = plane.overlay_topology(&reordered, &policy).await?;
        assert!(Arc::ptr_eq(&first, &reordered_topology));

        let updated_node_id = nodes[0].node_id.clone();
        store
            .update_node_candidates(
                &updated_node_id,
                vec![EndpointCandidate {
                    node_id: updated_node_id.clone(),
                    kind: EndpointCandidateKind::LocalUdp,
                    addr: "10.0.0.10:51820".parse()?,
                    observed_at: Utc::now(),
                    priority: 10,
                    cost: 1,
                    source: CandidateSource::InterfaceScan,
                }],
            )
            .await?;
        store
            .upsert_health(
                updated_node_id,
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now(),
                    latency_ms: Some(1.0),
                    relay_load: None,
                    message: None,
                },
            )
            .await?;
        let refreshed_nodes = plane.overlay_nodes().await?;
        let refreshed_topology = plane.overlay_topology(&refreshed_nodes, &policy).await?;
        assert!(Arc::ptr_eq(&first, &refreshed_topology));

        let mut non_topology_policy = policy.clone();
        non_topology_policy.path_state_ttl_seconds += 1;
        plane
            .set_cluster_policy(non_topology_policy.clone())
            .await?;
        let policy_refreshed_topology = plane
            .overlay_topology(&refreshed_nodes, &non_topology_policy)
            .await?;
        assert!(Arc::ptr_eq(&first, &policy_refreshed_topology));

        let mut added = node_record("topology-cache-added");
        added.cluster_id = cluster_id;
        added.vpn_ip = VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 20)));
        store.insert_node(added).await?;
        plane.invalidate_overlay_node_snapshot().await;
        let expanded_nodes = plane.overlay_nodes().await?;
        let expanded_topology = plane
            .overlay_topology(&expanded_nodes, &non_topology_policy)
            .await?;
        assert!(!Arc::ptr_eq(&first, &expanded_topology));
        assert_ne!(first.topology_epoch(), expanded_topology.topology_epoch());

        let mut changed_policy = non_topology_policy;
        changed_policy.overlay_max_degree = 6;
        plane.set_cluster_policy(changed_policy.clone()).await?;
        let changed_topology = plane
            .overlay_topology(&expanded_nodes, &changed_policy)
            .await?;
        assert!(!Arc::ptr_eq(&expanded_topology, &changed_topology));
        assert_ne!(
            expanded_topology.topology_epoch(),
            changed_topology.topology_epoch()
        );
        Ok(())
    }

    #[tokio::test]
    async fn stale_overlay_node_keeps_recovery_neighbors_but_is_excluded_from_paths(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");
        let vpn_pool = Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 24)?;
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(cluster_id.clone(), vpn_pool),
            store.clone(),
        );
        for index in 0..12 {
            let mut node = node_record(&format!("topology-health-{index}"));
            node.cluster_id = cluster_id.clone();
            node.vpn_ip = VpnIp(IpAddr::V4(Ipv4Addr::new(
                100,
                64,
                0,
                u8::try_from(index + 1)?,
            )));
            store.insert_node(node).await?;
        }

        let policy = plane.current_cluster_policy().await?;
        let initial_nodes = plane.overlay_nodes().await?;
        let initial_topology = plane.overlay_topology(&initial_nodes, &policy).await?;
        assert_eq!(initial_nodes.len(), 12);
        let (source_node, failed_node, target_node) = initial_nodes
            .iter()
            .find_map(|failed| {
                initial_nodes.iter().find_map(|source| {
                    initial_nodes.iter().find_map(|target| {
                        if source.node_id == failed.node_id
                            || target.node_id == failed.node_id
                            || source.node_id == target.node_id
                        {
                            return None;
                        }
                        initial_topology
                            .shortest_path(&source.node_id, &target.node_id)
                            .filter(|path| {
                                path.iter()
                                    .skip(1)
                                    .take(path.len().saturating_sub(2))
                                    .any(|node_id| node_id == &failed.node_id)
                            })
                            .map(|_| (source.clone(), failed.clone(), target.clone()))
                    })
                })
            })
            .ok_or("test topology did not contain an internal transit node")?;
        let healthy_neighbor_id = initial_topology
            .neighbors(&failed_node.node_id)
            .and_then(|neighbors| neighbors.iter().next())
            .cloned()
            .ok_or("failed node did not have a recovery neighbor")?;
        let initial_epoch = initial_topology.topology_epoch();

        store
            .upsert_health(
                failed_node.node_id.clone(),
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now()
                        - Duration::seconds(i64::try_from(policy.relay_health_ttl_seconds)? + 1),
                    latency_ms: None,
                    relay_load: None,
                    message: None,
                },
            )
            .await?;
        plane.invalidate_overlay_node_snapshot().await;
        assert!(plane
            .overlay_nodes()
            .await?
            .iter()
            .all(|node| node.node_id != failed_node.node_id));

        let neighbor_map = plane.neighbor_map_for(&healthy_neighbor_id).await?;
        assert!(neighbor_map
            .neighbors
            .iter()
            .any(|neighbor| neighbor.node.node_id == failed_node.node_id));
        let recovering_map = plane.neighbor_map_for(&failed_node.node_id).await?;
        assert_eq!(
            recovering_map
                .neighbors
                .iter()
                .map(|neighbor| neighbor.node.node_id.clone())
                .collect::<BTreeSet<_>>(),
            initial_topology
                .neighbors(&failed_node.node_id)
                .cloned()
                .unwrap_or_default()
        );
        assert_eq!(recovering_map.topology_epoch, initial_epoch);
        assert!(recovering_map.neighbors.len() <= usize::from(policy.overlay_max_degree));

        let displayed = plane.overlay_topology_snapshot().await?;
        assert_eq!(displayed.node_count, 12);
        assert_eq!(displayed.topology_epoch, initial_epoch.to_string());
        let failed_display = displayed
            .nodes
            .iter()
            .find(|node| node.node_id == failed_node.node_id)
            .ok_or("stale registered node was absent from topology display")?;
        assert_eq!(failed_display.health_state, Some(HealthState::Unhealthy));
        assert!(failed_display.last_seen_at.is_some());

        let path = plane
            .overlay_path_for(&OverlayPathQuery {
                source: source_node.node_id,
                destination: target_node.vpn_ip.0,
                source_identity_proof: ipars_types::api::NodeApiRequestSignature {
                    signed_at: Utc::now(),
                    nonce: "stale-transit-recovery-test".to_string(),
                    signature: String::new(),
                },
            })
            .await?;
        assert!(!path.ordered_nodes.contains(&failed_node.node_id));
        assert!(path
            .secondary_ordered_nodes
            .as_ref()
            .is_none_or(|secondary| !secondary.contains(&failed_node.node_id)));
        Ok(())
    }

    #[tokio::test]
    async fn overlay_topology_cache_memoizes_deterministic_synthesis_errors(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");
        let vpn_pool = Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 24)?;
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(cluster_id.clone(), vpn_pool),
            Arc::new(InMemoryStore::default()),
        );
        let mut nodes = Vec::new();
        for index in 0..8 {
            let mut node = node_record(&format!("topology-error-{index}"));
            node.cluster_id = cluster_id.clone();
            node.vpn_ip = VpnIp(IpAddr::V4(Ipv4Addr::new(
                100,
                64,
                0,
                u8::try_from(index + 1)?,
            )));
            nodes.push(node);
        }
        let invalid_policy = ClusterPolicy {
            overlay_block_size: 3,
            ..ClusterPolicy::default()
        };

        for _ in 0..2 {
            assert!(matches!(
                plane.overlay_topology(&nodes, &invalid_policy).await,
                Err(ControlPlaneError::BoundedTopology(_))
            ));
        }
        let cache = plane.overlay_topology_cache.lock().await;
        assert_eq!(cache.len(), 1);
        assert!(cache.values().all(|cell| cell.initialized()));
        Ok(())
    }

    #[tokio::test]
    async fn overlay_node_snapshot_is_reused_across_a_thousand_pollers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");
        let store = Arc::new(InMemoryStore::default());
        for index in 0..1_000 {
            let mut node = node_record(&format!("snapshot-node-{index:04}"));
            node.cluster_id = cluster_id.clone();
            store.insert_node(node).await?;
        }
        let mut client = node_record("snapshot-client");
        client.cluster_id = cluster_id.clone();
        client.role = Role::client();
        store.insert_node(client).await?;
        let mut foreign = node_record("snapshot-foreign");
        foreign.cluster_id = ClusterId::from_string("cluster-b");
        store.insert_node(foreign).await?;
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(cluster_id, Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 24)?),
            store,
        );

        let policy = plane.current_cluster_policy().await?;
        let routing_epoch = plane
            .store
            .get_overlay_routing_epoch(&plane.config.cluster_id)
            .await?;
        let first = plane.overlay_node_snapshot(&policy, routing_epoch).await?;
        assert_eq!(first.nodes.len(), 1_000);
        assert_eq!(first.nodes_by_id.len(), 1_000);
        assert_eq!(first.clients.len(), 1);
        assert_eq!(first.topology_cache_key.node_count, 1_000);
        for _ in 0..1_000 {
            let cached = plane.overlay_node_snapshot(&policy, routing_epoch).await?;
            assert!(Arc::ptr_eq(&first, &cached));
        }

        plane.invalidate_overlay_node_snapshot().await;
        let refreshed = plane.overlay_node_snapshot(&policy, routing_epoch).await?;
        assert!(!Arc::ptr_eq(&first, &refreshed));
        Ok(())
    }

    #[tokio::test]
    async fn shared_routing_epoch_invalidates_another_replicas_cached_map_and_path(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-shared-routing-epoch");
        let vpn_pool = Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 24)?;
        let store = Arc::new(InMemoryStore::default());
        let plane_a = ControlPlane::new(
            ControlPlaneConfig::new(cluster_id.clone(), vpn_pool),
            store.clone(),
        );
        let plane_b = ControlPlane::new(
            ControlPlaneConfig::new(cluster_id.clone(), vpn_pool),
            store.clone(),
        );
        let mut source = node_record("routing-epoch-source");
        source.cluster_id = cluster_id.clone();
        source.vpn_ip = VpnIp("100.64.0.2".parse()?);
        let mut target = node_record("routing-epoch-target");
        target.cluster_id = cluster_id;
        target.vpn_ip = VpnIp("100.64.0.3".parse()?);
        target.token_policy.allowed_routes = vec!["10.0.0.0/8".parse()?];
        target.routes = vec![route("old-route", "10.42.1.0/24", "routing-epoch-target")?];
        store.insert_node(source.clone()).await?;
        store.insert_node(target.clone()).await?;

        let old_map = plane_a.neighbor_map_for(&source.node_id).await?;
        let old_epoch = old_map.routing_epoch;
        assert_eq!(
            old_map.aggregate_routes,
            vec![AggregateOverlayRoute {
                cidr: "10.42.1.0/24".parse()?
            }]
        );
        let query = |destination| OverlayPathQuery {
            source: source.node_id.clone(),
            destination,
            source_identity_proof: ipars_types::api::NodeApiRequestSignature {
                signed_at: Utc::now(),
                nonce: format!("shared-routing-epoch-{destination}"),
                signature: String::new(),
            },
        };
        let old_path = plane_a
            .overlay_path_for(&query("10.42.1.10".parse()?))
            .await?;
        assert_eq!(old_path.routing_epoch, old_epoch);

        let accepted_at = Utc::now();
        plane_b
            .heartbeat(signed_heartbeat_at(
                "routing-epoch-target",
                HeartbeatRequest {
                    node_id: target.node_id.clone(),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: accepted_at,
                        latency_ms: Some(1.0),
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    nat_classification: None,
                    relay_capability: None,
                    routes: Some(vec![route(
                        "new-route",
                        "10.43.1.0/24",
                        "routing-epoch-target",
                    )?]),
                    service_advertisement: None,
                    path_state: Vec::new(),
                    node_signature: None,
                },
                accepted_at,
            ))
            .await?;
        let shared_epoch = store.get_overlay_routing_epoch(&target.cluster_id).await?;
        assert!(shared_epoch > old_epoch);

        let policy = plane_a.current_cluster_policy().await?;
        assert!(matches!(
            plane_a.overlay_node_snapshot(&policy, old_epoch).await,
            Err(ControlPlaneError::OverlayRouteCatalogChanged)
        ));

        let refreshed_map = plane_a.neighbor_map_for(&source.node_id).await?;
        assert_eq!(refreshed_map.routing_epoch, shared_epoch);
        assert_eq!(
            refreshed_map.aggregate_routes,
            vec![AggregateOverlayRoute {
                cidr: "10.43.1.0/24".parse()?
            }]
        );
        assert!(matches!(
            plane_a
                .overlay_path_for(&query("10.42.1.10".parse()?))
                .await,
            Err(ControlPlaneError::OverlayDestinationNotFound(_))
        ));
        let refreshed_path = plane_a
            .overlay_path_for(&query("10.43.1.10".parse()?))
            .await?;
        assert_eq!(refreshed_path.routing_epoch, shared_epoch);
        assert_eq!(refreshed_path.target.node_id, target.node_id);
        let replica_b_path = plane_b
            .overlay_path_for(&query("10.43.1.10".parse()?))
            .await?;
        assert_eq!(replica_b_path.routing_epoch, shared_epoch);
        assert_eq!(replica_b_path.target, refreshed_path.target);
        Ok(())
    }

    #[test]
    fn aggregate_overlay_routes_collapses_1024_contiguous_pod_cidrs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut provider = node_record("aggregate-provider");
        for index in 0..1_024_u32 {
            let cidr = Ipv4Net::new(
                Ipv4Addr::new(10, u8::try_from(index >> 8)?, index as u8, 0),
                24,
            )?;
            provider.routes.push(Route {
                id: format!("pod-cidr-{index:04}"),
                cidr: IpNet::V4(cidr),
                advertised_by: provider.node_id.clone(),
                via: None,
                metric: 100,
                tags: BTreeSet::new(),
            });
        }
        provider.routes.push(Route {
            id: "covered-noncanonical-route".to_string(),
            cidr: "10.0.0.1/25".parse()?,
            advertised_by: provider.node_id.clone(),
            via: None,
            metric: 1,
            tags: BTreeSet::new(),
        });

        assert_eq!(
            aggregate_overlay_routes(&[provider]),
            vec![AggregateOverlayRoute {
                cidr: "10.0.0.0/14".parse()?
            }]
        );
        Ok(())
    }

    #[test]
    fn overlay_routing_epoch_tracks_route_catalog_and_acl_changes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut provider = node_record("routing-epoch-provider");
        provider.routes = vec![route(
            "routing-epoch-route",
            "10.42.0.0/16",
            "routing-epoch-provider",
        )?];
        let base_catalog = overlay_route_catalog_epoch(&[provider.clone()])?;
        let base_policy = ClusterPolicy::default();
        let base_epoch = overlay_routing_epoch(base_catalog, &base_policy)?;

        provider
            .endpoint_candidates
            .push(candidate("routing-epoch-provider"));
        assert_eq!(
            overlay_route_catalog_epoch(&[provider.clone()])?,
            base_catalog
        );

        provider.routes[0].metric += 1;
        let changed_catalog = overlay_route_catalog_epoch(&[provider])?;
        assert_ne!(changed_catalog, base_catalog);
        assert_ne!(
            overlay_routing_epoch(changed_catalog, &base_policy)?,
            base_epoch
        );

        let mut acl_policy = base_policy.clone();
        acl_policy.acl_rules.push(AclRule {
            id: "routing-epoch-deny".to_string(),
            from_roles: BTreeSet::new(),
            from_tags: BTreeSet::new(),
            to_roles: BTreeSet::new(),
            to_tags: BTreeSet::new(),
            routes: vec!["10.42.1.0/24".parse()?],
            protocol: TransportProtocol::Any,
            action: AclAction::Deny,
        });
        assert_ne!(
            overlay_routing_epoch(base_catalog, &acl_policy)?,
            base_epoch
        );

        let mut timeout_policy = base_policy.clone();
        timeout_policy.idle_timeout_seconds += 1;
        assert_eq!(
            overlay_routing_epoch(base_catalog, &timeout_policy)?,
            base_epoch
        );
        Ok(())
    }

    #[test]
    fn cluster_policy_rejects_protocol_acl_without_dataplane_enforcement() {
        let mut policy = ClusterPolicy::default();
        policy.acl_rules.push(AclRule {
            id: "tcp-only".to_string(),
            from_roles: BTreeSet::new(),
            from_tags: BTreeSet::new(),
            to_roles: BTreeSet::new(),
            to_tags: BTreeSet::new(),
            routes: Vec::new(),
            protocol: TransportProtocol::Tcp,
            action: AclAction::Allow,
        });

        assert!(matches!(
            validate_cluster_policy(&policy),
            Err(ControlPlaneError::InvalidClusterPolicy(reason))
                if reason.contains("only protocol=any")
        ));
    }

    #[test]
    fn cluster_policy_validates_overlay_route_scope_shape() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut policy = ClusterPolicy {
            overlay_route_scopes: (0..MAX_OVERLAY_ROUTE_SCOPES)
                .map(|index| format!("10.{index}.0.0/16").parse())
                .collect::<Result<Vec<_>, _>>()?,
            ..ClusterPolicy::default()
        };
        validate_cluster_policy(&policy)?;

        policy.overlay_route_scopes.push("10.64.0.0/16".parse()?);
        assert!(matches!(
            validate_cluster_policy(&policy),
            Err(ControlPlaneError::InvalidClusterPolicy(reason))
                if reason.contains("at most 64")
        ));

        policy.overlay_route_scopes = vec!["10.42.0.1/16".parse()?];
        assert!(matches!(
            validate_cluster_policy(&policy),
            Err(ControlPlaneError::InvalidClusterPolicy(reason))
                if reason.contains("must be canonical")
        ));

        policy.overlay_route_scopes = vec!["10.42.0.0/16".parse()?, "10.42.1.0/24".parse()?];
        assert!(matches!(
            validate_cluster_policy(&policy),
            Err(ControlPlaneError::InvalidClusterPolicy(reason))
                if reason.contains("overlaps")
        ));

        policy.overlay_route_scopes = vec!["::/0".parse()?];
        assert!(matches!(
            validate_cluster_policy(&policy),
            Err(ControlPlaneError::InvalidClusterPolicy(reason))
                if reason.contains("unrestricted")
        ));

        policy.overlay_route_scopes = vec!["fe80::/10".parse()?];
        assert!(matches!(
            validate_cluster_policy(&policy),
            Err(ControlPlaneError::InvalidClusterPolicy(reason))
                if reason.contains("link-local")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn setting_overlay_route_scopes_rejects_vpn_overlap_and_uncovered_existing_routes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(cluster_id, Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 24)?),
            store.clone(),
        );
        let mut provider = node_record("scope-existing-provider");
        provider.routes = vec![route(
            "existing-pod-cidr",
            "10.43.1.0/24",
            "scope-existing-provider",
        )?];
        store.insert_node(provider).await?;

        let vpn_overlap = ClusterPolicy {
            overlay_route_scopes: vec!["100.64.0.0/25".parse()?],
            ..ClusterPolicy::default()
        };
        assert!(matches!(
            plane.set_cluster_policy(vpn_overlap).await,
            Err(ControlPlaneError::InvalidClusterPolicy(reason))
                if reason.contains("overlaps VPN pool")
        ));

        let uncovered = ClusterPolicy {
            overlay_route_scopes: vec!["10.42.0.0/16".parse()?],
            ..ClusterPolicy::default()
        };
        assert!(matches!(
            plane.set_cluster_policy(uncovered).await,
            Err(ControlPlaneError::InvalidClusterPolicy(reason))
                if reason.contains("existing-pod-cidr")
        ));

        let covering = ClusterPolicy {
            overlay_route_scopes: vec!["10.0.0.0/8".parse()?],
            ..ClusterPolicy::default()
        };
        assert_eq!(plane.set_cluster_policy(covering.clone()).await?, covering);
        Ok(())
    }

    #[tokio::test]
    async fn registration_rejects_routes_outside_configured_overlay_scopes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");
        let mut config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 24)?,
        );
        config.cluster_policy.overlay_route_scopes = vec!["10.42.0.0/16".parse()?];
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        let mut token_claims = claims(cluster_id);
        token_claims.policy.allowed_routes = vec!["10.0.0.0/8".parse()?];
        let mut request = registration_request("scoped-registration");
        request.requested_routes = vec![route(
            "outside-scope",
            "10.43.1.0/24",
            "scoped-registration",
        )?];

        assert!(matches!(
            plane
                .register_with_claims(token_claims.clone(), request.clone())
                .await,
            Err(ControlPlaneError::NodeRegistrationRejected { reason, .. })
                if reason.contains("not fully contained")
        ));

        request.requested_routes = vec![route(
            "inside-scope",
            "10.42.1.0/24",
            "scoped-registration",
        )?];
        let registered = plane.register_with_claims(token_claims, request).await?;
        assert_eq!(registered.node.routes[0].id, "inside-scope");
        Ok(())
    }

    #[tokio::test]
    async fn registration_rejects_vpn_overlap_and_excess_automatic_route_scopes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 24)?,
            ),
            Arc::new(InMemoryStore::default()),
        );
        let mut request = registration_request("bounded-route-registration");
        request.requested_routes = vec![route(
            "vpn-overlap",
            "100.64.0.0/25",
            "bounded-route-registration",
        )?];
        let mut token_claims = claims(cluster_id.clone());
        token_claims.policy.allowed_routes = vec!["100.64.0.0/10".parse()?];
        assert!(matches!(
            plane
                .register_with_claims(token_claims, request.clone())
                .await,
            Err(ControlPlaneError::NodeRegistrationRejected { reason, .. })
                if reason.contains("overlaps VPN pool")
        ));

        let first_address = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        request.requested_routes = (0..=MAX_OVERLAY_ROUTE_SCOPES)
            .map(|index| {
                route(
                    &format!("fragmented-route-{index:02}"),
                    &format!("{}/32", Ipv4Addr::from(first_address + (index as u32 * 2))),
                    "bounded-route-registration",
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut token_claims = claims(cluster_id);
        token_claims.policy.allowed_routes = vec!["10.0.0.0/8".parse()?];
        assert!(matches!(
            plane.register_with_claims(token_claims, request).await,
            Err(ControlPlaneError::NodeRegistrationRejected { reason, .. })
                if reason.contains("65 aggregate capture scopes")
        ));
        Ok(())
    }

    #[test]
    fn overlay_route_index_prefers_longest_prefix_then_metric_node_and_route_id(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let source = node_record("indexed-source");
        let mut broad = node_record("indexed-broad");
        let mut broad_route = route("broad", "10.42.0.0/16", "indexed-broad")?;
        broad_route.metric = 0;
        broad.routes = vec![broad_route];

        let mut exact = vec![
            node_record("indexed-exact-a"),
            node_record("indexed-exact-b"),
        ];
        exact.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let exact_cidr = "10.42.1.0/24".parse()?;
        for node in &mut exact {
            node.routes = ["z-route", "a-route"]
                .into_iter()
                .map(|route_id| Route {
                    id: route_id.to_string(),
                    cidr: exact_cidr,
                    advertised_by: node.node_id.clone(),
                    via: None,
                    metric: 10,
                    tags: BTreeSet::new(),
                })
                .collect();
        }
        let expected_node_id = exact[0].node_id.clone();

        let mut worse_metric = node_record("indexed-worse-metric");
        let mut worse_route = route(
            "lower-priority-exact",
            "10.42.1.0/24",
            "indexed-worse-metric",
        )?;
        worse_route.metric = 50;
        worse_metric.routes = vec![worse_route];

        let mut nodes = vec![source.clone(), broad, worse_metric];
        nodes.extend(exact);
        let index = OverlayRouteIndex::build(&nodes);
        let active_nodes_by_id = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.node_id.clone(), index))
            .collect::<BTreeMap<_, _>>();

        let target = index
            .resolve_destination(
                &source,
                &nodes,
                &active_nodes_by_id,
                "10.42.1.99".parse()?,
                &ClusterPolicy::default(),
            )
            .ok_or("indexed route should resolve")?;

        assert_eq!(target.node_id, expected_node_id);
        assert_eq!(target.routes.len(), 1);
        assert_eq!(target.routes[0].id, "a-route");
        assert_eq!(target.routes[0].cidr, "10.42.1.0/24".parse()?);
        Ok(())
    }

    #[test]
    fn overlay_route_index_uses_acl_allowed_less_specific_fallback(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let source = node_record("acl-index-source");
        let mut denied = node_record("acl-index-denied");
        denied.tags.insert(Tag::from_string("blocked"));
        let mut denied_route = route("denied-specific", "10.42.1.0/24", "acl-index-denied")?;
        denied_route.metric = 1;
        denied.routes = vec![denied_route];

        let mut allowed = node_record("acl-index-allowed");
        allowed.tags.insert(Tag::from_string("allowed"));
        let mut allowed_route = route("allowed-fallback", "10.42.0.0/16", "acl-index-allowed")?;
        allowed_route.metric = 100;
        allowed.routes = vec![allowed_route];

        let nodes = vec![source.clone(), denied, allowed.clone()];
        let index = OverlayRouteIndex::build(&nodes);
        let active_nodes_by_id = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.node_id.clone(), index))
            .collect::<BTreeMap<_, _>>();
        let policy = ClusterPolicy {
            acl_rules: vec![
                AclRule {
                    id: "deny-blocked".to_string(),
                    from_roles: BTreeSet::new(),
                    from_tags: BTreeSet::new(),
                    to_roles: BTreeSet::new(),
                    to_tags: BTreeSet::from([Tag::from_string("blocked")]),
                    routes: Vec::new(),
                    protocol: TransportProtocol::Any,
                    action: AclAction::Deny,
                },
                AclRule {
                    id: "allow-route-provider".to_string(),
                    from_roles: BTreeSet::new(),
                    from_tags: BTreeSet::new(),
                    to_roles: BTreeSet::new(),
                    to_tags: BTreeSet::from([Tag::from_string("allowed")]),
                    routes: vec!["10.42.0.0/16".parse()?],
                    protocol: TransportProtocol::Any,
                    action: AclAction::Allow,
                },
            ],
            ..ClusterPolicy::default()
        };

        let target = index
            .resolve_destination(
                &source,
                &nodes,
                &active_nodes_by_id,
                "10.42.1.99".parse()?,
                &policy,
            )
            .ok_or("ACL-allowed fallback should resolve")?;

        assert_eq!(target.node_id, allowed.node_id);
        assert_eq!(target.routes.len(), 1);
        assert_eq!(target.routes[0].id, "overlay-v4-0a2a0163");
        assert_eq!(target.routes[0].cidr, "10.42.1.99/32".parse()?);
        assert_eq!(target.routes[0].advertised_by, allowed.node_id);
        Ok(())
    }

    #[test]
    fn overlay_route_index_does_not_bypass_specific_deny_with_broad_allow(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let source = node_record("acl-prefix-source");
        let mut provider = node_record("acl-prefix-provider");
        provider.routes = vec![route(
            "broad-provider-route",
            "10.42.0.0/16",
            "acl-prefix-provider",
        )?];
        let nodes = vec![source.clone(), provider.clone()];
        let index = OverlayRouteIndex::build(&nodes);
        let active_nodes_by_id = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.node_id.clone(), index))
            .collect::<BTreeMap<_, _>>();
        let policy = ClusterPolicy {
            acl_rules: vec![
                AclRule {
                    id: "allow-broad".to_string(),
                    from_roles: BTreeSet::new(),
                    from_tags: BTreeSet::new(),
                    to_roles: BTreeSet::new(),
                    to_tags: BTreeSet::new(),
                    routes: vec!["10.42.0.0/16".parse()?],
                    protocol: TransportProtocol::Any,
                    action: AclAction::Allow,
                },
                AclRule {
                    id: "deny-specific".to_string(),
                    from_roles: BTreeSet::new(),
                    from_tags: BTreeSet::new(),
                    to_roles: BTreeSet::new(),
                    to_tags: BTreeSet::new(),
                    routes: vec!["10.42.1.0/24".parse()?],
                    protocol: TransportProtocol::Any,
                    action: AclAction::Deny,
                },
            ],
            ..ClusterPolicy::default()
        };

        assert!(index
            .resolve_destination(
                &source,
                &nodes,
                &active_nodes_by_id,
                "10.42.1.99".parse()?,
                &policy,
            )
            .is_none());
        let target = index
            .resolve_destination(
                &source,
                &nodes,
                &active_nodes_by_id,
                "10.42.2.99".parse()?,
                &policy,
            )
            .ok_or("destination outside the deny prefix should resolve")?;
        assert_eq!(target.node_id, provider.node_id);
        assert_eq!(target.routes[0].cidr, "10.42.2.99/32".parse()?);
        Ok(())
    }

    #[tokio::test]
    async fn neighbor_map_uses_configured_acl_independent_route_scopes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");
        let mut config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 24)?,
        );
        config.cluster_policy.overlay_route_scopes = vec!["10.0.0.0/8".parse()?];
        config.cluster_policy.acl_rules = vec![AclRule {
            id: "deny-all".to_string(),
            from_roles: BTreeSet::new(),
            from_tags: BTreeSet::new(),
            to_roles: BTreeSet::new(),
            to_tags: BTreeSet::new(),
            routes: Vec::new(),
            protocol: TransportProtocol::Any,
            action: AclAction::Deny,
        }];
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let mut source = node_record("aggregate-source");
        source.vpn_ip = VpnIp("100.64.0.2".parse()?);
        let mut provider = node_record("aggregate-denied-provider");
        provider.vpn_ip = VpnIp("100.64.0.3".parse()?);
        provider.routes = vec![route(
            "denied-pod-cidr",
            "10.42.1.0/24",
            "aggregate-denied-provider",
        )?];
        store.insert_node(source.clone()).await?;
        store.insert_node(provider).await?;

        let neighbor_map = plane.neighbor_map_for(&source.node_id).await?;
        assert!(neighbor_map
            .neighbors
            .iter()
            .all(|neighbor| neighbor.node.routes.is_empty()));
        assert_eq!(
            neighbor_map.aggregate_routes,
            vec![AggregateOverlayRoute {
                cidr: "10.0.0.0/8".parse()?
            }]
        );

        let query = OverlayPathQuery {
            source: source.node_id,
            destination: "10.42.1.10".parse()?,
            source_identity_proof: ipars_types::api::NodeApiRequestSignature {
                signed_at: Utc::now(),
                nonce: "acl-authoritative-route-query".to_string(),
                signature: String::new(),
            },
        };
        assert!(matches!(
            plane.overlay_path_for(&query).await,
            Err(ControlPlaneError::OverlayDestinationNotFound(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn neighbor_map_rejects_more_than_64_exact_aggregates_without_widening(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(cluster_id, Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 24)?),
            store.clone(),
        );
        let mut source = node_record("aggregate-limit-source");
        source.vpn_ip = VpnIp("100.64.0.2".parse()?);
        let mut provider = node_record("aggregate-limit-provider");
        provider.vpn_ip = VpnIp("100.64.0.3".parse()?);
        let first_address = u32::from(Ipv4Addr::new(10, 0, 0, 0));
        for index in 0..65_u32 {
            provider.routes.push(Route {
                id: format!("disjoint-route-{index:02}"),
                cidr: IpNet::V4(Ipv4Net::new(Ipv4Addr::from(first_address + index * 2), 32)?),
                advertised_by: provider.node_id.clone(),
                via: None,
                metric: 100,
                tags: BTreeSet::new(),
            });
        }
        store.insert_node(source.clone()).await?;
        store.insert_node(provider).await?;

        let policy = plane.current_cluster_policy().await?;
        let routing_epoch = plane
            .store
            .get_overlay_routing_epoch(&plane.config.cluster_id)
            .await?;
        let snapshot = plane.overlay_node_snapshot(&policy, routing_epoch).await?;
        assert_eq!(snapshot.aggregate_routes.len(), 65);
        assert!(snapshot
            .aggregate_routes
            .iter()
            .all(|route| route.cidr.prefix_len() == 32));

        let error = match plane.neighbor_map_for(&source.node_id).await {
            Ok(_) => return Err("65 exact aggregates were unexpectedly accepted".into()),
            Err(error) => error,
        };
        let ControlPlaneError::BoundedTopology(reason) = error else {
            return Err(format!("unexpected error: {error}").into());
        };
        assert!(reason.contains("count 65"));
        assert!(reason.contains("limit 64"));
        Ok(())
    }

    #[test]
    fn client_route_projection_does_not_return_the_full_worker_directory(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = Utc::now();
        let mut gateway_a = node_record("projection-gateway-a");
        gateway_a.role = Role::gateway();
        gateway_a.vpn_ip = VpnIp("100.64.0.10".parse()?);
        let mut gateway_a_candidate = candidate("projection-gateway-a");
        gateway_a_candidate.kind = EndpointCandidateKind::PublicUdp;
        gateway_a_candidate.addr = "1.1.1.1:51820".parse()?;
        gateway_a.endpoint_candidates = vec![gateway_a_candidate];

        let mut gateway_b = node_record("projection-gateway-b");
        gateway_b.role = Role::gateway();
        gateway_b.vpn_ip = VpnIp("100.64.0.11".parse()?);
        let mut gateway_b_candidate = candidate("projection-gateway-b");
        gateway_b_candidate.kind = EndpointCandidateKind::PublicUdp;
        gateway_b_candidate.addr = "8.8.8.8:51820".parse()?;
        gateway_b.endpoint_candidates = vec![gateway_b_candidate];

        let mut backbone_nodes = vec![gateway_a.clone(), gateway_b.clone()];
        let mut worker_ids = BTreeSet::new();
        for index in 0..998 {
            let worker = node_record(&format!("projection-worker-{index:04}"));
            worker_ids.insert(worker.node_id.clone());
            backbone_nodes.push(worker);
        }

        let mut direct_client = node_record("projection-client-direct");
        direct_client.role = Role::client();
        direct_client.vpn_ip = VpnIp("100.64.1.10".parse()?);
        let mut remote_client = node_record("projection-client-remote");
        remote_client.role = Role::client();
        remote_client.vpn_ip = VpnIp("100.64.1.11".parse()?);
        let clients = vec![direct_client.clone(), remote_client.clone()];
        let selections = BTreeMap::from([
            (
                direct_client.node_id.clone(),
                ClientGatewaySelection {
                    client_id: direct_client.node_id.clone(),
                    gateway_node_id: gateway_a.node_id.clone(),
                    selected_at: now,
                },
            ),
            (
                remote_client.node_id.clone(),
                ClientGatewaySelection {
                    client_id: remote_client.node_id.clone(),
                    gateway_node_id: gateway_b.node_id.clone(),
                    selected_at: now,
                },
            ),
        ]);

        let projection = node_client_route_projection(
            &gateway_a,
            &backbone_nodes,
            &clients,
            &BTreeMap::new(),
            &selections,
            &ClusterPolicy::default(),
            now,
        );

        assert_eq!(projection.len(), 2);
        assert!(projection
            .iter()
            .any(|peer| peer.node_id == direct_client.node_id && peer.role.is_client()));
        let projected_gateway = projection
            .iter()
            .find(|peer| peer.node_id == gateway_b.node_id)
            .ok_or("remote client gateway should be projected")?;
        assert_eq!(projected_gateway.routes.len(), 1);
        assert_eq!(projected_gateway.routes[0].cidr, "100.64.1.11/32".parse()?);
        assert!(projection
            .iter()
            .all(|peer| !worker_ids.contains(&peer.node_id)));
        Ok(())
    }

    #[tokio::test]
    async fn overlay_topology_cache_prunes_abandoned_cells_and_stays_bounded(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 24)?,
            ),
            Arc::new(InMemoryStore::default()),
        );
        {
            let mut cache = plane.overlay_topology_cache.lock().await;
            for index in 0..32 {
                cache.insert(
                    OverlayTopologyCacheKey {
                        membership_epoch: index,
                        node_count: 1,
                        block_size: DEFAULT_OVERLAY_BLOCK_SIZE,
                        max_degree: ClusterPolicy::default().overlay_max_degree,
                        permutation_seed: cluster_id.as_str().to_string(),
                    },
                    Arc::new(OnceCell::new()),
                );
            }
        }

        let policy = plane.current_cluster_policy().await?;
        let mut nodes = Vec::new();
        for index in 0..12 {
            let mut node = node_record(&format!("bounded-cache-{index}"));
            node.cluster_id = cluster_id.clone();
            nodes.push(node);
        }
        plane.overlay_topology(&nodes, &policy).await?;
        {
            let cache = plane.overlay_topology_cache.lock().await;
            assert_eq!(cache.len(), 1);
            assert!(cache.values().all(|cell| cell.initialized()));
        }

        for retained in 4..=12 {
            plane.overlay_topology(&nodes[..retained], &policy).await?;
        }
        let cache = plane.overlay_topology_cache.lock().await;
        assert!(cache.len() <= MAX_OVERLAY_TOPOLOGY_CACHE_ENTRIES);
        assert!(cache.values().all(|cell| cell.initialized()));
        Ok(())
    }

    #[derive(Default)]
    struct RacingVpnIpStore {
        inner: InMemoryStore,
        race_once: AtomicBool,
    }

    #[async_trait]
    impl ControlPlaneStore for RacingVpnIpStore {
        async fn get_cluster_policy(
            &self,
            cluster_id: &ClusterId,
        ) -> Result<Option<ClusterPolicy>, ControlPlaneError> {
            self.inner.get_cluster_policy(cluster_id).await
        }

        async fn initialize_cluster_policy_if_absent(
            &self,
            cluster_id: &ClusterId,
            policy: ClusterPolicy,
        ) -> Result<ClusterPolicy, ControlPlaneError> {
            self.inner
                .initialize_cluster_policy_if_absent(cluster_id, policy)
                .await
        }

        async fn get_overlay_routing_epoch(
            &self,
            cluster_id: &ClusterId,
        ) -> Result<u64, ControlPlaneError> {
            self.inner.get_overlay_routing_epoch(cluster_id).await
        }

        async fn upsert_cluster_policy(
            &self,
            cluster_id: &ClusterId,
            policy: ClusterPolicy,
        ) -> Result<(), ControlPlaneError> {
            self.inner.upsert_cluster_policy(cluster_id, policy).await
        }

        async fn upsert_cluster_policy_if_route_catalog_epoch(
            &self,
            cluster_id: &ClusterId,
            policy: ClusterPolicy,
            expected_route_catalog_epoch: u64,
        ) -> Result<bool, ControlPlaneError> {
            self.inner
                .upsert_cluster_policy_if_route_catalog_epoch(
                    cluster_id,
                    policy,
                    expected_route_catalog_epoch,
                )
                .await
        }

        async fn insert_node(&self, node: NodeRecord) -> Result<(), ControlPlaneError> {
            if node.vpn_ip.0 == IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
                && !self.race_once.swap(true, Ordering::SeqCst)
            {
                let mut competing_node = node_record("node-racing-peer");
                competing_node.cluster_id = node.cluster_id.clone();
                competing_node.vpn_ip = node.vpn_ip;
                self.inner.insert_node(competing_node).await?;
                return Err(ControlPlaneError::VpnIpAlreadyAllocated(node.vpn_ip));
            }
            self.inner.insert_node(node).await
        }

        async fn insert_node_if_cluster_policy(
            &self,
            node: NodeRecord,
            expected_cluster_policy: Option<ClusterPolicy>,
            expected_route_catalog_epoch: Option<u64>,
        ) -> Result<(), ControlPlaneError> {
            if node.vpn_ip.0 == IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
                && !self.race_once.swap(true, Ordering::SeqCst)
            {
                let mut competing_node = node_record("node-racing-peer");
                competing_node.cluster_id = node.cluster_id.clone();
                competing_node.vpn_ip = node.vpn_ip;
                self.inner.insert_node(competing_node).await?;
                return Err(ControlPlaneError::VpnIpAlreadyAllocated(node.vpn_ip));
            }
            self.inner
                .insert_node_if_cluster_policy(
                    node,
                    expected_cluster_policy,
                    expected_route_catalog_epoch,
                )
                .await
        }

        async fn get_node(
            &self,
            node_id: &NodeId,
        ) -> Result<Option<NodeRecord>, ControlPlaneError> {
            self.inner.get_node(node_id).await
        }

        async fn list_nodes(&self) -> Result<Vec<NodeRecord>, ControlPlaneError> {
            self.inner.list_nodes().await
        }

        async fn remove_node(&self, node_id: &NodeId) -> Result<RemovedNode, ControlPlaneError> {
            self.inner.remove_node(node_id).await
        }

        async fn update_node_candidates(
            &self,
            node_id: &NodeId,
            candidates: Vec<EndpointCandidate>,
        ) -> Result<(), ControlPlaneError> {
            self.inner.update_node_candidates(node_id, candidates).await
        }

        async fn update_node_relay_capability(
            &self,
            node_id: &NodeId,
            relay_capability: Option<RelayCapability>,
        ) -> Result<(), ControlPlaneError> {
            self.inner
                .update_node_relay_capability(node_id, relay_capability)
                .await
        }

        async fn update_node_routes(
            &self,
            node_id: &NodeId,
            routes: Vec<Route>,
        ) -> Result<(), ControlPlaneError> {
            self.inner.update_node_routes(node_id, routes).await
        }

        async fn update_node_routes_if_cluster_policy(
            &self,
            cluster_id: &ClusterId,
            node_id: &NodeId,
            routes: Vec<Route>,
            expected_cluster_policy: Option<ClusterPolicy>,
            expected_route_catalog_epoch: Option<u64>,
        ) -> Result<(), ControlPlaneError> {
            self.inner
                .update_node_routes_if_cluster_policy(
                    cluster_id,
                    node_id,
                    routes,
                    expected_cluster_policy,
                    expected_route_catalog_epoch,
                )
                .await
        }

        async fn rejoin_node_if_cluster_policy(
            &self,
            update: RejoinNodeStoreUpdate,
        ) -> Result<NodeRecord, ControlPlaneError> {
            self.inner.rejoin_node_if_cluster_policy(update).await
        }

        async fn rotate_node_wireguard_public_key(
            &self,
            node_id: &NodeId,
            expected_current_public_key: &str,
            next_public_key: String,
        ) -> Result<NodeRecord, ControlPlaneError> {
            self.inner
                .rotate_node_wireguard_public_key(
                    node_id,
                    expected_current_public_key,
                    next_public_key,
                )
                .await
        }

        async fn upsert_health(
            &self,
            node_id: NodeId,
            health: NodeHealth,
        ) -> Result<(), ControlPlaneError> {
            self.inner.upsert_health(node_id, health).await
        }

        async fn get_health(
            &self,
            node_id: &NodeId,
        ) -> Result<Option<NodeHealth>, ControlPlaneError> {
            self.inner.get_health(node_id).await
        }

        async fn get_heartbeat_signature_timestamp(
            &self,
            node_id: &NodeId,
        ) -> Result<Option<chrono::DateTime<Utc>>, ControlPlaneError> {
            self.inner.get_heartbeat_signature_timestamp(node_id).await
        }

        async fn upsert_nat_classification(
            &self,
            node_id: NodeId,
            classification: NatClassification,
        ) -> Result<(), ControlPlaneError> {
            self.inner
                .upsert_nat_classification(node_id, classification)
                .await
        }

        async fn get_nat_classification(
            &self,
            node_id: &NodeId,
        ) -> Result<Option<NatClassification>, ControlPlaneError> {
            self.inner.get_nat_classification(node_id).await
        }

        async fn list_nat_classifications(
            &self,
        ) -> Result<BTreeMap<NodeId, NatClassification>, ControlPlaneError> {
            self.inner.list_nat_classifications().await
        }

        async fn apply_heartbeat(
            &self,
            update: HeartbeatStoreUpdate,
        ) -> Result<(), ControlPlaneError> {
            self.inner.apply_heartbeat(update).await
        }

        async fn upsert_path(&self, path: PathRecord) -> Result<(), ControlPlaneError> {
            self.inner.upsert_path(path).await
        }

        async fn replace_node_paths(
            &self,
            node_id: &NodeId,
            paths: Vec<PathRecord>,
        ) -> Result<(), ControlPlaneError> {
            self.inner.replace_node_paths(node_id, paths).await
        }

        async fn list_paths_for(
            &self,
            node_id: &NodeId,
        ) -> Result<Vec<PathRecord>, ControlPlaneError> {
            self.inner.list_paths_for(node_id).await
        }

        async fn upsert_service_instance(
            &self,
            instance: ServiceInstance,
        ) -> Result<(), ControlPlaneError> {
            self.inner.upsert_service_instance(instance).await
        }

        async fn remove_service_instance(
            &self,
            cluster_id: &ClusterId,
            instance_id: &str,
        ) -> Result<bool, ControlPlaneError> {
            self.inner
                .remove_service_instance(cluster_id, instance_id)
                .await
        }

        async fn list_service_instances(
            &self,
            cluster_id: &ClusterId,
        ) -> Result<Vec<ServiceInstance>, ControlPlaneError> {
            self.inner.list_service_instances(cluster_id).await
        }

        async fn upsert_client_gateway_selection(
            &self,
            selection: ClientGatewaySelection,
        ) -> Result<(), ControlPlaneError> {
            self.inner.upsert_client_gateway_selection(selection).await
        }

        async fn remove_client_gateway_selection(
            &self,
            client_id: &NodeId,
        ) -> Result<bool, ControlPlaneError> {
            self.inner.remove_client_gateway_selection(client_id).await
        }

        async fn list_client_gateway_selections(
            &self,
        ) -> Result<BTreeMap<NodeId, ClientGatewaySelection>, ControlPlaneError> {
            self.inner.list_client_gateway_selections().await
        }

        async fn latest_client_gateway_selection_at(
            &self,
        ) -> Result<Option<chrono::DateTime<Utc>>, ControlPlaneError> {
            self.inner.latest_client_gateway_selection_at().await
        }
    }

    fn route(id: &str, cidr: &str, advertised_by: &str) -> Result<Route, ipnet::AddrParseError> {
        Ok(Route {
            id: id.to_string(),
            cidr: cidr.parse()?,
            advertised_by: node_id(advertised_by),
            via: None,
            metric: 100,
            tags: BTreeSet::new(),
        })
    }

    fn candidate(node_id: &str) -> EndpointCandidate {
        EndpointCandidate {
            node_id: self::node_id(node_id),
            kind: EndpointCandidateKind::StunReflexive,
            addr: std::net::SocketAddr::from(([203, 0, 113, 10], 51820)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::StunProbe,
        }
    }

    fn candidate_at(node_id: &str, addr: std::net::SocketAddr) -> EndpointCandidate {
        EndpointCandidate {
            addr,
            ..candidate(node_id)
        }
    }

    fn invalid_ipv6_candidate(node_id: &str) -> EndpointCandidate {
        EndpointCandidate {
            kind: EndpointCandidateKind::Ipv6,
            ..candidate(node_id)
        }
    }

    fn stale_candidate(node_id: &str) -> EndpointCandidate {
        let mut candidate = candidate(node_id);
        candidate.observed_at = Utc::now() - Duration::seconds(60);
        candidate
    }

    #[test]
    fn nat_classification_shape_rejects_forged_private_public_state() {
        let now = Utc::now();
        let private_addr = std::net::SocketAddr::from(([100, 100, 20, 30], 51_820));
        let mut classification = NatClassification::from_observations(
            private_addr,
            vec![NatProbeObservation {
                local_addr: private_addr,
                stun_server: std::net::SocketAddr::from(([100, 100, 20, 40], 3478)),
                reflexive_addr: private_addr,
                observed_at: now,
            }],
            now,
        );
        classification.connectivity_state = NatConnectivityState::Public;

        assert!(matches!(
            validate_nat_classification_shape(
                &node_id("node-a"),
                &classification,
                now,
                std::time::Duration::from_secs(5),
            ),
            Err(error)
                if error.contains("requires matching globally routable direct or explicitly mapped observations")
        ));
    }

    fn path(local: &str, remote: &str) -> PathRecord {
        PathRecord {
            key: PeerPathKey::new(node_id(local), node_id(remote)),
            selected_state: PathState::DirectNatTraversal,
            selected_candidate: None,
            relay_node: None,
            score: PathScore::calculate(
                PathState::DirectNatTraversal,
                &PathMetrics::default(),
                true,
                0,
            ),
            updated_at: Utc::now(),
            pinned: false,
        }
    }

    fn relay_path(local: &str, remote: &str, relay: Option<&str>) -> PathRecord {
        PathRecord {
            selected_state: PathState::Relay,
            selected_candidate: None,
            relay_node: relay.map(node_id),
            score: PathScore::calculate(PathState::Relay, &PathMetrics::default(), true, 0),
            ..path(local, remote)
        }
    }

    fn heartbeat_store_update(
        node: &NodeRecord,
        accepted_at: chrono::DateTime<Utc>,
    ) -> HeartbeatStoreUpdate {
        HeartbeatStoreUpdate {
            cluster_id: node.cluster_id.clone(),
            expected_cluster_policy: None,
            expected_route_catalog_epoch: None,
            node_id: node.node_id.clone(),
            expected_identity_public_key: node.identity_public_key.clone(),
            expected_registered_at: node.registered_at,
            accepted_signature_at: Some(accepted_at),
            hostname: None,
            candidates: vec![EndpointCandidate {
                node_id: node.node_id.clone(),
                kind: EndpointCandidateKind::StunReflexive,
                addr: std::net::SocketAddr::from(([203, 0, 113, 42], 51820)),
                observed_at: accepted_at,
                priority: 100,
                cost: 10,
                source: CandidateSource::StunProbe,
            }],
            nat_classification: None,
            relay_capability: None,
            routes: None,
            health: NodeHealth {
                state: HealthState::Healthy,
                last_seen_at: accepted_at,
                latency_ms: Some(1.0),
                relay_load: None,
                message: Some("generation-cas".to_string()),
            },
            paths: Vec::new(),
        }
    }

    async fn set_in_memory_routing_epoch(
        store: &InMemoryStore,
        cluster_id: &ClusterId,
        epoch: u64,
    ) {
        store
            .overlay_routing_epochs
            .write()
            .await
            .insert(cluster_id.clone(), epoch);
    }

    fn assert_routing_epoch_exhausted<T>(
        result: Result<T, ControlPlaneError>,
        cluster_id: &ClusterId,
    ) {
        assert!(matches!(
            result,
            Err(ControlPlaneError::Store(reason))
                if reason
                    == format!("overlay routing epoch exhausted for cluster {cluster_id}")
        ));
    }

    #[test]
    fn topology_edge_observation_distinguishes_live_partial_and_stale_paths() {
        let now = Utc::now();
        let forward = path("node-a", "node-b");
        let reverse = path("node-b", "node-a");
        assert_eq!(
            topology_edge_observation(&[], now, 30).0,
            ControlPlaneTopologyEdgeStatus::Unknown
        );
        assert_eq!(
            topology_edge_observation(&[&forward], now, 30).0,
            ControlPlaneTopologyEdgeStatus::Partial
        );
        assert_eq!(
            topology_edge_observation(&[&forward, &reverse], now, 30).0,
            ControlPlaneTopologyEdgeStatus::Connected
        );

        let unreachable = PathRecord {
            selected_state: PathState::Unreachable,
            ..forward.clone()
        };
        assert_eq!(
            topology_edge_observation(&[&unreachable], now, 30).0,
            ControlPlaneTopologyEdgeStatus::Unreachable
        );

        let stale = PathRecord {
            updated_at: now - Duration::seconds(31),
            ..forward
        };
        assert_eq!(
            topology_edge_observation(&[&stale], now, 30).0,
            ControlPlaneTopologyEdgeStatus::Stale
        );
    }

    fn join_service(
        cluster_id: ClusterId,
        issuer: &IdentityKeyPair,
        key_id: KeyId,
    ) -> Result<
        ControlPlaneJoinService<InMemoryStore, InMemoryTokenLedger>,
        Box<dyn std::error::Error>,
    > {
        let config =
            ControlPlaneConfig::new(cluster_id, Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?);
        let plane = Arc::new(ControlPlane::new(
            config,
            Arc::new(InMemoryStore::default()),
        ));
        let ledger = Arc::new(InMemoryTokenLedger::default());
        let mut key_ring = IssuerKeyRing::default();
        key_ring.insert(issuer.node_id(), key_id, issuer.public_key_b64());
        Ok(ControlPlaneJoinService::new(plane, ledger, key_ring))
    }

    fn signed_token_revocation(
        issuer: &IdentityKeyPair,
        cluster_id: ClusterId,
        nonce: &str,
        key_id: KeyId,
        signed_at: chrono::DateTime<Utc>,
    ) -> Result<RevokeTokenRequest, Box<dyn std::error::Error>> {
        let mut request = RevokeTokenRequest {
            cluster_id,
            nonce: nonce.to_string(),
            issuer: issuer.node_id(),
            key_id,
            issuer_signature: None,
        };
        request.issuer_signature = Some(issuer.sign_token_revocation_request(&request, signed_at)?);
        Ok(request)
    }

    #[tokio::test]
    async fn service_directory_expires_members_and_requires_two_complete_public_nodes_for_ha(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-ha");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store.clone(),
        );
        let now = Utc::now();
        insert_eligible_service_node(
            store.as_ref(),
            &cluster_id,
            "public-a",
            Ipv4Addr::new(8, 8, 8, 10),
            now,
        )
        .await?;
        insert_eligible_service_node(
            store.as_ref(),
            &cluster_id,
            "public-b",
            Ipv4Addr::new(8, 8, 8, 11),
            now,
        )
        .await?;
        insert_eligible_service_node(
            store.as_ref(),
            &cluster_id,
            "expired-public",
            Ipv4Addr::new(8, 8, 8, 12),
            now,
        )
        .await?;

        plane
            .advertise_service_instance(service_instance(
                &cluster_id,
                "public-a",
                "public-a.example",
                now,
                now + Duration::seconds(30),
            ))
            .await?;
        plane
            .advertise_service_instance(service_instance(
                &cluster_id,
                "public-b",
                "public-b.example",
                now,
                now + Duration::seconds(30),
            ))
            .await?;
        plane
            .advertise_service_instance(service_instance(
                &cluster_id,
                "expired-public",
                "expired.example",
                now - Duration::seconds(60),
                now - Duration::seconds(30),
            ))
            .await?;

        let directory = plane.service_directory().await?;
        assert_eq!(
            directory
                .instances
                .iter()
                .map(|instance| instance.instance_id.as_str())
                .collect::<Vec<_>>(),
            vec!["public-a", "public-b"]
        );
        assert_eq!(directory.bootstrap_endpoints.len(), 10);
        assert!(directory
            .bootstrap_endpoints
            .iter()
            .all(|endpoint| !endpoint.url.contains("expired")));

        let metrics = plane.metrics().await?;
        assert_eq!(metrics.active_service_instance_count, 2);
        assert_eq!(metrics.active_service_host_count, 2);
        assert_eq!(metrics.active_control_plane_count, 2);
        assert_eq!(metrics.active_signal_count, 2);
        assert_eq!(metrics.active_stun_count, 2);
        assert_eq!(metrics.active_relay_count, 2);
        assert_eq!(metrics.active_web_ui_count, 2);
        assert!(metrics.ha_ready);

        let mut colocated_public_b = service_instance(
            &cluster_id,
            "public-b",
            "public-b.example",
            now,
            now + Duration::seconds(30),
        );
        let public_a_node_id = node_id("public-a");
        colocated_public_b.owner_host_id = public_a_node_id.as_str().to_string();
        colocated_public_b.owner_node_id = Some(public_a_node_id);
        plane.advertise_service_instance(colocated_public_b).await?;
        let metrics = plane.metrics().await?;
        assert_eq!(metrics.active_service_host_count, 1);
        assert_eq!(metrics.active_control_plane_count, 1);
        assert!(!metrics.ha_ready);
        plane
            .advertise_service_instance(service_instance(
                &cluster_id,
                "public-b",
                "public-b.example",
                now,
                now + Duration::seconds(30),
            ))
            .await?;

        let mut duplicate_kind = service_instance(
            &cluster_id,
            "invalid-public",
            "invalid.example",
            now,
            now + Duration::seconds(30),
        );
        duplicate_kind
            .endpoints
            .push(duplicate_kind.endpoints[0].clone());
        assert!(plane
            .advertise_service_instance(duplicate_kind)
            .await
            .is_err());

        let mut invalid_owner = service_instance(
            &cluster_id,
            "invalid-owner",
            "invalid-owner.example",
            now,
            now + Duration::seconds(30),
        );
        invalid_owner.owner_node_id = Some(NodeId::from_string("invalid owner"));
        assert!(plane
            .advertise_service_instance(invalid_owner)
            .await
            .is_err());

        let mut missing_owner = service_instance(
            &cluster_id,
            "missing-owner",
            "missing-owner.example",
            now,
            now + Duration::seconds(30),
        );
        missing_owner.owner_node_id = None;
        assert!(plane
            .advertise_service_instance(missing_owner)
            .await
            .is_err());

        let mut mismatched_owner = service_instance(
            &cluster_id,
            "mismatched-owner",
            "mismatched-owner.example",
            now,
            now + Duration::seconds(30),
        );
        mismatched_owner.owner_node_id = Some(NodeId::from_string("different-node"));
        assert!(plane
            .advertise_service_instance(mismatched_owner)
            .await
            .is_err());

        let mut invalid_host = service_instance(
            &cluster_id,
            "invalid-host",
            "invalid-host.example",
            now,
            now + Duration::seconds(30),
        );
        invalid_host.owner_host_id = "invalid host".to_string();
        assert!(plane
            .advertise_service_instance(invalid_host)
            .await
            .is_err());

        let mut signer_without_control_plane = service_instance(
            &cluster_id,
            "invalid-signer",
            "invalid-signer.example",
            now,
            now + Duration::seconds(30),
        );
        signer_without_control_plane.enrollment_signer = true;
        signer_without_control_plane
            .endpoints
            .retain(|endpoint| endpoint.kind != BootstrapEndpointKind::ControlPlane);
        assert!(matches!(
            plane
                .advertise_service_instance(signer_without_control_plane)
                .await,
            Err(ControlPlaneError::Store(reason))
                if reason
                    == "enrollment signer service instance invalid-signer must advertise a control-plane endpoint"
        ));

        let mut duplicate_urls = service_instance(
            &cluster_id,
            "public-b",
            "public-b.example",
            now,
            now + Duration::seconds(30),
        );
        duplicate_urls.endpoints = service_instance(
            &cluster_id,
            "public-a-copy",
            "public-a.example",
            now,
            now + Duration::seconds(30),
        )
        .endpoints;
        plane.advertise_service_instance(duplicate_urls).await?;
        let metrics = plane.metrics().await?;
        assert_eq!(metrics.active_control_plane_count, 2);
        assert!(metrics.ha_ready);

        let mut degraded = service_instance(
            &cluster_id,
            "public-b",
            "public-b.example",
            now,
            now + Duration::seconds(30),
        );
        degraded
            .endpoints
            .retain(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane);
        plane.advertise_service_instance(degraded).await?;

        let metrics = plane.metrics().await?;
        assert_eq!(metrics.active_control_plane_count, 2);
        assert_eq!(metrics.active_signal_count, 1);
        assert!(!metrics.ha_ready);
        Ok(())
    }

    #[tokio::test]
    async fn split_service_owners_do_not_satisfy_ha() -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-split-service-ha");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store.clone(),
        );
        let now = Utc::now();
        for (index, label) in ["core-a", "core-b", "edge-a", "edge-b"]
            .into_iter()
            .enumerate()
        {
            insert_eligible_service_node(
                store.as_ref(),
                &cluster_id,
                label,
                Ipv4Addr::new(8, 8, 4, 10 + index as u8),
                now,
            )
            .await?;
            let mut instance = service_instance(
                &cluster_id,
                label,
                &format!("{label}.example"),
                now,
                now + Duration::seconds(30),
            );
            if label.starts_with("core") {
                instance.endpoints.retain(|endpoint| {
                    matches!(
                        endpoint.kind,
                        BootstrapEndpointKind::ControlPlane
                            | BootstrapEndpointKind::Signal
                            | BootstrapEndpointKind::Stun
                    )
                });
            } else {
                instance.endpoints.retain(|endpoint| {
                    matches!(
                        endpoint.kind,
                        BootstrapEndpointKind::Relay | BootstrapEndpointKind::WebUi
                    )
                });
            }
            plane.advertise_service_instance(instance).await?;
        }

        let metrics = plane.metrics().await?;
        assert_eq!(metrics.active_control_plane_count, 2);
        assert_eq!(metrics.active_signal_count, 2);
        assert_eq!(metrics.active_stun_count, 2);
        assert_eq!(metrics.active_relay_count, 2);
        assert_eq!(metrics.active_web_ui_count, 2);
        assert!(!metrics.ha_ready);
        Ok(())
    }

    #[tokio::test]
    async fn unregistered_and_foreign_service_owners_are_ignored(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-service-owner");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store.clone(),
        );
        let now = Utc::now();
        let unregistered = service_instance(
            &cluster_id,
            "unregistered",
            "unregistered.example",
            now,
            now + Duration::seconds(30),
        );
        plane.advertise_service_instance(unregistered).await?;
        assert!(plane.service_directory().await?.instances.is_empty());
        assert_eq!(plane.metrics().await?.active_service_instance_count, 0);

        let mut foreign = node_record("foreign-owner");
        foreign.cluster_id = ClusterId::from_string("other-cluster");
        store.insert_node(foreign).await?;
        plane
            .advertise_service_instance(service_instance(
                &cluster_id,
                "foreign-owner",
                "foreign.example",
                now,
                now + Duration::seconds(30),
            ))
            .await?;
        assert!(plane.service_directory().await?.instances.is_empty());
        assert_eq!(plane.metrics().await?.active_service_instance_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn stale_or_unreachable_service_owners_are_excluded(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-service-eligibility");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store.clone(),
        );
        let now = Utc::now();
        insert_eligible_service_node(
            store.as_ref(),
            &cluster_id,
            "eligible",
            Ipv4Addr::new(8, 8, 4, 20),
            now,
        )
        .await?;
        let stale_node_id = insert_eligible_service_node(
            store.as_ref(),
            &cluster_id,
            "stale",
            Ipv4Addr::new(8, 8, 4, 21),
            now,
        )
        .await?;
        let unreachable_node_id = insert_eligible_service_node(
            store.as_ref(),
            &cluster_id,
            "unreachable",
            Ipv4Addr::new(8, 8, 4, 22),
            now,
        )
        .await?;
        store
            .upsert_health(
                stale_node_id,
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: now - Duration::seconds(91),
                    latency_ms: None,
                    relay_load: None,
                    message: None,
                },
            )
            .await?;
        let private_addr = std::net::SocketAddr::from(([192, 168, 1, 20], 51_820));
        store
            .upsert_nat_classification(
                unreachable_node_id,
                NatClassification::from_observations(
                    private_addr,
                    vec![NatProbeObservation {
                        local_addr: private_addr,
                        stun_server: std::net::SocketAddr::from(([1, 1, 1, 1], 3478)),
                        reflexive_addr: std::net::SocketAddr::from(([8, 8, 4, 22], 51_820)),
                        observed_at: now,
                    }],
                    now,
                ),
            )
            .await?;
        for label in ["eligible", "stale", "unreachable"] {
            plane
                .advertise_service_instance(service_instance(
                    &cluster_id,
                    label,
                    &format!("{label}.example"),
                    now,
                    now + Duration::seconds(30),
                ))
                .await?;
        }

        let directory = plane.service_directory().await?;
        assert_eq!(directory.instances.len(), 1);
        assert_eq!(directory.instances[0].instance_id, "eligible");
        let metrics = plane.metrics().await?;
        assert_eq!(metrics.active_service_host_count, 1);
        assert_eq!(metrics.active_control_plane_count, 1);
        assert!(!metrics.ha_ready);
        Ok(())
    }

    #[tokio::test]
    async fn explicitly_mapped_public_service_owner_is_eligible(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-mapped-service-owner");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store.clone(),
        );
        let now = Utc::now();
        let mapped_ip = IpAddr::from([8, 8, 4, 40]);
        let local_addr = std::net::SocketAddr::from(([10, 10, 10, 103], 51_820));
        let mut node = node_record("mapped-owner");
        node.cluster_id = cluster_id.clone();
        node.endpoint_candidates = vec![EndpointCandidate {
            node_id: node.node_id.clone(),
            kind: EndpointCandidateKind::PublicUdp,
            addr: std::net::SocketAddr::new(mapped_ip, 51_820),
            observed_at: now,
            priority: 80,
            cost: 20,
            source: CandidateSource::StunProbe,
        }];
        let node_id = node.node_id.clone();
        store.insert_node(node).await?;
        store
            .upsert_health(
                node_id.clone(),
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: now,
                    latency_ms: None,
                    relay_load: None,
                    message: None,
                },
            )
            .await?;
        let observations = [
            std::net::SocketAddr::from(([1, 1, 1, 1], 3478)),
            std::net::SocketAddr::from(([8, 8, 8, 8], 3478)),
        ]
        .into_iter()
        .map(|stun_server| NatProbeObservation {
            local_addr,
            stun_server,
            reflexive_addr: std::net::SocketAddr::new(mapped_ip, 51_820),
            observed_at: now,
        })
        .collect();
        let mut classification =
            NatClassification::from_observations(local_addr, observations, now);
        assert_eq!(classification.declare_mapped_public_ip(mapped_ip), Ok(()));
        store
            .upsert_nat_classification(node_id, classification)
            .await?;
        plane
            .advertise_service_instance(service_instance(
                &cluster_id,
                "mapped-owner",
                "mapped.example",
                now,
                now + Duration::seconds(30),
            ))
            .await?;

        let directory = plane.service_directory().await?;
        assert_eq!(directory.instances.len(), 1);
        assert_eq!(directory.instances[0].instance_id, "mapped-owner");
        Ok(())
    }

    #[tokio::test]
    async fn ha_respects_configured_full_service_replica_count(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-configured-service-ha");
        let store = Arc::new(InMemoryStore::default());
        let mut config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        config.service_ha_replica_count = 3;
        let plane = ControlPlane::new(config, store.clone());
        let now = Utc::now();
        for (index, label) in ["public-a", "public-b", "public-c"].into_iter().enumerate() {
            insert_eligible_service_node(
                store.as_ref(),
                &cluster_id,
                label,
                Ipv4Addr::new(8, 8, 4, 30 + index as u8),
                now,
            )
            .await?;
            plane
                .advertise_service_instance(service_instance(
                    &cluster_id,
                    label,
                    &format!("{label}.example"),
                    now,
                    now + Duration::seconds(30),
                ))
                .await?;
            assert_eq!(plane.metrics().await?.ha_ready, index == 2);
        }
        Ok(())
    }

    #[tokio::test]
    async fn service_instance_withdrawal_removes_active_endpoint_immediately(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-withdrawal");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store.clone(),
        );
        let now = Utc::now();
        insert_eligible_service_node(
            store.as_ref(),
            &cluster_id,
            "dynamic-web",
            Ipv4Addr::new(8, 8, 8, 20),
            now,
        )
        .await?;
        let mut dynamic_web = service_instance(
            &cluster_id,
            "dynamic-web",
            "public.example",
            now,
            now + Duration::seconds(45),
        );
        dynamic_web
            .endpoints
            .retain(|endpoint| endpoint.kind == BootstrapEndpointKind::WebUi);
        plane.advertise_service_instance(dynamic_web).await?;
        let partial = plane.service_directory().await?;
        assert_eq!(partial.instances.len(), 1);
        assert!(partial.bootstrap_endpoints.is_empty());
        assert!(plane.withdraw_service_instance("dynamic-web").await?);
        assert!(!plane.withdraw_service_instance("dynamic-web").await?);
        assert!(plane.service_directory().await?.instances.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn service_directory_retains_core_instance_when_web_leases_exceed_limit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-core-retention");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store.clone(),
        );
        let now = Utc::now();
        let core_node_id = insert_eligible_service_node(
            store.as_ref(),
            &cluster_id,
            "core-a",
            Ipv4Addr::new(8, 8, 8, 21),
            now,
        )
        .await?;
        plane
            .advertise_service_instance(service_instance(
                &cluster_id,
                "core-a",
                "core-a.example",
                now - Duration::seconds(30),
                now + Duration::seconds(30),
            ))
            .await?;
        for index in 0..=MAX_ACTIVE_SERVICE_INSTANCES {
            let mut dynamic_web = service_instance(
                &cluster_id,
                &format!("dynamic-web-{index:03}"),
                &format!("web-{index:03}.example"),
                now,
                now + Duration::seconds(45),
            );
            dynamic_web
                .endpoints
                .retain(|endpoint| endpoint.kind == BootstrapEndpointKind::WebUi);
            dynamic_web.owner_host_id = core_node_id.as_str().to_string();
            dynamic_web.owner_node_id = Some(core_node_id.clone());
            plane.advertise_service_instance(dynamic_web).await?;
        }

        let directory = plane.service_directory().await?;

        assert_eq!(directory.instances.len(), MAX_ACTIVE_SERVICE_INSTANCES);
        assert!(directory
            .instances
            .iter()
            .any(|instance| instance.instance_id == "core-a"));
        assert!(bootstrap_endpoints_include_core_services(
            &directory.bootstrap_endpoints
        ));
        for kind in [
            BootstrapEndpointKind::ControlPlane,
            BootstrapEndpointKind::Signal,
            BootstrapEndpointKind::Stun,
        ] {
            assert!(directory
                .bootstrap_endpoints
                .iter()
                .any(|endpoint| endpoint.kind == kind && endpoint.url.contains("core-a.example")));
        }
        Ok(())
    }

    #[tokio::test]
    async fn service_directory_prioritizes_signers_across_instance_and_endpoint_limits(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const INSTANCE_COUNT: usize = 1_000;
        const SIGNER_COUNT: usize = 4;

        let cluster_id = ClusterId::from_string("cluster-signer-retention");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store.clone(),
        );
        let now = Utc::now();
        let owner_node_id = insert_eligible_service_node(
            store.as_ref(),
            &cluster_id,
            "shared-owner",
            Ipv4Addr::new(8, 8, 8, 24),
            now,
        )
        .await?;

        for index in 0..(INSTANCE_COUNT - SIGNER_COUNT) {
            let instance_id = format!("instance-{index:04}");
            let mut instance = service_instance(
                &cluster_id,
                &instance_id,
                &format!("{instance_id}.example"),
                now,
                now + Duration::seconds(30),
            );
            instance.owner_host_id = owner_node_id.as_str().to_string();
            instance.owner_node_id = Some(owner_node_id.clone());
            plane.advertise_service_instance(instance).await?;
        }
        for index in 0..SIGNER_COUNT {
            let instance_id = format!("signer-{index:04}");
            let mut signer = service_instance(
                &cluster_id,
                &instance_id,
                &format!("{instance_id}.example"),
                now - Duration::seconds(30),
                now + Duration::seconds(30),
            );
            signer.owner_host_id = owner_node_id.as_str().to_string();
            signer.owner_node_id = Some(owner_node_id.clone());
            signer.enrollment_signer = true;
            plane.advertise_service_instance(signer).await?;
        }

        let directory = plane.service_directory().await?;

        assert_eq!(directory.instances.len(), MAX_ACTIVE_SERVICE_INSTANCES);
        assert_eq!(
            directory
                .instances
                .iter()
                .filter(|instance| instance.enrollment_signer)
                .map(|instance| instance.instance_id.as_str())
                .collect::<Vec<_>>(),
            vec!["signer-0000", "signer-0001", "signer-0002", "signer-0003"]
        );

        let control_plane_urls = directory
            .bootstrap_endpoints
            .iter()
            .filter(|endpoint| endpoint.kind == BootstrapEndpointKind::ControlPlane)
            .map(|endpoint| endpoint.url.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            control_plane_urls.len(),
            MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND
        );
        assert_eq!(
            &control_plane_urls[..SIGNER_COUNT],
            [
                "https://signer-0000.example:8443",
                "https://signer-0001.example:8443",
                "https://signer-0002.example:8443",
                "https://signer-0003.example:8443",
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn enrollment_service_directory_keeps_only_recently_expired_instances(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-enrollment-directory");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store.clone(),
        );
        let now = Utc::now();
        insert_eligible_service_node(
            store.as_ref(),
            &cluster_id,
            "public-a",
            Ipv4Addr::new(8, 8, 8, 22),
            now,
        )
        .await?;
        insert_eligible_service_node(
            store.as_ref(),
            &cluster_id,
            "public-b",
            Ipv4Addr::new(8, 8, 8, 23),
            now,
        )
        .await?;
        plane
            .advertise_service_instance(service_instance(
                &cluster_id,
                "public-a",
                "public-a.example",
                now - Duration::seconds(90),
                now - Duration::seconds(60),
            ))
            .await?;
        plane
            .advertise_service_instance(service_instance(
                &cluster_id,
                "public-b",
                "public-b.example",
                now,
                now + Duration::seconds(30),
            ))
            .await?;

        let active = plane.service_directory().await?;
        assert_eq!(active.instances.len(), 1);
        assert_eq!(active.instances[0].instance_id, "public-b");

        let enrollment = plane
            .enrollment_service_directory(std::time::Duration::from_secs(5 * 60))
            .await?;
        assert_eq!(
            enrollment
                .instances
                .iter()
                .map(|instance| instance.instance_id.as_str())
                .collect::<Vec<_>>(),
            vec!["public-a", "public-b"]
        );
        assert_eq!(enrollment.bootstrap_endpoints.len(), 10);

        let expired = plane
            .enrollment_service_directory(std::time::Duration::from_secs(30))
            .await?;
        assert_eq!(expired.instances.len(), 1);
        assert_eq!(expired.instances[0].instance_id, "public-b");

        assert!(plane
            .enrollment_service_directory(std::time::Duration::from_secs(
                MAX_JOIN_TOKEN_TTL_SECONDS as u64 + 1,
            ))
            .await
            .is_err());
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_service_instances_are_isolated_by_cluster() -> Result<(), ControlPlaneError>
    {
        let store = InMemoryStore::default();
        let now = Utc::now();
        for cluster_id in ["cluster-a", "cluster-b"] {
            let cluster_id = ClusterId::from_string(cluster_id);
            store
                .upsert_service_instance(service_instance(
                    &cluster_id,
                    "public-a",
                    &format!("{cluster_id}.example"),
                    now,
                    now + Duration::seconds(30),
                ))
                .await?;
        }
        for cluster_id in ["cluster-a", "cluster-b"] {
            let cluster_id = ClusterId::from_string(cluster_id);
            let instances = store.list_service_instances(&cluster_id).await?;
            assert_eq!(instances.len(), 1);
            assert_eq!(instances[0].cluster_id, cluster_id);
        }
        Ok(())
    }

    #[tokio::test]
    async fn registration_allocates_vpn_ip_and_returns_relay_map(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 30)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        let identity = identity_for_node("node-a");
        let request = RegisterNodeRequest {
            node_id: identity.node_id(),
            identity_public_key: identity.public_key_b64(),
            wireguard_public_key: wireguard_public_key_for_node("node-a"),
            candidates: Vec::new(),
            nat_classification: None,
            relay_capability: Some(relay_capability()),
            requested_routes: Vec::new(),
        };
        let mut claims = claims(cluster_id);
        claims.policy.allow_relay = true;

        let response = plane.register_with_claims(claims, request).await?;

        assert_eq!(
            response.node.vpn_ip.0,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
        );
        assert_eq!(
            response
                .node
                .relay_capability
                .as_ref()
                .map(|capability| capability.enabled_by_policy),
            Some(true)
        );
        assert!(
            response.relay_map.relays.is_empty(),
            "relay candidates require a fresh healthy heartbeat"
        );
        let metrics = plane.metrics().await?;
        assert_eq!(metrics.vpn_pool_total_count, 2);
        assert_eq!(metrics.vpn_pool_allocated_count, 1);
        assert_eq!(metrics.vpn_pool_available_count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn relay_map_and_metrics_require_fresh_healthy_relay(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let mut relay_claims = claims(cluster_id.clone());
        relay_claims.policy.allow_relay = true;
        let mut relay_request = registration_request("relay-a");
        relay_request.relay_capability = Some(relay_capability());

        let relay_registration = plane
            .register_with_claims(relay_claims, relay_request)
            .await?;
        assert!(relay_registration.relay_map.relays.is_empty());
        assert_eq!(plane.metrics().await?.relay_candidate_count, 0);

        plane
            .heartbeat(signed_heartbeat(
                "relay-a",
                HeartbeatRequest {
                    node_id: node_id("relay-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: Some(1.0),
                        relay_load: Some(0.10),
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: Some(relay_capability()),
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await?;
        assert_eq!(plane.metrics().await?.relay_candidate_count, 1);

        let source_registration = plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("node-a"))
            .await?;
        assert_eq!(source_registration.relay_map.relays.len(), 1);
        assert_eq!(
            source_registration.relay_map.relays[0].node_id,
            node_id("relay-a")
        );

        store
            .upsert_health(
                node_id("relay-a"),
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now() - Duration::seconds(120),
                    latency_ms: Some(1.0),
                    relay_load: Some(0.10),
                    message: None,
                },
            )
            .await?;
        assert_eq!(plane.metrics().await?.relay_candidate_count, 0);

        store
            .upsert_health(
                node_id("relay-a"),
                NodeHealth {
                    state: HealthState::Unhealthy,
                    last_seen_at: Utc::now(),
                    latency_ms: None,
                    relay_load: None,
                    message: Some("overloaded".to_string()),
                },
            )
            .await?;
        let late_registration = plane
            .register_with_claims(claims(cluster_id), registration_request("node-b"))
            .await?;
        assert!(late_registration.relay_map.relays.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_heartbeats_commit_only_monotonic_complete_snapshots(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store.clone(),
        );
        plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("node-a"))
            .await?;
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-b"))
            .await?;
        let old_at = Utc::now();
        let new_at = old_at + Duration::milliseconds(1);
        let heartbeat = |signed_at: chrono::DateTime<Utc>, marker: &str, host_octet: u8| {
            let mut reported_path = path("node-a", "node-b");
            reported_path.updated_at = signed_at;
            signed_heartbeat_at(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: signed_at,
                        latency_ms: Some(f32::from(host_octet)),
                        relay_load: None,
                        message: Some(marker.to_string()),
                    },
                    candidates: vec![candidate_at(
                        "node-a",
                        std::net::SocketAddr::from(([203, 0, 113, host_octet], 51820)),
                    )],
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![reported_path],
                    nat_classification: None,
                    node_signature: None,
                },
                signed_at,
            )
        };
        let old = heartbeat(old_at, "old", 10);
        let newest = heartbeat(new_at, "new", 11);

        let (old_result, new_result) = tokio::join!(plane.heartbeat(old), plane.heartbeat(newest));
        assert!(new_result.is_ok());
        assert!(
            old_result.is_ok()
                || matches!(
                    old_result,
                    Err(ControlPlaneError::NodeSignatureRejected { .. })
                )
        );

        let stored_node = store
            .get_node(&node_id("node-a"))
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id("node-a")))?;
        assert_eq!(
            stored_node.endpoint_candidates[0].addr,
            std::net::SocketAddr::from(([203, 0, 113, 11], 51820))
        );
        let stored_health = store
            .get_health(&node_id("node-a"))
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id("node-a")))?;
        assert!(stored_health.last_seen_at >= old_at);
        assert_eq!(stored_health.message.as_deref(), Some("new"));
        assert_eq!(
            store
                .get_heartbeat_signature_timestamp(&node_id("node-a"))
                .await?,
            Some(new_at)
        );
        let stored_paths = store.list_paths_for(&node_id("node-a")).await?;
        assert_eq!(stored_paths.len(), 1);
        assert_eq!(stored_paths[0].updated_at, new_at);
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_heartbeat_generation_cas_rejects_aba_replacements(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store = InMemoryStore::default();
        let original = node_record("node-a");
        store.insert_node(original.clone()).await?;
        let update = heartbeat_store_update(&original, Utc::now());

        store.remove_node(&original.node_id).await?;
        let mut newer_registration = original.clone();
        newer_registration.registered_at = original.registered_at + Duration::seconds(1);
        store.insert_node(newer_registration.clone()).await?;
        assert!(matches!(
            store.apply_heartbeat(update.clone()).await,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("node generation changed")
        ));
        assert_eq!(
            store.get_node(&original.node_id).await?,
            Some(newer_registration.clone())
        );
        assert_eq!(store.get_health(&original.node_id).await?, None);

        store.remove_node(&original.node_id).await?;
        let mut replacement_identity = original.clone();
        replacement_identity.identity_public_key =
            identity_for_node("replacement-identity").public_key_b64();
        store.insert_node(replacement_identity.clone()).await?;
        assert!(matches!(
            store.apply_heartbeat(update).await,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("node generation changed")
        ));
        assert_eq!(
            store.get_node(&original.node_id).await?,
            Some(replacement_identity)
        );
        assert_eq!(store.get_health(&original.node_id).await?, None);
        assert!(store.list_paths_for(&original.node_id).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_routing_epoch_advances_only_for_effective_routing_changes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");
        let store = InMemoryStore::default();
        let base_policy = ClusterPolicy::default();
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 0);
        assert_eq!(
            store
                .initialize_cluster_policy_if_absent(&cluster_id, base_policy.clone())
                .await?,
            base_policy
        );
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 1);
        store
            .upsert_cluster_policy(&cluster_id, base_policy.clone())
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 1);

        let mut policy = base_policy;
        policy.idle_timeout_seconds += 1;
        store
            .upsert_cluster_policy(&cluster_id, policy.clone())
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 2);
        store
            .upsert_cluster_policy(&cluster_id, policy.clone())
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 2);

        let mut node = node_record("node-a");
        node.routes = vec![route("route-a", "10.42.1.0/24", "node-a")?];
        store.insert_node(node.clone()).await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 3);
        let catalog_epoch = overlay_route_catalog_epoch(&[node.clone()])?;
        assert!(
            store
                .upsert_cluster_policy_if_route_catalog_epoch(
                    &cluster_id,
                    policy.clone(),
                    catalog_epoch,
                )
                .await?
        );
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 3);

        store
            .update_node_routes(&node.node_id, node.routes.clone())
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 3);
        let route_b = route("route-b", "10.43.1.0/24", "node-a")?;
        store
            .update_node_routes(&node.node_id, vec![route_b.clone()])
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 4);
        let catalog_epoch = overlay_route_catalog_epoch(&store.list_nodes().await?)?;
        store
            .update_node_routes_if_cluster_policy(
                &cluster_id,
                &node.node_id,
                vec![route_b.clone()],
                Some(policy.clone()),
                Some(catalog_epoch),
            )
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 4);

        let previous_key = node.wireguard_public_key.clone();
        let next_key = wireguard_public_key_for_node("node-a-next-key");
        store
            .rotate_node_wireguard_public_key(&node.node_id, &previous_key, next_key.clone())
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 5);
        store
            .rotate_node_wireguard_public_key(&node.node_id, &next_key, next_key.clone())
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 5);

        let expected_node = store
            .get_node(&node.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node.node_id.clone()))?;
        let catalog_epoch = overlay_route_catalog_epoch(std::slice::from_ref(&expected_node))?;
        let rejoined = store
            .rejoin_node_if_cluster_policy(RejoinNodeStoreUpdate {
                cluster_id: cluster_id.clone(),
                expected_cluster_policy: Some(policy.clone()),
                expected_route_catalog_epoch: Some(catalog_epoch),
                expected_node,
                candidates: vec![candidate("node-a")],
                relay_capability: None,
                routes: vec![route_b.clone()],
            })
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 5);

        let accepted_at = Utc::now();
        let mut same_route_heartbeat = heartbeat_store_update(&rejoined, accepted_at);
        same_route_heartbeat.expected_cluster_policy = Some(policy.clone());
        same_route_heartbeat.expected_route_catalog_epoch = Some(overlay_route_catalog_epoch(
            std::slice::from_ref(&rejoined),
        )?);
        same_route_heartbeat.routes = Some(rejoined.routes.clone());
        store.apply_heartbeat(same_route_heartbeat).await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 5);

        let current_node = store
            .get_node(&node.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node.node_id.clone()))?;
        let route_c = route("route-c", "10.44.1.0/24", "node-a")?;
        let mut changed_route_heartbeat =
            heartbeat_store_update(&current_node, accepted_at + Duration::seconds(1));
        changed_route_heartbeat.expected_cluster_policy = Some(policy.clone());
        changed_route_heartbeat.expected_route_catalog_epoch = Some(overlay_route_catalog_epoch(
            std::slice::from_ref(&current_node),
        )?);
        changed_route_heartbeat.routes = Some(vec![route_c.clone()]);
        store.apply_heartbeat(changed_route_heartbeat).await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 6);

        set_in_memory_routing_epoch(&store, &cluster_id, u64::MAX).await;
        store
            .upsert_cluster_policy(&cluster_id, policy.clone())
            .await?;
        let current_node = store
            .get_node(&node.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node.node_id.clone()))?;
        store
            .update_node_routes(&node.node_id, current_node.routes.clone())
            .await?;
        store
            .rotate_node_wireguard_public_key(
                &node.node_id,
                &current_node.wireguard_public_key,
                current_node.wireguard_public_key.clone(),
            )
            .await?;
        let mut final_heartbeat =
            heartbeat_store_update(&current_node, accepted_at + Duration::seconds(2));
        final_heartbeat.expected_cluster_policy = Some(policy);
        final_heartbeat.expected_route_catalog_epoch = Some(overlay_route_catalog_epoch(
            std::slice::from_ref(&current_node),
        )?);
        final_heartbeat.routes = Some(vec![route_c]);
        store.apply_heartbeat(final_heartbeat).await?;
        assert_eq!(
            store.get_overlay_routing_epoch(&cluster_id).await?,
            u64::MAX
        );
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_routing_epoch_overflow_preserves_policies_and_insertions(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");
        let policy = ClusterPolicy::default();

        {
            let store = InMemoryStore::default();
            set_in_memory_routing_epoch(&store, &cluster_id, u64::MAX).await;
            assert_routing_epoch_exhausted(
                store
                    .initialize_cluster_policy_if_absent(&cluster_id, policy.clone())
                    .await,
                &cluster_id,
            );
            assert_eq!(store.get_cluster_policy(&cluster_id).await?, None);
            assert_eq!(
                store.get_overlay_routing_epoch(&cluster_id).await?,
                u64::MAX
            );
        }

        let mut changed_policy = policy.clone();
        changed_policy.idle_timeout_seconds += 1;
        {
            let store = InMemoryStore::default();
            store
                .initialize_cluster_policy_if_absent(&cluster_id, policy.clone())
                .await?;
            set_in_memory_routing_epoch(&store, &cluster_id, u64::MAX).await;
            assert_routing_epoch_exhausted(
                store
                    .upsert_cluster_policy(&cluster_id, changed_policy.clone())
                    .await,
                &cluster_id,
            );
            assert_eq!(
                store.get_cluster_policy(&cluster_id).await?,
                Some(policy.clone())
            );
        }

        {
            let store = InMemoryStore::default();
            store
                .initialize_cluster_policy_if_absent(&cluster_id, policy.clone())
                .await?;
            set_in_memory_routing_epoch(&store, &cluster_id, u64::MAX).await;
            assert_routing_epoch_exhausted(
                store
                    .upsert_cluster_policy_if_route_catalog_epoch(
                        &cluster_id,
                        changed_policy,
                        overlay_route_catalog_epoch(&[])?,
                    )
                    .await,
                &cluster_id,
            );
            assert_eq!(store.get_cluster_policy(&cluster_id).await?, Some(policy));
        }

        {
            let store = InMemoryStore::default();
            let node = node_record("overflow-direct-insert");
            set_in_memory_routing_epoch(&store, &cluster_id, u64::MAX).await;
            assert_routing_epoch_exhausted(store.insert_node(node.clone()).await, &cluster_id);
            assert_eq!(store.get_node(&node.node_id).await?, None);
        }

        {
            let store = InMemoryStore::default();
            let node = node_record("overflow-guarded-insert");
            set_in_memory_routing_epoch(&store, &cluster_id, u64::MAX).await;
            assert_routing_epoch_exhausted(
                store
                    .insert_node_if_cluster_policy(
                        node.clone(),
                        None,
                        Some(overlay_route_catalog_epoch(&[])?),
                    )
                    .await,
                &cluster_id,
            );
            assert_eq!(store.get_node(&node.node_id).await?, None);
        }
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_routing_epoch_overflow_preserves_node_mutations(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");

        {
            let store = InMemoryStore::default();
            let mut node = node_record("overflow-direct-routes");
            node.routes = vec![route("route-a", "10.42.1.0/24", "overflow-direct-routes")?];
            store.insert_node(node.clone()).await?;
            set_in_memory_routing_epoch(&store, &cluster_id, u64::MAX).await;
            assert_routing_epoch_exhausted(
                store
                    .update_node_routes(
                        &node.node_id,
                        vec![route("route-b", "10.43.1.0/24", "overflow-direct-routes")?],
                    )
                    .await,
                &cluster_id,
            );
            assert_eq!(store.get_node(&node.node_id).await?, Some(node));
        }

        {
            let store = InMemoryStore::default();
            let mut node = node_record("overflow-guarded-routes");
            node.routes = vec![route("route-a", "10.42.1.0/24", "overflow-guarded-routes")?];
            store.insert_node(node.clone()).await?;
            let catalog_epoch = overlay_route_catalog_epoch(&[node.clone()])?;
            set_in_memory_routing_epoch(&store, &cluster_id, u64::MAX).await;
            assert_routing_epoch_exhausted(
                store
                    .update_node_routes_if_cluster_policy(
                        &cluster_id,
                        &node.node_id,
                        vec![route("route-b", "10.43.1.0/24", "overflow-guarded-routes")?],
                        None,
                        Some(catalog_epoch),
                    )
                    .await,
                &cluster_id,
            );
            assert_eq!(store.get_node(&node.node_id).await?, Some(node));
        }

        {
            let store = InMemoryStore::default();
            let node = node_record("overflow-remove");
            let health = NodeHealth {
                state: HealthState::Healthy,
                last_seen_at: Utc::now(),
                latency_ms: Some(1.0),
                relay_load: None,
                message: Some("preserve".to_string()),
            };
            let observed_path = path("overflow-remove", "overflow-remove-peer");
            store.insert_node(node.clone()).await?;
            store
                .upsert_health(node.node_id.clone(), health.clone())
                .await?;
            store.upsert_path(observed_path.clone()).await?;
            set_in_memory_routing_epoch(&store, &cluster_id, u64::MAX).await;
            assert_routing_epoch_exhausted(store.remove_node(&node.node_id).await, &cluster_id);
            assert_eq!(store.get_node(&node.node_id).await?, Some(node.clone()));
            assert_eq!(store.get_health(&node.node_id).await?, Some(health));
            assert_eq!(
                store.list_paths_for(&node.node_id).await?,
                vec![observed_path]
            );
        }

        {
            let store = InMemoryStore::default();
            let mut node = node_record("overflow-rejoin");
            node.routes = vec![route("route-a", "10.42.1.0/24", "overflow-rejoin")?];
            store.insert_node(node.clone()).await?;
            let catalog_epoch = overlay_route_catalog_epoch(&[node.clone()])?;
            set_in_memory_routing_epoch(&store, &cluster_id, u64::MAX).await;
            assert_routing_epoch_exhausted(
                store
                    .rejoin_node_if_cluster_policy(RejoinNodeStoreUpdate {
                        cluster_id: cluster_id.clone(),
                        expected_cluster_policy: None,
                        expected_route_catalog_epoch: Some(catalog_epoch),
                        expected_node: node.clone(),
                        candidates: vec![candidate("overflow-rejoin")],
                        relay_capability: Some(relay_capability()),
                        routes: vec![route("route-b", "10.43.1.0/24", "overflow-rejoin")?],
                    })
                    .await,
                &cluster_id,
            );
            assert_eq!(store.get_node(&node.node_id).await?, Some(node));
        }

        {
            let store = InMemoryStore::default();
            let node = node_record("overflow-key");
            store.insert_node(node.clone()).await?;
            set_in_memory_routing_epoch(&store, &cluster_id, u64::MAX).await;
            assert_routing_epoch_exhausted(
                store
                    .rotate_node_wireguard_public_key(
                        &node.node_id,
                        &node.wireguard_public_key,
                        wireguard_public_key_for_node("overflow-next-key"),
                    )
                    .await,
                &cluster_id,
            );
            assert_eq!(store.get_node(&node.node_id).await?, Some(node));
        }
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_routing_epoch_overflow_preserves_complete_heartbeat_state(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-a");
        let store = InMemoryStore::default();
        let mut node = node_record("overflow-heartbeat");
        node.routes = vec![route("route-a", "10.42.1.0/24", "overflow-heartbeat")?];
        store.insert_node(node.clone()).await?;
        set_in_memory_routing_epoch(&store, &cluster_id, u64::MAX).await;

        let accepted_at = Utc::now();
        let mut update = heartbeat_store_update(&node, accepted_at);
        update.routes = Some(vec![route(
            "route-b",
            "10.43.1.0/24",
            "overflow-heartbeat",
        )?]);
        update.paths = vec![path("overflow-heartbeat", "overflow-heartbeat-peer")];
        assert_routing_epoch_exhausted(store.apply_heartbeat(update).await, &cluster_id);

        assert_eq!(store.get_node(&node.node_id).await?, Some(node.clone()));
        assert_eq!(store.get_health(&node.node_id).await?, None);
        assert_eq!(
            store
                .get_heartbeat_signature_timestamp(&node.node_id)
                .await?,
            None
        );
        assert_eq!(store.get_nat_classification(&node.node_id).await?, None);
        assert!(store.list_paths_for(&node.node_id).await?.is_empty());
        assert_eq!(
            store.get_overlay_routing_epoch(&cluster_id).await?,
            u64::MAX
        );
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_cluster_boundary_rejects_heartbeat_and_route_mutation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_a = ClusterId::from_string("cluster-a");
        let cluster_b = ClusterId::from_string("cluster-b");
        let store = Arc::new(InMemoryStore::default());
        let mut foreign = node_record("node-a");
        foreign.cluster_id = cluster_b;
        store.insert_node(foreign.clone()).await?;

        let mut update = heartbeat_store_update(&foreign, Utc::now());
        update.cluster_id = cluster_a.clone();
        assert!(matches!(
            store.apply_heartbeat(update).await,
            Err(ControlPlaneError::NodeNotFound(node_id)) if node_id == foreign.node_id
        ));
        assert!(matches!(
            store
                .update_node_routes_if_cluster_policy(
                    &cluster_a,
                    &foreign.node_id,
                    vec![route("foreign-route", "10.42.0.0/16", "node-a")?],
                    None,
                    None,
                )
                .await,
            Err(ControlPlaneError::NodeNotFound(node_id)) if node_id == foreign.node_id
        ));
        assert_eq!(
            store.get_node(&foreign.node_id).await?,
            Some(foreign.clone())
        );
        assert_eq!(store.get_health(&foreign.node_id).await?, None);

        let plane = ControlPlane::new(
            ControlPlaneConfig::new(cluster_a, Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?),
            store,
        );
        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: foreign.node_id.clone(),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    nat_classification: None,
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    node_signature: None,
                },
            ))
            .await;
        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeNotFound(node_id)) if node_id == foreign.node_id
        ));
        Ok(())
    }

    #[tokio::test]
    async fn registration_skips_vpn_ips_already_present_in_store(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let store = Arc::new(InMemoryStore::default());
        let mut existing = node_record("node-existing");
        existing.cluster_id = cluster_id.clone();
        existing.vpn_ip = VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)));
        store.insert_node(existing).await?;
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, store);

        let response = plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;

        assert_eq!(
            response.node.vpn_ip.0,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))
        );
        Ok(())
    }

    #[tokio::test]
    async fn node_removal_reclaims_vpn_ip_and_clears_runtime_state(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let store = Arc::new(InMemoryStore::default());
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, store.clone());
        let first = plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("node-a"))
            .await?;
        let second = plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("node-b"))
            .await?;
        assert_eq!(
            first.node.vpn_ip.0,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
        );
        assert_eq!(
            second.node.vpn_ip.0,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))
        );

        store
            .upsert_health(
                first.node.node_id.clone(),
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now(),
                    latency_ms: Some(1.0),
                    relay_load: None,
                    message: None,
                },
            )
            .await?;
        store.upsert_path(path("node-a", "node-b")).await?;
        store.upsert_path(path("node-b", "node-a")).await?;

        let unsigned = RemoveNodeRequest {
            node_id: first.node.node_id.clone(),
            node_signature: None,
        };
        assert!(matches!(
            plane.remove_node(unsigned).await,
            Err(ControlPlaneError::NodeSignatureRequired(_))
        ));
        let mut tampered = signed_remove_node("node-a");
        tampered.node_id = node_id("node-b");
        assert!(matches!(
            plane.remove_node(tampered).await,
            Err(ControlPlaneError::NodeSignatureRejected { .. })
        ));

        let removed = plane.remove_node(signed_remove_node("node-a")).await?;
        assert_eq!(removed.node.node_id, first.node.node_id);
        assert_eq!(removed.removed_path_count, 2);
        assert!(removed.removed_health);
        assert!(matches!(
            plane.peer_map_for(&first.node.node_id).await,
            Err(ControlPlaneError::NodeNotFound(_))
        ));
        assert!(plane
            .paths_for(&second.node.node_id)
            .await?
            .paths
            .is_empty());
        let metrics = plane.metrics().await?;
        assert_eq!(metrics.node_count, 1);
        assert_eq!(metrics.path_count, 0);
        assert_eq!(metrics.vpn_pool_allocated_count, 1);
        assert_eq!(metrics.vpn_pool_available_count, 5);
        assert_eq!(metrics.node_removal_success_count, 1);
        assert_eq!(metrics.node_removal_failure_count, 2);
        assert_eq!(metrics.wireguard_key_rotation_success_count, 0);
        assert_eq!(metrics.wireguard_key_rotation_failure_count, 0);

        let replacement = plane
            .register_with_claims(claims(cluster_id), registration_request("node-c"))
            .await?;
        assert_eq!(replacement.node.vpn_ip, first.node.vpn_ip);
        Ok(())
    }

    #[tokio::test]
    async fn registration_is_idempotent_for_same_node_identity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let store = Arc::new(InMemoryStore::default());
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, store);
        let mut request = registration_request("node-a");
        request.candidates = vec![EndpointCandidate {
            node_id: request.node_id.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr: "198.51.100.10:40000".parse()?,
            observed_at: Utc::now(),
            priority: 80,
            cost: 20,
            source: CandidateSource::StunProbe,
        }];

        let first = plane
            .register_with_claims(claims(cluster_id.clone()), request.clone())
            .await?;
        request.candidates[0].addr = "198.51.100.10:40001".parse()?;
        let second = plane
            .register_with_claims(claims(cluster_id), request.clone())
            .await?;

        assert_eq!(second.node.node_id, first.node.node_id);
        assert_eq!(second.node.vpn_ip, first.node.vpn_ip);
        assert_eq!(second.node.endpoint_candidates, request.candidates);
        assert_eq!(plane.peer_map_for(&request.node_id).await?.peers.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn sponsored_client_registration_requires_both_signatures_and_is_retryable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-sponsored-client");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(10, 250, 0, 0), 29)?,
            ),
            store,
        );
        let sponsor_identity = identity_for_node("ssh-sponsor");
        let mut sponsor_claims = claims(cluster_id);
        sponsor_claims.role = Role::gateway();
        let mut sponsor_registration = registration_request("ssh-sponsor");
        sponsor_registration.candidates = vec![EndpointCandidate {
            node_id: sponsor_identity.node_id(),
            kind: EndpointCandidateKind::PublicUdp,
            addr: "8.8.8.8:51820".parse()?,
            observed_at: Utc::now(),
            priority: 100,
            cost: 1,
            source: CandidateSource::InterfaceScan,
        }];
        plane
            .register_with_claims(sponsor_claims, sponsor_registration)
            .await?;

        let client_identity = identity_for_node("desktop-client");
        let issued_at = chrono::DateTime::from_timestamp(Utc::now().timestamp(), 0)
            .ok_or("current whole-second timestamp is invalid")?;
        let mut bundle = ClientRegistrationBundle {
            schema_version: CLIENT_REGISTRATION_SCHEMA_VERSION,
            registration: RegisterClientRequest {
                client_id: client_identity.node_id(),
                identity_public_key: client_identity.public_key_b64(),
                wireguard_public_key: wireguard_public_key_for_node("desktop-client"),
            },
            issued_at,
            expires_at: issued_at + Duration::hours(1),
            nonce: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD".to_string(),
            signature: String::new(),
        };
        bundle.signature = client_identity.sign_client_registration_bundle(&bundle);
        let mut request = SponsoredClientRegistrationRequest {
            sponsor_node_id: sponsor_identity.node_id(),
            bundle: bundle.clone(),
            request_signature: None,
        };
        request.request_signature = Some(
            sponsor_identity.sign_sponsored_client_registration_request(&request, Utc::now())?,
        );

        let mut fractional_bundle = bundle.clone();
        fractional_bundle.expires_at += Duration::nanoseconds(1);
        assert!(
            verify_client_registration_bundle_signature(&fractional_bundle).is_ok(),
            "whole-second signature compatibility should not silently admit fractions"
        );
        let mut fractional_request = SponsoredClientRegistrationRequest {
            sponsor_node_id: sponsor_identity.node_id(),
            bundle: fractional_bundle,
            request_signature: None,
        };
        fractional_request.request_signature = Some(
            sponsor_identity
                .sign_sponsored_client_registration_request(&fractional_request, Utc::now())?,
        );
        assert!(matches!(
            plane
                .register_sponsored_client(fractional_request, Utc::now())
                .await,
            Err(ControlPlaneError::NodeRegistrationRejected { reason, .. })
                if reason.contains("whole-second precision")
        ));

        let first = plane
            .register_sponsored_client(request.clone(), Utc::now())
            .await?;
        assert_eq!(first.client.node_id, client_identity.node_id());
        assert_eq!(first.peer_map.peers.len(), 1);
        assert!(first.peer_map.peers[0]
            .endpoint_candidates
            .iter()
            .all(|candidate| {
                matches!(
                    candidate.kind,
                    EndpointCandidateKind::PublicUdp | EndpointCandidateKind::Ipv6
                ) && socket_addr_is_globally_routable(candidate.addr)
            }));
        assert!(matches!(
            plane.register_sponsored_client(request, Utc::now()).await,
            Err(ControlPlaneError::NodeRequestReplay(_))
        ));

        let mut retry = SponsoredClientRegistrationRequest {
            sponsor_node_id: sponsor_identity.node_id(),
            bundle: bundle.clone(),
            request_signature: None,
        };
        retry.request_signature =
            Some(sponsor_identity.sign_sponsored_client_registration_request(&retry, Utc::now())?);
        let retried = plane.register_sponsored_client(retry, Utc::now()).await?;
        assert_eq!(retried.client.vpn_ip, first.client.vpn_ip);

        let mut tampered_bundle = bundle;
        tampered_bundle.registration.wireguard_public_key =
            wireguard_public_key_for_node("attacker");
        let mut tampered = SponsoredClientRegistrationRequest {
            sponsor_node_id: sponsor_identity.node_id(),
            bundle: tampered_bundle,
            request_signature: None,
        };
        tampered.request_signature = Some(
            sponsor_identity.sign_sponsored_client_registration_request(&tampered, Utc::now())?,
        );
        assert!(matches!(
            plane.register_sponsored_client(tampered, Utc::now()).await,
            Err(ControlPlaneError::NodeRegistrationRejected { .. })
        ));
        Ok(())
    }

    #[test]
    fn client_gateway_rejects_non_global_ipv6_candidates() {
        let now = Utc::now();
        let mut node = node_record("ula-gateway");
        node.endpoint_candidates = vec![EndpointCandidate {
            node_id: node.node_id.clone(),
            kind: EndpointCandidateKind::Ipv6,
            addr: "[fd00::1]:51820"
                .parse()
                .unwrap_or_else(|error| panic!("ULA candidate should parse: {error}")),
            observed_at: now,
            priority: 100,
            cost: 1,
            source: CandidateSource::InterfaceScan,
        }];
        assert!(client_gateway_candidate_score(&node, now, &ClusterPolicy::default()).is_none());

        node.endpoint_candidates[0].addr = "[2606:4700:4700::1111]:51820"
            .parse()
            .unwrap_or_else(|error| panic!("global IPv6 candidate should parse: {error}"));
        assert!(client_gateway_candidate_score(&node, now, &ClusterPolicy::default()).is_some());
        node.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(
                "8.8.8.8:51820"
                    .parse()
                    .unwrap_or_else(|error| panic!("relay endpoint should parse: {error}")),
            ),
            admission_url: Some("https://8.8.8.8:18447".to_string()),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        });
        let ipv6_disabled = ClusterPolicy {
            allow_ipv6_direct: false,
            ..ClusterPolicy::default()
        };
        assert!(client_gateway_candidate_score(&node, now, &ipv6_disabled).is_none());
        let projected = filter_client_gateway_endpoint_candidates(node, now, &ipv6_disabled);
        assert!(projected.endpoint_candidates.is_empty());
        assert_eq!(projected.relay_capability, None);
    }

    #[tokio::test]
    async fn control_client_receives_ready_gateway_failover_without_joining_the_mesh(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-client");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 96, 0, 0), 29)?,
            ),
            store.clone(),
        );

        let mut gateway_claims = claims(cluster_id.clone());
        gateway_claims.role = Role::gateway();
        let mut gateway_registration = registration_request("client-gateway");
        gateway_registration.candidates = vec![candidate("client-gateway")];
        gateway_registration.candidates[0].kind = EndpointCandidateKind::PublicUdp;
        gateway_registration.candidates[0].addr = "8.8.8.8:51820".parse()?;
        gateway_registration.candidates[0].cost = 1;
        let gateway = plane
            .register_with_claims(gateway_claims, gateway_registration)
            .await?
            .node;
        let mut backup_claims = claims(cluster_id.clone());
        backup_claims.role = Role::gateway();
        let mut backup_registration = registration_request("client-gateway-backup");
        backup_registration.candidates = vec![candidate("client-gateway-backup")];
        backup_registration.candidates[0].kind = EndpointCandidateKind::PublicUdp;
        backup_registration.candidates[0].addr = "8.8.4.4:51820".parse()?;
        backup_registration.candidates[0].cost = 20;
        let backup_gateway = plane
            .register_with_claims(backup_claims, backup_registration)
            .await?
            .node;
        let worker = plane
            .register_with_claims(
                claims(cluster_id.clone()),
                registration_request("client-worker"),
            )
            .await?
            .node;

        let client_identity = identity_for_node("mac-client");
        let mut client_claims = claims(cluster_id);
        client_claims.role = Role::client();
        client_claims.tags.clear();
        client_claims.policy.allowed_tags.clear();
        client_claims.policy.max_token_uses = Some(1);

        let mut reusable_client_claims = client_claims.clone();
        reusable_client_claims.policy.max_token_uses = Some(2);
        let reusable_identity = identity_for_node("reusable-mac-client");
        let reusable_wireguard_public_key = wireguard_public_key_for_node("reusable-mac-client");
        assert!(matches!(
            plane
                .register_client_with_claims(
                    reusable_client_claims,
                    RegisterClientRequest {
                        client_id: reusable_identity.node_id(),
                        identity_public_key: reusable_identity.public_key_b64(),
                        wireguard_public_key: reusable_wireguard_public_key,
                    },
                )
                .await,
            Err(ControlPlaneError::JoinDenied)
        ));

        let mut tagged_client_claims = client_claims.clone();
        tagged_client_claims
            .tags
            .insert(Tag::from_string("privileged"));
        tagged_client_claims
            .policy
            .allowed_tags
            .insert(Tag::from_string("privileged"));
        let tagged_identity = identity_for_node("tagged-mac-client");
        assert!(matches!(
            plane
                .register_client_with_claims(
                    tagged_client_claims,
                    RegisterClientRequest {
                        client_id: tagged_identity.node_id(),
                        identity_public_key: tagged_identity.public_key_b64(),
                        wireguard_public_key: wireguard_public_key_for_node("tagged-mac-client"),
                    },
                )
                .await,
            Err(ControlPlaneError::JoinDenied)
        ));

        let registration = plane
            .register_client_with_claims(
                client_claims,
                RegisterClientRequest {
                    client_id: client_identity.node_id(),
                    identity_public_key: client_identity.public_key_b64(),
                    wireguard_public_key: wireguard_public_key_for_node("mac-client"),
                },
            )
            .await?;
        let client = registration.client;
        let worker_cidr: IpNet = format!("{}/32", worker.vpn_ip).parse()?;
        let client_cidr: IpNet = format!("{}/32", client.vpn_ip).parse()?;

        assert_eq!(registration.peer_map.peers.len(), 2);
        assert_eq!(registration.peer_map.peers[0].node_id, gateway.node_id);
        assert!(registration
            .peer_map
            .peers
            .iter()
            .all(|gateway| gateway.routes.iter().any(|route| route.cidr == worker_cidr)));

        let listed_nodes = plane.list_nodes().await?;
        assert_eq!(listed_nodes.len(), 3);
        assert!(listed_nodes.iter().all(|node| !node.role.is_client()));
        let metrics = plane.metrics().await?;
        assert_eq!(metrics.node_count, 3);
        assert_eq!(metrics.client_count, 1);
        assert_eq!(metrics.vpn_pool_allocated_count, 4);

        let gateway_map = plane.peer_map_for(&gateway.node_id).await?;
        assert!(gateway_map
            .peers
            .iter()
            .any(|peer| peer.node_id == client.node_id));
        let backup_gateway_map = plane.peer_map_for(&backup_gateway.node_id).await?;
        assert!(backup_gateway_map
            .peers
            .iter()
            .all(|peer| peer.node_id != client.node_id));
        assert!(backup_gateway_map.peers.iter().any(|peer| {
            peer.node_id == gateway.node_id
                && peer.routes.iter().any(|route| {
                    route.cidr == client_cidr
                        && route.advertised_by == gateway.node_id
                        && route.via.as_ref() == Some(&gateway.node_id)
                })
        }));
        let worker_map = plane.peer_map_for(&worker.node_id).await?;
        assert!(worker_map
            .peers
            .iter()
            .all(|peer| peer.node_id != client.node_id));
        assert!(worker_map.peers.iter().any(|peer| {
            peer.node_id == gateway.node_id
                && peer.routes.iter().any(|route| {
                    route.cidr == client_cidr
                        && route.advertised_by == gateway.node_id
                        && route.via.as_ref() == Some(&gateway.node_id)
                })
        }));

        let mut query = ClientControlRequest {
            client_id: client.node_id.clone(),
            active_gateway_node_id: Some(backup_gateway.node_id.clone()),
            request_signature: None,
        };
        query.request_signature = Some(client_identity.sign_client_control_request(
            &query,
            ClientRequestKind::PeerMap,
            Utc::now(),
        ));
        let authenticated = plane
            .authenticate_client_request(&query, ClientRequestKind::PeerMap, Utc::now())
            .await?;
        let waiting_heartbeat = plane.wait_for_connection_intents(
            &worker.node_id,
            HeartbeatResponse {
                accepted: true,
                policy_version: 0,
                peer_delta_available: false,
                bootstrap_endpoints: Vec::new(),
                connection_intents: Vec::new(),
            },
            std::time::Duration::from_secs(2),
        );
        let selection_update = async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            plane
                .update_client_gateway_selection(
                    &authenticated,
                    query.active_gateway_node_id.as_ref(),
                    Utc::now(),
                )
                .await
        };
        let (heartbeat, selection_update) = tokio::join!(waiting_heartbeat, selection_update);
        selection_update?;
        assert!(heartbeat?.peer_delta_available);
        let selected_backup = plane.peer_map_for(&client.node_id).await?;
        assert_eq!(selected_backup.peers[0].node_id, backup_gateway.node_id);
        let primary_gateway_after_client_switch = plane.peer_map_for(&gateway.node_id).await?;
        assert!(primary_gateway_after_client_switch
            .peers
            .iter()
            .all(|peer| peer.node_id != client.node_id));
        assert!(primary_gateway_after_client_switch
            .peers
            .iter()
            .any(|peer| {
                peer.node_id == backup_gateway.node_id
                    && peer.routes.iter().any(|route| {
                        route.cidr == client_cidr
                            && route.advertised_by == backup_gateway.node_id
                            && route.via.as_ref() == Some(&backup_gateway.node_id)
                    })
            }));
        let backup_gateway_after_client_switch =
            plane.peer_map_for(&backup_gateway.node_id).await?;
        assert!(backup_gateway_after_client_switch
            .peers
            .iter()
            .any(|peer| peer.node_id == client.node_id));
        let worker_after_client_switch = plane.peer_map_for(&worker.node_id).await?;
        assert!(worker_after_client_switch.peers.iter().any(|peer| {
            peer.node_id == backup_gateway.node_id
                && peer.routes.iter().any(|route| {
                    route.cidr == client_cidr
                        && route.advertised_by == backup_gateway.node_id
                        && route.via.as_ref() == Some(&backup_gateway.node_id)
                })
        }));
        assert!(worker_after_client_switch.peers.iter().all(|peer| {
            peer.node_id != gateway.node_id
                || peer.routes.iter().all(|route| route.cidr != client_cidr)
        }));

        store
            .upsert_health(
                gateway.node_id.clone(),
                NodeHealth {
                    state: HealthState::Unhealthy,
                    last_seen_at: Utc::now(),
                    latency_ms: None,
                    relay_load: None,
                    message: Some("test failure".to_string()),
                },
            )
            .await?;
        let failed_over = plane.peer_map_for(&client.node_id).await?;
        assert_eq!(failed_over.peers.len(), 1);
        assert_eq!(failed_over.peers[0].node_id, backup_gateway.node_id);

        assert!(matches!(
            plane.paths_for(&client.node_id).await,
            Err(ControlPlaneError::NodeUpdateRejected { .. })
        ));
        assert!(matches!(
            plane
                .rotate_wireguard_key(signed_wireguard_key_rotation(
                    "mac-client",
                    client.wireguard_public_key.clone(),
                    wireguard_public_key_for_node("mac-client-rotated"),
                ))
                .await,
            Err(ControlPlaneError::NodeUpdateRejected { .. })
        ));

        assert!(matches!(
            plane
                .authenticate_client_request(&query, ClientRequestKind::PeerMap, Utc::now())
                .await,
            Err(ControlPlaneError::NodeRequestReplay(_))
        ));

        let mut removal = ClientControlRequest {
            client_id: client.node_id.clone(),
            active_gateway_node_id: None,
            request_signature: None,
        };
        removal.request_signature = Some(client_identity.sign_client_control_request(
            &removal,
            ClientRequestKind::Remove,
            Utc::now(),
        ));
        let removed = plane.remove_client(removal).await?;
        assert_eq!(removed.client.node_id, client.node_id);
        let metrics = plane.metrics().await?;
        assert_eq!(metrics.node_count, 3);
        assert_eq!(metrics.client_count, 0);
        assert_eq!(metrics.vpn_pool_allocated_count, 3);
        Ok(())
    }

    #[tokio::test]
    async fn registration_rejoin_updates_routes_within_token_policy(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let store = Arc::new(InMemoryStore::default());
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, store.clone());
        let mut token_claims = claims(cluster_id.clone());
        token_claims.policy.allowed_routes = vec!["10.96.0.0/12".parse()?];
        let mut request = registration_request("node-a");
        let initial_route = route("service-a", "10.96.10.0/24", "node-a")?;
        request.requested_routes = vec![initial_route.clone()];

        plane
            .register_with_claims(token_claims.clone(), request.clone())
            .await?;
        let replacement_route = route("service-b", "10.96.20.0/24", "node-a")?;
        request.requested_routes = vec![replacement_route.clone()];

        let response = plane.register_with_claims(token_claims, request).await?;

        assert_eq!(response.node.routes, vec![replacement_route.clone()]);
        assert_eq!(
            store
                .get_node(&response.node.node_id)
                .await?
                .ok_or("rejoined node was not persisted")?
                .routes,
            vec![replacement_route]
        );
        assert_ne!(response.node.routes, vec![initial_route]);
        Ok(())
    }

    #[tokio::test]
    async fn registration_rejects_existing_node_with_different_wireguard_key(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let store = Arc::new(InMemoryStore::default());
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, store);
        let mut request = registration_request("node-a");
        plane
            .register_with_claims(claims(cluster_id.clone()), request.clone())
            .await?;

        request.wireguard_public_key = wireguard_public_key_for_node("node-a-replacement");
        let error = plane
            .register_with_claims(claims(cluster_id), request)
            .await;

        assert!(matches!(
            error,
            Err(ControlPlaneError::NodeAlreadyExists(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn registration_retries_after_vpn_ip_insert_race(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let store = Arc::new(RacingVpnIpStore::default());
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, store.clone());

        let response = plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;

        assert_eq!(
            response.node.vpn_ip.0,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))
        );
        let nodes = store.list_nodes().await?;
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().any(|node| {
            node.node_id == node_id("node-racing-peer")
                && node.vpn_ip.0 == IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
        }));
        Ok(())
    }

    #[tokio::test]
    async fn registration_allows_routes_within_token_route_policy(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 30)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        let mut request = registration_request("node-a");
        request.requested_routes = vec![route("route-a", "10.42.1.0/24", "node-a")?];
        let mut claims = claims(cluster_id);
        claims.policy.allowed_routes = vec!["10.42.0.0/16".parse()?];

        let response = plane.register_with_claims(claims, request).await?;

        assert_eq!(response.node.routes.len(), 1);
        assert_eq!(response.node.routes[0].cidr, "10.42.1.0/24".parse()?);
        Ok(())
    }

    #[tokio::test]
    async fn registration_rejects_routes_outside_token_route_policy(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 30)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        let mut request = registration_request("node-a");
        request.requested_routes = vec![route("route-a", "10.43.0.0/16", "node-a")?];
        let mut claims = claims(cluster_id);
        claims.policy.allowed_routes = vec!["10.42.0.0/16".parse()?];

        let error = match plane.register_with_claims(claims, request).await {
            Ok(_) => return Err("unexpected successful route registration".into()),
            Err(error) => error,
        };

        assert!(matches!(error, ControlPlaneError::RouteDenied(route) if route == "route-a"));
        Ok(())
    }

    #[tokio::test]
    async fn registration_rejects_unowned_candidates_and_routes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 30)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));

        let mut candidate_request = registration_request("node-a");
        candidate_request.candidates = vec![candidate("node-b")];
        let error = match plane
            .register_with_claims(claims(cluster_id.clone()), candidate_request)
            .await
        {
            Ok(_) => return Err("unexpected successful candidate registration".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeRegistrationRejected { .. }
        ));

        let mut route_request = registration_request("node-a");
        route_request.requested_routes = vec![route("route-b", "10.42.1.0/24", "node-b")?];
        let mut route_claims = claims(cluster_id);
        route_claims.policy.allowed_routes = vec!["10.42.0.0/16".parse()?];
        let error = match plane
            .register_with_claims(route_claims, route_request)
            .await
        {
            Ok(_) => return Err("unexpected successful route registration".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeRegistrationRejected { .. }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn registration_rejects_future_endpoint_candidate_before_persistence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 30)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let mut request = registration_request("node-a");
        let mut future_candidate = candidate("node-a");
        future_candidate.observed_at = Utc::now() + Duration::seconds(301);
        request.candidates = vec![future_candidate];

        let result = plane
            .register_with_claims(claims(cluster_id), request)
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeRegistrationRejected { reason, .. })
                if reason.contains("observed_at")
                    && reason.contains("too far in the future")
        ));
        assert!(store.list_nodes().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn registration_rejects_invalid_route_shape() -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 30)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        let mut claims = claims(cluster_id);
        claims.policy.allowed_routes = vec!["10.42.0.0/16".parse()?];

        let mut zero_metric = route("route-zero-metric", "10.42.1.0/24", "node-a")?;
        zero_metric.metric = 0;
        let mut cases = vec![
            (
                vec![route("", "10.42.1.0/24", "node-a")?],
                "route ID cannot be empty",
            ),
            (
                vec![route("bad/route", "10.42.1.0/24", "node-a")?],
                "route ID must contain only ASCII letters",
            ),
            (
                vec![
                    route("route-a", "10.42.1.0/24", "node-a")?,
                    route("route-a", "10.42.2.0/24", "node-a")?,
                ],
                "must not repeat route ID route-a",
            ),
            (
                vec![
                    route("route-a", "10.42.1.0/24", "node-a")?,
                    route("route-b", "10.42.1.0/24", "node-a")?,
                ],
                "must not repeat CIDR 10.42.1.0/24",
            ),
            (
                vec![route("route-noncanonical", "10.42.1.1/24", "node-a")?],
                "must use canonical CIDR 10.42.1.0/24",
            ),
            (
                vec![route("route-unrestricted", "0.0.0.0/0", "node-a")?],
                "must not include unrestricted CIDR 0.0.0.0/0",
            ),
            (
                vec![route("route-loopback", "127.0.0.0/8", "node-a")?],
                "must not include loopback CIDR 127.0.0.0/8",
            ),
            (
                vec![route("route-ipv6-link-local", "fe80::/10", "node-a")?],
                "must not include link-local CIDR fe80::/10",
            ),
            (
                vec![zero_metric],
                "route route-zero-metric metric must be greater than zero",
            ),
        ];
        cases.push((
            (0..=MAX_OVERLAY_NODE_ROUTES)
                .map(|index| {
                    route(
                        &format!("route-{index}"),
                        &format!("10.42.{}.{}/32", index / 256, index % 256),
                        "node-a",
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
            "maximum is 256",
        ));

        for (routes, expected) in cases {
            let mut request = registration_request("node-a");
            request.requested_routes = routes;
            let error = match plane.register_with_claims(claims.clone(), request).await {
                Ok(_) => return Err("unexpected successful route registration".into()),
                Err(error) => error,
            };

            assert!(
                matches!(
                    error,
                    ControlPlaneError::NodeRegistrationRejected { ref reason, .. }
                        if reason.contains(expected)
                ),
                "expected {expected}, got {error}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn registration_rejects_invalid_candidate_kind_addresses(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 30)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        let mut request = registration_request("node-a");
        request.candidates = vec![invalid_ipv6_candidate("node-a")];

        let error = match plane
            .register_with_claims(claims(cluster_id), request)
            .await
        {
            Ok(_) => return Err("unexpected successful candidate registration".into()),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ControlPlaneError::NodeRegistrationRejected { .. }
        ));
        assert!(error.to_string().contains("IPv6 candidates must use"));
        Ok(())
    }

    #[tokio::test]
    async fn registration_rejects_invalid_identity_public_key(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 30)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        let mut request = registration_request("node-a");
        request.identity_public_key = "not-valid-base64".to_string();

        let error = match plane
            .register_with_claims(claims(cluster_id.clone()), request)
            .await
        {
            Ok(_) => return Err("unexpected successful identity registration".into()),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ControlPlaneError::NodeRegistrationRejected { .. }
        ));

        let mut mismatched = registration_request("node-a");
        mismatched.node_id = node_id("node-b");
        let error = match plane
            .register_with_claims(claims(cluster_id), mismatched)
            .await
        {
            Ok(_) => return Err("unexpected successful mismatched identity registration".into()),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ControlPlaneError::NodeRegistrationRejected { .. }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn registration_rejects_invalid_wireguard_public_key(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 30)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        let mut request = registration_request("node-a");
        request.wireguard_public_key = "not-valid-base64".to_string();

        let error = match plane
            .register_with_claims(claims(cluster_id.clone()), request)
            .await
        {
            Ok(_) => return Err("unexpected successful WireGuard key registration".into()),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ControlPlaneError::NodeRegistrationRejected { .. }
        ));

        let mut short_key = registration_request("node-b");
        short_key.wireguard_public_key = encode_bytes(&[1, 2, 3]);
        let error = match plane
            .register_with_claims(claims(cluster_id), short_key)
            .await
        {
            Ok(_) => return Err("unexpected successful short WireGuard key registration".into()),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ControlPlaneError::NodeRegistrationRejected { .. }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn signed_wireguard_key_rotation_updates_registered_node(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 30)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        let registration = plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let previous_key = registration.node.wireguard_public_key;
        let next_key = wireguard_public_key_for_node("node-a-rotated");

        let rotation =
            signed_wireguard_key_rotation("node-a", previous_key.clone(), next_key.clone());
        let response = plane.rotate_wireguard_key(rotation.clone()).await?;

        assert_eq!(response.node.node_id, node_id("node-a"));
        assert_eq!(response.node.wireguard_public_key, next_key);
        assert!(response.peer_map.peers.is_empty());

        let replay = plane.rotate_wireguard_key(rotation).await;
        assert!(matches!(
            replay,
            Err(ControlPlaneError::NodeUpdateRejected { .. })
        ));

        let mut tampered =
            signed_wireguard_key_rotation("node-a", next_key.clone(), previous_key.clone());
        tampered.next_wireguard_public_key = wireguard_public_key_for_node("node-a-tampered");
        assert!(matches!(
            plane.rotate_wireguard_key(tampered).await,
            Err(ControlPlaneError::NodeSignatureRejected { .. })
        ));

        let unsigned = RotateWireGuardKeyRequest {
            node_id: node_id("node-a"),
            previous_wireguard_public_key: next_key,
            next_wireguard_public_key: wireguard_public_key_for_node("node-a-next"),
            node_signature: None,
        };
        assert!(matches!(
            plane.rotate_wireguard_key(unsigned).await,
            Err(ControlPlaneError::NodeSignatureRequired(_))
        ));
        let metrics = plane.metrics().await?;
        assert_eq!(metrics.wireguard_key_rotation_success_count, 1);
        assert_eq!(metrics.wireguard_key_rotation_failure_count, 3);
        assert_eq!(metrics.node_removal_success_count, 0);
        assert_eq!(metrics.node_removal_failure_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn registration_rejects_relay_capability_when_token_policy_denies_relay(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 30)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        let mut request = registration_request("node-a");
        request.relay_capability = Some(relay_capability());

        let error = match plane
            .register_with_claims(claims(cluster_id), request)
            .await
        {
            Ok(_) => return Err("unexpected successful relay registration".into()),
            Err(error) => error,
        };

        assert!(matches!(error, ControlPlaneError::RelayDenied));
        Ok(())
    }

    #[tokio::test]
    async fn registration_rejects_invalid_relay_capability_shape(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        let mut relay_claims = claims(cluster_id.clone());
        relay_claims.policy.allow_relay = true;

        let mut bad_endpoint = relay_capability();
        bad_endpoint.public_endpoint = Some(std::net::SocketAddr::from(([0, 0, 0, 0], 51820)));
        let mut request = registration_request("node-a");
        request.relay_capability = Some(bad_endpoint);
        let error = match plane
            .register_with_claims(relay_claims.clone(), request)
            .await
        {
            Ok(_) => return Err("unexpected successful relay registration".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeRegistrationRejected { .. }
        ));
        assert!(error.to_string().contains("relay public endpoint"));

        let mut bad_admission_url = relay_capability();
        bad_admission_url.admission_url = Some("udp://203.0.113.10:9580".to_string());
        let mut request = registration_request("node-b");
        request.relay_capability = Some(bad_admission_url);
        let error = match plane
            .register_with_claims(relay_claims.clone(), request)
            .await
        {
            Ok(_) => return Err("unexpected successful relay registration".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeRegistrationRejected { .. }
        ));
        assert!(error.to_string().contains("relay admission URL"));

        let mut unusable_admission_url = relay_capability();
        unusable_admission_url.admission_url = Some("http://0.0.0.0:9580".to_string());
        let mut request = registration_request("node-c");
        request.relay_capability = Some(unusable_admission_url);
        let error = match plane.register_with_claims(relay_claims, request).await {
            Ok(_) => return Err("unexpected successful relay registration".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeRegistrationRejected { .. }
        ));
        assert!(error.to_string().contains("relay admission URL"));
        Ok(())
    }

    #[tokio::test]
    async fn overlay_path_rejects_a_source_owned_destination(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        let source = plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("node-a"))
            .await?
            .node;
        let target = plane
            .register_with_claims(claims(cluster_id), registration_request("node-b"))
            .await?
            .node;
        let query = |destination| OverlayPathQuery {
            source: source.node_id.clone(),
            destination,
            source_identity_proof: ipars_types::api::NodeApiRequestSignature {
                signed_at: Utc::now(),
                nonce: "overlay-self-path-test".to_string(),
                signature: String::new(),
            },
        };

        assert!(matches!(
            plane.overlay_path_for(&query(source.vpn_ip.0)).await,
            Err(ControlPlaneError::OverlayDestinationNotFound(destination))
                if destination == source.vpn_ip.0
        ));

        let path = plane.overlay_path_for(&query(target.vpn_ip.0)).await?;
        assert_eq!(path.source, source.node_id);
        assert_eq!(path.target.node_id, target.node_id);
        assert_eq!(path.ordered_nodes.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_applies_acl_roles_tags_and_routes() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut config = ControlPlaneConfig::new(
            ClusterId::from_string("cluster-a"),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        config.cluster_policy.acl_rules = vec![
            AclRule {
                id: "edge-to-app".to_string(),
                from_roles: BTreeSet::from([Role::edge()]),
                from_tags: BTreeSet::new(),
                to_roles: BTreeSet::new(),
                to_tags: BTreeSet::from([Tag::from_string("app")]),
                routes: Vec::new(),
                protocol: TransportProtocol::Any,
                action: AclAction::Allow,
            },
            AclRule {
                id: "deny-blocked".to_string(),
                from_roles: BTreeSet::new(),
                from_tags: BTreeSet::new(),
                to_roles: BTreeSet::new(),
                to_tags: BTreeSet::from([Tag::from_string("blocked")]),
                routes: Vec::new(),
                protocol: TransportProtocol::Any,
                action: AclAction::Deny,
            },
            AclRule {
                id: "allow-route".to_string(),
                from_roles: BTreeSet::new(),
                from_tags: BTreeSet::new(),
                to_roles: BTreeSet::new(),
                to_tags: BTreeSet::new(),
                routes: vec!["10.42.0.0/16".parse()?],
                protocol: TransportProtocol::Any,
                action: AclAction::Allow,
            },
        ];
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let mut source = node_record("source");
        source.tags.insert(Tag::from_string("client"));
        let mut allowed = node_record("allowed");
        allowed.tags.insert(Tag::from_string("app"));
        let mut denied = node_record("denied");
        denied.tags.insert(Tag::from_string("app"));
        denied.tags.insert(Tag::from_string("blocked"));
        let mut route_provider = node_record("route-provider");
        route_provider.routes = vec![
            route("allowed-route", "10.42.1.0/24", "route-provider")?,
            route("denied-route", "10.99.0.0/16", "route-provider")?,
        ];

        store.insert_node(source.clone()).await?;
        store.insert_node(allowed.clone()).await?;
        store.insert_node(denied).await?;
        store.insert_node(route_provider).await?;

        let peer_map = plane.peer_map_for(&source.node_id).await?;

        assert_eq!(peer_map.peers.len(), 2);
        let allowed_peer = peer_map
            .peers
            .iter()
            .find(|peer| peer.node_id == node_id("allowed"))
            .ok_or("allowed peer should be visible")?;
        assert!(allowed_peer.routes.is_empty());
        let route_peer = peer_map
            .peers
            .iter()
            .find(|peer| peer.node_id == node_id("route-provider"))
            .ok_or("route provider should be visible")?;
        assert_eq!(route_peer.routes.len(), 1);
        assert_eq!(route_peer.routes[0].id, "allowed-route");
        assert!(peer_map
            .peers
            .iter()
            .all(|peer| peer.node_id != node_id("denied")));
        store.upsert_path(path("source", "allowed")).await?;
        store.upsert_path(path("source", "denied")).await?;
        store.upsert_path(path("route-provider", "source")).await?;

        let paths = plane.paths_for(&source.node_id).await?;

        assert_eq!(paths.node_id, source.node_id);
        assert_eq!(paths.paths.len(), 2);
        assert!(paths.paths.iter().any(|path| {
            path.key.local == node_id("source") && path.key.remote == node_id("allowed")
        }));
        assert!(paths.paths.iter().any(|path| {
            path.key.local == node_id("route-provider") && path.key.remote == node_id("source")
        }));
        assert!(paths
            .paths
            .iter()
            .all(|path| path.key.remote != node_id("denied")));
        let metrics = plane.metrics().await?;
        assert_eq!(metrics.peer_map_candidate_count, 12);
        assert_eq!(metrics.peer_map_visible_count, 6);
        assert_eq!(metrics.peer_map_acl_denied_count, 6);
        assert_eq!(metrics.peer_map_route_candidate_count, 6);
        assert_eq!(metrics.peer_map_route_visible_count, 3);
        assert_eq!(metrics.peer_map_route_acl_denied_count, 3);
        Ok(())
    }

    #[tokio::test]
    async fn connection_intents_include_only_fresh_incoming_local_activity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = ControlPlaneConfig::new(
            ClusterId::from_string("cluster-a"),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        config.cluster_policy.idle_timeout_seconds = 10;
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        store.insert_node(node_record("source")).await?;
        store.insert_node(node_record("target")).await?;
        store.insert_node(node_record("stale-source")).await?;
        store.insert_node(node_record("remote-only-source")).await?;
        let now = Utc::now();
        let fresh_activity_at =
            chrono::DateTime::<Utc>::from_timestamp_millis(now.timestamp_millis())
                .ok_or("current test timestamp should fit in milliseconds")?;
        let stale_activity_at = fresh_activity_at - Duration::seconds(11);

        let mut fresh = path("source", "target");
        fresh.updated_at = now;
        fresh.score.reasons.push(format!(
            "{LAZY_CONNECT_LOCAL_ACTIVITY_REASON_PREFIX}{}",
            fresh_activity_at.timestamp_millis()
        ));
        store.upsert_path(fresh).await?;
        let mut stale = path("stale-source", "target");
        stale.updated_at = now;
        stale.score.reasons.push(format!(
            "{LAZY_CONNECT_LOCAL_ACTIVITY_REASON_PREFIX}{}",
            stale_activity_at.timestamp_millis()
        ));
        store.upsert_path(stale).await?;
        store
            .upsert_path(path("remote-only-source", "target"))
            .await?;

        let intents = plane
            .connection_intents_for(&node_id("target"), now)
            .await?;
        let source_vpn_ip = store
            .get_node(&node_id("source"))
            .await?
            .ok_or("source node should remain registered")?
            .vpn_ip;

        assert_eq!(
            intents,
            vec![PeerConnectionIntent {
                peer: node_id("source"),
                peer_vpn_ip: source_vpn_ip,
                observed_at: fresh_activity_at,
            }]
        );
        Ok(())
    }

    #[tokio::test]
    async fn waiting_heartbeat_wakes_when_peer_reports_local_activity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let mut config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        config.cluster_policy.idle_timeout_seconds = 10;
        let store = Arc::new(InMemoryStore::default());
        let plane = Arc::new(ControlPlane::new(config, store));
        plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("source"))
            .await?;
        plane
            .register_with_claims(claims(cluster_id), registration_request("target"))
            .await?;

        let health = |at| NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: at,
            latency_ms: None,
            relay_load: None,
            message: None,
        };
        let target_reported_at = Utc::now();
        let target_request = signed_heartbeat_at(
            "target",
            HeartbeatRequest {
                node_id: node_id("target"),
                health: health(target_reported_at),
                candidates: Vec::new(),
                nat_classification: None,
                relay_capability: None,
                routes: None,
                service_advertisement: None,
                path_state: Vec::new(),
                node_signature: None,
            },
            target_reported_at,
        );
        let waiting_plane = plane.clone();
        let waiter = tokio::spawn(async move {
            waiting_plane
                .heartbeat_with_connection_intent_wait(
                    target_request,
                    std::time::Duration::from_secs(2),
                )
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let source_reported_at = Utc::now();
        let mut source_path = path("source", "target");
        source_path.updated_at = source_reported_at;
        source_path.score.reasons.push(format!(
            "{LAZY_CONNECT_LOCAL_ACTIVITY_REASON_PREFIX}{}",
            source_reported_at.timestamp_millis()
        ));
        plane
            .heartbeat(signed_heartbeat_at(
                "source",
                HeartbeatRequest {
                    node_id: node_id("source"),
                    health: health(source_reported_at),
                    candidates: Vec::new(),
                    nat_classification: None,
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![source_path],
                    node_signature: None,
                },
                source_reported_at,
            ))
            .await?;

        let response = tokio::time::timeout(std::time::Duration::from_secs(1), waiter).await???;
        assert_eq!(response.connection_intents.len(), 1);
        assert_eq!(response.connection_intents[0].peer, node_id("source"));
        Ok(())
    }

    #[test]
    fn lazy_connect_activity_reason_requires_one_valid_timestamp(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut record = path("source", "target");
        assert_eq!(lazy_connect_local_activity_at(&record)?, None);

        record.score.reasons.push(format!(
            "{LAZY_CONNECT_LOCAL_ACTIVITY_REASON_PREFIX}invalid"
        ));
        assert!(lazy_connect_local_activity_at(&record).is_err());

        let observed_at = chrono::DateTime::<Utc>::from_timestamp_millis(1_700_000_000_123)
            .ok_or("test timestamp should be representable")?;
        record.score.reasons.clear();
        record.score.reasons.push(format!(
            "{LAZY_CONNECT_LOCAL_ACTIVITY_REASON_PREFIX}{}",
            observed_at.timestamp_millis()
        ));
        assert_eq!(lazy_connect_local_activity_at(&record)?, Some(observed_at));

        record.score.reasons.push(format!(
            "{LAZY_CONNECT_LOCAL_ACTIVITY_REASON_PREFIX}{}",
            observed_at.timestamp_millis()
        ));
        assert!(lazy_connect_local_activity_at(&record).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_filters_stale_endpoint_candidates() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut config = ControlPlaneConfig::new(
            ClusterId::from_string("cluster-a"),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        config.cluster_policy.endpoint_candidate_ttl_seconds = 30;
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let source = node_record("source");
        let mut peer = node_record("peer-a");
        peer.endpoint_candidates = vec![stale_candidate("peer-a"), candidate("peer-a")];
        let mut relay = node_record("relay-a");
        relay.endpoint_candidates = vec![stale_candidate("relay-a"), candidate("relay-a")];
        relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            ..relay_capability()
        });

        store.insert_node(source.clone()).await?;
        store.insert_node(peer).await?;
        store.insert_node(relay).await?;
        store
            .upsert_health(
                node_id("relay-a"),
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now(),
                    latency_ms: Some(1.0),
                    relay_load: Some(0.10),
                    message: None,
                },
            )
            .await?;

        let peer_map = plane.peer_map_for(&source.node_id).await?;
        let peer = peer_map
            .peers
            .iter()
            .find(|peer| peer.node_id == node_id("peer-a"))
            .ok_or("peer should remain visible with fresh candidate")?;
        assert_eq!(peer.endpoint_candidates.len(), 1);
        assert!(peer.endpoint_candidates[0].observed_at > Utc::now() - Duration::seconds(30));

        let relay_registration = plane
            .register_with_claims(
                claims(ClusterId::from_string("cluster-a")),
                registration_request("node-b"),
            )
            .await?;
        let relay = relay_registration
            .relay_map
            .relays
            .iter()
            .find(|relay| relay.node_id == node_id("relay-a"))
            .ok_or("fresh healthy relay should remain visible")?;
        assert_eq!(relay.endpoint_candidates.len(), 1);

        let metrics = plane.metrics().await?;
        assert_eq!(metrics.stale_endpoint_candidate_count, 2);
        assert_eq!(metrics.endpoint_candidate_ttl_seconds, 30);
        Ok(())
    }

    #[tokio::test]
    async fn peer_map_filters_unusable_endpoint_candidates(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = ControlPlaneConfig::new(
            ClusterId::from_string("cluster-a"),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let source = node_record("source");
        let mut peer = node_record("peer-a");
        peer.endpoint_candidates = vec![
            candidate_at("peer-a", std::net::SocketAddr::from(([203, 0, 113, 10], 0))),
            candidate_at("peer-a", std::net::SocketAddr::from(([0, 0, 0, 0], 51820))),
            candidate_at(
                "peer-a",
                std::net::SocketAddr::from(([224, 0, 0, 1], 51820)),
            ),
            candidate_at(
                "peer-a",
                std::net::SocketAddr::from(([255, 255, 255, 255], 51820)),
            ),
            candidate_at(
                "peer-a",
                std::net::SocketAddr::from(([198, 51, 100, 20], 51820)),
            ),
        ];
        let mut relay = node_record("relay-a");
        relay.endpoint_candidates = vec![
            candidate_at(
                "relay-a",
                std::net::SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 51820),
            ),
            candidate_at(
                "relay-a",
                std::net::SocketAddr::new(
                    IpAddr::V6(std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
                    51820,
                ),
            ),
            candidate_at(
                "relay-a",
                std::net::SocketAddr::from(([198, 51, 100, 30], 51820)),
            ),
        ];
        relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            ..relay_capability()
        });

        store.insert_node(source.clone()).await?;
        store.insert_node(peer).await?;
        store.insert_node(relay).await?;
        store
            .upsert_health(
                node_id("relay-a"),
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now(),
                    latency_ms: Some(1.0),
                    relay_load: Some(0.10),
                    message: None,
                },
            )
            .await?;

        let peer_map = plane.peer_map_for(&source.node_id).await?;
        let peer = peer_map
            .peers
            .iter()
            .find(|peer| peer.node_id == node_id("peer-a"))
            .ok_or("peer should remain visible with usable candidate")?;
        assert_eq!(
            peer.endpoint_candidates
                .iter()
                .map(|candidate| candidate.addr)
                .collect::<Vec<_>>(),
            vec![std::net::SocketAddr::from(([198, 51, 100, 20], 51820))]
        );

        let relay_registration = plane
            .register_with_claims(
                claims(ClusterId::from_string("cluster-a")),
                registration_request("node-b"),
            )
            .await?;
        let relay = relay_registration
            .relay_map
            .relays
            .iter()
            .find(|relay| relay.node_id == node_id("relay-a"))
            .ok_or("relay should remain visible with usable candidate")?;
        assert_eq!(
            relay
                .endpoint_candidates
                .iter()
                .map(|candidate| candidate.addr)
                .collect::<Vec<_>>(),
            vec![std::net::SocketAddr::from(([198, 51, 100, 30], 51820))]
        );
        Ok(())
    }

    #[tokio::test]
    async fn path_status_and_metrics_filter_stale_path_state(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = ControlPlaneConfig::new(
            ClusterId::from_string("cluster-a"),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        config.cluster_policy.path_state_ttl_seconds = 30;
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let source = node_record("source");
        store.insert_node(source.clone()).await?;
        store.insert_node(node_record("fresh-peer")).await?;
        store.insert_node(node_record("stale-peer")).await?;
        store.upsert_path(path("source", "fresh-peer")).await?;
        let mut stale_path = path("source", "stale-peer");
        stale_path.updated_at = Utc::now() - Duration::seconds(31);
        store.upsert_path(stale_path).await?;

        let paths = plane.paths_for(&source.node_id).await?;

        assert_eq!(paths.paths.len(), 1);
        assert_eq!(paths.paths[0].key.remote, node_id("fresh-peer"));
        assert_eq!(paths.stale_path_count, 1);
        assert_eq!(paths.path_state_ttl_seconds, 30);

        let metrics = plane.metrics().await?;
        assert_eq!(metrics.path_count, 1);
        assert_eq!(metrics.stale_path_count, 1);
        assert_eq!(metrics.path_state_ttl_seconds, 30);
        assert_eq!(metrics.path_state_counts.len(), 5);
        assert_eq!(
            metrics
                .path_state_counts
                .iter()
                .find(|count| count.state == PathState::DirectNatTraversal)
                .map(|count| count.count),
            Some(1)
        );
        assert_eq!(
            metrics
                .path_state_counts
                .iter()
                .find(|count| count.state == PathState::Relay)
                .map(|count| count.count),
            Some(0)
        );
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_records_health_candidates_and_paths(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("node-a"))
            .await?;
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-b"))
            .await?;
        let reported_at = Utc::now();
        let health = NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: reported_at,
            latency_ms: Some(12.0),
            relay_load: None,
            message: Some("ok".to_string()),
        };

        let response = plane
            .heartbeat(signed_heartbeat_at(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: health.clone(),
                    candidates: vec![candidate("node-a")],
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![path("node-a", "node-b")],
                    nat_classification: None,
                    node_signature: None,
                },
                reported_at,
            ))
            .await?;

        assert!(response.accepted);
        assert_eq!(
            store
                .get_node(&node_id("node-a"))
                .await?
                .ok_or(ControlPlaneError::NodeNotFound(node_id("node-a")))?
                .endpoint_candidates
                .len(),
            1
        );
        let stored_health = store
            .get_health(&node_id("node-a"))
            .await?
            .ok_or("health should be stored")?;
        assert_eq!(stored_health.state, health.state);
        assert_eq!(stored_health.latency_ms, health.latency_ms);
        assert_eq!(stored_health.message, health.message);
        assert!(stored_health.last_seen_at >= reported_at);
        assert_eq!(
            store
                .get_heartbeat_signature_timestamp(&node_id("node-a"))
                .await?,
            Some(reported_at)
        );
        assert_eq!(store.list_paths_for(&node_id("node-a")).await?.len(), 1);

        let second_reported_at = reported_at + Duration::seconds(1);
        let second_health = NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: second_reported_at,
            latency_ms: Some(9.0),
            relay_load: None,
            message: Some("idle".to_string()),
        };
        let second_response = plane
            .heartbeat(signed_heartbeat_at(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: second_health.clone(),
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
                second_reported_at,
            ))
            .await?;

        assert!(second_response.accepted);
        let stored_health = store
            .get_health(&node_id("node-a"))
            .await?
            .ok_or("second health should be stored")?;
        assert_eq!(stored_health.state, second_health.state);
        assert_eq!(stored_health.latency_ms, second_health.latency_ms);
        assert_eq!(stored_health.message, second_health.message);
        assert_eq!(
            store
                .get_heartbeat_signature_timestamp(&node_id("node-a"))
                .await?,
            Some(second_reported_at)
        );
        assert!(store.list_paths_for(&node_id("node-a")).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_publishes_signed_node_service_lease(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store,
        );
        let mut relay_claims = claims(cluster_id);
        relay_claims.policy.allow_relay = true;
        let registration = plane
            .register_with_claims(relay_claims, registration_request("service-node"))
            .await?;

        let now = Utc::now();
        let public_ip = Ipv4Addr::new(8, 8, 8, 8);
        let wireguard_addr = std::net::SocketAddr::from((public_ip, 51_820));
        let relay_addr = std::net::SocketAddr::from((public_ip, 18_445));
        let classification = NatClassification::from_observations(
            wireguard_addr,
            vec![NatProbeObservation {
                local_addr: wireguard_addr,
                stun_server: std::net::SocketAddr::from(([198, 51, 100, 1], 3478)),
                reflexive_addr: wireguard_addr,
                observed_at: now,
            }],
            now,
        );
        let health = NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: now,
            latency_ms: Some(1.0),
            relay_load: Some(0.0),
            message: None,
        };
        let candidate = EndpointCandidate {
            node_id: node_id("service-node"),
            kind: EndpointCandidateKind::PublicUdp,
            addr: wireguard_addr,
            observed_at: now,
            priority: 100,
            cost: 10,
            source: CandidateSource::StunProbe,
        };
        let relay = RelayCapability {
            enabled_by_policy: false,
            public_endpoint: Some(relay_addr),
            admission_url: Some("http://100.64.0.1:18447".to_string()),
            max_sessions: 100,
            active_sessions: 0,
            max_mbps: 1_000,
            e2e_only: true,
        };
        plane
            .heartbeat(signed_heartbeat_at(
                "service-node",
                HeartbeatRequest {
                    node_id: node_id("service-node"),
                    health: health.clone(),
                    candidates: vec![candidate.clone()],
                    nat_classification: Some(classification.clone()),
                    relay_capability: Some(relay.clone()),
                    routes: None,
                    service_advertisement: Some(NodeServiceAdvertisement {
                        hostname: Some("service-host".to_string()),
                        endpoints: vec![
                            BootstrapEndpoint {
                                kind: BootstrapEndpointKind::Signal,
                                url: format!("http://{}:19443", registration.node.vpn_ip),
                            },
                            BootstrapEndpoint {
                                kind: BootstrapEndpointKind::Stun,
                                url: format!("udp://{public_ip}:19444"),
                            },
                            BootstrapEndpoint {
                                kind: BootstrapEndpointKind::Relay,
                                url: format!("udp://{relay_addr}"),
                            },
                        ],
                    }),
                    path_state: Vec::new(),
                    node_signature: None,
                },
                now,
            ))
            .await?;

        let directory = plane.service_directory().await?;
        assert_eq!(directory.instances.len(), 1);
        assert_eq!(
            directory.instances[0].instance_id,
            heartbeat_service_instance_id(&node_id("service-node"))
        );
        assert_eq!(directory.instances[0].endpoints.len(), 3);
        assert_eq!(
            plane
                .list_nodes()
                .await?
                .into_iter()
                .find(|node| node.node_id == node_id("service-node"))
                .and_then(|node| node.hostname),
            Some("service-host".to_string())
        );

        let rejected_signal = plane
            .heartbeat(signed_heartbeat_at(
                "service-node",
                HeartbeatRequest {
                    node_id: node_id("service-node"),
                    health: health.clone(),
                    candidates: vec![candidate.clone()],
                    nat_classification: Some(classification.clone()),
                    relay_capability: Some(relay),
                    routes: None,
                    service_advertisement: Some(NodeServiceAdvertisement {
                        hostname: None,
                        endpoints: vec![BootstrapEndpoint {
                            kind: BootstrapEndpointKind::Signal,
                            url: "http://100.64.0.2:19443".to_string(),
                        }],
                    }),
                    path_state: Vec::new(),
                    node_signature: None,
                },
                now + Duration::milliseconds(1),
            ))
            .await;
        assert!(matches!(
            rejected_signal,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("does not match node VPN IP")
        ));

        let rejected = plane
            .heartbeat(signed_heartbeat_at(
                "service-node",
                HeartbeatRequest {
                    node_id: node_id("service-node"),
                    health,
                    candidates: vec![candidate],
                    nat_classification: Some(classification),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: Some(NodeServiceAdvertisement {
                        hostname: None,
                        endpoints: vec![BootstrapEndpoint {
                            kind: BootstrapEndpointKind::Stun,
                            url: "udp://1.1.1.1:19444".to_string(),
                        }],
                    }),
                    path_state: Vec::new(),
                    node_signature: None,
                },
                now + Duration::milliseconds(2),
            ))
            .await;
        assert!(matches!(
            rejected,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("does not match classified public IP")
        ));

        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_invalid_health_before_persistence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let signed_at = Utc::now();
        let cases = [
            (
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: signed_at + Duration::seconds(301),
                    latency_ms: None,
                    relay_load: None,
                    message: None,
                },
                "last_seen_at",
            ),
            (
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: signed_at,
                    latency_ms: Some(-1.0),
                    relay_load: None,
                    message: None,
                },
                "latency_ms",
            ),
            (
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: signed_at,
                    latency_ms: None,
                    relay_load: Some(1.1),
                    message: None,
                },
                "relay_load",
            ),
        ];

        for (health, expected) in cases {
            let result = plane
                .heartbeat(signed_heartbeat_at(
                    "node-a",
                    HeartbeatRequest {
                        node_id: node_id("node-a"),
                        health,
                        candidates: Vec::new(),
                        relay_capability: None,
                        routes: None,
                        service_advertisement: None,
                        path_state: Vec::new(),
                        nat_classification: None,
                        node_signature: None,
                    },
                    signed_at,
                ))
                .await;

            assert!(matches!(
                result,
                Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                    if reason.contains(expected)
            ));
            assert!(store.get_health(&node_id("node-a")).await?.is_none());
        }
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_updates_routes_when_policy_allows() -> Result<(), Box<dyn std::error::Error>>
    {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let mut claims = claims(cluster_id);
        claims.policy.allowed_routes = vec!["10.42.0.0/16".parse()?];
        plane
            .register_with_claims(claims, registration_request("node-a"))
            .await?;
        let route = route("route-a", "10.42.1.0/24", "node-a")?;

        plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: Some(12.0),
                        relay_load: None,
                        message: Some("routes refreshed".to_string()),
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: Some(vec![route.clone()]),
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await?;

        assert_eq!(
            store
                .get_node(&node_id("node-a"))
                .await?
                .ok_or(ControlPlaneError::NodeNotFound(node_id("node-a")))?
                .routes,
            vec![route.clone()]
        );

        plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: Some(13.0),
                        relay_load: None,
                        message: Some("no route update".to_string()),
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await?;

        assert_eq!(
            store
                .get_node(&node_id("node-a"))
                .await?
                .ok_or(ControlPlaneError::NodeNotFound(node_id("node-a")))?
                .routes,
            vec![route]
        );
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_routes_outside_configured_overlay_scopes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let mut config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        config.cluster_policy.overlay_route_scopes = vec!["10.42.0.0/16".parse()?];
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let mut claims = claims(cluster_id);
        claims.policy.allowed_routes = vec!["10.0.0.0/8".parse()?];
        plane
            .register_with_claims(claims, registration_request("node-a"))
            .await?;
        let outside_scope = route("outside-scope", "10.43.1.0/24", "node-a")?;

        let error = match plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: Some(12.0),
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: Some(vec![outside_scope]),
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await
        {
            Ok(_) => return Err("out-of-scope heartbeat route was unexpectedly accepted".into()),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ControlPlaneError::NodeUpdateRejected { reason, .. }
                if reason.contains("not fully contained")
        ));
        assert!(store
            .get_node(&node_id("node-a"))
            .await?
            .ok_or("registered node should remain")?
            .routes
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_routes_outside_token_policy(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store);
        let mut claims = claims(cluster_id);
        claims.policy.allowed_routes = vec!["10.42.0.0/16".parse()?];
        plane
            .register_with_claims(claims, registration_request("node-a"))
            .await?;

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: Some(12.0),
                        relay_load: None,
                        message: Some("bad route".to_string()),
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: Some(vec![route("route-denied", "10.43.1.0/24", "node-a")?]),
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::RouteDenied(route)) if route == "route-denied"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_routes_advertised_by_other_nodes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store);
        let mut claims = claims(cluster_id);
        claims.policy.allowed_routes = vec!["10.42.0.0/16".parse()?];
        plane
            .register_with_claims(claims, registration_request("node-a"))
            .await?;

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: Some(12.0),
                        relay_load: None,
                        message: Some("unowned route".to_string()),
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: Some(vec![route("route-unowned", "10.42.1.0/24", "node-b")?]),
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("route route-unowned is advertised by node")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_invalid_route_shape_before_persistence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let mut claims = claims(cluster_id);
        claims.policy.allowed_routes = vec!["10.42.0.0/16".parse()?];
        plane
            .register_with_claims(claims, registration_request("node-a"))
            .await?;

        let mut zero_metric = route("route-zero-metric", "10.42.1.0/24", "node-a")?;
        zero_metric.metric = 0;
        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: Some(12.0),
                        relay_load: None,
                        message: Some("bad route shape".to_string()),
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: Some(vec![zero_metric]),
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("route route-zero-metric metric must be greater than zero")
        ));
        assert!(store
            .get_node(&node_id("node-a"))
            .await?
            .ok_or(ControlPlaneError::NodeNotFound(node_id("node-a")))?
            .routes
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_replayed_node_signature() -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let signed_at = Utc::now() - Duration::seconds(120);
        let request = signed_heartbeat_at(
            "node-a",
            HeartbeatRequest {
                node_id: node_id("node-a"),
                health: NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: signed_at - Duration::seconds(30),
                    latency_ms: Some(8.0),
                    relay_load: None,
                    message: Some("fresh payload".to_string()),
                },
                candidates: vec![candidate("node-a")],
                relay_capability: None,
                routes: None,
                service_advertisement: None,
                path_state: Vec::new(),
                nat_classification: None,
                node_signature: None,
            },
            signed_at,
        );

        plane.heartbeat(request.clone()).await?;
        let accepted_health = store
            .get_health(&node_id("node-a"))
            .await?
            .ok_or("health should be stored")?;
        assert!(accepted_health.last_seen_at > signed_at + Duration::seconds(90));
        assert_eq!(
            store
                .get_heartbeat_signature_timestamp(&node_id("node-a"))
                .await?,
            Some(signed_at)
        );
        assert!(plane
            .overlay_nodes()
            .await?
            .iter()
            .any(|node| node.node_id == node_id("node-a")));

        let replay = plane.heartbeat(request).await;
        assert!(matches!(
            replay,
            Err(ControlPlaneError::NodeSignatureRejected { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_requires_valid_node_signature() -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let unsigned = HeartbeatRequest {
            node_id: node_id("node-a"),
            health: NodeHealth {
                state: HealthState::Healthy,
                last_seen_at: Utc::now(),
                latency_ms: None,
                relay_load: None,
                message: None,
            },
            candidates: Vec::new(),
            relay_capability: None,
            routes: None,
            service_advertisement: None,
            path_state: Vec::new(),
            nat_classification: None,
            node_signature: None,
        };

        let result = plane.heartbeat(unsigned.clone()).await;
        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeSignatureRequired(_))
        ));

        let mut tampered = signed_heartbeat("node-a", unsigned);
        tampered.health.message = Some("changed after signing".to_string());
        let result = plane.heartbeat(tampered).await;
        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeSignatureRejected { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_updates_for_other_nodes() -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let health = NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: Utc::now(),
            latency_ms: None,
            relay_load: None,
            message: None,
        };

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: health.clone(),
                    candidates: vec![candidate("node-b")],
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;
        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { .. })
        ));

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health,
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![path("node-b", "node-c")],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;
        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_path_state_with_unowned_selected_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let mut reported_path = path("node-a", "node-b");
        reported_path.selected_candidate = Some(candidate("node-c"));

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![reported_path],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        let error = match result {
            Ok(_) => return Err("unexpected successful heartbeat path-state update".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeUpdateRejected { .. }
        ));
        assert!(error
            .to_string()
            .contains("selected candidate belongs to node"));
        assert!(error.to_string().contains("instead of path peer"));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_direct_path_state_with_wrong_candidate_kind(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let mut reported_path = path("node-a", "node-b");
        reported_path.selected_state = PathState::DirectPublic;
        reported_path.selected_candidate = Some(candidate("node-b"));

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![reported_path],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("selected state DirectPublic")
                    && reason.contains("selected candidate kind StunReflexive")
        ));
        assert!(store.list_paths_for(&node_id("node-a")).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_duplicate_path_state_before_persistence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![path("node-a", "node-b"), path("node-a", "node-b")],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("is repeated in heartbeat path_state")
        ));
        assert!(store.list_paths_for(&node_id("node-a")).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_unbounded_path_state_before_persistence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![path("node-a", "node-b"); MAX_HEARTBEAT_PATH_STATES + 1],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("heartbeat path_state contains 4097 entries")
                    && reason.contains("maximum is 4096")
        ));
        assert_eq!(store.get_health(&node_id("node-a")).await?, None);
        assert!(store.list_paths_for(&node_id("node-a")).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_path_state_for_unregistered_peer_before_persistence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("node-a"))
            .await?;

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![path("node-a", "node-b")],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("remote node is not registered")
        ));
        assert!(store.list_paths_for(&node_id("node-a")).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_path_state_hidden_by_acl_before_persistence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let mut config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        config.cluster_policy.acl_rules = vec![
            AclRule {
                id: "deny-hidden-peer".to_string(),
                from_roles: BTreeSet::new(),
                from_tags: BTreeSet::new(),
                to_roles: BTreeSet::new(),
                to_tags: BTreeSet::from([Tag::from_string("hidden-peer")]),
                routes: Vec::new(),
                protocol: TransportProtocol::Any,
                action: AclAction::Deny,
            },
            AclRule {
                id: "allow-other-peers".to_string(),
                from_roles: BTreeSet::new(),
                from_tags: BTreeSet::new(),
                to_roles: BTreeSet::new(),
                to_tags: BTreeSet::new(),
                routes: Vec::new(),
                protocol: TransportProtocol::Any,
                action: AclAction::Allow,
            },
        ];
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("node-a"))
            .await?;
        let mut hidden_claims = claims(cluster_id);
        hidden_claims.tags.insert(Tag::from_string("hidden-peer"));
        plane
            .register_with_claims(hidden_claims, registration_request("node-b"))
            .await?;

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![path("node-a", "node-b")],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("remote node is not visible")
        ));
        assert!(store.list_paths_for(&node_id("node-a")).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_policy_generation_remains_bound_after_cache_is_replaced(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::from_string("cluster-policy-generation");
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store.clone(),
        );
        let acquired_policy = ClusterPolicy {
            acl_rules: vec![
                AclRule {
                    id: "deny-hidden".to_string(),
                    from_roles: BTreeSet::new(),
                    from_tags: BTreeSet::new(),
                    to_roles: BTreeSet::new(),
                    to_tags: BTreeSet::from([Tag::from_string("hidden")]),
                    routes: Vec::new(),
                    protocol: TransportProtocol::Any,
                    action: AclAction::Deny,
                },
                AclRule {
                    id: "allow-visible".to_string(),
                    from_roles: BTreeSet::new(),
                    from_tags: BTreeSet::new(),
                    to_roles: BTreeSet::new(),
                    to_tags: BTreeSet::new(),
                    routes: Vec::new(),
                    protocol: TransportProtocol::Any,
                    action: AclAction::Allow,
                },
            ],
            ..ClusterPolicy::default()
        };
        store
            .upsert_cluster_policy(&cluster_id, acquired_policy.clone())
            .await?;
        let acquired_policy = plane.current_cluster_policy().await?;

        // Model an older request overwriting the process-local cache after this
        // heartbeat has already acquired the persisted policy generation.
        plane.cache_cluster_policy(ClusterPolicy::default())?;
        assert!(plane.cluster_policy()?.acl_rules.is_empty());

        let mut reporter = node_record("node-a");
        reporter.cluster_id = cluster_id.clone();
        let mut visible_peer = node_record("node-b");
        visible_peer.cluster_id = cluster_id.clone();
        let mut hidden_relay = node_record("relay-a");
        hidden_relay.cluster_id = cluster_id;
        hidden_relay.tags.insert(Tag::from_string("hidden"));
        hidden_relay.relay_capability = Some(RelayCapability {
            enabled_by_policy: true,
            ..relay_capability()
        });
        let nodes = vec![reporter.clone(), visible_peer.clone(), hidden_relay.clone()];

        let hidden_peer_request = HeartbeatRequest {
            node_id: reporter.node_id.clone(),
            health: NodeHealth {
                state: HealthState::Healthy,
                last_seen_at: Utc::now(),
                latency_ms: None,
                relay_load: None,
                message: None,
            },
            candidates: Vec::new(),
            nat_classification: None,
            relay_capability: None,
            routes: None,
            service_advertisement: None,
            path_state: vec![path("node-a", "relay-a")],
            node_signature: None,
        };
        assert!(matches!(
            plane.validate_heartbeat_path_peers_visible(
                &hidden_peer_request,
                &reporter,
                &nodes,
                &acquired_policy,
            ),
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("is not visible")
        ));

        let relay_request = HeartbeatRequest {
            service_advertisement: None,
            path_state: vec![relay_path("node-a", "node-b", Some("relay-a"))],
            ..hidden_peer_request
        };
        plane.validate_heartbeat_path_peers_visible(
            &relay_request,
            &reporter,
            &nodes,
            &acquired_policy,
        )?;
        let health_by_node = BTreeMap::from([(
            hidden_relay.node_id.clone(),
            NodeHealth {
                state: HealthState::Healthy,
                last_seen_at: Utc::now(),
                latency_ms: Some(1.0),
                relay_load: Some(0.1),
                message: None,
            },
        )]);
        assert!(matches!(
            plane.validate_heartbeat_path_relay_eligibility(
                &relay_request,
                &reporter,
                &nodes,
                &health_by_node,
                Utc::now(),
                &acquired_policy,
            ),
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("is not visible")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_future_path_state_before_persistence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let signed_at = Utc::now();
        let mut reported_path = path("node-a", "node-b");
        reported_path.updated_at = signed_at + Duration::seconds(301);

        let result = plane
            .heartbeat(signed_heartbeat_at(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: signed_at,
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![reported_path],
                    nat_classification: None,
                    node_signature: None,
                },
                signed_at,
            ))
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("updated_at")
                    && reason.contains("too far in the future")
        ));
        assert!(store.list_paths_for(&node_id("node-a")).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_invalid_path_score_before_persistence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;

        let mut positive_infinity = path("node-a", "node-b");
        positive_infinity.score = PathScore {
            value: f32::INFINITY,
            reasons: vec!["state=DirectNatTraversal".to_string()],
        };
        let mut unreasoned_negative_infinity = path("node-a", "node-b");
        unreasoned_negative_infinity.score = PathScore {
            value: f32::NEG_INFINITY,
            reasons: Vec::new(),
        };
        let mut too_many_reasons = path("node-a", "node-b");
        too_many_reasons.score.reasons = (0..=MAX_PATH_SCORE_REASONS)
            .map(|index| format!("r{index}"))
            .collect();
        let mut oversized_reason = path("node-a", "node-b");
        oversized_reason.score.reasons = vec!["x".repeat(MAX_PATH_SCORE_REASON_BYTES + 1)];
        let mut control_character_reason = path("node-a", "node-b");
        control_character_reason.score.reasons = vec!["bad\nreason".to_string()];
        let cases = [
            (positive_infinity, "positive infinity"),
            (unreasoned_negative_infinity, "negative-infinity score"),
            (too_many_reasons, "score reasons must not exceed"),
            (oversized_reason, "score reason must not exceed"),
            (control_character_reason, "control characters"),
        ];

        for (reported_path, expected) in cases {
            let signed_at = Utc::now();
            let result = plane
                .heartbeat(signed_heartbeat_at(
                    "node-a",
                    HeartbeatRequest {
                        node_id: node_id("node-a"),
                        health: NodeHealth {
                            state: HealthState::Healthy,
                            last_seen_at: signed_at,
                            latency_ms: None,
                            relay_load: None,
                            message: None,
                        },
                        candidates: Vec::new(),
                        relay_capability: None,
                        routes: None,
                        service_advertisement: None,
                        path_state: vec![reported_path],
                        nat_classification: None,
                        node_signature: None,
                    },
                    signed_at,
                ))
                .await;

            assert!(matches!(
                result,
                Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                    if reason.contains(expected)
            ));
            assert!(store.list_paths_for(&node_id("node-a")).await?.is_empty());
        }
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_path_state_with_future_selected_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let signed_at = Utc::now();
        let mut future_candidate = candidate("node-b");
        future_candidate.observed_at = signed_at + Duration::seconds(301);
        let mut reported_path = path("node-a", "node-b");
        reported_path.selected_candidate = Some(future_candidate);

        let result = plane
            .heartbeat(signed_heartbeat_at(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: signed_at,
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![reported_path],
                    nat_classification: None,
                    node_signature: None,
                },
                signed_at,
            ))
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("selected candidate")
                    && reason.contains("observed_at")
                    && reason.contains("too far in the future")
        ));
        assert!(store.list_paths_for(&node_id("node-a")).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_path_state_with_stale_selected_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let mut config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        config.cluster_policy.endpoint_candidate_ttl_seconds = 30;
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("node-a"))
            .await?;
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-b"))
            .await?;
        let signed_at = Utc::now();
        let mut stale_candidate = candidate("node-b");
        stale_candidate.observed_at = signed_at - Duration::seconds(31);
        let mut reported_path = path("node-a", "node-b");
        reported_path.selected_candidate = Some(stale_candidate);

        let result = plane
            .heartbeat(signed_heartbeat_at(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: signed_at,
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![reported_path],
                    nat_classification: None,
                    node_signature: None,
                },
                signed_at,
            ))
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("selected candidate")
                    && reason.contains("is stale")
        ));
        assert!(store.list_paths_for(&node_id("node-a")).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_path_state_with_invalid_selected_candidate_address(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let mut reported_path = path("node-a", "node-b");
        reported_path.selected_candidate = Some(invalid_ipv6_candidate("node-b"));

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![reported_path],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        let error = match result {
            Ok(_) => return Err("unexpected successful heartbeat path-state update".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeUpdateRejected { .. }
        ));
        assert!(error.to_string().contains("IPv6 candidates must use"));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_path_state_with_unusable_selected_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let mut reported_path = path("node-a", "node-b");
        reported_path.selected_candidate = Some(candidate_at(
            "node-b",
            std::net::SocketAddr::from(([203, 0, 113, 10], 0)),
        ));

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![reported_path],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        let error = match result {
            Ok(_) => return Err("unexpected successful heartbeat path-state update".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeUpdateRejected { .. }
        ));
        assert!(error.to_string().contains("selected candidate"));
        assert!(error.to_string().contains("is unusable"));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_relay_path_without_relay_node(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![relay_path("node-a", "node-b", None)],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        let error = match result {
            Ok(_) => return Err("unexpected successful relay path-state update".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeUpdateRejected { .. }
        ));
        assert!(error.to_string().contains("is missing relay node"));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_relay_path_with_direct_selected_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let mut reported_path = relay_path("node-a", "node-b", Some("relay-a"));
        reported_path.selected_candidate = Some(candidate("node-b"));

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![reported_path],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        let error = match result {
            Ok(_) => {
                return Err(
                    "unexpected successful relay path-state update with selected candidate".into(),
                )
            }
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeUpdateRejected { .. }
        ));
        assert!(error
            .to_string()
            .contains("must not carry a direct selected candidate"));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_unreachable_path_with_selected_candidate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let mut reported_path = path("node-a", "node-b");
        reported_path.selected_state = PathState::Unreachable;
        reported_path.selected_candidate = Some(candidate("node-b"));

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![reported_path],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        let error =
            match result {
                Ok(_) => return Err(
                    "unexpected successful unreachable path-state update with selected candidate"
                        .into(),
                ),
                Err(error) => error,
            };
        assert!(matches!(
            error,
            ControlPlaneError::NodeUpdateRejected { .. }
        ));
        assert!(error
            .to_string()
            .contains("must not carry a selected candidate"));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_relay_path_with_ineligible_relay_node(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        let mut relay_claims = claims(cluster_id.clone());
        relay_claims.policy.allow_relay = true;
        let mut relay_request = registration_request("relay-a");
        relay_request.relay_capability = Some(relay_capability());
        plane
            .register_with_claims(relay_claims, relay_request)
            .await?;
        plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("node-a"))
            .await?;
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-b"))
            .await?;

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![relay_path("node-a", "node-b", Some("relay-a"))],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        let error = match result {
            Ok(_) => return Err("unexpected successful relay path-state update".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeUpdateRejected { .. }
        ));
        assert!(error
            .to_string()
            .contains("is not an eligible relay candidate"));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_relay_path_using_endpoint_as_relay(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![relay_path("node-a", "node-b", Some("node-a"))],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        let error = match result {
            Ok(_) => return Err("unexpected successful endpoint relay path-state update".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeUpdateRejected { .. }
        ));
        assert!(error.to_string().contains("uses endpoint"));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_relay_path_hidden_by_acl() -> Result<(), Box<dyn std::error::Error>>
    {
        let cluster_id = ClusterId::new();
        let mut config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        config.cluster_policy.acl_rules = vec![
            AclRule {
                id: "deny-relay".to_string(),
                from_roles: BTreeSet::new(),
                from_tags: BTreeSet::new(),
                to_roles: BTreeSet::new(),
                to_tags: BTreeSet::from([Tag::from_string("relay-hidden")]),
                routes: Vec::new(),
                protocol: TransportProtocol::Any,
                action: AclAction::Deny,
            },
            AclRule {
                id: "allow-other-peers".to_string(),
                from_roles: BTreeSet::new(),
                from_tags: BTreeSet::new(),
                to_roles: BTreeSet::new(),
                to_tags: BTreeSet::new(),
                routes: Vec::new(),
                protocol: TransportProtocol::Any,
                action: AclAction::Allow,
            },
        ];
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        let mut relay_claims = claims(cluster_id.clone());
        relay_claims.policy.allow_relay = true;
        relay_claims.tags.insert(Tag::from_string("relay-hidden"));
        let mut relay_request = registration_request("relay-a");
        relay_request.relay_capability = Some(relay_capability());
        plane
            .register_with_claims(relay_claims, relay_request)
            .await?;
        plane
            .heartbeat(signed_heartbeat(
                "relay-a",
                HeartbeatRequest {
                    node_id: node_id("relay-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: Some(1.0),
                        relay_load: Some(0.1),
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: Some(relay_capability()),
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await?;
        plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("node-a"))
            .await?;
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-b"))
            .await?;

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![relay_path("node-a", "node-b", Some("relay-a"))],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        let error = match result {
            Ok(_) => return Err("unexpected successful ACL-hidden relay path-state update".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeUpdateRejected { .. }
        ));
        assert!(error.to_string().contains("is not visible"));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_records_relay_path_visible_by_acl() -> Result<(), Box<dyn std::error::Error>>
    {
        let cluster_id = ClusterId::new();
        let mut config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        config.cluster_policy.acl_rules = vec![
            AclRule {
                id: "allow-relay".to_string(),
                from_roles: BTreeSet::new(),
                from_tags: BTreeSet::new(),
                to_roles: BTreeSet::new(),
                to_tags: BTreeSet::from([Tag::from_string("relay-visible")]),
                routes: Vec::new(),
                protocol: TransportProtocol::Any,
                action: AclAction::Allow,
            },
            AclRule {
                id: "allow-edge-peer".to_string(),
                from_roles: BTreeSet::new(),
                from_tags: BTreeSet::new(),
                to_roles: BTreeSet::new(),
                to_tags: BTreeSet::from([Tag::from_string("edge")]),
                routes: Vec::new(),
                protocol: TransportProtocol::Any,
                action: AclAction::Allow,
            },
        ];
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let mut relay_claims = claims(cluster_id.clone());
        relay_claims.policy.allow_relay = true;
        relay_claims.tags.insert(Tag::from_string("relay-visible"));
        let mut relay_request = registration_request("relay-a");
        relay_request.relay_capability = Some(relay_capability());
        plane
            .register_with_claims(relay_claims, relay_request)
            .await?;
        plane
            .heartbeat(signed_heartbeat(
                "relay-a",
                HeartbeatRequest {
                    node_id: node_id("relay-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: Some(1.0),
                        relay_load: Some(0.1),
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: Some(relay_capability()),
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await?;
        plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("node-a"))
            .await?;
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-b"))
            .await?;

        let response = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![relay_path("node-a", "node-b", Some("relay-a"))],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await?;

        assert!(response.accepted);
        let paths = store.list_paths_for(&node_id("node-a")).await?;
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].relay_node, Some(node_id("relay-a")));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_records_relay_path_with_eligible_relay_node(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let mut relay_claims = claims(cluster_id.clone());
        relay_claims.policy.allow_relay = true;
        let mut relay_request = registration_request("relay-a");
        relay_request.relay_capability = Some(relay_capability());
        plane
            .register_with_claims(relay_claims, relay_request)
            .await?;
        plane
            .heartbeat(signed_heartbeat(
                "relay-a",
                HeartbeatRequest {
                    node_id: node_id("relay-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: Some(1.0),
                        relay_load: Some(0.1),
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: Some(relay_capability()),
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await?;
        plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("node-a"))
            .await?;
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-b"))
            .await?;

        let response = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![relay_path("node-a", "node-b", Some("relay-a"))],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await?;

        assert!(response.accepted);
        let paths = store.list_paths_for(&node_id("node-a")).await?;
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].selected_state, PathState::Relay);
        assert_eq!(paths[0].relay_node, Some(node_id("relay-a")));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_non_relay_path_with_relay_node(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let mut reported_path = path("node-a", "node-b");
        reported_path.relay_node = Some(node_id("relay-a"));

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: vec![reported_path],
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        let error = match result {
            Ok(_) => return Err("unexpected successful non-relay path-state update".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeUpdateRejected { .. }
        ));
        assert!(error.to_string().contains("non-relay path"));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_invalid_candidate_kind_addresses(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: vec![invalid_ipv6_candidate("node-a")],
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        let error = match result {
            Ok(_) => return Err("unexpected successful heartbeat candidate update".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeUpdateRejected { .. }
        ));
        assert!(error.to_string().contains("IPv6 candidates must use"));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_future_endpoint_candidate_before_persistence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let signed_at = Utc::now();
        let mut future_candidate = candidate("node-a");
        future_candidate.observed_at = signed_at + Duration::seconds(301);

        let result = plane
            .heartbeat(signed_heartbeat_at(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: signed_at,
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: vec![future_candidate],
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
                signed_at,
            ))
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("observed_at")
                    && reason.contains("too far in the future")
        ));
        assert!(store
            .get_node(&node_id("node-a"))
            .await?
            .ok_or(ControlPlaneError::NodeNotFound(node_id("node-a")))?
            .endpoint_candidates
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_updates_relay_capability_when_policy_allows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let mut claims = claims(cluster_id);
        claims.policy.allow_relay = true;
        plane
            .register_with_claims(claims, registration_request("node-a"))
            .await?;
        let mut heartbeat_relay = relay_capability();
        heartbeat_relay.enabled_by_policy = false;
        heartbeat_relay.active_sessions = 7;

        let response = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: Some(0.25),
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: Some(heartbeat_relay),
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await?;

        assert!(response.accepted);
        let node = store
            .get_node(&node_id("node-a"))
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id("node-a")))?;
        let Some(relay) = node.relay_capability else {
            return Err("expected heartbeat relay capability".into());
        };
        assert!(relay.enabled_by_policy);
        assert_eq!(relay.active_sessions, 7);
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_clears_relay_capability_when_not_reported(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let mut relay_claims = claims(cluster_id.clone());
        relay_claims.policy.allow_relay = true;
        let mut relay_request = registration_request("relay-a");
        relay_request.relay_capability = Some(relay_capability());
        plane
            .register_with_claims(relay_claims, relay_request)
            .await?;

        plane
            .heartbeat(signed_heartbeat(
                "relay-a",
                HeartbeatRequest {
                    node_id: node_id("relay-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: Some(1.0),
                        relay_load: Some(0.10),
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: Some(relay_capability()),
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await?;
        assert_eq!(plane.metrics().await?.relay_candidate_count, 1);

        plane
            .heartbeat(signed_heartbeat(
                "relay-a",
                HeartbeatRequest {
                    node_id: node_id("relay-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: Some(1.0),
                        relay_load: None,
                        message: Some("relay stopped".to_string()),
                    },
                    candidates: Vec::new(),
                    relay_capability: None,
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await?;

        let relay_node = store
            .get_node(&node_id("relay-a"))
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id("relay-a")))?;
        assert!(relay_node.relay_capability.is_none());
        assert_eq!(plane.metrics().await?.relay_candidate_count, 0);

        let source_registration = plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        assert!(source_registration.relay_map.relays.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_relay_capability_when_policy_denies(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = ControlPlane::new(config, Arc::new(InMemoryStore::default()));
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;

        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: Some(relay_capability()),
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        assert!(matches!(result, Err(ControlPlaneError::RelayDenied)));
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_invalid_relay_capability_shape(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let store = Arc::new(InMemoryStore::default());
        let plane = ControlPlane::new(config, store.clone());
        let mut claims = claims(cluster_id);
        claims.policy.allow_relay = true;
        plane
            .register_with_claims(claims, registration_request("node-a"))
            .await?;

        let mut bad_admission_url = relay_capability();
        bad_admission_url.admission_url = Some("http://0.0.0.0:9580".to_string());
        let result = plane
            .heartbeat(signed_heartbeat(
                "node-a",
                HeartbeatRequest {
                    node_id: node_id("node-a"),
                    health: NodeHealth {
                        state: HealthState::Healthy,
                        last_seen_at: Utc::now(),
                        latency_ms: None,
                        relay_load: None,
                        message: None,
                    },
                    candidates: Vec::new(),
                    relay_capability: Some(bad_admission_url),
                    routes: None,
                    service_advertisement: None,
                    path_state: Vec::new(),
                    nat_classification: None,
                    node_signature: None,
                },
            ))
            .await;

        let error = match result {
            Ok(_) => return Err("unexpected successful relay heartbeat".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ControlPlaneError::NodeUpdateRejected { .. }
        ));
        assert!(error.to_string().contains("relay admission URL"));
        let node = store
            .get_node(&node_id("node-a"))
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id("node-a")))?;
        assert!(node.relay_capability.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn token_admission_enforces_max_uses_and_revocation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cluster_id = ClusterId::new();
        let token_claims = claims(cluster_id.clone());
        let ledger = Arc::new(InMemoryTokenLedger::default());
        let admission = TokenAdmission::new(ledger.clone());
        admission
            .issue_from_claims(&token_claims, Utc::now())
            .await?;

        let first_use = admission.admit_join(&token_claims, Utc::now()).await?;
        assert_eq!(first_use.uses, 1);

        let reissued = admission
            .issue_from_claims(&token_claims, Utc::now())
            .await?;
        assert_eq!(reissued.uses, 1);

        let second_use = admission.admit_join(&token_claims, Utc::now()).await;
        assert!(matches!(
            second_use,
            Err(ControlPlaneError::TokenRejected {
                status: TokenStatus::Exhausted,
                ..
            })
        ));

        let mut conflicting_claims = token_claims.clone();
        conflicting_claims.policy.allowed_routes = vec!["10.42.0.0/16".parse()?];
        let conflict = admission.admit_join(&conflicting_claims, Utc::now()).await;
        assert!(matches!(
            conflict,
            Err(ControlPlaneError::TokenVerification(_))
        ));

        let mut revoked_claims = claims(cluster_id);
        revoked_claims.nonce = "revoked".to_string();
        admission
            .issue_from_claims(&revoked_claims, Utc::now())
            .await?;
        ledger
            .revoke_token(TokenRevocationRecord {
                cluster_id: revoked_claims.cluster_id.clone(),
                nonce: revoked_claims.nonce.clone(),
                issuer: revoked_claims.issuer.clone(),
                key_id: revoked_claims.key_id.clone(),
                revoked_at: Utc::now(),
            })
            .await?;
        let revoked = admission.admit_join(&revoked_claims, Utc::now()).await;
        assert!(matches!(
            revoked,
            Err(ControlPlaneError::TokenRejected {
                status: TokenStatus::Revoked,
                ..
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn join_service_verifies_token_and_registers_node(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("root");
        let cluster_id = ClusterId::new();
        let token = issuer.sign_join_token(claims_for_issuer(
            cluster_id.clone(),
            issuer.node_id(),
            key_id.clone(),
            "join-service-valid",
        ))?;
        let service = join_service(cluster_id, &issuer, key_id)?;

        let response = service
            .join(token, registration_request("node-a"), Utc::now())
            .await?;

        assert_eq!(response.node.node_id, node_id("node-a"));
        assert_eq!(
            response.node.vpn_ip.0,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
        );
        Ok(())
    }

    #[tokio::test]
    async fn join_service_validates_claim_shape_before_issuer_lookup(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("root");
        let cluster_id = ClusterId::new();
        let mut token = issuer.sign_join_token(claims_for_issuer(
            cluster_id.clone(),
            issuer.node_id(),
            key_id.clone(),
            "join-service-invalid-shape",
        ))?;
        token.claims.issuer = NodeId::from_string("x".repeat(MAX_JOIN_TOKEN_IDENTIFIER_BYTES + 1));
        let service = join_service(cluster_id, &issuer, key_id)?;

        let error = match service
            .join(token, registration_request("node-a"), Utc::now())
            .await
        {
            Ok(_) => return Err("invalid token claim shape was accepted".into()),
            Err(error) => error,
        };
        assert!(matches!(error, ControlPlaneError::TokenVerification(_)));
        assert!(error
            .to_string()
            .contains("issuer node ID exceeds 255 bytes"));
        Ok(())
    }

    #[tokio::test]
    async fn join_service_accepts_overlapping_issuer_keys_for_rotation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let old_issuer = IdentityKeyPair::generate();
        let next_issuer = IdentityKeyPair::generate();
        let old_key_id = KeyId::from_string("root");
        let next_key_id = KeyId::from_string("root-next");
        let cluster_id = ClusterId::new();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = Arc::new(ControlPlane::new(
            config,
            Arc::new(InMemoryStore::default()),
        ));
        let ledger = Arc::new(InMemoryTokenLedger::default());
        let mut key_ring = IssuerKeyRing::default();
        key_ring.insert(
            old_issuer.node_id(),
            old_key_id.clone(),
            old_issuer.public_key_b64(),
        );
        key_ring.insert(
            next_issuer.node_id(),
            next_key_id.clone(),
            next_issuer.public_key_b64(),
        );
        let service = ControlPlaneJoinService::new(plane, ledger, key_ring);
        let old_token = old_issuer.sign_join_token(claims_for_issuer(
            cluster_id.clone(),
            old_issuer.node_id(),
            old_key_id,
            "old-issuer-token",
        ))?;
        let next_token = next_issuer.sign_join_token(claims_for_issuer(
            cluster_id,
            next_issuer.node_id(),
            next_key_id,
            "next-issuer-token",
        ))?;

        let old_response = service
            .join(old_token, registration_request("node-old"), Utc::now())
            .await?;
        let next_response = service
            .join(next_token, registration_request("node-next"), Utc::now())
            .await?;

        assert_eq!(old_response.node.node_id, node_id("node-old"));
        assert_eq!(next_response.node.node_id, node_id("node-next"));
        Ok(())
    }

    #[tokio::test]
    async fn node_enrollment_issuer_key_is_limited_to_bounded_node_join_tokens(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("web-enrollment");
        let cluster_id = ClusterId::new();
        let now = Utc::now();
        let config = ControlPlaneConfig::new(
            cluster_id.clone(),
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 29)?,
        );
        let plane = Arc::new(ControlPlane::new(
            config,
            Arc::new(InMemoryStore::default()),
        ));
        let mut key_ring = IssuerKeyRing::default();
        key_ring.insert_node_enrollment_key(
            issuer.node_id(),
            key_id.clone(),
            issuer.public_key_b64(),
            3_600,
        );
        let service =
            ControlPlaneJoinService::new(plane, Arc::new(InMemoryTokenLedger::default()), key_ring);
        let valid_claims = node_enrollment_claims(
            cluster_id,
            issuer.node_id(),
            key_id.clone(),
            "valid-enrollment",
            now,
        );
        service.validate_join_token(&issuer.sign_join_token(valid_claims.clone())?, now)?;

        let rejected_reason =
            |claims: JoinTokenClaims| -> Result<String, Box<dyn std::error::Error>> {
                let token = issuer.sign_join_token(claims)?;
                let error = match service.validate_join_token(&token, now) {
                    Ok(()) => return Err("restricted enrollment claims were accepted".into()),
                    Err(error) => error,
                };
                Ok(error.to_string())
            };

        let mut valid_client = valid_claims.clone();
        valid_client.role = Role::client();
        valid_client.tags.clear();
        valid_client.policy.allowed_tags.clear();
        valid_client.policy.max_token_uses = Some(1);
        service.validate_join_token(&issuer.sign_join_token(valid_client.clone())?, now)?;

        let mut reusable_client = valid_client.clone();
        reusable_client.policy.max_token_uses = Some(2);
        assert!(rejected_reason(reusable_client)?.contains("client tokens must be single-use"));

        let mut tagged_client = valid_client;
        tagged_client.tags.insert(Tag::from_string("privileged"));
        tagged_client
            .policy
            .allowed_tags
            .insert(Tag::from_string("privileged"));
        assert!(rejected_reason(tagged_client)?.contains("client tokens must be single-use"));

        let mut elevated_role = valid_claims.clone();
        elevated_role.role = Role::control_plane();
        assert!(rejected_reason(elevated_role)?.contains("role is not allowed"));

        let mut unlimited = valid_claims.clone();
        unlimited.policy.max_token_uses = None;
        assert!(rejected_reason(unlimited)?.contains("token uses must be finite and bounded"));

        let mut route_authority = valid_claims.clone();
        route_authority.policy.allowed_routes = vec!["10.42.0.0/16".parse()?];
        assert!(rejected_reason(route_authority)?.contains("route authorization is not allowed"));

        let mut no_ha = valid_claims.clone();
        no_ha.bootstrap_endpoints.remove(1);
        assert!(rejected_reason(no_ha)?.contains("HA bootstrap endpoints are required"));

        let mut excessive_ttl = valid_claims.clone();
        excessive_ttl.expires_at = now + Duration::hours(2);
        assert!(rejected_reason(excessive_ttl)?.contains("validity exceeds the configured maximum"));

        let mut mismatched_tags = valid_claims.clone();
        mismatched_tags
            .policy
            .allowed_tags
            .insert(Tag::from_string("privileged"));
        assert!(
            rejected_reason(mismatched_tags)?.contains("claim tags and allowed tags must match")
        );

        let revocation = signed_token_revocation(
            &issuer,
            valid_claims.cluster_id,
            "root-issued-token",
            key_id,
            now,
        )?;
        let revocation_error = match service.revoke_token(&revocation, now).await {
            Ok(_) => return Err("enrollment issuer performed token revocation".into()),
            Err(error) => error,
        };
        assert!(revocation_error
            .to_string()
            .contains("not authorized for token revocation"));
        Ok(())
    }

    #[tokio::test]
    async fn join_service_requires_fresh_trusted_issuer_signature_for_token_revocation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("root");
        let cluster_id = ClusterId::new();
        let nonce = "signed-revocation";
        let now = Utc::now();
        let token = issuer.sign_join_token(claims_for_issuer(
            cluster_id.clone(),
            issuer.node_id(),
            key_id.clone(),
            nonce,
        ))?;
        let service = join_service(cluster_id.clone(), &issuer, key_id.clone())?;
        service
            .join(token, registration_request("node-revocation"), now)
            .await?;

        let unsigned = RevokeTokenRequest {
            cluster_id: cluster_id.clone(),
            nonce: nonce.to_string(),
            issuer: issuer.node_id(),
            key_id: key_id.clone(),
            issuer_signature: None,
        };
        assert!(matches!(
            service.revoke_token(&unsigned, now).await,
            Err(ControlPlaneError::TokenVerification(_))
        ));

        let wrong_cluster =
            signed_token_revocation(&issuer, ClusterId::new(), nonce, key_id.clone(), now)?;
        let error = match service.revoke_token(&wrong_cluster, now).await {
            Ok(_) => return Err("wrong-cluster token revocation was accepted".into()),
            Err(error) => error,
        };
        assert!(matches!(error, ControlPlaneError::TokenVerification(_)));
        assert!(error.to_string().contains("cluster mismatch"));

        let untrusted_issuer = IdentityKeyPair::generate();
        let untrusted = signed_token_revocation(
            &untrusted_issuer,
            cluster_id.clone(),
            nonce,
            key_id.clone(),
            now,
        )?;
        assert!(matches!(
            service.revoke_token(&untrusted, now).await,
            Err(ControlPlaneError::IssuerKeyNotFound { .. })
        ));

        let stale = signed_token_revocation(
            &issuer,
            cluster_id.clone(),
            nonce,
            key_id.clone(),
            now - Duration::seconds(301),
        )?;
        let error = match service.revoke_token(&stale, now).await {
            Ok(_) => return Err("stale token revocation signature was accepted".into()),
            Err(error) => error,
        };
        assert!(matches!(error, ControlPlaneError::TokenVerification(_)));
        assert!(error
            .to_string()
            .contains("outside the allowed 300s window"));

        let mut tampered =
            signed_token_revocation(&issuer, cluster_id.clone(), nonce, key_id.clone(), now)?;
        tampered.nonce = "tampered-revocation".to_string();
        assert!(matches!(
            service.revoke_token(&tampered, now).await,
            Err(ControlPlaneError::TokenVerification(_))
        ));

        let request =
            signed_token_revocation(&issuer, cluster_id.clone(), nonce, key_id.clone(), now)?;
        let revoked = service.revoke_token(&request, now).await?;
        assert_eq!(
            revoked.record.map(|record| record.status(now)),
            Some(TokenStatus::Revoked)
        );

        let unused_nonce = "unused-signed-revocation";
        let unused_token = issuer.sign_join_token(claims_for_issuer(
            cluster_id.clone(),
            issuer.node_id(),
            key_id.clone(),
            unused_nonce,
        ))?;
        let unused_request =
            signed_token_revocation(&issuer, cluster_id, unused_nonce, key_id, now)?;
        let unused_revocation = service.revoke_token(&unused_request, now).await?;
        assert!(unused_revocation.record.is_none());
        assert_eq!(unused_revocation.revocation.nonce, unused_nonce);
        let rejected = service
            .join(
                unused_token,
                registration_request("node-unused-revocation"),
                now,
            )
            .await;
        assert!(matches!(
            rejected,
            Err(ControlPlaneError::TokenRejected {
                status: TokenStatus::Revoked,
                ..
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn join_service_rejects_cluster_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("root");
        let expected_cluster = ClusterId::new();
        let token = issuer.sign_join_token(claims_for_issuer(
            ClusterId::new(),
            issuer.node_id(),
            key_id.clone(),
            "wrong-cluster",
        ))?;
        let service = join_service(expected_cluster, &issuer, key_id)?;

        let result = service
            .join(token, registration_request("node-a"), Utc::now())
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::TokenVerification(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn join_service_rejects_bad_signature() -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("root");
        let cluster_id = ClusterId::new();
        let mut token = issuer.sign_join_token(claims_for_issuer(
            cluster_id.clone(),
            issuer.node_id(),
            key_id.clone(),
            "bad-signature",
        ))?;
        token.signature = "not-a-valid-signature".to_string();
        let service = join_service(cluster_id, &issuer, key_id)?;

        let result = service
            .join(token, registration_request("node-a"), Utc::now())
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::TokenVerification(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn join_service_rejects_exhausted_token() -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("root");
        let cluster_id = ClusterId::new();
        let token = issuer.sign_join_token(claims_for_issuer(
            cluster_id.clone(),
            issuer.node_id(),
            key_id.clone(),
            "single-use",
        ))?;
        let service = join_service(cluster_id, &issuer, key_id)?;

        service
            .join(token.clone(), registration_request("node-a"), Utc::now())
            .await?;
        let result = service
            .join(token, registration_request("node-b"), Utc::now())
            .await;

        assert!(matches!(
            result,
            Err(ControlPlaneError::TokenRejected {
                status: TokenStatus::Exhausted,
                ..
            })
        ));
        Ok(())
    }
}
