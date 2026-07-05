use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use ipars_crypto::{
    validate_identity_public_key_b64, verify_heartbeat_request_signature, verify_join_token,
    CryptoError,
};
use ipars_types::api::{
    ControlPlaneMetricsResponse, HeartbeatRequest, HeartbeatResponse, PathStateCount, PeerMap,
    RegisterNodeRequest, RegisterNodeResponse, RelayMap,
};
use ipars_types::{
    AclAction, AclRule, ClusterId, ClusterPolicy, EndpointCandidate, HealthState, JoinTokenClaims,
    KeyId, NodeHealth, NodeId, NodeRecord, PathRecord, PathState, RelayCapability, Route,
    SignedJoinToken, TokenLedgerRecord, TokenStatus, TransportProtocol, VpnIp,
};
use ipnet::IpNet;
use ipnet::Ipv4Net;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum ControlPlaneError {
    #[error("join token does not allow node registration")]
    JoinDenied,
    #[error("node {0} already exists")]
    NodeAlreadyExists(NodeId),
    #[error("VPN IP {0} is already allocated")]
    VpnIpAlreadyAllocated(VpnIp),
    #[error("node {0} heartbeat signature is required")]
    NodeSignatureRequired(NodeId),
    #[error("node {node_id} heartbeat signature rejected: {reason}")]
    NodeSignatureRejected { node_id: NodeId, reason: String },
    #[error("node {node_id} heartbeat update rejected: {reason}")]
    NodeUpdateRejected { node_id: NodeId, reason: String },
    #[error("node {node_id} registration rejected: {reason}")]
    NodeRegistrationRejected { node_id: NodeId, reason: String },
    #[error("node not found: {0}")]
    NodeNotFound(NodeId),
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

#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    pub cluster_id: ClusterId,
    pub vpn_pool: Ipv4Net,
    pub cluster_policy: ClusterPolicy,
    pub require_heartbeat_signature: bool,
    pub heartbeat_signature_max_age: Duration,
}

impl ControlPlaneConfig {
    pub fn new(cluster_id: ClusterId, vpn_pool: Ipv4Net) -> Self {
        Self {
            cluster_id,
            vpn_pool,
            cluster_policy: ClusterPolicy::default(),
            require_heartbeat_signature: true,
            heartbeat_signature_max_age: Duration::from_secs(300),
        }
    }
}

#[async_trait]
pub trait ControlPlaneStore: Send + Sync {
    async fn insert_node(&self, node: NodeRecord) -> Result<(), ControlPlaneError>;
    async fn get_node(&self, node_id: &NodeId) -> Result<Option<NodeRecord>, ControlPlaneError>;
    async fn list_nodes(&self) -> Result<Vec<NodeRecord>, ControlPlaneError>;
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
    async fn upsert_health(
        &self,
        node_id: NodeId,
        health: NodeHealth,
    ) -> Result<(), ControlPlaneError>;
    async fn get_health(&self, node_id: &NodeId) -> Result<Option<NodeHealth>, ControlPlaneError>;
    async fn upsert_path(&self, path: PathRecord) -> Result<(), ControlPlaneError>;
    async fn list_paths_for(&self, node_id: &NodeId) -> Result<Vec<PathRecord>, ControlPlaneError>;
}

#[async_trait]
pub trait TokenLedger: Send + Sync {
    async fn upsert_token(&self, record: TokenLedgerRecord) -> Result<(), ControlPlaneError>;
    async fn get_token(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
    ) -> Result<Option<TokenLedgerRecord>, ControlPlaneError>;
    async fn revoke_token(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
        revoked_at: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError>;
    async fn record_token_use(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError>;
}

#[derive(Debug, Default)]
pub struct InMemoryStore {
    nodes: RwLock<BTreeMap<NodeId, NodeRecord>>,
    health: RwLock<BTreeMap<NodeId, NodeHealth>>,
    paths: RwLock<Vec<PathRecord>>,
}

#[async_trait]
impl ControlPlaneStore for InMemoryStore {
    async fn insert_node(&self, node: NodeRecord) -> Result<(), ControlPlaneError> {
        let mut nodes = self.nodes.write().await;
        if nodes.contains_key(&node.node_id) {
            return Err(ControlPlaneError::NodeAlreadyExists(node.node_id));
        }
        nodes.insert(node.node_id.clone(), node);
        Ok(())
    }

    async fn get_node(&self, node_id: &NodeId) -> Result<Option<NodeRecord>, ControlPlaneError> {
        Ok(self.nodes.read().await.get(node_id).cloned())
    }

    async fn list_nodes(&self) -> Result<Vec<NodeRecord>, ControlPlaneError> {
        Ok(self.nodes.read().await.values().cloned().collect())
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

    async fn upsert_path(&self, path: PathRecord) -> Result<(), ControlPlaneError> {
        let mut paths = self.paths.write().await;
        if let Some(existing) = paths.iter_mut().find(|existing| existing.key == path.key) {
            *existing = path;
        } else {
            paths.push(path);
        }
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
}

#[derive(Debug, Default)]
pub struct InMemoryTokenLedger {
    tokens: RwLock<BTreeMap<String, TokenLedgerRecord>>,
}

#[async_trait]
impl TokenLedger for InMemoryTokenLedger {
    async fn upsert_token(&self, record: TokenLedgerRecord) -> Result<(), ControlPlaneError> {
        self.tokens
            .write()
            .await
            .insert(token_key(&record.cluster_id, &record.nonce), record);
        Ok(())
    }

    async fn get_token(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
    ) -> Result<Option<TokenLedgerRecord>, ControlPlaneError> {
        Ok(self
            .tokens
            .read()
            .await
            .get(&token_key(cluster_id, nonce))
            .cloned())
    }

    async fn revoke_token(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
        revoked_at: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        let mut tokens = self.tokens.write().await;
        let record = tokens
            .get_mut(&token_key(cluster_id, nonce))
            .ok_or_else(|| ControlPlaneError::TokenNotFound(nonce.to_string()))?;
        record.revoked_at = Some(revoked_at);
        Ok(record.clone())
    }

    async fn record_token_use(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        let mut tokens = self.tokens.write().await;
        let record = tokens
            .get_mut(&token_key(cluster_id, nonce))
            .ok_or_else(|| ControlPlaneError::TokenNotFound(nonce.to_string()))?;
        let status = record.status(now);
        if status != TokenStatus::Active {
            return Err(ControlPlaneError::TokenRejected {
                nonce: nonce.to_string(),
                status,
            });
        }
        record.uses = record.uses.saturating_add(1);
        Ok(record.clone())
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
        self.ledger.upsert_token(record.clone()).await?;
        Ok(record)
    }

    pub async fn admit_join(
        &self,
        claims: &JoinTokenClaims,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        let record = self
            .ledger
            .get_token(&claims.cluster_id, &claims.nonce)
            .await?
            .unwrap_or_else(|| TokenLedgerRecord::from_claims(claims, now));

        if self
            .ledger
            .get_token(&claims.cluster_id, &claims.nonce)
            .await?
            .is_none()
        {
            self.ledger.upsert_token(record).await?;
        }

        self.ledger
            .record_token_use(&claims.cluster_id, &claims.nonce, now)
            .await
    }

    pub async fn revoke_token(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
        revoked_at: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        self.ledger
            .revoke_token(cluster_id, nonce, revoked_at)
            .await
    }
}

#[derive(Debug, Clone, Default)]
pub struct IssuerKeyRing {
    keys: BTreeMap<(NodeId, KeyId), String>,
}

impl IssuerKeyRing {
    pub fn insert(&mut self, issuer: NodeId, key_id: KeyId, public_key_b64: String) {
        self.keys.insert((issuer, key_id), public_key_b64);
    }

    pub fn get(&self, issuer: &NodeId, key_id: &KeyId) -> Option<&str> {
        self.keys
            .get(&(issuer.clone(), key_id.clone()))
            .map(String::as_str)
    }
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

    pub async fn join(
        &self,
        token: SignedJoinToken,
        request: RegisterNodeRequest,
        now: chrono::DateTime<Utc>,
    ) -> Result<RegisterNodeResponse, ControlPlaneError> {
        if !token.claims.policy.allow_join {
            return Err(ControlPlaneError::JoinDenied);
        }

        let issuer_public_key = self
            .issuer_keys
            .get(&token.claims.issuer, &token.claims.key_id)
            .ok_or_else(|| ControlPlaneError::IssuerKeyNotFound {
                issuer: token.claims.issuer.clone(),
                key_id: token.claims.key_id.clone(),
            })?;
        verify_join_token(
            &token,
            issuer_public_key,
            now,
            &self.plane.config.cluster_id,
        )?;
        self.admission.admit_join(&token.claims, now).await?;
        self.plane.register_with_claims(token.claims, request).await
    }

    pub async fn revoke_token(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
        revoked_at: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        self.admission
            .revoke_token(cluster_id, nonce, revoked_at)
            .await
    }
}

#[derive(Debug)]
pub struct ControlPlane<S> {
    config: ControlPlaneConfig,
    store: Arc<S>,
    allocator: RwLock<VpnAllocator>,
}

impl<S> ControlPlane<S>
where
    S: ControlPlaneStore,
{
    pub fn new(config: ControlPlaneConfig, store: Arc<S>) -> Self {
        Self {
            allocator: RwLock::new(VpnAllocator::new(config.vpn_pool)),
            config,
            store,
        }
    }

    pub fn config(&self) -> &ControlPlaneConfig {
        &self.config
    }

    pub async fn register_with_claims(
        &self,
        claims: JoinTokenClaims,
        request: RegisterNodeRequest,
    ) -> Result<RegisterNodeResponse, ControlPlaneError> {
        if !claims.policy.allow_join {
            return Err(ControlPlaneError::JoinDenied);
        }
        validate_registration_request(&request)?;
        for route in &request.requested_routes {
            if !route_allowed(route, &claims) {
                return Err(ControlPlaneError::RouteDenied(route.id.clone()));
            }
        }

        let relay_capability = relay_capability_allowed(request.relay_capability.clone(), &claims)?;
        let now = Utc::now();
        let node = self
            .insert_node_with_fresh_vpn_ip(claims, request, relay_capability, now)
            .await?;
        let peers = self.store.list_nodes().await?;
        let health_by_node = self.health_by_node(&peers).await?;
        let peer_map = self.filtered_peer_map_for_node(&node, &peers, now);
        let relay_map = self.filtered_relay_map_for_node(&node, &peers, &health_by_node, now);

        Ok(RegisterNodeResponse {
            node,
            peer_map,
            relay_map,
            cluster_policy: self.config.cluster_policy.clone(),
        })
    }

    async fn insert_node_with_fresh_vpn_ip(
        &self,
        claims: JoinTokenClaims,
        request: RegisterNodeRequest,
        relay_capability: Option<RelayCapability>,
        registered_at: chrono::DateTime<Utc>,
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

            match self.store.insert_node(node.clone()).await {
                Ok(()) => return Ok(node),
                Err(ControlPlaneError::VpnIpAlreadyAllocated(_)) => continue,
                Err(error) => return Err(error),
            }
        }
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

        Ok(self.filtered_peer_map_for_node(&source, &peers, Utc::now()))
    }

    pub async fn heartbeat(
        &self,
        request: HeartbeatRequest,
    ) -> Result<HeartbeatResponse, ControlPlaneError> {
        let node = self
            .store
            .get_node(&request.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(request.node_id.clone()))?;
        self.validate_heartbeat_request(&request, &node, Utc::now())?;
        self.store
            .update_node_candidates(&request.node_id, request.candidates)
            .await?;
        if let Some(mut relay_capability) = request.relay_capability {
            if !node.token_policy.allow_relay {
                return Err(ControlPlaneError::RelayDenied);
            }
            relay_capability.enabled_by_policy = true;
            self.store
                .update_node_relay_capability(&request.node_id, Some(relay_capability))
                .await?;
        }
        self.store
            .upsert_health(request.node_id.clone(), request.health)
            .await?;
        for path in request.path_state {
            self.store.upsert_path(path).await?;
        }

        Ok(HeartbeatResponse {
            accepted: true,
            policy_version: 0,
            peer_delta_available: false,
        })
    }

    fn validate_heartbeat_request(
        &self,
        request: &HeartbeatRequest,
        node: &NodeRecord,
        now: chrono::DateTime<Utc>,
    ) -> Result<(), ControlPlaneError> {
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
        if let Some(path) = request
            .path_state
            .iter()
            .find(|path| path.key.local != request.node_id && path.key.remote != request.node_id)
        {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: request.node_id.clone(),
                reason: format!(
                    "path {} -> {} does not include reporting node",
                    path.key.local, path.key.remote
                ),
            });
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
        Ok(())
    }

    pub async fn metrics(&self) -> Result<ControlPlaneMetricsResponse, ControlPlaneError> {
        let nodes = self.store.list_nodes().await?;
        let health_by_node = self.health_by_node(&nodes).await?;
        let mut healthy_node_count = 0;
        let mut degraded_node_count = 0;
        let mut unhealthy_node_count = 0;
        let now = Utc::now();
        let relay_candidate_count = nodes
            .iter()
            .filter(|node| {
                relay_candidate_allowed(
                    node,
                    health_by_node.get(&node.node_id),
                    now,
                    &self.config.cluster_policy,
                )
            })
            .count();
        let stale_endpoint_candidate_count = nodes
            .iter()
            .flat_map(|node| &node.endpoint_candidates)
            .filter(|candidate| {
                !endpoint_candidate_is_fresh(
                    candidate,
                    now,
                    self.config.cluster_policy.endpoint_candidate_ttl_seconds,
                )
            })
            .count();

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

        let mut path_state_counts = BTreeMap::<PathState, usize>::new();
        for path in paths.values() {
            *path_state_counts.entry(path.selected_state).or_default() += 1;
        }

        Ok(ControlPlaneMetricsResponse {
            cluster_id: self.config.cluster_id.clone(),
            node_count: nodes.len(),
            relay_candidate_count,
            healthy_node_count,
            degraded_node_count,
            unhealthy_node_count,
            stale_endpoint_candidate_count,
            path_count: paths.len(),
            path_state_counts: path_state_counts
                .into_iter()
                .map(|(state, count)| PathStateCount { state, count })
                .collect(),
            endpoint_candidate_ttl_seconds: self
                .config
                .cluster_policy
                .endpoint_candidate_ttl_seconds,
            generated_at: Utc::now(),
        })
    }

    async fn health_by_node(
        &self,
        nodes: &[NodeRecord],
    ) -> Result<BTreeMap<NodeId, NodeHealth>, ControlPlaneError> {
        let mut health_by_node = BTreeMap::new();
        for node in nodes {
            if let Some(health) = self.store.get_health(&node.node_id).await? {
                health_by_node.insert(node.node_id.clone(), health);
            }
        }
        Ok(health_by_node)
    }

    fn filtered_peer_map_for_node(
        &self,
        source: &NodeRecord,
        peers: &[NodeRecord],
        generated_at: chrono::DateTime<Utc>,
    ) -> PeerMap {
        PeerMap {
            cluster_id: self.config.cluster_id.clone(),
            peers: peers
                .iter()
                .filter(|peer| peer.node_id != source.node_id)
                .filter_map(|peer| acl_filter_peer(source, peer, &self.config.cluster_policy))
                .map(|peer| {
                    filter_stale_endpoint_candidates(
                        peer,
                        generated_at,
                        &self.config.cluster_policy,
                    )
                })
                .collect(),
            generated_at,
        }
    }

    fn filtered_relay_map_for_node(
        &self,
        source: &NodeRecord,
        peers: &[NodeRecord],
        health_by_node: &BTreeMap<NodeId, NodeHealth>,
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
                        &self.config.cluster_policy,
                    )
                })
                .filter_map(|peer| {
                    if peer.node_id == source.node_id {
                        Some(peer.clone())
                    } else {
                        acl_filter_peer(source, peer, &self.config.cluster_policy)
                    }
                })
                .map(|peer| {
                    filter_stale_endpoint_candidates(
                        peer,
                        generated_at,
                        &self.config.cluster_policy,
                    )
                })
                .collect(),
            generated_at,
        }
    }
}

fn filter_stale_endpoint_candidates(
    mut node: NodeRecord,
    now: chrono::DateTime<Utc>,
    policy: &ClusterPolicy,
) -> NodeRecord {
    node.endpoint_candidates.retain(|candidate| {
        endpoint_candidate_is_fresh(candidate, now, policy.endpoint_candidate_ttl_seconds)
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

fn relay_candidate_allowed(
    node: &NodeRecord,
    health: Option<&NodeHealth>,
    now: chrono::DateTime<Utc>,
    policy: &ClusterPolicy,
) -> bool {
    node.relay_capability
        .as_ref()
        .is_some_and(|capability| capability.can_admit())
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
    match route {
        Some(route) => {
            rule.routes.is_empty()
                || rule
                    .routes
                    .iter()
                    .any(|allowed| ipnet_contains(allowed, &route.cidr))
        }
        None => rule.routes.is_empty(),
    }
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

fn route_allowed(route: &Route, claims: &JoinTokenClaims) -> bool {
    claims
        .policy
        .allowed_routes
        .iter()
        .any(|allowed_route| allowed_route.contains(&route.cidr))
}

fn relay_capability_allowed(
    relay_capability: Option<RelayCapability>,
    claims: &JoinTokenClaims,
) -> Result<Option<RelayCapability>, ControlPlaneError> {
    relay_capability
        .map(|mut capability| {
            if !claims.policy.allow_relay {
                return Err(ControlPlaneError::RelayDenied);
            }
            capability.enabled_by_policy = true;
            Ok(capability)
        })
        .transpose()
}

fn validate_registration_request(request: &RegisterNodeRequest) -> Result<(), ControlPlaneError> {
    validate_identity_public_key_b64(&request.identity_public_key).map_err(|error| {
        ControlPlaneError::NodeRegistrationRejected {
            node_id: request.node_id.clone(),
            reason: format!("identity public key is invalid: {error}"),
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, Ordering};

    use chrono::{Duration, Utc};
    use ipars_crypto::IdentityKeyPair;
    use ipars_types::api::{HeartbeatRequest, RegisterNodeRequest};
    use ipars_types::{
        AclAction, AclRule, BootstrapEndpoint, BootstrapEndpointKind, CandidateSource,
        EndpointCandidate, EndpointCandidateKind, HealthState, KeyId, NodeHealth, PathMetrics,
        PathRecord, PathScore, PathState, PeerPathKey, RelayCapability, Role, Tag, TokenPolicy,
        TransportProtocol,
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

    fn registration_request(node_id: &str) -> RegisterNodeRequest {
        let identity = identity_for_node(node_id);
        RegisterNodeRequest {
            node_id: NodeId::from_string(node_id),
            identity_public_key: identity.public_key_b64(),
            wireguard_public_key: format!("wg-{node_id}"),
            candidates: Vec::new(),
            relay_capability: None,
            requested_routes: Vec::new(),
        }
    }

    fn node_record(node_id: &str) -> NodeRecord {
        let identity = identity_for_node(node_id);
        NodeRecord {
            node_id: NodeId::from_string(node_id),
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
            identity_public_key: identity.public_key_b64(),
            wireguard_public_key: format!("wg-{node_id}"),
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

    fn signed_heartbeat(mut request: HeartbeatRequest) -> HeartbeatRequest {
        let identity = identity_for_node(request.node_id.as_str());
        request.node_signature = Some(
            match identity.sign_heartbeat_request(&request, Utc::now()) {
                Ok(signature) => signature,
                Err(error) => panic!("test identity should sign heartbeat: {error}"),
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

    #[derive(Default)]
    struct RacingVpnIpStore {
        inner: InMemoryStore,
        race_once: AtomicBool,
    }

    #[async_trait]
    impl ControlPlaneStore for RacingVpnIpStore {
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

        async fn get_node(
            &self,
            node_id: &NodeId,
        ) -> Result<Option<NodeRecord>, ControlPlaneError> {
            self.inner.get_node(node_id).await
        }

        async fn list_nodes(&self) -> Result<Vec<NodeRecord>, ControlPlaneError> {
            self.inner.list_nodes().await
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

        async fn upsert_path(&self, path: PathRecord) -> Result<(), ControlPlaneError> {
            self.inner.upsert_path(path).await
        }

        async fn list_paths_for(
            &self,
            node_id: &NodeId,
        ) -> Result<Vec<PathRecord>, ControlPlaneError> {
            self.inner.list_paths_for(node_id).await
        }
    }

    fn route(id: &str, cidr: &str, advertised_by: &str) -> Result<Route, ipnet::AddrParseError> {
        Ok(Route {
            id: id.to_string(),
            cidr: cidr.parse()?,
            advertised_by: NodeId::from_string(advertised_by),
            via: None,
            metric: 100,
            tags: BTreeSet::new(),
        })
    }

    fn candidate(node_id: &str) -> EndpointCandidate {
        EndpointCandidate {
            node_id: NodeId::from_string(node_id),
            kind: EndpointCandidateKind::StunReflexive,
            addr: std::net::SocketAddr::from(([203, 0, 113, 10], 51820)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::StunProbe,
        }
    }

    fn stale_candidate(node_id: &str) -> EndpointCandidate {
        let mut candidate = candidate(node_id);
        candidate.observed_at = Utc::now() - Duration::seconds(60);
        candidate
    }

    fn path(local: &str, remote: &str) -> PathRecord {
        PathRecord {
            key: PeerPathKey::new(NodeId::from_string(local), NodeId::from_string(remote)),
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
            node_id: NodeId::from_string("node-a"),
            identity_public_key: identity.public_key_b64(),
            wireguard_public_key: "wg".to_string(),
            candidates: Vec::new(),
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
            .heartbeat(signed_heartbeat(HeartbeatRequest {
                node_id: NodeId::from_string("relay-a"),
                health: NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now(),
                    latency_ms: Some(1.0),
                    relay_load: Some(0.10),
                    message: None,
                },
                candidates: Vec::new(),
                relay_capability: None,
                path_state: Vec::new(),
                node_signature: None,
            }))
            .await?;
        assert_eq!(plane.metrics().await?.relay_candidate_count, 1);

        let source_registration = plane
            .register_with_claims(claims(cluster_id.clone()), registration_request("node-a"))
            .await?;
        assert_eq!(source_registration.relay_map.relays.len(), 1);
        assert_eq!(
            source_registration.relay_map.relays[0].node_id,
            NodeId::from_string("relay-a")
        );

        store
            .upsert_health(
                NodeId::from_string("relay-a"),
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
                NodeId::from_string("relay-a"),
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
            node.node_id == NodeId::from_string("node-racing-peer")
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
            .register_with_claims(claims(cluster_id), request)
            .await
        {
            Ok(_) => return Err("unexpected successful identity registration".into()),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ControlPlaneError::NodeRegistrationRejected { .. }
        ));
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
            .find(|peer| peer.node_id == NodeId::from_string("allowed"))
            .ok_or("allowed peer should be visible")?;
        assert!(allowed_peer.routes.is_empty());
        let route_peer = peer_map
            .peers
            .iter()
            .find(|peer| peer.node_id == NodeId::from_string("route-provider"))
            .ok_or("route provider should be visible")?;
        assert_eq!(route_peer.routes.len(), 1);
        assert_eq!(route_peer.routes[0].id, "allowed-route");
        assert!(peer_map
            .peers
            .iter()
            .all(|peer| peer.node_id != NodeId::from_string("denied")));
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
                NodeId::from_string("relay-a"),
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
            .find(|peer| peer.node_id == NodeId::from_string("peer-a"))
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
            .find(|relay| relay.node_id == NodeId::from_string("relay-a"))
            .ok_or("fresh healthy relay should remain visible")?;
        assert_eq!(relay.endpoint_candidates.len(), 1);

        let metrics = plane.metrics().await?;
        assert_eq!(metrics.stale_endpoint_candidate_count, 2);
        assert_eq!(metrics.endpoint_candidate_ttl_seconds, 30);
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
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
            .await?;
        let health = NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: Utc::now(),
            latency_ms: Some(12.0),
            relay_load: None,
            message: Some("ok".to_string()),
        };

        let response = plane
            .heartbeat(signed_heartbeat(HeartbeatRequest {
                node_id: NodeId::from_string("node-a"),
                health: health.clone(),
                candidates: vec![candidate("node-a")],
                relay_capability: None,
                path_state: vec![path("node-a", "node-b")],
                node_signature: None,
            }))
            .await?;

        assert!(response.accepted);
        assert_eq!(
            store
                .get_node(&NodeId::from_string("node-a"))
                .await?
                .ok_or(ControlPlaneError::NodeNotFound(NodeId::from_string(
                    "node-a"
                )))?
                .endpoint_candidates
                .len(),
            1
        );
        assert_eq!(
            store.get_health(&NodeId::from_string("node-a")).await?,
            Some(health)
        );
        assert_eq!(
            store
                .list_paths_for(&NodeId::from_string("node-a"))
                .await?
                .len(),
            1
        );
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
            node_id: NodeId::from_string("node-a"),
            health: NodeHealth {
                state: HealthState::Healthy,
                last_seen_at: Utc::now(),
                latency_ms: None,
                relay_load: None,
                message: None,
            },
            candidates: Vec::new(),
            relay_capability: None,
            path_state: Vec::new(),
            node_signature: None,
        };

        let result = plane.heartbeat(unsigned.clone()).await;
        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeSignatureRequired(_))
        ));

        let mut tampered = signed_heartbeat(unsigned);
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
            .heartbeat(signed_heartbeat(HeartbeatRequest {
                node_id: NodeId::from_string("node-a"),
                health: health.clone(),
                candidates: vec![candidate("node-b")],
                relay_capability: None,
                path_state: Vec::new(),
                node_signature: None,
            }))
            .await;
        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { .. })
        ));

        let result = plane
            .heartbeat(signed_heartbeat(HeartbeatRequest {
                node_id: NodeId::from_string("node-a"),
                health,
                candidates: Vec::new(),
                relay_capability: None,
                path_state: vec![path("node-b", "node-c")],
                node_signature: None,
            }))
            .await;
        assert!(matches!(
            result,
            Err(ControlPlaneError::NodeUpdateRejected { .. })
        ));
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
            .heartbeat(signed_heartbeat(HeartbeatRequest {
                node_id: NodeId::from_string("node-a"),
                health: NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now(),
                    latency_ms: None,
                    relay_load: Some(0.25),
                    message: None,
                },
                candidates: Vec::new(),
                relay_capability: Some(heartbeat_relay),
                path_state: Vec::new(),
                node_signature: None,
            }))
            .await?;

        assert!(response.accepted);
        let node = store
            .get_node(&NodeId::from_string("node-a"))
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(NodeId::from_string("node-a")))?;
        let Some(relay) = node.relay_capability else {
            return Err("expected heartbeat relay capability".into());
        };
        assert!(relay.enabled_by_policy);
        assert_eq!(relay.active_sessions, 7);
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
            .heartbeat(signed_heartbeat(HeartbeatRequest {
                node_id: NodeId::from_string("node-a"),
                health: NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now(),
                    latency_ms: None,
                    relay_load: None,
                    message: None,
                },
                candidates: Vec::new(),
                relay_capability: Some(relay_capability()),
                path_state: Vec::new(),
                node_signature: None,
            }))
            .await;

        assert!(matches!(result, Err(ControlPlaneError::RelayDenied)));
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

        let second_use = admission.admit_join(&token_claims, Utc::now()).await;
        assert!(matches!(
            second_use,
            Err(ControlPlaneError::TokenRejected {
                status: TokenStatus::Exhausted,
                ..
            })
        ));

        let mut revoked_claims = claims(cluster_id);
        revoked_claims.nonce = "revoked".to_string();
        admission
            .issue_from_claims(&revoked_claims, Utc::now())
            .await?;
        ledger
            .revoke_token(
                &revoked_claims.cluster_id,
                &revoked_claims.nonce,
                Utc::now(),
            )
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

        assert_eq!(response.node.node_id, NodeId::from_string("node-a"));
        assert_eq!(
            response.node.vpn_ip.0,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
        );
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

        assert_eq!(old_response.node.node_id, NodeId::from_string("node-old"));
        assert_eq!(next_response.node.node_id, NodeId::from_string("node-next"));
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
