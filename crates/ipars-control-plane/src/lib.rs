use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use ipars_crypto::{
    node_id_from_public_key_b64, validate_wireguard_public_key_b64,
    verify_heartbeat_request_signature, verify_join_token, verify_wireguard_key_rotation_signature,
    CryptoError,
};
use ipars_types::api::{
    ControlPlaneMetricsResponse, ControlPlanePathsResponse, HeartbeatRequest, HeartbeatResponse,
    PathStateCount, PeerMap, RegisterNodeRequest, RegisterNodeResponse, RelayMap,
    RotateWireGuardKeyRequest, RotateWireGuardKeyResponse,
};
use ipars_types::{
    AclAction, AclRule, ClusterId, ClusterPolicy, EndpointCandidate, HealthState, JoinTokenClaims,
    KeyId, NodeHealth, NodeId, NodeRecord, PathRecord, PathState, RelayCapability, Route,
    SignedJoinToken, TokenLedgerMetrics, TokenLedgerRecord, TokenStatus, TransportProtocol, VpnIp,
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
    async fn update_node_routes(
        &self,
        node_id: &NodeId,
        routes: Vec<Route>,
    ) -> Result<(), ControlPlaneError>;
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
    async fn upsert_path(&self, path: PathRecord) -> Result<(), ControlPlaneError>;
    async fn replace_node_paths(
        &self,
        node_id: &NodeId,
        paths: Vec<PathRecord>,
    ) -> Result<(), ControlPlaneError>;
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
    async fn token_metrics(
        &self,
        cluster_id: &ClusterId,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerMetrics, ControlPlaneError>;
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

    async fn update_node_routes(
        &self,
        node_id: &NodeId,
        routes: Vec<Route>,
    ) -> Result<(), ControlPlaneError> {
        let mut nodes = self.nodes.write().await;
        let node = nodes
            .get_mut(node_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        node.routes = routes;
        Ok(())
    }

    async fn rotate_node_wireguard_public_key(
        &self,
        node_id: &NodeId,
        expected_current_public_key: &str,
        next_public_key: String,
    ) -> Result<NodeRecord, ControlPlaneError> {
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

    async fn token_metrics(
        &self,
        cluster_id: &ClusterId,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerMetrics, ControlPlaneError> {
        let mut metrics = TokenLedgerMetrics::default();
        for record in self
            .tokens
            .read()
            .await
            .values()
            .filter(|record| &record.cluster_id == cluster_id)
        {
            metrics.observe_record(record, now);
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

    pub async fn token_metrics(
        &self,
        cluster_id: &ClusterId,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerMetrics, ControlPlaneError> {
        self.ledger.token_metrics(cluster_id, now).await
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

    pub async fn token_metrics(
        &self,
        cluster_id: &ClusterId,
        now: chrono::DateTime<Utc>,
    ) -> Result<TokenLedgerMetrics, ControlPlaneError> {
        self.admission.token_metrics(cluster_id, now).await
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

    pub async fn paths_for(
        &self,
        node_id: &NodeId,
    ) -> Result<ControlPlanePathsResponse, ControlPlaneError> {
        let source = self
            .store
            .get_node(node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        let peers = self.store.list_nodes().await?;
        let peers_by_id = peers
            .iter()
            .map(|peer| (peer.node_id.clone(), peer))
            .collect::<BTreeMap<_, _>>();
        let now = Utc::now();
        let mut stale_path_count = 0;
        let paths = self
            .store
            .list_paths_for(node_id)
            .await?
            .into_iter()
            .filter_map(|path| {
                let peer_id = if path.key.local == source.node_id {
                    &path.key.remote
                } else if path.key.remote == source.node_id {
                    &path.key.local
                } else {
                    return None;
                };
                let visible = peers_by_id.get(peer_id).is_some_and(|peer| {
                    acl_filter_peer(&source, peer, &self.config.cluster_policy).is_some()
                });
                if !visible {
                    return None;
                }
                if path_is_fresh(
                    &path,
                    now,
                    self.config.cluster_policy.path_state_ttl_seconds,
                ) {
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
            path_state_ttl_seconds: self.config.cluster_policy.path_state_ttl_seconds,
            generated_at: now,
        })
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
        let previous_health = self.store.get_health(&request.node_id).await?;
        let now = Utc::now();
        self.validate_heartbeat_request(&request, &node, previous_health.as_ref(), now)?;
        self.validate_heartbeat_path_relay_shape(&request)?;
        if request
            .path_state
            .iter()
            .any(|path| path.selected_state == PathState::Relay)
        {
            let nodes = self.store.list_nodes().await?;
            let health_by_node = self.health_by_node(&nodes).await?;
            self.validate_heartbeat_path_relay_eligibility(
                &request,
                &node,
                &nodes,
                &health_by_node,
                now,
            )?;
        }
        if let Some(signature) = request.node_signature.as_ref() {
            request.health.last_seen_at = signature.signed_at;
        }
        let relay_capability = request
            .relay_capability
            .map(|mut relay_capability| {
                if !node.token_policy.allow_relay {
                    return Err(ControlPlaneError::RelayDenied);
                }
                relay_capability.enabled_by_policy = true;
                Ok(relay_capability)
            })
            .transpose()?;
        self.store
            .update_node_candidates(&request.node_id, request.candidates)
            .await?;
        self.store
            .update_node_relay_capability(&request.node_id, relay_capability)
            .await?;
        if let Some(routes) = request.routes {
            self.store
                .update_node_routes(&request.node_id, routes)
                .await?;
        }
        self.store
            .upsert_health(request.node_id.clone(), request.health)
            .await?;
        self.store
            .replace_node_paths(&request.node_id, request.path_state)
            .await?;

        Ok(HeartbeatResponse {
            accepted: true,
            policy_version: 0,
            peer_delta_available: false,
        })
    }

    pub async fn rotate_wireguard_key(
        &self,
        request: RotateWireGuardKeyRequest,
    ) -> Result<RotateWireGuardKeyResponse, ControlPlaneError> {
        let node = self
            .store
            .get_node(&request.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(request.node_id.clone()))?;
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
        let peer_map = self.filtered_peer_map_for_node(&updated_node, &peers, rotated_at);
        let relay_map =
            self.filtered_relay_map_for_node(&updated_node, &peers, &health_by_node, rotated_at);

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
        previous_health: Option<&NodeHealth>,
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
        if let Some(routes) = request.routes.as_ref() {
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
        for path in &request.path_state {
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
        if let Some(previous_health) = previous_health {
            if signed_at <= previous_health.last_seen_at {
                return Err(ControlPlaneError::NodeSignatureRejected {
                    node_id: request.node_id.clone(),
                    reason: format!(
                        "signed_at {signed_at} is not newer than last accepted heartbeat {}",
                        previous_health.last_seen_at
                    ),
                });
            }
        }
        Ok(())
    }

    fn validate_heartbeat_path_relay_shape(
        &self,
        request: &HeartbeatRequest,
    ) -> Result<(), ControlPlaneError> {
        for path in &request.path_state {
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

    fn validate_heartbeat_path_relay_eligibility(
        &self,
        request: &HeartbeatRequest,
        reporter: &NodeRecord,
        nodes: &[NodeRecord],
        health_by_node: &BTreeMap<NodeId, NodeHealth>,
        now: chrono::DateTime<Utc>,
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
            if !relay_candidate_allowed(
                relay,
                health_by_node.get(relay_node),
                now,
                &self.config.cluster_policy,
            ) {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason: format!("relay node {relay_node} is not an eligible relay candidate"),
                });
            }
            if acl_filter_peer(reporter, relay, &self.config.cluster_policy).is_none() {
                return Err(ControlPlaneError::NodeUpdateRejected {
                    node_id: request.node_id.clone(),
                    reason: format!("relay node {relay_node} is not visible to reporting node"),
                });
            }
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
        let vpn_pool_total_count = vpn_pool_usable_host_count(self.config.vpn_pool);
        let vpn_pool_allocated_count = assigned_ipv4_vpn_ips(&nodes)
            .into_iter()
            .filter(|ip| vpn_pool_contains_usable_host(self.config.vpn_pool, *ip))
            .count() as u64;
        let vpn_pool_available_count =
            vpn_pool_total_count.saturating_sub(vpn_pool_allocated_count);
        let peer_map_metrics = peer_map_visibility_metrics(&nodes, &self.config.cluster_policy);

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
            if !path_is_fresh(path, now, self.config.cluster_policy.path_state_ttl_seconds) {
                stale_path_count += 1;
                continue;
            }
            *path_state_counts.entry(path.selected_state).or_default() += 1;
        }
        let path_count = paths.len().saturating_sub(stale_path_count);

        Ok(ControlPlaneMetricsResponse {
            cluster_id: self.config.cluster_id.clone(),
            node_count: nodes.len(),
            relay_candidate_count,
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
            peer_map_candidate_count: peer_map_metrics.peer_candidates,
            peer_map_visible_count: peer_map_metrics.visible_peers,
            peer_map_acl_denied_count: peer_map_metrics.acl_denied_peers,
            peer_map_route_candidate_count: peer_map_metrics.route_candidates,
            peer_map_route_visible_count: peer_map_metrics.visible_routes,
            peer_map_route_acl_denied_count: peer_map_metrics.acl_denied_routes,
            stale_path_count,
            path_count,
            path_state_counts: path_state_counts
                .into_iter()
                .map(|(state, count)| PathStateCount { state, count })
                .collect(),
            endpoint_candidate_ttl_seconds: self
                .config
                .cluster_policy
                .endpoint_candidate_ttl_seconds,
            path_state_ttl_seconds: self.config.cluster_policy.path_state_ttl_seconds,
            generated_at: now,
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

fn path_is_fresh(path: &PathRecord, now: chrono::DateTime<Utc>, ttl_seconds: u64) -> bool {
    match now.signed_duration_since(path.updated_at).to_std() {
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
    route_allowed_by_policy(route, &claims.policy)
}

fn route_allowed_by_policy(route: &Route, policy: &ipars_types::TokenPolicy) -> bool {
    policy
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
    use ipars_types::api::{HeartbeatRequest, RegisterNodeRequest, RotateWireGuardKeyRequest};
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
            node_id: identity.node_id(),
            identity_public_key: identity.public_key_b64(),
            wireguard_public_key: wireguard_public_key_for_node(node_id),
            candidates: Vec::new(),
            relay_capability: None,
            requested_routes: Vec::new(),
        }
    }

    fn node_record(node_id: &str) -> NodeRecord {
        let identity = identity_for_node(node_id);
        NodeRecord {
            node_id: identity.node_id(),
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

        async fn update_node_routes(
            &self,
            node_id: &NodeId,
            routes: Vec<Route>,
        ) -> Result<(), ControlPlaneError> {
            self.inner.update_node_routes(node_id, routes).await
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
            node_id: identity.node_id(),
            identity_public_key: identity.public_key_b64(),
            wireguard_public_key: wireguard_public_key_for_node("node-a"),
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
                    path_state: Vec::new(),
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
        assert_eq!(
            metrics
                .path_state_counts
                .iter()
                .find(|count| count.state == PathState::DirectNatTraversal)
                .map(|count| count.count),
            Some(1)
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
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
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
                    path_state: vec![path("node-a", "node-b")],
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
        assert_eq!(store.get_health(&node_id("node-a")).await?, Some(health));
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
                    path_state: Vec::new(),
                    node_signature: None,
                },
                second_reported_at,
            ))
            .await?;

        assert!(second_response.accepted);
        assert_eq!(
            store.get_health(&node_id("node-a")).await?,
            Some(second_health)
        );
        assert!(store.list_paths_for(&node_id("node-a")).await?.is_empty());
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
                    path_state: Vec::new(),
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
                    path_state: Vec::new(),
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
                    path_state: Vec::new(),
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
                    path_state: Vec::new(),
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
        let signed_at = Utc::now();
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
                path_state: Vec::new(),
                node_signature: None,
            },
            signed_at,
        );

        plane.heartbeat(request.clone()).await?;
        let accepted_health = store
            .get_health(&node_id("node-a"))
            .await?
            .ok_or("health should be stored")?;
        assert_eq!(accepted_health.last_seen_at, signed_at);

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
            path_state: Vec::new(),
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
                    path_state: Vec::new(),
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
                    path_state: vec![path("node-b", "node-c")],
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
                    path_state: vec![reported_path],
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
                    path_state: vec![reported_path],
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
                    path_state: vec![relay_path("node-a", "node-b", None)],
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
                    path_state: vec![relay_path("node-a", "node-b", Some("relay-a"))],
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
                    path_state: vec![relay_path("node-a", "node-b", Some("node-a"))],
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
                    path_state: Vec::new(),
                    node_signature: None,
                },
            ))
            .await?;
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
                    path_state: vec![relay_path("node-a", "node-b", Some("relay-a"))],
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
        config.cluster_policy.acl_rules = vec![AclRule {
            id: "allow-relay".to_string(),
            from_roles: BTreeSet::new(),
            from_tags: BTreeSet::new(),
            to_roles: BTreeSet::new(),
            to_tags: BTreeSet::from([Tag::from_string("relay-visible")]),
            routes: Vec::new(),
            protocol: TransportProtocol::Any,
            action: AclAction::Allow,
        }];
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
                    path_state: Vec::new(),
                    node_signature: None,
                },
            ))
            .await?;
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
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
                    path_state: vec![relay_path("node-a", "node-b", Some("relay-a"))],
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
                    path_state: Vec::new(),
                    node_signature: None,
                },
            ))
            .await?;
        plane
            .register_with_claims(claims(cluster_id), registration_request("node-a"))
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
                    path_state: vec![relay_path("node-a", "node-b", Some("relay-a"))],
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
                    path_state: vec![reported_path],
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
                    path_state: Vec::new(),
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
                    path_state: Vec::new(),
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
                    path_state: Vec::new(),
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
                    path_state: Vec::new(),
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
                    path_state: Vec::new(),
                    node_signature: None,
                },
            ))
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

        assert_eq!(response.node.node_id, node_id("node-a"));
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

        assert_eq!(old_response.node.node_id, node_id("node-old"));
        assert_eq!(next_response.node.node_id, node_id("node-next"));
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
