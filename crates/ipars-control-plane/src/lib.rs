use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use ipars_crypto::{verify_join_token, CryptoError};
use ipars_types::api::{PeerMap, RegisterNodeRequest, RegisterNodeResponse, RelayMap};
use ipars_types::{
    ClusterId, ClusterPolicy, JoinTokenClaims, KeyId, NodeId, NodeRecord, PathRecord, Route,
    SignedJoinToken, TokenLedgerRecord, TokenStatus, VpnIp,
};
use ipnet::Ipv4Net;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum ControlPlaneError {
    #[error("join token does not allow node registration")]
    JoinDenied,
    #[error("node {0} already exists")]
    NodeAlreadyExists(NodeId),
    #[error("no available VPN IP in pool")]
    VpnPoolExhausted,
    #[error("route {0} is not permitted by token policy")]
    RouteDenied(String),
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
}

impl ControlPlaneConfig {
    pub fn new(cluster_id: ClusterId, vpn_pool: Ipv4Net) -> Self {
        Self {
            cluster_id,
            vpn_pool,
            cluster_policy: ClusterPolicy::default(),
        }
    }
}

#[async_trait]
pub trait ControlPlaneStore: Send + Sync {
    async fn insert_node(&self, node: NodeRecord) -> Result<(), ControlPlaneError>;
    async fn get_node(&self, node_id: &NodeId) -> Result<Option<NodeRecord>, ControlPlaneError>;
    async fn list_nodes(&self) -> Result<Vec<NodeRecord>, ControlPlaneError>;
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
        for route in &request.requested_routes {
            if !route_allowed(route, &claims) {
                return Err(ControlPlaneError::RouteDenied(route.id.clone()));
            }
        }

        let vpn_ip = self.allocator.write().await.allocate_next()?;
        let now = Utc::now();
        let node = NodeRecord {
            node_id: request.node_id,
            cluster_id: claims.cluster_id,
            vpn_ip,
            identity_public_key: request.identity_public_key,
            wireguard_public_key: request.wireguard_public_key,
            role: claims.role,
            tags: claims.tags,
            endpoint_candidates: request.candidates,
            relay_capability: request.relay_capability,
            token_policy: claims.policy,
            routes: request.requested_routes,
            registered_at: now,
        };

        self.store.insert_node(node.clone()).await?;
        let peers = self.store.list_nodes().await?;
        let peer_map = PeerMap {
            cluster_id: self.config.cluster_id.clone(),
            peers: peers
                .iter()
                .filter(|peer| peer.node_id != node.node_id)
                .cloned()
                .collect(),
            generated_at: now,
        };
        let relay_map = RelayMap {
            cluster_id: self.config.cluster_id.clone(),
            relays: peers
                .into_iter()
                .filter(|peer| {
                    peer.relay_capability
                        .as_ref()
                        .map(|capability| capability.can_admit())
                        .unwrap_or(false)
                })
                .collect(),
            generated_at: now,
        };

        Ok(RegisterNodeResponse {
            node,
            peer_map,
            relay_map,
            cluster_policy: self.config.cluster_policy.clone(),
        })
    }

    pub async fn peer_map_for(&self, node_id: &NodeId) -> Result<PeerMap, ControlPlaneError> {
        let peers = self
            .store
            .list_nodes()
            .await?
            .into_iter()
            .filter(|peer| &peer.node_id != node_id)
            .collect();

        Ok(PeerMap {
            cluster_id: self.config.cluster_id.clone(),
            peers,
            generated_at: Utc::now(),
        })
    }
}

fn route_allowed(route: &Route, claims: &JoinTokenClaims) -> bool {
    claims.policy.allowed_routes.contains(&route.cidr)
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

    fn allocate_next(&mut self) -> Result<VpnIp, ControlPlaneError> {
        let network = u32::from(self.pool.network());
        let broadcast = u32::from(self.pool.broadcast());

        if network.saturating_add(self.next_host_offset) < broadcast {
            let candidate = network + self.next_host_offset;
            self.next_host_offset += 1;
            return Ok(VpnIp(IpAddr::V4(Ipv4Addr::from(candidate))));
        }

        Err(ControlPlaneError::VpnPoolExhausted)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{Duration, Utc};
    use ipars_crypto::IdentityKeyPair;
    use ipars_types::api::RegisterNodeRequest;
    use ipars_types::{
        BootstrapEndpoint, BootstrapEndpointKind, KeyId, RelayCapability, Role, Tag, TokenPolicy,
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
        RegisterNodeRequest {
            node_id: NodeId::from_string(node_id),
            identity_public_key: format!("identity-{node_id}"),
            wireguard_public_key: format!("wg-{node_id}"),
            candidates: Vec::new(),
            relay_capability: None,
            requested_routes: Vec::new(),
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
        let request = RegisterNodeRequest {
            node_id: NodeId::from_string("node-a"),
            identity_public_key: "identity".to_string(),
            wireguard_public_key: "wg".to_string(),
            candidates: Vec::new(),
            relay_capability: Some(RelayCapability {
                enabled_by_policy: true,
                public_endpoint: Some(std::net::SocketAddr::from(([203, 0, 113, 10], 51820))),
                max_sessions: 100,
                active_sessions: 0,
                max_mbps: 1000,
                e2e_only: true,
            }),
            requested_routes: Vec::new(),
        };

        let response = plane
            .register_with_claims(claims(cluster_id), request)
            .await?;

        assert_eq!(
            response.node.vpn_ip.0,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
        );
        assert_eq!(response.relay_map.relays.len(), 1);
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
