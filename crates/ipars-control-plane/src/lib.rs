use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use ipars_types::api::{PeerMap, RegisterNodeRequest, RegisterNodeResponse, RelayMap};
use ipars_types::{
    ClusterId, ClusterPolicy, JoinTokenClaims, NodeId, NodeRecord, PathRecord, Route, VpnIp,
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
    #[error("store error: {0}")]
    Store(String),
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
}
