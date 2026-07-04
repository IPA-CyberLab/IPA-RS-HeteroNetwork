use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ClusterId(String);

impl ClusterId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn from_string(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ClusterId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for ClusterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn from_string(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for NodeId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyId(String);

impl KeyId {
    pub fn from_string(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for KeyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Role(String);

impl Role {
    pub fn from_string(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn control_plane() -> Self {
        Self::from_string("control-plane")
    }

    pub fn edge() -> Self {
        Self::from_string("edge")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Tag(String);

impl Tag {
    pub fn from_string(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for Tag {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VpnIp(pub IpAddr);

impl Display for VpnIp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapEndpoint {
    pub url: String,
    pub kind: BootstrapEndpointKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapEndpointKind {
    ControlPlane,
    Signal,
    Stun,
    Relay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointCandidate {
    pub node_id: NodeId,
    pub kind: EndpointCandidateKind,
    pub addr: SocketAddr,
    pub observed_at: DateTime<Utc>,
    pub priority: u16,
    pub cost: u32,
    pub source: CandidateSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointCandidateKind {
    PublicUdp,
    Ipv6,
    StunReflexive,
    LocalUdp,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSource {
    InterfaceScan,
    StunProbe,
    ControlPlane,
    RelayMap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PathState {
    DirectPublic,
    DirectIpv6,
    DirectNatTraversal,
    Relay,
    Unreachable,
}

impl PathState {
    pub fn is_direct(self) -> bool {
        matches!(
            self,
            Self::DirectPublic | Self::DirectIpv6 | Self::DirectNatTraversal
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathMetrics {
    pub latency_ms: Option<f32>,
    pub loss_ppm: u32,
    pub jitter_ms: Option<f32>,
    pub relay_load: Option<f32>,
    pub stability: f32,
}

impl Default for PathMetrics {
    fn default() -> Self {
        Self {
            latency_ms: None,
            loss_ppm: 0,
            jitter_ms: None,
            relay_load: None,
            stability: 1.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathScore {
    pub value: f32,
    pub reasons: Vec<String>,
}

impl PathScore {
    pub fn calculate(
        state: PathState,
        metrics: &PathMetrics,
        policy_allowed: bool,
        cost: u32,
    ) -> Self {
        if !policy_allowed {
            return Self {
                value: f32::NEG_INFINITY,
                reasons: vec!["policy_denied".to_string()],
            };
        }

        let mut value = match state {
            PathState::DirectIpv6 => 120.0,
            PathState::DirectPublic => 115.0,
            PathState::DirectNatTraversal => 105.0,
            PathState::Relay => 70.0,
            PathState::Unreachable => -1000.0,
        };
        let mut reasons = vec![format!("state={state:?}")];

        if let Some(latency_ms) = metrics.latency_ms {
            value -= latency_ms.min(500.0) / 10.0;
            reasons.push(format!("latency_ms={latency_ms:.1}"));
        }
        if metrics.loss_ppm > 0 {
            value -= (metrics.loss_ppm as f32 / 10_000.0).min(50.0);
            reasons.push(format!("loss_ppm={}", metrics.loss_ppm));
        }
        if let Some(jitter_ms) = metrics.jitter_ms {
            value -= jitter_ms.min(200.0) / 20.0;
            reasons.push(format!("jitter_ms={jitter_ms:.1}"));
        }
        if let Some(relay_load) = metrics.relay_load {
            value -= relay_load.clamp(0.0, 1.0) * 20.0;
            reasons.push(format!("relay_load={relay_load:.2}"));
        }
        value += metrics.stability.clamp(0.0, 1.0) * 15.0;
        value -= cost.min(10_000) as f32 / 100.0;
        reasons.push(format!("cost={cost}"));

        Self { value, reasons }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerPathKey {
    pub local: NodeId,
    pub remote: NodeId,
}

impl PeerPathKey {
    pub fn new(local: NodeId, remote: NodeId) -> Self {
        Self { local, remote }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathRecord {
    pub key: PeerPathKey,
    pub selected_state: PathState,
    pub selected_candidate: Option<EndpointCandidate>,
    pub relay_node: Option<NodeId>,
    pub score: PathScore,
    pub updated_at: DateTime<Utc>,
    pub pinned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayCapability {
    pub enabled_by_policy: bool,
    pub public_endpoint: Option<SocketAddr>,
    pub max_sessions: u32,
    pub active_sessions: u32,
    pub max_mbps: u32,
    pub e2e_only: bool,
}

impl RelayCapability {
    pub fn available_capacity(&self) -> u32 {
        self.max_sessions.saturating_sub(self.active_sessions)
    }

    pub fn can_admit(&self) -> bool {
        self.enabled_by_policy
            && self.public_endpoint.is_some()
            && self.e2e_only
            && self.available_capacity() > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPolicy {
    pub allow_join: bool,
    pub allow_relay: bool,
    pub allowed_routes: Vec<IpNet>,
    pub allowed_tags: BTreeSet<Tag>,
    pub max_token_uses: Option<u32>,
}

impl Default for TokenPolicy {
    fn default() -> Self {
        Self {
            allow_join: true,
            allow_relay: false,
            allowed_routes: Vec::new(),
            allowed_tags: BTreeSet::new(),
            max_token_uses: Some(1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPolicy {
    pub allow_ipv6_direct: bool,
    pub allow_nat_traversal: bool,
    pub allow_relay_fallback: bool,
    pub idle_timeout_seconds: u64,
    pub pinned_roles: BTreeSet<Role>,
    pub pinned_tags: BTreeSet<Tag>,
}

impl Default for ClusterPolicy {
    fn default() -> Self {
        let mut pinned_roles = BTreeSet::new();
        pinned_roles.insert(Role::control_plane());
        Self {
            allow_ipv6_direct: true,
            allow_nat_traversal: true,
            allow_relay_fallback: true,
            idle_timeout_seconds: 300,
            pinned_roles,
            pinned_tags: BTreeSet::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclRule {
    pub id: String,
    pub from_tags: BTreeSet<Tag>,
    pub to_tags: BTreeSet<Tag>,
    pub routes: Vec<IpNet>,
    pub protocol: TransportProtocol,
    pub action: AclAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub id: String,
    pub cidr: IpNet,
    pub advertised_by: NodeId,
    pub via: Option<NodeId>,
    pub metric: u32,
    pub tags: BTreeSet<Tag>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeHealth {
    pub state: HealthState,
    pub last_seen_at: DateTime<Utc>,
    pub latency_ms: Option<f32>,
    pub relay_load: Option<f32>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_id: NodeId,
    pub cluster_id: ClusterId,
    pub vpn_ip: VpnIp,
    pub identity_public_key: String,
    pub wireguard_public_key: String,
    pub role: Role,
    pub tags: BTreeSet<Tag>,
    pub endpoint_candidates: Vec<EndpointCandidate>,
    pub relay_capability: Option<RelayCapability>,
    pub token_policy: TokenPolicy,
    pub routes: Vec<Route>,
    pub registered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinTokenClaims {
    pub cluster_id: ClusterId,
    pub bootstrap_endpoints: Vec<BootstrapEndpoint>,
    pub expires_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub role: Role,
    pub tags: BTreeSet<Tag>,
    pub issuer: NodeId,
    pub key_id: KeyId,
    pub policy: TokenPolicy,
    pub nonce: String,
}

impl JoinTokenClaims {
    pub fn is_time_valid(&self, now: DateTime<Utc>) -> bool {
        now >= self.not_before && now < self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedJoinToken {
    pub claims: JoinTokenClaims,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenStatus {
    Active,
    Revoked,
    Expired,
    Exhausted,
}

impl Display for TokenStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Exhausted => "exhausted",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenLedgerRecord {
    pub cluster_id: ClusterId,
    pub nonce: String,
    pub issuer: NodeId,
    pub key_id: KeyId,
    pub role: Role,
    pub tags: BTreeSet<Tag>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl TokenLedgerRecord {
    pub fn from_claims(claims: &JoinTokenClaims, created_at: DateTime<Utc>) -> Self {
        Self {
            cluster_id: claims.cluster_id.clone(),
            nonce: claims.nonce.clone(),
            issuer: claims.issuer.clone(),
            key_id: claims.key_id.clone(),
            role: claims.role.clone(),
            tags: claims.tags.clone(),
            expires_at: claims.expires_at,
            max_uses: claims.policy.max_token_uses,
            uses: 0,
            revoked_at: None,
            created_at,
        }
    }

    pub fn status(&self, now: DateTime<Utc>) -> TokenStatus {
        if self.revoked_at.is_some() {
            return TokenStatus::Revoked;
        }
        if now >= self.expires_at {
            return TokenStatus::Expired;
        }
        if self
            .max_uses
            .map(|max_uses| self.uses >= max_uses)
            .unwrap_or(false)
        {
            return TokenStatus::Exhausted;
        }
        TokenStatus::Active
    }

    pub fn remaining_uses(&self) -> Option<u32> {
        self.max_uses
            .map(|max_uses| max_uses.saturating_sub(self.uses))
    }
}

pub mod api {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RegisterNodeRequest {
        pub node_id: NodeId,
        pub identity_public_key: String,
        pub wireguard_public_key: String,
        pub candidates: Vec<EndpointCandidate>,
        pub relay_capability: Option<RelayCapability>,
        pub requested_routes: Vec<Route>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RegisterNodeResponse {
        pub node: NodeRecord,
        pub peer_map: PeerMap,
        pub relay_map: RelayMap,
        pub cluster_policy: ClusterPolicy,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct JoinNodeRequest {
        pub token: SignedJoinToken,
        pub registration: RegisterNodeRequest,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PeerMap {
        pub cluster_id: ClusterId,
        pub peers: Vec<NodeRecord>,
        pub generated_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RelayMap {
        pub cluster_id: ClusterId,
        pub relays: Vec<NodeRecord>,
        pub generated_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct HeartbeatRequest {
        pub node_id: NodeId,
        pub health: NodeHealth,
        pub candidates: Vec<EndpointCandidate>,
        pub path_state: Vec<PathRecord>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct HeartbeatResponse {
        pub accepted: bool,
        pub policy_version: u64,
        pub peer_delta_available: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SignalPathRequest {
        pub source: NodeId,
        pub target: NodeId,
        pub source_candidates: Vec<EndpointCandidate>,
        pub desired_routes: Vec<IpNet>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct SignalPathResponse {
        pub key: PeerPathKey,
        pub target_candidates: Vec<EndpointCandidate>,
        pub relay_candidates: Vec<NodeRecord>,
        pub preferred_state: PathState,
        pub score: PathScore,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RelayStatusResponse {
        pub relay_node: NodeId,
        pub capability: RelayCapability,
        pub health: HealthState,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_path_scores_above_relay_when_metrics_are_close() {
        let metrics = PathMetrics {
            latency_ms: Some(30.0),
            loss_ppm: 10,
            jitter_ms: Some(2.0),
            relay_load: Some(0.2),
            stability: 0.9,
        };
        let direct = PathScore::calculate(PathState::DirectNatTraversal, &metrics, true, 10);
        let relay = PathScore::calculate(PathState::Relay, &metrics, true, 10);

        assert!(direct.value > relay.value);
    }

    #[test]
    fn policy_denial_makes_path_unusable() {
        let score =
            PathScore::calculate(PathState::DirectPublic, &PathMetrics::default(), false, 0);

        assert!(score.value.is_infinite());
        assert!(score.value.is_sign_negative());
        assert_eq!(score.reasons, vec!["policy_denied"]);
    }

    #[test]
    fn relay_requires_policy_endpoint_and_capacity() {
        let relay = RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(std::net::SocketAddr::from(([203, 0, 113, 10], 51820))),
            max_sessions: 10,
            active_sessions: 9,
            max_mbps: 1000,
            e2e_only: true,
        };

        assert!(relay.can_admit());
        assert_eq!(relay.available_capacity(), 1);
    }
}
