use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Utc};
use ipnet::{IpNet, Ipv4Net};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatProbeObservation {
    pub local_addr: SocketAddr,
    pub stun_server: SocketAddr,
    pub reflexive_addr: SocketAddr,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatMappingBehavior {
    Unknown,
    NoNat,
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatFilteringBehavior {
    Unknown,
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatFilteringProbeKind {
    SameAddress,
    ChangePort,
    ChangeAddressAndPort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatFilteringObservation {
    pub local_addr: SocketAddr,
    pub stun_server: SocketAddr,
    pub probe: NatFilteringProbeKind,
    pub response_origin: Option<SocketAddr>,
    pub other_address: Option<SocketAddr>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatTraversalStrategy {
    DirectCandidate,
    CoordinatedHolePunch,
    RelayPreferred,
    InsufficientData,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NatClassification {
    pub local_addr: SocketAddr,
    pub mapping_behavior: NatMappingBehavior,
    pub filtering_behavior: NatFilteringBehavior,
    pub observed_endpoint: Option<SocketAddr>,
    pub observations: Vec<NatProbeObservation>,
    pub filtering_observations: Vec<NatFilteringObservation>,
    pub strategy: NatTraversalStrategy,
    pub confidence: f32,
    pub assessed_at: DateTime<Utc>,
}

impl NatClassification {
    pub fn from_observations(
        local_addr: SocketAddr,
        observations: Vec<NatProbeObservation>,
        assessed_at: DateTime<Utc>,
    ) -> Self {
        Self::from_observations_with_filtering(local_addr, observations, Vec::new(), assessed_at)
    }

    pub fn from_observations_with_filtering(
        local_addr: SocketAddr,
        observations: Vec<NatProbeObservation>,
        filtering_observations: Vec<NatFilteringObservation>,
        assessed_at: DateTime<Utc>,
    ) -> Self {
        let mapping_behavior = classify_nat_mapping(local_addr, &observations);
        let filtering_behavior = classify_nat_filtering(&filtering_observations);
        let observed_endpoint = stable_observed_endpoint(&observations);
        let strategy = nat_traversal_strategy(mapping_behavior, filtering_behavior);
        let confidence = nat_classification_confidence(
            mapping_behavior,
            observations.len(),
            filtering_behavior,
            filtering_observations.len(),
        );

        Self {
            local_addr,
            mapping_behavior,
            filtering_behavior,
            observed_endpoint,
            observations,
            filtering_observations,
            strategy,
            confidence,
            assessed_at,
        }
    }
}

fn classify_nat_mapping(
    local_addr: SocketAddr,
    observations: &[NatProbeObservation],
) -> NatMappingBehavior {
    if observations.is_empty() {
        return NatMappingBehavior::Unknown;
    }
    if !local_addr.ip().is_unspecified()
        && observations
            .iter()
            .all(|observation| observation.reflexive_addr == local_addr)
    {
        return NatMappingBehavior::NoNat;
    }
    if observations.len() == 1 {
        return NatMappingBehavior::Unknown;
    }
    let first_reflexive = observations[0].reflexive_addr;
    if observations
        .iter()
        .all(|observation| observation.reflexive_addr == first_reflexive)
    {
        return NatMappingBehavior::EndpointIndependent;
    }
    if same_stun_address_different_port_changes_mapping(observations) {
        return NatMappingBehavior::AddressAndPortDependent;
    }
    NatMappingBehavior::AddressDependent
}

fn stable_observed_endpoint(observations: &[NatProbeObservation]) -> Option<SocketAddr> {
    let first = observations.first()?.reflexive_addr;
    observations
        .iter()
        .all(|observation| observation.reflexive_addr == first)
        .then_some(first)
}

fn same_stun_address_different_port_changes_mapping(observations: &[NatProbeObservation]) -> bool {
    observations.iter().enumerate().any(|(left_index, left)| {
        observations.iter().skip(left_index + 1).any(|right| {
            left.stun_server.ip() == right.stun_server.ip()
                && left.stun_server.port() != right.stun_server.port()
                && left.reflexive_addr != right.reflexive_addr
        })
    })
}

fn classify_nat_filtering(observations: &[NatFilteringObservation]) -> NatFilteringBehavior {
    if observations.is_empty() {
        return NatFilteringBehavior::Unknown;
    }
    if filtering_probe_received(observations, NatFilteringProbeKind::ChangeAddressAndPort) {
        return NatFilteringBehavior::EndpointIndependent;
    }
    if filtering_probe_received(observations, NatFilteringProbeKind::ChangePort) {
        return NatFilteringBehavior::AddressDependent;
    }
    if filtering_probe_received(observations, NatFilteringProbeKind::SameAddress) {
        return NatFilteringBehavior::AddressAndPortDependent;
    }
    NatFilteringBehavior::Unknown
}

fn filtering_probe_received(
    observations: &[NatFilteringObservation],
    probe: NatFilteringProbeKind,
) -> bool {
    observations
        .iter()
        .any(|observation| observation.probe == probe && observation.response_origin.is_some())
}

fn nat_traversal_strategy(
    mapping_behavior: NatMappingBehavior,
    filtering_behavior: NatFilteringBehavior,
) -> NatTraversalStrategy {
    if mapping_behavior == NatMappingBehavior::NoNat {
        return NatTraversalStrategy::DirectCandidate;
    }
    if matches!(
        mapping_behavior,
        NatMappingBehavior::AddressAndPortDependent | NatMappingBehavior::Unknown
    ) {
        return match mapping_behavior {
            NatMappingBehavior::Unknown => NatTraversalStrategy::InsufficientData,
            _ => NatTraversalStrategy::RelayPreferred,
        };
    }
    match filtering_behavior {
        NatFilteringBehavior::AddressAndPortDependent => NatTraversalStrategy::RelayPreferred,
        NatFilteringBehavior::EndpointIndependent
        | NatFilteringBehavior::AddressDependent
        | NatFilteringBehavior::Unknown => NatTraversalStrategy::CoordinatedHolePunch,
    }
}

fn nat_classification_confidence(
    mapping_behavior: NatMappingBehavior,
    observation_count: usize,
    filtering_behavior: NatFilteringBehavior,
    filtering_observation_count: usize,
) -> f32 {
    let mapping_confidence = match mapping_behavior {
        NatMappingBehavior::Unknown if observation_count == 0 => 0.0,
        NatMappingBehavior::Unknown => 0.25,
        NatMappingBehavior::NoNat => 1.0,
        NatMappingBehavior::EndpointIndependent => (0.6 + observation_count as f32 * 0.1).min(0.95),
        NatMappingBehavior::AddressDependent => (0.55 + observation_count as f32 * 0.1).min(0.9),
        NatMappingBehavior::AddressAndPortDependent => {
            (0.65 + observation_count as f32 * 0.1).min(0.95)
        }
    };
    let filtering_confidence = match filtering_behavior {
        NatFilteringBehavior::Unknown if filtering_observation_count == 0 => mapping_confidence,
        NatFilteringBehavior::Unknown => 0.25,
        NatFilteringBehavior::EndpointIndependent => {
            (0.6 + filtering_observation_count as f32 * 0.1).min(0.95)
        }
        NatFilteringBehavior::AddressDependent => {
            (0.55 + filtering_observation_count as f32 * 0.1).min(0.9)
        }
        NatFilteringBehavior::AddressAndPortDependent => {
            (0.65 + filtering_observation_count as f32 * 0.1).min(0.95)
        }
    };
    if filtering_observation_count == 0 {
        mapping_confidence
    } else {
        ((mapping_confidence + filtering_confidence) / 2.0).min(0.98)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathChangeKind {
    Created,
    StateChanged,
    RelayChanged,
    CandidateChanged,
    ScoreChanged,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathChangeEvent {
    pub key: PeerPathKey,
    pub kind: PathChangeKind,
    pub previous_state: Option<PathState>,
    pub new_state: PathState,
    pub previous_relay_node: Option<NodeId>,
    pub new_relay_node: Option<NodeId>,
    pub previous_candidate: Option<EndpointCandidate>,
    pub new_candidate: Option<EndpointCandidate>,
    pub previous_score: Option<PathScore>,
    pub new_score: PathScore,
    pub changed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayCapability {
    pub enabled_by_policy: bool,
    pub public_endpoint: Option<SocketAddr>,
    pub admission_url: Option<String>,
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
            && self.admission_url.is_some()
            && self.e2e_only
            && self.available_capacity() > 0
            && self.max_mbps > 0
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
    #[serde(default = "default_relay_health_ttl_seconds")]
    pub relay_health_ttl_seconds: u64,
    pub pinned_roles: BTreeSet<Role>,
    pub pinned_tags: BTreeSet<Tag>,
    #[serde(default)]
    pub acl_rules: Vec<AclRule>,
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
            relay_health_ttl_seconds: default_relay_health_ttl_seconds(),
            pinned_roles,
            pinned_tags: BTreeSet::new(),
            acl_rules: Vec::new(),
        }
    }
}

fn default_relay_health_ttl_seconds() -> u64 {
    90
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclRule {
    pub id: String,
    #[serde(default)]
    pub from_roles: BTreeSet<Role>,
    pub from_tags: BTreeSet<Tag>,
    #[serde(default)]
    pub to_roles: BTreeSet<Role>,
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
        #[serde(default)]
        pub relay_capability: Option<RelayCapability>,
        pub path_state: Vec<PathRecord>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct HeartbeatResponse {
        pub accepted: bool,
        pub policy_version: u64,
        pub peer_delta_available: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RevokeTokenRequest {
        pub cluster_id: ClusterId,
        pub nonce: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RevokeTokenResponse {
        pub record: TokenLedgerRecord,
        pub status: TokenStatus,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ControlPlanePolicyResponse {
        pub cluster_id: ClusterId,
        pub vpn_pool: Ipv4Net,
        pub cluster_policy: ClusterPolicy,
        pub generated_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ControlPlaneMetricsResponse {
        pub cluster_id: ClusterId,
        pub node_count: usize,
        pub relay_candidate_count: usize,
        pub healthy_node_count: usize,
        pub degraded_node_count: usize,
        pub unhealthy_node_count: usize,
        pub path_count: usize,
        pub path_state_counts: Vec<PathStateCount>,
        pub generated_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SignalMetricsResponse {
        pub node_count: usize,
        pub relay_candidate_count: usize,
        pub nat_classification_count: usize,
        pub health_report_count: usize,
        pub healthy_node_count: usize,
        pub degraded_node_count: usize,
        pub unhealthy_node_count: usize,
        pub stale_health_report_count: usize,
        pub node_upsert_count: u64,
        pub path_negotiation_count: u64,
        pub hole_punch_plan_count: u64,
        pub relay_health_ttl_seconds: u64,
        pub generated_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct SignalPathRequest {
        pub source: NodeId,
        pub target: NodeId,
        pub source_candidates: Vec<EndpointCandidate>,
        #[serde(default)]
        pub source_nat_classification: Option<NatClassification>,
        pub desired_routes: Vec<IpNet>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct SignalNodeUpsertRequest {
        pub node: NodeRecord,
        #[serde(default)]
        pub nat_classification: Option<NatClassification>,
        #[serde(default)]
        pub health: Option<NodeHealth>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SignalNodeUpsertResponse {
        pub node: NodeRecord,
        pub registered_at: DateTime<Utc>,
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
    pub struct SignalHolePunchPlanResponse {
        pub key: PeerPathKey,
        pub source_reflexive: Option<EndpointCandidate>,
        pub target_reflexive: Option<EndpointCandidate>,
        pub start_after_millis: u64,
        pub expires_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum RelayDataplaneDropReason {
        AdmissionDenied,
        UnknownSession,
        SessionExpired,
        InvalidSessionCredential,
        RateLimited,
        MalformedFrame,
        FrameTooLarge,
        SocketError,
    }

    impl RelayDataplaneDropReason {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::AdmissionDenied => "admission_denied",
                Self::UnknownSession => "unknown_session",
                Self::SessionExpired => "session_expired",
                Self::InvalidSessionCredential => "invalid_session_credential",
                Self::RateLimited => "rate_limited",
                Self::MalformedFrame => "malformed_frame",
                Self::FrameTooLarge => "frame_too_large",
                Self::SocketError => "socket_error",
            }
        }
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RelayDataplaneMetrics {
        pub datagrams_received: u64,
        pub datagrams_forwarded: u64,
        pub datagrams_dropped: u64,
        pub datagram_bytes_received: u64,
        pub payload_bytes_forwarded: u64,
        pub datagram_bytes_dropped: u64,
        pub drops_by_reason: BTreeMap<RelayDataplaneDropReason, u64>,
    }

    impl RelayDataplaneMetrics {
        pub fn record_received(&mut self, datagram_bytes: usize) {
            self.datagrams_received = self.datagrams_received.saturating_add(1);
            self.datagram_bytes_received = self
                .datagram_bytes_received
                .saturating_add(datagram_bytes as u64);
        }

        pub fn record_forwarded(&mut self, payload_bytes: usize) {
            self.datagrams_forwarded = self.datagrams_forwarded.saturating_add(1);
            self.payload_bytes_forwarded = self
                .payload_bytes_forwarded
                .saturating_add(payload_bytes as u64);
        }

        pub fn record_drop(&mut self, reason: RelayDataplaneDropReason, datagram_bytes: usize) {
            self.datagrams_dropped = self.datagrams_dropped.saturating_add(1);
            self.datagram_bytes_dropped = self
                .datagram_bytes_dropped
                .saturating_add(datagram_bytes as u64);
            let count = self.drops_by_reason.entry(reason).or_default();
            *count = count.saturating_add(1);
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RelayStatusResponse {
        pub relay_node: NodeId,
        pub capability: RelayCapability,
        pub health: HealthState,
        #[serde(default)]
        pub dataplane: RelayDataplaneMetrics,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RelayAdmissionRequest {
        pub left: NodeId,
        pub right: NodeId,
        pub left_addr: SocketAddr,
        pub right_addr: SocketAddr,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RelayAdmissionResponse {
        pub relay_node: NodeId,
        pub session_id: String,
        pub session_token: String,
        pub expires_at: DateTime<Utc>,
        pub left: NodeId,
        pub right: NodeId,
        pub left_addr: SocketAddr,
        pub right_addr: SocketAddr,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct AgentStatusResponse {
        pub node_id: NodeId,
        pub identity_public_key: String,
        pub wireguard_public_key: String,
        pub candidate_count: usize,
        pub candidates: Vec<EndpointCandidate>,
        pub nat_classification: Option<NatClassification>,
        pub state_updated_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentStunProbeRequest {
        pub local_bind: SocketAddr,
        pub stun_server: SocketAddr,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentStunProbeResponse {
        pub candidate: EndpointCandidate,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentNatClassifyRequest {
        pub local_bind: SocketAddr,
        pub stun_servers: Vec<SocketAddr>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct AgentNatClassifyResponse {
        pub classification: NatClassification,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentPeerActivityRequest {
        pub peer: NodeId,
        #[serde(default)]
        pub pin: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentPeerActivityResponse {
        pub peer: NodeId,
        pub recorded_at: DateTime<Utc>,
        pub pinned: bool,
    }

    fn default_policy_allowed() -> bool {
        true
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct AgentPathProbeRequest {
        pub peer: NodeId,
        pub selected_state: PathState,
        #[serde(default)]
        pub selected_candidate: Option<EndpointCandidate>,
        #[serde(default)]
        pub relay_node: Option<NodeId>,
        #[serde(default)]
        pub metrics: PathMetrics,
        #[serde(default = "default_policy_allowed")]
        pub policy_allowed: bool,
        #[serde(default)]
        pub cost: u32,
        #[serde(default)]
        pub pin: bool,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct AgentPathProbeResponse {
        pub path: PathRecord,
        pub recorded_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AgentPacketFlowMatchKind {
        PeerVpnIp,
        AdvertisedRoute,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AgentPacketFlowDropReason {
        Unspecified,
        Loopback,
        Multicast,
        Broadcast,
        LinkLocal,
    }

    impl AgentPacketFlowDropReason {
        pub const ALL: [Self; 5] = [
            Self::Unspecified,
            Self::Loopback,
            Self::Multicast,
            Self::Broadcast,
            Self::LinkLocal,
        ];

        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Unspecified => "unspecified",
                Self::Loopback => "loopback",
                Self::Multicast => "multicast",
                Self::Broadcast => "broadcast",
                Self::LinkLocal => "link_local",
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AgentPacketFlowConntrackStatus {
        Unreplied,
        Assured,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AgentPacketFlowTcpState {
        SynSent,
        SynRecv,
        Established,
        FinWait,
        TimeWait,
        Close,
        CloseWait,
        LastAck,
        Listen,
        SynSent2,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AgentPacketFlowClassification {
        Unknown,
        Opening,
        Unreplied,
        Assured,
        Established,
        Closing,
        Closed,
    }

    impl AgentPacketFlowClassification {
        pub const ALL: [Self; 7] = [
            Self::Unknown,
            Self::Opening,
            Self::Unreplied,
            Self::Assured,
            Self::Established,
            Self::Closing,
            Self::Closed,
        ];

        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Unknown => "unknown",
                Self::Opening => "opening",
                Self::Unreplied => "unreplied",
                Self::Assured => "assured",
                Self::Established => "established",
                Self::Closing => "closing",
                Self::Closed => "closed",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentPacketFlowRequest {
        pub destination: IpAddr,
        #[serde(default)]
        pub pin: bool,
        #[serde(default, flatten)]
        pub observation: AgentPacketFlowObservation,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentPacketFlowObservation {
        #[serde(default)]
        pub source: Option<IpAddr>,
        #[serde(default)]
        pub protocol: Option<TransportProtocol>,
        #[serde(default)]
        pub source_port: Option<u16>,
        #[serde(default)]
        pub destination_port: Option<u16>,
        #[serde(default)]
        pub detector: Option<String>,
        #[serde(default)]
        pub conntrack_status: Vec<AgentPacketFlowConntrackStatus>,
        #[serde(default)]
        pub tcp_state: Option<AgentPacketFlowTcpState>,
    }

    impl AgentPacketFlowObservation {
        pub fn classification(&self) -> AgentPacketFlowClassification {
            if self
                .conntrack_status
                .contains(&AgentPacketFlowConntrackStatus::Unreplied)
            {
                return AgentPacketFlowClassification::Unreplied;
            }

            match self.tcp_state {
                Some(AgentPacketFlowTcpState::SynSent)
                | Some(AgentPacketFlowTcpState::SynRecv)
                | Some(AgentPacketFlowTcpState::Listen)
                | Some(AgentPacketFlowTcpState::SynSent2) => AgentPacketFlowClassification::Opening,
                Some(AgentPacketFlowTcpState::Established) => {
                    AgentPacketFlowClassification::Established
                }
                Some(AgentPacketFlowTcpState::FinWait)
                | Some(AgentPacketFlowTcpState::TimeWait)
                | Some(AgentPacketFlowTcpState::CloseWait)
                | Some(AgentPacketFlowTcpState::LastAck) => AgentPacketFlowClassification::Closing,
                Some(AgentPacketFlowTcpState::Close) => AgentPacketFlowClassification::Closed,
                None if self
                    .conntrack_status
                    .contains(&AgentPacketFlowConntrackStatus::Assured) =>
                {
                    AgentPacketFlowClassification::Assured
                }
                None => AgentPacketFlowClassification::Unknown,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentPacketFlowMatch {
        pub peer: NodeId,
        pub kind: AgentPacketFlowMatchKind,
        pub route: Option<IpNet>,
        pub pinned: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentPacketFlowResponse {
        pub destination: IpAddr,
        pub recorded_at: DateTime<Utc>,
        pub observation: AgentPacketFlowObservation,
        pub matched: Option<AgentPacketFlowMatch>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentRelayForwarderMetrics {
        pub peer: NodeId,
        pub relay_node: NodeId,
        pub relay_endpoint: SocketAddr,
        pub local_endpoint: SocketAddr,
        pub outbound_packets: u64,
        pub outbound_payload_bytes: u64,
        pub outbound_datagram_bytes: u64,
        pub inbound_packets: u64,
        pub inbound_payload_bytes: u64,
        pub last_forwarded_at: Option<DateTime<Utc>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PathStateCount {
        pub state: PathState,
        pub count: usize,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct LazyConnectMetrics {
        pub active_peer_count: usize,
        pub pinned_peer_count: usize,
        pub observed_peer_vpn_ip_count: usize,
        pub observed_route_peer_count: usize,
        pub observed_route_count: usize,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentPacketFlowDropReasonCount {
        pub reason: AgentPacketFlowDropReason,
        pub count: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentPacketFlowClassificationCount {
        pub classification: AgentPacketFlowClassification,
        pub count: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentMetricsResponse {
        pub node_id: NodeId,
        pub candidate_count: usize,
        pub path_count: usize,
        pub relay_session_count: usize,
        pub relay_admission_attempt_count: u64,
        pub relay_admission_success_count: u64,
        pub relay_admission_failure_count: u64,
        pub relay_forwarder_count: usize,
        pub relay_forwarders: Vec<AgentRelayForwarderMetrics>,
        pub path_change_event_count: usize,
        pub path_state_counts: Vec<PathStateCount>,
        pub lazy_connect: LazyConnectMetrics,
        pub path_probe_record_count: u64,
        pub peer_activity_record_count: u64,
        pub packet_flow_observation_count: u64,
        pub packet_flow_match_count: u64,
        pub packet_flow_unmatched_count: u64,
        pub packet_flow_filtered_count: u64,
        pub packet_flow_filtered_reason_counts: Vec<AgentPacketFlowDropReasonCount>,
        #[serde(default)]
        pub packet_flow_classification_counts: Vec<AgentPacketFlowClassificationCount>,
        pub generated_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct AgentPathEventsResponse {
        pub events: Vec<PathChangeEvent>,
        pub generated_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct AgentPathsResponse {
        pub paths: Vec<PathRecord>,
        pub generated_at: DateTime<Utc>,
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
            admission_url: Some("http://203.0.113.10:9580".to_string()),
            max_sessions: 10,
            active_sessions: 9,
            max_mbps: 1000,
            e2e_only: true,
        };

        assert!(relay.can_admit());
        assert_eq!(relay.available_capacity(), 1);
    }

    #[test]
    fn packet_flow_observation_classifies_conntrack_lifecycle() {
        let opening = api::AgentPacketFlowObservation {
            tcp_state: Some(api::AgentPacketFlowTcpState::SynSent),
            ..Default::default()
        };
        assert_eq!(
            opening.classification(),
            api::AgentPacketFlowClassification::Opening
        );

        let unreplied = api::AgentPacketFlowObservation {
            conntrack_status: vec![api::AgentPacketFlowConntrackStatus::Unreplied],
            tcp_state: Some(api::AgentPacketFlowTcpState::SynSent),
            ..Default::default()
        };
        assert_eq!(
            unreplied.classification(),
            api::AgentPacketFlowClassification::Unreplied
        );

        let established = api::AgentPacketFlowObservation {
            tcp_state: Some(api::AgentPacketFlowTcpState::Established),
            ..Default::default()
        };
        assert_eq!(
            established.classification(),
            api::AgentPacketFlowClassification::Established
        );

        let udp_assured = api::AgentPacketFlowObservation {
            conntrack_status: vec![api::AgentPacketFlowConntrackStatus::Assured],
            ..Default::default()
        };
        assert_eq!(
            udp_assured.classification(),
            api::AgentPacketFlowClassification::Assured
        );
    }

    #[test]
    fn nat_classification_detects_endpoint_independent_mapping() {
        let assessed_at = Utc::now();
        let classification = NatClassification::from_observations(
            std::net::SocketAddr::from(([10, 0, 0, 10], 50_000)),
            vec![
                NatProbeObservation {
                    local_addr: std::net::SocketAddr::from(([10, 0, 0, 10], 50_000)),
                    stun_server: std::net::SocketAddr::from(([198, 51, 100, 1], 3478)),
                    reflexive_addr: std::net::SocketAddr::from(([203, 0, 113, 10], 40_000)),
                    observed_at: assessed_at,
                },
                NatProbeObservation {
                    local_addr: std::net::SocketAddr::from(([10, 0, 0, 10], 50_000)),
                    stun_server: std::net::SocketAddr::from(([198, 51, 100, 2], 3478)),
                    reflexive_addr: std::net::SocketAddr::from(([203, 0, 113, 10], 40_000)),
                    observed_at: assessed_at,
                },
            ],
            assessed_at,
        );

        assert_eq!(
            classification.mapping_behavior,
            NatMappingBehavior::EndpointIndependent
        );
        assert_eq!(
            classification.filtering_behavior,
            NatFilteringBehavior::Unknown
        );
        assert_eq!(
            classification.strategy,
            NatTraversalStrategy::CoordinatedHolePunch
        );
        assert_eq!(
            classification.observed_endpoint,
            Some(std::net::SocketAddr::from(([203, 0, 113, 10], 40_000)))
        );
    }

    #[test]
    fn nat_classification_detects_address_and_port_dependent_mapping() {
        let assessed_at = Utc::now();
        let classification = NatClassification::from_observations(
            std::net::SocketAddr::from(([10, 0, 0, 10], 50_000)),
            vec![
                NatProbeObservation {
                    local_addr: std::net::SocketAddr::from(([10, 0, 0, 10], 50_000)),
                    stun_server: std::net::SocketAddr::from(([198, 51, 100, 1], 3478)),
                    reflexive_addr: std::net::SocketAddr::from(([203, 0, 113, 10], 40_000)),
                    observed_at: assessed_at,
                },
                NatProbeObservation {
                    local_addr: std::net::SocketAddr::from(([10, 0, 0, 10], 50_000)),
                    stun_server: std::net::SocketAddr::from(([198, 51, 100, 1], 3479)),
                    reflexive_addr: std::net::SocketAddr::from(([203, 0, 113, 10], 40_001)),
                    observed_at: assessed_at,
                },
            ],
            assessed_at,
        );

        assert_eq!(
            classification.mapping_behavior,
            NatMappingBehavior::AddressAndPortDependent
        );
        assert_eq!(
            classification.filtering_behavior,
            NatFilteringBehavior::Unknown
        );
        assert_eq!(
            classification.strategy,
            NatTraversalStrategy::RelayPreferred
        );
        assert_eq!(classification.observed_endpoint, None);
    }

    #[test]
    fn nat_classification_detects_no_nat_when_reflexive_matches_local() {
        let assessed_at = Utc::now();
        let local_addr = std::net::SocketAddr::from(([192, 0, 2, 10], 50_000));
        let classification = NatClassification::from_observations(
            local_addr,
            vec![NatProbeObservation {
                local_addr,
                stun_server: std::net::SocketAddr::from(([198, 51, 100, 1], 3478)),
                reflexive_addr: local_addr,
                observed_at: assessed_at,
            }],
            assessed_at,
        );

        assert_eq!(classification.mapping_behavior, NatMappingBehavior::NoNat);
        assert_eq!(
            classification.filtering_behavior,
            NatFilteringBehavior::Unknown
        );
        assert_eq!(
            classification.strategy,
            NatTraversalStrategy::DirectCandidate
        );
        assert_eq!(classification.confidence, 1.0);
    }

    #[test]
    fn nat_classification_detects_filtering_behavior_from_change_request_probes() {
        let assessed_at = Utc::now();
        let local_addr = std::net::SocketAddr::from(([10, 0, 0, 10], 50_000));
        let stun_server = std::net::SocketAddr::from(([198, 51, 100, 1], 3478));
        let other_address = std::net::SocketAddr::from(([198, 51, 100, 2], 3479));
        let classification = NatClassification::from_observations_with_filtering(
            local_addr,
            vec![
                NatProbeObservation {
                    local_addr,
                    stun_server,
                    reflexive_addr: std::net::SocketAddr::from(([203, 0, 113, 10], 40_000)),
                    observed_at: assessed_at,
                },
                NatProbeObservation {
                    local_addr,
                    stun_server: other_address,
                    reflexive_addr: std::net::SocketAddr::from(([203, 0, 113, 10], 40_000)),
                    observed_at: assessed_at,
                },
            ],
            vec![
                NatFilteringObservation {
                    local_addr,
                    stun_server,
                    probe: NatFilteringProbeKind::SameAddress,
                    response_origin: Some(stun_server),
                    other_address: Some(other_address),
                    observed_at: assessed_at,
                },
                NatFilteringObservation {
                    local_addr,
                    stun_server,
                    probe: NatFilteringProbeKind::ChangeAddressAndPort,
                    response_origin: None,
                    other_address: Some(other_address),
                    observed_at: assessed_at,
                },
                NatFilteringObservation {
                    local_addr,
                    stun_server,
                    probe: NatFilteringProbeKind::ChangePort,
                    response_origin: Some(other_address),
                    other_address: Some(other_address),
                    observed_at: assessed_at,
                },
            ],
            assessed_at,
        );

        assert_eq!(
            classification.mapping_behavior,
            NatMappingBehavior::EndpointIndependent
        );
        assert_eq!(
            classification.filtering_behavior,
            NatFilteringBehavior::AddressDependent
        );
        assert_eq!(
            classification.strategy,
            NatTraversalStrategy::CoordinatedHolePunch
        );
        assert_eq!(classification.filtering_observations.len(), 3);
        assert!(classification.confidence > 0.5);
    }

    #[test]
    fn address_and_port_dependent_filtering_prefers_relay() {
        let assessed_at = Utc::now();
        let local_addr = std::net::SocketAddr::from(([10, 0, 0, 10], 50_000));
        let stun_server = std::net::SocketAddr::from(([198, 51, 100, 1], 3478));
        let classification = NatClassification::from_observations_with_filtering(
            local_addr,
            vec![
                NatProbeObservation {
                    local_addr,
                    stun_server,
                    reflexive_addr: std::net::SocketAddr::from(([203, 0, 113, 10], 40_000)),
                    observed_at: assessed_at,
                },
                NatProbeObservation {
                    local_addr,
                    stun_server: std::net::SocketAddr::from(([198, 51, 100, 2], 3478)),
                    reflexive_addr: std::net::SocketAddr::from(([203, 0, 113, 10], 40_000)),
                    observed_at: assessed_at,
                },
            ],
            vec![
                NatFilteringObservation {
                    local_addr,
                    stun_server,
                    probe: NatFilteringProbeKind::SameAddress,
                    response_origin: Some(stun_server),
                    other_address: Some(std::net::SocketAddr::from(([198, 51, 100, 2], 3479))),
                    observed_at: assessed_at,
                },
                NatFilteringObservation {
                    local_addr,
                    stun_server,
                    probe: NatFilteringProbeKind::ChangeAddressAndPort,
                    response_origin: None,
                    other_address: Some(std::net::SocketAddr::from(([198, 51, 100, 2], 3479))),
                    observed_at: assessed_at,
                },
                NatFilteringObservation {
                    local_addr,
                    stun_server,
                    probe: NatFilteringProbeKind::ChangePort,
                    response_origin: None,
                    other_address: Some(std::net::SocketAddr::from(([198, 51, 100, 2], 3479))),
                    observed_at: assessed_at,
                },
            ],
            assessed_at,
        );

        assert_eq!(
            classification.filtering_behavior,
            NatFilteringBehavior::AddressAndPortDependent
        );
        assert_eq!(
            classification.strategy,
            NatTraversalStrategy::RelayPreferred
        );
    }

    #[test]
    fn signal_requests_default_missing_nat_classification_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path_request: api::SignalPathRequest = serde_json::from_value(serde_json::json!({
            "source": "node-a",
            "target": "node-b",
            "source_candidates": [],
            "desired_routes": [],
        }))?;
        assert!(path_request.source_nat_classification.is_none());

        let node = NodeRecord {
            node_id: NodeId::from_string("node-a"),
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 2))),
            identity_public_key: "identity".to_string(),
            wireguard_public_key: "wireguard".to_string(),
            role: Role::edge(),
            tags: Default::default(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        };
        let upsert_request: api::SignalNodeUpsertRequest =
            serde_json::from_value(serde_json::json!({ "node": node }))?;
        assert!(upsert_request.nat_classification.is_none());
        assert!(upsert_request.health.is_none());

        Ok(())
    }
}
