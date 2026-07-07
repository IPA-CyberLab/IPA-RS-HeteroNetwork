use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use chrono::{DateTime, Utc};
use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod ebpf;

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

    pub fn route_provider() -> Self {
        Self::from_string("route-provider")
    }

    pub fn kubernetes_control_plane() -> Self {
        Self::from_string("kubernetes-control-plane")
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

impl EndpointCandidate {
    pub fn validate_kind_address(&self) -> Result<(), &'static str> {
        match self.kind {
            EndpointCandidateKind::Ipv6 if !self.addr.is_ipv6() => {
                Err("IPv6 candidates must use an IPv6 socket address")
            }
            _ => Ok(()),
        }
    }
}

pub fn endpoint_addr_is_usable(addr: SocketAddr) -> bool {
    if addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast() {
        return false;
    }

    match addr.ip() {
        IpAddr::V4(ip) => !ip.is_broadcast(),
        IpAddr::V6(_) => true,
    }
}

pub fn http_url_is_usable_endpoint(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };

    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    let Some(host) = url.host() else {
        return false;
    };
    let Some(port) = url.port_or_known_default() else {
        return false;
    };
    if port == 0 {
        return false;
    }

    match host {
        url::Host::Domain(_) => true,
        url::Host::Ipv4(ip) => endpoint_addr_is_usable(SocketAddr::new(IpAddr::V4(ip), port)),
        url::Host::Ipv6(ip) => endpoint_addr_is_usable(SocketAddr::new(IpAddr::V6(ip), port)),
    }
}

pub fn relay_admission_url_is_usable(value: &str) -> bool {
    http_url_is_usable_endpoint(value)
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

impl NatTraversalStrategy {
    pub const ALL: [Self; 4] = [
        Self::DirectCandidate,
        Self::CoordinatedHolePunch,
        Self::RelayPreferred,
        Self::InsufficientData,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectCandidate => "direct_candidate",
            Self::CoordinatedHolePunch => "coordinated_hole_punch",
            Self::RelayPreferred => "relay_preferred",
            Self::InsufficientData => "insufficient_data",
        }
    }
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
        NatFilteringBehavior::EndpointIndependent | NatFilteringBehavior::AddressDependent => {
            NatTraversalStrategy::CoordinatedHolePunch
        }
        NatFilteringBehavior::Unknown => NatTraversalStrategy::InsufficientData,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMetricsValidationError {
    field: &'static str,
    message: &'static str,
}

impl PathMetricsValidationError {
    fn new(field: &'static str, message: &'static str) -> Self {
        Self { field, message }
    }

    pub fn field(&self) -> &'static str {
        self.field
    }
}

impl Display for PathMetricsValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "path metric {} {}", self.field, self.message)
    }
}

impl std::error::Error for PathMetricsValidationError {}

impl PathMetrics {
    pub fn validate(&self) -> Result<(), PathMetricsValidationError> {
        validate_optional_non_negative_metric("latency_ms", self.latency_ms)?;
        validate_optional_non_negative_metric("jitter_ms", self.jitter_ms)?;
        validate_optional_unit_metric("relay_load", self.relay_load)?;
        validate_unit_metric("stability", self.stability)?;
        Ok(())
    }
}

fn validate_optional_non_negative_metric(
    field: &'static str,
    value: Option<f32>,
) -> Result<(), PathMetricsValidationError> {
    if let Some(value) = value {
        if !value.is_finite() || value < 0.0 {
            return Err(PathMetricsValidationError::new(
                field,
                "must be a finite non-negative value",
            ));
        }
    }
    Ok(())
}

fn validate_optional_unit_metric(
    field: &'static str,
    value: Option<f32>,
) -> Result<(), PathMetricsValidationError> {
    if let Some(value) = value {
        validate_unit_metric(field, value)?;
    }
    Ok(())
}

fn validate_unit_metric(field: &'static str, value: f32) -> Result<(), PathMetricsValidationError> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(PathMetricsValidationError::new(
            field,
            "must be a finite value between 0 and 1",
        ));
    }
    Ok(())
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
            value -= bounded_metric(latency_ms, 0.0, 500.0, 500.0) / 10.0;
            reasons.push(format!("latency_ms={latency_ms:.1}"));
        }
        if metrics.loss_ppm > 0 {
            value -= (metrics.loss_ppm as f32 / 10_000.0).min(50.0);
            reasons.push(format!("loss_ppm={}", metrics.loss_ppm));
        }
        if let Some(jitter_ms) = metrics.jitter_ms {
            value -= bounded_metric(jitter_ms, 0.0, 200.0, 200.0) / 20.0;
            reasons.push(format!("jitter_ms={jitter_ms:.1}"));
        }
        if let Some(relay_load) = metrics.relay_load {
            value -= bounded_metric(relay_load, 0.0, 1.0, 1.0) * 20.0;
            reasons.push(format!("relay_load={relay_load:.2}"));
        }
        let stability = bounded_metric(metrics.stability, 0.0, 1.0, 0.0);
        value += stability * 15.0;
        reasons.push(format!("stability={stability:.2}"));
        value -= cost.min(10_000) as f32 / 100.0;
        reasons.push(format!("cost={cost}"));

        Self { value, reasons }
    }
}

fn bounded_metric(value: f32, min: f32, max: f32, fallback: f32) -> f32 {
    if value.is_finite() {
        value.clamp(min, max)
    } else {
        fallback
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
            && self.public_endpoint.is_some_and(endpoint_addr_is_usable)
            && self
                .admission_url
                .as_deref()
                .is_some_and(relay_admission_url_is_usable)
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
    #[serde(default = "default_endpoint_candidate_ttl_seconds")]
    pub endpoint_candidate_ttl_seconds: u64,
    #[serde(default = "default_path_state_ttl_seconds")]
    pub path_state_ttl_seconds: u64,
    #[serde(default = "default_nat_classification_ttl_seconds")]
    pub nat_classification_ttl_seconds: u64,
    #[serde(default = "default_nat_classification_min_confidence_percent")]
    pub nat_classification_min_confidence_percent: u8,
    pub pinned_roles: BTreeSet<Role>,
    pub pinned_tags: BTreeSet<Tag>,
    #[serde(default)]
    pub acl_rules: Vec<AclRule>,
}

impl Default for ClusterPolicy {
    fn default() -> Self {
        let mut pinned_roles = BTreeSet::new();
        pinned_roles.insert(Role::control_plane());
        let mut pinned_tags = BTreeSet::new();
        pinned_tags.insert(Tag::route_provider());
        pinned_tags.insert(Tag::kubernetes_control_plane());
        Self {
            allow_ipv6_direct: true,
            allow_nat_traversal: true,
            allow_relay_fallback: true,
            idle_timeout_seconds: 300,
            relay_health_ttl_seconds: default_relay_health_ttl_seconds(),
            endpoint_candidate_ttl_seconds: default_endpoint_candidate_ttl_seconds(),
            path_state_ttl_seconds: default_path_state_ttl_seconds(),
            nat_classification_ttl_seconds: default_nat_classification_ttl_seconds(),
            nat_classification_min_confidence_percent:
                default_nat_classification_min_confidence_percent(),
            pinned_roles,
            pinned_tags,
            acl_rules: Vec::new(),
        }
    }
}

fn default_relay_health_ttl_seconds() -> u64 {
    90
}

fn default_endpoint_candidate_ttl_seconds() -> u64 {
    120
}

fn default_path_state_ttl_seconds() -> u64 {
    600
}

fn default_nat_classification_ttl_seconds() -> u64 {
    300
}

fn default_nat_classification_min_confidence_percent() -> u8 {
    50
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
    IpInIp,
    Tcp,
    Udp,
    Sctp,
    Icmp,
    Ipv6Encap,
    Gre,
    Esp,
    Ah,
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenLedgerMetrics {
    pub issued_count: u64,
    pub active_count: u64,
    pub revoked_count: u64,
    pub expired_count: u64,
    pub exhausted_count: u64,
    pub use_count: u64,
}

impl TokenLedgerMetrics {
    pub fn observe_record(&mut self, record: &TokenLedgerRecord, now: DateTime<Utc>) {
        self.issued_count = self.issued_count.saturating_add(1);
        self.use_count = self.use_count.saturating_add(record.uses as u64);
        match record.status(now) {
            TokenStatus::Active => self.active_count = self.active_count.saturating_add(1),
            TokenStatus::Revoked => self.revoked_count = self.revoked_count.saturating_add(1),
            TokenStatus::Expired => self.expired_count = self.expired_count.saturating_add(1),
            TokenStatus::Exhausted => {
                self.exhausted_count = self.exhausted_count.saturating_add(1);
            }
        }
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
    pub struct ControlPlanePathsResponse {
        pub cluster_id: ClusterId,
        pub node_id: NodeId,
        pub paths: Vec<PathRecord>,
        #[serde(default)]
        pub stale_path_count: usize,
        #[serde(default = "super::default_path_state_ttl_seconds")]
        pub path_state_ttl_seconds: u64,
        pub generated_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct NodeRequestSignature {
        pub signed_at: DateTime<Utc>,
        pub signature: String,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct HeartbeatSignaturePayload {
        pub node_id: NodeId,
        pub health: NodeHealth,
        pub candidates: Vec<EndpointCandidate>,
        pub relay_capability: Option<RelayCapability>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub routes: Option<Vec<Route>>,
        pub path_state: Vec<PathRecord>,
        pub signed_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct WireGuardKeyRotationSignaturePayload {
        pub node_id: NodeId,
        pub previous_wireguard_public_key: String,
        pub next_wireguard_public_key: String,
        pub signed_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct HeartbeatRequest {
        pub node_id: NodeId,
        pub health: NodeHealth,
        pub candidates: Vec<EndpointCandidate>,
        #[serde(default)]
        pub relay_capability: Option<RelayCapability>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub routes: Option<Vec<Route>>,
        pub path_state: Vec<PathRecord>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub node_signature: Option<NodeRequestSignature>,
    }

    impl HeartbeatRequest {
        pub fn signature_payload(&self, signed_at: DateTime<Utc>) -> HeartbeatSignaturePayload {
            HeartbeatSignaturePayload {
                node_id: self.node_id.clone(),
                health: self.health.clone(),
                candidates: self.candidates.clone(),
                relay_capability: self.relay_capability.clone(),
                routes: self.routes.clone(),
                path_state: self.path_state.clone(),
                signed_at,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct RotateWireGuardKeyRequest {
        pub node_id: NodeId,
        pub previous_wireguard_public_key: String,
        pub next_wireguard_public_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub node_signature: Option<NodeRequestSignature>,
    }

    impl RotateWireGuardKeyRequest {
        pub fn signature_payload(
            &self,
            signed_at: DateTime<Utc>,
        ) -> WireGuardKeyRotationSignaturePayload {
            WireGuardKeyRotationSignaturePayload {
                node_id: self.node_id.clone(),
                previous_wireguard_public_key: self.previous_wireguard_public_key.clone(),
                next_wireguard_public_key: self.next_wireguard_public_key.clone(),
                signed_at,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct RotateWireGuardKeyResponse {
        pub node: NodeRecord,
        pub peer_map: PeerMap,
        pub relay_map: RelayMap,
        pub rotated_at: DateTime<Utc>,
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
        #[serde(default)]
        pub stale_endpoint_candidate_count: usize,
        #[serde(default)]
        pub vpn_pool_total_count: u64,
        #[serde(default)]
        pub vpn_pool_allocated_count: u64,
        #[serde(default)]
        pub vpn_pool_available_count: u64,
        #[serde(default)]
        pub token_ledger_issued_count: u64,
        #[serde(default)]
        pub token_ledger_active_count: u64,
        #[serde(default)]
        pub token_ledger_revoked_count: u64,
        #[serde(default)]
        pub token_ledger_expired_count: u64,
        #[serde(default)]
        pub token_ledger_exhausted_count: u64,
        #[serde(default)]
        pub token_ledger_use_count: u64,
        #[serde(default)]
        pub peer_map_candidate_count: usize,
        #[serde(default)]
        pub peer_map_visible_count: usize,
        #[serde(default)]
        pub peer_map_acl_denied_count: usize,
        #[serde(default)]
        pub peer_map_route_candidate_count: usize,
        #[serde(default)]
        pub peer_map_route_visible_count: usize,
        #[serde(default)]
        pub peer_map_route_acl_denied_count: usize,
        #[serde(default)]
        pub stale_path_count: usize,
        pub path_count: usize,
        pub path_state_counts: Vec<PathStateCount>,
        #[serde(default = "super::default_endpoint_candidate_ttl_seconds")]
        pub endpoint_candidate_ttl_seconds: u64,
        #[serde(default = "super::default_path_state_ttl_seconds")]
        pub path_state_ttl_seconds: u64,
        pub generated_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SignalMetricsResponse {
        pub node_count: usize,
        pub relay_candidate_count: usize,
        pub nat_classification_count: usize,
        #[serde(default)]
        pub stale_nat_classification_count: usize,
        #[serde(default)]
        pub fresh_low_confidence_nat_classification_count: usize,
        #[serde(default)]
        pub fresh_nat_classification_strategy_counts: Vec<NatTraversalStrategyCount>,
        pub health_report_count: usize,
        pub healthy_node_count: usize,
        pub degraded_node_count: usize,
        pub unhealthy_node_count: usize,
        pub stale_health_report_count: usize,
        #[serde(default)]
        pub stale_endpoint_candidate_count: usize,
        pub node_upsert_count: u64,
        pub path_negotiation_count: u64,
        #[serde(default)]
        pub path_acl_denied_count: u64,
        #[serde(default)]
        pub relay_candidate_acl_denied_count: u64,
        #[serde(default)]
        pub path_negotiation_state_counts: Vec<PathStateCount>,
        pub hole_punch_plan_count: u64,
        #[serde(default)]
        pub hole_punch_acl_denied_count: u64,
        #[serde(default)]
        pub hole_punch_nat_suppressed_count: u64,
        #[serde(default)]
        pub hole_punch_nat_suppressed_strategy_counts: Vec<NatTraversalStrategyCount>,
        pub relay_health_ttl_seconds: u64,
        #[serde(default = "super::default_endpoint_candidate_ttl_seconds")]
        pub endpoint_candidate_ttl_seconds: u64,
        #[serde(default = "super::default_nat_classification_ttl_seconds")]
        pub nat_classification_ttl_seconds: u64,
        #[serde(default = "super::default_nat_classification_min_confidence_percent")]
        pub nat_classification_min_confidence_percent: u8,
        pub generated_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct StunMetricsResponse {
        pub listen: SocketAddr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alternate_listen: Option<SocketAddr>,
        pub binding_request_count: u64,
        pub binding_response_count: u64,
        pub invalid_packet_count: u64,
        pub socket_receive_error_count: u64,
        pub socket_send_error_count: u64,
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
        pub const ALL: [Self; 8] = [
            Self::AdmissionDenied,
            Self::UnknownSession,
            Self::SessionExpired,
            Self::InvalidSessionCredential,
            Self::RateLimited,
            Self::MalformedFrame,
            Self::FrameTooLarge,
            Self::SocketError,
        ];

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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum RelayAdmissionFailureReason {
        Unauthorized,
        InvalidAdmissionRequest,
        AdmissionDenied,
        NodeSessionLimitExceeded,
        RateLimited,
        InvalidSessionCredential,
        SocketError,
        InternalError,
    }

    impl RelayAdmissionFailureReason {
        pub const ALL: [Self; 8] = [
            Self::Unauthorized,
            Self::InvalidAdmissionRequest,
            Self::AdmissionDenied,
            Self::NodeSessionLimitExceeded,
            Self::RateLimited,
            Self::InvalidSessionCredential,
            Self::SocketError,
            Self::InternalError,
        ];

        pub fn as_str(self) -> &'static str {
            match self {
                Self::Unauthorized => "unauthorized",
                Self::InvalidAdmissionRequest => "invalid_admission_request",
                Self::AdmissionDenied => "admission_denied",
                Self::NodeSessionLimitExceeded => "node_session_limit_exceeded",
                Self::RateLimited => "rate_limited",
                Self::InvalidSessionCredential => "invalid_session_credential",
                Self::SocketError => "socket_error",
                Self::InternalError => "internal_error",
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
        pub admission_attempt_count: u64,
        #[serde(default)]
        pub admission_success_count: u64,
        #[serde(default)]
        pub admission_failure_count: u64,
        #[serde(default)]
        pub admission_failures_by_reason: BTreeMap<RelayAdmissionFailureReason, u64>,
        #[serde(default)]
        pub max_sessions_per_node: Option<u32>,
        #[serde(default)]
        pub dataplane: RelayDataplaneMetrics,
        #[serde(default = "Utc::now")]
        pub generated_at: DateTime<Utc>,
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
        #[serde(default)]
        pub userspace_wireguard_process: Option<AgentManagedProcessStatus>,
        pub state_updated_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
    pub struct AgentWireGuardKeyRotationRequest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub control_plane_url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct AgentWireGuardKeyRotationResponse {
        pub node_id: NodeId,
        pub previous_wireguard_public_key: String,
        pub next_wireguard_public_key: String,
        pub control_plane_node: NodeRecord,
        pub rotated_at: DateTime<Utc>,
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
        NoOverlayMatch,
        InconsistentTransportMetadata,
    }

    impl AgentPacketFlowDropReason {
        pub const ALL: [Self; 7] = [
            Self::Unspecified,
            Self::Loopback,
            Self::Multicast,
            Self::Broadcast,
            Self::LinkLocal,
            Self::NoOverlayMatch,
            Self::InconsistentTransportMetadata,
        ];

        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Unspecified => "unspecified",
                Self::Loopback => "loopback",
                Self::Multicast => "multicast",
                Self::Broadcast => "broadcast",
                Self::LinkLocal => "link_local",
                Self::NoOverlayMatch => "no_overlay_match",
                Self::InconsistentTransportMetadata => "inconsistent_transport_metadata",
            }
        }
    }

    pub fn packet_flow_destination_drop_reason(
        destination: IpAddr,
    ) -> Option<AgentPacketFlowDropReason> {
        if destination.is_unspecified() {
            return Some(AgentPacketFlowDropReason::Unspecified);
        }
        if destination.is_loopback() {
            return Some(AgentPacketFlowDropReason::Loopback);
        }
        if destination.is_multicast() {
            return Some(AgentPacketFlowDropReason::Multicast);
        }
        match destination {
            IpAddr::V4(address) if address == Ipv4Addr::BROADCAST => {
                Some(AgentPacketFlowDropReason::Broadcast)
            }
            IpAddr::V4(address) if address.is_link_local() => {
                Some(AgentPacketFlowDropReason::LinkLocal)
            }
            IpAddr::V6(address) if address.is_unicast_link_local() => {
                Some(AgentPacketFlowDropReason::LinkLocal)
            }
            _ => None,
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AgentPacketFlowApplication {
        Unknown,
        Dns,
        Dhcp,
        Http,
        Https,
        Ssh,
        Ldap,
        Smb,
        Nfs,
        Rdp,
        Kerberos,
        Ntp,
        Radius,
        Tacacs,
        Bgp,
        Bfd,
        KubernetesApi,
        Etcd,
        ZooKeeper,
        Consul,
        Vault,
        Nomad,
        Postgres,
        Mysql,
        MsSql,
        Oracle,
        ClickHouse,
        InfluxDb,
        Redis,
        Memcached,
        Prometheus,
        OpenTelemetry,
        Syslog,
        Snmp,
        Jaeger,
        Loki,
        Tempo,
        Zipkin,
        Grpc,
        Kafka,
        Nats,
        Mqtt,
        Amqp,
        Cassandra,
        MongoDb,
        Elasticsearch,
        Ike,
        Ipsec,
        IpTunnel,
        Gre,
        Vxlan,
        Geneve,
        WireGuard,
        Icmp,
    }

    impl AgentPacketFlowApplication {
        pub const ALL: [Self; 54] = [
            Self::Unknown,
            Self::Dns,
            Self::Dhcp,
            Self::Http,
            Self::Https,
            Self::Ssh,
            Self::Ldap,
            Self::Smb,
            Self::Nfs,
            Self::Rdp,
            Self::Kerberos,
            Self::Ntp,
            Self::Radius,
            Self::Tacacs,
            Self::Bgp,
            Self::Bfd,
            Self::KubernetesApi,
            Self::Etcd,
            Self::ZooKeeper,
            Self::Consul,
            Self::Vault,
            Self::Nomad,
            Self::Postgres,
            Self::Mysql,
            Self::MsSql,
            Self::Oracle,
            Self::ClickHouse,
            Self::InfluxDb,
            Self::Redis,
            Self::Memcached,
            Self::Prometheus,
            Self::OpenTelemetry,
            Self::Syslog,
            Self::Snmp,
            Self::Jaeger,
            Self::Loki,
            Self::Tempo,
            Self::Zipkin,
            Self::Grpc,
            Self::Kafka,
            Self::Nats,
            Self::Mqtt,
            Self::Amqp,
            Self::Cassandra,
            Self::MongoDb,
            Self::Elasticsearch,
            Self::Ike,
            Self::Ipsec,
            Self::IpTunnel,
            Self::Gre,
            Self::Vxlan,
            Self::Geneve,
            Self::WireGuard,
            Self::Icmp,
        ];

        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Unknown => "unknown",
                Self::Dns => "dns",
                Self::Dhcp => "dhcp",
                Self::Http => "http",
                Self::Https => "https",
                Self::Ssh => "ssh",
                Self::Ldap => "ldap",
                Self::Smb => "smb",
                Self::Nfs => "nfs",
                Self::Rdp => "rdp",
                Self::Kerberos => "kerberos",
                Self::Ntp => "ntp",
                Self::Radius => "radius",
                Self::Tacacs => "tacacs",
                Self::Bgp => "bgp",
                Self::Bfd => "bfd",
                Self::KubernetesApi => "kubernetes_api",
                Self::Etcd => "etcd",
                Self::ZooKeeper => "zookeeper",
                Self::Consul => "consul",
                Self::Vault => "vault",
                Self::Nomad => "nomad",
                Self::Postgres => "postgres",
                Self::Mysql => "mysql",
                Self::MsSql => "mssql",
                Self::Oracle => "oracle",
                Self::ClickHouse => "clickhouse",
                Self::InfluxDb => "influxdb",
                Self::Redis => "redis",
                Self::Memcached => "memcached",
                Self::Prometheus => "prometheus",
                Self::OpenTelemetry => "opentelemetry",
                Self::Syslog => "syslog",
                Self::Snmp => "snmp",
                Self::Jaeger => "jaeger",
                Self::Loki => "loki",
                Self::Tempo => "tempo",
                Self::Zipkin => "zipkin",
                Self::Grpc => "grpc",
                Self::Kafka => "kafka",
                Self::Nats => "nats",
                Self::Mqtt => "mqtt",
                Self::Amqp => "amqp",
                Self::Cassandra => "cassandra",
                Self::MongoDb => "mongodb",
                Self::Elasticsearch => "elasticsearch",
                Self::Ike => "ike",
                Self::Ipsec => "ipsec",
                Self::IpTunnel => "ip_tunnel",
                Self::Gre => "gre",
                Self::Vxlan => "vxlan",
                Self::Geneve => "geneve",
                Self::WireGuard => "wireguard",
                Self::Icmp => "icmp",
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

    pub const PACKET_FLOW_DETECTOR_MAX_BYTES: usize = 64;
    pub const PACKET_FLOW_CONNTRACK_STATUS_MAX_FLAGS: usize = 8;
    pub const PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES: usize = 128;

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
        #[serde(default, deserialize_with = "deserialize_packet_flow_detector")]
        pub detector: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<AgentPacketFlowApplication>,
        #[serde(
            default,
            skip_serializing_if = "Vec::is_empty",
            deserialize_with = "deserialize_packet_flow_payload_prefix"
        )]
        pub payload_prefix: Vec<u8>,
        #[serde(default, deserialize_with = "deserialize_packet_flow_conntrack_status")]
        pub conntrack_status: Vec<AgentPacketFlowConntrackStatus>,
        #[serde(default)]
        pub tcp_state: Option<AgentPacketFlowTcpState>,
    }

    impl AgentPacketFlowObservation {
        pub fn validate_transport_metadata(&self) -> Result<(), String> {
            if let Some(detector) = self.detector.as_deref() {
                validate_packet_flow_detector(detector)?;
            }
            if let Some(source) = self.source {
                validate_packet_flow_source(source)?;
            }
            if self.payload_prefix.len() > PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES {
                return Err(format!(
                    "packet-flow payload_prefix exceeds {PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES} bytes"
                ));
            }
            if self.conntrack_status.len() > PACKET_FLOW_CONNTRACK_STATUS_MAX_FLAGS {
                return Err(format!(
                    "packet-flow conntrack_status exceeds {PACKET_FLOW_CONNTRACK_STATUS_MAX_FLAGS} flags"
                ));
            }
            if self
                .conntrack_status
                .windows(2)
                .any(|window| window[0] >= window[1])
            {
                return Err(
                    "packet-flow conntrack_status must be sorted and deduplicated".to_string(),
                );
            }
            if self.protocol == Some(TransportProtocol::Any) {
                return Err(
                    "packet-flow protocol must be a concrete transport protocol, not any"
                        .to_string(),
                );
            }
            if let Some(application) = self.application {
                validate_packet_flow_application_hint(self.protocol, application)?;
            }
            if self.source_port == Some(0) || self.destination_port == Some(0) {
                return Err("packet-flow port metadata must use nonzero ports".to_string());
            }
            if self.protocol != Some(TransportProtocol::Tcp) && self.tcp_state.is_some() {
                return Err("packet-flow TCP state requires TCP protocol".to_string());
            }

            let protocol_has_ports = matches!(
                self.protocol,
                Some(TransportProtocol::Tcp | TransportProtocol::Udp | TransportProtocol::Sctp)
            );
            if !protocol_has_ports
                && (self.source_port.is_some() || self.destination_port.is_some())
            {
                return Err(
                    "packet-flow port metadata requires TCP, UDP, or SCTP protocol".to_string(),
                );
            }

            Ok(())
        }

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

        pub fn application(&self) -> AgentPacketFlowApplication {
            if let Some(application) = self.application {
                return application;
            }
            if self.protocol == Some(TransportProtocol::Icmp) {
                return AgentPacketFlowApplication::Icmp;
            }
            if matches!(
                self.protocol,
                Some(TransportProtocol::Esp | TransportProtocol::Ah)
            ) {
                return AgentPacketFlowApplication::Ipsec;
            }
            if matches!(
                self.protocol,
                Some(TransportProtocol::IpInIp | TransportProtocol::Ipv6Encap)
            ) {
                return AgentPacketFlowApplication::IpTunnel;
            }
            if self.protocol == Some(TransportProtocol::Gre) {
                return AgentPacketFlowApplication::Gre;
            }
            if self.involves_port(51820) && protocol_is(self.protocol, TransportProtocol::Udp) {
                return AgentPacketFlowApplication::WireGuard;
            }
            let payload_application = self.payload_prefix_application();
            if let Some(application) = payload_application {
                if self.payload_prefix_application_overrides_port(application) {
                    return application;
                }
            }
            if self.involves_port(6443) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::KubernetesApi;
            }
            if (self.involves_port(2379) || self.involves_port(2380))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Etcd;
            }
            if (self.involves_port(2181)
                || self.involves_port(2182)
                || self.involves_port(2888)
                || self.involves_port(3888))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::ZooKeeper;
            }
            if (self.involves_port(8300)
                || self.involves_port(8500)
                || self.involves_port(8501)
                || self.involves_port(8502))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Consul;
            }
            if (self.involves_port(8301) || self.involves_port(8302))
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp) | Some(TransportProtocol::Udp)
                )
            {
                return AgentPacketFlowApplication::Consul;
            }
            if (self.involves_port(8200) || self.involves_port(8201))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Vault;
            }
            if (self.involves_port(4646) || self.involves_port(4647))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Nomad;
            }
            if self.involves_port(4648)
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp) | Some(TransportProtocol::Udp)
                )
            {
                return AgentPacketFlowApplication::Nomad;
            }
            if (self.involves_port(53) || self.involves_port(853))
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp) | Some(TransportProtocol::Udp)
                )
            {
                return AgentPacketFlowApplication::Dns;
            }
            if (self.involves_port(67)
                || self.involves_port(68)
                || self.involves_port(546)
                || self.involves_port(547))
                && protocol_is(self.protocol, TransportProtocol::Udp)
            {
                return AgentPacketFlowApplication::Dhcp;
            }
            if (self.involves_port(4789) || self.involves_port(8472))
                && protocol_is(self.protocol, TransportProtocol::Udp)
            {
                return AgentPacketFlowApplication::Vxlan;
            }
            if self.involves_port(6081) && protocol_is(self.protocol, TransportProtocol::Udp) {
                return AgentPacketFlowApplication::Geneve;
            }
            if self.involves_port(80) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Http;
            }
            if self.involves_port(443) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Https;
            }
            if self.involves_port(22) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Ssh;
            }
            if (self.involves_port(389) || self.involves_port(636))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Ldap;
            }
            if self.involves_port(445) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Smb;
            }
            if self.involves_port(2049)
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp) | Some(TransportProtocol::Udp)
                )
            {
                return AgentPacketFlowApplication::Nfs;
            }
            if self.involves_port(3389) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Rdp;
            }
            if (self.involves_port(88) || self.involves_port(464))
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp) | Some(TransportProtocol::Udp)
                )
            {
                return AgentPacketFlowApplication::Kerberos;
            }
            if self.involves_port(123) && protocol_is(self.protocol, TransportProtocol::Udp) {
                return AgentPacketFlowApplication::Ntp;
            }
            if self.involves_port(4460) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Ntp;
            }
            if (self.involves_port(1812)
                || self.involves_port(1813)
                || self.involves_port(3799)
                || self.involves_port(1645)
                || self.involves_port(1646)
                || self.involves_port(2083))
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp) | Some(TransportProtocol::Udp)
                )
            {
                return AgentPacketFlowApplication::Radius;
            }
            if self.involves_port(49) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Tacacs;
            }
            if self.involves_port(179) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Bgp;
            }
            if (self.involves_port(3784) || self.involves_port(3785) || self.involves_port(4784))
                && protocol_is(self.protocol, TransportProtocol::Udp)
            {
                return AgentPacketFlowApplication::Bfd;
            }
            if self.involves_port(5432) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Postgres;
            }
            if self.involves_port(3306) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Mysql;
            }
            if self.involves_port(1433) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::MsSql;
            }
            if (self.involves_port(1521) || self.involves_port(2484))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Oracle;
            }
            if (self.involves_port(8123)
                || self.involves_port(9000)
                || self.involves_port(9009)
                || self.involves_port(9010)
                || self.involves_port(9011)
                || self.involves_port(9440))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::ClickHouse;
            }
            if self.involves_port(8086) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::InfluxDb;
            }
            if self.involves_port(6379) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Redis;
            }
            if self.involves_port(11211)
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp) | Some(TransportProtocol::Udp)
                )
            {
                return AgentPacketFlowApplication::Memcached;
            }
            if self.involves_port(9090) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Prometheus;
            }
            if (self.involves_port(4317) || self.involves_port(4318))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::OpenTelemetry;
            }
            if self.involves_port(514)
                && matches!(self.protocol, None | Some(TransportProtocol::Udp))
            {
                return AgentPacketFlowApplication::Syslog;
            }
            if self.involves_port(601)
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp) | Some(TransportProtocol::Udp)
                )
            {
                return AgentPacketFlowApplication::Syslog;
            }
            if self.involves_port(6514)
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp) | Some(TransportProtocol::Udp)
                )
            {
                return AgentPacketFlowApplication::Syslog;
            }
            if (self.involves_port(161)
                || self.involves_port(162)
                || self.involves_port(10161)
                || self.involves_port(10162))
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp) | Some(TransportProtocol::Udp)
                )
            {
                return AgentPacketFlowApplication::Snmp;
            }
            if (self.involves_port(5778)
                || self.involves_port(14250)
                || self.involves_port(14268)
                || self.involves_port(14269)
                || self.involves_port(16686))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Jaeger;
            }
            if (self.involves_port(6831) || self.involves_port(6832))
                && matches!(self.protocol, None | Some(TransportProtocol::Udp))
            {
                return AgentPacketFlowApplication::Jaeger;
            }
            if (self.involves_port(3100) || self.involves_port(9095))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Loki;
            }
            if self.involves_port(3200) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Tempo;
            }
            if self.involves_port(9411) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Zipkin;
            }
            if self.involves_port(50051) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Grpc;
            }
            if (self.involves_port(9092) || self.involves_port(9093))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Kafka;
            }
            if self.involves_port(4222) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Nats;
            }
            if (self.involves_port(1883) || self.involves_port(8883))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Mqtt;
            }
            if (self.involves_port(5671) || self.involves_port(5672))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Amqp;
            }
            if self.involves_port(9042) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Cassandra;
            }
            if self.involves_port(27017) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::MongoDb;
            }
            if (self.involves_port(9200) || self.involves_port(9300))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Elasticsearch;
            }
            if (self.involves_port(500) || self.involves_port(4500))
                && protocol_is(self.protocol, TransportProtocol::Udp)
            {
                return AgentPacketFlowApplication::Ike;
            }
            if let Some(application) = payload_application {
                return application;
            }
            AgentPacketFlowApplication::Unknown
        }

        fn involves_port(&self, port: u16) -> bool {
            self.source_port == Some(port) || self.destination_port == Some(port)
        }

        fn payload_prefix_application_overrides_port(
            &self,
            application: AgentPacketFlowApplication,
        ) -> bool {
            !matches!(
                application,
                AgentPacketFlowApplication::Http | AgentPacketFlowApplication::Https
            ) || self.involves_port(80)
                || self.involves_port(443)
        }

        fn payload_prefix_application(&self) -> Option<AgentPacketFlowApplication> {
            if self.payload_prefix.is_empty() {
                return None;
            }
            let payload = self.payload_prefix.as_slice();
            if dns_payload(payload, self.protocol) {
                return Some(AgentPacketFlowApplication::Dns);
            }
            if protocol_is(self.protocol, TransportProtocol::Udp)
                && (self.involves_port(67)
                    || self.involves_port(68)
                    || self.involves_port(546)
                    || self.involves_port(547))
                && (dhcp_payload(payload) || dhcpv6_payload(payload))
            {
                return Some(AgentPacketFlowApplication::Dhcp);
            }
            if protocol_is(self.protocol, TransportProtocol::Udp)
                && (self.involves_port(500) || self.involves_port(4500))
                && ike_payload(payload)
            {
                return Some(AgentPacketFlowApplication::Ike);
            }
            if protocol_is(self.protocol, TransportProtocol::Udp)
                && self.involves_port(4500)
                && ipsec_nat_t_payload(payload)
            {
                return Some(AgentPacketFlowApplication::Ipsec);
            }
            if protocol_is(self.protocol, TransportProtocol::Udp) && vxlan_payload(payload) {
                return Some(AgentPacketFlowApplication::Vxlan);
            }
            if protocol_is(self.protocol, TransportProtocol::Udp) && geneve_payload(payload) {
                return Some(AgentPacketFlowApplication::Geneve);
            }
            if protocol_is(self.protocol, TransportProtocol::Udp)
                && self.involves_port(443)
                && quic_long_header_payload(payload)
            {
                return Some(AgentPacketFlowApplication::Https);
            }
            if protocol_is(self.protocol, TransportProtocol::Udp) && wireguard_payload(payload) {
                return Some(AgentPacketFlowApplication::WireGuard);
            }
            if matches!(self.protocol, None | Some(TransportProtocol::Udp)) && ntp_payload(payload)
            {
                return Some(AgentPacketFlowApplication::Ntp);
            }
            if matches!(self.protocol, None | Some(TransportProtocol::Udp))
                && radius_payload(payload)
            {
                return Some(AgentPacketFlowApplication::Radius);
            }
            if matches!(
                self.protocol,
                None | Some(TransportProtocol::Tcp) | Some(TransportProtocol::Udp)
            ) && snmp_payload(payload)
            {
                return Some(AgentPacketFlowApplication::Snmp);
            }
            if syslog_payload(payload, self.protocol) {
                return Some(AgentPacketFlowApplication::Syslog);
            }
            if nfs_payload(payload, self.protocol) {
                return Some(AgentPacketFlowApplication::Nfs);
            }
            if kerberos_payload(payload, self.protocol) {
                return Some(AgentPacketFlowApplication::Kerberos);
            }
            if protocol_is(self.protocol, TransportProtocol::Tcp) && tacacs_payload(payload) {
                return Some(AgentPacketFlowApplication::Tacacs);
            }
            if protocol_is(self.protocol, TransportProtocol::Tcp) && bgp_payload(payload) {
                return Some(AgentPacketFlowApplication::Bgp);
            }
            if protocol_is(self.protocol, TransportProtocol::Udp)
                && (self.involves_port(3784)
                    || self.involves_port(3785)
                    || self.involves_port(4784))
                && bfd_payload(payload)
            {
                return Some(AgentPacketFlowApplication::Bfd);
            }
            if !protocol_is(self.protocol, TransportProtocol::Tcp) {
                return None;
            }
            http_payload_application(payload)
                .or_else(|| tls_client_hello_application(payload))
                .or_else(|| {
                    tls_handshake_payload(payload).then_some(AgentPacketFlowApplication::Https)
                })
                .or_else(|| ssh_payload(payload).then_some(AgentPacketFlowApplication::Ssh))
                .or_else(|| ldap_payload(payload).then_some(AgentPacketFlowApplication::Ldap))
                .or_else(|| smb_payload(payload).then_some(AgentPacketFlowApplication::Smb))
                .or_else(|| rdp_payload(payload).then_some(AgentPacketFlowApplication::Rdp))
                .or_else(|| {
                    zookeeper_payload(payload).then_some(AgentPacketFlowApplication::ZooKeeper)
                })
                .or_else(|| {
                    postgres_payload(payload).then_some(AgentPacketFlowApplication::Postgres)
                })
                .or_else(|| mysql_payload(payload).then_some(AgentPacketFlowApplication::Mysql))
                .or_else(|| mssql_tds_payload(payload).then_some(AgentPacketFlowApplication::MsSql))
                .or_else(|| {
                    oracle_tns_payload(payload).then_some(AgentPacketFlowApplication::Oracle)
                })
                .or_else(|| redis_payload(payload).then_some(AgentPacketFlowApplication::Redis))
                .or_else(|| {
                    memcached_payload(payload).then_some(AgentPacketFlowApplication::Memcached)
                })
                .or_else(|| kafka_payload(payload).then_some(AgentPacketFlowApplication::Kafka))
                .or_else(|| nats_payload(payload).then_some(AgentPacketFlowApplication::Nats))
                .or_else(|| mqtt_payload(payload).then_some(AgentPacketFlowApplication::Mqtt))
                .or_else(|| amqp_payload(payload).then_some(AgentPacketFlowApplication::Amqp))
                .or_else(|| {
                    cassandra_payload(payload).then_some(AgentPacketFlowApplication::Cassandra)
                })
                .or_else(|| mongodb_payload(payload).then_some(AgentPacketFlowApplication::MongoDb))
                .or_else(|| {
                    elasticsearch_transport_payload(payload)
                        .then_some(AgentPacketFlowApplication::Elasticsearch)
                })
        }
    }

    fn protocol_is(protocol: Option<TransportProtocol>, expected: TransportProtocol) -> bool {
        protocol.is_none() || protocol == Some(expected)
    }

    fn validate_packet_flow_application_hint(
        protocol: Option<TransportProtocol>,
        application: AgentPacketFlowApplication,
    ) -> Result<(), String> {
        let Some(protocol) = protocol else {
            return Ok(());
        };
        match application {
            AgentPacketFlowApplication::Unknown => Ok(()),
            AgentPacketFlowApplication::Icmp => require_packet_flow_application_protocol(
                protocol,
                application,
                "ICMP",
                |protocol| protocol == TransportProtocol::Icmp,
            ),
            AgentPacketFlowApplication::WireGuard
            | AgentPacketFlowApplication::Dhcp
            | AgentPacketFlowApplication::Ike
            | AgentPacketFlowApplication::Bfd
            | AgentPacketFlowApplication::Vxlan
            | AgentPacketFlowApplication::Geneve => {
                require_packet_flow_application_protocol(protocol, application, "UDP", |protocol| {
                    protocol == TransportProtocol::Udp
                })
            }
            AgentPacketFlowApplication::Ipsec => require_packet_flow_application_protocol(
                protocol,
                application,
                "UDP, ESP, or AH",
                |protocol| {
                    matches!(
                        protocol,
                        TransportProtocol::Udp | TransportProtocol::Esp | TransportProtocol::Ah
                    )
                },
            ),
            AgentPacketFlowApplication::IpTunnel => require_packet_flow_application_protocol(
                protocol,
                application,
                "IP-in-IP or IPv6 encapsulation",
                |protocol| {
                    matches!(
                        protocol,
                        TransportProtocol::IpInIp | TransportProtocol::Ipv6Encap
                    )
                },
            ),
            AgentPacketFlowApplication::Gre => {
                require_packet_flow_application_protocol(protocol, application, "GRE", |protocol| {
                    protocol == TransportProtocol::Gre
                })
            }
            AgentPacketFlowApplication::Dns
            | AgentPacketFlowApplication::Https
            | AgentPacketFlowApplication::Consul
            | AgentPacketFlowApplication::Nomad
            | AgentPacketFlowApplication::Jaeger
            | AgentPacketFlowApplication::Nfs
            | AgentPacketFlowApplication::Syslog
            | AgentPacketFlowApplication::Snmp
            | AgentPacketFlowApplication::Kerberos
            | AgentPacketFlowApplication::Ntp
            | AgentPacketFlowApplication::Radius
            | AgentPacketFlowApplication::Memcached => require_packet_flow_application_protocol(
                protocol,
                application,
                "TCP or UDP",
                |protocol| matches!(protocol, TransportProtocol::Tcp | TransportProtocol::Udp),
            ),
            _ => {
                require_packet_flow_application_protocol(protocol, application, "TCP", |protocol| {
                    protocol == TransportProtocol::Tcp
                })
            }
        }
    }

    fn require_packet_flow_application_protocol(
        protocol: TransportProtocol,
        application: AgentPacketFlowApplication,
        required: &'static str,
        is_allowed: impl FnOnce(TransportProtocol) -> bool,
    ) -> Result<(), String> {
        if is_allowed(protocol) {
            return Ok(());
        }
        Err(format!(
            "packet-flow application hint {} requires {required} protocol",
            application.as_str()
        ))
    }

    fn validate_packet_flow_source(source: IpAddr) -> Result<(), String> {
        if let Some(reason) = packet_flow_destination_drop_reason(source) {
            return Err(format!(
                "packet-flow source must not use {} address",
                reason.as_str()
            ));
        }
        Ok(())
    }

    fn deserialize_packet_flow_detector<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let detector = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
        let Some(detector) = detector else {
            return Ok(None);
        };
        validate_packet_flow_detector(&detector).map_err(serde::de::Error::custom)?;
        Ok(Some(detector))
    }

    fn validate_packet_flow_detector(detector: &str) -> Result<(), String> {
        if detector.len() > PACKET_FLOW_DETECTOR_MAX_BYTES {
            return Err(format!(
                "packet-flow detector exceeds {PACKET_FLOW_DETECTOR_MAX_BYTES} bytes"
            ));
        }
        if detector.trim().is_empty() {
            return Err("packet-flow detector must not be empty".to_string());
        }
        if detector.chars().any(char::is_control) {
            return Err("packet-flow detector must not contain control characters".to_string());
        }
        Ok(())
    }

    fn deserialize_packet_flow_conntrack_status<'de, D>(
        deserializer: D,
    ) -> Result<Vec<AgentPacketFlowConntrackStatus>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let Some(mut statuses) =
            <Option<Vec<AgentPacketFlowConntrackStatus>> as serde::Deserialize>::deserialize(
                deserializer,
            )?
        else {
            return Ok(Vec::new());
        };
        if statuses.len() > PACKET_FLOW_CONNTRACK_STATUS_MAX_FLAGS {
            return Err(serde::de::Error::custom(format!(
                "packet-flow conntrack_status exceeds {PACKET_FLOW_CONNTRACK_STATUS_MAX_FLAGS} flags"
            )));
        }
        statuses.sort();
        statuses.dedup();
        Ok(statuses)
    }

    fn deserialize_packet_flow_payload_prefix<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PayloadPrefixVisitor;

        impl<'de> serde::de::Visitor<'de> for PayloadPrefixVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    formatter,
                    "a packet-flow payload prefix string or byte array up to {PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES} bytes"
                )
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Vec::new())
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Vec::new())
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                bounded_packet_flow_payload_prefix(value.as_bytes())
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                bounded_packet_flow_payload_prefix(value)
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                bounded_packet_flow_payload_prefix(&value)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = Vec::new();
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if bytes.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES {
                        return Err(serde::de::Error::custom(format!(
                            "packet-flow payload_prefix exceeds {PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES} bytes"
                        )));
                    }
                    bytes.push(byte);
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_any(PayloadPrefixVisitor)
    }

    fn bounded_packet_flow_payload_prefix<E>(bytes: &[u8]) -> Result<Vec<u8>, E>
    where
        E: serde::de::Error,
    {
        if bytes.len() > PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES {
            return Err(E::custom(format!(
                "packet-flow payload_prefix exceeds {PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES} bytes"
            )));
        }
        Ok(bytes.to_vec())
    }

    const HTTP_REQUEST_METHODS: [&[u8]; 9] = [
        b"GET", b"HEAD", b"POST", b"PUT", b"PATCH", b"DELETE", b"OPTIONS", b"TRACE", b"CONNECT",
    ];
    const ETCD_GRPC_PATH_PREFIXES: [&[u8]; 8] = [
        b"/etcdserverpb.KV/",
        b"/etcdserverpb.Watch/",
        b"/etcdserverpb.Lease/",
        b"/etcdserverpb.Cluster/",
        b"/etcdserverpb.Maintenance/",
        b"/etcdserverpb.Auth/",
        b"/v3lockpb.Lock/",
        b"/v3electionpb.Election/",
    ];

    fn http_payload_application(payload: &[u8]) -> Option<AgentPacketFlowApplication> {
        if let Some(application) = http_payload_hint_application(payload) {
            return Some(application);
        }
        if let Some(path) = http_request_path(payload) {
            if loki_http_api_path(path) {
                return Some(AgentPacketFlowApplication::Loki);
            }
            if tempo_http_api_path(path) {
                return Some(AgentPacketFlowApplication::Tempo);
            }
            if zipkin_http_api_path(path) {
                return Some(AgentPacketFlowApplication::Zipkin);
            }
            if influxdb_http_api_path(path) {
                return Some(AgentPacketFlowApplication::InfluxDb);
            }
            if path_starts_with_any(path, &[b"/metrics", b"/federate"])
                || path_contains_any(path, &[b"/api/v1/query", b"/api/v1/write"])
            {
                return Some(AgentPacketFlowApplication::Prometheus);
            }
            if path_starts_with_any(path, &[b"/v1/traces", b"/v1/metrics", b"/v1/logs"]) {
                return Some(AgentPacketFlowApplication::OpenTelemetry);
            }
            if opentelemetry_grpc_path(path) {
                return Some(AgentPacketFlowApplication::OpenTelemetry);
            }
            if etcd_grpc_path(path) {
                return Some(AgentPacketFlowApplication::Etcd);
            }
            if etcd_http_api_path(path) {
                return Some(AgentPacketFlowApplication::Etcd);
            }
            if jaeger_http_api_path(path) {
                return Some(AgentPacketFlowApplication::Jaeger);
            }
            if consul_http_api_path(path) {
                return Some(AgentPacketFlowApplication::Consul);
            }
            if vault_http_api_path(path) {
                return Some(AgentPacketFlowApplication::Vault);
            }
            if nomad_http_api_path(path) {
                return Some(AgentPacketFlowApplication::Nomad);
            }
            if grpc_http_payload(payload) {
                return Some(AgentPacketFlowApplication::Grpc);
            }
            if path_starts_with_any(
                path,
                &[
                    b"/_bulk",
                    b"/_search",
                    b"/_msearch",
                    b"/_cluster",
                    b"/_cat",
                    b"/_nodes",
                ],
            ) || path_contains_any(path, &[b"/_bulk", b"/_search", b"/_msearch"])
            {
                return Some(AgentPacketFlowApplication::Elasticsearch);
            }
            return Some(AgentPacketFlowApplication::Http);
        }
        if payload.starts_with(b"HTTP/") || payload.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        {
            return http2_payload_application(payload).or(Some(AgentPacketFlowApplication::Http));
        }
        None
    }

    fn grpc_http_payload(payload: &[u8]) -> bool {
        contains_ascii_case_insensitive(payload, b"content-type: application/grpc")
            || contains_ascii_case_insensitive(payload, b"content-type: application/grpc-web")
    }

    fn http2_payload_application(payload: &[u8]) -> Option<AgentPacketFlowApplication> {
        const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        if !payload.starts_with(HTTP2_PREFACE) {
            return None;
        }
        let frames = payload.get(HTTP2_PREFACE.len()..).unwrap_or_default();
        http_payload_hint_application(frames)
    }

    fn http_payload_hint_application(payload: &[u8]) -> Option<AgentPacketFlowApplication> {
        if contains_ascii_case_insensitive(payload, b"/opentelemetry.proto.collector.") {
            return Some(AgentPacketFlowApplication::OpenTelemetry);
        }
        if contains_ascii_case_insensitive(payload, b"/zipkin.proto3.SpanService/Report") {
            return Some(AgentPacketFlowApplication::Zipkin);
        }
        if etcd_grpc_payload(payload) {
            return Some(AgentPacketFlowApplication::Etcd);
        }
        if contains_ascii_case_insensitive(payload, b"\r\nx-clickhouse-") {
            return Some(AgentPacketFlowApplication::ClickHouse);
        }
        if contains_ascii_case_insensitive(payload, b"\r\nx-influxdb-")
            || contains_ascii_case_insensitive(payload, b"\r\nx-influx-")
        {
            return Some(AgentPacketFlowApplication::InfluxDb);
        }
        if grpc_http_payload(payload)
            || contains_ascii_case_insensitive(payload, b"application/grpc")
        {
            return Some(AgentPacketFlowApplication::Grpc);
        }
        None
    }

    fn opentelemetry_grpc_path(path: &[u8]) -> bool {
        path_starts_with_any(
            path,
            &[
                b"/opentelemetry.proto.collector.trace.v1.TraceService/",
                b"/opentelemetry.proto.collector.metrics.v1.MetricsService/",
                b"/opentelemetry.proto.collector.logs.v1.LogsService/",
            ],
        )
    }

    fn etcd_grpc_path(path: &[u8]) -> bool {
        path_starts_with_any(path, &ETCD_GRPC_PATH_PREFIXES)
    }

    fn etcd_grpc_payload(payload: &[u8]) -> bool {
        ETCD_GRPC_PATH_PREFIXES
            .iter()
            .any(|prefix| contains_ascii_case_insensitive(payload, prefix))
    }

    fn etcd_http_api_path(path: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 12] = [
            b"/v2/keys",
            b"/v2/machines",
            b"/v2/members",
            b"/v2/stats",
            b"/v3/auth",
            b"/v3/cluster",
            b"/v3/election",
            b"/v3/kv",
            b"/v3/lease",
            b"/v3/lock",
            b"/v3/maintenance",
            b"/v3/watch",
        ];

        PREFIXES
            .iter()
            .any(|prefix| path_starts_with_api_prefix(path, prefix))
    }

    fn jaeger_http_api_path(path: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 6] = [
            b"/api/archive",
            b"/api/dependencies",
            b"/api/operations",
            b"/api/services",
            b"/api/traces",
            b"/jaeger/api/traces",
        ];

        PREFIXES
            .iter()
            .any(|prefix| path_starts_with_api_prefix(path, prefix))
    }

    fn loki_http_api_path(path: &[u8]) -> bool {
        path_starts_with_api_prefix(path, b"/loki/api/v1")
    }

    fn tempo_http_api_path(path: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 5] = [
            b"/api/v2/traces",
            b"/api/search",
            b"/api/metrics/query",
            b"/api/metrics/query_range",
            b"/api/echo",
        ];

        path.starts_with(b"/api/traces/")
            || PREFIXES
                .iter()
                .any(|prefix| path_starts_with_api_prefix(path, prefix))
    }

    fn zipkin_http_api_path(path: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 13] = [
            b"/zipkin",
            b"/api/v2/spans",
            b"/api/v2/services",
            b"/api/v2/trace",
            b"/api/v2/dependencies",
            b"/api/v2/autocompleteTags",
            b"/api/v1/spans",
            b"/api/v1/services",
            b"/api/v1/trace",
            b"/api/v1/dependencies",
            b"/config.json",
            b"/health",
            b"/info",
        ];

        PREFIXES
            .iter()
            .any(|prefix| path_starts_with_api_prefix(path, prefix))
    }

    fn influxdb_http_api_path(path: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 4] = [
            b"/api/v2/write",
            b"/api/v2/query",
            b"/api/v2/buckets",
            b"/api/v2/delete",
        ];

        PREFIXES
            .iter()
            .any(|prefix| path_starts_with_api_prefix(path, prefix))
    }

    fn consul_http_api_path(path: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 19] = [
            b"/v1/acl",
            b"/v1/agent",
            b"/v1/catalog",
            b"/v1/config",
            b"/v1/connect",
            b"/v1/coordinate",
            b"/v1/discovery-chain",
            b"/v1/event",
            b"/v1/exported-services",
            b"/v1/health",
            b"/v1/intention",
            b"/v1/kv",
            b"/v1/operator",
            b"/v1/partition",
            b"/v1/peering",
            b"/v1/query",
            b"/v1/session",
            b"/v1/status",
            b"/v1/txn",
        ];

        PREFIXES
            .iter()
            .any(|prefix| path_starts_with_api_prefix(path, prefix))
    }

    fn nomad_http_api_path(path: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 24] = [
            b"/v1/allocation",
            b"/v1/allocations",
            b"/v1/alloc",
            b"/v1/client/allocation",
            b"/v1/csi",
            b"/v1/deployment",
            b"/v1/deployments",
            b"/v1/evaluation",
            b"/v1/evaluations",
            b"/v1/job",
            b"/v1/jobs",
            b"/v1/namespace",
            b"/v1/namespaces",
            b"/v1/node",
            b"/v1/nodes",
            b"/v1/plugin",
            b"/v1/plugins",
            b"/v1/quota",
            b"/v1/quotas",
            b"/v1/scaling",
            b"/v1/search",
            b"/v1/var",
            b"/v1/variables",
            b"/v1/volumes",
        ];

        PREFIXES
            .iter()
            .any(|prefix| path_starts_with_api_prefix(path, prefix))
    }

    fn vault_http_api_path(path: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 17] = [
            b"/v1/auth",
            b"/v1/aws",
            b"/v1/azure",
            b"/v1/cubbyhole",
            b"/v1/database",
            b"/v1/gcp",
            b"/v1/identity",
            b"/v1/ldap",
            b"/v1/nomad",
            b"/v1/pki",
            b"/v1/rabbitmq",
            b"/v1/secret",
            b"/v1/ssh",
            b"/v1/sys",
            b"/v1/token",
            b"/v1/transit",
            b"/v1/transform",
        ];

        PREFIXES
            .iter()
            .any(|prefix| path_starts_with_api_prefix(path, prefix))
    }

    fn dns_payload(payload: &[u8], protocol: Option<TransportProtocol>) -> bool {
        match protocol {
            Some(TransportProtocol::Udp) => dns_message_payload(payload),
            Some(TransportProtocol::Tcp) => dns_tcp_payload(payload),
            None => dns_message_payload(payload) || dns_tcp_payload(payload),
            Some(
                TransportProtocol::Any
                | TransportProtocol::IpInIp
                | TransportProtocol::Icmp
                | TransportProtocol::Sctp
                | TransportProtocol::Ipv6Encap
                | TransportProtocol::Gre
                | TransportProtocol::Esp
                | TransportProtocol::Ah,
            ) => false,
        }
    }

    fn dns_tcp_payload(payload: &[u8]) -> bool {
        if payload.len() < 14 {
            return false;
        }
        let message_len = u16::from_be_bytes([payload[0], payload[1]]);
        (12..=4096).contains(&message_len) && dns_message_payload(&payload[2..])
    }

    fn dns_message_payload(payload: &[u8]) -> bool {
        if payload.len() < 12 {
            return false;
        }
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let opcode = (flags >> 11) & 0x0f;
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        if opcode > 5 || qdcount == 0 || flags & 0x0040 != 0 {
            return false;
        }
        dns_question_payload(payload)
    }

    fn dhcp_payload(payload: &[u8]) -> bool {
        if payload.len() < 44 || !matches!(payload[0], 1 | 2) {
            return false;
        }
        let hardware_len = payload[2] as usize;
        if hardware_len == 0 || hardware_len > 16 || payload[3] > 16 {
            return false;
        }
        if payload[4..8].iter().all(|byte| *byte == 0) {
            return false;
        }
        let flags = u16::from_be_bytes([payload[10], payload[11]]);
        if flags & 0x7fff != 0 {
            return false;
        }
        let client_hardware_end = 28 + hardware_len;
        if payload[28..client_hardware_end]
            .iter()
            .all(|byte| *byte == 0)
        {
            return false;
        }
        payload.len() < 240 || payload.get(236..240) == Some(&[99, 130, 83, 99][..])
    }

    fn dhcpv6_payload(payload: &[u8]) -> bool {
        if payload.len() < 4 {
            return false;
        }
        match payload[0] {
            1..=11 | 14 => {
                if payload[1..4].iter().all(|byte| *byte == 0) {
                    return false;
                }
                dhcpv6_options_payload(payload, 4, false)
            }
            12 | 13 => {
                if payload.len() < 34 || payload[1] > 32 {
                    return false;
                }
                if payload[18..34].iter().all(|byte| *byte == 0) {
                    return false;
                }
                dhcpv6_options_payload(payload, 34, true)
            }
            _ => false,
        }
    }

    fn dhcpv6_options_payload(
        payload: &[u8],
        mut offset: usize,
        require_relay_message: bool,
    ) -> bool {
        let mut option_count = 0_usize;
        let mut relay_message_seen = false;
        while offset < payload.len() {
            if payload.len() - offset < 4 {
                return payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
            }
            let option_code = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let option_len =
                u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
            let Some(value_offset) = offset.checked_add(4) else {
                return false;
            };
            let Some(next_offset) = value_offset.checked_add(option_len) else {
                return false;
            };
            if next_offset > payload.len() {
                return payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
            }
            option_count += 1;
            relay_message_seen |= option_code == 9 && option_len > 0;
            offset = next_offset;
        }
        option_count > 0 && (!require_relay_message || relay_message_seen)
    }

    fn dns_question_payload(payload: &[u8]) -> bool {
        let mut offset = 12_usize;
        let mut labels = 0_usize;
        let mut name_len = 0_usize;
        loop {
            let Some(&len) = payload.get(offset) else {
                return false;
            };
            if len & 0xc0 != 0 {
                return false;
            }
            offset += 1;
            if len == 0 {
                break;
            }
            if len > 63 {
                return false;
            }
            let len = len as usize;
            let Some(label_end) = offset.checked_add(len) else {
                return false;
            };
            let Some(label) = payload.get(offset..label_end) else {
                return false;
            };
            if !label
                .iter()
                .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return false;
            }
            labels += 1;
            name_len += len + 1;
            if labels > 32 || name_len > 255 {
                return false;
            }
            offset = label_end;
        }
        if labels == 0 {
            return false;
        }
        let Some(question_end) = offset.checked_add(4) else {
            return false;
        };
        let Some(question) = payload.get(offset..question_end) else {
            return false;
        };
        let qtype = u16::from_be_bytes([question[0], question[1]]);
        let qclass = u16::from_be_bytes([question[2], question[3]]);
        qtype != 0 && qclass != 0
    }

    fn tls_handshake_payload(payload: &[u8]) -> bool {
        if payload.len() < 6 {
            return false;
        }
        let record_len = u16::from_be_bytes([payload[3], payload[4]]);
        payload[0] == 0x16
            && payload[1] == 0x03
            && (0x01..=0x04).contains(&payload[2])
            && (1..=16_384).contains(&record_len)
            && matches!(payload[5], 0x01 | 0x02)
    }

    fn tls_client_hello_application(payload: &[u8]) -> Option<AgentPacketFlowApplication> {
        if payload.len() < 9
            || payload[0] != 0x16
            || payload[1] != 0x03
            || !(0x01..=0x04).contains(&payload[2])
            || payload[5] != 0x01
        {
            return None;
        }
        let record_len = read_u16_be(payload, 3)? as usize;
        if !(1..=16_384).contains(&record_len) {
            return None;
        }
        let handshake_len = read_u24_be(payload, 6)?;
        if handshake_len < 38 || handshake_len.checked_add(4)? > record_len {
            return None;
        }
        let handshake_end = 9_usize.checked_add(handshake_len)?;
        if handshake_end > payload.len() {
            return None;
        }

        let mut offset = 9_usize.checked_add(34)?;
        let session_id_len = *payload.get(offset)? as usize;
        offset = offset.checked_add(1)?.checked_add(session_id_len)?;
        if offset >= handshake_end {
            return None;
        }

        let cipher_suites_len = read_u16_be(payload, offset)? as usize;
        if cipher_suites_len == 0 || !cipher_suites_len.is_multiple_of(2) {
            return None;
        }
        offset = offset.checked_add(2)?.checked_add(cipher_suites_len)?;
        if offset >= handshake_end {
            return None;
        }

        let compression_methods_len = *payload.get(offset)? as usize;
        if compression_methods_len == 0 {
            return None;
        }
        offset = offset
            .checked_add(1)?
            .checked_add(compression_methods_len)?;
        if offset >= handshake_end {
            return None;
        }

        let extensions_len = read_u16_be(payload, offset)? as usize;
        offset = offset.checked_add(2)?;
        let extensions_end = offset.checked_add(extensions_len)?;
        if extensions_end != handshake_end {
            return None;
        }

        let mut alpn_application = None;
        while offset.checked_add(4)? <= extensions_end {
            let extension_type = read_u16_be(payload, offset)?;
            let extension_len = read_u16_be(payload, offset + 2)? as usize;
            offset = offset.checked_add(4)?;
            let extension_end = offset.checked_add(extension_len)?;
            if extension_end > extensions_end {
                return None;
            }
            let extension = payload.get(offset..extension_end)?;
            match extension_type {
                0 => {
                    if let Some(application) = tls_sni_extension_application(extension) {
                        return Some(application);
                    }
                }
                16 if alpn_application.is_none() => {
                    alpn_application = tls_alpn_extension_application(extension);
                }
                _ => {}
            }
            offset = extension_end;
        }
        alpn_application
    }

    fn tls_sni_extension_application(extension: &[u8]) -> Option<AgentPacketFlowApplication> {
        let server_name_list_len = read_u16_be(extension, 0)? as usize;
        let server_name_list_end = 2_usize.checked_add(server_name_list_len)?;
        if server_name_list_end > extension.len() {
            return None;
        }

        let mut offset = 2_usize;
        while offset < server_name_list_end {
            let name_type = *extension.get(offset)?;
            let name_len = read_u16_be(extension, offset + 1)? as usize;
            let name_offset = offset.checked_add(3)?;
            let name_end = name_offset.checked_add(name_len)?;
            if name_end > server_name_list_end {
                return None;
            }
            if name_type == 0 {
                if let Some(application) =
                    tls_sni_hostname_application(extension.get(name_offset..name_end)?)
                {
                    return Some(application);
                }
            }
            offset = name_end;
        }
        None
    }

    fn tls_sni_hostname_application(hostname: &[u8]) -> Option<AgentPacketFlowApplication> {
        if !tls_sni_hostname_is_valid(hostname) {
            return None;
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"kubernetes")
            || tls_sni_hostname_has_label_prefix(hostname, b"kube-apiserver")
            || tls_sni_hostname_has_label_prefix(hostname, b"kube-api")
        {
            return Some(AgentPacketFlowApplication::KubernetesApi);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"etcd") {
            return Some(AgentPacketFlowApplication::Etcd);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"zookeeper")
            || tls_sni_hostname_has_label_prefix(hostname, b"zk")
        {
            return Some(AgentPacketFlowApplication::ZooKeeper);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"consul") {
            return Some(AgentPacketFlowApplication::Consul);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"vault") {
            return Some(AgentPacketFlowApplication::Vault);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"nomad") {
            return Some(AgentPacketFlowApplication::Nomad);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"prometheus") {
            return Some(AgentPacketFlowApplication::Prometheus);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"opentelemetry")
            || tls_sni_hostname_has_label_prefix(hostname, b"otel")
            || tls_sni_hostname_has_label_prefix(hostname, b"otlp")
        {
            return Some(AgentPacketFlowApplication::OpenTelemetry);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"jaeger") {
            return Some(AgentPacketFlowApplication::Jaeger);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"loki") {
            return Some(AgentPacketFlowApplication::Loki);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"tempo") {
            return Some(AgentPacketFlowApplication::Tempo);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"zipkin") {
            return Some(AgentPacketFlowApplication::Zipkin);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"grpc") {
            return Some(AgentPacketFlowApplication::Grpc);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"kafka") {
            return Some(AgentPacketFlowApplication::Kafka);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"nats") {
            return Some(AgentPacketFlowApplication::Nats);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"mqtt")
            || tls_sni_hostname_has_label_prefix(hostname, b"mosquitto")
            || tls_sni_hostname_has_label_prefix(hostname, b"emqx")
        {
            return Some(AgentPacketFlowApplication::Mqtt);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"amqp")
            || tls_sni_hostname_has_label_prefix(hostname, b"amqps")
            || tls_sni_hostname_has_label_prefix(hostname, b"rabbitmq")
        {
            return Some(AgentPacketFlowApplication::Amqp);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"cassandra") {
            return Some(AgentPacketFlowApplication::Cassandra);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"mongodb")
            || tls_sni_hostname_has_label_prefix(hostname, b"mongo")
        {
            return Some(AgentPacketFlowApplication::MongoDb);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"elasticsearch")
            || tls_sni_hostname_has_label_prefix(hostname, b"elastic")
        {
            return Some(AgentPacketFlowApplication::Elasticsearch);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"postgres")
            || tls_sni_hostname_has_label_prefix(hostname, b"postgresql")
            || tls_sni_hostname_has_label_prefix(hostname, b"pg")
        {
            return Some(AgentPacketFlowApplication::Postgres);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"mysql")
            || tls_sni_hostname_has_label_prefix(hostname, b"mariadb")
        {
            return Some(AgentPacketFlowApplication::Mysql);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"mssql")
            || tls_sni_hostname_has_label_prefix(hostname, b"sqlserver")
            || tls_sni_hostname_has_label_prefix(hostname, b"sql-server")
        {
            return Some(AgentPacketFlowApplication::MsSql);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"oracle")
            || tls_sni_hostname_has_label_prefix(hostname, b"oracledb")
            || tls_sni_hostname_has_label_prefix(hostname, b"tns")
        {
            return Some(AgentPacketFlowApplication::Oracle);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"clickhouse") {
            return Some(AgentPacketFlowApplication::ClickHouse);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"influxdb")
            || tls_sni_hostname_has_label_prefix(hostname, b"influx")
        {
            return Some(AgentPacketFlowApplication::InfluxDb);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"syslog")
            || tls_sni_hostname_has_label_prefix(hostname, b"rsyslog")
        {
            return Some(AgentPacketFlowApplication::Syslog);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"snmp")
            || tls_sni_hostname_has_label_prefix(hostname, b"snmptrap")
        {
            return Some(AgentPacketFlowApplication::Snmp);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"redis")
            || tls_sni_hostname_has_label_prefix(hostname, b"valkey")
        {
            return Some(AgentPacketFlowApplication::Redis);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"memcached")
            || tls_sni_hostname_has_label_prefix(hostname, b"memcache")
        {
            return Some(AgentPacketFlowApplication::Memcached);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"ldap")
            || tls_sni_hostname_has_label_prefix(hostname, b"ldaps")
        {
            return Some(AgentPacketFlowApplication::Ldap);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"kerberos")
            || tls_sni_hostname_has_label_prefix(hostname, b"krb5")
            || tls_sni_hostname_has_label_prefix(hostname, b"kdc")
        {
            return Some(AgentPacketFlowApplication::Kerberos);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"ntp")
            || tls_sni_hostname_has_label_prefix(hostname, b"ntske")
            || tls_sni_hostname_has_label_prefix(hostname, b"chrony")
        {
            return Some(AgentPacketFlowApplication::Ntp);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"radius")
            || tls_sni_hostname_has_label_prefix(hostname, b"radsec")
        {
            return Some(AgentPacketFlowApplication::Radius);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"tacacs")
            || tls_sni_hostname_has_label_prefix(hostname, b"tacacsplus")
            || tls_sni_hostname_has_label_prefix(hostname, b"tacacs-plus")
        {
            return Some(AgentPacketFlowApplication::Tacacs);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"bgp")
            || tls_sni_hostname_has_label_prefix(hostname, b"bgp4")
        {
            return Some(AgentPacketFlowApplication::Bgp);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"smb") {
            return Some(AgentPacketFlowApplication::Smb);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"nfs") {
            return Some(AgentPacketFlowApplication::Nfs);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"rdp") {
            return Some(AgentPacketFlowApplication::Rdp);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"ssh") {
            return Some(AgentPacketFlowApplication::Ssh);
        }
        None
    }

    fn tls_alpn_extension_application(extension: &[u8]) -> Option<AgentPacketFlowApplication> {
        let protocol_list_len = read_u16_be(extension, 0)? as usize;
        let protocol_list_end = 2_usize.checked_add(protocol_list_len)?;
        if protocol_list_end != extension.len() {
            return None;
        }

        let mut offset = 2_usize;
        while offset < protocol_list_end {
            let protocol_len = *extension.get(offset)? as usize;
            let protocol_offset = offset.checked_add(1)?;
            let protocol_end = protocol_offset.checked_add(protocol_len)?;
            if protocol_len == 0 || protocol_end > protocol_list_end {
                return None;
            }
            if let Some(application) =
                tls_alpn_protocol_application(extension.get(protocol_offset..protocol_end)?)
            {
                return Some(application);
            }
            offset = protocol_end;
        }
        None
    }

    fn tls_alpn_protocol_application(protocol: &[u8]) -> Option<AgentPacketFlowApplication> {
        if protocol.eq_ignore_ascii_case(b"kubernetes")
            || protocol.eq_ignore_ascii_case(b"kube-apiserver")
            || protocol.eq_ignore_ascii_case(b"kube-api")
        {
            return Some(AgentPacketFlowApplication::KubernetesApi);
        }
        if protocol.eq_ignore_ascii_case(b"etcd") {
            return Some(AgentPacketFlowApplication::Etcd);
        }
        if protocol.eq_ignore_ascii_case(b"zookeeper")
            || protocol.eq_ignore_ascii_case(b"zk")
            || protocol.eq_ignore_ascii_case(b"zab")
        {
            return Some(AgentPacketFlowApplication::ZooKeeper);
        }
        if protocol.eq_ignore_ascii_case(b"consul")
            || protocol.eq_ignore_ascii_case(b"consul-rpc")
            || protocol.eq_ignore_ascii_case(b"consul-grpc")
        {
            return Some(AgentPacketFlowApplication::Consul);
        }
        if protocol.eq_ignore_ascii_case(b"vault")
            || protocol.eq_ignore_ascii_case(b"vault-rpc")
            || protocol.eq_ignore_ascii_case(b"vault-api")
        {
            return Some(AgentPacketFlowApplication::Vault);
        }
        if protocol.eq_ignore_ascii_case(b"nomad")
            || protocol.eq_ignore_ascii_case(b"nomad-rpc")
            || protocol.eq_ignore_ascii_case(b"nomad-serf")
        {
            return Some(AgentPacketFlowApplication::Nomad);
        }
        if protocol.eq_ignore_ascii_case(b"prometheus") {
            return Some(AgentPacketFlowApplication::Prometheus);
        }
        if protocol.eq_ignore_ascii_case(b"opentelemetry")
            || protocol.eq_ignore_ascii_case(b"otel")
            || protocol.eq_ignore_ascii_case(b"otlp")
            || tls_alpn_protocol_has_token(protocol, b"otlp")
        {
            return Some(AgentPacketFlowApplication::OpenTelemetry);
        }
        if protocol.eq_ignore_ascii_case(b"jaeger")
            || protocol.eq_ignore_ascii_case(b"jaeger-grpc")
            || protocol.eq_ignore_ascii_case(b"jaeger-thrift")
        {
            return Some(AgentPacketFlowApplication::Jaeger);
        }
        if protocol.eq_ignore_ascii_case(b"loki")
            || protocol.eq_ignore_ascii_case(b"loki-grpc")
            || protocol.eq_ignore_ascii_case(b"loki-http")
        {
            return Some(AgentPacketFlowApplication::Loki);
        }
        if protocol.eq_ignore_ascii_case(b"tempo")
            || protocol.eq_ignore_ascii_case(b"tempo-grpc")
            || protocol.eq_ignore_ascii_case(b"tempo-http")
        {
            return Some(AgentPacketFlowApplication::Tempo);
        }
        if protocol.eq_ignore_ascii_case(b"zipkin")
            || protocol.eq_ignore_ascii_case(b"zipkin-http")
            || protocol.eq_ignore_ascii_case(b"zipkin-grpc")
        {
            return Some(AgentPacketFlowApplication::Zipkin);
        }
        if protocol.eq_ignore_ascii_case(b"clickhouse")
            || protocol.eq_ignore_ascii_case(b"clickhouse-native")
            || protocol.eq_ignore_ascii_case(b"clickhouse-http")
        {
            return Some(AgentPacketFlowApplication::ClickHouse);
        }
        if protocol.eq_ignore_ascii_case(b"influxdb")
            || protocol.eq_ignore_ascii_case(b"influxdb-http")
            || protocol.eq_ignore_ascii_case(b"influx")
        {
            return Some(AgentPacketFlowApplication::InfluxDb);
        }
        if protocol.eq_ignore_ascii_case(b"syslog")
            || protocol.eq_ignore_ascii_case(b"syslog-tls")
            || protocol.eq_ignore_ascii_case(b"rsyslog")
        {
            return Some(AgentPacketFlowApplication::Syslog);
        }
        if protocol.eq_ignore_ascii_case(b"snmp")
            || protocol.eq_ignore_ascii_case(b"snmp-tls")
            || protocol.eq_ignore_ascii_case(b"snmptls")
            || protocol.eq_ignore_ascii_case(b"snmp-dtls")
            || protocol.eq_ignore_ascii_case(b"snmpdtls")
            || protocol.eq_ignore_ascii_case(b"snmptrap")
        {
            return Some(AgentPacketFlowApplication::Snmp);
        }
        if protocol.eq_ignore_ascii_case(b"nfs")
            || protocol.eq_ignore_ascii_case(b"nfs4")
            || protocol.eq_ignore_ascii_case(b"nfsv4")
        {
            return Some(AgentPacketFlowApplication::Nfs);
        }
        if protocol.eq_ignore_ascii_case(b"grpc") || protocol.eq_ignore_ascii_case(b"grpc-exp") {
            return Some(AgentPacketFlowApplication::Grpc);
        }
        if protocol.eq_ignore_ascii_case(b"kafka") {
            return Some(AgentPacketFlowApplication::Kafka);
        }
        if protocol.eq_ignore_ascii_case(b"nats") {
            return Some(AgentPacketFlowApplication::Nats);
        }
        if protocol.eq_ignore_ascii_case(b"mqtt")
            || protocol
                .get(..5)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"mqttv"))
            || tls_alpn_protocol_has_token(protocol, b"mqtt")
            || protocol.eq_ignore_ascii_case(b"mosquitto")
            || protocol.eq_ignore_ascii_case(b"emqx")
        {
            return Some(AgentPacketFlowApplication::Mqtt);
        }
        if protocol.eq_ignore_ascii_case(b"amqp")
            || protocol.eq_ignore_ascii_case(b"amqp/1.0")
            || protocol.eq_ignore_ascii_case(b"rabbitmq")
        {
            return Some(AgentPacketFlowApplication::Amqp);
        }
        if protocol.eq_ignore_ascii_case(b"cassandra") {
            return Some(AgentPacketFlowApplication::Cassandra);
        }
        if protocol.eq_ignore_ascii_case(b"mongodb") || protocol.eq_ignore_ascii_case(b"mongo") {
            return Some(AgentPacketFlowApplication::MongoDb);
        }
        if protocol.eq_ignore_ascii_case(b"elasticsearch")
            || protocol.eq_ignore_ascii_case(b"elastic")
        {
            return Some(AgentPacketFlowApplication::Elasticsearch);
        }
        if protocol.eq_ignore_ascii_case(b"postgres")
            || protocol.eq_ignore_ascii_case(b"postgresql")
            || protocol.eq_ignore_ascii_case(b"pg")
        {
            return Some(AgentPacketFlowApplication::Postgres);
        }
        if protocol.eq_ignore_ascii_case(b"mysql") || protocol.eq_ignore_ascii_case(b"mariadb") {
            return Some(AgentPacketFlowApplication::Mysql);
        }
        if protocol.eq_ignore_ascii_case(b"mssql")
            || protocol.eq_ignore_ascii_case(b"sqlserver")
            || protocol.eq_ignore_ascii_case(b"tds")
        {
            return Some(AgentPacketFlowApplication::MsSql);
        }
        if protocol.eq_ignore_ascii_case(b"oracle")
            || protocol.eq_ignore_ascii_case(b"oracle-tns")
            || protocol.eq_ignore_ascii_case(b"tns")
        {
            return Some(AgentPacketFlowApplication::Oracle);
        }
        if protocol.eq_ignore_ascii_case(b"redis") || protocol.eq_ignore_ascii_case(b"valkey") {
            return Some(AgentPacketFlowApplication::Redis);
        }
        if protocol.eq_ignore_ascii_case(b"memcached") || protocol.eq_ignore_ascii_case(b"memcache")
        {
            return Some(AgentPacketFlowApplication::Memcached);
        }
        if protocol.eq_ignore_ascii_case(b"ldap") || protocol.eq_ignore_ascii_case(b"ldaps") {
            return Some(AgentPacketFlowApplication::Ldap);
        }
        if protocol.eq_ignore_ascii_case(b"kerberos")
            || protocol.eq_ignore_ascii_case(b"krb5")
            || protocol.eq_ignore_ascii_case(b"kerberos-tcp")
            || protocol.eq_ignore_ascii_case(b"kerberos-udp")
        {
            return Some(AgentPacketFlowApplication::Kerberos);
        }
        if protocol.eq_ignore_ascii_case(b"ntp")
            || protocol.eq_ignore_ascii_case(b"ntske")
            || protocol.eq_ignore_ascii_case(b"ntske/1")
        {
            return Some(AgentPacketFlowApplication::Ntp);
        }
        if protocol.eq_ignore_ascii_case(b"radius") || protocol.eq_ignore_ascii_case(b"radsec") {
            return Some(AgentPacketFlowApplication::Radius);
        }
        if protocol.eq_ignore_ascii_case(b"tacacs")
            || protocol.eq_ignore_ascii_case(b"tacacs+")
            || protocol.eq_ignore_ascii_case(b"tacacsplus")
            || protocol.eq_ignore_ascii_case(b"tacacs-plus")
        {
            return Some(AgentPacketFlowApplication::Tacacs);
        }
        if protocol.eq_ignore_ascii_case(b"bgp") || protocol.eq_ignore_ascii_case(b"bgp4") {
            return Some(AgentPacketFlowApplication::Bgp);
        }
        if protocol.eq_ignore_ascii_case(b"smb") {
            return Some(AgentPacketFlowApplication::Smb);
        }
        if protocol.eq_ignore_ascii_case(b"rdp") {
            return Some(AgentPacketFlowApplication::Rdp);
        }
        if protocol.eq_ignore_ascii_case(b"ssh") {
            return Some(AgentPacketFlowApplication::Ssh);
        }
        None
    }

    fn tls_alpn_protocol_has_token(protocol: &[u8], token: &[u8]) -> bool {
        if token.is_empty() || token.len() > protocol.len() {
            return false;
        }
        for offset in 0..=protocol.len() - token.len() {
            let token_end = offset + token.len();
            if !protocol[offset..token_end].eq_ignore_ascii_case(token) {
                continue;
            }
            let previous_is_separator = offset == 0
                || protocol
                    .get(offset - 1)
                    .is_some_and(|byte| !byte.is_ascii_alphanumeric());
            let next_is_separator = token_end == protocol.len()
                || protocol
                    .get(token_end)
                    .is_some_and(|byte| !byte.is_ascii_alphanumeric());
            if previous_is_separator && next_is_separator {
                return true;
            }
        }
        false
    }

    fn tls_sni_hostname_is_valid(hostname: &[u8]) -> bool {
        if hostname.is_empty() || hostname.len() > 253 {
            return false;
        }
        let mut previous_dot = true;
        for byte in hostname {
            match *byte {
                b'.' => {
                    if previous_dot {
                        return false;
                    }
                    previous_dot = true;
                }
                byte if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') => {
                    previous_dot = false;
                }
                _ => return false,
            }
        }
        !previous_dot
    }

    fn tls_sni_hostname_has_label_prefix(hostname: &[u8], prefix: &[u8]) -> bool {
        let mut offset = 0_usize;
        while offset < hostname.len() {
            let relative_end = hostname[offset..]
                .iter()
                .position(|byte| *byte == b'.')
                .unwrap_or(hostname.len() - offset);
            let label_end = offset + relative_end;
            let label = &hostname[offset..label_end];
            if label.eq_ignore_ascii_case(prefix)
                || (label.len() > prefix.len()
                    && label
                        .get(..prefix.len())
                        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
                    && label.get(prefix.len()) == Some(&b'-'))
            {
                return true;
            }
            offset = label_end.saturating_add(1);
        }
        false
    }

    fn read_u16_be(payload: &[u8], offset: usize) -> Option<u16> {
        let bytes = payload.get(offset..offset.checked_add(2)?)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u16_le(payload: &[u8], offset: usize) -> Option<u16> {
        let bytes = payload.get(offset..offset.checked_add(2)?)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u24_be(payload: &[u8], offset: usize) -> Option<usize> {
        let bytes = payload.get(offset..offset.checked_add(3)?)?;
        Some(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
    }

    fn read_u24_le(payload: &[u8], offset: usize) -> Option<usize> {
        let bytes = payload.get(offset..offset.checked_add(3)?)?;
        Some((bytes[0] as usize) | ((bytes[1] as usize) << 8) | ((bytes[2] as usize) << 16))
    }

    fn read_u32_be(payload: &[u8], offset: usize) -> Option<u32> {
        let bytes = payload.get(offset..offset.checked_add(4)?)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u32_le(payload: &[u8], offset: usize) -> Option<u32> {
        let bytes = payload.get(offset..offset.checked_add(4)?)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn quic_long_header_payload(payload: &[u8]) -> bool {
        if payload.len() < 7 || payload[0] & 0x80 == 0 {
            return false;
        }
        let Some(version) = read_u32_be(payload, 1) else {
            return false;
        };
        if version == 0 {
            return false;
        }
        if version != 1 {
            return payload[0] & 0x40 != 0 && quic_connection_id_lengths(payload, 255).is_some();
        }
        if payload[0] & 0x40 == 0 {
            return false;
        }
        let Some((payload_offset, _dcid_len, _scid_len)) = quic_connection_id_lengths(payload, 20)
        else {
            return false;
        };
        let packet_number_len = (payload[0] & 0x03) as usize + 1;
        match (payload[0] & 0x30) >> 4 {
            0 => quic_initial_packet_payload(payload, payload_offset, packet_number_len),
            1 | 2 => quic_length_packet_payload(payload, payload_offset, packet_number_len),
            3 => quic_retry_packet_payload(payload, payload_offset),
            _ => false,
        }
    }

    fn quic_connection_id_lengths(payload: &[u8], max_len: usize) -> Option<(usize, usize, usize)> {
        let dcid_len = *payload.get(5)? as usize;
        if dcid_len > max_len {
            return None;
        }
        let scid_len_index = 6_usize.checked_add(dcid_len)?;
        let scid_len = *payload.get(scid_len_index)? as usize;
        if scid_len > max_len {
            return None;
        }
        let payload_offset = scid_len_index.checked_add(1)?.checked_add(scid_len)?;
        (payload.len() >= payload_offset).then_some((payload_offset, dcid_len, scid_len))
    }

    fn quic_initial_packet_payload(
        payload: &[u8],
        offset: usize,
        packet_number_len: usize,
    ) -> bool {
        let Some((token_len, token_offset)) = read_quic_varint(payload, offset) else {
            return false;
        };
        let Some(length_offset) = token_offset.checked_add(token_len as usize) else {
            return false;
        };
        if length_offset > payload.len() {
            return false;
        }
        quic_length_packet_payload(payload, length_offset, packet_number_len)
    }

    fn quic_length_packet_payload(payload: &[u8], offset: usize, packet_number_len: usize) -> bool {
        let Some((declared_len, packet_number_offset)) = read_quic_varint(payload, offset) else {
            return false;
        };
        let Some(packet_payload_min_len) = packet_number_len.checked_add(1) else {
            return false;
        };
        if declared_len < packet_payload_min_len as u64 {
            return false;
        }
        packet_number_offset
            .checked_add(packet_payload_min_len)
            .is_some_and(|end| payload.len() >= end)
    }

    fn quic_retry_packet_payload(payload: &[u8], offset: usize) -> bool {
        let Some(&odcid_len) = payload.get(offset) else {
            return false;
        };
        if odcid_len > 20 {
            return false;
        }
        offset
            .checked_add(1)
            .and_then(|offset| offset.checked_add(odcid_len as usize))
            .and_then(|offset| offset.checked_add(16))
            .is_some_and(|minimum_len| payload.len() >= minimum_len)
    }

    fn read_quic_varint(payload: &[u8], offset: usize) -> Option<(u64, usize)> {
        let first = *payload.get(offset)?;
        let len = 1_usize << ((first >> 6) as usize);
        let bytes = payload.get(offset..offset.checked_add(len)?)?;
        let mut value = (bytes[0] & 0x3f) as u64;
        for byte in &bytes[1..] {
            value = value.checked_shl(8)?.checked_add(*byte as u64)?;
        }
        Some((value, offset + len))
    }

    const WIREGUARD_HANDSHAKE_INITIATION_LEN: usize = 148;
    const WIREGUARD_HANDSHAKE_RESPONSE_LEN: usize = 92;
    const WIREGUARD_COOKIE_REPLY_LEN: usize = 64;
    const WIREGUARD_TRANSPORT_KEEPALIVE_LEN: usize = 32;
    const IKE_HEADER_LEN: usize = 28;
    const IPSEC_ESP_HEADER_LEN: usize = 8;
    const IKE_NAT_T_NON_ESP_MARKER: [u8; 4] = [0, 0, 0, 0];
    const VXLAN_HEADER_LEN: usize = 8;
    const GENEVE_HEADER_LEN: usize = 8;
    const ETHERNET_HEADER_LEN: usize = 14;
    const GENEVE_PROTOCOL_TRANSPARENT_ETHERNET: u16 = 0x6558;

    fn ike_payload(payload: &[u8]) -> bool {
        let payload = payload
            .strip_prefix(&IKE_NAT_T_NON_ESP_MARKER)
            .unwrap_or(payload);
        if payload.len() < IKE_HEADER_LEN {
            return false;
        }
        if payload[..16].iter().all(|byte| *byte == 0) {
            return false;
        }
        let next_payload = payload[16];
        let major_version = payload[17] >> 4;
        let exchange_type = payload[18];
        let flags = payload[19];
        if major_version != 2
            || !(next_payload == 0 || (33..=48).contains(&next_payload))
            || !matches!(exchange_type, 34..=37)
        {
            return false;
        }
        if flags & !0x38 != 0 {
            return false;
        }
        let packet_len =
            u32::from_be_bytes([payload[24], payload[25], payload[26], payload[27]]) as usize;
        if packet_len < IKE_HEADER_LEN {
            return false;
        }
        packet_len <= payload.len()
            || (payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES
                && packet_len > PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES)
    }

    fn ipsec_nat_t_payload(payload: &[u8]) -> bool {
        if payload.len() < IPSEC_ESP_HEADER_LEN
            || payload.starts_with(&IKE_NAT_T_NON_ESP_MARKER)
            || payload == [0xff]
        {
            return false;
        }
        let spi = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let sequence = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        spi != 0 && sequence != 0
    }

    fn ethernet_frame_payload(payload: &[u8], offset: usize) -> bool {
        let Some(ethertype_offset) = offset.checked_add(12) else {
            return false;
        };
        let Some(ethertype_bytes) =
            payload.get(ethertype_offset..ethertype_offset.saturating_add(2))
        else {
            return false;
        };
        u16::from_be_bytes([ethertype_bytes[0], ethertype_bytes[1]]) >= 0x0600
    }

    fn vxlan_payload(payload: &[u8]) -> bool {
        let minimum_len = VXLAN_HEADER_LEN + ETHERNET_HEADER_LEN;
        if payload.len() < minimum_len {
            return false;
        }
        if payload[0] != 0x08 || payload.get(1..4) != Some(&[0, 0, 0]) || payload[7] != 0 {
            return false;
        }
        if payload[4..7].iter().all(|byte| *byte == 0) {
            return false;
        }
        ethernet_frame_payload(payload, VXLAN_HEADER_LEN)
    }

    fn geneve_payload(payload: &[u8]) -> bool {
        if payload.len() < GENEVE_HEADER_LEN {
            return false;
        }
        if payload[0] >> 6 != 0 || payload[1] & 0x3f != 0 || payload[7] != 0 {
            return false;
        }
        let option_words = (payload[0] & 0x3f) as usize;
        let Some(header_len) = GENEVE_HEADER_LEN.checked_add(option_words.saturating_mul(4)) else {
            return false;
        };
        if header_len > payload.len() {
            return false;
        }
        let protocol_type = u16::from_be_bytes([payload[2], payload[3]]);
        if protocol_type != GENEVE_PROTOCOL_TRANSPARENT_ETHERNET
            || payload[4..7].iter().all(|byte| *byte == 0)
        {
            return false;
        }
        ethernet_frame_payload(payload, header_len)
    }

    fn wireguard_observed_len_matches(payload_len: usize, wire_len: usize) -> bool {
        payload_len == wire_len
            || (wire_len > PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES
                && payload_len == PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES)
    }

    fn wireguard_payload(payload: &[u8]) -> bool {
        if payload.len() < 4 || payload.get(1..4) != Some(&[0, 0, 0]) {
            return false;
        }
        match payload[0] {
            1 => wireguard_observed_len_matches(payload.len(), WIREGUARD_HANDSHAKE_INITIATION_LEN),
            2 => payload.len() == WIREGUARD_HANDSHAKE_RESPONSE_LEN,
            3 => payload.len() == WIREGUARD_COOKIE_REPLY_LEN,
            4 => {
                payload.len() >= WIREGUARD_TRANSPORT_KEEPALIVE_LEN
                    && payload.len().is_multiple_of(16)
            }
            _ => false,
        }
    }

    fn http_request_path(payload: &[u8]) -> Option<&[u8]> {
        HTTP_REQUEST_METHODS.iter().find_map(|method| {
            let method_len = method.len();
            if payload.get(..method_len)? != *method || payload.get(method_len) != Some(&b' ') {
                return None;
            }
            let rest = payload.get(method_len + 1..)?;
            let end = rest
                .iter()
                .position(|byte| matches!(byte, b' ' | b'\r' | b'\n'))
                .unwrap_or(rest.len());
            let tail = rest.get(end..)?;
            (end > 0 && tail.starts_with(b" HTTP/")).then_some(&rest[..end])
        })
    }

    fn ssh_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        while offset < payload.len() {
            let remaining = &payload[offset..];
            let line_end = remaining.iter().position(|byte| *byte == b'\n');
            let (raw_line, complete) = match line_end {
                Some(line_end) => (&remaining[..line_end], true),
                None => (remaining, false),
            };
            let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
            if line.starts_with(b"SSH-") {
                let wire_len = raw_line.len() + usize::from(complete);
                return ssh_identification_line(line, wire_len);
            }
            if !complete || raw_line.contains(&0) {
                return false;
            }
            offset = offset.saturating_add(line_end.unwrap_or(remaining.len()) + 1);
        }
        false
    }

    fn ssh_identification_line(line: &[u8], wire_len: usize) -> bool {
        if wire_len > 255 || line.len() < b"SSH-2.0-a".len() {
            return false;
        }
        let rest = &line[4..];
        let Some(version_end) = rest.iter().position(|byte| *byte == b'-') else {
            return false;
        };
        let version = &rest[..version_end];
        if !matches!(version, b"2.0" | b"1.99") {
            return false;
        }
        let software_and_comments = &rest[version_end + 1..];
        let software_end = software_and_comments
            .iter()
            .position(|byte| *byte == b' ')
            .unwrap_or(software_and_comments.len());
        let software = &software_and_comments[..software_end];
        if software.is_empty()
            || !software
                .iter()
                .all(|byte| (0x21..=0x7e).contains(byte) && *byte != b'-')
        {
            return false;
        }
        software_and_comments[software_end..]
            .iter()
            .all(|byte| (0x20..=0x7e).contains(byte))
    }

    fn ldap_payload(payload: &[u8]) -> bool {
        if payload.len() < 7 || payload[0] != 0x30 {
            return false;
        }
        let Some((sequence_len, sequence_content_offset)) = ber_length(payload, 1) else {
            return false;
        };
        if !(5..=16_777_216).contains(&sequence_len)
            || payload.get(sequence_content_offset) != Some(&0x02)
        {
            return false;
        }
        let Some(sequence_end) = sequence_content_offset.checked_add(sequence_len) else {
            return false;
        };
        let Some((message_id_len, message_id_offset)) =
            ber_length(payload, sequence_content_offset + 1)
        else {
            return false;
        };
        if !(1..=4).contains(&message_id_len)
            || !ldap_message_id_payload(payload, message_id_offset, message_id_len)
        {
            return false;
        }
        let Some(protocol_op_offset) = message_id_offset.checked_add(message_id_len) else {
            return false;
        };
        if protocol_op_offset >= sequence_end {
            return false;
        }
        let Some(&protocol_op_tag) = payload.get(protocol_op_offset) else {
            return false;
        };
        if !ldap_protocol_op_tag(protocol_op_tag) {
            return false;
        }
        let Some((protocol_op_len, protocol_op_content_offset)) =
            ber_length(payload, protocol_op_offset + 1)
        else {
            return false;
        };
        if !ldap_protocol_op_length(protocol_op_tag, protocol_op_len) {
            return false;
        }
        let Some(protocol_op_end) = protocol_op_content_offset.checked_add(protocol_op_len) else {
            return false;
        };
        if protocol_op_end > sequence_end {
            return false;
        }
        if protocol_op_end < sequence_end {
            payload
                .get(protocol_op_end)
                .is_none_or(|next_tag| *next_tag == 0xa0)
        } else {
            true
        }
    }

    fn ldap_message_id_payload(payload: &[u8], offset: usize, len: usize) -> bool {
        let Some(value) = payload.get(offset..offset.saturating_add(len)) else {
            return false;
        };
        if value.is_empty() || value[0] & 0x80 != 0 {
            return false;
        }
        !(len > 1 && value[0] == 0 && value[1] & 0x80 == 0)
    }

    fn ldap_protocol_op_tag(tag: u8) -> bool {
        matches!(
            tag,
            0x42 | 0x4a
                | 0x50
                | 0x60
                | 0x61
                | 0x63
                | 0x64
                | 0x65
                | 0x66
                | 0x67
                | 0x68
                | 0x69
                | 0x6b
                | 0x6c
                | 0x6d
                | 0x6e
                | 0x6f
                | 0x73
                | 0x77
                | 0x78
                | 0x79
        )
    }

    fn ldap_protocol_op_length(tag: u8, len: usize) -> bool {
        match tag {
            0x42 => len == 0,
            0x4a => (1..=65_535).contains(&len),
            0x50 => (1..=4).contains(&len),
            _ => (1..=16_777_216).contains(&len),
        }
    }

    fn ber_length(payload: &[u8], offset: usize) -> Option<(usize, usize)> {
        let first = *payload.get(offset)?;
        if first & 0x80 == 0 {
            return Some((first as usize, offset + 1));
        }
        let length_bytes = (first & 0x7f) as usize;
        if length_bytes == 0 || length_bytes > 4 {
            return None;
        }
        let mut len = 0_usize;
        for byte in payload.get(offset + 1..offset + 1 + length_bytes)? {
            len = len.checked_shl(8)?.checked_add(*byte as usize)?;
        }
        Some((len, offset + 1 + length_bytes))
    }

    fn ntp_payload(payload: &[u8]) -> bool {
        if payload.len() < 48 {
            return false;
        }
        let version = (payload[0] >> 3) & 0x07;
        let mode = payload[0] & 0x07;
        if !(3..=4).contains(&version) || !matches!(mode, 3 | 4 | 5) {
            return false;
        }
        let stratum = payload[1];
        if mode == 3 {
            stratum == 0
        } else {
            stratum <= 16
        }
    }

    fn radius_payload(payload: &[u8]) -> bool {
        if payload.len() < 20 || !radius_code(payload[0]) {
            return false;
        }
        let packet_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        if !(20..=4096).contains(&packet_len) {
            return false;
        }
        let allow_truncated =
            packet_len > payload.len() && payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
        if packet_len > payload.len() && !allow_truncated {
            return false;
        }

        let available_end = packet_len.min(payload.len());
        let mut offset = 20_usize;
        let mut attribute_count = 0_usize;
        while offset < available_end {
            if available_end - offset < 2 {
                return allow_truncated;
            }
            let attribute_len = payload[offset + 1] as usize;
            if attribute_len < 2 {
                return false;
            }
            let Some(attribute_end) = offset.checked_add(attribute_len) else {
                return false;
            };
            if attribute_end > available_end {
                return allow_truncated;
            }
            attribute_count += 1;
            offset = attribute_end;
        }
        attribute_count > 0
    }

    fn radius_code(code: u8) -> bool {
        matches!(
            code,
            1 | 2 | 3 | 4 | 5 | 11 | 12 | 13 | 40 | 41 | 42 | 43 | 44 | 45
        )
    }

    fn tacacs_payload(payload: &[u8]) -> bool {
        const TACACS_HEADER_LEN: usize = 12;
        const TACACS_MAX_BODY_PREFIX_HINT: usize = 1_048_576;

        if payload.len() < TACACS_HEADER_LEN {
            return false;
        }
        let version = payload[0];
        if version & 0xf0 != 0xc0 || version & 0x0f > 1 {
            return false;
        }
        if !matches!(payload[1], 1 | 2 | 3) {
            return false;
        }
        if payload[2] == 0 {
            return false;
        }
        if payload[3] & !0x05 != 0 {
            return false;
        }

        let body_len =
            u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]) as usize;
        if body_len == 0 || body_len > TACACS_MAX_BODY_PREFIX_HINT {
            return false;
        }
        let Some(total_len) = TACACS_HEADER_LEN.checked_add(body_len) else {
            return false;
        };
        total_len <= payload.len()
            || (payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES
                && total_len > PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES)
    }

    fn bgp_payload(payload: &[u8]) -> bool {
        const BGP_HEADER_LEN: usize = 19;

        if payload.len() < BGP_HEADER_LEN || !payload[..16].iter().all(|byte| *byte == 0xff) {
            return false;
        }
        let message_len = u16::from_be_bytes([payload[16], payload[17]]) as usize;
        if !(BGP_HEADER_LEN..=4096).contains(&message_len)
            || !matches!(payload[18], 1 | 2 | 3 | 4 | 5)
        {
            return false;
        }
        message_len <= payload.len()
            || (payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES
                && message_len > PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES)
    }

    fn bfd_payload(payload: &[u8]) -> bool {
        const BFD_CONTROL_HEADER_MIN_LEN: usize = 24;

        if payload.len() < BFD_CONTROL_HEADER_MIN_LEN {
            return false;
        }
        if payload[0] >> 5 != 1 || payload[1] & 0x01 != 0 || payload[2] == 0 {
            return false;
        }
        let packet_len = payload[3] as usize;
        if packet_len < BFD_CONTROL_HEADER_MIN_LEN {
            return false;
        }
        if payload[4..8].iter().all(|byte| *byte == 0) {
            return false;
        }
        packet_len <= payload.len()
            || (payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES
                && packet_len > PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES)
    }

    fn kerberos_payload(payload: &[u8], protocol: Option<TransportProtocol>) -> bool {
        match protocol {
            Some(TransportProtocol::Udp) => kerberos_message_payload(
                payload,
                payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES,
            ),
            Some(TransportProtocol::Tcp) => kerberos_tcp_payload(payload),
            None => {
                kerberos_message_payload(
                    payload,
                    payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES,
                ) || kerberos_tcp_payload(payload)
            }
            Some(
                TransportProtocol::Any
                | TransportProtocol::IpInIp
                | TransportProtocol::Icmp
                | TransportProtocol::Sctp
                | TransportProtocol::Ipv6Encap
                | TransportProtocol::Gre
                | TransportProtocol::Esp
                | TransportProtocol::Ah,
            ) => false,
        }
    }

    fn kerberos_tcp_payload(payload: &[u8]) -> bool {
        if payload.len() < 8 {
            return false;
        }
        let message_len =
            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        if !(4..=1_048_576).contains(&message_len) {
            return false;
        }
        let available = payload.len().saturating_sub(4);
        let message_prefix_len = available.min(message_len);
        let allow_truncated =
            available < message_len && payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
        kerberos_message_payload(&payload[4..4 + message_prefix_len], allow_truncated)
    }

    fn kerberos_message_payload(payload: &[u8], allow_truncated: bool) -> bool {
        if payload.len() < 8 {
            return false;
        }
        let Some(expected_msg_type) = kerberos_application_message_type(payload[0]) else {
            return false;
        };
        let Some((message_len, message_offset)) = ber_length(payload, 1) else {
            return false;
        };
        if !(6..=1_048_576).contains(&message_len) {
            return false;
        }
        let Some(message_end) = message_offset.checked_add(message_len) else {
            return false;
        };
        if message_end > payload.len() && !allow_truncated {
            return false;
        }
        if payload.get(message_offset) != Some(&0x30) {
            return false;
        }
        let Some((sequence_len, sequence_offset)) = ber_length(payload, message_offset + 1) else {
            return false;
        };
        let Some(sequence_end) = sequence_offset.checked_add(sequence_len) else {
            return false;
        };
        if sequence_end > message_end {
            return false;
        }
        if sequence_end > payload.len() && !allow_truncated {
            return false;
        }
        let sequence_available_end = sequence_end.min(payload.len());
        let Some(sequence) = payload.get(sequence_offset..sequence_available_end) else {
            return false;
        };
        kerberos_context_integer(sequence, 0xa1) == Some(5)
            && kerberos_context_integer(sequence, 0xa2) == Some(expected_msg_type)
    }

    fn kerberos_application_message_type(tag: u8) -> Option<u32> {
        match tag {
            0x6a => Some(10),
            0x6b => Some(11),
            0x6c => Some(12),
            0x6d => Some(13),
            0x6e => Some(14),
            0x6f => Some(15),
            0x74 => Some(20),
            0x75 => Some(21),
            0x76 => Some(22),
            0x7e => Some(30),
            _ => None,
        }
    }

    fn kerberos_context_integer(payload: &[u8], tag: u8) -> Option<u32> {
        let mut offset = 0_usize;
        while offset < payload.len() {
            let tag_offset = payload
                .get(offset..)?
                .iter()
                .position(|candidate| *candidate == tag)?
                + offset;
            let (field_len, field_offset) = ber_length(payload, tag_offset + 1)?;
            let field_end = field_offset.checked_add(field_len)?;
            if field_end > payload.len() {
                return None;
            }
            if payload.get(field_offset) != Some(&0x02) {
                offset = tag_offset + 1;
                continue;
            }
            let (integer_len, integer_offset) = ber_length(payload, field_offset + 1)?;
            let integer_end = integer_offset.checked_add(integer_len)?;
            if integer_len == 0 || integer_len > 4 || integer_end > field_end {
                return None;
            }
            let bytes = payload.get(integer_offset..integer_end)?;
            if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
                return None;
            }
            let mut value = 0_u32;
            for byte in bytes {
                value = value.checked_shl(8)?.checked_add(*byte as u32)?;
            }
            return Some(value);
        }
        None
    }

    fn snmp_payload(payload: &[u8]) -> bool {
        if payload.len() < 10 || payload[0] != 0x30 {
            return false;
        }
        let Some((message_len, message_offset)) = ber_length(payload, 1) else {
            return false;
        };
        if !(6..=16_777_216).contains(&message_len) {
            return false;
        }
        let Some(message_end) = message_offset.checked_add(message_len) else {
            return false;
        };
        if message_end > payload.len() && payload.len() < PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES {
            return false;
        }

        let Some((version_len, version_offset)) =
            snmp_element(payload, message_offset, message_end, 0x02)
        else {
            return false;
        };
        if !(1..=4).contains(&version_len) {
            return false;
        }
        let Some(version_end) = version_offset.checked_add(version_len) else {
            return false;
        };
        if version_end > payload.len() || version_end > message_end {
            return false;
        }
        let Some(version) = snmp_nonnegative_integer(payload, version_offset, version_len) else {
            return false;
        };
        if version > 3 {
            return false;
        }

        match version {
            0..=2 => snmp_community_message(payload, version_end, message_end),
            3 => snmp_v3_message(payload, version_end, message_end),
            _ => false,
        }
    }

    fn snmp_community_message(payload: &[u8], offset: usize, message_end: usize) -> bool {
        let Some((community_len, community_offset)) =
            snmp_element(payload, offset, message_end, 0x04)
        else {
            return false;
        };
        if community_len > 255 {
            return false;
        }
        let Some(pdu_offset) = community_offset.checked_add(community_len) else {
            return false;
        };
        if pdu_offset > payload.len() || pdu_offset > message_end {
            return false;
        }
        snmp_pdu(payload, pdu_offset, message_end)
    }

    fn snmp_v3_message(payload: &[u8], offset: usize, message_end: usize) -> bool {
        let Some((header_len, header_offset)) = snmp_element(payload, offset, message_end, 0x30)
        else {
            return false;
        };
        if !(1..=65_535).contains(&header_len) {
            return false;
        }
        let Some(security_offset) = header_offset.checked_add(header_len) else {
            return false;
        };
        if security_offset > payload.len() || security_offset > message_end {
            return false;
        }

        let Some((security_len, security_content_offset)) =
            snmp_element(payload, security_offset, message_end, 0x04)
        else {
            return false;
        };
        if security_len > 65_535 {
            return false;
        }
        let Some(scoped_pdu_offset) = security_content_offset.checked_add(security_len) else {
            return false;
        };
        if scoped_pdu_offset > payload.len() || scoped_pdu_offset > message_end {
            return false;
        }

        let Some(&scoped_pdu_tag) = payload.get(scoped_pdu_offset) else {
            return false;
        };
        if !matches!(scoped_pdu_tag, 0x30 | 0x04) {
            return false;
        }
        let Some((scoped_pdu_len, scoped_pdu_content_offset)) =
            snmp_element(payload, scoped_pdu_offset, message_end, scoped_pdu_tag)
        else {
            return false;
        };
        scoped_pdu_len > 0
            && scoped_pdu_content_offset <= payload.len()
            && scoped_pdu_content_offset <= message_end
    }

    fn snmp_pdu(payload: &[u8], offset: usize, message_end: usize) -> bool {
        let Some(&tag) = payload.get(offset) else {
            return false;
        };
        if !(0xa0..=0xa8).contains(&tag) {
            return false;
        }
        let Some((pdu_len, pdu_content_offset)) = snmp_element(payload, offset, message_end, tag)
        else {
            return false;
        };
        (1..=16_777_216).contains(&pdu_len)
            && pdu_content_offset <= payload.len()
            && pdu_content_offset <= message_end
    }

    fn snmp_element(
        payload: &[u8],
        offset: usize,
        message_end: usize,
        expected_tag: u8,
    ) -> Option<(usize, usize)> {
        if offset >= message_end || payload.get(offset) != Some(&expected_tag) {
            return None;
        }
        let (len, content_offset) = ber_length(payload, offset.checked_add(1)?)?;
        let content_end = content_offset.checked_add(len)?;
        if content_offset > message_end || content_end > message_end {
            return None;
        }
        if content_offset > payload.len() {
            return None;
        }
        Some((len, content_offset))
    }

    fn snmp_nonnegative_integer(payload: &[u8], offset: usize, len: usize) -> Option<u32> {
        let value = payload.get(offset..offset.checked_add(len)?)?;
        if value.is_empty() || value[0] & 0x80 != 0 {
            return None;
        }
        let mut integer = 0_u32;
        for byte in value {
            integer = integer.checked_shl(8)?.checked_add(*byte as u32)?;
        }
        Some(integer)
    }

    fn syslog_payload(payload: &[u8], protocol: Option<TransportProtocol>) -> bool {
        match protocol {
            None | Some(TransportProtocol::Tcp) => {
                syslog_message_payload(payload) || syslog_octet_counted_payload(payload)
            }
            Some(TransportProtocol::Udp) => syslog_message_payload(payload),
            Some(
                TransportProtocol::Any
                | TransportProtocol::IpInIp
                | TransportProtocol::Icmp
                | TransportProtocol::Sctp
                | TransportProtocol::Ipv6Encap
                | TransportProtocol::Gre
                | TransportProtocol::Esp
                | TransportProtocol::Ah,
            ) => false,
        }
    }

    fn syslog_octet_counted_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        while offset < payload.len() && payload[offset].is_ascii_digit() {
            offset += 1;
            if offset > 6 {
                return false;
            }
        }
        if offset == 0 || payload.get(offset) != Some(&b' ') || payload[0] == b'0' {
            return false;
        }
        let frame_len = decimal_usize(&payload[..offset]).unwrap_or(0);
        if frame_len == 0 {
            return false;
        }
        let message = &payload[offset + 1..];
        if message.len() > frame_len {
            return false;
        }
        syslog_message_payload(message)
    }

    fn syslog_message_payload(payload: &[u8]) -> bool {
        let Some(offset) = syslog_priority_prefix(payload) else {
            return false;
        };
        let message = &payload[offset..];
        syslog_rfc5424_message(message) || syslog_rfc3164_message(message)
    }

    fn syslog_priority_prefix(payload: &[u8]) -> Option<usize> {
        if payload.first() != Some(&b'<') {
            return None;
        }
        let mut offset = 1_usize;
        while offset < payload.len() && payload[offset].is_ascii_digit() {
            offset += 1;
            if offset > 4 {
                return None;
            }
        }
        if offset == 1 || payload.get(offset) != Some(&b'>') {
            return None;
        }
        let priority = decimal_usize(&payload[1..offset])?;
        (priority <= 191).then_some(offset + 1)
    }

    fn syslog_rfc5424_message(payload: &[u8]) -> bool {
        let Some(mut offset) = payload.strip_prefix(b"1 ").map(|_| 2_usize) else {
            return false;
        };
        let Some((timestamp, next_offset)) = syslog_next_token(payload, offset, 64) else {
            return false;
        };
        if !syslog_rfc5424_timestamp(timestamp) {
            return false;
        }
        offset = next_offset;
        for max_len in [255_usize, 48, 128, 32] {
            let Some((token, next_offset)) = syslog_next_token(payload, offset, max_len) else {
                return false;
            };
            if !syslog_printable_token(token) {
                return false;
            }
            offset = next_offset;
        }
        matches!(payload.get(offset), Some(b'-' | b'['))
    }

    fn syslog_rfc5424_timestamp(token: &[u8]) -> bool {
        if token == b"-" {
            return true;
        }
        token.len() >= b"2000-01-01T00:00:00Z".len()
            && token.contains(&b'T')
            && token.iter().all(|byte| {
                byte.is_ascii_digit() || matches!(byte, b'-' | b':' | b'.' | b'T' | b'Z' | b'+')
            })
    }

    fn syslog_next_token(payload: &[u8], offset: usize, max_len: usize) -> Option<(&[u8], usize)> {
        let rest = payload.get(offset..)?;
        let len = rest.iter().position(|byte| *byte == b' ')?;
        if len == 0 || len > max_len {
            return None;
        }
        Some((&rest[..len], offset + len + 1))
    }

    fn syslog_printable_token(token: &[u8]) -> bool {
        token == b"-"
            || token
                .iter()
                .all(|byte| (0x21..=0x7e).contains(byte) && *byte != b']')
    }

    fn syslog_rfc3164_message(payload: &[u8]) -> bool {
        if payload.len() < 17 || !syslog_month(payload.get(..3).unwrap_or_default()) {
            return false;
        }
        if payload.get(3) != Some(&b' ') || payload.get(6) != Some(&b' ') {
            return false;
        }
        let day = match (payload[4], payload[5]) {
            (b' ', second) if second.is_ascii_digit() => (second - b'0') as u8,
            (first, second) if first.is_ascii_digit() && second.is_ascii_digit() => {
                (first - b'0') * 10 + (second - b'0')
            }
            _ => return false,
        };
        if !(1..=31).contains(&day) || !syslog_time(payload.get(7..15).unwrap_or_default()) {
            return false;
        }
        if payload.get(15) != Some(&b' ') {
            return false;
        }
        let Some((hostname, message_offset)) = syslog_next_token(payload, 16, 255) else {
            return false;
        };
        syslog_printable_token(hostname)
            && payload
                .get(message_offset..)
                .is_some_and(|message| message.iter().any(|byte| !byte.is_ascii_control()))
    }

    fn syslog_month(value: &[u8]) -> bool {
        matches!(
            value,
            b"Jan"
                | b"Feb"
                | b"Mar"
                | b"Apr"
                | b"May"
                | b"Jun"
                | b"Jul"
                | b"Aug"
                | b"Sep"
                | b"Oct"
                | b"Nov"
                | b"Dec"
        )
    }

    fn syslog_time(value: &[u8]) -> bool {
        if value.len() != 8 || value.get(2) != Some(&b':') || value.get(5) != Some(&b':') {
            return false;
        }
        let Some(hour) = decimal_u8(&value[0..2]) else {
            return false;
        };
        let Some(minute) = decimal_u8(&value[3..5]) else {
            return false;
        };
        let Some(second) = decimal_u8(&value[6..8]) else {
            return false;
        };
        hour <= 23 && minute <= 59 && second <= 59
    }

    fn nfs_payload(payload: &[u8], protocol: Option<TransportProtocol>) -> bool {
        match protocol {
            None => nfs_rpc_payload(payload, false) || nfs_tcp_payload(payload),
            Some(TransportProtocol::Tcp) => nfs_tcp_payload(payload),
            Some(TransportProtocol::Udp) => nfs_rpc_payload(payload, false),
            Some(
                TransportProtocol::Any
                | TransportProtocol::IpInIp
                | TransportProtocol::Icmp
                | TransportProtocol::Sctp
                | TransportProtocol::Ipv6Encap
                | TransportProtocol::Gre
                | TransportProtocol::Esp
                | TransportProtocol::Ah,
            ) => false,
        }
    }

    fn nfs_tcp_payload(payload: &[u8]) -> bool {
        const RPC_TCP_RECORD_LEN_MASK: u32 = 0x7fff_ffff;

        let Some(record) = read_u32_be(payload, 0) else {
            return false;
        };
        let fragment_len = (record & RPC_TCP_RECORD_LEN_MASK) as usize;
        if !(40..=16_777_216).contains(&fragment_len) {
            return false;
        }
        let available = payload.len().saturating_sub(4);
        let message_prefix_len = available.min(fragment_len);
        let allow_truncated =
            available < fragment_len && payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
        if available < fragment_len && !allow_truncated {
            return false;
        }
        nfs_rpc_payload(&payload[4..4 + message_prefix_len], allow_truncated)
    }

    fn nfs_rpc_payload(payload: &[u8], allow_truncated: bool) -> bool {
        const ONC_RPC_CALL: u32 = 0;
        const ONC_RPC_VERSION: u32 = 2;
        const NFS_PROGRAM: u32 = 100_003;

        if payload.len() < 24 {
            return false;
        }
        let xid = read_u32_be(payload, 0).unwrap_or(0);
        let message_type = read_u32_be(payload, 4).unwrap_or(u32::MAX);
        let rpc_version = read_u32_be(payload, 8).unwrap_or(0);
        let program = read_u32_be(payload, 12).unwrap_or(0);
        let version = read_u32_be(payload, 16).unwrap_or(0);
        let procedure = read_u32_be(payload, 20).unwrap_or(u32::MAX);
        if xid == 0
            || message_type != ONC_RPC_CALL
            || rpc_version != ONC_RPC_VERSION
            || program != NFS_PROGRAM
            || !matches!(version, 2..=4)
            || !nfs_procedure(version, procedure)
        {
            return false;
        }
        let Some(credential_end) = rpc_auth_opaque_end(payload, 24, allow_truncated) else {
            return false;
        };
        if credential_end >= payload.len() {
            return allow_truncated;
        }
        rpc_auth_opaque_end(payload, credential_end, allow_truncated).is_some()
    }

    fn nfs_procedure(version: u32, procedure: u32) -> bool {
        match version {
            2 | 3 => procedure <= 21,
            4 => procedure <= 2,
            _ => false,
        }
    }

    fn rpc_auth_opaque_end(payload: &[u8], offset: usize, allow_truncated: bool) -> Option<usize> {
        const RPC_AUTH_MAX_BYTES: usize = 400;

        let auth_len_offset = offset.checked_add(4)?;
        let len_offset = offset.checked_add(8)?;
        if len_offset > payload.len() {
            return allow_truncated.then_some(payload.len());
        }
        let len = read_u32_be(payload, auth_len_offset)? as usize;
        if len > RPC_AUTH_MAX_BYTES {
            return None;
        }
        let padded_len = len.checked_add(3)? & !3;
        let end = len_offset.checked_add(padded_len)?;
        if end > payload.len() {
            return allow_truncated.then_some(payload.len());
        }
        Some(end)
    }

    fn decimal_usize(value: &[u8]) -> Option<usize> {
        let mut parsed = 0_usize;
        for byte in value {
            if !byte.is_ascii_digit() {
                return None;
            }
            parsed = parsed
                .checked_mul(10)?
                .checked_add((byte - b'0') as usize)?;
        }
        Some(parsed)
    }

    fn decimal_u8(value: &[u8]) -> Option<u8> {
        let parsed = decimal_usize(value)?;
        u8::try_from(parsed).ok()
    }

    fn smb_payload(payload: &[u8]) -> bool {
        smb_message_payload(payload, 0, None) || smb_direct_tcp_payload(payload)
    }

    fn smb_direct_tcp_payload(payload: &[u8]) -> bool {
        if payload.len() < 8 || payload[0] != 0 {
            return false;
        }
        let message_len =
            ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | payload[3] as usize;
        if !(32..=16_777_215).contains(&message_len) {
            return false;
        }
        if payload.len() > message_len.saturating_add(4) {
            return false;
        }
        smb_message_payload(payload, 4, Some(message_len))
    }

    fn smb_message_payload(payload: &[u8], offset: usize, declared_len: Option<usize>) -> bool {
        let Some(protocol_id) = payload.get(offset..offset.saturating_add(4)) else {
            return false;
        };
        match protocol_id {
            [0xff, b'S', b'M', b'B'] => smb1_header_payload(payload, offset, declared_len),
            [0xfe, b'S', b'M', b'B'] => smb2_header_payload(payload, offset, declared_len),
            _ => false,
        }
    }

    fn smb1_header_payload(payload: &[u8], offset: usize, declared_len: Option<usize>) -> bool {
        if declared_len.is_some_and(|len| len < 32) {
            return false;
        }
        let Some(command) = payload.get(offset.saturating_add(4)) else {
            return false;
        };
        if !smb1_command(*command) {
            return false;
        }
        payload.len() >= offset.saturating_add(32)
    }

    fn smb1_command(command: u8) -> bool {
        matches!(
            command,
            0x04 | 0x06
                | 0x07
                | 0x08
                | 0x0a
                | 0x0b
                | 0x0c
                | 0x0d
                | 0x0e
                | 0x0f
                | 0x10
                | 0x11
                | 0x12
                | 0x1a
                | 0x1d
                | 0x23
                | 0x24
                | 0x25
                | 0x26
                | 0x2d
                | 0x2e
                | 0x2f
                | 0x32
                | 0x33
                | 0x34
                | 0x35
                | 0x70
                | 0x71
                | 0x72
                | 0x73
                | 0x74
                | 0x75
                | 0x80
                | 0xa0
                | 0xa2
                | 0xa4
                | 0xa5
                | 0xc0
                | 0xd8
        )
    }

    fn smb2_header_payload(payload: &[u8], offset: usize, declared_len: Option<usize>) -> bool {
        if declared_len.is_some_and(|len| len < 64) {
            return false;
        }
        let Some(structure_size) = read_u16_le(payload, offset.saturating_add(4)) else {
            return false;
        };
        if structure_size != 64 {
            return false;
        }
        if let Some(command) = read_u16_le(payload, offset.saturating_add(12)) {
            if command > 0x12 {
                return false;
            }
        }
        if let Some(flags) = read_u32_le(payload, offset.saturating_add(16)) {
            let known_flags = 0x0000_007f | 0x1000_0000 | 0x2000_0000;
            if flags & !known_flags != 0 {
                return false;
            }
        }
        true
    }

    fn rdp_payload(payload: &[u8]) -> bool {
        if payload.len() < 7 || payload[0] != 0x03 || payload[1] != 0x00 {
            return false;
        }
        let length = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        if !(7..=65_535).contains(&length) || payload.len() > length {
            return false;
        }
        let x224_len = payload[4] as usize;
        let Some(tpdu_end) = 5_usize.checked_add(x224_len) else {
            return false;
        };
        if x224_len < 2 || tpdu_end > length {
            return false;
        }
        match payload[5] {
            0xe0 | 0xd0 => rdp_x224_connection_tpdu(payload, x224_len),
            0xf0 => rdp_x224_data_tpdu(payload, x224_len),
            _ => false,
        }
    }

    fn rdp_x224_connection_tpdu(payload: &[u8], x224_len: usize) -> bool {
        if x224_len < 6 || payload.len() < 11 {
            return false;
        }
        let dst_ref = u16::from_be_bytes([payload[6], payload[7]]);
        let src_ref = u16::from_be_bytes([payload[8], payload[9]]);
        let class_options = payload[10];
        if payload[5] == 0xe0 && (dst_ref != 0 || src_ref != 0 || class_options != 0) {
            return false;
        }
        class_options & 0x0f == 0
    }

    fn rdp_x224_data_tpdu(payload: &[u8], x224_len: usize) -> bool {
        x224_len == 2 && payload.len() >= 7 && payload[6] & 0x7f == 0
    }

    fn zookeeper_payload(payload: &[u8]) -> bool {
        zookeeper_four_letter_command(payload) || zookeeper_connect_request(payload)
    }

    fn zookeeper_four_letter_command(payload: &[u8]) -> bool {
        let command = match payload {
            [a, b, c, d] => [*a, *b, *c, *d],
            [a, b, c, d, b'\n'] => [*a, *b, *c, *d],
            [a, b, c, d, b'\r', b'\n'] => [*a, *b, *c, *d],
            _ => return false,
        };
        zookeeper_known_four_letter_command(&command)
    }

    fn zookeeper_known_four_letter_command(command: &[u8; 4]) -> bool {
        let commands: [&[u8; 4]; 17] = [
            b"ruok", b"stat", b"srvr", b"mntr", b"conf", b"cons", b"dump", b"envi", b"wchs",
            b"wchc", b"wchp", b"isro", b"srst", b"crst", b"dirs", b"gtmk", b"stmk",
        ];
        commands
            .iter()
            .any(|known| command.eq_ignore_ascii_case(*known))
    }

    fn zookeeper_connect_request(payload: &[u8]) -> bool {
        if payload.len() < 33 {
            return false;
        }
        let Some(frame_len) = read_u32_be(payload, 0).map(|value| value as usize) else {
            return false;
        };
        let Some(frame_end) = 4_usize.checked_add(frame_len) else {
            return false;
        };
        if !(29..=4096).contains(&frame_len) || payload.len() != frame_end {
            return false;
        }
        let Some(protocol_version) = read_u32_be(payload, 4) else {
            return false;
        };
        if protocol_version != 0 {
            return false;
        }
        let Some(timeout_ms) = read_u32_be(payload, 16) else {
            return false;
        };
        if !(1..=3_600_000).contains(&timeout_ms) {
            return false;
        }
        let Some(passwd_len) = read_u32_be(payload, 28).map(|value| value as usize) else {
            return false;
        };
        if passwd_len > 64 {
            return false;
        }
        let Some(read_only_offset) = 32_usize.checked_add(passwd_len) else {
            return false;
        };
        if read_only_offset.checked_add(1) != Some(frame_end) {
            return false;
        }
        matches!(payload.get(read_only_offset).copied(), Some(0 | 1))
    }

    fn postgres_payload(payload: &[u8]) -> bool {
        postgres_startup_payload(payload) || postgres_frontend_message_payload(payload)
    }

    fn postgres_startup_payload(payload: &[u8]) -> bool {
        if payload.len() < 8 {
            return false;
        }
        let length = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        (8..=10_000).contains(&length) && matches!(code, 196_608 | 80_877_102 | 80_877_103)
    }

    fn postgres_frontend_message_payload(payload: &[u8]) -> bool {
        if payload.len() < 5 {
            return false;
        }
        let Some(length) = read_u32_be(payload, 1).map(|length| length as usize) else {
            return false;
        };
        if !(4..=10_000).contains(&length) {
            return false;
        }
        let Some(frame_end) = 1_usize.checked_add(length) else {
            return false;
        };
        let Some(frame) = payload.get(..frame_end) else {
            return false;
        };
        let body = &frame[5..];
        match payload[0] {
            b'Q' => postgres_query_message_payload(body),
            b'P' => postgres_parse_message_payload(body),
            b'B' => postgres_bind_message_payload(body),
            b'C' | b'D' => postgres_named_portal_or_statement_payload(body),
            b'E' => postgres_execute_message_payload(body),
            b'p' => postgres_password_message_payload(body),
            b'H' | b'S' | b'X' => body.is_empty(),
            _ => false,
        }
    }

    fn postgres_query_message_payload(body: &[u8]) -> bool {
        body.len() >= 2 && body.last() == Some(&0) && postgres_nonempty_cstring(body, 0)
    }

    fn postgres_parse_message_payload(body: &[u8]) -> bool {
        let Some(after_statement_name) = postgres_cstring_end(body, 0) else {
            return false;
        };
        let Some(after_query) = postgres_cstring_end(body, after_statement_name) else {
            return false;
        };
        if after_query <= after_statement_name + 1 {
            return false;
        }
        let Some(parameter_count) = read_u16_be(body, after_query).map(|count| count as usize)
        else {
            return false;
        };
        after_query
            .checked_add(2)
            .and_then(|offset| offset.checked_add(parameter_count.checked_mul(4)?))
            == Some(body.len())
    }

    fn postgres_bind_message_payload(body: &[u8]) -> bool {
        let Some(after_portal) = postgres_cstring_end(body, 0) else {
            return false;
        };
        let Some(after_statement) = postgres_cstring_end(body, after_portal) else {
            return false;
        };
        body.get(after_statement..after_statement.saturating_add(2))
            .is_some()
    }

    fn postgres_named_portal_or_statement_payload(body: &[u8]) -> bool {
        let Some((&kind, name)) = body.split_first() else {
            return false;
        };
        matches!(kind, b'P' | b'S') && postgres_cstring_end(name, 0) == Some(name.len())
    }

    fn postgres_execute_message_payload(body: &[u8]) -> bool {
        let Some(after_portal) = postgres_cstring_end(body, 0) else {
            return false;
        };
        after_portal.checked_add(4) == Some(body.len())
    }

    fn postgres_password_message_payload(body: &[u8]) -> bool {
        postgres_nonempty_cstring(body, 0)
    }

    fn postgres_nonempty_cstring(payload: &[u8], offset: usize) -> bool {
        postgres_cstring_end(payload, offset).is_some_and(|end| end > offset + 1)
    }

    fn postgres_cstring_end(payload: &[u8], offset: usize) -> Option<usize> {
        let tail = payload.get(offset..)?;
        let terminator = tail.iter().position(|byte| *byte == 0)?;
        Some(offset + terminator + 1)
    }

    fn mysql_payload(payload: &[u8]) -> bool {
        mysql_initial_handshake_payload(payload) || mysql_command_packet_payload(payload)
    }

    const MYSQL_MAX_PACKET_PAYLOAD_LEN: usize = 16_777_215;
    const MYSQL_MAX_PACKET_SEQUENCE_ID: u8 = 64;

    fn mysql_initial_handshake_payload(payload: &[u8]) -> bool {
        const HANDSHAKE_V10_MIN_PAYLOAD_LEN: usize = 17;

        if payload.len() < 5 || payload.get(3) != Some(&0) {
            return false;
        }
        let Some(payload_len) = mysql_packet_payload_len(payload, 0) else {
            return false;
        };
        if payload_len < HANDSHAKE_V10_MIN_PAYLOAD_LEN {
            return false;
        }
        let Some(packet_end) = 4_usize.checked_add(payload_len) else {
            return false;
        };
        if payload.len() > packet_end {
            return false;
        }
        let Some(body) = mysql_observed_packet_body(payload, 0, payload_len) else {
            return false;
        };
        mysql_handshake_v10_payload_prefix(body, payload_len)
    }

    fn mysql_command_packet_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut packet_count = 0_usize;
        while offset < payload.len() {
            match mysql_command_packet(payload, offset) {
                Some(MysqlCommandPacketParse::Complete(next_offset)) => {
                    packet_count += 1;
                    if packet_count > 16 {
                        return false;
                    }
                    offset = next_offset;
                }
                Some(MysqlCommandPacketParse::IncompleteBeforeCommand) => {
                    return packet_count > 0;
                }
                Some(MysqlCommandPacketParse::IncompleteAfterCommand) => {
                    return true;
                }
                None => return false,
            }
        }
        packet_count > 0
    }

    enum MysqlCommandPacketParse {
        Complete(usize),
        IncompleteBeforeCommand,
        IncompleteAfterCommand,
    }

    fn mysql_command_packet(payload: &[u8], offset: usize) -> Option<MysqlCommandPacketParse> {
        if payload.len().saturating_sub(offset) < 4 {
            return Some(MysqlCommandPacketParse::IncompleteBeforeCommand);
        }
        let payload_len = mysql_packet_payload_len(payload, offset)?;
        let sequence_id = *payload.get(offset.checked_add(3)?)?;
        if sequence_id > MYSQL_MAX_PACKET_SEQUENCE_ID {
            return None;
        }
        let body_offset = offset.checked_add(4)?;
        if payload.len() <= body_offset {
            return Some(MysqlCommandPacketParse::IncompleteBeforeCommand);
        }
        let packet_end = body_offset.checked_add(payload_len)?;
        let body_end = payload.len().min(packet_end);
        let body = payload.get(body_offset..body_end)?;
        if !mysql_command_packet_body(payload_len, body) {
            return None;
        }
        if payload.len() < packet_end {
            Some(MysqlCommandPacketParse::IncompleteAfterCommand)
        } else {
            Some(MysqlCommandPacketParse::Complete(packet_end))
        }
    }

    fn mysql_packet_payload_len(payload: &[u8], offset: usize) -> Option<usize> {
        let payload_len = read_u24_le(payload, offset)?;
        (1..=MYSQL_MAX_PACKET_PAYLOAD_LEN)
            .contains(&payload_len)
            .then_some(payload_len)
    }

    fn mysql_observed_packet_body(
        payload: &[u8],
        offset: usize,
        payload_len: usize,
    ) -> Option<&[u8]> {
        let body_offset = offset.checked_add(4)?;
        if payload.len() <= body_offset {
            return None;
        }
        let packet_end = body_offset.checked_add(payload_len)?;
        payload.get(body_offset..payload.len().min(packet_end))
    }

    fn mysql_handshake_v10_payload_prefix(body: &[u8], payload_len: usize) -> bool {
        if body.first() != Some(&10) {
            return false;
        };
        let version = &body[1..];
        if version.is_empty() {
            return false;
        }
        let Some(version_end) = version.iter().position(|byte| *byte == 0) else {
            return version.iter().all(mysql_server_version_byte);
        };
        if version_end == 0 || !version[..version_end].iter().all(mysql_server_version_byte) {
            return false;
        }
        let post_version = 1 + version_end + 1;
        let Some(filler_offset) = post_version
            .checked_add(4)
            .and_then(|offset| offset.checked_add(8))
        else {
            return false;
        };
        if payload_len <= filler_offset {
            return false;
        }
        body.get(filler_offset).is_none_or(|filler| *filler == 0)
    }

    fn mysql_server_version_byte(byte: &u8) -> bool {
        matches!(*byte, 0x20..=0x7e)
    }

    fn mysql_command_packet_body(payload_len: usize, body: &[u8]) -> bool {
        let Some((&command, args)) = body.split_first() else {
            return false;
        };
        match command {
            0x01 | 0x09 | 0x0a | 0x0d | 0x0e | 0x0f | 0x10 | 0x1f => payload_len == 1,
            0x02 | 0x05 | 0x06 | 0x11 => mysql_nonempty_text_arg(args),
            0x03 | 0x16 => mysql_sql_command_arg(args),
            0x04 => mysql_nonempty_text_arg(args),
            0x07 => payload_len == 2 && args.len() == 1,
            0x08 => payload_len <= 2 && args.len() == payload_len.saturating_sub(1),
            0x0c | 0x19 | 0x1a => payload_len == 5 && args.len() == 4,
            0x17 => payload_len >= 10 && args.len() >= 9,
            0x18 => payload_len >= 7 && args.len() >= 6,
            0x1b => payload_len == 3 && args.len() == 2,
            0x1c => payload_len == 9 && args.len() == 8,
            _ => false,
        }
    }

    fn mysql_sql_command_arg(args: &[u8]) -> bool {
        let statement = trim_ascii_space(args);
        if statement.is_empty() {
            return false;
        }
        if !statement
            .iter()
            .all(|byte| !byte.is_ascii_control() || matches!(*byte, b'\t' | b'\n' | b'\r'))
        {
            return false;
        }
        let keywords: [&[u8]; 29] = [
            b"SELECT",
            b"INSERT",
            b"UPDATE",
            b"DELETE",
            b"REPLACE",
            b"CALL",
            b"SHOW",
            b"SET",
            b"USE",
            b"BEGIN",
            b"START",
            b"COMMIT",
            b"ROLLBACK",
            b"SAVEPOINT",
            b"CREATE",
            b"ALTER",
            b"DROP",
            b"TRUNCATE",
            b"EXPLAIN",
            b"DESCRIBE",
            b"DESC",
            b"WITH",
            b"ANALYZE",
            b"OPTIMIZE",
            b"LOCK",
            b"UNLOCK",
            b"GRANT",
            b"REVOKE",
            b"DO",
        ];
        keywords
            .iter()
            .any(|keyword| starts_ascii_keyword(statement, keyword))
    }

    fn mysql_nonempty_text_arg(args: &[u8]) -> bool {
        !args.is_empty()
            && args
                .iter()
                .all(|byte| !byte.is_ascii_control() || *byte == b'\t')
    }

    fn mssql_tds_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut packet_count = 0_usize;
        while offset < payload.len() {
            if payload.len().saturating_sub(offset) < 8 {
                return packet_count > 0;
            }
            match mssql_tds_packet(payload, offset) {
                Some(MsSqlTdsPacketParse::Complete(next_offset)) => {
                    packet_count += 1;
                    if packet_count > 16 {
                        return false;
                    }
                    offset = next_offset;
                }
                Some(MsSqlTdsPacketParse::Incomplete) => return true,
                None => return false,
            }
        }
        packet_count > 0
    }

    enum MsSqlTdsPacketParse {
        Complete(usize),
        Incomplete,
    }

    fn mssql_tds_packet(payload: &[u8], offset: usize) -> Option<MsSqlTdsPacketParse> {
        let packet_type = *payload.get(offset)?;
        let status = *payload.get(offset.checked_add(1)?)?;
        let length = read_u16_be(payload, offset.checked_add(2)?)? as usize;
        let packet_id = *payload.get(offset.checked_add(6)?)?;
        let window = *payload.get(offset.checked_add(7)?)?;
        if !mssql_tds_packet_type(packet_type)
            || !mssql_tds_status(status)
            || !(8..=65_535).contains(&length)
            || packet_id > 128
            || window > 1
        {
            return None;
        }
        let packet_end = offset.checked_add(length)?;
        let body_offset = offset.checked_add(8)?;
        let observed_body_end = payload.len().min(packet_end);
        let body = payload.get(body_offset..observed_body_end)?;
        if !mssql_tds_packet_body(packet_type, body, length - 8, payload.len() < packet_end) {
            return None;
        }
        if payload.len() < packet_end {
            Some(MsSqlTdsPacketParse::Incomplete)
        } else {
            Some(MsSqlTdsPacketParse::Complete(packet_end))
        }
    }

    fn mssql_tds_packet_type(packet_type: u8) -> bool {
        matches!(packet_type, 0x01 | 0x10 | 0x12)
    }

    fn mssql_tds_status(status: u8) -> bool {
        status & !0x1f == 0
    }

    fn mssql_tds_packet_body(
        packet_type: u8,
        body: &[u8],
        declared_body_len: usize,
        incomplete: bool,
    ) -> bool {
        match packet_type {
            0x01 => mssql_sql_batch_body(body, incomplete),
            0x10 => mssql_login7_body(body, declared_body_len, incomplete),
            0x12 => mssql_prelogin_body(body, declared_body_len, incomplete),
            _ => false,
        }
    }

    fn mssql_prelogin_body(body: &[u8], declared_body_len: usize, incomplete: bool) -> bool {
        if declared_body_len < 6 {
            return false;
        }
        let mut offset = 0_usize;
        let mut seen_tokens = 0_u16;
        let mut value_ranges = [(0_usize, 0_usize); 16];
        let mut token_count = 0_usize;
        loop {
            let Some(&token) = body.get(offset) else {
                return incomplete && token_count > 0;
            };
            if token == 0xff {
                let Some(value_table_end) = offset.checked_add(1) else {
                    return false;
                };
                return token_count > 0
                    && value_ranges[..token_count]
                        .iter()
                        .all(|(value_offset, value_len)| {
                            *value_offset >= value_table_end
                                && value_offset
                                    .checked_add(*value_len)
                                    .is_some_and(|end| end <= declared_body_len)
                        });
            }
            if token > 0x07 {
                return false;
            }
            let token_bit = 1_u16 << u32::from(token);
            if seen_tokens & token_bit != 0 {
                return false;
            }
            let Some(value_offset_offset) = offset.checked_add(1) else {
                return false;
            };
            let Some(value_offset) =
                read_u16_be(body, value_offset_offset).map(|value| value as usize)
            else {
                return incomplete && token_count > 0;
            };
            let Some(value_len_offset) = offset.checked_add(3) else {
                return false;
            };
            let Some(value_len) = read_u16_be(body, value_len_offset).map(|value| value as usize)
            else {
                return incomplete && token_count > 0;
            };
            if value_offset < 6 || value_offset > declared_body_len {
                return false;
            }
            if value_offset
                .checked_add(value_len)
                .is_none_or(|end| end > declared_body_len)
            {
                return false;
            }
            seen_tokens |= token_bit;
            value_ranges[token_count] = (value_offset, value_len);
            token_count += 1;
            if token_count > 16 {
                return false;
            }
            offset += 5;
        }
    }

    fn mssql_login7_body(body: &[u8], declared_body_len: usize, incomplete: bool) -> bool {
        if declared_body_len < 36 {
            return false;
        }
        if body.len() < 4 {
            return incomplete;
        }
        let Some(login_len) = read_u32_le(body, 0).map(|value| value as usize) else {
            return false;
        };
        login_len == declared_body_len && login_len >= 36 && login_len <= 65_527
    }

    fn mssql_sql_batch_body(body: &[u8], incomplete: bool) -> bool {
        if body.is_empty() {
            return incomplete;
        }
        let statement = trim_utf16le_ascii_space(body);
        if statement.is_empty() {
            return false;
        }
        let keywords: [&[u8]; 31] = [
            b"SELECT",
            b"INSERT",
            b"UPDATE",
            b"DELETE",
            b"MERGE",
            b"EXEC",
            b"EXECUTE",
            b"DECLARE",
            b"SET",
            b"USE",
            b"BEGIN",
            b"COMMIT",
            b"ROLLBACK",
            b"SAVE",
            b"CREATE",
            b"ALTER",
            b"DROP",
            b"TRUNCATE",
            b"WITH",
            b"GRANT",
            b"REVOKE",
            b"BACKUP",
            b"RESTORE",
            b"DBCC",
            b"PRINT",
            b"RAISERROR",
            b"THROW",
            b"WAITFOR",
            b"IF",
            b"WHILE",
            b"OPEN",
        ];
        keywords
            .iter()
            .any(|keyword| starts_utf16le_ascii_keyword(statement, keyword))
    }

    fn oracle_tns_payload(payload: &[u8]) -> bool {
        oracle_tns_connect_packet(payload)
    }

    fn oracle_tns_connect_packet(payload: &[u8]) -> bool {
        if payload.len() < 34 {
            return false;
        }
        let Some(packet_len) = read_u16_be(payload, 0).map(|value| value as usize) else {
            return false;
        };
        let Some(packet_checksum) = read_u16_be(payload, 2) else {
            return false;
        };
        let Some(&packet_type) = payload.get(4) else {
            return false;
        };
        let Some(&reserved) = payload.get(5) else {
            return false;
        };
        let Some(header_checksum) = read_u16_be(payload, 6) else {
            return false;
        };
        if !(34..=65_535).contains(&packet_len)
            || payload.len() > packet_len
            || packet_checksum != 0
            || packet_type != 0x01
            || reserved != 0
            || header_checksum != 0
        {
            return false;
        }
        let Some(version) = read_u16_be(payload, 8) else {
            return false;
        };
        let Some(compatible_version) = read_u16_be(payload, 10) else {
            return false;
        };
        if !(0x0100..=0x2000).contains(&version)
            || !(0x0100..=version).contains(&compatible_version)
        {
            return false;
        }
        let Some(sdu) = read_u16_be(payload, 14) else {
            return false;
        };
        let Some(tdu) = read_u16_be(payload, 16) else {
            return false;
        };
        let Some(marker) = read_u16_be(payload, 22) else {
            return false;
        };
        if !(512..=65_535).contains(&sdu) || !(512..=65_535).contains(&tdu) || marker != 1 {
            return false;
        }
        let Some(connect_data_len) = read_u16_be(payload, 24).map(|value| value as usize) else {
            return false;
        };
        let Some(connect_data_offset) = read_u16_be(payload, 26).map(|value| value as usize) else {
            return false;
        };
        if connect_data_len == 0
            || connect_data_offset < 34
            || connect_data_offset >= packet_len
            || connect_data_offset
                .checked_add(connect_data_len)
                .is_none_or(|end| end > packet_len)
            || payload.len() <= connect_data_offset
        {
            return false;
        }
        let connect_data_end = connect_data_offset + connect_data_len;
        let observed_end = payload.len().min(connect_data_end);
        let Some(connect_data) = payload.get(connect_data_offset..observed_end) else {
            return false;
        };
        oracle_tns_connect_descriptor(connect_data)
    }

    fn oracle_tns_connect_descriptor(payload: &[u8]) -> bool {
        let descriptor = trim_ascii_space(payload);
        if descriptor.len() < 12 || descriptor.first() != Some(&b'(') {
            return false;
        }
        if !descriptor
            .iter()
            .all(|byte| matches!(*byte, b'\t' | b'\n' | b'\r') || (0x20..=0x7e).contains(byte))
        {
            return false;
        }
        let has_description = ascii_contains_ignore_case(descriptor, b"(DESCRIPTION");
        let has_connect_data = ascii_contains_ignore_case(descriptor, b"(CONNECT_DATA");
        let has_service = ascii_contains_ignore_case(descriptor, b"(SERVICE_NAME")
            || ascii_contains_ignore_case(descriptor, b"(SID")
            || ascii_contains_ignore_case(descriptor, b"(INSTANCE_NAME");
        let has_address = ascii_contains_ignore_case(descriptor, b"(ADDRESS")
            && ascii_contains_ignore_case(descriptor, b"(PROTOCOL=TCP");
        has_description && (has_connect_data || has_service || has_address)
    }

    fn redis_payload(payload: &[u8]) -> bool {
        redis_resp_array_payload(payload) || redis_inline_command_payload(payload)
    }

    fn redis_resp_array_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut command_count = 0_usize;
        while offset < payload.len() {
            match redis_resp_command_array(payload, offset) {
                Some(RedisRespCommandParse::Complete(next_offset)) => {
                    command_count += 1;
                    if command_count > 16 {
                        return false;
                    }
                    offset = next_offset;
                }
                Some(RedisRespCommandParse::IncompleteBeforeCommand) => {
                    return command_count > 0;
                }
                Some(RedisRespCommandParse::IncompleteAfterCommand) => {
                    return true;
                }
                None => return false,
            }
        }
        command_count > 0
    }

    enum RedisRespCommandParse {
        Complete(usize),
        IncompleteBeforeCommand,
        IncompleteAfterCommand,
    }

    enum RedisBulkStringParse {
        Complete(usize),
        Incomplete,
    }

    fn redis_resp_command_array(payload: &[u8], offset: usize) -> Option<RedisRespCommandParse> {
        const MAX_ARRAY_LEN: usize = 1024;
        const MAX_COMMAND_LEN: usize = 64;
        const MAX_BULK_STRING_LEN: usize = 512 * 1024 * 1024;

        if payload.get(offset) != Some(&b'*') {
            return None;
        }
        let array_len_offset = offset.checked_add(1)?;
        let (array_len, mut item_offset) =
            match redis_decimal_crlf(payload, array_len_offset, 1, MAX_ARRAY_LEN) {
                Some(header) => header,
                None if redis_decimal_crlf_incomplete(payload, array_len_offset, MAX_ARRAY_LEN) => {
                    return Some(RedisRespCommandParse::IncompleteBeforeCommand);
                }
                None => return None,
            };
        let Some((command, command_offset)) =
            redis_bulk_string(payload, item_offset, 1, MAX_COMMAND_LEN)
        else {
            return match redis_bulk_string_prefix(payload, item_offset, 1, MAX_COMMAND_LEN)? {
                RedisBulkStringParse::Complete(_) => None,
                RedisBulkStringParse::Incomplete => {
                    Some(RedisRespCommandParse::IncompleteBeforeCommand)
                }
            };
        };
        if !redis_known_command(command) {
            return None;
        }

        item_offset = command_offset;
        for _ in 1..array_len {
            match redis_bulk_string_prefix(payload, item_offset, 0, MAX_BULK_STRING_LEN)? {
                RedisBulkStringParse::Complete(next_offset) => {
                    item_offset = next_offset;
                }
                RedisBulkStringParse::Incomplete => {
                    return Some(RedisRespCommandParse::IncompleteAfterCommand);
                }
            }
        }
        Some(RedisRespCommandParse::Complete(item_offset))
    }

    fn redis_inline_command_payload(payload: &[u8]) -> bool {
        if payload.first() == Some(&b'*') {
            return false;
        }
        let line_end = payload
            .iter()
            .position(|byte| matches!(*byte, b'\r' | b'\n'))
            .unwrap_or(payload.len());
        let line = trim_ascii_space(&payload[..line_end]);
        if line.is_empty() {
            return false;
        }
        let command_end = line
            .iter()
            .position(|byte| byte.is_ascii_whitespace())
            .unwrap_or(line.len());
        redis_known_inline_command(&line[..command_end], trim_ascii_space(&line[command_end..]))
    }

    fn redis_bulk_string(
        payload: &[u8],
        offset: usize,
        min: usize,
        max: usize,
    ) -> Option<(&[u8], usize)> {
        if payload.get(offset) != Some(&b'$') {
            return None;
        }
        let (len, data_offset) = redis_decimal_crlf(payload, offset.checked_add(1)?, min, max)?;
        let data_end = data_offset.checked_add(len)?;
        let crlf_end = data_end.checked_add(2)?;
        if payload.get(data_end..crlf_end)? != b"\r\n" {
            return None;
        }
        Some((payload.get(data_offset..data_end)?, crlf_end))
    }

    fn redis_bulk_string_prefix(
        payload: &[u8],
        offset: usize,
        min: usize,
        max: usize,
    ) -> Option<RedisBulkStringParse> {
        if offset >= payload.len() {
            return Some(RedisBulkStringParse::Incomplete);
        }
        if payload.get(offset) != Some(&b'$') {
            return None;
        }
        let len_offset = offset.checked_add(1)?;
        let (len, data_offset) = match redis_decimal_crlf(payload, len_offset, min, max) {
            Some(header) => header,
            None if redis_decimal_crlf_incomplete(payload, len_offset, max) => {
                return Some(RedisBulkStringParse::Incomplete);
            }
            None => return None,
        };
        let data_end = data_offset.checked_add(len)?;
        let crlf_end = data_end.checked_add(2)?;
        if payload.len() < data_end {
            return Some(RedisBulkStringParse::Incomplete);
        }
        if payload.len() < crlf_end {
            return match payload.get(data_end..) {
                Some(b"") | Some(b"\r") => Some(RedisBulkStringParse::Incomplete),
                _ => None,
            };
        }
        if payload.get(data_end..crlf_end)? != b"\r\n" {
            return None;
        }
        Some(RedisBulkStringParse::Complete(crlf_end))
    }

    fn redis_decimal_crlf(
        payload: &[u8],
        mut offset: usize,
        min: usize,
        max: usize,
    ) -> Option<(usize, usize)> {
        let mut value = 0_usize;
        let mut digits = 0_usize;
        loop {
            let byte = *payload.get(offset)?;
            match byte {
                b'0'..=b'9' => {
                    value = value.checked_mul(10)?.checked_add((byte - b'0') as usize)?;
                    digits += 1;
                    if value > max || digits > 10 {
                        return None;
                    }
                    offset += 1;
                }
                b'\r' if payload.get(offset + 1) == Some(&b'\n') => {
                    return (digits > 0 && value >= min && value <= max)
                        .then_some((value, offset + 2));
                }
                _ => return None,
            }
        }
    }

    fn redis_decimal_crlf_incomplete(payload: &[u8], mut offset: usize, max: usize) -> bool {
        if offset >= payload.len() {
            return true;
        }

        let mut value = 0_usize;
        let mut digits = 0_usize;
        loop {
            let Some(byte) = payload.get(offset) else {
                return digits > 0;
            };
            match *byte {
                b'0'..=b'9' => {
                    value = match value
                        .checked_mul(10)
                        .and_then(|value| value.checked_add((byte - b'0') as usize))
                    {
                        Some(value) => value,
                        None => return false,
                    };
                    digits += 1;
                    if value > max || digits > 10 {
                        return false;
                    }
                    offset += 1;
                }
                b'\r' if payload.get(offset + 1).is_none() => return digits > 0,
                _ => return false,
            }
        }
    }

    fn redis_known_command(command: &[u8]) -> bool {
        let commands: [&[u8]; 38] = [
            b"PING",
            b"ECHO",
            b"GET",
            b"SET",
            b"DEL",
            b"EXISTS",
            b"SUBSCRIBE",
            b"PUBLISH",
            b"AUTH",
            b"SELECT",
            b"HELLO",
            b"CLIENT",
            b"EVAL",
            b"EVALSHA",
            b"XADD",
            b"XREAD",
            b"XGROUP",
            b"INFO",
            b"COMMAND",
            b"ACL",
            b"CONFIG",
            b"DBSIZE",
            b"FLUSHDB",
            b"FLUSHALL",
            b"QUIT",
            b"MONITOR",
            b"MULTI",
            b"EXEC",
            b"DISCARD",
            b"WATCH",
            b"UNWATCH",
            b"PSUBSCRIBE",
            b"PUNSUBSCRIBE",
            b"ZADD",
            b"HGET",
            b"HSET",
            b"LPUSH",
            b"RPUSH",
        ];
        commands
            .iter()
            .any(|known| command.eq_ignore_ascii_case(known))
    }

    fn redis_known_inline_command(command: &[u8], args: &[u8]) -> bool {
        if command.eq_ignore_ascii_case(b"INFO") {
            return args.is_empty() || redis_inline_argument(args);
        }

        let commands: [&[u8]; 23] = [
            b"HELLO",
            b"CLIENT",
            b"COMMAND",
            b"SUBSCRIBE",
            b"UNSUBSCRIBE",
            b"PSUBSCRIBE",
            b"PUNSUBSCRIBE",
            b"PUBLISH",
            b"EVAL",
            b"EVALSHA",
            b"XADD",
            b"XREAD",
            b"XGROUP",
            b"ACL",
            b"CONFIG",
            b"DBSIZE",
            b"FLUSHDB",
            b"FLUSHALL",
            b"MONITOR",
            b"MULTI",
            b"DISCARD",
            b"WATCH",
            b"UNWATCH",
        ];
        commands
            .iter()
            .any(|known| command.eq_ignore_ascii_case(known))
    }

    fn redis_inline_argument(argument: &[u8]) -> bool {
        !argument.is_empty()
            && argument.len() <= 64
            && argument
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
    }

    fn memcached_payload(payload: &[u8]) -> bool {
        memcached_text_payload(payload) || memcached_binary_payload(payload)
    }

    fn memcached_text_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut command_count = 0_usize;
        while offset < payload.len() {
            match memcached_text_command(payload, offset) {
                Some(MemcachedTextCommandParse::Complete(next_offset)) => {
                    command_count += 1;
                    if command_count > 16 {
                        return false;
                    }
                    offset = next_offset;
                }
                Some(MemcachedTextCommandParse::Incomplete) => return true,
                None => return false,
            }
        }
        command_count > 0
    }

    enum MemcachedTextCommandParse {
        Complete(usize),
        Incomplete,
    }

    enum MemcachedTextCommandKind {
        Storage { bytes: usize },
        Line,
    }

    fn memcached_text_command(payload: &[u8], offset: usize) -> Option<MemcachedTextCommandParse> {
        let tail = payload.get(offset..)?;
        let line_delimiter = tail.iter().position(|byte| matches!(*byte, b'\r' | b'\n'));
        let (line, line_end) = match line_delimiter {
            Some(index) if tail.get(index) == Some(&b'\r') => {
                if tail.get(index + 1).is_none() {
                    return Some(MemcachedTextCommandParse::Incomplete);
                }
                if tail.get(index + 1) != Some(&b'\n') {
                    return None;
                }
                (tail.get(..index)?, Some(offset + index + 2))
            }
            Some(_) => return None,
            None => (tail, None),
        };
        let fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let command = memcached_text_command_kind(&fields)?;
        let Some(line_end) = line_end else {
            return Some(MemcachedTextCommandParse::Incomplete);
        };
        match command {
            MemcachedTextCommandKind::Line => Some(MemcachedTextCommandParse::Complete(line_end)),
            MemcachedTextCommandKind::Storage { bytes } => {
                let data_end = line_end.checked_add(bytes)?;
                let frame_end = data_end.checked_add(2)?;
                if payload.len() < data_end {
                    return Some(MemcachedTextCommandParse::Incomplete);
                }
                if payload.len() < frame_end {
                    return match payload.get(data_end..) {
                        Some(b"") | Some(b"\r") => Some(MemcachedTextCommandParse::Incomplete),
                        _ => None,
                    };
                }
                if payload.get(data_end..frame_end)? != b"\r\n" {
                    return None;
                }
                Some(MemcachedTextCommandParse::Complete(frame_end))
            }
        }
    }

    fn memcached_text_command_kind(fields: &[&[u8]]) -> Option<MemcachedTextCommandKind> {
        let command = *fields.first()?;

        if command.eq_ignore_ascii_case(b"get") || command.eq_ignore_ascii_case(b"gets") {
            return (fields.len() >= 2 && fields[1..].iter().all(|field| memcached_key(field)))
                .then_some(MemcachedTextCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"gat") || command.eq_ignore_ascii_case(b"gats") {
            return (fields.len() >= 3
                && memcached_decimal(fields[1])
                && fields[2..].iter().all(|field| memcached_key(field)))
            .then_some(MemcachedTextCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"set")
            || command.eq_ignore_ascii_case(b"add")
            || command.eq_ignore_ascii_case(b"replace")
            || command.eq_ignore_ascii_case(b"append")
            || command.eq_ignore_ascii_case(b"prepend")
        {
            return memcached_storage_fields(fields, false)
                .map(|bytes| MemcachedTextCommandKind::Storage { bytes });
        }
        if command.eq_ignore_ascii_case(b"cas") {
            return memcached_storage_fields(fields, true)
                .map(|bytes| MemcachedTextCommandKind::Storage { bytes });
        }
        if command.eq_ignore_ascii_case(b"delete") {
            return (fields.len() == 2 && memcached_key(fields[1])
                || fields.len() == 3
                    && memcached_key(fields[1])
                    && fields[2].eq_ignore_ascii_case(b"noreply"))
            .then_some(MemcachedTextCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"incr") || command.eq_ignore_ascii_case(b"decr") {
            return (fields.len() == 3 && memcached_key(fields[1]) && memcached_decimal(fields[2])
                || fields.len() == 4
                    && memcached_key(fields[1])
                    && memcached_decimal(fields[2])
                    && fields[3].eq_ignore_ascii_case(b"noreply"))
            .then_some(MemcachedTextCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"touch") {
            return (fields.len() == 3 && memcached_key(fields[1]) && memcached_decimal(fields[2])
                || fields.len() == 4
                    && memcached_key(fields[1])
                    && memcached_decimal(fields[2])
                    && fields[3].eq_ignore_ascii_case(b"noreply"))
            .then_some(MemcachedTextCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"stats") {
            return (fields.len() <= 4
                && fields
                    .iter()
                    .skip(1)
                    .all(|field| memcached_ascii_argument(field)))
            .then_some(MemcachedTextCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"version") {
            return (fields.len() == 1).then_some(MemcachedTextCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"flush_all") {
            return (fields.len() == 1
                || fields.len() == 2
                    && (memcached_decimal(fields[1])
                        || fields[1].eq_ignore_ascii_case(b"noreply"))
                || fields.len() == 3
                    && memcached_decimal(fields[1])
                    && fields[2].eq_ignore_ascii_case(b"noreply"))
            .then_some(MemcachedTextCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"verbosity") {
            return (fields.len() == 2 && memcached_decimal(fields[1])
                || fields.len() == 3
                    && memcached_decimal(fields[1])
                    && fields[2].eq_ignore_ascii_case(b"noreply"))
            .then_some(MemcachedTextCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"quit") {
            return (fields.len() == 1
                || fields.len() == 2 && fields[1].eq_ignore_ascii_case(b"noreply"))
            .then_some(MemcachedTextCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"slabs") {
            return memcached_slabs_fields(fields).then_some(MemcachedTextCommandKind::Line);
        }
        None
    }

    fn memcached_storage_fields(fields: &[&[u8]], includes_cas: bool) -> Option<usize> {
        let required = if includes_cas { 6 } else { 5 };
        if fields.len() != required
            && !(fields.len() == required + 1 && fields[required].eq_ignore_ascii_case(b"noreply"))
        {
            return None;
        }
        let bytes = memcached_decimal_value(fields[4], 1_048_576)?;
        (memcached_key(fields[1])
            && memcached_decimal(fields[2])
            && memcached_decimal(fields[3])
            && (!includes_cas || memcached_decimal(fields[5])))
        .then_some(bytes)
    }

    fn memcached_slabs_fields(fields: &[&[u8]]) -> bool {
        if fields.len() < 2 {
            return false;
        }
        if fields[1].eq_ignore_ascii_case(b"reassign") {
            return fields.len() == 4
                && memcached_decimal(fields[2])
                && memcached_decimal(fields[3]);
        }
        if fields[1].eq_ignore_ascii_case(b"automove") {
            return fields.len() == 2 || fields.len() == 3 && memcached_decimal(fields[2]);
        }
        false
    }

    fn memcached_key(field: &[u8]) -> bool {
        !field.is_empty()
            && field.len() <= 250
            && field
                .iter()
                .all(|byte| byte.is_ascii_graphic() && !matches!(*byte, b' ' | 0x7f))
    }

    fn memcached_decimal(field: &[u8]) -> bool {
        !field.is_empty() && field.len() <= 20 && field.iter().all(u8::is_ascii_digit)
    }

    fn memcached_decimal_value(field: &[u8], max: usize) -> Option<usize> {
        if field.is_empty() || field.len() > 20 {
            return None;
        }
        let mut value = 0_usize;
        for byte in field {
            let digit = byte.checked_sub(b'0')?;
            if digit > 9 {
                return None;
            }
            value = value.checked_mul(10)?.checked_add(digit as usize)?;
            if value > max {
                return None;
            }
        }
        Some(value)
    }

    fn memcached_ascii_argument(field: &[u8]) -> bool {
        !field.is_empty()
            && field.iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b':' | b'.')
            })
    }

    fn memcached_binary_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut packet_count = 0_usize;
        while offset < payload.len() {
            match memcached_binary_packet(payload, offset) {
                Some(MemcachedBinaryPacketParse::Complete(next_offset)) => {
                    packet_count += 1;
                    if packet_count > 16 {
                        return false;
                    }
                    offset = next_offset;
                }
                Some(MemcachedBinaryPacketParse::Incomplete) => return true,
                None => return false,
            }
        }
        packet_count > 0
    }

    enum MemcachedBinaryPacketParse {
        Complete(usize),
        Incomplete,
    }

    fn memcached_binary_packet(
        payload: &[u8],
        offset: usize,
    ) -> Option<MemcachedBinaryPacketParse> {
        let header = payload.get(offset..offset.checked_add(24)?)?;
        let magic = header[0];
        if !matches!(magic, 0x80 | 0x81) {
            return None;
        }
        let opcode = header[1];
        let key_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        let extras_len = header[4] as usize;
        let data_type = header[5];
        let total_body_len =
            u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
        let frame_end = offset.checked_add(24)?.checked_add(total_body_len)?;
        if data_type != 0
            || total_body_len > 1_048_576
            || key_len > 250
            || extras_len > 32
            || key_len.checked_add(extras_len)? > total_body_len
            || !memcached_binary_opcode_shape(magic, opcode, key_len, extras_len, total_body_len)
        {
            return None;
        }
        if payload.len() < frame_end {
            Some(MemcachedBinaryPacketParse::Incomplete)
        } else {
            Some(MemcachedBinaryPacketParse::Complete(frame_end))
        }
    }

    fn memcached_binary_opcode_shape(
        magic: u8,
        opcode: u8,
        key_len: usize,
        extras_len: usize,
        total_body_len: usize,
    ) -> bool {
        if magic == 0x81 {
            return opcode <= 0x22;
        }
        match opcode {
            0x00 | 0x09 | 0x0c | 0x0d => {
                extras_len == 0 && key_len > 0 && total_body_len == key_len
            }
            0x01..=0x03 => extras_len == 8 && key_len > 0 && total_body_len >= extras_len + key_len,
            0x04 => extras_len == 0 && key_len > 0 && total_body_len == key_len,
            0x05 | 0x06 => {
                extras_len == 20 && key_len > 0 && total_body_len == extras_len + key_len
            }
            0x07 | 0x0a | 0x0b => extras_len == 0 && key_len == 0 && total_body_len == 0,
            0x08 => key_len == 0 && matches!(extras_len, 0 | 4) && total_body_len == extras_len,
            0x0e | 0x0f => extras_len == 0 && key_len > 0 && total_body_len >= key_len,
            0x10 => extras_len == 0 && total_body_len == key_len,
            0x1c..=0x1e => extras_len == 4 && key_len > 0 && total_body_len == extras_len + key_len,
            0x20 => extras_len == 0 && key_len == 0 && total_body_len == 0,
            0x21 | 0x22 => extras_len == 0 && key_len > 0 && total_body_len >= key_len,
            _ => false,
        }
    }

    fn kafka_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut frame_count = 0_usize;
        while offset < payload.len() {
            if payload.len().saturating_sub(offset) < 4 {
                return frame_count > 0;
            }
            match kafka_request_frame(payload, offset) {
                Some(KafkaFrameParse::Complete(next_offset)) => {
                    frame_count += 1;
                    if frame_count > 16 {
                        return false;
                    }
                    offset = next_offset;
                }
                Some(KafkaFrameParse::Incomplete) => {
                    return true;
                }
                None => return false,
            }
        }
        frame_count > 0
    }

    enum KafkaFrameParse {
        Complete(usize),
        Incomplete,
    }

    enum KafkaHeaderParse {
        Complete,
        Incomplete,
    }

    enum KafkaVarintParse {
        Complete(u64, usize),
        Incomplete,
    }

    fn kafka_request_frame(payload: &[u8], offset: usize) -> Option<KafkaFrameParse> {
        let frame_len = read_u32_be(payload, offset)? as usize;
        let header_offset = offset.checked_add(4)?;
        let api_key = read_u16_be(payload, header_offset)?;
        let api_version = read_u16_be(payload, header_offset.checked_add(2)?)?;
        if !(8..=100_000_000).contains(&frame_len) || api_key > 92 || api_version > 20 {
            return None;
        }
        let frame_end = header_offset.checked_add(frame_len)?;
        let correlation_id_end = header_offset.checked_add(8)?;
        if payload.len() < correlation_id_end {
            return Some(KafkaFrameParse::Incomplete);
        }
        if frame_len == 8 {
            return if payload.len() < frame_end {
                Some(KafkaFrameParse::Incomplete)
            } else {
                Some(KafkaFrameParse::Complete(frame_end))
            };
        }
        let header_tail = payload.get(correlation_id_end..)?;
        let remaining_frame_len = frame_len - 8;
        let header_parse = kafka_request_header_payload(header_tail, remaining_frame_len)?;
        match header_parse {
            KafkaHeaderParse::Complete => {
                if payload.len() < frame_end {
                    Some(KafkaFrameParse::Incomplete)
                } else {
                    Some(KafkaFrameParse::Complete(frame_end))
                }
            }
            KafkaHeaderParse::Incomplete => Some(KafkaFrameParse::Incomplete),
        }
    }

    fn kafka_request_header_payload(
        payload: &[u8],
        remaining_frame_len: usize,
    ) -> Option<KafkaHeaderParse> {
        kafka_nullable_client_id_header_payload(payload, remaining_frame_len)
            .or_else(|| kafka_compact_client_id_header_payload(payload, remaining_frame_len))
    }

    fn kafka_nullable_client_id_header_payload(
        payload: &[u8],
        remaining_frame_len: usize,
    ) -> Option<KafkaHeaderParse> {
        if remaining_frame_len < 2 {
            return None;
        }
        if payload.len() < 2 {
            return Some(KafkaHeaderParse::Incomplete);
        }
        let client_id_len = i16::from_be_bytes([payload[0], payload[1]]);
        if client_id_len == -1 {
            return Some(KafkaHeaderParse::Complete);
        }
        if client_id_len < 0 {
            return None;
        };
        let client_id_len = client_id_len as usize;
        let header_len = 2_usize.checked_add(client_id_len)?;
        if client_id_len > 1_024 || header_len > remaining_frame_len {
            return None;
        }
        if payload.len() < header_len {
            return Some(KafkaHeaderParse::Incomplete);
        }
        kafka_client_id_payload(&payload[2..header_len]).then_some(KafkaHeaderParse::Complete)
    }

    fn kafka_compact_client_id_header_payload(
        payload: &[u8],
        remaining_frame_len: usize,
    ) -> Option<KafkaHeaderParse> {
        let (client_id_len_plus_one, client_id_offset) =
            match kafka_unsigned_varint_prefix(payload, remaining_frame_len)? {
                KafkaVarintParse::Complete(value, offset) => (value, offset),
                KafkaVarintParse::Incomplete => return Some(KafkaHeaderParse::Incomplete),
            };
        let client_id_remaining = remaining_frame_len.checked_sub(client_id_offset)?;
        let client_id_len = client_id_len_plus_one.saturating_sub(1) as usize;
        let client_id_end = client_id_offset.checked_add(client_id_len)?;
        if client_id_len > 1_024 || client_id_len > client_id_remaining {
            return None;
        }
        if payload.len() < client_id_end {
            return Some(KafkaHeaderParse::Incomplete);
        }
        if !kafka_client_id_payload(&payload[client_id_offset..client_id_end]) {
            return None;
        }
        let tag_payload = payload.get(client_id_end..)?;
        let tag_count_remaining = remaining_frame_len.checked_sub(client_id_end)?;
        let (tags_len, tags_len_bytes) =
            match kafka_unsigned_varint_prefix(tag_payload, tag_count_remaining)? {
                KafkaVarintParse::Complete(value, offset) => (value, offset),
                KafkaVarintParse::Incomplete => return Some(KafkaHeaderParse::Incomplete),
            };
        if tags_len > 16 || tags_len_bytes > tag_count_remaining {
            return None;
        };
        let tags_len = tags_len as usize;
        let tag_section_remaining = tag_count_remaining.checked_sub(tags_len_bytes)?;
        if tags_len == 0 {
            return Some(KafkaHeaderParse::Complete);
        }
        if tags_len.checked_mul(2)? > tag_section_remaining {
            return None;
        }
        kafka_tag_buffer_payload(
            tag_payload.get(tags_len_bytes..)?,
            tags_len,
            tag_section_remaining,
        )
    }

    fn kafka_tag_buffer_payload(
        mut payload: &[u8],
        tags_len: usize,
        mut remaining_frame_len: usize,
    ) -> Option<KafkaHeaderParse> {
        let mut previous_tag = None;
        for _ in 0..tags_len {
            let (tag, tag_len_bytes) =
                match kafka_unsigned_varint_prefix(payload, remaining_frame_len)? {
                    KafkaVarintParse::Complete(value, offset) => (value, offset),
                    KafkaVarintParse::Incomplete => return Some(KafkaHeaderParse::Incomplete),
                };
            if tag_len_bytes > remaining_frame_len {
                return None;
            };
            if previous_tag.is_some_and(|previous| tag <= previous) || tag > u32::MAX as u64 {
                return None;
            }
            previous_tag = Some(tag);
            payload = payload.get(tag_len_bytes..)?;
            remaining_frame_len = remaining_frame_len.checked_sub(tag_len_bytes)?;
            let (size, size_len_bytes) =
                match kafka_unsigned_varint_prefix(payload, remaining_frame_len)? {
                    KafkaVarintParse::Complete(value, offset) => (value, offset),
                    KafkaVarintParse::Incomplete => return Some(KafkaHeaderParse::Incomplete),
                };
            if size_len_bytes > remaining_frame_len {
                return None;
            };
            let size = size as usize;
            payload = payload.get(size_len_bytes..)?;
            remaining_frame_len = remaining_frame_len.checked_sub(size_len_bytes)?;
            if size > remaining_frame_len {
                return None;
            }
            if payload.len() < size {
                return Some(KafkaHeaderParse::Incomplete);
            }
            payload = payload.get(size..)?;
            remaining_frame_len -= size;
        }
        Some(KafkaHeaderParse::Complete)
    }

    fn kafka_client_id_payload(client_id: &[u8]) -> bool {
        client_id.is_empty()
            || (std::str::from_utf8(client_id).is_ok()
                && client_id
                    .iter()
                    .all(|byte| !byte.is_ascii_control() || *byte == b'\t'))
    }

    fn kafka_unsigned_varint_prefix(
        payload: &[u8],
        remaining_len: usize,
    ) -> Option<KafkaVarintParse> {
        if remaining_len == 0 {
            return None;
        }
        let available_len = payload.len().min(remaining_len);
        let available = payload.get(..available_len)?;
        if let Some((value, offset)) = kafka_unsigned_varint(available) {
            return Some(KafkaVarintParse::Complete(value, offset));
        }
        (payload.len() < remaining_len && kafka_unsigned_varint_incomplete(available))
            .then_some(KafkaVarintParse::Incomplete)
    }

    fn kafka_unsigned_varint(payload: &[u8]) -> Option<(u64, usize)> {
        let mut value = 0_u64;
        for (index, byte) in payload.iter().take(10).enumerate() {
            value |= ((byte & 0x7f) as u64).checked_shl((7 * index) as u32)?;
            if byte & 0x80 == 0 {
                return Some((value, index + 1));
            }
        }
        None
    }

    fn kafka_unsigned_varint_incomplete(payload: &[u8]) -> bool {
        if payload.is_empty() {
            return true;
        }
        for byte in payload.iter().take(10) {
            if byte & 0x80 == 0 {
                return false;
            }
        }
        payload.len() < 10
    }

    fn nats_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut frame_count = 0_usize;
        while offset < payload.len() {
            match nats_frame(payload, offset) {
                Some(NatsFrameParse::Complete(next_offset)) => {
                    frame_count += 1;
                    if frame_count > 16 {
                        return false;
                    }
                    offset = next_offset;
                }
                Some(NatsFrameParse::IncompleteBody) => return true,
                Some(NatsFrameParse::IncompleteLine) => return frame_count > 0,
                None => return false,
            }
        }
        frame_count > 0
    }

    enum NatsFrameParse {
        Complete(usize),
        IncompleteLine,
        IncompleteBody,
    }

    enum NatsLineParse<'a> {
        Complete { line: &'a [u8], next_offset: usize },
        Incomplete,
    }

    enum NatsCommandKind {
        Line,
        Payload {
            bytes: usize,
        },
        Headers {
            header_bytes: usize,
            total_bytes: usize,
        },
    }

    fn nats_frame(payload: &[u8], offset: usize) -> Option<NatsFrameParse> {
        let NatsLineParse::Complete { line, next_offset } = nats_control_line(payload, offset)?
        else {
            return Some(NatsFrameParse::IncompleteLine);
        };
        let command = nats_command_kind(line)?;
        match command {
            NatsCommandKind::Line => Some(NatsFrameParse::Complete(next_offset)),
            NatsCommandKind::Payload { bytes } => {
                nats_payload_body(payload, next_offset, bytes, None)
            }
            NatsCommandKind::Headers {
                header_bytes,
                total_bytes,
            } => nats_payload_body(payload, next_offset, total_bytes, Some(header_bytes)),
        }
    }

    fn nats_command_kind(line: &[u8]) -> Option<NatsCommandKind> {
        let fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let command = *fields.first()?;

        if command.eq_ignore_ascii_case(b"INFO") || command.eq_ignore_ascii_case(b"CONNECT") {
            return nats_json_object_after_command(line, command.len())
                .then_some(NatsCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"PING") || command.eq_ignore_ascii_case(b"PONG") {
            return (fields.len() == 1).then_some(NatsCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"+OK") {
            return (fields.len() == 1).then_some(NatsCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"-ERR") {
            return (fields.len() >= 2).then_some(NatsCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"PUB") {
            let bytes =
                nats_decimal_value(fields[fields.len().saturating_sub(1)], 64 * 1024 * 1024)?;
            return ((fields.len() == 3 || fields.len() == 4)
                && nats_subject(fields[1])
                && fields
                    .get(fields.len().saturating_sub(2))
                    .is_some_and(|field| fields.len() == 3 || nats_reply_subject(field))
                && nats_decimal(fields[fields.len() - 1]))
            .then_some(NatsCommandKind::Payload { bytes });
        }
        if command.eq_ignore_ascii_case(b"HPUB") {
            let header_bytes =
                nats_decimal_value(fields[fields.len().saturating_sub(2)], 64 * 1024 * 1024)?;
            let total_bytes =
                nats_decimal_value(fields[fields.len().saturating_sub(1)], 64 * 1024 * 1024)?;
            return ((fields.len() == 4 || fields.len() == 5)
                && nats_subject(fields[1])
                && fields
                    .get(fields.len().saturating_sub(3))
                    .is_some_and(|field| fields.len() == 4 || nats_reply_subject(field))
                && nats_decimal(fields[fields.len() - 2])
                && nats_decimal(fields[fields.len() - 1])
                && header_bytes <= total_bytes)
                .then_some(NatsCommandKind::Headers {
                    header_bytes,
                    total_bytes,
                });
        }
        if command.eq_ignore_ascii_case(b"SUB") {
            return ((fields.len() == 3 || fields.len() == 4)
                && nats_subscription_subject(fields[1])
                && fields
                    .get(fields.len().saturating_sub(2))
                    .is_some_and(|field| fields.len() == 3 || nats_queue_group(field))
                && nats_sid(fields[fields.len() - 1]))
            .then_some(NatsCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"UNSUB") {
            return ((fields.len() == 2 || fields.len() == 3)
                && nats_sid(fields[1])
                && (fields.len() == 2 || nats_decimal(fields[2])))
            .then_some(NatsCommandKind::Line);
        }
        if command.eq_ignore_ascii_case(b"MSG") {
            let bytes =
                nats_decimal_value(fields[fields.len().saturating_sub(1)], 64 * 1024 * 1024)?;
            return ((fields.len() == 4 || fields.len() == 5)
                && nats_subject(fields[1])
                && nats_sid(fields[2])
                && fields
                    .get(fields.len().saturating_sub(2))
                    .is_some_and(|field| fields.len() == 4 || nats_reply_subject(field))
                && nats_decimal(fields[fields.len() - 1]))
            .then_some(NatsCommandKind::Payload { bytes });
        }
        if command.eq_ignore_ascii_case(b"HMSG") {
            let header_bytes =
                nats_decimal_value(fields[fields.len().saturating_sub(2)], 64 * 1024 * 1024)?;
            let total_bytes =
                nats_decimal_value(fields[fields.len().saturating_sub(1)], 64 * 1024 * 1024)?;
            return ((fields.len() == 5 || fields.len() == 6)
                && nats_subject(fields[1])
                && nats_sid(fields[2])
                && fields
                    .get(fields.len().saturating_sub(3))
                    .is_some_and(|field| fields.len() == 5 || nats_reply_subject(field))
                && nats_decimal(fields[fields.len() - 2])
                && nats_decimal(fields[fields.len() - 1])
                && header_bytes <= total_bytes)
                .then_some(NatsCommandKind::Headers {
                    header_bytes,
                    total_bytes,
                });
        }
        None
    }

    fn nats_control_line(payload: &[u8], offset: usize) -> Option<NatsLineParse<'_>> {
        let tail = payload.get(offset..)?;
        let newline = tail.iter().position(|byte| *byte == b'\n');
        let Some(newline) = newline else {
            return Some(NatsLineParse::Incomplete);
        };
        if newline == 0 || tail.get(newline.saturating_sub(1)) != Some(&b'\r') {
            return None;
        }
        let line = tail.get(..newline - 1)?;
        (!line.is_empty()
            && line
                .iter()
                .all(|byte| !byte.is_ascii_control() || *byte == b'\t'))
        .then_some(NatsLineParse::Complete {
            line,
            next_offset: offset + newline + 1,
        })
    }

    fn nats_payload_body(
        payload: &[u8],
        payload_offset: usize,
        bytes: usize,
        header_bytes: Option<usize>,
    ) -> Option<NatsFrameParse> {
        let data_end = payload_offset.checked_add(bytes)?;
        let frame_end = data_end.checked_add(2)?;
        if let Some(header_bytes) = header_bytes {
            if header_bytes > bytes {
                return None;
            }
            let header_end = payload_offset.checked_add(header_bytes)?;
            if payload.len() >= header_end
                && !nats_header_block(payload.get(payload_offset..header_end)?)
            {
                return None;
            }
        }
        if payload.len() < data_end {
            return Some(NatsFrameParse::IncompleteBody);
        }
        if payload.len() < frame_end {
            return match payload.get(data_end..) {
                Some(b"") | Some(b"\r") => Some(NatsFrameParse::IncompleteBody),
                _ => None,
            };
        }
        (payload.get(data_end..frame_end)? == b"\r\n")
            .then_some(NatsFrameParse::Complete(frame_end))
    }

    fn nats_header_block(header: &[u8]) -> bool {
        header.starts_with(b"NATS/1.0\r\n") && header.ends_with(b"\r\n\r\n")
    }

    fn nats_json_object_after_command(line: &[u8], command_len: usize) -> bool {
        let Some(rest) = line.get(command_len..) else {
            return false;
        };
        let json = trim_ascii_space(rest);
        json.len() >= 2 && json.first() == Some(&b'{') && json.last() == Some(&b'}')
    }

    fn nats_subject(field: &[u8]) -> bool {
        nats_subject_tokens(field, false)
    }

    fn nats_subscription_subject(field: &[u8]) -> bool {
        nats_subject_tokens(field, true)
    }

    fn nats_subject_tokens(field: &[u8], allow_wildcards: bool) -> bool {
        if !nats_token(field) || field.starts_with(b".") || field.ends_with(b".") {
            return false;
        }
        let mut tokens = field.split(|byte| *byte == b'.').peekable();
        while let Some(token) = tokens.next() {
            if token.is_empty() {
                return false;
            }
            if token.contains(&b'*') || token.contains(&b'>') {
                let valid_wildcard = token == b"*" || (token == b">" && tokens.peek().is_none());
                if !allow_wildcards || !valid_wildcard {
                    return false;
                }
            }
        }
        true
    }

    fn nats_reply_subject(field: &[u8]) -> bool {
        nats_subject(field)
    }

    fn nats_queue_group(field: &[u8]) -> bool {
        nats_token(field)
    }

    fn nats_sid(field: &[u8]) -> bool {
        nats_token(field)
    }

    fn nats_token(field: &[u8]) -> bool {
        !field.is_empty()
            && field.len() <= 1024
            && field
                .iter()
                .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
    }

    fn nats_decimal(field: &[u8]) -> bool {
        !field.is_empty() && field.len() <= 20 && field.iter().all(u8::is_ascii_digit)
    }

    fn nats_decimal_value(field: &[u8], max: usize) -> Option<usize> {
        if field.is_empty() || field.len() > 20 {
            return None;
        }
        let mut value = 0_usize;
        for byte in field {
            let digit = byte.checked_sub(b'0')?;
            if digit > 9 {
                return None;
            }
            value = value.checked_mul(10)?.checked_add(digit as usize)?;
            if value > max {
                return None;
            }
        }
        Some(value)
    }

    fn mqtt_payload(payload: &[u8]) -> bool {
        if payload.len() < 8 || payload[0] != 0x10 {
            return false;
        }
        let Some((remaining_len, mut offset)) = mqtt_variable_integer(payload, 1) else {
            return false;
        };
        if remaining_len < 10 {
            return false;
        }
        let Some(remaining_end) = offset.checked_add(remaining_len) else {
            return false;
        };
        if remaining_end > payload.len() {
            return false;
        }
        let Some(protocol_name_len) = read_u16_be(payload, offset).map(|len| len as usize) else {
            return false;
        };
        offset += 2;
        let Some(protocol_name_end) = offset.checked_add(protocol_name_len) else {
            return false;
        };
        let Some(variable_header_len) = 2_usize
            .checked_add(protocol_name_len)
            .and_then(|len| len.checked_add(4))
        else {
            return false;
        };
        if remaining_len < variable_header_len {
            return false;
        }
        let Some(protocol_name) = payload.get(offset..protocol_name_end) else {
            return false;
        };
        let Some(&protocol_level) = payload.get(protocol_name_end) else {
            return false;
        };
        let Some(&connect_flags) = payload.get(protocol_name_end + 1) else {
            return false;
        };
        let keepalive_end = protocol_name_end + 4;
        if payload.get(protocol_name_end + 2..keepalive_end).is_none()
            || !mqtt_connect_flags(connect_flags)
            || remaining_end < keepalive_end
        {
            return false;
        }

        let payload_start = if protocol_name == b"MQTT" && protocol_level == 5 {
            let Some((properties_len, properties_offset)) =
                mqtt_variable_integer_until(payload, keepalive_end, remaining_end)
            else {
                return false;
            };
            let Some(payload_start) = properties_offset.checked_add(properties_len) else {
                return false;
            };
            if payload_start > remaining_end {
                return false;
            }
            payload_start
        } else {
            keepalive_end
        };

        let protocol_ok = protocol_name == b"MQTT" && matches!(protocol_level, 4 | 5)
            || protocol_name == b"MQIsdp" && protocol_level == 3;
        protocol_ok
            && mqtt_connect_payload(
                payload,
                payload_start,
                remaining_end,
                connect_flags,
                protocol_level,
            )
    }

    fn mqtt_variable_integer(payload: &[u8], offset: usize) -> Option<(usize, usize)> {
        mqtt_variable_integer_until(payload, offset, payload.len())
    }

    fn mqtt_variable_integer_until(
        payload: &[u8],
        mut offset: usize,
        limit: usize,
    ) -> Option<(usize, usize)> {
        let mut value = 0_usize;
        let mut multiplier = 1_usize;
        for _ in 0..4 {
            if offset >= limit {
                return None;
            }
            let byte = *payload.get(offset)?;
            value = value.checked_add(((byte & 0x7f) as usize).checked_mul(multiplier)?)?;
            offset += 1;
            if byte & 0x80 == 0 {
                return Some((value, offset));
            }
            multiplier = multiplier.checked_mul(128)?;
        }
        None
    }

    fn mqtt_connect_flags(flags: u8) -> bool {
        let username = flags & 0x80 != 0;
        let password = flags & 0x40 != 0;
        let will_retain = flags & 0x20 != 0;
        let will_qos = (flags >> 3) & 0x03;
        let will = flags & 0x04 != 0;

        flags & 0x01 == 0
            && (!password || username)
            && (will || (!will_retain && will_qos == 0))
            && will_qos != 0x03
    }

    fn mqtt_connect_payload(
        payload: &[u8],
        payload_start: usize,
        remaining_end: usize,
        connect_flags: u8,
        protocol_level: u8,
    ) -> bool {
        let Some((client_id, mut offset)) = mqtt_utf8_field(payload, payload_start, remaining_end)
        else {
            return false;
        };
        if !mqtt_client_identifier(client_id, connect_flags) {
            return false;
        }

        if connect_flags & 0x04 != 0 {
            if protocol_level == 5 {
                let Some((will_properties_len, will_properties_offset)) =
                    mqtt_variable_integer_until(payload, offset, remaining_end)
                else {
                    return false;
                };
                let Some(will_topic_offset) =
                    will_properties_offset.checked_add(will_properties_len)
                else {
                    return false;
                };
                if will_topic_offset > remaining_end {
                    return false;
                }
                offset = will_topic_offset;
            }
            let Some((_, will_payload_offset)) = mqtt_utf8_field(payload, offset, remaining_end)
            else {
                return false;
            };
            let Some((_, next_offset)) =
                mqtt_len_prefixed_field(payload, will_payload_offset, remaining_end)
            else {
                return false;
            };
            offset = next_offset;
        }

        if connect_flags & 0x80 != 0 {
            let Some((_, next_offset)) = mqtt_utf8_field(payload, offset, remaining_end) else {
                return false;
            };
            offset = next_offset;
        }
        if connect_flags & 0x40 != 0 {
            let Some((_, next_offset)) = mqtt_len_prefixed_field(payload, offset, remaining_end)
            else {
                return false;
            };
            offset = next_offset;
        }

        offset == remaining_end
    }

    fn mqtt_client_identifier(client_id: &[u8], connect_flags: u8) -> bool {
        let clean_start = connect_flags & 0x02 != 0;
        (!client_id.is_empty() || clean_start) && mqtt_utf8_string(client_id)
    }

    fn mqtt_utf8_field(
        payload: &[u8],
        offset: usize,
        remaining_end: usize,
    ) -> Option<(&[u8], usize)> {
        let (field, next_offset) = mqtt_len_prefixed_field(payload, offset, remaining_end)?;
        mqtt_utf8_string(field).then_some((field, next_offset))
    }

    fn mqtt_len_prefixed_field(
        payload: &[u8],
        offset: usize,
        remaining_end: usize,
    ) -> Option<(&[u8], usize)> {
        let len = read_u16_be(payload, offset)? as usize;
        let start = offset.checked_add(2)?;
        let end = start.checked_add(len)?;
        if end > remaining_end {
            return None;
        }
        payload.get(start..end).map(|field| (field, end))
    }

    fn mqtt_utf8_string(field: &[u8]) -> bool {
        std::str::from_utf8(field).is_ok()
            && field
                .iter()
                .all(|byte| *byte != 0 && !byte.is_ascii_control())
    }

    fn amqp_payload(payload: &[u8]) -> bool {
        amqp_protocol_header_payload(payload) || amqp_frame_payload(payload)
    }

    fn amqp_protocol_header_payload(payload: &[u8]) -> bool {
        if payload.len() < 8 || payload.get(..4) != Some(b"AMQP") {
            return false;
        }
        matches!(
            (payload[4], payload[5], payload[6], payload[7]),
            (0, 0, 9, 1) | (0, 1, 0, 0) | (3, 1, 0, 0)
        )
    }

    fn amqp_frame_payload(payload: &[u8]) -> bool {
        if payload.len() < 8 {
            return false;
        }
        let frame_type = payload[0];
        let channel = u16::from_be_bytes([payload[1], payload[2]]);
        let frame_size =
            u32::from_be_bytes([payload[3], payload[4], payload[5], payload[6]]) as usize;
        let Some(frame_end_offset) = 7_usize.checked_add(frame_size) else {
            return false;
        };
        if frame_end_offset >= payload.len() || payload[frame_end_offset] != 0xce {
            return false;
        }
        match frame_type {
            1 => (4..=131_072).contains(&frame_size),
            2 => channel != 0 && (14..=131_072).contains(&frame_size),
            3 => channel != 0 && frame_size <= 16_777_216,
            8 => channel == 0 && frame_size == 0,
            _ => false,
        }
    }

    fn cassandra_payload(payload: &[u8]) -> bool {
        if payload.len() < 9 {
            return false;
        }
        let version_byte = payload[0];
        let version = version_byte & 0x7f;
        let flags = payload[1];
        let opcode = payload[4];
        let body_len =
            u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]) as usize;
        let body_prefix = &payload[9..];

        if !matches!(version_byte, 0x03..=0x05 | 0x83..=0x85)
            || !(3..=5).contains(&version)
            || flags & !0x1f != 0
            || body_len > 16_777_216
        {
            return false;
        }

        let is_response = version_byte & 0x80 != 0;
        if is_response {
            cassandra_response_body(opcode, body_len, body_prefix)
        } else {
            cassandra_request_body(version, opcode, body_len, body_prefix)
        }
    }

    fn cassandra_request_body(
        version: u8,
        opcode: u8,
        body_len: usize,
        body_prefix: &[u8],
    ) -> bool {
        match opcode {
            0x01 => cassandra_startup_body(body_len, body_prefix),
            0x05 => body_len == 0,
            0x07 => cassandra_cql_query_body(version, body_len, body_prefix, true),
            0x09 => cassandra_cql_query_body(version, body_len, body_prefix, false),
            0x0a => cassandra_execute_body(version, body_len, body_prefix),
            0x0b => cassandra_string_list_body(body_len, body_prefix),
            0x0d => body_len >= 6 && body_prefix.len() >= 6,
            0x0f => body_len >= 4 && body_prefix.len() >= 4,
            _ => false,
        }
    }

    fn cassandra_response_body(opcode: u8, body_len: usize, body_prefix: &[u8]) -> bool {
        match opcode {
            0x00 => body_len >= 8 && body_prefix.len() >= 8,
            0x02 => body_len == 0,
            0x03 => cassandra_string_body(body_len, body_prefix),
            0x06 => body_len >= 2 && body_prefix.len() >= 2,
            0x08 => body_len >= 4 && body_prefix.len() >= 4,
            0x0c => cassandra_string_prefix_body(body_len, body_prefix),
            0x0e | 0x10 => body_len >= 4 && body_prefix.len() >= 4,
            _ => false,
        }
    }

    fn cassandra_startup_body(body_len: usize, body_prefix: &[u8]) -> bool {
        if body_len < 2 || body_prefix.len() < body_len {
            return false;
        }
        let Some(count) = read_u16_be(body_prefix, 0).map(|count| count as usize) else {
            return false;
        };
        if count == 0 || count > 64 {
            return false;
        }

        let mut offset = 2;
        let mut has_cql_version = false;
        for _ in 0..count {
            let Some((key, next_offset)) = cassandra_string_field(body_prefix, offset) else {
                return false;
            };
            let Some((value, next_offset)) = cassandra_string_field(body_prefix, next_offset)
            else {
                return false;
            };
            has_cql_version |= key.eq_ignore_ascii_case(b"CQL_VERSION") && value.starts_with(b"3.");
            offset = next_offset;
        }
        offset == body_len && has_cql_version
    }

    fn cassandra_cql_query_body(
        version: u8,
        body_len: usize,
        body_prefix: &[u8],
        has_consistency: bool,
    ) -> bool {
        if body_len < 5 || body_prefix.len() < 4 {
            return false;
        }
        let Some(query_len) = read_u32_be(body_prefix, 0).map(|len| len as usize) else {
            return false;
        };
        if query_len == 0 || query_len > 1_048_576 {
            return false;
        }
        let Some(query_end) = 4_usize.checked_add(query_len) else {
            return false;
        };
        let required_len = if has_consistency {
            cassandra_query_parameter_header_len(version)
                .and_then(|parameters_len| query_end.checked_add(parameters_len))
        } else {
            Some(query_end)
        };
        let Some(required_len) = required_len else {
            return false;
        };
        if body_len < required_len || body_prefix.len() < required_len {
            return false;
        }
        if !has_consistency && body_len != required_len {
            return false;
        }
        let query = trim_ascii_space(&body_prefix[4..query_end]);
        cassandra_cql_statement(query)
            && (!has_consistency
                || cassandra_query_parameters(version, body_len, body_prefix, query_end))
    }

    fn cassandra_cql_statement(query: &[u8]) -> bool {
        let keywords: [&[u8]; 17] = [
            b"SELECT",
            b"INSERT",
            b"UPDATE",
            b"DELETE",
            b"BEGIN",
            b"APPLY",
            b"USE",
            b"CREATE",
            b"ALTER",
            b"DROP",
            b"TRUNCATE",
            b"GRANT",
            b"REVOKE",
            b"LIST",
            b"DESCRIBE",
            b"DESC",
            b"UNLOGGED",
        ];
        keywords
            .iter()
            .any(|keyword| starts_ascii_keyword(query, keyword))
    }

    fn cassandra_execute_body(version: u8, body_len: usize, body_prefix: &[u8]) -> bool {
        if body_prefix.len() < 2 {
            return false;
        }
        let Some(prepared_id_len) = read_u16_be(body_prefix, 0).map(|len| len as usize) else {
            return false;
        };
        if prepared_id_len == 0 || prepared_id_len > 65_535 {
            return false;
        }
        let Some(required_len) = 2_usize
            .checked_add(prepared_id_len)
            .and_then(|len| len.checked_add(cassandra_query_parameter_header_len(version)?))
        else {
            return false;
        };
        body_len >= required_len
            && body_prefix.len() >= required_len
            && cassandra_query_parameters(version, body_len, body_prefix, 2 + prepared_id_len)
    }

    fn cassandra_query_parameter_header_len(version: u8) -> Option<usize> {
        match version {
            3 | 4 => Some(3),
            5 => Some(6),
            _ => None,
        }
    }

    fn cassandra_query_parameters(
        version: u8,
        body_len: usize,
        body_prefix: &[u8],
        offset: usize,
    ) -> bool {
        let Some(consistency) = read_u16_be(body_prefix, offset) else {
            return false;
        };
        if !cassandra_consistency(consistency) {
            return false;
        }
        let Some(mut offset) = offset.checked_add(2) else {
            return false;
        };

        let Some((flags, next_offset)) =
            cassandra_query_parameter_flags(version, body_prefix, offset)
        else {
            return false;
        };
        if !cassandra_query_parameter_flags_supported(version, flags) {
            return false;
        }
        offset = next_offset;

        if body_prefix.len() < body_len {
            return true;
        }

        if flags & 0x01 != 0 {
            let Some(count) = read_u16_be(body_prefix, offset).map(|count| count as usize) else {
                return false;
            };
            if count > 1024 {
                return false;
            }
            let Some(next_offset) = offset.checked_add(2) else {
                return false;
            };
            offset = next_offset;
            for _ in 0..count {
                if flags & 0x40 != 0 {
                    let Some((_name, next_offset)) = cassandra_string_field(body_prefix, offset)
                    else {
                        return false;
                    };
                    offset = next_offset;
                }
                let Some(next_offset) = cassandra_bytes_field(body_prefix, offset, body_len, true)
                else {
                    return false;
                };
                offset = next_offset;
            }
        }

        if flags & 0x04 != 0 {
            let Some(page_size) = read_u32_be(body_prefix, offset) else {
                return false;
            };
            if page_size == 0 || page_size & 0x8000_0000 != 0 {
                return false;
            }
            let Some(next_offset) = offset.checked_add(4) else {
                return false;
            };
            offset = next_offset;
        }
        if flags & 0x08 != 0 {
            let Some(next_offset) = cassandra_bytes_field(body_prefix, offset, body_len, false)
            else {
                return false;
            };
            offset = next_offset;
        }
        if flags & 0x10 != 0 {
            let Some(serial_consistency) = read_u16_be(body_prefix, offset) else {
                return false;
            };
            if !matches!(serial_consistency, 0x0008 | 0x0009) {
                return false;
            }
            let Some(next_offset) = offset.checked_add(2) else {
                return false;
            };
            offset = next_offset;
        }
        if flags & 0x20 != 0 {
            let Some(timestamp) = body_prefix.get(offset..offset.saturating_add(8)) else {
                return false;
            };
            if timestamp.first().is_some_and(|byte| byte & 0x80 != 0) {
                return false;
            }
            let Some(next_offset) = offset.checked_add(8) else {
                return false;
            };
            offset = next_offset;
        }
        if version == 5 {
            if flags & 0x80 != 0 {
                let Some((_keyspace, next_offset)) = cassandra_string_field(body_prefix, offset)
                else {
                    return false;
                };
                offset = next_offset;
            }
            if flags & 0x100 != 0 {
                let Some(now) = read_u32_be(body_prefix, offset) else {
                    return false;
                };
                if now & 0x8000_0000 != 0 {
                    return false;
                }
                let Some(next_offset) = offset.checked_add(4) else {
                    return false;
                };
                offset = next_offset;
            }
        }

        offset == body_len
    }

    fn cassandra_query_parameter_flags(
        version: u8,
        payload: &[u8],
        offset: usize,
    ) -> Option<(u32, usize)> {
        match version {
            3 | 4 => payload
                .get(offset)
                .and_then(|flags| offset.checked_add(1).map(|next| (*flags as u32, next))),
            5 => read_u32_be(payload, offset).zip(offset.checked_add(4)),
            _ => None,
        }
    }

    fn cassandra_query_parameter_flags_supported(version: u8, flags: u32) -> bool {
        let supported = match version {
            3 | 4 => 0x7f,
            5 => 0x01ff,
            _ => return false,
        };
        flags & !supported == 0 && (flags & 0x40 == 0 || flags & 0x01 != 0)
    }

    fn cassandra_consistency(consistency: u16) -> bool {
        matches!(consistency, 0x0000..=0x000a)
    }

    fn cassandra_bytes_field(
        payload: &[u8],
        offset: usize,
        body_len: usize,
        allow_unset: bool,
    ) -> Option<usize> {
        let length_bytes = payload.get(offset..offset.checked_add(4)?)?;
        let len = i32::from_be_bytes(length_bytes.try_into().ok()?);
        let value_start = offset.checked_add(4)?;
        if len == -1 || (allow_unset && len == -2) {
            return Some(value_start);
        }
        if len < 0 {
            return None;
        }
        let len = len as usize;
        if len > 16_777_216 {
            return None;
        }
        let value_end = value_start.checked_add(len)?;
        if value_end > body_len || value_end > payload.len() {
            return None;
        }
        Some(value_end)
    }

    fn cassandra_string_list_body(body_len: usize, body_prefix: &[u8]) -> bool {
        if body_len < 2 || body_prefix.len() < body_len {
            return false;
        }
        let Some(count) = read_u16_be(body_prefix, 0).map(|count| count as usize) else {
            return false;
        };
        if count == 0 || count > 64 {
            return false;
        }
        let mut offset = 2;
        for _ in 0..count {
            let Some((_value, next_offset)) = cassandra_string_field(body_prefix, offset) else {
                return false;
            };
            offset = next_offset;
        }
        offset == body_len
    }

    fn cassandra_string_body(body_len: usize, body_prefix: &[u8]) -> bool {
        if body_prefix.len() < body_len {
            return false;
        }
        cassandra_string_field(body_prefix, 0).is_some_and(|(_value, offset)| offset == body_len)
    }

    fn cassandra_string_prefix_body(body_len: usize, body_prefix: &[u8]) -> bool {
        if body_prefix.len() < body_len {
            return false;
        }
        cassandra_string_field(body_prefix, 0).is_some_and(|(_value, offset)| offset <= body_len)
    }

    fn cassandra_string_field(payload: &[u8], offset: usize) -> Option<(&[u8], usize)> {
        let len = read_u16_be(payload, offset)? as usize;
        if len == 0 || len > 4096 {
            return None;
        }
        let value_start = offset.checked_add(2)?;
        let value_end = value_start.checked_add(len)?;
        let value = payload.get(value_start..value_end)?;
        if !value
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
        {
            return None;
        }
        Some((value, value_end))
    }

    fn mongodb_payload(payload: &[u8]) -> bool {
        if payload.len() < 16 {
            return false;
        }
        let Some(message_len) = read_u32_le(payload, 0).map(|len| len as usize) else {
            return false;
        };
        let Some(opcode) = read_u32_le(payload, 12) else {
            return false;
        };
        if !(16..=100_000_000).contains(&message_len) {
            return false;
        }

        match opcode {
            1 => mongodb_op_reply_payload(payload, message_len),
            2012 => mongodb_op_compressed_payload(payload, message_len),
            2001 => mongodb_op_update_payload(payload, message_len),
            2002 => mongodb_op_insert_payload(payload, message_len),
            2004 => mongodb_op_query_payload(payload, message_len),
            2005 => mongodb_op_get_more_payload(payload, message_len),
            2006 => mongodb_op_delete_payload(payload, message_len),
            2007 => mongodb_op_kill_cursors_payload(payload, message_len),
            2013 => mongodb_op_msg_payload(payload, message_len),
            _ => false,
        }
    }

    fn mongodb_op_reply_payload(payload: &[u8], message_len: usize) -> bool {
        if message_len < 36 || payload.len() < 36 {
            return false;
        }
        let Some(flags) = read_u32_le(payload, 16) else {
            return false;
        };
        let Some(number_returned) = read_u32_le(payload, 32).map(|count| count as usize) else {
            return false;
        };
        if flags & !0x0f != 0 || number_returned > 1_000_000 {
            return false;
        }
        if number_returned == 0 {
            return message_len == 36;
        }
        let min_documents = if mongodb_full_message_observed(payload, message_len) {
            number_returned
        } else {
            1
        };
        mongodb_bson_document_sequence(
            payload,
            36,
            message_len,
            min_documents,
            Some(number_returned),
        )
    }

    fn mongodb_op_compressed_payload(payload: &[u8], message_len: usize) -> bool {
        if message_len < 25 || payload.len() < 25 {
            return false;
        }
        let Some(original_opcode) = read_u32_le(payload, 16) else {
            return false;
        };
        let Some(uncompressed_size) = read_u32_le(payload, 20).map(|size| size as usize) else {
            return false;
        };
        let Some(compressor_id) = payload.get(24) else {
            return false;
        };
        mongodb_wire_opcode(original_opcode)
            && original_opcode != 2012
            && uncompressed_size <= 100_000_000
            && matches!(*compressor_id, 0..=3)
            && (!mongodb_full_message_observed(payload, message_len) || message_len > 25)
    }

    fn mongodb_op_update_payload(payload: &[u8], message_len: usize) -> bool {
        if message_len < 35 || payload.len() < 25 || read_u32_le(payload, 16) != Some(0) {
            return false;
        }
        let Some((namespace, flags_offset)) = mongodb_cstring_field(payload, 20, message_len)
        else {
            return false;
        };
        let Some(flags) = read_u32_le(payload, flags_offset) else {
            return false;
        };
        if !mongodb_collection_namespace(namespace) || flags & !0x03 != 0 {
            return false;
        }
        let selector_offset = flags_offset + 4;
        mongodb_bson_document_sequence(payload, selector_offset, message_len, 2, Some(2))
    }

    fn mongodb_op_insert_payload(payload: &[u8], message_len: usize) -> bool {
        if message_len < 30 || payload.len() < 25 {
            return false;
        }
        let Some(flags) = read_u32_le(payload, 16) else {
            return false;
        };
        let Some((namespace, document_offset)) = mongodb_cstring_field(payload, 20, message_len)
        else {
            return false;
        };
        flags & !0x01 == 0
            && mongodb_collection_namespace(namespace)
            && mongodb_bson_document_sequence(payload, document_offset, message_len, 1, None)
    }

    fn mongodb_op_query_payload(payload: &[u8], message_len: usize) -> bool {
        if message_len < 37 || payload.len() < 29 {
            return false;
        }
        let Some(flags) = read_u32_le(payload, 16) else {
            return false;
        };
        let Some((namespace, skip_offset)) = mongodb_cstring_field(payload, 20, message_len) else {
            return false;
        };
        let Some(query_offset) = skip_offset.checked_add(8) else {
            return false;
        };
        flags & !0x7f == 0
            && mongodb_collection_namespace(namespace)
            && query_offset <= message_len
            && payload.len() >= skip_offset.saturating_add(8)
            && mongodb_bson_document_sequence(payload, query_offset, message_len, 1, Some(2))
    }

    fn mongodb_op_get_more_payload(payload: &[u8], message_len: usize) -> bool {
        if message_len < 32 || payload.len() < 28 || read_u32_le(payload, 16) != Some(0) {
            return false;
        }
        let Some((namespace, number_to_return_offset)) =
            mongodb_cstring_field(payload, 20, message_len)
        else {
            return false;
        };
        let Some(end) = number_to_return_offset.checked_add(12) else {
            return false;
        };
        mongodb_collection_namespace(namespace) && end == message_len && payload.len() >= end
    }

    fn mongodb_op_delete_payload(payload: &[u8], message_len: usize) -> bool {
        if message_len < 35 || payload.len() < 25 || read_u32_le(payload, 16) != Some(0) {
            return false;
        }
        let Some((namespace, flags_offset)) = mongodb_cstring_field(payload, 20, message_len)
        else {
            return false;
        };
        let Some(flags) = read_u32_le(payload, flags_offset) else {
            return false;
        };
        let selector_offset = flags_offset + 4;
        flags & !0x01 == 0
            && mongodb_collection_namespace(namespace)
            && mongodb_bson_document_sequence(payload, selector_offset, message_len, 1, Some(1))
    }

    fn mongodb_op_kill_cursors_payload(payload: &[u8], message_len: usize) -> bool {
        if message_len < 32 || payload.len() < 32 || read_u32_le(payload, 16) != Some(0) {
            return false;
        }
        let Some(cursor_count) = read_u32_le(payload, 20).map(|count| count as usize) else {
            return false;
        };
        if cursor_count == 0 || cursor_count > 10_000 {
            return false;
        }
        let Some(cursor_bytes) = cursor_count.checked_mul(8) else {
            return false;
        };
        let Some(expected_len) = 24_usize.checked_add(cursor_bytes) else {
            return false;
        };
        expected_len == message_len && payload.len() >= expected_len
    }

    fn mongodb_op_msg_payload(payload: &[u8], message_len: usize) -> bool {
        if message_len < 26 || payload.len() < 21 {
            return false;
        }
        let Some(flags) = read_u32_le(payload, 16) else {
            return false;
        };
        if flags & 0x0000_fffc != 0 {
            return false;
        }
        let checksum_len = if flags & 0x0000_0001 != 0 { 4 } else { 0 };
        let Some(section_limit) = message_len.checked_sub(checksum_len) else {
            return false;
        };
        if section_limit <= 20 {
            return false;
        }
        mongodb_op_msg_sections(payload, 20, section_limit)
    }

    fn mongodb_op_msg_sections(payload: &[u8], mut offset: usize, section_limit: usize) -> bool {
        let full_message = mongodb_full_message_observed(payload, section_limit);
        let mut section_count = 0_usize;
        while offset < section_limit {
            let Some(next_offset) = mongodb_op_msg_section(payload, offset, section_limit) else {
                return false;
            };
            section_count += 1;
            if next_offset > payload.len() {
                return !full_message;
            }
            offset = next_offset;
            if !full_message && offset >= payload.len() {
                return true;
            }
        }
        section_count > 0 && offset == section_limit
    }

    fn mongodb_op_msg_section(
        payload: &[u8],
        offset: usize,
        section_limit: usize,
    ) -> Option<usize> {
        let section_kind = *payload.get(offset)?;
        match section_kind {
            0 => mongodb_bson_document_prefix(payload, offset.checked_add(1)?, section_limit),
            1 => {
                let section_size = read_u32_le(payload, offset.checked_add(1)?)? as usize;
                if !(6..=16_777_216).contains(&section_size) {
                    return None;
                }
                let section_body_offset = offset.checked_add(5)?;
                let section_end = offset.checked_add(1)?.checked_add(section_size)?;
                if section_end > section_limit {
                    return None;
                }
                let (identifier, document_offset) =
                    mongodb_cstring_field(payload, section_body_offset, section_end)?;
                if !mongodb_sequence_identifier(identifier) {
                    return None;
                }
                mongodb_bson_document_sequence(payload, document_offset, section_end, 0, None)
                    .then_some(())?;
                Some(section_end)
            }
            _ => None,
        }
    }

    fn mongodb_bson_document_prefix(
        payload: &[u8],
        offset: usize,
        message_len: usize,
    ) -> Option<usize> {
        let document_len = read_u32_le(payload, offset)? as usize;
        if !(5..=16_777_216).contains(&document_len) {
            return None;
        }
        let document_end = offset.checked_add(document_len)?;
        if document_end > message_len {
            return None;
        }
        if payload.len() >= document_end && payload.get(document_end - 1) != Some(&0) {
            return None;
        }
        Some(document_end)
    }

    fn mongodb_bson_document_sequence(
        payload: &[u8],
        mut offset: usize,
        message_len: usize,
        min_documents: usize,
        max_documents: Option<usize>,
    ) -> bool {
        if offset > message_len {
            return false;
        }
        let full_message = mongodb_full_message_observed(payload, message_len);
        let mut document_count = 0_usize;
        while offset < message_len {
            if !full_message && payload.len().saturating_sub(offset) < 4 {
                return document_count >= min_documents
                    && max_documents.is_none_or(|max| document_count <= max);
            }
            if max_documents.is_some_and(|max| document_count >= max) {
                return false;
            }
            let Some(next_offset) = mongodb_bson_document_prefix(payload, offset, message_len)
            else {
                return false;
            };
            document_count += 1;
            if next_offset > payload.len() {
                return !full_message && document_count >= min_documents;
            }
            offset = next_offset;
            if !full_message && offset >= payload.len() {
                return document_count >= min_documents
                    && max_documents.is_none_or(|max| document_count <= max);
            }
        }
        document_count >= min_documents
            && max_documents.is_none_or(|max| document_count <= max)
            && offset == message_len
    }

    fn mongodb_cstring_field(
        payload: &[u8],
        offset: usize,
        message_len: usize,
    ) -> Option<(&[u8], usize)> {
        let limit = payload.len().min(message_len);
        let tail = payload.get(offset..limit)?;
        let terminator = tail.iter().position(|byte| *byte == 0)?;
        if terminator == 0 || terminator > 512 {
            return None;
        }
        let end = offset.checked_add(terminator)?;
        Some((payload.get(offset..end)?, end + 1))
    }

    fn mongodb_collection_namespace(namespace: &[u8]) -> bool {
        mongodb_ascii_name(namespace)
            && namespace.contains(&b'.')
            && !namespace.starts_with(b".")
            && !namespace.ends_with(b".")
    }

    fn mongodb_wire_opcode(opcode: u32) -> bool {
        matches!(
            opcode,
            1 | 2001 | 2002 | 2004 | 2005 | 2006 | 2007 | 2012 | 2013
        )
    }

    fn mongodb_full_message_observed(payload: &[u8], message_len: usize) -> bool {
        payload.len() >= message_len
    }

    fn mongodb_sequence_identifier(identifier: &[u8]) -> bool {
        mongodb_ascii_name(identifier)
    }

    fn mongodb_ascii_name(value: &[u8]) -> bool {
        !value.is_empty()
            && value.len() <= 512
            && value.iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.' | b'$')
            })
    }

    fn elasticsearch_transport_payload(payload: &[u8]) -> bool {
        const FRAME_PREFIX_LEN: usize = 6;
        const HEADER_LEN: usize = 17;
        const HEADER_END: usize = FRAME_PREFIX_LEN + HEADER_LEN;
        const MAX_MESSAGE_LEN: usize = 128 * 1024 * 1024;

        if payload.len() < HEADER_END || payload.get(..2) != Some(b"ES") {
            return false;
        }
        let Some(message_len) = read_u32_be(payload, 2).map(|len| len as usize) else {
            return false;
        };
        if !(HEADER_LEN..=MAX_MESSAGE_LEN).contains(&message_len) {
            return false;
        }
        let Some(frame_end) = FRAME_PREFIX_LEN.checked_add(message_len) else {
            return false;
        };
        let Some(&status) = payload.get(14) else {
            return false;
        };
        let Some(version_id) = read_u32_be(payload, 15) else {
            return false;
        };
        let Some(variable_header_size) = read_u32_be(payload, 19).map(|len| len as usize) else {
            return false;
        };
        let Some(variable_header_end) = HEADER_END.checked_add(variable_header_size) else {
            return false;
        };

        elasticsearch_transport_status(status)
            && elasticsearch_transport_version_id(version_id)
            && variable_header_size <= message_len - HEADER_LEN
            && variable_header_end <= frame_end
    }

    fn elasticsearch_transport_status(status: u8) -> bool {
        let response = status & 0x01 != 0;
        let error = status & 0x02 != 0;
        status & !0x0f == 0 && (response || !error)
    }

    fn elasticsearch_transport_version_id(version_id: u32) -> bool {
        const MIN_VERSION_WITH_VARIABLE_HEADER_SIZE: u32 = 7_06_00_00;
        const MAX_PLAUSIBLE_VERSION: u32 = 99_99_99_99;

        (MIN_VERSION_WITH_VARIABLE_HEADER_SIZE..=MAX_PLAUSIBLE_VERSION).contains(&version_id)
    }

    fn starts_ascii_keyword(payload: &[u8], keyword: &[u8]) -> bool {
        let Some(head) = payload.get(..keyword.len()) else {
            return false;
        };
        if !head.eq_ignore_ascii_case(keyword) {
            return false;
        }
        payload
            .get(keyword.len())
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
    }

    fn ascii_contains_ignore_case(payload: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && payload
                .windows(needle.len())
                .any(|window| window.eq_ignore_ascii_case(needle))
    }

    fn trim_ascii_space(payload: &[u8]) -> &[u8] {
        let start = payload
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .unwrap_or(payload.len());
        let end = payload
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())
            .map(|index| index + 1)
            .unwrap_or(start);
        &payload[start..end]
    }

    fn trim_utf16le_ascii_space(payload: &[u8]) -> &[u8] {
        if payload.len() < 2 {
            return &[];
        }
        let mut start = 0_usize;
        while start + 1 < payload.len()
            && payload[start + 1] == 0
            && payload[start].is_ascii_whitespace()
        {
            start += 2;
        }
        let mut end = payload.len() & !1;
        while end >= start + 2 && payload[end - 1] == 0 && payload[end - 2].is_ascii_whitespace() {
            end -= 2;
        }
        let candidate = &payload[start..end];
        if candidate.is_empty()
            || !candidate.chunks_exact(2).all(|chunk| {
                chunk[1] == 0 && (!chunk[0].is_ascii_control() || chunk[0].is_ascii_whitespace())
            })
        {
            return &[];
        }
        candidate
    }

    fn starts_utf16le_ascii_keyword(payload: &[u8], keyword: &[u8]) -> bool {
        let keyword_bytes = keyword.len().checked_mul(2).unwrap_or(usize::MAX);
        if keyword.is_empty() || payload.len() < keyword_bytes {
            return false;
        }
        for (index, expected) in keyword.iter().enumerate() {
            let offset = index * 2;
            let Some((&byte, &zero)) = payload.get(offset).zip(payload.get(offset + 1)) else {
                return false;
            };
            if zero != 0 || !byte.eq_ignore_ascii_case(expected) {
                return false;
            }
        }
        if payload.len() == keyword_bytes {
            return true;
        }
        let Some((&byte, &zero)) = payload
            .get(keyword_bytes)
            .zip(payload.get(keyword_bytes + 1))
        else {
            return true;
        };
        zero == 0 && !byte.is_ascii_alphanumeric() && byte != b'_'
    }

    fn path_starts_with_any(path: &[u8], prefixes: &[&[u8]]) -> bool {
        prefixes.iter().any(|prefix| path.starts_with(prefix))
    }

    fn path_starts_with_api_prefix(path: &[u8], prefix: &[u8]) -> bool {
        path.starts_with(prefix) && matches!(path.get(prefix.len()), None | Some(b'/') | Some(b'?'))
    }

    fn path_contains_any(path: &[u8], needles: &[&[u8]]) -> bool {
        needles
            .iter()
            .any(|needle| path.windows(needle.len()).any(|window| window == *needle))
    }

    fn contains_ascii_case_insensitive(payload: &[u8], needle: &[u8]) -> bool {
        payload
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filtered_reason: Option<AgentPacketFlowDropReason>,
        pub matched: Option<AgentPacketFlowMatch>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentRelayForwarderMetrics {
        pub peer: NodeId,
        pub relay_node: NodeId,
        pub relay_endpoint: SocketAddr,
        pub local_endpoint: SocketAddr,
        #[serde(default)]
        pub socket_receive_errors: u64,
        pub outbound_packets: u64,
        pub outbound_payload_bytes: u64,
        pub outbound_datagram_bytes: u64,
        #[serde(default)]
        pub outbound_dropped_unexpected_source_packets: u64,
        #[serde(default)]
        pub outbound_dropped_unexpected_source_payload_bytes: u64,
        #[serde(default)]
        pub outbound_dropped_expired_session_packets: u64,
        #[serde(default)]
        pub outbound_dropped_expired_session_payload_bytes: u64,
        #[serde(default)]
        pub outbound_dropped_oversized_packets: u64,
        #[serde(default)]
        pub outbound_dropped_oversized_payload_bytes: u64,
        #[serde(default)]
        pub outbound_dropped_oversized_datagram_bytes: u64,
        #[serde(default)]
        pub outbound_dropped_socket_error_packets: u64,
        #[serde(default)]
        pub outbound_dropped_socket_error_payload_bytes: u64,
        #[serde(default)]
        pub outbound_dropped_socket_error_datagram_bytes: u64,
        #[serde(default)]
        pub outbound_dropped_non_wireguard_packets: u64,
        #[serde(default)]
        pub outbound_dropped_non_wireguard_payload_bytes: u64,
        pub inbound_packets: u64,
        pub inbound_payload_bytes: u64,
        #[serde(default)]
        pub inbound_dropped_expired_session_packets: u64,
        #[serde(default)]
        pub inbound_dropped_expired_session_payload_bytes: u64,
        #[serde(default)]
        pub inbound_dropped_oversized_packets: u64,
        #[serde(default)]
        pub inbound_dropped_oversized_payload_bytes: u64,
        #[serde(default)]
        pub inbound_dropped_socket_error_packets: u64,
        #[serde(default)]
        pub inbound_dropped_socket_error_payload_bytes: u64,
        #[serde(default)]
        pub inbound_dropped_non_wireguard_packets: u64,
        #[serde(default)]
        pub inbound_dropped_non_wireguard_payload_bytes: u64,
        pub last_forwarded_at: Option<DateTime<Utc>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PathStateCount {
        pub state: PathState,
        pub count: usize,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct NatTraversalStrategyCount {
        pub strategy: NatTraversalStrategy,
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AgentRelayAdmissionFailureReason {
        NoEndpointCandidate,
        InvalidRelayCandidate,
        Unavailable,
        Rejected,
        InvalidResponse,
    }

    impl AgentRelayAdmissionFailureReason {
        pub const ALL: [Self; 5] = [
            Self::NoEndpointCandidate,
            Self::InvalidRelayCandidate,
            Self::Unavailable,
            Self::Rejected,
            Self::InvalidResponse,
        ];

        pub const fn as_str(self) -> &'static str {
            match self {
                Self::NoEndpointCandidate => "no_endpoint_candidate",
                Self::InvalidRelayCandidate => "invalid_relay_candidate",
                Self::Unavailable => "unavailable",
                Self::Rejected => "rejected",
                Self::InvalidResponse => "invalid_response",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentRelayAdmissionFailureReasonCount {
        pub reason: AgentRelayAdmissionFailureReason,
        pub count: u64,
    }

    #[derive(
        Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
    )]
    #[serde(rename_all = "snake_case")]
    pub enum AgentManagedProcessState {
        #[default]
        Disabled,
        Starting,
        Ready,
        Exited,
        Stopping,
        Stopped,
        Failed,
    }

    impl AgentManagedProcessState {
        pub const ALL: [Self; 7] = [
            Self::Disabled,
            Self::Starting,
            Self::Ready,
            Self::Exited,
            Self::Stopping,
            Self::Stopped,
            Self::Failed,
        ];

        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Disabled => "disabled",
                Self::Starting => "starting",
                Self::Ready => "ready",
                Self::Exited => "exited",
                Self::Stopping => "stopping",
                Self::Stopped => "stopped",
                Self::Failed => "failed",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentManagedProcessStatus {
        pub state: AgentManagedProcessState,
        pub pid: Option<u32>,
        pub exit_status: Option<String>,
        pub message: Option<String>,
        pub updated_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentPacketFlowDropReasonCount {
        pub reason: AgentPacketFlowDropReason,
        pub count: u64,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum AgentPacketFlowDuplicateSource {
        ProcNetConntrack,
        ConntrackNetlink,
        ConntrackNetlinkEvents,
        EbpfJsonl,
        EbpfRingbuf,
    }

    impl AgentPacketFlowDuplicateSource {
        pub const ALL: [Self; 5] = [
            Self::ProcNetConntrack,
            Self::ConntrackNetlink,
            Self::ConntrackNetlinkEvents,
            Self::EbpfJsonl,
            Self::EbpfRingbuf,
        ];

        pub const fn as_str(self) -> &'static str {
            match self {
                Self::ProcNetConntrack => "proc-net-conntrack",
                Self::ConntrackNetlink => "conntrack-netlink",
                Self::ConntrackNetlinkEvents => "conntrack-netlink-events",
                Self::EbpfJsonl => "ebpf-jsonl",
                Self::EbpfRingbuf => "ebpf-ringbuf",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentPacketFlowDuplicateSourceCount {
        pub source: AgentPacketFlowDuplicateSource,
        pub count: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentPacketFlowClassificationCount {
        pub classification: AgentPacketFlowClassification,
        pub count: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentPacketFlowApplicationCount {
        pub application: AgentPacketFlowApplication,
        pub count: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AgentMetricsResponse {
        pub node_id: NodeId,
        pub candidate_count: usize,
        #[serde(default)]
        pub peer_map_synced: bool,
        #[serde(default)]
        pub peer_map_peer_count: usize,
        #[serde(default)]
        pub peer_map_route_count: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub peer_map_generated_at: Option<DateTime<Utc>>,
        pub path_count: usize,
        pub relay_session_count: usize,
        pub relay_admission_attempt_count: u64,
        pub relay_admission_success_count: u64,
        pub relay_admission_failure_count: u64,
        #[serde(default)]
        pub relay_admission_failure_reason_counts: Vec<AgentRelayAdmissionFailureReasonCount>,
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
        pub packet_flow_duplicate_suppression_count: u64,
        #[serde(default)]
        pub packet_flow_duplicate_suppression_counts: Vec<AgentPacketFlowDuplicateSourceCount>,
        #[serde(default)]
        pub packet_flow_classification_counts: Vec<AgentPacketFlowClassificationCount>,
        #[serde(default)]
        pub packet_flow_application_counts: Vec<AgentPacketFlowApplicationCount>,
        #[serde(default)]
        pub userspace_wireguard_process: Option<AgentManagedProcessStatus>,
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
    fn endpoint_candidate_ipv6_kind_requires_ipv6_address() {
        let mut candidate = EndpointCandidate {
            node_id: NodeId::from_string("node-a"),
            kind: EndpointCandidateKind::Ipv6,
            addr: std::net::SocketAddr::from(([203, 0, 113, 10], 51820)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::InterfaceScan,
        };

        assert_eq!(
            candidate.validate_kind_address(),
            Err("IPv6 candidates must use an IPv6 socket address")
        );
        candidate.addr = std::net::SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x10)),
            51820,
        );
        assert_eq!(candidate.validate_kind_address(), Ok(()));
    }

    #[test]
    fn endpoint_addr_usability_rejects_unrouteable_session_endpoints() {
        let unusable = [
            std::net::SocketAddr::from(([203, 0, 113, 10], 0)),
            std::net::SocketAddr::from(([0, 0, 0, 0], 51820)),
            std::net::SocketAddr::from(([224, 0, 0, 1], 51820)),
            std::net::SocketAddr::from(([255, 255, 255, 255], 51820)),
            std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 51820),
            std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
                51820,
            ),
        ];
        for addr in unusable {
            assert!(!endpoint_addr_is_usable(addr), "{addr} should be unusable");
        }

        let usable = [
            std::net::SocketAddr::from(([10, 0, 0, 1], 51820)),
            std::net::SocketAddr::from(([127, 0, 0, 1], 51820)),
            std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 51820),
            std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x10)),
                51820,
            ),
        ];
        for addr in usable {
            assert!(endpoint_addr_is_usable(addr), "{addr} should be usable");
        }
    }

    #[test]
    fn relay_admission_url_usability_rejects_unusable_numeric_endpoints() {
        for url in [
            "http://relay.example:9580",
            "https://relay.example",
            "http://203.0.113.10:9580",
            "https://[2001:db8::10]",
            "http://127.0.0.1:9580",
        ] {
            assert!(relay_admission_url_is_usable(url), "{url} should be usable");
        }

        for url in [
            "relay.example:9580",
            "udp://relay.example:9580",
            "http://relay.example:0",
            "http://0.0.0.0:9580",
            "http://224.0.0.1:9580",
            "http://255.255.255.255:9580",
            "http://[::]:9580",
            "http://[ff02::1]:9580",
        ] {
            assert!(
                !relay_admission_url_is_usable(url),
                "{url} should be unusable"
            );
        }
    }

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
        assert!(direct
            .reasons
            .iter()
            .any(|reason| reason == "stability=0.90"));
    }

    #[test]
    fn agent_status_defaults_missing_userspace_wireguard_process() {
        let status: api::AgentStatusResponse = match serde_json::from_str(
            r#"{
                "node_id": "node-a",
                "identity_public_key": "identity-a",
                "wireguard_public_key": "wireguard-a",
                "candidate_count": 0,
                "candidates": [],
                "nat_classification": null,
                "state_updated_at": "2026-07-05T00:00:00Z"
            }"#,
        ) {
            Ok(status) => status,
            Err(error) => panic!("legacy status response should decode: {error}"),
        };

        assert_eq!(status.node_id, NodeId::from_string("node-a"));
        assert!(status.userspace_wireguard_process.is_none());
    }

    #[test]
    fn path_metrics_reject_invalid_probe_values() {
        let mut metrics = PathMetrics {
            latency_ms: Some(-1.0),
            ..PathMetrics::default()
        };
        let error = match metrics.validate() {
            Ok(()) => panic!("negative latency must fail"),
            Err(error) => error,
        };
        assert_eq!(error.field(), "latency_ms");

        metrics = PathMetrics {
            jitter_ms: Some(-0.1),
            ..PathMetrics::default()
        };
        let error = match metrics.validate() {
            Ok(()) => panic!("negative jitter must fail"),
            Err(error) => error,
        };
        assert_eq!(error.field(), "jitter_ms");

        metrics = PathMetrics {
            relay_load: Some(1.1),
            ..PathMetrics::default()
        };
        let error = match metrics.validate() {
            Ok(()) => panic!("out-of-range relay load must fail"),
            Err(error) => error,
        };
        assert_eq!(error.field(), "relay_load");

        metrics = PathMetrics {
            stability: f32::NAN,
            ..PathMetrics::default()
        };
        let error = match metrics.validate() {
            Ok(()) => panic!("NaN stability must fail"),
            Err(error) => error,
        };
        assert_eq!(error.field(), "stability");
    }

    #[test]
    fn path_score_bounds_invalid_metrics_defensively() {
        let score = PathScore::calculate(
            PathState::DirectPublic,
            &PathMetrics {
                latency_ms: Some(f32::NAN),
                loss_ppm: 0,
                jitter_ms: Some(f32::INFINITY),
                relay_load: Some(f32::NAN),
                stability: f32::NAN,
            },
            true,
            0,
        );

        assert!(score.value.is_finite());
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
    fn relay_rejects_unusable_public_endpoint() {
        let mut relay = RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(std::net::SocketAddr::from(([0, 0, 0, 0], 51820))),
            admission_url: Some("http://203.0.113.10:9580".to_string()),
            max_sessions: 10,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        };

        assert!(!relay.can_admit());

        relay.public_endpoint = Some(std::net::SocketAddr::from(([203, 0, 113, 10], 0)));

        assert!(!relay.can_admit());
    }

    #[test]
    fn relay_rejects_unusable_admission_url() {
        let mut relay = RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(std::net::SocketAddr::from(([203, 0, 113, 10], 51820))),
            admission_url: Some("relay-a:9580".to_string()),
            max_sessions: 10,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        };

        assert!(!relay.can_admit());

        relay.admission_url = Some("udp://203.0.113.10:9580".to_string());

        assert!(!relay.can_admit());

        relay.admission_url = Some("http://".to_string());

        assert!(!relay.can_admit());
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
    fn packet_flow_observation_classifies_application_protocol() {
        let dns = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(53),
            ..Default::default()
        };
        assert_eq!(dns.application(), api::AgentPacketFlowApplication::Dns);

        let dns_over_tls = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(853),
            payload_prefix: vec![0x16, 0x03, 0x03, 0x00, 0x31, 0x01, 0x00, 0x00],
            ..Default::default()
        };
        assert_eq!(
            dns_over_tls.application(),
            api::AgentPacketFlowApplication::Dns
        );

        let dns_over_quic = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(853),
            ..Default::default()
        };
        assert_eq!(
            dns_over_quic.application(),
            api::AgentPacketFlowApplication::Dns
        );

        let kubernetes_api = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(6443),
            ..Default::default()
        };
        assert_eq!(
            kubernetes_api.application(),
            api::AgentPacketFlowApplication::KubernetesApi
        );

        let wireguard = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            source_port: Some(51820),
            ..Default::default()
        };
        assert_eq!(
            wireguard.application(),
            api::AgentPacketFlowApplication::WireGuard
        );

        let native_esp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Esp),
            ..Default::default()
        };
        assert_eq!(
            native_esp.application(),
            api::AgentPacketFlowApplication::Ipsec
        );

        let native_ah = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Ah),
            ..Default::default()
        };
        assert_eq!(
            native_ah.application(),
            api::AgentPacketFlowApplication::Ipsec
        );

        let ip_in_ip = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::IpInIp),
            ..Default::default()
        };
        assert_eq!(
            ip_in_ip.application(),
            api::AgentPacketFlowApplication::IpTunnel
        );

        let ipv6_encap = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Ipv6Encap),
            ..Default::default()
        };
        assert_eq!(
            ipv6_encap.application(),
            api::AgentPacketFlowApplication::IpTunnel
        );

        let gre = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Gre),
            ..Default::default()
        };
        assert_eq!(gre.application(), api::AgentPacketFlowApplication::Gre);

        let dhcp_client = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            source_port: Some(68),
            destination_port: Some(67),
            ..Default::default()
        };
        assert_eq!(
            dhcp_client.application(),
            api::AgentPacketFlowApplication::Dhcp
        );

        let dhcp_server = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            source_port: Some(67),
            destination_port: Some(68),
            ..Default::default()
        };
        assert_eq!(
            dhcp_server.application(),
            api::AgentPacketFlowApplication::Dhcp
        );

        let dhcpv6_client = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            source_port: Some(546),
            destination_port: Some(547),
            ..Default::default()
        };
        assert_eq!(
            dhcpv6_client.application(),
            api::AgentPacketFlowApplication::Dhcp
        );

        let dhcpv6_server = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            source_port: Some(547),
            destination_port: Some(546),
            ..Default::default()
        };
        assert_eq!(
            dhcpv6_server.application(),
            api::AgentPacketFlowApplication::Dhcp
        );

        let vxlan = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(4789),
            ..Default::default()
        };
        assert_eq!(vxlan.application(), api::AgentPacketFlowApplication::Vxlan);

        let vxlan_legacy = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(8472),
            ..Default::default()
        };
        assert_eq!(
            vxlan_legacy.application(),
            api::AgentPacketFlowApplication::Vxlan
        );

        let geneve = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(6081),
            ..Default::default()
        };
        assert_eq!(
            geneve.application(),
            api::AgentPacketFlowApplication::Geneve
        );

        let ike = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(500),
            ..Default::default()
        };
        assert_eq!(ike.application(), api::AgentPacketFlowApplication::Ike);

        let ike_nat_t = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(4500),
            ..Default::default()
        };
        assert_eq!(
            ike_nat_t.application(),
            api::AgentPacketFlowApplication::Ike
        );

        let https = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(443),
            ..Default::default()
        };
        assert_eq!(https.application(), api::AgentPacketFlowApplication::Https);

        let ldap = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(389),
            ..Default::default()
        };
        assert_eq!(ldap.application(), api::AgentPacketFlowApplication::Ldap);

        let smb = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(445),
            ..Default::default()
        };
        assert_eq!(smb.application(), api::AgentPacketFlowApplication::Smb);

        let nfs_tcp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(2049),
            ..Default::default()
        };
        assert_eq!(nfs_tcp.application(), api::AgentPacketFlowApplication::Nfs);

        let nfs_udp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(2049),
            ..Default::default()
        };
        assert_eq!(nfs_udp.application(), api::AgentPacketFlowApplication::Nfs);

        let rdp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(3389),
            ..Default::default()
        };
        assert_eq!(rdp.application(), api::AgentPacketFlowApplication::Rdp);

        let kerberos_kdc = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(88),
            ..Default::default()
        };
        assert_eq!(
            kerberos_kdc.application(),
            api::AgentPacketFlowApplication::Kerberos
        );

        let kerberos_kpasswd = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(464),
            ..Default::default()
        };
        assert_eq!(
            kerberos_kpasswd.application(),
            api::AgentPacketFlowApplication::Kerberos
        );

        let ntp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(123),
            ..Default::default()
        };
        assert_eq!(ntp.application(), api::AgentPacketFlowApplication::Ntp);

        let nts_ke = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(4460),
            ..Default::default()
        };
        assert_eq!(nts_ke.application(), api::AgentPacketFlowApplication::Ntp);

        let radius_auth = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(1812),
            ..Default::default()
        };
        assert_eq!(
            radius_auth.application(),
            api::AgentPacketFlowApplication::Radius
        );

        let radius_accounting = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(1813),
            ..Default::default()
        };
        assert_eq!(
            radius_accounting.application(),
            api::AgentPacketFlowApplication::Radius
        );

        let radsec = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(2083),
            ..Default::default()
        };
        assert_eq!(
            radsec.application(),
            api::AgentPacketFlowApplication::Radius
        );

        let tacacs = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(49),
            ..Default::default()
        };
        assert_eq!(
            tacacs.application(),
            api::AgentPacketFlowApplication::Tacacs
        );

        let bgp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(179),
            ..Default::default()
        };
        assert_eq!(bgp.application(), api::AgentPacketFlowApplication::Bgp);

        let bfd = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(3784),
            ..Default::default()
        };
        assert_eq!(bfd.application(), api::AgentPacketFlowApplication::Bfd);

        let bfd_echo = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(3785),
            ..Default::default()
        };
        assert_eq!(bfd_echo.application(), api::AgentPacketFlowApplication::Bfd);

        let bfd_multihop = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(4784),
            ..Default::default()
        };
        assert_eq!(
            bfd_multihop.application(),
            api::AgentPacketFlowApplication::Bfd
        );

        let etcd = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(2379),
            ..Default::default()
        };
        assert_eq!(etcd.application(), api::AgentPacketFlowApplication::Etcd);

        let zookeeper = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(2181),
            ..Default::default()
        };
        assert_eq!(
            zookeeper.application(),
            api::AgentPacketFlowApplication::ZooKeeper
        );

        let consul_api = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(8500),
            ..Default::default()
        };
        assert_eq!(
            consul_api.application(),
            api::AgentPacketFlowApplication::Consul
        );

        let consul_gossip = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(8301),
            ..Default::default()
        };
        assert_eq!(
            consul_gossip.application(),
            api::AgentPacketFlowApplication::Consul
        );

        let vault_api = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(8200),
            ..Default::default()
        };
        assert_eq!(
            vault_api.application(),
            api::AgentPacketFlowApplication::Vault
        );

        let nomad_api = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(4646),
            ..Default::default()
        };
        assert_eq!(
            nomad_api.application(),
            api::AgentPacketFlowApplication::Nomad
        );

        let nomad_serf = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(4648),
            ..Default::default()
        };
        assert_eq!(
            nomad_serf.application(),
            api::AgentPacketFlowApplication::Nomad
        );

        let postgres = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(5432),
            ..Default::default()
        };
        assert_eq!(
            postgres.application(),
            api::AgentPacketFlowApplication::Postgres
        );

        let mysql = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(3306),
            ..Default::default()
        };
        assert_eq!(mysql.application(), api::AgentPacketFlowApplication::Mysql);

        let mssql = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(1433),
            ..Default::default()
        };
        assert_eq!(mssql.application(), api::AgentPacketFlowApplication::MsSql);

        let oracle = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(1521),
            ..Default::default()
        };
        assert_eq!(
            oracle.application(),
            api::AgentPacketFlowApplication::Oracle
        );

        let clickhouse_http = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(8123),
            ..Default::default()
        };
        assert_eq!(
            clickhouse_http.application(),
            api::AgentPacketFlowApplication::ClickHouse
        );

        let clickhouse_native_tls = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(9440),
            ..Default::default()
        };
        assert_eq!(
            clickhouse_native_tls.application(),
            api::AgentPacketFlowApplication::ClickHouse
        );

        let influxdb_http = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(8086),
            ..Default::default()
        };
        assert_eq!(
            influxdb_http.application(),
            api::AgentPacketFlowApplication::InfluxDb
        );

        let redis = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(6379),
            ..Default::default()
        };
        assert_eq!(redis.application(), api::AgentPacketFlowApplication::Redis);

        let memcached = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(11211),
            ..Default::default()
        };
        assert_eq!(
            memcached.application(),
            api::AgentPacketFlowApplication::Memcached
        );

        let prometheus = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(9090),
            ..Default::default()
        };
        assert_eq!(
            prometheus.application(),
            api::AgentPacketFlowApplication::Prometheus
        );

        let opentelemetry = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(4317),
            ..Default::default()
        };
        assert_eq!(
            opentelemetry.application(),
            api::AgentPacketFlowApplication::OpenTelemetry
        );

        let syslog_udp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(514),
            ..Default::default()
        };
        assert_eq!(
            syslog_udp.application(),
            api::AgentPacketFlowApplication::Syslog
        );

        let syslog_conn = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(601),
            ..Default::default()
        };
        assert_eq!(
            syslog_conn.application(),
            api::AgentPacketFlowApplication::Syslog
        );

        let syslog_tls = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(6514),
            ..Default::default()
        };
        assert_eq!(
            syslog_tls.application(),
            api::AgentPacketFlowApplication::Syslog
        );

        let syslog_dtls = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(6514),
            ..Default::default()
        };
        assert_eq!(
            syslog_dtls.application(),
            api::AgentPacketFlowApplication::Syslog
        );

        let snmp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(161),
            ..Default::default()
        };
        assert_eq!(snmp.application(), api::AgentPacketFlowApplication::Snmp);

        let snmptrap = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(162),
            ..Default::default()
        };
        assert_eq!(
            snmptrap.application(),
            api::AgentPacketFlowApplication::Snmp
        );

        let snmp_tls = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(10161),
            ..Default::default()
        };
        assert_eq!(
            snmp_tls.application(),
            api::AgentPacketFlowApplication::Snmp
        );

        let snmptrap_dtls = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(10162),
            ..Default::default()
        };
        assert_eq!(
            snmptrap_dtls.application(),
            api::AgentPacketFlowApplication::Snmp
        );

        let jaeger_collector = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(14268),
            ..Default::default()
        };
        assert_eq!(
            jaeger_collector.application(),
            api::AgentPacketFlowApplication::Jaeger
        );

        let jaeger_agent = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(6831),
            ..Default::default()
        };
        assert_eq!(
            jaeger_agent.application(),
            api::AgentPacketFlowApplication::Jaeger
        );

        let loki = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(3100),
            ..Default::default()
        };
        assert_eq!(loki.application(), api::AgentPacketFlowApplication::Loki);

        let tempo = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(3200),
            ..Default::default()
        };
        assert_eq!(tempo.application(), api::AgentPacketFlowApplication::Tempo);

        let zipkin = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(9411),
            ..Default::default()
        };
        assert_eq!(
            zipkin.application(),
            api::AgentPacketFlowApplication::Zipkin
        );

        let grpc = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(50051),
            ..Default::default()
        };
        assert_eq!(grpc.application(), api::AgentPacketFlowApplication::Grpc);

        let kafka = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(9092),
            ..Default::default()
        };
        assert_eq!(kafka.application(), api::AgentPacketFlowApplication::Kafka);

        let nats = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(4222),
            ..Default::default()
        };
        assert_eq!(nats.application(), api::AgentPacketFlowApplication::Nats);

        let mqtt = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(1883),
            ..Default::default()
        };
        assert_eq!(mqtt.application(), api::AgentPacketFlowApplication::Mqtt);

        let amqp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(5672),
            ..Default::default()
        };
        assert_eq!(amqp.application(), api::AgentPacketFlowApplication::Amqp);

        let cassandra = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(9042),
            ..Default::default()
        };
        assert_eq!(
            cassandra.application(),
            api::AgentPacketFlowApplication::Cassandra
        );

        let mongodb = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(27017),
            ..Default::default()
        };
        assert_eq!(
            mongodb.application(),
            api::AgentPacketFlowApplication::MongoDb
        );

        let elasticsearch = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(9200),
            ..Default::default()
        };
        assert_eq!(
            elasticsearch.application(),
            api::AgentPacketFlowApplication::Elasticsearch
        );

        let detector_hint_overrides_port_guess = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(443),
            application: Some(api::AgentPacketFlowApplication::Postgres),
            ..Default::default()
        };
        assert_eq!(
            detector_hint_overrides_port_guess.application(),
            api::AgentPacketFlowApplication::Postgres
        );

        let specific_payload_overrides_generic_https_port = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(443),
            payload_prefix: b"POST /opentelemetry.proto.collector.trace.v1.TraceService/Export HTTP/1.1\r\ncontent-type: application/grpc\r\n".to_vec(),
            ..Default::default()
        };
        assert_eq!(
            specific_payload_overrides_generic_https_port.application(),
            api::AgentPacketFlowApplication::OpenTelemetry
        );

        let tls_payload_overrides_generic_http_port = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(80),
            payload_prefix: vec![0x16, 0x03, 0x03, 0x00, 0x31, 0x01, 0x00, 0x00],
            ..Default::default()
        };
        assert_eq!(
            tls_payload_overrides_generic_http_port.application(),
            api::AgentPacketFlowApplication::Https
        );

        let generic_tls_keeps_kubernetes_api_port = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(6443),
            payload_prefix: vec![0x16, 0x03, 0x03, 0x00, 0x31, 0x01, 0x00, 0x00],
            ..Default::default()
        };
        assert_eq!(
            generic_tls_keeps_kubernetes_api_port.application(),
            api::AgentPacketFlowApplication::KubernetesApi
        );
    }

    #[test]
    fn packet_flow_observation_classifies_payload_prefix_application_protocol() {
        fn tls_client_hello_with_sni(name: &str) -> Vec<u8> {
            tls_client_hello(Some(name), &[])
        }

        fn tls_client_hello_with_alpn(protocols: &[&[u8]]) -> Vec<u8> {
            tls_client_hello(None, protocols)
        }

        fn tls_client_hello(sni_name: Option<&str>, alpn_protocols: &[&[u8]]) -> Vec<u8> {
            let mut extensions = Vec::new();

            if let Some(name) = sni_name {
                let mut server_name = Vec::new();
                server_name.push(0);
                server_name.extend_from_slice(&(name.len() as u16).to_be_bytes());
                server_name.extend_from_slice(name.as_bytes());

                let mut sni = Vec::new();
                sni.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
                sni.extend_from_slice(&server_name);

                extensions.extend_from_slice(&0_u16.to_be_bytes());
                extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
                extensions.extend_from_slice(&sni);
            }

            if !alpn_protocols.is_empty() {
                let mut protocol_list = Vec::new();
                for protocol in alpn_protocols {
                    protocol_list.push(protocol.len() as u8);
                    protocol_list.extend_from_slice(protocol);
                }

                let mut alpn = Vec::new();
                alpn.extend_from_slice(&(protocol_list.len() as u16).to_be_bytes());
                alpn.extend_from_slice(&protocol_list);

                extensions.extend_from_slice(&16_u16.to_be_bytes());
                extensions.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
                extensions.extend_from_slice(&alpn);
            }

            let mut body = Vec::new();
            body.extend_from_slice(&[0x03, 0x03]);
            body.extend_from_slice(&[0; 32]);
            body.push(0);
            body.extend_from_slice(&2_u16.to_be_bytes());
            body.extend_from_slice(&[0x13, 0x01]);
            body.push(1);
            body.push(0);
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);

            let mut payload = Vec::new();
            payload.extend_from_slice(&[0x16, 0x03, 0x03]);
            payload.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
            payload.push(0x01);
            let handshake_len = body.len() as u32;
            payload.extend_from_slice(&[
                ((handshake_len >> 16) & 0xff) as u8,
                ((handshake_len >> 8) & 0xff) as u8,
                (handshake_len & 0xff) as u8,
            ]);
            payload.extend_from_slice(&body);
            payload
        }

        fn wireguard_message(message_type: u32, len: usize) -> Vec<u8> {
            let mut payload = vec![0xa5; len];
            payload[..4].copy_from_slice(&message_type.to_le_bytes());
            payload
        }

        fn ethernet_ipv4_frame() -> Vec<u8> {
            vec![
                0x02, 0x00, 0x5e, 0x10, 0x00, 0x01, 0x02, 0x00, 0x5e, 0x20, 0x00, 0x01, 0x08, 0x00,
            ]
        }

        fn vxlan_frame(vni: [u8; 3]) -> Vec<u8> {
            let mut payload = vec![0x08, 0, 0, 0, vni[0], vni[1], vni[2], 0];
            payload.extend_from_slice(&ethernet_ipv4_frame());
            payload
        }

        fn geneve_frame(vni: [u8; 3]) -> Vec<u8> {
            let mut payload = vec![0, 0, 0x65, 0x58, vni[0], vni[1], vni[2], 0];
            payload.extend_from_slice(&ethernet_ipv4_frame());
            payload
        }

        fn bfd_control_packet() -> Vec<u8> {
            let mut payload = vec![0x20, 0xc0, 3, 24];
            payload.extend_from_slice(&0x1234_5678_u32.to_be_bytes());
            payload.extend_from_slice(&0x8765_4321_u32.to_be_bytes());
            payload.extend_from_slice(&1_000_000_u32.to_be_bytes());
            payload.extend_from_slice(&1_000_000_u32.to_be_bytes());
            payload.extend_from_slice(&1_000_000_u32.to_be_bytes());
            payload
        }

        fn ike_sa_init_packet() -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
            payload.extend_from_slice(&0_u64.to_be_bytes());
            payload.push(33);
            payload.push(0x20);
            payload.push(34);
            payload.push(0x08);
            payload.extend_from_slice(&0_u32.to_be_bytes());
            payload.extend_from_slice(&28_u32.to_be_bytes());
            payload
        }

        fn ipsec_nat_t_esp_packet() -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(&0x1234_5678_u32.to_be_bytes());
            payload.extend_from_slice(&1_u32.to_be_bytes());
            payload.extend_from_slice(&[0xa5; 16]);
            payload
        }

        fn postgres_frontend_message(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut payload = vec![tag];
            let length = (body.len() as u32) + 4;
            payload.extend_from_slice(&length.to_be_bytes());
            payload.extend_from_slice(body);
            payload
        }

        fn zookeeper_connect_packet(timeout_ms: u32, password: &[u8], read_only: bool) -> Vec<u8> {
            let frame_len = 29 + password.len();
            let mut payload = Vec::with_capacity(4 + frame_len);
            payload.extend_from_slice(&(frame_len as u32).to_be_bytes());
            payload.extend_from_slice(&0_u32.to_be_bytes());
            payload.extend_from_slice(&0_u64.to_be_bytes());
            payload.extend_from_slice(&timeout_ms.to_be_bytes());
            payload.extend_from_slice(&0_u64.to_be_bytes());
            payload.extend_from_slice(&(password.len() as u32).to_be_bytes());
            payload.extend_from_slice(password);
            payload.push(u8::from(read_only));
            payload
        }

        fn mysql_packet(sequence_id: u8, body: &[u8]) -> Vec<u8> {
            let length = body.len() as u32;
            let mut payload = vec![
                (length & 0xff) as u8,
                ((length >> 8) & 0xff) as u8,
                ((length >> 16) & 0xff) as u8,
                sequence_id,
            ];
            payload.extend_from_slice(body);
            payload
        }

        fn mysql_handshake_packet(server_version: &[u8]) -> Vec<u8> {
            let mut body = Vec::new();
            body.push(10);
            body.extend_from_slice(server_version);
            body.push(0);
            body.extend_from_slice(&1_u32.to_le_bytes());
            body.extend_from_slice(b"abcdefgh");
            body.push(0);
            body.extend_from_slice(&0xffff_u16.to_le_bytes());
            body.push(45);
            body.extend_from_slice(&2_u16.to_le_bytes());
            body.extend_from_slice(&0_u16.to_le_bytes());
            body.push(21);
            body.extend_from_slice(&[0; 10]);
            body.extend_from_slice(b"ijklmnopqrst");
            body.push(0);
            mysql_packet(0, &body)
        }

        fn mssql_tds_packet(packet_type: u8, body: &[u8]) -> Vec<u8> {
            let length = 8 + body.len();
            let mut payload = vec![
                packet_type,
                0x01,
                ((length >> 8) & 0xff) as u8,
                (length & 0xff) as u8,
                0,
                0,
                1,
                0,
            ];
            payload.extend_from_slice(body);
            payload
        }

        fn utf16le_ascii(value: &[u8]) -> Vec<u8> {
            let mut payload = Vec::with_capacity(value.len() * 2);
            for byte in value {
                payload.push(*byte);
                payload.push(0);
            }
            payload
        }

        fn oracle_tns_connect_packet(descriptor: &[u8]) -> Vec<u8> {
            let connect_data_offset = 34_usize;
            let length = connect_data_offset + descriptor.len();
            let mut payload = Vec::with_capacity(length);
            payload.extend_from_slice(&(length as u16).to_be_bytes());
            payload.extend_from_slice(&0_u16.to_be_bytes());
            payload.push(0x01);
            payload.push(0);
            payload.extend_from_slice(&0_u16.to_be_bytes());
            payload.extend_from_slice(&0x0136_u16.to_be_bytes());
            payload.extend_from_slice(&0x012c_u16.to_be_bytes());
            payload.extend_from_slice(&0_u16.to_be_bytes());
            payload.extend_from_slice(&8192_u16.to_be_bytes());
            payload.extend_from_slice(&32767_u16.to_be_bytes());
            payload.extend_from_slice(&0x7f08_u16.to_be_bytes());
            payload.extend_from_slice(&0_u16.to_be_bytes());
            payload.extend_from_slice(&1_u16.to_be_bytes());
            payload.extend_from_slice(&(descriptor.len() as u16).to_be_bytes());
            payload.extend_from_slice(&(connect_data_offset as u16).to_be_bytes());
            payload.extend_from_slice(&0_u32.to_be_bytes());
            payload.push(0);
            payload.push(0);
            payload.extend_from_slice(descriptor);
            payload
        }

        fn memcached_binary_request(
            opcode: u8,
            key: &[u8],
            extras: &[u8],
            value: &[u8],
        ) -> Vec<u8> {
            let total_body_len = extras.len() + key.len() + value.len();
            let mut payload = Vec::with_capacity(24 + total_body_len);
            payload.push(0x80);
            payload.push(opcode);
            payload.extend_from_slice(&(key.len() as u16).to_be_bytes());
            payload.push(extras.len() as u8);
            payload.push(0);
            payload.extend_from_slice(&0_u16.to_be_bytes());
            payload.extend_from_slice(&(total_body_len as u32).to_be_bytes());
            payload.extend_from_slice(&0_u32.to_be_bytes());
            payload.extend_from_slice(&0_u64.to_be_bytes());
            payload.extend_from_slice(extras);
            payload.extend_from_slice(key);
            payload.extend_from_slice(value);
            payload
        }

        fn kafka_request(
            api_key: u16,
            api_version: u16,
            client_id: Option<&[u8]>,
            body: &[u8],
        ) -> Vec<u8> {
            let mut frame = Vec::new();
            frame.extend_from_slice(&api_key.to_be_bytes());
            frame.extend_from_slice(&api_version.to_be_bytes());
            frame.extend_from_slice(&1_u32.to_be_bytes());
            match client_id {
                Some(client_id) => {
                    frame.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
                    frame.extend_from_slice(client_id);
                }
                None => frame.extend_from_slice(&(-1_i16).to_be_bytes()),
            }
            frame.extend_from_slice(body);
            let mut payload = (frame.len() as u32).to_be_bytes().to_vec();
            payload.extend_from_slice(&frame);
            payload
        }

        fn kafka_flexible_request(
            api_key: u16,
            api_version: u16,
            client_id: Option<&[u8]>,
            body: &[u8],
        ) -> Vec<u8> {
            let mut frame = Vec::new();
            frame.extend_from_slice(&api_key.to_be_bytes());
            frame.extend_from_slice(&api_version.to_be_bytes());
            frame.extend_from_slice(&1_u32.to_be_bytes());
            match client_id {
                Some(client_id) => {
                    frame.extend_from_slice(&kafka_unsigned_varint(client_id.len() as u64 + 1));
                    frame.extend_from_slice(client_id);
                }
                None => frame.push(0),
            }
            frame.push(0);
            frame.extend_from_slice(body);
            let mut payload = (frame.len() as u32).to_be_bytes().to_vec();
            payload.extend_from_slice(&frame);
            payload
        }

        fn kafka_unsigned_varint(mut value: u64) -> Vec<u8> {
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

        fn mqtt_connect_packet(
            protocol_level: u8,
            connect_flags: u8,
            payload_fields: &[Vec<u8>],
        ) -> Vec<u8> {
            let mut body = vec![
                0,
                4,
                b'M',
                b'Q',
                b'T',
                b'T',
                protocol_level,
                connect_flags,
                0,
                60,
            ];
            if protocol_level == 5 {
                body.push(0);
            }
            for field in payload_fields {
                body.extend_from_slice(field);
            }
            let mut payload = vec![0x10];
            payload.extend_from_slice(&mqtt_remaining_length(body.len()));
            payload.extend_from_slice(&body);
            payload
        }

        fn mqtt_field(value: &[u8]) -> Vec<u8> {
            let mut field = (value.len() as u16).to_be_bytes().to_vec();
            field.extend_from_slice(value);
            field
        }

        fn mqtt_remaining_length(mut value: usize) -> Vec<u8> {
            let mut encoded = Vec::new();
            loop {
                let mut byte = (value % 128) as u8;
                value /= 128;
                if value > 0 {
                    byte |= 0x80;
                }
                encoded.push(byte);
                if value == 0 {
                    break;
                }
            }
            encoded
        }

        fn cassandra_request_frame(opcode: u8, body: &[u8]) -> Vec<u8> {
            let mut payload = vec![0x04, 0, 0, 0, opcode];
            payload.extend_from_slice(&(body.len() as u32).to_be_bytes());
            payload.extend_from_slice(body);
            payload
        }

        fn cassandra_query_frame(
            query: &[u8],
            consistency: u16,
            flags: u8,
            parameter_tail: &[u8],
        ) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&(query.len() as u32).to_be_bytes());
            body.extend_from_slice(query);
            body.extend_from_slice(&consistency.to_be_bytes());
            body.push(flags);
            body.extend_from_slice(parameter_tail);
            cassandra_request_frame(0x07, &body)
        }

        fn mongodb_message(opcode: u32, body: &[u8]) -> Vec<u8> {
            let length = (16 + body.len()) as u32;
            let mut payload = Vec::with_capacity(length as usize);
            payload.extend_from_slice(&length.to_le_bytes());
            payload.extend_from_slice(&1_u32.to_le_bytes());
            payload.extend_from_slice(&0_u32.to_le_bytes());
            payload.extend_from_slice(&opcode.to_le_bytes());
            payload.extend_from_slice(body);
            payload
        }

        fn mongodb_empty_document() -> [u8; 5] {
            [5, 0, 0, 0, 0]
        }

        fn elasticsearch_transport_frame(
            status: u8,
            variable_header: &[u8],
            body: &[u8],
        ) -> Vec<u8> {
            elasticsearch_transport_frame_with_version(status, 8_00_00_99, variable_header, body)
        }

        fn elasticsearch_transport_frame_with_version(
            status: u8,
            version_id: u32,
            variable_header: &[u8],
            body: &[u8],
        ) -> Vec<u8> {
            let message_len = 17 + variable_header.len() + body.len();
            let mut payload = Vec::with_capacity(6 + message_len);
            payload.extend_from_slice(b"ES");
            payload.extend_from_slice(&(message_len as u32).to_be_bytes());
            payload.extend_from_slice(&1_u64.to_be_bytes());
            payload.push(status);
            payload.extend_from_slice(&version_id.to_be_bytes());
            payload.extend_from_slice(&(variable_header.len() as u32).to_be_bytes());
            payload.extend_from_slice(variable_header);
            payload.extend_from_slice(body);
            payload
        }

        fn nfs_rpc_call(program: u32, version: u32, procedure: u32) -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(&0x1020_3040_u32.to_be_bytes());
            payload.extend_from_slice(&0_u32.to_be_bytes());
            payload.extend_from_slice(&2_u32.to_be_bytes());
            payload.extend_from_slice(&program.to_be_bytes());
            payload.extend_from_slice(&version.to_be_bytes());
            payload.extend_from_slice(&procedure.to_be_bytes());
            payload.extend_from_slice(&0_u32.to_be_bytes());
            payload.extend_from_slice(&0_u32.to_be_bytes());
            payload.extend_from_slice(&0_u32.to_be_bytes());
            payload.extend_from_slice(&0_u32.to_be_bytes());
            payload
        }

        let observation_for_payload = |payload: &[u8]| api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            payload_prefix: payload.to_vec(),
            ..Default::default()
        };
        let observation_for_udp_payload = |payload: &[u8]| api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            source_port: Some(30123),
            destination_port: Some(30234),
            payload_prefix: payload.to_vec(),
            ..Default::default()
        };
        let observation_for_dhcp_payload = |payload: &[u8]| api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            source_port: Some(68),
            destination_port: Some(67),
            payload_prefix: payload.to_vec(),
            ..Default::default()
        };
        let observation_for_dhcpv6_payload = |payload: &[u8]| api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            source_port: Some(546),
            destination_port: Some(547),
            payload_prefix: payload.to_vec(),
            ..Default::default()
        };
        let observation_for_bfd_payload = |payload: &[u8]| api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            source_port: Some(49152),
            destination_port: Some(3784),
            payload_prefix: payload.to_vec(),
            ..Default::default()
        };
        let observation_for_ike_payload =
            |payload: &[u8], destination_port| api::AgentPacketFlowObservation {
                protocol: Some(TransportProtocol::Udp),
                source_port: Some(49152),
                destination_port: Some(destination_port),
                payload_prefix: payload.to_vec(),
                ..Default::default()
            };
        let dns_query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
            b'p', b'i', 0x07, b's', b'e', b'r', b'v', b'i', b'c', b'e', 0x05, b'l', b'o', b'c',
            b'a', b'l', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let dns_udp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(1053),
            payload_prefix: dns_query.clone(),
            ..Default::default()
        };
        assert_eq!(dns_udp.application(), api::AgentPacketFlowApplication::Dns);
        let mut dns_tcp_payload = (dns_query.len() as u16).to_be_bytes().to_vec();
        dns_tcp_payload.extend_from_slice(&dns_query);
        assert_eq!(
            observation_for_payload(&dns_tcp_payload).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let malformed_dns_like = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(1053),
            payload_prefix: vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xff],
            ..Default::default()
        };
        assert_eq!(
            malformed_dns_like.application(),
            api::AgentPacketFlowApplication::Unknown
        );

        let mut dhcp_discover_prefix = vec![0_u8; 44];
        dhcp_discover_prefix[0] = 1;
        dhcp_discover_prefix[1] = 1;
        dhcp_discover_prefix[2] = 6;
        dhcp_discover_prefix[4..8].copy_from_slice(&0x3903_f326_u32.to_be_bytes());
        dhcp_discover_prefix[10..12].copy_from_slice(&0x8000_u16.to_be_bytes());
        dhcp_discover_prefix[28..34].copy_from_slice(&[0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]);
        assert_eq!(
            observation_for_dhcp_payload(&dhcp_discover_prefix).application(),
            api::AgentPacketFlowApplication::Dhcp
        );
        let dhcpv6_solicit = vec![
            1, 0x12, 0x34, 0x56, 0, 1, 0, 10, 0, 1, 0, 1, 0x12, 0x34, 0x56, 0x78, 0x02, 0x00,
        ];
        assert_eq!(
            observation_for_dhcpv6_payload(&dhcpv6_solicit).application(),
            api::AgentPacketFlowApplication::Dhcp
        );

        let vxlan_payload = vxlan_frame([0x00, 0x12, 0x34]);
        assert_eq!(
            observation_for_udp_payload(&vxlan_payload).application(),
            api::AgentPacketFlowApplication::Vxlan
        );
        let mut vxlan_without_i_flag = vxlan_payload.clone();
        vxlan_without_i_flag[0] = 0;
        assert_eq!(
            observation_for_udp_payload(&vxlan_without_i_flag).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let vxlan_without_vni = vxlan_frame([0, 0, 0]);
        assert_eq!(
            observation_for_udp_payload(&vxlan_without_vni).application(),
            api::AgentPacketFlowApplication::Unknown
        );

        let geneve_payload = geneve_frame([0x00, 0x12, 0x34]);
        assert_eq!(
            observation_for_udp_payload(&geneve_payload).application(),
            api::AgentPacketFlowApplication::Geneve
        );
        let mut geneve_with_reserved_bits = geneve_payload.clone();
        geneve_with_reserved_bits[1] = 0x01;
        assert_eq!(
            observation_for_udp_payload(&geneve_with_reserved_bits).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let geneve_without_vni = geneve_frame([0, 0, 0]);
        assert_eq!(
            observation_for_udp_payload(&geneve_without_vni).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&vxlan_payload).application(),
            api::AgentPacketFlowApplication::Unknown
        );

        let ike_payload = ike_sa_init_packet();
        assert_eq!(
            observation_for_ike_payload(&ike_payload, 500).application(),
            api::AgentPacketFlowApplication::Ike
        );
        let mut ike_nat_t_payload = vec![0, 0, 0, 0];
        ike_nat_t_payload.extend_from_slice(&ike_payload);
        assert_eq!(
            observation_for_ike_payload(&ike_nat_t_payload, 4500).application(),
            api::AgentPacketFlowApplication::Ike
        );
        assert_eq!(
            observation_for_udp_payload(&ike_payload).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut ike_wrong_version = ike_payload.clone();
        ike_wrong_version[17] = 0x10;
        assert_eq!(
            observation_for_udp_payload(&ike_wrong_version).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let ipsec_nat_t_payload = ipsec_nat_t_esp_packet();
        assert_eq!(
            observation_for_ike_payload(&ipsec_nat_t_payload, 4500).application(),
            api::AgentPacketFlowApplication::Ipsec
        );
        assert_eq!(
            observation_for_udp_payload(&ipsec_nat_t_payload).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let ipsec_nat_t_keepalive = vec![0xff];
        assert_eq!(
            observation_for_udp_payload(&ipsec_nat_t_keepalive).application(),
            api::AgentPacketFlowApplication::Unknown
        );

        let snmp_get_request = vec![
            0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
            0x19, 0x02, 0x04, 0, 0, 0, 1, 0x02, 0x01, 0, 0x02, 0x01, 0, 0x30, 0x0b, 0x30, 0x09,
            0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
        ];
        assert_eq!(
            observation_for_udp_payload(&snmp_get_request).application(),
            api::AgentPacketFlowApplication::Snmp
        );
        assert_eq!(
            observation_for_payload(&snmp_get_request).application(),
            api::AgentPacketFlowApplication::Snmp
        );
        let mut invalid_snmp_pdu_tag = snmp_get_request.clone();
        invalid_snmp_pdu_tag[13] = 0x30;
        assert_eq!(
            observation_for_udp_payload(&invalid_snmp_pdu_tag).application(),
            api::AgentPacketFlowApplication::Unknown
        );

        let syslog_rfc5424 = b"<34>1 2026-07-07T12:34:56Z edge-1 iparsd 123 ID47 - path selected";
        assert_eq!(
            observation_for_udp_payload(syslog_rfc5424).application(),
            api::AgentPacketFlowApplication::Syslog
        );
        let syslog_rfc3164 = b"<13>Oct 11 22:14:15 edge-1 iparsd: path selected";
        assert_eq!(
            observation_for_udp_payload(syslog_rfc3164).application(),
            api::AgentPacketFlowApplication::Syslog
        );
        let mut syslog_octet_counted = syslog_rfc5424.len().to_string().into_bytes();
        syslog_octet_counted.push(b' ');
        syslog_octet_counted.extend_from_slice(syslog_rfc5424);
        assert_eq!(
            observation_for_payload(&syslog_octet_counted).application(),
            api::AgentPacketFlowApplication::Syslog
        );
        assert_eq!(
            observation_for_udp_payload(b"<999>1 2026-07-07T12:34:56Z edge app 1 ID - nope")
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(b"<34>GET / HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );

        let nfs_v4_compound = nfs_rpc_call(100_003, 4, 1);
        assert_eq!(
            observation_for_udp_payload(&nfs_v4_compound).application(),
            api::AgentPacketFlowApplication::Nfs
        );
        let mut nfs_tcp = ((0x8000_0000_u32) | (nfs_v4_compound.len() as u32))
            .to_be_bytes()
            .to_vec();
        nfs_tcp.extend_from_slice(&nfs_v4_compound);
        assert_eq!(
            observation_for_payload(&nfs_tcp).application(),
            api::AgentPacketFlowApplication::Nfs
        );
        let not_nfs_mount_rpc = nfs_rpc_call(100_005, 3, 1);
        assert_eq!(
            observation_for_udp_payload(&not_nfs_mount_rpc).application(),
            api::AgentPacketFlowApplication::Unknown
        );

        let kerberos_as_req = vec![
            0x6a, 0x0c, 0x30, 0x0a, 0xa1, 0x03, 0x02, 0x01, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x0a,
        ];
        assert_eq!(
            observation_for_udp_payload(&kerberos_as_req).application(),
            api::AgentPacketFlowApplication::Kerberos
        );
        let mut kerberos_tcp = (kerberos_as_req.len() as u32).to_be_bytes().to_vec();
        kerberos_tcp.extend_from_slice(&kerberos_as_req);
        assert_eq!(
            observation_for_payload(&kerberos_tcp).application(),
            api::AgentPacketFlowApplication::Kerberos
        );
        let mut invalid_kerberos_msg_type = kerberos_as_req.clone();
        invalid_kerberos_msg_type[13] = 0x0b;
        assert_eq!(
            observation_for_udp_payload(&invalid_kerberos_msg_type).application(),
            api::AgentPacketFlowApplication::Unknown
        );

        let mut ntp_client_request = vec![0_u8; 48];
        ntp_client_request[0] = 0x23;
        assert_eq!(
            observation_for_udp_payload(&ntp_client_request).application(),
            api::AgentPacketFlowApplication::Ntp
        );
        let mut ntp_server_response = ntp_client_request.clone();
        ntp_server_response[0] = 0x24;
        ntp_server_response[1] = 2;
        assert_eq!(
            observation_for_udp_payload(&ntp_server_response).application(),
            api::AgentPacketFlowApplication::Ntp
        );
        let mut invalid_ntp_version = ntp_client_request.clone();
        invalid_ntp_version[0] = 0x03;
        assert_eq!(
            observation_for_udp_payload(&invalid_ntp_version).application(),
            api::AgentPacketFlowApplication::Unknown
        );

        let mut radius_access_request = vec![
            1, 7, 0, 27, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 1, 7, b'a', b'l', b'i', b'c', b'e',
        ];
        assert_eq!(
            observation_for_udp_payload(&radius_access_request).application(),
            api::AgentPacketFlowApplication::Radius
        );
        radius_access_request[0] = 255;
        assert_eq!(
            observation_for_udp_payload(&radius_access_request).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        radius_access_request[0] = 1;
        radius_access_request[21] = 1;
        assert_eq!(
            observation_for_udp_payload(&radius_access_request).application(),
            api::AgentPacketFlowApplication::Unknown
        );

        let mut tacacs_auth_start = vec![
            0xc0, 1, 1, 0x01, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 4, 1, 2, 3, 4,
        ];
        assert_eq!(
            observation_for_payload(&tacacs_auth_start).application(),
            api::AgentPacketFlowApplication::Tacacs
        );
        tacacs_auth_start[1] = 9;
        assert_eq!(
            observation_for_payload(&tacacs_auth_start).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        tacacs_auth_start[1] = 1;
        tacacs_auth_start[3] = 0x80;
        assert_eq!(
            observation_for_payload(&tacacs_auth_start).application(),
            api::AgentPacketFlowApplication::Unknown
        );

        let mut bgp_open = vec![0xff; 19];
        bgp_open[16] = 0;
        bgp_open[17] = 29;
        bgp_open[18] = 1;
        bgp_open.extend_from_slice(&[4, 0, 100, 0, 90, 192, 0, 2, 1, 0]);
        assert_eq!(
            observation_for_payload(&bgp_open).application(),
            api::AgentPacketFlowApplication::Bgp
        );
        bgp_open[18] = 9;
        assert_eq!(
            observation_for_payload(&bgp_open).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        bgp_open[18] = 1;
        bgp_open[0] = 0xfe;
        assert_eq!(
            observation_for_payload(&bgp_open).application(),
            api::AgentPacketFlowApplication::Unknown
        );

        let bfd_control = bfd_control_packet();
        assert_eq!(
            observation_for_bfd_payload(&bfd_control).application(),
            api::AgentPacketFlowApplication::Bfd
        );
        assert_eq!(
            observation_for_udp_payload(&bfd_control).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut bfd_wrong_version = bfd_control.clone();
        bfd_wrong_version[0] = 0x40;
        assert_eq!(
            observation_for_udp_payload(&bfd_wrong_version).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut bfd_zero_detect_multiplier = bfd_control.clone();
        bfd_zero_detect_multiplier[2] = 0;
        assert_eq!(
            observation_for_udp_payload(&bfd_zero_detect_multiplier).application(),
            api::AgentPacketFlowApplication::Unknown
        );

        assert_eq!(
            observation_for_payload(b"GET /app HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(b"GET /metrics HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Prometheus
        );
        assert_eq!(
            observation_for_payload(b"POST /v1/traces HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::OpenTelemetry
        );
        assert_eq!(
            observation_for_payload(
                b"POST /package.Service/Method HTTP/1.1\r\ncontent-type: application/grpc\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Grpc
        );
        assert_eq!(
            observation_for_payload(
                b"POST /opentelemetry.proto.collector.trace.v1.TraceService/Export HTTP/1.1\r\ncontent-type: application/grpc\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::OpenTelemetry
        );
        assert_eq!(
            observation_for_payload(
                b"POST /etcdserverpb.KV/Range HTTP/1.1\r\ncontent-type: application/grpc\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Etcd
        );
        assert_eq!(
            observation_for_payload(
                b"POST /etcdserverpb.KVs/Range HTTP/1.1\r\ncontent-type: application/grpc\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Grpc
        );
        assert_eq!(
            observation_for_payload(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0*application/grpc")
                .application(),
            api::AgentPacketFlowApplication::Grpc
        );
        assert_eq!(
            observation_for_payload(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0/opentelemetry.proto.collector.metrics.v1.MetricsService/Export"
            )
            .application(),
            api::AgentPacketFlowApplication::OpenTelemetry
        );
        assert_eq!(
            observation_for_payload(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0/etcdserverpb.Watch/Watch")
                .application(),
            api::AgentPacketFlowApplication::Etcd
        );
        assert_eq!(
            observation_for_payload(b"\x00\x00*application/grpc\x00\x00\x00").application(),
            api::AgentPacketFlowApplication::Grpc
        );
        assert_eq!(
            observation_for_payload(
                b"\x00/opentelemetry.proto.collector.logs.v1.LogsService/Export"
            )
            .application(),
            api::AgentPacketFlowApplication::OpenTelemetry
        );
        assert_eq!(
            observation_for_payload(b"\x00/v3lockpb.Lock/Lock").application(),
            api::AgentPacketFlowApplication::Etcd
        );
        assert_eq!(
            observation_for_payload(b"POST /v3/kv/range HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Etcd
        );
        assert_eq!(
            observation_for_payload(b"GET /v2/machines HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Etcd
        );
        assert_eq!(
            observation_for_payload(b"GET /v3/kvs HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(b"GET /index/_search HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Elasticsearch
        );
        assert_eq!(
            observation_for_payload(b"GET /v1/agent/self HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Consul
        );
        assert_eq!(
            observation_for_payload(b"GET /v1/catalog/services?dc=dc1 HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Consul
        );
        assert_eq!(
            observation_for_payload(b"GET /v1/agency HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(b"GET /v1/sys/health HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Vault
        );
        assert_eq!(
            observation_for_payload(b"POST /v1/transit/encrypt/app HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Vault
        );
        assert_eq!(
            observation_for_payload(b"GET /v1/system HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(b"GET /v1/jobs HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Nomad
        );
        assert_eq!(
            observation_for_payload(b"GET /v1/allocations?namespace=default HTTP/1.1\r\n")
                .application(),
            api::AgentPacketFlowApplication::Nomad
        );
        assert_eq!(
            observation_for_payload(b"GET /v1/jobber HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(&[0x16, 0x03, 0x03, 0x00, 0x31, 0x01, 0x00, 0x00])
                .application(),
            api::AgentPacketFlowApplication::Https
        );
        let kubernetes_sni = tls_client_hello_with_sni("kubernetes.default.svc.cluster.local");
        assert!(kubernetes_sni.len() <= api::PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES);
        assert_eq!(
            observation_for_payload(&kubernetes_sni).application(),
            api::AgentPacketFlowApplication::KubernetesApi
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni("etcd-0.kube-system.svc"))
                .application(),
            api::AgentPacketFlowApplication::Etcd
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni(
                "prometheus-server.monitoring.svc"
            ))
            .application(),
            api::AgentPacketFlowApplication::Prometheus
        );
        let otel_sni = tls_client_hello_with_sni("otel-collector.observability.svc");
        let otel_on_https_port = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(443),
            payload_prefix: otel_sni,
            ..Default::default()
        };
        assert_eq!(
            otel_on_https_port.application(),
            api::AgentPacketFlowApplication::OpenTelemetry
        );
        assert_eq!(
            observation_for_payload(b"GET /api/traces?service=agent HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Jaeger
        );
        assert_eq!(
            observation_for_payload(b"GET /api/services HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Jaeger
        );
        assert_eq!(
            observation_for_payload(b"GET /api/tracer HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(b"GET /loki/api/v1/query?query=up HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Loki
        );
        assert_eq!(
            observation_for_payload(b"POST /loki/api/v1/push HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Loki
        );
        assert_eq!(
            observation_for_payload(b"GET /loki/api/v1ish/query HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(b"GET /api/traces/f1cfe82a8eef933b HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Tempo
        );
        assert_eq!(
            observation_for_payload(b"GET /api/v2/traces/f1cfe82a8eef933b HTTP/1.1\r\n")
                .application(),
            api::AgentPacketFlowApplication::Tempo
        );
        assert_eq!(
            observation_for_payload(b"GET /api/search?q=%7Bstatus%3Derror%7D HTTP/1.1\r\n")
                .application(),
            api::AgentPacketFlowApplication::Tempo
        );
        assert_eq!(
            observation_for_payload(
                b"GET /api/metrics/query_range?q=%7B%7D%7Crate() HTTP/1.1\r\n",
            )
            .application(),
            api::AgentPacketFlowApplication::Tempo
        );
        assert_eq!(
            observation_for_payload(b"GET /api/echo HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Tempo
        );
        assert_eq!(
            observation_for_payload(b"POST /api/v2/spans HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Zipkin
        );
        assert_eq!(
            observation_for_payload(b"GET /api/v2/trace/f1cfe82a8eef933b HTTP/1.1\r\n")
                .application(),
            api::AgentPacketFlowApplication::Zipkin
        );
        assert_eq!(
            observation_for_payload(b"GET /zipkin/ HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Zipkin
        );
        assert_eq!(
            observation_for_payload(
                b"POST /zipkin.proto3.SpanService/Report HTTP/2\r\ncontent-type: application/grpc\r\n",
            )
            .application(),
            api::AgentPacketFlowApplication::Zipkin
        );
        assert_eq!(
            observation_for_payload(
                b"POST /?query=SELECT%201 HTTP/1.1\r\nHost: clickhouse.example\r\nX-ClickHouse-User: default\r\n\r\n",
            )
            .application(),
            api::AgentPacketFlowApplication::ClickHouse
        );
        assert_eq!(
            observation_for_payload(b"POST /api/v2/write?org=ops&bucket=metrics HTTP/1.1\r\n")
                .application(),
            api::AgentPacketFlowApplication::InfluxDb
        );
        assert_eq!(
            observation_for_payload(b"POST /api/v2/query?org=ops HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::InfluxDb
        );
        assert_eq!(
            observation_for_payload(
                b"GET /ready HTTP/1.1\r\nHost: influx.example\r\nX-Influxdb-Version: 2.7\r\n\r\n",
            )
            .application(),
            api::AgentPacketFlowApplication::InfluxDb
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni(
                "elasticsearch-master.logging.svc"
            ))
            .application(),
            api::AgentPacketFlowApplication::Elasticsearch
        );
        for (hostname, expected) in [
            (
                "grpc-api.default.svc",
                api::AgentPacketFlowApplication::Grpc,
            ),
            (
                "jaeger-collector.observability.svc",
                api::AgentPacketFlowApplication::Jaeger,
            ),
            (
                "loki-gateway.observability.svc",
                api::AgentPacketFlowApplication::Loki,
            ),
            (
                "tempo-query-frontend.observability.svc",
                api::AgentPacketFlowApplication::Tempo,
            ),
            (
                "zipkin-collector.observability.svc",
                api::AgentPacketFlowApplication::Zipkin,
            ),
            (
                "clickhouse-0.analytics.svc",
                api::AgentPacketFlowApplication::ClickHouse,
            ),
            (
                "influxdb-0.observability.svc",
                api::AgentPacketFlowApplication::InfluxDb,
            ),
            (
                "syslog-collector.logs.svc",
                api::AgentPacketFlowApplication::Syslog,
            ),
            (
                "snmp-manager.ops.svc",
                api::AgentPacketFlowApplication::Snmp,
            ),
            (
                "kafka-broker.messaging.svc",
                api::AgentPacketFlowApplication::Kafka,
            ),
            (
                "nats-leaf.messaging.svc",
                api::AgentPacketFlowApplication::Nats,
            ),
            ("mqtt-broker.iot.svc", api::AgentPacketFlowApplication::Mqtt),
            (
                "rabbitmq.messaging.svc",
                api::AgentPacketFlowApplication::Amqp,
            ),
            (
                "zookeeper-0.control.svc",
                api::AgentPacketFlowApplication::ZooKeeper,
            ),
            (
                "consul-server.control.svc",
                api::AgentPacketFlowApplication::Consul,
            ),
            (
                "vault-active.secrets.svc",
                api::AgentPacketFlowApplication::Vault,
            ),
            (
                "nomad-server.scheduler.svc",
                api::AgentPacketFlowApplication::Nomad,
            ),
            (
                "cassandra-seed.db.svc",
                api::AgentPacketFlowApplication::Cassandra,
            ),
            (
                "mongo-router.db.svc",
                api::AgentPacketFlowApplication::MongoDb,
            ),
            (
                "postgres-primary.db.svc",
                api::AgentPacketFlowApplication::Postgres,
            ),
            (
                "pg-analytics.db.svc",
                api::AgentPacketFlowApplication::Postgres,
            ),
            (
                "mysql-primary.db.svc",
                api::AgentPacketFlowApplication::Mysql,
            ),
            (
                "mariadb-replica.db.svc",
                api::AgentPacketFlowApplication::Mysql,
            ),
            (
                "mssql-primary.db.svc",
                api::AgentPacketFlowApplication::MsSql,
            ),
            (
                "sqlserver-primary.db.svc",
                api::AgentPacketFlowApplication::MsSql,
            ),
            (
                "oracle-listener.db.svc",
                api::AgentPacketFlowApplication::Oracle,
            ),
            (
                "oracledb-primary.db.svc",
                api::AgentPacketFlowApplication::Oracle,
            ),
            (
                "redis-cache.cache.svc",
                api::AgentPacketFlowApplication::Redis,
            ),
            (
                "valkey-primary.cache.svc",
                api::AgentPacketFlowApplication::Redis,
            ),
            (
                "memcache-shard.cache.svc",
                api::AgentPacketFlowApplication::Memcached,
            ),
            (
                "ldaps-directory.identity.svc",
                api::AgentPacketFlowApplication::Ldap,
            ),
            (
                "kerberos-kdc.identity.svc",
                api::AgentPacketFlowApplication::Kerberos,
            ),
            ("ntp-server.time.svc", api::AgentPacketFlowApplication::Ntp),
            (
                "radius-auth.identity.svc",
                api::AgentPacketFlowApplication::Radius,
            ),
            (
                "tacacs-server.identity.svc",
                api::AgentPacketFlowApplication::Tacacs,
            ),
            (
                "bgp-route-provider.network.svc",
                api::AgentPacketFlowApplication::Bgp,
            ),
            (
                "smb-files.storage.svc",
                api::AgentPacketFlowApplication::Smb,
            ),
            (
                "nfs-files.storage.svc",
                api::AgentPacketFlowApplication::Nfs,
            ),
            ("rdp-admin.ops.svc", api::AgentPacketFlowApplication::Rdp),
            ("ssh-bastion.ops.svc", api::AgentPacketFlowApplication::Ssh),
        ] {
            assert_eq!(
                observation_for_payload(&tls_client_hello_with_sni(hostname)).application(),
                expected,
                "{hostname}"
            );
        }
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni("notkafka.example.com"))
                .application(),
            api::AgentPacketFlowApplication::Https
        );
        for (protocols, expected) in [
            (
                &[b"grpc".as_slice()][..],
                api::AgentPacketFlowApplication::Grpc,
            ),
            (
                &[b"otlp-grpc".as_slice()][..],
                api::AgentPacketFlowApplication::OpenTelemetry,
            ),
            (
                &[b"jaeger-grpc".as_slice()][..],
                api::AgentPacketFlowApplication::Jaeger,
            ),
            (
                &[b"loki-grpc".as_slice()][..],
                api::AgentPacketFlowApplication::Loki,
            ),
            (
                &[b"tempo-grpc".as_slice()][..],
                api::AgentPacketFlowApplication::Tempo,
            ),
            (
                &[b"zipkin-grpc".as_slice()][..],
                api::AgentPacketFlowApplication::Zipkin,
            ),
            (
                &[b"clickhouse-native".as_slice()][..],
                api::AgentPacketFlowApplication::ClickHouse,
            ),
            (
                &[b"influxdb-http".as_slice()][..],
                api::AgentPacketFlowApplication::InfluxDb,
            ),
            (
                &[b"syslog-tls".as_slice()][..],
                api::AgentPacketFlowApplication::Syslog,
            ),
            (
                &[b"snmp-tls".as_slice()][..],
                api::AgentPacketFlowApplication::Snmp,
            ),
            (
                &[b"nfsv4".as_slice()][..],
                api::AgentPacketFlowApplication::Nfs,
            ),
            (
                &[b"kafka".as_slice()][..],
                api::AgentPacketFlowApplication::Kafka,
            ),
            (
                &[b"zookeeper".as_slice()][..],
                api::AgentPacketFlowApplication::ZooKeeper,
            ),
            (
                &[b"consul-grpc".as_slice()][..],
                api::AgentPacketFlowApplication::Consul,
            ),
            (
                &[b"vault".as_slice()][..],
                api::AgentPacketFlowApplication::Vault,
            ),
            (
                &[b"nomad-rpc".as_slice()][..],
                api::AgentPacketFlowApplication::Nomad,
            ),
            (
                &[b"nats".as_slice()][..],
                api::AgentPacketFlowApplication::Nats,
            ),
            (
                &[b"x-amzn-mqtt-ca".as_slice()][..],
                api::AgentPacketFlowApplication::Mqtt,
            ),
            (
                &[b"amqp/1.0".as_slice()][..],
                api::AgentPacketFlowApplication::Amqp,
            ),
            (
                &[b"postgresql".as_slice()][..],
                api::AgentPacketFlowApplication::Postgres,
            ),
            (
                &[b"mssql".as_slice()][..],
                api::AgentPacketFlowApplication::MsSql,
            ),
            (
                &[b"oracle-tns".as_slice()][..],
                api::AgentPacketFlowApplication::Oracle,
            ),
            (
                &[b"valkey".as_slice()][..],
                api::AgentPacketFlowApplication::Redis,
            ),
            (
                &[b"kerberos".as_slice()][..],
                api::AgentPacketFlowApplication::Kerberos,
            ),
            (
                &[b"ntske/1".as_slice()][..],
                api::AgentPacketFlowApplication::Ntp,
            ),
            (
                &[b"radsec".as_slice()][..],
                api::AgentPacketFlowApplication::Radius,
            ),
            (
                &[b"tacacs".as_slice()][..],
                api::AgentPacketFlowApplication::Tacacs,
            ),
            (
                &[b"bgp".as_slice()][..],
                api::AgentPacketFlowApplication::Bgp,
            ),
        ] {
            assert_eq!(
                observation_for_payload(&tls_client_hello_with_alpn(protocols)).application(),
                expected
            );
        }
        assert_eq!(
            observation_for_payload(&tls_client_hello(
                Some("kafka-broker.messaging.svc"),
                &[b"mqtt".as_slice()]
            ))
            .application(),
            api::AgentPacketFlowApplication::Kafka
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello(
                Some("api.example.com"),
                &[b"amqp".as_slice()]
            ))
            .application(),
            api::AgentPacketFlowApplication::Amqp
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_alpn(&[b"h2".as_slice()])).application(),
            api::AgentPacketFlowApplication::Https
        );
        for protocols in [
            &[b"notlp".as_slice()][..],
            &[b"amqtt".as_slice()][..],
            &[b"h2".as_slice(), b"http/1.1".as_slice()][..],
        ] {
            assert_eq!(
                observation_for_payload(&tls_client_hello_with_alpn(protocols)).application(),
                api::AgentPacketFlowApplication::Https
            );
        }
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni("api.example.com")).application(),
            api::AgentPacketFlowApplication::Https
        );
        let quic = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(443),
            payload_prefix: vec![
                0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 5, 0, 0, 0, 1, 6,
            ],
            ..Default::default()
        };
        assert_eq!(quic.application(), api::AgentPacketFlowApplication::Https);
        let quic_zero_rtt = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(443),
            payload_prefix: vec![
                0xd3, 0x00, 0x00, 0x00, 0x01, 0x08, 0, 1, 2, 3, 4, 5, 6, 7, 0, 5, 0, 0, 0, 1, 6,
            ],
            ..Default::default()
        };
        assert_eq!(
            quic_zero_rtt.application(),
            api::AgentPacketFlowApplication::Https
        );
        let quic_handshake = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(443),
            payload_prefix: vec![
                0xe3, 0x00, 0x00, 0x00, 0x01, 0x08, 0, 1, 2, 3, 4, 5, 6, 7, 0, 5, 0, 0, 0, 1, 6,
            ],
            ..Default::default()
        };
        assert_eq!(
            quic_handshake.application(),
            api::AgentPacketFlowApplication::Https
        );
        let mut quic_retry_payload = vec![
            0xf0, 0x00, 0x00, 0x00, 0x01, 0x08, 0, 1, 2, 3, 4, 5, 6, 7, 0, 8, 8, 7, 6, 5, 4, 3, 2,
            1,
        ];
        quic_retry_payload.extend_from_slice(&[0xaa; 16]);
        let quic_retry = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(443),
            payload_prefix: quic_retry_payload,
            ..Default::default()
        };
        assert_eq!(
            quic_retry.application(),
            api::AgentPacketFlowApplication::Https
        );
        let invalid_quic_fixed_bit = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(443),
            payload_prefix: vec![
                0x83, 0x00, 0x00, 0x00, 0x01, 0x08, 0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 5, 0, 0, 0, 1, 6,
            ],
            ..Default::default()
        };
        assert_eq!(
            invalid_quic_fixed_bit.application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let invalid_quic_cid_len = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(443),
            payload_prefix: vec![0xc3, 0x00, 0x00, 0x00, 0x01, 21],
            ..Default::default()
        };
        assert_eq!(
            invalid_quic_cid_len.application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let invalid_quic_declared_len = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(443),
            payload_prefix: vec![
                0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 4, 0, 0, 0, 1, 6,
            ],
            ..Default::default()
        };
        assert_eq!(
            invalid_quic_declared_len.application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let non_quic_udp_443 = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(443),
            payload_prefix: b"not-quic".to_vec(),
            ..Default::default()
        };
        assert_eq!(
            non_quic_udp_443.application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(1, 128)).application(),
            api::AgentPacketFlowApplication::WireGuard
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(1, 148)).application(),
            api::AgentPacketFlowApplication::WireGuard
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(1, 149)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(
                1,
                api::PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES - 1
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(1, 64)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(2, 92)).application(),
            api::AgentPacketFlowApplication::WireGuard
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(2, 91)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(2, 93)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut wireguard_with_nonzero_reserved = wireguard_message(2, 92);
        wireguard_with_nonzero_reserved[1] = 1;
        assert_eq!(
            observation_for_udp_payload(&wireguard_with_nonzero_reserved).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(3, 64)).application(),
            api::AgentPacketFlowApplication::WireGuard
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(3, 65)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(4, 32)).application(),
            api::AgentPacketFlowApplication::WireGuard
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(4, 48)).application(),
            api::AgentPacketFlowApplication::WireGuard
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(4, 31)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(4, 33)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&wireguard_message(2, 92)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"SSH-2.0-OpenSSH_9.0\r\n").application(),
            api::AgentPacketFlowApplication::Ssh
        );
        assert_eq!(
            observation_for_payload(b"tcp-wrapper notice\r\nSSH-2.0-OpenSSH_9.0 comment\r\n")
                .application(),
            api::AgentPacketFlowApplication::Ssh
        );
        assert_eq!(
            observation_for_payload(b"SSH-2.0-OpenSSH_9.0").application(),
            api::AgentPacketFlowApplication::Ssh
        );
        assert_eq!(
            observation_for_payload(b"SSH-3.0-OpenSSH_9.0\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"SSH-2.0-\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"SSH-2.0-Open-SSH\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"SSH-2.0-OpenSSH_9.0\0\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
            ])
            .application(),
            api::AgentPacketFlowApplication::Ldap
        );
        assert_eq!(
            observation_for_payload(&[0x30, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00]).application(),
            api::AgentPacketFlowApplication::Ldap
        );
        assert_eq!(
            observation_for_payload(&[0x30, 0x06, 0x02, 0x01, 0x06, 0x50, 0x01, 0x05])
                .application(),
            api::AgentPacketFlowApplication::Ldap
        );
        assert_eq!(
            observation_for_payload(&[
                0x30, 0x09, 0x02, 0x01, 0x01, 0x42, 0x00, 0xa0, 0x02, 0x30, 0x00,
            ])
            .application(),
            api::AgentPacketFlowApplication::Ldap
        );
        assert_eq!(
            observation_for_payload(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x62, 0x01, 0x00])
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0x30, 0x06, 0x02, 0x02, 0x00, 0x01, 0x42, 0x00])
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x42, 0x01, 0x00])
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                0x30, 0x09, 0x02, 0x01, 0x01, 0x42, 0x00, 0x30, 0x02, 0x30, 0x00,
            ])
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                0x00, 0x00, 0x00, 0x40, 0xfe, b'S', b'M', b'B', 0x40, 0x00, 0x00, 0x00,
            ])
            .application(),
            api::AgentPacketFlowApplication::Smb
        );
        let mut smb1_negotiate = vec![0x00, 0x00, 0x00, 0x20, 0xff, b'S', b'M', b'B', 0x72];
        smb1_negotiate.resize(36, 0);
        assert_eq!(
            observation_for_payload(&smb1_negotiate).application(),
            api::AgentPacketFlowApplication::Smb
        );
        assert_eq!(
            observation_for_payload(&[
                0x00, 0x00, 0x00, 0x40, 0xfe, b'S', b'M', b'B', 0x41, 0x00, 0x00, 0x00,
            ])
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                0x00, 0x00, 0x00, 0x40, 0xfe, b'S', b'M', b'B', 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x13, 0x00, 0x00, 0x00,
            ])
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                0x00, 0x00, 0x00, 0x40, 0xfe, b'S', b'M', b'B', 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
            ])
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0xfe, b'S', b'M', b'B', 0x40, 0x00, 0x00, 0x00])
                .application(),
            api::AgentPacketFlowApplication::Smb
        );
        assert_eq!(
            observation_for_payload(&[
                0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ])
            .application(),
            api::AgentPacketFlowApplication::Rdp
        );
        assert_eq!(
            observation_for_payload(&[
                0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x12, 0x34, 0x56, 0x78, 0x00,
            ])
            .application(),
            api::AgentPacketFlowApplication::Rdp
        );
        assert_eq!(
            observation_for_payload(&[0x03, 0x00, 0x00, 0x07, 0x02, 0xf0, 0x80]).application(),
            api::AgentPacketFlowApplication::Rdp
        );
        assert_eq!(
            observation_for_payload(&[
                0x03, 0x01, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
            ])
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0x03, 0x00, 0x00, 0x06, 0xff, 0xf0, 0x80]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x01, 0x00, 0x00, 0x00,
            ])
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0x03, 0x00, 0x00, 0x07, 0x02, 0xf0, 0x01]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"ruok").application(),
            api::AgentPacketFlowApplication::ZooKeeper
        );
        assert_eq!(
            observation_for_payload(b"stat\r\n").application(),
            api::AgentPacketFlowApplication::ZooKeeper
        );
        assert_eq!(
            observation_for_payload(b"confused").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let zookeeper_connect = zookeeper_connect_packet(30_000, &[], false);
        assert_eq!(
            observation_for_payload(&zookeeper_connect).application(),
            api::AgentPacketFlowApplication::ZooKeeper
        );
        let invalid_zookeeper_version = {
            let mut payload = zookeeper_connect.clone();
            payload[4] = 0xff;
            payload[5] = 0xff;
            payload
        };
        assert_eq!(
            observation_for_payload(&invalid_zookeeper_version).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0, 0, 0, 8, 4, 210, 22, 47]).application(),
            api::AgentPacketFlowApplication::Postgres
        );
        assert_eq!(
            observation_for_payload(&postgres_frontend_message(b'Q', b"SELECT 1\0")).application(),
            api::AgentPacketFlowApplication::Postgres
        );
        let mut parse_body = Vec::new();
        parse_body.push(0);
        parse_body.extend_from_slice(b"SELECT $1\0");
        parse_body.extend_from_slice(&1_u16.to_be_bytes());
        parse_body.extend_from_slice(&23_u32.to_be_bytes());
        assert_eq!(
            observation_for_payload(&postgres_frontend_message(b'P', &parse_body)).application(),
            api::AgentPacketFlowApplication::Postgres
        );
        assert_eq!(
            observation_for_payload(&postgres_frontend_message(b'D', b"Sprepared\0")).application(),
            api::AgentPacketFlowApplication::Postgres
        );
        assert_eq!(
            observation_for_payload(&postgres_frontend_message(b'S', b"")).application(),
            api::AgentPacketFlowApplication::Postgres
        );
        assert_eq!(
            observation_for_payload(&postgres_frontend_message(b'Q', b"SELECT 1")).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0x4a, 0, 0, 0, 10, b'8', b'.', b'0']).application(),
            api::AgentPacketFlowApplication::Mysql
        );
        assert_eq!(
            observation_for_payload(&mysql_handshake_packet(b"8.0.36")).application(),
            api::AgentPacketFlowApplication::Mysql
        );
        let mut invalid_mysql_handshake_filler = mysql_handshake_packet(b"8.0.36");
        invalid_mysql_handshake_filler[4 + 1 + b"8.0.36".len() + 1 + 4 + 8] = 1;
        assert_eq!(
            observation_for_payload(&invalid_mysql_handshake_filler).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[1, 0, 0, 65, 10]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mysql_packet(
                0,
                &[0x03, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'1']
            ))
            .application(),
            api::AgentPacketFlowApplication::Mysql
        );
        assert_eq!(
            observation_for_payload(
                &[
                    mysql_packet(0, &[0x03, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'1']),
                    mysql_packet(0, &[0x0e]),
                ]
                .concat()
            )
            .application(),
            api::AgentPacketFlowApplication::Mysql
        );
        let mut mysql_query_with_trailing_junk =
            mysql_packet(0, &[0x03, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'1']);
        mysql_query_with_trailing_junk.extend_from_slice(b"junk");
        assert_eq!(
            observation_for_payload(&mysql_query_with_trailing_junk).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mysql_packet(
                0,
                &[0x16, b'I', b'N', b'S', b'E', b'R', b'T', b' ', b'I', b'N', b'T', b'O']
            ))
            .application(),
            api::AgentPacketFlowApplication::Mysql
        );
        assert_eq!(
            observation_for_payload(&mysql_packet(0, &[0x0e])).application(),
            api::AgentPacketFlowApplication::Mysql
        );
        assert_eq!(
            observation_for_payload(&mysql_packet(65, &[0x0e])).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mysql_packet(0, &[0x03])).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mysql_packet(
                0,
                &[0x03, b'n', b'o', b't', b's', b'q', b'l']
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mysql_packet(
                0,
                &[0x03, b'S', b'E', b'L', b'E', b'C', b'T', 0]
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mssql_prelogin = mssql_tds_packet(
            0x12,
            &[
                0x00, 0x00, 0x06, 0x00, 0x06, 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        );
        assert_eq!(
            observation_for_payload(&mssql_prelogin).application(),
            api::AgentPacketFlowApplication::MsSql
        );
        let mssql_sql_batch = mssql_tds_packet(0x01, &utf16le_ascii(b"SELECT 1"));
        assert_eq!(
            observation_for_payload(&mssql_sql_batch).application(),
            api::AgentPacketFlowApplication::MsSql
        );
        let invalid_mssql_status = vec![
            0x12, 0xe0, 0x00, 0x14, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x06, 0xff,
            0x0f, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            observation_for_payload(&invalid_mssql_status).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let oracle_descriptor =
            b"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=x)))";
        let oracle_connect = oracle_tns_connect_packet(oracle_descriptor);
        assert!(oracle_connect.len() <= api::PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES);
        assert_eq!(
            observation_for_payload(&oracle_connect).application(),
            api::AgentPacketFlowApplication::Oracle
        );
        let invalid_oracle_type = {
            let mut payload = oracle_connect.clone();
            payload[4] = 0x06;
            payload
        };
        assert_eq!(
            observation_for_payload(&invalid_oracle_type).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let invalid_oracle_descriptor = oracle_tns_connect_packet(b"(NOT_ORACLE=1)");
        assert_eq!(
            observation_for_payload(&invalid_oracle_descriptor).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"*1\r\n$4\r\nPING\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"*1\r\n$4\r\nPING\r\n*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
                .application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nva").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"XADD stream * field value\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"INFO memory\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"*1\r\n$6\r\nNOTGET\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"*2\r\n$3\r\nGET").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"*1\r\n$4\r\nPING\r\njunk").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"*2\r\n$3\r\nGET\r\njunk").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"*2\r\n$3\r\nGET\r\n+OK\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"SELECT 1\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"set cache-key 0 60 5\r\nvalue\r\n").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"set cache-key 0 60 5\r\nval").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"set cache-key 0 60 5\r\nvalue\r").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"set cache-key 0 60 5\r\nvalue\r\nget another-key\r\n")
                .application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"get cache-key another-key\r\n").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"get cache-key\r\ngets another-key\r\n").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"cas cache-key 0 60 5 12345 noreply\r\nvalue\r\n")
                .application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"incr cache-key 1\r\n").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"stats cachedump 1 20\r\n").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"set cache-key\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"settings cache-key 0 60 5\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"getaway cache-key\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"get cache-key\r\njunk").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"set cache-key 0 60 5\r\nvalueX\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"set cache-key 0 60 1048577\r\nvalue\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&memcached_binary_request(0x00, b"key", b"", b""))
                .application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(&memcached_binary_request(
                0x01,
                b"key",
                &[0, 0, 0, 0, 0, 0, 0, 60],
                b"val"
            ))
            .application(),
            api::AgentPacketFlowApplication::Memcached
        );
        let mut partial_memcached_binary =
            memcached_binary_request(0x01, b"key", &[0, 0, 0, 0, 0, 0, 0, 60], b"value");
        partial_memcached_binary.truncate(24 + 8 + 3);
        assert_eq!(
            observation_for_payload(&partial_memcached_binary).application(),
            api::AgentPacketFlowApplication::Memcached
        );
        let mut memcached_binary_with_trailing = memcached_binary_request(0x00, b"key", b"", b"");
        memcached_binary_with_trailing.extend_from_slice(b"junk");
        assert_eq!(
            observation_for_payload(&memcached_binary_with_trailing).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&memcached_binary_request(0x00, b"key", &[0, 0, 0, 0], b""))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0, 0, 0, 8, 0, 3, 0, 9, 0, 0, 0, 1]).application(),
            api::AgentPacketFlowApplication::Kafka
        );
        assert_eq!(
            observation_for_payload(&kafka_request(3, 9, Some(b"rust-client"), b"body"))
                .application(),
            api::AgentPacketFlowApplication::Kafka
        );
        assert_eq!(
            observation_for_payload(&kafka_request(18, 3, None, b"body")).application(),
            api::AgentPacketFlowApplication::Kafka
        );
        assert_eq!(
            observation_for_payload(&kafka_flexible_request(
                18,
                3,
                Some(b"rust-client"),
                b"body"
            ))
            .application(),
            api::AgentPacketFlowApplication::Kafka
        );
        let mut kafka_pipelined = kafka_request(18, 3, None, b"");
        kafka_pipelined.extend_from_slice(&kafka_request(3, 9, Some(b"rust-client"), b""));
        assert_eq!(
            observation_for_payload(&kafka_pipelined).application(),
            api::AgentPacketFlowApplication::Kafka
        );
        let mut kafka_partial_body = kafka_request(3, 9, Some(b"rust-client"), b"body");
        kafka_partial_body.truncate(kafka_partial_body.len() - 2);
        assert_eq!(
            observation_for_payload(&kafka_partial_body).application(),
            api::AgentPacketFlowApplication::Kafka
        );
        let mut kafka_with_trailing_junk = kafka_request(18, 3, None, b"");
        kafka_with_trailing_junk.extend_from_slice(b"junk");
        assert_eq!(
            observation_for_payload(&kafka_with_trailing_junk).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&kafka_request(18, 3, Some(b"bad\0client"), b"")).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                0, 0, 0, 21, 0, 18, 0, 3, 0, 0, 0, 1, 0, 11, b'r', b'u', b's', b't', b'-', b'c',
                b'l', b'i', b'e', b'n', b't',
            ])
            .application(),
            api::AgentPacketFlowApplication::Kafka
        );
        assert_eq!(
            observation_for_payload(&[0, 0, 0, 7, 0, 4, 0, 9, 0, 0, 0, 1]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0, 0, 0, 8, 0, 93, 0, 1, 0, 0, 0, 1]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0, 0, 0, 10, 0, 18, 0, 3, 0, 0, 0, 1, 0, 4]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0, 0, 0, 10, 0, 18, 0, 3, 0, 0, 0, 1, 0xff, 0xfe])
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"CONNECT {\"verbose\":false}\r\n").application(),
            api::AgentPacketFlowApplication::Nats
        );
        assert_eq!(
            observation_for_payload(b"INFO {\"server_id\":\"n1\"}\r\n").application(),
            api::AgentPacketFlowApplication::Nats
        );
        assert_eq!(
            observation_for_payload(b"PING\r\n").application(),
            api::AgentPacketFlowApplication::Nats
        );
        assert_eq!(
            observation_for_payload(b"PUB events.created reply.inbox 5\r\nhello\r\n").application(),
            api::AgentPacketFlowApplication::Nats
        );
        assert_eq!(
            observation_for_payload(b"PUB events.created 5\r\nhe").application(),
            api::AgentPacketFlowApplication::Nats
        );
        assert_eq!(
            observation_for_payload(b"PUB events.created 5\r\nhello\r").application(),
            api::AgentPacketFlowApplication::Nats
        );
        assert_eq!(
            observation_for_payload(b"PING\r\nPUB events.created reply.inbox 5\r\nhello\r\n")
                .application(),
            api::AgentPacketFlowApplication::Nats
        );
        assert_eq!(
            observation_for_payload(
                b"HPUB events.created 22 27\r\nNATS/1.0\r\nBar: Baz\r\n\r\nhello\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Nats
        );
        assert_eq!(
            observation_for_payload(
                b"HMSG events.created sid-1 22 27\r\nNATS/1.0\r\nBar: Baz\r\n\r\nhello\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Nats
        );
        assert_eq!(
            observation_for_payload(b"SUB events.* workers sid-1\r\n").application(),
            api::AgentPacketFlowApplication::Nats
        );
        assert_eq!(
            observation_for_payload(b"SUB events.> workers sid-1\r\n").application(),
            api::AgentPacketFlowApplication::Nats
        );
        assert_eq!(
            observation_for_payload(b"CONNECT not-json\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"PUB events.created nope\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"PING\r\njunk\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"PUB events.created 5\r\nhello!\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(
                b"HPUB events.created 28 27\r\nNATS/1.0\r\nBar: Baz\r\n\r\nhello\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(
                b"HPUB events.created 22 27\r\nNOTNATS\r\nBar: Baz\r\n\r\nhello\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"PUB events.* 5\r\nhello\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"PUB events.created reply.* 5\r\nhello\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"PUB events..created 5\r\nhello\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"SUB events.>.tail sid-1\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"SUB events* sid-1\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"MSG events.* 1 0\r\n\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"CONNECT {\"verbose\":false}").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                0x10, 0x11, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x05,
                b'a', b'g', b'e', b'n', b't',
            ])
            .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&[
                0x10, 0x12, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x05, 0x02, 0x00, 0x3c, 0x00, 0x00,
                0x05, b'a', b'g', b'e', b'n', b't',
            ])
            .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&mqtt_connect_packet(
                4,
                0x82,
                &[mqtt_field(b"agent"), mqtt_field(b"user")]
            ))
            .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&mqtt_connect_packet(
                4,
                0xc2,
                &[
                    mqtt_field(b"agent"),
                    mqtt_field(b"user"),
                    mqtt_field(&[0, 1])
                ]
            ))
            .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&mqtt_connect_packet(
                4,
                0x06,
                &[
                    mqtt_field(b"agent"),
                    mqtt_field(b"status/offline"),
                    mqtt_field(b"offline")
                ]
            ))
            .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&[
                0x10, 0x11, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x03, 0x00, 0x3c, 0x00, 0x05,
                b'a', b'g', b'e', b'n', b't',
            ])
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                0x10, 0x11, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x42, 0x00, 0x3c, 0x00, 0x05,
                b'a', b'g', b'e', b'n', b't',
            ])
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_connect_packet(4, 0x82, &[mqtt_field(b"agent")]))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_connect_packet(4, 0x06, &[mqtt_field(b"agent")]))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut mqtt_overstated_remaining = mqtt_connect_packet(4, 0x02, &[mqtt_field(b"agent")]);
        mqtt_overstated_remaining[1] += 1;
        assert_eq!(
            observation_for_payload(&mqtt_overstated_remaining).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_connect_packet(4, 0x02, &[mqtt_field(&[0xff])]))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"AMQP\0\0\x09\x01").application(),
            api::AgentPacketFlowApplication::Amqp
        );
        assert_eq!(
            observation_for_payload(&[1, 0, 1, 0, 0, 0, 4, 0, 10, 0, 10, 0xce]).application(),
            api::AgentPacketFlowApplication::Amqp
        );
        assert_eq!(
            observation_for_payload(&[8, 0, 0, 0, 0, 0, 0, 0xce]).application(),
            api::AgentPacketFlowApplication::Amqp
        );
        assert_eq!(
            observation_for_payload(b"AMQPxxxx").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[1, 0, 1, 0, 0, 0, 4, 0, 10, 0, 10, 0]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[8, 0, 1, 0, 0, 0, 0, 0xce]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[4, 0, 1, 0, 0, 0, 0, 0xce]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                0x04, 0, 0, 0, 0x07, 0, 0, 0, 15, 0, 0, 0, 8, b'S', b'E', b'L', b'E', b'C', b'T',
                b' ', b'1', 0, 1, 0,
            ])
            .application(),
            api::AgentPacketFlowApplication::Cassandra
        );
        assert_eq!(
            observation_for_payload(&[
                0x04, 0, 0, 0, 0x01, 0, 0, 0, 22, 0, 1, 0, 11, b'C', b'Q', b'L', b'_', b'V', b'E',
                b'R', b'S', b'I', b'O', b'N', 0, 5, b'3', b'.', b'0', b'.', b'0',
            ])
            .application(),
            api::AgentPacketFlowApplication::Cassandra
        );
        assert_eq!(
            observation_for_payload(&[0x84, 0, 0, 0, 0x02, 0, 0, 0, 0]).application(),
            api::AgentPacketFlowApplication::Cassandra
        );
        assert_eq!(
            observation_for_payload(&[0x04, 0, 0, 0, 0x07, 0, 0, 0, 0]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0x04, 0xe0, 0, 0, 0x07, 0, 0, 0, 0]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0x04, 0, 0, 0, 0x04, 0, 0, 0, 0]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                0x04, 0, 0, 0, 0x07, 0, 0, 0, 13, 0, 0, 0, 6, b'n', b'o', b't', b'c', b'q', b'l',
                0, 1, 0,
            ])
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut cassandra_value_parameters = Vec::new();
        cassandra_value_parameters.extend_from_slice(&1_u16.to_be_bytes());
        cassandra_value_parameters.extend_from_slice(&4_i32.to_be_bytes());
        cassandra_value_parameters.extend_from_slice(&1234_i32.to_be_bytes());
        assert_eq!(
            observation_for_payload(&cassandra_query_frame(
                b"SELECT * FROM ks.tbl WHERE id=?",
                0x0001,
                0x01,
                &cassandra_value_parameters
            ))
            .application(),
            api::AgentPacketFlowApplication::Cassandra
        );
        assert_eq!(
            observation_for_payload(&cassandra_query_frame(b"SELECT 1", 0x00ff, 0, &[]))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&cassandra_query_frame(b"SELECT 1", 0x0001, 0x80, &[]))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&cassandra_query_frame(b"SELECT 1", 0x0001, 0x40, &[]))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&cassandra_query_frame(
                b"SELECT 1",
                0x0001,
                0x10,
                &0x0008_u16.to_be_bytes()
            ))
            .application(),
            api::AgentPacketFlowApplication::Cassandra
        );
        assert_eq!(
            observation_for_payload(&cassandra_query_frame(
                b"SELECT 1",
                0x0001,
                0x10,
                &0x0001_u16.to_be_bytes()
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&cassandra_query_frame(
                b"SELECT 1",
                0x0001,
                0x04,
                &0_u32.to_be_bytes()
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let empty_bson = mongodb_empty_document();
        let mut mongodb_op_msg = Vec::new();
        mongodb_op_msg.extend_from_slice(&0_u32.to_le_bytes());
        mongodb_op_msg.push(0);
        mongodb_op_msg.extend_from_slice(&empty_bson);
        assert_eq!(
            observation_for_payload(&mongodb_message(2013, &mongodb_op_msg)).application(),
            api::AgentPacketFlowApplication::MongoDb
        );
        let mut mongodb_op_msg_with_sequence = Vec::new();
        mongodb_op_msg_with_sequence.extend_from_slice(&0_u32.to_le_bytes());
        mongodb_op_msg_with_sequence.push(0);
        mongodb_op_msg_with_sequence.extend_from_slice(&empty_bson);
        mongodb_op_msg_with_sequence.push(1);
        let sequence_identifier = b"documents\0";
        let sequence_size = 4 + sequence_identifier.len() + empty_bson.len();
        mongodb_op_msg_with_sequence.extend_from_slice(&(sequence_size as u32).to_le_bytes());
        mongodb_op_msg_with_sequence.extend_from_slice(sequence_identifier);
        mongodb_op_msg_with_sequence.extend_from_slice(&empty_bson);
        assert_eq!(
            observation_for_payload(&mongodb_message(2013, &mongodb_op_msg_with_sequence))
                .application(),
            api::AgentPacketFlowApplication::MongoDb
        );
        let mut mongodb_compressed = Vec::new();
        mongodb_compressed.extend_from_slice(&2013_u32.to_le_bytes());
        mongodb_compressed.extend_from_slice(&9_u32.to_le_bytes());
        mongodb_compressed.push(0);
        mongodb_compressed.extend_from_slice(b"compressed");
        assert_eq!(
            observation_for_payload(&mongodb_message(2012, &mongodb_compressed)).application(),
            api::AgentPacketFlowApplication::MongoDb
        );
        let mut mongodb_op_query = Vec::new();
        mongodb_op_query.extend_from_slice(&0_u32.to_le_bytes());
        mongodb_op_query.extend_from_slice(b"admin.$cmd\0");
        mongodb_op_query.extend_from_slice(&0_i32.to_le_bytes());
        mongodb_op_query.extend_from_slice(&1_i32.to_le_bytes());
        mongodb_op_query.extend_from_slice(&empty_bson);
        assert_eq!(
            observation_for_payload(&mongodb_message(2004, &mongodb_op_query)).application(),
            api::AgentPacketFlowApplication::MongoDb
        );
        let mut mongodb_op_reply = Vec::new();
        mongodb_op_reply.extend_from_slice(&0_u32.to_le_bytes());
        mongodb_op_reply.extend_from_slice(&0_u64.to_le_bytes());
        mongodb_op_reply.extend_from_slice(&0_i32.to_le_bytes());
        mongodb_op_reply.extend_from_slice(&0_i32.to_le_bytes());
        assert_eq!(
            observation_for_payload(&mongodb_message(1, &mongodb_op_reply)).application(),
            api::AgentPacketFlowApplication::MongoDb
        );
        let mut invalid_mongodb_op_msg_trailing = mongodb_op_msg.clone();
        invalid_mongodb_op_msg_trailing.extend_from_slice(b"junk");
        assert_eq!(
            observation_for_payload(&mongodb_message(2013, &invalid_mongodb_op_msg_trailing))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut invalid_mongodb_query_trailing = mongodb_op_query.clone();
        invalid_mongodb_query_trailing.extend_from_slice(b"junk");
        assert_eq!(
            observation_for_payload(&mongodb_message(2004, &invalid_mongodb_query_trailing))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut invalid_mongodb_reply_count = Vec::new();
        invalid_mongodb_reply_count.extend_from_slice(&0_u32.to_le_bytes());
        invalid_mongodb_reply_count.extend_from_slice(&0_u64.to_le_bytes());
        invalid_mongodb_reply_count.extend_from_slice(&0_i32.to_le_bytes());
        invalid_mongodb_reply_count.extend_from_slice(&2_i32.to_le_bytes());
        invalid_mongodb_reply_count.extend_from_slice(&empty_bson);
        assert_eq!(
            observation_for_payload(&mongodb_message(1, &invalid_mongodb_reply_count))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut invalid_mongodb_compressed = Vec::new();
        invalid_mongodb_compressed.extend_from_slice(&2012_u32.to_le_bytes());
        invalid_mongodb_compressed.extend_from_slice(&9_u32.to_le_bytes());
        invalid_mongodb_compressed.push(4);
        invalid_mongodb_compressed.extend_from_slice(b"compressed");
        assert_eq!(
            observation_for_payload(&mongodb_message(2012, &invalid_mongodb_compressed))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xdd, 0x07, 0, 0])
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                26, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xdd, 0x07, 0, 0, 0, 0, 0, 0, 3, 5, 0, 0, 0,
                0,
            ])
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut invalid_mongodb_op_msg = Vec::new();
        invalid_mongodb_op_msg.extend_from_slice(&0_u32.to_le_bytes());
        invalid_mongodb_op_msg.push(0);
        invalid_mongodb_op_msg.extend_from_slice(&6_u32.to_le_bytes());
        invalid_mongodb_op_msg.push(0);
        assert_eq!(
            observation_for_payload(&mongodb_message(2013, &invalid_mongodb_op_msg)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut invalid_mongodb_query = Vec::new();
        invalid_mongodb_query.extend_from_slice(&0_u32.to_le_bytes());
        invalid_mongodb_query.extend_from_slice(b"admin\0");
        invalid_mongodb_query.extend_from_slice(&0_i32.to_le_bytes());
        invalid_mongodb_query.extend_from_slice(&1_i32.to_le_bytes());
        invalid_mongodb_query.extend_from_slice(&empty_bson);
        assert_eq!(
            observation_for_payload(&mongodb_message(2004, &invalid_mongodb_query)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&elasticsearch_transport_frame(0x08, b"", b"")).application(),
            api::AgentPacketFlowApplication::Elasticsearch
        );
        assert_eq!(
            observation_for_payload(&elasticsearch_transport_frame(0x09, b"vh", b"body"))
                .application(),
            api::AgentPacketFlowApplication::Elasticsearch
        );
        let mut elasticsearch_with_trailing_frame =
            elasticsearch_transport_frame(0x08, b"", b"body");
        elasticsearch_with_trailing_frame
            .extend_from_slice(&elasticsearch_transport_frame(0x09, b"vh", b"body"));
        assert_eq!(
            observation_for_payload(&elasticsearch_with_trailing_frame).application(),
            api::AgentPacketFlowApplication::Elasticsearch
        );
        assert_eq!(
            observation_for_payload(&[
                b'E', b'S', 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 1, 0x40, 0, 0, 0, 1, 0, 0, 0, 0,
            ])
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&elasticsearch_transport_frame(0x02, b"", b"")).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                b'E', b'S', 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 1, 0x08, 8, 0, 0, 99, 0, 0, 0, 1,
            ])
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&elasticsearch_transport_frame_with_version(
                0x08, 1, b"", b""
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
    }

    #[test]
    fn packet_flow_payload_prefix_deserialization_is_bounded(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parsed: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"payload_prefix":"GET / HTTP/1.1\r\n"}"#)?;
        assert_eq!(parsed.payload_prefix, b"GET / HTTP/1.1\r\n");

        let oversized_payload = vec!["1"; api::PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES + 1].join(",");
        let error = match serde_json::from_str::<api::AgentPacketFlowObservation>(&format!(
            r#"{{"payload_prefix":[{oversized_payload}]}}"#
        )) {
            Ok(_) => return Err("oversized payload_prefix should be rejected".into()),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("packet-flow payload_prefix exceeds"));
        Ok(())
    }

    #[test]
    fn packet_flow_detector_deserialization_is_bounded_and_printable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parsed: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"detector":"ebpf-jsonl"}"#)?;
        assert_eq!(parsed.detector.as_deref(), Some("ebpf-jsonl"));

        let oversized_detector = "x".repeat(api::PACKET_FLOW_DETECTOR_MAX_BYTES + 1);
        let error = match serde_json::from_str::<api::AgentPacketFlowObservation>(&format!(
            r#"{{"detector":"{oversized_detector}"}}"#
        )) {
            Ok(_) => return Err("oversized detector should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("packet-flow detector exceeds"));

        let error =
            match serde_json::from_str::<api::AgentPacketFlowObservation>(r#"{"detector":""}"#) {
                Ok(_) => return Err("empty detector should be rejected".into()),
                Err(error) => error,
            };
        assert!(error
            .to_string()
            .contains("packet-flow detector must not be empty"));

        let error = match serde_json::from_str::<api::AgentPacketFlowObservation>(
            "{\"detector\":\"ebpf-jsonl\\nspoof\"}",
        ) {
            Ok(_) => return Err("detector with control characters should be rejected".into()),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("packet-flow detector must not contain control characters"));
        Ok(())
    }

    #[test]
    fn packet_flow_conntrack_status_deserialization_is_bounded_and_normalized(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parsed: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"conntrack_status":["assured","unreplied","assured"]}"#)?;
        assert_eq!(
            parsed.conntrack_status,
            vec![
                api::AgentPacketFlowConntrackStatus::Unreplied,
                api::AgentPacketFlowConntrackStatus::Assured,
            ]
        );

        let oversized_statuses =
            ["\"assured\""; api::PACKET_FLOW_CONNTRACK_STATUS_MAX_FLAGS + 1].join(",");
        let error = match serde_json::from_str::<api::AgentPacketFlowObservation>(&format!(
            r#"{{"conntrack_status":[{oversized_statuses}]}}"#
        )) {
            Ok(_) => return Err("oversized conntrack_status should be rejected".into()),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("packet-flow conntrack_status exceeds"));
        Ok(())
    }

    #[test]
    fn packet_flow_observation_validation_rechecks_direct_bounds(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let oversized_detector = api::AgentPacketFlowObservation {
            detector: Some("x".repeat(api::PACKET_FLOW_DETECTOR_MAX_BYTES + 1)),
            ..Default::default()
        };
        let error = match oversized_detector.validate_transport_metadata() {
            Ok(()) => return Err("direct oversized detector should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("packet-flow detector exceeds"));

        let empty_detector = api::AgentPacketFlowObservation {
            detector: Some(" ".to_string()),
            ..Default::default()
        };
        let error = match empty_detector.validate_transport_metadata() {
            Ok(()) => return Err("direct empty detector should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("packet-flow detector must not be empty"));

        let control_detector = api::AgentPacketFlowObservation {
            detector: Some("proc\nconntrack".to_string()),
            ..Default::default()
        };
        let error = match control_detector.validate_transport_metadata() {
            Ok(()) => return Err("direct detector control characters should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("packet-flow detector must not contain control characters"));

        let oversized_payload = api::AgentPacketFlowObservation {
            payload_prefix: vec![0; api::PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES + 1],
            ..Default::default()
        };
        let error = match oversized_payload.validate_transport_metadata() {
            Ok(()) => return Err("direct oversized payload prefix should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("packet-flow payload_prefix exceeds"));

        let oversized_status = api::AgentPacketFlowObservation {
            conntrack_status: vec![
                api::AgentPacketFlowConntrackStatus::Assured;
                api::PACKET_FLOW_CONNTRACK_STATUS_MAX_FLAGS + 1
            ],
            ..Default::default()
        };
        let error = match oversized_status.validate_transport_metadata() {
            Ok(()) => return Err("direct oversized conntrack status should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("packet-flow conntrack_status exceeds"));

        let duplicated_status = api::AgentPacketFlowObservation {
            conntrack_status: vec![
                api::AgentPacketFlowConntrackStatus::Assured,
                api::AgentPacketFlowConntrackStatus::Assured,
            ],
            ..Default::default()
        };
        let error = match duplicated_status.validate_transport_metadata() {
            Ok(()) => return Err("direct duplicate conntrack status should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("sorted and deduplicated"));

        let reversed_status = api::AgentPacketFlowObservation {
            conntrack_status: vec![
                api::AgentPacketFlowConntrackStatus::Assured,
                api::AgentPacketFlowConntrackStatus::Unreplied,
            ],
            ..Default::default()
        };
        let error = match reversed_status.validate_transport_metadata() {
            Ok(()) => return Err("direct unsorted conntrack status should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("sorted and deduplicated"));
        Ok(())
    }

    #[test]
    fn packet_flow_observation_transport_metadata_is_consistent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let udp_with_port: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","destination_port":53}"#)?;
        udp_with_port.validate_transport_metadata()?;

        let sctp_with_port: api::AgentPacketFlowObservation = serde_json::from_str(
            r#"{"protocol":"sctp","source_port":5000,"destination_port":5001}"#,
        )?;
        sctp_with_port.validate_transport_metadata()?;

        let usable_source: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"source":"192.0.2.10"}"#)?;
        usable_source.validate_transport_metadata()?;

        let unspecified_source: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"source":"0.0.0.0"}"#)?;
        let error = match unspecified_source.validate_transport_metadata() {
            Ok(()) => return Err("unspecified packet-flow source should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("source must not use unspecified address"));

        let link_local_source: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"source":"fe80::1"}"#)?;
        let error = match link_local_source.validate_transport_metadata() {
            Ok(()) => return Err("link-local packet-flow source should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("source must not use link_local address"));

        let tcp_with_zero_port: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","destination_port":0}"#)?;
        let error = match tcp_with_zero_port.validate_transport_metadata() {
            Ok(()) => return Err("TCP observation with zero port should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("nonzero ports"));

        let tcp_with_state: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","tcp_state":"established"}"#)?;
        tcp_with_state.validate_transport_metadata()?;

        let udp_with_tcp_state: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","tcp_state":"established"}"#)?;
        let error = match udp_with_tcp_state.validate_transport_metadata() {
            Ok(()) => return Err("UDP observation with TCP state should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("TCP state requires TCP protocol"));

        let sctp_with_tcp_state: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"sctp","tcp_state":"established"}"#)?;
        let error = match sctp_with_tcp_state.validate_transport_metadata() {
            Ok(()) => return Err("SCTP observation with TCP state should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("TCP state requires TCP protocol"));

        let icmp_with_port: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"icmp","destination_port":8}"#)?;
        let error = match icmp_with_port.validate_transport_metadata() {
            Ok(()) => return Err("ICMP observation with port metadata should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("port metadata requires TCP, UDP, or SCTP protocol"));

        let gre_with_port: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"gre","destination_port":47}"#)?;
        let error = match gre_with_port.validate_transport_metadata() {
            Ok(()) => return Err("GRE observation with port metadata should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("port metadata requires TCP, UDP, or SCTP protocol"));

        let ah_with_port: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"ah","destination_port":51}"#)?;
        let error = match ah_with_port.validate_transport_metadata() {
            Ok(()) => return Err("AH observation with port metadata should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("port metadata requires TCP, UDP, or SCTP protocol"));

        let ip_tunnel_with_port: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"ip_in_ip","destination_port":4}"#)?;
        let error = match ip_tunnel_with_port.validate_transport_metadata() {
            Ok(()) => {
                return Err("IP-in-IP observation with port metadata should be rejected".into());
            }
            Err(error) => error,
        };
        assert!(error.contains("port metadata requires TCP, UDP, or SCTP protocol"));

        let application_without_protocol: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"application":"postgres"}"#)?;
        application_without_protocol.validate_transport_metadata()?;

        let udp_wireguard_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"wire_guard"}"#)?;
        udp_wireguard_hint.validate_transport_metadata()?;

        let udp_dns_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"dns"}"#)?;
        udp_dns_hint.validate_transport_metadata()?;

        let tcp_dns_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"dns"}"#)?;
        tcp_dns_hint.validate_transport_metadata()?;

        let udp_dhcp_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"dhcp"}"#)?;
        udp_dhcp_hint.validate_transport_metadata()?;

        let tcp_dhcp_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"dhcp"}"#)?;
        let error = match tcp_dhcp_hint.validate_transport_metadata() {
            Ok(()) => return Err("TCP DHCP hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint dhcp requires UDP protocol"));

        let udp_bfd_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"bfd"}"#)?;
        udp_bfd_hint.validate_transport_metadata()?;

        let tcp_bfd_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"bfd"}"#)?;
        let error = match tcp_bfd_hint.validate_transport_metadata() {
            Ok(()) => return Err("TCP BFD hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint bfd requires UDP protocol"));

        let udp_ike_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"ike"}"#)?;
        udp_ike_hint.validate_transport_metadata()?;

        let tcp_ike_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"ike"}"#)?;
        let error = match tcp_ike_hint.validate_transport_metadata() {
            Ok(()) => return Err("TCP IKE hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint ike requires UDP protocol"));

        let udp_ipsec_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"ipsec"}"#)?;
        udp_ipsec_hint.validate_transport_metadata()?;

        let esp_ipsec_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"esp","application":"ipsec"}"#)?;
        esp_ipsec_hint.validate_transport_metadata()?;

        let ah_ipsec_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"ah","application":"ipsec"}"#)?;
        ah_ipsec_hint.validate_transport_metadata()?;

        let ip_tunnel_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"ip_in_ip","application":"ip_tunnel"}"#)?;
        ip_tunnel_hint.validate_transport_metadata()?;

        let ipv6_tunnel_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"ipv6_encap","application":"ip_tunnel"}"#)?;
        ipv6_tunnel_hint.validate_transport_metadata()?;

        let tcp_ip_tunnel_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"ip_tunnel"}"#)?;
        let error = match tcp_ip_tunnel_hint.validate_transport_metadata() {
            Ok(()) => return Err("TCP IP tunnel hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains(
            "application hint ip_tunnel requires IP-in-IP or IPv6 encapsulation protocol"
        ));

        let tcp_ipsec_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"ipsec"}"#)?;
        let error = match tcp_ipsec_hint.validate_transport_metadata() {
            Ok(()) => return Err("TCP IPsec hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint ipsec requires UDP, ESP, or AH protocol"));

        let gre_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"gre","application":"gre"}"#)?;
        gre_hint.validate_transport_metadata()?;

        let tcp_gre_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"gre"}"#)?;
        let error = match tcp_gre_hint.validate_transport_metadata() {
            Ok(()) => return Err("TCP GRE hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint gre requires GRE protocol"));

        let udp_vxlan_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"vxlan"}"#)?;
        udp_vxlan_hint.validate_transport_metadata()?;

        let tcp_vxlan_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"vxlan"}"#)?;
        let error = match tcp_vxlan_hint.validate_transport_metadata() {
            Ok(()) => return Err("TCP VXLAN hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint vxlan requires UDP protocol"));

        let udp_geneve_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"geneve"}"#)?;
        udp_geneve_hint.validate_transport_metadata()?;

        let tcp_geneve_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"geneve"}"#)?;
        let error = match tcp_geneve_hint.validate_transport_metadata() {
            Ok(()) => return Err("TCP Geneve hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint geneve requires UDP protocol"));

        let udp_https_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"https"}"#)?;
        udp_https_hint.validate_transport_metadata()?;

        let udp_memcached_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"memcached"}"#)?;
        udp_memcached_hint.validate_transport_metadata()?;

        let udp_syslog_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"syslog"}"#)?;
        udp_syslog_hint.validate_transport_metadata()?;

        let tcp_syslog_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"syslog"}"#)?;
        tcp_syslog_hint.validate_transport_metadata()?;

        let udp_snmp_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"snmp"}"#)?;
        udp_snmp_hint.validate_transport_metadata()?;

        let tcp_snmp_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"snmp"}"#)?;
        tcp_snmp_hint.validate_transport_metadata()?;

        let udp_kerberos_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"kerberos"}"#)?;
        udp_kerberos_hint.validate_transport_metadata()?;

        let tcp_kerberos_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"kerberos"}"#)?;
        tcp_kerberos_hint.validate_transport_metadata()?;

        let udp_ntp_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"ntp"}"#)?;
        udp_ntp_hint.validate_transport_metadata()?;

        let tcp_ntp_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"ntp"}"#)?;
        tcp_ntp_hint.validate_transport_metadata()?;

        let udp_radius_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"radius"}"#)?;
        udp_radius_hint.validate_transport_metadata()?;

        let tcp_radius_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"radius"}"#)?;
        tcp_radius_hint.validate_transport_metadata()?;

        let tcp_tacacs_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"tacacs"}"#)?;
        tcp_tacacs_hint.validate_transport_metadata()?;

        let udp_tacacs_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"tacacs"}"#)?;
        let error = match udp_tacacs_hint.validate_transport_metadata() {
            Ok(()) => return Err("UDP TACACS+ hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint tacacs requires TCP protocol"));

        let tcp_bgp_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"bgp"}"#)?;
        tcp_bgp_hint.validate_transport_metadata()?;

        let udp_bgp_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"bgp"}"#)?;
        let error = match udp_bgp_hint.validate_transport_metadata() {
            Ok(()) => return Err("UDP BGP hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint bgp requires TCP protocol"));

        let tcp_wireguard_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"wire_guard"}"#)?;
        let error = match tcp_wireguard_hint.validate_transport_metadata() {
            Ok(()) => return Err("TCP WireGuard hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint wireguard requires UDP protocol"));

        let tcp_icmp_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"icmp"}"#)?;
        let error = match tcp_icmp_hint.validate_transport_metadata() {
            Ok(()) => return Err("TCP ICMP hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint icmp requires ICMP protocol"));

        let udp_postgres_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"postgres"}"#)?;
        let error = match udp_postgres_hint.validate_transport_metadata() {
            Ok(()) => return Err("UDP TCP-only service application hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint postgres requires TCP protocol"));

        let icmp_postgres_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"icmp","application":"postgres"}"#)?;
        let error = match icmp_postgres_hint.validate_transport_metadata() {
            Ok(()) => return Err("ICMP service application hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint postgres requires TCP protocol"));

        let any_protocol: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"any"}"#)?;
        let error = match any_protocol.validate_transport_metadata() {
            Ok(()) => {
                return Err("packet-flow observation with protocol any should be rejected".into())
            }
            Err(error) => error,
        };
        assert!(error.contains("concrete transport protocol"));
        Ok(())
    }

    #[test]
    fn packet_flow_destination_classifier_rejects_unusable_targets(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for destination in [
            "100.64.0.11",
            "10.42.7.25",
            "172.20.1.10",
            "fd00::42",
            "2001:db8::42",
        ] {
            assert_eq!(
                api::packet_flow_destination_drop_reason(destination.parse()?),
                None,
                "{destination} should remain eligible"
            );
        }

        assert_eq!(
            api::packet_flow_destination_drop_reason("0.0.0.0".parse()?),
            Some(api::AgentPacketFlowDropReason::Unspecified)
        );
        assert_eq!(
            api::packet_flow_destination_drop_reason("::".parse()?),
            Some(api::AgentPacketFlowDropReason::Unspecified)
        );
        assert_eq!(
            api::packet_flow_destination_drop_reason("127.0.0.1".parse()?),
            Some(api::AgentPacketFlowDropReason::Loopback)
        );
        assert_eq!(
            api::packet_flow_destination_drop_reason("::1".parse()?),
            Some(api::AgentPacketFlowDropReason::Loopback)
        );
        assert_eq!(
            api::packet_flow_destination_drop_reason("224.0.0.1".parse()?),
            Some(api::AgentPacketFlowDropReason::Multicast)
        );
        assert_eq!(
            api::packet_flow_destination_drop_reason("ff02::1".parse()?),
            Some(api::AgentPacketFlowDropReason::Multicast)
        );
        assert_eq!(
            api::packet_flow_destination_drop_reason("255.255.255.255".parse()?),
            Some(api::AgentPacketFlowDropReason::Broadcast)
        );
        assert_eq!(
            api::packet_flow_destination_drop_reason("169.254.10.20".parse()?),
            Some(api::AgentPacketFlowDropReason::LinkLocal)
        );
        assert_eq!(
            api::packet_flow_destination_drop_reason("fe80::1".parse()?),
            Some(api::AgentPacketFlowDropReason::LinkLocal)
        );
        Ok(())
    }

    #[test]
    fn nat_classification_requires_filtering_evidence_for_hole_punch_strategy() {
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
            NatTraversalStrategy::InsufficientData
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
    fn nat_classification_detects_address_dependent_mapping() {
        let assessed_at = Utc::now();
        let local_addr = std::net::SocketAddr::from(([10, 0, 0, 10], 50_000));
        let first_stun = std::net::SocketAddr::from(([198, 51, 100, 1], 3478));
        let second_stun = std::net::SocketAddr::from(([198, 51, 100, 2], 3478));
        let classification = NatClassification::from_observations_with_filtering(
            local_addr,
            vec![
                NatProbeObservation {
                    local_addr,
                    stun_server: first_stun,
                    reflexive_addr: std::net::SocketAddr::from(([203, 0, 113, 10], 40_000)),
                    observed_at: assessed_at,
                },
                NatProbeObservation {
                    local_addr,
                    stun_server: second_stun,
                    reflexive_addr: std::net::SocketAddr::from(([203, 0, 113, 10], 40_001)),
                    observed_at: assessed_at,
                },
            ],
            vec![
                NatFilteringObservation {
                    local_addr,
                    stun_server: first_stun,
                    probe: NatFilteringProbeKind::SameAddress,
                    response_origin: Some(first_stun),
                    other_address: Some(second_stun),
                    observed_at: assessed_at,
                },
                NatFilteringObservation {
                    local_addr,
                    stun_server: first_stun,
                    probe: NatFilteringProbeKind::ChangePort,
                    response_origin: Some(std::net::SocketAddr::from(([198, 51, 100, 1], 3479))),
                    other_address: Some(second_stun),
                    observed_at: assessed_at,
                },
                NatFilteringObservation {
                    local_addr,
                    stun_server: first_stun,
                    probe: NatFilteringProbeKind::ChangeAddressAndPort,
                    response_origin: None,
                    other_address: Some(second_stun),
                    observed_at: assessed_at,
                },
            ],
            assessed_at,
        );

        assert_eq!(
            classification.mapping_behavior,
            NatMappingBehavior::AddressDependent
        );
        assert_eq!(
            classification.filtering_behavior,
            NatFilteringBehavior::AddressDependent
        );
        assert_eq!(
            classification.strategy,
            NatTraversalStrategy::CoordinatedHolePunch
        );
        assert_eq!(classification.observed_endpoint, None);
        assert!(classification.confidence > 0.5);
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
