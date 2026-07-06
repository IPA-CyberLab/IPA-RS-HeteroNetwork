use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};

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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum RelayAdmissionFailureReason {
        Unauthorized,
        AdmissionDenied,
        NodeSessionLimitExceeded,
        RateLimited,
        InvalidSessionCredential,
        SocketError,
        InternalError,
    }

    impl RelayAdmissionFailureReason {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::Unauthorized => "unauthorized",
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
        Http,
        Https,
        Ssh,
        Ldap,
        Smb,
        Rdp,
        KubernetesApi,
        Etcd,
        Postgres,
        Mysql,
        Redis,
        Memcached,
        Prometheus,
        OpenTelemetry,
        Grpc,
        Kafka,
        Nats,
        Mqtt,
        Amqp,
        Cassandra,
        MongoDb,
        Elasticsearch,
        WireGuard,
        Icmp,
    }

    impl AgentPacketFlowApplication {
        pub const ALL: [Self; 26] = [
            Self::Unknown,
            Self::Dns,
            Self::Http,
            Self::Https,
            Self::Ssh,
            Self::Ldap,
            Self::Smb,
            Self::Rdp,
            Self::KubernetesApi,
            Self::Etcd,
            Self::Postgres,
            Self::Mysql,
            Self::Redis,
            Self::Memcached,
            Self::Prometheus,
            Self::OpenTelemetry,
            Self::Grpc,
            Self::Kafka,
            Self::Nats,
            Self::Mqtt,
            Self::Amqp,
            Self::Cassandra,
            Self::MongoDb,
            Self::Elasticsearch,
            Self::WireGuard,
            Self::Icmp,
        ];

        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Unknown => "unknown",
                Self::Dns => "dns",
                Self::Http => "http",
                Self::Https => "https",
                Self::Ssh => "ssh",
                Self::Ldap => "ldap",
                Self::Smb => "smb",
                Self::Rdp => "rdp",
                Self::KubernetesApi => "kubernetes_api",
                Self::Etcd => "etcd",
                Self::Postgres => "postgres",
                Self::Mysql => "mysql",
                Self::Redis => "redis",
                Self::Memcached => "memcached",
                Self::Prometheus => "prometheus",
                Self::OpenTelemetry => "opentelemetry",
                Self::Grpc => "grpc",
                Self::Kafka => "kafka",
                Self::Nats => "nats",
                Self::Mqtt => "mqtt",
                Self::Amqp => "amqp",
                Self::Cassandra => "cassandra",
                Self::MongoDb => "mongodb",
                Self::Elasticsearch => "elasticsearch",
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
            if self.protocol != Some(TransportProtocol::Tcp) && self.tcp_state.is_some() {
                return Err("packet-flow TCP state requires TCP protocol".to_string());
            }

            let protocol_has_ports = matches!(
                self.protocol,
                Some(TransportProtocol::Tcp | TransportProtocol::Udp)
            );
            if !protocol_has_ports
                && (self.source_port.is_some() || self.destination_port.is_some())
            {
                return Err("packet-flow port metadata requires TCP or UDP protocol".to_string());
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
            if self.involves_port(53)
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp) | Some(TransportProtocol::Udp)
                )
            {
                return AgentPacketFlowApplication::Dns;
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
            if self.involves_port(3389) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Rdp;
            }
            if self.involves_port(5432) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Postgres;
            }
            if self.involves_port(3306) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Mysql;
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
                && self.involves_port(443)
                && quic_long_header_payload(payload)
            {
                return Some(AgentPacketFlowApplication::Https);
            }
            if protocol_is(self.protocol, TransportProtocol::Udp) && wireguard_payload(payload) {
                return Some(AgentPacketFlowApplication::WireGuard);
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
                    postgres_payload(payload).then_some(AgentPacketFlowApplication::Postgres)
                })
                .or_else(|| mysql_payload(payload).then_some(AgentPacketFlowApplication::Mysql))
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

    fn deserialize_packet_flow_detector<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let detector = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
        let Some(detector) = detector else {
            return Ok(None);
        };
        if detector.len() > PACKET_FLOW_DETECTOR_MAX_BYTES {
            return Err(serde::de::Error::custom(format!(
                "packet-flow detector exceeds {PACKET_FLOW_DETECTOR_MAX_BYTES} bytes"
            )));
        }
        Ok(Some(detector))
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

    fn http_payload_application(payload: &[u8]) -> Option<AgentPacketFlowApplication> {
        if let Some(application) = http_payload_hint_application(payload) {
            return Some(application);
        }
        if let Some(path) = http_request_path(payload) {
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

    fn dns_payload(payload: &[u8], protocol: Option<TransportProtocol>) -> bool {
        match protocol {
            Some(TransportProtocol::Udp) => dns_message_payload(payload),
            Some(TransportProtocol::Tcp) => dns_tcp_payload(payload),
            None => dns_message_payload(payload) || dns_tcp_payload(payload),
            Some(TransportProtocol::Any | TransportProtocol::Icmp) => false,
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
        if tls_sni_hostname_has_label_prefix(hostname, b"prometheus") {
            return Some(AgentPacketFlowApplication::Prometheus);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"opentelemetry")
            || tls_sni_hostname_has_label_prefix(hostname, b"otel")
            || tls_sni_hostname_has_label_prefix(hostname, b"otlp")
        {
            return Some(AgentPacketFlowApplication::OpenTelemetry);
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
        if tls_sni_hostname_has_label_prefix(hostname, b"smb") {
            return Some(AgentPacketFlowApplication::Smb);
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

    fn read_u24_be(payload: &[u8], offset: usize) -> Option<usize> {
        let bytes = payload.get(offset..offset.checked_add(3)?)?;
        Some(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
    }

    fn read_u32_be(payload: &[u8], offset: usize) -> Option<u32> {
        let bytes = payload.get(offset..offset.checked_add(4)?)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn quic_long_header_payload(payload: &[u8]) -> bool {
        if payload.len() < 7 || payload[0] & 0xc0 != 0xc0 {
            return false;
        }
        let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        if version == 0 {
            return false;
        }
        let dcid_len = payload[5] as usize;
        let Some(scid_len_index) = 6_usize.checked_add(dcid_len) else {
            return false;
        };
        let Some(scid_len) = payload.get(scid_len_index).map(|len| *len as usize) else {
            return false;
        };
        scid_len_index
            .checked_add(1)
            .and_then(|offset| offset.checked_add(scid_len))
            .is_some_and(|minimum_len| payload.len() >= minimum_len)
    }

    fn wireguard_payload(payload: &[u8]) -> bool {
        if payload.len() < 4 || payload.get(1..4) != Some(&[0, 0, 0]) {
            return false;
        }
        match payload[0] {
            1 => payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES,
            2 => payload.len() >= 92,
            3 => payload.len() >= 64,
            4 => payload.len() >= 32 && payload.len().is_multiple_of(16),
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
        payload.starts_with(b"SSH-")
    }

    fn ldap_payload(payload: &[u8]) -> bool {
        if payload.len() < 7 || payload[0] != 0x30 {
            return false;
        }
        let Some((sequence_len, mut offset)) = ber_length(payload, 1) else {
            return false;
        };
        if !(1..=16_777_216).contains(&sequence_len) || payload.get(offset) != Some(&0x02) {
            return false;
        }
        let Some((message_id_len, message_id_offset)) = ber_length(payload, offset + 1) else {
            return false;
        };
        if !(1..=4).contains(&message_id_len) {
            return false;
        }
        let Some(protocol_op_offset) = message_id_offset.checked_add(message_id_len) else {
            return false;
        };
        offset = protocol_op_offset;
        matches!(payload.get(offset), Some(0x42 | 0x4a | 0x50 | 0x60..=0x79))
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

    fn smb_payload(payload: &[u8]) -> bool {
        smb_magic_at(payload, 0) || smb_magic_at(payload, 4)
    }

    fn smb_magic_at(payload: &[u8], offset: usize) -> bool {
        matches!(
            payload.get(offset..offset + 4),
            Some([0xff, b'S', b'M', b'B']) | Some([0xfe, b'S', b'M', b'B'])
        )
    }

    fn rdp_payload(payload: &[u8]) -> bool {
        if payload.len() < 7 || payload[0] != 0x03 || payload[1] != 0x00 {
            return false;
        }
        let length = u16::from_be_bytes([payload[2], payload[3]]);
        let x224_len = payload[4] as u16;
        (7..=4096).contains(&length)
            && x224_len >= 2
            && x224_len + 5 <= length
            && matches!(payload[5], 0xd0 | 0xe0 | 0xf0)
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
        payload.len() >= 5 && payload[3] == 0 && payload[4] == 10
    }

    fn redis_payload(payload: &[u8]) -> bool {
        if !payload.starts_with(b"*") {
            return false;
        }
        let commands: [&[u8]; 14] = [
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
            b"XADD",
        ];
        commands
            .iter()
            .any(|command| contains_ascii_case_insensitive(payload, command))
    }

    fn memcached_payload(payload: &[u8]) -> bool {
        memcached_text_payload(payload) || memcached_binary_payload(payload)
    }

    fn memcached_text_payload(payload: &[u8]) -> bool {
        let commands: [&[u8]; 20] = [
            b"get",
            b"gets",
            b"gat",
            b"gats",
            b"set",
            b"add",
            b"replace",
            b"append",
            b"prepend",
            b"cas",
            b"delete",
            b"incr",
            b"decr",
            b"touch",
            b"stats",
            b"version",
            b"flush_all",
            b"verbosity",
            b"quit",
            b"slabs",
        ];
        commands
            .iter()
            .any(|command| starts_ascii_word(payload, command))
    }

    fn memcached_binary_payload(payload: &[u8]) -> bool {
        if payload.len() < 24 || !matches!(payload[0], 0x80 | 0x81) {
            return false;
        }
        let opcode = payload[1];
        let key_len = u16::from_be_bytes([payload[2], payload[3]]) as u32;
        let extras_len = payload[4] as u32;
        let data_type = payload[5];
        let total_body_len = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        data_type == 0
            && opcode <= 0x22
            && key_len.saturating_add(extras_len) <= total_body_len
            && total_body_len <= 1_048_576
    }

    fn kafka_payload(payload: &[u8]) -> bool {
        if payload.len() < 12 {
            return false;
        }
        let frame_len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let api_key = u16::from_be_bytes([payload[4], payload[5]]);
        let api_version = u16::from_be_bytes([payload[6], payload[7]]);
        (8..=100_000_000).contains(&frame_len) && api_key <= 75 && api_version <= 20
    }

    fn nats_payload(payload: &[u8]) -> bool {
        let commands: [&[u8]; 8] = [
            b"INFO", b"CONNECT", b"PUB", b"HPUB", b"SUB", b"UNSUB", b"MSG", b"HMSG",
        ];
        commands
            .iter()
            .any(|command| starts_ascii_word(payload, command))
    }

    fn mqtt_payload(payload: &[u8]) -> bool {
        if payload.len() < 8 || payload[0] != 0x10 {
            return false;
        }
        let Some((remaining_len, mut offset)) = mqtt_remaining_length(payload) else {
            return false;
        };
        if remaining_len < 10 {
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
        if payload.get(protocol_name_end + 2..keepalive_end).is_none() || connect_flags & 0x01 != 0
        {
            return false;
        }

        (protocol_name == b"MQTT"
            && (protocol_level == 4 || (protocol_level == 5 && remaining_len > 10)))
            || (protocol_name == b"MQIsdp" && protocol_level == 3)
    }

    fn mqtt_remaining_length(payload: &[u8]) -> Option<(usize, usize)> {
        let mut value = 0_usize;
        let mut multiplier = 1_usize;
        for offset in 1..=4 {
            let byte = *payload.get(offset)?;
            value = value.checked_add(((byte & 0x7f) as usize).checked_mul(multiplier)?)?;
            if byte & 0x80 == 0 {
                return Some((value, offset + 1));
            }
            multiplier = multiplier.checked_mul(128)?;
        }
        None
    }

    fn amqp_payload(payload: &[u8]) -> bool {
        if payload.len() < 8 || payload.get(..4) != Some(b"AMQP") {
            return false;
        }
        matches!(
            (payload[4], payload[5], payload[6], payload[7]),
            (0, 0, 9, 1) | (0, 1, 0, 0) | (3, 1, 0, 0)
        )
    }

    fn cassandra_payload(payload: &[u8]) -> bool {
        if payload.len() < 9 {
            return false;
        }
        let version_byte = payload[0];
        let version = version_byte & 0x7f;
        let flags = payload[1];
        let opcode = payload[4];
        let body_len = u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]);
        let valid_opcode = matches!(opcode, 0x00 | 0x01 | 0x02 | 0x03 | 0x05..=0x10);

        matches!(version_byte, 0x03..=0x05 | 0x83..=0x85)
            && (3..=5).contains(&version)
            && flags & !0x1f == 0
            && valid_opcode
            && body_len <= 16_777_216
    }

    fn mongodb_payload(payload: &[u8]) -> bool {
        if payload.len() < 16 {
            return false;
        }
        let message_len = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let opcode = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
        if !(16..=100_000_000).contains(&message_len) {
            return false;
        }

        match opcode {
            1 => message_len >= 36 && payload.len() >= 20,
            1000 | 2001 | 2002 | 2003 | 2005 | 2006 | 2007 | 2010 | 2011 | 2012 => {
                message_len >= 20 && payload.len() >= 20
            }
            2004 => mongodb_op_query_payload(payload, message_len),
            2013 => mongodb_op_msg_payload(payload, message_len),
            _ => false,
        }
    }

    fn mongodb_op_query_payload(payload: &[u8], message_len: u32) -> bool {
        if message_len < 34 || payload.len() < 20 {
            return false;
        }
        let flags = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
        flags & !0xfe == 0
    }

    fn mongodb_op_msg_payload(payload: &[u8], message_len: u32) -> bool {
        if message_len < 26 || payload.len() < 21 {
            return false;
        }
        let flags = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
        let section_kind = payload[20];
        flags & !0x0001_0003 == 0
            && (flags & 0x0000_0001 == 0 || message_len >= 30)
            && matches!(section_kind, 0 | 1)
    }

    fn elasticsearch_transport_payload(payload: &[u8]) -> bool {
        if payload.len() < 19 || payload.get(..2) != Some(b"ES") {
            return false;
        }
        let message_len = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
        let status = payload[14];
        let version_id = u32::from_be_bytes([payload[15], payload[16], payload[17], payload[18]]);

        (13..=128 * 1024 * 1024).contains(&message_len) && status & !0x0f == 0 && version_id != 0
    }

    fn starts_ascii_word(payload: &[u8], word: &[u8]) -> bool {
        let Some(head) = payload.get(..word.len()) else {
            return false;
        };
        if !head.eq_ignore_ascii_case(word) {
            return false;
        }
        payload
            .get(word.len())
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    }

    fn path_starts_with_any(path: &[u8], prefixes: &[&[u8]]) -> bool {
        prefixes.iter().any(|prefix| path.starts_with(prefix))
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

        let rdp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(3389),
            ..Default::default()
        };
        assert_eq!(rdp.application(), api::AgentPacketFlowApplication::Rdp);

        let etcd = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(2379),
            ..Default::default()
        };
        assert_eq!(etcd.application(), api::AgentPacketFlowApplication::Etcd);

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

        fn postgres_frontend_message(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut payload = vec![tag];
            let length = (body.len() as u32) + 4;
            payload.extend_from_slice(&length.to_be_bytes());
            payload.extend_from_slice(body);
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
            observation_for_payload(b"GET /index/_search HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Elasticsearch
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
                "smb-files.storage.svc",
                api::AgentPacketFlowApplication::Smb,
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
                &[b"kafka".as_slice()][..],
                api::AgentPacketFlowApplication::Kafka,
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
                &[b"valkey".as_slice()][..],
                api::AgentPacketFlowApplication::Redis,
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
                0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0, 1, 2, 3, 4, 5, 6, 7, 0,
            ],
            ..Default::default()
        };
        assert_eq!(quic.application(), api::AgentPacketFlowApplication::Https);
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
            observation_for_udp_payload(&wireguard_message(1, 64)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(2, 92)).application(),
            api::AgentPacketFlowApplication::WireGuard
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
            observation_for_udp_payload(&wireguard_message(4, 32)).application(),
            api::AgentPacketFlowApplication::WireGuard
        );
        assert_eq!(
            observation_for_udp_payload(&wireguard_message(4, 31)).application(),
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
            observation_for_payload(&[
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
            ])
            .application(),
            api::AgentPacketFlowApplication::Ldap
        );
        assert_eq!(
            observation_for_payload(&[
                0x00, 0x00, 0x00, 0x40, 0xfe, b'S', b'M', b'B', 0x40, 0x00, 0x00, 0x00,
            ])
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
            observation_for_payload(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"set cache-key 0 60 5\r\nvalue\r\n").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(&[
                0x80, 0x00, 0x00, 0x03, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0,
                b'k', b'e', b'y',
            ])
            .application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(&[0, 0, 0, 8, 0, 3, 0, 9, 0, 0, 0, 1]).application(),
            api::AgentPacketFlowApplication::Kafka
        );
        assert_eq!(
            observation_for_payload(b"CONNECT {\"verbose\":false}\r\n").application(),
            api::AgentPacketFlowApplication::Nats
        );
        assert_eq!(
            observation_for_payload(&[
                0x10, 0x0e, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c,
            ])
            .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&[
                0x10, 0x0e, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x03, 0x00, 0x3c,
            ])
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"AMQP\0\0\x09\x01").application(),
            api::AgentPacketFlowApplication::Amqp
        );
        assert_eq!(
            observation_for_payload(b"AMQPxxxx").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0x04, 0, 0, 0, 0x07, 0, 0, 0, 0]).application(),
            api::AgentPacketFlowApplication::Cassandra
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
                26, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xdd, 0x07, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0,
                0,
            ])
            .application(),
            api::AgentPacketFlowApplication::MongoDb
        );
        assert_eq!(
            observation_for_payload(&[16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xdd, 0x07, 0, 0,])
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
        assert_eq!(
            observation_for_payload(&[
                b'E', b'S', 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 1, 0x08, 0, 0, 0, 1, 0, 0, 0, 0,
            ])
            .application(),
            api::AgentPacketFlowApplication::Elasticsearch
        );
        assert_eq!(
            observation_for_payload(&[
                b'E', b'S', 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 1, 0x40, 0, 0, 0, 1, 0, 0, 0, 0,
            ])
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
    fn packet_flow_detector_deserialization_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
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
    fn packet_flow_observation_transport_metadata_is_consistent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let udp_with_port: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","destination_port":53}"#)?;
        udp_with_port.validate_transport_metadata()?;

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

        let icmp_with_port: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"icmp","destination_port":8}"#)?;
        let error = match icmp_with_port.validate_transport_metadata() {
            Ok(()) => return Err("ICMP observation with port metadata should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("port metadata requires TCP or UDP protocol"));
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
