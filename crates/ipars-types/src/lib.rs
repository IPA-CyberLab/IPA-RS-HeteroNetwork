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

    pub fn allows_selected_candidate_kind(self, kind: EndpointCandidateKind) -> bool {
        matches!(
            (self, kind),
            (Self::DirectPublic, EndpointCandidateKind::PublicUdp)
                | (Self::DirectIpv6, EndpointCandidateKind::Ipv6)
                | (
                    Self::DirectNatTraversal,
                    EndpointCandidateKind::StunReflexive
                )
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
        Vnc,
        Ftp,
        Tftp,
        Rsync,
        Smtp,
        Imap,
        Pop3,
        Sip,
        Kerberos,
        Ntp,
        Radius,
        Tacacs,
        Bgp,
        Bfd,
        IparsControlPlane,
        IparsSignal,
        IparsAgent,
        IparsRelay,
        Stun,
        Turn,
        KubernetesApi,
        Kubelet,
        DockerApi,
        Cri,
        Containerd,
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
        Coap,
        Amqp,
        Cassandra,
        MongoDb,
        Elasticsearch,
        #[serde(alias = "opensearch")]
        OpenSearch,
        Solr,
        Git,
        Ike,
        Ipsec,
        IpTunnel,
        Gre,
        Vxlan,
        Geneve,
        WireGuard,
        #[serde(alias = "openvpn")]
        OpenVpn,
        Icmp,
    }

    impl AgentPacketFlowApplication {
        pub const ALL: [Self; 77] = [
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
            Self::Vnc,
            Self::Ftp,
            Self::Tftp,
            Self::Rsync,
            Self::Smtp,
            Self::Imap,
            Self::Pop3,
            Self::Sip,
            Self::Kerberos,
            Self::Ntp,
            Self::Radius,
            Self::Tacacs,
            Self::Bgp,
            Self::Bfd,
            Self::IparsControlPlane,
            Self::IparsSignal,
            Self::IparsAgent,
            Self::IparsRelay,
            Self::Stun,
            Self::Turn,
            Self::KubernetesApi,
            Self::Kubelet,
            Self::DockerApi,
            Self::Cri,
            Self::Containerd,
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
            Self::Coap,
            Self::Amqp,
            Self::Cassandra,
            Self::MongoDb,
            Self::Elasticsearch,
            Self::OpenSearch,
            Self::Solr,
            Self::Git,
            Self::Ike,
            Self::Ipsec,
            Self::IpTunnel,
            Self::Gre,
            Self::Vxlan,
            Self::Geneve,
            Self::WireGuard,
            Self::OpenVpn,
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
                Self::Vnc => "vnc",
                Self::Ftp => "ftp",
                Self::Tftp => "tftp",
                Self::Rsync => "rsync",
                Self::Smtp => "smtp",
                Self::Imap => "imap",
                Self::Pop3 => "pop3",
                Self::Sip => "sip",
                Self::Kerberos => "kerberos",
                Self::Ntp => "ntp",
                Self::Radius => "radius",
                Self::Tacacs => "tacacs",
                Self::Bgp => "bgp",
                Self::Bfd => "bfd",
                Self::IparsControlPlane => "ipars_control_plane",
                Self::IparsSignal => "ipars_signal",
                Self::IparsAgent => "ipars_agent",
                Self::IparsRelay => "ipars_relay",
                Self::Stun => "stun",
                Self::Turn => "turn",
                Self::KubernetesApi => "kubernetes_api",
                Self::Kubelet => "kubelet",
                Self::DockerApi => "docker_api",
                Self::Cri => "cri",
                Self::Containerd => "containerd",
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
                Self::Coap => "coap",
                Self::Amqp => "amqp",
                Self::Cassandra => "cassandra",
                Self::MongoDb => "mongodb",
                Self::Elasticsearch => "elasticsearch",
                Self::OpenSearch => "opensearch",
                Self::Solr => "solr",
                Self::Git => "git",
                Self::Ike => "ike",
                Self::Ipsec => "ipsec",
                Self::IpTunnel => "ip_tunnel",
                Self::Gre => "gre",
                Self::Vxlan => "vxlan",
                Self::Geneve => "geneve",
                Self::WireGuard => "wireguard",
                Self::OpenVpn => "openvpn",
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
    const DNS_MAX_QUESTION_COUNT: u16 = 64;
    const DNS_MAX_NAME_POINTER_DEPTH: usize = 8;

    enum DnsSectionParse {
        Complete(usize),
        Truncated,
    }

    struct DnsNameParse {
        end: usize,
        labels: usize,
        name_len: usize,
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
            let payload_application = self.payload_prefix_application();
            if let Some(application) = payload_application {
                if self.payload_prefix_application_overrides_port(application) {
                    return application;
                }
            }
            if self.involves_port(51820) && protocol_is(self.protocol, TransportProtocol::Udp) {
                return AgentPacketFlowApplication::WireGuard;
            }
            if self.involves_port(1194)
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp | TransportProtocol::Udp)
                )
            {
                return AgentPacketFlowApplication::OpenVpn;
            }
            if self.involves_port(8443) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::IparsControlPlane;
            }
            if self.involves_port(9443) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::IparsSignal;
            }
            if self.involves_port(9780) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::IparsAgent;
            }
            if self.involves_port(9580) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::IparsRelay;
            }
            if self.involves_port(3478) && protocol_is(self.protocol, TransportProtocol::Udp) {
                return AgentPacketFlowApplication::Stun;
            }
            if self.involves_port(5349)
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp | TransportProtocol::Udp)
                )
            {
                return AgentPacketFlowApplication::Turn;
            }
            if self.involves_port(6443) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::KubernetesApi;
            }
            if (self.involves_port(10250) || self.involves_port(10255))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Kubelet;
            }
            if (self.involves_port(2375) || self.involves_port(2376))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::DockerApi;
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
            if self.involves_port(69) && protocol_is(self.protocol, TransportProtocol::Udp) {
                return AgentPacketFlowApplication::Tftp;
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
            if (5900..=5999).any(|port| self.involves_port(port))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Vnc;
            }
            if (self.involves_port(20)
                || self.involves_port(21)
                || self.involves_port(989)
                || self.involves_port(990))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Ftp;
            }
            if self.involves_port(873) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Rsync;
            }
            if self.involves_port(9418) && protocol_is(self.protocol, TransportProtocol::Tcp) {
                return AgentPacketFlowApplication::Git;
            }
            if (self.involves_port(25) || self.involves_port(465) || self.involves_port(587))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Smtp;
            }
            if (self.involves_port(143) || self.involves_port(993))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Imap;
            }
            if (self.involves_port(110) || self.involves_port(995))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Pop3;
            }
            if self.involves_port(5060)
                && matches!(
                    self.protocol,
                    None | Some(
                        TransportProtocol::Tcp | TransportProtocol::Udp | TransportProtocol::Sctp
                    )
                )
            {
                return AgentPacketFlowApplication::Sip;
            }
            if self.involves_port(5061)
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp | TransportProtocol::Sctp)
                )
            {
                return AgentPacketFlowApplication::Sip;
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
            if (self.involves_port(5683) || self.involves_port(5684))
                && matches!(
                    self.protocol,
                    None | Some(TransportProtocol::Tcp | TransportProtocol::Udp)
                )
            {
                return AgentPacketFlowApplication::Coap;
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
            if (self.involves_port(8983) || self.involves_port(8984))
                && protocol_is(self.protocol, TransportProtocol::Tcp)
            {
                return AgentPacketFlowApplication::Solr;
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
            if protocol_is(self.protocol, TransportProtocol::Udp) && tftp_payload(payload) {
                return Some(AgentPacketFlowApplication::Tftp);
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
            if protocol_is(self.protocol, TransportProtocol::Udp) && relay_frame_payload(payload) {
                return Some(AgentPacketFlowApplication::IparsRelay);
            }
            if matches!(
                self.protocol,
                None | Some(TransportProtocol::Tcp) | Some(TransportProtocol::Udp)
            ) && turn_payload(payload)
            {
                return Some(AgentPacketFlowApplication::Turn);
            }
            if matches!(self.protocol, None | Some(TransportProtocol::Udp)) && stun_payload(payload)
            {
                return Some(AgentPacketFlowApplication::Stun);
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
            if matches!(
                self.protocol,
                None | Some(TransportProtocol::Tcp | TransportProtocol::Udp)
            ) && openvpn_payload(payload, self.protocol)
            {
                return Some(AgentPacketFlowApplication::OpenVpn);
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
            if matches!(
                self.protocol,
                None | Some(TransportProtocol::Tcp)
                    | Some(TransportProtocol::Udp)
                    | Some(TransportProtocol::Sctp)
            ) && sip_payload(payload)
            {
                return Some(AgentPacketFlowApplication::Sip);
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
            if matches!(self.protocol, None | Some(TransportProtocol::Udp)) && coap_payload(payload)
            {
                return Some(AgentPacketFlowApplication::Coap);
            }
            if !protocol_is(self.protocol, TransportProtocol::Tcp) {
                return None;
            }
            http_payload_application(payload)
                .or_else(|| tls_client_hello_application(payload))
                .or_else(|| tls_server_hello_application(payload))
                .or_else(|| {
                    tls_handshake_payload(payload).then_some(AgentPacketFlowApplication::Https)
                })
                .or_else(|| ssh_payload(payload).then_some(AgentPacketFlowApplication::Ssh))
                .or_else(|| ldap_payload(payload).then_some(AgentPacketFlowApplication::Ldap))
                .or_else(|| smb_payload(payload).then_some(AgentPacketFlowApplication::Smb))
                .or_else(|| rdp_payload(payload).then_some(AgentPacketFlowApplication::Rdp))
                .or_else(|| vnc_payload(payload).then_some(AgentPacketFlowApplication::Vnc))
                .or_else(|| {
                    zookeeper_payload(payload).then_some(AgentPacketFlowApplication::ZooKeeper)
                })
                .or_else(|| smtp_payload(payload).then_some(AgentPacketFlowApplication::Smtp))
                .or_else(|| imap_payload(payload).then_some(AgentPacketFlowApplication::Imap))
                .or_else(|| pop3_payload(payload).then_some(AgentPacketFlowApplication::Pop3))
                .or_else(|| ftp_payload(payload).then_some(AgentPacketFlowApplication::Ftp))
                .or_else(|| rsync_payload(payload).then_some(AgentPacketFlowApplication::Rsync))
                .or_else(|| git_payload(payload).then_some(AgentPacketFlowApplication::Git))
                .or_else(|| {
                    postgres_payload(payload).then_some(AgentPacketFlowApplication::Postgres)
                })
                .or_else(|| mysql_payload(payload).then_some(AgentPacketFlowApplication::Mysql))
                .or_else(|| mssql_tds_payload(payload).then_some(AgentPacketFlowApplication::MsSql))
                .or_else(|| {
                    oracle_tns_payload(payload).then_some(AgentPacketFlowApplication::Oracle)
                })
                .or_else(|| {
                    clickhouse_native_payload(
                        payload,
                        self.involves_port(9000) || self.involves_port(9440),
                    )
                    .then_some(AgentPacketFlowApplication::ClickHouse)
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
            | AgentPacketFlowApplication::Stun
            | AgentPacketFlowApplication::Bfd
            | AgentPacketFlowApplication::Tftp
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
            AgentPacketFlowApplication::Sip => require_packet_flow_application_protocol(
                protocol,
                application,
                "TCP, UDP, or SCTP",
                |protocol| {
                    matches!(
                        protocol,
                        TransportProtocol::Tcp | TransportProtocol::Udp | TransportProtocol::Sctp
                    )
                },
            ),
            AgentPacketFlowApplication::Dns
            | AgentPacketFlowApplication::Https
            | AgentPacketFlowApplication::Turn
            | AgentPacketFlowApplication::Consul
            | AgentPacketFlowApplication::Nomad
            | AgentPacketFlowApplication::Jaeger
            | AgentPacketFlowApplication::Nfs
            | AgentPacketFlowApplication::Syslog
            | AgentPacketFlowApplication::Snmp
            | AgentPacketFlowApplication::Kerberos
            | AgentPacketFlowApplication::Ntp
            | AgentPacketFlowApplication::Radius
            | AgentPacketFlowApplication::Memcached
            | AgentPacketFlowApplication::OpenVpn
            | AgentPacketFlowApplication::Coap
            | AgentPacketFlowApplication::IparsRelay => require_packet_flow_application_protocol(
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
        if detector.trim() != detector {
            return Err(
                "packet-flow detector must not contain leading or trailing whitespace".to_string(),
            );
        }
        if detector.chars().any(char::is_control) {
            return Err("packet-flow detector must not contain control characters".to_string());
        }
        if !detector
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(
                "packet-flow detector must be an ASCII token using letters, digits, '.', '_', or '-'"
                    .to_string(),
            );
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
    const GIT_SMART_SERVICES: [&[u8]; 3] = [
        b"git-upload-pack",
        b"git-receive-pack",
        b"git-upload-archive",
    ];

    fn http_payload_application(payload: &[u8]) -> Option<AgentPacketFlowApplication> {
        if let Some(application) = http_payload_hint_application(payload) {
            return Some(application);
        }
        if let Some(application) = http_response_application(payload) {
            return Some(application);
        }
        if let Some((_, path, _)) = http_request_line(payload) {
            if doh_http_request(payload) {
                return Some(AgentPacketFlowApplication::Dns);
            }
            if ipars_control_plane_http_api_path(path) {
                return Some(AgentPacketFlowApplication::IparsControlPlane);
            }
            if ipars_signal_http_api_path(path) {
                return Some(AgentPacketFlowApplication::IparsSignal);
            }
            if ipars_agent_http_api_path(path) {
                return Some(AgentPacketFlowApplication::IparsAgent);
            }
            if ipars_relay_http_api_path(path) {
                return Some(AgentPacketFlowApplication::IparsRelay);
            }
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
            if kubelet_http_api_path(path) {
                return Some(AgentPacketFlowApplication::Kubelet);
            }
            if docker_http_api_path(path) {
                return Some(AgentPacketFlowApplication::DockerApi);
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
            if cri_grpc_path(path) {
                return Some(AgentPacketFlowApplication::Cri);
            }
            if containerd_grpc_path(path) {
                return Some(AgentPacketFlowApplication::Containerd);
            }
            if etcd_grpc_path(path) {
                return Some(AgentPacketFlowApplication::Etcd);
            }
            if etcd_http_api_path(path) {
                return Some(AgentPacketFlowApplication::Etcd);
            }
            if kubernetes_http_api_path(path) {
                return Some(AgentPacketFlowApplication::KubernetesApi);
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
            if opensearch_http_api_path(path) {
                return Some(AgentPacketFlowApplication::OpenSearch);
            }
            if solr_http_api_path(path) {
                return Some(AgentPacketFlowApplication::Solr);
            }
            if git_http_api_path(path) {
                return Some(AgentPacketFlowApplication::Git);
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

    fn http_response_application(payload: &[u8]) -> Option<AgentPacketFlowApplication> {
        let line_end = payload.iter().position(|byte| *byte == b'\n')?;
        let status_line = payload[..line_end]
            .strip_suffix(b"\r")
            .unwrap_or(&payload[..line_end]);
        if !http_response_status_line(status_line) {
            return None;
        }
        http_response_header_application(payload.get(line_end + 1..).unwrap_or_default())
    }

    fn http_response_status_line(line: &[u8]) -> bool {
        if line.len() < b"HTTP/1.1 200".len()
            || !(line.starts_with(b"HTTP/1.0 ") || line.starts_with(b"HTTP/1.1 "))
        {
            return false;
        }
        let code = &line[9..12];
        if !code.iter().all(u8::is_ascii_digit) {
            return false;
        }
        let status_code = usize::from(code[0] - b'0') * 100
            + usize::from(code[1] - b'0') * 10
            + usize::from(code[2] - b'0');
        (100..=599).contains(&status_code)
            && line
                .get(12)
                .is_none_or(|byte| *byte == b' ' || *byte == b'\t')
            && line
                .iter()
                .all(|byte| *byte == b'\t' || *byte == b' ' || byte.is_ascii_graphic())
    }

    fn http_response_header_application(headers: &[u8]) -> Option<AgentPacketFlowApplication> {
        if doh_http_media_type(headers) {
            return Some(AgentPacketFlowApplication::Dns);
        }
        if http_header_contains(headers, b"x-kubernetes-pf-flowschema-uid")
            || http_header_contains(headers, b"x-kubernetes-pf-prioritylevel-uid")
            || http_header_contains(headers, b"audit-id")
            || http_header_value_contains(
                headers,
                b"content-type",
                b"application/vnd.kubernetes.protobuf",
            )
        {
            return Some(AgentPacketFlowApplication::KubernetesApi);
        }
        if http_header_contains(headers, b"docker-experimental")
            || http_header_contains(headers, b"docker-api-version")
        {
            return Some(AgentPacketFlowApplication::DockerApi);
        }
        if http_header_contains(headers, b"x-etcd-index")
            || http_header_contains(headers, b"x-raft-index")
            || http_header_contains(headers, b"x-raft-term")
        {
            return Some(AgentPacketFlowApplication::Etcd);
        }
        if http_header_contains(headers, b"x-consul-index")
            || http_header_contains(headers, b"x-consul-knownleader")
            || http_header_contains(headers, b"x-consul-lastcontact")
        {
            return Some(AgentPacketFlowApplication::Consul);
        }
        if http_header_name_has_prefix(headers, b"x-vault-") {
            return Some(AgentPacketFlowApplication::Vault);
        }
        if http_header_name_has_prefix(headers, b"x-nomad-") {
            return Some(AgentPacketFlowApplication::Nomad);
        }
        if http_header_name_has_prefix(headers, b"x-opensearch-")
            || http_header_value_contains(headers, b"x-opensearch-product", b"opensearch")
        {
            return Some(AgentPacketFlowApplication::OpenSearch);
        }
        if http_header_name_has_prefix(headers, b"x-solr-") {
            return Some(AgentPacketFlowApplication::Solr);
        }
        if http_header_value_contains(headers, b"x-elastic-product", b"elasticsearch") {
            return Some(AgentPacketFlowApplication::Elasticsearch);
        }
        if http_header_name_has_prefix(headers, b"x-clickhouse-") {
            return Some(AgentPacketFlowApplication::ClickHouse);
        }
        if http_header_name_has_prefix(headers, b"x-influxdb-")
            || http_header_name_has_prefix(headers, b"x-influx-")
        {
            return Some(AgentPacketFlowApplication::InfluxDb);
        }
        if http_header_value_contains(headers, b"content-type", b"application/openmetrics-text")
            || http_header_value_contains(headers, b"content-type", b"text/plain; version=0.0.4")
        {
            return Some(AgentPacketFlowApplication::Prometheus);
        }
        if http_header_value_contains(headers, b"content-type", b"application/grpc")
            || http_header_contains(headers, b"grpc-status")
        {
            return Some(AgentPacketFlowApplication::Grpc);
        }
        None
    }

    fn http_header_contains(headers: &[u8], name: &[u8]) -> bool {
        http_header_name_matches(headers, |candidate| candidate.eq_ignore_ascii_case(name))
    }

    fn http_header_name_has_prefix(headers: &[u8], prefix: &[u8]) -> bool {
        http_header_name_matches(headers, |candidate| {
            candidate
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        })
    }

    fn http_header_value_contains(headers: &[u8], name: &[u8], needle: &[u8]) -> bool {
        http_header_value_matches(headers, name, |value| {
            contains_ascii_case_insensitive(value, needle)
        })
    }

    fn http_header_media_type_matches(headers: &[u8], name: &[u8], media_type: &[u8]) -> bool {
        http_header_value_matches(headers, name, |value| {
            let media_type_end = value
                .iter()
                .position(|byte| *byte == b';')
                .unwrap_or(value.len());
            trim_ascii_space(&value[..media_type_end]).eq_ignore_ascii_case(media_type)
        })
    }

    fn http_header_name_matches<F>(headers: &[u8], mut matches_name: F) -> bool
    where
        F: FnMut(&[u8]) -> bool,
    {
        http_header_value_matches(headers, b"", |line| {
            let Some(colon) = line.iter().position(|byte| *byte == b':') else {
                return false;
            };
            let name = trim_ascii_space(&line[..colon]);
            !name.is_empty() && matches_name(name)
        })
    }

    fn http_header_value_matches<F>(headers: &[u8], name: &[u8], mut matches_value: F) -> bool
    where
        F: FnMut(&[u8]) -> bool,
    {
        let mut offset = 0_usize;
        while offset < headers.len() {
            let remaining = &headers[offset..];
            let line_end = remaining
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(remaining.len());
            let line = remaining[..line_end]
                .strip_suffix(b"\r")
                .unwrap_or(&remaining[..line_end]);
            if line.is_empty() {
                break;
            }
            if line.len() > 512
                || !line
                    .iter()
                    .all(|byte| *byte == b'\t' || *byte == b' ' || byte.is_ascii_graphic())
            {
                return false;
            }
            if name.is_empty() {
                if matches_value(line) {
                    return true;
                }
            } else if let Some(colon) = line.iter().position(|byte| *byte == b':') {
                let candidate = trim_ascii_space(&line[..colon]);
                if candidate.eq_ignore_ascii_case(name)
                    && matches_value(trim_ascii_space(&line[colon + 1..]))
                {
                    return true;
                }
            }
            if line_end == remaining.len() {
                break;
            }
            offset = offset.saturating_add(line_end + 1);
        }
        false
    }

    fn doh_http_request(payload: &[u8]) -> bool {
        let Some((method, path, line_end)) = http_request_line(payload) else {
            return false;
        };
        let headers = payload.get(line_end + 1..).unwrap_or_default();
        if method == b"GET" {
            return doh_get_request_path(path);
        }
        method == b"POST" && doh_endpoint_path(path) && doh_http_media_type(headers)
    }

    fn doh_http_media_type(headers: &[u8]) -> bool {
        http_header_media_type_matches(headers, b"content-type", b"application/dns-message")
            || http_header_media_type_matches(
                headers,
                b"content-type",
                b"application/oblivious-dns-message",
            )
    }

    fn doh_get_request_path(path: &[u8]) -> bool {
        let Some(query_offset) = doh_endpoint_path_query_offset(path) else {
            return false;
        };
        let query = &path[query_offset + 1..];
        query.split(|byte| *byte == b'&').any(|part| {
            part.get(..4)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"dns="))
                && doh_base64url_query_value(&part[4..])
        })
    }

    fn doh_endpoint_path(path: &[u8]) -> bool {
        matches!(
            path.get(b"/dns-query".len()),
            None | Some(b'?') | Some(b'/')
        ) && path.starts_with(b"/dns-query")
    }

    fn doh_endpoint_path_query_offset(path: &[u8]) -> Option<usize> {
        if !doh_endpoint_path(path) {
            return None;
        }
        path.iter().position(|byte| *byte == b'?')
    }

    fn doh_base64url_query_value(value: &[u8]) -> bool {
        !value.is_empty()
            && value.len() <= 512
            && value
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'='))
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
        if cri_grpc_payload(payload) {
            return Some(AgentPacketFlowApplication::Cri);
        }
        if containerd_grpc_payload(payload) {
            return Some(AgentPacketFlowApplication::Containerd);
        }
        if etcd_grpc_payload(payload) {
            return Some(AgentPacketFlowApplication::Etcd);
        }
        if contains_ascii_case_insensitive(payload, b"\r\nx-opensearch-") {
            return Some(AgentPacketFlowApplication::OpenSearch);
        }
        if contains_ascii_case_insensitive(payload, b"\r\nx-solr-") {
            return Some(AgentPacketFlowApplication::Solr);
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

    fn ipars_control_plane_http_api_path(path: &[u8]) -> bool {
        path_starts_with_api_prefix(path, b"/v1/join")
            || path_starts_with_api_prefix(path, b"/v1/heartbeat")
            || path_starts_with_api_prefix(path, b"/v1/policy")
            || path_starts_with_api_prefix(path, b"/v1/tokens/revoke")
            || (path.starts_with(b"/v1/nodes/") && path_contains_any(path, &[b"/wireguard-key"]))
            || (path.starts_with(b"/v1/peers/") && path.len() > b"/v1/peers/".len())
            || (path.starts_with(b"/v1/paths/")
                && path.len() > b"/v1/paths/".len()
                && !path_starts_with_api_prefix(path, b"/v1/paths/negotiate"))
    }

    fn ipars_signal_http_api_path(path: &[u8]) -> bool {
        path_starts_with_api_prefix(path, b"/v1/paths/negotiate")
            || path.starts_with(b"/v1/hole-punch/")
            || (path.starts_with(b"/v1/nodes/") && path.len() > b"/v1/nodes/".len())
    }

    fn ipars_agent_http_api_path(path: &[u8]) -> bool {
        path_starts_with_api_prefix(path, b"/v1/path-events")
            || path_starts_with_api_prefix(path, b"/v1/path-probe")
            || path_starts_with_api_prefix(path, b"/v1/stun-probe")
            || path_starts_with_api_prefix(path, b"/v1/nat-classification")
            || path_starts_with_api_prefix(path, b"/v1/peer-activity")
            || path_starts_with_api_prefix(path, b"/v1/packet-flow")
            || path_starts_with_api_prefix(path, b"/v1/wireguard-key/rotate")
            || path == b"/v1/peers"
            || path == b"/v1/paths"
    }

    fn ipars_relay_http_api_path(path: &[u8]) -> bool {
        path_starts_with_api_prefix(path, b"/v1/sessions")
    }

    fn opensearch_http_api_path(path: &[u8]) -> bool {
        path_starts_with_api_prefix(path, b"/_plugins")
            || path_starts_with_api_prefix(path, b"/_opendistro")
    }

    fn solr_http_api_path(path: &[u8]) -> bool {
        path_starts_with_api_prefix(path, b"/solr")
            || path_starts_with_api_prefix(path, b"/api/collections")
            || path_starts_with_api_prefix(path, b"/api/cores")
    }

    fn git_http_api_path(path: &[u8]) -> bool {
        git_http_info_refs_path(path) || git_http_rpc_path(path)
    }

    fn git_http_info_refs_path(path: &[u8]) -> bool {
        let Some(query_start) = path.iter().position(|byte| *byte == b'?') else {
            return false;
        };
        let resource = &path[..query_start];
        resource.ends_with(b".git/info/refs")
            && git_http_query_has_service(path.get(query_start + 1..).unwrap_or_default())
    }

    fn git_http_rpc_path(path: &[u8]) -> bool {
        let resource = http_path_without_query(path);
        let marker = b".git/";
        let Some(mut offset) = find_subslice(resource, marker).map(|index| index + marker.len())
        else {
            return false;
        };

        loop {
            let tail = &resource[offset..];
            if GIT_SMART_SERVICES
                .iter()
                .any(|service| git_http_service_path_tail(tail, service))
            {
                return true;
            }
            let Some(next_marker) = find_subslice(tail, marker) else {
                return false;
            };
            offset += next_marker + marker.len();
        }
    }

    fn git_http_query_has_service(mut query: &[u8]) -> bool {
        loop {
            let delimiter = query.iter().position(|byte| *byte == b'&');
            let (param, tail) = match delimiter {
                Some(index) => (&query[..index], &query[index + 1..]),
                None => (query, &[][..]),
            };
            if param
                .strip_prefix(b"service=")
                .is_some_and(git_service_name)
            {
                return true;
            }
            if tail.is_empty() {
                return false;
            }
            query = tail;
        }
    }

    fn git_http_service_path_tail(tail: &[u8], service: &[u8]) -> bool {
        tail.get(..service.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(service))
            && matches!(tail.get(service.len()), None | Some(b'/'))
    }

    fn git_service_name(value: &[u8]) -> bool {
        GIT_SMART_SERVICES
            .iter()
            .any(|service| value.eq_ignore_ascii_case(service))
    }

    fn http_path_without_query(path: &[u8]) -> &[u8] {
        match path.iter().position(|byte| *byte == b'?') {
            Some(query_start) => &path[..query_start],
            None => path,
        }
    }

    fn cri_grpc_path(path: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 8] = [
            b"/runtime.v1.RuntimeService/",
            b"/runtime.v1.ImageService/",
            b"/runtime.v1alpha2.RuntimeService/",
            b"/runtime.v1alpha2.ImageService/",
            b"/containerd.services.runtime.v1.Runtime/",
            b"/containerd.services.runtime.v2.Task/",
            b"/containerd.services.sandbox.v1.Sandbox/",
            b"/containerd.services.sandbox.v1.Controller/",
        ];

        path_starts_with_any(path, &PREFIXES)
    }

    fn cri_grpc_payload(payload: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 8] = [
            b"/runtime.v1.RuntimeService/",
            b"/runtime.v1.ImageService/",
            b"/runtime.v1alpha2.RuntimeService/",
            b"/runtime.v1alpha2.ImageService/",
            b"/containerd.services.runtime.v1.Runtime/",
            b"/containerd.services.runtime.v2.Task/",
            b"/containerd.services.sandbox.v1.Sandbox/",
            b"/containerd.services.sandbox.v1.Controller/",
        ];

        PREFIXES
            .iter()
            .any(|prefix| contains_ascii_case_insensitive(payload, prefix))
    }

    fn containerd_grpc_path(path: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 20] = [
            b"/containerd.services.containers.v1.Containers/",
            b"/containerd.services.content.v1.Content/",
            b"/containerd.services.diff.v1.Diff/",
            b"/containerd.services.events.v1.Events/",
            b"/containerd.services.images.v1.Images/",
            b"/containerd.services.introspection.v1.Introspection/",
            b"/containerd.services.leases.v1.Leases/",
            b"/containerd.services.namespaces.v1.Namespaces/",
            b"/containerd.services.snapshots.v1.Snapshots/",
            b"/containerd.services.tasks.v1.Tasks/",
            b"/containerd.services.version.v1.Version/",
            b"/containerd.services.transfer.v1.Transfer/",
            b"/containerd.types.transfer.Registry/",
            b"/containerd.services.gc.v1.GC/",
            b"/containerd.services.healthcheck.v1.Health/",
            b"/containerd.services.sandbox.v1.Store/",
            b"/containerd.services.streaming.v1.Streaming/",
            b"/containerd.services.ttrpc.v1.TTRPC/",
            b"/containerd.services.plugins.v1.Plugins/",
            b"/containerd.services.opt.v1.Opt/",
        ];

        path_starts_with_any(path, &PREFIXES)
    }

    fn containerd_grpc_payload(payload: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 20] = [
            b"/containerd.services.containers.v1.Containers/",
            b"/containerd.services.content.v1.Content/",
            b"/containerd.services.diff.v1.Diff/",
            b"/containerd.services.events.v1.Events/",
            b"/containerd.services.images.v1.Images/",
            b"/containerd.services.introspection.v1.Introspection/",
            b"/containerd.services.leases.v1.Leases/",
            b"/containerd.services.namespaces.v1.Namespaces/",
            b"/containerd.services.snapshots.v1.Snapshots/",
            b"/containerd.services.tasks.v1.Tasks/",
            b"/containerd.services.version.v1.Version/",
            b"/containerd.services.transfer.v1.Transfer/",
            b"/containerd.types.transfer.Registry/",
            b"/containerd.services.gc.v1.GC/",
            b"/containerd.services.healthcheck.v1.Health/",
            b"/containerd.services.sandbox.v1.Store/",
            b"/containerd.services.streaming.v1.Streaming/",
            b"/containerd.services.ttrpc.v1.TTRPC/",
            b"/containerd.services.plugins.v1.Plugins/",
            b"/containerd.services.opt.v1.Opt/",
        ];

        PREFIXES
            .iter()
            .any(|prefix| contains_ascii_case_insensitive(payload, prefix))
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

    fn kubernetes_http_api_path(path: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 4] = [b"/api/v1", b"/apis", b"/openapi/v2", b"/openapi/v3"];

        PREFIXES
            .iter()
            .any(|prefix| path_starts_with_api_prefix(path, prefix))
    }

    fn kubelet_http_api_path(path: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 10] = [
            b"/pods",
            b"/runningpods",
            b"/stats",
            b"/metrics/cadvisor",
            b"/metrics/resource",
            b"/metrics/probes",
            b"/metrics/slis",
            b"/configz",
            b"/checkpoint",
            b"/containerLogs",
        ];

        PREFIXES
            .iter()
            .any(|prefix| path_starts_with_api_prefix(path, prefix))
    }

    fn docker_http_api_path(path: &[u8]) -> bool {
        docker_http_api_path_without_version(path)
            || docker_api_versioned_path(path)
                .map(docker_http_api_path_without_version)
                .unwrap_or(false)
    }

    fn docker_api_versioned_path(path: &[u8]) -> Option<&[u8]> {
        let mut offset = 0;
        if path.get(offset) != Some(&b'/') || path.get(offset + 1) != Some(&b'v') {
            return None;
        }
        offset += 2;
        let first_digit = offset;
        while path.get(offset).is_some_and(u8::is_ascii_digit) {
            offset += 1;
        }
        if offset == first_digit {
            return None;
        }
        let mut has_dot = false;
        while path.get(offset) == Some(&b'.') {
            has_dot = true;
            offset += 1;
            let component_start = offset;
            while path.get(offset).is_some_and(u8::is_ascii_digit) {
                offset += 1;
            }
            if offset == component_start {
                return None;
            }
        }
        if !has_dot {
            return None;
        }
        (path.get(offset) == Some(&b'/')).then_some(&path[offset..])
    }

    fn docker_http_api_path_without_version(path: &[u8]) -> bool {
        const PREFIXES: [&[u8]; 22] = [
            b"/_ping",
            b"/auth",
            b"/build",
            b"/commit",
            b"/configs",
            b"/containers",
            b"/distribution",
            b"/events",
            b"/exec",
            b"/images",
            b"/info",
            b"/networks",
            b"/nodes",
            b"/plugins",
            b"/secrets",
            b"/services",
            b"/session",
            b"/swarm",
            b"/system",
            b"/tasks",
            b"/version",
            b"/volumes",
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
        let message_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if !(12..=4096).contains(&message_len) {
            return false;
        }
        let available = payload.len() - 2;
        let truncated = available < message_len;
        if truncated && payload.len() < PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES {
            return false;
        }
        let frame_len = available.min(message_len);
        dns_message_payload_with_truncation(&payload[2..2 + frame_len], truncated)
    }

    fn dns_message_payload(payload: &[u8]) -> bool {
        dns_message_payload_with_truncation(
            payload,
            payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES,
        )
    }

    fn dns_message_payload_with_truncation(payload: &[u8], allow_truncated: bool) -> bool {
        if payload.len() < 12 {
            return false;
        }
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let opcode = (flags >> 11) & 0x0f;
        let is_response = flags & 0x8000 != 0;
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;
        let nscount = u16::from_be_bytes([payload[8], payload[9]]) as usize;
        let arcount = u16::from_be_bytes([payload[10], payload[11]]) as usize;
        if opcode > 5 || flags & 0x0040 != 0 {
            return false;
        }
        if qdcount > 0 {
            return match dns_question_payload(payload, qdcount, allow_truncated) {
                Some(DnsSectionParse::Complete(question_end)) => {
                    if opcode == 0 && !is_response && (ancount > 0 || nscount > 0) {
                        return false;
                    }
                    let rr_count = if opcode == 0 && !is_response {
                        arcount
                    } else {
                        ancount + nscount + arcount
                    };
                    rr_count == 0
                        || dns_resource_records_payload(
                            payload,
                            question_end,
                            rr_count,
                            allow_truncated,
                        )
                }
                Some(DnsSectionParse::Truncated) => true,
                None => false,
            };
        }
        is_response
            && dns_resource_records_payload(
                payload,
                12,
                ancount + nscount + arcount,
                allow_truncated,
            )
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

    fn dns_question_payload(
        payload: &[u8],
        qdcount: u16,
        allow_truncated: bool,
    ) -> Option<DnsSectionParse> {
        if qdcount > DNS_MAX_QUESTION_COUNT {
            return None;
        }
        let mut offset = 12_usize;
        for question_index in 0..qdcount {
            let Some(name_end) = dns_name_payload(payload, offset) else {
                return (question_index > 0 && allow_truncated)
                    .then_some(DnsSectionParse::Truncated);
            };
            offset = name_end;
            let Some(question_end) = offset.checked_add(4) else {
                return None;
            };
            let Some(question) = payload.get(offset..question_end) else {
                return (question_index > 0 && allow_truncated)
                    .then_some(DnsSectionParse::Truncated);
            };
            let qtype = u16::from_be_bytes([question[0], question[1]]);
            let qclass = u16::from_be_bytes([question[2], question[3]]);
            if qtype == 0 || qclass == 0 {
                return None;
            }
            offset = question_end;
        }
        Some(DnsSectionParse::Complete(offset))
    }

    fn dns_resource_records_payload(
        payload: &[u8],
        mut offset: usize,
        rr_count: usize,
        allow_truncated: bool,
    ) -> bool {
        if !(1..=4096).contains(&rr_count) {
            return false;
        }
        for rr_index in 0..rr_count {
            if offset >= payload.len() {
                return rr_index > 0 && allow_truncated;
            }
            match dns_resource_record_payload(payload, offset, allow_truncated) {
                Some(DnsSectionParse::Complete(rr_end)) => offset = rr_end,
                Some(DnsSectionParse::Truncated) => return allow_truncated,
                None => return false,
            }
        }
        true
    }

    fn dns_resource_record_payload(
        payload: &[u8],
        mut offset: usize,
        allow_truncated: bool,
    ) -> Option<DnsSectionParse> {
        let Some(name) = dns_resource_record_name_payload(payload, offset) else {
            return None;
        };
        offset = name.end;
        let Some(rr_header_end) = offset.checked_add(10) else {
            return None;
        };
        let Some(rr_header) = payload.get(offset..rr_header_end) else {
            return None;
        };
        let rr_type = u16::from_be_bytes([rr_header[0], rr_header[1]]);
        let rr_class = u16::from_be_bytes([rr_header[2], rr_header[3]]);
        let rr_ttl = u32::from_be_bytes([rr_header[4], rr_header[5], rr_header[6], rr_header[7]]);
        let rdlength = u16::from_be_bytes([rr_header[8], rr_header[9]]) as usize;
        let Some(rr_end) = rr_header_end.checked_add(rdlength) else {
            return None;
        };
        if rr_type == 0
            || !dns_resource_record_header_payload(rr_type, rr_class, rr_ttl, name.labels)
            || !dns_resource_record_rdata_length_payload(rr_type, rdlength)
        {
            return None;
        }
        if rr_end > payload.len() {
            return allow_truncated.then_some(DnsSectionParse::Truncated);
        }
        if !dns_resource_record_rdata_payload(payload, rr_header_end, rr_end, rr_type) {
            return None;
        }
        Some(DnsSectionParse::Complete(rr_end))
    }

    fn dns_resource_record_header_payload(
        rr_type: u16,
        rr_class: u16,
        rr_ttl: u32,
        owner_labels: usize,
    ) -> bool {
        if rr_type == 41 {
            let edns_version = ((rr_ttl >> 16) & 0xff) as u8;
            let edns_flags = (rr_ttl & 0xffff) as u16;
            return owner_labels == 0
                && dns_resource_record_class_payload(rr_type, rr_class)
                && edns_version == 0
                && edns_flags & !0x8000 == 0;
        }
        dns_resource_record_class_payload(rr_type, rr_class)
    }

    fn dns_resource_record_rdata_length_payload(rr_type: u16, rdlength: usize) -> bool {
        match rr_type {
            1 => rdlength == 4,
            28 => rdlength == 16,
            _ => true,
        }
    }

    fn dns_resource_record_rdata_payload(
        payload: &[u8],
        rdata_offset: usize,
        rdata_end: usize,
        rr_type: u16,
    ) -> bool {
        match rr_type {
            2 | 5 | 7 | 8 | 9 | 12 | 39 => {
                dns_name_payload_with_root(payload, rdata_offset, true) == Some(rdata_end)
            }
            6 => {
                let Some(rname_offset) = dns_name_payload_with_root(payload, rdata_offset, true)
                else {
                    return false;
                };
                dns_name_payload_with_root(payload, rname_offset, true)
                    .and_then(|tail_offset| tail_offset.checked_add(20))
                    == Some(rdata_end)
            }
            13 => dns_character_strings_payload(payload, rdata_offset, rdata_end, 2, Some(2)),
            14 | 17 => dns_two_names_rdata_payload(payload, rdata_offset, rdata_end),
            15 => {
                rdata_offset
                    .checked_add(2)
                    .and_then(|name_offset| dns_name_payload_with_root(payload, name_offset, true))
                    == Some(rdata_end)
            }
            16 => dns_character_strings_payload(payload, rdata_offset, rdata_end, 1, None),
            18 | 21 | 36 => dns_preference_name_rdata_payload(payload, rdata_offset, rdata_end),
            26 => dns_preference_two_names_rdata_payload(payload, rdata_offset, rdata_end),
            33 => {
                rdata_offset
                    .checked_add(6)
                    .and_then(|name_offset| dns_name_payload_with_root(payload, name_offset, true))
                    == Some(rdata_end)
            }
            35 => dns_naptr_rdata_payload(payload, rdata_offset, rdata_end),
            43 => dns_ds_rdata_payload(payload, rdata_offset, rdata_end),
            44 => dns_sshfp_rdata_payload(payload, rdata_offset, rdata_end),
            46 => dns_rrsig_rdata_payload(payload, rdata_offset, rdata_end),
            47 => dns_nsec_rdata_payload(payload, rdata_offset, rdata_end),
            48 => dns_dnskey_rdata_payload(payload, rdata_offset, rdata_end),
            50 => dns_nsec3_rdata_payload(payload, rdata_offset, rdata_end),
            51 => dns_nsec3param_rdata_payload(payload, rdata_offset, rdata_end),
            52 | 53 => dns_certificate_association_rdata_payload(payload, rdata_offset, rdata_end),
            64 | 65 => dns_svcb_rdata_payload(payload, rdata_offset, rdata_end),
            256 => dns_uri_rdata_payload(payload, rdata_offset, rdata_end),
            257 => dns_caa_rdata_payload(payload, rdata_offset, rdata_end),
            _ => true,
        }
    }

    fn dns_two_names_rdata_payload(payload: &[u8], rdata_offset: usize, rdata_end: usize) -> bool {
        dns_name_payload_with_root(payload, rdata_offset, true)
            .and_then(|second_offset| dns_name_payload_with_root(payload, second_offset, true))
            == Some(rdata_end)
    }

    fn dns_preference_name_rdata_payload(
        payload: &[u8],
        rdata_offset: usize,
        rdata_end: usize,
    ) -> bool {
        rdata_offset
            .checked_add(2)
            .and_then(|name_offset| dns_name_payload_with_root(payload, name_offset, true))
            == Some(rdata_end)
    }

    fn dns_preference_two_names_rdata_payload(
        payload: &[u8],
        rdata_offset: usize,
        rdata_end: usize,
    ) -> bool {
        rdata_offset.checked_add(2).is_some_and(|first_offset| {
            dns_two_names_rdata_payload(payload, first_offset, rdata_end)
        })
    }

    fn dns_character_strings_payload(
        payload: &[u8],
        mut offset: usize,
        end: usize,
        min_count: usize,
        max_count: Option<usize>,
    ) -> bool {
        let mut count = 0_usize;
        while offset < end {
            let Some(next_offset) = dns_character_string_payload(payload, offset, end) else {
                return false;
            };
            count += 1;
            if max_count.is_some_and(|max| count > max) {
                return false;
            }
            offset = next_offset;
        }
        count >= min_count && max_count.is_none_or(|max| count <= max)
    }

    fn dns_character_string_payload(payload: &[u8], offset: usize, end: usize) -> Option<usize> {
        let len = *payload.get(offset)? as usize;
        let value_offset = offset.checked_add(1)?;
        let next_offset = value_offset.checked_add(len)?;
        (next_offset <= end).then_some(next_offset)
    }

    fn dns_naptr_rdata_payload(payload: &[u8], rdata_offset: usize, rdata_end: usize) -> bool {
        let Some(mut offset) = rdata_offset.checked_add(4) else {
            return false;
        };
        if offset > rdata_end {
            return false;
        }
        for _ in 0..3 {
            let Some(next_offset) = dns_character_string_payload(payload, offset, rdata_end) else {
                return false;
            };
            offset = next_offset;
        }
        dns_name_payload_with_root(payload, offset, true) == Some(rdata_end)
    }

    fn dns_caa_rdata_payload(payload: &[u8], rdata_offset: usize, rdata_end: usize) -> bool {
        let Some(tag_len_offset) = rdata_offset.checked_add(1) else {
            return false;
        };
        if tag_len_offset >= rdata_end {
            return false;
        }
        let tag_len = payload[tag_len_offset] as usize;
        let Some(tag_offset) = tag_len_offset.checked_add(1) else {
            return false;
        };
        let Some(value_offset) = tag_offset.checked_add(tag_len) else {
            return false;
        };
        value_offset <= rdata_end
            && dns_caa_tag_payload(payload.get(tag_offset..value_offset).unwrap_or_default())
    }

    fn dns_caa_tag_payload(tag: &[u8]) -> bool {
        (1..=15).contains(&tag.len()) && tag.iter().all(u8::is_ascii_alphanumeric)
    }

    fn dns_ds_rdata_payload(payload: &[u8], rdata_offset: usize, rdata_end: usize) -> bool {
        let Some(rdata_len) = rdata_end.checked_sub(rdata_offset) else {
            return false;
        };
        if rdata_len < 5 {
            return false;
        }
        let Some(&algorithm) = payload.get(rdata_offset + 2) else {
            return false;
        };
        let Some(&digest_type) = payload.get(rdata_offset + 3) else {
            return false;
        };
        let digest_len = rdata_len - 4;
        algorithm != 0
            && digest_type != 0
            && match digest_type {
                1 => digest_len == 20,
                2 | 3 => digest_len == 32,
                4 => digest_len == 48,
                _ => digest_len > 0,
            }
    }

    fn dns_rrsig_rdata_payload(payload: &[u8], rdata_offset: usize, rdata_end: usize) -> bool {
        let Some(fixed_end) = rdata_offset.checked_add(18) else {
            return false;
        };
        if fixed_end >= rdata_end {
            return false;
        }
        let type_covered = u16::from_be_bytes([payload[rdata_offset], payload[rdata_offset + 1]]);
        let algorithm = payload[rdata_offset + 2];
        let labels = payload[rdata_offset + 3];
        type_covered != 0
            && algorithm != 0
            && labels <= 127
            && dns_name_payload_with_root(payload, fixed_end, true)
                .is_some_and(|signature_offset| signature_offset < rdata_end)
    }

    fn dns_dnskey_rdata_payload(payload: &[u8], rdata_offset: usize, rdata_end: usize) -> bool {
        let Some(rdata_len) = rdata_end.checked_sub(rdata_offset) else {
            return false;
        };
        if rdata_len < 5 {
            return false;
        }
        payload.get(rdata_offset + 2) == Some(&3)
            && payload
                .get(rdata_offset + 3)
                .is_some_and(|algorithm| *algorithm != 0)
    }

    fn dns_nsec_rdata_payload(payload: &[u8], rdata_offset: usize, rdata_end: usize) -> bool {
        dns_name_payload_with_root(payload, rdata_offset, true).is_some_and(|bitmap_offset| {
            dns_type_bit_maps_payload(payload, bitmap_offset, rdata_end)
        })
    }

    fn dns_nsec3_rdata_payload(payload: &[u8], rdata_offset: usize, rdata_end: usize) -> bool {
        let Some(salt_len_offset) = rdata_offset.checked_add(4) else {
            return false;
        };
        if salt_len_offset >= rdata_end {
            return false;
        }
        let algorithm = payload[rdata_offset];
        let flags = payload[rdata_offset + 1];
        let salt_len = payload[salt_len_offset] as usize;
        let Some(salt_offset) = salt_len_offset.checked_add(1) else {
            return false;
        };
        let Some(hash_len_offset) = salt_offset.checked_add(salt_len) else {
            return false;
        };
        if hash_len_offset >= rdata_end {
            return false;
        }
        let hash_len = payload[hash_len_offset] as usize;
        let Some(hash_offset) = hash_len_offset.checked_add(1) else {
            return false;
        };
        let Some(bitmap_offset) = hash_offset.checked_add(hash_len) else {
            return false;
        };
        algorithm != 0
            && flags & !0x01 == 0
            && hash_len > 0
            && bitmap_offset < rdata_end
            && dns_type_bit_maps_payload(payload, bitmap_offset, rdata_end)
    }

    fn dns_nsec3param_rdata_payload(payload: &[u8], rdata_offset: usize, rdata_end: usize) -> bool {
        let Some(salt_len_offset) = rdata_offset.checked_add(4) else {
            return false;
        };
        if salt_len_offset >= rdata_end {
            return false;
        }
        let algorithm = payload[rdata_offset];
        let flags = payload[rdata_offset + 1];
        let salt_len = payload[salt_len_offset] as usize;
        let Some(salt_offset) = salt_len_offset.checked_add(1) else {
            return false;
        };
        algorithm != 0 && flags & !0x01 == 0 && salt_offset.checked_add(salt_len) == Some(rdata_end)
    }

    fn dns_type_bit_maps_payload(payload: &[u8], mut offset: usize, end: usize) -> bool {
        let mut previous_window = None;
        let mut window_count = 0_usize;
        while offset < end {
            let Some(&window) = payload.get(offset) else {
                return false;
            };
            let Some(&bitmap_len) = payload.get(offset + 1) else {
                return false;
            };
            let bitmap_len = bitmap_len as usize;
            if !(1..=32).contains(&bitmap_len)
                || previous_window.is_some_and(|previous| window <= previous)
            {
                return false;
            }
            let Some(bitmap_offset) = offset.checked_add(2) else {
                return false;
            };
            let Some(next_offset) = bitmap_offset.checked_add(bitmap_len) else {
                return false;
            };
            if next_offset > end || payload.get(next_offset - 1) == Some(&0) {
                return false;
            }
            previous_window = Some(window);
            window_count += 1;
            offset = next_offset;
        }
        window_count > 0
    }

    fn dns_sshfp_rdata_payload(payload: &[u8], rdata_offset: usize, rdata_end: usize) -> bool {
        let Some(rdata_len) = rdata_end.checked_sub(rdata_offset) else {
            return false;
        };
        if rdata_len < 3 {
            return false;
        }
        let algorithm = payload[rdata_offset];
        let fingerprint_type = payload[rdata_offset + 1];
        let fingerprint_len = rdata_len - 2;
        algorithm != 0
            && fingerprint_type != 0
            && match fingerprint_type {
                1 => fingerprint_len == 20,
                2 => fingerprint_len == 32,
                _ => fingerprint_len > 0,
            }
    }

    fn dns_certificate_association_rdata_payload(
        payload: &[u8],
        rdata_offset: usize,
        rdata_end: usize,
    ) -> bool {
        let Some(rdata_len) = rdata_end.checked_sub(rdata_offset) else {
            return false;
        };
        if rdata_len < 4 {
            return false;
        }
        let cert_usage = payload[rdata_offset];
        let selector = payload[rdata_offset + 1];
        let matching_type = payload[rdata_offset + 2];
        let association_len = rdata_len - 3;
        cert_usage <= 3
            && selector <= 1
            && matching_type <= 2
            && match matching_type {
                0 => association_len > 0,
                1 => association_len == 32,
                2 => association_len == 64,
                _ => false,
            }
    }

    fn dns_uri_rdata_payload(payload: &[u8], rdata_offset: usize, rdata_end: usize) -> bool {
        let Some(target_offset) = rdata_offset.checked_add(4) else {
            return false;
        };
        target_offset < rdata_end
            && payload[target_offset..rdata_end]
                .iter()
                .all(|byte| byte.is_ascii_graphic())
    }

    fn dns_svcb_rdata_payload(payload: &[u8], rdata_offset: usize, rdata_end: usize) -> bool {
        let Some(target_offset) = rdata_offset.checked_add(2) else {
            return false;
        };
        if target_offset >= rdata_end {
            return false;
        }
        let priority = u16::from_be_bytes([payload[rdata_offset], payload[rdata_offset + 1]]);
        let Some(params_offset) = dns_name_payload_with_root(payload, target_offset, true) else {
            return false;
        };
        if priority == 0 {
            return params_offset == rdata_end;
        }
        dns_svcb_params_payload(payload, params_offset, rdata_end)
    }

    fn dns_svcb_params_payload(payload: &[u8], mut offset: usize, end: usize) -> bool {
        let mut previous_key = None;
        while offset < end {
            let Some(header_end) = offset.checked_add(4) else {
                return false;
            };
            let Some(header) = payload.get(offset..header_end) else {
                return false;
            };
            let key = u16::from_be_bytes([header[0], header[1]]);
            let value_len = u16::from_be_bytes([header[2], header[3]]) as usize;
            if previous_key.is_some_and(|previous| key <= previous) {
                return false;
            }
            let Some(value_end) = header_end.checked_add(value_len) else {
                return false;
            };
            if value_end > end || !dns_svcb_param_value_payload(payload, header_end, value_end, key)
            {
                return false;
            }
            previous_key = Some(key);
            offset = value_end;
        }
        offset == end
    }

    fn dns_svcb_param_value_payload(
        payload: &[u8],
        value_offset: usize,
        value_end: usize,
        key: u16,
    ) -> bool {
        let value_len = value_end - value_offset;
        match key {
            0 => dns_svcb_mandatory_payload(payload, value_offset, value_end),
            1 => dns_svcb_alpn_payload(payload, value_offset, value_end),
            2 => value_len == 0,
            3 => {
                value_len == 2
                    && u16::from_be_bytes([payload[value_offset], payload[value_offset + 1]]) != 0
            }
            4 => value_len > 0 && value_len.is_multiple_of(4),
            5 => value_len > 0,
            6 => value_len > 0 && value_len.is_multiple_of(16),
            7 => {
                value_len > 0
                    && payload[value_offset..value_end]
                        .iter()
                        .all(|byte| byte.is_ascii_graphic())
            }
            _ => true,
        }
    }

    fn dns_svcb_mandatory_payload(payload: &[u8], mut offset: usize, end: usize) -> bool {
        let Some(value_len) = end.checked_sub(offset) else {
            return false;
        };
        if value_len == 0 || value_len % 2 != 0 {
            return false;
        }
        let mut previous_key = None;
        while offset < end {
            let key = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            if key == 0 || previous_key.is_some_and(|previous| key <= previous) {
                return false;
            }
            previous_key = Some(key);
            offset += 2;
        }
        true
    }

    fn dns_svcb_alpn_payload(payload: &[u8], mut offset: usize, end: usize) -> bool {
        let mut alpn_count = 0_usize;
        while offset < end {
            let Some(&len) = payload.get(offset) else {
                return false;
            };
            if len == 0 {
                return false;
            }
            let Some(value_offset) = offset.checked_add(1) else {
                return false;
            };
            let Some(next_offset) = value_offset.checked_add(len as usize) else {
                return false;
            };
            if next_offset > end {
                return false;
            }
            alpn_count += 1;
            offset = next_offset;
        }
        alpn_count > 0
    }

    fn dns_resource_record_class_payload(rr_type: u16, rr_class: u16) -> bool {
        if rr_type == 41 {
            return (512..=4096).contains(&rr_class);
        }
        let class = rr_class & 0x7fff;
        matches!(class, 1..=4 | 254 | 255) && (rr_class & 0x8000 == 0 || class == 1)
    }

    fn dns_name_payload(payload: &[u8], offset: usize) -> Option<usize> {
        dns_name_payload_with_root(payload, offset, false)
    }

    fn dns_resource_record_name_payload(payload: &[u8], offset: usize) -> Option<DnsNameParse> {
        dns_name_payload_inner(payload, offset, 0)
    }

    fn dns_name_payload_with_root(
        payload: &[u8],
        offset: usize,
        allow_root: bool,
    ) -> Option<usize> {
        let parsed = dns_name_payload_inner(payload, offset, 0)?;
        (allow_root || parsed.labels > 0).then_some(parsed.end)
    }

    fn dns_name_payload_inner(
        payload: &[u8],
        mut offset: usize,
        pointer_depth: usize,
    ) -> Option<DnsNameParse> {
        if pointer_depth > DNS_MAX_NAME_POINTER_DEPTH {
            return None;
        }
        let mut labels = 0_usize;
        let mut name_len = 0_usize;
        loop {
            let Some(&len) = payload.get(offset) else {
                return None;
            };
            if len & 0xc0 == 0xc0 {
                let pointer = read_u16_be(payload, offset)?;
                let pointer_offset = (pointer & 0x3fff) as usize;
                if pointer_offset >= offset {
                    return None;
                }
                let target = dns_name_payload_inner(payload, pointer_offset, pointer_depth + 1)?;
                labels += target.labels;
                name_len += target.name_len;
                if labels > 32 || name_len > 255 {
                    return None;
                }
                offset = offset.checked_add(2)?;
                break;
            }
            if len & 0xc0 != 0 {
                return None;
            }
            offset += 1;
            if len == 0 {
                break;
            }
            if len > 63 {
                return None;
            }
            let len = len as usize;
            let Some(label_end) = offset.checked_add(len) else {
                return None;
            };
            let Some(label) = payload.get(offset..label_end) else {
                return None;
            };
            if !label
                .iter()
                .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return None;
            }
            labels += 1;
            name_len += len + 1;
            if labels > 32 || name_len > 255 {
                return None;
            }
            offset = label_end;
        }
        Some(DnsNameParse {
            end: offset,
            labels,
            name_len,
        })
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
        if tls_sni_hostname_has_label_prefix(hostname, b"ipars-control-plane")
            || tls_sni_hostname_has_label_prefix(hostname, b"ipars-control")
            || tls_sni_hostname_has_label_prefix(hostname, b"control-plane")
        {
            return Some(AgentPacketFlowApplication::IparsControlPlane);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"ipars-signal")
            || tls_sni_hostname_has_label_prefix(hostname, b"signal")
        {
            return Some(AgentPacketFlowApplication::IparsSignal);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"ipars-agent")
            || tls_sni_hostname_has_label_prefix(hostname, b"agent")
        {
            return Some(AgentPacketFlowApplication::IparsAgent);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"ipars-relay")
            || tls_sni_hostname_has_label_prefix(hostname, b"relay")
        {
            return Some(AgentPacketFlowApplication::IparsRelay);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"ipars-stun")
            || tls_sni_hostname_has_label_prefix(hostname, b"stun")
        {
            return Some(AgentPacketFlowApplication::Stun);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"dns")
            || tls_sni_hostname_has_label_prefix(hostname, b"doh")
        {
            return Some(AgentPacketFlowApplication::Dns);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"turn")
            || tls_sni_hostname_has_label_prefix(hostname, b"turns")
            || tls_sni_hostname_has_label_prefix(hostname, b"turnserver")
        {
            return Some(AgentPacketFlowApplication::Turn);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"coap")
            || tls_sni_hostname_has_label_prefix(hostname, b"coaps")
        {
            return Some(AgentPacketFlowApplication::Coap);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"kubernetes")
            || tls_sni_hostname_has_label_prefix(hostname, b"kube-apiserver")
            || tls_sni_hostname_has_label_prefix(hostname, b"kube-api")
        {
            return Some(AgentPacketFlowApplication::KubernetesApi);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"kubelet") {
            return Some(AgentPacketFlowApplication::Kubelet);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"docker")
            || tls_sni_hostname_has_label_prefix(hostname, b"dockerd")
            || tls_sni_hostname_has_label_prefix(hostname, b"docker-api")
        {
            return Some(AgentPacketFlowApplication::DockerApi);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"cri")
            || tls_sni_hostname_has_label_prefix(hostname, b"crio")
            || tls_sni_hostname_has_label_prefix(hostname, b"cri-o")
        {
            return Some(AgentPacketFlowApplication::Cri);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"containerd") {
            return Some(AgentPacketFlowApplication::Containerd);
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
        if tls_sni_hostname_has_label_prefix(hostname, b"opensearch") {
            return Some(AgentPacketFlowApplication::OpenSearch);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"solr") {
            return Some(AgentPacketFlowApplication::Solr);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"git")
            || tls_sni_hostname_has_label_prefix(hostname, b"gitea")
            || tls_sni_hostname_has_label_prefix(hostname, b"gitlab")
            || tls_sni_hostname_has_label_prefix(hostname, b"github")
            || tls_sni_hostname_has_label_prefix(hostname, b"bitbucket")
        {
            return Some(AgentPacketFlowApplication::Git);
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
        if tls_sni_hostname_has_label_prefix(hostname, b"openvpn")
            || tls_sni_hostname_has_label_prefix(hostname, b"ovpn")
        {
            return Some(AgentPacketFlowApplication::OpenVpn);
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
        if tls_sni_hostname_has_label_prefix(hostname, b"vnc")
            || tls_sni_hostname_has_label_prefix(hostname, b"rfb")
        {
            return Some(AgentPacketFlowApplication::Vnc);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"ftp")
            || tls_sni_hostname_has_label_prefix(hostname, b"ftps")
        {
            return Some(AgentPacketFlowApplication::Ftp);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"rsync")
            || tls_sni_hostname_has_label_prefix(hostname, b"rsyncd")
        {
            return Some(AgentPacketFlowApplication::Rsync);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"smtp")
            || tls_sni_hostname_has_label_prefix(hostname, b"mx")
        {
            return Some(AgentPacketFlowApplication::Smtp);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"imap") {
            return Some(AgentPacketFlowApplication::Imap);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"pop3")
            || tls_sni_hostname_has_label_prefix(hostname, b"pop")
        {
            return Some(AgentPacketFlowApplication::Pop3);
        }
        if tls_sni_hostname_has_label_prefix(hostname, b"sip")
            || tls_sni_hostname_has_label_prefix(hostname, b"sips")
        {
            return Some(AgentPacketFlowApplication::Sip);
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
        if protocol.eq_ignore_ascii_case(b"ipars-control-plane")
            || protocol.eq_ignore_ascii_case(b"ipars-control")
        {
            return Some(AgentPacketFlowApplication::IparsControlPlane);
        }
        if protocol.eq_ignore_ascii_case(b"ipars-signal") {
            return Some(AgentPacketFlowApplication::IparsSignal);
        }
        if protocol.eq_ignore_ascii_case(b"ipars-agent") {
            return Some(AgentPacketFlowApplication::IparsAgent);
        }
        if protocol.eq_ignore_ascii_case(b"ipars-relay") {
            return Some(AgentPacketFlowApplication::IparsRelay);
        }
        if protocol.eq_ignore_ascii_case(b"ipars-stun") || protocol.eq_ignore_ascii_case(b"stun") {
            return Some(AgentPacketFlowApplication::Stun);
        }
        if protocol.eq_ignore_ascii_case(b"dot") || protocol.eq_ignore_ascii_case(b"doq") {
            return Some(AgentPacketFlowApplication::Dns);
        }
        if protocol.eq_ignore_ascii_case(b"turn")
            || protocol.eq_ignore_ascii_case(b"turns")
            || protocol.eq_ignore_ascii_case(b"stun.turn")
        {
            return Some(AgentPacketFlowApplication::Turn);
        }
        if protocol.eq_ignore_ascii_case(b"coap")
            || protocol.eq_ignore_ascii_case(b"coaps")
            || protocol.eq_ignore_ascii_case(b"coap+tcp")
            || protocol.eq_ignore_ascii_case(b"coaps+tcp")
        {
            return Some(AgentPacketFlowApplication::Coap);
        }
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
        if protocol.eq_ignore_ascii_case(b"ftp")
            || protocol.eq_ignore_ascii_case(b"ftps")
            || protocol.eq_ignore_ascii_case(b"ftp-tls")
        {
            return Some(AgentPacketFlowApplication::Ftp);
        }
        if protocol.eq_ignore_ascii_case(b"rsync") || protocol.eq_ignore_ascii_case(b"rsyncd") {
            return Some(AgentPacketFlowApplication::Rsync);
        }
        if protocol.eq_ignore_ascii_case(b"git") || git_service_name(protocol) {
            return Some(AgentPacketFlowApplication::Git);
        }
        if protocol.eq_ignore_ascii_case(b"smtp")
            || protocol.eq_ignore_ascii_case(b"esmtp")
            || protocol.eq_ignore_ascii_case(b"submission")
        {
            return Some(AgentPacketFlowApplication::Smtp);
        }
        if protocol.eq_ignore_ascii_case(b"imap") || protocol.eq_ignore_ascii_case(b"imap4") {
            return Some(AgentPacketFlowApplication::Imap);
        }
        if protocol.eq_ignore_ascii_case(b"pop3") || protocol.eq_ignore_ascii_case(b"pop") {
            return Some(AgentPacketFlowApplication::Pop3);
        }
        if protocol.eq_ignore_ascii_case(b"sip") || protocol.eq_ignore_ascii_case(b"sips") {
            return Some(AgentPacketFlowApplication::Sip);
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
        if protocol.eq_ignore_ascii_case(b"opensearch") {
            return Some(AgentPacketFlowApplication::OpenSearch);
        }
        if protocol.eq_ignore_ascii_case(b"solr") {
            return Some(AgentPacketFlowApplication::Solr);
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
        if protocol.eq_ignore_ascii_case(b"openvpn") || protocol.eq_ignore_ascii_case(b"ovpn") {
            return Some(AgentPacketFlowApplication::OpenVpn);
        }
        if protocol.eq_ignore_ascii_case(b"smb") {
            return Some(AgentPacketFlowApplication::Smb);
        }
        if protocol.eq_ignore_ascii_case(b"rdp") {
            return Some(AgentPacketFlowApplication::Rdp);
        }
        if protocol.eq_ignore_ascii_case(b"vnc") || protocol.eq_ignore_ascii_case(b"rfb") {
            return Some(AgentPacketFlowApplication::Vnc);
        }
        if protocol.eq_ignore_ascii_case(b"ssh") {
            return Some(AgentPacketFlowApplication::Ssh);
        }
        None
    }

    fn tls_server_hello_application(payload: &[u8]) -> Option<AgentPacketFlowApplication> {
        if payload.len() < 9
            || payload[0] != 0x16
            || payload[1] != 0x03
            || !(0x01..=0x04).contains(&payload[2])
            || payload[5] != 0x02
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
        if session_id_len > 32 {
            return None;
        }
        offset = offset.checked_add(1)?.checked_add(session_id_len)?;
        if offset.checked_add(3)? > handshake_end || payload.get(offset + 2) != Some(&0) {
            return None;
        }
        offset = offset.checked_add(3)?;
        if offset == handshake_end {
            return None;
        }

        let extensions_len = read_u16_be(payload, offset)? as usize;
        offset = offset.checked_add(2)?;
        let extensions_end = offset.checked_add(extensions_len)?;
        if extensions_end != handshake_end {
            return None;
        }

        while offset.checked_add(4)? <= extensions_end {
            let extension_type = read_u16_be(payload, offset)?;
            let extension_len = read_u16_be(payload, offset + 2)? as usize;
            offset = offset.checked_add(4)?;
            let extension_end = offset.checked_add(extension_len)?;
            if extension_end > extensions_end {
                return None;
            }
            if extension_type == 16 {
                return tls_alpn_single_protocol_application(payload.get(offset..extension_end)?);
            }
            offset = extension_end;
        }
        None
    }

    fn tls_alpn_single_protocol_application(
        extension: &[u8],
    ) -> Option<AgentPacketFlowApplication> {
        let protocol_list_len = read_u16_be(extension, 0)? as usize;
        let protocol_list_end = 2_usize.checked_add(protocol_list_len)?;
        if protocol_list_end != extension.len() {
            return None;
        }
        let protocol_len = *extension.get(2)? as usize;
        let protocol_offset = 3_usize;
        let protocol_end = protocol_offset.checked_add(protocol_len)?;
        if protocol_len == 0 || protocol_end != protocol_list_end {
            return None;
        }
        tls_alpn_protocol_application(extension.get(protocol_offset..protocol_end)?)
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
    const STUN_HEADER_LEN: usize = 20;
    const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
    const IPARS_RELAY_FRAME_MAGIC_V1: &[u8] = b"IPARS-RLY1";
    const IPARS_RELAY_FRAME_MAGIC_V2: &[u8] = b"IPARS-RLY2";
    const OPENVPN_CONTROL_MIN_LEN: usize = 14;
    const OPENVPN_MAX_ACKED_PACKET_IDS: usize = 32;

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

    fn relay_frame_payload(payload: &[u8]) -> bool {
        payload.starts_with(IPARS_RELAY_FRAME_MAGIC_V1)
            || payload.starts_with(IPARS_RELAY_FRAME_MAGIC_V2)
    }

    fn stun_payload(payload: &[u8]) -> bool {
        if payload.len() < STUN_HEADER_LEN || payload[0] & 0xc0 != 0 {
            return false;
        }
        let message_len = read_u16_be(payload, 2).unwrap_or_default() as usize;
        if !message_len.is_multiple_of(4) || payload.get(4..8) != Some(&STUN_MAGIC_COOKIE) {
            return false;
        }
        STUN_HEADER_LEN
            .checked_add(message_len)
            .is_some_and(|end| end <= payload.len())
    }

    fn turn_payload(payload: &[u8]) -> bool {
        if !stun_payload(payload) {
            return false;
        }
        let Some(message_type) = read_u16_be(payload, 0) else {
            return false;
        };
        matches!(
            stun_method(message_type),
            0x0003 | 0x0004 | 0x0006 | 0x0007 | 0x0008 | 0x0009 | 0x000a | 0x000b | 0x000c
        )
    }

    fn stun_method(message_type: u16) -> u16 {
        (message_type & 0x000f) | ((message_type & 0x00e0) >> 1) | ((message_type & 0x3e00) >> 2)
    }

    fn coap_payload(payload: &[u8]) -> bool {
        if payload.len() < 4 {
            return false;
        }
        let version = payload[0] >> 6;
        let message_type = (payload[0] >> 4) & 0x03;
        let token_len = (payload[0] & 0x0f) as usize;
        if version != 1 || token_len > 8 {
            return false;
        }
        let Some(header_len) = 4_usize.checked_add(token_len) else {
            return false;
        };
        if header_len > payload.len() {
            return false;
        }
        let code_class = payload[1] >> 5;
        let code_detail = payload[1] & 0x1f;
        if code_class == 0 && code_detail == 0 {
            return token_len == 0 && payload.len() == 4 && matches!(message_type, 2 | 3);
        }
        let code_ok = match (code_class, code_detail) {
            (0, 1..=5) => matches!(message_type, 0 | 1),
            (2, 1..=31) | (4, 0..=31) | (5, 0..=31) => matches!(message_type, 0 | 1 | 2),
            _ => false,
        };
        code_ok && coap_options_payload(payload, header_len)
    }

    fn coap_options_payload(payload: &[u8], mut offset: usize) -> bool {
        let mut option_number = 0_u32;
        let mut option_count = 0_usize;
        while offset < payload.len() {
            let option_header = payload[offset];
            offset += 1;
            if option_header == 0xff {
                return offset < payload.len()
                    || payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
            }
            let delta_nibble = option_header >> 4;
            let length_nibble = option_header & 0x0f;
            if delta_nibble == 15 || length_nibble == 15 {
                return false;
            }
            let Some((delta, next_offset)) =
                coap_option_nibble_value(payload, offset, delta_nibble)
            else {
                return payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
            };
            offset = next_offset;
            let Some((option_len, next_offset)) =
                coap_option_nibble_value(payload, offset, length_nibble)
            else {
                return payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
            };
            offset = next_offset;
            option_number = match option_number.checked_add(delta as u32) {
                Some(value) => value,
                None => return false,
            };
            if option_count == 0 && option_number == 0 {
                return false;
            }
            option_count += 1;
            let Some(option_end) = offset.checked_add(option_len) else {
                return false;
            };
            if option_end > payload.len() {
                return payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
            }
            offset = option_end;
        }
        true
    }

    fn coap_option_nibble_value(
        payload: &[u8],
        offset: usize,
        nibble: u8,
    ) -> Option<(usize, usize)> {
        match nibble {
            0..=12 => Some((nibble as usize, offset)),
            13 => Some((13 + *payload.get(offset)? as usize, offset + 1)),
            14 => {
                let value = read_u16_be(payload, offset)? as usize;
                Some((269 + value, offset + 2))
            }
            _ => None,
        }
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

    fn openvpn_payload(payload: &[u8], protocol: Option<TransportProtocol>) -> bool {
        match protocol {
            None => openvpn_datagram_payload(payload) || openvpn_tcp_payload(payload),
            Some(TransportProtocol::Udp) => openvpn_datagram_payload(payload),
            Some(TransportProtocol::Tcp) => openvpn_tcp_payload(payload),
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

    fn openvpn_datagram_payload(payload: &[u8]) -> bool {
        openvpn_plain_control_packet(payload, false)
    }

    fn openvpn_tcp_payload(payload: &[u8]) -> bool {
        let Some(packet_len) = read_u16_be(payload, 0).map(|len| len as usize) else {
            return false;
        };
        if !(OPENVPN_CONTROL_MIN_LEN..=65_535).contains(&packet_len) {
            return false;
        }
        let available = payload.len().saturating_sub(2);
        let observed_len = available.min(packet_len);
        if observed_len < OPENVPN_CONTROL_MIN_LEN {
            return false;
        }
        let Some(observed) = payload.get(2..2 + observed_len) else {
            return false;
        };
        let truncated = available < packet_len;
        if truncated && payload.len() < PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES {
            return false;
        }
        openvpn_plain_control_packet(observed, truncated)
    }

    fn openvpn_plain_control_packet(payload: &[u8], allow_truncated: bool) -> bool {
        if payload.len() < OPENVPN_CONTROL_MIN_LEN {
            return false;
        }
        let opcode = payload[0] >> 3;
        if !matches!(opcode, 3 | 4 | 5 | 7 | 8 | 10 | 11) {
            return false;
        }
        if payload[1..9].iter().all(|byte| *byte == 0) {
            return false;
        }

        let ack_count = payload[9] as usize;
        if ack_count > OPENVPN_MAX_ACKED_PACKET_IDS {
            return false;
        }
        if matches!(opcode, 3 | 4 | 11) && ack_count == 0 {
            return false;
        }
        let Some(ack_list_len) = ack_count.checked_mul(4) else {
            return false;
        };
        let Some(ack_list_end) = 10_usize.checked_add(ack_list_len) else {
            return false;
        };
        if ack_list_end > payload.len() {
            return allow_truncated && payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
        }

        let mut offset = ack_list_end;
        if ack_count > 0 {
            let Some(peer_session_end) = offset.checked_add(8) else {
                return false;
            };
            if peer_session_end > payload.len() {
                return allow_truncated && payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
            }
            if payload[offset..peer_session_end]
                .iter()
                .all(|byte| *byte == 0)
            {
                return false;
            }
            offset = peer_session_end;
        }

        if opcode == 5 {
            return ack_count > 0;
        }

        let Some(packet_id_end) = offset.checked_add(4) else {
            return false;
        };
        packet_id_end <= payload.len()
            || (allow_truncated && payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES)
    }

    fn http_request_line(payload: &[u8]) -> Option<(&[u8], &[u8], usize)> {
        let line_end = payload
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(payload.len());
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
            (end > 0 && tail.starts_with(b" HTTP/")).then_some((*method, &rest[..end], line_end))
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

    fn vnc_payload(payload: &[u8]) -> bool {
        if payload.len() < 12 || !payload.starts_with(b"RFB ") {
            return false;
        }
        if payload[7] != b'.' || payload[11] != b'\n' {
            return false;
        }
        if !payload[4..7].iter().all(u8::is_ascii_digit)
            || !payload[8..11].iter().all(u8::is_ascii_digit)
        {
            return false;
        }
        payload[4..7] == *b"003"
            && matches!(
                &payload[8..11],
                b"003" | b"004" | b"005" | b"006" | b"007" | b"008"
            )
    }

    fn smtp_payload(payload: &[u8]) -> bool {
        let line = first_ascii_line(payload);
        if line.is_empty() {
            return false;
        }
        if smtp_reply_line(line) {
            return true;
        }
        ascii_starts_with_ignore_case(line, b"EHLO ")
            || ascii_starts_with_ignore_case(line, b"HELO ")
            || ascii_starts_with_ignore_case(line, b"MAIL FROM:")
            || ascii_starts_with_ignore_case(line, b"RCPT TO:")
            || smtp_line_command(line, b"DATA")
            || smtp_line_command(line, b"RSET")
            || smtp_line_command(line, b"NOOP")
            || smtp_line_command(line, b"QUIT")
            || smtp_line_command(line, b"STARTTLS")
            || ascii_starts_with_ignore_case(line, b"AUTH ")
            || ascii_starts_with_ignore_case(line, b"VRFY ")
            || ascii_starts_with_ignore_case(line, b"EXPN ")
    }

    fn smtp_reply_line(line: &[u8]) -> bool {
        if line.len() < 4
            || !line[0..3].iter().all(u8::is_ascii_digit)
            || !matches!(line[3], b' ' | b'-')
        {
            return false;
        }
        let Some(code) = decimal_usize(&line[0..3]) else {
            return false;
        };
        if !smtp_known_reply_code(code) {
            return false;
        }
        let text = trim_ascii_space(&line[4..]);
        if text.len() > 512 || !smtp_reply_text(text) {
            return false;
        }
        if code == 220 {
            return ascii_contains_ignore_case(text, b"SMTP")
                || ascii_contains_ignore_case(text, b"ESMTP");
        }
        if code == 354 {
            return ascii_contains_ignore_case(text, b"mail input")
                || ascii_contains_ignore_case(text, b"send message")
                || ascii_contains_ignore_case(text, b"<CRLF>.<CRLF>")
                || ascii_contains_ignore_case(text, b"CRLF.CRLF");
        }
        if smtp_enhanced_status_reply_text(code, text) {
            return true;
        }
        code == 250 && smtp_ehlo_extension_reply_text(text)
    }

    fn smtp_known_reply_code(code: usize) -> bool {
        matches!(
            code,
            211 | 214
                | 220
                | 221
                | 235
                | 250
                | 251
                | 252
                | 334
                | 354
                | 421
                | 432
                | 450
                | 451
                | 452
                | 454
                | 455
                | 500
                | 501
                | 502
                | 503
                | 504
                | 530
                | 534
                | 535
                | 538
                | 550
                | 551
                | 552
                | 553
                | 554
                | 555
        )
    }

    fn smtp_reply_text(text: &[u8]) -> bool {
        text.iter()
            .all(|byte| *byte == b'\t' || *byte == b' ' || byte.is_ascii_graphic())
    }

    fn smtp_enhanced_status_reply_text(code: usize, text: &[u8]) -> bool {
        let expected_class = b'0' + (code / 100) as u8;
        if !matches!(expected_class, b'2' | b'4' | b'5')
            || text.first() != Some(&expected_class)
            || text.get(1) != Some(&b'.')
        {
            return false;
        }
        let Some(subject_end) = smtp_enhanced_status_number_end(text, 2) else {
            return false;
        };
        if text.get(subject_end) != Some(&b'.') {
            return false;
        }
        let Some(detail_end) = smtp_enhanced_status_number_end(text, subject_end + 1) else {
            return false;
        };
        text.get(detail_end)
            .is_none_or(|byte| byte.is_ascii_whitespace())
    }

    fn smtp_enhanced_status_number_end(text: &[u8], mut offset: usize) -> Option<usize> {
        let start = offset;
        while offset < text.len() && text[offset].is_ascii_digit() {
            offset += 1;
            if offset - start > 3 {
                return None;
            }
        }
        (offset > start).then_some(offset)
    }

    fn smtp_ehlo_extension_reply_text(text: &[u8]) -> bool {
        let Some((keyword, _)) = split_ascii_token(text) else {
            return false;
        };
        keyword.eq_ignore_ascii_case(b"8BITMIME")
            || keyword.eq_ignore_ascii_case(b"AUTH")
            || keyword.eq_ignore_ascii_case(b"BINARYMIME")
            || keyword.eq_ignore_ascii_case(b"CHUNKING")
            || keyword.eq_ignore_ascii_case(b"DSN")
            || keyword.eq_ignore_ascii_case(b"ENHANCEDSTATUSCODES")
            || keyword.eq_ignore_ascii_case(b"ETRN")
            || keyword.eq_ignore_ascii_case(b"EXPN")
            || keyword.eq_ignore_ascii_case(b"HELP")
            || keyword.eq_ignore_ascii_case(b"PIPELINING")
            || keyword.eq_ignore_ascii_case(b"SIZE")
            || keyword.eq_ignore_ascii_case(b"SMTPUTF8")
            || keyword.eq_ignore_ascii_case(b"STARTTLS")
            || keyword.eq_ignore_ascii_case(b"VRFY")
    }

    fn smtp_line_command(line: &[u8], command: &[u8]) -> bool {
        line.eq_ignore_ascii_case(command)
            || line
                .get(command.len())
                .is_some_and(|byte| byte.is_ascii_whitespace())
                && line
                    .get(..command.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(command))
    }

    fn imap_payload(payload: &[u8]) -> bool {
        let line = first_ascii_line(payload);
        if line.is_empty() {
            return false;
        }
        if imap_server_response_line(line) {
            return true;
        }

        let Some((tag, rest)) = split_ascii_token(line) else {
            return false;
        };
        if !imap_tag(tag) {
            return false;
        }
        let Some((command, tail)) = split_ascii_token(trim_ascii_space(rest)) else {
            return false;
        };
        if command.eq_ignore_ascii_case(b"UID") {
            let Some((uid_command, _)) = split_ascii_token(trim_ascii_space(tail)) else {
                return false;
            };
            return imap_known_uid_command(uid_command);
        }
        imap_known_command(command)
    }

    fn imap_server_response_line(line: &[u8]) -> bool {
        if line.len() > 1024 {
            return false;
        }
        let Some((first, rest)) = split_ascii_token(line) else {
            return false;
        };
        if first == b"*" {
            return imap_untagged_response_line(trim_ascii_space(rest));
        }
        if !imap_tag(first) {
            return false;
        }
        let Some((status, text_tail)) = split_ascii_token(trim_ascii_space(rest)) else {
            return false;
        };
        imap_status_atom(status) && imap_response_text(trim_ascii_space(text_tail))
    }

    fn imap_untagged_response_line(line: &[u8]) -> bool {
        let Some((atom, text_tail)) = split_ascii_token(line) else {
            return false;
        };
        if atom.eq_ignore_ascii_case(b"CAPABILITY") {
            return imap_capability_list(trim_ascii_space(text_tail));
        }
        if atom.eq_ignore_ascii_case(b"OK")
            || atom.eq_ignore_ascii_case(b"PREAUTH")
            || atom.eq_ignore_ascii_case(b"BYE")
        {
            let text = trim_ascii_space(text_tail);
            return ascii_contains_ignore_case(text, b"IMAP") || imap_response_text(text);
        }
        false
    }

    fn imap_response_text(text: &[u8]) -> bool {
        if text.is_empty() || text.len() > 512 || !imap_printable_text(text) {
            return false;
        }
        if ascii_contains_ignore_case(text, b"IMAP4rev1")
            || ascii_contains_ignore_case(text, b"IMAP4rev2")
        {
            return true;
        }
        imap_bracketed_response_code(text) || imap_command_completion_text(text)
    }

    fn imap_bracketed_response_code(text: &[u8]) -> bool {
        if text.first() != Some(&b'[') {
            return false;
        }
        let Some(close) = text.iter().position(|byte| *byte == b']') else {
            return false;
        };
        let code = trim_ascii_space(&text[1..close]);
        let Some((atom, tail)) = split_ascii_token(code) else {
            return false;
        };
        if atom.eq_ignore_ascii_case(b"CAPABILITY") {
            return imap_capability_list(trim_ascii_space(tail));
        }
        imap_known_response_code(atom)
    }

    fn imap_command_completion_text(text: &[u8]) -> bool {
        let Some((command, tail)) = split_ascii_token(text) else {
            return false;
        };
        if !imap_known_command(command) {
            return false;
        }
        let Some((completion, _)) = split_ascii_token(trim_ascii_space(tail)) else {
            return false;
        };
        completion.eq_ignore_ascii_case(b"completed")
            || completion.eq_ignore_ascii_case(b"done")
            || completion.eq_ignore_ascii_case(b"failed")
    }

    fn imap_capability_list(text: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut saw_imap = false;
        let mut count = 0_usize;
        let text = trim_ascii_space(text);
        while offset < text.len() {
            let rest = trim_ascii_space(&text[offset..]);
            if rest.is_empty() {
                break;
            }
            let Some((capability, tail)) = split_ascii_token(rest) else {
                return false;
            };
            count += 1;
            if count > 64 || !imap_capability_token(capability) {
                return false;
            }
            saw_imap |= capability.eq_ignore_ascii_case(b"IMAP4rev1")
                || capability.eq_ignore_ascii_case(b"IMAP4rev2");
            offset = text.len().saturating_sub(tail.len());
        }
        saw_imap
    }

    fn imap_status_atom(atom: &[u8]) -> bool {
        atom.eq_ignore_ascii_case(b"OK")
            || atom.eq_ignore_ascii_case(b"NO")
            || atom.eq_ignore_ascii_case(b"BAD")
    }

    fn imap_known_response_code(atom: &[u8]) -> bool {
        atom.eq_ignore_ascii_case(b"ALERT")
            || atom.eq_ignore_ascii_case(b"BADCHARSET")
            || atom.eq_ignore_ascii_case(b"PARSE")
            || atom.eq_ignore_ascii_case(b"PERMANENTFLAGS")
            || atom.eq_ignore_ascii_case(b"READ-ONLY")
            || atom.eq_ignore_ascii_case(b"READ-WRITE")
            || atom.eq_ignore_ascii_case(b"TRYCREATE")
            || atom.eq_ignore_ascii_case(b"UIDNEXT")
            || atom.eq_ignore_ascii_case(b"UIDVALIDITY")
            || atom.eq_ignore_ascii_case(b"APPENDUID")
            || atom.eq_ignore_ascii_case(b"COPYUID")
            || atom.eq_ignore_ascii_case(b"UIDNOTSTICKY")
            || atom.eq_ignore_ascii_case(b"UNAVAILABLE")
            || atom.eq_ignore_ascii_case(b"AUTHENTICATIONFAILED")
            || atom.eq_ignore_ascii_case(b"AUTHORIZATIONFAILED")
            || atom.eq_ignore_ascii_case(b"EXPIRED")
            || atom.eq_ignore_ascii_case(b"PRIVACYREQUIRED")
            || atom.eq_ignore_ascii_case(b"CONTACTADMIN")
            || atom.eq_ignore_ascii_case(b"NOPERM")
            || atom.eq_ignore_ascii_case(b"INUSE")
            || atom.eq_ignore_ascii_case(b"EXPUNGEISSUED")
            || atom.eq_ignore_ascii_case(b"CORRUPTION")
            || atom.eq_ignore_ascii_case(b"SERVERBUG")
            || atom.eq_ignore_ascii_case(b"CLIENTBUG")
            || atom.eq_ignore_ascii_case(b"CANNOT")
            || atom.eq_ignore_ascii_case(b"LIMIT")
            || atom.eq_ignore_ascii_case(b"OVERQUOTA")
            || atom.eq_ignore_ascii_case(b"ALREADYEXISTS")
            || atom.eq_ignore_ascii_case(b"NONEXISTENT")
            || atom.eq_ignore_ascii_case(b"NOTSAVED")
            || atom.eq_ignore_ascii_case(b"HASCHILDREN")
            || atom.eq_ignore_ascii_case(b"CLOSED")
    }

    fn imap_tag(tag: &[u8]) -> bool {
        !tag.is_empty()
            && tag.len() <= 32
            && tag
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-'))
    }

    fn imap_capability_token(token: &[u8]) -> bool {
        !token.is_empty()
            && token.len() <= 128
            && token
                .iter()
                .all(|byte| byte.is_ascii_graphic() && !matches!(*byte, b'(' | b')' | b'[' | b']'))
    }

    fn imap_printable_text(text: &[u8]) -> bool {
        text.iter()
            .all(|byte| *byte == b'\t' || *byte == b' ' || byte.is_ascii_graphic())
    }

    fn imap_known_command(command: &[u8]) -> bool {
        command.eq_ignore_ascii_case(b"CAPABILITY")
            || command.eq_ignore_ascii_case(b"NOOP")
            || command.eq_ignore_ascii_case(b"LOGOUT")
            || command.eq_ignore_ascii_case(b"STARTTLS")
            || command.eq_ignore_ascii_case(b"AUTHENTICATE")
            || command.eq_ignore_ascii_case(b"LOGIN")
            || command.eq_ignore_ascii_case(b"SELECT")
            || command.eq_ignore_ascii_case(b"EXAMINE")
            || command.eq_ignore_ascii_case(b"CREATE")
            || command.eq_ignore_ascii_case(b"DELETE")
            || command.eq_ignore_ascii_case(b"RENAME")
            || command.eq_ignore_ascii_case(b"SUBSCRIBE")
            || command.eq_ignore_ascii_case(b"UNSUBSCRIBE")
            || command.eq_ignore_ascii_case(b"LIST")
            || command.eq_ignore_ascii_case(b"LSUB")
            || command.eq_ignore_ascii_case(b"STATUS")
            || command.eq_ignore_ascii_case(b"APPEND")
            || command.eq_ignore_ascii_case(b"CHECK")
            || command.eq_ignore_ascii_case(b"CLOSE")
            || command.eq_ignore_ascii_case(b"EXPUNGE")
            || command.eq_ignore_ascii_case(b"SEARCH")
            || command.eq_ignore_ascii_case(b"FETCH")
            || command.eq_ignore_ascii_case(b"STORE")
            || command.eq_ignore_ascii_case(b"COPY")
            || command.eq_ignore_ascii_case(b"MOVE")
            || command.eq_ignore_ascii_case(b"IDLE")
    }

    fn imap_known_uid_command(command: &[u8]) -> bool {
        command.eq_ignore_ascii_case(b"FETCH")
            || command.eq_ignore_ascii_case(b"SEARCH")
            || command.eq_ignore_ascii_case(b"STORE")
            || command.eq_ignore_ascii_case(b"COPY")
            || command.eq_ignore_ascii_case(b"MOVE")
            || command.eq_ignore_ascii_case(b"EXPUNGE")
    }

    fn pop3_payload(payload: &[u8]) -> bool {
        let line = first_ascii_line(payload);
        if line.is_empty() {
            return false;
        }
        if pop3_response_line(line) {
            return true;
        }
        let Some((command, rest)) = split_ascii_token(line) else {
            return false;
        };
        pop3_known_command(command, trim_ascii_space(rest))
    }

    fn pop3_response_line(line: &[u8]) -> bool {
        if line.len() > 512 || !pop3_printable_text(line) {
            return false;
        }
        let Some((status, rest)) = split_ascii_token(line) else {
            return false;
        };
        if !matches!(status, b"+OK" | b"-ERR") {
            return false;
        }
        let text = trim_ascii_space(rest);
        if ascii_contains_ignore_case(text, b"POP3") {
            return true;
        }
        if text.first() == Some(&b'[') && pop3_response_code_text(text) {
            return true;
        }
        if status == b"+OK" {
            return pop3_positive_response_text(text);
        }
        pop3_negative_response_text(text)
    }

    fn pop3_positive_response_text(text: &[u8]) -> bool {
        if pop3_drop_listing_response_text(text) {
            return true;
        }
        ascii_contains_ignore_case(text, b"capability list follows")
            || ascii_contains_ignore_case(text, b"scan listing follows")
            || ascii_contains_ignore_case(text, b"message follows")
            || ascii_contains_ignore_case(text, b"maildrop has")
            || ascii_contains_ignore_case(text, b"signing off")
            || ascii_contains_ignore_case(text, b"message deleted")
            || pop3_octets_response_text(text)
    }

    fn pop3_negative_response_text(text: &[u8]) -> bool {
        ascii_contains_ignore_case(text, b"no such message")
            || ascii_contains_ignore_case(text, b"already deleted")
            || ascii_contains_ignore_case(text, b"maildrop")
            || ascii_contains_ignore_case(text, b"authentication")
            || ascii_contains_ignore_case(text, b"authorization")
    }

    fn pop3_response_code_text(text: &[u8]) -> bool {
        let Some(close) = text.iter().position(|byte| *byte == b']') else {
            return false;
        };
        let code = &text[1..close];
        !code.is_empty()
            && code.len() <= 64
            && code
                .split(|byte| *byte == b'/')
                .all(pop3_response_code_atom)
    }

    fn pop3_response_code_atom(atom: &[u8]) -> bool {
        atom.eq_ignore_ascii_case(b"LOGIN-DELAY")
            || atom.eq_ignore_ascii_case(b"IN-USE")
            || atom.eq_ignore_ascii_case(b"SYS")
            || atom.eq_ignore_ascii_case(b"AUTH")
            || atom.eq_ignore_ascii_case(b"EXPIRE")
    }

    fn pop3_drop_listing_response_text(text: &[u8]) -> bool {
        let Some((messages, rest)) = split_ascii_token(text) else {
            return false;
        };
        let Some((octets, tail)) = split_ascii_token(trim_ascii_space(rest)) else {
            return false;
        };
        pop3_decimal_token(messages)
            && pop3_decimal_token(octets)
            && trim_ascii_space(tail)
                .first()
                .is_none_or(|byte| !byte.is_ascii_digit())
    }

    fn pop3_octets_response_text(text: &[u8]) -> bool {
        let Some((octets, rest)) = split_ascii_token(text) else {
            return false;
        };
        pop3_decimal_token(octets)
            && split_ascii_token(trim_ascii_space(rest)).is_some_and(|(unit, _)| {
                unit.eq_ignore_ascii_case(b"octets")
                    || unit.eq_ignore_ascii_case(b"messages")
                    || unit.eq_ignore_ascii_case(b"message")
            })
    }

    fn pop3_decimal_token(token: &[u8]) -> bool {
        !token.is_empty() && token.len() <= 10 && token.iter().all(u8::is_ascii_digit)
    }

    fn pop3_printable_text(text: &[u8]) -> bool {
        text.iter()
            .all(|byte| *byte == b'\t' || *byte == b' ' || byte.is_ascii_graphic())
    }

    fn pop3_known_command(command: &[u8], rest: &[u8]) -> bool {
        if command.eq_ignore_ascii_case(b"STAT") {
            return rest.is_empty();
        }
        command.eq_ignore_ascii_case(b"USER")
            || command.eq_ignore_ascii_case(b"PASS")
            || command.eq_ignore_ascii_case(b"APOP")
            || command.eq_ignore_ascii_case(b"AUTH")
            || command.eq_ignore_ascii_case(b"CAPA")
            || command.eq_ignore_ascii_case(b"STLS")
            || command.eq_ignore_ascii_case(b"LIST")
            || command.eq_ignore_ascii_case(b"RETR")
            || command.eq_ignore_ascii_case(b"DELE")
            || command.eq_ignore_ascii_case(b"NOOP")
            || command.eq_ignore_ascii_case(b"RSET")
            || command.eq_ignore_ascii_case(b"TOP")
            || command.eq_ignore_ascii_case(b"UIDL")
            || command.eq_ignore_ascii_case(b"QUIT")
    }

    fn sip_payload(payload: &[u8]) -> bool {
        let line = first_ascii_line(payload);
        if line.is_empty() {
            return false;
        }
        if ascii_starts_with_ignore_case(line, b"SIP/2.0 ") {
            let Some(status) = line.get(8..11) else {
                return false;
            };
            return status.iter().all(u8::is_ascii_digit)
                && line.get(11).is_none_or(|byte| byte.is_ascii_whitespace());
        }

        let Some((method, rest)) = split_ascii_token(line) else {
            return false;
        };
        if !sip_known_method(method) {
            return false;
        }
        let Some((uri, version_tail)) = split_ascii_token(trim_ascii_space(rest)) else {
            return false;
        };
        if !sip_request_uri(uri) {
            return false;
        }
        let Some((version, trailing)) = split_ascii_token(trim_ascii_space(version_tail)) else {
            return false;
        };
        version.eq_ignore_ascii_case(b"SIP/2.0") && trim_ascii_space(trailing).is_empty()
    }

    fn sip_known_method(method: &[u8]) -> bool {
        method.eq_ignore_ascii_case(b"INVITE")
            || method.eq_ignore_ascii_case(b"ACK")
            || method.eq_ignore_ascii_case(b"BYE")
            || method.eq_ignore_ascii_case(b"CANCEL")
            || method.eq_ignore_ascii_case(b"OPTIONS")
            || method.eq_ignore_ascii_case(b"REGISTER")
            || method.eq_ignore_ascii_case(b"PRACK")
            || method.eq_ignore_ascii_case(b"SUBSCRIBE")
            || method.eq_ignore_ascii_case(b"NOTIFY")
            || method.eq_ignore_ascii_case(b"PUBLISH")
            || method.eq_ignore_ascii_case(b"INFO")
            || method.eq_ignore_ascii_case(b"REFER")
            || method.eq_ignore_ascii_case(b"MESSAGE")
            || method.eq_ignore_ascii_case(b"UPDATE")
    }

    fn sip_request_uri(uri: &[u8]) -> bool {
        uri == b"*"
            || ((ascii_starts_with_ignore_case(uri, b"sip:")
                || ascii_starts_with_ignore_case(uri, b"sips:"))
                && uri.len() <= 256
                && uri
                    .iter()
                    .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace()))
    }

    fn ftp_payload(payload: &[u8]) -> bool {
        let line = first_ascii_line(payload);
        if line.is_empty() {
            return false;
        }
        if ftp_reply_line(line) {
            return true;
        }
        let Some((command, _)) = split_ascii_token(line) else {
            return false;
        };
        ftp_known_command(command)
    }

    fn ftp_reply_line(line: &[u8]) -> bool {
        if line.len() < 4
            || line.len() > 512
            || !line[0..3].iter().all(u8::is_ascii_digit)
            || !matches!(line[3], b' ' | b'-')
        {
            return false;
        }
        let Some(code) = decimal_usize(&line[0..3]) else {
            return false;
        };
        if !ftp_known_reply_code(code) {
            return false;
        }
        let text = trim_ascii_space(&line[4..]);
        if !ftp_reply_text(text) {
            return false;
        }
        if ascii_contains_ignore_case(text, b"FTP") || ascii_contains_ignore_case(text, b"FTPS") {
            return true;
        }
        match code {
            110 => ftp_restart_marker_text(text),
            120 => {
                ascii_contains_ignore_case(text, b"service ready")
                    && ascii_contains_ignore_case(text, b"minute")
            }
            125 => {
                ascii_contains_ignore_case(text, b"data connection")
                    && (ascii_contains_ignore_case(text, b"open")
                        || ascii_contains_ignore_case(text, b"starting"))
            }
            150 => {
                ascii_contains_ignore_case(text, b"data connection")
                    || ascii_contains_ignore_case(text, b"opening")
                    || ascii_contains_ignore_case(text, b"file status")
            }
            200 => {
                ascii_contains_ignore_case(text, b"command okay")
                    || ascii_contains_ignore_case(text, b"type set")
                    || ascii_contains_ignore_case(text, b"mode set")
            }
            202 => {
                ascii_contains_ignore_case(text, b"command not implemented")
                    || ascii_contains_ignore_case(text, b"superfluous")
            }
            211 => ascii_contains_ignore_case(text, b"system status"),
            212 => ascii_contains_ignore_case(text, b"directory status"),
            213 => ascii_contains_ignore_case(text, b"file status"),
            214 => ascii_contains_ignore_case(text, b"help"),
            215 => ascii_contains_ignore_case(text, b"system type"),
            221 => {
                ascii_contains_ignore_case(text, b"service closing")
                    || ascii_contains_ignore_case(text, b"control connection")
                    || ascii_contains_ignore_case(text, b"logged out")
            }
            225 => ascii_contains_ignore_case(text, b"data connection"),
            226 => {
                ascii_contains_ignore_case(text, b"data connection")
                    || ascii_contains_ignore_case(text, b"transfer complete")
                    || ascii_contains_ignore_case(text, b"file transfer")
            }
            227 => ftp_passive_mode_reply_text(text),
            229 => ftp_extended_passive_mode_reply_text(text),
            230 => ascii_contains_ignore_case(text, b"logged in"),
            250 => {
                (ascii_contains_ignore_case(text, b"requested file action")
                    && (ascii_contains_ignore_case(text, b"okay")
                        || ascii_contains_ignore_case(text, b"completed")))
                    || ascii_contains_ignore_case(text, b"directory successfully changed")
            }
            257 => ftp_quoted_path_reply_text(text),
            331 => ascii_contains_ignore_case(text, b"password"),
            332 | 532 => ascii_contains_ignore_case(text, b"account"),
            350 => {
                ascii_contains_ignore_case(text, b"pending")
                    || ascii_contains_ignore_case(text, b"further information")
            }
            421 => {
                ascii_contains_ignore_case(text, b"service not available")
                    || ascii_contains_ignore_case(text, b"closing control connection")
            }
            425 | 426 => ascii_contains_ignore_case(text, b"data connection"),
            450 | 451 | 452 | 550 | 551 | 552 | 553 => {
                ascii_contains_ignore_case(text, b"requested action")
                    || ascii_contains_ignore_case(text, b"file")
                    || ascii_contains_ignore_case(text, b"directory")
                    || ascii_contains_ignore_case(text, b"storage")
                    || ascii_contains_ignore_case(text, b"access")
            }
            500 | 501 | 502 | 503 | 504 => {
                ascii_contains_ignore_case(text, b"syntax")
                    || ascii_contains_ignore_case(text, b"command")
                    || ascii_contains_ignore_case(text, b"parameter")
                    || ascii_contains_ignore_case(text, b"argument")
                    || ascii_contains_ignore_case(text, b"sequence")
            }
            530 => ascii_contains_ignore_case(text, b"logged in"),
            _ => false,
        }
    }

    fn ftp_known_reply_code(code: usize) -> bool {
        matches!(
            code,
            110 | 120
                | 125
                | 150
                | 200
                | 202
                | 211
                | 212
                | 213
                | 214
                | 215
                | 220
                | 221
                | 225
                | 226
                | 227
                | 229
                | 230
                | 250
                | 257
                | 331
                | 332
                | 350
                | 421
                | 425
                | 426
                | 450
                | 451
                | 452
                | 500
                | 501
                | 502
                | 503
                | 504
                | 530
                | 532
                | 550
                | 551
                | 552
                | 553
        )
    }

    fn ftp_reply_text(text: &[u8]) -> bool {
        !text.is_empty()
            && text
                .iter()
                .all(|byte| *byte == b'\t' || *byte == b' ' || byte.is_ascii_graphic())
    }

    fn ftp_restart_marker_text(text: &[u8]) -> bool {
        ascii_starts_with_ignore_case(text, b"MARK ")
            && text.windows(3).any(|window| window == b" = ")
    }

    fn ftp_passive_mode_reply_text(text: &[u8]) -> bool {
        if !ascii_contains_ignore_case(text, b"passive mode") {
            return false;
        }
        let Some(open) = text.iter().position(|byte| *byte == b'(') else {
            return false;
        };
        let Some(close_rel) = text[open + 1..].iter().position(|byte| *byte == b')') else {
            return false;
        };
        let tuple = &text[open + 1..open + 1 + close_rel];
        let mut count = 0_usize;
        for part in tuple.split(|byte| *byte == b',') {
            count += 1;
            if count > 6 {
                return false;
            }
            let Some(value) = decimal_usize(part) else {
                return false;
            };
            if value > 255 {
                return false;
            }
        }
        count == 6
    }

    fn ftp_extended_passive_mode_reply_text(text: &[u8]) -> bool {
        if !ascii_contains_ignore_case(text, b"extended passive mode") {
            return false;
        }
        let Some(open) = text.iter().position(|byte| *byte == b'(') else {
            return false;
        };
        let Some(close_rel) = text[open + 1..].iter().position(|byte| *byte == b')') else {
            return false;
        };
        let fields = &text[open + 1..open + 1 + close_rel];
        if fields.len() < 5 {
            return false;
        }
        let delimiter = fields[0];
        if !delimiter.is_ascii_graphic() || delimiter.is_ascii_digit() {
            return false;
        }
        if fields.get(1) != Some(&delimiter) || fields.get(2) != Some(&delimiter) {
            return false;
        }
        let port_end = fields[3..].iter().position(|byte| *byte == delimiter);
        let Some(port_end) = port_end else {
            return false;
        };
        if 3 + port_end + 1 != fields.len() {
            return false;
        }
        let Some(port) = decimal_usize(&fields[3..3 + port_end]) else {
            return false;
        };
        (1..=65_535).contains(&port)
    }

    fn ftp_quoted_path_reply_text(text: &[u8]) -> bool {
        if text.first() != Some(&b'"') {
            return false;
        }
        let Some(close) = text[1..].iter().position(|byte| *byte == b'"') else {
            return false;
        };
        let tail = trim_ascii_space(&text[1 + close + 1..]);
        !tail.is_empty()
            && (ascii_contains_ignore_case(tail, b"created")
                || ascii_contains_ignore_case(tail, b"current directory"))
    }

    fn ftp_known_command(command: &[u8]) -> bool {
        command.eq_ignore_ascii_case(b"ACCT")
            || command.eq_ignore_ascii_case(b"ALLO")
            || command.eq_ignore_ascii_case(b"APPE")
            || command.eq_ignore_ascii_case(b"CDUP")
            || command.eq_ignore_ascii_case(b"CWD")
            || command.eq_ignore_ascii_case(b"EPRT")
            || command.eq_ignore_ascii_case(b"EPSV")
            || command.eq_ignore_ascii_case(b"FEAT")
            || command.eq_ignore_ascii_case(b"MLSD")
            || command.eq_ignore_ascii_case(b"MLST")
            || command.eq_ignore_ascii_case(b"MODE")
            || command.eq_ignore_ascii_case(b"OPTS")
            || command.eq_ignore_ascii_case(b"PASV")
            || command.eq_ignore_ascii_case(b"PBSZ")
            || command.eq_ignore_ascii_case(b"PORT")
            || command.eq_ignore_ascii_case(b"PROT")
            || command.eq_ignore_ascii_case(b"PWD")
            || command.eq_ignore_ascii_case(b"REST")
            || command.eq_ignore_ascii_case(b"RNFR")
            || command.eq_ignore_ascii_case(b"RNTO")
            || command.eq_ignore_ascii_case(b"SITE")
            || command.eq_ignore_ascii_case(b"SMNT")
            || command.eq_ignore_ascii_case(b"STOR")
            || command.eq_ignore_ascii_case(b"STOU")
            || command.eq_ignore_ascii_case(b"STRU")
            || command.eq_ignore_ascii_case(b"SYST")
            || command.eq_ignore_ascii_case(b"TYPE")
            || command.eq_ignore_ascii_case(b"XCUP")
            || command.eq_ignore_ascii_case(b"XCWD")
            || command.eq_ignore_ascii_case(b"XMKD")
            || command.eq_ignore_ascii_case(b"XPWD")
            || command.eq_ignore_ascii_case(b"XRMD")
    }

    fn rsync_payload(payload: &[u8]) -> bool {
        let line = first_ascii_line(payload);
        if line.len() > 512 || !rsync_printable_line(line) {
            return false;
        }
        if ascii_starts_with_ignore_case(line, b"@ERROR:") {
            let message = trim_ascii_space(&line[b"@ERROR:".len()..]);
            return !message.is_empty();
        }
        if !ascii_starts_with_ignore_case(line, b"@RSYNCD:") {
            return false;
        }
        let command = trim_ascii_space(&line[b"@RSYNCD:".len()..]);
        if command.eq_ignore_ascii_case(b"OK") || command.eq_ignore_ascii_case(b"EXIT") {
            return true;
        }
        if ascii_starts_with_ignore_case(command, b"AUTHREQD ") {
            return rsync_auth_challenge(&command[b"AUTHREQD ".len()..]);
        }
        rsync_version_greeting(command)
    }

    fn rsync_version_greeting(version: &[u8]) -> bool {
        let Some((protocol, tail)) = split_ascii_token(version) else {
            return false;
        };
        if protocol.is_empty()
            || protocol.len() > 16
            || !protocol.iter().any(|byte| byte.is_ascii_digit())
            || !protocol
                .iter()
                .all(|byte| byte.is_ascii_digit() || *byte == b'.')
        {
            return false;
        }
        let mut offset = version.len().saturating_sub(tail.len());
        let mut digest_count = 0_usize;
        while offset < version.len() {
            let rest = trim_ascii_space(&version[offset..]);
            if rest.is_empty() {
                break;
            }
            let Some((digest, digest_tail)) = split_ascii_token(rest) else {
                return false;
            };
            digest_count += 1;
            if digest_count > 16 || !rsync_digest_token(digest) {
                return false;
            }
            offset = version.len().saturating_sub(digest_tail.len());
        }
        true
    }

    fn rsync_auth_challenge(challenge: &[u8]) -> bool {
        let challenge = trim_ascii_space(challenge);
        !challenge.is_empty()
            && challenge.len() <= 128
            && challenge
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'+' | b'/' | b'='))
    }

    fn rsync_digest_token(digest: &[u8]) -> bool {
        !digest.is_empty()
            && digest.len() <= 32
            && digest
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
    }

    fn rsync_printable_line(line: &[u8]) -> bool {
        line.iter()
            .all(|byte| *byte == b'\t' || *byte == b' ' || byte.is_ascii_graphic())
    }

    fn git_payload(payload: &[u8]) -> bool {
        let Some(line_len) = git_pkt_line_len(payload) else {
            return false;
        };
        if line_len < 4 || line_len > 65_520 {
            return false;
        }
        let available_end = line_len.min(payload.len());
        let Some(line) = payload.get(4..available_end) else {
            return false;
        };
        git_service_request_line(line)
    }

    fn git_pkt_line_len(payload: &[u8]) -> Option<usize> {
        let prefix = payload.get(..4)?;
        let mut value = 0_usize;
        for byte in prefix {
            let digit = match *byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return None,
            };
            value = value.checked_mul(16)?.checked_add(digit as usize)?;
        }
        Some(value)
    }

    fn git_service_request_line(line: &[u8]) -> bool {
        GIT_SMART_SERVICES.iter().any(|service| {
            line.get(..service.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(service))
                && matches!(line.get(service.len()), Some(b' ' | b'\0' | b'\n' | b'\r'))
        })
    }

    fn tftp_payload(payload: &[u8]) -> bool {
        if payload.len() < 4 {
            return false;
        }
        let Some(opcode) = read_u16_be(payload, 0) else {
            return false;
        };
        match opcode {
            1 | 2 => tftp_request_payload(payload),
            5 => tftp_error_payload(payload),
            6 => tftp_oack_payload(payload),
            _ => false,
        }
    }

    fn tftp_request_payload(payload: &[u8]) -> bool {
        let mut offset = 2_usize;
        let Some((filename, next_offset)) = tftp_zstring(payload, offset) else {
            return false;
        };
        if filename.is_empty() || filename.len() > 255 || !tftp_token(filename) {
            return false;
        }
        offset = next_offset;

        let Some((mode, next_offset)) = tftp_zstring(payload, offset) else {
            return false;
        };
        if !tftp_mode(mode) {
            return false;
        }
        offset = next_offset;

        let mut option_count = 0_usize;
        while offset < payload.len() {
            option_count += 1;
            if option_count > 16 {
                return false;
            }
            let Some((option_name, next_offset)) = tftp_zstring(payload, offset) else {
                return false;
            };
            if option_name.is_empty() || !tftp_token(option_name) {
                return false;
            }
            let Some((option_value, value_offset)) = tftp_zstring(payload, next_offset) else {
                return false;
            };
            if option_value.is_empty() || !tftp_token(option_value) {
                return false;
            }
            offset = value_offset;
        }
        true
    }

    fn tftp_error_payload(payload: &[u8]) -> bool {
        let Some(error_code) = read_u16_be(payload, 2) else {
            return false;
        };
        if error_code > 8 {
            return false;
        }
        let Some((message, next_offset)) = tftp_zstring(payload, 4) else {
            return false;
        };
        next_offset == payload.len()
            && !message.is_empty()
            && message.len() <= 512
            && tftp_token(message)
    }

    fn tftp_oack_payload(payload: &[u8]) -> bool {
        let mut offset = 2_usize;
        let mut option_count = 0_usize;
        while offset < payload.len() {
            option_count += 1;
            if option_count > 16 {
                return false;
            }
            let Some((option_name, next_offset)) = tftp_zstring(payload, offset) else {
                return false;
            };
            if option_name.is_empty() || !tftp_known_option(option_name) {
                return false;
            }
            let Some((option_value, value_offset)) = tftp_zstring(payload, next_offset) else {
                return false;
            };
            if option_value.is_empty() || !tftp_token(option_value) {
                return false;
            }
            offset = value_offset;
        }
        option_count > 0
    }

    fn tftp_zstring(payload: &[u8], offset: usize) -> Option<(&[u8], usize)> {
        if offset >= payload.len() {
            return None;
        }
        let nul = payload[offset..].iter().position(|byte| *byte == 0)?;
        let end = offset.checked_add(nul)?;
        Some((&payload[offset..end], end.checked_add(1)?))
    }

    fn tftp_mode(mode: &[u8]) -> bool {
        mode.eq_ignore_ascii_case(b"netascii")
            || mode.eq_ignore_ascii_case(b"octet")
            || mode.eq_ignore_ascii_case(b"mail")
    }

    fn tftp_known_option(option: &[u8]) -> bool {
        option.eq_ignore_ascii_case(b"blksize")
            || option.eq_ignore_ascii_case(b"timeout")
            || option.eq_ignore_ascii_case(b"tsize")
            || option.eq_ignore_ascii_case(b"windowsize")
            || option.eq_ignore_ascii_case(b"multicast")
    }

    fn tftp_token(token: &[u8]) -> bool {
        token
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    }

    fn first_ascii_line(payload: &[u8]) -> &[u8] {
        let line_end = payload
            .iter()
            .position(|byte| matches!(*byte, b'\r' | b'\n'))
            .unwrap_or(payload.len());
        trim_ascii_space(&payload[..line_end])
    }

    fn split_ascii_token(line: &[u8]) -> Option<(&[u8], &[u8])> {
        let line = trim_ascii_space(line);
        if line.is_empty() {
            return None;
        }
        let token_end = line
            .iter()
            .position(|byte| byte.is_ascii_whitespace())
            .unwrap_or(line.len());
        Some((&line[..token_end], &line[token_end..]))
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
        postgres_startup_payload(payload)
            || postgres_frontend_message_payload(payload)
            || postgres_backend_message_payload(payload)
    }

    fn postgres_startup_payload(payload: &[u8]) -> bool {
        if payload.len() < 8 {
            return false;
        }
        let Some(length) = read_u32_be(payload, 0).map(|value| value as usize) else {
            return false;
        };
        if !(8..=10_000).contains(&length) || payload.len() > length {
            return false;
        }
        let Some(code) = read_u32_be(payload, 4) else {
            return false;
        };
        match code {
            196_608 => postgres_startup_parameters_payload(payload, length),
            80_877_103 | 80_877_104 => length == 8 && payload.len() == 8,
            80_877_102 => {
                length == 16
                    && payload.len() == 16
                    && payload
                        .get(8..16)
                        .is_some_and(|payload| payload.iter().any(|byte| *byte != 0))
            }
            _ => false,
        }
    }

    fn postgres_startup_parameters_payload(payload: &[u8], length: usize) -> bool {
        let incomplete = length > payload.len();
        if incomplete && payload.len() < PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES {
            return false;
        }
        let Some(body) = payload.get(8..) else {
            return false;
        };
        if body.is_empty() {
            return false;
        }
        postgres_startup_parameter_fields(body, incomplete)
    }

    fn postgres_startup_parameter_fields(payload: &[u8], incomplete: bool) -> bool {
        let mut offset = 0_usize;
        let mut parameter_count = 0_usize;
        let mut saw_user = false;
        while offset < payload.len() {
            if payload[offset] == 0 {
                return !incomplete && offset.checked_add(1) == Some(payload.len()) && saw_user;
            }
            let (key, value_offset) = match postgres_cstring_field(payload, offset, 128) {
                Some(PostgresCStringParse::Complete { value, next_offset }) => {
                    if !postgres_startup_parameter_key(value) {
                        return false;
                    }
                    (value, next_offset)
                }
                Some(PostgresCStringParse::Incomplete { value }) => {
                    return incomplete
                        && (saw_user || postgres_startup_parameter_key_prefix(value));
                }
                None => return false,
            };
            let (value, next_offset) = match postgres_cstring_field(payload, value_offset, 1024) {
                Some(PostgresCStringParse::Complete { value, next_offset }) => {
                    if !postgres_startup_parameter_value(value) {
                        return false;
                    }
                    (value, next_offset)
                }
                Some(PostgresCStringParse::Incomplete { value }) => {
                    return incomplete
                        && postgres_startup_parameter_value(value)
                        && (saw_user || key.eq_ignore_ascii_case(b"user"));
                }
                None => return false,
            };
            if key.eq_ignore_ascii_case(b"user") {
                if value.is_empty() {
                    return false;
                }
                saw_user = true;
            }
            parameter_count += 1;
            if parameter_count > 64 {
                return false;
            }
            offset = next_offset;
        }
        incomplete && saw_user
    }

    enum PostgresCStringParse<'a> {
        Complete { value: &'a [u8], next_offset: usize },
        Incomplete { value: &'a [u8] },
    }

    fn postgres_cstring_field(
        payload: &[u8],
        offset: usize,
        max_len: usize,
    ) -> Option<PostgresCStringParse<'_>> {
        let tail = payload.get(offset..)?;
        if let Some(terminator) = tail.iter().position(|byte| *byte == 0) {
            if terminator > max_len {
                return None;
            }
            return Some(PostgresCStringParse::Complete {
                value: &tail[..terminator],
                next_offset: offset + terminator + 1,
            });
        }
        if tail.len() > max_len {
            return None;
        }
        Some(PostgresCStringParse::Incomplete { value: tail })
    }

    fn postgres_startup_parameter_key(value: &[u8]) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.' | b'-'))
    }

    fn postgres_startup_parameter_key_prefix(value: &[u8]) -> bool {
        const COMMON_KEYS: &[&[u8]] = &[
            b"user",
            b"database",
            b"application_name",
            b"client_encoding",
            b"DateStyle",
            b"TimeZone",
            b"options",
            b"replication",
            b"search_path",
        ];
        !value.is_empty()
            && value.len() <= 128
            && postgres_startup_parameter_key(value)
            && COMMON_KEYS.iter().any(|key| {
                key.get(..value.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(value))
            })
    }

    fn postgres_startup_parameter_value(value: &[u8]) -> bool {
        value.len() <= 1024
            && value
                .iter()
                .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    }

    fn postgres_frontend_message_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut frame_count = 0_usize;
        while offset < payload.len() {
            match postgres_frontend_message_frame(payload, offset) {
                Some(PostgresFrontendMessageParse::Complete(next_offset)) => {
                    frame_count += 1;
                    if frame_count > 16 {
                        return false;
                    }
                    offset = next_offset;
                }
                Some(PostgresFrontendMessageParse::Incomplete) => {
                    return frame_count > 0
                        && payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
                }
                None => return false,
            }
        }
        frame_count > 0
    }

    fn postgres_backend_message_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut frame_count = 0_usize;
        while offset < payload.len() {
            match postgres_backend_message_frame(payload, offset) {
                Some(PostgresBackendMessageParse::Complete(next_offset)) => {
                    frame_count += 1;
                    if frame_count > 32 {
                        return false;
                    }
                    offset = next_offset;
                }
                Some(PostgresBackendMessageParse::Incomplete) => {
                    return frame_count > 0
                        && payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
                }
                None => return false,
            }
        }
        frame_count > 0
    }

    enum PostgresFrontendMessageParse {
        Complete(usize),
        Incomplete,
    }

    enum PostgresBackendMessageParse {
        Complete(usize),
        Incomplete,
    }

    fn postgres_frontend_message_frame(
        payload: &[u8],
        offset: usize,
    ) -> Option<PostgresFrontendMessageParse> {
        if payload.len().saturating_sub(offset) < 5 {
            return Some(PostgresFrontendMessageParse::Incomplete);
        }
        let tag = *payload.get(offset)?;
        let length = read_u32_be(payload, offset.checked_add(1)?).map(|length| length as usize)?;
        if !(4..=10_000).contains(&length) {
            return None;
        }
        let frame_end = offset.checked_add(1)?.checked_add(length)?;
        let Some(frame) = payload.get(offset..frame_end) else {
            return Some(PostgresFrontendMessageParse::Incomplete);
        };
        let body = &frame[5..];
        let valid = match tag {
            b'Q' => postgres_query_message_payload(body),
            b'P' => postgres_parse_message_payload(body),
            b'B' => postgres_bind_message_payload(body),
            b'C' | b'D' => postgres_named_portal_or_statement_payload(body),
            b'E' => postgres_execute_message_payload(body),
            b'p' => postgres_password_message_payload(body),
            b'H' | b'S' | b'X' => body.is_empty(),
            _ => false,
        };
        valid.then_some(PostgresFrontendMessageParse::Complete(frame_end))
    }

    fn postgres_backend_message_frame(
        payload: &[u8],
        offset: usize,
    ) -> Option<PostgresBackendMessageParse> {
        if payload.len().saturating_sub(offset) < 5 {
            return Some(PostgresBackendMessageParse::Incomplete);
        }
        let tag = *payload.get(offset)?;
        let length = read_u32_be(payload, offset.checked_add(1)?).map(|length| length as usize)?;
        if !(4..=10_000).contains(&length) {
            return None;
        }
        let frame_end = offset.checked_add(1)?.checked_add(length)?;
        let Some(frame) = payload.get(offset..frame_end) else {
            return Some(PostgresBackendMessageParse::Incomplete);
        };
        let body = &frame[5..];
        let valid = match tag {
            b'R' => postgres_authentication_message_payload(body),
            b'S' => postgres_parameter_status_message_payload(body),
            b'K' => postgres_backend_key_data_message_payload(body),
            b'Z' => postgres_ready_for_query_message_payload(body),
            b'C' => postgres_command_complete_message_payload(body),
            b'E' | b'N' => postgres_error_or_notice_message_payload(body),
            _ => false,
        };
        valid.then_some(PostgresBackendMessageParse::Complete(frame_end))
    }

    fn postgres_authentication_message_payload(body: &[u8]) -> bool {
        let Some(code) = read_u32_be(body, 0) else {
            return false;
        };
        match code {
            0 | 2 | 3 | 7 | 9 => body.len() == 4,
            5 => body.len() == 8,
            8 | 11 | 12 => body.len() > 4,
            10 => postgres_sasl_mechanisms_payload(&body[4..]),
            _ => false,
        }
    }

    fn postgres_sasl_mechanisms_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut saw_mechanism = false;
        while offset < payload.len() {
            if payload[offset] == 0 {
                return saw_mechanism && offset.checked_add(1) == Some(payload.len());
            }
            let Some(next_offset) = postgres_cstring_end(payload, offset) else {
                return false;
            };
            let mechanism = &payload[offset..next_offset - 1];
            if mechanism.is_empty()
                || mechanism.len() > 64
                || !mechanism.iter().all(|byte| byte.is_ascii_graphic())
            {
                return false;
            }
            saw_mechanism = true;
            offset = next_offset;
        }
        false
    }

    fn postgres_parameter_status_message_payload(body: &[u8]) -> bool {
        let Some(after_name) = postgres_cstring_end(body, 0) else {
            return false;
        };
        let Some(after_value) = postgres_cstring_end(body, after_name) else {
            return false;
        };
        let name = &body[..after_name - 1];
        let value = &body[after_name..after_value - 1];
        after_value == body.len()
            && postgres_startup_parameter_key(name)
            && postgres_startup_parameter_value(value)
    }

    fn postgres_backend_key_data_message_payload(body: &[u8]) -> bool {
        if !(8..=260).contains(&body.len()) {
            return false;
        }
        let Some(pid) = read_u32_be(body, 0) else {
            return false;
        };
        pid != 0 && body[4..].iter().any(|byte| *byte != 0)
    }

    fn postgres_ready_for_query_message_payload(body: &[u8]) -> bool {
        body.len() == 1 && matches!(body[0], b'I' | b'T' | b'E')
    }

    fn postgres_command_complete_message_payload(body: &[u8]) -> bool {
        if body.len() < 2 || body.last() != Some(&0) {
            return false;
        }
        let command = &body[..body.len() - 1];
        command.len() <= 128
            && command
                .iter()
                .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
            && postgres_sql_statement(command)
    }

    fn postgres_error_or_notice_message_payload(body: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut field_count = 0_usize;
        let mut saw_message = false;
        while offset < body.len() {
            let field_type = body[offset];
            offset += 1;
            if field_type == 0 {
                return field_count > 0 && saw_message && offset == body.len();
            }
            if !field_type.is_ascii_alphabetic() {
                return false;
            }
            let Some(next_offset) = postgres_cstring_end(body, offset) else {
                return false;
            };
            let value = &body[offset..next_offset - 1];
            if !postgres_backend_text_field(value, false) {
                return false;
            }
            if field_type == b'M' {
                saw_message = true;
            }
            field_count += 1;
            if field_count > 32 {
                return false;
            }
            offset = next_offset;
        }
        false
    }

    fn postgres_query_message_payload(body: &[u8]) -> bool {
        if body.len() < 2 || body.last() != Some(&0) {
            return false;
        }
        postgres_sql_statement(&body[..body.len() - 1])
    }

    fn postgres_parse_message_payload(body: &[u8]) -> bool {
        let Some(after_statement_name) = postgres_cstring_end(body, 0) else {
            return false;
        };
        let Some(after_query) = postgres_cstring_end(body, after_statement_name) else {
            return false;
        };
        if after_query <= after_statement_name + 1
            || !postgres_sql_statement(&body[after_statement_name..after_query - 1])
        {
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

    fn postgres_sql_statement(statement: &[u8]) -> bool {
        if statement.is_empty()
            || statement.len() > 8192
            || !statement
                .iter()
                .all(|byte| !byte.is_ascii_control() || matches!(*byte, b'\t' | b'\n' | b'\r'))
        {
            return false;
        }
        let Some(statement) = postgres_sql_statement_start(statement) else {
            return false;
        };
        const KEYWORDS: &[&[u8]] = &[
            b"SELECT",
            b"INSERT",
            b"UPDATE",
            b"DELETE",
            b"MERGE",
            b"COPY",
            b"VALUES",
            b"CALL",
            b"DO",
            b"WITH",
            b"TABLE",
            b"SET",
            b"RESET",
            b"SHOW",
            b"BEGIN",
            b"START",
            b"COMMIT",
            b"END",
            b"ROLLBACK",
            b"SAVEPOINT",
            b"RELEASE",
            b"PREPARE",
            b"EXECUTE",
            b"DEALLOCATE",
            b"DECLARE",
            b"FETCH",
            b"MOVE",
            b"CLOSE",
            b"LISTEN",
            b"NOTIFY",
            b"UNLISTEN",
            b"LOAD",
            b"DISCARD",
            b"CHECKPOINT",
            b"VACUUM",
            b"ANALYZE",
            b"EXPLAIN",
            b"CREATE",
            b"ALTER",
            b"DROP",
            b"TRUNCATE",
            b"COMMENT",
            b"GRANT",
            b"REVOKE",
            b"LOCK",
            b"CLUSTER",
            b"REINDEX",
            b"REFRESH",
            b"IMPORT",
        ];
        KEYWORDS
            .iter()
            .any(|keyword| starts_ascii_keyword(statement, keyword))
    }

    fn postgres_sql_statement_start(mut statement: &[u8]) -> Option<&[u8]> {
        loop {
            statement = statement.trim_ascii_start();
            if statement.is_empty() {
                return None;
            }
            if statement.starts_with(b";") {
                statement = &statement[1..];
                continue;
            }
            if statement.starts_with(b"--") {
                let newline = statement.iter().position(|byte| *byte == b'\n')?;
                statement = &statement[newline + 1..];
                continue;
            }
            if statement.starts_with(b"/*") {
                let comment_end = statement
                    .windows(2)
                    .position(|window| window == b"*/")
                    .map(|offset| offset + 2)?;
                statement = &statement[comment_end..];
                continue;
            }
            return Some(statement);
        }
    }

    fn postgres_bind_message_payload(body: &[u8]) -> bool {
        let Some(after_portal) = postgres_cstring_end(body, 0) else {
            return false;
        };
        let Some(after_statement) = postgres_cstring_end(body, after_portal) else {
            return false;
        };
        let Some((request_format_count, after_request_formats)) =
            postgres_format_codes_payload(body, after_statement)
        else {
            return false;
        };
        let Some(parameter_count) =
            read_u16_be(body, after_request_formats).map(|count| count as usize)
        else {
            return false;
        };
        if !matches!(request_format_count, 0 | 1) && request_format_count != parameter_count {
            return false;
        }

        let Some(mut offset) = after_request_formats.checked_add(2) else {
            return false;
        };
        for _ in 0..parameter_count {
            let Some(raw_len) = read_u32_be(body, offset) else {
                return false;
            };
            offset += 4;
            if raw_len == u32::MAX {
                continue;
            }
            let Some(next_offset) = offset.checked_add(raw_len as usize) else {
                return false;
            };
            if next_offset > body.len() {
                return false;
            }
            offset = next_offset;
        }

        postgres_format_codes_payload(body, offset)
            .is_some_and(|(_, next_offset)| next_offset == body.len())
    }

    fn postgres_format_codes_payload(payload: &[u8], offset: usize) -> Option<(usize, usize)> {
        let count = read_u16_be(payload, offset)? as usize;
        let mut cursor = offset.checked_add(2)?;
        for _ in 0..count {
            let format_code = read_u16_be(payload, cursor)?;
            if !matches!(format_code, 0 | 1) {
                return None;
            }
            cursor = cursor.checked_add(2)?;
        }
        Some((count, cursor))
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

    fn postgres_backend_text_field(value: &[u8], allow_empty: bool) -> bool {
        (allow_empty || !value.is_empty())
            && value.len() <= 4096
            && value.iter().all(|byte| {
                byte.is_ascii_graphic() || matches!(*byte, b' ' | b'\t' | b'\n' | b'\r')
            })
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
        mysql_initial_handshake_payload(payload)
            || mysql_client_handshake_payload(payload)
            || mysql_command_packet_payload(payload)
            || mysql_server_response_packet_payload(payload)
    }

    const MYSQL_CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
    const MYSQL_CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
    const MYSQL_CLIENT_SSL: u32 = 0x0000_0800;
    const MYSQL_CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
    const MYSQL_CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
    const MYSQL_CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;
    const MYSQL_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;

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

    enum MysqlServerResponsePacketParse {
        Complete(usize),
        Incomplete,
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

    fn mysql_server_response_packet_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut packet_count = 0_usize;
        while offset < payload.len() {
            match mysql_server_response_packet(payload, offset) {
                Some(MysqlServerResponsePacketParse::Complete(next_offset)) => {
                    packet_count += 1;
                    if packet_count > 16 {
                        return false;
                    }
                    offset = next_offset;
                }
                Some(MysqlServerResponsePacketParse::Incomplete) => {
                    return packet_count > 0
                        && payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
                }
                None => return false,
            }
        }
        packet_count > 0
    }

    fn mysql_server_response_packet(
        payload: &[u8],
        offset: usize,
    ) -> Option<MysqlServerResponsePacketParse> {
        if payload.len().saturating_sub(offset) < 4 {
            return Some(MysqlServerResponsePacketParse::Incomplete);
        }
        let payload_len = mysql_packet_payload_len(payload, offset)?;
        let sequence_id = *payload.get(offset.checked_add(3)?)?;
        if sequence_id == 0 || sequence_id > MYSQL_MAX_PACKET_SEQUENCE_ID {
            return None;
        }
        let body_offset = offset.checked_add(4)?;
        let packet_end = body_offset.checked_add(payload_len)?;
        let Some(body) = payload.get(body_offset..packet_end) else {
            return Some(MysqlServerResponsePacketParse::Incomplete);
        };
        mysql_server_response_packet_body(payload_len, body)
            .then_some(MysqlServerResponsePacketParse::Complete(packet_end))
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

    fn mysql_client_handshake_payload(payload: &[u8]) -> bool {
        if payload.len() < 36 {
            return false;
        }
        let Some(payload_len) = mysql_packet_payload_len(payload, 0) else {
            return false;
        };
        let Some(&sequence_id) = payload.get(3) else {
            return false;
        };
        if !(1..=4).contains(&sequence_id) || payload_len < 32 {
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
        mysql_client_handshake_body(body, payload_len)
    }

    fn mysql_client_handshake_body(body: &[u8], payload_len: usize) -> bool {
        if body.len() < 32 {
            return false;
        }
        let Some(client_flags) = read_u32_le(body, 0) else {
            return false;
        };
        if client_flags & MYSQL_CLIENT_PROTOCOL_41 == 0
            || body[8] == 0
            || body[9..32].iter().any(|byte| *byte != 0)
        {
            return false;
        }
        if payload_len == 32 {
            return client_flags & MYSQL_CLIENT_SSL != 0;
        }
        let username_offset = 32;
        let Some(username_end) =
            mysql_client_null_terminated_field(body, username_offset, payload_len)
        else {
            return payload_len > body.len()
                && mysql_client_text_field(&body[username_offset..], 320, false);
        };
        if !mysql_client_text_field(&body[username_offset..username_end - 1], 320, false) {
            return false;
        }
        mysql_client_auth_response_payload(body, username_end, client_flags, payload_len)
    }

    fn mysql_client_auth_response_payload(
        body: &[u8],
        offset: usize,
        client_flags: u32,
        payload_len: usize,
    ) -> bool {
        let auth_end = if client_flags & MYSQL_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            let Some((auth_len, auth_offset)) = mysql_length_encoded_integer(body, offset) else {
                return payload_len > body.len();
            };
            let Some(auth_end) = auth_offset.checked_add(auth_len) else {
                return false;
            };
            if auth_end > payload_len {
                return false;
            }
            if body.len() < auth_end {
                return true;
            }
            auth_end
        } else if client_flags & MYSQL_CLIENT_SECURE_CONNECTION != 0 {
            let Some(&auth_len) = body.get(offset) else {
                return payload_len > body.len();
            };
            let Some(auth_offset) = offset.checked_add(1) else {
                return false;
            };
            let Some(auth_end) = auth_offset.checked_add(auth_len as usize) else {
                return false;
            };
            if auth_end > payload_len {
                return false;
            }
            if body.len() < auth_end {
                return true;
            }
            auth_end
        } else {
            let Some(auth_end) = mysql_client_null_terminated_field(body, offset, payload_len)
            else {
                return payload_len > body.len();
            };
            auth_end
        };

        mysql_client_handshake_tail_payload(body, auth_end, client_flags, payload_len)
    }

    fn mysql_client_handshake_tail_payload(
        body: &[u8],
        mut offset: usize,
        client_flags: u32,
        payload_len: usize,
    ) -> bool {
        if client_flags & MYSQL_CLIENT_CONNECT_WITH_DB != 0 {
            let Some(database_end) = mysql_client_null_terminated_field(body, offset, payload_len)
            else {
                return payload_len > body.len()
                    && mysql_client_text_field(&body[offset..], 1024, false);
            };
            if !mysql_client_text_field(&body[offset..database_end - 1], 1024, false) {
                return false;
            }
            offset = database_end;
        }
        if client_flags & MYSQL_CLIENT_PLUGIN_AUTH != 0 {
            let Some(plugin_end) = mysql_client_null_terminated_field(body, offset, payload_len)
            else {
                return payload_len > body.len()
                    && mysql_client_plugin_name_prefix(&body[offset..]);
            };
            if !mysql_client_plugin_name(&body[offset..plugin_end - 1]) {
                return false;
            }
            offset = plugin_end;
        }
        if client_flags & MYSQL_CLIENT_CONNECT_ATTRS != 0 {
            return mysql_client_connection_attrs_payload(body, offset, payload_len);
        }
        offset == payload_len || (payload_len > body.len() && offset == body.len())
    }

    fn mysql_client_null_terminated_field(
        body: &[u8],
        offset: usize,
        payload_len: usize,
    ) -> Option<usize> {
        if offset >= payload_len {
            return None;
        }
        let tail = body.get(offset..)?;
        let terminator = tail.iter().position(|byte| *byte == 0)?;
        let end = offset.checked_add(terminator)?.checked_add(1)?;
        (end <= payload_len).then_some(end)
    }

    fn mysql_client_text_field(value: &[u8], max: usize, allow_empty: bool) -> bool {
        (allow_empty || !value.is_empty())
            && value.len() <= max
            && value
                .iter()
                .all(|byte| !byte.is_ascii_control() && *byte != 0x7f)
    }

    fn mysql_client_plugin_name(value: &[u8]) -> bool {
        mysql_client_text_field(value, 128, false)
            && value
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
    }

    fn mysql_client_plugin_name_prefix(value: &[u8]) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
    }

    fn mysql_client_connection_attrs_payload(
        body: &[u8],
        offset: usize,
        payload_len: usize,
    ) -> bool {
        let Some((attrs_len, attrs_offset)) = mysql_length_encoded_integer(body, offset) else {
            return payload_len > body.len();
        };
        let Some(attrs_end) = attrs_offset.checked_add(attrs_len) else {
            return false;
        };
        if attrs_end > payload_len {
            return false;
        }
        if body.len() < attrs_end {
            let Some(attrs_prefix) = body.get(attrs_offset..) else {
                return false;
            };
            return payload_len > body.len()
                && attrs_prefix.len() <= attrs_len
                && mysql_client_connection_attrs_body(attrs_prefix, true);
        }
        let Some(attrs) = body.get(attrs_offset..attrs_end) else {
            return false;
        };
        mysql_client_connection_attrs_body(attrs, false)
            && (attrs_end == payload_len || (payload_len > body.len() && attrs_end == body.len()))
    }

    enum MysqlLengthEncodedStringParse<'a> {
        Complete(&'a [u8], usize),
        Incomplete,
    }

    fn mysql_client_connection_attrs_body(payload: &[u8], incomplete: bool) -> bool {
        let mut offset = 0_usize;
        let mut pair_count = 0_usize;
        while offset < payload.len() {
            let (key, value_offset) =
                match mysql_length_encoded_string_prefix(payload, offset, 1, 1024) {
                    Some(MysqlLengthEncodedStringParse::Complete(value, next_offset)) => {
                        (value, next_offset)
                    }
                    Some(MysqlLengthEncodedStringParse::Incomplete) => return incomplete,
                    None => return false,
                };
            if !mysql_client_text_field(key, 1024, false) {
                return false;
            }
            match mysql_length_encoded_string_prefix(payload, value_offset, 0, 4096) {
                Some(MysqlLengthEncodedStringParse::Complete(value, next_offset)) => {
                    if !mysql_client_text_field(value, 4096, true) {
                        return false;
                    }
                    pair_count += 1;
                    if pair_count > 64 {
                        return false;
                    }
                    offset = next_offset;
                }
                Some(MysqlLengthEncodedStringParse::Incomplete) => return incomplete,
                None => return false,
            }
        }
        true
    }

    fn mysql_length_encoded_string_prefix(
        payload: &[u8],
        offset: usize,
        min: usize,
        max: usize,
    ) -> Option<MysqlLengthEncodedStringParse<'_>> {
        let (len, data_offset) = match mysql_length_encoded_integer_prefix(payload, offset)? {
            MysqlLengthEncodedIntegerParse::Complete(value, next_offset) => (value, next_offset),
            MysqlLengthEncodedIntegerParse::Incomplete => {
                return Some(MysqlLengthEncodedStringParse::Incomplete)
            }
        };
        if len < min || len > max {
            return None;
        }
        let data_end = data_offset.checked_add(len)?;
        if payload.len() < data_end {
            let partial = payload.get(data_offset..)?;
            return mysql_client_text_field(partial, max, min == 0)
                .then_some(MysqlLengthEncodedStringParse::Incomplete);
        }
        Some(MysqlLengthEncodedStringParse::Complete(
            payload.get(data_offset..data_end)?,
            data_end,
        ))
    }

    enum MysqlLengthEncodedIntegerParse {
        Complete(usize, usize),
        Incomplete,
    }

    fn mysql_length_encoded_integer_prefix(
        payload: &[u8],
        offset: usize,
    ) -> Option<MysqlLengthEncodedIntegerParse> {
        let first = *payload.get(offset)?;
        match first {
            0x00..=0xfa => Some(MysqlLengthEncodedIntegerParse::Complete(
                first as usize,
                offset.checked_add(1)?,
            )),
            0xfc => {
                let value_offset = offset.checked_add(1)?;
                if payload.len().saturating_sub(value_offset) < 2 {
                    return Some(MysqlLengthEncodedIntegerParse::Incomplete);
                }
                read_u16_le(payload, value_offset).map(|value| {
                    MysqlLengthEncodedIntegerParse::Complete(value as usize, offset + 3)
                })
            }
            0xfd => {
                let value_offset = offset.checked_add(1)?;
                if payload.len().saturating_sub(value_offset) < 3 {
                    return Some(MysqlLengthEncodedIntegerParse::Incomplete);
                }
                read_u24_le(payload, value_offset)
                    .map(|value| MysqlLengthEncodedIntegerParse::Complete(value, offset + 4))
            }
            0xfe => {
                let value_offset = offset.checked_add(1)?;
                if payload.len().saturating_sub(value_offset) < 8 {
                    return Some(MysqlLengthEncodedIntegerParse::Incomplete);
                }
                let bytes = payload.get(value_offset..offset.checked_add(9)?)?;
                let value = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                (value <= usize::MAX as u64).then_some(MysqlLengthEncodedIntegerParse::Complete(
                    value as usize,
                    offset + 9,
                ))
            }
            _ => None,
        }
    }

    fn mysql_length_encoded_integer(payload: &[u8], offset: usize) -> Option<(usize, usize)> {
        match mysql_length_encoded_integer_prefix(payload, offset)? {
            MysqlLengthEncodedIntegerParse::Complete(value, next_offset) => {
                Some((value, next_offset))
            }
            MysqlLengthEncodedIntegerParse::Incomplete => None,
        }
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

    fn mysql_server_response_packet_body(payload_len: usize, body: &[u8]) -> bool {
        if body.len() != payload_len {
            return false;
        }
        match body.first().copied() {
            Some(0x00) => mysql_ok_packet_body(body),
            Some(0xff) => mysql_err_packet_body(body),
            Some(0xfe) if payload_len == 5 => mysql_eof_packet_body(body),
            Some(0xfe) => mysql_auth_switch_request_packet_body(body),
            _ => false,
        }
    }

    fn mysql_ok_packet_body(body: &[u8]) -> bool {
        if body.len() < 7 {
            return false;
        }
        let Some((_affected_rows, offset)) = mysql_length_encoded_integer(body, 1) else {
            return false;
        };
        let Some((_last_insert_id, offset)) = mysql_length_encoded_integer(body, offset) else {
            return false;
        };
        let Some(status_flags) = read_u16_le(body, offset) else {
            return false;
        };
        if status_flags & !0x7fff != 0 {
            return false;
        }
        let Some(info_offset) = offset.checked_add(4) else {
            return false;
        };
        let Some(info) = body.get(info_offset..) else {
            return false;
        };
        mysql_client_text_field(info, 4096, true)
    }

    fn mysql_err_packet_body(body: &[u8]) -> bool {
        if body.len() < 10 {
            return false;
        }
        let Some(error_code) = read_u16_le(body, 1) else {
            return false;
        };
        error_code != 0
            && body.get(3) == Some(&b'#')
            && body
                .get(4..9)
                .is_some_and(|state| state.iter().all(|byte| byte.is_ascii_alphanumeric()))
            && mysql_client_text_field(body.get(9..).unwrap_or_default(), 4096, false)
    }

    fn mysql_eof_packet_body(body: &[u8]) -> bool {
        if body.len() != 5 {
            return false;
        }
        read_u16_le(body, 3).is_some_and(|status_flags| status_flags & !0x7fff == 0)
    }

    fn mysql_auth_switch_request_packet_body(body: &[u8]) -> bool {
        if body.len() < 4 || body[0] != 0xfe {
            return false;
        }
        let Some(plugin_end) = mysql_client_null_terminated_field(body, 1, body.len()) else {
            return false;
        };
        let plugin = &body[1..plugin_end - 1];
        if !mysql_auth_plugin_name(plugin) {
            return false;
        }
        let auth_data = &body[plugin_end..];
        !auth_data.is_empty() && auth_data.len() <= 1024
    }

    fn mysql_auth_plugin_name(value: &[u8]) -> bool {
        matches!(
            value,
            b"mysql_native_password"
                | b"caching_sha2_password"
                | b"sha256_password"
                | b"mysql_clear_password"
                | b"auth_socket"
        )
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
        matches!(packet_type, 0x01 | 0x04 | 0x10 | 0x12)
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
            0x04 => mssql_server_token_stream_body(body, incomplete),
            0x10 => mssql_login7_body(body, declared_body_len, incomplete),
            0x12 => mssql_prelogin_body(body, declared_body_len, incomplete),
            _ => false,
        }
    }

    fn mssql_server_token_stream_body(body: &[u8], incomplete: bool) -> bool {
        let mut offset = 0_usize;
        let mut token_count = 0_usize;
        while offset < body.len() {
            let Some(&token) = body.get(offset) else {
                return incomplete && token_count > 0;
            };
            match token {
                0xfd..=0xff => {
                    let Some(token_end) = offset.checked_add(13) else {
                        return false;
                    };
                    let Some(token_body) = body.get(offset..token_end) else {
                        return incomplete && token_count > 0;
                    };
                    if !mssql_done_token_body(token_body) {
                        return false;
                    }
                    offset = token_end;
                }
                0xaa | 0xab => {
                    let Some(length_offset) = offset.checked_add(1) else {
                        return false;
                    };
                    let Some(length) = read_u16_le(body, length_offset).map(|value| value as usize)
                    else {
                        return incomplete && token_count > 0;
                    };
                    if length > 8192 {
                        return false;
                    }
                    let Some(token_body_offset) = offset.checked_add(3) else {
                        return false;
                    };
                    let Some(token_end) = token_body_offset.checked_add(length) else {
                        return false;
                    };
                    let Some(token_body) = body.get(token_body_offset..token_end) else {
                        return incomplete && token_count > 0;
                    };
                    if !mssql_error_or_info_token_body(token, token_body) {
                        return false;
                    }
                    offset = token_end;
                }
                _ => return false,
            }
            token_count += 1;
            if token_count > 32 {
                return false;
            }
        }
        token_count > 0
    }

    fn mssql_done_token_body(token: &[u8]) -> bool {
        if token.len() != 13 || !matches!(token[0], 0xfd..=0xff) {
            return false;
        }
        let Some(status) = read_u16_le(token, 1) else {
            return false;
        };
        status & !0x0137 == 0
    }

    fn mssql_error_or_info_token_body(token: u8, body: &[u8]) -> bool {
        if body.len() < 12 {
            return false;
        }
        let Some(number) = read_u32_le(body, 0) else {
            return false;
        };
        if token == 0xaa && number == 0 {
            return false;
        }
        let class = body[5];
        if class > 25 {
            return false;
        }

        let Some(message_chars) = read_u16_le(body, 6).map(|value| value as usize) else {
            return false;
        };
        let Some(message_bytes) = message_chars.checked_mul(2) else {
            return false;
        };
        if message_bytes == 0 || message_bytes > 4096 {
            return false;
        }
        let Some(mut offset) = 8_usize.checked_add(message_bytes) else {
            return false;
        };
        let Some(message) = body.get(8..offset) else {
            return false;
        };
        if !mssql_utf16le_text_field(message, false) {
            return false;
        }

        let Some(next_offset) = mssql_b_varchar_field(body, offset, 128, true) else {
            return false;
        };
        offset = next_offset;
        let Some(next_offset) = mssql_b_varchar_field(body, offset, 128, true) else {
            return false;
        };
        offset = next_offset;
        matches!(body.len().checked_sub(offset), Some(2 | 4))
    }

    fn mssql_b_varchar_field(
        payload: &[u8],
        offset: usize,
        max_chars: usize,
        allow_empty: bool,
    ) -> Option<usize> {
        let chars = *payload.get(offset)? as usize;
        if chars > max_chars || (!allow_empty && chars == 0) {
            return None;
        }
        let value_offset = offset.checked_add(1)?;
        let value_bytes = chars.checked_mul(2)?;
        let value_end = value_offset.checked_add(value_bytes)?;
        let value = payload.get(value_offset..value_end)?;
        mssql_utf16le_text_field(value, allow_empty).then_some(value_end)
    }

    fn mssql_utf16le_text_field(value: &[u8], allow_empty: bool) -> bool {
        (allow_empty || !value.is_empty())
            && value.len().is_multiple_of(2)
            && value.chunks_exact(2).all(|chunk| {
                chunk[1] == 0
                    && (chunk[0].is_ascii_graphic()
                        || matches!(chunk[0], b' ' | b'\t' | b'\n' | b'\r'))
            })
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

    fn clickhouse_native_payload(payload: &[u8], native_port_hint: bool) -> bool {
        clickhouse_native_client_hello_payload(payload)
            || clickhouse_native_server_hello_payload(payload)
            || clickhouse_native_query_payload(payload)
            || clickhouse_native_server_exception_payload(payload)
            || clickhouse_native_server_progress_payload(payload, native_port_hint)
            || (native_port_hint && clickhouse_native_empty_server_payload(payload))
    }

    fn clickhouse_native_client_hello_payload(payload: &[u8]) -> bool {
        let Some((packet_type, mut offset)) = clickhouse_uvarint(payload, 0) else {
            return false;
        };
        if packet_type != 0 {
            return false;
        }

        let Some((client_name, next_offset)) = clickhouse_string(payload, offset, 128) else {
            return false;
        };
        if !clickhouse_text_field(client_name, false) {
            return false;
        }
        offset = next_offset;

        let Some((major, next_offset)) = clickhouse_uvarint(payload, offset) else {
            return false;
        };
        if major > 100 {
            return false;
        }
        offset = next_offset;

        let Some((minor, next_offset)) = clickhouse_uvarint(payload, offset) else {
            return false;
        };
        if minor > 1000 {
            return false;
        }
        offset = next_offset;

        let Some((protocol_revision, next_offset)) = clickhouse_uvarint(payload, offset) else {
            return false;
        };
        if !(54_000..=1_000_000).contains(&protocol_revision) {
            return false;
        }
        offset = next_offset;

        let Some((database, next_offset)) = clickhouse_string(payload, offset, 256) else {
            return false;
        };
        if !clickhouse_text_field(database, false) {
            return false;
        }
        offset = next_offset;

        let Some((user, next_offset)) = clickhouse_string(payload, offset, 256) else {
            return false;
        };
        if !clickhouse_text_field(user, false) {
            return false;
        }
        offset = next_offset;

        let Some((password, mut offset)) = clickhouse_string(payload, offset, 4096) else {
            return false;
        };
        if !clickhouse_text_field(password, true) {
            return false;
        }

        if offset == payload.len() || payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES {
            return true;
        }

        for _ in 0..2 {
            let Some((field, next_offset)) = clickhouse_string(payload, offset, 1024) else {
                return false;
            };
            if !clickhouse_text_field(field, true) {
                return false;
            }
            offset = next_offset;
            if offset == payload.len() {
                return true;
            }
        }
        false
    }

    fn clickhouse_native_server_hello_payload(payload: &[u8]) -> bool {
        let Some((packet_type, mut offset)) = clickhouse_uvarint(payload, 0) else {
            return false;
        };
        if packet_type != 0 {
            return false;
        }

        let Some((server_name, next_offset)) = clickhouse_string(payload, offset, 128) else {
            return false;
        };
        if !clickhouse_text_field(server_name, false) {
            return false;
        }
        offset = next_offset;

        let Some((major, next_offset)) = clickhouse_uvarint(payload, offset) else {
            return false;
        };
        if major > 100 {
            return false;
        }
        offset = next_offset;

        let Some((minor, next_offset)) = clickhouse_uvarint(payload, offset) else {
            return false;
        };
        if minor > 1000 {
            return false;
        }
        offset = next_offset;

        let Some((revision, next_offset)) = clickhouse_uvarint(payload, offset) else {
            return false;
        };
        if !(54_000..=1_000_000).contains(&revision) {
            return false;
        }
        offset = next_offset;

        let Some((timezone, next_offset)) = clickhouse_string(payload, offset, 128) else {
            return false;
        };
        if !clickhouse_text_field(timezone, false) {
            return false;
        }
        offset = next_offset;

        let Some((display_name, next_offset)) = clickhouse_string(payload, offset, 128) else {
            return false;
        };
        if !clickhouse_text_field(display_name, false) {
            return false;
        }
        offset = next_offset;

        let Some((patch, offset)) = clickhouse_uvarint(payload, offset) else {
            return false;
        };
        patch <= 1000
            && offset == payload.len()
            && (ascii_contains_ignore_case(server_name, b"clickhouse")
                || ascii_contains_ignore_case(display_name, b"clickhouse"))
    }

    fn clickhouse_native_query_payload(payload: &[u8]) -> bool {
        let Some((packet_type, mut offset)) = clickhouse_uvarint(payload, 0) else {
            return false;
        };
        if packet_type != 1 {
            return false;
        }

        let Some((query_id, next_offset)) = clickhouse_string(payload, offset, 256) else {
            return false;
        };
        if !clickhouse_text_field(query_id, true) {
            return false;
        }
        offset = next_offset;

        let Some(next_offset) = clickhouse_client_info(payload, offset) else {
            return false;
        };
        offset = next_offset;

        let Some(next_offset) = clickhouse_settings(payload, offset) else {
            return false;
        };
        offset = next_offset;

        let Some((secret, next_offset)) = clickhouse_string(payload, offset, 4096) else {
            return false;
        };
        if !clickhouse_text_field(secret, true) {
            return false;
        }
        offset = next_offset;

        let Some((stage, next_offset)) = clickhouse_uvarint(payload, offset) else {
            return false;
        };
        if stage > 2 {
            return false;
        }
        offset = next_offset;

        let Some((compression, next_offset)) = clickhouse_uvarint(payload, offset) else {
            return false;
        };
        if compression > 1 {
            return false;
        }
        offset = next_offset;

        let Some(query) = clickhouse_string_prefix(payload, offset, 65_536) else {
            return false;
        };
        clickhouse_sql_statement(query.value, query.complete)
            && (!query.complete || query.next_offset == payload.len())
    }

    fn clickhouse_native_server_exception_payload(payload: &[u8]) -> bool {
        let Some((packet_type, offset)) = clickhouse_uvarint(payload, 0) else {
            return false;
        };
        if packet_type != 2 {
            return false;
        }
        matches!(
            clickhouse_server_exception_frame(payload, offset, 0),
            Some(end) if end == payload.len()
        )
    }

    fn clickhouse_server_exception_frame(
        payload: &[u8],
        mut offset: usize,
        depth: usize,
    ) -> Option<usize> {
        if depth > 4 {
            return None;
        }

        let code = read_u32_le(payload, offset)?;
        if code == 0 || code > 1_000_000 {
            return None;
        }
        offset = offset.checked_add(4)?;

        let (name, next) = clickhouse_string(payload, offset, 512)?;
        if !clickhouse_text_field(name, false) || !ascii_contains_ignore_case(name, b"exception") {
            return None;
        }
        offset = next;

        let (message, next) = clickhouse_string(payload, offset, 4096)?;
        if !clickhouse_exception_text_field(message, false) {
            return None;
        }
        offset = next;

        let (stack_trace, next) = clickhouse_string(payload, offset, 16_384)?;
        if !clickhouse_exception_text_field(stack_trace, true) {
            return None;
        }
        offset = next;

        let nested = *payload.get(offset)?;
        if nested > 1 {
            return None;
        }
        offset = offset.checked_add(1)?;
        if nested == 0 {
            Some(offset)
        } else {
            clickhouse_server_exception_frame(payload, offset, depth + 1)
        }
    }

    fn clickhouse_native_server_progress_payload(payload: &[u8], native_port_hint: bool) -> bool {
        let Some((packet_type, mut offset)) = clickhouse_uvarint(payload, 0) else {
            return false;
        };
        if packet_type != 3 {
            return false;
        }

        let mut counters = [0_u64; 5];
        for index in 0..5 {
            let Some((value, next)) = clickhouse_uvarint(payload, offset) else {
                return false;
            };
            if value > 1_000_000_000_000_000 {
                return false;
            }
            counters[index] = value;
            offset = next;
        }

        let read_progress = counters[0] > 0 && counters[1] >= counters[0];
        let write_progress = native_port_hint && (counters[3] > 0 || counters[4] > 0);
        (read_progress || write_progress) && offset == payload.len()
    }

    fn clickhouse_native_empty_server_payload(payload: &[u8]) -> bool {
        let Some((packet_type, offset)) = clickhouse_uvarint(payload, 0) else {
            return false;
        };
        matches!(packet_type, 4 | 5) && offset == payload.len()
    }

    fn clickhouse_client_info(payload: &[u8], mut offset: usize) -> Option<usize> {
        let query_kind = *payload.get(offset)?;
        if query_kind > 2 {
            return None;
        }
        offset = offset.checked_add(1)?;

        let (initial_user, next) = clickhouse_string(payload, offset, 256)?;
        if !clickhouse_text_field(initial_user, true) {
            return None;
        }
        offset = next;

        let (initial_query_id, next) = clickhouse_string(payload, offset, 256)?;
        if !clickhouse_text_field(initial_query_id, true) {
            return None;
        }
        offset = next;

        let (initial_address, next) = clickhouse_string(payload, offset, 256)?;
        if !clickhouse_text_field(initial_address, true) {
            return None;
        }
        offset = next;

        offset = offset.checked_add(8)?;
        payload.get(offset - 8..offset)?;

        let interface = *payload.get(offset)?;
        if !matches!(interface, 1 | 2) {
            return None;
        }
        offset = offset.checked_add(1)?;

        let (os_user, next) = clickhouse_string(payload, offset, 256)?;
        if !clickhouse_text_field(os_user, true) {
            return None;
        }
        offset = next;

        let (client_hostname, next) = clickhouse_string(payload, offset, 256)?;
        if !clickhouse_text_field(client_hostname, true) {
            return None;
        }
        offset = next;

        let (client_name, next) = clickhouse_string(payload, offset, 128)?;
        if !clickhouse_text_field(client_name, false) {
            return None;
        }
        offset = next;

        let (major, next) = clickhouse_uvarint(payload, offset)?;
        if major > 100 {
            return None;
        }
        offset = next;

        let (minor, next) = clickhouse_uvarint(payload, offset)?;
        if minor > 1000 {
            return None;
        }
        offset = next;

        let (revision, next) = clickhouse_uvarint(payload, offset)?;
        if !(54_000..=1_000_000).contains(&revision) {
            return None;
        }
        offset = next;

        let (quota_key, next) = clickhouse_string(payload, offset, 256)?;
        if !clickhouse_text_field(quota_key, true) {
            return None;
        }
        offset = next;

        let (distributed_depth, next) = clickhouse_uvarint(payload, offset)?;
        if distributed_depth > 1024 {
            return None;
        }
        offset = next;

        let (patch, next) = clickhouse_uvarint(payload, offset)?;
        if patch > 1000 {
            return None;
        }
        offset = next;

        let otel = *payload.get(offset)?;
        if otel > 1 {
            return None;
        }
        offset = offset.checked_add(1)?;
        if otel == 0 {
            return Some(offset);
        }

        offset = offset.checked_add(24)?;
        payload.get(offset - 24..offset)?;

        let (trace_state, next) = clickhouse_string(payload, offset, 1024)?;
        if !clickhouse_text_field(trace_state, true) {
            return None;
        }
        offset = next;

        payload.get(offset)?;
        offset.checked_add(1)
    }

    fn clickhouse_settings(payload: &[u8], mut offset: usize) -> Option<usize> {
        for _ in 0..64 {
            let (key, next) = clickhouse_string(payload, offset, 256)?;
            offset = next;
            let (value, next) = clickhouse_string(payload, offset, 4096)?;
            offset = next;
            if key.is_empty() && value.is_empty() {
                return Some(offset);
            }
            if key.is_empty()
                || !clickhouse_text_field(key, false)
                || !clickhouse_text_field(value, true)
            {
                return None;
            }
            let important = *payload.get(offset)?;
            if important > 1 {
                return None;
            }
            offset = offset.checked_add(1)?;
        }
        None
    }

    struct ClickHouseStringPrefix<'a> {
        value: &'a [u8],
        next_offset: usize,
        complete: bool,
    }

    fn clickhouse_string_prefix(
        payload: &[u8],
        offset: usize,
        max_len: usize,
    ) -> Option<ClickHouseStringPrefix<'_>> {
        let (len, value_offset) = clickhouse_uvarint(payload, offset)?;
        let len = usize::try_from(len).ok()?;
        if len > max_len {
            return None;
        }
        let value_end = value_offset.checked_add(len)?;
        if let Some(value) = payload.get(value_offset..value_end) {
            return Some(ClickHouseStringPrefix {
                value,
                next_offset: value_end,
                complete: true,
            });
        }
        if payload.len() < PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES || value_offset >= payload.len() {
            return None;
        }
        Some(ClickHouseStringPrefix {
            value: payload.get(value_offset..)?,
            next_offset: payload.len(),
            complete: false,
        })
    }

    fn clickhouse_string(payload: &[u8], offset: usize, max_len: usize) -> Option<(&[u8], usize)> {
        let (len, value_offset) = clickhouse_uvarint(payload, offset)?;
        let len = usize::try_from(len).ok()?;
        if len > max_len {
            return None;
        }
        let value_end = value_offset.checked_add(len)?;
        Some((payload.get(value_offset..value_end)?, value_end))
    }

    fn clickhouse_uvarint(payload: &[u8], offset: usize) -> Option<(u64, usize)> {
        let mut value = 0_u64;
        for (index, byte) in payload.get(offset..)?.iter().take(10).enumerate() {
            value |= ((byte & 0x7f) as u64).checked_shl((7 * index) as u32)?;
            if byte & 0x80 == 0 {
                return Some((value, offset + index + 1));
            }
        }
        None
    }

    fn clickhouse_text_field(value: &[u8], allow_empty: bool) -> bool {
        (allow_empty || !value.is_empty())
            && value
                .iter()
                .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    }

    fn clickhouse_exception_text_field(value: &[u8], allow_empty: bool) -> bool {
        (allow_empty || !value.is_empty())
            && value.iter().all(|byte| {
                byte.is_ascii_graphic() || matches!(*byte, b' ' | b'\t' | b'\n' | b'\r')
            })
    }

    fn clickhouse_sql_statement(statement: &[u8], _complete: bool) -> bool {
        if statement.is_empty()
            || statement.len() > 65_536
            || !statement
                .iter()
                .all(|byte| !byte.is_ascii_control() || matches!(*byte, b'\t' | b'\n' | b'\r'))
        {
            return false;
        }
        let Some(statement) = postgres_sql_statement_start(statement) else {
            return false;
        };
        const KEYWORDS: &[&[u8]] = &[
            b"SELECT",
            b"INSERT",
            b"UPDATE",
            b"DELETE",
            b"CREATE",
            b"ALTER",
            b"DROP",
            b"TRUNCATE",
            b"RENAME",
            b"ATTACH",
            b"DETACH",
            b"OPTIMIZE",
            b"CHECK",
            b"KILL",
            b"SYSTEM",
            b"SHOW",
            b"DESCRIBE",
            b"DESC",
            b"EXPLAIN",
            b"EXISTS",
            b"USE",
            b"SET",
            b"WATCH",
            b"GRANT",
            b"REVOKE",
            b"BACKUP",
            b"RESTORE",
        ];
        KEYWORDS
            .iter()
            .any(|keyword| starts_ascii_keyword(statement, keyword))
    }

    fn redis_payload(payload: &[u8]) -> bool {
        redis_resp_array_payload(payload)
            || redis_inline_command_payload(payload)
            || redis_resp_response_payload(payload)
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

    enum RedisRespResponseParse {
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

    fn redis_resp_response_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut response_count = 0_usize;
        while offset < payload.len() {
            match redis_resp_response_frame(payload, offset) {
                Some(RedisRespResponseParse::Complete(next_offset)) => {
                    response_count += 1;
                    if response_count > 32 {
                        return false;
                    }
                    offset = next_offset;
                }
                Some(RedisRespResponseParse::Incomplete) => {
                    return response_count > 0
                        || payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
                }
                None => return false,
            }
        }
        response_count > 0
    }

    fn redis_resp_response_frame(payload: &[u8], offset: usize) -> Option<RedisRespResponseParse> {
        redis_resp_response_frame_with_depth(payload, offset, 0)
    }

    fn redis_resp_response_frame_with_depth(
        payload: &[u8],
        offset: usize,
        depth: usize,
    ) -> Option<RedisRespResponseParse> {
        match *payload.get(offset)? {
            b'+' => redis_resp_simple_string_frame(payload, offset),
            b'-' => redis_resp_error_frame(payload, offset),
            b':' => redis_resp_integer_frame(payload, offset),
            b'$' => redis_resp_bulk_string_frame(payload, offset),
            b'*' => redis_resp_null_array_frame(payload, offset),
            b'%' | b'~' | b'>' => redis_resp_aggregate_frame(payload, offset, depth),
            b'|' => redis_resp_attribute_frame(payload, offset, depth),
            b'_' => redis_resp_null_frame(payload, offset),
            b'#' => redis_resp_bool_frame(payload, offset),
            b',' => redis_resp_double_frame(payload, offset),
            b'(' => redis_resp_big_number_frame(payload, offset),
            b'!' => redis_resp_blob_error_frame(payload, offset),
            b'=' => redis_resp_verbatim_string_frame(payload, offset),
            _ => None,
        }
    }

    fn redis_resp_simple_string_frame(
        payload: &[u8],
        offset: usize,
    ) -> Option<RedisRespResponseParse> {
        let line_offset = offset.checked_add(1)?;
        match redis_resp_line(payload, line_offset, 1024) {
            Some((line, next_offset)) => {
                redis_simple_reply(line).then_some(RedisRespResponseParse::Complete(next_offset))
            }
            None if redis_resp_line_incomplete(payload, line_offset, 1024) => {
                Some(RedisRespResponseParse::Incomplete)
            }
            None => None,
        }
    }

    fn redis_resp_error_frame(payload: &[u8], offset: usize) -> Option<RedisRespResponseParse> {
        let line_offset = offset.checked_add(1)?;
        match redis_resp_line(payload, line_offset, 4096) {
            Some((line, next_offset)) => {
                redis_error_reply(line).then_some(RedisRespResponseParse::Complete(next_offset))
            }
            None if redis_resp_line_incomplete(payload, line_offset, 4096) => {
                Some(RedisRespResponseParse::Incomplete)
            }
            None => None,
        }
    }

    fn redis_resp_integer_frame(payload: &[u8], offset: usize) -> Option<RedisRespResponseParse> {
        match redis_signed_decimal_crlf(payload, offset.checked_add(1)?) {
            Some(next_offset) => Some(RedisRespResponseParse::Complete(next_offset)),
            None if redis_signed_decimal_crlf_incomplete(payload, offset.checked_add(1)?) => {
                Some(RedisRespResponseParse::Incomplete)
            }
            None => None,
        }
    }

    fn redis_resp_bulk_string_frame(
        payload: &[u8],
        offset: usize,
    ) -> Option<RedisRespResponseParse> {
        const MAX_BULK_STRING_LEN: usize = 512 * 1024 * 1024;

        if payload.get(offset.checked_add(1)?) == Some(&b'-') {
            let len_offset = offset.checked_add(2)?;
            return match redis_decimal_crlf(payload, len_offset, 1, 1) {
                Some((_, next_offset)) => Some(RedisRespResponseParse::Complete(next_offset)),
                None if redis_decimal_crlf_incomplete(payload, len_offset, 1) => {
                    Some(RedisRespResponseParse::Incomplete)
                }
                None => None,
            };
        }

        match redis_bulk_string_prefix(payload, offset, 0, MAX_BULK_STRING_LEN)? {
            RedisBulkStringParse::Complete(next_offset) => {
                Some(RedisRespResponseParse::Complete(next_offset))
            }
            RedisBulkStringParse::Incomplete => Some(RedisRespResponseParse::Incomplete),
        }
    }

    fn redis_resp_aggregate_frame(
        payload: &[u8],
        offset: usize,
        depth: usize,
    ) -> Option<RedisRespResponseParse> {
        const MAX_AGGREGATE_LEN: usize = 1024;
        const MAX_AGGREGATE_DEPTH: usize = 4;

        if depth >= MAX_AGGREGATE_DEPTH {
            return None;
        }

        let marker = *payload.get(offset)?;
        let len_offset = offset.checked_add(1)?;

        let (len, mut item_offset) =
            match redis_decimal_crlf(payload, len_offset, 0, MAX_AGGREGATE_LEN) {
                Some(header) => header,
                None if redis_decimal_crlf_incomplete(payload, len_offset, MAX_AGGREGATE_LEN) => {
                    return Some(RedisRespResponseParse::Incomplete);
                }
                None => return None,
            };
        let item_count = if marker == b'%' {
            len.checked_mul(2)?
        } else {
            len
        };
        for _ in 0..item_count {
            match redis_resp_response_frame_with_depth(payload, item_offset, depth + 1)? {
                RedisRespResponseParse::Complete(next_offset) => item_offset = next_offset,
                RedisRespResponseParse::Incomplete => {
                    return Some(RedisRespResponseParse::Incomplete);
                }
            }
        }
        Some(RedisRespResponseParse::Complete(item_offset))
    }

    fn redis_resp_attribute_frame(
        payload: &[u8],
        offset: usize,
        depth: usize,
    ) -> Option<RedisRespResponseParse> {
        const MAX_ATTRIBUTE_LEN: usize = 128;
        const MAX_AGGREGATE_DEPTH: usize = 4;

        if depth >= MAX_AGGREGATE_DEPTH || payload.get(offset) != Some(&b'|') {
            return None;
        }

        let len_offset = offset.checked_add(1)?;
        let (len, mut item_offset) =
            match redis_decimal_crlf(payload, len_offset, 1, MAX_ATTRIBUTE_LEN) {
                Some(header) => header,
                None if redis_decimal_crlf_incomplete(payload, len_offset, MAX_ATTRIBUTE_LEN) => {
                    return Some(RedisRespResponseParse::Incomplete);
                }
                None => return None,
            };
        for _ in 0..len.checked_mul(2)? {
            match redis_resp_response_frame_with_depth(payload, item_offset, depth + 1)? {
                RedisRespResponseParse::Complete(next_offset) => item_offset = next_offset,
                RedisRespResponseParse::Incomplete => {
                    return Some(RedisRespResponseParse::Incomplete);
                }
            }
        }
        redis_resp_response_frame_with_depth(payload, item_offset, depth + 1)
    }

    fn redis_resp_null_array_frame(
        payload: &[u8],
        offset: usize,
    ) -> Option<RedisRespResponseParse> {
        if payload.get(offset) != Some(&b'*') {
            return None;
        }
        let value_offset = offset.checked_add(2)?;
        if payload.get(offset.checked_add(1)?) != Some(&b'-') {
            return None;
        }
        match redis_decimal_crlf(payload, value_offset, 1, 1) {
            Some((_len, next_offset)) => Some(RedisRespResponseParse::Complete(next_offset)),
            None if redis_decimal_crlf_incomplete(payload, value_offset, 1) => {
                Some(RedisRespResponseParse::Incomplete)
            }
            None => None,
        }
    }

    fn redis_resp_null_frame(payload: &[u8], offset: usize) -> Option<RedisRespResponseParse> {
        (payload.get(offset..offset.checked_add(3)?)? == b"_\r\n")
            .then_some(RedisRespResponseParse::Complete(offset + 3))
    }

    fn redis_resp_bool_frame(payload: &[u8], offset: usize) -> Option<RedisRespResponseParse> {
        let frame = payload.get(offset..offset.checked_add(4)?)?;
        (frame == b"#t\r\n" || frame == b"#f\r\n")
            .then_some(RedisRespResponseParse::Complete(offset + 4))
    }

    fn redis_resp_double_frame(payload: &[u8], offset: usize) -> Option<RedisRespResponseParse> {
        let line_offset = offset.checked_add(1)?;
        match redis_resp_line(payload, line_offset, 128) {
            Some((line, next_offset)) => {
                redis_double_value(line).then_some(RedisRespResponseParse::Complete(next_offset))
            }
            None if redis_resp_line_incomplete(payload, line_offset, 128) => {
                Some(RedisRespResponseParse::Incomplete)
            }
            None => None,
        }
    }

    fn redis_resp_big_number_frame(
        payload: &[u8],
        offset: usize,
    ) -> Option<RedisRespResponseParse> {
        let line_offset = offset.checked_add(1)?;
        match redis_resp_line(payload, line_offset, 1024) {
            Some((line, next_offset)) => redis_big_number_value(line)
                .then_some(RedisRespResponseParse::Complete(next_offset)),
            None if redis_resp_line_incomplete(payload, line_offset, 1024) => {
                Some(RedisRespResponseParse::Incomplete)
            }
            None => None,
        }
    }

    fn redis_resp_blob_error_frame(
        payload: &[u8],
        offset: usize,
    ) -> Option<RedisRespResponseParse> {
        const MAX_BLOB_ERROR_LEN: usize = 4096;

        if payload.get(offset) != Some(&b'!') {
            return None;
        }
        let (len, data_offset) =
            match redis_decimal_crlf(payload, offset.checked_add(1)?, 1, MAX_BLOB_ERROR_LEN) {
                Some(header) => header,
                None if redis_decimal_crlf_incomplete(
                    payload,
                    offset.checked_add(1)?,
                    MAX_BLOB_ERROR_LEN,
                ) =>
                {
                    return Some(RedisRespResponseParse::Incomplete);
                }
                None => return None,
            };
        let data_end = data_offset.checked_add(len)?;
        let crlf_end = data_end.checked_add(2)?;
        if payload.len() < data_end {
            return Some(RedisRespResponseParse::Incomplete);
        }
        if payload.len() < crlf_end {
            return match payload.get(data_end..) {
                Some(b"") | Some(b"\r") => Some(RedisRespResponseParse::Incomplete),
                _ => None,
            };
        }
        if payload.get(data_end..crlf_end)? != b"\r\n" {
            return None;
        }
        let data = payload.get(data_offset..data_end)?;
        redis_error_reply(data).then_some(RedisRespResponseParse::Complete(crlf_end))
    }

    fn redis_resp_verbatim_string_frame(
        payload: &[u8],
        offset: usize,
    ) -> Option<RedisRespResponseParse> {
        const MAX_VERBATIM_STRING_LEN: usize = 512 * 1024 * 1024;

        if payload.get(offset) != Some(&b'=') {
            return None;
        }
        let (len, data_offset) =
            match redis_decimal_crlf(payload, offset.checked_add(1)?, 4, MAX_VERBATIM_STRING_LEN) {
                Some(header) => header,
                None if redis_decimal_crlf_incomplete(
                    payload,
                    offset.checked_add(1)?,
                    MAX_VERBATIM_STRING_LEN,
                ) =>
                {
                    return Some(RedisRespResponseParse::Incomplete);
                }
                None => return None,
            };
        let data_end = data_offset.checked_add(len)?;
        let crlf_end = data_end.checked_add(2)?;
        if payload.len() < data_end {
            return Some(RedisRespResponseParse::Incomplete);
        }
        if payload.len() < crlf_end {
            return match payload.get(data_end..) {
                Some(b"") | Some(b"\r") => Some(RedisRespResponseParse::Incomplete),
                _ => None,
            };
        }
        if payload.get(data_end..crlf_end)? != b"\r\n" {
            return None;
        }
        let data = payload.get(data_offset..data_end)?;
        (data.get(3) == Some(&b':')
            && data[..3]
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && redis_resp_text(&data[4..]))
        .then_some(RedisRespResponseParse::Complete(crlf_end))
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

    fn redis_resp_line(payload: &[u8], offset: usize, max_len: usize) -> Option<(&[u8], usize)> {
        let tail = payload.get(offset..)?;
        let line_end = tail.windows(2).position(|window| window == b"\r\n")?;
        if line_end == 0 || line_end > max_len {
            return None;
        }
        let value = &tail[..line_end];
        redis_resp_text(value).then_some((value, offset + line_end + 2))
    }

    fn redis_resp_line_incomplete(payload: &[u8], offset: usize, max_len: usize) -> bool {
        let Some(tail) = payload.get(offset..) else {
            return true;
        };
        !tail.is_empty()
            && tail.len() <= max_len
            && !tail.windows(2).any(|window| window == b"\r\n")
            && redis_resp_text(tail)
    }

    fn redis_resp_text(value: &[u8]) -> bool {
        !value.is_empty()
            && value
                .iter()
                .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    }

    fn redis_double_value(value: &[u8]) -> bool {
        if value.eq_ignore_ascii_case(b"inf")
            || value.eq_ignore_ascii_case(b"-inf")
            || value.eq_ignore_ascii_case(b"nan")
        {
            return true;
        }

        let mut offset = usize::from(value.first() == Some(&b'-'));
        if offset == value.len() {
            return false;
        }
        let integer_start = offset;
        while value.get(offset).is_some_and(u8::is_ascii_digit) {
            offset += 1;
        }
        let integer_digits = offset - integer_start;
        let mut fraction_digits = 0_usize;
        if value.get(offset) == Some(&b'.') {
            offset += 1;
            let fraction_start = offset;
            while value.get(offset).is_some_and(u8::is_ascii_digit) {
                offset += 1;
            }
            fraction_digits = offset - fraction_start;
        }
        if integer_digits + fraction_digits == 0 {
            return false;
        }
        if matches!(value.get(offset), Some(b'e' | b'E')) {
            offset += 1;
            if matches!(value.get(offset), Some(b'+' | b'-')) {
                offset += 1;
            }
            let exponent_start = offset;
            while value.get(offset).is_some_and(u8::is_ascii_digit) {
                offset += 1;
            }
            if offset == exponent_start {
                return false;
            }
        }
        offset == value.len()
    }

    fn redis_big_number_value(value: &[u8]) -> bool {
        let mut offset = usize::from(value.first() == Some(&b'-'));
        if offset == value.len() {
            return false;
        }
        let digit_start = offset;
        while value.get(offset).is_some_and(u8::is_ascii_digit) {
            offset += 1;
        }
        offset > digit_start && offset == value.len()
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

    fn redis_signed_decimal_crlf(payload: &[u8], mut offset: usize) -> Option<usize> {
        if payload.get(offset) == Some(&b'-') {
            offset = offset.checked_add(1)?;
        }
        let mut digits = 0_usize;
        loop {
            let byte = *payload.get(offset)?;
            match byte {
                b'0'..=b'9' => {
                    digits += 1;
                    if digits > 19 {
                        return None;
                    }
                    offset += 1;
                }
                b'\r' if payload.get(offset + 1) == Some(&b'\n') => {
                    return (digits > 0).then_some(offset + 2);
                }
                _ => return None,
            }
        }
    }

    fn redis_signed_decimal_crlf_incomplete(payload: &[u8], mut offset: usize) -> bool {
        if offset >= payload.len() {
            return true;
        }
        if payload.get(offset) == Some(&b'-') {
            offset += 1;
        }
        let mut digits = 0_usize;
        loop {
            let Some(byte) = payload.get(offset) else {
                return digits > 0;
            };
            match *byte {
                b'0'..=b'9' => {
                    digits += 1;
                    if digits > 19 {
                        return false;
                    }
                    offset += 1;
                }
                b'\r' if payload.get(offset + 1).is_none() => return digits > 0,
                _ => return false,
            }
        }
    }

    fn redis_simple_reply(value: &[u8]) -> bool {
        value.eq_ignore_ascii_case(b"OK")
            || value.eq_ignore_ascii_case(b"PONG")
            || value.eq_ignore_ascii_case(b"QUEUED")
            || value
                .get(..11)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"FULLRESYNC "))
    }

    fn redis_error_reply(value: &[u8]) -> bool {
        let code_end = value
            .iter()
            .position(|byte| byte.is_ascii_whitespace())
            .unwrap_or(value.len());
        let code = &value[..code_end];
        !code.is_empty()
            && code
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || *byte == b'_')
            && redis_error_code(code)
    }

    fn redis_error_code(code: &[u8]) -> bool {
        const CODES: &[&[u8]] = &[
            b"ERR",
            b"WRONGTYPE",
            b"NOAUTH",
            b"NOPERM",
            b"WRONGPASS",
            b"DENIED",
            b"MOVED",
            b"ASK",
            b"TRYAGAIN",
            b"CLUSTERDOWN",
            b"READONLY",
            b"MASTERDOWN",
            b"LOADING",
            b"BUSY",
            b"NOSCRIPT",
            b"OOM",
            b"EXECABORT",
            b"CROSSSLOT",
        ];
        CODES.iter().any(|known| code.eq_ignore_ascii_case(known))
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
        memcached_text_payload(payload)
            || memcached_text_response_payload(payload)
            || memcached_binary_payload(payload)
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

    enum MemcachedTextResponseParse {
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

    fn memcached_text_response_payload(payload: &[u8]) -> bool {
        let mut offset = 0_usize;
        let mut response_count = 0_usize;
        while offset < payload.len() {
            match memcached_text_response(payload, offset) {
                Some(MemcachedTextResponseParse::Complete(next_offset)) => {
                    response_count += 1;
                    if response_count > 64 {
                        return false;
                    }
                    offset = next_offset;
                }
                Some(MemcachedTextResponseParse::Incomplete) => {
                    return response_count > 0
                        || payload.len() >= PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES;
                }
                None => return false,
            }
        }
        response_count > 0
    }

    fn memcached_text_response(
        payload: &[u8],
        offset: usize,
    ) -> Option<MemcachedTextResponseParse> {
        let (line, line_end) = match memcached_text_line(payload, offset, 4096)? {
            MemcachedTextLineParse::Complete { line, next_offset } => (line, next_offset),
            MemcachedTextLineParse::Incomplete => {
                return Some(MemcachedTextResponseParse::Incomplete)
            }
        };
        let fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let first = *fields.first()?;

        if memcached_simple_text_response(&fields) {
            return Some(MemcachedTextResponseParse::Complete(line_end));
        }
        if first.eq_ignore_ascii_case(b"VALUE") {
            return memcached_value_response(payload, line_end, &fields);
        }
        if first.eq_ignore_ascii_case(b"STAT") {
            return (fields.len() >= 3
                && memcached_ascii_argument(fields[1])
                && fields[2..].iter().all(|field| memcached_text_value(field)))
            .then_some(MemcachedTextResponseParse::Complete(line_end));
        }
        None
    }

    enum MemcachedTextLineParse<'a> {
        Complete { line: &'a [u8], next_offset: usize },
        Incomplete,
    }

    fn memcached_text_line(
        payload: &[u8],
        offset: usize,
        max_len: usize,
    ) -> Option<MemcachedTextLineParse<'_>> {
        let tail = payload.get(offset..)?;
        let line_delimiter = tail.iter().position(|byte| matches!(*byte, b'\r' | b'\n'));
        match line_delimiter {
            Some(index) if tail.get(index) == Some(&b'\r') => {
                if tail.get(index + 1).is_none() {
                    return Some(MemcachedTextLineParse::Incomplete);
                }
                if tail.get(index + 1) != Some(&b'\n') || index == 0 || index > max_len {
                    return None;
                }
                let line = tail.get(..index)?;
                memcached_text_value(line).then_some(MemcachedTextLineParse::Complete {
                    line,
                    next_offset: offset + index + 2,
                })
            }
            Some(_) => None,
            None => (!tail.is_empty() && tail.len() <= max_len && memcached_text_value(tail))
                .then_some(MemcachedTextLineParse::Incomplete),
        }
    }

    fn memcached_simple_text_response(fields: &[&[u8]]) -> bool {
        let Some(first) = fields.first().copied() else {
            return false;
        };
        const SIMPLE_RESPONSES: &[&[u8]] = &[
            b"STORED",
            b"NOT_STORED",
            b"EXISTS",
            b"NOT_FOUND",
            b"DELETED",
            b"TOUCHED",
            b"END",
            b"OK",
            b"ERROR",
        ];
        if SIMPLE_RESPONSES
            .iter()
            .any(|known| first.eq_ignore_ascii_case(known))
        {
            return fields.len() == 1;
        }
        if first.eq_ignore_ascii_case(b"VERSION") {
            return fields.len() == 2 && memcached_ascii_argument(fields[1]);
        }
        if first.eq_ignore_ascii_case(b"CLIENT_ERROR")
            || first.eq_ignore_ascii_case(b"SERVER_ERROR")
        {
            return fields.len() >= 2
                && fields[1..].iter().all(|field| memcached_text_value(field));
        }
        fields.len() == 1 && memcached_decimal(fields[0])
    }

    fn memcached_value_response(
        payload: &[u8],
        line_end: usize,
        fields: &[&[u8]],
    ) -> Option<MemcachedTextResponseParse> {
        if !(fields.len() == 4 || fields.len() == 5)
            || !memcached_key(fields[1])
            || !memcached_decimal(fields[2])
            || (fields.len() == 5 && !memcached_decimal(fields[4]))
        {
            return None;
        }
        let bytes = memcached_decimal_value(fields[3], 1_048_576)?;
        let data_end = line_end.checked_add(bytes)?;
        let frame_end = data_end.checked_add(2)?;
        if payload.len() < data_end {
            return Some(MemcachedTextResponseParse::Incomplete);
        }
        if payload.len() < frame_end {
            return match payload.get(data_end..) {
                Some(b"") | Some(b"\r") => Some(MemcachedTextResponseParse::Incomplete),
                _ => None,
            };
        }
        if payload.get(data_end..frame_end)? != b"\r\n" {
            return None;
        }
        Some(MemcachedTextResponseParse::Complete(frame_end))
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

    fn memcached_text_value(field: &[u8]) -> bool {
        !field.is_empty()
            && field
                .iter()
                .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
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
        let status = u16::from_be_bytes([header[6], header[7]]);
        let total_body_len =
            u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
        let frame_end = offset.checked_add(24)?.checked_add(total_body_len)?;
        if data_type != 0
            || total_body_len > 1_048_576
            || key_len > 250
            || extras_len > 32
            || key_len.checked_add(extras_len)? > total_body_len
            || !memcached_binary_opcode_shape(
                magic,
                opcode,
                status,
                key_len,
                extras_len,
                total_body_len,
            )
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
        status: u16,
        key_len: usize,
        extras_len: usize,
        total_body_len: usize,
    ) -> bool {
        if magic == 0x81 {
            return memcached_binary_response_shape(
                opcode,
                status,
                key_len,
                extras_len,
                total_body_len,
            );
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

    fn memcached_binary_response_shape(
        opcode: u8,
        status: u16,
        key_len: usize,
        extras_len: usize,
        total_body_len: usize,
    ) -> bool {
        if opcode > 0x22 || !memcached_binary_response_status(status) {
            return false;
        }
        if status != 0 {
            return key_len == 0 && extras_len == 0 && total_body_len <= 4096;
        }
        match opcode {
            0x00 | 0x09 | 0x1d | 0x1e => {
                extras_len == 4 && key_len == 0 && total_body_len >= extras_len
            }
            0x0c | 0x0d => extras_len == 4 && key_len > 0 && total_body_len >= extras_len + key_len,
            0x01..=0x04 | 0x07 | 0x08 | 0x0a | 0x0e | 0x0f | 0x11..=0x14 | 0x17..=0x1c => {
                extras_len == 0 && key_len == 0 && total_body_len == 0
            }
            0x05 | 0x06 | 0x15 | 0x16 => extras_len == 0 && key_len == 0 && total_body_len == 8,
            0x0b => extras_len == 0 && key_len == 0 && (1..=256).contains(&total_body_len),
            0x10 => {
                extras_len == 0
                    && total_body_len >= key_len
                    && (key_len == 0 && total_body_len == 0 || key_len > 0)
            }
            0x20..=0x22 => extras_len == 0 && key_len == 0 && total_body_len <= 4096,
            _ => false,
        }
    }

    fn memcached_binary_response_status(status: u16) -> bool {
        matches!(
            status,
            0x0000
                | 0x0001
                | 0x0002
                | 0x0003
                | 0x0004
                | 0x0005
                | 0x0006
                | 0x0007
                | 0x0008
                | 0x0020
                | 0x0021
                | 0x0081
                | 0x0082
                | 0x0083
                | 0x0084
                | 0x0085
                | 0x0086
                | 0x0087
        )
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

    enum KafkaHeaderEncoding {
        NullableClientId,
        CompactClientId,
        Either,
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
        let header_encoding = kafka_request_header_encoding(api_key, api_version);
        if frame_len == 8 {
            if matches!(header_encoding, KafkaHeaderEncoding::CompactClientId) {
                return None;
            }
            return if payload.len() < frame_end {
                Some(KafkaFrameParse::Incomplete)
            } else {
                Some(KafkaFrameParse::Complete(frame_end))
            };
        }
        let header_tail = payload.get(correlation_id_end..)?;
        let remaining_frame_len = frame_len - 8;
        let header_parse =
            kafka_request_header_payload(header_encoding, header_tail, remaining_frame_len)?;
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
        encoding: KafkaHeaderEncoding,
        payload: &[u8],
        remaining_frame_len: usize,
    ) -> Option<KafkaHeaderParse> {
        match encoding {
            KafkaHeaderEncoding::NullableClientId => {
                kafka_nullable_client_id_header_payload(payload, remaining_frame_len)
            }
            KafkaHeaderEncoding::CompactClientId => {
                kafka_compact_client_id_header_payload(payload, remaining_frame_len)
            }
            KafkaHeaderEncoding::Either => {
                kafka_nullable_client_id_header_payload(payload, remaining_frame_len).or_else(
                    || kafka_compact_client_id_header_payload(payload, remaining_frame_len),
                )
            }
        }
    }

    fn kafka_request_header_encoding(api_key: u16, api_version: u16) -> KafkaHeaderEncoding {
        if api_key == 18 {
            if api_version >= 3 {
                KafkaHeaderEncoding::CompactClientId
            } else {
                KafkaHeaderEncoding::NullableClientId
            }
        } else {
            KafkaHeaderEncoding::Either
        }
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
        mqtt_connect_packet_payload(payload)
            || mqtt_connack_packet_payload(payload)
            || mqtt_publish_packet_payload(payload)
            || mqtt_subscribe_packet_payload(payload)
            || mqtt_unsubscribe_packet_payload(payload)
    }

    fn mqtt_connect_packet_payload(payload: &[u8]) -> bool {
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

    fn mqtt_connack_packet_payload(payload: &[u8]) -> bool {
        if payload.len() < 4 || payload[0] != 0x20 {
            return false;
        }
        let Some((remaining_len, offset)) = mqtt_variable_integer(payload, 1) else {
            return false;
        };
        if remaining_len < 2 || remaining_len > PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES {
            return false;
        }
        let Some(remaining_end) = offset.checked_add(remaining_len) else {
            return false;
        };
        if remaining_end != payload.len() {
            return false;
        }

        let Some(&ack_flags) = payload.get(offset) else {
            return false;
        };
        let Some(&reason_code) = payload.get(offset + 1) else {
            return false;
        };
        if ack_flags & !0x01 != 0 || (reason_code != 0 && ack_flags != 0) {
            return false;
        }
        if remaining_len == 2 {
            return matches!(reason_code, 0..=5);
        }

        if !mqtt_v5_connack_reason_code(reason_code) {
            return false;
        }
        let properties_offset = offset + 2;
        let Some((properties_len, properties_start)) =
            mqtt_variable_integer_until(payload, properties_offset, remaining_end)
        else {
            return false;
        };
        mqtt_v5_connack_properties(payload, properties_start, remaining_end, properties_len)
    }

    fn mqtt_publish_packet_payload(payload: &[u8]) -> bool {
        if payload.len() < 5 || payload[0] & 0xf0 != 0x30 {
            return false;
        }
        let qos = (payload[0] >> 1) & 0x03;
        if qos == 0x03 {
            return false;
        }
        let Some((remaining_len, mut offset)) = mqtt_variable_integer(payload, 1) else {
            return false;
        };
        let Some(remaining_end) = offset.checked_add(remaining_len) else {
            return false;
        };
        if remaining_end != payload.len() || remaining_len < 3 {
            return false;
        }
        let Some((topic, next_offset)) = mqtt_utf8_field(payload, offset, remaining_end) else {
            return false;
        };
        if !mqtt_topic_name(topic) {
            return false;
        }
        offset = next_offset;
        if qos > 0 {
            let Some(packet_id) = read_u16_be(payload, offset) else {
                return false;
            };
            if packet_id == 0 {
                return false;
            }
            offset += 2;
        }
        offset <= remaining_end
    }

    fn mqtt_subscribe_packet_payload(payload: &[u8]) -> bool {
        if payload.len() < 8 || payload[0] != 0x82 {
            return false;
        }
        let Some((remaining_len, mut offset)) = mqtt_variable_integer(payload, 1) else {
            return false;
        };
        let Some(remaining_end) = offset.checked_add(remaining_len) else {
            return false;
        };
        if remaining_end != payload.len() || remaining_len < 5 {
            return false;
        }
        let Some(packet_id) = read_u16_be(payload, offset) else {
            return false;
        };
        if packet_id == 0 {
            return false;
        }
        offset += 2;

        mqtt_subscribe_filters_payload(payload, offset, remaining_end)
            || mqtt_v5_subscribe_tail_payload(payload, offset, remaining_end)
    }

    fn mqtt_unsubscribe_packet_payload(payload: &[u8]) -> bool {
        if payload.len() < 7 || payload[0] != 0xa2 {
            return false;
        }
        let Some((remaining_len, mut offset)) = mqtt_variable_integer(payload, 1) else {
            return false;
        };
        let Some(remaining_end) = offset.checked_add(remaining_len) else {
            return false;
        };
        if remaining_end != payload.len() || remaining_len < 5 {
            return false;
        }
        let Some(packet_id) = read_u16_be(payload, offset) else {
            return false;
        };
        if packet_id == 0 {
            return false;
        }
        offset += 2;

        mqtt_unsubscribe_filters_payload(payload, offset, remaining_end)
            || mqtt_v5_unsubscribe_tail_payload(payload, offset, remaining_end)
    }

    fn mqtt_subscribe_filters_payload(
        payload: &[u8],
        mut offset: usize,
        remaining_end: usize,
    ) -> bool {
        let mut filter_count = 0_usize;
        while offset < remaining_end {
            let Some((filter, options_offset)) = mqtt_utf8_field(payload, offset, remaining_end)
            else {
                return false;
            };
            let Some(&options) = payload.get(options_offset) else {
                return false;
            };
            let next_offset = options_offset + 1;
            if next_offset > remaining_end
                || !mqtt_topic_filter(filter)
                || !mqtt_subscription_options(options)
            {
                return false;
            }
            filter_count += 1;
            if filter_count > 64 {
                return false;
            }
            offset = next_offset;
        }
        filter_count > 0
    }

    fn mqtt_unsubscribe_filters_payload(
        payload: &[u8],
        mut offset: usize,
        remaining_end: usize,
    ) -> bool {
        let mut filter_count = 0_usize;
        while offset < remaining_end {
            let Some((filter, next_offset)) = mqtt_utf8_field(payload, offset, remaining_end)
            else {
                return false;
            };
            if !mqtt_topic_filter(filter) {
                return false;
            }
            filter_count += 1;
            if filter_count > 64 {
                return false;
            }
            offset = next_offset;
        }
        filter_count > 0
    }

    fn mqtt_v5_subscribe_tail_payload(payload: &[u8], offset: usize, remaining_end: usize) -> bool {
        let Some((properties_len, properties_start)) =
            mqtt_variable_integer_until(payload, offset, remaining_end)
        else {
            return false;
        };
        let Some(filters_offset) = properties_start.checked_add(properties_len) else {
            return false;
        };
        filters_offset <= remaining_end
            && mqtt_v5_subscribe_properties(payload, properties_start, filters_offset)
            && mqtt_subscribe_filters_payload(payload, filters_offset, remaining_end)
    }

    fn mqtt_v5_unsubscribe_tail_payload(
        payload: &[u8],
        offset: usize,
        remaining_end: usize,
    ) -> bool {
        let Some((properties_len, properties_start)) =
            mqtt_variable_integer_until(payload, offset, remaining_end)
        else {
            return false;
        };
        let Some(filters_offset) = properties_start.checked_add(properties_len) else {
            return false;
        };
        filters_offset <= remaining_end
            && mqtt_v5_unsubscribe_properties(payload, properties_start, filters_offset)
            && mqtt_unsubscribe_filters_payload(payload, filters_offset, remaining_end)
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

    fn mqtt_v5_connack_reason_code(reason_code: u8) -> bool {
        matches!(
            reason_code,
            0x00 | 0x80
                | 0x81
                | 0x82
                | 0x83
                | 0x84
                | 0x85
                | 0x86
                | 0x87
                | 0x88
                | 0x89
                | 0x8a
                | 0x8c
                | 0x90
                | 0x95
                | 0x97
                | 0x99
                | 0x9a
                | 0x9b
                | 0x9c
                | 0x9d
                | 0x9f
        )
    }

    fn mqtt_v5_connack_properties(
        payload: &[u8],
        mut offset: usize,
        remaining_end: usize,
        properties_len: usize,
    ) -> bool {
        let Some(properties_end) = offset.checked_add(properties_len) else {
            return false;
        };
        if properties_end != remaining_end {
            return false;
        }
        let mut property_count = 0_usize;
        let mut seen_single = 0_u128;
        while offset < properties_end {
            property_count += 1;
            if property_count > 64 {
                return false;
            }
            let Some((property_id, value_offset)) =
                mqtt_variable_integer_until(payload, offset, properties_end)
            else {
                return false;
            };
            offset = value_offset;
            if property_id != 0x26 {
                let Some(property_bit) = 1_u128.checked_shl(property_id as u32) else {
                    return false;
                };
                if seen_single & property_bit != 0 {
                    return false;
                }
                seen_single |= property_bit;
            }
            let Some(next_offset) =
                mqtt_v5_connack_property(payload, offset, properties_end, property_id)
            else {
                return false;
            };
            offset = next_offset;
        }
        offset == properties_end
    }

    fn mqtt_v5_connack_property(
        payload: &[u8],
        offset: usize,
        properties_end: usize,
        property_id: usize,
    ) -> Option<usize> {
        match property_id {
            0x11 | 0x27 => {
                let next_offset = offset.checked_add(4)?;
                let value = read_u32_be(payload, offset)?;
                (next_offset <= properties_end && (property_id != 0x27 || value != 0))
                    .then_some(next_offset)
            }
            0x13 | 0x22 => {
                let next_offset = offset.checked_add(2)?;
                payload
                    .get(offset..next_offset)
                    .filter(|_| next_offset <= properties_end)
                    .map(|_| next_offset)
            }
            0x21 => {
                let next_offset = offset.checked_add(2)?;
                let value = read_u16_be(payload, offset)?;
                (next_offset <= properties_end && value != 0).then_some(next_offset)
            }
            0x24 | 0x25 | 0x28 | 0x29 | 0x2a => {
                let value = *payload.get(offset)?;
                let next_offset = offset.checked_add(1)?;
                (next_offset <= properties_end
                    && if property_id == 0x24 {
                        value <= 1
                    } else {
                        matches!(value, 0 | 1)
                    })
                .then_some(next_offset)
            }
            0x12 | 0x15 | 0x1a | 0x1c | 0x1f => {
                let (_value, next_offset) = mqtt_utf8_field(payload, offset, properties_end)?;
                Some(next_offset)
            }
            0x16 => {
                let (_value, next_offset) =
                    mqtt_len_prefixed_field(payload, offset, properties_end)?;
                Some(next_offset)
            }
            0x26 => {
                let (_key, value_offset) = mqtt_utf8_field(payload, offset, properties_end)?;
                let (_value, next_offset) = mqtt_utf8_field(payload, value_offset, properties_end)?;
                Some(next_offset)
            }
            _ => None,
        }
    }

    fn mqtt_v5_subscribe_properties(
        payload: &[u8],
        mut offset: usize,
        properties_end: usize,
    ) -> bool {
        let mut property_count = 0_usize;
        let mut seen_subscription_identifier = false;
        while offset < properties_end {
            property_count += 1;
            if property_count > 64 {
                return false;
            }
            let Some((property_id, value_offset)) =
                mqtt_variable_integer_until(payload, offset, properties_end)
            else {
                return false;
            };
            offset = value_offset;
            if property_id == 0x0b {
                if seen_subscription_identifier {
                    return false;
                }
                seen_subscription_identifier = true;
            }
            let Some(next_offset) =
                mqtt_v5_subscribe_property(payload, offset, properties_end, property_id)
            else {
                return false;
            };
            offset = next_offset;
        }
        offset == properties_end
    }

    fn mqtt_v5_unsubscribe_properties(
        payload: &[u8],
        mut offset: usize,
        properties_end: usize,
    ) -> bool {
        let mut property_count = 0_usize;
        while offset < properties_end {
            property_count += 1;
            if property_count > 64 {
                return false;
            }
            let Some((property_id, value_offset)) =
                mqtt_variable_integer_until(payload, offset, properties_end)
            else {
                return false;
            };
            offset = value_offset;
            let Some(next_offset) =
                mqtt_v5_unsubscribe_property(payload, offset, properties_end, property_id)
            else {
                return false;
            };
            offset = next_offset;
        }
        offset == properties_end
    }

    fn mqtt_v5_subscribe_property(
        payload: &[u8],
        offset: usize,
        properties_end: usize,
        property_id: usize,
    ) -> Option<usize> {
        match property_id {
            0x0b => {
                let (subscription_id, next_offset) =
                    mqtt_variable_integer_until(payload, offset, properties_end)?;
                (subscription_id != 0).then_some(next_offset)
            }
            0x26 => mqtt_v5_user_property(payload, offset, properties_end),
            _ => None,
        }
    }

    fn mqtt_v5_unsubscribe_property(
        payload: &[u8],
        offset: usize,
        properties_end: usize,
        property_id: usize,
    ) -> Option<usize> {
        match property_id {
            0x26 => mqtt_v5_user_property(payload, offset, properties_end),
            _ => None,
        }
    }

    fn mqtt_v5_user_property(
        payload: &[u8],
        offset: usize,
        properties_end: usize,
    ) -> Option<usize> {
        let (_key, value_offset) = mqtt_utf8_field(payload, offset, properties_end)?;
        let (_value, next_offset) = mqtt_utf8_field(payload, value_offset, properties_end)?;
        Some(next_offset)
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

    fn mqtt_topic_name(topic: &[u8]) -> bool {
        !topic.is_empty()
            && topic.len() <= 1024
            && topic.contains(&b'/')
            && mqtt_utf8_string(topic)
            && !topic.iter().any(|byte| matches!(*byte, b'+' | b'#'))
    }

    fn mqtt_topic_filter(filter: &[u8]) -> bool {
        if filter.is_empty() || filter.len() > 1024 || !mqtt_utf8_string(filter) {
            return false;
        }
        if filter.starts_with(b"$share/") && !mqtt_shared_topic_filter(filter) {
            return false;
        }
        let mut tokens = filter.split(|byte| *byte == b'/').peekable();
        while let Some(token) = tokens.next() {
            if token.contains(&b'#') {
                if token != b"#" || tokens.peek().is_some() {
                    return false;
                }
            }
            if token.contains(&b'+') && token != b"+" {
                return false;
            }
        }
        true
    }

    fn mqtt_shared_topic_filter(filter: &[u8]) -> bool {
        let Some(shared_tail) = filter.strip_prefix(b"$share/") else {
            return false;
        };
        let Some(separator) = shared_tail.iter().position(|byte| *byte == b'/') else {
            return false;
        };
        let share_name = &shared_tail[..separator];
        let topic_filter = &shared_tail[separator + 1..];
        !share_name.is_empty()
            && !topic_filter.is_empty()
            && !share_name.iter().any(|byte| matches!(*byte, b'+' | b'#'))
    }

    fn mqtt_subscription_options(options: u8) -> bool {
        let max_qos = options & 0x03;
        let retain_handling = (options >> 4) & 0x03;
        options & 0x80 == 0 && max_qos <= 2 && retain_handling <= 2
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
        let Some(frame_body) = payload.get(7..frame_end_offset) else {
            return false;
        };
        match frame_type {
            1 => amqp_method_frame_payload(channel, frame_size, frame_body),
            2 => amqp_content_header_frame_payload(channel, frame_size, frame_body),
            3 => false,
            8 => channel == 0 && frame_size == 0,
            _ => false,
        }
    }

    fn amqp_method_frame_payload(channel: u16, frame_size: usize, frame_body: &[u8]) -> bool {
        if !(4..=131_072).contains(&frame_size) || frame_body.len() < 4 {
            return false;
        }
        let class_id = u16::from_be_bytes([frame_body[0], frame_body[1]]);
        let method_id = u16::from_be_bytes([frame_body[2], frame_body[3]]);
        let channel_ok = if class_id == 10 {
            channel == 0
        } else {
            channel != 0
        };
        channel_ok && amqp_known_method_id(class_id, method_id)
    }

    fn amqp_content_header_frame_payload(
        channel: u16,
        frame_size: usize,
        frame_body: &[u8],
    ) -> bool {
        if channel == 0 || !(14..=131_072).contains(&frame_size) || frame_body.len() != frame_size {
            return false;
        }
        let Some(class_id) = read_u16_be(frame_body, 0) else {
            return false;
        };
        let Some(weight) = read_u16_be(frame_body, 2) else {
            return false;
        };
        if class_id != 60 || weight != 0 || frame_body.get(4..12).is_none() {
            return false;
        }
        let Some(property_flags) = read_u16_be(frame_body, 12) else {
            return false;
        };
        if property_flags & 0x0003 != 0 {
            return false;
        }
        amqp_basic_property_values(frame_body, 14, property_flags)
    }

    fn amqp_basic_property_values(
        frame_body: &[u8],
        mut offset: usize,
        property_flags: u16,
    ) -> bool {
        let properties = [
            (0x8000, AmqpBasicPropertyKind::ShortString),
            (0x4000, AmqpBasicPropertyKind::ShortString),
            (0x2000, AmqpBasicPropertyKind::FieldTable),
            (0x1000, AmqpBasicPropertyKind::Octet),
            (0x0800, AmqpBasicPropertyKind::Octet),
            (0x0400, AmqpBasicPropertyKind::ShortString),
            (0x0200, AmqpBasicPropertyKind::ShortString),
            (0x0100, AmqpBasicPropertyKind::ShortString),
            (0x0080, AmqpBasicPropertyKind::ShortString),
            (0x0040, AmqpBasicPropertyKind::LongLong),
            (0x0020, AmqpBasicPropertyKind::ShortString),
            (0x0010, AmqpBasicPropertyKind::ShortString),
            (0x0008, AmqpBasicPropertyKind::ShortString),
            (0x0004, AmqpBasicPropertyKind::ShortString),
        ];
        for (flag, kind) in properties {
            if property_flags & flag == 0 {
                continue;
            }
            let Some(next_offset) = amqp_basic_property_value(frame_body, offset, kind) else {
                return false;
            };
            offset = next_offset;
        }
        offset == frame_body.len()
    }

    #[derive(Clone, Copy)]
    enum AmqpBasicPropertyKind {
        ShortString,
        FieldTable,
        Octet,
        LongLong,
    }

    fn amqp_basic_property_value(
        frame_body: &[u8],
        offset: usize,
        kind: AmqpBasicPropertyKind,
    ) -> Option<usize> {
        match kind {
            AmqpBasicPropertyKind::ShortString => {
                let len = *frame_body.get(offset)? as usize;
                let start = offset.checked_add(1)?;
                let end = start.checked_add(len)?;
                frame_body.get(start..end)?;
                Some(end)
            }
            AmqpBasicPropertyKind::FieldTable => {
                let len = read_u32_be(frame_body, offset)? as usize;
                if len > 65_536 {
                    return None;
                }
                let start = offset.checked_add(4)?;
                let end = start.checked_add(len)?;
                frame_body.get(start..end)?;
                Some(end)
            }
            AmqpBasicPropertyKind::Octet => {
                let end = offset.checked_add(1)?;
                frame_body.get(offset..end)?;
                Some(end)
            }
            AmqpBasicPropertyKind::LongLong => {
                let end = offset.checked_add(8)?;
                frame_body.get(offset..end)?;
                Some(end)
            }
        }
    }

    fn amqp_known_method_id(class_id: u16, method_id: u16) -> bool {
        match class_id {
            // connection
            10 => matches!(
                method_id,
                10 | 11 | 20 | 21 | 30 | 31 | 40 | 41 | 50 | 51 | 60 | 61 | 70 | 71
            ),
            // channel
            20 => matches!(method_id, 10 | 11 | 20 | 21 | 40 | 41),
            // exchange
            40 => matches!(method_id, 10 | 11 | 20 | 21 | 30 | 31 | 40 | 51),
            // queue
            50 => matches!(method_id, 10 | 11 | 20 | 21 | 30 | 31 | 40 | 41 | 50 | 51),
            // basic
            60 => matches!(
                method_id,
                10 | 11
                    | 20
                    | 21
                    | 30
                    | 31
                    | 40
                    | 50
                    | 60
                    | 70
                    | 71
                    | 72
                    | 80
                    | 90
                    | 100
                    | 110
                    | 111
                    | 120
            ),
            // confirm
            85 => matches!(method_id, 10 | 11),
            // tx
            90 => matches!(method_id, 10 | 11 | 20 | 21 | 30 | 31),
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
            0x08 => cassandra_result_body(body_len, body_prefix),
            0x0c => cassandra_string_prefix_body(body_len, body_prefix),
            0x0e | 0x10 => body_len >= 4 && body_prefix.len() >= 4,
            _ => false,
        }
    }

    fn cassandra_result_body(body_len: usize, body_prefix: &[u8]) -> bool {
        if body_len < 4 || body_prefix.len() < 4 {
            return false;
        }
        let Some(kind) = read_u32_be(body_prefix, 0) else {
            return false;
        };
        match kind {
            0x0001 => body_len == 4,
            0x0002 => cassandra_rows_result_body(body_len, body_prefix),
            0x0003 => cassandra_set_keyspace_result_body(body_len, body_prefix),
            0x0004 => cassandra_prepared_result_body(body_len, body_prefix),
            0x0005 => cassandra_schema_change_result_body(body_len, body_prefix),
            _ => false,
        }
    }

    fn cassandra_rows_result_body(body_len: usize, body_prefix: &[u8]) -> bool {
        let Some((metadata_offset, columns_count)) =
            cassandra_result_metadata(body_prefix, 4, body_len)
        else {
            return false;
        };
        let Some(rows_count) =
            read_u32_be(body_prefix, metadata_offset).map(|count| count as usize)
        else {
            return false;
        };
        if rows_count > 1_000_000 {
            return false;
        }
        let Some(mut offset) = metadata_offset.checked_add(4) else {
            return false;
        };
        if body_prefix.len() < body_len {
            return true;
        }
        if rows_count == 0 {
            return offset == body_len;
        }
        let Some(cell_count) = rows_count.checked_mul(columns_count) else {
            return false;
        };
        if cell_count == 0 || cell_count > 65_536 {
            return false;
        }
        for _ in 0..cell_count {
            let Some(next_offset) = cassandra_bytes_field(body_prefix, offset, body_len, false)
            else {
                return false;
            };
            offset = next_offset;
        }
        offset == body_len
    }

    fn cassandra_set_keyspace_result_body(body_len: usize, body_prefix: &[u8]) -> bool {
        let Some(body) = body_prefix.get(..body_len) else {
            return false;
        };
        cassandra_string_field(body, 4).is_some_and(|(_keyspace, offset)| offset == body_len)
    }

    fn cassandra_prepared_result_body(body_len: usize, body_prefix: &[u8]) -> bool {
        let Some(body) = body_prefix.get(..body_len) else {
            return false;
        };
        let Some(offset) = cassandra_short_bytes_field(body, 4, body_len) else {
            return false;
        };
        let Some((offset, _parameters_count)) = cassandra_result_metadata(body, offset, body_len)
        else {
            return false;
        };
        let Some((offset, _result_columns_count)) =
            cassandra_result_metadata(body, offset, body_len)
        else {
            return false;
        };
        offset == body_len
    }

    fn cassandra_schema_change_result_body(body_len: usize, body_prefix: &[u8]) -> bool {
        let Some(body) = body_prefix.get(..body_len) else {
            return false;
        };
        let mut offset = 4_usize;
        let mut strings = 0_usize;
        while offset < body_len {
            let Some((_value, next_offset)) = cassandra_string_field(body, offset) else {
                return false;
            };
            offset = next_offset;
            strings += 1;
            if strings > 5 {
                return false;
            }
        }
        matches!(strings, 3..=5) && offset == body_len
    }

    fn cassandra_result_metadata(
        body_prefix: &[u8],
        offset: usize,
        body_len: usize,
    ) -> Option<(usize, usize)> {
        let flags = read_u32_be(body_prefix, offset)?;
        let columns_count = read_u32_be(body_prefix, offset.checked_add(4)?)? as usize;
        if flags & !0x0007 != 0 || columns_count > 4096 {
            return None;
        }
        let global_tables_spec = flags & 0x0001 != 0;
        let has_more_pages = flags & 0x0002 != 0;
        let no_metadata = flags & 0x0004 != 0;
        let mut offset = offset.checked_add(8)?;
        if has_more_pages {
            offset = cassandra_bytes_field(body_prefix, offset, body_len, false)?;
        }
        if no_metadata {
            return Some((offset, columns_count));
        }
        let global_spec = if global_tables_spec {
            let (_keyspace, next_offset) = cassandra_string_field(body_prefix, offset)?;
            let (_table, next_offset) = cassandra_string_field(body_prefix, next_offset)?;
            offset = next_offset;
            true
        } else {
            false
        };
        for _ in 0..columns_count {
            if !global_spec {
                let (_keyspace, next_offset) = cassandra_string_field(body_prefix, offset)?;
                let (_table, next_offset) = cassandra_string_field(body_prefix, next_offset)?;
                offset = next_offset;
            }
            let (_name, next_offset) = cassandra_string_field(body_prefix, offset)?;
            offset = cassandra_type_option(body_prefix, next_offset, body_len)?;
        }
        Some((offset, columns_count))
    }

    fn cassandra_type_option(body_prefix: &[u8], offset: usize, body_len: usize) -> Option<usize> {
        cassandra_type_option_with_depth(body_prefix, offset, body_len, 0)
    }

    fn cassandra_type_option_with_depth(
        body_prefix: &[u8],
        offset: usize,
        body_len: usize,
        depth: usize,
    ) -> Option<usize> {
        if depth > 16 {
            return None;
        }
        let option_id = read_u16_be(body_prefix, offset)?;
        let mut offset = offset.checked_add(2)?;
        match option_id {
            0x0000 => cassandra_string_field(body_prefix, offset)
                .map(|(_custom_type, next_offset)| next_offset),
            0x0001 | 0x0002 | 0x0003 | 0x0004 | 0x0005 | 0x0006 | 0x0007 | 0x0008 | 0x0009
            | 0x000a | 0x000b | 0x000c | 0x000d | 0x000e | 0x000f | 0x0010 | 0x0011 | 0x0012
            | 0x0013 | 0x0014 | 0x0015 => Some(offset),
            0x0020 | 0x0022 => {
                cassandra_type_option_with_depth(body_prefix, offset, body_len, depth + 1)
            }
            0x0021 => {
                offset =
                    cassandra_type_option_with_depth(body_prefix, offset, body_len, depth + 1)?;
                cassandra_type_option_with_depth(body_prefix, offset, body_len, depth + 1)
            }
            0x0030 => {
                let (_keyspace, next_offset) = cassandra_string_field(body_prefix, offset)?;
                let (_type_name, next_offset) = cassandra_string_field(body_prefix, next_offset)?;
                let fields_count = read_u16_be(body_prefix, next_offset)? as usize;
                if fields_count > 128 {
                    return None;
                }
                offset = next_offset.checked_add(2)?;
                for _ in 0..fields_count {
                    let (_field_name, next_offset) = cassandra_string_field(body_prefix, offset)?;
                    offset = cassandra_type_option_with_depth(
                        body_prefix,
                        next_offset,
                        body_len,
                        depth + 1,
                    )?;
                }
                Some(offset)
            }
            0x0031 => {
                let count = read_u16_be(body_prefix, offset)? as usize;
                if count > 128 {
                    return None;
                }
                offset = offset.checked_add(2)?;
                for _ in 0..count {
                    offset =
                        cassandra_type_option_with_depth(body_prefix, offset, body_len, depth + 1)?;
                }
                Some(offset)
            }
            _ => None,
        }
        .filter(|offset| *offset <= body_len)
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

    fn cassandra_short_bytes_field(
        payload: &[u8],
        offset: usize,
        body_len: usize,
    ) -> Option<usize> {
        let len = read_u16_be(payload, offset)? as usize;
        if len == 0 || len > 65_535 {
            return None;
        }
        let value_start = offset.checked_add(2)?;
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
        let Some(compressed_message_len) = message_len.checked_sub(25) else {
            return false;
        };
        if uncompressed_size == 0 || uncompressed_size > 100_000_000 || compressed_message_len == 0
        {
            return false;
        }
        if *compressor_id == 0 && compressed_message_len != uncompressed_size {
            return false;
        }
        mongodb_wire_opcode(original_opcode)
            && original_opcode != 2012
            && matches!(*compressor_id, 0..=3)
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
        mongodb_op_query_flags(flags)
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

    fn mongodb_op_query_flags(flags: u32) -> bool {
        flags & !0xfe == 0
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

    fn ascii_starts_with_ignore_case(payload: &[u8], prefix: &[u8]) -> bool {
        payload
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
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

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
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

    const MYSQL_CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
    const MYSQL_CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
    const MYSQL_CLIENT_SSL: u32 = 0x0000_0800;
    const MYSQL_CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
    const MYSQL_CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
    const MYSQL_CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;
    const MYSQL_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;

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
    fn path_state_allows_only_matching_selected_candidate_kinds() {
        for (state, expected_kind) in [
            (PathState::DirectPublic, EndpointCandidateKind::PublicUdp),
            (PathState::DirectIpv6, EndpointCandidateKind::Ipv6),
            (
                PathState::DirectNatTraversal,
                EndpointCandidateKind::StunReflexive,
            ),
        ] {
            for kind in [
                EndpointCandidateKind::PublicUdp,
                EndpointCandidateKind::Ipv6,
                EndpointCandidateKind::StunReflexive,
                EndpointCandidateKind::LocalUdp,
                EndpointCandidateKind::Relay,
            ] {
                assert_eq!(
                    state.allows_selected_candidate_kind(kind),
                    kind == expected_kind,
                    "{state:?} candidate kind {kind:?}"
                );
            }
        }

        for state in [PathState::Relay, PathState::Unreachable] {
            for kind in [
                EndpointCandidateKind::PublicUdp,
                EndpointCandidateKind::Ipv6,
                EndpointCandidateKind::StunReflexive,
                EndpointCandidateKind::LocalUdp,
                EndpointCandidateKind::Relay,
            ] {
                assert!(
                    !state.allows_selected_candidate_kind(kind),
                    "{state:?} must not accept selected candidate kind {kind:?}"
                );
            }
        }
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
        let kubelet = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(10250),
            ..Default::default()
        };
        assert_eq!(
            kubelet.application(),
            api::AgentPacketFlowApplication::Kubelet
        );
        let docker_api = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(2376),
            ..Default::default()
        };
        assert_eq!(
            docker_api.application(),
            api::AgentPacketFlowApplication::DockerApi
        );

        let ipars_control_plane = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(8443),
            ..Default::default()
        };
        assert_eq!(
            ipars_control_plane.application(),
            api::AgentPacketFlowApplication::IparsControlPlane
        );
        let ipars_signal = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(9443),
            ..Default::default()
        };
        assert_eq!(
            ipars_signal.application(),
            api::AgentPacketFlowApplication::IparsSignal
        );
        let ipars_agent = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(9780),
            ..Default::default()
        };
        assert_eq!(
            ipars_agent.application(),
            api::AgentPacketFlowApplication::IparsAgent
        );
        let ipars_relay = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(9580),
            ..Default::default()
        };
        assert_eq!(
            ipars_relay.application(),
            api::AgentPacketFlowApplication::IparsRelay
        );
        let stun = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(3478),
            ..Default::default()
        };
        assert_eq!(stun.application(), api::AgentPacketFlowApplication::Stun);

        let turns = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(5349),
            ..Default::default()
        };
        assert_eq!(turns.application(), api::AgentPacketFlowApplication::Turn);

        let coaps = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(5684),
            ..Default::default()
        };
        assert_eq!(coaps.application(), api::AgentPacketFlowApplication::Coap);

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

        let tftp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(69),
            ..Default::default()
        };
        assert_eq!(tftp.application(), api::AgentPacketFlowApplication::Tftp);

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

        let vnc = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(5901),
            ..Default::default()
        };
        assert_eq!(vnc.application(), api::AgentPacketFlowApplication::Vnc);

        let ftp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(21),
            ..Default::default()
        };
        assert_eq!(ftp.application(), api::AgentPacketFlowApplication::Ftp);

        let ftps = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(990),
            ..Default::default()
        };
        assert_eq!(ftps.application(), api::AgentPacketFlowApplication::Ftp);

        let rsync = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(873),
            ..Default::default()
        };
        assert_eq!(rsync.application(), api::AgentPacketFlowApplication::Rsync);

        let openvpn_udp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(1194),
            ..Default::default()
        };
        assert_eq!(
            openvpn_udp.application(),
            api::AgentPacketFlowApplication::OpenVpn
        );

        let openvpn_tcp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(1194),
            ..Default::default()
        };
        assert_eq!(
            openvpn_tcp.application(),
            api::AgentPacketFlowApplication::OpenVpn
        );

        let smtp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(587),
            ..Default::default()
        };
        assert_eq!(smtp.application(), api::AgentPacketFlowApplication::Smtp);

        let imap = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(993),
            ..Default::default()
        };
        assert_eq!(imap.application(), api::AgentPacketFlowApplication::Imap);

        let pop3 = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(995),
            ..Default::default()
        };
        assert_eq!(pop3.application(), api::AgentPacketFlowApplication::Pop3);

        let sip_udp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            destination_port: Some(5060),
            ..Default::default()
        };
        assert_eq!(sip_udp.application(), api::AgentPacketFlowApplication::Sip);

        let sip_tls = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(5061),
            ..Default::default()
        };
        assert_eq!(sip_tls.application(), api::AgentPacketFlowApplication::Sip);

        let sip_sctp = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Sctp),
            destination_port: Some(5060),
            ..Default::default()
        };
        assert_eq!(sip_sctp.application(), api::AgentPacketFlowApplication::Sip);

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

        let solr = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(8983),
            ..Default::default()
        };
        assert_eq!(solr.application(), api::AgentPacketFlowApplication::Solr);

        let git = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Tcp),
            destination_port: Some(9418),
            ..Default::default()
        };
        assert_eq!(git.application(), api::AgentPacketFlowApplication::Git);

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

        fn tls_server_hello_with_alpn(protocol: &[u8]) -> Vec<u8> {
            tls_server_hello_with_alpn_protocols(&[protocol])
        }

        fn tls_server_hello_with_alpn_protocols(protocols: &[&[u8]]) -> Vec<u8> {
            let mut protocol_list = Vec::new();
            for protocol in protocols {
                protocol_list.push(protocol.len() as u8);
                protocol_list.extend_from_slice(protocol);
            }

            let mut alpn = Vec::new();
            alpn.extend_from_slice(&(protocol_list.len() as u16).to_be_bytes());
            alpn.extend_from_slice(&protocol_list);

            let mut extensions = Vec::new();
            extensions.extend_from_slice(&16_u16.to_be_bytes());
            extensions.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&alpn);

            let mut body = Vec::new();
            body.extend_from_slice(&[0x03, 0x03]);
            body.extend_from_slice(&[0xa5; 32]);
            body.push(0);
            body.extend_from_slice(&[0x13, 0x01]);
            body.push(0);
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);

            let mut payload = Vec::new();
            payload.extend_from_slice(&[0x16, 0x03, 0x03]);
            payload.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
            payload.push(0x02);
            let handshake_len = body.len() as u32;
            payload.extend_from_slice(&[
                ((handshake_len >> 16) & 0xff) as u8,
                ((handshake_len >> 8) & 0xff) as u8,
                (handshake_len & 0xff) as u8,
            ]);
            payload.extend_from_slice(&body);
            payload
        }

        fn git_pkt_line(service: &[u8], repository: &[u8]) -> Vec<u8> {
            let mut line = Vec::new();
            line.extend_from_slice(service);
            line.push(b' ');
            line.extend_from_slice(repository);
            line.push(0);
            line.extend_from_slice(b"host=git.example");

            let len = line.len() + 4;
            let mut payload = format!("{len:04x}").into_bytes();
            payload.extend_from_slice(&line);
            payload
        }

        fn wireguard_message(message_type: u32, len: usize) -> Vec<u8> {
            let mut payload = vec![0xa5; len];
            payload[..4].copy_from_slice(&message_type.to_le_bytes());
            payload
        }

        fn openvpn_plain_control(
            opcode: u8,
            acked_packet_ids: &[u32],
            packet_id: Option<u32>,
        ) -> Vec<u8> {
            let mut payload = vec![opcode << 3];
            payload.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
            payload.push(acked_packet_ids.len() as u8);
            for packet_id in acked_packet_ids {
                payload.extend_from_slice(&packet_id.to_be_bytes());
            }
            if !acked_packet_ids.is_empty() {
                payload.extend_from_slice(&0x8070_6050_4030_2010_u64.to_be_bytes());
            }
            if let Some(packet_id) = packet_id {
                payload.extend_from_slice(&packet_id.to_be_bytes());
            }
            payload
        }

        fn openvpn_hard_reset_client_v2() -> Vec<u8> {
            openvpn_plain_control(7, &[], Some(0))
        }

        fn openvpn_tcp_record(packet: &[u8]) -> Vec<u8> {
            let mut payload = (packet.len() as u16).to_be_bytes().to_vec();
            payload.extend_from_slice(packet);
            payload
        }

        fn stun_message(message_type: u16) -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(&message_type.to_be_bytes());
            payload.extend_from_slice(&0_u16.to_be_bytes());
            payload.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
            payload.extend_from_slice(&[0xa5; 12]);
            payload
        }

        fn stun_binding_request() -> Vec<u8> {
            stun_message(0x0001)
        }

        fn turn_allocate_request() -> Vec<u8> {
            stun_message(0x0003)
        }

        fn coap_get_request() -> Vec<u8> {
            vec![0x40, 0x01, 0x12, 0x34]
        }

        fn coap_get_uri_path_request(path: &[u8]) -> Vec<u8> {
            let mut payload = vec![0x41, 0x01, 0x12, 0x34, 0xaa];
            if path.len() <= 12 {
                payload.push(0xb0 | path.len() as u8);
            } else {
                payload.push(0xbd);
                payload.push((path.len() - 13) as u8);
            }
            payload.extend_from_slice(path);
            payload
        }

        fn ipars_relay_datagram() -> Vec<u8> {
            let session_id = b"session-a";
            let token = b"token-a";
            let payload = b"opaque-wireguard-payload";
            let mut datagram = Vec::new();
            datagram.extend_from_slice(b"IPARS-RLY1");
            datagram.extend_from_slice(&(session_id.len() as u16).to_be_bytes());
            datagram.extend_from_slice(&(token.len() as u16).to_be_bytes());
            datagram.extend_from_slice(session_id);
            datagram.extend_from_slice(token);
            datagram.extend_from_slice(payload);
            datagram
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

        fn postgres_backend_message(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut payload = vec![tag];
            let length = (body.len() as u32) + 4;
            payload.extend_from_slice(&length.to_be_bytes());
            payload.extend_from_slice(body);
            payload
        }

        fn postgres_parameter_status(name: &[u8], value: &[u8]) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(name);
            body.push(0);
            body.extend_from_slice(value);
            body.push(0);
            postgres_backend_message(b'S', &body)
        }

        fn postgres_backend_key_data(pid: u32, key: &[u8]) -> Vec<u8> {
            let mut body = pid.to_be_bytes().to_vec();
            body.extend_from_slice(key);
            postgres_backend_message(b'K', &body)
        }

        fn postgres_ready_for_query(status: u8) -> Vec<u8> {
            postgres_backend_message(b'Z', &[status])
        }

        fn postgres_command_complete(command: &[u8]) -> Vec<u8> {
            let mut body = command.to_vec();
            body.push(0);
            postgres_backend_message(b'C', &body)
        }

        fn postgres_error_response(fields: &[(u8, &[u8])]) -> Vec<u8> {
            let mut body = Vec::new();
            for (field_type, value) in fields {
                body.push(*field_type);
                body.extend_from_slice(value);
                body.push(0);
            }
            body.push(0);
            postgres_backend_message(b'E', &body)
        }

        fn postgres_bind_message_body(
            portal: &[u8],
            statement: &[u8],
            request_formats: &[u16],
            params: &[Option<&[u8]>],
            result_formats: &[u16],
        ) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(portal);
            body.push(0);
            body.extend_from_slice(statement);
            body.push(0);
            body.extend_from_slice(&(request_formats.len() as u16).to_be_bytes());
            for format in request_formats {
                body.extend_from_slice(&format.to_be_bytes());
            }
            body.extend_from_slice(&(params.len() as u16).to_be_bytes());
            for param in params {
                match param {
                    Some(value) => {
                        body.extend_from_slice(&(value.len() as u32).to_be_bytes());
                        body.extend_from_slice(value);
                    }
                    None => body.extend_from_slice(&u32::MAX.to_be_bytes()),
                }
            }
            body.extend_from_slice(&(result_formats.len() as u16).to_be_bytes());
            for format in result_formats {
                body.extend_from_slice(&format.to_be_bytes());
            }
            body
        }

        fn postgres_startup_message(params: &[(&[u8], &[u8])]) -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(&0_u32.to_be_bytes());
            payload.extend_from_slice(&196_608_u32.to_be_bytes());
            for (key, value) in params {
                payload.extend_from_slice(key);
                payload.push(0);
                payload.extend_from_slice(value);
                payload.push(0);
            }
            payload.push(0);
            let length = payload.len() as u32;
            payload[0..4].copy_from_slice(&length.to_be_bytes());
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

        fn mysql_client_handshake_response_packet(
            sequence_id: u8,
            client_flags: u32,
            username: &[u8],
            auth_response: &[u8],
            database: Option<&[u8]>,
            plugin: Option<&[u8]>,
            attrs: Option<&[(&[u8], &[u8])]>,
        ) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&client_flags.to_le_bytes());
            body.extend_from_slice(&16_777_216_u32.to_le_bytes());
            body.push(45);
            body.extend_from_slice(&[0; 23]);
            body.extend_from_slice(username);
            body.push(0);
            if client_flags & MYSQL_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
                body.push(auth_response.len() as u8);
                body.extend_from_slice(auth_response);
            } else if client_flags & MYSQL_CLIENT_SECURE_CONNECTION != 0 {
                body.push(auth_response.len() as u8);
                body.extend_from_slice(auth_response);
            } else {
                body.extend_from_slice(auth_response);
                body.push(0);
            }
            if client_flags & MYSQL_CLIENT_CONNECT_WITH_DB != 0 {
                body.extend_from_slice(database.unwrap_or(b"app"));
                body.push(0);
            }
            if client_flags & MYSQL_CLIENT_PLUGIN_AUTH != 0 {
                body.extend_from_slice(plugin.unwrap_or(b"caching_sha2_password"));
                body.push(0);
            }
            if client_flags & MYSQL_CLIENT_CONNECT_ATTRS != 0 {
                let mut encoded_attrs = Vec::new();
                for (key, value) in
                    attrs.unwrap_or(&[(b"_client_name".as_slice(), b"ipars-test".as_slice())])
                {
                    mysql_lenenc_string(&mut encoded_attrs, key);
                    mysql_lenenc_string(&mut encoded_attrs, value);
                }
                mysql_lenenc_string_length(&mut body, encoded_attrs.len());
                body.extend_from_slice(&encoded_attrs);
            }
            mysql_packet(sequence_id, &body)
        }

        fn mysql_lenenc_string(payload: &mut Vec<u8>, value: &[u8]) {
            mysql_lenenc_string_length(payload, value.len());
            payload.extend_from_slice(value);
        }

        fn mysql_lenenc_integer(payload: &mut Vec<u8>, value: u64) {
            assert!(
                value <= 250,
                "test helper only encodes small length-encoded integers"
            );
            payload.push(value as u8);
        }

        fn mysql_lenenc_string_length(payload: &mut Vec<u8>, len: usize) {
            assert!(
                len <= 250,
                "test helper only encodes small length-encoded strings"
            );
            payload.push(len as u8);
        }

        fn mysql_ssl_request_packet() -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(
                &(MYSQL_CLIENT_PROTOCOL_41 | MYSQL_CLIENT_SSL | MYSQL_CLIENT_SECURE_CONNECTION)
                    .to_le_bytes(),
            );
            body.extend_from_slice(&16_777_216_u32.to_le_bytes());
            body.push(45);
            body.extend_from_slice(&[0; 23]);
            mysql_packet(1, &body)
        }

        fn mysql_ok_packet(
            sequence_id: u8,
            affected_rows: u64,
            last_insert_id: u64,
            status_flags: u16,
            warnings: u16,
            info: &[u8],
        ) -> Vec<u8> {
            let mut body = Vec::new();
            body.push(0x00);
            mysql_lenenc_integer(&mut body, affected_rows);
            mysql_lenenc_integer(&mut body, last_insert_id);
            body.extend_from_slice(&status_flags.to_le_bytes());
            body.extend_from_slice(&warnings.to_le_bytes());
            body.extend_from_slice(info);
            mysql_packet(sequence_id, &body)
        }

        fn mysql_err_packet(
            sequence_id: u8,
            error_code: u16,
            sql_state: &[u8; 5],
            message: &[u8],
        ) -> Vec<u8> {
            let mut body = Vec::new();
            body.push(0xff);
            body.extend_from_slice(&error_code.to_le_bytes());
            body.push(b'#');
            body.extend_from_slice(sql_state);
            body.extend_from_slice(message);
            mysql_packet(sequence_id, &body)
        }

        fn mysql_eof_packet(sequence_id: u8, warnings: u16, status_flags: u16) -> Vec<u8> {
            let mut body = vec![0xfe];
            body.extend_from_slice(&warnings.to_le_bytes());
            body.extend_from_slice(&status_flags.to_le_bytes());
            mysql_packet(sequence_id, &body)
        }

        fn mysql_auth_switch_request_packet(
            sequence_id: u8,
            plugin: &[u8],
            auth_data: &[u8],
        ) -> Vec<u8> {
            let mut body = vec![0xfe];
            body.extend_from_slice(plugin);
            body.push(0);
            body.extend_from_slice(auth_data);
            mysql_packet(sequence_id, &body)
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

        fn mssql_done_token(status: u16, cur_cmd: u16, row_count: u64) -> Vec<u8> {
            let mut token = vec![0xfd];
            token.extend_from_slice(&status.to_le_bytes());
            token.extend_from_slice(&cur_cmd.to_le_bytes());
            token.extend_from_slice(&row_count.to_le_bytes());
            token
        }

        fn mssql_error_token(
            number: u32,
            state: u8,
            class: u8,
            message: &[u8],
            server: &[u8],
            procedure: &[u8],
            line: u32,
        ) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&number.to_le_bytes());
            body.push(state);
            body.push(class);
            body.extend_from_slice(&(message.len() as u16).to_le_bytes());
            body.extend_from_slice(&utf16le_ascii(message));
            body.push(server.len() as u8);
            body.extend_from_slice(&utf16le_ascii(server));
            body.push(procedure.len() as u8);
            body.extend_from_slice(&utf16le_ascii(procedure));
            body.extend_from_slice(&line.to_le_bytes());

            let mut token = vec![0xaa];
            token.extend_from_slice(&(body.len() as u16).to_le_bytes());
            token.extend_from_slice(&body);
            token
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

        fn clickhouse_client_hello(
            client_name: &[u8],
            revision: u64,
            database: &[u8],
            user: &[u8],
            password: &[u8],
            optional_tail: &[&[u8]],
        ) -> Vec<u8> {
            let mut payload = clickhouse_uvarint(0);
            payload.extend_from_slice(&clickhouse_string(client_name));
            payload.extend_from_slice(&clickhouse_uvarint(1));
            payload.extend_from_slice(&clickhouse_uvarint(10));
            payload.extend_from_slice(&clickhouse_uvarint(revision));
            payload.extend_from_slice(&clickhouse_string(database));
            payload.extend_from_slice(&clickhouse_string(user));
            payload.extend_from_slice(&clickhouse_string(password));
            for field in optional_tail {
                payload.extend_from_slice(&clickhouse_string(field));
            }
            payload
        }

        fn clickhouse_server_hello(
            server_name: &[u8],
            revision: u64,
            timezone: &[u8],
            display_name: &[u8],
            patch: u64,
        ) -> Vec<u8> {
            let mut payload = clickhouse_uvarint(0);
            payload.extend_from_slice(&clickhouse_string(server_name));
            payload.extend_from_slice(&clickhouse_uvarint(21));
            payload.extend_from_slice(&clickhouse_uvarint(12));
            payload.extend_from_slice(&clickhouse_uvarint(revision));
            payload.extend_from_slice(&clickhouse_string(timezone));
            payload.extend_from_slice(&clickhouse_string(display_name));
            payload.extend_from_slice(&clickhouse_uvarint(patch));
            payload
        }

        fn clickhouse_server_exception(
            code: u32,
            name: &[u8],
            message: &[u8],
            stack_trace: &[u8],
        ) -> Vec<u8> {
            let mut payload = clickhouse_uvarint(2);
            payload.extend_from_slice(&code.to_le_bytes());
            payload.extend_from_slice(&clickhouse_string(name));
            payload.extend_from_slice(&clickhouse_string(message));
            payload.extend_from_slice(&clickhouse_string(stack_trace));
            payload.push(0);
            payload
        }

        fn clickhouse_server_progress(
            rows: u64,
            bytes: u64,
            total_rows: u64,
            wrote_rows: u64,
            wrote_bytes: u64,
        ) -> Vec<u8> {
            let mut payload = clickhouse_uvarint(3);
            payload.extend_from_slice(&clickhouse_uvarint(rows));
            payload.extend_from_slice(&clickhouse_uvarint(bytes));
            payload.extend_from_slice(&clickhouse_uvarint(total_rows));
            payload.extend_from_slice(&clickhouse_uvarint(wrote_rows));
            payload.extend_from_slice(&clickhouse_uvarint(wrote_bytes));
            payload
        }

        fn clickhouse_empty_server_packet(packet_type: u64) -> Vec<u8> {
            clickhouse_uvarint(packet_type)
        }

        fn clickhouse_query_packet(query: &[u8], settings: &[(&[u8], &[u8], bool)]) -> Vec<u8> {
            let mut payload = clickhouse_uvarint(1);
            payload.extend_from_slice(&clickhouse_string(b"query-1"));

            payload.push(1);
            payload.extend_from_slice(&clickhouse_string(b"reader"));
            payload.extend_from_slice(&clickhouse_string(b"query-1"));
            payload.extend_from_slice(&clickhouse_string(b"127.0.0.1:9000"));
            payload.extend_from_slice(&0_i64.to_le_bytes());
            payload.push(1);
            payload.extend_from_slice(&clickhouse_string(b"ipars"));
            payload.extend_from_slice(&clickhouse_string(b"edge-a"));
            payload.extend_from_slice(&clickhouse_string(b"Go Client"));
            payload.extend_from_slice(&clickhouse_uvarint(1));
            payload.extend_from_slice(&clickhouse_uvarint(10));
            payload.extend_from_slice(&clickhouse_uvarint(54_451));
            payload.extend_from_slice(&clickhouse_string(b""));
            payload.extend_from_slice(&clickhouse_uvarint(0));
            payload.extend_from_slice(&clickhouse_uvarint(3));
            payload.push(0);

            for (key, value, important) in settings {
                payload.extend_from_slice(&clickhouse_string(key));
                payload.extend_from_slice(&clickhouse_string(value));
                payload.push(u8::from(*important));
            }
            payload.extend_from_slice(&clickhouse_string(b""));
            payload.extend_from_slice(&clickhouse_string(b""));

            payload.extend_from_slice(&clickhouse_string(b""));
            payload.extend_from_slice(&clickhouse_uvarint(2));
            payload.extend_from_slice(&clickhouse_uvarint(0));
            payload.extend_from_slice(&clickhouse_string(query));
            payload
        }

        fn clickhouse_string(value: &[u8]) -> Vec<u8> {
            let mut encoded = clickhouse_uvarint(value.len() as u64);
            encoded.extend_from_slice(value);
            encoded
        }

        fn clickhouse_uvarint(mut value: u64) -> Vec<u8> {
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

        fn memcached_binary_response(
            opcode: u8,
            status: u16,
            key: &[u8],
            extras: &[u8],
            value: &[u8],
        ) -> Vec<u8> {
            let total_body_len = extras.len() + key.len() + value.len();
            let mut payload = Vec::with_capacity(24 + total_body_len);
            payload.push(0x81);
            payload.push(opcode);
            payload.extend_from_slice(&(key.len() as u16).to_be_bytes());
            payload.push(extras.len() as u8);
            payload.push(0);
            payload.extend_from_slice(&status.to_be_bytes());
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

        fn amqp_frame(frame_type: u8, channel: u16, body: &[u8]) -> Vec<u8> {
            let mut payload = vec![frame_type];
            payload.extend_from_slice(&channel.to_be_bytes());
            payload.extend_from_slice(&(body.len() as u32).to_be_bytes());
            payload.extend_from_slice(body);
            payload.push(0xce);
            payload
        }

        fn amqp_content_header_body(
            class_id: u16,
            weight: u16,
            body_size: u64,
            property_flags: u16,
            properties: &[u8],
        ) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&class_id.to_be_bytes());
            body.extend_from_slice(&weight.to_be_bytes());
            body.extend_from_slice(&body_size.to_be_bytes());
            body.extend_from_slice(&property_flags.to_be_bytes());
            body.extend_from_slice(properties);
            body
        }

        fn amqp_short_string(value: &[u8]) -> Vec<u8> {
            let mut encoded = vec![value.len() as u8];
            encoded.extend_from_slice(value);
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

        fn mqtt_connack_packet(
            ack_flags: u8,
            reason_code: u8,
            properties: Option<&[u8]>,
        ) -> Vec<u8> {
            let mut body = vec![ack_flags, reason_code];
            if let Some(properties) = properties {
                body.extend_from_slice(&mqtt_remaining_length(properties.len()));
                body.extend_from_slice(properties);
            }
            let mut payload = vec![0x20];
            payload.extend_from_slice(&mqtt_remaining_length(body.len()));
            payload.extend_from_slice(&body);
            payload
        }

        fn mqtt_publish_packet(
            flags: u8,
            topic: &[u8],
            packet_id: Option<u16>,
            payload: &[u8],
        ) -> Vec<u8> {
            let mut body = mqtt_field(topic);
            if let Some(packet_id) = packet_id {
                body.extend_from_slice(&packet_id.to_be_bytes());
            }
            body.extend_from_slice(payload);
            let mut packet = vec![0x30 | flags];
            packet.extend_from_slice(&mqtt_remaining_length(body.len()));
            packet.extend_from_slice(&body);
            packet
        }

        fn mqtt_subscribe_packet(packet_id: u16, filters: &[(&[u8], u8)]) -> Vec<u8> {
            let mut body = packet_id.to_be_bytes().to_vec();
            for (filter, options) in filters {
                body.extend_from_slice(&mqtt_field(filter));
                body.push(*options);
            }
            let mut packet = vec![0x82];
            packet.extend_from_slice(&mqtt_remaining_length(body.len()));
            packet.extend_from_slice(&body);
            packet
        }

        fn mqtt_subscribe_v5_packet(
            packet_id: u16,
            properties: &[u8],
            filters: &[(&[u8], u8)],
        ) -> Vec<u8> {
            let mut body = packet_id.to_be_bytes().to_vec();
            body.extend_from_slice(&mqtt_remaining_length(properties.len()));
            body.extend_from_slice(properties);
            for (filter, options) in filters {
                body.extend_from_slice(&mqtt_field(filter));
                body.push(*options);
            }
            let mut packet = vec![0x82];
            packet.extend_from_slice(&mqtt_remaining_length(body.len()));
            packet.extend_from_slice(&body);
            packet
        }

        fn mqtt_unsubscribe_packet(packet_id: u16, filters: &[&[u8]]) -> Vec<u8> {
            let mut body = packet_id.to_be_bytes().to_vec();
            for filter in filters {
                body.extend_from_slice(&mqtt_field(filter));
            }
            let mut packet = vec![0xa2];
            packet.extend_from_slice(&mqtt_remaining_length(body.len()));
            packet.extend_from_slice(&body);
            packet
        }

        fn mqtt_unsubscribe_v5_packet(
            packet_id: u16,
            properties: &[u8],
            filters: &[&[u8]],
        ) -> Vec<u8> {
            let mut body = packet_id.to_be_bytes().to_vec();
            body.extend_from_slice(&mqtt_remaining_length(properties.len()));
            body.extend_from_slice(properties);
            for filter in filters {
                body.extend_from_slice(&mqtt_field(filter));
            }
            let mut packet = vec![0xa2];
            packet.extend_from_slice(&mqtt_remaining_length(body.len()));
            packet.extend_from_slice(&body);
            packet
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

        fn cassandra_response_frame(opcode: u8, body: &[u8]) -> Vec<u8> {
            let mut payload = vec![0x84, 0, 0, 0, opcode];
            payload.extend_from_slice(&(body.len() as u32).to_be_bytes());
            payload.extend_from_slice(body);
            payload
        }

        fn cassandra_string(value: &[u8]) -> Vec<u8> {
            let mut encoded = (value.len() as u16).to_be_bytes().to_vec();
            encoded.extend_from_slice(value);
            encoded
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
        let observation_for_clickhouse_native_payload =
            |payload: &[u8]| api::AgentPacketFlowObservation {
                protocol: Some(TransportProtocol::Tcp),
                destination_port: Some(9000),
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
        let mut multi_question_dns_query = dns_query.clone();
        multi_question_dns_query[5] = 2;
        multi_question_dns_query.extend_from_slice(&[
            0x03, b'a', b'p', b'i', 0x02, b'v', b'6', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00,
            0x00, 0x1c, 0x00, 0x01,
        ]);
        assert_eq!(
            observation_for_udp_payload(&multi_question_dns_query).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut missing_second_dns_question = dns_query.clone();
        missing_second_dns_question[5] = 2;
        assert_eq!(
            observation_for_udp_payload(&missing_second_dns_question).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut excessive_question_count_dns_query = dns_query.clone();
        excessive_question_count_dns_query[5] = 65;
        assert_eq!(
            observation_for_udp_payload(&excessive_question_count_dns_query).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut truncated_second_question_dns_query = dns_query.clone();
        truncated_second_question_dns_query[5] = 2;
        truncated_second_question_dns_query.push(63);
        truncated_second_question_dns_query.extend(std::iter::repeat_n(b'a', 63));
        truncated_second_question_dns_query.push(63);
        truncated_second_question_dns_query.resize(api::PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES, b'a');
        assert_eq!(
            observation_for_udp_payload(&truncated_second_question_dns_query).application(),
            api::AgentPacketFlowApplication::Dns
        );
        assert_eq!(
            observation_for_udp_payload(
                &truncated_second_question_dns_query
                    [..api::PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES - 1]
            )
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_query_with_opt = dns_query.clone();
        dns_query_with_opt[11] = 1;
        dns_query_with_opt.extend_from_slice(&[
            0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_query_with_opt).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let opt_type_offset = dns_query.len() + 1;
        let mut dns_query_with_do_opt = dns_query_with_opt.clone();
        dns_query_with_do_opt[opt_type_offset + 6] = 0x80;
        assert_eq!(
            observation_for_udp_payload(&dns_query_with_do_opt).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut missing_dns_query_additional = dns_query.clone();
        missing_dns_query_additional[11] = 1;
        assert_eq!(
            observation_for_udp_payload(&missing_dns_query_additional).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_query_with_bad_opt_type = dns_query_with_opt.clone();
        dns_query_with_bad_opt_type[opt_type_offset] = 0;
        dns_query_with_bad_opt_type[opt_type_offset + 1] = 0;
        assert_eq!(
            observation_for_udp_payload(&dns_query_with_bad_opt_type).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_query_with_bad_opt_size = dns_query_with_opt.clone();
        dns_query_with_bad_opt_size[opt_type_offset + 2] = 0x00;
        dns_query_with_bad_opt_size[opt_type_offset + 3] = 0x01;
        assert_eq!(
            observation_for_udp_payload(&dns_query_with_bad_opt_size).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_query_with_bad_opt_version = dns_query_with_opt.clone();
        dns_query_with_bad_opt_version[opt_type_offset + 5] = 1;
        assert_eq!(
            observation_for_udp_payload(&dns_query_with_bad_opt_version).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_query_with_bad_opt_flags = dns_query_with_opt.clone();
        dns_query_with_bad_opt_flags[opt_type_offset + 7] = 1;
        assert_eq!(
            observation_for_udp_payload(&dns_query_with_bad_opt_flags).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_query_with_named_opt = dns_query.clone();
        dns_query_with_named_opt[11] = 1;
        dns_query_with_named_opt.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_query_with_named_opt).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_query_with_answer_section = dns_query.clone();
        dns_query_with_answer_section[7] = 1;
        dns_query_with_answer_section.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 23,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_query_with_answer_section).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_query_with_authority_section = dns_query.clone();
        dns_query_with_authority_section[9] = 1;
        dns_query_with_authority_section.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 24,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_query_with_authority_section).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_tcp_payload = (dns_query.len() as u16).to_be_bytes().to_vec();
        dns_tcp_payload.extend_from_slice(&dns_query);
        assert_eq!(
            observation_for_payload(&dns_tcp_payload).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut short_declared_dns_tcp_payload =
            ((dns_query.len() - 1) as u16).to_be_bytes().to_vec();
        short_declared_dns_tcp_payload.extend_from_slice(&dns_query);
        assert_eq!(
            observation_for_payload(&short_declared_dns_tcp_payload).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut long_declared_dns_tcp_payload =
            ((dns_query.len() + 1) as u16).to_be_bytes().to_vec();
        long_declared_dns_tcp_payload.extend_from_slice(&dns_query);
        assert_eq!(
            observation_for_payload(&long_declared_dns_tcp_payload).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_response_with_answer = dns_query.clone();
        dns_response_with_answer[2] = 0x81;
        dns_response_with_answer[3] = 0x80;
        dns_response_with_answer[7] = 0x01;
        dns_response_with_answer.extend_from_slice(&[
            0x03, b'a', b'p', b'i', 0x07, b's', b'e', b'r', b'v', b'i', b'c', b'e', 0x05, b'l',
            b'o', b'c', b'a', b'l', 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00,
            0x04, 192, 0, 2, 20,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_compressed_answer = dns_query.clone();
        dns_response_with_compressed_answer[2] = 0x81;
        dns_response_with_compressed_answer[3] = 0x80;
        dns_response_with_compressed_answer[7] = 0x01;
        dns_response_with_compressed_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 21,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_compressed_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_aaaa_answer = dns_query.clone();
        dns_response_with_aaaa_answer[2] = 0x81;
        dns_response_with_aaaa_answer[3] = 0x80;
        dns_response_with_aaaa_answer[7] = 0x01;
        dns_response_with_aaaa_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10, 0x20, 0x01,
            0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_aaaa_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_cname_answer = dns_query.clone();
        dns_response_with_cname_answer[2] = 0x81;
        dns_response_with_cname_answer[3] = 0x80;
        dns_response_with_cname_answer[7] = 0x01;
        dns_response_with_cname_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x02, 0xc0, 0x0c,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_cname_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_cname_rdata = dns_response_with_cname_answer.clone();
        let cname_rdlength_offset = dns_query.len() + 10;
        dns_response_with_bad_cname_rdata[cname_rdlength_offset] = 0x00;
        dns_response_with_bad_cname_rdata[cname_rdlength_offset + 1] = 0x03;
        dns_response_with_bad_cname_rdata.push(0x00);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_cname_rdata).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let qtype_offset = dns_query.len() - 4;
        let mut mb_query = dns_query.clone();
        mb_query[qtype_offset] = 0x00;
        mb_query[qtype_offset + 1] = 0x07;
        let mut dns_response_with_mb_answer = mb_query.clone();
        dns_response_with_mb_answer[2] = 0x81;
        dns_response_with_mb_answer[3] = 0x80;
        dns_response_with_mb_answer[7] = 0x01;
        dns_response_with_mb_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x02, 0xc0, 0x0c,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_mb_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_mb_rdata = dns_response_with_mb_answer.clone();
        let mb_rdata_pointer_offset = mb_query.len() + 12;
        dns_response_with_bad_mb_rdata[mb_rdata_pointer_offset + 1] = 0xff;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_mb_rdata).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut minfo_query = dns_query.clone();
        minfo_query[qtype_offset] = 0x00;
        minfo_query[qtype_offset + 1] = 0x0e;
        let mut dns_response_with_minfo_answer = minfo_query.clone();
        dns_response_with_minfo_answer[2] = 0x81;
        dns_response_with_minfo_answer[3] = 0x80;
        dns_response_with_minfo_answer[7] = 0x01;
        dns_response_with_minfo_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0x0c,
            0xc0, 0x0c,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_minfo_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_minfo_rdata = dns_response_with_minfo_answer.clone();
        let minfo_second_pointer_offset = minfo_query.len() + 14;
        dns_response_with_bad_minfo_rdata[minfo_second_pointer_offset + 1] = 0xff;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_minfo_rdata).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut afsdb_query = dns_query.clone();
        afsdb_query[qtype_offset] = 0x00;
        afsdb_query[qtype_offset + 1] = 0x12;
        let mut dns_response_with_afsdb_answer = afsdb_query.clone();
        dns_response_with_afsdb_answer[2] = 0x81;
        dns_response_with_afsdb_answer[3] = 0x80;
        dns_response_with_afsdb_answer[7] = 0x01;
        dns_response_with_afsdb_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x12, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0x00, 0x01,
            0xc0, 0x0c,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_afsdb_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_afsdb_rdata = dns_response_with_afsdb_answer.clone();
        let afsdb_answer_rdlength_offset = afsdb_query.len() + 10;
        dns_response_with_bad_afsdb_rdata[afsdb_answer_rdlength_offset + 1] = 0x03;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_afsdb_rdata).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut px_query = dns_query.clone();
        px_query[qtype_offset] = 0x00;
        px_query[qtype_offset + 1] = 0x1a;
        let mut dns_response_with_px_answer = px_query.clone();
        dns_response_with_px_answer[2] = 0x81;
        dns_response_with_px_answer[3] = 0x80;
        dns_response_with_px_answer[7] = 0x01;
        dns_response_with_px_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x06, 0x00, 0x0a,
            0xc0, 0x0c, 0xc0, 0x0c,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_px_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_px_rdata = dns_response_with_px_answer.clone();
        let px_second_pointer_offset = px_query.len() + 16;
        dns_response_with_bad_px_rdata[px_second_pointer_offset + 1] = 0xff;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_px_rdata).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut soa_query = dns_query.clone();
        soa_query[qtype_offset] = 0x00;
        soa_query[qtype_offset + 1] = 0x06;
        let mut dns_response_with_soa_answer = soa_query.clone();
        dns_response_with_soa_answer[2] = 0x81;
        dns_response_with_soa_answer[3] = 0x80;
        dns_response_with_soa_answer[7] = 0x01;
        dns_response_with_soa_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x18, 0xc0, 0x0c,
            0xc0, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00, 0x02, 0x58,
            0x00, 0x09, 0x3a, 0x80, 0x00, 0x00, 0x00, 0x3c,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_soa_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_soa_length = dns_response_with_soa_answer.clone();
        let soa_answer_rdlength_offset = soa_query.len() + 10;
        dns_response_with_bad_soa_length[soa_answer_rdlength_offset] = 0x00;
        dns_response_with_bad_soa_length[soa_answer_rdlength_offset + 1] = 0x17;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_soa_length).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_response_with_bad_soa_rname = dns_response_with_soa_answer.clone();
        let soa_rname_pointer_offset = soa_query.len() + 14;
        dns_response_with_bad_soa_rname[soa_rname_pointer_offset + 1] = 0xff;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_soa_rname).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut hinfo_query = dns_query.clone();
        hinfo_query[qtype_offset] = 0x00;
        hinfo_query[qtype_offset + 1] = 0x0d;
        let mut dns_response_with_hinfo_answer = hinfo_query.clone();
        dns_response_with_hinfo_answer[2] = 0x81;
        dns_response_with_hinfo_answer[3] = 0x80;
        dns_response_with_hinfo_answer[7] = 0x01;
        dns_response_with_hinfo_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x0d, 0x06, b'x',
            b'8', b'6', b'_', b'6', b'4', 0x05, b'l', b'i', b'n', b'u', b'x',
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_hinfo_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_hinfo_rdata = dns_response_with_hinfo_answer.clone();
        let hinfo_answer_rdlength_offset = hinfo_query.len() + 10;
        dns_response_with_bad_hinfo_rdata[hinfo_answer_rdlength_offset] = 0x00;
        dns_response_with_bad_hinfo_rdata[hinfo_answer_rdlength_offset + 1] = 0x0e;
        dns_response_with_bad_hinfo_rdata.push(0x00);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_hinfo_rdata).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut txt_query = dns_query.clone();
        txt_query[qtype_offset] = 0x00;
        txt_query[qtype_offset + 1] = 0x10;
        let mut dns_response_with_txt_answer = txt_query.clone();
        dns_response_with_txt_answer[2] = 0x81;
        dns_response_with_txt_answer[3] = 0x80;
        dns_response_with_txt_answer[7] = 0x01;
        dns_response_with_txt_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x0b, 0x03, b'v',
            b'=', b'1', 0x06, b'i', b'p', b'a', b'r', b's', b'!',
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_txt_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_txt_rdata = dns_response_with_txt_answer.clone();
        let txt_second_string_len_offset = txt_query.len() + 16;
        dns_response_with_bad_txt_rdata[txt_second_string_len_offset] = 0x07;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_txt_rdata).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut naptr_query = dns_query.clone();
        naptr_query[qtype_offset] = 0x00;
        naptr_query[qtype_offset + 1] = 0x23;
        let mut dns_response_with_naptr_answer = naptr_query.clone();
        dns_response_with_naptr_answer[2] = 0x81;
        dns_response_with_naptr_answer[3] = 0x80;
        dns_response_with_naptr_answer[7] = 0x01;
        dns_response_with_naptr_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x23, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x11, 0x00, 0x01,
            0x00, 0x0a, 0x01, b'S', 0x07, b'S', b'I', b'P', b'+', b'D', b'2', b'U', 0x00, 0xc0,
            0x0c,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_naptr_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_naptr_rdata = dns_response_with_naptr_answer.clone();
        let naptr_services_len_offset = naptr_query.len() + 18;
        dns_response_with_bad_naptr_rdata[naptr_services_len_offset] = 0x08;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_naptr_rdata).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut caa_query = dns_query.clone();
        caa_query[qtype_offset] = 0x01;
        caa_query[qtype_offset + 1] = 0x01;
        let mut dns_response_with_caa_answer = caa_query.clone();
        dns_response_with_caa_answer[2] = 0x81;
        dns_response_with_caa_answer[3] = 0x80;
        dns_response_with_caa_answer[7] = 0x01;
        dns_response_with_caa_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x0c, 0x00, 0x05,
            b'i', b's', b's', b'u', b'e', b'c', b'a', b'.', b'i', b'o',
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_caa_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_caa_tag = dns_response_with_caa_answer.clone();
        let caa_tag_len_offset = caa_query.len() + 13;
        dns_response_with_bad_caa_tag[caa_tag_len_offset] = 0x00;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_caa_tag).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_response_with_bad_caa_rdata = dns_response_with_caa_answer.clone();
        let caa_tag_offset = caa_query.len() + 14;
        dns_response_with_bad_caa_rdata[caa_tag_offset] = b'-';
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_caa_rdata).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut ds_query = dns_query.clone();
        ds_query[qtype_offset] = 0x00;
        ds_query[qtype_offset + 1] = 0x2b;
        let mut dns_response_with_ds_answer = ds_query.clone();
        dns_response_with_ds_answer[2] = 0x81;
        dns_response_with_ds_answer[3] = 0x80;
        dns_response_with_ds_answer[7] = 0x01;
        dns_response_with_ds_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x2b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x24, 0x12, 0x34,
            0x0d, 0x02, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
            0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
            0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_ds_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_ds_length = dns_response_with_ds_answer.clone();
        let ds_answer_rdlength_offset = ds_query.len() + 10;
        dns_response_with_bad_ds_length[ds_answer_rdlength_offset + 1] = 0x23;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_ds_length).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dnskey_query = dns_query.clone();
        dnskey_query[qtype_offset] = 0x00;
        dnskey_query[qtype_offset + 1] = 0x30;
        let mut dns_response_with_dnskey_answer = dnskey_query.clone();
        dns_response_with_dnskey_answer[2] = 0x81;
        dns_response_with_dnskey_answer[3] = 0x80;
        dns_response_with_dnskey_answer[7] = 0x01;
        dns_response_with_dnskey_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x0c, 0x01, 0x01,
            0x03, 0x0d, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_dnskey_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_dnskey_protocol = dns_response_with_dnskey_answer.clone();
        let dnskey_protocol_offset = dnskey_query.len() + 14;
        dns_response_with_bad_dnskey_protocol[dnskey_protocol_offset] = 0x02;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_dnskey_protocol).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut rrsig_query = dns_query.clone();
        rrsig_query[qtype_offset] = 0x00;
        rrsig_query[qtype_offset + 1] = 0x2e;
        let mut dns_response_with_rrsig_answer = rrsig_query.clone();
        dns_response_with_rrsig_answer[2] = 0x81;
        dns_response_with_rrsig_answer[3] = 0x80;
        dns_response_with_rrsig_answer[7] = 0x01;
        dns_response_with_rrsig_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x2e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x18, 0x00, 0x01,
            0x0d, 0x03, 0x00, 0x00, 0x00, 0x78, 0x70, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
            0x12, 0x34, 0xc0, 0x0c, 0xc3, 0xc3, 0xc3, 0xc3,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_rrsig_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_rrsig_signer = dns_response_with_rrsig_answer.clone();
        let rrsig_signer_pointer_offset = rrsig_query.len() + 30;
        dns_response_with_bad_rrsig_signer[rrsig_signer_pointer_offset + 1] = 0xff;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_rrsig_signer).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_response_with_empty_rrsig_signature = dns_response_with_rrsig_answer.clone();
        let rrsig_answer_rdlength_offset = rrsig_query.len() + 10;
        dns_response_with_empty_rrsig_signature[rrsig_answer_rdlength_offset + 1] = 0x14;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_empty_rrsig_signature).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut nsec_query = dns_query.clone();
        nsec_query[qtype_offset] = 0x00;
        nsec_query[qtype_offset + 1] = 0x2f;
        let mut dns_response_with_nsec_answer = nsec_query.clone();
        dns_response_with_nsec_answer[2] = 0x81;
        dns_response_with_nsec_answer[3] = 0x80;
        dns_response_with_nsec_answer[7] = 0x01;
        dns_response_with_nsec_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x2f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x05, 0xc0, 0x0c,
            0x00, 0x01, 0x40,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_nsec_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_nsec_bitmap = dns_response_with_nsec_answer.clone();
        let nsec_bitmap_byte_offset = nsec_query.len() + 16;
        dns_response_with_bad_nsec_bitmap[nsec_bitmap_byte_offset] = 0x00;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_nsec_bitmap).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut nsec3_query = dns_query.clone();
        nsec3_query[qtype_offset] = 0x00;
        nsec3_query[qtype_offset + 1] = 0x32;
        let mut dns_response_with_nsec3_answer = nsec3_query.clone();
        dns_response_with_nsec3_answer[2] = 0x81;
        dns_response_with_nsec3_answer[3] = 0x80;
        dns_response_with_nsec3_answer[7] = 0x01;
        dns_response_with_nsec3_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x32, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x0f, 0x01, 0x00,
            0x00, 0x02, 0x02, 0xaa, 0xbb, 0x04, 0x01, 0x02, 0x03, 0x04, 0x00, 0x01, 0x40,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_nsec3_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_nsec3_flags = dns_response_with_nsec3_answer.clone();
        let nsec3_flags_offset = nsec3_query.len() + 13;
        dns_response_with_bad_nsec3_flags[nsec3_flags_offset] = 0x02;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_nsec3_flags).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_response_with_bad_nsec3_hash = dns_response_with_nsec3_answer.clone();
        let nsec3_hash_len_offset = nsec3_query.len() + 19;
        dns_response_with_bad_nsec3_hash[nsec3_hash_len_offset] = 0x00;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_nsec3_hash).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut nsec3param_query = dns_query.clone();
        nsec3param_query[qtype_offset] = 0x00;
        nsec3param_query[qtype_offset + 1] = 0x33;
        let mut dns_response_with_nsec3param_answer = nsec3param_query.clone();
        dns_response_with_nsec3param_answer[2] = 0x81;
        dns_response_with_nsec3param_answer[3] = 0x80;
        dns_response_with_nsec3param_answer[7] = 0x01;
        dns_response_with_nsec3param_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x33, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x07, 0x01, 0x00,
            0x00, 0x02, 0x02, 0xaa, 0xbb,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_nsec3param_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_nsec3param_salt = dns_response_with_nsec3param_answer.clone();
        let nsec3param_salt_len_offset = nsec3param_query.len() + 16;
        dns_response_with_bad_nsec3param_salt[nsec3param_salt_len_offset] = 0x03;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_nsec3param_salt).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dname_query = dns_query.clone();
        dname_query[qtype_offset] = 0x00;
        dname_query[qtype_offset + 1] = 0x27;
        let mut dns_response_with_dname_answer = dname_query.clone();
        dns_response_with_dname_answer[2] = 0x81;
        dns_response_with_dname_answer[3] = 0x80;
        dns_response_with_dname_answer[7] = 0x01;
        dns_response_with_dname_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x27, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x02, 0xc0, 0x0c,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_dname_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_dname_rdata = dns_response_with_dname_answer.clone();
        let dname_target_pointer_offset = dname_query.len() + 12;
        dns_response_with_bad_dname_rdata[dname_target_pointer_offset + 1] = 0xff;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_dname_rdata).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut sshfp_query = dns_query.clone();
        sshfp_query[qtype_offset] = 0x00;
        sshfp_query[qtype_offset + 1] = 0x2c;
        let mut dns_response_with_sshfp_answer = sshfp_query.clone();
        dns_response_with_sshfp_answer[2] = 0x81;
        dns_response_with_sshfp_answer[3] = 0x80;
        dns_response_with_sshfp_answer[7] = 0x01;
        dns_response_with_sshfp_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x22, 0x04, 0x02,
        ]);
        dns_response_with_sshfp_answer.extend(std::iter::repeat_n(0xb6, 32));
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_sshfp_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_sshfp_length = dns_response_with_sshfp_answer.clone();
        let sshfp_answer_rdlength_offset = sshfp_query.len() + 10;
        dns_response_with_bad_sshfp_length[sshfp_answer_rdlength_offset + 1] = 0x21;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_sshfp_length).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut tlsa_query = dns_query.clone();
        tlsa_query[qtype_offset] = 0x00;
        tlsa_query[qtype_offset + 1] = 0x34;
        let mut dns_response_with_tlsa_answer = tlsa_query.clone();
        dns_response_with_tlsa_answer[2] = 0x81;
        dns_response_with_tlsa_answer[3] = 0x80;
        dns_response_with_tlsa_answer[7] = 0x01;
        dns_response_with_tlsa_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x34, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x23, 0x03, 0x01,
            0x01,
        ]);
        dns_response_with_tlsa_answer.extend(std::iter::repeat_n(0xc4, 32));
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_tlsa_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_tlsa_selector = dns_response_with_tlsa_answer.clone();
        let tlsa_selector_offset = tlsa_query.len() + 13;
        dns_response_with_bad_tlsa_selector[tlsa_selector_offset] = 0x02;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_tlsa_selector).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut smimea_query = dns_query.clone();
        smimea_query[qtype_offset] = 0x00;
        smimea_query[qtype_offset + 1] = 0x35;
        let mut dns_response_with_smimea_answer = smimea_query.clone();
        dns_response_with_smimea_answer[2] = 0x81;
        dns_response_with_smimea_answer[3] = 0x80;
        dns_response_with_smimea_answer[7] = 0x01;
        dns_response_with_smimea_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x35, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x43, 0x03, 0x01,
            0x02,
        ]);
        dns_response_with_smimea_answer.extend(std::iter::repeat_n(0xc5, 64));
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_smimea_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_smimea_length = dns_response_with_smimea_answer.clone();
        let smimea_answer_rdlength_offset = smimea_query.len() + 10;
        dns_response_with_bad_smimea_length[smimea_answer_rdlength_offset + 1] = 0x42;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_smimea_length).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut uri_query = dns_query.clone();
        uri_query[qtype_offset] = 0x01;
        uri_query[qtype_offset + 1] = 0x00;
        let mut dns_response_with_uri_answer = uri_query.clone();
        dns_response_with_uri_answer[2] = 0x81;
        dns_response_with_uri_answer[3] = 0x80;
        dns_response_with_uri_answer[7] = 0x01;
        dns_response_with_uri_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x12, 0x00, 0x0a,
            0x00, 0x01, b'h', b't', b't', b'p', b's', b':', b'/', b'/', b'i', b'p', b'a', b'.',
            b'r', b's',
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_uri_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_uri_target = dns_response_with_uri_answer.clone();
        let uri_target_offset = uri_query.len() + 16;
        dns_response_with_bad_uri_target[uri_target_offset] = 0x00;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_uri_target).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut svcb_query = dns_query.clone();
        svcb_query[qtype_offset] = 0x00;
        svcb_query[qtype_offset + 1] = 0x40;
        let mut dns_response_with_svcb_answer = svcb_query.clone();
        dns_response_with_svcb_answer[2] = 0x81;
        dns_response_with_svcb_answer[3] = 0x80;
        dns_response_with_svcb_answer[7] = 0x01;
        dns_response_with_svcb_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x1c, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x06, 0x02, b'h', b'2', 0x02, b'h', b'3', 0x00, 0x03,
            0x00, 0x02, 0x01, 0xbb, 0x00, 0x04, 0x00, 0x04, 192, 0, 2, 10,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_svcb_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_duplicate_svcb_param = dns_response_with_svcb_answer.clone();
        let svcb_second_param_key_offset = svcb_query.len() + 26;
        dns_response_with_duplicate_svcb_param[svcb_second_param_key_offset] = 0x00;
        dns_response_with_duplicate_svcb_param[svcb_second_param_key_offset + 1] = 0x01;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_duplicate_svcb_param).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_response_with_bad_svcb_alpn = dns_response_with_svcb_answer.clone();
        let svcb_first_alpn_len_offset = svcb_query.len() + 20;
        dns_response_with_bad_svcb_alpn[svcb_first_alpn_len_offset] = 0x00;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_svcb_alpn).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut https_query = dns_query.clone();
        https_query[qtype_offset] = 0x00;
        https_query[qtype_offset + 1] = 0x41;
        let mut dns_response_with_https_alias = https_query.clone();
        dns_response_with_https_alias[2] = 0x81;
        dns_response_with_https_alias[3] = 0x80;
        dns_response_with_https_alias[7] = 0x01;
        dns_response_with_https_alias.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0x00, 0x00,
            0xc0, 0x0c,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_https_alias).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_https_alias = https_query.clone();
        dns_response_with_bad_https_alias[2] = 0x81;
        dns_response_with_bad_https_alias[3] = 0x80;
        dns_response_with_bad_https_alias[7] = 0x01;
        dns_response_with_bad_https_alias.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x08, 0x00, 0x00,
            0xc0, 0x0c, 0x00, 0x02, 0x00, 0x00,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_https_alias).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_response_with_bad_class = dns_response_with_compressed_answer.clone();
        let compressed_answer_class_offset = dns_query.len() + 4;
        dns_response_with_bad_class[compressed_answer_class_offset] = 0xff;
        dns_response_with_bad_class[compressed_answer_class_offset + 1] = 0x00;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_class).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let compressed_answer_rdlength_offset = dns_query.len() + 10;
        let mut dns_response_with_bad_a_length = dns_response_with_compressed_answer.clone();
        dns_response_with_bad_a_length[compressed_answer_rdlength_offset] = 0x00;
        dns_response_with_bad_a_length[compressed_answer_rdlength_offset + 1] = 0x03;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_a_length).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_response_with_bad_aaaa_length = dns_response_with_aaaa_answer.clone();
        dns_response_with_bad_aaaa_length[compressed_answer_rdlength_offset] = 0x00;
        dns_response_with_bad_aaaa_length[compressed_answer_rdlength_offset + 1] = 0x04;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_aaaa_length).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut missing_dns_answer = dns_query.clone();
        missing_dns_answer[2] = 0x81;
        missing_dns_answer[3] = 0x80;
        missing_dns_answer[7] = 0x01;
        assert_eq!(
            observation_for_udp_payload(&missing_dns_answer).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut dns_response_self_pointer_answer = dns_query.clone();
        dns_response_self_pointer_answer[2] = 0x81;
        dns_response_self_pointer_answer[3] = 0x80;
        dns_response_self_pointer_answer[7] = 0x01;
        let self_pointer =
            0xc000_u16 | u16::try_from(dns_response_self_pointer_answer.len()).unwrap();
        dns_response_self_pointer_answer.extend_from_slice(&self_pointer.to_be_bytes());
        dns_response_self_pointer_answer.extend_from_slice(&[
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 22,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_self_pointer_answer).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let ptr_query = vec![
            0x12, 0x35, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, b'1',
            b'0', 0x01, b'2', 0x01, b'0', 0x03, b'1', b'9', b'2', 0x07, b'i', b'n', b'-', b'a',
            b'd', b'd', b'r', 0x04, b'a', b'r', b'p', b'a', 0x00, 0x00, 0x0c, 0x00, 0x01,
        ];
        let mut dns_response_with_ptr_answer = ptr_query.clone();
        dns_response_with_ptr_answer[2] = 0x81;
        dns_response_with_ptr_answer[3] = 0x80;
        dns_response_with_ptr_answer[7] = 0x01;
        dns_response_with_ptr_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x0f, 0x07, b's',
            b'e', b'r', b'v', b'i', b'c', b'e', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_ptr_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_ptr_rdata = dns_response_with_ptr_answer.clone();
        let ptr_answer_rdlength_offset = ptr_query.len() + 10;
        dns_response_with_bad_ptr_rdata[ptr_answer_rdlength_offset] = 0x00;
        dns_response_with_bad_ptr_rdata[ptr_answer_rdlength_offset + 1] = 0x02;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_ptr_rdata).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut mx_query = dns_query.clone();
        mx_query[qtype_offset] = 0x00;
        mx_query[qtype_offset + 1] = 0x0f;
        let mut dns_response_with_mx_answer = mx_query.clone();
        dns_response_with_mx_answer[2] = 0x81;
        dns_response_with_mx_answer[3] = 0x80;
        dns_response_with_mx_answer[7] = 0x01;
        dns_response_with_mx_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0x00, 0x0a,
            0xc0, 0x0c,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_mx_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_mx_rdata = dns_response_with_mx_answer.clone();
        let mx_answer_rdlength_offset = mx_query.len() + 10;
        dns_response_with_bad_mx_rdata[mx_answer_rdlength_offset] = 0x00;
        dns_response_with_bad_mx_rdata[mx_answer_rdlength_offset + 1] = 0x03;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_mx_rdata).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut srv_query = dns_query.clone();
        srv_query[qtype_offset] = 0x00;
        srv_query[qtype_offset + 1] = 0x21;
        let mut dns_response_with_srv_answer = srv_query.clone();
        dns_response_with_srv_answer[2] = 0x81;
        dns_response_with_srv_answer[3] = 0x80;
        dns_response_with_srv_answer[7] = 0x01;
        dns_response_with_srv_answer.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x08, 0x00, 0x01,
            0x00, 0x05, 0x1f, 0x90, 0xc0, 0x0c,
        ]);
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_srv_answer).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut dns_response_with_bad_srv_rdata = dns_response_with_srv_answer.clone();
        let srv_answer_rdlength_offset = srv_query.len() + 10;
        dns_response_with_bad_srv_rdata[srv_answer_rdlength_offset] = 0x00;
        dns_response_with_bad_srv_rdata[srv_answer_rdlength_offset + 1] = 0x07;
        assert_eq!(
            observation_for_udp_payload(&dns_response_with_bad_srv_rdata).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mdns_response = vec![
            0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'p',
            b'r', b'i', b'n', b't', b'e', b'r', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00, 0x00,
            0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 192, 0, 2, 10,
        ];
        assert_eq!(
            observation_for_udp_payload(&mdns_response).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut mdns_two_answer_response = mdns_response.clone();
        mdns_two_answer_response[7] = 0x02;
        mdns_two_answer_response.extend_from_slice(&[
            0x06, b'b', b'a', b'c', b'k', b'u', b'p', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00,
            0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 192, 0, 2, 11,
        ]);
        assert_eq!(
            observation_for_udp_payload(&mdns_two_answer_response).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut mdns_two_answer_compressed_response = mdns_response.clone();
        mdns_two_answer_compressed_response[7] = 0x02;
        mdns_two_answer_compressed_response.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 192, 0, 2, 12,
        ]);
        assert_eq!(
            observation_for_udp_payload(&mdns_two_answer_compressed_response).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut mdns_missing_second_answer = mdns_response.clone();
        mdns_missing_second_answer[7] = 0x02;
        assert_eq!(
            observation_for_udp_payload(&mdns_missing_second_answer).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut mdns_tcp_payload = (mdns_response.len() as u16).to_be_bytes().to_vec();
        mdns_tcp_payload.extend_from_slice(&mdns_response);
        assert_eq!(
            observation_for_payload(&mdns_tcp_payload).application(),
            api::AgentPacketFlowApplication::Dns
        );
        let mut long_mdns_response = mdns_response.clone();
        long_mdns_response[27] = 0x00;
        long_mdns_response[28] = 0x10;
        long_mdns_response[35] = 0x00;
        long_mdns_response[36] = 150;
        long_mdns_response.truncate(37);
        long_mdns_response.extend(std::iter::repeat_n(0xa5, 150));
        let mut long_mdns_tcp_payload = (long_mdns_response.len() as u16).to_be_bytes().to_vec();
        long_mdns_tcp_payload.extend_from_slice(&long_mdns_response);
        assert_eq!(
            observation_for_payload(
                &long_mdns_tcp_payload[..api::PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES]
            )
            .application(),
            api::AgentPacketFlowApplication::Dns
        );
        assert_eq!(
            observation_for_payload(
                &long_mdns_tcp_payload[..api::PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES - 1]
            )
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut mdns_response_without_answers = mdns_response.clone();
        mdns_response_without_answers[6] = 0;
        mdns_response_without_answers[7] = 0;
        assert_eq!(
            observation_for_udp_payload(&mdns_response_without_answers).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut mdns_response_bad_type = mdns_response.clone();
        mdns_response_bad_type[27] = 0;
        mdns_response_bad_type[28] = 0;
        assert_eq!(
            observation_for_udp_payload(&mdns_response_bad_type).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut mdns_response_bad_cache_flush_class = mdns_response.clone();
        mdns_response_bad_cache_flush_class[29] = 0x80;
        mdns_response_bad_cache_flush_class[30] = 0x03;
        assert_eq!(
            observation_for_udp_payload(&mdns_response_bad_cache_flush_class).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mdns_response_self_pointer = vec![
            0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 192, 0, 2, 10,
        ];
        assert_eq!(
            observation_for_udp_payload(&mdns_response_self_pointer).application(),
            api::AgentPacketFlowApplication::Unknown
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
            observation_for_udp_payload(&stun_binding_request()).application(),
            api::AgentPacketFlowApplication::Stun
        );
        assert_eq!(
            observation_for_udp_payload(&turn_allocate_request()).application(),
            api::AgentPacketFlowApplication::Turn
        );
        assert_eq!(
            observation_for_udp_payload(&coap_get_request()).application(),
            api::AgentPacketFlowApplication::Coap
        );
        assert_eq!(
            observation_for_udp_payload(&coap_get_uri_path_request(b"status")).application(),
            api::AgentPacketFlowApplication::Coap
        );
        assert_eq!(
            observation_for_udp_payload(&coap_get_uri_path_request(b"temperature-c")).application(),
            api::AgentPacketFlowApplication::Coap
        );
        assert_eq!(
            observation_for_udp_payload(&[0x40, 0x02, 0x12, 0x34, 0xff, b'o', b'k']).application(),
            api::AgentPacketFlowApplication::Coap
        );
        assert_eq!(
            observation_for_udp_payload(&[0x60, 0x00, 0x12, 0x34]).application(),
            api::AgentPacketFlowApplication::Coap
        );
        assert_eq!(
            observation_for_udp_payload(&[0x70, 0x00, 0x12, 0x34]).application(),
            api::AgentPacketFlowApplication::Coap
        );
        assert_eq!(
            observation_for_udp_payload(&[0x80, 0x01, 0x12, 0x34]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&[0x60, 0x01, 0x12, 0x34]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&[0x70, 0x45, 0x12, 0x34]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&[0x40, 0x02, 0x12, 0x34, 0xff]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&[0x40, 0x01, 0x12, 0x34, 0xf0]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&[0x40, 0x01, 0x12, 0x34, 0x0f]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(&[0x40, 0x01, 0x12, 0x34, 0xb5, b'a']).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut malformed_stun = stun_binding_request();
        malformed_stun[4] = 0;
        assert_eq!(
            observation_for_udp_payload(&malformed_stun).application(),
            api::AgentPacketFlowApplication::Unknown
        );

        let ipars_relay = ipars_relay_datagram();
        assert_eq!(
            observation_for_udp_payload(&ipars_relay).application(),
            api::AgentPacketFlowApplication::IparsRelay
        );
        let relay_on_wireguard_port = api::AgentPacketFlowObservation {
            protocol: Some(TransportProtocol::Udp),
            source_port: Some(51820),
            payload_prefix: ipars_relay,
            ..Default::default()
        };
        assert_eq!(
            relay_on_wireguard_port.application(),
            api::AgentPacketFlowApplication::IparsRelay
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
        assert_eq!(
            observation_for_udp_payload(b"\0\x01pxelinux.0\0octet\0").application(),
            api::AgentPacketFlowApplication::Tftp
        );
        assert_eq!(
            observation_for_udp_payload(b"\0\x02startup.cfg\0netascii\0timeout\05\0").application(),
            api::AgentPacketFlowApplication::Tftp
        );
        assert_eq!(
            observation_for_udp_payload(b"\x00\x05\x00\x01file not found\x00").application(),
            api::AgentPacketFlowApplication::Tftp
        );
        assert_eq!(
            observation_for_udp_payload(b"\x00\x06blksize\x001024\x00timeout\x005\x00")
                .application(),
            api::AgentPacketFlowApplication::Tftp
        );
        assert_eq!(
            observation_for_udp_payload(b"\0\x01pxelinux.0\0binary\0").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(b"\x00\x03\x00\x01payload").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(b"\x00\x04\x00\x01").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(b"\x00\x05\x00\x09file not found\x00").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(b"\x00\x05\x00\x01\x00").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(b"\x00\x05\x00\x01file not found").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_udp_payload(b"\x00\x06unknown\x001\x00").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"\0\x01pxelinux.0\0octet\0").application(),
            api::AgentPacketFlowApplication::Unknown
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
            observation_for_payload(b"POST /v1/join HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::IparsControlPlane
        );
        assert_eq!(
            observation_for_payload(b"POST /v1/paths/negotiate HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::IparsSignal
        );
        assert_eq!(
            observation_for_payload(b"POST /v1/packet-flow HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::IparsAgent
        );
        assert_eq!(
            observation_for_payload(b"POST /v1/sessions HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::IparsRelay
        );
        assert_eq!(
            observation_for_payload(b"GET /metrics HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Prometheus
        );
        assert_eq!(
            observation_for_payload(b"GET /metrics/cadvisor HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Kubelet
        );
        assert_eq!(
            observation_for_payload(b"GET /stats/summary HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Kubelet
        );
        assert_eq!(
            observation_for_payload(b"GET /pods HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Kubelet
        );
        assert_eq!(
            observation_for_payload(b"GET /v1.43/containers/json HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::DockerApi
        );
        assert_eq!(
            observation_for_payload(b"POST /v1.43/exec/abc/start HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::DockerApi
        );
        assert_eq!(
            observation_for_payload(b"GET /_ping HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::DockerApi
        );
        assert_eq!(
            observation_for_payload(b"GET /v1alpha/containers/json HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Http
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
                b"POST /runtime.v1.RuntimeService/ListContainers HTTP/1.1\r\ncontent-type: application/grpc\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Cri
        );
        assert_eq!(
            observation_for_payload(
                b"POST /containerd.services.content.v1.Content/Info HTTP/1.1\r\ncontent-type: application/grpc\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Containerd
        );
        assert_eq!(
            observation_for_payload(
                b"POST /containerd.services.runtime.v2.Task/Get HTTP/1.1\r\ncontent-type: application/grpc\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Cri
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
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0/runtime.v1.ImageService/ListImages"
            )
            .application(),
            api::AgentPacketFlowApplication::Cri
        );
        assert_eq!(
            observation_for_payload(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0/containerd.services.images.v1.Images/List"
            )
            .application(),
            api::AgentPacketFlowApplication::Containerd
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
            observation_for_payload(b"GET /api/v1/namespaces/default/pods HTTP/1.1\r\n")
                .application(),
            api::AgentPacketFlowApplication::KubernetesApi
        );
        assert_eq!(
            observation_for_payload(b"GET /apis/apps/v1/deployments HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::KubernetesApi
        );
        assert_eq!(
            observation_for_payload(b"GET /openapi/v3/apis/apps/v1 HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::KubernetesApi
        );
        assert_eq!(
            observation_for_payload(b"GET /api/v1beta HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(b"GET /index/_search HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Elasticsearch
        );
        assert_eq!(
            observation_for_payload(b"GET /_plugins/_security/api/roles HTTP/1.1\r\n")
                .application(),
            api::AgentPacketFlowApplication::OpenSearch
        );
        assert_eq!(
            observation_for_payload(b"GET /_opendistro/_security/api/account HTTP/1.1\r\n")
                .application(),
            api::AgentPacketFlowApplication::OpenSearch
        );
        assert_eq!(
            observation_for_payload(b"GET /_pluginsfoo HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(b"GET /solr/admin/collections?action=LIST HTTP/1.1\r\n")
                .application(),
            api::AgentPacketFlowApplication::Solr
        );
        assert_eq!(
            observation_for_payload(b"GET /api/collections HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Solr
        );
        assert_eq!(
            observation_for_payload(b"GET /solrfoo/admin HTTP/1.1\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(
                b"GET /team/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Git
        );
        assert_eq!(
            observation_for_payload(b"POST /team/repo.git/git-receive-pack HTTP/1.1\r\n")
                .application(),
            api::AgentPacketFlowApplication::Git
        );
        assert_eq!(
            observation_for_payload(b"POST /team/repo.git/git-upload-archive HTTP/1.1\r\n")
                .application(),
            api::AgentPacketFlowApplication::Git
        );
        assert_eq!(
            observation_for_payload(
                b"GET /team/repo/info/refs?service=git-upload-pack HTTP/1.1\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(
                b"GET /team/repo.git/info/refs?service=git-upload-packish HTTP/1.1\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(&git_pkt_line(b"git-upload-pack", b"/team/repo.git"))
                .application(),
            api::AgentPacketFlowApplication::Git
        );
        assert_eq!(
            observation_for_payload(&git_pkt_line(b"git-receive-pack", b"/team/repo.git"))
                .application(),
            api::AgentPacketFlowApplication::Git
        );
        assert_eq!(
            observation_for_payload(b"zzzzgit-upload-pack /team/repo.git\0host=git.example")
                .application(),
            api::AgentPacketFlowApplication::Unknown
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
            observation_for_payload(
                b"GET /dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE HTTP/2\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Dns
        );
        assert_eq!(
            observation_for_payload(
                b"POST /dns-query HTTP/2\r\nContent-Type: application/dns-message\r\n\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Dns
        );
        assert_eq!(
            observation_for_payload(
                b"POST /dns-query?targethost=dnstarget.example&targetpath=/dns-query HTTP/2\r\nContent-Type: application/oblivious-dns-message\r\n\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Dns
        );
        assert_eq!(
            observation_for_payload(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message; charset=binary\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Dns
        );
        assert_eq!(
            observation_for_payload(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/oblivious-dns-message\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Dns
        );
        assert_eq!(
            observation_for_payload(b"GET /dns-query?name=example.com HTTP/2\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(
                b"POST /dns-query HTTP/2\r\nContent-Type: application/dns-messageish\r\n\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(
                b"POST /dns-query HTTP/2\r\nContent-Type: application/oblivious-dns-messageish\r\n\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(
                b"GET /dns-querying?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE HTTP/2\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(
                b"HTTP/1.1 200 OK\r\nX-Kubernetes-Pf-Flowschema-Uid: flow-a\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::KubernetesApi
        );
        assert_eq!(
            observation_for_payload(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.kubernetes.protobuf\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::KubernetesApi
        );
        assert_eq!(
            observation_for_payload(b"HTTP/1.1 200 OK\r\nDocker-Experimental: false\r\n")
                .application(),
            api::AgentPacketFlowApplication::DockerApi
        );
        assert_eq!(
            observation_for_payload(b"HTTP/1.1 200 OK\r\nX-Etcd-Index: 42\r\n").application(),
            api::AgentPacketFlowApplication::Etcd
        );
        assert_eq!(
            observation_for_payload(b"HTTP/1.1 200 OK\r\nX-Consul-Index: 42\r\n").application(),
            api::AgentPacketFlowApplication::Consul
        );
        assert_eq!(
            observation_for_payload(b"HTTP/1.1 200 OK\r\nX-Vault-Index: 42\r\n").application(),
            api::AgentPacketFlowApplication::Vault
        );
        assert_eq!(
            observation_for_payload(b"HTTP/1.1 200 OK\r\nX-Nomad-Index: 42\r\n").application(),
            api::AgentPacketFlowApplication::Nomad
        );
        assert_eq!(
            observation_for_payload(b"HTTP/1.1 200 OK\r\nX-Elastic-Product: Elasticsearch\r\n")
                .application(),
            api::AgentPacketFlowApplication::Elasticsearch
        );
        assert_eq!(
            observation_for_payload(b"HTTP/1.1 200 OK\r\nX-OpenSearch-Product: OpenSearch\r\n")
                .application(),
            api::AgentPacketFlowApplication::OpenSearch
        );
        assert_eq!(
            observation_for_payload(b"HTTP/1.1 200 OK\r\nX-OpenSearch-Version: 2.15.0\r\n")
                .application(),
            api::AgentPacketFlowApplication::OpenSearch
        );
        assert_eq!(
            observation_for_payload(b"HTTP/1.1 200 OK\r\nX-Solr-Version: 9.6.1\r\n").application(),
            api::AgentPacketFlowApplication::Solr
        );
        assert_eq!(
            observation_for_payload(b"HTTP/1.1 200 OK\r\nX-ClickHouse-Summary: {}\r\n")
                .application(),
            api::AgentPacketFlowApplication::ClickHouse
        );
        assert_eq!(
            observation_for_payload(b"HTTP/1.1 200 OK\r\nX-Influxdb-Version: 2.7\r\n")
                .application(),
            api::AgentPacketFlowApplication::InfluxDb
        );
        assert_eq!(
            observation_for_payload(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/openmetrics-text; version=1.0.0\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Prometheus
        );
        assert_eq!(
            observation_for_payload(b"HTTP/1.1 200 OK\r\nGrpc-Status: 0\r\n").application(),
            api::AgentPacketFlowApplication::Grpc
        );
        assert_eq!(
            observation_for_payload(b"GET / HTTP/1.1\r\nX-Consul-Index: 42\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(b"HTTP/1.1 200 OK\r\nX-Consulate-Index: 42\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(b"HTTP/9.9 200 OK\r\nX-Consul-Index: 42\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(b"HTTP/1.1 ABC OK\r\nX-Consul-Index: 42\r\n").application(),
            api::AgentPacketFlowApplication::Http
        );
        assert_eq!(
            observation_for_payload(&[0x16, 0x03, 0x03, 0x00, 0x31, 0x01, 0x00, 0x00])
                .application(),
            api::AgentPacketFlowApplication::Https
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni(
                "ipars-control-plane.public-a.example"
            ))
            .application(),
            api::AgentPacketFlowApplication::IparsControlPlane
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni("ipars-signal.public-a.example"))
                .application(),
            api::AgentPacketFlowApplication::IparsSignal
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni("ipars-agent.node-a.local"))
                .application(),
            api::AgentPacketFlowApplication::IparsAgent
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni("ipars-relay.public-a.example"))
                .application(),
            api::AgentPacketFlowApplication::IparsRelay
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_alpn(&[b"ipars-stun"])).application(),
            api::AgentPacketFlowApplication::Stun
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni("dns.google")).application(),
            api::AgentPacketFlowApplication::Dns
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni("doh.resolver.example"))
                .application(),
            api::AgentPacketFlowApplication::Dns
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_alpn(&[b"dot"])).application(),
            api::AgentPacketFlowApplication::Dns
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_alpn(&[b"doq"])).application(),
            api::AgentPacketFlowApplication::Dns
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni("turn-relay.public.example"))
                .application(),
            api::AgentPacketFlowApplication::Turn
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_alpn(&[b"stun.turn"])).application(),
            api::AgentPacketFlowApplication::Turn
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni("coaps.edge.example")).application(),
            api::AgentPacketFlowApplication::Coap
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_alpn(&[b"coap+tcp"])).application(),
            api::AgentPacketFlowApplication::Coap
        );
        let kubernetes_sni = tls_client_hello_with_sni("kubernetes.default.svc.cluster.local");
        assert!(kubernetes_sni.len() <= api::PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES);
        assert_eq!(
            observation_for_payload(&kubernetes_sni).application(),
            api::AgentPacketFlowApplication::KubernetesApi
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni("kubelet.worker-a.local"))
                .application(),
            api::AgentPacketFlowApplication::Kubelet
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni("docker-api.node-a.local"))
                .application(),
            api::AgentPacketFlowApplication::DockerApi
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni("crio.worker-a.local"))
                .application(),
            api::AgentPacketFlowApplication::Cri
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_sni("containerd.worker-a.local"))
                .application(),
            api::AgentPacketFlowApplication::Containerd
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
                "opensearch-data.search.svc",
                api::AgentPacketFlowApplication::OpenSearch,
            ),
            (
                "solr-cloud.search.svc",
                api::AgentPacketFlowApplication::Solr,
            ),
            ("gitlab-code.scm.svc", api::AgentPacketFlowApplication::Git),
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
                "openvpn-access.vpn.svc",
                api::AgentPacketFlowApplication::OpenVpn,
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
            ("vnc-console.ops.svc", api::AgentPacketFlowApplication::Vnc),
            (
                "ftp-files.storage.svc",
                api::AgentPacketFlowApplication::Ftp,
            ),
            (
                "rsync-files.storage.svc",
                api::AgentPacketFlowApplication::Rsync,
            ),
            ("smtp-relay.mail.svc", api::AgentPacketFlowApplication::Smtp),
            (
                "imap-mailbox.mail.svc",
                api::AgentPacketFlowApplication::Imap,
            ),
            (
                "pop3-mailbox.mail.svc",
                api::AgentPacketFlowApplication::Pop3,
            ),
            ("sip-proxy.voice.svc", api::AgentPacketFlowApplication::Sip),
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
                &[b"opensearch".as_slice()][..],
                api::AgentPacketFlowApplication::OpenSearch,
            ),
            (
                &[b"solr".as_slice()][..],
                api::AgentPacketFlowApplication::Solr,
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
                &[b"rfb".as_slice()][..],
                api::AgentPacketFlowApplication::Vnc,
            ),
            (
                &[b"ftps".as_slice()][..],
                api::AgentPacketFlowApplication::Ftp,
            ),
            (
                &[b"rsync".as_slice()][..],
                api::AgentPacketFlowApplication::Rsync,
            ),
            (
                &[b"git".as_slice()][..],
                api::AgentPacketFlowApplication::Git,
            ),
            (
                &[b"git-upload-pack".as_slice()][..],
                api::AgentPacketFlowApplication::Git,
            ),
            (
                &[b"submission".as_slice()][..],
                api::AgentPacketFlowApplication::Smtp,
            ),
            (
                &[b"imap4".as_slice()][..],
                api::AgentPacketFlowApplication::Imap,
            ),
            (
                &[b"pop3".as_slice()][..],
                api::AgentPacketFlowApplication::Pop3,
            ),
            (
                &[b"sips".as_slice()][..],
                api::AgentPacketFlowApplication::Sip,
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
            (
                &[b"openvpn".as_slice()][..],
                api::AgentPacketFlowApplication::OpenVpn,
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
        assert_eq!(
            observation_for_payload(&tls_server_hello_with_alpn(b"grpc")).application(),
            api::AgentPacketFlowApplication::Grpc
        );
        assert_eq!(
            observation_for_payload(&tls_server_hello_with_alpn(b"doq")).application(),
            api::AgentPacketFlowApplication::Dns
        );
        assert_eq!(
            observation_for_payload(&tls_server_hello_with_alpn(b"x-amzn-mqtt-ca")).application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&tls_server_hello_with_alpn(b"h2")).application(),
            api::AgentPacketFlowApplication::Https
        );
        assert_eq!(
            observation_for_payload(&tls_client_hello_with_alpn(&[b"h3"])).application(),
            api::AgentPacketFlowApplication::Https
        );
        assert_eq!(
            observation_for_payload(&tls_server_hello_with_alpn_protocols(&[
                b"grpc".as_slice(),
                b"mqtt".as_slice(),
            ]))
            .application(),
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
        let openvpn_reset = openvpn_hard_reset_client_v2();
        assert_eq!(
            observation_for_udp_payload(&openvpn_reset).application(),
            api::AgentPacketFlowApplication::OpenVpn
        );
        assert_eq!(
            observation_for_payload(&openvpn_tcp_record(&openvpn_reset)).application(),
            api::AgentPacketFlowApplication::OpenVpn
        );
        assert_eq!(
            observation_for_udp_payload(&openvpn_plain_control(5, &[0], None)).application(),
            api::AgentPacketFlowApplication::OpenVpn
        );
        assert_eq!(
            observation_for_udp_payload(&openvpn_plain_control(4, &[0], Some(1))).application(),
            api::AgentPacketFlowApplication::OpenVpn
        );
        let mut openvpn_zero_session = openvpn_reset.clone();
        openvpn_zero_session[1..9].fill(0);
        assert_eq!(
            observation_for_udp_payload(&openvpn_zero_session).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut openvpn_data_packet = openvpn_reset.clone();
        openvpn_data_packet[0] = 6 << 3;
        assert_eq!(
            observation_for_udp_payload(&openvpn_data_packet).application(),
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
            observation_for_payload(b"RFB 003.008\n").application(),
            api::AgentPacketFlowApplication::Vnc
        );
        assert_eq!(
            observation_for_payload(b"RFB 003.003\n").application(),
            api::AgentPacketFlowApplication::Vnc
        );
        assert_eq!(
            observation_for_payload(b"RFB 002.008\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"RFB 003.009\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"220 FTP server ready\r\n").application(),
            api::AgentPacketFlowApplication::Ftp
        );
        assert_eq!(
            observation_for_payload(b"227 Entering Passive Mode (192,0,2,10,195,80)\r\n")
                .application(),
            api::AgentPacketFlowApplication::Ftp
        );
        assert_eq!(
            observation_for_payload(b"229 Entering Extended Passive Mode (|||6446|)\r\n")
                .application(),
            api::AgentPacketFlowApplication::Ftp
        );
        assert_eq!(
            observation_for_payload(b"150 Opening BINARY mode data connection for backup.tar\r\n")
                .application(),
            api::AgentPacketFlowApplication::Ftp
        );
        assert_eq!(
            observation_for_payload(b"226 Transfer complete\r\n").application(),
            api::AgentPacketFlowApplication::Ftp
        );
        assert_eq!(
            observation_for_payload(b"331 Please specify the password.\r\n").application(),
            api::AgentPacketFlowApplication::Ftp
        );
        assert_eq!(
            observation_for_payload(b"530 Not logged in.\r\n").application(),
            api::AgentPacketFlowApplication::Ftp
        );
        assert_eq!(
            observation_for_payload(b"202 Command not implemented, superfluous at this site.\r\n")
                .application(),
            api::AgentPacketFlowApplication::Ftp
        );
        assert_eq!(
            observation_for_payload(b"250 Directory successfully changed.\r\n").application(),
            api::AgentPacketFlowApplication::Ftp
        );
        assert_eq!(
            observation_for_payload(b"257 \"/var/ftp\" is current directory\r\n").application(),
            api::AgentPacketFlowApplication::Ftp
        );
        assert_eq!(
            observation_for_payload(b"PASV\r\n").application(),
            api::AgentPacketFlowApplication::Ftp
        );
        assert_eq!(
            observation_for_payload(b"STOR backup.tar\r\n").application(),
            api::AgentPacketFlowApplication::Ftp
        );
        assert_eq!(
            observation_for_payload(b"220 service ready\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"227 Passive Mode\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"229 Entering Extended Passive Mode (|1|127.0.0.1|6446|)\r\n")
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"@RSYNCD: 31.0\n").application(),
            api::AgentPacketFlowApplication::Rsync
        );
        assert_eq!(
            observation_for_payload(b"@RSYNCD: 31.0 sha512 sha256 md5\n").application(),
            api::AgentPacketFlowApplication::Rsync
        );
        assert_eq!(
            observation_for_payload(b"@RSYNCD: OK\n").application(),
            api::AgentPacketFlowApplication::Rsync
        );
        assert_eq!(
            observation_for_payload(b"@RSYNCD: AUTHREQD QWxhZGRpbjpvcGVuIHNlc2FtZQ==\n")
                .application(),
            api::AgentPacketFlowApplication::Rsync
        );
        assert_eq!(
            observation_for_payload(b"@RSYNCD: EXIT\n").application(),
            api::AgentPacketFlowApplication::Rsync
        );
        assert_eq!(
            observation_for_payload(b"@ERROR: access denied to module\n").application(),
            api::AgentPacketFlowApplication::Rsync
        );
        assert_eq!(
            observation_for_payload(b"@RSYNCD: beta\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"@RSYNCD: AUTHREQD not base64!\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"@RSYNCD: READY\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"@ERROR:\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"@RSYNC: 31.0\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"220 mx.example ESMTP ready\r\n").application(),
            api::AgentPacketFlowApplication::Smtp
        );
        assert_eq!(
            observation_for_payload(b"220-mx.example SMTP service ready\r\n").application(),
            api::AgentPacketFlowApplication::Smtp
        );
        assert_eq!(
            observation_for_payload(b"250-PIPELINING\r\n").application(),
            api::AgentPacketFlowApplication::Smtp
        );
        assert_eq!(
            observation_for_payload(b"250 2.1.0 Originator <agent@example.test> ok\r\n")
                .application(),
            api::AgentPacketFlowApplication::Smtp
        );
        assert_eq!(
            observation_for_payload(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                .application(),
            api::AgentPacketFlowApplication::Smtp
        );
        assert_eq!(
            observation_for_payload(b"550 5.1.1 Mailbox does not exist\r\n").application(),
            api::AgentPacketFlowApplication::Smtp
        );
        assert_eq!(
            observation_for_payload(b"EHLO edge-node.example\r\n").application(),
            api::AgentPacketFlowApplication::Smtp
        );
        assert_eq!(
            observation_for_payload(b"MAIL FROM:<agent@example.test>\r\n").application(),
            api::AgentPacketFlowApplication::Smtp
        );
        assert_eq!(
            observation_for_payload(b"220 service ready\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"250 OK\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"250 Directory successfully changed.\r\n").application(),
            api::AgentPacketFlowApplication::Ftp
        );
        assert_eq!(
            observation_for_payload(b"500 Internal Server Error\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"550 No such user here\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"* OK [CAPABILITY IMAP4rev1 UIDPLUS] ready\r\n").application(),
            api::AgentPacketFlowApplication::Imap
        );
        assert_eq!(
            observation_for_payload(b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN IDLE\r\n")
                .application(),
            api::AgentPacketFlowApplication::Imap
        );
        assert_eq!(
            observation_for_payload(b"A001 OK [READ-WRITE] SELECT completed\r\n").application(),
            api::AgentPacketFlowApplication::Imap
        );
        assert_eq!(
            observation_for_payload(b"A002 NO [AUTHENTICATIONFAILED] Authentication failed\r\n")
                .application(),
            api::AgentPacketFlowApplication::Imap
        );
        assert_eq!(
            observation_for_payload(b"A003 OK LOGIN completed\r\n").application(),
            api::AgentPacketFlowApplication::Imap
        );
        assert_eq!(
            observation_for_payload(b"A001 UID FETCH 42 BODY[]\r\n").application(),
            api::AgentPacketFlowApplication::Imap
        );
        assert_eq!(
            observation_for_payload(b"* OK ready\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"* CAPABILITY STARTTLS AUTH=PLAIN IDLE\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"A001 OK completed\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"A001 OK [UNKNOWN] completed\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"* FLAGS (\\Seen \\Answered)\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"+OK POP3 server ready\r\n").application(),
            api::AgentPacketFlowApplication::Pop3
        );
        assert_eq!(
            observation_for_payload(b"+OK 2 320\r\n").application(),
            api::AgentPacketFlowApplication::Pop3
        );
        assert_eq!(
            observation_for_payload(b"+OK Capability list follows\r\n").application(),
            api::AgentPacketFlowApplication::Pop3
        );
        assert_eq!(
            observation_for_payload(b"+OK 120 octets\r\n").application(),
            api::AgentPacketFlowApplication::Pop3
        );
        assert_eq!(
            observation_for_payload(b"-ERR no such message, only 2 messages in maildrop\r\n")
                .application(),
            api::AgentPacketFlowApplication::Pop3
        );
        assert_eq!(
            observation_for_payload(b"-ERR [IN-USE] maildrop locked\r\n").application(),
            api::AgentPacketFlowApplication::Pop3
        );
        assert_eq!(
            observation_for_payload(b"USER agent\r\n").application(),
            api::AgentPacketFlowApplication::Pop3
        );
        assert_eq!(
            observation_for_payload(b"+OK success\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"+OK 2\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"-ERR failed\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"INVITE sip:alice@example.com SIP/2.0\r\n").application(),
            api::AgentPacketFlowApplication::Sip
        );
        assert_eq!(
            observation_for_payload(b"SIP/2.0 200 OK\r\n").application(),
            api::AgentPacketFlowApplication::Sip
        );
        assert_eq!(
            observation_for_udp_payload(b"REGISTER sips:edge@example.com SIP/2.0\r\n")
                .application(),
            api::AgentPacketFlowApplication::Sip
        );
        assert_eq!(
            observation_for_payload(b"INVITE mailto:alice@example.com SIP/2.0\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"INVITE sip:alice@example.com HTTP/1.1\r\n").application(),
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
            observation_for_payload(&[0, 0, 0, 8, 4, 210, 22, 48]).application(),
            api::AgentPacketFlowApplication::Postgres
        );
        assert_eq!(
            observation_for_payload(&[0, 0, 0, 16, 4, 210, 22, 46, 0, 0, 0, 42, 0, 0, 0, 7,])
                .application(),
            api::AgentPacketFlowApplication::Postgres
        );
        let postgres_startup = postgres_startup_message(&[
            (b"user".as_slice(), b"app_user".as_slice()),
            (b"database".as_slice(), b"app_db".as_slice()),
            (b"application_name".as_slice(), b"ipars-agent".as_slice()),
        ]);
        assert_eq!(
            observation_for_payload(&postgres_startup).application(),
            api::AgentPacketFlowApplication::Postgres
        );
        let long_postgres_options = vec![b'a'; 256];
        let truncated_postgres_startup = postgres_startup_message(&[
            (b"user".as_slice(), b"app_user".as_slice()),
            (b"options".as_slice(), long_postgres_options.as_slice()),
        ]);
        assert_eq!(
            observation_for_payload(
                &truncated_postgres_startup[..api::PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES]
            )
            .application(),
            api::AgentPacketFlowApplication::Postgres
        );
        let missing_postgres_user =
            postgres_startup_message(&[(b"database".as_slice(), b"app_db".as_slice())]);
        assert_eq!(
            observation_for_payload(&missing_postgres_user).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let invalid_postgres_key =
            postgres_startup_message(&[(b"user\n".as_slice(), b"app_user".as_slice())]);
        assert_eq!(
            observation_for_payload(&invalid_postgres_key).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut postgres_startup_with_trailing = postgres_startup.clone();
        postgres_startup_with_trailing.extend_from_slice(b"junk");
        assert_eq!(
            observation_for_payload(&postgres_startup_with_trailing).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut postgres_startup_response = postgres_backend_message(b'R', &0_u32.to_be_bytes());
        postgres_startup_response
            .extend_from_slice(&postgres_parameter_status(b"server_version", b"16.3"));
        postgres_startup_response
            .extend_from_slice(&postgres_parameter_status(b"client_encoding", b"UTF8"));
        postgres_startup_response.extend_from_slice(&postgres_backend_key_data(
            12_345,
            &[0x10, 0x20, 0x30, 0x40],
        ));
        postgres_startup_response.extend_from_slice(&postgres_ready_for_query(b'I'));
        assert_eq!(
            observation_for_payload(&postgres_startup_response).application(),
            api::AgentPacketFlowApplication::Postgres
        );
        let mut postgres_query_response = postgres_command_complete(b"SELECT 1");
        postgres_query_response.extend_from_slice(&postgres_ready_for_query(b'I'));
        assert_eq!(
            observation_for_payload(&postgres_query_response).application(),
            api::AgentPacketFlowApplication::Postgres
        );
        let postgres_error = postgres_error_response(&[
            (b'S', b"ERROR".as_slice()),
            (b'C', b"42P01".as_slice()),
            (b'M', b"relation does not exist".as_slice()),
        ]);
        assert_eq!(
            observation_for_payload(&postgres_error).application(),
            api::AgentPacketFlowApplication::Postgres
        );
        assert_eq!(
            observation_for_payload(&postgres_error_response(&[(b'S', b"ERROR".as_slice())]))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[0, 0, 0, 16, 4, 210, 22, 46]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&postgres_frontend_message(b'Q', b"SELECT 1\0")).application(),
            api::AgentPacketFlowApplication::Postgres
        );
        assert_eq!(
            observation_for_payload(&postgres_frontend_message(
                b'Q',
                b"/* ipars */\nWITH probe AS (SELECT 1) SELECT * FROM probe\0",
            ))
            .application(),
            api::AgentPacketFlowApplication::Postgres
        );
        let mut postgres_query_then_sync = postgres_frontend_message(b'Q', b"SELECT 1\0");
        postgres_query_then_sync.extend_from_slice(&postgres_frontend_message(b'S', b""));
        assert_eq!(
            observation_for_payload(&postgres_query_then_sync).application(),
            api::AgentPacketFlowApplication::Postgres
        );
        let mut postgres_query_with_trailing_junk = postgres_frontend_message(b'Q', b"SELECT 1\0");
        postgres_query_with_trailing_junk.extend_from_slice(b"junk");
        assert_eq!(
            observation_for_payload(&postgres_query_with_trailing_junk).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&postgres_frontend_message(b'Q', b"hello postgres\0"))
                .application(),
            api::AgentPacketFlowApplication::Unknown
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
        let mut invalid_parse_body = Vec::new();
        invalid_parse_body.push(0);
        invalid_parse_body.extend_from_slice(b"hello postgres\0");
        invalid_parse_body.extend_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            observation_for_payload(&postgres_frontend_message(b'P', &invalid_parse_body))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let bind_body =
            postgres_bind_message_body(b"", b"prepared", &[0], &[Some(b"42"), None], &[0]);
        assert_eq!(
            observation_for_payload(&postgres_frontend_message(b'B', &bind_body)).application(),
            api::AgentPacketFlowApplication::Postgres
        );
        assert_eq!(
            observation_for_payload(&postgres_frontend_message(b'B', b"\0prepared\0\0\x01"))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let bind_bad_format_count =
            postgres_bind_message_body(b"", b"prepared", &[0, 1], &[Some(b"42")], &[0]);
        assert_eq!(
            observation_for_payload(&postgres_frontend_message(b'B', &bind_bad_format_count))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let bind_bad_format_code =
            postgres_bind_message_body(b"", b"prepared", &[2], &[Some(b"42")], &[0]);
        assert_eq!(
            observation_for_payload(&postgres_frontend_message(b'B', &bind_bad_format_code))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut bind_trailing = bind_body.clone();
        bind_trailing.push(0);
        assert_eq!(
            observation_for_payload(&postgres_frontend_message(b'B', &bind_trailing)).application(),
            api::AgentPacketFlowApplication::Unknown
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
        let mysql_client_flags = MYSQL_CLIENT_PROTOCOL_41
            | MYSQL_CLIENT_SECURE_CONNECTION
            | MYSQL_CLIENT_PLUGIN_AUTH
            | MYSQL_CLIENT_CONNECT_WITH_DB;
        assert_eq!(
            observation_for_payload(&mysql_client_handshake_response_packet(
                1,
                mysql_client_flags,
                b"app_user",
                b"01234567890123456789",
                Some(b"app_db"),
                Some(b"caching_sha2_password"),
                None,
            ))
            .application(),
            api::AgentPacketFlowApplication::Mysql
        );
        let mysql_lenenc_client_flags =
            mysql_client_flags | MYSQL_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;
        assert_eq!(
            observation_for_payload(&mysql_client_handshake_response_packet(
                1,
                mysql_lenenc_client_flags,
                b"app_user",
                b"01234567890123456789012345678901",
                Some(b"app_db"),
                Some(b"mysql_native_password"),
                None,
            ))
            .application(),
            api::AgentPacketFlowApplication::Mysql
        );
        let mysql_attrs_client_flags = mysql_lenenc_client_flags | MYSQL_CLIENT_CONNECT_ATTRS;
        assert_eq!(
            observation_for_payload(&mysql_client_handshake_response_packet(
                1,
                mysql_attrs_client_flags,
                b"app_user",
                b"01234567890123456789012345678901",
                Some(b"app_db"),
                Some(b"mysql_native_password"),
                Some(&[
                    (b"_client_name".as_slice(), b"ipars-agent".as_slice()),
                    (b"program_name".as_slice(), b"packet-flow-smoke".as_slice()),
                ]),
            ))
            .application(),
            api::AgentPacketFlowApplication::Mysql
        );
        assert_eq!(
            observation_for_payload(&mysql_ssl_request_packet()).application(),
            api::AgentPacketFlowApplication::Mysql
        );
        assert_eq!(
            observation_for_payload(&mysql_ok_packet(2, 1, 0, 0x0002, 0, b"Rows matched: 1"))
                .application(),
            api::AgentPacketFlowApplication::Mysql
        );
        assert_eq!(
            observation_for_payload(&mysql_err_packet(
                1,
                1_145,
                b"42S02",
                b"Table 'app.missing' doesn't exist",
            ))
            .application(),
            api::AgentPacketFlowApplication::Mysql
        );
        assert_eq!(
            observation_for_payload(&mysql_eof_packet(3, 0, 0x0002)).application(),
            api::AgentPacketFlowApplication::Mysql
        );
        assert_eq!(
            observation_for_payload(&mysql_auth_switch_request_packet(
                2,
                b"caching_sha2_password",
                b"01234567890123456789",
            ))
            .application(),
            api::AgentPacketFlowApplication::Mysql
        );
        let mut invalid_mysql_client_filler = mysql_client_handshake_response_packet(
            1,
            mysql_client_flags,
            b"app_user",
            b"01234567890123456789",
            Some(b"app_db"),
            Some(b"caching_sha2_password"),
            None,
        );
        invalid_mysql_client_filler[4 + 9] = 1;
        assert_eq!(
            observation_for_payload(&invalid_mysql_client_filler).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mysql_ok_packet(2, 0, 0, 0x8000, 0, b"")).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut invalid_mysql_error = mysql_err_packet(1, 1_145, b"42S02", b"missing");
        invalid_mysql_error[4 + 3] = b'!';
        assert_eq!(
            observation_for_payload(&invalid_mysql_error).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mysql_eof_packet(0, 0, 0x0002)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mysql_auth_switch_request_packet(
                2,
                b"unknown_auth_plugin",
                b"01234567890123456789",
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut unflagged_mysql_client_trailing = mysql_client_handshake_response_packet(
            1,
            mysql_client_flags,
            b"app_user",
            b"01234567890123456789",
            Some(b"app_db"),
            Some(b"caching_sha2_password"),
            None,
        );
        unflagged_mysql_client_trailing[0] += 1;
        unflagged_mysql_client_trailing.push(0xa5);
        assert_eq!(
            observation_for_payload(&unflagged_mysql_client_trailing).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mysql_client_handshake_response_packet(
                1,
                mysql_attrs_client_flags,
                b"app_user",
                b"01234567890123456789012345678901",
                Some(b"app_db"),
                Some(b"mysql_native_password"),
                Some(&[(b"_client\n".as_slice(), b"ipars-agent".as_slice())]),
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let missing_protocol_41_flags = mysql_client_flags & !MYSQL_CLIENT_PROTOCOL_41;
        assert_eq!(
            observation_for_payload(&mysql_client_handshake_response_packet(
                1,
                missing_protocol_41_flags,
                b"app_user",
                b"01234567890123456789",
                Some(b"app_db"),
                Some(b"caching_sha2_password"),
                None,
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
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
        let mssql_done = mssql_tds_packet(0x04, &mssql_done_token(0x0010, 0, 1));
        assert_eq!(
            observation_for_payload(&mssql_done).application(),
            api::AgentPacketFlowApplication::MsSql
        );
        let mssql_error_done = mssql_tds_packet(
            0x04,
            &[
                mssql_error_token(
                    208,
                    1,
                    16,
                    b"Invalid object name 'missing'.",
                    b"sql-a",
                    b"",
                    1,
                ),
                mssql_done_token(0x0002, 0, 0),
            ]
            .concat(),
        );
        assert_eq!(
            observation_for_payload(&mssql_error_done).application(),
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
        let invalid_mssql_done = mssql_tds_packet(0x04, &mssql_done_token(0x8000, 0, 0));
        assert_eq!(
            observation_for_payload(&invalid_mssql_done).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let invalid_mssql_error = mssql_tds_packet(
            0x04,
            &mssql_error_token(
                0,
                1,
                16,
                b"Invalid object name 'missing'.",
                b"sql-a",
                b"",
                1,
            ),
        );
        assert_eq!(
            observation_for_payload(&invalid_mssql_error).application(),
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
        let clickhouse_hello =
            clickhouse_client_hello(b"Go Client", 54_451, b"default", b"default", b"secret", &[]);
        assert_eq!(
            observation_for_payload(&clickhouse_hello).application(),
            api::AgentPacketFlowApplication::ClickHouse
        );
        let clickhouse_hello_with_quota = clickhouse_client_hello(
            b"ClickHouse Rust client",
            54_452,
            b"analytics",
            b"reader",
            b"",
            &[b"quota-key".as_slice()],
        );
        assert_eq!(
            observation_for_payload(&clickhouse_hello_with_quota).application(),
            api::AgentPacketFlowApplication::ClickHouse
        );
        let clickhouse_server =
            clickhouse_server_hello(b"Clickhouse", 54_452, b"Europe/Moscow", b"Clickhouse", 3);
        assert_eq!(
            observation_for_payload(&clickhouse_server).application(),
            api::AgentPacketFlowApplication::ClickHouse
        );
        let clickhouse_exception = clickhouse_server_exception(
            60,
            b"DB::Exception",
            b"DB::Exception: Table X doesn't exist",
            b"frame one\nframe two",
        );
        assert_eq!(
            observation_for_payload(&clickhouse_exception).application(),
            api::AgentPacketFlowApplication::ClickHouse
        );
        let clickhouse_progress = clickhouse_server_progress(65_535, 871_799, 0, 0, 0);
        assert_eq!(
            observation_for_payload(&clickhouse_progress).application(),
            api::AgentPacketFlowApplication::ClickHouse
        );
        let clickhouse_pong = clickhouse_empty_server_packet(4);
        assert_eq!(
            observation_for_clickhouse_native_payload(&clickhouse_pong).application(),
            api::AgentPacketFlowApplication::ClickHouse
        );
        assert_eq!(
            observation_for_payload(&clickhouse_pong).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let clickhouse_end_of_stream = clickhouse_empty_server_packet(5);
        assert_eq!(
            observation_for_clickhouse_native_payload(&clickhouse_end_of_stream).application(),
            api::AgentPacketFlowApplication::ClickHouse
        );
        assert_eq!(
            observation_for_payload(&clickhouse_end_of_stream).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let clickhouse_query = clickhouse_query_packet(
            b"SELECT count() FROM system.tables",
            &[(b"send_logs_level".as_slice(), b"trace".as_slice(), true)],
        );
        assert_eq!(
            observation_for_payload(&clickhouse_query).application(),
            api::AgentPacketFlowApplication::ClickHouse
        );
        let long_clickhouse_query = clickhouse_query_packet(
            b"SELECT event_time, trace_id, service_name FROM observability.events WHERE service_name = 'ipars-agent' ORDER BY event_time DESC LIMIT 1000",
            &[],
        );
        assert!(long_clickhouse_query.len() > api::PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES);
        assert_eq!(
            observation_for_payload(
                &long_clickhouse_query[..api::PACKET_FLOW_PAYLOAD_PREFIX_MAX_BYTES]
            )
            .application(),
            api::AgentPacketFlowApplication::ClickHouse
        );
        let clickhouse_old_revision =
            clickhouse_client_hello(b"Go Client", 100, b"default", b"default", b"", &[]);
        assert_eq!(
            observation_for_payload(&clickhouse_old_revision).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let clickhouse_control_client =
            clickhouse_client_hello(b"Go\nClient", 54_451, b"default", b"default", b"", &[]);
        assert_eq!(
            observation_for_payload(&clickhouse_control_client).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let clickhouse_plain_error = clickhouse_server_exception(
            60,
            b"DB::Error",
            b"DB::Exception: Table X doesn't exist",
            b"",
        );
        assert_eq!(
            observation_for_payload(&clickhouse_plain_error).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let clickhouse_idle_progress = clickhouse_server_progress(0, 0, 0, 0, 0);
        assert_eq!(
            observation_for_payload(&clickhouse_idle_progress).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut clickhouse_with_trailing_junk = clickhouse_hello.clone();
        clickhouse_with_trailing_junk.extend_from_slice(b"junk");
        assert_eq!(
            observation_for_payload(&clickhouse_with_trailing_junk).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let clickhouse_non_sql_query = clickhouse_query_packet(b"hello clickhouse", &[]);
        assert_eq!(
            observation_for_payload(&clickhouse_non_sql_query).application(),
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
            observation_for_payload(b"+OK\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"+PONG\r\n:1\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(
                b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n"
            )
            .application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b":-1\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"$5\r\nvalue\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"$-1\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"*-1\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"_\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"#t\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b",1.25\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b",-inf\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"(3492890328409238509324850943850943825024385\r\n")
                .application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"!3\r\nERR\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"=15\r\ntxt:Some string\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"%1\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"~2\r\n:1\r\n:2\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b">2\r\n$7\r\nmessage\r\n$5\r\nhello\r\n").application(),
            api::AgentPacketFlowApplication::Redis
        );
        assert_eq!(
            observation_for_payload(b"|1\r\n$3\r\nttl\r\n:60\r\n$5\r\nvalue\r\n").application(),
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
            observation_for_payload(b"+HELLO\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"-wat no\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"$-2\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"$3\r\nfoo").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"*2\r\n$5\r\nvalue\r\njunk").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"%1\r\n$4\r\nmode\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"#x\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b",hello\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b",1e\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"(12x\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"|0\r\n$5\r\nvalue\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"|1\r\n$3\r\nttl\r\n:60\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"!3\r\nwat\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"=3\r\nbad\r\n").application(),
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
            observation_for_payload(b"STORED\r\n").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"NOT_FOUND\r\n").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"VALUE cache-key 0 5\r\nvalue\r\nEND\r\n").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"VALUE cache-key 0 5 12345\r\nvalue\r\nEND\r\n").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"STAT pid 123\r\nSTAT uptime 456\r\nEND\r\n").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"VERSION 1.6.22\r\n").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"CLIENT_ERROR bad command line format\r\n").application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(b"12345\r\n").application(),
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
            observation_for_payload(b"STORED extra\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"VALUE cache-key 0 5\r\nvalueX\r\nEND\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"STAT pid\r\n").application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"CLIENT_ERROR\r\n").application(),
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
            observation_for_payload(&memcached_binary_response(
                0x00,
                0,
                b"",
                &[0, 0, 0, 1],
                b"value"
            ))
            .application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(&memcached_binary_response(
                0x0c,
                0,
                b"key",
                &[0, 0, 0, 1],
                b"value"
            ))
            .application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(&memcached_binary_response(
                0x05,
                0,
                b"",
                b"",
                &42_u64.to_be_bytes()
            ))
            .application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(&memcached_binary_response(0x0b, 0, b"", b"", b"1.6.22"))
                .application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(&memcached_binary_response(0x00, 1, b"", b"", b"not found"))
                .application(),
            api::AgentPacketFlowApplication::Memcached
        );
        let mut partial_memcached_response =
            memcached_binary_response(0x00, 0, b"", &[0, 0, 0, 1], b"value");
        partial_memcached_response.truncate(24 + 4 + 2);
        assert_eq!(
            observation_for_payload(&partial_memcached_response).application(),
            api::AgentPacketFlowApplication::Memcached
        );
        assert_eq!(
            observation_for_payload(&memcached_binary_response(0x00, 0x9999, b"", b"", b"bad"))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&memcached_binary_response(0x00, 0, b"", b"", b"value"))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&memcached_binary_response(
                0x0c,
                0,
                b"",
                &[0, 0, 0, 1],
                b"value"
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&memcached_binary_response(0x00, 1, b"", &[0, 0, 0, 1], b""))
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
            observation_for_payload(&kafka_request(18, 2, None, b"body")).application(),
            api::AgentPacketFlowApplication::Kafka
        );
        assert_eq!(
            observation_for_payload(&kafka_request(18, 3, None, b"body")).application(),
            api::AgentPacketFlowApplication::Unknown
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
        let mut kafka_pipelined = kafka_flexible_request(18, 3, None, b"");
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
        let mut kafka_with_trailing_junk = kafka_flexible_request(18, 3, None, b"");
        kafka_with_trailing_junk.extend_from_slice(b"junk");
        assert_eq!(
            observation_for_payload(&kafka_with_trailing_junk).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&kafka_request(18, 2, Some(b"bad\0client"), b"")).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                0, 0, 0, 21, 0, 18, 0, 3, 0, 0, 0, 1, 0, 11, b'r', b'u', b's', b't', b'-', b'c',
                b'l', b'i', b'e', b'n', b't',
            ])
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[
                0, 0, 0, 21, 0, 18, 0, 3, 0, 0, 0, 1, 12, b'r', b'u', b's', b't', b'-', b'c', b'l',
                b'i', b'e', b'n', b't', 0,
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
            observation_for_payload(&mqtt_connack_packet(0x00, 0x00, None)).application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&mqtt_connack_packet(0x00, 0x01, None)).application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&mqtt_connack_packet(0x01, 0x00, Some(&[]))).application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&mqtt_connack_packet(0x00, 0x84, Some(&[]))).application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&mqtt_connack_packet(0x00, 0x00, Some(&[0x21, 0x00, 0x0a])))
                .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        let mut mqtt_connack_reason = vec![0x1f];
        mqtt_connack_reason.extend_from_slice(&mqtt_field(b"accepted"));
        assert_eq!(
            observation_for_payload(&mqtt_connack_packet(0x00, 0x00, Some(&mqtt_connack_reason)))
                .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&mqtt_publish_packet(0x00, b"sensors/temp", None, b"22.4"))
                .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&mqtt_publish_packet(
                0x02,
                b"devices/edge-1/state",
                Some(7),
                b"online"
            ))
            .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&mqtt_subscribe_packet(
                12,
                &[
                    (b"sensors/+/temp".as_slice(), 1),
                    (b"$SYS/broker/#".as_slice(), 0)
                ]
            ))
            .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        let mut mqtt_v5_subscribe_properties = vec![0x0b, 0x2a, 0x26];
        mqtt_v5_subscribe_properties.extend_from_slice(&mqtt_field(b"source"));
        mqtt_v5_subscribe_properties.extend_from_slice(&mqtt_field(b"agent"));
        assert_eq!(
            observation_for_payload(&mqtt_subscribe_v5_packet(
                14,
                &[],
                &[(b"sensors/+/humidity".as_slice(), 2)]
            ))
            .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&mqtt_subscribe_v5_packet(
                15,
                &mqtt_v5_subscribe_properties,
                &[(b"$share/workers/sensors/#".as_slice(), 0)]
            ))
            .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&mqtt_unsubscribe_packet(
                13,
                &[b"sensors/+/temp".as_slice(), b"$SYS/broker/#".as_slice()]
            ))
            .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        let mut mqtt_v5_unsubscribe_properties = vec![0x26];
        mqtt_v5_unsubscribe_properties.extend_from_slice(&mqtt_field(b"source"));
        mqtt_v5_unsubscribe_properties.extend_from_slice(&mqtt_field(b"agent"));
        assert_eq!(
            observation_for_payload(&mqtt_unsubscribe_v5_packet(
                16,
                &[],
                &[b"sensors/+/humidity".as_slice()]
            ))
            .application(),
            api::AgentPacketFlowApplication::Mqtt
        );
        assert_eq!(
            observation_for_payload(&mqtt_unsubscribe_v5_packet(
                17,
                &mqtt_v5_unsubscribe_properties,
                &[b"$share/workers/sensors/#".as_slice()]
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
            observation_for_payload(&[0x21, 0x02, 0x00, 0x00]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_publish_packet(0x00, b"plain", None, b"value"))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_publish_packet(0x00, b"sensors/+", None, b"value"))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_publish_packet(
                0x06,
                b"sensors/temp",
                Some(7),
                b"value"
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_publish_packet(
                0x02,
                b"sensors/temp",
                Some(0),
                b"value"
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_subscribe_packet(
                0,
                &[(b"sensors/+/temp".as_slice(), 1)]
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_subscribe_packet(
                12,
                &[(b"sensors/temp#".as_slice(), 1)]
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_subscribe_packet(
                12,
                &[(b"sensors/temp".as_slice(), 3)]
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_subscribe_v5_packet(
                12,
                &[0x01],
                &[(b"sensors/+/temp".as_slice(), 1)]
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_subscribe_v5_packet(
                12,
                &[0x0b, 0x00],
                &[(b"sensors/+/temp".as_slice(), 1)]
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_subscribe_v5_packet(
                12,
                &[0x0b, 0x2a, 0x0b, 0x2b],
                &[(b"sensors/+/temp".as_slice(), 1)]
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_subscribe_packet(
                12,
                &[(b"$share//sensors/#".as_slice(), 1)]
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_subscribe_v5_packet(
                12,
                &[],
                &[(b"$share/+/sensors/#".as_slice(), 1)]
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_unsubscribe_packet(0, &[b"sensors/+/temp".as_slice()]))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_unsubscribe_packet(13, &[b"sensors/temp#".as_slice()]))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_unsubscribe_packet(
                13,
                &[b"$share/workers".as_slice()]
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_unsubscribe_v5_packet(
                13,
                &[0x0b, 0x01],
                &[b"sensors/+/temp".as_slice()]
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut mqtt_unsubscribe_wrong_flags =
            mqtt_unsubscribe_packet(13, &[b"sensors/+/temp".as_slice()]);
        mqtt_unsubscribe_wrong_flags[0] = 0xa0;
        assert_eq!(
            observation_for_payload(&mqtt_unsubscribe_wrong_flags).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_connack_packet(0x02, 0x00, None)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_connack_packet(0x01, 0x01, None)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_connack_packet(0x00, 0x06, None)).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_connack_packet(0x00, 0x00, Some(&[0x7f]))).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_connack_packet(
                0x00,
                0x00,
                Some(&[0x25, 0x01, 0x25, 0x00])
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&mqtt_connack_packet(0x00, 0x00, Some(&[0x21, 0x00, 0x00])))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut mqtt_connack_trailing = mqtt_connack_packet(0x00, 0x00, None);
        mqtt_connack_trailing.push(0);
        assert_eq!(
            observation_for_payload(&mqtt_connack_trailing).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(b"AMQP\0\0\x09\x01").application(),
            api::AgentPacketFlowApplication::Amqp
        );
        assert_eq!(
            observation_for_payload(&[1, 0, 0, 0, 0, 0, 4, 0, 10, 0, 10, 0xce]).application(),
            api::AgentPacketFlowApplication::Amqp
        );
        assert_eq!(
            observation_for_payload(&[1, 0, 1, 0, 0, 0, 4, 0, 20, 0, 10, 0xce]).application(),
            api::AgentPacketFlowApplication::Amqp
        );
        assert_eq!(
            observation_for_payload(&[1, 0, 1, 0, 0, 0, 4, 0, 85, 0, 10, 0xce]).application(),
            api::AgentPacketFlowApplication::Amqp
        );
        assert_eq!(
            observation_for_payload(&amqp_frame(
                2,
                1,
                &amqp_content_header_body(60, 0, 0, 0, &[])
            ))
            .application(),
            api::AgentPacketFlowApplication::Amqp
        );
        let mut amqp_basic_properties = amqp_short_string(b"text/plain");
        amqp_basic_properties.extend_from_slice(&[2, 0]);
        assert_eq!(
            observation_for_payload(&amqp_frame(
                2,
                1,
                &amqp_content_header_body(60, 0, 42, 0x9800, &amqp_basic_properties)
            ))
            .application(),
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
            observation_for_payload(&[1, 0, 1, 0, 0, 0, 4, 0, 10, 0, 10, 0xce]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[1, 0, 0, 0, 0, 0, 4, 0, 20, 0, 10, 0xce]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&amqp_frame(
                2,
                1,
                &amqp_content_header_body(40, 0, 0, 0, &[])
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&amqp_frame(
                2,
                1,
                &amqp_content_header_body(60, 1, 0, 0, &[])
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&amqp_frame(
                2,
                1,
                &amqp_content_header_body(60, 0, 0, 0x0001, &[])
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&amqp_frame(
                2,
                1,
                &amqp_content_header_body(60, 0, 0, 0x8000, &[])
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&amqp_frame(3, 1, b"opaque broker payload")).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[1, 0, 1, 0, 0, 0, 4, 0, 60, 0, 12, 0xce]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&[1, 0, 1, 0, 0, 0, 4, 0, 70, 0, 10, 0xce]).application(),
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
            observation_for_payload(&cassandra_response_frame(0x08, &1_u32.to_be_bytes()))
                .application(),
            api::AgentPacketFlowApplication::Cassandra
        );
        let mut cassandra_set_keyspace_result = 3_u32.to_be_bytes().to_vec();
        cassandra_set_keyspace_result.extend_from_slice(&cassandra_string(b"ks"));
        assert_eq!(
            observation_for_payload(&cassandra_response_frame(
                0x08,
                &cassandra_set_keyspace_result
            ))
            .application(),
            api::AgentPacketFlowApplication::Cassandra
        );
        let mut cassandra_rows_result = 2_u32.to_be_bytes().to_vec();
        cassandra_rows_result.extend_from_slice(&1_u32.to_be_bytes());
        cassandra_rows_result.extend_from_slice(&1_u32.to_be_bytes());
        cassandra_rows_result.extend_from_slice(&cassandra_string(b"ks"));
        cassandra_rows_result.extend_from_slice(&cassandra_string(b"tbl"));
        cassandra_rows_result.extend_from_slice(&cassandra_string(b"id"));
        cassandra_rows_result.extend_from_slice(&0x0009_u16.to_be_bytes());
        cassandra_rows_result.extend_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            observation_for_payload(&cassandra_response_frame(0x08, &cassandra_rows_result))
                .application(),
            api::AgentPacketFlowApplication::Cassandra
        );
        let mut cassandra_rows_collection_result = 2_u32.to_be_bytes().to_vec();
        cassandra_rows_collection_result.extend_from_slice(&1_u32.to_be_bytes());
        cassandra_rows_collection_result.extend_from_slice(&1_u32.to_be_bytes());
        cassandra_rows_collection_result.extend_from_slice(&cassandra_string(b"ks"));
        cassandra_rows_collection_result.extend_from_slice(&cassandra_string(b"tbl"));
        cassandra_rows_collection_result.extend_from_slice(&cassandra_string(b"items"));
        cassandra_rows_collection_result.extend_from_slice(&0x0020_u16.to_be_bytes());
        cassandra_rows_collection_result.extend_from_slice(&0x0009_u16.to_be_bytes());
        cassandra_rows_collection_result.extend_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            observation_for_payload(&cassandra_response_frame(
                0x08,
                &cassandra_rows_collection_result
            ))
            .application(),
            api::AgentPacketFlowApplication::Cassandra
        );
        let mut cassandra_rows_custom_result = 2_u32.to_be_bytes().to_vec();
        cassandra_rows_custom_result.extend_from_slice(&1_u32.to_be_bytes());
        cassandra_rows_custom_result.extend_from_slice(&1_u32.to_be_bytes());
        cassandra_rows_custom_result.extend_from_slice(&cassandra_string(b"ks"));
        cassandra_rows_custom_result.extend_from_slice(&cassandra_string(b"tbl"));
        cassandra_rows_custom_result.extend_from_slice(&cassandra_string(b"custom_value"));
        cassandra_rows_custom_result.extend_from_slice(&0x0000_u16.to_be_bytes());
        cassandra_rows_custom_result.extend_from_slice(&cassandra_string(b"org.example.Type"));
        cassandra_rows_custom_result.extend_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            observation_for_payload(&cassandra_response_frame(
                0x08,
                &cassandra_rows_custom_result
            ))
            .application(),
            api::AgentPacketFlowApplication::Cassandra
        );
        let mut cassandra_prepared_result = 4_u32.to_be_bytes().to_vec();
        cassandra_prepared_result.extend_from_slice(&3_u16.to_be_bytes());
        cassandra_prepared_result.extend_from_slice(b"pid");
        cassandra_prepared_result.extend_from_slice(&4_u32.to_be_bytes());
        cassandra_prepared_result.extend_from_slice(&0_u32.to_be_bytes());
        cassandra_prepared_result.extend_from_slice(&4_u32.to_be_bytes());
        cassandra_prepared_result.extend_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            observation_for_payload(&cassandra_response_frame(0x08, &cassandra_prepared_result))
                .application(),
            api::AgentPacketFlowApplication::Cassandra
        );
        let mut cassandra_schema_change_result = 5_u32.to_be_bytes().to_vec();
        cassandra_schema_change_result.extend_from_slice(&cassandra_string(b"CREATED"));
        cassandra_schema_change_result.extend_from_slice(&cassandra_string(b"TABLE"));
        cassandra_schema_change_result.extend_from_slice(&cassandra_string(b"ks"));
        cassandra_schema_change_result.extend_from_slice(&cassandra_string(b"tbl"));
        assert_eq!(
            observation_for_payload(&cassandra_response_frame(
                0x08,
                &cassandra_schema_change_result
            ))
            .application(),
            api::AgentPacketFlowApplication::Cassandra
        );
        assert_eq!(
            observation_for_payload(&[0x04, 0, 0, 0, 0x07, 0, 0, 0, 0]).application(),
            api::AgentPacketFlowApplication::Unknown
        );
        assert_eq!(
            observation_for_payload(&cassandra_response_frame(0x08, &0x9999_u32.to_be_bytes()))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut cassandra_rows_bad_flags = 2_u32.to_be_bytes().to_vec();
        cassandra_rows_bad_flags.extend_from_slice(&0x8000_u32.to_be_bytes());
        cassandra_rows_bad_flags.extend_from_slice(&0_u32.to_be_bytes());
        cassandra_rows_bad_flags.extend_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            observation_for_payload(&cassandra_response_frame(0x08, &cassandra_rows_bad_flags))
                .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut cassandra_rows_deep_type = 2_u32.to_be_bytes().to_vec();
        cassandra_rows_deep_type.extend_from_slice(&1_u32.to_be_bytes());
        cassandra_rows_deep_type.extend_from_slice(&1_u32.to_be_bytes());
        cassandra_rows_deep_type.extend_from_slice(&cassandra_string(b"ks"));
        cassandra_rows_deep_type.extend_from_slice(&cassandra_string(b"tbl"));
        cassandra_rows_deep_type.extend_from_slice(&cassandra_string(b"deep"));
        for _ in 0..18 {
            cassandra_rows_deep_type.extend_from_slice(&0x0020_u16.to_be_bytes());
        }
        cassandra_rows_deep_type.extend_from_slice(&0x0009_u16.to_be_bytes());
        cassandra_rows_deep_type.extend_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            observation_for_payload(&cassandra_response_frame(0x08, &cassandra_rows_deep_type))
                .application(),
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
        mongodb_compressed.extend_from_slice(&(b"compressed".len() as u32).to_le_bytes());
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
        let mut mongodb_op_query_partial_flag = Vec::new();
        mongodb_op_query_partial_flag.extend_from_slice(&0x80_u32.to_le_bytes());
        mongodb_op_query_partial_flag.extend_from_slice(b"admin.$cmd\0");
        mongodb_op_query_partial_flag.extend_from_slice(&0_i32.to_le_bytes());
        mongodb_op_query_partial_flag.extend_from_slice(&1_i32.to_le_bytes());
        mongodb_op_query_partial_flag.extend_from_slice(&empty_bson);
        assert_eq!(
            observation_for_payload(&mongodb_message(2004, &mongodb_op_query_partial_flag))
                .application(),
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
        let mut invalid_mongodb_query_reserved_flag = Vec::new();
        invalid_mongodb_query_reserved_flag.extend_from_slice(&1_u32.to_le_bytes());
        invalid_mongodb_query_reserved_flag.extend_from_slice(b"admin.$cmd\0");
        invalid_mongodb_query_reserved_flag.extend_from_slice(&0_i32.to_le_bytes());
        invalid_mongodb_query_reserved_flag.extend_from_slice(&1_i32.to_le_bytes());
        invalid_mongodb_query_reserved_flag.extend_from_slice(&empty_bson);
        assert_eq!(
            observation_for_payload(&mongodb_message(2004, &invalid_mongodb_query_reserved_flag))
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
        let mut invalid_mongodb_compressed_noop_size = Vec::new();
        invalid_mongodb_compressed_noop_size.extend_from_slice(&2013_u32.to_le_bytes());
        invalid_mongodb_compressed_noop_size.extend_from_slice(&9_u32.to_le_bytes());
        invalid_mongodb_compressed_noop_size.push(0);
        invalid_mongodb_compressed_noop_size.extend_from_slice(b"compressed");
        assert_eq!(
            observation_for_payload(&mongodb_message(
                2012,
                &invalid_mongodb_compressed_noop_size
            ))
            .application(),
            api::AgentPacketFlowApplication::Unknown
        );
        let mut invalid_mongodb_compressed_empty = Vec::new();
        invalid_mongodb_compressed_empty.extend_from_slice(&2013_u32.to_le_bytes());
        invalid_mongodb_compressed_empty.extend_from_slice(&1_u32.to_le_bytes());
        invalid_mongodb_compressed_empty.push(1);
        assert_eq!(
            observation_for_payload(&mongodb_message(2012, &invalid_mongodb_compressed_empty))
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
            serde_json::from_str(r#"{"detector":"ebpf-jsonl.v1_0"}"#)?;
        assert_eq!(parsed.detector.as_deref(), Some("ebpf-jsonl.v1_0"));

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
            r#"{"detector":" ebpf-jsonl"}"#,
        ) {
            Ok(_) => return Err("detector with leading whitespace should be rejected".into()),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("packet-flow detector must not contain leading or trailing whitespace"));

        let error = match serde_json::from_str::<api::AgentPacketFlowObservation>(
            "{\"detector\":\"ebpf-jsonl\\nspoof\"}",
        ) {
            Ok(_) => return Err("detector with control characters should be rejected".into()),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("packet-flow detector must not contain control characters"));

        let error = match serde_json::from_str::<api::AgentPacketFlowObservation>(
            r#"{"detector":"ebpf jsonl"}"#,
        ) {
            Ok(_) => return Err("detector with internal whitespace should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains(
            "packet-flow detector must be an ASCII token using letters, digits, '.', '_', or '-'"
        ));
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

        let whitespace_detector = api::AgentPacketFlowObservation {
            detector: Some("proc-net-conntrack ".to_string()),
            ..Default::default()
        };
        let error = match whitespace_detector.validate_transport_metadata() {
            Ok(()) => return Err("direct detector whitespace should be rejected".into()),
            Err(error) => error,
        };
        assert!(
            error.contains("packet-flow detector must not contain leading or trailing whitespace")
        );

        let non_token_detector = api::AgentPacketFlowObservation {
            detector: Some("proc/net/conntrack".to_string()),
            ..Default::default()
        };
        let error = match non_token_detector.validate_transport_metadata() {
            Ok(()) => return Err("direct detector non-token characters should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains(
            "packet-flow detector must be an ASCII token using letters, digits, '.', '_', or '-'"
        ));

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

        let udp_openvpn_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"openvpn"}"#)?;
        udp_openvpn_hint.validate_transport_metadata()?;

        let tcp_openvpn_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"open_vpn"}"#)?;
        tcp_openvpn_hint.validate_transport_metadata()?;

        let gre_openvpn_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"gre","application":"openvpn"}"#)?;
        let error = match gre_openvpn_hint.validate_transport_metadata() {
            Ok(()) => return Err("GRE OpenVPN hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint openvpn requires TCP or UDP protocol"));

        let udp_sip_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"sip"}"#)?;
        udp_sip_hint.validate_transport_metadata()?;

        let tcp_sip_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"sip"}"#)?;
        tcp_sip_hint.validate_transport_metadata()?;

        let sctp_sip_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"sctp","application":"sip"}"#)?;
        sctp_sip_hint.validate_transport_metadata()?;

        let gre_sip_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"gre","application":"sip"}"#)?;
        let error = match gre_sip_hint.validate_transport_metadata() {
            Ok(()) => return Err("GRE SIP hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint sip requires TCP, UDP, or SCTP protocol"));

        let udp_turn_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"turn"}"#)?;
        udp_turn_hint.validate_transport_metadata()?;

        let tcp_turn_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"turn"}"#)?;
        tcp_turn_hint.validate_transport_metadata()?;

        let gre_turn_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"gre","application":"turn"}"#)?;
        let error = match gre_turn_hint.validate_transport_metadata() {
            Ok(()) => return Err("GRE TURN hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint turn requires TCP or UDP protocol"));

        let udp_coap_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"udp","application":"coap"}"#)?;
        udp_coap_hint.validate_transport_metadata()?;

        let tcp_coap_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"tcp","application":"coap"}"#)?;
        tcp_coap_hint.validate_transport_metadata()?;

        let gre_coap_hint: api::AgentPacketFlowObservation =
            serde_json::from_str(r#"{"protocol":"gre","application":"coap"}"#)?;
        let error = match gre_coap_hint.validate_transport_metadata() {
            Ok(()) => return Err("GRE CoAP hint should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.contains("application hint coap requires TCP or UDP protocol"));

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
