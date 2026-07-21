use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use ipars_route_manager::{with_linux_network_namespace, LinuxNetworkNamespace};
use ipars_types::{
    EndpointCandidate, NodeId, NodeRecord, PathMetrics, PathQualityObservation, PathRecord,
    PathState, VpnIp,
};
use rand_core::{OsRng, RngCore};
use tokio::net::UdpSocket;

use crate::{AgentError, AgentRuntime};

pub const DEFAULT_PEER_PROBE_PORT: u16 = 51_821;
const PEER_PROBE_PACKET_LEN: usize = 32;
const PEER_PROBE_MAGIC: [u8; 8] = *b"IPARSPRB";
const PEER_PROBE_VERSION: u8 = 1;
const PEER_PROBE_NONCE_LEN: usize = 16;
const PEER_PROBE_MAX_DISCARDED_DATAGRAMS_PER_SAMPLE: usize = 128;
const PEER_PROBE_RATE_WINDOW: Duration = Duration::from_secs(1);
const PEER_PROBE_WAKE_RESPONSE_DELAY: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerProbeConfig {
    pub port: u16,
    pub sample_count: u16,
    pub response_timeout: Duration,
    pub sample_interval: Duration,
    pub max_requests_per_second_per_peer: u32,
}

impl Default for PeerProbeConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_PEER_PROBE_PORT,
            sample_count: 5,
            response_timeout: Duration::from_millis(500),
            sample_interval: Duration::from_millis(20),
            max_requests_per_second_per_peer: 100,
        }
    }
}

impl PeerProbeConfig {
    pub fn validate(&self) -> Result<(), AgentError> {
        if self.port == 0 {
            return Err(AgentError::PeerProbe(
                "probe port must be greater than zero".to_string(),
            ));
        }
        if self.sample_count == 0 || self.sample_count > 64 {
            return Err(AgentError::PeerProbe(
                "probe sample count must be between 1 and 64".to_string(),
            ));
        }
        if self.response_timeout.is_zero() || self.response_timeout > Duration::from_secs(10) {
            return Err(AgentError::PeerProbe(
                "probe response timeout must be greater than zero and at most 10 seconds"
                    .to_string(),
            ));
        }
        if self.sample_interval > Duration::from_secs(10) {
            return Err(AgentError::PeerProbe(
                "probe sample interval must be at most 10 seconds".to_string(),
            ));
        }
        if self.max_requests_per_second_per_peer == 0
            || self.max_requests_per_second_per_peer > 100_000
        {
            return Err(AgentError::PeerProbe(
                "probe responder rate limit must be between 1 and 100000 requests per second per peer"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PeerQualityProbeTarget {
    pub peer: NodeRecord,
    pub path: PathRecord,
    pub wake_passive_peer: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerProbeMeasurement {
    sample_count: u16,
    round_trip_times: Vec<Duration>,
}

impl PeerProbeMeasurement {
    pub fn sample_count(&self) -> u16 {
        self.sample_count
    }

    pub fn successful_sample_count(&self) -> u16 {
        self.round_trip_times.len() as u16
    }

    pub fn timeout_count(&self) -> u16 {
        self.sample_count
            .saturating_sub(self.successful_sample_count())
    }

    #[cfg(test)]
    fn from_round_trip_times(sample_count: u16, round_trip_times: Vec<Duration>) -> Self {
        Self {
            sample_count,
            round_trip_times,
        }
    }

    pub(crate) fn to_path_observation(
        &self,
        path: &PathRecord,
        previous: Option<&PathQualityObservation>,
        observed_at: DateTime<Utc>,
    ) -> Result<PathQualityObservation, AgentError> {
        if self.sample_count == 0 || self.round_trip_times.len() > usize::from(self.sample_count) {
            return Err(AgentError::PeerProbe(
                "probe measurement sample counts are invalid".to_string(),
            ));
        }
        if path.selected_state == PathState::Unreachable {
            return Err(AgentError::PeerProbe(
                "an unreachable path cannot produce a quality observation".to_string(),
            ));
        }

        let successful_sample_count = self.successful_sample_count();
        let lost = u64::from(self.sample_count - successful_sample_count);
        let loss_ppm = (lost * 1_000_000 / u64::from(self.sample_count)) as u32;
        let latency_ms = mean_duration_millis(&self.round_trip_times);
        let jitter_ms = mean_jitter_millis(&self.round_trip_times);
        let availability = f32::from(successful_sample_count) / f32::from(self.sample_count);
        let jitter_ratio = match (latency_ms, jitter_ms) {
            (Some(latency), Some(jitter)) if latency > 0.0 => (jitter / latency).clamp(0.0, 1.0),
            _ => 0.0,
        };
        let round_stability = availability * (1.0 - jitter_ratio * 0.5);
        let stability = match previous {
            Some(previous) if path_matches_observation(path, previous) => {
                previous.metrics.stability * 0.7 + round_stability * 0.3
            }
            Some(_) => round_stability * 0.5,
            None => round_stability,
        }
        .clamp(0.0, 1.0);

        Ok(PathQualityObservation {
            selected_state: path.selected_state,
            selected_candidate: path.selected_candidate.clone(),
            relay_node: path.relay_node.clone(),
            metrics: PathMetrics {
                latency_ms,
                loss_ppm,
                jitter_ms,
                relay_load: None,
                stability,
            },
            sample_count: self.sample_count,
            successful_sample_count,
            observed_at,
        })
    }
}

fn mean_duration_millis(values: &[Duration]) -> Option<f32> {
    if values.is_empty() {
        return None;
    }
    let total = values.iter().map(Duration::as_secs_f64).sum::<f64>();
    Some((total * 1_000.0 / values.len() as f64) as f32)
}

fn mean_jitter_millis(values: &[Duration]) -> Option<f32> {
    if values.len() < 2 {
        return None;
    }
    let total = values
        .windows(2)
        .map(|pair| pair[0].abs_diff(pair[1]).as_secs_f64())
        .sum::<f64>();
    Some((total * 1_000.0 / (values.len() - 1) as f64) as f32)
}

#[derive(Debug, Clone)]
pub struct UdpPeerProbe {
    local_vpn_ip: VpnIp,
    namespace: Option<LinuxNetworkNamespace>,
    config: PeerProbeConfig,
}

impl UdpPeerProbe {
    pub fn new(
        local_vpn_ip: VpnIp,
        namespace: Option<LinuxNetworkNamespace>,
        config: PeerProbeConfig,
    ) -> Result<Self, AgentError> {
        config.validate()?;
        Ok(Self {
            local_vpn_ip,
            namespace,
            config,
        })
    }

    pub async fn measure(&self, target_vpn_ip: VpnIp) -> Result<PeerProbeMeasurement, AgentError> {
        self.measure_with_wake_intent(target_vpn_ip, false).await
    }

    pub async fn wake_and_measure(
        &self,
        target_vpn_ip: VpnIp,
    ) -> Result<PeerProbeMeasurement, AgentError> {
        self.measure_with_wake_intent(target_vpn_ip, true).await
    }

    async fn measure_with_wake_intent(
        &self,
        target_vpn_ip: VpnIp,
        wake_passive_peer: bool,
    ) -> Result<PeerProbeMeasurement, AgentError> {
        if target_vpn_ip == self.local_vpn_ip {
            return Err(AgentError::PeerProbe(
                "peer probe target must differ from the local VPN IP".to_string(),
            ));
        }
        if std::mem::discriminant(&target_vpn_ip.0) != std::mem::discriminant(&self.local_vpn_ip.0)
        {
            return Err(AgentError::PeerProbe(
                "peer probe target and local VPN IP families must match".to_string(),
            ));
        }
        let socket = bind_udp_socket(
            SocketAddr::new(self.local_vpn_ip.0, 0),
            self.namespace.as_ref(),
        )?;
        let target = SocketAddr::new(target_vpn_ip.0, self.config.port);
        let mut nonce = [0_u8; PEER_PROBE_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let mut round_trip_times = Vec::with_capacity(usize::from(self.config.sample_count));

        for sequence in 0..u32::from(self.config.sample_count) {
            let request = PeerProbePacket {
                kind: PeerProbePacketKind::Request,
                wake_passive_peer,
                nonce,
                sequence,
            };
            let started_at = Instant::now();
            if socket.send_to(&request.encode(), target).await.is_ok()
                && receive_matching_response(
                    &socket,
                    target,
                    nonce,
                    sequence,
                    wake_passive_peer,
                    self.config.response_timeout,
                )
                .await?
            {
                round_trip_times.push(started_at.elapsed());
            }
            if sequence + 1 < u32::from(self.config.sample_count)
                && !self.config.sample_interval.is_zero()
            {
                tokio::time::sleep(self.config.sample_interval).await;
            }
        }

        Ok(PeerProbeMeasurement {
            sample_count: self.config.sample_count,
            round_trip_times,
        })
    }
}

async fn receive_matching_response(
    socket: &UdpSocket,
    target: SocketAddr,
    nonce: [u8; PEER_PROBE_NONCE_LEN],
    sequence: u32,
    wake_passive_peer: bool,
    timeout: Duration,
) -> Result<bool, AgentError> {
    let deadline = Instant::now() + timeout;
    let mut discarded = 0;
    let mut buffer = [0_u8; PEER_PROBE_PACKET_LEN + 1];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || discarded >= PEER_PROBE_MAX_DISCARDED_DATAGRAMS_PER_SAMPLE {
            return Ok(false);
        }
        let received = match tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await {
            Ok(Ok(received)) => received,
            Ok(Err(error)) if recoverable_udp_error(&error) => continue,
            Ok(Err(error)) => {
                return Err(AgentError::PeerProbe(format!(
                    "failed to receive UDP probe response: {error}"
                )));
            }
            Err(_) => return Ok(false),
        };
        let (length, source) = received;
        let matches = source == target
            && PeerProbePacket::decode(&buffer[..length]).is_some_and(|packet| {
                packet.kind == PeerProbePacketKind::Response
                    && packet.wake_passive_peer == wake_passive_peer
                    && packet.nonce == nonce
                    && packet.sequence == sequence
            });
        if matches {
            return Ok(true);
        }
        discarded += 1;
    }
}

#[derive(Debug)]
pub struct UdpPeerProbeResponder {
    socket: UdpSocket,
    config: PeerProbeConfig,
}

impl UdpPeerProbeResponder {
    pub fn bind(
        local_vpn_ip: VpnIp,
        namespace: Option<&LinuxNetworkNamespace>,
        config: PeerProbeConfig,
    ) -> Result<Self, AgentError> {
        config.validate()?;
        let socket = bind_udp_socket(SocketAddr::new(local_vpn_ip.0, config.port), namespace)?;
        Ok(Self { socket, config })
    }

    pub async fn run(self, runtime: Arc<AgentRuntime>) -> Result<(), AgentError> {
        let mut rate_limits = BTreeMap::<NodeId, PeerProbeRateWindow>::new();
        let mut buffer = [0_u8; PEER_PROBE_PACKET_LEN + 1];
        loop {
            let (length, source) = match self.socket.recv_from(&mut buffer).await {
                Ok(received) => received,
                Err(error) if recoverable_udp_error(&error) => continue,
                Err(error) => {
                    return Err(AgentError::PeerProbe(format!(
                        "failed to receive UDP probe request: {error}"
                    )));
                }
            };
            let Some(peer) = runtime.peer_node_for_vpn_ip(source.ip()).await else {
                runtime.record_peer_probe_responder_unknown_source();
                continue;
            };
            let Some(request) = PeerProbePacket::decode(&buffer[..length]) else {
                runtime.record_peer_probe_responder_invalid();
                continue;
            };
            if request.kind != PeerProbePacketKind::Request {
                runtime.record_peer_probe_responder_invalid();
                continue;
            }
            let now = Instant::now();
            rate_limits.retain(|_, limit| {
                now.duration_since(limit.window_started) < PEER_PROBE_RATE_WINDOW
            });
            let limit = rate_limits
                .entry(peer.clone())
                .or_insert_with(|| PeerProbeRateWindow::new(now));
            if !limit.allow(now, self.config.max_requests_per_second_per_peer) {
                runtime.record_peer_probe_responder_rate_limited();
                continue;
            }
            let woke_passive_peer = if request.wake_passive_peer {
                runtime.wake_passive_peer_from_probe(peer, Utc::now()).await
            } else {
                false
            };
            if woke_passive_peer {
                // Give the notified peer-map reconciler time to install the
                // return route before the first response leaves this socket.
                tokio::time::sleep(PEER_PROBE_WAKE_RESPONSE_DELAY).await;
            }
            let response = PeerProbePacket {
                kind: PeerProbePacketKind::Response,
                ..request
            }
            .encode();
            match self.socket.send_to(&response, source).await {
                Ok(sent) if sent == PEER_PROBE_PACKET_LEN => {
                    runtime.record_peer_probe_responder_request();
                }
                Ok(_) => runtime.record_peer_probe_responder_send_failure(),
                Err(error) if recoverable_udp_error(&error) => {
                    runtime.record_peer_probe_responder_send_failure();
                }
                Err(_error) => {
                    runtime.record_peer_probe_responder_send_failure();
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PeerProbeRateWindow {
    window_started: Instant,
    request_count: u32,
}

impl PeerProbeRateWindow {
    fn new(now: Instant) -> Self {
        Self {
            window_started: now,
            request_count: 0,
        }
    }

    fn allow(&mut self, now: Instant, maximum: u32) -> bool {
        if now.duration_since(self.window_started) >= PEER_PROBE_RATE_WINDOW {
            self.window_started = now;
            self.request_count = 0;
        }
        if self.request_count >= maximum {
            return false;
        }
        self.request_count += 1;
        true
    }
}

fn bind_udp_socket(
    bind_addr: SocketAddr,
    namespace: Option<&LinuxNetworkNamespace>,
) -> Result<UdpSocket, AgentError> {
    let socket = with_linux_network_namespace(namespace, || {
        let socket = StdUdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    })
    .map_err(|error| {
        AgentError::PeerProbe(format!(
            "failed to bind UDP peer probe socket at {bind_addr}: {error}"
        ))
    })?;
    UdpSocket::from_std(socket).map_err(|error| {
        AgentError::PeerProbe(format!(
            "failed to register UDP peer probe socket at {bind_addr}: {error}"
        ))
    })
}

fn recoverable_udp_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerProbePacketKind {
    Request = 1,
    Response = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerProbePacket {
    kind: PeerProbePacketKind,
    wake_passive_peer: bool,
    nonce: [u8; PEER_PROBE_NONCE_LEN],
    sequence: u32,
}

impl PeerProbePacket {
    fn encode(self) -> [u8; PEER_PROBE_PACKET_LEN] {
        let mut packet = [0_u8; PEER_PROBE_PACKET_LEN];
        packet[..PEER_PROBE_MAGIC.len()].copy_from_slice(&PEER_PROBE_MAGIC);
        packet[8] = PEER_PROBE_VERSION;
        packet[9] = self.kind as u8;
        packet[10] = u8::from(self.wake_passive_peer);
        packet[12..28].copy_from_slice(&self.nonce);
        packet[28..32].copy_from_slice(&self.sequence.to_be_bytes());
        packet
    }

    fn decode(packet: &[u8]) -> Option<Self> {
        if packet.len() != PEER_PROBE_PACKET_LEN
            || packet[..8] != PEER_PROBE_MAGIC
            || packet[8] != PEER_PROBE_VERSION
            || packet[11] != 0
        {
            return None;
        }
        let kind = match packet[9] {
            1 => PeerProbePacketKind::Request,
            2 => PeerProbePacketKind::Response,
            _ => return None,
        };
        let wake_passive_peer = match packet[10] {
            0 => false,
            1 => true,
            _ => return None,
        };
        Some(Self {
            kind,
            wake_passive_peer,
            nonce: packet[12..28].try_into().ok()?,
            sequence: u32::from_be_bytes(packet[28..32].try_into().ok()?),
        })
    }
}

pub(crate) fn path_records_same_path(left: &PathRecord, right: &PathRecord) -> bool {
    left.key == right.key
        && left.selected_state == right.selected_state
        && endpoint_candidates_match(
            left.selected_candidate.as_ref(),
            right.selected_candidate.as_ref(),
        )
        && left.relay_node == right.relay_node
}

pub(crate) fn path_matches_observation(
    path: &PathRecord,
    observation: &PathQualityObservation,
) -> bool {
    path.selected_state == observation.selected_state
        && endpoint_candidates_match(
            path.selected_candidate.as_ref(),
            observation.selected_candidate.as_ref(),
        )
        && path.relay_node == observation.relay_node
}

fn endpoint_candidates_match(
    left: Option<&EndpointCandidate>,
    right: Option<&EndpointCandidate>,
) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => {
            left.node_id == right.node_id && left.kind == right.kind && left.addr == right.addr
        }
        (None, None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, UdpSocket as StdUdpSocket};

    use ipars_types::{
        api::PeerMap, CandidateSource, ClusterId, EndpointCandidateKind, PathScore, PeerPathKey,
        Role, TokenPolicy,
    };

    use super::*;
    use crate::AgentNodeState;

    fn path(state: PathState) -> PathRecord {
        let peer = NodeId::from_string("peer-a");
        let selected_candidate = state.is_direct().then(|| EndpointCandidate {
            node_id: peer.clone(),
            kind: if state == PathState::DirectPublic {
                EndpointCandidateKind::PublicUdp
            } else if state == PathState::DirectIpv6 {
                EndpointCandidateKind::Ipv6
            } else {
                EndpointCandidateKind::StunReflexive
            },
            addr: SocketAddr::from(([8, 8, 8, 10], 51_820)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::StunProbe,
        });
        PathRecord {
            key: PeerPathKey::new(NodeId::from_string("local"), peer),
            selected_state: state,
            selected_candidate,
            relay_node: (state == PathState::Relay).then(|| NodeId::from_string("relay-a")),
            score: PathScore {
                value: 1.0,
                reasons: Vec::new(),
            },
            updated_at: Utc::now(),
            pinned: false,
        }
    }

    fn peer_record(vpn_ip: IpAddr) -> NodeRecord {
        NodeRecord {
            node_id: NodeId::from_string("peer-a"),
            cluster_id: ClusterId::new(),
            vpn_ip: VpnIp(vpn_ip),
            identity_public_key: "identity".to_string(),
            wireguard_public_key: "wireguard".to_string(),
            role: Role::edge(),
            tags: BTreeSet::new(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        }
    }

    #[test]
    fn fixed_width_probe_packet_round_trips_and_rejects_malformed_input() {
        let packet = PeerProbePacket {
            kind: PeerProbePacketKind::Request,
            wake_passive_peer: true,
            nonce: [7; PEER_PROBE_NONCE_LEN],
            sequence: 42,
        };
        let encoded = packet.encode();
        assert_eq!(encoded.len(), PEER_PROBE_PACKET_LEN);
        assert_eq!(PeerProbePacket::decode(&encoded), Some(packet));

        let mut malformed = encoded;
        malformed[10] = 2;
        assert_eq!(PeerProbePacket::decode(&malformed), None);
        assert_eq!(PeerProbePacket::decode(&encoded[..31]), None);
        let mut unknown_kind = encoded;
        unknown_kind[9] = 3;
        assert_eq!(PeerProbePacket::decode(&unknown_kind), None);
    }

    #[test]
    fn measurement_calculates_loss_latency_jitter_and_stability() -> Result<(), AgentError> {
        let measurement = PeerProbeMeasurement::from_round_trip_times(
            5,
            vec![
                Duration::from_millis(10),
                Duration::from_millis(20),
                Duration::from_millis(30),
                Duration::from_millis(40),
            ],
        );
        let observation =
            measurement.to_path_observation(&path(PathState::DirectPublic), None, Utc::now())?;

        assert_eq!(observation.sample_count, 5);
        assert_eq!(observation.successful_sample_count, 4);
        assert_eq!(observation.metrics.loss_ppm, 200_000);
        assert_eq!(observation.metrics.latency_ms, Some(25.0));
        assert_eq!(observation.metrics.jitter_ms, Some(10.0));
        assert!((observation.metrics.stability - 0.64).abs() < 0.001);
        Ok(())
    }

    #[tokio::test]
    async fn responder_echoes_only_for_peer_map_vpn_sources() -> Result<(), AgentError> {
        let reservation = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = reservation.local_addr()?.port();
        drop(reservation);
        let config = PeerProbeConfig {
            port,
            sample_count: 3,
            response_timeout: Duration::from_millis(250),
            sample_interval: Duration::from_millis(1),
            max_requests_per_second_per_peer: 100,
        };
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ipars_types::ClusterPolicy::default(),
        ));
        let peer = peer_record(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
        runtime
            .record_peer_map_snapshot(PeerMap {
                cluster_id: ClusterId::new(),
                peers: vec![peer.clone()],
                bootstrap_endpoints: Vec::new(),
                generated_at: Utc::now(),
            })
            .await;
        let responder =
            UdpPeerProbeResponder::bind(VpnIp(IpAddr::V4(Ipv4Addr::LOCALHOST)), None, config)?;
        let responder_task = tokio::spawn(responder.run(runtime.clone()));
        let probe =
            UdpPeerProbe::new(VpnIp(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))), None, config)?;

        let routine_measurement = probe
            .measure(VpnIp(IpAddr::V4(Ipv4Addr::LOCALHOST)))
            .await?;
        assert_eq!(routine_measurement.sample_count(), 3);
        assert_eq!(routine_measurement.successful_sample_count(), 3);
        assert!(!runtime.should_connect_peer(&peer).await);

        let measurement = probe
            .wake_and_measure(VpnIp(IpAddr::V4(Ipv4Addr::LOCALHOST)))
            .await?;
        responder_task.abort();
        assert_eq!(measurement.sample_count(), 3);
        assert_eq!(measurement.successful_sample_count(), 3);
        assert!(runtime.should_connect_peer(&peer).await);
        assert_eq!(
            runtime
                .recent_local_peer_activity(&peer.node_id, Utc::now())
                .await,
            None
        );
        Ok(())
    }

    #[tokio::test]
    async fn only_local_activity_marks_quality_probes_as_wake_intent() -> Result<(), AgentError> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = AgentRuntime::new(state, ipars_types::ClusterPolicy::default());
        let peer = peer_record(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)));
        let peer_map = PeerMap {
            cluster_id: ClusterId::new(),
            peers: vec![peer.clone()],
            bootstrap_endpoints: Vec::new(),
            generated_at: Utc::now(),
        };
        runtime
            .observe_peer_map_for_lazy_connect(&peer_map.peers)
            .await;
        runtime.record_peer_map_snapshot(peer_map).await;
        let mut selected_path = path(PathState::DirectPublic);
        selected_path.key = PeerPathKey::new(local_node, peer.node_id.clone());
        runtime.upsert_path_state(selected_path).await?;

        runtime
            .record_remote_peer_activity(peer.node_id.clone(), Utc::now())
            .await;
        let remote_targets = runtime.peer_quality_probe_targets().await;
        assert_eq!(remote_targets.len(), 1);
        assert!(!remote_targets[0].wake_passive_peer);

        runtime
            .record_peer_activity(peer.node_id, Utc::now(), false)
            .await;
        let local_targets = runtime.peer_quality_probe_targets().await;
        assert_eq!(local_targets.len(), 1);
        assert!(local_targets[0].wake_passive_peer);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_caches_measurement_only_while_path_fingerprint_matches(
    ) -> Result<(), AgentError> {
        let state = AgentNodeState::generate(Utc::now());
        let local_node = state.node_id.clone();
        let runtime = AgentRuntime::new(state, ipars_types::ClusterPolicy::default());
        let peer = peer_record(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)));
        let mut selected_path = path(PathState::DirectPublic);
        selected_path.key = PeerPathKey::new(local_node, peer.node_id.clone());
        runtime.upsert_path_state(selected_path.clone()).await?;
        let target = PeerQualityProbeTarget {
            peer: peer.clone(),
            path: selected_path.clone(),
            wake_passive_peer: false,
        };
        let measurement = PeerProbeMeasurement::from_round_trip_times(
            3,
            vec![Duration::from_millis(10), Duration::from_millis(12)],
        );
        let observed_at = Utc::now();

        let Some(observation) = runtime
            .record_peer_probe_measurement(&target, &measurement, observed_at)
            .await?
        else {
            panic!("unchanged path should accept peer probe measurement");
        };
        assert_eq!(observation.metrics.loss_ppm, 333_333);
        assert_eq!(
            runtime
                .path_quality_observation_for_peer(
                    &peer.node_id,
                    observed_at,
                    Duration::from_secs(120),
                )
                .await,
            Some(observation)
        );

        let mut changed_path = selected_path;
        let Some(candidate) = changed_path.selected_candidate.as_mut() else {
            panic!("direct test path must contain a selected candidate");
        };
        candidate.addr.set_port(51_821);
        runtime.upsert_path_state(changed_path).await?;
        assert!(
            runtime
                .path_quality_observation_for_peer(
                    &peer.node_id,
                    observed_at,
                    Duration::from_secs(120),
                )
                .await
                .is_none()
        );
        assert!(runtime
            .record_peer_probe_measurement(&target, &measurement, Utc::now())
            .await?
            .is_none());
        Ok(())
    }
}
