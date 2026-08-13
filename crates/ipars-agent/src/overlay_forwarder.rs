//! Bounded-degree overlay forwarding for opaque inner WireGuard datagrams.
//!
//! The caller must derive `previous_hop` from an authenticated hop transport,
//! such as the outer WireGuard peer. Each engine validates only the two edges
//! adjacent to its local node. Taken together, those checks validate every edge
//! of a multi-hop path without distributing the full overlay graph to each node.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use ipars_relay::multihop::{
    MultiHopCodecError, MultiHopEnvelope, MAX_MULTIHOP_FRAME_BYTES, MAX_MULTIHOP_PATH_NODES,
    MAX_MULTIHOP_PAYLOAD_BYTES, MULTIHOP_PATH_ID_BYTES,
};
use ipars_types::{NeighborMap, NodeId, OverlayPath};
use thiserror::Error;

pub const DEFAULT_OVERLAY_REPLAY_CACHE_CAPACITY: usize = 4_096;
pub const MAX_OVERLAY_REPLAY_CACHE_CAPACITY: usize = 65_536;

// A peer proxy permits 256 concurrent datagrams and reserves one sequence for
// each primary and secondary attempt before those sends complete. The bitmap
// therefore covers twice the maximum 512-sequence in-flight span.
const OVERLAY_PEER_MAX_IN_FLIGHT_DATAGRAMS: usize = 256;
const OVERLAY_SEQUENCE_RESERVATIONS_PER_DATAGRAM: usize = 2;
const OVERLAY_REPLAY_SEQUENCE_WINDOW_BITS: usize =
    OVERLAY_PEER_MAX_IN_FLIGHT_DATAGRAMS * OVERLAY_SEQUENCE_RESERVATIONS_PER_DATAGRAM * 2;
const OVERLAY_REPLAY_SEQUENCE_WINDOW_WORDS: usize =
    OVERLAY_REPLAY_SEQUENCE_WINDOW_BITS / u64::BITS as usize;

const PREVIOUS_TOPOLOGY_EPOCH_GRACE: Duration = Duration::from_secs(120);
// Neighbor maps can include route projections, so rapid control-plane churn
// must not grow retained topology memory without a hard limit.
const MAX_RETAINED_TOPOLOGY_EPOCHS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayForwarderConfig {
    pub max_frame_bytes: usize,
    pub max_relay_hops: u16,
    pub replay_cache_capacity: usize,
}

impl Default for OverlayForwarderConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: MAX_MULTIHOP_FRAME_BYTES,
            max_relay_hops: MAX_MULTIHOP_PATH_NODES as u16,
            replay_cache_capacity: DEFAULT_OVERLAY_REPLAY_CACHE_CAPACITY,
        }
    }
}

impl OverlayForwarderConfig {
    fn validate(self) -> Result<Self, OverlayForwarderError> {
        if self.max_frame_bytes == 0 || self.max_frame_bytes > MAX_MULTIHOP_FRAME_BYTES {
            return Err(OverlayForwarderError::InvalidConfig(format!(
                "max_frame_bytes must be between 1 and {MAX_MULTIHOP_FRAME_BYTES}"
            )));
        }
        if self.max_relay_hops == 0 || usize::from(self.max_relay_hops) > MAX_MULTIHOP_PATH_NODES {
            return Err(OverlayForwarderError::InvalidConfig(format!(
                "max_relay_hops must be between 1 and {MAX_MULTIHOP_PATH_NODES}"
            )));
        }
        if self.replay_cache_capacity == 0
            || self.replay_cache_capacity > MAX_OVERLAY_REPLAY_CACHE_CAPACITY
        {
            return Err(OverlayForwarderError::InvalidConfig(format!(
                "replay_cache_capacity must be between 1 and \
                 {MAX_OVERLAY_REPLAY_CACHE_CAPACITY}"
            )));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayPathSelection {
    Primary,
    Secondary,
}

/// The only data-bearing actions emitted by the forwarding engine.
///
/// `Forward` always contains an encoded `MultiHopEnvelope`; it never exposes
/// the inner payload separately. `Deliver` is emitted only by the declared
/// destination after the route is complete. The codec cannot encode an empty
/// relay path, so a directly adjacent destination is represented explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayForwardAction {
    Forward { next_hop: NodeId, datagram: Vec<u8> },
    Deliver { source: NodeId, payload: Vec<u8> },
    DirectNeighbor { peer: NodeId, datagram: Vec<u8> },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OverlayForwarderError {
    #[error("invalid overlay forwarder configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid neighbor map: {0}")]
    InvalidNeighborMap(String),
    #[error("neighbor map belongs to node {map_node}, not local node {local_node}")]
    NeighborMapNodeMismatch {
        local_node: NodeId,
        map_node: NodeId,
    },
    #[error("neighbor map topology epoch must be non-zero")]
    ZeroTopologyEpoch,
    #[error("neighbor map cluster changed from {current_cluster} to {received_cluster}")]
    NeighborMapClusterChanged {
        current_cluster: String,
        received_cluster: String,
    },
    #[error("invalid overlay path: {0}")]
    InvalidOverlayPath(String),
    #[error("overlay path source {path_source} does not match local node {local_node}")]
    PathSourceMismatch {
        local_node: NodeId,
        path_source: NodeId,
    },
    #[error(
        "overlay target belongs to cluster {target_cluster}, not local cluster {local_cluster}"
    )]
    PathClusterMismatch {
        local_cluster: String,
        target_cluster: String,
    },
    #[error("overlay path cannot target its own source node {0}")]
    PathTargetsSource(NodeId),
    #[error("overlay path has no secondary route")]
    SecondaryPathUnavailable,
    #[error("stale topology epoch {received_epoch}; local topology epoch is {current_epoch}")]
    StaleTopologyEpoch {
        current_epoch: u64,
        received_epoch: u64,
    },
    #[error("future topology epoch {received_epoch}; local topology epoch is {current_epoch}")]
    FutureTopologyEpoch {
        current_epoch: u64,
        received_epoch: u64,
    },
    #[error("overlay relay path has {actual} hops, exceeding configured maximum {maximum}")]
    RelayPathTooLong { actual: usize, maximum: u16 },
    #[error("multi-hop path ID must not be all zero")]
    InvalidPathId,
    #[error("inner WireGuard datagram cannot be empty")]
    EmptyInnerDatagram,
    #[error("inner WireGuard datagram exceeds {maximum} bytes")]
    InnerDatagramTooLarge { maximum: usize },
    #[error("multi-hop frame is {actual} bytes, exceeding configured maximum {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },
    #[error("multi-hop hop limit {actual} does not match the relay path length {expected}")]
    InvalidHopLimit { expected: u16, actual: u16 },
    #[error("frame is for forwarding node {expected}, not local node {actual}")]
    UnexpectedLocalHop { expected: NodeId, actual: NodeId },
    #[error("completed frame is for destination {expected}, not local node {actual}")]
    UnexpectedDestination { expected: NodeId, actual: NodeId },
    #[error("frame arrived from {actual}, but its route requires previous hop {expected}")]
    PreviousHopMismatch { expected: NodeId, actual: NodeId },
    #[error("required previous hop {0} is not in the local neighbor map")]
    PreviousHopNotNeighbor(NodeId),
    #[error("required next hop {0} is not in the local neighbor map")]
    NextHopNotNeighbor(NodeId),
    #[error(
        "replayed or out-of-window frame from {source_node}: sequence {sequence}, highest {highest}"
    )]
    ReplayRejected {
        source_node: NodeId,
        sequence: u64,
        highest: u64,
    },
    #[error("multi-hop codec error: {0}")]
    Codec(#[from] MultiHopCodecError),
}

struct RetainedNeighborMap {
    neighbor_map: NeighborMap,
    neighbor_ids: BTreeSet<NodeId>,
    expires_at: Instant,
}

/// Stateful forwarding engine for one local node and bounded epoch overlap.
pub struct BoundedOverlayForwarder {
    local_node: NodeId,
    neighbor_map: NeighborMap,
    neighbor_ids: BTreeSet<NodeId>,
    retained_neighbor_maps: VecDeque<RetainedNeighborMap>,
    config: OverlayForwarderConfig,
    replay_window: ReplayWindow,
}

impl BoundedOverlayForwarder {
    pub fn new(
        local_node: NodeId,
        neighbor_map: NeighborMap,
        config: OverlayForwarderConfig,
    ) -> Result<Self, OverlayForwarderError> {
        let config = config.validate()?;
        let neighbor_ids = validate_neighbor_map(&local_node, &neighbor_map)?;
        let replay_window = ReplayWindow::new(config.replay_cache_capacity);
        Ok(Self {
            local_node,
            neighbor_map,
            neighbor_ids,
            retained_neighbor_maps: VecDeque::with_capacity(MAX_RETAINED_TOPOLOGY_EPOCHS),
            config,
            replay_window,
        })
    }

    pub fn local_node(&self) -> &NodeId {
        &self.local_node
    }

    pub fn neighbor_map(&self) -> &NeighborMap {
        &self.neighbor_map
    }

    pub fn replay_cache_len(&self) -> usize {
        self.replay_window.len()
    }

    /// Replace the current local map. Topology epochs are opaque content
    /// identifiers. Changed maps remain available for a bounded migration
    /// grace so in-flight and make-before-break paths can finish.
    pub fn update_neighbor_map(
        &mut self,
        neighbor_map: NeighborMap,
    ) -> Result<(), OverlayForwarderError> {
        let neighbor_ids = validate_neighbor_map(&self.local_node, &neighbor_map)?;
        if neighbor_map.cluster_id != self.neighbor_map.cluster_id {
            return Err(OverlayForwarderError::NeighborMapClusterChanged {
                current_cluster: self.neighbor_map.cluster_id.to_string(),
                received_cluster: neighbor_map.cluster_id.to_string(),
            });
        }
        self.expire_retained_neighbor_maps();

        if neighbor_map.topology_epoch != self.neighbor_map.topology_epoch {
            let incoming_epoch = neighbor_map.topology_epoch;
            self.retained_neighbor_maps
                .retain(|retained| retained.neighbor_map.topology_epoch != incoming_epoch);

            let retained_neighbor_map = std::mem::replace(&mut self.neighbor_map, neighbor_map);
            let retained_neighbor_ids = std::mem::replace(&mut self.neighbor_ids, neighbor_ids);
            let retained_epoch = retained_neighbor_map.topology_epoch;
            self.retained_neighbor_maps
                .retain(|retained| retained.neighbor_map.topology_epoch != retained_epoch);
            self.retained_neighbor_maps.push_back(RetainedNeighborMap {
                neighbor_map: retained_neighbor_map,
                neighbor_ids: retained_neighbor_ids,
                expires_at: Instant::now() + PREVIOUS_TOPOLOGY_EPOCH_GRACE,
            });
            while self.retained_neighbor_maps.len() > MAX_RETAINED_TOPOLOGY_EPOCHS {
                self.retained_neighbor_maps.pop_front();
            }
            self.retain_replay_epochs();
            return Ok(());
        }
        self.neighbor_map = neighbor_map;
        self.neighbor_ids = neighbor_ids;
        Ok(())
    }

    /// Encapsulate over the primary path. This is the default initial route.
    pub fn encapsulate(
        &mut self,
        path: &OverlayPath,
        path_id: [u8; MULTIHOP_PATH_ID_BYTES],
        sequence: u64,
        inner_wireguard_datagram: Vec<u8>,
    ) -> Result<OverlayForwardAction, OverlayForwarderError> {
        self.encapsulate_selected(
            path,
            OverlayPathSelection::Primary,
            path_id,
            sequence,
            inner_wireguard_datagram,
        )
    }

    /// Encapsulate over a caller-selected path. Selecting `Secondary` is the
    /// failover operation; the secondary path is fully validated before use.
    pub fn encapsulate_selected(
        &mut self,
        path: &OverlayPath,
        selection: OverlayPathSelection,
        path_id: [u8; MULTIHOP_PATH_ID_BYTES],
        sequence: u64,
        inner_wireguard_datagram: Vec<u8>,
    ) -> Result<OverlayForwardAction, OverlayForwarderError> {
        self.validate_inner_datagram(&inner_wireguard_datagram)?;
        if path_id.iter().all(|byte| *byte == 0) {
            return Err(OverlayForwarderError::InvalidPathId);
        }

        let topology_epoch = path.topology_epoch;
        let ordered_nodes = self.validate_selected_path(path, selection)?;
        let next_hop = ordered_nodes
            .get(1)
            .cloned()
            .ok_or_else(|| OverlayForwarderError::PathTargetsSource(self.local_node.clone()))?;
        self.require_next_neighbor(&next_hop, topology_epoch)?;

        if ordered_nodes.len() == 2 {
            self.replay_window
                .observe(topology_epoch, &self.local_node, path_id, sequence)?;
            return Ok(OverlayForwardAction::DirectNeighbor {
                peer: next_hop,
                datagram: inner_wireguard_datagram,
            });
        }

        let relay_nodes = ordered_nodes[1..ordered_nodes.len() - 1].to_vec();
        self.validate_relay_count(relay_nodes.len())?;
        let hop_limit = relay_nodes.len() as u16;
        let envelope = MultiHopEnvelope::new(
            topology_epoch,
            path_id,
            sequence,
            hop_limit,
            self.local_node.clone(),
            path.target.node_id.clone(),
            relay_nodes,
            inner_wireguard_datagram,
        )?;
        let datagram = envelope.encode()?;
        self.validate_frame_size(datagram.len())?;
        self.replay_window
            .observe(topology_epoch, &self.local_node, path_id, sequence)?;
        Ok(OverlayForwardAction::Forward { next_hop, datagram })
    }

    /// Process one frame received from an authenticated adjacent peer.
    pub fn receive(
        &mut self,
        previous_hop: &NodeId,
        datagram: &[u8],
    ) -> Result<OverlayForwardAction, OverlayForwarderError> {
        self.validate_frame_size(datagram.len())?;
        let mut envelope = MultiHopEnvelope::decode(datagram, 1)?;
        let topology_epoch = envelope.topology_epoch();
        self.validate_inbound_topology_epoch(topology_epoch)?;
        self.validate_envelope_hop_limit(&envelope)?;

        if envelope.is_route_complete() {
            return self.deliver(previous_hop, envelope, topology_epoch);
        }

        let expected_local = envelope
            .next_hop()
            .cloned()
            .ok_or(MultiHopCodecError::UnexpectedHop)?;
        if expected_local != self.local_node {
            return Err(OverlayForwarderError::UnexpectedLocalHop {
                expected: expected_local,
                actual: self.local_node.clone(),
            });
        }

        let hop_index = usize::from(envelope.hop_index());
        let expected_previous = if hop_index == 0 {
            envelope.source().clone()
        } else {
            envelope
                .path()
                .get(hop_index - 1)
                .cloned()
                .ok_or(MultiHopCodecError::UnexpectedHop)?
        };
        self.validate_previous_hop(previous_hop, &expected_previous, topology_epoch)?;

        envelope.advance_hop(&self.local_node, topology_epoch)?;
        let next_hop = envelope
            .next_hop()
            .cloned()
            .unwrap_or_else(|| envelope.destination().clone());
        self.require_next_neighbor(&next_hop, topology_epoch)?;

        let source = envelope.source().clone();
        let path_id = *envelope.path_id();
        let sequence = envelope.sequence();
        let forwarded = envelope.encode()?;
        self.validate_frame_size(forwarded.len())?;
        self.replay_window
            .observe(topology_epoch, &source, path_id, sequence)?;
        Ok(OverlayForwardAction::Forward {
            next_hop,
            datagram: forwarded,
        })
    }

    fn deliver(
        &mut self,
        previous_hop: &NodeId,
        envelope: MultiHopEnvelope,
        topology_epoch: u64,
    ) -> Result<OverlayForwardAction, OverlayForwarderError> {
        if envelope.destination() != &self.local_node {
            return Err(OverlayForwarderError::UnexpectedDestination {
                expected: envelope.destination().clone(),
                actual: self.local_node.clone(),
            });
        }
        let expected_previous = envelope
            .path()
            .last()
            .cloned()
            .ok_or(MultiHopCodecError::InvalidPath)?;
        self.validate_previous_hop(previous_hop, &expected_previous, topology_epoch)?;

        let source = envelope.source().clone();
        let path_id = *envelope.path_id();
        let sequence = envelope.sequence();
        let payload = envelope.payload_for_destination(&self.local_node)?.to_vec();
        self.replay_window
            .observe(topology_epoch, &source, path_id, sequence)?;
        Ok(OverlayForwardAction::Deliver { source, payload })
    }

    fn validate_selected_path<'a>(
        &mut self,
        path: &'a OverlayPath,
        selection: OverlayPathSelection,
    ) -> Result<&'a [NodeId], OverlayForwarderError> {
        path.validate()
            .map_err(|error| OverlayForwarderError::InvalidOverlayPath(error.to_string()))?;
        self.validate_topology_epoch(path.topology_epoch)?;
        if path.source != self.local_node {
            return Err(OverlayForwarderError::PathSourceMismatch {
                local_node: self.local_node.clone(),
                path_source: path.source.clone(),
            });
        }
        if path.target.cluster_id != self.neighbor_map.cluster_id {
            return Err(OverlayForwarderError::PathClusterMismatch {
                local_cluster: self.neighbor_map.cluster_id.to_string(),
                target_cluster: path.target.cluster_id.to_string(),
            });
        }
        if path.target.node_id == self.local_node {
            return Err(OverlayForwarderError::PathTargetsSource(
                self.local_node.clone(),
            ));
        }

        let ordered_nodes = match selection {
            OverlayPathSelection::Primary => path.ordered_nodes.as_slice(),
            OverlayPathSelection::Secondary => path
                .secondary_ordered_nodes
                .as_deref()
                .ok_or(OverlayForwarderError::SecondaryPathUnavailable)?,
        };
        let relay_count = ordered_nodes.len().saturating_sub(2);
        if relay_count > 0 {
            self.validate_relay_count(relay_count)?;
        }
        Ok(ordered_nodes)
    }

    fn validate_topology_epoch(
        &mut self,
        received_epoch: u64,
    ) -> Result<(), OverlayForwarderError> {
        self.expire_retained_neighbor_maps();
        let current_epoch = self.neighbor_map.topology_epoch;
        // Epochs are opaque hashes; membership is the only valid freshness test.
        if self.neighbor_ids_for_epoch(received_epoch).is_some() {
            return Ok(());
        }
        Err(OverlayForwarderError::StaleTopologyEpoch {
            current_epoch,
            received_epoch,
        })
    }

    fn validate_inbound_topology_epoch(
        &mut self,
        received_epoch: u64,
    ) -> Result<(), OverlayForwarderError> {
        self.validate_topology_epoch(received_epoch)
    }

    fn expire_retained_neighbor_maps(&mut self) {
        let now = Instant::now();
        let previous_len = self.retained_neighbor_maps.len();
        self.retained_neighbor_maps
            .retain(|retained| now < retained.expires_at);
        if self.retained_neighbor_maps.len() != previous_len {
            self.retain_replay_epochs();
        }
    }

    fn retain_replay_epochs(&mut self) {
        let mut retained_epochs =
            HashSet::with_capacity(self.retained_neighbor_maps.len().saturating_add(1));
        retained_epochs.insert(self.neighbor_map.topology_epoch);
        retained_epochs.extend(
            self.retained_neighbor_maps
                .iter()
                .map(|retained| retained.neighbor_map.topology_epoch),
        );
        self.replay_window.retain_epochs(&retained_epochs);
    }

    fn neighbor_ids_for_epoch(&self, topology_epoch: u64) -> Option<&BTreeSet<NodeId>> {
        if topology_epoch == self.neighbor_map.topology_epoch {
            return Some(&self.neighbor_ids);
        }
        self.retained_neighbor_maps
            .iter()
            .find(|retained| retained.neighbor_map.topology_epoch == topology_epoch)
            .map(|retained| &retained.neighbor_ids)
    }

    fn validate_envelope_hop_limit(
        &self,
        envelope: &MultiHopEnvelope,
    ) -> Result<(), OverlayForwarderError> {
        self.validate_relay_count(envelope.path().len())?;
        let expected = envelope.path().len() as u16;
        if envelope.hop_limit() != expected {
            return Err(OverlayForwarderError::InvalidHopLimit {
                expected,
                actual: envelope.hop_limit(),
            });
        }
        Ok(())
    }

    fn validate_relay_count(&self, relay_count: usize) -> Result<(), OverlayForwarderError> {
        if relay_count > usize::from(self.config.max_relay_hops) {
            return Err(OverlayForwarderError::RelayPathTooLong {
                actual: relay_count,
                maximum: self.config.max_relay_hops,
            });
        }
        Ok(())
    }

    fn validate_previous_hop(
        &self,
        actual: &NodeId,
        expected: &NodeId,
        topology_epoch: u64,
    ) -> Result<(), OverlayForwarderError> {
        if actual != expected {
            return Err(OverlayForwarderError::PreviousHopMismatch {
                expected: expected.clone(),
                actual: actual.clone(),
            });
        }
        if !self
            .neighbor_ids_for_epoch(topology_epoch)
            .is_some_and(|neighbor_ids| neighbor_ids.contains(expected))
        {
            return Err(OverlayForwarderError::PreviousHopNotNeighbor(
                expected.clone(),
            ));
        }
        Ok(())
    }

    fn require_next_neighbor(
        &self,
        next_hop: &NodeId,
        topology_epoch: u64,
    ) -> Result<(), OverlayForwarderError> {
        if !self
            .neighbor_ids_for_epoch(topology_epoch)
            .is_some_and(|neighbor_ids| neighbor_ids.contains(next_hop))
        {
            return Err(OverlayForwarderError::NextHopNotNeighbor(next_hop.clone()));
        }
        Ok(())
    }

    fn validate_inner_datagram(&self, datagram: &[u8]) -> Result<(), OverlayForwarderError> {
        if datagram.is_empty() {
            return Err(OverlayForwarderError::EmptyInnerDatagram);
        }
        let maximum = self.config.max_frame_bytes.min(MAX_MULTIHOP_PAYLOAD_BYTES);
        if datagram.len() > maximum {
            return Err(OverlayForwarderError::InnerDatagramTooLarge { maximum });
        }
        Ok(())
    }

    fn validate_frame_size(&self, actual: usize) -> Result<(), OverlayForwarderError> {
        if actual > self.config.max_frame_bytes {
            return Err(OverlayForwarderError::FrameTooLarge {
                actual,
                maximum: self.config.max_frame_bytes,
            });
        }
        Ok(())
    }
}

fn validate_neighbor_map(
    local_node: &NodeId,
    neighbor_map: &NeighborMap,
) -> Result<BTreeSet<NodeId>, OverlayForwarderError> {
    neighbor_map
        .validate()
        .map_err(|error| OverlayForwarderError::InvalidNeighborMap(error.to_string()))?;
    if neighbor_map.node_id != *local_node {
        return Err(OverlayForwarderError::NeighborMapNodeMismatch {
            local_node: local_node.clone(),
            map_node: neighbor_map.node_id.clone(),
        });
    }
    if neighbor_map.topology_epoch == 0 {
        return Err(OverlayForwarderError::ZeroTopologyEpoch);
    }
    Ok(neighbor_map
        .neighbors
        .iter()
        .map(|neighbor| neighbor.node.node_id.clone())
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReplayPathKey {
    topology_epoch: u64,
    source: NodeId,
    path_id: [u8; MULTIHOP_PATH_ID_BYTES],
}

struct ReplayWindow {
    capacity: usize,
    sequences: HashMap<ReplayPathKey, ReplaySequenceWindow>,
    recency: VecDeque<(ReplayPathKey, u64)>,
}

#[derive(Debug, Clone, Copy)]
struct ReplaySequenceWindow {
    highest: u64,
    seen: [u64; OVERLAY_REPLAY_SEQUENCE_WINDOW_WORDS],
}

impl ReplaySequenceWindow {
    fn new(highest: u64) -> Self {
        let mut seen = [0; OVERLAY_REPLAY_SEQUENCE_WINDOW_WORDS];
        seen[0] = 1;
        Self { highest, seen }
    }

    fn advance_to(&mut self, sequence: u64) {
        let advance = sequence - self.highest;
        if advance >= OVERLAY_REPLAY_SEQUENCE_WINDOW_BITS as u64 {
            self.seen.fill(0);
        } else {
            self.shift_older(advance as usize);
        }
        self.highest = sequence;
        self.seen[0] |= 1;
    }

    fn shift_older(&mut self, distance: usize) {
        let previous = self.seen;
        self.seen.fill(0);
        let word_shift = distance / u64::BITS as usize;
        let bit_shift = distance % u64::BITS as usize;

        for (source_index, word) in previous.into_iter().enumerate() {
            let target_index = source_index + word_shift;
            if target_index >= self.seen.len() {
                break;
            }
            self.seen[target_index] |= word << bit_shift;
            if bit_shift > 0 && target_index + 1 < self.seen.len() {
                self.seen[target_index + 1] |= word >> (u64::BITS as usize - bit_shift);
            }
        }
    }

    fn contains(&self, distance: usize) -> bool {
        let word_index = distance / u64::BITS as usize;
        let bit_index = distance % u64::BITS as usize;
        self.seen[word_index] & (1_u64 << bit_index) != 0
    }

    fn insert(&mut self, distance: usize) {
        let word_index = distance / u64::BITS as usize;
        let bit_index = distance % u64::BITS as usize;
        self.seen[word_index] |= 1_u64 << bit_index;
    }
}

impl ReplayWindow {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            sequences: HashMap::with_capacity(capacity),
            recency: VecDeque::with_capacity(capacity),
        }
    }

    fn len(&self) -> usize {
        self.sequences.len()
    }

    fn observe(
        &mut self,
        topology_epoch: u64,
        source: &NodeId,
        path_id: [u8; MULTIHOP_PATH_ID_BYTES],
        sequence: u64,
    ) -> Result<(), OverlayForwarderError> {
        let key = ReplayPathKey {
            topology_epoch,
            source: source.clone(),
            path_id,
        };
        let recency_sequence = match self.sequences.get_mut(&key) {
            Some(window) if sequence > window.highest => {
                window.advance_to(sequence);
                Some(window.highest)
            }
            Some(window) => {
                let distance = window.highest - sequence;
                if distance >= OVERLAY_REPLAY_SEQUENCE_WINDOW_BITS as u64 {
                    return Err(OverlayForwarderError::ReplayRejected {
                        source_node: source.clone(),
                        sequence,
                        highest: window.highest,
                    });
                }
                let distance = distance as usize;
                if window.contains(distance) {
                    return Err(OverlayForwarderError::ReplayRejected {
                        source_node: source.clone(),
                        sequence,
                        highest: window.highest,
                    });
                }
                window.insert(distance);
                None
            }
            None => {
                self.sequences
                    .insert(key.clone(), ReplaySequenceWindow::new(sequence));
                Some(sequence)
            }
        };

        if let Some(recency_sequence) = recency_sequence {
            if self.recency.len() >= self.capacity.saturating_mul(2) {
                self.compact_recency();
            }
            self.recency.push_back((key, recency_sequence));
        }
        self.evict_to_capacity();
        Ok(())
    }

    fn retain_epochs(&mut self, retained_epochs: &HashSet<u64>) {
        self.sequences
            .retain(|key, _| retained_epochs.contains(&key.topology_epoch));
        self.compact_recency();
    }

    fn evict_to_capacity(&mut self) {
        while self.sequences.len() > self.capacity {
            let Some((key, observed_sequence)) = self.recency.pop_front() else {
                break;
            };
            if self
                .sequences
                .get(&key)
                .is_some_and(|window| window.highest == observed_sequence)
            {
                self.sequences.remove(&key);
            }
        }
    }

    fn compact_recency(&mut self) {
        self.recency.retain(|(key, observed_sequence)| {
            self.sequences
                .get(key)
                .is_some_and(|window| window.highest == *observed_sequence)
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashSet};
    use std::error::Error;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    use chrono::Utc;
    use ipars_relay::multihop::{MultiHopCodecError, MultiHopEnvelope};
    use ipars_types::{
        ClusterId, NeighborMap, NodeId, NodeRecord, OverlayNeighbor, OverlayNeighborKind,
        OverlayPath, Role, TokenPolicy, VpnIp,
    };

    use super::{
        BoundedOverlayForwarder, OverlayForwardAction, OverlayForwarderConfig,
        OverlayForwarderError, OverlayPathSelection, ReplaySequenceWindow, ReplayWindow,
        MAX_RETAINED_TOPOLOGY_EPOCHS, OVERLAY_PEER_MAX_IN_FLIGHT_DATAGRAMS,
        OVERLAY_REPLAY_SEQUENCE_WINDOW_BITS, OVERLAY_REPLAY_SEQUENCE_WINDOW_WORDS,
        OVERLAY_SEQUENCE_RESERVATIONS_PER_DATAGRAM,
    };

    type TestResult = Result<(), Box<dyn Error>>;

    fn node(value: &str) -> NodeId {
        NodeId::from_string(value)
    }

    fn node_octet(value: &str) -> u8 {
        match value {
            "s" => 1,
            "a" => 2,
            "b" => 3,
            "c" => 4,
            "e" => 5,
            "d" => 6,
            "x" => 7,
            _ => 254,
        }
    }

    fn node_record(value: &str) -> NodeRecord {
        NodeRecord {
            node_id: node(value),
            display_name: None,
            hostname: None,
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(10, 250, 0, node_octet(value)))),
            identity_public_key: format!("identity-{value}"),
            wireguard_public_key: format!("wireguard-{value}"),
            role: Role::edge(),
            tags: BTreeSet::new(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        }
    }

    fn neighbor_map(local: &str, neighbors: &[&str], topology_epoch: u64) -> NeighborMap {
        NeighborMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            node_id: node(local),
            topology_epoch,
            routing_epoch: topology_epoch,
            max_degree: neighbors.len() as u16,
            on_demand_peer_limit: 4,
            vpn_cidr: match "10.250.0.0/24".parse() {
                Ok(cidr) => cidr,
                Err(error) => panic!("static test VPN CIDR must parse: {error}"),
            },
            neighbors: neighbors
                .iter()
                .map(|neighbor| OverlayNeighbor {
                    node: node_record(neighbor),
                    kind: OverlayNeighborKind::BackbonePrimary,
                })
                .collect(),
            pinned_peers: Vec::new(),
            aggregate_routes: Vec::new(),
            client_route_peers: Vec::new(),
            bootstrap_endpoints: Vec::new(),
            generated_at: Utc::now(),
        }
    }

    fn engine(
        local: &str,
        neighbors: &[&str],
        topology_epoch: u64,
    ) -> Result<BoundedOverlayForwarder, OverlayForwarderError> {
        BoundedOverlayForwarder::new(
            node(local),
            neighbor_map(local, neighbors, topology_epoch),
            OverlayForwarderConfig::default(),
        )
    }

    fn overlay_path(
        primary: &[&str],
        secondary: Option<&[&str]>,
        topology_epoch: u64,
    ) -> OverlayPath {
        let target = node_record(primary[primary.len() - 1]);
        OverlayPath {
            topology_epoch,
            routing_epoch: topology_epoch,
            source: node(primary[0]),
            destination: target.vpn_ip.0,
            target,
            ordered_nodes: primary.iter().map(|value| node(value)).collect(),
            secondary_ordered_nodes: secondary
                .map(|nodes| nodes.iter().map(|value| node(value)).collect()),
            generated_at: Utc::now(),
        }
    }

    fn forwarded(action: OverlayForwardAction, expected_next_hop: &str) -> Vec<u8> {
        match action {
            OverlayForwardAction::Forward { next_hop, datagram } => {
                assert_eq!(next_hop, node(expected_next_hop));
                datagram
            }
            other => panic!("expected forward action, got {other:?}"),
        }
    }

    #[test]
    fn forwards_three_hops_and_delivers_only_at_destination() -> TestResult {
        let path = overlay_path(&["s", "a", "b", "d"], None, 7);
        let payload = vec![0x04, 0x88, 0x13, 0x37];
        let mut source = engine("s", &["a"], 7)?;
        let mut relay_a = engine("a", &["s", "b"], 7)?;
        let mut relay_b = engine("b", &["a", "d"], 7)?;
        let mut destination = engine("d", &["b"], 7)?;

        let to_a = forwarded(source.encapsulate(&path, [1; 16], 1, payload.clone())?, "a");
        let to_b = forwarded(relay_a.receive(&node("s"), &to_a)?, "b");
        let to_destination = forwarded(relay_b.receive(&node("a"), &to_b)?, "d");

        assert_eq!(
            destination.receive(&node("b"), &to_destination)?,
            OverlayForwardAction::Deliver {
                source: node("s"),
                payload,
            }
        );
        Ok(())
    }

    #[test]
    fn rejects_wrong_previous_hop_identity() -> TestResult {
        let path = overlay_path(&["s", "a", "d"], None, 7);
        let mut source = engine("s", &["a"], 7)?;
        let mut relay = engine("a", &["s", "d", "x"], 7)?;
        let to_a = forwarded(source.encapsulate(&path, [2; 16], 1, vec![1])?, "a");

        assert!(matches!(
            relay.receive(&node("x"), &to_a),
            Err(OverlayForwarderError::PreviousHopMismatch {
                expected,
                actual,
            }) if expected == node("s") && actual == node("x")
        ));
        Ok(())
    }

    #[test]
    fn rejects_unknown_topology_epoch_without_ordering_opaque_hashes() -> TestResult {
        let path = overlay_path(&["s", "a", "d"], None, 99);
        let mut source = engine("s", &["a"], 99)?;
        let mut relay = engine("a", &["s", "d"], 7)?;
        let to_a = forwarded(source.encapsulate(&path, [3; 16], 1, vec![1])?, "a");

        assert_eq!(
            relay.receive(&node("s"), &to_a),
            Err(OverlayForwarderError::StaleTopologyEpoch {
                current_epoch: 7,
                received_epoch: 99,
            })
        );
        Ok(())
    }

    #[test]
    fn retains_multiple_unexpired_epochs_and_their_replay_state() -> TestResult {
        let epoch_one = 0xf123_4567_89ab_cdef;
        let epoch_two = 7;
        let epoch_three = 0x1234_5678_9abc_def0;
        let path_id = [0x33; 16];
        let path_one = overlay_path(&["s", "a", "d"], None, epoch_one);
        let mut source_one = engine("s", &["a"], epoch_one)?;
        let epoch_one_first =
            forwarded(source_one.encapsulate(&path_one, path_id, 1, vec![1])?, "a");
        let epoch_one_second =
            forwarded(source_one.encapsulate(&path_one, path_id, 2, vec![2])?, "a");
        let mut relay = engine("a", &["s", "d"], epoch_one)?;
        let _ = relay.receive(&node("s"), &epoch_one_first)?;

        relay.update_neighbor_map(neighbor_map("a", &["x", "d"], epoch_two))?;
        let path_two = overlay_path(&["x", "a", "d"], None, epoch_two);
        let mut source_two = engine("x", &["a"], epoch_two)?;
        let epoch_two_first =
            forwarded(source_two.encapsulate(&path_two, path_id, 1, vec![3])?, "a");
        let epoch_two_second =
            forwarded(source_two.encapsulate(&path_two, path_id, 2, vec![4])?, "a");
        let _ = relay.receive(&node("x"), &epoch_two_first)?;

        relay.update_neighbor_map(neighbor_map("a", &["c", "d"], epoch_three))?;
        let path_three = overlay_path(&["c", "a", "d"], None, epoch_three);
        let mut source_three = engine("c", &["a"], epoch_three)?;
        let epoch_three_first = forwarded(
            source_three.encapsulate(&path_three, path_id, 1, vec![5])?,
            "a",
        );
        let _ = relay.receive(&node("c"), &epoch_three_first)?;

        let retained_epochs: HashSet<_> = relay
            .retained_neighbor_maps
            .iter()
            .map(|retained| retained.neighbor_map.topology_epoch)
            .collect();
        assert_eq!(retained_epochs, HashSet::from([epoch_one, epoch_two]));

        assert!(matches!(
            relay.receive(&node("s"), &epoch_one_first),
            Err(OverlayForwarderError::ReplayRejected {
                sequence: 1,
                highest: 1,
                ..
            })
        ));
        assert!(matches!(
            relay.receive(&node("x"), &epoch_two_first),
            Err(OverlayForwarderError::ReplayRejected {
                sequence: 1,
                highest: 1,
                ..
            })
        ));
        assert!(matches!(
            relay.receive(&node("c"), &epoch_three_first),
            Err(OverlayForwarderError::ReplayRejected {
                sequence: 1,
                highest: 1,
                ..
            })
        ));

        let forwarded_epoch_one = forwarded(relay.receive(&node("s"), &epoch_one_second)?, "d");
        assert_eq!(
            MultiHopEnvelope::decode(&forwarded_epoch_one, 1)?.topology_epoch(),
            epoch_one
        );
        let forwarded_epoch_two = forwarded(relay.receive(&node("x"), &epoch_two_second)?, "d");
        assert_eq!(
            MultiHopEnvelope::decode(&forwarded_epoch_two, 1)?.topology_epoch(),
            epoch_two
        );
        Ok(())
    }

    #[test]
    fn outbound_paths_can_finish_on_retained_epochs_with_epoch_local_validation() -> TestResult {
        let epoch_one = 0xfedc_ba98_7654_3210;
        let epoch_two = 3;
        let epoch_three = 0x0123_4567_89ab_cdef;
        let mut source = engine("s", &["a"], epoch_one)?;

        source.update_neighbor_map(neighbor_map("s", &["b"], epoch_two))?;
        source.update_neighbor_map(neighbor_map("s", &["c"], epoch_three))?;

        let retained_path = overlay_path(&["s", "a", "d"], None, epoch_one);
        let retained_datagram = forwarded(
            source.encapsulate(&retained_path, [0x34; 16], 1, vec![1])?,
            "a",
        );
        assert_eq!(
            MultiHopEnvelope::decode(&retained_datagram, 1)?.topology_epoch(),
            epoch_one
        );

        let cross_epoch_path = overlay_path(&["s", "b", "d"], None, epoch_one);
        assert_eq!(
            source.encapsulate(&cross_epoch_path, [0x35; 16], 1, vec![1]),
            Err(OverlayForwarderError::NextHopNotNeighbor(node("b")))
        );
        Ok(())
    }

    #[test]
    fn deduplicates_epochs_when_a_retained_epoch_becomes_current_again() -> TestResult {
        let epoch_one = 0x9000_0000_0000_0001;
        let epoch_two = 2;
        let epoch_three = 0x8000_0000_0000_0003;
        let mut forwarder = engine("a", &["s", "d"], epoch_one)?;

        forwarder.update_neighbor_map(neighbor_map("a", &["x", "d"], epoch_two))?;
        forwarder.update_neighbor_map(neighbor_map("a", &["c", "d"], epoch_three))?;
        forwarder.update_neighbor_map(neighbor_map("a", &["x", "d"], epoch_two))?;
        forwarder.update_neighbor_map(neighbor_map("a", &["x", "d"], epoch_two))?;

        assert_eq!(forwarder.neighbor_map.topology_epoch, epoch_two);
        let retained_epochs: Vec<_> = forwarder
            .retained_neighbor_maps
            .iter()
            .map(|retained| retained.neighbor_map.topology_epoch)
            .collect();
        assert_eq!(retained_epochs.len(), 2);
        assert_eq!(
            retained_epochs.iter().copied().collect::<HashSet<_>>(),
            HashSet::from([epoch_one, epoch_three])
        );
        assert!(!retained_epochs.contains(&epoch_two));
        Ok(())
    }

    #[test]
    fn expires_each_retained_epoch_and_only_its_replay_state() -> TestResult {
        let epoch_one = 0x7000_0000_0000_0001;
        let epoch_two = 2;
        let epoch_three = 0x6000_0000_0000_0003;
        let replay_source = node("s");
        let mut forwarder = engine("a", &["s", "d"], epoch_one)?;
        forwarder
            .replay_window
            .observe(epoch_one, &replay_source, [0x36; 16], 1)?;

        forwarder.update_neighbor_map(neighbor_map("a", &["x", "d"], epoch_two))?;
        forwarder
            .replay_window
            .observe(epoch_two, &replay_source, [0x37; 16], 1)?;
        forwarder.update_neighbor_map(neighbor_map("a", &["c", "d"], epoch_three))?;
        forwarder
            .replay_window
            .observe(epoch_three, &replay_source, [0x38; 16], 1)?;

        let retained_epoch_one = forwarder
            .retained_neighbor_maps
            .iter_mut()
            .find(|retained| retained.neighbor_map.topology_epoch == epoch_one);
        match retained_epoch_one {
            Some(retained) => retained.expires_at = Instant::now(),
            None => panic!("first topology epoch must be retained"),
        }
        forwarder.expire_retained_neighbor_maps();

        let retained_epochs: HashSet<_> = forwarder
            .retained_neighbor_maps
            .iter()
            .map(|retained| retained.neighbor_map.topology_epoch)
            .collect();
        assert_eq!(retained_epochs, HashSet::from([epoch_two]));
        let replay_epochs: HashSet<_> = forwarder
            .replay_window
            .sequences
            .keys()
            .map(|key| key.topology_epoch)
            .collect();
        assert_eq!(replay_epochs, HashSet::from([epoch_two, epoch_three]));
        assert_eq!(
            forwarder.validate_topology_epoch(epoch_one),
            Err(OverlayForwarderError::StaleTopologyEpoch {
                current_epoch: epoch_three,
                received_epoch: epoch_one,
            })
        );
        assert_eq!(forwarder.validate_topology_epoch(epoch_two), Ok(()));
        Ok(())
    }

    #[test]
    fn migration_history_and_replay_epochs_stay_within_the_same_bound() -> TestResult {
        let epochs: Vec<_> = (1..=MAX_RETAINED_TOPOLOGY_EPOCHS + 3)
            .map(|index| (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
            .collect();
        let replay_source = node("s");
        let mut forwarder = engine("a", &["s", "d"], epochs[0])?;

        for (index, next_epoch) in epochs.iter().copied().enumerate().skip(1) {
            let current_epoch = forwarder.neighbor_map.topology_epoch;
            forwarder
                .replay_window
                .observe(current_epoch, &replay_source, [index as u8; 16], 1)?;
            forwarder.update_neighbor_map(neighbor_map("a", &["s", "d"], next_epoch))?;
        }
        forwarder.replay_window.observe(
            forwarder.neighbor_map.topology_epoch,
            &replay_source,
            [0xff; 16],
            1,
        )?;

        assert_eq!(
            forwarder.retained_neighbor_maps.len(),
            MAX_RETAINED_TOPOLOGY_EPOCHS
        );
        let expected_retained =
            &epochs[epochs.len() - MAX_RETAINED_TOPOLOGY_EPOCHS - 1..epochs.len() - 1];
        let retained_epochs: Vec<_> = forwarder
            .retained_neighbor_maps
            .iter()
            .map(|retained| retained.neighbor_map.topology_epoch)
            .collect();
        assert_eq!(retained_epochs, expected_retained);

        let expected_replay_epochs: HashSet<_> = expected_retained
            .iter()
            .copied()
            .chain(std::iter::once(epochs[epochs.len() - 1]))
            .collect();
        let replay_epochs: HashSet<_> = forwarder
            .replay_window
            .sequences
            .keys()
            .map(|key| key.topology_epoch)
            .collect();
        assert_eq!(replay_epochs, expected_replay_epochs);
        Ok(())
    }

    #[test]
    fn rejects_duplicates_but_accepts_bounded_reordering() -> TestResult {
        let path = overlay_path(&["s", "a", "d"], None, 7);
        let path_id = [4; 16];
        let mut source = engine("s", &["a"], 7)?;
        let mut relay = engine("a", &["s", "d"], 7)?;
        let sequence_ten = forwarded(source.encapsulate(&path, path_id, 10, vec![1])?, "a");

        let _ = relay.receive(&node("s"), &sequence_ten)?;
        assert!(matches!(
            relay.receive(&node("s"), &sequence_ten),
            Err(OverlayForwarderError::ReplayRejected {
                sequence: 10,
                highest: 10,
                ..
            })
        ));

        let mut restarted_source = engine("s", &["a"], 7)?;
        let sequence_nine = forwarded(
            restarted_source.encapsulate(&path, path_id, 9, vec![2])?,
            "a",
        );
        assert!(matches!(
            relay.receive(&node("s"), &sequence_nine),
            Ok(OverlayForwardAction::Forward { .. })
        ));
        assert!(matches!(
            relay.receive(&node("s"), &sequence_nine),
            Err(OverlayForwarderError::ReplayRejected {
                sequence: 9,
                highest: 10,
                ..
            })
        ));

        let sequence_eleven = forwarded(
            restarted_source.encapsulate(&path, path_id, 11, vec![3])?,
            "a",
        );
        assert!(matches!(
            relay.receive(&node("s"), &sequence_eleven),
            Ok(OverlayForwardAction::Forward { .. })
        ));
        Ok(())
    }

    #[test]
    fn replay_window_covers_the_full_proxy_in_flight_sequence_span() -> TestResult {
        let in_flight_sequence_span =
            OVERLAY_PEER_MAX_IN_FLIGHT_DATAGRAMS * OVERLAY_SEQUENCE_RESERVATIONS_PER_DATAGRAM;
        assert_eq!(OVERLAY_REPLAY_SEQUENCE_WINDOW_BITS, 1_024);
        assert!(OVERLAY_REPLAY_SEQUENCE_WINDOW_BITS >= in_flight_sequence_span);
        assert_eq!(
            std::mem::size_of::<ReplaySequenceWindow>(),
            (OVERLAY_REPLAY_SEQUENCE_WINDOW_WORDS + 1) * std::mem::size_of::<u64>()
        );

        let source = node("s");
        let latest_in_flight = (in_flight_sequence_span - 1) as u64;
        let mut replay = ReplayWindow::new(4);

        replay.observe(7, &source, [0x41; 16], latest_in_flight)?;
        replay.observe(7, &source, [0x41; 16], 0)?;
        assert!(matches!(
            replay.observe(7, &source, [0x41; 16], 0),
            Err(OverlayForwarderError::ReplayRejected {
                sequence: 0,
                highest,
                ..
            }) if highest == latest_in_flight
        ));

        replay.observe(7, &source, [0x42; 16], 0)?;
        replay.observe(7, &source, [0x42; 16], latest_in_flight)?;
        assert!(matches!(
            replay.observe(7, &source, [0x42; 16], 0),
            Err(OverlayForwarderError::ReplayRejected {
                sequence: 0,
                highest,
                ..
            }) if highest == latest_in_flight
        ));

        replay.observe(
            7,
            &source,
            [0x43; 16],
            OVERLAY_REPLAY_SEQUENCE_WINDOW_BITS as u64,
        )?;
        replay.observe(7, &source, [0x43; 16], 1)?;
        assert!(matches!(
            replay.observe(7, &source, [0x43; 16], 0),
            Err(OverlayForwarderError::ReplayRejected {
                sequence: 0,
                highest,
                ..
            }) if highest == OVERLAY_REPLAY_SEQUENCE_WINDOW_BITS as u64
        ));
        Ok(())
    }

    #[test]
    fn rejects_non_neighbor_next_hop() -> TestResult {
        let path = overlay_path(&["s", "a", "b", "d"], None, 7);
        let mut source = engine("s", &["a"], 7)?;
        let mut relay = engine("a", &["s"], 7)?;
        let to_a = forwarded(source.encapsulate(&path, [5; 16], 1, vec![1])?, "a");

        assert_eq!(
            relay.receive(&node("s"), &to_a),
            Err(OverlayForwarderError::NextHopNotNeighbor(node("b")))
        );
        Ok(())
    }

    #[test]
    fn caller_can_fail_over_to_validated_secondary_path() -> TestResult {
        let path = overlay_path(&["s", "a", "d"], Some(&["s", "c", "d"]), 7);
        let path_id = [6; 16];
        let mut source = engine("s", &["a", "c"], 7)?;

        let primary = source.encapsulate(&path, path_id, 1, vec![1])?;
        assert!(matches!(
            primary,
            OverlayForwardAction::Forward { next_hop, .. } if next_hop == node("a")
        ));

        let to_c = forwarded(
            source.encapsulate_selected(
                &path,
                OverlayPathSelection::Secondary,
                path_id,
                2,
                vec![2],
            )?,
            "c",
        );
        let mut relay_c = engine("c", &["s", "d"], 7)?;
        let mut destination = engine("d", &["c"], 7)?;
        let to_destination = forwarded(relay_c.receive(&node("s"), &to_c)?, "d");
        assert_eq!(
            destination.receive(&node("c"), &to_destination)?,
            OverlayForwardAction::Deliver {
                source: node("s"),
                payload: vec![2],
            }
        );
        Ok(())
    }

    #[test]
    fn intermediate_action_keeps_payload_opaque() -> TestResult {
        let path = overlay_path(&["s", "a", "d"], None, 7);
        let payload = vec![0, 0xff, 0x42, 0, 0x13, 0x37];
        let mut source = engine("s", &["a"], 7)?;
        let mut relay = engine("a", &["s", "d"], 7)?;
        let to_a = forwarded(source.encapsulate(&path, [7; 16], 1, payload.clone())?, "a");
        let to_destination = forwarded(relay.receive(&node("s"), &to_a)?, "d");

        let forwarded_envelope = MultiHopEnvelope::decode(&to_destination, 7)?;
        assert!(forwarded_envelope.is_route_complete());
        assert_eq!(forwarded_envelope.opaque_payload_len(), payload.len());
        assert_eq!(
            forwarded_envelope.payload_for_destination(&node("a")),
            Err(MultiHopCodecError::PayloadUnavailable)
        );
        Ok(())
    }

    #[test]
    fn direct_path_returns_explicit_direct_neighbor_action() -> TestResult {
        let path = overlay_path(&["s", "d"], None, 7);
        let payload = vec![1, 2, 3];
        let mut source = engine("s", &["d"], 7)?;

        assert_eq!(
            source.encapsulate(&path, [8; 16], 1, payload.clone())?,
            OverlayForwardAction::DirectNeighbor {
                peer: node("d"),
                datagram: payload,
            }
        );
        Ok(())
    }

    #[test]
    fn enforces_exact_ttl_budget() -> TestResult {
        let envelope = MultiHopEnvelope::new(
            7,
            [9; 16],
            1,
            2,
            node("s"),
            node("d"),
            vec![node("a")],
            vec![1],
        )?;
        let mut relay = engine("a", &["s", "d"], 7)?;

        assert_eq!(
            relay.receive(&node("s"), &envelope.encode()?),
            Err(OverlayForwarderError::InvalidHopLimit {
                expected: 1,
                actual: 2,
            })
        );
        Ok(())
    }

    #[test]
    fn replay_cache_stays_within_configured_bound() -> TestResult {
        let config = OverlayForwarderConfig {
            replay_cache_capacity: 2,
            ..OverlayForwarderConfig::default()
        };
        let path = overlay_path(&["s", "a", "d"], None, 7);
        let mut source = engine("s", &["a"], 7)?;
        let mut relay =
            BoundedOverlayForwarder::new(node("a"), neighbor_map("a", &["s", "d"], 7), config)?;

        for path_byte in 1_u8..=8 {
            let to_a = forwarded(
                source.encapsulate(&path, [path_byte; 16], 1, vec![path_byte])?,
                "a",
            );
            let _ = relay.receive(&node("s"), &to_a)?;
            assert!(relay.replay_cache_len() <= 2);
        }
        assert_eq!(relay.replay_cache_len(), 2);
        Ok(())
    }
}
