//! Versioned framing for end-to-end encrypted datagrams forwarded by relays.
//!
//! The route metadata is visible to relays, but `opaque_payload` is never
//! interpreted by this codec. The containing relay transport must authenticate
//! the metadata; the payload is intended to remain an inner WireGuard datagram.

use ipars_types::NodeId;
use thiserror::Error;

pub const MULTIHOP_FRAME_VERSION: u8 = 1;
pub const MULTIHOP_PATH_ID_BYTES: usize = 16;
pub const MAX_MULTIHOP_NODE_ID_BYTES: usize = 128;
pub const MAX_MULTIHOP_PATH_NODES: usize = 32;
pub const MAX_MULTIHOP_PAYLOAD_BYTES: usize = 65_000;
pub const MAX_MULTIHOP_FRAME_BYTES: usize = 65_507;

const MULTIHOP_FRAME_MAGIC: &[u8; 8] = b"IPARS-MH";
const VERSION_OFFSET: usize = MULTIHOP_FRAME_MAGIC.len();
const FLAGS_OFFSET: usize = VERSION_OFFSET + 1;
const TOPOLOGY_EPOCH_OFFSET: usize = FLAGS_OFFSET + 1;
const PATH_ID_OFFSET: usize = TOPOLOGY_EPOCH_OFFSET + 8;
const SEQUENCE_OFFSET: usize = PATH_ID_OFFSET + MULTIHOP_PATH_ID_BYTES;
const HOP_INDEX_OFFSET: usize = SEQUENCE_OFFSET + 8;
const HOP_LIMIT_OFFSET: usize = HOP_INDEX_OFFSET + 1;
const PATH_COUNT_OFFSET: usize = HOP_LIMIT_OFFSET + 1;
const RESERVED_OFFSET: usize = PATH_COUNT_OFFSET + 1;
const SOURCE_LENGTH_OFFSET: usize = RESERVED_OFFSET + 1;
const DESTINATION_LENGTH_OFFSET: usize = SOURCE_LENGTH_OFFSET + 2;
const PAYLOAD_LENGTH_OFFSET: usize = DESTINATION_LENGTH_OFFSET + 2;
const FIXED_HEADER_BYTES: usize = PAYLOAD_LENGTH_OFFSET + 4;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MultiHopCodecError {
    #[error("malformed multi-hop frame")]
    MalformedFrame,
    #[error("unsupported multi-hop frame version {0}")]
    UnsupportedVersion(u8),
    #[error("non-canonical multi-hop frame")]
    NonCanonicalFrame,
    #[error("multi-hop frame contains trailing bytes")]
    TrailingBytes,
    #[error("multi-hop frame exceeds a size limit")]
    FrameTooLarge,
    #[error("invalid multi-hop node id")]
    InvalidNodeId,
    #[error("invalid multi-hop path")]
    InvalidPath,
    #[error("multi-hop path exceeds its node limit")]
    PathTooLong,
    #[error("multi-hop path id is invalid")]
    InvalidPathId,
    #[error("multi-hop frame has expired")]
    ExpiredFrame,
    #[error("multi-hop topology epoch is stale")]
    StaleTopologyEpoch,
    #[error("multi-hop path contains or attempted a loop")]
    LoopDetected,
    #[error("frame arrived at an unexpected forwarding node")]
    UnexpectedHop,
    #[error("multi-hop route is already complete")]
    RouteComplete,
    #[error("opaque payload is unavailable at this node")]
    PayloadUnavailable,
}

/// A validated V1 multi-hop envelope.
///
/// `path` contains relay nodes only, in forwarding order. `hop_index` is the
/// number of path entries already consumed. A complete envelope has
/// `hop_index == path.len()` and may expose its payload only to `destination`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiHopEnvelope {
    topology_epoch: u64,
    path_id: [u8; MULTIHOP_PATH_ID_BYTES],
    sequence: u64,
    hop_index: u8,
    hop_limit: u8,
    source: NodeId,
    destination: NodeId,
    path: Vec<NodeId>,
    opaque_payload: Vec<u8>,
}

impl MultiHopEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        topology_epoch: u64,
        path_id: [u8; MULTIHOP_PATH_ID_BYTES],
        sequence: u64,
        hop_limit: u8,
        source: NodeId,
        destination: NodeId,
        path: Vec<NodeId>,
        opaque_payload: Vec<u8>,
    ) -> Result<Self, MultiHopCodecError> {
        let envelope = Self {
            topology_epoch,
            path_id,
            sequence,
            hop_index: 0,
            hop_limit,
            source,
            destination,
            path,
            opaque_payload,
        };
        envelope.validate(1)?;
        Ok(envelope)
    }

    /// Decode one canonical frame and reject topology epochs older than
    /// `minimum_topology_epoch`.
    pub fn decode(frame: &[u8], minimum_topology_epoch: u64) -> Result<Self, MultiHopCodecError> {
        if frame.len() > MAX_MULTIHOP_FRAME_BYTES {
            return Err(MultiHopCodecError::FrameTooLarge);
        }
        if frame.len() < FIXED_HEADER_BYTES {
            return Err(MultiHopCodecError::MalformedFrame);
        }

        let mut reader = FrameReader::new(frame);
        if reader.take(MULTIHOP_FRAME_MAGIC.len())? != MULTIHOP_FRAME_MAGIC {
            return Err(MultiHopCodecError::MalformedFrame);
        }

        let version = reader.read_u8()?;
        if version != MULTIHOP_FRAME_VERSION {
            return Err(MultiHopCodecError::UnsupportedVersion(version));
        }
        if reader.read_u8()? != 0 {
            return Err(MultiHopCodecError::NonCanonicalFrame);
        }

        let topology_epoch = reader.read_u64()?;
        let mut path_id = [0_u8; MULTIHOP_PATH_ID_BYTES];
        path_id.copy_from_slice(reader.take(MULTIHOP_PATH_ID_BYTES)?);
        let sequence = reader.read_u64()?;
        let hop_index = reader.read_u8()?;
        let hop_limit = reader.read_u8()?;
        let path_count = usize::from(reader.read_u8()?);
        if reader.read_u8()? != 0 {
            return Err(MultiHopCodecError::NonCanonicalFrame);
        }

        let source_len = usize::from(reader.read_u16()?);
        let destination_len = usize::from(reader.read_u16()?);
        let payload_len =
            usize::try_from(reader.read_u32()?).map_err(|_| MultiHopCodecError::FrameTooLarge)?;

        validate_declared_node_length(source_len)?;
        validate_declared_node_length(destination_len)?;
        if path_count == 0 {
            return Err(MultiHopCodecError::InvalidPath);
        }
        if path_count > MAX_MULTIHOP_PATH_NODES {
            return Err(MultiHopCodecError::PathTooLong);
        }
        if payload_len == 0 {
            return Err(MultiHopCodecError::MalformedFrame);
        }
        if payload_len > MAX_MULTIHOP_PAYLOAD_BYTES {
            return Err(MultiHopCodecError::FrameTooLarge);
        }

        let source = decode_node_id(reader.take(source_len)?)?;
        let destination = decode_node_id(reader.take(destination_len)?)?;
        let mut path = Vec::with_capacity(path_count);
        for _ in 0..path_count {
            let node_len = usize::from(reader.read_u16()?);
            validate_declared_node_length(node_len)?;
            path.push(decode_node_id(reader.take(node_len)?)?);
        }
        let opaque_payload = reader.take(payload_len)?.to_vec();
        if !reader.is_complete() {
            return Err(MultiHopCodecError::TrailingBytes);
        }

        let envelope = Self {
            topology_epoch,
            path_id,
            sequence,
            hop_index,
            hop_limit,
            source,
            destination,
            path,
            opaque_payload,
        };
        envelope.validate(minimum_topology_epoch)?;
        Ok(envelope)
    }

    /// Encode the envelope using the only canonical V1 representation.
    pub fn encode(&self) -> Result<Vec<u8>, MultiHopCodecError> {
        let encoded_len = self.validate(1)?;
        let mut frame = Vec::with_capacity(encoded_len);
        frame.extend_from_slice(MULTIHOP_FRAME_MAGIC);
        frame.push(MULTIHOP_FRAME_VERSION);
        frame.push(0);
        frame.extend_from_slice(&self.topology_epoch.to_be_bytes());
        frame.extend_from_slice(&self.path_id);
        frame.extend_from_slice(&self.sequence.to_be_bytes());
        frame.push(self.hop_index);
        frame.push(self.hop_limit);
        frame.push(self.path.len() as u8);
        frame.push(0);
        frame.extend_from_slice(&(self.source.as_str().len() as u16).to_be_bytes());
        frame.extend_from_slice(&(self.destination.as_str().len() as u16).to_be_bytes());
        frame.extend_from_slice(&(self.opaque_payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(self.source.as_str().as_bytes());
        frame.extend_from_slice(self.destination.as_str().as_bytes());
        for node in &self.path {
            frame.extend_from_slice(&(node.as_str().len() as u16).to_be_bytes());
            frame.extend_from_slice(node.as_str().as_bytes());
        }
        frame.extend_from_slice(&self.opaque_payload);
        debug_assert_eq!(frame.len(), encoded_len);
        Ok(frame)
    }

    /// Consume the current relay hop without returning or interpreting payload.
    ///
    /// A forwarding node must match the next path entry. Re-entering a node
    /// already consumed by this frame is reported as a loop.
    pub fn advance_hop(
        &mut self,
        forwarding_node: &NodeId,
        minimum_topology_epoch: u64,
    ) -> Result<(), MultiHopCodecError> {
        self.validate(minimum_topology_epoch)?;
        let current_index = usize::from(self.hop_index);
        if current_index >= self.path.len() {
            return Err(MultiHopCodecError::RouteComplete);
        }
        if self.hop_index >= self.hop_limit {
            return Err(MultiHopCodecError::ExpiredFrame);
        }

        if self.path.get(current_index) != Some(forwarding_node) {
            if forwarding_node == &self.source
                || forwarding_node == &self.destination
                || self.path[..current_index].contains(forwarding_node)
            {
                return Err(MultiHopCodecError::LoopDetected);
            }
            return Err(MultiHopCodecError::UnexpectedHop);
        }

        let next_index = self
            .hop_index
            .checked_add(1)
            .ok_or(MultiHopCodecError::ExpiredFrame)?;
        if next_index > self.hop_limit {
            return Err(MultiHopCodecError::ExpiredFrame);
        }
        self.hop_index = next_index;
        Ok(())
    }

    pub fn topology_epoch(&self) -> u64 {
        self.topology_epoch
    }

    pub fn path_id(&self) -> &[u8; MULTIHOP_PATH_ID_BYTES] {
        &self.path_id
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn hop_index(&self) -> u8 {
        self.hop_index
    }

    pub fn hop_limit(&self) -> u8 {
        self.hop_limit
    }

    pub fn source(&self) -> &NodeId {
        &self.source
    }

    pub fn destination(&self) -> &NodeId {
        &self.destination
    }

    pub fn path(&self) -> &[NodeId] {
        &self.path
    }

    pub fn next_hop(&self) -> Option<&NodeId> {
        self.path.get(usize::from(self.hop_index))
    }

    pub fn remaining_hops(&self) -> usize {
        self.path.len().saturating_sub(usize::from(self.hop_index))
    }

    pub fn is_route_complete(&self) -> bool {
        usize::from(self.hop_index) == self.path.len()
    }

    pub fn opaque_payload_len(&self) -> usize {
        self.opaque_payload.len()
    }

    /// Return the inner datagram only after the complete path reaches its
    /// declared destination.
    pub fn payload_for_destination(
        &self,
        local_node: &NodeId,
    ) -> Result<&[u8], MultiHopCodecError> {
        if local_node != &self.destination || !self.is_route_complete() {
            return Err(MultiHopCodecError::PayloadUnavailable);
        }
        Ok(&self.opaque_payload)
    }

    /// Consume the envelope and return the inner datagram only at destination.
    pub fn into_payload_for_destination(
        self,
        local_node: &NodeId,
    ) -> Result<Vec<u8>, MultiHopCodecError> {
        if local_node != &self.destination || !self.is_route_complete() {
            return Err(MultiHopCodecError::PayloadUnavailable);
        }
        Ok(self.opaque_payload)
    }

    fn validate(&self, minimum_topology_epoch: u64) -> Result<usize, MultiHopCodecError> {
        if self.topology_epoch == 0 || self.topology_epoch < minimum_topology_epoch {
            return Err(MultiHopCodecError::StaleTopologyEpoch);
        }
        if self.path_id.iter().all(|byte| *byte == 0) {
            return Err(MultiHopCodecError::InvalidPathId);
        }

        validate_node_id(&self.source)?;
        validate_node_id(&self.destination)?;
        if self.source == self.destination {
            return Err(MultiHopCodecError::LoopDetected);
        }

        if self.path.is_empty() {
            return Err(MultiHopCodecError::InvalidPath);
        }
        if self.path.len() > MAX_MULTIHOP_PATH_NODES {
            return Err(MultiHopCodecError::PathTooLong);
        }
        if self.hop_limit == 0 || usize::from(self.hop_limit) > MAX_MULTIHOP_PATH_NODES {
            return Err(MultiHopCodecError::InvalidPath);
        }
        if self.path.len() > usize::from(self.hop_limit) || self.hop_index > self.hop_limit {
            return Err(MultiHopCodecError::ExpiredFrame);
        }
        if usize::from(self.hop_index) > self.path.len() {
            return Err(MultiHopCodecError::MalformedFrame);
        }

        for (index, node) in self.path.iter().enumerate() {
            validate_node_id(node)?;
            if node == &self.source
                || node == &self.destination
                || self.path[..index].contains(node)
            {
                return Err(MultiHopCodecError::LoopDetected);
            }
        }

        if self.opaque_payload.is_empty() {
            return Err(MultiHopCodecError::MalformedFrame);
        }
        if self.opaque_payload.len() > MAX_MULTIHOP_PAYLOAD_BYTES {
            return Err(MultiHopCodecError::FrameTooLarge);
        }

        let mut encoded_len = FIXED_HEADER_BYTES
            .checked_add(self.source.as_str().len())
            .and_then(|len| len.checked_add(self.destination.as_str().len()))
            .ok_or(MultiHopCodecError::FrameTooLarge)?;
        for node in &self.path {
            encoded_len = encoded_len
                .checked_add(2)
                .and_then(|len| len.checked_add(node.as_str().len()))
                .ok_or(MultiHopCodecError::FrameTooLarge)?;
        }
        encoded_len = encoded_len
            .checked_add(self.opaque_payload.len())
            .ok_or(MultiHopCodecError::FrameTooLarge)?;
        if encoded_len > MAX_MULTIHOP_FRAME_BYTES {
            return Err(MultiHopCodecError::FrameTooLarge);
        }
        Ok(encoded_len)
    }
}

fn validate_declared_node_length(node_len: usize) -> Result<(), MultiHopCodecError> {
    if node_len == 0 {
        return Err(MultiHopCodecError::InvalidNodeId);
    }
    if node_len > MAX_MULTIHOP_NODE_ID_BYTES {
        return Err(MultiHopCodecError::FrameTooLarge);
    }
    Ok(())
}

fn validate_node_id(node_id: &NodeId) -> Result<(), MultiHopCodecError> {
    let node_id = node_id.as_str();
    validate_declared_node_length(node_id.len())?;
    if matches!(node_id, "." | "..")
        || node_id.starts_with('-')
        || !node_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(MultiHopCodecError::InvalidNodeId);
    }
    Ok(())
}

fn decode_node_id(bytes: &[u8]) -> Result<NodeId, MultiHopCodecError> {
    let node_id = std::str::from_utf8(bytes).map_err(|_| MultiHopCodecError::MalformedFrame)?;
    let node_id = NodeId::from_string(node_id);
    validate_node_id(&node_id)?;
    Ok(node_id)
}

struct FrameReader<'a> {
    frame: &'a [u8],
    offset: usize,
}

impl<'a> FrameReader<'a> {
    fn new(frame: &'a [u8]) -> Self {
        Self { frame, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], MultiHopCodecError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(MultiHopCodecError::MalformedFrame)?;
        let bytes = self
            .frame
            .get(self.offset..end)
            .ok_or(MultiHopCodecError::MalformedFrame)?;
        self.offset = end;
        Ok(bytes)
    }

    fn read_u8(&mut self) -> Result<u8, MultiHopCodecError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(MultiHopCodecError::MalformedFrame)
    }

    fn read_u16(&mut self) -> Result<u16, MultiHopCodecError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, MultiHopCodecError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, MultiHopCodecError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn is_complete(&self) -> bool {
        self.offset == self.frame.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(value: &str) -> NodeId {
        NodeId::from_string(value)
    }

    fn path_id() -> [u8; MULTIHOP_PATH_ID_BYTES] {
        [0x11; MULTIHOP_PATH_ID_BYTES]
    }

    fn sample_envelope(payload: Vec<u8>) -> Result<MultiHopEnvelope, MultiHopCodecError> {
        MultiHopEnvelope::new(
            7,
            path_id(),
            42,
            4,
            node("source"),
            node("destination"),
            vec![node("relay-a"), node("relay-b")],
            payload,
        )
    }

    #[test]
    fn v1_encoding_is_canonical_and_round_trips() -> Result<(), MultiHopCodecError> {
        let envelope = MultiHopEnvelope::new(
            1,
            path_id(),
            2,
            1,
            node("s"),
            node("d"),
            vec![node("r")],
            vec![0xaa, 0xbb],
        )?;
        let encoded = envelope.encode()?;

        let mut expected = Vec::new();
        expected.extend_from_slice(b"IPARS-MH");
        expected.extend_from_slice(&[1, 0]);
        expected.extend_from_slice(&1_u64.to_be_bytes());
        expected.extend_from_slice(&path_id());
        expected.extend_from_slice(&2_u64.to_be_bytes());
        expected.extend_from_slice(&[0, 1, 1, 0]);
        expected.extend_from_slice(&1_u16.to_be_bytes());
        expected.extend_from_slice(&1_u16.to_be_bytes());
        expected.extend_from_slice(&2_u32.to_be_bytes());
        expected.extend_from_slice(b"s");
        expected.extend_from_slice(b"d");
        expected.extend_from_slice(&1_u16.to_be_bytes());
        expected.extend_from_slice(b"r");
        expected.extend_from_slice(&[0xaa, 0xbb]);

        assert_eq!(encoded, expected);
        assert_eq!(MultiHopEnvelope::decode(&encoded, 1)?, envelope);
        Ok(())
    }

    #[test]
    fn payload_remains_opaque_until_destination() -> Result<(), MultiHopCodecError> {
        let payload = vec![0, 0xff, 4, 0, 0x88, 0x44, 0x13, 0x37];
        let mut envelope = sample_envelope(payload.clone())?;
        assert_eq!(envelope.opaque_payload_len(), payload.len());
        assert!(matches!(
            envelope.payload_for_destination(&node("destination")),
            Err(MultiHopCodecError::PayloadUnavailable)
        ));

        envelope.advance_hop(&node("relay-a"), 7)?;
        assert_eq!(envelope.opaque_payload, payload);
        assert_eq!(envelope.hop_index(), 1);
        envelope.advance_hop(&node("relay-b"), 7)?;
        assert!(envelope.is_route_complete());
        assert_eq!(
            envelope.payload_for_destination(&node("destination"))?,
            payload
        );
        assert!(matches!(
            envelope.payload_for_destination(&node("relay-b")),
            Err(MultiHopCodecError::PayloadUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn advance_hop_rejects_wrong_repeated_and_complete_routes() -> Result<(), MultiHopCodecError> {
        let mut envelope = sample_envelope(vec![1, 2, 3])?;
        assert!(matches!(
            envelope.advance_hop(&node("relay-z"), 7),
            Err(MultiHopCodecError::UnexpectedHop)
        ));
        envelope.advance_hop(&node("relay-a"), 7)?;
        assert!(matches!(
            envelope.advance_hop(&node("relay-a"), 7),
            Err(MultiHopCodecError::LoopDetected)
        ));
        envelope.advance_hop(&node("relay-b"), 7)?;
        assert!(matches!(
            envelope.advance_hop(&node("relay-b"), 7),
            Err(MultiHopCodecError::RouteComplete)
        ));
        Ok(())
    }

    #[test]
    fn stale_and_expired_frames_are_rejected() -> Result<(), MultiHopCodecError> {
        let encoded = sample_envelope(vec![1, 2, 3])?.encode()?;
        assert!(matches!(
            MultiHopEnvelope::decode(&encoded, 8),
            Err(MultiHopCodecError::StaleTopologyEpoch)
        ));

        let mut exhausted = encoded.clone();
        exhausted[HOP_LIMIT_OFFSET] = 1;
        assert!(matches!(
            MultiHopEnvelope::decode(&exhausted, 7),
            Err(MultiHopCodecError::ExpiredFrame)
        ));

        let mut invalid_index = encoded;
        invalid_index[HOP_INDEX_OFFSET] = 5;
        assert!(matches!(
            MultiHopEnvelope::decode(&invalid_index, 7),
            Err(MultiHopCodecError::ExpiredFrame)
        ));
        Ok(())
    }

    #[test]
    fn complete_frame_is_deliverable_but_not_forwardable() -> Result<(), MultiHopCodecError> {
        let payload = vec![9, 8, 7];
        let mut envelope = MultiHopEnvelope::new(
            3,
            path_id(),
            u64::MAX,
            1,
            node("source"),
            node("destination"),
            vec![node("relay")],
            payload.clone(),
        )?;
        envelope.advance_hop(&node("relay"), 3)?;
        let encoded = envelope.encode()?;
        let decoded = MultiHopEnvelope::decode(&encoded, 3)?;

        assert!(decoded.is_route_complete());
        assert_eq!(
            decoded.payload_for_destination(&node("destination"))?,
            payload
        );
        Ok(())
    }

    #[test]
    fn looping_paths_are_rejected_on_construction_and_decode() -> Result<(), MultiHopCodecError> {
        for path in [
            vec![node("source")],
            vec![node("destination")],
            vec![node("relay-a"), node("relay-a")],
        ] {
            let result = MultiHopEnvelope::new(
                1,
                path_id(),
                1,
                4,
                node("source"),
                node("destination"),
                path,
                vec![1],
            );
            assert!(matches!(result, Err(MultiHopCodecError::LoopDetected)));
        }

        let same_endpoint = MultiHopEnvelope::new(
            1,
            path_id(),
            1,
            4,
            node("same"),
            node("same"),
            vec![node("relay")],
            vec![1],
        );
        assert!(matches!(
            same_endpoint,
            Err(MultiHopCodecError::LoopDetected)
        ));

        let mut encoded = sample_envelope(vec![1])?.encode()?;
        let path_start = FIXED_HEADER_BYTES + "source".len() + "destination".len();
        let second_node_start = path_start + 2 + "relay-a".len() + 2;
        encoded[second_node_start..second_node_start + "relay-a".len()].copy_from_slice(b"relay-a");
        assert!(matches!(
            MultiHopEnvelope::decode(&encoded, 7),
            Err(MultiHopCodecError::LoopDetected)
        ));
        Ok(())
    }

    #[test]
    fn ids_path_and_payload_limits_are_enforced() -> Result<(), MultiHopCodecError> {
        let maximum_path = (0..MAX_MULTIHOP_PATH_NODES)
            .map(|index| node(&format!("relay-{index:02}")))
            .collect::<Vec<_>>();
        let maximum_payload = vec![0x5a; MAX_MULTIHOP_PAYLOAD_BYTES];
        let maximum = MultiHopEnvelope::new(
            1,
            path_id(),
            1,
            MAX_MULTIHOP_PATH_NODES as u8,
            node("s"),
            node("d"),
            maximum_path,
            maximum_payload,
        )?;
        let maximum_encoded = maximum.encode()?;
        assert!(maximum_encoded.len() <= MAX_MULTIHOP_FRAME_BYTES);
        assert_eq!(MultiHopEnvelope::decode(&maximum_encoded, 1)?, maximum);

        let too_many_hops = (0..=MAX_MULTIHOP_PATH_NODES)
            .map(|index| node(&format!("relay-{index:02}")))
            .collect();
        assert!(matches!(
            MultiHopEnvelope::new(
                1,
                path_id(),
                1,
                MAX_MULTIHOP_PATH_NODES as u8,
                node("s"),
                node("d"),
                too_many_hops,
                vec![1],
            ),
            Err(MultiHopCodecError::PathTooLong)
        ));
        assert!(matches!(
            MultiHopEnvelope::new(
                1,
                path_id(),
                1,
                1,
                node("s"),
                node("d"),
                vec![node("relay")],
                vec![0; MAX_MULTIHOP_PAYLOAD_BYTES + 1],
            ),
            Err(MultiHopCodecError::FrameTooLarge)
        ));
        assert!(matches!(
            MultiHopEnvelope::new(
                1,
                path_id(),
                1,
                1,
                node(&"s".repeat(MAX_MULTIHOP_NODE_ID_BYTES + 1)),
                node("d"),
                vec![node("relay")],
                vec![1],
            ),
            Err(MultiHopCodecError::FrameTooLarge)
        ));
        assert!(matches!(
            MultiHopEnvelope::new(
                1,
                [0; MULTIHOP_PATH_ID_BYTES],
                1,
                1,
                node("s"),
                node("d"),
                vec![node("relay")],
                vec![1],
            ),
            Err(MultiHopCodecError::InvalidPathId)
        ));
        Ok(())
    }

    #[test]
    fn invalid_node_ids_and_empty_fields_are_rejected() {
        for invalid in ["", ".", "..", "-node", "node/a", "node:a", "node a", "n\n"] {
            let result = MultiHopEnvelope::new(
                1,
                path_id(),
                1,
                1,
                node(invalid),
                node("destination"),
                vec![node("relay")],
                vec![1],
            );
            assert!(
                matches!(result, Err(MultiHopCodecError::InvalidNodeId)),
                "{invalid:?} should be rejected"
            );
        }

        assert!(matches!(
            MultiHopEnvelope::new(
                1,
                path_id(),
                1,
                1,
                node("source"),
                node("destination"),
                Vec::new(),
                vec![1],
            ),
            Err(MultiHopCodecError::InvalidPath)
        ));
        assert!(matches!(
            MultiHopEnvelope::new(
                1,
                path_id(),
                1,
                1,
                node("source"),
                node("destination"),
                vec![node("relay")],
                Vec::new(),
            ),
            Err(MultiHopCodecError::MalformedFrame)
        ));
    }

    #[test]
    fn malformed_versions_flags_lengths_and_trailing_bytes_are_rejected(
    ) -> Result<(), MultiHopCodecError> {
        let encoded = sample_envelope(vec![1, 2, 3, 4])?.encode()?;

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 0xff;
        assert!(matches!(
            MultiHopEnvelope::decode(&bad_magic, 1),
            Err(MultiHopCodecError::MalformedFrame)
        ));

        let mut bad_version = encoded.clone();
        bad_version[VERSION_OFFSET] = MULTIHOP_FRAME_VERSION + 1;
        assert!(matches!(
            MultiHopEnvelope::decode(&bad_version, 1),
            Err(MultiHopCodecError::UnsupportedVersion(2))
        ));

        for offset in [FLAGS_OFFSET, RESERVED_OFFSET] {
            let mut non_canonical = encoded.clone();
            non_canonical[offset] = 1;
            assert!(matches!(
                MultiHopEnvelope::decode(&non_canonical, 1),
                Err(MultiHopCodecError::NonCanonicalFrame)
            ));
        }

        let mut trailing = encoded.clone();
        trailing.extend_from_slice(&[0xde, 0xad]);
        assert!(matches!(
            MultiHopEnvelope::decode(&trailing, 1),
            Err(MultiHopCodecError::TrailingBytes)
        ));

        let mut oversized_source = encoded.clone();
        oversized_source[SOURCE_LENGTH_OFFSET..SOURCE_LENGTH_OFFSET + 2]
            .copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            MultiHopEnvelope::decode(&oversized_source, 1),
            Err(MultiHopCodecError::FrameTooLarge)
        ));

        let mut oversized_payload = encoded;
        oversized_payload[PAYLOAD_LENGTH_OFFSET..PAYLOAD_LENGTH_OFFSET + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            MultiHopEnvelope::decode(&oversized_payload, 1),
            Err(MultiHopCodecError::FrameTooLarge)
        ));
        Ok(())
    }

    #[test]
    fn invalid_utf8_and_noncanonical_node_bytes_are_rejected() -> Result<(), MultiHopCodecError> {
        let encoded = sample_envelope(vec![1])?.encode()?;

        let mut invalid_utf8 = encoded.clone();
        invalid_utf8[FIXED_HEADER_BYTES] = 0xff;
        assert!(matches!(
            MultiHopEnvelope::decode(&invalid_utf8, 1),
            Err(MultiHopCodecError::MalformedFrame)
        ));

        let mut unsafe_ascii = encoded;
        unsafe_ascii[FIXED_HEADER_BYTES] = b'/';
        assert!(matches!(
            MultiHopEnvelope::decode(&unsafe_ascii, 1),
            Err(MultiHopCodecError::InvalidNodeId)
        ));
        Ok(())
    }

    #[test]
    fn every_truncated_canonical_frame_is_rejected() -> Result<(), MultiHopCodecError> {
        let encoded = sample_envelope(vec![1, 2, 3, 4])?.encode()?;
        for end in 0..encoded.len() {
            assert!(
                MultiHopEnvelope::decode(&encoded[..end], 1).is_err(),
                "truncation at byte {end} was accepted"
            );
        }
        Ok(())
    }

    #[test]
    fn oversized_raw_frame_is_rejected_before_parsing() {
        let oversized = vec![0_u8; MAX_MULTIHOP_FRAME_BYTES + 1];
        assert!(matches!(
            MultiHopEnvelope::decode(&oversized, 0),
            Err(MultiHopCodecError::FrameTooLarge)
        ));
    }

    #[test]
    fn deterministic_mutation_sweep_never_accepts_noncanonical_bytes(
    ) -> Result<(), MultiHopCodecError> {
        let encoded = sample_envelope(vec![0, 1, 2, 3, 4, 0xff])?.encode()?;
        for index in 0..encoded.len() {
            for mask in [0x01_u8, 0x5a, 0xff] {
                let mut candidate = encoded.clone();
                candidate[index] ^= mask;
                if let Ok(decoded) = MultiHopEnvelope::decode(&candidate, 1) {
                    assert_eq!(decoded.encode()?, candidate);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn deterministic_random_inputs_never_panic_or_decode_noncanonically(
    ) -> Result<(), MultiHopCodecError> {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for iteration in 0..512_usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state as usize) % 2_048;
            let mut candidate = vec![0_u8; len];
            for byte in &mut candidate {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            if iteration % 3 == 0 && candidate.len() >= FIXED_HEADER_BYTES {
                candidate[..MULTIHOP_FRAME_MAGIC.len()].copy_from_slice(MULTIHOP_FRAME_MAGIC);
                candidate[VERSION_OFFSET] = MULTIHOP_FRAME_VERSION;
                candidate[FLAGS_OFFSET] = 0;
                candidate[RESERVED_OFFSET] = 0;
            }

            if let Ok(decoded) = MultiHopEnvelope::decode(&candidate, 0) {
                assert_eq!(decoded.encode()?, candidate);
            }
        }
        Ok(())
    }
}
