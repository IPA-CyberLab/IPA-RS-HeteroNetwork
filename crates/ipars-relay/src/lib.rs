use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use ipars_types::api::{
    RelayAdmissionFailureReason, RelayAdmissionRequest, RelayAdmissionResponse,
    RelayDataplaneDropReason, RelayDataplaneMetrics, RelayStatusResponse,
};
use ipars_types::{endpoint_addr_is_usable, HealthState, NodeId, RelayCapability};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{watch, RwLock};
use uuid::Uuid;

const DEFAULT_SESSION_TTL_SECONDS: i64 = 300;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("invalid relay admission request")]
    InvalidAdmissionRequest,
    #[error("relay admission denied")]
    AdmissionDenied,
    #[error("relay node session limit exceeded")]
    NodeSessionLimitExceeded,
    #[error("unknown relay session")]
    UnknownSession,
    #[error("relay session expired")]
    SessionExpired,
    #[error("invalid relay session credential")]
    InvalidSessionCredential,
    #[error("relay session rate limit exceeded")]
    RateLimited,
    #[error("malformed relay frame")]
    MalformedFrame,
    #[error("relay frame exceeds size limit")]
    FrameTooLarge,
    #[error("udp socket error: {0}")]
    Socket(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RelaySessionId(String);

impl RelaySessionId {
    pub fn new(left: &NodeId, right: &NodeId) -> Self {
        Self(format!("{left}:{right}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySession {
    pub id: RelaySessionId,
    pub session_token: String,
    pub left: NodeId,
    pub right: NodeId,
    pub left_addr: SocketAddr,
    pub right_addr: SocketAddr,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub bytes_forwarded: u64,
    window_started_at: DateTime<Utc>,
    window_bytes: u64,
    max_bytes_per_second: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySessionCredentials {
    pub session_id: RelaySessionId,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySessionAdmission {
    pub left: NodeId,
    pub right: NodeId,
    pub left_addr: SocketAddr,
    pub right_addr: SocketAddr,
    pub session_token: String,
    pub session_ttl: chrono::Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayAdmissionRateLimit {
    pub max_attempts: u32,
    pub window: chrono::Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFrame {
    pub session_id: RelaySessionId,
    pub session_token: String,
    pub source: NodeId,
    pub destination: NodeId,
    pub ciphertext_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayDatagram {
    session_id: RelaySessionId,
    session_token: String,
    source: Option<NodeId>,
    destination: Option<NodeId>,
    ciphertext_payload: Vec<u8>,
    endpoint_announcement: bool,
}

const RELAY_FRAME_MAGIC: &[u8] = b"IPARS-RLY1";
const RELAY_FRAME_MAGIC_V2: &[u8] = b"IPARS-RLY2";
const RELAY_FRAME_MAGIC_V3: &[u8] = b"IPARS-RLY3";
const MAX_RELAY_SESSION_ID_BYTES: usize = 4096;
const MAX_RELAY_SESSION_TOKEN_BYTES: usize = 256;
const MAX_RELAY_NODE_ID_BYTES: usize = 128;
const MAX_RELAY_CIPHERTEXT_PAYLOAD_BYTES: usize = 128 * 1024;

pub fn encode_relay_datagram(
    session_id: &str,
    session_token: &str,
    ciphertext_payload: &[u8],
) -> Result<Vec<u8>, RelayError> {
    if session_id.is_empty() || session_token.is_empty() || ciphertext_payload.is_empty() {
        return Err(RelayError::MalformedFrame);
    }
    validate_relay_frame_sizes(
        session_id.len(),
        session_token.len(),
        ciphertext_payload.len(),
    )?;

    let mut datagram = Vec::with_capacity(
        RELAY_FRAME_MAGIC.len()
            + 4
            + session_id.len()
            + session_token.len()
            + ciphertext_payload.len(),
    );
    datagram.extend_from_slice(RELAY_FRAME_MAGIC);
    datagram.extend_from_slice(&(session_id.len() as u16).to_be_bytes());
    datagram.extend_from_slice(&(session_token.len() as u16).to_be_bytes());
    datagram.extend_from_slice(session_id.as_bytes());
    datagram.extend_from_slice(session_token.as_bytes());
    datagram.extend_from_slice(ciphertext_payload);
    Ok(datagram)
}

pub fn encode_relay_datagram_with_route(
    session_id: &str,
    session_token: &str,
    source: &NodeId,
    destination: &NodeId,
    ciphertext_payload: &[u8],
) -> Result<Vec<u8>, RelayError> {
    if session_id.is_empty()
        || session_token.is_empty()
        || source.as_str().is_empty()
        || destination.as_str().is_empty()
        || ciphertext_payload.is_empty()
    {
        return Err(RelayError::MalformedFrame);
    }
    validate_relay_frame_sizes(
        session_id.len(),
        session_token.len(),
        ciphertext_payload.len(),
    )?;
    validate_relay_frame_node_id(source.as_str())?;
    validate_relay_frame_node_id(destination.as_str())?;

    let mut datagram = Vec::with_capacity(
        RELAY_FRAME_MAGIC_V2.len()
            + 8
            + session_id.len()
            + session_token.len()
            + source.as_str().len()
            + destination.as_str().len()
            + ciphertext_payload.len(),
    );
    datagram.extend_from_slice(RELAY_FRAME_MAGIC_V2);
    datagram.extend_from_slice(&(session_id.len() as u16).to_be_bytes());
    datagram.extend_from_slice(&(session_token.len() as u16).to_be_bytes());
    datagram.extend_from_slice(&(source.as_str().len() as u16).to_be_bytes());
    datagram.extend_from_slice(&(destination.as_str().len() as u16).to_be_bytes());
    datagram.extend_from_slice(session_id.as_bytes());
    datagram.extend_from_slice(session_token.as_bytes());
    datagram.extend_from_slice(source.as_str().as_bytes());
    datagram.extend_from_slice(destination.as_str().as_bytes());
    datagram.extend_from_slice(ciphertext_payload);
    Ok(datagram)
}

/// Encode an authenticated endpoint announcement without forwarding payload.
///
/// Relay forwarders bind an ephemeral UDP port, which may differ from the
/// endpoint advertised during registration. The relay learns that port from
/// the source address of this frame before normal WireGuard traffic starts.
pub fn encode_relay_endpoint_announcement(
    session_id: &str,
    session_token: &str,
    source: &NodeId,
    destination: &NodeId,
) -> Result<Vec<u8>, RelayError> {
    if session_id.is_empty()
        || session_token.is_empty()
        || source.as_str().is_empty()
        || destination.as_str().is_empty()
    {
        return Err(RelayError::MalformedFrame);
    }
    validate_relay_frame_sizes_allow_empty(session_id.len(), session_token.len(), 0)?;
    validate_relay_frame_node_id(source.as_str())?;
    validate_relay_frame_node_id(destination.as_str())?;

    let mut datagram = Vec::with_capacity(
        RELAY_FRAME_MAGIC_V3.len()
            + 8
            + session_id.len()
            + session_token.len()
            + source.as_str().len()
            + destination.as_str().len(),
    );
    datagram.extend_from_slice(RELAY_FRAME_MAGIC_V3);
    datagram.extend_from_slice(&(session_id.len() as u16).to_be_bytes());
    datagram.extend_from_slice(&(session_token.len() as u16).to_be_bytes());
    datagram.extend_from_slice(&(source.as_str().len() as u16).to_be_bytes());
    datagram.extend_from_slice(&(destination.as_str().len() as u16).to_be_bytes());
    datagram.extend_from_slice(session_id.as_bytes());
    datagram.extend_from_slice(session_token.as_bytes());
    datagram.extend_from_slice(source.as_str().as_bytes());
    datagram.extend_from_slice(destination.as_str().as_bytes());
    Ok(datagram)
}

#[derive(Debug, Default)]
pub struct RelayTable {
    sessions: BTreeMap<RelaySessionId, RelaySession>,
    dataplane: RelayDataplaneMetrics,
}

impl RelayTable {
    pub fn admit(
        &mut self,
        capability: &RelayCapability,
        left: NodeId,
        right: NodeId,
        left_addr: SocketAddr,
        right_addr: SocketAddr,
    ) -> Result<RelaySessionCredentials, RelayError> {
        self.admit_with_options(
            capability,
            RelaySessionAdmission {
                left,
                right,
                left_addr,
                right_addr,
                session_token: Uuid::new_v4().to_string(),
                session_ttl: default_session_ttl(),
            },
        )
    }

    pub fn admit_with_token(
        &mut self,
        capability: &RelayCapability,
        left: NodeId,
        right: NodeId,
        left_addr: SocketAddr,
        right_addr: SocketAddr,
        session_token: String,
    ) -> Result<RelaySessionCredentials, RelayError> {
        self.admit_with_options(
            capability,
            RelaySessionAdmission {
                left,
                right,
                left_addr,
                right_addr,
                session_token,
                session_ttl: default_session_ttl(),
            },
        )
    }

    pub fn admit_with_options(
        &mut self,
        capability: &RelayCapability,
        admission: RelaySessionAdmission,
    ) -> Result<RelaySessionCredentials, RelayError> {
        let now = Utc::now();
        self.purge_expired(now);

        let id = RelaySessionId::new(&admission.left, &admission.right);
        validate_relay_session_admission(&admission, &id)?;
        let expires_at = now + admission.session_ttl.max(chrono::Duration::milliseconds(1));
        if let Some(existing) = self.sessions.values_mut().find(|session| {
            (session.left == admission.left && session.right == admission.right)
                || (session.left == admission.right && session.right == admission.left)
        }) {
            if existing.left == admission.left {
                existing.left_addr = admission.left_addr;
                existing.right_addr = admission.right_addr;
            } else {
                existing.left_addr = admission.right_addr;
                existing.right_addr = admission.left_addr;
            }
            existing.expires_at = expires_at;
            existing.max_bytes_per_second = megabits_to_bytes_per_second(capability.max_mbps);
            return Ok(RelaySessionCredentials {
                session_id: existing.id.clone(),
                session_token: existing.session_token.clone(),
                expires_at,
            });
        }
        if !capability.can_admit() {
            return Err(RelayError::AdmissionDenied);
        }
        self.sessions.insert(
            id.clone(),
            RelaySession {
                id: id.clone(),
                session_token: admission.session_token.clone(),
                left: admission.left,
                right: admission.right,
                left_addr: admission.left_addr,
                right_addr: admission.right_addr,
                created_at: now,
                expires_at,
                bytes_forwarded: 0,
                window_started_at: now,
                window_bytes: 0,
                max_bytes_per_second: megabits_to_bytes_per_second(capability.max_mbps),
            },
        );
        Ok(RelaySessionCredentials {
            session_id: id,
            session_token: admission.session_token,
            expires_at,
        })
    }

    pub fn forward_target(&mut self, frame: &RelayFrame) -> Result<SocketAddr, RelayError> {
        self.forward_target_at(frame, Utc::now())
    }

    pub fn forward_target_at(
        &mut self,
        frame: &RelayFrame,
        now: DateTime<Utc>,
    ) -> Result<SocketAddr, RelayError> {
        self.dataplane
            .record_received(frame.ciphertext_payload.len());
        let result = self.forward_target_at_inner(frame, now);
        match result {
            Ok(target) => {
                self.dataplane
                    .record_forwarded(frame.ciphertext_payload.len());
                Ok(target)
            }
            Err(error) => {
                self.dataplane.record_drop(
                    relay_error_drop_reason(&error),
                    frame.ciphertext_payload.len(),
                );
                Err(error)
            }
        }
    }

    fn forward_target_at_inner(
        &mut self,
        frame: &RelayFrame,
        now: DateTime<Utc>,
    ) -> Result<SocketAddr, RelayError> {
        validate_relay_frame_sizes(
            frame.session_id.as_str().len(),
            frame.session_token.len(),
            frame.ciphertext_payload.len(),
        )?;
        self.remove_expired_session(&frame.session_id, now)?;
        let session = self
            .sessions
            .get_mut(&frame.session_id)
            .ok_or(RelayError::UnknownSession)?;
        session.verify_token(&frame.session_token)?;
        let target = if frame.source == session.left && frame.destination == session.right {
            session.right_addr
        } else if frame.source == session.right && frame.destination == session.left {
            session.left_addr
        } else {
            return Err(RelayError::UnknownSession);
        };

        session.consume_rate_limit(frame.ciphertext_payload.len(), now)?;
        session.bytes_forwarded = session
            .bytes_forwarded
            .saturating_add(frame.ciphertext_payload.len() as u64);
        Ok(target)
    }

    pub fn forward_datagram_for_addr(
        &mut self,
        source_addr: SocketAddr,
        datagram: &[u8],
    ) -> Result<(SocketAddr, Vec<u8>), RelayError> {
        self.forward_datagram_for_addr_at(source_addr, datagram, Utc::now())
    }

    pub fn forward_datagram_for_addr_at(
        &mut self,
        source_addr: SocketAddr,
        datagram: &[u8],
        now: DateTime<Utc>,
    ) -> Result<(SocketAddr, Vec<u8>), RelayError> {
        self.dataplane.record_received(datagram.len());
        let result = self.forward_datagram_for_addr_at_inner(source_addr, datagram, now);
        match result {
            Ok(forward) => {
                if forward.should_forward {
                    self.dataplane.record_forwarded(forward.payload.len());
                }
                Ok((forward.target, forward.payload))
            }
            Err(error) => {
                self.dataplane
                    .record_drop(relay_error_drop_reason(&error), datagram.len());
                Err(error)
            }
        }
    }

    fn forward_datagram_for_addr_at_inner(
        &mut self,
        source_addr: SocketAddr,
        datagram: &[u8],
        now: DateTime<Utc>,
    ) -> Result<RelayDatagramForward, RelayError> {
        let datagram = decode_relay_datagram(datagram)?;
        self.remove_expired_session(&datagram.session_id, now)?;
        let session = self
            .sessions
            .get_mut(&datagram.session_id)
            .ok_or(RelayError::UnknownSession)?;
        session.verify_token(&datagram.session_token)?;
        let target = match (datagram.source.as_ref(), datagram.destination.as_ref()) {
            (Some(source), Some(destination))
                if source == &session.left && destination == &session.right =>
            {
                session.left_addr = source_addr;
                session.right_addr
            }
            (Some(source), Some(destination))
                if source == &session.right && destination == &session.left =>
            {
                session.right_addr = source_addr;
                session.left_addr
            }
            (Some(_), Some(_)) => return Err(RelayError::UnknownSession),
            _ if session.left_addr == source_addr => session.right_addr,
            _ if session.right_addr == source_addr => session.left_addr,
            _ => return Err(RelayError::UnknownSession),
        };

        session.consume_rate_limit(datagram.ciphertext_payload.len(), now)?;
        session.bytes_forwarded = session
            .bytes_forwarded
            .saturating_add(datagram.ciphertext_payload.len() as u64);
        Ok(RelayDatagramForward {
            target,
            payload: datagram.ciphertext_payload,
            should_forward: !datagram.endpoint_announcement,
        })
    }

    pub fn purge_expired(&mut self, now: DateTime<Utc>) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|_, session| !session.is_expired(now));
        before.saturating_sub(self.sessions.len())
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn active_session_count_for_node(&self, node: &NodeId) -> usize {
        self.sessions
            .values()
            .filter(|session| session.left == *node || session.right == *node)
            .count()
    }

    pub fn bytes_forwarded(&self) -> u64 {
        self.dataplane.payload_bytes_forwarded
    }

    pub fn dataplane_metrics(&self) -> RelayDataplaneMetrics {
        self.dataplane.clone()
    }

    fn has_session_pair(&self, left: &NodeId, right: &NodeId) -> bool {
        self.sessions.values().any(|session| {
            (session.left == *left && session.right == *right)
                || (session.left == *right && session.right == *left)
        })
    }

    fn remove_expired_session(
        &mut self,
        session_id: &RelaySessionId,
        now: DateTime<Utc>,
    ) -> Result<(), RelayError> {
        let expired = self
            .sessions
            .get(session_id)
            .map(|session| session.is_expired(now))
            .unwrap_or(false);
        if expired {
            self.sessions.remove(session_id);
            return Err(RelayError::SessionExpired);
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RelayDatagramForward {
    target: SocketAddr,
    payload: Vec<u8>,
    should_forward: bool,
}

impl RelaySession {
    fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    fn verify_token(&self, session_token: &str) -> Result<(), RelayError> {
        if relay_session_token_matches(&self.session_token, session_token) {
            Ok(())
        } else {
            Err(RelayError::InvalidSessionCredential)
        }
    }

    fn consume_rate_limit(
        &mut self,
        payload_len: usize,
        now: DateTime<Utc>,
    ) -> Result<(), RelayError> {
        if now.signed_duration_since(self.window_started_at) >= chrono::Duration::seconds(1) {
            self.window_started_at = now;
            self.window_bytes = 0;
        }

        let payload_len = payload_len as u64;
        if self.window_bytes.saturating_add(payload_len) > self.max_bytes_per_second {
            return Err(RelayError::RateLimited);
        }
        self.window_bytes = self.window_bytes.saturating_add(payload_len);
        Ok(())
    }
}

fn megabits_to_bytes_per_second(max_mbps: u32) -> u64 {
    u64::from(max_mbps).saturating_mul(1_000_000) / 8
}

fn default_session_ttl() -> chrono::Duration {
    chrono::Duration::seconds(DEFAULT_SESSION_TTL_SECONDS)
}

fn relay_error_drop_reason(error: &RelayError) -> RelayDataplaneDropReason {
    match error {
        RelayError::InvalidAdmissionRequest => RelayDataplaneDropReason::AdmissionDenied,
        RelayError::AdmissionDenied => RelayDataplaneDropReason::AdmissionDenied,
        RelayError::NodeSessionLimitExceeded => RelayDataplaneDropReason::AdmissionDenied,
        RelayError::UnknownSession => RelayDataplaneDropReason::UnknownSession,
        RelayError::SessionExpired => RelayDataplaneDropReason::SessionExpired,
        RelayError::InvalidSessionCredential => RelayDataplaneDropReason::InvalidSessionCredential,
        RelayError::RateLimited => RelayDataplaneDropReason::RateLimited,
        RelayError::MalformedFrame => RelayDataplaneDropReason::MalformedFrame,
        RelayError::FrameTooLarge => RelayDataplaneDropReason::FrameTooLarge,
        RelayError::Socket(_) => RelayDataplaneDropReason::SocketError,
    }
}

fn relay_error_admission_failure_reason(error: &RelayError) -> RelayAdmissionFailureReason {
    match error {
        RelayError::InvalidAdmissionRequest => RelayAdmissionFailureReason::InvalidAdmissionRequest,
        RelayError::AdmissionDenied => RelayAdmissionFailureReason::AdmissionDenied,
        RelayError::NodeSessionLimitExceeded => {
            RelayAdmissionFailureReason::NodeSessionLimitExceeded
        }
        RelayError::RateLimited => RelayAdmissionFailureReason::RateLimited,
        RelayError::InvalidSessionCredential => {
            RelayAdmissionFailureReason::InvalidSessionCredential
        }
        RelayError::Socket(_) => RelayAdmissionFailureReason::SocketError,
        RelayError::UnknownSession
        | RelayError::SessionExpired
        | RelayError::MalformedFrame
        | RelayError::FrameTooLarge => RelayAdmissionFailureReason::InternalError,
    }
}

fn zero_filled_admission_failure_reasons(
    observed: BTreeMap<RelayAdmissionFailureReason, u64>,
) -> BTreeMap<RelayAdmissionFailureReason, u64> {
    RelayAdmissionFailureReason::ALL
        .into_iter()
        .map(|reason| (reason, observed.get(&reason).copied().unwrap_or_default()))
        .collect()
}

fn zero_filled_dataplane_metrics(mut metrics: RelayDataplaneMetrics) -> RelayDataplaneMetrics {
    let observed = metrics.drops_by_reason;
    metrics.drops_by_reason = RelayDataplaneDropReason::ALL
        .into_iter()
        .map(|reason| (reason, observed.get(&reason).copied().unwrap_or_default()))
        .collect();
    metrics
}

fn validate_relay_session_admission(
    admission: &RelaySessionAdmission,
    session_id: &RelaySessionId,
) -> Result<(), RelayError> {
    validate_relay_admission_node_id(&admission.left)?;
    validate_relay_admission_node_id(&admission.right)?;
    if admission.left == admission.right || admission.left_addr == admission.right_addr {
        return Err(RelayError::AdmissionDenied);
    }
    if !endpoint_addr_is_usable(admission.left_addr)
        || !endpoint_addr_is_usable(admission.right_addr)
    {
        return Err(RelayError::AdmissionDenied);
    }
    if session_id.as_str().len() > MAX_RELAY_SESSION_ID_BYTES {
        return Err(RelayError::AdmissionDenied);
    }
    if admission.session_token.is_empty()
        || admission.session_token.len() > MAX_RELAY_SESSION_TOKEN_BYTES
    {
        return Err(RelayError::InvalidSessionCredential);
    }
    Ok(())
}

fn validate_relay_admission_node_id(node_id: &NodeId) -> Result<(), RelayError> {
    if relay_node_id_is_valid(node_id.as_str()) {
        Ok(())
    } else {
        Err(RelayError::InvalidAdmissionRequest)
    }
}

fn validate_relay_frame_node_id(node_id: &str) -> Result<(), RelayError> {
    if relay_node_id_is_valid(node_id) {
        Ok(())
    } else {
        Err(RelayError::MalformedFrame)
    }
}

fn relay_node_id_is_valid(node_id: &str) -> bool {
    !node_id.is_empty()
        && node_id.len() <= MAX_RELAY_NODE_ID_BYTES
        && !matches!(node_id, "." | "..")
        && !node_id.starts_with('-')
        && node_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_relay_frame_sizes(
    session_id_len: usize,
    session_token_len: usize,
    ciphertext_payload_len: usize,
) -> Result<(), RelayError> {
    validate_relay_frame_sizes_with_options(
        session_id_len,
        session_token_len,
        ciphertext_payload_len,
        false,
    )
}

fn validate_relay_frame_sizes_allow_empty(
    session_id_len: usize,
    session_token_len: usize,
    ciphertext_payload_len: usize,
) -> Result<(), RelayError> {
    validate_relay_frame_sizes_with_options(
        session_id_len,
        session_token_len,
        ciphertext_payload_len,
        true,
    )
}

fn validate_relay_frame_sizes_with_options(
    session_id_len: usize,
    session_token_len: usize,
    ciphertext_payload_len: usize,
    allow_empty_payload: bool,
) -> Result<(), RelayError> {
    if session_id_len == 0
        || session_token_len == 0
        || (!allow_empty_payload && ciphertext_payload_len == 0)
    {
        return Err(RelayError::MalformedFrame);
    }
    if session_id_len > MAX_RELAY_SESSION_ID_BYTES
        || session_token_len > MAX_RELAY_SESSION_TOKEN_BYTES
        || ciphertext_payload_len > MAX_RELAY_CIPHERTEXT_PAYLOAD_BYTES
    {
        return Err(RelayError::FrameTooLarge);
    }
    if session_id_len > u16::MAX as usize || session_token_len > u16::MAX as usize {
        return Err(RelayError::FrameTooLarge);
    }
    Ok(())
}

fn validate_relay_node_id_size(node_id_len: usize) -> Result<(), RelayError> {
    if node_id_len == 0 || node_id_len > MAX_RELAY_NODE_ID_BYTES || node_id_len > u16::MAX as usize
    {
        return Err(RelayError::FrameTooLarge);
    }
    Ok(())
}

fn relay_session_token_matches(expected: &str, provided: &str) -> bool {
    if expected.len() > MAX_RELAY_SESSION_TOKEN_BYTES
        || provided.len() > MAX_RELAY_SESSION_TOKEN_BYTES
    {
        return false;
    }

    let expected = expected.as_bytes();
    let provided = provided.as_bytes();
    let mut diff = expected.len() ^ provided.len();
    for index in 0..MAX_RELAY_SESSION_TOKEN_BYTES {
        let expected_byte = expected.get(index).copied().unwrap_or_default();
        let provided_byte = provided.get(index).copied().unwrap_or_default();
        diff |= usize::from(expected_byte ^ provided_byte);
    }
    diff == 0
}

fn decode_relay_datagram(datagram: &[u8]) -> Result<RelayDatagram, RelayError> {
    if datagram.starts_with(RELAY_FRAME_MAGIC_V3) {
        return decode_relay_datagram_v3(datagram);
    }
    if datagram.starts_with(RELAY_FRAME_MAGIC_V2) {
        return decode_relay_datagram_v2(datagram);
    }
    decode_relay_datagram_v1(datagram)
}

fn decode_relay_datagram_v1(datagram: &[u8]) -> Result<RelayDatagram, RelayError> {
    let fixed_header_len = RELAY_FRAME_MAGIC.len() + 4;
    if datagram.len() <= fixed_header_len || !datagram.starts_with(RELAY_FRAME_MAGIC) {
        return Err(RelayError::MalformedFrame);
    }

    let session_len_offset = RELAY_FRAME_MAGIC.len();
    let token_len_offset = session_len_offset + 2;
    let session_len = u16::from_be_bytes([
        datagram[session_len_offset],
        datagram[session_len_offset + 1],
    ]) as usize;
    let token_len =
        u16::from_be_bytes([datagram[token_len_offset], datagram[token_len_offset + 1]]) as usize;
    let session_start = fixed_header_len;
    let token_start = session_start + session_len;
    let payload_start = token_start + token_len;
    if session_len == 0 || token_len == 0 {
        return Err(RelayError::MalformedFrame);
    }
    validate_relay_frame_sizes(
        session_len,
        token_len,
        datagram.len().saturating_sub(payload_start),
    )?;
    if token_start > datagram.len() || payload_start >= datagram.len() {
        return Err(RelayError::MalformedFrame);
    }

    let session_id = String::from_utf8(datagram[session_start..token_start].to_vec())
        .map_err(|_| RelayError::MalformedFrame)?;
    let session_token = String::from_utf8(datagram[token_start..payload_start].to_vec())
        .map_err(|_| RelayError::MalformedFrame)?;

    Ok(RelayDatagram {
        session_id: RelaySessionId(session_id),
        session_token,
        source: None,
        destination: None,
        ciphertext_payload: datagram[payload_start..].to_vec(),
        endpoint_announcement: false,
    })
}

fn decode_relay_datagram_v2(datagram: &[u8]) -> Result<RelayDatagram, RelayError> {
    decode_relay_datagram_v2_with_options(datagram, RELAY_FRAME_MAGIC_V2, false)
}

fn decode_relay_datagram_v3(datagram: &[u8]) -> Result<RelayDatagram, RelayError> {
    decode_relay_datagram_v2_with_options(datagram, RELAY_FRAME_MAGIC_V3, true)
}

fn decode_relay_datagram_v2_with_options(
    datagram: &[u8],
    magic: &[u8],
    endpoint_announcement: bool,
) -> Result<RelayDatagram, RelayError> {
    let fixed_header_len = magic.len() + 8;
    if datagram.len() < fixed_header_len || !datagram.starts_with(magic) {
        return Err(RelayError::MalformedFrame);
    }

    let session_len_offset = magic.len();
    let token_len_offset = session_len_offset + 2;
    let source_len_offset = token_len_offset + 2;
    let destination_len_offset = source_len_offset + 2;
    let session_len = u16::from_be_bytes([
        datagram[session_len_offset],
        datagram[session_len_offset + 1],
    ]) as usize;
    let token_len =
        u16::from_be_bytes([datagram[token_len_offset], datagram[token_len_offset + 1]]) as usize;
    let source_len =
        u16::from_be_bytes([datagram[source_len_offset], datagram[source_len_offset + 1]]) as usize;
    let destination_len = u16::from_be_bytes([
        datagram[destination_len_offset],
        datagram[destination_len_offset + 1],
    ]) as usize;

    let session_start = fixed_header_len;
    let token_start = session_start + session_len;
    let source_start = token_start + token_len;
    let destination_start = source_start + source_len;
    let payload_start = destination_start + destination_len;
    if session_len == 0 || token_len == 0 || source_len == 0 || destination_len == 0 {
        return Err(RelayError::MalformedFrame);
    }
    if endpoint_announcement {
        validate_relay_frame_sizes_allow_empty(
            session_len,
            token_len,
            datagram.len().saturating_sub(payload_start),
        )?;
    } else {
        validate_relay_frame_sizes(
            session_len,
            token_len,
            datagram.len().saturating_sub(payload_start),
        )?;
    }
    validate_relay_node_id_size(source_len)?;
    validate_relay_node_id_size(destination_len)?;
    if token_start > datagram.len()
        || source_start > datagram.len()
        || destination_start > datagram.len()
        || payload_start > datagram.len()
        || (!endpoint_announcement && payload_start == datagram.len())
    {
        return Err(RelayError::MalformedFrame);
    }

    let session_id = String::from_utf8(datagram[session_start..token_start].to_vec())
        .map_err(|_| RelayError::MalformedFrame)?;
    let session_token = String::from_utf8(datagram[token_start..source_start].to_vec())
        .map_err(|_| RelayError::MalformedFrame)?;
    let source = String::from_utf8(datagram[source_start..destination_start].to_vec())
        .map_err(|_| RelayError::MalformedFrame)?;
    let destination = String::from_utf8(datagram[destination_start..payload_start].to_vec())
        .map_err(|_| RelayError::MalformedFrame)?;
    validate_relay_frame_node_id(&source)?;
    validate_relay_frame_node_id(&destination)?;

    Ok(RelayDatagram {
        session_id: RelaySessionId(session_id),
        session_token,
        source: Some(NodeId::from_string(source)),
        destination: Some(NodeId::from_string(destination)),
        ciphertext_payload: datagram[payload_start..].to_vec(),
        endpoint_announcement,
    })
}

#[derive(Debug)]
pub struct RelayService {
    relay_node: NodeId,
    capability: RwLock<RelayCapability>,
    table: std::sync::Arc<RwLock<RelayTable>>,
    session_ttl: chrono::Duration,
    admission_rate_limit: Option<RelayAdmissionRateLimit>,
    max_sessions_per_node: Option<u32>,
    admission_rate_window: Mutex<RelayAdmissionRateWindow>,
    admission_attempts: AtomicU64,
    admission_successes: AtomicU64,
    admission_failures: AtomicU64,
    admission_failures_by_reason: Mutex<BTreeMap<RelayAdmissionFailureReason, u64>>,
}

#[derive(Debug)]
struct RelayAdmissionRateWindow {
    started_at: DateTime<Utc>,
    attempts: u32,
}

impl RelayService {
    pub fn new(relay_node: NodeId, capability: RelayCapability) -> Self {
        Self::with_session_ttl(relay_node, capability, default_session_ttl())
    }

    pub fn with_session_ttl(
        relay_node: NodeId,
        capability: RelayCapability,
        session_ttl: chrono::Duration,
    ) -> Self {
        Self::with_session_ttl_and_admission_rate_limit(relay_node, capability, session_ttl, None)
    }

    pub fn with_session_ttl_and_admission_rate_limit(
        relay_node: NodeId,
        capability: RelayCapability,
        session_ttl: chrono::Duration,
        admission_rate_limit: Option<RelayAdmissionRateLimit>,
    ) -> Self {
        Self::with_session_ttl_admission_controls(
            relay_node,
            capability,
            session_ttl,
            admission_rate_limit,
            None,
        )
    }

    pub fn with_session_ttl_admission_controls(
        relay_node: NodeId,
        capability: RelayCapability,
        session_ttl: chrono::Duration,
        admission_rate_limit: Option<RelayAdmissionRateLimit>,
        max_sessions_per_node: Option<u32>,
    ) -> Self {
        Self {
            relay_node,
            capability: RwLock::new(capability),
            table: std::sync::Arc::new(RwLock::new(RelayTable::default())),
            session_ttl: session_ttl.max(chrono::Duration::milliseconds(1)),
            admission_rate_limit,
            max_sessions_per_node: max_sessions_per_node.filter(|limit| *limit > 0),
            admission_rate_window: Mutex::new(RelayAdmissionRateWindow {
                started_at: Utc::now(),
                attempts: 0,
            }),
            admission_attempts: AtomicU64::new(0),
            admission_successes: AtomicU64::new(0),
            admission_failures: AtomicU64::new(0),
            admission_failures_by_reason: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn table(&self) -> std::sync::Arc<RwLock<RelayTable>> {
        self.table.clone()
    }

    pub async fn admit(
        &self,
        request: RelayAdmissionRequest,
    ) -> Result<RelayAdmissionResponse, RelayError> {
        self.admission_attempts.fetch_add(1, Ordering::Relaxed);
        let result = match self.record_admission_attempt_for_limit(Utc::now()) {
            Ok(()) => self.admit_inner(request).await,
            Err(error) => Err(error),
        };
        match &result {
            Ok(_) => {
                self.admission_successes.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => {
                self.record_admission_failure(relay_error_admission_failure_reason(error));
            }
        }
        result
    }

    pub fn record_unauthorized_admission_attempt(&self) -> Result<(), RelayError> {
        self.admission_attempts.fetch_add(1, Ordering::Relaxed);
        match self.record_admission_attempt_for_limit(Utc::now()) {
            Ok(()) => {
                self.record_admission_failure(RelayAdmissionFailureReason::Unauthorized);
                Ok(())
            }
            Err(error) => {
                self.record_admission_failure(relay_error_admission_failure_reason(&error));
                Err(error)
            }
        }
    }

    fn record_admission_attempt_for_limit(&self, now: DateTime<Utc>) -> Result<(), RelayError> {
        let Some(limit) = self.admission_rate_limit else {
            return Ok(());
        };
        if limit.max_attempts == 0 || limit.window <= chrono::Duration::zero() {
            return Ok(());
        }

        let mut window = self
            .admission_rate_window
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if now.signed_duration_since(window.started_at) >= limit.window {
            window.started_at = now;
            window.attempts = 0;
        }
        if window.attempts >= limit.max_attempts {
            return Err(RelayError::RateLimited);
        }
        window.attempts = window.attempts.saturating_add(1);
        Ok(())
    }

    fn record_admission_failure(&self, reason: RelayAdmissionFailureReason) {
        self.admission_failures.fetch_add(1, Ordering::Relaxed);
        let mut failures_by_reason = self
            .admission_failures_by_reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = failures_by_reason.entry(reason).or_default();
        *count = count.saturating_add(1);
    }

    fn admission_failures_by_reason(&self) -> BTreeMap<RelayAdmissionFailureReason, u64> {
        self.admission_failures_by_reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    async fn admit_inner(
        &self,
        request: RelayAdmissionRequest,
    ) -> Result<RelayAdmissionResponse, RelayError> {
        let mut capability = self.capability.write().await;
        let mut table = self.table.write().await;
        table.purge_expired(Utc::now());
        capability.active_sessions = table.session_count() as u32;
        let admission = RelaySessionAdmission {
            left: request.left.clone(),
            right: request.right.clone(),
            left_addr: request.left_addr,
            right_addr: request.right_addr,
            session_token: Uuid::new_v4().to_string(),
            session_ttl: self.session_ttl,
        };
        let session_id = RelaySessionId::new(&admission.left, &admission.right);
        validate_relay_session_admission(&admission, &session_id)?;
        if !table.has_session_pair(&admission.left, &admission.right)
            && (self.node_session_limit_exceeded(&table, &admission.left)
                || self.node_session_limit_exceeded(&table, &admission.right))
        {
            return Err(RelayError::NodeSessionLimitExceeded);
        }
        let credentials = table.admit_with_options(&capability, admission)?;
        capability.active_sessions = table.session_count() as u32;

        Ok(RelayAdmissionResponse {
            relay_node: self.relay_node.clone(),
            session_id: credentials.session_id.as_str().to_string(),
            session_token: credentials.session_token,
            expires_at: credentials.expires_at,
            left: request.left,
            right: request.right,
            left_addr: request.left_addr,
            right_addr: request.right_addr,
        })
    }

    pub async fn status(&self) -> RelayStatusResponse {
        let generated_at = Utc::now();
        let mut capability = self.capability.write().await;
        let mut table = self.table.write().await;
        table.purge_expired(generated_at);
        capability.active_sessions = table.session_count() as u32;
        RelayStatusResponse {
            relay_node: self.relay_node.clone(),
            capability: capability.clone(),
            health: HealthState::Healthy,
            admission_attempt_count: self.admission_attempts.load(Ordering::Relaxed),
            admission_success_count: self.admission_successes.load(Ordering::Relaxed),
            admission_failure_count: self.admission_failures.load(Ordering::Relaxed),
            admission_failures_by_reason: zero_filled_admission_failure_reasons(
                self.admission_failures_by_reason(),
            ),
            max_sessions_per_node: self.max_sessions_per_node,
            dataplane: zero_filled_dataplane_metrics(table.dataplane_metrics()),
            generated_at,
        }
    }

    fn node_session_limit_exceeded(&self, table: &RelayTable, node: &NodeId) -> bool {
        self.max_sessions_per_node
            .map(|limit| table.active_session_count_for_node(node) >= limit as usize)
            .unwrap_or(false)
    }
}

pub struct UdpRelay {
    socket: UdpSocket,
}

impl UdpRelay {
    pub async fn bind(addr: SocketAddr) -> Result<Self, RelayError> {
        Ok(Self {
            socket: UdpSocket::bind(addr).await?,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, RelayError> {
        Ok(self.socket.local_addr()?)
    }

    pub async fn serve(
        self,
        table: std::sync::Arc<RwLock<RelayTable>>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), RelayError> {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                packet = self.socket.recv_from(&mut buffer) => {
                    let (len, peer) = packet?;
                    let target = table.write().await.forward_datagram_for_addr(peer, &buffer[..len]);
                    if let Ok((target, payload)) = target {
                        if !payload.is_empty() {
                            self.socket.send_to(&payload, target).await?;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ipars_types::api::RelayAdmissionFailureReason;
    use ipars_types::RelayCapability;

    use super::*;

    fn relay_capability(public_endpoint: SocketAddr, max_mbps: u32) -> RelayCapability {
        RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(public_endpoint),
            admission_url: Some("http://203.0.113.10:9580".to_string()),
            max_sessions: 10,
            active_sessions: 0,
            max_mbps,
            e2e_only: true,
        }
    }

    #[test]
    fn relay_forwards_only_known_opaque_session_payloads() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left = NodeId::from_string("left");
        let right = NodeId::from_string("right");
        let credentials = table.admit_with_token(
            &capability,
            left.clone(),
            right.clone(),
            SocketAddr::from(([10, 0, 0, 1], 10000)),
            SocketAddr::from(([10, 0, 0, 2], 10000)),
            "relay-secret".to_string(),
        )?;
        let target = table.forward_target(&RelayFrame {
            session_id: credentials.session_id,
            session_token: credentials.session_token,
            source: left,
            destination: right,
            ciphertext_payload: vec![1, 2, 3],
        })?;

        assert_eq!(target, SocketAddr::from(([10, 0, 0, 2], 10000)));
        Ok(())
    }

    #[test]
    fn relay_rejects_invalid_session_token() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left = NodeId::from_string("left");
        let right = NodeId::from_string("right");
        let credentials = table.admit_with_token(
            &capability,
            left.clone(),
            right.clone(),
            SocketAddr::from(([10, 0, 0, 1], 10000)),
            SocketAddr::from(([10, 0, 0, 2], 10000)),
            "relay-secret".to_string(),
        )?;

        let error = table.forward_target(&RelayFrame {
            session_id: credentials.session_id,
            session_token: "wrong-secret".to_string(),
            source: left,
            destination: right,
            ciphertext_payload: vec![1, 2, 3],
        });

        assert!(matches!(error, Err(RelayError::InvalidSessionCredential)));
        let metrics = table.dataplane_metrics();
        assert_eq!(metrics.datagrams_received, 1);
        assert_eq!(metrics.datagrams_forwarded, 0);
        assert_eq!(metrics.datagrams_dropped, 1);
        assert_eq!(
            metrics
                .drops_by_reason
                .get(&RelayDataplaneDropReason::InvalidSessionCredential),
            Some(&1)
        );
        Ok(())
    }

    #[test]
    fn relay_rejects_self_or_same_endpoint_admission() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left_addr = SocketAddr::from(([10, 0, 0, 1], 10000));
        let right_addr = SocketAddr::from(([10, 0, 0, 2], 10000));

        let same_node = table.admit_with_token(
            &capability,
            NodeId::from_string("node-a"),
            NodeId::from_string("node-a"),
            left_addr,
            right_addr,
            "relay-secret".to_string(),
        );
        assert!(matches!(same_node, Err(RelayError::AdmissionDenied)));

        let same_endpoint = table.admit_with_token(
            &capability,
            NodeId::from_string("node-a"),
            NodeId::from_string("node-b"),
            left_addr,
            left_addr,
            "relay-secret".to_string(),
        );
        assert!(matches!(same_endpoint, Err(RelayError::AdmissionDenied)));
        assert_eq!(table.session_count(), 0);
        Ok(())
    }

    #[test]
    fn relay_rejects_unusable_session_endpoint_admission() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left = NodeId::from_string("node-a");
        let right = NodeId::from_string("node-b");
        let valid_addr = SocketAddr::from(([10, 0, 0, 2], 10000));

        for addr in [
            SocketAddr::from(([0, 0, 0, 0], 10000)),
            SocketAddr::from(([10, 0, 0, 1], 0)),
            SocketAddr::from(([224, 0, 0, 1], 10000)),
            SocketAddr::from(([255, 255, 255, 255], 10000)),
            SocketAddr::from(([0xff02, 0, 0, 0, 0, 0, 0, 1], 10000)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 10000)),
        ] {
            let rejected = table.admit_with_token(
                &capability,
                left.clone(),
                right.clone(),
                addr,
                valid_addr,
                "relay-secret".to_string(),
            );
            assert!(
                matches!(rejected, Err(RelayError::AdmissionDenied)),
                "{addr} should be denied"
            );
        }
        assert_eq!(table.session_count(), 0);
        Ok(())
    }

    #[test]
    fn relay_rejects_unsafe_node_id_admission() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left_addr = SocketAddr::from(([10, 0, 0, 1], 10000));
        let right_addr = SocketAddr::from(([10, 0, 0, 2], 10000));
        let oversized = "x".repeat(MAX_RELAY_NODE_ID_BYTES + 1);

        for node_id in [
            "",
            ".",
            "..",
            "-node",
            "node/../a",
            "node:a",
            "node a",
            "node\nspoof",
            oversized.as_str(),
        ] {
            let rejected = table.admit_with_token(
                &capability,
                NodeId::from_string(node_id),
                NodeId::from_string("node-b"),
                left_addr,
                right_addr,
                "relay-secret".to_string(),
            );
            assert!(
                matches!(rejected, Err(RelayError::InvalidAdmissionRequest)),
                "{node_id:?} should be rejected"
            );
        }

        let rejected_right = table.admit_with_token(
            &capability,
            NodeId::from_string("node-a"),
            NodeId::from_string("node/b"),
            left_addr,
            right_addr,
            "relay-secret".to_string(),
        );
        assert!(matches!(
            rejected_right,
            Err(RelayError::InvalidAdmissionRequest)
        ));
        assert_eq!(table.session_count(), 0);
        Ok(())
    }

    #[test]
    fn relay_reuses_duplicate_node_pair_admission() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left = NodeId::from_string("node-a");
        let right = NodeId::from_string("node-b");
        let left_addr = SocketAddr::from(([10, 0, 0, 1], 10000));
        let right_addr = SocketAddr::from(([10, 0, 0, 2], 10000));
        let credentials = table.admit_with_token(
            &capability,
            left.clone(),
            right.clone(),
            left_addr,
            right_addr,
            "relay-secret".to_string(),
        )?;

        let duplicate_same_direction = table.admit_with_token(
            &capability,
            left.clone(),
            right.clone(),
            left_addr,
            right_addr,
            "replacement-secret".to_string(),
        )?;
        assert_eq!(duplicate_same_direction.session_id, credentials.session_id);
        assert_eq!(
            duplicate_same_direction.session_token,
            credentials.session_token
        );
        assert!(duplicate_same_direction.expires_at > credentials.expires_at);

        let duplicate_reversed = table.admit_with_token(
            &capability,
            right.clone(),
            left.clone(),
            right_addr,
            left_addr,
            "replacement-secret".to_string(),
        )?;
        assert_eq!(duplicate_reversed.session_id, credentials.session_id);
        assert_eq!(duplicate_reversed.session_token, credentials.session_token);
        assert!(duplicate_reversed.expires_at > duplicate_same_direction.expires_at);
        assert_eq!(table.session_count(), 1);

        assert_eq!(
            table.forward_target(&RelayFrame {
                session_id: credentials.session_id,
                session_token: credentials.session_token,
                source: left,
                destination: right,
                ciphertext_payload: b"opaque".to_vec(),
            })?,
            right_addr
        );
        Ok(())
    }

    #[test]
    fn relay_rejects_oversized_frames_and_records_drop_reason() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left = NodeId::from_string("left");
        let right = NodeId::from_string("right");
        let left_addr = SocketAddr::from(([10, 0, 0, 1], 10000));
        let right_addr = SocketAddr::from(([10, 0, 0, 2], 10000));
        let credentials = table.admit_with_token(
            &capability,
            left.clone(),
            right.clone(),
            left_addr,
            right_addr,
            "relay-secret".to_string(),
        )?;

        let oversized_payload = vec![0_u8; MAX_RELAY_CIPHERTEXT_PAYLOAD_BYTES + 1];
        assert!(matches!(
            encode_relay_datagram(
                credentials.session_id.as_str(),
                &credentials.session_token,
                &oversized_payload,
            ),
            Err(RelayError::FrameTooLarge)
        ));
        assert!(matches!(
            encode_relay_datagram(
                credentials.session_id.as_str(),
                &"s".repeat(MAX_RELAY_SESSION_TOKEN_BYTES + 1),
                b"opaque",
            ),
            Err(RelayError::FrameTooLarge)
        ));

        let error = table.forward_target(&RelayFrame {
            session_id: credentials.session_id,
            session_token: credentials.session_token,
            source: left,
            destination: right,
            ciphertext_payload: oversized_payload,
        });

        assert!(matches!(error, Err(RelayError::FrameTooLarge)));
        let metrics = table.dataplane_metrics();
        assert_eq!(metrics.datagrams_received, 1);
        assert_eq!(metrics.datagrams_forwarded, 0);
        assert_eq!(metrics.datagrams_dropped, 1);
        assert_eq!(
            metrics
                .drops_by_reason
                .get(&RelayDataplaneDropReason::FrameTooLarge),
            Some(&1)
        );
        assert_eq!(
            RelayDataplaneDropReason::FrameTooLarge.as_str(),
            "frame_too_large"
        );
        Ok(())
    }

    #[test]
    fn relay_rejects_empty_direct_frames_and_records_drop_reason() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left = NodeId::from_string("left");
        let right = NodeId::from_string("right");
        let credentials = table.admit_with_token(
            &capability,
            left.clone(),
            right.clone(),
            SocketAddr::from(([10, 0, 0, 1], 10000)),
            SocketAddr::from(([10, 0, 0, 2], 10000)),
            "relay-secret".to_string(),
        )?;

        let error = table.forward_target(&RelayFrame {
            session_id: credentials.session_id,
            session_token: credentials.session_token,
            source: left,
            destination: right,
            ciphertext_payload: Vec::new(),
        });

        assert!(matches!(error, Err(RelayError::MalformedFrame)));
        let metrics = table.dataplane_metrics();
        assert_eq!(metrics.datagrams_received, 1);
        assert_eq!(metrics.datagrams_forwarded, 0);
        assert_eq!(metrics.datagrams_dropped, 1);
        assert_eq!(
            metrics
                .drops_by_reason
                .get(&RelayDataplaneDropReason::MalformedFrame),
            Some(&1)
        );
        assert_eq!(metrics.payload_bytes_forwarded, 0);
        Ok(())
    }

    #[test]
    fn relay_removes_expired_session_before_forwarding() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left = NodeId::from_string("left");
        let right = NodeId::from_string("right");
        let credentials = table.admit_with_options(
            &capability,
            RelaySessionAdmission {
                left: left.clone(),
                right: right.clone(),
                left_addr: SocketAddr::from(([10, 0, 0, 1], 10000)),
                right_addr: SocketAddr::from(([10, 0, 0, 2], 10000)),
                session_token: "relay-secret".to_string(),
                session_ttl: chrono::Duration::seconds(1),
            },
        )?;
        let error = table.forward_target_at(
            &RelayFrame {
                session_id: credentials.session_id,
                session_token: credentials.session_token,
                source: left,
                destination: right,
                ciphertext_payload: vec![1, 2, 3],
            },
            credentials.expires_at,
        );

        assert!(matches!(error, Err(RelayError::SessionExpired)));
        assert_eq!(table.session_count(), 0);
        Ok(())
    }

    #[test]
    fn relay_enforces_per_session_rate_limit() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1);
        let left = NodeId::from_string("left");
        let right = NodeId::from_string("right");
        let credentials = table.admit_with_token(
            &capability,
            left.clone(),
            right.clone(),
            SocketAddr::from(([10, 0, 0, 1], 10000)),
            SocketAddr::from(([10, 0, 0, 2], 10000)),
            "relay-secret".to_string(),
        )?;
        let first = RelayFrame {
            session_id: credentials.session_id.clone(),
            session_token: credentials.session_token.clone(),
            source: left.clone(),
            destination: right.clone(),
            ciphertext_payload: vec![1; 100_000],
        };
        let second = RelayFrame {
            session_id: credentials.session_id,
            session_token: credentials.session_token,
            source: left,
            destination: right,
            ciphertext_payload: vec![2; 30_000],
        };

        table.forward_target(&first)?;
        let error = table.forward_target(&second);

        assert!(matches!(error, Err(RelayError::RateLimited)));
        Ok(())
    }

    #[test]
    fn relay_admission_reuses_live_session_and_refreshes_endpoints() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left = NodeId::from_string("left");
        let right = NodeId::from_string("right");
        let first_left_addr = SocketAddr::from(([10, 0, 0, 1], 10000));
        let first_right_addr = SocketAddr::from(([10, 0, 0, 2], 10000));
        let second_left_addr = SocketAddr::from(([10, 0, 0, 3], 10000));
        let second_right_addr = SocketAddr::from(([10, 0, 0, 4], 10000));
        let first = table.admit_with_token(
            &capability,
            left.clone(),
            right.clone(),
            first_left_addr,
            first_right_addr,
            "left-secret".to_string(),
        )?;

        let second = table.admit_with_token(
            &capability,
            left,
            right,
            second_left_addr,
            second_right_addr,
            "right-secret".to_string(),
        )?;
        assert_eq!(second.session_id, first.session_id);
        assert_eq!(second.session_token, first.session_token);
        assert!(second.expires_at > first.expires_at);
        assert_eq!(table.session_count(), 1);
        let datagram =
            encode_relay_datagram(second.session_id.as_str(), &second.session_token, b"opaque")?;
        let (target, payload) = table.forward_datagram_for_addr(second_left_addr, &datagram)?;
        assert_eq!(target, second_right_addr);
        assert_eq!(payload, b"opaque");
        let rejected = table.forward_datagram_for_addr(first_left_addr, &datagram);
        assert!(matches!(rejected, Err(RelayError::UnknownSession)));
        Ok(())
    }

    #[test]
    fn relay_datagram_route_updates_symmetric_nat_source_addr() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left = NodeId::from_string("left");
        let right = NodeId::from_string("right");
        let admitted_left_addr = SocketAddr::from(([198, 51, 100, 10], 40000));
        let admitted_right_addr = SocketAddr::from(([198, 51, 100, 20], 40000));
        let learned_left_addr = SocketAddr::from(([198, 51, 100, 10], 41000));
        let learned_right_addr = SocketAddr::from(([198, 51, 100, 20], 42000));
        let credentials = table.admit_with_token(
            &capability,
            left.clone(),
            right.clone(),
            admitted_left_addr,
            admitted_right_addr,
            "relay-secret".to_string(),
        )?;

        let first_left = encode_relay_datagram_with_route(
            credentials.session_id.as_str(),
            &credentials.session_token,
            &left,
            &right,
            b"left-first",
        )?;
        let (target, payload) = table.forward_datagram_for_addr(learned_left_addr, &first_left)?;
        assert_eq!(target, admitted_right_addr);
        assert_eq!(payload, b"left-first");

        let first_right = encode_relay_datagram_with_route(
            credentials.session_id.as_str(),
            &credentials.session_token,
            &right,
            &left,
            b"right-first",
        )?;
        let (target, payload) =
            table.forward_datagram_for_addr(learned_right_addr, &first_right)?;
        assert_eq!(target, learned_left_addr);
        assert_eq!(payload, b"right-first");

        let second_left = encode_relay_datagram_with_route(
            credentials.session_id.as_str(),
            &credentials.session_token,
            &left,
            &right,
            b"left-second",
        )?;
        let (target, payload) = table.forward_datagram_for_addr(learned_left_addr, &second_left)?;
        assert_eq!(target, learned_right_addr);
        assert_eq!(payload, b"left-second");
        Ok(())
    }

    #[test]
    fn relay_endpoint_announcements_learn_forwarder_addresses_without_forwarding_payload(
    ) -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left = NodeId::from_string("left");
        let right = NodeId::from_string("right");
        let admitted_left_addr = SocketAddr::from(([198, 51, 100, 10], 40000));
        let admitted_right_addr = SocketAddr::from(([198, 51, 100, 20], 40000));
        let learned_left_addr = SocketAddr::from(([198, 51, 100, 10], 41000));
        let learned_right_addr = SocketAddr::from(([198, 51, 100, 20], 42000));
        let credentials = table.admit_with_token(
            &capability,
            left.clone(),
            right.clone(),
            admitted_left_addr,
            admitted_right_addr,
            "relay-secret".to_string(),
        )?;

        let left_announcement = encode_relay_endpoint_announcement(
            credentials.session_id.as_str(),
            &credentials.session_token,
            &left,
            &right,
        )?;
        let (target, payload) =
            table.forward_datagram_for_addr(learned_left_addr, &left_announcement)?;
        assert_eq!(target, admitted_right_addr);
        assert!(payload.is_empty());

        let right_announcement = encode_relay_endpoint_announcement(
            credentials.session_id.as_str(),
            &credentials.session_token,
            &right,
            &left,
        )?;
        let (target, payload) =
            table.forward_datagram_for_addr(learned_right_addr, &right_announcement)?;
        assert_eq!(target, learned_left_addr);
        assert!(payload.is_empty());

        let left_payload = encode_relay_datagram_with_route(
            credentials.session_id.as_str(),
            &credentials.session_token,
            &left,
            &right,
            b"left-after-announcement",
        )?;
        let (target, payload) =
            table.forward_datagram_for_addr(learned_left_addr, &left_payload)?;
        assert_eq!(target, learned_right_addr);
        assert_eq!(payload, b"left-after-announcement");
        let metrics = table.dataplane_metrics();
        assert_eq!(
            metrics.payload_bytes_forwarded,
            b"left-after-announcement".len() as u64
        );
        assert_eq!(metrics.datagrams_forwarded, 1);
        Ok(())
    }

    #[test]
    fn relay_rejects_unsafe_route_metadata_node_ids() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left = NodeId::from_string("left");
        let right = NodeId::from_string("right");
        let left_addr = SocketAddr::from(([10, 0, 0, 1], 10000));
        let right_addr = SocketAddr::from(([10, 0, 0, 2], 10000));
        let credentials = table.admit_with_token(
            &capability,
            left.clone(),
            right.clone(),
            left_addr,
            right_addr,
            "relay-secret".to_string(),
        )?;

        let invalid_encoded = encode_relay_datagram_with_route(
            credentials.session_id.as_str(),
            &credentials.session_token,
            &NodeId::from_string("left/../spoof"),
            &right,
            b"opaque",
        );
        assert!(matches!(invalid_encoded, Err(RelayError::MalformedFrame)));

        let source = b"left/../spoof";
        let destination = right.as_str().as_bytes();
        let payload = b"opaque";
        let mut raw = Vec::new();
        raw.extend_from_slice(RELAY_FRAME_MAGIC_V2);
        raw.extend_from_slice(&(credentials.session_id.as_str().len() as u16).to_be_bytes());
        raw.extend_from_slice(&(credentials.session_token.len() as u16).to_be_bytes());
        raw.extend_from_slice(&(source.len() as u16).to_be_bytes());
        raw.extend_from_slice(&(destination.len() as u16).to_be_bytes());
        raw.extend_from_slice(credentials.session_id.as_str().as_bytes());
        raw.extend_from_slice(credentials.session_token.as_bytes());
        raw.extend_from_slice(source);
        raw.extend_from_slice(destination);
        raw.extend_from_slice(payload);

        let rejected = table.forward_datagram_for_addr(left_addr, &raw);
        assert!(matches!(rejected, Err(RelayError::MalformedFrame)));
        let metrics = table.dataplane_metrics();
        assert_eq!(
            metrics
                .drops_by_reason
                .get(&RelayDataplaneDropReason::MalformedFrame),
            Some(&1)
        );
        Ok(())
    }

    #[test]
    fn relay_frame_uses_length_prefixed_metadata() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left = NodeId::from_string("left");
        let right = NodeId::from_string("right");
        let left_addr = SocketAddr::from(([10, 0, 0, 1], 10000));
        let right_addr = SocketAddr::from(([10, 0, 0, 2], 10000));
        let credentials = table.admit_with_token(
            &capability,
            left,
            right,
            left_addr,
            right_addr,
            "relay\nsecret".to_string(),
        )?;
        let datagram = encode_relay_datagram(
            credentials.session_id.as_str(),
            &credentials.session_token,
            b"opaque",
        )?;

        let (target, payload) = table.forward_datagram_for_addr(left_addr, &datagram)?;

        assert_eq!(target, right_addr);
        assert_eq!(payload, b"opaque");
        Ok(())
    }

    #[test]
    fn relay_records_udp_dataplane_drop_reasons() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        let left = NodeId::from_string("left");
        let right = NodeId::from_string("right");
        let left_addr = SocketAddr::from(([10, 0, 0, 1], 10000));
        let right_addr = SocketAddr::from(([10, 0, 0, 2], 10000));
        let credentials = table.admit_with_token(
            &capability,
            left,
            right,
            left_addr,
            right_addr,
            "relay-secret".to_string(),
        )?;

        let malformed = table.forward_datagram_for_addr(left_addr, b"not-a-relay-frame");
        assert!(matches!(malformed, Err(RelayError::MalformedFrame)));

        let unknown = encode_relay_datagram("missing-session", "relay-secret", b"opaque")?;
        let unknown = table.forward_datagram_for_addr(left_addr, &unknown);
        assert!(matches!(unknown, Err(RelayError::UnknownSession)));

        let invalid =
            encode_relay_datagram(credentials.session_id.as_str(), "wrong-secret", b"opaque")?;
        let invalid = table.forward_datagram_for_addr(left_addr, &invalid);
        assert!(matches!(invalid, Err(RelayError::InvalidSessionCredential)));

        let mut oversized = Vec::new();
        oversized.extend_from_slice(RELAY_FRAME_MAGIC);
        oversized.extend_from_slice(&1_u16.to_be_bytes());
        oversized.extend_from_slice(&((MAX_RELAY_SESSION_TOKEN_BYTES + 1) as u16).to_be_bytes());
        oversized.extend_from_slice(b"s");
        oversized.extend_from_slice(&vec![b't'; MAX_RELAY_SESSION_TOKEN_BYTES + 1]);
        oversized.extend_from_slice(b"opaque");
        let oversized = table.forward_datagram_for_addr(left_addr, &oversized);
        assert!(matches!(oversized, Err(RelayError::FrameTooLarge)));

        let valid = encode_relay_datagram(
            credentials.session_id.as_str(),
            &credentials.session_token,
            b"opaque",
        )?;
        let (_target, payload) = table.forward_datagram_for_addr(left_addr, &valid)?;

        let metrics = table.dataplane_metrics();
        assert_eq!(payload, b"opaque");
        assert_eq!(metrics.datagrams_received, 5);
        assert_eq!(metrics.datagrams_forwarded, 1);
        assert_eq!(metrics.datagrams_dropped, 4);
        assert_eq!(metrics.payload_bytes_forwarded, 6);
        assert_eq!(
            metrics
                .drops_by_reason
                .get(&RelayDataplaneDropReason::MalformedFrame),
            Some(&1)
        );
        assert_eq!(
            metrics
                .drops_by_reason
                .get(&RelayDataplaneDropReason::UnknownSession),
            Some(&1)
        );
        assert_eq!(
            metrics
                .drops_by_reason
                .get(&RelayDataplaneDropReason::InvalidSessionCredential),
            Some(&1)
        );
        assert_eq!(
            metrics
                .drops_by_reason
                .get(&RelayDataplaneDropReason::FrameTooLarge),
            Some(&1)
        );
        Ok(())
    }

    #[tokio::test]
    async fn relay_service_status_purges_expired_sessions() -> Result<(), Box<dyn std::error::Error>>
    {
        let service = RelayService::with_session_ttl(
            NodeId::from_string("relay"),
            relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000),
            chrono::Duration::milliseconds(1),
        );
        let _admission = service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left"),
                right: NodeId::from_string("right"),
                left_addr: SocketAddr::from(([10, 0, 0, 1], 10000)),
                right_addr: SocketAddr::from(([10, 0, 0, 2], 10000)),
            })
            .await?;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let status = service.status().await;

        assert_eq!(status.capability.active_sessions, 0);
        Ok(())
    }

    #[tokio::test]
    async fn relay_service_status_zero_fills_reason_metrics(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let service = RelayService::new(
            NodeId::from_string("relay"),
            relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000),
        );

        let status = service.status().await;

        assert_eq!(
            status.admission_failures_by_reason.len(),
            RelayAdmissionFailureReason::ALL.len()
        );
        for reason in RelayAdmissionFailureReason::ALL {
            assert_eq!(
                status.admission_failures_by_reason.get(&reason),
                Some(&0),
                "{reason:?} should be zero-filled"
            );
        }
        assert_eq!(
            status.dataplane.drops_by_reason.len(),
            RelayDataplaneDropReason::ALL.len()
        );
        for reason in RelayDataplaneDropReason::ALL {
            assert_eq!(
                status.dataplane.drops_by_reason.get(&reason),
                Some(&0),
                "{reason:?} should be zero-filled"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn relay_service_status_reports_admission_counters(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut capability = relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000);
        capability.max_sessions = 1;
        let service = RelayService::new(NodeId::from_string("relay"), capability);

        service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left-a"),
                right: NodeId::from_string("right-a"),
                left_addr: SocketAddr::from(([10, 0, 0, 1], 10000)),
                right_addr: SocketAddr::from(([10, 0, 0, 2], 10000)),
            })
            .await?;
        let rejected = service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left-b"),
                right: NodeId::from_string("right-b"),
                left_addr: SocketAddr::from(([10, 0, 0, 3], 10000)),
                right_addr: SocketAddr::from(([10, 0, 0, 4], 10000)),
            })
            .await;

        assert!(matches!(rejected, Err(RelayError::AdmissionDenied)));
        let status = service.status().await;
        assert_eq!(status.capability.active_sessions, 1);
        assert_eq!(status.admission_attempt_count, 2);
        assert_eq!(status.admission_success_count, 1);
        assert_eq!(status.admission_failure_count, 1);
        assert_eq!(
            status
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::AdmissionDenied),
            Some(&1)
        );
        Ok(())
    }

    #[tokio::test]
    async fn relay_service_reuses_duplicate_pair_admission(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let service = RelayService::new(
            NodeId::from_string("relay"),
            relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000),
        );
        service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left"),
                right: NodeId::from_string("right"),
                left_addr: SocketAddr::from(([10, 0, 0, 1], 10000)),
                right_addr: SocketAddr::from(([10, 0, 0, 2], 10000)),
            })
            .await?;
        let duplicate = service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("right"),
                right: NodeId::from_string("left"),
                left_addr: SocketAddr::from(([10, 0, 0, 2], 10001)),
                right_addr: SocketAddr::from(([10, 0, 0, 1], 10001)),
            })
            .await?;
        assert_eq!(duplicate.left, NodeId::from_string("right"));
        assert_eq!(duplicate.right, NodeId::from_string("left"));
        let status = service.status().await;
        assert_eq!(status.capability.active_sessions, 1);
        assert_eq!(status.admission_attempt_count, 2);
        assert_eq!(status.admission_success_count, 2);
        assert_eq!(status.admission_failure_count, 0);
        assert_eq!(
            status
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::AdmissionDenied),
            Some(&0)
        );
        Ok(())
    }

    #[tokio::test]
    async fn relay_service_enforces_per_node_session_limit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let service = RelayService::with_session_ttl_admission_controls(
            NodeId::from_string("relay"),
            relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000),
            chrono::Duration::seconds(300),
            None,
            Some(1),
        );
        service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("shared-left"),
                right: NodeId::from_string("right-a"),
                left_addr: SocketAddr::from(([10, 0, 0, 1], 10000)),
                right_addr: SocketAddr::from(([10, 0, 0, 2], 10000)),
            })
            .await?;
        let rejected = service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("shared-left"),
                right: NodeId::from_string("right-b"),
                left_addr: SocketAddr::from(([10, 0, 0, 1], 10001)),
                right_addr: SocketAddr::from(([10, 0, 0, 3], 10000)),
            })
            .await;

        assert!(matches!(
            rejected,
            Err(RelayError::NodeSessionLimitExceeded)
        ));
        let status = service.status().await;
        assert_eq!(status.capability.active_sessions, 1);
        assert_eq!(status.max_sessions_per_node, Some(1));
        assert_eq!(status.admission_attempt_count, 2);
        assert_eq!(status.admission_success_count, 1);
        assert_eq!(status.admission_failure_count, 1);
        assert_eq!(
            status
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::NodeSessionLimitExceeded),
            Some(&1)
        );
        assert_eq!(
            RelayAdmissionFailureReason::NodeSessionLimitExceeded.as_str(),
            "node_session_limit_exceeded"
        );
        Ok(())
    }

    #[tokio::test]
    async fn relay_service_counts_invalid_admission_as_denied(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let service = RelayService::new(
            NodeId::from_string("relay"),
            relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000),
        );
        let rejected = service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left"),
                right: NodeId::from_string("left"),
                left_addr: SocketAddr::from(([10, 0, 0, 1], 10000)),
                right_addr: SocketAddr::from(([10, 0, 0, 2], 10000)),
            })
            .await;

        assert!(matches!(rejected, Err(RelayError::AdmissionDenied)));
        let status = service.status().await;
        assert_eq!(status.capability.active_sessions, 0);
        assert_eq!(status.admission_attempt_count, 1);
        assert_eq!(status.admission_success_count, 0);
        assert_eq!(status.admission_failure_count, 1);
        assert_eq!(
            status
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::AdmissionDenied),
            Some(&1)
        );
        Ok(())
    }

    #[tokio::test]
    async fn relay_service_counts_unsafe_node_id_admission_as_invalid_request(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let service = RelayService::new(
            NodeId::from_string("relay"),
            relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000),
        );
        let rejected = service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left/../spoof"),
                right: NodeId::from_string("right"),
                left_addr: SocketAddr::from(([10, 0, 0, 1], 10000)),
                right_addr: SocketAddr::from(([10, 0, 0, 2], 10000)),
            })
            .await;

        assert!(matches!(rejected, Err(RelayError::InvalidAdmissionRequest)));
        let status = service.status().await;
        assert_eq!(status.capability.active_sessions, 0);
        assert_eq!(status.admission_attempt_count, 1);
        assert_eq!(status.admission_success_count, 0);
        assert_eq!(status.admission_failure_count, 1);
        assert_eq!(
            status
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::InvalidAdmissionRequest),
            Some(&1)
        );
        assert_eq!(
            RelayAdmissionFailureReason::InvalidAdmissionRequest.as_str(),
            "invalid_admission_request"
        );
        Ok(())
    }

    #[tokio::test]
    async fn relay_service_counts_unusable_endpoint_admission_as_denied(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let service = RelayService::new(
            NodeId::from_string("relay"),
            relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000),
        );
        let rejected = service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left"),
                right: NodeId::from_string("right"),
                left_addr: SocketAddr::from(([0, 0, 0, 0], 10000)),
                right_addr: SocketAddr::from(([10, 0, 0, 2], 10000)),
            })
            .await;

        assert!(matches!(rejected, Err(RelayError::AdmissionDenied)));
        let status = service.status().await;
        assert_eq!(status.capability.active_sessions, 0);
        assert_eq!(status.admission_attempt_count, 1);
        assert_eq!(status.admission_success_count, 0);
        assert_eq!(status.admission_failure_count, 1);
        assert_eq!(
            status
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::AdmissionDenied),
            Some(&1)
        );
        Ok(())
    }

    #[test]
    fn relay_admission_rate_limit_window_resets() -> Result<(), RelayError> {
        let service = RelayService::with_session_ttl_and_admission_rate_limit(
            NodeId::from_string("relay"),
            relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000),
            chrono::Duration::seconds(300),
            Some(RelayAdmissionRateLimit {
                max_attempts: 1,
                window: chrono::Duration::seconds(1),
            }),
        );
        let now = Utc::now();

        service.record_admission_attempt_for_limit(now)?;
        let limited = service.record_admission_attempt_for_limit(now);
        assert!(matches!(limited, Err(RelayError::RateLimited)));
        service.record_admission_attempt_for_limit(now + chrono::Duration::seconds(1))?;
        Ok(())
    }

    #[tokio::test]
    async fn relay_service_counts_rate_limited_admission() -> Result<(), Box<dyn std::error::Error>>
    {
        let service = RelayService::with_session_ttl_and_admission_rate_limit(
            NodeId::from_string("relay"),
            relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000),
            chrono::Duration::seconds(300),
            Some(RelayAdmissionRateLimit {
                max_attempts: 2,
                window: chrono::Duration::seconds(60),
            }),
        );

        for index in 0..2 {
            service
                .admit(RelayAdmissionRequest {
                    left: NodeId::from_string(format!("left-{index}")),
                    right: NodeId::from_string(format!("right-{index}")),
                    left_addr: SocketAddr::from(([10, 0, 0, 1], 10000 + index)),
                    right_addr: SocketAddr::from(([10, 0, 0, 2], 10000 + index)),
                })
                .await?;
        }

        let rejected = service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left-limited"),
                right: NodeId::from_string("right-limited"),
                left_addr: SocketAddr::from(([10, 0, 0, 1], 12000)),
                right_addr: SocketAddr::from(([10, 0, 0, 2], 12000)),
            })
            .await;

        assert!(matches!(rejected, Err(RelayError::RateLimited)));
        let status = service.status().await;
        assert_eq!(status.capability.active_sessions, 2);
        assert_eq!(status.admission_attempt_count, 3);
        assert_eq!(status.admission_success_count, 2);
        assert_eq!(status.admission_failure_count, 1);
        assert_eq!(
            status
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::RateLimited),
            Some(&1)
        );
        assert_eq!(
            RelayAdmissionFailureReason::RateLimited.as_str(),
            "rate_limited"
        );
        Ok(())
    }

    #[tokio::test]
    async fn relay_service_rate_limits_unauthorized_admission_attempts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let service = RelayService::with_session_ttl_and_admission_rate_limit(
            NodeId::from_string("relay"),
            relay_capability(SocketAddr::from(([203, 0, 113, 10], 51820)), 1000),
            chrono::Duration::seconds(300),
            Some(RelayAdmissionRateLimit {
                max_attempts: 1,
                window: chrono::Duration::seconds(60),
            }),
        );

        service.record_unauthorized_admission_attempt()?;
        let rejected = service.record_unauthorized_admission_attempt();

        assert!(matches!(rejected, Err(RelayError::RateLimited)));
        let status = service.status().await;
        assert_eq!(status.capability.active_sessions, 0);
        assert_eq!(status.admission_attempt_count, 2);
        assert_eq!(status.admission_success_count, 0);
        assert_eq!(status.admission_failure_count, 2);
        assert_eq!(
            status
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::Unauthorized),
            Some(&1)
        );
        assert_eq!(
            status
                .admission_failures_by_reason
                .get(&RelayAdmissionFailureReason::RateLimited),
            Some(&1)
        );
        Ok(())
    }

    #[tokio::test]
    async fn udp_relay_forwards_opaque_payload_by_session_addr(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let relay = UdpRelay::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let relay_addr = relay.local_addr()?;
        let left_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let right_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let capability = relay_capability(relay_addr, 1000);
        let service = RelayService::new(NodeId::from_string("relay"), capability);
        let admission = service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left"),
                right: NodeId::from_string("right"),
                left_addr: left_socket.local_addr()?,
                right_addr: right_socket.local_addr()?,
            })
            .await?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let relay_task = tokio::spawn(relay.serve(service.table(), shutdown_rx));

        let datagram = encode_relay_datagram(
            &admission.session_id,
            &admission.session_token,
            b"opaque-wireguard-packet",
        )?;
        left_socket.send_to(&datagram, relay_addr).await?;
        let mut buffer = [0_u8; 128];
        let (len, _peer) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            right_socket.recv_from(&mut buffer),
        )
        .await??;

        assert_eq!(&buffer[..len], b"opaque-wireguard-packet");
        let metrics = service.table().read().await.dataplane_metrics();
        assert_eq!(metrics.datagrams_received, 1);
        assert_eq!(metrics.datagrams_forwarded, 1);
        assert_eq!(metrics.datagrams_dropped, 0);
        assert_eq!(metrics.payload_bytes_forwarded, len as u64);
        shutdown_tx.send(true)?;
        relay_task.await??;
        Ok(())
    }
}
