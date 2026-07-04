use std::collections::BTreeMap;
use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use ipars_types::api::{RelayAdmissionRequest, RelayAdmissionResponse, RelayStatusResponse};
use ipars_types::{HealthState, NodeId, RelayCapability};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{watch, RwLock};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("relay admission denied")]
    AdmissionDenied,
    #[error("unknown relay session")]
    UnknownSession,
    #[error("invalid relay session credential")]
    InvalidSessionCredential,
    #[error("relay session rate limit exceeded")]
    RateLimited,
    #[error("malformed relay frame")]
    MalformedFrame,
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
    pub bytes_forwarded: u64,
    window_started_at: DateTime<Utc>,
    window_bytes: u64,
    max_bytes_per_second: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySessionCredentials {
    pub session_id: RelaySessionId,
    pub session_token: String,
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
    ciphertext_payload: Vec<u8>,
}

const RELAY_FRAME_MAGIC: &[u8] = b"IPARS-RLY1";

pub fn encode_relay_datagram(
    session_id: &str,
    session_token: &str,
    ciphertext_payload: &[u8],
) -> Result<Vec<u8>, RelayError> {
    if session_id.len() > u16::MAX as usize
        || session_token.len() > u16::MAX as usize
        || ciphertext_payload.is_empty()
    {
        return Err(RelayError::MalformedFrame);
    }

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

#[derive(Debug, Default)]
pub struct RelayTable {
    sessions: BTreeMap<RelaySessionId, RelaySession>,
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
        self.admit_with_token(
            capability,
            left,
            right,
            left_addr,
            right_addr,
            Uuid::new_v4().to_string(),
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
        if !capability.can_admit() {
            return Err(RelayError::AdmissionDenied);
        }

        let id = RelaySessionId::new(&left, &right);
        let now = Utc::now();
        self.sessions.insert(
            id.clone(),
            RelaySession {
                id: id.clone(),
                session_token: session_token.clone(),
                left,
                right,
                left_addr,
                right_addr,
                created_at: now,
                bytes_forwarded: 0,
                window_started_at: now,
                window_bytes: 0,
                max_bytes_per_second: megabits_to_bytes_per_second(capability.max_mbps),
            },
        );
        Ok(RelaySessionCredentials {
            session_id: id,
            session_token,
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
        let datagram = decode_relay_datagram(datagram)?;
        let session = self
            .sessions
            .get_mut(&datagram.session_id)
            .ok_or(RelayError::UnknownSession)?;
        session.verify_token(&datagram.session_token)?;
        let target = if session.left_addr == source_addr {
            session.right_addr
        } else if session.right_addr == source_addr {
            session.left_addr
        } else {
            return Err(RelayError::UnknownSession);
        };

        session.consume_rate_limit(datagram.ciphertext_payload.len(), now)?;
        session.bytes_forwarded = session
            .bytes_forwarded
            .saturating_add(datagram.ciphertext_payload.len() as u64);
        Ok((target, datagram.ciphertext_payload))
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn bytes_forwarded(&self) -> u64 {
        self.sessions
            .values()
            .map(|session| session.bytes_forwarded)
            .sum()
    }
}

impl RelaySession {
    fn verify_token(&self, session_token: &str) -> Result<(), RelayError> {
        if self.session_token == session_token {
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

fn decode_relay_datagram(datagram: &[u8]) -> Result<RelayDatagram, RelayError> {
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
    if session_len == 0
        || token_len == 0
        || payload_start >= datagram.len()
        || token_start > datagram.len()
    {
        return Err(RelayError::MalformedFrame);
    }

    let session_id = String::from_utf8(datagram[session_start..token_start].to_vec())
        .map_err(|_| RelayError::MalformedFrame)?;
    let session_token = String::from_utf8(datagram[token_start..payload_start].to_vec())
        .map_err(|_| RelayError::MalformedFrame)?;

    Ok(RelayDatagram {
        session_id: RelaySessionId(session_id),
        session_token,
        ciphertext_payload: datagram[payload_start..].to_vec(),
    })
}

#[derive(Debug)]
pub struct RelayService {
    relay_node: NodeId,
    capability: RwLock<RelayCapability>,
    table: std::sync::Arc<RwLock<RelayTable>>,
}

impl RelayService {
    pub fn new(relay_node: NodeId, capability: RelayCapability) -> Self {
        Self {
            relay_node,
            capability: RwLock::new(capability),
            table: std::sync::Arc::new(RwLock::new(RelayTable::default())),
        }
    }

    pub fn table(&self) -> std::sync::Arc<RwLock<RelayTable>> {
        self.table.clone()
    }

    pub async fn admit(
        &self,
        request: RelayAdmissionRequest,
    ) -> Result<RelayAdmissionResponse, RelayError> {
        let mut capability = self.capability.write().await;
        let credentials = self.table.write().await.admit(
            &capability,
            request.left.clone(),
            request.right.clone(),
            request.left_addr,
            request.right_addr,
        )?;
        capability.active_sessions = capability.active_sessions.saturating_add(1);

        Ok(RelayAdmissionResponse {
            relay_node: self.relay_node.clone(),
            session_id: credentials.session_id.as_str().to_string(),
            session_token: credentials.session_token,
            left: request.left,
            right: request.right,
            left_addr: request.left_addr,
            right_addr: request.right_addr,
        })
    }

    pub async fn status(&self) -> RelayStatusResponse {
        RelayStatusResponse {
            relay_node: self.relay_node.clone(),
            capability: self.capability.read().await.clone(),
            health: HealthState::Healthy,
        }
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
                        self.socket.send_to(&payload, target).await?;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ipars_types::RelayCapability;

    use super::*;

    #[test]
    fn relay_forwards_only_known_opaque_session_payloads() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 10], 51820))),
            max_sessions: 10,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        };
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
        let capability = RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 10], 51820))),
            max_sessions: 10,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        };
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
        Ok(())
    }

    #[test]
    fn relay_enforces_per_session_rate_limit() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 10], 51820))),
            max_sessions: 10,
            active_sessions: 0,
            max_mbps: 1,
            e2e_only: true,
        };
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
    fn relay_frame_uses_length_prefixed_metadata() -> Result<(), RelayError> {
        let mut table = RelayTable::default();
        let capability = RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 10], 51820))),
            max_sessions: 10,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        };
        let left = NodeId::from_string("left\nspoof");
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

    #[tokio::test]
    async fn udp_relay_forwards_opaque_payload_by_session_addr(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let relay = UdpRelay::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let relay_addr = relay.local_addr()?;
        let left_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let right_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let capability = RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(relay_addr),
            max_sessions: 10,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
        };
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
        assert_eq!(service.table().read().await.bytes_forwarded(), len as u64);
        shutdown_tx.send(true)?;
        relay_task.await??;
        Ok(())
    }
}
