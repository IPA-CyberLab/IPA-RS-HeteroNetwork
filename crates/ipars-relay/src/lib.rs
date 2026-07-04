use std::collections::BTreeMap;
use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use ipars_types::{NodeId, RelayCapability};
use thiserror::Error;
use tokio::net::UdpSocket;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("relay admission denied")]
    AdmissionDenied,
    #[error("unknown relay session")]
    UnknownSession,
    #[error("udp socket error: {0}")]
    Socket(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RelaySessionId(String);

impl RelaySessionId {
    pub fn new(left: &NodeId, right: &NodeId) -> Self {
        Self(format!("{left}:{right}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySession {
    pub id: RelaySessionId,
    pub left: NodeId,
    pub right: NodeId,
    pub left_addr: SocketAddr,
    pub right_addr: SocketAddr,
    pub created_at: DateTime<Utc>,
    pub bytes_forwarded: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFrame {
    pub session_id: RelaySessionId,
    pub source: NodeId,
    pub destination: NodeId,
    pub ciphertext_payload: Vec<u8>,
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
    ) -> Result<RelaySessionId, RelayError> {
        if !capability.can_admit() {
            return Err(RelayError::AdmissionDenied);
        }

        let id = RelaySessionId::new(&left, &right);
        self.sessions.insert(
            id.clone(),
            RelaySession {
                id: id.clone(),
                left,
                right,
                left_addr,
                right_addr,
                created_at: Utc::now(),
                bytes_forwarded: 0,
            },
        );
        Ok(id)
    }

    pub fn forward_target(&mut self, frame: &RelayFrame) -> Result<SocketAddr, RelayError> {
        let session = self
            .sessions
            .get_mut(&frame.session_id)
            .ok_or(RelayError::UnknownSession)?;
        session.bytes_forwarded = session
            .bytes_forwarded
            .saturating_add(frame.ciphertext_payload.len() as u64);

        if frame.source == session.left && frame.destination == session.right {
            return Ok(session.right_addr);
        }
        if frame.source == session.right && frame.destination == session.left {
            return Ok(session.left_addr);
        }

        Err(RelayError::UnknownSession)
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
        let id = table.admit(
            &capability,
            left.clone(),
            right.clone(),
            SocketAddr::from(([10, 0, 0, 1], 10000)),
            SocketAddr::from(([10, 0, 0, 2], 10000)),
        )?;
        let target = table.forward_target(&RelayFrame {
            session_id: id,
            source: left,
            destination: right,
            ciphertext_payload: vec![1, 2, 3],
        })?;

        assert_eq!(target, SocketAddr::from(([10, 0, 0, 2], 10000)));
        Ok(())
    }
}
