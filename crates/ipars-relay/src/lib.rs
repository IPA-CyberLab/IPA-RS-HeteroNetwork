use std::collections::BTreeMap;
use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use ipars_types::api::{RelayAdmissionRequest, RelayAdmissionResponse, RelayStatusResponse};
use ipars_types::{HealthState, NodeId, RelayCapability};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{watch, RwLock};

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

    pub fn as_str(&self) -> &str {
        &self.0
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

    pub fn forward_target_for_addr(
        &mut self,
        source_addr: SocketAddr,
        payload_len: usize,
    ) -> Result<SocketAddr, RelayError> {
        let session = self
            .sessions
            .values_mut()
            .find(|session| session.left_addr == source_addr || session.right_addr == source_addr)
            .ok_or(RelayError::UnknownSession)?;
        session.bytes_forwarded = session.bytes_forwarded.saturating_add(payload_len as u64);

        if session.left_addr == source_addr {
            return Ok(session.right_addr);
        }
        Ok(session.left_addr)
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
        let session_id = self.table.write().await.admit(
            &capability,
            request.left.clone(),
            request.right.clone(),
            request.left_addr,
            request.right_addr,
        )?;
        capability.active_sessions = capability.active_sessions.saturating_add(1);

        Ok(RelayAdmissionResponse {
            relay_node: self.relay_node.clone(),
            session_id: session_id.as_str().to_string(),
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
                    let target = table.write().await.forward_target_for_addr(peer, len);
                    if let Ok(target) = target {
                        self.socket.send_to(&buffer[..len], target).await?;
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
        service
            .admit(RelayAdmissionRequest {
                left: NodeId::from_string("left"),
                right: NodeId::from_string("right"),
                left_addr: left_socket.local_addr()?,
                right_addr: right_socket.local_addr()?,
            })
            .await?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let relay_task = tokio::spawn(relay.serve(service.table(), shutdown_rx));

        left_socket
            .send_to(b"opaque-wireguard-packet", relay_addr)
            .await?;
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
