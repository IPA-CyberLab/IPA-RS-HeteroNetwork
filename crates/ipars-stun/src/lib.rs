use std::net::SocketAddr;

use async_trait::async_trait;
use chrono::Utc;
use ipars_types::{CandidateSource, EndpointCandidate, EndpointCandidateKind, NodeId};
use thiserror::Error;
use tokio::net::UdpSocket;

#[derive(Debug, Error)]
pub enum StunError {
    #[error("stun socket error: {0}")]
    Socket(#[from] std::io::Error),
}

#[async_trait]
pub trait StunProbe: Send + Sync {
    async fn probe(
        &self,
        node_id: NodeId,
        local_bind: SocketAddr,
        stun_server: SocketAddr,
    ) -> Result<EndpointCandidate, StunError>;
}

#[derive(Debug, Clone)]
pub struct UdpStunProbe;

#[async_trait]
impl StunProbe for UdpStunProbe {
    async fn probe(
        &self,
        node_id: NodeId,
        local_bind: SocketAddr,
        stun_server: SocketAddr,
    ) -> Result<EndpointCandidate, StunError> {
        let socket = UdpSocket::bind(local_bind).await?;
        socket.send_to(b"ipars-stun-probe", stun_server).await?;
        let mut buffer = [0_u8; 128];
        let (_len, observed_addr) = socket.recv_from(&mut buffer).await?;

        Ok(EndpointCandidate {
            node_id,
            kind: EndpointCandidateKind::StunReflexive,
            addr: observed_addr,
            observed_at: Utc::now(),
            priority: 80,
            cost: 20,
            source: CandidateSource::StunProbe,
        })
    }
}

pub struct EchoStunServer {
    socket: UdpSocket,
}

impl EchoStunServer {
    pub async fn bind(addr: SocketAddr) -> Result<Self, StunError> {
        Ok(Self {
            socket: UdpSocket::bind(addr).await?,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, StunError> {
        Ok(self.socket.local_addr()?)
    }

    pub async fn serve_once(&self) -> Result<(), StunError> {
        let mut buffer = [0_u8; 128];
        let (_len, peer) = self.socket.recv_from(&mut buffer).await?;
        self.socket
            .send_to(peer.to_string().as_bytes(), peer)
            .await?;
        Ok(())
    }
}
