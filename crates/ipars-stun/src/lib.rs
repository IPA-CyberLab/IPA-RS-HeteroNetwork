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
    #[error("stun response is invalid: {0}")]
    InvalidResponse(String),
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
        let (len, _server_addr) = socket.recv_from(&mut buffer).await?;
        let observed_addr = std::str::from_utf8(&buffer[..len])
            .map_err(|error| StunError::InvalidResponse(error.to_string()))?
            .parse::<SocketAddr>()
            .map_err(|error| StunError::InvalidResponse(error.to_string()))?;

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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use ipars_types::EndpointCandidateKind;

    use super::*;

    #[tokio::test]
    async fn udp_probe_returns_reflexive_endpoint_from_echo_response(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = EchoStunServer::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move { server.serve_once().await });

        let candidate = UdpStunProbe
            .probe(
                NodeId::from_string("node-a"),
                SocketAddr::from(([127, 0, 0, 1], 0)),
                server_addr,
            )
            .await?;
        server_task.await??;

        assert_eq!(candidate.kind, EndpointCandidateKind::StunReflexive);
        assert_eq!(candidate.addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(candidate.addr.port(), 0);
        Ok(())
    }
}
