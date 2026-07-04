use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use async_trait::async_trait;
use chrono::Utc;
use ipars_types::{
    CandidateSource, EndpointCandidate, EndpointCandidateKind, NatProbeObservation, NodeId,
};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::watch;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_HEADER_LEN: usize = 20;
const MAGIC_COOKIE: u32 = 0x2112_A442;

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

impl UdpStunProbe {
    pub async fn observe_binding(
        &self,
        local_bind: SocketAddr,
        stun_server: SocketAddr,
    ) -> Result<NatProbeObservation, StunError> {
        let socket = UdpSocket::bind(local_bind).await?;
        observe_binding_with_socket(&socket, stun_server).await
    }

    pub async fn observe_binding_many(
        &self,
        local_bind: SocketAddr,
        stun_servers: &[SocketAddr],
    ) -> Result<Vec<NatProbeObservation>, StunError> {
        let socket = UdpSocket::bind(local_bind).await?;
        let mut observations = Vec::with_capacity(stun_servers.len());
        for stun_server in stun_servers {
            observations.push(observe_binding_with_socket(&socket, *stun_server).await?);
        }
        Ok(observations)
    }
}

#[async_trait]
impl StunProbe for UdpStunProbe {
    async fn probe(
        &self,
        node_id: NodeId,
        local_bind: SocketAddr,
        stun_server: SocketAddr,
    ) -> Result<EndpointCandidate, StunError> {
        let observation = self.observe_binding(local_bind, stun_server).await?;
        Ok(candidate_from_observation(node_id, &observation))
    }
}

pub struct BindingStunServer {
    socket: UdpSocket,
}

pub type EchoStunServer = BindingStunServer;

impl BindingStunServer {
    pub async fn bind(addr: SocketAddr) -> Result<Self, StunError> {
        Ok(Self {
            socket: UdpSocket::bind(addr).await?,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, StunError> {
        Ok(self.socket.local_addr()?)
    }

    pub async fn serve_once(&self) -> Result<(), StunError> {
        let mut buffer = [0_u8; 1500];
        let (len, peer) = self.socket.recv_from(&mut buffer).await?;
        let transaction_id = decode_binding_request(&buffer[..len])?;
        let response = encode_binding_success_response(transaction_id, peer)?;
        self.socket.send_to(&response, peer).await?;
        Ok(())
    }

    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> Result<(), StunError> {
        let mut buffer = [0_u8; 1500];
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                packet = self.socket.recv_from(&mut buffer) => {
                    let (len, peer) = packet?;
                    if let Ok(transaction_id) = decode_binding_request(&buffer[..len]) {
                        let response = encode_binding_success_response(transaction_id, peer)?;
                        self.socket.send_to(&response, peer).await?;
                    }
                }
            }
        }
    }
}

type TransactionId = [u8; 12];

async fn observe_binding_with_socket(
    socket: &UdpSocket,
    stun_server: SocketAddr,
) -> Result<NatProbeObservation, StunError> {
    let transaction_id = new_transaction_id();
    let request = encode_binding_request(transaction_id);
    socket.send_to(&request, stun_server).await?;
    let mut buffer = [0_u8; 1500];
    let (len, _server_addr) = socket.recv_from(&mut buffer).await?;
    let reflexive_addr = decode_binding_success_response(&buffer[..len], transaction_id)?;
    Ok(NatProbeObservation {
        local_addr: socket.local_addr()?,
        stun_server,
        reflexive_addr,
        observed_at: Utc::now(),
    })
}

fn candidate_from_observation(
    node_id: NodeId,
    observation: &NatProbeObservation,
) -> EndpointCandidate {
    EndpointCandidate {
        node_id,
        kind: EndpointCandidateKind::StunReflexive,
        addr: observation.reflexive_addr,
        observed_at: observation.observed_at,
        priority: 80,
        cost: 20,
        source: CandidateSource::StunProbe,
    }
}

fn new_transaction_id() -> TransactionId {
    let mut transaction_id = [0_u8; 12];
    OsRng.fill_bytes(&mut transaction_id);
    transaction_id
}

fn encode_binding_request(transaction_id: TransactionId) -> Vec<u8> {
    let mut message = Vec::with_capacity(STUN_HEADER_LEN);
    write_header(&mut message, BINDING_REQUEST, 0, transaction_id);
    message
}

fn decode_binding_request(message: &[u8]) -> Result<TransactionId, StunError> {
    let (message_type, _message_len, transaction_id) = read_header(message)?;
    if message_type != BINDING_REQUEST {
        return Err(StunError::InvalidResponse(format!(
            "expected binding request, got message type 0x{message_type:04x}"
        )));
    }
    Ok(transaction_id)
}

fn encode_binding_success_response(
    transaction_id: TransactionId,
    mapped_addr: SocketAddr,
) -> Result<Vec<u8>, StunError> {
    let mut attributes = Vec::new();
    write_xor_mapped_address(&mut attributes, transaction_id, mapped_addr)?;
    let mut message = Vec::with_capacity(STUN_HEADER_LEN + attributes.len());
    write_header(
        &mut message,
        BINDING_SUCCESS_RESPONSE,
        attributes.len() as u16,
        transaction_id,
    );
    message.extend_from_slice(&attributes);
    Ok(message)
}

fn decode_binding_success_response(
    message: &[u8],
    expected_transaction_id: TransactionId,
) -> Result<SocketAddr, StunError> {
    let (message_type, message_len, transaction_id) = read_header(message)?;
    if message_type != BINDING_SUCCESS_RESPONSE {
        return Err(StunError::InvalidResponse(format!(
            "expected binding success response, got message type 0x{message_type:04x}"
        )));
    }
    if transaction_id != expected_transaction_id {
        return Err(StunError::InvalidResponse(
            "transaction id mismatch".to_string(),
        ));
    }

    let attributes_end = STUN_HEADER_LEN + message_len as usize;
    let mut cursor = STUN_HEADER_LEN;
    while cursor + 4 <= attributes_end {
        let attr_type = u16::from_be_bytes([message[cursor], message[cursor + 1]]);
        let attr_len = u16::from_be_bytes([message[cursor + 2], message[cursor + 3]]) as usize;
        let value_start = cursor + 4;
        let value_end = value_start + attr_len;
        if value_end > attributes_end {
            return Err(StunError::InvalidResponse(
                "attribute length exceeds message length".to_string(),
            ));
        }
        if attr_type == XOR_MAPPED_ADDRESS {
            return decode_xor_mapped_address(&message[value_start..value_end], transaction_id);
        }
        cursor = value_end + padding_len(attr_len);
    }

    Err(StunError::InvalidResponse(
        "XOR-MAPPED-ADDRESS attribute missing".to_string(),
    ))
}

fn write_header(
    message: &mut Vec<u8>,
    message_type: u16,
    message_len: u16,
    transaction_id: TransactionId,
) {
    message.extend_from_slice(&message_type.to_be_bytes());
    message.extend_from_slice(&message_len.to_be_bytes());
    message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    message.extend_from_slice(&transaction_id);
}

fn read_header(message: &[u8]) -> Result<(u16, u16, TransactionId), StunError> {
    if message.len() < STUN_HEADER_LEN {
        return Err(StunError::InvalidResponse(
            "message shorter than STUN header".to_string(),
        ));
    }
    let message_type = u16::from_be_bytes([message[0], message[1]]);
    if message_type & 0b1100_0000_0000_0000 != 0 {
        return Err(StunError::InvalidResponse(
            "message does not have STUN leading bits".to_string(),
        ));
    }
    let message_len = u16::from_be_bytes([message[2], message[3]]);
    let expected_len = STUN_HEADER_LEN + message_len as usize;
    if message.len() < expected_len {
        return Err(StunError::InvalidResponse(
            "message length exceeds received datagram".to_string(),
        ));
    }
    if message_len % 4 != 0 {
        return Err(StunError::InvalidResponse(
            "message length is not 32-bit aligned".to_string(),
        ));
    }
    let magic_cookie = u32::from_be_bytes([message[4], message[5], message[6], message[7]]);
    if magic_cookie != MAGIC_COOKIE {
        return Err(StunError::InvalidResponse(
            "magic cookie mismatch".to_string(),
        ));
    }
    let mut transaction_id = [0_u8; 12];
    transaction_id.copy_from_slice(&message[8..STUN_HEADER_LEN]);
    Ok((message_type, message_len, transaction_id))
}

fn write_xor_mapped_address(
    attributes: &mut Vec<u8>,
    transaction_id: TransactionId,
    mapped_addr: SocketAddr,
) -> Result<(), StunError> {
    let mut value = Vec::new();
    value.push(0);
    match mapped_addr.ip() {
        IpAddr::V4(ip) => {
            value.push(0x01);
            let xor_port = mapped_addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            value.extend_from_slice(&xor_port.to_be_bytes());
            let xor_addr = u32::from(ip) ^ MAGIC_COOKIE;
            value.extend_from_slice(&xor_addr.to_be_bytes());
        }
        IpAddr::V6(ip) => {
            value.push(0x02);
            let xor_port = mapped_addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            value.extend_from_slice(&xor_port.to_be_bytes());
            let mask = ipv6_xor_mask(transaction_id);
            for (octet, mask) in ip.octets().iter().zip(mask) {
                value.push(*octet ^ mask);
            }
        }
    }

    write_attribute(attributes, XOR_MAPPED_ADDRESS, &value)
}

fn decode_xor_mapped_address(
    value: &[u8],
    transaction_id: TransactionId,
) -> Result<SocketAddr, StunError> {
    if value.len() < 4 || value[0] != 0 {
        return Err(StunError::InvalidResponse(
            "malformed XOR-MAPPED-ADDRESS attribute".to_string(),
        ));
    }
    let port = u16::from_be_bytes([value[2], value[3]]) ^ ((MAGIC_COOKIE >> 16) as u16);
    match value[1] {
        0x01 => {
            if value.len() != 8 {
                return Err(StunError::InvalidResponse(
                    "malformed IPv4 XOR-MAPPED-ADDRESS".to_string(),
                ));
            }
            let encoded = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let ip = Ipv4Addr::from(encoded ^ MAGIC_COOKIE);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            if value.len() != 20 {
                return Err(StunError::InvalidResponse(
                    "malformed IPv6 XOR-MAPPED-ADDRESS".to_string(),
                ));
            }
            let mask = ipv6_xor_mask(transaction_id);
            let mut octets = [0_u8; 16];
            for index in 0..16 {
                octets[index] = value[4 + index] ^ mask[index];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        family => Err(StunError::InvalidResponse(format!(
            "unsupported XOR-MAPPED-ADDRESS family {family}"
        ))),
    }
}

fn write_attribute(
    attributes: &mut Vec<u8>,
    attr_type: u16,
    value: &[u8],
) -> Result<(), StunError> {
    if value.len() > u16::MAX as usize {
        return Err(StunError::InvalidResponse(
            "attribute value too large".to_string(),
        ));
    }
    attributes.extend_from_slice(&attr_type.to_be_bytes());
    attributes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    attributes.extend_from_slice(value);
    attributes.resize(attributes.len() + padding_len(value.len()), 0);
    Ok(())
}

fn padding_len(value_len: usize) -> usize {
    (4 - (value_len % 4)) % 4
}

fn ipv6_xor_mask(transaction_id: TransactionId) -> [u8; 16] {
    let mut mask = [0_u8; 16];
    mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    mask[4..].copy_from_slice(&transaction_id);
    mask
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use ipars_types::EndpointCandidateKind;

    use super::*;

    #[test]
    fn binding_success_round_trips_xor_mapped_ipv4() -> Result<(), StunError> {
        let transaction_id = [7_u8; 12];
        let mapped_addr = SocketAddr::from(([198, 51, 100, 10], 54_321));
        let response = encode_binding_success_response(transaction_id, mapped_addr)?;

        assert_eq!(
            decode_binding_success_response(&response, transaction_id)?,
            mapped_addr
        );
        Ok(())
    }

    #[test]
    fn binding_success_round_trips_xor_mapped_ipv6() -> Result<(), StunError> {
        let transaction_id = [9_u8; 12];
        let mapped_addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0db8, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006,
            )),
            54_322,
        );
        let response = encode_binding_success_response(transaction_id, mapped_addr)?;

        assert_eq!(
            decode_binding_success_response(&response, transaction_id)?,
            mapped_addr
        );
        Ok(())
    }

    #[test]
    fn binding_success_rejects_transaction_mismatch() -> Result<(), StunError> {
        let response =
            encode_binding_success_response([1_u8; 12], SocketAddr::from(([127, 0, 0, 1], 3478)))?;

        assert!(matches!(
            decode_binding_success_response(&response, [2_u8; 12]),
            Err(StunError::InvalidResponse(message)) if message == "transaction id mismatch"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn udp_probe_returns_reflexive_endpoint_from_binding_response(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = BindingStunServer::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
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

    #[tokio::test]
    async fn binding_server_serves_until_shutdown() -> Result<(), Box<dyn std::error::Error>> {
        let server = BindingStunServer::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let server_addr = server.local_addr()?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move { server.serve(shutdown_rx).await });

        let candidate = UdpStunProbe
            .probe(
                NodeId::from_string("node-a"),
                SocketAddr::from(([127, 0, 0, 1], 0)),
                server_addr,
            )
            .await?;
        assert_eq!(candidate.addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        shutdown_tx.send(true)?;
        server_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn udp_probe_collects_multiple_binding_observations_with_single_socket(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let first_server = BindingStunServer::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let first_server_addr = first_server.local_addr()?;
        let first_task = tokio::spawn(async move { first_server.serve_once().await });
        let second_server = BindingStunServer::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let second_server_addr = second_server.local_addr()?;
        let second_task = tokio::spawn(async move { second_server.serve_once().await });

        let observations = UdpStunProbe
            .observe_binding_many(
                SocketAddr::from(([127, 0, 0, 1], 0)),
                &[first_server_addr, second_server_addr],
            )
            .await?;
        first_task.await??;
        second_task.await??;

        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].stun_server, first_server_addr);
        assert_eq!(observations[1].stun_server, second_server_addr);
        assert_eq!(observations[0].local_addr, observations[1].local_addr);
        assert_eq!(
            observations[0].reflexive_addr,
            observations[1].reflexive_addr
        );
        Ok(())
    }
}
