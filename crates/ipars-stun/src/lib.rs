use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use ipars_types::{
    endpoint_addr_is_usable, CandidateSource, EndpointCandidate, EndpointCandidateKind,
    NatFilteringObservation, NatFilteringProbeKind, NatProbeObservation, NodeId,
};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::watch;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const CHANGE_REQUEST: u16 = 0x0003;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const RESPONSE_ORIGIN: u16 = 0x802b;
const OTHER_ADDRESS: u16 = 0x802c;
const STUN_HEADER_LEN: usize = 20;
const MAGIC_COOKIE: u32 = 0x2112_A442;
const CHANGE_REQUEST_CHANGE_IP: u32 = 0x04;
const CHANGE_REQUEST_CHANGE_PORT: u32 = 0x02;
const BINDING_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);
const FILTERING_PROBE_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Debug, Error)]
pub enum StunError {
    #[error("stun socket error: {0}")]
    Socket(#[from] std::io::Error),
    #[error("stun response is invalid: {0}")]
    InvalidResponse(String),
    #[error("stun request to {stun_server} timed out after {timeout:?}")]
    Timeout {
        stun_server: SocketAddr,
        timeout: Duration,
    },
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
        validate_stun_server(stun_server)?;
        let socket = UdpSocket::bind(local_bind).await?;
        observe_binding_with_socket(&socket, stun_server).await
    }

    pub async fn observe_binding_many(
        &self,
        local_bind: SocketAddr,
        stun_servers: &[SocketAddr],
    ) -> Result<Vec<NatProbeObservation>, StunError> {
        validate_stun_servers(stun_servers)?;
        let socket = UdpSocket::bind(local_bind).await?;
        let mut observations = Vec::with_capacity(stun_servers.len().max(2));
        let mut alternate_servers = Vec::new();
        let mut first_error = None;
        for stun_server in stun_servers {
            match observe_binding_details_with_socket(
                &socket,
                *stun_server,
                BindingRequestOptions::default(),
            )
            .await
            {
                Ok(response) => {
                    if let Some(other_address) = response.other_address.filter(|other_address| {
                        endpoint_addr_is_usable(*other_address)
                            && *other_address != *stun_server
                            && !stun_servers.contains(other_address)
                    }) {
                        if !alternate_servers.contains(&other_address) {
                            alternate_servers.push(other_address);
                        }
                    }
                    observations.push(
                        binding_observation_from_response(&socket, *stun_server, response).await?,
                    );
                }
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }

        // One RFC 5780 service can provide the second destination needed to
        // distinguish endpoint-independent from destination-dependent mapping.
        if observations.len() < 2 {
            for alternate_server in alternate_servers {
                match observe_binding_with_socket(&socket, alternate_server).await {
                    Ok(observation) => observations.push(observation),
                    Err(error) if first_error.is_none() => first_error = Some(error),
                    Err(_) => {}
                }
                if observations.len() >= 2 {
                    break;
                }
            }
        }
        if observations.is_empty() {
            return Err(first_error.unwrap_or_else(|| {
                StunError::InvalidResponse("no STUN server returned an observation".to_string())
            }));
        }
        Ok(observations)
    }

    pub async fn observe_filtering(
        &self,
        local_bind: SocketAddr,
        stun_server: SocketAddr,
    ) -> Result<Vec<NatFilteringObservation>, StunError> {
        validate_stun_server(stun_server)?;
        let socket = UdpSocket::bind(local_bind).await?;
        let baseline = match tokio::time::timeout(
            FILTERING_PROBE_TIMEOUT,
            observe_binding_details_with_socket(
                &socket,
                stun_server,
                BindingRequestOptions::same_address(),
            ),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return Err(error),
            Err(_) => return Ok(Vec::new()),
        };
        let Some(other_address) = baseline.other_address else {
            return Ok(Vec::new());
        };
        let local_addr = concrete_local_addr(socket.local_addr()?, stun_server).await?;
        let mut observations = vec![NatFilteringObservation {
            local_addr,
            stun_server,
            probe: NatFilteringProbeKind::SameAddress,
            response_origin: baseline.response_origin.or(Some(stun_server)),
            other_address: Some(other_address),
            observed_at: Utc::now(),
        }];

        let change_address_and_port = observe_filtering_probe_with_socket(
            &socket,
            stun_server,
            NatFilteringProbeKind::ChangeAddressAndPort,
            BindingRequestOptions::change_address_and_port(),
            Some(other_address),
        )
        .await?;
        let received_changed_address = change_address_and_port.response_origin.is_some();
        observations.push(change_address_and_port);

        if !received_changed_address {
            observations.push(
                observe_filtering_probe_with_socket(
                    &socket,
                    stun_server,
                    NatFilteringProbeKind::ChangePort,
                    BindingRequestOptions::change_port(),
                    Some(other_address),
                )
                .await?,
            );
        }

        Ok(observations)
    }
}

fn validate_stun_servers(stun_servers: &[SocketAddr]) -> Result<(), StunError> {
    for stun_server in stun_servers {
        validate_stun_server(*stun_server)?;
    }
    Ok(())
}

fn validate_stun_server(stun_server: SocketAddr) -> Result<(), StunError> {
    if !endpoint_addr_is_usable(stun_server) {
        return Err(StunError::InvalidResponse(format!(
            "STUN server {stun_server} is unusable"
        )));
    }
    Ok(())
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StunServerMetricsSnapshot {
    pub binding_request_count: u64,
    pub binding_response_count: u64,
    pub invalid_packet_count: u64,
    pub socket_receive_error_count: u64,
    pub socket_send_error_count: u64,
}

#[derive(Debug, Default)]
pub struct StunServerStats {
    binding_request_count: AtomicU64,
    binding_response_count: AtomicU64,
    invalid_packet_count: AtomicU64,
    socket_receive_error_count: AtomicU64,
    socket_send_error_count: AtomicU64,
}

impl StunServerStats {
    pub fn snapshot(&self) -> StunServerMetricsSnapshot {
        StunServerMetricsSnapshot {
            binding_request_count: self.binding_request_count.load(Ordering::Relaxed),
            binding_response_count: self.binding_response_count.load(Ordering::Relaxed),
            invalid_packet_count: self.invalid_packet_count.load(Ordering::Relaxed),
            socket_receive_error_count: self.socket_receive_error_count.load(Ordering::Relaxed),
            socket_send_error_count: self.socket_send_error_count.load(Ordering::Relaxed),
        }
    }

    fn record_binding_request(&self) {
        self.binding_request_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_binding_response(&self) {
        self.binding_response_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_invalid_packet(&self) {
        self.invalid_packet_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_socket_receive_error(&self) {
        self.socket_receive_error_count
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_socket_send_error(&self) {
        self.socket_send_error_count.fetch_add(1, Ordering::Relaxed);
    }
}

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
        self.serve_once_inner(None).await
    }

    pub async fn serve_once_with_stats(&self, stats: &StunServerStats) -> Result<(), StunError> {
        self.serve_once_inner(Some(stats)).await
    }

    async fn serve_once_inner(&self, stats: Option<&StunServerStats>) -> Result<(), StunError> {
        let mut buffer = [0_u8; 1500];
        let (len, peer) = match self.socket.recv_from(&mut buffer).await {
            Ok(packet) => packet,
            Err(error) => {
                if let Some(stats) = stats {
                    stats.record_socket_receive_error();
                }
                return Err(error.into());
            }
        };
        respond_to_binding_request(
            &self.socket,
            &buffer[..len],
            peer,
            Some(self.socket.local_addr()?),
            None,
            stats,
        )
        .await
    }

    pub async fn serve(self, shutdown: watch::Receiver<bool>) -> Result<(), StunError> {
        self.serve_inner(shutdown, None).await
    }

    pub async fn serve_with_stats(
        self,
        shutdown: watch::Receiver<bool>,
        stats: Arc<StunServerStats>,
    ) -> Result<(), StunError> {
        self.serve_inner(shutdown, Some(stats)).await
    }

    async fn serve_inner(
        self,
        mut shutdown: watch::Receiver<bool>,
        stats: Option<Arc<StunServerStats>>,
    ) -> Result<(), StunError> {
        let mut buffer = [0_u8; 1500];
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                packet = self.socket.recv_from(&mut buffer) => {
                    let (len, peer) = match packet {
                        Ok(packet) => packet,
                        Err(error) => {
                            if let Some(stats) = stats.as_deref() {
                                stats.record_socket_receive_error();
                            }
                            return Err(error.into());
                        }
                    };
                    respond_to_binding_request(
                        &self.socket,
                        &buffer[..len],
                            peer,
                            Some(self.socket.local_addr()?),
                            None,
                        stats.as_deref(),
                    )
                    .await?;
                }
            }
        }
    }
}

async fn respond_to_binding_request(
    response_socket: &UdpSocket,
    request_bytes: &[u8],
    peer: SocketAddr,
    response_origin: Option<SocketAddr>,
    other_address: Option<SocketAddr>,
    stats: Option<&StunServerStats>,
) -> Result<(), StunError> {
    let request = match decode_binding_request(request_bytes) {
        Ok(request) => request,
        Err(_) => {
            if let Some(stats) = stats {
                stats.record_invalid_packet();
            }
            return Ok(());
        }
    };
    if let Some(stats) = stats {
        stats.record_binding_request();
    }
    let response_origin = match response_origin {
        Some(addr) => Some(concrete_local_addr(addr, peer).await?),
        None => None,
    };
    let other_address = match other_address {
        Some(addr) => Some(concrete_local_addr(addr, peer).await?),
        None => None,
    };
    let response = encode_binding_success_response_with_attrs(
        request.transaction_id,
        peer,
        response_origin,
        other_address,
    )?;
    if let Err(error) = response_socket.send_to(&response, peer).await {
        if let Some(stats) = stats {
            stats.record_socket_send_error();
        }
        return Err(error.into());
    }
    if let Some(stats) = stats {
        stats.record_binding_response();
    }
    Ok(())
}

pub struct Rfc5780StunServer {
    primary: UdpSocket,
    alternate: UdpSocket,
}

impl Rfc5780StunServer {
    pub async fn bind(
        primary_addr: SocketAddr,
        alternate_addr: SocketAddr,
    ) -> Result<Self, StunError> {
        Ok(Self {
            primary: UdpSocket::bind(primary_addr).await?,
            alternate: UdpSocket::bind(alternate_addr).await?,
        })
    }

    pub fn primary_addr(&self) -> Result<SocketAddr, StunError> {
        Ok(self.primary.local_addr()?)
    }

    pub fn alternate_addr(&self) -> Result<SocketAddr, StunError> {
        Ok(self.alternate.local_addr()?)
    }

    pub async fn serve_once(&self) -> Result<(), StunError> {
        self.serve_once_inner(None).await
    }

    pub async fn serve_once_with_stats(&self, stats: &StunServerStats) -> Result<(), StunError> {
        self.serve_once_inner(Some(stats)).await
    }

    async fn serve_once_inner(&self, stats: Option<&StunServerStats>) -> Result<(), StunError> {
        let mut primary_buffer = [0_u8; 1500];
        let mut alternate_buffer = [0_u8; 1500];
        tokio::select! {
            packet = self.primary.recv_from(&mut primary_buffer) => {
                let (len, peer) = match packet {
                    Ok(packet) => packet,
                    Err(error) => {
                        if let Some(stats) = stats {
                            stats.record_socket_receive_error();
                        }
                        return Err(error.into());
                    }
                };
                self.respond_to_request(&self.primary, &self.alternate, &primary_buffer[..len], peer, stats).await
            }
            packet = self.alternate.recv_from(&mut alternate_buffer) => {
                let (len, peer) = match packet {
                    Ok(packet) => packet,
                    Err(error) => {
                        if let Some(stats) = stats {
                            stats.record_socket_receive_error();
                        }
                        return Err(error.into());
                    }
                };
                self.respond_to_request(&self.alternate, &self.primary, &alternate_buffer[..len], peer, stats).await
            }
        }
    }

    pub async fn serve(self, shutdown: watch::Receiver<bool>) -> Result<(), StunError> {
        self.serve_inner(shutdown, None).await
    }

    pub async fn serve_with_stats(
        self,
        shutdown: watch::Receiver<bool>,
        stats: Arc<StunServerStats>,
    ) -> Result<(), StunError> {
        self.serve_inner(shutdown, Some(stats)).await
    }

    async fn serve_inner(
        self,
        mut shutdown: watch::Receiver<bool>,
        stats: Option<Arc<StunServerStats>>,
    ) -> Result<(), StunError> {
        let mut primary_buffer = [0_u8; 1500];
        let mut alternate_buffer = [0_u8; 1500];
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                packet = self.primary.recv_from(&mut primary_buffer) => {
                    let (len, peer) = match packet {
                        Ok(packet) => packet,
                        Err(error) => {
                            if let Some(stats) = stats.as_deref() {
                                stats.record_socket_receive_error();
                            }
                            return Err(error.into());
                        }
                    };
                    self.respond_to_request(&self.primary, &self.alternate, &primary_buffer[..len], peer, stats.as_deref()).await?;
                }
                packet = self.alternate.recv_from(&mut alternate_buffer) => {
                    let (len, peer) = match packet {
                        Ok(packet) => packet,
                        Err(error) => {
                            if let Some(stats) = stats.as_deref() {
                                stats.record_socket_receive_error();
                            }
                            return Err(error.into());
                        }
                    };
                    self.respond_to_request(&self.alternate, &self.primary, &alternate_buffer[..len], peer, stats.as_deref()).await?;
                }
            }
        }
    }

    async fn respond_to_request(
        &self,
        received_on: &UdpSocket,
        other_socket: &UdpSocket,
        request_bytes: &[u8],
        peer: SocketAddr,
        stats: Option<&StunServerStats>,
    ) -> Result<(), StunError> {
        let request = match decode_binding_request(request_bytes) {
            Ok(request) => request,
            Err(_) => {
                if let Some(stats) = stats {
                    stats.record_invalid_packet();
                }
                return Ok(());
            }
        };
        if let Some(stats) = stats {
            stats.record_binding_request();
        }
        let response_socket = if request.options.change_ip || request.options.change_port {
            other_socket
        } else {
            received_on
        };
        let response_origin = concrete_local_addr(response_socket.local_addr()?, peer).await?;
        let other_address = concrete_local_addr(other_socket.local_addr()?, peer).await?;
        let response = encode_binding_success_response_with_attrs(
            request.transaction_id,
            peer,
            Some(response_origin),
            Some(other_address),
        )?;
        if let Err(error) = response_socket.send_to(&response, peer).await {
            if let Some(stats) = stats {
                stats.record_socket_send_error();
            }
            return Err(error.into());
        }
        if let Some(stats) = stats {
            stats.record_binding_response();
        }
        Ok(())
    }
}

type TransactionId = [u8; 12];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct BindingRequestOptions {
    change_ip: bool,
    change_port: bool,
}

impl BindingRequestOptions {
    fn same_address() -> Self {
        Self::default()
    }

    fn change_port() -> Self {
        Self {
            change_ip: false,
            change_port: true,
        }
    }

    fn change_address_and_port() -> Self {
        Self {
            change_ip: true,
            change_port: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BindingRequest {
    transaction_id: TransactionId,
    options: BindingRequestOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BindingResponse {
    mapped_addr: SocketAddr,
    response_origin: Option<SocketAddr>,
    other_address: Option<SocketAddr>,
}

async fn observe_binding_with_socket(
    socket: &UdpSocket,
    stun_server: SocketAddr,
) -> Result<NatProbeObservation, StunError> {
    let response =
        observe_binding_details_with_socket(socket, stun_server, BindingRequestOptions::default())
            .await?;
    binding_observation_from_response(socket, stun_server, response).await
}

async fn binding_observation_from_response(
    socket: &UdpSocket,
    stun_server: SocketAddr,
    response: BindingResponse,
) -> Result<NatProbeObservation, StunError> {
    Ok(NatProbeObservation {
        local_addr: concrete_local_addr(socket.local_addr()?, stun_server).await?,
        stun_server,
        reflexive_addr: response.mapped_addr,
        observed_at: Utc::now(),
    })
}

async fn observe_binding_details_with_socket(
    socket: &UdpSocket,
    stun_server: SocketAddr,
    options: BindingRequestOptions,
) -> Result<BindingResponse, StunError> {
    let transaction_id = new_transaction_id();
    let request = encode_binding_request(transaction_id, options)?;
    socket.send_to(&request, stun_server).await?;
    let mut buffer = [0_u8; 1500];
    let (len, _server_addr) =
        match tokio::time::timeout(BINDING_RESPONSE_TIMEOUT, socket.recv_from(&mut buffer)).await {
            Ok(response) => response?,
            Err(_) => {
                return Err(StunError::Timeout {
                    stun_server,
                    timeout: BINDING_RESPONSE_TIMEOUT,
                })
            }
        };
    decode_binding_success_response_details(&buffer[..len], transaction_id)
}

async fn observe_filtering_probe_with_socket(
    socket: &UdpSocket,
    stun_server: SocketAddr,
    probe: NatFilteringProbeKind,
    options: BindingRequestOptions,
    other_address: Option<SocketAddr>,
) -> Result<NatFilteringObservation, StunError> {
    let observed_at = Utc::now();
    let response = match tokio::time::timeout(
        FILTERING_PROBE_TIMEOUT,
        observe_binding_details_with_socket(socket, stun_server, options),
    )
    .await
    {
        Ok(Ok(response)) => Some(response),
        Ok(Err(error)) => return Err(error),
        Err(_) => None,
    };

    Ok(NatFilteringObservation {
        local_addr: concrete_local_addr(socket.local_addr()?, stun_server).await?,
        stun_server,
        probe,
        response_origin: response.and_then(|response| response.response_origin),
        other_address: response
            .and_then(|response| response.other_address)
            .or(other_address),
        observed_at,
    })
}

async fn concrete_local_addr(
    bound_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> Result<SocketAddr, StunError> {
    if !bound_addr.ip().is_unspecified() {
        return Ok(bound_addr);
    }

    let route_bind = match remote_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let route_socket = UdpSocket::bind(route_bind).await?;
    route_socket.connect(remote_addr).await?;
    Ok(SocketAddr::new(
        route_socket.local_addr()?.ip(),
        bound_addr.port(),
    ))
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

fn encode_binding_request(
    transaction_id: TransactionId,
    options: BindingRequestOptions,
) -> Result<Vec<u8>, StunError> {
    let mut attributes = Vec::new();
    if options.change_ip || options.change_port {
        write_change_request(&mut attributes, options)?;
    }
    let mut message = Vec::with_capacity(STUN_HEADER_LEN + attributes.len());
    write_header(
        &mut message,
        BINDING_REQUEST,
        attributes.len() as u16,
        transaction_id,
    );
    message.extend_from_slice(&attributes);
    Ok(message)
}

fn decode_binding_request(message: &[u8]) -> Result<BindingRequest, StunError> {
    let (message_type, message_len, transaction_id) = read_header(message)?;
    if message_type != BINDING_REQUEST {
        return Err(StunError::InvalidResponse(format!(
            "expected binding request, got message type 0x{message_type:04x}"
        )));
    }
    let mut options = BindingRequestOptions::default();
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
        if attr_type == CHANGE_REQUEST {
            options = decode_change_request(&message[value_start..value_end])?;
        }
        cursor = value_end + padding_len(attr_len);
    }
    Ok(BindingRequest {
        transaction_id,
        options,
    })
}

fn encode_binding_success_response_with_attrs(
    transaction_id: TransactionId,
    mapped_addr: SocketAddr,
    response_origin: Option<SocketAddr>,
    other_address: Option<SocketAddr>,
) -> Result<Vec<u8>, StunError> {
    let mut attributes = Vec::new();
    write_xor_mapped_address(&mut attributes, transaction_id, mapped_addr)?;
    if let Some(response_origin) = response_origin {
        write_address_attribute(&mut attributes, RESPONSE_ORIGIN, response_origin)?;
    }
    if let Some(other_address) = other_address {
        write_address_attribute(&mut attributes, OTHER_ADDRESS, other_address)?;
    }
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

fn decode_binding_success_response_details(
    message: &[u8],
    expected_transaction_id: TransactionId,
) -> Result<BindingResponse, StunError> {
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
    let mut mapped_addr = None;
    let mut response_origin = None;
    let mut other_address = None;
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
            mapped_addr = Some(decode_xor_mapped_address(
                &message[value_start..value_end],
                transaction_id,
            )?);
        } else if attr_type == RESPONSE_ORIGIN {
            response_origin = Some(decode_address_attribute(&message[value_start..value_end])?);
        } else if attr_type == OTHER_ADDRESS {
            other_address = Some(decode_address_attribute(&message[value_start..value_end])?);
        }
        cursor = value_end + padding_len(attr_len);
    }

    let mapped_addr = mapped_addr.ok_or_else(|| {
        StunError::InvalidResponse("XOR-MAPPED-ADDRESS attribute missing".to_string())
    })?;
    Ok(BindingResponse {
        mapped_addr,
        response_origin,
        other_address,
    })
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
    if !message_len.is_multiple_of(4) {
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

fn write_change_request(
    attributes: &mut Vec<u8>,
    options: BindingRequestOptions,
) -> Result<(), StunError> {
    let mut flags = 0_u32;
    if options.change_ip {
        flags |= CHANGE_REQUEST_CHANGE_IP;
    }
    if options.change_port {
        flags |= CHANGE_REQUEST_CHANGE_PORT;
    }
    write_attribute(attributes, CHANGE_REQUEST, &flags.to_be_bytes())
}

fn decode_change_request(value: &[u8]) -> Result<BindingRequestOptions, StunError> {
    if value.len() != 4 {
        return Err(StunError::InvalidResponse(
            "malformed CHANGE-REQUEST attribute".to_string(),
        ));
    }
    let flags = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
    Ok(BindingRequestOptions {
        change_ip: flags & CHANGE_REQUEST_CHANGE_IP != 0,
        change_port: flags & CHANGE_REQUEST_CHANGE_PORT != 0,
    })
}

fn write_address_attribute(
    attributes: &mut Vec<u8>,
    attr_type: u16,
    addr: SocketAddr,
) -> Result<(), StunError> {
    let mut value = Vec::new();
    value.push(0);
    match addr.ip() {
        IpAddr::V4(ip) => {
            value.push(0x01);
            value.extend_from_slice(&addr.port().to_be_bytes());
            value.extend_from_slice(&u32::from(ip).to_be_bytes());
        }
        IpAddr::V6(ip) => {
            value.push(0x02);
            value.extend_from_slice(&addr.port().to_be_bytes());
            value.extend_from_slice(&ip.octets());
        }
    }
    write_attribute(attributes, attr_type, &value)
}

fn decode_address_attribute(value: &[u8]) -> Result<SocketAddr, StunError> {
    if value.len() < 4 || value[0] != 0 {
        return Err(StunError::InvalidResponse(
            "malformed address attribute".to_string(),
        ));
    }
    let port = u16::from_be_bytes([value[2], value[3]]);
    match value[1] {
        0x01 => {
            if value.len() != 8 {
                return Err(StunError::InvalidResponse(
                    "malformed IPv4 address attribute".to_string(),
                ));
            }
            let ip = Ipv4Addr::from(u32::from_be_bytes([value[4], value[5], value[6], value[7]]));
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            if value.len() != 20 {
                return Err(StunError::InvalidResponse(
                    "malformed IPv6 address attribute".to_string(),
                ));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&value[4..20]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        family => Err(StunError::InvalidResponse(format!(
            "unsupported address attribute family {family}"
        ))),
    }
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
        let response =
            encode_binding_success_response_with_attrs(transaction_id, mapped_addr, None, None)?;

        assert_eq!(
            decode_binding_success_response_details(&response, transaction_id)?.mapped_addr,
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
        let response =
            encode_binding_success_response_with_attrs(transaction_id, mapped_addr, None, None)?;

        assert_eq!(
            decode_binding_success_response_details(&response, transaction_id)?.mapped_addr,
            mapped_addr
        );
        Ok(())
    }

    #[test]
    fn binding_request_round_trips_change_request_options() -> Result<(), StunError> {
        let transaction_id = [3_u8; 12];
        let request = encode_binding_request(
            transaction_id,
            BindingRequestOptions::change_address_and_port(),
        )?;

        assert_eq!(
            decode_binding_request(&request)?,
            BindingRequest {
                transaction_id,
                options: BindingRequestOptions {
                    change_ip: true,
                    change_port: true,
                },
            }
        );
        Ok(())
    }

    #[test]
    fn binding_success_round_trips_rfc5780_addresses() -> Result<(), StunError> {
        let transaction_id = [5_u8; 12];
        let mapped_addr = SocketAddr::from(([198, 51, 100, 10], 54_321));
        let response_origin = SocketAddr::from(([203, 0, 113, 10], 3478));
        let other_address = SocketAddr::from(([203, 0, 113, 11], 3479));
        let response = encode_binding_success_response_with_attrs(
            transaction_id,
            mapped_addr,
            Some(response_origin),
            Some(other_address),
        )?;

        assert_eq!(
            decode_binding_success_response_details(&response, transaction_id)?,
            BindingResponse {
                mapped_addr,
                response_origin: Some(response_origin),
                other_address: Some(other_address),
            }
        );
        Ok(())
    }

    #[test]
    fn binding_success_rejects_transaction_mismatch() -> Result<(), StunError> {
        let response = encode_binding_success_response_with_attrs(
            [1_u8; 12],
            SocketAddr::from(([127, 0, 0, 1], 3478)),
            None,
            None,
        )?;

        assert!(matches!(
            decode_binding_success_response_details(&response, [2_u8; 12]),
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
    async fn udp_probe_reports_concrete_local_address_for_wildcard_bind(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = BindingStunServer::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move { server.serve_once().await });

        let observation = UdpStunProbe
            .observe_binding(SocketAddr::from(([0, 0, 0, 0], 0)), server_addr)
            .await?;
        server_task.await??;

        assert_eq!(observation.local_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(observation.local_addr.port(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn udp_probe_rejects_unusable_stun_servers_before_send() {
        let error = UdpStunProbe
            .probe(
                NodeId::from_string("node-a"),
                SocketAddr::from(([127, 0, 0, 1], 0)),
                SocketAddr::from(([203, 0, 113, 10], 0)),
            )
            .await;
        assert!(matches!(
            error,
            Err(StunError::InvalidResponse(message))
                if message.contains("STUN server 203.0.113.10:0 is unusable")
        ));

        let error = UdpStunProbe
            .observe_binding_many(
                SocketAddr::from(([127, 0, 0, 1], 0)),
                &[
                    SocketAddr::from(([203, 0, 113, 10], 3478)),
                    SocketAddr::from(([0, 0, 0, 0], 3478)),
                ],
            )
            .await;
        assert!(matches!(
            error,
            Err(StunError::InvalidResponse(message))
                if message.contains("STUN server 0.0.0.0:3478 is unusable")
        ));

        let error = UdpStunProbe
            .observe_filtering(
                SocketAddr::from(([127, 0, 0, 1], 0)),
                SocketAddr::from(([224, 0, 0, 1], 3478)),
            )
            .await;
        assert!(matches!(
            error,
            Err(StunError::InvalidResponse(message))
                if message.contains("STUN server 224.0.0.1:3478 is unusable")
        ));
    }

    #[tokio::test]
    async fn udp_probe_times_out_when_server_does_not_answer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let unused_addr = socket.local_addr()?;
        drop(socket);

        let error = UdpStunProbe
            .probe(
                NodeId::from_string("node-a"),
                SocketAddr::from(([127, 0, 0, 1], 0)),
                unused_addr,
            )
            .await;
        assert!(matches!(
            error,
            Err(StunError::Timeout { stun_server, .. }) if stun_server == unused_addr
        ));
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
    async fn binding_server_stats_count_valid_and_invalid_packets(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = BindingStunServer::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let server_addr = server.local_addr()?;
        let stats = Arc::new(StunServerStats::default());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_stats = stats.clone();
        let server_task =
            tokio::spawn(async move { server.serve_with_stats(shutdown_rx, server_stats).await });

        let invalid_sender = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        invalid_sender
            .send_to(b"not-a-stun-binding-request", server_addr)
            .await?;

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
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.binding_request_count, 1);
        assert_eq!(snapshot.binding_response_count, 1);
        assert_eq!(snapshot.invalid_packet_count, 1);
        assert_eq!(snapshot.socket_receive_error_count, 0);
        assert_eq!(snapshot.socket_send_error_count, 0);
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

    #[tokio::test]
    async fn udp_probe_uses_rfc5780_other_address_for_second_mapping_observation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = Rfc5780StunServer::bind(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .await?;
        let primary_addr = server.primary_addr()?;
        let alternate_addr = server.alternate_addr()?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move { server.serve(shutdown_rx).await });

        let observations = UdpStunProbe
            .observe_binding_many(SocketAddr::from(([127, 0, 0, 1], 0)), &[primary_addr])
            .await?;

        shutdown_tx.send(true)?;
        server_task.await??;
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].stun_server, primary_addr);
        assert_eq!(observations[1].stun_server, alternate_addr);
        assert_eq!(observations[0].local_addr, observations[1].local_addr);
        assert_eq!(
            observations[0].reflexive_addr,
            observations[1].reflexive_addr
        );
        Ok(())
    }

    #[tokio::test]
    async fn udp_probe_keeps_observations_when_an_earlier_server_is_unavailable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let unavailable = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let unavailable_addr = unavailable.local_addr()?;
        let available = BindingStunServer::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let available_addr = available.local_addr()?;
        let available_task = tokio::spawn(async move { available.serve_once().await });

        let observations = UdpStunProbe
            .observe_binding_many(
                SocketAddr::from(([127, 0, 0, 1], 0)),
                &[unavailable_addr, available_addr],
            )
            .await?;
        available_task.await??;

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].stun_server, available_addr);
        Ok(())
    }

    #[tokio::test]
    async fn udp_probe_leaves_filtering_unknown_without_other_address(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = BindingStunServer::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move { server.serve_once().await });

        let observations = UdpStunProbe
            .observe_filtering(SocketAddr::from(([127, 0, 0, 1], 0)), server_addr)
            .await?;
        server_task.await??;

        assert!(observations.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn udp_probe_observes_endpoint_independent_filtering_with_rfc5780_server(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = Rfc5780StunServer::bind(
            SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::from(([0, 0, 0, 0], 0)),
        )
        .await?;
        let primary_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            server.primary_addr()?.port(),
        );
        let alternate_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            server.alternate_addr()?.port(),
        );
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move { server.serve(shutdown_rx).await });

        let observations = UdpStunProbe
            .observe_filtering(SocketAddr::from(([0, 0, 0, 0], 0)), primary_addr)
            .await?;

        shutdown_tx.send(true)?;
        server_task.await??;

        assert_eq!(observations.len(), 2);
        assert_eq!(
            observations[0].local_addr.ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_ne!(observations[0].local_addr.port(), 0);
        assert_eq!(observations[0].local_addr, observations[1].local_addr);
        assert_eq!(observations[0].probe, NatFilteringProbeKind::SameAddress);
        assert_eq!(observations[0].response_origin, Some(primary_addr));
        assert_eq!(observations[0].other_address, Some(alternate_addr));
        assert_eq!(
            observations[1].probe,
            NatFilteringProbeKind::ChangeAddressAndPort
        );
        assert_eq!(observations[1].response_origin, Some(alternate_addr));
        assert_eq!(observations[1].other_address, Some(alternate_addr));
        Ok(())
    }

    #[tokio::test]
    async fn rfc5780_server_stats_count_filtering_probes_and_invalid_packets(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = Rfc5780StunServer::bind(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .await?;
        let primary_addr = server.primary_addr()?;
        let stats = Arc::new(StunServerStats::default());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_stats = stats.clone();
        let server_task =
            tokio::spawn(async move { server.serve_with_stats(shutdown_rx, server_stats).await });

        let invalid_sender = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        invalid_sender
            .send_to(b"not-a-stun-binding-request", primary_addr)
            .await?;

        let observations = UdpStunProbe
            .observe_filtering(SocketAddr::from(([127, 0, 0, 1], 0)), primary_addr)
            .await?;

        shutdown_tx.send(true)?;
        server_task.await??;
        assert_eq!(observations.len(), 2);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.binding_request_count, 2);
        assert_eq!(snapshot.binding_response_count, 2);
        assert_eq!(snapshot.invalid_packet_count, 1);
        assert_eq!(snapshot.socket_receive_error_count, 0);
        assert_eq!(snapshot.socket_send_error_count, 0);
        Ok(())
    }
}
