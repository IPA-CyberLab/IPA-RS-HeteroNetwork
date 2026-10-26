//! Bounded datagram transport over ordinary HTTP requests. WireGuard remains
//! responsible for end-to-end authentication and encryption. No Upgrade, UDP,
//! HTTP/3, or incoming client port is required on the external network.
pub mod tcp;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use ipars_types::api::{DataPlaneTransport, TransportObservation, TransportPhase};
use ipars_types::NodeId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Mutex as AsyncMutex};
use uuid::Uuid;

pub const MAX_PACKET_BYTES: usize = 65_507;
pub const MAX_BATCH_BYTES: usize = 256 * 1024;
pub const MAX_BATCH_PACKETS: usize = 64;
pub const NODE_HEADER: &str = "x-heteronetwork-node";
pub const TIME_HEADER: &str = "x-heteronetwork-time";
pub const NONCE_HEADER: &str = "x-heteronetwork-nonce";
pub const PROOF_HEADER: &str = "x-heteronetwork-proof";
pub const TOKEN_SCHEME: &str = "HeteroNetworkTunnel ";
const POLL_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Domain-separated static X25519 possession proof. It binds the registered
/// WireGuard key, both node IDs, timestamp, nonce, and exact opening packet.
/// This never sends a private key or a fleet-wide admission bearer over HTTP.
#[derive(Clone)]
pub struct TunnelAuth {
    pub gateway: NodeId,
    key: [u8; 32],
}

impl TunnelAuth {
    pub fn new(private: [u8; 32], public: [u8; 32], gateway: NodeId) -> Result<Self, TunnelError> {
        let shared = x25519_dalek::StaticSecret::from(private)
            .diffie_hellman(&x25519_dalek::PublicKey::from(public));
        if !shared.was_contributory() {
            return Err(TunnelError::Unauthorized);
        }
        let mut kdf = Hmac::<Sha256>::new_from_slice(b"heteronetwork-tunnel-auth-v1")
            .map_err(|_| TunnelError::Unauthorized)?;
        kdf.update(shared.as_bytes());
        Ok(Self {
            gateway,
            key: kdf.finalize().into_bytes().into(),
        })
    }

    fn mac(
        &self,
        node: &NodeId,
        timestamp: i64,
        nonce: &str,
        first: &[u8],
    ) -> Result<Hmac<Sha256>, TunnelError> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_| TunnelError::Unauthorized)?;
        mac.update(
            format!(
                "heteronetwork-http-tunnel-v1\n{node}\n{}\n{timestamp}\n{nonce}\n{}\n",
                self.gateway,
                hex::encode(Sha256::digest(first))
            )
            .as_bytes(),
        );
        Ok(mac)
    }

    pub fn proof(
        &self,
        node: &NodeId,
        timestamp: i64,
        nonce: &str,
        first: &[u8],
    ) -> Result<String, TunnelError> {
        Ok(hex::encode(
            self.mac(node, timestamp, nonce, first)?
                .finalize()
                .into_bytes(),
        ))
    }

    pub fn verify(
        &self,
        node: &NodeId,
        timestamp: i64,
        nonce: &str,
        first: &[u8],
        proof: &str,
    ) -> Result<(), TunnelError> {
        if Utc::now().timestamp().abs_diff(timestamp) > 60
            || nonce.len() != 32
            || !nonce.bytes().all(|b| b.is_ascii_hexdigit())
            || proof.len() != 64
        {
            return Err(TunnelError::Unauthorized);
        }
        let decoded = hex::decode(proof).map_err(|_| TunnelError::Unauthorized)?;
        self.mac(node, timestamp, nonce, first)?
            .verify_slice(&decoded)
            .map_err(|_| TunnelError::Unauthorized)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("invalid transport packet")]
    InvalidPacket,
    #[error("transport capacity exceeded")]
    Capacity,
    #[error("transport session is unavailable or expired")]
    Unauthorized,
    #[error("another receive request is active")]
    ConcurrentPoll,
    #[error("transport backend did not respond")]
    BackendTimeout,
    #[error("transport socket failed")]
    Socket(#[from] std::io::Error),
    #[error("transport request failed")]
    Request(#[from] reqwest::Error),
    #[error("transport endpoint returned HTTP {0}")]
    Status(u16),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenResponse {
    pub token: String,
    pub first_packet: Vec<u8>,
}

#[derive(Debug)]
struct Tunnel {
    socket: UdpSocket,
    receiver: AsyncMutex<()>,
    touched: Mutex<Instant>,
    expires_at: Instant,
    observation: Arc<Mutex<TransportObservation>>,
    scope: String,
}

pub struct TunnelHub {
    backend: SocketAddr,
    maximum: usize,
    sessions: AsyncMutex<BTreeMap<String, Arc<Tunnel>>>,
    observations: Mutex<BTreeMap<String, Arc<Mutex<TransportObservation>>>>,
    opening: tokio::sync::Semaphore,
    nonces: Mutex<BTreeMap<(NodeId, String), i64>>,
}

impl std::fmt::Debug for TunnelHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelHub")
            .field("backend", &self.backend)
            .field("maximum", &self.maximum)
            .finish_non_exhaustive()
    }
}

impl TunnelHub {
    pub fn new(backend: SocketAddr, maximum: usize) -> Self {
        Self {
            backend,
            maximum,
            sessions: AsyncMutex::new(BTreeMap::new()),
            observations: Mutex::new(BTreeMap::new()),
            opening: tokio::sync::Semaphore::new(16),
            nonces: Mutex::new(BTreeMap::new()),
        }
    }

    /// The caller must authenticate the first packet against the registered
    /// WireGuard peer or an admitted Relay session before calling this method.
    pub async fn open(
        &self,
        peer: NodeId,
        transport: DataPlaneTransport,
        first: &[u8],
        wait_for_reply: bool,
        lifetime: Duration,
        scope: String,
    ) -> Result<OpenResponse, TunnelError> {
        validate_packet(first)?;
        let _opening = self
            .opening
            .try_acquire()
            .map_err(|_| TunnelError::Capacity)?;
        {
            let mut sessions = self.sessions.lock().await;
            sessions.retain(|_, tunnel| tunnel.alive());
            if sessions.len() >= self.maximum && !sessions.values().any(|t| t.scope == scope) {
                return Err(TunnelError::Capacity);
            }
        }
        let bind = match self.backend.ip() {
            IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(self.backend).await?;
        socket.send(first).await?;
        let mut first_packet = Vec::new();
        if wait_for_reply {
            first_packet.resize(MAX_PACKET_BYTES, 0);
            let len = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut first_packet))
                .await
                .map_err(|_| TunnelError::BackendTimeout)??;
            first_packet.truncate(len);
            if !wireguard_packet(&first_packet) {
                return Err(TunnelError::InvalidPacket);
            }
        }
        // Commit capacity, observation ownership, and token replacement under
        // one session lock after I/O, including concurrent opening requests.
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, tunnel| tunnel.alive());
        if sessions.len() >= self.maximum && !sessions.values().any(|t| t.scope == scope) {
            return Err(TunnelError::Capacity);
        }
        let active_scopes = sessions
            .values()
            .map(|t| t.scope.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let observation = {
            let mut observations = self.observations.lock().unwrap_or_else(|e| e.into_inner());
            observations.retain(|_, status| {
                (Utc::now() - status.lock().unwrap_or_else(|e| e.into_inner()).updated_at)
                    .num_seconds()
                    < 300
            });
            if !observations.contains_key(&scope) && observations.len() >= self.maximum {
                let inactive = observations
                    .iter()
                    .filter(|(key, _)| !active_scopes.contains(*key))
                    .min_by_key(|(_, value)| {
                        value.lock().unwrap_or_else(|e| e.into_inner()).updated_at
                    })
                    .map(|(key, _)| key.clone());
                if let Some(key) = inactive {
                    observations.remove(&key);
                } else {
                    return Err(TunnelError::Capacity);
                }
            }
            observations
                .entry(scope.clone())
                .or_insert_with(|| {
                    Arc::new(Mutex::new(TransportObservation::new(
                        peer,
                        self.backend.to_string(),
                    )))
                })
                .clone()
        };
        update(&observation, |status| {
            status.connection_id = Some(scope.clone());
            if status.transport != transport {
                status.switches += 1;
            }
            status.transport = transport;
            status.direction = ipars_types::api::TransportDirection::Incoming;
            status.phase = TransportPhase::Connected;
            status.endpoint = self.backend.to_string();
            status.fallback_reason = Some("remote_http_tunnel".to_string());
            status.last_error = None;
            status.rx_packets += 1;
            status.rx_bytes += first.len() as u64;
            if !first_packet.is_empty() {
                status.tx_packets += 1;
                status.tx_bytes += first_packet.len() as u64;
            }
        });
        let tunnel = Arc::new(Tunnel {
            socket,
            receiver: AsyncMutex::new(()),
            touched: Mutex::new(Instant::now()),
            expires_at: Instant::now() + lifetime.min(Duration::from_secs(3600)),
            observation,
            scope: scope.clone(),
        });
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        sessions.retain(|_, tunnel| tunnel.alive() && tunnel.scope != scope);
        if sessions.len() >= self.maximum {
            return Err(TunnelError::Capacity);
        }
        sessions.insert(token.clone(), tunnel);
        Ok(OpenResponse {
            token,
            first_packet,
        })
    }

    async fn session(&self, token: &str) -> Result<Arc<Tunnel>, TunnelError> {
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(TunnelError::Unauthorized);
        }
        let mut sessions = self.sessions.lock().await;
        let tunnel = sessions.get(token).filter(|tunnel| tunnel.alive()).cloned();
        if tunnel.is_none() {
            sessions.remove(token);
        }
        let tunnel = tunnel.ok_or(TunnelError::Unauthorized)?;
        *tunnel.touched.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        update(&tunnel.observation, |_| {});
        Ok(tunnel)
    }

    pub async fn send(&self, token: &str, body: &[u8]) -> Result<(), TunnelError> {
        let packets = decode_batch(body)?;
        let tunnel = self.session(token).await?;
        for packet in packets {
            if let Err(error) = tunnel.socket.send(packet).await {
                update(&tunnel.observation, |s| {
                    s.phase = TransportPhase::Failed;
                    s.last_error = Some("backend_socket_failed".to_string());
                });
                return Err(error.into());
            }
            update(&tunnel.observation, |status| {
                status.rx_packets += 1;
                status.rx_bytes += packet.len() as u64;
                status.last_received_at = Some(Utc::now());
            });
        }
        Ok(())
    }

    pub async fn receive(&self, token: &str) -> Result<Vec<u8>, TunnelError> {
        let tunnel = self.session(token).await?;
        let _receiving = tunnel
            .receiver
            .try_lock()
            .map_err(|_| TunnelError::ConcurrentPoll)?;
        let mut buffer = vec![0; MAX_PACKET_BYTES];
        let len = match tokio::time::timeout(POLL_TIMEOUT, tunnel.socket.recv(&mut buffer)).await {
            Ok(len) => len?,
            Err(_) => return Ok(Vec::new()),
        };
        let mut body = Vec::new();
        append_packet(&mut body, &buffer[..len])?;
        let mut count = 1_u64;
        let mut bytes = len as u64;
        while count < MAX_BATCH_PACKETS as u64
            && body.len() + MAX_PACKET_BYTES + 2 <= MAX_BATCH_BYTES
        {
            match tunnel.socket.try_recv(&mut buffer) {
                Ok(len) => {
                    append_packet(&mut body, &buffer[..len])?;
                    count += 1;
                    bytes += len as u64;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        update(&tunnel.observation, |status| {
            status.tx_packets += count;
            status.tx_bytes += bytes;
        });
        Ok(body)
    }

    pub async fn touch(&self, token: &str) -> Result<(), TunnelError> {
        self.session(token).await.map(|_| ())
    }

    pub async fn close(&self, token: &str) {
        self.sessions.lock().await.remove(token);
    }

    pub async fn diagnostics(
        &self,
        token: &str,
        failures: BTreeMap<String, u64>,
    ) -> Result<(), TunnelError> {
        let tunnel = self.session(token).await?;
        update(&tunnel.observation, |status| {
            status.failures = failures;
            status.fallback_reason = Some("udp_probe_timeout".to_string());
        });
        Ok(())
    }

    pub fn consume_nonce(
        &self,
        peer: &NodeId,
        nonce: &str,
        timestamp: i64,
    ) -> Result<(), TunnelError> {
        let mut nonces = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now().timestamp();
        nonces.retain(|_, timestamp| now.abs_diff(*timestamp) <= 60);
        let key = (peer.clone(), nonce.to_string());
        if nonces.contains_key(&key) {
            return Err(TunnelError::Unauthorized);
        }
        if nonces.len() >= self.maximum.saturating_mul(8)
            || nonces.keys().filter(|(node, _)| node == peer).count() >= 8
        {
            return Err(TunnelError::Capacity);
        }
        nonces.insert(key, timestamp);
        Ok(())
    }

    pub fn observations(&self) -> Vec<TransportObservation> {
        self.observations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|status| {
                let mut status = status.lock().unwrap_or_else(|e| e.into_inner()).clone();
                if (Utc::now() - status.updated_at).num_seconds() > 60 {
                    status.phase = TransportPhase::Failed;
                    status.last_error = Some("tunnel_idle_or_closed".to_string());
                }
                status
            })
            .collect()
    }
}

impl Tunnel {
    fn alive(&self) -> bool {
        Instant::now() < self.expires_at
            && self
                .touched
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .elapsed()
                < IDLE_TIMEOUT
    }
}

pub fn wireguard_packet(packet: &[u8]) -> bool {
    if packet.len() < 4 || packet[1..4] != [0, 0, 0] {
        return false;
    }
    match packet[0] {
        1 => packet.len() == 148,
        2 => packet.len() == 92,
        3 => packet.len() == 64,
        4 => packet.len() >= 32 && packet.len() <= MAX_PACKET_BYTES,
        _ => false,
    }
}

fn validate_packet(packet: &[u8]) -> Result<(), TunnelError> {
    if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
        Err(TunnelError::InvalidPacket)
    } else {
        Ok(())
    }
}

pub fn append_packet(body: &mut Vec<u8>, packet: &[u8]) -> Result<(), TunnelError> {
    validate_packet(packet)?;
    if body.len() + packet.len() + 2 > MAX_BATCH_BYTES {
        return Err(TunnelError::InvalidPacket);
    }
    body.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    body.extend_from_slice(packet);
    Ok(())
}

pub fn decode_batch(mut body: &[u8]) -> Result<Vec<&[u8]>, TunnelError> {
    if body.len() > MAX_BATCH_BYTES {
        return Err(TunnelError::InvalidPacket);
    }
    let mut packets = Vec::new();
    while !body.is_empty() {
        if body.len() < 2 || packets.len() >= MAX_BATCH_PACKETS {
            return Err(TunnelError::InvalidPacket);
        }
        let len = u16::from_be_bytes([body[0], body[1]]) as usize;
        body = &body[2..];
        if len == 0 || len > MAX_PACKET_BYTES || body.len() < len {
            return Err(TunnelError::InvalidPacket);
        }
        packets.push(&body[..len]);
        body = &body[len..];
    }
    Ok(packets)
}

pub fn encode_open(
    packet: &[u8],
    failures: &BTreeMap<String, u64>,
) -> Result<Vec<u8>, TunnelError> {
    let diagnostics = serde_json::to_vec(failures).map_err(|_| TunnelError::InvalidPacket)?;
    if diagnostics.len() > 2048 {
        return Err(TunnelError::InvalidPacket);
    }
    let mut body = b"HNT1".to_vec();
    body.extend_from_slice(&(diagnostics.len() as u16).to_be_bytes());
    body.extend_from_slice(&diagnostics);
    body.extend_from_slice(packet);
    Ok(body)
}

pub fn decode_open(body: &[u8]) -> Result<(&[u8], BTreeMap<String, u64>), TunnelError> {
    if body.len() < 6 || &body[..4] != b"HNT1" {
        return Err(TunnelError::InvalidPacket);
    }
    let size = u16::from_be_bytes([body[4], body[5]]) as usize;
    if size > 2048 || body.len() < 6 + size {
        return Err(TunnelError::InvalidPacket);
    }
    let failures: BTreeMap<String, u64> = serde_json_from_bytes(&body[6..6 + size])?;
    if failures.len() > 16
        || failures.keys().any(|key| {
            key.len() > 64
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
    {
        return Err(TunnelError::InvalidPacket);
    }
    Ok((&body[6 + size..], failures))
}

pub fn update(
    status: &Arc<Mutex<TransportObservation>>,
    change: impl FnOnce(&mut TransportObservation),
) {
    let mut status = status.lock().unwrap_or_else(|e| e.into_inner());
    change(&mut status);
    status.updated_at = Utc::now();
}

/// No redirects: a proxy or captive portal must never receive tunnel secrets.
/// reqwest retains certificate verification and normal HTTP(S)_PROXY support.
pub fn http_client() -> Result<reqwest::Client, TunnelError> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(25))
        .pool_max_idle_per_host(2)
        .build()?)
}

pub struct HttpTunnel {
    client: reqwest::Client,
    packets_url: String,
    token: String,
    pub first_packet: Vec<u8>,
}

impl HttpTunnel {
    pub async fn open(
        client: reqwest::Client,
        open_url: &str,
        node: &NodeId,
        first: Vec<u8>,
        auth: Option<&TunnelAuth>,
        failures: &BTreeMap<String, u64>,
    ) -> Result<Self, TunnelError> {
        let first = if auth.is_some() {
            encode_open(&first, failures)?
        } else {
            first
        };
        let url = reqwest::Url::parse(open_url).map_err(|_| TunnelError::InvalidPacket)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(TunnelError::InvalidPacket);
        }
        let mut request = client
            .post(url.clone())
            .header(NODE_HEADER, node.as_str())
            .header("Content-Type", "application/octet-stream")
            .timeout(Duration::from_secs(5));
        if let Some(auth) = auth {
            let timestamp = Utc::now().timestamp();
            let nonce = Uuid::new_v4().simple().to_string();
            request = request
                .header(TIME_HEADER, timestamp.to_string())
                .header(NONCE_HEADER, &nonce)
                .header(PROOF_HEADER, auth.proof(node, timestamp, &nonce, &first)?);
        }
        let response = request.body(first).send().await?;
        if !response.status().is_success() {
            return Err(TunnelError::Status(response.status().as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_BATCH_BYTES as u64)
        {
            return Err(TunnelError::InvalidPacket);
        }
        let mut body = Vec::new();
        let mut response = response;
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_BATCH_BYTES {
                return Err(TunnelError::InvalidPacket);
            }
            body.extend_from_slice(&chunk);
        }
        let opened: OpenResponse = serde_json_from_bytes(&body)?;
        if opened.token.len() != 64
            || !opened.token.bytes().all(|b| b.is_ascii_hexdigit())
            || opened.first_packet.len() > MAX_PACKET_BYTES
        {
            return Err(TunnelError::InvalidPacket);
        }
        let packets_url = open_url
            .strip_suffix("/open")
            .ok_or(TunnelError::InvalidPacket)?
            .to_string()
            + "/packets";
        Ok(Self {
            client,
            packets_url,
            token: opened.token,
            first_packet: opened.first_packet,
        })
    }

    pub async fn send(&self, body: Vec<u8>) -> Result<(), TunnelError> {
        decode_batch(&body)?;
        let response = self
            .client
            .post(&self.packets_url)
            .header("Authorization", format!("{TOKEN_SCHEME}{}", self.token))
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(TunnelError::Status(response.status().as_u16()))
        }
    }

    pub async fn receive(&self) -> Result<Vec<Vec<u8>>, TunnelError> {
        let mut response = self
            .client
            .get(&self.packets_url)
            .header("Authorization", format!("{TOKEN_SCHEME}{}", self.token))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(TunnelError::Status(response.status().as_u16()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_BATCH_BYTES {
                return Err(TunnelError::InvalidPacket);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(decode_batch(&body)?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect())
    }
}

fn serde_json_from_bytes<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, TunnelError> {
    serde_json::from_slice(body).map_err(|_| TunnelError::InvalidPacket)
}

enum ReliableTunnel {
    Tcp(tcp::TcpTunnel),
    Http(HttpTunnel),
}
impl ReliableTunnel {
    fn first_packet(&self) -> &[u8] {
        match self {
            Self::Tcp(_) => &[],
            Self::Http(tunnel) => &tunnel.first_packet,
        }
    }
    async fn send(&self, body: Vec<u8>) -> Result<(), TunnelError> {
        match self {
            Self::Tcp(tunnel) => tunnel.send(body).await,
            Self::Http(tunnel) => tunnel.send(body).await,
        }
    }
    async fn receive(&self) -> Result<Vec<Vec<u8>>, TunnelError> {
        match self {
            Self::Tcp(tunnel) => tunnel.receive().await,
            Self::Http(tunnel) => tunnel.receive().await,
        }
    }
}
#[derive(Clone)]
pub struct RelayEnvelope {
    pub announcement: Vec<u8>,
    pub prefix: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

/// A stable loopback endpoint prevents OS tunnel/service reinstalls on a
/// transport change. All queues and retry rates are bounded per active peer.
pub struct DatagramProxy {
    pub node: NodeId,
    pub peer: NodeId,
    pub udp_endpoint: SocketAddr,
    pub wireguard_endpoint: SocketAddr,
    pub open_urls: Vec<String>,
    pub tcp_endpoints: Vec<SocketAddr>,
    pub relay: Option<RelayEnvelope>,
    pub auth: Option<TunnelAuth>,
    pub status: Arc<Mutex<TransportObservation>>,
    pub forwarding_enabled: Option<Arc<std::sync::atomic::AtomicBool>>,
}

struct AbortTask(tokio::task::JoinHandle<()>);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl DatagramProxy {
    fn encoded(&self, packet: &[u8]) -> Vec<u8> {
        if let Some(relay) = &self.relay {
            // Relay V2 encodes payload size implicitly after its fixed route.
            let mut framed = relay.prefix.clone();
            framed.extend_from_slice(packet);
            framed
        } else {
            packet.to_vec()
        }
    }

    pub async fn serve(
        self,
        local: UdpSocket,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), TunnelError> {
        let bind = if self.udp_endpoint.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let network = match UdpSocket::bind(bind).await {
            Ok(socket) => socket,
            Err(_) if self.udp_endpoint.is_ipv6() => UdpSocket::bind("0.0.0.0:0").await?,
            Err(error) => return Err(error.into()),
        };
        let client = http_client()?;
        let mut local_buffer = vec![0; MAX_PACKET_BYTES];
        let mut network_buffer = vec![0; MAX_PACKET_BYTES];
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        let mut first_pending: Option<Vec<u8>> = None;
        let mut pending = std::collections::VecDeque::new();
        let mut deadline = Instant::now() + Duration::from_secs(3);
        let mut retry_at = Instant::now();
        let mut retry_delay = Duration::from_secs(1);
        let (event_tx, mut event_rx) =
            mpsc::channel::<(u64, Result<Vec<u8>, ()>)>(MAX_BATCH_PACKETS);
        let mut generation = 0_u64;
        let mut return_udp_after = Instant::now();
        let mut http_task: Option<AbortTask> = None;
        let mut http_tx: Option<mpsc::Sender<Vec<u8>>> = None;
        let mut received_udp = false;
        let mut last_udp_received = Instant::now();
        let mut next_udp_probe = Instant::now();
        let mut udp_probe_pending: Option<(Vec<u8>, Instant)> = None;
        if let Some(relay) = &self.relay {
            let _ = network
                .send_to(&relay.announcement, self.udp_endpoint)
                .await;
        }
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { break; }
                }
                packet = local.recv_from(&mut local_buffer) => {
                    let (len, source) = packet?;
                    if source != self.wireguard_endpoint || !wireguard_packet(&local_buffer[..len]) { continue; }
                    if self.forwarding_enabled.as_ref().is_some_and(|enabled| !enabled.load(std::sync::atomic::Ordering::Relaxed)) { continue; }
                    if self.relay.as_ref().is_some_and(|r| r.expires_at <= Utc::now()) { break; }
                    let packet = local_buffer[..len].to_vec();
                    if received_udp && packet.len()>32 && last_udp_received.elapsed() > Duration::from_secs(20) { received_udp = false; }
                    if first_pending.is_none() && packet.len()>32 {
                        first_pending = Some(packet.clone()); deadline = Instant::now() + Duration::from_secs(if packet[0]==1 {3} else {12});
                    }
                    if let Some(sender) = &http_tx {
                        let probing = packet.len() > 32 && Instant::now() >= next_udp_probe;
                        if probing {
                            let probe = self.relay.as_ref().map(|r| r.announcement.clone()).unwrap_or_else(|| packet.clone());
                            let _ = network.send_to(&probe, self.udp_endpoint).await;
                            next_udp_probe = Instant::now() + Duration::from_secs(60);
                        }
                        if probing && self.relay.is_none() {
                            // A duplicate WireGuard counter sent concurrently
                            // over HTTP would be discarded by the receiver.
                            udp_probe_pending = Some((self.encoded(&packet), Instant::now()+Duration::from_secs(2)));
                        } else if sender.try_send(self.encoded(&packet)).is_err() {
                            update(&self.status, |s| s.last_error = Some("send_queue_full".to_string()));
                        }
                    } else {
                        let _ = network.send_to(&self.encoded(&packet), self.udp_endpoint).await;
                        if !received_udp && pending.len() < MAX_BATCH_PACKETS { pending.push_back(packet); }
                    }
                    update(&self.status, |s| { s.tx_packets += 1; s.tx_bytes += len as u64; });
                }
                packet = network.recv_from(&mut network_buffer) => {
                    let (len, source) = match packet { Ok(packet) => packet, Err(_) => continue };
                    if source != self.udp_endpoint { continue; }
                    let announcement_ack = self.relay.as_ref().is_some_and(|r| network_buffer[..len] == r.announcement);
                    if !announcement_ack && !wireguard_packet(&network_buffer[..len]) { continue; }
                    last_udp_received = Instant::now();
                    if http_task.is_some() && Instant::now() < return_udp_after {
                        if !announcement_ack { local.send_to(&network_buffer[..len], self.wireguard_endpoint).await?; }
                        continue;
                    }
                    received_udp = true;
                    udp_probe_pending = None;
                    first_pending = None; pending.clear();
                    if let Some(task) = http_task.take() { generation = generation.wrapping_add(1); task.0.abort(); }
                    http_tx = None;
                    update(&self.status, |s| {
                        if s.transport != DataPlaneTransport::Udp { s.switches += 1; }
                        s.transport = DataPlaneTransport::Udp; s.phase = TransportPhase::Connected;
                        s.endpoint = self.udp_endpoint.to_string(); s.last_error = None;
                        s.last_received_at = Some(Utc::now());
                    });
                    if !announcement_ack {
                        local.send_to(&network_buffer[..len], self.wireguard_endpoint).await?;
                        update(&self.status, |s| { s.rx_packets += 1; s.rx_bytes += len as u64; });
                    }
                }
                event = event_rx.recv(), if http_task.is_some() => {
                    let event = match event { Some((tag,event)) if tag==generation => Some(event), _ => continue };
                    match event {
                        Some(Ok(packet)) => {
                            if packet.is_empty() { update(&self.status, |_| {}); }
                            if wireguard_packet(&packet) {
                                local.send_to(&packet, self.wireguard_endpoint).await?;
                                update(&self.status, |s| {
                                    s.phase = TransportPhase::Connected; s.last_error = None;
                                    s.rx_packets += 1; s.rx_bytes += packet.len() as u64;
                                    s.last_received_at = Some(Utc::now());
                                });
                            }
                        }
                        _ => {
                            if let Some(task) = http_task.take() { task.0.abort(); }
                            http_tx = None; received_udp = false;
                            retry_at = Instant::now() + retry_delay;
                            retry_delay = (retry_delay * 2).min(Duration::from_secs(30));
                            update(&self.status, |s| { s.phase = TransportPhase::Reconnecting; s.reconnects += 1; s.last_error = Some(if s.transport==DataPlaneTransport::Tcp{"tcp_tunnel_unavailable"}else{"http_tunnel_unavailable"}.to_string()); });
                        }
                    }
                }
                _ = tick.tick() => {
                    if udp_probe_pending.as_ref().is_some_and(|(_,at)|Instant::now()>=*at) {
                        if let Some((packet,_))=udp_probe_pending.take() {
                            if let Some(sender)=&http_tx { let _=sender.try_send(packet); }
                        }
                    }
                    if self.relay.as_ref().is_some_and(|r| r.expires_at <= Utc::now()) { break; }
                    if received_udp || http_task.is_some() || Instant::now() < deadline || Instant::now() < retry_at { continue; }
                    let Some(first) = first_pending.clone() else { continue; };
                    let initial = self.relay.as_ref().map(|r| r.announcement.clone()).unwrap_or(first);
                    generation = generation.wrapping_add(1);
                    let http_generation = generation;
                    return_udp_after = Instant::now() + Duration::from_secs(30);
                    next_udp_probe = Instant::now() + Duration::from_secs(60);
                    let node = self.node.clone(); let urls = self.open_urls.clone();
                    let tcp_endpoints = self.tcp_endpoints.clone();
                    let auth = self.auth.clone();
                    let status = self.status.clone(); let client = client.clone(); let events = event_tx.clone();
                    let (sender, mut outgoing) = mpsc::channel::<Vec<u8>>(MAX_BATCH_PACKETS);
                    let mut queued = Vec::new();
                    while let Some(packet) = pending.pop_front() { queued.push(self.encoded(&packet)); }
                    http_tx = Some(sender);
                    update(&self.status, |s| {
                        s.phase = TransportPhase::Reconnecting; s.fallback_reason = Some("udp_probe_timeout".to_string());
                        *s.failures.entry("udp_probe_timeout".to_string()).or_default() += 1;
                    });
                    http_task = Some(AbortTask(tokio::spawn(async move {
                        let mut opened = None;
                        let candidates=tcp_endpoints.into_iter().map(|endpoint|format!("tcp://{endpoint}")).chain(urls);
                        for url in candidates {
                            let failures = status.lock().unwrap_or_else(|e| e.into_inner()).failures.clone();
                            let result=if let Some(endpoint)=url.strip_prefix("tcp://") {
                                match endpoint.parse::<SocketAddr>() {
                                    Ok(endpoint)=>tcp::TcpTunnel::open(endpoint,&node,initial.clone(),auth.as_ref(),&failures).await.map(ReliableTunnel::Tcp),
                                    Err(_)=>Err(TunnelError::InvalidPacket),
                                }
                            }else{HttpTunnel::open(client.clone(), &url, &node, initial.clone(), auth.as_ref(), &failures).await.map(ReliableTunnel::Http)};
                            match result {
                                Ok(tunnel) => {
                                    update(&status, |s| {
                                        let transport = if url.starts_with("tcp:"){DataPlaneTransport::Tcp}else if url.starts_with("https:") { DataPlaneTransport::Https } else { DataPlaneTransport::Http };
                                        if s.transport != transport { s.switches += 1; }
                                        s.transport = transport; s.endpoint = url; s.last_error = None;
                                        s.phase = TransportPhase::Connected;
                                    });
                                    opened = Some(tunnel); break;
                                }
                                Err(error) => {
                                    let protocol = if url.starts_with("tcp:"){"tcp"}else if url.starts_with("https:") { "https" } else { "http" };
                                    let reason = match error {
                                        TunnelError::Status(407) => "proxy_authentication_required",
                                        TunnelError::Status(401 | 403) => "authentication_failed",
                                        TunnelError::Status(429) => "capacity_exceeded",
                                        _ => "unavailable",
                                    };
                                    update(&status, |s| { *s.failures.entry(format!("{protocol}_{reason}")).or_default() += 1; });
                                    continue;
                                },
                            }
                        }
                        let Some(tunnel) = opened else { let _ = events.send((http_generation, Err(()))).await; return; };
                        let tunnel = Arc::new(tunnel);
                        if !tunnel.first_packet().is_empty() && events.send((http_generation, Ok(tunnel.first_packet().to_vec()))).await.is_err() { return; }
                        {
                            for packet in queued {
                                let mut body = Vec::new();
                                if append_packet(&mut body, &packet).is_err() || tunnel.send(body).await.is_err() { let _ = events.send((http_generation, Err(()))).await; return; }
                            }
                        }
                        let receiving = tunnel.clone();
                        let received = events.clone();
                        let mut receiver = AbortTask(tokio::spawn(async move {
                            loop {
                                match receiving.receive().await {
                                    Ok(packets) => {
                                        if packets.is_empty() && received.send((http_generation, Ok(Vec::new()))).await.is_err() { return; }
                                        for packet in packets { if received.send((http_generation, Ok(packet))).await.is_err() { return; } }
                                    },
                                    Err(_) => { let _ = received.send((http_generation, Err(()))).await; return; }
                                }
                            }
                        }));
                        loop {
                            tokio::select! {
                                _ = &mut receiver.0 => break,
                                packet = outgoing.recv() => {
                                    let Some(packet) = packet else { break; };
                                    let mut body = Vec::new();
                                    if append_packet(&mut body, &packet).is_err() { break; }
                                    while body.len() + MAX_PACKET_BYTES + 2 <= MAX_BATCH_BYTES {
                                        let Ok(packet) = outgoing.try_recv() else { break; };
                                        if append_packet(&mut body, &packet).is_err() { break; }
                                    }
                                    if tunnel.send(body).await.is_err() { break; }
                                }
                            }
                        }
                        receiver.0.abort();
                        let _ = events.send((http_generation, Err(()))).await;
                    })));
                }
            }
        }
        if let Some(task) = http_task {
            task.0.abort();
        }
        update(&self.status, |s| {
            s.phase = TransportPhase::Failed;
            s.last_error = Some("tunnel_stopped".to_string());
        });
        Ok(())
    }
}
