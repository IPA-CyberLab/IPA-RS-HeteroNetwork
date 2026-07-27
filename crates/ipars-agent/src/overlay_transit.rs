//! Asynchronous UDP transport for bounded multi-hop overlay frames.
//!
//! UDP source endpoints are mapped back to bounded neighbors before a frame is
//! passed to [`BoundedOverlayForwarder`]. This makes the endpoint directory part
//! of the authenticated hop transport contract: callers must populate it from
//! the same trusted neighbor map used to construct the forwarder.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use ipars_relay::multihop::{
    MAX_MULTIHOP_FRAME_BYTES, MAX_MULTIHOP_PAYLOAD_BYTES, MULTIHOP_PATH_ID_BYTES,
};
use ipars_types::{NodeId, OverlayPath};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;

use crate::overlay_forwarder::{
    BoundedOverlayForwarder, OverlayForwardAction, OverlayForwarderError, OverlayPathSelection,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayNeighborEndpoint {
    pub node_id: NodeId,
    pub vpn_ip: IpAddr,
    pub udp_endpoint: SocketAddr,
}

#[derive(Default)]
struct EndpointIndexes {
    by_node: BTreeMap<NodeId, SocketAddr>,
    by_endpoint: HashMap<SocketAddr, NodeId>,
}

/// Atomically replaceable mapping between bounded neighbors and their overlay
/// UDP endpoints.
#[derive(Clone, Default)]
pub struct OverlayNeighborEndpointDirectory {
    indexes: Arc<RwLock<EndpointIndexes>>,
}

impl OverlayNeighborEndpointDirectory {
    pub fn new(
        endpoints: impl IntoIterator<Item = OverlayNeighborEndpoint>,
    ) -> Result<Self, OverlayTransitError> {
        let directory = Self::default();
        directory.replace(endpoints)?;
        Ok(directory)
    }

    pub fn replace(
        &self,
        endpoints: impl IntoIterator<Item = OverlayNeighborEndpoint>,
    ) -> Result<(), OverlayTransitError> {
        let mut replacement = EndpointIndexes::default();
        for endpoint in endpoints {
            validate_endpoint(&endpoint)?;
            if replacement
                .by_node
                .insert(endpoint.node_id.clone(), endpoint.udp_endpoint)
                .is_some()
            {
                return Err(OverlayTransitError::DuplicateNeighbor(endpoint.node_id));
            }
            if let Some(existing) = replacement
                .by_endpoint
                .insert(endpoint.udp_endpoint, endpoint.node_id.clone())
            {
                return Err(OverlayTransitError::DuplicateEndpoint {
                    endpoint: endpoint.udp_endpoint,
                    first: existing,
                    second: endpoint.node_id,
                });
            }
        }

        let mut indexes = self
            .indexes
            .write()
            .unwrap_or_else(|error| error.into_inner());
        *indexes = replacement;
        Ok(())
    }

    pub fn endpoint_for(&self, neighbor: &NodeId) -> Option<SocketAddr> {
        self.indexes
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .by_node
            .get(neighbor)
            .copied()
    }

    pub fn neighbor_for_endpoint(&self, endpoint: SocketAddr) -> Option<NodeId> {
        self.indexes
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .by_endpoint
            .get(&endpoint)
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.indexes
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .by_node
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn validate_endpoint(endpoint: &OverlayNeighborEndpoint) -> Result<(), OverlayTransitError> {
    if endpoint.udp_endpoint.port() == 0 {
        return Err(OverlayTransitError::InvalidEndpoint {
            node_id: endpoint.node_id.clone(),
            reason: "UDP port must be non-zero",
        });
    }
    if endpoint.udp_endpoint.ip() != endpoint.vpn_ip {
        return Err(OverlayTransitError::InvalidEndpoint {
            node_id: endpoint.node_id.clone(),
            reason: "UDP endpoint IP must match the neighbor VPN IP",
        });
    }
    if endpoint.vpn_ip.is_unspecified() || endpoint.vpn_ip.is_multicast() {
        return Err(OverlayTransitError::InvalidEndpoint {
            node_id: endpoint.node_id.clone(),
            reason: "neighbor VPN IP must be unicast",
        });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum OverlayNeighborSendError {
    #[error("bounded neighbor {0} has no UDP endpoint")]
    UnknownNeighbor(NodeId),
    #[error("failed to send overlay frame to {next_hop} at {endpoint}: {source}")]
    Io {
        next_hop: NodeId,
        endpoint: SocketAddr,
        #[source]
        source: io::Error,
    },
}

/// Sending is abstracted so callers can use a transport with stronger
/// authentication than plain UDP while retaining the forwarding state machine.
#[async_trait]
pub trait OverlayNeighborSender: Send + Sync {
    async fn send_frame(
        &self,
        next_hop: &NodeId,
        frame: &[u8],
    ) -> Result<(), OverlayNeighborSendError>;
}

pub struct UdpOverlayNeighborSender {
    socket: Arc<UdpSocket>,
    endpoints: OverlayNeighborEndpointDirectory,
}

impl UdpOverlayNeighborSender {
    pub fn new(socket: Arc<UdpSocket>, endpoints: OverlayNeighborEndpointDirectory) -> Self {
        Self { socket, endpoints }
    }
}

#[async_trait]
impl OverlayNeighborSender for UdpOverlayNeighborSender {
    async fn send_frame(
        &self,
        next_hop: &NodeId,
        frame: &[u8],
    ) -> Result<(), OverlayNeighborSendError> {
        let endpoint = self
            .endpoints
            .endpoint_for(next_hop)
            .ok_or_else(|| OverlayNeighborSendError::UnknownNeighbor(next_hop.clone()))?;
        let sent = self
            .socket
            .send_to(frame, endpoint)
            .await
            .map_err(|source| OverlayNeighborSendError::Io {
                next_hop: next_hop.clone(),
                endpoint,
                source,
            })?;
        if sent != frame.len() {
            return Err(OverlayNeighborSendError::Io {
                next_hop: next_hop.clone(),
                endpoint,
                source: io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("sent {sent} of {} bytes", frame.len()),
                ),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayDelivery {
    pub source: NodeId,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlaySendOutcome {
    pub selection: OverlayPathSelection,
    pub sequence: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OverlayTransitStatsSnapshot {
    pub received_frames: u64,
    pub forwarded_frames: u64,
    pub delivered_frames: u64,
    pub invalid_frames_dropped: u64,
    pub unknown_sources_dropped: u64,
    pub delivery_queue_drops: u64,
    pub send_failures: u64,
}

#[derive(Default)]
struct OverlayTransitStatsInner {
    received_frames: AtomicU64,
    forwarded_frames: AtomicU64,
    delivered_frames: AtomicU64,
    invalid_frames_dropped: AtomicU64,
    unknown_sources_dropped: AtomicU64,
    delivery_queue_drops: AtomicU64,
    send_failures: AtomicU64,
}

#[derive(Clone, Default)]
pub struct OverlayTransitStats {
    inner: Arc<OverlayTransitStatsInner>,
}

impl OverlayTransitStats {
    pub fn snapshot(&self) -> OverlayTransitStatsSnapshot {
        OverlayTransitStatsSnapshot {
            received_frames: self.inner.received_frames.load(Ordering::Relaxed),
            forwarded_frames: self.inner.forwarded_frames.load(Ordering::Relaxed),
            delivered_frames: self.inner.delivered_frames.load(Ordering::Relaxed),
            invalid_frames_dropped: self.inner.invalid_frames_dropped.load(Ordering::Relaxed),
            unknown_sources_dropped: self.inner.unknown_sources_dropped.load(Ordering::Relaxed),
            delivery_queue_drops: self.inner.delivery_queue_drops.load(Ordering::Relaxed),
            send_failures: self.inner.send_failures.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Error)]
pub enum OverlayTransitError {
    #[error("invalid endpoint for {node_id}: {reason}")]
    InvalidEndpoint {
        node_id: NodeId,
        reason: &'static str,
    },
    #[error("duplicate bounded neighbor {0}")]
    DuplicateNeighbor(NodeId),
    #[error("UDP endpoint {endpoint} is shared by bounded neighbors {first} and {second}")]
    DuplicateEndpoint {
        endpoint: SocketAddr,
        first: NodeId,
        second: NodeId,
    },
    #[error("overlay delivery queue capacity must be non-zero")]
    ZeroDeliveryQueueCapacity,
    #[error("overlay forwarding validation failed: {0}")]
    Forwarder(#[from] OverlayForwarderError),
    #[error("overlay neighbor send failed: {0}")]
    Send(#[from] OverlayNeighborSendError),
    #[error("primary send failed ({primary}); secondary path could not be prepared ({secondary})")]
    FailoverPreparation {
        primary: Box<OverlayNeighborSendError>,
        secondary: Box<OverlayForwarderError>,
    },
    #[error("both overlay paths failed: primary ({primary}); secondary ({secondary})")]
    BothPathsFailed {
        primary: Box<OverlayNeighborSendError>,
        secondary: Box<OverlayNeighborSendError>,
    },
    #[error("cannot allocate a secondary sequence after {0}")]
    SequenceOverflow(u64),
    #[error(
        "direct neighbor {peer} must receive its inner datagram through the WireGuard dataplane"
    )]
    DirectNeighborRequiresDataplane { peer: NodeId },
    #[error("overlay transit receive failed: {0}")]
    Receive(#[source] io::Error),
    #[error("overlay transit task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

#[derive(Clone)]
pub struct OverlayTransitClient {
    forwarder: Arc<Mutex<BoundedOverlayForwarder>>,
    sender: Arc<dyn OverlayNeighborSender>,
    stats: OverlayTransitStats,
}

impl OverlayTransitClient {
    /// Send over the primary path without automatic retry.
    pub async fn send(
        &self,
        path: &OverlayPath,
        path_id: [u8; MULTIHOP_PATH_ID_BYTES],
        sequence: u64,
        inner_wireguard_datagram: Vec<u8>,
    ) -> Result<OverlaySendOutcome, OverlayTransitError> {
        let action = {
            let mut forwarder = self.forwarder.lock().await;
            forwarder.encapsulate(path, path_id, sequence, inner_wireguard_datagram)?
        };
        self.send_action(action).await?;
        Ok(OverlaySendOutcome {
            selection: OverlayPathSelection::Primary,
            sequence,
        })
    }

    /// Try primary once, then prepare and send the secondary path once if the
    /// primary UDP send fails. The retry consumes `sequence + 1` because the
    /// forwarder records the primary sequence before attempting I/O.
    pub async fn send_with_secondary_failover(
        &self,
        path: &OverlayPath,
        path_id: [u8; MULTIHOP_PATH_ID_BYTES],
        sequence: u64,
        inner_wireguard_datagram: Vec<u8>,
    ) -> Result<OverlaySendOutcome, OverlayTransitError> {
        let primary = {
            let mut forwarder = self.forwarder.lock().await;
            forwarder.encapsulate(path, path_id, sequence, inner_wireguard_datagram.clone())?
        };
        match self.send_action(primary).await {
            Ok(()) => Ok(OverlaySendOutcome {
                selection: OverlayPathSelection::Primary,
                sequence,
            }),
            Err(OverlayTransitError::Send(primary)) => {
                let secondary_sequence = sequence
                    .checked_add(1)
                    .ok_or(OverlayTransitError::SequenceOverflow(sequence))?;
                let secondary_result = {
                    let mut forwarder = self.forwarder.lock().await;
                    forwarder.encapsulate_selected(
                        path,
                        OverlayPathSelection::Secondary,
                        path_id,
                        secondary_sequence,
                        inner_wireguard_datagram,
                    )
                };
                let secondary = match secondary_result {
                    Ok(secondary) => secondary,
                    Err(secondary) => {
                        return Err(OverlayTransitError::FailoverPreparation {
                            primary: Box::new(primary),
                            secondary: Box::new(secondary),
                        });
                    }
                };
                match self.send_action(secondary).await {
                    Ok(()) => Ok(OverlaySendOutcome {
                        selection: OverlayPathSelection::Secondary,
                        sequence: secondary_sequence,
                    }),
                    Err(OverlayTransitError::Send(secondary)) => {
                        Err(OverlayTransitError::BothPathsFailed {
                            primary: Box::new(primary),
                            secondary: Box::new(secondary),
                        })
                    }
                    Err(other) => Err(other),
                }
            }
            Err(other) => Err(other),
        }
    }

    pub async fn update_neighbor_map(
        &self,
        neighbor_map: ipars_types::NeighborMap,
    ) -> Result<(), OverlayTransitError> {
        self.forwarder
            .lock()
            .await
            .update_neighbor_map(neighbor_map)?;
        Ok(())
    }

    pub fn stats(&self) -> OverlayTransitStats {
        self.stats.clone()
    }

    async fn send_action(&self, action: OverlayForwardAction) -> Result<(), OverlayTransitError> {
        let (next_hop, datagram) = match action {
            OverlayForwardAction::Forward { next_hop, datagram } => (next_hop, datagram),
            OverlayForwardAction::DirectNeighbor { peer, .. } => {
                return Err(OverlayTransitError::DirectNeighborRequiresDataplane { peer });
            }
            OverlayForwardAction::Deliver { .. } => {
                unreachable!("encapsulation never creates a delivery action")
            }
        };
        self.sender
            .send_frame(&next_hop, &datagram)
            .await
            .inspect_err(|_| {
                self.stats
                    .inner
                    .send_failures
                    .fetch_add(1, Ordering::Relaxed);
            })?;
        Ok(())
    }
}

pub struct OverlayTransit {
    client: OverlayTransitClient,
    deliveries: mpsc::Receiver<OverlayDelivery>,
    shutdown_tx: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), OverlayTransitError>>>,
}

impl OverlayTransit {
    pub fn spawn(
        socket: UdpSocket,
        endpoints: OverlayNeighborEndpointDirectory,
        forwarder: BoundedOverlayForwarder,
        delivery_queue_capacity: usize,
    ) -> Result<Self, OverlayTransitError> {
        let socket = Arc::new(socket);
        let sender: Arc<dyn OverlayNeighborSender> = Arc::new(UdpOverlayNeighborSender::new(
            Arc::clone(&socket),
            endpoints.clone(),
        ));
        Self::spawn_with_sender(
            socket,
            endpoints,
            forwarder,
            sender,
            delivery_queue_capacity,
        )
    }

    pub fn spawn_with_sender(
        socket: Arc<UdpSocket>,
        endpoints: OverlayNeighborEndpointDirectory,
        forwarder: BoundedOverlayForwarder,
        sender: Arc<dyn OverlayNeighborSender>,
        delivery_queue_capacity: usize,
    ) -> Result<Self, OverlayTransitError> {
        if delivery_queue_capacity == 0 {
            return Err(OverlayTransitError::ZeroDeliveryQueueCapacity);
        }

        let forwarder = Arc::new(Mutex::new(forwarder));
        let stats = OverlayTransitStats::default();
        let client = OverlayTransitClient {
            forwarder: Arc::clone(&forwarder),
            sender: Arc::clone(&sender),
            stats: stats.clone(),
        };
        let (delivery_tx, deliveries) = mpsc::channel(delivery_queue_capacity);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(run_receive_loop(
            socket,
            endpoints,
            forwarder,
            sender,
            delivery_tx,
            stats,
            shutdown_rx,
        ));

        Ok(Self {
            client,
            deliveries,
            shutdown_tx,
            task: Some(task),
        })
    }

    pub fn client(&self) -> OverlayTransitClient {
        self.client.clone()
    }

    pub fn delivery_receiver(&mut self) -> &mut mpsc::Receiver<OverlayDelivery> {
        &mut self.deliveries
    }

    pub fn stats(&self) -> OverlayTransitStats {
        self.client.stats()
    }

    pub async fn shutdown(mut self) -> Result<(), OverlayTransitError> {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.task.take() {
            task.await??;
        }
        Ok(())
    }
}

impl Drop for OverlayTransit {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayWireGuardPeerForwarderConfig {
    pub wireguard_endpoint: SocketAddr,
    pub injection_endpoint: SocketAddr,
    pub path_id: [u8; MULTIHOP_PATH_ID_BYTES],
    pub initial_sequence: u64,
}

impl OverlayWireGuardPeerForwarderConfig {
    fn validate(self) -> Result<Self, OverlayWireGuardPeerForwarderError> {
        for (name, endpoint) in [
            ("wireguard", self.wireguard_endpoint),
            ("injection", self.injection_endpoint),
        ] {
            if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
                return Err(
                    OverlayWireGuardPeerForwarderError::InvalidConfiguredEndpoint {
                        name,
                        endpoint,
                    },
                );
            }
        }
        if self.wireguard_endpoint == self.injection_endpoint {
            return Err(
                OverlayWireGuardPeerForwarderError::SharedConfiguredEndpoint(
                    self.wireguard_endpoint,
                ),
            );
        }
        if self.path_id.iter().all(|byte| *byte == 0) {
            return Err(OverlayWireGuardPeerForwarderError::ZeroPathId);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OverlayWireGuardPeerForwarderStatsSnapshot {
    pub received_datagrams: u64,
    pub overlay_datagrams_sent: u64,
    pub secondary_failovers: u64,
    pub wireguard_datagrams_injected: u64,
    pub unexpected_sources_dropped: u64,
    pub non_wireguard_datagrams_dropped: u64,
    pub oversized_datagrams_dropped: u64,
    pub overlay_send_failures: u64,
    pub wireguard_injection_failures: u64,
    pub accepted_path_updates: u64,
    pub rejected_path_updates: u64,
    pub sequence_overflows: u64,
}

#[derive(Default)]
struct OverlayWireGuardPeerForwarderStatsInner {
    received_datagrams: AtomicU64,
    overlay_datagrams_sent: AtomicU64,
    secondary_failovers: AtomicU64,
    wireguard_datagrams_injected: AtomicU64,
    unexpected_sources_dropped: AtomicU64,
    non_wireguard_datagrams_dropped: AtomicU64,
    oversized_datagrams_dropped: AtomicU64,
    overlay_send_failures: AtomicU64,
    wireguard_injection_failures: AtomicU64,
    accepted_path_updates: AtomicU64,
    rejected_path_updates: AtomicU64,
    sequence_overflows: AtomicU64,
}

#[derive(Clone, Default)]
pub struct OverlayWireGuardPeerForwarderStats {
    inner: Arc<OverlayWireGuardPeerForwarderStatsInner>,
}

impl OverlayWireGuardPeerForwarderStats {
    pub fn snapshot(&self) -> OverlayWireGuardPeerForwarderStatsSnapshot {
        OverlayWireGuardPeerForwarderStatsSnapshot {
            received_datagrams: self.inner.received_datagrams.load(Ordering::Relaxed),
            overlay_datagrams_sent: self.inner.overlay_datagrams_sent.load(Ordering::Relaxed),
            secondary_failovers: self.inner.secondary_failovers.load(Ordering::Relaxed),
            wireguard_datagrams_injected: self
                .inner
                .wireguard_datagrams_injected
                .load(Ordering::Relaxed),
            unexpected_sources_dropped: self
                .inner
                .unexpected_sources_dropped
                .load(Ordering::Relaxed),
            non_wireguard_datagrams_dropped: self
                .inner
                .non_wireguard_datagrams_dropped
                .load(Ordering::Relaxed),
            oversized_datagrams_dropped: self
                .inner
                .oversized_datagrams_dropped
                .load(Ordering::Relaxed),
            overlay_send_failures: self.inner.overlay_send_failures.load(Ordering::Relaxed),
            wireguard_injection_failures: self
                .inner
                .wireguard_injection_failures
                .load(Ordering::Relaxed),
            accepted_path_updates: self.inner.accepted_path_updates.load(Ordering::Relaxed),
            rejected_path_updates: self.inner.rejected_path_updates.load(Ordering::Relaxed),
            sequence_overflows: self.inner.sequence_overflows.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Error)]
pub enum OverlayWireGuardPeerForwarderError {
    #[error("{name} endpoint {endpoint} must be a loopback address with a non-zero UDP port")]
    InvalidConfiguredEndpoint {
        name: &'static str,
        endpoint: SocketAddr,
    },
    #[error("WireGuard and injection endpoints must differ, but both are {0}")]
    SharedConfiguredEndpoint(SocketAddr),
    #[error("overlay WireGuard path ID must not be all zero")]
    ZeroPathId,
    #[error("invalid initial overlay path: {0}")]
    InvalidInitialPath(String),
    #[error("proxy socket {0} must be bound to a loopback address")]
    NonLoopbackSocket(SocketAddr),
    #[error("overlay WireGuard proxy receive failed: {0}")]
    Receive(#[source] io::Error),
    #[error("overlay WireGuard sequence space is exhausted at {0}")]
    SequenceOverflow(u64),
}

/// Proxies one remote WireGuard peer through a bounded overlay path.
///
/// The supplied socket is the sole local proxy socket. Only datagrams from
/// `wireguard_endpoint` enter the overlay, and only datagrams from
/// `injection_endpoint` are sent back to WireGuard.
pub struct OverlayWireGuardPeerForwarder {
    transit: OverlayTransitClient,
    config: OverlayWireGuardPeerForwarderConfig,
    path_updates: watch::Receiver<OverlayPath>,
    stats: OverlayWireGuardPeerForwarderStats,
}

impl OverlayWireGuardPeerForwarder {
    pub fn new(
        transit: OverlayTransitClient,
        config: OverlayWireGuardPeerForwarderConfig,
        path_updates: watch::Receiver<OverlayPath>,
    ) -> Result<Self, OverlayWireGuardPeerForwarderError> {
        let config = config.validate()?;
        path_updates.borrow().validate().map_err(|error| {
            OverlayWireGuardPeerForwarderError::InvalidInitialPath(error.to_string())
        })?;
        Ok(Self {
            transit,
            config,
            path_updates,
            stats: OverlayWireGuardPeerForwarderStats::default(),
        })
    }

    pub fn stats(&self) -> OverlayWireGuardPeerForwarderStats {
        self.stats.clone()
    }

    pub async fn serve(
        mut self,
        socket: UdpSocket,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), OverlayWireGuardPeerForwarderError> {
        let local_endpoint = socket
            .local_addr()
            .map_err(OverlayWireGuardPeerForwarderError::Receive)?;
        if !local_endpoint.ip().is_loopback() {
            return Err(OverlayWireGuardPeerForwarderError::NonLoopbackSocket(
                local_endpoint,
            ));
        }
        if *shutdown.borrow() {
            return Ok(());
        }

        let mut path = self.path_updates.borrow().clone();
        let path_source = path.source.clone();
        let path_target = path.target.node_id.clone();
        let mut next_sequence = self.config.initial_sequence;
        let mut path_updates_open = true;
        let mut datagram = vec![0_u8; MAX_MULTIHOP_PAYLOAD_BYTES + 1];

        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                changed = self.path_updates.changed(), if path_updates_open => {
                    match changed {
                        Ok(()) => {
                            let candidate = self.path_updates.borrow_and_update().clone();
                            if valid_peer_path_update(
                                &path,
                                &candidate,
                                &path_source,
                                &path_target,
                            ) {
                                path = candidate;
                                self.stats
                                    .inner
                                    .accepted_path_updates
                                    .fetch_add(1, Ordering::Relaxed);
                            } else {
                                self.stats
                                    .inner
                                    .rejected_path_updates
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => path_updates_open = false,
                    }
                }
                received = socket.recv_from(&mut datagram) => {
                    let (length, source) =
                        received.map_err(OverlayWireGuardPeerForwarderError::Receive)?;
                    self.stats
                        .inner
                        .received_datagrams
                        .fetch_add(1, Ordering::Relaxed);
                    if source != self.config.wireguard_endpoint
                        && source != self.config.injection_endpoint
                    {
                        self.stats
                            .inner
                            .unexpected_sources_dropped
                            .fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if length > MAX_MULTIHOP_PAYLOAD_BYTES {
                        self.stats
                            .inner
                            .oversized_datagrams_dropped
                            .fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let payload = &datagram[..length];
                    if !overlay_wireguard_datagram(payload) {
                        self.stats
                            .inner
                            .non_wireguard_datagrams_dropped
                            .fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    if source == self.config.injection_endpoint {
                        match socket.send_to(payload, self.config.wireguard_endpoint).await {
                            Ok(sent) if sent == payload.len() => {
                                self.stats
                                    .inner
                                    .wireguard_datagrams_injected
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(_) | Err(_) => {
                                self.stats
                                    .inner
                                    .wireguard_injection_failures
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        continue;
                    }

                    let Some(reserved_limit) = next_sequence.checked_add(1) else {
                        self.stats
                            .inner
                            .sequence_overflows
                            .fetch_add(1, Ordering::Relaxed);
                        return Err(OverlayWireGuardPeerForwarderError::SequenceOverflow(
                            next_sequence,
                        ));
                    };
                    let result = self
                        .transit
                        .send_with_secondary_failover(
                            &path,
                            self.config.path_id,
                            next_sequence,
                            payload.to_vec(),
                        )
                        .await;
                    next_sequence = reserved_limit
                        .checked_add(1)
                        .unwrap_or(reserved_limit);
                    match result {
                        Ok(outcome) => {
                            self.stats
                                .inner
                                .overlay_datagrams_sent
                                .fetch_add(1, Ordering::Relaxed);
                            if outcome.selection == OverlayPathSelection::Secondary {
                                self.stats
                                    .inner
                                    .secondary_failovers
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
                            self.stats
                                .inner
                                .overlay_send_failures
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }
}

fn valid_peer_path_update(
    current: &OverlayPath,
    candidate: &OverlayPath,
    source: &NodeId,
    target: &NodeId,
) -> bool {
    candidate.validate().is_ok()
        && candidate.source == *source
        && candidate.target.node_id == *target
        && candidate.topology_epoch >= current.topology_epoch
}

fn overlay_wireguard_datagram(payload: &[u8]) -> bool {
    if payload.len() < 4 || payload.get(1..4) != Some(&[0, 0, 0]) {
        return false;
    }
    match payload[0] {
        1 => payload.len() == 148,
        2 => payload.len() == 92,
        3 => payload.len() == 64,
        4 => payload.len() >= 32 && payload.len().is_multiple_of(16),
        _ => false,
    }
}

async fn run_receive_loop(
    socket: Arc<UdpSocket>,
    endpoints: OverlayNeighborEndpointDirectory,
    forwarder: Arc<Mutex<BoundedOverlayForwarder>>,
    sender: Arc<dyn OverlayNeighborSender>,
    deliveries: mpsc::Sender<OverlayDelivery>,
    stats: OverlayTransitStats,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), OverlayTransitError> {
    let mut datagram = vec![0_u8; MAX_MULTIHOP_FRAME_BYTES];
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            received = socket.recv_from(&mut datagram) => {
                let (length, source_endpoint) =
                    received.map_err(OverlayTransitError::Receive)?;
                stats.inner.received_frames.fetch_add(1, Ordering::Relaxed);
                let Some(previous_hop) = endpoints.neighbor_for_endpoint(source_endpoint) else {
                    stats
                        .inner
                        .unknown_sources_dropped
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let action = {
                    let mut forwarder = forwarder.lock().await;
                    forwarder.receive(&previous_hop, &datagram[..length])
                };
                match action {
                    Ok(OverlayForwardAction::Forward { next_hop, datagram }) => {
                        match sender.send_frame(&next_hop, &datagram).await {
                            Ok(()) => {
                                stats
                                    .inner
                                    .forwarded_frames
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_) => {
                                stats.inner.send_failures.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Ok(OverlayForwardAction::Deliver { source, payload }) => {
                        if deliveries.try_send(OverlayDelivery { source, payload }).is_ok() {
                            stats
                                .inner
                                .delivered_frames
                                .fetch_add(1, Ordering::Relaxed);
                        } else {
                            stats
                                .inner
                                .delivery_queue_drops
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Ok(OverlayForwardAction::DirectNeighbor { .. }) => {
                        stats
                            .inner
                            .invalid_frames_dropped
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        stats
                            .inner
                            .invalid_frames_dropped
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, VecDeque};
    use std::error::Error;
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;
    use ipars_relay::multihop::MultiHopEnvelope;
    use ipars_types::{
        ClusterId, NeighborMap, NodeRecord, OverlayNeighbor, OverlayNeighborKind, Role,
        TokenPolicy, VpnIp,
    };
    use tokio::time::{sleep, timeout, Duration};

    use super::*;
    use crate::overlay_forwarder::OverlayForwarderConfig;

    type TestResult = Result<(), Box<dyn Error>>;

    fn node(value: &str) -> NodeId {
        NodeId::from_string(value)
    }

    fn node_octet(value: &str) -> u8 {
        match value {
            "s" => 1,
            "a" => 2,
            "c" => 3,
            "d" => 4,
            _ => 254,
        }
    }

    fn node_record(value: &str) -> NodeRecord {
        NodeRecord {
            node_id: node(value),
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(10, 250, 0, node_octet(value)))),
            identity_public_key: format!("identity-{value}"),
            wireguard_public_key: format!("wireguard-{value}"),
            role: Role::edge(),
            tags: BTreeSet::new(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        }
    }

    fn neighbor_map(local: &str, neighbors: &[&str], epoch: u64) -> NeighborMap {
        NeighborMap {
            cluster_id: ClusterId::from_string("cluster-a"),
            node_id: node(local),
            topology_epoch: epoch,
            max_degree: neighbors.len() as u16,
            vpn_cidr: "10.250.0.0/24"
                .parse()
                .unwrap_or_else(|error| panic!("test CIDR must parse: {error}")),
            neighbors: neighbors
                .iter()
                .map(|neighbor| OverlayNeighbor {
                    node: node_record(neighbor),
                    kind: OverlayNeighborKind::BackbonePrimary,
                })
                .collect(),
            aggregate_routes: Vec::new(),
            bootstrap_endpoints: Vec::new(),
            generated_at: Utc::now(),
        }
    }

    fn forwarder(
        local: &str,
        neighbors: &[&str],
        epoch: u64,
    ) -> Result<BoundedOverlayForwarder, OverlayForwarderError> {
        BoundedOverlayForwarder::new(
            node(local),
            neighbor_map(local, neighbors, epoch),
            OverlayForwarderConfig::default(),
        )
    }

    fn path(primary: &[&str], secondary: Option<&[&str]>, epoch: u64) -> OverlayPath {
        let target = node_record(primary[primary.len() - 1]);
        OverlayPath {
            topology_epoch: epoch,
            source: node(primary[0]),
            destination: target.vpn_ip.0,
            target,
            ordered_nodes: primary.iter().map(|value| node(value)).collect(),
            secondary_ordered_nodes: secondary
                .map(|nodes| nodes.iter().map(|value| node(value)).collect()),
            generated_at: Utc::now(),
        }
    }

    fn endpoint(node_id: &str, udp_endpoint: SocketAddr) -> OverlayNeighborEndpoint {
        OverlayNeighborEndpoint {
            node_id: node(node_id),
            vpn_ip: udp_endpoint.ip(),
            udp_endpoint,
        }
    }

    async fn loopback_socket() -> io::Result<UdpSocket> {
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await
    }

    fn wireguard_datagram(fill: u8) -> Vec<u8> {
        let mut datagram = vec![fill; 32];
        datagram[..4].copy_from_slice(&4_u32.to_le_bytes());
        datagram
    }

    fn peer_forwarder_config(
        wireguard_endpoint: SocketAddr,
        injection_endpoint: SocketAddr,
    ) -> OverlayWireGuardPeerForwarderConfig {
        OverlayWireGuardPeerForwarderConfig {
            wireguard_endpoint,
            injection_endpoint,
            path_id: [9; MULTIHOP_PATH_ID_BYTES],
            initial_sequence: 100,
        }
    }

    #[derive(Default)]
    struct RecordingSender {
        attempted: Mutex<VecDeque<(NodeId, Vec<u8>)>>,
    }

    #[async_trait]
    impl OverlayNeighborSender for RecordingSender {
        async fn send_frame(
            &self,
            next_hop: &NodeId,
            frame: &[u8],
        ) -> Result<(), OverlayNeighborSendError> {
            self.attempted
                .lock()
                .await
                .push_back((next_hop.clone(), frame.to_vec()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn loopback_udp_forwards_and_delivers_opaque_payload() -> TestResult {
        let source_socket = loopback_socket().await?;
        let relay_socket = loopback_socket().await?;
        let destination_socket = loopback_socket().await?;
        let source_address = source_socket.local_addr()?;
        let relay_address = relay_socket.local_addr()?;
        let destination_address = destination_socket.local_addr()?;

        let source_endpoints =
            OverlayNeighborEndpointDirectory::new([endpoint("a", relay_address)])?;
        let relay_endpoints = OverlayNeighborEndpointDirectory::new([
            endpoint("s", source_address),
            endpoint("d", destination_address),
        ])?;
        let destination_endpoints =
            OverlayNeighborEndpointDirectory::new([endpoint("a", relay_address)])?;

        let source = OverlayTransit::spawn(
            source_socket,
            source_endpoints,
            forwarder("s", &["a"], 7)?,
            8,
        )?;
        let relay = OverlayTransit::spawn(
            relay_socket,
            relay_endpoints,
            forwarder("a", &["s", "d"], 7)?,
            8,
        )?;
        let mut destination = OverlayTransit::spawn(
            destination_socket,
            destination_endpoints,
            forwarder("d", &["a"], 7)?,
            8,
        )?;

        let payload = vec![0, 0xff, 0x42, 0, 0x13, 0x37];
        let outcome = source
            .client()
            .send(
                &path(&["s", "a", "d"], None, 7),
                [1; 16],
                1,
                payload.clone(),
            )
            .await?;
        assert_eq!(outcome.selection, OverlayPathSelection::Primary);
        let delivery = timeout(
            Duration::from_secs(2),
            destination.delivery_receiver().recv(),
        )
        .await?
        .ok_or("delivery channel closed")?;
        assert_eq!(
            delivery,
            OverlayDelivery {
                source: node("s"),
                payload,
            }
        );
        assert_eq!(relay.stats().snapshot().forwarded_frames, 1);
        assert_eq!(destination.stats().snapshot().delivered_frames, 1);

        source.shutdown().await?;
        relay.shutdown().await?;
        destination.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn replay_epoch_hop_limit_and_path_violations_are_not_forwarded() -> TestResult {
        let source_socket = loopback_socket().await?;
        let relay_socket = loopback_socket().await?;
        let destination_socket = loopback_socket().await?;
        let source_address = source_socket.local_addr()?;
        let relay_address = relay_socket.local_addr()?;
        let destination_address = destination_socket.local_addr()?;

        let relay_endpoints = OverlayNeighborEndpointDirectory::new([
            endpoint("s", source_address),
            endpoint("d", destination_address),
        ])?;
        let destination_endpoints =
            OverlayNeighborEndpointDirectory::new([endpoint("a", relay_address)])?;
        let relay = OverlayTransit::spawn(
            relay_socket,
            relay_endpoints,
            forwarder("a", &["s", "d"], 8)?,
            8,
        )?;
        let mut destination = OverlayTransit::spawn(
            destination_socket,
            destination_endpoints,
            forwarder("d", &["a"], 8)?,
            8,
        )?;

        let mut current_source = forwarder("s", &["a"], 8)?;
        let valid_frame = match current_source.encapsulate(
            &path(&["s", "a", "d"], None, 8),
            [1; 16],
            1,
            vec![0x42],
        )? {
            OverlayForwardAction::Forward { datagram, .. } => datagram,
            other => panic!("expected forwarding frame, got {other:?}"),
        };
        source_socket.send_to(&valid_frame, relay_address).await?;
        source_socket.send_to(&valid_frame, relay_address).await?;

        let mut stale_source = forwarder("s", &["a"], 7)?;
        let stale_frame = match stale_source.encapsulate(
            &path(&["s", "a", "d"], None, 7),
            [2; 16],
            1,
            vec![1],
        )? {
            OverlayForwardAction::Forward { datagram, .. } => datagram,
            other => panic!("expected forwarding frame, got {other:?}"),
        };
        source_socket.send_to(&stale_frame, relay_address).await?;

        let invalid_hop_limit = MultiHopEnvelope::new(
            8,
            [3; 16],
            1,
            2,
            node("s"),
            node("d"),
            vec![node("a")],
            vec![1],
        )?
        .encode()?;
        source_socket
            .send_to(&invalid_hop_limit, relay_address)
            .await?;

        let invalid_path = MultiHopEnvelope::new(
            8,
            [4; 16],
            1,
            1,
            node("c"),
            node("d"),
            vec![node("a")],
            vec![1],
        )?
        .encode()?;
        source_socket.send_to(&invalid_path, relay_address).await?;

        let delivery = timeout(
            Duration::from_secs(2),
            destination.delivery_receiver().recv(),
        )
        .await?
        .ok_or("delivery channel closed")?;
        assert_eq!(delivery.payload, vec![0x42]);
        sleep(Duration::from_millis(100)).await;
        assert_eq!(relay.stats().snapshot().forwarded_frames, 1);
        assert_eq!(relay.stats().snapshot().invalid_frames_dropped, 4);
        assert!(timeout(
            Duration::from_millis(100),
            destination.delivery_receiver().recv()
        )
        .await
        .is_err());

        relay.shutdown().await?;
        destination.shutdown().await?;
        Ok(())
    }

    struct FailPrimarySender {
        primary: NodeId,
        attempted: Mutex<VecDeque<NodeId>>,
    }

    #[async_trait]
    impl OverlayNeighborSender for FailPrimarySender {
        async fn send_frame(
            &self,
            next_hop: &NodeId,
            _frame: &[u8],
        ) -> Result<(), OverlayNeighborSendError> {
            self.attempted.lock().await.push_back(next_hop.clone());
            if next_hop == &self.primary {
                return Err(OverlayNeighborSendError::Io {
                    next_hop: next_hop.clone(),
                    endpoint: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
                    source: io::Error::new(io::ErrorKind::ConnectionRefused, "test failure"),
                });
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn primary_send_failure_switches_to_secondary_once() -> TestResult {
        let socket = Arc::new(loopback_socket().await?);
        let sender = Arc::new(FailPrimarySender {
            primary: node("a"),
            attempted: Mutex::new(VecDeque::new()),
        });
        let endpoints = OverlayNeighborEndpointDirectory::new([
            endpoint("a", SocketAddr::from((Ipv4Addr::LOCALHOST, 10001))),
            endpoint("c", SocketAddr::from((Ipv4Addr::LOCALHOST, 10002))),
        ])?;
        let transit = OverlayTransit::spawn_with_sender(
            socket,
            endpoints,
            forwarder("s", &["a", "c"], 7)?,
            sender.clone(),
            8,
        )?;

        let outcome = transit
            .client()
            .send_with_secondary_failover(
                &path(&["s", "a", "d"], Some(&["s", "c", "d"]), 7),
                [3; 16],
                40,
                vec![1, 2, 3],
            )
            .await?;
        assert_eq!(
            outcome,
            OverlaySendOutcome {
                selection: OverlayPathSelection::Secondary,
                sequence: 41,
            }
        );
        assert_eq!(
            sender
                .attempted
                .lock()
                .await
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            vec![node("a"), node("c")]
        );
        assert_eq!(transit.stats().snapshot().send_failures, 1);

        timeout(Duration::from_secs(1), transit.shutdown()).await??;
        Ok(())
    }

    #[tokio::test]
    async fn wireguard_peer_forwarder_proxies_both_directions_and_updates_epoch() -> TestResult {
        let transit_socket = Arc::new(loopback_socket().await?);
        let sender = Arc::new(RecordingSender::default());
        let endpoints = OverlayNeighborEndpointDirectory::new([endpoint(
            "a",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 10001)),
        )])?;
        let transit = OverlayTransit::spawn_with_sender(
            transit_socket,
            endpoints,
            forwarder("s", &["a"], 7)?,
            sender.clone(),
            8,
        )?;
        let client = transit.client();

        let wireguard = loopback_socket().await?;
        let injection = loopback_socket().await?;
        let proxy_socket = loopback_socket().await?;
        let wireguard_endpoint = wireguard.local_addr()?;
        let injection_endpoint = injection.local_addr()?;
        let proxy_endpoint = proxy_socket.local_addr()?;
        let (path_tx, path_rx) = watch::channel(path(&["s", "a", "d"], None, 7));
        let proxy = OverlayWireGuardPeerForwarder::new(
            client.clone(),
            peer_forwarder_config(wireguard_endpoint, injection_endpoint),
            path_rx,
        )?;
        let stats = proxy.stats();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let proxy_task = tokio::spawn(proxy.serve(proxy_socket, shutdown_rx));

        client
            .update_neighbor_map(neighbor_map("s", &["a"], 8))
            .await?;
        path_tx.send(path(&["s", "a", "d"], None, 8))?;
        timeout(Duration::from_secs(1), async {
            while stats.snapshot().accepted_path_updates != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        let outbound = wireguard_datagram(0x41);
        wireguard.send_to(&outbound, proxy_endpoint).await?;
        let recorded = timeout(Duration::from_secs(1), async {
            loop {
                if let Some(recorded) = sender.attempted.lock().await.pop_front() {
                    break recorded;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(recorded.0, node("a"));
        let envelope = MultiHopEnvelope::decode(&recorded.1, 1)?;
        assert_eq!(envelope.topology_epoch(), 8);
        assert_eq!(envelope.opaque_payload_len(), outbound.len());

        let inbound = wireguard_datagram(0x52);
        injection.send_to(&inbound, proxy_endpoint).await?;
        let mut received = vec![0_u8; 128];
        let (length, source) =
            timeout(Duration::from_secs(1), wireguard.recv_from(&mut received)).await??;
        assert_eq!(source, proxy_endpoint);
        assert_eq!(&received[..length], inbound);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.overlay_datagrams_sent, 1);
        assert_eq!(snapshot.wireguard_datagrams_injected, 1);
        assert_eq!(snapshot.accepted_path_updates, 1);

        shutdown_tx.send(true)?;
        timeout(Duration::from_secs(1), proxy_task).await???;
        transit.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn wireguard_peer_forwarder_drops_untrusted_invalid_and_oversized_datagrams() -> TestResult
    {
        let transit_socket = Arc::new(loopback_socket().await?);
        let sender = Arc::new(RecordingSender::default());
        let endpoints = OverlayNeighborEndpointDirectory::new([endpoint(
            "a",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 10001)),
        )])?;
        let transit = OverlayTransit::spawn_with_sender(
            transit_socket,
            endpoints,
            forwarder("s", &["a"], 7)?,
            sender.clone(),
            8,
        )?;

        let wireguard = loopback_socket().await?;
        let injection = loopback_socket().await?;
        let unexpected = loopback_socket().await?;
        let proxy_socket = loopback_socket().await?;
        let proxy_endpoint = proxy_socket.local_addr()?;
        let (_path_tx, path_rx) = watch::channel(path(&["s", "a", "d"], None, 7));
        let proxy = OverlayWireGuardPeerForwarder::new(
            transit.client(),
            peer_forwarder_config(wireguard.local_addr()?, injection.local_addr()?),
            path_rx,
        )?;
        let stats = proxy.stats();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let proxy_task = tokio::spawn(proxy.serve(proxy_socket, shutdown_rx));

        unexpected
            .send_to(&wireguard_datagram(0x61), proxy_endpoint)
            .await?;
        wireguard.send_to(b"not-wireguard", proxy_endpoint).await?;
        injection.send_to(b"not-wireguard", proxy_endpoint).await?;
        let mut oversized = vec![0x71; MAX_MULTIHOP_PAYLOAD_BYTES + 1];
        oversized[..4].copy_from_slice(&4_u32.to_le_bytes());
        wireguard.send_to(&oversized, proxy_endpoint).await?;

        timeout(Duration::from_secs(1), async {
            while stats.snapshot().received_datagrams != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.unexpected_sources_dropped, 1);
        assert_eq!(snapshot.non_wireguard_datagrams_dropped, 2);
        assert_eq!(snapshot.oversized_datagrams_dropped, 1);
        assert!(sender.attempted.lock().await.is_empty());
        let mut received = [0_u8; 64];
        assert!(timeout(
            Duration::from_millis(100),
            wireguard.recv_from(&mut received)
        )
        .await
        .is_err());

        shutdown_tx.send(true)?;
        timeout(Duration::from_secs(1), proxy_task).await???;
        transit.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn wireguard_peer_forwarder_uses_secondary_after_primary_send_failure() -> TestResult {
        let transit_socket = Arc::new(loopback_socket().await?);
        let sender = Arc::new(FailPrimarySender {
            primary: node("a"),
            attempted: Mutex::new(VecDeque::new()),
        });
        let endpoints = OverlayNeighborEndpointDirectory::new([
            endpoint("a", SocketAddr::from((Ipv4Addr::LOCALHOST, 10001))),
            endpoint("c", SocketAddr::from((Ipv4Addr::LOCALHOST, 10002))),
        ])?;
        let transit = OverlayTransit::spawn_with_sender(
            transit_socket,
            endpoints,
            forwarder("s", &["a", "c"], 7)?,
            sender.clone(),
            8,
        )?;

        let wireguard = loopback_socket().await?;
        let injection = loopback_socket().await?;
        let proxy_socket = loopback_socket().await?;
        let proxy_endpoint = proxy_socket.local_addr()?;
        let (_path_tx, path_rx) = watch::channel(path(&["s", "a", "d"], Some(&["s", "c", "d"]), 7));
        let proxy = OverlayWireGuardPeerForwarder::new(
            transit.client(),
            peer_forwarder_config(wireguard.local_addr()?, injection.local_addr()?),
            path_rx,
        )?;
        let stats = proxy.stats();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let proxy_task = tokio::spawn(proxy.serve(proxy_socket, shutdown_rx));

        wireguard
            .send_to(&wireguard_datagram(0x81), proxy_endpoint)
            .await?;
        timeout(Duration::from_secs(1), async {
            while stats.snapshot().overlay_datagrams_sent != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(
            sender
                .attempted
                .lock()
                .await
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            vec![node("a"), node("c")]
        );
        assert_eq!(stats.snapshot().secondary_failovers, 1);

        shutdown_tx.send(true)?;
        timeout(Duration::from_secs(1), proxy_task).await???;
        transit.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn wireguard_peer_forwarder_rejects_zero_path_id_and_stops_on_sequence_overflow(
    ) -> TestResult {
        let transit_socket = Arc::new(loopback_socket().await?);
        let sender = Arc::new(RecordingSender::default());
        let endpoints = OverlayNeighborEndpointDirectory::new([endpoint(
            "a",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 10001)),
        )])?;
        let transit = OverlayTransit::spawn_with_sender(
            transit_socket,
            endpoints,
            forwarder("s", &["a"], 7)?,
            sender,
            8,
        )?;
        let wireguard = loopback_socket().await?;
        let injection = loopback_socket().await?;
        let proxy_socket = loopback_socket().await?;
        let proxy_endpoint = proxy_socket.local_addr()?;
        let (_path_tx, path_rx) = watch::channel(path(&["s", "a", "d"], None, 7));
        let mut config = peer_forwarder_config(wireguard.local_addr()?, injection.local_addr()?);
        config.path_id = [0; MULTIHOP_PATH_ID_BYTES];
        assert!(matches!(
            OverlayWireGuardPeerForwarder::new(transit.client(), config, path_rx.clone()),
            Err(OverlayWireGuardPeerForwarderError::ZeroPathId)
        ));

        config.path_id = [1; MULTIHOP_PATH_ID_BYTES];
        config.initial_sequence = u64::MAX;
        let proxy = OverlayWireGuardPeerForwarder::new(transit.client(), config, path_rx)?;
        let stats = proxy.stats();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let proxy_task = tokio::spawn(proxy.serve(proxy_socket, shutdown_rx));
        wireguard
            .send_to(&wireguard_datagram(0x91), proxy_endpoint)
            .await?;
        let error = timeout(Duration::from_secs(1), proxy_task).await??;
        assert!(matches!(
            error,
            Err(OverlayWireGuardPeerForwarderError::SequenceOverflow(
                u64::MAX
            ))
        ));
        assert_eq!(stats.snapshot().sequence_overflows, 1);

        transit.shutdown().await?;
        Ok(())
    }
}
