//! In-process userspace WireGuard backend.
//!
//! The backend uses BoringTun's standard UAPI surface instead of spawning a
//! second process.  That keeps key and peer configuration inside the agent
//! while still allowing an operator to provide a pre-opened TUN file
//! descriptor from a rootless container runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use boringtun::device::tun::TunSocket;
use boringtun::device::{DeviceConfig, DeviceHandle};

use ipars_crypto::{
    decode_wireguard_private_key_b64, decode_wireguard_public_key_b64, encode_bytes,
};
use ipars_route_manager::{with_linux_network_namespace, LinuxNetworkNamespace};

use super::{
    AgentError, WireGuardBackend, WireGuardPeerConfig, WireGuardPeerInventorySource,
    WireGuardPeerTelemetry, WireGuardPeerTelemetrySource,
};

#[derive(Clone)]
struct BoringTunUapi {
    stream: Arc<Mutex<UnixStream>>,
    // Dropping DeviceHandle signals all event-loop threads to stop.  The
    // handle must live as long as the UAPI client because it owns the TUN fd.
    device: Arc<Mutex<Option<DeviceHandle>>>,
}

impl fmt::Debug for BoringTunUapi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoringTunUapi")
            .field("device_active", &self.device_active())
            .finish()
    }
}

impl BoringTunUapi {
    fn new(interface: &str, tun_fd: Option<i32>) -> Result<Self, AgentError> {
        let tun_name = tun_fd
            .map(|fd| fd.to_string())
            .unwrap_or_else(|| interface.to_string());
        let tun = TunSocket::new(&tun_name).map_err(|error| {
            AgentError::WireGuard(format!(
                "failed to open userspace WireGuard TUN `{interface}` (source `{tun_name}`): {error}"
            ))
        })?;
        let tun_raw_fd = tun.as_raw_fd();
        let (client, server) = UnixStream::pair().map_err(|error| {
            AgentError::WireGuard(format!(
                "failed to create userspace WireGuard UAPI socket for `{interface}`: {error}"
            ))
        })?;
        let server_fd = server.as_raw_fd();
        let config = DeviceConfig {
            n_threads: 1,
            use_connected_socket: true,
            use_multi_queue: false,
            uapi_fd: server_fd,
        };
        let device = match DeviceHandle::new(&tun_raw_fd.to_string(), config) {
            Ok(device) => device,
            Err(error) => {
                return Err(AgentError::WireGuard(format!(
                    "failed to start in-process userspace WireGuard `{interface}`: {error}"
                )))
            }
        };

        // DeviceHandle now owns the raw TUN and UAPI descriptors.  The
        // original wrappers must not close those descriptors on return.
        std::mem::forget(tun);
        std::mem::forget(server);

        Ok(Self {
            stream: Arc::new(Mutex::new(client)),
            device: Arc::new(Mutex::new(Some(device))),
        })
    }

    fn device_active(&self) -> bool {
        self.device
            .lock()
            .map(|device| device.is_some())
            .unwrap_or(false)
    }

    fn set_device(&self, private_key_b64: &str, listen_port: u16) -> Result<(), AgentError> {
        let private_key = decode_wireguard_private_key_b64(private_key_b64).map_err(|error| {
            AgentError::WireGuard(format!("invalid userspace WireGuard private key: {error}"))
        })?;
        let private_key = hex::encode(private_key);
        self.transact(
            "set=1",
            &[
                format!("private_key={private_key}"),
                format!("listen_port={listen_port}"),
            ],
        )?;
        Ok(())
    }

    fn upsert_peer(&self, config: &WireGuardPeerConfig) -> Result<(), AgentError> {
        let public_key = decode_wireguard_public_key_b64(&config.public_key).map_err(|error| {
            AgentError::WireGuard(format!(
                "invalid userspace WireGuard peer public key: {error}"
            ))
        })?;
        let mut lines = vec![
            format!("public_key={}", hex::encode(public_key)),
            "replace_allowed_ips=true".to_string(),
        ];
        if let Some(endpoint) = config.endpoint.as_deref() {
            validate_uapi_value(endpoint, "WireGuard endpoint")?;
            let _: SocketAddr = endpoint.parse().map_err(|error| {
                AgentError::WireGuard(format!("invalid WireGuard endpoint `{endpoint}`: {error}"))
            })?;
            lines.push(format!("endpoint={endpoint}"));
        }
        if let Some(keepalive) = config.persistent_keepalive_seconds {
            lines.push(format!("persistent_keepalive_interval={keepalive}"));
        }
        for allowed_ip in &config.allowed_ips {
            validate_uapi_value(allowed_ip, "WireGuard allowed IP")?;
            lines.push(format!("allowed_ip={allowed_ip}"));
        }
        lines.push("protocol_version=1".to_string());
        self.transact("set=1", &lines)?;
        Ok(())
    }

    fn remove_peer_by_public_key(&self, public_key: &str) -> Result<(), AgentError> {
        let public_key = decode_wireguard_public_key_b64(public_key).map_err(|error| {
            AgentError::WireGuard(format!(
                "invalid userspace WireGuard peer public key: {error}"
            ))
        })?;
        self.transact(
            "set=1",
            &[
                format!("public_key={}", hex::encode(public_key)),
                "remove=true".to_string(),
                "protocol_version=1".to_string(),
            ],
        )?;
        Ok(())
    }

    fn get(&self) -> Result<Vec<String>, AgentError> {
        self.transact("get=1", &[])
    }

    fn transact(&self, command: &str, lines: &[String]) -> Result<Vec<String>, AgentError> {
        validate_uapi_value(command, "WireGuard UAPI command")?;
        let mut stream = self.stream.lock().map_err(|_| {
            AgentError::WireGuard("userspace WireGuard UAPI lock was poisoned".to_string())
        })?;
        stream.write_all(command.as_bytes())?;
        stream.write_all(b"\n")?;
        for line in lines {
            validate_uapi_value(line, "WireGuard UAPI value")?;
            stream.write_all(line.as_bytes())?;
            stream.write_all(b"\n")?;
        }
        stream.write_all(b"\n")?;
        stream.flush()?;

        let mut reader = BufReader::new(&mut *stream);
        let mut response = Vec::new();
        let mut line = String::new();
        loop {
            line.clear();
            let read = reader.read_line(&mut line)?;
            if read == 0 {
                return Err(AgentError::WireGuard(
                    "userspace WireGuard UAPI closed unexpectedly".to_string(),
                ));
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                break;
            }
            response.push(line.to_string());
        }
        let errno = response
            .iter()
            .find_map(|line| line.strip_prefix("errno="))
            .ok_or_else(|| {
                AgentError::WireGuard("userspace WireGuard UAPI response omitted errno".to_string())
            })?;
        if errno != "0" {
            return Err(AgentError::WireGuard(format!(
                "userspace WireGuard UAPI request `{command}` failed with errno {errno}"
            )));
        }
        Ok(response)
    }
}

fn validate_uapi_value(value: &str, label: &str) -> Result<(), AgentError> {
    if value.is_empty() || value.contains(['\0', '\r', '\n']) {
        return Err(AgentError::WireGuard(format!(
            "{label} must be non-empty and must not contain NUL or newline characters"
        )));
    }
    Ok(())
}

pub struct BoringTunWireGuardBackend {
    interface: String,
    uapi: Arc<BoringTunUapi>,
    peer_public_keys: Arc<tokio::sync::RwLock<BTreeMap<ipars_types::NodeId, String>>>,
    peer_configs: Arc<tokio::sync::RwLock<BTreeMap<ipars_types::NodeId, WireGuardPeerConfig>>>,
}

impl fmt::Debug for BoringTunWireGuardBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoringTunWireGuardBackend")
            .field("interface", &self.interface)
            .field("device_active", &self.uapi.device_active())
            .finish()
    }
}

impl Clone for BoringTunWireGuardBackend {
    fn clone(&self) -> Self {
        Self {
            interface: self.interface.clone(),
            uapi: Arc::clone(&self.uapi),
            peer_public_keys: Arc::clone(&self.peer_public_keys),
            peer_configs: Arc::clone(&self.peer_configs),
        }
    }
}

impl BoringTunWireGuardBackend {
    pub fn new(interface: impl Into<String>, tun_fd: Option<i32>) -> Result<Self, AgentError> {
        Self::new_in_namespace(interface, tun_fd, None)
    }

    pub fn new_in_namespace(
        interface: impl Into<String>,
        tun_fd: Option<i32>,
        namespace: Option<&LinuxNetworkNamespace>,
    ) -> Result<Self, AgentError> {
        let interface = interface.into();
        let uapi = if let Some(namespace) = namespace {
            with_linux_network_namespace(Some(namespace), || {
                BoringTunUapi::new(&interface, tun_fd)
                    .map_err(|error| io::Error::other(error.to_string()))
            })
            .map_err(|error| {
                AgentError::WireGuard(format!(
                    "failed to initialize userspace WireGuard `{interface}` in network namespace `{}`: {error}",
                    namespace.name()
                ))
            })?
        } else {
            BoringTunUapi::new(&interface, tun_fd)?
        };
        Ok(Self {
            interface,
            uapi: Arc::new(uapi),
            peer_public_keys: Arc::new(tokio::sync::RwLock::new(BTreeMap::new())),
            peer_configs: Arc::new(tokio::sync::RwLock::new(BTreeMap::new())),
        })
    }

    pub async fn configure_interface(
        &self,
        private_key_b64: &str,
        listen_port: u16,
    ) -> Result<(), AgentError> {
        if listen_port == 0 {
            return Err(AgentError::WireGuard(
                "userspace WireGuard listen port must be nonzero".to_string(),
            ));
        }
        let uapi = Arc::clone(&self.uapi);
        let private_key = private_key_b64.to_string();
        tokio::task::spawn_blocking(move || uapi.set_device(&private_key, listen_port))
            .await
            .map_err(|error| {
                AgentError::WireGuard(format!(
                    "userspace WireGuard configuration task failed: {error}"
                ))
            })??;
        Ok(())
    }

    pub fn inventory_source(&self) -> BoringTunPeerInventorySource {
        BoringTunPeerInventorySource {
            uapi: Arc::clone(&self.uapi),
        }
    }

    pub fn telemetry_source(&self) -> BoringTunPeerTelemetrySource {
        BoringTunPeerTelemetrySource {
            uapi: Arc::clone(&self.uapi),
        }
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }
}

#[async_trait]
impl WireGuardBackend for BoringTunWireGuardBackend {
    async fn configure_private_key(&self, private_key_b64: &str) -> Result<(), AgentError> {
        let private_key = private_key_b64.to_string();
        let uapi = Arc::clone(&self.uapi);
        tokio::task::spawn_blocking(move || {
            let private_key = decode_wireguard_private_key_b64(&private_key).map_err(|error| {
                AgentError::WireGuard(format!("invalid userspace WireGuard private key: {error}"))
            })?;
            uapi.transact(
                "set=1",
                &[format!("private_key={}", hex::encode(private_key))],
            )
            .map(|_| ())
        })
        .await
        .map_err(|error| {
            AgentError::WireGuard(format!(
                "userspace WireGuard private-key task failed: {error}"
            ))
        })??;
        Ok(())
    }

    async fn upsert_peer(&self, config: WireGuardPeerConfig) -> Result<(), AgentError> {
        if self
            .peer_configs
            .read()
            .await
            .get(&config.peer)
            .is_some_and(|applied| applied == &config)
        {
            return Ok(());
        }
        let previous = self
            .peer_public_keys
            .read()
            .await
            .get(&config.peer)
            .cloned();
        let uapi = Arc::clone(&self.uapi);
        let config_for_task = config.clone();
        tokio::task::spawn_blocking(move || {
            if let Some(previous) = previous.as_deref() {
                uapi.remove_peer_by_public_key(previous)?;
            }
            // BoringTun 0.7 does not merge an existing peer and panics when
            // update_peer sees one.  Reconcile against the live UAPI state so
            // restart recovery and repeated peer-map snapshots are safe even
            // when the in-memory NodeId cache starts empty.
            let current_keys = parse_peer_keys(&uapi.get()?)?;
            if current_keys.contains(&config_for_task.public_key) {
                uapi.remove_peer_by_public_key(&config_for_task.public_key)?;
            }
            uapi.upsert_peer(&config_for_task)
        })
        .await
        .map_err(|error| {
            AgentError::WireGuard(format!(
                "userspace WireGuard peer configuration task failed: {error}"
            ))
        })??;
        let peer = config.peer.clone();
        let public_key = config.public_key.clone();
        self.peer_public_keys
            .write()
            .await
            .insert(peer.clone(), public_key);
        self.peer_configs.write().await.insert(peer, config);
        Ok(())
    }

    async fn remove_peer(&self, peer: &ipars_types::NodeId) -> Result<(), AgentError> {
        let public_key = self
            .peer_public_keys
            .read()
            .await
            .get(peer)
            .cloned()
            .ok_or_else(|| AgentError::MissingPeer(peer.clone()))?;
        self.remove_peer_by_public_key(&public_key).await
    }

    async fn remove_peer_by_public_key(&self, public_key: &str) -> Result<(), AgentError> {
        let public_key = public_key.to_string();
        let uapi = Arc::clone(&self.uapi);
        let public_key_for_task = public_key.clone();
        tokio::task::spawn_blocking(move || uapi.remove_peer_by_public_key(&public_key_for_task))
            .await
            .map_err(|error| {
                AgentError::WireGuard(format!(
                    "userspace WireGuard peer removal task failed: {error}"
                ))
            })??;
        self.peer_public_keys
            .write()
            .await
            .retain(|_, stored_key| *stored_key != public_key);
        self.peer_configs
            .write()
            .await
            .retain(|_, config| config.public_key != public_key);
        Ok(())
    }
}

#[derive(Clone)]
pub struct BoringTunPeerInventorySource {
    uapi: Arc<BoringTunUapi>,
}

impl fmt::Debug for BoringTunPeerInventorySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoringTunPeerInventorySource")
            .field("device_active", &self.uapi.device_active())
            .finish()
    }
}

#[async_trait]
impl WireGuardPeerInventorySource for BoringTunPeerInventorySource {
    async fn public_keys(&self) -> Result<BTreeSet<String>, AgentError> {
        let uapi = Arc::clone(&self.uapi);
        tokio::task::spawn_blocking(move || {
            let response = uapi.get()?;
            parse_peer_keys(&response)
        })
        .await
        .map_err(|error| {
            AgentError::WireGuard(format!(
                "userspace WireGuard inventory task failed: {error}"
            ))
        })?
    }
}

#[derive(Clone)]
pub struct BoringTunPeerTelemetrySource {
    uapi: Arc<BoringTunUapi>,
}

impl fmt::Debug for BoringTunPeerTelemetrySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoringTunPeerTelemetrySource")
            .field("device_active", &self.uapi.device_active())
            .finish()
    }
}

#[async_trait]
impl WireGuardPeerTelemetrySource for BoringTunPeerTelemetrySource {
    async fn snapshot(&self) -> Result<BTreeMap<String, WireGuardPeerTelemetry>, AgentError> {
        let uapi = Arc::clone(&self.uapi);
        tokio::task::spawn_blocking(move || {
            let response = uapi.get()?;
            parse_peer_telemetry(&response)
        })
        .await
        .map_err(|error| {
            AgentError::WireGuard(format!(
                "userspace WireGuard telemetry task failed: {error}"
            ))
        })?
    }
}

fn parse_peer_keys(response: &[String]) -> Result<BTreeSet<String>, AgentError> {
    let mut keys = BTreeSet::new();
    for line in response {
        let Some(key) = line.strip_prefix("public_key=") else {
            continue;
        };
        let key = hex::decode(key).map_err(|error| {
            AgentError::WireGuard(format!(
                "invalid userspace WireGuard inventory key: {error}"
            ))
        })?;
        if key.len() != 32 {
            return Err(AgentError::WireGuard(
                "userspace WireGuard inventory public key must be 32 bytes".to_string(),
            ));
        }
        keys.insert(encode_bytes(&key));
    }
    Ok(keys)
}

fn parse_peer_telemetry(
    response: &[String],
) -> Result<BTreeMap<String, WireGuardPeerTelemetry>, AgentError> {
    let mut telemetry = BTreeMap::new();
    let mut current_key: Option<String> = None;
    let mut current: Option<WireGuardPeerTelemetry> = None;
    let mut handshake_seconds = None;
    let mut handshake_nanos = None;
    for line in response {
        if let Some(key) = line.strip_prefix("public_key=") {
            if let Some(previous_key) = current_key.take() {
                if let Some(mut value) = current.take() {
                    value.latest_handshake_at = handshake_seconds
                        .zip(handshake_nanos.or(Some(0)))
                        .and_then(|(seconds, nanos)| {
                            chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, nanos)
                        });
                    telemetry.insert(previous_key, value);
                }
            }
            handshake_seconds = None;
            handshake_nanos = None;
            let bytes = hex::decode(key).map_err(|error| {
                AgentError::WireGuard(format!(
                    "invalid userspace WireGuard telemetry key: {error}"
                ))
            })?;
            if bytes.len() != 32 {
                return Err(AgentError::WireGuard(
                    "userspace WireGuard telemetry public key must be 32 bytes".to_string(),
                ));
            }
            let public_key_b64 = encode_bytes(&bytes);
            current_key = Some(public_key_b64.clone());
            current = Some(WireGuardPeerTelemetry::new(public_key_b64));
            continue;
        }
        let Some(value) = current.as_mut() else {
            continue;
        };
        if let Some(endpoint) = line.strip_prefix("endpoint=") {
            let endpoint = endpoint.parse::<SocketAddr>().map_err(|error| {
                AgentError::WireGuard(format!("invalid userspace WireGuard endpoint: {error}"))
            })?;
            value.endpoint = Some(endpoint.to_string());
        } else if let Some(seconds) = line.strip_prefix("last_handshake_time_sec=") {
            handshake_seconds = Some(seconds.parse::<i64>().map_err(|error| {
                AgentError::WireGuard(format!(
                    "invalid userspace WireGuard handshake seconds: {error}"
                ))
            })?);
        } else if let Some(nanos) = line.strip_prefix("last_handshake_time_nsec=") {
            handshake_nanos = Some(nanos.parse::<u32>().map_err(|error| {
                AgentError::WireGuard(format!(
                    "invalid userspace WireGuard handshake nanoseconds: {error}"
                ))
            })?);
        } else if let Some(bytes) = line.strip_prefix("rx_bytes=") {
            value.rx_bytes = bytes.parse().map_err(|error| {
                AgentError::WireGuard(format!(
                    "invalid userspace WireGuard rx byte count: {error}"
                ))
            })?;
        } else if let Some(bytes) = line.strip_prefix("tx_bytes=") {
            value.tx_bytes = bytes.parse().map_err(|error| {
                AgentError::WireGuard(format!(
                    "invalid userspace WireGuard tx byte count: {error}"
                ))
            })?;
        }
    }
    if let Some(key) = current_key {
        if let Some(mut value) = current {
            value.latest_handshake_at = handshake_seconds
                .zip(handshake_nanos.or(Some(0)))
                .and_then(|(seconds, nanos)| {
                    chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, nanos)
                });
            telemetry.insert(key, value);
        }
    }
    Ok(telemetry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_inventory_decodes_strict_fixed_width_keys() -> Result<(), AgentError> {
        let key = "07".repeat(32);
        let keys = parse_peer_keys(&[format!("public_key={key}"), "errno=0".to_string()])?;
        assert!(keys.contains(&encode_bytes(&[7; 32])));

        let result = parse_peer_keys(&["public_key=00".to_string()]);
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(error.to_string().contains("32 bytes"));
        }
        Ok(())
    }

    #[test]
    fn peer_telemetry_groups_uapi_records() -> Result<(), AgentError> {
        let first = "0a".repeat(32);
        let second = "0b".repeat(32);
        let telemetry = parse_peer_telemetry(&[
            format!("public_key={first}"),
            "endpoint=192.0.2.1:51820".to_string(),
            "last_handshake_time_sec=1700000000".to_string(),
            "last_handshake_time_nsec=12".to_string(),
            "rx_bytes=4".to_string(),
            "tx_bytes=5".to_string(),
            format!("public_key={second}"),
            "rx_bytes=6".to_string(),
            "tx_bytes=7".to_string(),
            "errno=0".to_string(),
        ])?;
        let first_key = encode_bytes(&[10; 32]);
        let second_key = encode_bytes(&[11; 32]);
        assert_eq!(
            telemetry[&first_key].endpoint.as_deref(),
            Some("192.0.2.1:51820")
        );
        assert_eq!(telemetry[&first_key].rx_bytes, 4);
        assert_eq!(telemetry[&second_key].tx_bytes, 7);
        assert!(telemetry[&first_key].latest_handshake_at.is_some());
        Ok(())
    }

    #[test]
    fn uapi_values_reject_line_injection() {
        let result = validate_uapi_value("public_key=abc\nremove=true", "test");
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(error.to_string().contains("newline"));
        }
    }
}
