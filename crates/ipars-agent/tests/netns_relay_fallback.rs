use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{Duration as ChronoDuration, Utc};
use ipars_agent::{RelayForwarderStats, RelaySessionState, UdpRelayFrameForwarder};
use ipars_relay::{encode_relay_datagram, RelayTable, UdpRelay};
use ipars_types::api::{RelayDataplaneDropReason, RelayDataplaneMetrics};
use ipars_types::{NodeId, RelayCapability};
use tokio::sync::RwLock;

const TEST_NAME: &str = "relay_forwarder_fallback_proxies_datagrams_between_network_namespaces";
const SESSION_ID: &str = "node-a:node-b";
const SESSION_TOKEN: &str = "relay-secret";
const WRONG_SESSION_TOKEN: &str = "relay-wrong-secret";
const LEFT_NODE: &str = "node-a";
const RIGHT_NODE: &str = "node-b";
const RELAY_NODE: &str = "relay-a";

#[tokio::test]
async fn relay_forwarder_fallback_proxies_datagrams_between_network_namespaces(
) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(role) = std::env::var("IPARS_RELAY_NETNS_CHILD_ROLE") {
        return run_child(&role).await;
    }

    if std::env::var("IPARS_RUN_RELAY_NETNS_TESTS").ok().as_deref() != Some("1") {
        eprintln!(
            "skipping relay fallback netns integration test; set IPARS_RUN_RELAY_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    require_command("ip")?;

    let suffix = unique_suffix()?;
    let client_namespace = format!("ipars-rf-client-{suffix}");
    let relay_namespace = format!("ipars-rf-relay-{suffix}");
    let peer_namespace = format!("ipars-rf-peer-{suffix}");
    let _client_guard = NamespaceGuard::create(client_namespace.clone())?;
    let _relay_guard = NamespaceGuard::create(relay_namespace.clone())?;
    let _peer_guard = NamespaceGuard::create(peer_namespace.clone())?;

    let client_if = format!("iprfc{suffix}");
    let relay_client_if = format!("iprfrc{suffix}");
    let peer_if = format!("iprfp{suffix}");
    let relay_peer_if = format!("iprfrp{suffix}");
    let _client_relay_veth = VethGuard::create(&client_if, &relay_client_if)?;
    let _peer_relay_veth = VethGuard::create(&peer_if, &relay_peer_if)?;
    command(
        "ip",
        [
            "link",
            "set",
            client_if.as_str(),
            "netns",
            client_namespace.as_str(),
        ],
    )?;
    command(
        "ip",
        [
            "link",
            "set",
            relay_client_if.as_str(),
            "netns",
            relay_namespace.as_str(),
        ],
    )?;
    command(
        "ip",
        [
            "link",
            "set",
            peer_if.as_str(),
            "netns",
            peer_namespace.as_str(),
        ],
    )?;
    command(
        "ip",
        [
            "link",
            "set",
            relay_peer_if.as_str(),
            "netns",
            relay_namespace.as_str(),
        ],
    )?;

    configure_namespace_interface(&client_namespace, &client_if, "10.241.0.1/30")?;
    configure_namespace_interface(&relay_namespace, &relay_client_if, "10.241.0.2/30")?;
    configure_namespace_interface(&peer_namespace, &peer_if, "10.241.0.5/30")?;
    configure_namespace_interface(&relay_namespace, &relay_peer_if, "10.241.0.6/30")?;

    let relay_ready = temp_file(format!("ipars-rf-relay-ready-{suffix}"));
    let peer_ready = temp_file(format!("ipars-rf-peer-ready-{suffix}"));
    let relay_stop = temp_file(format!("ipars-rf-relay-stop-{suffix}"));
    let relay_metrics = temp_file(format!("ipars-rf-relay-metrics-{suffix}.json"));
    let relay_ready_str = relay_ready.to_string_lossy().into_owned();
    let peer_ready_str = peer_ready.to_string_lossy().into_owned();
    let relay_stop_str = relay_stop.to_string_lossy().into_owned();
    let relay_metrics_str = relay_metrics.to_string_lossy().into_owned();

    let relay = spawn_child(
        &relay_namespace,
        [
            ("IPARS_RELAY_NETNS_CHILD_ROLE", "relay"),
            ("IPARS_RELAY_BIND", "0.0.0.0:41000"),
            ("IPARS_RELAY_PUBLIC_ENDPOINT", "10.241.0.2:41000"),
            ("IPARS_RELAY_LEFT_ADDR", "10.241.0.1:42000"),
            ("IPARS_RELAY_RIGHT_ADDR", "10.241.0.5:43000"),
            ("IPARS_RELAY_READY_FILE", relay_ready_str.as_str()),
            ("IPARS_RELAY_STOP_FILE", relay_stop_str.as_str()),
            ("IPARS_RELAY_METRICS_FILE", relay_metrics_str.as_str()),
        ],
    )?;
    wait_for_file(&relay_ready)?;

    let peer = spawn_child(
        &peer_namespace,
        [
            ("IPARS_RELAY_NETNS_CHILD_ROLE", "peer"),
            ("IPARS_RELAY_PEER_BIND", "10.241.0.5:43000"),
            ("IPARS_RELAY_PEER_ENDPOINT", "10.241.0.6:41000"),
            ("IPARS_RELAY_PEER_READY_FILE", peer_ready_str.as_str()),
        ],
    )?;
    wait_for_file(&peer_ready)?;

    let forwarder = spawn_child(
        &client_namespace,
        [
            ("IPARS_RELAY_NETNS_CHILD_ROLE", "forwarder"),
            ("IPARS_RELAY_FORWARDER_BIND", "10.241.0.1:42000"),
            ("IPARS_RELAY_FORWARDER_RELAY_ENDPOINT", "10.241.0.2:41000"),
            ("IPARS_RELAY_FORWARDER_PEER_ADDR", "10.241.0.5:43000"),
            (
                "IPARS_RELAY_FORWARDER_WIREGUARD_ENDPOINT",
                "127.0.0.1:44000",
            ),
        ],
    )?;

    let forwarder_output = forwarder.wait_with_output()?;
    let peer_output = peer.wait_with_output()?;
    fs::write(&relay_stop, b"stop")?;
    let relay_output = relay.wait_with_output()?;

    assert_success("relay", relay_output)?;
    assert_success("peer", peer_output)?;
    assert_success("forwarder", forwarder_output)?;
    let relay_metrics_snapshot: RelayDataplaneMetrics =
        serde_json::from_slice(&fs::read(&relay_metrics)?)?;
    assert_eq!(relay_metrics_snapshot.datagrams_received, 3);
    assert_eq!(relay_metrics_snapshot.datagrams_forwarded, 2);
    assert_eq!(relay_metrics_snapshot.datagrams_dropped, 1);
    assert_eq!(
        relay_metrics_snapshot
            .drops_by_reason
            .get(&RelayDataplaneDropReason::InvalidSessionCredential)
            .copied()
            .unwrap_or_default(),
        1
    );

    let _ = fs::remove_file(relay_ready);
    let _ = fs::remove_file(peer_ready);
    let _ = fs::remove_file(relay_stop);
    let _ = fs::remove_file(relay_metrics);
    Ok(())
}

async fn run_child(role: &str) -> Result<(), Box<dyn std::error::Error>> {
    match role {
        "relay" => run_relay().await,
        "peer" => run_peer().await,
        "forwarder" => run_forwarder().await,
        other => Err(format!("unknown relay netns child role `{other}`").into()),
    }
}

async fn run_relay() -> Result<(), Box<dyn std::error::Error>> {
    let bind = required_env("IPARS_RELAY_BIND")?.parse::<SocketAddr>()?;
    let public_endpoint = required_env("IPARS_RELAY_PUBLIC_ENDPOINT")?.parse::<SocketAddr>()?;
    let left_addr = required_env("IPARS_RELAY_LEFT_ADDR")?.parse::<SocketAddr>()?;
    let right_addr = required_env("IPARS_RELAY_RIGHT_ADDR")?.parse::<SocketAddr>()?;
    let ready_file = PathBuf::from(required_env("IPARS_RELAY_READY_FILE")?);
    let stop_file = PathBuf::from(required_env("IPARS_RELAY_STOP_FILE")?);
    let metrics_file = std::env::var("IPARS_RELAY_METRICS_FILE")
        .ok()
        .map(PathBuf::from);

    let relay = UdpRelay::bind(bind).await?;
    let mut table = RelayTable::default();
    let capability = RelayCapability {
        enabled_by_policy: true,
        public_endpoint: Some(public_endpoint),
        admission_url: Some("http://relay-a.local:9580".to_string()),
        max_sessions: 10,
        active_sessions: 0,
        max_mbps: 1000,
        e2e_only: true,
    };
    table.admit_with_token(
        &capability,
        NodeId::from_string(LEFT_NODE),
        NodeId::from_string(RIGHT_NODE),
        left_addr,
        right_addr,
        SESSION_TOKEN.to_string(),
    )?;
    let table = Arc::new(RwLock::new(table));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let watcher = tokio::spawn(async move {
        loop {
            if stop_file.exists() {
                let _ = shutdown_tx.send(true);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });

    fs::write(&ready_file, b"ready")?;
    let table_metrics = table.clone();
    let result =
        tokio::time::timeout(Duration::from_secs(10), relay.serve(table, shutdown_rx)).await;
    watcher.abort();
    match result {
        Ok(result) => result?,
        Err(_) => return Err("timed out waiting for relay stop file".into()),
    }
    if let Some(metrics_file) = metrics_file {
        let metrics = table_metrics.read().await.dataplane_metrics();
        fs::write(metrics_file, serde_json::to_vec(&metrics)?)?;
    }
    Ok(())
}

async fn run_peer() -> Result<(), Box<dyn std::error::Error>> {
    let bind = required_env("IPARS_RELAY_PEER_BIND")?.parse::<SocketAddr>()?;
    let relay_endpoint = required_env("IPARS_RELAY_PEER_ENDPOINT")?.parse::<SocketAddr>()?;
    let ready_file = PathBuf::from(required_env("IPARS_RELAY_PEER_READY_FILE")?);
    let socket = tokio::net::UdpSocket::bind(bind).await?;
    fs::write(&ready_file, b"ready")?;

    let mut buffer = [0_u8; 512];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await??;
    let outbound_payload = wireguard_transport_payload(0xb1);
    assert_eq!(&buffer[..len], outbound_payload.as_slice());

    let rejected_datagram = encode_relay_datagram(
        SESSION_ID,
        WRONG_SESSION_TOKEN,
        b"credential-bypass-attempt",
    )?;
    socket.send_to(&rejected_datagram, relay_endpoint).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let inbound_payload = wireguard_transport_payload(0xc1);
    let datagram = encode_relay_datagram(SESSION_ID, SESSION_TOKEN, &inbound_payload)?;
    socket.send_to(&datagram, relay_endpoint).await?;
    Ok(())
}

async fn run_forwarder() -> Result<(), Box<dyn std::error::Error>> {
    let bind = required_env("IPARS_RELAY_FORWARDER_BIND")?.parse::<SocketAddr>()?;
    let relay_endpoint =
        required_env("IPARS_RELAY_FORWARDER_RELAY_ENDPOINT")?.parse::<SocketAddr>()?;
    let peer_addr = required_env("IPARS_RELAY_FORWARDER_PEER_ADDR")?.parse::<SocketAddr>()?;
    let wireguard_endpoint =
        required_env("IPARS_RELAY_FORWARDER_WIREGUARD_ENDPOINT")?.parse::<SocketAddr>()?;

    let forwarder_socket = tokio::net::UdpSocket::bind(bind).await?;
    let forwarder_addr = forwarder_socket.local_addr()?;
    let wireguard_socket = tokio::net::UdpSocket::bind(wireguard_endpoint).await?;
    let stats = Arc::new(RelayForwarderStats::new(
        NodeId::from_string(RIGHT_NODE),
        NodeId::from_string(RELAY_NODE),
        relay_endpoint,
        forwarder_addr,
    ));
    let forwarder = UdpRelayFrameForwarder::new(
        RelaySessionState {
            peer: NodeId::from_string(RIGHT_NODE),
            relay_node: NodeId::from_string(RELAY_NODE),
            relay_endpoint,
            admitted_local_addr: forwarder_addr,
            admitted_peer_addr: peer_addr,
            session_id: SESSION_ID.to_string(),
            session_token: SESSION_TOKEN.to_string(),
            expires_at: Utc::now() + ChronoDuration::seconds(30),
        },
        wireguard_endpoint,
    )
    .with_metrics(stats.clone());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let forwarder_task = tokio::spawn(forwarder.serve(forwarder_socket, shutdown_rx));

    let outbound_payload = wireguard_transport_payload(0xb1);
    wireguard_socket
        .send_to(&outbound_payload, forwarder_addr)
        .await?;
    let mut buffer = [0_u8; 512];
    let (len, _) = tokio::time::timeout(
        Duration::from_secs(5),
        wireguard_socket.recv_from(&mut buffer),
    )
    .await??;
    let inbound_payload = wireguard_transport_payload(0xc1);
    assert_eq!(&buffer[..len], inbound_payload.as_slice());

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.outbound_packets, 1);
    assert_eq!(
        snapshot.outbound_payload_bytes,
        outbound_payload.len() as u64
    );
    assert!(snapshot.outbound_datagram_bytes > snapshot.outbound_payload_bytes);
    assert_eq!(snapshot.inbound_packets, 1);
    assert_eq!(snapshot.inbound_payload_bytes, inbound_payload.len() as u64);
    assert!(snapshot.last_forwarded_at.is_some());

    shutdown_tx.send(true)?;
    forwarder_task.await??;
    Ok(())
}

fn configure_namespace_interface(
    namespace: &str,
    interface: &str,
    cidr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    command("ip", ["-n", namespace, "link", "set", "lo", "up"])?;
    command(
        "ip",
        ["-n", namespace, "addr", "add", cidr, "dev", interface],
    )?;
    command("ip", ["-n", namespace, "link", "set", interface, "up"])
}

fn spawn_child<const N: usize>(
    namespace: &str,
    envs: [(&str, &str); N],
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new("ip");
    command
        .args(["netns", "exec", namespace])
        .arg(std::env::current_exe()?)
        .arg(TEST_NAME)
        .arg("--exact")
        .arg("--nocapture")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    Ok(command.spawn()?)
}

struct NamespaceGuard {
    name: String,
}

impl NamespaceGuard {
    fn create(name: String) -> Result<Self, Box<dyn std::error::Error>> {
        command("ip", ["netns", "add", name.as_str()])?;
        Ok(Self { name })
    }
}

impl Drop for NamespaceGuard {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["netns", "del", self.name.as_str()])
            .status();
    }
}

struct VethGuard {
    first: String,
    second: String,
}

impl VethGuard {
    fn create(first: &str, second: &str) -> Result<Self, Box<dyn std::error::Error>> {
        command(
            "ip",
            ["link", "add", first, "type", "veth", "peer", "name", second],
        )?;
        Ok(Self {
            first: first.to_string(),
            second: second.to_string(),
        })
    }
}

impl Drop for VethGuard {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "del", &self.first])
            .status();
        let _ = Command::new("ip")
            .args(["link", "del", &self.second])
            .status();
    }
}

fn wait_for_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..100 {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(format!("timed out waiting for {}", path.display()).into())
}

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|_| format!("required env `{name}` is missing").into())
}

fn wireguard_transport_payload(fill: u8) -> [u8; 32] {
    let mut payload = [fill; 32];
    payload[..4].copy_from_slice(&4_u32.to_le_bytes());
    payload
}

fn unique_suffix() -> Result<String, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() % 1_000_000_000;
    Ok(format!(
        "{:03}{:05}",
        std::process::id() % 1000,
        nanos % 100_000
    ))
}

fn temp_file(name: String) -> PathBuf {
    std::env::temp_dir().join(name)
}

fn require_command(program: &str) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("sh")
        .args(["-c", &format!("command -v {program}")])
        .output()?;
    if output.status.success() {
        return Ok(());
    }

    Err(format!("required command `{program}` is not available in PATH").into())
}

fn command<const N: usize>(
    program: &str,
    args: [&str; N],
) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        return Ok(());
    }

    Err(command_error(program, output).into())
}

fn assert_success(label: &str, output: Output) -> Result<(), Box<dyn std::error::Error>> {
    if output.status.success() {
        return Ok(());
    }

    Err(format!(
        "{label} failed with status {}: stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    )
    .into())
}

fn command_error(program: &str, output: Output) -> String {
    format!(
        "{program} failed with status {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )
}
