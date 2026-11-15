use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use ipars_agent::{
    BoringTunWireGuardBackend, KernelWireGuardBackend, KernelWireGuardPeerTelemetrySource,
    LinuxWireGuardBackend, NamespacedLinuxCommandRunner, TimedSystemCommandRunner,
    WireGuardBackend, WireGuardPeerConfig, WireGuardPeerInventorySource,
    WireGuardPeerTelemetrySource,
};
use ipars_crypto::{encode_bytes, WireGuardKeyPair};
use ipars_route_manager::{with_linux_network_namespace, LinuxNetworkNamespace};
use ipars_types::{NodeId, VpnIp};

#[tokio::test]
async fn reapplying_unclamped_key_preserves_kernel_wireguard_session(
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("HETERONETWORK_RUN_WG_NETNS_TESTS")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!("skipping kernel WireGuard key stability test without netns opt-in");
        return Ok(());
    }
    for name in ["ip", "wg", "ping"] {
        require_command(name)?;
    }
    let suffix = unique_suffix()?;
    let namespace_a = format!("ipars-key-a-{suffix}");
    let namespace_b = format!("ipars-key-b-{suffix}");
    let _guard_a = NamespaceGuard::create(namespace_a.clone())?;
    let _guard_b = NamespaceGuard::create(namespace_b.clone())?;
    let veth_a = format!("ka{suffix}");
    let veth_b = format!("kb{suffix}");
    let _veth_guard = VethGuard::create(&veth_a, &veth_b)?;
    command("ip", ["link", "set", &veth_a, "netns", &namespace_a])?;
    command("ip", ["link", "set", &veth_b, "netns", &namespace_b])?;
    configure_namespace_interface(&namespace_a, &veth_a, "10.241.98.1/30")?;
    configure_namespace_interface(&namespace_b, &veth_b, "10.241.98.2/30")?;

    let ns_a = LinuxNetworkNamespace::from_name(&namespace_a)?;
    let ns_b = LinuxNetworkNamespace::from_name(&namespace_b)?;
    let backend_a = KernelWireGuardBackend::new_in_namespace("iparswg0", ns_a.clone());
    let backend_b = KernelWireGuardBackend::new_in_namespace("iparswg0", ns_b.clone());
    let telemetry = KernelWireGuardPeerTelemetrySource::new_in_namespace("iparswg0", ns_a.clone());
    // These deterministic test-only values are deliberately not clamped.
    let key_a = WireGuardKeyPair::from_private_key_b64(&encode_bytes(&[7; 32]))?;
    let key_b = WireGuardKeyPair::from_private_key_b64(&encode_bytes(&[9; 32]))?;
    backend_a.ensure_interface().await?;
    backend_b.ensure_interface().await?;
    backend_a
        .configure_interface_private_key(&key_a.private_key_b64)
        .await?;
    backend_b
        .configure_interface_private_key(&key_b.private_key_b64)
        .await?;
    backend_a.configure_interface_listen_port(51940).await?;
    backend_b.configure_interface_listen_port(51940).await?;
    backend_a
        .configure_interface_address(VpnIp("100.64.98.1".parse()?))
        .await?;
    backend_b
        .configure_interface_address(VpnIp("100.64.98.2".parse()?))
        .await?;
    backend_a
        .upsert_peer(WireGuardPeerConfig {
            peer: NodeId::from_string("test-b"),
            public_key: key_b.public_key_b64.clone(),
            endpoint: Some("10.241.98.2:51940".to_string()),
            allowed_ips: vec!["100.64.98.2/32".to_string()],
            persistent_keepalive_seconds: None,
        })
        .await?;
    backend_b
        .upsert_peer(WireGuardPeerConfig {
            peer: NodeId::from_string("test-a"),
            public_key: key_a.public_key_b64.clone(),
            endpoint: Some("10.241.98.1:51940".to_string()),
            allowed_ips: vec!["100.64.98.1/32".to_string()],
            persistent_keepalive_seconds: None,
        })
        .await?;
    command(
        "ip",
        [
            "-n",
            &namespace_a,
            "route",
            "replace",
            "100.64.98.2/32",
            "dev",
            "iparswg0",
        ],
    )?;
    command(
        "ip",
        [
            "-n",
            &namespace_b,
            "route",
            "replace",
            "100.64.98.1/32",
            "dev",
            "iparswg0",
        ],
    )?;
    let ping = || {
        command(
            "ip",
            [
                "netns",
                "exec",
                &namespace_a,
                "ping",
                "-n",
                "-q",
                "-c",
                "3",
                "-W",
                "2",
                "100.64.98.2",
            ],
        )
    };
    ping()?;
    let first = telemetry
        .snapshot()
        .await?
        .get(&key_b.public_key_b64)
        .and_then(|peer| peer.latest_handshake_at)
        .ok_or("initial handshake missing")?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Reproduce the old behavior against the actual Linux kernel without
    // exposing even test keys in command arguments or logs.
    let mut raw_refresh = Command::new("ip")
        .args([
            "netns",
            "exec",
            &namespace_a,
            "wg",
            "set",
            "iparswg0",
            "private-key",
            "/dev/stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        use std::io::Write;
        let mut input = raw_refresh.stdin.take().ok_or("missing key stdin")?;
        writeln!(input, "{}", key_a.private_key_b64)?;
    }
    let raw_output = raw_refresh.wait_with_output()?;
    if !raw_output.status.success() {
        return Err(command_error("wg raw refresh", raw_output).into());
    }
    ping()?;
    let after_raw = telemetry
        .snapshot()
        .await?
        .get(&key_b.public_key_b64)
        .and_then(|peer| peer.latest_handshake_at)
        .ok_or("handshake after raw refresh missing")?;
    assert!(
        after_raw > first,
        "the unclamped-key regression did not reproduce"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Both production Linux backends must preserve the established keypair.
    backend_a
        .configure_interface_private_key(&key_a.private_key_b64)
        .await?;
    ping()?;
    let after_netlink = telemetry
        .snapshot()
        .await?
        .get(&key_b.public_key_b64)
        .and_then(|peer| peer.latest_handshake_at)
        .ok_or("netlink handshake missing")?;
    assert_eq!(
        after_netlink, after_raw,
        "netlink key refresh restarted the session"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    let command_backend = LinuxWireGuardBackend::new(
        "iparswg0",
        NamespacedLinuxCommandRunner::new(ns_a, TimedSystemCommandRunner::default()),
    );
    command_backend
        .configure_interface_private_key(&key_a.private_key_b64)
        .await?;
    ping()?;
    let after_command = telemetry
        .snapshot()
        .await?
        .get(&key_b.public_key_b64)
        .and_then(|peer| peer.latest_handshake_at)
        .ok_or("command handshake missing")?;
    assert_eq!(
        after_command, after_raw,
        "command key refresh restarted the session"
    );
    Ok(())
}

#[tokio::test]
async fn kernel_wireguard_backend_manages_peer_inside_network_namespace(
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("HETERONETWORK_RUN_WG_NETNS_TESTS")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!(
            "skipping WireGuard netns integration test; set HETERONETWORK_RUN_WG_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    require_command("ip")?;

    let namespace_name = unique_namespace_name()?;
    let _guard = NamespaceGuard::create(namespace_name.clone())?;
    command(
        "ip",
        ["-n", namespace_name.as_str(), "link", "set", "lo", "up"],
    )?;

    let interface = "iparswg0";
    let namespace = LinuxNetworkNamespace::from_name(namespace_name.as_str())?;
    let backend = KernelWireGuardBackend::new_in_namespace(interface, namespace.clone());
    let telemetry_source =
        KernelWireGuardPeerTelemetrySource::new_in_namespace(interface, namespace.clone())
            .with_timeout(Duration::from_secs(5));

    backend.ensure_interface().await?;
    let link = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "link",
            "show",
            "dev",
            interface,
        ],
    )?;
    assert!(link.contains(interface));

    let local_key = WireGuardKeyPair::generate();
    backend
        .configure_interface_private_key(&local_key.private_key_b64)
        .await?;
    backend.configure_interface_listen_port(51820).await?;
    backend
        .configure_interface_address(VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 99, 1))))
        .await?;
    let local_address = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "-o",
            "-4",
            "addr",
            "show",
            "dev",
            interface,
        ],
    )?;
    assert!(local_address.contains("100.64.99.1/32"));
    let peer = NodeId::from_string("wg-netns-peer");
    let peer_key = WireGuardKeyPair::generate();
    backend
        .upsert_peer(WireGuardPeerConfig {
            peer: peer.clone(),
            public_key: peer_key.public_key_b64.clone(),
            endpoint: Some("127.0.0.1:51820".to_string()),
            allowed_ips: vec!["100.64.99.2/32".to_string()],
            persistent_keepalive_seconds: Some(25),
        })
        .await?;

    let telemetry = telemetry_source.snapshot().await?;
    let peer_telemetry = telemetry
        .get(&peer_key.public_key_b64)
        .ok_or("kernel WireGuard telemetry did not include the configured peer")?;
    assert_eq!(peer_telemetry.endpoint.as_deref(), Some("127.0.0.1:51820"));
    assert_eq!(peer_telemetry.latest_handshake_at, None);

    drop(backend);
    let restarted_backend = KernelWireGuardBackend::new_in_namespace(interface, namespace);
    restarted_backend
        .remove_peer_by_public_key(&peer_key.public_key_b64)
        .await?;
    assert!(!telemetry_source
        .snapshot()
        .await?
        .contains_key(&peer_key.public_key_b64));

    Ok(())
}

#[tokio::test]
async fn boringtun_backend_manages_peer_inside_network_namespace(
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("HETERONETWORK_RUN_BORINGTUN_NETNS_TESTS")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!(
            "skipping BoringTun netns integration test; set HETERONETWORK_RUN_BORINGTUN_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    require_command("ip")?;
    if !std::path::Path::new("/dev/net/tun").exists() {
        return Err("/dev/net/tun is required for the BoringTun netns integration test".into());
    }

    let namespace_name = unique_namespace_name()?;
    let _guard = NamespaceGuard::create(namespace_name.clone())?;
    command(
        "ip",
        ["-n", namespace_name.as_str(), "link", "set", "lo", "up"],
    )?;

    let interface = "iparsbt0";
    let namespace = LinuxNetworkNamespace::from_name(namespace_name.as_str())?;
    let backend = BoringTunWireGuardBackend::new_in_namespace(interface, None, Some(&namespace))?;
    let inventory_source = backend.inventory_source();
    let telemetry_source = backend.telemetry_source();
    let local_key = WireGuardKeyPair::generate();
    backend
        .configure_interface(&local_key.private_key_b64, 51830)
        .await?;

    command(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "link",
            "set",
            "up",
            "dev",
            interface,
        ],
    )?;
    command(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "address",
            "replace",
            "100.64.99.3/32",
            "dev",
            interface,
        ],
    )?;
    let local_address = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "-o",
            "-4",
            "addr",
            "show",
            "dev",
            interface,
        ],
    )?;
    assert!(local_address.contains("100.64.99.3/32"));

    let peer = NodeId::from_string("boringtun-netns-peer");
    let peer_key = WireGuardKeyPair::generate();
    backend
        .upsert_peer(WireGuardPeerConfig {
            peer,
            public_key: peer_key.public_key_b64.clone(),
            endpoint: Some("127.0.0.1:51831".to_string()),
            allowed_ips: vec!["100.64.99.4/32".to_string()],
            persistent_keepalive_seconds: Some(25),
        })
        .await?;
    backend
        .upsert_peer(WireGuardPeerConfig {
            peer: NodeId::from_string("boringtun-netns-peer"),
            public_key: peer_key.public_key_b64.clone(),
            endpoint: Some("127.0.0.1:51831".to_string()),
            allowed_ips: vec!["100.64.99.4/32".to_string()],
            persistent_keepalive_seconds: Some(25),
        })
        .await?;

    assert!(inventory_source
        .public_keys()
        .await?
        .contains(&peer_key.public_key_b64));
    let telemetry = telemetry_source.snapshot().await?;
    let peer_telemetry = telemetry
        .get(&peer_key.public_key_b64)
        .ok_or("BoringTun telemetry did not include the configured peer")?;
    assert_eq!(peer_telemetry.endpoint.as_deref(), Some("127.0.0.1:51831"));
    assert_eq!(peer_telemetry.latest_handshake_at, None);

    backend
        .remove_peer_by_public_key(&peer_key.public_key_b64)
        .await?;
    assert!(!inventory_source
        .public_keys()
        .await?
        .contains(&peer_key.public_key_b64));

    Ok(())
}

#[tokio::test]
async fn boringtun_backends_transport_vpn_packets_between_network_namespaces(
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("HETERONETWORK_RUN_BORINGTUN_NETNS_TESTS")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!(
            "skipping BoringTun packet netns integration test; set HETERONETWORK_RUN_BORINGTUN_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    require_command("ip")?;
    if !std::path::Path::new("/dev/net/tun").exists() {
        return Err(
            "/dev/net/tun is required for the BoringTun packet netns integration test".into(),
        );
    }

    let suffix = unique_suffix()?;
    let namespace_a = format!("ipars-bt-a-{suffix}");
    let namespace_b = format!("ipars-bt-b-{suffix}");
    let _guard_a = NamespaceGuard::create(namespace_a.clone())?;
    let _guard_b = NamespaceGuard::create(namespace_b.clone())?;

    let veth_a = format!("bta{suffix}");
    let veth_b = format!("btb{suffix}");
    let _veth_guard = VethGuard::create(&veth_a, &veth_b)?;
    command(
        "ip",
        [
            "link",
            "set",
            veth_a.as_str(),
            "netns",
            namespace_a.as_str(),
        ],
    )?;
    command(
        "ip",
        [
            "link",
            "set",
            veth_b.as_str(),
            "netns",
            namespace_b.as_str(),
        ],
    )?;
    configure_namespace_interface(&namespace_a, &veth_a, "10.241.99.1/30")?;
    configure_namespace_interface(&namespace_b, &veth_b, "10.241.99.2/30")?;

    let namespace_a_ref = LinuxNetworkNamespace::from_name(namespace_a.as_str())?;
    let namespace_b_ref = LinuxNetworkNamespace::from_name(namespace_b.as_str())?;
    let interface_a = format!("bga{suffix}");
    let interface_b = format!("bgb{suffix}");
    let vpn_ip_a = Ipv4Addr::new(100, 64, 99, 11);
    let vpn_ip_b = Ipv4Addr::new(100, 64, 99, 12);
    let listen_a = 51930;
    let listen_b = 51931;
    let key_a = WireGuardKeyPair::generate();
    let key_b = WireGuardKeyPair::generate();

    let backend_a = BoringTunWireGuardBackend::new_in_namespace(
        interface_a.clone(),
        None,
        Some(&namespace_a_ref),
    )?;
    let backend_b = BoringTunWireGuardBackend::new_in_namespace(
        interface_b.clone(),
        None,
        Some(&namespace_b_ref),
    )?;
    let telemetry_a = backend_a.telemetry_source();
    let telemetry_b = backend_b.telemetry_source();

    backend_a
        .configure_interface(&key_a.private_key_b64, listen_a)
        .await?;
    backend_b
        .configure_interface(&key_b.private_key_b64, listen_b)
        .await?;
    for (namespace, interface, cidr) in [
        (
            namespace_a.as_str(),
            interface_a.as_str(),
            format!("{vpn_ip_a}/32"),
        ),
        (
            namespace_b.as_str(),
            interface_b.as_str(),
            format!("{vpn_ip_b}/32"),
        ),
    ] {
        command(
            "ip",
            ["-n", namespace, "link", "set", "up", "dev", interface],
        )?;
        command(
            "ip",
            [
                "-n",
                namespace,
                "address",
                "replace",
                cidr.as_str(),
                "dev",
                interface,
            ],
        )?;
    }

    let peer_a_config = WireGuardPeerConfig {
        peer: NodeId::from_string("boringtun-packet-peer-b"),
        public_key: key_b.public_key_b64.clone(),
        endpoint: Some(format!("10.241.99.2:{listen_b}")),
        allowed_ips: vec![format!("{vpn_ip_b}/32")],
        persistent_keepalive_seconds: Some(5),
    };
    let peer_b_config = WireGuardPeerConfig {
        peer: NodeId::from_string("boringtun-packet-peer-a"),
        public_key: key_a.public_key_b64.clone(),
        endpoint: Some(format!("10.241.99.1:{listen_a}")),
        allowed_ips: vec![format!("{vpn_ip_a}/32")],
        persistent_keepalive_seconds: Some(5),
    };
    backend_a.upsert_peer(peer_a_config.clone()).await?;
    backend_b.upsert_peer(peer_b_config.clone()).await?;
    command(
        "ip",
        [
            "-n",
            namespace_a.as_str(),
            "route",
            "replace",
            format!("{vpn_ip_b}/32").as_str(),
            "dev",
            interface_a.as_str(),
        ],
    )?;
    command(
        "ip",
        [
            "-n",
            namespace_b.as_str(),
            "route",
            "replace",
            format!("{vpn_ip_a}/32").as_str(),
            "dev",
            interface_b.as_str(),
        ],
    )?;

    let server_namespace = namespace_b_ref.clone();
    let server = thread::spawn(move || -> Result<Vec<u8>, String> {
        with_linux_network_namespace(Some(&server_namespace), || {
            let socket = UdpSocket::bind(SocketAddr::from((vpn_ip_b, 40000)))?;
            socket.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut packet = [0u8; 128];
            let (length, peer) = socket.recv_from(&mut packet)?;
            socket.send_to(&packet[..length], peer)?;
            Ok(packet[..length].to_vec())
        })
        .map_err(|error| error.to_string())
    });
    thread::sleep(Duration::from_millis(100));

    let payload = b"ipars-boringtun-vpn-packet";
    let client_namespace = namespace_a_ref.clone();
    let response = thread::spawn(move || -> Result<Vec<u8>, String> {
        with_linux_network_namespace(Some(&client_namespace), || {
            let socket = UdpSocket::bind(SocketAddr::from((vpn_ip_a, 0)))?;
            socket.set_read_timeout(Some(Duration::from_millis(750)))?;
            let destination = SocketAddr::from((vpn_ip_b, 40000));
            let mut packet = [0u8; 128];
            let mut last_error = None;
            for _ in 0..20 {
                socket.send_to(payload, destination)?;
                match socket.recv_from(&mut packet) {
                    Ok((length, _)) if &packet[..length] == payload => {
                        return Ok(packet[..length].to_vec())
                    }
                    Ok((length, _)) => {
                        last_error = Some(format!("unexpected response length {length}"));
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || error.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        last_error = Some(error.to_string());
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                last_error.unwrap_or_else(|| "no VPN response".to_string()),
            ))
        })
        .map_err(|error| error.to_string())
    })
    .join()
    .map_err(|_| "BoringTun VPN packet client thread panicked")??;
    let received = server
        .join()
        .map_err(|_| "BoringTun VPN packet server thread panicked")??;
    assert_eq!(response, payload);
    assert_eq!(received, payload);

    let telemetry = telemetry_a.snapshot().await?;
    let peer_telemetry = telemetry
        .get(&key_b.public_key_b64)
        .ok_or("BoringTun packet telemetry did not include peer B")?;
    assert!(
        peer_telemetry.latest_handshake_at.is_some(),
        "BoringTun packet exchange did not record a handshake"
    );
    let reverse_telemetry = telemetry_b.snapshot().await?;
    let reverse_peer_telemetry = reverse_telemetry
        .get(&key_a.public_key_b64)
        .ok_or("BoringTun packet telemetry did not include peer A")?;
    assert!(reverse_peer_telemetry.latest_handshake_at.is_some());

    backend_a.upsert_peer(peer_a_config).await?;
    backend_b.upsert_peer(peer_b_config).await?;
    assert!(telemetry_a
        .snapshot()
        .await?
        .get(&key_b.public_key_b64)
        .and_then(|peer| peer.latest_handshake_at)
        .is_some());
    assert!(telemetry_b
        .snapshot()
        .await?
        .get(&key_a.public_key_b64)
        .and_then(|peer| peer.latest_handshake_at)
        .is_some());

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
        [
            "-n", namespace, "address", "replace", cidr, "dev", interface,
        ],
    )?;
    command(
        "ip",
        ["-n", namespace, "link", "set", "up", "dev", interface],
    )
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
}

impl VethGuard {
    fn create(first: &str, second: &str) -> Result<Self, Box<dyn std::error::Error>> {
        command(
            "ip",
            ["link", "add", first, "type", "veth", "peer", "name", second],
        )?;
        Ok(Self {
            first: first.to_string(),
        })
    }
}

impl Drop for VethGuard {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "del", self.first.as_str()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn unique_namespace_name() -> Result<String, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() % 1_000_000_000;
    Ok(format!("ipars-wg-it-{}-{nanos}", std::process::id()))
}

fn unique_suffix() -> Result<String, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() % 0x1_00000;
    Ok(format!("{:x}{:x}", std::process::id() % 0xffff, nanos))
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

fn command_output<const N: usize>(
    program: &str,
    args: [&str; N],
) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        return Ok(String::from_utf8(output.stdout)?);
    }

    Err(command_error(program, output).into())
}

fn command_error(program: &str, output: std::process::Output) -> String {
    format!(
        "{program} failed with status {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )
}
