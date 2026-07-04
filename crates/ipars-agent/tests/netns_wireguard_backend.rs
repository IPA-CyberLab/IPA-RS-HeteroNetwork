use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ipars_agent::{KernelWireGuardBackend, WireGuardBackend, WireGuardPeerConfig};
use ipars_crypto::WireGuardKeyPair;
use ipars_route_manager::LinuxNetworkNamespace;
use ipars_types::NodeId;

#[tokio::test]
async fn kernel_wireguard_backend_manages_peer_inside_network_namespace(
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("IPARS_RUN_WG_NETNS_TESTS").ok().as_deref() != Some("1") {
        eprintln!(
            "skipping WireGuard netns integration test; set IPARS_RUN_WG_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    require_command("ip")?;
    require_command("wg")?;

    let namespace_name = unique_namespace_name()?;
    let _guard = NamespaceGuard::create(namespace_name.clone())?;
    command(
        "ip",
        ["-n", namespace_name.as_str(), "link", "set", "lo", "up"],
    )?;

    let interface = "iparswg0";
    let namespace = LinuxNetworkNamespace::from_name(namespace_name.as_str())?;
    let backend = KernelWireGuardBackend::new_in_namespace(interface, namespace);

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

    let allowed_ips = command_output(
        "ip",
        [
            "netns",
            "exec",
            namespace_name.as_str(),
            "wg",
            "show",
            interface,
            "allowed-ips",
        ],
    )?;
    assert!(allowed_ips.contains(&peer_key.public_key_b64));
    assert!(allowed_ips.contains("100.64.99.2/32"));

    backend.remove_peer(&peer).await?;
    let peers_after_remove = command_output(
        "ip",
        [
            "netns",
            "exec",
            namespace_name.as_str(),
            "wg",
            "show",
            interface,
            "peers",
        ],
    )?;
    assert!(!peers_after_remove.contains(&peer_key.public_key_b64));

    Ok(())
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

fn unique_namespace_name() -> Result<String, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() % 1_000_000_000;
    Ok(format!("ipars-wg-it-{}-{nanos}", std::process::id()))
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
