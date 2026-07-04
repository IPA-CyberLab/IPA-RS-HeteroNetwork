use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{Duration as ChronoDuration, Utc};
use ipars_agent::UdpHolePuncher;
use ipars_types::api::SignalHolePunchPlanResponse;
use ipars_types::{CandidateSource, EndpointCandidate, EndpointCandidateKind, NodeId, PeerPathKey};

const TEST_NAME: &str = "udp_hole_puncher_sends_signal_payload_between_network_namespaces";

#[tokio::test]
async fn udp_hole_puncher_sends_signal_payload_between_network_namespaces(
) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(role) = std::env::var("IPARS_HOLE_PUNCH_CHILD_ROLE") {
        return run_child(&role).await;
    }

    if std::env::var("IPARS_RUN_HOLE_PUNCH_NETNS_TESTS")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!(
            "skipping hole-punch netns integration test; set IPARS_RUN_HOLE_PUNCH_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    require_command("ip")?;

    let suffix = unique_suffix()?;
    let namespace_a = format!("ipars-hp-a-{suffix}");
    let namespace_b = format!("ipars-hp-b-{suffix}");
    let _guard_a = NamespaceGuard::create(namespace_a.clone())?;
    let _guard_b = NamespaceGuard::create(namespace_b.clone())?;

    let veth_a = format!("iphpa{suffix}");
    let veth_b = format!("iphpb{suffix}");
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

    configure_namespace_interface(&namespace_a, &veth_a, "10.240.0.1/30")?;
    configure_namespace_interface(&namespace_b, &veth_b, "10.240.0.2/30")?;

    let ready_a = temp_file(format!("ipars-hp-ready-a-{suffix}"));
    let ready_b = temp_file(format!("ipars-hp-ready-b-{suffix}"));
    let receiver_a = spawn_child(
        &namespace_a,
        [
            ("IPARS_HOLE_PUNCH_CHILD_ROLE", "receiver"),
            ("IPARS_HOLE_PUNCH_BIND", "10.240.0.1:40101"),
            ("IPARS_HOLE_PUNCH_EXPECT_LOCAL", "node-b"),
            (
                "IPARS_HOLE_PUNCH_READY_FILE",
                ready_a.to_str().unwrap_or_default(),
            ),
        ],
    )?;
    let receiver_b = spawn_child(
        &namespace_b,
        [
            ("IPARS_HOLE_PUNCH_CHILD_ROLE", "receiver"),
            ("IPARS_HOLE_PUNCH_BIND", "10.240.0.2:40102"),
            ("IPARS_HOLE_PUNCH_EXPECT_LOCAL", "node-a"),
            (
                "IPARS_HOLE_PUNCH_READY_FILE",
                ready_b.to_str().unwrap_or_default(),
            ),
        ],
    )?;
    wait_for_file(&ready_a)?;
    wait_for_file(&ready_b)?;

    let puncher_a = spawn_child(
        &namespace_a,
        [
            ("IPARS_HOLE_PUNCH_CHILD_ROLE", "puncher"),
            ("IPARS_HOLE_PUNCH_LOCAL_NODE", "node-a"),
            ("IPARS_HOLE_PUNCH_BIND", "10.240.0.1:0"),
        ],
    )?;
    let puncher_b = spawn_child(
        &namespace_b,
        [
            ("IPARS_HOLE_PUNCH_CHILD_ROLE", "puncher"),
            ("IPARS_HOLE_PUNCH_LOCAL_NODE", "node-b"),
            ("IPARS_HOLE_PUNCH_BIND", "10.240.0.2:0"),
        ],
    )?;

    assert_success("puncher-a", puncher_a.wait_with_output()?)?;
    assert_success("puncher-b", puncher_b.wait_with_output()?)?;
    assert_success("receiver-a", receiver_a.wait_with_output()?)?;
    assert_success("receiver-b", receiver_b.wait_with_output()?)?;

    let _ = fs::remove_file(ready_a);
    let _ = fs::remove_file(ready_b);
    Ok(())
}

async fn run_child(role: &str) -> Result<(), Box<dyn std::error::Error>> {
    match role {
        "receiver" => run_receiver().await,
        "puncher" => run_puncher().await,
        other => Err(format!("unknown hole-punch child role `{other}`").into()),
    }
}

async fn run_receiver() -> Result<(), Box<dyn std::error::Error>> {
    let bind = required_env("IPARS_HOLE_PUNCH_BIND")?.parse::<SocketAddr>()?;
    let expected_local = required_env("IPARS_HOLE_PUNCH_EXPECT_LOCAL")?;
    let ready_file = PathBuf::from(required_env("IPARS_HOLE_PUNCH_READY_FILE")?);
    let socket = tokio::net::UdpSocket::bind(bind).await?;
    fs::write(&ready_file, b"ready")?;

    let mut buffer = [0_u8; 512];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buffer)).await??;
    let payload = std::str::from_utf8(&buffer[..len])?;

    assert!(payload.contains("ipars-hole-punch-v1"));
    assert!(payload.contains("source=node-a target=node-b"));
    assert!(payload.contains(&format!("local={expected_local}")));
    Ok(())
}

async fn run_puncher() -> Result<(), Box<dyn std::error::Error>> {
    let local_node = NodeId::from_string(required_env("IPARS_HOLE_PUNCH_LOCAL_NODE")?);
    let bind = required_env("IPARS_HOLE_PUNCH_BIND")?.parse::<SocketAddr>()?;
    let plan = SignalHolePunchPlanResponse {
        key: PeerPathKey::new(NodeId::from_string("node-a"), NodeId::from_string("node-b")),
        source_reflexive: Some(reflexive_candidate("node-a", "10.240.0.1:40101")?),
        target_reflexive: Some(reflexive_candidate("node-b", "10.240.0.2:40102")?),
        start_after_millis: 0,
        expires_at: Utc::now() + ChronoDuration::seconds(10),
    };

    let sent = UdpHolePuncher::new(bind)
        .with_attempts(1)
        .with_interval(Duration::ZERO)
        .execute(&local_node, &plan)
        .await?;
    assert_eq!(sent, 1);
    Ok(())
}

fn reflexive_candidate(
    node_id: &str,
    addr: &str,
) -> Result<EndpointCandidate, Box<dyn std::error::Error>> {
    Ok(EndpointCandidate {
        node_id: NodeId::from_string(node_id),
        kind: EndpointCandidateKind::StunReflexive,
        addr: addr.parse()?,
        observed_at: Utc::now(),
        priority: 100,
        cost: 10,
        source: CandidateSource::StunProbe,
    })
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
