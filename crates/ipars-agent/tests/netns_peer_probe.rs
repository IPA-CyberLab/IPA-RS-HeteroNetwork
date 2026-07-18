#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::Utc;
use ipars_agent::{
    AgentNodeState, AgentRuntime, PeerProbeConfig, UdpPeerProbe, UdpPeerProbeResponder,
};
use ipars_route_manager::LinuxNetworkNamespace;
use ipars_types::api::PeerMap;
use ipars_types::{ClusterId, ClusterPolicy, NodeId, NodeRecord, Role, TokenPolicy, VpnIp};

#[tokio::test]
async fn udp_peer_probe_crosses_linux_network_namespaces() -> Result<(), Box<dyn std::error::Error>>
{
    if std::env::var_os("HETERONETWORK_RUN_PEER_PROBE_NETNS_TESTS").is_none() {
        return Ok(());
    }

    let suffix = unique_suffix();
    let namespace_a = format!("ipars-pp-a-{suffix}");
    let namespace_b = format!("ipars-pp-b-{suffix}");
    let veth_a = format!("ippa{suffix}");
    let veth_b = format!("ippb{suffix}");
    let guard = NetnsGuard::create(&namespace_a, &namespace_b)?;
    run_ip(&[
        "link", "add", &veth_a, "type", "veth", "peer", "name", &veth_b,
    ])?;
    run_ip(&["link", "set", &veth_a, "netns", &namespace_a])?;
    run_ip(&["link", "set", &veth_b, "netns", &namespace_b])?;
    configure_namespace_link(&namespace_a, &veth_a, "100.64.0.1/30")?;
    configure_namespace_link(&namespace_b, &veth_b, "100.64.0.2/30")?;

    let vpn_a = VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)));
    let vpn_b = VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)));
    let peer_b = peer_record(NodeId::from_string("peer-b"), vpn_b);
    let runtime_a = Arc::new(AgentRuntime::new(
        AgentNodeState::generate(Utc::now()),
        ClusterPolicy::default(),
    ));
    runtime_a
        .record_peer_map_snapshot(PeerMap {
            cluster_id: ClusterId::from_string("cluster-netns-probe"),
            peers: vec![peer_b],
            generated_at: Utc::now(),
        })
        .await;
    let config = PeerProbeConfig {
        port: 51_821,
        sample_count: 3,
        response_timeout: Duration::from_millis(500),
        sample_interval: Duration::from_millis(10),
        max_requests_per_second_per_peer: 100,
    };
    let namespace_a = LinuxNetworkNamespace::from_name(namespace_a)?;
    let namespace_b = LinuxNetworkNamespace::from_name(namespace_b)?;
    let responder = UdpPeerProbeResponder::bind(vpn_a, Some(&namespace_a), config)?;
    let responder_task = tokio::spawn(responder.run(runtime_a));
    let probe = UdpPeerProbe::new(vpn_b, Some(namespace_b), config)?;

    let measurement = probe.measure(vpn_a).await;
    responder_task.abort();
    let measurement = measurement?;
    assert_eq!(measurement.sample_count(), 3);
    assert_eq!(measurement.successful_sample_count(), 3);
    assert_eq!(measurement.timeout_count(), 0);
    drop(guard);
    Ok(())
}

fn peer_record(node_id: NodeId, vpn_ip: VpnIp) -> NodeRecord {
    NodeRecord {
        node_id,
        cluster_id: ClusterId::from_string("cluster-netns-probe"),
        vpn_ip,
        identity_public_key: "identity".to_string(),
        wireguard_public_key: "wireguard".to_string(),
        role: Role::edge(),
        tags: BTreeSet::new(),
        endpoint_candidates: Vec::new(),
        relay_capability: None,
        token_policy: TokenPolicy::default(),
        routes: Vec::new(),
        registered_at: Utc::now(),
    }
}

fn configure_namespace_link(
    namespace: &str,
    interface: &str,
    cidr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    run_ip(&["-n", namespace, "link", "set", "lo", "up"])?;
    run_ip(&["-n", namespace, "addr", "add", cidr, "dev", interface])?;
    run_ip(&["-n", namespace, "link", "set", interface, "up"])?;
    Ok(())
}

fn run_ip(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("ip").args(args).output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "ip {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )
    .into())
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{:x}",
        (nanos ^ u128::from(std::process::id())) & 0x00ff_ffff
    )
}

struct NetnsGuard {
    namespaces: [String; 2],
}

impl NetnsGuard {
    fn create(left: &str, right: &str) -> Result<Self, Box<dyn std::error::Error>> {
        run_ip(&["netns", "add", left])?;
        if let Err(error) = run_ip(&["netns", "add", right]) {
            let _ = Command::new("ip").args(["netns", "del", left]).status();
            return Err(error);
        }
        Ok(Self {
            namespaces: [left.to_string(), right.to_string()],
        })
    }
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        for namespace in self.namespaces.iter().rev() {
            let _ = Command::new("ip")
                .args(["netns", "del", namespace])
                .status();
        }
    }
}
