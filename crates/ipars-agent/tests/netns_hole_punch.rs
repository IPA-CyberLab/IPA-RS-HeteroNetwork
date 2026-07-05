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

const DIRECT_TEST_NAME: &str = "udp_hole_puncher_sends_signal_payload_between_network_namespaces";
const NAT_TEST_NAME: &str =
    "udp_hole_puncher_traverses_endpoint_independent_nat_network_namespaces";
const FIXED_PORT_NAT_TEST_NAME: &str =
    "udp_hole_puncher_traverses_fixed_port_snat_network_namespaces";
const MIXED_PORT_NAT_TEST_NAME: &str =
    "udp_hole_puncher_traverses_mixed_port_snat_network_namespaces";
const ONE_SIDED_NAT_TEST_NAME: &str =
    "udp_hole_puncher_traverses_one_sided_public_peer_snat_network_namespaces";
const ONE_SIDED_PORT_PRESERVING_NAT_TEST_NAME: &str =
    "udp_hole_puncher_traverses_one_sided_port_preserving_public_peer_snat_network_namespaces";
const ONE_SIDED_ADDRESS_PORT_DEPENDENT_NAT_TEST_NAME: &str =
    "udp_hole_puncher_does_not_traverse_one_sided_address_port_dependent_snat_network_namespaces";
const ADDRESS_PORT_DEPENDENT_NAT_TEST_NAME: &str =
    "udp_hole_puncher_does_not_traverse_address_port_dependent_snat_network_namespaces";
const ASYMMETRIC_ADDRESS_PORT_DEPENDENT_NAT_TEST_NAME: &str =
    "udp_hole_puncher_does_not_traverse_asymmetric_address_port_dependent_snat_network_namespaces";

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
        DIRECT_TEST_NAME,
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
        DIRECT_TEST_NAME,
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
        DIRECT_TEST_NAME,
        &namespace_a,
        [
            ("IPARS_HOLE_PUNCH_CHILD_ROLE", "puncher"),
            ("IPARS_HOLE_PUNCH_LOCAL_NODE", "node-a"),
            ("IPARS_HOLE_PUNCH_BIND", "10.240.0.1:0"),
        ],
    )?;
    let puncher_b = spawn_child(
        DIRECT_TEST_NAME,
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

#[tokio::test]
async fn udp_hole_puncher_traverses_endpoint_independent_nat_network_namespaces(
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
            "skipping hole-punch NAT netns integration test; set IPARS_RUN_HOLE_PUNCH_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    require_command("ip")?;
    require_command("iptables")?;
    require_command("sysctl")?;

    run_two_sided_snat_hole_punch_topology(
        NAT_TEST_NAME,
        "nat",
        TwoSidedSnatTopology {
            private_second_octet: 242,
            public_third_octet: 0,
            left_bind_port: 40101,
            right_bind_port: 40102,
            left_reflexive_port: 40101,
            right_reflexive_port: 40102,
            left_snat_port: None,
            right_snat_port: None,
            expect_hole_punch_success: true,
        },
    )
}

#[tokio::test]
async fn udp_hole_puncher_traverses_fixed_port_snat_network_namespaces(
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
            "skipping fixed-port SNAT hole-punch netns integration test; set IPARS_RUN_HOLE_PUNCH_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    require_command("ip")?;
    require_command("iptables")?;
    require_command("sysctl")?;

    run_two_sided_snat_hole_punch_topology(
        FIXED_PORT_NAT_TEST_NAME,
        "pnat",
        TwoSidedSnatTopology {
            private_second_octet: 243,
            public_third_octet: 1,
            left_bind_port: 40101,
            right_bind_port: 40102,
            left_reflexive_port: 50101,
            right_reflexive_port: 50102,
            left_snat_port: Some(50101),
            right_snat_port: Some(50102),
            expect_hole_punch_success: true,
        },
    )
}

#[tokio::test]
async fn udp_hole_puncher_traverses_mixed_port_snat_network_namespaces(
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
            "skipping mixed-port SNAT hole-punch netns integration test; set IPARS_RUN_HOLE_PUNCH_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    require_command("ip")?;
    require_command("iptables")?;
    require_command("sysctl")?;

    run_two_sided_snat_hole_punch_topology(
        MIXED_PORT_NAT_TEST_NAME,
        "mixednat",
        TwoSidedSnatTopology {
            private_second_octet: 245,
            public_third_octet: 3,
            left_bind_port: 40101,
            right_bind_port: 40102,
            left_reflexive_port: 40101,
            right_reflexive_port: 50102,
            left_snat_port: None,
            right_snat_port: Some(50102),
            expect_hole_punch_success: true,
        },
    )
}

#[tokio::test]
async fn udp_hole_puncher_does_not_traverse_address_port_dependent_snat_network_namespaces(
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
            "skipping address/port-dependent SNAT hole-punch netns integration test; set IPARS_RUN_HOLE_PUNCH_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    require_command("ip")?;
    require_command("iptables")?;
    require_command("sysctl")?;

    run_two_sided_snat_hole_punch_topology(
        ADDRESS_PORT_DEPENDENT_NAT_TEST_NAME,
        "apdnat",
        TwoSidedSnatTopology {
            private_second_octet: 246,
            public_third_octet: 4,
            left_bind_port: 40101,
            right_bind_port: 40102,
            left_reflexive_port: 50101,
            right_reflexive_port: 50102,
            left_snat_port: Some(51101),
            right_snat_port: Some(51102),
            expect_hole_punch_success: false,
        },
    )
}

#[tokio::test]
async fn udp_hole_puncher_does_not_traverse_asymmetric_address_port_dependent_snat_network_namespaces(
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
            "skipping asymmetric address/port-dependent SNAT hole-punch netns integration test; set IPARS_RUN_HOLE_PUNCH_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    require_command("ip")?;
    require_command("iptables")?;
    require_command("sysctl")?;

    run_two_sided_snat_hole_punch_topology(
        ASYMMETRIC_ADDRESS_PORT_DEPENDENT_NAT_TEST_NAME,
        "asymapdnat",
        TwoSidedSnatTopology {
            private_second_octet: 247,
            public_third_octet: 5,
            left_bind_port: 40101,
            right_bind_port: 40102,
            left_reflexive_port: 50101,
            right_reflexive_port: 40102,
            left_snat_port: Some(51101),
            right_snat_port: None,
            expect_hole_punch_success: false,
        },
    )
}

#[tokio::test]
async fn udp_hole_puncher_traverses_one_sided_public_peer_snat_network_namespaces(
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
            "skipping one-sided public-peer SNAT hole-punch netns integration test; set IPARS_RUN_HOLE_PUNCH_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    require_command("ip")?;
    require_command("iptables")?;
    require_command("sysctl")?;

    run_one_sided_snat_hole_punch_topology(ONE_SIDED_NAT_TEST_NAME)
}

#[tokio::test]
async fn udp_hole_puncher_traverses_one_sided_port_preserving_public_peer_snat_network_namespaces(
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
            "skipping one-sided port-preserving public-peer SNAT hole-punch netns integration test; set IPARS_RUN_HOLE_PUNCH_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    require_command("ip")?;
    require_command("iptables")?;
    require_command("sysctl")?;

    run_one_sided_snat_hole_punch_topology_with(
        ONE_SIDED_PORT_PRESERVING_NAT_TEST_NAME,
        OneSidedSnatTopology {
            label: "onepresnat",
            private_second_octet: 248,
            public_third_octet: 6,
            left_bind_port: 40101,
            left_reflexive_port: 40101,
            left_snat_port: None,
            right_bind_port: 40102,
            expect_left_packet: true,
            expect_right_packet: true,
        },
    )
}

#[tokio::test]
async fn udp_hole_puncher_does_not_traverse_one_sided_address_port_dependent_snat_network_namespaces(
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
            "skipping one-sided address/port-dependent public-peer SNAT hole-punch netns integration test; set IPARS_RUN_HOLE_PUNCH_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    require_command("ip")?;
    require_command("iptables")?;
    require_command("sysctl")?;

    run_one_sided_snat_hole_punch_topology_with(
        ONE_SIDED_ADDRESS_PORT_DEPENDENT_NAT_TEST_NAME,
        OneSidedSnatTopology {
            label: "oneapdnat",
            private_second_octet: 249,
            public_third_octet: 7,
            left_bind_port: 40101,
            left_reflexive_port: 50101,
            left_snat_port: Some(51101),
            right_bind_port: 40102,
            expect_left_packet: false,
            expect_right_packet: true,
        },
    )
}

#[derive(Debug, Clone, Copy)]
struct TwoSidedSnatTopology {
    private_second_octet: u8,
    public_third_octet: u8,
    left_bind_port: u16,
    right_bind_port: u16,
    left_reflexive_port: u16,
    right_reflexive_port: u16,
    left_snat_port: Option<u16>,
    right_snat_port: Option<u16>,
    expect_hole_punch_success: bool,
}

fn run_two_sided_snat_hole_punch_topology(
    test_name: &str,
    label: &str,
    topology: TwoSidedSnatTopology,
) -> Result<(), Box<dyn std::error::Error>> {
    let suffix = unique_suffix()?;
    let left_namespace = format!("ipars-hp-left-{suffix}");
    let left_nat_namespace = format!("ipars-hp-lnat-{suffix}");
    let right_namespace = format!("ipars-hp-right-{suffix}");
    let right_nat_namespace = format!("ipars-hp-rnat-{suffix}");
    let _left_guard = NamespaceGuard::create(left_namespace.clone())?;
    let _left_nat_guard = NamespaceGuard::create(left_nat_namespace.clone())?;
    let _right_guard = NamespaceGuard::create(right_namespace.clone())?;
    let _right_nat_guard = NamespaceGuard::create(right_nat_namespace.clone())?;

    let left_if = format!("ihpl{suffix}");
    let left_nat_private_if = format!("ihpnlp{suffix}");
    let right_if = format!("ihpr{suffix}");
    let right_nat_private_if = format!("ihpnrp{suffix}");
    let left_nat_public_if = format!("ihpnlu{suffix}");
    let right_nat_public_if = format!("ihpnru{suffix}");
    let _left_nat_veth = VethGuard::create(&left_if, &left_nat_private_if)?;
    let _right_nat_veth = VethGuard::create(&right_if, &right_nat_private_if)?;
    let _public_veth = VethGuard::create(&left_nat_public_if, &right_nat_public_if)?;

    move_link_to_namespace(&left_if, &left_namespace)?;
    move_link_to_namespace(&left_nat_private_if, &left_nat_namespace)?;
    move_link_to_namespace(&right_if, &right_namespace)?;
    move_link_to_namespace(&right_nat_private_if, &right_nat_namespace)?;
    move_link_to_namespace(&left_nat_public_if, &left_nat_namespace)?;
    move_link_to_namespace(&right_nat_public_if, &right_nat_namespace)?;

    let left_ip = format!("10.{}.0.2", topology.private_second_octet);
    let left_gateway = format!("10.{}.0.1", topology.private_second_octet);
    let right_ip = format!("10.{}.1.2", topology.private_second_octet);
    let right_gateway = format!("10.{}.1.1", topology.private_second_octet);
    let left_public_ip = format!("198.18.{}.1", topology.public_third_octet);
    let right_public_ip = format!("198.18.{}.2", topology.public_third_octet);

    configure_namespace_interface(&left_namespace, &left_if, &format!("{left_ip}/30"))?;
    configure_namespace_interface(
        &left_nat_namespace,
        &left_nat_private_if,
        &format!("{left_gateway}/30"),
    )?;
    configure_namespace_interface(&right_namespace, &right_if, &format!("{right_ip}/30"))?;
    configure_namespace_interface(
        &right_nat_namespace,
        &right_nat_private_if,
        &format!("{right_gateway}/30"),
    )?;
    configure_namespace_interface(
        &left_nat_namespace,
        &left_nat_public_if,
        &format!("{left_public_ip}/30"),
    )?;
    configure_namespace_interface(
        &right_nat_namespace,
        &right_nat_public_if,
        &format!("{right_public_ip}/30"),
    )?;
    command(
        "ip",
        [
            "-n",
            left_namespace.as_str(),
            "route",
            "replace",
            "default",
            "via",
            left_gateway.as_str(),
        ],
    )?;
    command(
        "ip",
        [
            "-n",
            right_namespace.as_str(),
            "route",
            "replace",
            "default",
            "via",
            right_gateway.as_str(),
        ],
    )?;

    enable_snat_namespace(
        &left_nat_namespace,
        &left_nat_public_if,
        &format!("{left_ip}/32"),
        &left_public_ip,
        topology.left_snat_port,
    )?;
    enable_snat_namespace(
        &right_nat_namespace,
        &right_nat_public_if,
        &format!("{right_ip}/32"),
        &right_public_ip,
        topology.right_snat_port,
    )?;

    let left_ready = temp_file(format!("ipars-hp-{label}-ready-left-{suffix}"));
    let right_ready = temp_file(format!("ipars-hp-{label}-ready-right-{suffix}"));
    let start_file = temp_file(format!("ipars-hp-{label}-start-{suffix}"));
    let left_ready_str = left_ready.to_string_lossy().into_owned();
    let right_ready_str = right_ready.to_string_lossy().into_owned();
    let start_file_str = start_file.to_string_lossy().into_owned();
    let left_bind = format!("{}:{}", left_ip, topology.left_bind_port);
    let right_bind = format!("{}:{}", right_ip, topology.right_bind_port);
    let source_reflexive = format!("{}:{}", left_public_ip, topology.left_reflexive_port);
    let target_reflexive = format!("{}:{}", right_public_ip, topology.right_reflexive_port);
    let child_role = if topology.expect_hole_punch_success {
        "nat-duplex"
    } else {
        "nat-duplex-timeout"
    };

    let left = spawn_child(
        test_name,
        &left_namespace,
        [
            ("IPARS_HOLE_PUNCH_CHILD_ROLE", child_role),
            ("IPARS_HOLE_PUNCH_LOCAL_NODE", "node-a"),
            ("IPARS_HOLE_PUNCH_BIND", left_bind.as_str()),
            (
                "IPARS_HOLE_PUNCH_SOURCE_REFLEXIVE",
                source_reflexive.as_str(),
            ),
            (
                "IPARS_HOLE_PUNCH_TARGET_REFLEXIVE",
                target_reflexive.as_str(),
            ),
            ("IPARS_HOLE_PUNCH_EXPECT_LOCAL", "node-b"),
            ("IPARS_HOLE_PUNCH_READY_FILE", left_ready_str.as_str()),
            ("IPARS_HOLE_PUNCH_START_FILE", start_file_str.as_str()),
        ],
    )?;
    let right = spawn_child(
        test_name,
        &right_namespace,
        [
            ("IPARS_HOLE_PUNCH_CHILD_ROLE", child_role),
            ("IPARS_HOLE_PUNCH_LOCAL_NODE", "node-b"),
            ("IPARS_HOLE_PUNCH_BIND", right_bind.as_str()),
            (
                "IPARS_HOLE_PUNCH_SOURCE_REFLEXIVE",
                source_reflexive.as_str(),
            ),
            (
                "IPARS_HOLE_PUNCH_TARGET_REFLEXIVE",
                target_reflexive.as_str(),
            ),
            ("IPARS_HOLE_PUNCH_EXPECT_LOCAL", "node-a"),
            ("IPARS_HOLE_PUNCH_READY_FILE", right_ready_str.as_str()),
            ("IPARS_HOLE_PUNCH_START_FILE", start_file_str.as_str()),
        ],
    )?;
    wait_for_file(&left_ready)?;
    wait_for_file(&right_ready)?;
    fs::write(&start_file, b"start")?;

    assert_success("nat-left", left.wait_with_output()?)?;
    assert_success("nat-right", right.wait_with_output()?)?;

    let _ = fs::remove_file(left_ready);
    let _ = fs::remove_file(right_ready);
    let _ = fs::remove_file(start_file);
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct OneSidedSnatTopology {
    label: &'static str,
    private_second_octet: u8,
    public_third_octet: u8,
    left_bind_port: u16,
    left_reflexive_port: u16,
    left_snat_port: Option<u16>,
    right_bind_port: u16,
    expect_left_packet: bool,
    expect_right_packet: bool,
}

fn run_one_sided_snat_hole_punch_topology(
    test_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    run_one_sided_snat_hole_punch_topology_with(
        test_name,
        OneSidedSnatTopology {
            label: "onesnat",
            private_second_octet: 244,
            public_third_octet: 2,
            left_bind_port: 40101,
            left_reflexive_port: 50101,
            left_snat_port: Some(50101),
            right_bind_port: 40102,
            expect_left_packet: true,
            expect_right_packet: true,
        },
    )
}

fn run_one_sided_snat_hole_punch_topology_with(
    test_name: &str,
    topology: OneSidedSnatTopology,
) -> Result<(), Box<dyn std::error::Error>> {
    let suffix = unique_suffix()?;
    let left_namespace = format!("ipars-hp-left-{suffix}");
    let left_nat_namespace = format!("ipars-hp-lnat-{suffix}");
    let right_namespace = format!("ipars-hp-pub-{suffix}");
    let _left_guard = NamespaceGuard::create(left_namespace.clone())?;
    let _left_nat_guard = NamespaceGuard::create(left_nat_namespace.clone())?;
    let _right_guard = NamespaceGuard::create(right_namespace.clone())?;

    let left_if = format!("ihpol{suffix}");
    let left_nat_private_if = format!("ihponp{suffix}");
    let left_nat_public_if = format!("ihponu{suffix}");
    let right_if = format!("ihpop{suffix}");
    let _left_nat_veth = VethGuard::create(&left_if, &left_nat_private_if)?;
    let _public_veth = VethGuard::create(&left_nat_public_if, &right_if)?;

    move_link_to_namespace(&left_if, &left_namespace)?;
    move_link_to_namespace(&left_nat_private_if, &left_nat_namespace)?;
    move_link_to_namespace(&left_nat_public_if, &left_nat_namespace)?;
    move_link_to_namespace(&right_if, &right_namespace)?;

    let left_ip = format!("10.{}.0.2", topology.private_second_octet);
    let left_gateway = format!("10.{}.0.1", topology.private_second_octet);
    let left_public_ip = format!("198.18.{}.1", topology.public_third_octet);
    let right_public_ip = format!("198.18.{}.2", topology.public_third_octet);

    configure_namespace_interface(&left_namespace, &left_if, &format!("{left_ip}/30"))?;
    configure_namespace_interface(
        &left_nat_namespace,
        &left_nat_private_if,
        &format!("{left_gateway}/30"),
    )?;
    configure_namespace_interface(
        &left_nat_namespace,
        &left_nat_public_if,
        &format!("{left_public_ip}/30"),
    )?;
    configure_namespace_interface(
        &right_namespace,
        &right_if,
        &format!("{right_public_ip}/30"),
    )?;
    command(
        "ip",
        [
            "-n",
            left_namespace.as_str(),
            "route",
            "replace",
            "default",
            "via",
            left_gateway.as_str(),
        ],
    )?;

    enable_snat_namespace(
        &left_nat_namespace,
        &left_nat_public_if,
        &format!("{left_ip}/32"),
        left_public_ip.as_str(),
        topology.left_snat_port,
    )?;

    let left_ready = temp_file(format!("ipars-hp-{}-ready-left-{suffix}", topology.label));
    let right_ready = temp_file(format!("ipars-hp-{}-ready-right-{suffix}", topology.label));
    let start_file = temp_file(format!("ipars-hp-{}-start-{suffix}", topology.label));
    let left_ready_str = left_ready.to_string_lossy().into_owned();
    let right_ready_str = right_ready.to_string_lossy().into_owned();
    let start_file_str = start_file.to_string_lossy().into_owned();
    let left_bind = format!("{}:{}", left_ip, topology.left_bind_port);
    let right_bind = format!("{}:{}", right_public_ip, topology.right_bind_port);
    let source_reflexive = format!("{}:{}", left_public_ip, topology.left_reflexive_port);
    let target_reflexive = right_bind.clone();
    let left_child_role = if topology.expect_left_packet {
        "nat-duplex"
    } else {
        "nat-duplex-timeout"
    };
    let right_child_role = if topology.expect_right_packet {
        "nat-duplex"
    } else {
        "nat-duplex-timeout"
    };

    let left = spawn_child(
        test_name,
        &left_namespace,
        [
            ("IPARS_HOLE_PUNCH_CHILD_ROLE", left_child_role),
            ("IPARS_HOLE_PUNCH_LOCAL_NODE", "node-a"),
            ("IPARS_HOLE_PUNCH_BIND", left_bind.as_str()),
            (
                "IPARS_HOLE_PUNCH_SOURCE_REFLEXIVE",
                source_reflexive.as_str(),
            ),
            (
                "IPARS_HOLE_PUNCH_TARGET_REFLEXIVE",
                target_reflexive.as_str(),
            ),
            ("IPARS_HOLE_PUNCH_EXPECT_LOCAL", "node-b"),
            ("IPARS_HOLE_PUNCH_READY_FILE", left_ready_str.as_str()),
            ("IPARS_HOLE_PUNCH_START_FILE", start_file_str.as_str()),
        ],
    )?;
    let right = spawn_child(
        test_name,
        &right_namespace,
        [
            ("IPARS_HOLE_PUNCH_CHILD_ROLE", right_child_role),
            ("IPARS_HOLE_PUNCH_LOCAL_NODE", "node-b"),
            ("IPARS_HOLE_PUNCH_BIND", right_bind.as_str()),
            (
                "IPARS_HOLE_PUNCH_SOURCE_REFLEXIVE",
                source_reflexive.as_str(),
            ),
            (
                "IPARS_HOLE_PUNCH_TARGET_REFLEXIVE",
                target_reflexive.as_str(),
            ),
            ("IPARS_HOLE_PUNCH_EXPECT_LOCAL", "node-a"),
            ("IPARS_HOLE_PUNCH_READY_FILE", right_ready_str.as_str()),
            ("IPARS_HOLE_PUNCH_START_FILE", start_file_str.as_str()),
        ],
    )?;
    wait_for_file(&left_ready)?;
    wait_for_file(&right_ready)?;
    fs::write(&start_file, b"start")?;

    assert_success("one-sided-nat-left", left.wait_with_output()?)?;
    assert_success("one-sided-nat-right", right.wait_with_output()?)?;

    let _ = fs::remove_file(left_ready);
    let _ = fs::remove_file(right_ready);
    let _ = fs::remove_file(start_file);
    Ok(())
}

async fn run_child(role: &str) -> Result<(), Box<dyn std::error::Error>> {
    match role {
        "receiver" => run_receiver().await,
        "puncher" => run_puncher().await,
        "nat-duplex" => run_nat_duplex(true).await,
        "nat-duplex-timeout" => run_nat_duplex(false).await,
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

async fn run_nat_duplex(expect_packet: bool) -> Result<(), Box<dyn std::error::Error>> {
    let local_node = NodeId::from_string(required_env("IPARS_HOLE_PUNCH_LOCAL_NODE")?);
    let bind = required_env("IPARS_HOLE_PUNCH_BIND")?.parse::<SocketAddr>()?;
    let source_reflexive =
        required_env("IPARS_HOLE_PUNCH_SOURCE_REFLEXIVE")?.parse::<SocketAddr>()?;
    let target_reflexive =
        required_env("IPARS_HOLE_PUNCH_TARGET_REFLEXIVE")?.parse::<SocketAddr>()?;
    let expected_local = required_env("IPARS_HOLE_PUNCH_EXPECT_LOCAL")?;
    let ready_file = PathBuf::from(required_env("IPARS_HOLE_PUNCH_READY_FILE")?);
    let start_file = PathBuf::from(required_env("IPARS_HOLE_PUNCH_START_FILE")?);
    let socket = tokio::net::UdpSocket::bind(bind).await?;
    fs::write(&ready_file, b"ready")?;
    wait_for_file(&start_file)?;

    let plan = SignalHolePunchPlanResponse {
        key: PeerPathKey::new(NodeId::from_string("node-a"), NodeId::from_string("node-b")),
        source_reflexive: Some(reflexive_candidate_addr("node-a", source_reflexive)),
        target_reflexive: Some(reflexive_candidate_addr("node-b", target_reflexive)),
        start_after_millis: 0,
        expires_at: Utc::now() + ChronoDuration::seconds(10),
    };

    let sent = UdpHolePuncher::new(bind)
        .with_attempts(20)
        .with_interval(Duration::from_millis(50))
        .execute_on_socket(&local_node, &plan, &socket)
        .await?;
    assert_eq!(sent, 20);

    let mut buffer = [0_u8; 512];
    let received =
        tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await;
    if !expect_packet {
        match received {
            Err(_) => return Ok(()),
            Ok(Err(error)) => return Err(error.into()),
            Ok(Ok((len, from))) => {
                let payload = String::from_utf8_lossy(&buffer[..len]);
                return Err(format!("unexpected hole-punch payload from {from}: {payload}").into());
            }
        }
    }

    let (len, _) = received??;
    let payload = std::str::from_utf8(&buffer[..len])?;

    assert!(payload.contains("ipars-hole-punch-v1"));
    assert!(payload.contains("source=node-a target=node-b"));
    assert!(payload.contains(&format!("local={expected_local}")));
    Ok(())
}

fn reflexive_candidate(
    node_id: &str,
    addr: &str,
) -> Result<EndpointCandidate, Box<dyn std::error::Error>> {
    Ok(reflexive_candidate_addr(node_id, addr.parse()?))
}

fn reflexive_candidate_addr(node_id: &str, addr: SocketAddr) -> EndpointCandidate {
    EndpointCandidate {
        node_id: NodeId::from_string(node_id),
        kind: EndpointCandidateKind::StunReflexive,
        addr,
        observed_at: Utc::now(),
        priority: 100,
        cost: 10,
        source: CandidateSource::StunProbe,
    }
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

fn move_link_to_namespace(
    interface: &str,
    namespace: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    command("ip", ["link", "set", interface, "netns", namespace])
}

fn enable_snat_namespace(
    namespace: &str,
    public_interface: &str,
    source_cidr: &str,
    public_ip: &str,
    public_port: Option<u16>,
) -> Result<(), Box<dyn std::error::Error>> {
    command(
        "ip",
        [
            "netns",
            "exec",
            namespace,
            "sysctl",
            "-w",
            "net.ipv4.ip_forward=1",
        ],
    )?;
    command(
        "ip",
        [
            "netns", "exec", namespace, "iptables", "-P", "FORWARD", "ACCEPT",
        ],
    )?;
    let public_mapping = public_port
        .map(|port| format!("{public_ip}:{port}-{port}"))
        .unwrap_or_else(|| public_ip.to_string());
    let mut args = vec![
        "netns",
        "exec",
        namespace,
        "iptables",
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        source_cidr,
        "-o",
        public_interface,
    ];
    if public_port.is_some() {
        args.extend(["-p", "udp"]);
    }
    args.extend(["-j", "SNAT", "--to-source", public_mapping.as_str()]);
    command_dynamic("ip", &args)
}

fn spawn_child<const N: usize>(
    test_name: &str,
    namespace: &str,
    envs: [(&str, &str); N],
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new("ip");
    command
        .args(["netns", "exec", namespace])
        .arg(std::env::current_exe()?)
        .arg(test_name)
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

fn command_dynamic(program: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
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
