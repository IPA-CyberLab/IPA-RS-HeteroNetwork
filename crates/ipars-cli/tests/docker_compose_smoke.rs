use std::collections::BTreeSet;
use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::Value;

const COMPOSE_RELAY_ADMISSION_BEARER_TOKEN: &str =
    "compose-relay-admission-secret-with-at-least-32-bytes";
const COMPOSE_AGENT_API_BEARER_TOKEN: &str = "compose-agent-api-secret-with-at-least-32-bytes";
const COMPOSE_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN: &str =
    "compose-control-plane-operator-secret";
const COMPOSE_SIGNAL_OPERATOR_API_BEARER_TOKEN: &str = "compose-signal-operator-api-secret";
const COMPOSE_STUN_OPERATOR_API_BEARER_TOKEN: &str = "compose-stun-operator-api-secret";
const COMPOSE_RELAY_OPERATOR_API_BEARER_TOKEN: &str = "compose-relay-operator-api-secret";

#[test]
fn docker_compose_stack_reaches_healthy_services_with_generated_token() -> Result<()> {
    if std::env::var("IPARS_RUN_DOCKER_COMPOSE_SMOKE")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!(
            "skipping Docker Compose smoke test; set IPARS_RUN_DOCKER_COMPOSE_SMOKE=1 to run it"
        );
        return Ok(());
    }

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .context("failed to resolve repository root")?;
    let temp_dir = create_temp_dir_in(&repo_root.join("target"), "ipars-compose-smoke")?;
    let _temp_guard = TempDirGuard {
        path: temp_dir.clone(),
    };

    let tcp_ports = reserve_tcp_ports(6)?;
    let udp_ports = reserve_udp_ports(3)?;
    let control_plane_port = tcp_ports.ports[0];
    let signal_port = tcp_ports.ports[1];
    let relay_http_port = tcp_ports.ports[2];
    let agent_port = tcp_ports.ports[3];
    let stun_http_port = tcp_ports.ports[4];
    let agent_b_port = tcp_ports.ports[5];
    let stun_port = udp_ports.ports[0];
    let stun_alternate_port = udp_ports.ports[1];
    let relay_udp_port = udp_ports.ports[2];

    let init = generated_init_output(relay_udp_port)?;
    let cluster_id = json_string(&init, "cluster_id")?;
    let issuer_node_id = json_string(&init, "issuer_node_id")?;
    let issuer_public_key = json_string(&init, "issuer_public_key")?;
    let join_token = init
        .get("join_token")
        .context("init output missing join_token")?
        .to_string();

    let override_path = temp_dir.join("compose.override.yaml");
    let override_config = ComposeOverrideConfig {
        repo_root: &repo_root,
        cluster_id: &cluster_id,
        issuer_node_id: &issuer_node_id,
        issuer_public_key: &issuer_public_key,
        join_token: &join_token,
        relay_admission_bearer_token: COMPOSE_RELAY_ADMISSION_BEARER_TOKEN,
        ports: ComposeOverridePorts {
            control_plane: control_plane_port,
            signal: signal_port,
            stun: stun_port,
            stun_alternate: stun_alternate_port,
            stun_http: stun_http_port,
            relay_udp: relay_udp_port,
            relay_http: relay_http_port,
            agent: agent_port,
            agent_b: agent_b_port,
        },
    };
    fs::write(&override_path, compose_override(&override_config))
        .with_context(|| format!("failed to write {}", override_path.display()))?;

    let docker_socket = temp_dir.join("docker.sock");
    let base_compose = ComposeProject {
        repo_root: repo_root.clone(),
        project_name: format!("ipars-config-{}", unique_suffix()?),
        compose_files: vec![PathBuf::from("docker/compose.yaml")],
        docker_socket: docker_socket.clone(),
        extra_env: Vec::new(),
    };
    let rendered = run_compose(&base_compose, ["config"])?;
    let rendered =
        String::from_utf8(rendered.stdout).context("compose config output was not UTF-8")?;
    anyhow::ensure!(
        !rendered.contains(&format!("source: {}", docker_socket.display())),
        "rendered base Compose config unexpectedly included the Docker API socket bind"
    );
    anyhow::ensure!(
        !rendered.contains("target: /run/ipars/docker.sock"),
        "rendered base Compose config unexpectedly mounted the Docker API socket in the agent container"
    );
    anyhow::ensure!(
        rendered.contains("apply-peer-map"),
        "rendered base Compose config did not enable agent peer-map application"
    );
    anyhow::ensure!(
        rendered.contains("IPARS_AGENT_API_BEARER_TOKEN_PATH")
            && rendered.contains("/run/secrets/ipars-agent-api-bearer-token"),
        "rendered base Compose config did not mount the agent API Bearer secret"
    );
    anyhow::ensure!(
        rendered.contains("IPARS_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN_PATH")
            && rendered.contains("/run/secrets/ipars-control-plane-operator-api-bearer-token"),
        "rendered base Compose config did not mount the control-plane operator API Bearer secret"
    );
    anyhow::ensure!(
        rendered.contains("IPARS_SIGNAL_OPERATOR_API_BEARER_TOKEN_PATH")
            && rendered.contains("/run/secrets/ipars-signal-operator-api-bearer-token"),
        "rendered base Compose config did not mount the signal operator API Bearer secret"
    );
    anyhow::ensure!(
        rendered.contains("IPARS_STUN_OPERATOR_API_BEARER_TOKEN_PATH")
            && rendered.contains("/run/secrets/ipars-stun-operator-api-bearer-token"),
        "rendered base Compose config did not mount the STUN operator API Bearer secret"
    );
    anyhow::ensure!(
        rendered.contains("IPARS_RELAY_OPERATOR_API_BEARER_TOKEN_PATH")
            && rendered.contains("/run/secrets/ipars-relay-operator-api-bearer-token"),
        "rendered base Compose config did not mount the relay operator API Bearer secret"
    );
    anyhow::ensure!(
        rendered.contains("IPARS_RELAY_ADMISSION_BEARER_TOKEN_PATH")
            && rendered.contains("IPARS_AGENT_RELAY_ADMISSION_BEARER_TOKEN_PATH")
            && rendered.contains("/run/secrets/ipars-relay-admission-bearer-token"),
        "rendered base Compose config did not share the file-backed relay admission Bearer secret"
    );

    let rootful_discovery_compose = ComposeProject {
        repo_root: repo_root.clone(),
        project_name: format!("ipars-config-{}", unique_suffix()?),
        compose_files: vec![
            PathBuf::from("docker/compose.yaml"),
            PathBuf::from("docker/compose.docker-discovery.yaml"),
        ],
        docker_socket,
        extra_env: vec![
            (
                "IPARS_AGENT_APPLY_DOCKER_ROUTES".to_string(),
                "true".to_string(),
            ),
            (
                "IPARS_DOCKER_DISCOVER_NETWORKS".to_string(),
                "true".to_string(),
            ),
            (
                "IPARS_DOCKER_NETWORKS".to_string(),
                "edge_default,edge_apps".to_string(),
            ),
            (
                "IPARS_DOCKER_CONTAINER_NAMESPACE".to_string(),
                "compose-edge".to_string(),
            ),
            (
                "IPARS_DOCKER_HOST_INTERFACE".to_string(),
                "br-edge".to_string(),
            ),
            (
                "IPARS_DOCKER_EXPOSE_HOST_ROUTES".to_string(),
                "false".to_string(),
            ),
            (
                "IPARS_DOCKER_ROUTE_INTERVAL_SECONDS".to_string(),
                "15".to_string(),
            ),
            (
                "IPARS_AGENT_WIREGUARD_BACKEND".to_string(),
                "userspace-command".to_string(),
            ),
            (
                "IPARS_AGENT_USERSPACE_WIREGUARD_COMMAND".to_string(),
                "wireguard-go".to_string(),
            ),
            (
                "IPARS_AGENT_USERSPACE_WIREGUARD_ARGS".to_string(),
                "ipars0,--foreground".to_string(),
            ),
            (
                "IPARS_AGENT_USERSPACE_WIREGUARD_READY_TIMEOUT_SECONDS".to_string(),
                "30".to_string(),
            ),
            (
                "IPARS_AGENT_USERSPACE_WIREGUARD_SHUTDOWN_TIMEOUT_SECONDS".to_string(),
                "20".to_string(),
            ),
            (
                "IPARS_AGENT_DISABLE_PEER_PROBE".to_string(),
                "false".to_string(),
            ),
            (
                "IPARS_AGENT_PEER_PROBE_PORT".to_string(),
                "51900".to_string(),
            ),
            (
                "IPARS_AGENT_PEER_PROBE_SAMPLE_COUNT".to_string(),
                "7".to_string(),
            ),
            (
                "IPARS_AGENT_PEER_PROBE_OBSERVATION_MAX_AGE_SECONDS".to_string(),
                "90".to_string(),
            ),
            (
                "IPARS_AGENT_RELAY_FORWARDER_ENDPOINT".to_string(),
                "127.0.0.1:45182".to_string(),
            ),
            (
                "IPARS_AGENT_RELAY_FORWARDER_BIND".to_string(),
                "0.0.0.0:45182".to_string(),
            ),
            (
                "IPARS_AGENT_RELAY_FORWARDER_WIREGUARD_ENDPOINT".to_string(),
                "127.0.0.1:51820".to_string(),
            ),
            (
                "IPARS_AGENT_RELAY_FORWARDER_NETNS".to_string(),
                "relay-fw".to_string(),
            ),
            (
                "IPARS_AGENT_RELAY_FORWARDER_MAX_SESSIONS".to_string(),
                "7".to_string(),
            ),
            (
                "IPARS_AGENT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS".to_string(),
                "11".to_string(),
            ),
            (
                "IPARS_AGENT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS".to_string(),
                "22".to_string(),
            ),
            (
                "IPARS_AGENT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW".to_string(),
                "4".to_string(),
            ),
            (
                "IPARS_AGENT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS".to_string(),
                "33".to_string(),
            ),
        ],
    };
    let rendered = run_compose(&rootful_discovery_compose, ["config"])?;
    let rendered =
        String::from_utf8(rendered.stdout).context("compose config output was not UTF-8")?;
    assert_rendered_compose_env(
        &rendered,
        &[
            ("IPARS_AGENT_APPLY_DOCKER_ROUTES", "true"),
            ("IPARS_AGENT_STUN_BIND", "0.0.0.0:51821"),
            ("IPARS_AGENT_WIREGUARD_LISTEN_PORT", "51821"),
            ("IPARS_AGENT_RUNTIME_BACKEND", "linux-command"),
            ("IPARS_DOCKER_DISCOVER_NETWORKS", "true"),
            ("IPARS_DOCKER_API_SOCKET", "/run/ipars/docker.sock"),
            ("IPARS_DOCKER_NETWORKS", "edge_default,edge_apps"),
            ("IPARS_DOCKER_CONTAINER_NAMESPACE", "compose-edge"),
            ("IPARS_DOCKER_HOST_INTERFACE", "br-edge"),
            ("IPARS_DOCKER_EXPOSE_HOST_ROUTES", "false"),
            ("IPARS_DOCKER_ROUTE_INTERVAL_SECONDS", "15"),
            ("IPARS_AGENT_WIREGUARD_BACKEND", "userspace-command"),
            ("IPARS_AGENT_USERSPACE_WIREGUARD_COMMAND", "wireguard-go"),
            (
                "IPARS_AGENT_USERSPACE_WIREGUARD_ARGS",
                "ipars0,--foreground",
            ),
            (
                "IPARS_AGENT_USERSPACE_WIREGUARD_READY_TIMEOUT_SECONDS",
                "30",
            ),
            (
                "IPARS_AGENT_USERSPACE_WIREGUARD_SHUTDOWN_TIMEOUT_SECONDS",
                "20",
            ),
            ("IPARS_AGENT_DISABLE_PEER_PROBE", "false"),
            ("IPARS_AGENT_PEER_PROBE_PORT", "51900"),
            ("IPARS_AGENT_PEER_PROBE_SAMPLE_COUNT", "7"),
            ("IPARS_AGENT_PEER_PROBE_OBSERVATION_MAX_AGE_SECONDS", "90"),
            ("IPARS_AGENT_RELAY_FORWARDER_ENDPOINT", "127.0.0.1:45182"),
            ("IPARS_AGENT_RELAY_FORWARDER_BIND", "0.0.0.0:45182"),
            (
                "IPARS_AGENT_RELAY_FORWARDER_WIREGUARD_ENDPOINT",
                "127.0.0.1:51820",
            ),
            ("IPARS_AGENT_RELAY_FORWARDER_NETNS", "relay-fw"),
            ("IPARS_AGENT_RELAY_FORWARDER_MAX_SESSIONS", "7"),
            ("IPARS_AGENT_RELAY_FORWARDER_RESTART_BACKOFF_SECONDS", "11"),
            ("IPARS_AGENT_RELAY_FORWARDER_CRASH_WINDOW_SECONDS", "22"),
            ("IPARS_AGENT_RELAY_FORWARDER_MAX_CRASHES_PER_WINDOW", "4"),
            ("IPARS_AGENT_RELAY_FORWARDER_CRASH_COOLDOWN_SECONDS", "33"),
        ],
    )?;
    anyhow::ensure!(
        rendered.contains("target: /run/ipars/docker.sock"),
        "rendered Docker discovery Compose config did not mount the Docker API socket"
    );
    anyhow::ensure!(
        rendered.contains(&format!(
            "source: {}",
            rootful_discovery_compose.docker_socket.display()
        )),
        "rendered Docker discovery Compose config did not bind the requested host Docker API socket"
    );
    anyhow::ensure!(
        rendered.contains("read_only: true"),
        "rendered Docker discovery Compose config did not keep the Docker API socket bind read-only"
    );
    let discovery_source = fs::read_to_string(
        rootful_discovery_compose
            .repo_root
            .join("docker/compose.docker-discovery.yaml"),
    )
    .context("failed to read Docker discovery Compose source")?;
    anyhow::ensure!(
        discovery_source.contains("create_host_path: false"),
        "Docker discovery Compose source could create a missing host Docker API socket path"
    );

    let rootless_compose = ComposeProject {
        repo_root: repo_root.clone(),
        project_name: format!("ipars-config-{}", unique_suffix()?),
        compose_files: vec![
            PathBuf::from("docker/compose.yaml"),
            PathBuf::from("docker/compose.rootless.yaml"),
        ],
        docker_socket: temp_dir.join("rootless-docker.sock"),
        extra_env: vec![
            (
                "IPARS_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS".to_string(),
                "7".to_string(),
            ),
            (
                "IPARS_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS".to_string(),
                "45".to_string(),
            ),
            (
                "IPARS_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS".to_string(),
                "90".to_string(),
            ),
            (
                "IPARS_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS".to_string(),
                "240".to_string(),
            ),
            (
                "IPARS_AGENT_APPLY_DOCKER_ROUTES".to_string(),
                "true".to_string(),
            ),
            (
                "IPARS_DOCKER_DISCOVER_NETWORKS".to_string(),
                "true".to_string(),
            ),
            (
                "IPARS_DOCKER_API_SOCKET".to_string(),
                "/run/ipars/docker.sock".to_string(),
            ),
            (
                "IPARS_DOCKER_NETWORKS".to_string(),
                "edge_default,edge_apps".to_string(),
            ),
            (
                "IPARS_DOCKER_CONTAINER_NAMESPACE".to_string(),
                "compose-edge".to_string(),
            ),
            (
                "IPARS_DOCKER_HOST_INTERFACE".to_string(),
                "br-edge".to_string(),
            ),
            (
                "IPARS_DOCKER_CONTAINER_CIDRS".to_string(),
                "172.31.0.0/16".to_string(),
            ),
            (
                "IPARS_DOCKER_EXPOSE_HOST_ROUTES".to_string(),
                "false".to_string(),
            ),
            (
                "IPARS_DOCKER_ROUTE_INTERVAL_SECONDS".to_string(),
                "15".to_string(),
            ),
            (
                "IPARS_AGENT_WIREGUARD_BACKEND".to_string(),
                "command".to_string(),
            ),
            (
                "IPARS_AGENT_USERSPACE_WIREGUARD_COMMAND".to_string(),
                "wireguard-go".to_string(),
            ),
            (
                "IPARS_AGENT_USERSPACE_WIREGUARD_ARGS".to_string(),
                "ipars0".to_string(),
            ),
            (
                "IPARS_AGENT_USERSPACE_WIREGUARD_READY_TIMEOUT_SECONDS".to_string(),
                "30".to_string(),
            ),
            (
                "IPARS_AGENT_USERSPACE_WIREGUARD_SHUTDOWN_TIMEOUT_SECONDS".to_string(),
                "20".to_string(),
            ),
            (
                "IPARS_AGENT_DISABLE_PEER_PROBE".to_string(),
                "false".to_string(),
            ),
            (
                "IPARS_AGENT_PEER_PROBE_PORT".to_string(),
                "51900".to_string(),
            ),
            (
                "IPARS_AGENT_PEER_PROBE_SAMPLE_COUNT".to_string(),
                "7".to_string(),
            ),
            (
                "IPARS_AGENT_PEER_PROBE_OBSERVATION_MAX_AGE_SECONDS".to_string(),
                "90".to_string(),
            ),
            (
                "IPARS_AGENT_RELAY_FORWARDER_NETNS".to_string(),
                "relay-fw".to_string(),
            ),
        ],
    };
    let rendered = run_compose(&rootless_compose, ["config"])?;
    let rendered =
        String::from_utf8(rendered.stdout).context("compose config output was not UTF-8")?;
    assert_rendered_compose_env(
        &rendered,
        &[
            ("IPARS_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS", "7"),
            ("IPARS_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS", "45"),
            ("IPARS_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS", "90"),
            ("IPARS_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS", "240"),
            ("IPARS_AGENT_APPLY_DOCKER_ROUTES", "false"),
            ("IPARS_AGENT_STUN_BIND", "0.0.0.0:51821"),
            ("IPARS_AGENT_WIREGUARD_LISTEN_PORT", "51821"),
            ("IPARS_AGENT_RUNTIME_BACKEND", "dry-run"),
            ("IPARS_AGENT_DISABLE_PEER_PROBE", "true"),
            ("IPARS_AGENT_PEER_PROBE_PORT", "51900"),
            ("IPARS_AGENT_PEER_PROBE_SAMPLE_COUNT", "7"),
            ("IPARS_AGENT_PEER_PROBE_OBSERVATION_MAX_AGE_SECONDS", "90"),
            ("IPARS_DOCKER_DISCOVER_NETWORKS", "false"),
            ("IPARS_AGENT_WIREGUARD_BACKEND", "command"),
            ("IPARS_AGENT_ROUTE_BACKEND", "command"),
        ],
    )?;
    for forbidden in [
        "IPARS_DOCKER_API_SOCKET:",
        "IPARS_DOCKER_NETWORKS:",
        "IPARS_DOCKER_CONTAINER_NAMESPACE:",
        "IPARS_DOCKER_CONTAINER_CIDRS:",
        "IPARS_DOCKER_HOST_INTERFACE:",
        "IPARS_DOCKER_EXPOSE_HOST_ROUTES:",
        "IPARS_DOCKER_ROUTE_INTERVAL_SECONDS:",
        "IPARS_AGENT_RELAY_FORWARDER_",
        "IPARS_AGENT_USERSPACE_WIREGUARD_COMMAND:",
        "IPARS_AGENT_USERSPACE_WIREGUARD_ARGS:",
        "IPARS_AGENT_USERSPACE_WIREGUARD_READY_TIMEOUT_SECONDS:",
        "IPARS_AGENT_USERSPACE_WIREGUARD_SHUTDOWN_TIMEOUT_SECONDS:",
        "target: /run/ipars/docker.sock",
    ] {
        anyhow::ensure!(
            !rendered.contains(forbidden),
            "rendered rootless Compose config retained forbidden Docker or namespace setting {forbidden}\n{rendered}"
        );
    }
    anyhow::ensure!(
        !rendered.contains("cap_add"),
        "rendered rootless Compose config unexpectedly kept Linux capability additions"
    );
    anyhow::ensure!(
        !rendered.contains("/dev/net/tun"),
        "rendered rootless Compose config unexpectedly kept the TUN device mount"
    );

    let compose = ComposeProject {
        repo_root,
        project_name: format!("ipars-smoke-{}", unique_suffix()?),
        compose_files: vec![PathBuf::from("docker/compose.yaml"), override_path],
        docker_socket: temp_dir.join("unused-docker.sock"),
        extra_env: Vec::new(),
    };
    let _compose_guard = ComposeCleanup {
        repo_root: compose.repo_root.clone(),
        project_name: compose.project_name.clone(),
        compose_files: compose.compose_files.clone(),
        docker_socket: compose.docker_socket.clone(),
        extra_env: compose.extra_env.clone(),
    };

    let rendered = run_compose(&compose, ["config"])?;
    let rendered =
        String::from_utf8(rendered.stdout).context("compose config output was not UTF-8")?;
    anyhow::ensure!(
        rendered.contains(&format!(
            "IPARS_AGENT_CONTROL_PLANE_URL: http://127.0.0.1:{control_plane_port}"
        )),
        "rendered Compose config did not include the control-plane host port override"
    );
    anyhow::ensure!(
        rendered.contains("IPARS_AGENT_JOIN_TOKEN:"),
        "rendered smoke Compose config did not include the inline join token override"
    );
    anyhow::ensure!(
        rendered.contains("IPARS_RELAY_ADMISSION_BEARER_TOKEN")
            && rendered.contains(COMPOSE_RELAY_ADMISSION_BEARER_TOKEN),
        "rendered smoke Compose config did not require relay admission Bearer auth"
    );
    anyhow::ensure!(
        rendered.contains("IPARS_AGENT_RELAY_ADMISSION_BEARER_TOKEN")
            && rendered.contains(COMPOSE_RELAY_ADMISSION_BEARER_TOKEN),
        "rendered smoke Compose config did not pass the relay admission Bearer token to the agent"
    );
    anyhow::ensure!(
        rendered.contains("IPARS_AGENT_API_BEARER_TOKEN")
            && rendered.contains(COMPOSE_AGENT_API_BEARER_TOKEN),
        "rendered smoke Compose config did not require agent API Bearer auth"
    );
    anyhow::ensure!(
        rendered.contains("IPARS_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN")
            && rendered.contains(COMPOSE_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN),
        "rendered smoke Compose config did not require control-plane operator API Bearer auth"
    );
    anyhow::ensure!(
        rendered.contains("IPARS_SIGNAL_OPERATOR_API_BEARER_TOKEN")
            && rendered.contains(COMPOSE_SIGNAL_OPERATOR_API_BEARER_TOKEN),
        "rendered smoke Compose config did not require signal operator API Bearer auth"
    );
    anyhow::ensure!(
        rendered.contains("IPARS_STUN_OPERATOR_API_BEARER_TOKEN")
            && rendered.contains(COMPOSE_STUN_OPERATOR_API_BEARER_TOKEN),
        "rendered smoke Compose config did not require STUN operator API Bearer auth"
    );
    anyhow::ensure!(
        rendered.contains("IPARS_RELAY_OPERATOR_API_BEARER_TOKEN")
            && rendered.contains(COMPOSE_RELAY_OPERATOR_API_BEARER_TOKEN),
        "rendered smoke Compose config did not require relay operator API Bearer auth"
    );

    drop(tcp_ports);
    drop(udp_ports);
    run_compose_with_diagnostics(
        &compose,
        ["up", "-d", "--build", "--wait", "--wait-timeout", "180"],
    )?;
    assert_compose_services_running(
        &compose,
        &[
            "postgres",
            "control-plane",
            "signal",
            "stun",
            "relay",
            "agent",
            "agent-b",
        ],
    )?;
    let api_ports = ComposeApiPorts {
        agent: agent_port,
        agent_b: agent_b_port,
    };
    let unauthorized_agent_status = compose_exec_http_status(
        &compose,
        "agent",
        "GET",
        &format!("http://127.0.0.1:{agent_port}/v1/status"),
        None,
        "agent status without Bearer auth",
    )?;
    anyhow::ensure!(
        unauthorized_agent_status == 401,
        "agent status without Bearer auth returned {unauthorized_agent_status}, expected 401"
    );
    let unauthorized_control_plane_metrics = compose_exec_http_status(
        &compose,
        "control-plane",
        "GET",
        "http://127.0.0.1:8443/v1/metrics",
        None,
        "control-plane metrics without Bearer auth",
    )?;
    anyhow::ensure!(
        unauthorized_control_plane_metrics == 401,
        "control-plane metrics without Bearer auth returned {unauthorized_control_plane_metrics}, expected 401"
    );
    let unauthorized_signal_metrics = compose_exec_http_status(
        &compose,
        "signal",
        "GET",
        "http://127.0.0.1:9443/v1/metrics",
        None,
        "signal metrics without Bearer auth",
    )?;
    anyhow::ensure!(
        unauthorized_signal_metrics == 401,
        "signal metrics without Bearer auth returned {unauthorized_signal_metrics}, expected 401"
    );
    let unauthorized_stun_metrics = compose_exec_http_status(
        &compose,
        "stun",
        "GET",
        "http://127.0.0.1:3479/v1/metrics",
        None,
        "STUN metrics without Bearer auth",
    )?;
    anyhow::ensure!(
        unauthorized_stun_metrics == 401,
        "STUN metrics without Bearer auth returned {unauthorized_stun_metrics}, expected 401"
    );
    let unauthorized_relay_metrics = compose_exec_http_status(
        &compose,
        "relay",
        "GET",
        "http://127.0.0.1:9580/metrics",
        None,
        "relay metrics without Bearer auth",
    )?;
    anyhow::ensure!(
        unauthorized_relay_metrics == 401,
        "relay metrics without Bearer auth returned {unauthorized_relay_metrics}, expected 401"
    );
    let agent_nodes = assert_compose_service_apis(&compose, &api_ports)?;
    assert_compose_control_plane_peer_maps(&compose, &agent_nodes)?;
    assert_compose_agent_peer_maps(&compose, &agent_nodes, &api_ports)?;
    assert_compose_agent_packet_flow_lazy_connect(&compose, &agent_nodes, &api_ports)?;
    assert_compose_agent_lazy_connect_paths(&compose, &agent_nodes, &api_ports)?;
    assert_compose_signal_path_negotiation_metrics(&compose)?;
    assert_compose_control_plane_path_state(&compose, &agent_nodes)?;
    assert_compose_stun_dataplane(&compose)?;
    assert_compose_relay_admission_auth_required(&compose)?;
    assert_compose_relay_dataplane(&compose)?;

    Ok(())
}

fn generated_init_output(relay_udp_port: u16) -> Result<Value> {
    let output = Command::new(env!("CARGO_BIN_EXE_ipars"))
        .args([
            "init",
            "--public-endpoint",
            &format!("127.0.0.1:{relay_udp_port}"),
            "--bootstrap-scheme",
            "http",
            "--emit-issuer-private-key",
            "--allow-relay",
            "--unlimited-uses",
            "--token-ttl-seconds",
            "3600",
            "--allowed-route",
            "100.64.0.0/10",
            "--allowed-route",
            "172.18.0.0/16",
        ])
        .output()
        .context("failed to run ipars init")?;
    ensure_success("ipars init", &output)?;
    serde_json::from_slice(&output.stdout).context("failed to parse ipars init output")
}

struct ComposeOverrideConfig<'a> {
    repo_root: &'a Path,
    cluster_id: &'a str,
    issuer_node_id: &'a str,
    issuer_public_key: &'a str,
    join_token: &'a str,
    relay_admission_bearer_token: &'a str,
    ports: ComposeOverridePorts,
}

struct ComposeOverridePorts {
    control_plane: u16,
    signal: u16,
    stun: u16,
    stun_alternate: u16,
    stun_http: u16,
    relay_udp: u16,
    relay_http: u16,
    agent: u16,
    agent_b: u16,
}

struct ComposeApiPorts {
    agent: u16,
    agent_b: u16,
}

struct ComposeAgentNodes {
    agent: String,
    agent_b: String,
}

fn compose_override(config: &ComposeOverrideConfig<'_>) -> String {
    format!(
        r#"services:
  postgres:
    ports: !reset []

  control-plane:
    command:
      - control-plane
      - --listen
      - 0.0.0.0:8443
      - --cluster-id
      - {cluster_id}
      - --issuer-node-id
      - {issuer_node_id}
      - --issuer-key-id
      - root
      - --issuer-public-key
      - {issuer_public_key}
    environment: !override
      IPARS_DATABASE_URL: postgres://ipars:ipars-dev@postgres:5432/ipars
      IPARS_ROLE: control-plane
      IPARS_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN: {control_plane_operator_api_bearer_token}
    secrets: !reset []
    ports:
      - "{control_plane_port}:8443"

  signal:
    environment: !override
      IPARS_ROLE: signal
      IPARS_SIGNAL_CONTROL_PLANE_URLS: http://control-plane:8443
      IPARS_SIGNAL_OPERATOR_API_BEARER_TOKEN: {signal_operator_api_bearer_token}
    secrets: !reset []
    ports:
      - "{signal_port}:9443"

  stun:
    environment: !override
      IPARS_ROLE: stun
      IPARS_STUN_ALTERNATE_LISTEN: 0.0.0.0:3480
      IPARS_STUN_OPERATOR_API_BEARER_TOKEN: {stun_operator_api_bearer_token}
    secrets: !reset []
    ports:
      - "{stun_port}:3478/udp"
      - "{stun_alternate_port}:3480/udp"
      - "{stun_http_port}:3479"

  relay:
    cap_add: !reset []
    devices: !reset []
    environment: !override
      IPARS_ROLE: relay
      IPARS_RELAY_PUBLIC_ENDPOINT: 127.0.0.1:{relay_udp_port}
      IPARS_RELAY_ADMISSION_URL: http://127.0.0.1:{relay_http_port}
      IPARS_RELAY_MAX_SESSIONS: "10000"
      IPARS_RELAY_MAX_SESSIONS_PER_NODE: "0"
      IPARS_RELAY_MAX_MBPS: "1000"
      IPARS_RELAY_SESSION_TTL_SECONDS: "300"
      IPARS_RELAY_ADMISSION_RATE_LIMIT: "4096"
      IPARS_RELAY_ADMISSION_RATE_LIMIT_WINDOW_SECONDS: "60"
      IPARS_RELAY_ADMISSION_BEARER_TOKEN: {relay_admission_bearer_token}
      IPARS_RELAY_OPERATOR_API_BEARER_TOKEN: {relay_operator_api_bearer_token}
    secrets: !reset []
    ports:
      - "{relay_udp_port}:51820/udp"
      - "{relay_http_port}:9580"

  agent:
    cap_add: !reset []
    devices: !reset []
    secrets: !reset []
    volumes: !reset
      - agent-data:/var/lib/ipars
    environment: !override
      IPARS_ROLE: agent
      IPARS_AGENT_CONTROL_PLANE_URL: http://127.0.0.1:{control_plane_port}
      IPARS_AGENT_SIGNAL_URL: http://127.0.0.1:{signal_port}
      IPARS_AGENT_JOIN_TOKEN: {join_token}
      IPARS_AGENT_API_BEARER_TOKEN: {agent_api_bearer_token}
      IPARS_AGENT_STUN_BIND: 0.0.0.0:0
      IPARS_AGENT_RUNTIME_BACKEND: dry-run
      IPARS_AGENT_APPLY_DOCKER_ROUTES: "false"
      IPARS_DOCKER_DISCOVER_NETWORKS: "false"
      IPARS_AGENT_RELAY_PUBLIC_ENDPOINT: 127.0.0.1:{relay_udp_port}
      IPARS_AGENT_RELAY_ADMISSION_URL: http://127.0.0.1:{relay_http_port}
      IPARS_AGENT_RELAY_STATUS_URL: http://127.0.0.1:{relay_http_port}
      IPARS_AGENT_RELAY_MAX_SESSIONS: "10000"
      IPARS_AGENT_RELAY_MAX_MBPS: "1000"
      IPARS_AGENT_RELAY_ADMISSION_BEARER_TOKEN: {relay_admission_bearer_token}
    command:
      - agent
      - --listen
      - 0.0.0.0:{agent_port}
      - --state-path
      - /var/lib/ipars/agent.json
      - --apply-peer-map
      - --peer-map-poll-interval-seconds
      - "1"
      - --signal-path-interval-seconds
      - "1"
      - --heartbeat-interval-seconds
      - "1"
      - --stun-server
      - 127.0.0.1:{stun_port}
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:{agent_port}/healthz >/dev/null"]
      interval: 10s
      timeout: 3s
      retries: 6
      start_period: 10s

  agent-b:
    build:
      context: {repo_root}
      dockerfile: docker/Dockerfile
    entrypoint:
      - /usr/local/bin/iparsd
    network_mode: host
    volumes:
      - agent-b-data:/var/lib/ipars
    environment:
      IPARS_ROLE: agent
      IPARS_AGENT_CONTROL_PLANE_URL: http://127.0.0.1:{control_plane_port}
      IPARS_AGENT_SIGNAL_URL: http://127.0.0.1:{signal_port}
      IPARS_AGENT_JOIN_TOKEN: {join_token}
      IPARS_AGENT_API_BEARER_TOKEN: {agent_api_bearer_token}
      IPARS_AGENT_STUN_BIND: 0.0.0.0:0
      IPARS_AGENT_RUNTIME_BACKEND: dry-run
      IPARS_AGENT_APPLY_DOCKER_ROUTES: "false"
      IPARS_DOCKER_DISCOVER_NETWORKS: "false"
    command:
      - agent
      - --listen
      - 0.0.0.0:{agent_b_port}
      - --state-path
      - /var/lib/ipars/agent-b.json
      - --apply-peer-map
      - --peer-map-poll-interval-seconds
      - "1"
      - --signal-path-interval-seconds
      - "1"
      - --heartbeat-interval-seconds
      - "1"
      - --stun-server
      - 127.0.0.1:{stun_port}
    depends_on:
      control-plane:
        condition: service_healthy
      signal:
        condition: service_healthy
      stun:
        condition: service_healthy
      relay:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:{agent_b_port}/healthz >/dev/null"]
      interval: 10s
      timeout: 3s
      retries: 6
      start_period: 10s

volumes:
  agent-b-data:
"#,
        repo_root = yaml_single_quoted(&config.repo_root.display().to_string()),
        cluster_id = config.cluster_id,
        issuer_node_id = config.issuer_node_id,
        issuer_public_key = config.issuer_public_key,
        control_plane_operator_api_bearer_token =
            yaml_single_quoted(COMPOSE_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN),
        signal_operator_api_bearer_token =
            yaml_single_quoted(COMPOSE_SIGNAL_OPERATOR_API_BEARER_TOKEN),
        stun_operator_api_bearer_token = yaml_single_quoted(COMPOSE_STUN_OPERATOR_API_BEARER_TOKEN),
        relay_operator_api_bearer_token =
            yaml_single_quoted(COMPOSE_RELAY_OPERATOR_API_BEARER_TOKEN),
        join_token = yaml_single_quoted(config.join_token),
        agent_api_bearer_token = yaml_single_quoted(COMPOSE_AGENT_API_BEARER_TOKEN),
        relay_admission_bearer_token = yaml_single_quoted(config.relay_admission_bearer_token),
        control_plane_port = config.ports.control_plane,
        signal_port = config.ports.signal,
        stun_port = config.ports.stun,
        stun_alternate_port = config.ports.stun_alternate,
        stun_http_port = config.ports.stun_http,
        relay_udp_port = config.ports.relay_udp,
        relay_http_port = config.ports.relay_http,
        agent_port = config.ports.agent,
        agent_b_port = config.ports.agent_b,
    )
}

fn yaml_single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn assert_rendered_compose_env(rendered: &str, expected: &[(&str, &str)]) -> Result<()> {
    for (name, value) in expected {
        anyhow::ensure!(
            rendered.contains(name) && rendered.contains(value),
            "rendered Compose config did not include expected environment {name}={value}\n{rendered}"
        );
    }
    Ok(())
}

#[derive(Debug)]
struct ComposeProject {
    repo_root: PathBuf,
    project_name: String,
    compose_files: Vec<PathBuf>,
    docker_socket: PathBuf,
    extra_env: Vec<(String, String)>,
}

#[derive(Debug)]
struct ComposeCleanup {
    repo_root: PathBuf,
    project_name: String,
    compose_files: Vec<PathBuf>,
    docker_socket: PathBuf,
    extra_env: Vec<(String, String)>,
}

impl Drop for ComposeCleanup {
    fn drop(&mut self) {
        let project = ComposeProject {
            repo_root: self.repo_root.clone(),
            project_name: self.project_name.clone(),
            compose_files: self.compose_files.clone(),
            docker_socket: self.docker_socket.clone(),
            extra_env: self.extra_env.clone(),
        };
        let mut command = compose_command(&project);
        command.args(["down", "--volumes", "--remove-orphans", "--timeout", "1"]);
        let _ = command.output();
    }
}

#[derive(Debug)]
struct TempDirGuard {
    path: PathBuf,
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_compose<const N: usize>(compose: &ComposeProject, args: [&str; N]) -> Result<Output> {
    let mut command = compose_command(compose);
    command.args(args);
    let output = command
        .output()
        .with_context(|| format!("failed to run docker compose {args:?}"))?;
    ensure_success(&format!("docker compose {args:?}"), &output)?;
    Ok(output)
}

fn run_compose_with_diagnostics<const N: usize>(
    compose: &ComposeProject,
    args: [&str; N],
) -> Result<Output> {
    let mut command = compose_command(compose);
    command.args(args);
    let output = command
        .output()
        .with_context(|| format!("failed to run docker compose {args:?}"))?;
    if output.status.success() {
        return Ok(output);
    }
    anyhow::bail!(
        "docker compose {args:?} failed with status {}\nstdout:\n{}\nstderr:\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        compose_diagnostics(compose)
    )
}

fn assert_compose_services_running(compose: &ComposeProject, expected: &[&str]) -> Result<()> {
    let output = run_compose(compose, ["ps", "--format", "json"])?;
    let containers = parse_compose_ps(&output.stdout)?;
    for service in expected {
        let container = containers
            .iter()
            .find(|container| {
                json_string_field(container, &["Service", "service"]) == Some(*service)
            })
            .with_context(|| {
                format!(
                    "service {service} was missing from docker compose ps\n{}",
                    compose_diagnostics(compose)
                )
            })?;
        let state = json_string_field(container, &["State", "state"]).unwrap_or_default();
        anyhow::ensure!(
            state == "running",
            "service {service} state was {state:?}\n{}",
            compose_diagnostics(compose)
        );
        if let Some(health) = json_string_field(container, &["Health", "health"]) {
            anyhow::ensure!(
                health.is_empty() || health == "healthy",
                "service {service} health was {health:?}\n{}",
                compose_diagnostics(compose)
            );
        }
    }
    Ok(())
}

fn assert_compose_service_apis(
    compose: &ComposeProject,
    ports: &ComposeApiPorts,
) -> Result<ComposeAgentNodes> {
    let control_plane_metrics = wait_for_json(
        compose,
        "control-plane metrics",
        "control-plane",
        "http://127.0.0.1:8443/v1/metrics",
        |value| {
            ensure_json_u64_at_least(value, "node_count", 2)?;
            ensure_json_u64_at_least(value, "vpn_pool_allocated_count", 2)?;
            Ok(())
        },
    )?;
    anyhow::ensure!(
        json_string_field(&control_plane_metrics, &["cluster_id"]).is_some(),
        "control-plane metrics did not include cluster_id: {control_plane_metrics}"
    );

    wait_for_json(
        compose,
        "signal metrics",
        "signal",
        "http://127.0.0.1:9443/v1/metrics",
        |value| {
            ensure_json_u64_at_least(value, "node_count", 2)?;
            ensure_json_u64_at_least(value, "node_upsert_count", 2)?;
            Ok(())
        },
    )?;

    wait_for_json(
        compose,
        "STUN metrics",
        "stun",
        "http://127.0.0.1:3479/v1/metrics",
        |value| {
            ensure_json_string_contains(value, "listen", "3478")?;
            ensure_json_string_contains(value, "alternate_listen", "3480")?;
            Ok(())
        },
    )?;

    wait_for_json(
        compose,
        "relay status",
        "relay",
        "http://127.0.0.1:9580/v1/status",
        |value| {
            ensure_json_string_equals(value, "relay_node", "relay-dev")?;
            ensure_json_string_equals(value, "health", "healthy")?;
            ensure_json_u64_at_least(value, "admission_attempt_count", 0)?;
            Ok(())
        },
    )?;

    let agent = assert_compose_agent_status(compose, "agent", ports.agent)?;
    let agent_b = assert_compose_agent_status(compose, "agent-b", ports.agent_b)?;
    anyhow::ensure!(
        agent != agent_b,
        "Compose smoke agents unexpectedly registered the same node_id {agent:?}"
    );

    Ok(ComposeAgentNodes { agent, agent_b })
}

fn assert_compose_agent_status(
    compose: &ComposeProject,
    service: &str,
    port: u16,
) -> Result<String> {
    let status = wait_for_json(
        compose,
        &format!("{service} status"),
        service,
        &format!("http://127.0.0.1:{port}/v1/status"),
        |value| {
            ensure_json_string_nonempty(value, "node_id")?;
            ensure_json_string_nonempty(value, "identity_public_key")?;
            ensure_json_string_nonempty(value, "wireguard_public_key")?;
            ensure_json_string_nonempty(value, "vpn_ip")?;
            let candidate_count = json_u64_field(value, "candidate_count")?;
            let candidates = value
                .get("candidates")
                .and_then(Value::as_array)
                .context("agent status missing candidates array")?;
            anyhow::ensure!(
                candidate_count == candidates.len() as u64,
                "agent status candidate_count {candidate_count} did not match candidates array length {}: {value}",
                candidates.len()
            );
            Ok(())
        },
    )?;

    json_string_required(&status, "node_id")
}

fn assert_compose_control_plane_peer_maps(
    compose: &ComposeProject,
    nodes: &ComposeAgentNodes,
) -> Result<()> {
    wait_for_ipars_control_plane_query(
        compose,
        "control-plane peer map for agent",
        "agent",
        &[
            "peers",
            "--control-plane-url",
            "http://127.0.0.1:8443",
            "--node-id",
            &nodes.agent,
        ],
        |value| ensure_peer_map_contains(value, &nodes.agent_b),
    )?;
    wait_for_ipars_control_plane_query(
        compose,
        "control-plane peer map for agent-b",
        "agent-b",
        &[
            "peers",
            "--control-plane-url",
            "http://127.0.0.1:8443",
            "--node-id",
            &nodes.agent_b,
        ],
        |value| ensure_peer_map_contains(value, &nodes.agent),
    )?;
    wait_for_json(
        compose,
        "control-plane metrics after two-agent peer maps",
        "control-plane",
        "http://127.0.0.1:8443/v1/metrics",
        |value| {
            ensure_json_u64_at_least(value, "peer_map_visible_count", 2)?;
            Ok(())
        },
    )?;

    Ok(())
}

fn assert_compose_agent_peer_maps(
    compose: &ComposeProject,
    nodes: &ComposeAgentNodes,
    ports: &ComposeApiPorts,
) -> Result<()> {
    assert_compose_agent_peer_map(compose, "agent", ports.agent, &nodes.agent_b)?;
    assert_compose_agent_peer_map(compose, "agent-b", ports.agent_b, &nodes.agent)?;
    Ok(())
}

fn assert_compose_agent_peer_map(
    compose: &ComposeProject,
    service: &str,
    port: u16,
    expected_node_id: &str,
) -> Result<()> {
    wait_for_json(
        compose,
        &format!("{service} peer-map metrics"),
        service,
        &format!("http://127.0.0.1:{port}/v1/metrics"),
        |value| {
            ensure_json_bool_equals(value, "peer_map_synced", true)?;
            ensure_json_u64_at_least(value, "peer_map_peer_count", 1)?;
            Ok(())
        },
    )?;
    wait_for_json(
        compose,
        &format!("{service} peer map"),
        service,
        &format!("http://127.0.0.1:{port}/v1/peers"),
        |value| ensure_peer_map_contains(value, expected_node_id),
    )?;
    Ok(())
}

fn assert_compose_agent_lazy_connect_paths(
    compose: &ComposeProject,
    nodes: &ComposeAgentNodes,
    ports: &ComposeApiPorts,
) -> Result<()> {
    assert_compose_agent_peer_activity(compose, "agent", ports.agent, &nodes.agent_b)?;
    assert_compose_agent_peer_activity(compose, "agent-b", ports.agent_b, &nodes.agent)?;
    assert_compose_agent_path(compose, "agent", ports.agent, &nodes.agent, &nodes.agent_b)?;
    assert_compose_agent_path(
        compose,
        "agent-b",
        ports.agent_b,
        &nodes.agent_b,
        &nodes.agent,
    )?;
    Ok(())
}

fn assert_compose_agent_packet_flow_lazy_connect(
    compose: &ComposeProject,
    nodes: &ComposeAgentNodes,
    ports: &ComposeApiPorts,
) -> Result<()> {
    assert_compose_agent_packet_flow(compose, "agent", ports.agent, &nodes.agent, &nodes.agent_b)?;
    assert_compose_agent_packet_flow(
        compose,
        "agent-b",
        ports.agent_b,
        &nodes.agent_b,
        &nodes.agent,
    )?;
    assert_compose_agent_path(compose, "agent", ports.agent, &nodes.agent, &nodes.agent_b)?;
    assert_compose_agent_path(
        compose,
        "agent-b",
        ports.agent_b,
        &nodes.agent_b,
        &nodes.agent,
    )?;
    Ok(())
}

fn assert_compose_agent_packet_flow(
    compose: &ComposeProject,
    service: &str,
    port: u16,
    local: &str,
    remote: &str,
) -> Result<()> {
    let destination = compose_agent_peer_vpn_ip(compose, service, port, remote)?;
    let body = serde_json::json!({
        "destination": destination,
        "source": "192.0.2.10",
        "protocol": "udp",
        "source_port": 50000,
        "destination_port": 51820,
        "detector": "compose-smoke",
        "application": "wire_guard",
        "conntrack_status": ["assured"],
        "pin": true,
    })
    .to_string();
    let response = compose_exec_post_json(
        compose,
        service,
        &format!("http://127.0.0.1:{port}/v1/packet-flow"),
        &body,
    )?;
    ensure_json_string_equals(&response, "destination", &destination)?;
    ensure_json_field_absent_or_null(&response, &["filtered_reason"])?;
    ensure_json_string_equals_at(&response, &["matched", "peer"], remote)?;
    ensure_json_string_equals_at(&response, &["matched", "kind"], "peer_vpn_ip")?;
    ensure_json_bool_equals_at(&response, &["matched", "pinned"], true)?;
    ensure_json_string_equals_at(&response, &["observation", "source"], "192.0.2.10")?;
    ensure_json_string_equals_at(&response, &["observation", "protocol"], "udp")?;
    ensure_json_string_equals_at(&response, &["observation", "detector"], "compose-smoke")?;
    ensure_json_string_equals_at(&response, &["observation", "application"], "wire_guard")?;

    assert_compose_agent_packet_flow_no_overlay_match(compose, service, port)?;

    wait_for_json(
        compose,
        &format!("{service} packet-flow lazy-connect metrics"),
        service,
        &format!("http://127.0.0.1:{port}/v1/metrics"),
        |value| {
            ensure_json_string_equals(value, "node_id", local)?;
            ensure_json_u64_at_least(value, "packet_flow_observation_count", 2)?;
            ensure_json_u64_at_least(value, "packet_flow_match_count", 1)?;
            ensure_json_u64_at_least(value, "packet_flow_unmatched_count", 1)?;
            ensure_json_u64_at_least(value, "packet_flow_filtered_count", 1)?;
            ensure_json_count_array_entry_at_least(
                value,
                "packet_flow_filtered_reason_counts",
                "reason",
                "no_overlay_match",
                1,
            )?;
            ensure_json_u64_at_least_at(value, &["lazy_connect", "observed_peer_vpn_ip_count"], 1)?;
            ensure_json_u64_at_least_at(value, &["lazy_connect", "active_peer_count"], 1)?;
            ensure_json_u64_at_least_at(value, &["lazy_connect", "pinned_peer_count"], 1)?;
            Ok(())
        },
    )?;
    assert_compose_agent_packet_flow_prometheus_metrics(compose, service, port, local)?;

    Ok(())
}

fn assert_compose_agent_packet_flow_no_overlay_match(
    compose: &ComposeProject,
    service: &str,
    port: u16,
) -> Result<()> {
    let body = serde_json::json!({
        "destination": "198.51.100.10",
        "source": "192.0.2.10",
        "protocol": "udp",
        "source_port": 50001,
        "destination_port": 51820,
        "detector": "compose-smoke-miss",
        "application": "wire_guard",
        "conntrack_status": ["assured"],
        "pin": false,
    })
    .to_string();
    let response = compose_exec_post_json(
        compose,
        service,
        &format!("http://127.0.0.1:{port}/v1/packet-flow"),
        &body,
    )?;
    ensure_json_string_equals(&response, "destination", "198.51.100.10")?;
    ensure_json_string_equals(&response, "filtered_reason", "no_overlay_match")?;
    ensure_json_field_absent_or_null(&response, &["matched"])?;
    ensure_json_string_equals_at(
        &response,
        &["observation", "detector"],
        "compose-smoke-miss",
    )?;
    ensure_json_string_equals_at(&response, &["observation", "application"], "wire_guard")?;
    Ok(())
}

fn assert_compose_agent_packet_flow_prometheus_metrics(
    compose: &ComposeProject,
    service: &str,
    port: u16,
    node_id: &str,
) -> Result<()> {
    let metrics = compose_exec_text(
        compose,
        service,
        &format!("http://127.0.0.1:{port}/metrics"),
    )?;
    ensure_prometheus_sample_at_least(
        &metrics,
        "ipars_agent_packet_flow_observations_total",
        node_id,
        1.0,
    )?;
    ensure_prometheus_sample_at_least(
        &metrics,
        "ipars_agent_packet_flow_matches_total",
        node_id,
        1.0,
    )?;
    ensure_prometheus_sample_at_least(
        &metrics,
        "ipars_agent_packet_flow_unmatched_total",
        node_id,
        1.0,
    )?;
    ensure_prometheus_sample_at_least(
        &metrics,
        "ipars_agent_packet_flow_filtered_total",
        node_id,
        1.0,
    )?;
    ensure_prometheus_sample_with_labels_at_least(
        &metrics,
        "ipars_agent_packet_flow_filtered_by_reason_total",
        &[("node_id", node_id), ("reason", "no_overlay_match")],
        1.0,
    )?;
    ensure_prometheus_sample_at_least(&metrics, "ipars_agent_observed_peer_vpn_ips", node_id, 1.0)?;
    ensure_prometheus_sample_with_labels_at_least(
        &metrics,
        "ipars_agent_packet_flow_classified_by_lifecycle_total",
        &[("node_id", node_id), ("classification", "assured")],
        1.0,
    )?;
    ensure_prometheus_sample_with_labels_at_least(
        &metrics,
        "ipars_agent_packet_flow_classified_by_application_total",
        &[("node_id", node_id), ("application", "wireguard")],
        1.0,
    )?;
    ensure_prometheus_sample_at_least(&metrics, "ipars_agent_active_peers", node_id, 1.0)?;
    ensure_prometheus_sample_at_least(&metrics, "ipars_agent_pinned_peers", node_id, 1.0)?;
    Ok(())
}

fn compose_agent_peer_vpn_ip(
    compose: &ComposeProject,
    service: &str,
    port: u16,
    expected_node_id: &str,
) -> Result<String> {
    let peer_map = wait_for_json(
        compose,
        &format!("{service} peer map for packet-flow destination"),
        service,
        &format!("http://127.0.0.1:{port}/v1/peers"),
        |value| ensure_peer_map_contains(value, expected_node_id),
    )?;
    peer_map_peer_string(&peer_map, expected_node_id, "vpn_ip")
}

fn peer_map_peer_string(value: &Value, expected_node_id: &str, field: &str) -> Result<String> {
    let peers = value
        .get("peers")
        .and_then(Value::as_array)
        .context("peer map missing peers array")?;
    for peer in peers {
        let node_id = json_string_required(peer, "node_id")?;
        if node_id == expected_node_id {
            return json_string_required(peer, field);
        }
    }
    anyhow::bail!("peer map did not include expected node {expected_node_id}: {value}")
}

fn assert_compose_agent_peer_activity(
    compose: &ComposeProject,
    service: &str,
    port: u16,
    peer: &str,
) -> Result<()> {
    let body = serde_json::json!({
        "peer": peer,
        "pin": true,
    })
    .to_string();
    let response = compose_exec_post_json(
        compose,
        service,
        &format!("http://127.0.0.1:{port}/v1/peer-activity"),
        &body,
    )?;
    ensure_json_string_equals(&response, "peer", peer)?;
    ensure_json_bool_equals(&response, "pinned", true)?;
    Ok(())
}

fn assert_compose_agent_path(
    compose: &ComposeProject,
    service: &str,
    port: u16,
    local: &str,
    remote: &str,
) -> Result<()> {
    wait_for_json(
        compose,
        &format!("{service} lazy-connect path metrics"),
        service,
        &format!("http://127.0.0.1:{port}/v1/metrics"),
        |value| {
            ensure_json_u64_at_least(value, "path_count", 1)?;
            Ok(())
        },
    )?;
    wait_for_json(
        compose,
        &format!("{service} lazy-connect paths"),
        service,
        &format!("http://127.0.0.1:{port}/v1/paths"),
        |value| ensure_agent_paths_contain(value, local, remote),
    )?;
    Ok(())
}

fn ensure_agent_paths_contain(value: &Value, local: &str, remote: &str) -> Result<()> {
    let paths = value
        .get("paths")
        .and_then(Value::as_array)
        .context("agent paths response missing paths array")?;
    for path in paths {
        let path_local = json_string_required_at(path, &["key", "local"])?;
        let path_remote = json_string_required_at(path, &["key", "remote"])?;
        if path_local == local && path_remote == remote {
            ensure_json_string_nonempty(path, "selected_state")?;
            return Ok(());
        }
    }
    anyhow::bail!("agent paths did not include path {local}->{remote}: {value}")
}

fn assert_compose_signal_path_negotiation_metrics(compose: &ComposeProject) -> Result<()> {
    wait_for_json(
        compose,
        "signal path negotiation metrics",
        "signal",
        "http://127.0.0.1:9443/v1/metrics",
        |value| {
            ensure_json_u64_at_least(value, "path_negotiation_count", 2)?;
            ensure_json_u64_equals(value, "path_acl_denied_count", 0)?;
            ensure_json_u64_equals(value, "relay_candidate_acl_denied_count", 0)?;
            ensure_json_count_array_total_at_least(value, "path_negotiation_state_counts", 2)?;
            Ok(())
        },
    )?;
    Ok(())
}

fn assert_compose_control_plane_path_state(
    compose: &ComposeProject,
    nodes: &ComposeAgentNodes,
) -> Result<()> {
    assert_compose_control_plane_node_path(compose, "agent", &nodes.agent, &nodes.agent_b)?;
    assert_compose_control_plane_node_path(compose, "agent-b", &nodes.agent_b, &nodes.agent)?;
    wait_for_json(
        compose,
        "control-plane metrics after agent path-state heartbeats",
        "control-plane",
        "http://127.0.0.1:8443/v1/metrics",
        |value| {
            ensure_json_u64_at_least(value, "path_count", 2)?;
            Ok(())
        },
    )?;
    Ok(())
}

fn assert_compose_control_plane_node_path(
    compose: &ComposeProject,
    service: &str,
    local: &str,
    remote: &str,
) -> Result<()> {
    wait_for_ipars_control_plane_query(
        compose,
        &format!("control-plane path state for {local}"),
        service,
        &[
            "path",
            "status",
            "--control-plane-url",
            "http://127.0.0.1:8443",
            "--node-id",
            local,
        ],
        |value| ensure_agent_paths_contain(value, local, remote),
    )?;
    Ok(())
}

fn ensure_peer_map_contains(value: &Value, expected_node_id: &str) -> Result<()> {
    let peers = value
        .get("peers")
        .and_then(Value::as_array)
        .context("peer map missing peers array")?;
    let peer_ids = peers
        .iter()
        .map(|peer| json_string_required(peer, "node_id"))
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        peer_ids.iter().any(|node_id| node_id == expected_node_id),
        "peer map did not include expected node {expected_node_id}: {value}"
    );
    Ok(())
}

fn assert_compose_stun_dataplane(compose: &ComposeProject) -> Result<()> {
    let primary = compose_exec_ipars_json(
        compose,
        "stun",
        &[
            "stun",
            "probe",
            "--stun-server",
            "127.0.0.1:3478",
            "--local-bind",
            "127.0.0.1:0",
        ],
        "STUN primary UDP probe",
    )?;
    ensure_json_string_equals(&primary, "stun_server", "127.0.0.1:3478")?;
    ensure_json_string_nonempty(&primary, "local_addr")?;
    ensure_json_string_nonempty(&primary, "reflexive_addr")?;

    let alternate = compose_exec_ipars_json(
        compose,
        "stun",
        &[
            "stun",
            "probe",
            "--stun-server",
            "127.0.0.1:3480",
            "--local-bind",
            "127.0.0.1:0",
        ],
        "STUN alternate UDP probe",
    )?;
    ensure_json_string_equals(&alternate, "stun_server", "127.0.0.1:3480")?;
    ensure_json_string_nonempty(&alternate, "local_addr")?;
    ensure_json_string_nonempty(&alternate, "reflexive_addr")?;

    wait_for_json(
        compose,
        "STUN metrics after UDP probes",
        "stun",
        "http://127.0.0.1:3479/v1/metrics",
        |value| {
            ensure_json_u64_at_least(value, "binding_request_count", 2)?;
            ensure_json_u64_at_least(value, "binding_response_count", 2)?;
            ensure_json_u64_equals(value, "socket_send_error_count", 0)?;
            Ok(())
        },
    )?;

    Ok(())
}

fn assert_compose_relay_admission_auth_required(compose: &ComposeProject) -> Result<()> {
    let status = compose_exec_http_status(
        compose,
        "relay",
        "POST",
        "http://127.0.0.1:9580/v1/sessions",
        Some(
            r#"{"left":"compose-unauth-left","right":"compose-unauth-right","left_addr":"127.0.0.1:31001","right_addr":"127.0.0.1:31002"}"#,
        ),
        "unauthenticated relay admission",
    )?;
    anyhow::ensure!(
        status == 401,
        "unauthenticated relay admission returned HTTP {status}, expected 401"
    );

    wait_for_json(
        compose,
        "relay status after unauthenticated admission",
        "relay",
        "http://127.0.0.1:9580/v1/status",
        |value| {
            ensure_json_u64_at_least(value, "admission_attempt_count", 1)?;
            ensure_json_u64_at_least(value, "admission_failure_count", 1)?;
            ensure_json_u64_equals(value, "admission_success_count", 0)?;
            ensure_json_u64_at_least_at(
                value,
                &["admission_failures_by_reason", "unauthorized"],
                1,
            )?;
            Ok(())
        },
    )?;

    Ok(())
}

fn assert_compose_relay_dataplane(compose: &ComposeProject) -> Result<()> {
    let probe = compose_exec_ipars_json(
        compose,
        "relay",
        &[
            "relay",
            "probe",
            "--relay-url",
            "http://127.0.0.1:9580",
            "--relay-udp",
            "127.0.0.1:51820",
            "--left-node-id",
            "compose-left",
            "--right-node-id",
            "compose-right",
            "--payload",
            "compose-relay-dataplane-probe",
            "--send-invalid-credential",
            "--timeout-ms",
            "5000",
        ],
        "relay dataplane probe",
    )?;
    ensure_json_string_equals(&probe, "relay_node", "relay-dev")?;
    ensure_json_u64_at_least_at(
        &probe,
        &["status_after_probe", "dataplane", "datagrams_forwarded"],
        2,
    )?;
    ensure_json_u64_at_least_at(
        &probe,
        &["status_after_probe", "dataplane", "datagrams_dropped"],
        1,
    )?;
    ensure_json_u64_at_least_at(
        &probe,
        &[
            "status_after_probe",
            "dataplane",
            "drops_by_reason",
            "invalid_session_credential",
        ],
        1,
    )?;
    ensure_json_u64_at_least_at(
        &probe,
        &["status_after_probe", "dataplane", "payload_bytes_forwarded"],
        2,
    )?;
    ensure_json_u64_at_least_at(&probe, &["invalid_credential_drop", "bytes_sent"], 1)?;
    ensure_json_u64_at_least_at(
        &probe,
        &["status_after_probe", "admission_success_count"],
        1,
    )?;
    ensure_json_u64_at_least_at(
        &probe,
        &["status_after_probe", "admission_failure_count"],
        1,
    )?;
    ensure_json_u64_at_least_at(
        &probe,
        &[
            "status_after_probe",
            "admission_failures_by_reason",
            "unauthorized",
        ],
        1,
    )?;

    wait_for_json(
        compose,
        "relay status after dataplane probe",
        "relay",
        "http://127.0.0.1:9580/v1/status",
        |value| {
            ensure_json_u64_at_least(value, "admission_success_count", 1)?;
            ensure_json_u64_at_least(value, "admission_failure_count", 1)?;
            ensure_json_u64_at_least_at(
                value,
                &["admission_failures_by_reason", "unauthorized"],
                1,
            )?;
            ensure_json_u64_at_least_at(value, &["capability", "active_sessions"], 1)?;
            ensure_json_u64_at_least_at(value, &["dataplane", "datagrams_received"], 2)?;
            ensure_json_u64_at_least_at(value, &["dataplane", "datagrams_forwarded"], 2)?;
            ensure_json_u64_at_least_at(value, &["dataplane", "datagrams_dropped"], 1)?;
            ensure_json_u64_at_least_at(
                value,
                &["dataplane", "drops_by_reason", "invalid_session_credential"],
                1,
            )?;
            ensure_json_u64_at_least_at(value, &["dataplane", "payload_bytes_forwarded"], 2)?;
            Ok(())
        },
    )?;
    assert_compose_relay_prometheus_metrics(compose)?;

    Ok(())
}

fn assert_compose_relay_prometheus_metrics(compose: &ComposeProject) -> Result<()> {
    let metrics = compose_exec_text(compose, "relay", "http://127.0.0.1:9580/metrics")?;
    ensure_prometheus_sample_at_least_for_label(
        &metrics,
        "ipars_relay_admission_attempts_total",
        "relay_node",
        "relay-dev",
        2.0,
    )?;
    ensure_prometheus_sample_at_least_for_label(
        &metrics,
        "ipars_relay_admission_success_total",
        "relay_node",
        "relay-dev",
        1.0,
    )?;
    ensure_prometheus_sample_at_least_for_label(
        &metrics,
        "ipars_relay_admission_failures_total",
        "relay_node",
        "relay-dev",
        1.0,
    )?;
    ensure_prometheus_sample_with_labels_at_least(
        &metrics,
        "ipars_relay_admission_failures_by_reason_total",
        &[("relay_node", "relay-dev"), ("reason", "unauthorized")],
        1.0,
    )?;
    ensure_prometheus_sample_at_least_for_label(
        &metrics,
        "ipars_relay_datagrams_received_total",
        "relay_node",
        "relay-dev",
        3.0,
    )?;
    ensure_prometheus_sample_at_least_for_label(
        &metrics,
        "ipars_relay_datagrams_forwarded_total",
        "relay_node",
        "relay-dev",
        2.0,
    )?;
    ensure_prometheus_sample_at_least_for_label(
        &metrics,
        "ipars_relay_datagrams_dropped_total",
        "relay_node",
        "relay-dev",
        1.0,
    )?;
    ensure_prometheus_sample_with_labels_at_least(
        &metrics,
        "ipars_relay_datagrams_dropped_by_reason_total",
        &[
            ("relay_node", "relay-dev"),
            ("reason", "invalid_session_credential"),
        ],
        1.0,
    )?;
    Ok(())
}

fn wait_for_ipars_control_plane_query<F>(
    compose: &ComposeProject,
    label: &str,
    service: &str,
    args: &[&str],
    mut validate: F,
) -> Result<Value>
where
    F: FnMut(&Value) -> Result<()>,
{
    let agent_state_path = match service {
        "agent" => "/var/lib/ipars/agent.json",
        "agent-b" => "/var/lib/ipars/agent-b.json",
        _ => anyhow::bail!("service {service} does not have an agent identity state path"),
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let result: Result<Value> = (|| {
            let mut command = compose_command(compose);
            command.args([
                "exec",
                "-T",
                service,
                "/usr/local/bin/ipars",
                "--agent-state-path",
                agent_state_path,
            ]);
            command.args(args);
            let output = command.output().with_context(|| {
                format!("failed to run signed control-plane query {args:?} in {service}")
            })?;
            ensure_success(
                &format!("signed control-plane query {args:?} in {service}"),
                &output,
            )?;
            let value: Value = serde_json::from_slice(&output.stdout).with_context(|| {
                format!(
                    "failed to parse signed control-plane query JSON: {}",
                    String::from_utf8_lossy(&output.stdout)
                )
            })?;
            validate(&value)?;
            Ok(value)
        })();
        match result {
            Ok(value) => return Ok(value),
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(error) => {
                anyhow::bail!(
                    "{label} signed query in service {service} did not satisfy expectations: {error}\n{}",
                    compose_diagnostics(compose)
                )
            }
        }
    }
}

fn wait_for_json<F>(
    compose: &ComposeProject,
    label: &str,
    service: &str,
    url: &str,
    mut validate: F,
) -> Result<Value>
where
    F: FnMut(&Value) -> Result<()>,
{
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match compose_exec_json(compose, service, url).and_then(|value| {
            validate(&value)?;
            Ok(value)
        }) {
            Ok(value) => return Ok(value),
            Err(error) => {
                let error = error.to_string();
                if Instant::now() >= deadline {
                    anyhow::bail!(
                        "{label} from service {service} at {url} did not satisfy expectations: {error}\n{}",
                        compose_diagnostics(compose)
                    );
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }
}

fn compose_exec_json(compose: &ComposeProject, service: &str, url: &str) -> Result<Value> {
    let mut command = compose_command(compose);
    command.args([
        "exec",
        "-T",
        service,
        "curl",
        "-fsS",
        "--max-time",
        "5",
        "-H",
        "Accept: application/json",
    ]);
    add_api_bearer_header(&mut command, service);
    command.arg(url);
    let output = command
        .output()
        .with_context(|| format!("failed to run docker compose exec {service} curl {url}"))?;
    ensure_success(
        &format!("docker compose exec {service} curl {url}"),
        &output,
    )?;
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "failed to parse JSON from docker compose exec {service} curl {url}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn compose_exec_text(compose: &ComposeProject, service: &str, url: &str) -> Result<String> {
    let mut command = compose_command(compose);
    command.args([
        "exec",
        "-T",
        service,
        "curl",
        "-fsS",
        "--max-time",
        "5",
        "-H",
        "Accept: text/plain",
    ]);
    add_api_bearer_header(&mut command, service);
    command.arg(url);
    let output = command
        .output()
        .with_context(|| format!("failed to run docker compose exec {service} curl {url}"))?;
    ensure_success(
        &format!("docker compose exec {service} curl {url}"),
        &output,
    )?;
    String::from_utf8(output.stdout).with_context(|| {
        format!("text response from docker compose exec {service} curl {url} was not UTF-8")
    })
}

fn compose_exec_post_json(
    compose: &ComposeProject,
    service: &str,
    url: &str,
    body: &str,
) -> Result<Value> {
    let mut command = compose_command(compose);
    command.args([
        "exec",
        "-T",
        service,
        "curl",
        "-fsS",
        "--max-time",
        "5",
        "-H",
        "Accept: application/json",
        "-H",
        "Content-Type: application/json",
        "--data-binary",
        body,
    ]);
    add_api_bearer_header(&mut command, service);
    command.arg(url);
    let output = command
        .output()
        .with_context(|| format!("failed to run docker compose exec {service} curl POST {url}"))?;
    ensure_success(
        &format!("docker compose exec {service} curl POST {url}"),
        &output,
    )?;
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "failed to parse JSON from docker compose exec {service} curl POST {url}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn add_api_bearer_header(command: &mut Command, service: &str) {
    let token = match service {
        "agent" | "agent-b" => Some(COMPOSE_AGENT_API_BEARER_TOKEN),
        "control-plane" => Some(COMPOSE_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN),
        "signal" => Some(COMPOSE_SIGNAL_OPERATOR_API_BEARER_TOKEN),
        "stun" => Some(COMPOSE_STUN_OPERATOR_API_BEARER_TOKEN),
        "relay" => Some(COMPOSE_RELAY_OPERATOR_API_BEARER_TOKEN),
        _ => None,
    };
    if let Some(token) = token {
        command.args(["-H", &format!("Authorization: Bearer {token}")]);
    }
}

fn compose_exec_http_status(
    compose: &ComposeProject,
    service: &str,
    method: &str,
    url: &str,
    body: Option<&str>,
    label: &str,
) -> Result<u16> {
    let mut command = compose_command(compose);
    command.args([
        "exec",
        "-T",
        service,
        "curl",
        "-sS",
        "--max-time",
        "5",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "-X",
        method,
    ]);
    if let Some(body) = body {
        command.args([
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            body,
        ]);
    }
    command.arg(url);
    let output = command
        .output()
        .with_context(|| format!("failed to run docker compose exec {service} curl {url}"))?;
    ensure_success(
        &format!("docker compose exec {service} curl {label}"),
        &output,
    )?;
    let status = std::str::from_utf8(&output.stdout)
        .with_context(|| format!("{label} HTTP status output was not UTF-8"))?
        .trim();
    status
        .parse::<u16>()
        .with_context(|| format!("{label} HTTP status output was not a status code: {status:?}"))
}

fn compose_exec_ipars_json(
    compose: &ComposeProject,
    service: &str,
    args: &[&str],
    label: &str,
) -> Result<Value> {
    let mut command = compose_command(compose);
    command.args(["exec", "-T", service, "ipars"]);
    command.args(args);
    let output = command
        .output()
        .with_context(|| format!("failed to run docker compose exec {service} ipars {args:?}"))?;
    ensure_success(
        &format!("docker compose exec {service} ipars {args:?}"),
        &output,
    )?;
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "failed to parse JSON from {label}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn ensure_json_u64_at_least(value: &Value, field: &str, minimum: u64) -> Result<()> {
    let actual = json_u64_field(value, field)?;
    anyhow::ensure!(
        actual >= minimum,
        "expected JSON field {field} to be at least {minimum}, got {actual}: {value}"
    );
    Ok(())
}

fn ensure_json_u64_equals(value: &Value, field: &str, expected: u64) -> Result<()> {
    let actual = json_u64_field(value, field)?;
    anyhow::ensure!(
        actual == expected,
        "expected JSON field {field} to equal {expected}, got {actual}: {value}"
    );
    Ok(())
}

fn ensure_json_bool_equals(value: &Value, field: &str, expected: bool) -> Result<()> {
    let actual = value
        .get(field)
        .and_then(Value::as_bool)
        .with_context(|| format!("JSON field {field} was missing or not a boolean: {value}"))?;
    anyhow::ensure!(
        actual == expected,
        "expected JSON field {field} to equal {expected}, got {actual}: {value}"
    );
    Ok(())
}

fn ensure_json_bool_equals_at(value: &Value, path: &[&str], expected: bool) -> Result<()> {
    let field = path.join(".");
    let actual = json_value_at(value, path)
        .and_then(Value::as_bool)
        .with_context(|| format!("JSON field {field} was missing or not a boolean: {value}"))?;
    anyhow::ensure!(
        actual == expected,
        "expected JSON field {field} to equal {expected}, got {actual}: {value}"
    );
    Ok(())
}

fn ensure_json_field_absent_or_null(value: &Value, path: &[&str]) -> Result<()> {
    let Some(actual) = json_value_at(value, path) else {
        return Ok(());
    };
    anyhow::ensure!(
        actual.is_null(),
        "expected JSON field {} to be absent or null, got {actual}: {value}",
        path.join(".")
    );
    Ok(())
}

fn ensure_json_count_array_total_at_least(value: &Value, field: &str, minimum: u64) -> Result<()> {
    let counts = value
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("JSON field {field} was missing or not an array: {value}"))?;
    let mut total = 0_u64;
    for count in counts {
        ensure_json_string_nonempty(count, "state")?;
        total = total
            .checked_add(json_u64_field(count, "count")?)
            .with_context(|| format!("JSON field {field} count total overflowed: {value}"))?;
    }
    anyhow::ensure!(
        total >= minimum,
        "expected JSON field {field} count total to be at least {minimum}, got {total}: {value}"
    );
    Ok(())
}

fn ensure_json_count_array_entry_at_least(
    value: &Value,
    field: &str,
    key_field: &str,
    expected_key: &str,
    minimum: u64,
) -> Result<()> {
    let counts = value
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("JSON field {field} was missing or not an array: {value}"))?;
    for count in counts {
        let key = json_string_required(count, key_field)?;
        if key != expected_key {
            continue;
        }
        let actual = json_u64_field(count, "count")?;
        anyhow::ensure!(
            actual >= minimum,
            "expected JSON field {field} entry {key_field}={expected_key:?} count to be at least {minimum}, got {actual}: {value}"
        );
        return Ok(());
    }
    anyhow::bail!("JSON field {field} did not include {key_field}={expected_key:?}: {value}")
}

fn ensure_json_u64_at_least_at(value: &Value, path: &[&str], minimum: u64) -> Result<()> {
    let actual = json_u64_field_at(value, path)?;
    anyhow::ensure!(
        actual >= minimum,
        "expected JSON field {} to be at least {minimum}, got {actual}: {value}",
        path.join(".")
    );
    Ok(())
}

fn json_u64_field(value: &Value, field: &str) -> Result<u64> {
    value.get(field).and_then(Value::as_u64).with_context(|| {
        format!("JSON field {field} was missing or not an unsigned integer: {value}")
    })
}

fn json_u64_field_at(value: &Value, path: &[&str]) -> Result<u64> {
    let field = path.join(".");
    json_value_at(value, path)
        .and_then(Value::as_u64)
        .with_context(|| {
            format!("JSON field {field} was missing or not an unsigned integer: {value}")
        })
}

fn json_value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |current, field| current.get(*field))
}

fn ensure_json_string_equals(value: &Value, field: &str, expected: &str) -> Result<()> {
    let actual = json_string_field(value, &[field])
        .with_context(|| format!("JSON field {field} was missing or not a string: {value}"))?;
    anyhow::ensure!(
        actual == expected,
        "expected JSON field {field} to equal {expected:?}, got {actual:?}: {value}"
    );
    Ok(())
}

fn ensure_json_string_equals_at(value: &Value, path: &[&str], expected: &str) -> Result<()> {
    let field = path.join(".");
    let actual = json_string_required_at(value, path)?;
    anyhow::ensure!(
        actual == expected,
        "expected JSON field {field} to equal {expected:?}, got {actual:?}: {value}"
    );
    Ok(())
}

fn ensure_json_string_contains(value: &Value, field: &str, expected: &str) -> Result<()> {
    let actual = json_string_field(value, &[field])
        .with_context(|| format!("JSON field {field} was missing or not a string: {value}"))?;
    anyhow::ensure!(
        actual.contains(expected),
        "expected JSON field {field} to contain {expected:?}, got {actual:?}: {value}"
    );
    Ok(())
}

fn ensure_json_string_nonempty(value: &Value, field: &str) -> Result<()> {
    let actual = json_string_field(value, &[field])
        .with_context(|| format!("JSON field {field} was missing or not a string: {value}"))?;
    anyhow::ensure!(
        !actual.is_empty(),
        "expected JSON field {field} to be non-empty: {value}"
    );
    Ok(())
}

fn ensure_prometheus_sample_at_least(
    text: &str,
    metric: &str,
    node_id: &str,
    minimum: f64,
) -> Result<()> {
    ensure_prometheus_sample_at_least_for_label(text, metric, "node_id", node_id, minimum)
}

fn ensure_prometheus_sample_at_least_for_label(
    text: &str,
    metric: &str,
    label_name: &str,
    label_value: &str,
    minimum: f64,
) -> Result<()> {
    ensure_prometheus_sample_with_labels_at_least(
        text,
        metric,
        &[(label_name, label_value)],
        minimum,
    )
}

fn ensure_prometheus_sample_with_labels_at_least(
    text: &str,
    metric: &str,
    labels: &[(&str, &str)],
    minimum: f64,
) -> Result<()> {
    let rendered_labels = labels
        .iter()
        .map(|(name, value)| format!("{name}=\"{}\"", prometheus_label_value(value)))
        .collect::<Vec<_>>()
        .join(",");
    let prefix = format!("{metric}{{{rendered_labels}}} ");
    for line in text.lines() {
        let Some(value) = line.strip_prefix(&prefix) else {
            continue;
        };
        let actual = value
            .trim()
            .parse::<f64>()
            .with_context(|| format!("Prometheus sample {metric} was not numeric: {line:?}"))?;
        anyhow::ensure!(
            actual >= minimum,
            "expected Prometheus sample {metric} with labels {labels:?} to be at least {minimum}, got {actual}:\n{text}"
        );
        return Ok(());
    }
    anyhow::bail!("Prometheus sample {metric} with labels {labels:?} was missing:\n{text}")
}

fn prometheus_label_value(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('\n', r"\n")
        .replace('"', "\\\"")
}

fn parse_compose_ps(stdout: &[u8]) -> Result<Vec<Value>> {
    let text = std::str::from_utf8(stdout).context("docker compose ps output was not UTF-8")?;
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    match serde_json::from_str::<Value>(text) {
        Ok(value) => {
            if let Some(array) = value.as_array() {
                return Ok(array.clone());
            }
            Ok(vec![value])
        }
        Err(array_error) => text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str::<Value>(line).with_context(|| {
                    format!("failed to parse docker compose ps JSON line after array parse failed: {array_error}")
                })
            })
            .collect(),
    }
}

fn json_string_field<'a>(value: &'a Value, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| value.get(*name)?.as_str())
}

fn json_string_required(value: &Value, field: &str) -> Result<String> {
    json_string_field(value, &[field])
        .map(ToString::to_string)
        .with_context(|| format!("JSON field {field} was missing or not a string: {value}"))
}

fn json_string_required_at(value: &Value, path: &[&str]) -> Result<String> {
    let field = path.join(".");
    json_value_at(value, path)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .with_context(|| format!("JSON field {field} was missing or not a string: {value}"))
}

fn compose_diagnostics(compose: &ComposeProject) -> String {
    let mut ps = compose_command(compose);
    ps.args(["ps", "--all"]);
    let ps_output = ps.output();

    let mut logs = compose_command(compose);
    logs.args(["logs", "--no-color", "--tail", "120"]);
    let logs_output = logs.output();

    format!(
        "docker compose ps:\n{}\n\ndocker compose logs:\n{}",
        command_output_text(ps_output),
        command_output_text(logs_output)
    )
}

fn command_output_text(output: std::io::Result<Output>) -> String {
    match output {
        Ok(output) => format!(
            "status: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => format!("failed to collect diagnostics: {error}"),
    }
}

fn compose_command(compose: &ComposeProject) -> Command {
    let mut command = Command::new("docker");
    command
        .current_dir(&compose.repo_root)
        .env("IPARS_DOCKER_API_SOCKET_HOST", &compose.docker_socket)
        .args(["compose", "-p", &compose.project_name]);
    for (name, value) in &compose.extra_env {
        command.env(name, value);
    }
    for file in &compose.compose_files {
        command.arg("-f").arg(file);
    }
    command
}

fn ensure_success(label: &str, output: &Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    anyhow::bail!(
        "{label} failed with status {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn json_string(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .with_context(|| format!("init output missing string field {key}"))
}

fn create_temp_dir_in(parent: &Path, prefix: &str) -> Result<PathBuf> {
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create temp parent {}", parent.display()))?;
    let path = parent.join(format!("{prefix}-{}", unique_suffix()?));
    fs::create_dir(&path).with_context(|| format!("failed to create {}", path.display()))?;
    Ok(path)
}

fn unique_suffix() -> Result<String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_millis();
    Ok(format!("{}-{millis}", std::process::id()))
}

struct ReservedPorts<T> {
    ports: Vec<u16>,
    _sockets: Vec<T>,
}

fn reserve_tcp_ports(count: usize) -> Result<ReservedPorts<TcpListener>> {
    let mut ports = BTreeSet::new();
    let mut listeners = Vec::new();
    let max_attempts = count.saturating_mul(16).max(16);
    for _ in 0..max_attempts {
        let listener =
            TcpListener::bind("127.0.0.1:0").context("failed to bind ephemeral TCP port")?;
        if ports.insert(listener.local_addr()?.port()) {
            listeners.push(listener);
        }
        if ports.len() == count {
            return Ok(ReservedPorts {
                ports: ports.into_iter().collect(),
                _sockets: listeners,
            });
        }
    }
    anyhow::bail!("failed to allocate {count} distinct ephemeral TCP ports")
}

fn reserve_udp_ports(count: usize) -> Result<ReservedPorts<UdpSocket>> {
    let mut ports = BTreeSet::new();
    let mut sockets = Vec::new();
    let max_attempts = count.saturating_mul(16).max(16);
    for _ in 0..max_attempts {
        let socket = UdpSocket::bind("127.0.0.1:0").context("failed to bind ephemeral UDP port")?;
        if ports.insert(socket.local_addr()?.port()) {
            sockets.push(socket);
        }
        if ports.len() == count {
            return Ok(ReservedPorts {
                ports: ports.into_iter().collect(),
                _sockets: sockets,
            });
        }
    }
    anyhow::bail!("failed to allocate {count} distinct ephemeral UDP ports")
}
