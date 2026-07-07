use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::Value;

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

    let control_plane_port = free_tcp_port()?;
    let signal_port = free_tcp_port()?;
    let relay_http_port = free_tcp_port()?;
    let agent_port = free_tcp_port()?;
    let stun_port = free_udp_port()?;
    let stun_http_port = free_tcp_port()?;
    let relay_udp_port = free_udp_port()?;

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
        cluster_id: &cluster_id,
        issuer_node_id: &issuer_node_id,
        issuer_public_key: &issuer_public_key,
        join_token: &join_token,
        ports: ComposeOverridePorts {
            control_plane: control_plane_port,
            signal: signal_port,
            stun: stun_port,
            stun_http: stun_http_port,
            relay_udp: relay_udp_port,
            relay_http: relay_http_port,
            agent: agent_port,
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

    let multi_network_compose = ComposeProject {
        repo_root: repo_root.clone(),
        project_name: format!("ipars-config-{}", unique_suffix()?),
        compose_files: vec![
            PathBuf::from("docker/compose.yaml"),
            PathBuf::from("docker/compose.rootless.yaml"),
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
    let rendered = run_compose(&multi_network_compose, ["config"])?;
    let rendered =
        String::from_utf8(rendered.stdout).context("compose config output was not UTF-8")?;
    assert_rendered_compose_env(
        &rendered,
        &[
            ("IPARS_AGENT_APPLY_DOCKER_ROUTES", "true"),
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
        ],
    )?;

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
    cluster_id: &'a str,
    issuer_node_id: &'a str,
    issuer_public_key: &'a str,
    join_token: &'a str,
    ports: ComposeOverridePorts,
}

struct ComposeOverridePorts {
    control_plane: u16,
    signal: u16,
    stun: u16,
    stun_http: u16,
    relay_udp: u16,
    relay_http: u16,
    agent: u16,
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
    ports:
      - "{control_plane_port}:8443"

  signal:
    ports:
      - "{signal_port}:9443"

  stun:
    ports:
      - "{stun_port}:3478/udp"
      - "{stun_http_port}:3479"

  relay:
    cap_add: !reset []
    devices: !reset []
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
      IPARS_AGENT_APPLY_DOCKER_ROUTES: "false"
      IPARS_DOCKER_DISCOVER_NETWORKS: "false"
      IPARS_AGENT_RELAY_PUBLIC_ENDPOINT: 127.0.0.1:{relay_udp_port}
      IPARS_AGENT_RELAY_ADMISSION_URL: http://127.0.0.1:{relay_http_port}
      IPARS_AGENT_RELAY_STATUS_URL: http://127.0.0.1:{relay_http_port}
      IPARS_AGENT_RELAY_MAX_SESSIONS: "10000"
      IPARS_AGENT_RELAY_MAX_MBPS: "1000"
    command:
      - agent
      - --listen
      - 0.0.0.0:{agent_port}
      - --state-path
      - /var/lib/ipars/agent.json
      - --runtime-backend
      - dry-run
      - --stun-server
      - 127.0.0.1:{stun_port}
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:{agent_port}/healthz >/dev/null"]
      interval: 10s
      timeout: 3s
      retries: 6
      start_period: 10s
"#,
        cluster_id = config.cluster_id,
        issuer_node_id = config.issuer_node_id,
        issuer_public_key = config.issuer_public_key,
        join_token = yaml_single_quoted(config.join_token),
        control_plane_port = config.ports.control_plane,
        signal_port = config.ports.signal,
        stun_port = config.ports.stun,
        stun_http_port = config.ports.stun_http,
        relay_udp_port = config.ports.relay_udp,
        relay_http_port = config.ports.relay_http,
        agent_port = config.ports.agent,
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

fn free_tcp_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("failed to bind ephemeral TCP port")?;
    Ok(listener.local_addr()?.port())
}

fn free_udp_port() -> Result<u16> {
    let socket = UdpSocket::bind("127.0.0.1:0").context("failed to bind ephemeral UDP port")?;
    Ok(socket.local_addr()?.port())
}
