use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ipars_route_manager::{
    DockerNetworkIntent, KubernetesUnderlayIntent, LinuxNetlinkRouteManager, LinuxNetworkNamespace,
    LinuxRouteManager, NamespacedLinuxRouteCommandRunner, RouteManager, RoutePlan,
    SystemRouteCommandRunner,
};
use ipars_types::{NodeId, Route};

#[tokio::test]
async fn linux_route_manager_applies_and_removes_routes_inside_network_namespace(
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("IPARS_RUN_NETNS_TESTS").ok().as_deref() != Some("1") {
        eprintln!("skipping netns integration test; set IPARS_RUN_NETNS_TESTS=1 to run it");
        return Ok(());
    }

    let namespace_name = unique_namespace_name()?;
    let _guard = NamespaceGuard::create(namespace_name.clone())?;
    command(
        "ip",
        ["-n", namespace_name.as_str(), "link", "set", "lo", "up"],
    )?;

    let namespace = LinuxNetworkNamespace::from_name(namespace_name.as_str())?;
    let manager = LinuxRouteManager::new(NamespacedLinuxRouteCommandRunner::new(
        namespace,
        SystemRouteCommandRunner,
    ));
    let plan = RoutePlan {
        interface: "lo".to_string(),
        routes: vec![Route {
            id: "netns-smoke".to_string(),
            cidr: "198.51.100.0/24".parse()?,
            advertised_by: NodeId::from_string("peer-netns"),
            via: None,
            metric: 77,
            tags: Default::default(),
        }],
        policy_rules: Vec::new(),
    };

    manager.apply_routes(plan.clone()).await?;
    let route_after_apply = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "route",
            "show",
            "198.51.100.0/24",
        ],
    )?;
    assert!(route_after_apply.contains("198.51.100.0/24"));
    assert!(route_after_apply.contains("dev lo"));
    assert!(route_after_apply.contains("metric 77"));

    manager.remove_routes(plan).await?;
    let route_after_remove = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "route",
            "show",
            "198.51.100.0/24",
        ],
    )?;
    assert!(route_after_remove.trim().is_empty());

    Ok(())
}

#[tokio::test]
async fn linux_route_manager_applies_docker_and_kubernetes_intents_inside_network_namespace(
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("IPARS_RUN_NETNS_TESTS").ok().as_deref() != Some("1") {
        eprintln!("skipping netns integration test; set IPARS_RUN_NETNS_TESTS=1 to run it");
        return Ok(());
    }

    let namespace_name = unique_namespace_name()?;
    let _guard = NamespaceGuard::create(namespace_name.clone())?;
    command(
        "ip",
        ["-n", namespace_name.as_str(), "link", "set", "lo", "up"],
    )?;

    let namespace = LinuxNetworkNamespace::from_name(namespace_name.as_str())?;
    let manager = LinuxRouteManager::new(NamespacedLinuxRouteCommandRunner::new(
        namespace,
        SystemRouteCommandRunner,
    ));

    let docker_plan = manager
        .apply_docker_intent(DockerNetworkIntent {
            container_namespace: "compose-edge".to_string(),
            host_interface: "docker0".to_string(),
            overlay_interface: "lo".to_string(),
            container_cidrs: vec!["172.18.0.0/16".parse()?],
            expose_host_routes: true,
        })
        .await?;
    let docker_route = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "route",
            "show",
            "table",
            "10064",
            "172.18.0.0/16",
        ],
    )?;
    assert!(docker_route.contains("172.18.0.0/16"));
    assert!(docker_route.contains("dev lo"));
    assert!(docker_route.contains("metric 100"));
    let docker_rule = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "rule",
            "show",
            "priority",
            "10064",
        ],
    )?;
    assert!(docker_rule.contains("fwmark 0x6473"));
    assert!(docker_rule.contains("lookup 10064"));

    manager.remove_routes(docker_plan).await?;
    let docker_route_after_remove = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "route",
            "show",
            "table",
            "10064",
            "172.18.0.0/16",
        ],
    )?;
    assert!(docker_route_after_remove.trim().is_empty());
    let docker_rule_after_remove = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "rule",
            "show",
            "priority",
            "10064",
        ],
    )?;
    assert!(docker_rule_after_remove.trim().is_empty());

    let kubernetes_plan = manager
        .apply_kubernetes_intent(KubernetesUnderlayIntent {
            node_name: "node-a".to_string(),
            overlay_interface: "lo".to_string(),
            api_server_cidrs: vec!["10.0.0.1/32".parse()?],
            service_cidrs: vec!["10.96.0.0/12".parse()?],
            route_provider: NodeId::from_string("route-provider-a"),
        })
        .await?;
    let kubernetes_api_route = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "route",
            "show",
            "table",
            "10064",
            "10.0.0.1/32",
        ],
    )?;
    assert!(kubernetes_api_route.contains("10.0.0.1"));
    assert!(kubernetes_api_route.contains("dev lo"));
    assert!(kubernetes_api_route.contains("metric 50"));
    let kubernetes_service_route = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "route",
            "show",
            "table",
            "10064",
            "10.96.0.0/12",
        ],
    )?;
    assert!(kubernetes_service_route.contains("10.96.0.0/12"));
    assert!(kubernetes_service_route.contains("dev lo"));
    let kubernetes_rule = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "rule",
            "show",
            "priority",
            "10050",
        ],
    )?;
    assert!(kubernetes_rule.contains("lookup 10064"));

    manager.remove_routes(kubernetes_plan).await?;
    let kubernetes_route_after_remove = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "route",
            "show",
            "table",
            "10064",
            "10.96.0.0/12",
        ],
    )?;
    assert!(kubernetes_route_after_remove.trim().is_empty());
    let kubernetes_rule_after_remove = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "rule",
            "show",
            "priority",
            "10050",
        ],
    )?;
    assert!(kubernetes_rule_after_remove.trim().is_empty());

    Ok(())
}

#[tokio::test]
async fn linux_netlink_route_manager_applies_and_removes_routes_inside_network_namespace(
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("IPARS_RUN_NETNS_TESTS").ok().as_deref() != Some("1") {
        eprintln!("skipping netns integration test; set IPARS_RUN_NETNS_TESTS=1 to run it");
        return Ok(());
    }

    let namespace_name = unique_namespace_name()?;
    let _guard = NamespaceGuard::create(namespace_name.clone())?;
    command(
        "ip",
        ["-n", namespace_name.as_str(), "link", "set", "lo", "up"],
    )?;

    let namespace = LinuxNetworkNamespace::from_name(namespace_name.as_str())?;
    let manager = LinuxNetlinkRouteManager::new_in_namespace(namespace);
    let plan = RoutePlan {
        interface: "lo".to_string(),
        routes: vec![Route {
            id: "netns-netlink-smoke".to_string(),
            cidr: "198.51.101.0/24".parse()?,
            advertised_by: NodeId::from_string("peer-netns"),
            via: None,
            metric: 78,
            tags: Default::default(),
        }],
        policy_rules: Vec::new(),
    };

    manager.apply_routes(plan.clone()).await?;
    let route_after_apply = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "route",
            "show",
            "198.51.101.0/24",
        ],
    )?;
    assert!(route_after_apply.contains("198.51.101.0/24"));
    assert!(route_after_apply.contains("dev lo"));
    assert!(route_after_apply.contains("metric 78"));

    manager.remove_routes(plan).await?;
    let route_after_remove = command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "route",
            "show",
            "198.51.101.0/24",
        ],
    )?;
    assert!(route_after_remove.trim().is_empty());

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
    Ok(format!("ipars-it-{}-{nanos}", std::process::id()))
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
