use std::collections::BTreeSet;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, path::PathBuf};

use ipars_route_manager::{
    DockerNetworkIntent, KubernetesUnderlayIntent, LinuxNetlinkRouteManager, LinuxNetworkNamespace,
    LinuxRouteManager, ManagedRoute, ManagedRouteInventory, NamespacedLinuxRouteCommandRunner,
    RouteManager, RoutePlan, RoutePlanOwner, SystemRouteCommandRunner,
};
use ipars_types::{NodeId, Route};

static NEXT_NAMESPACE_ID: AtomicU64 = AtomicU64::new(0);

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
        namespace.clone(),
        SystemRouteCommandRunner,
    ));
    let plan = RoutePlan {
        owner: RoutePlanOwner::PeerMap,
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

    let restarted_manager = LinuxRouteManager::new(NamespacedLinuxRouteCommandRunner::new(
        namespace,
        SystemRouteCommandRunner,
    ));
    let inventory = restarted_manager
        .managed_route_inventory(&plan)
        .await?
        .ok_or("command route inventory unexpectedly unavailable")?;
    assert_eq!(
        inventory,
        ManagedRouteInventory {
            routes: BTreeSet::from([ManagedRoute::current(
                RoutePlanOwner::PeerMap,
                "198.51.100.0/24".parse()?,
                77,
                254,
            )]),
            policy_rules: BTreeSet::new(),
        }
    );
    restarted_manager
        .remove_managed_route_inventory("lo", &inventory)
        .await?;
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
    command(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "route",
            "replace",
            "172.19.0.0/16",
            "dev",
            "lo",
            "protocol",
            "241",
            "table",
            "10065",
            "metric",
            "777",
        ],
    )?;
    command(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "-4",
            "rule",
            "add",
            "priority",
            "10063",
            "table",
            "10065",
            "protocol",
            "241",
        ],
    )?;
    let restarted_manager = LinuxRouteManager::new(NamespacedLinuxRouteCommandRunner::new(
        LinuxNetworkNamespace::from_name(namespace_name.as_str())?,
        SystemRouteCommandRunner,
    ));
    let inventory = restarted_manager
        .managed_route_inventory(&docker_plan)
        .await?
        .ok_or("Docker route inventory unexpectedly unavailable")?;
    assert_eq!(inventory.routes.len(), 2);
    assert_eq!(inventory.policy_rules.len(), 3);
    let reconciliation = restarted_manager
        .reconcile_routes(docker_plan.clone())
        .await?;
    assert_eq!(reconciliation.routes_removed, 1);
    assert_eq!(reconciliation.policy_rules_removed, 1);
    assert!(command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "route",
            "show",
            "table",
            "10065",
            "172.19.0.0/16",
        ],
    )?
    .trim()
    .is_empty());
    assert!(command_output(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "-4",
            "rule",
            "show",
            "priority",
            "10063",
        ],
    )?
    .trim()
    .is_empty());
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
    let manager = LinuxNetlinkRouteManager::new_in_namespace(namespace.clone());
    let plan = RoutePlan {
        owner: RoutePlanOwner::PeerMap,
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

    command(
        "ip",
        [
            "-n",
            namespace_name.as_str(),
            "route",
            "replace",
            "198.51.102.0/24",
            "dev",
            "lo",
            "protocol",
            "240",
            "table",
            "10065",
            "metric",
            "779",
        ],
    )?;

    let restarted_manager = LinuxNetlinkRouteManager::new_in_namespace(namespace);
    let inventory = restarted_manager
        .managed_route_inventory(&plan)
        .await?
        .ok_or("netlink route inventory unexpectedly unavailable")?;
    assert_eq!(inventory.routes.len(), 2);
    assert!(inventory.routes.contains(&ManagedRoute {
        cidr: "198.51.102.0/24".parse()?,
        metric: 779,
        table: 10_065,
        protocol: 240,
    }));
    let reconciliation = restarted_manager.reconcile_routes(plan.clone()).await?;
    assert_eq!(reconciliation.routes_removed, 1);
    let inventory = restarted_manager
        .managed_route_inventory(&plan)
        .await?
        .ok_or("netlink route inventory unexpectedly available after reconcile")?;
    assert_eq!(
        inventory,
        ManagedRouteInventory {
            routes: BTreeSet::from([ManagedRoute::current(
                RoutePlanOwner::PeerMap,
                "198.51.101.0/24".parse()?,
                78,
                254,
            )]),
            policy_rules: BTreeSet::new(),
        }
    );
    restarted_manager
        .remove_managed_route_inventory("lo", &inventory)
        .await?;
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

#[test]
fn namespace_guard_removes_network_namespace_on_drop() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("IPARS_RUN_NETNS_TESTS").ok().as_deref() != Some("1") {
        eprintln!(
            "skipping netns lifecycle integration test; set IPARS_RUN_NETNS_TESTS=1 to run it"
        );
        return Ok(());
    }

    let namespace_name = unique_namespace_name()?;
    let namespace_path = PathBuf::from("/var/run/netns").join(&namespace_name);
    {
        let _guard = NamespaceGuard::create(namespace_name.clone())?;
        assert!(
            namespace_is_listed(&namespace_name)?,
            "created namespace should be listed by `ip netns list`"
        );
        let metadata = fs::symlink_metadata(&namespace_path)?;
        assert!(
            !metadata.file_type().is_symlink(),
            "created namespace entry must not be a symlink"
        );
    }

    assert!(
        !namespace_is_listed(&namespace_name)?,
        "dropped namespace guard should remove namespace from `ip netns list`"
    );
    assert!(
        !namespace_path.exists(),
        "dropped namespace guard should remove {}",
        namespace_path.display()
    );
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
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(unique_namespace_name_from_nanos(nanos))
}

fn unique_namespace_name_from_nanos(nanos: u128) -> String {
    let serial = NEXT_NAMESPACE_ID.fetch_add(1, Ordering::Relaxed);
    format!("ipars-it-{}-{nanos}-{serial}", std::process::id())
}

#[test]
fn namespace_names_are_unique_when_generated_concurrently() {
    let names = std::thread::scope(|scope| {
        (0..32)
            .map(|_| scope.spawn(|| unique_namespace_name_from_nanos(42)))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| match thread.join() {
                Ok(name) => name,
                Err(_) => panic!("namespace name generation thread panicked"),
            })
            .collect::<BTreeSet<_>>()
    });

    assert_eq!(names.len(), 32);
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

fn namespace_is_listed(name: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let output = command_output("ip", ["netns", "list"])?;
    Ok(output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .any(|listed| listed == name))
}

fn command_error(program: &str, output: std::process::Output) -> String {
    format!(
        "{program} failed with status {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )
}
