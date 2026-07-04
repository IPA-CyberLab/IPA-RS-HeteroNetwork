use std::collections::BTreeSet;
use std::process::Command;

use async_trait::async_trait;
use ipars_types::{NodeId, Route};
use ipnet::IpNet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RouteManagerError {
    #[error("route manager io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("route manager backend failed: {0}")]
    Backend(String),
    #[error("invalid linux network namespace name: {0}")]
    InvalidNamespace(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    pub interface: String,
    pub routes: Vec<Route>,
    pub policy_rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub table: u32,
    pub priority: u32,
    pub from: Option<IpNet>,
    pub to: Option<IpNet>,
    pub fwmark: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxNetworkNamespace {
    name: String,
}

impl LinuxNetworkNamespace {
    pub fn from_name(name: impl Into<String>) -> Result<Self, RouteManagerError> {
        let name = name.into();
        if !is_valid_namespace_name(&name) {
            return Err(RouteManagerError::InvalidNamespace(name));
        }
        Ok(Self { name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn wrap_program_args(&self, program: &str, args: &[String]) -> (String, Vec<String>) {
        let mut wrapped = Vec::with_capacity(args.len() + 4);
        wrapped.push("netns".to_string());
        wrapped.push("exec".to_string());
        wrapped.push(self.name.clone());
        wrapped.push(program.to_string());
        wrapped.extend(args.iter().cloned());
        ("ip".to_string(), wrapped)
    }
}

fn is_valid_namespace_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerNetworkIntent {
    pub container_namespace: String,
    pub host_interface: String,
    pub overlay_interface: String,
    pub container_cidrs: Vec<IpNet>,
    pub expose_host_routes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesUnderlayIntent {
    pub node_name: String,
    pub overlay_interface: String,
    pub api_server_cidrs: Vec<IpNet>,
    pub service_cidrs: Vec<IpNet>,
    pub route_provider: NodeId,
}

#[async_trait]
pub trait RouteManager: Send + Sync {
    async fn apply_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError>;
    async fn remove_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError>;
    async fn apply_docker_intent(
        &self,
        intent: DockerNetworkIntent,
    ) -> Result<RoutePlan, RouteManagerError>;
    async fn apply_kubernetes_intent(
        &self,
        intent: KubernetesUnderlayIntent,
    ) -> Result<RoutePlan, RouteManagerError>;
}

pub fn docker_route_plan(intent: DockerNetworkIntent) -> RoutePlan {
    RoutePlan {
        interface: intent.overlay_interface,
        routes: intent
            .container_cidrs
            .into_iter()
            .enumerate()
            .map(|(index, cidr)| Route {
                id: format!("docker-{index}"),
                cidr,
                advertised_by: NodeId::from_string(intent.container_namespace.clone()),
                via: None,
                metric: 100,
                tags: Default::default(),
            })
            .collect(),
        policy_rules: vec![PolicyRule {
            table: 10_064,
            priority: 10_064,
            from: None,
            to: None,
            fwmark: Some(0x6473),
        }],
    }
}

pub fn kubernetes_route_plan(intent: KubernetesUnderlayIntent) -> RoutePlan {
    let mut routes = Vec::new();
    for (index, cidr) in intent
        .api_server_cidrs
        .into_iter()
        .chain(intent.service_cidrs)
        .enumerate()
    {
        routes.push(Route {
            id: format!("k8s-{index}"),
            cidr,
            advertised_by: intent.route_provider.clone(),
            via: Some(intent.route_provider.clone()),
            metric: 50,
            tags: Default::default(),
        });
    }

    RoutePlan {
        interface: intent.overlay_interface,
        routes,
        policy_rules: vec![PolicyRule {
            table: 10_064,
            priority: 10_050,
            from: None,
            to: None,
            fwmark: None,
        }],
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxRouteCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl LinuxRouteCommand {
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn in_namespace(self, namespace: &LinuxNetworkNamespace) -> Self {
        let (program, args) = namespace.wrap_program_args(&self.program, &self.args);
        Self { program, args }
    }
}

#[async_trait]
pub trait LinuxRouteCommandRunner: Send + Sync {
    async fn run(&self, command: LinuxRouteCommand) -> Result<(), RouteManagerError>;
}

#[derive(Debug, Clone, Default)]
pub struct SystemRouteCommandRunner;

#[async_trait]
impl LinuxRouteCommandRunner for SystemRouteCommandRunner {
    async fn run(&self, command: LinuxRouteCommand) -> Result<(), RouteManagerError> {
        let output = Command::new(&command.program)
            .args(&command.args)
            .output()?;
        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(RouteManagerError::Backend(format!(
            "{} {} failed: {}",
            command.program,
            command.args.join(" "),
            stderr.trim()
        )))
    }
}

#[derive(Debug, Clone)]
pub struct NamespacedLinuxRouteCommandRunner<R> {
    namespace: LinuxNetworkNamespace,
    inner: R,
}

impl<R> NamespacedLinuxRouteCommandRunner<R> {
    pub fn new(namespace: LinuxNetworkNamespace, inner: R) -> Self {
        Self { namespace, inner }
    }
}

#[async_trait]
impl<R> LinuxRouteCommandRunner for NamespacedLinuxRouteCommandRunner<R>
where
    R: LinuxRouteCommandRunner,
{
    async fn run(&self, command: LinuxRouteCommand) -> Result<(), RouteManagerError> {
        self.inner.run(command.in_namespace(&self.namespace)).await
    }
}

#[derive(Debug, Clone)]
pub struct LinuxRouteManager<R> {
    runner: R,
}

impl<R> LinuxRouteManager<R>
where
    R: LinuxRouteCommandRunner,
{
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    fn route_tables(plan: &RoutePlan) -> Vec<Option<u32>> {
        let tables = plan
            .policy_rules
            .iter()
            .map(|rule| rule.table)
            .collect::<BTreeSet<_>>();
        if tables.is_empty() {
            vec![None]
        } else {
            tables.into_iter().map(Some).collect()
        }
    }

    fn apply_route_commands(plan: &RoutePlan) -> Vec<LinuxRouteCommand> {
        let mut commands = Vec::new();
        for table in Self::route_tables(plan) {
            for route in &plan.routes {
                commands.push(Self::route_command("replace", plan, route, table));
            }
        }
        commands
    }

    fn remove_route_commands(plan: &RoutePlan) -> Vec<LinuxRouteCommand> {
        let mut commands = Vec::new();
        for table in Self::route_tables(plan) {
            for route in &plan.routes {
                commands.push(Self::route_command("del", plan, route, table));
            }
        }
        commands
    }

    fn route_command(
        action: &str,
        plan: &RoutePlan,
        route: &Route,
        table: Option<u32>,
    ) -> LinuxRouteCommand {
        let mut args = vec![
            "route".to_string(),
            action.to_string(),
            route.cidr.to_string(),
            "dev".to_string(),
            plan.interface.clone(),
        ];
        if let Some(table) = table {
            args.push("table".to_string());
            args.push(table.to_string());
        }
        if action == "replace" {
            args.push("metric".to_string());
            args.push(route.metric.to_string());
        }
        LinuxRouteCommand::new("ip", args)
    }

    fn policy_rule_command(action: &str, rule: &PolicyRule) -> LinuxRouteCommand {
        let mut args = vec![
            "rule".to_string(),
            action.to_string(),
            "priority".to_string(),
            rule.priority.to_string(),
        ];
        if let Some(from) = rule.from {
            args.push("from".to_string());
            args.push(from.to_string());
        }
        if let Some(to) = rule.to {
            args.push("to".to_string());
            args.push(to.to_string());
        }
        if let Some(fwmark) = rule.fwmark {
            args.push("fwmark".to_string());
            args.push(format!("0x{fwmark:x}"));
        }
        args.push("table".to_string());
        args.push(rule.table.to_string());
        LinuxRouteCommand::new("ip", args)
    }
}

#[async_trait]
impl<R> RouteManager for LinuxRouteManager<R>
where
    R: LinuxRouteCommandRunner,
{
    async fn apply_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError> {
        for command in Self::apply_route_commands(&plan) {
            self.runner.run(command).await?;
        }
        for rule in &plan.policy_rules {
            let _ = self
                .runner
                .run(Self::policy_rule_command("del", rule))
                .await;
            self.runner
                .run(Self::policy_rule_command("add", rule))
                .await?;
        }
        Ok(())
    }

    async fn remove_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError> {
        for rule in &plan.policy_rules {
            self.runner
                .run(Self::policy_rule_command("del", rule))
                .await?;
        }
        for command in Self::remove_route_commands(&plan) {
            self.runner.run(command).await?;
        }
        Ok(())
    }

    async fn apply_docker_intent(
        &self,
        intent: DockerNetworkIntent,
    ) -> Result<RoutePlan, RouteManagerError> {
        let plan = docker_route_plan(intent);
        self.apply_routes(plan.clone()).await?;
        Ok(plan)
    }

    async fn apply_kubernetes_intent(
        &self,
        intent: KubernetesUnderlayIntent,
    ) -> Result<RoutePlan, RouteManagerError> {
        let plan = kubernetes_route_plan(intent);
        self.apply_routes(plan.clone()).await?;
        Ok(plan)
    }
}

#[derive(Debug, Clone)]
pub struct DryRunLinuxRouteManager;

#[async_trait]
impl RouteManager for DryRunLinuxRouteManager {
    async fn apply_routes(&self, _plan: RoutePlan) -> Result<(), RouteManagerError> {
        Ok(())
    }

    async fn remove_routes(&self, _plan: RoutePlan) -> Result<(), RouteManagerError> {
        Ok(())
    }

    async fn apply_docker_intent(
        &self,
        intent: DockerNetworkIntent,
    ) -> Result<RoutePlan, RouteManagerError> {
        Ok(docker_route_plan(intent))
    }

    async fn apply_kubernetes_intent(
        &self,
        intent: KubernetesUnderlayIntent,
    ) -> Result<RoutePlan, RouteManagerError> {
        Ok(kubernetes_route_plan(intent))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct RecordingRunner {
        commands: Arc<tokio::sync::RwLock<Vec<LinuxRouteCommand>>>,
        fail_rule_delete: bool,
    }

    impl RecordingRunner {
        fn with_failed_rule_delete() -> Self {
            Self {
                fail_rule_delete: true,
                ..Self::default()
            }
        }

        async fn commands(&self) -> Vec<LinuxRouteCommand> {
            self.commands.read().await.clone()
        }
    }

    #[async_trait]
    impl LinuxRouteCommandRunner for RecordingRunner {
        async fn run(&self, command: LinuxRouteCommand) -> Result<(), RouteManagerError> {
            let should_fail_rule_delete = self.fail_rule_delete
                && command.program == "ip"
                && command
                    .args
                    .iter()
                    .map(String::as_str)
                    .take(2)
                    .eq(["rule", "del"]);
            self.commands.write().await.push(command);
            if should_fail_rule_delete {
                Err(RouteManagerError::Backend("rule missing".to_string()))
            } else {
                Ok(())
            }
        }
    }

    fn route_plan() -> Result<RoutePlan, Box<dyn std::error::Error>> {
        Ok(RoutePlan {
            interface: "ipars0".to_string(),
            routes: vec![Route {
                id: "route-a".to_string(),
                cidr: "10.42.0.0/16".parse()?,
                advertised_by: NodeId::from_string("peer-a"),
                via: None,
                metric: 100,
                tags: Default::default(),
            }],
            policy_rules: vec![PolicyRule {
                table: 10_064,
                priority: 10_064,
                from: Some("10.0.0.0/8".parse()?),
                to: None,
                fwmark: Some(0x6473),
            }],
        })
    }

    #[test]
    fn linux_network_namespace_validates_name() -> Result<(), Box<dyn std::error::Error>> {
        let namespace = LinuxNetworkNamespace::from_name("node-a_1.prod")?;

        assert_eq!(namespace.name(), "node-a_1.prod");
        assert!(matches!(
            LinuxNetworkNamespace::from_name(""),
            Err(RouteManagerError::InvalidNamespace(name)) if name.is_empty()
        ));
        assert!(matches!(
            LinuxNetworkNamespace::from_name("../node-a"),
            Err(RouteManagerError::InvalidNamespace(name)) if name == "../node-a"
        ));
        assert!(matches!(
            LinuxNetworkNamespace::from_name("node a"),
            Err(RouteManagerError::InvalidNamespace(name)) if name == "node a"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn namespaced_route_runner_wraps_command() -> Result<(), Box<dyn std::error::Error>> {
        let runner = RecordingRunner::default();
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let namespaced_runner = NamespacedLinuxRouteCommandRunner::new(namespace, runner.clone());

        namespaced_runner
            .run(LinuxRouteCommand::new("ip", ["route", "show"]))
            .await?;

        assert_eq!(
            runner.commands().await,
            vec![LinuxRouteCommand::new(
                "ip",
                ["netns", "exec", "node-a", "ip", "route", "show"],
            )]
        );
        Ok(())
    }

    #[tokio::test]
    async fn docker_intent_builds_explicit_route_plan() -> Result<(), Box<dyn std::error::Error>> {
        let manager = DryRunLinuxRouteManager;
        let plan = manager
            .apply_docker_intent(DockerNetworkIntent {
                container_namespace: "container-a".to_string(),
                host_interface: "eth0".to_string(),
                overlay_interface: "ipars0".to_string(),
                container_cidrs: vec!["172.18.0.0/16".parse()?],
                expose_host_routes: true,
            })
            .await?;

        assert_eq!(plan.interface, "ipars0");
        assert_eq!(plan.routes.len(), 1);
        assert_eq!(plan.policy_rules[0].table, 10_064);
        Ok(())
    }

    #[tokio::test]
    async fn linux_route_manager_generates_apply_and_remove_commands(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runner = RecordingRunner::default();
        let manager = LinuxRouteManager::new(runner.clone());
        let plan = route_plan()?;

        manager.apply_routes(plan.clone()).await?;
        manager.remove_routes(plan).await?;

        assert_eq!(
            runner.commands().await,
            vec![
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "route",
                        "replace",
                        "10.42.0.0/16",
                        "dev",
                        "ipars0",
                        "table",
                        "10064",
                        "metric",
                        "100",
                    ],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "rule",
                        "del",
                        "priority",
                        "10064",
                        "from",
                        "10.0.0.0/8",
                        "fwmark",
                        "0x6473",
                        "table",
                        "10064",
                    ],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "rule",
                        "add",
                        "priority",
                        "10064",
                        "from",
                        "10.0.0.0/8",
                        "fwmark",
                        "0x6473",
                        "table",
                        "10064",
                    ],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "rule",
                        "del",
                        "priority",
                        "10064",
                        "from",
                        "10.0.0.0/8",
                        "fwmark",
                        "0x6473",
                        "table",
                        "10064",
                    ],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "route",
                        "del",
                        "10.42.0.0/16",
                        "dev",
                        "ipars0",
                        "table",
                        "10064",
                    ],
                ),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn linux_route_manager_ignores_missing_rule_during_apply(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runner = RecordingRunner::with_failed_rule_delete();
        let manager = LinuxRouteManager::new(runner.clone());

        manager.apply_routes(route_plan()?).await?;

        assert_eq!(
            runner.commands().await,
            vec![
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "route",
                        "replace",
                        "10.42.0.0/16",
                        "dev",
                        "ipars0",
                        "table",
                        "10064",
                        "metric",
                        "100",
                    ],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "rule",
                        "del",
                        "priority",
                        "10064",
                        "from",
                        "10.0.0.0/8",
                        "fwmark",
                        "0x6473",
                        "table",
                        "10064",
                    ],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "rule",
                        "add",
                        "priority",
                        "10064",
                        "from",
                        "10.0.0.0/8",
                        "fwmark",
                        "0x6473",
                        "table",
                        "10064",
                    ],
                ),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn linux_route_manager_applies_docker_intent_plan(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runner = RecordingRunner::default();
        let manager = LinuxRouteManager::new(runner.clone());

        let plan = manager
            .apply_docker_intent(DockerNetworkIntent {
                container_namespace: "container-a".to_string(),
                host_interface: "eth0".to_string(),
                overlay_interface: "ipars0".to_string(),
                container_cidrs: vec!["172.18.0.0/16".parse()?],
                expose_host_routes: true,
            })
            .await?;

        assert_eq!(plan.routes[0].cidr, "172.18.0.0/16".parse::<IpNet>()?);
        assert_eq!(
            runner.commands().await,
            vec![
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "route",
                        "replace",
                        "172.18.0.0/16",
                        "dev",
                        "ipars0",
                        "table",
                        "10064",
                        "metric",
                        "100",
                    ],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    ["rule", "del", "priority", "10064", "fwmark", "0x6473", "table", "10064",],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    ["rule", "add", "priority", "10064", "fwmark", "0x6473", "table", "10064",],
                ),
            ]
        );
        Ok(())
    }
}
