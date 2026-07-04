use async_trait::async_trait;
use ipars_types::{NodeId, Route};
use ipnet::IpNet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RouteManagerError {
    #[error("route manager backend failed: {0}")]
    Backend(String),
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
        Ok(RoutePlan {
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
        })
    }

    async fn apply_kubernetes_intent(
        &self,
        intent: KubernetesUnderlayIntent,
    ) -> Result<RoutePlan, RouteManagerError> {
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

        Ok(RoutePlan {
            interface: intent.overlay_interface,
            routes,
            policy_rules: vec![PolicyRule {
                table: 10_064,
                priority: 10_050,
                from: None,
                to: None,
                fwmark: None,
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
