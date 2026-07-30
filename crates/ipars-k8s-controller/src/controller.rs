use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use ipars_k8s_controller::{
    managed_service, plan_assignments, public_nodes, ready_agent_nodes, ready_endpoint_nodes,
    ManagedService, ServiceAssignment, ServiceKey, ASSIGNED_NODES_ANNOTATION,
    PUBLIC_SERVICE_GENERATION_LABEL, PUBLIC_SERVICE_MANAGED_BY_LABEL,
    PUBLIC_SERVICE_MANAGED_BY_VALUE, PUBLIC_SERVICE_OBSERVED_GENERATION_ANNOTATION,
    RECONCILE_ERROR_ANNOTATION,
};
use k8s_openapi::api::core::v1::{LoadBalancerIngress, Node, Pod, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::{Client, ResourceExt};
use serde_json::json;
use tokio::task::JoinHandle;

use crate::{agones, customer_resources};
use crate::{webhook, ControllerArgs};

pub async fn run(args: ControllerArgs) -> anyhow::Result<()> {
    let client = Client::try_default()
        .await
        .context("failed to initialize Kubernetes client")?;
    let tls = RustlsConfig::from_pem_file(&args.tls_cert_path, &args.tls_key_path)
        .await
        .with_context(|| {
            format!(
                "failed to load webhook TLS certificate {} and key {}",
                args.tls_cert_path.display(),
                args.tls_key_path.display()
            )
        })?;
    let args = Arc::new(args);
    let reconcile_task = spawn_reconcile_loop(client.clone(), Arc::clone(&args));
    let customer_resource_task =
        customer_resources::spawn_reconcile_loop(client, Arc::clone(&args))?;
    let handle = Handle::new();
    let server = axum_server::bind_rustls(args.webhook_bind, tls)
        .handle(handle.clone())
        .serve(webhook::router().into_make_service());
    tokio::pin!(server);

    tracing::info!(
        bind = %args.webhook_bind,
        load_balancer_class = %args.load_balancer_class,
        customer_resources_enabled = customer_resource_task.is_some(),
        "Kubernetes controller and admission webhook started"
    );

    tokio::select! {
        result = &mut server => {
            result.context("admission webhook server failed")?;
        }
        signal = crate::shutdown_signal() => {
            signal?;
            handle.graceful_shutdown(Some(Duration::from_secs(10)));
            server
                .await
                .context("admission webhook graceful shutdown failed")?;
        }
    }
    reconcile_task.abort();
    let _ = reconcile_task.await;
    if let Some(task) = customer_resource_task {
        task.abort();
        let _ = task.await;
    }
    Ok(())
}

fn spawn_reconcile_loop(client: Client, args: Arc<ControllerArgs>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(args.reconcile_interval_seconds));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(error) = reconcile_once(client.clone(), &args).await {
                tracing::error!(error = %error, "Kubernetes reconciliation failed");
            }
        }
    })
}

async fn reconcile_once(client: Client, args: &ControllerArgs) -> anyhow::Result<()> {
    let agones_available = if args.enable_agones_integration {
        agones::reconcile_services(
            client.clone(),
            &args.load_balancer_class,
            args.agones_port_range_start,
            args.agones_port_range_end,
        )
        .await?
    } else {
        false
    };

    let nodes_api: Api<Node> = Api::all(client.clone());
    let services_api: Api<Service> = Api::all(client.clone());
    let endpoint_slices_api: Api<EndpointSlice> = Api::all(client.clone());
    let agent_pods_api: Api<Pod> = Api::namespaced(client.clone(), &args.agent_pod_namespace);
    let list_params = ListParams::default();
    let agent_pod_list_params = ListParams::default().labels(&args.agent_pod_label_selector);
    let (nodes, services, endpoint_slices, agent_pods) = tokio::try_join!(
        nodes_api.list(&list_params),
        services_api.list(&list_params),
        endpoint_slices_api.list(&list_params),
        agent_pods_api.list(&agent_pod_list_params),
    )
    .context("failed to list Kubernetes networking objects")?;

    let ready_agents = ready_agent_nodes(&agent_pods.items);
    let public = public_nodes(&nodes.items, &ready_agents);
    let endpoint_nodes = ready_endpoint_nodes(&endpoint_slices.items);
    let mut parsed = Vec::<ManagedService>::new();
    let mut parse_errors = BTreeMap::<ServiceKey, String>::new();
    let mut service_objects = BTreeMap::<ServiceKey, Service>::new();

    for service in services.items {
        let Some(key) = ServiceKey::from_service(&service) else {
            continue;
        };
        let is_managed = service.spec.as_ref().is_some_and(|spec| {
            spec.type_.as_deref() == Some("LoadBalancer")
                && spec.load_balancer_class.as_deref() == Some(args.load_balancer_class.as_str())
        });
        if !is_managed {
            continue;
        }
        match managed_service(&service, &args.load_balancer_class) {
            Ok(Some(managed)) => parsed.push(managed),
            Ok(None) => continue,
            Err(error) => {
                parse_errors.insert(key.clone(), error);
            }
        }
        service_objects.insert(key, service);
    }

    let assignments = plan_assignments(&parsed, &public, &endpoint_nodes)
        .into_iter()
        .map(|assignment| (assignment.key.clone(), assignment))
        .collect::<BTreeMap<_, _>>();

    for (key, service) in service_objects {
        let assignment = assignments
            .get(&key)
            .cloned()
            .unwrap_or_else(|| ServiceAssignment {
                key: key.clone(),
                nodes: Vec::new(),
                error: parse_errors.get(&key).cloned(),
            });
        if let Err(error) = reconcile_service(client.clone(), &service, &assignment).await {
            tracing::error!(
                service = %format!("{}/{}", key.namespace, key.name),
                error = %error,
                "failed to reconcile managed Service"
            );
        }
    }
    if agones_available {
        agones::publish_addresses(client).await?;
    }

    tracing::debug!(
        public_nodes = public.len(),
        managed_services = parsed.len() + parse_errors.len(),
        "Kubernetes LoadBalancer reconciliation completed"
    );
    Ok(())
}

async fn reconcile_service(
    client: Client,
    service: &Service,
    assignment: &ServiceAssignment,
) -> anyhow::Result<()> {
    let namespace = service
        .namespace()
        .context("managed Service has no namespace")?;
    let name = service.name_any();
    let api: Api<Service> = Api::namespaced(client, &namespace);
    let assigned_json =
        serde_json::to_string(&assignment.nodes).context("failed to encode assigned nodes")?;
    let current_annotations = service.metadata.annotations.as_ref();
    let current_assigned =
        current_annotations.and_then(|annotations| annotations.get(ASSIGNED_NODES_ANNOTATION));
    let current_error =
        current_annotations.and_then(|annotations| annotations.get(RECONCILE_ERROR_ANNOTATION));
    let resource_generation = service.metadata.labels.as_ref().and_then(|labels| {
        if labels
            .get(PUBLIC_SERVICE_MANAGED_BY_LABEL)
            .is_some_and(|value| value == PUBLIC_SERVICE_MANAGED_BY_VALUE)
        {
            labels.get(PUBLIC_SERVICE_GENERATION_LABEL)
        } else {
            None
        }
    });
    let current_observed_generation = current_annotations
        .and_then(|annotations| annotations.get(PUBLIC_SERVICE_OBSERVED_GENERATION_ANNOTATION));

    let metadata_needs_patch = current_assigned.map(String::as_str) != Some(assigned_json.as_str())
        || current_error.map(String::as_str) != assignment.error.as_deref()
        || resource_generation.map(String::as_str)
            != current_observed_generation.map(String::as_str);

    let desired_ingress = assignment
        .nodes
        .iter()
        .map(|node| LoadBalancerIngress {
            ip: Some(node.public_ip.to_string()),
            ip_mode: Some("VIP".to_string()),
            ..LoadBalancerIngress::default()
        })
        .collect::<Vec<_>>();
    let current_ingress = service
        .status
        .as_ref()
        .and_then(|status| status.load_balancer.as_ref())
        .and_then(|status| status.ingress.as_ref())
        .cloned()
        .unwrap_or_default();
    let status_needs_patch = !ingress_equal(&current_ingress, &desired_ingress);
    let clear_observed_generation = resource_generation.is_some()
        && resource_generation.map(String::as_str)
            == current_observed_generation.map(String::as_str)
        && (metadata_needs_patch || status_needs_patch);
    if clear_observed_generation {
        let marker_patch = json!({
            "metadata": {
                "annotations": {
                    PUBLIC_SERVICE_OBSERVED_GENERATION_ANNOTATION: Option::<String>::None,
                }
            }
        });
        api.patch(&name, &PatchParams::default(), &Patch::Merge(&marker_patch))
            .await
            .with_context(|| {
                format!("failed to clear Service {namespace}/{name} reconciliation marker")
            })?;
    }
    if status_needs_patch {
        let status_patch = json!({
            "status": {
                "loadBalancer": {
                    "ingress": desired_ingress,
                }
            }
        });
        api.patch_status(&name, &PatchParams::default(), &Patch::Merge(&status_patch))
            .await
            .with_context(|| format!("failed to patch Service {namespace}/{name} status"))?;
    }
    if metadata_needs_patch || clear_observed_generation {
        let metadata_patch = json!({
            "metadata": {
                "annotations": {
                    ASSIGNED_NODES_ANNOTATION: assigned_json,
                    RECONCILE_ERROR_ANNOTATION: assignment.error,
                    PUBLIC_SERVICE_OBSERVED_GENERATION_ANNOTATION: resource_generation,
                }
            }
        });
        api.patch(
            &name,
            &PatchParams::default(),
            &Patch::Merge(&metadata_patch),
        )
        .await
        .with_context(|| format!("failed to patch Service {namespace}/{name} annotations"))?;
    }
    Ok(())
}

fn ingress_equal(left: &[LoadBalancerIngress], right: &[LoadBalancerIngress]) -> bool {
    fn normalized(values: &[LoadBalancerIngress]) -> Vec<LoadBalancerIngress> {
        let mut result = values.to_vec();
        result.sort_by(|left, right| {
            (
                left.ip.as_deref(),
                left.hostname.as_deref(),
                left.ip_mode.as_deref(),
            )
                .cmp(&(
                    right.ip.as_deref(),
                    right.hostname.as_deref(),
                    right.ip_mode.as_deref(),
                ))
        });
        result
    }
    normalized(left) == normalized(right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn ingress_comparison_is_order_independent() {
        let first = LoadBalancerIngress {
            ip: Some("198.51.100.10".to_string()),
            ip_mode: Some("VIP".to_string()),
            ..LoadBalancerIngress::default()
        };
        let second = LoadBalancerIngress {
            ip: Some("198.51.100.11".to_string()),
            ip_mode: Some("VIP".to_string()),
            ..LoadBalancerIngress::default()
        };
        assert!(ingress_equal(
            &[first.clone(), second.clone()],
            &[second, first.clone()]
        ));

        let mut stale = first.clone();
        stale.hostname = Some("stale.example.test".to_string());
        assert!(!ingress_equal(&[stale], &[first]));
    }

    #[test]
    fn metadata_patch_null_removes_error_annotation() {
        let patch: Value = json!({
            "metadata": {
                "annotations": {
                    RECONCILE_ERROR_ANNOTATION: Option::<String>::None,
                }
            }
        });
        assert!(patch["metadata"]["annotations"][RECONCILE_ERROR_ANNOTATION].is_null());
    }
}
