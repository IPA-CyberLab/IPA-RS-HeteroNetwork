use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ipars_k8s_controller::{
    INGRESS_REPLICAS_ANNOTATION, MAX_INGRESS_REPLICAS, PUBLIC_SERVICE_GENERATION_LABEL,
    PUBLIC_SERVICE_MANAGED_BY_LABEL, PUBLIC_SERVICE_MANAGED_BY_VALUE,
    PUBLIC_SERVICE_OBSERVED_GENERATION_ANNOTATION, PUBLIC_SERVICE_RESOURCE_ID_LABEL,
    RECONCILE_ERROR_ANNOTATION, TRAFFIC_MODE_KEY,
};
use k8s_openapi::api::core::v1::{Namespace, Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::{Api, Client, ResourceExt};
use reqwest::header::IF_MATCH;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::ControllerArgs;

const FIELD_MANAGER: &str = "heteronetwork-public-service-controller";
const INTERNAL_PUBLIC_SERVICES_PATH: &str = "/internal/v1/customer/public-services";
const CUSTOMER_NAMESPACE_CLUSTER_ID_ANNOTATION: &str =
    "networking.heteronetwork.io/customer-cluster-id";
const CUSTOMER_NAMESPACE_ACCOUNT_ID_ANNOTATION: &str =
    "networking.heteronetwork.io/customer-account-id";
const CUSTOMER_NAMESPACE_PROJECT_ID_ANNOTATION: &str =
    "networking.heteronetwork.io/customer-project-id";
const MIN_BEARER_TOKEN_BYTES: u64 = 32;
const MAX_BEARER_TOKEN_BYTES: u64 = 512;
const MAX_INTERNAL_ENDPOINTS: usize = 32;
const MAX_INTERNAL_URL_BYTES: usize = 4_096;
const MAX_DESIRED_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_STATUS_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_DESIRED_PROJECTS: usize = 10_000;
const MAX_DESIRED_RESOURCES: usize = 10_000;
const MAX_PUBLIC_ADDRESSES: usize = 32;
const MAX_STATUS_MESSAGE_BYTES: usize = 2_048;
const MAX_API_INGRESS_REPLICAS: u16 = 128;
const HTTP_TIMEOUT_SECONDS: u64 = 15;

#[derive(Debug, Clone)]
struct CustomerResourceConfig {
    collection_urls: Vec<Url>,
    bearer_token_file: PathBuf,
    poll_interval: Duration,
}

#[derive(Debug)]
struct CustomerResourceApi {
    http: reqwest::Client,
    config: CustomerResourceConfig,
    preferred_endpoint: AtomicUsize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CustomerProject {
    cluster_id: String,
    project_id: String,
    account_id: String,
    name: String,
    kubernetes_namespace: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PublicServiceResource {
    cluster_id: String,
    resource_id: String,
    account_id: String,
    project_id: String,
    name: String,
    namespace: String,
    spec: PublicServiceSpec,
    generation: u64,
    status: PublicServiceStatus,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PublicServiceSpec {
    traffic_mode: PublicServiceTrafficMode,
    protocol: PublicServiceProtocol,
    public_port: u16,
    backend_service: String,
    backend_port: u16,
    ingress_replicas: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PublicServiceTrafficMode {
    Direct,
    Forwarded,
}

impl PublicServiceTrafficMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Forwarded => "forwarded",
        }
    }

    fn external_traffic_policy(self) -> &'static str {
        match self {
            Self::Direct => "Local",
            Self::Forwarded => "Cluster",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum PublicServiceProtocol {
    Tcp,
    Udp,
}

impl PublicServiceProtocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }

    fn service_port_name(self) -> &'static str {
        match self {
            Self::Tcp => "public-tcp",
            Self::Udp => "public-udp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PublicServiceAddress {
    host: String,
    port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PublicServicePhase {
    Pending,
    Ready,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PublicServiceStatus {
    phase: PublicServicePhase,
    public_addresses: Vec<PublicServiceAddress>,
    message: Option<String>,
    observed_generation: u64,
    observed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct DesiredCustomerResources {
    projects: Vec<CustomerProject>,
    public_services: Vec<PublicServiceResource>,
}

#[derive(Debug, Serialize)]
struct UpdatePublicServiceStatusRequest<'a> {
    expected_generation: u64,
    status: &'a PublicServiceStatus,
}

enum FacadeReconcileOutcome {
    Applied(Box<Service>),
    Invalid(String),
    Superseded(u64),
}

enum StatusReportOutcome {
    Updated,
    GenerationConflict,
}

#[derive(Debug, Clone)]
enum CustomerNamespaceOutcome {
    Ready,
    Invalid(String),
    Failed(String),
}

pub(crate) fn validate_configuration(
    internal_urls: &[String],
    bearer_token_file: Option<&Path>,
    poll_interval_seconds: u64,
) -> Result<()> {
    anyhow::ensure!(
        (1..=86_400).contains(&poll_interval_seconds),
        "--customer-resource-poll-interval-seconds must be between 1 and 86400"
    );
    match (internal_urls.is_empty(), bearer_token_file) {
        (true, None) => Ok(()),
        (false, None) => anyhow::bail!(
            "--customer-resource-api-bearer-token-file is required with --customer-resource-internal-url"
        ),
        (true, Some(_)) => anyhow::bail!(
            "at least one --customer-resource-internal-url is required with --customer-resource-api-bearer-token-file"
        ),
        (false, Some(bearer_token_file)) => {
            parse_internal_urls(internal_urls)?;
            read_bearer_token(bearer_token_file)?;
            Ok(())
        }
    }
}

pub(crate) fn spawn_reconcile_loop(
    client: Client,
    args: Arc<ControllerArgs>,
) -> Result<Option<JoinHandle<()>>> {
    if args.customer_resource_internal_urls.is_empty() {
        return Ok(None);
    }
    let bearer_token_file = args
        .customer_resource_api_bearer_token_file
        .clone()
        .context("customer resource bearer token file is not configured")?;
    let config = CustomerResourceConfig {
        collection_urls: parse_internal_urls(&args.customer_resource_internal_urls)?,
        bearer_token_file,
        poll_interval: Duration::from_secs(args.customer_resource_poll_interval_seconds),
    };
    let api = Arc::new(CustomerResourceApi::new(config)?);
    let load_balancer_class = args.load_balancer_class.clone();
    Ok(Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(api.config.poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(error) =
                reconcile_once(client.clone(), api.as_ref(), &load_balancer_class).await
            {
                tracing::error!(
                    error = %error,
                    "customer PublicServiceResource reconciliation failed"
                );
            }
        }
    })))
}

impl CustomerResourceApi {
    fn new(config: CustomerResourceConfig) -> Result<Self> {
        anyhow::ensure!(
            !config.collection_urls.is_empty(),
            "customer resource API requires at least one internal endpoint"
        );
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECONDS))
            .build()
            .context("failed to build customer resource HTTP client")?;
        Ok(Self {
            http,
            config,
            preferred_endpoint: AtomicUsize::new(0),
        })
    }

    async fn desired_customer_resources(&self, token: &str) -> Result<DesiredCustomerResources> {
        let mut failures = Vec::new();
        for endpoint_index in self.endpoint_order() {
            let collection_url = &self.config.collection_urls[endpoint_index];
            let attempt = async {
                let response = self
                    .http
                    .get(collection_url.clone())
                    .bearer_auth(token)
                    .send()
                    .await
                    .context("request failed")?;
                let status = response.status();
                let body = bounded_response_body(response, MAX_DESIRED_RESPONSE_BYTES).await?;
                anyhow::ensure!(
                    status.is_success(),
                    "returned {status}: {}",
                    response_error_message(&body)
                );
                let response: DesiredCustomerResources =
                    serde_json::from_slice(&body).context("returned invalid desired-state JSON")?;
                Ok::<_, anyhow::Error>(response)
            }
            .await;
            match attempt {
                Ok(desired) => {
                    self.remember_success(endpoint_index);
                    return Ok(desired);
                }
                Err(error) => {
                    tracing::warn!(
                        endpoint = %collection_url,
                        error = %error,
                        "customer resource desired-state endpoint failed"
                    );
                    failures.push(format!("{collection_url}: {error}"));
                }
            }
        }
        anyhow::bail!(
            "all customer resource endpoints failed while polling desired state: {}",
            failures.join("; ")
        )
    }

    async fn update_status(
        &self,
        resource_id: &str,
        expected_generation: u64,
        status: &PublicServiceStatus,
        token: &str,
    ) -> Result<StatusReportOutcome> {
        let request = UpdatePublicServiceStatusRequest {
            expected_generation,
            status,
        };
        let mut failures = Vec::new();
        for endpoint_index in self.endpoint_order() {
            let collection_url = &self.config.collection_urls[endpoint_index];
            let attempt = async {
                let response = self
                    .http
                    .put(status_url(collection_url, resource_id)?)
                    .header(IF_MATCH, format!("\"{expected_generation}\""))
                    .bearer_auth(token)
                    .json(&request)
                    .send()
                    .await
                    .context("request failed")?;
                let response_status = response.status();
                let body = bounded_response_body(response, MAX_STATUS_RESPONSE_BYTES).await?;
                if matches!(
                    response_status,
                    StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED
                ) {
                    return Ok(StatusReportOutcome::GenerationConflict);
                }
                anyhow::ensure!(
                    response_status.is_success(),
                    "returned {response_status}: {}",
                    response_error_message(&body)
                );
                Ok(StatusReportOutcome::Updated)
            }
            .await;
            match attempt {
                Ok(outcome) => {
                    self.remember_success(endpoint_index);
                    return Ok(outcome);
                }
                Err(error) => {
                    tracing::warn!(
                        endpoint = %collection_url,
                        resource_id,
                        error = %error,
                        "customer resource status endpoint failed"
                    );
                    failures.push(format!("{collection_url}: {error}"));
                }
            }
        }
        anyhow::bail!(
            "all customer resource endpoints failed while reporting public service {resource_id} status: {}",
            failures.join("; ")
        )
    }

    fn endpoint_order(&self) -> Vec<usize> {
        let endpoint_count = self.config.collection_urls.len();
        let preferred = self.preferred_endpoint.load(Ordering::Relaxed) % endpoint_count;
        (0..endpoint_count)
            .map(|offset| (preferred + offset) % endpoint_count)
            .collect()
    }

    fn remember_success(&self, endpoint_index: usize) {
        self.preferred_endpoint
            .store(endpoint_index, Ordering::Relaxed);
    }
}

async fn reconcile_once(
    client: Client,
    api: &CustomerResourceApi,
    load_balancer_class: &str,
) -> Result<()> {
    let token = read_bearer_token(&api.config.bearer_token_file)?;
    let desired = api.desired_customer_resources(&token).await?;
    validate_desired_resources(&desired)?;
    let resources = &desired.public_services;

    let services_api: Api<Service> = Api::all(client.clone());
    let managed_selector =
        format!("{PUBLIC_SERVICE_MANAGED_BY_LABEL}={PUBLIC_SERVICE_MANAGED_BY_VALUE}");
    let existing_facades = services_api
        .list(&ListParams::default().labels(&managed_selector))
        .await
        .context("failed to list managed public service facades")?;
    let desired_facades = resources
        .iter()
        .map(|resource| {
            Ok((
                (
                    resource.namespace.clone(),
                    facade_service_name(&resource.resource_id)?,
                ),
                resource.resource_id.clone(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut namespace_outcomes = BTreeMap::new();
    for project in &desired.projects {
        let outcome = match reconcile_customer_namespace(client.clone(), project).await {
            Ok(outcome) => outcome,
            Err(error) => CustomerNamespaceOutcome::Failed(error.to_string()),
        };
        match &outcome {
            CustomerNamespaceOutcome::Ready => {}
            CustomerNamespaceOutcome::Invalid(message) => {
                tracing::warn!(
                    project_id = %project.project_id,
                    namespace = %project.kubernetes_namespace,
                    error = message,
                    "customer Namespace ownership is invalid"
                );
            }
            CustomerNamespaceOutcome::Failed(message) => {
                tracing::error!(
                    project_id = %project.project_id,
                    namespace = %project.kubernetes_namespace,
                    error = message,
                    "customer Namespace reconciliation failed"
                );
            }
        }
        namespace_outcomes.insert(project.kubernetes_namespace.clone(), outcome);
    }

    for resource in resources {
        let facade_name = facade_service_name(&resource.resource_id)?;
        let namespace_outcome = namespace_outcomes
            .get(&resource.namespace)
            .context("customer Namespace outcome is missing")?;
        let facade_outcome = match namespace_outcome {
            CustomerNamespaceOutcome::Ready => {
                reconcile_facade(client.clone(), load_balancer_class, resource).await
            }
            CustomerNamespaceOutcome::Invalid(message) => {
                Ok(FacadeReconcileOutcome::Invalid(message.clone()))
            }
            CustomerNamespaceOutcome::Failed(message) => Err(anyhow::anyhow!(message.clone())),
        };
        let status = match facade_outcome {
            Ok(FacadeReconcileOutcome::Applied(service)) => {
                status_from_facade(resource, service.as_ref(), Utc::now())
            }
            Ok(FacadeReconcileOutcome::Superseded(current_generation)) => {
                tracing::debug!(
                    resource_id = %resource.resource_id,
                    desired_generation = resource.generation,
                    current_generation,
                    "ignored superseded PublicServiceResource observation"
                );
                continue;
            }
            Ok(FacadeReconcileOutcome::Invalid(message)) => {
                let message = match delete_owned_facade(
                    client.clone(),
                    &resource.namespace,
                    &facade_name,
                    &resource.resource_id,
                )
                .await
                {
                    Ok(()) => message,
                    Err(error) => format!("{message}; failed to withdraw facade: {error}"),
                };
                error_status(resource.generation, message, Utc::now())
            }
            Err(error) => error_status(resource.generation, error.to_string(), Utc::now()),
        };
        if let Err(error) = report_status_if_changed(api, resource, &status, &token).await {
            tracing::error!(
                resource_id = %resource.resource_id,
                generation = resource.generation,
                error = %error,
                "failed to report PublicServiceResource status"
            );
        }
    }

    for service in existing_facades.items {
        if facade_is_desired(&service, &desired_facades) {
            continue;
        }
        let Some(namespace) = service.namespace() else {
            continue;
        };
        let name = service.name_any();
        delete_service(client.clone(), &namespace, &name).await?;
        tracing::info!(
            service = %format!("{namespace}/{name}"),
            "deleted stale customer public service facade"
        );
    }

    tracing::debug!(
        desired_projects = desired.projects.len(),
        desired_public_services = resources.len(),
        "customer PublicServiceResource reconciliation completed"
    );
    Ok(())
}

async fn reconcile_customer_namespace(
    client: Client,
    project: &CustomerProject,
) -> Result<CustomerNamespaceOutcome> {
    let namespaces: Api<Namespace> = Api::all(client);
    let desired = desired_customer_namespace(project);
    let existing = namespaces
        .get_opt(&project.kubernetes_namespace)
        .await
        .with_context(|| {
            format!(
                "failed to inspect customer Namespace {}",
                project.kubernetes_namespace
            )
        })?;

    let current = match existing {
        Some(namespace) => namespace,
        None => {
            let post_params = PostParams {
                field_manager: Some(FIELD_MANAGER.to_string()),
                ..PostParams::default()
            };
            match namespaces.create(&post_params, &desired).await {
                Ok(namespace) => namespace,
                Err(kube::Error::Api(status)) if status.code == 409 => namespaces
                    .get(&project.kubernetes_namespace)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to inspect concurrently created customer Namespace {}",
                            project.kubernetes_namespace
                        )
                    })?,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to create customer Namespace {}",
                            project.kubernetes_namespace
                        )
                    });
                }
            }
        }
    };

    if let Some(message) = customer_namespace_ownership_error(&current, project) {
        return Ok(CustomerNamespaceOutcome::Invalid(message));
    }

    namespaces
        .patch(
            &project.kubernetes_namespace,
            &PatchParams::apply(FIELD_MANAGER).force(),
            &Patch::Apply(&desired),
        )
        .await
        .with_context(|| {
            format!(
                "failed to server-side apply customer Namespace {}",
                project.kubernetes_namespace
            )
        })?;
    Ok(CustomerNamespaceOutcome::Ready)
}

fn desired_customer_namespace(project: &CustomerProject) -> Namespace {
    Namespace {
        metadata: ObjectMeta {
            name: Some(project.kubernetes_namespace.clone()),
            labels: Some(BTreeMap::from([(
                PUBLIC_SERVICE_MANAGED_BY_LABEL.to_string(),
                PUBLIC_SERVICE_MANAGED_BY_VALUE.to_string(),
            )])),
            annotations: Some(customer_namespace_ownership(project)),
            ..ObjectMeta::default()
        },
        ..Namespace::default()
    }
}

fn customer_namespace_ownership(project: &CustomerProject) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            CUSTOMER_NAMESPACE_CLUSTER_ID_ANNOTATION.to_string(),
            project.cluster_id.clone(),
        ),
        (
            CUSTOMER_NAMESPACE_ACCOUNT_ID_ANNOTATION.to_string(),
            project.account_id.clone(),
        ),
        (
            CUSTOMER_NAMESPACE_PROJECT_ID_ANNOTATION.to_string(),
            project.project_id.clone(),
        ),
    ])
}

fn customer_namespace_ownership_error(
    namespace: &Namespace,
    project: &CustomerProject,
) -> Option<String> {
    if namespace.metadata.deletion_timestamp.is_some() {
        return Some(format!(
            "customer Namespace {} is being deleted",
            project.kubernetes_namespace
        ));
    }
    let managed = namespace
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(PUBLIC_SERVICE_MANAGED_BY_LABEL))
        .is_some_and(|value| value == PUBLIC_SERVICE_MANAGED_BY_VALUE);
    if !managed {
        return Some(format!(
            "refusing to take ownership of existing non-managed Namespace {}",
            project.kubernetes_namespace
        ));
    }
    let expected = customer_namespace_ownership(project);
    let annotations = namespace.metadata.annotations.as_ref();
    for (key, expected_value) in expected {
        if annotations.and_then(|values| values.get(&key)) != Some(&expected_value) {
            return Some(format!(
                "refusing to take ownership of Namespace {} assigned to a different customer project",
                project.kubernetes_namespace
            ));
        }
    }
    None
}

async fn reconcile_facade(
    client: Client,
    load_balancer_class: &str,
    resource: &PublicServiceResource,
) -> Result<FacadeReconcileOutcome> {
    let facade_name = facade_service_name(&resource.resource_id)?;
    if let Err(message) = validate_supported_spec(resource) {
        return Ok(FacadeReconcileOutcome::Invalid(message));
    }
    if resource.spec.backend_service == facade_name {
        return Ok(FacadeReconcileOutcome::Invalid(
            "backend_service must not reference the managed facade Service".to_string(),
        ));
    }
    let services: Api<Service> = Api::namespaced(client, &resource.namespace);
    let backend = services
        .get_opt(&resource.spec.backend_service)
        .await
        .with_context(|| {
            format!(
                "failed to read backend Service {}/{}",
                resource.namespace, resource.spec.backend_service
            )
        })?;
    let Some(backend) = backend else {
        return Ok(FacadeReconcileOutcome::Invalid(format!(
            "backend Service {}/{} does not exist",
            resource.namespace, resource.spec.backend_service
        )));
    };
    let desired = match desired_facade_service(load_balancer_class, resource, &backend) {
        Ok(desired) => desired,
        Err(message) => return Ok(FacadeReconcileOutcome::Invalid(message)),
    };
    if let Some(existing) = services.get_opt(&facade_name).await.with_context(|| {
        format!(
            "failed to inspect facade Service {}/{}",
            resource.namespace, facade_name
        )
    })? {
        if !service_is_owned_by_resource(&existing, &resource.resource_id) {
            return Ok(FacadeReconcileOutcome::Invalid(format!(
                "refusing to take ownership of existing Service {}/{}",
                resource.namespace, facade_name
            )));
        }
        if let Some(current_generation) = public_service_generation(&existing) {
            if current_generation > resource.generation {
                return Ok(FacadeReconcileOutcome::Superseded(current_generation));
            }
        }
    }
    let applied = services
        .patch(
            &facade_name,
            &PatchParams::apply(FIELD_MANAGER).force(),
            &Patch::Apply(&desired),
        )
        .await
        .with_context(|| {
            format!(
                "failed to apply facade Service {}/{}",
                resource.namespace, facade_name
            )
        })?;
    Ok(FacadeReconcileOutcome::Applied(Box::new(applied)))
}

fn desired_facade_service(
    load_balancer_class: &str,
    resource: &PublicServiceResource,
    backend: &Service,
) -> Result<Service, String> {
    validate_supported_spec(resource)?;
    if backend.metadata.deletion_timestamp.is_some() {
        return Err(format!(
            "backend Service {}/{} is being deleted",
            resource.namespace, resource.spec.backend_service
        ));
    }
    if service_is_managed_facade(backend) {
        return Err("backend_service must not reference a managed facade Service".to_string());
    }
    let backend_spec = backend.spec.as_ref().ok_or_else(|| {
        format!(
            "backend Service {}/{} has no spec",
            resource.namespace, resource.spec.backend_service
        )
    })?;
    let selector = backend_spec
        .selector
        .as_ref()
        .filter(|selector| !selector.is_empty())
        .cloned()
        .ok_or_else(|| {
            format!(
                "backend Service {}/{} must have a non-empty selector",
                resource.namespace, resource.spec.backend_service
            )
        })?;
    let expected_protocol = resource.spec.protocol.as_str();
    let backend_port = backend_spec
        .ports
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|port| {
            port.port == i32::from(resource.spec.backend_port)
                && port.protocol.as_deref().unwrap_or("TCP") == expected_protocol
        })
        .ok_or_else(|| {
            format!(
                "backend Service {}/{} has no {} port {}",
                resource.namespace,
                resource.spec.backend_service,
                expected_protocol,
                resource.spec.backend_port
            )
        })?;
    let target_port = backend_port.target_port.clone().or_else(|| {
        Some(
            k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(i32::from(
                resource.spec.backend_port,
            )),
        )
    });
    let facade_name =
        facade_service_name(&resource.resource_id).map_err(|error| error.to_string())?;
    let labels = BTreeMap::from([
        (
            PUBLIC_SERVICE_MANAGED_BY_LABEL.to_string(),
            PUBLIC_SERVICE_MANAGED_BY_VALUE.to_string(),
        ),
        (
            PUBLIC_SERVICE_RESOURCE_ID_LABEL.to_string(),
            resource.resource_id.clone(),
        ),
        (
            PUBLIC_SERVICE_GENERATION_LABEL.to_string(),
            resource.generation.to_string(),
        ),
    ]);
    let annotations = BTreeMap::from([
        (
            TRAFFIC_MODE_KEY.to_string(),
            resource.spec.traffic_mode.as_str().to_string(),
        ),
        (
            INGRESS_REPLICAS_ANNOTATION.to_string(),
            resource.spec.ingress_replicas.to_string(),
        ),
    ]);
    Ok(Service {
        metadata: ObjectMeta {
            name: Some(facade_name),
            namespace: Some(resource.namespace.clone()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..ObjectMeta::default()
        },
        spec: Some(ServiceSpec {
            allocate_load_balancer_node_ports: Some(false),
            external_traffic_policy: Some(
                resource
                    .spec
                    .traffic_mode
                    .external_traffic_policy()
                    .to_string(),
            ),
            load_balancer_class: Some(load_balancer_class.to_string()),
            ports: Some(vec![ServicePort {
                app_protocol: backend_port.app_protocol.clone(),
                name: Some(resource.spec.protocol.service_port_name().to_string()),
                port: i32::from(resource.spec.public_port),
                protocol: Some(expected_protocol.to_string()),
                target_port,
                ..ServicePort::default()
            }]),
            selector: Some(selector),
            type_: Some("LoadBalancer".to_string()),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

fn validate_supported_spec(resource: &PublicServiceResource) -> Result<(), String> {
    if resource.spec.public_port == 0 {
        return Err("public_port must be greater than zero".to_string());
    }
    if resource.spec.backend_port == 0 {
        return Err("backend_port must be greater than zero".to_string());
    }
    if resource.spec.ingress_replicas == 0
        || usize::from(resource.spec.ingress_replicas) > MAX_INGRESS_REPLICAS
    {
        return Err(format!(
            "ingress_replicas must be between 1 and {MAX_INGRESS_REPLICAS}"
        ));
    }
    Ok(())
}

fn status_from_facade(
    resource: &PublicServiceResource,
    facade: &Service,
    observed_at: DateTime<Utc>,
) -> PublicServiceStatus {
    let annotations = facade.metadata.annotations.as_ref();
    let observed_generation = annotations
        .and_then(|values| values.get(PUBLIC_SERVICE_OBSERVED_GENERATION_ANNOTATION))
        .and_then(|value| value.parse::<u64>().ok());
    if observed_generation != Some(resource.generation) {
        return PublicServiceStatus {
            phase: PublicServicePhase::Pending,
            public_addresses: Vec::new(),
            message: Some("facade Service is awaiting load-balancer reconciliation".to_string()),
            observed_generation: resource.generation,
            observed_at: Some(observed_at),
        };
    }

    let mut hosts = facade
        .status
        .as_ref()
        .and_then(|status| status.load_balancer.as_ref())
        .and_then(|status| status.ingress.as_deref())
        .unwrap_or_default()
        .iter()
        .filter_map(|ingress| ingress.ip.clone().or_else(|| ingress.hostname.clone()))
        .filter(|host| !host.is_empty())
        .collect::<BTreeSet<_>>();
    let too_many_addresses = hosts.len() > MAX_PUBLIC_ADDRESSES;
    let public_addresses = hosts
        .iter()
        .take(MAX_PUBLIC_ADDRESSES)
        .map(|host| PublicServiceAddress {
            host: host.clone(),
            port: resource.spec.public_port,
        })
        .collect::<Vec<_>>();
    hosts.clear();

    let reconcile_error = annotations
        .and_then(|values| values.get(RECONCILE_ERROR_ANNOTATION))
        .filter(|message| !message.is_empty())
        .cloned();
    let (phase, message) = if too_many_addresses {
        (
            PublicServicePhase::Error,
            Some(format!(
                "facade Service reported more than {MAX_PUBLIC_ADDRESSES} public addresses"
            )),
        )
    } else if let Some(error) = reconcile_error {
        (PublicServicePhase::Error, Some(error))
    } else if public_addresses.is_empty() {
        (PublicServicePhase::Pending, None)
    } else {
        (PublicServicePhase::Ready, None)
    };
    PublicServiceStatus {
        phase,
        public_addresses,
        message: message.map(|message| bounded_message(&message)),
        observed_generation: resource.generation,
        observed_at: Some(observed_at),
    }
}

fn error_status(
    generation: u64,
    message: impl AsRef<str>,
    observed_at: DateTime<Utc>,
) -> PublicServiceStatus {
    PublicServiceStatus {
        phase: PublicServicePhase::Error,
        public_addresses: Vec::new(),
        message: Some(bounded_message(message.as_ref())),
        observed_generation: generation,
        observed_at: Some(observed_at),
    }
}

async fn report_status_if_changed(
    api: &CustomerResourceApi,
    resource: &PublicServiceResource,
    status: &PublicServiceStatus,
    token: &str,
) -> Result<()> {
    if statuses_equivalent(&resource.status, status) {
        return Ok(());
    }
    match api
        .update_status(&resource.resource_id, resource.generation, status, token)
        .await?
    {
        StatusReportOutcome::Updated => {}
        StatusReportOutcome::GenerationConflict => {
            tracing::debug!(
                resource_id = %resource.resource_id,
                expected_generation = resource.generation,
                "skipped stale PublicServiceResource status update"
            );
        }
    }
    Ok(())
}

fn statuses_equivalent(left: &PublicServiceStatus, right: &PublicServiceStatus) -> bool {
    left.phase == right.phase
        && left.public_addresses == right.public_addresses
        && left.message == right.message
        && left.observed_generation == right.observed_generation
}

async fn delete_owned_facade(
    client: Client,
    namespace: &str,
    name: &str,
    resource_id: &str,
) -> Result<()> {
    let services: Api<Service> = Api::namespaced(client, namespace);
    let Some(service) = services
        .get_opt(name)
        .await
        .with_context(|| format!("failed to inspect facade Service {namespace}/{name}"))?
    else {
        return Ok(());
    };
    if !service_is_owned_by_resource(&service, resource_id) {
        return Ok(());
    }
    match services.delete(name, &DeleteParams::default()).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(status)) if status.is_not_found() => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to delete facade Service {namespace}/{name}")),
    }
}

async fn delete_service(client: Client, namespace: &str, name: &str) -> Result<()> {
    let services: Api<Service> = Api::namespaced(client, namespace);
    match services.delete(name, &DeleteParams::default()).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(status)) if status.is_not_found() => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to delete facade Service {namespace}/{name}")),
    }
}

fn service_is_managed_facade(service: &Service) -> bool {
    service
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(PUBLIC_SERVICE_MANAGED_BY_LABEL))
        .is_some_and(|value| value == PUBLIC_SERVICE_MANAGED_BY_VALUE)
}

fn service_is_owned_by_resource(service: &Service, resource_id: &str) -> bool {
    service_is_managed_facade(service)
        && service
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(PUBLIC_SERVICE_RESOURCE_ID_LABEL))
            .is_some_and(|value| value == resource_id)
}

fn public_service_generation(service: &Service) -> Option<u64> {
    service
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(PUBLIC_SERVICE_GENERATION_LABEL))
        .and_then(|generation| generation.parse().ok())
}

fn facade_is_desired(
    service: &Service,
    desired_facades: &BTreeMap<(String, String), String>,
) -> bool {
    let Some(namespace) = service.namespace() else {
        return false;
    };
    let resource_id = service
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(PUBLIC_SERVICE_RESOURCE_ID_LABEL));
    resource_id == desired_facades.get(&(namespace, service.name_any()))
}

fn validate_desired_resources(desired: &DesiredCustomerResources) -> Result<()> {
    anyhow::ensure!(
        desired.projects.len() <= MAX_DESIRED_PROJECTS,
        "desired customer resource response exceeds {MAX_DESIRED_PROJECTS} projects"
    );
    anyhow::ensure!(
        desired.public_services.len() <= MAX_DESIRED_RESOURCES,
        "desired public service response exceeds {MAX_DESIRED_RESOURCES} resources"
    );
    let mut projects = BTreeMap::new();
    let mut project_namespaces = BTreeSet::new();
    for project in &desired.projects {
        validate_customer_project(project)?;
        let project_key = (project.cluster_id.clone(), project.project_id.clone());
        anyhow::ensure!(
            projects.insert(project_key, project).is_none(),
            "desired customer resource response contains duplicate project ID {}",
            project.project_id
        );
        anyhow::ensure!(
            project_namespaces.insert(project.kubernetes_namespace.clone()),
            "desired customer resource response assigns Namespace {} to multiple projects",
            project.kubernetes_namespace
        );
    }

    let mut resource_ids = BTreeSet::new();
    let mut facades = BTreeSet::new();
    for resource in &desired.public_services {
        validate_resource(resource)?;
        let project = projects
            .get(&(resource.cluster_id.clone(), resource.project_id.clone()))
            .with_context(|| {
                format!(
                    "public service {} references missing project {}",
                    resource.resource_id, resource.project_id
                )
            })?;
        anyhow::ensure!(
            resource.account_id == project.account_id
                && resource.namespace == project.kubernetes_namespace,
            "public service {} ownership does not match project {}",
            resource.resource_id,
            resource.project_id
        );
        anyhow::ensure!(
            resource_ids.insert(resource.resource_id.clone()),
            "desired public service response contains duplicate resource ID {}",
            resource.resource_id
        );
        let facade = (
            resource.namespace.clone(),
            facade_service_name(&resource.resource_id)?,
        );
        anyhow::ensure!(
            facades.insert(facade),
            "desired public service response contains duplicate facade ownership"
        );
    }
    Ok(())
}

fn validate_customer_project(project: &CustomerProject) -> Result<()> {
    validate_bounded_opaque("project cluster_id", &project.cluster_id, 128)?;
    validate_bounded_opaque("project account_id", &project.account_id, 64)?;
    validate_bounded_opaque("project project_id", &project.project_id, 64)?;
    validate_dns_label("project name", &project.name)?;
    validate_dns_label(
        "project kubernetes_namespace",
        &project.kubernetes_namespace,
    )
}

fn validate_resource(resource: &PublicServiceResource) -> Result<()> {
    validate_bounded_opaque("cluster_id", &resource.cluster_id, 128)?;
    validate_bounded_opaque("account_id", &resource.account_id, 64)?;
    validate_bounded_opaque("project_id", &resource.project_id, 64)?;
    validate_dns_label("name", &resource.name)?;
    validate_dns_label("namespace", &resource.namespace)?;
    validate_dns_label("backend_service", &resource.spec.backend_service)?;
    facade_service_name(&resource.resource_id)?;
    anyhow::ensure!(resource.generation > 0, "generation must be at least 1");
    anyhow::ensure!(
        resource.status.observed_generation <= resource.generation,
        "observed_generation must not exceed generation"
    );
    anyhow::ensure!(
        resource.updated_at >= resource.created_at,
        "updated_at must not precede created_at"
    );
    anyhow::ensure!(
        resource.spec.public_port > 0,
        "public_port must be greater than zero"
    );
    anyhow::ensure!(
        resource.spec.backend_port > 0,
        "backend_port must be greater than zero"
    );
    anyhow::ensure!(
        (1..=MAX_API_INGRESS_REPLICAS).contains(&resource.spec.ingress_replicas),
        "ingress_replicas must be between 1 and {MAX_API_INGRESS_REPLICAS}"
    );
    anyhow::ensure!(
        resource.status.public_addresses.len() <= MAX_PUBLIC_ADDRESSES,
        "status exceeds {MAX_PUBLIC_ADDRESSES} public addresses"
    );
    Ok(())
}

fn facade_service_name(resource_id: &str) -> Result<String> {
    let suffix = resource_id
        .strip_prefix("psvc_")
        .context("resource_id must start with psvc_")?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("resource_id must contain exactly 32 lowercase hexadecimal characters");
    }
    Ok(format!("hn-psvc-{suffix}"))
}

fn validate_dns_label(field: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    anyhow::ensure!(valid, "{field} must be a Kubernetes DNS label");
    Ok(())
}

fn validate_bounded_opaque(field: &str, value: &str, max_bytes: usize) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control),
        "{field} must be 1 to {max_bytes} non-control bytes"
    );
    Ok(())
}

fn parse_internal_urls(values: &[String]) -> Result<Vec<Url>> {
    anyhow::ensure!(
        (1..=MAX_INTERNAL_ENDPOINTS).contains(&values.len()),
        "customer resource integration requires 1 to {MAX_INTERNAL_ENDPOINTS} internal endpoints"
    );
    let mut normalized = Vec::with_capacity(values.len());
    let mut unique = BTreeSet::new();
    for value in values {
        let url = parse_internal_url(value)?;
        anyhow::ensure!(
            unique.insert(url.as_str().to_string()),
            "customer resource internal endpoints must be unique after normalization"
        );
        normalized.push(url);
    }
    Ok(normalized)
}

fn parse_internal_url(value: &str) -> Result<Url> {
    anyhow::ensure!(
        !value.is_empty() && value.len() <= MAX_INTERNAL_URL_BYTES,
        "--customer-resource-internal-url must contain 1 to {MAX_INTERNAL_URL_BYTES} bytes"
    );
    let mut url = Url::parse(value)
        .context("--customer-resource-internal-url must be a valid HTTP or HTTPS URL")?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "--customer-resource-internal-url must use http or https"
    );
    anyhow::ensure!(
        url.host_str().is_some(),
        "--customer-resource-internal-url must include a host"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "--customer-resource-internal-url must not include credentials"
    );
    anyhow::ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "--customer-resource-internal-url must not include a query or fragment"
    );
    let configured_path = url.path().trim_end_matches('/');
    anyhow::ensure!(
        configured_path.is_empty() || configured_path == INTERNAL_PUBLIC_SERVICES_PATH,
        "--customer-resource-internal-url path must be {INTERNAL_PUBLIC_SERVICES_PATH}"
    );
    url.set_path(INTERNAL_PUBLIC_SERVICES_PATH);
    Ok(url)
}

fn status_url(collection_url: &Url, resource_id: &str) -> Result<Url> {
    facade_service_name(resource_id)?;
    let mut url = collection_url.clone();
    url.set_path(&format!(
        "{}/{resource_id}/status",
        collection_url.path().trim_end_matches('/')
    ));
    Ok(url)
}

fn read_bearer_token(path: &Path) -> Result<String> {
    let metadata = std::fs::metadata(path).with_context(|| {
        format!(
            "customer resource bearer token file {} is not readable",
            path.display()
        )
    })?;
    anyhow::ensure!(
        metadata.is_file() && (1..=MAX_BEARER_TOKEN_BYTES + 2).contains(&metadata.len()),
        "customer resource bearer token file must be a regular file no larger than {} bytes",
        MAX_BEARER_TOKEN_BYTES + 2
    );
    let token = std::fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read customer resource bearer token file {}",
            path.display()
        )
    })?;
    let token = token.trim().to_string();
    anyhow::ensure!(
        (MIN_BEARER_TOKEN_BYTES as usize..=MAX_BEARER_TOKEN_BYTES as usize)
            .contains(&token.len())
            && !token.chars().any(char::is_whitespace)
            && !token.chars().any(char::is_control),
        "customer resource bearer token must contain {MIN_BEARER_TOKEN_BYTES} to {MAX_BEARER_TOKEN_BYTES} non-whitespace bytes"
    );
    Ok(token)
}

async fn bounded_response_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        anyhow::bail!("customer resource API response exceeds {max_bytes} bytes");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read customer resource API response")?
    {
        anyhow::ensure!(
            body.len().saturating_add(chunk.len()) <= max_bytes,
            "customer resource API response exceeds {max_bytes} bytes"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn response_error_message(body: &[u8]) -> String {
    let message = String::from_utf8_lossy(body);
    let message = message.trim();
    if message.is_empty() {
        "empty response body".to_string()
    } else {
        bounded_message(message)
    }
}

fn bounded_message(message: &str) -> String {
    if message.len() <= MAX_STATUS_MESSAGE_BYTES {
        return message.to_string();
    }
    let mut end = MAX_STATUS_MESSAGE_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_string()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use axum::routing::{get, put};
    use axum::{Json, Router};
    use k8s_openapi::api::core::v1::{LoadBalancerIngress, LoadBalancerStatus, ServiceStatus};
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

    fn resource(
        mode: PublicServiceTrafficMode,
        protocol: PublicServiceProtocol,
    ) -> PublicServiceResource {
        let now = Utc::now();
        PublicServiceResource {
            cluster_id: "cluster-a".to_string(),
            resource_id: "psvc_0123456789abcdef0123456789abcdef".to_string(),
            account_id: "acct_0123456789abcdef0123456789abcdef".to_string(),
            project_id: "prj_0123456789abcdef0123456789abcdef".to_string(),
            name: "livekit".to_string(),
            namespace: "hn-livekit-1234abcd".to_string(),
            spec: PublicServiceSpec {
                traffic_mode: mode,
                protocol,
                public_port: 7882,
                backend_service: "livekit-backend".to_string(),
                backend_port: 7880,
                ingress_replicas: 2,
            },
            generation: 7,
            status: PublicServiceStatus {
                phase: PublicServicePhase::Pending,
                public_addresses: Vec::new(),
                message: None,
                observed_generation: 0,
                observed_at: None,
            },
            created_at: now,
            updated_at: now,
        }
    }

    fn project() -> CustomerProject {
        CustomerProject {
            cluster_id: "cluster-a".to_string(),
            project_id: "prj_0123456789abcdef0123456789abcdef".to_string(),
            account_id: "acct_0123456789abcdef0123456789abcdef".to_string(),
            name: "livekit".to_string(),
            kubernetes_namespace: "hn-livekit-1234abcd".to_string(),
            created_at: Utc::now(),
        }
    }

    fn backend_service(protocol: &str, target_port: IntOrString) -> Service {
        Service {
            metadata: ObjectMeta {
                name: Some("livekit-backend".to_string()),
                namespace: Some("hn-livekit-1234abcd".to_string()),
                ..ObjectMeta::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(vec![ServicePort {
                    port: 7880,
                    protocol: Some(protocol.to_string()),
                    target_port: Some(target_port),
                    ..ServicePort::default()
                }]),
                selector: Some(BTreeMap::from([("app".to_string(), "livekit".to_string())])),
                ..ServiceSpec::default()
            }),
            status: None,
        }
    }

    fn test_api(internal_urls: &[String]) -> CustomerResourceApi {
        CustomerResourceApi::new(CustomerResourceConfig {
            collection_urls: parse_internal_urls(internal_urls).expect("internal URLs"),
            bearer_token_file: PathBuf::from("/unused-in-test"),
            poll_interval: Duration::from_secs(15),
        })
        .expect("customer resource API")
    }

    async fn spawn_test_server(router: Router) -> (String, JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener");
        let address = listener.local_addr().expect("test address");
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("test HTTP server");
        });
        (format!("http://{address}"), task)
    }

    #[test]
    fn customer_namespace_has_durable_owner_and_rejects_takeover() {
        let project = project();
        let namespace = desired_customer_namespace(&project);
        assert_eq!(
            namespace.metadata.name.as_deref(),
            Some("hn-livekit-1234abcd")
        );
        assert_eq!(
            namespace
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(PUBLIC_SERVICE_MANAGED_BY_LABEL))
                .map(String::as_str),
            Some(PUBLIC_SERVICE_MANAGED_BY_VALUE)
        );
        assert_eq!(
            namespace
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| {
                    annotations.get(CUSTOMER_NAMESPACE_PROJECT_ID_ANNOTATION)
                })
                .map(String::as_str),
            Some(project.project_id.as_str())
        );
        assert!(customer_namespace_ownership_error(&namespace, &project).is_none());

        let unmanaged = Namespace {
            metadata: ObjectMeta {
                name: Some(project.kubernetes_namespace.clone()),
                ..ObjectMeta::default()
            },
            ..Namespace::default()
        };
        assert!(customer_namespace_ownership_error(&unmanaged, &project)
            .is_some_and(|message| message.contains("non-managed")));

        let mut other_project = namespace;
        other_project
            .metadata
            .annotations
            .get_or_insert_with(BTreeMap::new)
            .insert(
                CUSTOMER_NAMESPACE_PROJECT_ID_ANNOTATION.to_string(),
                "prj_ffffffffffffffffffffffffffffffff".to_string(),
            );
        assert!(customer_namespace_ownership_error(&other_project, &project)
            .is_some_and(|message| message.contains("different customer project")));
    }

    #[test]
    fn project_without_public_services_is_valid_desired_state() {
        let desired = DesiredCustomerResources {
            projects: vec![project()],
            public_services: Vec::new(),
        };
        validate_desired_resources(&desired).expect("project-only desired state");
        assert_eq!(
            desired_customer_namespace(&desired.projects[0])
                .metadata
                .name
                .as_deref(),
            Some("hn-livekit-1234abcd")
        );
    }

    #[test]
    fn public_service_ownership_must_match_project_envelope() {
        let service = resource(
            PublicServiceTrafficMode::Forwarded,
            PublicServiceProtocol::Tcp,
        );
        let valid = DesiredCustomerResources {
            projects: vec![project()],
            public_services: vec![service.clone()],
        };
        validate_desired_resources(&valid).expect("matching ownership");

        let mut wrong_account = service.clone();
        wrong_account.account_id = "acct_ffffffffffffffffffffffffffffffff".to_string();
        let error = validate_desired_resources(&DesiredCustomerResources {
            projects: vec![project()],
            public_services: vec![wrong_account],
        })
        .expect_err("account ownership mismatch");
        assert!(error.to_string().contains("ownership does not match"));

        let mut wrong_namespace = service.clone();
        wrong_namespace.namespace = "hn-other-1234abcd".to_string();
        let error = validate_desired_resources(&DesiredCustomerResources {
            projects: vec![project()],
            public_services: vec![wrong_namespace],
        })
        .expect_err("Namespace ownership mismatch");
        assert!(error.to_string().contains("ownership does not match"));

        let mut missing_project = service;
        missing_project.project_id = "prj_ffffffffffffffffffffffffffffffff".to_string();
        let error = validate_desired_resources(&DesiredCustomerResources {
            projects: vec![project()],
            public_services: vec![missing_project],
        })
        .expect_err("missing project");
        assert!(error.to_string().contains("references missing project"));
    }

    #[test]
    fn desired_projects_cannot_share_a_namespace() {
        let first = project();
        let mut second = first.clone();
        second.project_id = "prj_ffffffffffffffffffffffffffffffff".to_string();
        second.name = "livekit-other".to_string();
        let error = validate_desired_resources(&DesiredCustomerResources {
            projects: vec![first, second],
            public_services: Vec::new(),
        })
        .expect_err("duplicate Namespace");
        assert!(error.to_string().contains("multiple projects"));
    }

    #[tokio::test]
    async fn desired_poll_fails_over_and_keeps_successful_endpoint_preferred() {
        let first_calls = Arc::new(AtomicUsize::new(0));
        let first_handler_calls = Arc::clone(&first_calls);
        let first_router = Router::new().route(
            INTERNAL_PUBLIC_SERVICES_PATH,
            get(move || {
                let calls = Arc::clone(&first_handler_calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::SERVICE_UNAVAILABLE, "not ready")
                }
            }),
        );
        let second_calls = Arc::new(AtomicUsize::new(0));
        let second_handler_calls = Arc::clone(&second_calls);
        let second_router = Router::new().route(
            INTERNAL_PUBLIC_SERVICES_PATH,
            get(move || {
                let calls = Arc::clone(&second_handler_calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({
                        "projects": [],
                        "public_services": []
                    }))
                }
            }),
        );
        let (first_url, first_task) = spawn_test_server(first_router).await;
        let (second_url, second_task) = spawn_test_server(second_router).await;
        let api = test_api(&[first_url, second_url]);

        let first = api
            .desired_customer_resources("0123456789abcdef0123456789abcdef")
            .await
            .expect("first poll");
        assert!(first.projects.is_empty());
        assert!(first.public_services.is_empty());
        let second = api
            .desired_customer_resources("0123456789abcdef0123456789abcdef")
            .await
            .expect("second poll");
        assert!(second.projects.is_empty());
        assert!(second.public_services.is_empty());
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 2);
        assert_eq!(api.preferred_endpoint.load(Ordering::Relaxed), 1);

        first_task.abort();
        second_task.abort();
    }

    #[tokio::test]
    async fn status_update_fails_over_and_keeps_successful_endpoint_preferred() {
        let status_path = "/internal/v1/customer/public-services/{resource_id}/status";
        let first_calls = Arc::new(AtomicUsize::new(0));
        let first_handler_calls = Arc::clone(&first_calls);
        let first_router = Router::new().route(
            status_path,
            put(move || {
                let calls = Arc::clone(&first_handler_calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::SERVICE_UNAVAILABLE, "not ready")
                }
            }),
        );
        let second_calls = Arc::new(AtomicUsize::new(0));
        let second_handler_calls = Arc::clone(&second_calls);
        let second_router = Router::new().route(
            status_path,
            put(move || {
                let calls = Arc::clone(&second_handler_calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }
            }),
        );
        let (first_url, first_task) = spawn_test_server(first_router).await;
        let (second_url, second_task) = spawn_test_server(second_router).await;
        let api = test_api(&[first_url, second_url]);
        let resource = resource(
            PublicServiceTrafficMode::Forwarded,
            PublicServiceProtocol::Tcp,
        );
        let status = error_status(resource.generation, "test", Utc::now());

        assert!(matches!(
            api.update_status(
                &resource.resource_id,
                resource.generation,
                &status,
                "0123456789abcdef0123456789abcdef",
            )
            .await
            .expect("first status update"),
            StatusReportOutcome::Updated
        ));
        assert!(matches!(
            api.update_status(
                &resource.resource_id,
                resource.generation,
                &status,
                "0123456789abcdef0123456789abcdef",
            )
            .await
            .expect("second status update"),
            StatusReportOutcome::Updated
        ));
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 2);
        assert_eq!(api.preferred_endpoint.load(Ordering::Relaxed), 1);

        first_task.abort();
        second_task.abort();
    }

    #[test]
    fn direct_facade_binds_backend_without_mutating_it() {
        let resource = resource(PublicServiceTrafficMode::Direct, PublicServiceProtocol::Tcp);
        let backend = backend_service("TCP", IntOrString::Int(8080));
        let original_backend = backend.clone();
        let facade =
            desired_facade_service("heteronetwork.io/public", &resource, &backend).expect("facade");
        assert_eq!(backend, original_backend);
        assert_eq!(
            facade.metadata.name.as_deref(),
            Some("hn-psvc-0123456789abcdef0123456789abcdef")
        );
        assert_eq!(
            facade
                .metadata
                .annotations
                .as_ref()
                .and_then(|values| values.get(TRAFFIC_MODE_KEY))
                .map(String::as_str),
            Some("direct")
        );
        assert_eq!(
            facade
                .metadata
                .labels
                .as_ref()
                .and_then(|values| values.get(PUBLIC_SERVICE_GENERATION_LABEL))
                .map(String::as_str),
            Some("7")
        );
        let spec = facade.spec.as_ref().expect("facade spec");
        assert_eq!(
            spec.load_balancer_class.as_deref(),
            Some("heteronetwork.io/public")
        );
        assert_eq!(spec.external_traffic_policy.as_deref(), Some("Local"));
        assert_eq!(
            spec.selector,
            Some(BTreeMap::from([("app".to_string(), "livekit".to_string())]))
        );
        let port = &spec.ports.as_ref().expect("ports")[0];
        assert_eq!(port.port, 7882);
        assert_eq!(port.protocol.as_deref(), Some("TCP"));
        assert_eq!(port.target_port, Some(IntOrString::Int(8080)));
    }

    #[test]
    fn forwarded_udp_facade_uses_cluster_policy() {
        let resource = resource(
            PublicServiceTrafficMode::Forwarded,
            PublicServiceProtocol::Udp,
        );
        let backend = backend_service("UDP", IntOrString::String("rtc".to_string()));
        let facade =
            desired_facade_service("heteronetwork.io/public", &resource, &backend).expect("facade");
        let spec = facade.spec.as_ref().expect("facade spec");
        assert_eq!(spec.external_traffic_policy.as_deref(), Some("Cluster"));
        let port = &spec.ports.as_ref().expect("ports")[0];
        assert_eq!(port.protocol.as_deref(), Some("UDP"));
        assert_eq!(
            port.target_port,
            Some(IntOrString::String("rtc".to_string()))
        );
    }

    #[test]
    fn facade_status_waits_for_matching_generation_then_reports_addresses() {
        let resource = resource(
            PublicServiceTrafficMode::Forwarded,
            PublicServiceProtocol::Tcp,
        );
        let mut facade = desired_facade_service(
            "heteronetwork.io/public",
            &resource,
            &backend_service("TCP", IntOrString::Int(7880)),
        )
        .expect("facade");
        facade.status = Some(ServiceStatus {
            load_balancer: Some(LoadBalancerStatus {
                ingress: Some(vec![LoadBalancerIngress {
                    ip: Some("198.51.100.10".to_string()),
                    ..LoadBalancerIngress::default()
                }]),
            }),
            ..ServiceStatus::default()
        });
        let pending = status_from_facade(&resource, &facade, Utc::now());
        assert_eq!(pending.phase, PublicServicePhase::Pending);
        assert!(pending.public_addresses.is_empty());

        facade
            .metadata
            .annotations
            .get_or_insert_with(BTreeMap::new)
            .insert(
                PUBLIC_SERVICE_OBSERVED_GENERATION_ANNOTATION.to_string(),
                resource.generation.to_string(),
            );
        let ready = status_from_facade(&resource, &facade, Utc::now());
        assert_eq!(ready.phase, PublicServicePhase::Ready);
        assert_eq!(
            ready.public_addresses,
            vec![PublicServiceAddress {
                host: "198.51.100.10".to_string(),
                port: 7882,
            }]
        );
        assert_eq!(ready.observed_generation, 7);
    }

    #[test]
    fn snake_case_wire_response_and_optimistic_status_body_match_contract() {
        let body = serde_json::json!({
            "projects": [{
                "cluster_id": "cluster-a",
                "project_id": "prj_0123456789abcdef0123456789abcdef",
                "account_id": "acct_0123456789abcdef0123456789abcdef",
                "name": "livekit",
                "kubernetes_namespace": "hn-livekit-1234abcd",
                "created_at": "2026-07-30T00:00:00Z"
            }],
            "public_services": [{
                "cluster_id": "cluster-a",
                "resource_id": "psvc_0123456789abcdef0123456789abcdef",
                "account_id": "acct_0123456789abcdef0123456789abcdef",
                "project_id": "prj_0123456789abcdef0123456789abcdef",
                "name": "livekit",
                "namespace": "hn-livekit-1234abcd",
                "spec": {
                    "traffic_mode": "forwarded",
                    "protocol": "UDP",
                    "public_port": 7882,
                    "backend_service": "livekit-backend",
                    "backend_port": 7880,
                    "ingress_replicas": 2
                },
                "generation": 7,
                "status": {
                    "phase": "pending",
                    "public_addresses": [],
                    "message": null,
                    "observed_generation": 0,
                    "observed_at": null
                },
                "created_at": "2026-07-30T00:00:00Z",
                "updated_at": "2026-07-30T00:00:00Z"
            }]
        });
        let response: DesiredCustomerResources =
            serde_json::from_value(body).expect("wire response");
        validate_desired_resources(&response).expect("valid resources");
        assert_eq!(response.projects.len(), 1);
        assert_eq!(response.public_services.len(), 1);

        let status = error_status(7, "backend unavailable", Utc::now());
        let request = UpdatePublicServiceStatusRequest {
            expected_generation: 7,
            status: &status,
        };
        let encoded = serde_json::to_value(request).expect("status request");
        assert_eq!(encoded["expected_generation"], 7);
        assert_eq!(encoded["status"]["observed_generation"], 7);
        assert_eq!(encoded["status"]["phase"], "error");
    }

    #[test]
    fn internal_origin_and_collection_url_resolve_to_controller_contract() {
        for configured in [
            "http://customer-controller:19882",
            "http://customer-controller:19882/",
            "http://customer-controller:19882/internal/v1/customer/public-services",
        ] {
            let collection = parse_internal_url(configured).expect("internal URL");
            assert_eq!(
                collection.as_str(),
                "http://customer-controller:19882/internal/v1/customer/public-services"
            );
            assert_eq!(
                status_url(&collection, "psvc_0123456789abcdef0123456789abcdef")
                    .expect("status URL")
                    .as_str(),
                "http://customer-controller:19882/internal/v1/customer/public-services/psvc_0123456789abcdef0123456789abcdef/status"
            );
        }
        assert!(parse_internal_url("http://user:password@customer-controller:19882").is_err());
        assert!(parse_internal_url("http://customer-controller:19882/v1/customer").is_err());
        assert!(parse_internal_urls(&[
            "http://customer-controller:19882".to_string(),
            "http://customer-controller:19882/internal/v1/customer/public-services/".to_string(),
        ])
        .is_err());
    }

    #[test]
    fn stale_facade_detection_requires_matching_namespace_name_and_resource() {
        let resource = resource(
            PublicServiceTrafficMode::Forwarded,
            PublicServiceProtocol::Tcp,
        );
        let facade = desired_facade_service(
            "heteronetwork.io/public",
            &resource,
            &backend_service("TCP", IntOrString::Int(7880)),
        )
        .expect("facade");
        let key = (
            resource.namespace.clone(),
            facade_service_name(&resource.resource_id).expect("facade name"),
        );
        let desired = BTreeMap::from([(key, resource.resource_id.clone())]);
        assert!(facade_is_desired(&facade, &desired));

        let wrong_owner = BTreeMap::from([(
            (
                resource.namespace,
                facade_service_name(&resource.resource_id).expect("facade name"),
            ),
            "psvc_ffffffffffffffffffffffffffffffff".to_string(),
        )]);
        assert!(!facade_is_desired(&facade, &wrong_owner));
    }

    #[test]
    fn facade_rejects_resource_replica_count_above_existing_controller_limit() {
        let mut resource = resource(
            PublicServiceTrafficMode::Forwarded,
            PublicServiceProtocol::Tcp,
        );
        resource.spec.ingress_replicas = MAX_INGRESS_REPLICAS as u16 + 1;
        let error = desired_facade_service(
            "heteronetwork.io/public",
            &resource,
            &backend_service("TCP", IntOrString::Int(7880)),
        )
        .expect_err("unsupported replica count");
        assert!(error.contains("ingress_replicas"));
    }
}
