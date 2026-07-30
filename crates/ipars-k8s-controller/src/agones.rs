use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context;
use ipars_k8s_controller::{
    TrafficMode, AGONES_GAME_SERVER_LABEL, AGONES_MANAGED_LABEL,
    AGONES_PUBLIC_ADDRESSES_ANNOTATION, AGONES_PUBLIC_READY_LABEL, INGRESS_REPLICAS_ANNOTATION,
    RECONCILE_ERROR_ANNOTATION, TRAFFIC_MODE_KEY,
};
use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{
    Api, ApiResource, DeleteParams, DynamicObject, GroupVersionKind, ListParams, Patch,
    PatchParams, PostParams,
};
use kube::{Client, ResourceExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

const AGONES_POD_LABEL: &str = "agones.dev/gameserver";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GameServerSpec {
    #[serde(default)]
    ports: Vec<GameServerPort>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GameServerPort {
    name: String,
    port_policy: String,
    container_port: i32,
    #[serde(default = "default_udp")]
    protocol: String,
}

#[derive(Debug, Clone)]
struct DesiredGameServer {
    object: DynamicObject,
    namespace: String,
    name: String,
    service_name: String,
    mode: TrafficMode,
    ports: Vec<GameServerPort>,
}

#[derive(Debug, Clone)]
struct GameServerIdentity {
    uid: Option<String>,
    managed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AgonesPortClaim {
    protocol: String,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PublicAddress {
    name: String,
    address: String,
    port: i32,
    protocol: String,
}

type InvalidGameServer = Box<(DynamicObject, String)>;

fn default_udp() -> String {
    "UDP".to_string()
}

fn api_resource() -> ApiResource {
    ApiResource::from_gvk_with_plural(
        &GroupVersionKind::gvk("agones.dev", "v1", "GameServer"),
        "gameservers",
    )
}

pub async fn reconcile_services(
    client: Client,
    load_balancer_class: &str,
    port_range_start: u16,
    port_range_end: u16,
) -> anyhow::Result<bool> {
    let resource = api_resource();
    let game_servers_api: Api<DynamicObject> = Api::all_with(client.clone(), &resource);
    let game_servers = match game_servers_api.list(&ListParams::default()).await {
        Ok(game_servers) => game_servers,
        Err(kube::Error::Api(status)) if status.is_not_found() => {
            tracing::warn!("Agones integration is enabled but the GameServer CRD is not installed");
            return Ok(false);
        }
        Err(error) => return Err(error).context("failed to list Agones GameServers"),
    };
    let services_api: Api<Service> = Api::all(client.clone());
    let services = services_api
        .list(&ListParams::default())
        .await
        .context("failed to list Services for Agones reconciliation")?;

    let game_server_identities = game_servers
        .items
        .iter()
        .filter_map(|game_server| {
            Some((
                (game_server.namespace()?, game_server.name_any()),
                GameServerIdentity {
                    uid: game_server.metadata.uid.clone(),
                    managed: game_server
                        .metadata
                        .annotations
                        .as_ref()
                        .is_some_and(|annotations| annotations.contains_key(TRAFFIC_MODE_KEY)),
                },
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let mut desired = Vec::new();
    for game_server in game_servers.items {
        let has_publication =
            game_server
                .metadata
                .annotations
                .as_ref()
                .is_some_and(|annotations| {
                    annotations.contains_key(AGONES_PUBLIC_ADDRESSES_ANNOTATION)
                        || annotations.contains_key(RECONCILE_ERROR_ANNOTATION)
                })
                || game_server
                    .metadata
                    .labels
                    .as_ref()
                    .is_some_and(|labels| labels.contains_key(AGONES_PUBLIC_READY_LABEL));
        match desired_game_server(game_server.clone()) {
            Ok(Some(game_server)) => desired.push(game_server),
            Ok(None) if has_publication => {
                patch_game_server_publication(
                    client.clone(),
                    &resource,
                    &game_server,
                    None,
                    None,
                    Some(false),
                )
                .await?;
            }
            Ok(None) => {}
            Err(error) => {
                let (game_server, error) = *error;
                patch_game_server_publication(
                    client.clone(),
                    &resource,
                    &game_server,
                    None,
                    Some(&error),
                    Some(false),
                )
                .await?;
            }
        }
    }
    desired
        .sort_by(|left, right| (&left.namespace, &left.name).cmp(&(&right.namespace, &right.name)));

    let existing = services
        .items
        .iter()
        .filter(|service| is_agones_managed(service))
        .filter_map(|service| {
            Some((
                (
                    service.namespace()?,
                    service
                        .metadata
                        .labels
                        .as_ref()?
                        .get(AGONES_GAME_SERVER_LABEL)?
                        .clone(),
                ),
                service.clone(),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let mut used_ports = reserved_non_agones_ports(
        &services.items,
        load_balancer_class,
        port_range_start,
        port_range_end,
    );
    let desired_keys = desired
        .iter()
        .map(|game_server| (game_server.namespace.clone(), game_server.name.clone()))
        .collect::<BTreeSet<_>>();
    for service in services
        .items
        .iter()
        .filter(|service| is_agones_managed(service))
    {
        let service_key = service.metadata.labels.as_ref().and_then(|labels| {
            Some((
                service.namespace()?,
                labels.get(AGONES_GAME_SERVER_LABEL)?.clone(),
            ))
        });
        if service_key.is_none_or(|key| !desired_keys.contains(&key)) {
            used_ports.extend(service_port_claims(
                service,
                port_range_start,
                port_range_end,
            ));
        }
    }
    for game_server in desired {
        let key = (game_server.namespace.clone(), game_server.name.clone());
        let existing_service = existing
            .get(&key)
            .filter(|service| service.name_any() == game_server.service_name);
        match assigned_ports(
            &game_server,
            existing_service,
            &mut used_ports,
            port_range_start,
            port_range_end,
        ) {
            Ok(ports) => {
                if let Err(error) = reconcile_game_server_service(
                    client.clone(),
                    load_balancer_class,
                    &game_server,
                    existing_service,
                    ports,
                )
                .await
                {
                    patch_game_server_publication(
                        client.clone(),
                        &resource,
                        &game_server.object,
                        None,
                        Some(&error.to_string()),
                        Some(false),
                    )
                    .await?;
                    continue;
                }
                let current_addresses = game_server
                    .object
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|annotations| annotations.get(AGONES_PUBLIC_ADDRESSES_ANNOTATION))
                    .map(String::as_str);
                patch_game_server_publication(
                    client.clone(),
                    &resource,
                    &game_server.object,
                    current_addresses,
                    None,
                    None,
                )
                .await?;
            }
            Err(error) => {
                patch_game_server_publication(
                    client.clone(),
                    &resource,
                    &game_server.object,
                    None,
                    Some(&error),
                    Some(false),
                )
                .await?;
            }
        }
    }

    for service in services
        .items
        .iter()
        .filter(|service| is_agones_managed(service))
    {
        let Some(namespace) = service.namespace() else {
            continue;
        };
        let Some(game_server_name) = service
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(AGONES_GAME_SERVER_LABEL))
        else {
            continue;
        };
        let Some(identity) =
            game_server_identities.get(&(namespace.clone(), game_server_name.clone()))
        else {
            // GameServer deletion is handled by Kubernetes owner-reference GC.
            continue;
        };
        if identity.managed
            || service.name_any() != generated_service_name(&namespace, game_server_name)
            || !service_is_owned_by_identity(service, game_server_name, identity.uid.as_deref())
        {
            continue;
        }
        let name = service.name_any();
        let api: Api<Service> = Api::namespaced(client.clone(), &namespace);
        match api.delete(&name, &DeleteParams::default()).await {
            Ok(_) => {
                tracing::info!(service = %format!("{namespace}/{name}"), "deleted stale Agones Service");
            }
            Err(kube::Error::Api(status)) if status.is_not_found() => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to delete stale Service {namespace}/{name}"));
            }
        }
    }
    Ok(true)
}

pub async fn publish_addresses(client: Client) -> anyhow::Result<()> {
    let resource = api_resource();
    let game_servers_api: Api<DynamicObject> = Api::all_with(client.clone(), &resource);
    let game_servers = match game_servers_api.list(&ListParams::default()).await {
        Ok(game_servers) => game_servers,
        Err(kube::Error::Api(status)) if status.is_not_found() => return Ok(()),
        Err(error) => return Err(error).context("failed to list Agones GameServers"),
    };
    let game_servers = game_servers
        .items
        .into_iter()
        .filter_map(|game_server| {
            Some((
                (game_server.namespace()?, game_server.name_any()),
                game_server,
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let services_api: Api<Service> = Api::all(client.clone());
    let services = services_api
        .list(&ListParams::default())
        .await
        .context("failed to list generated Agones Services")?;

    for service in services
        .items
        .iter()
        .filter(|service| is_agones_managed(service))
    {
        let Some(namespace) = service.namespace() else {
            continue;
        };
        let Some(game_server_name) = service
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(AGONES_GAME_SERVER_LABEL))
        else {
            continue;
        };
        let Some(game_server) = game_servers.get(&(namespace.clone(), game_server_name.clone()))
        else {
            continue;
        };
        let addresses = service_public_addresses(service);
        let addresses = (!addresses.is_empty())
            .then(|| serde_json::to_string(&addresses))
            .transpose()
            .context("failed to encode Agones public addresses")?;
        let public_ready = addresses.is_some();
        patch_game_server_publication(
            client.clone(),
            &resource,
            game_server,
            addresses.as_deref(),
            None,
            Some(public_ready),
        )
        .await?;
    }
    Ok(())
}

fn desired_game_server(
    game_server: DynamicObject,
) -> Result<Option<DesiredGameServer>, InvalidGameServer> {
    let mode = game_server
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(TRAFFIC_MODE_KEY))
        .cloned();
    let Some(mode) = mode else {
        return Ok(None);
    };
    let mode = match TrafficMode::parse(&mode) {
        Some(mode) => mode,
        None => {
            return Err(Box::new((
                game_server,
                format!("{TRAFFIC_MODE_KEY} must be forwarded or direct"),
            )));
        }
    };
    let Some(namespace) = game_server.namespace() else {
        return Err(Box::new((
            game_server,
            "GameServer must have a namespace".to_string(),
        )));
    };
    let name = game_server.name_any();
    let spec = match game_server.data.get("spec").cloned() {
        Some(spec) => match serde_json::from_value::<GameServerSpec>(spec) {
            Ok(spec) => spec,
            Err(error) => {
                return Err(Box::new((
                    game_server,
                    format!("invalid GameServer port specification: {error}"),
                )));
            }
        },
        None => {
            return Err(Box::new((
                game_server,
                "GameServer must include spec".to_string(),
            )));
        }
    };
    if spec.ports.is_empty() {
        return Err(Box::new((
            game_server,
            "GameServer must expose at least one port".to_string(),
        )));
    }
    let mut names = BTreeSet::new();
    for port in &spec.ports {
        if port.name.is_empty() || !names.insert(port.name.clone()) {
            return Err(Box::new((
                game_server,
                "GameServer ports must have unique non-empty names".to_string(),
            )));
        }
        if port.port_policy != "None" {
            return Err(Box::new((
                game_server,
                format!("GameServer port {} must use portPolicy None", port.name),
            )));
        }
        if !(1..=65_535).contains(&port.container_port) {
            return Err(Box::new((
                game_server,
                format!("GameServer port {} has an invalid containerPort", port.name),
            )));
        }
        if !matches!(port.protocol.as_str(), "UDP" | "TCP" | "TCPUDP") {
            return Err(Box::new((
                game_server,
                format!(
                    "GameServer port {} protocol must be UDP, TCP, or TCPUDP",
                    port.name
                ),
            )));
        }
    }
    let service_name = generated_service_name(&namespace, &name);
    Ok(Some(DesiredGameServer {
        object: game_server,
        namespace,
        name,
        service_name,
        mode,
        ports: spec.ports,
    }))
}

fn assigned_ports(
    game_server: &DesiredGameServer,
    existing: Option<&Service>,
    used_ports: &mut BTreeSet<AgonesPortClaim>,
    range_start: u16,
    range_end: u16,
) -> Result<BTreeMap<String, u16>, String> {
    let existing = existing.map(existing_allocations).unwrap_or_default();
    let mut result = BTreeMap::new();
    for game_port in &game_server.ports {
        let reusable = existing
            .get(&game_port.name)
            .copied()
            .filter(|port| (range_start..=range_end).contains(port))
            .filter(|port| port_is_available(used_ports, game_port, *port));
        let selected = reusable
            .or_else(|| {
                (range_start..=range_end)
                    .find(|port| port_is_available(used_ports, game_port, *port))
            })
            .ok_or_else(|| {
                format!("Agones public port range {range_start}-{range_end} is exhausted")
            })?;
        reserve_port(used_ports, game_port, selected);
        result.insert(game_port.name.clone(), selected);
    }
    Ok(result)
}

fn existing_allocations(service: &Service) -> BTreeMap<String, u16> {
    let mut result = BTreeMap::new();
    for port in service
        .spec
        .as_ref()
        .and_then(|spec| spec.ports.as_ref())
        .into_iter()
        .flatten()
    {
        let Some(name) = port.name.as_deref() else {
            continue;
        };
        let base_name = name
            .strip_suffix("-tcp")
            .or_else(|| name.strip_suffix("-udp"))
            .unwrap_or(name);
        if let Ok(port) = u16::try_from(port.port) {
            result.entry(base_name.to_string()).or_insert(port);
        }
    }
    result
}

fn reserved_non_agones_ports(
    services: &[Service],
    load_balancer_class: &str,
    range_start: u16,
    range_end: u16,
) -> BTreeSet<AgonesPortClaim> {
    services
        .iter()
        .filter(|service| !is_agones_managed(service))
        .filter(|service| {
            service.spec.as_ref().is_some_and(|spec| {
                spec.type_.as_deref() == Some("LoadBalancer")
                    && spec.load_balancer_class.as_deref() == Some(load_balancer_class)
            })
        })
        .flat_map(|service| service_port_claims(service, range_start, range_end))
        .collect()
}

fn service_port_claims(
    service: &Service,
    range_start: u16,
    range_end: u16,
) -> Vec<AgonesPortClaim> {
    service
        .spec
        .as_ref()
        .and_then(|spec| spec.ports.as_ref())
        .into_iter()
        .flatten()
        .filter_map(|port| {
            let number = u16::try_from(port.port).ok()?;
            (range_start..=range_end)
                .contains(&number)
                .then(|| AgonesPortClaim {
                    protocol: port
                        .protocol
                        .clone()
                        .unwrap_or_else(|| "TCP".to_string())
                        .to_ascii_uppercase(),
                    port: number,
                })
        })
        .collect()
}

fn port_is_available(
    used_ports: &BTreeSet<AgonesPortClaim>,
    game_port: &GameServerPort,
    port: u16,
) -> bool {
    protocols(&game_port.protocol).iter().all(|protocol| {
        !used_ports.contains(&AgonesPortClaim {
            protocol: (*protocol).to_string(),
            port,
        })
    })
}

fn reserve_port(used_ports: &mut BTreeSet<AgonesPortClaim>, game_port: &GameServerPort, port: u16) {
    for protocol in protocols(&game_port.protocol) {
        used_ports.insert(AgonesPortClaim {
            protocol: (*protocol).to_string(),
            port,
        });
    }
}

async fn reconcile_game_server_service(
    client: Client,
    load_balancer_class: &str,
    game_server: &DesiredGameServer,
    existing: Option<&Service>,
    assigned_ports: BTreeMap<String, u16>,
) -> anyhow::Result<()> {
    let service = desired_service(load_balancer_class, game_server, assigned_ports)?;
    let api: Api<Service> = Api::namespaced(client, &game_server.namespace);
    match existing {
        Some(existing) if !service_is_owned_by(existing, game_server) => {
            anyhow::bail!(
                "refusing to take ownership of stale Service {}/{}",
                game_server.namespace,
                game_server.service_name
            );
        }
        Some(existing)
            if existing.name_any() == game_server.service_name
                && service_matches(existing, &service) => {}
        Some(existing) if existing.name_any() == game_server.service_name => {
            let patch = json!({
                "metadata": {
                    "annotations": service.metadata.annotations,
                    "labels": service.metadata.labels,
                    "ownerReferences": service.metadata.owner_references,
                },
                "spec": {
                    "allocateLoadBalancerNodePorts": false,
                    "externalTrafficPolicy": service.spec.as_ref().and_then(|spec| spec.external_traffic_policy.clone()),
                    "loadBalancerClass": load_balancer_class,
                    "ports": service.spec.as_ref().and_then(|spec| spec.ports.clone()),
                    "selector": service.spec.as_ref().and_then(|spec| spec.selector.clone()),
                    "type": "LoadBalancer",
                }
            });
            api.patch(
                &game_server.service_name,
                &PatchParams::default(),
                &Patch::Merge(&patch),
            )
            .await
            .with_context(|| {
                format!(
                    "failed to update Agones Service {}/{}",
                    game_server.namespace, game_server.service_name
                )
            })?;
        }
        Some(existing) => {
            anyhow::bail!(
                "GameServer {}/{} has unexpected managed Service {}",
                game_server.namespace,
                game_server.name,
                existing.name_any()
            );
        }
        None => match api.create(&PostParams::default(), &service).await {
            Ok(_) => {}
            Err(kube::Error::Api(status)) if status.code == 409 => {
                let current = api.get(&game_server.service_name).await.with_context(|| {
                    format!(
                        "failed to inspect conflicting Service {}/{}",
                        game_server.namespace, game_server.service_name
                    )
                })?;
                anyhow::ensure!(
                    service_is_owned_by(&current, game_server),
                    "refusing to take ownership of existing Service {}/{}",
                    game_server.namespace,
                    game_server.service_name
                );
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to create Agones Service {}/{}",
                        game_server.namespace, game_server.service_name
                    )
                });
            }
        },
    }
    Ok(())
}

fn desired_service(
    load_balancer_class: &str,
    game_server: &DesiredGameServer,
    assigned_ports: BTreeMap<String, u16>,
) -> anyhow::Result<Service> {
    let uid = game_server
        .object
        .metadata
        .uid
        .clone()
        .context("GameServer has no UID")?;
    let mut ports = Vec::new();
    for game_port in &game_server.ports {
        let public_port = i32::from(
            *assigned_ports
                .get(&game_port.name)
                .context("GameServer public port was not allocated")?,
        );
        for protocol in protocols(&game_port.protocol) {
            let name = if game_port.protocol == "TCPUDP" {
                format!("{}-{}", game_port.name, protocol.to_ascii_lowercase())
            } else {
                game_port.name.clone()
            };
            ports.push(ServicePort {
                name: Some(name),
                port: public_port,
                protocol: Some(protocol.to_string()),
                target_port: Some(IntOrString::Int(game_port.container_port)),
                ..ServicePort::default()
            });
        }
    }
    let mut annotations = BTreeMap::from([(
        TRAFFIC_MODE_KEY.to_string(),
        game_server.mode.as_str().to_string(),
    )]);
    if game_server.mode == TrafficMode::Direct {
        annotations.insert(INGRESS_REPLICAS_ANNOTATION.to_string(), "1".to_string());
    }
    Ok(Service {
        metadata: ObjectMeta {
            name: Some(game_server.service_name.clone()),
            namespace: Some(game_server.namespace.clone()),
            annotations: Some(annotations),
            labels: Some(BTreeMap::from([
                (AGONES_MANAGED_LABEL.to_string(), "true".to_string()),
                (
                    AGONES_GAME_SERVER_LABEL.to_string(),
                    game_server.name.clone(),
                ),
            ])),
            owner_references: Some(vec![OwnerReference {
                api_version: "agones.dev/v1".to_string(),
                kind: "GameServer".to_string(),
                name: game_server.name.clone(),
                uid,
                controller: Some(true),
                block_owner_deletion: None,
            }]),
            ..ObjectMeta::default()
        },
        spec: Some(ServiceSpec {
            allocate_load_balancer_node_ports: Some(false),
            external_traffic_policy: Some(
                match game_server.mode {
                    TrafficMode::Forwarded => "Cluster",
                    TrafficMode::Direct => "Local",
                }
                .to_string(),
            ),
            load_balancer_class: Some(load_balancer_class.to_string()),
            ports: Some(ports),
            selector: Some(BTreeMap::from([(
                AGONES_POD_LABEL.to_string(),
                game_server.name.clone(),
            )])),
            type_: Some("LoadBalancer".to_string()),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

fn protocols(protocol: &str) -> &'static [&'static str] {
    match protocol {
        "TCP" => &["TCP"],
        "TCPUDP" => &["TCP", "UDP"],
        _ => &["UDP"],
    }
}

fn service_public_addresses(service: &Service) -> Vec<PublicAddress> {
    let ingress = service
        .status
        .as_ref()
        .and_then(|status| status.load_balancer.as_ref())
        .and_then(|status| status.ingress.as_ref())
        .into_iter()
        .flatten()
        .filter_map(|ingress| ingress.ip.as_deref());
    let ports = service
        .spec
        .as_ref()
        .and_then(|spec| spec.ports.as_ref())
        .into_iter()
        .flatten()
        .filter_map(|port| {
            Some((
                port.name.clone()?,
                port.port,
                port.protocol.clone().unwrap_or_else(|| "TCP".to_string()),
            ))
        })
        .collect::<Vec<_>>();
    let mut result = ingress
        .flat_map(|address| {
            ports
                .iter()
                .map(move |(name, port, protocol)| PublicAddress {
                    name: name.clone(),
                    address: address.to_string(),
                    port: *port,
                    protocol: protocol.clone(),
                })
        })
        .collect::<Vec<_>>();
    result.sort_by(|left, right| {
        (&left.address, left.port, &left.protocol, &left.name).cmp(&(
            &right.address,
            right.port,
            &right.protocol,
            &right.name,
        ))
    });
    result
}

async fn patch_game_server_publication(
    client: Client,
    resource: &ApiResource,
    game_server: &DynamicObject,
    public_addresses: Option<&str>,
    error: Option<&str>,
    public_ready: Option<bool>,
) -> anyhow::Result<()> {
    let namespace = game_server
        .namespace()
        .context("GameServer has no namespace")?;
    let name = game_server.name_any();
    let current_annotations = game_server.metadata.annotations.as_ref();
    let current_addresses = current_annotations
        .and_then(|annotations| annotations.get(AGONES_PUBLIC_ADDRESSES_ANNOTATION))
        .map(String::as_str);
    let current_error = current_annotations
        .and_then(|annotations| annotations.get(RECONCILE_ERROR_ANNOTATION))
        .map(String::as_str);
    let current_public_ready = game_server
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(AGONES_PUBLIC_READY_LABEL));
    let public_ready_matches = match public_ready {
        Some(true) => current_public_ready.is_some_and(|value| value == "true"),
        Some(false) => current_public_ready.is_none(),
        None => true,
    };
    if current_addresses == public_addresses && current_error == error && public_ready_matches {
        return Ok(());
    }
    let api: Api<DynamicObject> = Api::namespaced_with(client, &namespace, resource);
    let mut metadata = json!({
        "annotations": {
            AGONES_PUBLIC_ADDRESSES_ANNOTATION: public_addresses,
            RECONCILE_ERROR_ANNOTATION: error,
        }
    });
    if let Some(public_ready) = public_ready {
        metadata["labels"] = json!({
            AGONES_PUBLIC_READY_LABEL: public_ready.then_some("true"),
        });
    }
    let patch = json!({ "metadata": metadata });
    api.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .with_context(|| format!("failed to patch GameServer {namespace}/{name} annotations"))?;
    Ok(())
}

fn generated_service_name(namespace: &str, game_server_name: &str) -> String {
    let digest = Sha256::digest(format!("{namespace}\0{game_server_name}").as_bytes());
    let suffix = digest[..10]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("hn-agones-{suffix}")
}

fn is_agones_managed(service: &Service) -> bool {
    service
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(AGONES_MANAGED_LABEL))
        .is_some_and(|value| value == "true")
}

fn service_is_owned_by(service: &Service, game_server: &DesiredGameServer) -> bool {
    service_is_owned_by_identity(
        service,
        &game_server.name,
        game_server.object.metadata.uid.as_deref(),
    )
}

fn service_is_owned_by_identity(
    service: &Service,
    game_server_name: &str,
    expected_uid: Option<&str>,
) -> bool {
    is_agones_managed(service)
        && service
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(AGONES_GAME_SERVER_LABEL))
            .is_some_and(|value| value == game_server_name)
        && service
            .metadata
            .owner_references
            .as_ref()
            .into_iter()
            .flatten()
            .any(|owner| {
                owner.api_version == "agones.dev/v1"
                    && owner.kind == "GameServer"
                    && owner.name == game_server_name
                    && Some(owner.uid.as_str()) == expected_uid
            })
}

fn service_matches(existing: &Service, desired: &Service) -> bool {
    let Some(existing_spec) = existing.spec.as_ref() else {
        return false;
    };
    let Some(desired_spec) = desired.spec.as_ref() else {
        return false;
    };
    let desired_annotations = desired.metadata.annotations.as_ref();
    let desired_labels = desired.metadata.labels.as_ref();
    let metadata_matches = desired_annotations.is_none_or(|desired_values| {
        desired_values.iter().all(|(key, value)| {
            existing
                .metadata
                .annotations
                .as_ref()
                .and_then(|values| values.get(key))
                == Some(value)
        })
    }) && desired_labels.is_none_or(|desired_values| {
        desired_values.iter().all(|(key, value)| {
            existing
                .metadata
                .labels
                .as_ref()
                .and_then(|values| values.get(key))
                == Some(value)
        })
    });
    metadata_matches
        && existing.metadata.owner_references == desired.metadata.owner_references
        && existing_spec.allocate_load_balancer_node_ports
            == desired_spec.allocate_load_balancer_node_ports
        && existing_spec.external_traffic_policy == desired_spec.external_traffic_policy
        && existing_spec.load_balancer_class == desired_spec.load_balancer_class
        && existing_spec.ports == desired_spec.ports
        && existing_spec.selector == desired_spec.selector
        && existing_spec.type_ == desired_spec.type_
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{LoadBalancerIngress, LoadBalancerStatus, ServiceStatus};

    fn game_server(name: &str, mode: &str, protocol: &str) -> DynamicObject {
        let resource = api_resource();
        let mut object = DynamicObject::new(name, &resource)
            .within("default")
            .data(json!({
                "spec": {
                    "ports": [{
                        "name": "game",
                        "portPolicy": "None",
                        "containerPort": 7654,
                        "protocol": protocol,
                    }]
                }
            }));
        object.metadata.uid = Some(format!("uid-{name}"));
        object.metadata.annotations = Some(BTreeMap::from([(
            TRAFFIC_MODE_KEY.to_string(),
            mode.to_string(),
        )]));
        object
    }

    #[test]
    fn generated_name_is_stable_and_short() {
        let first = generated_service_name("default", "game-1");
        assert_eq!(first, generated_service_name("default", "game-1"));
        assert_ne!(first, generated_service_name("other", "game-1"));
        assert!(first.len() <= 63);
    }

    #[test]
    fn direct_service_uses_local_policy_and_public_selector() {
        let desired = desired_game_server(game_server("game-1", "direct", "UDP"))
            .expect("valid GameServer")
            .expect("managed GameServer");
        let service = desired_service(
            ipars_k8s_controller::LOAD_BALANCER_CLASS,
            &desired,
            BTreeMap::from([("game".to_string(), 7001)]),
        )
        .expect("Service");
        let spec = service.spec.expect("Service spec");
        assert_eq!(spec.external_traffic_policy.as_deref(), Some("Local"));
        assert_eq!(
            spec.selector
                .as_ref()
                .and_then(|selector| selector.get(AGONES_POD_LABEL))
                .map(String::as_str),
            Some("game-1")
        );
        assert_eq!(spec.ports.expect("ports")[0].port, 7001);
        assert_eq!(
            service
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(INGRESS_REPLICAS_ANNOTATION))
                .map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn tcpudp_expands_to_two_service_ports() {
        let desired = desired_game_server(game_server("game-1", "forwarded", "TCPUDP"))
            .expect("valid GameServer")
            .expect("managed GameServer");
        let service = desired_service(
            ipars_k8s_controller::LOAD_BALANCER_CLASS,
            &desired,
            BTreeMap::from([("game".to_string(), 7001)]),
        )
        .expect("Service");
        let ports = service.spec.expect("spec").ports.expect("ports");
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].port, ports[1].port);
    }

    #[test]
    fn allocator_reuses_existing_port_and_avoids_reserved_port() {
        let desired = desired_game_server(game_server("game-1", "forwarded", "UDP"))
            .expect("valid GameServer")
            .expect("managed GameServer");
        let existing = desired_service(
            ipars_k8s_controller::LOAD_BALANCER_CLASS,
            &desired,
            BTreeMap::from([("game".to_string(), 7002)]),
        )
        .expect("Service");
        let mut used = BTreeSet::from([AgonesPortClaim {
            protocol: "UDP".to_string(),
            port: 7001,
        }]);
        let assigned =
            assigned_ports(&desired, Some(&existing), &mut used, 7000, 7010).expect("allocation");
        assert_eq!(assigned["game"], 7002);
    }

    #[test]
    fn allocator_can_reuse_a_port_for_a_different_protocol() {
        let desired = desired_game_server(game_server("game-1", "forwarded", "TCP"))
            .expect("valid GameServer")
            .expect("managed GameServer");
        let mut used = BTreeSet::from([AgonesPortClaim {
            protocol: "UDP".to_string(),
            port: 7000,
        }]);
        let assigned =
            assigned_ports(&desired, None, &mut used, 7000, 7000).expect("TCP allocation");
        assert_eq!(assigned["game"], 7000);
    }

    #[test]
    fn public_addresses_are_cartesian_product_of_ingress_and_ports() {
        let mut service = Service {
            spec: Some(ServiceSpec {
                ports: Some(vec![ServicePort {
                    name: Some("game".to_string()),
                    port: 7001,
                    protocol: Some("UDP".to_string()),
                    ..ServicePort::default()
                }]),
                ..ServiceSpec::default()
            }),
            status: Some(ServiceStatus {
                load_balancer: Some(LoadBalancerStatus {
                    ingress: Some(vec![
                        LoadBalancerIngress {
                            ip: Some("198.51.100.10".to_string()),
                            ..LoadBalancerIngress::default()
                        },
                        LoadBalancerIngress {
                            ip: Some("198.51.100.11".to_string()),
                            ..LoadBalancerIngress::default()
                        },
                    ]),
                }),
                ..ServiceStatus::default()
            }),
            ..Service::default()
        };
        service.metadata.name = Some("game".to_string());
        assert_eq!(service_public_addresses(&service).len(), 2);
    }
}
