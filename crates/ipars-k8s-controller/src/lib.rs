use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ipars_types::{CandidateSource, EndpointCandidate, EndpointCandidateKind};
use k8s_openapi::api::core::v1::{Node, Pod, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::ResourceExt;
use serde::{Deserialize, Serialize};

pub const LOAD_BALANCER_CLASS: &str = "heteronetwork.io/public";
pub const TRAFFIC_MODE_KEY: &str = "networking.heteronetwork.io/traffic-mode";
pub const PUBLIC_INGRESS_LABEL: &str = "networking.heteronetwork.io/public-ingress";
pub const PUBLIC_INGRESS_ENABLED_ANNOTATION: &str =
    "networking.heteronetwork.io/public-ingress-enabled";
pub const NODE_ID_ANNOTATION: &str = "networking.heteronetwork.io/node-id";
pub const VPN_IP_ANNOTATION: &str = "networking.heteronetwork.io/vpn-ip";
pub const PUBLIC_IP_ANNOTATION: &str = "networking.heteronetwork.io/public-ip";
pub const MANAGED_EXTERNAL_IP_ANNOTATION: &str = "networking.heteronetwork.io/managed-external-ip";
pub const INGRESS_REPLICAS_ANNOTATION: &str = "networking.heteronetwork.io/ingress-replicas";
pub const ASSIGNED_NODES_ANNOTATION: &str = "networking.heteronetwork.io/assigned-nodes";
pub const RECONCILE_ERROR_ANNOTATION: &str = "networking.heteronetwork.io/reconcile-error";
pub const PLACEMENT_INJECTED_ANNOTATION: &str = "networking.heteronetwork.io/placement-injected";
pub const AGONES_MANAGED_LABEL: &str = "networking.heteronetwork.io/agones-managed";
pub const AGONES_GAME_SERVER_LABEL: &str = "networking.heteronetwork.io/agones-game-server";
pub const AGONES_PUBLIC_READY_LABEL: &str = "networking.heteronetwork.io/public-ready";
pub const AGONES_PUBLIC_ADDRESSES_ANNOTATION: &str = "networking.heteronetwork.io/public-addresses";
pub const DEFAULT_INGRESS_REPLICAS: usize = 2;
pub const MAX_INGRESS_REPLICAS: usize = 64;
const PUBLIC_CANDIDATE_FUTURE_SKEW_SECONDS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficMode {
    Forwarded,
    Direct,
}

impl TrafficMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "forwarded" => Some(Self::Forwarded),
            "direct" => Some(Self::Direct),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::Direct => "direct",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceKey {
    pub namespace: String,
    pub name: String,
}

impl ServiceKey {
    pub fn from_service(service: &Service) -> Option<Self> {
        Some(Self {
            namespace: service.namespace()?,
            name: service.name_any(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicNode {
    pub name: String,
    pub public_ip: IpAddr,
    pub vpn_ip: Option<IpAddr>,
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PortClaim {
    pub protocol: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpFamily {
    Ipv4,
    Ipv6,
}

impl IpFamily {
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedService {
    pub key: ServiceKey,
    pub creation_timestamp: Option<String>,
    pub mode: TrafficMode,
    pub ingress_replicas: usize,
    pub requested_ip: Option<IpAddr>,
    pub ip_families: BTreeSet<IpFamily>,
    pub ports: Vec<PortClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignedNode {
    pub name: String,
    pub public_ip: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpn_ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAssignment {
    pub key: ServiceKey,
    pub nodes: Vec<AssignedNode>,
    pub error: Option<String>,
}

pub fn traffic_mode(service: &Service) -> Result<TrafficMode, String> {
    let value = service
        .metadata
        .annotations
        .as_ref()
        .and_then(|values| values.get(TRAFFIC_MODE_KEY))
        .ok_or_else(|| format!("{TRAFFIC_MODE_KEY} annotation is required"))?;
    let policy = service
        .spec
        .as_ref()
        .and_then(|spec| spec.external_traffic_policy.as_deref())
        .unwrap_or("Cluster");
    let derived = match policy {
        "Cluster" => TrafficMode::Forwarded,
        "Local" => TrafficMode::Direct,
        other => {
            return Err(format!(
                "externalTrafficPolicy must be Cluster or Local, got {other}"
            ));
        }
    };
    let explicit = TrafficMode::parse(value)
        .ok_or_else(|| format!("{TRAFFIC_MODE_KEY} must be forwarded or direct, got {value}"))?;
    if explicit != derived {
        return Err(format!(
            "{} mode requires externalTrafficPolicy {}, got {policy}",
            explicit.as_str(),
            match explicit {
                TrafficMode::Forwarded => "Cluster",
                TrafficMode::Direct => "Local",
            }
        ));
    }
    Ok(explicit)
}

pub fn managed_service(service: &Service, class: &str) -> Result<Option<ManagedService>, String> {
    let Some(spec) = service.spec.as_ref() else {
        return Ok(None);
    };
    if spec.type_.as_deref() != Some("LoadBalancer")
        || spec.load_balancer_class.as_deref() != Some(class)
    {
        return Ok(None);
    }
    let key = ServiceKey::from_service(service)
        .ok_or_else(|| "managed Service must have a namespace".to_string())?;
    let mode = traffic_mode(service)?;
    let ingress_replicas = service
        .metadata
        .annotations
        .as_ref()
        .and_then(|values| values.get(INGRESS_REPLICAS_ANNOTATION))
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| format!("{INGRESS_REPLICAS_ANNOTATION} must be an integer"))
        })
        .transpose()?
        .unwrap_or(DEFAULT_INGRESS_REPLICAS);
    if !(1..=MAX_INGRESS_REPLICAS).contains(&ingress_replicas) {
        return Err(format!(
            "{INGRESS_REPLICAS_ANNOTATION} must be between 1 and {MAX_INGRESS_REPLICAS}"
        ));
    }
    let requested_ip = spec
        .load_balancer_ip
        .as_deref()
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|_| format!("loadBalancerIP {value} is not a valid IP address"))
        })
        .transpose()?;
    let mut ip_families = BTreeSet::new();
    for family in spec.ip_families.as_deref().unwrap_or_default() {
        match family.as_str() {
            "IPv4" => {
                ip_families.insert(IpFamily::Ipv4);
            }
            "IPv6" => {
                ip_families.insert(IpFamily::Ipv6);
            }
            other => return Err(format!("unsupported Service IP family {other}")),
        }
    }
    if ip_families.is_empty() {
        for cluster_ip in spec
            .cluster_ips
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(String::as_str)
            .chain(spec.cluster_ip.as_deref())
        {
            if let Ok(ip) = cluster_ip.parse::<IpAddr>() {
                ip_families.insert(IpFamily::of(ip));
            }
        }
    }
    if ip_families.is_empty() {
        ip_families.insert(IpFamily::Ipv4);
    }
    if requested_ip.is_some_and(|ip| !ip_families.contains(&IpFamily::of(ip))) {
        return Err("loadBalancerIP family must match a Service IP family".to_string());
    }
    let mut ports = Vec::new();
    let mut seen = BTreeSet::new();
    for service_port in spec.ports.as_deref().unwrap_or_default() {
        let port = u16::try_from(service_port.port)
            .map_err(|_| format!("Service port {} is out of range", service_port.port))?;
        if port == 0 {
            return Err("Service ports must be greater than zero".to_string());
        }
        let protocol = service_port
            .protocol
            .as_deref()
            .unwrap_or("TCP")
            .to_ascii_uppercase();
        if !matches!(protocol.as_str(), "TCP" | "UDP" | "SCTP") {
            return Err(format!("unsupported Service protocol {protocol}"));
        }
        let claim = PortClaim { protocol, port };
        if seen.insert(claim.clone()) {
            ports.push(claim);
        }
    }
    if ports.is_empty() {
        return Err("managed LoadBalancer Service must expose at least one port".to_string());
    }
    ports.sort();
    Ok(Some(ManagedService {
        key,
        creation_timestamp: service
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|value| value.0.to_string()),
        mode,
        ingress_replicas,
        requested_ip,
        ip_families,
        ports,
    }))
}

pub fn public_nodes(nodes: &[Node], ready_agent_nodes: &BTreeSet<String>) -> Vec<PublicNode> {
    let mut public = nodes
        .iter()
        .filter(|node| node_is_ready(node))
        .filter(|node| ready_agent_nodes.contains(&node.name_any()))
        .filter(|node| {
            node.metadata
                .labels
                .as_ref()
                .and_then(|values| values.get(PUBLIC_INGRESS_LABEL))
                .is_some_and(|value| value == "true")
        })
        .filter(|node| {
            node.metadata
                .annotations
                .as_ref()
                .and_then(|values| values.get(PUBLIC_INGRESS_ENABLED_ANNOTATION))
                .is_none_or(|value| value != "false")
        })
        .filter_map(|node| {
            let annotations = node.metadata.annotations.as_ref()?;
            let public_ip = annotations.get(PUBLIC_IP_ANNOTATION)?.parse().ok()?;
            let vpn_ip = annotations
                .get(VPN_IP_ANNOTATION)
                .and_then(|value| value.parse().ok());
            let node_id = annotations.get(NODE_ID_ANNOTATION).cloned();
            Some(PublicNode {
                name: node.name_any(),
                public_ip,
                vpn_ip,
                node_id,
            })
        })
        .collect::<Vec<_>>();
    public.sort_by(|left, right| {
        (left.public_ip, left.name.as_str()).cmp(&(right.public_ip, right.name.as_str()))
    });
    public.dedup_by_key(|node| node.public_ip);
    public
}

pub fn ready_agent_nodes(pods: &[Pod]) -> BTreeSet<String> {
    pods.iter()
        .filter(|pod| pod.metadata.deletion_timestamp.is_none())
        .filter(|pod| {
            pod.status
                .as_ref()
                .and_then(|status| status.conditions.as_ref())
                .is_some_and(|conditions| {
                    conditions
                        .iter()
                        .any(|condition| condition.type_ == "Ready" && condition.status == "True")
                })
        })
        .filter_map(|pod| pod.spec.as_ref()?.node_name.clone())
        .collect()
}

fn node_is_ready(node: &Node) -> bool {
    node.status
        .as_ref()
        .and_then(|status| status.conditions.as_ref())
        .is_some_and(|conditions| {
            conditions
                .iter()
                .any(|condition| condition.type_ == "Ready" && condition.status == "True")
        })
}

pub fn ready_endpoint_nodes(
    endpoint_slices: &[EndpointSlice],
) -> BTreeMap<ServiceKey, BTreeSet<String>> {
    let mut ready = BTreeMap::<ServiceKey, BTreeSet<String>>::new();
    let mut terminating_serving = BTreeMap::<ServiceKey, BTreeSet<String>>::new();
    for slice in endpoint_slices {
        let Some(namespace) = slice.namespace() else {
            continue;
        };
        let Some(service_name) = slice
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get("kubernetes.io/service-name"))
        else {
            continue;
        };
        let key = ServiceKey {
            namespace,
            name: service_name.clone(),
        };
        for endpoint in &slice.endpoints {
            let Some(node_name) = &endpoint.node_name else {
                continue;
            };
            let conditions = endpoint.conditions.as_ref();
            let is_terminating = conditions.and_then(|value| value.terminating) == Some(true);
            let is_ready = conditions.and_then(|value| value.ready) != Some(false);
            let is_serving = conditions.and_then(|value| value.serving) != Some(false);
            if !is_terminating && is_ready {
                ready
                    .entry(key.clone())
                    .or_default()
                    .insert(node_name.clone());
            } else if is_terminating && is_serving {
                terminating_serving
                    .entry(key.clone())
                    .or_default()
                    .insert(node_name.clone());
            }
        }
    }
    for (key, node_names) in terminating_serving {
        ready.entry(key).or_default().extend(node_names);
    }
    ready
}

pub fn plan_assignments(
    services: &[ManagedService],
    nodes: &[PublicNode],
    endpoint_nodes: &BTreeMap<ServiceKey, BTreeSet<String>>,
) -> Vec<ServiceAssignment> {
    let mut services = services.to_vec();
    services.sort_by(|left, right| {
        (left.creation_timestamp.as_deref().unwrap_or(""), &left.key).cmp(&(
            right.creation_timestamp.as_deref().unwrap_or(""),
            &right.key,
        ))
    });
    let mut used = BTreeMap::<(IpAddr, PortClaim), ServiceKey>::new();
    let mut assignments = Vec::with_capacity(services.len());
    let node_identities = nodes
        .iter()
        .map(|node| (node_identity_hash(node), node))
        .collect::<Vec<_>>();
    for service in services {
        let direct_nodes = endpoint_nodes.get(&service.key);
        let mut assigned = Vec::new();
        let service_hash = service_identity_hash(&service.key);
        let mut candidates = node_identities
            .iter()
            .map(|(node_hash, node)| (rendezvous_score(service_hash, *node_hash), *node))
            .collect::<Vec<_>>();
        candidates.sort_unstable_by(|(left_score, left), (right_score, right)| {
            right_score.cmp(left_score).then_with(|| {
                (left.public_ip, left.name.as_str()).cmp(&(right.public_ip, right.name.as_str()))
            })
        });
        for (_, node) in candidates {
            if !service.ip_families.contains(&IpFamily::of(node.public_ip)) {
                continue;
            }
            if service
                .requested_ip
                .is_some_and(|requested| requested != node.public_ip)
            {
                continue;
            }
            if service.mode == TrafficMode::Direct
                && !direct_nodes.is_some_and(|names| names.contains(&node.name))
            {
                continue;
            }
            let conflict = service.ports.iter().any(|port| {
                used.get(&(node.public_ip, port.clone()))
                    .is_some_and(|owner| owner != &service.key)
            });
            if conflict {
                continue;
            }
            for port in &service.ports {
                used.insert((node.public_ip, port.clone()), service.key.clone());
            }
            assigned.push(AssignedNode {
                name: node.name.clone(),
                public_ip: node.public_ip,
                vpn_ip: node.vpn_ip,
                node_id: node.node_id.clone(),
            });
            if assigned.len() >= service.ingress_replicas {
                break;
            }
        }
        let error = if assigned.is_empty() {
            Some(match service.mode {
                TrafficMode::Forwarded => {
                    "no healthy public node has all requested Service ports available".to_string()
                }
                TrafficMode::Direct => {
                    "no healthy public node with a local Ready endpoint has all requested Service ports available".to_string()
                }
            })
        } else if assigned.len() < service.ingress_replicas {
            Some(format!(
                "assigned {} of {} requested ingress nodes",
                assigned.len(),
                service.ingress_replicas
            ))
        } else {
            None
        };
        assignments.push(ServiceAssignment {
            key: service.key,
            nodes: assigned,
            error,
        });
    }
    assignments
}

fn stable_hash(domain: &[u8], values: &[&[u8]]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    fn update(hash: &mut u64, value: &[u8]) {
        for byte in (value.len() as u64).to_be_bytes().iter().chain(value) {
            *hash ^= u64::from(*byte);
            *hash = hash.wrapping_mul(FNV_PRIME);
        }
    }

    let mut hash = FNV_OFFSET;
    update(&mut hash, domain);
    for value in values {
        update(&mut hash, value);
    }
    hash
}

fn service_identity_hash(service: &ServiceKey) -> u64 {
    stable_hash(
        b"heteronetwork-kubernetes-service-v1",
        &[service.namespace.as_bytes(), service.name.as_bytes()],
    )
}

fn node_identity_hash(node: &PublicNode) -> u64 {
    let public_ip = node.public_ip.to_string();
    stable_hash(
        b"heteronetwork-kubernetes-public-node-v1",
        &[node.name.as_bytes(), public_ip.as_bytes()],
    )
}

fn rendezvous_score(service_hash: u64, node_hash: u64) -> u64 {
    let mut value = service_hash ^ node_hash.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

pub fn locally_owned_public_ip(
    candidates: &[EndpointCandidate],
    expected_node_id: &str,
    now: DateTime<Utc>,
    max_age_seconds: i64,
) -> Option<IpAddr> {
    let max_age = ChronoDuration::seconds(max_age_seconds.max(0));
    let future_skew = ChronoDuration::seconds(PUBLIC_CANDIDATE_FUTURE_SKEW_SECONDS);
    let mut candidates = candidates
        .iter()
        .filter(|candidate| candidate.node_id.as_str() == expected_node_id)
        .filter(|candidate| candidate.kind == EndpointCandidateKind::PublicUdp)
        .filter(|candidate| {
            matches!(
                candidate.source,
                CandidateSource::InterfaceScan | CandidateSource::StunProbe
            )
        })
        .filter(|candidate| ipars_types::socket_addr_is_globally_routable(candidate.addr))
        .filter(|candidate| {
            let age = now.signed_duration_since(candidate.observed_at);
            age >= -future_skew && age <= max_age
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| {
        (
            std::cmp::Reverse(candidate.priority),
            candidate.cost,
            candidate.addr.ip(),
        )
    });
    candidates.first().map(|candidate| candidate.addr.ip())
}

pub fn direct_pod_patch(pod: &Pod) -> Result<json_patch::Patch, String> {
    let mode = pod
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(TRAFFIC_MODE_KEY));
    if mode.map(String::as_str) != Some("direct") {
        return Ok(json_patch::Patch(Vec::new()));
    }
    let mut desired = pod.clone();
    let spec = desired
        .spec
        .as_mut()
        .ok_or_else(|| "direct Pod must include spec".to_string())?;
    let selector = spec.node_selector.get_or_insert_with(BTreeMap::new);
    if selector
        .get(PUBLIC_INGRESS_LABEL)
        .is_some_and(|value| value != "true")
    {
        return Err(format!(
            "direct Pod nodeSelector {PUBLIC_INGRESS_LABEL} must be true"
        ));
    }
    selector.insert(PUBLIC_INGRESS_LABEL.to_string(), "true".to_string());
    desired
        .metadata
        .annotations
        .get_or_insert_with(BTreeMap::new)
        .insert(
            PLACEMENT_INJECTED_ANNOTATION.to_string(),
            "true".to_string(),
        );
    let original = serde_json::to_value(pod)
        .map_err(|error| format!("failed to serialize admitted Pod: {error}"))?;
    let desired = serde_json::to_value(desired)
        .map_err(|error| format!("failed to serialize mutated Pod: {error}"))?;
    Ok(json_patch::diff(&original, &desired))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use ipars_types::{NodeId, VpnIp};
    use k8s_openapi::api::core::v1::{
        NodeCondition, NodeStatus, PodCondition, PodSpec, PodStatus, ServicePort, ServiceSpec,
    };
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    use super::*;

    fn public_node(name: &str, public_ip: &str) -> PublicNode {
        PublicNode {
            name: name.to_string(),
            public_ip: public_ip.parse().expect("test public IP"),
            vpn_ip: Some("10.250.0.2".parse().expect("test VPN IP")),
            node_id: Some(format!("node-{name}")),
        }
    }

    fn managed(key: &str, mode: TrafficMode, port: u16) -> ManagedService {
        ManagedService {
            key: ServiceKey {
                namespace: "default".to_string(),
                name: key.to_string(),
            },
            creation_timestamp: Some(format!("2026-01-01T00:00:0{port}Z")),
            mode,
            ingress_replicas: 2,
            requested_ip: None,
            ip_families: BTreeSet::from([IpFamily::Ipv4]),
            ports: vec![PortClaim {
                protocol: "UDP".to_string(),
                port,
            }],
        }
    }

    #[test]
    fn forwarded_assigns_public_nodes_without_local_endpoints() {
        let services = vec![managed("voice", TrafficMode::Forwarded, 7882)];
        let nodes = vec![
            public_node("public-a", "198.51.100.10"),
            public_node("public-b", "198.51.100.11"),
        ];
        let planned = plan_assignments(&services, &nodes, &BTreeMap::new());
        assert_eq!(planned[0].nodes.len(), 2);
        assert!(planned[0].error.is_none());
    }

    #[test]
    fn direct_only_assigns_nodes_with_ready_local_endpoints() {
        let services = vec![managed("game", TrafficMode::Direct, 7777)];
        let nodes = vec![
            public_node("public-a", "198.51.100.10"),
            public_node("public-b", "198.51.100.11"),
        ];
        let endpoint_nodes = BTreeMap::from([(
            services[0].key.clone(),
            BTreeSet::from(["public-b".to_string()]),
        )]);
        let planned = plan_assignments(&services, &nodes, &endpoint_nodes);
        assert_eq!(planned[0].nodes.len(), 1);
        assert_eq!(planned[0].nodes[0].name, "public-b");
    }

    #[test]
    fn conflicting_services_use_distinct_public_ips() {
        let mut first = managed("first", TrafficMode::Forwarded, 443);
        first.ingress_replicas = 1;
        let mut second = managed("second", TrafficMode::Forwarded, 443);
        second.ingress_replicas = 1;
        let nodes = vec![
            public_node("public-a", "198.51.100.10"),
            public_node("public-b", "198.51.100.11"),
        ];
        let planned = plan_assignments(&[first, second], &nodes, &BTreeMap::new());
        assert_ne!(planned[0].nodes[0].public_ip, planned[1].nodes[0].public_ip);
    }

    #[test]
    fn rendezvous_assignment_spreads_services_and_is_deterministic() {
        let services = (0..32)
            .map(|index| {
                let mut service = managed(
                    &format!("service-{index}"),
                    TrafficMode::Forwarded,
                    10_000 + index,
                );
                service.ingress_replicas = 1;
                service
            })
            .collect::<Vec<_>>();
        let nodes = vec![
            public_node("public-a", "198.51.100.10"),
            public_node("public-b", "198.51.100.11"),
        ];
        let first = plan_assignments(&services, &nodes, &BTreeMap::new());
        let second = plan_assignments(&services, &nodes, &BTreeMap::new());
        assert_eq!(first, second);
        assert_eq!(
            first
                .iter()
                .map(|assignment| assignment.nodes[0].name.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            2
        );
    }

    #[test]
    fn thousand_node_assignment_does_not_concentrate_on_fixed_gateways() {
        let services = (0..1_000_u16)
            .map(|index| {
                managed(
                    &format!("service-{index}"),
                    TrafficMode::Forwarded,
                    10_000 + index,
                )
            })
            .collect::<Vec<_>>();
        let nodes = (0..1_000_u16)
            .map(|index| {
                public_node(
                    &format!("node-{index:04}"),
                    &format!("11.{}.{}.1", index / 256, index % 256),
                )
            })
            .collect::<Vec<_>>();
        let planned = plan_assignments(&services, &nodes, &BTreeMap::new());
        assert!(planned
            .iter()
            .all(|assignment| { assignment.nodes.len() == 2 && assignment.error.is_none() }));
        let mut counts = BTreeMap::<&str, usize>::new();
        for assignment in &planned {
            for node in &assignment.nodes {
                *counts.entry(&node.name).or_default() += 1;
            }
        }
        assert!(counts.len() > 750);
        assert!(counts.values().copied().max().unwrap_or_default() < 20);
    }

    #[test]
    fn partial_assignment_reports_reduced_redundancy() {
        let services = vec![managed("voice", TrafficMode::Forwarded, 7882)];
        let nodes = vec![public_node("public-a", "198.51.100.10")];
        let planned = plan_assignments(&services, &nodes, &BTreeMap::new());
        assert_eq!(planned[0].nodes.len(), 1);
        assert_eq!(
            planned[0].error.as_deref(),
            Some("assigned 1 of 2 requested ingress nodes")
        );
    }

    #[test]
    fn service_ip_family_filters_public_nodes() {
        let services = vec![managed("voice", TrafficMode::Forwarded, 7882)];
        let nodes = vec![public_node("public-v6", "2001:4860:4860::8888")];
        let planned = plan_assignments(&services, &nodes, &BTreeMap::new());
        assert!(planned[0].nodes.is_empty());
    }

    #[test]
    fn direct_pod_patch_injects_public_node_selector() {
        let pod = Pod {
            metadata: ObjectMeta {
                labels: Some(BTreeMap::from([(
                    TRAFFIC_MODE_KEY.to_string(),
                    "direct".to_string(),
                )])),
                ..ObjectMeta::default()
            },
            spec: Some(PodSpec {
                containers: Vec::new(),
                ..PodSpec::default()
            }),
            status: None,
        };
        let patch = direct_pod_patch(&pod).expect("direct patch");
        let encoded = serde_json::to_string(&patch).expect("patch JSON");
        assert!(encoded.contains("public-ingress"));
        assert!(encoded.contains("placement-injected"));
    }

    #[test]
    fn service_mode_must_match_external_traffic_policy() {
        let service = Service {
            metadata: ObjectMeta {
                namespace: Some("default".to_string()),
                name: Some("test".to_string()),
                annotations: Some(BTreeMap::from([(
                    TRAFFIC_MODE_KEY.to_string(),
                    "direct".to_string(),
                )])),
                ..ObjectMeta::default()
            },
            spec: Some(ServiceSpec {
                type_: Some("LoadBalancer".to_string()),
                load_balancer_class: Some(LOAD_BALANCER_CLASS.to_string()),
                external_traffic_policy: Some("Cluster".to_string()),
                ports: Some(vec![ServicePort {
                    port: 443,
                    ..ServicePort::default()
                }]),
                ..ServiceSpec::default()
            }),
            status: None,
        };
        let error =
            managed_service(&service, LOAD_BALANCER_CLASS).expect_err("mode mismatch must fail");
        assert!(error.contains("requires externalTrafficPolicy Local"));
    }

    #[test]
    fn managed_service_requires_explicit_traffic_mode_annotation() {
        let service = Service {
            metadata: ObjectMeta {
                namespace: Some("default".to_string()),
                name: Some("test".to_string()),
                ..ObjectMeta::default()
            },
            spec: Some(ServiceSpec {
                type_: Some("LoadBalancer".to_string()),
                load_balancer_class: Some(LOAD_BALANCER_CLASS.to_string()),
                external_traffic_policy: Some("Cluster".to_string()),
                ports: Some(vec![ServicePort {
                    port: 443,
                    ..ServicePort::default()
                }]),
                ..ServiceSpec::default()
            }),
            status: None,
        };
        let error =
            managed_service(&service, LOAD_BALANCER_CLASS).expect_err("missing mode must fail");
        assert_eq!(error, format!("{TRAFFIC_MODE_KEY} annotation is required"));
    }

    #[test]
    fn direct_pod_annotation_without_label_is_not_mutated() {
        let pod = Pod {
            metadata: ObjectMeta {
                annotations: Some(BTreeMap::from([(
                    TRAFFIC_MODE_KEY.to_string(),
                    "direct".to_string(),
                )])),
                ..ObjectMeta::default()
            },
            spec: Some(PodSpec {
                containers: Vec::new(),
                ..PodSpec::default()
            }),
            status: None,
        };
        assert!(direct_pod_patch(&pod)
            .expect("non-matching Pod")
            .0
            .is_empty());
    }

    #[test]
    fn public_node_requires_ready_condition_and_plugin_label() {
        let node = Node {
            metadata: ObjectMeta {
                name: Some("public-a".to_string()),
                labels: Some(BTreeMap::from([(
                    PUBLIC_INGRESS_LABEL.to_string(),
                    "true".to_string(),
                )])),
                annotations: Some(BTreeMap::from([
                    (
                        PUBLIC_IP_ANNOTATION.to_string(),
                        "198.51.100.10".to_string(),
                    ),
                    (
                        VPN_IP_ANNOTATION.to_string(),
                        VpnIp("10.250.0.2".parse().expect("VPN IP")).to_string(),
                    ),
                    (
                        NODE_ID_ANNOTATION.to_string(),
                        NodeId::from_string("node-public-a").to_string(),
                    ),
                ])),
                ..ObjectMeta::default()
            },
            status: Some(NodeStatus {
                conditions: Some(vec![NodeCondition {
                    status: "True".to_string(),
                    type_: "Ready".to_string(),
                    ..NodeCondition::default()
                }]),
                ..NodeStatus::default()
            }),
            spec: None,
        };
        let selected = public_nodes(
            std::slice::from_ref(&node),
            &BTreeSet::from(["public-a".to_string()]),
        );
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].name, "public-a");

        assert!(public_nodes(std::slice::from_ref(&node), &BTreeSet::new()).is_empty());

        let mut disabled = node.clone();
        disabled
            .metadata
            .annotations
            .get_or_insert_default()
            .insert(
                PUBLIC_INGRESS_ENABLED_ANNOTATION.to_string(),
                "false".to_string(),
            );
        assert!(public_nodes(
            std::slice::from_ref(&disabled),
            &BTreeSet::from(["public-a".to_string()]),
        )
        .is_empty());

        let mut duplicate = node.clone();
        duplicate.metadata.name = Some("public-b".to_string());
        let selected = public_nodes(
            &[duplicate, node],
            &BTreeSet::from(["public-a".to_string(), "public-b".to_string()]),
        );
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].name, "public-a");
    }

    #[test]
    fn ready_agent_nodes_require_a_ready_non_terminating_pod() {
        let ready = Pod {
            metadata: ObjectMeta {
                name: Some("agent-a".to_string()),
                ..ObjectMeta::default()
            },
            spec: Some(PodSpec {
                node_name: Some("node-a".to_string()),
                containers: Vec::new(),
                ..PodSpec::default()
            }),
            status: Some(PodStatus {
                conditions: Some(vec![PodCondition {
                    status: "True".to_string(),
                    type_: "Ready".to_string(),
                    ..PodCondition::default()
                }]),
                ..PodStatus::default()
            }),
        };
        let mut unready = ready.clone();
        unready.metadata.name = Some("agent-b".to_string());
        unready.spec.as_mut().expect("spec").node_name = Some("node-b".to_string());
        unready
            .status
            .as_mut()
            .expect("status")
            .conditions
            .as_mut()
            .expect("conditions")[0]
            .status = "False".to_string();
        assert_eq!(
            ready_agent_nodes(&[ready, unready]),
            BTreeSet::from(["node-a".to_string()])
        );
    }

    #[test]
    fn public_candidate_must_be_fresh_and_owned_by_the_reported_node() {
        let now = Utc::now();
        let candidate = EndpointCandidate {
            node_id: NodeId::from_string("node-a"),
            kind: EndpointCandidateKind::PublicUdp,
            addr: "8.8.8.8:51820".parse().expect("candidate address"),
            observed_at: now - ChronoDuration::seconds(30),
            priority: 100,
            cost: 1,
            source: CandidateSource::InterfaceScan,
        };
        assert_eq!(
            locally_owned_public_ip(std::slice::from_ref(&candidate), "node-a", now, 180),
            Some("8.8.8.8".parse().expect("public IP"))
        );
        let mut no_nat = candidate.clone();
        no_nat.source = CandidateSource::StunProbe;
        assert_eq!(
            locally_owned_public_ip(std::slice::from_ref(&no_nat), "node-a", now, 180),
            Some("8.8.8.8".parse().expect("public IP"))
        );
        assert!(
            locally_owned_public_ip(std::slice::from_ref(&candidate), "node-b", now, 180).is_none()
        );
        let mut stale = candidate;
        stale.observed_at = now - ChronoDuration::seconds(181);
        assert!(locally_owned_public_ip(&[stale], "node-a", now, 180).is_none());
    }

    #[test]
    fn direct_mode_keeps_serving_terminating_endpoint_nodes() {
        let slice = EndpointSlice {
            address_type: "IPv4".to_string(),
            endpoints: vec![
                Endpoint {
                    addresses: vec!["10.244.0.10".to_string()],
                    conditions: Some(EndpointConditions {
                        ready: Some(true),
                        serving: Some(true),
                        terminating: Some(false),
                    }),
                    node_name: Some("node-ready".to_string()),
                    ..Endpoint::default()
                },
                Endpoint {
                    addresses: vec!["10.244.0.11".to_string()],
                    conditions: Some(EndpointConditions {
                        ready: Some(false),
                        serving: Some(true),
                        terminating: Some(true),
                    }),
                    node_name: Some("node-draining".to_string()),
                    ..Endpoint::default()
                },
                Endpoint {
                    addresses: vec!["10.244.0.12".to_string()],
                    conditions: Some(EndpointConditions {
                        ready: Some(false),
                        serving: Some(false),
                        terminating: Some(true),
                    }),
                    node_name: Some("node-stopped".to_string()),
                    ..Endpoint::default()
                },
            ],
            metadata: ObjectMeta {
                namespace: Some("default".to_string()),
                labels: Some(BTreeMap::from([(
                    "kubernetes.io/service-name".to_string(),
                    "game".to_string(),
                )])),
                ..ObjectMeta::default()
            },
            ports: None,
        };
        let nodes = ready_endpoint_nodes(&[slice]);
        assert_eq!(
            nodes[&ServiceKey {
                namespace: "default".to_string(),
                name: "game".to_string(),
            }],
            BTreeSet::from(["node-draining".to_string(), "node-ready".to_string()])
        );
    }
}
