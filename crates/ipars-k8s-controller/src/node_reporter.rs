use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use axum::extract::State;
use axum::http::StatusCode;
use axum::{routing::get, Router};
use chrono::Utc;
use ipars_agent::FileAgentStateStore;
use ipars_k8s_controller::{
    locally_owned_public_ip, MANAGED_EXTERNAL_IP_ANNOTATION, NODE_ID_ANNOTATION,
    PUBLIC_INGRESS_ENABLED_ANNOTATION, PUBLIC_INGRESS_LABEL, PUBLIC_IP_ANNOTATION,
    VPN_IP_ANNOTATION,
};
use ipars_types::api::AgentStatusResponse;
use ipars_types::EndpointCandidate;
use k8s_openapi::api::core::v1::{Node, NodeAddress};
use kube::api::{Api, Patch as KubePatch, PatchParams};
use kube::Client;
use serde_json::json;

use crate::NodeReporterArgs;

#[derive(Debug)]
struct AgentSnapshot {
    node_id: String,
    vpn_ip: Option<IpAddr>,
    candidates: Vec<EndpointCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesiredNodeState {
    node_id: String,
    vpn_ip: Option<IpAddr>,
    public_ip: Option<IpAddr>,
    managed_external_ip: Option<IpAddr>,
}

#[derive(Clone)]
struct HealthState {
    last_success: Arc<AtomicI64>,
    max_age_seconds: i64,
}

pub async fn run(args: NodeReporterArgs) -> anyhow::Result<()> {
    let client = Client::try_default()
        .await
        .context("failed to initialize Kubernetes client")?;
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()
        .context("failed to initialize Agent status client")?;
    let mut interval = tokio::time::interval(Duration::from_secs(args.reconcile_interval_seconds));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let health_state = HealthState {
        last_success: Arc::new(AtomicI64::new(0)),
        max_age_seconds: i64::try_from(args.reconcile_interval_seconds.saturating_mul(3).max(30))
            .unwrap_or(i64::MAX),
    };
    let health_listener = tokio::net::TcpListener::bind(args.health_bind)
        .await
        .with_context(|| {
            format!(
                "failed to bind node reporter health server {}",
                args.health_bind
            )
        })?;
    let health_router = Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/readyz", get(ready))
        .with_state(health_state.clone());
    let mut health_task =
        tokio::spawn(async move { axum::serve(health_listener, health_router).await });
    let shutdown = crate::shutdown_signal();
    tokio::pin!(shutdown);
    let mut last_applied = None;
    let full_reconcile_interval = Duration::from_secs(args.full_reconcile_interval_seconds);
    let full_reconcile_phase = reconcile_phase(&args.node_name, full_reconcile_interval);
    let mut next_full_reconcile = None;

    tracing::info!(
        node = %args.node_name,
        health_bind = %args.health_bind,
        "Kubernetes node reporter started"
    );
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now = std::time::Instant::now();
                let force = next_full_reconcile.is_none_or(|next| now >= next);
                match reconcile_once(
                    client.clone(),
                    &http,
                    &args,
                    &mut last_applied,
                    force,
                ).await {
                    Ok(true) => {
                        health_state
                            .last_success
                            .store(unix_timestamp(), Ordering::Release);
                        if force {
                            next_full_reconcile = Some(next_reconcile_deadline(
                                next_full_reconcile,
                                now,
                                full_reconcile_interval,
                                full_reconcile_phase,
                            ));
                        }
                    }
                    Ok(false) => {
                        health_state.last_success.store(0, Ordering::Release);
                        if force {
                            next_full_reconcile = Some(next_reconcile_deadline(
                                next_full_reconcile,
                                now,
                                full_reconcile_interval,
                                full_reconcile_phase,
                            ));
                        }
                    }
                    Err(error) => {
                        health_state.last_success.store(0, Ordering::Release);
                        tracing::error!(node = %args.node_name, error = %error, "node reporting failed");
                    }
                }
            }
            result = &mut health_task => {
                return result
                    .context("node reporter health task failed")?
                    .context("node reporter health server failed");
            }
            signal = &mut shutdown => {
                signal?;
                health_task.abort();
                let _ = health_task.await;
                return Ok(());
            }
        }
    }
}

async fn ready(State(state): State<HealthState>) -> StatusCode {
    let last_success = state.last_success.load(Ordering::Acquire);
    if last_success > 0 && unix_timestamp().saturating_sub(last_success) <= state.max_age_seconds {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}

fn reconcile_phase(node_name: &str, interval: Duration) -> Duration {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let interval_millis = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
    if interval_millis <= 1 {
        return interval;
    }
    let hash = node_name.bytes().fold(FNV_OFFSET, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
    });
    Duration::from_millis((hash % interval_millis).max(1))
}

fn next_reconcile_deadline(
    previous: Option<std::time::Instant>,
    now: std::time::Instant,
    interval: Duration,
    initial_phase: Duration,
) -> std::time::Instant {
    let Some(mut next) = previous else {
        return now + initial_phase;
    };
    while next <= now {
        next += interval;
    }
    next
}

async fn reconcile_once(
    client: Client,
    http: &reqwest::Client,
    args: &NodeReporterArgs,
    last_applied: &mut Option<DesiredNodeState>,
    force: bool,
) -> anyhow::Result<bool> {
    let (snapshot, agent_status_fresh) = match snapshot_from_agent(http, args).await {
        Ok(snapshot) => (snapshot, true),
        Err(error) => {
            tracing::warn!(
                error = %error,
                path = %args.agent_state_path.display(),
                "Agent status API unavailable; using persisted Agent state"
            );
            (snapshot_from_state(args)?, false)
        }
    };
    let public_ip = locally_owned_public_ip(
        &snapshot.candidates,
        &snapshot.node_id,
        Utc::now(),
        args.public_candidate_max_age_seconds,
    );
    let managed_external_ip = args.publish_node_external_ip.then_some(public_ip).flatten();
    let desired = DesiredNodeState {
        node_id: snapshot.node_id.clone(),
        vpn_ip: snapshot.vpn_ip,
        public_ip,
        managed_external_ip,
    };
    if !force && last_applied.as_ref() == Some(&desired) {
        return Ok(agent_status_fresh);
    }
    let api: Api<Node> = Api::all(client);
    let current = api
        .get(&args.node_name)
        .await
        .with_context(|| format!("failed to get Kubernetes Node {}", args.node_name))?;
    let old_managed_ip = current
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(MANAGED_EXTERNAL_IP_ANNOTATION))
        .and_then(|value| value.parse::<IpAddr>().ok());
    patch_addresses(
        &api,
        &args.node_name,
        &current,
        old_managed_ip,
        managed_external_ip,
    )
    .await?;
    *last_applied = Some(desired);
    patch_metadata(
        &api,
        &args.node_name,
        &snapshot,
        public_ip,
        managed_external_ip,
        &current,
    )
    .await?;

    tracing::debug!(
        node = %args.node_name,
        public_ip = ?public_ip,
        vpn_ip = ?snapshot.vpn_ip,
        "Kubernetes Node metadata reconciled"
    );
    Ok(agent_status_fresh)
}

async fn snapshot_from_agent(
    http: &reqwest::Client,
    args: &NodeReporterArgs,
) -> anyhow::Result<AgentSnapshot> {
    let mut request = http.get(&args.agent_status_url);
    if let Some(token) = args.agent_api_bearer_token.as_deref() {
        request = request.bearer_auth(token);
    }
    let status = request
        .send()
        .await
        .context("failed to request local Agent status")?
        .error_for_status()
        .context("local Agent status returned an error")?
        .json::<AgentStatusResponse>()
        .await
        .context("failed to decode local Agent status")?;
    Ok(AgentSnapshot {
        node_id: status.node_id.to_string(),
        vpn_ip: status.vpn_ip.map(|value| value.0),
        candidates: status.candidates,
    })
}

fn snapshot_from_state(args: &NodeReporterArgs) -> anyhow::Result<AgentSnapshot> {
    let state = FileAgentStateStore::new(&args.agent_state_path)
        .load()
        .with_context(|| {
            format!(
                "failed to load Agent state {}",
                args.agent_state_path.display()
            )
        })?;
    Ok(AgentSnapshot {
        node_id: state.node_id.to_string(),
        vpn_ip: state.vpn_ip.map(|value| value.0),
        // Persisted candidates can outlive an interface or public route. Keep
        // identity fallback, but fail closed for public ingress eligibility.
        candidates: Vec::new(),
    })
}

async fn patch_metadata(
    api: &Api<Node>,
    name: &str,
    snapshot: &AgentSnapshot,
    public_ip: Option<IpAddr>,
    managed_external_ip: Option<IpAddr>,
    current: &Node,
) -> anyhow::Result<()> {
    let public_ip = public_ip.map(|value| value.to_string());
    let managed_external_ip = managed_external_ip.map(|value| value.to_string());
    let vpn_ip = snapshot.vpn_ip.map(|value| value.to_string());
    let public_ingress_enabled = current
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(PUBLIC_INGRESS_ENABLED_ANNOTATION))
        .is_none_or(|value| value != "false");
    let desired_public_label = if public_ip.is_some() && public_ingress_enabled {
        "true"
    } else {
        "false"
    };
    if current
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(PUBLIC_INGRESS_LABEL))
        .is_some_and(|value| value == desired_public_label)
        && annotation_matches(current, NODE_ID_ANNOTATION, Some(&snapshot.node_id))
        && annotation_matches(current, VPN_IP_ANNOTATION, vpn_ip.as_ref())
        && annotation_matches(current, PUBLIC_IP_ANNOTATION, public_ip.as_ref())
        && annotation_matches(
            current,
            MANAGED_EXTERNAL_IP_ANNOTATION,
            managed_external_ip.as_ref(),
        )
    {
        return Ok(());
    }
    let patch = json!({
        "metadata": {
            "labels": {
                PUBLIC_INGRESS_LABEL: desired_public_label,
            },
            "annotations": {
                NODE_ID_ANNOTATION: snapshot.node_id,
                VPN_IP_ANNOTATION: vpn_ip,
                PUBLIC_IP_ANNOTATION: public_ip,
                MANAGED_EXTERNAL_IP_ANNOTATION: managed_external_ip,
            }
        }
    });
    api.patch(name, &PatchParams::default(), &KubePatch::Merge(&patch))
        .await
        .with_context(|| format!("failed to patch Kubernetes Node {name} metadata"))?;
    Ok(())
}

fn annotation_matches(node: &Node, key: &str, desired: Option<&String>) -> bool {
    node.metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(key))
        == desired
}

async fn patch_addresses(
    api: &Api<Node>,
    name: &str,
    current: &Node,
    old_managed_ip: Option<IpAddr>,
    desired_managed_ip: Option<IpAddr>,
) -> anyhow::Result<()> {
    let current_addresses = current
        .status
        .as_ref()
        .and_then(|status| status.addresses.as_ref())
        .cloned()
        .unwrap_or_default();
    let desired_addresses =
        desired_node_addresses(&current_addresses, old_managed_ip, desired_managed_ip);
    if current_addresses == desired_addresses {
        return Ok(());
    }
    let resource_version = current
        .metadata
        .resource_version
        .as_ref()
        .context("Kubernetes Node has no resourceVersion")?;
    let patch = serde_json::from_value::<json_patch::Patch>(json!([
        {
            "op": "test",
            "path": "/metadata/resourceVersion",
            "value": resource_version,
        },
        {
            "op": "add",
            "path": "/status/addresses",
            "value": desired_addresses,
        }
    ]))
    .context("failed to encode Kubernetes Node status patch")?;
    api.patch_status(name, &PatchParams::default(), &KubePatch::<()>::Json(patch))
        .await
        .with_context(|| format!("failed to patch Kubernetes Node {name} addresses"))?;
    Ok(())
}

fn desired_node_addresses(
    current_addresses: &[NodeAddress],
    old_managed_ip: Option<IpAddr>,
    desired_managed_ip: Option<IpAddr>,
) -> Vec<NodeAddress> {
    let mut desired_addresses = current_addresses
        .iter()
        .filter(|address| {
            !(address.type_ == "ExternalIP"
                && old_managed_ip.is_some_and(|ip| address.address == ip.to_string()))
        })
        .cloned()
        .collect::<Vec<_>>();
    if let Some(ip) = desired_managed_ip {
        let address = ip.to_string();
        if !desired_addresses
            .iter()
            .any(|entry| entry.type_ == "ExternalIP" && entry.address == address)
        {
            desired_addresses.push(NodeAddress {
                address,
                type_: "ExternalIP".to_string(),
            });
        }
    }
    desired_addresses
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn full_reconcile_phase_is_stable_and_spreads_nodes() {
        let interval = Duration::from_secs(300);
        assert_eq!(
            reconcile_phase("node-a", interval),
            reconcile_phase("node-a", interval)
        );
        let phases = (0..100)
            .map(|index| reconcile_phase(&format!("node-{index}"), interval))
            .collect::<std::collections::BTreeSet<_>>();
        assert!(phases.len() > 90);
        assert!(phases
            .iter()
            .all(|phase| *phase > Duration::ZERO && *phase < interval));
    }

    #[test]
    fn full_reconcile_deadline_advances_from_previous_phase() {
        let now = std::time::Instant::now();
        let interval = Duration::from_secs(300);
        let phase = Duration::from_secs(17);
        let first = next_reconcile_deadline(None, now, interval, phase);
        assert_eq!(first, now + phase);
        assert_eq!(
            next_reconcile_deadline(Some(first), first, interval, phase),
            first + interval
        );
    }

    #[test]
    fn address_update_preserves_unmanaged_external_addresses() {
        let current = vec![
            NodeAddress {
                type_: "InternalIP".to_string(),
                address: "10.0.0.1".to_string(),
            },
            NodeAddress {
                type_: "ExternalIP".to_string(),
                address: "203.0.113.10".to_string(),
            },
            NodeAddress {
                type_: "ExternalIP".to_string(),
                address: "198.51.100.10".to_string(),
            },
        ];
        let addresses = desired_node_addresses(
            &current,
            Some("198.51.100.10".parse().expect("old IP")),
            Some("198.51.100.11".parse().expect("new IP")),
        );
        assert!(addresses
            .iter()
            .any(|value| value.address == "203.0.113.10"));
        assert!(!addresses
            .iter()
            .any(|value| value.address == "198.51.100.10"));
        assert!(addresses
            .iter()
            .any(|value| value.address == "198.51.100.11"));
    }
}
