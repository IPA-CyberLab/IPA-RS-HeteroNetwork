use std::fmt::Write;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipars_agent::{AgentError, AgentRuntime};
use ipars_types::api::{
    AgentMetricsResponse, AgentNatClassifyRequest, AgentNatClassifyResponse,
    AgentPacketFlowRequest, AgentPacketFlowResponse, AgentPathEventsResponse, AgentPathsResponse,
    AgentPeerActivityRequest, AgentPeerActivityResponse, AgentStatusResponse,
    AgentStunProbeRequest, AgentStunProbeResponse,
};
use ipars_types::PathState;
use serde::Serialize;

macro_rules! prometheus_line {
    ($body:expr, $($arg:tt)*) => {{
        let _ = writeln!($body, $($arg)*);
    }};
}

#[derive(Debug, Clone)]
pub struct AgentHttpState {
    runtime: Arc<AgentRuntime>,
}

impl AgentHttpState {
    pub fn new(runtime: Arc<AgentRuntime>) -> Self {
        Self { runtime }
    }
}

pub fn router(state: AgentHttpState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(prometheus_metrics))
        .route("/v1/status", get(status))
        .route("/v1/metrics", get(metrics))
        .route("/v1/paths", get(paths))
        .route("/v1/path-events", get(path_events))
        .route("/v1/stun-probe", post(stun_probe))
        .route("/v1/nat-classification", post(nat_classification))
        .route("/v1/peer-activity", post(peer_activity))
        .route("/v1/packet-flow", post(packet_flow))
        .with_state(state)
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn status(State(state): State<AgentHttpState>) -> Json<AgentStatusResponse> {
    Json(state.runtime.status().await)
}

async fn metrics(State(state): State<AgentHttpState>) -> Json<AgentMetricsResponse> {
    Json(state.runtime.metrics().await)
}

async fn prometheus_metrics(State(state): State<AgentHttpState>) -> impl IntoResponse {
    let metrics = state.runtime.metrics().await;
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render_prometheus_metrics(&metrics),
    )
}

async fn path_events(State(state): State<AgentHttpState>) -> Json<AgentPathEventsResponse> {
    Json(AgentPathEventsResponse {
        events: state.runtime.path_change_events().await,
        generated_at: chrono::Utc::now(),
    })
}

async fn paths(State(state): State<AgentHttpState>) -> Json<AgentPathsResponse> {
    Json(AgentPathsResponse {
        paths: state.runtime.path_state().await,
        generated_at: chrono::Utc::now(),
    })
}

async fn stun_probe(
    State(state): State<AgentHttpState>,
    Json(request): Json<AgentStunProbeRequest>,
) -> Result<(StatusCode, Json<AgentStunProbeResponse>), ApiError> {
    let candidate = state
        .runtime
        .probe_stun(request.local_bind, request.stun_server)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(AgentStunProbeResponse { candidate }),
    ))
}

async fn nat_classification(
    State(state): State<AgentHttpState>,
    Json(request): Json<AgentNatClassifyRequest>,
) -> Result<(StatusCode, Json<AgentNatClassifyResponse>), ApiError> {
    let classification = state
        .runtime
        .classify_nat(request.local_bind, request.stun_servers)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(AgentNatClassifyResponse { classification }),
    ))
}

async fn peer_activity(
    State(state): State<AgentHttpState>,
    Json(request): Json<AgentPeerActivityRequest>,
) -> Result<(StatusCode, Json<AgentPeerActivityResponse>), ApiError> {
    let recorded_at = chrono::Utc::now();
    let pinned = state
        .runtime
        .record_peer_activity(request.peer.clone(), recorded_at, request.pin)
        .await;
    Ok((
        StatusCode::ACCEPTED,
        Json(AgentPeerActivityResponse {
            peer: request.peer,
            recorded_at,
            pinned,
        }),
    ))
}

async fn packet_flow(
    State(state): State<AgentHttpState>,
    Json(request): Json<AgentPacketFlowRequest>,
) -> Result<(StatusCode, Json<AgentPacketFlowResponse>), ApiError> {
    let recorded_at = chrono::Utc::now();
    let matched = state
        .runtime
        .record_packet_flow_activity(request.destination, recorded_at, request.pin)
        .await;
    Ok((
        StatusCode::ACCEPTED,
        Json(AgentPacketFlowResponse {
            destination: request.destination,
            recorded_at,
            matched,
        }),
    ))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

fn render_prometheus_metrics(metrics: &AgentMetricsResponse) -> String {
    let node_id = prometheus_label(metrics.node_id.as_str());
    let mut body = String::new();
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_candidates Number of endpoint candidates currently known."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_candidates gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_candidates{{node_id=\"{node_id}\"}} {}",
        metrics.candidate_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_paths Number of peer paths currently tracked."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_paths gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_paths{{node_id=\"{node_id}\"}} {}",
        metrics.path_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_sessions Number of active relay sessions held by the agent."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_relay_sessions gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_relay_sessions{{node_id=\"{node_id}\"}} {}",
        metrics.relay_session_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarders Number of supervised relay forwarder endpoints."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_relay_forwarders gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_relay_forwarders{{node_id=\"{node_id}\"}} {}",
        metrics.relay_forwarder_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_packets_total Relay forwarder packets sent from local WireGuard to relay."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_packets_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_payload_bytes_total Relay forwarder opaque payload bytes sent from local WireGuard to relay."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_payload_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_outbound_datagram_bytes_total Relay forwarder framed datagram bytes sent to relay."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_outbound_datagram_bytes_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_inbound_packets_total Relay forwarder packets received from relay and sent to local WireGuard."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_inbound_packets_total counter"
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_relay_forwarder_inbound_payload_bytes_total Relay forwarder opaque payload bytes received from relay."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_relay_forwarder_inbound_payload_bytes_total counter"
    );
    for forwarder in &metrics.relay_forwarders {
        let peer = prometheus_label(forwarder.peer.as_str());
        let relay_node = prometheus_label(forwarder.relay_node.as_str());
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_packets_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_packets
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_payload_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_payload_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_outbound_datagram_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.outbound_datagram_bytes
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_inbound_packets_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.inbound_packets
        );
        prometheus_line!(
            &mut body,
            "ipars_agent_relay_forwarder_inbound_payload_bytes_total{{node_id=\"{node_id}\",peer=\"{peer}\",relay_node=\"{relay_node}\"}} {}",
            forwarder.inbound_payload_bytes
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_path_change_events Number of retained path change events."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_path_change_events gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_path_change_events{{node_id=\"{node_id}\"}} {}",
        metrics.path_change_event_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_active_peers Number of peers with recent lazy-connect activity."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_active_peers gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_active_peers{{node_id=\"{node_id}\"}} {}",
        metrics.lazy_connect.active_peer_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_pinned_peers Number of peers pinned in lazy-connect state."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_pinned_peers gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_pinned_peers{{node_id=\"{node_id}\"}} {}",
        metrics.lazy_connect.pinned_peer_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_observed_peer_vpn_ips Number of peer VPN IPs indexed for packet-flow resolution."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_observed_peer_vpn_ips gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_observed_peer_vpn_ips{{node_id=\"{node_id}\"}} {}",
        metrics.lazy_connect.observed_peer_vpn_ip_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_observed_route_peers Number of peers with advertised routes indexed for packet-flow resolution."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_observed_route_peers gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_observed_route_peers{{node_id=\"{node_id}\"}} {}",
        metrics.lazy_connect.observed_route_peer_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_observed_routes Number of advertised routes indexed for packet-flow resolution."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_observed_routes gauge");
    prometheus_line!(
        &mut body,
        "ipars_agent_observed_routes{{node_id=\"{node_id}\"}} {}",
        metrics.lazy_connect.observed_route_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_peer_activity_records_total Peer activity records accepted by the agent."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_peer_activity_records_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_peer_activity_records_total{{node_id=\"{node_id}\"}} {}",
        metrics.peer_activity_record_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_packet_flow_observations_total Packet-flow observations submitted to lazy-connect resolution."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_packet_flow_observations_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_packet_flow_observations_total{{node_id=\"{node_id}\"}} {}",
        metrics.packet_flow_observation_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_packet_flow_matches_total Packet-flow observations that resolved to a peer."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_packet_flow_matches_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_packet_flow_matches_total{{node_id=\"{node_id}\"}} {}",
        metrics.packet_flow_match_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_packet_flow_unmatched_total Packet-flow observations that did not resolve to a peer."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_agent_packet_flow_unmatched_total counter"
    );
    prometheus_line!(
        &mut body,
        "ipars_agent_packet_flow_unmatched_total{{node_id=\"{node_id}\"}} {}",
        metrics.packet_flow_unmatched_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_agent_path_state_count Number of peer paths by selected state."
    );
    prometheus_line!(&mut body, "# TYPE ipars_agent_path_state_count gauge");
    for state_count in &metrics.path_state_counts {
        prometheus_line!(
            &mut body,
            "ipars_agent_path_state_count{{node_id=\"{node_id}\",state=\"{}\"}} {}",
            path_state_label(state_count.state),
            state_count.count
        );
    }
    body
}

fn path_state_label(state: PathState) -> &'static str {
    match state {
        PathState::DirectPublic => "DIRECT_PUBLIC",
        PathState::DirectIpv6 => "DIRECT_IPV6",
        PathState::DirectNatTraversal => "DIRECT_NAT_TRAVERSAL",
        PathState::Relay => "RELAY",
        PathState::Unreachable => "UNREACHABLE",
    }
}

fn prometheus_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[derive(Debug)]
pub struct ApiError(AgentError);

impl From<AgentError> for ApiError {
    fn from(error: AgentError) -> Self {
        Self(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            AgentError::Io(_)
            | AgentError::Json(_)
            | AgentError::Crypto(_)
            | AgentError::Stun(_)
            | AgentError::RouteManager(_)
            | AgentError::RoutePlanning(_)
            | AgentError::ControlPlaneClient(_)
            | AgentError::HolePunch(_)
            | AgentError::RelaySession(_)
            | AgentError::WireGuard(_) => StatusCode::SERVICE_UNAVAILABLE,
            AgentError::MissingPeer(_) => StatusCode::NOT_FOUND,
        };
        (
            status,
            Json(ErrorResponse {
                error: self.0.to_string(),
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{header, Request};
    use chrono::Utc;
    use ipars_agent::{AgentNodeState, AgentRuntime, RelayForwarderStats};
    use ipars_types::api::AgentPacketFlowMatchKind;
    use ipars_types::{
        ClusterId, ClusterPolicy, NodeId, NodeRecord, PathRecord, PathScore, PathState,
        PeerPathKey, Role, Route, TokenPolicy, VpnIp,
    };
    use tower::ServiceExt;

    use super::*;

    fn peer_record(node_id: NodeId, vpn_ip: IpAddr, routes: Vec<Route>) -> NodeRecord {
        NodeRecord {
            node_id,
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(vpn_ip),
            identity_public_key: "identity-public".to_string(),
            wireguard_public_key: "wireguard-public".to_string(),
            role: Role::edge(),
            tags: BTreeSet::new(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes,
            registered_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn http_agent_status_returns_node_keys() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let node_id = runtime.state().node_id.clone();
        let app = router(AgentHttpState::new(runtime));

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/status")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let status: AgentStatusResponse = serde_json::from_slice(&body)?;
        assert_eq!(status.node_id, node_id);
        assert_eq!(status.candidate_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_exports_metrics_and_path_events() -> Result<(), Box<dyn std::error::Error>>
    {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let node_id = runtime.state().node_id.clone();
        runtime
            .upsert_path_state(PathRecord {
                key: PeerPathKey::new(node_id.clone(), NodeId::from_string("peer-a")),
                selected_state: PathState::Relay,
                selected_candidate: None,
                relay_node: Some(NodeId::from_string("relay-a")),
                score: PathScore {
                    value: 70.0,
                    reasons: vec!["state=Relay".to_string()],
                },
                updated_at: Utc::now(),
                pinned: false,
            })
            .await;
        let forwarder_metrics = Arc::new(RelayForwarderStats::new(
            NodeId::from_string("peer-a"),
            NodeId::from_string("relay-a"),
            std::net::SocketAddr::from(([127, 0, 0, 1], 51820)),
            std::net::SocketAddr::from(([127, 0, 0, 1], 52000)),
        ));
        forwarder_metrics.record_outbound(64, 128);
        forwarder_metrics.record_inbound(32);
        runtime
            .upsert_relay_forwarder_endpoint(
                NodeId::from_string("peer-a"),
                std::net::SocketAddr::from(([127, 0, 0, 1], 52000)),
            )
            .await;
        runtime
            .register_relay_forwarder_metrics(forwarder_metrics)
            .await;
        runtime
            .record_peer_activity(NodeId::from_string("peer-a"), Utc::now(), true)
            .await;
        runtime
            .record_packet_flow_activity(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                Utc::now(),
                false,
            )
            .await;
        let app = router(AgentHttpState::new(runtime));

        let metrics_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/metrics")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(metrics_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(metrics_response.into_body(), usize::MAX).await?;
        let metrics: AgentMetricsResponse = serde_json::from_slice(&body)?;
        assert_eq!(metrics.node_id, node_id);
        assert_eq!(metrics.path_count, 1);
        assert_eq!(metrics.relay_forwarder_count, 1);
        assert_eq!(metrics.path_change_event_count, 1);
        assert_eq!(metrics.relay_forwarders.len(), 1);
        assert_eq!(metrics.relay_forwarders[0].outbound_packets, 1);
        assert_eq!(metrics.relay_forwarders[0].outbound_payload_bytes, 64);
        assert_eq!(metrics.relay_forwarders[0].outbound_datagram_bytes, 128);
        assert_eq!(metrics.relay_forwarders[0].inbound_packets, 1);
        assert_eq!(metrics.relay_forwarders[0].inbound_payload_bytes, 32);
        assert_eq!(metrics.lazy_connect.active_peer_count, 1);
        assert_eq!(metrics.lazy_connect.pinned_peer_count, 1);
        assert_eq!(metrics.peer_activity_record_count, 1);
        assert_eq!(metrics.packet_flow_observation_count, 1);
        assert_eq!(metrics.packet_flow_match_count, 0);
        assert_eq!(metrics.packet_flow_unmatched_count, 1);

        let prometheus_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(prometheus_response.status(), StatusCode::OK);
        assert_eq!(
            prometheus_response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static(
                "text/plain; version=0.0.4; charset=utf-8"
            ))
        );
        let body = axum::body::to_bytes(prometheus_response.into_body(), usize::MAX).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("ipars_agent_paths"));
        assert!(body.contains("state=\"RELAY\""));
        assert!(body.contains("ipars_agent_relay_forwarder_outbound_packets_total"));
        assert!(body.contains("peer=\"peer-a\""));
        assert!(body.contains("relay_node=\"relay-a\""));
        assert!(body.contains("peer=\"peer-a\",relay_node=\"relay-a\"} 64"));
        assert!(body.contains("peer=\"peer-a\",relay_node=\"relay-a\"} 32"));
        assert!(body.contains("ipars_agent_active_peers"));
        assert!(body.contains("ipars_agent_pinned_peers"));
        assert!(body.contains("ipars_agent_peer_activity_records_total"));
        assert!(body.contains("ipars_agent_packet_flow_observations_total"));
        assert!(body.contains("ipars_agent_packet_flow_unmatched_total"));

        let paths_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/paths")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(paths_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(paths_response.into_body(), usize::MAX).await?;
        let paths: AgentPathsResponse = serde_json::from_slice(&body)?;
        assert_eq!(paths.paths.len(), 1);
        assert_eq!(paths.paths[0].selected_state, PathState::Relay);

        let events_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/path-events")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(events_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(events_response.into_body(), usize::MAX).await?;
        let events: AgentPathEventsResponse = serde_json::from_slice(&body)?;
        assert_eq!(events.events.len(), 1);
        assert_eq!(events.events[0].new_state, PathState::Relay);
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_records_peer_activity_for_lazy_connect(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let peer = NodeId::from_string("peer-active");
        let app = router(AgentHttpState::new(runtime.clone()));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/peer-activity")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&AgentPeerActivityRequest {
                        peer: peer.clone(),
                        pin: true,
                    })?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let activity: AgentPeerActivityResponse = serde_json::from_slice(&body)?;
        assert_eq!(activity.peer, peer);
        assert!(activity.pinned);
        assert!(runtime.idle_peers_to_close(Utc::now()).await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn http_agent_records_packet_flow_for_lazy_connect(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Arc::new(AgentRuntime::new(
            AgentNodeState::generate(Utc::now()),
            ClusterPolicy::default(),
        ));
        let peer = NodeId::from_string("peer-route");
        let route = "10.44.0.0/16".parse()?;
        let peer_record = peer_record(
            peer.clone(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 44)),
            vec![Route {
                id: "peer-route-cidr".to_string(),
                cidr: route,
                advertised_by: peer.clone(),
                via: None,
                metric: 10,
                tags: BTreeSet::new(),
            }],
        );
        runtime
            .observe_peer_map_for_lazy_connect(std::slice::from_ref(&peer_record))
            .await;
        let app = router(AgentHttpState::new(runtime.clone()));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/packet-flow")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&AgentPacketFlowRequest {
                        destination: IpAddr::V4(Ipv4Addr::new(10, 44, 3, 10)),
                        pin: true,
                    })?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let packet_flow: AgentPacketFlowResponse = serde_json::from_slice(&body)?;
        let matched = packet_flow
            .matched
            .ok_or_else(|| std::io::Error::other("route should match peer"))?;
        assert_eq!(matched.peer, peer);
        assert_eq!(matched.kind, AgentPacketFlowMatchKind::AdvertisedRoute);
        assert_eq!(matched.route, Some(route));
        assert!(matched.pinned);
        assert!(runtime.should_connect_peer(&peer_record).await);
        Ok(())
    }
}
