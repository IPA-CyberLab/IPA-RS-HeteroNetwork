use std::fmt::Write;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::Utc;
use ipars_control_plane::{
    ControlPlane, ControlPlaneError, ControlPlaneJoinService, ControlPlaneStore, TokenLedger,
};
use ipars_types::api::{
    ControlPlaneMetricsResponse, ControlPlanePolicyResponse, HeartbeatRequest, HeartbeatResponse,
    JoinNodeRequest, PeerMap, RegisterNodeResponse, RevokeTokenRequest, RevokeTokenResponse,
    RotateWireGuardKeyRequest, RotateWireGuardKeyResponse,
};
use ipars_types::{NodeId, PathState, TokenLedgerMetrics};
use serde::Serialize;

macro_rules! prometheus_line {
    ($body:expr, $($arg:tt)*) => {{
        let _ = writeln!($body, $($arg)*);
    }};
}

#[derive(Debug)]
pub struct ControlPlaneHttpState<S, L> {
    plane: Arc<ControlPlane<S>>,
    join_service: Arc<ControlPlaneJoinService<S, L>>,
}

impl<S, L> Clone for ControlPlaneHttpState<S, L> {
    fn clone(&self) -> Self {
        Self {
            plane: self.plane.clone(),
            join_service: self.join_service.clone(),
        }
    }
}

impl<S, L> ControlPlaneHttpState<S, L> {
    pub fn new(
        plane: Arc<ControlPlane<S>>,
        join_service: Arc<ControlPlaneJoinService<S, L>>,
    ) -> Self {
        Self {
            plane,
            join_service,
        }
    }
}

pub fn router<S, L>(state: ControlPlaneHttpState<S, L>) -> Router
where
    S: ControlPlaneStore + 'static,
    L: TokenLedger + 'static,
{
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(prometheus_metrics::<S, L>))
        .route("/v1/join", post(join::<S, L>))
        .route("/v1/heartbeat", post(heartbeat::<S, L>))
        .route("/v1/metrics", get(metrics::<S, L>))
        .route("/v1/policy", get(policy::<S, L>))
        .route("/v1/peers/{node_id}", get(peers::<S, L>))
        .route(
            "/v1/nodes/{node_id}/wireguard-key",
            put(rotate_wireguard_key::<S, L>),
        )
        .route("/v1/tokens/revoke", post(revoke_token::<S, L>))
        .with_state(state)
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn metrics<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
) -> Result<Json<ControlPlaneMetricsResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    Ok(Json(control_plane_metrics(&state).await?))
}

async fn policy<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
) -> Json<ControlPlanePolicyResponse>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let config = state.plane.config();
    Json(ControlPlanePolicyResponse {
        cluster_id: config.cluster_id.clone(),
        vpn_pool: config.vpn_pool,
        cluster_policy: config.cluster_policy.clone(),
        generated_at: Utc::now(),
    })
}

async fn prometheus_metrics<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
) -> Result<impl IntoResponse, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let metrics = control_plane_metrics(&state).await?;
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render_prometheus_metrics(&metrics),
    ))
}

async fn control_plane_metrics<S, L>(
    state: &ControlPlaneHttpState<S, L>,
) -> Result<ControlPlaneMetricsResponse, ControlPlaneError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let mut metrics = state.plane.metrics().await?;
    let token_metrics = state
        .join_service
        .token_metrics(&metrics.cluster_id, Utc::now())
        .await?;
    apply_token_ledger_metrics(&mut metrics, token_metrics);
    Ok(metrics)
}

fn apply_token_ledger_metrics(
    metrics: &mut ControlPlaneMetricsResponse,
    token_metrics: TokenLedgerMetrics,
) {
    metrics.token_ledger_issued_count = token_metrics.issued_count;
    metrics.token_ledger_active_count = token_metrics.active_count;
    metrics.token_ledger_revoked_count = token_metrics.revoked_count;
    metrics.token_ledger_expired_count = token_metrics.expired_count;
    metrics.token_ledger_exhausted_count = token_metrics.exhausted_count;
    metrics.token_ledger_use_count = token_metrics.use_count;
}

async fn join<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<JoinNodeRequest>,
) -> Result<(StatusCode, Json<RegisterNodeResponse>), ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let response = state
        .join_service
        .join(request.token, request.registration, Utc::now())
        .await?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn revoke_token<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<RevokeTokenRequest>,
) -> Result<Json<RevokeTokenResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let record = state
        .join_service
        .revoke_token(&request.cluster_id, &request.nonce, Utc::now())
        .await?;
    let status = record.status(Utc::now());
    Ok(Json(RevokeTokenResponse { record, status }))
}

async fn peers<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Path(node_id): Path<String>,
) -> Result<Json<PeerMap>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let node_id = NodeId::from_string(node_id);
    let response = state.plane.peer_map_for(&node_id).await?;
    Ok(Json(response))
}

async fn heartbeat<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Json(request): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    Ok(Json(state.plane.heartbeat(request).await?))
}

async fn rotate_wireguard_key<S, L>(
    State(state): State<ControlPlaneHttpState<S, L>>,
    Path(node_id): Path<String>,
    Json(request): Json<RotateWireGuardKeyRequest>,
) -> Result<Json<RotateWireGuardKeyResponse>, ApiError>
where
    S: ControlPlaneStore,
    L: TokenLedger,
{
    let path_node_id = NodeId::from_string(node_id);
    if request.node_id != path_node_id {
        return Err(ControlPlaneError::NodeUpdateRejected {
            node_id: request.node_id.clone(),
            reason: format!(
                "path node ID {path_node_id} does not match request node ID {}",
                request.node_id
            ),
        }
        .into());
    }
    Ok(Json(state.plane.rotate_wireguard_key(request).await?))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

fn render_prometheus_metrics(metrics: &ControlPlaneMetricsResponse) -> String {
    let cluster_id = prometheus_label(metrics.cluster_id.as_str());
    let mut body = String::new();
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_nodes Number of registered nodes."
    );
    prometheus_line!(&mut body, "# TYPE ipars_control_plane_nodes gauge");
    prometheus_line!(
        &mut body,
        "ipars_control_plane_nodes{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.node_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_relay_candidates Number of relay-capable registered nodes."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_relay_candidates gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_relay_candidates{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.relay_candidate_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_stale_endpoint_candidates Number of endpoint candidates older than the control-plane candidate TTL."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_stale_endpoint_candidates gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_stale_endpoint_candidates{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.stale_endpoint_candidate_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_endpoint_candidate_ttl_seconds Endpoint candidate freshness window used by control-plane peer maps."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_endpoint_candidate_ttl_seconds gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_endpoint_candidate_ttl_seconds{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.endpoint_candidate_ttl_seconds
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_vpn_pool_total Usable VPN IP addresses in the configured pool."
    );
    prometheus_line!(&mut body, "# TYPE ipars_control_plane_vpn_pool_total gauge");
    prometheus_line!(
        &mut body,
        "ipars_control_plane_vpn_pool_total{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.vpn_pool_total_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_vpn_pool_allocated Allocated VPN IP addresses in the configured pool."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_vpn_pool_allocated gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_vpn_pool_allocated{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.vpn_pool_allocated_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_vpn_pool_available Unallocated usable VPN IP addresses in the configured pool."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_vpn_pool_available gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_vpn_pool_available{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.vpn_pool_available_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_join_tokens Issued join tokens by current status."
    );
    prometheus_line!(&mut body, "# TYPE ipars_control_plane_join_tokens gauge");
    for (status, count) in [
        ("active", metrics.token_ledger_active_count),
        ("revoked", metrics.token_ledger_revoked_count),
        ("expired", metrics.token_ledger_expired_count),
        ("exhausted", metrics.token_ledger_exhausted_count),
    ] {
        prometheus_line!(
            &mut body,
            "ipars_control_plane_join_tokens{{cluster_id=\"{cluster_id}\",status=\"{status}\"}} {count}"
        );
    }
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_join_tokens_issued Total join-token ledger records."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_join_tokens_issued gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_join_tokens_issued{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.token_ledger_issued_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_join_token_uses Total accepted join-token uses recorded by the ledger."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_join_token_uses gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_join_token_uses{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.token_ledger_use_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_peer_map_candidates Source-target peer-map candidates before ACL filtering."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_peer_map_candidates gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_peer_map_candidates{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.peer_map_candidate_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_peer_map_visible Source-target peer-map entries visible after ACL filtering."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_peer_map_visible gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_peer_map_visible{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.peer_map_visible_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_peer_map_acl_denied Source-target peer-map entries hidden by ACL filtering."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_peer_map_acl_denied gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_peer_map_acl_denied{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.peer_map_acl_denied_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_peer_map_route_candidates Advertised route candidates considered for peer maps before ACL filtering."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_peer_map_route_candidates gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_peer_map_route_candidates{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.peer_map_route_candidate_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_peer_map_routes_visible Advertised routes visible in peer maps after ACL filtering."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_peer_map_routes_visible gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_peer_map_routes_visible{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.peer_map_route_visible_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_peer_map_routes_acl_denied Advertised routes hidden by peer-map ACL filtering."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_peer_map_routes_acl_denied gauge"
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_peer_map_routes_acl_denied{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.peer_map_route_acl_denied_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_node_health Registered nodes by last reported health."
    );
    prometheus_line!(&mut body, "# TYPE ipars_control_plane_node_health gauge");
    prometheus_line!(
        &mut body,
        "ipars_control_plane_node_health{{cluster_id=\"{cluster_id}\",state=\"healthy\"}} {}",
        metrics.healthy_node_count
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_node_health{{cluster_id=\"{cluster_id}\",state=\"degraded\"}} {}",
        metrics.degraded_node_count
    );
    prometheus_line!(
        &mut body,
        "ipars_control_plane_node_health{{cluster_id=\"{cluster_id}\",state=\"unhealthy\"}} {}",
        metrics.unhealthy_node_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_paths Number of pair-scoped paths persisted by the control plane."
    );
    prometheus_line!(&mut body, "# TYPE ipars_control_plane_paths gauge");
    prometheus_line!(
        &mut body,
        "ipars_control_plane_paths{{cluster_id=\"{cluster_id}\"}} {}",
        metrics.path_count
    );
    prometheus_line!(
        &mut body,
        "# HELP ipars_control_plane_path_state_count Pair-scoped paths by selected state."
    );
    prometheus_line!(
        &mut body,
        "# TYPE ipars_control_plane_path_state_count gauge"
    );
    for state_count in &metrics.path_state_counts {
        prometheus_line!(
            &mut body,
            "ipars_control_plane_path_state_count{{cluster_id=\"{cluster_id}\",state=\"{}\"}} {}",
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
pub struct ApiError(ControlPlaneError);

impl From<ControlPlaneError> for ApiError {
    fn from(error: ControlPlaneError) -> Self {
        Self(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            ControlPlaneError::JoinDenied
            | ControlPlaneError::RelayDenied
            | ControlPlaneError::RouteDenied(_)
            | ControlPlaneError::TokenRejected { .. } => StatusCode::FORBIDDEN,
            ControlPlaneError::TokenNotFound(_) | ControlPlaneError::IssuerKeyNotFound { .. } => {
                StatusCode::UNAUTHORIZED
            }
            ControlPlaneError::NodeSignatureRequired(_)
            | ControlPlaneError::NodeSignatureRejected { .. } => StatusCode::UNAUTHORIZED,
            ControlPlaneError::TokenVerification(_) => StatusCode::UNAUTHORIZED,
            ControlPlaneError::NodeAlreadyExists(_)
            | ControlPlaneError::VpnIpAlreadyAllocated(_) => StatusCode::CONFLICT,
            ControlPlaneError::NodeUpdateRejected { .. }
            | ControlPlaneError::NodeRegistrationRejected { .. } => StatusCode::FORBIDDEN,
            ControlPlaneError::NodeNotFound(_) => StatusCode::NOT_FOUND,
            ControlPlaneError::VpnPoolExhausted | ControlPlaneError::Store(_) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        };
        let body = Json(ErrorResponse {
            error: self.0.to_string(),
        });
        (status, body).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use axum::body::Body;
    use axum::http::{header, Request};
    use ipars_control_plane::{
        ControlPlaneConfig, ControlPlaneJoinService, InMemoryStore, InMemoryTokenLedger,
        IssuerKeyRing,
    };
    use ipars_crypto::{encode_bytes, IdentityKeyPair};
    use ipars_types::api::{
        ControlPlaneMetricsResponse, ControlPlanePolicyResponse, HeartbeatRequest,
        HeartbeatResponse, JoinNodeRequest, RegisterNodeRequest, RegisterNodeResponse,
        RevokeTokenRequest, RevokeTokenResponse, RotateWireGuardKeyRequest,
        RotateWireGuardKeyResponse,
    };
    use ipars_types::{
        AclAction, AclRule, BootstrapEndpoint, BootstrapEndpointKind, ClusterId, HealthState,
        JoinTokenClaims, KeyId, NodeHealth, NodeId, Role, Tag, TokenPolicy, TokenStatus,
        TransportProtocol,
    };
    use ipnet::Ipv4Net;
    use tower::ServiceExt;

    use super::*;

    fn claims(cluster_id: ClusterId, issuer: NodeId, key_id: KeyId) -> JoinTokenClaims {
        let now = Utc::now();
        let mut tags = BTreeSet::new();
        tags.insert(Tag::from_string("edge"));
        JoinTokenClaims {
            cluster_id,
            bootstrap_endpoints: vec![BootstrapEndpoint {
                url: "https://203.0.113.10:8443".to_string(),
                kind: BootstrapEndpointKind::ControlPlane,
            }],
            expires_at: now + chrono::Duration::minutes(5),
            not_before: now - chrono::Duration::seconds(1),
            role: Role::edge(),
            tags,
            issuer,
            key_id,
            policy: TokenPolicy::default(),
            nonce: "http-join".to_string(),
        }
    }

    fn registration(node_id: &str) -> RegisterNodeRequest {
        let identity = identity_for_node(node_id);
        RegisterNodeRequest {
            node_id: identity.node_id(),
            identity_public_key: identity.public_key_b64(),
            wireguard_public_key: wireguard_public_key_for_node(node_id),
            candidates: Vec::new(),
            relay_capability: None,
            requested_routes: Vec::new(),
        }
    }

    fn identity_for_node(node_id: &str) -> IdentityKeyPair {
        let mut seed = [0_u8; 32];
        for (index, byte) in node_id.as_bytes().iter().enumerate() {
            seed[index % seed.len()] = seed[index % seed.len()].wrapping_add(*byte);
        }
        if seed.iter().all(|byte| *byte == 0) {
            seed[0] = 1;
        }
        IdentityKeyPair::from_signing_bytes(seed)
    }

    fn wireguard_public_key_for_node(node_id: &str) -> String {
        let mut bytes = [0_u8; 32];
        for (index, byte) in format!("wg-{node_id}").as_bytes().iter().enumerate() {
            bytes[index % 32] = bytes[index % 32].wrapping_add(*byte);
        }
        if bytes.iter().all(|byte| *byte == 0) {
            bytes[0] = 1;
        }
        encode_bytes(&bytes)
    }

    fn node_id(label: &str) -> NodeId {
        identity_for_node(label).node_id()
    }

    fn signed_heartbeat(label: &str, mut request: HeartbeatRequest) -> HeartbeatRequest {
        let identity = identity_for_node(label);
        request.node_signature = Some(
            match identity.sign_heartbeat_request(&request, Utc::now()) {
                Ok(signature) => signature,
                Err(error) => panic!("test identity should sign heartbeat: {error}"),
            },
        );
        request
    }

    fn signed_wireguard_key_rotation(
        label: &str,
        previous_wireguard_public_key: String,
        next_wireguard_public_key: String,
    ) -> RotateWireGuardKeyRequest {
        let identity = identity_for_node(label);
        let mut request = RotateWireGuardKeyRequest {
            node_id: identity.node_id(),
            previous_wireguard_public_key,
            next_wireguard_public_key,
            node_signature: None,
        };
        request.node_signature = Some(
            match identity.sign_wireguard_key_rotation_request(&request, Utc::now()) {
                Ok(signature) => signature,
                Err(error) => panic!("test identity should sign wireguard key rotation: {error}"),
            },
        );
        request
    }

    #[tokio::test]
    async fn http_join_registers_node() -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("root");
        let cluster_id = ClusterId::new();
        let store = Arc::new(InMemoryStore::default());
        let ledger = Arc::new(InMemoryTokenLedger::default());
        let vpn_pool = Ipv4Net::new(std::net::Ipv4Addr::new(100, 64, 0, 0), 29)?;
        let mut config = ControlPlaneConfig::new(cluster_id.clone(), vpn_pool);
        config.cluster_policy.allow_relay_fallback = false;
        let mut from_roles = BTreeSet::new();
        from_roles.insert(Role::edge());
        config.cluster_policy.acl_rules = vec![AclRule {
            id: "allow-edge".to_string(),
            from_roles,
            from_tags: BTreeSet::new(),
            to_roles: BTreeSet::new(),
            to_tags: BTreeSet::new(),
            routes: Vec::new(),
            protocol: TransportProtocol::Any,
            action: AclAction::Allow,
        }];
        let plane = Arc::new(ControlPlane::new(config, store));
        let mut key_ring = IssuerKeyRing::default();
        key_ring.insert(issuer.node_id(), key_id.clone(), issuer.public_key_b64());
        let join_service = Arc::new(ControlPlaneJoinService::new(
            plane.clone(),
            ledger,
            key_ring,
        ));
        let app = router(ControlPlaneHttpState::new(plane, join_service));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/policy")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let policy: ControlPlanePolicyResponse = serde_json::from_slice(&body)?;
        assert_eq!(policy.cluster_id, cluster_id);
        assert_eq!(policy.vpn_pool, vpn_pool);
        assert!(!policy.cluster_policy.allow_relay_fallback);
        assert_eq!(policy.cluster_policy.acl_rules.len(), 1);
        assert_eq!(policy.cluster_policy.acl_rules[0].id, "allow-edge");

        let request_body = JoinNodeRequest {
            token: issuer.sign_join_token(claims(cluster_id, issuer.node_id(), key_id))?,
            registration: registration("node-http"),
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/join")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&request_body)?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response: RegisterNodeResponse = serde_json::from_slice(&body)?;
        assert_eq!(response.node.node_id, node_id("node-http"));
        let previous_wireguard_public_key = response.node.wireguard_public_key.clone();
        let next_wireguard_public_key = wireguard_public_key_for_node("node-http-rotated");

        let rotation = signed_wireguard_key_rotation(
            "node-http",
            previous_wireguard_public_key,
            next_wireguard_public_key.clone(),
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/nodes/{}/wireguard-key", node_id("node-http")))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&rotation)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response: RotateWireGuardKeyResponse = serde_json::from_slice(&body)?;
        assert_eq!(
            response.node.wireguard_public_key,
            next_wireguard_public_key
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens/revoke")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&RevokeTokenRequest {
                        cluster_id: request_body.token.claims.cluster_id.clone(),
                        nonce: request_body.token.claims.nonce.clone(),
                    })?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response: RevokeTokenResponse = serde_json::from_slice(&body)?;
        assert_eq!(response.status, TokenStatus::Revoked);

        let rejected_join = JoinNodeRequest {
            token: request_body.token.clone(),
            registration: registration("node-revoked"),
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/join")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&rejected_join)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let heartbeat = signed_heartbeat(
            "node-http",
            HeartbeatRequest {
                node_id: node_id("node-http"),
                health: NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: Utc::now(),
                    latency_ms: Some(1.0),
                    relay_load: None,
                    message: None,
                },
                candidates: Vec::new(),
                relay_capability: None,
                path_state: Vec::new(),
                node_signature: None,
            },
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/heartbeat")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&heartbeat)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response: HeartbeatResponse = serde_json::from_slice(&body)?;
        assert!(response.accepted);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/metrics")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let metrics: ControlPlaneMetricsResponse = serde_json::from_slice(&body)?;
        assert_eq!(metrics.node_count, 1);
        assert_eq!(metrics.healthy_node_count, 1);
        assert_eq!(metrics.stale_endpoint_candidate_count, 0);
        assert_eq!(metrics.endpoint_candidate_ttl_seconds, 120);
        assert_eq!(metrics.vpn_pool_total_count, 6);
        assert_eq!(metrics.vpn_pool_allocated_count, 1);
        assert_eq!(metrics.vpn_pool_available_count, 5);
        assert_eq!(metrics.token_ledger_issued_count, 1);
        assert_eq!(metrics.token_ledger_active_count, 0);
        assert_eq!(metrics.token_ledger_revoked_count, 1);
        assert_eq!(metrics.token_ledger_expired_count, 0);
        assert_eq!(metrics.token_ledger_exhausted_count, 0);
        assert_eq!(metrics.token_ledger_use_count, 1);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static(
                "text/plain; version=0.0.4; charset=utf-8"
            ))
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("ipars_control_plane_nodes"));
        assert!(body.contains("ipars_control_plane_stale_endpoint_candidates"));
        assert!(body.contains("ipars_control_plane_endpoint_candidate_ttl_seconds"));
        assert!(body.contains("ipars_control_plane_vpn_pool_total"));
        assert!(body.contains("ipars_control_plane_vpn_pool_allocated"));
        assert!(body.contains("ipars_control_plane_vpn_pool_available"));
        assert!(body.contains("ipars_control_plane_join_tokens"));
        assert!(body.contains("ipars_control_plane_join_tokens_issued"));
        assert!(body.contains("ipars_control_plane_join_token_uses"));
        assert!(body.contains("ipars_control_plane_peer_map_candidates"));
        assert!(body.contains("ipars_control_plane_peer_map_visible"));
        assert!(body.contains("ipars_control_plane_peer_map_acl_denied"));
        assert!(body.contains("ipars_control_plane_peer_map_route_candidates"));
        assert!(body.contains("ipars_control_plane_peer_map_routes_visible"));
        assert!(body.contains("ipars_control_plane_peer_map_routes_acl_denied"));
        assert!(body.contains("ipars_control_plane_node_health"));
        Ok(())
    }
}
