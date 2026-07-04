use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use ipars_control_plane::{
    ControlPlane, ControlPlaneError, ControlPlaneJoinService, ControlPlaneStore, TokenLedger,
};
use ipars_types::api::{JoinNodeRequest, PeerMap, RegisterNodeResponse};
use ipars_types::NodeId;
use serde::Serialize;

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
        .route("/v1/join", post(join::<S, L>))
        .route("/v1/peers/{node_id}", get(peers::<S, L>))
        .with_state(state)
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
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

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
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
            | ControlPlaneError::RouteDenied(_)
            | ControlPlaneError::TokenRejected { .. } => StatusCode::FORBIDDEN,
            ControlPlaneError::TokenNotFound(_) | ControlPlaneError::IssuerKeyNotFound { .. } => {
                StatusCode::UNAUTHORIZED
            }
            ControlPlaneError::TokenVerification(_) => StatusCode::UNAUTHORIZED,
            ControlPlaneError::NodeAlreadyExists(_) => StatusCode::CONFLICT,
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
    use ipars_crypto::IdentityKeyPair;
    use ipars_types::api::{JoinNodeRequest, RegisterNodeRequest, RegisterNodeResponse};
    use ipars_types::{
        BootstrapEndpoint, BootstrapEndpointKind, ClusterId, JoinTokenClaims, KeyId, NodeId, Role,
        Tag, TokenPolicy,
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
        RegisterNodeRequest {
            node_id: NodeId::from_string(node_id),
            identity_public_key: format!("identity-{node_id}"),
            wireguard_public_key: format!("wg-{node_id}"),
            candidates: Vec::new(),
            relay_capability: None,
            requested_routes: Vec::new(),
        }
    }

    #[tokio::test]
    async fn http_join_registers_node() -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IdentityKeyPair::generate();
        let key_id = KeyId::from_string("root");
        let cluster_id = ClusterId::new();
        let store = Arc::new(InMemoryStore::default());
        let ledger = Arc::new(InMemoryTokenLedger::default());
        let plane = Arc::new(ControlPlane::new(
            ControlPlaneConfig::new(
                cluster_id.clone(),
                Ipv4Net::new(std::net::Ipv4Addr::new(100, 64, 0, 0), 29)?,
            ),
            store,
        ));
        let mut key_ring = IssuerKeyRing::default();
        key_ring.insert(issuer.node_id(), key_id.clone(), issuer.public_key_b64());
        let join_service = Arc::new(ControlPlaneJoinService::new(
            plane.clone(),
            ledger,
            key_ring,
        ));
        let app = router(ControlPlaneHttpState::new(plane, join_service));
        let request_body = JoinNodeRequest {
            token: issuer.sign_join_token(claims(cluster_id, issuer.node_id(), key_id))?,
            registration: registration("node-http"),
        };

        let response = app
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
        assert_eq!(response.node.node_id, NodeId::from_string("node-http"));
        Ok(())
    }
}
