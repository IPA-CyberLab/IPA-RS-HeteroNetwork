use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipars_agent::AgentRuntime;
use ipars_http_tunnel::{
    TunnelError, TunnelHub, MAX_BATCH_BYTES, NODE_HEADER, NONCE_HEADER, PROOF_HEADER, TIME_HEADER,
    TOKEN_SCHEME,
};
use ipars_types::NodeId;

#[derive(Clone)]
struct GatewayState {
    runtime: Arc<AgentRuntime>,
    hub: Arc<TunnelHub>,
    relay: Option<(String, Arc<str>)>,
    client: reqwest::Client,
    authorizing: Arc<tokio::sync::Semaphore>,
    lookup_budget: Arc<std::sync::Mutex<(std::time::Instant, u32)>>,
}

pub fn router(
    runtime: Arc<AgentRuntime>,
    backend: SocketAddr,
    relay: Option<(String, String)>,
) -> Router {
    let hub = Arc::new(TunnelHub::new(backend, 2048));
    runtime.set_http_gateway(hub.clone());
    Router::new()
        .route("/v1/tunnels/wireguard/open", post(open))
        .route(
            "/v1/tunnels/wireguard/packets",
            get(receive).post(send).delete(close),
        )
        .route("/v1/tunnels/relay/admit", post(admit))
        .layer(DefaultBodyLimit::max(MAX_BATCH_BYTES))
        .layer(middleware::from_fn_with_state(
            Arc::new(tokio::sync::Semaphore::new(128)),
            bound_posts,
        ))
        .with_state(GatewayState {
            runtime,
            hub,
            relay: relay.map(|(url, token)| (url, Arc::from(token))),
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            authorizing: Arc::new(tokio::sync::Semaphore::new(32)),
            lookup_budget: Arc::new(std::sync::Mutex::new((std::time::Instant::now(), 0))),
        })
}

async fn bound_posts(
    State(limit): State<Arc<tokio::sync::Semaphore>>,
    request: Request,
    next: Next,
) -> Response {
    let _permit = if request.method() == axum::http::Method::POST {
        match limit.try_acquire() {
            Ok(permit) => Some(permit),
            Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
        }
    } else {
        None
    };
    next.run(request).await
}

fn allow_lookup(state: &GatewayState) -> Result<(), StatusCode> {
    let mut budget = state
        .lookup_budget
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if budget.0.elapsed() >= Duration::from_secs(1) {
        *budget = (std::time::Instant::now(), 0);
    }
    if budget.1 >= 64 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    budget.1 += 1;
    Ok(())
}
fn validate_proof_headers(timestamp: i64, nonce: &str, proof: &str) -> Result<(), StatusCode> {
    if chrono::Utc::now().timestamp().abs_diff(timestamp) > 60
        || nonce.len() != 32
        || proof.len() != 64
        || !nonce
            .bytes()
            .chain(proof.bytes())
            .all(|v| v.is_ascii_hexdigit())
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, StatusCode> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)
}

fn token(headers: &HeaderMap) -> Result<&str, StatusCode> {
    header(headers, "authorization")?
        .strip_prefix(TOKEN_SCHEME)
        .ok_or(StatusCode::UNAUTHORIZED)
}

fn failure(error: TunnelError) -> StatusCode {
    match error {
        TunnelError::Unauthorized => StatusCode::UNAUTHORIZED,
        TunnelError::Capacity => StatusCode::TOO_MANY_REQUESTS,
        TunnelError::ConcurrentPoll => StatusCode::CONFLICT,
        TunnelError::InvalidPacket => StatusCode::BAD_REQUEST,
        _ => StatusCode::BAD_GATEWAY,
    }
}

async fn open(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let _authorizing = state
        .authorizing
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let (packet, diagnostics) = ipars_http_tunnel::decode_open(&body).map_err(failure)?;
    if !ipars_http_tunnel::wireguard_packet(packet) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let node = NodeId::from_string(header(&headers, NODE_HEADER)?);
    if node.as_str().len() > 128 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let timestamp = header(&headers, TIME_HEADER)?
        .parse::<i64>()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let nonce = header(&headers, NONCE_HEADER)?;
    let proof = header(&headers, PROOF_HEADER)?;
    validate_proof_headers(timestamp, nonce, proof)?;
    if state.runtime.http_tunnel_peer_is_known(&node).await {
        state
            .runtime
            .verify_http_tunnel(&node, timestamp, nonce, &body, proof)
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
    } else {
        allow_lookup(&state)?;
        let peer = state
            .runtime
            .query_http_transport_peer(node.clone(), None)
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        if !peer.peer.role.is_client() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        state
            .runtime
            .verify_http_transport_key(&peer.peer, timestamp, nonce, &body, proof)
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
    }
    state
        .hub
        .consume_nonce(&node, nonce, timestamp)
        .map_err(failure)?;
    let transport = if headers
        .get("x-forwarded-proto")
        .is_some_and(|v| v == "https")
    {
        ipars_types::api::DataPlaneTransport::Https
    } else {
        ipars_types::api::DataPlaneTransport::Http
    };
    let opened = state
        .hub
        .open(
            node.clone(),
            transport,
            packet,
            false,
            Duration::from_secs(3600),
            node.to_string(),
        )
        .await
        .map_err(failure)?;
    state
        .hub
        .diagnostics(&opened.token, diagnostics)
        .await
        .map_err(failure)?;
    Ok(([("Cache-Control", "no-store")], Json(opened)).into_response())
}

async fn admit(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let _authorizing = state
        .authorizing
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let (url, token) = state
        .relay
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let node = NodeId::from_string(header(&headers, NODE_HEADER)?);
    let timestamp = header(&headers, TIME_HEADER)?
        .parse::<i64>()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let nonce = header(&headers, NONCE_HEADER)?;
    let proof = header(&headers, PROOF_HEADER)?;
    validate_proof_headers(timestamp, nonce, proof)?;
    allow_lookup(&state)?;
    let admission: ipars_types::api::RelayAdmissionRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let peer = state
        .runtime
        .query_http_transport_peer(node.clone(), Some(admission.clone()))
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    state
        .runtime
        .verify_http_transport_key(&peer.peer, timestamp, nonce, &body, proof)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    state
        .hub
        .consume_nonce(&node, nonce, timestamp)
        .map_err(failure)?;
    // The fleet admission token is sent only to the configured local/VPN
    // backend; it is never returned or placed on a public HTTP connection.
    let response = state
        .client
        .post(format!("{}/v1/sessions", url.trim_end_matches('/')))
        .bearer_auth(token.as_ref())
        .json(&admission)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    if !response.status().is_success() {
        return Err(StatusCode::BAD_GATEWAY);
    }
    if response.content_length().is_some_and(|n| n > 64 * 1024) {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?
    {
        if bytes.len() + chunk.len() > 64 * 1024 {
            return Err(StatusCode::BAD_GATEWAY);
        }
        bytes.extend_from_slice(&chunk);
    }
    let admitted: ipars_types::api::RelayAdmissionResponse =
        serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_GATEWAY)?;
    if admitted.relay_node != state.runtime.state().node_id {
        return Err(StatusCode::BAD_GATEWAY);
    }
    Ok(([("Cache-Control", "no-store")], Json(admitted)).into_response())
}

async fn send(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    let packets = ipars_http_tunnel::decode_batch(&body).map_err(failure)?;
    if packets.is_empty()
        || packets
            .iter()
            .any(|packet| !ipars_http_tunnel::wireguard_packet(packet))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    state
        .hub
        .send(token(&headers)?, &body)
        .await
        .map_err(failure)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn receive(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let body = state.hub.receive(token(&headers)?).await.map_err(failure)?;
    Ok((
        [
            ("Content-Type", "application/octet-stream"),
            ("Cache-Control", "no-store"),
        ],
        body,
    )
        .into_response())
}

async fn close(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Result<StatusCode, StatusCode> {
    state.hub.close(token(&headers)?).await;
    Ok(StatusCode::NO_CONTENT)
}
