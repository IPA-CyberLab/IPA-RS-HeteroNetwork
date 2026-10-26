use super::RelayHttpState;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipars_http_tunnel::{TunnelError, MAX_BATCH_BYTES, NODE_HEADER, TOKEN_SCHEME};
use ipars_types::NodeId;
use std::time::Duration;

pub fn routes() -> Router<RelayHttpState> {
    Router::new()
        .route("/v1/tunnels/relay/open", post(open))
        .route(
            "/v1/tunnels/relay/packets",
            get(receive).post(send).delete(close),
        )
        .layer(DefaultBodyLimit::max(MAX_BATCH_BYTES))
}

fn token(headers: &HeaderMap) -> Result<&str, StatusCode> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix(TOKEN_SCHEME))
        .ok_or(StatusCode::UNAUTHORIZED)
}
fn fail(error: TunnelError) -> StatusCode {
    match error {
        TunnelError::Unauthorized => StatusCode::UNAUTHORIZED,
        TunnelError::Capacity => StatusCode::TOO_MANY_REQUESTS,
        TunnelError::ConcurrentPoll => StatusCode::CONFLICT,
        TunnelError::InvalidPacket => StatusCode::BAD_REQUEST,
        _ => StatusCode::BAD_GATEWAY,
    }
}

async fn open(
    State(state): State<RelayHttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let hub = state.http_transport.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    let node = NodeId::from_string(
        headers
            .get(NODE_HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?,
    );
    let (session, expires) = state
        .relay
        .table()
        .write()
        .await
        .authorize_http_announcement(&node, &body)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let lifetime = (expires - chrono::Utc::now())
        .to_std()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let transport = if headers
        .get("x-forwarded-proto")
        .is_some_and(|v| v == "https")
    {
        ipars_types::api::DataPlaneTransport::Https
    } else {
        ipars_types::api::DataPlaneTransport::Http
    };
    let opened = hub
        .open(
            node.clone(),
            transport,
            &body,
            false,
            lifetime.min(Duration::from_secs(3600)),
            format!("{session}:{node}"),
        )
        .await
        .map_err(fail)?;
    Ok(([("Cache-Control", "no-store")], Json(opened)).into_response())
}
async fn send(
    State(state): State<RelayHttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    state
        .http_transport
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?
        .send(token(&headers)?, &body)
        .await
        .map_err(fail)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn receive(
    State(state): State<RelayHttpState>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let body = state
        .http_transport
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?
        .receive(token(&headers)?)
        .await
        .map_err(fail)?;
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
    State(state): State<RelayHttpState>,
    headers: HeaderMap,
) -> Result<StatusCode, StatusCode> {
    state
        .http_transport
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?
        .close(token(&headers)?)
        .await;
    Ok(StatusCode::NO_CONTENT)
}
