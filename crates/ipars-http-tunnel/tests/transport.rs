use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use boringtun::noise::{Tunn, TunnResult};
use ipars_http_tunnel::*;
use ipars_types::{
    api::{DataPlaneTransport, TransportObservation},
    NodeId,
};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::{net::UdpSocket, sync::watch};
use x25519_dalek::{PublicKey, StaticSecret};

fn id(value: &str) -> NodeId {
    NodeId::from_string(value)
}
fn auths() -> (TunnelAuth, TunnelAuth) {
    let client = [7; 32];
    let server = [11; 32];
    (
        TunnelAuth::new(
            client,
            PublicKey::from(&StaticSecret::from(server)).to_bytes(),
            id("gateway"),
        )
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}")),
        TunnelAuth::new(
            server,
            PublicKey::from(&StaticSecret::from(client)).to_bytes(),
            id("gateway"),
        )
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}")),
    )
}
#[test]
fn proof_binds_both_identities_time_nonce_and_exact_body() {
    let (client, server) = auths();
    let node = id("client");
    let timestamp = chrono::Utc::now().timestamp();
    let nonce = "00112233445566778899aabbccddeeff";
    let body = encode_open(
        &[1; 148],
        &BTreeMap::from([("https_unavailable".to_string(), 3)]),
    )
    .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    let proof = client
        .proof(&node, timestamp, nonce, &body)
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    assert!(server
        .verify(&node, timestamp, nonce, &body, &proof)
        .is_ok());
    assert!(server
        .verify(&id("impostor"), timestamp, nonce, &body, &proof)
        .is_err());
    assert!(server
        .verify(&node, timestamp - 120, nonce, &body, &proof)
        .is_err());
    assert!(server
        .verify(
            &node,
            timestamp,
            "10112233445566778899aabbccddeeff",
            &body,
            &proof
        )
        .is_err());
    let mut altered = body.clone();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    assert!(server
        .verify(&node, timestamp, nonce, &altered, &proof)
        .is_err());
    assert!(TunnelAuth::new([7; 32], [0; 32], id("gateway")).is_err());
    let other = TunnelAuth::new(
        [7; 32],
        PublicKey::from(&StaticSecret::from([11; 32])).to_bytes(),
        id("another-gateway"),
    )
    .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    assert_ne!(
        other
            .proof(&node, timestamp, nonce, &body)
            .unwrap_or_else(|error| panic!("test fixture failed: {error:?}")),
        proof
    );
    let hub = TunnelHub::new(
        "127.0.0.1:1"
            .parse()
            .unwrap_or_else(|error| panic!("test fixture failed: {error:?}")),
        16,
    );
    assert!(hub.consume_nonce(&node, nonce, timestamp).is_ok());
    assert!(hub.consume_nonce(&node, nonce, timestamp).is_err());
}
#[test]
fn authentication_matches_the_native_go_fixture() {
    let (client, _) = auths();
    assert_eq!(
        client
            .proof(
                &id("client"),
                123,
                "00112233445566778899aabbccddeeff",
                b"test"
            )
            .unwrap_or_else(|error| panic!("test fixture failed: {error:?}")),
        "cb4a2ccf100a94e0d1872b22a8fec340595db2e1460e89e9745a000ebf287974"
    );
}
#[test]
fn wire_format_rejects_oversized_truncated_and_unbounded_inputs() {
    assert!(decode_batch(&[0, 0]).is_err());
    assert!(decode_batch(&[0, 5, 1]).is_err());
    assert!(decode_batch(&vec![0; MAX_BATCH_BYTES + 1]).is_err());
    let mut body = Vec::new();
    for _ in 0..65 {
        append_packet(&mut body, &[1])
            .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    }
    assert!(decode_batch(&body).is_err());
    let encoded = encode_open(
        &[1, 2],
        &BTreeMap::from([("udp_probe_timeout".to_string(), 1)]),
    )
    .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    let (packet, diagnostics) =
        decode_open(&encoded).unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    assert_eq!(packet, &[1, 2]);
    assert_eq!(diagnostics["udp_probe_timeout"], 1);
    let bad = encode_open(
        &[1],
        &BTreeMap::from([("secret=https://example/token".to_string(), 1)]),
    )
    .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    assert!(decode_open(&bad).is_err());
    assert!(!wireguard_packet(&[4, 0, 0, 0]));
    let mut packet = vec![0; 32];
    packet[0] = 4;
    assert!(wireguard_packet(&packet));
}

#[derive(Clone)]
struct Fixture {
    hub: Arc<TunnelHub>,
    auth: TunnelAuth,
}
fn bearer(headers: &HeaderMap) -> Result<&str, StatusCode> {
    headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix(TOKEN_SCHEME))
        .ok_or(StatusCode::UNAUTHORIZED)
}
async fn open(
    State(state): State<Fixture>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<OpenResponse>, StatusCode> {
    let get = |name: &str| {
        headers
            .get(name)
            .and_then(|h| h.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)
    };
    let node = id(get(NODE_HEADER)?);
    let time = get(TIME_HEADER)?
        .parse()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    state
        .auth
        .verify(&node, time, get(NONCE_HEADER)?, &body, get(PROOF_HEADER)?)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    state
        .hub
        .consume_nonce(&node, get(NONCE_HEADER)?, time)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let (first, diagnostics) = decode_open(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let opened = state
        .hub
        .open(
            node.clone(),
            DataPlaneTransport::Http,
            first,
            false,
            Duration::from_secs(300),
            node.to_string(),
        )
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    state
        .hub
        .diagnostics(&opened.token, diagnostics)
        .await
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    Ok(Json(opened))
}
async fn send(
    State(state): State<Fixture>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    state
        .hub
        .send(bearer(&headers)?, &body)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn receive(State(state): State<Fixture>, headers: HeaderMap) -> Result<Vec<u8>, StatusCode> {
    state
        .hub
        .receive(bearer(&headers)?)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)
}
async fn fixture(backend: SocketAddr) -> (String, Arc<TunnelHub>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    let base = format!(
        "http://{}/v1/tunnels/wireguard/open",
        listener
            .local_addr()
            .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"))
    );
    let hub = Arc::new(TunnelHub::new(backend, 16));
    let (_, auth) = auths();
    let app = Router::new()
        .route("/v1/tunnels/wireguard/open", post(open))
        .route("/v1/tunnels/wireguard/packets", get(receive).post(send))
        .with_state(Fixture {
            hub: hub.clone(),
            auth,
        });
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    });
    (base, hub, task)
}
fn network(result: TunnResult<'_>) -> Vec<u8> {
    match result {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        other => panic!("expected encrypted packet, got {other:?}"),
    }
}
fn tunnels() -> (Tunn, Tunn) {
    let client = StaticSecret::from([7; 32]);
    let server = StaticSecret::from([11; 32]);
    (
        Tunn::new(
            client.clone(),
            PublicKey::from(&server),
            None,
            None,
            1,
            None,
        ),
        Tunn::new(server, PublicKey::from(&client), None, None, 2, None),
    )
}
fn ipv4() -> Vec<u8> {
    let payload = b"heteronet encrypted payload over TCP";
    let mut inner = vec![0; 20];
    inner[0] = 0x45;
    inner[9] = 17;
    inner[12..16].copy_from_slice(&[10, 1, 0, 1]);
    inner[16..20].copy_from_slice(&[10, 1, 0, 2]);
    inner.extend_from_slice(payload);
    let len = inner.len() as u16;
    inner[2..4].copy_from_slice(&len.to_be_bytes());
    inner
}
async fn responder(socket: UdpSocket, mut tunnel: Tunn) {
    let mut buffer = vec![0; MAX_PACKET_BYTES];
    let mut out = vec![0; MAX_PACKET_BYTES];
    loop {
        let (len, source) = socket
            .recv_from(&mut buffer)
            .await
            .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
        let result = tunnel.decapsulate(None, &buffer[..len], &mut out);
        match result {
            TunnResult::WriteToNetwork(packet) => {
                socket
                    .send_to(packet, source)
                    .await
                    .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
            }
            TunnResult::WriteToTunnelV4(inner, _) => {
                let mut reply = inner.to_vec();
                let src = reply[12..16].to_vec();
                let dst = reply[16..20].to_vec();
                reply[12..16].copy_from_slice(&dst);
                reply[16..20].copy_from_slice(&src);
                let packet = network(tunnel.encapsulate(&reply, &mut out));
                socket
                    .send_to(&packet, source)
                    .await
                    .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
            }
            TunnResult::Done | TunnResult::Err(_) => {}
            other => panic!("unexpected tunnel result: {other:?}"),
        }
    }
}

#[tokio::test]
async fn udp_blackhole_falls_back_and_carries_real_encrypted_wireguard_bidirectionally() {
    let backend = UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    let (mut client, server) = tunnels();
    let backend_addr = backend
        .local_addr()
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    let responder = tokio::spawn(responder(backend, server));
    let (url, hub, http_server) = fixture(backend_addr).await;
    // A bound socket intentionally discards every outgoing WAN UDP packet.
    let blackhole = UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    let wireguard = UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    let local = UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    let endpoint = local
        .local_addr()
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    let status = Arc::new(Mutex::new(TransportObservation::new(
        id("gateway"),
        blackhole
            .local_addr()
            .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"))
            .to_string(),
    )));
    let (shutdown, receiver) = watch::channel(false);
    let (auth, _) = auths();
    let proxy = DatagramProxy {
        node: id("client"),
        peer: id("gateway"),
        udp_endpoint: blackhole
            .local_addr()
            .unwrap_or_else(|error| panic!("test fixture failed: {error:?}")),
        wireguard_endpoint: wireguard
            .local_addr()
            .unwrap_or_else(|error| panic!("test fixture failed: {error:?}")),
        open_urls: vec![url],
        relay: None,
        auth: Some(auth),
        status: status.clone(),
        forwarding_enabled: None,
    };
    let task = tokio::spawn(proxy.serve(local, receiver));
    let mut out = vec![0; MAX_PACKET_BYTES];
    let packet = network(client.encapsulate(&ipv4(), &mut out));
    wireguard
        .send_to(&packet, endpoint)
        .await
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    let mut buffer = vec![0; MAX_PACKET_BYTES];
    let (len, reply_source) =
        tokio::time::timeout(Duration::from_secs(8), wireguard.recv_from(&mut buffer))
            .await
            .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"))
            .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    assert_eq!(reply_source, endpoint);
    let packet = network(client.decapsulate(None, &buffer[..len], &mut out));
    wireguard
        .send_to(&packet, endpoint)
        .await
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    // Send application data only after the actual WireGuard handshake.
    let packet = network(client.encapsulate(&ipv4(), &mut out));
    wireguard
        .send_to(&packet, endpoint)
        .await
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    let inner = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let len = wireguard
                .recv(&mut buffer)
                .await
                .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
            match client.decapsulate(None, &buffer[..len], &mut out) {
                TunnResult::WriteToTunnelV4(inner, _) => break inner.to_vec(),
                TunnResult::Done => {}
                TunnResult::WriteToNetwork(packet) => {
                    wireguard
                        .send_to(packet, endpoint)
                        .await
                        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
                }
                other => panic!("client rejected ciphertext: {other:?}"),
            }
        }
    })
    .await
    .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    assert_eq!(&inner[20..], &ipv4()[20..]);
    assert_eq!(&inner[12..16], &[10, 1, 0, 2]);
    let snapshot = status
        .lock()
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"))
        .clone();
    assert_eq!(snapshot.transport, DataPlaneTransport::Http);
    assert!(snapshot.tx_bytes > 0 && snapshot.rx_bytes > 0);
    assert_eq!(snapshot.failures["udp_probe_timeout"], 1);
    assert!(hub
        .observations()
        .iter()
        .any(|o| o.peer == id("client") && o.tx_bytes > 0));
    // Restore WAN UDP without replacing the stable WireGuard endpoint. The
    // probe packet must not be duplicated over HTTP, which would consume its
    // authenticated replay counter before the UDP reply can be generated.
    let bridge = UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    let forwarding = tokio::spawn(async move {
        let mut outbound = vec![0; MAX_PACKET_BYTES];
        let mut inbound = vec![0; MAX_PACKET_BYTES];
        let mut peer = None;
        loop {
            tokio::select! {
                packet=blackhole.recv_from(&mut outbound)=>{let (len,source)=packet.unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));peer=Some(source);bridge.send_to(&outbound[..len],backend_addr).await.unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));},
                packet=bridge.recv_from(&mut inbound)=>{let (len,source)=packet.unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));if source==backend_addr {if let Some(peer)=peer {blackhole.send_to(&inbound[..len],peer).await.unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));}}}
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(70), async {
        loop {
            let packet = network(client.encapsulate(&ipv4(), &mut out));
            wireguard
                .send_to(&packet, endpoint)
                .await
                .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
            if let Ok(Ok((len, source))) =
                tokio::time::timeout(Duration::from_secs(1), wireguard.recv_from(&mut buffer)).await
            {
                assert_eq!(source, endpoint);
                if let TunnResult::WriteToTunnelV4(inner, _) =
                    client.decapsulate(None, &buffer[..len], &mut out)
                {
                    assert_eq!(&inner[20..], &ipv4()[20..]);
                    if status
                        .lock()
                        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"))
                        .transport
                        == DataPlaneTransport::Udp
                    {
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .unwrap_or_else(|error| panic!("UDP did not recover automatically: {error:?}"));
    assert!(
        status
            .lock()
            .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"))
            .switches
            >= 2
    );
    forwarding.abort();
    shutdown
        .send(true)
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    task.await
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"))
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    responder.abort();
    http_server.abort();
}

#[tokio::test]
async fn hub_replaces_same_scope_rejects_concurrent_polls_and_reclaims_closed_clients() {
    let backend = UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    let hub = Arc::new(TunnelHub::new(
        backend
            .local_addr()
            .unwrap_or_else(|error| panic!("test fixture failed: {error:?}")),
        1,
    ));
    let first = hub
        .open(
            id("client"),
            DataPlaneTransport::Http,
            &[1],
            false,
            Duration::from_secs(60),
            "scope".into(),
        )
        .await
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    assert!(matches!(
        hub.open(
            id("other"),
            DataPlaneTransport::Http,
            &[1],
            false,
            Duration::from_secs(60),
            "other".into()
        )
        .await,
        Err(TunnelError::Capacity)
    ));
    let second = hub
        .open(
            id("client"),
            DataPlaneTransport::Https,
            &[1],
            false,
            Duration::from_secs(60),
            "scope".into(),
        )
        .await
        .unwrap_or_else(|error| panic!("test fixture failed: {error:?}"));
    assert!(hub.send(&first.token, &[0, 1, 1]).await.is_err());
    let running = hub.clone();
    let token = second.token.clone();
    let poll = tokio::spawn(async move { running.receive(&token).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(matches!(
        hub.receive(&second.token).await,
        Err(TunnelError::ConcurrentPoll)
    ));
    poll.abort();
    hub.close(&second.token).await;
    assert!(hub.send(&second.token, &[0, 1, 1]).await.is_err());
    assert!(hub
        .open(
            id("replacement-client"),
            DataPlaneTransport::Http,
            &[1],
            false,
            Duration::from_secs(60),
            "new-scope".into()
        )
        .await
        .is_ok());
}
