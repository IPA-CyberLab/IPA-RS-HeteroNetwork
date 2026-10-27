//! Private, disposable control-plane replicas for HTTP-only scale E2E.
//! Credentials are read from the environment and written only to a 0600 file.
use chrono::Utc;
use ipars_control_plane::{
    ControlPlane, ControlPlaneConfig, ControlPlaneJoinService, ControlPlaneStore, IssuerKeyRing,
    TokenLedger,
};
use ipars_crypto::IdentityKeyPair;
use ipars_store::{PostgresControlPlaneStore, SqliteControlPlaneStore};
use ipars_types::{
    BootstrapEndpoint, BootstrapEndpointKind, ClusterId, JoinTokenClaims, KeyId, NodeId,
    NodeRecord, Role, Tag, TokenPolicy, VpnIp,
};
use std::{collections::BTreeSet, env, path::PathBuf, sync::Arc};

async fn serve<S: ControlPlaneStore + TokenLedger + 'static>(store: Arc<S>) -> anyhow::Result<()> {
    let issuer = IdentityKeyPair::from_signing_key_b64(&env::var("HTTP_MESH_FIXTURE_ISSUER")?)?;
    let now = chrono::DateTime::parse_from_rfc3339(&env::var("HTTP_MESH_FIXTURE_TIME")?)?
        .with_timezone(&Utc);
    let cluster = ClusterId::from_string("http-mesh-disposable-e2e");
    if env::var("HTTP_MESH_FIXTURE_VERIFY_LEASES").as_deref() == Ok("1") {
        let now = Utc::now();
        let mesh = store
            .http_mesh()
            .ok_or_else(|| anyhow::anyhow!("fixture store does not support HTTP mesh"))?;
        let mut records = Vec::new();
        for index in 0..5 {
            let mut node = NodeRecord {
                node_id: NodeId::from_string(format!("lease-{}-{index}", issuer.node_id())),
                display_name: None,
                hostname: None,
                cluster_id: cluster.clone(),
                vpn_ip: VpnIp(format!("fd91:bb21::{:x}", 100 + index).parse()?),
                identity_public_key: issuer.public_key_b64(),
                wireguard_public_key: "fixture-key".into(),
                role: Role::from_string("worker"),
                tags: BTreeSet::new(),
                endpoint_candidates: vec![],
                relay_capability: None,
                token_policy: TokenPolicy::default(),
                routes: vec![],
                registered_at: now,
            };
            if index == 2 {
                node.tags.insert(Tag::from_string("heteronetwork-stopped"));
            }
            store.insert_node(node.clone()).await?;
            let at = if index == 4 {
                now
            } else {
                now - chrono::Duration::minutes(6)
            };
            mesh.lease(&node, index != 1, true, at).await?;
            if index == 3 {
                mesh.poll(&node.node_id, &[], now).await?;
            }
            records.push(node);
        }
        assert_eq!(store.reap_expired_http_members(now).await?, 1);
        for (index, record) in records.iter().enumerate() {
            assert_eq!(store.get_node(&record.node_id).await?.is_some(), index != 0);
            if index != 0 {
                store.remove_node(&record.node_id).await?;
            }
        }
        println!("lease_cleanup_ok");
        return Ok(());
    }
    let key_id = KeyId::from_string("fixture");
    let token = issuer.sign_join_token(JoinTokenClaims {
        cluster_id: cluster.clone(),
        bootstrap_endpoints: vec![BootstrapEndpoint {
            kind: BootstrapEndpointKind::ControlPlane,
            url: "https://fixture.example.test".into(),
        }],
        expires_at: now + chrono::Duration::hours(1),
        not_before: now - chrono::Duration::seconds(5),
        role: Role::from_string("worker"),
        tags: BTreeSet::new(),
        issuer: issuer.node_id(),
        key_id: key_id.clone(),
        policy: TokenPolicy {
            max_token_uses: Some(5000),
            ..Default::default()
        },
        nonce: format!("http-mesh-{}", issuer.node_id()),
    })?;
    let path = PathBuf::from(env::var("HTTP_MESH_FIXTURE_TOKEN_PATH")?);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options
        .open(path)?
        .write_all(&serde_json::to_vec(&token)?)?;
    let mut keys = IssuerKeyRing::default();
    keys.insert(issuer.node_id(), key_id, issuer.public_key_b64());
    let plane = Arc::new(ControlPlane::new(
        ControlPlaneConfig::new(cluster, "10.254.0.0/16".parse()?),
        store.clone(),
    ));
    let joins = Arc::new(ControlPlaneJoinService::new(plane.clone(), store, keys));
    let state = ipars_control_plane_http::ControlPlaneHttpState::new(plane, joins)
        .require_operator_api_bearer_token(env::var("HTTP_MESH_FIXTURE_OPERATOR")?);
    let listener = tokio::net::TcpListener::bind(env::var("HTTP_MESH_FIXTURE_LISTEN")?).await?;
    axum::serve(listener, ipars_control_plane_http::router(state)).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let database = env::var("HTTP_MESH_FIXTURE_DATABASE")?;
    if database.starts_with("postgres") {
        serve(Arc::new(
            PostgresControlPlaneStore::connect(&database).await?,
        ))
        .await
    } else {
        serve(Arc::new(SqliteControlPlaneStore::connect(&database).await?)).await
    }
}
