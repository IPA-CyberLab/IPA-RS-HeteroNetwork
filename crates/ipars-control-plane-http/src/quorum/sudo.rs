//! Dedicated typed sudo issuance. No generic signing, redemption, or execution.
//! Policy, membership, share and owner identity are trusted local configuration.

use super::*;
use ipars_quorum::sudo::{SudoIdentity, SudoPolicy};
pub use ipars_quorum::sudo::{SudoRound1Request, SudoRound2Request};

pub const ROUND1_PATH: &str = "/v1/quorum/sudo/round1";
pub const ROUND2_PATH: &str = "/v1/quorum/sudo/round2";

struct SudoSignerState {
    auth: SignerHttpAuth,
    policy: SudoPolicy,
    identity: SudoIdentity,
    engine: Mutex<SignerEngine>,
}

/// Bind only to an authenticated transport, such as the trusted VPN or TLS.
/// `auth` must pin the owner issuer, subject and email. The body cannot select
/// the authenticated identity, policy, attestation key, or signing membership.
pub fn sudo_signer_router(
    policy: SudoPolicy,
    key_package: frost::keys::KeyPackage,
    node_id: impl AsRef<str>,
    auth: WebUiAuthConfig,
) -> Result<Router, String> {
    policy
        .validate()
        .map_err(|_| "invalid trusted sudo policy".to_string())?;
    let auth = SignerHttpAuth::new(auth)?;
    let identity = SudoIdentity {
        issuer: auth.owner.issuer_url.clone(),
        subject: auth
            .owner
            .required_subject
            .clone()
            .ok_or_else(|| "sudo signer requires a pinned owner subject".to_string())?,
    };
    if !policy
        .hosts
        .values()
        .any(|host| host.callers.values().any(|owner| owner == &identity))
    {
        return Err("configured sudo owner is absent from trusted policy".to_string());
    }
    let engine = SignerEngine::new(
        policy.manifest.clone(),
        node_id.as_ref(),
        key_package,
        128,
        60,
    )
    .map_err(|_| "sudo signer share does not match trusted policy".to_string())?;
    let state = Arc::new(SudoSignerState {
        auth,
        policy,
        identity,
        engine: Mutex::new(engine),
    });
    Ok(Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route(ROUND1_PATH, post(round1))
        .route(ROUND2_PATH, post(round2))
        .with_state(state))
}

async fn round1(
    State(state): State<Arc<SudoSignerState>>,
    request: Request,
) -> Result<Response, Response> {
    let _permit = state.auth.authenticate(request.headers()).await?;
    let (_, bytes) = bounded_body(request, MAX_SIGNER_BODY_BYTES).await?;
    let request: SudoRound1Request = serde_json::from_slice(&bytes).map_err(|_| {
        rejected(
            StatusCode::BAD_REQUEST,
            "invalid typed sudo signing request",
        )
    })?;
    let mut engine = state
        .engine
        .try_lock()
        .map_err(|_| rejected(StatusCode::TOO_MANY_REQUESTS, "sudo signer busy"))?;
    let result = engine
        .round1_sudo(
            &state.policy,
            &state.identity,
            &request,
            current_seconds().map_err(IntoResponse::into_response)?,
        )
        .map_err(round_error)?;
    Ok(Json(result).into_response())
}

async fn round2(
    State(state): State<Arc<SudoSignerState>>,
    request: Request,
) -> Result<Response, Response> {
    let _permit = state.auth.authenticate(request.headers()).await?;
    let (_, bytes) = bounded_body(request, MAX_SIGNER_BODY_BYTES).await?;
    let request: SudoRound2Request = serde_json::from_slice(&bytes).map_err(|_| {
        rejected(
            StatusCode::BAD_REQUEST,
            "invalid typed sudo signing request",
        )
    })?;
    let mut engine = state
        .engine
        .try_lock()
        .map_err(|_| rejected(StatusCode::TOO_MANY_REQUESTS, "sudo signer busy"))?;
    let signature_share = engine
        .round2_sudo(
            &state.policy,
            &state.identity,
            &request,
            current_seconds().map_err(IntoResponse::into_response)?,
        )
        .map_err(round_error)?;
    Ok(Json(Round2Response { signature_share }).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use ipars_quorum::sudo::{SudoChallenge, SudoGrant, SudoHostPolicy, SUDO_SCHEMA_VERSION};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tower::ServiceExt;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn fixture() -> TestResult<(
        SudoPolicy,
        Vec<frost::keys::KeyPackage>,
        SudoChallenge,
        SigningKey,
    )> {
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            rand_core::OsRng,
        )?;
        let manifest = Manifest {
            schema_version: 1,
            cluster_id: "sudo-http-test".into(),
            epoch: 1,
            members: (1..=3)
                .map(|identifier| ipars_quorum::Member {
                    identifier,
                    node_id: format!("node-{identifier}"),
                    endpoint: format!("https://node-{identifier}.example/"),
                })
                .collect(),
            public_key_package: public.serialize()?,
        };
        let keys = (1..=3)
            .map(|id| {
                let id = frost::Identifier::try_from(id)?;
                Ok(frost::keys::KeyPackage::try_from(
                    shares.get(&id).ok_or("missing fixture share")?.clone(),
                )?)
            })
            .collect::<TestResult<Vec<_>>>()?;
        let identity = SudoIdentity {
            issuer: "https://issuer.example.test/realms/test".into(),
            subject: "owner".into(),
        };
        let host = SigningKey::from_bytes(&[31; 32]);
        let requester = SigningKey::from_bytes(&[32; 32]);
        let policy = SudoPolicy {
            schema_version: SUDO_SCHEMA_VERSION,
            manifest,
            hosts: BTreeMap::from([(
                "node-1".into(),
                SudoHostPolicy {
                    attestation_key_epoch: 1,
                    attestation_public_key: host.verifying_key().to_bytes(),
                    callers: BTreeMap::from([(1000, identity.clone())]),
                },
            )]),
        };
        let now = u64::try_from(Utc::now().timestamp())?;
        let grant = SudoGrant {
            schema_version: SUDO_SCHEMA_VERSION,
            cluster_id: policy.manifest.cluster_id.clone(),
            host_node_id: "node-1".into(),
            caller_uid: 1000,
            runas_uid: 0,
            identity,
            attestation_key_epoch: 1,
            requester_public_key: requester.verifying_key().to_bytes(),
            manifest_epoch: 1,
            manifest_digest: policy.manifest.digest()?,
            policy_digest: policy.digest()?,
            nonce: [42; 32],
            issued_at: now,
            expires_at: now + 60,
        };
        let host_signature = host.sign(&grant.attestation_bytes()?).to_bytes().to_vec();
        Ok((
            policy,
            keys,
            SudoChallenge {
                grant,
                host_signature,
            },
            requester,
        ))
    }

    fn auth(backchannel: String) -> TestResult<WebUiAuthConfig> {
        Ok(WebUiAuthConfig::new(
            super::super::super::WebAuthProvider::Keycloak,
            "https://issuer.example.test/realms/test".into(),
            "test-client".into(),
            None,
            Some(backchannel),
            "openid".into(),
        )?
        .with_required_email("owner@example.test".into())?
        .with_required_subject("owner".into())?)
    }

    fn request(path: &str, body: &impl Serialize, token: Option<&str>) -> TestResult<Request> {
        let mut builder = Request::builder().method(Method::POST).uri(path);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        Ok(builder.body(Body::from(serde_json::to_vec(body)?))?)
    }

    #[test]
    fn sudo_router_requires_trusted_identity_and_matching_share() -> TestResult {
        let (policy, keys, _, _) = fixture()?;
        let auth = auth("http://127.0.0.1:9/realms/test".into())?;
        let mut missing = auth.clone();
        missing.required_subject = None;
        assert!(sudo_signer_router(policy.clone(), keys[0].clone(), "node-1", missing).is_err());
        let mut missing = auth.clone();
        missing.required_email = None;
        assert!(sudo_signer_router(policy.clone(), keys[0].clone(), "node-1", missing).is_err());
        let mut wrong = auth.clone();
        wrong.issuer_url = "https://another-issuer.example/".into();
        assert!(sudo_signer_router(policy.clone(), keys[0].clone(), "node-1", wrong).is_err());
        assert!(sudo_signer_router(policy, keys[1].clone(), "node-1", auth).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn sudo_rounds_authenticate_pinned_owner_and_reject_cross_domain_requests() -> TestResult
    {
        let (policy, keys, challenge, requester) = fixture()?;
        let revoked = Arc::new(AtomicBool::new(false));
        let flag = revoked.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let provider = Router::new().route(
            "/realms/test/protocol/openid-connect/userinfo",
            get(move |headers: HeaderMap| {
                let flag = flag.clone();
                async move {
                    match headers.get("authorization").and_then(|v| v.to_str().ok()) {
                        Some("Bearer owner-token") if !flag.load(Ordering::SeqCst) => {
                            Json(serde_json::json!({"sub":"owner", "email":"owner@example.test"}))
                                .into_response()
                        }
                        Some("Bearer other-subject") => {
                            Json(serde_json::json!({"sub":"other", "email":"owner@example.test"}))
                                .into_response()
                        }
                        _ => StatusCode::UNAUTHORIZED.into_response(),
                    }
                }
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, provider).await;
        });
        let auth = auth(format!("http://{address}/realms/test"))?;
        let apps = keys
            .iter()
            .enumerate()
            .take(2)
            .map(|(i, key)| {
                sudo_signer_router(
                    policy.clone(),
                    key.clone(),
                    format!("node-{}", i + 1),
                    auth.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut first = SudoRound1Request {
            identifier: 1,
            challenge: challenge.clone(),
            requester_proof: Vec::new(),
        };
        first.requester_proof = requester.sign(&first.proof_bytes()?).to_bytes().to_vec();
        for token in [None, Some("operator-token"), Some("other-subject")] {
            assert_eq!(
                apps[0]
                    .clone()
                    .oneshot(request(ROUND1_PATH, &first, token)?)
                    .await?
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        for path in ["/v1/quorum/round1", "/v1/quorum/rotation/round1"] {
            assert_eq!(
                apps[0]
                    .clone()
                    .oneshot(request(path, &first, Some("owner-token"))?)
                    .await?
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
        for value in [
            serde_json::json!({"claims":{}, "proof":{}}),
            serde_json::json!({"transition":{}}),
        ] {
            assert_eq!(
                apps[0]
                    .clone()
                    .oneshot(request(ROUND1_PATH, &value, Some("owner-token"))?)
                    .await?
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let mut injected = serde_json::to_value(&first)?;
        injected["authenticated"] = serde_json::to_value(&challenge.grant.identity)?;
        assert_eq!(
            apps[0]
                .clone()
                .oneshot(request(ROUND1_PATH, &injected, Some("owner-token"))?)
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        let mut bad = first.clone();
        bad.challenge.host_signature[0] ^= 1;
        bad.requester_proof = requester.sign(&bad.proof_bytes()?).to_bytes().to_vec();
        assert_eq!(
            apps[0]
                .clone()
                .oneshot(request(ROUND1_PATH, &bad, Some("owner-token"))?)
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        // A valid Ed25519 signature from the requester over the admin domain is not sudo PoP.
        let admin = CapabilityClaims {
            schema_version: 1,
            cluster_id: policy.manifest.cluster_id.clone(),
            epoch: 1,
            manifest_digest: policy.manifest.digest()?,
            method: "PUT".into(),
            path: "/v1/admin/policy".into(),
            body_sha256: Sha256::digest(b"{}").into(),
            requester_public_key: requester.verifying_key().to_bytes(),
            request_id: [44; 32],
            issued_at: challenge.grant.issued_at,
            expires_at: challenge.grant.expires_at,
        };
        bad = first.clone();
        bad.requester_proof = requester.sign(&admin.proof_bytes()).to_bytes().to_vec();
        assert_eq!(
            apps[0]
                .clone()
                .oneshot(request(ROUND1_PATH, &bad, Some("owner-token"))?)
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        let mut rounds = Vec::new();
        for (i, app) in apps.iter().enumerate() {
            first.identifier = u16::try_from(i + 1)?;
            first.requester_proof = requester.sign(&first.proof_bytes()?).to_bytes().to_vec();
            let response = app
                .clone()
                .oneshot(request(ROUND1_PATH, &first, Some("owner-token"))?)
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            rounds.push(serde_json::from_slice::<ipars_quorum::Round1Response>(
                &to_bytes(response.into_body(), MAX_SIGNER_BODY_BYTES).await?,
            )?);
        }
        let commitments = rounds
            .iter()
            .map(|r| Ok((frost::Identifier::try_from(r.identifier)?, r.commitments)))
            .collect::<TestResult<BTreeMap<_, _>>>()?;
        let package = frost::SigningPackage::new(commitments, &challenge.signing_bytes()?);
        let mut shares = BTreeMap::new();
        for (app, r) in apps.iter().zip(rounds) {
            let mut second = SudoRound2Request {
                identifier: r.identifier,
                session_id: r.session_id,
                challenge: challenge.clone(),
                signing_package: package.clone(),
                requester_proof: Vec::new(),
            };
            second.requester_proof = requester.sign(&second.proof_bytes()?).to_bytes().to_vec();
            revoked.store(true, Ordering::SeqCst);
            assert_eq!(
                app.clone()
                    .oneshot(request(ROUND2_PATH, &second, Some("owner-token"))?)
                    .await?
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            revoked.store(false, Ordering::SeqCst);
            let response = app
                .clone()
                .oneshot(request(ROUND2_PATH, &second, Some("owner-token"))?)
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let response: Round2Response = serde_json::from_slice(
                &to_bytes(response.into_body(), MAX_SIGNER_BODY_BYTES).await?,
            )?;
            shares.insert(
                frost::Identifier::try_from(r.identifier)?,
                response.signature_share,
            );
            assert_eq!(
                app.clone()
                    .oneshot(request(ROUND2_PATH, &second, Some("owner-token"))?)
                    .await?
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let public = policy.manifest.public_keys()?;
        let signature = frost::aggregate(&package, &shares, &public)?;
        public
            .verifying_key()
            .verify(&challenge.signing_bytes()?, &signature)?;
        assert!(public
            .verifying_key()
            .verify(&admin.signing_bytes(), &signature)
            .is_err());
        server.abort();
        Ok(())
    }
}
